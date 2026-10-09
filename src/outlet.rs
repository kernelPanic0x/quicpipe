//! The consumer side: dials (and redials), keeps the write cursor, and asks the
//! inlet to resume from it.

use std::time::Duration;

use color_eyre::eyre::Result;
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::completer::enter_code;
use crate::protocol::*;
use crate::sink::{self, Event as SinkEvent, Sink};
use crate::{OutletArgs, app_config, link, net, signals};

const SINK_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

enum Session {
    Done,
    PeerBye,
    Interrupted,
    BrokenPipe,
    Fatal(String),
}

struct Lost(String);

pub async fn run(mut args: OutletArgs) -> Result<()> {
    let key = args
        .common
        .private_key
        .clone()
        .unwrap_or_else(SecretKey::generate);
    let endpoint = net::bind(&key, false).await?;

    if args.common.code.is_none() {
        args.common.code = Some(enter_code()?.parse()?);
    }

    let mailbox = MailboxConnection::connect(
        app_config(&args.common),
        args.common.code.expect("Code set").clone(),
        false,
    )
    .await?;
    let mut wormhole = Wormhole::connect(mailbox).await?;
    wormhole
        .send(wincode::serialize(&net::payload_for(&endpoint, &key))?)
        .await?;
    let peer: HandshakePayload = wincode::deserialize(&wormhole.receive().await?)?;
    let peer_id = PublicKey::from_bytes(&peer.public_key)?;

    let mut addr = EndpointAddr::new(peer_id);
    if let Some(relay) = &peer.relay_url {
        addr = addr.with_relay_url(relay.parse()?);
    }
    for ip in &peer.direct_addresses {
        addr = addr.with_ip_addr(*ip);
    }
    eprintln!("[quicpipe] connecting to {}", peer_id.fmt_short());

    let (events_tx, mut events_rx) = mpsc::channel::<SinkEvent>(64);
    let (sink, sink_task) = sink::Sink::spawn(&args.common.path, 2, events_tx)?;

    let (signal_tx, mut signal_rx) = mpsc::channel(1);
    signals::forward(signal_tx);

    let mut attempt = 0u32;
    loop {
        let conn = match net::dial(&endpoint, addr.clone()).await {
            Ok(conn) => conn,
            Err(e) if net::transient(&e) => {
                attempt += 1;
                eprintln!("[quicpipe] connect failed: {e}; retrying");
                if !net::wait_for_retry(net::backoff(attempt), &mut signal_rx).await {
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        attempt = 0;

        match session(&conn, &sink, &mut events_rx, &mut signal_rx).await {
            Ok(Session::Done) | Ok(Session::PeerBye) => {
                // The sink may still be flushing the tail; let it finish so the
                // last bytes reach the consumer. The sink runs on its own
                // thread, so drain first (bounded), then join that thread.
                sink::drain(&sink, SINK_DRAIN_TIMEOUT).await;
                let _ = tokio::task::spawn_blocking(move || sink_task.join()).await;
                return Ok(());
            }
            Ok(Session::Interrupted) => signals::die_of(libc::SIGINT),
            Ok(Session::BrokenPipe) => signals::die_of(libc::SIGPIPE),
            Ok(Session::Fatal(msg)) => {
                eprintln!("[quicpipe] {msg}");
                return Err(color_eyre::eyre::eyre!(msg));
            }
            Err(Lost(reason)) => {
                eprintln!("[quicpipe] connection lost: {reason}; reconnecting");
                if !net::wait_for_retry(Duration::from_millis(200), &mut signal_rx).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn session(
    conn: &Connection,
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    signals: &mut mpsc::Receiver<()>,
) -> Result<Session, Lost> {
    let (send, recv) = conn.open_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_inlet_tx, to_inlet_rx) = mpsc::channel::<OutletToInlet>(4);
    let (from_inlet_tx, mut from_inlet_rx) = mpsc::channel::<InletToOutlet>(4);
    let (faults_tx, mut faults_rx) = mpsc::channel::<String>(2);

    sink::pump(recv, sink.tx.clone(), from_inlet_tx, faults_tx.clone());
    let writer = link::write_half(send, to_inlet_rx, faults_tx.clone());

    // The greeting *is* the resume request: whatever we have written, that is
    // where we want the inlet to start. The inlet answers with a `Fatal` if it
    // can no longer reproduce those bytes, and `Data` otherwise.
    let cursor = sink.cursor();
    to_inlet_tx
        .send(OutletToInlet::Received(cursor))
        .await
        .map_err(|_| Lost("inlet left immediately".into()))?;
    eprintln!("[quicpipe] connected; resuming at byte {cursor}");

    let outcome: Result<Session, Lost> = 'session: loop {
        select! {
            biased;

            // Local first, so Ctrl-C and a broken downstream are reported
            // promptly even while the stream is saturated.
            _ = signals.recv() => {
                let _ = to_inlet_tx.try_send(OutletToInlet::SIGINT);
                break 'session Ok(Session::Interrupted);
            }

            Some(event) = events.recv() => match event {
                SinkEvent::Ack(n) => {
                    // try_send on purpose: a dropped ack is superseded by the
                    // next one, and the greeting on the next connection.
                    let _ = to_inlet_tx.try_send(OutletToInlet::Received(n));
                }
                SinkEvent::BrokenPipe => {
                    // Our consumer is gone. Tell the inlet so its producer dies
                    // too, then die like a pipe ourselves.
                    let _ = to_inlet_tx.try_send(OutletToInlet::SIGPIPE);
                    let _ = to_inlet_tx.try_send(OutletToInlet::Bye);
                    break 'session Ok(Session::BrokenPipe);
                }
                SinkEvent::Gap { expected, got } => {
                    break 'session Ok(Session::Fatal(format!(
                        "inlet started at byte {got} but we had written {expected}: \
                         bytes are missing from the stream"
                    )));
                }
                SinkEvent::Error(e) => break 'session Ok(Session::Fatal(e)),
            },

            Some(msg) = from_inlet_rx.recv() => match msg {
                InletToOutlet::EOF => {
                    // Let the sink finish the tail, then report the true final
                    // offset so the inlet's window can close cleanly.
                    let drained = select! {
                        biased;
                        Some(f) = faults_rx.recv() => break 'session Err(Lost(f)),
                        _ = signals.recv() => break 'session Ok(Session::Interrupted),
                        n = sink::drain(sink, SINK_DRAIN_TIMEOUT) => n,
                    };
                    if let Some(n) = drained {
                        let _ = to_inlet_tx.send(OutletToInlet::Received(n)).await;
                    }
                    let _ = to_inlet_tx.try_send(OutletToInlet::Bye);
                    let _ = sink.tx.try_send(sink::Msg::Eof);
                    break 'session Ok(Session::Done);
                }
                InletToOutlet::SIGINT => break 'session Ok(Session::Interrupted),
                InletToOutlet::Fatal(msg) => break 'session Ok(Session::Fatal(msg)),
                InletToOutlet::Bye => break 'session Ok(Session::PeerBye),
                InletToOutlet::Data { .. } => {
                    break 'session Err(Lost("data frame reached the session".into()))
                }
            },

            Some(fault) = faults_rx.recv() => break 'session Err(Lost(fault)),
            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    drop(to_inlet_tx);
    let _ = timeout(Duration::from_secs(3), writer).await;
    outcome
}
