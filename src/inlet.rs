//! The producer side: source, replay window, reconnect loop. It never re-reads
//! its source, so stdin and a seekable file are handled identically.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use color_eyre::eyre::{Result, eyre};
use iroh::endpoint::{Connection, Endpoint};
use iroh::{PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::protocol::{HandshakePayload, InletToOutlet, MAX_BUFFERED_BYTES, OutletToInlet};
use crate::replay::Window;
use crate::ui::{Phase, Ui, UiConfig};
use crate::signals::Termination;
use crate::{InletArgs, app_config, link, net, signals, size, source};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const CTRL_GRACE: Duration = Duration::from_secs(3);

/// How long to keep the connection open after announcing cancellation, waiting
/// for the peer to close back (proof the cancellation frame was delivered).
/// Only then is the connection closed as a backstop.
const PEER_CLOSE_GRACE: Duration = Duration::from_secs(3);

enum Session {
    /// The outlet wrote, verified and acknowledged everything.
    PeerBye,
    /// The user cancelled this side of the transfer.
    Cancelled(Termination),
    /// The outlet's downstream consumer is gone, so ours must stop too.
    ConsumerGone,
    Fatal(String),
}

/// "The connection went away" — the one thing worth retrying.
struct Lost(String);

pub async fn run(args: InletArgs) -> Result<()> {
    let key = SecretKey::generate();
    let endpoint = net::bind(&key, true).await?;
    let result = inlet_session(&endpoint, &key, args).await;
    // Shut the transport down gracefully on every exit path so pending
    // connection state is flushed deterministically instead of iroh aborting
    // with "Endpoint dropped without calling Endpoint::close".
    endpoint.close().await;
    result
}

async fn inlet_session(endpoint: &Endpoint, key: &SecretKey, args: InletArgs) -> Result<()> {
    let common = &args.common;
    // Explicit -s wins; otherwise a regular file (or a regular stdin) gives
    // an exact total. Pipes have no meaningful size and stay unknown.
    let total = args.common.size.or_else(|| size::detect(&common.path));
    let position = Arc::new(AtomicU64::new(0));
    let ui = Ui::start(&UiConfig::new(common.quiet), total, &position);

    let mailbox = MailboxConnection::create(app_config(common), args.code_length).await?;
    ui.notice(format!("Wormhole Code: {}", mailbox.code()));
    ui.phase(Phase::WaitingForPeer);
    tracing::info!("waiting for the other end...");
    let mut wormhole = Wormhole::connect(mailbox).await?;
    wormhole
        .send(wincode::serialize(&net::payload_for(endpoint, key, total))?)
        .await?;
    let peer: HandshakePayload = wincode::deserialize(&wormhole.receive().await?)?;
    let peer_id = PublicKey::from_bytes(&peer.public_key)?;
    tracing::info!("peer is {}", peer_id.fmt_short());

    let mut source = source::spawn(&common.path, 2)?;
    let (signal_tx, mut signal_rx) = mpsc::channel::<Termination>(1);
    signals::forward(signal_tx);

    let mut window = Window::new(MAX_BUFFERED_BYTES as u64);
    let mut source_done = false;
    let mut source_checksum: Option<u64> = None;
    let mut attempt = 0u32;

    loop {
        // Cancelled while waiting for a connection: die like a signal
        // handler should, so the exit code says 130/143, not 0.
        let conn = match accept(endpoint, peer_id, &mut signal_rx).await? {
            Accepted::Connection(conn) => conn,
            Accepted::Cancelled(why) => signals::exit(why),
        };
        ui.watch_connection(&conn);
        ui.phase(Phase::Transferring);

        match session(
            &conn,
            &mut window,
            &mut source.rx,
            &mut source_done,
            &mut source_checksum,
            &mut signal_rx,
            &position,
        )
        .await
        {
            Ok(Session::PeerBye) => {
                ui.finish_success();
                return Ok(());
            }
            Ok(Session::Cancelled(why)) => signals::exit(why),
            Ok(Session::ConsumerGone) => signals::exit(Termination::ConsumerGone),
            Ok(Session::Fatal(msg)) => return Err(eyre!(msg)),
            Err(Lost(reason)) => {
                ui.clear_connection();
                // A lost connection is only worth waiting on if the peer did
                // not leave on purpose. Non-success close codes are definitive
                // even when the matching in-band frame was lost; success still
                // requires the in-band `Bye` (see the DONE arm).
                match net::close_kind(&conn).await {
                    net::CloseKind::App(net::close::DONE, r) => {
                        // Only the in-band `Bye` proves that the outlet
                        // verified our checksum. A `DONE` close arriving
                        // without it may be a spurious/transport-level close:
                        // never turn that into success. This mirrors the
                        // outlet's refusal to trust `DONE` without `Checksum`.
                        return Err(eyre!(
                            "outlet closed with 'done' but never said Bye: \
                             the transfer may be incomplete ({r})"
                        ));
                    }
                    net::CloseKind::App(net::close::CANCELLED, _) => signals::exit(Termination::Interrupt),
                    net::CloseKind::App(net::close::CONSUMER_GONE, _) => signals::exit(Termination::ConsumerGone),
                    net::CloseKind::App(net::close::FATAL, r) => {
                        return Err(eyre!("outlet reported a fatal error: {r}"));
                    }
                    net::CloseKind::App(code, r) => {
                        // An unexpected application close is not a verdict we
                        // can trust as complete. Never exit 0 here: the
                        // upstream producer must learn the transfer failed.
                        return Err(eyre!(
                            "outlet closed the connection unexpectedly ({code}: {r}); \
                             the stream is incomplete"
                        ));
                    }
                    net::CloseKind::TimedOut | net::CloseKind::Lost(_) => {
                        attempt = attempt.saturating_add(1);
                        ui.phase(Phase::Reconnecting { attempt });
                        tracing::warn!("connection lost: {reason}; waiting for a reconnect");
                    }
                }
            }
        }
    }
}

/// What the accept loop produced before it ended.
enum Accepted {
    Connection(Connection),
    Cancelled(Termination),
}

/// Queues a control frame on a possibly congested channel: the writer drains
/// it continuously, so poll until it accepts the frame instead of betting on a
/// single timed send.
async fn queue_ctrl(tx: &mpsc::Sender<InletToOutlet>, msg: InletToOutlet) {
    let deadline = tokio::time::Instant::now() + CTRL_GRACE;
    loop {
        match tx.try_send(msg.clone()) {
            // Success and a torn-down session both end the queueing loop;
            // the close code takes over.
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
            // The writer drains the channel continuously, so Full is a brief
            // congestion.
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if tokio::time::Instant::now() >= deadline {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// Accepts only connections from the endpoint we rendezvoused with.
async fn accept(
    endpoint: &Endpoint,
    peer: PublicKey,
    signals: &mut mpsc::Receiver<Termination>,
) -> Result<Accepted> {
    loop {
        let incoming = select! {
            biased;
            why = signals.recv() => {
                return Ok(Accepted::Cancelled(why.unwrap_or(Termination::Interrupt)));
            }
            incoming = endpoint.accept() => {
                // A closed endpoint is an infrastructure failure, not a user
                // cancellation: report it, never disguise it as a cancellation.
                match incoming {
                    Some(next) => next,
                    None => {
                        return Err(eyre!("the endpoint stopped accepting connections"));
                    }
                }
            }
        };
        let conn = match incoming.accept() {
            Ok(connecting) => match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("handshake failed: {e}");
                    continue;
                }
            },
            Err(e) => {
                // Retransmitted datagrams can produce failures we may ignore.
                tracing::debug!("dropped incoming connection: {e}");
                continue;
            }
        };
        if conn.remote_id() != peer {
            tracing::debug!(
                "ignoring {}; waiting for {}",
                conn.remote_id().fmt_short(),
                peer.fmt_short()
            );
            continue;
        }
        return Ok(Accepted::Connection(conn));
    }
}

async fn session(
    conn: &Connection,
    window: &mut Window,
    source: &mut mpsc::Receiver<source::Msg>,
    source_done: &mut bool,
    source_checksum: &mut Option<u64>,
    signals: &mut mpsc::Receiver<Termination>,
    position: &AtomicU64,
) -> Result<Session, Lost> {
    let (control_send, control_recv) = conn.accept_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_outlet_tx, to_outlet_rx) = mpsc::channel::<InletToOutlet>(4);
    let (from_outlet_tx, mut from_outlet_rx) = mpsc::channel::<OutletToInlet>(8);
    let (faults_tx, mut faults_rx) = mpsc::channel::<String>(2);

    link::read_half(control_recv, from_outlet_tx, faults_tx.clone());
    let control_writer = link::write_half(control_send, to_outlet_rx, faults_tx.clone());

    // The first frame is the outlet saying how much it has written, which is
    // also exactly where it wants us to resume from.
    let resume_from = match timeout(HANDSHAKE_TIMEOUT, from_outlet_rx.recv()).await {
        Ok(Some(OutletToInlet::Written(n))) => n,
        Ok(Some(other)) => return Err(Lost(format!("expected the resume point, got {other:?}"))),
        Ok(None) => return Err(Lost("outlet left before greeting".into())),
        Err(_) => return Err(Lost("outlet did not greet us in time".into())),
    };

    // Offsets stay internal to the replay window. Once the bytes are rebuilt
    // from `resume_from`, the data stream itself is just bytes in order.
    let mut backlog: VecDeque<Bytes> = match window.replay_from(resume_from) {
        Ok(chunks) => chunks.into_iter().map(|(_offset, payload)| payload).collect(),
        Err(out_of_range) => {
            // Bytes are gone. Inventing them would silently corrupt the stream,
            // so refuse loudly and let the exit code carry the verdict.
            let msg = out_of_range.to_string();
            tracing::error!("{msg}");
            let _ = timeout(
                CTRL_GRACE,
                to_outlet_tx.send(InletToOutlet::Fatal(msg.clone())),
            )
            .await;
            drop(to_outlet_tx);
            let _ = timeout(CTRL_GRACE, control_writer).await;
            net::close_intentional(conn, net::close::FATAL, "fatal");
            return Ok(Session::Fatal(msg));
        }
    };

    // The resume point is acknowledged: the bytes below it can leave the window
    // and the accounting after a reconnect starts from where the peer is.
    window.ack(resume_from);
    position.fetch_max(resume_from, Ordering::Relaxed);

    let data_send = conn.open_uni().await.map_err(|e| Lost(e.to_string()))?;
    let (data_out, data_rx) = mpsc::channel::<Bytes>(2);
    let mut data_tx = Some(data_out);
    let data_writer = link::write_bytes(data_send, data_rx, faults_tx.clone());
    let mut data_closed = false;
    let mut checksum_sent = false;

    tracing::info!(
        "outlet connected; resuming from byte {resume_from} \
         ({} chunks buffered, {} unacknowledged)",
        backlog.len(),
        window.unacked()
    );

    let outcome: Result<Session, Lost> = 'session: loop {
        // The checksum travels on the control stream as soon as the source is
        // exhausted; the outlet waits for both this frame and the data FIN.
        if *source_done && !checksum_sent {
            let checksum = source_checksum.expect("source_done implies a checksum");
            let _ = timeout(
                CTRL_GRACE,
                to_outlet_tx.send(InletToOutlet::Checksum(checksum)),
            )
            .await;
            checksum_sent = true;
        }

        // Once every byte is either replayed or still queued in the data
        // channel, dropping the sender lets the writer drain and FIN the
        // stream. This is the raw replacement for a separate EOF frame.
        if *source_done && !data_closed && backlog.is_empty() {
            data_tx = None;
            data_closed = true;
        }

        let data_slot = data_tx.as_ref().is_some_and(|tx| tx.capacity() > 0);
        let can_replay = !backlog.is_empty() && data_slot;
        let has_room = !window.is_full() && data_slot;
        let can_pull = !*source_done && has_room && backlog.is_empty();

        select! {
            biased;

            // A stream task died, which means the connection is gone.
            Some(fault) = faults_rx.recv() => break 'session Err(Lost(fault)),

            why = signals.recv() => {
                // The control channel is tiny; poll until the writer takes the
                // cancellation frame rather than betting on one timed send.
                queue_ctrl(&to_outlet_tx, InletToOutlet::Cancel).await;
                break 'session Ok(Session::Cancelled(why.unwrap_or(Termination::Interrupt)));
            }

            Some(msg) = from_outlet_rx.recv() => match msg {
                OutletToInlet::Written(n) => {
                    window.ack(n);
                    position.fetch_max(n, Ordering::Relaxed);
                }
                OutletToInlet::Bye => break 'session Ok(Session::PeerBye),
                OutletToInlet::Cancel => break 'session Ok(Session::Cancelled(Termination::Interrupt)),
                OutletToInlet::ConsumerGone => break 'session Ok(Session::ConsumerGone),
            },

            () = std::future::ready(()), if can_replay => {
                if let (Some(tx), Some(payload)) = (&data_tx, backlog.pop_front()) {
                    let _ = tx.try_send(payload);
                }
            }

            // Exactly one branch may touch the source. `select!` evaluates every
            // branch's async expression before polling any of them, so a second
            // `source.recv()` would be a second simultaneous `&mut *source` —
            // and a disabled branch is still evaluated.
            msg = source.recv(), if can_pull => match msg {
                Some(source::Msg::Data(chunk)) => {
                    window.push(chunk.clone());
                    if let Some(tx) = &data_tx {
                        let _ = tx.try_send(chunk);
                    }
                }
                Some(source::Msg::Eof { checksum }) => {
                    *source_done = true;
                    *source_checksum = Some(checksum);
                }
                Some(source::Msg::Error(e)) => {
                    let _ = timeout(
                        CTRL_GRACE,
                        to_outlet_tx.send(InletToOutlet::Fatal(e.clone())),
                    )
                    .await;
                    break 'session Ok(Session::Fatal(e));
                }
                // The only sender lives inside the source thread, so a closed
                // channel with neither `Eof` nor `Error` means it died
                // abnormally. The stream may be truncated, and claiming a clean
                // EOF for a truncated stream is the one lie worth avoiding.
                None => {
                    let msg = "source thread exited without finishing".to_string();
                    let _ = timeout(
                        CTRL_GRACE,
                        to_outlet_tx.send(InletToOutlet::Fatal(msg.clone())),
                    )
                    .await;
                    break 'session Ok(Session::Fatal(msg));
                }
            },

            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    // Dropping the data sender lets the raw writer flush queued bytes and FIN.
    // On a lost/cancelled connection there is no peer left to flush to, so the
    // writer is aborted instead of delaying teardown.
    drop(data_tx);
    match &outcome {
        Ok(Session::Cancelled(_) | Session::ConsumerGone | Session::Fatal(_)) | Err(_) => {
            data_writer.abort();
        }
        Ok(Session::PeerBye) => {
            let _ = timeout(CTRL_GRACE, data_writer).await;
        }
    }
    drop(to_outlet_tx);
    if outcome.is_err() {
        control_writer.abort();
    } else {
        let _ = timeout(CTRL_GRACE, control_writer).await;
    }

    // Announce the verdict at the transport level. For cancellation the
    // connection must NOT be closed right away: `close` discards stream data
    // that has not been acked, which could destroy the in-flight cancellation frame.
    // The stream is the reliable channel (QUIC retransmits it until acked), so
    // cancellation waits for the peer to close back; everything else closes as
    // a backstop announcing the verdict even if the in-band frame was lost.
    match &outcome {
        Ok(Session::Cancelled(_)) => {
            if timeout(PEER_CLOSE_GRACE, conn.closed()).await.is_err() {
                net::close_intentional(conn, net::close::CANCELLED, "cancelled");
                tokio::time::sleep(net::CLOSE_PROPAGATE).await;
            }
        }
        Ok(Session::PeerBye) => {
            net::close_intentional(conn, net::close::DONE, "done");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::ConsumerGone) => {
            net::close_intentional(conn, net::close::CONSUMER_GONE, "consumer gone");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::Fatal(msg)) => {
            // The close reason carries the message; QUIC truncates it to fit a
            // packet, so keep it short.
            net::close_intentional(conn, net::close::FATAL, &msg[..msg.len().min(256)]);
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Err(Lost(_)) => {} // the connection is already gone
    }
    outcome
}
