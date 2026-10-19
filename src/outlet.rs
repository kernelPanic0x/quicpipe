//! The consumer side: dials (and redials), keeps the write cursor, and asks the
//! inlet to resume from it.

use std::time::Duration;

use color_eyre::eyre::{Result, eyre};
use iroh::endpoint::{Connection, Endpoint};
use iroh::{EndpointAddr, PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::completer::enter_code;
use crate::protocol::{HandshakePayload, InletToOutlet, OutletToInlet};
use crate::sink::{self, Event as SinkEvent, Sink};
use crate::ui::{Phase, Ui, UiConfig};
use crate::{OutletArgs, app_config, link, net, signals};

const SINK_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to keep the connection open after announcing cancellation, waiting
/// for the peer to close back (proof the SIGINT frame was delivered). Only then
/// is the connection closed as a backstop.
const PEER_CLOSE_GRACE: Duration = Duration::from_secs(3);

/// How long a control-frame send may wait for the writer to take it before we
/// treat the connection as wedged. `mpsc::Sender::send` is cancel-safe, so a
/// timed-out send is *guaranteed* not to have delivered the frame: no silent
/// loss, the caller always knows.
const CTRL_GRACE: Duration = Duration::from_secs(3);

enum Session {
    Done,
    /// The *peer* was cancelled (SIGINT/SIGTERM): the stream is over but did
    /// not complete. This must surface as an error, not a clean exit.
    PeerCancelled,
    /// We ourselves were cancelled.
    Interrupted(i32),
    BrokenPipe,
    Fatal(String),
}

struct Lost(String);

/// Sends a control frame, waiting up to `CTRL_GRACE` for the writer to take
/// it. Returns false if the frame could not be queued in time (writer wedged
/// or session torn down) — the caller must then treat the frame as undelivered
/// rather than assume it went out.
async fn send_ctrl(tx: &mpsc::Sender<OutletToInlet>, msg: OutletToInlet) -> bool {
    !matches!(timeout(CTRL_GRACE, tx.send(msg)).await, Err(_) | Ok(Err(_)))
}

pub async fn run(args: OutletArgs) -> Result<()> {
    let key = SecretKey::generate();
    let endpoint = net::bind(&key, false).await?;
    let result = outlet_session(&endpoint, &key, args).await;
    // Shut the transport down gracefully on every exit path so pending
    // connection state is flushed deterministically instead of iroh aborting
    // with "Endpoint dropped without calling Endpoint::close".
    endpoint.close().await;
    result
}

async fn outlet_session(endpoint: &Endpoint, key: &SecretKey, mut args: OutletArgs) -> Result<()> {
    if args.code.is_none() {
        args.code = Some(enter_code()?.parse()?);
    }
    let code = args.code.take();

    let mailbox =
        MailboxConnection::connect(app_config(&args.common), code.expect("Code set"), false)
            .await?;
    let mut wormhole = Wormhole::connect(mailbox).await?;
    wormhole
        .send(wincode::serialize(&net::payload_for(endpoint, key, None))?)
        .await?;
    let peer: HandshakePayload = wincode::deserialize(&wormhole.receive().await?)?;
    let peer_id = PublicKey::from_bytes(&peer.public_key)?;

    // The inlet's advertised total is authoritative. `-s` on the outlet is a
    // fallback for peers that do not announce one (and an expectation the
    // inlet's value silently overrides, since only it knows the source).
    if let (Some(announced), Some(declared)) = (peer.size, args.common.size)
        && announced != declared
    {
        tracing::warn!(
            "inlet announced {announced} bytes but outlet -s says {declared}; \
             using the inlet's value"
        );
    }
    let total = peer.size.or(args.common.size);

    let mut addr = EndpointAddr::new(peer_id);
    if let Some(relay) = &peer.relay_url {
        addr = addr.with_relay_url(relay.parse()?);
    }
    for ip in &peer.direct_addresses {
        addr = addr.with_ip_addr(*ip);
    }
    tracing::info!("connecting to {}", peer_id.fmt_short());

    let (events_tx, mut events_rx) = mpsc::channel::<SinkEvent>(64);
    let (sink, sink_task) = sink::Sink::spawn(&args.common.path, 2, events_tx)?;

    // The sink's own cursor is the position source: it advances exactly when
    // bytes are handed to the OS, which is the truth the bar should show.
    let ui = Ui::start(
        &UiConfig::new(args.common.quiet),
        total,
        &sink.cursor_handle(),
    );
    ui.phase(Phase::Connecting);

    let (signal_tx, mut signal_rx) = mpsc::channel::<i32>(1);
    signals::forward(signal_tx);

    let mut announced_checksum: Option<u64> = None;
    let mut attempt = 0u32;
    let mut lost_attempts = 0u32;
    let mut ever_connected = false;
    loop {
        let conn = match net::dial(endpoint, addr.clone()).await {
            Ok(conn) => {
                // A successful dial only resets the backoff; the reconnect
                // budget below renews on *progress*, so a peer that accepts
                // connections but never delivers data still gets bounded.
                attempt = 0;
                ever_connected = true;
                ui.watch_connection(&conn);
                ui.phase(Phase::Transferring);
                conn
            }
            Err(e) if net::transient(&e) => {
                attempt += 1;
                lost_attempts += 1;
                // Before the first connection this is still "connecting";
                // only a lost established connection is a *re*connect.
                ui.phase(if ever_connected {
                    Phase::Reconnecting {
                        attempt: lost_attempts,
                    }
                } else {
                    Phase::Connecting
                });
                tracing::warn!("connect failed: {e}; retrying");
                if let Some(sig) = net::wait_for_retry(net::backoff(attempt), &mut signal_rx).await
                {
                    // Cancelled while retrying: exit like a signal handler.
                    signals::die_of(sig);
                }
                continue;
            }
            Err(e) => return Err(e),
        };

        match session(
            &conn,
            &sink,
            &mut events_rx,
            &mut announced_checksum,
            &mut signal_rx,
            &ui,
        )
        .await
        {
            Ok(Session::Done) => {
                // The sink may still be flushing the tail; let it finish, then
                // the gate inside finish_sink verifies the checksum. Only a
                // verified transfer exits 0.
                finish_sink(&sink, sink_task, announced_checksum).await?;
                ui.finish_success();
                return Ok(());
            }
            Ok(Session::PeerCancelled) => {
                // The bytes received so far are a clean prefix: flush them,
                // but the exit must stay loud — the stream did not complete.
                let _ = finish_sink(&sink, sink_task, announced_checksum).await;
                return Err(eyre!(
                    "the inlet cancelled the transfer (SIGINT); \
                     the stream did not complete"
                ));
            }
            Ok(Session::Interrupted(sig)) => signals::die_of(sig),
            Ok(Session::BrokenPipe) => signals::die_of(libc::SIGPIPE),
            Ok(Session::Fatal(msg)) => {
                tracing::error!("{msg}");
                return Err(color_eyre::eyre::eyre!(msg));
            }
            Err(Lost(reason)) => {
                lost_attempts += 1;
                ui.clear_connection();
                ui.phase(Phase::Connecting);
                // First ask the connection why it ended. An application close
                // means the inlet made a final decision and must not be
                // second-guessed by a reconnect — this is what keeps the
                // outlet from redialling an inlet that exited via Ctrl+C.
                match net::close_kind(&conn).await {
                    net::CloseKind::App(net::close::CANCEL, _) => {
                        // The bytes received so far are a clean prefix: flush
                        // them, but the exit must stay loud — the stream did
                        // not complete.
                        let _ = finish_sink(&sink, sink_task, announced_checksum).await;
                        return Err(eyre!(
                            "the inlet cancelled the transfer (SIGINT); \
                             the stream did not complete"
                        ));
                    }
                    net::CloseKind::App(net::close::SIGPIPE, _) => signals::die_of(libc::SIGPIPE),
                    net::CloseKind::App(net::close::FATAL, r) => {
                        return Err(eyre!("inlet reported a fatal error: {r}"));
                    }
                    net::CloseKind::App(net::close::DONE, r) => {
                        // A clean close is only clean if the inlet had already
                        // said `EOF`; a `DONE` arriving without it means the
                        // stream ended early. Data integrity outranks
                        // everything: exit loudly with a non-zero code.
                        let _ = finish_sink(&sink, sink_task, announced_checksum).await;
                        return Err(eyre!(
                            "inlet closed with 'done' but never announced EOF: \
                             the stream ended early ({r})"
                        ));
                    }
                    net::CloseKind::App(_, r) => {
                        // An unexpected application close is not a verdict we
                        // can trust as complete. Never exit 0 here. Flush the
                        // received prefix first: it is valid data even if the
                        // transfer as a whole failed.
                        let _ = finish_sink(&sink, sink_task, announced_checksum).await;
                        return Err(eyre!(
                            "inlet closed the connection unexpectedly ({r}); \
                             the stream is incomplete"
                        ));
                    }
                    net::CloseKind::TimedOut => {
                        // Only an ordinary network failure may be retried.
                        ui.phase(Phase::Reconnecting {
                            attempt: lost_attempts,
                        });
                        tracing::warn!("connection lost: {reason}; reconnecting");
                        if let Some(sig) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::die_of(sig);
                        }
                    }
                    net::CloseKind::Lost(why) => {
                        // Only an ordinary network failure may be retried.
                        ui.phase(Phase::Reconnecting {
                            attempt: lost_attempts,
                        });
                        tracing::warn!(
                            "connection lost: {reason}; reconnecting (transport: {why})"
                        );
                        if let Some(sig) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::die_of(sig);
                        }
                    }
                }
            }
        }
    }
}

/// Lets the sink flush the tail, verify the checksum, then join the writer
/// thread. The sink runs on its own thread, so drain first (bounded), then
/// verify, then close.
///
/// This is THE structural exit gate: `Ok(())` from here proves (a) every
/// queued byte was written, (b) the digest of the bytes handed to the OS
/// matches what the inlet announced, and (c) the writer exited cleanly.
/// Successful transfers reach this through the `Done` arm, which
/// propagates any error - so exit 0 is impossible without a verified
/// checksum. Error paths call this with `let _ =` to flush the valid prefix
/// on the way out; their own error is the verdict that matters.
async fn finish_sink(
    sink: &sink::Sink,
    sink_task: std::thread::JoinHandle<()>,
    announced_checksum: Option<u64>,
) -> Result<()> {
    let Some((_cursor, written_digest)) = sink::drain(sink, SINK_DRAIN_TIMEOUT).await else {
        return Err(eyre!(
            "the sink did not write its tail within {SINK_DRAIN_TIMEOUT:?}; \
             the stream is incomplete"
        ));
    };
    // The integrity verdict: what the inlet's source produced must equal what
    // we handed to the OS. A mismatch means a protocol bug corrupted the
    // stream - never exit 0. A missing checksum means verification was
    // skipped - also never exit 0.
    let Some(expected) = announced_checksum else {
        return Err(eyre!(
            "the inlet never announced a checksum: the stream could not be verified"
        ));
    };
    if expected != written_digest {
        return Err(eyre!(
            "checksum mismatch: the inlet sent {expected:#018x}, \
             we wrote {written_digest:#018x}: the stream is corrupt"
        ));
    }
    // The drain barrier is answered, so the writer thread is alive: now it
    // takes the EOF, which flushes and closes the fd for downstream readers.
    if timeout(CTRL_GRACE, sink.tx.send(sink::Msg::Eof))
        .await
        .is_err()
    {
        return Err(eyre!("the sink did not accept EOF"));
    }
    let _ = tokio::task::spawn_blocking(move || sink_task.join()).await;
    Ok(())
}

async fn session(
    conn: &Connection,
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    announced_checksum: &mut Option<u64>,
    signals: &mut mpsc::Receiver<i32>,
    ui: &Ui,
) -> Result<Session, Lost> {
    let (control_send, control_recv) = conn.open_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_inlet_tx, to_inlet_rx) = mpsc::channel::<OutletToInlet>(8);
    let (from_inlet_tx, mut from_inlet_rx) = mpsc::channel::<InletToOutlet>(8);
    let (faults_tx, mut faults_rx) = mpsc::channel::<String>(2);

    link::read_half(control_recv, from_inlet_tx, faults_tx.clone());
    let control_writer = link::write_half(control_send, to_inlet_rx, faults_tx.clone());

    // The greeting *is* the resume request: whatever we have written, that is
    // where we want the inlet to start. The inlet answers by opening the data
    // stream, or with `Fatal` if it can no longer reproduce those bytes.
    let cursor = sink.cursor();
    if !send_ctrl(&to_inlet_tx, OutletToInlet::Written(cursor)).await {
        return Err(Lost("inlet left immediately".into()));
    }
    tracing::info!("connected; resuming at byte {cursor}");

    let (data_end_tx, mut data_end_rx) = mpsc::channel::<()>(1);

    // Wait for the inlet's data stream while remaining responsive to control
    // frames: a rejected resume arrives as `Fatal` instead of a stream.
    let data_recv = loop {
        select! {
            biased;

            received_sig = signals.recv() => {
                let sig = received_sig.unwrap_or(libc::SIGINT);
                let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGINT).await;
                return Ok(Session::Interrupted(sig));
            }

            Some(msg) = from_inlet_rx.recv() => match msg {
                InletToOutlet::Checksum(sum) => *announced_checksum = Some(sum),
                InletToOutlet::SIGINT => return Ok(Session::PeerCancelled),
                InletToOutlet::Fatal(report) => return Ok(Session::Fatal(report)),
            },

            Some(fault) = faults_rx.recv() => return Err(Lost(fault)),
            _ = conn.closed() => return Err(Lost("connection closed before data stream".into())),

            accepted = conn.accept_uni() => match accepted {
                Ok(recv) => break recv,
                Err(e) => return Err(Lost(e.to_string())),
            },
        }
    };

    let data_pump = sink::pump(data_recv, sink.tx.clone(), data_end_tx, faults_tx.clone());
    let mut data_finished = false;
    let mut verify = false;

    let outcome: Result<Session, Lost> = 'session: loop {
        select! {
            biased;

            // Local first, so Ctrl-C is reported promptly even while the
            // stream is saturated.
            received_sig = signals.recv() => {
                // The producer's Ctrl-C must reach the inlet: the source dies
                // of SIGINT, so this goodbye is its only way to learn. Awaited
                // (bounded) so it cannot be silently dropped by a wedged
                // writer.
                let sig = received_sig.unwrap_or(libc::SIGINT);
                let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGINT).await;
                break 'session Ok(Session::Interrupted(sig));
            }

            // Control frames outrank sink acks: a continuously acking sink
            // must never starve the inlet's checksum or cancellation.
            Some(msg) = from_inlet_rx.recv() => match msg {
                InletToOutlet::Checksum(sum) => {
                    *announced_checksum = Some(sum);
                    if data_finished {
                        verify = true;
                        break 'session Ok(Session::Done); // placeholder, finalize below
                    }
                }
                InletToOutlet::SIGINT => break 'session Ok(Session::PeerCancelled),
                InletToOutlet::Fatal(report) => break 'session Ok(Session::Fatal(report)),
            },

            Some(()) = data_end_rx.recv() => {
                data_finished = true;
                ui.phase(Phase::Verifying);
                if announced_checksum.is_some() {
                    verify = true;
                    break 'session Ok(Session::Done); // placeholder, finalize below
                }
            }

            Some(event) = events.recv() => match event {
                SinkEvent::Ack(n) => {
                    // try_send on purpose: a dropped ack is superseded by the
                    // next one, and the greeting on the next connection.
                    let _ = to_inlet_tx.try_send(OutletToInlet::Written(n));
                }
                SinkEvent::BrokenPipe => {
                    // Our consumer is gone. Tell the inlet so its producer dies
                    // too, then die like a pipe ourselves. Both frames are
                    // awaited (bounded): this goodbye is the producer's only
                    // SIGPIPE, so it must not be silently dropped by a wedged
                    // writer.
                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGPIPE).await;
                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Bye).await;
                    break 'session Ok(Session::BrokenPipe);
                }
                SinkEvent::Error(e) => break 'session Ok(Session::Fatal(e)),
            },

            Some(fault) = faults_rx.recv() => break 'session Err(Lost(fault)),
            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    // No new data may enter the queue after this point: a reconnect drain must
    // observe a fixed sink queue before taking its cursor. A *graceful* verdict
    // (cancel, broken pipe, fatal) is delivered on the control stream, so the
    // data stream is left alone: resetting it here would race the control frame
    // and could turn a clean cancellation into a spurious "lost connection".
    // It ends by itself when the connection closes.
    if outcome.is_err() {
        data_pump.abort();
    }

    // Finalize first: it sends the last `Written` and the `Bye`, so the
    // control sender (and the writer draining it) must still be alive.
    let verdict = if verify {
        finalize(
            sink,
            events,
            *announced_checksum,
            signals,
            &to_inlet_tx,
            conn,
        )
        .await
    } else {
        outcome
    };

    // Only now wind the control stream down: dropping the sender lets the
    // writer finish the stream (FIN), so the inlet sees a clean end of control.
    drop(to_inlet_tx);
    if verdict.is_err() {
        control_writer.abort();
    } else {
        let _ = timeout(Duration::from_secs(3), control_writer).await;
    }

    // Announce the verdict at the transport level. For cancellation the
    // connection must NOT be closed right away: `close` discards stream data
    // that has not been acked, which could destroy the in-flight SIGINT frame.
    // Wait for the peer to close back first; close as a backstop otherwise.
    match &verdict {
        Ok(Session::Interrupted(_)) => {
            if timeout(PEER_CLOSE_GRACE, conn.closed()).await.is_err() {
                net::close_intentional(conn, net::close::CANCEL, "SIGINT");
                tokio::time::sleep(net::CLOSE_PROPAGATE).await;
            }
        }
        Ok(Session::Done) => {
            net::close_intentional(conn, net::close::DONE, "done");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::PeerCancelled) => {
            net::close_intentional(conn, net::close::CANCEL, "SIGINT");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::BrokenPipe) => {
            net::close_intentional(conn, net::close::SIGPIPE, "SIGPIPE");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::Fatal(msg)) => {
            net::close_intentional(conn, net::close::FATAL, &msg[..msg.len().min(256)]);
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Err(Lost(_)) => {} // the connection is already gone
    }
    verdict
}

/// Called once the data stream FIN and the checksum are both in hand. Drains
/// the sink, reports the true final cursor, verifies the digest and says
/// goodbye. It stays responsive to Ctrl-C and a dead consumer.
async fn finalize(
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    announced_checksum: Option<u64>,
    signals: &mut mpsc::Receiver<i32>,
    to_inlet_tx: &mpsc::Sender<OutletToInlet>,
    conn: &Connection,
) -> Result<Session, Lost> {
    let final_offset = 'drain: loop {
        select! {
            biased;

            received_sig = signals.recv() => {
                return Ok(Session::Interrupted(received_sig.unwrap_or(libc::SIGINT)));
            }
            _ = conn.closed() => {
                return Err(Lost("connection closed while draining the tail".into()));
            }

            Some(event) = events.recv() => match event {
                SinkEvent::BrokenPipe => {
                    let _ = send_ctrl(to_inlet_tx, OutletToInlet::SIGPIPE).await;
                    let _ = send_ctrl(to_inlet_tx, OutletToInlet::Bye).await;
                    return Ok(Session::BrokenPipe);
                }
                SinkEvent::Error(e) => return Ok(Session::Fatal(e)),
                SinkEvent::Ack(n) => {
                    // A write during the drain advanced the cursor. The final
                    // `Written` below covers it, but forward late acks so the
                    // greeting of a reconnect stays truthful.
                    let _ = send_ctrl(to_inlet_tx, OutletToInlet::Written(n)).await;
                }
            },

            verdict = sink::drain(sink, Duration::MAX) => break 'drain verdict,
        }
    };

    let Some((tail_end, written_digest)) = final_offset else {
        return Ok(Session::Fatal(
            "sink stopped before the tail was written".into(),
        ));
    };

    // The goodbye is the inlet's only way to reach success, so it must be
    // delivered: both frames are awaited, and a failure becomes `Lost` instead
    // of ending the session silently. On reconnect the greeting restates the
    // same cursor, so the handshake converges.
    if !send_ctrl(to_inlet_tx, OutletToInlet::Written(tail_end)).await {
        return Err(Lost("could not deliver the final ack".into()));
    }
    if !send_ctrl(to_inlet_tx, OutletToInlet::Bye).await {
        return Err(Lost("could not deliver the goodbye".into()));
    }

    // The integrity verdict: what the inlet's source produced must equal what
    // we handed to the OS. A mismatch means a protocol bug corrupted the
    // stream — never exit 0.
    let Some(expected) = announced_checksum else {
        return Ok(Session::Fatal(
            "the inlet sent EOF without a checksum".into(),
        ));
    };
    if expected != written_digest {
        return Ok(Session::Fatal(format!(
            "checksum mismatch: the inlet sent {expected:#018x}, \
             we wrote {written_digest:#018x}: the stream is corrupt"
        )));
    }

    // All data is written and verified; `finish_sink` now sends the sink's own
    // EOF (flush + close) after its drain barrier, so the writer thread is
    // still alive to answer it.
    Ok(Session::Done)
}
