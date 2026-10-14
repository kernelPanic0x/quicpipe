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
use crate::protocol::{OutletToInlet, HandshakePayload, InletToOutlet};
use crate::sink::{self, Event as SinkEvent, Sink};
use crate::{OutletArgs, app_config, link, net, signals};

const SINK_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to keep the connection open after announcing cancellation, waiting
/// for the peer to close back (proof the SIGINT frame was delivered). Only then
/// is the connection closed as a backstop.
const PEER_CLOSE_GRACE: Duration = Duration::from_secs(3);

/// How many consecutive reconnects the outlet tolerates after a lost
/// connection before concluding the inlet is gone for good. An idle timeout on
/// a live network recovers well within this; a hard-killed inlet never will.
const MAX_RECONNECTS: u32 = 10;

/// How long a control-frame send may wait for the writer to take it before we
/// treat the connection as wedged. `mpsc::Sender::send` is cancel-safe, so a
/// timed-out send is *guaranteed* not to have delivered the frame: no silent
/// loss, the caller always knows.
const CTRL_GRACE: Duration = Duration::from_secs(3);

enum Session {
    Done,
    PeerBye,
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

    let mailbox = MailboxConnection::connect(
        app_config(&args.common),
        code.expect("Code set"),
        false,
    )
    .await?;
    let mut wormhole = Wormhole::connect(mailbox).await?;
    wormhole
        .send(wincode::serialize(&net::payload_for(endpoint, key))?)
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
    tracing::info!("connecting to {}", peer_id.fmt_short());

    let (events_tx, mut events_rx) = mpsc::channel::<SinkEvent>(64);
    let (sink, sink_task) = sink::Sink::spawn(&args.common.path, 2, events_tx)?;

    let (signal_tx, mut signal_rx) = mpsc::channel::<i32>(1);
    signals::forward(signal_tx);

    let mut attempt = 0u32;
    let mut lost_attempts = 0u32;
    loop {
        let conn = match net::dial(endpoint, addr.clone()).await {
            Ok(conn) => {
                // A successful dial only resets the backoff; the reconnect
                // budget below renews on *progress*, so a peer that accepts
                // connections but never delivers data still gets bounded.
                attempt = 0;
                conn
            }
            Err(e) if net::transient(&e) => {
                attempt += 1;
                lost_attempts += 1;
                if lost_attempts > MAX_RECONNECTS {
                    return Err(eyre!(
                        "cannot reach the inlet after {MAX_RECONNECTS} attempts: {e}"
                    ));
                }
                tracing::warn!("connect failed: {e}; retrying");
                if let Some(sig) = net::wait_for_retry(net::backoff(attempt), &mut signal_rx).await {
                    // Cancelled while retrying: exit like a signal handler.
                    signals::die_of(sig);
                }
                continue;
            }
            Err(e) => return Err(e),
        };

        let progress_before = sink.cursor();
        match session(&conn, &sink, &mut events_rx, &mut signal_rx).await {
            Ok(Session::Done | Session::PeerBye) => {
                // The sink may still be flushing the tail; let it finish so the
                // last bytes reach the consumer. A stalled sink is an error:
                // the stream did not fully reach the consumer.
                finish_sink(&sink, sink_task).await?;
                return Ok(());
            }
            Ok(Session::PeerCancelled) => {
                // The bytes received so far are a clean prefix: flush them,
                // but the exit must stay loud — the stream did not complete.
                let _ = finish_sink(&sink, sink_task).await;
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
                // The reconnect budget renews only on actual progress: data
                // that reached the consumer since the last attempt. A peer
                // that accepts dials but never delivers stays bounded.
                if sink.cursor() > progress_before {
                    lost_attempts = 0;
                }
                lost_attempts += 1;
                // First ask the connection why it ended. An application close
                // means the inlet made a final decision and must not be
                // second-guessed by a reconnect — this is what keeps the
                // outlet from redialling an inlet that exited via Ctrl+C.
                match net::close_kind(&conn).await {
                    net::CloseKind::App(net::close::CANCEL, _) => {
                        // The bytes received so far are a clean prefix: flush
                        // them, but the exit must stay loud — the stream did
                        // not complete.
                        let _ = finish_sink(&sink, sink_task).await;
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
                        let _ = finish_sink(&sink, sink_task).await;
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
                        let _ = finish_sink(&sink, sink_task).await;
                        return Err(eyre!(
                            "inlet closed the connection unexpectedly ({r}); \
                             the stream is incomplete"
                        ));
                    }
                    net::CloseKind::TimedOut => {
                        // Only an ordinary network failure may be retried.
                        if lost_attempts > MAX_RECONNECTS {
                            return Err(eyre!(
                                "connection lost {MAX_RECONNECTS} times without the \
                                 inlet coming back; giving up (timed out)"
                            ));
                        }
                        tracing::warn!("connection lost: {reason}; reconnecting");
                        if let Some(sig) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::die_of(sig);
                        }
                    }
                    net::CloseKind::Lost(why) => {
                        // Only an ordinary network failure may be retried.
                        if lost_attempts > MAX_RECONNECTS {
                            return Err(eyre!(
                                "connection lost {MAX_RECONNECTS} times without the \
                                 inlet coming back; giving up ({why})"
                            ));
                        }
                        tracing::warn!("connection lost: {reason}; reconnecting");
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

/// Lets the sink flush the tail, then joins its thread. The sink runs on its
/// own thread, so drain first (bounded), then join.
///
/// Returns an error if the sink did not drain within the budget: exiting
/// successfully with unwritten tail bytes would be silent truncation, and
/// data integrity outranks a slow consumer.
async fn finish_sink(
    sink: &sink::Sink,
    sink_task: std::thread::JoinHandle<()>,
) -> Result<()> {
    if sink::drain(sink, SINK_DRAIN_TIMEOUT).await.is_none() {
        return Err(eyre!(
            "the sink did not write its tail within {SINK_DRAIN_TIMEOUT:?}; \
             the stream is incomplete"
        ));
    }
    // The drain barrier is answered, so the writer thread is alive: now it
    // takes the EOF, which flushes and closes the fd for downstream readers.
    if timeout(CTRL_GRACE, sink.tx.send(sink::Msg::Eof)).await.is_err() {
        return Err(eyre!("the sink did not accept EOF"));
    }
    let _ = tokio::task::spawn_blocking(move || sink_task.join()).await;
    Ok(())
}

async fn session(
    conn: &Connection,
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    signals: &mut mpsc::Receiver<i32>,
) -> Result<Session, Lost> {
    let (send, recv) = conn.open_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_inlet_tx, to_inlet_rx) = mpsc::channel::<OutletToInlet>(4);
    let (from_inlet_tx, mut from_inlet_rx) = mpsc::channel::<InletToOutlet>(4);
    let (faults_tx, mut faults_rx) = mpsc::channel::<String>(2);
    let mut announced_checksum: Option<u64> = None;

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
    tracing::info!("connected; resuming at byte {cursor}");

    let outcome: Result<Session, Lost> = 'session: loop {
        select! {
            biased;

            // Local first, so Ctrl-C and a broken downstream are reported
            // promptly even while the stream is saturated.
            received_sig = signals.recv() => {
                // The producer's Ctrl-C must reach the inlet: the source dies
                // of SIGINT, so this goodbye is its only way to learn. Awaited
                // (bounded) so it cannot be silently dropped by a wedged
                // writer.
                let sig = received_sig.unwrap_or(libc::SIGINT);
                let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGINT).await;
                break 'session Ok(Session::Interrupted(sig));
            }

            // Peer control frames outrank sink acks: a continuously acking
            // sink must never starve the inlet's SIGINT/EOF/Bye frames, or
            // cancellation and the final handshake stall while the inlet's
            // close destroys the unacked frame.
            Some(msg) = from_inlet_rx.recv() => match msg {
                InletToOutlet::EOF => {
                    // Let the sink finish the tail. Deliberately *no* timeout:
                    // a slow consumer is the downstream's own backpressure,
                    // exactly as with an ordinary pipe, and exiting before the
                    // tail is written would hang the inlet's window forever.
                    // Instead the drain races the sink's own failure, so a
                    // dead consumer surfaces here as SIGPIPE rather than
                    // hanging the barrier.
                    let final_offset = 'drain: loop {
                        select! {
                            biased;

                            Some(f) = faults_rx.recv() => break 'session Err(Lost(f)),

                            // Promptness over ack-forwarding: a late ack is
                            // recoverable, a missed Ctrl-C or a dead
                            // connection is not.
                            received_sig = signals.recv() => {
                                break 'session Ok(Session::Interrupted(
                                    received_sig.unwrap_or(libc::SIGINT),
                                ))
                            }
                            _ = conn.closed() => {
                                break 'session Err(Lost(
                                    "connection closed while draining the tail".into(),
                                ))
                            }

                            Some(event) = events.recv() => match event {
                                SinkEvent::BrokenPipe => {
                                    // The consumer exited mid-tail. What it
                                    // consumed is the true final count, and
                                    // the producer upstream must get SIGPIPE.
                                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGPIPE).await;
                                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Bye).await;
                                    break 'session Ok(Session::BrokenPipe);
                                }
                                SinkEvent::Error(e) => break 'session Ok(Session::Fatal(e)),
                                SinkEvent::Ack(n) => {
                                    // A write during the drain advanced the
                                    // cursor. The final `Received` below
                                    // covers it, but forward late acks so the
                                    // greeting of a reconnect stays truthful.
                                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Received(n)).await;
                                }
                                // Impossible mid-tail: the inlet replays from
                                // our cursor, so it can never start beyond it.
                                SinkEvent::Gap { .. } => {}
                            },

                            verdict = sink::drain(sink, Duration::MAX) => break 'drain verdict,
                        }
                    };
                    let Some((tail_end, written_digest)) = final_offset else {
                        break 'session Ok(Session::Fatal(
                            "sink stopped before the tail was written".into(),
                        ));
                    };

                    // The goodbye is the inlet's only way to reach `Done`, so
                    // it must be delivered: both frames are awaited, and a
                    // failure breaks `Lost` instead of ending the session
                    // silently. On reconnect the greeting restates the same
                    // cursor, so the handshake converges.
                    if !send_ctrl(&to_inlet_tx, OutletToInlet::Received(tail_end)).await {
                        break 'session Err(Lost("could not deliver the final ack".into()));
                    }
                    if !send_ctrl(&to_inlet_tx, OutletToInlet::Bye).await {
                        break 'session Err(Lost("could not deliver the goodbye".into()));
                    }

                    // The integrity verdict: what the inlet's source produced
                    // must equal what we handed to the OS. A mismatch means a
                    // protocol bug corrupted the stream — never exit 0.
                    let Some(expected) = announced_checksum else {
                        break 'session Ok(Session::Fatal(
                            "the inlet sent EOF without a checksum".into(),
                        ));
                    };
                    if expected != written_digest {
                        break 'session Ok(Session::Fatal(format!(
                            "checksum mismatch: the inlet sent {expected:#018x}, \
                             we wrote {written_digest:#018x}: the stream is corrupt"
                        )));
                    }

                    // All data is written and verified; `finish_sink` now
                    // sends the sink's own EOF (flush + close) after its drain
                    // barrier, so the writer thread is still alive to answer it.
                    break 'session Ok(Session::Done);
                }
                InletToOutlet::Checksum(sum) => {
                    // Arrives before EOF; the verdict is enforced there.
                    announced_checksum = Some(sum);
                }
                InletToOutlet::SIGINT => break 'session Ok(Session::PeerCancelled),
                InletToOutlet::Fatal(report) => break 'session Ok(Session::Fatal(report)),
                InletToOutlet::Bye => break 'session Ok(Session::PeerBye),
                InletToOutlet::Data { .. } => {
                    break 'session Err(Lost("data frame reached the session".into()))
                }
            },

            Some(event) = events.recv() => match event {
                SinkEvent::Ack(n) => {
                    // try_send on purpose: a dropped ack is superseded by the
                    // next one, and the greeting on the next connection.
                    let _ = to_inlet_tx.try_send(OutletToInlet::Received(n));
                }                SinkEvent::BrokenPipe => {
                    // Our consumer is gone. Tell the inlet so its producer dies
                    // too, then die like a pipe ourselves. Both frames are
                    // awaited (bounded): this goodbye is the producer's only
                    // SIGPIPE, so it must not be silently dropped by a wedged
                    // writer.
                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::SIGPIPE).await;
                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Bye).await;
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

            Some(fault) = faults_rx.recv() => break 'session Err(Lost(fault)),
            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    drop(to_inlet_tx);
    let _ = timeout(Duration::from_secs(3), writer).await;

    // Announce the verdict at the transport level. For cancellation the
    // connection must NOT be closed right away: `close` discards stream data
    // that has not been acked, which could destroy the in-flight SIGINT frame.
    // Wait for the peer to close back first; close as a backstop otherwise.
    match &outcome {
        Ok(Session::Interrupted(_)) => {
            if timeout(PEER_CLOSE_GRACE, conn.closed()).await.is_err() {
                net::close_intentional(conn, net::close::CANCEL, "SIGINT");
                tokio::time::sleep(net::CLOSE_PROPAGATE).await;
            }
        }
        Ok(Session::Done | Session::PeerBye) => {
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
    outcome
}
