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
use crate::protocol::{HandshakePayload, InletToOutlet, OutletToInlet, SourceEnd};
use crate::sink::{self, Event as SinkEvent, Sink};
use crate::ui::{Phase, Ui, UiConfig};
use crate::signals::Termination;
use crate::{OutletArgs, app_config, link, net, signals};

const SINK_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a new connection may take to become usable (control stream greeted,
/// data stream opened). Expiring means "reconnect", never a verdict: resume is
/// exact, so redialling is always safe and cheaper than waiting on a peer that
/// may be gone.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a finished outlet stays reachable to re-answer a `Bye` that was
/// lost together with the connection it travelled on.
const GOODBYE_LINGER: Duration = Duration::from_secs(30);

/// Pause between dial attempts while lingering.
const LINGER_PAUSE: Duration = Duration::from_millis(250);

/// How long to keep the connection open after announcing cancellation, waiting
/// for the peer to close back (proof the cancellation frame was delivered).
/// Only then is the connection closed as a backstop.
const PEER_CLOSE_GRACE: Duration = Duration::from_secs(3);

/// How long a control-frame send may wait for the writer to take it before we
/// treat the connection as wedged. `mpsc::Sender::send` is cancel-safe, so a
/// timed-out send is *guaranteed* not to have delivered the frame: no silent
/// loss, the caller always knows.
const CTRL_GRACE: Duration = Duration::from_secs(3);

enum Session {
    Done { acknowledged: bool },
    /// The *peer* was cancelled (Ctrl-C/terminate): the stream is over but did
    /// not complete. This must surface as an error, not a clean exit.
    PeerCancelled,
    /// We ourselves were cancelled.
    Cancelled(Termination),
    /// Our downstream consumer is gone; the inlet must stop too.
    ConsumerGone,
    Fatal(String),
    /// No frame from the inlet for `net::STALL_TIMEOUT`: this connection is up
    /// but not carrying anything. Not a verdict — the transfer is untouched.
    Stalled(String),
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
    // 64 × 256 KiB = 16 MiB of slack in front of the blocking writer. The old
    // depth of two made the async reader wait for the writer thread to wake on
    // almost every chunk; locally that alone capped throughput at ~150 MB/s
    // even though the transport sustains >500 MB/s. Deeper than this showed no
    // further gain; the remaining cost is the separate control stream's share
    // of the transport scheduler.
    let (sink, sink_task) = sink::Sink::spawn(&args.common.path, 64, events_tx)?;

    // The sink's own cursor is the position source: it advances exactly when
    // bytes are handed to the OS, which is the truth the bar should show.
    let ui = Ui::start(
        &UiConfig::new(args.common.quiet),
        total,
        &sink.cursor_handle(),
    );
    ui.phase(Phase::Connecting);

    let (signal_tx, mut signal_rx) = mpsc::channel::<Termination>(1);
    signals::forward(signal_tx);

    let mut announced: Option<SourceEnd> = None;
    let mut attempt = 0u32;
    let mut lost_attempts = 0u32;
    let mut ever_connected = false;
    loop {
        // The resume point is a claim the inlet will trust: drain the writer to
        // a barrier *before* dialling, so everything below the cursor is on the
        // destination and nothing above it is still queued. Skipping this made
        // a reconnect resume from a stale snapshot and replay bytes the sink
        // had already queued — duplicated output, and a checksum mismatch.
        let _ = sink::drain(&sink, SINK_DRAIN_TIMEOUT).await;

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
                if let Some(why) = net::wait_for_retry(net::backoff(attempt), &mut signal_rx).await
                {
                    // Cancelled while retrying: exit like a signal handler.
                    signals::exit(why);
                }
                continue;
            }
            Err(e) => return Err(e),
        };

        match session(
            &conn,
            &sink,
            &mut events_rx,
            &mut announced,
            &mut signal_rx,
            &ui,
        )
        .await
        {
            Ok(Session::Done { acknowledged }) => {
                // `finalize` drained, verified and *committed* the destination
                // (the sink's EOF went out before `Bye`), so the transfer is
                // complete. If the inlet did not close back after the goodbye,
                // it may not have read `Bye` before the connection went away:
                // stay reachable for a moment and repeat it. If it *did* close
                // back, it has the goodbye and is gone — nothing to linger for.
                if !acknowledged {
                    linger(endpoint, &addr, peer_id, &sink, &mut signal_rx).await;
                }
                let _ = tokio::task::spawn_blocking(move || sink_task.join()).await;
                ui.finish_success();
                return Ok(());
            }
            Ok(Session::PeerCancelled) => {
                // The bytes received so far are a clean prefix: flush them,
                // but the exit must stay loud — the stream did not complete.
                let _ = finish_sink(&sink, sink_task, announced).await;
                return Err(eyre!(
                    "the inlet cancelled the transfer; \
                     the stream did not complete"
                ));
            }
            Ok(Session::Cancelled(why)) => signals::exit(why),
            Ok(Session::ConsumerGone) => signals::exit(Termination::ConsumerGone),
            Ok(Session::Fatal(msg)) => {
                tracing::error!("{msg}");
                return Err(color_eyre::eyre::eyre!(msg));
            }
            Ok(Session::Stalled(reason)) => {
                lost_attempts += 1;
                ui.clear_connection();
                ui.phase(Phase::Reconnecting {
                    attempt: lost_attempts,
                });
                tracing::warn!("{reason}; reconnecting");
                if let Some(why) =
                    net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                {
                    signals::exit(why);
                }
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
                    net::CloseKind::App(net::close::CANCELLED, _) => {
                        // The bytes received so far are a clean prefix: flush
                        // them, but the exit must stay loud — the stream did
                        // not complete.
                        let _ = finish_sink(&sink, sink_task, announced).await;
                        return Err(eyre!(
                            "the inlet cancelled the transfer; \
                             the stream did not complete"
                        ));
                    }
                    net::CloseKind::App(net::close::CONSUMER_GONE, _) => signals::exit(Termination::ConsumerGone),
                    net::CloseKind::App(net::close::FATAL, r) => {
                        return Err(eyre!("inlet reported a fatal error: {r}"));
                    }
                    net::CloseKind::App(net::close::DONE, r) => {
                        // The inlet closes with `DONE` only after it has our
                        // `Bye`, so this should be unreachable — and it is not a
                        // verdict either way, because the inlet also closes with
                        // code 0 when a connection handle is simply dropped.
                        // Reconnect: an exact resume costs nothing, and the
                        // ordered goodbye decides.
                        lost_attempts += 1;
                        ui.phase(Phase::Reconnecting {
                            attempt: lost_attempts,
                        });
                        tracing::warn!(
                            "inlet closed with 'done' ({r}) but never announced the end \
                             of its source; reconnecting"
                        );
                        if let Some(why) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::exit(why);
                        }
                    }
                    net::CloseKind::App(_, r) => {
                        // An unexpected application close is not a verdict we
                        // can trust as complete. Never exit 0 here. Flush the
                        // received prefix first: it is valid data even if the
                        // transfer as a whole failed.
                        let _ = finish_sink(&sink, sink_task, announced).await;
                        return Err(eyre!(
                            "inlet closed the connection unexpectedly ({r}); \
                             the stream is incomplete"
                        ));
                    }
                    net::CloseKind::Stalled(r) => {
                        // The inlet's watchdog dropped a connection that had
                        // stopped carrying frames. Not a cancellation: resume.
                        ui.phase(Phase::Reconnecting {
                            attempt: lost_attempts,
                        });
                        tracing::warn!("inlet stalled on its side ({r}); reconnecting");
                        if let Some(why) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::exit(why);
                        }
                    }
                    net::CloseKind::TimedOut => {
                        // Only an ordinary network failure may be retried.
                        ui.phase(Phase::Reconnecting {
                            attempt: lost_attempts,
                        });
                        tracing::warn!("connection lost: {reason}; reconnecting");
                        if let Some(why) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::exit(why);
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
                        if let Some(why) =
                            net::wait_for_retry(net::backoff(lost_attempts), &mut signal_rx).await
                        {
                            signals::exit(why);
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
    announced: Option<SourceEnd>,
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
    let Some(end) = announced else {
        return Err(eyre!(
            "the inlet never announced the end of its source: the stream could not be verified"
        ));
    };
    if end.checksum != written_digest {
        return Err(eyre!(
            "checksum mismatch: the inlet sent {:#018x}, \
             we wrote {written_digest:#018x}: the stream is corrupt",
            end.checksum
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

/// Stays reachable after a verified transfer, re-answering any inlet that comes
/// back.
///
/// The digest is final and nothing can be written any more, so `Bye` is always
/// truthful here. This is what keeps "the inlet never saw the goodbye" from
/// being fatal: the inlet reconnects exactly like after any other transport
/// loss and gets the same answer instead of retrying into the void. Bounded, so
/// a peer that is genuinely gone cannot keep this process alive.
async fn linger(
    endpoint: &Endpoint,
    addr: &EndpointAddr,
    peer: PublicKey,
    sink: &Sink,
    signals: &mut mpsc::Receiver<Termination>,
) {
    let deadline = tokio::time::Instant::now() + GOODBYE_LINGER;
    loop {
        let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
            return;
        };
        let dial = select! {
            biased;
            why = signals.recv() => signals::exit(why.unwrap_or(Termination::Interrupt)),
            res = timeout(remaining.min(HANDSHAKE_TIMEOUT), net::dial(endpoint, addr.clone())) => res,
        };
        let Ok(Ok(conn)) = dial else {
            // The inlet is still in its own backoff: wait, then try again.
            if let Some(why) = net::wait_for_retry(LINGER_PAUSE, signals).await {
                signals::exit(why);
            }
            continue;
        };
        if conn.remote_id() != peer {
            continue;
        }
        // Hold the receive half open: dropping it would stop the inlet's
        // control stream, and its `End` may still be on its way.
        let Ok(Ok((send, _recv))) = timeout(HANDSHAKE_TIMEOUT, conn.open_bi()).await else {
            continue;
        };
        let (tx, rx) = mpsc::channel::<OutletToInlet>(2);
        // A throwaway fault sink: nothing here is worth reporting.
        let (dead_tx, _dead_rx) = mpsc::channel::<link::Inbound<OutletToInlet>>(1);
        let writer = link::write_half(send, rx, dead_tx);
        let _ = tx.send(OutletToInlet::Written(sink.cursor())).await;
        let _ = tx.send(OutletToInlet::Bye).await;
        drop(tx);
        // The inlet hangs up as soon as it has the goodbye.
        let _ = timeout(PEER_CLOSE_GRACE, conn.closed()).await;
        let _ = timeout(CTRL_GRACE, writer).await;
        return;
    }
}

async fn session(
    conn: &Connection,
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    announced: &mut Option<SourceEnd>,
    signals: &mut mpsc::Receiver<Termination>,
    ui: &Ui,
) -> Result<Session, Lost> {
    // Each connection must deliver its own `End`: a value left over from a
    // previous connection would hide a session that never announced anything.
    *announced = None;

    let (control_send, control_recv) = conn.open_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_inlet_tx, to_inlet_rx) = mpsc::channel::<OutletToInlet>(8);
    // Frames and stream failures share one channel (see `link::Inbound`), so no
    // branch-order policy can decide whether this transfer succeeded.
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<link::Inbound<InletToOutlet>>(8);

    link::read_half(control_recv, inbound_tx.clone());
    let control_writer = link::write_half(control_send, to_inlet_rx, inbound_tx.clone());

    // The greeting *is* the resume request: whatever we have written, that is
    // where we want the inlet to start. The inlet answers by opening the data
    // stream, or with `Fatal` if it can no longer reproduce those bytes.
    let cursor = sink.cursor();
    if !send_ctrl(&to_inlet_tx, OutletToInlet::Written(cursor)).await {
        return Err(Lost("inlet left immediately".into()));
    }
    tracing::info!("connected; resuming at byte {cursor}");

    // Liveness. Frames arriving at all refresh `last_frame` — including the
    // inlet's `Alive` pings, which it sends even while its source is idle — and
    // this side restates its own liveness with a repeated `Written` (a cursor
    // that did not move carries no information, by design). Silence on both
    // counts for `STALL_TIMEOUT` therefore means the connection is not carrying
    // frames, not that there is nothing to send.
    let mut last_frame = tokio::time::Instant::now();
    let mut alive = tokio::time::interval(net::ALIVE_INTERVAL);
    alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    alive.tick().await; // the first tick is immediate

    let (data_end_tx, mut data_end_rx) = mpsc::channel::<()>(1);

    // Wait for the inlet's data stream while remaining responsive to control
    // frames: a rejected resume arrives as `Fatal` instead of a stream. The
    // wait is bounded — a peer that greets and then wedges must not hold this
    // side open until the transport's idle timeout.
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let data_recv = loop {
        select! {
            biased;

            received_sig = signals.recv() => {
                let why = received_sig.unwrap_or(Termination::Interrupt);
                let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Cancel).await;
                return Ok(Session::Cancelled(why));
            }

            Some(event) = inbound_rx.recv() => match event {
                link::Inbound::Frame(InletToOutlet::Alive) => {}
                link::Inbound::Frame(InletToOutlet::End(end)) => *announced = Some(end),
                link::Inbound::Frame(InletToOutlet::Cancel) => return Ok(Session::PeerCancelled),
                link::Inbound::Frame(InletToOutlet::Fatal(report)) => {
                    return Ok(Session::Fatal(report));
                }
                link::Inbound::Fault(fault) => return Err(Lost(fault)),
            },

            _ = conn.closed() => return Err(Lost("connection closed before data stream".into())),
            () = tokio::time::sleep_until(deadline) => {
                return Err(Lost("inlet did not open the data stream in time".into()));
            }

            accepted = conn.accept_uni() => match accepted {
                Ok(recv) => break recv,
                Err(e) => return Err(Lost(e.to_string())),
            },
        }
    };

    let data_pump =
        sink::pump(data_recv, sink.tx.clone(), data_end_tx, inbound_tx.clone());
    let mut data_finished = false;
    let mut verify = false;

    let outcome: Result<Session, Lost> = 'session: loop {
        select! {
            biased;

            // Local first, so Ctrl-C is reported promptly even while the
            // stream is saturated.
            received_sig = signals.recv() => {
                // The producer's Ctrl-C must reach the inlet: the source is
                // cancelled, so this goodbye is its only way to learn. Awaited
                // (bounded) so it cannot be silently dropped by a wedged
                // writer.
                let why = received_sig.unwrap_or(Termination::Interrupt);
                let _ = send_ctrl(&to_inlet_tx, OutletToInlet::Cancel).await;
                break 'session Ok(Session::Cancelled(why));
            }

            // Control frames outrank sink acks: a continuously acking sink
            // must never starve the inlet's end-of-source or cancellation.
            Some(event) = inbound_rx.recv() => {
                // Any frame at all, including a liveness ping, proves the
                // connection is still carrying frames.
                last_frame = tokio::time::Instant::now();
                match event {
                    // Nothing to report: the inlet is alive, that is all.
                    link::Inbound::Frame(InletToOutlet::Alive) => {}
                    link::Inbound::Frame(InletToOutlet::End(end)) => {
                        *announced = Some(end);
                        if data_finished {
                            verify = true;
                            break 'session Ok(Session::Done { acknowledged: false }); // placeholder, finalize below
                        }
                    }
                    link::Inbound::Frame(InletToOutlet::Cancel) => {
                        break 'session Ok(Session::PeerCancelled);
                    }
                    link::Inbound::Frame(InletToOutlet::Fatal(report)) => {
                        break 'session Ok(Session::Fatal(report));
                    }
                    link::Inbound::Fault(fault) => break 'session Err(Lost(fault)),
                }
            },

            // Liveness ping. A repeated `Written` is harmless: the inlet's
            // window ignores stale acks, so this says "still here" without
            // claiming anything new.
            _ = alive.tick() => {
                let _ = to_inlet_tx.try_send(OutletToInlet::Written(sink.cursor()));
            }

            // The inlet has said nothing at all for `STALL_TIMEOUT`, although
            // it pings whenever it is alive. Tear this connection down and
            // redial: the replay window makes that lossless, so a false
            // positive costs one reconnect while waiting costs the transfer.
            () = tokio::time::sleep_until(last_frame + net::STALL_TIMEOUT) => {
                break 'session Ok(Session::Stalled(format!(
                    "no frame from the inlet for {:?}",
                    net::STALL_TIMEOUT
                )));
            }

            // The data stream's FIN corroborates `End.total`: it says "no more
            // bytes are coming". Both facts are required, and neither is
            // trusted to arrive before the other.
            Some(()) = data_end_rx.recv() => {
                data_finished = true;
                ui.phase(Phase::Verifying);
                if announced.is_some() {
                    verify = true;
                    break 'session Ok(Session::Done { acknowledged: false }); // placeholder, finalize below
                }
            }

            Some(event) = events.recv() => match event {
                SinkEvent::Ack(n) => {
                    // try_send on purpose: a dropped ack is superseded by the
                    // next one, and the greeting on the next connection.
                    let _ = to_inlet_tx.try_send(OutletToInlet::Written(n));
                }
                SinkEvent::ConsumerGone => {
                    // Our consumer is gone. Tell the inlet so its producer dies
                    // too, then die like a pipe ourselves. Both frames are
                    // awaited (bounded): this goodbye is the producer's only
                    // consumer-gone verdict, so it must not be silently dropped by a wedged
                    // writer.
                    let _ = send_ctrl(&to_inlet_tx, OutletToInlet::ConsumerGone).await;
                    break 'session Ok(Session::ConsumerGone);
                }
                SinkEvent::Error(e) => break 'session Ok(Session::Fatal(e)),
            },

            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    // No new data may enter the queue after this point: a reconnect drain must
    // observe a fixed sink queue before taking its cursor. A *graceful* verdict
    // (cancel, broken pipe, fatal) is delivered on the control stream, so the
    // data stream is left alone: resetting it here would race the control frame
    // and could turn a clean cancellation into a spurious "lost connection".
    // It ends by itself when the connection closes.
    if outcome.is_err() || matches!(outcome, Ok(Session::Stalled(_))) {
        data_pump.abort();
    }

    // Finalize first: it sends the last `Written` and the `Bye`, so the
    // control sender (and the writer draining it) must still be alive.
    let verdict = if verify {
        finalize(sink, events, *announced, signals, &to_inlet_tx, conn).await
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

    // Announce the verdict at the transport level. When the peer still has to
    // *read* an in-band frame from us (`Bye` for success, `Cancel` for our own
    // cancellation) the connection must NOT be closed right away: `close`
    // discards stream data the peer's session loop has not consumed yet, even
    // when its transport already acknowledged it. Those two wait for the peer
    // to close back and close as a backstop otherwise; the rest close at once,
    // announcing the verdict even if the in-band frame was lost.
    match &verdict {
        Ok(Session::Cancelled(_)) => {
            if timeout(PEER_CLOSE_GRACE, conn.closed()).await.is_err() {
                net::close_intentional(conn, net::close::CANCELLED, "cancelled");
                tokio::time::sleep(net::CLOSE_PROPAGATE).await;
            }
        }
        Ok(Session::Done { acknowledged: false }) => {
            // `Bye` is delivered when this returns, not when it was queued: the
            // wait above ends once the peer's *transport* acknowledged the
            // frame, which says nothing about the peer's session loop having
            // read it. Closing here discards the still-unread frame, and the
            // inlet then reports "outlet closed with 'done' but never said
            // Bye" for a transfer that verified perfectly. So let the inlet
            // close back first: it does so with `DONE` the moment it sees
            // `Bye`, which is the application-level acknowledgement the
            // protocol asks for. Same choreography as cancellation above.
            //
            // Report which one happened: only an *unacknowledged* goodbye
            // needs the linger below. Re-dialling a peer that has provably read
            // the goodbye and hung up would keep this process alive for no
            // reason (and hold the user's "verifying" spinner up with it).
            return Ok(Session::Done {
                acknowledged: if let Ok(err) = timeout(PEER_CLOSE_GRACE, conn.closed()).await {
                    tracing::info!("inlet closed back after the goodbye: {err}");
                    true
                } else {
                    net::close_intentional(conn, net::close::DONE, "done");
                    tokio::time::sleep(net::CLOSE_PROPAGATE).await;
                    false
                },
            });
        }
        Ok(Session::PeerCancelled) => {
            net::close_intentional(conn, net::close::CANCELLED, "cancelled");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::ConsumerGone) => {
            net::close_intentional(conn, net::close::CONSUMER_GONE, "consumer gone");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::Fatal(msg)) => {
            net::close_intentional(conn, net::close::FATAL, &msg[..msg.len().min(256)]);
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::Stalled(reason)) => {
            // A transport verdict, not a cancellation: drop the connection,
            // not the transfer. The close code says which one this is.
            net::close_intentional(conn, net::close::STALLED, &reason[..reason.len().min(256)]);
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        // The first pattern is unreachable from here: only the branch above
        // ever sets the flag, and it returns. Kept for exhaustiveness.
        Ok(Session::Done { acknowledged: true }) | Err(Lost(_)) => {}
    }
    verdict
}

/// Called once the data stream FIN and the checksum are both in hand. Drains
/// the sink, reports the true final cursor, verifies the digest and says
/// goodbye. It stays responsive to Ctrl-C and a dead consumer.
async fn finalize(
    sink: &Sink,
    events: &mut mpsc::Receiver<SinkEvent>,
    announced: Option<SourceEnd>,
    signals: &mut mpsc::Receiver<Termination>,
    to_inlet_tx: &mpsc::Sender<OutletToInlet>,
    conn: &Connection,
) -> Result<Session, Lost> {
    // The inlet is still waiting for our `Bye` while this drain runs, and its
    // watchdog is armed: a slow sink can take longer than `STALL_TIMEOUT` to
    // flush the tail, so keep the liveness pings going until the verdict is in
    // hand. Without this a slow destination would look exactly like a dead
    // connection to the inlet, and it would drop a transfer that is about to
    // succeed.
    let mut alive = tokio::time::interval(net::ALIVE_INTERVAL);
    alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    alive.tick().await; // the first tick is immediate

    let final_offset = 'drain: loop {
        select! {
            biased;

            received_sig = signals.recv() => {
                // The tail is not acknowledged yet, so the inlet must not
                // mistake our close for success. Same contract as the main
                // session loop: report the cancellation before returning.
                let why = received_sig.unwrap_or(Termination::Interrupt);
                let _ = send_ctrl(to_inlet_tx, OutletToInlet::Cancel).await;
                return Ok(Session::Cancelled(why));
            }
            _ = conn.closed() => {
                return Err(Lost("connection closed while draining the tail".into()));
            }

            Some(event) = events.recv() => match event {
                SinkEvent::ConsumerGone => {
                    let _ = send_ctrl(to_inlet_tx, OutletToInlet::ConsumerGone).await;
                    return Ok(Session::ConsumerGone);
                }
                SinkEvent::Error(e) => return Ok(Session::Fatal(e)),
                SinkEvent::Ack(n) => {
                    // A write during the drain advanced the cursor. The final
                    // `Written` below covers it, but forward late acks so the
                    // greeting of a reconnect stays truthful.
                    let _ = send_ctrl(to_inlet_tx, OutletToInlet::Written(n)).await;
                }
            },

            // Still here, still draining: the same liveness ping as in the
            // session loop, and for the same reason.
            _ = alive.tick() => {
                let _ = to_inlet_tx.try_send(OutletToInlet::Written(sink.cursor()));
            }

            verdict = sink::drain(sink, Duration::MAX) => break 'drain verdict,
        }
    };

    let Some((tail_end, written_digest)) = final_offset else {
        return Ok(Session::Fatal(
            "sink stopped before the tail was written".into(),
        ));
    };

    // The verdict has two independent parts: the exact length, which catches a
    // truncation or an overrun that a colliding digest would hide, and the
    // digest of every byte handed to the destination. `Bye` is the inlet's only
    // success signal, so it must never travel before both hold.
    let Some(end) = announced else {
        return Ok(Session::Fatal(
            "the inlet ended without announcing the source length".into(),
        ));
    };
    if tail_end != end.total {
        return Ok(Session::Fatal(format!(
            "the stream ended at byte {tail_end} but the inlet's source is {} bytes: \
             the stream is incomplete",
            end.total
        )));
    }
    if end.checksum != written_digest {
        return Ok(Session::Fatal(format!(
            "checksum mismatch: the inlet sent {:#018x}, \
             we wrote {written_digest:#018x}: the stream is corrupt",
            end.checksum
        )));
    }

    // Commit the destination before announcing it. `Bye` means "written and
    // verified", so the flush and the close must already have happened: a
    // success reported ahead of the sink's own EOF would let the inlet exit 0
    // for a destination this side has not finished.
    if timeout(CTRL_GRACE, sink.tx.send(sink::Msg::Eof))
        .await
        .is_err()
    {
        return Ok(Session::Fatal(
            "the sink stopped before the tail was committed".into(),
        ));
    }

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

    Ok(Session::Done { acknowledged: false })
}
