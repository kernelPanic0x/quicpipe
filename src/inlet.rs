//! The producer side: source, replay window, reconnect loop. It never re-reads
//! its source, so stdin and a seekable file are handled identically.

use std::collections::VecDeque;

use bytes::Bytes;
use color_eyre::eyre::{Result, eyre};
use iroh::endpoint::{Connection, Endpoint};
use iroh::{PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::protocol::*;
use crate::replay::Window;
use crate::{InletArgs, app_config, link, net, signals, source};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const CTRL_GRACE: Duration = Duration::from_secs(3);

/// How long to keep the connection open after announcing cancellation, waiting
/// for the peer to close back (proof the SIGINT frame was delivered). Only then
/// is the connection closed as a backstop.
const PEER_CLOSE_GRACE: Duration = Duration::from_secs(3);

enum Session {
    /// Everything sent and acknowledged.
    Done,
    PeerBye,
    Interrupted,
    /// The peer's stdout is gone, so ours should die of SIGPIPE too.
    SigPipe,
    Fatal(String),
}

/// "The connection went away" — the one thing worth retrying.
struct Lost(String);

pub async fn run(args: InletArgs) -> Result<()> {
    let common = &args.common;
    let key = SecretKey::generate();
    let endpoint = net::bind(&key, true).await?;

    let mailbox = MailboxConnection::create(app_config(common), args.code_length).await?;
    eprintln!("Wormhole Code: {}", mailbox.code());
    tracing::info!("waiting for the other end...");
    let mut wormhole = Wormhole::connect(mailbox).await?;
    wormhole
        .send(wincode::serialize(&net::payload_for(&endpoint, &key))?)
        .await?;
    let peer: HandshakePayload = wincode::deserialize(&wormhole.receive().await?)?;
    let peer_id = PublicKey::from_bytes(&peer.public_key)?;
    tracing::info!("peer is {}", peer_id.fmt_short());

    let mut source = source::spawn(&common.path, 2)?;
    let (signal_tx, mut signal_rx) = mpsc::channel(1);
    signals::forward(signal_tx);

    let mut window = Window::new(MAX_BUFFERED_BYTES as u64);
    let mut source_done = false;

    loop {
        let Some(conn) = accept(&endpoint, peer_id, &mut signal_rx).await else {
            // Cancelled while waiting for a connection: die like a signal
            // handler should, so the exit code says 130, not 0.
            signals::die_of(libc::SIGINT);
        };

        match session(
            &conn,
            &mut window,
            &mut source.rx,
            &mut source_done,
            &mut signal_rx,
        )
        .await
        {
            Ok(Session::Done) | Ok(Session::PeerBye) => return Ok(()),
            Ok(Session::Interrupted) => signals::die_of(libc::SIGINT),
            Ok(Session::SigPipe) => signals::die_of(libc::SIGPIPE),
            Ok(Session::Fatal(msg)) => return Err(eyre!(msg)),
            Err(Lost(reason)) => {
                // A lost connection is only worth waiting on if the peer did
                // not leave on purpose: its close code is the definitive
                // verdict, surviving even a lost in-band control frame.
                match net::close_kind(&conn).await {
                    net::CloseKind::App(net::close::DONE, _) => return Ok(()),
                    net::CloseKind::App(net::close::CANCEL, _) => signals::die_of(libc::SIGINT),
                    net::CloseKind::App(net::close::SIGPIPE, _) => signals::die_of(libc::SIGPIPE),
                    net::CloseKind::App(net::close::FATAL, r) => {
                        return Err(eyre!("outlet reported a fatal error: {r}"));
                    }
                    net::CloseKind::App(code, r) => {
                        tracing::warn!("outlet closed the connection ({code}: {r})");
                        return Ok(());
                    }
                    net::CloseKind::TimedOut | net::CloseKind::Lost(_) => {
                        tracing::warn!("connection lost: {reason}; waiting for a reconnect");
                    }
                }
            }
        }
    }
}

/// Queues a control frame on a possibly congested channel: the writer drains
/// it continuously, so poll until it accepts the frame instead of betting on a
/// single timed send.
async fn queue_ctrl(tx: &mpsc::Sender<InletToOutlet>, msg: InletToOutlet) {
    let deadline = tokio::time::Instant::now() + CTRL_GRACE;
    loop {
        match tx.try_send(msg.clone()) {
            Ok(()) => return,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(_) => return, // session torn down; the close code takes over
        }
    }
}

/// Accepts only connections from the endpoint we rendezvoused with.
async fn accept(
    endpoint: &Endpoint,
    peer: PublicKey,
    signals: &mut mpsc::Receiver<()>,
) -> Option<Connection> {
    loop {
        let incoming = select! {
            biased;
            _ = signals.recv() => return None,
            incoming = endpoint.accept() => incoming?,
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
        return Some(conn);
    }
}

async fn session(
    conn: &Connection,
    window: &mut Window,
    source: &mut mpsc::Receiver<source::Msg>,
    source_done: &mut bool,
    signals: &mut mpsc::Receiver<()>,
) -> Result<Session, Lost> {
    let (send, recv) = conn.accept_bi().await.map_err(|e| Lost(e.to_string()))?;

    let (to_outlet_tx, to_outlet_rx) = mpsc::channel::<InletToOutlet>(2);
    let (from_outlet_tx, mut from_outlet_rx) = mpsc::channel::<OutletToInlet>(4);
    let (faults_tx, mut faults_rx) = mpsc::channel::<String>(2);

    link::read_half(recv, from_outlet_tx, faults_tx.clone());
    let writer = link::write_half(send, to_outlet_rx, faults_tx.clone());

    // The first frame is the outlet saying how much it has written, which is
    // also exactly where it wants us to resume from.
    let resume_from = match timeout(HANDSHAKE_TIMEOUT, from_outlet_rx.recv()).await {
        Ok(Some(OutletToInlet::Received(n))) => n,
        Ok(Some(other)) => return Err(Lost(format!("expected the resume point, got {other:?}"))),
        Ok(None) => return Err(Lost("outlet left before greeting".into())),
        Err(_) => return Err(Lost("outlet did not greet us in time".into())),
    };

    let mut backlog: VecDeque<(u64, Bytes)> = match window.replay_from(resume_from) {
        Ok(chunks) => chunks.into(),
        Err(out_of_range) => {
            // Bytes are gone. Inventing them would silently corrupt the stream,
            // so refuse loudly and let the exit code carry the verdict.
            let msg = out_of_range.to_string();
            tracing::error!("{msg}");
            net::close_intentional(conn, net::close::FATAL, "fatal");
            let _ = timeout(
                CTRL_GRACE,
                to_outlet_tx.send(InletToOutlet::Fatal(msg.clone())),
            )
            .await;
            drop(to_outlet_tx);
            let _ = timeout(CTRL_GRACE, writer).await;
            return Ok(Session::Fatal(msg));
        }
    };

    // The resume point is acknowledged: the bytes below it can leave the window
    // and the accounting after a reconnect starts from where the peer is.
    window.ack(resume_from);

    tracing::info!(
        "outlet connected; replaying from byte {resume_from} \
         ({} chunks buffered, {} unacknowledged)",
        backlog.len(),
        window.unacked()
    );

    let mut eof_queued = false;
    let outcome: Result<Session, Lost> = 'session: loop {
        // All control frames are delivered here, with an await, so none of them
        // can be lost to a full channel. The body runs after the select has
        // completed, so a brief await can only delay Lost detection, never
        // corrupt framing: each frame is tiny and the writer forwards promptly.
        // Top-of-loop, so it fires even when the final ack arrived in the same
        // iteration as the last data frame.
        if *source_done && !eof_queued && backlog.is_empty() {
            // EOF goes first and alone: everything the source produced is now
            // either buffered for replay or already sent, so the true end of
            // the stream is this exact frame — however many connections it
            // takes to deliver it.
            let _ = timeout(CTRL_GRACE, to_outlet_tx.send(InletToOutlet::EOF)).await;
            eof_queued = true;
        }
        if *source_done && eof_queued && window.unacked() == 0 {
            let _ = timeout(CTRL_GRACE, to_outlet_tx.send(InletToOutlet::Bye)).await;
            break 'session Ok(Session::Done);
        }

        // Replay strictly before new bytes: order is the contract, and the
        // source is only read once the backlog is drained and the window has
        // room. That guard is the backpressure.
        let can_replay = !backlog.is_empty() && to_outlet_tx.capacity() > 0;
        let has_room = !window.is_full() && to_outlet_tx.capacity() > 0;
        let can_pull = !*source_done && has_room && backlog.is_empty();

        select! {
            biased;

            // A stream task died, which means the connection is gone.
            Some(fault) = faults_rx.recv() => break 'session Err(Lost(fault)),

            _ = signals.recv() => {
                // The channel may be jammed with data frames queued behind a
                // congested stream; the writer drains it continuously, so poll
                // until it takes the cancellation frame instead of betting on
                // a single timed send.
                queue_ctrl(&to_outlet_tx, InletToOutlet::SIGINT).await;
                break 'session Ok(Session::Interrupted);
            }

            Some(msg) = from_outlet_rx.recv() => match msg {
                OutletToInlet::Received(n) => window.ack(n),
                OutletToInlet::Bye => break 'session Ok(Session::PeerBye),
                OutletToInlet::SIGINT => break 'session Ok(Session::Interrupted),
                OutletToInlet::SIGPIPE => break 'session Ok(Session::SigPipe),
            },

            _ = std::future::ready(()), if can_replay => {
                if let Some((offset, payload)) = backlog.pop_front() {
                    let _ = to_outlet_tx.try_send(InletToOutlet::Data { offset, payload });
                }
            }

            // Exactly one branch may touch the source. `select!` evaluates every
            // branch's async expression before polling any of them, so a second
            // `source.recv()` would be a second simultaneous `&mut *source` —
            // and a disabled branch is still evaluated.
            msg = source.recv(), if can_pull => match msg {
                Some(source::Msg::Data(chunk)) => {
                    let (offset, payload) = window.push(chunk);
                    let _ = to_outlet_tx.try_send(InletToOutlet::Data { offset, payload });
                }
                Some(source::Msg::Eof) => {
                    *source_done = true;
                }
                Some(source::Msg::Error(e)) => {
                    let _ = timeout(CTRL_GRACE, to_outlet_tx.send(InletToOutlet::Fatal(e.clone()))).await;
                    break 'session Ok(Session::Fatal(e));
                }
                // The only sender lives inside the source thread, so a closed
                // channel with neither `Eof` nor `Error` means it died
                // abnormally. The stream may be truncated, and claiming a clean
                // EOF for a truncated stream is the one lie worth avoiding.
                None => {
                    let msg = "source thread exited without finishing".to_string();
                    let _ = timeout(CTRL_GRACE, to_outlet_tx.send(InletToOutlet::Fatal(msg.clone()))).await;
                    break 'session Ok(Session::Fatal(msg));
                }
            },

            _ = conn.closed() => break 'session Err(Lost("connection closed".into())),
        }
    };

    // Dropping the sender ends the writer task, which flushes and finishes the
    // stream. Waiting for it means a queued `Bye` or `Fatal` still lands.
    drop(to_outlet_tx);
    let _ = timeout(CTRL_GRACE, writer).await;

    // Announce the verdict at the transport level. For cancellation the
    // connection must NOT be closed right away: `close` discards stream data
    // that has not been acked, which could destroy the in-flight SIGINT frame.
    // The stream is the reliable channel (QUIC retransmits it until acked), so
    // cancellation waits for the peer to close back; everything else closes as
    // a backstop announcing the verdict even if the in-band frame was lost.
    match &outcome {
        Ok(Session::Interrupted) => {
            if timeout(PEER_CLOSE_GRACE, conn.closed()).await.is_err() {
                net::close_intentional(conn, net::close::CANCEL, "SIGINT");
                tokio::time::sleep(net::CLOSE_PROPAGATE).await;
            }
        }
        Ok(Session::Done | Session::PeerBye) => {
            net::close_intentional(conn, net::close::DONE, "done");
            tokio::time::sleep(net::CLOSE_PROPAGATE).await;
        }
        Ok(Session::SigPipe) => {
            net::close_intentional(conn, net::close::SIGPIPE, "SIGPIPE");
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
