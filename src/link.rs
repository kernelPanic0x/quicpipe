//! The two halves of a QUIC stream, each owned by exactly one task.
//!
//! This exists so that no `select!` ever races an in-flight read or write:
//! reading a length-delimited frame is *not* cancel-safe, so a task that owns a
//! whole frame at a time is the only way to keep the framing honest.
//!
//! Everything a session learns from its transport — frames and the failure of a
//! stream task — arrives through **one** channel ([`Inbound`]), so no ordering
//! between two ready inputs ever has to be reasoned about.
//!
//! Connection setup (bind, dial, retry/backoff) lives in `net.rs`.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::net::FLUSH_GRACE;
use crate::protocol::{Encoder, WireCodec};

/// Everything a session can learn from its transport, on one channel.
///
/// This type is the fix for a whole class of race: with frames and stream
/// failures on separate channels, "which one is ready first" decides the
/// outcome, and a dead stream task can preempt a verdict the peer has already
/// sent (a `Bye` sitting unread in the other channel). One channel means one
/// order — the order things actually happened — so no `select!` branch policy
/// can decide whether a transfer succeeded.
#[derive(Debug)]
pub enum Inbound<T> {
    /// A decoded frame, in the order the peer sent it.
    Frame(T),
    /// A stream task died: the transport is gone, or framing broke. Never a
    /// verdict by itself; only the caller knows whether a lost transport is
    /// worth reconnecting.
    Fault(String),
}

/// Feeds decoded frames, and its own failure, to `tx` until the stream ends.
pub fn read_half<T: Encoder + Send + 'static>(recv: RecvStream, tx: mpsc::Sender<Inbound<T>>) {
    tokio::spawn(async move {
        let mut frames = FramedRead::new(recv, WireCodec::<T>::new());
        while let Some(frame) = frames.next().await {
            let msg = match frame {
                Ok(msg) => msg,
                Err(e) => {
                    let _ = tx.try_send(Inbound::Fault(format!("read: {e}")));
                    return;
                }
            };
            if tx.send(Inbound::Frame(msg)).await.is_err() {
                return; // session gone
            }
        }
    });
}

/// Writes raw bytes until the channel closes, then FINs the stream.
///
/// There is no framing here on purpose: QUIC already delivers this stream in
/// order and intact. Reconnect continuity is established by the control
/// handshake, not by per-chunk offsets.
///
/// Generic over `T` only because the fault it reports has to travel on the
/// session's single inbound channel; it never produces a frame of its own.
pub fn write_bytes<I: Send + 'static>(
    mut send: SendStream,
    mut rx: mpsc::Receiver<Bytes>,
    faults: mpsc::Sender<Inbound<I>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            if let Err(e) = send.write_all(&chunk).await {
                let _ = faults.try_send(Inbound::Fault(format!("write data: {e}")));
                return;
            }
        }
        let _ = send.finish();
        let _ = timeout(FLUSH_GRACE, send.stopped()).await;
    })
}

/// Publishes outbound frames until the channel closes, then finishes the stream
/// cleanly and waits (bounded) for the peer to acknowledge the last byte.
pub fn write_half<T: Encoder + Send + 'static, I: Send + 'static>(
    send: SendStream,
    mut rx: mpsc::Receiver<T>,
    faults: mpsc::Sender<Inbound<I>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut frames = FramedWrite::new(send, WireCodec::<T>::new());
        while let Some(msg) = rx.recv().await {
            if let Err(e) = frames.send(msg).await {
                let _ = faults.try_send(Inbound::Fault(format!("write: {e}")));
                return;
            }
        }
        // Closing the channel means "no more frames". finish() sends the FIN and
        // is implied by Drop anyway, but doing it here lets us wait for the ack.
        let mut send = frames.into_inner();
        let _ = send.finish();
        let _ = timeout(FLUSH_GRACE, send.stopped()).await;
    })
}
