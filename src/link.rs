//! The two halves of a QUIC stream, each owned by exactly one task.
//!
//! This exists so that no `select!` ever races an in-flight read or write:
//! reading a length-delimited frame is *not* cancel-safe, so a task that owns a
//! whole frame at a time is the only way to keep the framing honest.
//!
//! Connection setup (bind, dial, retry/backoff) lives in `net.rs`.

use futures_util::{SinkExt, StreamExt};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::net::FLUSH_GRACE;
use crate::protocol::{Encoder, WireCodec};

/// Feeds decoded frames to `tx` until the stream ends or fails.
pub fn read_half<T: Encoder + Send + 'static>(
    recv: RecvStream,
    tx: mpsc::Sender<T>,
    faults: mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        let mut frames = FramedRead::new(recv, WireCodec::<T>::new());
        while let Some(frame) = frames.next().await {
            let msg = match frame {
                Ok(msg) => msg,
                Err(e) => {
                    let _ = faults.try_send(format!("read: {e}"));
                    return;
                }
            };
            if tx.send(msg).await.is_err() {
                return; // session gone
            }
        }
    });
}

/// Publishes outbound frames until the channel closes, then finishes the stream
/// cleanly and waits (bounded) for the peer to acknowledge the last byte.
pub fn write_half<T: Encoder + Send + 'static>(
    send: SendStream,
    mut rx: mpsc::Receiver<T>,
    faults: mpsc::Sender<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut frames = FramedWrite::new(send, WireCodec::<T>::new());
        while let Some(msg) = rx.recv().await {
            if let Err(e) = frames.send(msg).await {
                let _ = faults.try_send(format!("write: {e}"));
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
