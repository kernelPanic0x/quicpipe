//! The consumer side: a blocking writer on its own thread that owns the write
//! cursor.
//!
//! The writer task owns the fd *and* the byte cursor, so the dedupe decision and
//! the write happen in the same task with no window between them. That is what
//! makes a replayed chunk idempotent rather than merely unlikely to duplicate.
//!
//! Using `clio::Output` means `-`, a plain path and friends behave the same,
//! without hand-rolled open logic, and a slow stdout blocks this thread and not
//! the runtime.

use std::path::Path;
use std::thread;

use bytes::Bytes;
use iroh::endpoint::RecvStream;
use tokio::sync::mpsc;

use crate::protocol::InletToOutlet;



#[derive(Debug)]
pub enum Msg {
    Data {
        offset: u64,
        payload: Bytes,
    },
    /// Drain barrier: resolves with the cursor once everything queued before it
    /// has been written. Used at end-of-stream so the final `Received` we send
    /// is the true total.
    Barrier(tokio::sync::oneshot::Sender<u64>),
    Eof,
}

#[derive(Debug)]
pub enum Event {
    /// stdout advanced to this offset. Advisory: the greeting on the next
    /// connection restates the same truth, so losing an ack costs only memory.
    Ack(u64),
    /// The downstream consumer exited. Ordinary pipe semantics, not an error.
    BrokenPipe,
    /// The sender started beyond our cursor. Unrecoverable.
    Gap {
        expected: u64,
        got: u64,
    },
    Error(String),
}

pub struct Sink {
    pub tx: mpsc::Sender<Msg>,
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Sink {
    pub fn spawn(
        path: &Path,
        capacity: usize,
        events: mpsc::Sender<Event>,
    ) -> std::io::Result<(Sink, thread::JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel(capacity);
        let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let path = path.to_owned();
        let cursor = written.clone();
        let join = thread::Builder::new()
            .name("quicpipe-sink".into())
            .spawn(move || writer(path, rx, cursor, events))?;
        Ok((
            Sink {
                tx,
                written,
            },
            join,
        ))
    }

    /// How far stdout has actually advanced. This is the resume request.
    pub fn cursor(&self) -> u64 {
        self.written
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Waits for everything already queued to be written, and reports the cursor.
pub async fn drain(sink: &Sink, within: std::time::Duration) -> Option<u64> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let barrier = async {
        sink.tx.send(Msg::Barrier(tx)).await.ok()?;
        rx.await.ok()
    };
    tokio::time::timeout(within, barrier)
        .await
        .ok()
        .flatten()
}

fn writer(
    path: std::path::PathBuf,
    mut rx: mpsc::Receiver<Msg>,
    cursor: std::sync::Arc<std::sync::atomic::AtomicU64>,
    events: mpsc::Sender<Event>,
) {
    use std::io::Write as _; // trait scope for clio::Output/stdout flush

    let to_stdout = path.as_os_str() == "-";
    let mut out = match clio::Output::new(&path) {
        Ok(out) => out,
        Err(e) => {
            let _ = events.blocking_send(Event::Error(format!("{}: {e}", path.display())));
            return;
        }
    };

    let mut acked: u64 = 0;
    loop {
        let msg = match rx.blocking_recv() {
            Some(msg) => msg,
            None => return,
        };
        match msg {
            Msg::Data { offset, payload } => {
                let done = cursor.load(std::sync::atomic::Ordering::SeqCst);
                let end = offset + payload.len() as u64;
                let fresh = if end <= done {
                    continue; // a replay of bytes we already wrote
                } else if offset > done {
                    let _ = events.blocking_send(Event::Gap {
                        expected: done,
                        got: offset,
                    });
                    return;
                } else {
                    payload.slice((done - offset) as usize..)
                };

                if let Err(e) = out.write_all(&fresh) {
                    let _ = events.blocking_send(if e.kind() == std::io::ErrorKind::BrokenPipe {
                        Event::BrokenPipe
                    } else {
                        Event::Error(e.to_string())
                    });
                    return;
                }
                // Only now is it true. `Received` means "handed to the OS", not
                // "durably stored", and the doc says so.
                let total = done + fresh.len() as u64;
                cursor.store(total, std::sync::atomic::Ordering::SeqCst);
                if total > acked {
                    acked = total;
                    let _ = events.blocking_send(Event::Ack(total));
                }
            }
            Msg::Barrier(reply) => {
                let _ = reply.send(cursor.load(std::sync::atomic::Ordering::SeqCst));
            }
            Msg::Eof => {
                let _ = out.flush();
                if to_stdout {
                    // A downstream reader only sees EOF when the last writer
                    // closes the fd; flush() alone will not do it.
                    let _ = std::io::stdout().flush();
                    unsafe { libc::close(1) };
                }
                return;
            }
        }
    }
}

/// Routes inbound frames: bulk data straight to the sink, control to the session.
///
/// Data goes to the sink directly so that a full sink queue backpressures the
/// QUIC stream, rather than being absorbed by the session loop.
pub fn pump(
    recv: RecvStream,
    sink: mpsc::Sender<Msg>,
    ctrl: mpsc::Sender<InletToOutlet>,
    faults: mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<InletToOutlet>(4);
        crate::link::read_half(recv, tx, faults.clone());
        while let Some(msg) = rx.recv().await {
            match msg {
                InletToOutlet::Data { offset, payload } => {
                    if sink.send(Msg::Data { offset, payload }).await.is_err() {
                        return; // sink gone; the session will notice
                    }
                }
                other => {
                    if ctrl.send(other).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
}
