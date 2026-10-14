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
        let owned_path = path.to_owned();
        let cursor = std::sync::Arc::clone(&written);
        let join = thread::Builder::new()
            .name("quicpipe-sink".into())
            .spawn(move || writer(owned_path, rx, cursor, events))?;
        Ok((Sink { tx, written }, join))
    }

    /// How far stdout has actually advanced. This is the resume request.
    pub fn cursor(&self) -> u64 {
        self.written.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Waits for everything already queued to be written, and reports the cursor.
pub async fn drain(sink: &Sink, within: std::time::Duration) -> Option<u64> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let barrier = async {
        sink.tx.send(Msg::Barrier(tx)).await.ok()?;
        rx.await.ok()
    };
    tokio::time::timeout(within, barrier).await.ok().flatten()
}

// A thread-entry function must own its arguments ('static closure), even the
// ones it only reads.
#[allow(clippy::needless_pass_by_value)]
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
        let Some(msg) = rx.blocking_recv() else {
            return;
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
                    payload.slice(usize::try_from(done - offset).expect("within the chunk")..)
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

#[cfg(test)]
mod sink_tests {
    #![allow(
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use crate::protocol::CHUNK_SIZE;

    /// Feeds frames through the real writer thread against a real temp file,
    /// then returns (file bytes, final cursor). This is the black-box
    /// corruption test: whatever interleaving goes in, the file must be a
    /// correct prefix of the intended stream, or a Gap/Error must have fired.
    /// Feeds frames through the real writer thread against a real temp file,
    /// then returns (file bytes, final cursor if the writer was still alive,
    /// observed events). The drain happens before any terminal event so the
    /// cursor reflects exactly the frames sent so far.
    async fn run(frames: Vec<Msg>, terminate: bool) -> (Vec<u8>, Option<u64>, Vec<Event>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.bin");
        let (events_tx, mut events_rx) = mpsc::channel::<Event>(1024);
        let (sink, task) = Sink::spawn(&path, 64, events_tx).expect("spawn sink");

        for frame in frames {
            // The writer may already have exited (e.g. after a Gap), in which
            // case sending fails and that is the test's verdict, not a hang.
            if sink.tx.send(frame).await.is_err() {
                break;
            }
        }
        let cursor = drain(&sink, std::time::Duration::from_secs(5)).await;

        let mut events = Vec::new();
        while let Ok(ev) = events_rx.try_recv() {
            events.push(ev);
        }

        if terminate {
            let _ = sink.tx.send(Msg::Eof).await;
        }
        drop(sink);
        task.join().expect("writer thread");

        while let Ok(ev) = events_rx.try_recv() {
            events.push(ev);
        }
        (std::fs::read(&path).expect("read file"), cursor, events)
    }

    fn data(offset: u64, s: &[u8]) -> Msg {
        Msg::Data {
            offset,
            payload: Bytes::copy_from_slice(s),
        }
    }

    #[tokio::test]
    async fn sequential_writes_are_exact() {
        let (bytes, cursor, events) = run(
            vec![data(0, b"hello "), data(6, b"world")],
            true,
        )
        .await;
        assert_eq!(bytes, b"hello world");
        assert_eq!(cursor, Some(11));
        assert!(events.iter().all(|e| matches!(e, Event::Ack(_))));
    }

    #[tokio::test]
    async fn duplicates_and_replays_are_idempotent() {
        // Same bytes delivered twice, and an overlapping resend that starts
        // below the cursor: the file must not change and the cursor must not
        // move beyond the true end.
        let (bytes, cursor, _) = run(
            vec![
                data(0, b"abcdef"),
                data(0, b"abcdef"), // full duplicate
                data(2, b"cdefgh"), // partial overlap, same prefix
                data(6, b"gh"),     // duplicate tail
            ],
            true,
        )
        .await;
        assert_eq!(bytes, b"abcdefgh");
        assert_eq!(cursor, Some(8));
    }

    #[tokio::test]
    async fn a_gap_is_a_fatal_not_a_silent_skip() {
        let (bytes, cursor, events) = run(
            vec![data(0, b"abc"), data(10, b"xyz")], // starts beyond the cursor
            false,
        )
        .await;
        assert_eq!(bytes, b"abc"); // the valid prefix is intact
        assert_eq!(cursor, None); // the writer exited, so no barrier answer
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::Gap { expected: 3, got: 10 }
            )),
            "expected a Gap event, got {events:?}"
        );
    }

    #[tokio::test]
    async fn chunk_larger_than_one_write_is_fine() {
        let big = vec![0xABu8; CHUNK_SIZE * 2];
        let (bytes, cursor, _) = run(vec![data(0, &big)], true).await;
        assert_eq!(bytes.len(), big.len());
        assert_eq!(cursor, Some(big.len() as u64));
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn eof_reaches_the_file() {
        // The Eof path must flush AND release the file so a downstream reader
        // sees the data; verify by reading after the writer thread exits.
        let (bytes, cursor, _) = run(vec![data(0, b"tail")], true).await;
        assert_eq!(bytes, b"tail");
        assert_eq!(cursor, Some(4));
    }
}
