//! The consumer side: a blocking writer on its own thread that owns the write
//! cursor.
//!
//! The writer task owns the destination *and* the byte cursor, so "handed to
//! the OS" and "the cursor advanced" are the same event. Reconnect continuity
//! comes from draining to this cursor before the next connection; the sink
//! itself never needs to know that a reconnect happened.
//!
//! Using `clio::Output` means `-`, a plain path and friends behave the same,
//! without hand-rolled open logic, and a slow stdout blocks this thread and not
//! the runtime.

use std::path::Path;
use std::thread;

use bytes::Bytes;
use iroh::endpoint::RecvStream;
use tokio::sync::mpsc;


#[derive(Debug)]
pub enum Msg {
    Data(Bytes),
    /// Drain barrier: resolves with (cursor, digest) once everything queued
    /// before it has been written. Used at end-of-stream so the final
    /// `Written` is the true total and the checksum verdict is computed over
    /// exactly the bytes handed to the OS.
    Barrier(tokio::sync::oneshot::Sender<(u64, u64)>),
    Eof,
}

#[derive(Debug)]
pub enum Event {
    /// stdout advanced to this offset. Advisory: the greeting on the next
    /// connection restates the same truth, so losing an ack costs only memory.
    Ack(u64),
    /// The downstream consumer exited. Ordinary pipe semantics, not an error.
    ConsumerGone,
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

    /// Shared cursor handle for the progress UI. It advances only after a
    /// successful write, so the bar reflects delivered bytes, not queued ones.
    pub fn cursor_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.written)
    }
}

/// Waits for everything already queued to be written, and reports the cursor
/// and the XXH3-64 digest of every byte written so far.
pub async fn drain(sink: &Sink, within: std::time::Duration) -> Option<(u64, u64)> {
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

    // Hashes exactly the bytes handed to the OS, in write order: the verdict
    // the checksum is compared against.
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();

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
            Msg::Data(payload) => {
                let len = payload.len() as u64;
                if let Err(e) = out.write_all(&payload) {
                    let _ = events.blocking_send(if e.kind() == std::io::ErrorKind::BrokenPipe {
                        Event::ConsumerGone
                    } else {
                        Event::Error(e.to_string())
                    });
                    return;
                }
                // Only now is it true. `Written` means "handed to the OS", not
                // "durably stored", and the doc says so.
                let total = cursor.load(std::sync::atomic::Ordering::SeqCst) + len;
                cursor.store(total, std::sync::atomic::Ordering::SeqCst);
                hasher.update(&payload);
                if total > acked {
                    acked = total;
                    // Advisory and superseded by the next ack (or by the
                    // resume handshake), so a full channel must not stall the
                    // writer while no session is consuming events during a
                    // reconnect drain.
                    let _ = events.try_send(Event::Ack(total));
                }
            }
            Msg::Barrier(reply) => {
                let _ = reply.send((
                    cursor.load(std::sync::atomic::Ordering::SeqCst),
                    hasher.digest(),
                ));
            }
            Msg::Eof => {
                let _ = out.flush();
                if to_stdout {
                    // A downstream reader only sees EOF once the last writer
                    // closes the destination; flush() alone will not do it.
                    let _ = std::io::stdout().flush();
                    crate::platform::close_stdout();
                }
                return;
            }
        }
    }
}

/// Reads raw bytes from the data stream and queues them for the writer.
///
/// The stream is ordered and reliable within one connection; reconnect
/// continuity comes from the drained cursor in the handshake, never from
/// per-chunk offsets. A chunk read but not yet queued when the connection dies
/// is simply replayed by the inlet.
pub fn pump(
    mut recv: RecvStream,
    sink: mpsc::Sender<Msg>,
    data_end: mpsc::Sender<()>,
    faults: mpsc::Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match recv.read_chunk(READ_CHUNK).await {
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    if sink.send(Msg::Data(payload)).await.is_err() {
                        return; // sink gone; the session will notice
                    }
                }
                Ok(None) => {
                    let _ = data_end.try_send(());
                    return;
                }
                Err(e) => {
                    let _ = faults.try_send(format!("read data: {e}"));
                    return;
                }
            }
        }
    })
}

/// Local read granularity on the consumer side. Independent of the wire now:
/// QUIC segments as it likes, and ack frequency is the only thing this tunes.
const READ_CHUNK: usize = 256 * 1024;

#[cfg(test)]
mod sink_tests {
    #![allow(
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    /// Feeds messages through the real writer thread against a real temp file,
    /// then returns (file bytes, final cursor if the writer was still alive,
    /// observed events). The drain happens before any terminal event so the
    /// cursor reflects exactly the bytes sent so far.
    async fn run(frames: Vec<Msg>, terminate: bool) -> (Vec<u8>, Option<(u64, u64)>, Vec<Event>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.bin");
        let (events_tx, mut events_rx) = mpsc::channel::<Event>(1024);
        let (sink, task) = Sink::spawn(&path, 64, events_tx).expect("spawn sink");

        for frame in frames {
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

    fn data(s: &[u8]) -> Msg {
        Msg::Data(Bytes::copy_from_slice(s))
    }

    #[tokio::test]
    async fn sequential_writes_are_exact() {
        let (bytes, cursor, events) = run(vec![data(b"hello "), data(b"world")], true).await;
        assert_eq!(bytes, b"hello world");
        assert_eq!(
            cursor,
            Some((11, xxhash_rust::xxh3::xxh3_64(b"hello world")))
        );
        assert!(events.iter().all(|e| matches!(e, Event::Ack(_))));
    }

    #[tokio::test]
    async fn chunk_larger_than_one_write_is_fine() {
        let big = vec![0xABu8; 512 * 1024];
        let (bytes, cursor, _) = run(vec![data(&big)], true).await;
        assert_eq!(bytes.len(), big.len());
        assert_eq!(
            cursor,
            Some((big.len() as u64, xxhash_rust::xxh3::xxh3_64(&big)))
        );
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn eof_reaches_the_file() {
        // The Eof path must flush AND release the file so a downstream reader
        // sees the data; verify by reading after the writer thread exits.
        let (bytes, cursor, _) = run(vec![data(b"tail")], true).await;
        assert_eq!(bytes, b"tail");
        assert_eq!(cursor, Some((4, xxhash_rust::xxh3::xxh3_64(b"tail"))));
    }
}
