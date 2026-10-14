//! The producer: reads the source on a blocking thread and hands chunks to the
//! async side through a bounded channel.
//!
//! Using `clio::Input` means `-`, a plain path, `/dev/stdin` and friends all
//! behave the same, without hand-rolled open logic. The read loop is deliberately
//! blocking and lives on its own thread: `tokio::io::stdin()` is an uncancellable
//! blocking read on a runtime thread, and `tokio::fs::File` is a blocking op on a
//! helper thread, so neither may be polled from inside a `select!`. A thread plus
//! a bounded channel gives both kinds of source correct backpressure.

use std::path::Path;
use std::thread;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::protocol::CHUNK_SIZE;

#[derive(Debug)]
pub enum Msg {
    Data(Bytes),
    Eof,
    Error(String),
}

pub struct Source {
    pub rx: mpsc::Receiver<Msg>,
}

/// `capacity` is deliberately tiny: the replay window is the real buffer, and a
/// deep channel here would only add latency to the SIGPIPE path.
pub fn spawn(path: &Path, capacity: usize) -> std::io::Result<Source> {
    let owned_path = path.to_owned();
    let (tx, rx) = mpsc::channel::<Msg>(capacity);

    thread::Builder::new()
        .name("quicpipe-source".into())
        .spawn(move || {
            use std::io::Read as _; // trait scope for clio::Input

            let mut input = match clio::Input::new(&owned_path) {
                Ok(input) => input,
                Err(e) => {
                    let _ = tx.blocking_send(Msg::Error(format!("{}: {e}", owned_path.display())));
                    return;
                }
            };

            // Read directly into a reusable BytesMut and freeze the filled
            // prefix: zero copies per chunk, unlike read-then-copy_from_slice
            // which would memcpy every byte twice.
            let mut buf = BytesMut::with_capacity(CHUNK_SIZE);
            loop {
                buf.reserve(CHUNK_SIZE);
                // SAFETY: `chunk_mut` hands out the uninitialized spare
                // capacity as a raw pointer. The read below initializes
                // exactly its first `n` bytes (a successful read(2) always
                // fills what it reports); `advance_mut(n)` then marks those
                // bytes as the buffer's live contents, and `split_to(n)`
                // detaches exactly them into a `Bytes`. The uninitialized
                // tail remains outside every live view. This is the pattern
                // the bytes crate documents for zero-copy IO into a
                // `BytesMut` — the advance is what makes the read visible.
                let read = {
                    let chunk = buf.chunk_mut();
                    let spare =
                        unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) };
                    input.read(spare)
                };
                match read {
                    Ok(0) => {
                        let _ = tx.blocking_send(Msg::Eof);
                        return;
                    }
                    Ok(n) => {
                        unsafe { buf.advance_mut(n) };
                        let chunk = buf.split_to(n).freeze();
                        // This is where backpressure lands: when the replay
                        // window is full the channel fills, this parks, and the
                        // OS pipe upstream backs up.
                        if tx.blocking_send(Msg::Data(chunk)).is_err() {
                            return;
                        }
                    }
                    // EINTR: the loop simply reads again.
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        let _ = tx.blocking_send(Msg::Error(e.to_string()));
                        return;
                    }
                }
            }
        })?;

    Ok(Source { rx })
}

#[cfg(test)]
mod source_tests {
    #![allow(clippy::unwrap_used, clippy::pedantic, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn reads_a_file_completely_and_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("in.bin");
        let payload: Vec<u8> = (0..(CHUNK_SIZE * 2 + 1234)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &payload).expect("write");

        let mut source = spawn(&path, 4).expect("spawn");
        let mut received = Vec::new();
        while let Some(msg) = source.rx.recv().await {
            match msg {
                Msg::Data(chunk) => received.extend_from_slice(&chunk),
                Msg::Eof => break,
                Msg::Error(e) => panic!("source errored: {e}"),
            }
        }
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn a_missing_file_is_an_error_not_silence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist");
        let mut source = spawn(&path, 4).expect("spawn");
        match source.rx.recv().await {
            Some(Msg::Error(_)) => {}
            other => panic!("expected an Error, got {other:?}"),
        }
    }
}
