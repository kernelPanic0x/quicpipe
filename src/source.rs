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

use bytes::Bytes;
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

            // One copy per chunk: the kernel fills `buf`, we copy the read
            // prefix into an owned `Bytes` so it can outlive the buffer.
            // (True zero-copy via `Read::read_buf` is still unstable, and the
            // `chunk_mut`/raw-pointer pattern is not worth an `unsafe` for
            // ~0.03% of the transfer's time budget.)
            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                match input.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.blocking_send(Msg::Eof);
                        return;
                    }
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(buf.get(..n).expect("read reported n bytes"));
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
