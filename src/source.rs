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
    let path = path.to_owned();
    let (tx, rx) = mpsc::channel::<Msg>(capacity);

    thread::Builder::new()
        .name("quicpipe-source".into())
        .spawn(move || {
            let mut input = match clio::Input::new(&path) {
                Ok(input) => input,
                Err(e) => {
                    let _ = tx.blocking_send(Msg::Error(format!("{}: {e}", path.display())));
                    return;
                }
            };

            use std::io::Read as _; // trait scope for clio::Input

            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                match input.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.blocking_send(Msg::Eof);
                        return;
                    }
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&buf[..n]);
                        // This is where backpressure lands: when the replay
                        // window is full the channel fills, this parks, and the
                        // OS pipe upstream backs up.
                        if tx.blocking_send(Msg::Data(chunk)).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = tx.blocking_send(Msg::Error(e.to_string()));
                        return;
                    }
                }
            }
        })?;

    Ok(Source { rx })
}
