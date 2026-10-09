//! src/signals.rs
//!
//! Signal handling never touches the transport: it only pokes a channel, so a
//! wedged connection can never make Ctrl-C unresponsive.

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

pub fn forward(tx: mpsc::Sender<()>) {
    tokio::spawn(async move {
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut hits = 0u32;
        loop {
            tokio::select! {
                _ = int.recv() => {}
                _ = term.recv() => {}
            }
            hits += 1;
            if hits >= 3 {
                eprintln!("[quicpipe] exiting now");
                std::process::exit(130);
            }
            let _ = tx.try_send(());
        }
    });
}

/// Dies of `sig`, so that a pipeline behaves like a pipeline.
///
/// Restoring SIG_DFL matters: Rust installs SIG_IGN for SIGPIPE at startup, so
/// `raise` alone would be a no-op and the producer upstream would never die.
pub fn die_of(sig: i32) -> ! {
    unsafe {
        if sig == libc::SIGPIPE {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        libc::raise(sig);
    }
    std::process::exit(128 + sig)
}
