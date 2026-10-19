//! Why and how a transfer ends early, in platform-neutral terms.
//!
//! The protocol never talks about Unix signals: a transfer is cancelled by the
//! user, or the downstream consumer is gone. Only this module knows how to
//! express those endings on the host, and how to forward the host's
//! interruption requests into the runtime.

use tokio::sync::mpsc;

/// An early ending, as the user or the pipeline sees it.
///
/// `Interrupt` and `Terminate` are user requests; `ConsumerGone` is the
/// pipeline verdict "the process reading our output has exited". On Unix the
/// process then dies by the matching signal (`SIGINT`, `SIGTERM`, `SIGPIPE`) so
/// the rest of the pipeline learns the truth. Windows has no signal deaths, so
/// each maps to its conventional exit code instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Interrupt,
    Terminate,
    ConsumerGone,
}

impl Termination {
    /// Shell convention: `128 + signal`. Windows has no signals, but the same
    /// numbers are what wrappers and CI scripts already understand.
    pub const fn code(self) -> i32 {
        match self {
            Self::Interrupt => 130,
            Self::Terminate => 143,
            Self::ConsumerGone => 141,
        }
    }

    #[cfg(unix)]
    const fn number(self) -> i32 {
        match self {
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
            Self::ConsumerGone => libc::SIGPIPE,
        }
    }
}

/// Forwards the host's interruption requests to `tx`.
///
/// The channel only carries the verdict; the transport is never touched here,
/// so a wedged connection can never make Ctrl-C unresponsive.
pub fn forward(tx: mpsc::Sender<Termination>) {
    imp::forward(tx);
}

/// Ends the process the way `why` demands: by the matching signal on Unix, by
/// its conventional exit code everywhere else. Never returns.
pub fn exit(why: Termination) -> ! {
    #[cfg(unix)]
    unsafe {
        // Rust installs `SIG_IGN` for `SIGPIPE` at startup, so `raise` alone
        // would be a no-op and the producer upstream would never learn that its
        // reader is gone.
        if why == Termination::ConsumerGone {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        libc::raise(why.number());
    }
    std::process::exit(why.code())
}

#[cfg(unix)]
mod imp {
    use super::Termination;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::mpsc;

    pub fn forward(tx: mpsc::Sender<Termination>) {
        tokio::spawn(async move {
            let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT");
            let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM");
            let mut hits = 0u32;
            loop {
                let why = tokio::select! {
                    _ = interrupt.recv() => Termination::Interrupt,
                    _ = terminate.recv() => Termination::Terminate,
                };
                hits += 1;
                if hits >= 3 {
                    tracing::warn!("exiting now");
                    std::process::exit(why.code());
                }
                let _ = tx.try_send(why);
            }
        });
    }
}

#[cfg(windows)]
mod imp {
    use super::Termination;
    use tokio::signal::windows::{ctrl_break, ctrl_c};
    use tokio::sync::mpsc;

    pub fn forward(tx: mpsc::Sender<Termination>) {
        tokio::spawn(async move {
            let mut interrupt = ctrl_c().expect("console control handler");
            let mut terminate = ctrl_break().expect("console control handler");
            let mut hits = 0u32;
            loop {
                let why = tokio::select! {
                    _ = interrupt.recv() => Termination::Interrupt,
                    _ = terminate.recv() => Termination::Terminate,
                };
                hits += 1;
                if hits >= 3 {
                    tracing::warn!("exiting now");
                    std::process::exit(why.code());
                }
                let _ = tx.try_send(why);
            }
        });
    }
}
