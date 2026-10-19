//! The status line: connection state, progress, speed and ETA on stderr.
//!
//! The design keeps the data path free of terminal work. Producers update a
//! monotonic [`AtomicU64`] and a [`Phase`]; a single renderer task samples
//! those plus an iroh [`ConnView`] a few times per second and redraws one
//! `indicatif` bar. Chunks never touch a lock or the terminal.
//!
//! Position is deliberately *delivered* bytes, not bytes read or sent:
//! - inlet: the highest `Received(n)` ack (the replay window's `base`)
//! - outlet: the sink's write cursor
//!
//! That is what makes the bar advance truthfully across a reconnect instead
//! of reaching 100% while data is still buffered.

mod conn;
mod render;

use std::collections::VecDeque;
use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use indicatif::ProgressBar;
use iroh::endpoint::Connection;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use conn::{ConnView, PathKind};

const RENDER_INTERVAL: Duration = Duration::from_millis(150);
const CONN_INTERVAL: Duration = Duration::from_millis(500);

/// What the transfer is doing right now. Kept separate from the network path:
/// a reconnecting transfer has no selected path, a connected one has both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Talking to the rendezvous server, before the code is usable.
    Rendezvous,
    /// Code printed/entered; waiting for the peer to show up.
    WaitingForPeer,
    /// Dialing (outlet) or waiting for the next accept (inlet).
    Connecting,
    /// A connection was lost; the reconnect policy is waiting out a backoff.
    Reconnecting {
        attempt: u32,
    },
    /// Bytes are flowing.
    Transferring,
    /// EOF received; the sink is draining and the checksum is being checked.
    Verifying,
    Done,
}

pub struct UiConfig {
    enabled: bool,
    color: bool,
}

impl UiConfig {
    /// `--quiet` and non-TTY stderr both disable the bar. The latter is what
    /// keeps `quicpipe ... | tee log` free of escape sequences.
    pub fn new(quiet: bool) -> Self {
        let enabled = !quiet && std::io::stderr().is_terminal();
        Self {
            enabled,
            // Colour is a separate question from drawing the bar: a terminal
            // may support one and not the other, and `NO_COLOR` must win.
            color: enabled && render::color_capable(),
        }
    }
}

/// A handle to the status line. Dropping it clears the bar, so early `?`
/// returns cannot leave a half-drawn line behind.
pub struct Ui {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    pb: ProgressBar,
    phase: Arc<Mutex<Phase>>,
    conn: watch::Sender<ConnView>,
    ticker: JoinHandle<()>,
    watcher: Mutex<Option<JoinHandle<()>>>,
}

impl Ui {
    pub fn start(cfg: &UiConfig, total: Option<u64>, position: &Arc<AtomicU64>) -> Self {
        if !cfg.enabled {
            return Self { inner: None };
        }
        render::set_color(cfg.color);

        // `ProgressBar::new_spinner` enables a steady tick immediately, which
        // would draw one frame before the style, prefix and metrics are set.
        // A plain bar plus our own tick avoids that empty first frame; the
        // spinner template animates from the same tick.
        let pb = ProgressBar::new(total.unwrap_or(0));
        if let Ok(style) = render::style(total.is_some()) {
            pb.set_style(style);
        }
        let start_position = position.load(Ordering::Relaxed);
        let phase = Arc::new(Mutex::new(Phase::Rendezvous));
        // Seed every variable column *before* the first draw: `set_position`
        // ticks and redraws, and an unset prefix/message would render as an
        // empty `[]` plus a dangling ` · ` for one frame.
        pb.set_prefix(render::styled_prefix(
            *lock_phase(&phase),
            &ConnView::default(),
        ));
        pb.set_message(render::metrics(0.0, eta(total, start_position, 0.0)));
        pb.set_position(start_position);
        pb.enable_steady_tick(Duration::from_millis(100));

        let (conn_tx, mut conn_rx) = watch::channel(ConnView::default());

        let ticker = {
            let pb_task = pb.clone();
            let position_task = Arc::clone(position);
            let phase_task = Arc::clone(&phase);
            let total_task = total;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(RENDER_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut speed = Speedometer::new(Duration::from_secs(2));
                loop {
                    tick.tick().await;
                    // Monotonic by construction; this is only a display read.
                    let pos = position_task.load(Ordering::Relaxed);
                    let rate = speed.update(pos, Instant::now());
                    pb_task.set_position(pos);
                    pb_task.set_message(render::metrics(rate, eta(total_task, pos, rate)));
                    let conn = conn_rx.borrow_and_update().clone();
                    pb_task.set_prefix(render::styled_prefix(*lock_phase(&phase_task), &conn));
                }
            })
        };

        Self {
            inner: Some(Arc::new(Inner {
                pb,
                phase,
                conn: conn_tx,
                ticker,
                watcher: Mutex::new(None),
            })),
        }
    }

    pub fn phase(&self, phase: Phase) {
        if let Some(inner) = &self.inner {
            *lock_phase(&inner.phase) = phase;
        }
    }

    /// Follows a connection's iroh paths until it closes, reporting whether
    /// application data currently travels directly or through a relay.
    pub fn watch_connection(&self, conn: &Connection) {
        let Some(inner) = &self.inner else {
            return;
        };
        self.clear_connection();

        let _ = inner.conn.send(ConnView::sample(conn));
        let tx = inner.conn.clone();
        let conn_task = conn.clone();
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(CONN_INTERVAL);
            loop {
                tokio::select! {
                    _ = conn_task.closed() => break,
                    _ = tick.tick() => {
                        let _ = tx.send(ConnView::sample(&conn_task));
                    }
                }
            }
        });
        *lock_watcher(inner) = Some(handle);
    }

    /// Forgets the previous path (reconnect, connection ended). The phase
    /// prefix then describes the wait instead of stale endpoints.
    pub fn clear_connection(&self) {
        if let Some(inner) = &self.inner {
            if let Some(handle) = lock_watcher(inner).take() {
                handle.abort();
            }
            let _ = inner.conn.send(ConnView::default());
        }
    }

    /// Prints a line above the bar (or plainly when the UI is disabled).
    /// Used for the wormhole code and other one-off notices.
    pub fn notice(&self, line: impl AsRef<str>) {
        match &self.inner {
            Some(inner) => inner.pb.println(line.as_ref()),
            None => eprintln!("{}", line.as_ref()),
        }
    }

    /// Freezes the bar at its last position and removes it. Any earlier
    /// error path is covered by `Drop`.
    pub fn finish_success(&self) {
        if let Some(inner) = &self.inner {
            *lock_phase(&inner.phase) = Phase::Done;
            inner.pb.finish_and_clear();
        }
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.ticker.abort();
            self.clear_connection();
            inner.pb.finish_and_clear();
        }
    }
}

fn lock_phase(phase: &Mutex<Phase>) -> parking_lot::MutexGuard<'_, Phase> {
    phase.lock()
}

fn lock_watcher(inner: &Inner) -> parking_lot::MutexGuard<'_, Option<JoinHandle<()>>> {
    inner.watcher.lock()
}

/// A short sliding-window rate. `indicatif`'s own estimator has a long time
/// constant (tens of seconds), which makes short transfers look like the rate
/// is still ramping up when they finish. Two seconds is pv-like: responsive to
/// stalls, but long enough not to flicker on a 150 ms tick.
struct Speedometer {
    window: Duration,
    samples: VecDeque<(Instant, u64)>,
}

impl Speedometer {
    fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn update(&mut self, position: u64, now: Instant) -> f64 {
        self.samples.push_back((now, position));
        while self.samples.len() > 1 {
            let Some(&(oldest, _)) = self.samples.front() else {
                break;
            };
            if now.saturating_duration_since(oldest) > self.window {
                self.samples.pop_front();
            } else {
                break;
            }
        }

        let Some(&(start_time, start_position)) = self.samples.front() else {
            return 0.0;
        };
        let elapsed = now.saturating_duration_since(start_time).as_secs_f64();
        if elapsed < 0.05 || position <= start_position {
            return 0.0;
        }
        (position - start_position) as f64 / elapsed
    }
}

/// `None` means "not computable yet" (unknown total or zero speed), which the
/// renderer shows as `--:--:--`.
#[allow(clippy::cast_precision_loss)]
fn eta(total: Option<u64>, position: u64, rate: f64) -> Option<Duration> {
    let total_bytes = total?;
    if position >= total_bytes {
        return Some(Duration::ZERO);
    }
    if !rate.is_finite() || rate <= 0.0 {
        return None;
    }
    let seconds = (total_bytes - position) as f64 / rate;
    // Keep the value in a range `Duration::from_secs_f64` accepts and the
    // fixed-width ETA field can display.
    Some(Duration::from_secs_f64(seconds.min(359_999.0)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic)]

    use super::*;

    #[test]
    fn speed_reflects_only_the_recent_window() {
        let start = Instant::now();
        let mut speed = Speedometer::new(Duration::from_secs(2));
        speed.update(0, start);
        speed.update(1_000, start + Duration::from_secs(1));
        speed.update(2_000, start + Duration::from_secs(2));
        assert!((speed.update(3_000, start + Duration::from_secs(3)) - 1_000.0).abs() < 1.0);
    }

    #[test]
    fn a_stall_decays_to_zero() {
        let start = Instant::now();
        let mut speed = Speedometer::new(Duration::from_secs(2));
        speed.update(0, start);
        speed.update(1_000, start + Duration::from_secs(1));
        speed.update(1_000, start + Duration::from_secs(3));
        assert!(speed.update(1_000, start + Duration::from_secs(4)) <= f64::EPSILON);
    }

    #[test]
    fn eta_needs_a_total_and_a_rate() {
        assert_eq!(eta(None, 0, 10.0), None);
        assert_eq!(eta(Some(100), 0, 0.0), None);
        assert_eq!(eta(Some(100), 50, 10.0), Some(Duration::from_secs(5)));
        assert_eq!(eta(Some(100), 100, 10.0), Some(Duration::ZERO));
    }
}
