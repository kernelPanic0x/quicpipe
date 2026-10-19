//! Pure formatting for the status line. Keeping this separate from the
//! renderer makes the labels and templates unit-testable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use indicatif::{BinaryBytes, FormattedDuration, ProgressStyle};

use super::{ConnView, PathKind, Phase};

/// The bar is only used when the total is known; otherwise a spinner with
/// byte and speed counters is the honest display (there is no ETA to compute).
///
/// `{wide_bar}` lets the bar absorb whatever width is left after the fixed
/// columns, so narrow terminals degrade gracefully.
pub fn style(known_total: bool) -> Result<ProgressStyle, indicatif::style::TemplateError> {
    // No fixed-width fields: every column grows with its value and
    // `{wide_bar}` absorbs whatever remains, so the bar fills the terminal
    // and shrinks again when long labels (e.g. `reconnect #1234`) appear.
    let template = if known_total {
        "[{prefix}] [{wide_bar:.cyan/blue}] \
         {binary_bytes}/{binary_total_bytes} {msg}"
    } else {
        "[{prefix}] {spinner:.cyan} {binary_bytes} {msg}"
    };
    ProgressStyle::with_template(template)
}

/// Speed and ETA are computed by the renderer rather than by `indicatif`:
/// its estimator smooths over tens of seconds and barely reacts within a
/// short transfer. Brackets also keep the columns self-delimiting now that
/// the values change width.
pub fn metrics(speed: f64, remaining: Option<Duration>) -> String {
    // Display-only conversion: clamp first, then round to a byte count.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bytes = BinaryBytes(speed.max(0.0).round() as u64);
    let rate = format!("[{}]", paint(&format!("{bytes}/s"), MUTED, false));
    let eta = match remaining {
        Some(left) => format!(
            "[{}]",
            paint(&format!("ETA {}", FormattedDuration(left)), MUTED, false)
        ),
        None => format!("[{}]", paint("ETA --:--:--", MUTED, false)),
    };
    format!("{rate} {eta}")
}

/// Whether SGR escapes should be emitted at all. Set once at startup from
/// [`color_capable`], so rendering stays allocation-light and the decision is
/// made a single time.
static COLOR: AtomicBool = AtomicBool::new(false);

pub fn set_color(on: bool) {
    COLOR.store(on, Ordering::Relaxed);
}

/// Whether this host can render colour on stderr: an ANSI-capable terminal,
/// no `NO_COLOR`, and not a dumb terminal. On Windows this also switches the
/// console into virtual-terminal mode, so the inline escapes below render
/// instead of printing literally (and old consoles decline instead).
pub fn color_capable() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("TERM").is_some_and(|term| term == "dumb") {
        return false;
    }
    crate::platform::enable_ansi()
}

/// SGR parameters rather than a styling crate: the bar already only exists on
/// a terminal, and writing the few escapes we need inline keeps the dependency
/// graph — and therefore dialoguer's console version — untouched.
const GREEN: &str = "32";
const YELLOW: &str = "33";
const CYAN: &str = "36";
const RED: &str = "31";
/// A grey quieter than default foreground text, readable on dark and light
/// terminals. Signal colours are reserved for state.
const MUTED: &str = "38;5;245";
const RESET: &str = "\x1b[0m";

/// Paints only the contents of a field, never its brackets.
fn paint(text: &str, sgr: &str, bold: bool) -> String {
    if !COLOR.load(Ordering::Relaxed) {
        return text.to_owned();
    }
    let weight = if bold { "1;" } else { "" };
    format!("\x1b[{weight}{sgr}m{text}{RESET}")
}

/// The first column: what the transfer is doing, and how it is connected.
///
/// Connection state is only shown while transferring; during a wait the
/// meaningful information is the wait itself, not a stale endpoint.
pub fn prefix(phase: Phase, conn: &ConnView) -> String {
    match phase {
        Phase::Rendezvous => "rendezvous".into(),
        Phase::WaitingForPeer => "waiting".into(),
        Phase::Connecting => "connecting".into(),
        Phase::Reconnecting { attempt } => format!("reconnect #{attempt}"),
        Phase::Transferring => match conn.kind {
            PathKind::Direct => "direct".into(),
            PathKind::Relay => "via relay".into(),
            PathKind::Unknown => "connected".into(),
        },
        Phase::Verifying => "verifying".into(),
        Phase::Done => "done".into(),
    }
}

/// Colour carries the state at a glance: green is healthy and direct,
/// yellow is a degraded wait (relay or connecting), red is a lost link.
pub fn styled_prefix(phase: Phase, conn: &ConnView) -> String {
    let label = prefix(phase, conn);
    let color = match phase {
        Phase::Reconnecting { .. } => RED,
        Phase::Transferring => match conn.kind {
            PathKind::Direct => GREEN,
            PathKind::Relay => YELLOW,
            PathKind::Unknown => CYAN,
        },
        Phase::Rendezvous | Phase::WaitingForPeer => YELLOW,
        Phase::Connecting | Phase::Verifying => CYAN,
        Phase::Done => GREEN,
    };
    paint(&label, color, true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic)]

    use super::*;

    fn conn(kind: PathKind) -> ConnView {
        ConnView { kind }
    }

    #[test]
    fn direct_and_relay_are_named() {
        assert_eq!(
            prefix(Phase::Transferring, &conn(PathKind::Direct)),
            "direct"
        );
        assert_eq!(
            prefix(Phase::Transferring, &conn(PathKind::Relay)),
            "via relay"
        );
    }

    #[test]
    fn waiting_states_do_not_leak_stale_state() {
        assert_eq!(
            prefix(Phase::WaitingForPeer, &conn(PathKind::Direct)),
            "waiting"
        );
        assert_eq!(
            prefix(Phase::Reconnecting { attempt: 3 }, &conn(PathKind::Relay)),
            "reconnect #3"
        );
    }

    #[test]
    fn templates_compile_for_both_known_and_unknown_totals() {
        assert!(style(true).is_ok());
        assert!(style(false).is_ok());
    }
}
