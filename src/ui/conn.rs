//! Owned snapshot of an iroh connection's current path.
//!
//! `PathList` and `Path` borrow the `Connection` and cannot cross a task
//! boundary, so the sampler copies the few displayable fields into [`ConnView`].

use iroh::endpoint::Connection;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PathKind {
    #[default]
    Unknown,
    /// Data travels over a direct IP path (holepunched or local).
    Direct,
    /// Data travels through an iroh relay.
    Relay,
}

#[derive(Clone, Debug, Default)]
pub struct ConnView {
    pub kind: PathKind,
}

impl ConnView {
    /// Reads the currently selected path. iroh begins on a relay and may
    /// upgrade to a direct path later; sampling this on reconnect and every
    /// half second makes the status line follow that transition.
    pub fn sample(conn: &Connection) -> Self {
        let paths = conn.paths();
        let Some(path) = paths.iter().find(iroh::endpoint::Path::is_selected) else {
            return Self::default();
        };

        let kind = if path.is_ip() {
            PathKind::Direct
        } else if path.is_relay() {
            PathKind::Relay
        } else {
            PathKind::Unknown
        };
        Self { kind }
    }
}
