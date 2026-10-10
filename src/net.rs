//! Connection setup shared by inlet and outlet.
//!
//! Both sides bind the same endpoint shape, build the same wormhole payload,
//! and treat the same errors as retryable. These helpers live in one module
//! rather than being duplicated in two files with drift.

use std::net::SocketAddr;

use color_eyre::eyre::Result;
use iroh::endpoint::{Connection, ConnectionError, Endpoint, VarInt, presets};
use iroh::{RelayMode, SecretKey};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::protocol::{ALPN, HandshakePayload};

/// How long to wait for a connection to reveal *why* it ended when a stream
/// task failed before the connection itself reported anything.
pub const CLOSE_REVEAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to linger after an intentional `close` so the CONNECTION_CLOSE
/// frame reaches the peer before the endpoint (or the whole process) goes away.
pub const CLOSE_PROPAGATE: std::time::Duration = std::time::Duration::from_millis(500);

/// Application close codes carried in the QUIC CONNECTION_CLOSE frame.
///
/// These are the authoritative cancellation signal: in-band control frames
/// (`SIGINT`, `Bye`, `Fatal`) can be lost together with the stream, but the
/// close code tells the peer definitively whether the other side left on
/// purpose — and therefore whether reconnecting would contradict it.
pub mod close {
    /// Clean shutdown: everything was delivered.
    pub const DONE: u64 = 0;
    /// Cancelled by SIGINT/SIGTERM.
    pub const CANCEL: u64 = 1;
    /// The peer's downstream consumer is gone.
    pub const SIGPIPE: u64 = 2;
    /// Unrecoverable error on the closing side.
    pub const FATAL: u64 = 3;
}

/// How the connection ended, classified for the reconnect policy.
pub enum CloseKind {
    /// The peer closed the connection on purpose: it has made its final
    /// decision and will not come back. Reconnecting would contradict it.
    App(u64, String),
    /// Idle timeout — the ordinary network failure, safe to retry.
    TimedOut,
    /// Anything else: transport error, reset, or a local stream failure.
    Lost(String),
}

/// Closes the connection immediately with an application close code, announcing
/// an intentional exit at the transport level.
pub fn close_intentional(conn: &Connection, code: u64, reason: &str) {
    if let Ok(code) = VarInt::from_u64(code) {
        conn.close(code, reason.as_bytes());
    }
}

/// Determines why a connection ended. Prefers the synchronous close reason;
/// if the connection is still open (a stream task failed first), gives the
/// peer a moment to close it on purpose before calling it a loss.
pub async fn close_kind(conn: &Connection) -> CloseKind {
    if let Some(err) = conn.close_reason() {
        return classify(err);
    }
    match timeout(CLOSE_REVEAL, conn.closed()).await {
        Ok(err) => classify(err),
        Err(_) => CloseKind::Lost("connection still open; a stream failed".into()),
    }
}

fn classify(err: ConnectionError) -> CloseKind {
    match err {
        ConnectionError::ApplicationClosed(c) => CloseKind::App(
            c.error_code.into_inner(),
            String::from_utf8_lossy(&c.reason).into_owned(),
        ),
        ConnectionError::TimedOut => CloseKind::TimedOut,
        other => CloseKind::Lost(other.to_string()),
    }
}

/// How long to wait for the peer to confirm it received a finished stream. A
/// `Bye` or `Fatal` still in flight must not be discarded by teardown.
pub const FLUSH_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Same endpoint shape for both sides: a stable key so the peer can pin us, and
/// relays so reconnects survive NAT rebinds.
///
/// The accepting side *must* advertise the ALPN: without it the endpoint never
/// offers `quicpipe/v1`, and a dial from the outlet fails the TLS handshake
/// with "peer doesn't support any known protocol". The dialing side needs no
/// `alpns`, the protocol name rides on `connect`.
pub async fn bind(key: &SecretKey, accept: bool) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .relay_mode(RelayMode::Default);
    if accept {
        builder = builder.alpns(vec![ALPN.as_bytes().to_vec()]);
    }
    Ok(builder.bind().await?)
}

pub fn payload_for(endpoint: &Endpoint, key: &SecretKey) -> HandshakePayload {
    let addr = endpoint.addr();
    HandshakePayload {
        public_key: *key.public().as_bytes(),
        // The relay URL survives NAT rebinds and interface changes; the direct
        // addresses are only a shortcut and will go stale.
        relay_url: addr.relay_urls().next().map(|url| url.to_string()),
        direct_addresses: addr.ip_addrs().cloned().collect::<Vec<SocketAddr>>(),
    }
}

/// Dials the inlet. Kept here so the retry policy in the outlet reads without
/// transport noise.
pub async fn dial(
    endpoint: &Endpoint,
    addr: iroh::EndpointAddr,
) -> Result<iroh::endpoint::Connection> {
    endpoint
        .connect(addr, ALPN.as_bytes())
        .await
        .map_err(color_eyre::Report::from)
}

// Waiting for a retry must stay responsive to Ctrl-C, so the sleep races the
// signal channel rather than blocking on it.
pub async fn wait_for_retry(delay: std::time::Duration, signals: &mut mpsc::Receiver<()>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        _ = signals.recv() => false,
    }
}

pub fn transient(e: &color_eyre::Report) -> bool {
    // Retrying is the safe failure mode; only a self-connect is worth giving up on.
    !e.to_string().contains("ourself")
}

pub fn backoff(attempt: u32) -> std::time::Duration {
    let base = 200u64.saturating_mul(1 << attempt.min(6)).min(5_000);
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis() as u64)
        .unwrap_or(0)
        % (base / 2 + 1);
    std::time::Duration::from_millis(base / 2 + jitter)
}
