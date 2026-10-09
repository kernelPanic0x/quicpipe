//! Connection setup shared by inlet and outlet.
//!
//! Both sides bind the same endpoint shape, build the same wormhole payload,
//! and treat the same errors as retryable. These helpers live in one module
//! rather than being duplicated in two files with drift.

use std::net::SocketAddr;

use color_eyre::eyre::Result;
use iroh::endpoint::{Endpoint, presets};
use iroh::{RelayMode, SecretKey};
use tokio::sync::mpsc;

use crate::protocol::{ALPN, HandshakePayload};

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
