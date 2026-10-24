use std::marker::PhantomData;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, LengthDelimitedCodec};
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

/// Control messages are tiny (a cursor, a digest, a short failure reason).
/// Bulk bytes travel on a separate unframed stream.
pub const CONTROL_MAX_FRAME: usize = 64 * 1024;
pub const MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024; // 16 MiB max in-memory window
/// Manual protocol version, bumped only when the wire format changes —
/// deliberately NOT tied to the crate version, so patch releases stay
/// compatible and a version bump is always an explicit, reviewable decision.
pub const ALPN: &str = "quicpipe/v1";

pub trait Encoder: Sized {
    fn encode(&self) -> color_eyre::Result<Bytes>;
    fn decode(bytes: &[u8]) -> color_eyre::Result<Self>;
}

impl<T> Encoder for T
where
    T: Serialize<Src = T> + for<'de> Deserialize<'de, Dst = T>,
{
    fn encode(&self) -> color_eyre::Result<Bytes> {
        let serialized = wincode::serialize(self)?;
        Ok(Bytes::from(serialized))
    }

    fn decode(bytes: &[u8]) -> color_eyre::Result<Self> {
        let msg = wincode::deserialize(bytes)?;
        Ok(msg)
    }
}

/// One message per length-delimited frame.
///
/// Framing comes from `LengthDelimitedCodec`, payloads from wincode, so neither
/// direction needs hand-written tags or big-endian integer reads: the enums
/// *are* the wire format.
#[derive(Debug)]
pub struct WireCodec<T> {
    framing: LengthDelimitedCodec,
    msg: PhantomData<fn() -> T>,
}

impl<T> WireCodec<T> {
    pub fn new() -> Self {
        let framing = LengthDelimitedCodec::builder()
            .max_frame_length(CONTROL_MAX_FRAME)
            .new_codec();
        Self {
            framing,
            msg: PhantomData,
        }
    }
}

impl<T> Default for WireCodec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Encoder> tokio_util::codec::Encoder<T> for WireCodec<T> {
    type Error = color_eyre::Report;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> color_eyre::Result<()> {
        tokio_util::codec::Encoder::encode(&mut self.framing, item.encode()?, dst)?;
        Ok(())
    }
}

impl<T: Encoder> Decoder for WireCodec<T> {
    type Item = T;
    type Error = color_eyre::Report;

    fn decode(&mut self, src: &mut BytesMut) -> color_eyre::Result<Option<T>> {
        match self.framing.decode(src)? {
            Some(frame) => Ok(Some(T::decode(&frame)?)),
            None => Ok(None),
        }
    }
}

/// The end of the inlet's source, as a single fact: how many bytes it produced
/// and their XXH3-64 digest.
///
/// Both fields are needed together. `total` turns "the stream ended" into an
/// exact predicate the outlet can check against its own cursor
/// (`written == total`), which is what keeps the raw data stream's FIN from
/// being load-bearing; `checksum` is the end-to-end integrity verdict.
#[derive(SchemaWrite, SchemaRead, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEnd {
    pub total: u64,
    pub checksum: u64,
}

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum InletToOutlet {
    /// End of the source, announced once per connection when the source is
    /// exhausted: its exact length and the XXH3-64 digest of every byte the
    /// inlet produced. Any mismatch — a skipped or duplicated byte, a bad
    /// resume, anything QUIC's per-stream ordering could not see across a
    /// reconnect — fails the transfer loudly.
    #[wincode(tag = 0)]
    End(SourceEnd),
    /// The outlet no longer wants the bytes. The inlet stops its source and
    /// exits with the cancellation code; nothing is wrong with the stream.
    #[wincode(tag = 1)]
    Cancel,
    /// Unrecoverable: a source read failure, a protocol violation, or a resume
    /// request that fell outside the replay window. The transfer is over.
    #[wincode(tag = 2)]
    Fatal(String),
}

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum OutletToInlet {
    /// "Everything below this offset has been written to the destination."
    ///
    /// Sent after writes, and as the first frame of every connection — where
    /// it is exactly the resume request. Same meaning, so it is the same frame.
    #[wincode(tag = 0)]
    Written(u64),
    /// The user cancelled the transfer on this side.
    #[wincode(tag = 1)]
    Cancel,
    /// The outlet's downstream consumer is gone (its output reader exited).
    /// The inlet must stop producing, exactly like a broken pipe.
    #[wincode(tag = 2)]
    ConsumerGone,
    /// Every byte was written and verified; this is the clean goodbye.
    #[wincode(tag = 3)]
    Bye,
}

#[derive(SchemaWrite, SchemaRead)]
pub struct HandshakePayload {
    pub public_key: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<SocketAddr>,
    /// Total size of the inlet's source when known (`-s` or auto-detected).
    /// Purely advisory: it drives the progress bar and ETA, never the
    /// integrity verdict, which remains the end-to-end checksum.
    pub size: Option<u64>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::pedantic)]

    use super::*;

    /// The wire contract: the leading bytes of a frame are its variant tag
    /// (wincode's default little-endian `u32`) and a reordering would silently
    /// reinterpret frames. Renaming variants is free; changing these is not.
    #[test]
    fn frame_tags_are_frozen() {
        let tag = |frame: &[u8]| <[u8; 4]>::try_from(frame.get(..4).unwrap()).unwrap();

        assert_eq!(
            tag(&InletToOutlet::End(SourceEnd {
                total: 7,
                checksum: 9
            })
            .encode()
            .unwrap()),
            [0, 0, 0, 0]
        );
        assert_eq!(tag(&InletToOutlet::Cancel.encode().unwrap()), [1, 0, 0, 0]);
        assert_eq!(
            tag(&InletToOutlet::Fatal("x".into()).encode().unwrap()),
            [2, 0, 0, 0]
        );

        assert_eq!(tag(&OutletToInlet::Written(7).encode().unwrap()), [0, 0, 0, 0]);
        assert_eq!(tag(&OutletToInlet::Cancel.encode().unwrap()), [1, 0, 0, 0]);
        assert_eq!(tag(&OutletToInlet::ConsumerGone.encode().unwrap()), [2, 0, 0, 0]);
        assert_eq!(tag(&OutletToInlet::Bye.encode().unwrap()), [3, 0, 0, 0]);
    }
}
