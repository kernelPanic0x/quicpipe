use std::marker::PhantomData;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, LengthDelimitedCodec};
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
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
            // A chunk plus the enum tag and the payload length prefix.
            .max_frame_length(CHUNK_SIZE + 4096)
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

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum InletToOutlet {
    /// A slice of the byte stream, tagged with its absolute offset so a replayed
    /// chunk is recognised rather than written twice.
    Data {
        offset: u64,
        payload: Bytes,
    },
    EOF,
    /// Ctrl+C
    SIGINT,
    /// Unrecoverable: a source read failure, a protocol violation, or a resume
    /// request that fell outside the replay window. The pipe is over.
    Fatal(String),
    Bye,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum OutletToInlet {
    /// "Everything below this offset has been written to stdout."
    ///
    /// Sent after each write, and as the first frame of every connection — where
    /// it is exactly the resume request. Same meaning, so it is the same frame.
    Received(u64),
    /// Ctrl+C
    SIGINT,
    /// The outlet's stdout is gone; the producer upstream should get SIGPIPE.
    SIGPIPE,
    Bye,
}

#[derive(SchemaWrite, SchemaRead)]
pub struct HandshakePayload {
    pub public_key: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<SocketAddr>,
}
