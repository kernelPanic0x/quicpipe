use std::net::SocketAddr;

use bytes::Bytes;
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
pub const MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024; // 16 MiB max in-memory window
pub const ALPN: &'static str = "quicpipe/v1";

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

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum InletToOutlet {
    Data(Bytes),
    EOF,
    /// Ctrl+C
    SIGINT,
    ReadError(String),
    Bye,
}

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum OutletToInlet {
    Received(u64),
    /// Ctrl+C
    SIGINT,
    /// Outlet tried to write to closed pipe
    SIGPIPE,
    WriteError(String),
    Bye,
}

#[derive(SchemaWrite, SchemaRead)]
pub struct HandshakePayload {
    pub public_key: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<SocketAddr>,
}
