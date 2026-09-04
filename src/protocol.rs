use std::net::SocketAddr;

use bytes::Bytes;
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

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
    Closed { reason: String },
}

#[derive(SchemaWrite, SchemaRead, Debug, Clone)]
pub enum OutletToInlet {
    Closed { reason: String },
}

#[derive(SchemaWrite, SchemaRead)]
pub struct HandshakePayload {
    pub public_key: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<SocketAddr>,
}
