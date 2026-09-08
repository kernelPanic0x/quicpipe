use std::pin::Pin;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use iroh::{Endpoint, RelayMode, endpoint::presets};
use iroh::{EndpointAddr, PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::io::AsyncReadExt;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tokio::{fs::File, io::AsyncRead};

use crate::protocol::{CHUNK_SIZE, Encoder, InletToOutlet};
use crate::{
    InletArgs, app_config,
    protocol::{HandshakePayload, MAX_BUFFERED_BYTES},
};

type ReaderType = Pin<Box<dyn AsyncRead + Send>>;

pub async fn run(args: InletArgs) -> color_eyre::Result<()> {
    let mut reader: ReaderType = if args.common.path.as_os_str() == "-" {
        Box::pin(tokio::io::stdin())
    } else {
        Box::pin(File::open(&args.common.path).await?)
    };

    let link = Link::connect(args).await?;

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut buf = BytesMut::with_capacity(CHUNK_SIZE);

    loop {
        select! {
            _ = sigint.recv() => {
                link.send(InletToOutlet::SIGINT).await;
            }

            _ = link.wait_for_bye() => {
                break;
            }

            // Read stdin or file
            res = reader.read_buf(&mut buf) => match res {
                Ok(n) if n == 0 => link.send(InletToOutlet::EOF).await,
                Ok(_) => {
                    let chunk = buf.split().freeze();
                    link.send(InletToOutlet::Data(chunk)).await;
                },
                Err(e) => link.send(InletToOutlet::ReadError(e.to_string())).await,
            }
        }
    }
    todo!()
}

#[derive(Clone)]
struct Link {
    tx: Sender<Bytes>,
    bye_signal: Arc<Notify>,
}

impl Link {
    async fn connect(args: InletArgs) -> color_eyre::Result<Self> {
        let secret_key = args
            .common
            .private_key
            .clone()
            .unwrap_or_else(SecretKey::generate);
        let public_key = secret_key.public();

        let mailbox = MailboxConnection::connect(
            app_config(&args.common),
            args.common.code.expect("code always set"),
            false,
        )
        .await?;
        let mut wormhole = Wormhole::connect(mailbox).await?;
        let bytes = wormhole.receive().await?;
        let payload: HandshakePayload = wincode::deserialize(&bytes)?;

        wormhole.send(public_key.to_vec()).await?;

        #[cfg(target_os = "android")]
        let endpoint = {
            use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

            use iroh::dns::DnsResolver;

            Endpoint::builder(presets::Minimal)
                .secret_key(secret_key)
                .dns_resolver(DnsResolver::with_nameserver(SocketAddr::V4(
                    SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
                )))
                .relay_mode(RelayMode::Default)
                .bind()
                .await?
        };

        #[cfg(not(target_os = "android"))]
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .relay_mode(RelayMode::Default)
            .bind()
            .await?;

        let mut target_addr = EndpointAddr::new(PublicKey::from_bytes(&payload.public_key)?);
        if let Some(relay_str) = payload.relay_url {
            target_addr = target_addr.with_relay_url(relay_str.parse()?);
        }

        for ip in payload.direct_addresses {
            target_addr = target_addr.with_ip_addr(ip);
        }

        todo!()
    }

    pub async fn send(&self, msg: InletToOutlet) {
        let _ = self
            .tx
            .send(msg.encode().expect("Encoding can't fail"))
            .await;
    }

    pub async fn wait_for_bye(&self) {
        self.bye_signal.notified().await
    }
}

struct BufferManager {
    current_chunk: Bytes,
    offset: u64,
}

impl BufferManager {
    pub fn default() -> Self {
        Self {
            buffer: BytesMut::with_capacity(MAX_BUFFERED_BYTES),
            offset: 0,
        }
    }

    pub fn put(&mut self, chunk: Bytes) {
        self.offset = self.offset.strict_add(chunk.len() as u64);
        self.current_chunk = chunk;
    }

    pub fn advance(&mut self, remote_offset: u64) {
        if remote_offset > self.offset {
            self.buffer.advance(cnt);
        }
    }
}
