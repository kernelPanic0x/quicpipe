use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use color_eyre::eyre::bail;
use iroh::{Endpoint, RelayMode, endpoint::presets};
use iroh::{EndpointAddr, PublicKey, SecretKey};
use magic_wormhole::{MailboxConnection, Wormhole};
use tokio::io::AsyncReadExt;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{fs::File, io::AsyncRead};

use crate::protocol::{ALPN, CHUNK_SIZE, Encoder, InletToOutlet, OutletToInlet};
use crate::{InletArgs, app_config, protocol::HandshakePayload};

type ReaderType = Pin<Box<dyn AsyncRead + Send>>;

pub async fn run(args: InletArgs) -> color_eyre::Result<()> {
    let mut reader: ReaderType = if args.common.path.as_os_str() == "-" {
        Box::pin(tokio::io::stdin())
    } else {
        Box::pin(File::open(&args.common.path).await?)
    };

    let (from_outlet_tx, mut from_outlet_rx) = tokio::sync::mpsc::channel::<OutletToInlet>(1);
    let link = Link::connect(args, from_outlet_tx).await?;

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut buf = BytesMut::with_capacity(CHUNK_SIZE);
    let mut cancel_requests = 0;

    let mut inlet_bytes: u64 = 0;
    let mut outlet_bytes: u64 = 0;

    loop {
        select! {
            _ = sigint.recv() => {
                link.send(InletToOutlet::SIGINT).await;
                eprintln!("Shutting down...");
                cancel_requests += 1;
                if cancel_requests > 2 {
                    eprintln!("Exiting now!");
                    std::process::exit(130); // 128 + SIGINT
                }
            }

            msg = from_outlet_rx.recv() => {
                match msg.expect("Outlet TX") {
                    OutletToInlet::Received(n) => todo!(),
                    OutletToInlet::SIGINT => bail!("SIGINT on outlet!"),
                    OutletToInlet::SIGPIPE => bail!("SIGPIPE on outlet!"),
                    OutletToInlet::WriteError(e) => bail!("Write error on outlet: {}", e),
                    OutletToInlet::Bye => break,
                }
            }

            // Read stdin or file
            res = reader.read_buf(&mut buf) => match res {
                Ok(n) if n == 0 => link.send(InletToOutlet::EOF).await,
                Ok(_) => {
                    let chunk = buf.split().freeze();
                    inlet_bytes += chunk.len() as u64;
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
}

impl Link {
    async fn connect(
        args: InletArgs,
        from_outlet_tx: Sender<OutletToInlet>,
    ) -> color_eyre::Result<Self> {
        let secret_key = args
            .common
            .private_key
            .clone()
            .unwrap_or_else(SecretKey::generate);
        let public_key = secret_key.public();

        let mailbox = MailboxConnection::create(app_config(&args.common), args.code_length).await?;
        eprintln!("Wormhole code: {}", mailbox.code());
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

        let mut addr = EndpointAddr::new(PublicKey::from_bytes(&payload.public_key)?);
        if let Some(relay_str) = payload.relay_url {
            addr = addr.with_relay_url(relay_str.parse()?);
        }

        for ip in payload.direct_addresses {
            addr = addr.with_ip_addr(ip);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(1);

        tokio::spawn(async move { loop {} });

        Ok(Self { tx })
    }

    async fn handle_connection(
        mut rx: Receiver<Bytes>,
        from_outlet_tx: &mut Sender<OutletToInlet>,
        endpoint: &Endpoint,
        addr: EndpointAddr,
    ) -> color_eyre::Result<()> {
        let connection = endpoint.connect(addr, ALPN.as_bytes()).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = BytesMut::new();

        select! {
            chunk = rx.recv() => {
                match chunk {
                    Some(c) => send.write_chunk(c).await?,
                    None => return Ok(()),
                }
            }
            res = recv.read_buf(&mut buf) => {
                let _ = res?;
                let msg = OutletToInlet::decode(&buf.split())?;
                from_outlet_tx.send(msg).await?;
            }
        }

        todo!()
    }

    pub async fn send(&self, msg: InletToOutlet) {
        let _ = self
            .tx
            .send(msg.encode().expect("Encoding can't fail"))
            .await;
    }
}
