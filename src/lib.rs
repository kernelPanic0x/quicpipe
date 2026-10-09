use clap::{Args, Parser, Subcommand};
use color_eyre::eyre::{Context, eyre};
use iroh::SecretKey;
use magic_wormhole::{AppID, Code, transfer::APP_CONFIG};
use std::{borrow::Cow, io::Read, path::PathBuf};

mod completer;
mod inlet;
mod link;
mod net;
mod outlet;
mod protocol;
mod replay;
mod signals;
mod sink;
mod source;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pipe inlet
    Inlet(InletArgs),
    /// Pipe outlet
    Outlet(OutletArgs),
    /// Generate an iroh secret key and print it to stdout.
    GenKey,
    /// Generate an iroh public key based a secret key read from stdin.
    GenPub,
}

#[derive(Debug, Clone, Args)]
struct InletArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Wormhole code length
    #[arg(long, short = 'l', default_value_t = 2)]
    pub code_length: usize,
}

#[derive(Debug, Clone, Args)]
struct OutletArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Debug, Clone, Args)]
struct CommonArgs {
    /// Path or '-' for stdin/stdout
    #[arg(default_value = "-")]
    pub path: PathBuf,

    /// Use a custom rendezvous server. Both sides need to use the same value in order to find each other.
    #[arg(long, value_name = "ws://example.org", value_hint = clap::ValueHint::Url, env = "WORMHOLE_MAILBOX_URL")]
    rendezvous_server: Option<url::Url>,

    /// Manually set a fixed private key.
    #[arg(long, env = "QUICPIPE_PRIVATE_KEY")]
    private_key: Option<SecretKey>,

    /// The wormhole code to establish a connection.
    #[arg(long, short, env = "RESCUE_SHELL_CODE")]
    code: Option<Code>,
}

fn gen_public_key() -> color_eyre::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read from stdin")?;

    let trimmed = input.trim();
    let bytes = hex::decode(trimmed).context("Invalid hex input")?;

    let secret_key = SecretKey::try_from(bytes.as_slice())
        .map_err(|e| eyre!("Invalid secret key bytes: {e}"))?;

    let public_key = secret_key.public();

    println!("{public_key}");

    Ok(())
}

fn gen_secret_key() {
    let secret_key = SecretKey::generate();
    let hex = hex::encode(secret_key.to_bytes());
    println!("{hex}");
}

async fn async_main(argv: Vec<std::ffi::OsString>) -> color_eyre::Result<i32> {
    let cli = match Cli::try_parse_from(argv) {
        Ok(app) => app,
        Err(err) => {
            // --help/--version print to stdout (code 0), usage errors to stderr (code 2)
            err.print()?;
            return Ok(err.exit_code());
        }
    };

    match cli.cmd {
        Cmd::Inlet(args) => inlet::run(args).await?,
        Cmd::Outlet(args) => outlet::run(args).await?,
        Cmd::GenKey => gen_secret_key(),
        Cmd::GenPub => gen_public_key()?,
    }

    Ok(0)
}

pub async fn run_from<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let _ = color_eyre::install(); // ignore "already installed"

    let argv: Vec<std::ffi::OsString> =
        std::iter::once(std::ffi::OsString::from(env!("CARGO_PKG_NAME")))
            .chain(args.into_iter().map(Into::into))
            .collect();

    match async_main(argv).await {
        Ok(code) => code,
        Err(report) => {
            eprintln!("{report:?}");
            1
        }
    }
}

fn app_config(
    common: &CommonArgs,
) -> magic_wormhole::AppConfig<magic_wormhole::transfer::AppVersion> {
    let mut config = APP_CONFIG.id(AppID::new(concat!(env!("CARGO_PKG_NAME"), "-v1")));
    if let Some(url) = &common.rendezvous_server {
        config = config.rendezvous_url(Cow::Owned(url.to_string()));
    }
    config
}
