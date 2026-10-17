use clap::{Args, Parser, Subcommand};
use magic_wormhole::{AppID, Code, transfer::APP_CONFIG};
use std::{borrow::Cow, path::PathBuf};

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

/// Initialize logging: `RUST_LOG` wins if set, otherwise `--quiet` maps to
/// error-only, otherwise errors from any crate plus quicpipe status lines.
/// Everything goes to stderr, never to stdout (stdout is the pipe payload).
pub fn init_logging(quiet: bool) {
    let default_filter = if quiet {
        "error"
    } else {
        "error,quicpipe=info"
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

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

    /// The wormhole code to establish a connection.
    #[arg(long, short, env = "QUICPIPE_CODE")]
    code: Option<Code>,
}

#[derive(Debug, Clone, Args)]
struct CommonArgs {
    /// Path or '-' for stdin/stdout
    #[arg(default_value = "-")]
    pub path: PathBuf,

    /// Use a custom rendezvous server. Both sides need to use the same value in order to find each other.
    #[arg(long, value_name = "ws://example.org", value_hint = clap::ValueHint::Url, env = "WORMHOLE_MAILBOX_URL")]
    rendezvous_server: Option<url::Url>,

    /// Silence status output (errors only). `RUST_LOG` overrides this.
    #[arg(long, short)]
    pub quiet: bool,
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
        Cmd::Inlet(inlet_args) => {
            init_logging(inlet_args.common.quiet);
            inlet::run(inlet_args).await?;
        }
        Cmd::Outlet(outlet_args) => {
            init_logging(outlet_args.common.quiet);
            outlet::run(outlet_args).await?;
        }
    }

    Ok(0)
}

pub async fn run_from<I, S>(raw_args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let _ = color_eyre::install(); // ignore "already installed"

    let argv: Vec<std::ffi::OsString> =
        std::iter::once(std::ffi::OsString::from(env!("CARGO_PKG_NAME")))
            .chain(raw_args.into_iter().map(Into::into))
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
