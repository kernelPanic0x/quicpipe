use clap::{Args, Parser, Subcommand};
use magic_wormhole::{AppID, Code, transfer::APP_CONFIG};
use std::{borrow::Cow, path::PathBuf};

mod completer;
mod inlet;
mod link;
mod net;
mod outlet;
mod platform;
mod protocol;
mod replay;
mod signals;
mod sink;
mod size;
mod source;
mod ui;

/// Initialize logging: `RUST_LOG` wins if set. Otherwise logs stay silent and
/// the progress bar is the only status indication; `--quiet` additionally
/// disables the bar. Errors are still reported by the exit path. Everything
/// goes to stderr, never to stdout (stdout is the pipe payload).
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error"));
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

    /// Total size of the input, e.g. 500M, 1.5GiB or 734003200.
    /// Suffixes are binary, matching pv and the progress bar: k/Ki = 1024,
    /// M/Mi = 1024², and so on.
    /// The inlet transmits this to the outlet so both sides can show progress.
    /// On the inlet it is auto-detected for regular files when omitted.
    #[arg(
        long,
        short = 's',
        value_name = "BYTES",
        value_parser = parse_byte_size
    )]
    pub size: Option<u64>,
}

/// `parse-size` defaults to decimal prefixes (`1k` = 1000), which would make
/// `-s 8M` disagree with the binary units the progress bar displays. pv-style
/// binary suffixes keep the two consistent.
fn parse_byte_size(input: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(input)
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
            init_logging();
            inlet::run(inlet_args).await?;
        }
        Cmd::Outlet(outlet_args) => {
            init_logging();
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

#[cfg(test)]
mod size_arg_tests {
    #![allow(clippy::unwrap_used, clippy::pedantic)]

    use super::parse_byte_size;

    #[test]
    fn suffixes_are_binary_to_match_the_progress_bar() {
        assert_eq!(parse_byte_size("8M").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_byte_size("1Ki").unwrap(), 1024);
        assert_eq!(
            parse_byte_size("1.5GiB").unwrap(),
            1024 * 1024 * 1024 + 512 * 1024 * 1024
        );
        assert_eq!(parse_byte_size("0").unwrap(), 0);
    }

    #[test]
    fn malformed_sizes_are_rejected() {
        assert!(parse_byte_size("12x").is_err());
    }
}
