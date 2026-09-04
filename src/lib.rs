use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, eyre};
use iroh::SecretKey;
use std::{
    io::{Read, stdin},
    path::PathBuf,
};

mod inlet;
mod outlet;
mod protocol;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pipe inlet
    Inlet {
        #[arg(default_value = "-")]
        path: PathBuf,
    },
    /// Pipe outlet
    Outlet {
        #[arg(default_value = "-")]
        path: PathBuf,
    },
    /// Generate an iroh secret key and print it to stdout.
    GenKey,
    /// Generate an iroh public key based a secret key read from stdin.
    GenPub,
}

fn gen_public_key() -> color_eyre::Result<()> {
    let mut input = String::new();
    stdin()
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
        Cmd::Inlet { path } => inlet::run().await?,
        Cmd::Outlet { path } => todo!(),
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
        Ok(_) => 0,
        Err(report) => {
            eprintln!("{report:?}");
            1
        }
    }
}
