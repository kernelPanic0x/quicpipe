use std::pin::Pin;

use tokio::{fs::OpenOptions, io::AsyncWrite};

use crate::OutletArgs;

pub async fn run(args: OutletArgs) -> color_eyre::Result<()> {
    let writer: Pin<Box<dyn AsyncWrite + Send>> = if args.common.path.as_os_str() == "-" {
        Box::pin(tokio::io::stdout())
    } else {
        Box::pin(
            OpenOptions::new()
                .write(true)
                .open(args.common.path)
                .await?,
        )
    };
    todo!()
}
