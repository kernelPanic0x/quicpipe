use quicpipe::run_from;

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1);
    let code = run_from(args).await;
    if code != 0 {
        std::process::exit(code);
    }
}
