use anyhow::Result;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 22));
    tracing::debug!("Connecting to SSH server (addr = {})", addr);
    let mut session = minissh::transport::connect(&addr).await?;

    tracing::debug!("Handshake");
    futures::future::poll_fn(|cx| session.poll_handshake(cx)).await?;
    tracing::debug!("--> Done");

    Ok(())
}
