use anyhow::Result;
use futures::future::poll_fn;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([192, 168, 122, 10], 22));

    tracing::debug!("connect to SSH server (addr = {})", addr);
    let stream = TcpStream::connect(&addr).await?;

    tracing::debug!("establish SSH transport");
    let mut transport = minissh::transport::establish(stream).await?;

    tracing::debug!("establish SSH transport");
    let mut userauth = minissh::userauth::start(&mut transport).await?;
    poll_fn(|cx| userauth.poll_request_userauth_password(cx, &mut transport, "devenv", "devenv"))
        .await?;
    let _authenticated = poll_fn(|cx| userauth.poll_authenticate(cx, &mut transport)).await?;

    Ok(())
}
