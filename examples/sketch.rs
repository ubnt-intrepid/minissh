use anyhow::Result;
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
    userauth
        .request_userauth_password(&mut transport, "devenv", "devenv")
        .await?;
    let conn = userauth.authenticate(&mut transport).await?;

    Ok(())
}
