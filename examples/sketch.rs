use anyhow::Result;
use std::net::{SocketAddr, TcpStream};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([192, 168, 122, 10], 22));
    tracing::debug!("Connecting to SSH server (addr = {})", addr);
    let stream = TcpStream::connect(&addr)?;

    let _session = minissh::OpenSession::new(stream).open()?;

    Ok(())
}
