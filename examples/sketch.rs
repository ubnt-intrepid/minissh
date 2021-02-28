use std::net::TcpStream;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    tracing::trace!("establish TCP connection");
    let _stream = TcpStream::connect("127.0.0.1:22")?;

    Ok(())
}
