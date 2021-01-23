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

    tracing::debug!("userauth");
    let mut userauth = minissh::userauth::Authenticator::default();
    poll_fn(|cx| userauth.poll_userauth_password(cx, &mut transport, "devenv", "devenv")).await?;
    loop {
        let res = poll_fn(|cx| userauth.poll_authenticate(cx, &mut transport)).await?;
        match res {
            minissh::userauth::AuthResult::Success => break,
            minissh::userauth::AuthResult::Failure { .. } => tracing::error!("auth failed"),
        }
    }
    tracing::debug!("--> success");

    tracing::debug!("connection");
    let mut conn = minissh::connection::Connection::default();

    let channel = poll_fn(|cx| conn.poll_channel_open_session(cx, &mut transport)).await?;
    loop {
        use minissh::connection::{ChannelResponse, Response};

        let response = poll_fn(|cx| conn.poll_recv(cx, &mut transport)).await?;
        match response {
            Response::Channel(id, ChannelResponse::OpenConfirmation) => {
                tracing::debug!("open confirmation");
                debug_assert_eq!(id, channel);
                break;
            }
            Response::Channel(_id, ChannelResponse::OpenFailure { .. }) => {
                tracing::debug!("open failure");
                break;
            }
            _ => (),
        }
    }

    poll_fn(|cx| conn.poll_request_exec(cx, &mut transport, channel, "pwd")).await?;
    poll_fn(|cx| conn.poll_window_adjust(cx, &mut transport, channel, 1024 * 8)).await?;
    loop {
        use minissh::connection::{ChannelResponse, Response};

        let response = poll_fn(|cx| conn.poll_recv(cx, &mut transport)).await?;
        match response {
            Response::Channel(_id, ChannelResponse::Data(data)) => {
                tracing::debug!("data: {:?}", std::str::from_utf8(&*data));
            }
            Response::Channel(_id, ChannelResponse::Eof) => {
                tracing::debug!("EOF");
                break;
            }
            _ => (),
        }
    }

    Ok(())
}
