use anyhow::Result;
use futures::{future::poll_fn, ready};
use minissh::{
    connection::Connection,
    transport::Transport,
    userauth::{AuthMethod, AuthResult, Userauth},
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([192, 168, 122, 10], 22));

    tracing::debug!("establish SSH transport (addr = {})", addr);
    let stream = TcpStream::connect(&addr).await?;
    let mut transport = Transport::new(stream);
    poll_fn(|cx| transport.poll_handshake(cx)).await?;

    tracing::debug!("userauth");
    let mut userauth = Userauth::default();
    poll_fn(|cx| userauth.poll_service_request(cx, &mut transport)).await?;

    poll_fn(|cx| {
        ready!(transport.poll_send_ready(cx))?;
        userauth
            .send_userauth(
                &mut transport,
                "devenv",
                AuthMethod::Password {
                    current: "devenv",
                    new: None,
                },
            )
            .into()
    })
    .await?;
    loop {
        let res = poll_fn(|cx| userauth.poll_authenticate(cx, &mut transport)).await?;
        match res {
            AuthResult::Success => {
                tracing::debug!("--> success");
                break;
            }
            AuthResult::Banner { message, .. } => {
                tracing::debug!("--> banner(message = {:?})", std::str::from_utf8(&message));
            }
            AuthResult::Failure { .. } | AuthResult::PasswordChangeReq { .. } => {
                anyhow::bail!("auth failed");
            }
            _ => unreachable!(),
        }
    }

    tracing::debug!("connection");
    let mut conn = Connection::default();
    let channel = conn.channel_open_session(&mut transport)?;
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

    poll_fn(|cx| transport.poll_flush(cx)).await?;
    conn.channel_request_exec(&mut transport, channel, "pwd")?;
    conn.window_adjust(&mut transport, channel, 1024 * 8)?;
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
