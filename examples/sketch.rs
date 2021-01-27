use anyhow::Result;
use futures::future::poll_fn;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut agent = minissh::agent::Agent::connect().await?;

    tracing::trace!("request identities");
    poll_fn(|cx| {
        futures::ready!(agent.poll_flush(cx))?;
        agent.send_request_identities().into()
    })
    .await?;
    tracing::trace!("fetch identities");
    let identity = match poll_fn(|cx| agent.poll_recv(cx)).await? {
        minissh::agent::Response::Identities(ident) => ident.into_iter().next().unwrap(),
        _ => panic!("unexpected response type"),
    };
    tracing::trace!("--> {:?}", identity);

    tracing::trace!("sign data");
    poll_fn(|cx| {
        futures::ready!(agent.poll_flush(cx))?;
        agent
            .send_sign_request(&identity, &mut &b"foo"[..], 0)
            .into()
    })
    .await?;
    let signature = match poll_fn(|cx| agent.poll_recv(cx)).await? {
        minissh::agent::Response::SignResponse(sig) => sig,
        _ => panic!("unexpected response type"),
    };
    tracing::trace!("--> {:?}", String::from_utf8_lossy(&signature));

    let addr = SocketAddr::from(([192, 168, 122, 10], 22));

    tracing::debug!("establish SSH transport (addr = {})", addr);
    let stream = TcpStream::connect(&addr).await?;
    let mut transport = minissh::transport::Transport::new(stream);
    poll_fn(|cx| transport.poll_handshake(cx)).await?;

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
