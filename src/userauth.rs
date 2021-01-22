use crate::{
    consts,
    transport::Transport,
    util::{get_ssh_string, put_ssh_string},
};
use bytes::{Buf, BufMut};
use futures::{
    future::poll_fn,
    ready,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn start<T>(transport: &mut Transport<T>) -> Result<Authenticator, crate::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const PAYLOAD: &[u8] = b"\x05\x00\x00\x00\x0Cssh-userauth";

    tracing::trace!("request ssh-userauth");
    poll_fn(|cx| transport.poll_send_ready(cx)).await?;
    transport.send(&mut &PAYLOAD[..])?;
    poll_fn(|cx| transport.poll_flush(cx)).await?;

    tracing::trace!("wait response for ssh-userauth service request");
    poll_fn(|cx| {
        let mut payload = ready!(transport.poll_recv(cx))?;

        let typ = payload.get_u8();
        if typ != consts::SSH_MSG_SERVICE_ACCEPT {
            return Err(crate::Error::userauth("incorrect reply")).into();
        }

        let service_name = get_ssh_string(&mut payload);
        if service_name != b"ssh-userauth" {
            return Err(crate::Error::userauth("incorrect service name")).into();
        }

        Ok(()).into()
    })
    .await?;

    Ok(Authenticator {
        num_requested_auths: 0,
    })
}

pub struct Authenticator {
    num_requested_auths: usize,
}

impl Authenticator {
    /// Request a password-based authentication.
    pub fn poll_request_userauth_password<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
        username: &str,
        password: &str,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // ref: https://tools.ietf.org/html/rfc4252#section-8
        // FIXME: prevent password leakage.

        ready!(transport.poll_send_ready(cx))?;

        let mut payload = vec![];
        payload.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
        put_ssh_string(&mut payload, username.as_ref());
        put_ssh_string(&mut payload, b"ssh-connection"); // service name
        put_ssh_string(&mut payload, b"password"); // method name
        payload.put_u8(0); // FALSE
        put_ssh_string(&mut payload, password.as_ref());
        transport.send(&mut &payload[..])?;

        self.num_requested_auths += 1;

        Poll::Ready(Ok(()))
    }

    /// Wait for the completion of authentication process.
    pub fn poll_authenticate<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
    ) -> Poll<Result<bool, crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        ready!(transport.poll_flush(cx))?;

        while self.num_requested_auths > 0 {
            let mut payload = ready!(transport.poll_recv(cx))?;

            let typ = payload.get_u8();
            match typ {
                consts::SSH_MSG_USERAUTH_SUCCESS => {
                    tracing::trace!("--> USERAUTH_SUCCESS");
                    debug_assert!(!payload.has_remaining());

                    return Poll::Ready(Ok(true));
                }

                consts::SSH_MSG_USERAUTH_FAILURE => {
                    tracing::trace!("--> USERAUTH_FAILURE");

                    self.num_requested_auths -= 1;

                    let _continues = get_ssh_string(&mut payload);
                    let _partial_success = payload.get_u8();
                }

                consts::SSH_MSG_USERAUTH_BANNER => {
                    tracing::trace!("--> USERAUTH_BANNER");
                    let _message = get_ssh_string(&mut payload);
                    let _language = get_ssh_string(&mut payload);
                }

                typ => {
                    tracing::error!("unsupported packet type: {}", typ);
                    return Poll::Ready(Err(crate::Error::userauth("unsupported packet type")));
                }
            }
        }

        Poll::Ready(Ok(false))
    }
}
