use crate::{connection::Connection, consts, transport::Transport};
use bytes::{Buf, BufMut};
use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn start<T>(transport: &mut Transport<T>) -> Result<Authenticator, crate::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    const PAYLOAD: &[u8] = b"\x05\x00\x00\x00\x0Cssh-userauth";

    tracing::trace!("request ssh-userauth");
    poll_fn(|cx| transport.poll_send(cx, &mut &PAYLOAD[..])).await?;
    poll_fn(|cx| transport.poll_flush(cx)).await?;

    tracing::trace!("wait response for ssh-userauth service request");
    poll_fn(|cx| transport.poll_recv(cx)).await?;
    let mut payload = transport.payload();

    let typ = payload.get_u8();
    if typ != consts::SSH_MSG_SERVICE_ACCEPT {
        return Err(crate::Error::userauth("incorrect reply"));
    }

    let service_name = get_ssh_string(&mut payload);
    if service_name != b"ssh-userauth" {
        return Err(crate::Error::userauth("incorrect service name"));
    }

    Ok(Authenticator {
        num_requested_auths: 0,
    })
}

pub struct Authenticator {
    num_requested_auths: usize,
}

impl Authenticator {
    /// Request a password-based authentication.
    pub async fn request_userauth_password<T>(
        &mut self,
        transport: &mut Transport<T>,
        username: &str,
        password: &str,
    ) -> Result<(), crate::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // ref: https://tools.ietf.org/html/rfc4252#section-8
        // FIXME: prevent password leakage.

        let mut payload = vec![];
        payload.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
        put_ssh_string(&mut payload, username.as_ref());
        put_ssh_string(&mut payload, b"ssh-connection"); // service name
        put_ssh_string(&mut payload, b"password"); // method name
        payload.put_u8(0); // FALSE
        put_ssh_string(&mut payload, password.as_ref());

        poll_fn(|cx| transport.poll_send(cx, &mut &payload[..])).await?;

        // Zeroing payload buffer before drop.
        unsafe {
            std::ptr::write_bytes(payload.as_mut_ptr(), 0u8, payload.len());
        }
        drop(payload);

        self.num_requested_auths += 1;

        Ok(())
    }

    /// Wait for the completion of authentication process.
    pub async fn authenticate<T>(
        &mut self,
        transport: &mut Transport<T>,
    ) -> Result<bool, crate::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        poll_fn(|cx| transport.poll_flush(cx)).await?;

        while self.num_requested_auths > 0 {
            poll_fn(|cx| transport.poll_recv(cx)).await?;
            let mut payload = transport.payload();

            let typ = payload.get_u8();
            match typ {
                consts::SSH_MSG_USERAUTH_SUCCESS => {
                    tracing::trace!("--> USERAUTH_SUCCESS");
                    debug_assert!(payload.is_empty());
                    return Ok(true);
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
                    return Err(crate::Error::userauth("unsupported packet type"));
                }
            }
        }

        Ok(false)
    }
}

fn get_ssh_string<B: Buf>(mut b: B) -> Vec<u8> {
    let len = b.get_u32();
    let mut s = vec![0u8; len as usize];
    b.copy_to_slice(&mut s[..]);
    s
}

fn put_ssh_string<B: BufMut>(mut b: B, s: &[u8]) {
    let len = s.len() as u32;
    b.put_u32(len);
    b.put_slice(s);
}
