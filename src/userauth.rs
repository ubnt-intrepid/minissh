//! Manages authentication process described in RFC4252.

// Refs:
// * https://tools.ietf.org/html/rfc4252

use crate::{
    consts,
    transport::Transport,
    util::{get_ssh_string, put_ssh_string},
};
use bytes::{Buf, BufMut};
use futures::{
    ready,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub enum AuthResult {
    Success,
    Failure {
        continues: Vec<u8>,
        partial_success: u8,
    },
}

pub struct Authenticator {
    state: AuthState,
    recv_buf: Box<[u8]>,
}

enum AuthState {
    Init,
    ServiceRequest,
    AuthRequests,
    Authenticated,
}

impl Default for Authenticator {
    fn default() -> Self {
        Self {
            state: AuthState::Init,
            recv_buf: vec![0u8; 0x10000].into_boxed_slice(),
        }
    }
}

impl Authenticator {
    pub fn poll_service_request<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            match self.state {
                AuthState::Init => {
                    ready!(transport.poll_ready(cx))?;
                    transport.fill_buf(|buf| {
                        buf.put_slice(b"\x05\x00\x00\x00\x0Cssh-userauth");
                    })?;

                    self.state = AuthState::ServiceRequest;
                }

                AuthState::ServiceRequest => {
                    ready!(transport.poll_flush(cx))?;
                    let mut payload = ready!(transport.poll_recv(cx, &mut self.recv_buf))?;

                    let typ = payload.get_u8();
                    if typ != consts::SSH_MSG_SERVICE_ACCEPT {
                        return Err(crate::Error::userauth("incorrect reply")).into();
                    }

                    let service_name = get_ssh_string(&mut payload);
                    if service_name != b"ssh-userauth" {
                        return Err(crate::Error::userauth("incorrect service name")).into();
                    }

                    self.state = AuthState::AuthRequests;
                    break;
                }

                AuthState::AuthRequests | AuthState::Authenticated => break,
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Request a password-based authentication.
    pub fn userauth_password<T>(
        &mut self,
        transport: &mut Transport<T>,
        username: &str,
        password: &str,
    ) -> Result<(), crate::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        assert!(matches!(self.state, AuthState::AuthRequests));

        transport.fill_buf(|mut buf| {
            buf.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
            put_ssh_string(&mut buf, username.as_ref());
            put_ssh_string(&mut buf, b"ssh-connection"); // service name
            put_ssh_string(&mut buf, b"password"); // method name
            buf.put_u8(0); // FALSE
            put_ssh_string(&mut buf, password.as_ref());
        })?;
        Ok(())
    }

    /// Wait for the completion of authentication process.
    pub fn poll_authenticate<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
    ) -> Poll<Result<AuthResult, crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            match self.state {
                AuthState::Authenticated => return Poll::Ready(Ok(AuthResult::Success)),

                AuthState::Init | AuthState::ServiceRequest => {
                    ready!(self.poll_service_request(cx, transport))?;
                }

                AuthState::AuthRequests => {
                    ready!(transport.poll_flush(cx))?;
                    let mut payload = ready!(transport.poll_recv(cx, &mut self.recv_buf))?;

                    let typ = payload.get_u8();
                    match typ {
                        consts::SSH_MSG_USERAUTH_SUCCESS => {
                            tracing::trace!("--> USERAUTH_SUCCESS");
                            debug_assert!(!payload.has_remaining());
                            self.state = AuthState::Authenticated;
                        }

                        consts::SSH_MSG_USERAUTH_FAILURE => {
                            tracing::trace!("--> USERAUTH_FAILURE");

                            let continues = get_ssh_string(&mut payload);
                            let partial_success = payload.get_u8();

                            return Poll::Ready(Ok(AuthResult::Failure {
                                continues,
                                partial_success,
                            }));
                        }

                        consts::SSH_MSG_USERAUTH_BANNER => {
                            tracing::trace!("--> USERAUTH_BANNER");
                            let _message = get_ssh_string(&mut payload);
                            let _language = get_ssh_string(&mut payload);
                            // TODO: handle banner message
                            continue;
                        }

                        typ => {
                            tracing::error!("unsupported packet type: {}", typ);
                            return Poll::Ready(Err(crate::Error::userauth(
                                "unsupported packet type",
                            )));
                        }
                    }
                }
            }
        }
    }
}
