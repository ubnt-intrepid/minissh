/*!
The implementation of SSH authentication protocol, described in [RFC 4252].

[RFC 4252]: https://tools.ietf.org/html/rfc4252
*/

use crate::{
    consts,
    transport::Transport,
    util::{get_ssh_string, put_ssh_string},
};
use bytes::Buf;
use futures::{
    ready,
    task::{self, Poll},
};
use std::{collections::VecDeque, convert::TryFrom, mem, pin::Pin};

/// The object that manages authentication state during a SSH session.
pub struct Userauth {
    state: AuthState,
    pending_auths: VecDeque<PendingAuth>,
    recv_buf: Box<[u8]>,
}

enum AuthState {
    Init,
    ServiceRequest,
    AuthRequests,
    Authenticated,
}

enum PendingAuth {
    PublicKey { has_signature: bool },
    Password,
}

impl Default for Userauth {
    fn default() -> Self {
        Self {
            state: AuthState::Init,
            pending_auths: VecDeque::new(),
            recv_buf: vec![0u8; 0x10000].into_boxed_slice(),
        }
    }
}

impl Userauth {
    pub fn poll_service_request<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut transport: Pin<&mut T>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport,
    {
        loop {
            match self.state {
                AuthState::Init => {
                    const PAYLOAD: &[u8] = b"\x05\x00\x00\x00\x0Cssh-userauth";
                    ready!(transport.as_mut().poll_send_ready(cx, PAYLOAD.len() as u32))?;
                    transport.as_mut().start_send(&mut &PAYLOAD[..])?;

                    self.state = AuthState::ServiceRequest;
                }

                AuthState::ServiceRequest => {
                    ready!(transport.as_mut().poll_flush(cx))?;
                    let mut payload = ready!(transport.as_mut().poll_recv(cx, &mut self.recv_buf))?;

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

    #[allow(clippy::too_many_arguments)]
    pub fn poll_userauth_publickey<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut transport: Pin<&mut T>,
        username: &str,
        service_name: &str,
        algorithm: &[u8],
        blob: &[u8],
        signature: Option<&[u8]>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport,
    {
        const METHOD_NAME: &[u8] = b"publickey";

        assert!(matches!(self.state, AuthState::AuthRequests));

        let payload_length = u32::try_from(
            mem::size_of::<u8>()
                + ssh_string_len(username.as_ref())
                + ssh_string_len(service_name.as_ref())
                + ssh_string_len(METHOD_NAME)
                + mem::size_of::<u8>()
                + ssh_string_len(algorithm)
                + ssh_string_len(blob)
                + signature.map_or(0, ssh_string_len),
        )
        .expect("payload is too large");
        ready!(transport.as_mut().poll_send_ready(cx, payload_length))?;

        transport.start_send(&mut crate::transport::payload_fn(|mut buf| {
            buf.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
            put_ssh_string(&mut buf, username.as_ref());
            put_ssh_string(&mut buf, service_name.as_ref());
            put_ssh_string(&mut buf, METHOD_NAME);
            if let Some(signature) = signature {
                buf.put_u8(1);
                put_ssh_string(&mut buf, algorithm);
                put_ssh_string(&mut buf, blob);
                put_ssh_string(&mut buf, signature);
            } else {
                buf.put_u8(0);
                put_ssh_string(&mut buf, algorithm);
                put_ssh_string(&mut buf, blob);
            }
        }))?;

        self.pending_auths.push_back(PendingAuth::PublicKey {
            has_signature: signature.is_some(),
        });

        Poll::Ready(Ok(()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_userauth_password<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut transport: Pin<&mut T>,
        username: &str,
        service_name: &str,
        password: &str,
        new_password: Option<&str>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport,
    {
        const METHOD_NAME: &[u8] = b"password";

        assert!(matches!(self.state, AuthState::AuthRequests));

        let payload_length = u32::try_from(
            mem::size_of::<u8>()
                + ssh_string_len(username.as_ref())
                + ssh_string_len(service_name.as_ref())
                + ssh_string_len(METHOD_NAME)
                + mem::size_of::<u8>()
                + ssh_string_len(password.as_ref())
                + new_password.map_or(0, |p| ssh_string_len(p.as_ref())),
        )
        .expect("payload is too large");
        ready!(transport.as_mut().poll_send_ready(cx, payload_length))?;

        transport.start_send(&mut crate::transport::payload_fn(|mut buf| {
            buf.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
            put_ssh_string(&mut buf, username.as_ref());
            put_ssh_string(&mut buf, service_name.as_ref());
            put_ssh_string(&mut buf, METHOD_NAME);
            if let Some(new_password) = new_password {
                buf.put_u8(1);
                put_ssh_string(&mut buf, password.as_ref());
                put_ssh_string(&mut buf, new_password.as_ref());
            } else {
                buf.put_u8(0);
                put_ssh_string(&mut buf, password.as_ref());
            }
        }))?;

        self.pending_auths.push_back(PendingAuth::Password);

        Poll::Ready(Ok(()))
    }

    /// Wait for the completion of authentication process.
    pub fn poll_recv<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut transport: Pin<&mut T>,
    ) -> Poll<Result<AuthResult, crate::Error>>
    where
        T: Transport,
    {
        loop {
            match self.state {
                AuthState::Init | AuthState::ServiceRequest => {
                    panic!("called before poll_service_request() complete");
                }

                AuthState::Authenticated => {
                    return Poll::Ready(Ok(AuthResult::Success));
                }

                AuthState::AuthRequests => {
                    let mut payload = ready!(transport.as_mut().poll_recv(cx, &mut self.recv_buf))?;

                    let typ = payload.get_u8();
                    match typ {
                        consts::SSH_MSG_USERAUTH_SUCCESS => {
                            debug_assert!(!payload.has_remaining());

                            let pending = self
                                .pending_auths
                                .pop_front()
                                .expect("no authentication methods are requested");

                            if let PendingAuth::PublicKey {
                                has_signature: false,
                            } = pending
                            {
                                tracing::warn!("publickey userauth succeeds without signature");
                            }

                            self.state = AuthState::Authenticated;
                            self.pending_auths.clear();

                            return Poll::Ready(Ok(AuthResult::Success));
                        }

                        consts::SSH_MSG_USERAUTH_FAILURE => {
                            let _pending = self
                                .pending_auths
                                .pop_front()
                                .expect("no authentication methods are requested");

                            let continues = get_ssh_string(&mut payload);
                            let partial_success = payload.get_u8();

                            return Poll::Ready(Ok(AuthResult::Failure {
                                continues,
                                partial_success,
                            }));
                        }

                        consts::SSH_MSG_USERAUTH_BANNER => {
                            let message = get_ssh_string(&mut payload);
                            let language_tag = get_ssh_string(&mut payload);
                            return Poll::Ready(Ok(AuthResult::Banner {
                                message,
                                language_tag,
                            }));
                        }

                        #[allow(unreachable_patterns)]
                        consts::SSH_MSG_USERAUTH_PK_OK
                        | consts::SSH_MSG_USERAUTH_PASSWD_CHANGEREQ => {
                            let pending = self
                                .pending_auths
                                .pop_front()
                                .expect("no authentication methods are requested");

                            match pending {
                                PendingAuth::PublicKey { .. } => {
                                    let algorithm = get_ssh_string(&mut payload);
                                    let blob = get_ssh_string(&mut payload);
                                    return Poll::Ready(Ok(AuthResult::PublicKeyOk {
                                        algorithm,
                                        blob,
                                    }));
                                }

                                PendingAuth::Password { .. } => {
                                    let prompt = get_ssh_string(&mut payload);
                                    let language_tag = get_ssh_string(&mut payload);
                                    return Poll::Ready(Ok(AuthResult::PasswordChangeReq {
                                        prompt,
                                        language_tag,
                                    }));
                                }
                            }
                        }

                        typ => {
                            return Poll::Ready(Err(crate::Error::userauth(format!(
                                "unsupported packet type: {}",
                                typ
                            ))));
                        }
                    }
                }
            }
        }
    }
}

#[non_exhaustive]
#[must_use]
pub enum AuthResult {
    Success,
    Failure {
        continues: Vec<u8>,
        partial_success: u8,
    },
    Banner {
        message: Vec<u8>,
        language_tag: Vec<u8>,
    },
    PublicKeyOk {
        algorithm: Vec<u8>,
        blob: Vec<u8>,
    },
    PasswordChangeReq {
        prompt: Vec<u8>,
        language_tag: Vec<u8>,
    },
}

#[inline(always)]
const fn ssh_string_len(s: &[u8]) -> usize {
    mem::size_of::<u32>() + s.len()
}
