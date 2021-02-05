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
use std::{collections::VecDeque, pin::Pin};

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

    /// Send an user authentication request.
    pub fn send_userauth<T>(
        &mut self,
        transport: Pin<&mut T>,
        username: &str,
        service_name: &str,
        method: AuthMethod<'_>,
    ) -> Result<(), crate::Error>
    where
        T: Transport,
    {
        assert!(matches!(self.state, AuthState::AuthRequests));

        transport.start_send(&mut crate::transport::payload_fn(|mut buf| {
            buf.put_u8(consts::SSH_MSG_USERAUTH_REQUEST);
            put_ssh_string(&mut buf, username.as_ref());
            put_ssh_string(&mut buf, service_name.as_ref());
            match method {
                AuthMethod::PublicKey {
                    algorithm,
                    blob: key,
                    signature,
                } => {
                    put_ssh_string(&mut buf, b"publickey"); // method name
                    if let Some(signature) = signature {
                        buf.put_u8(1);
                        put_ssh_string(&mut buf, algorithm);
                        put_ssh_string(&mut buf, key);
                        put_ssh_string(&mut buf, signature);
                        self.pending_auths.push_back(PendingAuth::PublicKey {
                            has_signature: true,
                        });
                    } else {
                        buf.put_u8(0);
                        put_ssh_string(&mut buf, algorithm);
                        put_ssh_string(&mut buf, key);
                        self.pending_auths.push_back(PendingAuth::PublicKey {
                            has_signature: false,
                        });
                    }
                }

                AuthMethod::Password { current, new } => {
                    put_ssh_string(&mut buf, b"password"); // method name
                    if let Some(new) = new {
                        buf.put_u8(1);
                        put_ssh_string(&mut buf, current.as_ref());
                        put_ssh_string(&mut buf, new.as_ref());
                    } else {
                        buf.put_u8(0);
                        put_ssh_string(&mut buf, current.as_ref());
                    }
                    self.pending_auths.push_back(PendingAuth::Password);
                }
            }
        }))?;
        Ok(())
    }

    /// Wait for the completion of authentication process.
    pub fn poll_authenticate<T>(
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
pub enum AuthMethod<'a> {
    PublicKey {
        algorithm: &'a [u8],
        blob: &'a [u8],
        signature: Option<&'a [u8]>,
    },

    Password {
        current: &'a str,
        new: Option<&'a str>,
    },
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
