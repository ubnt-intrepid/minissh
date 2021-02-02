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
    /// Wait for the completion of authentication process.
    pub fn poll_authenticate<T, A>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: Pin<&mut T>,
        username: &str,
        service_name: &str,
        method: Pin<&mut A>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport,
        A: AuthMethod,
    {
        todo!()
    }
}

pub trait AuthMethod {
    fn poll_authenticate<T>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        auth: Pin<&mut AuthContext<'_, T>>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport;
}

pub struct AuthContext<'a, T> {
    _marker: std::marker::PhantomData<Pin<&'a mut T>>,
}

pub struct Password<'a>(pub &'a str);
impl AuthMethod for Password<'_> {
    fn poll_authenticate<T>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        auth: Pin<&mut AuthContext<'_, T>>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: Transport,
    {
        todo!()
    }
}
