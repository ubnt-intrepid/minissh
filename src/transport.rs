/*!
The implementation of SSH transport layer protocol, described in [RFC 4253].

[RFC 4253]: https://tools.ietf.org/html/rfc4253
*/

mod default;

pub use default::DefaultTransport;

use bytes::{Buf, BufMut};
use futures::{
    ready,
    task::{self, Poll},
};
use std::{convert::TryFrom, ops::Range, pin::Pin};

/// A trait that abstracts SSH transport layer.
pub trait Transport {
    /// Perform the negotiation process of transport layer protocol.
    ///
    /// This function performs the exchange of SSH identifier line and the first
    /// key exchange session with the server, and will prepare the client to send
    /// and/or receive encrypted packets.
    fn poll_handshake(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>>;

    /// Return the session identifier for this connection.
    ///
    /// The session identifier is calculated during the first key exchange session,
    /// and used by the upper layer, such as public key based user authentication.
    ///
    /// # Panics
    /// This function causes a panic if called before completion of `poll_handshake`.
    fn session_id(&self) -> &[u8];

    /// Receive a packet from the peer.
    ///
    /// `recv_buf` is used for reading the cipher text and decrypting,
    /// and must have enough capacity for storing intermediate data.
    /// The returned value represents the range of payload data in `recv_buf`.
    ///
    /// Several packet types, such as key exchange negotiation, are filtered out
    /// and handle by the transport.
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        recv_buf: &mut [u8],
    ) -> Poll<Result<Range<usize>, crate::Error>>;

    /// Prepare the transport to write a packet of specified payload length.
    ///
    /// This function may implicitly flush the contents of the internal buffer
    /// if the remaining part of it does not have enough capacity.
    ///
    /// This function must be called and return `Poll::Ready(Ok(()))` prior
    /// to each call to `start_send`.
    fn poll_send_ready(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        payload_length: u32,
    ) -> Poll<Result<(), crate::Error>>;

    /// Begin the process to write a packet of specified payload data.
    ///
    /// The actual transmission of packet data is deferred until `poll_flush` is called.
    fn start_send<F>(self: Pin<&mut Self>, filler: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut dyn BufMut);

    /// Write a packet to the peer.
    fn poll_send<B>(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        payload: &mut B,
    ) -> Poll<Result<(), crate::Error>>
    where
        B: Buf,
    {
        let payload_length = u32::try_from(payload.remaining()).expect("payload is too large");
        ready!(self.as_mut().poll_send_ready(cx, payload_length))?;
        self.start_send(|buf| {
            while payload.has_remaining() {
                buf.put_slice(payload.chunk());
                payload.advance(payload.chunk().len());
            }
        })?;
        Poll::Ready(Ok(()))
    }

    /// Flush the internal buffer to the I/O.
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>>;
}
