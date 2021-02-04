/*!
The implementation of SSH transport layer protocol, described in [RFC 4253].

[RFC 4253]: https://tools.ietf.org/html/rfc4253
*/

mod default;

pub use default::DefaultTransport;

use bytes::{Buf, BufMut};
use futures::task::{self, Poll};
use std::pin::Pin;

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
    /// After decryption, the payload part is returned as a sub slice of
    /// `recv_buf`.
    ///
    /// Several packet types, such as key exchange negotiation, are filtered out
    /// and handle by the transport.
    fn poll_recv<'a>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        recv_buf: &'a mut [u8],
    ) -> Poll<Result<&'a [u8], crate::Error>>;

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
    fn start_send<P>(self: Pin<&mut Self>, payload: &mut P) -> Result<(), crate::Error>
    where
        P: Payload;

    /// Flush the internal buffer to the I/O.
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>>;
}

pub trait Payload {
    fn fill_buffer(&mut self, buf: &mut dyn BufMut);
}

impl<T: Buf> Payload for T {
    fn fill_buffer(&mut self, buf: &mut dyn BufMut) {
        while self.has_remaining() {
            buf.put_slice(self.chunk());
            self.advance(self.chunk().len());
        }
    }
}

pub(crate) fn payload_fn<F>(f: F) -> impl Payload
where
    F: FnOnce(&mut dyn BufMut),
{
    struct PayloadFn<F>(Option<F>);
    impl<F> Payload for PayloadFn<F>
    where
        F: FnOnce(&mut dyn BufMut),
    {
        fn fill_buffer(&mut self, buf: &mut dyn BufMut) {
            let filler = self.0.take().expect("already consumed");
            filler(buf)
        }
    }
    PayloadFn(Some(f))
}
