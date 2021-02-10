use super::Transport;
use crate::{
    consts,
    util::{get_ssh_string, peek_u8, put_ssh_string},
};
use bytes::{buf::UninitSlice, Buf, BufMut, Bytes, BytesMut};
use futures::{
    ready,
    task::{self, Poll},
};
use pin_project_lite::pin_project;
use ring::{aead::chacha20_poly1305_openssh as aead, agreement, digest, rand, signature};
use std::{cmp, convert::TryInto as _, io, mem::MaybeUninit, num, ops::Range, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// defined in https://git.libssh.org/projects/libssh.git/tree/doc/curve25519-sha256@libssh.org.txt#n62
const CURVE25519_SHA256: &str = "curve25519-sha256@libssh.org";

// defined in http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?rev=1.5&content-type=text/x-cvsweb-markup
const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";

const CLIENT_SSH_ID: &[u8] = concat!("SSH-2.0-minissh_", env!("CARGO_PKG_VERSION")).as_bytes();

/// The object that drives SSH transport layer.
pub struct DefaultTransport<T> {
    inner: Inner<T>,
}

impl<T> DefaultTransport<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// Create a new `Transport` with the specified I/O object.
    pub fn new(stream: T) -> Self {
        Self {
            inner: Inner {
                stream,
                state: TransportState::Init,
                send: SendPacket::new(0x10000),
                recv: RecvPacket::default(),
                kex: KeyExchange::default(),
                session_id: None,
                rng: rand::SystemRandom::new(),
            },
        }
    }

    /// Return a reference to underlying I/O object.
    #[inline]
    pub fn get_ref(&self) -> &T {
        &self.inner.stream
    }

    /// Return a mutable reference to underlying I/O object.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T
    where
        T: Unpin,
    {
        &mut self.inner.stream
    }

    /// Return a pinned reference to underlying I/O object.
    #[inline]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut T> {
        self.inner_proj().stream
    }

    #[inline]
    fn inner_proj(self: Pin<&mut Self>) -> InnerProj<'_, T> {
        unsafe { Pin::map_unchecked_mut(self, |me| &mut me.inner) }.project()
    }
}

impl<T> Transport for DefaultTransport<T>
where
    T: AsyncRead + AsyncWrite,
{
    #[inline]
    fn poll_handshake(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>> {
        self.inner_proj().poll_handshake(cx)
    }

    #[inline]
    fn session_id(&self) -> &[u8] {
        self.inner.session_id.as_ref().unwrap().as_ref()
    }

    #[inline]
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        recv_buf: &mut [u8],
    ) -> Poll<Result<Range<usize>, crate::Error>> {
        self.inner_proj().poll_recv(cx, recv_buf)
    }

    #[inline]
    fn poll_send_ready(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        payload_length: u32,
    ) -> Poll<Result<(), crate::Error>> {
        self.inner_proj().poll_send_ready(cx, payload_length)
    }

    #[inline]
    fn start_send<F>(self: Pin<&mut Self>, filler: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut dyn BufMut),
    {
        self.inner_proj().start_send(filler)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>> {
        self.inner_proj().poll_flush(cx)
    }
}

pin_project! {
    #[project = InnerProj]
    struct Inner<T> {
        #[pin]
        stream: T,
        state: TransportState,
        send: SendPacket,
        recv: RecvPacket,
        kex: KeyExchange,
        session_id: Option<digest::Digest>,
        rng: rand::SystemRandom,
    }
}

enum TransportState {
    Init,
    WriteClientSshId {
        line: Vec<u8>,
        written: usize,
    },
    FlushClientSshId,
    ReadServerSshId {
        buf: BytesMut,
    },
    WaitingServerKexInit {
        recv_buf: Box<[u8]>,
        remains: Option<Bytes>,
    },
    Kex,
    Ready,
    Disconnected,
}

impl<T> InnerProj<'_, T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_handshake(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_handshake");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init => {
                    tracing::trace!("--> Init");
                    *self.state = TransportState::WriteClientSshId {
                        line: {
                            let mut line = CLIENT_SSH_ID.to_owned();
                            line.put_slice(b"\r\n");
                            line
                        },
                        written: 0,
                    };
                }

                TransportState::WriteClientSshId {
                    ref line,
                    ref mut written,
                } => {
                    tracing::trace!("--> WriteClientSshId(written = {})", written);

                    let mut stream = Pin::new(&mut self.stream);

                    let mut buf = &line[*written..];
                    while buf.has_remaining() {
                        let amt = ready!(stream.as_mut().poll_write(cx, buf))
                            .map_err(crate::Error::io)?;
                        buf.advance(amt);
                        *written += amt;
                    }

                    *self.state = TransportState::FlushClientSshId;
                }

                TransportState::FlushClientSshId => {
                    tracing::trace!("--> FlushClientSshId");

                    let mut stream = Pin::new(&mut self.stream);
                    ready!(stream.as_mut().poll_flush(cx)).map_err(crate::Error::io)?;

                    *self.state = TransportState::ReadServerSshId {
                        buf: BytesMut::with_capacity(256), // TODO: choose appropriate buffer size
                    };
                }

                TransportState::ReadServerSshId { ref mut buf } => {
                    tracing::trace!(
                        "--> ReadServerSshId(buf = {:?})",
                        String::from_utf8_lossy(&buf)
                    );

                    let mut stream = Pin::new(&mut self.stream);

                    unsafe {
                        let mut read_buf = ReadBuf::uninit(std::slice::from_raw_parts_mut(
                            buf.as_mut_ptr() as *mut MaybeUninit<u8>,
                            buf.capacity(),
                        ));
                        read_buf.assume_init(buf.len());
                        read_buf.set_filled(buf.len());

                        let rem = read_buf.remaining();
                        ready!(stream.as_mut().poll_read(cx, &mut read_buf))
                            .map_err(crate::Error::io)?;
                        if rem == read_buf.remaining() {
                            return Poll::Ready(Err(crate::Error::io(eof("recv server SSH id"))));
                        }

                        buf.set_len(read_buf.filled().len());
                    }

                    let (server_id, remains) = match buf.iter().position(|&b| b == b'\n') {
                        Some(pos) => {
                            let mut line = buf.split_to(pos + 1); // including \n
                            if !line.starts_with(b"SSH-") {
                                // ignore banner text.
                                continue;
                            }

                            let buf = std::mem::take(buf);

                            let n = line
                                .iter()
                                .take_while(|&&c| c != b'\r' && c != b'\n')
                                .count();
                            line.truncate(n);

                            (line.freeze(), buf.freeze())
                        }
                        None => {
                            // continue reading line.
                            continue;
                        }
                    };

                    tracing::trace!("--> server_id = {:?}", String::from_utf8_lossy(&server_id));

                    self.kex.server_id = server_id.to_vec();
                    *self.state = TransportState::WaitingServerKexInit {
                        recv_buf: vec![0u8; 0x10000].into_boxed_slice(),
                        remains: Some(remains),
                    };
                }

                TransportState::WaitingServerKexInit {
                    ref mut recv_buf,
                    ref mut remains,
                } => {
                    tracing::trace!("--> WaitingServerKexInit");

                    let range = ready!(self.recv.poll_recv(
                        cx,
                        Pin::new(&mut Rewind {
                            stream: self.stream.as_mut(),
                            remains,
                        }),
                        recv_buf
                    ))?;
                    debug_assert!(remains.as_ref().map_or(true, |buf| buf.is_empty()));

                    let mut payload = &recv_buf[range];

                    match peek_u8(&payload) {
                        Some(consts::SSH_MSG_DISCONNECT) => {
                            // TODO: parse disconnect message
                            *self.state = TransportState::Disconnected;
                        }

                        Some(consts::SSH_MSG_KEXINIT) => {
                            tracing::trace!("--> KEXINIT");
                            self.kex.start(&mut payload, &self.rng)?;
                            *self.state = TransportState::Kex;
                        }

                        Some(typ) => {
                            tracing::trace!("--> {}, ignoring", typ);
                        }

                        None => panic!("payload is too short"),
                    }
                }

                TransportState::Kex => {
                    tracing::trace!("--> Kex");
                    ready!(self.poll_kex(cx))?;
                }

                TransportState::Ready => return Poll::Ready(Ok(())),

                TransportState::Disconnected => {
                    return Poll::Ready(Err(crate::Error::transport("disconnected")));
                }
            }
        }
    }

    fn poll_kex(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        assert!(
            matches!(self.state, TransportState::Kex),
            "unexpected condition"
        );

        let (opening_key, sealing_key, exchange_hash) = ready!(self.kex.poll_complete(
            cx,
            self.stream.as_mut(),
            &mut self.send,
            &mut self.recv,
            self.session_id.as_ref(),
        ))?;

        self.recv.key = OpeningKey::Chacha20Poly1305(opening_key);
        self.send.key = SealingKey::Chacha20Poly1305(sealing_key);

        // The first exchange hash is used as 'session id'.
        self.session_id.get_or_insert(exchange_hash);

        *self.state = TransportState::Ready;

        Poll::Ready(Ok(()))
    }

    fn poll_recv(
        &mut self,
        cx: &mut task::Context<'_>,
        recv_buf: &mut [u8],
    ) -> Poll<Result<Range<usize>, crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_recv");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init
                | TransportState::WriteClientSshId { .. }
                | TransportState::FlushClientSshId
                | TransportState::ReadServerSshId { .. }
                | TransportState::WaitingServerKexInit { .. } => {
                    panic!("called before poll_handshake() completed")
                }

                TransportState::Ready => {
                    tracing::trace!("--> Ready");

                    let range = ready!(self.recv.poll_recv(cx, self.stream.as_mut(), recv_buf))?;
                    let mut payload = &recv_buf[range.clone()];

                    match peek_u8(&payload) {
                        Some(consts::SSH_MSG_DISCONNECT) => {
                            // TODO: parse disconnect message
                            *self.state = TransportState::Disconnected;
                        }

                        Some(consts::SSH_MSG_IGNORE) => { /* ignore silently */ }
                        Some(consts::SSH_MSG_DEBUG) => { /* ignore for simplicity */ }
                        Some(consts::SSH_MSG_UNIMPLEMENTED) => {
                            // Bypassed since it was caused by the upper layer.
                            return Poll::Ready(Ok(range));
                        }

                        Some(consts::SSH_MSG_KEXINIT) => {
                            tracing::trace!("--> KEXINIT");
                            self.kex.start(&mut payload, &self.rng)?;
                            *self.state = TransportState::Kex;
                        }

                        Some(typ) => {
                            tracing::trace!("--> {}, state=TransportState::Ready", typ);
                            return Poll::Ready(Ok(range));
                        }

                        None => panic!("payload is too short"),
                    }
                }

                TransportState::Kex => {
                    tracing::trace!("--> Kex");
                    ready!(self.poll_kex(cx))?;
                }

                TransportState::Disconnected => {
                    return Poll::Ready(Err(crate::Error::transport("disconnected")));
                }
            }
        }
    }

    fn poll_send_ready(
        &mut self,
        cx: &mut task::Context<'_>,
        payload_length: u32,
    ) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_send_ready");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init
                | TransportState::WriteClientSshId { .. }
                | TransportState::FlushClientSshId
                | TransportState::ReadServerSshId { .. }
                | TransportState::WaitingServerKexInit { .. } => {
                    panic!("called before poll_handshake() completed")
                }

                TransportState::Kex => {
                    tracing::trace!("--> Kex");
                    ready!(self.poll_kex(cx))?;
                }

                TransportState::Ready => {
                    tracing::trace!("--> Ready");
                    ready!(self
                        .send
                        .poll_send_ready(cx, self.stream.as_mut(), payload_length))?;
                    return Poll::Ready(Ok(()));
                }

                TransportState::Disconnected => {
                    return Poll::Ready(Err(crate::Error::transport("disconnected")));
                }
            }
        }
    }

    fn start_send<F>(&mut self, filler: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut dyn BufMut),
    {
        let span = tracing::trace_span!("Transport::send");
        let _enter = span.enter();

        assert!(
            matches!(self.state, TransportState::Ready),
            "transport is not ready to send"
        );

        self.send.start_send(filler)?;

        Ok(())
    }

    fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        self.send.poll_flush(cx, self.stream.as_mut())
    }
}

pin_project! {
    struct Rewind<'a, T> {
        #[pin]
        stream: T,
        remains: &'a mut Option<Bytes>,
    }
}

impl<T> AsyncRead for Rewind<'_, T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();

        if let Some(ref mut remains) = me.remains {
            if !remains.is_empty() {
                let amt = cmp::min(remains.len(), buf.remaining());
                buf.put_slice(&remains[..amt]);
                remains.advance(amt);

                if remains.is_empty() {
                    me.remains.take();
                }

                return Poll::Ready(Ok(()));
            }
        }

        me.stream.poll_read(cx, buf)
    }
}

// ==== SendPacket ====

struct SendPacket {
    buf: Box<[u8]>,
    filled: usize,
    state: SendPacketState,
    seqn: num::Wrapping<u32>,
    key: SealingKey,
}

enum SendPacketState {
    Buffering,
    Writing(usize),
    Flushing,
}

impl SendPacket {
    #[inline]
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            filled: 0,
            state: SendPacketState::Buffering,
            seqn: num::Wrapping(0),
            key: SealingKey::ClearText,
        }
    }

    fn poll_send_ready<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: Pin<&mut T>,
        payload_length: u32,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncWrite,
    {
        if let SendPacketState::Buffering = self.state {
            let padding_length = self.key.padding_length(payload_length as usize);
            let packet_length = 1 + payload_length as usize + padding_length;
            let encrypted_packet_length = 4 + packet_length as usize + self.key.tag_len();

            if self.filled + encrypted_packet_length <= self.buf.len() {
                return Poll::Ready(Ok(()));
            }
        }

        self.poll_flush(cx, stream)
    }

    fn start_send<F>(&mut self, filler: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut dyn BufMut),
    {
        assert!(
            matches!(self.state, SendPacketState::Buffering),
            "not ready to buffer data"
        );

        let buf = &mut self.buf[self.filled..];

        let payload_length = {
            let mut send_buf = SendBuf {
                buf: &mut buf[4 + 1..], // packet_length(u32) + padding_length(u8)
                filled: 0,
            };
            filler(&mut send_buf);
            send_buf.filled
        };
        tracing::trace!("--> payload_length = {}", payload_length);

        let padding_length = self.key.padding_length(payload_length);
        let packet_length = 1 + payload_length + padding_length;
        let encrypted_packet_length = 4 + packet_length + self.key.tag_len();
        tracing::trace!("--> payload_length = {}", payload_length);

        self.filled += encrypted_packet_length;
        let buf = &mut buf[..encrypted_packet_length];

        buf[..4].copy_from_slice(&(packet_length as u32).to_be_bytes());
        buf[4] = padding_length as u8;
        unsafe {
            let padding = &mut buf[5 + payload_length..5 + payload_length + padding_length];
            std::ptr::write_bytes(padding.as_mut_ptr(), 0, padding.len());
        }

        tracing::trace!("encrypt packet");
        {
            let (packet, tag) = buf.split_at_mut(4 + packet_length);
            assert_eq!(tag.len(), self.key.tag_len());
            self.key.seal_in_place(self.seqn.0, packet, tag)?;
        }

        self.seqn += num::Wrapping(1);

        Ok(())
    }

    fn poll_flush<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut stream: Pin<&mut T>,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncWrite,
    {
        loop {
            match self.state {
                SendPacketState::Buffering => {
                    if self.filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.state = SendPacketState::Writing(0);
                }

                SendPacketState::Writing(ref mut written) => {
                    let mut buf = &self.buf[*written..self.filled];
                    while buf.has_remaining() {
                        let amt = ready!(stream.as_mut().poll_write(cx, buf.chunk()))
                            .map_err(crate::Error::io)?;
                        buf.advance(amt);
                        *written += amt;
                    }
                    self.state = SendPacketState::Flushing;
                }

                SendPacketState::Flushing => {
                    ready!(stream.as_mut().poll_flush(cx)).map_err(crate::Error::io)?;

                    // clear the previous ciphertext.
                    unsafe {
                        let slot = &mut self.buf[..self.filled];
                        std::ptr::write_bytes(slot.as_mut_ptr(), 0u8, slot.len());
                    }

                    self.state = SendPacketState::Buffering;
                    self.filled = 0;

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

struct SendBuf<'a> {
    buf: &'a mut [u8],
    filled: usize,
}
unsafe impl BufMut for SendBuf<'_> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.buf.len() - self.filled
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let remaining = &mut self.buf[self.filled..];
        unsafe { UninitSlice::from_raw_parts_mut(remaining.as_mut_ptr(), remaining.len()) }
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.filled += cnt;
    }

    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        assert!(self.remaining_mut() >= src.len(), "slice is too large");
        self.buf[self.filled..self.filled + src.len()].copy_from_slice(src);
        self.filled += src.len();
    }
}

// ==== RecvPacket ====

struct RecvPacket {
    state: RecvPacketState,
    seqn: num::Wrapping<u32>,
    key: OpeningKey,
}

enum RecvPacketState {
    Ready,
    ReadingLength {
        filled: usize,
    },
    ReadingPacket {
        packet_length: u32,
        buf_len: usize,
        filled: usize,
    },
}

impl Default for RecvPacket {
    fn default() -> Self {
        Self {
            state: RecvPacketState::Ready,
            seqn: num::Wrapping(0),
            key: OpeningKey::ClearText,
        }
    }
}

impl RecvPacket {
    /// Attempt to receive a packet from underlying I/O, and decrypt the ciphertext.
    fn poll_recv<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut stream: Pin<&mut T>,
        buf: &mut [u8],
    ) -> Poll<Result<Range<usize>, crate::Error>>
    where
        T: AsyncRead,
    {
        let span = tracing::trace_span!("RecvPacket::poll_recv");
        let _enter = span.enter();

        loop {
            match self.state {
                RecvPacketState::Ready => {
                    tracing::trace!("--> Ready");
                    self.state = RecvPacketState::ReadingLength { filled: 0 };
                }

                RecvPacketState::ReadingLength { ref mut filled } => {
                    tracing::trace!("--> ReadingLength(filled = {})", filled);

                    let mut read_buf = ReadBuf::new(&mut buf[..aead::PACKET_LENGTH_LEN]);
                    read_buf.set_filled(*filled);

                    loop {
                        let rem = read_buf.remaining();
                        if rem == 0 {
                            break;
                        }

                        ready!(stream.as_mut().poll_read(cx, &mut read_buf))
                            .map_err(crate::Error::io)?;
                        *filled = read_buf.filled().len();

                        if read_buf.remaining() == rem {
                            return Poll::Ready(Err(crate::Error::io(eof(
                                "unexpected eof during reading packet length",
                            ))));
                        }
                    }

                    let encrypted_packet_length = &buf[..aead::PACKET_LENGTH_LEN] //
                        .try_into()
                        .expect("packet length is too short");
                    let packet_length = u32::from_be_bytes(
                        self.key
                            .decrypt_packet_length(self.seqn.0, *encrypted_packet_length),
                    );
                    tracing::trace!("packet_lenghth = {}", packet_length);

                    let buf_len =
                        aead::PACKET_LENGTH_LEN + packet_length as usize + self.key.tag_len();
                    assert!(buf.len() >= buf_len, "provided buffer is too short");

                    self.state = RecvPacketState::ReadingPacket {
                        packet_length,
                        buf_len,
                        filled: aead::PACKET_LENGTH_LEN,
                    };
                }

                RecvPacketState::ReadingPacket {
                    packet_length,
                    buf_len,
                    ref mut filled,
                } => {
                    tracing::trace!("--> ReadingPacket(filled = {})", filled);

                    let buf = &mut buf[..buf_len];

                    {
                        let mut read_buf = ReadBuf::new(buf);
                        read_buf.set_filled(*filled);

                        loop {
                            let rem = read_buf.remaining();
                            if rem == 0 {
                                break;
                            }

                            ready!(stream.as_mut().poll_read(cx, &mut read_buf))
                                .map_err(crate::Error::io)?;
                            *filled = read_buf.filled().len();

                            if read_buf.remaining() == rem {
                                return Poll::Ready(Err(crate::Error::io(eof(
                                    "unexpected eof during reading packet",
                                ))));
                            }
                        }
                    }

                    let (ciphertext, tag) =
                        buf.split_at_mut(aead::PACKET_LENGTH_LEN + packet_length as usize);
                    debug_assert_eq!(tag.len(), self.key.tag_len());
                    self.key.open_in_place(self.seqn.0, ciphertext, tag)?;

                    self.seqn += num::Wrapping(1);
                    self.state = RecvPacketState::Ready;

                    let padding_length = buf[aead::PACKET_LENGTH_LEN];
                    let payload_length = packet_length as usize - padding_length as usize - 1;

                    return Poll::Ready(Ok(
                        aead::PACKET_LENGTH_LEN + 1..aead::PACKET_LENGTH_LEN + 1 + payload_length
                    ));
                }
            }
        }
    }
}

// ==== KeyExchange ====

struct KeyExchange {
    server_id: Vec<u8>,
    client_kexinit_payload: Vec<u8>,
    client_ephemeral_key: Option<(agreement::EphemeralPrivateKey, agreement::PublicKey)>,
    digest: Option<digest::Context>,
    state: KeyExchangeState,
    output: Option<(aead::OpeningKey, aead::SealingKey, digest::Digest)>,
    recv_buf: Box<[u8]>,
}

enum KeyExchangeState {
    Init,
    SendingClientKexInit,
    SendingEcdhInit,
    ReceivingEcdhReply,
    SendingClientNewKeys,
    ReceivingServerNewKeys,
    Exchanged,
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self {
            server_id: vec![],
            client_kexinit_payload: vec![],
            client_ephemeral_key: None,
            digest: None,
            state: KeyExchangeState::Init,
            output: None,
            recv_buf: vec![0u8; 0x10000].into_boxed_slice(),
        }
    }
}

impl KeyExchange {
    fn start<B>(
        &mut self,
        server_kexinit_payload: &mut B,
        rng: &rand::SystemRandom,
    ) -> Result<(), crate::Error>
    where
        B: Buf,
    {
        let span = tracing::trace_span!("start_kex");
        let _enter = span.enter();

        match self.state {
            KeyExchangeState::Init | KeyExchangeState::Exchanged => (),
            _ => panic!("key exchange is not completed"),
        }

        let mut digest = digest::Context::new(&digest::SHA256);
        digest_ssh_string(&mut digest, &CLIENT_SSH_ID[..]);
        digest_ssh_string(&mut digest, &self.server_id[..]);

        // set client kexinit.
        tracing::trace!("init client_kex_payload");
        self.client_kexinit_payload = client_kex_payload(rng)?;
        digest_ssh_string(&mut digest, &self.client_kexinit_payload[..]);
        digest_ssh_string(&mut digest, server_kexinit_payload);

        // Generate ephemeral ECDH key.
        tracing::trace!("init ephemeral ECDH key");
        self.client_ephemeral_key = Some({
            let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
                .map_err(|_| crate::Error::transport("failed to generate ephemeral private key"))?;
            let public_key = private_key
                .compute_public_key()
                .map_err(|_| crate::Error::transport("failed to compute ephemeral public key"))?;
            (private_key, public_key)
        });

        self.digest = Some(digest);
        self.state = KeyExchangeState::SendingClientKexInit;

        Ok(())
    }

    fn client_public_key(&self) -> &agreement::PublicKey {
        &self
            .client_ephemeral_key
            .as_ref()
            .expect("ephemeral key is not available")
            .1
    }

    #[allow(clippy::clippy::too_many_arguments)]
    fn poll_complete<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        mut stream: Pin<&mut T>,
        send: &mut SendPacket,
        recv: &mut RecvPacket,
        session_id: Option<&digest::Digest>,
    ) -> Poll<Result<(aead::OpeningKey, aead::SealingKey, digest::Digest), crate::Error>>
    where
        T: AsyncRead + AsyncWrite,
    {
        let span = tracing::trace_span!("KeyExchange::poll_complete_kex");
        let _enter = span.enter();

        loop {
            match self.state {
                KeyExchangeState::SendingClientKexInit => {
                    tracing::trace!("--> SendingClientKexInit");

                    ready!(send.poll_flush(cx, stream.as_mut()))?;
                    send.start_send(|buf| {
                        buf.put_slice(&self.client_kexinit_payload[..]);
                    })?;
                    self.state = KeyExchangeState::SendingEcdhInit;
                }

                KeyExchangeState::SendingEcdhInit => {
                    tracing::trace!("--> SendingEcdhInit");

                    ready!(send.poll_flush(cx, stream.as_mut()))?;

                    let client_public_key = self.client_public_key();
                    send.start_send(|mut buf| {
                        buf.put_u8(consts::SSH_MSG_KEX_ECDH_INIT);
                        put_ssh_string(&mut buf, client_public_key.as_ref());
                    })?;

                    self.state = KeyExchangeState::ReceivingEcdhReply;
                }

                KeyExchangeState::ReceivingEcdhReply => {
                    tracing::trace!("--> ReceivingEcdhReply");

                    ready!(send.poll_flush(cx, stream.as_mut()))?;

                    let range = ready!(recv.poll_recv(cx, stream.as_mut(), &mut self.recv_buf))?;
                    let mut payload = &self.recv_buf[range];

                    let mut digest = self.digest.take().unwrap();
                    let client_public_key = self.client_public_key();

                    if payload.get_u8() != consts::SSH_MSG_KEX_ECDH_REPLY {
                        return Poll::Ready(Err(crate::Error::transport(
                            "reply is not ECDH_REPLY",
                        )));
                    }

                    let server_host_key = {
                        let raw = get_ssh_string(&mut payload);
                        let mut raw = &raw[..];

                        digest_ssh_string(&mut digest, raw);

                        let key_type = get_ssh_string(&mut raw);
                        match &*key_type {
                            b"ssh-ed25519" => {
                                // ref: https://tools.ietf.org/html/rfc8709#section-4
                                let key = get_ssh_string(&mut raw);
                                signature::UnparsedPublicKey::new(&signature::ED25519, key)
                            }
                            _ => {
                                return Poll::Ready(Err(crate::Error::transport(
                                    "unexpected server host key type",
                                )))
                            }
                        }
                    };
                    // TODO: verify server host key.

                    let server_public_key = {
                        let raw = get_ssh_string(&mut payload);

                        digest_ssh_string(&mut digest, client_public_key.as_ref());
                        digest_ssh_string(&mut digest, &raw[..]);

                        agreement::UnparsedPublicKey::new(&agreement::X25519, raw)
                    };

                    let exchange_hash_sig = {
                        tracing::trace!("parse exchange_hash_sig (len = {})", payload.remaining());
                        let raw = get_ssh_string(&mut payload);
                        let mut raw = &raw[..];

                        let key_type = get_ssh_string(&mut raw);
                        match &*key_type {
                            b"ssh-ed25519" => {
                                // ref: https://tools.ietf.org/html/rfc8709#section-6
                                get_ssh_string(&mut raw)
                            }
                            _ => {
                                return Poll::Ready(Err(crate::Error::transport(
                                    "unexpected exchange hash signature type",
                                )))
                            }
                        }
                    };

                    let (client_private_key, _) = self.client_ephemeral_key.take().unwrap();
                    agreement::agree_ephemeral(
                        client_private_key,
                        &server_public_key,
                        crate::Error::transport("errored during key agreement"),
                        {
                            let slot_out = &mut self.output;
                            move |secret| {
                                tracing::trace!("calculate exchange hash H");
                                let exchange_hash = {
                                    digest_ssh_mpint(&mut digest, secret);
                                    digest.finish()
                                };
                                server_host_key
                                    .verify(exchange_hash.as_ref(), &exchange_hash_sig[..])
                                    .map_err(|_| {
                                        crate::Error::transport("exchange hash mismatched")
                                    })?;

                                tracing::trace!("calculate encryption keys");
                                let session_id = session_id.unwrap_or(&exchange_hash);
                                let sealing_key = {
                                    let mut key = [0u8; aead::KEY_LEN];
                                    let mut key_buf = KeyBuf::new(&mut key[..]);
                                    compute_key(
                                        &mut key_buf,
                                        b'C',
                                        secret,
                                        &exchange_hash,
                                        session_id,
                                    )?;
                                    aead::SealingKey::new(&key)
                                };
                                let opening_key = {
                                    let mut key = [0u8; aead::KEY_LEN];
                                    let mut key_buf = KeyBuf::new(&mut key[..]);
                                    compute_key(
                                        &mut key_buf,
                                        b'D',
                                        secret,
                                        &exchange_hash,
                                        session_id,
                                    )?;
                                    aead::OpeningKey::new(&key)
                                };

                                *slot_out = Some((opening_key, sealing_key, exchange_hash));

                                Ok(())
                            }
                        },
                    )?;

                    self.state = KeyExchangeState::SendingClientNewKeys;
                }

                KeyExchangeState::SendingClientNewKeys => {
                    tracing::trace!("--> SendingClientNewKeys");

                    ready!(send.poll_flush(cx, stream.as_mut()))?;

                    send.start_send(|buf| {
                        buf.put_u8(consts::SSH_MSG_NEWKEYS);
                    })?;

                    self.state = KeyExchangeState::ReceivingServerNewKeys;
                }

                KeyExchangeState::ReceivingServerNewKeys => {
                    tracing::trace!("--> ReceivingServerNewKeys");

                    ready!(send.poll_flush(cx, stream.as_mut()))?;

                    let range = ready!(recv.poll_recv(cx, stream.as_mut(), &mut self.recv_buf))?;
                    let mut payload = &self.recv_buf[range];

                    if payload.get_u8() != consts::SSH_MSG_NEWKEYS {
                        // TODO: send DISCONNECT
                        return Poll::Ready(Err(crate::Error::transport("is not NEWKEYS")));
                    }

                    self.state = KeyExchangeState::Exchanged;

                    return Poll::Ready(Ok(self.output.take().unwrap()));
                }

                KeyExchangeState::Init | KeyExchangeState::Exchanged => panic!("unexpected state"),
            }
        }
    }
}

fn client_kex_payload(rng: &rand::SystemRandom) -> Result<Vec<u8>, crate::Error> {
    let mut payload = vec![];
    payload.put_u8(consts::SSH_MSG_KEXINIT);

    let cookie = ring::rand::generate::<[u8; 16]>(rng)
        .map_err(|_| crate::Error::transport("failed to generate random"))?
        .expose();
    payload.put_slice(&cookie[..]);

    put_ssh_string(&mut payload, CURVE25519_SHA256.as_ref()); // kex_algorithms
    put_ssh_string(&mut payload, b"ssh-ed25519"); // server_host_key_algorithms

    put_ssh_string(&mut payload, CHACHA20_POLY1305.as_ref()); // encryption_algorithms_client_to_server
    put_ssh_string(&mut payload, CHACHA20_POLY1305.as_ref()); // encryption_algorithms_server_to_client

    put_ssh_string(&mut payload, b"none"); // mac_algorithms_client_to_server
    put_ssh_string(&mut payload, b"none"); // mac_algorithms_server_to_client

    put_ssh_string(&mut payload, b"none"); // compression_algorithms_client_to_server
    put_ssh_string(&mut payload, b"none"); // compression_algorithms_server_to_client

    put_ssh_string(&mut payload, b""); // languages_client_to_server
    put_ssh_string(&mut payload, b""); // languages_server_to_client

    payload.put_u8(0); // first_kex_packet_follows
    payload.put_u32(0); // reserved

    Ok(payload)
}

// ==== ciphers ====

enum OpeningKey {
    ClearText,
    Chacha20Poly1305(aead::OpeningKey),
}
impl OpeningKey {
    #[inline]
    fn decrypt_packet_length(
        &self,
        seqn: u32,
        encrypted_packet_length: [u8; aead::PACKET_LENGTH_LEN],
    ) -> [u8; aead::PACKET_LENGTH_LEN] {
        match self {
            OpeningKey::ClearText => encrypted_packet_length,
            OpeningKey::Chacha20Poly1305(ref key) => {
                key.decrypt_packet_length(seqn, encrypted_packet_length)
            }
        }
    }

    #[inline]
    fn tag_len(&self) -> usize {
        match self {
            OpeningKey::ClearText => 0,
            OpeningKey::Chacha20Poly1305(..) => aead::TAG_LEN,
        }
    }

    #[inline]
    fn open_in_place(
        &self,
        seqn: u32,
        ciphertext_in_plaintext_out: &mut [u8],
        tag: &[u8],
    ) -> Result<(), crate::Error> {
        if let OpeningKey::Chacha20Poly1305(key) = self {
            let tag: &[u8; aead::TAG_LEN] = tag.try_into().expect("tag is too short");
            key.open_in_place(seqn, ciphertext_in_plaintext_out, tag)
                .map_err(|_| crate::Error::transport("failed to open ciphertext"))?;
        }
        Ok(())
    }
}

enum SealingKey {
    ClearText,
    Chacha20Poly1305(aead::SealingKey),
}
impl SealingKey {
    #[inline]
    fn padding_length(&self, payload_len: usize) -> usize {
        match self {
            SealingKey::ClearText => {
                const BLOCK_SIZE: usize = 8;
                let padding_length = BLOCK_SIZE - ((5 + payload_len) % BLOCK_SIZE);
                if padding_length < 4 {
                    padding_length + BLOCK_SIZE
                } else {
                    padding_length
                }
            }
            SealingKey::Chacha20Poly1305(..) => {
                const BLOCK_SIZE: usize = 8;
                const MINIMUM_PACKET_LEN: usize = 16;

                let padding_len = if 5 + payload_len <= MINIMUM_PACKET_LEN {
                    MINIMUM_PACKET_LEN - payload_len - 1
                } else {
                    BLOCK_SIZE - ((1 + payload_len) % BLOCK_SIZE)
                };

                if padding_len < aead::PACKET_LENGTH_LEN {
                    padding_len + BLOCK_SIZE
                } else {
                    padding_len
                }
            }
        }
    }

    #[inline]
    fn tag_len(&self) -> usize {
        match self {
            SealingKey::ClearText => 0,
            SealingKey::Chacha20Poly1305(..) => aead::TAG_LEN,
        }
    }

    #[inline]
    fn seal_in_place(
        &self,
        seqn: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), crate::Error> {
        if let SealingKey::Chacha20Poly1305(key) = self {
            let tag_out: &mut [u8; aead::TAG_LEN] =
                tag_out.try_into().expect("tag_len is too short");
            key.seal_in_place(seqn, plaintext_in_ciphertext_out, tag_out);
        }
        Ok(())
    }
}

// ==== misc ====

fn digest_ssh_string<B: Buf>(digest: &mut digest::Context, mut data: B) {
    let len = data.remaining() as u32;
    digest.update(&len.to_be_bytes());
    while data.has_remaining() {
        digest.update(data.chunk());
        data.advance(data.chunk().len());
    }
}

fn digest_ssh_mpint(digest: &mut digest::Context, s: &[u8]) {
    // Skip initial 0s.
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1;
    }

    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if s[i] & 0x80 != 0 {
        digest.update(&((s.len() - i + 1) as u32).to_be_bytes());
        digest.update(&[0]);
    } else {
        digest.update(&((s.len() - i) as u32).to_be_bytes());
    }

    digest.update(&s[i..]);
}

// ==== compute_key ====

struct KeyBuf<'a> {
    data: &'a mut [u8],
    filled: usize,
}
impl<'a> KeyBuf<'a> {
    #[inline]
    fn new(data: &'a mut [u8]) -> Self {
        Self { data, filled: 0 }
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        &self.data[..self.filled]
    }
}
unsafe impl BufMut for KeyBuf<'_> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.data.len() - self.filled
    }
    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let remaining = &mut self.data[self.filled..];
        unsafe { UninitSlice::from_raw_parts_mut(remaining.as_mut_ptr(), remaining.len()) }
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.filled += cnt;
    }
}

fn compute_key(
    key_buf: &mut KeyBuf<'_>,
    c: u8,
    secret: &[u8],
    exchange_hash: &digest::Digest,
    session_id: &digest::Digest,
) -> Result<(), crate::Error> {
    // described in https://tools.ietf.org/html/rfc4253#section-7.2

    assert!(
        key_buf.remaining_mut() % digest::SHA256.output_len == 0,
        "incorrect key_buf size"
    );

    let digest = {
        let mut h = digest::Context::new(&digest::SHA256);
        digest_ssh_mpint(&mut h, secret);
        h.update(exchange_hash.as_ref());
        h.update(&[c]);
        h.update(session_id.as_ref());
        h.finish()
    }; // K1
    key_buf.put_slice(digest.as_ref());

    while key_buf.has_remaining_mut() {
        let digest = {
            let mut h = digest::Context::new(&digest::SHA256);
            digest_ssh_mpint(&mut h, secret);
            h.update(exchange_hash.as_ref());
            h.update(key_buf.filled());
            h.finish()
        }; // K2, K3, ...
        key_buf.put_slice(digest.as_ref());
    }

    Ok(())
}

fn eof(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}
