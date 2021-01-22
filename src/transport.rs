//! The implementation of SSH transport protocol.

// Refs:
// * https://tools.ietf.org/html/rfc4253
// * https://tools.ietf.org/html/rfc5656

use crate::consts;
use bytes::{Buf, BufMut};
use futures::{
    ready,
    task::{self, Poll},
};
use ring::{aead::chacha20_poly1305_openssh as aead, agreement, digest, rand, signature};
use std::{convert::TryInto as _, io, num, pin::Pin};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader, ReadBuf,
};

// defined in https://git.libssh.org/projects/libssh.git/tree/doc/curve25519-sha256@libssh.org.txt#n62
const CURVE25519_SHA256: &str = "curve25519-sha256@libssh.org";

// defined in http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?rev=1.5&content-type=text/x-cvsweb-markup
const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";

pub async fn establish<T>(stream: T) -> Result<Transport<T>, crate::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);

    tracing::debug!("Exchange SSH identifiers");
    let client_id = concat!("SSH-2.0-minissh_", env!("CARGO_PKG_VERSION"))
        .as_bytes()
        .to_owned();
    stream
        .get_mut()
        .write_all(&client_id[..])
        .await
        .map_err(crate::Error::io)?;
    stream
        .get_mut()
        .write_all(b"\r\n")
        .await
        .map_err(crate::Error::io)?;
    stream.get_mut().flush().await.map_err(crate::Error::io)?;

    let server_id = {
        let mut line = vec![];
        loop {
            let _amt = stream
                .read_until(b'\n', &mut line)
                .await
                .map_err(crate::Error::io)?;
            if line.starts_with(b"SSH-") {
                break;
            }
            line.clear();
        }
        let n = line
            .iter()
            .take_while(|&&c| c != b'\r' && c != b'\n')
            .count();
        line.resize(n, 0);
        line
    };
    tracing::debug!(
        "--> client_id={:?}, server_id={:?}",
        String::from_utf8_lossy(&client_id),
        String::from_utf8_lossy(&server_id)
    );

    let mut transport = Transport {
        stream,
        state: TransportState::Init,
        send: SendPacket::default(),
        recv: RecvPacket::default(),
        kex: KeyExchange::new(client_id, server_id),
        opening_key: Box::new(ClearText),
        sealing_key: Box::new(ClearText),
        session_id: None,
    };

    tracing::trace!("Handshake");
    futures::future::poll_fn(|cx| transport.poll_handshake(cx)).await?;
    tracing::trace!("--> Done");

    Ok(transport)
}

// ==== Transport ====

pub struct Transport<T> {
    stream: BufReader<T>,
    state: TransportState,
    send: SendPacket,
    recv: RecvPacket,
    kex: KeyExchange,
    opening_key: Box<dyn OpeningKey + Send>,
    sealing_key: Box<dyn SealingKey + Send>,
    session_id: Option<digest::Digest>,
}

enum TransportState {
    Init,
    Kex,
    Ready,
}

impl<T> Transport<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn poll_handshake(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_handshake");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init => {
                    tracing::trace!("--> Init");

                    // Wait until server KEXINIT is received.
                    loop {
                        ready!(self
                            .recv
                            .poll_recv(cx, &mut self.stream, &*self.opening_key))?;

                        let payload = self.recv.payload();

                        if !payload.is_empty() && payload[0] == consts::SSH_MSG_KEXINIT {
                            self.kex.start_kex(payload)?;
                            self.state = TransportState::Kex;
                            break;
                        }
                    }
                }
                TransportState::Kex => {
                    tracing::trace!("--> Kex");

                    let session_id = ready!(self.poll_kex(cx))?;
                    self.session_id = Some(session_id);
                    return Poll::Ready(Ok(()));
                }
                TransportState::Ready => {
                    tracing::trace!("--> Ready");
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    pub fn poll_recv(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_recv");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init => panic!("transport is not initialized"),
                TransportState::Kex => {
                    tracing::trace!("--> Kex");
                    let _session_id = ready!(self.poll_kex(cx))?;
                }
                TransportState::Ready => {
                    tracing::trace!("--> Ready");
                    ready!(self
                        .recv
                        .poll_recv(cx, &mut self.stream, &*self.opening_key))?;

                    let payload = self.recv.payload();
                    if !payload.is_empty() && payload[0] == consts::SSH_MSG_KEXINIT {
                        self.kex.start_kex(payload)?;
                        self.state = TransportState::Kex;
                        continue;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    pub fn payload(&self) -> &[u8] {
        assert!(
            matches!(self.state, TransportState::Ready),
            "packet is not ready"
        );
        self.recv.payload()
    }

    pub fn poll_send_ready(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_send");
        let _enter = span.enter();

        loop {
            match self.state {
                TransportState::Init => panic!("transport is not initialized"),
                TransportState::Kex => {
                    tracing::trace!("--> Kex");
                    ready!(self.poll_kex(cx))?;
                }
                TransportState::Ready => {
                    tracing::trace!("--> Ready");
                    ready!(self.send.poll_flush(cx, &mut self.stream))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    pub fn send<B>(&mut self, payload: &mut B) -> Result<(), crate::Error>
    where
        B: Buf,
    {
        let span = tracing::trace_span!("Transport::send");
        let _enter = span.enter();

        assert!(
            matches!(self.state, TransportState::Ready),
            "transport is not ready to send"
        );

        self.send.fill_buf(payload, &*self.sealing_key)?;

        Ok(())
    }

    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), crate::Error>> {
        let span = tracing::trace_span!("Transport::poll_flush");
        let _enter = span.enter();

        // a
        self.send.poll_flush(cx, &mut self.stream)
    }

    fn poll_kex(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<digest::Digest, crate::Error>> {
        assert!(
            matches!(self.state, TransportState::Kex),
            "unexpected condition"
        );

        let (opening_key, sealing_key, exchange_hash) = ready!(self.kex.poll_complete_kex(
            cx,
            &mut self.stream,
            &mut self.send,
            &mut self.recv,
            &*self.opening_key,
            &*self.sealing_key,
        ))?;

        self.opening_key = Box::new(opening_key);
        self.sealing_key = Box::new(sealing_key);

        self.state = TransportState::Ready;

        Poll::Ready(Ok(exchange_hash))
    }

    pub fn session_id(&self) -> &[u8] {
        self.session_id.as_ref().unwrap().as_ref()
    }
}

// ==== SendPacket ====

struct SendPacket {
    buf: Vec<u8>,
    state: SendPacketState,
    seqn: num::Wrapping<u32>,
}

enum SendPacketState {
    Available,
    Writing(usize),
    Flushing,
}

impl Default for SendPacket {
    fn default() -> Self {
        Self {
            buf: vec![],
            state: SendPacketState::Available,
            seqn: num::Wrapping(0),
        }
    }
}

impl SendPacket {
    fn fill_buf<B>(
        &mut self,
        payload: &mut B,
        sealing_key: &dyn SealingKey,
    ) -> Result<(), crate::Error>
    where
        B: Buf,
    {
        assert!(
            matches!(self.state, SendPacketState::Available),
            "buffer is not empty"
        );

        let padding_length = sealing_key.padding_length(payload.remaining());
        let packet_length = 1 + payload.remaining() + padding_length;
        tracing::trace!("packet_length = {}", packet_length);
        tracing::trace!("padding_length = {}", padding_length);

        tracing::trace!("fill send_buffer");
        self.buf
            .resize(4 + packet_length + sealing_key.tag_len(), 0);
        {
            let mut buf = &mut self.buf[..4 + packet_length];
            buf.put_u32(packet_length as u32);
            buf.put_u8(padding_length as u8);
            while payload.has_remaining() {
                buf.put_slice(payload.chunk());
                payload.advance(payload.chunk().len());
            }
            let padding = {
                let (padding, remains) = buf.split_at_mut(padding_length);
                buf = remains;
                padding
            };
            sealing_key.fill_padding(padding);
            debug_assert!(buf.is_empty());
        }

        tracing::trace!("encrypt packet");
        {
            let (packet, tag) = self.buf.split_at_mut(4 + packet_length);
            assert_eq!(tag.len(), sealing_key.tag_len());
            sealing_key.seal_in_place(self.seqn.0, packet, tag)?;
        }

        self.state = SendPacketState::Writing(0);
        self.seqn += num::Wrapping(1);

        Ok(())
    }

    fn poll_flush<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut T,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncWrite + Unpin,
    {
        let mut stream = Pin::new(stream);
        loop {
            match self.state {
                SendPacketState::Available => return Poll::Ready(Ok(())),

                SendPacketState::Writing(ref mut written) => {
                    let mut buf = &self.buf[..];
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
                    self.state = SendPacketState::Available;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

// ==== RecvPacket ====

struct RecvPacket {
    buf: Vec<u8>,
    packet_length: u32,
    state: RecvPacketState,
    seqn: num::Wrapping<u32>,
}

enum RecvPacketState {
    ReadingLength(usize),
    ReadingPacket(usize),
    Decrypted,
}

impl Default for RecvPacket {
    fn default() -> Self {
        Self {
            buf: vec![0u8; 4],
            packet_length: 0,
            state: RecvPacketState::ReadingLength(0),
            seqn: num::Wrapping(0),
        }
    }
}

impl RecvPacket {
    pub fn poll_recv<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut T,
        opening_key: &dyn OpeningKey,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + Unpin,
    {
        let span = tracing::trace_span!("RecvPacket::poll_recv");
        let _enter = span.enter();

        let mut stream = Pin::new(stream);
        loop {
            match self.state {
                RecvPacketState::Decrypted => {
                    tracing::trace!("--> Decrypted");
                    unsafe {
                        // zeroing previous cleartext.
                        std::ptr::write_bytes(self.buf.as_mut_ptr(), 0, self.buf.len());
                    }
                    self.buf.resize(4, 0u8);
                    self.state = RecvPacketState::ReadingLength(0);
                }

                RecvPacketState::ReadingLength(ref mut read) => {
                    tracing::trace!("--> ReadingLength({})", read);

                    let mut read_buf = ReadBuf::new(&mut self.buf[..4]);
                    read_buf.set_filled(*read);

                    loop {
                        let rem = read_buf.remaining();
                        if rem != 0 {
                            ready!(stream.as_mut().poll_read(cx, &mut read_buf))
                                .map_err(crate::Error::io)?;
                            if read_buf.remaining() == rem {
                                return Poll::Ready(Err(crate::Error::io(eof(
                                    "unexpected eof during reading packet length",
                                ))));
                            }
                            *read = read_buf.filled().len();
                        } else {
                            break;
                        }
                    }

                    let encrypted_packet_length = &self.buf[..4];
                    let packet_length =
                        opening_key.decrypt_packet_length(self.seqn.0, encrypted_packet_length);
                    tracing::trace!("packet_lenghth = {}", packet_length);

                    self.packet_length = packet_length;
                    self.buf
                        .resize(4 + packet_length as usize + opening_key.tag_len(), 0);
                    self.state = RecvPacketState::ReadingPacket(4);
                }

                RecvPacketState::ReadingPacket(ref mut read) => {
                    tracing::trace!("--> ReadingPacket({})", read);

                    let mut read_buf = ReadBuf::new(&mut self.buf[..]);
                    read_buf.set_filled(*read);

                    while read_buf.remaining() > 0 {
                        ready!(stream.as_mut().poll_read(cx, &mut read_buf))
                            .map_err(crate::Error::io)?;
                        *read = read_buf.filled().len();
                    }

                    let (ciphertext, tag) = self.buf.split_at_mut(4 + self.packet_length as usize);
                    debug_assert_eq!(tag.len(), opening_key.tag_len());
                    opening_key.open_in_place(self.seqn.0, ciphertext, tag)?;

                    self.seqn += num::Wrapping(1);
                    self.state = RecvPacketState::Decrypted;

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn payload(&self) -> &[u8] {
        assert!(
            matches!(self.state, RecvPacketState::Decrypted),
            "cleartext is not ready to read"
        );
        let padding_length = self.buf[4];
        let payload_length = self.packet_length as usize - padding_length as usize - 1;
        &self.buf[5..5 + payload_length]
    }
}

// ==== KeyExchange ====

struct KeyExchange {
    client_id: Vec<u8>,
    server_id: Vec<u8>,
    client_kexinit_payload: Vec<u8>,
    client_ephemeral_key: Option<(agreement::EphemeralPrivateKey, agreement::PublicKey)>,
    digest: Option<digest::Context>,
    state: KeyExchangeState,
    out: Option<(aead::OpeningKey, aead::SealingKey, digest::Digest)>,
    rng: rand::SystemRandom,
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

impl KeyExchange {
    fn new(client_id: Vec<u8>, server_id: Vec<u8>) -> Self {
        Self {
            client_id,
            server_id,
            client_kexinit_payload: vec![],
            client_ephemeral_key: None,
            digest: None,
            state: KeyExchangeState::Init,
            out: None,
            rng: rand::SystemRandom::new(),
        }
    }

    fn start_kex(&mut self, server_kexinit_payload: &[u8]) -> Result<(), crate::Error> {
        let span = tracing::trace_span!("start_kex");
        let _enter = span.enter();

        match self.state {
            KeyExchangeState::Init | KeyExchangeState::Exchanged => (),
            _ => panic!("key exchange is not completed"),
        }

        let mut digest = digest::Context::new(&digest::SHA256);
        digest_ssh_string(&mut digest, &self.client_id[..]);
        digest_ssh_string(&mut digest, &self.server_id[..]);

        // set client kexinit.
        tracing::trace!("init client_kex_payload");
        self.client_kexinit_payload = client_kex_payload(&self.rng)?;
        digest_ssh_string(&mut digest, &self.client_kexinit_payload[..]);
        digest_ssh_string(&mut digest, server_kexinit_payload);

        // Generate ephemeral ECDH key.
        tracing::trace!("init ephemeral ECDH key");
        self.client_ephemeral_key = Some({
            let private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng).map_err(
                    |_| crate::Error::transport("failed to generate ephemeral private key"),
                )?;
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

    fn poll_complete_kex<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut T,
        send: &mut SendPacket,
        recv: &mut RecvPacket,
        opening_key: &dyn OpeningKey,
        sealing_key: &dyn SealingKey,
    ) -> Poll<Result<(aead::OpeningKey, aead::SealingKey, digest::Digest), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let span = tracing::trace_span!("KeyExchange::poll_complete_kex");
        let _enter = span.enter();

        loop {
            match self.state {
                KeyExchangeState::SendingClientKexInit => {
                    tracing::trace!("--> SendingClientKexInit");

                    ready!(send.poll_flush(cx, stream))?;
                    send.fill_buf(&mut &self.client_kexinit_payload[..], sealing_key)?;
                    self.state = KeyExchangeState::SendingEcdhInit;
                }

                KeyExchangeState::SendingEcdhInit => {
                    tracing::trace!("--> SendingEcdhInit");

                    ready!(send.poll_flush(cx, stream))?;

                    let mut payload = vec![];
                    payload.put_u8(consts::SSH_MSG_KEX_ECDH_INIT);
                    put_ssh_string(&mut payload, self.client_public_key().as_ref());

                    send.fill_buf(&mut &payload[..], sealing_key)?;

                    self.state = KeyExchangeState::ReceivingEcdhReply;
                }

                KeyExchangeState::ReceivingEcdhReply => {
                    tracing::trace!("--> ReceivingEcdhReply");

                    ready!(send.poll_flush(cx, stream))?;
                    ready!(recv.poll_recv(cx, stream, opening_key))?;

                    let mut digest = self.digest.take().unwrap();
                    let client_public_key = self.client_public_key();

                    let mut payload = recv.payload();

                    let typ = payload.get_u8();
                    if typ != consts::SSH_MSG_KEX_ECDH_REPLY {
                        // TODO: set state
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
                        tracing::trace!("parse exchange_hash_sig (len = {})", payload.len());
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
                            let slot_out = &mut self.out;
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
                                let sealing_key = compute_key(
                                    64,
                                    b'C',
                                    secret,
                                    exchange_hash.as_ref(),
                                    exchange_hash.as_ref(), // equivalent to session_id,
                                    |key| {
                                        let key: &[u8; aead::KEY_LEN] = key.try_into().unwrap();
                                        Ok(aead::SealingKey::new(key))
                                    },
                                )?;
                                let opening_key = compute_key(
                                    64,
                                    b'D',
                                    secret,
                                    exchange_hash.as_ref(),
                                    exchange_hash.as_ref(), // equivalent to session_id,
                                    |key| {
                                        let key: &[u8; aead::KEY_LEN] = key.try_into().unwrap();
                                        Ok(aead::OpeningKey::new(key))
                                    },
                                )?;

                                *slot_out = Some((opening_key, sealing_key, exchange_hash));

                                Ok(())
                            }
                        },
                    )?;

                    self.state = KeyExchangeState::SendingClientNewKeys;
                }

                KeyExchangeState::SendingClientNewKeys => {
                    tracing::trace!("--> SendingClientNewKeys");

                    ready!(send.poll_flush(cx, stream))?;

                    let mut payload = vec![];
                    payload.put_u8(consts::SSH_MSG_NEWKEYS);
                    send.fill_buf(&mut &payload[..], sealing_key)?;

                    self.state = KeyExchangeState::ReceivingServerNewKeys;
                }

                KeyExchangeState::ReceivingServerNewKeys => {
                    tracing::trace!("--> ReceivingServerNewKeys");

                    ready!(send.poll_flush(cx, stream))?;
                    ready!(recv.poll_recv(cx, stream, opening_key))?;

                    let payload = recv.payload();
                    if payload.is_empty() || payload[0] != consts::SSH_MSG_NEWKEYS {
                        // TODO: send DISCONNECT
                        return Poll::Ready(Err(crate::Error::transport("is not NEWKEYS")));
                    }

                    self.state = KeyExchangeState::Exchanged;

                    let out = self.out.take().unwrap();
                    return Poll::Ready(Ok(out));
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

trait SealingKey {
    fn padding_length(&self, payload_len: usize) -> usize;
    fn fill_padding(&self, padding: &mut [u8]);
    fn tag_len(&self) -> usize;
    fn seal_in_place(
        &self,
        seqn: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), crate::Error>;
}

trait OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: &[u8]) -> u32;
    fn tag_len(&self) -> usize;
    fn open_in_place(
        &self,
        seqn: u32,
        ciphertext_in_plaintext_out: &mut [u8],
        tag: &[u8],
    ) -> Result<(), crate::Error>;
}

pub struct ClearText;
impl SealingKey for ClearText {
    fn padding_length(&self, payload_len: usize) -> usize {
        const BLOCK_SIZE: usize = 8;
        let padding_length = BLOCK_SIZE - ((5 + payload_len) % BLOCK_SIZE);
        if padding_length < 4 {
            padding_length + BLOCK_SIZE
        } else {
            padding_length
        }
    }
    fn fill_padding(&self, padding: &mut [u8]) {
        unsafe {
            std::ptr::write_bytes(padding.as_mut_ptr(), 0, padding.len());
        }
    }
    fn tag_len(&self) -> usize {
        0
    }
    fn seal_in_place(&self, _seqn: u32, _: &mut [u8], _: &mut [u8]) -> Result<(), crate::Error> {
        Ok(())
    }
}
impl OpeningKey for ClearText {
    fn decrypt_packet_length(&self, _: u32, encrypted_packet_length: &[u8]) -> u32 {
        u32::from_be_bytes(
            encrypted_packet_length
                .try_into()
                .expect("encrypted_packet_length is too short"),
        )
    }
    fn tag_len(&self) -> usize {
        0
    }
    fn open_in_place(&self, _: u32, _: &mut [u8], _: &[u8]) -> Result<(), crate::Error> {
        Ok(())
    }
}

impl SealingKey for aead::SealingKey {
    fn padding_length(&self, payload_len: usize) -> usize {
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
    fn fill_padding(&self, padding: &mut [u8]) {
        unsafe {
            std::ptr::write_bytes(padding.as_mut_ptr(), 0u8, padding.len());
        }
    }
    fn tag_len(&self) -> usize {
        aead::TAG_LEN
    }
    fn seal_in_place(
        &self,
        seqn: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), crate::Error> {
        let tag_out: &mut [u8; aead::TAG_LEN] = tag_out.try_into().expect("tag_len is too short");
        self.seal_in_place(seqn, plaintext_in_ciphertext_out, tag_out);
        Ok(())
    }
}

impl OpeningKey for aead::OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: &[u8]) -> u32 {
        let encrypted_packet_length: [u8; aead::PACKET_LENGTH_LEN] = encrypted_packet_length
            .try_into()
            .expect("packet length is too short");
        let decrypted = self.decrypt_packet_length(seqn, encrypted_packet_length);
        u32::from_be_bytes(decrypted)
    }
    fn tag_len(&self) -> usize {
        aead::TAG_LEN
    }
    fn open_in_place(
        &self,
        seqn: u32,
        ciphertext_in_plaintext_out: &mut [u8],
        tag: &[u8],
    ) -> Result<(), crate::Error> {
        let tag: &[u8; aead::TAG_LEN] = tag.try_into().expect("tag is too short");
        self.open_in_place(seqn, ciphertext_in_plaintext_out, tag)
            .map_err(|_| crate::Error::transport("failed to open ciphertext"))?;
        Ok(())
    }
}

// ==== misc ====

fn get_ssh_string<B: Buf>(mut b: B) -> Vec<u8> {
    let len = b.get_u32();
    tracing::trace!("remaining = {}", b.remaining());
    tracing::trace!("len = {}", len);
    let mut s = vec![0u8; len as usize];
    b.copy_to_slice(&mut s[..]);
    s
}

fn put_ssh_string<B: BufMut>(mut b: B, s: &[u8]) {
    let len = s.len() as u32;
    b.put_u32(len);
    b.put_slice(s);
}

fn digest_ssh_string(digest: &mut digest::Context, s: &[u8]) {
    let len = s.len() as u32;
    digest.update(&len.to_be_bytes());
    digest.update(s);
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

fn compute_key<K>(
    expected_key_len: usize,
    c: u8,
    secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    make_key: fn(&[u8]) -> Result<K, crate::Error>,
) -> Result<K, crate::Error> {
    // described in https://tools.ietf.org/html/rfc4253#section-7.2

    // TODO: make secret
    let mut key = vec![];

    let digest = {
        let mut h = digest::Context::new(&digest::SHA256);
        digest_ssh_mpint(&mut h, secret);
        h.update(exchange_hash);
        h.update(&[c]);
        h.update(session_id);
        h.finish()
    }; // K1
    key.put_slice(digest.as_ref());

    while key.len() < expected_key_len {
        let digest = {
            let mut h = digest::Context::new(&digest::SHA256);
            digest_ssh_mpint(&mut h, secret);
            h.update(exchange_hash);
            h.update(&key[..]);
            h.finish()
        }; // K2, K3, ...
        key.put_slice(digest.as_ref());
    }

    make_key(&key[..expected_key_len])
}

fn eof(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}
