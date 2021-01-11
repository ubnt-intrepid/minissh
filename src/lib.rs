use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::{Buf, BufMut};
use ring::{aead::chacha20_poly1305_openssh as aead, agreement, digest, rand, signature};
use std::{
    convert::TryInto as _,
    io::{self, prelude::*},
    net::TcpStream,
};

// Refs:
// * https://tools.ietf.org/html/rfc4253
// * https://tools.ietf.org/html/rfc5656

pub struct OpenSession {
    stream: io::BufReader<TcpStream>,
}

impl OpenSession {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: io::BufReader::new(stream),
        }
    }

    /// Open a SSH session on the specified TCP socket.
    pub fn open(mut self) -> io::Result<Session> {
        let rng = rand::SystemRandom::new();

        tracing::debug!("Exchange SSH identifiers");
        let client_id = concat!("SSH-2.0-minissh_", env!("CARGO_PKG_VERSION")).as_bytes();
        self.stream.get_ref().write_all(&client_id[..])?;
        self.stream.get_ref().write_all(b"\r\n")?;
        self.stream.get_ref().flush()?;
        let server_id = {
            let mut line = vec![];
            loop {
                let _amt = self.stream.read_until(b'\n', &mut line)?;
                if line.starts_with(b"SSH-") {
                    break;
                }
                line.clear();
            }
            tracing::trace!("line={:?}", std::str::from_utf8(&line));
            let n = line
                .iter()
                .take_while(|&&c| c != b'\r' && c != b'\n')
                .count();
            line.resize(n, 0);
            line
        };
        tracing::debug!("--> server_id = {:?}", std::str::from_utf8(&server_id));

        tracing::debug!("Send client KEXINIT");
        let client_kexinit_payload = {
            // described in https://tools.ietf.org/html/rfc4253#section-7.1

            let mut payload = vec![];
            payload.put_u8(consts::SSH_MSG_KEXINIT);

            let cookie = ring::rand::generate::<[u8; 16]>(&rng).unwrap().expose();
            payload.put_slice(&cookie[..]);

            put_ssh_string(&mut payload, consts::CURVE25519_SHA256.as_ref()); // kex_algorithms
            put_ssh_string(&mut payload, b"ssh-ed25519"); // server_host_key_algorithms

            put_ssh_string(&mut payload, consts::CHACHA20_POLY1305.as_ref()); // encryption_algorithms_client_to_server
            put_ssh_string(&mut payload, consts::CHACHA20_POLY1305.as_ref()); // encryption_algorithms_server_to_client

            put_ssh_string(&mut payload, b"none"); // mac_algorithms_client_to_server
            put_ssh_string(&mut payload, b"none"); // mac_algorithms_server_to_client

            put_ssh_string(&mut payload, b"none"); // compression_algorithms_client_to_server
            put_ssh_string(&mut payload, b"none"); // compression_algorithms_server_to_client

            put_ssh_string(&mut payload, b""); // languages_client_to_server
            put_ssh_string(&mut payload, b""); // languages_server_to_client

            payload.put_u8(0); // first_kex_packet_follows
            payload.put_u32(0); // reserved

            tracing::trace!("payload = {:?}", String::from_utf8_lossy(&payload));

            write_packet(self.stream.get_ref(), &payload[..])?;
            self.stream.get_ref().flush()?;

            payload
        };

        tracing::debug!("Recv server KEXINIT");
        let server_kexinit_payload = {
            let packet_length = self.stream.read_u32::<NetworkEndian>()?;
            tracing::trace!("packet_length = {}", packet_length);
            let mut r = io::Read::take(&mut self.stream, packet_length as u64);

            let padding_length = r.read_u8()?;
            tracing::trace!("padding_length = {}", padding_length);

            let payload_len = packet_length as usize - padding_length as usize - 1;
            let mut payload = vec![0u8; payload_len];
            r.read_exact(&mut payload[..])?;
            // TODO: handle KEXINIT payload

            let mut padding = vec![0u8; padding_length as usize];
            r.read_exact(&mut padding[..])?;

            debug_assert!(r.limit() == 0);

            payload
        };

        tracing::debug!("Generate ephemeral private key for ECDH");
        let client_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let client_public_key = client_private_key.compute_public_key().unwrap();

        tracing::debug!("Send ECDH_INIT");
        {
            let mut payload = vec![];
            payload.put_u8(consts::SSH_MSG_KEX_ECDH_INIT);
            put_ssh_string(&mut payload, client_public_key.as_ref());

            write_packet(self.stream.get_ref(), &payload[..])?;
            self.stream.get_ref().flush()?;
        }

        tracing::debug!("Recv ECDH_REPLY");
        let (server_host_key_raw, server_public_key_raw, exchange_hash_sig_raw) = {
            let packet_length = self.stream.read_u32::<NetworkEndian>()?;
            let mut r = io::Read::take(&mut self.stream, packet_length as u64);

            let padding_length = r.read_u8()?;

            let typ = r.read_u8()?;
            tracing::trace!("typ = {}", typ);
            if typ != consts::SSH_MSG_KEX_ECDH_REPLY {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid reply from server",
                ));
            }
            let k_s = read_ssh_string(&mut r)?;
            let q_s = read_ssh_string(&mut r)?;
            let sig = read_ssh_string(&mut r)?;

            let mut padding = vec![0u8; padding_length as usize];
            r.read_exact(&mut padding[..])?;

            debug_assert!(r.limit() == 0);

            (k_s, q_s, sig)
        };
        tracing::trace!("server_host_key_raw_len = {}", server_host_key_raw.len());
        tracing::trace!(
            "server_public_key_raw_len = {}",
            server_public_key_raw.len()
        );
        tracing::trace!(
            "exchange_hash_sig_raw_len = {}",
            exchange_hash_sig_raw.len()
        );

        tracing::debug!("Calculate shared secret");

        // digest remaining parts since kex keys will be consumed after agreement.
        let mut digest = digest::Context::new(&digest::SHA256);
        digest_ssh_string(&mut digest, &client_id[..]);
        digest_ssh_string(&mut digest, &server_id[..]);
        digest_ssh_string(&mut digest, &client_kexinit_payload[..]);
        digest_ssh_string(&mut digest, &server_kexinit_payload[..]);
        digest_ssh_string(&mut digest, &server_host_key_raw[..]);
        digest_ssh_string(&mut digest, client_public_key.as_ref());
        digest_ssh_string(&mut digest, &server_public_key_raw[..]);

        tracing::debug!("Parse server host key for verifying signature");
        let server_host_key = {
            let mut reader = Buf::reader(&server_host_key_raw[..]);
            let key_type = read_ssh_string(&mut reader)?;
            match &*key_type {
                b"ssh-ed25519" => {
                    tracing::trace!("ssh-ed25519");
                    // ref: https://tools.ietf.org/html/rfc8709#section-4
                    let key = read_ssh_string(&mut reader)?;
                    tracing::trace!("key_len = {}", key.len());
                    signature::UnparsedPublicKey::new(&signature::ED25519, key)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unsupported server host key format",
                    ))
                }
            }
        };
        // TODO: verify server host key.

        let server_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519, //
            &server_public_key_raw[..],
        );

        tracing::debug!("Parse exchange hash signature");
        let exchange_hash_sig = {
            let mut reader = Buf::reader(&exchange_hash_sig_raw[..]);
            let key_type = read_ssh_string(&mut reader)?;
            match &*key_type {
                b"ssh-ed25519" => {
                    tracing::trace!("ssh-ed25519");
                    // ref: https://tools.ietf.org/html/rfc8709#section-6
                    read_ssh_string(&mut reader)?
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unsupported exchange hash signature format",
                    ))
                }
            }
        };
        tracing::trace!("exchange_hash_sig_len = {}", exchange_hash_sig.len());

        let (opening_key, sealing_key, session_id) = agreement::agree_ephemeral(
            client_private_key,
            &server_public_key,
            io::Error::new(io::ErrorKind::Other, "errored before calling kdf"),
            |secret| {
                tracing::trace!("calculate exchange hash H");
                let exchange_hash = {
                    digest_ssh_mpint(&mut digest, secret);
                    digest.finish()
                };
                server_host_key
                    .verify(exchange_hash.as_ref(), &exchange_hash_sig[..])
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::Other, "exchange hash is not valid")
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

                Ok((opening_key, sealing_key, exchange_hash))
            },
        )?;

        tracing::debug!("Send client NEWKEYS");
        {
            let mut payload = vec![];
            payload.put_u8(consts::SSH_MSG_NEWKEYS);

            write_packet(self.stream.get_ref(), &payload[..])?;
            self.stream.get_ref().flush()?;
        }

        tracing::debug!("Recv server NEWKEYS");
        {
            let packet_length = self.stream.read_u32::<NetworkEndian>()?;
            tracing::trace!("packet_length = {}", packet_length);
            let mut r = io::Read::take(&mut self.stream, packet_length as u64);

            let padding_length = r.read_u8()?;
            tracing::trace!("padding_length = {}", padding_length);

            let payload_len = packet_length as usize - padding_length as usize - 1;
            let mut payload = vec![0u8; payload_len];
            r.read_exact(&mut payload[..])?;
            if payload.is_empty() || payload[0] != consts::SSH_MSG_NEWKEYS {
                // TODO: send DISCONNECT
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "incorrect packet type",
                ));
            }

            let mut padding = vec![0u8; padding_length as usize];
            r.read_exact(&mut padding[..])?;

            debug_assert!(r.limit() == 0);
        };

        Ok(Session {
            stream: self.stream,
            opening_key,
            sealing_key,
            session_id,
        })
    }
}

fn compute_key<K>(
    expected_key_len: usize,
    c: u8,
    secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    make_key: fn(&[u8]) -> io::Result<K>,
) -> io::Result<K> {
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

#[allow(dead_code)]
pub struct Session {
    stream: io::BufReader<TcpStream>,
    opening_key: aead::OpeningKey,
    sealing_key: aead::SealingKey,
    session_id: digest::Digest,
}

fn put_ssh_string<B: BufMut>(mut b: B, s: &[u8]) {
    let len = s.len() as u32;
    b.put_u32(len);
    b.put_slice(s);
}

fn read_ssh_string<R: io::Read>(mut r: R) -> io::Result<Vec<u8>> {
    let len = r.read_u32::<NetworkEndian>()?;
    let mut s = vec![0u8; len as usize];
    r.read_exact(&mut s[..])?;
    Ok(s)
}

fn write_ssh_string<W: io::Write>(mut w: W, s: &[u8]) -> io::Result<()> {
    let len = s.len() as u32;
    w.write_u32::<NetworkEndian>(len)?;
    w.write_all(s)?;
    Ok(())
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

fn write_packet<W>(mut w: W, payload: &[u8]) -> io::Result<()>
where
    W: io::Write,
{
    let padding_length = padding_length(&payload[..], 8);
    let packet_length = 1 + payload.len() + padding_length; // padding_length(u8) + payload + padding
    tracing::trace!("packet_length = {}", packet_length);
    tracing::trace!("padding_length = {}", padding_length);

    let mut write_buf = Vec::with_capacity(packet_length + 4);
    write_buf.put_u32(packet_length as u32);
    write_buf.put_u8(padding_length as u8); // padding_length
    write_buf.put_slice(&payload[..]);
    write_buf.extend(std::iter::repeat(0u8).take(padding_length));

    w.write_all(&write_buf[..])?;

    Ok(())
}

const fn padding_length(payload: &[u8], block_size: usize) -> usize {
    let padding_length = block_size - ((5 + payload.len()) % block_size);
    if padding_length < 4 {
        padding_length + block_size
    } else {
        padding_length
    }
}

#[allow(dead_code)]
mod consts {
    // defined in https://tools.ietf.org/html/rfc4253#section-12
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;

    // defined in https://tools.ietf.org/html/rfc5656#section-7.1
    pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
    pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

    // defined in https://git.libssh.org/projects/libssh.git/tree/doc/curve25519-sha256@libssh.org.txt#n62
    pub const CURVE25519_SHA256: &str = "curve25519-sha256@libssh.org";

    // defined in http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?rev=1.5&content-type=text/x-cvsweb-markup
    pub const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";
}
