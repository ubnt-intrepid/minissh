//! Cryptography abstraction in SSH transport layer.
//!
//! This module provides the abstraction of encryption/decryption between client and server
//! and the key exchange method, described in RFC 4253.

#[derive(Debug, thiserror::Error)]
#[error("crypto error")]
pub struct CryptoError;

/// A key exchange context.
pub trait Kex {
    /// Returns the contents of ephemeral public key.
    fn public_key(&self) -> &[u8];

    /// Accepts the client's identifier string.
    fn accept_client_ssh_id(&mut self, id: &[u8]);

    /// Accepts the server's identifier string.
    fn accept_server_ssh_id(&mut self, id: &[u8]);

    /// Accepts the payload of client's `SSH_MSG_KEXINIT` packet.
    fn accept_client_kexinit(&mut self, payload: &[u8]);

    /// Accepts the payload of server's `SSH_MSG_KEXINIT` packet.
    fn accept_server_kexinit(&mut self, payload: &[u8]);

    /// Accepts the server's host key.
    fn accept_server_host_key(&mut self, payload: &[u8]);

    /// Accepts the ephemeral public key from other party.
    fn accept_peer_public_key(&mut self, public_key: &PeerPublicKey<'_>);

    /// Completes key exchange.
    fn finish<F, R, E>(
        self,
        public_key: &PeerPublicKey<'_>,
        session_id: Option<&[u8]>,
        error_value: E,
        kdf: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&mut dyn KeyDerivation) -> Result<R, E>;
}

/// The ephemeral public key delivered from other party.
pub enum PeerPublicKey<'key> {
    /// The key delivered from the server.
    FromServer(&'key [u8]),

    /// The key delivered from the client.
    FromClient(&'key [u8]),
}
impl AsRef<[u8]> for PeerPublicKey<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            PeerPublicKey::FromClient(key) => key,
            PeerPublicKey::FromServer(key) => key,
        }
    }
}

/// The key derivation context.
pub trait KeyDerivation {
    /// Return the value of exchange hash in raw bytes.
    fn exchange_hash(&self) -> &[u8];

    fn compute_iv_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_iv_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_encryption_key_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_encryption_key_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_integrity_key_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_integrity_key_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError>;
}

/// Opening (authentication and decryption) context.
pub trait Opening {
    /// Returns the length of authentication tag.
    fn tag_len(&self) -> usize;

    /// Decrypts the length of a packet.
    ///
    /// Note that the length of authentication tag is not included in the value
    /// returned from this function.
    fn decrypt_packet_length(&mut self, encrypted: [u8; 4]) -> u32;

    /// Opens (authenticates and decrypts) a packet.
    ///
    /// The input data `in_out` must be a concatenation of encrypted packet length,
    /// the ciphertext of packet payload and the authentication tag.
    fn open_in_place(&mut self, in_out: &mut [u8], packet_length: u32) -> Result<(), CryptoError>;
}

/// Sealing (encryption and signing) context.
pub trait Sealing {
    /// Returns the length of authentication tag.
    fn tag_len(&self) -> usize;

    /// Seals (encrypts and signs) a packet.
    ///
    /// The input data `in_out` must be a concatenation of packet length and the plaintext of
    /// packet payload with random padding.
    ///
    /// The length of `tag_out` must be equal to `tag_len`.
    fn seal_in_place(&mut self, in_out: &mut [u8], tag_out: &mut [u8]) -> Result<(), CryptoError>;
}

/// The name of key exchange algorithm.
#[derive(Clone, Copy, Debug)]
pub struct KexAlgorithm(pub &'static str);

impl AsRef<str> for KexAlgorithm {
    #[inline]
    fn as_ref(&self) -> &str {
        &*self.0
    }
}

/// The name of cipher algorithm.
#[derive(Clone, Copy, Debug)]
pub struct CipherAlgorithm(pub &'static str);

impl AsRef<str> for CipherAlgorithm {
    #[inline]
    fn as_ref(&self) -> &str {
        &*self.0
    }
}
pub trait CipherSuite {
    type Kex: Kex;
    type Opening: Opening;
    type Sealing: Sealing;

    /// Return the name list of available key exchange algorithms.
    fn kex_algorithms(&self) -> &[KexAlgorithm];

    /// Return the name list of available encryption methods used for opening (authenticated decryption).
    fn opening_algorithms(&self) -> &[CipherAlgorithm];

    /// Return the name list of available encryption methods used for sealing (authenticated encryption).
    fn sealing_algorithms(&self) -> &[CipherAlgorithm];

    /// Fill the specified buffer with random bytes.
    ///
    /// This function is typically used for filling cookie field in KEXINIT packet.
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>;

    /// Initiate a key exchange process.
    fn start_kex(&mut self, guessed: &KexAlgorithm) -> Result<Self::Kex, CryptoError>;
}
