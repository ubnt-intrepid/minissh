use minissh2::crypto::{CryptoError, KexAlgorithm, PeerPublicKey};
use ring::{
    agreement::{self, EphemeralPrivateKey, PublicKey},
    digest,
    rand::SecureRandom,
};

pub struct Kex {
    private_key: EphemeralPrivateKey,
    public_key: PublicKey,
    digest: digest::Context,
}

impl Kex {
    pub(crate) fn new(
        rng: &dyn SecureRandom,
        algorithm: &KexAlgorithm,
    ) -> Result<Self, CryptoError> {
        let (agreement, digest) = match algorithm {
            KexAlgorithm("curve25519-sha256") | KexAlgorithm("curve25519-sha256@libssh.org") => {
                (&agreement::X25519, &digest::SHA256)
            }
            _ => return Err(CryptoError), // unsupported
        };

        let private_key = EphemeralPrivateKey::generate(agreement, rng).map_err(|_| CryptoError)?;
        let public_key = private_key.compute_public_key().map_err(|_| CryptoError)?;

        Ok(Self {
            private_key,
            public_key,
            digest: digest::Context::new(digest),
        })
    }

    pub(crate) const fn algorithms() -> &'static [KexAlgorithm] {
        &[KexAlgorithm("curve25519-sha256@libssh.org")]
    }
}

impl minissh2::crypto::Kex for Kex {
    #[inline]
    fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    #[inline]
    fn accept_client_ssh_id(&mut self, id: &[u8]) {
        self.digest.update(id);
    }

    #[inline]
    fn accept_server_ssh_id(&mut self, id: &[u8]) {
        self.digest.update(id);
    }

    #[inline]
    fn accept_client_kexinit(&mut self, payload: &[u8]) {
        digest_ssh_string(&mut self.digest, payload);
    }

    #[inline]
    fn accept_server_kexinit(&mut self, payload: &[u8]) {
        digest_ssh_string(&mut self.digest, payload);
    }

    #[inline]
    fn accept_server_host_key(&mut self, payload: &[u8]) {
        digest_ssh_string(&mut self.digest, payload);
    }

    #[inline]
    fn accept_peer_public_key(&mut self, key: &PeerPublicKey<'_>) {
        match key {
            PeerPublicKey::FromServer(key) => {
                digest_ssh_string(&mut self.digest, self.public_key.as_ref());
                digest_ssh_string(&mut self.digest, key);
            }
            PeerPublicKey::FromClient(key) => {
                digest_ssh_string(&mut self.digest, key);
                digest_ssh_string(&mut self.digest, self.public_key.as_ref());
            }
        }
    }

    fn finish<F, R, E>(
        self,
        peer_public_key: &PeerPublicKey<'_>,
        session_id: Option<&[u8]>,
        error_value: E,
        kdf: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&mut dyn minissh2::crypto::KeyDerivation) -> Result<R, E>,
    {
        let Self {
            private_key,
            mut digest,
            ..
        } = self;

        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);

        agreement::agree_ephemeral(private_key, &peer_public_key, error_value, |secret| {
            // calculate exchange hash H
            digest_ssh_mpint(&mut digest, secret);
            let exchange_hash = digest.finish();
            let exchange_hash = exchange_hash.as_ref();

            let session_id = session_id.unwrap_or(exchange_hash);

            kdf(&mut KeyDerivation {
                secret,
                exchange_hash,
                session_id,
            })
        })
    }
}

struct KeyDerivation<'a> {
    secret: &'a [u8],
    exchange_hash: &'a [u8],
    session_id: &'a [u8],
}

impl KeyDerivation<'_> {
    fn compute_key(&self, c: u8, out: &mut [u8]) -> Result<(), CryptoError> {
        todo!()
    }
}

impl minissh2::crypto::KeyDerivation for KeyDerivation<'_> {
    fn exchange_hash(&self) -> &[u8] {
        self.exchange_hash
    }

    fn compute_iv_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'A', out)
    }

    fn compute_iv_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'B', out)
    }

    fn compute_encryption_key_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'C', out)
    }

    fn compute_encryption_key_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'D', out)
    }

    fn compute_integrity_key_ctos(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'E', out)
    }

    fn compute_integrity_key_stoc(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.compute_key(b'F', out)
    }
}

#[inline]
fn digest_ssh_string(digest: &mut digest::Context, data: &[u8]) {
    let len = data.len() as u32;
    digest.update(&len.to_be_bytes());
    digest.update(data);
}

#[inline]
fn digest_ssh_mpint(digest: &mut digest::Context, data: &[u8]) {
    let i = data.iter().take_while(|&&b| b == 0).count();
    let data = &data[i..];
    let data_len = data.len() as u32;
    match data.get(0) {
        Some(b) if b & 0x80 != 0 => {
            digest.update(&(data_len + 1).to_be_bytes());
            digest.update(&[0]);
            digest.update(data);
        }
        Some(..) => {
            digest.update(&data_len.to_be_bytes());
            digest.update(data);
        }
        None => {
            digest.update(&[0, 0, 0, 0]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn test_digest_ssh_mpint_case(
        algo: &'static digest::Algorithm,
        input: &[u8],
        equivalent: &[u8],
    ) {
        let mut ctx = digest::Context::new(algo);
        digest_ssh_mpint(&mut ctx, input);
        let digest1 = ctx.finish();
        let digest2 = digest::digest(algo, equivalent);
        assert_eq!(digest1.as_ref(), digest2.as_ref(), "digest is mismatched");
    }

    fn digest_ssh_mpint_cases(algo: &'static digest::Algorithm) {
        // https://tools.ietf.org/html/rfc4251#section-5

        // input = 00
        test_digest_ssh_mpint_case(&digest::SHA256, &[0x00], &[0x00, 0x00, 0x00, 0x00]);
        test_digest_ssh_mpint_case(
            &digest::SHA256,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00],
        );

        // input = 9a378f9b2e332a7
        test_digest_ssh_mpint_case(
            algo,
            &[0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7],
            &[
                0x00, 0x00, 0x00, 0x08, 0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7,
            ],
        );
        test_digest_ssh_mpint_case(
            algo,
            &[0x00, 0x00, 0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7],
            &[
                0x00, 0x00, 0x00, 0x08, 0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7,
            ],
        );

        // input = 80
        test_digest_ssh_mpint_case(algo, &[0x80], &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
        test_digest_ssh_mpint_case(
            algo,
            &[0x00, 0x00, 0x80],
            &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80],
        );
    }

    #[test]
    fn digest_ssh_mpint_sha256() {
        digest_ssh_mpint_cases(&digest::SHA256);
    }

    #[test]
    fn digest_ssh_mpint_sha384() {
        digest_ssh_mpint_cases(&digest::SHA384);
    }

    #[test]
    fn digest_ssh_mpint_sha512() {
        digest_ssh_mpint_cases(&digest::SHA512);
    }
}
