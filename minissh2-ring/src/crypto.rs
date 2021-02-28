use minissh2::crypto::{CipherAlgorithm, CipherSuite, CryptoError, KexAlgorithm};
use ring::rand::{SecureRandom, SystemRandom};

pub use crate::kex::Kex;

pub struct DefaultCipherSuite {
    rng: SystemRandom,
}

impl Default for DefaultCipherSuite {
    fn default() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl CipherSuite for DefaultCipherSuite {
    type Kex = Kex;
    type Opening = crate::chacha20_poly1305::Opening;
    type Sealing = crate::chacha20_poly1305::Sealing;

    #[inline]
    fn kex_algorithms(&self) -> &[KexAlgorithm] {
        Kex::algorithms()
    }

    fn opening_algorithms(&self) -> &[CipherAlgorithm] {
        &[CipherAlgorithm("chacha20-poly1305@openssh.com")]
    }

    fn sealing_algorithms(&self) -> &[CipherAlgorithm] {
        &[CipherAlgorithm("chacha20-poly1305@openssh.com")]
    }

    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.rng.fill(buf).map_err(|_| CryptoError)
    }

    #[inline]
    fn start_kex(&mut self, algorithm: &KexAlgorithm) -> Result<Self::Kex, CryptoError> {
        Kex::new(&self.rng, &algorithm)
    }
}
