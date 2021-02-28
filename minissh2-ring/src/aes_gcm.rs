//! AES in GCM mode.

use minissh2::crypto::{self, CryptoError};
use ring::{
    aead::{self, Aad, BoundKey as _, Nonce, OpeningKey, SealingKey, UnboundKey},
    error::Unspecified,
};

pub struct Opening {
    key: OpeningKey<NonceSequence>,
}
impl Opening {
    pub fn new(key_material: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        let unbounded =
            UnboundKey::new(&aead::AES_128_GCM, key_material).map_err(|_| CryptoError)?;
        let nonces = NonceSequence::new(iv)?;
        Ok(Self {
            key: OpeningKey::new(unbounded, nonces),
        })
    }
}
impl crypto::Opening for Opening {
    #[inline]
    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }

    #[inline]
    fn decrypt_packet_length(&mut self, encrypted: [u8; 4]) -> u32 {
        // The packet length is not encrypted in AES-GCM mode.
        // Ref: https://tools.ietf.org/html/rfc5647#section-8.2
        u32::from_be_bytes(encrypted)
    }

    #[inline]
    fn open_in_place(&mut self, in_out: &mut [u8], _: u32) -> Result<(), CryptoError> {
        let (aad, in_out) = in_out.split_at_mut(4);
        self.key
            .open_in_place(Aad::from(&*aad), in_out)
            .map_err(|_| CryptoError)?;
        Ok(())
    }
}

pub struct Sealing {
    key: SealingKey<NonceSequence>,
}
impl Sealing {
    pub fn new(key_material: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        let unbounded =
            UnboundKey::new(&aead::AES_128_GCM, key_material).map_err(|_| CryptoError)?;
        let nonces = NonceSequence::new(iv)?;
        Ok(Self {
            key: SealingKey::new(unbounded, nonces),
        })
    }
}
impl crypto::Sealing for Sealing {
    #[inline]
    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }

    fn seal_in_place(&mut self, in_out: &mut [u8], tag_out: &mut [u8]) -> Result<(), CryptoError> {
        let (aad, in_out) = in_out.split_at_mut(4);

        let tag = self
            .key
            .seal_in_place_separate_tag(Aad::from(&*aad), in_out)
            .map_err(|_| CryptoError)?;
        let tag = tag.as_ref();

        let tag_out = tag_out.get_mut(..tag.len()).ok_or(CryptoError)?;
        tag_out.copy_from_slice(tag);

        Ok(())
    }
}

// SSH AES-GCM nonce sequence
// ref: https://tools.ietf.org/html/rfc5647#section-7.1

struct NonceSequence {
    fixed: u32,
    invocation_counter: u64,
}
impl NonceSequence {
    fn new(iv: &[u8]) -> Result<Self, CryptoError> {
        todo!()
    }
}
impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        todo!()
    }
}
