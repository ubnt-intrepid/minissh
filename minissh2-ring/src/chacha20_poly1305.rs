//! Chacha20-Poly1305.

use minissh2::crypto::{self, CryptoError};
use ring::aead::chacha20_poly1305_openssh as aead;
use std::{convert::TryInto as _, num::Wrapping};

pub struct Opening {
    key: aead::OpeningKey,
    seqn: Wrapping<u32>,
}
impl Opening {
    pub fn new(key_material: &[u8], _iv: &[u8]) -> Result<Self, CryptoError> {
        let key_material = key_material.try_into().map_err(|_| CryptoError)?;
        Ok(Self {
            key: aead::OpeningKey::new(key_material),
            seqn: Wrapping(0),
        })
    }
}
impl crypto::Opening for Opening {
    #[inline]
    fn tag_len(&self) -> usize {
        aead::TAG_LEN
    }

    #[inline]
    fn decrypt_packet_length(&mut self, encrypted: [u8; 4]) -> u32 {
        u32::from_be_bytes(self.key.decrypt_packet_length(self.seqn.0, encrypted))
    }

    fn open_in_place(&mut self, in_out: &mut [u8], packet_length: u32) -> Result<(), CryptoError> {
        let (in_out, tag) = in_out.split_at_mut(4 + packet_length as usize);
        let tag: &mut [u8; aead::TAG_LEN] = tag.try_into().map_err(|_| CryptoError)?;

        self.key
            .open_in_place(self.seqn.0, in_out, tag)
            .map_err(|_| CryptoError)?;

        self.seqn += Wrapping(1);

        Ok(())
    }
}

pub struct Sealing {
    key: aead::SealingKey,
    seqn: Wrapping<u32>,
}
impl Sealing {
    pub fn new(key_material: &[u8], _iv: &[u8]) -> Result<Self, CryptoError> {
        let key_material = key_material.try_into().map_err(|_| CryptoError)?;
        Ok(Self {
            key: aead::SealingKey::new(key_material),
            seqn: Wrapping(0),
        })
    }
}
impl crypto::Sealing for Sealing {
    #[inline]
    fn tag_len(&self) -> usize {
        aead::TAG_LEN
    }

    fn seal_in_place(&mut self, in_out: &mut [u8], tag_out: &mut [u8]) -> Result<(), CryptoError> {
        let tag_out: &mut [u8; aead::TAG_LEN] = tag_out.try_into().map_err(|_| CryptoError)?;

        self.key.seal_in_place(self.seqn.0, in_out, tag_out);
        self.seqn += Wrapping(1);

        Ok(())
    }
}
