use bytes::Buf;
use minissh2::hostauth::{AuthError, HostAuth, HostKey, HostKeyAlgorithm, Signature};

pub struct DefaultHostAuth;

impl DefaultHostAuth {
    fn verify_ed25519(
        &self,
        exchange_hash: &[u8],
        host_key: HostKey<'_>,
        signature: Signature<'_>,
    ) -> Result<(), AuthError> {
        let host_key = {
            let mut data = host_key.key_data;
            let len = data.get_u32() as usize;
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &data[..len])
        };

        // TODO: certificate the host key.

        if signature.sig_type != b"ssh-ed25519" {
            return Err(AuthError); // key type mismatched
        }
        let signature = {
            let mut data = signature.sig_data;
            let len = data.get_u32() as usize;
            &data[..len]
        };

        host_key
            .verify(exchange_hash, signature)
            .map_err(|_| AuthError) // verification failed
    }
}
impl HostAuth for DefaultHostAuth {
    fn algorithms(&self) -> &[HostKeyAlgorithm] {
        &[HostKeyAlgorithm("ssh-ed25519")]
    }

    fn verify(
        &mut self,
        exchange_hash: &[u8],
        host_key: HostKey<'_>,
        signature: Signature<'_>,
    ) -> Result<(), AuthError> {
        match host_key.key_type {
            b"ssh-ed25519" => self.verify_ed25519(exchange_hash, host_key, signature),
            _ => Err(AuthError), // unsupported key type
        }
    }
}
