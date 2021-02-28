//! Host authentication.

pub struct AuthError;

/// Server authentication during an SSH session.
pub trait HostAuth {
    /// Returns a list of accepted algorithm names.
    fn algorithms(&self) -> &[HostKeyAlgorithm];

    /// Verify the calculated exchange hash using the provided host key and signature.
    ///
    /// This function will be called at every key exchange.
    fn verify(
        &mut self,
        exchange_hash: &[u8],
        host_key: HostKey<'_>,
        signature: Signature<'_>,
    ) -> Result<(), AuthError>;
}

/// The name of host key algorithm.
#[derive(Clone, Copy, Debug)]
pub struct HostKeyAlgorithm(pub &'static str);

impl AsRef<str> for HostKeyAlgorithm {
    #[inline]
    fn as_ref(&self) -> &str {
        &*self.0
    }
}

#[non_exhaustive]
pub struct HostKey<'key> {
    pub key_type: &'key [u8],
    pub key_data: &'key [u8],
}

#[non_exhaustive]
pub struct Signature<'sig> {
    pub sig_type: &'sig [u8],
    pub sig_data: &'sig [u8],
}
