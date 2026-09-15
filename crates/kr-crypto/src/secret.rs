//! Secret buffers that are zeroised when they are dropped.
//!
//! Section 20 requires temporary secret buffers to be zeroised. A key that lives in a plain array
//! is copied by every move and left in memory by every drop, so every secret in this crate lives
//! in one of the two types below, which zeroise on drop and refuse to print their contents.

use core::fmt;

use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::sodium;

/// A fixed-width secret.
///
/// It does not implement `Copy`: a `Copy` secret would leave a duplicate behind on every move,
/// and a duplicate cannot be zeroised. `Clone` is implemented and explicit, so a second copy is
/// always something the caller asked for.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Length in bytes.
    pub const LEN: usize = N;

    /// Wraps raw bytes. The caller's own copy is untouched; zeroise it if it was a secret.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Generates a secret from libsodium's random generator.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; N];
        sodium::random_bytes(&mut bytes)?;
        // An array is `Copy`, so wrapping it leaves the local behind. Wipe it.
        let secret = Self(bytes);
        sodium::memzero(&mut bytes);
        Ok(secret)
    }

    /// Wraps a slice of exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Truncated`] or [`CryptoError::TooLarge`] when the slice is a
    /// different length.
    pub fn from_slice(what: &'static str, slice: &[u8]) -> Result<Self> {
        match <[u8; N]>::try_from(slice) {
            Ok(mut bytes) => {
                let secret = Self(bytes);
                sodium::memzero(&mut bytes);
                Ok(secret)
            }
            Err(_) if slice.len() < N => Err(CryptoError::Truncated {
                what,
                minimum: N,
                actual: slice.len(),
            }),
            Err(_) => Err(CryptoError::TooLarge {
                what,
                limit: N,
                actual: slice.len(),
            }),
        }
    }

    /// Returns the bytes.
    ///
    /// The name is deliberate: every call site that reads a secret is one a reviewer can find.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Returns true when the two secrets are equal, comparing in constant time.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        sodium::constant_time_eq(&self.0, &other.0)
    }
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        sodium::memzero(&mut self.0);
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Secret<{N}>(redacted)")
    }
}

/// A variable-width secret.
///
/// It is used for plaintext that is secret but not a key: a decrypted envelope body, a secret read
/// back from the platform store, a buffer being assembled before encryption.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Wraps raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        // `Vec::zeroize` clears the whole allocation, including the part past the length, and then
        // truncates. A reallocation earlier in the value's life can still have left a copy behind,
        // which is why a secret that is built up incrementally is allocated at its final size.
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretVec({} bytes, redacted)", self.0.len())
    }
}

/// A 256-bit symmetric key.
pub type SymmetricKey = Secret<32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_hides_its_contents_from_debug_output() {
        let secret = Secret::<32>::from_bytes([7; 32]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "Secret<32>(redacted)");
        assert!(!rendered.contains('7'));
        let variable = SecretVec::new(vec![7; 8]);
        assert_eq!(format!("{variable:?}"), "SecretVec(8 bytes, redacted)");
    }

    #[test]
    fn a_secret_built_from_a_slice_keeps_the_bytes() {
        let secret = Secret::<4>::from_slice("a test key", &[1, 2, 3, 4]).expect("four bytes");
        assert_eq!(secret.expose(), &[1, 2, 3, 4]);
    }

    #[test]
    fn a_random_secret_is_not_all_zeroes() {
        let secret = Secret::<32>::random().expect("libsodium is available");
        assert_ne!(secret.expose(), &[0u8; 32]);
    }

    #[test]
    fn equality_is_constant_time_and_correct() {
        let left = Secret::<32>::from_bytes([1; 32]);
        let right = Secret::<32>::from_bytes([1; 32]);
        let other = Secret::<32>::from_bytes([2; 32]);
        assert!(left.constant_time_eq(&right));
        assert!(!left.constant_time_eq(&other));
    }

    #[test]
    fn a_slice_of_the_wrong_length_is_rejected() {
        assert!(matches!(
            Secret::<32>::from_slice("a test key", &[0; 31]),
            Err(CryptoError::Truncated { actual: 31, .. })
        ));
        assert!(matches!(
            Secret::<32>::from_slice("a test key", &[0; 33]),
            Err(CryptoError::TooLarge { actual: 33, .. })
        ));
    }
}
