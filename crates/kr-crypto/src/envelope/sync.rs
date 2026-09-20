//! Sealing a synchronised object under the key a person's devices share.
//!
//! Section 20 stores settings, drafts and a client's own position on a service that holds
//! ciphertext and no keys, and it pads them to the same declared buckets a mailbox item uses. The
//! padding rule therefore lives here, beside the envelope's, rather than being restated somewhere
//! a second reading of section 20 could drift from this one.
//!
//! # What binds an object to its place
//!
//! Nothing outside the ciphertext. The additional authenticated data is the format domain and that
//! alone, so a ciphertext produced for one purpose cannot be opened as another. What identifies the
//! object, its own identity and its revision, is inside the sealed plaintext, and the reader checks
//! it there against what it asked for. That is the same rule the draft store keeps: the seal says
//! the bytes came from a device that holds the key, not that they belong where they were found.
//!
//! Binding the requested collection into the additional data would be sound too, and would refuse
//! a misplaced object one step earlier. It is not done here because the check the reader has to
//! make either way is the one inside the plaintext: an object is its identity and its revision,
//! and a second statement of the same fact outside the encryption would be a second thing to keep
//! in step.

use kr_protocol::scalars::{Bytes, U64};
use kr_protocol::sync::{MAX_SYNC_OBJECT_PLAINTEXT_BYTES, SealedSyncObject};

use super::{pad_to_bucket, unpadded_len};
use crate::aead;
use crate::error::{CryptoError, Result};
use crate::secret::{SecretVec, SymmetricKey};
use crate::sodium;

/// The additional authenticated data every synchronised object is sealed under.
///
/// It separates this use of the device's key from every other use of a symmetric key in the
/// system, so a ciphertext produced for one purpose cannot be opened as another.
pub const SYNC_OBJECT_DOMAIN: &[u8] = b"kr-sync-object/1";

/// Seals one synchronised object, padded to its declared size bucket.
///
/// The nonce is generated inside the AEAD wrapper and returned with the ciphertext, so a caller
/// cannot repeat one. The returned object satisfies the structure rules a service applies, which
/// is checked here rather than left for the service to discover: a producer that built an object
/// the service must refuse would find out one round trip later.
///
/// # Errors
///
/// Returns [`CryptoError::TooLarge`] when the plaintext's bucket is past the 64 KiB a synchronised
/// object may carry, [`CryptoError::BindingMismatch`] when the padding does not reach its bucket,
/// and a library error when libsodium fails.
pub fn seal_sync_object(key: &SymmetricKey, plaintext: &[u8]) -> Result<SealedSyncObject> {
    let mut encoded = plaintext.to_vec();
    let (mut padded, bucket) = match pad_to_bucket(&mut encoded) {
        Ok(padded) => padded,
        Err(error) => {
            sodium::memzero(&mut encoded);
            return Err(error);
        }
    };
    if bucket > MAX_SYNC_OBJECT_PLAINTEXT_BYTES {
        sodium::memzero(&mut padded);
        return Err(CryptoError::TooLarge {
            what: "a synchronised object",
            limit: MAX_SYNC_OBJECT_PLAINTEXT_BYTES as usize,
            actual: plaintext.len(),
        });
    }

    let sealed = aead::seal(key, SYNC_OBJECT_DOMAIN, &padded);
    sodium::memzero(&mut padded);
    let (nonce, ciphertext) = sealed?;

    let object = SealedSyncObject {
        nonce,
        size_bucket_bytes: U64::new(bucket),
        ciphertext: Bytes::new(ciphertext),
    };
    object
        .check_structure()
        .map_err(|_| CryptoError::BindingMismatch {
            what: "the shape of a synchronised object this device sealed",
        })?;
    Ok(object)
}

/// Opens one synchronised object and removes its padding.
///
/// The keyless rules run first, so an object whose declared bucket and ciphertext length disagree
/// is refused before the key is used. What comes back is the content alone: the padding is removed
/// and the buffer that held it is cleared.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the object's shape is not one section 20's rules
/// produce, and [`CryptoError::Authentication`] when the ciphertext does not authenticate under
/// this key.
pub fn open_sync_object(key: &SymmetricKey, object: &SealedSyncObject) -> Result<SecretVec> {
    object
        .check_structure()
        .map_err(|_| CryptoError::BindingMismatch {
            what: "the shape of a synchronised object",
        })?;
    let opened = aead::open(
        key,
        &object.nonce,
        SYNC_OBJECT_DOMAIN,
        object.ciphertext.as_slice(),
    )?;
    // The declared bucket is checked against the length that was actually sealed, so a service that
    // stored one figure and served another is caught by the opened length rather than by its own
    // record of it.
    if opened.len() as u64 != object.size_bucket_bytes.get() {
        return Err(CryptoError::BindingMismatch {
            what: "the declared size bucket of a synchronised object",
        });
    }
    let content_len = unpadded_len(opened.expose())?;
    Ok(SecretVec::from(opened.expose()[..content_len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;

    fn key() -> SymmetricKey {
        Secret::from_bytes([0x5a; 32])
    }

    #[test]
    fn an_object_round_trips_and_is_padded_to_its_bucket() {
        let object = seal_sync_object(&key(), b"a setting").expect("sealed");
        assert_eq!(object.size_bucket_bytes.get(), 1024);
        assert_eq!(object.ciphertext.as_slice().len(), 1024 + 16);
        let opened = open_sync_object(&key(), &object).expect("opened");
        assert_eq!(opened.expose(), b"a setting");
    }

    #[test]
    fn two_objects_of_different_sizes_share_one_stored_length() {
        let first = seal_sync_object(&key(), &[1; 8]).expect("sealed");
        let second = seal_sync_object(&key(), &[2; 900]).expect("sealed");
        assert_eq!(first.stored_bytes(), second.stored_bytes());
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn an_object_larger_than_a_synchronised_object_may_be_is_refused_before_it_is_sealed() {
        let too_large = vec![0; MAX_SYNC_OBJECT_PLAINTEXT_BYTES as usize + 1];
        assert!(matches!(
            seal_sync_object(&key(), &too_large),
            Err(CryptoError::TooLarge {
                what: "a synchronised object",
                ..
            })
        ));
    }

    #[test]
    fn another_key_does_not_open_it_and_neither_does_another_purpose() {
        let object = seal_sync_object(&key(), b"a setting").expect("sealed");
        let other: SymmetricKey = Secret::from_bytes([0x5b; 32]);
        assert!(open_sync_object(&other, &object).is_err());

        // The domain is inside the authentication, so a ciphertext produced for another purpose
        // under the same key does not open as a synchronised object.
        let (nonce, ciphertext) = aead::seal(&key(), b"kr-other/1", &[0; 1024]).expect("sealed");
        let elsewhere = SealedSyncObject {
            nonce,
            size_bucket_bytes: U64::new(1024),
            ciphertext: Bytes::new(ciphertext),
        };
        assert!(matches!(
            open_sync_object(&key(), &elsewhere),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn a_rewritten_declared_bucket_is_refused() {
        let mut object = seal_sync_object(&key(), b"a setting").expect("sealed");
        object.size_bucket_bytes = U64::new(2048);
        assert!(matches!(
            open_sync_object(&key(), &object),
            Err(CryptoError::BindingMismatch {
                what: "the shape of a synchronised object"
            })
        ));
    }
}
