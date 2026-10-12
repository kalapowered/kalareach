//! `crypto_secretstream_xchacha20poly1305` in one-mebibyte records.
//!
//! Section 20 encrypts every backup object through `secretstream` in 1 MiB records and requires
//! its final authenticated record before a complete object is accepted. A truncated upload is
//! therefore not a shorter valid object: it has no final record, and [`decrypt_object`] rejects it.
//!
//! # Framing
//!
//! An encrypted object is `header || record...`. Every record except the last carries exactly
//! [`RECORD_LEN`] plaintext bytes plus the per-record overhead; the last carries whatever remains
//! and the final tag. An empty object is one empty final record, so every object has at least one.
//! The reader derives record boundaries from that rule rather than from a length prefix, so there
//! is no unauthenticated framing for an attacker to rewrite.

use kr_protocol::archive::SECRETSTREAM_RECORD_LEN;

use crate::error::{CryptoError, Result};
use crate::secret::{SecretVec, SymmetricKey};
use crate::sodium;

/// Plaintext bytes in one record.
pub const RECORD_LEN: usize = SECRETSTREAM_RECORD_LEN;

/// Bytes in the stream header.
pub const HEADER_LEN: usize = sodium::STREAM_HEADER_LEN;

/// Bytes each record adds to its plaintext.
pub const RECORD_OVERHEAD: usize = sodium::STREAM_RECORD_OVERHEAD;

/// Bytes in one complete record that carries a full plaintext record.
const FULL_RECORD_LEN: usize = RECORD_LEN + RECORD_OVERHEAD;

/// Encrypts one complete object.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn encrypt_object(key: &SymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (mut state, header) = sodium::stream_init_push(key.expose())?;
    let mut object = Vec::with_capacity(encrypted_len(plaintext.len()));
    object.extend_from_slice(&header);

    let mut offset = 0usize;
    loop {
        let end = offset.saturating_add(RECORD_LEN).min(plaintext.len());
        let is_last = end == plaintext.len();
        let tag = if is_last {
            sodium::TAG_FINAL
        } else {
            sodium::TAG_MESSAGE
        };
        let record = sodium::stream_push(&mut state, &plaintext[offset..end], tag)?;
        object.extend_from_slice(&record);
        if is_last {
            break;
        }
        offset = end;
    }
    Ok(object)
}

/// Decrypts one complete object, requiring its final authenticated record.
///
/// # Errors
///
/// Returns [`CryptoError::Truncated`] when the object is shorter than a header,
/// [`CryptoError::MissingFinalRecord`] when it ends without the final record,
/// [`CryptoError::RecordsAfterFinal`] when data follows it, and
/// [`CryptoError::Authentication`] when any record fails to authenticate.
pub fn decrypt_object(key: &SymmetricKey, object: &[u8]) -> Result<SecretVec> {
    // The plaintext is never longer than the object, so this allocation never grows and never
    // abandons a buffer holding a copy of it.
    let mut plaintext = Vec::with_capacity(object.len());
    match decrypt_into(key, object, &mut plaintext) {
        Ok(()) => Ok(SecretVec::new(plaintext)),
        Err(error) => {
            // Every failure path arrives here, so a partly assembled plaintext is wiped whether
            // the object was cut short, carried a record after its final one, or failed a tag.
            sodium::memzero(&mut plaintext);
            Err(error)
        }
    }
}

/// Reads every record into `plaintext`, leaving the zeroisation of a failure to the caller.
fn decrypt_into(key: &SymmetricKey, object: &[u8], plaintext: &mut Vec<u8>) -> Result<()> {
    if object.len() < HEADER_LEN {
        return Err(CryptoError::Truncated {
            what: "an encrypted object",
            minimum: HEADER_LEN,
            actual: object.len(),
        });
    }
    let (header, mut records) = object.split_at(HEADER_LEN);
    let header: &[u8; HEADER_LEN] = header.try_into().expect("the split is the header length");
    let mut state = sodium::stream_init_pull(header, key.expose())?;

    loop {
        if records.is_empty() {
            // Every object ends with a final record, so running out of records means the object
            // was cut short.
            return Err(CryptoError::MissingFinalRecord);
        }
        let take = records.len().min(FULL_RECORD_LEN);
        let (record, rest) = records.split_at(take);
        let (mut chunk, tag) = sodium::stream_pull(&mut state, record)?;
        plaintext.extend_from_slice(&chunk);
        // The library handed back its own allocation; wipe it rather than leaving it to the
        // allocator.
        sodium::memzero(&mut chunk);
        records = rest;
        if tag == sodium::TAG_FINAL {
            if records.is_empty() {
                return Ok(());
            }
            return Err(CryptoError::RecordsAfterFinal);
        }
        if take != FULL_RECORD_LEN {
            // A short record that is not the final one breaks the framing rule, so the object was
            // not produced by this format.
            return Err(CryptoError::MissingFinalRecord);
        }
    }
}

/// Returns the encrypted size of a plaintext of `plaintext_len` bytes.
#[must_use]
pub const fn encrypted_len(plaintext_len: usize) -> usize {
    let records = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(RECORD_LEN)
    };
    HEADER_LEN + plaintext_len + records * RECORD_OVERHEAD
}

/// Returns the plaintext length an encrypted object of `encrypted_len` bytes holds, or nothing when
/// no plaintext encrypts to that length.
///
/// It is the inverse of [`encrypted_len`], so a size can be bounded from a manifest's stored length
/// before a byte of the object is read.
#[must_use]
pub const fn plaintext_len(encrypted_len: u64) -> Option<u64> {
    let Some(body) = encrypted_len.checked_sub(HEADER_LEN as u64) else {
        return None;
    };
    let records = body / FULL_RECORD_LEN as u64;
    let rest = body % FULL_RECORD_LEN as u64;
    let full = records * RECORD_LEN as u64;
    if records == 0 {
        // An empty object is one empty final record, so even the shortest object has a record.
        return if rest >= RECORD_OVERHEAD as u64 {
            Some(rest - RECORD_OVERHEAD as u64)
        } else {
            None
        };
    }
    if rest == 0 {
        return Some(full);
    }
    // A partial record after full ones holds at least one byte, or the object would have ended at
    // the last full record.
    if rest > RECORD_OVERHEAD as u64 {
        Some(full + rest - RECORD_OVERHEAD as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plaintext_length_of_a_stored_length_is_the_inverse_of_the_stored_length_of_a_plaintext()
    {
        for len in [
            0usize,
            1,
            100,
            RECORD_LEN - 1,
            RECORD_LEN,
            RECORD_LEN + 1,
            2 * RECORD_LEN,
            2 * RECORD_LEN + 7,
            192 << 20,
        ] {
            assert_eq!(
                plaintext_len(encrypted_len(len) as u64),
                Some(len as u64),
                "plaintext of {len} bytes"
            );
        }
        // Lengths no object has: too short for a header and a record, and a partial record that
        // would be empty.
        for stored in [
            0u64,
            HEADER_LEN as u64,
            (HEADER_LEN + RECORD_OVERHEAD - 1) as u64,
            (HEADER_LEN + FULL_RECORD_LEN + RECORD_OVERHEAD) as u64,
        ] {
            assert_eq!(plaintext_len(stored), None, "stored length {stored}");
        }
    }

    #[test]
    fn an_object_round_trips() {
        let key = SymmetricKey::random().expect("a key");
        for len in [0usize, 1, 100, RECORD_LEN - 1, RECORD_LEN, RECORD_LEN + 1] {
            let plaintext: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
            let object = encrypt_object(&key, &plaintext).expect("an object");
            assert_eq!(object.len(), encrypted_len(len), "length for {len} bytes");
            let opened = decrypt_object(&key, &object).expect("the plaintext");
            assert_eq!(opened.expose(), plaintext.as_slice(), "round trip at {len}");
        }
    }

    #[test]
    fn an_object_cut_before_its_final_record_is_rejected() {
        let key = SymmetricKey::random().expect("a key");
        let plaintext = vec![7u8; RECORD_LEN + 10];
        let object = encrypt_object(&key, &plaintext).expect("an object");
        let truncated = &object[..HEADER_LEN + FULL_RECORD_LEN];
        assert!(matches!(
            decrypt_object(&key, truncated),
            Err(CryptoError::MissingFinalRecord)
        ));
    }

    #[test]
    fn bytes_appended_inside_the_last_record_do_not_authenticate() {
        // The last record is short, so appended bytes land inside it and break its tag rather
        // than forming a record of their own.
        let key = SymmetricKey::random().expect("a key");
        let mut object = encrypt_object(&key, b"body").expect("an object");
        object.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            decrypt_object(&key, &object),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn a_record_after_the_final_one_is_rejected() {
        // A plaintext of exactly one record ends on a record boundary, so appended bytes are a
        // record of their own and the reader sees data after the final record.
        let key = SymmetricKey::random().expect("a key");
        let mut object = encrypt_object(&key, &vec![9u8; RECORD_LEN]).expect("an object");
        assert_eq!(object.len(), HEADER_LEN + FULL_RECORD_LEN);
        object.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            decrypt_object(&key, &object),
            Err(CryptoError::RecordsAfterFinal)
        ));
    }

    #[test]
    fn a_tampered_record_does_not_authenticate() {
        let key = SymmetricKey::random().expect("a key");
        let mut object = encrypt_object(&key, b"body").expect("an object");
        let last = object.len() - 1;
        object[last] ^= 0x01;
        assert!(matches!(
            decrypt_object(&key, &object),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn another_key_does_not_open_the_object() {
        let key = SymmetricKey::random().expect("a key");
        let other = SymmetricKey::random().expect("a key");
        let object = encrypt_object(&key, b"body").expect("an object");
        assert!(decrypt_object(&other, &object).is_err());
    }

    #[test]
    fn a_header_alone_is_truncated() {
        let key = SymmetricKey::random().expect("a key");
        let object = encrypt_object(&key, b"body").expect("an object");
        assert!(matches!(
            decrypt_object(&key, &object[..HEADER_LEN]),
            Err(CryptoError::MissingFinalRecord)
        ));
        assert!(matches!(
            decrypt_object(&key, &object[..HEADER_LEN - 1]),
            Err(CryptoError::Truncated { .. })
        ));
    }

    #[test]
    fn two_objects_under_the_same_key_use_two_headers() {
        let key = SymmetricKey::random().expect("a key");
        let first = encrypt_object(&key, b"body").expect("an object");
        let second = encrypt_object(&key, b"body").expect("an object");
        assert_ne!(first[..HEADER_LEN], second[..HEADER_LEN]);
        assert_ne!(first, second);
    }
}
