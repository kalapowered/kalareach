//! The canonical encoder.
//!
//! `ciborium`, the maintained implementation, writes the bytes. This module is the adaptation
//! layer around it: a [`CanonicalValue`] already satisfies every profile rule and keeps its maps in
//! canonical key order, so converting it to a `ciborium` value and handing that over produces
//! canonical bytes. Nothing here writes a CBOR head by hand.
//!
//! `ciborium` chooses the shortest head for every integer and length and writes definite lengths,
//! which is the rest of RFC 8949 section 4.2.1. The conformance tests check that claim against the
//! fixture bytes rather than assuming it.

use crate::error::{CborError, Result};
use crate::serde_bridge::to_ciborium;
use crate::value::CanonicalValue;

/// Encodes one value as canonical KR-CBOR-1 bytes.
#[must_use]
pub fn encode(value: &CanonicalValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Appends the canonical encoding of `value` to `out`.
///
/// # Panics
///
/// Never in practice. A [`CanonicalValue`] holds only shapes the profile permits, and writing to a
/// `Vec` cannot fail, so `ciborium` has no failure to report.
pub fn encode_into(value: &CanonicalValue, out: &mut Vec<u8>) {
    ciborium::into_writer(&to_ciborium(value), out)
        .expect("a validated canonical value always encodes into a vector");
}

/// Returns how many bytes the canonical encoding of `value` occupies, without producing them.
///
/// The bytes are written to a counter rather than to a buffer, so asking how long a message would
/// be costs no memory proportional to its length. The count comes from the same encoder that
/// writes the bytes, so it is the length the encoding actually has rather than an arithmetic
/// estimate of it.
#[must_use]
pub fn encoded_len(value: &CanonicalValue) -> usize {
    let mut counter = ByteCounter::default();
    ciborium::into_writer(&to_ciborium(value), &mut counter)
        .expect("a validated canonical value always encodes into a counter");
    counter.written
}

/// Encodes `value` only if its canonical encoding is at most `limit` bytes.
///
/// The length is counted first, so a message above the bound is refused before anything the size
/// of its encoding is allocated. A message inside the bound is then written into a buffer of
/// exactly that length, which is also what a caller that holds the result while a write is blocked
/// is charged for.
///
/// # Errors
///
/// Returns [`CborError::InputTooLarge`] with the length the encoding would have had.
pub fn encode_within(value: &CanonicalValue, limit: usize) -> Result<Vec<u8>> {
    let len = encoded_len(value);
    if len > limit {
        return Err(CborError::InputTooLarge { len, limit });
    }
    let mut out = Vec::with_capacity(len);
    encode_into(value, &mut out);
    Ok(out)
}

/// A sink that keeps the length of what was written to it and none of the bytes.
#[derive(Debug, Default)]
struct ByteCounter {
    written: usize,
}

impl std::io::Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written = self.written.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{CanonicalMap, CanonicalValue};

    fn long_text(len: usize) -> CanonicalValue {
        CanonicalValue::Text("k".repeat(len))
    }

    #[test]
    fn the_counted_length_is_the_encoding_s_own_length() {
        let mut map = CanonicalMap::new();
        map.insert(
            "z".to_owned(),
            CanonicalValue::integer(1).expect("in range"),
        )
        .expect("a fresh key");
        map.insert("aa".to_owned(), long_text(300))
            .expect("a fresh key");
        let value = CanonicalValue::Map(map);
        assert_eq!(encoded_len(&value), encode(&value).len());
    }

    #[test]
    fn a_message_inside_its_bound_encodes_to_exactly_its_counted_length() {
        let value = long_text(1_000);
        let bytes = encode_within(&value, 2_000).expect("inside the bound");
        assert_eq!(bytes.len(), encoded_len(&value));
        assert_eq!(bytes, encode(&value));
        // The buffer holds what the counter said it would, so nothing a caller charges itself for
        // is capacity the encoder grew past the message.
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn an_oversized_message_is_refused_with_the_length_it_would_have_had() {
        let value = long_text(4_096);
        let full = encode(&value).len();
        let error = encode_within(&value, 1_024).expect_err("past the bound");
        assert!(matches!(
            error,
            CborError::InputTooLarge { len, limit } if len == full && limit == 1_024
        ));
    }
}
