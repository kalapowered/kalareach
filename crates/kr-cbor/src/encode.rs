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
