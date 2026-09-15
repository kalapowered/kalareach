//! SHA-256 digests and domain-separated signing input.
//!
//! Section 23 requires every signature to cover the exact validated encoding under a stated domain
//! and purpose. [`signing_input`] builds the one shape the specification uses for that:
//! `CBOR([domain, element, ...])`, encoded canonically. Callers never sign a fragment of a message
//! or a re-serialised diagnostic representation.

use sha2::{Digest, Sha256};

use crate::encode::encode;
use crate::error::Result;
use crate::value::CanonicalValue;

/// Length of a SHA-256 digest in bytes.
pub const SHA256_LEN: usize = 32;

/// Returns the SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
}

/// Returns the SHA-256 digest of the canonical encoding of `value`.
#[must_use]
pub fn sha256_of_canonical(value: &CanonicalValue) -> [u8; SHA256_LEN] {
    sha256(&encode(value))
}

/// Builds the canonical signing input `CBOR([domain, element, ...])`.
///
/// # Errors
///
/// Returns an error only when the assembled array breaks a profile rule.
pub fn signing_input(domain: &str, elements: Vec<CanonicalValue>) -> Result<Vec<u8>> {
    Ok(encode(&signing_value(domain, elements)))
}

/// Builds the signing input and returns its SHA-256 digest.
///
/// # Errors
///
/// Returns an error only when the assembled array breaks a profile rule.
pub fn signing_digest(domain: &str, elements: Vec<CanonicalValue>) -> Result<[u8; SHA256_LEN]> {
    Ok(sha256(&signing_input(domain, elements)?))
}

/// Builds the signing input as a value, for callers that embed it in a larger transcript.
#[must_use]
pub fn signing_value(domain: &str, elements: Vec<CanonicalValue>) -> CanonicalValue {
    let mut items = Vec::with_capacity(elements.len() + 1);
    items.push(CanonicalValue::text(domain));
    items.extend(elements);
    CanonicalValue::Array(items)
}
