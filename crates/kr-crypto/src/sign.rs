//! Ed25519 authorisation signatures.
//!
//! Section 23 requires every signature to cover the exact validated encoding under a stated domain
//! and purpose, and forbids signing only parameters or a diagnostic JSON rendering. The functions
//! below take a domain and the elements it separates, build
//! `CBOR([domain, element, ...])` through `kr-cbor`, and sign those bytes. There is no way to sign
//! a bare message with this module, because there is no correct use for one.

use kr_cbor::{CanonicalValue, signing_value};
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use serde::Serialize;

use crate::error::Result;
use crate::keys::AuthorisationKeyPair;
use crate::sodium;

/// Signs `CBOR([domain, element, ...])` with a device's authorisation key.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn sign_elements(
    key: &AuthorisationKeyPair,
    domain: &str,
    elements: Vec<CanonicalValue>,
) -> Result<Signature64> {
    let message = kr_cbor::encode(&signing_value(domain, elements));
    sign_bytes(key, &message)
}

/// Verifies a signature over `CBOR([domain, element, ...])`.
///
/// # Errors
///
/// Returns [`crate::CryptoError::Authentication`] when the signature does not verify.
pub fn verify_elements(
    public: &AuthorisationKey,
    domain: &str,
    elements: Vec<CanonicalValue>,
    signature: &Signature64,
) -> Result<()> {
    let message = kr_cbor::encode(&signing_value(domain, elements));
    verify_bytes(public, &message, signature)
}

/// Signs `CBOR([domain, value])` where `value` is one serialisable wire object.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and a library error when
/// libsodium fails.
pub fn sign_object<T: Serialize>(
    key: &AuthorisationKeyPair,
    domain: &str,
    value: &T,
) -> Result<Signature64> {
    sign_elements(key, domain, vec![kr_cbor::to_canonical_value(value)?])
}

/// Verifies a signature over `CBOR([domain, value])`.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and
/// [`crate::CryptoError::Authentication`] when the signature does not verify.
pub fn verify_object<T: Serialize>(
    public: &AuthorisationKey,
    domain: &str,
    value: &T,
    signature: &Signature64,
) -> Result<()> {
    verify_elements(
        public,
        domain,
        vec![kr_cbor::to_canonical_value(value)?],
        signature,
    )
}

/// Signs exact bytes that a caller has already built as a domain-separated transcript.
///
/// Callers inside this workspace use it for the three transcripts the specification writes as
/// arrays: the pairing context, the direct transcript and the connection transcript.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn sign_bytes(key: &AuthorisationKeyPair, message: &[u8]) -> Result<Signature64> {
    let signature = sodium::sign_detached(message, key.expanded().expose())?;
    Ok(Signature64::from_bytes(signature))
}

/// Verifies a signature over exact bytes.
///
/// # Errors
///
/// Returns [`crate::CryptoError::Authentication`] when the signature does not verify.
pub fn verify_bytes(
    public: &AuthorisationKey,
    message: &[u8],
    signature: &Signature64,
) -> Result<()> {
    sodium::sign_verify_detached(signature.as_bytes(), message, public.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    #[test]
    fn a_signature_verifies_under_its_own_domain_only() {
        let key = AuthorisationKeyPair::generate().expect("a keypair");
        let elements = || vec![CanonicalValue::text("payload")];
        let signature = sign_elements(&key, "kr-test/1", elements()).expect("a signature");
        assert!(verify_elements(key.public(), "kr-test/1", elements(), &signature).is_ok());
        assert!(matches!(
            verify_elements(key.public(), "kr-test/2", elements(), &signature),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn another_key_does_not_verify() {
        let key = AuthorisationKeyPair::generate().expect("a keypair");
        let other = AuthorisationKeyPair::generate().expect("a keypair");
        let signature =
            sign_elements(&key, "kr-test/1", vec![CanonicalValue::text("x")]).expect("a signature");
        assert!(
            verify_elements(
                other.public(),
                "kr-test/1",
                vec![CanonicalValue::text("x")],
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn a_changed_element_does_not_verify() {
        let key = AuthorisationKeyPair::generate().expect("a keypair");
        let signature =
            sign_elements(&key, "kr-test/1", vec![CanonicalValue::text("x")]).expect("a signature");
        assert!(
            verify_elements(
                key.public(),
                "kr-test/1",
                vec![CanonicalValue::text("y")],
                &signature
            )
            .is_err()
        );
    }
}
