//! Ed25519 authorisation signatures.
//!
//! Section 23 requires every signature to cover the exact validated encoding under a stated domain
//! and purpose, and forbids signing only parameters or a diagnostic JSON rendering. The functions
//! below take a domain and the elements it separates, build
//! `CBOR([domain, element, ...])` through `kr-cbor`, and sign those bytes. There is no way to sign
//! a bare message with this module, because there is no correct use for one.

use kr_cbor::{CanonicalValue, signing_value};
use kr_protocol::scalars::{AuthorisationKey, Digest256, Signature64};
use serde::Serialize;

use crate::error::{CryptoError, Result};
use crate::keys::AuthorisationKeyPair;
use crate::sodium;

/// Bytes that are known to be a domain-separated canonical transcript.
///
/// There is no way to sign anything else with this module. A `&[u8]` would let a caller sign a
/// fragment of a message or a diagnostic rendering, which section 23 forbids; a value of this type
/// is either built from a domain and its elements or checked against the domain it claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningTranscript(Vec<u8>);

impl SigningTranscript {
    /// Builds `CBOR([domain, element, ...])`.
    #[must_use]
    pub fn from_elements(domain: &str, elements: Vec<CanonicalValue>) -> Self {
        Self(kr_cbor::encode(&signing_value(domain, elements)))
    }

    /// Builds `CBOR([domain, value])` from one serialisable wire object.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the value is outside KR-CBOR-1.
    pub fn from_object<T: Serialize>(domain: &str, value: &T) -> Result<Self> {
        Ok(Self::from_elements(
            domain,
            vec![kr_cbor::to_canonical_value(value)?],
        ))
    }

    /// Accepts bytes another module has already built, after checking that they are a canonical
    /// array whose first element is `domain`.
    ///
    /// The three transcripts the specification writes as arrays, rather than as objects, are built
    /// elsewhere: the pairing context, the direct transcript and the connection transcript. This is
    /// how they reach a signature without a bare-bytes entry point existing.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the bytes are not a domain-separated array,
    /// or when its domain is not `domain`.
    pub fn from_canonical_bytes(domain: &str, bytes: Vec<u8>) -> Result<Self> {
        let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)?;
        let CanonicalValue::Array(items) = &value else {
            return Err(CryptoError::BindingMismatch {
                what: "a signing transcript, which is a domain-separated array",
            });
        };
        if items.first().and_then(CanonicalValue::as_text) != Some(domain) {
            return Err(CryptoError::BindingMismatch {
                what: "the domain of a signing transcript",
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact bytes that are signed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the SHA-256 of those bytes.
    #[must_use]
    pub fn digest(&self) -> Digest256 {
        Digest256::from_bytes(kr_cbor::sha256(&self.0))
    }
}

/// Signs a transcript with a device's authorisation key.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn sign(key: &AuthorisationKeyPair, transcript: &SigningTranscript) -> Result<Signature64> {
    let signature = sodium::sign_detached(transcript.as_bytes(), key.expanded().expose())?;
    Ok(Signature64::from_bytes(signature))
}

/// Verifies a signature over a transcript.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify(
    public: &AuthorisationKey,
    transcript: &SigningTranscript,
    signature: &Signature64,
) -> Result<()> {
    sodium::sign_verify_detached(
        signature.as_bytes(),
        transcript.as_bytes(),
        public.as_bytes(),
    )
}

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
    sign(key, &SigningTranscript::from_elements(domain, elements))
}

/// Verifies a signature over `CBOR([domain, element, ...])`.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_elements(
    public: &AuthorisationKey,
    domain: &str,
    elements: Vec<CanonicalValue>,
    signature: &Signature64,
) -> Result<()> {
    verify(
        public,
        &SigningTranscript::from_elements(domain, elements),
        signature,
    )
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
    sign(key, &SigningTranscript::from_object(domain, value)?)
}

/// Verifies a signature over `CBOR([domain, value])`.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and
/// [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_object<T: Serialize>(
    public: &AuthorisationKey,
    domain: &str,
    value: &T,
    signature: &Signature64,
) -> Result<()> {
    verify(
        public,
        &SigningTranscript::from_object(domain, value)?,
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    /// KR-REQ-23.06: a signature verifies only under the domain it was made in.
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

    /// KR-REQ-23.06: only the exact canonical encoding of a domain-separated array can be signed.
    #[test]
    fn a_transcript_is_checked_against_the_domain_it_claims() {
        let bytes = SigningTranscript::from_elements("kr-test/1", vec![CanonicalValue::text("x")])
            .as_bytes()
            .to_vec();
        assert!(SigningTranscript::from_canonical_bytes("kr-test/1", bytes.clone()).is_ok());
        assert!(matches!(
            SigningTranscript::from_canonical_bytes("kr-test/2", bytes.clone()),
            Err(CryptoError::BindingMismatch {
                what: "the domain of a signing transcript"
            })
        ));

        // The bytes have to be the canonical encoding itself: the same array written with a longer
        // head than necessary is refused, so nothing normalised or re-encoded is ever signed.
        let mut longer = vec![0x98, 0x02];
        longer.extend_from_slice(&bytes[1..]);
        assert!(SigningTranscript::from_canonical_bytes("kr-test/1", longer).is_err());

        // A map is not a domain-separated transcript, so it cannot be signed at all.
        let mut map = kr_cbor::CanonicalMap::new();
        map.insert("a".to_owned(), CanonicalValue::text("b"))
            .expect("a fresh key");
        assert!(matches!(
            SigningTranscript::from_canonical_bytes(
                "kr-test/1",
                kr_cbor::encode(&CanonicalValue::Map(map))
            ),
            Err(CryptoError::BindingMismatch {
                what: "a signing transcript, which is a domain-separated array"
            })
        ));
    }

    /// KR-REQ-23.06: a signature covers every element of what it signs.
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
