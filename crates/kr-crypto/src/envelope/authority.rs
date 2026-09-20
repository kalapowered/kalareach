//! Authorisation-bearing payloads, and the authority a reader checks them against.
//!
//! Section 20 signs an authorisation-bearing payload before encryption *so pairwise message
//! authentication cannot substitute for an issuer's grant signature*. The box proves that a paired
//! device sealed the item. It proves nothing about authority, because a paired device is
//! authenticated and not trusted, and section 19 makes content data rather than authority.
//!
//! So the payload carries its issuer's own signature, and this module verifies it. The part that
//! matters is where the verifying key comes from: **not from the envelope**. The object names an
//! issuer key identifier; [`AuthorityDirectory`] is the seam a reader's own authority answers
//! through, and a name it does not answer for is refused. A grant the envelope references is
//! checked the same way: it must be a grant this host holds, under that issuer, rather than one
//! the envelope asserts.
//!
//! The seam is the whole of what this crate knows about a host's authority. `kr-controller`'s
//! grants service satisfies it from its durable store; a test satisfies it from a map; nothing
//! satisfies it from an envelope.
//!
//! ```no_run
//! # use kr_crypto::envelope::{AuthorityDirectory, PairedSenders, ReplayLedger,
//! #     open_delivered_envelope, verify_authority_payload};
//! # use kr_crypto::keys::StoredEnvelopeKeyPair;
//! # use kr_protocol::mailbox::{ForwardedAuthority, SealedEnvelope};
//! # fn example(
//! #     me: &StoredEnvelopeKeyPair,
//! #     senders: &PairedSenders,
//! #     ledger: &mut ReplayLedger,
//! #     item: &SealedEnvelope,
//! #     directory: &dyn AuthorityDirectory,
//! #     now_ms: u64,
//! # ) -> kr_crypto::Result<()> {
//! let mut verified: Option<ForwardedAuthority> = None;
//! let plaintext = open_delivered_envelope(me, senders, ledger, item, now_ms, |payload| {
//!     verified = Some(verify_authority_payload(directory, payload)?);
//!     Ok(())
//! })?;
//! // `verified` is set for an authority-bearing payload and `None` for any other kind, because
//! // nothing else reaches the check.
//! # let _ = (plaintext, verified);
//! # Ok(())
//! # }
//! ```

use kr_protocol::ids::GrantId;
use kr_protocol::mailbox::{EnvelopePlaintext, ForwardedAuthority};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{AuthorisationKey, KeyId};

use crate::error::{CryptoError, Result};
use crate::keys::key_id;
use crate::sign::{self, SigningTranscript};

/// The authority a reader already holds, which a forwarded object is checked against.
///
/// Two questions, and a host can answer both from its own records without reading anything the
/// envelope carried:
///
/// * which authorisation key it has recorded under an identifier, and
/// * whether it holds a particular grant, issued under that key.
///
/// A reader that could answer either from the envelope would be letting the sender decide what its
/// own message meant. That is the substitution section 20 forbids.
pub trait AuthorityDirectory {
    /// Returns the authorisation key this reader has recorded under `issuer_key_id`.
    ///
    /// `None` for a key it does not hold, and for one it has revoked: an issuer whose authority
    /// has been withdrawn is an issuer this reader cannot check, which is the same answer.
    fn issuer_key(&self, issuer_key_id: KeyId) -> Option<AuthorisationKey>;

    /// Returns true when this reader holds `grant_id` and it was issued under `issuer_key_id`.
    ///
    /// A grant reference on an envelope names the authority the payload acts under. The reference
    /// is checked against what this host holds rather than accepted as a description of it, so a
    /// sender cannot act under a grant by naming one.
    fn grant_is_held(&self, grant_id: GrantId, issuer_key_id: KeyId) -> bool;
}

/// Verifies the issuer's own signature over an authority-bearing payload.
///
/// This is what a host passes as `verify_payload` to [`super::open_envelope`] and
/// [`super::open_delivered_envelope`]. It performs, in order:
///
/// 1. refuses a payload type that does not bear authority, so an ordinary payload cannot be routed
///    through the authority path and come back as a verified object;
/// 2. decodes the payload as a [`ForwardedAuthority`], which is a closed set of signed objects;
/// 3. resolves the issuer's key identifier through the reader's own [`AuthorityDirectory`];
/// 4. checks that the resolved key is the key that identifier names, so a directory that answered
///    with the wrong key cannot make a signature verify;
/// 5. verifies the signature over the object's own domain-separated transcript;
/// 6. checks the envelope's grant reference against a grant this reader holds under that issuer.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the payload type carries no authority, when the
/// directory answers with a key that is not the one the identifier names, or when the envelope
/// references a grant this reader does not hold under that issuer; [`CryptoError::Authentication`]
/// when the reader holds no key for the issuer or the signature does not verify; and a CBOR error
/// when the payload is not one of the signed objects this build reads.
pub fn verify_authority_payload(
    directory: &dyn AuthorityDirectory,
    plaintext: &EnvelopePlaintext,
) -> Result<ForwardedAuthority> {
    if !plaintext.payload_type.bears_authority() {
        return Err(CryptoError::BindingMismatch {
            what: "the payload type of an object checked as authority, which carries none",
        });
    }

    let object: ForwardedAuthority =
        kr_cbor::from_canonical_slice(plaintext.payload.as_slice(), &kr_cbor::Limits::DEFAULT)?;

    let issuer_key_id = object.issuer_key_id();
    let issuer = directory
        .issuer_key(issuer_key_id)
        .ok_or(CryptoError::Authentication {
            what: "the issuer of a forwarded authority object, which this reader holds no key for",
        })?;
    // The identifier is derived from the key, so a directory that answered with another key is
    // caught here rather than by a signature that happens to verify under it. The archive's writer
    // rule is the same one: a writer whose identifier is not its own signing key's is rejected even
    // when it reaches the trusted list.
    if key_id(KeyPurpose::Authorisation, issuer.as_bytes()) != issuer_key_id {
        return Err(CryptoError::BindingMismatch {
            what: "the issuer key an authority directory answered with",
        });
    }

    let transcript =
        SigningTranscript::from_canonical_bytes(object.domain(), object.signing_input()?)?;
    sign::verify(&issuer, &transcript, &object.signature())?;

    if let Some(grant_id) = grant_reference(plaintext)
        && !directory.grant_is_held(grant_id, issuer_key_id)
    {
        return Err(CryptoError::BindingMismatch {
            what: "the grant an envelope references, which this reader does not hold",
        });
    }

    Ok(object)
}

/// Returns the grant an envelope references, when it references one.
const fn grant_reference(plaintext: &EnvelopePlaintext) -> Option<GrantId> {
    match plaintext.grant_id.as_ref() {
        Some(grant_id) => Some(*grant_id),
        None => None,
    }
}
