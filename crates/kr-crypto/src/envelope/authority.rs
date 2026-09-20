//! Authorisation-bearing payloads, and the authority a reader checks them against.
//!
//! Section 20 signs an authorisation-bearing payload before encryption *so pairwise message
//! authentication cannot substitute for an issuer's grant signature*. The box proves that a paired
//! device sealed the item. It proves nothing about authority, because a paired device is
//! authenticated and not trusted, and section 19 makes content data rather than authority.
//!
//! So the payload carries its issuer's own signature, and this module verifies it. Two parts
//! matter, and neither comes from the envelope.
//!
//! **Which key.** The object names the device that issued it and the key identifier that device
//! signed with. [`AuthorityDirectory`] answers which key the *reader* records for that device in
//! that role, and the identifier the object carries must be that key's. A key recorded for one
//! device therefore cannot sign an object that names another, and a key recorded for one role
//! cannot sign for the other: only the target host issues an ordered authority revision, and a
//! reader that resolved by key identifier alone would accept an owner's key in the host's place.
//!
//! **Which grant.** A grant the envelope references must be a grant the reader holds under that
//! same issuer. Naming a grant is not holding one.
//!
//! The seam is the whole of what this crate knows about a reader's authority, and it is
//! deliberately about the reader's own records rather than about any store. A host satisfies it
//! from its paired-device directory and its grant directory together: the directory carries each
//! paired device's authorisation key and whether the pairing still stands, and the grant directory
//! carries which device a grant was issued by. A test satisfies it from a map. Nothing satisfies
//! it from an envelope.
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

use kr_protocol::ids::{DeviceId, GrantId};
use kr_protocol::mailbox::{EnvelopePlaintext, ForwardedAuthority, ForwardedAuthorityKind};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::AuthorisationKey;

use crate::error::{CryptoError, Result};
use crate::keys::key_id;
use crate::sign::{self, SigningTranscript};

/// The authority a reader already holds, which a forwarded object is checked against.
///
/// Two questions, and a reader answers both from its own records without reading anything the
/// envelope carried:
///
/// * which authorisation key it records for a device **in a given issuer role**, and
/// * whether it holds a particular grant under that device's authority.
///
/// A reader that could answer either from the envelope would be letting the sender decide what its
/// own message meant. That is the substitution section 20 forbids.
pub trait AuthorityDirectory {
    /// Returns the authorisation key this reader records for `issuer` as a producer of `kind`.
    ///
    /// `None` for a device it does not know, for one whose pairing no longer stands, and for one
    /// that does not issue objects of that kind. The role is part of the question because the two
    /// kinds have different issuers: any paired owner may publish a revocation request, and only
    /// the target host issues an ordered authority revision. A reader that answered without the
    /// role would let a key it records for one of them sign for the other.
    fn issuer_key(
        &self,
        issuer: DeviceId,
        kind: ForwardedAuthorityKind,
    ) -> Option<AuthorisationKey>;

    /// Returns true when this reader holds `grant_id` under `issuer`'s authority.
    ///
    /// A grant reference on an envelope names the authority the payload acts under. The reference
    /// is checked against what this reader holds rather than accepted as a description of it, so a
    /// sender cannot act under a grant by naming one.
    fn grant_is_held(&self, grant_id: GrantId, issuer: DeviceId) -> bool;
}

/// Verifies the issuer's own signature over an authority-bearing payload.
///
/// This is what a host passes as `verify_payload` to [`super::open_envelope`] and
/// [`super::open_delivered_envelope`]. It performs, in order:
///
/// 1. refuses a payload type that does not bear authority, so an ordinary payload cannot be routed
///    through the authority path and come back as a verified object;
/// 2. decodes the payload as a [`ForwardedAuthority`], which is a closed set of signed objects;
/// 3. resolves the key the reader records for the device the object names, in that object's own
///    issuer role;
/// 4. checks that the key identifier the object carries is that key's, so an object signed by one
///    recorded key cannot name another device or another role and be accepted;
/// 5. verifies the signature over the object's own domain-separated transcript;
/// 6. checks the envelope's grant reference against a grant this reader holds under that issuer.
///
/// It verifies. It applies nothing: whether the revocation or the revision may be acted on is the
/// reader's own decision, made against its current authority after this returns.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the payload type carries no authority, when the
/// key identifier the object names is not the one the reader records for that device and role, or
/// when the envelope references a grant this reader does not hold under that issuer;
/// [`CryptoError::Authentication`] when the reader records no key for that device in that role or
/// the signature does not verify; and a CBOR error when the payload is not one of the signed
/// objects this build reads.
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

    let issuer_device = object.issuer_device_id();
    let issuer = directory
        .issuer_key(issuer_device, object.kind())
        .ok_or(CryptoError::Authentication {
            what: "the issuer of a forwarded authority object, which this reader records no key for",
        })?;
    // The identifier is derived from the key, so an object that named another device, or the same
    // device in the other role, resolves a key whose identifier is not the one it carries. The
    // archive's writer rule is the same one: a writer whose identifier is not its own signing
    // key's is rejected even when it reaches the trusted list.
    if key_id(KeyPurpose::Authorisation, issuer.as_bytes()) != object.issuer_key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the issuer key identifier a forwarded authority object names",
        });
    }

    let transcript =
        SigningTranscript::from_canonical_bytes(object.domain(), object.signing_input()?)?;
    sign::verify(&issuer, &transcript, &object.signature())?;

    if let Some(grant_id) = grant_reference(plaintext)
        && !directory.grant_is_held(grant_id, issuer_device)
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
