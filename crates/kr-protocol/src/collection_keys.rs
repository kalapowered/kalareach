//! The key record of a synchronised collection: who holds its key, and at which epoch (section 20).
//!
//! A synchronised collection is sealed under one symmetric key per epoch, and the service that
//! stores it holds no key at all. The devices that may read and write it are its members, and this
//! module is the record that says who they are: one signed statement per revision, naming every
//! member by its two public keys and carrying the epoch's key wrapped for each of them.
//!
//! # What is fixed here, and what is not
//!
//! The shapes, their limits and the rules a reader can check without a key, which is
//! [`CollectionKeyRecord::check_structure`]. The cryptography is `kr-crypto`'s: sealing a wrap,
//! opening one, signing a record and the rules between two revisions of one record.
//!
//! # Why a record carries both an epoch and a revision
//!
//! The revision counts records: every accepted record is the next one. The epoch counts keys: it
//! moves on only when the key changes, and a removal always changes it, because a device removed
//! from the collection must not hold the key the remaining members write with next. An addition
//! keeps the epoch, and the new member's wrap carries the key already in use.
//!
//! # Why a wrap has one sender
//!
//! The issuer of a revision wraps the epoch's key for every member it names, itself included. A
//! reader therefore opens its own wrap against the issuer's stored-envelope key, which it looks up
//! from its own paired records rather than taking from the record, and every wrap in one record is
//! checked against the same sender.

use kr_cbor::CborError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{InstallationId, SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision};
use crate::pairing::{KeyPurpose, key_id};
use crate::scalars::{
    AuthorisationKey, Bytes, Digest256, KeyId, Nonce192, Nullable, Signature64, StoredEnvelopeKey,
    TimestampMs,
};
use crate::service::installation_id;

/// The domain a key record's signature covers.
pub const COLLECTION_KEY_RECORD_DOMAIN: &str = "kr-collection-keys/1";

/// The most members one collection's record may name.
pub const MAX_COLLECTION_MEMBERS: usize = 64;

/// The most bytes one record may occupy, in its canonical encoding.
pub const MAX_COLLECTION_KEY_RECORD_LEN: usize = 64 * 1024;

/// Bytes in a collection key.
pub const COLLECTION_KEY_LEN: usize = 32;

/// Bytes `crypto_box_easy` adds to the plaintext it seals.
const BOX_OVERHEAD_BYTES: usize = 16;

/// The collection-key wrap format this build writes and reads.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub enum CollectionKeyWrapFormat {
    /// Version 1.
    #[serde(rename = "kr-collection-key-wrap/1")]
    V1,
}

/// The fields a collection-key wrap authenticates, apart from the key itself.
///
/// A wrap is valid for one collection, one epoch and one recipient. A reader that finds it in
/// another record, at another epoch or addressed to another key fails to authenticate it rather
/// than obtaining a key it was not given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionKeyWrapContext {
    /// The wrap format.
    pub format: CollectionKeyWrapFormat,
    /// The collection the key seals.
    pub collection_id: SyncCollectionId,
    /// The epoch the key belongs to.
    pub key_epoch: SyncKeyEpoch,
    /// The issuer's stored-envelope key.
    pub sender_key_id: KeyId,
    /// The member's stored-envelope key.
    pub recipient_key_id: KeyId,
}

/// Builds everything in a wrap plaintext up to, but not including, the key itself.
///
/// The plaintext is `CBOR([context, key])`, assembled by hand rather than through a value tree for
/// the reason the backup key wrap gives: a tree would hold a copy of the key no caller can reach and
/// therefore none can clear. The bytes are `0x82` (a two-element array), the canonical context, then
/// `0x58 0x20` (a 32-byte string head). An opener rebuilds this prefix from the context it expects
/// and compares it with the opened plaintext, which is both the shape check and the context check.
///
/// # Errors
///
/// Returns a CBOR error when the context is outside KR-CBOR-1.
pub fn collection_key_wrap_prefix(
    context: &CollectionKeyWrapContext,
) -> Result<Vec<u8>, CborError> {
    let encoded_context = kr_cbor::to_canonical_vec(context)?;
    let mut prefix = Vec::with_capacity(encoded_context.len() + 3 + COLLECTION_KEY_LEN);
    prefix.push(0x82);
    prefix.extend_from_slice(&encoded_context);
    prefix.push(0x58);
    prefix.push(0x20);
    Ok(prefix)
}

/// Builds the authenticated plaintext of one wrap: `CBOR([context, key])`.
///
/// The returned buffer holds the key in the clear. Its caller seals it and clears it; nothing else
/// may hold on to it.
///
/// # Errors
///
/// Returns a CBOR error when the context is outside KR-CBOR-1.
pub fn collection_key_wrap_plaintext(
    context: &CollectionKeyWrapContext,
    key: &[u8; COLLECTION_KEY_LEN],
) -> Result<Vec<u8>, CborError> {
    let mut plaintext = collection_key_wrap_prefix(context)?;
    plaintext.extend_from_slice(key.as_slice());
    Ok(plaintext)
}

/// One collection key wrapped for one member.
///
/// Every wrap uses a fresh random 24-byte nonce from libsodium's generator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedCollectionKeyWrap {
    /// The fields the wrap authenticates.
    pub context: CollectionKeyWrapContext,
    /// The fresh 24-byte nonce.
    pub nonce: Nonce192,
    /// The `crypto_box_easy` output over the canonical wrap plaintext.
    pub ciphertext: Bytes,
}

/// One member of a synchronised collection, and the epoch's key wrapped for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionMember {
    /// The member's Ed25519 authorisation key, which is also the key its service requests are
    /// signed with and from which its installation identifier derives.
    pub authorisation: AuthorisationKey,
    /// The member's X25519 stored-envelope key, which its wrap is sealed to.
    pub stored_envelope: StoredEnvelopeKey,
    /// The epoch's key, wrapped for this member by the record's issuer.
    pub wrap: SealedCollectionKeyWrap,
}

impl CollectionMember {
    /// Returns the identifier of the member's authorisation key.
    #[must_use]
    pub fn authorisation_key_id(&self) -> KeyId {
        key_id(KeyPurpose::Authorisation, self.authorisation.as_bytes())
    }

    /// Returns the identifier of the member's stored-envelope key.
    #[must_use]
    pub fn stored_envelope_key_id(&self) -> KeyId {
        key_id(KeyPurpose::StoredEnvelope, self.stored_envelope.as_bytes())
    }

    /// Returns the installation identifier the member's authorisation key derives.
    ///
    /// It is what a service admits a signed request by, so a service reads membership from the
    /// keys the record names rather than from an identifier a caller could claim.
    #[must_use]
    pub fn installation_id(&self) -> InstallationId {
        installation_id(&self.authorisation)
    }
}

/// What the issuer of one revision states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionKeyRecordPayload {
    /// The collection.
    pub collection_id: SyncCollectionId,
    /// The installation whose namespace the collection lives in: the one that created it.
    pub home: InstallationId,
    /// The epoch of the key the wraps carry.
    pub key_epoch: SyncKeyEpoch,
    /// This record's place in the collection's sequence of records. The first is one.
    pub revision: SyncKeyRecordRevision,
    /// The SHA-256 of the canonical encoding of the record this one follows, or null for the
    /// first.
    pub previous: Nullable<Digest256>,
    /// The identifier of the authorisation key the issuer signed with.
    pub issuer_key_id: KeyId,
    /// When the issuer signed it, in UTC milliseconds. It is shown to a person and decides nothing.
    pub issued_at_ms: TimestampMs,
    /// Every member, each with its wrap of the epoch's key.
    pub members: Vec<CollectionMember>,
}

impl CollectionKeyRecordPayload {
    /// Builds the canonical bytes the issuer's signature covers:
    /// `CBOR(["kr-collection-keys/1", payload])`.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            COLLECTION_KEY_RECORD_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// One revision of a collection's membership, signed by the member that issued it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionKeyRecord {
    /// What the issuer states.
    pub payload: CollectionKeyRecordPayload,
    /// The issuer's Ed25519 signature over [`CollectionKeyRecordPayload::signing_input`].
    pub signature: Signature64,
}

/// Why a record is not one this contract admits, before any key is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CollectionKeyRecordError {
    /// The record cannot be written in KR-CBOR-1.
    #[error("the record cannot be written in the canonical encoding")]
    Unencodable,
    /// The record is larger than a record may be.
    #[error("a key record is at most {limit} bytes; this one is {len}")]
    TooLarge {
        /// The canonical length.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The record names no member.
    #[error("a key record names at least one member")]
    NoMembers,
    /// The record names more members than one collection may have.
    #[error("a key record names at most {limit} members; this one names {count}")]
    TooManyMembers {
        /// How many it names.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// The revision is zero, which no record has.
    #[error("the first key record is revision 1")]
    RevisionZero,
    /// The first revision names a record before it, or a later one names none.
    #[error("revision 1 follows no record, and every later revision follows exactly one")]
    PreviousMismatch,
    /// A key appears twice: two members share one, or one member declares one key for both
    /// purposes.
    #[error("every key in a record belongs to one member and one purpose")]
    DuplicateKey,
    /// The issuer is not one of the members the record names.
    #[error("the issuer of a key record is one of its members")]
    IssuerNotListed,
    /// A wrap does not match the member and the record it is in.
    #[error(
        "the wrap of member {position} does not name this collection, this epoch, the issuer and that member, or is not one wrapped key long"
    )]
    WrapMismatch {
        /// The member's position in the record.
        position: usize,
    },
}

impl CollectionKeyRecord {
    /// Returns the SHA-256 of this record's canonical encoding, which is what the next record
    /// names as the one it follows.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the record cannot be represented in KR-CBOR-1.
    pub fn digest(&self) -> Result<Digest256, CborError> {
        Ok(Digest256::from_bytes(kr_cbor::sha256(
            &kr_cbor::to_canonical_vec(self)?,
        )))
    }

    /// Returns the member whose authorisation key the issuer signed with, when the record names
    /// one.
    #[must_use]
    pub fn issuer(&self) -> Option<&CollectionMember> {
        self.member_by_authorisation_key_id(&self.payload.issuer_key_id)
    }

    /// Returns the member whose authorisation key has this identifier.
    #[must_use]
    pub fn member_by_authorisation_key_id(&self, key_id: &KeyId) -> Option<&CollectionMember> {
        self.payload
            .members
            .iter()
            .find(|member| &member.authorisation_key_id() == key_id)
    }

    /// Returns the member with this authorisation key.
    #[must_use]
    pub fn member(&self, authorisation: &AuthorisationKey) -> Option<&CollectionMember> {
        self.payload
            .members
            .iter()
            .find(|member| &member.authorisation == authorisation)
    }

    /// Returns true when an installation is one of the members, which is what a service admits by.
    #[must_use]
    pub fn admits(&self, installation: &InstallationId) -> bool {
        self.payload
            .members
            .iter()
            .any(|member| &member.installation_id() == installation)
    }

    /// Checks everything about this record that needs no key.
    ///
    /// The record fits its limits, names at least one member and at most
    /// [`MAX_COLLECTION_MEMBERS`], counts its revisions from one with a previous record named
    /// exactly when there is one, gives every key to one member and one purpose, names its issuer
    /// among its members, and carries for each member a wrap whose context names this collection,
    /// this epoch, the issuer's stored-envelope key as sender and that member's as recipient, and
    /// whose ciphertext is one wrapped key long.
    ///
    /// # Errors
    ///
    /// Returns the first rule the record breaks.
    pub fn check_structure(&self) -> Result<(), CollectionKeyRecordError> {
        let len = kr_cbor::to_canonical_vec(self)
            .map_err(|_| CollectionKeyRecordError::Unencodable)?
            .len();
        if len > MAX_COLLECTION_KEY_RECORD_LEN {
            return Err(CollectionKeyRecordError::TooLarge {
                len,
                limit: MAX_COLLECTION_KEY_RECORD_LEN,
            });
        }
        let payload = &self.payload;
        if payload.members.is_empty() {
            return Err(CollectionKeyRecordError::NoMembers);
        }
        if payload.members.len() > MAX_COLLECTION_MEMBERS {
            return Err(CollectionKeyRecordError::TooManyMembers {
                count: payload.members.len(),
                limit: MAX_COLLECTION_MEMBERS,
            });
        }
        match payload.revision.get() {
            0 => return Err(CollectionKeyRecordError::RevisionZero),
            1 if payload.previous.is_present() => {
                return Err(CollectionKeyRecordError::PreviousMismatch);
            }
            1 => {}
            _ if !payload.previous.is_present() => {
                return Err(CollectionKeyRecordError::PreviousMismatch);
            }
            _ => {}
        }

        // Every 32-byte key once, whatever its purpose: two members sharing a key would be one
        // device named twice, and one member declaring one key for both purposes would be a key
        // reused across purposes, which section 10 forbids.
        let mut keys: Vec<&[u8; 32]> = Vec::with_capacity(payload.members.len() * 2);
        for member in &payload.members {
            for key in [
                member.authorisation.as_bytes(),
                member.stored_envelope.as_bytes(),
            ] {
                if keys.contains(&key) {
                    return Err(CollectionKeyRecordError::DuplicateKey);
                }
                keys.push(key);
            }
        }

        let issuer = self
            .issuer()
            .ok_or(CollectionKeyRecordError::IssuerNotListed)?;
        let sender_key_id = issuer.stored_envelope_key_id();
        for (position, member) in payload.members.iter().enumerate() {
            let expected = CollectionKeyWrapContext {
                format: CollectionKeyWrapFormat::V1,
                collection_id: payload.collection_id,
                key_epoch: payload.key_epoch,
                sender_key_id,
                recipient_key_id: member.stored_envelope_key_id(),
            };
            let wrapped_len = collection_key_wrap_prefix(&expected)
                .map_err(|_| CollectionKeyRecordError::Unencodable)?
                .len()
                + COLLECTION_KEY_LEN
                + BOX_OVERHEAD_BYTES;
            if member.wrap.context != expected
                || member.wrap.ciphertext.as_slice().len() != wrapped_len
            {
                return Err(CollectionKeyRecordError::WrapMismatch { position });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    fn member(seed: u8, issuer_envelope: &StoredEnvelopeKey) -> CollectionMember {
        let stored_envelope = StoredEnvelopeKey::from_bytes([seed.wrapping_add(1); 32]);
        let context = CollectionKeyWrapContext {
            format: CollectionKeyWrapFormat::V1,
            collection_id: SyncCollectionId::new(Uuid::from_bytes([7; 16])),
            key_epoch: SyncKeyEpoch::new(0),
            sender_key_id: key_id(KeyPurpose::StoredEnvelope, issuer_envelope.as_bytes()),
            recipient_key_id: key_id(KeyPurpose::StoredEnvelope, stored_envelope.as_bytes()),
        };
        let len = collection_key_wrap_prefix(&context)
            .expect("a prefix")
            .len()
            + COLLECTION_KEY_LEN
            + BOX_OVERHEAD_BYTES;
        CollectionMember {
            authorisation: AuthorisationKey::from_bytes([seed; 32]),
            stored_envelope,
            wrap: SealedCollectionKeyWrap {
                context,
                nonce: Nonce192::from_bytes([9; 24]),
                ciphertext: Bytes::new(vec![0; len]),
            },
        }
    }

    fn record() -> CollectionKeyRecord {
        let issuer_envelope = StoredEnvelopeKey::from_bytes([0x11; 32]);
        let issuer = member(0x10, &issuer_envelope);
        let other = member(0x20, &issuer_envelope);
        CollectionKeyRecord {
            payload: CollectionKeyRecordPayload {
                collection_id: SyncCollectionId::new(Uuid::from_bytes([7; 16])),
                home: issuer.installation_id(),
                key_epoch: SyncKeyEpoch::new(0),
                revision: SyncKeyRecordRevision::new(2),
                previous: Nullable::some(Digest256::from_bytes([3; 32])),
                issuer_key_id: issuer.authorisation_key_id(),
                issued_at_ms: TimestampMs::new(1),
                members: vec![issuer, other],
            },
            signature: Signature64::from_bytes([0; 64]),
        }
    }

    #[test]
    fn a_record_whose_shape_is_the_one_the_rules_produce_is_admitted() {
        assert_eq!(record().check_structure(), Ok(()));
    }

    #[test]
    fn a_record_names_its_issuer_among_its_members() {
        let mut record = record();
        record.payload.issuer_key_id = KeyId::from_bytes([0x55; 32]);
        assert_eq!(
            record.check_structure(),
            Err(CollectionKeyRecordError::IssuerNotListed)
        );
    }

    #[test]
    fn the_first_revision_follows_nothing_and_every_later_one_follows_a_record() {
        let mut first = record();
        first.payload.revision = SyncKeyRecordRevision::new(1);
        assert_eq!(
            first.check_structure(),
            Err(CollectionKeyRecordError::PreviousMismatch)
        );
        first.payload.previous = Nullable::null();
        assert_eq!(first.check_structure(), Ok(()));

        let mut later = record();
        later.payload.previous = Nullable::null();
        assert_eq!(
            later.check_structure(),
            Err(CollectionKeyRecordError::PreviousMismatch)
        );

        let mut zero = record();
        zero.payload.revision = SyncKeyRecordRevision::new(0);
        assert_eq!(
            zero.check_structure(),
            Err(CollectionKeyRecordError::RevisionZero)
        );
    }

    #[test]
    fn a_key_belongs_to_one_member_and_one_purpose() {
        let mut shared = record();
        shared.payload.members[1].stored_envelope = shared.payload.members[0].stored_envelope;
        assert_eq!(
            shared.check_structure(),
            Err(CollectionKeyRecordError::DuplicateKey)
        );

        let mut reused = record();
        let key = *reused.payload.members[1].authorisation.as_bytes();
        reused.payload.members[1].stored_envelope = StoredEnvelopeKey::from_bytes(key);
        assert_eq!(
            reused.check_structure(),
            Err(CollectionKeyRecordError::DuplicateKey)
        );
    }

    #[test]
    fn a_wrap_names_this_collection_this_epoch_the_issuer_and_its_member() {
        let mut moved = record();
        moved.payload.key_epoch = SyncKeyEpoch::new(1);
        assert_eq!(
            moved.check_structure(),
            Err(CollectionKeyRecordError::WrapMismatch { position: 0 })
        );

        let mut swapped = record();
        let first = swapped.payload.members[0].wrap.clone();
        swapped.payload.members[1].wrap = first;
        assert_eq!(
            swapped.check_structure(),
            Err(CollectionKeyRecordError::WrapMismatch { position: 1 })
        );

        let mut short = record();
        short.payload.members[1].wrap.ciphertext = Bytes::new(vec![0; 16]);
        assert_eq!(
            short.check_structure(),
            Err(CollectionKeyRecordError::WrapMismatch { position: 1 })
        );
    }

    #[test]
    fn a_record_names_between_one_and_the_limit_of_members() {
        let mut empty = record();
        empty.payload.members.clear();
        assert_eq!(
            empty.check_structure(),
            Err(CollectionKeyRecordError::NoMembers)
        );

        let mut crowded = record();
        let issuer_envelope = crowded.payload.members[0].stored_envelope;
        crowded.payload.members.truncate(1);
        for seed in 0..MAX_COLLECTION_MEMBERS {
            crowded.payload.members.push(member(
                0x40 + 2 * u8::try_from(seed).expect("small"),
                &issuer_envelope,
            ));
        }
        assert!(matches!(
            crowded.check_structure(),
            Err(CollectionKeyRecordError::TooManyMembers { count, limit: MAX_COLLECTION_MEMBERS })
                if count == MAX_COLLECTION_MEMBERS + 1
        ));
    }

    #[test]
    fn a_service_admits_the_installations_the_members_keys_derive_and_no_other() {
        let record = record();
        for member in &record.payload.members {
            assert!(record.admits(&member.installation_id()));
        }
        assert!(!record.admits(&installation_id(&AuthorisationKey::from_bytes([0x77; 32]))));
    }

    #[test]
    fn the_signature_covers_the_payload_under_its_own_domain() {
        let record = record();
        let input = record.payload.signing_input().expect("an input");
        let expected = kr_cbor::encode(&kr_cbor::signing_value(
            COLLECTION_KEY_RECORD_DOMAIN,
            vec![kr_cbor::to_canonical_value(&record.payload).expect("a value")],
        ));
        assert_eq!(input, expected);
    }
}
