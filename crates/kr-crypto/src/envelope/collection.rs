//! Collection keys: sealing one to a member, opening it, signing a record and the rules between two.
//!
//! [`kr_protocol::collection_keys`] holds the shapes and the rules that need no key. This module is
//! the half that needs one:
//!
//! * [`wrap_collection_key`] seals the epoch's key for one member with `crypto_box_easy` from the
//!   issuer's stored-envelope key, under a fresh random nonce, with the collection, the epoch and
//!   both key identifiers authenticated inside the box: the rule section 20 gives every key wrap.
//! * [`open_collection_key`] opens one against a sender key the caller chose from its own paired
//!   records. Nothing here takes a sender key from a record: section 20 opens only against
//!   previously paired sender keys.
//! * [`issue_collection_key_record`] wraps the key for every member, the issuer included, and signs
//!   the record. There is no way to issue a record whose wraps have another sender or whose issuer
//!   is not a member.
//! * [`verify_collection_key_record`], [`check_genesis`] and [`check_successor`] are the rules one
//!   record and two consecutive records keep, which a member and the service both apply.
//! * [`CollectionMembers`] is the member set. It is an [`ArchiveRecipients`] of a mutable shared
//!   collection with each member's authorisation key beside it, so removing members advances the
//!   epoch once and says, as every revocation does, that it takes nothing back.

use kr_protocol::collection_keys::{
    COLLECTION_KEY_LEN, COLLECTION_KEY_RECORD_DOMAIN, CollectionKeyRecord,
    CollectionKeyRecordError, CollectionKeyRecordPayload, CollectionKeyWrapContext,
    CollectionKeyWrapFormat, CollectionMember, SealedCollectionKeyWrap,
    collection_key_wrap_plaintext, collection_key_wrap_prefix,
};
use kr_protocol::ids::{InstallationId, SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, Digest256, KeyId, Nullable, StoredEnvelopeKey, TimestampMs,
};

use crate::backup::{ArchiveRecipients, CollectionKind, KeyRotation, Revocation};
use crate::error::{CryptoError, Result};
use crate::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair, key_id};
use crate::secret::{Secret, SecretVec, SymmetricKey};
use crate::{sealed, sign, sodium};

/// Seals one collection key for one member.
///
/// The context names the two keys actually used, which is checked here, so a wrap cannot claim a
/// sender or a recipient other than the ones that sealed and can open it.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the context does not name the two keys used, and a
/// library error when libsodium fails.
pub fn wrap_collection_key(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKey,
    context: CollectionKeyWrapContext,
    key: &SymmetricKey,
) -> Result<SealedCollectionKeyWrap> {
    if context.sender_key_id != sender.key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the sender key identifier in a collection key wrap",
        });
    }
    if context.recipient_key_id != key_id(KeyPurpose::StoredEnvelope, recipient.as_bytes()) {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient key identifier in a collection key wrap",
        });
    }
    let mut plaintext = collection_key_wrap_plaintext(&context, key.expose())?;
    let sealed_result = sealed::seal_stored_envelope(sender, recipient, &plaintext);
    sodium::memzero(&mut plaintext);
    let (nonce, ciphertext) = sealed_result?;
    Ok(SealedCollectionKeyWrap {
        context,
        nonce,
        ciphertext: Bytes::new(ciphertext),
    })
}

/// Opens one collection key wrap, checking it against the context the caller expects.
///
/// `sender` is the issuer's stored-envelope key as the caller's own paired records hold it. The
/// expected context comes from the record the caller is reading, so a wrap moved to another
/// collection, epoch or recipient fails before its key is used. Nothing is stored here.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the expected context does not name the two keys in
/// use or is not the wrap's own, and [`CryptoError::Authentication`] when the wrap does not open.
pub fn open_collection_key(
    recipient: &StoredEnvelopeKeyPair,
    sender: &StoredEnvelopeKey,
    wrap: &SealedCollectionKeyWrap,
    expected: &CollectionKeyWrapContext,
) -> Result<SymmetricKey> {
    // `crypto_box` derives one shared secret from either direction, so a wrap sealed from A to B
    // also opens from B to A. Checking both parties against the expected context is what stops a
    // recipient opening a wrap addressed to its sender and taking the key as its own.
    if expected.recipient_key_id != recipient.key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient of a collection key wrap, which is not the key opening it",
        });
    }
    if expected.sender_key_id != key_id(KeyPurpose::StoredEnvelope, sender.as_bytes()) {
        return Err(CryptoError::BindingMismatch {
            what: "the sender of a collection key wrap, which is not the key it is opened against",
        });
    }
    if &wrap.context != expected {
        return Err(CryptoError::BindingMismatch {
            what: "the context of a collection key wrap",
        });
    }
    let opened =
        sealed::open_stored_envelope(recipient, sender, &wrap.nonce, wrap.ciphertext.as_slice())?;
    read_wrapped_key(&opened, expected)
}

/// Reads the key out of an opened wrap by comparing the prefix the expected context produces.
///
/// Decoding the plaintext would put the key into a value tree nobody can clear; comparing the
/// rebuilt prefix is both the shape check and the context check, and the key is what remains.
fn read_wrapped_key(
    opened: &SecretVec,
    expected: &CollectionKeyWrapContext,
) -> Result<SymmetricKey> {
    let prefix = collection_key_wrap_prefix(expected)?;
    let bytes = opened.expose();
    if bytes.len() != prefix.len() + COLLECTION_KEY_LEN {
        return Err(CryptoError::BindingMismatch {
            what: "the length of a collection key wrap plaintext",
        });
    }
    if !sodium::constant_time_eq(&bytes[..prefix.len()], &prefix) {
        return Err(CryptoError::BindingMismatch {
            what: "the context inside a collection key wrap",
        });
    }
    Secret::from_slice("a collection key", &bytes[prefix.len()..])
}

/// One member a record will name, before its wrap exists: the two public keys that identify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectionRecipient {
    /// The member's authorisation key.
    pub authorisation: AuthorisationKey,
    /// The member's stored-envelope key, which its wrap is sealed to.
    pub stored_envelope: StoredEnvelopeKey,
}

impl CollectionRecipient {
    /// Returns the identifier of the member's stored-envelope key.
    #[must_use]
    pub fn stored_envelope_key_id(&self) -> KeyId {
        key_id(KeyPurpose::StoredEnvelope, self.stored_envelope.as_bytes())
    }

    /// Returns the member a record names, without its wrap.
    #[must_use]
    pub const fn of(member: &CollectionMember) -> Self {
        Self {
            authorisation: member.authorisation,
            stored_envelope: member.stored_envelope,
        }
    }
}

/// What an issuer states in one record, apart from the wraps and the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionRecordDraft {
    /// The collection.
    pub collection_id: SyncCollectionId,
    /// The installation whose namespace the collection lives in.
    pub home: InstallationId,
    /// The epoch of the key the record carries.
    pub key_epoch: SyncKeyEpoch,
    /// The record's revision.
    pub revision: SyncKeyRecordRevision,
    /// The digest of the record this one follows, or nothing for the first.
    pub previous: Option<Digest256>,
    /// When the issuer signs it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// Every member, the issuer included.
    pub members: Vec<CollectionRecipient>,
}

/// Wraps the epoch's key for every member and signs the record.
///
/// The issuer's two key pairs are what seal and sign, and the issuer must be one of the members the
/// draft names, so every record has one sender for all its wraps and names its own issuer.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the issuer is not among the members or the record
/// breaks one of its structure rules, and a library or encoding error when a wrap or the signature
/// fails.
pub fn issue_collection_key_record(
    issuer: &AuthorisationKeyPair,
    issuer_envelope: &StoredEnvelopeKeyPair,
    draft: &CollectionRecordDraft,
    key: &SymmetricKey,
) -> Result<CollectionKeyRecord> {
    let listed = draft.members.iter().any(|member| {
        member.authorisation == *issuer.public()
            && member.stored_envelope == *issuer_envelope.public()
    });
    if !listed {
        return Err(CryptoError::BindingMismatch {
            what: "the issuer of a key record, which is not among its members",
        });
    }

    let mut members = Vec::with_capacity(draft.members.len());
    for member in &draft.members {
        let context = CollectionKeyWrapContext {
            format: CollectionKeyWrapFormat::V1,
            collection_id: draft.collection_id,
            key_epoch: draft.key_epoch,
            sender_key_id: issuer_envelope.key_id(),
            recipient_key_id: member.stored_envelope_key_id(),
        };
        members.push(CollectionMember {
            authorisation: member.authorisation,
            stored_envelope: member.stored_envelope,
            wrap: wrap_collection_key(issuer_envelope, &member.stored_envelope, context, key)?,
        });
    }

    let payload = CollectionKeyRecordPayload {
        collection_id: draft.collection_id,
        home: draft.home,
        key_epoch: draft.key_epoch,
        revision: draft.revision,
        previous: draft.previous.map_or_else(Nullable::null, Nullable::some),
        issuer_key_id: issuer.key_id(),
        issued_at_ms: draft.issued_at_ms,
        members,
    };
    let signature = sign::sign_object(issuer, COLLECTION_KEY_RECORD_DOMAIN, &payload)?;
    let record = CollectionKeyRecord { payload, signature };
    record.check_structure().map_err(structure_fault)?;
    Ok(record)
}

/// Verifies one record's shape and its issuer's signature under the key the caller holds for it.
///
/// `issuer` is the authorisation key the caller trusts for the record's issuer: a reader's own
/// paired records, the member list of the record before this one, or, at the service, the key that
/// carried the request. The record's issuer identifier must be that key's.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the record breaks a structure rule or names another
/// issuer key, and [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_collection_key_record(
    record: &CollectionKeyRecord,
    issuer: &AuthorisationKey,
) -> Result<()> {
    record.check_structure().map_err(structure_fault)?;
    if key_id(KeyPurpose::Authorisation, issuer.as_bytes()) != record.payload.issuer_key_id {
        return Err(CryptoError::BindingMismatch {
            what: "the issuer key identifier a key record names",
        });
    }
    sign::verify_object(
        issuer,
        COLLECTION_KEY_RECORD_DOMAIN,
        &record.payload,
        &record.signature,
    )
}

/// Checks the record that creates a collection.
///
/// Only the home claims a collection: the first record is revision one at the first epoch, follows
/// nothing, names exactly one member, its issuer, and that member's authorisation key derives the
/// home installation. It is signed by that key.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] for the first rule the record breaks and
/// [`CryptoError::Authentication`] when its signature does not verify.
pub fn check_genesis(record: &CollectionKeyRecord) -> Result<()> {
    record.check_structure().map_err(structure_fault)?;
    let payload = &record.payload;
    let issuer = record.issuer().ok_or(CryptoError::BindingMismatch {
        what: "the issuer of a key record, which is not among its members",
    })?;
    if payload.revision.get() != 1 || payload.previous.is_present() {
        return Err(CryptoError::BindingMismatch {
            what: "the revision of a first key record, which is one and follows nothing",
        });
    }
    if payload.key_epoch.get() != KeyRotation::INITIAL.get() {
        return Err(CryptoError::BindingMismatch {
            what: "the epoch of a first key record, which is the first epoch",
        });
    }
    if payload.members.len() != 1 {
        return Err(CryptoError::BindingMismatch {
            what: "the members of a first key record, which is its issuer alone",
        });
    }
    if issuer.installation_id() != payload.home {
        return Err(CryptoError::BindingMismatch {
            what: "the home of a first key record, which is its issuer's own installation",
        });
    }
    verify_collection_key_record(record, &issuer.authorisation)
}

/// Checks that `next` may follow `previous`.
///
/// The same collection and home; the next revision; the previous record's digest; an issuer that
/// was a member of the previous record with the same two keys, whose key the signature verifies
/// under; an epoch that stays or moves on by one; and at an unchanged epoch, every member of the
/// previous record still named with the same two keys, so a removal cannot be stored without a new
/// epoch. Whether the new epoch's key is fresh is the issuer's to ensure, and nothing that reads a
/// record can see it.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] for the first rule the pair breaks and
/// [`CryptoError::Authentication`] when the signature does not verify.
pub fn check_successor(previous: &CollectionKeyRecord, next: &CollectionKeyRecord) -> Result<()> {
    previous.check_structure().map_err(structure_fault)?;
    next.check_structure().map_err(structure_fault)?;
    let (before, after) = (&previous.payload, &next.payload);
    if after.collection_id != before.collection_id || after.home != before.home {
        return Err(CryptoError::BindingMismatch {
            what: "the collection a key record belongs to, which is the previous record's",
        });
    }
    // Checked rather than saturating: the last revision a counter can hold has no successor, and
    // two records at that one value would be two answers to one place in the order.
    if before.revision.get().checked_add(1) != Some(after.revision.get()) {
        return Err(CryptoError::BindingMismatch {
            what: "the revision of a key record, which is the one after the previous record's",
        });
    }
    if after.previous.as_ref() != Some(&previous.digest()?) {
        return Err(CryptoError::BindingMismatch {
            what: "the previous record a key record names",
        });
    }
    let epoch = after.key_epoch.get();
    let before_epoch = before.key_epoch.get();
    if epoch != before_epoch && before_epoch.checked_add(1) != Some(epoch) {
        return Err(CryptoError::BindingMismatch {
            what: "the epoch of a key record, which stays or moves on by one",
        });
    }

    // The issuer must have been a member already, with the keys it had then: a device the previous
    // record did not name cannot state who the members are now.
    let issuer_before = previous
        .member_by_authorisation_key_id(&after.issuer_key_id)
        .ok_or(CryptoError::BindingMismatch {
            what: "the issuer of a key record, which was not a member of the previous record",
        })?;
    let issuer_after = next.issuer().ok_or(CryptoError::BindingMismatch {
        what: "the issuer of a key record, which is not among its members",
    })?;
    if issuer_after.stored_envelope != issuer_before.stored_envelope {
        return Err(CryptoError::BindingMismatch {
            what: "the issuer's stored-envelope key, which is the one the previous record named",
        });
    }

    if epoch == before_epoch {
        let everyone_kept = before.members.iter().all(|member| {
            next.member(&member.authorisation)
                .is_some_and(|kept| kept.stored_envelope == member.stored_envelope)
        });
        if !everyone_kept {
            return Err(CryptoError::BindingMismatch {
                what: "the members of a key record at an unchanged epoch, which only adds to the previous record's",
            });
        }
    }

    verify_collection_key_record(next, &issuer_before.authorisation)
}

/// Says which structure rule a record broke, as the error this crate returns.
fn structure_fault(error: CollectionKeyRecordError) -> CryptoError {
    let what = match error {
        CollectionKeyRecordError::Unencodable => {
            "a key record, which the canonical encoding cannot hold"
        }
        CollectionKeyRecordError::TooLarge { .. } => "the size of a key record",
        CollectionKeyRecordError::NoMembers => "the members of a key record, which names none",
        CollectionKeyRecordError::TooManyMembers { .. } => {
            "the members of a key record, which names more than a collection may have"
        }
        CollectionKeyRecordError::RevisionZero => "the revision of a key record, which is zero",
        CollectionKeyRecordError::PreviousMismatch => {
            "the previous record a key record names, against its revision"
        }
        CollectionKeyRecordError::DuplicateKey => "a key a record names twice",
        CollectionKeyRecordError::IssuerNotListed => {
            "the issuer of a key record, which is not among its members"
        }
        CollectionKeyRecordError::WrapMismatch { .. } => {
            "a wrap that does not match its member and its record"
        }
    };
    CryptoError::BindingMismatch { what }
}

/// The members of one synchronised collection, and the epoch their key is at.
///
/// The set is an [`ArchiveRecipients`] of a [`CollectionKind::MutableShared`] collection, whose
/// rotation is the epoch, with each member's authorisation key kept beside its stored-envelope key.
/// Adding a member keeps the epoch; removing members advances it once and reports a
/// [`Revocation`], which claims no retroactive secrecy.
#[derive(Clone, Debug)]
pub struct CollectionMembers {
    recipients: ArchiveRecipients,
    members: Vec<CollectionRecipient>,
}

impl CollectionMembers {
    /// Builds the empty set of a collection that does not exist yet, at the first epoch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recipients: ArchiveRecipients::new(CollectionKind::MutableShared),
            members: Vec::new(),
        }
    }

    /// Builds the set one record names, at its epoch.
    #[must_use]
    pub fn of_record(record: &CollectionKeyRecord) -> Self {
        let mut set = Self {
            recipients: ArchiveRecipients::restored(
                CollectionKind::MutableShared,
                KeyRotation::new(record.payload.key_epoch.get()),
            ),
            members: Vec::with_capacity(record.payload.members.len()),
        };
        for member in &record.payload.members {
            set.add(CollectionRecipient::of(member));
        }
        set
    }

    /// Adds one member at the current epoch. Returns false when either of its keys is already a
    /// member's.
    pub fn add(&mut self, member: CollectionRecipient) -> bool {
        let known = self.members.iter().any(|held| {
            held.authorisation == member.authorisation
                || held.stored_envelope == member.stored_envelope
        });
        if known || !self.recipients.add(member.stored_envelope) {
            return false;
        }
        self.members.push(member);
        true
    }

    /// Removes members, named by their stored-envelope key identifiers, in one step.
    ///
    /// The epoch advances once however many leave, because one new key replaces the one they all
    /// held. Returns `None` when the set names none of them.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RotationExhausted`] at the last epoch, removing nobody.
    pub fn revoke(&mut self, stored_envelope_key_ids: &[KeyId]) -> Result<Option<Revocation>> {
        let Some(revocation) = self.recipients.revoke(stored_envelope_key_ids)? else {
            return Ok(None);
        };
        self.members.retain(|member| {
            !revocation
                .removed
                .contains(&member.stored_envelope_key_id())
        });
        Ok(Some(revocation))
    }

    /// Returns the epoch the members' key is at.
    #[must_use]
    pub const fn key_epoch(&self) -> SyncKeyEpoch {
        SyncKeyEpoch::new(self.recipients.rotation().get())
    }

    /// Returns every member, in the order they joined the set.
    #[must_use]
    pub fn members(&self) -> &[CollectionRecipient] {
        &self.members
    }

    /// Returns true when a member has this stored-envelope key identifier.
    #[must_use]
    pub fn contains(&self, stored_envelope_key_id: &KeyId) -> bool {
        self.recipients.contains(stored_envelope_key_id)
    }

    /// Returns the draft of the record that follows `previous` with these members at this epoch.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when `previous` is at the last revision a record can
    /// have, and an encoding error when it cannot be digested.
    pub fn successor_draft(
        &self,
        previous: &CollectionKeyRecord,
        issued_at_ms: TimestampMs,
    ) -> Result<CollectionRecordDraft> {
        let revision =
            previous
                .payload
                .revision
                .get()
                .checked_add(1)
                .ok_or(CryptoError::BindingMismatch {
                    what: "the revision after the last one a key record can have",
                })?;
        Ok(CollectionRecordDraft {
            collection_id: previous.payload.collection_id,
            home: previous.payload.home,
            key_epoch: self.key_epoch(),
            revision: SyncKeyRecordRevision::new(revision),
            previous: Some(previous.digest()?),
            issued_at_ms,
            members: self.members.clone(),
        })
    }
}

impl Default for CollectionMembers {
    fn default() -> Self {
        Self::new()
    }
}
