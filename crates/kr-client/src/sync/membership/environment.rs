//! Everything the reconciler reads, writes and asks, behind one seam.
//!
//! [`Environment`] is what a reconciler needs beyond its own facts: this device's keys and the
//! checks that need them, the key store, the membership file, the key-record service and the
//! hosts. [`DeviceEnvironment`] is a device's own, over signed records and the stores a device
//! keeps. The exhaustive test supplies another, over records small enough to enumerate, so the
//! reconciler it explores is this one, row for row and write for write.

use std::sync::Arc;

use kr_crypto::envelope::{
    CollectionRecipient, CollectionRecordDraft, check_genesis, check_successor,
    issue_collection_key_record, open_collection_key, verify_collection_key_record,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_protocol::collection_keys::{
    CollectionKeyRecord, CollectionKeyWrapContext, CollectionKeyWrapFormat,
};
use kr_protocol::ids::{SyncKeyEpoch, SyncKeyRecordRevision};
use kr_protocol::scalars::{AuthorisationKey, Digest256, TimestampMs, Uuid};

use super::facts::{Facts, Kinds};
use super::file::{FileLock, MembershipFile};
use super::{
    CollectionRef, Device, DeviceDirectory, KeyRecordService, KeyRecords, MembershipError,
    RecordAt, RecordedAnswers, RekeyAnswer, RekeyFence, RekeyStatus,
};
use crate::services::ServiceFuture;
use crate::sync::keys::StoredCollectionKeys;

/// The member type of an environment's kinds.
pub(crate) type MemberOf<E> = <<E as Environment>::Kinds as Kinds>::Member;
/// The record type of an environment's kinds.
pub(crate) type RecordOf<E> = <<E as Environment>::Kinds as Kinds>::Record;
/// The mark type of an environment's kinds.
pub(crate) type MarkOf<E> = <<E as Environment>::Kinds as Kinds>::Mark;
/// The answers type of an environment's kinds.
pub(crate) type AnswersOf<E> = <<E as Environment>::Kinds as Kinds>::Answers;

/// What the reconciler runs against.
pub(crate) trait Environment: Send + Sync {
    /// The shapes it works over.
    type Kinds: Kinds;
    /// A collection key.
    type Key: Send + Sync;
    /// The hold on the membership file one operation keeps.
    type Guard;

    /// This device, as the records name it.
    fn me(&self) -> MemberOf<Self>;

    /// Takes the membership file's lock for one operation.
    ///
    /// # Errors
    ///
    /// When the lock cannot be taken.
    fn lock(&self) -> Result<Self::Guard, MembershipError>;
    /// Reads the membership file, or nothing when there is none.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or decoded.
    fn load(&self) -> Result<Option<Facts<Self::Kinds>>, MembershipError>;
    /// Replaces the membership file whole, durably.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    fn replace(&self, facts: &Facts<Self::Kinds>) -> Result<(), MembershipError>;

    /// Check 2 for one link: `next` follows `previous`.
    fn follows(&self, previous: &RecordOf<Self>, next: &RecordOf<Self>) -> bool;
    /// The first record's rules, for this collection.
    fn first(&self, collection: &CollectionRef, record: &RecordOf<Self>) -> bool;
    /// Check 1, the issuer's signature under the key its record names, and this device's own
    /// wrap opened against the issuer's stored-envelope key: the mark of the key it holds, or
    /// nothing when the record does not list this device or its wrap does not open.
    fn mark_of(&self, record: &RecordOf<Self>) -> Option<MarkOf<Self>>;
    /// Opens this device's own wrap in an accepted record, for row 4 to store.
    ///
    /// # Errors
    ///
    /// When the record does not list this device or its wrap does not open.
    fn open_key(&self, record: &RecordOf<Self>) -> Result<Self::Key, MembershipError>;
    /// The mark of a key.
    fn mark(&self, key: &Self::Key) -> MarkOf<Self>;
    /// Draws a fresh key for a new epoch.
    ///
    /// # Errors
    ///
    /// When the random generator is unavailable.
    fn draw_key(
        &self,
        epoch: u64,
        base: u64,
        members: &[MemberOf<Self>],
    ) -> Result<Self::Key, MembershipError>;
    /// Wraps a key for every member and signs the record that follows `base`.
    ///
    /// # Errors
    ///
    /// When a wrap or the signature fails, or the record breaks a structure rule.
    fn issue(
        &self,
        collection: &CollectionRef,
        base: Option<&RecordOf<Self>>,
        epoch: u64,
        members: &[MemberOf<Self>],
        key: &Self::Key,
        now: TimestampMs,
    ) -> Result<RecordOf<Self>, MembershipError>;

    /// The key the store holds for one epoch, or nothing.
    ///
    /// # Errors
    ///
    /// When the store cannot be read.
    fn held_key(
        &self,
        collection: &CollectionRef,
        epoch: u64,
    ) -> Result<Option<Self::Key>, MembershipError>;
    /// Stores one epoch's key.
    ///
    /// # Errors
    ///
    /// When the store rejects the write.
    fn store_key(
        &self,
        collection: &CollectionRef,
        epoch: u64,
        key: &Self::Key,
    ) -> Result<(), MembershipError>;
    /// Forgets one epoch's key. Forgetting one that is not held succeeds.
    ///
    /// # Errors
    ///
    /// When the store rejects the deletion.
    fn forget_key(&self, collection: &CollectionRef, epoch: u64) -> Result<(), MembershipError>;

    /// A fresh request identity.
    ///
    /// # Errors
    ///
    /// When the random generator is unavailable.
    fn fresh_request(&self) -> Result<Uuid, MembershipError>;

    /// The records after a revision, in order.
    fn records_after<'a>(
        &'a self,
        collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords<RecordOf<Self>>>;
    /// The record at one revision.
    fn record_at<'a>(
        &'a self,
        collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt<RecordOf<Self>>>;
    /// Sends one candidate, once.
    fn rekey<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
        signed_at: TimestampMs,
        record: &'a RecordOf<Self>,
    ) -> ServiceFuture<'a, RekeyAnswer>;
    /// What the service recorded about one `rekey`.
    fn rekey_status<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus>;
    /// Ends one `rekey`, and says what became of it.
    fn rekey_fence<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
        first_signed_at: TimestampMs,
        last_signed_at: TimestampMs,
    ) -> ServiceFuture<'a, RekeyFence>;
    /// Check 3's answers from every host, or nothing when no host answers.
    fn answers(&self) -> ServiceFuture<'_, Option<AnswersOf<Self>>>;
}

/// The kinds a device works over: signed key records, and devices named by their two keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DeviceKinds;

impl Kinds for DeviceKinds {
    type Member = Device;
    type Record = CollectionKeyRecord;
    type Mark = Digest256;
    type Answers = RecordedAnswers;
    type Revocation = AuthorisationKey;

    fn revision(record: &CollectionKeyRecord) -> u64 {
        record.payload.revision.get()
    }

    fn epoch(record: &CollectionKeyRecord) -> u64 {
        record.payload.key_epoch.get()
    }

    fn issuer(record: &CollectionKeyRecord) -> Option<Device> {
        record.issuer().map(Device::of)
    }

    fn members(record: &CollectionKeyRecord) -> Vec<Device> {
        record.payload.members.iter().map(Device::of).collect()
    }

    fn lists(record: &CollectionKeyRecord, member: &Device) -> bool {
        record
            .member(&member.authorisation)
            .is_some_and(|entry| entry.stored_envelope == member.stored_envelope)
    }

    fn passes(answers: &RecordedAnswers, member: &Device) -> bool {
        answers.passes(member)
    }

    fn revoke(answers: &mut RecordedAnswers, revocation: AuthorisationKey) {
        answers.verified.insert(revocation);
    }

    fn refreshed(previous: &RecordedAnswers, fresh: RecordedAnswers) -> RecordedAnswers {
        let mut verified = previous.verified.clone();
        verified.extend(fresh.verified);
        RecordedAnswers {
            hosts: fresh.hosts,
            verified,
        }
    }
}

/// The domain a key's mark is computed under.
const MARK_DOMAIN: &[u8] = b"kr-collection-key-mark/1";

/// A device's own environment.
pub(crate) struct DeviceEnvironment {
    /// This device's authorisation key pair: it signs the records this device issues.
    pub(crate) authorisation: AuthorisationKeyPair,
    /// This device's stored-envelope key pair: its wraps are sealed to it and from it.
    pub(crate) envelope: StoredEnvelopeKeyPair,
    /// Where the collection keys are kept.
    pub(crate) keys: StoredCollectionKeys,
    /// The membership file.
    pub(crate) file: MembershipFile,
    /// The key-record service.
    pub(crate) service: Arc<dyn KeyRecordService>,
    /// This device's hosts.
    pub(crate) hosts: Arc<dyn DeviceDirectory>,
}

impl std::fmt::Debug for DeviceEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceEnvironment")
            .field("keys", &self.keys)
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

impl DeviceEnvironment {
    /// The name a collection's keys are kept under.
    fn key_name(collection: &CollectionRef) -> String {
        collection.collection_id.to_string()
    }

    /// This device's own entry in a record, and the issuer's.
    fn entries<'r>(
        &self,
        record: &'r CollectionKeyRecord,
    ) -> Option<(
        &'r kr_protocol::collection_keys::CollectionMember,
        &'r kr_protocol::collection_keys::CollectionMember,
    )> {
        let own = record.member(self.authorisation.public())?;
        if own.stored_envelope != *self.envelope.public() {
            return None;
        }
        Some((own, record.issuer()?))
    }
}

impl Environment for DeviceEnvironment {
    type Kinds = DeviceKinds;
    type Key = SymmetricKey;
    type Guard = FileLock;

    fn me(&self) -> Device {
        Device {
            authorisation: *self.authorisation.public(),
            stored_envelope: *self.envelope.public(),
        }
    }

    fn lock(&self) -> Result<FileLock, MembershipError> {
        self.file.lock()
    }

    fn load(&self) -> Result<Option<Facts<DeviceKinds>>, MembershipError> {
        self.file.load()
    }

    fn replace(&self, facts: &Facts<DeviceKinds>) -> Result<(), MembershipError> {
        self.file.replace(facts)
    }

    fn follows(&self, previous: &CollectionKeyRecord, next: &CollectionKeyRecord) -> bool {
        check_successor(previous, next).is_ok()
    }

    fn first(&self, collection: &CollectionRef, record: &CollectionKeyRecord) -> bool {
        record.payload.home == collection.home
            && record.payload.collection_id == collection.collection_id
            && check_genesis(record).is_ok()
    }

    fn mark_of(&self, record: &CollectionKeyRecord) -> Option<Digest256> {
        let (_, issuer) = self.entries(record)?;
        verify_collection_key_record(record, &issuer.authorisation).ok()?;
        let key = self.open_key(record).ok()?;
        Some(self.mark(&key))
    }

    fn open_key(&self, record: &CollectionKeyRecord) -> Result<SymmetricKey, MembershipError> {
        let (own, issuer) = self.entries(record).ok_or(MembershipError::NotListed)?;
        // The issuer's stored-envelope key is the one its record names. A record reaches this
        // point only after check 3 found the issuer at a host with that same key, so it is the
        // key the directory reports, never one taken from a record alone.
        let context = CollectionKeyWrapContext {
            format: CollectionKeyWrapFormat::V1,
            collection_id: record.payload.collection_id,
            key_epoch: record.payload.key_epoch,
            sender_key_id: issuer.stored_envelope_key_id(),
            recipient_key_id: self.envelope.key_id(),
        };
        Ok(open_collection_key(
            &self.envelope,
            &issuer.stored_envelope,
            &own.wrap,
            &context,
        )?)
    }

    fn mark(&self, key: &SymmetricKey) -> Digest256 {
        let mut input = crate::sync::Zeroising(Vec::with_capacity(MARK_DOMAIN.len() + 32));
        input.0.extend_from_slice(MARK_DOMAIN);
        input.0.extend_from_slice(key.expose());
        Digest256::from_bytes(kr_cbor::sha256(&input.0))
    }

    fn draw_key(
        &self,
        _epoch: u64,
        _base: u64,
        _members: &[Device],
    ) -> Result<SymmetricKey, MembershipError> {
        Ok(Secret::random()?)
    }

    fn issue(
        &self,
        collection: &CollectionRef,
        base: Option<&CollectionKeyRecord>,
        epoch: u64,
        members: &[Device],
        key: &SymmetricKey,
        now: TimestampMs,
    ) -> Result<CollectionKeyRecord, MembershipError> {
        let (revision, previous) = match base {
            Some(base) => (
                base.payload.revision.get().saturating_add(1),
                Some(base.digest()?),
            ),
            None => (1, None),
        };
        let draft = CollectionRecordDraft {
            collection_id: collection.collection_id,
            home: collection.home,
            key_epoch: SyncKeyEpoch::new(epoch),
            revision: SyncKeyRecordRevision::new(revision),
            previous,
            issued_at_ms: now,
            members: members
                .iter()
                .map(|member| CollectionRecipient {
                    authorisation: member.authorisation,
                    stored_envelope: member.stored_envelope,
                })
                .collect(),
        };
        Ok(issue_collection_key_record(
            &self.authorisation,
            &self.envelope,
            &draft,
            key,
        )?)
    }

    fn held_key(
        &self,
        collection: &CollectionRef,
        epoch: u64,
    ) -> Result<Option<SymmetricKey>, MembershipError> {
        self.keys
            .held(&Self::key_name(collection), epoch)
            .map_err(MembershipError::Keys)
    }

    fn store_key(
        &self,
        collection: &CollectionRef,
        epoch: u64,
        key: &SymmetricKey,
    ) -> Result<(), MembershipError> {
        self.keys
            .put(&Self::key_name(collection), epoch, key)
            .map_err(MembershipError::Keys)
    }

    fn forget_key(&self, collection: &CollectionRef, epoch: u64) -> Result<(), MembershipError> {
        self.keys
            .forget(&Self::key_name(collection), epoch)
            .map_err(MembershipError::Keys)
    }

    fn fresh_request(&self) -> Result<Uuid, MembershipError> {
        kr_transport::random::fresh_uuid_v4()
            .map_err(|error| MembershipError::Service(error.into()))
    }

    fn records_after<'a>(
        &'a self,
        collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords<CollectionKeyRecord>> {
        self.service.records_after(collection, after)
    }

    fn record_at<'a>(
        &'a self,
        collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt<CollectionKeyRecord>> {
        self.service.record_at(collection, revision)
    }

    fn rekey<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
        signed_at: TimestampMs,
        record: &'a CollectionKeyRecord,
    ) -> ServiceFuture<'a, RekeyAnswer> {
        self.service
            .rekey(collection, request, signed_at.get(), record)
    }

    fn rekey_status<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus> {
        self.service.rekey_status(collection, request)
    }

    fn rekey_fence<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request: Uuid,
        first_signed_at: TimestampMs,
        last_signed_at: TimestampMs,
    ) -> ServiceFuture<'a, RekeyFence> {
        self.service.rekey_fence(
            collection,
            request,
            first_signed_at.get(),
            last_signed_at.get(),
        )
    }

    fn answers(&self) -> ServiceFuture<'_, Option<RecordedAnswers>> {
        Box::pin(async move {
            Ok(self.hosts.answers().await?.map(|hosts| RecordedAnswers {
                hosts,
                verified: std::collections::BTreeSet::new(),
            }))
        })
    }
}
