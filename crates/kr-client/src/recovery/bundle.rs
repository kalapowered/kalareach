//! The recovery bundle at its stable locator: reading it, committing it, and moving it.
//!
//! The bundle is the only thing a restore trusts a writer key from. Everything about how it is
//! written follows from that:
//!
//! * **Committed before the writer is declared.** [`BundleStore::enable_writer`] writes the bundle
//!   and only then returns [`WriterEnabled`], which is what a caller needs to declare a writer
//!   recovery-enabled. There is no other way to build one.
//! * **Compare-and-swap at the locator.** Two devices that both enrol a writer do not lose one
//!   another's enrolment silently: the loser is told the bundle moved on and reads again.
//! * **Bound to where it is stored.** The encryption key mixes the seed with the origin and the
//!   locator, so a bundle copied to another location does not authenticate there. A migration is
//!   therefore a deliberate act with its own record, not a copy.
//!
//! # The bundle is key material, and it settles itself
//!
//! Section 20 ¶11 says what a bundle holds: collection locators, trusted backup-writer signing
//! public keys and generation checkpoints. None of that is session content, so the bundle is not
//! one of section 24's content-bearing outboxes: enabling privacy mode does not fence it, does not
//! cancel a write of it and does not delete it, because a deleted bundle is a restore that cannot
//! verify an archive the owner still holds. It follows that a bundle write needs none of the
//! request accounting the settings-sync outbox keeps, which exists for content under a privacy
//! generation and keeps the content it sends. This is a direct, synchronous consumer of
//! [`SyncBackupService`], and the two paths share the service and nothing else.
//!
//! What a direct consumer still owes is an answer for a write it never heard back about. Every
//! write carries a fresh identity and the instant the call was made, nothing is retried on its own,
//! and a lost answer is reported as an unknown outcome ([`LostWrite`]). The store keeps a record of
//! the last write it sent, and the record holds what settling that write takes and nothing more:
//! the place it compared against, the identity and the instant it went out under, and the digest
//! of the encrypted bundle it sent. It is on this device's disk before the write leaves, so a
//! process that ends with the write unanswered leaves it for the next store to take up; it never
//! holds the bundle, its ciphertext or a key. Two things settle it:
//!
//! * **A read that recognises the write.** When the bytes at the locator are the very bytes this
//!   device sent, whose digest says so, that write applied and cannot apply again, because a
//!   service answers a repeated identity from the receipt it already holds. The bytes and not the
//!   bundle inside them: every encryption starts from a fresh random header, so another write of
//!   the same bundle, even one made at the same instant, is other bytes.
//! * **Ending the request.** A read that finds another bundle has established what is there and
//!   not that a request still on its way cannot land afterwards, so it settles nothing. Only the
//!   service can end that possibility, and [`BundleStore::end_lost_write`] asks it to: the
//!   identity is fenced, so nothing executes under it from that moment.
//!
//! Until one of the two happens the store writes nothing further, which is what keeps this device
//! from ever meeting its own earlier write and being told another device wrote.

use std::path::Path;
use std::sync::Arc;

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{
    ArchiveCheckpoint, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryContext,
    RecoveryKit, TrustedProducer, TrustedWriter,
};
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{
    Bytes, Digest256, KeyId, Nullable, StoredEnvelopeKey, TimestampMs, U64,
};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::recovery::record::{RecordFile, WriteRecord};
use crate::recovery::{RecoveryError, Result};
use crate::services::{SyncBackupService, SyncExchanged, SyncPosition, SyncRequestFence};

/// Returns the collection name one bundle is stored under.
///
/// It is the locator itself. The locator is opaque and stable, which is the whole point of it:
/// bundle updates go to the same name for the life of the kit, so enabling a new writer never
/// means reprinting the seed.
#[must_use]
pub fn bundle_collection(context: &RecoveryContext) -> &str {
    &context.bundle_locator
}

/// What became of a bundle write whose answer never arrived.
///
/// A write that is answered settles itself: the service either applied it or refused the
/// comparison. One that is not answered leaves a question, and this is the store's record of that
/// question and of what became of it. It is not a retry: nothing here sends anything again, and
/// the caller decides what to do with the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LostWrite {
    /// The answer never arrived and nothing has ended the request.
    ///
    /// This device sent a bundle and does not know whether the service applied it, so the store
    /// will not write again while this stands. Reading is not enough on its own: a read says what
    /// is at the locator now, and a request still on its way can land after it, so a second write
    /// made on the strength of that read could be refused by this device's own earlier write and
    /// reported as somebody else's conflict. [`BundleStore::end_lost_write`] is what ends it.
    Unsettled {
        /// The digest of the encrypted bundle this device sent, as the service would store it.
        sent: Digest256,
    },
    /// The write applied: a read found the very bytes this device sent, or the service said so
    /// when the request was ended.
    Applied,
    /// The request is over: nothing executes under its identity from now on, and the service did
    /// not record that it applied.
    ///
    /// Whether it ever ran may or may not be established, and it decides nothing further: what is
    /// at the locator is what a restore will use, and a read makes that this store's baseline.
    Ended {
        /// The copy the service kept of the write, when it refused it and kept one.
        retained: Option<SyncConflictId>,
    },
}

/// The last write this store sent, and what became of it where no answer arrived.
///
/// One value for the write and its fate, so the store cannot hold the record of one write and a
/// settled report about another.
#[derive(Clone, Debug)]
struct LastWrite {
    record: WriteRecord,
    /// [`None`] when the service answered the write, which leaves no question to settle.
    lost: Option<LostWrite>,
}

/// Where this store last saw the bundle, and the bundle it authenticated there.
///
/// The place and the content together or neither. A place without the content read there could
/// not tell a second reading of that place from a fork, and content without its place gives a write
/// nothing to compare against.
#[derive(Clone, Debug)]
pub(super) struct Baseline {
    position: SyncPosition,
    pub(super) bundle: RecoveryBundle,
    /// The digest of the encrypted bundle as it was read or written there, which a record of a
    /// write is compared against.
    sealed: Digest256,
}

/// The owner's bundle at one service, and where this device last saw it.
///
/// One store writes one bundle from this device at a time. It keeps the record of its last write
/// on this device's disk and holds a lock beside it while it is open, so a second store for the
/// same bundle is refused rather than left to pass its own guard on a write the first one has
/// outstanding.
pub struct BundleStore {
    service: Arc<dyn SyncBackupService>,
    context: RecoveryContext,
    /// Where this store last saw the bundle, and the bundle it authenticated there.
    ///
    /// A caller holding a bundle it read earlier holds a snapshot, and writing that snapshot back
    /// against this store's newer compare-and-swap token would write over whatever landed in
    /// between. The store keeps what it read, so a commit of a bundle that is not what this store
    /// last saw is refused rather than accepted with the token it happens to hold.
    baseline: Option<Baseline>,
    /// The last write this store sent.
    last_write: Option<LastWrite>,
    /// Where the record of that write is kept across a restart.
    file: RecordFile,
}

impl std::fmt::Debug for BundleStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleStore")
            .field("service_origin", &self.context.service_origin)
            .field("bundle_locator", &self.context.bundle_locator)
            .field("position", &self.position())
            .field("lost_write", &self.lost_write())
            .finish_non_exhaustive()
    }
}

impl BundleStore {
    /// Opens the bundle at one retrieval context, keeping its write record in `directory`.
    ///
    /// `directory` is where this device keeps its recovery state, and it has to exist already. One
    /// directory holds the records of every bundle location the device writes: each record is
    /// named after its location. A record left there by a write whose answer never came back, in
    /// this process or one that has since ended, is taken up here, and the store starts with that
    /// write outstanding: [`Self::lost_write`] says so, and nothing is written until
    /// [`Self::fetch`] recognises the write or [`Self::end_lost_write`] ends it.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleStoreInUse`] while another store holds this location's
    /// record, [`RecoveryError::Storage`] when the directory or the record cannot be used, and
    /// [`RecoveryError::UnreadableWriteRecord`] for a record this build cannot read.
    pub fn open(
        service: Arc<dyn SyncBackupService>,
        context: RecoveryContext,
        directory: &Path,
    ) -> Result<Self> {
        let (file, record) = RecordFile::open(directory, &context)?;
        let last_write = record.map(|record| LastWrite {
            lost: Some(LostWrite::Unsettled { sent: record.sent }),
            record,
        });
        Ok(Self {
            service,
            context,
            baseline: None,
            last_write,
            file,
        })
    }

    /// Returns where this bundle is stored.
    #[must_use]
    pub const fn context(&self) -> &RecoveryContext {
        &self.context
    }

    /// Returns where this device last read or wrote the bundle, when it has read or written it.
    #[must_use]
    pub const fn position(&self) -> Option<SyncPosition> {
        match &self.baseline {
            Some(baseline) => Some(baseline.position),
            None => None,
        }
    }

    /// Returns what became of the last write whose answer never arrived.
    ///
    /// [`None`] until one is lost. It stays until the next answered commit, because what was
    /// established about that write stays true. A store opened over the record of a write whose
    /// answer never came back starts with that write unsettled here, whatever the process that
    /// sent it had learned before it ended.
    #[must_use]
    pub fn lost_write(&self) -> Option<LostWrite> {
        self.last_write.as_ref().and_then(|write| write.lost)
    }

    /// Returns the record of a write whose answer never arrived and which nothing has ended.
    fn unsettled(&self) -> Option<&WriteRecord> {
        self.last_write
            .as_ref()
            .filter(|write| matches!(write.lost, Some(LostWrite::Unsettled { .. })))
            .map(|write| &write.record)
    }

    /// Records what became of a write whose answer never arrived.
    ///
    /// Only an unsettled write changes. An answered one has no question to settle, and a settled
    /// one keeps the answer it was given, because every way of settling it asks the service or the
    /// locator a question whose answer does not change.
    fn settle(&mut self, outcome: LostWrite) {
        if let Some(write) = &mut self.last_write
            && matches!(write.lost, Some(LostWrite::Unsettled { .. }))
        {
            write.lost = Some(outcome);
        }
    }

    /// Returns the evidence for a writer the bundle this store last authenticated carries.
    ///
    /// The evidence says a writer's bundle has landed at this origin and locator, and a store only
    /// holds a bundle it fetched from the service or committed to it. So a write whose answer was
    /// lost and which did apply yields its evidence from the read that recognised it, without
    /// another write: the bundle carrying the writer is at the locator, which is the whole of what
    /// [`Self::enable_writer`] promises.
    #[must_use]
    pub fn writer_enabled(&self, writer_key_id: KeyId) -> Option<WriterEnabled> {
        let baseline = self.baseline.as_ref()?;
        baseline
            .bundle
            .trusted_writers
            .iter()
            .find(|writer| writer.writer_key_id == writer_key_id)
            .map(|_| WriterEnabled {
                writer_key_id,
                context: self.context.clone(),
                bundle_revision: baseline.bundle.revision.get(),
                bundle_position: baseline.position,
            })
    }

    /// Asks the service to fence the identity one write went out under.
    ///
    /// Nothing executes under it from that moment, and the answer is whatever the service had
    /// already decided about it. Fencing an identity twice is answered the same way both times.
    async fn fence(&self, record: &WriteRecord) -> Result<SyncRequestFence> {
        self.service
            .fence_request(
                bundle_collection(&self.context),
                record.request_id,
                record.signed_at_ms.get(),
                record.signed_at_ms.get(),
            )
            .await
            .map_err(RecoveryError::Service)
    }

    /// Ends a write whose answer never arrived, and says what became of it.
    ///
    /// Reading says what is at the locator; it does not say that a request still on its way cannot
    /// land afterwards. Only the service can say that, and this is how it is asked: the identity
    /// the write went out under is fenced, so nothing executes under it from that moment, and the
    /// fence answers with whatever the service had already decided about it. That is what makes
    /// the next write safe rather than hopeful.
    ///
    /// It is not a privacy operation and it ends nothing else. Fencing here is simply how a caller
    /// makes a request over when no answer to it ever came back.
    ///
    /// The fence's answer decides what else is needed. A refusal says the bundle was not written at
    /// all, so nothing is read. An applied receipt names where that write landed: a store that has
    /// already read that place or a later one reads nothing, and a store behind it reads the
    /// bundle back and holds it to the receipt, because the store keeps the write's digest and not
    /// the bundle it carried. A fence that finds no receipt and cannot establish that none was
    /// ever removed says only that nothing will run from now on, which leaves this device's
    /// baseline possibly behind its own applied write, so the bundle is read before the store will
    /// write again.
    ///
    /// Returns what the store now knows, which is [`None`] when nothing was ever lost. A service
    /// that cannot be asked leaves the write outstanding and the store still refusing to write,
    /// which is the safe direction; a second attempt fences the same identity and is answered the
    /// same way.
    ///
    /// # Errors
    ///
    /// Returns a service error when the fence cannot be made, and the refusals [`Self::commit`]
    /// lists for a receipt this device cannot read. A read that follows an applied receipt reports
    /// its own failure, and so does a read that follows a fence that cannot say nothing ran, but
    /// the second only while this store holds a baseline; a store that has adopted nothing ends
    /// the request instead, because its next write compares against absence and a service refuses
    /// that comparison wherever a bundle is there.
    pub async fn end_lost_write(&mut self, seed: &RecoverySeed) -> Result<Option<LostWrite>> {
        let Some(record) = self.unsettled().cloned() else {
            return Ok(self.lost_write());
        };
        let settled = match self.fence(&record).await? {
            SyncRequestFence::Applied { position } => {
                // A receipt is history: it says where *this* write landed, which is a write on
                // from where it was dispatched against. That is what it is held to, and not this
                // store's baseline, because another device can have moved the bundle on since and
                // this store can already have read that.
                diagnose_applied(record.expected.0, position)?;
                self.adopt_the_applied_write(seed, position, record.sent)
                    .await?;
                LostWrite::Applied
            }
            SyncRequestFence::Refused { retained } => LostWrite::Ended { retained },
            // The service established that nothing ever ran, so this store's baseline is still
            // where it was and the write left nothing anywhere.
            SyncRequestFence::Fenced { never_ran: true } => LostWrite::Ended { retained: None },
            // Nothing will run from now on, and whether this write ran before is not established.
            // If it did, the bundle at the locator is this device's own and the baseline is behind
            // it, so the read that recognises it is what makes the next write safe.
            SyncRequestFence::Fenced { never_ran: false } => match self.fetch(seed).await {
                Ok(_) => match self.lost_write() {
                    Some(LostWrite::Applied) => return Ok(Some(LostWrite::Applied)),
                    _ => LostWrite::Ended { retained: None },
                },
                // A read that fails leaves the question open. While this store holds a baseline it
                // stays outstanding and the caller asks again: the bundle at the locator may be
                // this device's own applied write, and settling would leave the baseline behind
                // it. Fencing the same identity twice is answered the same way.
                //
                // A store holding no baseline has nothing to be behind. No baseline says that this
                // store has adopted nothing, not that the locator is empty; another device may have
                // written there. Settling is safe for two reasons together: the fence has already
                // stopped this request executing, and a store with no baseline can only compare
                // against absence, which a service refuses wherever a bundle is there, this
                // device's own lost first write included. Staying outstanding would only leave the
                // store unable to write at all.
                Err(failure) => {
                    if self.baseline.is_some() {
                        return Err(failure);
                    }
                    LostWrite::Ended { retained: None }
                }
            },
        };
        self.settle(settled);
        Ok(Some(settled))
    }

    /// Takes a write the service says it applied as this store's baseline, where that is forward.
    ///
    /// A receipt can be older than what this store has already read, and reading it as the place
    /// the bundle is now would put the store behind its own knowledge. So the newer of the two
    /// stands, and a receipt behind the baseline changes nothing.
    ///
    /// One place in the order holds one write for the life of a collection, so a receipt and a
    /// baseline that share a place have to be the same write: another name for it, or the same
    /// name over content with another digest, is two histories and is refused rather than
    /// resolved.
    ///
    /// A store behind the receipt, or one that has read nothing, reads the bundle back, because it
    /// keeps the write's digest and not the bundle, and a baseline is a place together with the
    /// content read there. What comes back is held to the receipt the same way: the write's own
    /// place with the write's own bytes, or a later place another write has moved it on to.
    async fn adopt_the_applied_write(
        &mut self,
        seed: &RecoverySeed,
        landed: SyncPosition,
        sent: Digest256,
    ) -> Result<()> {
        if let Some(baseline) = &self.baseline {
            if baseline.position.write_sequence > landed.write_sequence {
                return Ok(());
            }
            if baseline.position.write_sequence == landed.write_sequence {
                return same_write(baseline, landed, sent);
            }
        }
        let read = self.read(seed).await?;
        if read.position.write_sequence < landed.write_sequence {
            return Err(RecoveryError::BundleWentBack {
                expected: landed.write_sequence,
                found: read.position.write_sequence,
            });
        }
        if read.position.write_sequence == landed.write_sequence {
            same_write(&read, landed, sent)?;
        }
        self.baseline = Some(read);
        Ok(())
    }

    /// Builds the first bundle for a collection that has none.
    #[must_use]
    pub fn empty(now_ms: TimestampMs) -> RecoveryBundle {
        RecoveryBundle {
            schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
            collections: Vec::new(),
            trusted_writers: [].into_iter().collect(),
            trusted_producers: [].into_iter().collect(),
            checkpoints: [].into_iter().collect(),
            revision: U64::new(0),
            written_at_ms: now_ms,
        }
    }

    /// Fetches the bundle, authenticates it under the key this seed and context derive, and makes
    /// it this store's.
    ///
    /// This is where a write whose answer never arrived is recognised: when the bytes that come back
    /// are the very bytes this device sent, that write applied, and it cannot apply a second time,
    /// because a service answers a repeated identity from the receipt it already holds. So the
    /// write is settled, the store's baseline is its own write, and the next commit compares
    /// against the right place rather than meeting itself as somebody else's conflict.
    ///
    /// A read that finds another bundle settles nothing, and says so by leaving the write
    /// outstanding. It has established what is at the locator, which is worth having, and not that
    /// the request cannot still land afterwards; [`Self::end_lost_write`] is what establishes that.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleNotAuthentic`] when the bytes do not open here, which is
    /// what a substituted origin or locator looks like, the refusals [`Self::commit`] lists for a
    /// position this device cannot read, among them [`RecoveryError::BundleHistoryForked`] for
    /// other content at the very place this store last read, and a service error when the fetch
    /// fails.
    pub async fn fetch(&mut self, seed: &RecoverySeed) -> Result<RecoveryBundle> {
        Ok(self.adopt(seed).await?.bundle)
    }

    /// Reads the bundle, settles a lost write it recognises, and makes it this store's baseline.
    async fn adopt(&mut self, seed: &RecoverySeed) -> Result<Baseline> {
        let read = self.read(seed).await?;
        if self
            .unsettled()
            .is_some_and(|record| record.sent == read.sealed)
        {
            self.settle(LostWrite::Applied);
        }
        self.baseline = Some(read.clone());
        Ok(read)
    }

    /// Reads and authenticates the bundle without making it this store's.
    ///
    /// [`Self::fetch`] is this, the settlement of a lost write and the remembering. A caller that
    /// has still to decide whether what came back is acceptable wants this one: a bundle adopted
    /// before it was judged would leave this store holding the very thing it went on to refuse,
    /// and the refusal would then pass on the next attempt.
    ///
    /// Every read is held to what this store already holds. The place has to be one a write of the
    /// bundle can be at, no earlier than the last one read, and not another name for it; and
    /// **one place names one content**. A second reading of the very place this store last read
    /// that comes back with other content is a fork, and the caller is told so. Taking it would be
    /// a silent replacement of the bundle this store authenticated there, which is the one thing a
    /// compare-and-swap exists to prevent, and the settlement of a lost write already holds a
    /// receipt to the same rule.
    async fn read(&self, seed: &RecoverySeed) -> Result<Baseline> {
        let read = read_bundle(self.service.as_ref(), &self.context, self.position(), seed).await?;
        if let Some(baseline) = &self.baseline
            && baseline.position == read.position
            && baseline.bundle != read.bundle
        {
            return Err(RecoveryError::BundleHistoryForked {
                expected: baseline.position,
                found: read.position,
            });
        }
        Ok(read)
    }

    /// Commits a bundle at the position this device last saw.
    ///
    /// The revision advances with the write, so a reader can tell which of two bundles it is
    /// holding without asking the service.
    ///
    /// Each attempt carries an identity of its own and the instant of this call, which the service
    /// signs with and measures freshness against. The identity is fresh every time because nothing
    /// here is ever resent: a request identity earns its keep by letting a retry be answered from
    /// the receipt of the first attempt, and this store retries nothing. What it does instead is
    /// read, which establishes the one thing that matters about the bundle: what is at the locator
    /// now.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleConflict`] when the service refused the comparison because
    /// another device wrote first, [`RecoveryError::BundleOutcomeUnknown`] when the answer never
    /// came back, [`RecoveryError::BundleWriteUnsettled`] when a previous write is still
    /// outstanding, and [`RecoveryError::BundleNotAWrite`], [`RecoveryError::BundleWentBack`],
    /// [`RecoveryError::BundleDidNotMoveOn`] or [`RecoveryError::BundleHistoryForked`] for a
    /// position this device cannot read.
    pub async fn commit(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        now_ms: TimestampMs,
    ) -> Result<SyncPosition> {
        // A write this device never got an answer to has to be over before another goes out.
        // Writing again while it could still land would be refused where it did land, and the
        // caller would be told another device had written when what it had met was its own write.
        if let Some(record) = self.unsettled() {
            return Err(RecoveryError::BundleWriteUnsettled { sent: record.sent });
        }
        let expected = self.position();
        // The bundle being written has to be the one this store last authenticated, changed. A
        // snapshot from before somebody else's write would otherwise be committed against this
        // store's newer token and take their change with it.
        if self
            .baseline
            .as_ref()
            .is_some_and(|baseline| baseline.bundle.revision.get() != bundle.revision.get())
        {
            return Err(RecoveryError::BundleConflict {
                expected,
                retained: None,
            });
        }
        // The candidate is prepared beside the caller's bundle, so a failure anywhere below leaves
        // the caller's revision where it was: a rollback after the fact would not cover a failure
        // that happened before it, and the caller would then be holding a revision it could never
        // commit.
        let mut candidate = bundle.clone();
        candidate.revision = U64::new(candidate.revision.get().saturating_add(1));
        candidate.written_at_ms = now_ms;
        let key = seed.bundle_key_for(&self.context)?;
        let ciphertext = kr_crypto::archive::encrypt_recovery_bundle(&key, &candidate)?;
        let sent = sealed_digest(&ciphertext);
        let request_id = kr_transport::random::fresh_uuid_v4().map_err(ClientError::from)?;
        // Recorded before the call and not after it, because the case this is for is the one where
        // nothing comes back: a store that noted the write only on the way out would have no
        // record of a write that was dropped between here and the service, and no identity to end
        // it by. It is on the disk before it is in memory, and both before anything is sent, so a
        // process that ends at any point from here on leaves the record for the next store to
        // find, and a record that cannot be written sends nothing at all.
        let record = WriteRecord {
            context: self.context.clone(),
            expected: Nullable::from(expected),
            request_id,
            signed_at_ms: now_ms,
            sent,
        };
        self.file.save(&record)?;
        self.last_write = Some(LastWrite {
            record,
            lost: Some(LostWrite::Unsettled { sent }),
        });
        match self
            .service
            .compare_exchange(
                bundle_collection(&self.context),
                request_id,
                now_ms.get(),
                expected,
                &ciphertext,
            )
            .await
        {
            Ok(SyncExchanged::Applied { position }) => {
                // A position this device cannot read leaves the write outstanding rather than
                // recorded: the service says it applied the write, and where it says it landed is
                // somewhere no write of this bundle can be. Ending the request is then what
                // establishes what actually happened.
                diagnose_applied(expected, position)?;
                self.answered();
                self.baseline = Some(Baseline {
                    position,
                    bundle: candidate.clone(),
                    sealed: sent,
                });
                *bundle = candidate;
                Ok(position)
            }
            Ok(SyncExchanged::Refused { retained }) => {
                // A refusal is an answer: the service compared, the comparison did not hold, and
                // the bundle this device sent was not written. Nothing is outstanding.
                self.answered();
                Err(RecoveryError::BundleConflict { expected, retained })
            }
            // Anything else stopped the exchange from being answered at all, and an exchange that
            // was not answered may still have been executed. This device concludes nothing from it
            // and says so, which is the safe direction.
            Err(error) => Err(RecoveryError::BundleOutcomeUnknown {
                sent,
                source: Box::new(error),
            }),
        }
    }

    /// Records that the service answered the last write, so no question about it is left.
    ///
    /// The record on the disk goes as well, because a restart has nothing to ask about an answered
    /// write. Removing it can fail, and the answer stands all the same: the record left behind names
    /// a write the service has already decided, so a restart that finds it asks about it once and is
    /// told what this call was told. Reporting the removal instead would report a write that
    /// applied as one that failed.
    fn answered(&mut self) {
        if let Some(write) = &mut self.last_write {
            write.lost = None;
        }
        let _ = self.file.clear();
    }

    /// Enables a backup writer, committing the updated bundle *before* declaring it.
    ///
    /// Section 20: *enabling a new backup writer or rotating its signing key commits an updated
    /// bundle before declaring that writer recovery-enabled.* The declaration is
    /// [`WriterEnabled`], and it is returned by this call and constructed nowhere else, so a
    /// caller cannot declare a writer whose bundle has not landed.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns. The writer is not declared when the commit
    /// fails.
    pub async fn enable_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        writer: TrustedWriter,
        now_ms: TimestampMs,
    ) -> Result<WriterEnabled> {
        let writer_key_id = writer.writer_key_id;
        let mut writers: Vec<TrustedWriter> = bundle.trusted_writers.iter().cloned().collect();
        writers.retain(|held| held.writer_key_id != writer_key_id);
        writers.push(writer);
        bundle.trusted_writers = writers.into_iter().collect();
        let position = self.commit(seed, bundle, now_ms).await?;
        Ok(WriterEnabled {
            writer_key_id,
            context: self.context.clone(),
            bundle_revision: bundle.revision.get(),
            bundle_position: position,
        })
    }

    /// Enrols the producer whose key wraps a restore will have to open.
    ///
    /// A restore that has only the kit needs the producer's *public* stored-envelope key: a wrap
    /// is a `crypto_box` between two keys and the descriptor carries only an identifier, which is
    /// a hash. Taking it from the archive instead would be taking key material from something
    /// untrusted, which is the one thing section 20 ¶10 forbids.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn enable_producer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        sender_key_id: KeyId,
        stored_envelope_key: StoredEnvelopeKey,
        now_ms: TimestampMs,
    ) -> Result<SyncPosition> {
        let mut producers: Vec<TrustedProducer> =
            bundle.trusted_producers.iter().cloned().collect();
        producers.retain(|held| held.sender_key_id != sender_key_id);
        producers.push(TrustedProducer {
            sender_key_id,
            stored_envelope_key,
            enrolled_at_ms: now_ms,
        });
        bundle.trusted_producers = producers.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Rotates a writer's signing key: the replacement enters the bundle and the retired key
    /// stays, in one commit.
    ///
    /// **The retired key stays.** The bundle is the only place a restore takes a writer key from,
    /// so removing the old one would leave every archive it had already signed unverifiable: a
    /// rotation would silently destroy the backups it was meant to protect. What rotation changes
    /// is which writer may *publish*, and that is the collection's enrolment record rather than
    /// this set. [`Self::retire_writer`] is the separate, deliberate step that drops a key once no
    /// retained archive needs it.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn rotate_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        replacement: TrustedWriter,
        now_ms: TimestampMs,
    ) -> Result<WriterEnabled> {
        self.enable_writer(seed, bundle, replacement, now_ms).await
    }

    /// Drops a writer key from the bundle, which no restore will verify against afterwards.
    ///
    /// It is separate from a rotation because it is a different decision: rotating a key is about
    /// what may be published next, and dropping one is about what may still be read. A caller
    /// takes this step when no retained archive is signed by that key any more.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn retire_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        retiring: &KeyId,
        now_ms: TimestampMs,
    ) -> Result<SyncPosition> {
        let mut writers: Vec<TrustedWriter> = bundle.trusted_writers.iter().cloned().collect();
        writers.retain(|held| &held.writer_key_id != retiring);
        bundle.trusted_writers = writers.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Records the latest generation the owner has verified for one archive.
    ///
    /// A checkpoint only ever moves forward. A verification of generation four arriving after one
    /// of generation nine is a late answer, not a newer fact, and writing it would give a service
    /// five generations of archives it could replay unnoticed. The compare-and-swap protects the
    /// bundle's revision; this protects what the bundle says.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::CheckpointWentBackwards`] when the recorded generation is newer
    /// than this one, and whatever [`Self::commit`] returns.
    pub async fn record_checkpoint(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        checkpoint: ArchiveCheckpoint,
        now_ms: TimestampMs,
    ) -> Result<SyncPosition> {
        let mut checkpoints: Vec<ArchiveCheckpoint> = bundle.checkpoints.iter().cloned().collect();
        if let Some(held) = checkpoints
            .iter()
            .find(|held| held.archive_id == checkpoint.archive_id)
        {
            if held.backup_generation.get() > checkpoint.backup_generation.get() {
                return Err(RecoveryError::CheckpointWentBackwards {
                    recorded: held.backup_generation.get(),
                    offered: checkpoint.backup_generation.get(),
                });
            }
            if held.backup_generation == checkpoint.backup_generation
                && held.encrypted_manifest_hash != checkpoint.encrypted_manifest_hash
            {
                return Err(RecoveryError::CheckpointWentBackwards {
                    recorded: held.backup_generation.get(),
                    offered: checkpoint.backup_generation.get(),
                });
            }
        }
        checkpoints.retain(|held| held.archive_id != checkpoint.archive_id);
        checkpoints.push(checkpoint);
        bundle.checkpoints = checkpoints.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Moves the bundle to another service origin or another locator.
    ///
    /// The key is bound to where the bundle lives, so a migration re-encrypts rather than copies.
    /// It is verified before it is reported: the bundle is written at the new location, read back
    /// from it and authenticated there, and only then is the updated kit produced. A migration
    /// that could not be read back is not a migration.
    ///
    /// **The copy at the old location stays there.** This seam publishes and fetches; it does not
    /// delete, and removing the old object is the service's own operation. That is also the safer
    /// order: a bundle removed before its owner has the new kit in hand would be a migration that
    /// lost the archive it was moving. [`MigrationRecord::describe`] says so, because an owner who
    /// keeps the old kit keeps a kit that still opens a superseded bundle.
    ///
    /// **Everything that can be checked is checked before anything is written.** The kit is the
    /// one this store's bundle belongs to and carries the seed being migrated; the bundle at the
    /// old location is read again and has to be the one the caller is holding, so a write another
    /// device made in between is a conflict rather than a migration that quietly moves an older
    /// writer set. What cannot be checked first is the write itself, and it fails in two different
    /// ways.
    ///
    /// A destination that **takes** the bundle and then fails to serve it back leaves the new
    /// location populated and this store where it was. The caller's bundle is untouched, so
    /// reading the old location again is a valid retry, and the destination object has to be
    /// cleared before one can succeed.
    ///
    /// A destination that **answers nothing** leaves a write that may still land, and clearing the
    /// object would not help, because the delayed request would write it again. That is why the
    /// destination is a store the caller holds rather than one this call makes and drops: the
    /// store that made the write keeps the record of it and refuses to write again while it
    /// stands. [`Self::complete_migration`] is the step that follows: it ends that write and, where
    /// it landed, completes the migration from it. [`Self::end_lost_write`] on the destination
    /// store ends the write and completes nothing. A migration abandoned part-way, by a failure, by a
    /// dropped future or by the process ending, leaves that record where either will find it, in a
    /// destination store opened afterwards as well.
    ///
    /// **The destination store has to hold nothing, and it stays the caller's.** A migration writes
    /// a bundle where there is none, so a store that has already read one at the destination is
    /// refused rather than written over, and that refusal comes before the old location is read
    /// at all. On success this store is *not* turned into the destination: the caller already
    /// holds that store, and one collection answers to one store, because two handles would each
    /// pass their own guard on a write the other had outstanding. What this store names afterwards
    /// is still the old location and the superseded copy there.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::UnknownServiceOrigin`] when the kit does not name this store's
    /// origin, [`RecoveryError::KitLocatorMismatch`] when it names another bundle,
    /// [`RecoveryError::MigrationWouldLoseAnOrigin`] for a kit that names several origins,
    /// [`RecoveryError::KitIsForAnotherSeed`] when the kit and the seed disagree,
    /// [`RecoveryError::DestinationHoldsABundle`] when the destination store has read a bundle
    /// there, [`RecoveryError::BundleConflict`] when the old location has moved on,
    /// [`RecoveryError::BundleNotAuthentic`] when the bundle does not read back at the new
    /// location, and whatever [`Self::commit`] returns for the write itself.
    pub async fn migrate(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        kit: &RecoveryKit,
        moved: &mut Self,
        now_ms: TimestampMs,
    ) -> Result<Migrated> {
        let updated_kit = self.kit_for_the_move(seed, kit, &moved.context)?;
        // A migration writes a bundle where there is none. A destination store that has already
        // read one would compare against it and put this bundle over the top, and the read-back
        // check would pass, because what came back is what went in. The bundle it replaced would
        // be gone, and a bundle is the only thing a restore takes a writer key from.
        //
        // This is checked before the old location is read. A destination that already holds a
        // bundle is refused whatever the old location holds, so the refusal names the reason no
        // retry can get past rather than one that reading again would.
        if moved.baseline.is_some() {
            return Err(RecoveryError::DestinationHoldsABundle);
        }

        // The bundle being moved has to be the one at the old location *now*, not the one this
        // device read at some point. Migrating a snapshot from before somebody else's write would
        // move an older writer set and older checkpoints to the new location and point the updated
        // kit at them. Reading it again is also what proves this seed opens it: a seed that does
        // not is an authentication failure here rather than a bundle re-encrypted under the wrong
        // authority at the destination.
        //
        // Authentication says who could have written the ciphertext, never how long ago. A service
        // that serves a bundle this device has already seen superseded is serving a replay, so the
        // revision this store knew is held against what comes back: a source that has gone
        // backwards is a conflict, not a migration that quietly drops the writers in between. The
        // read does not make what it returns this store's, so a refused replay does not become the
        // baseline that would let the next attempt through.
        let current = self.read_the_source(seed).await?;
        if &current != bundle {
            return Err(self.source_moved_on());
        }
        // The candidate is prepared beside the caller's bundle. A destination that takes the write
        // and then fails to serve it back must not leave the caller holding a revision it has
        // nowhere to commit: what it holds is still the bundle at the old location.
        let mut candidate = bundle.clone();
        let position = moved.commit(seed, &mut candidate, now_ms).await?;
        // Read back and authenticate at the new location. The key there is a different key, so a
        // service that stored the old ciphertext under the new name fails here.
        let verified = moved.fetch(seed).await?;
        if verified != candidate {
            // The revision alone would not do: a service that served a different bundle at the
            // same revision would pass. What was written is what has to come back.
            return Err(RecoveryError::BundleNotAuthentic);
        }

        *bundle = candidate;
        // This store is not made into the destination. The caller holds the destination store, and
        // one collection answers to one store: two handles to it would each pass their own guard,
        // so a write through one could go out while a write through the other was still able to
        // land. What this store names is still the old location, which is where the superseded
        // copy stays.
        Ok(self.migrated(moved, bundle, position, updated_kit, now_ms))
    }

    /// Completes a migration whose write at the destination went out and whose answer did not
    /// come back.
    ///
    /// [`Self::migrate`] reports that migration as [`RecoveryError::BundleOutcomeUnknown`], and
    /// its write may still have landed. Calling it again cannot finish the move: while the write
    /// is outstanding the destination store will not write, and once that store has read the
    /// bundle there it refuses, because a migration writes where there is none. This is the step
    /// that finishes it, and it writes nothing at either location.
    ///
    /// **The bundle at the destination has to be this migration's own, and its place in the
    /// order never says so on its own.** Another writer's bundle can be at the very place this
    /// write would have taken. So two things are asked, and both have to agree. The service is
    /// asked about the identity the destination's write went out under: the identity is fenced,
    /// which ends the write where it was still open and repeats what the service recorded where it
    /// was not. A write the service refused, or one it establishes never ran, left nothing, and
    /// whatever is at the destination belongs to somebody else. The bundle there is then read back
    /// and authenticated, and it has to be the very bytes that write sent, at the place the
    /// service's receipt names wherever the service still holds one. Bytes rather than the bundle
    /// inside them: another device moving the same bundle at the same instant writes an equal
    /// bundle, and other bytes, because every encryption starts from its own random header.
    ///
    /// **Then everything [`Self::migrate`] checks is checked.** The kit is this bundle's and this
    /// seed's, the bundle at the destination is the caller's bundle moved on by the one revision a
    /// write adds, and the old location still holds the bundle that was moved: a write made there
    /// since would leave the updated kit pointing at a bundle without it. The caller may hold the
    /// bundle that was moved or, where an earlier completion already returned, the one it became.
    ///
    /// It can be asked again, and it answers the same way: the fence repeats its answer, the read
    /// finds the same bundle, and nothing is written. The destination store keeps its record of the
    /// write until it writes again, and keeps it on this device's disk while no answer to that
    /// write has arrived, so a destination store opened after a restart completes the move too.
    ///
    /// # Errors
    ///
    /// Returns the refusals of the kit [`Self::migrate`] lists,
    /// [`RecoveryError::DestinationHoldsABundle`] when the bundle at the destination is not the one
    /// this migration's write left there, [`RecoveryError::MigrationDidNotLand`] when that write
    /// left nothing and nothing can be read there, [`RecoveryError::BundleConflict`] when the old
    /// location has moved on, a service error when the fence or a read fails, and the refusals
    /// [`Self::commit`] lists for a position this device cannot read.
    pub async fn complete_migration(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        kit: &RecoveryKit,
        moved: &mut Self,
        now_ms: TimestampMs,
    ) -> Result<Migrated> {
        let updated_kit = self.kit_for_the_move(seed, kit, &moved.context)?;
        // The destination comes first, as it does for a migration: a destination whose bundle is
        // not this migration's is refused whatever the old location holds.
        let landed = moved.recognise_its_own_write(seed).await?;
        // The destination's bundle has to be a move of the one the caller is completing. A write
        // the destination store made for any other reason is its own, and still not this
        // migration's.
        if &landed.bundle != bundle && !is_a_move_of(&landed.bundle, bundle) {
            return Err(RecoveryError::DestinationHoldsABundle);
        }
        let current = self.read_the_source(seed).await?;
        if !is_a_move_of(&landed.bundle, &current) {
            return Err(self.source_moved_on());
        }
        *bundle = landed.bundle;
        Ok(self.migrated(moved, bundle, landed.position, updated_kit, now_ms))
    }

    /// Establishes that the bundle at this store's location is the one its last write left there,
    /// and makes it this store's baseline.
    ///
    /// Both the writer's identity and the content decide it. The identity is fenced, and the
    /// service's answer about it has to leave the write able to have landed: an applied receipt,
    /// or a fence that cannot say the write never ran. Then the bytes read back have to be the
    /// ones the write sent, at the place the receipt names where there is one. A place in the order
    /// alone says nothing about which write is there, and neither does a bundle equal to the one
    /// the write carried.
    async fn recognise_its_own_write(&mut self, seed: &RecoverySeed) -> Result<Baseline> {
        let Some(record) = self.last_write.as_ref().map(|write| write.record.clone()) else {
            // This store has sent nothing, so nothing at its location can be its own.
            return Err(self.left_nothing(seed).await);
        };
        let receipt = match self.fence(&record).await? {
            SyncRequestFence::Applied { position } => {
                diagnose_applied(record.expected.0, position)?;
                Some(position)
            }
            // The service can no longer say whether the write ran, and nothing will run under it
            // from now on. The bytes it sent are what is left to recognise it by, and they are its
            // own: no other write, even of an equal bundle at the same instant, sent those bytes.
            SyncRequestFence::Fenced { never_ran: false } => None,
            SyncRequestFence::Refused { retained } => {
                self.settle(LostWrite::Ended { retained });
                return Err(self.left_nothing(seed).await);
            }
            SyncRequestFence::Fenced { never_ran: true } => {
                self.settle(LostWrite::Ended { retained: None });
                return Err(self.left_nothing(seed).await);
            }
        };
        let read = self.read(seed).await?;
        if let Some(receipt) = receipt {
            // The receipt names the place this write took. A read behind it is a service that has
            // gone back, and that one place holding other bytes is two histories rather than a
            // bundle to decline politely. Neither becomes this store's baseline.
            diagnose(Some(receipt), read.position)?;
            if read.position == receipt && read.sealed != record.sent {
                return Err(RecoveryError::BundleHistoryForked {
                    expected: receipt,
                    found: read.position,
                });
            }
        }
        let own =
            read.sealed == record.sent && receipt.is_none_or(|receipt| receipt == read.position);
        // What was read is what the location holds, whoever wrote it, so it is the baseline either
        // way: a store that has read a bundle there will not be migrated into afterwards.
        self.settle(if own || receipt.is_some() {
            LostWrite::Applied
        } else {
            LostWrite::Ended { retained: None }
        });
        self.baseline = Some(read.clone());
        if !own {
            // Another bundle is there: somebody else's, or one that has moved the location on
            // since this write landed. Either way it is not what this write left.
            return Err(RecoveryError::DestinationHoldsABundle);
        }
        Ok(read)
    }

    /// Says what a location holds when nothing this store sent landed there.
    ///
    /// The answer about the migration is already final, and the read only decides which refusal
    /// says it better. A bundle read there is somebody else's, and it becomes this store's
    /// baseline, so a migration into this store is refused as well. Where nothing can be read, the
    /// move can be made again: nothing this store sent will land later, and a write that meets a
    /// bundle the read missed compares against absence, which the service refuses.
    async fn left_nothing(&mut self, seed: &RecoverySeed) -> RecoveryError {
        match self.adopt(seed).await {
            Ok(_) => RecoveryError::DestinationHoldsABundle,
            Err(_) => RecoveryError::MigrationDidNotLand,
        }
    }

    /// Checks the kit a migration is given and builds the one it will hand back.
    ///
    /// Everything here is decided before anything is read or written, which is what lets a
    /// refusal leave both locations exactly as they were.
    fn kit_for_the_move(
        &self,
        seed: &RecoverySeed,
        kit: &RecoveryKit,
        destination: &RecoveryContext,
    ) -> Result<RecoveryKit> {
        // A kit's origins share one locator, so the updated kit can name only the destination: an
        // origin left in it would point at a bundle this migration did not move. That makes a kit
        // naming several origins impossible to migrate one service at a time without losing the
        // others, so it is refused rather than silently reduced. Per-origin locators are what a
        // multiple-service migration needs, and this build does not have them.
        if kit.service_origins.len() > 1 {
            return Err(RecoveryError::MigrationWouldLoseAnOrigin {
                origins: kit.service_origins.len(),
            });
        }
        if !kit
            .service_origins
            .iter()
            .any(|origin| origin == &self.context.service_origin)
        {
            return Err(RecoveryError::UnknownServiceOrigin);
        }
        if kit.bundle_locator != self.context.bundle_locator {
            return Err(RecoveryError::KitLocatorMismatch);
        }
        // The kit has to be this seed's. `from_kit` reads it under its declared profile and checks
        // its own checksum, which is what a mistyped or foreign-profile kit fails; the checksums
        // then have to agree, because the updated kit this call returns is built from the *seed*,
        // and a caller that handed in a kit for another seed would be handed back a kit that opens
        // nothing it owns while its existing archives still wrap their keys for the old recovery
        // recipient.
        let kit_seed = RecoverySeed::from_kit(kit)?;
        if !kit_seed
            .bundle_key_for(&self.context)?
            .constant_time_eq(&seed.bundle_key_for(&self.context)?)
        {
            return Err(RecoveryError::KitIsForAnotherSeed);
        }
        // The kit the migration will hand back has to be one its owner can actually keep. A
        // destination whose locator cannot be printed, or whose kit is larger than a scannable
        // code, would otherwise be found out after the bundle had been written there, which is
        // the one failure a migration cannot undo.
        let updated_kit = kr_crypto::kdf::RecoverySeed::to_kit(
            seed,
            vec![destination.service_origin.clone()],
            destination.bundle_locator.clone(),
        );
        drop(crate::recovery::kit::render(&updated_kit)?);
        Ok(updated_kit)
    }

    /// Reads the bundle at the old location again, as a migration's source.
    ///
    /// The revision this store knew is held against what comes back, because authentication says
    /// who wrote a bundle and never how long ago: a revision behind it is a replay.
    async fn read_the_source(&self, seed: &RecoverySeed) -> Result<RecoveryBundle> {
        let known = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.bundle.revision.get());
        let current = self.read(seed).await?.bundle;
        if known.is_some_and(|known| known > current.revision.get()) {
            return Err(self.source_moved_on());
        }
        Ok(current)
    }

    /// The refusal for an old location that no longer holds the bundle being moved.
    const fn source_moved_on(&self) -> RecoveryError {
        RecoveryError::BundleConflict {
            expected: self.position(),
            retained: None,
        }
    }

    /// Builds the record of a verified move and the kit that goes with it.
    fn migrated(
        &self,
        moved: &Self,
        bundle: &RecoveryBundle,
        position: SyncPosition,
        updated_kit: RecoveryKit,
        now_ms: TimestampMs,
    ) -> Migrated {
        Migrated {
            record: MigrationRecord {
                from: self.context.clone(),
                to: moved.context.clone(),
                bundle_revision: bundle.revision.get(),
                bundle_position: position,
                verified_at_ms: now_ms,
            },
            updated_kit,
        }
    }
}

/// The evidence that a writer's bundle landed before the writer was declared.
///
/// It is returned by [`BundleStore::enable_writer`] and built nowhere else, so holding one is
/// holding the ordering section 20 requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterEnabled {
    writer_key_id: KeyId,
    context: RecoveryContext,
    bundle_revision: u64,
    bundle_position: SyncPosition,
}

impl WriterEnabled {
    /// Returns the writer this evidence is for.
    #[must_use]
    pub const fn writer_key_id(&self) -> KeyId {
        self.writer_key_id
    }

    /// Returns where the bundle that carries it is stored.
    ///
    /// The evidence is about one bundle at one location. A writer enabled in the bundle at one
    /// origin is not enabled in the bundle at another, and carrying the context is what stops that
    /// being assumed.
    #[must_use]
    pub const fn context(&self) -> &RecoveryContext {
        &self.context
    }

    /// Returns the bundle revision that carries the writer.
    #[must_use]
    pub const fn bundle_revision(&self) -> u64 {
        self.bundle_revision
    }

    /// Returns where the service put the write that carries the writer.
    #[must_use]
    pub const fn bundle_position(&self) -> SyncPosition {
        self.bundle_position
    }
}

/// A verified move of the bundle to another origin or locator.
///
/// It names both locations, because after a migration both hold bytes: the new one holds the
/// bundle and the old one holds the copy it superseded, until the service removes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRecord {
    /// Where the bundle was.
    pub from: RecoveryContext,
    /// Where it is now.
    pub to: RecoveryContext,
    /// The revision that was moved.
    pub bundle_revision: u64,
    /// Where at the new location it landed.
    pub bundle_position: SyncPosition,
    /// When it was read back and authenticated at the new location.
    pub verified_at_ms: TimestampMs,
}

impl MigrationRecord {
    /// The sentence an owner is shown, which says what to do with the kit they were holding.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "Your recovery bundle is now at {} under a new locator, and it was read back and \
             authenticated there. Keep the updated kit and destroy the old one: the old kit still \
             opens the copy left at {}, which is the bundle as it was before this move.",
            self.to.service_origin, self.from.service_origin
        )
    }
}

/// A migration and the kit it obsoletes the old one with.
#[derive(Debug)]
pub struct Migrated {
    /// The verified record of the move.
    pub record: MigrationRecord,
    /// The kit a person keeps from now on. The old one points at a location the bundle has left.
    pub updated_kit: RecoveryKit,
}

/// One offline export: the encrypted bundle and the selected archives' own ciphertext.
///
/// Everything in it is already encrypted, so the export adds no protection of its own and claims
/// none. It exists so an owner can keep a copy somewhere the service is not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineExport {
    /// The encrypted recovery bundle, as the service holds it.
    pub encrypted_bundle: Bytes,
    /// The archive's public descriptor bytes.
    pub descriptor: Bytes,
    /// The encrypted archive manifest object.
    pub encrypted_manifest: Bytes,
    /// The selected member objects' encrypted bytes.
    pub objects: Vec<Bytes>,
}

impl OfflineExport {
    /// Constructs one offline export.
    #[must_use]
    pub fn new(
        encrypted_bundle: Vec<u8>,
        descriptor: Vec<u8>,
        encrypted_manifest: Vec<u8>,
        objects: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            encrypted_bundle: Bytes::new(encrypted_bundle),
            descriptor: Bytes::new(descriptor),
            encrypted_manifest: Bytes::new(encrypted_manifest),
            objects: objects.into_iter().map(Bytes::new).collect(),
        }
    }

    /// Encodes this offline export into its canonical KR-CBOR-1 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the export cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(kr_cbor::to_canonical_vec(self)?)
    }

    /// Decodes an offline export from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the bytes cannot be decoded.
    pub fn from_canonical_slice(bytes: &[u8]) -> Result<Self> {
        let limits = kr_cbor::Limits {
            max_message_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_message_len),
            max_bytes_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_bytes_len),
            max_collection_len: 65_536,
            max_items: 1_000_000,
            ..kr_cbor::Limits::DEFAULT
        };
        Ok(kr_cbor::from_canonical_slice(bytes, &limits)?)
    }
}

/// Fetches the bundle at one location and authenticates it under the key this seed and location
/// derive.
///
/// `seen` is where the reader last saw the bundle, and the place that comes back is held to it:
/// one a write of the bundle can be at, no earlier, and not another name for the same place.
///
/// # Errors
///
/// Returns [`RecoveryError::BundleNotAuthentic`] when the bytes do not open here, the refusals of
/// a place [`BundleStore::commit`] lists, and a service error when the fetch fails.
pub(super) async fn read_bundle(
    service: &dyn SyncBackupService,
    context: &RecoveryContext,
    seen: Option<SyncPosition>,
    seed: &RecoverySeed,
) -> Result<Baseline> {
    let (position, ciphertext) = service
        .fetch(bundle_collection(context))
        .await
        .map_err(RecoveryError::Service)?;
    diagnose(seen, position)?;
    let key = seed.bundle_key_for(context)?;
    let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &ciphertext)
        .map_err(|_| RecoveryError::BundleNotAuthentic)?;
    Ok(Baseline {
        position,
        bundle,
        sealed: sealed_digest(&ciphertext),
    })
}

/// Returns the digest of one encrypted bundle, the bytes as a service stores them.
///
/// It is how a read recognises a write this device lost the answer to, and it is what the record
/// of a write keeps instead of the write: the digest is the part the question needs, and keeping
/// only that is keeping nothing a key could be recovered from.
fn sealed_digest(ciphertext: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(ciphertext))
}

/// Returns true when `moved` is `source` as a migration writes it: the same bundle, one revision on.
///
/// A migration writes the caller's bundle at the destination and the write adds one revision and
/// stamps the instant it was made, so those two are what may differ and nothing else may.
fn is_a_move_of(moved: &RecoveryBundle, source: &RecoveryBundle) -> bool {
    moved.revision.get() == source.revision.get().saturating_add(1)
        && RecoveryBundle {
            revision: source.revision,
            written_at_ms: source.written_at_ms,
            ..moved.clone()
        } == *source
}

/// Checks that what this store holds at one place is the write a receipt names at that same place.
///
/// One place in the order holds one write for the life of a collection. The receipt's name for it
/// and the bytes that write sent both have to match what is held there, and either disagreeing is
/// two histories under one place.
fn same_write(held: &Baseline, landed: SyncPosition, sent: Digest256) -> Result<()> {
    if held.position.revision != landed.revision || held.sealed != sent {
        return Err(RecoveryError::BundleHistoryForked {
            expected: held.position,
            found: landed,
        });
    }
    Ok(())
}

/// Checks a position the service answered against where this store last saw the bundle.
///
/// The bundle is an object this device writes and never removes, so the position beside it is
/// where a write of it landed. A removal's place and nought are therefore answers about something
/// else, and this declines them rather than reading them as a place to compare against next time.
///
/// A write sequence only goes forward, and one sequence names one write for the life of a
/// collection. So a smaller sequence is a service that has gone back behind what this device
/// already read, and the same sequence under another name is a history that forked. Either says
/// the locator is not the collection this store has been talking to, and the owner's recovery is
/// the explicit one: read the bundle from a store that knows nothing, and judge what comes back.
fn diagnose(held: Option<SyncPosition>, found: SyncPosition) -> Result<()> {
    if found.is_removal() || found.write_sequence == 0 {
        return Err(RecoveryError::BundleNotAWrite { found });
    }
    let Some(held) = held else {
        return Ok(());
    };
    if found.write_sequence < held.write_sequence {
        return Err(RecoveryError::BundleWentBack {
            expected: held.write_sequence,
            found: found.write_sequence,
        });
    }
    if found.write_sequence == held.write_sequence && found.revision != held.revision {
        return Err(RecoveryError::BundleHistoryForked {
            expected: held,
            found,
        });
    }
    Ok(())
}

/// Checks a position the service answered for a write it says it applied.
///
/// A read may answer the place this device already knows, because the bundle is where it was. An
/// applied write may not: every applied write takes the next place in its collection's order, so
/// an answer that stands still is a service saying it wrote and did not write. Reading it as a
/// position would leave this store naming a place its own content is not at.
fn diagnose_applied(held: Option<SyncPosition>, found: SyncPosition) -> Result<()> {
    diagnose(held, found)?;
    if held.is_some_and(|held| found.write_sequence == held.write_sequence) {
        return Err(RecoveryError::BundleDidNotMoveOn { found });
    }
    Ok(())
}
