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
//! durable request accounting the settings-sync outbox keeps. This is a direct, synchronous
//! consumer of [`SyncBackupService`], and the two paths share the service and nothing else.
//!
//! What a direct consumer still owes is an answer for a write it never heard back about. This one
//! pays it without remembering anything across a restart. Every write carries a fresh identity and
//! the instant the call was made, nothing is retried on its own, and a lost answer is reported as
//! an unknown outcome ([`LostWrite`]). Two things settle it, and neither is a durable account:
//!
//! * **A read that recognises the write.** When the bundle at the locator is the one this device
//!   sent, whose digest says so, that write applied and cannot apply again, because a service
//!   answers a repeated identity from the receipt it already holds.
//! * **Ending the request.** A read that finds another bundle has established what is there and
//!   not that a request still on its way cannot land afterwards, so it settles nothing. Only the
//!   service can end that possibility, and [`BundleStore::end_lost_write`] asks it to: the
//!   identity is fenced, so nothing executes under it from that moment.
//!
//! Until one of the two happens the store writes nothing further, which is what keeps this device
//! from ever meeting its own earlier write and being told another device wrote.

use std::sync::Arc;

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{
    ArchiveCheckpoint, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryContext,
    RecoveryKit, TrustedProducer, TrustedWriter,
};
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{Bytes, Digest256, KeyId, StoredEnvelopeKey, TimestampMs, U64, Uuid};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
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
        /// The digest of the canonical bundle this device sent.
        sent: Digest256,
    },
    /// The write applied: a read authenticated the very bundle this device sent, or the service
    /// said so when the request was ended.
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

/// A write this store sent and has still to learn the outcome of.
#[derive(Clone, Debug)]
struct Outstanding {
    /// The identity that write went out under, which is what ends it.
    request_id: Uuid,
    /// The instant it was signed at, which is what bounds when the service may still run it.
    signed_at_ms: u64,
    /// Where it compared against, which is what any receipt of it has to follow on from.
    ///
    /// A receipt is history, so it names where *that* write landed. Another device can have moved
    /// the bundle on since, and this store can have read that; the receipt is then behind the
    /// store's own baseline and is not a service going back. Holding the receipt against where the
    /// write was dispatched is what tells the two apart.
    expected: Option<SyncPosition>,
    /// The digest of `bundle`, which is how a read recognises it.
    digest: Digest256,
    /// The bundle it would have left at the locator.
    bundle: RecoveryBundle,
}

/// A write whose answer never arrived, before and after it was ended.
///
/// One field rather than two, so the store cannot hold an outstanding write and a settled report
/// that disagree.
#[derive(Clone, Debug)]
enum Lost {
    Outstanding(Box<Outstanding>),
    Settled(LostWrite),
}

/// The owner's bundle at one service, and where this device last saw it.
#[derive(Clone)]
pub struct BundleStore {
    service: Arc<dyn SyncBackupService>,
    context: RecoveryContext,
    position: Option<SyncPosition>,
    /// The bundle this store last authenticated at that position.
    ///
    /// A caller holding a bundle it read earlier holds a snapshot, and writing that snapshot back
    /// against this store's newer compare-and-swap token would write over whatever landed in
    /// between. The store keeps what it read, so a commit of a bundle that is not what this store
    /// last saw is refused rather than accepted with the token it happens to hold.
    held: Option<RecoveryBundle>,
    /// A write this device sent and has still to learn the outcome of.
    lost: Option<Lost>,
}

impl std::fmt::Debug for BundleStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleStore")
            .field("service_origin", &self.context.service_origin)
            .field("bundle_locator", &self.context.bundle_locator)
            .field("position", &self.position)
            .field("lost_write", &self.lost_write())
            .finish_non_exhaustive()
    }
}

impl BundleStore {
    /// Opens the bundle at one retrieval context.
    #[must_use]
    pub fn new(service: Arc<dyn SyncBackupService>, context: RecoveryContext) -> Self {
        Self {
            service,
            context,
            position: None,
            held: None,
            lost: None,
        }
    }

    /// Returns where this bundle is stored.
    #[must_use]
    pub const fn context(&self) -> &RecoveryContext {
        &self.context
    }

    /// Returns where this device last read or wrote the bundle, when it has read or written it.
    #[must_use]
    pub const fn position(&self) -> Option<SyncPosition> {
        self.position
    }

    /// Returns what became of the last write whose answer never arrived.
    ///
    /// [`None`] until one is lost. It stays until the next answered commit, because what was
    /// established about that write stays true.
    #[must_use]
    pub fn lost_write(&self) -> Option<LostWrite> {
        match &self.lost {
            Some(Lost::Outstanding(outstanding)) => Some(LostWrite::Unsettled {
                sent: outstanding.digest,
            }),
            Some(Lost::Settled(settled)) => Some(*settled),
            None => None,
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
        let held = self.held.as_ref()?;
        let position = self.position?;
        held.trusted_writers
            .iter()
            .find(|writer| writer.writer_key_id == writer_key_id)
            .map(|_| WriterEnabled {
                writer_key_id,
                context: self.context.clone(),
                bundle_revision: held.revision.get(),
                bundle_position: position,
            })
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
    /// The fence's answer decides what else is needed. A receipt says what happened, so nothing is
    /// read: an applied receipt names where that write landed and what it left there, and a
    /// refusal says the bundle was not written at all. A fence that finds no receipt and cannot
    /// establish that none was ever removed says only that nothing will run from now on, which
    /// leaves this device's baseline possibly behind its own applied write, so the bundle is read
    /// before the store will write again.
    ///
    /// Returns what the store now knows, which is [`None`] when nothing was ever lost. A service
    /// that cannot be asked leaves the write outstanding and the store still refusing to write,
    /// which is the safe direction; a second attempt fences the same identity and is answered the
    /// same way.
    ///
    /// # Errors
    ///
    /// Returns a service error when the fence or the read that follows it cannot be made, and the
    /// refusals [`Self::commit`] lists for a receipt this device cannot read.
    pub async fn end_lost_write(&mut self, seed: &RecoverySeed) -> Result<Option<LostWrite>> {
        let Some(Lost::Outstanding(outstanding)) = self.lost.clone() else {
            return Ok(self.lost_write());
        };
        let fence = self
            .service
            .fence_request(
                bundle_collection(&self.context),
                outstanding.request_id,
                outstanding.signed_at_ms,
                outstanding.signed_at_ms,
            )
            .await
            .map_err(RecoveryError::Service)?;
        let settled = match fence {
            SyncRequestFence::Applied { position } => {
                // A receipt is history: it says where *this* write landed, which is a write on
                // from where it was dispatched against. That is what it is held to, and not this
                // store's baseline, because another device can have moved the bundle on since and
                // this store can already have read that.
                diagnose_applied(outstanding.expected, position)?;
                self.adopt_the_applied_write(position, outstanding.bundle)?;
                LostWrite::Applied
            }
            SyncRequestFence::Refused { retained } => LostWrite::Ended { retained },
            // The service established that nothing ever ran, so this store's baseline is still
            // where it was and the write left nothing anywhere.
            SyncRequestFence::Fenced { never_ran: true } => LostWrite::Ended { retained: None },
            // Nothing will run from now on, and whether this write ran before is not established.
            // If it did, the bundle at the locator is this device's own and the baseline is behind
            // it, so the read that recognises it is what makes the next write safe.
            SyncRequestFence::Fenced { never_ran: false } => {
                self.fetch(seed).await?;
                match self.lost {
                    Some(Lost::Settled(settled)) => return Ok(Some(settled)),
                    _ => LostWrite::Ended { retained: None },
                }
            }
        };
        self.lost = Some(Lost::Settled(settled));
        Ok(Some(settled))
    }

    /// Takes a write the service says it applied as this store's baseline, where that is forward.
    ///
    /// A receipt can be older than what this store has already read, and reading it as the place
    /// the bundle is now would put the store behind its own knowledge. So the newer of the two
    /// stands. Two answers under one place in the order are two histories, and that is refused
    /// rather than resolved.
    fn adopt_the_applied_write(
        &mut self,
        position: SyncPosition,
        bundle: RecoveryBundle,
    ) -> Result<()> {
        if let Some(held) = self.position {
            if held.write_sequence == position.write_sequence && held.revision != position.revision
            {
                return Err(RecoveryError::BundleHistoryForked {
                    expected: held,
                    found: position,
                });
            }
            if held.write_sequence > position.write_sequence {
                return Ok(());
            }
        }
        self.position = Some(position);
        self.held = Some(bundle);
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
    /// This is where a write whose answer never arrived is recognised: when the bundle that comes
    /// back is the one this device sent, that write applied, and it cannot apply a second time,
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
    /// position this device cannot read, and a service error when the fetch fails.
    pub async fn fetch(&mut self, seed: &RecoverySeed) -> Result<RecoveryBundle> {
        let (position, bundle) = self.read(seed).await?;
        if let Some(Lost::Outstanding(outstanding)) = &self.lost
            && digest_of(&bundle)? == outstanding.digest
        {
            self.lost = Some(Lost::Settled(LostWrite::Applied));
        }
        self.position = Some(position);
        self.held = Some(bundle.clone());
        Ok(bundle)
    }

    /// Reads and authenticates the bundle without making it this store's.
    ///
    /// [`Self::fetch`] is this, the settlement of a lost write and the remembering. A caller that
    /// has still to decide whether what came back is acceptable wants this one: a bundle adopted
    /// before it was judged would leave this store holding the very thing it went on to refuse,
    /// and the refusal would then pass on the next attempt.
    async fn read(&self, seed: &RecoverySeed) -> Result<(SyncPosition, RecoveryBundle)> {
        let (position, ciphertext) = self
            .service
            .fetch(bundle_collection(&self.context))
            .await
            .map_err(RecoveryError::Service)?;
        diagnose(self.position, position)?;
        let key = seed.bundle_key_for(&self.context)?;
        let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &ciphertext)
            .map_err(|_| RecoveryError::BundleNotAuthentic)?;
        Ok((position, bundle))
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
        if let Some(Lost::Outstanding(outstanding)) = &self.lost {
            return Err(RecoveryError::BundleWriteUnsettled {
                sent: outstanding.digest,
            });
        }
        let expected = self.position;
        // The bundle being written has to be the one this store last authenticated, changed. A
        // snapshot from before somebody else's write would otherwise be committed against this
        // store's newer token and take their change with it.
        if self
            .held
            .as_ref()
            .is_some_and(|held| held.revision.get() != bundle.revision.get())
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
        let sent = digest_of(&candidate)?;
        let signed_at_ms = now_ms.get();
        let request_id = kr_transport::random::fresh_uuid_v4().map_err(ClientError::from)?;
        // Recorded before the call and not after it, because the case this is for is the one where
        // nothing comes back: a store that noted the write only on the way out would have no
        // record of a write that was dropped between here and the service, and no identity to end
        // it by.
        self.lost = Some(Lost::Outstanding(Box::new(Outstanding {
            request_id,
            signed_at_ms,
            expected,
            digest: sent,
            bundle: candidate.clone(),
        })));
        match self
            .service
            .compare_exchange(
                bundle_collection(&self.context),
                request_id,
                signed_at_ms,
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
                self.lost = None;
                self.position = Some(position);
                self.held = Some(candidate.clone());
                *bundle = candidate;
                Ok(position)
            }
            Ok(SyncExchanged::Refused { retained }) => {
                // A refusal is an answer: the service compared, the comparison did not hold, and
                // the bundle this device sent was not written. Nothing is outstanding.
                self.lost = None;
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
    /// store that made the write keeps the record of it, refuses to write again while it stands,
    /// and [`Self::end_lost_write`] on that store is what ends it. A migration abandoned part-way,
    /// by a failure or by a dropped future, leaves that record where a retry will find it.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::UnknownServiceOrigin`] when the kit does not name this store's
    /// origin, [`RecoveryError::KitLocatorMismatch`] when it names another bundle,
    /// [`RecoveryError::MigrationWouldLoseAnOrigin`] for a kit that names several origins,
    /// [`RecoveryError::KitIsForAnotherSeed`] when the kit and the seed disagree,
    /// [`RecoveryError::BundleConflict`] when the old location has moved on,
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
        let destination = moved.context.clone();
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
        // the one failure this call cannot undo.
        let origins = vec![destination.service_origin.clone()];
        let updated_kit =
            kr_crypto::kdf::RecoverySeed::to_kit(seed, origins, destination.bundle_locator.clone());
        drop(crate::recovery::kit::render(&updated_kit)?);

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
        let known = self.held.as_ref().map(|held| held.revision.get());
        let (_, current) = self.read(seed).await?;
        if &current != bundle || known.is_some_and(|known| known > current.revision.get()) {
            return Err(RecoveryError::BundleConflict {
                expected: self.position,
                retained: None,
            });
        }
        let origin = self.context.clone();
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
        *self = moved.clone();
        Ok(Migrated {
            record: MigrationRecord {
                from: origin,
                to: destination,
                bundle_revision: bundle.revision.get(),
                bundle_position: position,
                verified_at_ms: now_ms,
            },
            updated_kit,
        })
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

/// Returns the digest of one bundle's canonical bytes.
///
/// It is how a read recognises a write this device lost the answer to. The bundle is a small value
/// and the comparison could hold the whole of it, but the digest is the part that has to be kept
/// while the answer is outstanding, and keeping only that is keeping only what the question needs.
///
/// # Errors
///
/// Returns [`RecoveryError::Cbor`] when the bundle cannot be encoded.
fn digest_of(bundle: &RecoveryBundle) -> Result<Digest256> {
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(bundle)?,
    )))
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
