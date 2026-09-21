//! The environment's backup service: what this host has produced, staged and accounted for.
//!
//! The producer itself is `kr_crypto::backup`: it encrypts the objects, wraps the keys, signs the
//! manifest and builds the descriptor. Object storage is the storage service's. What this module
//! owns is the part in between, which is the part a crash can lose:
//!
//! * **`backup.sqlite`.** Generation records, object rows, upload state and an outbox, each write
//!   committed in the same transaction as the state transition it belongs to. See
//!   [`store::BackupStore`].
//! * **Reconciliation at startup.** What is still authorised resumes; what is not is cancelled;
//!   and a publication that was dispatched and never answered is recorded as *unknown*, because
//!   that is what this host knows about it.
//! * **Verification before a restore.** The owner's enrolment, the writer's signature over the
//!   publication, and the generation against the trusted checkpoint, in that order. A restore that
//!   has not passed all three does not start.
//! * **Data only.** [`RestoreRequest::admit`] answers every material kind a caller asks for, and
//!   refuses each one that would recreate authority rather than return data. The answer is
//!   `kr_crypto::backup`'s, so a host and a device cannot disagree about it.
//! * **The privacy hook.** [`BackupService`] implements `kr_worker::privacy::PrivacySubsystem`
//!   directly: it fences the outbox at the generation, takes back what has not been dispatched,
//!   removes the staged ciphertext it holds, reports what is still in flight, names what it keeps,
//!   and shows already-uploaded archives as retained artifacts. It marks them **not** deletable,
//!   because this host holds no route through which it could ask a service to remove one; the
//!   separately authorised deletion action section 24 asks for is not built here.
//!
//! # What this host never writes down
//!
//! An object key, a plaintext or a filename. The keys stay in the producer's hands until the
//! generation is sealed; the filenames are inside the encrypted manifest. `backup.sqlite` holds
//! identities, hashes, sizes, states and the paths of ciphertext.

pub mod store;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_crypto::backup::{
    GenerationExpectation, Material, RestoreAdmissions, RestoreGeneration, SealedArchive,
    StagedObject, admit_for_restore,
};
use kr_protocol::archive::{
    ArchiveCheckpoint, BackupGenerationPublication, BackupWriterRecord, BackupWriterRecordPayload,
};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{AuthorisationKey, KeyId, TimestampMs};
use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
};

use crate::backup::store::{
    BackupStore, FenceRelease, GenerationRecord, GenerationState, ObjectRecord, ObjectState,
    Obligation, ObligationKind, OutboxEntry, PrivacyRequest, PrivacyStatus, Step,
};
use crate::error::{ControllerError, Result};

/// The stable name this subsystem is reported under, which is section 24's.
pub const SUBSYSTEM_NAME: &str = "backup";

/// The privacy steps this host can fail to carry out in a process, for the guard that counts them.
///
/// They name steps, never pieces of cleanup. What is owed lives in the store; these say only that
/// this process tried a step and the store would not take it, which is a reason to report work
/// outstanding and never a reason to report any of it done.
const FENCE_STEP: &str = "raise the backup privacy fence";
const CANCEL_STEP: &str = "cancel undispatched backup work";
const REMOVE_STEP: &str = "remove staged backup ciphertext";

/// One generation this host has admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The outbox entry that will carry it.
    pub sequence: u64,
    /// How many objects were staged, the encrypted manifest included.
    pub staged_objects: usize,
    /// How many bytes of ciphertext are on this host for it.
    pub staged_bytes: u64,
}

/// Everything that keeps backup cleanup from being complete, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutstandingWork {
    /// Where this host stands with privacy mode.
    pub status: PrivacyStatus,
    /// Each piece of cleanup a fence wrote down and this host has not finished.
    pub obligations: Vec<Obligation>,
    /// How many attempts had left this host and have not been answered.
    pub dispatched_attempts: u64,
    /// Privacy steps this process tried and the store would not take.
    ///
    /// They last as long as this process. A step that later works clears its own entry and no
    /// other, and nothing here ever discharges a durable obligation.
    pub failed_steps: Vec<&'static str>,
}

impl OutstandingWork {
    /// Returns true when nothing is left: no fence, no obligation, no unanswered attempt.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.obligations.is_empty()
            && self.failed_steps.is_empty()
            // Before a fence exists, an attempt that has left this host is the outstanding work.
            // Once one does, that attempt has an obligation of its own and is counted there.
            && (self.status.inhibited_at().is_some() || self.dispatched_attempts == 0)
    }

    /// Returns a line per outstanding thing, for a report a person reads.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.obligations.iter().map(Obligation::describe).collect();
        if self.dispatched_attempts > 0 {
            lines.push(format!(
                "{} backup attempts have left this host and have not been answered",
                self.dispatched_attempts
            ));
        }
        for step in &self.failed_steps {
            lines.push(format!("this host could not {step}"));
        }
        lines
    }
}

/// What startup reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Generations whose work this host may still do, and has put back in hand.
    pub resumed: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations this host may no longer publish, which are cancelled.
    pub no_longer_authorised: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations whose publication left this host and was never answered.
    pub outcome_unknown: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations with an attempt that left this host and has not been answered.
    ///
    /// A restart does not end that wait. Only evidence about the attempt itself does: the service
    /// answering, or the caller establishing that the transfer stopped. Until then the attempt and
    /// whatever cleanup names it are both still there, which is what keeps this host from
    /// reporting a reconciliation it has not made.
    pub unanswered: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations left where they are because privacy mode fenced this host.
    ///
    /// A restart does not un-fence work a fence stopped. They are neither resumed nor settled:
    /// turning privacy mode off is what decides what becomes of them.
    pub fenced: Vec<(ArchiveId, BackupGeneration)>,
}

impl Reconciliation {
    /// Returns true when there was nothing to reconcile.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resumed.is_empty()
            && self.no_longer_authorised.is_empty()
            && self.outcome_unknown.is_empty()
            && self.unanswered.is_empty()
            && self.fenced.is_empty()
    }
}

/// One restore, before anything of it is read.
#[derive(Clone, Debug)]
pub struct RestoreRequest<'a> {
    /// The archive this restore means to read.
    ///
    /// The caller's own expectation rather than the publication's claim. Without it, another valid
    /// enrolment and publication under the same owner would pass every signature check and restore
    /// a different collection.
    pub archive_id: ArchiveId,
    /// The publication the service handed back.
    pub publication: &'a BackupGenerationPublication,
    /// The size of the descriptor as it arrived, which is the quantity section 20 bounds.
    pub descriptor_len: usize,
    /// The owner's enrolment of the writer, as the owner signed it.
    pub enrolment: &'a BackupWriterRecord,
    /// The owner's authorisation key, which the enrolment is verified against.
    pub owner_key: &'a AuthorisationKey,
    /// The writer's signing key, from the owner's recovery bundle and nowhere else.
    pub writer_key: &'a AuthorisationKey,
    /// What the generation the service offered is compared against.
    pub generation: GenerationExpectation<'a>,
}

/// A restore whose authority and generation have both been established.
///
/// There is no way to build one except through [`RestoreRequest::verify`], so a caller cannot
/// reach the reading half without having passed the checking half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRestore {
    archive_id: ArchiveId,
    writer_key_id: KeyId,
    writer_revision: u64,
    generation: RestoreGeneration,
    /// The generation and manifest the publication's signature actually covered.
    ///
    /// The archive that is opened is opened against this, so a second valid generation of the same
    /// collection cannot be substituted for the one whose authority was established.
    pinned: ArchiveCheckpoint,
}

impl VerifiedRestore {
    /// Returns the archive whose authority and generation were established.
    #[must_use]
    pub const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    /// Returns the writer whose signature was verified.
    #[must_use]
    pub const fn writer_key_id(&self) -> KeyId {
        self.writer_key_id
    }

    /// Returns the enrolment revision the owner signed.
    #[must_use]
    pub const fn writer_revision(&self) -> u64 {
        self.writer_revision
    }

    /// Returns where the generation stands against the trusted checkpoint, which a restore
    /// displays.
    #[must_use]
    pub const fn generation(&self) -> RestoreGeneration {
        self.generation
    }

    /// Returns what this restore hands to `kr_crypto::backup::open_archive`.
    ///
    /// It takes no argument, and that is the point. It is built entirely from what verification
    /// established: the archive whose authority was checked, and the exact generation and
    /// encrypted-manifest hash the publication's signature covered. Opening against it therefore
    /// admits one archive at one generation with one manifest, so a second genuine generation of
    /// the same collection cannot be substituted for the one that was verified.
    #[must_use]
    pub const fn expectation(&self) -> kr_crypto::backup::ArchiveExpectation<'_> {
        kr_crypto::backup::ArchiveExpectation {
            archive_id: self.archive_id,
            generation: GenerationExpectation::Exactly(&self.pinned),
        }
    }
}

impl RestoreRequest<'_> {
    /// Verifies the owner's enrolment, the writer's signature and the generation, in that order.
    ///
    /// The order matters. The enrolment is what says this writer may publish for this archive at
    /// all, and it is the owner's own signature; the publication's signature is then checked
    /// against the key that enrolment names, which is also the key the recovery bundle supplied;
    /// and the generation is compared with the checkpoint last. A restore that started reading
    /// before any of the three would be reading an archive nothing had vouched for.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when the enrolment, the writer or the
    /// signature does not hold, and [`ControllerError::InvalidArgument`] when the generation is
    /// one the checkpoint refuses.
    pub fn verify(&self) -> Result<VerifiedRestore> {
        let payload = &self.enrolment.payload;
        // The collection the caller meant, before anything else. A genuine enrolment and a genuine
        // publication for another archive of the same owner would otherwise pass.
        if self.publication.payload.descriptor.archive_id != self.archive_id
            || payload.archive_id != self.archive_id
        {
            return Err(ControllerError::PermissionDenied {
                detail: "that publication is for another archive than the one being restored"
                    .to_owned(),
            });
        }
        // 1. The owner's own statement about who may write this collection.
        let transcript = enrolment_transcript(payload)?;
        kr_crypto::sign::verify(self.owner_key, &transcript, &self.enrolment.signature).map_err(
            |_| ControllerError::PermissionDenied {
                detail: "the backup writer enrolment is not signed by this collection's owner"
                    .to_owned(),
            },
        )?;
        if payload.owner_key_id != authorisation_key_id(self.owner_key) {
            return Err(ControllerError::PermissionDenied {
                detail: "the backup writer enrolment names another owner key".to_owned(),
            });
        }
        // 2. The writer key the bundle supplied is the one the owner enrolled, and it is its own
        //    identifier. A key that named itself something else would pass the enrolment check and
        //    verify nothing.
        let writer_key_id = authorisation_key_id(self.writer_key);
        if payload.writer.writer_key_id != writer_key_id
            || payload.writer.signing_key != *self.writer_key
        {
            return Err(ControllerError::PermissionDenied {
                detail: "the writer key this restore holds is not the one the owner enrolled"
                    .to_owned(),
            });
        }
        // 3. The publication's own structure, and then its signature under that writer.
        self.publication
            .check_structure(self.descriptor_len, payload)
            .map_err(|error| ControllerError::PermissionDenied {
                detail: error.to_string(),
            })?;
        let transcript = publication_transcript(self.publication)?;
        kr_crypto::sign::verify(self.writer_key, &transcript, &self.publication.signature)
            .map_err(|_| ControllerError::PermissionDenied {
                detail: "the backup generation publication is not signed by its writer".to_owned(),
            })?;

        // 4. The generation, against the checkpoint the owner trusts.
        let generation =
            RestoreGeneration::against(&self.publication.payload.descriptor, self.generation);
        if !generation.is_admissible() {
            return Err(ControllerError::InvalidArgument(generation.describe()));
        }
        let descriptor = &self.publication.payload.descriptor;
        Ok(VerifiedRestore {
            archive_id: descriptor.archive_id,
            writer_key_id,
            writer_revision: payload.writer_revision.get(),
            generation,
            pinned: ArchiveCheckpoint {
                archive_id: descriptor.archive_id,
                backup_generation: descriptor.backup_generation,
                encrypted_manifest_hash: descriptor.encrypted_manifest.encrypted_object_hash,
                verified_at_ms: self.publication.payload.published_at_ms,
            },
        })
    }

    /// Answers every material kind a caller asked to restore.
    ///
    /// Section 24: *restore data only, not reusable host-control keys.* The answer is
    /// `kr_crypto::backup`'s, so this host and the device that made the backup give the same one,
    /// and every refusal carries the reason rather than being a silent omission.
    #[must_use]
    pub fn admit(candidates: &[Material]) -> RestoreAdmissions {
        admit_for_restore(candidates)
    }
}

/// The environment's backup service.
///
/// It owns `backup.sqlite` and the staging directory beside it. Its calls talk to SQLite and to
/// files, so a caller on an asynchronous runtime runs them on a blocking task.
#[derive(Debug)]
pub struct BackupService {
    store: Mutex<BackupStore>,
    failed_steps: Mutex<BTreeSet<&'static str>>,
}

impl BackupService {
    /// Opens the service beside `state_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be opened.
    pub fn open(state_dir: &Path) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(BackupStore::open(state_dir)?),
            failed_steps: Mutex::new(BTreeSet::new()),
        })
    }

    /// Opens a service whose store exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be created.
    pub fn in_memory(staging_root: &Path) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(BackupStore::in_memory(staging_root)?),
            failed_steps: Mutex::new(BTreeSet::new()),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, BackupStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records that one privacy step could not be carried out in this process.
    ///
    /// This is a guard, not an account. It can only make this subsystem report *more* work than
    /// the store does, never less, and nothing it holds discharges a durable obligation. Its whole
    /// job is the window the store owns nothing in: a request this host could not even accept
    /// leaves no row behind, so without the guard a failed enabling would look like a host with
    /// nothing to do.
    fn note_step_failed(&self, step: &'static str) {
        self.failed_steps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(step);
    }

    /// Records that one privacy step did, in the end, do what it was asked.
    ///
    /// Only that step. Another step succeeding says nothing about this one, and a read that works
    /// says nothing about a write that did not.
    fn note_step_succeeded(&self, step: &'static str) {
        self.failed_steps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(step);
    }

    fn failed_steps(&self) -> BTreeSet<&'static str> {
        self.failed_steps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns every piece of cleanup privacy mode is owed that this host has not done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read. The error
    /// is the answer: a host that cannot read what it owes does not owe nothing.
    pub fn obligations(&self) -> Result<Vec<Obligation>> {
        self.store().obligations()
    }

    /// Returns where this host stands with privacy mode.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_status(&self) -> Result<PrivacyStatus> {
        self.store().privacy_status()
    }

    /// Returns one privacy request, if this host accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_request(&self, privacy_generation: u64) -> Result<Option<PrivacyRequest>> {
        self.store().privacy_request(privacy_generation)
    }

    /// Returns the directory this service's staged ciphertext lives in, and owns exclusively.
    #[must_use]
    pub fn staging_root(&self) -> PathBuf {
        self.store().staging_root().to_path_buf()
    }

    /// Accepts privacy mode's request to stop backup production, before the fence is attempted.
    ///
    /// The caller takes this step first and keeps the request until it succeeds: a store that
    /// cannot commit it cannot hold it at all, so the request stays the caller's to replay. Once
    /// it is accepted, this host is inhibited whatever happens next.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the generation is older than the one in
    /// force, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn accept_privacy_request(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<PrivacyRequest> {
        self.store()
            .accept_privacy_request(generation.get(), now_ms)
    }

    /// Accepts privacy mode's request and raises the fence it asks for.
    ///
    /// This is the step behind [`PrivacySubsystem::fence`], with its error kept. The trait's
    /// method has nowhere to put one and must return a count, so it turns a failure into a guard
    /// that keeps this subsystem reporting work outstanding; a caller that can act on the reason
    /// calls this instead.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store will not accept the request
    /// or raise the fence. A request that could not be accepted is the caller's to keep and
    /// replay: no design can persist it in the same database that would not take it.
    pub fn raise_fence(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Fenced> {
        let mut store = self.store();
        let items = store
            .outbox()?
            .iter()
            .filter(|entry| !entry.dispatched)
            .count() as u64;
        store.accept_privacy_request(generation.get(), now_ms)?;
        store.activate_fence(generation.get(), now_ms)?;
        Ok(Fenced { queues: 1, items })
    }

    /// Takes back every admitted, undispatched piece of backup work, with its error kept.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_undispatched_work(&self, now_ms: TimestampMs) -> Result<Cancelled> {
        let (undispatched, in_flight) = self
            .store()
            .cancel_undispatched(now_ms, "privacy mode cancelled undispatched backup work")?;
        Ok(Cancelled {
            undispatched,
            in_flight,
        })
    }

    /// Carries out the cleanup a fence wrote down, and reports what it actually removed.
    ///
    /// Three passes, in this order, because each one can create work for the next. The staging
    /// walk first, since it turns ciphertext no row names into removals of its own; then the
    /// removals; then whatever bookkeeping is now ready. The obligations are re-read between
    /// passes rather than carried over, so every step acts on the durable list as it stands.
    ///
    /// Each removal follows one order: read the obligation, unlink the file, flush its directory
    /// where the platform allows it, and commit the absence together with the discharge. A stop
    /// between the unlink and the commit leaves the obligation, and the retry accepts a file that
    /// is already gone and finishes the store's half.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    /// A target this host could not remove is not an error: its obligation stays, with the reason
    /// recorded beside it, and cleanup is simply not complete.
    pub fn run_cleanup(&self, now_ms: TimestampMs) -> Result<Removed> {
        let mut removed = Removed::default();
        let mut store = self.store();
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::ScanStaging)
        {
            match unregistered_staged_files(&store) {
                Ok(found) => {
                    let records = store.record_staging_scan(&obligation, &found, now_ms)?;
                    removed.records = removed.records.saturating_add(records);
                }
                Err(error) => {
                    // A directory this host cannot read is a directory it cannot say is empty.
                    store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                }
            }
        }
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
        {
            // The staging root is absolute, and a registered path is absolute with it, so an
            // already-rooted path is never rooted a second time. Only the walk's own findings are
            // relative, and they are relative to this root.
            let Some(path) = obligation.staged_path.as_ref().map(|path| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    store.staging_root().join(path)
                }
            }) else {
                continue;
            };
            let bytes = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            };
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                // The file is already gone. The obligation is still this host's to end, because
                // the row that says the ciphertext is here has not been written over yet.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                    continue;
                }
            }
            // The name is gone from the directory; on platforms that can, the directory entry is
            // flushed so losing power cannot bring it back. A flush this host could not make is
            // not a removal it may report: losing power could return the name, and the obligation
            // that would find it again would be gone. On Windows the flush is a stated no-op, so
            // there is nothing to fail there.
            if let Err(error) = sync_directory(&path) {
                store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                continue;
            }
            let records = store.note_object_unlinked(&obligation)?;
            removed.bytes = removed.bytes.saturating_add(bytes);
            removed.records = removed.records.saturating_add(records);
        }
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::FinishGeneration)
        {
            removed.records = removed
                .records
                .saturating_add(store.finish_generation(&obligation)?);
        }
        Ok(removed)
    }

    /// Returns everything that keeps this subsystem from reporting its cleanup complete.
    ///
    /// The whole answer, with its error kept, rather than the single count the privacy contract
    /// takes. A caller that has to explain *why* backup cleanup is not finished reads this.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outstanding_work(&self) -> Result<OutstandingWork> {
        let store = self.store();
        let status = store.privacy_status()?;
        let obligations = store.obligations()?;
        let dispatched = store
            .outbox()?
            .iter()
            .filter(|entry| entry.dispatched)
            .count() as u64;
        Ok(OutstandingWork {
            status,
            obligations,
            dispatched_attempts: dispatched,
            failed_steps: self.failed_steps().into_iter().collect(),
        })
    }

    #[doc(hidden)]
    pub fn set_query_only(&self, query_only: bool) -> Result<()> {
        self.store().set_query_only(query_only)
    }

    /// Enrols a backup writer for one archive.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn enrol_writer(
        &self,
        writer_key_id: KeyId,
        archive_id: ArchiveId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store().enrol_writer(writer_key_id, archive_id, now_ms)
    }

    /// Retires a backup writer for one archive, so its unfinished generations there stop being
    /// authorised. Its enrolments for other collections are untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn retire_writer(
        &self,
        archive_id: ArchiveId,
        writer_key_id: KeyId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store()
            .retire_writer(archive_id, writer_key_id, now_ms)
    }

    /// Releases one privacy fence, so backup production is admitted again under a new generation.
    ///
    /// It names both generations, and it refuses while that fence still has cleanup outstanding:
    /// backup production does not resume into a scope this host has not finished clearing, because
    /// new content admitted there would join work that is still being removed. A caller takes this
    /// step after `PrivacyMode::disable`, and takes it again once the cleanup finishes.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the resumed generation is not newer than
    /// the fence, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn release_fence(
        &self,
        fence_generation: PrivacyGeneration,
        resumed_generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<FenceRelease> {
        self.store()
            .release_fence(fence_generation.get(), resumed_generation.get(), now_ms)
    }

    /// Stages one sealed generation and records it.
    ///
    /// The ciphertext is written first and the rows second, so a crash between them leaves files
    /// nothing claims rather than rows naming files that are not there: a sweep can remove the
    /// first, and nothing can recover from the second.
    ///
    /// The object keys are never written. They are in the [`StagedObject`]s the caller holds, and
    /// they stop mattering the moment the generation is sealed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the ciphertext cannot be written or
    /// the store refuses the transaction.
    pub fn admit(
        &self,
        sealed: &SealedArchive,
        objects: &[StagedObject],
        writer_key_id: KeyId,
        privacy_generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Admitted> {
        let archive_id = sealed.descriptor.archive_id;
        let backup_generation = sealed.descriptor.backup_generation;
        let mut store = self.store();

        // Privacy mode stopped content-bearing backup production at a generation, and it stays
        // stopped. A host that recorded a fence and then admitted more work would have fenced
        // nothing.
        if let Some(fenced_at) = store.fenced_at()? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!("backup production is fenced at privacy generation {fenced_at}"),
            });
        }
        // Authority is the pair: this writer, this archive.
        if !store.authorises(archive_id, writer_key_id)? {
            return Err(ControllerError::PermissionDenied {
                detail: "this host holds no enrolment of that writer for that archive".to_owned(),
            });
        }
        // A generation already admitted is not admitted again. Writing its ciphertext first and
        // finding out second would overwrite the staged manifest of the archive already recorded.
        if store.generation(archive_id, backup_generation)?.is_some() {
            return Err(ControllerError::InvalidArgument(
                "that backup generation is already admitted on this host".to_owned(),
            ));
        }
        // The encrypted manifest is staged under its own object identifier, so a member that
        // claimed it would have them write over each other.
        let manifest_object_id = sealed.descriptor.encrypted_manifest.object_id;
        if objects
            .iter()
            .any(|staged| staged.object_id() == manifest_object_id)
        {
            return Err(ControllerError::InvalidArgument(
                "a member object under the encrypted manifest's own identifier".to_owned(),
            ));
        }
        // The writer is the one that signed the manifest, not a label the caller chose. Admitting
        // work under a writer that did not sign it would account for it under an authority it does
        // not have.
        if sealed.signed_manifest.writer_key_id != writer_key_id {
            return Err(ControllerError::PermissionDenied {
                detail: "that generation's manifest is signed by another writer".to_owned(),
            });
        }
        // And the objects are the manifest's members, exactly. A caller that admitted fewer than
        // the manifest names would stage an archive this host could complete and publish while
        // some of its members had never been uploaded at all.
        let members = &sealed.signed_manifest.manifest.objects;
        if members.len() != objects.len()
            || !members.iter().all(|entry| {
                objects
                    .iter()
                    .any(|staged| staged.reference() == &entry.object)
            })
        {
            return Err(ControllerError::InvalidArgument(
                "the objects offered are not the members the signed manifest names".to_owned(),
            ));
        }

        let mut rows: Vec<ObjectRecord> = Vec::with_capacity(objects.len() + 1);
        let mut staged_bytes = 0u64;
        let mut written_paths = Vec::new();
        for staged in objects {
            let path = store.staged_path(archive_id, backup_generation, staged.object_id());
            if let Err(error) = write_staged(&path, staged.bytes()) {
                cleanup_staged(&written_paths);
                return Err(error);
            }
            written_paths.push(path.clone());
            staged_bytes = staged_bytes.saturating_add(staged.bytes().len() as u64);
            rows.push(ObjectRecord {
                archive_id,
                backup_generation,
                object_id: staged.object_id(),
                encrypted_object_hash: staged.reference().encrypted_object_hash,
                encrypted_len: staged.reference().encrypted_len.get(),
                staged_path: path,
                uploaded_bytes: 0,
                state: ObjectState::Staged,
            });
        }
        // The encrypted manifest is an object like any other, so the upload accounting covers it
        // and a generation is complete only when it has arrived too.
        let manifest = &sealed.descriptor.encrypted_manifest;
        let manifest_path = store.staged_path(archive_id, backup_generation, manifest.object_id);
        if let Err(error) = write_staged(&manifest_path, &sealed.encrypted_manifest) {
            cleanup_staged(&written_paths);
            return Err(error);
        }
        written_paths.push(manifest_path.clone());
        staged_bytes = staged_bytes.saturating_add(sealed.encrypted_manifest.len() as u64);
        rows.push(ObjectRecord {
            archive_id,
            backup_generation,
            object_id: manifest.object_id,
            encrypted_object_hash: manifest.encrypted_object_hash,
            encrypted_len: manifest.encrypted_len.get(),
            staged_path: manifest_path,
            uploaded_bytes: 0,
            state: ObjectState::Staged,
        });

        let record = GenerationRecord {
            archive_id,
            backup_generation,
            state: GenerationState::Staging,
            writer_key_id,
            privacy_generation: privacy_generation.get(),
            descriptor: Some(sealed.descriptor_bytes.clone()),
            created_at_ms: now_ms,
            settled_at_ms: None,
            detail: None,
        };
        let sequence = match store.admit(&record, &rows, now_ms) {
            Ok(sequence) => sequence,
            Err(error) => {
                cleanup_staged(&written_paths);
                return Err(error);
            }
        };
        Ok(Admitted {
            archive_id,
            backup_generation,
            sequence,
            staged_objects: rows.len(),
            staged_bytes,
        })
    }

    /// Records that one outbox entry has been handed to the service.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_dispatched(&self, sequence: u64) -> Result<()> {
        let mut store = self.store();
        // The fence is what stops a queue that already holds content from reaching anything
        // outside this host. Recording the number and then letting an entry go would be a fence
        // in name only.
        if let Some(fenced_at) = store.fenced_at()? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!("backup production is fenced at privacy generation {fenced_at}"),
            });
        }
        store.note_dispatched(sequence)
    }

    /// Records that one object's bytes reached the service.
    ///
    /// Returns true when the generation has no object left to arrive. That is a fact about the
    /// objects, not about the call: an acknowledgement repeated after the upload had finished
    /// returns true again and changes nothing, whether the generation has since been published,
    /// cancelled or recorded with an outcome nobody knows.
    ///
    /// A finished upload ordinarily enqueues the publish step in the same transaction. A
    /// generation privacy mode cancelled, or one finishing while production is fenced, gets no
    /// publication at all: the upload leaves the outbox and nothing takes its place, so a true
    /// here is not a promise that anything is waiting to be published.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_object_uploaded(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        now_ms: TimestampMs,
    ) -> Result<bool> {
        self.store()
            .note_object_uploaded(archive_id, backup_generation, object_id, now_ms)
    }

    /// Records that the service accepted a generation's publication.
    ///
    /// `produced_under` is the privacy generation the work that produced this result was admitted
    /// under, as the caller reports it. Every other term of the decision is the store's, read
    /// inside the transaction that records the result: the generation this host actually admitted
    /// the work under, the privacy generation in force, and whether a fence stands. A caller that
    /// could supply those could relabel work privacy mode had already drawn a line under, which is
    /// the one thing the late-result rule exists to stop.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the result belongs to another privacy generation
    /// or a fence stands, and [`ControllerError::RegistryUnavailable`] when the store refuses the
    /// write.
    pub fn note_published(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        produced_under: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store()
            .note_published(archive_id, backup_generation, produced_under.get(), now_ms)
    }

    /// Records that a generation's work stopped and this host cannot establish what became of it.
    ///
    /// It is a statement about two things, and a caller makes it only when both hold: the transfer
    /// has ended, and the answer never arrived. From then on the generation is not in flight - so
    /// it does not hold privacy mode's reconciliation open for ever - and it *is* a copy that may
    /// be at the service, so [`PrivacySubsystem::exported`] shows it as one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_outcome_unknown(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        detail: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        // Both halves of the caller's statement are recorded: the attempt has ended, so its row
        // and obligation go, and what became of it remotely is written down as unknown.
        self.store().settle_ended_attempts(
            archive_id,
            backup_generation,
            GenerationState::Unknown,
            Some(detail),
            now_ms,
        )
    }

    /// Resolves whatever an earlier daemon left unfinished.
    ///
    /// A generation that has already settled is left exactly as it is. An attempt of it that had
    /// left this host and was never answered is **not** ended here and is listed instead: a
    /// restart is not evidence about what the service did, and a wait ended on the strength of
    /// one would be a cleanup reported over work still out there. Only an answer, or a caller
    /// establishing that the transfer stopped, settles such an attempt.
    ///
    /// For everything still unfinished there are four answers, in this order:
    ///
    /// * A generation whose *publication* was dispatched and never answered is recorded as
    ///   **unknown**, and that is decided first. The service may hold it and may not, and a host
    ///   that wrote either answer would be writing something it does not know; section 23 never
    ///   retries that automatically, and retiring the writer afterwards must not rewrite an
    ///   outcome this host never learned.
    /// * A generation whose writer this host no longer holds an enrolment for, **for that
    ///   archive**, is **cancelled**. It is work this host may not do, whatever state it was left
    ///   in.
    /// * A generation privacy mode fenced stays **fenced**. A restart does not un-fence work a
    ///   fence stopped.
    /// * Everything else **resumes**. A dispatched upload is put back in hand: the same object
    ///   under the same identity and hash is the same object, so sending it again is not a second
    ///   publication.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub fn reconcile(&self, now_ms: TimestampMs) -> Result<Reconciliation> {
        let mut store = self.store();
        let authorised = store.authorised_writers()?;
        let fenced = store.fenced_at()?;
        let generations = store.generations()?;
        let outbox = store.outbox()?;
        let mut outcome = Reconciliation::default();
        for record in generations {
            let entries: Vec<&OutboxEntry> = outbox
                .iter()
                .filter(|entry| {
                    entry.archive_id == record.archive_id
                        && entry.backup_generation == record.backup_generation
                })
                .collect();
            if record.state.is_settled() {
                // Nothing is reconstructed here and nothing is ended here. What privacy mode is
                // owed was written down when its fence went up, one row per target, and those
                // rows are what a restart reads back. An attempt that had already left this host
                // is still unanswered: reopening a store is not evidence that it stopped, and a
                // restart that cleared it would report a cleanup nobody had followed.
                if entries.iter().any(|entry| entry.dispatched) {
                    outcome
                        .unanswered
                        .push((record.archive_id, record.backup_generation));
                }
                continue;
            }
            // An uncertain outcome is settled as uncertain even when the writer has since been
            // retired: retiring a writer stops future work and does not rewrite what this host
            // already dispatched and never heard back about.
            if entries
                .iter()
                .any(|entry| entry.dispatched && entry.step == Step::Publish)
            {
                store.settle(
                    record.archive_id,
                    record.backup_generation,
                    GenerationState::Unknown,
                    Some(
                        "its publication left this host and was never answered, so whether the \
                         service holds it is not something this host can say",
                    ),
                    now_ms,
                )?;
                outcome
                    .outcome_unknown
                    .push((record.archive_id, record.backup_generation));
                outcome
                    .unanswered
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            // Authority is the pair. A writer enrolled for one archive does not authorise
            // unfinished work for another.
            if !authorised.iter().any(|(archive, writer)| {
                *archive == record.archive_id && *writer == record.writer_key_id
            }) {
                store.settle(
                    record.archive_id,
                    record.backup_generation,
                    GenerationState::Cancelled,
                    Some("this host no longer holds an enrolment of that writer for that archive"),
                    now_ms,
                )?;
                outcome
                    .no_longer_authorised
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            // A fence stops what it stopped. A restart does not un-fence undispatched work.
            if fenced.is_some() {
                outcome
                    .fenced
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            for entry in &entries {
                if entry.dispatched {
                    store.note_undispatched(entry.sequence)?;
                }
            }
            store.note_object_resumable(record.archive_id, record.backup_generation)?;
            outcome
                .resumed
                .push((record.archive_id, record.backup_generation));
        }
        Ok(outcome)
    }

    /// Returns every generation this host has a record of, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generations(&self) -> Result<Vec<GenerationRecord>> {
        self.store().generations()
    }

    /// Returns one generation's record.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generation(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<GenerationRecord>> {
        self.store().generation(archive_id, backup_generation)
    }

    /// Returns one generation's objects.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn objects(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Vec<ObjectRecord>> {
        self.store().objects(archive_id, backup_generation)
    }

    /// Returns the outbox, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>> {
        self.store().outbox()
    }

    /// Returns the privacy generation this host recorded a fence at, if it has.
    ///
    /// It is read back from the store rather than held in memory, so a restart comes back fenced
    /// rather than dispatching the entries the fence had just stopped.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn fenced_at(&self) -> Result<Option<u64>> {
        self.store().fenced_at()
    }
}

/// Returns every file under this store's staging directory that no object row names.
///
/// Ciphertext is written before the row that names it, so a stop in between leaves a file nothing
/// accounts for. Only the directory this store owns is walked, and a directory it cannot read is
/// an error rather than an empty answer: "there is nothing there" and "this host cannot look" are
/// not the same finding.
fn unregistered_staged_files(store: &BackupStore) -> Result<Vec<PathBuf>> {
    let registered: std::collections::BTreeSet<PathBuf> =
        store.registered_staged_paths()?.into_iter().collect();
    let mut found = Vec::new();
    let mut directories = vec![store.staging_root().to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ControllerError::registry(error)),
        };
        for entry in entries {
            let entry = entry.map_err(ControllerError::registry)?;
            let path = entry.path();
            let kind = entry.file_type().map_err(ControllerError::registry)?;
            if kind.is_dir() {
                directories.push(path);
            } else if !registered.contains(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Removes staged ciphertext files that were written before staging failed.
fn cleanup_staged(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// Writes one staged object's ciphertext, durably, before any row names it.
///
/// Created exclusively, flushed, and its directory entry flushed, so a row committed afterwards
/// never names a file that losing power would take away. Exclusive creation is also what stops a
/// second admission writing over ciphertext an earlier one is still accounting for.
fn write_staged(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let Some(parent) = path.parent() else {
        return Err(ControllerError::registry(
            "a staged object has no directory",
        ));
    };
    std::fs::create_dir_all(parent).map_err(ControllerError::registry)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(ControllerError::registry)?;
    file.write_all(bytes).map_err(ControllerError::registry)?;
    file.flush().map_err(ControllerError::registry)?;
    file.sync_all().map_err(ControllerError::registry)?;
    drop(file);
    // The bytes are on the disk; the name that reaches them may not be until the directory that
    // holds it is flushed, nor the directory itself until *its* parent is.
    sync_directory(path)
}

/// Flushes the directory entry of `path` and of every directory made for it under the staging root.
///
/// A file flushed into a directory that was itself created and never flushed is a file whose name
/// losing power can take away, so the walk goes up to the staging root rather than stopping at the
/// immediate parent.
///
/// On Windows it does nothing and says so. There is no portable way to flush a directory entry
/// there, and opening a directory as a file fails outright: a staging write that tried would fail
/// after the ciphertext was already on the disk. The contents are written and flushed on every
/// platform, so a reader never sees a file half written; what a Windows host does not get is the
/// guarantee that a name survives losing power, and `docs/host/README.md` says so.
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let mut directory = path.parent();
        while let Some(current) = directory {
            let handle = std::fs::File::open(current).map_err(ControllerError::registry)?;
            handle.sync_all().map_err(ControllerError::registry)?;
            if current.file_name().is_some_and(|name| name == "backup") {
                break;
            }
            directory = current.parent();
        }
        Ok(())
    }
}

/// Builds the transcript one writer enrolment is signed over.
fn enrolment_transcript(
    payload: &BackupWriterRecordPayload,
) -> Result<kr_crypto::sign::SigningTranscript> {
    let bytes = payload
        .signing_input()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    kr_crypto::sign::SigningTranscript::from_canonical_bytes(
        kr_protocol::archive::BACKUP_WRITER_DOMAIN,
        bytes,
    )
    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Builds the transcript one generation publication is signed over.
fn publication_transcript(
    publication: &BackupGenerationPublication,
) -> Result<kr_crypto::sign::SigningTranscript> {
    let bytes = publication
        .payload
        .signing_input()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    kr_crypto::sign::SigningTranscript::from_canonical_bytes(
        kr_protocol::archive::BACKUP_PUBLICATION_DOMAIN,
        bytes,
    )
    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Returns the key identifier of one authorisation public key.
fn authorisation_key_id(key: &AuthorisationKey) -> KeyId {
    kr_crypto::keys::key_id(
        kr_protocol::pairing::KeyPurpose::Authorisation,
        key.as_bytes(),
    )
}

impl PrivacySubsystem for BackupService {
    fn name(&self) -> &'static str {
        SUBSYSTEM_NAME
    }

    /// Stops the outbox at this generation, durably, before anything else is touched.
    ///
    /// Two transactions, in this order, and the order is the point. The first accepts the request
    /// and records the obligation to raise the fence; the second raises it. An activation that
    /// fails therefore leaves an accepted request and an outstanding obligation behind, so this
    /// host is inhibited, counts the work, and cannot report a fence it did not raise. A request
    /// this host could not even accept leaves the caller holding it: the count is nought and
    /// [`PrivacySubsystem::outstanding`] is not, because a store that will not answer is not a
    /// store with nothing outstanding.
    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        match self.raise_fence(generation, kr_ipc::now_ms()) {
            Ok(fenced) => {
                self.note_step_succeeded(FENCE_STEP);
                fenced
            }
            Err(_) => {
                self.note_step_failed(FENCE_STEP);
                Fenced::default()
            }
        }
    }

    /// Takes back every admitted, undispatched piece of backup work.
    ///
    /// What has been dispatched is counted rather than claimed: it has left this host and can only
    /// be followed, which is what reconciliation is for.
    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        match self.cancel_undispatched_work(kr_ipc::now_ms()) {
            Ok(cancelled) => {
                self.note_step_succeeded(CANCEL_STEP);
                cancelled
            }
            Err(_) => {
                self.note_step_failed(CANCEL_STEP);
                Cancelled::default()
            }
        }
    }

    /// Carries out the cleanup the fence wrote down, one obligation at a time.
    ///
    /// It reports only what it actually removed, and it ends only what it has evidence for. A file
    /// this host could not unlink keeps its obligation, with the reason written beside it, so the
    /// next pass finds the same target rather than a fresh guess at what is left.
    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        match self.run_cleanup(kr_ipc::now_ms()) {
            Ok(removed) => {
                self.note_step_succeeded(REMOVE_STEP);
                removed
            }
            Err(_) => {
                self.note_step_failed(REMOVE_STEP);
                Removed::default()
            }
        }
    }

    /// Returns how much backup work is still being cleaned up.
    ///
    /// One query over the durable rows. While a fence stands, what is outstanding is the cleanup
    /// that fence wrote down and this host has not finished; before there is a fence, it is the
    /// work that has left this host and not been answered. Nothing is counted twice: an attempt
    /// that an obligation already names is that obligation.
    ///
    /// A store that cannot be read answers one, not nought. "This host cannot say what it owes" is
    /// not "this host owes nothing", and privacy mode must never read the first as the second.
    fn outstanding(&self) -> u64 {
        let store = self.store();
        // A step this process could not carry out counts whatever the store says. It is the one
        // case the store owns nothing for: a request it would not accept left no row behind.
        let failed = self.failed_steps().len() as u64;
        let Ok(status) = store.privacy_status() else {
            return failed.max(1);
        };
        if status.inhibited_at().is_some() {
            // Under a fence the obligations are the account, and nothing else is. A pending
            // activation has an obligation of its own, so a request whose fence never went up is
            // counted here; an attempt that has left this host is counted by the obligation that
            // names it, never a second time. A fence that is still up over finished cleanup is
            // not outstanding work: what is outstanding is what has not been done.
            return status.obligations.saturating_add(failed);
        }
        // A generation whose outcome is *unknown* is not counted here, and that is deliberate.
        // `note_outcome_unknown` is the caller saying the transfer stopped and the answer never
        // came; the work is not still in flight, and counting it would leave privacy mode
        // reconciling for ever over something that will never become known. It is a copy that may
        // have left, which section 24 answers by showing it: [`Self::exported`] lists it as a
        // retained artifact whose outcome this host cannot establish.
        let dispatched = store
            .outbox()
            .map(|entries| entries.iter().filter(|entry| entry.dispatched).count() as u64)
            .unwrap_or(1);
        dispatched
            .saturating_add(status.obligations)
            .saturating_add(failed)
    }

    /// Names what this host keeps whatever privacy mode is doing.
    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![
            KeptExplicitly {
                what: "the record of each backup generation this host produced, and what became \
                       of it",
                why: "a host that forgot which generations it had published could not tell a \
                      replayed older archive from a current one",
            },
            KeptExplicitly {
                what: "the enrolment of each backup writer this host holds",
                why: "a host that forgot its writers could not say whether unfinished work is \
                      still authorised after a restart",
            },
        ]
    }

    /// Names the archives that had already left this host.
    ///
    /// Privacy mode does not erase them and does not claim it could. What it offers is this list:
    /// the reference is the archive and generation, never a path. `deletable` is false, because
    /// this host holds no route through which it could ask a service to remove one; the separately
    /// authorised deletion action section 24 asks for needs that route, and building it belongs
    /// with the component that carries an object to a service.
    fn exported(&self) -> Vec<Exported> {
        let store = self.store();
        let Ok(generations) = store.generations() else {
            return Vec::new();
        };
        // An attempt that left this host and has not been answered is a copy that may be at the
        // service. It is shown on the same terms as one this host knows left: the alternative is
        // to say nothing about bytes that may well be there.
        let unanswered: Vec<(ArchiveId, BackupGeneration)> = store
            .outbox()
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.dispatched)
            .map(|entry| (entry.archive_id, entry.backup_generation))
            .collect();
        generations
            .into_iter()
            .filter_map(|record| {
                let left = matches!(
                    record.state,
                    GenerationState::Published | GenerationState::Unknown
                );
                let in_doubt = unanswered.iter().any(|(archive, generation)| {
                    *archive == record.archive_id && *generation == record.backup_generation
                });
                if !left && !in_doubt {
                    return None;
                }
                Some(Exported {
                    kind: if record.state == GenerationState::Published {
                        "backup archive".to_owned()
                    } else {
                        // It left this host and nothing here knows whether the service kept it. A
                        // person is told that rather than told nothing.
                        "backup archive, outcome unknown".to_owned()
                    },
                    reference: format!(
                        "{} generation {}",
                        record.archive_id,
                        record.backup_generation.get()
                    ),
                    left_at_ms: record.settled_at_ms.unwrap_or(record.created_at_ms),
                    // False, and it stays false until this host holds a route to ask for the
                    // removal. `deletable` says this host has a way to ask; it does not say a
                    // person cannot ask the service themselves. Claiming otherwise would offer an
                    // action nothing here can perform, which is the false promise section 24
                    // forbids.
                    deletable: false,
                })
            })
            .collect()
    }
}
