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
//!   and shows already-uploaded archives as retained artifacts with a deletion that is authorised
//!   on its own.
//!
//! # What this host never writes down
//!
//! An object key, a plaintext or a filename. The keys stay in the producer's hands until the
//! generation is sealed; the filenames are inside the encrypted manifest. `backup.sqlite` holds
//! identities, hashes, sizes, states and the paths of ciphertext.

pub mod store;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_crypto::backup::{
    CheckpointSource, Material, RestoreAdmissions, RestoreGeneration, SealedArchive, StagedObject,
    admit_for_restore,
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
    BackupStore, GenerationRecord, GenerationState, ObjectRecord, ObjectState, OutboxEntry, Step,
};
use crate::error::{ControllerError, Result};

/// The stable name this subsystem is reported under, which is section 24's.
pub const SUBSYSTEM_NAME: &str = "backup";

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

/// What startup reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Generations whose work this host may still do, and has put back in hand.
    pub resumed: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations this host may no longer publish, which are cancelled.
    pub no_longer_authorised: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations whose publication left this host and was never answered.
    pub outcome_unknown: Vec<(ArchiveId, BackupGeneration)>,
}

impl Reconciliation {
    /// Returns true when there was nothing to reconcile.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resumed.is_empty()
            && self.no_longer_authorised.is_empty()
            && self.outcome_unknown.is_empty()
    }
}

/// One restore, before anything of it is read.
#[derive(Clone, Debug)]
pub struct RestoreRequest<'a> {
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
    /// The latest generation the owner verified for this archive, and where it came from.
    pub checkpoint: Option<(CheckpointSource, &'a ArchiveCheckpoint)>,
}

/// A restore whose authority and generation have both been established.
///
/// There is no way to build one except through [`RestoreRequest::verify`], so a caller cannot
/// reach the reading half without having passed the checking half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRestore {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The writer whose signature was verified.
    pub writer_key_id: KeyId,
    /// The enrolment revision the owner signed.
    pub writer_revision: u64,
    /// Where the generation stands against the trusted checkpoint, which a restore displays.
    pub generation: RestoreGeneration,
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
            RestoreGeneration::against(&self.publication.payload.descriptor, self.checkpoint);
        if !generation.is_admissible() {
            return Err(ControllerError::InvalidArgument(generation.describe()));
        }
        Ok(VerifiedRestore {
            archive_id: self.publication.payload.descriptor.archive_id,
            writer_key_id,
            writer_revision: payload.writer_revision.get(),
            generation,
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
    /// What a privacy step asked for and could not do.
    ///
    /// The privacy contract's methods report counts and have nowhere to put a failure, and a
    /// subsystem that reported a clean fence it had not performed would let privacy mode report
    /// complete over work that was still leaving. So a failure is recorded here and counted in
    /// [`PrivacySubsystem::outstanding`], which is what reconciliation waits on.
    faults: Mutex<Vec<String>>,
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
            faults: Mutex::new(Vec::new()),
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
            faults: Mutex::new(Vec::new()),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, BackupStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn note_fault(&self, what: String) {
        if let Ok(mut faults) = self.faults.lock() {
            faults.push(what);
        }
    }

    /// Returns what a privacy step could not do, in the order it happened.
    #[must_use]
    pub fn faults(&self) -> Vec<String> {
        self.faults
            .lock()
            .map(|faults| faults.clone())
            .unwrap_or_default()
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

    /// Retires a backup writer, so its unfinished generations stop being authorised.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn retire_writer(&self, writer_key_id: KeyId, now_ms: TimestampMs) -> Result<()> {
        self.store().retire_writer(writer_key_id, now_ms)
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

        let mut rows: Vec<ObjectRecord> = Vec::with_capacity(objects.len() + 1);
        let mut staged_bytes = 0u64;
        for staged in objects {
            let path = store.staged_path(archive_id, backup_generation, staged.reference.object_id);
            write_staged(&path, &staged.bytes)?;
            staged_bytes = staged_bytes.saturating_add(staged.bytes.len() as u64);
            rows.push(ObjectRecord {
                archive_id,
                backup_generation,
                object_id: staged.reference.object_id,
                encrypted_object_hash: staged.reference.encrypted_object_hash,
                encrypted_len: staged.reference.encrypted_len.get(),
                staged_path: path,
                uploaded_bytes: 0,
                state: ObjectState::Staged,
            });
        }
        // The encrypted manifest is an object like any other, so the upload accounting covers it
        // and a generation is complete only when it has arrived too.
        let manifest = &sealed.descriptor.encrypted_manifest;
        let manifest_path = store.staged_path(archive_id, backup_generation, manifest.object_id);
        write_staged(&manifest_path, &sealed.encrypted_manifest)?;
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
        let sequence = store.admit(&record, &rows, now_ms)?;
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
        self.store().note_dispatched(sequence)
    }

    /// Records that one object's bytes reached the service.
    ///
    /// Returns true when it was the last one, which is when the publish step is enqueued in the
    /// same transaction.
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
    /// under. A result from before the generation in force is refused rather than published, which
    /// is T-040's late-result rule applied where the publication actually happens: the comparison
    /// is `PrivacyMode::accepts_result`'s, not a second one written here.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the result was produced under another generation,
    /// and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_published(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        produced_under: PrivacyGeneration,
        mode: &kr_worker::privacy::PrivacyMode,
        now_ms: TimestampMs,
    ) -> Result<()> {
        if !mode.accepts_result(produced_under) {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup result was produced under privacy generation {}, and this host is \
                     at {}",
                    produced_under.get(),
                    mode.generation().get()
                ),
            });
        }
        self.store().settle(
            archive_id,
            backup_generation,
            GenerationState::Published,
            None,
            now_ms,
        )
    }

    /// Records that this host cannot establish what became of a generation.
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
        self.store().settle(
            archive_id,
            backup_generation,
            GenerationState::Unknown,
            Some(detail),
            now_ms,
        )
    }

    /// Resolves whatever an earlier daemon left unfinished.
    ///
    /// Three answers, and only three:
    ///
    /// * A generation whose writer this host no longer holds an enrolment for is **cancelled**. It
    ///   is work this host may not do, whatever state it was left in.
    /// * A generation whose *publication* was dispatched and never answered is recorded as
    ///   **unknown**. The service may hold it and may not, and a host that wrote either answer
    ///   would be writing something it does not know. Section 23 never retries that automatically.
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
        let generations = store.generations()?;
        let outbox = store.outbox()?;
        let mut outcome = Reconciliation::default();
        for record in generations {
            if record.state.is_settled() {
                continue;
            }
            let entries: Vec<&OutboxEntry> = outbox
                .iter()
                .filter(|entry| {
                    entry.archive_id == record.archive_id
                        && entry.backup_generation == record.backup_generation
                })
                .collect();
            if !authorised.contains(&record.writer_key_id) {
                store.settle(
                    record.archive_id,
                    record.backup_generation,
                    GenerationState::Cancelled,
                    Some("this host no longer holds an enrolment for that backup writer"),
                    now_ms,
                )?;
                outcome
                    .no_longer_authorised
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
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

/// Writes one staged object's ciphertext, creating its generation's directory.
fn write_staged(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(ControllerError::registry)?;
    }
    std::fs::write(path, bytes).map_err(ControllerError::registry)
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
    /// The fence is written down rather than held in memory: a host that fenced and restarted
    /// would otherwise come back and dispatch the entries it had just stopped.
    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        let now_ms = kr_ipc::now_ms();
        let mut store = self.store();
        let items = match store.outbox() {
            Ok(entries) => entries.iter().filter(|entry| !entry.dispatched).count() as u64,
            Err(error) => {
                drop(store);
                self.note_fault(format!("the backup outbox could not be read: {error}"));
                return Fenced::default();
            }
        };
        if let Err(error) = store.record_fence(generation.get(), now_ms) {
            drop(store);
            self.note_fault(format!(
                "the backup fence at privacy generation {} could not be recorded: {error}",
                generation.get()
            ));
            return Fenced::default();
        }
        Fenced { queues: 1, items }
    }

    /// Takes back every admitted, undispatched piece of backup work.
    ///
    /// What has been dispatched is counted rather than claimed: it has left this host and can only
    /// be followed, which is what reconciliation is for.
    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        let now_ms = kr_ipc::now_ms();
        let mut store = self.store();
        match store.cancel_undispatched(now_ms, "privacy mode cancelled undispatched backup work") {
            Ok((undispatched, in_flight)) => Cancelled {
                undispatched,
                in_flight,
            },
            Err(error) => {
                drop(store);
                self.note_fault(format!(
                    "undispatched backup work could not be cancelled: {error}"
                ));
                Cancelled::default()
            }
        }
    }

    /// Removes the staged ciphertext and the production state of everything not published.
    ///
    /// It reports only what it actually removed. A file this host could not unlink stays in the
    /// accounting and is recorded as a fault, because a subsystem that reported a removal it had
    /// not performed is exactly what section 24 forbids.
    ///
    /// Two kinds of generation keep their record after their bytes have gone. A **published** one,
    /// because a copy that has already left is shown as a retained artifact rather than forgotten.
    /// And one with **work still in flight**, because forgetting it would take its outbox entry
    /// with it, and this subsystem would then report nothing outstanding over work that was still
    /// out there: section 24 reconciles in-flight cleanup before reporting complete, and a record
    /// removed is a reconciliation that can never happen.
    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        let mut removed = Removed::default();
        let mut store = self.store();
        let generations = match store.generations() {
            Ok(generations) => generations,
            Err(error) => {
                drop(store);
                self.note_fault(format!("the backup generations could not be read: {error}"));
                return removed;
            }
        };
        let outbox = match store.outbox() {
            Ok(outbox) => outbox,
            Err(error) => {
                drop(store);
                self.note_fault(format!("the backup outbox could not be read: {error}"));
                return removed;
            }
        };
        let mut faults = Vec::new();
        for record in generations {
            let objects = match store.objects(record.archive_id, record.backup_generation) {
                Ok(objects) => objects,
                Err(error) => {
                    faults.push(format!("a generation's objects could not be read: {error}"));
                    continue;
                }
            };
            let mut unlinked = 0u64;
            for object in &objects {
                if object.state == ObjectState::Removed {
                    continue;
                }
                match std::fs::remove_file(&object.staged_path) {
                    Ok(()) => {
                        removed.bytes = removed.bytes.saturating_add(object.encrypted_len);
                        unlinked += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        unlinked += 1;
                    }
                    Err(error) => {
                        faults.push(format!(
                            "staged backup ciphertext could not be removed: {error}"
                        ));
                    }
                }
            }
            if unlinked as usize != objects.len() {
                // Some of it is still on the disk, so the rows stay: a record that named files
                // this host still holds would be a record that lied about what is here.
                continue;
            }
            let in_flight = outbox.iter().any(|entry| {
                entry.dispatched
                    && entry.archive_id == record.archive_id
                    && entry.backup_generation == record.backup_generation
            });
            if record.state == GenerationState::Published || in_flight {
                // Its staged copy is gone and its record stays: a published archive because it
                // has already left and is shown rather than pretended away, and one with work in
                // flight because the outbox entry is what says the cleanup is not finished.
                if let Err(error) =
                    store.note_objects_removed(record.archive_id, record.backup_generation)
                {
                    faults.push(format!(
                        "a generation's objects could not be marked: {error}"
                    ));
                } else {
                    removed.records = removed.records.saturating_add(objects.len() as u64);
                }
                continue;
            }
            match store.forget(record.archive_id, record.backup_generation) {
                Ok(forgotten) => {
                    removed.records = removed
                        .records
                        .saturating_add(forgotten.len().saturating_add(1) as u64);
                }
                Err(error) => faults.push(format!("a generation could not be forgotten: {error}")),
            }
        }
        drop(store);
        for fault in faults {
            self.note_fault(fault);
        }
        removed
    }

    /// Returns how much backup work is still being cleaned up.
    ///
    /// Dispatched outbox entries, plus anything a privacy step could not do. The second term is
    /// what stops privacy mode reporting complete over a fence that did not happen.
    fn outstanding(&self) -> u64 {
        let dispatched = self
            .store()
            .outbox()
            .map(|entries| entries.iter().filter(|entry| entry.dispatched).count() as u64)
            .unwrap_or(1);
        dispatched.saturating_add(self.faults().len() as u64)
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
    /// Privacy mode does not erase them and does not claim it could. What it offers instead is
    /// this list and a deletion that is authorised on its own: the reference is the archive and
    /// generation, never a path, and `deletable` says this host has a reference it can ask through,
    /// not that asking will succeed or that no other copy exists.
    fn exported(&self) -> Vec<Exported> {
        self.store()
            .generations()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.state == GenerationState::Published)
            .map(|record| Exported {
                kind: "backup archive".to_owned(),
                reference: format!(
                    "{} generation {}",
                    record.archive_id,
                    record.backup_generation.get()
                ),
                left_at_ms: record.settled_at_ms.unwrap_or(record.created_at_ms),
                deletable: true,
            })
            .collect()
    }
}
