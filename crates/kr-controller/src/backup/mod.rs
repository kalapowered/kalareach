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
    BackupStore, GenerationRecord, GenerationState, ObjectRecord, ObjectState, OutboxEntry, Step,
};
use crate::error::{ControllerError, Result};

/// The stable name this subsystem is reported under, which is section 24's.
pub const SUBSYSTEM_NAME: &str = "backup";

/// The obligation each privacy step owes while it has not done what it was asked.
///
/// One name per step, so a retry that works clears exactly what the failure recorded.
const FENCE_STEP: &str = "record the backup fence";
const CANCEL_STEP: &str = "cancel undispatched backup work";
const REMOVE_STEP: &str = "remove staged backup ciphertext";

/// The obligation a store that will not answer leaves behind.
const FAILED_TO_RECORD: &str = "read the backup store";

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
    /// Generations cancelled while work was in flight, whose wait for an answer a restart ended.
    ///
    /// The cancellation stands; what changes is that this host stops counting the transfer as
    /// something still being cleaned up. No answer can reach this process, so leaving the entry
    /// would hold privacy-mode cleanup open over work nothing will ever report on.
    pub cancelled_in_flight: Vec<(ArchiveId, BackupGeneration)>,
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
            && self.cancelled_in_flight.is_empty()
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
    unpersisted_obligations: Mutex<Vec<String>>,
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
            unpersisted_obligations: Mutex::new(Vec::new()),
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
            unpersisted_obligations: Mutex::new(Vec::new()),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, BackupStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records something privacy mode asked for that this host could not do.
    ///
    /// The privacy contract's methods report counts and have nowhere to put a failure, and a
    /// subsystem that reported a clean fence it had not performed would let privacy mode report
    /// complete over content that had not gone. So a failure becomes a durable obligation, and
    /// [`PrivacySubsystem::outstanding`] counts it: a restart comes back owing what it owed, and
    /// only the retry's own success clears it.
    /// Returns whether the obligation reached the disk. An in-memory one lasts as long as this
    /// process and no longer, so a caller about to write over the only other durable record of the
    /// same work has to know which it got.
    fn owe(&self, store: &mut BackupStore, what: String) -> bool {
        if store.record_obligation(&what, kr_ipc::now_ms()).is_ok() {
            return true;
        }
        // A store that will not record the obligation cannot be asked what it owes either, so the
        // failure is kept where `outstanding` will still see it: a store that cannot be read
        // answers "one thing outstanding" rather than "nothing".
        let _ = store.record_obligation(FAILED_TO_RECORD, kr_ipc::now_ms());
        let mut unpersisted = self
            .unpersisted_obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !unpersisted.contains(&what) {
            unpersisted.push(what);
        }
        false
    }

    /// Records that one privacy step did what it was asked, clearing what it owed.
    ///
    /// Keyed by the step rather than by the message, so a retry that works clears the obligation
    /// the failure recorded rather than adding a second entry beside it.
    fn settled(&self, store: &mut BackupStore, step: &str) {
        let _ = store.clear_obligation(step);
        let mut unpersisted = self
            .unpersisted_obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owed_in_memory = !unpersisted.is_empty();
        unpersisted.retain(|item| !item.contains(step));
        if owed_in_memory && unpersisted.is_empty() {
            // The marker stands in for work *this process* could not write down, and this was the
            // last of it. The condition it reported has passed, so it goes with the work.
            //
            // Only when this process is the one that could not write. A marker left by an earlier
            // process stands for a step whose name that process could not record either, and
            // nothing here can establish that it was ever done: an empty list after a restart is
            // an empty list, not evidence. Clearing it on the strength of some other step's
            // success would report a cleanup nobody performed.
            let _ = store.clear_obligation(FAILED_TO_RECORD);
        }
    }

    /// Returns what privacy mode asked for that this host has not done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn obligations(&self) -> Result<Vec<String>> {
        let mut owed = self.store().obligations()?;
        let unpersisted = self
            .unpersisted_obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for item in unpersisted.iter() {
            if !owed.contains(item) {
                owed.push(item.clone());
            }
        }
        Ok(owed)
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

    /// Releases the privacy fence, so backup production is admitted again from this moment.
    ///
    /// It is the durable half of turning privacy mode off, and it reconstructs nothing: the work
    /// the fence cancelled stays cancelled, and what is admitted afterwards is admitted under the
    /// new generation. A caller takes this step after `PrivacyMode::disable`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn release_fence(&self) -> Result<()> {
        self.store().release_fence()
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
        let mut store = self.store();
        // The generation the work was admitted under is the store's, not the caller's. A caller
        // that could name it could relabel work privacy mode had already drawn a line under, which
        // is the one thing the late-result rule exists to stop.
        let record = store
            .generation(archive_id, backup_generation)?
            .ok_or_else(|| {
                ControllerError::registry("that backup generation is not one this host admitted")
            })?;
        let admitted_under = PrivacyGeneration::new(record.privacy_generation);
        if admitted_under != produced_under {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup result claims privacy generation {}, and this host admitted the \
                     work under {}",
                    produced_under.get(),
                    admitted_under.get()
                ),
            });
        }
        if !mode.accepts_result(admitted_under) {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup result was produced under privacy generation {}, and this host is \
                     at {}",
                    admitted_under.get(),
                    mode.generation().get()
                ),
            });
        }
        store.settle(
            archive_id,
            backup_generation,
            GenerationState::Published,
            None,
            now_ms,
        )
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
    /// A generation that has already settled is left alone unless its outbox is not empty, which
    /// is what a cancellation over work that had already left this host leaves behind. That wait
    /// ends here: a dispatched publication makes the outcome **unknown**, and anything else is
    /// **cleared** with the settled state it already had, because no answer from the previous
    /// process can reach this one and privacy-mode cleanup cannot stay open for ever over it.
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
                // Cancelled work this host still holds ciphertext for is a removal it owes, and
                // the obligation is recorded before anything else is written. A cancellation says
                // this host will not do the work; the staged copies are then bytes nothing will
                // ever use, and a stop between the cancellation and the removal leaves them here
                // with nothing else to say so. Recording it first is what makes it durable: the
                // outbox entry this loop is about to clear was the only other thing counting the
                // cleanup, and an obligation written afterwards is one a stop in between loses.
                // Two reasons this host still owes a removal. Cancelled work is work it will
                // not do, so its staged copies are bytes nothing will ever use. And while a fence
                // is recorded, every staged copy is a removal privacy mode asked for, whatever
                // became of the generation: a published archive's ciphertext is as much here as a
                // cancelled one's, and a stop before the removal leaves both.
                let owed = (record.state == GenerationState::Cancelled || fenced.is_some())
                    && store
                        .objects(record.archive_id, record.backup_generation)?
                        .iter()
                        .any(|object| object.state != ObjectState::Removed);
                if owed && !self.owe(&mut store, REMOVE_STEP.to_owned()) {
                    // The obligation got no further than this process. The outbox entry is then
                    // the only durable thing left counting this cleanup, so it stays: settling
                    // over it would leave a store that says nothing is outstanding and a disk that
                    // still holds the ciphertext. The next reconciliation tries again.
                    continue;
                }
                if entries.is_empty() {
                    continue;
                }
                // A generation privacy mode cancelled while its work was in flight keeps that
                // entry, because the answer it is waiting for is what ends the cleanup. This
                // process cannot receive the last one's answers, so the wait ends here instead:
                // a publication that left is an outcome nobody here can state, and anything else
                // is cleared so the cancellation does not hold cleanup open for ever.
                let state = if entries
                    .iter()
                    .any(|entry| entry.dispatched && entry.step == Step::Publish)
                {
                    outcome
                        .outcome_unknown
                        .push((record.archive_id, record.backup_generation));
                    GenerationState::Unknown
                } else {
                    outcome
                        .cancelled_in_flight
                        .push((record.archive_id, record.backup_generation));
                    record.state
                };
                let detail = if state == GenerationState::Unknown {
                    "its publication left this host and was never answered, so whether the \
                     service holds it is not something this host can say"
                } else {
                    "it was cancelled while work was in flight, and the restart ended the wait \
                     for an answer this host can no longer receive"
                };
                store.settle(
                    record.archive_id,
                    record.backup_generation,
                    state,
                    Some(detail),
                    now_ms,
                )?;
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
    /// The fence is written down rather than held in memory: a host that fenced and restarted
    /// would otherwise come back and dispatch the entries it had just stopped.
    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        let now_ms = kr_ipc::now_ms();
        let mut store = self.store();
        let items = match store.outbox() {
            Ok(entries) => entries.iter().filter(|entry| !entry.dispatched).count() as u64,
            Err(_) => {
                self.owe(&mut store, FENCE_STEP.to_owned());
                return Fenced::default();
            }
        };
        if store.record_fence(generation.get(), now_ms).is_err() {
            self.owe(&mut store, FENCE_STEP.to_owned());
            return Fenced::default();
        }
        self.settled(&mut store, FENCE_STEP);
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
            Ok((undispatched, in_flight)) => {
                self.settled(&mut store, CANCEL_STEP);
                Cancelled {
                    undispatched,
                    in_flight,
                }
            }
            Err(_) => {
                self.owe(&mut store, CANCEL_STEP.to_owned());
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
            Err(_) => {
                self.owe(&mut store, REMOVE_STEP.to_owned());
                return removed;
            }
        };
        let outbox = match store.outbox() {
            Ok(outbox) => outbox,
            Err(_) => {
                self.owe(&mut store, REMOVE_STEP.to_owned());
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
                    // Already gone, and counted as gone. A pass that left it out of the tally
                    // would never see a generation as wholly removed, so a second pass over
                    // anything this one part-finished could never finish it either.
                    unlinked += 1;
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
            let left_this_host = matches!(
                record.state,
                GenerationState::Published | GenerationState::Unknown
            );
            if left_this_host || in_flight {
                // Its staged copy is gone and its record stays. A published archive because it has
                // already left and is shown rather than pretended away; one whose outcome is
                // unknown for the same reason, because a copy this host cannot account for is
                // still a copy; and one with work in flight because the outbox entry is what says
                // the cleanup is not finished.
                if let Err(error) =
                    store.note_objects_removed(record.archive_id, record.backup_generation)
                {
                    faults.push(format!(
                        "a generation's objects could not be marked: {error}"
                    ));
                } else {
                    // What this pass changed, not what it looked at. A generation whose rows
                    // already said the ciphertext had gone is one this call removed nothing from.
                    removed.records = removed.records.saturating_add(
                        objects
                            .iter()
                            .filter(|object| object.state != ObjectState::Removed)
                            .count() as u64,
                    );
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
        if faults.is_empty() {
            self.settled(&mut store, REMOVE_STEP);
        } else {
            // One name for the step, whatever went wrong inside it: a retry that empties the
            // staging directory clears the obligation the failure recorded rather than leaving a
            // per-file entry nothing will ever match.
            self.owe(&mut store, REMOVE_STEP.to_owned());
        }
        removed
    }

    /// Returns how much backup work is still being cleaned up.
    ///
    /// Dispatched outbox entries, plus anything a privacy step could not do. The second term is
    /// what stops privacy mode reporting complete over a fence that did not happen.
    fn outstanding(&self) -> u64 {
        let store = self.store();
        let dispatched = store
            .outbox()
            .map(|entries| entries.iter().filter(|entry| entry.dispatched).count() as u64)
            .unwrap_or(1);
        // A generation whose outcome is *unknown* is not counted here, and that is deliberate.
        // `note_outcome_unknown` is the caller saying the transfer stopped and the answer never
        // came; the work is not still in flight, and counting it would leave privacy mode
        // reconciling for ever over something that will never become known. It is a copy that may
        // have left, which section 24 answers by showing it: [`Self::exported`] lists it as a
        // retained artifact whose outcome this host cannot establish.
        let owed = store
            .obligations()
            .map(|owed| owed.len() as u64)
            .unwrap_or(1);
        let unpersisted = self
            .unpersisted_obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u64;
        dispatched.saturating_add(owed).saturating_add(unpersisted)
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
        self.store()
            .generations()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                matches!(
                    record.state,
                    GenerationState::Published | GenerationState::Unknown
                )
            })
            .map(|record| Exported {
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
                // False, and it stays false until this host holds a route to ask for the removal.
                // `deletable` says this host has a way to ask; it does not say a person cannot ask
                // the service themselves. Claiming otherwise would offer an action nothing here
                // can perform, which is exactly the false promise section 24 forbids.
                deletable: false,
            })
            .collect()
    }
}
