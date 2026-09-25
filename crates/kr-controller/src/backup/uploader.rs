//! The uploader: the executor that carries this host's backup outbox to managed storage and the
//! backup manifest.
//!
//! [`BackupService`] owns what this host produced and what it owes, and its outbox waits for an
//! executor; this is that executor. It takes the outbox's attempts in order, marks each dispatched
//! to itself, uploads the staged objects of the attempt's generation under that attempt's identity,
//! and publishes the generation's descriptor once every object is at the service. Each answer is
//! written down in the store as it arrives: the upload a service created, the parts it
//! acknowledged, each object it holds, the attempt it took whole and the publication it holds.
//!
//! # One step at a time
//!
//! [`Uploader::step`] does one thing: a record in the store, or one request and the record of its
//! answer. An object's parts go in one step, and each acknowledgement is recorded before the next
//! part leaves. [`Uploader::pass`] steps until nothing more can be done now. A step decides from
//! the store, so a process that stops between two steps, or in the middle of one, leaves the store
//! saying what comes next:
//!
//! * An attempt handed to this uploader stays its attempt. A restart ends nothing: the store keeps
//!   the attempt dispatched to [`EXECUTOR`], and the next process carries it on.
//! * An upload goes on at the part after the last one the service acknowledged, because the store
//!   keeps the upload's identity and that count. A part whose answer was lost is the one thing sent
//!   again, and the service answers it as the part it already holds.
//! * A completion asked for again is answered with the result the first one got, so nothing is
//!   stored twice.
//! * A creation whose answer was lost leaves the object's identity held by an upload this host
//!   cannot name. The service refuses another creation until that upload's lifetime runs out, and
//!   a pass after that creates it again.
//!
//! # What ends an attempt
//!
//! Evidence about its own work. The service holding every object of the generation ends an upload
//! attempt as accepted, and the service holding this generation's publication ends a publication
//! attempt as published. A collection deleted from the account console ends either as stopped:
//! this host retires its writer for that archive and cancels what it was still producing for it,
//! because backing up again means enrolling a new collection. A staged object that is gone, or is
//! not what this host admitted, stops its attempt and its generation, since it can never be sent.
//! Every other refusal, and every failure of the transport, leaves the attempt for the next pass,
//! with the reason in the pass's report.
//!
//! # An upload the service refuses
//!
//! A part or a completion refused as not permitted may be an upload that expired or closed, or a
//! pair of proofs the service could not bind that time; the refusal cannot say which. The uploader
//! asks the service to abandon the upload. An abandonment the service confirms is the explicit end,
//! and the object is uploaded again under a new upload in the next pass. One the service refuses
//! too is left as it is, because a pair of proofs that binds then continues the same upload.
//!
//! # A publication is made the same way every time
//!
//! The writer signs the generation's descriptor at the instant the generation was admitted, and an
//! Ed25519 signature over the same bytes is the same signature, so a publication refused by an
//! answer, or refused on this host before it left, is sent again as the same publication. The one
//! exception is a refusal from a service that already holds a generation of the archive at or
//! above this one. It takes no generation at or below the newest it has held, so this one is never
//! published, and its attempt stops naming the generation that carries its content.
//!
//! One that may have left without an answer is never sent again: section 23 retries no outcome that
//! is unknown, and nothing the service offers can prove that a request it admitted will not still
//! run. The uploader fetches the generation instead. The service holding its descriptor under this
//! writer is the answer. One that still does not hold it two freshness windows after the send is
//! given up on as [`Stepped::Unknown`]: the attempt stops, which writes down that this host cannot
//! establish what the service holds and ends the generation's production. That this host may have
//! sent it is written down before the request can leave, so a pass cancelled while the request is
//! on its way leaves the next pass asking rather than sending.
//!
//! # An unknown generation
//!
//! A generation whose outcome is unknown is never success. It is not a completed backup, nothing of
//! it is sent again, the pass reports it as unknown, and the next generation carries its content.
//! It changes nothing newer either. Should its publication reach the service after a newer
//! generation is published, the service refuses it, because it takes no generation at or below
//! the newest it has held, and a fetch of the newest is answered with the highest generation held.
//!
//! # What an unknown generation leaves at the service
//!
//! Every object an unknown generation stored is still at the service, and nothing the service does
//! gives that storage back: it keeps a stored object until something deletes it. So the uploader
//! does, once nothing can name the objects any more, which is when this host holds a newer
//! generation of the archive as published. It asks whether the service holds the unknown one,
//! which it does if the publication landed before the newer one: that one is written down as
//! published and keeps everything. Otherwise it never will, and each of its objects is deleted
//! once and the answer written down, and the service gives the storage back after its tombstone
//! window. An object another generation this host still holds also names is kept, because the
//! service holds one object under one name. Nothing is deleted under privacy mode's line, whose
//! retained artifacts go only by the person's own action, nor from a collection deleted from the
//! account console, which the service empties itself.
//!
//! # A restart with a publication on its way
//!
//! [`Uploader::settle`] makes that fetch for every publication an earlier process dispatched, and a
//! daemon calls it before [`BackupService::reconcile`]. Reconciliation writes a publication that
//! left and was never answered down as an outcome this host cannot establish, and ends its
//! generation's production; one the service holds is recorded first, so reconciliation finishes
//! the generation instead. One the service does not hold stays unknown, and so does one whose
//! process stopped between its dispatch and its send: that generation's production ends there,
//! each pass names it unknown while this host still asks the service about it, and the next
//! generation carries the backup.
//!
//! # Privacy mode
//!
//! A fence stops everything not yet sent. Nothing is dispatched under it, no further part, object
//! or publication is sent, an upload in progress is abandoned at the service, and the attempt that
//! carried it is stopped, which is what lets privacy mode's cleanup finish. What the service
//! already holds stays there: section 24 erases nothing retroactively. A host that was asked to
//! take a privacy step and could not sends nothing at all until it can.
//!
//! # What this host sends
//!
//! Staged ciphertext, the public descriptor, and the deletion of objects no publication can name,
//! and nothing else. A staged object is read back and held to the length and hash it was admitted
//! with before any of it leaves. Nothing is sent before this host has reconciled its store, and
//! nothing new while the storage service says backup storage is off.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use kr_client::error::ClientError;
use kr_client::services::{
    ArchiveAnswer, BackupManifestService, BackupState, Dispatched, NewUpload, PartTable,
    StorageService, UploadId, UploadProgress, upload_parts,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::archive::{
    ArchiveDescriptor, BACKUP_PUBLICATION_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{Digest256, TimestampMs};
use kr_protocol::service::SERVICE_REQUEST_FRESHNESS_MS;
use kr_worker::privacy::PrivacyGeneration;

use crate::backup::BackupService;
use crate::backup::store::{
    Attempt, AttemptStatus, GenerationRecord, ObjectRecord, PrivacyStatus, Production, Publication,
    Remote, Step, UploadRecord,
};
use crate::error::{ControllerError, Result};

/// The name every attempt this uploader carries is dispatched to.
///
/// One name for every process that runs the uploader, because an attempt belongs to the executor it
/// was handed to rather than to one run of it: a process that stopped leaves its attempts to the
/// next.
pub const EXECUTOR: &str = "the managed storage uploader";

/// How long the uploader keeps asking whether a publication sent without an answer reached the
/// service before it gives up on it: a freshness window, with the service's clock allowed to differ
/// from this host's by as much again.
///
/// It bounds the wait. It is not evidence that nothing sent will land, and giving up records the
/// outcome as one this host cannot establish.
const WAITS_FOR_AN_ANSWER_MS: u64 = 2 * SERVICE_REQUEST_FRESHNESS_MS;

/// What one step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stepped {
    /// A queued attempt was handed to this uploader.
    Dispatched {
        /// The attempt.
        sequence: u64,
    },
    /// The service created an upload for one object, and its identity is recorded.
    Created {
        /// The attempt that asked for it.
        sequence: u64,
        /// The object.
        object_id: BackupObjectId,
    },
    /// The service holds every part of one object's upload, each acknowledgement recorded as it
    /// came.
    Sent {
        /// The attempt that sent them.
        sequence: u64,
        /// The object.
        object_id: BackupObjectId,
        /// How many parts the object has.
        parts: u32,
    },
    /// The service stored one object, and it is recorded under the attempt that carried it.
    Stored {
        /// The attempt.
        sequence: u64,
        /// The object.
        object_id: BackupObjectId,
    },
    /// The service holds every object of the attempt's generation, and the attempt is accepted.
    Accepted {
        /// The attempt.
        sequence: u64,
    },
    /// The service holds this generation's publication, and it is recorded.
    Published {
        /// The attempt.
        sequence: u64,
        /// What recording it did.
        publication: Publication,
    },
    /// A publication an earlier process sent and never heard back about is one the service holds,
    /// and it is recorded.
    Settled {
        /// The attempt.
        sequence: u64,
    },
    /// An upload the service confirmed abandoned, which is forgotten.
    Abandoned {
        /// The object it carried.
        object_id: BackupObjectId,
    },
    /// An upload the service holds none of under the identity this host kept, which is forgotten.
    Forgotten {
        /// The object it carried.
        object_id: BackupObjectId,
    },
    /// An upload nothing carries any more that the service would not abandon.
    ///
    /// It is forgotten, and nothing more is sent under it. What the service holds of the object is
    /// not known here: an open upload ends when its lifetime runs out, and a completed one stays
    /// stored.
    Unabandoned {
        /// The object it carried.
        object_id: BackupObjectId,
        /// What the service answered.
        reason: String,
    },
    /// The attempt ended without the service taking its work, for the reason given.
    Stopped {
        /// The attempt.
        sequence: u64,
        /// Why.
        reason: String,
    },
    /// A publication that may have left this host, which the service does not hold, and which
    /// this host has stopped asking about.
    ///
    /// Its generation's outcome is unknown, and unknown is never success: the generation is not a
    /// completed backup, nothing of it is sent again, and the next generation of the archive
    /// carries its content. Should the publication still reach the service after a newer
    /// generation is published, the service refuses it, because it takes no generation at or below
    /// the newest it has held.
    Unknown {
        /// The publication attempt, which is stopped.
        sequence: u64,
        /// The archive.
        archive_id: ArchiveId,
        /// The generation whose outcome is unknown.
        backup_generation: BackupGeneration,
        /// Privacy mode's line under the generation, when it drew one. No later generation
        /// carries content from before that line.
        privacy: Option<String>,
    },
    /// The service no longer holds one object of a generation no publication can name, so the
    /// storage it took is given back.
    ///
    /// The generation's outcome was unknown, this host holds a newer generation of the archive as
    /// published, so the service takes no publication of the old one any more, and the service
    /// said it does not hold that one. This host asked for the object's deletion and wrote the
    /// answer down.
    Released {
        /// The archive.
        archive_id: ArchiveId,
        /// The generation that named the object.
        backup_generation: BackupGeneration,
        /// The object.
        object_id: BackupObjectId,
        /// Whether the service deleted it, rather than answering that it holds no object of that
        /// name.
        deleted: bool,
    },
    /// The archive's collection was deleted from the account console.
    ///
    /// The attempt is stopped, this host's writer for that archive is retired and what it was still
    /// producing for it is cancelled, so nothing more is sent to a collection that takes nothing.
    /// Backing up again means enrolling a new collection.
    CollectionDeleted {
        /// The attempt.
        sequence: u64,
        /// The archive whose collection was deleted.
        archive_id: ArchiveId,
    },
    /// Nothing more can be done about one attempt, or one upload, until the next pass.
    Waiting {
        /// Why.
        reason: String,
    },
}

impl Stepped {
    /// One line for a report a person reads.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Dispatched { sequence } => format!("backup attempt {sequence} is under way"),
            Self::Created {
                sequence,
                object_id,
            } => format!("backup attempt {sequence} began uploading object {object_id}"),
            Self::Sent {
                sequence,
                object_id,
                parts,
            } => format!(
                "backup attempt {sequence} has all {parts} parts of object {object_id} at the \
                 service"
            ),
            Self::Stored {
                sequence,
                object_id,
            } => format!("backup attempt {sequence} stored object {object_id}"),
            Self::Accepted { sequence } => {
                format!("backup attempt {sequence} uploaded every object of its generation")
            }
            Self::Published {
                sequence,
                publication: Publication::Recorded,
            } => format!("backup attempt {sequence} published its generation"),
            Self::Published {
                sequence,
                publication: Publication::RetainedArtifact { .. },
            } => format!(
                "backup attempt {sequence} found its generation published after this host had \
                 stopped producing it, and keeps it as a retained artifact"
            ),
            Self::Settled { sequence } => format!(
                "the publication of backup attempt {sequence} reached the service before this \
                 host restarted, and is recorded"
            ),
            Self::Abandoned { object_id } => {
                format!("an upload of object {object_id} was abandoned at the service")
            }
            Self::Forgotten { object_id } => format!(
                "the service holds no upload of object {object_id} under the identity this host \
                 kept, so this host forgets it"
            ),
            Self::Unabandoned { object_id, reason } => format!(
                "the service would not abandon the upload of object {object_id}, so what it holds \
                 of that object is not known here: {reason}"
            ),
            Self::Stopped { sequence, reason } => {
                format!("backup attempt {sequence} stopped: {reason}")
            }
            Self::Unknown {
                archive_id,
                backup_generation,
                privacy,
                ..
            } => format!(
                "backup generation {} of archive {archive_id} is unknown: the service does not \
                 hold its publication, which may have left this host. {}",
                backup_generation.get(),
                never_complete(privacy.as_deref())
            ),
            Self::Released {
                archive_id,
                backup_generation,
                object_id,
                deleted: true,
            } => format!(
                "object {object_id} of backup generation {} of archive {archive_id} is deleted at \
                 the service, since no publication can name it, and its storage is given back \
                 after the service's tombstone window",
                backup_generation.get()
            ),
            Self::Released {
                archive_id,
                backup_generation,
                object_id,
                deleted: false,
            } => format!(
                "the service holds no object {object_id} of backup generation {} of archive \
                 {archive_id}, which no publication can name, so nothing of it is charged",
                backup_generation.get()
            ),
            Self::CollectionDeleted {
                sequence,
                archive_id,
            } => format!(
                "backup attempt {sequence} stopped: the backup collection of archive {archive_id} \
                 was deleted from the account console, and this host no longer backs up to it. To \
                 back up again, enrol a new collection"
            ),
            Self::Waiting { reason } => format!("backup is waiting: {reason}"),
        }
    }
}

/// Why a pass took no step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Idle {
    /// This host has not reconciled its backup store since it opened, or was asked to take a
    /// privacy step and could not.
    Unready {
        /// Why.
        reason: String,
    },
    /// Backup storage is off for the account, and nothing is uploaded until it is turned on.
    BackupOff,
    /// The storage service could not be asked, or would not say.
    Unavailable {
        /// Why.
        reason: String,
    },
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Why the pass took no step, when it took none for a reason.
    pub idle: Option<Idle>,
    /// Every step the pass took, in order.
    pub steps: Vec<Stepped>,
}

impl PassReport {
    /// One line per step, after the reason for an idle pass, for a report a person reads.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = match &self.idle {
            Some(Idle::Unready { reason }) => vec![format!("backup is not uploading: {reason}")],
            Some(Idle::BackupOff) => vec![
                "managed backup storage is off, so nothing is uploaded until it is turned on"
                    .to_owned(),
            ],
            Some(Idle::Unavailable { reason }) => {
                vec![format!("the storage service could not be asked: {reason}")]
            }
            None => Vec::new(),
        };
        lines.extend(self.steps.iter().map(Stepped::describe));
        lines
    }
}

/// What one pass has already met, so it neither comes back to it nor goes round in a circle.
#[derive(Debug, Default)]
struct Turn {
    /// Attempts that waited in this pass.
    waited: BTreeSet<u64>,
    /// Objects whose upload ended in this pass, which are uploaded again in the next one.
    restarted: BTreeSet<(ArchiveId, BackupGeneration, BackupObjectId)>,
    /// Uploads that could not be abandoned in this pass.
    unabandoned: BTreeSet<String>,
    /// Generations left behind whose reclamation waited in this pass.
    unreclaimed: BTreeSet<(ArchiveId, BackupGeneration)>,
}

/// The executor that carries the backup outbox.
pub struct Uploader {
    backup: Arc<BackupService>,
    storage: Arc<dyn StorageService>,
    manifest: Arc<dyn BackupManifestService>,
    /// The writer's key, which signs every publication and whose generations this uploader
    /// publishes.
    writer: AuthorisationKeyPair,
    /// When this uploader began: every request an earlier process sent was signed before it.
    started_at_ms: u64,
    /// Publication attempts this process dispatched, so every send of them is one it knows of.
    dispatched_here: BTreeSet<u64>,
    /// Publication attempts whose request this process sent without an answer, and when.
    unanswered: BTreeMap<u64, u64>,
    /// Generations left behind that this process asked the service about and found it does not
    /// hold. Nothing can publish one after that, so the answer stands.
    unheld: BTreeSet<(ArchiveId, BackupGeneration)>,
}

impl fmt::Debug for Uploader {
    /// The writer it publishes as and how much it is waiting on. Never a key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Uploader")
            .field("writer_key_id", &self.writer.key_id())
            .field("unanswered_publications", &self.unanswered.len())
            .finish_non_exhaustive()
    }
}

impl Uploader {
    /// An uploader for `backup`'s outbox, beginning at `now`.
    ///
    /// It uploads through `storage` and publishes through `manifest` as `writer`. The service
    /// takes a publication only when the request carrying it is signed by the writer that signed
    /// it, so `manifest` signs its requests with the same key.
    #[must_use]
    pub fn new(
        backup: Arc<BackupService>,
        storage: Arc<dyn StorageService>,
        manifest: Arc<dyn BackupManifestService>,
        writer: AuthorisationKeyPair,
        now: TimestampMs,
    ) -> Self {
        Self {
            backup,
            storage,
            manifest,
            writer,
            started_at_ms: now.get(),
            dispatched_here: BTreeSet::new(),
            unanswered: BTreeMap::new(),
            unheld: BTreeSet::new(),
        }
    }

    /// Records the publications an earlier process sent that the service holds, before the store
    /// is reconciled.
    ///
    /// For each publication attempt dispatched to [`EXECUTOR`] and never answered, it fetches the
    /// generation. One the service holds, exactly this generation's descriptor under its writer, is
    /// recorded as published, so reconciliation finishes its production. One the service does not
    /// hold, or cannot say about, is left for reconciliation, which records that this host cannot
    /// establish its outcome, and nothing is published again.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub async fn settle(&mut self, now: TimestampMs) -> Result<Vec<Stepped>> {
        let mut settled = Vec::new();
        for attempt in self.backup.outbox()? {
            if attempt.step != Step::Publish
                || attempt.status != AttemptStatus::Dispatched
                || attempt.executor.as_deref() != Some(EXECUTOR)
            {
                continue;
            }
            let Some(generation) = self
                .backup
                .generation(attempt.archive_id, attempt.backup_generation)?
            else {
                continue;
            };
            if !matches!(self.held(&generation).await, Ok(true)) {
                continue;
            }
            settled.push(
                match self.backup.note_published(
                    attempt.sequence,
                    PrivacyGeneration::new(attempt.privacy_generation),
                    now,
                ) {
                    Ok(_) => Stepped::Settled {
                        sequence: attempt.sequence,
                    },
                    Err(error) => waiting_on(error)?,
                },
            );
        }
        Ok(settled)
    }

    /// Steps until nothing more can be done now, and says what it did.
    ///
    /// Nothing is sent for new work unless the storage service says backup storage is on, which
    /// also establishes that the account's proof reaches it. Work privacy mode stopped is ended
    /// whether or not it is.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub async fn pass(&mut self, now: TimestampMs) -> Result<PassReport> {
        let mut report = PassReport::default();
        if let Some(reason) = self.backup.unready() {
            report.idle = Some(Idle::Unready { reason });
            return Ok(report);
        }
        let uploads = self.backup.store().uploads()?;
        let outbox = self.backup.outbox()?;
        let privacy = self.backup.privacy_status()?;
        if outbox.is_empty()
            && uploads.is_empty()
            && self.reclaimable(&outbox, &privacy)?.is_empty()
        {
            return Ok(report);
        }
        if privacy.inhibited_at().is_none() {
            match self.storage.status().await {
                Ok(status) if status.backup == BackupState::On => {}
                Ok(_) => {
                    report.idle = Some(Idle::BackupOff);
                    return Ok(report);
                }
                Err(error) => {
                    report.idle = Some(Idle::Unavailable {
                        reason: error.to_string(),
                    });
                    return Ok(report);
                }
            }
        }
        let mut turn = Turn::default();
        while let Some(stepped) = self.next(now, &mut turn).await? {
            report.steps.push(stepped);
        }
        Ok(report)
    }

    /// Takes the next step, or answers none when nothing can be done now.
    ///
    /// It does not ask the storage service whether backup storage is on: [`Self::pass`] does, and a
    /// pass is what a daemon runs.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub async fn step(&mut self, now: TimestampMs) -> Result<Option<Stepped>> {
        self.next(now, &mut Turn::default()).await
    }

    async fn next(&mut self, now: TimestampMs, turn: &mut Turn) -> Result<Option<Stepped>> {
        if self.backup.unready().is_some() {
            return Ok(None);
        }
        let privacy = self.backup.privacy_status()?;
        let outbox = self.backup.outbox()?;
        for attempt in &outbox {
            if turn.waited.contains(&attempt.sequence)
                || (attempt.status == AttemptStatus::Dispatched
                    && attempt.executor.as_deref() != Some(EXECUTOR))
            {
                // Waited already in this pass, or another executor's to carry and to end.
                continue;
            }
            let Some(generation) = self
                .backup
                .generation(attempt.archive_id, attempt.backup_generation)?
            else {
                continue;
            };
            let producing = may_produce(&generation, &privacy);
            let stepped = match (attempt.step, attempt.status) {
                (_, AttemptStatus::Terminal) => continue,
                (Step::Upload, AttemptStatus::Queued) => {
                    // Work the store takes back, work another attempt is carrying, and work that
                    // is already done are the store's to settle, and none of them is sent.
                    if !producing || carried(attempt, &outbox) || !self.outstanding(&generation)? {
                        continue;
                    }
                    self.dispatch(attempt, now)?
                }
                (Step::Publish, AttemptStatus::Queued) => {
                    if !producing {
                        continue;
                    }
                    self.dispatch(attempt, now)?
                }
                (Step::Upload, AttemptStatus::Dispatched) if producing => {
                    self.carry_upload(attempt, &generation, now, turn).await?
                }
                (Step::Upload, AttemptStatus::Dispatched) => {
                    let reason = production_over(&generation, &privacy);
                    self.end_upload(attempt, &generation, reason, now, turn)
                        .await?
                }
                (Step::Publish, AttemptStatus::Dispatched) => {
                    self.carry_publication(attempt, &generation, &privacy, now)
                        .await?
                }
            };
            if matches!(stepped, Stepped::Waiting { .. }) {
                turn.waited.insert(attempt.sequence);
            }
            return Ok(Some(stepped));
        }
        if let Some(stepped) = self.abandon_what_was_left(&outbox, &privacy, turn).await? {
            return Ok(Some(stepped));
        }
        self.reclaim(&outbox, &privacy, now, turn).await
    }

    /* ---------------------------------------------------------------------- */
    /* Dispatch                                                                */
    /* ---------------------------------------------------------------------- */

    fn dispatch(&mut self, attempt: &Attempt, now: TimestampMs) -> Result<Stepped> {
        match self.backup.note_dispatched(attempt.sequence, EXECUTOR, now) {
            Ok(()) => {
                if attempt.step == Step::Publish {
                    self.dispatched_here.insert(attempt.sequence);
                }
                Ok(Stepped::Dispatched {
                    sequence: attempt.sequence,
                })
            }
            Err(error) => waiting_on(error),
        }
    }

    /// Whether any object of `generation` is not yet at the service.
    fn outstanding(&self, generation: &GenerationRecord) -> Result<bool> {
        Ok(self
            .backup
            .objects(generation.archive_id, generation.backup_generation)?
            .iter()
            .any(|object| !object.is_acknowledged()))
    }

    /* ---------------------------------------------------------------------- */
    /* An upload attempt                                                       */
    /* ---------------------------------------------------------------------- */

    async fn carry_upload(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        let objects = self
            .backup
            .objects(generation.archive_id, generation.backup_generation)?;
        let Some(object) = objects.into_iter().find(|object| !object.is_acknowledged()) else {
            return self.accept(attempt, now);
        };
        if turn.restarted.contains(&key(&object)) {
            return Ok(Stepped::Waiting {
                reason: format!(
                    "the upload of object {} ended in this pass, and the next pass uploads it again",
                    object.object_id
                ),
            });
        }
        let recorded = self.backup.store().upload(
            object.archive_id,
            object.backup_generation,
            object.object_id,
        )?;
        match recorded {
            None => self.create(attempt, generation, &object, now).await,
            Some(record) => {
                self.continue_upload(attempt, generation, &object, &record, now, turn)
                    .await
            }
        }
    }

    async fn create(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        object: &ObjectRecord,
        now: TimestampMs,
    ) -> Result<Stepped> {
        // The object this host admitted and nothing else, held to its length and hash before any
        // of it leaves.
        match staged(object) {
            Ok(_) => {}
            Err(Unstaged::Unreadable(reason)) => return Ok(Stepped::Waiting { reason }),
            Err(Unstaged::NotAdmitted(reason)) => {
                return self.give_up(attempt, generation, reason, now);
            }
        }
        let upload = NewUpload {
            archive_id: object.archive_id,
            object_id: object.object_id,
            backup_generation: object.backup_generation,
            declared_max_bytes: object.encrypted_len,
            total_bytes: object.encrypted_len,
            encrypted_object_hash: object.encrypted_object_hash,
        };
        if !may_send(&self.backup, attempt)? {
            return Ok(not_carried());
        }
        match self.storage.create_upload(&upload).await {
            Ok(ArchiveAnswer::Done(created)) => {
                self.backup.store().record_upload(
                    attempt.sequence,
                    object.archive_id,
                    object.backup_generation,
                    object.object_id,
                    created.upload_id.as_str(),
                )?;
                Ok(Stepped::Created {
                    sequence: attempt.sequence,
                    object_id: object.object_id,
                })
            }
            Ok(ArchiveAnswer::CollectionDeleted) => {
                self.collection_deleted(attempt, generation, now)
            }
            Ok(ArchiveAnswer::UploadGone) => Ok(Stepped::Waiting {
                reason: "the service answered a creation as an upload it holds none of".to_owned(),
            }),
            Err(error) => Ok(Stepped::Waiting {
                reason: format!(
                    "the service did not create an upload of object {}: {error}",
                    object.object_id
                ),
            }),
        }
    }

    async fn continue_upload(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        object: &ObjectRecord,
        record: &UploadRecord,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        let Ok(upload_id) = UploadId::new(record.upload_id.clone()) else {
            return self.forget(record, turn);
        };
        let ciphertext = match staged(object) {
            Ok(ciphertext) => ciphertext,
            Err(Unstaged::Unreadable(reason)) => return Ok(Stepped::Waiting { reason }),
            Err(Unstaged::NotAdmitted(reason)) => {
                return self.give_up(attempt, generation, reason, now);
            }
        };
        let Some(table) = PartTable::for_total(object.encrypted_len) else {
            return self.give_up(
                attempt,
                generation,
                format!(
                    "object {} is empty or larger than the storage service stores",
                    object.object_id
                ),
                now,
            );
        };
        let mut progress = UploadProgress {
            upload_id,
            table,
            parts_acknowledged: u32::try_from(record.parts_acknowledged)
                .unwrap_or(u32::MAX)
                .min(table.part_count()),
        };
        if !progress.every_part_acknowledged() {
            if !may_send(&self.backup, attempt)? {
                return Ok(not_carried());
            }
            let backup = &*self.backup;
            let mut failure: Option<ControllerError> = None;
            let mut withdrawn = false;
            let sent = {
                // Each acknowledgement is recorded before the next part leaves, and the next part
                // leaves only while the store still holds this attempt for this uploader.
                let mut keep = |progress: &UploadProgress| -> kr_client::Result<()> {
                    // Its own statement, so the store is let go before `may_send` reads it again.
                    let recorded = backup.store().note_parts_acknowledged(
                        object.archive_id,
                        object.backup_generation,
                        object.object_id,
                        &record.upload_id,
                        u64::from(progress.parts_acknowledged),
                    );
                    match recorded.and_then(|()| may_send(backup, attempt)) {
                        Ok(true) => Ok(()),
                        Ok(false) => {
                            withdrawn = true;
                            Err(held_back())
                        }
                        Err(error) => {
                            failure = Some(error);
                            Err(held_back())
                        }
                    }
                };
                upload_parts(&*self.storage, &mut progress, &ciphertext, &mut keep).await
            };
            if let Some(error) = failure {
                return Err(error);
            }
            return match sent {
                Ok(ArchiveAnswer::Done(())) => Ok(Stepped::Sent {
                    sequence: attempt.sequence,
                    object_id: object.object_id,
                    parts: progress.parts_acknowledged,
                }),
                Ok(ArchiveAnswer::CollectionDeleted) => {
                    self.collection_deleted(attempt, generation, now)
                }
                Ok(ArchiveAnswer::UploadGone) => self.forget(record, turn),
                Err(_) if withdrawn => Ok(not_carried()),
                Err(error) if not_permitted(&error) => {
                    self.abandon(record, &progress.upload_id, turn).await
                }
                Err(error) => Ok(Stepped::Waiting {
                    reason: format!(
                        "the upload of object {} stopped after part {}: {error}",
                        object.object_id, progress.parts_acknowledged
                    ),
                }),
            };
        }
        if !may_send(&self.backup, attempt)? {
            return Ok(not_carried());
        }
        match self
            .storage
            .complete_upload(&progress.upload_id, &progress.table)
            .await
        {
            Ok(ArchiveAnswer::Done(completed)) => {
                if completed.archive_id != object.archive_id
                    || completed.backup_generation != object.backup_generation
                    || completed.object.object_id != object.object_id
                    || completed.object.encrypted_object_hash != object.encrypted_object_hash
                    || completed.object.encrypted_len != object.encrypted_len
                {
                    return Ok(Stepped::Waiting {
                        reason: format!(
                            "the service completed the upload of object {} as another object",
                            object.object_id
                        ),
                    });
                }
                self.backup.note_object_uploaded(
                    attempt.sequence,
                    object.archive_id,
                    object.backup_generation,
                    object.object_id,
                    now,
                )?;
                Ok(Stepped::Stored {
                    sequence: attempt.sequence,
                    object_id: object.object_id,
                })
            }
            Ok(ArchiveAnswer::CollectionDeleted) => {
                self.collection_deleted(attempt, generation, now)
            }
            Ok(ArchiveAnswer::UploadGone) => self.forget(record, turn),
            Err(error) if not_permitted(&error) => {
                self.abandon(record, &progress.upload_id, turn).await
            }
            Err(error) => Ok(Stepped::Waiting {
                reason: format!(
                    "the upload of object {} was not completed: {error}",
                    object.object_id
                ),
            }),
        }
    }

    fn accept(&self, attempt: &Attempt, now: TimestampMs) -> Result<Stepped> {
        match self.backup.note_attempt_accepted(attempt.sequence, now) {
            Ok(()) => Ok(Stepped::Accepted {
                sequence: attempt.sequence,
            }),
            Err(error) => waiting_on(error),
        }
    }

    /// Asks the service to abandon an upload it refused a part or a completion of.
    ///
    /// An abandonment the service confirms is the explicit end of the upload, which is forgotten
    /// so the object is uploaded under a new one. One it refuses too may be a pair of proofs it
    /// could not bind, and the upload is left as it is for the next pass.
    async fn abandon(
        &mut self,
        record: &UploadRecord,
        upload_id: &UploadId,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        match self.storage.abort_upload(upload_id).await {
            Ok(ArchiveAnswer::Done(_)) => {
                self.drop_upload(record, turn)?;
                Ok(Stepped::Abandoned {
                    object_id: record.object_id,
                })
            }
            Ok(ArchiveAnswer::UploadGone) => self.forget(record, turn),
            Ok(ArchiveAnswer::CollectionDeleted) => Ok(Stepped::Waiting {
                reason: "the service answered an abandonment as a deleted collection".to_owned(),
            }),
            Err(error) => Ok(Stepped::Waiting {
                reason: format!(
                    "the upload of object {} was refused and could not be abandoned: {error}",
                    record.object_id
                ),
            }),
        }
    }

    /// Forgets an upload the service holds none of.
    fn forget(&self, record: &UploadRecord, turn: &mut Turn) -> Result<Stepped> {
        self.drop_upload(record, turn)?;
        Ok(Stepped::Forgotten {
            object_id: record.object_id,
        })
    }

    fn drop_upload(&self, record: &UploadRecord, turn: &mut Turn) -> Result<()> {
        self.backup.store().forget_upload(
            record.archive_id,
            record.backup_generation,
            record.object_id,
            &record.upload_id,
        )?;
        turn.restarted.insert((
            record.archive_id,
            record.backup_generation,
            record.object_id,
        ));
        Ok(())
    }

    /// Ends an upload attempt whose generation may no longer produce.
    ///
    /// Its uploads in progress are abandoned at the service first, one a step. Then the attempt
    /// ends as accepted when the service holds every object, and as stopped when it does not. An
    /// abandonment the service cannot be asked for now does not hold the attempt open: nothing more
    /// is sent under it either way, and the upload is abandoned in a later pass.
    async fn end_upload(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        reason: String,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        for record in self.uploads_of(generation)? {
            if turn.unabandoned.contains(&record.upload_id) {
                continue;
            }
            let stepped = self.abandon_left(&record, turn).await?;
            if !matches!(stepped, Stepped::Waiting { .. }) {
                return Ok(stepped);
            }
        }
        let everything_held = self
            .backup
            .objects(generation.archive_id, generation.backup_generation)?
            .iter()
            .all(ObjectRecord::is_acknowledged);
        if everything_held {
            return self.accept(attempt, now);
        }
        self.stop(attempt, reason, now)
    }

    fn uploads_of(&self, generation: &GenerationRecord) -> Result<Vec<UploadRecord>> {
        let uploads = self.backup.store().uploads()?;
        Ok(uploads
            .into_iter()
            .filter(|record| {
                record.archive_id == generation.archive_id
                    && record.backup_generation == generation.backup_generation
            })
            .collect())
    }

    /// Asks the service to abandon an upload nothing carries any more.
    ///
    /// Whatever the service answers, the upload is over for this host: confirmed, gone, or one the
    /// service would not abandon, which it ends itself when its lifetime runs out. Only an
    /// abandonment that got no answer is kept, for a later pass.
    async fn abandon_left(&mut self, record: &UploadRecord, turn: &mut Turn) -> Result<Stepped> {
        let Ok(upload_id) = UploadId::new(record.upload_id.clone()) else {
            return self.forget(record, turn);
        };
        match self.storage.abort_upload(&upload_id).await {
            Ok(ArchiveAnswer::Done(_)) => {
                self.drop_upload(record, turn)?;
                Ok(Stepped::Abandoned {
                    object_id: record.object_id,
                })
            }
            Ok(ArchiveAnswer::UploadGone) => self.forget(record, turn),
            Ok(ArchiveAnswer::CollectionDeleted) => {
                self.drop_upload(record, turn)?;
                Ok(Stepped::Unabandoned {
                    object_id: record.object_id,
                    reason: "its collection was deleted from the account console".to_owned(),
                })
            }
            Err(error @ ClientError::Refused { .. }) => {
                self.drop_upload(record, turn)?;
                Ok(Stepped::Unabandoned {
                    object_id: record.object_id,
                    reason: error.to_string(),
                })
            }
            Err(error) => {
                turn.unabandoned.insert(record.upload_id.clone());
                Ok(Stepped::Waiting {
                    reason: format!(
                        "an upload of object {} that nothing carries any more could not be \
                         abandoned yet: {error}",
                        record.object_id
                    ),
                })
            }
        }
    }

    /// Abandons an upload nothing carries any more, whose generation may no longer produce.
    async fn abandon_what_was_left(
        &mut self,
        outbox: &[Attempt],
        privacy: &PrivacyStatus,
        turn: &mut Turn,
    ) -> Result<Option<Stepped>> {
        let uploads = self.backup.store().uploads()?;
        for record in uploads {
            if turn.unabandoned.contains(&record.upload_id) {
                continue;
            }
            let carried_on = outbox.iter().any(|attempt| {
                attempt.archive_id == record.archive_id
                    && attempt.backup_generation == record.backup_generation
                    && attempt.step == Step::Upload
            });
            let producing = self
                .backup
                .generation(record.archive_id, record.backup_generation)?
                .is_some_and(|generation| may_produce(&generation, privacy));
            if carried_on || producing {
                continue;
            }
            return self.abandon_left(&record, turn).await.map(Some);
        }
        Ok(None)
    }

    fn stop(&self, attempt: &Attempt, reason: String, now: TimestampMs) -> Result<Stepped> {
        match self.backup.note_attempt_stopped(attempt.sequence, now) {
            Ok(()) => Ok(Stepped::Stopped {
                sequence: attempt.sequence,
                reason,
            }),
            Err(error) => waiting_on(error),
        }
    }

    /// Ends an attempt whose generation can never be sent or published, and the generation with
    /// it.
    ///
    /// Production is cancelled first, with the reason, so a stop in between leaves nothing that
    /// would be given another attempt at the same staged object or the same publication.
    fn give_up(
        &self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        reason: String,
        now: TimestampMs,
    ) -> Result<Stepped> {
        self.backup.store().cancel_production(
            generation.archive_id,
            generation.backup_generation,
            &reason,
            now,
        )?;
        self.stop(attempt, reason, now)
    }

    /// A collection deleted from the account console.
    ///
    /// This host retires its writer for the archive and cancels every generation of it still
    /// producing, which takes back the attempts it had not sent, and the attempt that met the
    /// answer stops. The uploads in progress are abandoned in the steps after, and the attempts
    /// already sent for the archive's other generations end the same way as they meet the
    /// cancellation.
    fn collection_deleted(
        &self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        now: TimestampMs,
    ) -> Result<Stepped> {
        let archive_id = generation.archive_id;
        self.backup
            .retire_writer(archive_id, generation.writer_key_id, now)?;
        let detail = format!(
            "the backup collection of archive {archive_id} was deleted from the account console; \
             to back up again, enrol a new collection"
        );
        for other in self.backup.generations()? {
            if other.archive_id == archive_id && other.production == Production::Producing {
                self.backup.store().cancel_production(
                    archive_id,
                    other.backup_generation,
                    &detail,
                    now,
                )?;
            }
        }
        match self.backup.note_attempt_stopped(attempt.sequence, now) {
            Ok(()) => Ok(Stepped::CollectionDeleted {
                sequence: attempt.sequence,
                archive_id,
            }),
            Err(error) => waiting_on(error),
        }
    }

    /* ---------------------------------------------------------------------- */
    /* A publication attempt                                                   */
    /* ---------------------------------------------------------------------- */

    /// Carries a publication attempt dispatched to this uploader.
    ///
    /// A send of it that may be on its way without an answer, this process's or an earlier one's, is
    /// established by fetching the generation and never by sending it again. The service holding it
    /// is the answer. One that does not hold it once [`WAITS_FOR_AN_ANSWER_MS`] have passed since the
    /// send is given up on as [`Stepped::Unknown`]: the attempt stops with its outcome unknown.
    async fn carry_publication(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        privacy: &PrivacyStatus,
        now: TimestampMs,
    ) -> Result<Stepped> {
        let sequence = attempt.sequence;
        // Since when a send of it may be on its way without an answer: one this process made, or,
        // for an attempt an earlier process dispatched, any it may have made before this began.
        let on_its_way_since = if self.dispatched_here.contains(&sequence) {
            self.unanswered.get(&sequence).copied()
        } else {
            Some(self.started_at_ms)
        };
        let Some(since) = on_its_way_since else {
            // Nothing of it is on its way, so it is sent, or it ends where it may not be.
            if may_produce(generation, privacy) {
                return self.publish(attempt, generation, now).await;
            }
            return self.stop(attempt, production_over(generation, privacy), now);
        };
        match self.held(generation).await {
            Ok(true) => self.published(attempt, now),
            Ok(false) if now.get() >= since.saturating_add(WAITS_FOR_AN_ANSWER_MS) => {
                // The note that it may have left goes only once the stop is written down: a stop
                // the store refused leaves the attempt dispatched, and the next pass has to ask
                // again rather than send.
                match self.backup.note_attempt_stopped(sequence, now) {
                    Ok(()) => {
                        self.unanswered.remove(&sequence);
                        self.dispatched_here.remove(&sequence);
                        Ok(Stepped::Unknown {
                            sequence,
                            archive_id: generation.archive_id,
                            backup_generation: generation.backup_generation,
                            privacy: privacy_line(generation, privacy),
                        })
                    }
                    Err(error) => waiting_on(error),
                }
            }
            // An earlier process dispatched it, so its outcome is already one this host cannot
            // establish, and that is what a person is told while this host still asks.
            Ok(false) if !self.dispatched_here.contains(&sequence) => Ok(Stepped::Waiting {
                reason: format!(
                    "the service does not hold the publication of backup generation {} of archive \
                     {}, which may have left before this host restarted. That generation is \
                     unknown. {}",
                    generation.backup_generation.get(),
                    generation.archive_id,
                    never_complete(privacy_line(generation, privacy).as_deref())
                ),
            }),
            Ok(false) => Ok(Stepped::Waiting {
                reason: format!(
                    "the publication of backup attempt {sequence} may still reach the service, \
                     which does not hold it yet"
                ),
            }),
            Err(error) => Ok(Stepped::Waiting {
                reason: format!(
                    "whether the service holds the publication of backup attempt {sequence} is \
                     not known: {error}"
                ),
            }),
        }
    }

    async fn publish(
        &mut self,
        attempt: &Attempt,
        generation: &GenerationRecord,
        now: TimestampMs,
    ) -> Result<Stepped> {
        let publication = match self.publication(generation) {
            Ok(publication) => publication,
            Err(reason) => return Ok(Stepped::Waiting { reason }),
        };
        if !may_send(&self.backup, attempt)? {
            return Ok(not_carried());
        }
        // Written down before the request can leave and cleared only by an answer or by a refusal
        // made before anything left, so a pass cancelled while it is on its way leaves the next one
        // asking the service rather than sending again.
        let sequence = attempt.sequence;
        self.unanswered.insert(sequence, now.get());
        match self.manifest.publish_dispatched(&publication).await {
            Ok(Dispatched::Answered(ArchiveAnswer::Done(_))) => self.published(attempt, now),
            Ok(Dispatched::Answered(ArchiveAnswer::CollectionDeleted)) => {
                self.unanswered.remove(&sequence);
                self.collection_deleted(attempt, generation, now)
            }
            Ok(Dispatched::Answered(ArchiveAnswer::UploadGone)) => {
                self.unanswered.remove(&sequence);
                Ok(Stepped::Waiting {
                    reason: "the service answered a publication as an upload it holds none of"
                        .to_owned(),
                })
            }
            Ok(Dispatched::NotSent(error)) => {
                self.unanswered.remove(&sequence);
                Ok(Stepped::Waiting {
                    reason: format!("the publication was not sent: {error}"),
                })
            }
            // The service answered and published nothing. One that already holds a generation of
            // the archive at or above this one never takes it, whatever the refusal said, so the
            // attempt ends there; otherwise the same publication sent again is the first one that
            // can land.
            Err(error @ ClientError::Refused { .. }) => {
                self.unanswered.remove(&sequence);
                if let Some(held) = self.passed_by(generation).await {
                    let reason = format!(
                        "the service already holds generation {} of archive {} and takes no \
                         generation at or below it, so this one is never published and it is not \
                         sent again. Generation {} carries its content",
                        held.get(),
                        generation.archive_id,
                        held.get()
                    );
                    return self.give_up(attempt, generation, reason, now);
                }
                Ok(Stepped::Waiting {
                    reason: format!("the service did not publish the generation: {error}"),
                })
            }
            Err(error) => Ok(Stepped::Waiting {
                reason: format!("the publication may have left and was not answered: {error}"),
            }),
        }
    }

    fn published(&mut self, attempt: &Attempt, now: TimestampMs) -> Result<Stepped> {
        match self.backup.note_published(
            attempt.sequence,
            PrivacyGeneration::new(attempt.privacy_generation),
            now,
        ) {
            Ok(publication) => {
                self.unanswered.remove(&attempt.sequence);
                self.dispatched_here.remove(&attempt.sequence);
                Ok(Stepped::Published {
                    sequence: attempt.sequence,
                    publication,
                })
            }
            Err(error) => waiting_on(error),
        }
    }

    /// Whether the service holds this generation's descriptor under the writer that sealed it.
    async fn held(&self, generation: &GenerationRecord) -> std::result::Result<bool, ClientError> {
        let Some(descriptor) = descriptor_of(generation) else {
            return Ok(false);
        };
        let fetched = self
            .manifest
            .fetch(
                generation.archive_id,
                Some(generation.backup_generation),
                None,
            )
            .await?;
        Ok(fetched.is_some_and(|fetched| {
            fetched.publication.payload.descriptor == descriptor
                && fetched.publication.payload.writer_key_id == generation.writer_key_id
        }))
    }

    /// The newest generation the service holds of `generation`'s archive, when that is another
    /// publication at or above this generation.
    ///
    /// The service takes no generation at or below the newest it has held, so this generation is
    /// then never published. None when the service holds nothing that high, when its newest is
    /// this very publication, or when it cannot say now.
    async fn passed_by(&self, generation: &GenerationRecord) -> Option<BackupGeneration> {
        let newest = self
            .manifest
            .fetch(generation.archive_id, None, None)
            .await
            .ok()
            .flatten()?;
        let payload = &newest.publication.payload;
        let this_one = descriptor_of(generation).is_some_and(|descriptor| {
            payload.descriptor == descriptor && payload.writer_key_id == generation.writer_key_id
        });
        let held = payload.descriptor.backup_generation;
        (held >= generation.backup_generation && !this_one).then_some(held)
    }

    /// The generation's publication, made the same way every time: the writer's signature over its
    /// descriptor at the instant the generation was admitted.
    fn publication(
        &self,
        generation: &GenerationRecord,
    ) -> std::result::Result<BackupGenerationPublication, String> {
        if self.writer.key_id() != generation.writer_key_id {
            return Err(
                "this host holds no signing key for the writer that sealed that generation"
                    .to_owned(),
            );
        }
        let Some(descriptor) = descriptor_of(generation) else {
            return Err("that generation holds no descriptor this build reads".to_owned());
        };
        let payload = BackupGenerationPublicationPayload {
            descriptor,
            writer_key_id: generation.writer_key_id,
            published_at_ms: generation.created_at_ms,
        };
        let unsigned =
            |error: &dyn fmt::Display| format!("the publication could not be signed: {error}");
        let input = payload.signing_input().map_err(|error| unsigned(&error))?;
        let transcript = SigningTranscript::from_canonical_bytes(BACKUP_PUBLICATION_DOMAIN, input)
            .map_err(|error| unsigned(&error))?;
        let signature =
            kr_crypto::sign::sign(&self.writer, &transcript).map_err(|error| unsigned(&error))?;
        Ok(BackupGenerationPublication { payload, signature })
    }

    /* ---------------------------------------------------------------------- */
    /* What an unknown generation left at the service                          */
    /* ---------------------------------------------------------------------- */

    /// Gives back, one object a step, what a generation no publication can name left at the
    /// service.
    ///
    /// A generation left behind is asked about first: the service holding it means its
    /// publication landed before the newer one, and it is written down as published and keeps
    /// everything. One the service does not hold never will, so each of its objects that no other
    /// generation still names is deleted, and the answer written down.
    async fn reclaim(
        &mut self,
        outbox: &[Attempt],
        privacy: &PrivacyStatus,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Option<Stepped>> {
        loop {
            let Some(work) = self
                .reclaimable(outbox, privacy)?
                .into_iter()
                .find(|work| !turn.unreclaimed.contains(&work.generation_key()))
            else {
                return Ok(None);
            };
            let generation = match work {
                Reclaim::Delete(generation, object) => {
                    return self
                        .release(&generation, &object, now, turn)
                        .await
                        .map(Some);
                }
                Reclaim::Ask(generation) => generation,
            };
            let generation_key = generation_key(&generation);
            match self.held(&generation).await {
                // Its objects can be deleted now, in this step.
                Ok(false) => {
                    self.unheld.insert(generation_key);
                }
                Ok(true) => return self.found_published(&generation, now, turn).map(Some),
                Err(error) => {
                    turn.unreclaimed.insert(generation_key);
                    return Ok(Some(Stepped::Waiting {
                        reason: format!(
                            "whether the service holds backup generation {} of archive {}, which \
                             no publication can name any more, is not known: {error}",
                            generation.backup_generation.get(),
                            generation.archive_id
                        ),
                    }));
                }
            }
        }
    }

    /// What can be done now about generations no publication can name, in the order of the store.
    ///
    /// Each such generation is asked about until the service is known not to hold it: this
    /// process asked, or a deletion of one of its objects is written down, which is only ever
    /// asked for after that. Then each object of it is deleted that is not yet written down as
    /// released and that no other generation this host records names, unless that generation is
    /// one no publication can name either and the service is known not to hold. Nothing is done
    /// under privacy mode, whose retained artifacts are deleted only by the person's own action.
    fn reclaimable(&self, outbox: &[Attempt], privacy: &PrivacyStatus) -> Result<Vec<Reclaim>> {
        if privacy.inhibited_at().is_some() {
            return Ok(Vec::new());
        }
        let generations = self.backup.generations()?;
        let uploads = self.backup.store().uploads()?;
        let mut behind: Vec<(GenerationRecord, Vec<ObjectRecord>, bool)> = Vec::new();
        for record in &generations {
            if !self.left_behind(record, &generations, outbox, &uploads, privacy)? {
                continue;
            }
            let objects = self
                .backup
                .objects(record.archive_id, record.backup_generation)?;
            let unheld = self.unheld.contains(&generation_key(record))
                || objects.iter().any(|object| object.released_at_ms.is_some());
            behind.push((record.clone(), objects, unheld));
        }
        if behind.is_empty() {
            return Ok(Vec::new());
        }
        // Every generation of each archive that names each object, whatever its state.
        let mut named: BTreeMap<(ArchiveId, BackupObjectId), Vec<BackupGeneration>> =
            BTreeMap::new();
        for record in &generations {
            if !behind
                .iter()
                .any(|(left, _, _)| left.archive_id == record.archive_id)
            {
                continue;
            }
            for object in self
                .backup
                .objects(record.archive_id, record.backup_generation)?
            {
                named
                    .entry((object.archive_id, object.object_id))
                    .or_default()
                    .push(record.backup_generation);
            }
        }
        let settled = |archive_id: ArchiveId, backup_generation: BackupGeneration| {
            behind.iter().any(|(left, _, unheld)| {
                *unheld
                    && left.archive_id == archive_id
                    && left.backup_generation == backup_generation
            })
        };
        let mut work = Vec::new();
        for (record, objects, unheld) in &behind {
            let unreleased = objects
                .iter()
                .filter(|object| object.released_at_ms.is_none());
            if !*unheld {
                if objects.iter().any(|object| object.released_at_ms.is_none()) {
                    work.push(Reclaim::Ask(record.clone()));
                }
                continue;
            }
            for object in unreleased {
                let held_elsewhere = named
                    .get(&(object.archive_id, object.object_id))
                    .into_iter()
                    .flatten()
                    .any(|other| {
                        *other != record.backup_generation && !settled(record.archive_id, *other)
                    });
                if !held_elsewhere {
                    work.push(Reclaim::Delete(record.clone(), object.clone()));
                }
            }
        }
        Ok(work)
    }

    /// Whether no publication can name `record` any more, and nothing of it is still in hand.
    ///
    /// Its production ended with its outcome unknown, no attempt or upload of it is open, privacy
    /// mode drew no line under it, its writer is still enrolled for the archive, so no deleted
    /// collection is touched, and this host holds a newer generation of the archive as published:
    /// the service takes no generation at or below the newest it has held.
    fn left_behind(
        &self,
        record: &GenerationRecord,
        generations: &[GenerationRecord],
        outbox: &[Attempt],
        uploads: &[UploadRecord],
        privacy: &PrivacyStatus,
    ) -> Result<bool> {
        let key = generation_key(record);
        if record.production != Production::Cancelled
            || record.remote != Remote::Unknown
            || privacy_line(record, privacy).is_some()
            || outbox
                .iter()
                .any(|attempt| (attempt.archive_id, attempt.backup_generation) == key)
            || uploads
                .iter()
                .any(|upload| (upload.archive_id, upload.backup_generation) == key)
        {
            return Ok(false);
        }
        let passed = generations.iter().any(|newer| {
            newer.archive_id == record.archive_id
                && newer.backup_generation > record.backup_generation
                && newer.remote == Remote::Published
        });
        Ok(passed
            && self
                .backup
                .store()
                .authorises(record.archive_id, record.writer_key_id)?)
    }

    /// Deletes one object of a generation no publication can name, and writes the answer down.
    ///
    /// A deletion the service answered and one it answered by holding no object of that name
    /// both end with nothing of it charged beyond the service's tombstone window. Any other answer
    /// leaves it for the next pass.
    async fn release(
        &mut self,
        generation: &GenerationRecord,
        object: &ObjectRecord,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        let deleted = match self
            .storage
            .delete_object(generation.archive_id, object.object_id)
            .await
        {
            Ok(_) => true,
            Err(error) if error.code() == ErrorCode::UnknownSession => false,
            Err(error) => {
                turn.unreclaimed.insert(generation_key(generation));
                return Ok(Stepped::Waiting {
                    reason: format!(
                        "object {} of backup generation {} of archive {} was not deleted at the \
                         service yet: {error}",
                        object.object_id,
                        generation.backup_generation.get(),
                        generation.archive_id
                    ),
                });
            }
        };
        let recorded = self.backup.store().note_object_released(
            generation.archive_id,
            generation.backup_generation,
            object.object_id,
            now,
        );
        let stepped = match recorded {
            Ok(()) => Stepped::Released {
                archive_id: generation.archive_id,
                backup_generation: generation.backup_generation,
                object_id: object.object_id,
                deleted,
            },
            Err(error) => waiting_on(error)?,
        };
        if matches!(stepped, Stepped::Waiting { .. }) {
            turn.unreclaimed.insert(generation_key(generation));
        }
        Ok(stepped)
    }

    /// Writes down a generation of unknown outcome the service turns out to hold: its publication
    /// reached the service after all, under the attempt that sent it.
    fn found_published(
        &mut self,
        generation: &GenerationRecord,
        now: TimestampMs,
        turn: &mut Turn,
    ) -> Result<Stepped> {
        let sent = self.backup.attempts()?.into_iter().find(|attempt| {
            attempt.archive_id == generation.archive_id
                && attempt.backup_generation == generation.backup_generation
                && attempt.step == Step::Publish
        });
        let stepped = match sent {
            Some(attempt) => self.published(&attempt, now)?,
            None => Stepped::Waiting {
                reason: format!(
                    "the service holds backup generation {} of archive {}, which this host has no \
                     record of sending, so everything it named is kept",
                    generation.backup_generation.get(),
                    generation.archive_id
                ),
            },
        };
        if matches!(stepped, Stepped::Waiting { .. }) {
            turn.unreclaimed.insert(generation_key(generation));
        }
        Ok(stepped)
    }
}

/// One thing that can be done about a generation no publication can name any more.
enum Reclaim {
    /// Ask the service whether it holds the generation.
    Ask(GenerationRecord),
    /// Delete one object of a generation the service does not hold.
    Delete(GenerationRecord, ObjectRecord),
}

impl Reclaim {
    fn generation_key(&self) -> (ArchiveId, BackupGeneration) {
        match self {
            Self::Ask(generation) | Self::Delete(generation, _) => generation_key(generation),
        }
    }
}

/// One generation, as the uploader keys what it knows about it.
const fn generation_key(generation: &GenerationRecord) -> (ArchiveId, BackupGeneration) {
    (generation.archive_id, generation.backup_generation)
}

/// Whether `generation` may still produce: nothing inhibits production, it is producing, and it was
/// admitted under the privacy generation in force. The store's own rule, read the same way.
fn may_produce(generation: &GenerationRecord, privacy: &PrivacyStatus) -> bool {
    privacy.inhibited_at().is_none()
        && generation.production == Production::Producing
        && generation.privacy_generation == privacy.current_generation
}

/// Whether the store still holds `attempt` dispatched to this uploader, and its generation may
/// still produce, read just before a request of it leaves.
///
/// The store is the control: an attempt it no longer holds, or holds for another executor, is never
/// sent, and nothing is sent under a fence or before this host is ready.
fn may_send(backup: &BackupService, attempt: &Attempt) -> Result<bool> {
    if backup.unready().is_some() {
        return Ok(false);
    }
    let privacy = backup.privacy_status()?;
    let held = backup.outbox()?.iter().any(|held| {
        held.sequence == attempt.sequence
            && held.status == AttemptStatus::Dispatched
            && held.executor.as_deref() == Some(EXECUTOR)
    });
    if !held {
        return Ok(false);
    }
    Ok(backup
        .generation(attempt.archive_id, attempt.backup_generation)?
        .is_some_and(|generation| may_produce(&generation, &privacy)))
}

/// Why a generation may no longer produce, for the attempt that stops over it.
fn production_over(generation: &GenerationRecord, privacy: &PrivacyStatus) -> String {
    if privacy.inhibited_at().is_none() && generation.production != Production::Producing {
        return generation.detail.clone().unwrap_or_else(|| {
            format!(
                "that backup generation's production is {}",
                generation.production.as_str()
            )
        });
    }
    privacy_line(generation, privacy)
        .unwrap_or_else(|| "that backup generation may no longer produce".to_owned())
}

/// The line privacy mode drew under `generation`, if it drew one: backup production stopped, or
/// this host moved to a later privacy generation since the work was admitted.
fn privacy_line(generation: &GenerationRecord, privacy: &PrivacyStatus) -> Option<String> {
    if let Some(fenced) = privacy.inhibited_at() {
        return Some(format!(
            "privacy mode stopped backup production at privacy generation {fenced}"
        ));
    }
    (generation.privacy_generation != privacy.current_generation).then(|| {
        format!(
            "that backup work was admitted under privacy generation {}, and this host is at {}",
            generation.privacy_generation, privacy.current_generation
        )
    })
}

/// What a generation whose outcome is unknown is to a person: never a completed backup, never
/// sent again, and carried by the next generation unless privacy mode drew its line under it.
fn never_complete(privacy: Option<&str>) -> String {
    let carried = privacy.map_or_else(
        || "the next generation carries its content".to_owned(),
        |line| format!("no later generation carries its content, because {line}"),
    );
    format!("It is not a completed backup and it is not sent again, and {carried}")
}

/// Whether another upload attempt of `attempt`'s generation is already carrying its objects.
fn carried(attempt: &Attempt, outbox: &[Attempt]) -> bool {
    outbox.iter().any(|other| {
        other.sequence != attempt.sequence
            && other.archive_id == attempt.archive_id
            && other.backup_generation == attempt.backup_generation
            && other.step == Step::Upload
            && other.status == AttemptStatus::Dispatched
    })
}

/// Whether the service refused a request as not permitted, which about an upload covers one that
/// expired or closed as well as proofs the service could not bind.
fn not_permitted(error: &ClientError) -> bool {
    matches!(error, ClientError::Refused { error, .. } if error.code == ErrorCode::PermissionDenied)
}

/// What a step is when the attempt it was about to send for is no longer this uploader's to send.
fn not_carried() -> Stepped {
    Stepped::Waiting {
        reason:
            "the store no longer holds that attempt for this uploader, or its generation may no \
                 longer produce"
                .to_owned(),
    }
}

/// What stops an upload part-way when the store no longer holds its attempt for this uploader.
///
/// Nothing reads it: the uploader knows why it stopped the upload.
fn held_back() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::PermissionDenied,
        "this host stopped the upload before its next part".to_owned(),
    ))
}

/// A store refusal that says to wait, rather than a store that failed.
fn waiting_on(error: ControllerError) -> Result<Stepped> {
    match error {
        ControllerError::Refused { .. }
        | ControllerError::PermissionDenied { .. }
        | ControllerError::InvalidArgument(_) => Ok(Stepped::Waiting {
            reason: error.to_string(),
        }),
        other => Err(other),
    }
}

/// The descriptor a generation was sealed with, as it was recorded.
fn descriptor_of(generation: &GenerationRecord) -> Option<ArchiveDescriptor> {
    generation
        .descriptor
        .as_deref()
        .and_then(|bytes| ArchiveDescriptor::from_canonical_bytes(bytes).ok())
}

/// One object, as a pass keys the uploads it has ended.
const fn key(object: &ObjectRecord) -> (ArchiveId, BackupGeneration, BackupObjectId) {
    (
        object.archive_id,
        object.backup_generation,
        object.object_id,
    )
}

/// Why a staged object is not sent.
enum Unstaged {
    /// It could not be read now, which a later pass may not meet.
    Unreadable(String),
    /// It is gone, or is not the ciphertext this host admitted, so it can never be sent.
    NotAdmitted(String),
}

/// Reads one object's staged ciphertext whole and holds it to what this host admitted.
///
/// The object is bounded by the part table's own limit first, and the file's length is read before
/// its bytes, so a file of another size is refused without being read.
fn staged(object: &ObjectRecord) -> std::result::Result<Vec<u8>, Unstaged> {
    let not_admitted = || {
        Unstaged::NotAdmitted(format!(
            "the staged ciphertext of object {} is not what this host admitted",
            object.object_id
        ))
    };
    let unreadable = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Unstaged::NotAdmitted(format!(
                "the staged ciphertext of object {} is gone from this host",
                object.object_id
            ))
        } else {
            Unstaged::Unreadable(format!(
                "the staged ciphertext of object {} could not be read: {error}",
                object.object_id
            ))
        }
    };
    if PartTable::for_total(object.encrypted_len).is_none() {
        return Err(Unstaged::NotAdmitted(format!(
            "object {} is empty or larger than the storage service stores",
            object.object_id
        )));
    }
    let length = std::fs::metadata(&object.staged_path)
        .map_err(unreadable)?
        .len();
    if length != object.encrypted_len {
        return Err(not_admitted());
    }
    let bytes = std::fs::read(&object.staged_path).map_err(unreadable)?;
    if bytes.len() as u64 != object.encrypted_len
        || Digest256::from_bytes(kr_cbor::sha256(&bytes)) != object.encrypted_object_hash
    {
        return Err(not_admitted());
    }
    Ok(bytes)
}
