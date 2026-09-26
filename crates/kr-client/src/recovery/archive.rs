//! This device's settings, backed up as a recovery-enabled archive.
//!
//! Section 20 ¶9 and ¶10. A generation is one member: the settings object [`export_settings`]
//! reads, carried under [`SETTINGS_FILENAME`] and sealed by `kr_crypto::backup` with its manifest
//! key wrapped for the recovery recipient, so a restore holding only the kit can open it. The
//! device uploads the member and the encrypted manifest to managed storage, then publishes the
//! descriptor through the backup manifest under the signature of the writer the recovery bundle
//! names.
//!
//! # The bundle first
//!
//! [`SettingsArchive::enable`] commits a bundle that names the archive's collection, its producer
//! and its writer, and only once that commit has landed does it enrol the writer at the manifest
//! service. A generation is made only by a [`SettingsArchive`], and a [`SettingsArchive`] holds the
//! [`WriterEnabled`] evidence, which nothing but a landed commit or a read of a bundle carrying the
//! writer produces. So no archive is published by a writer a restore could not verify.
//!
//! # Privacy mode
//!
//! The export refuses while privacy mode is on, before anything is sent, and names the privacy
//! generation it read the settings under. After that, every request of the generation leaves
//! through one transport that reads the device's privacy state at the moment it is handed the
//! request, which is after the request's account token is in hand and the request is signed. A
//! fence, or a generation that has moved on, that lands at any moment before then keeps the request
//! on this device, and every request after it; an upload it stops is abandoned at the service.
//!
//! # What this device writes down
//!
//! Before an object of a generation leaves, its identity is written down in the collection's
//! records directory, and a generation whose publication is answered is struck off. What stays
//! listed, across a restart, is every generation whose objects may be at the service without a
//! publication this device saw answered: one stopped by privacy mode, one that failed, and one
//! whose publication was never answered. [`SettingsArchive::unsettled`] lists them, so they can be
//! shown and removed; nothing here removes them.
//!
//! Each change of the record holds a lock beside it from the read to the rename, so two changes,
//! from one process or two, cannot each write over what the other added. The record is written
//! within the bounds it is read back under: a change that would take it past them is refused, and
//! no object leaves without its identity written down.
//!
//! # What leaves this device
//!
//! Ciphertext, the public descriptor and the records the owner and the writer sign. The settings
//! plaintext is cleared when its export is dropped, which is as soon as the generation is sealed.
//! Making a generation takes the recovery recipient's public key and nothing else of the seed.
//!
//! A generation that fails part-way is not made again under the same number: a new one is sealed
//! under new keys, so it is made as the next generation.

use std::fmt;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, ObjectSource, SealedArchive, seal_archive,
    stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_flush::{NameKind, flush_directory};
use kr_protocol::archive::{
    BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, BackupWriterRecord, BackupWriterRecordPayload,
    CollectionLocator, RecoveryBundle, TrustedProducer, TrustedWriter,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId, SyncObjectId,
};
use kr_protocol::scalars::{Digest256, StoredEnvelopeKey, TimestampMs};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::recovery::{
    BundleStore, RecoveryError, Result, SETTINGS_FILENAME, WriterEnabled, export_settings,
};
use crate::services::account::AccountTokenSource;
use crate::services::backup::ManagedBackupManifestService;
use crate::services::storage::{
    ManagedStorageService, STORAGE_UPLOAD_ABORT_PATH, collection_deleted,
};
use crate::services::{
    ArchiveAnswer, BackupManifestService, Dispatched, NewUpload, Published, ServiceFuture,
    ServiceHttp, ServiceHttpAnswer, ServiceSigner, StorageService, UploadProgress, upload_parts,
};
use crate::shown::{IoFault, Shown};
use crate::sync::{SyncError, SyncStore};

/// Where one device's settings archive goes, the keys each generation of it is made with, and where
/// this device writes down what each generation sent.
pub struct SettingsCollection {
    /// The archive the settings go to.
    pub archive_id: ArchiveId,
    /// The service origin its collection lives at, which the bundle names for a restore.
    pub service_origin: String,
    /// The device that owns the archive.
    pub owner_device_id: DeviceId,
    /// The key that signs each generation's manifest and publication.
    pub writer: AuthorisationKeyPair,
    /// The revision of the collection's enrolment that names this writer.
    pub writer_revision: BackupWriterRevision,
    /// The key the object keys and the manifest key are wrapped from.
    pub producer: StoredEnvelopeKeyPair,
    /// The recovery recipient's public key, which every generation's manifest key is wrapped for.
    pub recovery: StoredEnvelopeKey,
    /// The directory this device keeps its recovery state in, which has to exist already. One
    /// archive's record of what its generations sent is kept there, named after the archive, with
    /// the lock each change of it holds.
    pub records: PathBuf,
}

impl fmt::Debug for SettingsCollection {
    /// The archive, the service's origin as a diagnostic names one, and the device that owns it.
    /// Never a key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsCollection")
            .field("archive_id", &self.archive_id)
            .field(
                "service_origin",
                &crate::shown::Shown::address(&self.service_origin),
            )
            .field("owner_device_id", &self.owner_device_id)
            .finish_non_exhaustive()
    }
}

/// The managed services one generation goes to: the gateway, the transport, the key the requests
/// are signed with, and the account whose backup storage the generation spends.
///
/// The requests are signed by the writer's own key, since the service takes a publication only
/// from the writer it enrolled, and they carry the account's token for `backup.write`.
pub struct ArchiveServices {
    /// The gateway.
    pub origin: GatewayOrigin,
    /// The transport requests leave through.
    pub http: Arc<dyn ServiceHttp>,
    /// What signs each request.
    pub signer: Arc<dyn ServiceSigner>,
    /// Where the account's token comes from.
    pub tokens: Arc<dyn AccountTokenSource>,
}

impl fmt::Debug for ArchiveServices {
    /// The gateway and the signer's kind. Never a token.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signer: kr_protocol::service::ServiceRequestSigner = self.signer.signer();
        formatter
            .debug_struct("ArchiveServices")
            .field("origin", &self.origin)
            .field("signer", &signer)
            .finish_non_exhaustive()
    }
}

/// A settings archive whose writer the recovery bundle carries.
pub struct SettingsArchive {
    collection: SettingsCollection,
    enabled: WriterEnabled,
}

impl fmt::Debug for SettingsArchive {
    /// The collection, as its own rendering gives it, and the bundle revision that carries the
    /// writer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bundle_revision: u64 = self.enabled.bundle_revision();
        formatter
            .debug_struct("SettingsArchive")
            .field("collection", &self.collection)
            .field("bundle_revision", &bundle_revision)
            .finish()
    }
}

/// One generation of the settings, stored and published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsBackedUp {
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// What the backup manifest answered.
    pub published: Published,
}

/// One generation whose objects may be at the service without a publication this device saw
/// answered.
///
/// Its publication may still have landed: one sent without an answer, or answered after this
/// device could not write the answer down, is listed too. Ask the backup manifest before removing
/// anything it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsettled {
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// Every object of it that left, or was about to leave, this device.
    pub objects: Vec<BackupObjectId>,
}

impl SettingsArchive {
    /// Enables this device's settings writer: the recovery bundle first, the manifest service
    /// second.
    ///
    /// The bundle is committed naming the archive's collection, the producer a restore opens its
    /// wraps with and the writer it verifies the archive against, in one write. Only once that
    /// write has landed is the writer enrolled for the collection, under the owner's signature,
    /// through `manifest`, which signs as the owner. A commit that fails enrols nothing.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BundleStore::enable_writer`] returns, [`Service`] when the manifest
    /// service refuses or does not answer the enrolment, and [`Crypto`] or [`Cbor`] when the
    /// enrolment cannot be signed.
    ///
    /// [`Service`]: super::RecoveryError::Service
    /// [`Crypto`]: super::RecoveryError::Crypto
    /// [`Cbor`]: super::RecoveryError::Cbor
    pub async fn enable(
        collection: SettingsCollection,
        bundles: &mut BundleStore,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        owner: &AuthorisationKeyPair,
        manifest: &dyn BackupManifestService,
        now: TimestampMs,
    ) -> Result<Self> {
        let locator = CollectionLocator {
            service_origin: collection.service_origin.clone(),
            locator: collection.archive_id.to_string(),
            archive_id: collection.archive_id,
        };
        if !bundle.collections.contains(&locator) {
            bundle.collections.push(locator);
        }
        let sender_key_id = collection.producer.key_id();
        let mut producers: Vec<TrustedProducer> = bundle
            .trusted_producers
            .iter()
            .filter(|held| held.sender_key_id != sender_key_id)
            .cloned()
            .collect();
        producers.push(TrustedProducer {
            sender_key_id,
            stored_envelope_key: *collection.producer.public(),
            enrolled_at_ms: now,
        });
        bundle.trusted_producers = producers.into_iter().collect();
        let writer = TrustedWriter {
            writer_key_id: collection.writer.key_id(),
            signing_key: *collection.writer.public(),
            enrolled_at_ms: now,
        };
        let enabled = bundles
            .enable_writer(seed, bundle, writer.clone(), now)
            .await?;
        manifest
            .enrol(&enrolment(owner, &collection, writer, now)?)
            .await?;
        Ok(Self {
            collection,
            enabled,
        })
    }

    /// Takes the settings archive up again, for a device that enabled its writer earlier.
    ///
    /// The bundle is read from the service and authenticated here, so what decides is what the
    /// service holds and not a copy a caller kept. The archive is taken up only when that bundle
    /// names this collection at its origin, this producer's key and this writer's key, as
    /// [`Self::enable`] committed them: a writer a restore can verify is not enough when the
    /// restore could not find the collection or open its wraps. Answers none otherwise.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BundleStore::fetch`] returns.
    pub async fn resume(
        collection: SettingsCollection,
        bundles: &mut BundleStore,
        seed: &RecoverySeed,
    ) -> Result<Option<Self>> {
        let bundle = bundles.fetch(seed).await?;
        let carried = bundle.collections.iter().any(|held| {
            held.archive_id == collection.archive_id
                && held.service_origin == collection.service_origin
        }) && bundle.trusted_producers.iter().any(|held| {
            held.sender_key_id == collection.producer.key_id()
                && held.stored_envelope_key == *collection.producer.public()
        }) && bundle.trusted_writers.iter().any(|held| {
            held.writer_key_id == collection.writer.key_id()
                && held.signing_key == *collection.writer.public()
        });
        if !carried {
            return Ok(None);
        }
        Ok(bundles
            .writer_enabled(collection.writer.key_id())
            .map(|enabled| Self {
                collection,
                enabled,
            }))
    }

    /// Backs up this device's settings object as generation `generation`.
    ///
    /// The object is exported under the privacy generation in force, sealed as one member for the
    /// recovery recipient, and uploaded with the encrypted manifest and published through
    /// `services`, every request of it leaving through the privacy gate the module describes.
    ///
    /// # Errors
    ///
    /// Returns [`Sync`] with [`SyncError::Fenced`] while privacy mode is on, whether that is found
    /// before anything is sent or when a later request is handed over, and with
    /// [`SyncError::LateResult`] once the privacy generation has moved on from the one the settings
    /// were read under. Returns [`Service`] when a service refuses or does not answer, a collection
    /// deleted from the account console among them, [`Storage`] when this device cannot write down
    /// what a generation sent, and the export's and the producer's own errors otherwise.
    ///
    /// [`Sync`]: super::RecoveryError::Sync
    /// [`Service`]: super::RecoveryError::Service
    /// [`Storage`]: super::RecoveryError::Storage
    pub async fn back_up(
        &self,
        store: &SyncStore,
        object_id: SyncObjectId,
        generation: BackupGeneration,
        services: &ArchiveServices,
        now: TimestampMs,
    ) -> Result<SettingsBackedUp> {
        let collection = &self.collection;
        let exported = export_settings(store, object_id)?;
        let produced_under = exported.produced_under();
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        recipients.add(collection.recovery);
        let member = stage_object(
            &ObjectSource {
                object_id: fresh_object_id()?,
                filename: SETTINGS_FILENAME,
                plaintext: exported.plaintext(),
            },
            recipients.rotation(),
        )?;
        let sealed = seal_archive(
            &collection.writer,
            &collection.producer,
            &recipients,
            &ArchivePlan {
                archive_id: collection.archive_id,
                backup_generation: generation,
                owner_device_id: collection.owner_device_id,
                manifest_object_id: fresh_object_id()?,
                created_at_ms: now,
            },
            std::slice::from_ref(&member),
        )?;
        // The plaintext is cleared here: everything after this is ciphertext.
        drop(exported);

        let gate = Arc::new(PrivacyGate::new(
            Arc::clone(&services.http),
            store,
            produced_under,
        )?);
        let transport: Arc<dyn ServiceHttp> = gate.clone();
        let storage = ManagedStorageService::new(
            services.origin.clone(),
            Arc::clone(&transport),
            Arc::clone(&services.signer),
        )
        .presenting(Arc::clone(&services.tokens));
        let manifest = ManagedBackupManifestService::new(
            services.origin.clone(),
            transport,
            Arc::clone(&services.signer),
        )
        .presenting(Arc::clone(&services.tokens));

        let sent = self.journal();
        let encrypted_manifest = &sealed.descriptor.encrypted_manifest;
        for leaving in [
            Leaving {
                object_id: member.object_id(),
                bytes: member.bytes(),
                hash: member.reference().encrypted_object_hash,
            },
            Leaving {
                object_id: encrypted_manifest.object_id,
                bytes: sealed.encrypted_manifest.as_slice(),
                hash: encrypted_manifest.encrypted_object_hash,
            },
        ] {
            sent.note_leaving(generation, leaving.object_id)?;
            self.upload(&storage, &gate, generation, leaving).await?;
        }

        let publication = self.publication(&sealed, now)?;
        let manifest: &dyn BackupManifestService = &manifest;
        let answered = match manifest.publish_dispatched(&publication).await {
            Ok(answered) => answered,
            Err(error) => return Err(gate.refusal().unwrap_or_else(|| error.into())),
        };
        match answered {
            Dispatched::Answered(ArchiveAnswer::Done(published)) => {
                sent.settle(generation)?;
                Ok(SettingsBackedUp {
                    backup_generation: generation,
                    published,
                })
            }
            Dispatched::Answered(ArchiveAnswer::CollectionDeleted) => {
                Err(collection_deleted().into())
            }
            Dispatched::Answered(ArchiveAnswer::UploadGone) => {
                Err(contrary("a publication as an upload it holds none of").into())
            }
            Dispatched::NotSent(error) => Err(error.into()),
        }
    }

    /// Every generation of this archive whose objects may be at the service without a publication
    /// this device saw answered, as this device wrote them down.
    ///
    /// # Errors
    ///
    /// Returns [`Storage`] when the record cannot be read, and [`Cbor`] when it is not one this
    /// build reads.
    ///
    /// [`Storage`]: super::RecoveryError::Storage
    /// [`Cbor`]: super::RecoveryError::Cbor
    pub fn unsettled(&self) -> Result<Vec<Unsettled>> {
        Ok(self
            .journal()
            .read()?
            .generations
            .into_iter()
            .map(|written| Unsettled {
                backup_generation: written.backup_generation,
                objects: written.objects,
            })
            .collect())
    }

    /// Strikes one generation off the list, once whatever it left at the service has been dealt
    /// with. Returns whether it was listed.
    ///
    /// # Errors
    ///
    /// As [`Self::unsettled`], and [`Storage`] when the record cannot be written.
    ///
    /// [`Storage`]: super::RecoveryError::Storage
    pub fn forget_unsettled(&self, generation: BackupGeneration) -> Result<bool> {
        self.journal().settle(generation)
    }

    fn journal(&self) -> Journal {
        Journal::of(&self.collection.records, self.collection.archive_id)
    }

    /// Uploads one object of a generation whole, in the parts its table cuts.
    ///
    /// A request the privacy gate keeps on this device fails, and an upload that is open by then is
    /// abandoned at the service before the refusal is given back.
    async fn upload(
        &self,
        storage: &dyn StorageService,
        gate: &PrivacyGate,
        generation: BackupGeneration,
        leaving: Leaving<'_>,
    ) -> Result<()> {
        let Leaving {
            object_id,
            bytes,
            hash,
        } = leaving;
        let total = bytes.len() as u64;
        let upload = NewUpload {
            archive_id: self.collection.archive_id,
            object_id,
            backup_generation: generation,
            declared_max_bytes: total,
            total_bytes: total,
            encrypted_object_hash: hash,
        };
        let mut progress = match storage.create_upload(&upload).await {
            Ok(ArchiveAnswer::Done(created)) => created.progress(),
            Ok(ArchiveAnswer::CollectionDeleted) => return Err(collection_deleted().into()),
            Ok(ArchiveAnswer::UploadGone) => {
                return Err(contrary("a creation as an upload it holds none of").into());
            }
            Err(error) => return Err(gate.refusal().unwrap_or_else(|| error.into())),
        };
        let mut nothing_kept = |_: &UploadProgress| -> crate::Result<()> { Ok(()) };
        match upload_parts(storage, &mut progress, bytes, &mut nothing_kept).await {
            Ok(ArchiveAnswer::Done(())) => {}
            Ok(ArchiveAnswer::CollectionDeleted) => return Err(collection_deleted().into()),
            Ok(ArchiveAnswer::UploadGone) => {
                return Err(contrary("a part as an upload it holds none of").into());
            }
            Err(error) => return Err(stopped_or(storage, gate, &progress, error).await),
        }
        match storage
            .complete_upload(&progress.upload_id, &progress.table)
            .await
        {
            Ok(ArchiveAnswer::Done(completed))
                if completed.object.object_id == object_id
                    && completed.object.encrypted_object_hash == hash
                    && completed.object.encrypted_len == total =>
            {
                Ok(())
            }
            Ok(ArchiveAnswer::Done(_)) => Err(contrary("a completion of another object").into()),
            Ok(ArchiveAnswer::CollectionDeleted) => Err(collection_deleted().into()),
            Ok(ArchiveAnswer::UploadGone) => {
                Err(contrary("a completion as an upload it holds none of").into())
            }
            Err(error) => Err(stopped_or(storage, gate, &progress, error).await),
        }
    }

    /// The generation's publication, signed by the writer.
    fn publication(
        &self,
        sealed: &SealedArchive,
        now: TimestampMs,
    ) -> Result<BackupGenerationPublication> {
        let payload = BackupGenerationPublicationPayload {
            descriptor: sealed.descriptor.clone(),
            writer_key_id: self.collection.writer.key_id(),
            published_at_ms: now,
        };
        let transcript = SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input()?,
        )?;
        Ok(BackupGenerationPublication {
            signature: sign(&self.collection.writer, &transcript)?,
            payload,
        })
    }
}

/// One object of a generation on its way to the service: its identity, its ciphertext and the
/// ciphertext's hash.
struct Leaving<'a> {
    object_id: BackupObjectId,
    bytes: &'a [u8],
    hash: Digest256,
}

/// What a failed request of an open upload comes to: the privacy refusal, once the upload is
/// abandoned, when the gate kept the request here; the error itself otherwise.
///
/// The abandonment is asked for once. An upload it does not end was never completed, so it ends
/// when its lifetime runs out.
async fn stopped_or(
    storage: &dyn StorageService,
    gate: &PrivacyGate,
    progress: &UploadProgress,
    error: ClientError,
) -> RecoveryError {
    match gate.refusal() {
        Some(stopped) => {
            let _ = storage.abort_upload(&progress.upload_id).await;
            stopped
        }
        None => error.into(),
    }
}

/// The transport one generation's requests leave through, which reads this device's privacy state
/// at the moment it is handed each request.
///
/// A request reaches it only once its account token is in hand and it is signed, which is the last
/// moment before its bytes leave, so a fence or a moved generation that lands before then keeps
/// the request on this device. Once it has kept one request it keeps every other. Abandoning an
/// upload is let through: it carries no content, and it is how an upload privacy mode stopped is
/// ended.
struct PrivacyGate {
    http: Arc<dyn ServiceHttp>,
    store: SyncStore,
    produced_under: u64,
    kept: Mutex<Kept>,
}

/// Whether the gate has kept a request, and why, until the reason is taken.
#[derive(Default)]
struct Kept {
    closed: bool,
    because: Option<SyncError>,
}

impl PrivacyGate {
    fn new(http: Arc<dyn ServiceHttp>, store: &SyncStore, produced_under: u64) -> Result<Self> {
        Ok(Self {
            http,
            store: SyncStore::open(store.directory())?,
            produced_under,
            kept: Mutex::new(Kept::default()),
        })
    }

    /// Lets one request through to the transport, or keeps it here.
    fn admit(&self, url: &str) -> crate::Result<()> {
        if url.ends_with(STORAGE_UPLOAD_ABORT_PATH) {
            return Ok(());
        }
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.closed {
            return Err(kept_here());
        }
        if let Err(because) = still_in_force(&self.store, self.produced_under) {
            kept.closed = true;
            kept.because = Some(because);
            return Err(kept_here());
        }
        Ok(())
    }

    /// Why the gate kept a request, the first time it is asked after one was kept.
    fn refusal(&self) -> Option<RecoveryError> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .because
            .take()
            .map(RecoveryError::Sync)
    }
}

impl fmt::Debug for PrivacyGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyGate")
            .field("produced_under", &self.produced_under)
            .finish_non_exhaustive()
    }
}

impl ServiceHttp for PrivacyGate {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        match self.admit(url) {
            Ok(()) => self.http.post_json(url, body, headers),
            Err(kept) => Box::pin(async move { Err(kept) }),
        }
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        match self.admit(url) {
            Ok(()) => self.http.post_bytes(url, body, headers),
            Err(kept) => Box::pin(async move { Err(kept) }),
        }
    }
}

/// What a request the privacy gate kept fails with. Nothing reads it: the generation takes the
/// reason from the gate.
fn kept_here() -> ClientError {
    ClientError::refusal(
        ErrorCode::PermissionDenied,
        Shown::said("privacy mode kept this request on this device"),
    )
}

/// The bounds the record of sent objects is written within and read back under.
const RECORD_LIMITS: kr_cbor::Limits = kr_cbor::Limits::DEFAULT;

/// The record of what one archive's generations sent, in the collection's records directory.
struct Journal {
    directory: PathBuf,
    path: PathBuf,
    lock: PathBuf,
}

/// What the record holds.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sent {
    /// Every generation not struck off, oldest first.
    generations: Vec<SentGeneration>,
}

/// One generation's objects that left, or were about to leave, this device.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SentGeneration {
    backup_generation: BackupGeneration,
    objects: Vec<BackupObjectId>,
}

/// The lock one change of the record holds, released when it is dropped.
struct Held(std::fs::File);

impl Drop for Held {
    /// Releases the lock itself rather than leaving it to the file's closing, which a descriptor
    /// copied into a child process would delay.
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl Journal {
    fn of(records: &std::path::Path, archive_id: ArchiveId) -> Self {
        Self {
            directory: records.to_path_buf(),
            path: records.join(format!("settings-archive-{archive_id}.sent")),
            lock: records.join(format!("settings-archive-{archive_id}.sent-lock")),
        }
    }

    /// Takes the lock one change of the record holds, waiting for another change to finish.
    fn hold(&self) -> Result<Held> {
        let storage = |source| RecoveryError::Storage {
            path: Shown::root(&self.lock),
            fault: IoFault::from(source),
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock)
            .map_err(storage)?;
        file.lock().map_err(storage)?;
        Ok(Held(file))
    }

    fn read(&self) -> Result<Sent> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(kr_cbor::from_canonical_slice(&bytes, &RECORD_LIMITS)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Sent::default()),
            Err(source) => Err(RecoveryError::Storage {
                path: Shown::root(&self.path),
                fault: IoFault::from(source),
            }),
        }
    }

    /// Writes the record whole, through a partial file renamed into place and flushed, so a stop
    /// at any point leaves the old record or the new one. The caller holds the lock.
    ///
    /// A record past the bounds it is read back under is refused here, before anything is
    /// replaced, so the record on the disk stays one this build reads.
    fn write(&self, sent: &Sent) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec_within(sent, &RECORD_LIMITS)?;
        let partial = self.path.with_extension("sent-partial");
        let written = (|| {
            let mut file = std::fs::File::create(&partial)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            kr_flush::retry_while_held(|| std::fs::rename(&partial, &self.path))?;
            flush_directory(&self.directory, NameKind::File)
        })();
        written.map_err(|source| {
            let _ = std::fs::remove_file(&partial);
            RecoveryError::Storage {
                path: Shown::root(&self.path),
                fault: IoFault::from(source),
            }
        })
    }

    /// Writes down that one object of a generation is about to leave, before it does.
    fn note_leaving(&self, generation: BackupGeneration, object_id: BackupObjectId) -> Result<()> {
        let _held = self.hold()?;
        let mut sent = self.read()?;
        match sent
            .generations
            .iter_mut()
            .find(|held| held.backup_generation == generation)
        {
            Some(held) if held.objects.contains(&object_id) => return Ok(()),
            Some(held) => held.objects.push(object_id),
            None => sent.generations.push(SentGeneration {
                backup_generation: generation,
                objects: vec![object_id],
            }),
        }
        self.write(&sent)
    }

    /// Strikes one generation off. Returns whether it was listed.
    fn settle(&self, generation: BackupGeneration) -> Result<bool> {
        let _held = self.hold()?;
        let mut sent = self.read()?;
        let before = sent.generations.len();
        sent.generations
            .retain(|held| held.backup_generation != generation);
        if sent.generations.len() == before {
            return Ok(false);
        }
        self.write(&sent)?;
        Ok(true)
    }
}

/// The owner's record enrolling `writer` for the collection.
fn enrolment(
    owner: &AuthorisationKeyPair,
    collection: &SettingsCollection,
    writer: TrustedWriter,
    now: TimestampMs,
) -> Result<BackupWriterRecord> {
    let payload = BackupWriterRecordPayload {
        archive_id: collection.archive_id,
        writer,
        writer_revision: collection.writer_revision,
        owner_key_id: owner.key_id(),
        enrolled_at_ms: now,
    };
    let transcript =
        SigningTranscript::from_canonical_bytes(BACKUP_WRITER_DOMAIN, payload.signing_input()?)?;
    Ok(BackupWriterRecord {
        signature: sign(owner, &transcript)?,
        payload,
    })
}

/// Refuses what is about to leave once privacy mode has fenced production, or has moved past the
/// generation the settings were read under.
fn still_in_force(store: &SyncStore, produced_under: u64) -> std::result::Result<(), SyncError> {
    let privacy = store.privacy()?;
    let current = privacy.generation.get();
    if privacy.fenced {
        return Err(SyncError::Fenced {
            generation: current,
        });
    }
    if current != produced_under {
        return Err(SyncError::LateResult {
            produced_under,
            current,
        });
    }
    Ok(())
}

/// A fresh identifier for one object of one generation.
fn fresh_object_id() -> Result<BackupObjectId> {
    Ok(BackupObjectId::new(
        kr_transport::random::fresh_uuid_v4().map_err(ClientError::from)?,
    ))
}

/// An answer that was read and says something the service's contract does not allow.
fn contrary(what: &'static str) -> ClientError {
    ClientError::refusal(
        ErrorCode::OutcomeUnknown,
        crate::shown!("the service answered {}", what),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn object(seed: u16, index: u16) -> BackupObjectId {
        let mut bytes = [0_u8; 16];
        bytes[..2].copy_from_slice(&seed.to_be_bytes());
        bytes[2..4].copy_from_slice(&index.to_be_bytes());
        BackupObjectId::new(Uuid::from_bytes(bytes))
    }

    fn archive() -> ArchiveId {
        ArchiveId::new(Uuid::from_bytes([0x5e; 16]))
    }

    /// Changes made at once, from separate holders of the record, all land: none writes over what
    /// another added.
    #[test]
    fn changes_made_at_once_keep_every_generation() {
        let records = tempfile::tempdir().expect("a directory on the internal disk");
        let writers: Vec<_> = (0..4_u16)
            .map(|writer| {
                let records = records.path().to_path_buf();
                std::thread::spawn(move || {
                    let journal = Journal::of(&records, archive());
                    for generation in 0..8_u16 {
                        let number = u64::from(writer * 100 + generation + 1);
                        journal
                            .note_leaving(BackupGeneration::new(number), object(writer, generation))
                            .expect("the record takes the object");
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("a writer");
        }
        let sent = Journal::of(records.path(), archive())
            .read()
            .expect("the record");
        assert_eq!(sent.generations.len(), 32, "every generation stays listed");
        for generation in &sent.generations {
            assert_eq!(generation.objects.len(), 1);
        }
    }

    /// A record at its bound takes no further generation, and stays one this build reads; the
    /// generations it lists can still take objects and be struck off.
    #[test]
    fn a_record_at_its_bound_refuses_another_generation_and_stays_readable() {
        let records = tempfile::tempdir().expect("a directory on the internal disk");
        let journal = Journal::of(records.path(), archive());
        let full = Sent {
            generations: (1..=4_096_u16)
                .map(|generation| SentGeneration {
                    backup_generation: BackupGeneration::new(u64::from(generation)),
                    objects: vec![object(generation, 0)],
                })
                .collect(),
        };
        {
            let _held = journal.hold().expect("the lock");
            journal.write(&full).expect("a record at its bound");
        }

        let refused = journal.note_leaving(BackupGeneration::new(4_097), object(4_097, 0));
        assert!(
            matches!(refused, Err(RecoveryError::Cbor(_))),
            "{refused:?}"
        );
        assert_eq!(
            journal.read().expect("still readable").generations.len(),
            4_096
        );

        journal
            .note_leaving(BackupGeneration::new(1), object(1, 1))
            .expect("a listed generation takes another object");
        assert!(
            journal
                .settle(BackupGeneration::new(1))
                .expect("struck off")
        );
        journal
            .note_leaving(BackupGeneration::new(4_097), object(4_097, 0))
            .expect("room for one more");
        assert_eq!(journal.read().expect("readable").generations.len(), 4_096);
    }

    /// The record of sent objects says nothing of what it holds: the marker, planted in each of
    /// its leaves and keys in turn and in the bytes no encoder writes, is in no rendering of what
    /// reading it returns. The neutral control, planted the same way, is refused with the rule its
    /// bytes broke, as the record's own decoder reports it, and nothing it held.
    #[test]
    fn the_record_of_sent_objects_says_nothing_of_what_it_holds() {
        use crate::shown::marker::{
            MARKER, NEUTRAL, assert_unmarked, cbor_plantings, debug_renderings, failure_renderings,
        };

        let records = tempfile::tempdir().expect("a directory on the internal disk");
        let journal = Journal::of(records.path(), archive());
        for index in 0..2 {
            journal
                .note_leaving(BackupGeneration::new(7), object(7, index))
                .expect("the record takes the object");
        }
        let value = kr_cbor::decode(
            &std::fs::read(&journal.path).expect("the record"),
            &RECORD_LIMITS,
        )
        .expect("a value");

        let mut refused = 0;
        for planted in cbor_plantings(&value, MARKER) {
            std::fs::write(&journal.path, &planted.input).expect("written");
            match journal.read() {
                Ok(read) => assert_unmarked(&planted.at, &debug_renderings(&read)),
                Err(error) => {
                    refused += 1;
                    assert_unmarked(&planted.at, &failure_renderings(error));
                }
            }
        }
        assert!(refused > 0, "the plantings are refused");

        for planted in cbor_plantings(&value, NEUTRAL) {
            std::fs::write(&journal.path, &planted.input).expect("written");
            let broken =
                kr_cbor::from_canonical_slice::<Sent>(&planted.input, &RECORD_LIMITS).err();
            match (journal.read(), broken) {
                (Err(error), Some(broken)) => assert_eq!(
                    error.to_string(),
                    Shown::cbor(&broken).into_string(),
                    "{}",
                    planted.at
                ),
                (Ok(_), None) => {}
                (read, _) => panic!(
                    "{}: the record and its decoder disagree: {read:?}",
                    planted.at
                ),
            }
        }
    }
}
