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
//! generation it read the settings under. The device reads its privacy state again before each
//! object's upload is created, once it is, before each further part and before the completion, and
//! before the publication: a fence, or a generation that has moved on, refuses everything not yet
//! sent, and an upload it stops is abandoned at the service.
//!
//! An object already stored when that happens stays at the service, unpublished, where no restore
//! looks for it. This device keeps no record of it, so showing it among the archives privacy mode
//! retains, or deleting it, is not built here.
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

use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, ObjectSource, SealedArchive, seal_archive,
    stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, BackupWriterRecord, BackupWriterRecordPayload,
    CollectionLocator, RecoveryBundle, TrustedProducer, TrustedWriter,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId, SyncObjectId,
};
use kr_protocol::scalars::{Digest256, StoredEnvelopeKey, TimestampMs};

use crate::error::ClientError;
use crate::recovery::{
    BundleStore, RecoveryError, Result, SETTINGS_FILENAME, WriterEnabled, export_settings,
};
use crate::services::storage::collection_deleted;
use crate::services::{
    ArchiveAnswer, BackupManifestService, Dispatched, NewUpload, Published, StorageService,
    UploadProgress, upload_parts,
};
use crate::sync::{SyncError, SyncStore};

/// Where one device's settings archive goes, and the keys each generation of it is made with.
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
}

impl fmt::Debug for SettingsCollection {
    /// The archive and the keys by their identifiers. Never a private key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsCollection")
            .field("archive_id", &self.archive_id)
            .field("service_origin", &self.service_origin)
            .field("writer_key_id", &self.writer.key_id())
            .field("producer_key_id", &self.producer.key_id())
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
        formatter
            .debug_struct("SettingsArchive")
            .field("collection", &self.collection)
            .field("bundle_revision", &self.enabled.bundle_revision())
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

    /// The settings archive of a writer whose bundle has already landed, as a device that enabled
    /// it earlier takes it up again.
    ///
    /// `bundle` is the bundle `bundles` last authenticated, as [`BundleStore::fetch`] gave it back.
    /// The archive is taken up only when that bundle names this collection at its origin, this
    /// producer's key and this writer's key, as [`Self::enable`] committed them: a writer a restore
    /// can verify is not enough when the restore could not find the collection or open its wraps.
    /// Answers none otherwise.
    #[must_use]
    pub fn resume(
        collection: SettingsCollection,
        bundles: &BundleStore,
        bundle: &RecoveryBundle,
    ) -> Option<Self> {
        let enabled = bundles.writer_enabled(collection.writer.key_id())?;
        let carried = enabled.bundle_revision() == bundle.revision.get()
            && bundle.collections.iter().any(|held| {
                held.archive_id == collection.archive_id
                    && held.service_origin == collection.service_origin
            })
            && bundle.trusted_producers.iter().any(|held| {
                held.sender_key_id == collection.producer.key_id()
                    && held.stored_envelope_key == *collection.producer.public()
            })
            && bundle.trusted_writers.iter().any(|held| {
                held.writer_key_id == collection.writer.key_id()
                    && held.signing_key == *collection.writer.public()
            });
        carried.then_some(Self {
            collection,
            enabled,
        })
    }

    /// Backs up this device's settings object as generation `generation`.
    ///
    /// The object is exported under the privacy generation in force, sealed as one member for the
    /// recovery recipient, uploaded with the encrypted manifest through `storage`, and published
    /// through `manifest`, which signs as the writer. Both present the account's proof: a
    /// generation spends the account's backup storage.
    ///
    /// # Errors
    ///
    /// Returns [`Sync`] with [`SyncError::Fenced`] while privacy mode is on, whether that is found
    /// before anything is sent or before a later object or the publication leaves, and with
    /// [`SyncError::LateResult`] once the privacy generation has moved on from the one the settings
    /// were read under. Returns [`Service`] when a service refuses or does not answer, a collection
    /// deleted from the account console among them, and the export's and the producer's own errors
    /// otherwise.
    ///
    /// [`Sync`]: super::RecoveryError::Sync
    /// [`Service`]: super::RecoveryError::Service
    pub async fn back_up(
        &self,
        store: &SyncStore,
        object_id: SyncObjectId,
        generation: BackupGeneration,
        storage: &dyn StorageService,
        manifest: &dyn BackupManifestService,
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
            still_in_force(store, produced_under)?;
            self.upload(storage, store, produced_under, generation, leaving)
                .await?;
        }

        still_in_force(store, produced_under)?;
        let publication = self.publication(&sealed, now)?;
        match manifest.publish_dispatched(&publication).await? {
            Dispatched::Answered(ArchiveAnswer::Done(published)) => Ok(SettingsBackedUp {
                backup_generation: generation,
                published,
            }),
            Dispatched::Answered(ArchiveAnswer::CollectionDeleted) => {
                Err(collection_deleted().into())
            }
            Dispatched::Answered(ArchiveAnswer::UploadGone) => {
                Err(contrary("a publication as an upload it holds none of").into())
            }
            Dispatched::NotSent(error) => Err(error.into()),
        }
    }

    /// Uploads one object of a generation whole, in the parts its table cuts.
    ///
    /// Privacy mode can change while a request is on its way, so the device's privacy state is read
    /// again once the upload exists, before each further part and before the completion. An upload
    /// that meets a fence, or a generation that has moved on, is abandoned at the service and goes
    /// no further.
    async fn upload(
        &self,
        storage: &dyn StorageService,
        store: &SyncStore,
        produced_under: u64,
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
        let mut progress = match storage.create_upload(&upload).await? {
            ArchiveAnswer::Done(created) => created.progress(),
            ArchiveAnswer::CollectionDeleted => return Err(collection_deleted().into()),
            ArchiveAnswer::UploadGone => {
                return Err(contrary("a creation as an upload it holds none of").into());
            }
        };
        if let Err(stopped) = still_in_force(store, produced_under) {
            return Err(abandon(storage, &progress, stopped).await);
        }
        let mut stopped: Option<RecoveryError> = None;
        let sent = {
            let mut before_the_next_part = |_: &UploadProgress| -> crate::Result<()> {
                still_in_force(store, produced_under).map_err(|refusal| {
                    stopped = Some(refusal);
                    held_back()
                })
            };
            upload_parts(storage, &mut progress, bytes, &mut before_the_next_part).await
        };
        if let Some(stopped) = stopped {
            return Err(abandon(storage, &progress, stopped).await);
        }
        match sent? {
            ArchiveAnswer::Done(()) => {}
            ArchiveAnswer::CollectionDeleted => return Err(collection_deleted().into()),
            ArchiveAnswer::UploadGone => {
                return Err(contrary("a part as an upload it holds none of").into());
            }
        }
        if let Err(stopped) = still_in_force(store, produced_under) {
            return Err(abandon(storage, &progress, stopped).await);
        }
        match storage
            .complete_upload(&progress.upload_id, &progress.table)
            .await?
        {
            ArchiveAnswer::Done(completed)
                if completed.object.object_id == object_id
                    && completed.object.encrypted_object_hash == hash
                    && completed.object.encrypted_len == total =>
            {
                Ok(())
            }
            ArchiveAnswer::Done(_) => Err(contrary("a completion of another object").into()),
            ArchiveAnswer::CollectionDeleted => Err(collection_deleted().into()),
            ArchiveAnswer::UploadGone => {
                Err(contrary("a completion as an upload it holds none of").into())
            }
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

/// Abandons an upload privacy mode stopped, and gives back what stopped it.
///
/// The abandonment is asked for once. An upload it does not end was never completed, so it ends
/// when its lifetime runs out.
async fn abandon(
    storage: &dyn StorageService,
    progress: &UploadProgress,
    stopped: RecoveryError,
) -> RecoveryError {
    let _ = storage.abort_upload(&progress.upload_id).await;
    stopped
}

/// What stops an upload part-way once privacy mode has stopped it. Nothing reads it: the upload
/// knows why it stopped.
fn held_back() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::PermissionDenied,
        "privacy mode stopped the upload before its next part".to_owned(),
    ))
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
fn still_in_force(store: &SyncStore, produced_under: u64) -> Result<()> {
    let privacy = store.privacy()?;
    let current = privacy.generation.get();
    if privacy.fenced {
        return Err(SyncError::Fenced {
            generation: current,
        }
        .into());
    }
    if current != produced_under {
        return Err(SyncError::LateResult {
            produced_under,
            current,
        }
        .into());
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
fn contrary(what: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        format!("the service answered {what}"),
    ))
}
