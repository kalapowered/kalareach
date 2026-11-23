//! Generations of one backup archive, made the way a device's backup writer makes them, for the
//! legs that need the service to hold many.
//!
//! A leg that holds the managed service to its retention rules needs thirty-one generations in a
//! real deployment's storage and manifest services, and this is the smallest producer that makes
//! them. The writer's enrolment goes in the recovery bundle first and the manifest service second,
//! and a bundle that does not land enrols nothing; each generation stages one member for the
//! recovery recipient, seals the archive, uploads the member and the encrypted manifest through the
//! storage service and publishes the descriptor, signed by the writer. It is test support: it holds
//! no record of what it sent and no privacy gate, and a refusal after the bundle is a panic with
//! the service's own words.

use std::sync::Arc;

use kr_client::recovery::{ArchiveEntries, BundleStore, RecoveryError};
use kr_client::services::account::AccountTokenSource;
use kr_client::services::backup::{ManagedBackupManifestService, Published};
use kr_client::services::storage::{ArchiveAnswer, ManagedStorageService, NewUpload, upload_parts};
use kr_client::services::{
    BackupManifestService, Dispatched, ServiceHttp, ServiceSigner, StorageService, UploadProgress,
};
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
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId,
};
use kr_protocol::scalars::{StoredEnvelopeKey, TimestampMs};
use kr_protocol::service::GatewayOrigin;

/// The managed services one generation goes to: the gateway, the transport, the key the requests
/// are signed with, and the account whose backup storage the generation spends.
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

/// One archive and the keys its generations are made with.
pub struct Collection {
    /// The archive.
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

/// An archive whose writer the recovery bundle carries.
pub struct Generations {
    collection: Collection,
}

impl Generations {
    /// Enables the writer: the recovery bundle first, the manifest service second.
    ///
    /// # Errors
    ///
    /// Returns the bundle's refusal when it does not land, and enrols nothing.
    ///
    /// # Panics
    ///
    /// Panics with the service's refusal when the enrolment is not answered.
    pub async fn enable(
        collection: Collection,
        bundles: &mut BundleStore,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        owner: &AuthorisationKeyPair,
        manifest: &dyn BackupManifestService,
        now: TimestampMs,
    ) -> Result<Self, RecoveryError> {
        let entries = ArchiveEntries {
            collection: CollectionLocator {
                service_origin: collection.service_origin.clone(),
                locator: collection.archive_id.to_string(),
                archive_id: collection.archive_id,
            },
            writer: TrustedWriter {
                writer_key_id: collection.writer.key_id(),
                signing_key: *collection.writer.public(),
                enrolled_at_ms: now,
            },
            producer: TrustedProducer {
                sender_key_id: collection.producer.key_id(),
                stored_envelope_key: *collection.producer.public(),
                enrolled_at_ms: now,
            },
        };
        entries.commit(bundles, seed, bundle, now).await?;
        let payload = BackupWriterRecordPayload {
            archive_id: collection.archive_id,
            writer: entries.writer,
            writer_revision: collection.writer_revision,
            owner_key_id: owner.key_id(),
            enrolled_at_ms: now,
        };
        let transcript = SigningTranscript::from_canonical_bytes(
            BACKUP_WRITER_DOMAIN,
            payload
                .signing_input()
                .expect("an enrolment's signing input"),
        )
        .expect("a transcript");
        manifest
            .enrol(&BackupWriterRecord {
                signature: sign(owner, &transcript).expect("a signature"),
                payload,
            })
            .await
            .expect("the writer is enrolled");
        Ok(Self { collection })
    }

    /// Backs `member` up as generation `generation`: sealed for the recovery recipient under
    /// `filename`, uploaded with the encrypted manifest and published.
    ///
    /// # Panics
    ///
    /// Panics with the service's refusal when an upload or the publication is not answered as
    /// done.
    pub async fn back_up(
        &self,
        filename: &'static str,
        member: &[u8],
        generation: BackupGeneration,
        services: &ArchiveServices,
        now: TimestampMs,
    ) -> Published {
        let collection = &self.collection;
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        recipients.add(collection.recovery);
        let staged = stage_object(
            &ObjectSource {
                object_id: fresh_object_id(),
                filename,
                plaintext: member,
            },
            recipients.rotation(),
        )
        .expect("a staged member");
        let sealed: SealedArchive = seal_archive(
            &collection.writer,
            &collection.producer,
            &recipients,
            &ArchivePlan {
                archive_id: collection.archive_id,
                backup_generation: generation,
                owner_device_id: collection.owner_device_id,
                manifest_object_id: fresh_object_id(),
                created_at_ms: now,
            },
            std::slice::from_ref(&staged),
        )
        .expect("a sealed archive");

        let storage = ManagedStorageService::new(
            services.origin.clone(),
            Arc::clone(&services.http),
            Arc::clone(&services.signer),
        )
        .presenting(Arc::clone(&services.tokens));
        let manifest = ManagedBackupManifestService::new(
            services.origin.clone(),
            Arc::clone(&services.http),
            Arc::clone(&services.signer),
        )
        .presenting(Arc::clone(&services.tokens));

        let encrypted_manifest = &sealed.descriptor.encrypted_manifest;
        self.upload(
            &storage,
            generation,
            staged.object_id(),
            staged.bytes(),
            staged.reference().encrypted_object_hash,
        )
        .await;
        self.upload(
            &storage,
            generation,
            encrypted_manifest.object_id,
            sealed.encrypted_manifest.as_slice(),
            encrypted_manifest.encrypted_object_hash,
        )
        .await;

        let payload = BackupGenerationPublicationPayload {
            descriptor: sealed.descriptor.clone(),
            writer_key_id: collection.writer.key_id(),
            published_at_ms: now,
        };
        let transcript = SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload
                .signing_input()
                .expect("a publication's signing input"),
        )
        .expect("a transcript");
        let publication = BackupGenerationPublication {
            signature: sign(&collection.writer, &transcript).expect("a signature"),
            payload,
        };
        match manifest
            .publish_dispatched(&publication)
            .await
            .unwrap_or_else(|error| panic!("generation {generation:?} is published: {error}"))
        {
            Dispatched::Answered(ArchiveAnswer::Done(published)) => published,
            other => panic!("generation {generation:?} was not published: {other:?}"),
        }
    }

    /// Uploads one object of a generation whole, in the parts its table cuts.
    async fn upload(
        &self,
        storage: &dyn StorageService,
        generation: BackupGeneration,
        object_id: BackupObjectId,
        bytes: &[u8],
        hash: kr_protocol::scalars::Digest256,
    ) {
        let total = bytes.len() as u64;
        let created = storage
            .create_upload(&NewUpload {
                archive_id: self.collection.archive_id,
                object_id,
                backup_generation: generation,
                declared_max_bytes: total,
                total_bytes: total,
                encrypted_object_hash: hash,
            })
            .await
            .expect("the upload is created");
        let ArchiveAnswer::Done(created) = created else {
            panic!("the upload was not created");
        };
        let mut progress = created.progress();
        let mut nothing_kept = |_: &UploadProgress| -> kr_client::Result<()> { Ok(()) };
        match upload_parts(storage, &mut progress, bytes, &mut nothing_kept)
            .await
            .expect("the parts are uploaded")
        {
            ArchiveAnswer::Done(()) => {}
            _ => panic!("the parts were not accepted"),
        }
        match storage
            .complete_upload(&progress.upload_id, &progress.table)
            .await
            .expect("the upload is completed")
        {
            ArchiveAnswer::Done(completed)
                if completed.object.object_id == object_id
                    && completed.object.encrypted_object_hash == hash
                    && completed.object.encrypted_len == total => {}
            _ => panic!("the completion is of another object"),
        }
    }
}

/// A fresh identifier for one object of one generation.
fn fresh_object_id() -> BackupObjectId {
    BackupObjectId::new(kr_sync_integration::fresh_uuid())
}
