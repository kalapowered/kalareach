//! Backups a running daemon has published, written through its own backup service.
//!
//! The daemon's store is the one a host keeps at setup and publication, so a case that reads what
//! the host says of its backups seeds it the way the host fills it: a setup, then one generation
//! after another taken as far as a service accepting the descriptor. Nothing here touches a
//! database file or a storage service.

use kr_controller::backup::BackupService;
use kr_controller::backup::store::{SetupRecord, Step};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, seal_archive,
    stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::ArchiveDescriptor;
use kr_protocol::backup_checkpoint::HostCheckpoint;
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_worker::privacy::PrivacyGeneration;

/// The service the seeded setup is made at.
pub const ORIGIN: &str = "https://storage.example";

/// The executor a dispatched attempt is handed to.
const EXECUTOR: &str = "the test transport";

/// A host's backup setup and the keys that sign what it publishes.
pub struct SeededBackups {
    writer: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl SeededBackups {
    /// The archive every seeded generation belongs to.
    pub fn archive_id() -> ArchiveId {
        ArchiveId::new(Uuid::from_bytes([0x11; 16]))
    }

    /// Sets backups up on the daemon's backup service.
    pub fn set_up(service: &BackupService) -> Self {
        let seeded = Self {
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        };
        service
            .commit_setup(
                &SetupRecord {
                    archive_id: Self::archive_id(),
                    origin: ORIGIN.to_owned(),
                    account_mark: [9; 32],
                    recovery_public_key: *seeded.device.public(),
                    kit_fingerprint: "ABCD2345".to_owned(),
                    writer_key_id: seeded.writer.key_id(),
                    producer_key_id: seeded.sender.key_id(),
                    enabled_at_ms: TimestampMs::new(1_000),
                },
                false,
                TimestampMs::new(1_000),
                &|write| write(),
            )
            .expect("the setup is written");
        seeded
    }

    /// Takes the next generation as far as a service accepting its descriptor, and returns what
    /// the host says of it.
    pub fn publish(&self, service: &BackupService, generation: u64) -> HostCheckpoint {
        let seed = u8::try_from(generation).expect("a small generation");
        let objects = [stage_object(
            &ObjectSource {
                object_id: BackupObjectId::new(Uuid::from_bytes([0x20 + seed; 16])),
                filename: "a.cbor",
                plaintext: b"content",
            },
            KeyRotation::INITIAL,
        )
        .expect("a staged object")];
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.device.public()));
        let sealed = seal_archive(
            &self.writer,
            &self.sender,
            &recipients,
            &ArchivePlan {
                archive_id: Self::archive_id(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                manifest_object_id: BackupObjectId::new(Uuid::from_bytes([0xf0 + seed; 16])),
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            &objects,
        )
        .expect("a sealed archive");
        let now = TimestampMs::new(5_000 + generation);
        let upload = service
            .admit(&sealed, &objects, self.writer.key_id(), now)
            .expect("the generation is admitted")
            .sequence;
        service
            .note_dispatched(upload, EXECUTOR, now)
            .expect("its upload leaves");
        for row in service
            .objects(Self::archive_id(), BackupGeneration::new(generation))
            .expect("a read")
        {
            service
                .note_object_uploaded(
                    upload,
                    Self::archive_id(),
                    BackupGeneration::new(generation),
                    row.object_id,
                    now,
                )
                .expect("the object is acknowledged");
        }
        service
            .note_attempt_accepted(upload, now)
            .expect("the upload finished");
        let publication = service
            .outbox()
            .expect("a read")
            .into_iter()
            .find(|attempt| {
                attempt.step == Step::Publish
                    && attempt.backup_generation == BackupGeneration::new(generation)
            })
            .expect("a publication attempt")
            .sequence;
        service
            .note_dispatched(publication, EXECUTOR, now)
            .expect("the publication is in flight");
        service
            .note_published(publication, PrivacyGeneration::INITIAL, now)
            .expect("the service holds it");
        HostCheckpoint {
            service_origin: GatewayOrigin::new(ORIGIN).expect("an origin"),
            archive_id: Self::archive_id(),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest_hash: ArchiveDescriptor::from_canonical_bytes(
                &sealed.descriptor_bytes,
            )
            .expect("a descriptor")
            .encrypted_manifest
            .encrypted_object_hash,
        }
    }
}
