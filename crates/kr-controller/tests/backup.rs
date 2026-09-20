//! The environment's backup service: its store, its reconciliation, its restore checks and its
//! privacy hook.
//!
//! Section 24's ownership row for backup generations, and section 24's privacy paragraphs. Rule 12
//! applies to every path here: `backup.sqlite` and every staged byte live under the platform
//! temporary directory, which is on the internal disk, and nothing in this file launches a process.

use kr_controller::backup::store::{
    FenceRelease, GenerationState, ObjectState, ObligationKind, Step,
};
use kr_controller::backup::{BackupService, RestoreRequest, SUBSYSTEM_NAME};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CheckpointSource, CollectionKind, GenerationExpectation,
    KeyRotation, Material, ObjectSource, SealedArchive, StagedObject, seal_archive, stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::{
    ArchiveCheckpoint, BackupGenerationPublication, BackupGenerationPublicationPayload,
    BackupWriterRecord, BackupWriterRecordPayload, TrustedWriter,
};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::privacy::{PrivacyGeneration, PrivacyMode, PrivacySubsystem};

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn owner_device() -> DeviceId {
    DeviceId::new(Uuid::from_bytes([0x33; 16]))
}

fn object_id(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

/// A service whose store and staging directory live on the internal disk and go with the test.
struct Environment {
    service: BackupService,
    _root: tempfile::TempDir,
}

impl Environment {
    fn open() -> Self {
        let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
        let service = BackupService::in_memory(&root.path().join("backup"))
            .expect("a backup service with its own staging directory");
        Self {
            service,
            _root: root,
        }
    }

    fn service(&self) -> &BackupService {
        &self.service
    }
}

/// One writer, one producer key and one recipient.
struct Producer {
    writer: AuthorisationKeyPair,
    owner: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl Producer {
    fn generate() -> Self {
        Self {
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            owner: AuthorisationKeyPair::generate().expect("an owner key"),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        }
    }

    fn seal(&self, generation: u64, objects: &[StagedObject]) -> SealedArchive {
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.device.public()));
        seal_archive(
            &self.writer,
            &self.sender,
            &recipients,
            &ArchivePlan {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: owner_device(),
                manifest_object_id: object_id(0xf0),
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            objects,
        )
        .expect("a sealed archive")
    }

    fn enrolment(&self, revision: u64) -> BackupWriterRecord {
        let payload = BackupWriterRecordPayload {
            archive_id: archive_id(),
            writer: TrustedWriter {
                writer_key_id: self.writer.key_id(),
                signing_key: *self.writer.public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            },
            writer_revision: BackupWriterRevision::new(revision),
            owner_key_id: self.owner.key_id(),
            enrolled_at_ms: TimestampMs::new(1_000),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_WRITER_DOMAIN,
            payload.signing_input().expect("an enrolment input"),
        )
        .expect("a transcript");
        let signature = kr_crypto::sign::sign(&self.owner, &transcript).expect("a signature");
        BackupWriterRecord { payload, signature }
    }

    fn publish(&self, sealed: &SealedArchive) -> BackupGenerationPublication {
        let payload = BackupGenerationPublicationPayload {
            descriptor: sealed.descriptor.clone(),
            writer_key_id: self.writer.key_id(),
            published_at_ms: TimestampMs::new(2_000),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript");
        let signature = kr_crypto::sign::sign(&self.writer, &transcript).expect("a signature");
        BackupGenerationPublication { payload, signature }
    }
}

fn stage(seed: u8, filename: &str, plaintext: &[u8]) -> StagedObject {
    stage_object(
        &ObjectSource {
            object_id: object_id(seed),
            filename,
            plaintext,
        },
        KeyRotation::INITIAL,
    )
    .expect("a staged object")
}

// ---------------------------------------------------------------------------------------------
// The store: one transaction per state transition.
// ---------------------------------------------------------------------------------------------

#[test]
fn admitting_a_generation_writes_its_objects_and_its_outbox_entry_with_it() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);

    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(3),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    assert_eq!(admitted.archive_id, archive_id());
    assert_eq!(
        admitted.staged_objects, 3,
        "two members and the encrypted manifest"
    );
    assert!(admitted.staged_bytes > 0);

    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Staging);
    assert_eq!(record.writer_key_id, producer.writer.key_id());
    assert_eq!(record.privacy_generation, 3);
    assert_eq!(
        record.descriptor.as_deref(),
        Some(sealed.descriptor_bytes.as_slice())
    );

    let rows = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.state, ObjectState::Staged);
        assert_eq!(row.uploaded_bytes, 0);
        assert!(
            row.staged_path.exists(),
            "the ciphertext is on this host at {}",
            row.staged_path.display()
        );
        let bytes = std::fs::read(&row.staged_path).expect("the staged ciphertext");
        assert_eq!(bytes.len() as u64, row.encrypted_len);
    }

    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1, "one entry, admitted with the generation");
    assert_eq!(outbox[0].step, Step::Upload);
    assert!(!outbox[0].dispatched);
    assert_eq!(outbox[0].privacy_generation, 3);
    assert_eq!(outbox[0].sequence, admitted.sequence);
}

#[test]
fn the_publish_step_is_enqueued_with_the_last_object_that_finished_uploading() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let rows = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read");
    for (index, row) in rows.iter().enumerate() {
        let complete = environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                row.object_id,
                TimestampMs::new(6_000),
            )
            .expect("the object is recorded");
        assert_eq!(
            complete,
            index + 1 == rows.len(),
            "only the last object completes the generation"
        );
    }

    // One entry, not two: the upload step is retired in the same transaction that enqueues the
    // publish step, so nothing can resume an upload that has finished.
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].step, Step::Publish);

    // And a repeated acknowledgement of an object that had already arrived does not enqueue a
    // second publication.
    let first = rows[0].object_id;
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            first,
            TimestampMs::new(6_500),
        )
        .expect("a repeated acknowledgement");
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1, "one publication, however often it is told");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Uploading);
}

// ---------------------------------------------------------------------------------------------
// Startup reconciliation.
// ---------------------------------------------------------------------------------------------

#[test]
fn reconciliation_resumes_what_is_authorised_and_cancels_what_is_not() {
    let environment = Environment::open();
    let producer = Producer::generate();
    // A second producer of the same collection, with its own signing key. The writer a generation
    // is admitted under has to be the writer that signed it, so the second generation is sealed by
    // the writer it is admitted under.
    let leaving = Producer::generate();
    for writer in [producer.writer.key_id(), leaving.writer.key_id()] {
        environment
            .service()
            .enrol_writer(writer, archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
    }

    let objects = [stage(1, "a.cbor", b"one")];
    let first = producer.seal(1, &objects);
    let second = leaving.seal(2, &objects);
    for (sealed, writer) in [
        (&first, producer.writer.key_id()),
        (&second, leaving.writer.key_id()),
    ] {
        environment
            .service()
            .admit(
                sealed,
                &objects,
                writer,
                PrivacyGeneration::new(0),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
    }

    // The owner retires the second writer, and the daemon restarts.
    environment
        .service()
        .retire_writer(
            archive_id(),
            leaving.writer.key_id(),
            TimestampMs::new(6_000),
        )
        .expect("the writer is retired");
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");

    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert_eq!(
        outcome.no_longer_authorised,
        vec![(archive_id(), BackupGeneration::new(2))]
    );
    assert!(outcome.outcome_unknown.is_empty());

    let cancelled = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(cancelled.state, GenerationState::Cancelled);
    assert!(
        cancelled
            .detail
            .as_deref()
            .expect("a reason")
            .contains("no longer holds an enrolment")
    );
    assert!(
        environment
            .service()
            .outbox()
            .expect("a read")
            .iter()
            .all(|entry| entry.backup_generation == BackupGeneration::new(1)),
        "a cancelled generation leaves nothing in the outbox"
    );
}

#[test]
fn a_publication_that_left_this_host_and_was_never_answered_is_recorded_as_unknown() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // Every object arrives, the publish step is enqueued and dispatched, and then this host stops.
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                row.object_id,
                TimestampMs::new(6_000),
            )
            .expect("the object is recorded");
    }
    let publish = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|entry| entry.step == Step::Publish)
        .expect("a publish entry");
    environment
        .service()
        .note_dispatched(publish.sequence)
        .expect("the entry is dispatched");

    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.outcome_unknown,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.resumed.is_empty());
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Unknown);
    assert!(
        record
            .detail
            .as_deref()
            .expect("a reason")
            .contains("not something this host can say")
    );
}

#[test]
fn a_dispatched_upload_goes_back_in_hand_rather_than_becoming_unknown() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is dispatched");

    // The same object under the same identity and hash is the same object, so sending it again is
    // not a second publication.
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.outcome_unknown.is_empty());
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1);
    assert!(!outbox[0].dispatched, "it is back in hand");
}

#[test]
fn a_fence_stops_admission_and_dispatch_and_survives_a_restart() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let second = producer.seal(2, &objects);
    let admitted;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");

        service.fence(PrivacyGeneration::new(4));
        assert_eq!(service.fenced_at().expect("a read"), Some(4));

        // A fence that recorded a number and let the queue go would be a fence in name only.
        assert!(
            service.note_dispatched(admitted.sequence).is_err(),
            "the entry the fence stopped does not leave this host"
        );
        assert!(
            service
                .admit(
                    &second,
                    &objects,
                    producer.writer.key_id(),
                    PrivacyGeneration::new(4),
                    TimestampMs::new(6_000),
                )
                .is_err(),
            "no more content-bearing backup work is admitted while the fence holds"
        );
    }

    // A restart comes back fenced, and its reconciliation puts nothing back in hand. The fence
    // prohibited production for that generation when it went up, and a restart does not undo it.
    let service = BackupService::open(&state).expect("the service opens again");
    assert_eq!(service.fenced_at().expect("a read"), Some(4));
    assert!(service.note_dispatched(admitted.sequence).is_err());
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(outcome.resumed.is_empty());
    assert!(outcome.unanswered.is_empty(), "nothing had left this host");
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.state, GenerationState::Cancelled);
    assert!(
        record
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("privacy generation 4")),
        "the record says which fence stopped it: {:?}",
        record.detail
    );
}

#[test]
fn a_writer_enrolled_for_one_archive_does_not_authorise_another() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let elsewhere = ArchiveId::new(Uuid::from_bytes([0x99; 16]));
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), elsewhere, TimestampMs::new(1))
        .expect("the writer is enrolled for another archive");

    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    assert!(
        environment
            .service()
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .is_err(),
        "an enrolment for one collection does not authorise work for another"
    );
}

#[test]
fn a_generation_already_admitted_is_not_admitted_again() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    let before: Vec<Vec<u8>> = staged
        .iter()
        .map(|path| std::fs::read(path).expect("the staged ciphertext"))
        .collect();

    // Sealing the same generation again produces different ciphertext under different keys. If it
    // were staged over the top of the first, the rows this host has committed would name bytes
    // that no longer open.
    let again = producer.seal(1, &objects);
    assert!(
        environment
            .service()
            .admit(
                &again,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(6_000),
            )
            .is_err(),
        "a generation this host already accounts for is not admitted again"
    );
    for (path, bytes) in staged.iter().zip(before) {
        assert_eq!(
            std::fs::read(path).expect("the staged ciphertext"),
            bytes,
            "nothing wrote over the ciphertext this host is accounting for"
        );
    }
}

#[test]
fn releasing_the_fence_admits_backup_production_again_under_the_new_generation() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];

    let mut environment = environment;
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000));
    }
    assert!(
        environment
            .service()
            .admit(
                &producer.seal(1, &objects),
                &objects,
                producer.writer.key_id(),
                mode.generation(),
                TimestampMs::new(6_500),
            )
            .is_err(),
        "nothing is admitted while the fence holds"
    );

    // Turning privacy mode off releases the fence, under a generation of its own. Nothing the
    // fence cancelled comes back.
    let fenced_at = mode.generation();
    let resumed = mode.disable(TimestampMs::new(7_000));
    assert_eq!(
        environment
            .service()
            .release_fence(fenced_at, resumed.generation, TimestampMs::new(7_000))
            .expect("the release is attempted"),
        FenceRelease::Released,
        "nothing was left staged, so the fence has nothing outstanding under it"
    );
    assert_eq!(environment.service().fenced_at().expect("a read"), None);
    environment
        .service()
        .admit(
            &producer.seal(2, &objects),
            &objects,
            producer.writer.key_id(),
            resumed.generation,
            TimestampMs::new(8_000),
        )
        .expect("backup production is admitted again");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.privacy_generation, resumed.generation.get());
    assert!(
        environment
            .service()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .is_none(),
        "what the fence stopped is not reconstructed"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.16: generation and writer authority verified, and a restore that returns data only.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_restore_verifies_the_owners_enrolment_the_writers_signature_and_the_generation() {
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(4, &objects);
    let publication = producer.publish(&sealed);
    let enrolment = producer.enrolment(1);
    let checkpoint = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(4),
        encrypted_manifest_hash: sealed.descriptor.encrypted_manifest.encrypted_object_hash,
        verified_at_ms: TimestampMs::new(3_000),
    };

    let verified = RestoreRequest {
        archive_id: archive_id(),
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        generation: GenerationExpectation::Checkpoint(CheckpointSource::Pairing, &checkpoint),
    }
    .verify()
    .expect("the restore is admitted");
    assert_eq!(verified.archive_id(), archive_id());
    assert_eq!(verified.writer_key_id(), producer.writer.key_id());
    assert_eq!(verified.writer_revision(), 1);
    assert!(verified.generation().describe().contains("generation 4"));
    assert!(!verified.generation().proves_no_newer_archive());

    // What it hands the archive layer is built from what was verified and takes no argument, so a
    // second genuine generation of the same collection cannot be substituted for it.
    let expectation = verified.expectation();
    assert_eq!(expectation.archive_id, archive_id());
    let GenerationExpectation::Exactly(pinned) = expectation.generation else {
        panic!("a verified restore pins the generation it established");
    };
    assert_eq!(pinned.backup_generation, BackupGeneration::new(4));
    assert_eq!(
        pinned.encrypted_manifest_hash,
        sealed.descriptor.encrypted_manifest.encrypted_object_hash
    );

    // And the archive layer refuses another generation against it.
    let other = producer.seal(6, &objects);
    assert!(
        kr_crypto::backup::open_archive(
            &kr_crypto::backup::ArchiveReader::Device(&producer.device),
            producer.sender.public(),
            &[TrustedWriter {
                writer_key_id: producer.writer.key_id(),
                signing_key: *producer.writer.public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            }],
            &expectation,
            &other.descriptor_bytes,
            &other.encrypted_manifest,
        )
        .is_err(),
        "the archive opened is the archive whose authority was established"
    );
}

#[test]
fn a_restore_is_refused_when_any_of_the_three_checks_does_not_hold() {
    let producer = Producer::generate();
    let impostor = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(4, &objects);
    let publication = producer.publish(&sealed);
    let enrolment = producer.enrolment(1);

    // An enrolment signed by somebody who is not the collection's owner.
    assert!(
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: impostor.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the enrolment is verified against the owner's own key"
    );

    // A writer key that is not the one the owner enrolled.
    assert!(
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: impostor.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "a writer the bundle supplied is checked against the owner's enrolment"
    );

    // A publication whose signature is another writer's.
    let forged = BackupGenerationPublication {
        payload: publication.payload.clone(),
        signature: impostor.publish(&sealed).signature,
    };
    assert!(
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &forged,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the publication's own signature is verified under the enrolled writer"
    );

    // A publication for another archive than the one being restored.
    assert!(
        matches!(
            RestoreRequest {
                archive_id: ArchiveId::new(Uuid::from_bytes([0x99; 16])),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the caller's own expectation is checked before any signature"
    );

    // A generation the checkpoint says is older than what the owner verified.
    let checkpoint = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: Digest256::from_bytes([0xab; 32]),
        verified_at_ms: TimestampMs::new(3_000),
    };
    let refusal = RestoreRequest {
        archive_id: archive_id(),
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        generation: GenerationExpectation::Checkpoint(CheckpointSource::Pairing, &checkpoint),
    }
    .verify()
    .expect_err("a replayed older archive");
    assert!(refusal.to_string().contains("generation 4"));

    // A descriptor over section 20's byte limit fails before anything else.
    assert!(matches!(
        RestoreRequest {
            archive_id: archive_id(),
            publication: &publication,
            descriptor_len: kr_protocol::archive::MAX_ARCHIVE_DESCRIPTOR_LEN + 1,
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify(),
        Err(kr_controller::error::ControllerError::PermissionDenied { .. })
    ));
}

/// The table's answers, which are the decision a restore acts on rather than a gate over bytes.
///
/// `RestoreRequest::admit` classifies kinds a caller names. The archive layer below it carries
/// opaque objects, so what closes section 20 ¶11 is each import path asking for every kind it
/// carries; this establishes the answer it gets.
#[test]
fn a_restore_classifies_a_reusable_host_control_key_as_material_it_refuses() {
    let admitted = RestoreRequest::admit(&[
        Material::SessionData,
        Material::DeviceConfiguration,
        Material::BackupGenerationCheckpoint,
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::RecoverySeed,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ]);
    assert_eq!(admitted.restored.len(), 3);
    for refused in [
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::RecoverySeed,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ] {
        assert!(admitted.refused_kind(refused), "{refused:?} is refused");
    }
    assert!(admitted.limits.requires_fresh_owner_authorised_pairing());
    assert!(!admitted.limits.creates_remote_control_authority());
}

// ---------------------------------------------------------------------------------------------
// The privacy hook, under T-040's generation contract.
// ---------------------------------------------------------------------------------------------

#[test]
fn privacy_mode_fences_cancels_and_removes_what_this_host_still_holds() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");

    // One generation is staged and undispatched; a second has already been published.
    let objects = [stage(1, "a.cbor", b"one")];
    let staged = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &staged,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let published = producer.seal(2, &objects);
    environment
        .service()
        .admit(
            &published,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_100),
        )
        .expect("the generation is admitted");
    let mode = PrivacyMode::new();
    environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(2),
            PrivacyGeneration::INITIAL,
            &mode,
            TimestampMs::new(5_200),
        )
        .expect("the second generation is published");

    let mut mode = PrivacyMode::new();
    let generation = mode.open_generation(TimestampMs::new(6_000));
    let staged_paths: Vec<std::path::PathBuf> = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();

    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000))
    };
    assert_eq!(enabling.generation, generation);

    let (name, fenced) = enabling.fenced[0];
    assert_eq!(name, SUBSYSTEM_NAME);
    assert_eq!(fenced.queues, 1);
    assert_eq!(
        fenced.items, 1,
        "one undispatched entry was holding content"
    );

    let (_, cancelled) = enabling.cancelled[0];
    assert_eq!(cancelled.undispatched, 1);
    assert_eq!(cancelled.in_flight, 0);

    let (_, removed) = enabling.removed[0];
    assert!(removed.bytes > 0, "staged ciphertext left this host");
    assert!(removed.records > 0);
    for path in &staged_paths {
        assert!(
            !path.exists(),
            "the staged ciphertext at {} is gone",
            path.display()
        );
    }

    // The unpublished generation is forgotten; the published one is kept as a retained artifact.
    assert!(
        environment
            .service()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .is_none()
    );
    let kept = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the published generation is kept");
    assert_eq!(kept.state, GenerationState::Published);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(2))
        .expect("a read")
    {
        assert_eq!(row.state, ObjectState::Removed);
        assert!(!row.staged_path.exists());
    }

    // What had already left is shown rather than erased, with a deletion of its own.
    assert_eq!(enabling.exported.len(), 1);
    let exported = &enabling.exported[0];
    assert_eq!(exported.kind, "backup archive");
    assert!(exported.reference.contains("generation 2"));
    assert!(
        !exported.deletable,
        "this host holds no route to ask for the removal, and does not claim one"
    );
    assert!(
        !exported.reference.contains('/'),
        "the reference is an archive, never a path: {}",
        exported.reference
    );

    // What is kept is named rather than quietly retained.
    assert_eq!(enabling.kept.len(), 2);
    for kept in &enabling.kept {
        assert!(!kept.what.is_empty());
        assert!(!kept.why.is_empty());
    }

    // Nothing is outstanding, and nothing failed, so cleanup is complete.
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn dispatched_backup_work_keeps_reconciliation_open_until_it_is_settled() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");

    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000))
    };
    let (_, cancelled) = enabling.cancelled[0];
    assert_eq!(cancelled.undispatched, 0);
    assert_eq!(cancelled.in_flight, 1, "it had already left this host");
    assert_eq!(enabling.in_flight(), 1);

    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(
            !PrivacyMode::reconcile(&subsystems).is_complete(),
            "cleanup is not complete while a backup is still in flight"
        );
    }

    // The upload is followed to its end and the generation is settled, and only then is cleanup
    // complete.
    environment
        .service()
        .note_outcome_unknown(
            archive_id(),
            BackupGeneration::new(1),
            "the upload was in flight when privacy mode was enabled",
            TimestampMs::new(7_000),
        )
        .expect("the outcome is recorded");
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_result_is_published_only_under_the_generation_this_host_admitted_the_work_under() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let mut mode = PrivacyMode::new();
    let now = mode.open_generation(TimestampMs::new(6_000));

    // The answer to work admitted before privacy mode was enabled comes back afterwards. It is
    // refused under the generation it was really admitted under.
    let refusal = environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(1),
            PrivacyGeneration::INITIAL,
            &mode,
            TimestampMs::new(7_000),
        )
        .expect_err("a late old-generation result");
    assert!(refusal.to_string().contains("privacy generation 0"));

    // And relabelling it does not help: the generation the work was admitted under is the store's,
    // not the caller's, so a caller that could name it could not name its way past the boundary.
    let relabelled = environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(1),
            now,
            &mode,
            TimestampMs::new(7_000),
        )
        .expect_err("a result relabelled with the generation in force");
    assert!(
        relabelled
            .to_string()
            .contains("this host admitted the work under 0")
    );
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_ne!(
        record.state,
        GenerationState::Published,
        "neither refused result changed anything"
    );

    // Work admitted under the generation in force publishes. Privacy mode is off again here,
    // because a host in privacy mode admits no content-bearing backup work at all.
    let resumed = mode.disable(TimestampMs::new(8_000));
    let second = producer.seal(2, &objects);
    environment
        .service()
        .admit(
            &second,
            &objects,
            producer.writer.key_id(),
            resumed.generation,
            TimestampMs::new(9_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(2),
            resumed.generation,
            &mode,
            TimestampMs::new(10_000),
        )
        .expect("a result from the generation in force");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Published);
}

#[test]
fn a_fence_is_recorded_durably_and_a_restart_comes_back_fenced() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        assert_eq!(service.fenced_at().expect("a read"), None);
        let fenced = service.fence(PrivacyGeneration::new(4));
        assert_eq!(fenced.queues, 1);
        // The fence writes its own scope down. There is nothing staged here, so the only thing it
        // owes is the walk of the staging directory, which is how ciphertext no row names is found.
        let owed = service.obligations().expect("a read");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].kind, ObligationKind::ScanStaging);
        assert_eq!(service.fenced_at().expect("a read"), Some(4));
    }
    // A host that held the fence in memory would come back and dispatch what it had just stopped.
    let reopened = BackupService::open(&state).expect("the service opens again");
    assert_eq!(reopened.fenced_at().expect("a read"), Some(4));
    assert_eq!(reopened.obligations().expect("a read").len(), 1);
}

#[test]
fn a_store_that_will_not_take_the_request_reports_work_outstanding_rather_than_completion() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut service = BackupService::open(&state).expect("a backup service");

    // Put SQLite into query-only mode so writes fail while reads still work.
    service.set_query_only(true).expect("query_only pragma");

    // The request cannot be accepted, so there is no request and no obligation: no design can
    // persist a request in the database that would not take it.
    let error = service
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect_err("a store that will not write says so");
    assert!(
        matches!(
            error,
            kr_controller::error::ControllerError::RegistryUnavailable { .. }
        ),
        "the reason is the answer: {error}"
    );
    let fenced = service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 0);
    assert!(service.privacy_request(1).expect("a read").is_none());
    assert!(service.obligations().expect("a read").is_empty());

    // And the subsystem still reports work outstanding. A host that cannot say what it owes does
    // not owe nothing, and privacy mode must never read the first as the second.
    assert!(service.outstanding() > 0);
    let work = service.outstanding_work().expect("reads still work");
    assert!(!work.is_complete());
    assert_eq!(work.failed_steps, vec!["raise the backup privacy fence"]);

    // The guard is cleared by that step's own success and by nothing else.
    service.set_query_only(false).expect("query_only pragma");
    let fenced = service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1);
    let work = service.outstanding_work().expect("a read");
    assert!(work.failed_steps.is_empty());
    assert_eq!(service.fenced_at().expect("a read"), Some(1));
}

#[test]
fn an_activation_that_fails_leaves_the_request_and_its_obligation_behind() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .accept_privacy_request(PrivacyGeneration::new(4), TimestampMs::new(6_000))
            .expect("the request is accepted");
        // Everything after the request fails. The request stands, because it was committed on its
        // own before anything was attempted over it.
        service.set_query_only(true).expect("query_only pragma");
        let fenced = service.fence(PrivacyGeneration::new(4));
        assert_eq!(fenced.queues, 0, "no fence is reported that did not go up");
        assert!(service.outstanding() > 0);
    }

    // A restart reads the request and its obligation back. Neither an empty list nor another
    // step's success can stand in for the activation this host never performed.
    let reopened = BackupService::open(&state).expect("the service opens again");
    let request = reopened
        .privacy_request(4)
        .expect("a read")
        .expect("the accepted request");
    assert!(!request.is_applied());
    let owed = reopened.obligations().expect("a read");
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].kind, ObligationKind::ActivateFence);
    assert_eq!(owed[0].target_key, "request:4");
    assert!(reopened.outstanding() > 0);
    assert_eq!(
        reopened.fenced_at().expect("a read"),
        Some(4),
        "a request whose fence never went up still stops production"
    );

    // Its own retry is what ends it.
    let mut reopened = reopened;
    let fenced = reopened.fence(PrivacyGeneration::new(4));
    assert_eq!(fenced.queues, 1);
    let owed = reopened.obligations().expect("a read");
    assert!(
        owed.iter()
            .all(|obligation| obligation.kind != ObligationKind::ActivateFence),
        "the activation is done, and what is left is the scope it wrote: {owed:?}"
    );
    assert!(
        reopened
            .privacy_request(4)
            .expect("a read")
            .expect("the request")
            .is_applied()
    );
}

#[test]
fn a_fence_is_released_only_when_nothing_is_owed_under_it_and_never_by_hand() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .accept_privacy_request(PrivacyGeneration::new(2), TimestampMs::new(6_000))
        .expect("the request is accepted");

    // The activation obligation is outstanding, so the fence stands.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::NotHeld,
        "there is no raised fence yet, only the obligation to raise one"
    );
    let fenced = service.fence(PrivacyGeneration::new(2));
    assert_eq!(fenced.queues, 1);

    // A release under a generation that is not newer is refused outright.
    assert!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .is_err(),
        "production never resumes under the generation the fence stopped it at"
    );

    // The fence wrote down a walk of the staging directory, and that is outstanding, so the fence
    // stands. Backup production does not resume into a scope this host has not finished clearing.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending { obligations: 1 }
    );
    assert_eq!(service.fenced_at().expect("a read"), Some(2));

    // Direct SQL cannot get round it either: the trigger refuses the release and the deletion.
    service
        .run_cleanup(TimestampMs::new(7_000))
        .expect("cleanup");

    // With nothing outstanding the release goes through, once.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(4),
                TimestampMs::new(7_500),
            )
            .expect("a second release"),
        FenceRelease::NotHeld,
        "a released fence is not released again"
    );
    let status = service.privacy_status().expect("a read");
    assert_eq!(status.current_generation, 3);
    assert!(!status.enabled);
    assert_eq!(service.fenced_at().expect("a read"), None);
}

#[test]
fn a_late_upload_acknowledgement_while_fenced_does_not_enqueue_publication() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // The upload outbox entry is dispatched to the service.
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("dispatched");

    // Privacy mode is enabled: fence is recorded.
    let fenced = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1);
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1);

    // Now the in-flight uploads complete while fenced.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("upload noted");
    let complete = environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            manifest_id,
            TimestampMs::new(6_001),
        )
        .expect("manifest upload noted");
    assert!(complete);

    // It was the last object, but because the host was fenced, NO publish entry was enqueued into outbox!
    let outbox = environment.service().outbox().expect("outbox");
    assert!(
        outbox.is_empty(),
        "no publish step may be enqueued while fenced: {outbox:?}"
    );

    // The generation was settled as Cancelled rather than Uploading/Published.
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("read")
        .expect("record");
    assert_eq!(record.state, GenerationState::Cancelled);

    // When the fence is released later, nothing becomes dispatchable.
    environment
        .service()
        .release_fence(
            PrivacyGeneration::new(1),
            PrivacyGeneration::new(2),
            TimestampMs::new(7_000),
        )
        .expect("a release");
    let outbox_after = environment
        .service()
        .outbox()
        .expect("outbox after release");
    assert!(outbox_after.is_empty());
}

#[test]
fn an_upload_finishing_after_privacy_mode_stops_does_not_enqueue_publication_and_completes_reconciliation()
 {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // The upload outbox entry is dispatched to the service.
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("dispatched");

    // Privacy mode is enabled: fence is recorded and undispatched work cancelled.
    let _fenced = environment.service.fence(PrivacyGeneration::new(1));
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1);

    // Privacy mode is reconciling because work is in flight.
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // Privacy mode is turned off before the in-flight upload completes, and the fence does not
    // come down: backup production does not resume into a scope this host has not finished
    // clearing, and the upload that left is still unanswered.
    environment
        .service
        .remove_retained(PrivacyGeneration::new(1));
    assert!(matches!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending { .. }
    ));
    assert_eq!(environment.service().fenced_at().expect("read"), Some(1));

    // The in-flight upload completes now, after privacy mode has stopped.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("upload noted");
    let complete = environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            manifest_id,
            TimestampMs::new(6_001),
        )
        .expect("manifest upload noted");
    assert!(complete);

    // No publish step is enqueued: the generation was cancelled when privacy mode was enabled.
    let outbox = environment.service().outbox().expect("outbox");
    assert!(
        outbox.is_empty(),
        "no publish step may be enqueued for a generation cancelled by privacy mode: {outbox:?}"
    );

    // The acknowledgement that finished the upload is evidence about that exact attempt, so it
    // ends with the obligation that named it. The staged ciphertext went before, and nothing else
    // is owed, so cleanup is complete and the fence can come down.
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }
    assert_eq!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );

    // And nothing of it is left on this host: the generation was cancelled, its ciphertext was
    // removed, and its bookkeeping went with the last thing it was waiting on.
    assert!(
        environment
            .service()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("read")
            .is_none()
    );
}

#[test]
fn a_publication_that_left_before_the_cancellation_survives_a_repeated_upload_acknowledgement() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");

    // Both objects arrive, so the publication is enqueued, and it leaves this host.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member is acknowledged");
    assert!(
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(6_001),
            )
            .expect("the manifest is acknowledged")
    );
    let publication = environment.service().outbox().expect("a read");
    assert_eq!(publication.len(), 1);
    assert_eq!(publication[0].step, Step::Publish);
    environment
        .service()
        .note_dispatched(publication[0].sequence)
        .expect("the publication is in flight");

    // Privacy mode draws its line while the publication is out there.
    let _fenced = environment.service.fence(PrivacyGeneration::new(1));
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1, "the publication had already left");

    // The service acknowledges an object a second time. That says nothing about the publication,
    // and the entry this host is still owed an answer for stays where it is.
    assert!(
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(7_000),
            )
            .expect("the repeated acknowledgement is recorded")
    );
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(
        outbox.len(),
        1,
        "the dispatched publication is not deleted by an upload acknowledgement: {outbox:?}"
    );
    assert_eq!(outbox[0].step, Step::Publish);
    assert!(outbox[0].dispatched);

    // And cleanup is not reported complete over it.
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(
        !PrivacyMode::reconcile(&subsystems).is_complete(),
        "a publication whose answer is still owed keeps cleanup open"
    );
}

#[test]
fn a_restart_does_not_end_the_wait_over_an_upload_that_left_this_host() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence)
            .expect("the upload is in flight");
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
        service.remove_retained(PrivacyGeneration::new(1));

        // The fence cannot be released while the attempt that left this host is unanswered: the
        // obligation that names it is still there, and the guarded statement finds it.
        assert_eq!(
            service
                .release_fence(
                    PrivacyGeneration::new(1),
                    PrivacyGeneration::new(2),
                    TimestampMs::new(7_000),
                )
                .expect("the release is attempted"),
            FenceRelease::Pending { obligations: 2 },
            "the unanswered attempt, and the bookkeeping that waits on it"
        );
    }

    // A restart is not evidence about what the service did. The attempt stays, its obligation
    // stays, and cleanup is not complete. Only an answer, or the caller establishing that the
    // transfer stopped, ends it.
    let service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.outcome_unknown.is_empty());
    assert!(outcome.resumed.is_empty());
    assert_eq!(service.outbox().expect("a read").len(), 1);
    let owed = service.obligations().expect("a read");
    assert_eq!(owed.len(), 2, "the unanswered attempt and its bookkeeping");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::ResolveUpload)
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.state, GenerationState::Cancelled);
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // The caller establishes that the transfer stopped without an answer. That is evidence about
    // this attempt, so the attempt and its obligation end together, and cleanup is complete.
    service
        .note_outcome_unknown(
            archive_id(),
            BackupGeneration::new(1),
            "the transfer stopped and no answer arrived",
            TimestampMs::new(8_000),
        )
        .expect("the outcome is recorded");
    assert!(service.outbox().expect("a read").is_empty());
    assert!(service.obligations().expect("a read").is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_cancelled_generation_whose_publication_left_keeps_its_unanswered_attempt() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence)
            .expect("the upload is in flight");
        let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
        service
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(6_000),
            )
            .expect("the member is acknowledged");
        service
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(6_001),
            )
            .expect("the manifest is acknowledged");
        let publication = service.outbox().expect("a read");
        service
            .note_dispatched(publication[0].sequence)
            .expect("the publication is in flight");
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // A publication left this host and was never answered. Whether the service holds it is not
    // something this host can say, and neither a cancellation nor a restart makes it say
    // otherwise.
    let service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(outcome.outcome_unknown.is_empty());
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    // The outcome is recorded as unknown and the attempt is still there. The two say different
    // things: what the service did is unknown, and this host has not established that the attempt
    // ended. A restart may say the first and never the second.
    assert_eq!(service.outbox().expect("a read").len(), 1);
    let owed = service.obligations().expect("a read");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::ResolvePublication),
        "the publication attempt keeps its own obligation: {owed:?}"
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(
        record.state,
        GenerationState::Cancelled,
        "production is stopped, which is a different fact from what the service did"
    );
    assert!(
        service
            .exported()
            .iter()
            .any(|artifact| artifact.kind == "backup archive, outcome unknown"),
        "a copy this host cannot account for is shown rather than pretended away"
    );
}

#[test]
fn an_object_acknowledged_before_its_staged_copy_went_still_finishes_the_upload() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member arrives before privacy mode is enabled");

    // The whole privacy sequence, staged ciphertext and all.
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_500));
    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_500))
    };
    assert_eq!(enabling.in_flight(), 1);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert!(!row.staged_path.exists(), "the ciphertext left this host");
    }

    // The transfer that was already out there finishes. Every object has now reached the service,
    // so the upload this host was waiting on is over and cleanup completes.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    assert!(
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(7_000),
            )
            .expect("the manifest is acknowledged")
    );
    let outbox = environment.service().outbox().expect("a read");
    assert!(
        outbox.is_empty(),
        "the upload is over and nothing is published in its place: {outbox:?}"
    );
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(
        PrivacyMode::reconcile(&subsystems).is_complete(),
        "every transfer has ended, so the cleanup has too"
    );
}

#[test]
fn a_restart_over_an_unanswered_attempt_still_owes_the_ciphertext_this_host_holds() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence)
            .expect("the upload is in flight");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Privacy mode fences and cancels, and this host stops before it removes anything.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // The restart reads back what the fence wrote down: the staged ciphertext is still here, and
    // the removal obligations say so. The attempt that left this host is still unanswered too.
    let mut service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert_eq!(service.outbox().expect("a read").len(), 1);
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(
            !PrivacyMode::reconcile(&subsystems).is_complete(),
            "cleanup is not complete while this host still holds the ciphertext"
        );
    }

    // The removal it owed clears those obligations, and the attempt that left this host keeps its
    // own: removing the local copy says nothing about what the service did with the bytes.
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for path in &staged_paths {
        assert!(!path.exists(), "the ciphertext left this host");
    }
    {
        let owed = service.obligations().expect("a read");
        assert!(
            owed.iter()
                .any(|obligation| obligation.kind == ObligationKind::ResolveUpload),
            "removing the local copy is not evidence about the transfer: {owed:?}"
        );
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // Evidence about that attempt is what ends it, and only then is the cleanup complete.
    service
        .note_outcome_unknown(
            archive_id(),
            BackupGeneration::new(1),
            "the transfer stopped and no answer arrived",
            TimestampMs::new(8_000),
        )
        .expect("the outcome is recorded");
    assert!(service.obligations().expect("a read").is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn an_acknowledgement_repeated_after_publication_still_says_the_upload_had_finished() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member is acknowledged");
    assert!(
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(6_001),
            )
            .expect("the manifest is acknowledged")
    );

    let publication = environment.service().outbox().expect("a read");
    environment
        .service()
        .note_dispatched(publication[0].sequence)
        .expect("the publication is in flight");
    let mode = PrivacyMode::new();
    environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(1),
            PrivacyGeneration::INITIAL,
            &mode,
            TimestampMs::new(6_500),
        )
        .expect("the service accepted it");

    // What the answer says is what the objects say, and every object had arrived. A settled
    // generation takes no more transitions, and nothing is enqueued in its place.
    assert!(
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(7_000),
            )
            .expect("the repeated acknowledgement is recorded")
    );
    assert!(environment.service().outbox().expect("a read").is_empty());
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.state, GenerationState::Published);
}

#[test]
fn a_restart_owes_the_ciphertext_of_cancelled_work_that_never_left_this_host() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Nothing was dispatched, so the cancellation empties the outbox outright. This host then
        // stops before it removes anything.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        let cancelled = service.cancel_undispatched(PrivacyGeneration::new(1));
        assert_eq!(cancelled.in_flight, 0);
        assert!(service.outbox().expect("a read").is_empty());
    }

    // There is no outbox entry left to say the cleanup is unfinished, and the ciphertext is still
    // here. The restart says so itself rather than reporting a cleanup that did not happen.
    let service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A second restart before the removal still owes it: the obligation is durable, not something
    // the first reconciliation spent.
    drop(service);
    let mut service = BackupService::open(&state).expect("the service opens a third time");
    service
        .reconcile(TimestampMs::new(8_000))
        .expect("reconciliation");
    assert!(!service.obligations().expect("a read").is_empty());
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_late_acknowledgement_does_not_bring_back_a_cleanup_that_is_finished() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence)
            .expect("the upload is in flight");
        service
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(6_000),
            )
            .expect("the member arrives first");

        // The whole privacy sequence, staged ciphertext and all.
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(6_500));
        {
            let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut service];
            mode.apply(&mut subsystems, TimestampMs::new(6_500));
        }

        // The transfer that had already left finishes afterwards. What the service has is written
        // down; where the ciphertext is does not change, because it is nowhere here.
        let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
        assert!(
            service
                .note_object_uploaded(
                    archive_id(),
                    BackupGeneration::new(1),
                    manifest_id,
                    TimestampMs::new(7_000),
                )
                .expect("the manifest is acknowledged")
        );
        for row in service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
        {
            assert_eq!(row.state, ObjectState::Removed);
            assert!(!row.staged_path.exists());
        }
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A restart does not raise a removal this host has already done.
    let service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(8_000))
        .expect("reconciliation");
    assert!(
        service.obligations().expect("a read").is_empty(),
        "the cleanup is finished and stays finished"
    );
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_restart_owes_the_ciphertext_of_a_published_archive_the_fence_had_not_reached() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence)
            .expect("the upload is in flight");
        let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
        for object in [objects[0].object_id(), manifest_id] {
            service
                .note_object_uploaded(
                    archive_id(),
                    BackupGeneration::new(1),
                    object,
                    TimestampMs::new(6_000),
                )
                .expect("acknowledged");
        }
        let publication = service.outbox().expect("a read");
        service
            .note_dispatched(publication[0].sequence)
            .expect("the publication is in flight");
        let mode = PrivacyMode::new();
        service
            .note_published(
                archive_id(),
                BackupGeneration::new(1),
                PrivacyGeneration::INITIAL,
                &mode,
                TimestampMs::new(6_500),
            )
            .expect("the service accepted it");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Privacy mode fences and cancels, and this host stops before it removes anything. The
        // published generation has nothing left in its outbox, so nothing there says its staged
        // copies are still here.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // While the fence is recorded, every staged copy is a removal privacy mode asked for. A
    // published archive's ciphertext is as much on this host as a cancelled one's.
    let mut service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    assert_eq!(
        removed.records, 0,
        "a published archive keeps its record as a retained artifact, so no row was removed"
    );
    for path in &staged_paths {
        assert!(!path.exists(), "the ciphertext left this host");
    }
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A second pass has nothing to remove and says so, and the record of what left this host stays.
    let again = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(again.bytes, 0);
    assert_eq!(again.records, 0);
    let kept = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("a published archive is shown rather than pretended away");
    assert_eq!(kept.state, GenerationState::Published);
}

// ---------------------------------------------------------------------------------------------
// Durable cleanup obligations: what a fence writes down, and what ends one.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fence_writes_down_every_target_it_implies_and_a_repeat_adds_nothing() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let fenced = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1);
    let owed = environment.service().obligations().expect("a read");
    // Three staged copies, one queued entry, one generation's bookkeeping, one staging walk.
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
            .count(),
        3
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::CancelEntry)
            .count(),
        1
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::FinishGeneration)
            .count(),
        1
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::ScanStaging)
            .count(),
        1
    );
    assert!(
        owed.iter()
            .all(|obligation| obligation.privacy_generation == 1)
    );

    // Every obligation names its own target, and each staged copy carries the path to remove.
    for obligation in owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
    {
        assert!(obligation.staged_path.is_some());
        assert!(obligation.object_id.is_some());
        assert_eq!(obligation.archive_id, Some(archive_id()));
    }

    // Asking for the same generation again reads the request back. It does not write a second
    // scope, and it does not recreate cleanup that has already been done.
    let again = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(again.queues, 1);
    assert_eq!(environment.service().obligations().expect("a read"), owed);
}

#[test]
fn a_repeated_request_after_cleanup_finished_does_not_recreate_it() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000));
    }
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );

    // The same request arriving again finds its record applied. Recreating the scope would put
    // back removals whose targets are already gone, which no retry could ever discharge.
    let repeated = environment.service.fence(mode.generation());
    assert_eq!(repeated.queues, 1);
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
}

#[test]
fn a_staged_copy_this_host_cannot_remove_keeps_its_own_obligation_until_it_can() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));

    // The directory that holds the ciphertext is made unwritable, so every unlink fails.
    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();
    set_directory_writable(&directory, false);
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(removed.bytes, 0);
    let owed = service.obligations().expect("a read");
    let failed: Vec<&_> = owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
        .collect();
    assert_eq!(failed.len(), staged.len());
    for obligation in &failed {
        assert!(obligation.attempt_count >= 1);
        assert!(
            obligation.last_error.is_some(),
            "the reason is recorded beside the obligation, never instead of it"
        );
    }
    assert!(!PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending {
            obligations: owed.len() as u64
        }
    );

    // A second attempt while the fault holds finds the same targets, not new ones.
    service.remove_retained(PrivacyGeneration::new(1));
    let again = service.obligations().expect("a read");
    assert_eq!(again.len(), owed.len());
    for obligation in &failed {
        assert!(
            again
                .iter()
                .any(|later| later.id == obligation.id
                    && later.attempt_count > obligation.attempt_count),
            "the same row, tried again"
        );
    }

    // A restart does not recreate them either: the rows are the account, not the process.
    drop(service);
    let mut service = BackupService::open(&state).expect("the service opens again");
    assert_eq!(service.obligations().expect("a read").len(), again.len());

    // Access comes back, and their own success is what ends them.
    set_directory_writable(&directory, true);
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for path in &staged {
        assert!(!path.exists());
    }
    assert!(service.obligations().expect("a read").is_empty());
    assert!(PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
}

#[test]
fn a_store_that_stops_accepting_writes_mid_cleanup_keeps_the_obligation_for_the_file_that_went() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));

    // The file goes and the store will not take the discharge. The effect happened; the record of
    // it did not, and the obligation is what survives that gap.
    service.set_query_only(true).expect("query_only pragma");
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(removed.records, 0);
    let owed = service.obligations().expect("a read");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::UnlinkObject),
        "the removal is still owed although the file has gone: {owed:?}"
    );
    assert!(!PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());

    // With write access back, a file that is already gone is exactly what the retry expects.
    service.set_query_only(false).expect("query_only pragma");
    service.remove_retained(PrivacyGeneration::new(1));
    for path in &staged {
        assert!(!path.exists());
    }
    assert!(service.obligations().expect("a read").is_empty());
    assert!(PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
}

#[test]
fn ciphertext_no_row_names_keeps_cleanup_pending_until_the_walk_finds_and_removes_it() {
    let environment = Environment::open();
    let mut environment = environment;
    let stray = environment
        .service()
        .staging_root()
        .join("11111111-1")
        .join("orphan.krb");
    std::fs::create_dir_all(stray.parent().expect("a directory")).expect("the directory");
    std::fs::write(&stray, b"ciphertext a stop left behind").expect("the stray file");

    environment.service.fence(PrivacyGeneration::new(1));
    // Nothing is registered, so nothing but the walk is owed until the walk has run.
    let owed = environment.service().obligations().expect("a read");
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].kind, ObligationKind::ScanStaging);

    environment
        .service()
        .run_cleanup(TimestampMs::new(6_000))
        .expect("the walk runs");
    assert!(!stray.exists(), "the file the walk found is gone");
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    assert!(PrivacyMode::reconcile(&[&environment.service as &dyn PrivacySubsystem]).is_complete());
}

#[test]
fn a_late_acknowledgement_ends_only_its_own_attempt_and_puts_no_file_back() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");
    // One member is acknowledged before the fence goes up.
    environment
        .service()
        .note_object_uploaded(
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(5_500),
        )
        .expect("the member is acknowledged");

    environment.service.fence(PrivacyGeneration::new(1));
    environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    let removed = environment
        .service
        .remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert_eq!(row.state, ObjectState::Removed);
    }

    // The rest of the upload finishes afterwards. It ends its own attempt and nothing else: no
    // publication is enqueued, and no object is described as staged here again.
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                row.object_id,
                TimestampMs::new(6_000),
            )
            .expect("the acknowledgement is recorded");
    }
    assert!(environment.service().outbox().expect("a read").is_empty());
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert_eq!(
            row.state,
            ObjectState::Removed,
            "an acknowledgement does not put a file back"
        );
    }
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    assert!(PrivacyMode::reconcile(&[&environment.service as &dyn PrivacySubsystem]).is_complete());
}

#[test]
fn a_second_fence_is_not_released_by_the_first_ones_cleanup() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();

    // The first fence leaves work behind, because nothing can be removed.
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));
    set_directory_writable(&directory, false);
    service.remove_retained(PrivacyGeneration::new(1));
    assert!(!service.obligations().expect("a read").is_empty());

    // A second request arrives over the top of it.
    service.fence(PrivacyGeneration::new(5));
    let status = service.privacy_status().expect("a read");
    assert_eq!(status.current_generation, 5);
    assert_eq!(status.unreleased_fence, Some(1), "the older fence stands");

    // Cleanup of the older fence cannot release the newer one, and a release aimed at the older
    // one does not move the generation in force backwards.
    set_directory_writable(&directory, true);
    service.remove_retained(PrivacyGeneration::new(5));
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(6),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
    assert_eq!(
        service.fenced_at().expect("a read"),
        Some(5),
        "the newer fence is untouched by the older one's release"
    );
    let status = service.privacy_status().expect("a read");
    assert!(status.enabled);
    assert_eq!(status.current_generation, 6);
    assert!(
        service
            .release_fence(
                PrivacyGeneration::new(5),
                PrivacyGeneration::new(4),
                TimestampMs::new(8_500),
            )
            .is_err(),
        "the generation in force never moves backwards"
    );
}

#[test]
fn direct_sql_cannot_release_a_fence_that_still_has_cleanup_outstanding() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service.fence(PrivacyGeneration::new(1));
        assert!(!service.obligations().expect("a read").is_empty());
    }

    // The rule lives in the database, not in the calling code. A writer that went round the store
    // still cannot say a fence with cleanup outstanding is released, or delete it instead.
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    let released = connection.execute(
        "UPDATE privacy_fences SET released_at_ms = 1 WHERE privacy_generation = 1",
        [],
    );
    assert!(released.is_err(), "{released:?}");
    let deleted = connection.execute(
        "DELETE FROM privacy_fences WHERE privacy_generation = 1",
        [],
    );
    assert!(deleted.is_err(), "{deleted:?}");

    // And a released fence takes no new cleanup: an obligation written against one would be work
    // nothing would ever look at again.
    connection
        .execute("DELETE FROM privacy_obligations", [])
        .expect("the obligations are cleared for this check");
    connection
        .execute(
            "UPDATE privacy_fences SET released_at_ms = 1 WHERE privacy_generation = 1",
            [],
        )
        .expect("the fence releases once nothing is owed");
    let late = connection.execute(
        "INSERT INTO privacy_obligations
             (privacy_generation, kind, target_key, recorded_at_ms, attempt_count)
         VALUES (1, 'scan_staging', 'staging', 1, 0)",
        [],
    );
    assert!(late.is_err(), "{late:?}");

    // An obligation against a generation this host never accepted a request for is refused too.
    let rootless = connection.execute(
        "INSERT INTO privacy_obligations
             (privacy_generation, kind, target_key, recorded_at_ms, attempt_count)
         VALUES (99, 'scan_staging', 'staging', 1, 0)",
        [],
    );
    assert!(rootless.is_err(), "{rootless:?}");
}

/// Makes a staging directory refuse or allow the removal of what is in it.
///
/// Unix only: there is no portable way to deny a directory write, so the tests that need one run
/// where there is.
#[cfg(unix)]
fn set_directory_writable(directory: &std::path::Path, writable: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = if writable { 0o700 } else { 0o500 };
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
        .expect("the staging directory's permissions");
}

#[cfg(not(unix))]
fn set_directory_writable(_directory: &std::path::Path, _writable: bool) {
    unimplemented!("these checks need a platform where a directory write can be denied")
}
