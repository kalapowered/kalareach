//! The environment's backup service: its store, its reconciliation, its restore checks and its
//! privacy hook.
//!
//! Section 24's ownership row for backup generations, and section 24's privacy paragraphs. Rule 12
//! applies to every path here: `backup.sqlite` and every staged byte live under the platform
//! temporary directory, which is on the internal disk, and nothing in this file launches a process.

use kr_controller::backup::store::{GenerationState, ObjectState, Step};
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

    // A restart comes back fenced, and its reconciliation leaves the fenced work where it is
    // rather than putting it back in hand.
    let service = BackupService::open(&state).expect("the service opens again");
    assert_eq!(service.fenced_at().expect("a read"), Some(4));
    assert!(service.note_dispatched(admitted.sequence).is_err());
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.fenced,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.resumed.is_empty());
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
    let resumed = mode.disable(TimestampMs::new(7_000));
    environment
        .service()
        .release_fence()
        .expect("the fence is released");
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
        RestoreRequest {
            archive_id: archive_id(),
            publication: &publication,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: impostor.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify()
        .is_err(),
        "the enrolment is verified against the owner's own key"
    );

    // A writer key that is not the one the owner enrolled.
    assert!(
        RestoreRequest {
            archive_id: archive_id(),
            publication: &publication,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: impostor.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify()
        .is_err(),
        "a writer the bundle supplied is checked against the owner's enrolment"
    );

    // A publication whose signature is another writer's.
    let forged = BackupGenerationPublication {
        payload: publication.payload.clone(),
        signature: impostor.publish(&sealed).signature,
    };
    assert!(
        RestoreRequest {
            archive_id: archive_id(),
            publication: &forged,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify()
        .is_err(),
        "the publication's own signature is verified under the enrolled writer"
    );

    // A publication for another archive than the one being restored.
    assert!(
        RestoreRequest {
            archive_id: ArchiveId::new(Uuid::from_bytes([0x99; 16])),
            publication: &publication,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify()
        .is_err(),
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
    assert!(
        RestoreRequest {
            archive_id: archive_id(),
            publication: &publication,
            descriptor_len: kr_protocol::archive::MAX_ARCHIVE_DESCRIPTOR_LEN + 1,
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify()
        .is_err()
    );
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
        assert!(service.obligations().expect("a read").is_empty());
        assert_eq!(service.fenced_at().expect("a read"), Some(4));
    }
    // A host that held the fence in memory would come back and dispatch what it had just stopped.
    let reopened = BackupService::open(&state).expect("the service opens again");
    assert_eq!(reopened.fenced_at().expect("a read"), Some(4));
}

#[test]
fn unpersisted_obligations_keep_outstanding_nonzero_when_store_cannot_write() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut service = BackupService::open(&state).expect("a backup service");

    // Put SQLite into query-only mode so writes fail while reads still work.
    service.set_query_only(true).expect("query_only pragma");

    // Fencing tries to write the fence and fails, then tries to record the obligation in SQLite
    // and fails because the database is query-only.
    let fenced = service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 0);

    // Outstanding must remain above 0 so privacy reconciliation does not falsely report complete.
    assert!(service.outstanding() > 0);
    let obligations = service.obligations().expect("obligations");
    assert!(
        obligations
            .iter()
            .any(|item| item.contains("record the backup fence")),
        "the unpersisted obligation is reported: {obligations:?}"
    );
}
