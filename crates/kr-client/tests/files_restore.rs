//! A restore to files, held to hostile data at its own interface.
//!
//! The service and the honest clients refuse a replayed or substituted generation themselves, so a
//! test through them would pass with the restore's own check removed. These tests serve what a
//! hostile service could: a source that answers with whatever the test scripts, signed by writers
//! the owner trusts wherever the claim is about something other than the signature.
//!
//! The kit, the bundle and the archive are sealed here with the production primitives, and the
//! restore is the one `kr backup restore` calls.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use kr_client::ClientError;
use kr_client::Shown;
use kr_client::error::HostWord;
use kr_client::pairing::checkpoint::{
    Answer, Held, PairedCheckpoint, PairedCheckpoints, SnapshotCause, Unsettled,
};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_client::recovery::{
    BundleWrite, BundleWriter, BundleWritten, CandidateState, CheckpointRecorded, ExportSource,
    FilesRestore, MemberRefusal, MemberRole, MemberVerdict, OFFLINE_EXPORT_FORMAT, OfflineExport,
    PairingStanding, PlannedMember, PublicationRefusal, RecoveryError, RestoreError, RestorePlan,
    RestoreSource, RetrievalPolicy, SignInCause, SourceService, SourceSignIn, fresh_locator,
};
use kr_client::retry::RETRY_BACKOFF_MIN;
use kr_client::services::{ServiceFuture, SyncFetched, SyncPosition};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CheckpointSource, CollectionKind, GenerationStanding, Material,
    ObjectSource, RestoreGeneration, seal_archive, stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    ARCHIVE_DESCRIPTOR_VERSION, ARCHIVE_MANIFEST_SCHEMA_VERSION, ArchiveCheckpoint,
    ArchiveDescriptor, ArchiveManifest, BACKUP_PUBLICATION_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, CollectionLocator, DescriptorError, EncryptedObjectRef,
    KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, MANIFEST_PAYLOAD_LIMITS, ManifestObject,
    ManifestPayload, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryKit, TrustedProducer,
    TrustedWriter,
};
use kr_protocol::backup_checkpoint::HostCheckpoint;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{Bytes, Digest256, EndpointKey, KeyId, TimestampMs, U64, Uuid};
use kr_protocol::service::GatewayOrigin;

const ORIGIN: &str = "https://reach.kala.to";
const OTHER_ORIGIN: &str = "https://elsewhere.example";

fn id(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn archive() -> ArchiveId {
    ArchiveId::new(id(0x11))
}

/* -------------------------------------------------------------------------- */
/* What the test seals                                                         */
/* -------------------------------------------------------------------------- */

/// The producer key every world seals with. It is fixed for the process so that the owner of an
/// entry can declare it: an entry counts for an archive only when its producer is the archive's.
fn world_producer() -> &'static StoredEnvelopeKeyPair {
    static PRODUCER: OnceLock<StoredEnvelopeKeyPair> = OnceLock::new();
    PRODUCER.get_or_init(|| StoredEnvelopeKeyPair::generate().expect("a producer key"))
}

/// The owner's side: a seed, the keys of the writer and the producer, and the collection.
struct World {
    seed: RecoverySeed,
    locator: String,
    writer: AuthorisationKeyPair,
    producer: StoredEnvelopeKeyPair,
}

/// One sealed generation: its signed publication and the objects it names.
struct Sealed {
    publication: BackupGenerationPublication,
    objects: BTreeMap<BackupObjectId, Vec<u8>>,
    manifest_object: BackupObjectId,
}

impl World {
    fn new() -> Self {
        Self {
            seed: RecoverySeed::generate().expect("a seed"),
            locator: fresh_locator().expect("a locator"),
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            producer: world_producer().clone(),
        }
    }

    fn kit(&self) -> RecoveryKit {
        self.seed
            .to_kit(vec![ORIGIN.to_owned()], self.locator.clone())
    }

    fn trusted(key: &AuthorisationKeyPair) -> TrustedWriter {
        TrustedWriter {
            writer_key_id: key.key_id(),
            signing_key: *key.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    fn trusted_producer(&self) -> TrustedProducer {
        TrustedProducer {
            sender_key_id: self.producer.key_id(),
            stored_envelope_key: *self.producer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    /// The recipients of an archive that the owner can recover: the recovery recipient.
    fn recipients(&self) -> ArchiveRecipients {
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.seed.recipient().expect("a recipient").public()));
        recipients
    }

    /// An archive of the members `(name, plaintext)`, sealed as the production primitives seal one.
    fn seal(&self, generation: u64, members: &[(&str, Vec<u8>)]) -> Sealed {
        self.seal_with(
            generation,
            members,
            &self.writer,
            &self.writer,
            &self.recipients(),
        )
    }

    /// As [`Self::seal`], with the key that signs the manifest, the key that signs the publication
    /// and the recipients named.
    fn seal_with(
        &self,
        generation: u64,
        members: &[(&str, Vec<u8>)],
        manifest_writer: &AuthorisationKeyPair,
        publication_writer: &AuthorisationKeyPair,
        recipients: &ArchiveRecipients,
    ) -> Sealed {
        let staged: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(at, (name, plaintext))| {
                stage_object(
                    &ObjectSource {
                        object_id: BackupObjectId::new(id(0x20 + u8::try_from(at).expect("few"))),
                        filename: name,
                        plaintext,
                    },
                    recipients.rotation(),
                )
                .expect("a staged object")
            })
            .collect();
        let manifest_object = BackupObjectId::new(id(0xf0));
        let sealed = seal_archive(
            manifest_writer,
            &self.producer,
            recipients,
            &ArchivePlan {
                archive_id: archive(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: DeviceId::new(id(0x33)),
                manifest_object_id: manifest_object,
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            &staged,
        )
        .expect("a sealed archive");
        let mut objects: BTreeMap<_, _> = staged
            .iter()
            .map(|staged| (staged.object_id(), staged.bytes().to_vec()))
            .collect();
        objects.insert(manifest_object, sealed.encrypted_manifest.clone());
        Sealed {
            publication: publish(&sealed.descriptor, publication_writer),
            objects,
            manifest_object,
        }
    }

    /// An archive whose members are only declared: a manifest naming them with the stored lengths
    /// given, and no bytes behind them. A restore plans from the manifest and reads nothing else.
    fn seal_declared(&self, generation: u64, members: &[(&str, u64)]) -> Sealed {
        let recipient = self.seed.recipient().expect("a recipient");
        let recipient_key_id = kr_crypto::backup::recipient_key_id(recipient.public());
        let objects: Vec<ManifestObject> = members
            .iter()
            .enumerate()
            .map(|(at, (name, stored))| ManifestObject {
                object: EncryptedObjectRef {
                    object_id: BackupObjectId::new(Uuid::from_bytes({
                        let mut bytes = [0x40; 16];
                        bytes[14] = u8::try_from(at >> 8).expect("a byte");
                        bytes[15] = u8::try_from(at & 0xff).expect("a byte");
                        bytes
                    })),
                    encrypted_object_hash: Digest256::from_bytes([0x44; 32]),
                    encrypted_len: U64::new(*stored),
                },
                filename: (*name).to_owned(),
            })
            .collect();
        let manifest = kr_crypto::archive::sign_manifest(
            &self.writer,
            ArchiveManifest {
                schema_version: U64::new(ARCHIVE_MANIFEST_SCHEMA_VERSION),
                archive_id: archive(),
                owner_device_id: DeviceId::new(id(0x33)),
                backup_generation: BackupGeneration::new(generation),
                objects,
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
        )
        .expect("a signed manifest");
        let payload = ManifestPayload {
            manifest,
            member_key_wraps: Vec::new(),
        };
        let bytes =
            kr_cbor::to_canonical_vec_within(&payload, &MANIFEST_PAYLOAD_LIMITS).expect("encoded");
        let manifest_object = BackupObjectId::new(id(0xf1));
        let encrypted = kr_crypto::archive::encrypt_object(manifest_object, &bytes)
            .expect("an encrypted manifest");
        let wrap = kr_crypto::archive::wrap_object_key(
            &self.producer,
            recipient.public(),
            KeyWrapContext {
                format: KeyWrapFormat::V1,
                purpose: KeyWrapPurpose::ManifestKey,
                archive_id: archive(),
                backup_generation: BackupGeneration::new(generation),
                object_id: manifest_object,
                encrypted_object_hash: encrypted.reference.encrypted_object_hash,
                sender_key_id: self.producer.key_id(),
                recipient_key_id,
            },
            &encrypted.key,
        )
        .expect("a wrap");
        let descriptor = ArchiveDescriptor {
            version: U64::new(ARCHIVE_DESCRIPTOR_VERSION),
            archive_id: archive(),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest: encrypted.reference.clone(),
            manifest_key_wraps: vec![wrap],
        };
        Sealed {
            publication: publish(&descriptor, &self.writer),
            objects: BTreeMap::from([(manifest_object, encrypted.bytes)]),
            manifest_object,
        }
    }

    /// The sealed bundle the owner keeps at the locator, for the origin the kit names.
    fn bundle(&self, shape: &Shape) -> Vec<u8> {
        let mut writers = vec![Self::trusted(&self.writer)];
        writers.extend(shape.more_writers.iter().cloned());
        if let Some(only) = &shape.only_writers {
            writers.clone_from(only);
        }
        let producers = if shape.no_producer {
            Vec::new()
        } else {
            vec![self.trusted_producer()]
        };
        let bundle = RecoveryBundle {
            schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
            collections: shape.collections.clone().unwrap_or_else(|| {
                vec![collection(
                    ORIGIN,
                    &format!("collection-1{}", "x".repeat(shape.padding)),
                    archive(),
                )]
            }),
            trusted_writers: writers.into_iter().collect(),
            trusted_producers: producers.into_iter().collect(),
            checkpoints: shape
                .checkpoint
                .iter()
                .chain(shape.more_checkpoints.iter())
                .cloned()
                .collect(),
            revision: U64::new(shape.revision.unwrap_or(3)),
            written_at_ms: TimestampMs::new(2_000),
            device_settings: shape.device_settings.clone(),
        };
        let key = self
            .seed
            .bundle_key_for(&kr_protocol::archive::RecoveryContext {
                service_origin: shape.sealed_for_origin.unwrap_or(ORIGIN).to_owned(),
                bundle_locator: shape
                    .sealed_at_locator
                    .clone()
                    .unwrap_or_else(|| self.locator.clone()),
            })
            .expect("a bundle key");
        kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle).expect("a sealed bundle")
    }
}

/// How a test bends the bundle.
#[derive(Default)]
struct Shape {
    more_writers: Vec<TrustedWriter>,
    only_writers: Option<Vec<TrustedWriter>>,
    no_producer: bool,
    collections: Option<Vec<CollectionLocator>>,
    checkpoint: Option<ArchiveCheckpoint>,
    /// The checkpoints of other archives the bundle records.
    more_checkpoints: Vec<ArchiveCheckpoint>,
    /// The bundle's revision, when it is not the usual one.
    revision: Option<u64>,
    sealed_for_origin: Option<&'static str>,
    sealed_at_locator: Option<String>,
    /// The settings member saved in the bundle, when there is one.
    device_settings: Option<Bytes>,
    /// Characters added to the default collection's locator, to bring the sealed bundle near the
    /// bound a service keeps.
    padding: usize,
}

fn collection(origin: &str, locator: &str, archive_id: ArchiveId) -> CollectionLocator {
    CollectionLocator {
        service_origin: origin.to_owned(),
        locator: locator.to_owned(),
        archive_id,
    }
}

fn publish(
    descriptor: &ArchiveDescriptor,
    writer: &AuthorisationKeyPair,
) -> BackupGenerationPublication {
    let payload = BackupGenerationPublicationPayload {
        descriptor: descriptor.clone(),
        writer_key_id: writer.key_id(),
        published_at_ms: TimestampMs::new(5_000),
    };
    resign(payload, writer)
}

fn resign(
    payload: BackupGenerationPublicationPayload,
    writer: &AuthorisationKeyPair,
) -> BackupGenerationPublication {
    let signature = sign(
        writer,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    BackupGenerationPublication { payload, signature }
}

fn checkpoint_of(sealed: &Sealed) -> ArchiveCheckpoint {
    let descriptor = &sealed.publication.payload.descriptor;
    ArchiveCheckpoint {
        archive_id: archive(),
        backup_generation: descriptor.backup_generation,
        encrypted_manifest_hash: descriptor.encrypted_manifest.encrypted_object_hash,
        verified_at_ms: TimestampMs::new(4_000),
    }
}

/* -------------------------------------------------------------------------- */
/* What the service serves                                                     */
/* -------------------------------------------------------------------------- */

/// What one script serves, and what it was asked.
#[derive(Debug)]
struct Scripted {
    service: SourceService,
    /// The sealed bundle, served for the locator it is at, or for any locator when `anywhere`.
    bundle: Mutex<Option<(String, Vec<u8>)>>,
    anywhere: bool,
    generations: Mutex<BTreeMap<ArchiveId, BackupGenerationPublication>>,
    objects: Mutex<BTreeMap<(ArchiveId, BackupObjectId), Vec<u8>>>,
    asked: Mutex<Vec<String>>,
    /// Where the bundle is in the collection's order: a write takes the next place.
    place: Mutex<u64>,
    /// Answer a request held to a checkpoint with nothing when the generation held is older, as the
    /// real service does; a hostile one serves what it holds whatever it was asked.
    honours_the_hold: bool,
    /// Answer every object read with no bytes, as a service that has lost the object might.
    serves_empty_ranges: bool,
    /// How many empty answers have been given, so a restore that keeps asking fails here.
    empty_answers: std::sync::atomic::AtomicUsize,
}

impl Scripted {
    fn serving(world: &World, bundle: Vec<u8>) -> Self {
        Self {
            service: SourceService {
                origin: ORIGIN.to_owned(),
                managed_origin: ORIGIN.to_owned(),
                sign_in: SourceSignIn::Usable,
            },
            bundle: Mutex::new(Some((world.locator.clone(), bundle))),
            anywhere: false,
            generations: Mutex::default(),
            objects: Mutex::default(),
            asked: Mutex::default(),
            place: Mutex::new(1),
            honours_the_hold: false,
            serves_empty_ranges: false,
            empty_answers: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn honouring_the_hold(mut self) -> Self {
        self.honours_the_hold = true;
        self
    }

    fn publishing(self, sealed: &Sealed) -> Self {
        self.generations
            .lock()
            .expect("generations")
            .insert(archive(), sealed.publication.clone());
        let mut objects = self.objects.lock().expect("objects");
        for (object, bytes) in &sealed.objects {
            objects.insert((archive(), *object), bytes.clone());
        }
        drop(objects);
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }

    /// Where the bundle is now.
    fn position(&self) -> SyncPosition {
        let place = *self.place.lock().expect("place");
        SyncPosition::at(
            place,
            kr_client::services::SyncRevision::new(id(u8::try_from(0x70 + place).expect("few"))),
            None,
        )
    }

    /// Replaces the bundle at the next place, as a write from another device would.
    fn replace_bundle(&self, sealed: Vec<u8>) -> SyncPosition {
        *self.place.lock().expect("place") += 1;
        let mut held = self.bundle.lock().expect("bundle");
        let at = held.as_ref().map(|(at, _)| at.clone()).expect("a bundle");
        *held = Some((at, sealed));
        drop(held);
        self.position()
    }

    /// The sealed bundle the service holds.
    fn sealed_bundle(&self) -> Vec<u8> {
        self.bundle
            .lock()
            .expect("bundle")
            .as_ref()
            .map(|(_, sealed)| sealed.clone())
            .expect("a bundle")
    }

    /// Every ask for a generation, with the complete checkpoint it was held to, in order.
    fn generation_asks(&self) -> Vec<String> {
        self.asked()
            .into_iter()
            .filter(|call| call.starts_with("generation "))
            .collect()
    }

    fn object_reads(&self) -> usize {
        self.asked()
            .iter()
            .filter(|call| call.starts_with("object"))
            .count()
    }

    fn corrupt(&self, object: BackupObjectId) {
        let mut objects = self.objects.lock().expect("objects");
        let bytes = objects
            .get_mut(&(archive(), object))
            .expect("an object to corrupt");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
    }
}

impl RestoreSource for Scripted {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async { Ok(self.service.clone()) })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        self.asked.lock().expect("asked").push("bundle".to_owned());
        Box::pin(async move {
            let held = self.bundle.lock().expect("bundle").clone();
            Ok(match held {
                Some((at, ciphertext)) if self.anywhere || at == locator => SyncFetched::Held {
                    position: self.position(),
                    ciphertext,
                },
                _ => SyncFetched::Absent { recovery: None },
            })
        })
    }

    fn generation<'a>(
        &'a self,
        archive_id: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<kr_protocol::archive::BackupGenerationPublication>> {
        self.asked.lock().expect("asked").push(format!(
            "generation {} {}",
            archive_id,
            checkpoint.map_or_else(
                || "unheld".to_owned(),
                |checkpoint| format!(
                    "held to generation {} manifest {}",
                    checkpoint.backup_generation.get(),
                    hex(&checkpoint.encrypted_manifest_hash)
                )
            )
        ));
        Box::pin(async move {
            let held = self
                .generations
                .lock()
                .expect("generations")
                .get(&archive_id)
                .cloned();
            Ok(held.filter(|held| {
                !(self.honours_the_hold
                    && checkpoint.is_some_and(|checkpoint| {
                        held.payload.descriptor.backup_generation < checkpoint.backup_generation
                    }))
            }))
        })
    }

    fn object(
        &self,
        archive_id: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        self.asked
            .lock()
            .expect("asked")
            .push(format!("object {object:?} at {offset}"));
        Box::pin(async move {
            if self.serves_empty_ranges {
                let given = self
                    .empty_answers
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    given < 5,
                    "the restore keeps asking a service that answers nothing"
                );
                return Ok(Vec::new());
            }
            let objects = self.objects.lock().expect("objects");
            let bytes = objects
                .get(&(archive_id, object))
                .expect("a read of an object the script holds");
            let start = usize::try_from(offset).expect("an offset");
            let end = usize::try_from(offset + length)
                .expect("an end")
                .min(bytes.len());
            Ok(bytes[start..end].to_vec())
        })
    }
}

async fn restore(
    world: &World,
    source: &Arc<Scripted>,
    chosen: Option<ArchiveId>,
) -> Result<kr_client::recovery::PreparedRestore, RestoreError> {
    FilesRestore::prepare(
        world.kit(),
        Arc::clone(source) as Arc<dyn RestoreSource>,
        chosen,
        None,
        &Held::Absent,
    )
    .await
}

fn honest_members() -> Vec<(&'static str, Vec<u8>)> {
    let session = format!("sessions/{}.json", "0a1b2c3d-0000-4000-8000-000000000001");
    vec![
        (
            Box::leak(session.into_boxed_str()) as &str,
            b"what the session did".to_vec(),
        ),
        ("host/configuration.json", b"{\"storage\":{}}".to_vec()),
    ]
}

/// The honest case, which every refusal below is a variation of.
#[tokio::test]
async fn an_archive_the_bundle_vouches_for_restores_its_session_and_configuration() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let plan = prepared.plan();
    assert_eq!(plan.generation.get(), 4);
    assert_eq!(plan.members.len(), 2);
    let files: Vec<_> = plan
        .restored()
        .map(|(_, file, role)| (file.to_owned(), role))
        .collect();
    assert_eq!(
        files,
        vec![
            ("session-0001.json".to_owned(), MemberRole::Session),
            ("configuration.json".to_owned(), MemberRole::Configuration),
        ],
        "files are named from the role and a number, never from the archive's names"
    );
    assert!(plan.refused().next().is_none());
    // Nothing but the manifest object was read to make the plan.
    assert_eq!(source.object_reads(), 1);
    let first = prepared
        .member(plan.members[0].object_id)
        .await
        .expect("a member");
    assert_eq!(first.expose(), b"what the session did");
    let second = prepared
        .member(plan.members[1].object_id)
        .await
        .expect("a member");
    assert_eq!(second.expose(), b"{\"storage\":{}}");
}

/// A plan's digest is what a person confirms, so it changes with anything the person is
/// confirming.
#[tokio::test]
async fn the_digest_a_person_confirms_changes_with_the_destination_the_environment_and_the_archive()
{
    let world = World::new();
    let first = world.seal(4, &honest_members());
    let newer = world.seal(5, &honest_members());
    async fn digest(
        world: &World,
        sealed: &Sealed,
        environment: &str,
        destination: &[u8],
    ) -> String {
        let source =
            Arc::new(Scripted::serving(world, world.bundle(&Shape::default())).publishing(sealed));
        let prepared = restore(world, &source, None).await.expect("a restore");
        prepared
            .plan()
            .digest(environment, destination, "")
            .expect("a digest")
    }
    let base = digest(&world, &first, "env-1", b"/restore/a").await;
    assert_eq!(
        base,
        digest(&world, &first, "env-1", b"/restore/a").await,
        "it is stable"
    );
    assert_ne!(base, digest(&world, &first, "env-1", b"/restore/b").await);
    assert_ne!(base, digest(&world, &first, "env-2", b"/restore/a").await);
    assert_ne!(base, digest(&world, &newer, "env-1", b"/restore/a").await);
    // The same archive, signed again at another time, is another plan: the plan shows the time.
    let signed_again = {
        let mut payload = first.publication.payload.clone();
        payload.published_at_ms = TimestampMs::new(6_000);
        Sealed {
            publication: resign(payload, &world.writer),
            objects: first.objects.clone(),
            manifest_object: first.manifest_object,
        }
    };
    assert_ne!(
        base,
        digest(&world, &signed_again, "env-1", b"/restore/a").await
    );
    // Two folders whose names differ only in bytes that are not text are two destinations.
    assert_ne!(
        digest(&world, &first, "env-1", b"/restore/\xff").await,
        digest(&world, &first, "env-1", b"/restore/\xfe").await
    );
    // The same generation with other content has another manifest and the same names and sizes:
    // only the manifest's hash tells the two plans apart.
    let other_content = world.seal(
        4,
        &honest_members()
            .into_iter()
            .map(|(name, mut bytes)| {
                bytes[0] ^= 1;
                (name, bytes)
            })
            .collect::<Vec<_>>(),
    );
    assert_ne!(
        base,
        digest(&world, &other_content, "env-1", b"/restore/a").await,
        "a plan with another manifest is another plan"
    );
}

/// KR-REQ-24.16: writer authority is verified. Every claim about who may vouch for an archive, each
/// with a signature a trusted writer made wherever the claim is not about the signature itself.
#[tokio::test]
async fn a_restore_trusts_the_writers_and_the_generation_the_authenticated_bundle_names() {
    let world = World::new();
    let members = honest_members();

    // The control: the same archive, vouched for, restores.
    let honest = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&honest));
    assert!(restore(&world, &source, None).await.is_ok());

    // A writer the bundle does not name signed the publication (validly, with its own key).
    let impostor = AuthorisationKeyPair::generate().expect("a key");
    let by_impostor = world.seal_with(4, &members, &impostor, &impostor, &world.recipients());
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&by_impostor),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::WriterNotInBundle)
    ));
    assert_eq!(source.object_reads(), 0, "refused before an object is read");

    // A genuine publication of another collection of the same writer.
    let other = {
        let mut sealed = world.seal(4, &members);
        let mut payload = sealed.publication.payload.clone();
        payload.descriptor.archive_id = ArchiveId::new(id(0x12));
        for wrap in &mut payload.descriptor.manifest_key_wraps {
            wrap.context.archive_id = ArchiveId::new(id(0x12));
        }
        sealed.publication = resign(payload, &world.writer);
        sealed
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&other));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::OtherArchive)
    ));
    assert_eq!(source.object_reads(), 0);

    // A publication whose signature fails.
    let mut forged = world.seal(4, &members);
    let mut payload = forged.publication.payload.clone();
    payload.published_at_ms = TimestampMs::new(9_999);
    forged.publication = BackupGenerationPublication {
        payload,
        signature: forged.publication.signature,
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&forged));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::BadSignature)
    ));

    // A writer whose identifier in the bundle is not the identifier of the key it carries.
    let confused = {
        let mut claimed = World::trusted(&world.writer);
        claimed.signing_key = *impostor.public();
        claimed
    };
    // The publication names the writer's identifier and is signed by the key the bundle carries
    // under it, so only the identifier check can refuse it.
    let mut confusing = world.seal(4, &members);
    confusing.publication = resign(confusing.publication.payload.clone(), &impostor);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                only_writers: Some(vec![confused]),
                ..Shape::default()
            }),
        )
        .publishing(&confusing),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::WriterKeyMismatch)
    ));
    assert_eq!(source.object_reads(), 0);

    // A descriptor over the byte limit, validly signed by the trusted writer, is refused before an
    // object is read: the restore measures the descriptor it was handed.
    let mut oversize = world.seal(4, &members);
    let mut payload = oversize.publication.payload.clone();
    let wrap = payload.descriptor.manifest_key_wraps[0].clone();
    payload.descriptor.manifest_key_wraps = vec![wrap; 400];
    oversize.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&oversize));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Structure(
            DescriptorError::TooLarge { .. }
        ))
    ));
    assert_eq!(source.object_reads(), 0);

    // A descriptor the protocol refuses, validly signed by the trusted writer, is refused before
    // an object is read.
    let mut invalid = world.seal(4, &members);
    let mut payload = invalid.publication.payload.clone();
    payload.descriptor.version = U64::new(2);
    invalid.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&invalid));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Structure(_))
    ));
    assert_eq!(source.object_reads(), 0);

    // The publication's writer is not the manifest's: both are trusted, each signed its own.
    let second = AuthorisationKeyPair::generate().expect("a key");
    let split = world.seal_with(4, &members, &second, &world.writer, &world.recipients());
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                more_writers: vec![World::trusted(&second)],
                ..Shape::default()
            }),
        )
        .publishing(&split),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::ManifestWriter
    ));

    // A producer the bundle does not hold.
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                no_producer: true,
                ..Shape::default()
            }),
        )
        .publishing(&honest),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoProducer
    ));
    assert_eq!(source.object_reads(), 0);

    // A manifest key wrapped for another recipient only.
    let mut elsewhere = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(elsewhere.add(*StoredEnvelopeKeyPair::generate().expect("a key").public()));
    let for_another = world.seal_with(4, &members, &world.writer, &world.writer, &elsewhere);
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&for_another),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoWrap
    ));
    assert_eq!(source.object_reads(), 0);
}

/// KR-REQ-24.16: the generation is verified. The checkpoint is what catches a genuine archive from
/// the wrong time.
#[tokio::test]
async fn a_generation_the_checkpoint_refuses_is_refused_before_the_manifest_is_read() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let checkpoint = checkpoint_of(&current);
    let shape = || Shape {
        checkpoint: Some(checkpoint.clone()),
        ..Shape::default()
    };

    // The control: the checkpoint's own generation restores, and the standing says so.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&current));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    assert!(prepared.plan().standing.checkpoint_available());
    assert!(
        source
            .asked()
            .iter()
            .any(|call| call.contains("held to generation"))
    );

    // A word that names an older generation does not cover the checkpoint's own: the service holds
    // generation 5, which needs none, and it is not restored under a word the person gave for
    // another.
    let named = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(3)),
        &Held::Absent,
    )
    .await
    .expect_err("the named generation is not what is held");
    assert!(matches!(
        named,
        RestoreError::NamedGenerationNotHeld {
            named: 3,
            held: 5,
            checkpoint_source: CheckpointSource::RecoveryBundle,
            ..
        }
    ));

    // An older generation than the checkpoint, genuinely signed.
    let older = world.seal(3, &members);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&older));
    let replay = restore(&world, &source, None).await.expect_err("refused");
    assert!(matches!(
        replay,
        RestoreError::Publication(PublicationRefusal::Generation(..))
    ));
    // The person is told the two generations: the one offered and the one the checkpoint holds.
    let told = replay.to_string();
    assert!(
        told.contains("generation 3") && told.contains("generation 5"),
        "{told}"
    );
    assert!(
        !told.contains("Restoring"),
        "a generation that is refused is not introduced as being restored: {told}"
    );
    assert_eq!(source.object_reads(), 0, "a replay costs no download");

    // The checkpoint's generation with a second genuine manifest.
    let second = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&second));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Generation(..))
    ));
    assert_eq!(source.object_reads(), 0);

    // The honest service holds nothing at all: asked held to the checkpoint and then without it,
    // it answers nothing both times, and the restore stops, having read no object.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("stopped"),
        RestoreError::NothingAsNewAsTheCheckpoint { checkpoint: 5, .. }
    ));
    assert_eq!(source.object_reads(), 0);

    // The honest service holds only an older generation: held to the checkpoint it answers
    // nothing, and the restore asks once more, without it, to say what the service does hold. That
    // is verified before it is named, and no object is read.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&shape()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 3,
            ..
        }
    ));
    assert_eq!(source.object_reads(), 0);
    // Naming that generation restores it, and the standing says it was named.
    let prepared = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(3)),
        &Held::Absent,
    )
    .await
    .expect("the named generation restores");
    assert_eq!(prepared.plan().generation.get(), 3);
    // A generation the service does not hold is not accepted, and the refusal says what it holds.
    assert!(matches!(
        FilesRestore::prepare(
            world.kit(),
            Arc::clone(&source) as Arc<dyn RestoreSource>,
            None,
            Some(BackupGeneration::new(4)),
            &Held::Absent,
        )
        .await
        .expect_err("refused"),
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 3,
            ..
        }
    ));
    // With no checkpoint there is nothing to accept an older generation past.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    assert!(matches!(
        FilesRestore::prepare(
            world.kit(),
            Arc::clone(&source) as Arc<dyn RestoreSource>,
            None,
            Some(BackupGeneration::new(3)),
            &Held::Absent,
        )
        .await
        .expect_err("refused"),
        RestoreError::NoCheckpointToAcceptPast {
            pairing_consulted: false,
            ..
        }
    ));

    // With no checkpoint at all, an archive the service holds restores, and says nothing is
    // proven; and one it does not hold is a different stop.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&current));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    assert!(!prepared.plan().standing.checkpoint_available());
    assert!(!prepared.plan().standing.proves_no_newer_archive());
    let source = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("stopped"),
        RestoreError::NoGeneration
    ));
}

/// A service that takes writes of the bundle by compare-and-swap, the way the real one does, with
/// one thing a test can script: a write that lands from somewhere else just before the restore's
/// own, or an answer to the restore's own that never arrives.
#[derive(Debug)]
struct Bundle {
    source: Arc<Scripted>,
    /// The sealed bundle another device writes just before the next write meets the service.
    meanwhile: Mutex<Option<Vec<u8>>>,
    /// The code the next write that applies is answered with in place of its answer, after the
    /// service applied it.
    loses_the_answer: Mutex<Option<ErrorCode>>,
    /// The code the next write that applies is refused with, before the service applies it.
    refuses_with: Mutex<Option<ErrorCode>>,
    /// The code every write that applies is refused with, before the service applies it.
    keeps_refusing_with: Mutex<Option<ErrorCode>>,
    /// How many of the next writes find the bundle moved on, and are answered as a conflict.
    conflicts: Mutex<usize>,
    /// How many writes met the service.
    writes: Mutex<usize>,
}

impl Bundle {
    fn over(source: &Arc<Scripted>) -> Self {
        Self {
            source: Arc::clone(source),
            meanwhile: Mutex::new(None),
            loses_the_answer: Mutex::new(None),
            refuses_with: Mutex::new(None),
            keeps_refusing_with: Mutex::new(None),
            conflicts: Mutex::new(0),
            writes: Mutex::new(0),
        }
    }
}

impl BundleWriter for Bundle {
    fn write<'a>(&'a self, write: BundleWrite<'a>) -> ServiceFuture<'a, BundleWritten> {
        Box::pin(async move {
            *self.writes.lock().expect("writes") += 1;
            if let Some(other) = self.meanwhile.lock().expect("meanwhile").take() {
                self.source.replace_bundle(other);
            }
            if write.expected != self.source.position() {
                return Ok(BundleWritten::Conflict);
            }
            {
                let mut conflicts = self.conflicts.lock().expect("conflicts");
                if *conflicts > 0 {
                    *conflicts -= 1;
                    return Ok(BundleWritten::Conflict);
                }
            }
            let refusing = self
                .refuses_with
                .lock()
                .expect("refuses")
                .take()
                .or(*self.keeps_refusing_with.lock().expect("keeps refusing"));
            if let Some(code) = refusing {
                return Err(ClientError::Host(ProtocolError::new(
                    code,
                    "the service refused it".to_owned(),
                )));
            }
            let placed = self.source.replace_bundle(write.sealed.to_vec());
            if let Some(code) = self.loses_the_answer.lock().expect("loses").take() {
                return Err(ClientError::Host(ProtocolError::new(
                    code,
                    "the answer did not arrive".to_owned(),
                )));
            }
            Ok(BundleWritten::Written(placed))
        })
    }
}

/// The bundle the service holds, opened under the world's seed.
fn bundle_held(world: &World, source: &Scripted) -> RecoveryBundle {
    let key = world
        .seed
        .bundle_key_for(&kr_protocol::archive::RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: world.locator.clone(),
        })
        .expect("a bundle key");
    kr_crypto::archive::decrypt_recovery_bundle(&key, &source.sealed_bundle())
        .expect("the bundle opens")
}

/// KR-REQ-24.16, 20.12: the checkpoint a restore records is written on what the bundle holds when
/// the write is made, so a writer that another device added between the restore's read and its
/// write is still in the bundle afterwards, and a write whose answer never came is neither done
/// twice nor taken for undone.
#[tokio::test]
async fn recording_the_checkpoint_keeps_what_another_device_wrote_to_the_bundle_meanwhile() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let before = bundle_held(&world, &source);
    assert!(before.checkpoints.is_empty());

    // Another device enrols a writer after the restore read the bundle.
    let added = TrustedWriter {
        writer_key_id: AuthorisationKeyPair::generate().expect("a key").key_id(),
        signing_key: *AuthorisationKeyPair::generate().expect("a key").public(),
        enrolled_at_ms: TimestampMs::new(1_500),
    };
    let other = world.bundle(&Shape {
        more_writers: vec![added.clone()],
        ..Shape::default()
    });
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(other);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("recorded");
    assert!(matches!(recorded, CheckpointRecorded::Written { .. }));
    assert_eq!(
        *bundle.writes.lock().expect("writes"),
        2,
        "a conflict, then the write"
    );

    let after = bundle_held(&world, &source);
    assert!(
        after.trusted_writers.contains(&added),
        "the writer another device added is still trusted"
    );
    assert_eq!(after.trusted_producers, before.trusted_producers);
    assert_eq!(after.collections, before.collections);
    assert_eq!(
        after.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [ArchiveCheckpoint {
            verified_at_ms: TimestampMs::new(9_000),
            ..checkpoint_of(&sealed)
        }]
    );
    assert_eq!(after.revision.get(), before.revision.get() + 1);

    // A write that landed and was not answered: the next read finds the checkpoint recorded, and
    // nothing is written a second time.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.loses_the_answer.lock().expect("loses") = Some(ErrorCode::OutcomeUnknown);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("settled by reading");
    assert!(matches!(recorded, CheckpointRecorded::AlreadyThere));
    assert_eq!(*bundle.writes.lock().expect("writes"), 1);
    assert_eq!(bundle_held(&world, &source).checkpoints.len(), 1);
}

/// The shape of a bundle that leaves `room` bytes under the bound a service keeps.
fn leaving(world: &World, settings: Option<&Bytes>, room: usize) -> Shape {
    let target = usize::try_from(kr_protocol::sync::MAX_SEALED_RECOVERY_BUNDLE_BYTES)
        .expect("a length")
        - room;
    let mut padding = 100_000_usize;
    for _ in 0..6 {
        let shape = Shape {
            device_settings: settings.cloned(),
            padding,
            ..Shape::default()
        };
        let length = world.bundle(&shape).len();
        if length == target {
            return shape;
        }
        padding = (padding + target).saturating_sub(length);
    }
    panic!("the bundle never reached {room} bytes under the bound");
}

/// KR-REQ-20.17: the checkpoint a restore records is held to the policy every write of the bundle
/// is. One that would not fit under the bound with the settings saved in the bundle is written
/// without them, and the result says so; one that does not fit without them either is refused and
/// nothing is written.
#[tokio::test]
async fn a_checkpoint_that_would_not_fit_with_the_settings_is_written_without_them() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let member = Bytes::new(vec![0x5a; 1024]);

    let shape = leaving(&world, Some(&member), 20);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape)).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let before = bundle_held(&world, &source);
    assert_eq!(before.device_settings, Some(member.clone()));
    let bundle = Bundle::over(&source);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("recorded");
    assert!(matches!(
        recorded,
        CheckpointRecorded::WrittenWithoutSettings { .. }
    ));
    let after = bundle_held(&world, &source);
    assert_eq!(after.device_settings, None, "the settings were left out");
    assert_eq!(after.checkpoints.len(), 1, "the checkpoint is in");
    assert_eq!(after.collections, before.collections);

    let shape = leaving(&world, None, 20);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape)).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    match prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
    {
        Err(RestoreError::Recovery(error))
            if matches!(*error, RecoveryError::BundleTooLarge { .. }) => {}
        other => panic!("too large with or without the settings: {other:?}"),
    }
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);
}

/// KR-REQ-20.17: a checkpoint that was written without the settings, whose answer never came, is
/// told as written without them when the next read finds it recorded: the settings are out of the
/// bundle, and the person is told so. Where the settings are still in the bundle the next read
/// finds, it is told as it always was.
#[tokio::test]
async fn a_lost_answer_on_a_checkpoint_that_left_the_settings_out_still_says_so() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let member = Bytes::new(vec![0x5a; 1024]);

    let shape = leaving(&world, Some(&member), 20);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape)).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.loses_the_answer.lock().expect("loses") = Some(ErrorCode::OutcomeUnknown);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("settled by reading");
    assert!(
        matches!(recorded, CheckpointRecorded::WrittenWithoutSettings { .. }),
        "{recorded:?}"
    );
    assert_eq!(*bundle.writes.lock().expect("writes"), 1, "written once");
    let after = bundle_held(&world, &source);
    assert_eq!(after.device_settings, None, "the settings were left out");
    assert_eq!(after.checkpoints.len(), 1, "the checkpoint is in");

    // With room for both, the lost answer leaves the settings where they were: nothing to say.
    let shape = Shape {
        device_settings: Some(member.clone()),
        ..Shape::default()
    };
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape)).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.loses_the_answer.lock().expect("loses") = Some(ErrorCode::OutcomeUnknown);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("settled by reading");
    assert!(
        matches!(recorded, CheckpointRecorded::AlreadyThere),
        "{recorded:?}"
    );
    assert_eq!(bundle_held(&world, &source).device_settings, Some(member));
}

/// KR-REQ-20.17: a checkpoint written without the settings whose answer the service gave as a
/// refusal for now, after it applied the write, is told as written without them too: the pause the
/// policy gives passes, the next read finds the checkpoint recorded, and the settings are still out
/// of the bundle. This is the branch of a service that refused for now, beside the one of a service
/// that could not say.
#[tokio::test(start_paused = true)]
async fn a_checkpoint_that_left_the_settings_out_and_was_refused_for_now_still_says_so() {
    assert!(
        matches!(HostWord::of(ErrorCode::RateLimited), HostWord::Transient),
        "the code is one the service gives for now"
    );
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let member = Bytes::new(vec![0x5a; 1024]);

    let shape = leaving(&world, Some(&member), 20);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape)).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.loses_the_answer.lock().expect("loses") = Some(ErrorCode::RateLimited);
    let started = tokio::time::Instant::now();
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("settled by reading");
    assert!(
        matches!(recorded, CheckpointRecorded::WrittenWithoutSettings { .. }),
        "{recorded:?}"
    );
    assert!(
        started.elapsed() >= RETRY_BACKOFF_MIN,
        "the pause the policy gives was taken"
    );
    assert_eq!(*bundle.writes.lock().expect("writes"), 1, "written once");
    let after = bundle_held(&world, &source);
    assert_eq!(after.device_settings, None, "the settings were left out");
    assert_eq!(after.checkpoints.len(), 1, "the checkpoint is in");
}

/// KR-REQ-24.16: a checkpoint write the service refuses for now, or cannot say the outcome of, is
/// made again after the bundle is read again, and the service's definite word ends the call. The
/// three are told apart by the retry category of the code, every code, as every other place that
/// settles a send tells them. A write whose outcome is unknown is made again at once, since the
/// next read settles it; one the service refused for now is made again after the pause the retry
/// policy gives, and the pauses are not waited for when the clock is stopped: the case reads the
/// time the call slept.
#[tokio::test(start_paused = true)]
async fn a_checkpoint_write_the_service_does_not_take_for_now_is_made_again() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    for code in ErrorCode::ALL {
        let source = Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed),
        );
        let prepared = restore(&world, &source, None).await.expect("a restore");
        let bundle = Bundle::over(&source);
        *bundle.refuses_with.lock().expect("refuses") = Some(*code);
        let started = tokio::time::Instant::now();
        let recorded = prepared
            .record_checkpoint(&bundle, TimestampMs::new(9_000))
            .await;
        let slept = started.elapsed();
        match HostWord::of(*code) {
            HostWord::Definite => {
                assert!(
                    matches!(&recorded, Err(RestoreError::Read(error)) if error.code() == *code),
                    "{code:?}: a definite word ends the call"
                );
                assert_eq!(*bundle.writes.lock().expect("writes"), 1, "{code:?}");
                assert!(bundle_held(&world, &source).checkpoints.is_empty());
                assert!(slept.is_zero(), "{code:?}: it ends at once");
            }
            HostWord::Unknown => {
                assert!(
                    matches!(recorded, Ok(CheckpointRecorded::Written { .. })),
                    "{code:?}: the write is made again"
                );
                assert_eq!(*bundle.writes.lock().expect("writes"), 2, "{code:?}");
                assert_eq!(bundle_held(&world, &source).checkpoints.len(), 1);
                assert!(
                    slept.is_zero(),
                    "{code:?}: the next read settles it, at once"
                );
            }
            HostWord::Transient => {
                assert!(
                    matches!(recorded, Ok(CheckpointRecorded::Written { .. })),
                    "{code:?}: the write is made again"
                );
                assert_eq!(*bundle.writes.lock().expect("writes"), 2, "{code:?}");
                assert_eq!(bundle_held(&world, &source).checkpoints.len(), 1);
                assert!(
                    slept >= RETRY_BACKOFF_MIN,
                    "{code:?}: a service that refused for now is not asked again at once"
                );
            }
        }
    }
}

/// KR-REQ-24.16: the pause before another write is taken only when another write follows it. Three
/// writes that found the bundle moved on and a fourth that the service refused for now end the call
/// with that refusal at once.
#[tokio::test(start_paused = true)]
async fn a_refusal_for_now_at_the_last_attempt_is_not_followed_by_a_pause() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.conflicts.lock().expect("conflicts") = 3;
    *bundle.keeps_refusing_with.lock().expect("keeps refusing") = Some(ErrorCode::RateLimited);
    let started = tokio::time::Instant::now();
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await;
    assert!(
        matches!(&recorded, Err(RestoreError::Read(error)) if error.code() == ErrorCode::RateLimited),
        "the call ends with the service's word"
    );
    assert_eq!(*bundle.writes.lock().expect("writes"), 4);
    assert!(started.elapsed().is_zero(), "no pause before the end");
}

/// KR-REQ-24.16: a service that refuses every write for now is asked four times, with the policy's
/// pauses between, and the call ends with its refusal; one that cannot say what became of every
/// write is asked four times at once, and the call ends with that.
#[tokio::test(start_paused = true)]
async fn a_service_that_keeps_refusing_for_now_is_asked_four_times_with_pauses_between() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    for (code, paused) in [
        (ErrorCode::RateLimited, true),
        (ErrorCode::StorageUnavailable, true),
        (ErrorCode::OutcomeUnknown, false),
    ] {
        let source = Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed),
        );
        let prepared = restore(&world, &source, None).await.expect("a restore");
        let bundle = Bundle::over(&source);
        *bundle.keeps_refusing_with.lock().expect("keeps refusing") = Some(code);
        let started = tokio::time::Instant::now();
        let recorded = prepared
            .record_checkpoint(&bundle, TimestampMs::new(9_000))
            .await;
        let slept = started.elapsed();
        assert!(
            matches!(&recorded, Err(RestoreError::Read(error)) if error.code() == code),
            "{code:?}: the call ends with the service's word"
        );
        assert_eq!(*bundle.writes.lock().expect("writes"), 4, "{code:?}");
        if paused {
            assert!(
                slept >= RETRY_BACKOFF_MIN * 3,
                "{code:?}: three pauses between four writes, {slept:?}"
            );
        } else {
            assert!(slept.is_zero(), "{code:?}: no pause {slept:?}");
        }
    }
}

/// KR-REQ-24.16: a checkpoint is never lowered and never recorded over another manifest of the
/// same generation. A restore that another restore overtakes finds the bundle already past it.
#[tokio::test]
async fn a_checkpoint_is_not_lowered_and_not_recorded_over_another_manifest_of_its_generation() {
    let world = World::new();
    let members = honest_members();
    let sealed = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");

    // Another restore recorded a newer generation of the archive after this one read the bundle.
    let newer = world.seal(6, &members);
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&newer)),
        ..Shape::default()
    }));
    // The bundle is changed once the restore has read it, so that the restore's write is the first
    // thing to meet the newer bundle; it reads again and finds nothing to record.
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("nothing to record");
    assert!(matches!(recorded, CheckpointRecorded::AlreadyThere));
    let held = bundle_held(&world, &source);
    assert_eq!(
        held.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [checkpoint_of(&newer)],
        "the higher checkpoint stays"
    );

    // The bundle this restore read records generation 6, and it restores generation 4 on the
    // person's word. A later read that finds an older authentic bundle, one that records none, is
    // not written on, because the write would put the checkpoint at 4 where this restore saw 6.
    // The service replaces the bundle after the restore read it.
    let known = world.seal(6, &members);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                checkpoint: Some(checkpoint_of(&known)),
                ..Shape::default()
            }),
        )
        .publishing(&sealed)
        .honouring_the_hold(),
    );
    let prepared = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(4)),
        &Held::Absent,
    )
    .await
    .expect("the named generation restores");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape::default()));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("the bundle went back");
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 6 })
    ));
    assert!(
        bundle_held(&world, &source).checkpoints.is_empty(),
        "nothing was written over the bundle the service now holds"
    );

    // The bundle also records another archive, at generation 9, and this restore of the first at
    // generation 8 reads it. A later read that finds an older authentic bundle in which that other
    // archive stands at 5 is not written on either: the write would lower a checkpoint of an
    // archive the restore was not about.
    let other = another_archive_at(9);
    let lower = another_archive_at(5);
    let current = world.seal(8, &members);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                checkpoint: Some(checkpoint_of(&sealed)),
                more_checkpoints: vec![other.clone()],
                ..Shape::default()
            }),
        )
        .publishing(&current),
    );
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&sealed)),
        more_checkpoints: vec![lower],
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("another archive's checkpoint went back");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 9 })
    ));
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);

    // A bundle of an older revision than the one the restore read is not written on, whatever it
    // records.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape {
        revision: Some(2),
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("an older revision");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::BundleWentBackToAnOlderRevision { newest: 3 })
    ));
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);

    // Another restore recorded this very generation with another encrypted manifest.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let second = world.seal(4, &[("host/configuration.json", b"{}".to_vec())]);
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&second)),
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("a disagreement");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointDisagrees { generation: 4 })
    ));
    assert_eq!(
        bundle_held(&world, &source)
            .checkpoints
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        [checkpoint_of(&second)],
        "the bundle is left as the other restore wrote it"
    );
}

/// The checkpoint of an archive the restore is not about, at the generation given.
fn another_archive_at(generation: u64) -> ArchiveCheckpoint {
    ArchiveCheckpoint {
        archive_id: ArchiveId::new(id(0x42)),
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: Digest256::from_bytes(
            [u8::try_from(generation).expect("few"); 32],
        ),
        verified_at_ms: TimestampMs::new(4_000),
    }
}

/// A restore that read revision 5 of the bundle, which records the checkpoints `read_first`, after
/// which another device wrote revision 6, which records `then`. It returns the restore, the
/// service, the bytes of revision 5 as the service first served them, and a writer whose first
/// write meets whatever the test puts in `meanwhile`.
async fn a_restore_that_revision_6_overtook(
    world: &World,
    read_first: &[ArchiveCheckpoint],
    then: &[ArchiveCheckpoint],
) -> (
    kr_client::recovery::PreparedRestore,
    Arc<Scripted>,
    Vec<u8>,
    Bundle,
) {
    let sealed = world.seal(4, &honest_members());
    let first = world.bundle(&Shape {
        revision: Some(5),
        more_checkpoints: read_first.to_vec(),
        ..Shape::default()
    });
    let source = Arc::new(Scripted::serving(world, first).publishing(&sealed));
    let prepared = restore(world, &source, None).await.expect("a restore");
    let revision_5 = source.sealed_bundle();
    source.replace_bundle(world.bundle(&Shape {
        revision: Some(6),
        more_checkpoints: then.to_vec(),
        ..Shape::default()
    }));
    let writer = Bundle::over(&source);
    (prepared, source, revision_5, writer)
}

/// KR-REQ-24.16: what any read of the bundle showed holds every read after it. A write that meets
/// a conflict reads again, and a service that answers with revision 5 again, at a later place,
/// after an attempt read revision 6, is not written on: the write would put back the older bundle
/// and drop what revision 6 held.
#[tokio::test]
async fn a_retry_does_not_write_on_a_bundle_older_than_one_an_attempt_read() {
    let world = World::new();
    let (prepared, source, revision_5, writer) = a_restore_that_revision_6_overtook(
        &world,
        &[another_archive_at(5)],
        &[another_archive_at(9)],
    )
    .await;
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_5.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("revision 5 is older than the revision 6 an attempt read");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::BundleWentBackToAnOlderRevision { newest: 6 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_5,
        "nothing was written over what the service holds"
    );
}

/// KR-REQ-24.16: a checkpoint an attempt read is held on its own, whatever the revision: a retry
/// that finds a newer revision than any attempt read, with another archive's checkpoint lower than
/// one an attempt read, is not written on either.
#[tokio::test]
async fn a_retry_does_not_seal_a_checkpoint_below_one_an_attempt_read() {
    let world = World::new();
    let (prepared, source, _, writer) = a_restore_that_revision_6_overtook(
        &world,
        &[another_archive_at(5)],
        &[another_archive_at(9)],
    )
    .await;
    let revision_7 = world.bundle(&Shape {
        revision: Some(7),
        more_checkpoints: vec![another_archive_at(5)],
        ..Shape::default()
    });
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_7.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("the other archive's checkpoint went back");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 9 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_7,
        "nothing was written over what the service holds"
    );
}

/// KR-REQ-24.16: the manifest a checkpoint was read with at a generation is not replaced by
/// another when a later read records two manifests for that generation. The retry that finds one
/// of the two only is not written on, whichever of them it is.
#[tokio::test]
async fn a_retry_does_not_take_another_manifest_for_a_generation_an_attempt_read() {
    let world = World::new();
    let first = ArchiveCheckpoint {
        encrypted_manifest_hash: Digest256::from_bytes([6; 32]),
        ..another_archive_at(5)
    };
    let (prepared, source, _, writer) = a_restore_that_revision_6_overtook(
        &world,
        std::slice::from_ref(&first),
        &[another_archive_at(5), first.clone()],
    )
    .await;
    let revision_7 = world.bundle(&Shape {
        revision: Some(7),
        more_checkpoints: vec![another_archive_at(5)],
        ..Shape::default()
    });
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_7.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("another manifest for generation 5");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointDisagrees { generation: 5 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_7,
        "nothing was written over what the service holds"
    );
}

/// An export read back as a source, in bytes, as a file would hold it.
fn reread(export: &OfflineExport) -> Arc<ExportSource> {
    let bytes = export.to_canonical_bytes().expect("canonical bytes");
    Arc::new(ExportSource::new(
        OfflineExport::from_canonical_slice(&bytes).expect("the export reads back"),
    ))
}

/// KR-REQ-20.18: an archive exports as one file of ciphertext, and a host that holds nothing but the
/// kit and that file restores the same members as one that asks the service. The file holds no
/// member name or content in the clear, and everything about it is checked on the way back: the
/// kit's checksum, the bundle under the kit's key, the publication's signature and the manifest.
///
/// KR-REQ-20.17, the export of an archive, in part: the file adds no byte to what the service holds.
/// Its format line is the one this release writes, its origin is the kit's and its archive is the
/// one restored; the sealed bundle in it equals the one the service holds, the publication and the
/// manifest object equal the service's, and the member objects it carries are exactly the ones the
/// archive has, each once, each equal to the bytes the service holds under its identifier. Not shown
/// here: what the archive itself carries (the daemon's production case reads the host's), the
/// contents of the sealed bundle (the companion's export case opens the one it writes), or the
/// other data paths of backup and recovery material.
#[tokio::test]
async fn an_archive_exports_as_one_file_that_restores_with_only_the_kit() {
    let world = World::new();
    let members = honest_members();
    let sealed = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let export = prepared.export().await.expect("an export");
    assert_eq!(export.format, OFFLINE_EXPORT_FORMAT);
    assert_eq!(
        export.service_origin, ORIGIN,
        "the origin is the one the kit names"
    );
    assert_eq!(
        export.encrypted_bundle.as_slice(),
        source.sealed_bundle().as_slice(),
        "the bundle is the one the service holds"
    );
    let archived = export.archive.0.as_ref().expect("an archive");
    assert_eq!(archived.archive_id, archive(), "the archive restored");
    assert_eq!(archived.publication, sealed.publication);
    assert_eq!(
        archived.encrypted_manifest.as_slice(),
        sealed.objects[&sealed.manifest_object].as_slice(),
        "the manifest object is the one the service holds"
    );
    // Each member object of the archive once and no other: a repeated object with another missing
    // would keep the count.
    let carried: Vec<BackupObjectId> = archived
        .objects
        .iter()
        .map(|object| object.object_id)
        .collect();
    let once: BTreeSet<BackupObjectId> = carried.iter().copied().collect();
    assert_eq!(once.len(), carried.len(), "a member object appears twice");
    let held: BTreeSet<BackupObjectId> = sealed
        .objects
        .keys()
        .copied()
        .filter(|object| *object != sealed.manifest_object)
        .collect();
    assert_eq!(held.len() + 1, sealed.objects.len());
    assert_eq!(
        once, held,
        "every member object the archive has, and no other"
    );
    for object in &archived.objects {
        assert_eq!(
            object.bytes.as_slice(),
            sealed.objects[&object.object_id].as_slice(),
            "a member object is the one the service holds"
        );
    }
    let bytes = export.to_canonical_bytes().expect("canonical bytes");
    for clear in [
        b"what the session did".as_slice(),
        b"host/configuration.json",
        b"sessions/",
    ] {
        assert!(
            !bytes.windows(clear.len()).any(|window| window == clear),
            "an offline export carries no member name or content in the clear"
        );
    }

    // The file is the whole source: with no service in reach, the kit restores the same members.
    let file = reread(&export);
    let from_file = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&file) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect("a restore from the file");
    assert_eq!(from_file.plan().generation.get(), 4);
    assert_eq!(
        from_file.plan().members.len(),
        prepared.plan().members.len()
    );
    for planned in &prepared.plan().members {
        let asked = prepared.member(planned.object_id).await.expect("a member");
        let held = from_file.member(planned.object_id).await.expect("a member");
        assert_eq!(held.expose(), asked.expose());
    }
    assert!(!from_file.plan().standing.checkpoint_available());
}

/// KR-REQ-20.18: a file that is not what its reader trusts is refused by name, and restores
/// nothing: another format, a bundle sealed for another kit, an archive the bundle does not name, an
/// object whose bytes were changed, and an archive too large to be one file.
#[tokio::test]
async fn an_export_that_is_not_what_it_claims_is_refused_by_name() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let export = restore(&world, &source, None)
        .await
        .expect("a restore")
        .export()
        .await
        .expect("an export");

    // Another format.
    let mut other = export.clone();
    other.format = "kalareach-offline-export/2".to_owned();
    let bytes = other.to_canonical_bytes().expect("canonical bytes");
    assert!(matches!(
        OfflineExport::from_canonical_slice(&bytes),
        Err(RecoveryError::UnsupportedExport)
    ));
    // Not an export at all.
    assert!(OfflineExport::from_canonical_slice(b"not an export").is_err());

    // A bundle sealed for another kit does not authenticate under this one.
    let stranger = World::new();
    let refused = FilesRestore::prepare(
        stranger.kit(),
        reread(&export) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect_err("another kit");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause) if matches!(**cause, RecoveryError::BundleNotAuthentic)
    ));

    // An archive the bundle does not name.
    let unlisted = ArchiveId::new(id(0x99));
    assert!(matches!(
        FilesRestore::prepare(
            world.kit(),
            reread(&export) as _,
            Some(unlisted),
            None,
            &Held::Absent
        )
        .await
        .expect_err("not listed"),
        RestoreError::ArchiveNotListed
    ));

    // An object whose bytes were changed in the file is not a file.
    let mut changed = export.clone();
    let archive = changed.archive.0.as_mut().expect("an archive");
    let first = &mut archive.objects[0];
    let mut bytes = first.bytes.as_slice().to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    first.bytes = kr_protocol::scalars::Bytes::new(bytes);
    let object = first.object_id;
    let prepared = FilesRestore::prepare(
        world.kit(),
        reread(&changed) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect("the plan reads the manifest, which is whole");
    assert!(matches!(
        prepared.member(object).await,
        Err(RestoreError::Member(_))
    ));

    // An object the service serves other than the signed manifest names is not copied into a file.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    source.corrupt(prepared.plan().members[0].object_id);
    assert!(matches!(
        prepared.export().await,
        Err(RestoreError::Member(_))
    ));

    // An archive too large to be one file is said so, and nothing is read.
    let large = world.seal_declared(
        4,
        &[(
            "sessions/0a1b2c3d-0000-4000-8000-000000000001.json",
            300 << 20,
        )],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&large));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.export().await,
        Err(RestoreError::TooLargeToExport { .. })
    ));
    assert_eq!(source.object_reads(), 1, "only the manifest was read");
}

/// KR-REQ-20.18: the bundle alone exports too, after it has authenticated under the kit; a restore
/// from it has no archive to open and says so, and the archives it names are listed with the newest
/// generation of each.
#[tokio::test]
async fn the_bundle_exports_alone_and_the_archives_it_names_are_listed() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));

    let listed = FilesRestore::archives(world.kit(), Arc::clone(&source) as _, &Held::Absent)
        .await
        .expect("the archives");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].archive_id, archive());
    assert!(matches!(
        &listed[0].newest,
        CandidateState::Newest(newest) if newest.generation.get() == 4
    ));

    let export = FilesRestore::export_bundle(world.kit(), Arc::clone(&source) as _)
        .await
        .expect("the bundle exports");
    assert!(export.archive.0.is_none());
    assert!(matches!(
        FilesRestore::prepare(world.kit(), reread(&export) as _, None, None, &Held::Absent)
            .await
            .expect_err("no archive in the file"),
        RestoreError::NoGeneration
    ));
    // Not a kit this bundle opens for: the export is refused at the bundle.
    assert!(
        FilesRestore::export_bundle(World::new().kit(), source as _)
            .await
            .is_err()
    );
}

/// KR-REQ-24.16: the archive that is opened is the one whose publication was verified. Another
/// genuine generation of the same collection, served under the manifest object the verified
/// publication names, is not it.
#[tokio::test]
async fn a_second_genuine_manifest_served_for_the_verified_publication_does_not_open() {
    let world = World::new();
    let members = honest_members();
    let verified = world.seal(4, &members);
    let later = world.seal(6, &members);
    let swapped = Sealed {
        publication: verified.publication.clone(),
        objects: later.objects.clone(),
        manifest_object: verified.manifest_object,
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&swapped));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Archive(_)
    ));
    assert_eq!(source.object_reads(), 1, "only the manifest was read");
}

/// A publication that declares a manifest longer than any manifest is, is refused before a byte is
/// read.
#[tokio::test]
async fn a_manifest_longer_than_any_manifest_is_refused_before_it_is_read() {
    let world = World::new();
    let mut sealed = world.seal(4, &honest_members());
    let mut payload = sealed.publication.payload.clone();
    payload.descriptor.encrypted_manifest.encrypted_len = U64::new(1 << 40);
    for wrap in &mut payload.descriptor.manifest_key_wraps {
        wrap.context.encrypted_object_hash =
            payload.descriptor.encrypted_manifest.encrypted_object_hash;
    }
    sealed.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::ManifestTooLarge { .. }
    ));
    assert_eq!(source.object_reads(), 0);
}

/// Who the kit, the origin and the locator say a bundle belongs to.
#[tokio::test]
async fn a_bundle_served_for_another_kit_locator_or_origin_does_not_open() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let serve = |bundle: Vec<u8>, anywhere: bool| {
        let mut source = Scripted::serving(&world, bundle).publishing(&sealed);
        source.anywhere = anywhere;
        Arc::new(source)
    };

    // A kit of another seed meets the owner's bundle.
    let other = World {
        seed: RecoverySeed::generate().expect("a seed"),
        locator: world.locator.clone(),
        writer: AuthorisationKeyPair::generate().expect("a key"),
        producer: StoredEnvelopeKeyPair::generate().expect("a key"),
    };
    let source = serve(world.bundle(&Shape::default()), false);
    let refused = FilesRestore::prepare(
        other.kit(),
        Arc::clone(&source) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle sealed for another locator, served at the kit's.
    let source = serve(
        world.bundle(&Shape {
            sealed_at_locator: Some(fresh_locator().expect("a locator")),
            ..Shape::default()
        }),
        false,
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle sealed for another origin, served as this one's.
    let source = serve(
        world.bundle(&Shape {
            sealed_for_origin: Some(OTHER_ORIGIN),
            ..Shape::default()
        }),
        false,
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle at no locator the kit names is an absent bundle, kept apart from a bad one.
    let mut source = Scripted::serving(&world, world.bundle(&Shape::default()));
    source.bundle = Mutex::new(Some((fresh_locator().expect("a locator"), Vec::new())));
    assert!(matches!(
        restore(&world, &Arc::new(source), None)
            .await
            .expect_err("absent"),
        RestoreError::BundleAbsent
    ));
}

/// The kit has to name the service this host is configured for, and a mistyped kit stops first.
#[tokio::test]
async fn a_kit_that_names_no_service_this_host_reaches_is_refused_by_name() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let self_hosted = world
        .seed
        .to_kit(vec![OTHER_ORIGIN.to_owned()], world.locator.clone());
    let refused = FilesRestore::prepare(
        self_hosted,
        Arc::clone(&source) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect_err("refused");
    assert!(matches!(refused, RestoreError::OriginNotConfigured));
    assert!(
        !source.asked().iter().any(|call| call == "bundle"),
        "no locator left this process"
    );

    // A spelling of the configured origin other than the canonical one is another service's name:
    // the bundle key is derived from the kit's text byte for byte.
    let respelled = world.seed.to_kit(
        vec!["https://Reach.Kala.To".to_owned()],
        world.locator.clone(),
    );
    let refused = FilesRestore::prepare(
        respelled,
        Arc::clone(&source) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect_err("refused");
    assert!(matches!(refused, RestoreError::OriginNotConfigured));

    // A locator that is not an identifier in its canonical spelling is wrong before it is sent.
    let mut odd = world.kit();
    odd.bundle_locator = "not/an-identifier".to_owned();
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let refused = FilesRestore::prepare(odd, Arc::clone(&source) as _, None, None, &Held::Absent)
        .await
        .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::MalformedKit { .. })
    ));
    assert!(!source.asked().iter().any(|call| call == "bundle"));

    // A mistyped kit stops before the service is asked anything.
    let mut mistyped = world.kit();
    mistyped.seed_checksum = kr_protocol::scalars::Bytes::new(vec![0; 4]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let refused = FilesRestore::prepare(
        mistyped,
        Arc::clone(&source) as _,
        None,
        None,
        &Held::Absent,
    )
    .await
    .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::MistypedKit)
    ));
    assert!(source.asked().is_empty());

    // A host with no usable sign-in is told so, and nothing is sent.
    let mut signed_out = Scripted::serving(&world, world.bundle(&Shape::default()));
    signed_out.service.sign_in = SourceSignIn::Unusable(SignInCause::SignedOut);
    let signed_out = Arc::new(signed_out);
    assert!(matches!(
        restore(&world, &signed_out, None)
            .await
            .expect_err("refused"),
        RestoreError::NotSignedIn { .. }
    ));
    assert!(signed_out.asked().is_empty());
}

/// KR-REQ-20.19: the retrieval policy is the configured service's, the managed service's origin as
/// the host treats it being the managed account and any other a service the owner runs. A host with
/// no usable sign-in is refused naming the sign-in of that policy, with what is wrong and what to
/// do, before the kit's service is compared with the configured one and before anything is sent.
#[tokio::test]
async fn a_refusal_for_an_unusable_sign_in_names_the_sign_in_of_the_configured_services_policy() {
    assert_eq!(
        RetrievalPolicy::for_origin(ORIGIN, ORIGIN),
        RetrievalPolicy::Account
    );
    assert_eq!(
        RetrievalPolicy::for_origin(OTHER_ORIGIN, ORIGIN),
        RetrievalPolicy::SelfHosted
    );
    let causes = [
        SignInCause::SignedOut,
        SignInCause::Ended,
        SignInCause::Waiting,
        SignInCause::WithoutScope,
        SignInCause::NotRenewed,
    ];
    let account = [
        "no account is signed in on this host. Sign this host in with `kr account sign-in`.",
        "the service ended the sign-in on this host. Sign this host in with `kr account sign-in`.",
        "a sign-in on this host is waiting to finish. Finish the sign-in at the address `kr \
         account sign-in` printed.",
        "the account signed in on this host lacks the backup.write scope. Sign this host in again \
         with `kr account sign-in`, which asks for backup storage because storage.origin is set.",
        "this host could not renew the token of the account signed in on this host. This host asks \
         again by itself. Check that the account service is reachable, or sign this host in again \
         with `kr account sign-in`.",
    ];
    let self_hosted = [
        "this host is signed in to no account at the storage service its storage.origin names. \
         Sign this host in with `kr account sign-in --storage`.",
        "the service ended the sign-in on this host. Sign this host in with `kr account sign-in \
         --storage`.",
        "a sign-in on this host is waiting to finish. Finish the sign-in at the address `kr \
         account sign-in --storage` printed.",
        "the account signed in on this host lacks the backup.write scope. Sign this host in again \
         with `kr account sign-in --storage`, which asks for backup storage.",
        "this host could not renew the token of the account signed in on this host. This host asks \
         again by itself. Check that the storage service is reachable, or sign this host in again \
         with `kr account sign-in --storage`.",
    ];
    let world = World::new();
    // The kit names a service the host is not configured for: the refusal for the sign-in comes
    // first, and the control is that a usable sign-in then gets the refusal by name.
    let kit = world
        .seed
        .to_kit(vec![OTHER_ORIGIN.to_owned()], world.locator.clone());
    for (managed_origin, policy, sentences) in [
        (ORIGIN, RetrievalPolicy::Account, account),
        (
            "https://managed.example",
            RetrievalPolicy::SelfHosted,
            self_hosted,
        ),
    ] {
        for (cause, sentence) in causes.into_iter().zip(sentences) {
            let mut source = Scripted::serving(&world, world.bundle(&Shape::default()));
            source.service.managed_origin = managed_origin.to_owned();
            source.service.sign_in = SourceSignIn::Unusable(cause);
            let source = Arc::new(source);
            let refused = FilesRestore::prepare(
                kit.clone(),
                Arc::clone(&source) as _,
                None,
                None,
                &Held::Absent,
            )
            .await
            .expect_err("refused");
            let RestoreError::NotSignedIn {
                cause: named,
                policy: named_policy,
                ..
            } = refused
            else {
                panic!("a sign-in that cannot be used is refused as one: {refused:?}");
            };
            assert_eq!(named, cause);
            assert_eq!(named_policy, policy);
            assert_eq!(
                format!(
                    "{}. {}",
                    named.why(named_policy),
                    named.remedy(named_policy)
                ),
                sentence
            );
            assert!(source.asked().is_empty(), "nothing was sent");
        }
    }
    let usable = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    let refused = FilesRestore::prepare(kit, Arc::clone(&usable) as _, None, None, &Held::Absent)
        .await
        .expect_err("refused");
    assert!(matches!(refused, RestoreError::OriginNotConfigured));
}

/// An explicit archive has to be one the bundle lists at the configured origin, and without one the
/// restore will not guess among several.
#[tokio::test]
async fn the_archive_is_one_the_authenticated_bundle_lists_at_the_configured_service() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let elsewhere = ArchiveId::new(id(0x12));
    let two = vec![
        collection(ORIGIN, "collection-1", archive()),
        collection(OTHER_ORIGIN, "collection-2", elsewhere),
    ];
    let shape = || Shape {
        collections: Some(two.clone()),
        ..Shape::default()
    };

    // The archive the bundle lists under another origin is refused before any generation request.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, Some(elsewhere))
            .await
            .expect_err("refused"),
        RestoreError::ArchiveNotListed
    ));
    assert!(
        !source
            .asked()
            .iter()
            .any(|call| call.starts_with("generation")),
        "no generation was asked for"
    );
    // The one it lists at the configured origin is the default, and may be named.
    assert!(restore(&world, &source, None).await.is_ok());
    assert!(restore(&world, &source, Some(archive())).await.is_ok());

    // An archive the bundle does not list at all.
    assert!(matches!(
        restore(&world, &source, Some(ArchiveId::new(id(0x13))))
            .await
            .expect_err("refused"),
        RestoreError::ArchiveNotListed
    ));

    // Nothing listed here.
    let source = Arc::new(Scripted::serving(
        &world,
        world.bundle(&Shape {
            collections: Some(vec![collection(OTHER_ORIGIN, "collection-2", elsewhere)]),
            ..Shape::default()
        }),
    ));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoArchive
    ));

    // Several at the configured origin: the restore lists each with its newest generation, its
    // signed time and its writer, and picks none.
    let second = ArchiveId::new(id(0x14));
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                collections: Some(vec![
                    collection(ORIGIN, "collection-1", archive()),
                    collection(ORIGIN, "collection-3", second),
                ]),
                ..Shape::default()
            }),
        )
        .publishing(&sealed),
    );
    let candidates_of = |error: RestoreError| match error {
        RestoreError::SeveralArchives { count, candidates } => {
            assert_eq!(count, 2);
            candidates
        }
        other => panic!("several archives are listed, not chosen: {other:?}"),
    };
    let candidates = candidates_of(restore(&world, &source, None).await.expect_err("refused"));
    let held = candidates
        .iter()
        .find(|candidate| candidate.archive_id == archive())
        .expect("the first archive");
    let CandidateState::Newest(newest) = &held.newest else {
        panic!("the first archive has a generation");
    };
    assert_eq!(newest.generation.get(), 4);
    assert_eq!(newest.published_at_ms.get(), 5_000);
    assert_eq!(newest.writer, world.writer.key_id());
    let none = candidates
        .iter()
        .find(|candidate| candidate.archive_id == second)
        .expect("the second archive");
    assert!(
        matches!(none.newest, CandidateState::Nothing),
        "the service holds nothing of it"
    );

    // A candidate whose publication a restore would refuse is shown as refused, apart from one the
    // service holds nothing of.
    let impostor = AuthorisationKeyPair::generate().expect("a key");
    let forged = world.seal_with(
        4,
        &honest_members(),
        &impostor,
        &impostor,
        &world.recipients(),
    );
    source
        .generations
        .lock()
        .expect("generations")
        .insert(second, forged.publication.clone());
    let candidates = candidates_of(restore(&world, &source, None).await.expect_err("refused"));
    let other = candidates
        .iter()
        .find(|candidate| candidate.archive_id == second)
        .expect("the second archive");
    assert!(matches!(other.newest, CandidateState::Refused(_)));
}

/// KR-REQ-24.16 and 20.17: a restore returns data only. What a member is called decides what a
/// restore does with it, and nothing it is not told about is written.
#[tokio::test]
async fn members_a_restore_never_puts_back_and_names_it_does_not_know_are_refused() {
    let world = World::new();
    let session = "sessions/0a1b2c3d-0000-4000-8000-000000000001.json";
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            (session, stored),
            ("keys/endpoint/device-1", stored),
            ("keys/control/host", stored),
            ("keys/notification-preview/device-1", stored),
            ("keys/collection/settings", stored),
            ("authority/grants", stored),
            ("recovery/seed", stored),
            ("grants/revoked/g-1", stored),
            ("notes/readme.txt", stored),
            ("sessions/../../etc/passwd", stored),
            ("host/configuration.json", stored),
            ("host/configuration.json", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    let verdicts: Vec<_> = plan
        .members
        .iter()
        .map(|member| member.verdict.clone())
        .collect();

    assert!(matches!(
        &verdicts[0],
        MemberVerdict::Restore {
            role: MemberRole::Session,
            ..
        }
    ));
    let kinds: Vec<Material> = verdicts[1..8]
        .iter()
        .map(|verdict| match verdict {
            MemberVerdict::Refused(MemberRefusal::Kind { material, .. }) => *material,
            other => panic!("a kind the table refuses was {other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            Material::EndpointPrivateKey,
            Material::ControlSigningPrivateKey,
            Material::NotificationPreviewPrivateKey,
            Material::SyncCollectionKey,
            Material::HostGrantAuthority,
            Material::RecoverySeed,
            Material::Grant { revoked: true },
        ]
    );
    // A name the convention does not know, and a traversal, are refused as unknown.
    assert!(matches!(
        verdicts[8],
        MemberVerdict::Refused(MemberRefusal::UnknownKind)
    ));
    assert!(matches!(
        verdicts[9],
        MemberVerdict::Refused(MemberRefusal::UnknownKind)
    ));
    // Two members with one name are both refused.
    assert!(matches!(
        verdicts[10],
        MemberVerdict::Refused(MemberRefusal::Duplicate)
    ));
    assert!(matches!(
        verdicts[11],
        MemberVerdict::Refused(MemberRefusal::Duplicate)
    ));
    assert_eq!(plan.restored().count(), 1, "only the session is written");
    // No name the archive supplied reaches a file name.
    for (_, file, _) in plan.restored() {
        assert!(!file.contains('/') && !file.contains(".."), "{file}");
    }
}

/// A member, the members together and the number of members have a bound, and a member over its
/// bound is listed with the number that broke it and is not read.
#[tokio::test]
async fn members_over_their_bounds_are_refused_in_the_plan_and_never_read() {
    let world = World::new();
    let stored = |plaintext: u64| {
        let blocks = plaintext.div_ceil(1 << 20).max(1);
        24 + plaintext + blocks * 17
    };
    let cap = kr_crypto::backup::MAX_SESSION_MEMBER_BYTES;
    let name = |n: u32| format!("sessions/0a1b2c3d-0000-4000-8000-{n:012}.json");

    // At the cap restores; one byte over does not.
    let names: Vec<String> = (1..=8).map(name).collect();
    let sealed = world.seal_declared(
        4,
        &[
            (names[0].as_str(), stored(cap)),
            (names[1].as_str(), stored(cap + 1)),
            ("host/configuration.json", stored(1 << 20)),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert!(matches!(
        plan.members[0].verdict,
        MemberVerdict::Restore { .. }
    ));
    assert!(matches!(
        plan.members[1].verdict,
        MemberVerdict::Refused(MemberRefusal::OverMemberCap { size, cap: c }) if size == cap + 1 && c == cap
    ));
    assert!(matches!(
        plan.members[2].verdict,
        MemberVerdict::Restore { .. }
    ));
    assert_eq!(
        source.object_reads(),
        1,
        "only the manifest was read for the plan"
    );

    // A configuration over its own bound.
    let sealed = world.seal_declared(4, &[("host/configuration.json", stored((1 << 20) + 1))]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.plan().members[0].verdict,
        MemberVerdict::Refused(MemberRefusal::OverMemberCap { .. })
    ));

    // The total: members are admitted in manifest order until the next would pass it, and that
    // member and every later one are listed as refused.
    let total = kr_crypto::backup::MAX_RESTORED_BYTES;
    let each = cap;
    let fitting = usize::try_from(total / each).expect("a count");
    let many: Vec<String> = (1..=u32::try_from(fitting + 2).expect("a count"))
        .map(name)
        .collect();
    let members: Vec<(&str, u64)> = many
        .iter()
        .map(|name| (name.as_str(), stored(each)))
        .collect();
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert_eq!(plan.restored().count(), fitting);
    assert!(plan.restored_bytes() <= total);
    assert!(plan.members[fitting..].iter().all(|member| matches!(
        member.verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    )));

    // A stored length no object has.
    let sealed = world.seal_declared(4, &[("host/configuration.json", 30)]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.plan().members[0].verdict,
        MemberVerdict::Refused(MemberRefusal::BadStoredLength)
    ));

    // More members than an archive has: the whole archive is refused.
    let flood: Vec<String> = (1..=4097_u32).map(name).collect();
    let members: Vec<(&str, u64)> = flood
        .iter()
        .map(|name| (name.as_str(), stored(10)))
        .collect();
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::TooManyMembers {
            count: 4097,
            limit: 4096
        }
    ));
}

/// A corrupted object is an error, never a shorter file.
#[tokio::test]
async fn a_corrupted_manifest_or_member_is_an_error_and_not_a_file() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());

    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    source.corrupt(sealed.manifest_object);
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Archive(_)
    ));

    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let member = prepared.plan().members[0].object_id;
    source.corrupt(member);
    assert!(matches!(
        prepared.member(member).await,
        Err(RestoreError::Member(_))
    ));
    // The other member is untouched.
    assert!(
        prepared
            .member(prepared.plan().members[1].object_id)
            .await
            .is_ok()
    );
}

/// The record a restore leaves holds the plan and the refusals and none of the kit.
#[tokio::test]
async fn the_record_says_what_was_written_and_what_was_refused_and_holds_nothing_of_the_kit() {
    let world = World::new();
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            ("sessions/0a1b2c3d-0000-4000-8000-000000000001.json", stored),
            ("keys/control/host", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    let digest = plan.digest("env-1", b"/restore/a", "").expect("a digest");
    let written = vec![plan.members[0].object_id];
    let record = plan.record(&digest, &written, false).to_string();
    assert!(record.contains("kalareach-restore/1"));
    assert!(record.contains(&digest));
    assert!(record.contains("material_never_restored"));
    assert!(record.contains("session-0001.json"));
    let kit = world.kit();
    let seed_text = serde_json::to_string(&kit.seed).expect("the seed as the kit writes it");
    for secret in [world.locator.as_str(), seed_text.trim_matches('"')] {
        assert!(!record.contains(secret), "the record holds a kit value");
    }
    assert!(!format!("{prepared:?}").contains(&world.locator));
    // The kit and the context that reaches the bundle render without the locator, the seed or its
    // checksum, so a log line that carries one carries none of them.
    let context = kr_protocol::archive::RecoveryContext {
        service_origin: ORIGIN.to_owned(),
        bundle_locator: world.locator.clone(),
    };
    for shown in [format!("{kit:?}"), format!("{context:?}")] {
        assert!(!shown.contains(&world.locator), "{shown}");
        assert!(!shown.contains("checksum"), "{shown}");
    }
}

/// What a restore writes is a prefix of what fits: once one member would pass the total, it and
/// every member after it are refused, small ones included.
#[tokio::test]
async fn once_a_member_would_pass_the_total_every_later_member_is_refused() {
    let world = World::new();
    let stored = |plaintext: u64| 24 + plaintext + plaintext.div_ceil(1 << 20).max(1) * 17;
    let session = |n: u32| format!("sessions/0a1b2c3d-0000-4000-8000-{n:012}.json");
    let big = 190_u64 << 20;
    let names: Vec<String> = (1..=9).map(session).collect();
    let mut members: Vec<(&str, u64)> = names
        .iter()
        .map(|name| (name.as_str(), stored(big)))
        .collect();
    // 8 x 190 MiB is 1,520 MiB, so the ninth session passes the 1,536 MiB total and the
    // configuration after it, which alone would fit, is refused with it.
    members.push(("host/configuration.json", stored(1 << 20)));
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert_eq!(plan.restored().count(), 8);
    assert!(matches!(
        plan.members[8].verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    ));
    assert!(matches!(
        plan.members[9].verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    ));
}

/// A member is asked for by the plan's own entry: a refused one, or an object the manifest never
/// named, is not read.
#[tokio::test]
async fn only_a_member_the_plan_writes_can_be_read() {
    let world = World::new();
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            ("sessions/0a1b2c3d-0000-4000-8000-000000000001.json", stored),
            ("keys/control/host", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let reads = source.object_reads();
    for object in [
        prepared.plan().members[1].object_id,
        BackupObjectId::new(id(0x99)),
    ] {
        assert!(matches!(
            prepared.member(object).await,
            Err(RestoreError::NotInPlan)
        ));
    }
    assert_eq!(source.object_reads(), reads, "nothing was read for either");
}

/// A service that answers a read with no bytes cannot hold a restore in a loop.
#[tokio::test]
async fn a_service_that_answers_a_read_with_nothing_stops_the_restore() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let mut source = Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed);
    source.serves_empty_ranges = true;
    // The script fails the test when the restore asks more than a few times, so a restore that
    // never gave up fails here and does not hang.
    let stopped = restore(&world, &Arc::new(source), None).await;
    assert!(matches!(stopped.expect_err("stopped"), RestoreError::Range));
}

/* -------------------------------------------------------------------------- */
/* The checkpoints a paired host gave                                          */
/* -------------------------------------------------------------------------- */

/// An owner pairing that no list of hosts holds: an answer of it raises an entry and settles no
/// pairing. Its keys are fixed, so the entry it makes is the one `given_by_a_host` builds.
fn an_unlisted_owner() -> PairedHost {
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{DeviceKeyRevision, GrantId};
    use kr_protocol::pairing::{DevicePublicKeys, NetworkConfig, ProposedGrant};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, NotificationPreviewKey, Nullable};

    let keys = DevicePublicKeys {
        transport: EndpointKey::from_bytes([0x42; 32]),
        authorisation: AuthorisationKey::from_bytes([0x43; 32]),
        stored_envelope: *world_producer().public(),
        notification_preview: NotificationPreviewKey::from_bytes([0x45; 32]),
    };
    PairedHost {
        host_device_id: DeviceId::new(id(0x40)),
        host_key_revision: DeviceKeyRevision::new(1),
        host_endpoint_id: keys.transport,
        host_keys: keys,
        network_config: NetworkConfig::empty(),
        device_id: DeviceId::new(id(0x41)),
        grant_id: GrantId::new(id(0x46)),
        proposed_grant: ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::HostManage]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        name: None,
        paired_at_ms: 1_764_000_000_000,
        device_key_revision: DeviceKeyRevision::new(1),
    }
}

/// The endpoint of the host `an_unlisted_owner` is, which a checkpoint it gave names.
fn owner_endpoint() -> EndpointKey {
    an_unlisted_owner().host_endpoint_id
}

/// The checkpoint a host gave for the world's archive at the world's service, as `sealed` is
/// published.
fn given_by_a_host(sealed: &Sealed) -> PairedCheckpoint {
    let held = checkpoint_of(sealed);
    let host = an_unlisted_owner();
    PairedCheckpoint {
        host_endpoint_id: host.host_endpoint_id,
        producer: kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::StoredEnvelope,
            host.host_keys.stored_envelope.as_bytes(),
        ),
        service_origin: GatewayOrigin::new(ORIGIN).expect("an origin"),
        archive_id: held.archive_id,
        backup_generation: held.backup_generation,
        encrypted_manifest_hash: held.encrypted_manifest_hash,
        taken_at_ms: 3_000,
    }
}

/// The checkpoints a computer holds when each of `entries` was given by a host and none is owed.
fn held_with(entries: Vec<PairedCheckpoint>) -> Held {
    Held::Read {
        entries,
        owed: 0,
        listed: Vec::new(),
    }
}

/// A restore held to `held`, with the older generation named when `accept` is.
async fn restore_held(
    world: &World,
    source: &Arc<Scripted>,
    accept: Option<u64>,
    held: &Held,
) -> Result<kr_client::recovery::PreparedRestore, RestoreError> {
    FilesRestore::prepare(
        world.kit(),
        Arc::clone(source) as Arc<dyn RestoreSource>,
        None,
        accept.map(BackupGeneration::new),
        held,
    )
    .await
}

/// KR-REQ-20.12: a checkpoint a paired host gave holds a restore that the recovery bundle alone
/// would let through, and the restore says whose checkpoint it was held to.
#[tokio::test]
async fn a_checkpoint_a_paired_host_gave_holds_a_restore_that_the_bundle_alone_would_not() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let older = world.seal(3, &members);
    let newer = world.seal(6, &members);
    let bundle = || world.bundle(&Shape::default());

    // The file is written through the real API and read by a fresh handle, as the companion does.
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let pairing = an_unlisted_owner();
    let given = given_by_a_host(&current);
    let answer = Answer::Checkpoint(HostCheckpoint {
        service_origin: given.service_origin.clone(),
        archive_id: given.archive_id,
        backup_generation: given.backup_generation,
        encrypted_manifest_hash: given.encrypted_manifest_hash,
    });
    // No list of hosts holds this pairing, so the answer is taken as a checkpoint and settles none.
    assert_eq!(
        PairedCheckpoints::open(&folder)
            .expect("a directory")
            .settle_checkpoint(&pairing, &answer, 3_000),
        Err(Unsettled::Superseded)
    );
    let held = PairedCheckpoints::open(&folder)
        .expect("opened again")
        .held_checkpoints();
    let file = std::fs::read(folder.join("checkpoints.json")).expect("the file");

    // The bundle records no checkpoint. The service holds an older generation.
    let source = Arc::new(
        Scripted::serving(&world, bundle())
            .publishing(&older)
            .honouring_the_hold(),
    );
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("the older generation is refused")
    };
    // A host's checkpoint holds an older generation back in one variant, whichever ask found it,
    // and it names the host by its endpoint.
    assert!(
        matches!(
            &error,
            RestoreError::Publication(PublicationRefusal::Generation(standing, _))
                if standing.standing
                    == GenerationStanding::Replayed { checkpoint: BackupGeneration::new(5) }
                    && standing.backup_generation.get() == 3
                    && standing.source == Some(CheckpointSource::Pairing(owner_endpoint()))
        ),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "the checkpoint a host this device paired with reported refuses that generation. The service \
         offered backup generation 3. It is older than generation 5, the newest that a host this \
         device paired with reported when this device asked, so it is not being restored. No \
         restore can show that the service is not holding a newer backup back."
    );
    assert_eq!(source.object_reads(), 0, "a replay costs no download");

    // The service holds nothing at all: the bundle holds no checkpoint, so nothing was asked held
    // to one and the service holds no generation of the archive.
    let source = Arc::new(Scripted::serving(&world, bundle()));
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("a service that holds nothing stops the restore")
    };
    assert!(matches!(error, RestoreError::NoGeneration), "{error}");

    // A service that serves what it holds whatever it was asked to hold it to.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&older));
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("a replay is refused whatever the service answers")
    };
    assert!(matches!(
        &error,
        RestoreError::Publication(PublicationRefusal::Generation(standing, _))
            if standing.source == Some(CheckpointSource::Pairing(owner_endpoint()))
    ));
    assert!(
        error.to_string().starts_with(
            "the checkpoint a host this device paired with reported refuses that generation. "
        ),
        "{error}"
    );

    // The generation the host named restores, and the plan names it and whose checkpoint it met.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&current));
    let Ok(prepared) = restore_held(&world, &source, None, &held).await else {
        panic!("the generation the host named restores")
    };
    let plan = prepared.plan();
    assert_eq!(plan.generation.get(), 5);
    assert_eq!(
        plan.standing.source,
        Some(CheckpointSource::Pairing(owner_endpoint()))
    );
    assert!(matches!(
        plan.standing.standing,
        GenerationStanding::AtCheckpoint
    ));
    assert_eq!(
        plan.pairing,
        PairingStanding::Held {
            generation: BackupGeneration::new(5)
        }
    );

    // A newer generation restores too, ahead of the host's checkpoint.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    let Ok(prepared) = restore_held(&world, &source, None, &held).await else {
        panic!("a newer generation restores")
    };
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::Ahead { .. }
    ));

    // None of it wrote the file.
    assert_eq!(
        std::fs::read(folder.join("checkpoints.json")).expect("the file"),
        file,
        "a restore writes nothing to the file"
    );
}

/// KR-REQ-20.12: the bundle's set is the only one the restore keeps and records. A bundle replayed
/// to an older state leaves the restore held to the file's checkpoint; what the file holds is never
/// copied into the bundle.
#[tokio::test]
async fn the_effective_checkpoint_is_the_higher_of_the_two_and_only_the_bundles_is_recorded() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let middle = world.seal(4, &members);
    let old = world.seal(3, &members);
    let held = held_with(vec![given_by_a_host(&current)]);
    let replayed_bundle = || {
        world.bundle(&Shape {
            checkpoint: Some(checkpoint_of(&old)),
            ..Shape::default()
        })
    };

    // A bundle replayed to generation 3 leaves the restore held to the file's 5.
    let source = Arc::new(
        Scripted::serving(&world, replayed_bundle())
            .publishing(&middle)
            .honouring_the_hold(),
    );
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("generation 4 is older than the file's checkpoint")
    };
    // The first ask, held to the bundle's 3, is answered with 4, and the refusal follows its
    // verification: the file's entry holds it back as one variant, whichever ask found it.
    assert!(replayed_under(&error, 5), "{error}");
    assert_eq!(source.generation_asks().len(), 1);

    // A held entry above the bundle's, a restore of the generation it names, and the record. What
    // the file holds for another archive, or for the same archive at another service, holds nothing
    // up.
    let other_archive = PairedCheckpoint {
        archive_id: ArchiveId::new(id(0x61)),
        backup_generation: BackupGeneration::new(9),
        ..given_by_a_host(&current)
    };
    let other_service = PairedCheckpoint {
        service_origin: GatewayOrigin::new("https://elsewhere.example").expect("an origin"),
        backup_generation: BackupGeneration::new(9),
        ..given_by_a_host(&current)
    };
    let held = held_with(vec![
        given_by_a_host(&current),
        other_archive,
        other_service,
    ]);
    let source = Arc::new(Scripted::serving(&world, replayed_bundle()).publishing(&current));
    let Ok(prepared) = restore_held(&world, &source, None, &held).await else {
        panic!("the file's generation restores")
    };
    let bundle = Bundle::over(&source);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await;
    assert!(
        matches!(recorded, Ok(CheckpointRecorded::Written { .. })),
        "a checkpoint above the bundle's is recorded, not refused as one that went back"
    );
    let after = bundle_held(&world, &source);
    assert_eq!(
        after.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [ArchiveCheckpoint {
            verified_at_ms: TimestampMs::new(9_000),
            ..checkpoint_of(&current)
        }],
        "the bundle holds what the restore verified, and nothing the file held for another archive"
    );

    // The same with an older generation the person named: it is recorded where it raises the bundle's.
    let source = Arc::new(
        Scripted::serving(&world, replayed_bundle())
            .publishing(&middle)
            .honouring_the_hold(),
    );
    let Ok(prepared) = restore_held(&world, &source, Some(4), &held).await else {
        panic!("the generation named restores")
    };
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::OlderAccepted { .. }
    ));
    let recorded = prepared
        .record_checkpoint(&Bundle::over(&source), TimestampMs::new(9_000))
        .await;
    assert!(
        matches!(recorded, Ok(CheckpointRecorded::Written { .. })),
        "the bundle's checkpoint at 3 is raised to the 4 that was restored"
    );

    // Of two entries for one archive in the bundle, the highest is the floor, whichever comes first.
    let nine = world.seal(9, &members);
    let seven = world.seal(7, &members);
    for entries in [
        (checkpoint_of(&current), checkpoint_of(&nine)),
        (checkpoint_of(&nine), checkpoint_of(&current)),
    ] {
        let source = Arc::new(
            Scripted::serving(
                &world,
                world.bundle(&Shape {
                    checkpoint: Some(entries.0),
                    more_checkpoints: vec![entries.1],
                    ..Shape::default()
                }),
            )
            .publishing(&seven)
            .honouring_the_hold(),
        );
        let Err(error) = restore_held(&world, &source, None, &Held::Absent).await else {
            panic!("generation 7 is older than the highest entry, 9")
        };
        assert!(matches!(
            error,
            RestoreError::OlderThanTheCheckpoint {
                checkpoint: 9,
                held: 7,
                ..
            }
        ));
    }

    // Of two entries for one archive in the file, the highest is the floor, whichever comes first.
    for entries in [
        vec![given_by_a_host(&old), given_by_a_host(&current)],
        vec![given_by_a_host(&current), given_by_a_host(&old)],
    ] {
        let source = Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default()))
                .publishing(&middle)
                .honouring_the_hold(),
        );
        let Err(error) = restore_held(&world, &source, None, &held_with(entries)).await else {
            panic!("generation 4 is older than the highest entry in the file, 5")
        };
        assert!(replayed_under(&error, 5), "{error}");
    }

    // A checkpoint in the file that equals the bundle's is the bundle's, and one below it holds
    // nothing up: either way the generation 4 is older than the bundle's 5.
    for file_at in [&current, &old] {
        let source = Arc::new(
            Scripted::serving(
                &world,
                world.bundle(&Shape {
                    checkpoint: Some(checkpoint_of(&current)),
                    ..Shape::default()
                }),
            )
            .publishing(&middle)
            .honouring_the_hold(),
        );
        let held = held_with(vec![given_by_a_host(file_at)]);
        let Err(error) = restore_held(&world, &source, None, &held).await else {
            panic!("generation 4 is older than the bundle's checkpoint, 5")
        };
        assert!(matches!(
            error,
            RestoreError::OlderThanTheCheckpoint {
                checkpoint: 5,
                held: 4,
                ..
            }
        ));
    }
}

/// KR-REQ-20.12: where the bundle and a host name different manifests for one generation, that
/// generation alone is refused, and nothing is written to either source.
#[tokio::test]
async fn a_disagreement_between_the_two_checkpoints_refuses_only_the_generation_it_names() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let other = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let newer = world.seal(6, &members);
    let older = world.seal(4, &members);
    let bundle = || {
        world.bundle(&Shape {
            checkpoint: Some(checkpoint_of(&current)),
            ..Shape::default()
        })
    };
    let held = held_with(vec![given_by_a_host(&other)]);

    // The generation both name is refused, whichever manifest the service holds for it.
    for served in [&current, &other] {
        let source = Arc::new(Scripted::serving(&world, bundle()).publishing(served));
        let Err(error) = restore_held(&world, &source, None, &held).await else {
            panic!("the generation the two name differently is refused")
        };
        assert!(matches!(
            error,
            RestoreError::PairingCheckpointDisagrees { generation: 5, .. }
        ));
        assert_eq!(source.object_reads(), 0);
    }
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&current));
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("refused")
    };
    let digits = |hash: Digest256| {
        hash.as_bytes()
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        error.to_string(),
        format!(
            "the checkpoint this device kept when it paired and the recovery bundle name different \
             manifests for generation 5 ({} and {}); the restore cannot tell which is the archive \
             that was published",
            digits(given_by_a_host(&other).encrypted_manifest_hash),
            digits(checkpoint_of(&current).encrypted_manifest_hash)
        )
    );

    // A newer generation is ahead of both and restores.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    assert!(restore_held(&world, &source, None, &held).await.is_ok());

    // An older one is a replay under either: both name generation 5, and the bundle's words say so.
    let source = Arc::new(
        Scripted::serving(&world, bundle())
            .publishing(&older)
            .honouring_the_hold(),
    );
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("an older generation is a replay")
    };
    assert!(matches!(
        error,
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 4,
            ..
        }
    ));
}

/// A hash in full, as the scripted source records the checkpoint a request was held to.
fn hex(hash: &Digest256) -> String {
    hash.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The first eight hexadecimal digits of a manifest hash, as a refusal shows them.
fn eight_digits(hash: Digest256) -> String {
    hash.as_bytes()
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// KR-REQ-20.12: where the bundle itself holds two checkpoints for its highest generation that name
/// different manifests, that generation alone is refused, whichever manifest the service holds for
/// it, and the order the bundle lists them in decides nothing.
#[tokio::test]
async fn two_bundle_checkpoints_for_one_generation_that_name_different_manifests_refuse_it() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let other = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let newer = world.seal(6, &members);
    let older = world.seal(4, &members);
    let bundle = || {
        world.bundle(&Shape {
            checkpoint: Some(checkpoint_of(&current)),
            more_checkpoints: vec![checkpoint_of(&other)],
            ..Shape::default()
        })
    };
    let mut digits = [
        eight_digits(checkpoint_of(&current).encrypted_manifest_hash),
        eight_digits(checkpoint_of(&other).encrypted_manifest_hash),
    ];
    digits.sort();
    let words = format!(
        "the recovery bundle holds two checkpoints for generation 5 that name different manifests \
         ({} and {}); the restore cannot tell which is the archive that was published",
        digits[0], digits[1]
    );

    // Each manifest the two name, offered by the service for that generation, is refused, with and
    // without a host's checkpoint that agrees with one of them.
    for held in [Held::Absent, held_with(vec![given_by_a_host(&current)])] {
        for served in [&current, &other] {
            let source = Arc::new(Scripted::serving(&world, bundle()).publishing(served));
            let Err(error) = restore_held(&world, &source, None, &held).await else {
                panic!("the generation the bundle names twice is refused, whichever is served")
            };
            assert_eq!(error.to_string(), words);
            assert_eq!(source.object_reads(), 0);
        }
    }

    // A newer generation is ahead of both and restores; an older one is a replay.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    assert!(
        restore_held(&world, &source, None, &Held::Absent)
            .await
            .is_ok()
    );
    let source = Arc::new(
        Scripted::serving(&world, bundle())
            .publishing(&older)
            .honouring_the_hold(),
    );
    let Err(error) = restore_held(&world, &source, None, &Held::Absent).await else {
        panic!("an older generation is a replay")
    };
    assert!(matches!(
        error,
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 4,
            ..
        }
    ));

    // A host's checkpoint above the two is the floor, and the two below it decide nothing.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    let above = held_with(vec![given_by_a_host(&newer)]);
    assert!(restore_held(&world, &source, None, &above).await.is_ok());

    // The list marks the archive for the generation the two name, and not for a newer one.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&current));
    assert!(
        list(&world, &source, &Held::Absent).await[0].newest
            == CandidateState::BundleCheckpointsDisagree {
                generation: BackupGeneration::new(5)
            }
    );
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    assert!(matches!(
        list(&world, &source, &Held::Absent).await[0].newest,
        CandidateState::Newest(_)
    ));

    // Another archive's checkpoint for the same generation is not a second one for this archive.
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                checkpoint: Some(checkpoint_of(&current)),
                more_checkpoints: vec![another_archive_at(5)],
                ..Shape::default()
            }),
        )
        .publishing(&current),
    );
    assert!(
        restore_held(&world, &source, None, &Held::Absent)
            .await
            .is_ok()
    );
}

/// KR-REQ-20.12: a file that cannot be read is a refusal before the service is asked, never an empty
/// set; a restore of the bundle's settings and an export of the bundle alone are not held to it.
#[tokio::test]
async fn checkpoints_that_cannot_be_read_refuse_the_restore_and_the_list_and_never_read_as_none() {
    let world = World::new();
    let current = world.seal(5, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&current));

    for cause in [
        SnapshotCause::Unreadable,
        SnapshotCause::NewerVersion,
        SnapshotCause::Lock,
        SnapshotCause::Busy,
        SnapshotCause::HostsFile,
    ] {
        let (file, words) = match cause {
            SnapshotCause::Unreadable | SnapshotCause::NewerVersion => (
                "checkpoints.json",
                "the backup checkpoints this device kept when it paired cannot be read \
                 (checkpoints.json: the file is unreadable)",
            ),
            SnapshotCause::Lock | SnapshotCause::Busy => (
                "checkpoints.lock",
                "the lock file for the backup checkpoints this device kept when it paired cannot \
                 be used (checkpoints.lock: the file is unreadable)",
            ),
            SnapshotCause::HostsFile => (
                "hosts.json",
                "the list of hosts this device paired with cannot be read (hosts.json: the file \
                 is unreadable)",
            ),
        };
        let held = Held::Unreadable {
            file: Shown::said(file),
            why: Shown::said("the file is unreadable"),
            cause,
        };
        let Err(error) = restore_held(&world, &source, None, &held).await else {
            panic!("a restore is refused when the checkpoints cannot be read ({cause:?})")
        };
        assert!(
            matches!(&error, RestoreError::PairingCheckpointsUnreadable { cause: said, .. } if *said == cause),
            "{cause:?}"
        );
        assert_eq!(error.to_string(), words, "{cause:?}");
        let Err(listed) = FilesRestore::archives(
            world.kit(),
            Arc::clone(&source) as Arc<dyn RestoreSource>,
            &held,
        )
        .await
        else {
            panic!("the list is refused when the checkpoints cannot be read ({cause:?})")
        };
        assert!(matches!(
            listed,
            RestoreError::PairingCheckpointsUnreadable { .. }
        ));
    }
    assert!(
        source.asked().is_empty(),
        "nothing was asked of the service: {:?}",
        source.asked()
    );

    // A file that cannot be read in fact is the same.
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let checkpoints = PairedCheckpoints::open(&folder).expect("a directory");
    kr_ipc::paths::write_owner_only_file(&folder.join("checkpoints.json"), b"not a file")
        .expect("a file that is not one");
    let held = checkpoints.held_checkpoints();
    let Err(error) = restore_held(&world, &source, None, &held).await else {
        panic!("a file that does not parse refuses the restore")
    };
    assert!(matches!(
        error,
        RestoreError::PairingCheckpointsUnreadable {
            cause: SnapshotCause::Unreadable,
            ..
        }
    ));

    // The same restore with no file proceeds, and so does what takes no checkpoints.
    let held = PairedCheckpoints::open(directory.path().join("another"))
        .expect("a directory")
        .held_checkpoints();
    assert!(restore_held(&world, &source, None, &held).await.is_ok());
    assert!(
        FilesRestore::settings(world.kit(), Arc::clone(&source) as Arc<dyn RestoreSource>)
            .await
            .is_ok()
    );
    assert!(
        FilesRestore::export_bundle(world.kit(), Arc::clone(&source) as Arc<dyn RestoreSource>)
            .await
            .is_ok()
    );
}

/// KR-REQ-20.12: a lock file that cannot be opened, and a lock that something else holds, refuse a
/// restore in words about the lock file and not about the checkpoints file, which neither one
/// touched; a held lock is use, so it is not said to be a change.
#[tokio::test]
async fn a_lock_file_that_cannot_be_used_refuses_a_restore_in_words_about_the_lock_file() {
    let world = World::new();
    let current = world.seal(5, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&current));
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let checkpoints = PairedCheckpoints::open(&folder).expect("a directory");
    let lock = folder.join("checkpoints.lock");

    // A directory stands where the lock file goes: it cannot be opened.
    std::fs::create_dir(&lock).expect("a directory where the lock file goes");
    let Err(error) = restore_held(&world, &source, None, &checkpoints.held_checkpoints()).await
    else {
        panic!("a lock file that cannot be opened refuses the restore")
    };
    let words = error.to_string();
    assert!(
        words.starts_with(
            "the lock file for the backup checkpoints this device kept when it paired cannot be \
             used ("
        ),
        "{words}"
    );
    assert!(words.contains("checkpoints.lock: "), "{words}");
    assert!(!words.contains("cannot be read"), "{words}");
    std::fs::remove_dir(&lock).expect("the directory is removed");

    // Something else holds the lock for longer than a restore waits.
    let holder = kr_ipc::paths::open_lock_file(&lock).expect("a lock file");
    kr_flush::lock::exclusive(&holder).expect("held");
    let Err(error) = restore_held(&world, &source, None, &checkpoints.held_checkpoints()).await
    else {
        panic!("a lock that something else holds refuses the restore")
    };
    kr_flush::lock::release(&holder).expect("released");
    let words = error.to_string();
    assert!(
        words.starts_with(
            "the lock file for the backup checkpoints this device kept when it paired cannot be \
             used ("
        ),
        "{words}"
    );
    assert!(
        words.ends_with("checkpoints.lock: something else on this device is using it)"),
        "{words}"
    );
    assert!(
        source.asked().is_empty(),
        "nothing was asked of the service: {:?}",
        source.asked()
    );
}

/// KR-REQ-20.12: an older generation a person accepts past a higher checkpoint is still held to the
/// bundle's own checkpoint for that generation: the manifest the bundle verified restores, and
/// another manifest for it is a substitution that names the bundle.
#[tokio::test]
async fn an_accepted_older_generation_is_held_to_the_bundles_own_checkpoint_for_it() {
    let world = World::new();
    let members = honest_members();
    let nine = world.seal(9, &members);
    let five = world.seal(5, &members);
    let other_five = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let held = held_with(vec![given_by_a_host(&nine)]);
    let bundle = world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&five)),
        ..Shape::default()
    });
    let serving = |sealed: &Sealed| {
        Arc::new(
            Scripted::serving(&world, bundle.clone())
                .publishing(sealed)
                .honouring_the_hold(),
        )
    };

    // The manifest the bundle verified for generation 5 restores, named, past the host's 9.
    let Ok(prepared) = restore_held(&world, &serving(&five), Some(5), &held).await else {
        panic!("the generation the bundle verified is accepted past the host's checkpoint")
    };
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::OlderAccepted { .. }
    ));

    // Another manifest for generation 5 is not what the bundle verified, however it is named.
    let source = serving(&other_five);
    let Err(error) = restore_held(&world, &source, Some(5), &held).await else {
        panic!("another manifest for a generation the bundle verified is refused")
    };
    let RestoreError::Publication(PublicationRefusal::Generation(standing, _)) = error else {
        panic!("a substitution is refused as a publication: {error}")
    };
    assert!(matches!(
        standing.standing,
        GenerationStanding::Substituted { checkpoint } if checkpoint.get() == 5
    ));
    assert_eq!(standing.source, Some(CheckpointSource::RecoveryBundle));
    assert_eq!(source.object_reads(), 0);

    // The same holds where the bundle's own checkpoint is the higher one and an older entry of its
    // own is for the generation named.
    let both = world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&nine)),
        more_checkpoints: vec![checkpoint_of(&five)],
        ..Shape::default()
    });
    let source = Arc::new(
        Scripted::serving(&world, both)
            .publishing(&other_five)
            .honouring_the_hold(),
    );
    assert!(
        restore_held(&world, &source, Some(5), &Held::Absent)
            .await
            .is_err(),
        "an older entry of the bundle's own holds an accepted generation too"
    );

    // Without the name, generation 5 is a replay as before.
    let Err(error) = restore_held(&world, &serving(&five), None, &held).await else {
        panic!("an older generation that is not named is a replay")
    };
    // The host's entry holds it, in the one variant whichever ask found it.
    assert!(replayed_under(&error, 9), "{error}");
}

/// KR-REQ-20.12: accepting an older generation reads the effective checkpoint and writes no file;
/// there is nothing to accept past only when neither source holds a checkpoint, and a caller with no
/// store of paired hosts, as the command line is, cannot accept past one a host gave.
#[tokio::test]
async fn an_older_generation_can_be_accepted_past_a_pairing_checkpoint_in_the_library_only() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let older = world.seal(3, &members);
    let held = held_with(vec![given_by_a_host(&current)]);
    let source = || {
        Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default()))
                .publishing(&older)
                .honouring_the_hold(),
        )
    };

    // The library accepts generation 3 past the file's 5, and says so.
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let checkpoints = PairedCheckpoints::open(&folder).expect("a directory");
    let given = given_by_a_host(&current);
    checkpoints
        .settle_checkpoint(
            &an_unlisted_owner(),
            &Answer::Checkpoint(HostCheckpoint {
                service_origin: given.service_origin,
                archive_id: given.archive_id,
                backup_generation: given.backup_generation,
                encrypted_manifest_hash: given.encrypted_manifest_hash,
            }),
            3_000,
        )
        .expect_err("no list of hosts holds the pairing, so it settles none");
    let file = std::fs::read(folder.join("checkpoints.json")).expect("the file");
    let Ok(prepared) =
        restore_held(&world, &source(), Some(3), &checkpoints.held_checkpoints()).await
    else {
        panic!("the generation named is accepted past the file's checkpoint")
    };
    assert_eq!(prepared.plan().generation.get(), 3);
    assert_eq!(
        prepared.plan().standing.source,
        Some(CheckpointSource::Pairing(owner_endpoint()))
    );
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::OlderAccepted { .. }
    ));
    assert_eq!(
        std::fs::read(folder.join("checkpoints.json")).expect("the file"),
        file,
        "accepting an older generation writes nothing to the file"
    );

    // A name for another generation than the one the service holds needs no word, and says whose
    // checkpoint the service's generation met.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&current)
            .honouring_the_hold(),
    );
    let Err(error) = restore_held(&world, &source, Some(3), &held).await else {
        panic!("a name for a generation the service does not hold is refused")
    };
    assert!(matches!(
        error,
        RestoreError::NamedGenerationNotHeld {
            named: 3,
            held: 5,
            checkpoint_source: CheckpointSource::Pairing(_),
            ..
        }
    ));

    // Neither source holds a checkpoint: there is none to accept past, and the words say which
    // sources were looked at.
    let none = held_with(Vec::new());
    let Err(error) = restore_held(&world, &source, Some(3), &none).await else {
        panic!("there is nothing to accept past")
    };
    assert!(matches!(
        error,
        RestoreError::NoCheckpointToAcceptPast {
            pairing_consulted: true,
            ..
        }
    ));
    assert_eq!(
        error.to_string(),
        "neither the recovery bundle nor a host this device paired with reports a checkpoint for \
         that archive, so there is none to accept an older generation past"
    );

    // The command line passes no snapshot, so it cannot see a checkpoint only a host gave.
    let Err(error) = restore_held(&world, &source, Some(3), &Held::Absent).await else {
        panic!("with no pairing source there is nothing to accept past")
    };
    assert!(matches!(
        error,
        RestoreError::NoCheckpointToAcceptPast {
            pairing_consulted: false,
            ..
        }
    ));
    assert_eq!(
        error.to_string(),
        "the recovery bundle records no checkpoint for that archive, so there is none to accept an \
         older generation past"
    );
    // And a held entry that exists is there, so the difference is the snapshot and nothing else.
    assert!(matches!(&held, Held::Read { entries, .. } if entries.len() == 1));
}

/// Each refusal that names a checkpoint says whose it is, in the words the person reads: the whole
/// sentence, for each source.
#[test]
fn the_words_of_each_refusal_name_the_source_of_the_checkpoint() {
    let bundle = CheckpointSource::RecoveryBundle;
    let pairing = CheckpointSource::Pairing(owner_endpoint());

    // A restore asks the service held to the bundle's checkpoint alone, so these two refusals are
    // the bundle's and name nothing else.
    assert_eq!(
        RestoreError::nothing_as_new(5).to_string(),
        "the service holds no generation as new as the bundle's checkpoint, generation 5"
    );
    assert_eq!(
        RestoreError::older_than_the_checkpoint(3, 5).to_string(),
        "the service holds generation 3 of that archive, older than generation 5 that the \
         recovery bundle verified"
    );
    assert_eq!(
        RestoreError::named_generation_not_held(3, 5, bundle).to_string(),
        "generation 3 was named to be accepted past the bundle's checkpoint, and the service holds \
         generation 5, which needs no such word"
    );
    assert_eq!(
        RestoreError::named_generation_not_held(3, 5, pairing).to_string(),
        "generation 3 was named to be accepted past the checkpoint a host this device paired with \
         reported, and the service holds generation 5, which needs no such word"
    );
    assert_eq!(
        RestoreError::no_checkpoint_to_accept_past(false).to_string(),
        "the recovery bundle records no checkpoint for that archive, so there is none to accept an \
         older generation past"
    );
    assert_eq!(
        RestoreError::no_checkpoint_to_accept_past(true).to_string(),
        "neither the recovery bundle nor a host this device paired with reports a checkpoint for that \
         archive, so there is none to accept an older generation past"
    );

    let hash = Digest256::from_bytes([0xab; 32]);
    let refusal = |source: CheckpointSource| {
        let checkpoint = ArchiveCheckpoint {
            archive_id: archive(),
            backup_generation: BackupGeneration::new(5),
            encrypted_manifest_hash: hash,
            verified_at_ms: TimestampMs::new(1),
        };
        let world = World::new();
        let sealed = world.seal(3, &honest_members());
        let standing = kr_crypto::backup::RestoreGeneration::against(
            &sealed.publication.payload.descriptor,
            kr_crypto::backup::GenerationExpectation::Checkpoint {
                checkpoint: &checkpoint,
                source,
            },
        );
        let words = Shown::restore_refusal(&standing);
        PublicationRefusal::Generation(standing, words).to_string()
    };
    assert_eq!(
        refusal(bundle),
        "the recovery bundle's checkpoint refuses that generation. The service offered backup \
         generation 3. It is older than generation 5 that the recovery bundle verified, so it is \
         not being restored. No restore can show that the service is not holding a newer backup \
         back."
    );
    assert_eq!(
        refusal(pairing),
        "the checkpoint a host this device paired with reported refuses that generation. The service \
         offered backup generation 3. It is older than generation 5, the newest that a host this \
         device paired with reported when this device asked, so it is not being restored. No \
         restore can show that the service is not holding a newer backup back."
    );
    // The words say whose kind of checkpoint it is and never which host: two hosts read alike, so
    // that the plan's digest, which covers the words, does not tell them apart.
    assert_eq!(
        refusal(pairing),
        refusal(CheckpointSource::Pairing(EndpointKey::from_bytes(
            [0x99; 32]
        )))
    );
}

/// The archives the bundle names, listed held to `held`.
async fn list(
    world: &World,
    source: &Arc<Scripted>,
    held: &Held,
) -> Vec<kr_client::recovery::Candidate> {
    FilesRestore::archives(
        world.kit(),
        Arc::clone(source) as Arc<dyn RestoreSource>,
        held,
    )
    .await
    .expect("a list")
}

/// KR-REQ-20.12: an archive the service holds only an older generation of is listed as held back,
/// with the generations and whose checkpoint holds it back; a disagreement and what a paired host
/// owes are listed as what they are.
#[tokio::test]
async fn the_list_says_what_holds_an_archive_back_and_what_the_paired_hosts_say_of_it() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let older = world.seal(3, &members);
    let newer = world.seal(6, &members);
    let other = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let held_back =
        |held: u64, checkpoint: u64, source: CheckpointSource| CandidateState::HeldBack {
            held: BackupGeneration::new(held),
            checkpoint: BackupGeneration::new(checkpoint),
            source,
        };
    let bundle_at_five = || {
        world.bundle(&Shape {
            checkpoint: Some(checkpoint_of(&current)),
            ..Shape::default()
        })
    };

    // Held back by the bundle's checkpoint, and held back by a host's.
    let source = Arc::new(
        Scripted::serving(&world, bundle_at_five())
            .publishing(&older)
            .honouring_the_hold(),
    );
    let listed = list(&world, &source, &Held::Absent).await;
    assert!(
        listed[0].newest == held_back(3, 5, CheckpointSource::RecoveryBundle),
        "the bundle's checkpoint holds it back"
    );
    assert_eq!(listed[0].pairing, PairingStanding::None);
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    let held = held_with(vec![given_by_a_host(&current)]);
    let listed = list(&world, &source, &held).await;
    assert!(
        listed[0].newest == held_back(3, 5, CheckpointSource::Pairing(owner_endpoint())),
        "a host's checkpoint holds it back"
    );
    assert_eq!(
        listed[0].pairing,
        PairingStanding::Held {
            generation: BackupGeneration::new(5)
        }
    );

    // A service that holds nothing at all is nothing, not held back.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    assert!(matches!(
        list(&world, &source, &held).await[0].newest,
        CandidateState::Nothing
    ));

    // A newer generation is the newest, and so is the generation a checkpoint names.
    for served in [&newer, &current] {
        let source = Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default()))
                .publishing(served)
                .honouring_the_hold(),
        );
        assert!(matches!(
            list(&world, &source, &held).await[0].newest,
            CandidateState::Newest(_)
        ));
    }

    // Two checkpoints that name generation 5 differently: the service at 5 is a disagreement, and one at
    // 6 is not.
    let disagreeing = held_with(vec![given_by_a_host(&other)]);
    let source = Arc::new(Scripted::serving(&world, bundle_at_five()).publishing(&current));
    assert!(
        list(&world, &source, &disagreeing).await[0].newest
            == CandidateState::CheckpointsDisagree {
                generation: BackupGeneration::new(5),
                host: owner_endpoint(),
            }
    );
    let source = Arc::new(Scripted::serving(&world, bundle_at_five()).publishing(&newer));
    assert!(matches!(
        list(&world, &source, &disagreeing).await[0].newest,
        CandidateState::Newest(_)
    ));

    // A host that has not answered is owed, and an answer for another archive is not an answer for
    // this one.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&current));
    let owed = Held::Read {
        entries: Vec::new(),
        owed: 1,
        listed: Vec::new(),
    };
    assert_eq!(
        list(&world, &source, &owed).await[0].pairing,
        PairingStanding::Owed
    );
    let elsewhere = PairedCheckpoint {
        archive_id: ArchiveId::new(id(0x61)),
        ..given_by_a_host(&current)
    };
    assert_eq!(
        list(
            &world,
            &source,
            &Held::Read {
                entries: vec![elsewhere],
                owed: 1,
                listed: Vec::new(),
            }
        )
        .await[0]
            .pairing,
        PairingStanding::Owed
    );
    assert_eq!(
        list(&world, &source, &held_with(Vec::new())).await[0].pairing,
        PairingStanding::None
    );

    // The archives of a bundle that names several are listed with the snapshot too, so the one a
    // host's checkpoint holds back is marked and the one the service holds nothing of is not.
    let second = ArchiveId::new(id(0x14));
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                collections: Some(vec![
                    collection(ORIGIN, "collection-1", archive()),
                    collection(ORIGIN, "collection-3", second),
                ]),
                ..Shape::default()
            }),
        )
        .publishing(&older)
        .honouring_the_hold(),
    );
    let Err(RestoreError::SeveralArchives { candidates, .. }) =
        restore_held(&world, &source, None, &held).await
    else {
        panic!("several archives are listed, not chosen")
    };
    let state = |archive_id: ArchiveId| {
        candidates
            .iter()
            .find(|candidate| candidate.archive_id == archive_id)
            .map(|candidate| candidate.newest.clone())
    };
    assert!(state(archive()) == Some(held_back(3, 5, CheckpointSource::Pairing(owner_endpoint()))));
    assert!(matches!(state(second), Some(CandidateState::Nothing)));
}

/* -------------------------------------------------------------------------- */
/* A host's checkpoint counts only for the archive that host produces          */
/* -------------------------------------------------------------------------- */

/// The key id a producer other than the world's has.
fn another_producer() -> KeyId {
    StoredEnvelopeKeyPair::generate().expect("a key").key_id()
}

/// The entry of another host (by `endpoint`) that names `producer`, at `generation`, for the
/// archive `sealed` is.
fn entry_of(endpoint: u8, producer: KeyId, generation: u64, sealed: &Sealed) -> PairedCheckpoint {
    PairedCheckpoint {
        host_endpoint_id: EndpointKey::from_bytes([endpoint; 32]),
        producer,
        backup_generation: BackupGeneration::new(generation),
        ..given_by_a_host(sealed)
    }
}

/// `sealed` with its manifest key wrapped once more by each of `senders`, each for a recipient of
/// its own, and signed again by the writer: a publication of one archive that names several
/// producers. The wrap for the recovery recipient stays first and opens as it did.
fn with_senders(world: &World, sealed: &Sealed, senders: &[KeyId]) -> Sealed {
    let mut descriptor = sealed.publication.payload.descriptor.clone();
    let first = descriptor.manifest_key_wraps[0].clone();
    for (at, sender) in senders.iter().enumerate() {
        let mut wrap = first.clone();
        wrap.context.sender_key_id = *sender;
        wrap.context.recipient_key_id =
            KeyId::from_bytes([0x71 + u8::try_from(at).expect("few"); 32]);
        descriptor.manifest_key_wraps.push(wrap);
    }
    Sealed {
        publication: publish(&descriptor, &world.writer),
        objects: sealed.objects.clone(),
        manifest_object: sealed.manifest_object,
    }
}

/// `sealed` with no manifest key wrap at all, signed again by the writer.
fn without_wraps(world: &World, sealed: &Sealed) -> Sealed {
    let mut descriptor = sealed.publication.payload.descriptor.clone();
    descriptor.manifest_key_wraps.clear();
    Sealed {
        publication: publish(&descriptor, &world.writer),
        objects: sealed.objects.clone(),
        manifest_object: sealed.manifest_object,
    }
}

/// Whether the restore was refused as a replay of a generation older than `checkpoint`.
fn replayed_under(error: &RestoreError, checkpoint: u64) -> bool {
    matches!(
        error,
        RestoreError::Publication(PublicationRefusal::Generation(standing, _))
            if standing.standing
                == GenerationStanding::Replayed {
                    checkpoint: BackupGeneration::new(checkpoint)
                }
    )
}

/// KR-REQ-20.12: an entry holds the archive of the producer it names and no other. A host
/// whose entry sits at the highest generation there is holds nothing of this host's archive.
#[tokio::test]
async fn an_entry_holds_only_the_archive_of_the_producer_it_names() {
    let world = World::new();
    let members = honest_members();
    let older = world.seal(3, &members);
    let current = world.seal(5, &members);
    let newer = world.seal(6, &members);
    let own = given_by_a_host(&current);
    let elsewhere = entry_of(0x52, another_producer(), u64::MAX, &current);
    let bundle = || world.bundle(&Shape::default());

    // This host's own entry holds back its older generation, with no object read, and the one ask
    // carries the bundle's checkpoint alone: the bundle holds none, so it is unheld.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&older));
    let error = restore_held(&world, &source, None, &held_with(vec![own.clone()]))
        .await
        .expect_err("the host's own entry holds the older generation back");
    assert!(replayed_under(&error, 5), "{error}");
    assert_eq!(source.object_reads(), 0);
    assert_eq!(
        source.generation_asks(),
        vec![format!("generation {} unheld", archive())]
    );

    // Another host's entry, at the highest generation there is, holds nothing of this archive: the
    // older generation and the newer one are both offered.
    for offered in [&older, &newer] {
        let source = Arc::new(Scripted::serving(&world, bundle()).publishing(offered));
        let held = held_with(vec![elsewhere.clone()]);
        let prepared = restore_held(&world, &source, None, &held)
            .await
            .expect("an entry of another producer holds nothing");
        assert!(matches!(
            prepared.plan().standing.standing,
            GenerationStanding::NoCheckpoint
        ));
        assert_eq!(prepared.plan().pairing, PairingStanding::None);
    }

    // Control: the same entry with this host's producer holds the newer generation too.
    let named = PairedCheckpoint {
        producer: world_producer().key_id(),
        ..elsewhere.clone()
    };
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    let error = restore_held(&world, &source, None, &held_with(vec![named]))
        .await
        .expect_err("the entry that names this producer holds");
    assert!(replayed_under(&error, u64::MAX), "{error}");

    // Both entries together: only this host's counts.
    let source = Arc::new(Scripted::serving(&world, bundle()).publishing(&newer));
    let prepared = restore_held(&world, &source, None, &held_with(vec![elsewhere, own]))
        .await
        .expect("the newer generation is ahead of this host's entry");
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::Ahead { checkpoint } if checkpoint.get() == 5
    ));
    assert_eq!(
        prepared.plan().pairing,
        PairingStanding::Held {
            generation: BackupGeneration::new(5)
        }
    );
}

/// KR-REQ-20.12: a publication names no producer when it names two, or none, so no entry
/// counts for it; and listing it is not restoring it.
#[tokio::test]
async fn a_publication_that_names_two_producers_or_none_is_held_by_no_entry() {
    let world = World::new();
    let members = honest_members();
    let older = world.seal(3, &members);
    let own_id = world_producer().key_id();
    let other_id = another_producer();
    let two = with_senders(&world, &older, &[other_id]);
    let three = with_senders(&world, &older, &[other_id, another_producer()]);
    let none = without_wraps(&world, &older);
    let entry = |producer: KeyId| entry_of(0x52, producer, 9, &older);

    // Two senders: the entry of either holds nothing, so the older generation restores.
    for held_by in [own_id, other_id] {
        let source =
            Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&two));
        let held = held_with(vec![entry(held_by)]);
        let prepared = restore_held(&world, &source, None, &held)
            .await
            .expect("two producers are no producer");
        assert_eq!(prepared.plan().generation.get(), 3);
        assert_eq!(prepared.plan().pairing, PairingStanding::None);
    }
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&three));
    assert!(
        restore_held(&world, &source, None, &held_with(vec![entry(own_id)]))
            .await
            .is_ok(),
        "three producers are no producer"
    );

    // No wrap: no producer. The archive is listed at its generation whatever the entry says, and
    // the restore refuses for want of a wrap and not as a replay.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&none));
    let held = held_with(vec![entry(own_id)]);
    assert!(matches!(
        list(&world, &source, &held).await[0].newest,
        CandidateState::Newest(_)
    ));
    assert!(matches!(
        restore_held(&world, &source, None, &held)
            .await
            .expect_err("no wrap"),
        RestoreError::NoWrap
    ));

    // Control: one wrap of this producer lets its entry hold the same generation.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&older));
    let error = restore_held(&world, &source, None, &held_with(vec![entry(own_id)]))
        .await
        .expect_err("one producer, named by the entry");
    assert!(replayed_under(&error, 9), "{error}");
}

/// KR-REQ-20.12: a host that is forgotten keeps its entry, and the entry still holds its
/// archive: forgetting changes no floor. Through the files, as a restart would read them.
#[tokio::test]
async fn a_forgotten_hosts_entry_still_holds_its_archive_back() {
    let world = World::new();
    let members = honest_members();
    let older = world.seal(3, &members);
    let current = world.seal(5, &members);
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let owner = an_unlisted_owner();
    hosts.record(owner.clone()).expect("a paired host");
    let given = given_by_a_host(&current);
    let answer = Answer::Checkpoint(HostCheckpoint {
        service_origin: given.service_origin.clone(),
        archive_id: given.archive_id,
        backup_generation: given.backup_generation,
        encrypted_manifest_hash: given.encrypted_manifest_hash,
    });
    hosts
        .checkpoints()
        .settle_checkpoint(&owner, &answer, 3_000)
        .expect("the host's answer");
    let source =
        || Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&older));

    let listed = hosts.checkpoints().held_checkpoints();
    let error = restore_held(&world, &source(), None, &listed)
        .await
        .expect_err("a listed host holds");
    assert!(replayed_under(&error, 5), "{error}");

    hosts.forget(owner.host_device_id).expect("forgotten");
    let after = PairedCheckpoints::open(&folder)
        .expect("opened again")
        .held_checkpoints();
    let Held::Read {
        entries, listed, ..
    } = &after
    else {
        panic!("the checkpoints are read")
    };
    assert_eq!(entries.len(), 1);
    assert!(listed.is_empty(), "the host is no longer listed");
    let error = restore_held(&world, &source(), None, &after)
        .await
        .expect_err("a forgotten host's entry holds");
    assert!(replayed_under(&error, 5), "{error}");
}

/// KR-REQ-20.12: the service is asked held to the bundle's checkpoint alone, in full, however
/// high an entry is, and an entry above the bundle's is applied after the publication is verified.
#[tokio::test]
async fn the_service_is_asked_held_to_the_bundles_checkpoint_alone() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let nine = world.seal(9, &members);
    let at_five = world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&current)),
        ..Shape::default()
    });
    let own_nine = given_by_a_host(&nine);
    let held = held_with(vec![own_nine.clone()]);

    // The bundle holds 5 and a host's entry holds 9; the service holds 5. The first ask succeeds
    // and the refusal follows its verification: no second ask, and no ask held to 9.
    let source = Arc::new(
        Scripted::serving(&world, at_five.clone())
            .publishing(&current)
            .honouring_the_hold(),
    );
    let error = restore_held(&world, &source, None, &held)
        .await
        .expect_err("held back by the entry");
    assert!(replayed_under(&error, 9), "{error}");
    assert_eq!(
        source.generation_asks(),
        vec![format!(
            "generation {} held to generation 5 manifest {}",
            archive(),
            hex(&checkpoint_of(&current).encrypted_manifest_hash)
        )]
    );
    assert_eq!(source.object_reads(), 0);

    // The service holds nothing as new as the bundle's checkpoint: the second ask is unheld and
    // the older generation it names is judged by the entry.
    let older = world.seal(3, &members);
    let source = Arc::new(
        Scripted::serving(&world, at_five)
            .publishing(&older)
            .honouring_the_hold(),
    );
    let error = restore_held(&world, &source, None, &held)
        .await
        .expect_err("held back by the entry");
    assert!(replayed_under(&error, 9), "{error}");
    assert_eq!(source.generation_asks().len(), 2);
    assert!(source.generation_asks()[0].contains("held to generation 5 manifest"));
    assert!(source.generation_asks()[1].ends_with("unheld"));
}

/* -------------------------------------------------------------------------- */
/* The same publication, judged by a restore and by the list                   */
/* -------------------------------------------------------------------------- */

/// A source as a phrase: the bundle, or the host by the first byte of its endpoint.
fn who(source: CheckpointSource) -> String {
    match source {
        CheckpointSource::RecoveryBundle => "bundle".to_owned(),
        CheckpointSource::Pairing(host) => format!("host {:02x}", host.as_bytes()[0]),
    }
}

/// What a restore says of the publication the service serves, as one phrase. A generation that the
/// bundle's checkpoint holds back is `OlderThanTheCheckpoint` when it was found by the second ask,
/// and the same phrase here.
fn said_of_restore(result: Result<kr_client::recovery::PreparedRestore, RestoreError>) -> String {
    match result {
        Ok(prepared) => format!("offered {}", prepared.plan().generation.get()),
        Err(RestoreError::Publication(PublicationRefusal::Generation(standing, _))) => {
            let source = who(standing.source.expect("a checkpoint refused it"));
            match standing.standing {
                GenerationStanding::Replayed { checkpoint } => {
                    format!("replayed under {} by {source}", checkpoint.get())
                }
                GenerationStanding::Substituted { checkpoint } => {
                    format!("other manifest at {} by {source}", checkpoint.get())
                }
                other => format!("refused: {other:?}"),
            }
        }
        Err(RestoreError::OlderThanTheCheckpoint { checkpoint, .. }) => {
            format!("replayed under {checkpoint} by bundle")
        }
        Err(RestoreError::PairingCheckpointDisagrees {
            generation, host, ..
        }) => format!(
            "disagrees at {generation} with {}",
            who(CheckpointSource::Pairing(host))
        ),
        Err(RestoreError::BundleCheckpointsDisagree { generation, .. }) => {
            format!("bundle disagrees at {generation}")
        }
        Err(RestoreError::NoGeneration | RestoreError::NothingAsNewAsTheCheckpoint { .. }) => {
            "nothing".to_owned()
        }
        Err(other) => format!("{other}"),
    }
}

/// What the list says of the same publication, as the same phrase.
fn said_of_candidate(candidate: &kr_client::recovery::Candidate) -> String {
    match &candidate.newest {
        CandidateState::Newest(newest) => format!("offered {}", newest.generation.get()),
        CandidateState::HeldBack {
            checkpoint, source, ..
        } => format!("replayed under {} by {}", checkpoint.get(), who(*source)),
        CandidateState::HostNamesAnother { generation, host } => format!(
            "other manifest at {} by {}",
            generation.get(),
            who(CheckpointSource::Pairing(*host))
        ),
        CandidateState::CheckpointsDisagree { generation, host } => format!(
            "disagrees at {} with {}",
            generation.get(),
            who(CheckpointSource::Pairing(*host))
        ),
        CandidateState::BundleCheckpointsDisagree { generation } => {
            format!("bundle disagrees at {}", generation.get())
        }
        CandidateState::Nothing => "nothing".to_owned(),
        CandidateState::Refused(refusal) => format!("refused: {refusal}"),
    }
}

/// One scenario: the checkpoints the bundle records, the entries the computer holds, and what the
/// service serves. Both routes, a restore and a list, are held to say the same.
struct Scenario<'a> {
    bundle: Vec<&'a Sealed>,
    entries: Vec<PairedCheckpoint>,
    served: Option<&'a Sealed>,
    accept: Option<u64>,
}

impl Scenario<'_> {
    async fn said(&self, world: &World) -> (String, String) {
        let checkpoints: Vec<ArchiveCheckpoint> = self
            .bundle
            .iter()
            .map(|sealed| checkpoint_of(sealed))
            .collect();
        let shape = Shape {
            checkpoint: checkpoints.first().cloned(),
            more_checkpoints: checkpoints.iter().skip(1).cloned().collect(),
            ..Shape::default()
        };
        let mut script = Scripted::serving(world, world.bundle(&shape)).honouring_the_hold();
        if let Some(served) = self.served {
            script = script.publishing(served);
        }
        let source = Arc::new(script);
        let held = held_with(self.entries.clone());
        let restored = said_of_restore(restore_held(world, &source, self.accept, &held).await);
        let listed = said_of_candidate(&list(world, &source, &held).await[0]);
        (restored, listed)
    }

    /// Asserts that both routes say `expected`.
    async fn says(&self, world: &World, name: &str, expected: &str) {
        let (restored, listed) = self.said(world).await;
        assert_eq!(restored, expected, "{name}: a restore");
        assert_eq!(listed, expected, "{name}: the list");
    }
}

/// A scenario with no entry.
fn alone<'a>(bundle: Vec<&'a Sealed>, served: &'a Sealed) -> Scenario<'a> {
    Scenario {
        bundle,
        entries: Vec::new(),
        served: Some(served),
        accept: None,
    }
}

/// A scenario with one entry.
fn held_by<'a>(
    bundle: Vec<&'a Sealed>,
    entry: PairedCheckpoint,
    served: &'a Sealed,
) -> Scenario<'a> {
    Scenario {
        bundle,
        entries: vec![entry],
        served: Some(served),
        accept: None,
    }
}

/// KR-REQ-20.12: every row of the rule, through a restore and the list alike. B is the
/// bundle's checkpoint and E the best entry of the publication's producer. Each absence has its
/// positive control beside it.
#[tokio::test]
async fn each_row_of_the_rule_holds_through_a_restore_and_the_list_alike() {
    let world = World::new();
    let members = honest_members();
    let other_members = [("host/configuration.json", b"{}".to_vec())];
    let third_members = [("host/configuration.json", b"{\"third\":1}".to_vec())];
    let three = world.seal(3, &members);
    let five = world.seal(5, &members);
    let five_other = world.seal(5, &other_members);
    let five_third = world.seal(5, &third_members);
    let six = world.seal(6, &members);
    let nine = world.seal(9, &members);
    let own = given_by_a_host;
    let elsewhere = entry_of(0x52, another_producer(), 9, &five);
    let (none, with) = (alone, held_by);

    // Row 1: no checkpoint of the bundle, no entry of this producer: no floor. Another producer's
    // entry is no entry. Control: this producer's entry holds the same generation.
    none(Vec::new(), &three)
        .says(&world, "1 none", "offered 3")
        .await;
    with(Vec::new(), elsewhere.clone(), &three)
        .says(&world, "1 another producer's entry", "offered 3")
        .await;
    with(Vec::new(), own(&five), &three)
        .says(&world, "1 control", "replayed under 5 by host 42")
        .await;

    // Row 2: no bundle checkpoint, an entry E. A generation below E is held back; another
    // manifest at E's generation is its own state; E's own manifest and a newer generation are offered.
    let e5 = || own(&five);
    with(Vec::new(), e5(), &three)
        .says(&world, "2 below", "replayed under 5 by host 42")
        .await;
    with(Vec::new(), e5(), &five_other)
        .says(&world, "2 other manifest", "other manifest at 5 by host 42")
        .await;
    with(Vec::new(), e5(), &five)
        .says(&world, "2 the same", "offered 5")
        .await;
    with(Vec::new(), e5(), &six)
        .says(&world, "2 above", "offered 6")
        .await;

    // Row 3: a bundle checkpoint and no entry of this producer: the bundle's rule as it was.
    none(vec![&five], &three)
        .says(&world, "3 below", "replayed under 5 by bundle")
        .await;
    none(vec![&five], &five)
        .says(&world, "3 the same", "offered 5")
        .await;
    with(vec![&five], elsewhere.clone(), &three)
        .says(
            &world,
            "3 another producer's entry",
            "replayed under 5 by bundle",
        )
        .await;

    // Row 4: E above B: the floor is E, from the host. A split of the bundle's own is dropped.
    let e9 = || own(&nine);
    with(vec![&five], e9(), &six)
        .says(&world, "4 below E", "replayed under 9 by host 42")
        .await;
    with(vec![&five], e9(), &three)
        .says(&world, "4 below B", "replayed under 9 by host 42")
        .await;
    with(vec![&five], e9(), &nine)
        .says(&world, "4 at E", "offered 9")
        .await;
    with(vec![&five, &five_other], e9(), &six)
        .says(&world, "4 with a split", "replayed under 9 by host 42")
        .await;
    none(vec![&five, &five_other], &five)
        .says(&world, "4 the split alone", "bundle disagrees at 5")
        .await;

    // Row 5: E equals B with the same manifest: the bundle's.
    with(vec![&five], own(&five), &three)
        .says(&world, "5 below", "replayed under 5 by bundle")
        .await;
    with(vec![&five], own(&five), &five)
        .says(&world, "5 at", "offered 5")
        .await;

    // Row 6: E equals B with another manifest: that generation is a disagreement, the others
    // stand against B; the bundle's own split wins over the host's.
    for served in [&five, &five_other] {
        with(vec![&five], own(&five_other), served)
            .says(&world, "6 at the generation", "disagrees at 5 with host 42")
            .await;
    }
    with(vec![&five], own(&five_other), &six)
        .says(&world, "6 above", "offered 6")
        .await;
    with(vec![&five], own(&five_other), &three)
        .says(&world, "6 below", "replayed under 5 by bundle")
        .await;
    with(vec![&five, &five_other], own(&five_third), &five)
        .says(
            &world,
            "6 the bundle's own split wins",
            "bundle disagrees at 5",
        )
        .await;

    // Row 7: E below B: B, and E is ignored.
    with(vec![&nine], own(&five), &six)
        .says(&world, "7 below B", "replayed under 9 by bundle")
        .await;
    with(vec![&nine], own(&five), &nine)
        .says(&world, "7 at B", "offered 9")
        .await;
}

/// KR-REQ-20.12: of two entries of one producer at one generation, the smaller manifest hash
/// holds, and at one hash the smaller endpoint is the holder named, whatever order the entries are
/// kept in.
#[tokio::test]
async fn a_tie_of_two_entries_is_decided_by_the_hash_and_then_the_endpoint_in_either_order() {
    let world = World::new();
    let members = honest_members();
    let one = world.seal(5, &members);
    let two = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let three = world.seal(3, &members);
    let (small, large) = if checkpoint_of(&one).encrypted_manifest_hash.as_bytes()
        < checkpoint_of(&two).encrypted_manifest_hash.as_bytes()
    {
        (&one, &two)
    } else {
        (&two, &one)
    };
    let at =
        |endpoint: u8, sealed: &Sealed| entry_of(endpoint, world_producer().key_id(), 5, sealed);

    // Two manifests, two hosts: the smaller hash holds, and its host is the one named.
    for entries in [
        vec![at(0x42, small), at(0x52, large)],
        vec![at(0x52, large), at(0x42, small)],
        vec![at(0x52, small), at(0x42, large)],
        vec![at(0x42, large), at(0x52, small)],
    ] {
        let holder = entries
            .iter()
            .find(|entry| {
                entry.encrypted_manifest_hash == checkpoint_of(small).encrypted_manifest_hash
            })
            .map(|entry| entry.host_endpoint_id.as_bytes()[0])
            .expect("the entry of the smaller hash");
        let scenario = |served| Scenario {
            bundle: Vec::new(),
            entries: entries.clone(),
            served: Some(served),
            accept: None,
        };
        scenario(small)
            .says(&world, "the smaller hash is offered", "offered 5")
            .await;
        scenario(large)
            .says(
                &world,
                "the larger hash is another manifest",
                &format!("other manifest at 5 by host {holder:02x}"),
            )
            .await;
        scenario(&three)
            .says(
                &world,
                "an older generation is held back",
                &format!("replayed under 5 by host {holder:02x}"),
            )
            .await;
    }

    // One manifest, two hosts: the smaller endpoint is the holder named.
    for entries in [
        vec![at(0x42, small), at(0x52, small)],
        vec![at(0x52, small), at(0x42, small)],
    ] {
        Scenario {
            bundle: Vec::new(),
            entries,
            served: Some(&three),
            accept: None,
        }
        .says(
            &world,
            "the smaller endpoint",
            "replayed under 5 by host 42",
        )
        .await;
    }
}

/// A publication of `sealed` whose signature does not hold: the payload changed after it was
/// signed.
fn badly_signed(sealed: &Sealed) -> Sealed {
    let mut publication = sealed.publication.clone();
    publication.payload.published_at_ms = TimestampMs::new(6_000);
    Sealed {
        publication,
        objects: sealed.objects.clone(),
        manifest_object: sealed.manifest_object,
    }
}

/// KR-REQ-20.12: a publication that fails its signature gets no host, whatever an entry
/// says: it fails as a signature, nothing is held against it, and no host is named.
#[tokio::test]
async fn a_bad_signature_with_a_matching_high_entry_fails_as_a_signature_and_names_no_host() {
    let world = World::new();
    let members = honest_members();
    let older = world.seal(3, &members);
    let nine = world.seal(9, &members);
    let held = held_with(vec![given_by_a_host(&nine)]);
    let forged = badly_signed(&older);
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&forged)
            .honouring_the_hold(),
    );

    assert!(matches!(
        restore_held(&world, &source, None, &held)
            .await
            .expect_err("a bad signature"),
        RestoreError::Publication(PublicationRefusal::BadSignature)
    ));
    let listed = list(&world, &source, &held).await;
    assert!(
        matches!(
            listed[0].newest,
            CandidateState::Refused(PublicationRefusal::BadSignature)
        ),
        "the list says the signature failed"
    );
    assert_eq!(
        listed[0].pairing,
        PairingStanding::None,
        "an unverified publication names no producer, so no host's entry is named"
    );
    assert_eq!(source.object_reads(), 0);

    // Control: the same publication, signed, is held back by the same entry, and its host is named.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    assert!(replayed_under(
        &restore_held(&world, &source, None, &held)
            .await
            .expect_err("held back"),
        9
    ));
    assert_eq!(
        list(&world, &source, &held).await[0].pairing,
        PairingStanding::Held {
            generation: BackupGeneration::new(9)
        }
    );
}

/// KR-REQ-20.12: a service that holds no publication is nothing, with and without a bundle
/// checkpoint; only the bundle's checkpoint is named, and no entry is.
#[tokio::test]
async fn a_service_that_holds_no_publication_is_nothing_with_and_without_the_bundles_checkpoint() {
    let world = World::new();
    let members = honest_members();
    let five = world.seal(5, &members);
    let held = held_with(vec![given_by_a_host(&five)]);

    // No checkpoint of the bundle: one ask, unheld, and the restore finds no generation at all.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    assert!(matches!(
        restore_held(&world, &source, None, &held)
            .await
            .expect_err("nothing"),
        RestoreError::NoGeneration
    ));
    assert_eq!(
        source.generation_asks(),
        vec![format!("generation {} unheld", archive())]
    );
    let listed = list(&world, &source, &held).await;
    assert!(matches!(listed[0].newest, CandidateState::Nothing));
    assert_eq!(
        listed[0].pairing,
        PairingStanding::None,
        "a service that holds nothing names no producer"
    );

    // A checkpoint of the bundle: asked held to it, then once more without, and the refusal is the
    // bundle's.
    let at_five = || {
        world.bundle(&Shape {
            checkpoint: Some(checkpoint_of(&five)),
            ..Shape::default()
        })
    };
    let source = Arc::new(Scripted::serving(&world, at_five()));
    assert!(matches!(
        restore_held(&world, &source, None, &held)
            .await
            .expect_err("nothing"),
        RestoreError::NothingAsNewAsTheCheckpoint { checkpoint: 5 }
    ));
    assert_eq!(source.generation_asks().len(), 2);
    assert!(source.generation_asks()[0].contains("held to generation 5"));
    assert!(source.generation_asks()[1].ends_with("unheld"));
    assert!(matches!(
        list(&world, &source, &held).await[0].newest,
        CandidateState::Nothing
    ));

    // Owed, with no publication: still owed.
    let owed = Held::Read {
        entries: Vec::new(),
        owed: 1,
        listed: Vec::new(),
    };
    assert_eq!(
        list(&world, &source, &owed).await[0].pairing,
        PairingStanding::Owed
    );
}

/// KR-REQ-20.12: the generation a person names to accept is read after the producer is, so
/// an entry that counts for the archive makes room for it and one that does not leaves none.
#[tokio::test]
async fn an_accepted_older_generation_is_judged_after_the_producer_is_read() {
    let world = World::new();
    let members = honest_members();
    let three = world.seal(3, &members);
    let five = world.seal(5, &members);
    let two_senders = with_senders(&world, &three, &[another_producer()]);
    let held = held_with(vec![given_by_a_host(&five)]);
    let serving = |sealed: &Sealed| {
        Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default()))
                .publishing(sealed)
                .honouring_the_hold(),
        )
    };

    // One producer, which the entry names: the entry's checkpoint is there to accept past.
    let prepared = restore_held(&world, &serving(&three), Some(3), &held)
        .await
        .expect("the named generation is accepted past the host's checkpoint");
    assert!(matches!(
        prepared.plan().standing.standing,
        GenerationStanding::OlderAccepted { .. }
    ));

    // Two producers: no producer, so the entry is no checkpoint, and there is none to accept past.
    let error = restore_held(&world, &serving(&two_senders), Some(3), &held)
        .await
        .expect_err("no checkpoint counts for this archive");
    assert!(
        matches!(
            error,
            RestoreError::NoCheckpointToAcceptPast {
                pairing_consulted: true,
                ..
            }
        ),
        "{error}"
    );

    // A service that holds nothing: the answer is the service's, before any word is weighed.
    let empty = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    assert!(matches!(
        restore_held(&world, &empty, Some(3), &held)
            .await
            .expect_err("nothing"),
        RestoreError::NoGeneration
    ));
}

/* -------------------------------------------------------------------------- */
/* What the form does not stop                                                 */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.12: a host that is wrong about its own archive holds it back for ever and
/// nothing lowers the entry: a later, lower answer of the same host changes nothing, and the
/// restore stays refused, while a restore from the bundle's record alone is the way that exists.
#[tokio::test]
async fn an_archive_held_back_by_a_host_that_was_wrong_keeps_its_entry_and_no_call_lowers_it() {
    let world = World::new();
    let members = honest_members();
    let five = world.seal(5, &members);
    let six = world.seal(6, &members);
    let nine = world.seal(9, &members);
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let owner = an_unlisted_owner();
    hosts.record(owner.clone()).expect("a paired host");
    let answer = |sealed: &Sealed| {
        let given = given_by_a_host(sealed);
        Answer::Checkpoint(HostCheckpoint {
            service_origin: given.service_origin,
            archive_id: given.archive_id,
            backup_generation: given.backup_generation,
            encrypted_manifest_hash: given.encrypted_manifest_hash,
        })
    };
    let serving = |sealed: &Sealed| {
        Arc::new(
            Scripted::serving(&world, world.bundle(&Shape::default()))
                .publishing(sealed)
                .honouring_the_hold(),
        )
    };
    let checkpoints = hosts.checkpoints();
    checkpoints
        .settle_checkpoint(&owner, &answer(&nine), 3_000)
        .expect("the host names a generation the service never held");

    // The service holds 6: held back by the host's 9.
    let held = checkpoints.held_checkpoints();
    let error = restore_held(&world, &serving(&six), None, &held)
        .await
        .expect_err("held back");
    assert!(replayed_under(&error, 9), "{error}");

    // The host later says 5, which is what the service holds: no call lowers the entry.
    checkpoints
        .settle_checkpoint(&owner, &answer(&five), 4_000)
        .expect("a lower answer is taken as no change");
    let Held::Read { entries, .. } = checkpoints.held_checkpoints() else {
        panic!("the checkpoints are read")
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].backup_generation.get(), 9);
    let error = restore_held(
        &world,
        &serving(&six),
        None,
        &checkpoints.held_checkpoints(),
    )
    .await
    .expect_err("still held back");
    assert!(replayed_under(&error, 9), "{error}");

    // The way that exists: the same restore held to the bundle's own record alone goes on.
    let prepared = restore_held(&world, &serving(&six), None, &Held::Absent)
        .await
        .expect("a restore under the bundle's own record");
    assert_eq!(prepared.plan().generation.get(), 6);
}

/// KR-REQ-20.12: a writer the kit trusts can serve its own signed publication that names
/// no producer; no entry counts for it, so it is offered above the bundle's checkpoint, and the
/// restore refuses it for want of a wrap: listing is not restoring.
#[tokio::test]
async fn a_trusted_writers_publication_with_no_producer_is_listed_above_the_floor_and_not_restored()
{
    let world = World::new();
    let members = honest_members();
    let five = world.seal(5, &members);
    let six = world.seal(6, &members);
    let bare = without_wraps(&world, &six);
    let held = held_with(vec![given_by_a_host(&world.seal(9, &members))]);
    let bundle = world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&five)),
        ..Shape::default()
    });
    let source = Arc::new(
        Scripted::serving(&world, bundle)
            .publishing(&bare)
            .honouring_the_hold(),
    );

    assert!(matches!(
        list(&world, &source, &held).await[0].newest,
        CandidateState::Newest(ref newest) if newest.generation.get() == 6
    ));
    assert!(matches!(
        restore_held(&world, &source, None, &held)
            .await
            .expect_err("no wrap"),
        RestoreError::NoWrap
    ));
    assert_eq!(source.object_reads(), 0, "nothing was read");
}

/// KR-REQ-20.12: an archive whose producer this device holds no entry of is held to the
/// bundle's floor alone: with no entries at all, with the entries of other hosts, and with no
/// snapshot, it is offered.
#[tokio::test]
async fn an_archive_of_a_producer_no_entry_names_is_offered_under_the_bundles_floor_alone() {
    let world = World::new();
    let members = honest_members();
    let three = world.seal(3, &members);
    let nine = world.seal(9, &members);
    let others = [
        held_with(Vec::new()),
        held_with(vec![entry_of(0x52, another_producer(), 9, &nine)]),
        Held::Absent,
    ];
    for held in &others {
        let source =
            Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&three));
        let prepared = restore_held(&world, &source, None, held)
            .await
            .expect("no entry counts for this producer, so the older generation is offered");
        assert_eq!(prepared.plan().generation.get(), 3);
        assert!(matches!(
            list(&world, &source, held).await[0].newest,
            CandidateState::Newest(_)
        ));
    }

    // A host that is no longer listed still holds its own archive: forgetting changes no floor.
    let forgotten = Held::Read {
        entries: vec![given_by_a_host(&nine)],
        owed: 0,
        listed: Vec::new(),
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&three));
    assert!(replayed_under(
        &restore_held(&world, &source, None, &forgotten)
            .await
            .expect_err("held back"),
        9
    ));
}

/// KR-REQ-20.12: which host holds a generation is data on the state and never in the words or the
/// digest: two hosts that gave the same checkpoint make the same sentence and the same plan digest.
#[tokio::test]
async fn the_host_that_holds_is_data_and_changes_no_word_and_no_digest() {
    let world = World::new();
    let members = honest_members();
    let five = world.seal(5, &members);
    let six = world.seal(6, &members);
    let three = world.seal(3, &members);
    let by = |endpoint: u8| entry_of(endpoint, world_producer().key_id(), 5, &five);

    let mut digests = Vec::new();
    let mut words = Vec::new();
    let mut holders = Vec::new();
    for endpoint in [0x42, 0x52] {
        let held = held_with(vec![by(endpoint)]);
        // The plan of a newer generation, ahead of the host's checkpoint.
        let source =
            Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&six));
        let prepared = restore_held(&world, &source, None, &held)
            .await
            .expect("ahead of the host's checkpoint");
        digests.push(
            prepared
                .plan()
                .digest("env", b"/restore/a", "")
                .expect("a digest"),
        );
        words.push(prepared.plan().standing.describe());
        holders.push(prepared.plan().standing.source);
        // The refusal of an older generation reads alike for both, and names the host as data.
        let source =
            Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&three));
        let error = restore_held(&world, &source, None, &held)
            .await
            .expect_err("held back");
        words.push(error.to_string());
        let RestoreError::Publication(PublicationRefusal::Generation(standing, _)) = &error else {
            panic!("{error}")
        };
        holders.push(standing.source);
    }
    assert_eq!(
        digests[0], digests[1],
        "the plan digest does not name the host"
    );
    assert_eq!(
        words[0], words[2],
        "the standing reads alike for either host"
    );
    assert_eq!(
        words[1], words[3],
        "the refusal reads alike for either host"
    );
    assert_eq!(
        holders,
        vec![
            Some(CheckpointSource::Pairing(EndpointKey::from_bytes(
                [0x42; 32]
            ))),
            Some(CheckpointSource::Pairing(EndpointKey::from_bytes(
                [0x42; 32]
            ))),
            Some(CheckpointSource::Pairing(EndpointKey::from_bytes(
                [0x52; 32]
            ))),
            Some(CheckpointSource::Pairing(EndpointKey::from_bytes(
                [0x52; 32]
            ))),
        ],
        "the host is data on the standing and on the refusal"
    );
}

/// KR-REQ-20.12: the digest a person confirms is a fixed value for a fixed plan, and the host that
/// holds the checkpoint is not in it. The standing's sentence is the one text of the digest that
/// comes from the checkpoint's source, and it is the same for every host.
#[test]
fn the_digest_of_a_plan_held_by_a_host_is_a_fixed_value_that_names_no_host() {
    let plan = |source: CheckpointSource| RestorePlan {
        origin: ORIGIN.to_owned(),
        archive_id: archive(),
        generation: BackupGeneration::new(6),
        manifest_hash: Digest256::from_bytes([0x22; 32]),
        writer: KeyId::from_bytes([0x33; 32]),
        standing: RestoreGeneration {
            archive_id: archive(),
            backup_generation: BackupGeneration::new(6),
            standing: GenerationStanding::Ahead {
                checkpoint: BackupGeneration::new(5),
            },
            source: Some(source),
        },
        pairing: PairingStanding::None,
        bundle_revision: 1,
        published_at_ms: TimestampMs::new(1_700_000_000_000),
        members: vec![PlannedMember {
            object_id: BackupObjectId::new(id(0x20)),
            stored_len: 41,
            plaintext_len: Some(10),
            verdict: MemberVerdict::Restore {
                role: MemberRole::Configuration,
                file: "configuration.json".to_owned(),
            },
        }],
    };
    let host = |byte: u8| CheckpointSource::Pairing(EndpointKey::from_bytes([byte; 32]));
    let digest = |source| {
        plan(source)
            .digest("env", b"/restore/a", "")
            .expect("a digest")
    };

    assert_eq!(
        plan(host(0x42)).standing.describe(),
        "Restoring backup generation 6. It is newer than generation 5, the newest that a host \
         this device paired with reported when this device asked. No restore can show that the \
         service is not holding a newer backup back.",
        "the sentence the digest covers"
    );
    assert_eq!(
        digest(host(0x42)),
        "fa6a899689ee2a1f0dc21ff395f59eec4d7c9de0179c2abdad4a818b5995e2e2",
        "a plan held by a host"
    );
    assert_eq!(
        digest(host(0x52)),
        digest(host(0x42)),
        "no host is in the digest"
    );
    assert_eq!(
        digest(CheckpointSource::RecoveryBundle),
        "3a08d8954d76476f6cc7404e3a863d43acb280b9aafaf72547b6b709458f76b3",
        "a plan held by the bundle"
    );
}

/// KR-REQ-20.12: one endpoint that answered under two producers holds one entry for each,
/// through the store, and a restore of each producer's archive is held by its own entry alone.
#[tokio::test]
async fn one_endpoint_under_two_producers_holds_each_archive_by_its_own_entry() {
    let members = honest_members();
    let first = World::new();
    let second = World {
        producer: StoredEnvelopeKeyPair::generate().expect("a producer key"),
        ..World::new()
    };
    let (first_five, first_three, first_six) = (
        first.seal(5, &members),
        first.seal(3, &members),
        first.seal(6, &members),
    );
    let (second_nine, second_three) = (second.seal(9, &members), second.seal(3, &members));

    // The same endpoint, paired twice: the second record declares the second producer's key.
    let (owner_first, mut owner_second) = (an_unlisted_owner(), an_unlisted_owner());
    owner_second.host_keys.stored_envelope = *second.producer.public();
    let answer = |sealed: &Sealed| {
        let given = given_by_a_host(sealed);
        Answer::Checkpoint(HostCheckpoint {
            service_origin: given.service_origin,
            archive_id: given.archive_id,
            backup_generation: given.backup_generation,
            encrypted_manifest_hash: given.encrypted_manifest_hash,
        })
    };
    let directory = tempfile::tempdir().expect("a directory");
    let checkpoints = PairedCheckpoints::open(directory.path().join("pairing")).expect("a store");
    checkpoints
        .settle_checkpoint(&owner_first, &answer(&first_five), 3_000)
        .expect_err("no list holds the pairing, so it settles none");
    checkpoints
        .settle_checkpoint(&owner_second, &answer(&second_nine), 4_000)
        .expect_err("no list holds the pairing, so it settles none");
    let held = checkpoints.held_checkpoints();
    let Held::Read { entries, .. } = &held else {
        panic!("the checkpoints are read")
    };
    assert_eq!(
        entries.len(),
        2,
        "one entry for each producer of the endpoint"
    );

    let serving = |world: &World, sealed: &Sealed| {
        Arc::new(
            Scripted::serving(world, world.bundle(&Shape::default()))
                .publishing(sealed)
                .honouring_the_hold(),
        )
    };
    // The first producer's archive is held by its own entry, 5, and not by the second's, 9.
    let error = restore_held(&first, &serving(&first, &first_three), None, &held)
        .await
        .expect_err("held back by the first producer's entry");
    assert!(replayed_under(&error, 5), "{error}");
    restore_held(&first, &serving(&first, &first_six), None, &held)
        .await
        .expect("generation 6 is ahead of the first producer's entry, whatever the second holds");
    // The second producer's archive is held by its own entry, 9.
    let error = restore_held(&second, &serving(&second, &second_three), None, &held)
        .await
        .expect_err("held back by the second producer's entry");
    assert!(replayed_under(&error, 9), "{error}");
}
