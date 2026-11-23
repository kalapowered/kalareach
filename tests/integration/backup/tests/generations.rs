//! The generation producer the retention legs use, held to what a restore reads.
//!
//! The retention legs run against a deployment and skip without one. The producer they depend on
//! is shown here against the stand-in for the managed storage and backup manifest services, so a
//! change to it fails an ordinary test run: each generation it publishes is chained by the service
//! and is opened with the recovery kit's seed alone, against the writer and the producer the
//! restored bundle names, and the member it staged comes out unchanged. The writer is enrolled only
//! after the bundle that names it has landed, and a bundle that does not land enrols nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_backup_integration::DeviceSigner;
use kr_backup_integration::generations::{ArchiveServices, Collection, Generations};
use kr_client::ClientError;
use kr_client::recovery::{
    BundleStore, FreshRestore, RecoveryError, RetrievalPolicy, ServiceAccess,
};
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::backup::{
    Enrolled, FetchedGeneration, ManagedBackupManifestService, Published,
};
use kr_client::services::storage::{ArchiveAnswer, ManagedStorageService};
use kr_client::services::{
    BackupManifestService, ServiceFuture, ServiceSigner, StorageService, SyncBackupService,
    SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence, SyncRequestStatus, SyncRevision,
};
use kr_crypto::backup::{ArchiveExpectation, ArchiveReader, GenerationExpectation, open_archive};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::archive::{
    BackupGenerationPublication, BackupWriterRecord, RecoveryBundle, RecoveryContext,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupWriterRevision, DeviceId};
use kr_protocol::pairing::GenerationCheckpoint;
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_service_stand_in::{ServiceWeb, TOKEN};

const ORIGIN: &str = "https://reach.kala.to";
const MEMBER_NAME: &str = "retention/member.bin";

/// The account's token for `backup.write`.
#[derive(Debug)]
struct Tokens;

impl AccountTokenSource for Tokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = if scope == "backup.write" {
            AccountToken::new(TOKEN)
        } else {
            Err(ClientError::Host(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("this sign-in was not granted the {scope} scope"),
            )))
        };
        Box::pin(async move { token })
    }
}

/// The sync service holding the one recovery bundle: bytes and a place in the order.
#[derive(Debug, Default)]
struct Bundles {
    held: Mutex<BTreeMap<String, (u64, Vec<u8>)>>,
    /// Whether it refuses every write, as one does that finds the bundle moved.
    refuses: Mutex<bool>,
}

impl Bundles {
    /// The sealed bundle it holds now, if it holds one.
    fn sealed(&self) -> Option<Vec<u8>> {
        self.held
            .lock()
            .expect("the bundles")
            .values()
            .next()
            .map(|(_, ciphertext)| ciphertext.clone())
    }
}

/// The manifest service the producer enrols with. It notes the sealed bundle the sync service held
/// each time a writer was enrolled, and passes every call on.
#[derive(Debug)]
struct Watching {
    inner: ManagedBackupManifestService,
    bundles: Arc<Bundles>,
    /// One entry for each enrolment: the sealed bundle held then, or none.
    enrolments: Mutex<Vec<Option<Vec<u8>>>>,
}

impl BackupManifestService for Watching {
    fn enrol<'a>(&'a self, record: &'a BackupWriterRecord) -> ServiceFuture<'a, Enrolled> {
        self.enrolments
            .lock()
            .expect("the enrolments")
            .push(self.bundles.sealed());
        self.inner.enrol(record)
    }

    fn publish<'a>(
        &'a self,
        publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, ArchiveAnswer<Published>> {
        self.inner.publish(publication)
    }

    fn fetch<'a>(
        &'a self,
        archive_id: ArchiveId,
        generation: Option<BackupGeneration>,
        checkpoint: Option<&'a GenerationCheckpoint>,
    ) -> ServiceFuture<'a, Option<FetchedGeneration>> {
        self.inner.fetch(archive_id, generation, checkpoint)
    }
}

fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes(
            [u8::try_from(write_sequence).expect("few"); 16],
        )),
        None,
    )
}

fn refusal() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::UnsupportedCapability,
        "this service keeps bundles and nothing else",
    ))
}

impl SyncBackupService for Bundles {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        _request_id: Uuid,
        _signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let mut held = self.held.lock().expect("the bundles");
            let current = held.get(collection).map(|(place, _)| at(*place));
            if current != expected || *self.refuses.lock().expect("a flag") {
                return Ok(SyncExchanged::Refused {
                    retained: None,
                    current,
                    recovery: None,
                });
            }
            let next = held.get(collection).map_or(1, |(place, _)| place + 1);
            held.insert(collection.to_owned(), (next, ciphertext.to_vec()));
            Ok(SyncExchanged::Applied { position: at(next) })
        })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async { Err(refusal()) })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async { Err(refusal()) })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            Ok(self
                .held
                .lock()
                .expect("the bundles")
                .get(collection)
                .map_or(
                    SyncFetched::Absent { recovery: None },
                    |(place, ciphertext)| SyncFetched::Held {
                        position: at(*place),
                        ciphertext: ciphertext.clone(),
                    },
                ))
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: kr_protocol::ids::SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

fn now() -> TimestampMs {
    TimestampMs::new(1_700_000_000_000)
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x5e; 16]))
}

/// The device, the services and the recovery material a case starts from.
struct Case {
    web: Arc<ServiceWeb>,
    keys: DeviceKeys,
    signer: Arc<DeviceSigner>,
    origin: GatewayOrigin,
    /// The sync service that holds the bundle.
    service: Arc<Bundles>,
    /// The manifest service the writer is enrolled with.
    manifest: Watching,
    seed: RecoverySeed,
    locator: String,
    store: BundleStore,
    _disk: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let web = Arc::new(ServiceWeb::new());
        web.set_backup(true);
        let keys = DeviceKeys::generate().expect("a device's keys");
        let signer = Arc::new(DeviceSigner::new(keys.clone()));
        let origin = GatewayOrigin::new(ORIGIN).expect("an origin");
        let service = Arc::new(Bundles::default());
        let manifest = Watching {
            inner: ManagedBackupManifestService::new(
                origin.clone(),
                Arc::clone(&web) as Arc<_>,
                Arc::clone(&signer) as Arc<dyn ServiceSigner>,
            )
            .presenting(Arc::new(Tokens)),
            bundles: Arc::clone(&service),
            enrolments: Mutex::default(),
        };
        let seed = RecoverySeed::generate().expect("a seed");
        let locator = kr_client::recovery::fresh_locator().expect("a locator");
        let disk = tempfile::tempdir().expect("a directory on the internal disk");
        let store = BundleStore::open(
            Arc::clone(&service) as Arc<dyn SyncBackupService>,
            RecoveryContext {
                service_origin: ORIGIN.to_owned(),
                bundle_locator: locator.clone(),
            },
            disk.path(),
        )
        .expect("the bundle store");
        Self {
            web,
            keys,
            signer,
            origin,
            service,
            manifest,
            seed,
            locator,
            store,
            _disk: disk,
        }
    }

    /// Enables the writer the way the retention legs do.
    async fn enable(&mut self, bundle: &mut RecoveryBundle) -> Result<Generations, RecoveryError> {
        let recovery = self.seed.recipient().expect("the recovery recipient");
        let collection = Collection {
            archive_id: archive_id(),
            service_origin: ORIGIN.to_owned(),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            writer: self.keys.authorisation.clone(),
            writer_revision: BackupWriterRevision::new(1),
            producer: self.keys.stored_envelope.clone(),
            recovery: *recovery.public(),
        };
        Generations::enable(
            collection,
            &mut self.store,
            &self.seed,
            bundle,
            &self.keys.authorisation,
            &self.manifest,
            now(),
        )
        .await
    }

    /// What a restore that holds only the kit's seed reads from the bundle the service holds.
    async fn restored_bundle(&self) -> kr_client::recovery::TrustedMaterial {
        let kit = self
            .seed
            .to_kit(vec![ORIGIN.to_owned()], self.locator.clone());
        let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
        restore
            .obtained_access(ServiceAccess::new(
                RetrievalPolicy::Account,
                ORIGIN,
                Arc::clone(&self.service) as Arc<dyn SyncBackupService>,
            ))
            .expect("access to the service");
        restore
            .open_bundle(ORIGIN)
            .await
            .expect("the restore opens the bundle")
    }
}

/// KR-REQ-20.15, KR-REQ-20.22: the writer is enrolled once, after the bundle that names it and its
/// producer has landed, and the bundle a restore reads is the one that names them.
#[tokio::test]
async fn the_producer_enrols_its_writer_only_after_the_bundle_naming_it_has_landed() {
    let mut case = Case::new();
    let mut bundle = BundleStore::empty(now());
    case.enable(&mut bundle).await.expect("the bundle landed");

    // What the sync service held when the writer was enrolled: the bundle that names the writer, the
    // producer and the collection.
    let enrolments = case
        .manifest
        .enrolments
        .lock()
        .expect("the enrolments")
        .clone();
    let [Some(held)] = enrolments.as_slice() else {
        panic!(
            "the writer is enrolled once, with the bundle held: {} enrolments",
            enrolments.len()
        );
    };
    let key = case
        .seed
        .bundle_key_for(&RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: case.locator.clone(),
        })
        .expect("the bundle's key");
    let named = kr_crypto::archive::decrypt_recovery_bundle(&key, held).expect("the bundle opens");
    assert!(
        named
            .trusted_writers
            .iter()
            .any(|writer| writer.writer_key_id == case.keys.authorisation.key_id()),
        "the bundle held at the enrolment names the writer"
    );
    assert!(
        named
            .trusted_producers
            .iter()
            .any(|producer| producer.sender_key_id == case.keys.stored_envelope.key_id()),
        "and the producer"
    );
    assert_eq!(named.collections.len(), 1);

    // A restore reads the same names from the service.
    let material = case.restored_bundle().await;
    assert_eq!(material.trusted_writers.len(), 1);
    assert_eq!(material.trusted_producers.len(), 1);
    assert_eq!(
        material.trusted_writers[0].writer_key_id,
        case.keys.authorisation.key_id()
    );
    assert_eq!(
        material.trusted_producers[0].sender_key_id,
        case.keys.stored_envelope.key_id()
    );
}

/// KR-REQ-20.15: a bundle that does not land enrols nothing. Once it lands the writer is enrolled,
/// and not before.
#[tokio::test]
async fn a_bundle_that_does_not_land_enrols_no_writer() {
    let mut case = Case::new();
    let mut bundle = BundleStore::empty(now());
    *case.service.refuses.lock().expect("a flag") = true;
    let refused = case.enable(&mut bundle).await;
    assert!(
        matches!(refused, Err(RecoveryError::BundleConflict { .. })),
        "{:?}",
        refused.err()
    );
    assert!(
        case.manifest
            .enrolments
            .lock()
            .expect("the enrolments")
            .is_empty(),
        "no writer is enrolled for a bundle that did not land"
    );
    assert!(
        case.service.sealed().is_none(),
        "the service holds no bundle"
    );

    *case.service.refuses.lock().expect("a flag") = false;
    case.enable(&mut bundle).await.expect("the bundle landed");
    assert_eq!(
        case.manifest
            .enrolments
            .lock()
            .expect("the enrolments")
            .len(),
        1,
        "the writer is enrolled once the bundle has landed"
    );
}

/// KR-REQ-20.22: each generation the producer publishes is chained by the service as a device's
/// own would be, and a restore that holds only the kit's seed opens the newest against the writer
/// and the producer the restored bundle names, and gets the member the producer staged, under the
/// name it was staged under.
#[tokio::test]
async fn the_producer_makes_generations_the_service_chains_and_a_restore_opens() {
    let mut case = Case::new();
    let mut bundle = BundleStore::empty(now());
    let generations = case.enable(&mut bundle).await.expect("the bundle landed");

    let services = ArchiveServices {
        origin: case.origin.clone(),
        http: Arc::clone(&case.web) as Arc<_>,
        signer: Arc::clone(&case.signer) as Arc<dyn ServiceSigner>,
        tokens: Arc::new(Tokens),
    };
    let member = vec![0x5a_u8; 1024];
    for generation in 1..=2 {
        let published = generations
            .back_up(
                MEMBER_NAME,
                &member,
                BackupGeneration::new(generation),
                &services,
                now(),
            )
            .await;
        assert!(!published.duplicate);
        assert_eq!(published.collection.checkpoint_generation, generation);
        assert_eq!(published.collection.generations.len() as u64, generation);
    }

    // The newest generation, opened with the kit's seed alone.
    let found = case
        .manifest
        .fetch(archive_id(), None, None)
        .await
        .expect("a fetch")
        .expect("the newest generation");
    assert_eq!(found.collection.checkpoint_generation, 2);
    let descriptor_bytes =
        kr_cbor::to_canonical_vec(&found.publication.payload.descriptor).expect("a descriptor");
    let descriptor = kr_crypto::backup::read_descriptor(&descriptor_bytes).expect("a descriptor");
    let reference = &descriptor.encrypted_manifest;
    let storage = ManagedStorageService::new(
        case.origin.clone(),
        Arc::clone(&case.web) as Arc<_>,
        Arc::clone(&case.signer) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens));
    let encrypted_manifest = StorageService::read_object(
        &storage,
        archive_id(),
        reference.object_id,
        0,
        reference.encrypted_len.get(),
    )
    .await
    .expect("the manifest reads")
    .bytes;

    // The writer and the producer are the ones the restored bundle names, not the producer's own.
    let material = case.restored_bundle().await;
    let [producer] = material.trusted_producers.as_slice() else {
        panic!("the bundle names one producer");
    };
    let recovery = case.seed.recipient().expect("the recovery recipient");
    let reader = ArchiveReader::Recovery(&recovery);
    let opened = open_archive(
        &reader,
        &producer.stored_envelope_key,
        &material.trusted_writers,
        &ArchiveExpectation {
            archive_id: archive_id(),
            generation: GenerationExpectation::Unverified,
        },
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the archive opens with the kit's seed alone");
    let [staged] = opened.objects() else {
        panic!("one member");
    };
    assert_eq!(staged.filename, MEMBER_NAME);
    let stored = StorageService::read_object(
        &storage,
        archive_id(),
        staged.object.object_id,
        0,
        staged.object.encrypted_len.get(),
    )
    .await
    .expect("the member reads")
    .bytes;
    let restored = opened
        .restore_object(
            &reader,
            &producer.stored_envelope_key,
            staged.object.object_id,
            &stored,
        )
        .expect("the member restores");
    assert_eq!(restored.plaintext.expose(), member.as_slice());
}
