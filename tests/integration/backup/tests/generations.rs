//! The generation producer the retention legs use, held to what a restore reads.
//!
//! The retention legs run against a deployment and skip without one. The producer they depend on
//! is shown here against the stand-in for the managed storage and backup manifest services, so a
//! change to it fails an ordinary test run: each generation it publishes is chained by the service
//! and is opened with the recovery kit's seed alone, and the member it staged comes out unchanged.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_backup_integration::DeviceSigner;
use kr_backup_integration::generations::{ArchiveServices, Collection, Generations};
use kr_client::ClientError;
use kr_client::recovery::BundleStore;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::backup::ManagedBackupManifestService;
use kr_client::services::storage::ManagedStorageService;
use kr_client::services::{
    BackupManifestService, ServiceFuture, ServiceSigner, StorageService, SyncBackupService,
    SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence, SyncRequestStatus, SyncRevision,
};
use kr_crypto::backup::{ArchiveExpectation, ArchiveReader, GenerationExpectation, open_archive};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::archive::RecoveryContext;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupWriterRevision, DeviceId};
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
            if current != expected {
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

/// KR-REQ-20.22: each generation the producer publishes is chained by the service as a device's
/// own would be, and a restore that holds only the kit's seed opens the newest and gets the member
/// the producer staged, under the name it was staged under.
#[tokio::test]
async fn the_producer_makes_generations_the_service_chains_and_a_restore_opens() {
    let web = Arc::new(ServiceWeb::new());
    web.set_backup(true);
    let keys = DeviceKeys::generate().expect("a device's keys");
    let signer = Arc::new(DeviceSigner::new(keys.clone()));
    let origin = GatewayOrigin::new(ORIGIN).expect("an origin");
    let manifest = ManagedBackupManifestService::new(
        origin.clone(),
        Arc::clone(&web) as Arc<_>,
        Arc::clone(&signer) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens));
    let storage = ManagedStorageService::new(
        origin.clone(),
        Arc::clone(&web) as Arc<_>,
        Arc::clone(&signer) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens));

    let seed = RecoverySeed::generate().expect("a seed");
    let recovery = seed.recipient().expect("the recovery recipient");
    let disk = tempfile::tempdir().expect("a directory on the internal disk");
    let mut bundles = BundleStore::open(
        Arc::new(Bundles::default()),
        RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: kr_client::recovery::fresh_locator().expect("a locator"),
        },
        disk.path(),
    )
    .expect("the bundle store");
    let mut bundle = BundleStore::empty(TimestampMs::new(1_700_000_000_000));
    let archive_id = ArchiveId::new(Uuid::from_bytes([0x5e; 16]));
    let now = TimestampMs::new(1_700_000_000_000);
    let generations = Generations::enable(
        Collection {
            archive_id,
            service_origin: ORIGIN.to_owned(),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            writer: keys.authorisation.clone(),
            writer_revision: BackupWriterRevision::new(1),
            producer: keys.stored_envelope.clone(),
            recovery: *recovery.public(),
        },
        &mut bundles,
        &seed,
        &mut bundle,
        &keys.authorisation,
        &manifest,
        now,
    )
    .await;

    let services = ArchiveServices {
        origin,
        http: Arc::clone(&web) as Arc<_>,
        signer: Arc::clone(&signer) as Arc<dyn ServiceSigner>,
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
                now,
            )
            .await;
        assert!(!published.duplicate);
        assert_eq!(published.collection.checkpoint_generation, generation);
        assert_eq!(published.collection.generations.len() as u64, generation);
    }

    // The newest generation, opened with the kit's seed alone.
    let found = manifest
        .fetch(archive_id, None, None)
        .await
        .expect("a fetch")
        .expect("the newest generation");
    assert_eq!(found.collection.checkpoint_generation, 2);
    let descriptor_bytes =
        kr_cbor::to_canonical_vec(&found.publication.payload.descriptor).expect("a descriptor");
    let descriptor = kr_crypto::backup::read_descriptor(&descriptor_bytes).expect("a descriptor");
    let reference = &descriptor.encrypted_manifest;
    let encrypted_manifest = StorageService::read_object(
        &storage,
        archive_id,
        reference.object_id,
        0,
        reference.encrypted_len.get(),
    )
    .await
    .expect("the manifest reads")
    .bytes;
    let writers = vec![kr_protocol::archive::TrustedWriter {
        writer_key_id: keys.authorisation.key_id(),
        signing_key: *keys.authorisation.public(),
        enrolled_at_ms: now,
    }];
    let reader = ArchiveReader::Recovery(&recovery);
    let opened = open_archive(
        &reader,
        keys.stored_envelope.public(),
        &writers,
        &ArchiveExpectation {
            archive_id,
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
        archive_id,
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
            keys.stored_envelope.public(),
            staged.object.object_id,
            &stored,
        )
        .expect("the member restores");
    assert_eq!(restored.plaintext.expose(), member.as_slice());
}
