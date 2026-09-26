//! This device's settings, backed up as a recovery-enabled archive and brought back with only the
//! kit.
//!
//! Section 20 ¶9 and ¶10, and section 24's rule that privacy mode disables backup production.
//! Nothing here talks to a real service: `support/storage_web.rs` answers for managed storage and
//! the backup manifest as the service does, and the owner's sync service holding the recovery
//! bundle is scripted below.

#[path = "support/storage_web.rs"]
mod storage_web;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::recovery::{
    ArchiveServices, BundleStore, FreshRestore, RecoveryError, RetrievalPolicy, SETTINGS_FILENAME,
    ServiceAccess, SettingsArchive, SettingsCollection, Unsettled, import_settings, parse_kit,
    render_kit,
};
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::backup::{BACKUP_MANIFEST_PATH, ManagedBackupManifestService};
use kr_client::services::storage::{
    ManagedStorageService, STORAGE_UPLOAD_ABORT_PATH, STORAGE_UPLOAD_COMPLETE_PATH,
    STORAGE_UPLOAD_CREATE_PATH, STORAGE_UPLOAD_PART_PATH,
};
use kr_client::services::{
    BackupManifestService, ServiceFuture, ServiceHttp, ServiceHttpAnswer, ServiceSigner,
    StorageService, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::{
    PrivacyRecord, SettingValue, SyncBody, SyncError, SyncObject, SyncSettings, SyncStore,
};
use kr_crypto::backup::{
    ArchiveExpectation, ArchiveReader, GenerationExpectation, Material, open_archive,
    read_descriptor,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId, SyncConflictId,
    SyncObjectId, SyncRevisionId,
};
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs, U64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use storage_web::{StorageWeb, TOKEN};

const ORIGIN: &str = "https://reach.kala.to";
const LOCATOR: &str = "c4d2e6f8-settings-bundle";

/* -------------------------------------------------------------------------- */
/* The device, its account and its services                                    */
/* -------------------------------------------------------------------------- */

/// One installation's authorisation key, signing as a device signs.
///
/// It is the owner's key and the settings archive's writer at once, which is what a device that
/// backs up its own settings holds: the service takes an enrolment only from the owner and a
/// publication only from the writer it enrolled.
#[derive(Debug)]
struct Device(AuthorisationKeyPair);

impl Device {
    fn generate() -> Arc<Self> {
        Arc::new(Self(AuthorisationKeyPair::generate().expect("a key pair")))
    }
}

impl ServiceSigner for Device {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(kr_crypto::sign::sign(&self.0, &transcript).expect("a signature"))
    }
}

/// The account's token for `backup.write`, which the sign-in that turned recovery-enabled backup
/// on was granted.
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

fn origin() -> GatewayOrigin {
    GatewayOrigin::new(ORIGIN).expect("an origin")
}

fn storage(web: &Arc<StorageWeb>, device: &Arc<Device>) -> ManagedStorageService {
    ManagedStorageService::new(
        origin(),
        Arc::clone(web) as Arc<_>,
        Arc::clone(device) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens))
}

fn manifest(web: &Arc<StorageWeb>, device: &Arc<Device>) -> ManagedBackupManifestService {
    ManagedBackupManifestService::new(
        origin(),
        Arc::clone(web) as Arc<_>,
        Arc::clone(device) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens))
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x5e; 16]))
}

fn now() -> TimestampMs {
    TimestampMs::new(1_700_000_000_000)
}

/// The owner's sync service, holding the recovery bundle: bytes and a place in the order.
///
/// It also notes how many requests had reached the backup manifest each time a bundle write
/// arrived, which is how a test sees the order of the two.
#[derive(Debug)]
struct Bundles {
    web: Arc<StorageWeb>,
    held: Mutex<BTreeMap<String, (SyncPosition, Vec<u8>)>>,
    manifest_requests_at_each_write: Mutex<Vec<usize>>,
    lose_the_next_write: Mutex<bool>,
}

impl Bundles {
    fn beside(web: &Arc<StorageWeb>) -> Arc<Self> {
        Arc::new(Self {
            web: Arc::clone(web),
            held: Mutex::new(BTreeMap::new()),
            manifest_requests_at_each_write: Mutex::new(Vec::new()),
            lose_the_next_write: Mutex::new(false),
        })
    }

    fn writes(&self) -> Vec<usize> {
        self.manifest_requests_at_each_write
            .lock()
            .expect("the writes")
            .clone()
    }
}

/// The place the nth write of a collection takes.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes(
            [u8::try_from(write_sequence).expect("a few writes"); 16],
        )),
        None,
    )
}

/// The object a position names, which is what the service compares.
fn names(position: Option<SyncPosition>) -> Option<SyncRevision> {
    position.and_then(|position| position.revision.as_ref().copied())
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
            if std::mem::take(&mut *self.lose_the_next_write.lock().expect("the script")) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::UpstreamUnavailable,
                    "the request never reached the service",
                )));
            }
            self.manifest_requests_at_each_write
                .lock()
                .expect("the writes")
                .push(self.web.requests_to(BACKUP_MANIFEST_PATH));
            let mut held = self.held.lock().expect("the bundles");
            let current = held.get(collection).map(|(position, _)| *position);
            if names(current) != names(expected) {
                return Ok(SyncExchanged::Refused {
                    retained: None,
                    current,
                    recovery: None,
                });
            }
            let position = at(current.map_or(1, |held| held.write_sequence + 1));
            held.insert(collection.to_owned(), (position, ciphertext.to_vec()));
            Ok(SyncExchanged::Applied { position })
        })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async { Ok(SyncRequestStatus::Unknown { recovery: None }) })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async {
            Ok(SyncRequestFence::Fenced {
                never_ran: true,
                recovery: None,
            })
        })
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
                    |(position, bytes)| SyncFetched::Held {
                        position: *position,
                        ciphertext: bytes.clone(),
                    },
                ))
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

/// A device with its settings, its recovery seed and the services it backs up to.
struct Owner {
    web: Arc<StorageWeb>,
    bundles: Arc<Bundles>,
    device: Arc<Device>,
    seed: RecoverySeed,
    producer: StoredEnvelopeKeyPair,
    store: SyncStore,
    settings: SyncObject,
    bundle_disk: tempfile::TempDir,
    records: tempfile::TempDir,
    _sync_disk: tempfile::TempDir,
}

impl Owner {
    /// A device holding its settings object, on an account whose backup storage is on.
    fn new() -> Self {
        let web = Arc::new(StorageWeb::new());
        web.set_backup(true);
        let sync_disk = tempfile::tempdir().expect("a directory on the internal disk");
        let store = SyncStore::open(sync_disk.path().join("sync")).expect("a sync store");
        let settings = SyncObject {
            object_id: SyncObjectId::new(Uuid::from_bytes([0x5a; 16])),
            revision: SyncRevisionId::new(Uuid::from_bytes([0x6b; 16])),
            device_id: DeviceId::new(Uuid::from_bytes([0x7c; 16])),
            updated_at_ms: now(),
            body: SyncBody::Settings(SyncSettings {
                values: BTreeMap::from([
                    ("theme".to_owned(), SettingValue::Text("dusk".to_owned())),
                    ("font-size".to_owned(), SettingValue::Number(U64::new(14))),
                ]),
                pinned_labels: BTreeSet::from(["release".to_owned()]),
            }),
        };
        store.put_object(&settings).expect("the settings");
        Self {
            bundles: Bundles::beside(&web),
            web,
            device: Device::generate(),
            seed: RecoverySeed::generate().expect("a seed"),
            producer: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            store,
            settings,
            bundle_disk: tempfile::tempdir().expect("a directory on the internal disk"),
            records: tempfile::tempdir().expect("a directory on the internal disk"),
            _sync_disk: sync_disk,
        }
    }

    fn context() -> RecoveryContext {
        RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: LOCATOR.to_owned(),
        }
    }

    fn bundle_store(&self) -> BundleStore {
        BundleStore::open(
            Arc::clone(&self.bundles) as Arc<dyn SyncBackupService>,
            Self::context(),
            self.bundle_disk.path(),
        )
        .expect("the bundle store")
    }

    fn collection(&self) -> SettingsCollection {
        SettingsCollection {
            archive_id: archive_id(),
            service_origin: ORIGIN.to_owned(),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x7c; 16])),
            writer: self.device.0.clone(),
            writer_revision: BackupWriterRevision::new(1),
            producer: self.producer.clone(),
            recovery: *self
                .seed
                .recipient()
                .expect("the recovery recipient")
                .public(),
            records: self.records.path().to_path_buf(),
        }
    }

    /// Enables the settings writer, the bundle first.
    async fn enable(&self) -> Result<SettingsArchive, RecoveryError> {
        let mut bundles = self.bundle_store();
        let mut bundle = BundleStore::empty(now());
        SettingsArchive::enable(
            self.collection(),
            &mut bundles,
            &self.seed,
            &mut bundle,
            &self.device.0,
            &manifest(&self.web, &self.device),
            now(),
        )
        .await
    }

    async fn back_up(
        &self,
        archive: &SettingsArchive,
        generation: u64,
    ) -> Result<(), RecoveryError> {
        self.back_up_through(
            archive,
            generation,
            Arc::clone(&self.web) as Arc<dyn ServiceHttp>,
            Arc::new(Tokens),
        )
        .await
    }

    /// Backs up generation `generation` through `http`, with the account's tokens from `tokens`.
    async fn back_up_through(
        &self,
        archive: &SettingsArchive,
        generation: u64,
        http: Arc<dyn ServiceHttp>,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> Result<(), RecoveryError> {
        archive
            .back_up(
                &self.store,
                self.settings.object_id,
                BackupGeneration::new(generation),
                &ArchiveServices {
                    origin: origin(),
                    http,
                    signer: Arc::clone(&self.device) as Arc<dyn ServiceSigner>,
                    tokens,
                },
                now(),
            )
            .await
            .map(|backed_up| {
                assert_eq!(
                    backed_up.backup_generation,
                    BackupGeneration::new(generation)
                );
                assert!(!backed_up.published.duplicate);
            })
    }

    /// Takes the archive up again, as a device that enabled its writer earlier does.
    async fn resume(&self, collection: SettingsCollection) -> Option<SettingsArchive> {
        let mut bundles = self.bundle_store();
        SettingsArchive::resume(collection, &mut bundles, &self.seed)
            .await
            .expect("the bundle is read")
    }
}

/* -------------------------------------------------------------------------- */
/* Out and back                                                                */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.17, the settings part, the whole way: a generation made on one device comes back on
/// a new one that holds only the kit and the account, as that device's own settings.
#[tokio::test]
async fn the_settings_go_out_as_an_archive_and_come_back_with_only_the_kit() {
    let owner = Owner::new();
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    owner
        .back_up(&archive, 1)
        .await
        .expect("the settings are backed up");
    assert_eq!(owner.web.generations(&archive_id().to_string()), [1]);
    assert_eq!(owner.web.stored_objects(), 2, "the member and the manifest");
    assert!(
        archive.unsettled().expect("the record").is_empty(),
        "a generation whose publication was answered is struck off"
    );

    // A new device: the kit, read back from its printed form, and the account's access. Nothing
    // of the device that made the archive is held here.
    let kit = parse_kit(
        &render_kit(
            &owner
                .seed
                .to_kit(vec![ORIGIN.to_owned()], LOCATOR.to_owned()),
        )
        .expect("a printable kit"),
    )
    .expect("the kit reads back");
    let recovery = RecoverySeed::from_kit(&kit)
        .expect("the seed")
        .recipient()
        .expect("the recovery recipient");
    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess::new(
            RetrievalPolicy::Account,
            ORIGIN,
            Arc::clone(&owner.bundles) as Arc<dyn SyncBackupService>,
        ))
        .expect("the configured policy granted access");
    let material = restore
        .open_bundle(ORIGIN)
        .await
        .expect("the bundle authenticates under the kit");
    assert!(
        material
            .collections
            .iter()
            .any(|collection| collection.archive_id == archive_id()),
        "the bundle names the settings collection"
    );

    let restoring = Device::generate();
    let found =
        BackupManifestService::fetch(&manifest(&owner.web, &restoring), archive_id(), None, None)
            .await
            .expect("a fetch")
            .expect("the newest generation");
    let descriptor_bytes =
        kr_cbor::to_canonical_vec(&found.publication.payload.descriptor).expect("a descriptor");
    let descriptor = read_descriptor(&descriptor_bytes).expect("a descriptor");
    let sender = material
        .producer(descriptor.manifest_key_wraps[0].context.sender_key_id)
        .expect("the bundle names the producer")
        .stored_envelope_key;
    let reach = storage(&owner.web, &restoring);
    let read = |object_id: BackupObjectId, length: u64| {
        let reach = &reach;
        async move {
            StorageService::read_object(reach, archive_id(), object_id, 0, length)
                .await
                .expect("the account reaches the ciphertext")
                .bytes
        }
    };
    let manifest_object = &descriptor.encrypted_manifest;
    let encrypted_manifest = read(
        manifest_object.object_id,
        manifest_object.encrypted_len.get(),
    )
    .await;
    let reader = ArchiveReader::Recovery(&recovery);
    let opened = open_archive(
        &reader,
        &sender,
        &material.trusted_writers,
        &ArchiveExpectation {
            archive_id: archive_id(),
            generation: GenerationExpectation::Unverified,
        },
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the archive opens against the bundle's writer");
    let [member] = opened.objects() else {
        panic!("one member");
    };
    assert_eq!(member.filename, SETTINGS_FILENAME);
    let bytes = read(member.object.object_id, member.object.encrypted_len.get()).await;
    let restored = opened
        .restore_object(&reader, &sender, member.object.object_id, &bytes)
        .expect("the member restores");

    let disk = tempfile::tempdir().expect("a directory on the internal disk");
    let fresh = SyncStore::open(disk.path().join("sync")).expect("a sync store");
    let imported = import_settings(
        &fresh,
        Material::DeviceConfiguration,
        restored.plaintext.expose(),
    )
    .expect("the settings come back");
    assert_eq!(imported.object_id, owner.settings.object_id);
    assert_eq!(
        fresh.object(owner.settings.object_id).expect("readable"),
        Some(owner.settings.clone())
    );
}

/* -------------------------------------------------------------------------- */
/* The bundle before the writer                                                */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.15: the bundle naming the writer lands before the service is asked to enrol it, and a
/// bundle that does not land enrols nothing.
#[tokio::test]
async fn the_settings_writer_is_enrolled_only_after_the_bundle_naming_it_has_landed() {
    let owner = Owner::new();
    owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    assert_eq!(
        owner.bundles.writes(),
        [0],
        "one bundle write, made before any request reached the backup manifest"
    );
    assert_eq!(
        owner.web.requests_to(BACKUP_MANIFEST_PATH),
        1,
        "the enrolment"
    );

    let owner = Owner::new();
    *owner
        .bundles
        .lose_the_next_write
        .lock()
        .expect("the script") = true;
    let refused = owner.enable().await;
    assert!(
        matches!(refused, Err(RecoveryError::BundleOutcomeUnknown { .. })),
        "{refused:?}"
    );
    assert_eq!(
        owner.web.requests_to(BACKUP_MANIFEST_PATH),
        0,
        "nothing is enrolled for a writer whose bundle did not land"
    );
}

/* -------------------------------------------------------------------------- */
/* Privacy mode                                                                */
/* -------------------------------------------------------------------------- */

/// The request after whose answer privacy mode changes, counted from one among its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    Creation(u32),
    Part(u32),
    Completion(u32),
}

/// What privacy mode does then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    /// It is turned on, at the next generation.
    Fence,
    /// Its generation moves on, and it stays off.
    MoveOn,
}

/// Changes one device's privacy mode, as the person does.
fn change(store: &SyncStore, change: Change) {
    let current = store.privacy().expect("the privacy state").generation.get();
    match change {
        Change::Fence => {
            store
                .record_privacy(PrivacyRecord {
                    generation: U64::new(current + 1),
                    fenced: true,
                })
                .expect("privacy mode on");
        }
        Change::MoveOn => {
            store
                .advance_privacy(current + 1)
                .expect("privacy mode moves on");
        }
    }
}

/// The transport to the service, with privacy mode changed once one request has been answered: a
/// change that lands while the device is in the middle of a generation.
struct Meddling {
    web: Arc<StorageWeb>,
    store: SyncStore,
    after: After,
    change: Change,
    seen: Mutex<(u32, u32, u32)>,
}

impl Meddling {
    fn new(owner: &Owner, after: After, change: Change) -> Arc<Self> {
        Arc::new(Self {
            web: Arc::clone(&owner.web),
            store: SyncStore::open(owner.store.directory()).expect("the same sync store"),
            after,
            change,
            seen: Mutex::new((0, 0, 0)),
        })
    }

    /// Counts one answered request and changes privacy mode when it is the one chosen.
    fn answered(&self, url: &str) {
        let reached = {
            let mut seen = self.seen.lock().expect("the count");
            if url.ends_with(STORAGE_UPLOAD_CREATE_PATH) {
                seen.0 += 1;
                After::Creation(seen.0)
            } else if url.ends_with(STORAGE_UPLOAD_PART_PATH) {
                seen.1 += 1;
                After::Part(seen.1)
            } else if url.ends_with(STORAGE_UPLOAD_COMPLETE_PATH) {
                seen.2 += 1;
                After::Completion(seen.2)
            } else {
                return;
            }
        };
        if reached == self.after {
            change(&self.store, self.change);
        }
    }
}

impl std::fmt::Debug for Meddling {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Meddling")
            .field("after", &self.after)
            .field("change", &self.change)
            .finish_non_exhaustive()
    }
}

impl ServiceHttp for Meddling {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let answer = self.web.post_json(url, body, headers).await;
            self.answered(url);
            answer
        })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let answer = self.web.post_bytes(url, body, headers).await;
            self.answered(url);
            answer
        })
    }
}

/// The account's tokens, with privacy mode turned on while the device waits for one of them: a
/// fence that lands after a request's privacy was read and before the request leaves.
struct FencingTokens {
    web: Arc<StorageWeb>,
    store: SyncStore,
    at: usize,
    asked: Mutex<usize>,
    arrived_when_fenced: Mutex<Option<usize>>,
}

impl std::fmt::Debug for FencingTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FencingTokens")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

impl AccountTokenSource for FencingTokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let asked = {
            let mut asked = self.asked.lock().expect("the count");
            *asked += 1;
            *asked
        };
        if asked == self.at {
            *self.arrived_when_fenced.lock().expect("the mark") = Some(self.web.arrived().len());
            change(&self.store, Change::Fence);
        }
        Tokens.token(scope)
    }
}

/// Section 24: while privacy mode is on the settings are not read for an archive, so nothing is
/// sent.
#[tokio::test]
async fn privacy_mode_on_refuses_the_settings_archive_before_anything_is_sent() {
    let owner = Owner::new();
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    owner
        .store
        .record_privacy(PrivacyRecord {
            generation: U64::new(2),
            fenced: true,
        })
        .expect("privacy mode on");
    let before = owner.web.arrived().len();
    let refused = owner.back_up(&archive, 1).await;
    assert!(
        matches!(
            refused,
            Err(RecoveryError::Sync(SyncError::Fenced { generation: 2 }))
        ),
        "{refused:?}"
    );
    assert_eq!(owner.web.arrived().len(), before, "nothing was sent");
    assert!(archive.unsettled().expect("the record").is_empty());
}

/// Section 24: a generation read under one privacy generation is not published under another. What
/// it had already stored is written down, and a device that starts again finds it listed.
#[tokio::test]
async fn a_privacy_generation_that_moved_refuses_the_publication_and_what_was_stored_stays_listed()
{
    let owner = Owner::new();
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    let moving = Meddling::new(&owner, After::Completion(2), Change::MoveOn);
    let refused = owner
        .back_up_through(&archive, 1, moving, Arc::new(Tokens))
        .await;
    assert!(
        matches!(
            refused,
            Err(RecoveryError::Sync(SyncError::LateResult {
                produced_under: 0,
                current: 1
            }))
        ),
        "{refused:?}"
    );
    assert!(
        owner.web.generations(&archive_id().to_string()).is_empty(),
        "no publication was sent"
    );
    assert_eq!(owner.web.stored_objects(), 2);
    drop(archive);

    // The device starts again: what the refused generation stored is still listed, by identity.
    let archive = owner
        .resume(owner.collection())
        .await
        .expect("the archive is taken up again");
    let [unsettled] = archive
        .unsettled()
        .expect("the record")
        .try_into()
        .unwrap_or_else(|listed: Vec<Unsettled>| {
            panic!("one generation is listed, not {listed:?}")
        });
    assert_eq!(unsettled.backup_generation, BackupGeneration::new(1));
    assert_eq!(unsettled.objects.len(), 2);
    for object in &unsettled.objects {
        assert!(
            owner
                .web
                .stored(&archive_id().to_string(), &object.to_string())
                .is_some(),
            "object {object} is at the service"
        );
    }

    // The next generation is published and struck off; the refused one stays until it is dealt
    // with.
    owner
        .back_up(&archive, 2)
        .await
        .expect("the next generation");
    let listed = archive.unsettled().expect("the record");
    assert_eq!(
        listed
            .iter()
            .map(|unsettled| unsettled.backup_generation)
            .collect::<Vec<_>>(),
        [BackupGeneration::new(1)]
    );
    assert!(
        archive
            .forget_unsettled(BackupGeneration::new(1))
            .expect("the record")
    );
    assert!(archive.unsettled().expect("the record").is_empty());
}

/// Section 24: privacy mode turned on while an upload is under way keeps the next request on this
/// device, whichever request was on its way, and the upload is abandoned at the service.
#[tokio::test]
async fn privacy_mode_turned_on_during_an_upload_stops_it_and_abandons_it() {
    for (after, parts) in [(After::Creation(1), 0), (After::Part(1), 1)] {
        let owner = Owner::new();
        let archive = owner
            .enable()
            .await
            .expect("the settings writer is enabled");
        let fencing = Meddling::new(&owner, after, Change::Fence);
        let refused = owner
            .back_up_through(&archive, 1, fencing, Arc::new(Tokens))
            .await;
        assert!(
            matches!(
                refused,
                Err(RecoveryError::Sync(SyncError::Fenced { generation: 1 }))
            ),
            "{after:?}: {refused:?}"
        );
        assert_eq!(
            owner.web.requests_to(STORAGE_UPLOAD_CREATE_PATH),
            1,
            "{after:?}"
        );
        assert_eq!(
            owner.web.requests_to(STORAGE_UPLOAD_PART_PATH),
            parts,
            "{after:?}"
        );
        assert_eq!(
            owner.web.requests_to(STORAGE_UPLOAD_COMPLETE_PATH),
            0,
            "{after:?}: nothing is completed"
        );
        assert_eq!(
            owner.web.requests_to(STORAGE_UPLOAD_ABORT_PATH),
            1,
            "{after:?}: the upload is abandoned"
        );
        assert_eq!(owner.web.stored_objects(), 0, "{after:?}");
        assert!(owner.web.generations(&archive_id().to_string()).is_empty());
    }
}

/// Section 24: privacy mode turned on while the device waits for a request's account token keeps
/// that request on the device: it is read at the moment the request would leave, after its token
/// is in hand. Only abandonments leave afterwards.
#[tokio::test]
async fn privacy_mode_turned_on_while_a_token_is_fetched_keeps_that_request_on_the_device() {
    // The member's creation, its part and its completion, the manifest's creation, and the
    // publication: the first, second, third, fourth and seventh tokens asked for.
    for at in [1, 2, 3, 4, 7] {
        let owner = Owner::new();
        let archive = owner
            .enable()
            .await
            .expect("the settings writer is enabled");
        let tokens = Arc::new(FencingTokens {
            web: Arc::clone(&owner.web),
            store: SyncStore::open(owner.store.directory()).expect("the same sync store"),
            at,
            asked: Mutex::new(0),
            arrived_when_fenced: Mutex::new(None),
        });
        let refused = owner
            .back_up_through(
                &archive,
                1,
                Arc::clone(&owner.web) as Arc<dyn ServiceHttp>,
                Arc::clone(&tokens) as Arc<dyn AccountTokenSource>,
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(RecoveryError::Sync(SyncError::Fenced { generation: 1 }))
            ),
            "token {at}: {refused:?}"
        );
        let fenced_at = tokens
            .arrived_when_fenced
            .lock()
            .expect("the mark")
            .expect("the fence was raised");
        let after_the_fence: Vec<String> = owner.web.arrived()[fenced_at..]
            .iter()
            .map(|arrived| arrived.path.clone())
            .collect();
        assert!(
            after_the_fence
                .iter()
                .all(|path| path == STORAGE_UPLOAD_ABORT_PATH),
            "token {at}: only abandonments left after the fence: {after_the_fence:?}"
        );
        assert!(owner.web.generations(&archive_id().to_string()).is_empty());
    }
}

/* -------------------------------------------------------------------------- */
/* Taking the archive up again                                                 */
/* -------------------------------------------------------------------------- */

/// A device that enabled its writer earlier takes the archive up again only for the collection,
/// the producer and the writer the bundle at the service names, read and authenticated then, since
/// a restore with only the kit finds and opens nothing else. A bundle this device changed and could
/// not commit counts for nothing.
#[tokio::test]
async fn an_archive_taken_up_again_is_held_to_what_the_bundle_at_the_service_names() {
    let owner = Owner::new();
    owner
        .enable()
        .await
        .expect("the settings writer is enabled");

    // A second producer is enabled and its bundle write is lost: the bundle this device changed
    // names it, and the bundle at the service does not.
    *owner
        .bundles
        .lose_the_next_write
        .lock()
        .expect("the script") = true;
    let mut replaced = owner.collection();
    replaced.producer = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let other_producer = replaced.producer.clone();
    {
        let mut bundles = owner.bundle_store();
        let mut bundle = bundles.fetch(&owner.seed).await.expect("the bundle");
        let refused = SettingsArchive::enable(
            replaced,
            &mut bundles,
            &owner.seed,
            &mut bundle,
            &owner.device.0,
            &manifest(&owner.web, &owner.device),
            now(),
        )
        .await;
        assert!(refused.is_err(), "{refused:?}");
    }

    let resumed = owner
        .resume(owner.collection())
        .await
        .expect("the bundle at the service names the collection, the producer and the writer");
    owner
        .back_up(&resumed, 1)
        .await
        .expect("the settings are backed up");

    let mut uncommitted = owner.collection();
    uncommitted.producer = other_producer;
    assert!(
        owner.resume(uncommitted).await.is_none(),
        "a producer only an uncommitted bundle names"
    );
    let mut elsewhere = owner.collection();
    elsewhere.archive_id = ArchiveId::new(Uuid::from_bytes([0x6f; 16]));
    assert!(
        owner.resume(elsewhere).await.is_none(),
        "a collection the bundle does not name"
    );
    let mut another_writer = owner.collection();
    another_writer.writer = AuthorisationKeyPair::generate().expect("a writer key");
    assert!(
        owner.resume(another_writer).await.is_none(),
        "a writer the bundle does not name"
    );
}

/* -------------------------------------------------------------------------- */
/* A collection deleted from the account console                               */
/* -------------------------------------------------------------------------- */

/// The service takes nothing into a collection its owner deleted, and the device is told to enrol
/// a new one rather than to update.
#[tokio::test]
async fn a_deleted_collection_stops_the_settings_archive_and_says_to_enrol_a_new_one() {
    let owner = Owner::new();
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    owner.web.delete_collection(&archive_id().to_string());
    match owner.back_up(&archive, 1).await {
        Err(RecoveryError::Service(ClientError::Refused { error, action, .. })) => {
            assert!(
                error.message.contains("enrol a new collection"),
                "{error:?}"
            );
            assert_ne!(action, kr_client::retry::UserAction::Update);
        }
        other => panic!("a deleted collection is its own refusal, not {other:?}"),
    }
    assert_eq!(owner.web.stored_objects(), 0);
}

/* -------------------------------------------------------------------------- */
/* What a rendering shows                                                      */
/* -------------------------------------------------------------------------- */

/// The settings archive holds the writer's and the producer's private keys, and its rendering
/// names neither a key nor a key's identifier, whose bytes it would print whole: it says the archive
/// and where it stands.
#[tokio::test]
async fn a_settings_archive_renders_neither_its_keys_nor_their_identifiers() {
    let owner = Owner::new();
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    let shown = format!("{archive:?}");
    assert!(
        shown.starts_with("SettingsArchive { collection: SettingsCollection { archive_id: "),
        "{shown}"
    );
    assert!(
        !shown.contains(&format!("{:?}", owner.device.0.key_id())),
        "{shown}"
    );
    assert!(!shown.contains("seed"), "{shown}");
    assert!(!shown.contains("secret"), "{shown}");
    assert!(!shown.contains("expanded"), "{shown}");
}
