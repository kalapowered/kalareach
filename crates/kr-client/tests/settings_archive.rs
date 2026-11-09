//! This device's settings, backed up as a recovery-enabled archive and brought back with only the
//! kit.
//!
//! Section 20 ¶9 and ¶10, and section 24's rule that privacy mode disables backup production.
//! Nothing here talks to a real service: `kr-service-stand-in` answers for managed storage and
//! the backup manifest as the service does, and the owner's sync service holding the recovery
//! bundle is scripted below.

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
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys, StoredEnvelopeKeyPair};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId, SyncConflictId,
    SyncObjectId, SyncRevisionId,
};
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs, U64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ServiceWeb, TOKEN};

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

fn storage(web: &Arc<ServiceWeb>, device: &Arc<Device>) -> ManagedStorageService {
    ManagedStorageService::new(
        origin(),
        Arc::clone(web) as Arc<_>,
        Arc::clone(device) as Arc<dyn ServiceSigner>,
    )
    .presenting(Arc::new(Tokens))
}

fn manifest(web: &Arc<ServiceWeb>, device: &Arc<Device>) -> ManagedBackupManifestService {
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
    web: Arc<ServiceWeb>,
    held: Mutex<BTreeMap<String, (SyncPosition, Vec<u8>)>>,
    manifest_requests_at_each_write: Mutex<Vec<usize>>,
    lose_the_next_write: Mutex<bool>,
}

impl Bundles {
    fn beside(web: &Arc<ServiceWeb>) -> Arc<Self> {
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
    web: Arc<ServiceWeb>,
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
        Self::holding(DeviceKeys::generate().expect("a device's keys"))
    }

    /// As [`Self::new`], for the device whose keys are `keys`: its authorisation key is the owner's
    /// and the writer's, and its stored-envelope key is the producer's.
    fn holding(keys: DeviceKeys) -> Self {
        let web = Arc::new(ServiceWeb::new());
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
            went_over: Vec::new(),
        };
        store.put_object(&settings).expect("the settings");
        Self {
            bundles: Bundles::beside(&web),
            web,
            device: Arc::new(Device(keys.authorisation)),
            seed: RecoverySeed::generate().expect("a seed"),
            producer: keys.stored_envelope,
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

/// The forms in which a document could carry `key`, as the bytes to look for in it: the bytes
/// themselves and their hexadecimal in either case; and base64 in either alphabet, which puts three
/// bytes in four characters, so that the characters standing for the key's whole groups of three are
/// the same wherever the key lies in a longer value. Which groups those are depends on where the key
/// starts, so each of the three ways it can start is looked for.
fn forms_of(key: &[u8]) -> Vec<(String, Vec<u8>)> {
    let hex = |upper: bool| -> Vec<u8> {
        key.iter()
            .map(|byte| {
                if upper {
                    format!("{byte:02X}")
                } else {
                    format!("{byte:02x}")
                }
            })
            .collect::<String>()
            .into_bytes()
    };
    let mut forms = vec![
        ("as bytes".to_owned(), key.to_vec()),
        ("in lower-case hexadecimal".to_owned(), hex(false)),
        ("in upper-case hexadecimal".to_owned(), hex(true)),
    ];
    for start in 0..3 {
        let whole = &key[start..start + (key.len() - start) / 3 * 3];
        let url = kr_protocol::scalars::to_base64url(whole);
        forms.push((
            format!("in base64url from its byte {start}"),
            url.clone().into_bytes(),
        ));
        forms.push((
            format!("in base64 from its byte {start}"),
            url.replace('-', "+").replace('_', "/").into_bytes(),
        ));
    }
    forms
}

/// How `key` is carried in `haystack`, in a form [`forms_of`] names or as serde writes a list of
/// bytes, a list of numbers, with any space between its items; nothing when it is not.
fn carried_in(haystack: &[u8], key: &[u8]) -> Option<String> {
    let found = |needle: &[u8], haystack: &[u8]| {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    };
    if let Some((form, _)) = forms_of(key)
        .into_iter()
        .find(|(_, needle)| found(needle, haystack))
    {
        return Some(form);
    }
    let compact: Vec<u8> = haystack
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let numbers = key
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    found(&numbers, &compact).then(|| "as a list of numbers".to_owned())
}

/// Every key of `kept` that is carried in an object of `clear`, as the object's label and the key's
/// name with the form. Each object is read on its own.
fn carried_keys(clear: &[(String, Vec<u8>)], kept: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    for (label, bytes) in clear {
        for (name, key) in kept {
            if let Some(form) = carried_in(bytes, key) {
                found.push(format!("{label} holds the {name} {form}"));
            }
        }
    }
    found
}

/// The private keys a device keeps, as their bytes with a name: the four seeds, and the private
/// keys of the two X25519 pairs, which are made from their seeds by a hash (the first half of the
/// seed's SHA-512, which is what libsodium's `crypto_box_seed_keypair` makes of it) and are checked
/// here against the public key the pair has.
fn private_keys_of(keys: &DeviceKeys) -> Vec<(String, Vec<u8>)> {
    use kr_crypto::store::{MemoryStore, SecretName, SecretStore as _, store_device_keys};
    use kr_protocol::pairing::KeyPurpose;
    use sha2::Digest as _;

    // The seeds are read from a store they are written to, as the device's own are.
    let store = MemoryStore::new();
    store_device_keys(&store, "device", keys).expect("the keys are stored");
    let mut kept = Vec::new();
    for (purpose, public) in [
        (KeyPurpose::Transport, None),
        (KeyPurpose::Authorisation, None),
        (
            KeyPurpose::StoredEnvelope,
            Some(*keys.stored_envelope.public().as_bytes()),
        ),
        (
            KeyPurpose::NotificationPreview,
            Some(*keys.notification_preview.public().as_bytes()),
        ),
    ] {
        let name = SecretName::device_key("device", purpose).expect("a name");
        let seed = store
            .get(&name)
            .expect("the store reads")
            .unwrap_or_else(|| panic!("the store kept a {purpose:?} key"))
            .expose()
            .to_vec();
        kept.push((format!("{purpose:?} seed"), seed.clone()));
        if let Some(public) = public {
            let secret = sha2::Sha512::digest(&seed)[..32].to_vec();
            let derived = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &secret,
            )
            .expect("an X25519 private key")
            .compute_public_key()
            .expect("its public key");
            assert_eq!(
                derived.as_ref(),
                public.as_slice(),
                "the {purpose:?} private key is the first half of its seed's hash"
            );
            kept.push((format!("{purpose:?} private key (derived)"), secret));
        }
    }
    assert_eq!(kept.len(), 6, "four seeds and two keys made from them");
    for (name, key) in &kept {
        assert!(key.len() >= 32, "the {name} is a key, not a stub");
    }
    kept
}

/// The manifest object of a generation as `reader` decrypts it, whole: `open_archive` hands out the
/// signed manifest and keeps the member key wraps, so a scan of everything the object holds opens
/// it here, under the context `open_archive` checks the manifest key's wrap against.
fn manifest_payload_as(
    reader: &ArchiveReader<'_>,
    sender: &kr_protocol::scalars::StoredEnvelopeKey,
    descriptor: &kr_protocol::archive::ArchiveDescriptor,
    encrypted_manifest: &[u8],
) -> kr_protocol::archive::ManifestPayload {
    use kr_protocol::archive::{
        KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, MANIFEST_PAYLOAD_LIMITS,
    };

    let reader_key_id = reader.key_id();
    let wrap = kr_crypto::archive::manifest_wrap_for(descriptor, &reader_key_id)
        .expect("a manifest key wrap addressed to the reader");
    let expected = KeyWrapContext {
        format: KeyWrapFormat::V1,
        purpose: KeyWrapPurpose::ManifestKey,
        archive_id: descriptor.archive_id,
        backup_generation: descriptor.backup_generation,
        object_id: descriptor.encrypted_manifest.object_id,
        encrypted_object_hash: descriptor.encrypted_manifest.encrypted_object_hash,
        sender_key_id: kr_crypto::backup::recipient_key_id(sender),
        recipient_key_id: reader_key_id,
    };
    let key = match reader {
        ArchiveReader::Device(keys) => {
            kr_crypto::archive::unwrap_object_key(keys, sender, wrap, &expected)
        }
        ArchiveReader::Recovery(recovery) => {
            kr_crypto::archive::unwrap_object_key_with_recovery(recovery, sender, wrap, &expected)
        }
    }
    .expect("the manifest key opens");
    let plaintext = kr_crypto::archive::decrypt_object(
        &key,
        &descriptor.encrypted_manifest,
        encrypted_manifest,
    )
    .expect("the manifest object decrypts");
    kr_cbor::from_canonical_slice(plaintext.expose(), &MANIFEST_PAYLOAD_LIMITS)
        .expect("a manifest payload")
}

/// The keys the wraps of a generation seal for `reader`, as the reader unwraps them: the manifest's
/// key and each member's. A scan reads them, so that a wrap that holds a key the device keeps in
/// place of the member's own is read, and not only its ciphertext.
fn keys_sealed_for(
    reader: &ArchiveReader<'_>,
    sender: &kr_protocol::scalars::StoredEnvelopeKey,
    descriptor: &kr_protocol::archive::ArchiveDescriptor,
    payload: &kr_protocol::archive::ManifestPayload,
) -> Vec<(String, Vec<u8>)> {
    let reader_id = reader.key_id();
    let unwrap = |wrap: &kr_protocol::archive::SealedKeyWrap| -> Vec<u8> {
        match reader {
            ArchiveReader::Device(keys) => {
                kr_crypto::archive::unwrap_object_key(keys, sender, wrap, &wrap.context)
            }
            ArchiveReader::Recovery(recovery) => {
                kr_crypto::archive::unwrap_object_key_with_recovery(
                    recovery,
                    sender,
                    wrap,
                    &wrap.context,
                )
            }
        }
        .expect("a wrap addressed to the reader opens")
        .expose()
        .to_vec()
    };
    let mut keys = Vec::new();
    for wrap in &descriptor.manifest_key_wraps {
        if wrap.context.recipient_key_id == reader_id {
            keys.push(("the manifest's key".to_owned(), unwrap(wrap)));
        }
    }
    for wrap in &payload.member_key_wraps {
        if wrap.context.recipient_key_id == reader_id {
            keys.push((
                format!("the key of member object {}", wrap.context.object_id),
                unwrap(wrap),
            ));
        }
    }
    keys
}

/// The manifest object's payload in the two encodings a scan reads it in: the canonical bytes it was
/// sealed as, and the JSON a client sees.
fn payload_encodings(payload: &kr_protocol::archive::ManifestPayload) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "the manifest object as canonical bytes".to_owned(),
            kr_cbor::to_canonical_vec(payload).expect("a payload encodes"),
        ),
        (
            "the manifest object as JSON".to_owned(),
            serde_json::to_vec(payload).expect("a payload encodes"),
        ),
    ]
}

/// KR-REQ-20.17, the settings archive producer only, and only what this case reads: the bundle, the
/// descriptor, the manifest object and every request the producer sends the service hold none of
/// the private keys of the device that makes the archive. That device keeps four keys (transport,
/// which is the reusable endpoint key; authorisation, which is the control-signing key and here the
/// writer's; stored envelope, here the producer's; and notification preview). The case reads the
/// four seeds, and the private keys of the two X25519 pairs, checked against their public keys. It
/// reads, each on its own: the recovery bundle the service holds, opened with the kit's seed alone,
/// as the JSON a client sees and as canonical bytes; the publication as the service holds it, with
/// its descriptor, its writer's key identifier, its time and its signature; the descriptor as
/// canonical bytes; the manifest object decrypted whole, as a `ManifestPayload`, with the signed
/// manifest and every member key wrap (the sealed keys and the clear context fields of the wraps
/// among them), once as canonical bytes and once as JSON, with its wraps counted (one for each
/// member and for the archive's one recipient, the reader the case opens it as, so none is unused)
/// and the keys they seal, which the reader unwraps (the manifest's and the member's), read as
/// well; the settings member's plaintext; and every request sent to the storage and manifest services, each
/// body, the content beside it and the account token. Each key is looked for as bytes, in
/// hexadecimal of either case, in either base64 alphabet wherever it lies in a longer value, and as
/// a list of numbers. The controls are the scan finding a key where one is put, in each form and
/// inside a longer base64 value, in the sealed key of a wrap and in a clear context field of one, in
/// both encodings of the payload; the writer's public key in the bundle; the writer's key
/// identifier in the publication; and the manifest object's ciphertext in the contents sent. The
/// producer is given the device's authorisation and stored-envelope keys only, so no assertion
/// here can fail for the transport seed, the notification preview seed or the preview private key,
/// which are looked for all the same. Not shown here: the bundle's ciphertext as the owner's sync
/// service holds it and the stored bytes of the objects, which are read only as the ciphertext sent
/// (a key sealed inside them is read through the opened bundle and archive); the parts of a request
/// the stand-in does not keep (its headers other than the token, a query on its path, the
/// signature block, any member of the signed document other than its body, and the
/// authentication requests, which the stand-in answers before it keeps a record); a key in a
/// binary list of integers, split, reversed or
/// otherwise transformed; the seed of the recovery kit, which is not an endpoint or a control key;
/// or the other data paths of backup and recovery material.
#[tokio::test]
async fn the_settings_archive_holds_none_of_the_private_keys_the_device_keeps() {
    let keys = DeviceKeys::generate().expect("a device's keys");
    let kept = private_keys_of(&keys);
    let owner = Owner::holding(keys);
    let archive = owner
        .enable()
        .await
        .expect("the settings writer is enabled");
    owner
        .back_up(&archive, 1)
        .await
        .expect("the settings are backed up");
    let archive_text = archive_id().to_string();

    // The bundle the service holds, opened with the kit's seed alone.
    let sealed = {
        let held = owner.bundles.held.lock().expect("the bundles");
        assert_eq!(held.len(), 1, "one bundle");
        held.values().next().expect("a bundle").1.clone()
    };
    let key = owner
        .seed
        .bundle_key_for(&Owner::context())
        .expect("the bundle's key");
    let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &sealed)
        .expect("the kit's seed opens the bundle");
    assert!(
        bundle
            .collections
            .iter()
            .any(|collection| collection.archive_id == archive_id()),
        "the bundle names the settings collection"
    );

    // The publication as the service holds it, and the descriptor in it.
    let publication = owner
        .web
        .publication(&archive_text, 1)
        .expect("the service holds the publication");
    let held: kr_protocol::archive::BackupGenerationPublication =
        serde_json::from_value(publication.clone()).expect("a publication");
    let descriptor_bytes =
        kr_cbor::to_canonical_vec(&held.payload.descriptor).expect("a descriptor encodes");
    let descriptor = read_descriptor(&descriptor_bytes).expect("a descriptor");

    // The manifest object, whole, and the member, opened with the kit's seed alone.
    let encrypted_manifest = owner
        .web
        .stored(
            &archive_text,
            &descriptor.encrypted_manifest.object_id.to_string(),
        )
        .expect("the service holds the manifest object");
    let recovery = owner.seed.recipient().expect("the recovery recipient");
    let reader = ArchiveReader::Recovery(&recovery);
    let sender = *owner.producer.public();
    let trusted: Vec<_> = bundle.trusted_writers.iter().cloned().collect();
    let opened = open_archive(
        &reader,
        &sender,
        &trusted,
        &ArchiveExpectation {
            archive_id: archive_id(),
            generation: GenerationExpectation::Unverified,
        },
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the archive opens against the bundle's writer");
    let payload = manifest_payload_as(&reader, &sender, &descriptor, &encrypted_manifest);
    assert_eq!(
        &payload.manifest,
        opened.manifest(),
        "the payload read here is the manifest the archive opened"
    );
    let [member] = opened.objects() else {
        panic!("one member");
    };
    let member_bytes = owner
        .web
        .stored(&archive_text, &member.object.object_id.to_string())
        .expect("the service holds the member");
    let settings = opened
        .restore_object(&reader, &sender, member.object.object_id, &member_bytes)
        .expect("the member restores");

    // Every request the producer sent: the document, the content beside it, the token.
    let mut sent = Vec::new();
    for (at, arrived) in owner.web.arrived().iter().enumerate() {
        let to = format!("request {at} to {}", arrived.path);
        sent.push((
            format!("the body of {to}"),
            serde_json::to_vec(&arrived.body).expect("a body encodes"),
        ));
        if let Some(content) = &arrived.content {
            sent.push((format!("the content of {to}"), content.clone()));
        }
        if let Some(token) = &arrived.token {
            sent.push((format!("the token of {to}"), token.clone().into_bytes()));
        }
    }

    // The controls: the scan finds a key where one is put, in the unused wrap of the manifest
    // object (its sealed key and a clear context field, in both encodings), and reads the bundle,
    // the publication and what was sent.
    let (_, probe) = &kept[0];
    // The bytes and the hexadecimal forms are made here and not by the scan's own list of forms,
    // so a form dropped from that list fails here.
    let lower: String = probe.iter().map(|byte| format!("{byte:02x}")).collect();
    for (form, needle) in [
        ("as bytes", probe.clone()),
        ("in lower-case hexadecimal", lower.clone().into_bytes()),
        (
            "in upper-case hexadecimal",
            lower.to_uppercase().into_bytes(),
        ),
    ] {
        let document = [b"{\"a\":\"".as_slice(), &needle, b"\"}"].concat();
        assert!(
            carried_in(&document, probe).is_some(),
            "the scan misses a key {form}"
        );
    }
    for alphabet in ["base64url", "base64"] {
        for before in 0..3 {
            let mut longer = vec![0x5a_u8; before];
            longer.extend_from_slice(probe);
            longer.extend_from_slice(b"tail");
            let encoded = kr_protocol::scalars::to_base64url(&longer);
            let encoded = if alphabet == "base64" {
                encoded.replace('-', "+").replace('_', "/")
            } else {
                encoded
            };
            let value = format!("{{\"k\":\"{encoded}\"}}").into_bytes();
            assert!(
                carried_in(&value, probe).is_some(),
                "the scan misses a key inside a longer {alphabet} value that starts {before} \
                 bytes before it"
            );
        }
    }
    let list = format!(
        "{{\"k\":[\n  {}\n]}}",
        probe
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",\n  ")
    )
    .into_bytes();
    assert_eq!(
        carried_in(&list, probe).as_deref(),
        Some("as a list of numbers")
    );
    let wraps = &payload.member_key_wraps;
    // No wrap is unused: one for the member and each recipient the descriptor wraps the manifest
    // key for, and no other.
    let recipients: Vec<_> = descriptor
        .manifest_key_wraps
        .iter()
        .map(|wrap| wrap.context.recipient_key_id)
        .collect();
    assert_eq!(
        recipients,
        [reader.key_id()],
        "the archive has one recipient, the reader the case opens it as, so the case opens every wrap"
    );
    assert_eq!(
        wraps.len(),
        payload.manifest.manifest.objects.len() * recipients.len(),
        "the manifest object holds a wrap that is not for a member and a recipient of the archive"
    );
    for entry in &payload.manifest.manifest.objects {
        for recipient in &recipients {
            let wanted = wraps
                .iter()
                .filter(|wrap| {
                    wrap.context.object_id == entry.object.object_id
                        && wrap.context.recipient_key_id == *recipient
                })
                .count();
            assert_eq!(wanted, 1, "one wrap for each member and recipient");
        }
    }
    // The keys the wraps seal, as the reader unwraps them: the manifest's and each member's.
    let sealed_keys = keys_sealed_for(&reader, &sender, &descriptor, &payload);
    assert_eq!(
        sealed_keys.len(),
        1 + payload.manifest.manifest.objects.len(),
        "the manifest's key and the key of each member"
    );
    let probe_hash: [u8; 32] = probe.as_slice().try_into().expect("a 32-byte seed");
    for (where_, in_the_sealed_key) in [
        ("the sealed key of an unused wrap", true),
        ("a clear context field of an unused wrap", false),
    ] {
        let mut planted = payload.clone();
        let mut unused = wraps[0].clone();
        if in_the_sealed_key {
            unused.ciphertext = kr_protocol::scalars::Bytes::new(probe.clone());
        } else {
            unused.context.encrypted_object_hash =
                kr_protocol::scalars::Digest256::from_bytes(probe_hash);
        }
        planted.member_key_wraps.push(unused);
        assert_eq!(
            carried_keys(&payload_encodings(&planted), &kept[..1]).len(),
            2,
            "the scan of the manifest object misses a key in {where_}"
        );
    }
    assert_eq!(
        carried_keys(&payload_encodings(&payload), &kept[..1]).len(),
        0,
        "the unplanted payload carries the key the controls plant"
    );
    let bundle_json = serde_json::to_vec(&bundle).expect("a bundle encodes");
    assert!(
        carried_in(&bundle_json, owner.device.0.public().as_bytes()).is_some(),
        "the scan does not read the writer's key in the bundle"
    );
    let publication = serde_json::to_vec(&publication).expect("a publication encodes");
    assert!(
        carried_in(&publication, owner.device.0.key_id().as_bytes()).is_some(),
        "the scan does not read the publication's writer"
    );
    let manifest_object = &encrypted_manifest;
    assert!(
        sent.iter().any(|(_, bytes)| bytes
            .windows(manifest_object.len())
            .any(|window| window == manifest_object.as_slice())),
        "the scan does not read the contents sent"
    );

    // Everything the archive is, each read on its own.
    let mut clear = vec![
        ("the bundle as JSON".to_owned(), bundle_json),
        (
            "the bundle as canonical bytes".to_owned(),
            kr_cbor::to_canonical_vec(&bundle).expect("a bundle encodes"),
        ),
        ("the publication the service holds".to_owned(), publication),
        ("the descriptor".to_owned(), descriptor_bytes),
        (
            "the settings member".to_owned(),
            settings.plaintext.expose().to_vec(),
        ),
    ];
    clear.extend(payload_encodings(&payload));
    clear.extend(sealed_keys);
    clear.extend(sent);
    assert_eq!(
        carried_keys(&clear, &kept),
        Vec::<String>::new(),
        "something the settings archive makes or sends holds a private key the device keeps"
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
    web: Arc<ServiceWeb>,
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
    web: Arc<ServiceWeb>,
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
