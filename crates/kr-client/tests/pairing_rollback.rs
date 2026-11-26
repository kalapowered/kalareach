//! KR-REQ-20.12: a rollback to a release that does not know the checkpoints leaves the paired-host
//! files that release reads exactly as they were, and the checkpoints are there when the newer
//! release is back.
//!
//! The older release's records are frozen here: a copy of its file types, the host record and the
//! waiting attempt among them, as they stood before the checkpoints existed. Each refuses a field
//! it does not know, so a field added to a record, and not only to the file around it, is seen. The
//! types the records hold (keys, network configuration, grant) belong to the protocol and are
//! shared.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use kr_client::pairing::checkpoint::{Answer, Held, PairedCheckpoints};
use kr_client::pairing::paired::{AttemptMode, PairedHost, PairedHosts, PendingAttempt};
use kr_client::recovery::{
    FilesRestore, PublicationRefusal, RestoreError, RestoreSource, SourceService, SourceSignIn,
    fresh_locator,
};
use kr_client::services::{ServiceFuture, SyncFetched, SyncPosition, SyncRevision};
use kr_crypto::backup::GenerationStanding;
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    ARCHIVE_DESCRIPTOR_VERSION, ArchiveCheckpoint, ArchiveDescriptor, BACKUP_PUBLICATION_DOMAIN,
    BackupGenerationPublication, BackupGenerationPublicationPayload, CollectionLocator,
    EncryptedObjectRef, KeyWrapContext, KeyWrapFormat, KeyWrapPurpose,
    RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryContext, SealedKeyWrap, TrustedWriter,
};
use kr_protocol::backup_checkpoint::HostCheckpoint;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, DeviceId, DeviceKeyRevision, GrantId, InvitationId,
};
use kr_protocol::pairing::{DevicePublicKeys, NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    Bytes, CanonicalSet, Digest256, EndpointKey, KeyId, Nonce192, Nullable, TimestampMs, U64, Uuid,
};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

/// The file of paired hosts as the release before the checkpoints read and wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenHostsFile {
    version: u32,
    hosts: Vec<FrozenHost>,
}

/// A paired host as that release kept it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenHost {
    host_device_id: DeviceId,
    host_key_revision: DeviceKeyRevision,
    host_keys: DevicePublicKeys,
    host_endpoint_id: EndpointKey,
    network_config: NetworkConfig,
    device_id: DeviceId,
    grant_id: GrantId,
    proposed_grant: ProposedGrant,
    name: Option<String>,
    paired_at_ms: u64,
    #[serde(default = "first_revision", skip_serializing_if = "is_first_revision")]
    device_key_revision: DeviceKeyRevision,
}

fn first_revision() -> DeviceKeyRevision {
    DeviceKeyRevision::new(1)
}

fn is_first_revision(revision: &DeviceKeyRevision) -> bool {
    *revision == first_revision()
}

/// The file of a waiting attempt as that release read and wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAttemptFile {
    version: u32,
    attempt: FrozenAttempt,
}

/// How a waiting attempt was made, as that release spelled it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FrozenMode {
    Code,
    Direct,
}

/// A waiting attempt as that release kept it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAttempt {
    mode: FrozenMode,
    invitation_id: InvitationId,
    host_device_id: DeviceId,
    host_key_revision: DeviceKeyRevision,
    host_keys: DevicePublicKeys,
    host_endpoint_id: EndpointKey,
    network_config: NetworkConfig,
    proposed_grant: ProposedGrant,
    verification_value: String,
    value_confirmed: bool,
    expires_at_ms: Option<u64>,
    recover_until_ms: u64,
    tries_left: Option<u32>,
}

fn grant() -> ProposedGrant {
    ProposedGrant {
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
    }
}

fn owner(byte: u8) -> PairedHost {
    let keys = DeviceKeys::generate().expect("keys").public_keys();
    PairedHost {
        host_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
        host_key_revision: DeviceKeyRevision::new(1),
        host_endpoint_id: keys.transport,
        host_keys: keys,
        network_config: NetworkConfig::empty(),
        device_id: DeviceId::new(Uuid::from_bytes([byte + 1; 16])),
        grant_id: GrantId::new(Uuid::from_bytes([byte + 2; 16])),
        proposed_grant: grant(),
        name: Some("a host".to_owned()),
        paired_at_ms: 1_764_000_000_000,
        device_key_revision: DeviceKeyRevision::new(1),
    }
}

/// An attempt that has proved itself to a host and waits for its owner, valid as the store reads it.
fn waiting(byte: u8) -> PendingAttempt {
    let keys = DeviceKeys::generate().expect("keys").public_keys();
    PendingAttempt {
        mode: AttemptMode::Code,
        invitation_id: InvitationId::new(Uuid::from_bytes([byte + 3; 16])),
        host_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
        host_key_revision: DeviceKeyRevision::new(1),
        host_endpoint_id: keys.transport,
        host_keys: keys,
        network_config: NetworkConfig::empty(),
        proposed_grant: grant(),
        verification_value: "123456".to_owned(),
        value_confirmed: true,
        expires_at_ms: Some(1_764_000_300_000),
        recover_until_ms: 1_764_000_300_000,
        tries_left: Some(2),
    }
}

fn the_answer(generation: u64) -> Answer {
    Answer::Checkpoint(HostCheckpoint {
        service_origin: GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
        archive_id: ArchiveId::new(Uuid::from_bytes([0x33; 16])),
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: Digest256::from_bytes([0x44; 32]),
    })
}

fn bytes(folder: &Path, name: &str) -> Option<Vec<u8>> {
    std::fs::read(folder.join(name)).ok()
}

/// The names in the folder.
fn names(folder: &Path) -> BTreeSet<String> {
    std::fs::read_dir(folder)
        .expect("the folder")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// The permission bits of each file in the folder, and of the folder; empty where the platform has
/// no such bits.
#[cfg(unix)]
fn modes(folder: &Path) -> std::collections::BTreeMap<String, u32> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut found = std::collections::BTreeMap::new();
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    found.insert(".".to_owned(), mode(folder));
    for name in names(folder) {
        found.insert(name.clone(), mode(&folder.join(&name)));
    }
    found
}

#[cfg(not(unix))]
fn modes(_folder: &Path) -> std::collections::BTreeMap<String, u32> {
    std::collections::BTreeMap::new()
}

fn strings(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_rollback_reads_the_paired_hosts_as_before_and_the_checkpoints_are_there_when_it_is_undone() {
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let host = owner(0x10);
    let attempt = waiting(0x20);
    hosts.record(host.clone()).expect("a paired host");
    hosts.keep_attempt(&attempt).expect("a waiting attempt");
    let names_before = names(&folder);
    assert_eq!(names_before, strings(&["attempt.json", "hosts.json"]));
    let hosts_before = bytes(&folder, "hosts.json").expect("the hosts file");
    let attempt_before = bytes(&folder, "attempt.json").expect("the attempt file");
    let modes_before = modes(&folder);

    // The older release reads both files, as its own types.
    let Ok(frozen) = serde_json::from_slice::<FrozenHostsFile>(&hosts_before) else {
        panic!("the older release reads the file of hosts")
    };
    assert_eq!(frozen.version, 1);
    assert_eq!(frozen.hosts.len(), 1);
    assert_eq!(frozen.hosts[0].host_device_id, host.host_device_id);
    assert_eq!(frozen.hosts[0].device_id, host.device_id);
    assert_eq!(frozen.hosts[0].grant_id, host.grant_id);
    assert_eq!(frozen.hosts[0].name, host.name);
    let Ok(frozen_attempt) = serde_json::from_slice::<FrozenAttemptFile>(&attempt_before) else {
        panic!("the older release reads the waiting attempt")
    };
    assert_eq!(frozen_attempt.version, 1);
    assert_eq!(frozen_attempt.attempt.invitation_id, attempt.invitation_id);
    assert_eq!(frozen_attempt.attempt.verification_value, "123456");
    assert!(frozen_attempt.attempt.value_confirmed);
    assert_eq!(frozen_attempt.attempt.tries_left, Some(2));

    // The newer release keeps a checkpoint for the pairing.
    let checkpoints = hosts.checkpoints();
    assert!(
        checkpoints
            .settle_checkpoint(&host, &the_answer(5), 1_000)
            .is_ok()
    );
    assert_eq!(
        names(&folder),
        strings(&[
            "attempt.json",
            "checkpoints.json",
            "checkpoints.lock",
            "hosts.json"
        ]),
        "the checkpoints add two files and take none away"
    );
    assert_eq!(
        bytes(&folder, "hosts.json"),
        Some(hosts_before.clone()),
        "keeping a checkpoint leaves the file of hosts as it was, byte for byte"
    );
    assert_eq!(
        bytes(&folder, "attempt.json"),
        Some(attempt_before.clone()),
        "and the waiting attempt too"
    );
    let modes_kept = modes(&folder);
    for name in [".", "attempt.json", "hosts.json"] {
        assert_eq!(
            modes_kept.get(name),
            modes_before.get(name),
            "keeping a checkpoint leaves the mode of {name} as it was"
        );
    }
    #[cfg(unix)]
    {
        assert_eq!(modes_kept["checkpoints.json"], 0o600);
        assert_eq!(modes_kept["checkpoints.lock"], 0o600);
        assert_eq!(modes_kept["hosts.json"], 0o600);
        assert_eq!(modes_kept["attempt.json"], 0o600);
        assert_eq!(modes_kept["."], 0o700);
    }

    // The older release writes both files again, as it does when it records a host and keeps an
    // attempt, and leaves the checkpoints and their lock alone, since it does not know them.
    let file_before = bytes(&folder, "checkpoints.json").expect("the checkpoints file");
    kr_ipc::paths::write_owner_only_file(
        &folder.join("hosts.json"),
        &serde_json::to_vec_pretty(&frozen).expect("the file of hosts"),
    )
    .expect("written by the older release");
    kr_ipc::paths::write_owner_only_file(
        &folder.join("attempt.json"),
        &serde_json::to_vec(&frozen_attempt).expect("the waiting attempt"),
    )
    .expect("written by the older release");
    assert_eq!(
        bytes(&folder, "checkpoints.json"),
        Some(file_before),
        "the older release does not touch the checkpoints"
    );
    assert_eq!(
        names(&folder),
        strings(&[
            "attempt.json",
            "checkpoints.json",
            "checkpoints.lock",
            "hosts.json"
        ]),
        "the older release leaves the checkpoints' files where they are"
    );
    #[cfg(unix)]
    {
        let modes_after = modes(&folder);
        assert_eq!(modes_after["checkpoints.json"], 0o600);
        assert_eq!(
            modes_after["checkpoints.lock"], 0o600,
            "the lock file stays owner-only after the rollback"
        );
        assert_eq!(modes_after["hosts.json"], 0o600);
        assert_eq!(modes_after["attempt.json"], 0o600);
        assert_eq!(modes_after["."], 0o700);
    }

    // The newer release comes back: it reads what the older one wrote, the checkpoint is held, and
    // the host is not owed one.
    let again = PairedHosts::open(&folder).expect("opened again");
    assert_eq!(again.list().expect("the hosts"), vec![host.clone()]);
    assert!(
        again.waiting_attempt().expect("the attempt") == Some(attempt),
        "the waiting attempt is the one that was kept"
    );
    let checkpoints = PairedCheckpoints::open(&folder).expect("opened again");
    let Held::Read { entries, owed, .. } = checkpoints.held_checkpoints() else {
        panic!("the checkpoints are read again")
    };
    assert_eq!(owed, 0, "the host's answer is still on file");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].backup_generation.get(), 5);

    // And a later answer raises it as before: the held entries resume.
    assert!(
        checkpoints
            .settle_checkpoint(&host, &the_answer(7), 2_000)
            .is_ok()
    );
    let Held::Read { entries, .. } = checkpoints.held_checkpoints() else {
        panic!("the checkpoints are read again")
    };
    assert_eq!(entries[0].backup_generation.get(), 7);
}

/// KR-REQ-20.12: the older release never reads `checkpoints.json`, so what it does to the paired
/// hosts leaves every entry. A forget by it takes a record out of `hosts.json` and no entry out of
/// the checkpoints, and the newer release, back again, returns every entry with only the hosts that
/// remain listed.
#[test]
fn a_forget_by_the_older_release_leaves_every_entry() {
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let (first, second) = (owner(0x10), owner(0x20));
    hosts.record(first.clone()).expect("a paired host");
    hosts.record(second.clone()).expect("a paired host");
    let checkpoints = hosts.checkpoints();
    checkpoints
        .settle_checkpoint(&first, &the_answer(5), 1_000)
        .expect("the first host's answer");
    checkpoints
        .settle_checkpoint(&second, &the_answer(6), 2_000)
        .expect("the second host's answer");
    let entries_before = bytes(&folder, "checkpoints.json").expect("the checkpoints file");

    // The older release reads the file of hosts as its own type and writes it back without the
    // first host, then without any.
    let Ok(frozen) =
        serde_json::from_slice::<FrozenHostsFile>(&bytes(&folder, "hosts.json").expect("hosts"))
    else {
        panic!("the older release reads the file of hosts")
    };
    let remaining: Vec<FrozenHost> = frozen
        .hosts
        .into_iter()
        .filter(|host| host.host_device_id != first.host_device_id)
        .collect();
    assert_eq!(remaining.len(), 1);
    for (left, listed) in [(remaining, vec![second.clone()]), (Vec::new(), Vec::new())] {
        kr_ipc::paths::write_owner_only_file(
            &folder.join("hosts.json"),
            &serde_json::to_vec(&FrozenHostsFile {
                version: 1,
                hosts: left,
            })
            .expect("the file of hosts"),
        )
        .expect("written by the older release");
        assert_eq!(
            bytes(&folder, "checkpoints.json"),
            Some(entries_before.clone()),
            "the older release does not touch the checkpoints"
        );
        let again = PairedCheckpoints::open(&folder).expect("opened again");
        let Held::Read {
            entries,
            owed: _,
            listed: now,
        } = again.held_checkpoints()
        else {
            panic!("the checkpoints are read again")
        };
        let mut generations: Vec<u64> = entries
            .iter()
            .map(|entry| entry.backup_generation.get())
            .collect();
        generations.sort_unstable();
        assert_eq!(generations, vec![5, 6], "every entry is still returned");
        assert_eq!(
            now,
            listed
                .iter()
                .map(|host| (host.host_endpoint_id, host.name.clone()))
                .collect::<Vec<_>>(),
            "only the hosts that remain are listed"
        );
    }
}

/// A service that serves one bundle and the one publication it was given, and no object: a restore
/// that is refused at the generation never asks for one.
#[derive(Debug)]
struct Serving {
    locator: String,
    bundle: Vec<u8>,
    publication: BackupGenerationPublication,
}

impl RestoreSource for Serving {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async {
            Ok(SourceService {
                origin: ORIGIN.to_owned(),
                managed_origin: ORIGIN.to_owned(),
                sign_in: SourceSignIn::Usable,
            })
        })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            Ok(if locator == self.locator {
                SyncFetched::Held {
                    position: SyncPosition::at(
                        1,
                        SyncRevision::new(Uuid::from_bytes([0x71; 16])),
                        None,
                    ),
                    ciphertext: self.bundle.clone(),
                }
            } else {
                SyncFetched::Absent { recovery: None }
            })
        })
    }

    fn generation<'a>(
        &'a self,
        _archive_id: ArchiveId,
        _checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<BackupGenerationPublication>> {
        Box::pin(async move { Ok(Some(self.publication.clone())) })
    }

    fn object(
        &self,
        _archive_id: ArchiveId,
        _object: BackupObjectId,
        _offset: u64,
        _length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        panic!("a restore refused at its generation reads no object")
    }
}

const ORIGIN: &str = "https://reach.kala.to";

/// A restore of the archive `the_answer` names, at generation `generation`, from a service that
/// holds one publication whose manifest key a producer with the key identifier `producer` wrapped,
/// held to what `held` says.
async fn restore_from(generation: u64, producer: KeyId, held: &Held) -> Result<(), RestoreError> {
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = fresh_locator().expect("a locator");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let archive_id = ArchiveId::new(Uuid::from_bytes([0x33; 16]));
    let manifest = EncryptedObjectRef {
        object_id: BackupObjectId::new(Uuid::from_bytes([0xf0; 16])),
        encrypted_object_hash: Digest256::from_bytes([0x45; 32]),
        encrypted_len: U64::new(400),
    };
    let descriptor = ArchiveDescriptor {
        version: U64::new(ARCHIVE_DESCRIPTOR_VERSION),
        archive_id,
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest: manifest.clone(),
        manifest_key_wraps: vec![SealedKeyWrap {
            context: KeyWrapContext {
                format: KeyWrapFormat::V1,
                purpose: KeyWrapPurpose::ManifestKey,
                archive_id,
                backup_generation: BackupGeneration::new(generation),
                object_id: manifest.object_id,
                encrypted_object_hash: manifest.encrypted_object_hash,
                sender_key_id: producer,
                recipient_key_id: KeyId::from_bytes([0x72; 32]),
            },
            nonce: Nonce192::from_bytes([0x73; 24]),
            ciphertext: Bytes::new(vec![0x74; 48]),
        }],
    };
    let payload = BackupGenerationPublicationPayload {
        descriptor,
        writer_key_id: writer.key_id(),
        published_at_ms: TimestampMs::new(5_000),
    };
    let signature = sign(
        &writer,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("an input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    let bundle = RecoveryBundle {
        schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
        collections: vec![CollectionLocator {
            service_origin: ORIGIN.to_owned(),
            locator: "collection-1".to_owned(),
            archive_id,
        }],
        trusted_writers: [TrustedWriter {
            writer_key_id: writer.key_id(),
            signing_key: *writer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }]
        .into_iter()
        .collect(),
        trusted_producers: BTreeSet::new().into_iter().collect(),
        checkpoints: Vec::new().into_iter().collect(),
        revision: U64::new(3),
        written_at_ms: TimestampMs::new(2_000),
        device_settings: None,
    };
    let key = seed
        .bundle_key_for(&RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: locator.clone(),
        })
        .expect("a bundle key");
    let serving = Serving {
        locator: locator.clone(),
        bundle: kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle).expect("a bundle"),
        publication: BackupGenerationPublication {
            payload: payload.clone(),
            signature,
        },
    };
    FilesRestore::prepare(
        seed.to_kit(vec![ORIGIN.to_owned()], locator),
        Arc::new(serving),
        None,
        None,
        held,
    )
    .await
    .map(|_| ())
}

/// KR-REQ-20.12: a host forgotten by the older release leaves its entry, and this release, back
/// again, applies the kept entry to a restore: the older generation of that host's own archive is
/// refused as held back by it. An entry of another producer holds nothing of the same archive.
#[tokio::test]
async fn a_restore_after_the_older_releases_forget_is_still_held_by_the_kept_entry() {
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let (first, second) = (owner(0x10), owner(0x20));
    hosts.record(first.clone()).expect("a paired host");
    hosts.record(second.clone()).expect("a paired host");
    let checkpoints = hosts.checkpoints();
    checkpoints
        .settle_checkpoint(&first, &the_answer(5), 1_000)
        .expect("the first host's answer");
    let producer = |host: &PairedHost| {
        kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::StoredEnvelope,
            host.host_keys.stored_envelope.as_bytes(),
        )
    };
    let held = |folder: &Path| {
        PairedCheckpoints::open(folder)
            .expect("opened")
            .held_checkpoints()
    };

    // The entry holds the first host's own archive back while the host is paired.
    let before = restore_from(3, producer(&first), &held(&folder)).await;
    assert!(
        matches!(
            &before,
            Err(RestoreError::Publication(PublicationRefusal::Generation(standing, _)))
                if standing.standing
                    == GenerationStanding::Replayed { checkpoint: BackupGeneration::new(5) }
        ),
        "{before:?}"
    );

    // The older release forgets that host by rewriting the file of hosts without it.
    let Ok(frozen) =
        serde_json::from_slice::<FrozenHostsFile>(&bytes(&folder, "hosts.json").expect("hosts"))
    else {
        panic!("the older release reads the file of hosts")
    };
    let remaining: Vec<FrozenHost> = frozen
        .hosts
        .into_iter()
        .filter(|host| host.host_device_id != first.host_device_id)
        .collect();
    kr_ipc::paths::write_owner_only_file(
        &folder.join("hosts.json"),
        &serde_json::to_vec(&FrozenHostsFile {
            version: 1,
            hosts: remaining,
        })
        .expect("the file of hosts"),
    )
    .expect("written by the older release");
    let Held::Read { listed, .. } = held(&folder) else {
        panic!("the checkpoints are read again")
    };
    assert_eq!(listed.len(), 1, "only the second host is still listed");

    // This release applies the kept entry to a restore: the same refusal, though the host is gone.
    let after = restore_from(3, producer(&first), &held(&folder)).await;
    assert!(
        matches!(
            &after,
            Err(RestoreError::Publication(PublicationRefusal::Generation(standing, _)))
                if standing.standing
                    == GenerationStanding::Replayed { checkpoint: BackupGeneration::new(5) }
        ),
        "{after:?}"
    );

    // Control: an archive of the host that is still listed has no entry, so nothing holds it back,
    // and the restore goes on to the wrap, which names no key of this kit.
    let other = restore_from(3, producer(&second), &held(&folder)).await;
    assert!(
        matches!(other, Err(RestoreError::NoWrap)),
        "an archive of another producer is held by no entry: {other:?}"
    );
}
