//! KR-REQ-20.12: a rollback to a release that does not know the checkpoints leaves the paired-host
//! files that release reads exactly as they were, and the checkpoints are there when the newer
//! release is back.
//!
//! The older release's reader of `hosts.json` is frozen here: a copy of its file type as it stood
//! before the checkpoints existed, which refuses a field it does not know.

use std::path::Path;

use kr_client::pairing::checkpoint::{Answer, Held, PairedCheckpoints, PairingId};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::backup_checkpoint::HostCheckpoint;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{ArchiveId, BackupGeneration, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, Uuid};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

/// The file of paired hosts as the release before the checkpoints read and wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenHostsFile {
    version: u32,
    hosts: Vec<PairedHost>,
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

#[test]
fn a_rollback_reads_the_paired_hosts_as_before_and_the_checkpoints_are_there_when_it_is_undone() {
    let directory = tempfile::tempdir().expect("a directory");
    let folder = directory.path().join("pairing");
    let hosts = PairedHosts::open(&folder).expect("a store");
    let host = owner(0x10);
    hosts.record(host.clone()).expect("a paired host");
    // A waiting attempt is a file of the release's own that the checkpoints must leave alone.
    std::fs::write(
        folder.join("attempt.json"),
        b"an attempt this release wrote",
    )
    .expect("a file");
    let hosts_before = bytes(&folder, "hosts.json").expect("the hosts file");
    let attempt_before = bytes(&folder, "attempt.json").expect("the attempt file");

    // The newer release keeps a checkpoint for the pairing.
    let checkpoints = hosts.checkpoints();
    assert!(
        checkpoints
            .settle_checkpoint(PairingId::of(&host), &the_answer(5), 1_000)
            .is_ok()
    );
    assert!(folder.join("checkpoints.json").exists());
    assert!(folder.join("checkpoints.lock").exists());
    assert_eq!(
        bytes(&folder, "hosts.json"),
        Some(hosts_before.clone()),
        "keeping a checkpoint leaves the file of hosts as it was, byte for byte"
    );
    assert_eq!(
        bytes(&folder, "attempt.json"),
        Some(attempt_before),
        "and the waiting attempt too"
    );

    // The older release reads the same file, with the files it does not know beside it.
    let Ok(frozen) = serde_json::from_slice::<FrozenHostsFile>(&hosts_before) else {
        panic!("the older release reads the file of hosts")
    };
    assert_eq!(frozen.version, 1);
    assert_eq!(frozen.hosts.len(), 1);
    assert_eq!(frozen.hosts[0].host_device_id, host.host_device_id);
    assert_eq!(frozen.hosts[0].device_id, host.device_id);

    // It writes the file of hosts again, as it does when it records a host, and leaves the
    // checkpoints alone, since it does not know them.
    let file_before = bytes(&folder, "checkpoints.json").expect("the checkpoints file");
    std::fs::write(
        folder.join("hosts.json"),
        serde_json::to_vec_pretty(&frozen).expect("the file of hosts"),
    )
    .expect("written by the older release");
    assert_eq!(
        bytes(&folder, "checkpoints.json"),
        Some(file_before),
        "the older release does not touch the checkpoints"
    );

    // The newer release comes back: the checkpoint is held, and the host is not owed one.
    let again = PairedCheckpoints::open(&folder).expect("opened again");
    let Held::Read { entries, owed } = again.held_checkpoints() else {
        panic!("the checkpoints are read again")
    };
    assert_eq!(owed, 0, "the host's answer is still on file");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].backup_generation.get(), 5);

    // And a later answer raises it as before: the held entries resume.
    assert!(
        again
            .settle_checkpoint(PairingId::of(&host), &the_answer(7), 2_000)
            .is_ok()
    );
    let Held::Read { entries, .. } = again.held_checkpoints() else {
        panic!("the checkpoints are read again")
    };
    assert_eq!(entries[0].backup_generation.get(), 7);
}
