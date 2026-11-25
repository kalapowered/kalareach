//! The backup checkpoints a paired host gave this device, kept beside the paired-host records.
//!
//! A host that commits an owner device can say the newest backup generation its storage service
//! accepted. A device that keeps that answer can tell a service that hands back an older backup
//! than the host published, which a recovery bundle's own checkpoint cannot always catch. The
//! answers are kept in `checkpoints.json`, beside `hosts.json`, and nothing here changes `hosts.json`
//! or `attempt.json`.
//!
//! * A checkpoint belongs to an archive at a service, not to a pairing: it stays when a pairing is
//!   replaced or a host is forgotten, and no write ever lowers one.
//! * Whether a host still owes a checkpoint is derived, never written beforehand: an owner pairing
//!   with no `told` entry owes one. The file says only that a read of that pairing completed, and
//!   what it answered.
//! * Every operation takes an operating-system lock on `checkpoints.lock` for its own file work and
//!   never holds it across a wait on the network. The work is synchronous: a caller on a runtime
//!   runs it on a blocking task.
//! * A file this release cannot read is a refusal, never an empty set.

use std::collections::BTreeSet;
use std::fs::TryLockError;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_protocol::ids::{ArchiveId, BackupGeneration, DeviceId};
use kr_protocol::scalars::Digest256;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::failure::{FailureKind, PairingFailure};
use super::paired::{PairedHost, read_hosts};
use crate::shown::Shown;

/// The version of the file this release writes and reads.
const FORMAT_VERSION: u32 = 1;

/// The largest file this release reads. The checkpoints are bounded well below it.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The most checkpoints the file holds. A host cannot fill the file by naming archives.
const MAX_CHECKPOINTS: usize = 1_024;

/// The file the checkpoints and the answers are kept in.
const CHECKPOINTS_FILE: &str = "checkpoints.json";

/// The file the operating-system lock is taken on. It is never read as data.
const LOCK_FILE: &str = "checkpoints.lock";

/// How often a waiting operation tries the lock again.
const LOCK_STEP: Duration = Duration::from_millis(20);

/// How long an operation waits for the lock before it gives up.
const LOCK_WITHIN: Duration = Duration::from_secs(2);

/// One pairing: the host, and the identity the host gave this device in that pairing.
///
/// A device that pairs with a host again is given a new identity, so the new pairing is another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairingId {
    /// The host's device identity.
    pub host_device_id: DeviceId,
    /// The identity the host gave this device.
    pub device_id: DeviceId,
}

impl PairingId {
    /// The pairing a record holds.
    #[must_use]
    pub const fn of(host: &PairedHost) -> Self {
        Self {
            host_device_id: host.host_device_id,
            device_id: host.device_id,
        }
    }
}

/// The newest backup generation of one archive at one service that a host named, with the
/// manifest it named for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedCheckpoint {
    /// The service the archive is at, as the host spells it.
    pub service_origin: GatewayOrigin,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation the host named. It is never 0.
    pub backup_generation: BackupGeneration,
    /// The hash of that generation's encrypted manifest.
    pub encrypted_manifest_hash: Digest256,
    /// When this device took the checkpoint, in UTC milliseconds.
    pub taken_at_ms: u64,
}

/// What a host answered when this device asked for its checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intended {
    /// The host named a checkpoint.
    Checkpoint,
    /// The host had accepted no generation.
    NothingPublished,
}

/// A read of one pairing that completed, and what it answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Told {
    host_device_id: DeviceId,
    device_id: DeviceId,
    answer: Intended,
    /// When the answer last changed, in UTC milliseconds.
    at_ms: u64,
}

impl Told {
    fn is(&self, id: PairingId) -> bool {
        self.host_device_id == id.host_device_id && self.device_id == id.device_id
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointsFile {
    version: u32,
    checkpoints: Vec<PairedCheckpoint>,
    told: Vec<Told>,
}

impl CheckpointsFile {
    const fn empty() -> Self {
        Self {
            version: FORMAT_VERSION,
            checkpoints: Vec::new(),
            told: Vec::new(),
        }
    }
}

/// Why the checkpoints could not be read as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotCause {
    /// The file or the lock file cannot be used, or the file is not one this release reads.
    Unreadable,
    /// A newer release wrote the file.
    NewerVersion,
    /// Something else holds the lock, and did not let go in time.
    Busy,
    /// The list of paired hosts cannot be read, so it cannot be said which hosts owe a checkpoint.
    HostsFile,
}

/// The checkpoints as a restore reads them.
#[derive(Debug)]
pub enum Held {
    /// There is no store of paired hosts: this computer has paired with no host, as on a host that
    /// restores its own backup.
    Absent,
    /// The checkpoints that are held, and how many owner pairings have not been answered.
    Read {
        /// Every checkpoint held, for every archive and service.
        entries: Vec<PairedCheckpoint>,
        /// How many owner pairings have no answer on file.
        owed: usize,
    },
    /// The checkpoints cannot be read. A restore refuses, and never reads this as no checkpoint.
    Unreadable {
        /// The file that cannot be used.
        file: Shown,
        /// Why.
        why: Shown,
        /// The kind of reason.
        cause: SnapshotCause,
    },
}

/// Whether a host owes a checkpoint, and whether it is to be asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acquisition {
    /// The record is not an owner record, or it is not the host's current pairing: nothing is to be
    /// asked for it.
    NotAnOwner,
    /// An owner pairing no read of which has completed.
    Owed,
    /// An owner pairing whose host said it had accepted no generation. It may accept one later.
    NothingPublished,
    /// An owner pairing whose host named a checkpoint.
    Told,
}

/// A refusal to read the checkpoints, with the file it is about.
struct Refused {
    file: Shown,
    why: Shown,
    cause: SnapshotCause,
}

/// The checkpoints a paired host gave this device, in the directory the paired-host records are in.
///
/// It reads `hosts.json` and writes nothing there, so the application that only restores opens it
/// without a store of paired hosts.
#[derive(Clone)]
pub struct PairedCheckpoints {
    directory: PathBuf,
}

crate::debug_as_name!(PairedCheckpoints);

impl PairedCheckpoints {
    /// Opens the checkpoints in `directory`, creating it owner-only when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the directory cannot be created or is not one this
    /// user owns alone.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, PairingFailure> {
        let directory = directory.into();
        kr_ipc::paths::create_private_directory(&directory).map_err(|error| {
            PairingFailure::new(
                FailureKind::StoreFailed,
                crate::shown!("{}: {}", Shown::root(&directory), Shown::ipc(&error)),
            )
        })?;
        Ok(Self::at(directory))
    }

    /// The checkpoints of a directory that exists.
    pub(super) const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Every checkpoint held and how many owner pairings are unanswered, read under the lock.
    ///
    /// It never fails: a file that cannot be read is [`Held::Unreadable`], so that no caller reads a
    /// failure as no checkpoints.
    #[must_use]
    pub fn held_checkpoints(&self) -> Held {
        match self.snapshot() {
            Ok((_lock, snapshot)) => Held::Read {
                owed: snapshot.owed(),
                entries: snapshot.file.checkpoints,
            },
            Err(refused) => Held::Unreadable {
                file: refused.file,
                why: refused.why,
                cause: refused.cause,
            },
        }
    }

    /// Whether `record`'s host owes a checkpoint and is to be asked, from one snapshot under the
    /// lock.
    ///
    /// The record counts only while it is the host's current pairing in `hosts.json`: a record of an
    /// earlier pairing, and a host that is no longer listed, are [`Acquisition::NotAnOwner`]. A
    /// `told` entry of another pairing counts as absent.
    ///
    /// # Errors
    ///
    /// Returns why the snapshot could not be taken. A failed read of `hosts.json` is
    /// [`SnapshotCause::HostsFile`], never [`Acquisition::NotAnOwner`].
    pub fn acquisition(&self, record: &PairedHost) -> Result<Acquisition, SnapshotCause> {
        let (_lock, snapshot) = self.snapshot().map_err(|refused| refused.cause)?;
        let id = PairingId::of(record);
        let owner = snapshot
            .hosts
            .iter()
            .any(|host| PairingId::of(host) == id && host.is_owner());
        if !owner {
            return Ok(Acquisition::NotAnOwner);
        }
        Ok(match snapshot.told(id) {
            None => Acquisition::Owed,
            Some(Intended::NothingPublished) => Acquisition::NothingPublished,
            Some(Intended::Checkpoint) => Acquisition::Told,
        })
    }

    /// The file, and the paired hosts, read together while the lock is held. The lock is let go
    /// when the first of the pair drops.
    fn snapshot(&self) -> Result<(Locked, Snapshot), Refused> {
        let lock = self.lock()?;
        let file = self.read_file()?;
        let hosts = read_hosts(&self.directory).map_err(|failure| Refused {
            file: Shown::within(&self.directory, "hosts.json"),
            why: failure.detail,
            cause: SnapshotCause::HostsFile,
        })?;
        Ok((lock, Snapshot { file, hosts }))
    }

    /// Takes the lock, trying again every [`LOCK_STEP`] for at most [`LOCK_WITHIN`], with a handle
    /// of its own.
    fn lock(&self) -> Result<Locked, Refused> {
        let refused = |cause: SnapshotCause, why: Shown| Refused {
            file: Shown::within(&self.directory, LOCK_FILE),
            why,
            cause,
        };
        let file = kr_ipc::paths::open_lock_file(&self.directory.join(LOCK_FILE))
            .map_err(|error| refused(SnapshotCause::Unreadable, Shown::io(&error)))?;
        let started = Instant::now();
        loop {
            match kr_flush::lock::try_exclusive(&file) {
                Ok(()) => return Ok(Locked(file)),
                Err(TryLockError::WouldBlock) if started.elapsed() < LOCK_WITHIN => {
                    std::thread::sleep(LOCK_STEP);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(refused(
                        SnapshotCause::Busy,
                        Shown::said("something else on this device is changing it"),
                    ));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(refused(SnapshotCause::Unreadable, Shown::io(&error)));
                }
            }
        }
    }

    /// The file as it stands: empty when there is none, a refusal when it cannot be used.
    fn read_file(&self) -> Result<CheckpointsFile, Refused> {
        let refused = |cause: SnapshotCause, why: Shown| Refused {
            file: Shown::within(&self.directory, CHECKPOINTS_FILE),
            why,
            cause,
        };
        let path = self.directory.join(CHECKPOINTS_FILE);
        match kr_ipc::paths::read_owner_only_file(&path, MAX_FILE_BYTES) {
            Ok(None) => Ok(CheckpointsFile::empty()),
            Ok(Some(bytes)) => parse(&bytes).map_err(|(cause, why)| refused(cause, why)),
            Err(error) => Err(refused(SnapshotCause::Unreadable, Shown::ipc(&error))),
        }
    }
}

/// An operating-system lock on `checkpoints.lock`, let go when it drops.
struct Locked(std::fs::File);

impl Drop for Locked {
    /// It lets go before the handle closes, so that a child process that inherited the descriptor
    /// cannot keep the lock.
    fn drop(&mut self) {
        let _ = kr_flush::lock::release(&self.0);
    }
}

/// What one look at the file and at `hosts.json` showed.
struct Snapshot {
    file: CheckpointsFile,
    hosts: Vec<PairedHost>,
}

impl Snapshot {
    fn told(&self, id: PairingId) -> Option<Intended> {
        self.file
            .told
            .iter()
            .find(|told| told.is(id))
            .map(|told| told.answer)
    }

    /// How many owner pairings have no `told` entry.
    fn owed(&self) -> usize {
        self.hosts
            .iter()
            .filter(|host| host.is_owner() && self.told(PairingId::of(host)).is_none())
            .count()
    }
}

/// Reads a file as this release writes it, or says why it cannot.
///
/// A version above this release's is [`SnapshotCause::NewerVersion`] whatever else that file holds,
/// since a later release may change its shape.
fn parse(bytes: &[u8]) -> Result<CheckpointsFile, (SnapshotCause, Shown)> {
    let unreadable = |why: Shown| (SnapshotCause::Unreadable, why);
    let not_understood = |error: &serde_json::Error| {
        unreadable(crate::shown!(
            "it is not a checkpoints file this release understands: {}",
            Shown::json(error)
        ))
    };
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| not_understood(&e))?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if let Some(newer) = version.filter(|version| *version > u64::from(FORMAT_VERSION)) {
        return Err((
            SnapshotCause::NewerVersion,
            crate::shown!(
                "it is version {}, and this release reads {}",
                newer,
                FORMAT_VERSION
            ),
        ));
    }
    let file: CheckpointsFile = serde_json::from_value(value).map_err(|e| not_understood(&e))?;
    if file.version != FORMAT_VERSION {
        return Err(unreadable(crate::shown!(
            "it is version {}, and this release reads {}",
            file.version,
            FORMAT_VERSION
        )));
    }
    if file.checkpoints.len() > MAX_CHECKPOINTS {
        return Err(unreadable(crate::shown!(
            "it holds more than {} checkpoints",
            MAX_CHECKPOINTS
        )));
    }
    if file
        .checkpoints
        .iter()
        .any(|held| held.backup_generation.get() == 0)
    {
        return Err(unreadable(Shown::said(
            "it holds a checkpoint of generation 0, which no host publishes",
        )));
    }
    let mut archives = BTreeSet::new();
    if !file
        .checkpoints
        .iter()
        .all(|held| archives.insert((held.service_origin.as_str(), held.archive_id)))
    {
        return Err(unreadable(Shown::said(
            "it names one archive of one service twice",
        )));
    }
    let mut pairings = BTreeSet::new();
    if !file
        .told
        .iter()
        .all(|told| pairings.insert((told.host_device_id, told.device_id)))
    {
        return Err(unreadable(Shown::said("it names one pairing twice")));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::paired::PairedHosts;
    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{DeviceKeyRevision, GrantId};
    use kr_protocol::pairing::{NetworkConfig, ProposedGrant};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    fn grant(actions: &[ActionRight]) -> ProposedGrant {
        ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: actions.iter().copied().collect::<CanonicalSet<_>>(),
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

    /// A host of pairing `(byte, byte + 1)`.
    fn host(byte: u8, actions: &[ActionRight]) -> PairedHost {
        let keys = DeviceKeys::generate().expect("keys").public_keys();
        PairedHost {
            host_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
            host_key_revision: DeviceKeyRevision::new(1),
            host_endpoint_id: keys.transport,
            host_keys: keys,
            network_config: NetworkConfig::empty(),
            device_id: DeviceId::new(Uuid::from_bytes([byte + 1; 16])),
            grant_id: GrantId::new(Uuid::from_bytes([byte + 2; 16])),
            proposed_grant: grant(actions),
            name: None,
            paired_at_ms: 1_764_000_000_000,
            device_key_revision: DeviceKeyRevision::new(1),
        }
    }

    fn owner(byte: u8) -> PairedHost {
        host(byte, &[ActionRight::HostManage])
    }

    fn entry(archive: u8, generation: u64) -> PairedCheckpoint {
        PairedCheckpoint {
            service_origin: GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
            archive_id: ArchiveId::new(Uuid::from_bytes([archive; 16])),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest_hash: Digest256::from_bytes([archive; 32]),
            taken_at_ms: 1_764_000_000_000,
        }
    }

    fn told(host: &PairedHost, answer: Intended) -> Told {
        Told {
            host_device_id: host.host_device_id,
            device_id: host.device_id,
            answer,
            at_ms: 1_764_000_000_000,
        }
    }

    struct Rig {
        _directory: tempfile::TempDir,
        hosts: PairedHosts,
        checkpoints: PairedCheckpoints,
    }

    impl Rig {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a directory on the internal disk");
            let hosts = PairedHosts::open(directory.path().join("pairing")).expect("a store");
            let checkpoints = hosts.checkpoints();
            Self {
                _directory: directory,
                hosts,
                checkpoints,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.hosts.directory().join(name)
        }

        /// Writes the checkpoints file as `value` says, whatever it holds.
        fn write(&self, value: &serde_json::Value) {
            kr_ipc::paths::write_owner_only_file(
                &self.path(CHECKPOINTS_FILE),
                &serde_json::to_vec(value).expect("bytes"),
            )
            .expect("written");
        }

        fn write_file(&self, checkpoints: Vec<PairedCheckpoint>, told: Vec<Told>) {
            self.write(
                &serde_json::to_value(CheckpointsFile {
                    version: FORMAT_VERSION,
                    checkpoints,
                    told,
                })
                .expect("a value"),
            );
        }
    }

    fn cause(held: &Held) -> Option<SnapshotCause> {
        match held {
            Held::Unreadable { cause, .. } => Some(*cause),
            _ => None,
        }
    }

    /// An absent file is the empty set, and a host that has not answered is owed.
    #[test]
    fn an_absent_file_is_the_empty_set_and_an_unanswered_owner_is_owed() {
        let rig = Rig::new();
        let Held::Read { entries, owed } = rig.checkpoints.held_checkpoints() else {
            panic!("an absent file reads as the empty set");
        };
        assert!(entries.is_empty());
        assert_eq!(owed, 0, "no host is paired");

        rig.hosts.record(owner(1)).expect("recorded");
        rig.hosts
            .record(host(7, &[ActionRight::SessionView]))
            .expect("recorded");
        let Held::Read { entries, owed } = rig.checkpoints.held_checkpoints() else {
            panic!("an absent file reads as the empty set");
        };
        assert!(entries.is_empty());
        assert_eq!(owed, 1, "the owner is owed and the viewer is not");
    }

    /// Entries and answers read back as written, and an answer settles the pairing it names.
    #[test]
    fn what_the_file_holds_is_read_back_and_an_answer_settles_only_its_own_pairing() {
        let rig = Rig::new();
        let (first, second) = (owner(1), owner(4));
        rig.hosts.record(first.clone()).expect("recorded");
        rig.hosts.record(second.clone()).expect("recorded");
        rig.write_file(
            vec![entry(1, 7), entry(2, 3)],
            vec![told(&first, Intended::Checkpoint)],
        );
        let Held::Read { entries, owed } = rig.checkpoints.held_checkpoints() else {
            panic!("a readable file");
        };
        assert_eq!(entries, vec![entry(1, 7), entry(2, 3)]);
        assert_eq!(owed, 1, "only the second owner has no answer");
        assert_eq!(rig.checkpoints.acquisition(&first), Ok(Acquisition::Told));
        assert_eq!(rig.checkpoints.acquisition(&second), Ok(Acquisition::Owed));
    }

    /// Each refusal of the parser is an unreadable file, with its cause, and never an empty set.
    #[test]
    fn a_file_this_release_does_not_read_is_unreadable_and_never_empty() {
        let rig = Rig::new();
        rig.hosts.record(owner(1)).expect("recorded");
        let good = serde_json::to_value(CheckpointsFile {
            version: FORMAT_VERSION,
            checkpoints: vec![entry(1, 7)],
            told: vec![told(&owner(1), Intended::Checkpoint)],
        })
        .expect("a value");
        let with = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            change(&mut value);
            value
        };
        let too_many: Vec<PairedCheckpoint> = (0..=MAX_CHECKPOINTS)
            .map(|position| {
                let mut held = entry(1, 1);
                held.archive_id = ArchiveId::new(Uuid::from_bytes(
                    u128::try_from(position).expect("a count").to_be_bytes(),
                ));
                held
            })
            .collect();
        let cases: Vec<(&str, Vec<u8>, SnapshotCause)> = vec![
            ("not JSON", b"{".to_vec(), SnapshotCause::Unreadable),
            (
                "an unknown member",
                serde_json::to_vec(&with(&|v| {
                    v["extra"] = serde_json::json!(1);
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "version 0",
                serde_json::to_vec(&with(&|v| v["version"] = serde_json::json!(0))).expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "a newer version of another shape",
                serde_json::to_vec(&serde_json::json!({"version": 2, "other": []})).expect("bytes"),
                SnapshotCause::NewerVersion,
            ),
            (
                "a checkpoint named twice",
                serde_json::to_vec(&with(&|v| {
                    let held = v["checkpoints"][0].clone();
                    v["checkpoints"].as_array_mut().expect("a list").push(held);
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "a pairing told twice",
                serde_json::to_vec(&with(&|v| {
                    let again = v["told"][0].clone();
                    v["told"].as_array_mut().expect("a list").push(again);
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "an origin spelled with its default port",
                serde_json::to_vec(&with(&|v| {
                    v["checkpoints"][0]["service_origin"] =
                        serde_json::json!("https://reach.kala.to:443");
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "generation 0",
                serde_json::to_vec(&with(&|v| {
                    v["checkpoints"][0]["backup_generation"] = serde_json::json!("0");
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
            (
                "more than 1024 checkpoints",
                serde_json::to_vec(&with(&|v| {
                    v["checkpoints"] = serde_json::to_value(&too_many).expect("a value");
                }))
                .expect("bytes"),
                SnapshotCause::Unreadable,
            ),
        ];
        for (name, bytes, expected) in cases {
            kr_ipc::paths::write_owner_only_file(&rig.path(CHECKPOINTS_FILE), &bytes)
                .expect("written");
            let held = rig.checkpoints.held_checkpoints();
            assert_eq!(cause(&held), Some(expected), "{name}: {held:?}");
            assert_eq!(
                rig.checkpoints.acquisition(&owner(1)),
                Err(expected),
                "{name}"
            );
        }
        rig.write(&good);
        assert!(matches!(
            rig.checkpoints.held_checkpoints(),
            Held::Read { .. }
        ));
    }

    /// A file that is a directory, a link, or open to others is refused by the file helpers, and
    /// so is unreadable.
    #[cfg(unix)]
    #[test]
    fn a_file_that_is_a_directory_a_link_or_open_to_others_is_unreadable() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let rig = Rig::new();
        let path = rig.path(CHECKPOINTS_FILE);
        std::fs::create_dir(&path).expect("a directory");
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable),
            "a directory"
        );
        std::fs::remove_dir(&path).expect("removed");

        rig.write_file(vec![entry(1, 7)], Vec::new());
        let held = rig.path("held.json");
        std::fs::rename(&path, &held).expect("moved");
        symlink(&held, &path).expect("a link");
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable),
            "a link"
        );
        std::fs::remove_file(&path).expect("removed");

        std::fs::rename(&held, &path).expect("moved back");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("opened");
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable),
            "a file open to others"
        );
    }

    /// Each state of acquisition, for the current pairing and for the records that are not.
    #[test]
    fn acquisition_tells_each_state_apart_and_a_stale_record_is_not_an_owner() {
        let rig = Rig::new();
        let (owed, empty, told_one) = (owner(1), owner(4), owner(7));
        let viewer = host(10, &[ActionRight::SessionView]);
        for record in [&owed, &empty, &told_one, &viewer] {
            rig.hosts.record(record.clone()).expect("recorded");
        }
        rig.write_file(
            vec![entry(1, 7)],
            vec![
                told(&empty, Intended::NothingPublished),
                told(&told_one, Intended::Checkpoint),
            ],
        );
        let state = |record: &PairedHost| rig.checkpoints.acquisition(record);
        assert_eq!(state(&owed), Ok(Acquisition::Owed));
        assert_eq!(state(&empty), Ok(Acquisition::NothingPublished));
        assert_eq!(state(&told_one), Ok(Acquisition::Told));
        assert_eq!(state(&viewer), Ok(Acquisition::NotAnOwner));
        assert_eq!(
            state(&owner(20)),
            Ok(Acquisition::NotAnOwner),
            "a host that is not listed"
        );

        // The host is paired again: the old record is no longer the host's current pairing, the
        // new one has no answer, and the old answer does not count for it.
        let mut again = told_one.clone();
        again.device_id = DeviceId::new(Uuid::from_bytes([99; 16]));
        rig.hosts.record(again.clone()).expect("recorded");
        assert_eq!(
            state(&told_one),
            Ok(Acquisition::NotAnOwner),
            "the old pairing"
        );
        assert_eq!(
            state(&again),
            Ok(Acquisition::Owed),
            "an answer of another pairing"
        );
    }

    /// A failed read of `hosts.json` is a failure of the snapshot, never nothing owed and never a
    /// record that is not an owner.
    #[test]
    fn an_unreadable_hosts_file_is_a_failure_and_never_nothing_owed() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        kr_ipc::paths::write_owner_only_file(
            &rig.path("hosts.json"),
            b"{\"version\":1,\"hosts\":[{}]}",
        )
        .expect("overwritten");
        let held = rig.checkpoints.held_checkpoints();
        assert_eq!(cause(&held), Some(SnapshotCause::HostsFile), "{held:?}");
        assert_eq!(
            rig.checkpoints.acquisition(&record),
            Err(SnapshotCause::HostsFile)
        );
    }

    /// A snapshot waits for the lock, says Busy when it is not let go, and works again after.
    #[test]
    fn a_snapshot_waits_for_the_lock_and_says_busy_and_never_empty() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        rig.write_file(vec![entry(1, 7)], Vec::new());

        let holder = kr_ipc::paths::open_lock_file(&rig.path(LOCK_FILE)).expect("a lock file");
        kr_flush::lock::exclusive(&holder).expect("held");
        let started = Instant::now();
        let held = rig.checkpoints.held_checkpoints();
        assert_eq!(cause(&held), Some(SnapshotCause::Busy), "{held:?}");
        assert!(
            started.elapsed() >= LOCK_WITHIN,
            "it waited for the lock for the bound"
        );
        assert_eq!(
            rig.checkpoints.acquisition(&record),
            Err(SnapshotCause::Busy)
        );

        kr_flush::lock::release(&holder).expect("released");
        assert!(matches!(
            rig.checkpoints.held_checkpoints(),
            Held::Read { .. }
        ));
        assert_eq!(rig.checkpoints.acquisition(&record), Ok(Acquisition::Owed));
        assert!(
            rig.path(LOCK_FILE).exists(),
            "the lock file stays, and is never data"
        );
    }

    /// A lock file that is a link or a FIFO is refused at once, and a lock file is owner-only.
    #[cfg(unix)]
    #[test]
    fn a_lock_file_that_is_a_link_or_a_fifo_is_refused_without_blocking() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let rig = Rig::new();
        assert!(matches!(
            rig.checkpoints.held_checkpoints(),
            Held::Read { .. }
        ));
        let mode = std::fs::metadata(rig.path(LOCK_FILE))
            .expect("the lock file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the lock file is owner-only");
        std::fs::remove_file(rig.path(LOCK_FILE)).expect("removed");

        let target = rig.path("elsewhere");
        std::fs::write(&target, b"").expect("a file");
        symlink(&target, rig.path(LOCK_FILE)).expect("a link");
        let refused_within = |rig: &Rig| {
            let checkpoints = rig.checkpoints.clone();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(cause(&checkpoints.held_checkpoints()));
            });
            receiver.recv_timeout(Duration::from_secs(10))
        };
        assert_eq!(
            refused_within(&rig),
            Ok(Some(SnapshotCause::Unreadable)),
            "a link"
        );
        std::fs::remove_file(rig.path(LOCK_FILE)).expect("removed");

        let made = std::process::Command::new("mkfifo")
            .arg(rig.path(LOCK_FILE))
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        assert_eq!(
            refused_within(&rig),
            Ok(Some(SnapshotCause::Unreadable)),
            "a FIFO"
        );
    }
}
