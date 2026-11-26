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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_protocol::backup_checkpoint::{
    BackupCheckpointParams, BackupCheckpointResult, HostCheckpoint,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupGeneration, DeviceId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Digest256;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::failure::{FailureKind, PairingFailure};
use super::paired::{PairedHost, read_hosts};
use crate::error::ClientError;
use crate::recovery::Standing;
use crate::session::Session;
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for PairedCheckpoint {
    /// The generation only: the service, the archive and the manifest hash are what a host sent.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairedCheckpoint")
            .field("backup_generation", &self.backup_generation)
            .finish_non_exhaustive()
    }
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// What a host answered when this device asked it for its checkpoint.
#[derive(Clone, PartialEq, Eq)]
pub enum Answer {
    /// The host named a checkpoint.
    Checkpoint(HostCheckpoint),
    /// The host had accepted no generation.
    NothingPublished,
}

impl std::fmt::Debug for Answer {
    /// Which kind of answer it is and, for a checkpoint, its generation; never the manifest hash.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Checkpoint(given) => formatter
                .debug_struct("Checkpoint")
                .field("backup_generation", &given.backup_generation)
                .finish_non_exhaustive(),
            Self::NothingPublished => formatter.write_str("NothingPublished"),
        }
    }
}

impl Answer {
    /// What the pairing's `told` entry says once this answer is settled.
    const fn intended(&self) -> Intended {
        match self {
            Self::Checkpoint(_) => Intended::Checkpoint,
            Self::NothingPublished => Intended::NothingPublished,
        }
    }
}

/// How a settled answer stood against what the file held. No outcome lowers or deletes a
/// checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The archive had no checkpoint at that service, and now has this one.
    New,
    /// The host named a newer generation than the one held, and it replaced it.
    Raised,
    /// The host named the generation held, with the manifest held.
    Same,
    /// The host named an older generation than the one held, which stays.
    Lower,
    /// The host named the generation held with another manifest. The one held stays.
    Disagrees,
    /// The host had accepted no generation.
    NothingPublished,
    /// The file was replaced, and the directory could not be confirmed to hold it. The file is
    /// either the old one or the new one, whole.
    Uncertain,
}

/// An answer that is part of the file now: the pairing's `told` entry names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// How the answer stood against the file.
    pub outcome: Outcome,
    /// What the answer said, which an uncertain outcome does not otherwise tell.
    pub intended: Intended,
}

/// An answer that is not part of the file. The pairing's state is as it was, and no held
/// checkpoint was lowered or deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsettled {
    /// The pairing is no longer the host's current one in `hosts.json`. A checkpoint the answer
    /// raised was taken, and no `told` entry was written.
    Superseded,
    /// The answer names a new archive past the bound, or the file would pass the byte cap.
    Full,
    /// The answer names generation 0, which no host publishes and the file never holds.
    Malformed,
    /// The file or `hosts.json` cannot be read.
    Unreadable(SnapshotCause),
    /// Something else holds the lock.
    Busy,
    /// The file could not be written, and it was not replaced.
    WriteFailed,
}

impl From<Refused> for Unsettled {
    fn from(refused: Refused) -> Self {
        match refused.cause {
            SnapshotCause::Busy => Self::Busy,
            cause => Self::Unreadable(cause),
        }
    }
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
    /// How the file is replaced. The one value production gives is
    /// [`kr_ipc::paths::write_owner_only_file`]; a test gives another so that it can count the
    /// writes, or fail one, which no real directory does on request: the replacement can land and
    /// the flush of the directory after it fail, and a settle must tell that from a write that never
    /// began.
    write: Writer,
}

/// A function that replaces a file whole.
type Writer = fn(&Path, &[u8]) -> kr_ipc::Result<()>;

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
    pub(super) fn at(directory: PathBuf) -> Self {
        Self {
            directory,
            write: kr_ipc::paths::write_owner_only_file,
        }
    }

    /// These checkpoints, replacing the file through `write`.
    #[cfg(test)]
    fn with_writer(mut self, write: Writer) -> Self {
        self.write = write;
        self
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

    /// Settles what the host of pairing `id` answered: at most one write, under the lock, and never
    /// one that lowers or deletes a checkpoint.
    ///
    /// A checkpoint is set against the one held for its archive at its service (`Standing`), and
    /// only a newer generation replaces it. The pairing's `told` entry is written when the pairing
    /// is still the host's current one and the answer is new or changed; an entry of a pairing that
    /// has gone is dropped. When the write reports an error, the file is read again: if it holds
    /// what was meant, the replacement landed and the outcome is [`Outcome::Uncertain`].
    ///
    /// # Errors
    ///
    /// Returns why nothing was settled, and with [`Unsettled::Superseded`] that the pairing has
    /// gone, after the checkpoint it named was taken.
    pub fn settle_checkpoint(
        &self,
        id: PairingId,
        answer: &Answer,
        now_ms: u64,
    ) -> Result<Settled, Unsettled> {
        if matches!(answer, Answer::Checkpoint(given) if given.backup_generation.get() == 0) {
            return Err(Unsettled::Malformed);
        }
        let (_lock, snapshot) = self.snapshot()?;
        let Snapshot { file, hosts } = snapshot;
        let current = hosts.iter().any(|host| PairingId::of(host) == id);
        let intended = answer.intended();
        let mut next = file.clone();
        let mut outcome = match answer {
            Answer::NothingPublished => Outcome::NothingPublished,
            Answer::Checkpoint(given) => take(&mut next.checkpoints, given, now_ms)?,
        };
        next.told
            .retain(|told| hosts.iter().any(|host| told.is(PairingId::of(host))));
        if current {
            match next.told.iter_mut().find(|told| told.is(id)) {
                Some(told) if told.answer == intended => {}
                Some(told) => {
                    told.answer = intended;
                    told.at_ms = now_ms;
                }
                None => next.told.push(Told {
                    host_device_id: id.host_device_id,
                    device_id: id.device_id,
                    answer: intended,
                    at_ms: now_ms,
                }),
            }
        }
        if next != file {
            let bytes = serde_json::to_vec(&next).map_err(|_| Unsettled::WriteFailed)?;
            if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_FILE_BYTES) {
                return Err(Unsettled::Full);
            }
            let path = self.directory.join(CHECKPOINTS_FILE);
            if (self.write)(&path, &bytes).is_err() {
                match self.read_file() {
                    Ok(read) if read == next => outcome = Outcome::Uncertain,
                    _ => return Err(Unsettled::WriteFailed),
                }
            }
        }
        if current {
            Ok(Settled { outcome, intended })
        } else {
            Err(Unsettled::Superseded)
        }
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

/// Sets `given` against the checkpoint held for its archive at its service, and takes it when it
/// is newer. A new archive past the bound is refused.
fn take(
    held: &mut Vec<PairedCheckpoint>,
    given: &HostCheckpoint,
    now_ms: u64,
) -> Result<Outcome, Unsettled> {
    let key = |entry: &PairedCheckpoint| {
        entry.service_origin == given.service_origin && entry.archive_id == given.archive_id
    };
    let known = held.iter().any(key);
    let standing = Standing::of(
        held.iter()
            .find(|entry| key(entry))
            .map(|entry| (entry.backup_generation, &entry.encrypted_manifest_hash)),
        (given.backup_generation, &given.encrypted_manifest_hash),
    );
    match standing {
        Standing::Same => Ok(Outcome::Same),
        Standing::Lower => Ok(Outcome::Lower),
        Standing::Disagrees => Ok(Outcome::Disagrees),
        Standing::Raises => {
            if !known && held.len() >= MAX_CHECKPOINTS {
                return Err(Unsettled::Full);
            }
            held.retain(|entry| !key(entry));
            held.push(PairedCheckpoint {
                service_origin: given.service_origin.clone(),
                archive_id: given.archive_id,
                backup_generation: given.backup_generation,
                encrypted_manifest_hash: given.encrypted_manifest_hash,
                taken_at_ms: now_ms,
            });
            Ok(if known { Outcome::Raised } else { Outcome::New })
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

/// Why a read of a host's checkpoint did not give an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadCause {
    /// The host refused the method as one it does not serve, which is how a host of an earlier
    /// release answers, or the right to read it was withdrawn since the connection was made.
    HostLacksIt,
    /// The host refused for another reason.
    Refused(ErrorCode),
    /// The answer is not one this release reads, an answer of generation 0 among them.
    Malformed,
    /// The connection failed or ended.
    Lost,
    /// The host did not answer in time.
    TimedOut,
}

/// Asks the host `session` is connected to for its checkpoint, once.
///
/// The read does not signal the session's standing: a host of an earlier release refuses the
/// method as one it does not serve at each ask, and that is no sign the host withdrew the
/// connection. The caller bounds the wait, and a read cut at its bound can leave the session's
/// control stream marked, so the caller gives it a session that nothing else uses.
///
/// # Errors
///
/// Returns why the host gave no answer this release reads.
pub async fn read_checkpoint(session: &Session) -> Result<Answer, ReadCause> {
    let result: BackupCheckpointResult = session
        .read_unsignalled(Method::BackupCheckpoint, &BackupCheckpointParams {})
        .await
        .map_err(|error| match error {
            ClientError::Host(refusal) | ClientError::Refused { error: refusal, .. } => {
                if refusal.code == ErrorCode::PermissionDenied {
                    ReadCause::HostLacksIt
                } else {
                    ReadCause::Refused(refusal.code)
                }
            }
            ClientError::Cbor(_) => ReadCause::Malformed,
            _ => ReadCause::Lost,
        })?;
    Ok(result
        .checkpoint
        .as_ref()
        .map_or(Answer::NothingPublished, |held| {
            Answer::Checkpoint(held.clone())
        }))
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

    const NOW: u64 = 1_764_000_100_000;

    fn given(archive: u8, generation: u64) -> Answer {
        Answer::Checkpoint(host_checkpoint(
            "https://reach.kala.to",
            archive,
            generation,
            archive,
        ))
    }

    fn host_checkpoint(origin: &str, archive: u8, generation: u64, manifest: u8) -> HostCheckpoint {
        HostCheckpoint {
            service_origin: GatewayOrigin::new(origin).expect("an origin"),
            archive_id: ArchiveId::new(Uuid::from_bytes([archive; 16])),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest_hash: Digest256::from_bytes([manifest; 32]),
        }
    }

    fn id(record: &PairedHost) -> PairingId {
        PairingId::of(record)
    }

    fn entries(rig: &Rig) -> Vec<(u8, u64)> {
        let Held::Read { entries, .. } = rig.checkpoints.held_checkpoints() else {
            panic!("a readable file");
        };
        let mut named: Vec<(u8, u64)> = entries
            .iter()
            .map(|held| {
                let archive = (0..=u8::MAX)
                    .find(|byte| held.archive_id == ArchiveId::new(Uuid::from_bytes([*byte; 16])))
                    .unwrap_or(0);
                (archive, held.backup_generation.get())
            })
            .collect();
        named.sort_unstable();
        named
    }

    fn answers(rig: &Rig) -> Vec<(PairingId, Intended, u64)> {
        let bytes = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");
        let file: CheckpointsFile = serde_json::from_slice(&bytes).expect("a file");
        file.told
            .iter()
            .map(|told| {
                (
                    PairingId {
                        host_device_id: told.host_device_id,
                        device_id: told.device_id,
                    },
                    told.answer,
                    told.at_ms,
                )
            })
            .collect()
    }

    fn settled(outcome: Outcome, intended: Intended) -> Result<Settled, Unsettled> {
        Ok(Settled { outcome, intended })
    }

    /// Each outcome of a settle is its own, a held checkpoint never goes down, and the checkpoints
    /// are read apart from the answers.
    #[test]
    fn each_outcome_of_a_settle_is_its_own_and_no_held_checkpoint_goes_down() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(id(&record), &answer, NOW);

        assert_eq!(
            settle(given(1, 7)),
            settled(Outcome::New, Intended::Checkpoint)
        );
        assert_eq!(entries(&rig), vec![(1, 7)]);
        assert_eq!(
            answers(&rig),
            vec![(id(&record), Intended::Checkpoint, NOW)]
        );
        assert_eq!(
            settle(given(1, 7)),
            settled(Outcome::Same, Intended::Checkpoint)
        );
        assert_eq!(
            settle(given(1, 9)),
            settled(Outcome::Raised, Intended::Checkpoint)
        );
        assert_eq!(entries(&rig), vec![(1, 9)]);
        assert_eq!(
            settle(given(1, 8)),
            settled(Outcome::Lower, Intended::Checkpoint)
        );
        assert_eq!(entries(&rig), vec![(1, 9)], "a lower answer lowers nothing");
        let other_manifest = Answer::Checkpoint(host_checkpoint("https://reach.kala.to", 1, 9, 77));
        assert_eq!(
            settle(other_manifest),
            settled(Outcome::Disagrees, Intended::Checkpoint)
        );
        assert_eq!(entries(&rig), vec![(1, 9)], "the held entry stands");
        assert_eq!(
            rig.checkpoints.acquisition(&record),
            Ok(Acquisition::Told),
            "a host that disagreed is settled"
        );
        assert_eq!(
            settle(Answer::NothingPublished),
            settled(Outcome::NothingPublished, Intended::NothingPublished)
        );
        assert_eq!(
            entries(&rig),
            vec![(1, 9)],
            "no answer deletes a checkpoint"
        );
        assert_eq!(
            rig.checkpoints.acquisition(&record),
            Ok(Acquisition::NothingPublished)
        );
    }

    /// An answer for a pairing that is no longer the host's current one raises a checkpoint and
    /// writes no answer.
    #[test]
    fn an_answer_of_an_earlier_pairing_raises_a_checkpoint_and_settles_no_pairing() {
        let rig = Rig::new();
        let old = owner(1);
        let mut current = old.clone();
        current.device_id = DeviceId::new(Uuid::from_bytes([50; 16]));
        rig.hosts.record(current.clone()).expect("recorded");

        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&old), &given(1, 4), NOW),
            Err(Unsettled::Superseded)
        );
        assert_eq!(entries(&rig), vec![(1, 4)], "the checkpoint was taken");
        assert!(answers(&rig).is_empty(), "no answer was written");
        assert_eq!(
            rig.checkpoints.acquisition(&current),
            Ok(Acquisition::Owed),
            "the current pairing is still owed"
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&old), &Answer::NothingPublished, NOW),
            Err(Unsettled::Superseded)
        );
        assert!(answers(&rig).is_empty());
    }

    thread_local! {
        static WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    fn counting(path: &Path, bytes: &[u8]) -> kr_ipc::Result<()> {
        WRITES.set(WRITES.get() + 1);
        kr_ipc::paths::write_owner_only_file(path, bytes)
    }

    /// A write that changes nothing is not made.
    #[test]
    fn a_write_that_changes_nothing_is_not_made() {
        let mut rig = Rig::new();
        rig.checkpoints = rig.checkpoints.clone().with_writer(counting);
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(id(&record), &answer, NOW);
        WRITES.set(0);

        settle(given(1, 7)).expect("settled");
        assert_eq!(WRITES.get(), 1, "a new checkpoint is written");
        settle(given(1, 7)).expect("settled");
        settle(given(1, 6)).expect("settled");
        settle(Answer::Checkpoint(host_checkpoint(
            "https://reach.kala.to",
            1,
            7,
            99,
        )))
        .expect("settled");
        assert_eq!(
            WRITES.get(),
            1,
            "the same, a lower and a disagreeing answer write nothing"
        );
        settle(Answer::NothingPublished).expect("settled");
        assert_eq!(
            WRITES.get(),
            2,
            "an answer that changes the entry is written"
        );
        settle(Answer::NothingPublished).expect("settled");
        assert_eq!(WRITES.get(), 2, "the same answer again writes nothing");
    }

    fn fails_before(_: &Path, _: &[u8]) -> kr_ipc::Result<()> {
        Err(kr_ipc::IpcError::io(
            "write",
            "checkpoints.json",
            std::io::Error::other("no space"),
        ))
    }

    /// The write lands and then the directory flush fails, as `write_owner_only_file` reports it.
    fn fails_after(path: &Path, bytes: &[u8]) -> kr_ipc::Result<()> {
        kr_ipc::paths::write_owner_only_file(path, bytes)?;
        Err(kr_ipc::IpcError::io(
            "flush",
            "pairing",
            std::io::Error::other("the directory cannot be flushed"),
        ))
    }

    /// A write that fails before the replacement leaves the old file whole, and one that fails after
    /// it is told apart by reading the file again.
    #[test]
    fn a_failure_before_the_replacement_is_a_failure_and_one_after_it_is_uncertain() {
        let mut rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        rig.checkpoints
            .settle_checkpoint(id(&record), &given(1, 7), NOW)
            .expect("settled");
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");

        rig.checkpoints = rig.checkpoints.clone().with_writer(fails_before);
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 9), NOW),
            Err(Unsettled::WriteFailed)
        );
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            before,
            "the old file is whole"
        );

        rig.checkpoints = rig.checkpoints.clone().with_writer(fails_after);
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 9), NOW),
            settled(Outcome::Uncertain, Intended::Checkpoint)
        );
        assert_eq!(entries(&rig), vec![(1, 9)], "the new file stands");
    }

    /// A new archive past the bound is refused and an archive already held still rises, and an
    /// answer of generation 0 is never written.
    #[test]
    fn the_bound_refuses_a_new_archive_and_generation_zero_is_never_written() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let full: Vec<PairedCheckpoint> = (0..MAX_CHECKPOINTS)
            .map(|position| {
                let mut held = entry(1, 1);
                held.archive_id = ArchiveId::new(Uuid::from_bytes(
                    u128::try_from(position + 1).expect("a count").to_be_bytes(),
                ));
                held
            })
            .collect();
        rig.write_file(full, Vec::new());
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");

        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(200, 1), NOW),
            Err(Unsettled::Full)
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 0), NOW),
            Err(Unsettled::Malformed)
        );
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            before,
            "nothing was written"
        );
        let mut known = host_checkpoint("https://reach.kala.to", 1, 5, 1);
        known.archive_id = ArchiveId::new(Uuid::from_bytes(1_u128.to_be_bytes()));
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &Answer::Checkpoint(known), NOW),
            settled(Outcome::Raised, Intended::Checkpoint),
            "an archive already held still rises at the bound"
        );
    }

    /// An answer of a pairing that has gone is dropped at the next settle.
    #[test]
    fn an_answer_of_a_pairing_that_is_gone_is_dropped_at_the_next_settle() {
        let rig = Rig::new();
        let record = owner(1);
        let gone = owner(4);
        rig.hosts.record(record.clone()).expect("recorded");
        rig.write_file(Vec::new(), vec![told(&gone, Intended::Checkpoint)]);

        rig.checkpoints
            .settle_checkpoint(id(&record), &Answer::NothingPublished, NOW)
            .expect("settled");
        assert_eq!(
            answers(&rig),
            vec![(id(&record), Intended::NothingPublished, NOW)]
        );
    }

    /// A settle that cannot read the file, or `hosts.json`, writes nothing.
    #[test]
    fn a_settle_that_cannot_read_what_it_rests_on_writes_nothing() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let settle = || {
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 3), NOW)
        };

        kr_ipc::paths::write_owner_only_file(&rig.path(CHECKPOINTS_FILE), b"{").expect("a file");
        assert_eq!(
            settle(),
            Err(Unsettled::Unreadable(SnapshotCause::Unreadable))
        );
        rig.write(&serde_json::json!({"version": 2}));
        assert_eq!(
            settle(),
            Err(Unsettled::Unreadable(SnapshotCause::NewerVersion))
        );
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            serde_json::to_vec(&serde_json::json!({"version": 2})).expect("bytes"),
            "the file a newer release wrote is not replaced"
        );
        rig.write_file(Vec::new(), Vec::new());
        kr_ipc::paths::write_owner_only_file(
            &rig.path("hosts.json"),
            b"{\"version\":1,\"hosts\":[{}]}",
        )
        .expect("overwritten");
        assert_eq!(
            settle(),
            Err(Unsettled::Unreadable(SnapshotCause::HostsFile))
        );
    }

    /// Two archives of one id at two services are two entries, and the answered origin is the key.
    #[test]
    fn one_archive_id_at_two_services_is_two_entries() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let at = |origin: &str, generation: u64| {
            Answer::Checkpoint(host_checkpoint(origin, 1, generation, 1))
        };
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(id(&record), &answer, NOW);

        assert_eq!(
            settle(at("https://one.example", 3)),
            settled(Outcome::New, Intended::Checkpoint)
        );
        assert_eq!(
            settle(at("https://two.example", 5)),
            settled(Outcome::New, Intended::Checkpoint),
            "another service is another entry"
        );
        assert_eq!(
            settle(at("https://one.example", 4)),
            settled(Outcome::Raised, Intended::Checkpoint)
        );
        let Held::Read { entries, .. } = rig.checkpoints.held_checkpoints() else {
            panic!("a readable file");
        };
        let mut held: Vec<(String, u64)> = entries
            .iter()
            .map(|held| {
                (
                    held.service_origin.as_str().to_owned(),
                    held.backup_generation.get(),
                )
            })
            .collect();
        held.sort();
        assert_eq!(
            held,
            vec![
                ("https://one.example".to_owned(), 4),
                ("https://two.example".to_owned(), 5)
            ]
        );
    }

    /// A settle waits for the lock and says Busy, and writes nothing.
    #[test]
    fn a_settle_waits_for_the_lock_and_says_busy_and_writes_nothing() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let holder = kr_ipc::paths::open_lock_file(&rig.path(LOCK_FILE)).expect("a lock file");
        kr_flush::lock::exclusive(&holder).expect("held");

        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 3), NOW),
            Err(Unsettled::Busy)
        );
        assert!(!rig.path(CHECKPOINTS_FILE).exists(), "nothing was written");
        kr_flush::lock::release(&holder).expect("released");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(1, 3), NOW),
            settled(Outcome::New, Intended::Checkpoint)
        );
    }

    /// Handles of one directory, on two threads, never lose each other's entries or lower one.
    #[test]
    fn two_handles_settling_beside_each_other_lose_no_entry_and_lower_none() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let record_id = id(&record);
        let spawn = |archives: std::ops::Range<u8>| {
            let checkpoints = rig.hosts.checkpoints();
            std::thread::spawn(move || {
                for archive in archives {
                    checkpoints
                        .settle_checkpoint(record_id, &given(archive, 1), NOW)
                        .expect("settled");
                }
            })
        };
        let (first, second) = (spawn(1..31), spawn(31..61));
        first.join().expect("the first thread");
        second.join().expect("the second thread");
        assert_eq!(entries(&rig).len(), 60, "every entry is there");

        for round in 0..20_u8 {
            let key = 100 + round;
            let handles: Vec<_> = [10_u64, 12, 11]
                .into_iter()
                .map(|generation| {
                    let checkpoints = rig.hosts.checkpoints();
                    std::thread::spawn(move || {
                        checkpoints.settle_checkpoint(record_id, &given(key, generation), NOW)
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("a thread").expect("settled");
            }
            assert!(
                entries(&rig).contains(&(key, 12)),
                "round {round}: generations 10, 12 and 11 end at 12"
            );
        }
    }

    /// A second process settles beside this one under the same lock.
    #[test]
    fn a_second_process_settles_beside_this_one() {
        const CHILD: &str = "KR_CHECKPOINT_TEST_DIRECTORY";
        if let Ok(directory) = std::env::var(CHILD) {
            // The child process: it settles thirty archives through a handle of its own.
            let checkpoints = PairedCheckpoints::open(&directory).expect("the directory");
            let record = read_hosts(Path::new(&directory)).expect("hosts").remove(0);
            for archive in 31..61_u8 {
                checkpoints
                    .settle_checkpoint(id(&record), &given(archive, 1), NOW)
                    .expect("settled");
            }
            return;
        }
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let mut child = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "pairing::checkpoint::tests::a_second_process_settles_beside_this_one",
            ])
            .env(CHILD, rig.hosts.directory())
            .spawn()
            .expect("the child starts");
        for archive in 1..31_u8 {
            rig.checkpoints
                .settle_checkpoint(id(&record), &given(archive, 1), NOW)
                .expect("settled");
        }
        assert!(child.wait().expect("the child ends").success());
        assert_eq!(entries(&rig).len(), 60, "both processes' entries are there");
    }
}
