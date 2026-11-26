//! The backup checkpoints a paired host gave this device, kept beside the paired-host records.
//!
//! A host that commits an owner device can say the newest backup generation its storage service
//! accepted. A device that keeps that answer can tell a service that hands back an older backup
//! than the host published, which a recovery bundle's own checkpoint cannot always catch. The
//! answers are kept in `checkpoints.json`, beside `hosts.json`, and nothing here changes `hosts.json`
//! or `attempt.json`.
//!
//! * A checkpoint belongs to an archive at a service that one host produced, not to a pairing: the
//!   entry names the host's endpoint and the key id of the stored-envelope key its record declared
//!   (the producer), beside the service and the archive. It stays when a pairing is replaced or a
//!   host is forgotten, and no write ever lowers one.
//! * Whether a host still owes a checkpoint is derived, never written beforehand: an owner pairing
//!   with no `told` entry owes one. The file says only that a read of that pairing completed, and
//!   what it answered. Only an owner pairing is asked, so only an owner record settles an answer.
//! * A host's answer is taken only when the host proves it: each ask carries a fresh challenge and
//!   key, and the host's box must open under the key its pairing declares and hold this challenge,
//!   the host's endpoint and the checkpoint named beside it. See [`read_checkpoint`].
//! * Every operation takes an operating-system lock on `checkpoints.lock` for its own file work and
//!   never holds it across a wait on the network. The work is synchronous: a caller on a runtime
//!   runs it on a blocking task.
//! * A file this release cannot read is a refusal, never an empty set.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::TryLockError;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_crypto::keys::{StoredEnvelopeKeyPair, key_id};
use kr_crypto::sealed::open_stored_envelope;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::backup_checkpoint::{
    BackupCheckpointParams, BackupCheckpointResult, HOST_CHECKPOINT_PROOF_DOMAIN, HostCheckpoint,
    HostCheckpointProof,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupGeneration, DeviceId};
use kr_protocol::method::Method;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Digest256, EndpointKey, KeyId, Nonce256};
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

/// The most checkpoints one host endpoint holds over the whole history of this file, whatever its
/// producers, services, archives and pairings. A host cannot take the file's room for itself.
const MAX_PER_HOST: usize = 16;

/// The file the checkpoints and the answers are kept in.
const CHECKPOINTS_FILE: &str = "checkpoints.json";

/// The file the operating-system lock is taken on. It is never read as data.
const LOCK_FILE: &str = "checkpoints.lock";

/// How often a waiting operation tries the lock again.
const LOCK_STEP: Duration = Duration::from_millis(20);

/// How long an operation waits for the lock before it gives up.
const LOCK_WITHIN: Duration = Duration::from_secs(2);

/// One pairing: the host, the endpoint it is reached at, and the identity the host gave this device
/// in that pairing.
///
/// A device that pairs with a host again is given a new identity, so the new pairing is another one.
/// The host's identity is what the host declared, so two hosts can declare one: the endpoint tells
/// them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairingId {
    /// The host's device identity.
    pub host_device_id: DeviceId,
    /// The host's endpoint.
    pub host_endpoint_id: EndpointKey,
    /// The identity the host gave this device.
    pub device_id: DeviceId,
}

impl PairingId {
    /// The pairing a record holds.
    #[must_use]
    pub const fn of(host: &PairedHost) -> Self {
        Self {
            host_device_id: host.host_device_id,
            host_endpoint_id: host.host_endpoint_id,
            device_id: host.device_id,
        }
    }
}

/// The newest backup generation of one archive at one service that a host named, with the
/// manifest it named for it.
///
/// An entry is kept by its key: the host's endpoint, the producer, the service and the archive. Two
/// entries that differ in any one part are two entries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedCheckpoint {
    /// The endpoint of the host that gave the checkpoint.
    pub host_endpoint_id: EndpointKey,
    /// The key id of the stored-envelope key that host's record declared when it gave it: the key
    /// that names the host as the producer of an archive.
    pub producer: KeyId,
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
    host_endpoint_id: EndpointKey,
    device_id: DeviceId,
    answer: Intended,
    /// When the answer last changed, in UTC milliseconds.
    at_ms: u64,
}

impl Told {
    fn is(&self, id: PairingId) -> bool {
        self.host_device_id == id.host_device_id
            && self.host_endpoint_id == id.host_endpoint_id
            && self.device_id == id.device_id
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
    /// The file cannot be used, or is not one this release reads.
    Unreadable,
    /// A newer release wrote the file.
    NewerVersion,
    /// The lock file cannot be opened or locked. It holds no checkpoint. A program that holds the
    /// lock keeps it on the file it opened, so the file is removed only with every program that
    /// uses the store closed.
    Lock,
    /// Something else holds the lock, and did not let go in time: a use of the lock, not a change
    /// to the file.
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
        /// The hosts `hosts.json` lists, each by its endpoint and the name it gives people, read
        /// together with the entries. An entry names its host by endpoint whether or not the host
        /// is listed.
        listed: Vec<(EndpointKey, Option<String>)>,
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
}

/// An answer that is part of the file now: the pairing's `told` entry names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// How the answer stood against the file.
    pub outcome: Outcome,
    /// Whether the directory is known to hold the file this settle wrote. It is not when that file
    /// was replaced and the flush of the directory after it failed: the file is then the old one or
    /// the new one, whole. A settle that writes nothing gives `true`, also after an earlier settle
    /// whose write was not confirmed.
    pub confirmed: bool,
}

/// An answer that is not part of the file. The pairing's state is as it was, and no held
/// checkpoint was lowered or deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsettled {
    /// The record is not an owner pairing: a host asked for its checkpoint only on an owner
    /// pairing, so an answer for any other takes nothing and writes nothing.
    NotAnOwner,
    /// The pairing is no longer the host's current owner pairing in `hosts.json`. A checkpoint the
    /// answer raised was taken, and no `told` entry was written.
    Superseded,
    /// The answer names a new archive past the bound, or the file would pass the byte cap.
    Full,
    /// The answer names generation 0, which no host publishes and the file never holds.
    Malformed,
    /// The file, its lock file or `hosts.json` cannot be used.
    Unreadable(SnapshotCause),
    /// Something else holds the lock.
    Busy,
    /// The file could not be written. Either a second read showed the old file, or that read
    /// failed too; in the second case the replacement may have landed, since a failed read after a
    /// failed write cannot tell.
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
                listed: snapshot
                    .hosts
                    .iter()
                    .map(|host| (host.host_endpoint_id, host.name.clone()))
                    .collect(),
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

    /// Settles what the host of the pairing `host` holds answered: at most one write, under the
    /// lock, and never one that lowers or deletes a checkpoint.
    ///
    /// `host` is the record the answer was read through, and it alone says whose answer this is: the
    /// entry is kept under the endpoint of `host` and the producer its declared key names, never
    /// under what `hosts.json` holds now. A checkpoint is set against the one held for the same
    /// endpoint, producer, service and archive (`Standing`), and only a newer generation replaces
    /// it. The pairing's `told` entry is written when `host` is still the host's current owner
    /// pairing in `hosts.json` and the answer is new or changed; an entry of a pairing that has gone
    /// is dropped. When the write reports an error, the file is read again: if it holds what was
    /// meant, the replacement landed and the answer is settled with `confirmed` false.
    ///
    /// # Errors
    ///
    /// Returns [`Unsettled::NotAnOwner`] at once, before the lock and with nothing taken, for a
    /// record that is no owner. Otherwise returns why nothing was settled, and with
    /// [`Unsettled::Superseded`] that the pairing is no longer the current owner pairing, after the
    /// checkpoint it named was taken.
    pub fn settle_checkpoint(
        &self,
        host: &PairedHost,
        answer: &Answer,
        now_ms: u64,
    ) -> Result<Settled, Unsettled> {
        if !host.is_owner() {
            return Err(Unsettled::NotAnOwner);
        }
        let id = PairingId::of(host);
        if matches!(answer, Answer::Checkpoint(given) if given.backup_generation.get() == 0) {
            return Err(Unsettled::Malformed);
        }
        let (_lock, snapshot) = self.snapshot()?;
        let Snapshot { file, hosts } = snapshot;
        let current = hosts
            .iter()
            .any(|listed| PairingId::of(listed) == id && listed.is_owner());
        let intended = answer.intended();
        let mut next = file.clone();
        let mut confirmed = true;
        let outcome = match answer {
            Answer::NothingPublished => Outcome::NothingPublished,
            Answer::Checkpoint(given) => take(&mut next.checkpoints, host, given, now_ms)?,
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
                    host_endpoint_id: id.host_endpoint_id,
                    device_id: id.device_id,
                    answer: intended,
                    at_ms: now_ms,
                }),
            }
        }
        if next != file {
            let bytes = serde_json::to_vec(&next).map_err(|_| Unsettled::WriteFailed)?;
            // No readable file reaches this check. `parse` refuses a file of more than 1,024
            // checkpoints, one that names a key or a pairing twice and one that holds more than 16
            // checkpoints of one endpoint, and `take` refuses a new key at 1,024 or at 16 of its
            // endpoint, so a result holds at most 1,024 checkpoints of 473 bytes or less (the
            // longest service, an endpoint and a producer of 43 characters each, a generation and
            // a time of 20 digits). The settle drops each `told` entry of a pairing that no record
            // of `hosts.json` holds, so a result holds at most one `told` entry of 231 bytes or
            // less for each record (two identities of 36 characters, an endpoint of 43, the longest
            // answer and a time of 20 digits). That file is read up to 4 MiB, in records whose
            // values alone take 339 bytes or more (three identities and five keys), so it holds at
            // most 12,372 records: 1,024 x 474 + 12,372 x 232 + 40 = 3,355,720 bytes. The check
            // guards a change to those bounds.
            if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_FILE_BYTES) {
                return Err(Unsettled::Full);
            }
            let path = self.directory.join(CHECKPOINTS_FILE);
            if (self.write)(&path, &bytes).is_err() {
                match self.read_file() {
                    Ok(read) if read == next => confirmed = false,
                    // The file read again is not the one meant, or cannot be read: a failed read
                    // after a failed write cannot tell whether the replacement landed.
                    _ => return Err(Unsettled::WriteFailed),
                }
            }
        }
        if current {
            Ok(Settled { outcome, confirmed })
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
            .map_err(|error| refused(SnapshotCause::Lock, Shown::io(&error)))?;
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
                        Shown::said("something else on this device is using it"),
                    ));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(refused(SnapshotCause::Lock, Shown::io(&error)));
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

/// Sets `given` against the checkpoint that `host` gave for its archive at its service, and takes
/// it when it is newer. The entry is the one with the same endpoint, producer, service and archive;
/// an answer of another host never raises it. A new key past the file's bound, or past the bound of
/// the host's endpoint, is refused; an entry held is never refused, lowered or dropped.
fn take(
    held: &mut Vec<PairedCheckpoint>,
    host: &PairedHost,
    given: &HostCheckpoint,
    now_ms: u64,
) -> Result<Outcome, Unsettled> {
    let producer = producer_of(host);
    let key = |entry: &PairedCheckpoint| {
        entry.host_endpoint_id == host.host_endpoint_id
            && entry.producer == producer
            && entry.service_origin == given.service_origin
            && entry.archive_id == given.archive_id
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
            // An entry held always rises. A new key is refused at the file's bound and at the
            // bound of its host, which counts every entry of that endpoint.
            let of_host = held
                .iter()
                .filter(|entry| entry.host_endpoint_id == host.host_endpoint_id)
                .count();
            if !known && (held.len() >= MAX_CHECKPOINTS || of_host >= MAX_PER_HOST) {
                return Err(Unsettled::Full);
            }
            held.retain(|entry| !key(entry));
            held.push(PairedCheckpoint {
                host_endpoint_id: host.host_endpoint_id,
                producer,
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

/// The key id of the stored-envelope key `host`'s record declares: the producer an answer of that
/// host counts for.
fn producer_of(host: &PairedHost) -> KeyId {
    key_id(
        KeyPurpose::StoredEnvelope,
        host.host_keys.stored_envelope.as_bytes(),
    )
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

/// The version member alone, read first. A repeated `version` is refused here; the file's own type
/// then reads every other member and refuses one that appears twice or that it does not know.
#[derive(Deserialize)]
struct Header {
    version: Option<u64>,
}

/// Reads a file as this release writes it, or says why it cannot.
///
/// A version above this release's is [`SnapshotCause::NewerVersion`] whatever else that file holds,
/// since a later release may change its shape. Otherwise the file is read from its bytes into its
/// own type, so a member that appears twice, in the file or in an entry, makes it unreadable and
/// the last of the two is never taken.
fn parse(bytes: &[u8]) -> Result<CheckpointsFile, (SnapshotCause, Shown)> {
    let unreadable = |why: Shown| (SnapshotCause::Unreadable, why);
    let not_understood = |error: &serde_json::Error| {
        unreadable(crate::shown!(
            "it is not a checkpoints file this release understands: {}",
            Shown::json(error)
        ))
    };
    let header: Header = serde_json::from_slice(bytes).map_err(|e| not_understood(&e))?;
    if let Some(newer) = header
        .version
        .filter(|version| *version > u64::from(FORMAT_VERSION))
    {
        return Err((
            SnapshotCause::NewerVersion,
            crate::shown!(
                "it is version {}, and this release reads {}",
                newer,
                FORMAT_VERSION
            ),
        ));
    }
    let file: CheckpointsFile = serde_json::from_slice(bytes).map_err(|e| not_understood(&e))?;
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
    let mut keys = BTreeSet::new();
    if !file.checkpoints.iter().all(|held| {
        keys.insert((
            held.host_endpoint_id,
            held.producer,
            held.service_origin.as_str(),
            held.archive_id,
        ))
    }) {
        return Err(unreadable(Shown::said(
            "it names one archive of one service for one host and producer twice",
        )));
    }
    let mut per_host: BTreeMap<EndpointKey, usize> = BTreeMap::new();
    for held in &file.checkpoints {
        *per_host.entry(held.host_endpoint_id).or_default() += 1;
    }
    if per_host.values().any(|count| *count > MAX_PER_HOST) {
        return Err(unreadable(crate::shown!(
            "it holds more than {} checkpoints of one host",
            MAX_PER_HOST
        )));
    }
    let mut pairings = BTreeSet::new();
    if !file
        .told
        .iter()
        .all(|told| pairings.insert((told.host_device_id, told.host_endpoint_id, told.device_id)))
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
    /// The answer is not one this release reads: an answer of generation 0 or a box longer than
    /// any honest host makes among them.
    Malformed,
    /// The host's box does not show that the host made this answer for this ask: it does not open
    /// under the key the pairing declares for the host and the key this device drew for the ask, or
    /// it holds another challenge, another endpoint or another answer than the ones this device
    /// expects. No random value could be drawn for the ask is the same cause.
    NotProven,
    /// The connection failed or ended.
    Lost,
    /// The host did not answer in time.
    TimedOut,
}

/// Asks the host `session` is connected to for its checkpoint, once, and takes the answer only when
/// the host's box proves it.
///
/// Each ask carries a fresh challenge and a fresh key whose secret half stays in this function. The
/// host answers with a box from its own stored-envelope key to that key, and the answer counts only
/// when the box opens under the key `host` declares and holds exactly the challenge, the endpoint
/// of `host` and the checkpoint that came with it. `host` is the record the session was made from:
/// the session dials the endpoint that record names and authenticates it, and a session has no
/// accessor that says which endpoint it reached. A host that relays the ask to another host gets
/// that other host's box, which names that other host's endpoint, and the comparison refuses it.
///
/// The read does not signal the session's standing: a host of an earlier release refuses the
/// method as one it does not serve at each ask, and that is no sign the host withdrew the
/// connection. The caller bounds the wait, and a read cut at its bound can leave the session's
/// control stream marked, so the caller gives it a session that nothing else uses.
///
/// # Errors
///
/// Returns why the host gave no answer this release reads.
pub async fn read_checkpoint(session: &Session, host: &PairedHost) -> Result<Answer, ReadCause> {
    let challenge = kr_transport::random::fresh_nonce().map_err(|_| ReadCause::NotProven)?;
    let reply = StoredEnvelopeKeyPair::generate().map_err(|_| ReadCause::NotProven)?;
    let ask = BackupCheckpointParams {
        challenge,
        reply_key: *reply.public(),
    };
    let result: BackupCheckpointResult = session
        .read_unsignalled(Method::BackupCheckpoint, &ask)
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
    if !proves(&reply, challenge, host, &result) {
        return Err(ReadCause::NotProven);
    }
    Ok(result
        .checkpoint
        .as_ref()
        .map_or(Answer::NothingPublished, |held| {
            Answer::Checkpoint(held.clone())
        }))
}

/// Whether the box of `result` shows that `host` made this answer for the ask that carried
/// `challenge` and the public half of `reply`.
///
/// The box must open under the key `host` declares and `reply`'s secret, and its plaintext must be
/// exactly the bytes this device writes from its own values: the challenge it drew, the endpoint
/// `host` names and the checkpoint beside the box. One comparison covers the three.
fn proves(
    reply: &StoredEnvelopeKeyPair,
    challenge: Nonce256,
    host: &PairedHost,
    result: &BackupCheckpointResult,
) -> bool {
    let Ok(opened) = open_stored_envelope(
        reply,
        &host.host_keys.stored_envelope,
        &result.proof.nonce,
        result.proof.ciphertext.as_slice(),
    ) else {
        return false;
    };
    let Ok(expected) = SigningTranscript::from_object(
        HOST_CHECKPOINT_PROOF_DOMAIN,
        &HostCheckpointProof {
            challenge,
            host_endpoint_id: host.host_endpoint_id,
            checkpoint: result.checkpoint.clone(),
        },
    ) else {
        return false;
    };
    opened.expose() == expected.as_bytes()
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

    /// An entry of a host that no record names: its endpoint and producer are fixed bytes.
    fn entry(archive: u8, generation: u64) -> PairedCheckpoint {
        PairedCheckpoint {
            host_endpoint_id: EndpointKey::from_bytes([0xE0; 32]),
            producer: KeyId::from_bytes([0xE1; 32]),
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
            host_endpoint_id: host.host_endpoint_id,
            device_id: host.device_id,
            answer,
            at_ms: 1_764_000_000_000,
        }
    }

    const ORIGIN: &str = "https://reach.kala.to";

    /// An entry that `host` gave: its endpoint and the producer its record declares.
    fn entry_of(host: &PairedHost, archive: u8, generation: u64) -> PairedCheckpoint {
        PairedCheckpoint {
            host_endpoint_id: host.host_endpoint_id,
            producer: producer_of(host),
            ..entry(archive, generation)
        }
    }

    /// `record` at another endpoint: the same declared identities and keys.
    fn at_another_endpoint(record: &PairedHost) -> PairedHost {
        PairedHost {
            host_endpoint_id: DeviceKeys::generate()
                .expect("keys")
                .public_keys()
                .transport,
            ..record.clone()
        }
    }

    /// `record` declaring another stored-envelope key, at the same endpoint.
    fn under_another_producer(record: &PairedHost) -> PairedHost {
        let mut other = record.clone();
        other.host_keys.stored_envelope = DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .stored_envelope;
        other
    }

    /// `value` as 32 bytes: `tag` and then the number, so that no two numbers share bytes.
    fn counted(value: usize, tag: u8) -> [u8; 32] {
        let mut bytes = [tag; 32];
        bytes[24..].copy_from_slice(&u64::try_from(value).expect("a count").to_be_bytes());
        bytes
    }

    /// `count` entries spread over endpoints, sixteen to each, so that the bound of a host is never
    /// reached before the file's own.
    fn spread(count: usize) -> Vec<PairedCheckpoint> {
        (0..count)
            .map(|position| PairedCheckpoint {
                host_endpoint_id: EndpointKey::from_bytes(counted(position / MAX_PER_HOST, 0x10)),
                producer: KeyId::from_bytes(counted(position / MAX_PER_HOST, 0x20)),
                archive_id: ArchiveId::new(Uuid::from_bytes(
                    u128::try_from(position + 1).expect("a count").to_be_bytes(),
                )),
                ..entry(1, 1)
            })
            .collect()
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
        let Held::Read { entries, owed, .. } = rig.checkpoints.held_checkpoints() else {
            panic!("an absent file reads as the empty set");
        };
        assert!(entries.is_empty());
        assert_eq!(owed, 0, "no host is paired");

        rig.hosts.record(owner(1)).expect("recorded");
        rig.hosts
            .record(host(7, &[ActionRight::SessionView]))
            .expect("recorded");
        let Held::Read { entries, owed, .. } = rig.checkpoints.held_checkpoints() else {
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
        let Held::Read { entries, owed, .. } = rig.checkpoints.held_checkpoints() else {
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
        let too_many = spread(MAX_CHECKPOINTS + 1);
        let cases: Vec<(&str, Vec<u8>, SnapshotCause)> = vec![
            ("a zero-byte file", Vec::new(), SnapshotCause::Unreadable),
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

    /// One object as JSON text: each member in turn, with its value as JSON text.
    fn object(members: &[(String, String)]) -> String {
        let written: Vec<String> = members
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect();
        format!("{{{}}}", written.join(","))
    }

    /// The members of an object as (name, JSON text of the value).
    fn members_of<T: Serialize>(value: &T) -> Vec<(String, String)> {
        let value = serde_json::to_value(value).expect("a value");
        value
            .as_object()
            .expect("an object")
            .iter()
            .map(|(name, member)| (name.clone(), member.to_string()))
            .collect()
    }

    /// A file of one checkpoint entry and one `told` entry, as raw bytes, with `root` written after
    /// the file's own members.
    fn file_bytes(
        entry: &[(String, String)],
        told: &[(String, String)],
        root: Option<(&str, &str)>,
    ) -> Vec<u8> {
        let mut members = vec![
            ("version".to_owned(), "1".to_owned()),
            ("checkpoints".to_owned(), format!("[{}]", object(entry))),
            ("told".to_owned(), format!("[{}]", object(told))),
        ];
        if let Some((name, value)) = root {
            members.push((name.to_owned(), value.to_owned()));
        }
        object(&members).into_bytes()
    }

    /// What each read and a settle make of a file's bytes, and the bytes the file holds after.
    struct Tried {
        held: Option<SnapshotCause>,
        acquisition: Result<Acquisition, SnapshotCause>,
        settle: Result<Settled, Unsettled>,
        after: Vec<u8>,
    }

    /// Writes `bytes` as the file, reads it as a restore and as the watcher do, and settles an
    /// answer against it.
    fn tried(rig: &Rig, record: &PairedHost, bytes: &[u8]) -> Tried {
        kr_ipc::paths::write_owner_only_file(&rig.path(CHECKPOINTS_FILE), bytes).expect("written");
        Tried {
            held: cause(&rig.checkpoints.held_checkpoints()),
            acquisition: rig.checkpoints.acquisition(record),
            settle: rig.checkpoints.settle_checkpoint(record, &given(1, 9), NOW),
            after: std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
        }
    }

    /// Raw files that each hold one member of the root twice, with the name of the member. The
    /// second `version` is the same number: the repeat alone is refused.
    fn root_arms(record: &PairedHost) -> Vec<(String, Vec<u8>)> {
        let entry = members_of(&entry(1, 7));
        let told = members_of(&told(record, Intended::Checkpoint));
        [("version", "1"), ("checkpoints", "[]"), ("told", "[]")]
            .into_iter()
            .map(|(name, again)| {
                (
                    format!("the root's {name}"),
                    file_bytes(&entry, &told, Some((name, again))),
                )
            })
            .collect()
    }

    /// Raw files that each hold one member of an entry twice: every member of a checkpoint entry
    /// and of a `told` entry in turn, with its name. The second `service_origin` is the same origin.
    fn entry_arms(record: &PairedHost) -> Vec<(String, Vec<u8>)> {
        let entry = members_of(&entry(1, 7));
        let told = members_of(&told(record, Intended::Checkpoint));
        let other_entry = members_of(&entry_of_another());
        let other_told = members_of(&told_of_another());
        let mut arms = Vec::new();
        for (position, (name, _)) in entry.iter().enumerate() {
            let mut repeated = entry.clone();
            repeated.push((name.clone(), other_entry[position].1.clone()));
            arms.push((
                format!("a checkpoint's {name}"),
                file_bytes(&repeated, &told, None),
            ));
        }
        for (position, (name, _)) in told.iter().enumerate() {
            let mut repeated = told.clone();
            repeated.push((name.clone(), other_told[position].1.clone()));
            arms.push((
                format!("a told entry's {name}"),
                file_bytes(&entry, &repeated, None),
            ));
        }
        arms
    }

    /// The file that the arms above are made from, with no member repeated.
    fn control_bytes(record: &PairedHost) -> Vec<u8> {
        file_bytes(
            &members_of(&entry(1, 7)),
            &members_of(&told(record, Intended::Checkpoint)),
            None,
        )
    }

    /// A member that the file holds twice at its root makes it unreadable, whichever of the two a
    /// reader would take, and a settle leaves its bytes as they were.
    #[test]
    fn a_member_repeated_at_the_root_makes_the_file_unreadable_and_a_settle_leaves_it() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");

        let control = tried(&rig, &record, &control_bytes(&record));
        assert_eq!(
            control.acquisition,
            Ok(Acquisition::Told),
            "the file with no repeat reads"
        );
        for (name, bytes) in root_arms(&record) {
            let tried = tried(&rig, &record, &bytes);
            assert_eq!(tried.held, Some(SnapshotCause::Unreadable), "{name}");
            assert_eq!(tried.acquisition, Err(SnapshotCause::Unreadable), "{name}");
            assert_eq!(
                tried.settle,
                Err(Unsettled::Unreadable(SnapshotCause::Unreadable)),
                "{name}"
            );
            assert_eq!(
                tried.after, bytes,
                "{name}: a settle leaves the file as it was"
            );
        }
    }

    /// A member that an entry holds twice, in a checkpoint or in a `told` entry, makes the file
    /// unreadable, whichever of the two a reader would take, and a settle leaves its bytes as they
    /// were.
    #[test]
    fn a_member_repeated_in_an_entry_makes_the_file_unreadable_and_a_settle_leaves_it() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");

        for (name, bytes) in entry_arms(&record) {
            let tried = tried(&rig, &record, &bytes);
            assert_eq!(tried.held, Some(SnapshotCause::Unreadable), "{name}");
            assert_eq!(tried.acquisition, Err(SnapshotCause::Unreadable), "{name}");
            assert_eq!(
                tried.settle,
                Err(Unsettled::Unreadable(SnapshotCause::Unreadable)),
                "{name}"
            );
            assert_eq!(
                tried.after, bytes,
                "{name}: a settle leaves the file as it was"
            );
        }
    }

    /// An entry that differs from the one of the file in every member but the service, so that a
    /// repeat of any other member names another value.
    fn entry_of_another() -> PairedCheckpoint {
        PairedCheckpoint {
            host_endpoint_id: EndpointKey::from_bytes([0xE2; 32]),
            producer: KeyId::from_bytes([0xE3; 32]),
            service_origin: GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
            archive_id: ArchiveId::new(Uuid::from_bytes([2; 16])),
            backup_generation: BackupGeneration::new(1),
            encrypted_manifest_hash: Digest256::from_bytes([2; 32]),
            taken_at_ms: 5,
        }
    }

    /// A `told` entry that differs from the one of the file in every member.
    fn told_of_another() -> Told {
        Told {
            host_device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
            host_endpoint_id: DeviceKeys::generate()
                .expect("keys")
                .public_keys()
                .transport,
            device_id: DeviceId::new(Uuid::from_bytes([10; 16])),
            answer: Intended::NothingPublished,
            at_ms: 5,
        }
    }

    /// A file of exactly the largest size is read, and one byte more is unreadable and stays as it
    /// was after a settle.
    #[test]
    fn a_file_over_four_mebibytes_is_unreadable_and_one_of_that_size_is_read() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let mut bytes = serde_json::to_vec(&CheckpointsFile {
            version: FORMAT_VERSION,
            checkpoints: vec![entry(1, 7)],
            told: vec![told(&record, Intended::Checkpoint)],
        })
        .expect("bytes");
        bytes.resize(4 * 1024 * 1024, b' ');
        let at_the_size = tried(&rig, &record, &bytes);
        assert_eq!(
            at_the_size.acquisition,
            Ok(Acquisition::Told),
            "a file of 4 MiB is read"
        );
        bytes.push(b' ');
        let over = tried(&rig, &record, &bytes);
        assert_eq!(over.held, Some(SnapshotCause::Unreadable));
        assert_eq!(
            over.acquisition,
            Err(SnapshotCause::Unreadable),
            "a file one byte over 4 MiB"
        );
        assert_eq!(
            over.settle,
            Err(Unsettled::Unreadable(SnapshotCause::Unreadable))
        );
        assert_eq!(over.after, bytes, "a settle leaves the file as it was");
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
        let Held::Unreadable { file, why, .. } = &held else {
            panic!("a lock that is held is not empty: {held:?}")
        };
        assert!(file.to_string().ends_with(LOCK_FILE), "{file}");
        assert_eq!(
            why.to_string(),
            "something else on this device is using it",
            "a held lock proves use, not a write"
        );
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
            receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("the answer came within the 10 s bound")
        };
        assert_eq!(refused_within(&rig), Some(SnapshotCause::Lock), "a link");
        std::fs::remove_file(rig.path(LOCK_FILE)).expect("removed");

        let made = std::process::Command::new("mkfifo")
            .arg(rig.path(LOCK_FILE))
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        assert_eq!(refused_within(&rig), Some(SnapshotCause::Lock), "a FIFO");
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
                        host_endpoint_id: told.host_endpoint_id,
                        device_id: told.device_id,
                    },
                    told.answer,
                    told.at_ms,
                )
            })
            .collect()
    }

    fn settled(outcome: Outcome) -> Result<Settled, Unsettled> {
        Ok(Settled {
            outcome,
            confirmed: true,
        })
    }

    /// A settle whose write landed and could not be confirmed.
    fn unconfirmed(outcome: Outcome) -> Result<Settled, Unsettled> {
        Ok(Settled {
            outcome,
            confirmed: false,
        })
    }

    /// A record of the same declared identities at another endpoint is another pairing: the owner
    /// that stands at the first endpoint is not the one a record at the second names.
    #[test]
    fn a_record_at_another_endpoint_is_not_the_pairing_that_was_told() {
        let rig = Rig::new();
        let first = owner(1);
        rig.hosts.record(first.clone()).expect("recorded");
        rig.checkpoints
            .settle_checkpoint(&first, &given(1, 7), NOW)
            .expect("settled");
        let mut second = first.clone();
        second.host_endpoint_id = DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .transport;
        assert_eq!(rig.checkpoints.acquisition(&first), Ok(Acquisition::Told));
        assert_eq!(
            rig.checkpoints.acquisition(&second),
            Ok(Acquisition::NotAnOwner)
        );
    }

    /// A pairing that another one at a second endpoint replaced is not told what the first one
    /// answered: the `told` entry belongs to the endpoint it was written for.
    #[test]
    fn a_pairing_at_another_endpoint_is_not_told_what_the_replaced_one_answered() {
        let rig = Rig::new();
        let first = owner(1);
        rig.hosts.record(first.clone()).expect("recorded");
        rig.checkpoints
            .settle_checkpoint(&first, &given(1, 7), NOW)
            .expect("settled");
        let mut second = first.clone();
        second.host_endpoint_id = DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .transport;
        rig.hosts.record(second.clone()).expect("replaced");
        assert_eq!(rig.checkpoints.acquisition(&second), Ok(Acquisition::Owed));
    }

    /// A file that names one declared pairing at two endpoints names two pairings, and is read.
    #[test]
    fn a_file_that_names_one_declared_pairing_at_two_endpoints_is_read() {
        let rig = Rig::new();
        let first = owner(1);
        let mut second = first.clone();
        second.host_endpoint_id = DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .transport;
        rig.write_file(
            Vec::new(),
            vec![
                told(&first, Intended::Checkpoint),
                told(&second, Intended::Checkpoint),
            ],
        );
        assert_eq!(cause(&rig.checkpoints.held_checkpoints()), None);
    }

    /// A file that names one pairing twice, by all three parts of its identity, is unreadable.
    #[test]
    fn a_file_that_names_one_pairing_twice_is_unreadable() {
        let rig = Rig::new();
        let first = owner(1);
        rig.write_file(
            Vec::new(),
            vec![
                told(&first, Intended::Checkpoint),
                told(&first, Intended::NothingPublished),
            ],
        );
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable)
        );
    }

    /// The largest `told` entry takes the bytes that the size comment of the settle counts for it.
    #[test]
    fn the_largest_told_entry_takes_the_bytes_the_size_bound_counts() {
        let record = owner(1);
        let entry = Told {
            at_ms: u64::MAX,
            ..told(&record, Intended::NothingPublished)
        };
        assert_eq!(serde_json::to_vec(&entry).expect("serialises").len(), 231);
    }

    /// An answer for the pairing at another endpoint is told to none of the pairings that stand:
    /// it is superseded and writes no `told` entry.
    #[test]
    fn an_answer_of_the_pairing_at_another_endpoint_is_told_to_none() {
        let rig = Rig::new();
        let first = owner(1);
        rig.hosts.record(first.clone()).expect("recorded");
        let mut second = first.clone();
        second.host_endpoint_id = DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .transport;
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&second, &given(1, 7), NOW),
            Err(Unsettled::Superseded)
        );
        assert_eq!(answers(&rig), Vec::new());
    }

    /// Each outcome of a settle is its own, a held checkpoint never goes down, and the checkpoints
    /// are read apart from the answers.
    #[test]
    fn each_outcome_of_a_settle_is_its_own_and_no_held_checkpoint_goes_down() {
        let rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(&record, &answer, NOW);

        assert_eq!(settle(given(1, 7)), settled(Outcome::New));
        assert_eq!(entries(&rig), vec![(1, 7)]);
        assert_eq!(
            answers(&rig),
            vec![(id(&record), Intended::Checkpoint, NOW)]
        );
        assert_eq!(settle(given(1, 7)), settled(Outcome::Same));
        assert_eq!(settle(given(1, 9)), settled(Outcome::Raised));
        assert_eq!(entries(&rig), vec![(1, 9)]);
        assert_eq!(settle(given(1, 8)), settled(Outcome::Lower));
        assert_eq!(entries(&rig), vec![(1, 9)], "a lower answer lowers nothing");
        let other_manifest = Answer::Checkpoint(host_checkpoint("https://reach.kala.to", 1, 9, 77));
        assert_eq!(settle(other_manifest), settled(Outcome::Disagrees));
        assert_eq!(entries(&rig), vec![(1, 9)], "the held entry stands");
        assert_eq!(
            rig.checkpoints.acquisition(&record),
            Ok(Acquisition::Told),
            "a host that disagreed is settled"
        );
        assert_eq!(
            settle(Answer::NothingPublished),
            settled(Outcome::NothingPublished)
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
            rig.checkpoints.settle_checkpoint(&old, &given(1, 4), NOW),
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
                .settle_checkpoint(&old, &Answer::NothingPublished, NOW),
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
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(&record, &answer, NOW);
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
            .settle_checkpoint(&record, &given(1, 7), NOW)
            .expect("settled");
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");

        rig.checkpoints = rig.checkpoints.clone().with_writer(fails_before);
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&record, &given(1, 9), NOW),
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
                .settle_checkpoint(&record, &given(1, 9), NOW),
            unconfirmed(Outcome::Raised)
        );
        assert_eq!(entries(&rig), vec![(1, 9)], "the new file stands");
    }

    /// A write that lands and is not confirmed leaves the answer its own standing: a lower answer
    /// and a disagreeing answer are told as such, and the held checkpoint stands.
    #[test]
    fn an_unconfirmed_write_keeps_the_standing_of_a_lower_and_a_disagreeing_answer() {
        let mut rig = Rig::new();
        let record = owner(1);
        rig.hosts.record(record.clone()).expect("recorded");
        rig.checkpoints
            .settle_checkpoint(&record, &given(1, 9), NOW)
            .expect("settled");
        // An answer of nothing published changes the pairing's entry, so that the answer after it is
        // written again. The first is settled before the writer changes: the lower answer is then
        // the first one that a write that fails after the replacement meets.
        rig.checkpoints
            .settle_checkpoint(&record, &Answer::NothingPublished, NOW)
            .expect("settled");
        rig.checkpoints = rig.checkpoints.clone().with_writer(fails_after);
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(&record, &answer, NOW);
        let other_manifest = Answer::Checkpoint(host_checkpoint("https://reach.kala.to", 1, 9, 77));

        assert_eq!(settle(given(1, 8)), unconfirmed(Outcome::Lower));
        assert_eq!(
            settle(Answer::NothingPublished),
            unconfirmed(Outcome::NothingPublished)
        );
        assert_eq!(settle(other_manifest), unconfirmed(Outcome::Disagrees));
        assert_eq!(entries(&rig), vec![(1, 9)], "the held entry stands");
    }

    /// The entries a rig holds, as the file keeps them.
    fn held(rig: &Rig) -> Vec<PairedCheckpoint> {
        let Held::Read { entries, .. } = rig.checkpoints.held_checkpoints() else {
            panic!("a readable file");
        };
        entries
    }

    /// The generation of the entry that `host` gave for `archive` at `origin`, when there is one.
    fn generation_at(rig: &Rig, host: &PairedHost, origin: &str, archive: u8) -> Option<u64> {
        held(rig)
            .iter()
            .find(|held| {
                held.host_endpoint_id == host.host_endpoint_id
                    && held.producer == producer_of(host)
                    && held.service_origin.as_str() == origin
                    && held.archive_id == ArchiveId::new(Uuid::from_bytes([archive; 16]))
            })
            .map(|held| held.backup_generation.get())
    }

    /// The member names of an entry's host and producer.
    const NEW_MEMBERS: [&str; 2] = ["host_endpoint_id", "producer"];

    /// An entry names its host's endpoint and its producer. A file with both reads back as written,
    /// a file without either is unreadable, and the two members are written as 43 characters each.
    #[test]
    fn an_entry_names_its_host_and_producer_and_a_file_without_either_is_unreadable() {
        let rig = Rig::new();
        let host = owner(1);
        rig.hosts.record(host.clone()).expect("recorded");
        let written = vec![entry_of(&host, 1, 7)];
        rig.write_file(written.clone(), Vec::new());
        assert_eq!(held(&rig), written, "an entry reads back with both members");

        let value = serde_json::to_value(&written[0]).expect("a value");
        for member in NEW_MEMBERS {
            assert_eq!(
                value[member].as_str().map(str::len),
                Some(43),
                "{member} is 43 characters of base64url"
            );
        }
        for member in NEW_MEMBERS {
            let mut file = serde_json::to_value(CheckpointsFile {
                version: FORMAT_VERSION,
                checkpoints: written.clone(),
                told: Vec::new(),
            })
            .expect("a value");
            file["checkpoints"][0]
                .as_object_mut()
                .expect("an entry")
                .remove(member);
            rig.write(&file);
            assert_eq!(
                cause(&rig.checkpoints.held_checkpoints()),
                Some(SnapshotCause::Unreadable),
                "an entry without {member} is unreadable"
            );
        }
        rig.write_file(Vec::new(), Vec::new());
        assert!(held(&rig).is_empty(), "empty collections read (control)");
    }

    /// An entry is named once by its four-part key: two entries that differ in any one part read,
    /// two that repeat the key are refused, and one endpoint holds at most sixteen.
    #[test]
    fn a_file_names_each_entry_once_by_its_four_part_key_and_an_endpoint_at_most_sixteen_times() {
        let rig = Rig::new();
        let host = owner(1);
        let base = entry_of(&host, 1, 7);
        let other_endpoint = PairedCheckpoint {
            host_endpoint_id: EndpointKey::from_bytes([0xA1; 32]),
            ..base.clone()
        };
        let other_producer = PairedCheckpoint {
            producer: KeyId::from_bytes([0xA2; 32]),
            ..base.clone()
        };
        let other_service = PairedCheckpoint {
            service_origin: GatewayOrigin::new("https://other.example").expect("an origin"),
            ..base.clone()
        };
        let other_archive = PairedCheckpoint {
            archive_id: ArchiveId::new(Uuid::from_bytes([2; 16])),
            ..base.clone()
        };
        let both_others = PairedCheckpoint {
            host_endpoint_id: EndpointKey::from_bytes([0xA3; 32]),
            producer: KeyId::from_bytes([0xA4; 32]),
            ..base.clone()
        };
        for (name, other) in [
            ("endpoint", other_endpoint),
            ("producer", other_producer),
            ("service", other_service),
            ("archive", other_archive),
            ("endpoint and producer together", both_others),
        ] {
            rig.write_file(vec![base.clone(), other.clone()], Vec::new());
            assert_eq!(
                held(&rig),
                vec![base.clone(), other],
                "two entries that differ only in the {name} read"
            );
        }
        // The key repeated, with another generation, manifest and time: refused, never merged.
        let repeated = PairedCheckpoint {
            backup_generation: BackupGeneration::new(9),
            encrypted_manifest_hash: Digest256::from_bytes([9; 32]),
            taken_at_ms: 5,
            ..base.clone()
        };
        rig.write_file(vec![base.clone(), repeated], Vec::new());
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable),
            "a repeated key"
        );

        let of_one_endpoint = |count: u8| -> Vec<PairedCheckpoint> {
            (1..=count)
                .map(|archive| entry_of(&host, archive, 1))
                .collect()
        };
        rig.write_file(of_one_endpoint(16), Vec::new());
        assert_eq!(held(&rig).len(), 16, "sixteen entries of one endpoint read");
        rig.write_file(of_one_endpoint(17), Vec::new());
        assert_eq!(
            cause(&rig.checkpoints.held_checkpoints()),
            Some(SnapshotCause::Unreadable),
            "seventeen entries of one endpoint"
        );
        rig.write_file(spread(MAX_CHECKPOINTS), Vec::new());
        assert_eq!(
            held(&rig).len(),
            MAX_CHECKPOINTS,
            "1,024 entries spread over endpoints read"
        );
    }

    /// An answer raises only the entry that names its own endpoint, producer, service and archive:
    /// each part of the key is varied alone, and the entry of the first host stays where it was.
    #[test]
    fn an_answer_raises_only_the_entry_that_names_its_endpoint_producer_service_and_archive() {
        let first = owner(1);
        let variations = [
            ("endpoint", at_another_endpoint(&first), ORIGIN, 1_u8),
            ("producer", under_another_producer(&first), ORIGIN, 1),
            ("service", first.clone(), "https://other.example", 1),
            ("archive", first.clone(), ORIGIN, 2),
        ];
        for (part, other, origin, archive) in variations {
            let rig = Rig::new();
            rig.hosts.record(first.clone()).expect("recorded");
            rig.checkpoints
                .settle_checkpoint(&first, &given(1, 5), NOW)
                .expect("settled");
            // An answer of the other endpoint is a late one: no record of this device names it as
            // the host's current pairing. It still raises the entry that names its own key.
            let _ = rig.checkpoints.settle_checkpoint(
                &other,
                &Answer::Checkpoint(host_checkpoint(origin, archive, 9, archive)),
                NOW,
            );
            assert_eq!(
                generation_at(&rig, &first, ORIGIN, 1),
                Some(5),
                "{part}: the answer of the other key leaves the first entry alone"
            );
            assert_eq!(
                generation_at(&rig, &other, origin, archive),
                Some(9),
                "{part}: and has its own entry"
            );
            assert_eq!(held(&rig).len(), 2, "{part}");
        }
    }

    /// One endpoint under a second pairing raises its one entry; one endpoint with two producers
    /// holds two.
    #[test]
    fn one_endpoint_under_a_second_pairing_raises_its_one_entry_and_two_producers_hold_two() {
        let rig = Rig::new();
        let first = owner(1);
        rig.hosts.record(first.clone()).expect("recorded");
        rig.checkpoints
            .settle_checkpoint(&first, &given(1, 5), NOW)
            .expect("settled");
        let mut second = first.clone();
        second.device_id = DeviceId::new(Uuid::from_bytes([50; 16]));
        rig.hosts.record(second.clone()).expect("a second pairing");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&second, &given(1, 9), NOW),
            settled(Outcome::Raised),
            "the one entry of the endpoint rises"
        );
        assert_eq!(held(&rig).len(), 1);
        assert_eq!(generation_at(&rig, &second, ORIGIN, 1), Some(9));

        let other = under_another_producer(&second);
        assert_eq!(
            rig.checkpoints.settle_checkpoint(&other, &given(1, 3), NOW),
            settled(Outcome::New),
            "another producer at the same endpoint is another entry, not a lower answer"
        );
        assert_eq!(held(&rig).len(), 2);
        assert_eq!(generation_at(&rig, &second, ORIGIN, 1), Some(9));
        assert_eq!(generation_at(&rig, &other, ORIGIN, 1), Some(3));
    }

    /// A lower, an equal and another-manifest answer change no entry, and every entry is still
    /// returned after the host is forgotten and after another pairing replaces it.
    #[test]
    fn a_lower_an_equal_and_another_manifest_change_no_entry_and_every_entry_outlives_a_forget() {
        let rig = Rig::new();
        let (first, second) = (owner(1), owner(4));
        rig.hosts.record(first.clone()).expect("recorded");
        rig.hosts.record(second.clone()).expect("recorded");
        let settle = |host: &PairedHost, answer: Answer| {
            rig.checkpoints.settle_checkpoint(host, &answer, NOW)
        };
        assert_eq!(settle(&first, given(1, 7)), settled(Outcome::New));
        assert_eq!(settle(&second, given(1, 3)), settled(Outcome::New));
        let before = held(&rig);
        assert_eq!(before.len(), 2);

        assert_eq!(settle(&first, given(1, 6)), settled(Outcome::Lower));
        assert_eq!(settle(&first, given(1, 7)), settled(Outcome::Same));
        let other_manifest = Answer::Checkpoint(host_checkpoint(ORIGIN, 1, 7, 77));
        assert_eq!(settle(&first, other_manifest), settled(Outcome::Disagrees));
        assert_eq!(settle(&second, given(1, 2)), settled(Outcome::Lower));
        assert_eq!(held(&rig), before, "no answer changed an entry");

        rig.hosts.forget(first.host_device_id).expect("forgotten");
        let Held::Read {
            entries, listed, ..
        } = rig.checkpoints.held_checkpoints()
        else {
            panic!("a readable file");
        };
        assert_eq!(
            entries, before,
            "a forgotten host's entry is still returned"
        );
        assert_eq!(
            listed,
            vec![(second.host_endpoint_id, second.name.clone())],
            "the hosts that are listed come from the same read"
        );
        assert_eq!(
            settle(&second, given(1, 1)),
            settled(Outcome::Lower),
            "a settle after the forget"
        );
        assert_eq!(held(&rig), before, "and it removed no entry");

        let mut replaced = at_another_endpoint(&second);
        replaced.device_id = DeviceId::new(Uuid::from_bytes([60; 16]));
        rig.hosts.record(replaced.clone()).expect("a new pairing");
        let Held::Read {
            entries, listed, ..
        } = rig.checkpoints.held_checkpoints()
        else {
            panic!("a readable file");
        };
        assert_eq!(
            entries, before,
            "a replaced pairing's entry is still returned"
        );
        assert_eq!(listed, vec![(replaced.host_endpoint_id, replaced.name)]);
    }

    /// A record that is no owner takes nothing, whether or not the lock is held; a pairing that is
    /// no longer the current one takes its entry and no answer; the current owner takes both; and an
    /// owner that a viewer pairing replaced keeps its earlier entry.
    #[test]
    fn a_record_that_is_no_owner_takes_nothing_and_only_the_current_owner_is_told() {
        let rig = Rig::new();
        let viewer = host(10, &[ActionRight::SessionView]);
        rig.hosts.record(viewer.clone()).expect("recorded");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&viewer, &given(1, 7), NOW),
            Err(Unsettled::NotAnOwner),
            "a viewer record is told nothing"
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&viewer, &Answer::NothingPublished, NOW),
            Err(Unsettled::NotAnOwner)
        );
        assert!(
            !rig.path(CHECKPOINTS_FILE).exists(),
            "a viewer record writes nothing"
        );
        let holder = kr_ipc::paths::open_lock_file(&rig.path(LOCK_FILE)).expect("a lock file");
        kr_flush::lock::exclusive(&holder).expect("held");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&viewer, &given(1, 7), NOW),
            Err(Unsettled::NotAnOwner),
            "the answer is turned away before the lock, which is held"
        );
        kr_flush::lock::release(&holder).expect("released");

        // An owner that is not the host's current pairing: the entry is taken, no answer is told.
        let old = owner(20);
        let mut current = old.clone();
        current.device_id = DeviceId::new(Uuid::from_bytes([70; 16]));
        rig.hosts.record(current.clone()).expect("recorded");
        assert_eq!(
            rig.checkpoints.settle_checkpoint(&old, &given(1, 4), NOW),
            Err(Unsettled::Superseded)
        );
        assert_eq!(
            entries(&rig),
            vec![(1, 4)],
            "the late answer raised its entry"
        );
        assert!(answers(&rig).is_empty(), "and told no pairing");

        // The current owner gets both: the control.
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&current, &given(1, 5), NOW),
            settled(Outcome::Raised)
        );
        assert_eq!(
            answers(&rig),
            vec![(id(&current), Intended::Checkpoint, NOW)]
        );

        // A viewer pairing of the same host replaces the owner: its earlier entry stays.
        let mut viewing = current.clone();
        viewing.device_id = DeviceId::new(Uuid::from_bytes([71; 16]));
        viewing.proposed_grant = grant(&[ActionRight::SessionView]);
        rig.hosts.record(viewing.clone()).expect("replaced");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&viewing, &given(1, 9), NOW),
            Err(Unsettled::NotAnOwner)
        );
        assert_eq!(
            entries(&rig),
            vec![(1, 5)],
            "the owner's earlier entry stays"
        );
        assert_eq!(
            rig.checkpoints.acquisition(&viewing),
            Ok(Acquisition::NotAnOwner)
        );
    }

    /// Two records of one declared host at two endpoints are two pairings: each is owed and told on
    /// its own, and a name goes to the one whose identity names it.
    #[test]
    fn two_records_of_one_declared_host_at_two_endpoints_are_two_pairings() {
        let rig = Rig::new();
        let (first, second) = (owner(1), at_another_endpoint(&owner(1)));
        assert_eq!(first.host_device_id, second.host_device_id);
        assert_eq!(first.device_id, second.device_id);
        // `record` replaces a host by its declared identity, so the file is written as it stands.
        kr_ipc::paths::write_owner_only_file(
            &rig.path("hosts.json"),
            &serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "hosts": [first, second],
            }))
            .expect("bytes"),
        )
        .expect("a file of two records");
        assert_eq!(rig.checkpoints.acquisition(&first), Ok(Acquisition::Owed));
        assert_eq!(rig.checkpoints.acquisition(&second), Ok(Acquisition::Owed));

        assert_eq!(
            rig.checkpoints.settle_checkpoint(&first, &given(1, 7), NOW),
            settled(Outcome::New)
        );
        assert_eq!(rig.checkpoints.acquisition(&first), Ok(Acquisition::Told));
        assert_eq!(
            rig.checkpoints.acquisition(&second),
            Ok(Acquisition::Owed),
            "the other endpoint is still owed"
        );
        assert_eq!(answers(&rig), vec![(id(&first), Intended::Checkpoint, NOW)]);
        let Held::Read { owed, .. } = rig.checkpoints.held_checkpoints() else {
            panic!("a readable file");
        };
        assert_eq!(owed, 1);

        assert_eq!(
            rig.hosts
                .name_pairing(id(&second), Some("kitchen".to_owned()))
                .expect("named"),
            crate::pairing::paired::Naming::Named
        );
        let names: Vec<(EndpointKey, Option<String>)> = rig
            .hosts
            .list()
            .expect("hosts")
            .into_iter()
            .map(|record| (record.host_endpoint_id, record.name))
            .collect();
        assert_eq!(
            names,
            vec![
                (first.host_endpoint_id, None),
                (second.host_endpoint_id, Some("kitchen".to_owned()))
            ],
            "the name went to the record of the endpoint it names"
        );
    }

    /// The largest entry takes the bytes the settle's size comment counts for it, and the file
    /// those counts make stays inside the largest file this release reads.
    #[test]
    fn the_largest_entry_takes_the_bytes_the_size_bound_counts() {
        let host = owner(1);
        let authority = format!("{}.{}", "a".repeat(63), "b".repeat(56));
        let origin = GatewayOrigin::new(format!("https://{authority}")).expect("an origin");
        assert_eq!(
            origin.as_str().len(),
            kr_protocol::service::MAX_GATEWAY_ORIGIN_LEN
        );
        let largest = PairedCheckpoint {
            service_origin: origin,
            backup_generation: BackupGeneration::new(u64::MAX),
            taken_at_ms: u64::MAX,
            ..entry_of(&host, 1, 1)
        };
        assert_eq!(
            serde_json::to_vec(&largest).expect("serialises").len(),
            ENTRY_BYTES - 1,
            "the entry's text, less the comma that follows it in the list"
        );
        let told = Told {
            at_ms: u64::MAX,
            ..told(&host, Intended::NothingPublished)
        };
        assert_eq!(
            serde_json::to_vec(&told).expect("serialises").len(),
            TOLD_BYTES - 1
        );
        let most = u64::try_from(MAX_CHECKPOINTS).expect("a count")
            * u64::try_from(ENTRY_BYTES).expect("a size")
            + MOST_RECORDS * u64::try_from(TOLD_BYTES).expect("a size")
            + FILE_BYTES;
        assert_eq!(most, 3_355_720, "the figure of the comment");
        assert!(most <= MAX_FILE_BYTES);
    }

    /// The bytes the size comment of the settle counts for one entry, with the comma after it.
    const ENTRY_BYTES: usize = 474;
    /// The bytes it counts for one `told` entry, with the comma after it.
    const TOLD_BYTES: usize = 232;
    /// The most records of `hosts.json` that fit in the largest file this release reads.
    const MOST_RECORDS: u64 = 12_372;
    /// The bytes of the file's own members.
    const FILE_BYTES: u64 = 40;

    /// Whether two entries have the same key: endpoint, producer, service and archive.
    fn same_key(left: &PairedCheckpoint, right: &PairedCheckpoint) -> bool {
        left.host_endpoint_id == right.host_endpoint_id
            && left.producer == right.producer
            && left.service_origin == right.service_origin
            && left.archive_id == right.archive_id
    }

    /// A new key is refused at sixteen entries of one endpoint, whatever its producer, service or
    /// pairing; an entry held still rises there, another endpoint still settles, nothing is dropped,
    /// and an answer of generation 0 is never written.
    #[test]
    fn a_new_key_is_full_at_sixteen_entries_of_one_endpoint_and_nothing_is_dropped() {
        let rig = Rig::new();
        let first = owner(1);
        rig.hosts.record(first.clone()).expect("recorded");
        for archive in 1..=16 {
            assert_eq!(
                rig.checkpoints
                    .settle_checkpoint(&first, &given(archive, 1), NOW),
                settled(Outcome::New),
                "archive {archive}"
            );
        }
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");

        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&first, &given(17, 1), NOW),
            Err(Unsettled::Full),
            "the 17th archive of one endpoint"
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&under_another_producer(&first), &given(17, 1), NOW),
            Err(Unsettled::Full),
            "the same endpoint under another producer"
        );
        let elsewhere = Answer::Checkpoint(host_checkpoint("https://other.example", 1, 1, 1));
        assert_eq!(
            rig.checkpoints.settle_checkpoint(&first, &elsewhere, NOW),
            Err(Unsettled::Full),
            "the same endpoint at another service"
        );
        assert_eq!(
            rig.checkpoints.settle_checkpoint(&first, &given(1, 0), NOW),
            Err(Unsettled::Malformed),
            "generation 0 is never written"
        );
        let mut again = first.clone();
        again.device_id = DeviceId::new(Uuid::from_bytes([50; 16]));
        rig.hosts.record(again.clone()).expect("a second pairing");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&again, &given(17, 1), NOW),
            Err(Unsettled::Full),
            "the same endpoint under a second pairing"
        );
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            before,
            "nothing was written"
        );

        assert_eq!(
            rig.checkpoints.settle_checkpoint(&again, &given(1, 9), NOW),
            settled(Outcome::Raised),
            "an entry held still rises at sixteen"
        );
        assert_eq!(held(&rig).len(), 16, "nothing was dropped");
        let second = owner(4);
        rig.hosts.record(second.clone()).expect("recorded");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&second, &given(17, 1), NOW),
            settled(Outcome::New),
            "another endpoint still settles"
        );
        assert_eq!(held(&rig).len(), 17);
    }

    /// A new key is refused at the file's total bound, and the bound of a host cannot be what
    /// refuses it; an entry held still rises there; no entry is lowered or removed.
    #[test]
    fn a_new_key_is_full_at_the_total_bound_and_an_entry_held_still_rises_there() {
        let rig = Rig::new();
        let hosts: Vec<PairedHost> = (0..MAX_CHECKPOINTS / MAX_PER_HOST)
            .map(|position| owner(u8::try_from(1 + 3 * position).expect("a byte")))
            .collect();
        let full: Vec<PairedCheckpoint> = hosts
            .iter()
            .flat_map(|host| (1..=16_u8).map(move |archive| entry_of(host, archive, 1)))
            .collect();
        assert_eq!(full.len(), MAX_CHECKPOINTS);
        rig.write_file(full.clone(), Vec::new());
        assert_eq!(held(&rig).len(), MAX_CHECKPOINTS, "the file reads");
        let extra = owner(250);
        rig.hosts.record(extra.clone()).expect("recorded");
        rig.hosts.record(hosts[0].clone()).expect("recorded");
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");

        assert_eq!(
            rig.checkpoints.settle_checkpoint(&extra, &given(1, 1), NOW),
            Err(Unsettled::Full),
            "a host that holds none is refused at the total bound"
        );
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            before,
            "nothing was written"
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&hosts[0], &given(1, 9), NOW),
            settled(Outcome::Raised),
            "an entry held still rises at the total bound"
        );
        let after = held(&rig);
        assert_eq!(after.len(), MAX_CHECKPOINTS, "nothing was dropped");
        for was in &full {
            let now = after
                .iter()
                .find(|entry| same_key(entry, was))
                .expect("every entry is kept");
            assert!(
                now.backup_generation >= was.backup_generation,
                "none is lowered"
            );
        }
        assert_eq!(generation_at(&rig, &hosts[0], ORIGIN, 1), Some(9));
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
            .settle_checkpoint(&record, &Answer::NothingPublished, NOW)
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
                .settle_checkpoint(&record, &given(1, 3), NOW)
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
        let settle = |answer: Answer| rig.checkpoints.settle_checkpoint(&record, &answer, NOW);

        assert_eq!(settle(at("https://one.example", 3)), settled(Outcome::New));
        assert_eq!(
            settle(at("https://two.example", 5)),
            settled(Outcome::New),
            "another service is another entry"
        );
        assert_eq!(
            settle(at("https://one.example", 4)),
            settled(Outcome::Raised)
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
                .settle_checkpoint(&record, &given(1, 3), NOW),
            Err(Unsettled::Busy)
        );
        assert!(!rig.path(CHECKPOINTS_FILE).exists(), "nothing was written");
        kr_flush::lock::release(&holder).expect("released");
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&record, &given(1, 3), NOW),
            settled(Outcome::New)
        );
    }

    /// How long a test settles again after Busy. Each try already waited the lock's own bound, so a
    /// slow disk is waited for and a lock that is never let go is still found.
    const SETTLE_WITHIN: Duration = Duration::from_secs(120);

    /// Settles, and settles again after each Busy until [`SETTLE_WITHIN`] has passed. The store's
    /// answer at Busy is legal and writes nothing; a caller that wants the answer kept asks again.
    fn settled_within(
        checkpoints: &PairedCheckpoints,
        host: &PairedHost,
        answer: &Answer,
    ) -> Result<Settled, Unsettled> {
        let started = Instant::now();
        loop {
            match checkpoints.settle_checkpoint(host, answer, NOW) {
                Err(Unsettled::Busy) if started.elapsed() < SETTLE_WITHIN => {}
                result => return result,
            }
        }
    }

    /// Four owners that no record shares an identity or an endpoint with.
    fn four_owners(rig: &Rig) -> Vec<PairedHost> {
        let hosts: Vec<PairedHost> = [1_u8, 4, 7, 10].into_iter().map(owner).collect();
        for host in &hosts {
            rig.hosts.record(host.clone()).expect("recorded");
        }
        hosts
    }

    /// Handles of one directory, on two threads, never lose each other's entries or lower one. A
    /// settle that meets Busy is made again, so the checks are on what the file holds.
    #[test]
    fn two_handles_settling_beside_each_other_lose_no_entry_and_lower_none() {
        let rig = Rig::new();
        let hosts = four_owners(&rig);
        let spawn = |own: Vec<PairedHost>| {
            let checkpoints = rig.hosts.checkpoints();
            std::thread::spawn(move || {
                for host in &own {
                    for archive in 1..=8_u8 {
                        settled_within(&checkpoints, host, &given(archive, 1)).expect("settled");
                    }
                }
            })
        };
        let (first, second) = (spawn(hosts[..2].to_vec()), spawn(hosts[2..].to_vec()));
        first.join().expect("the first thread");
        second.join().expect("the second thread");
        assert_eq!(held(&rig).len(), 32, "every entry is there");
        for host in &hosts {
            for archive in 1..=8_u8 {
                assert_eq!(generation_at(&rig, host, ORIGIN, archive), Some(1));
            }
        }

        for round in 0..20_u8 {
            let host = &hosts[usize::from(round) % hosts.len()];
            let key = 100 + round;
            let handles: Vec<_> = [10_u64, 12, 11]
                .into_iter()
                .map(|generation| {
                    let checkpoints = rig.hosts.checkpoints();
                    let host = host.clone();
                    std::thread::spawn(move || {
                        settled_within(&checkpoints, &host, &given(key, generation))
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("a thread").expect("settled");
            }
            assert_eq!(
                generation_at(&rig, host, ORIGIN, key),
                Some(12),
                "round {round}: generations 10, 12 and 11 end at 12"
            );
        }
        assert_eq!(held(&rig).len(), 52, "no entry was lost or added twice");
    }

    /// A second process settles beside this one under the same lock.
    #[test]
    fn a_second_process_settles_beside_this_one() {
        const CHILD: &str = "KR_CHECKPOINT_TEST_DIRECTORY";
        if let Ok(directory) = std::env::var(CHILD) {
            // The child process: it settles eight archives of each of the last two hosts through a
            // handle of its own.
            let checkpoints = PairedCheckpoints::open(&directory).expect("the directory");
            let hosts = read_hosts(Path::new(&directory)).expect("hosts");
            for host in &hosts[2..] {
                for archive in 1..=8_u8 {
                    settled_within(&checkpoints, host, &given(archive, 1)).expect("settled");
                }
            }
            return;
        }
        let rig = Rig::new();
        let hosts = four_owners(&rig);
        let mut child = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "pairing::checkpoint::tests::a_second_process_settles_beside_this_one",
            ])
            .env(CHILD, rig.hosts.directory())
            .spawn()
            .expect("the child starts");
        for host in &hosts[..2] {
            for archive in 1..=8_u8 {
                settled_within(&rig.checkpoints, host, &given(archive, 1)).expect("settled");
            }
        }
        assert!(child.wait().expect("the child ends").success());
        assert_eq!(held(&rig).len(), 32, "both processes' entries are there");
        for host in &hosts {
            for archive in 1..=8_u8 {
                assert_eq!(generation_at(&rig, host, ORIGIN, archive), Some(1));
            }
        }
    }

    /// The store's own promise at Busy, with no load: while another handle holds the lock, every
    /// settle that would change the file answers Busy after the lock's bound, writes nothing and
    /// lowers nothing, and the same answers settle once the lock is let go. The holder is a second
    /// handle of the lock file, which is what another process holding it is to the store.
    #[test]
    fn a_settle_that_meets_a_held_lock_answers_busy_and_writes_and_lowers_nothing() {
        let rig = Rig::new();
        let (record, fresh) = (owner(1), owner(4));
        rig.hosts.record(record.clone()).expect("recorded");
        rig.hosts.record(fresh.clone()).expect("recorded");
        for (archive, generation) in [(1, 9), (2, 4)] {
            rig.checkpoints
                .settle_checkpoint(&record, &given(archive, generation), NOW)
                .expect("settled");
        }
        let before = std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file");
        let holder = kr_ipc::paths::open_lock_file(&rig.path(LOCK_FILE)).expect("a lock file");
        kr_flush::lock::exclusive(&holder).expect("held");

        // A raise, a lower, an answer of nothing published, a new archive and the first answer of a
        // host that was never told wait for the bound on their own threads, so that the case takes
        // one bound and not five.
        let answers = [
            (&record, given(1, 12)),
            (&record, given(1, 5)),
            (&record, Answer::NothingPublished),
            (&record, given(3, 1)),
            (&fresh, given(4, 1)),
        ];
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = answers
                .iter()
                .map(|(host, answer)| {
                    scope.spawn(|| rig.checkpoints.settle_checkpoint(host, answer, NOW))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("a thread"))
                .collect()
        });
        assert_eq!(results, vec![Err(Unsettled::Busy); answers.len()]);
        assert_eq!(
            std::fs::read(rig.path(CHECKPOINTS_FILE)).expect("the file"),
            before,
            "nothing was written"
        );

        kr_flush::lock::release(&holder).expect("released");
        assert_eq!(entries(&rig), vec![(1, 9), (2, 4)], "nothing was lowered");
        assert_eq!(
            rig.checkpoints.acquisition(&fresh),
            Ok(Acquisition::Owed),
            "a host whose answer met Busy is still owed, so the next ask is made"
        );
        assert_eq!(
            rig.checkpoints
                .settle_checkpoint(&record, &given(1, 12), NOW),
            settled(Outcome::Raised),
            "the same answer settles once the lock is let go"
        );
        assert_eq!(
            rig.checkpoints.settle_checkpoint(&fresh, &given(4, 1), NOW),
            settled(Outcome::New)
        );
        assert_eq!(
            rig.checkpoints.acquisition(&fresh),
            Ok(Acquisition::Told),
            "and the host is told once it settles"
        );
        assert_eq!(entries(&rig), vec![(1, 12), (2, 4), (4, 1)]);
    }
}
