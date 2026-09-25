//! The machine group this environment records for itself.
//!
//! Section 3 keeps logical machine grouping apart from execution authority. A machine group is a
//! random, owner-approved grouping of environments, never a hardware fingerprint, and it grants no
//! rights by itself: host names, serial numbers and matching paths never establish membership. So
//! each environment records its own group, in a file of its own beside its other state, and
//! changes it only by its own owner-approved step: it joins a group, takes its part in a merge, or
//! splits off into a fresh group. No other environment, no enrolment and no paired device writes
//! the file. The store does not decide who the owner is: its caller checks the owner's authority
//! first, and the store records who approved each step and the action that carried it.
//!
//! The group is minted once, at the environment's first start, while the daemon holds the
//! environment's singleton lock. The mint takes nothing from the machine or from the environment:
//! its value comes from the platform's secure random source alone, so two environments with the
//! same host name, user name and paths get different groups, and so does one environment whose
//! state is created again.
//!
//! The store keeps no copy of the record. Every step reads the record, checks the precondition the
//! owner approved against it and publishes a whole new record, holding one lock per process while
//! it does; the singleton lock keeps every other process out. A step is therefore never checked
//! against anything but the record on disk.
//!
//! A new record is written to a temporary file in the same directory, flushed, renamed over the
//! record, and the directory is flushed after it. The record's name holds a whole record
//! throughout: the old one until the rename, the new one after it. A step that fails before the
//! rename leaves the old record and says so. One that fails after it has published the new record,
//! which every later read returns, and says that whether the change survives a crash is not known.
//! The first record is written the same way and given its name by a link instead, which never
//! replaces a record that exists.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActorId, EnvironmentId, MachineId};
use serde::{Deserialize, Serialize};

use crate::error::{ControllerError, Result};
use crate::singleton::SingletonLock;

/// The name of the record in the environment's state directory.
pub const RECORD_FILE: &str = "machine-group";

/// The start of the name of every temporary file this store writes.
///
/// A publication renames its temporary file into place, so one that is still there was left by a
/// publication that stopped before its rename. The prefix is this store's own, so removing what is
/// left never touches another writer's temporary file in the same directory.
const TEMPORARY_PREFIX: &str = ".machine-group.";

/// The end of the name of every temporary file this store writes.
const TEMPORARY_SUFFIX: &str = ".tmp";

/// The largest record this store reads. A record is a few hundred bytes.
const MAX_RECORD_LEN: u64 = 4096;

/// Serialises every read, check and write of a record in this process.
///
/// The singleton lock keeps a second daemon away from the environment. This keeps two callers in
/// one daemon from each reading the same revision and each writing the one after it. It also covers
/// the first creation and the removal of leftover temporary files, so opening the store never
/// removes the temporary file of a publication that is about to be renamed into place.
static WRITER: Mutex<()> = Mutex::new(());

/// One environment's machine group, as its record states it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGroup {
    /// The environment this record belongs to.
    pub environment_id: EnvironmentId,
    /// The group the environment is in.
    pub machine_id: MachineId,
    /// The record's revision: 1 when it is created, and one more for every step after that.
    pub revision: u64,
    /// The step that wrote this revision.
    pub change: Change,
}

impl MachineGroup {
    /// Returns the precondition that names this record, for a step approved against it.
    #[must_use]
    pub const fn expected(&self) -> Expected {
        Expected {
            machine_id: self.machine_id,
            revision: self.revision,
        }
    }
}

/// The step that wrote a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// The environment's first start minted its group.
    Created {
        /// When the record was created, in milliseconds of the wall clock.
        at_ms: u64,
    },
    /// The owner moved this environment into another group.
    Joined(Step),
    /// The owner merged this environment's group into another; this was this environment's part.
    Merged(Step),
    /// The owner moved this environment into a fresh group of its own.
    Split(Step),
}

/// What an owner-approved step records about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The group this environment left. A step is undone by joining it again.
    pub previous: MachineId,
    /// The verified actor whose owner authority approved the step.
    pub actor: ActorId,
    /// The action that carried the step.
    pub action_id: ActionId,
    /// When the step was taken, in milliseconds of the wall clock.
    pub at_ms: u64,
}

/// The record an owner approved a step against: the group and the revision they saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    /// The group the environment was in.
    pub machine_id: MachineId,
    /// The revision of the record that said so.
    pub revision: u64,
}

/// The owner's approval of one step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    /// The verified actor whose owner authority approved the step.
    pub actor: ActorId,
    /// The action that carries the step.
    pub action_id: ActionId,
}

/// Where a step takes this environment.
#[derive(Clone, Copy, Debug)]
enum Destination {
    /// Into a group the owner named.
    Join(MachineId),
    /// Into the group the owner's merge moves this environment's group into.
    Merge(MachineId),
    /// Into a fresh group of its own.
    Split,
}

/// The points a publication passes, in order. The first record is published by a link, every
/// later one by a rename, and both pass the same points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// The temporary file exists and is empty.
    Created,
    /// The new record is in the temporary file, and may not be on disk yet.
    Written,
    /// The temporary file is flushed and closed, and is published next.
    Flushed,
    /// The record's name holds the new record; the directory is flushed next.
    Published,
}

/// One environment's machine-group record.
#[derive(Debug)]
pub struct MachineStore {
    environment_id: EnvironmentId,
    directory: PathBuf,
    record: PathBuf,
    lock: PathBuf,
}

impl MachineStore {
    /// Opens this environment's record, minting its group when the environment has none yet.
    ///
    /// A missing record is a first start, and the group minted for it is a group of this one
    /// environment. The first record is published by a link, which never replaces a name that
    /// exists, so of two callers that both found none only one group is ever published. Temporary
    /// files an earlier publication left behind, a first start's included, are removed; nothing
    /// reads them.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when `lock` is not this environment's
    /// singleton lock, and a storage failure when the record cannot be created, or exists and is
    /// damaged or belongs to another environment. A record that is refused is left as it is: a
    /// group minted over it would be a change the owner never approved.
    pub fn open(lock: &SingletonLock, paths: &EnvironmentPaths, now_ms: u64) -> Result<Self> {
        let store = Self {
            environment_id: paths.environment_id(),
            directory: paths.state_dir().to_path_buf(),
            record: paths.state_dir().join(RECORD_FILE),
            lock: paths.singleton_lock(),
        };
        store.check_lock(lock)?;
        let _writer = store.writer();
        store.remove_leftovers();
        if store.read()?.is_none() {
            store.mint(now_ms)?;
        }
        store.group()?;
        Ok(store)
    }

    /// Reads the environment's group.
    ///
    /// No lock is needed to read: the record's name always holds a whole record.
    ///
    /// # Errors
    ///
    /// Returns a storage failure when the record is missing, damaged or another environment's.
    pub fn group(&self) -> Result<MachineGroup> {
        self.read()?
            .ok_or_else(|| self.unreadable("the record is missing"))
    }

    /// Moves this environment into the group the owner named.
    ///
    /// Any group identifier is accepted, including one whose members have all left it: a group is
    /// only the value its members record, and this environment cannot see the others.
    ///
    /// # Errors
    ///
    /// Returns `DRAFT_CONFLICT` when the record is no longer the one `expected` names, and
    /// [`ControllerError::InvalidArgument`] when the environment is already in `into`; neither
    /// writes anything. Otherwise as [`Self::split`].
    pub fn join(
        &self,
        lock: &SingletonLock,
        into: MachineId,
        expected: Expected,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<MachineGroup> {
        self.take(lock, Destination::Join(into), expected, approval, now_ms)
    }

    /// Takes this environment's part in merging its group into `into`.
    ///
    /// A merge of two groups of independent environments is one such step on each environment of
    /// the group being merged, each approved against that environment's own record. The record
    /// says the step was a merge and names the group it left, which is how a merge left half done
    /// is recognised, finished or undone.
    ///
    /// # Errors
    ///
    /// As [`Self::join`].
    pub fn merge(
        &self,
        lock: &SingletonLock,
        into: MachineId,
        expected: Expected,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<MachineGroup> {
        self.take(lock, Destination::Merge(into), expected, approval, now_ms)
    }

    /// Moves this environment into a fresh group of its own, minted as the first one was.
    ///
    /// # Errors
    ///
    /// Returns `DRAFT_CONFLICT` when the record is no longer the one `expected` names,
    /// [`ControllerError::PermissionDenied`] when `lock` is not this environment's, a storage
    /// failure when the new record could not be published (the old one stands), and
    /// `OUTCOME_UNKNOWN` when it was published but the directory holding it could not be flushed.
    pub fn split(
        &self,
        lock: &SingletonLock,
        expected: Expected,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<MachineGroup> {
        self.take(lock, Destination::Split, expected, approval, now_ms)
    }

    /// Takes one owner-approved step, against the record on disk.
    fn take(
        &self,
        lock: &SingletonLock,
        destination: Destination,
        expected: Expected,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<MachineGroup> {
        self.check_lock(lock)?;
        let _writer = self.writer();
        let current = self.group()?;
        if current.expected() != expected {
            return Err(ControllerError::Refused {
                code: ErrorCode::DraftConflict,
                detail: format!(
                    "this environment's machine group is {} at revision {}, not {} at revision {} as \
                     the step was approved against",
                    current.machine_id, current.revision, expected.machine_id, expected.revision
                ),
            });
        }
        let step = Step {
            previous: current.machine_id,
            actor: approval.actor.clone(),
            action_id: approval.action_id,
            at_ms: now_ms,
        };
        let (machine_id, change) = match destination {
            Destination::Join(into) => (into, Change::Joined(step)),
            Destination::Merge(into) => (into, Change::Merged(step)),
            Destination::Split => (new_machine_id(), Change::Split(step)),
        };
        if machine_id == current.machine_id {
            return Err(ControllerError::InvalidArgument(format!(
                "this environment is already in machine group {machine_id}"
            )));
        }
        let revision = current
            .revision
            .checked_add(1)
            .ok_or_else(|| self.unreadable("the record has no revision after this one"))?;
        let record = MachineGroup {
            environment_id: self.environment_id,
            machine_id,
            revision,
            change,
        };
        self.publish(&record)?;
        Ok(record)
    }

    /// Refuses a lock that is not this environment's own.
    fn check_lock(&self, lock: &SingletonLock) -> Result<()> {
        if lock.environment_id() == self.environment_id && lock.path() == self.lock.as_path() {
            Ok(())
        } else {
            Err(ControllerError::PermissionDenied {
                detail: format!(
                    "only the holder of environment {}'s singleton lock may write its machine group",
                    self.environment_id
                ),
            })
        }
    }

    /// Reads and checks the record, or finds that there is none.
    fn read(&self) -> Result<Option<MachineGroup>> {
        let Some(bytes) = kr_ipc::paths::read_owner_only_file(&self.record, MAX_RECORD_LEN)
            .map_err(|error| self.unreadable(error))?
        else {
            return Ok(None);
        };
        let record: MachineGroup = serde_json::from_slice(&bytes).map_err(|error| {
            self.unreadable(format!(
                "this is not a machine group record this build understands: {error}"
            ))
        })?;
        if record.environment_id != self.environment_id {
            return Err(self.unreadable(format!(
                "this record belongs to environment {}, not to {}",
                record.environment_id, self.environment_id
            )));
        }
        // What this store writes: a creation at revision 1, and after it steps that each moved the
        // environment somewhere it was not.
        let consistent = match &record.change {
            Change::Created { .. } => record.revision == 1,
            Change::Joined(step) | Change::Merged(step) | Change::Split(step) => {
                record.revision > 1 && step.previous != record.machine_id
            }
        };
        if !consistent {
            return Err(
                self.unreadable("the record's revision and the step that wrote it do not agree")
            );
        }
        Ok(Some(record))
    }

    /// Publishes the first record of a first start.
    ///
    /// The record is complete and flushed before its name exists, and a link gives it the name.
    /// Unlike a rename, a link never replaces a name that exists, so a first start that finds a
    /// record published meanwhile keeps that one. A first start that stopped before the link left
    /// only a temporary file, which the next open removes before it mints again.
    fn mint(&self, now_ms: u64) -> Result<()> {
        let record = MachineGroup {
            environment_id: self.environment_id,
            machine_id: new_machine_id(),
            revision: 1,
            change: Change::Created { at_ms: now_ms },
        };
        let bytes = encode(&record, &self.record)?;
        let temporary = self.temporary();
        let linked = self
            .stage(&temporary, &bytes)
            .and_then(|()| self.passed(Boundary::Flushed))
            .and_then(|()| std::fs::hard_link(&temporary, &self.record));
        let _ = std::fs::remove_file(&temporary);
        match linked {
            Ok(()) => {}
            // Somebody published first. Theirs is the environment's group, and it is read and
            // checked like any other record.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => {
                return Err(storage(
                    "create the machine group record",
                    &self.record,
                    error,
                ));
            }
        }
        // The record exists from here on, and the next open reads it. A failed flush is reported,
        // because the first start cannot say it recorded the group durably.
        self.passed(Boundary::Published)
            .and_then(|()| flush_directory(&self.directory))
            .map_err(|error| storage("create the machine group record", &self.record, error))
    }

    /// Replaces the record with `record`, whole.
    fn publish(&self, record: &MachineGroup) -> Result<()> {
        let bytes = encode(record, &self.record)?;
        let temporary = self.temporary();
        let staged = self
            .stage(&temporary, &bytes)
            .and_then(|()| self.passed(Boundary::Flushed))
            .and_then(|()| std::fs::rename(&temporary, &self.record));
        if let Err(error) = staged {
            // Nothing was published: the record is still the one this step read.
            let _ = std::fs::remove_file(&temporary);
            return Err(storage(
                "write the machine group record",
                &self.record,
                error,
            ));
        }
        // The record's name holds the new record from here on, and every later read returns it.
        // What cannot be told without the directory flush is whether it survives a crash.
        self.passed(Boundary::Published)
            .and_then(|()| flush_directory(&self.directory))
            .map_err(|error| ControllerError::Uncertain {
                detail: format!(
                    "{} now names machine group {} at revision {}, but its directory could not be \
                     flushed, so whether the change survives a crash is not known: {error}",
                    self.record.display(),
                    record.machine_id,
                    record.revision
                ),
            })
    }

    /// Names a new temporary file of this store, in the record's own directory.
    fn temporary(&self) -> PathBuf {
        self.directory.join(format!(
            "{TEMPORARY_PREFIX}{}{TEMPORARY_SUFFIX}",
            kr_ipc::new_uuid()
        ))
    }

    /// Writes `bytes` to a new temporary file, owner-only from its creation, flushed and closed.
    fn stage(&self, temporary: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(kr_ipc::paths::OWNER_ONLY_FILE_MODE);
        }
        let mut file = options.open(temporary)?;
        self.passed(Boundary::Created)?;
        file.write_all(bytes)?;
        self.passed(Boundary::Written)?;
        file.sync_all()?;
        drop(file);
        Ok(())
    }

    /// Removes the temporary files publications of this record left behind.
    fn remove_leftovers(&self) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with(TEMPORARY_PREFIX) && name.ends_with(TEMPORARY_SUFFIX) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Takes this process's writer lock.
    fn writer(&self) -> std::sync::MutexGuard<'static, ()> {
        // A test learns here that a caller has come to the lock, whether or not it has to wait.
        #[cfg(test)]
        seam::locking(&self.record);
        WRITER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Says a publication of this record has passed `boundary`. A test stops or holds one here.
    #[cfg(test)]
    fn passed(&self, boundary: Boundary) -> std::io::Result<()> {
        seam::reached(&self.record, boundary)
    }

    /// Says a publication of this record has passed `boundary`.
    #[cfg(not(test))]
    fn passed(&self, _boundary: Boundary) -> std::io::Result<()> {
        Ok(())
    }

    /// Builds the failure of a record that cannot be read or is not this environment's.
    fn unreadable(&self, reason: impl std::fmt::Display) -> ControllerError {
        storage("read the machine group record", &self.record, reason)
    }
}

/// Mints a group: a random identifier from the platform's secure random source, and nothing else.
fn new_machine_id() -> MachineId {
    MachineId::new(kr_ipc::new_uuid())
}

/// Encodes a record as the file holds it.
fn encode(record: &MachineGroup, path: &Path) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| storage("encode the machine group record", path, error))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Builds a storage failure that names the record.
fn storage(
    operation: &'static str,
    path: &Path,
    reason: impl std::fmt::Display,
) -> ControllerError {
    ControllerError::Storage {
        operation,
        detail: format!("{}: {reason}", path.display()),
    }
}

/// Flushes a directory, so the rename inside it is on disk.
#[cfg(unix)]
fn flush_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

/// Flushes a directory. Windows offers no flush of a directory to ask for.
#[cfg(not(unix))]
fn flush_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Interruptions a test registers for one record, each taken by the first publication of that
/// record to reach its boundary.
#[cfg(test)]
mod seam {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    use super::Boundary;

    /// What a publication does at a registered boundary.
    pub(super) enum Interruption {
        /// Fails there, as a publication whose next operation failed. Its own clean-up runs.
        Fail,
        /// Ends there as a crash would: the thread unwinds, so nothing after this point runs and
        /// the files stay as they were at this moment.
        Crash,
        /// Says it has arrived, then waits there until it is let go on.
        Pause {
            arrived: Sender<()>,
            resume: Receiver<()>,
        },
    }

    type Registered = Vec<(PathBuf, Boundary, Interruption)>;

    static REGISTERED: Mutex<Registered> = Mutex::new(Vec::new());

    /// Callers waiting to hear that a store of their record has come to the writer lock.
    static LOCKING: Mutex<Vec<(PathBuf, Sender<()>)>> = Mutex::new(Vec::new());

    /// Registers one interruption of the next publication of `record` to reach `boundary`.
    pub(super) fn register(record: &Path, boundary: Boundary, interruption: Interruption) {
        REGISTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((record.to_path_buf(), boundary, interruption));
    }

    /// Asks to be told, once, when a store of `record` next comes to the writer lock.
    pub(super) fn watch_lock(record: &Path, told: Sender<()>) {
        LOCKING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((record.to_path_buf(), told));
    }

    /// Tells whoever asked that a store of `record` has come to the writer lock.
    pub(super) fn locking(record: &Path) {
        let watcher = {
            let mut watching = LOCKING.lock().unwrap_or_else(PoisonError::into_inner);
            watching
                .iter()
                .position(|(path, _)| path == record)
                .map(|index| watching.remove(index))
        };
        if let Some((_, told)) = watcher {
            let _ = told.send(());
        }
    }

    /// Acts on the interruption registered for this record and boundary, if there is one.
    pub(super) fn reached(record: &Path, boundary: Boundary) -> std::io::Result<()> {
        let taken = {
            let mut registered = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
            registered
                .iter()
                .position(|(path, at, _)| path == record && *at == boundary)
                .map(|index| registered.remove(index))
        };
        match taken {
            None => Ok(()),
            Some((_, _, Interruption::Fail)) => Err(std::io::Error::other(format!(
                "a test stopped this publication after {boundary:?}"
            ))),
            Some((_, _, Interruption::Crash)) => {
                panic!("a test crashed this publication after {boundary:?}")
            }
            Some((_, _, Interruption::Pause { arrived, resume })) => {
                let _ = arrived.send(());
                let _ = resume.recv_timeout(Duration::from_secs(30));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::panic::AssertUnwindSafe;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use kr_ipc::paths::HostPaths;
    use kr_ipc::testing::TempHost;
    use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
    use serde_json::json;

    use super::seam::Interruption;
    use super::*;

    /// One environment of its own: its directories and its singleton lock.
    struct Environment {
        lock: SingletonLock,
        host: TempHost,
    }

    impl Environment {
        fn create() -> Self {
            let host = TempHost::create();
            let lock =
                SingletonLock::acquire(&host.environment().singleton_lock(), host.environment_id())
                    .expect("takes the environment's lock");
            Self { lock, host }
        }

        fn paths(&self) -> EnvironmentPaths {
            self.host.environment()
        }

        fn open(&self) -> MachineStore {
            MachineStore::open(&self.lock, &self.paths(), 1_000).expect("opens the record")
        }

        /// Reads the group through a store opened afresh, as a restarted daemon would.
        fn reopened(&self) -> MachineGroup {
            self.open().group().expect("reads the record")
        }

        fn record(&self) -> PathBuf {
            self.paths().state_dir().join(RECORD_FILE)
        }
    }

    /// A directory that is removed when the test ends, however it ends.
    struct Removed(PathBuf);

    impl Drop for Removed {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// An approval by the owner at this machine, with an action of its own.
    fn approval() -> Approval {
        Approval {
            actor: ActorId::new("local:owner").expect("a principal"),
            action_id: ActionId::new(kr_ipc::new_uuid()),
        }
    }

    /// A group identifier an owner names: another environment's group, as read from it.
    fn some_group() -> MachineId {
        MachineId::new(kr_ipc::new_uuid())
    }

    /// The store's own temporary files in `directory`.
    fn leftovers(directory: &Path) -> Vec<String> {
        std::fs::read_dir(directory)
            .expect("reads the state directory")
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .filter(|name| name.starts_with(TEMPORARY_PREFIX))
            .collect()
    }

    /// The names in `directory`.
    fn names(directory: &Path) -> BTreeSet<String> {
        std::fs::read_dir(directory)
            .expect("reads a directory")
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .collect()
    }

    /// Every point a publication passes, in order.
    const BOUNDARIES: [Boundary; 4] = [
        Boundary::Created,
        Boundary::Written,
        Boundary::Flushed,
        Boundary::Published,
    ];

    /// The longest a test waits for another thread to reach a point it must reach. Only a failing
    /// test waits this long.
    const WAIT: Duration = Duration::from_secs(10);

    /// Lets a held publication go on when it is dropped, so a test that fails while one is held
    /// never leaves it waiting.
    struct Resume(mpsc::Sender<()>);

    impl Drop for Resume {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    /// Tells a reader to stop when it is dropped, however the test around it ends.
    struct Finish<'a>(&'a AtomicBool);

    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    /// What a file holds and what its metadata says.
    #[derive(Debug, PartialEq, Eq)]
    struct Facts {
        bytes: Vec<u8>,
        modified: std::time::SystemTime,
        #[cfg(unix)]
        inode: u64,
    }

    impl Facts {
        fn of(path: &Path) -> Self {
            let metadata = std::fs::symlink_metadata(path).expect("inspects a file");
            Self {
                bytes: std::fs::read(path).expect("reads a file"),
                modified: metadata.modified().expect("a modification time"),
                #[cfg(unix)]
                inode: std::os::unix::fs::MetadataExt::ino(&metadata),
            }
        }
    }

    /// Every file under `root` but the machine group record, with what it holds and its metadata.
    fn everything_but_the_record(root: &Path) -> BTreeMap<PathBuf, Facts> {
        let mut files = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("reads a directory") {
                let path = entry.expect("reads an entry").path();
                if std::fs::symlink_metadata(&path)
                    .expect("inspects an entry")
                    .is_dir()
                {
                    pending.push(path);
                } else if path.file_name() != Some(std::ffi::OsStr::new(RECORD_FILE)) {
                    files.insert(path.clone(), Facts::of(&path));
                }
            }
        }
        files
    }

    /// An enrolment of another environment, as the process bridge records one.
    fn enrolment() -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([7; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: "ubuntu".to_owned(),
            target: "Ubuntu-24.04".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    /// KR-REQ-03.07: a machine group is never a fingerprint. Two environments created with the
    /// same host name, the same user name and the same paths get different groups, and so does one
    /// environment identity whose state is created again: nothing the machine or the environment
    /// presents goes into the mint.
    #[test]
    fn equal_inputs_give_unequal_groups() {
        let suffix = kr_ipc::new_uuid().to_string();
        let root = Removed(std::env::temp_dir().join(format!("kr-{}", &suffix[..8])));
        // The host name and the user name are this process's own, the same in every start below,
        // and the roots are the same two directories each time.
        let start = || -> (EnvironmentId, MachineId) {
            kr_ipc::paths::create_private_tree(&root.0, &root.0).expect("an owner-only root");
            let paths = HostPaths::new(root.0.join("r"), root.0.join("s")).expect("absolute roots");
            let environment_id = paths
                .open_environment_id()
                .expect("an environment identity");
            let environment = paths.environment(environment_id);
            environment.create().expect("the environment's directories");
            let lock = SingletonLock::acquire(&environment.singleton_lock(), environment_id)
                .expect("takes the environment's lock");
            let store = MachineStore::open(&lock, &environment, 1_000).expect("opens the record");
            (
                environment_id,
                store.group().expect("reads the record").machine_id,
            )
        };
        let (first_environment, first) = start();
        // The same environment identity, with its state created again.
        std::fs::remove_dir_all(root.0.join("s").join("environments"))
            .expect("removes the environment's state");
        std::fs::remove_dir_all(root.0.join("r")).expect("removes the runtime root");
        let (second_environment, second) = start();
        // Another environment, created from nothing at the same paths.
        std::fs::remove_dir_all(&root.0).expect("removes everything");
        let (third_environment, third) = start();

        assert_eq!(
            second_environment, first_environment,
            "the identity was kept"
        );
        assert_ne!(
            third_environment, first_environment,
            "a new identity was minted"
        );
        // The two environments first: equal inputs, unequal groups. Then the one identity whose
        // state was created again, which a group derived from the identity would give away.
        assert_ne!(
            third, first,
            "two environments with the same host name, user name and paths share a group"
        );
        assert_ne!(
            second, first,
            "one environment identity with the same paths was given the same group again"
        );
        assert_ne!(third, second, "two starts at the same paths share a group");
        for group in [first, second, third] {
            assert_eq!(
                group.get().version(),
                4,
                "a group is a random version 4 identifier"
            );
        }
    }

    /// KR-REQ-03.07: nothing but this environment's own owner-approved steps changes its group. A
    /// reopen, an enrolment of another environment and a restart that finds the whole state tree
    /// moved leave the group as it was; the owner's join changes it.
    #[test]
    fn only_this_environments_own_steps_change_its_group() {
        let host = TempHost::create();
        let environment_id = host.environment_id();
        let paths = host.environment();
        let lock = SingletonLock::acquire(&paths.singleton_lock(), environment_id)
            .expect("takes the environment's lock");
        let created = MachineStore::open(&lock, &paths, 1_000)
            .and_then(|store| store.group())
            .expect("mints the group");
        assert_eq!(created.environment_id, environment_id);
        assert_eq!(created.revision, 1);
        assert_eq!(created.change, Change::Created { at_ms: 1_000 });

        for _ in 0..3 {
            let reopened = MachineStore::open(&lock, &paths, 9_000)
                .and_then(|store| store.group())
                .expect("reads the group again");
            assert_eq!(reopened, created, "a reopen changed the group");
        }

        crate::bridge::store::Store::with_locked(paths.state_dir(), |store| {
            store.enrol(enrolment(), 2_000)
        })
        .expect("enrols another environment");
        let after_enrolment = MachineStore::open(&lock, &paths, 9_000)
            .and_then(|store| store.group())
            .expect("reads the group after the enrolment");
        assert_eq!(after_enrolment, created, "an enrolment changed the group");

        // A restart that finds the whole state tree somewhere else.
        drop(lock);
        let moved = host.root().join("moved");
        std::fs::rename(host.paths().state_root(), &moved).expect("moves the state tree");
        let moved_paths =
            HostPaths::new(host.paths().runtime_root().to_path_buf(), moved).expect("new roots");
        assert_eq!(
            moved_paths
                .open_environment_id()
                .expect("reads the identity"),
            environment_id
        );
        let moved_environment = moved_paths.environment(environment_id);
        moved_environment
            .create()
            .expect("the environment's directories");
        let lock = SingletonLock::acquire(&moved_environment.singleton_lock(), environment_id)
            .expect("takes the lock where it now is");
        let store = MachineStore::open(&lock, &moved_environment, 9_000).expect("opens the record");
        assert_eq!(
            store.group().expect("reads the group"),
            created,
            "a move of the state tree changed the group"
        );

        let into = some_group();
        let joined = store
            .join(&lock, into, created.expected(), &approval(), 3_000)
            .expect("the owner's join");
        assert_eq!(joined.machine_id, into);
        assert_eq!(joined.revision, 2);
        assert_eq!(store.group().expect("reads the group"), joined);
    }

    /// KR-REQ-03.07: a join, a merge and a split write the machine group record and nothing else.
    /// The environment identity file, the identity markers in the runtime and state directories
    /// and every other file under both roots keep their bytes, their modification times and, on
    /// Unix, their inodes.
    #[test]
    fn join_merge_and_split_leave_the_environment_identity_untouched() {
        let environment = Environment::create();
        let store = environment.open();
        let before = everything_but_the_record(environment.host.root());
        for identity in [
            environment.host.paths().environment_id_file(),
            environment
                .paths()
                .state_dir()
                .join(kr_ipc::paths::ENVIRONMENT_MARKER),
            environment
                .paths()
                .runtime_dir()
                .join(kr_ipc::paths::ENVIRONMENT_MARKER),
        ] {
            assert!(
                before.contains_key(&identity),
                "{} is among what is compared",
                identity.display()
            );
        }

        let created = store.group().expect("reads the group");
        let joined = store
            .join(
                &environment.lock,
                some_group(),
                created.expected(),
                &approval(),
                2_000,
            )
            .expect("joins");
        assert_eq!(
            everything_but_the_record(environment.host.root()),
            before,
            "a join touched another file"
        );
        let merged = store
            .merge(
                &environment.lock,
                some_group(),
                joined.expected(),
                &approval(),
                3_000,
            )
            .expect("merges");
        assert_eq!(
            everything_but_the_record(environment.host.root()),
            before,
            "a merge touched another file"
        );
        store
            .split(&environment.lock, merged.expected(), &approval(), 4_000)
            .expect("splits");
        assert_eq!(
            everything_but_the_record(environment.host.root()),
            before,
            "a split touched another file"
        );
    }

    /// KR-REQ-03.07: a group survives a reopen of the store after every kind of step, and a
    /// restart under a new lock, with its revision and the step that wrote it.
    #[test]
    fn a_group_survives_a_reopen_after_every_step() {
        let environment = Environment::create();
        let store = environment.open();
        let created = store.group().expect("reads the group");
        assert_eq!(environment.reopened(), created);

        let approved = approval();
        let joined = store
            .join(
                &environment.lock,
                some_group(),
                created.expected(),
                &approved,
                2_000,
            )
            .expect("joins");
        assert_eq!(
            joined.change,
            Change::Joined(Step {
                previous: created.machine_id,
                actor: approved.actor.clone(),
                action_id: approved.action_id,
                at_ms: 2_000,
            })
        );
        assert_eq!(
            environment.reopened(),
            joined,
            "a join did not survive a reopen"
        );
        let merged = store
            .merge(
                &environment.lock,
                some_group(),
                joined.expected(),
                &approval(),
                3_000,
            )
            .expect("merges");
        assert_eq!(
            environment.reopened(),
            merged,
            "a merge did not survive a reopen"
        );
        let split = store
            .split(&environment.lock, merged.expected(), &approval(), 4_000)
            .expect("splits");
        assert_eq!(
            environment.reopened(),
            split,
            "a split did not survive a reopen"
        );

        // A restart: the lock is given up and taken again.
        let Environment { lock, host } = environment;
        drop(lock);
        let lock =
            SingletonLock::acquire(&host.environment().singleton_lock(), host.environment_id())
                .expect("takes the lock again");
        let restarted = MachineStore::open(&lock, &host.environment(), 9_000)
            .and_then(|store| store.group())
            .expect("reads the group after a restart");
        assert_eq!(restarted, split, "the group did not survive a restart");
    }

    /// KR-REQ-03.07: a step interrupted after any point of its publication, by a failure or by a
    /// crash, leaves the old group or the new one, never neither and never a fresh one: the old
    /// one until the record's name is replaced, the new one from then on. A failure is answered
    /// with `STORAGE_UNAVAILABLE` before that point and `OUTCOME_UNKNOWN` after it, and removes
    /// its temporary file; a crash leaves the temporary file, and the next open removes it.
    #[test]
    fn a_step_interrupted_at_any_point_leaves_the_old_group_or_the_new_one() {
        for crash in [false, true] {
            for boundary in BOUNDARIES {
                let environment = Environment::create();
                let store = environment.open();
                let before = store.group().expect("reads the group");
                let into = some_group();
                let interruption = if crash {
                    Interruption::Crash
                } else {
                    Interruption::Fail
                };
                seam::register(&environment.record(), boundary, interruption);
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    store.join(
                        &environment.lock,
                        into,
                        before.expected(),
                        &approval(),
                        2_000,
                    )
                }));
                let published = boundary == Boundary::Published;
                let what = if crash { "a crash" } else { "a failure" };
                match outcome {
                    Ok(answer) => {
                        assert!(!crash, "{what} after {boundary:?} did not end the step");
                        let failure = answer.expect_err("the failed step says so");
                        let code = if published {
                            ErrorCode::OutcomeUnknown
                        } else {
                            ErrorCode::StorageUnavailable
                        };
                        assert_eq!(failure.code(), code, "{what} after {boundary:?}");
                        assert!(
                            leftovers(environment.paths().state_dir()).is_empty(),
                            "{what} after {boundary:?} left its temporary file"
                        );
                    }
                    Err(_) => assert!(crash, "{what} after {boundary:?} unwound"),
                }
                let after = environment.reopened();
                assert!(
                    leftovers(environment.paths().state_dir()).is_empty(),
                    "the open after {what} after {boundary:?} left a temporary file"
                );
                if published {
                    assert_eq!(after.machine_id, into, "{what} after {boundary:?}");
                    assert_eq!(
                        after.revision,
                        before.revision + 1,
                        "{what} after {boundary:?}"
                    );
                } else {
                    assert_eq!(after, before, "{what} after {boundary:?} changed the group");
                }
            }
        }
    }

    /// KR-REQ-03.07: at every point of a step's publication the record's name holds a whole
    /// record: the old one until the new one replaces it, and the new one from then on. The step
    /// is held at each point while the record is read.
    #[test]
    fn the_record_is_whole_at_every_point_of_a_publication() {
        let environment = Environment::create();
        let store = environment.open();
        let before = store.group().expect("reads the group");
        let into = some_group();
        let mut checkpoints = Vec::new();
        for boundary in BOUNDARIES {
            let (arrived, arrival) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            seam::register(
                &environment.record(),
                boundary,
                Interruption::Pause {
                    arrived,
                    resume: resumed,
                },
            );
            checkpoints.push((boundary, arrival, Resume(resume)));
        }
        std::thread::scope(|scope| {
            let step = scope.spawn(|| {
                store.join(
                    &environment.lock,
                    into,
                    before.expected(),
                    &approval(),
                    2_000,
                )
            });
            for (boundary, arrival, resume) in checkpoints {
                arrival
                    .recv_timeout(WAIT)
                    .unwrap_or_else(|_| panic!("the step never reached {boundary:?}"));
                let bytes = std::fs::read(environment.record()).unwrap_or_else(|error| {
                    panic!("the record's name held no file after {boundary:?}: {error}")
                });
                let on_disk: MachineGroup =
                    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                        panic!("the record's name held part of one after {boundary:?}: {error}")
                    });
                if boundary == Boundary::Published {
                    assert_eq!(on_disk.machine_id, into, "after {boundary:?}");
                } else {
                    assert_eq!(on_disk, before, "after {boundary:?}");
                }
                drop(resume);
            }
            let written = step
                .join()
                .expect("the step ran")
                .expect("the step published its record");
            assert_eq!(written.machine_id, into);
        });
    }

    /// KR-REQ-03.07: a step never writes into the file that holds the current record. A second
    /// name for that file, taken before each step, still holds the old record afterwards, so the
    /// record's name held the whole old record until it held the whole new one.
    #[test]
    fn a_step_never_writes_the_current_record_in_place() {
        let environment = Environment::create();
        let store = environment.open();
        let kept = environment.paths().state_dir().join("kept");
        let mut current = store.group().expect("reads the group");
        for kind in ["join", "merge", "split"] {
            let before = std::fs::read(environment.record()).expect("reads the record");
            let _ = std::fs::remove_file(&kept);
            std::fs::hard_link(environment.record(), &kept).expect("a second name for the record");
            current = match kind {
                "join" => store.join(
                    &environment.lock,
                    some_group(),
                    current.expected(),
                    &approval(),
                    2_000,
                ),
                "merge" => store.merge(
                    &environment.lock,
                    some_group(),
                    current.expected(),
                    &approval(),
                    3_000,
                ),
                _ => store.split(&environment.lock, current.expected(), &approval(), 4_000),
            }
            .expect("takes the step");
            assert_eq!(
                std::fs::read(&kept).expect("reads the old file"),
                before,
                "a {kind} wrote into the file the old record was in"
            );
            assert_eq!(environment.reopened(), current);
        }
    }

    /// KR-REQ-03.07: a reader running beside real publications never finds the record's name
    /// missing or holding part of a record. The held checkpoints above prove each point of one
    /// publication; this reads while 64 run freely, from before the first one starts.
    #[test]
    fn a_reader_always_finds_a_whole_record_while_steps_publish() {
        let environment = Environment::create();
        let store = environment.open();
        let record = environment.record();
        let done = AtomicBool::new(false);
        let (reading, started) = mpsc::channel();
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut reads = 0_u64;
                loop {
                    let bytes = std::fs::read(&record)
                        .map_err(|error| format!("the record's name held no file: {error}"))?;
                    serde_json::from_slice::<MachineGroup>(&bytes)
                        .map_err(|error| format!("the record's name held part of one: {error}"))?;
                    reads += 1;
                    if reads == 1 {
                        let _ = reading.send(());
                    }
                    if done.load(Ordering::Acquire) {
                        return Ok::<u64, String>(reads);
                    }
                }
            });
            // The reader stops when the publishing ends, however it ends.
            let finish = Finish(&done);
            // A reader that failed at once ends without saying it started; its failure is reported
            // below.
            let _ = started.recv_timeout(WAIT);
            let mut current = store.group().expect("reads the group");
            for _ in 0..64 {
                current = store
                    .join(
                        &environment.lock,
                        some_group(),
                        current.expected(),
                        &approval(),
                        2_000,
                    )
                    .expect("joins");
            }
            drop(finish);
            let reads = reader
                .join()
                .expect("the reader ran")
                .unwrap_or_else(|failure| panic!("{failure}"));
            assert!(reads > 0, "the reader read the record");
        });
    }

    /// KR-REQ-03.07: a temporary file a stopped publication left behind is never read, and opening
    /// the store removes it; a temporary file of another writer in the same directory is left
    /// alone.
    #[test]
    fn a_leftover_temporary_file_is_never_read_and_is_removed() {
        let environment = Environment::create();
        let before = environment.reopened();
        let directory = environment.paths().state_dir().to_path_buf();
        let whole = MachineGroup {
            machine_id: some_group(),
            revision: before.revision + 1,
            change: Change::Joined(Step {
                previous: before.machine_id,
                actor: ActorId::new("local:owner").expect("a principal"),
                action_id: ActionId::new(kr_ipc::new_uuid()),
                at_ms: 2_000,
            }),
            ..before.clone()
        };
        let whole = encode(&whole, &environment.record()).expect("encodes a record");
        let ours = [
            directory.join(format!(
                "{TEMPORARY_PREFIX}{}{TEMPORARY_SUFFIX}",
                kr_ipc::new_uuid()
            )),
            directory.join(format!(
                "{TEMPORARY_PREFIX}{}{TEMPORARY_SUFFIX}",
                kr_ipc::new_uuid()
            )),
        ];
        kr_ipc::paths::write_owner_only_file(&ours[0], &whole[..whole.len() / 2])
            .expect("a torn temporary file");
        kr_ipc::paths::write_owner_only_file(&ours[1], &whole).expect("a whole temporary file");
        let theirs = directory.join(format!(".{}.tmp", kr_ipc::new_uuid()));
        kr_ipc::paths::write_owner_only_file(&theirs, b"another writer's").expect("another's file");

        assert_eq!(environment.reopened(), before, "a temporary file was read");
        for path in &ours {
            assert!(!path.exists(), "{} was left behind", path.display());
        }
        assert!(
            theirs.exists(),
            "another writer's temporary file was removed"
        );
    }

    /// KR-REQ-03.07: opening the store while a step is publishing waits for the writer lock the
    /// step holds, so it never removes the temporary file the step is about to publish. The step is
    /// held just before its rename; the opener says when it has come to the lock, and cannot have
    /// finished by then.
    #[test]
    fn opening_waits_for_a_publication_in_progress() {
        let environment = Environment::create();
        let store = environment.open();
        let before = store.group().expect("reads the group");
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        seam::register(
            &environment.record(),
            Boundary::Flushed,
            Interruption::Pause {
                arrived,
                resume: resumed,
            },
        );
        let resume = Resume(resume);
        let into = some_group();
        let environment = &environment;
        std::thread::scope(|scope| {
            let step = scope.spawn(|| {
                store.join(
                    &environment.lock,
                    into,
                    before.expected(),
                    &approval(),
                    2_000,
                )
            });
            arrival
                .recv_timeout(WAIT)
                .expect("the step reached its publication");
            // Asked only now, so the answer is the opener's: the step already holds the lock.
            let (told, locking) = mpsc::channel();
            seam::watch_lock(&environment.record(), told);
            let (opened, opening) = mpsc::channel();
            let opener = scope.spawn(move || {
                let read = MachineStore::open(&environment.lock, &environment.paths(), 3_000)
                    .and_then(|store| store.group());
                let _ = opened.send(());
                read
            });
            locking
                .recv_timeout(WAIT)
                .expect("the opener came to the writer lock");
            assert!(
                opening.try_recv().is_err(),
                "an open finished while a step was publishing"
            );
            drop(resume);
            let written = step
                .join()
                .expect("the step ran")
                .expect("the step published its record");
            let read = opener
                .join()
                .expect("the opener ran")
                .expect("the opener read the record");
            assert_eq!(written.machine_id, into);
            assert_eq!(read, written);
        });
    }

    /// KR-REQ-03.07: a first start interrupted after any point of its publication, by a failure
    /// or by a crash, leaves no record, so the next start mints a group, or the whole record it
    /// published, which the next start keeps. Nothing it wrote is left behind once the next start
    /// has run.
    #[test]
    fn a_first_start_interrupted_at_any_point_leaves_no_record_or_a_whole_one() {
        for crash in [false, true] {
            for boundary in BOUNDARIES {
                let environment = Environment::create();
                let directory = environment.paths().state_dir().to_path_buf();
                let mut expected = names(&directory);
                expected.insert(RECORD_FILE.to_owned());
                let interruption = if crash {
                    Interruption::Crash
                } else {
                    Interruption::Fail
                };
                seam::register(&environment.record(), boundary, interruption);
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    MachineStore::open(&environment.lock, &environment.paths(), 1_000)
                }));
                let what = if crash { "a crash" } else { "a failure" };
                match outcome {
                    Ok(answer) => {
                        assert!(!crash, "{what} after {boundary:?} did not end the start");
                        assert_eq!(
                            answer.expect_err("the failed start says so").code(),
                            ErrorCode::StorageUnavailable,
                            "{what} after {boundary:?}"
                        );
                    }
                    Err(_) => assert!(crash, "{what} after {boundary:?} unwound"),
                }
                let published = std::fs::read(environment.record()).ok();
                assert_eq!(
                    published.is_some(),
                    boundary == Boundary::Published,
                    "{what} after {boundary:?}"
                );
                let started_again = environment.reopened();
                assert_eq!(started_again.change, Change::Created { at_ms: 1_000 });
                if let Some(bytes) = published {
                    let kept: MachineGroup =
                        serde_json::from_slice(&bytes).expect("the published record is whole");
                    assert_eq!(
                        started_again, kept,
                        "the next start replaced the group {what} after {boundary:?} published"
                    );
                }
                assert_eq!(
                    names(&directory),
                    expected,
                    "{what} after {boundary:?} left a file the next start did not remove"
                );
            }
        }
    }

    /// KR-REQ-03.07: a first start that finds a record published after it looked keeps that
    /// record and publishes nothing of its own, so of two first starts only one group is ever
    /// published.
    #[test]
    fn a_first_start_never_replaces_a_record_published_meanwhile() {
        let environment = Environment::create();
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        seam::register(
            &environment.record(),
            Boundary::Flushed,
            Interruption::Pause {
                arrived,
                resume: resumed,
            },
        );
        let resume = Resume(resume);
        let other = MachineGroup {
            environment_id: environment.host.environment_id(),
            machine_id: some_group(),
            revision: 1,
            change: Change::Created { at_ms: 500 },
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                MachineStore::open(&environment.lock, &environment.paths(), 1_000)
                    .and_then(|store| store.group())
            });
            arrival
                .recv_timeout(WAIT)
                .expect("the first start is about to publish");
            kr_ipc::paths::write_owner_only_file(
                &environment.record(),
                &encode(&other, &environment.record()).expect("encodes a record"),
            )
            .expect("another start publishes first");
            drop(resume);
            let kept = first
                .join()
                .expect("the first start ran")
                .expect("the first start read the record");
            assert_eq!(
                kept, other,
                "a first start replaced a record published meanwhile"
            );
        });
        assert_eq!(environment.reopened(), other);
        assert!(leftovers(environment.paths().state_dir()).is_empty());
    }

    /// KR-REQ-03.07: a step approved against a record that is no longer current is refused, and so
    /// is a join into the group the environment is already in; neither writes anything.
    #[test]
    fn a_stale_precondition_is_refused_and_nothing_is_written() {
        let environment = Environment::create();
        let store = environment.open();
        let created = store.group().expect("reads the group");
        let joined = store
            .join(
                &environment.lock,
                some_group(),
                created.expected(),
                &approval(),
                2_000,
            )
            .expect("joins");
        let on_disk = Facts::of(&environment.record());

        let refusals = [
            // The group the owner saw has moved on.
            store.join(
                &environment.lock,
                some_group(),
                created.expected(),
                &approval(),
                3_000,
            ),
            // The current group, at a revision the owner never saw.
            store.merge(
                &environment.lock,
                some_group(),
                Expected {
                    revision: joined.revision + 1,
                    ..joined.expected()
                },
                &approval(),
                3_000,
            ),
            // The current revision, of another group.
            store.split(
                &environment.lock,
                Expected {
                    machine_id: some_group(),
                    ..joined.expected()
                },
                &approval(),
                3_000,
            ),
        ];
        for refusal in refusals {
            assert_eq!(
                refusal.expect_err("a stale precondition is refused").code(),
                ErrorCode::DraftConflict
            );
        }
        let already = store
            .join(
                &environment.lock,
                joined.machine_id,
                joined.expected(),
                &approval(),
                3_000,
            )
            .expect_err("a join into the current group is refused");
        assert_eq!(already.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            Facts::of(&environment.record()),
            on_disk,
            "a refused step wrote"
        );
        assert_eq!(store.group().expect("reads the group"), joined);
    }

    /// KR-REQ-03.07: only the holder of this environment's own singleton lock opens or writes its
    /// record. Another environment's lock is refused, and so is a lock for this environment's
    /// identity taken at another path.
    #[test]
    fn a_lock_for_another_environment_or_another_path_is_refused() {
        let first = Environment::create();
        let second = Environment::create();
        let refused = MachineStore::open(&second.lock, &first.paths(), 1_000)
            .expect_err("another environment's lock opens nothing");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert!(!first.record().exists(), "a refused open created a record");

        let store = first.open();
        let created = store.group().expect("reads the group");
        let refused = store
            .join(
                &second.lock,
                some_group(),
                created.expected(),
                &approval(),
                2_000,
            )
            .expect_err("another environment's lock writes nothing");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        let stray = SingletonLock::acquire(
            &first.host.root().join("elsewhere.lock"),
            first.host.environment_id(),
        )
        .expect("takes a lock at another path");
        let refused = store
            .split(&stray, created.expected(), &approval(), 2_000)
            .expect_err("a lock at another path writes nothing");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert_eq!(store.group().expect("reads the group"), created);
    }

    /// KR-REQ-03.07: a merge of two groups of independent environments is each environment's own
    /// step. Left half done, the moved environment records which group it left in a merge while
    /// the rest still report the old group; each remaining environment's own step, against the
    /// record the plan holds for it, finishes the merge, and a step sent again after it completed
    /// writes nothing.
    #[test]
    fn a_merge_left_half_done_is_finished_by_each_remaining_environments_own_step() {
        let first = Environment::create();
        let second = Environment::create();
        let third = Environment::create();
        let (one, two, three) = (first.open(), second.open(), third.open());
        let into = one.group().expect("reads the group").machine_id;
        // The second and third environments are one group: the third joined the second's.
        let merging = two.group().expect("reads the group").machine_id;
        let third_before = three
            .join(
                &third.lock,
                merging,
                three.group().expect("reads the group").expected(),
                &approval(),
                2_000,
            )
            .expect("joins");
        // The owner's plan: both, each with the record the owner saw.
        let second_before = two.group().expect("reads the group");

        let moved = two
            .merge(
                &second.lock,
                into,
                second_before.expected(),
                &approval(),
                3_000,
            )
            .expect("the second environment's step");
        // Half done.
        assert_eq!(moved.machine_id, into);
        assert!(
            matches!(&moved.change, Change::Merged(step) if step.previous == merging),
            "the moved environment names the group it left in a merge: {:?}",
            moved.change
        );
        assert_eq!(
            three.group().expect("reads the group").machine_id,
            merging,
            "an environment that took no step moved"
        );
        assert_eq!(one.group().expect("reads the group").machine_id, into);

        let finished = three
            .merge(
                &third.lock,
                into,
                third_before.expected(),
                &approval(),
                4_000,
            )
            .expect("the third environment's step");
        assert!(matches!(&finished.change, Change::Merged(step) if step.previous == merging));
        for store in [&one, &two, &three] {
            assert_eq!(store.group().expect("reads the group").machine_id, into);
        }
        let again = two
            .merge(
                &second.lock,
                into,
                second_before.expected(),
                &approval(),
                5_000,
            )
            .expect_err("a completed step is not taken twice");
        assert_eq!(again.code(), ErrorCode::DraftConflict);
    }

    /// KR-REQ-03.07: a merge is undone by each moved environment's own step back to the group its
    /// record says it left, approved against the record the merge wrote.
    #[test]
    fn a_merge_is_undone_by_each_moved_environments_own_step() {
        let first = Environment::create();
        let second = Environment::create();
        let into = first.reopened().machine_id;
        let store = second.open();
        let before = store.group().expect("reads the group");
        let merged = store
            .merge(&second.lock, into, before.expected(), &approval(), 2_000)
            .expect("merges");
        let Change::Merged(step) = &merged.change else {
            panic!("a merge recorded {:?}", merged.change);
        };
        let undone = store
            .join(
                &second.lock,
                step.previous,
                merged.expected(),
                &approval(),
                3_000,
            )
            .expect("undoes the merge");
        assert_eq!(undone.machine_id, before.machine_id);
        assert!(matches!(&undone.change, Change::Joined(step) if step.previous == into));
        assert_eq!(
            first.reopened().machine_id,
            into,
            "the other group is untouched"
        );
    }

    /// KR-REQ-03.07: an undo is bound to the record its step wrote, so it never reverses a later
    /// change, even one that brought the environment back to the same group.
    #[test]
    fn an_undo_never_reverses_a_later_change() {
        let environment = Environment::create();
        let store = environment.open();
        let start = store.group().expect("reads the group");
        let into = some_group();
        let merged = store
            .merge(
                &environment.lock,
                into,
                start.expected(),
                &approval(),
                2_000,
            )
            .expect("merges");
        let split = store
            .split(&environment.lock, merged.expected(), &approval(), 3_000)
            .expect("splits");
        let back = store
            .join(
                &environment.lock,
                into,
                split.expected(),
                &approval(),
                4_000,
            )
            .expect("joins the merged group again");
        assert_eq!(back.machine_id, merged.machine_id);

        let refused = store
            .join(
                &environment.lock,
                start.machine_id,
                merged.expected(),
                &approval(),
                5_000,
            )
            .expect_err("the merge's undo is refused after later changes");
        assert_eq!(refused.code(), ErrorCode::DraftConflict);
        assert_eq!(store.group().expect("reads the group"), back);
    }

    /// KR-REQ-03.07: a split gives the leaving environment a fresh random group, a different one
    /// for each environment that leaves, and leaves the environments that stay where they were.
    #[test]
    fn a_split_gives_the_leaving_environment_a_fresh_random_group() {
        let staying = Environment::create();
        let leaving = [Environment::create(), Environment::create()];
        let group = staying.reopened().machine_id;
        let mut left = Vec::new();
        for environment in &leaving {
            let store = environment.open();
            let joined = store
                .join(
                    &environment.lock,
                    group,
                    store.group().expect("reads the group").expected(),
                    &approval(),
                    2_000,
                )
                .expect("joins");
            let split = store
                .split(&environment.lock, joined.expected(), &approval(), 3_000)
                .expect("splits");
            assert!(matches!(&split.change, Change::Split(step) if step.previous == group));
            assert_ne!(split.machine_id, group, "a split kept the group");
            assert_eq!(
                split.machine_id.get().version(),
                4,
                "a fresh group is random"
            );
            left.push(split.machine_id);
        }
        assert_ne!(
            left[0], left[1],
            "two environments that left one group share a group"
        );
        assert_eq!(
            staying.reopened().machine_id,
            group,
            "the staying environment moved"
        );
    }

    /// KR-REQ-03.07: a join takes any group identifier the owner names, including one whose last
    /// member has left; no membership is asked for.
    #[test]
    fn an_environment_goes_back_to_a_group_its_last_member_left() {
        let environment = Environment::create();
        let store = environment.open();
        let alone = store.group().expect("reads the group");
        let split = store
            .split(&environment.lock, alone.expected(), &approval(), 2_000)
            .expect("splits");
        let back = store
            .join(
                &environment.lock,
                alone.machine_id,
                split.expected(),
                &approval(),
                3_000,
            )
            .expect("joins the group nobody is in");
        assert_eq!(back.machine_id, alone.machine_id);
    }

    /// KR-REQ-03.07: a record another environment wrote, or one this build cannot read, is refused
    /// and left exactly as it is. Nothing mints a group over it: that would change the group
    /// without the owner's approval.
    #[test]
    fn a_foreign_or_damaged_record_is_refused_and_kept() {
        let other = Environment::create();
        let foreign = {
            other.open();
            std::fs::read(other.record()).expect("reads another environment's record")
        };
        let environment = Environment::create();
        let store = environment.open();
        let created = store.group().expect("reads the group");
        let own = std::fs::read(environment.record()).expect("reads the record");
        let joined = {
            store
                .join(
                    &environment.lock,
                    some_group(),
                    created.expected(),
                    &approval(),
                    2_000,
                )
                .expect("joins");
            std::fs::read(environment.record()).expect("reads the record")
        };
        let edited = |bytes: &[u8], edit: &dyn Fn(&mut serde_json::Value)| {
            let mut value: serde_json::Value =
                serde_json::from_slice(bytes).expect("a record is JSON");
            edit(&mut value);
            serde_json::to_vec(&value).expect("encodes JSON")
        };
        let damaged = [
            ("another environment's record", foreign),
            ("a torn record", own[..own.len() / 2].to_vec()),
            (
                "an unknown member",
                edited(&own, &|value| value["colour"] = json!("blue")),
            ),
            (
                "an unknown member of a creation",
                edited(&own, &|value| value["change"]["colour"] = json!("blue")),
            ),
            (
                "an unknown member of a step",
                edited(&joined, &|value| value["change"]["colour"] = json!("blue")),
            ),
            (
                "an unknown kind of change",
                edited(&own, &|value| value["change"]["kind"] = json!("adopted")),
            ),
            (
                "revision zero",
                edited(&own, &|value| value["revision"] = json!(0)),
            ),
            (
                "a creation after the first revision",
                edited(&own, &|value| value["revision"] = json!(2)),
            ),
            (
                "a step into the group it left",
                edited(&joined, &|value| {
                    value["change"]["previous"] = value["machine_id"].clone();
                }),
            ),
        ];
        for (what, bytes) in damaged {
            kr_ipc::paths::write_owner_only_file(&environment.record(), &bytes)
                .expect("places the record");
            let refused =
                MachineStore::open(&environment.lock, &environment.paths(), 9_000).expect_err(what);
            assert_eq!(refused.code(), ErrorCode::StorageUnavailable, "{what}");
            let refused = store.group().expect_err(what);
            assert_eq!(refused.code(), ErrorCode::StorageUnavailable, "{what}");
            assert_eq!(
                std::fs::read(environment.record()).expect("reads the record"),
                bytes,
                "{what} was not kept as it was"
            );
        }
    }
}
