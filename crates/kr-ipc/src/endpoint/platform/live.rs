//! The lock file a listener holds for its whole life, what it records there, and the reading a
//! later bind makes of both before it removes a socket.
//!
//! A socket file is not a lock, and a refused connect is not proof that its listener ended: on
//! macOS a listener whose queue is full refuses a connect too. So every listener of this release
//! holds a shared advisory lock on `<socket>.live` from before its bind until it ends, and the
//! kernel frees the lock when the process ends, however it ends. A later bind that meets a
//! refused socket reads the lock, the record the listener left, and what the volume says about its
//! object numbers, and removes the socket only when all of them show that the listener that made
//! this very socket has ended.
//!
//! What a removal on macOS proves: a listener of this release made this socket (the record names
//! its device and inode and the inode of the lock file), that listener ended (the lock is free),
//! and the volume does not give an inode number out again (the volume's own report, read at each
//! decision). A volume that does not say so, a record that is missing, empty or another
//! listener's, a lock file that was replaced, a lock that cannot be read: each reads as unanswered
//! and nothing is removed. The limits that stay are written beside the rule, in the bind's
//! replacement of a refused socket.
//!
//! A filesystem that does not enforce `flock` gets no record: after taking its lock the listener
//! opens the file a second time and an exclusive try-lock must fail, else it writes none.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;

/// How often a live listener sets the times of its lock file.
///
/// The system's cleaners of temporary files delete a file that nothing touched for three days; the
/// figure is the runtime directory rule's own and sits well under that.
pub(super) const LIVE_REFRESH: Duration = Duration::from_secs(6 * 60 * 60);

/// The lock file of a socket: the same name with `.live` added.
pub(super) fn path_of(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".live");
    PathBuf::from(name)
}

/// What the lock file says to a bind that met a refused socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lock {
    /// There is no lock file.
    Missing,
    /// The file is there and nobody holds it.
    Free,
    /// A listener holds it.
    Held,
    /// It could not be opened or locked for a reason that is not contention.
    Unreadable,
}

/// What a bind read of the lock file and its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) lock: Lock,
    /// The record parses and names this socket and the file that was opened.
    pub(super) record_matches: bool,
}

/// What the volume of the socket's folder says about its object numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(not(target_vendor = "apple"), not(test)),
    expect(dead_code, reason = "only Apple systems read a volume's report")
)]
pub(in crate::endpoint) enum Volume {
    /// The volume says that its object numbers are persistent and not recycled.
    Persistent,
    /// The volume says they are not.
    NotPersistent,
    /// The volume did not say.
    Unknown,
    /// The read failed.
    ReadFailed,
}

/// What a bind does with a refused socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Removal {
    /// Remove it: its listener ended.
    Allowed,
    /// A listener's lock is held: the socket stays.
    LockHeld,
    /// Nothing shows that its listener ended: the socket stays.
    Unanswered,
}

/// The removal rule where a full queue also refuses a connect.
///
/// A socket is removed only when its lock file exists and is free, its record parses and equals
/// this socket and the lock file that was opened, and the volume's object numbers are persistent.
/// A held lock keeps the socket and names the lock; everything else keeps it unanswered.
pub(super) const fn removal_where_a_full_queue_refuses(
    evidence: Evidence,
    volume: Volume,
) -> Removal {
    match evidence.lock {
        Lock::Held => Removal::LockHeld,
        Lock::Free if evidence.record_matches && matches!(volume, Volume::Persistent) => {
            Removal::Allowed
        }
        Lock::Free | Lock::Missing | Lock::Unreadable => Removal::Unanswered,
    }
}

/// The removal rule where a full queue answers `EAGAIN`, so that a refused connect proves that no
/// listener holds the socket.
///
/// The reason is the kernel's, not a lock's: only a held lock stays, because it names a listener
/// of this release that has not ended, and everything else is as it was before the lock existed.
pub(super) const fn removal_where_a_refused_connect_proves_an_end(evidence: Evidence) -> Removal {
    match evidence.lock {
        Lock::Held => Removal::LockHeld,
        Lock::Free | Lock::Missing | Lock::Unreadable => Removal::Allowed,
    }
}

/// Whether the object `second` names is locked by another open of the same file that the caller
/// holds: the lock is enforced only when an exclusive try-lock on a second open meets contention,
/// and no other answer proves it.
pub(super) fn lock_is_enforced(
    second: &File,
    try_lock: impl FnOnce(&File) -> Result<(), Errno>,
) -> bool {
    matches!(try_lock(second), Err(error) if is_contention(error))
}

/// The one error of an advisory lock that says another holder has it.
fn is_contention(error: Errno) -> bool {
    error == Errno::WOULDBLOCK || error == Errno::AGAIN
}

fn try_exclusive(file: &File) -> Result<(), Errno> {
    flock(file, FlockOperation::NonBlockingLockExclusive)
}

/// The record a listener leaves in its lock file: its socket's device and inode, and the inode of
/// the lock file itself, in decimal, one line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) socket: (u64, u64),
    pub(super) file_inode: u64,
}

impl Record {
    pub(super) fn text(self) -> String {
        format!("{} {} {}\n", self.socket.0, self.socket.1, self.file_inode)
    }

    pub(super) fn parse(text: &str) -> Option<Self> {
        let line = text.strip_suffix('\n')?;
        let mut numbers = line.split(' ');
        let device = decimal(numbers.next()?)?;
        let inode = decimal(numbers.next()?)?;
        let file_inode = decimal(numbers.next()?)?;
        if numbers.next().is_some() {
            return None;
        }
        Some(Self {
            socket: (device, inode),
            file_inode,
        })
    }
}

/// A number written in decimal digits and nothing else.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Reads the lock file of `socket` for a bind that met a refused connect.
///
/// The file is opened without creating it, so a decision never makes one. Its lock is tried and
/// released in this call; the caller holds the endpoint's guard, so no other bind of this release
/// takes it in between.
pub(super) fn read(socket: &Path, identity: (u64, u64)) -> Evidence {
    let file = match File::open(path_of(socket)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Evidence {
                lock: Lock::Missing,
                record_matches: false,
            };
        }
        Err(_) => {
            return Evidence {
                lock: Lock::Unreadable,
                record_matches: false,
            };
        }
    };
    read_open(&file, identity, try_exclusive)
}

/// [`read`] over a file already opened and a lock attempt the caller chooses.
fn read_open(
    file: &File,
    identity: (u64, u64),
    try_lock: impl FnOnce(&File) -> Result<(), Errno>,
) -> Evidence {
    match try_lock(file) {
        Ok(()) => {}
        Err(error) if is_contention(error) => {
            return Evidence {
                lock: Lock::Held,
                record_matches: false,
            };
        }
        Err(_) => {
            return Evidence {
                lock: Lock::Unreadable,
                record_matches: false,
            };
        }
    }
    let mut text = String::new();
    let record = file
        .take(RECORD_LIMIT)
        .read_to_string(&mut text)
        .ok()
        .and_then(|_| Record::parse(&text));
    let record_matches = match (record, file.metadata()) {
        (Some(record), Ok(metadata)) => {
            record.socket == identity && record.file_inode == metadata.ino()
        }
        _ => false,
    };
    Evidence {
        lock: Lock::Free,
        record_matches,
    }
}

/// The most of a lock file's text that is read: a record is under a hundred bytes.
const RECORD_LIMIT: u64 = 256;

/// A listener's hold on its lock file, from before its bind until it ends.
///
/// The lock is released by closing the descriptor and by nothing else: a holder that forked keeps
/// its own copy until it exits, and no code unlocks. The file is opened through the standard
/// library, which marks it close-on-exec, so a program the listener's process starts never holds
/// it.
#[derive(Debug)]
pub(super) struct Hold {
    file: Arc<File>,
    path: PathBuf,
    refresh: Option<tokio::task::JoinHandle<()>>,
}

impl Hold {
    /// Opens the lock file, making it when it is not there, and takes a shared lock on it without
    /// waiting.
    pub(super) fn take(socket: &Path) -> std::io::Result<Self> {
        let path = path_of(socket);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        flock(&file, FlockOperation::NonBlockingLockShared).map_err(std::io::Error::from)?;
        Ok(Self {
            file: Arc::new(file),
            path,
            refresh: None,
        })
    }

    /// Leaves the record of the socket just bound, when the lock is shown to be enforced, and
    /// starts the task that keeps the file's times fresh.
    ///
    /// A failure to leave the record leaves none and does not fail the bind: a bind with no record
    /// is never replaced silently later, which is the safe side.
    pub(super) fn publish(&mut self, socket: (u64, u64)) {
        let enforced =
            File::open(&self.path).is_ok_and(|second| lock_is_enforced(&second, try_exclusive));
        self.publish_with(enforced, socket);
    }

    /// [`Self::publish`] once the self-test of the lock has been read.
    fn publish_with(&mut self, enforced: bool, socket: (u64, u64)) {
        if enforced && let Ok(metadata) = self.file.metadata() {
            let record = Record {
                socket,
                file_inode: metadata.ino(),
            }
            .text();
            // The record is one short line: a failed write leaves a file that parses as no record.
            let _ = self.file.set_len(0);
            let _ = self.file.write_all_at(record.as_bytes(), 0);
        }
        self.refresh = Some(keep_the_times_fresh(&self.file));
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        if let Some(task) = self.refresh.take() {
            task.abort();
        }
    }
}

/// Starts the task that sets the lock file's times every [`LIVE_REFRESH`] while the listener holds
/// it, through the handle the listener holds.
///
/// The task holds only a weak reference between ticks and never holds the file across an await, so
/// the lock ends with the listener and not with the task. The first tick is fixed when the task is
/// made, not when it first runs.
fn keep_the_times_fresh(file: &Arc<File>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(file);
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + LIVE_REFRESH, LIVE_REFRESH);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::spawn(async move {
        loop {
            ticks.tick().await;
            let Some(file) = weak.upgrade() else {
                break;
            };
            let _ = refresh(&file);
        }
    })
}

/// Sets the access and modification times of the file to now, through its handle.
pub(super) fn refresh(file: &File) -> std::io::Result<()> {
    let now = std::time::SystemTime::now();
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(now)
            .set_modified(now),
    )
}

#[cfg(test)]
mod tests;
