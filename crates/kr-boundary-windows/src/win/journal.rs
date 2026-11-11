//! The journal's file: one for each invocation, every row written through to the disk before the
//! step it protects, and read back after a crash.
//!
//! A row is framed (a length, the bytes, a checksum), appended in one write to a file opened to
//! write through, and flushed before [`Journal::append`] returns. A write that fails leaves the
//! journal closed to further rows: a torn tail is cut away when the file is taken up again, and the
//! rows before it stand. The order the rows may come in is the [`Tracker`]'s: a row out of order is
//! refused here and never reaches the file.

use std::fs::{File, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ};

use crate::filekey::FileKey;
use crate::journal::framing::{self, FramingError};
use crate::journal::replay::{self, Invocation, OrderError, Reading, Standing, Tracker};
use crate::journal::rows::Row;

use super::launch::{InvocationId, ResumePermit, SuspendedChild};
use super::root::{RootError, RootRows};

/// The extension of a journal file.
const EXTENSION: &str = "journal";

/// Why a row was not written, or a file could not be taken up.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file could not be made, opened, written or flushed.
    #[error("the journal's file: {0}")]
    Io(#[from] std::io::Error),
    /// The row could not be framed.
    #[error("the row could not be framed: {0}")]
    Framing(#[from] FramingError),
    /// The row may not come now.
    #[error("the row is out of order: {0}")]
    Order(#[from] OrderError),
    /// An earlier write failed, so no row is written until the file is taken up again.
    #[error("an earlier row could not be written, so the journal takes no more")]
    Closed,
    /// The file cannot be taken up again.
    #[error("the journal cannot be taken up: {0}")]
    Unusable(String),
}

/// Proof that a row is on the disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableRow {
    /// How many rows the file holds, this one included.
    pub rows: usize,
}

/// The open journal of one invocation.
pub struct Journal {
    file: File,
    path: PathBuf,
    invocation: InvocationId,
    tracker: Tracker,
    rows: usize,
    closed: bool,
}

/// The file's name for an invocation.
#[must_use]
pub fn file_name(invocation: InvocationId) -> String {
    format!("{}.{EXTENSION}", hex::encode(invocation.0))
}

fn open(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_WRITE_THROUGH);
    if create {
        options.create_new(true);
    }
    options.open(path)
}

impl Journal {
    /// Makes the journal of an invocation in the directory. The file must not exist.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be made.
    pub fn create(dir: &Path, invocation: InvocationId) -> Result<Journal, JournalError> {
        let path = dir.join(file_name(invocation));
        let file = open(&path, true)?;
        Ok(Journal {
            file,
            path,
            invocation,
            tracker: Tracker::new(),
            rows: 0,
            closed: false,
        })
    }

    /// Takes up the journal of an invocation that did not end, cutting away a torn tail so that the
    /// rows that follow are read back, and returns what the file said.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, holds no row, or is damaged or out of order.
    pub fn resume(
        dir: &Path,
        invocation: InvocationId,
        current_boot: &str,
    ) -> Result<(Journal, Invocation), JournalError> {
        let path = dir.join(file_name(invocation));
        let bytes = std::fs::read(&path)?;
        let id = hex::encode(invocation.0);
        let found = match replay::read_file(&id, &bytes, current_boot) {
            Reading::MadeNothing => {
                return Err(JournalError::Unusable("the file holds no row".to_owned()));
            }
            Reading::Invocation(found) => *found,
        };
        if found.standing == Standing::Unreadable {
            return Err(JournalError::Unusable(
                found
                    .damage
                    .clone()
                    .unwrap_or_else(|| "the file is damaged".to_owned()),
            ));
        }
        let mut file = open(&path, false)?;
        file.set_len(found.valid_len as u64)?;
        file.seek(SeekFrom::End(0))?;
        file.sync_all()?;
        let journal = Journal {
            file,
            path,
            invocation,
            tracker: found.tracker.clone(),
            rows: found.rows.len(),
            closed: false,
        };
        Ok((journal, found))
    }

    /// The file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What the rows written so far say.
    #[must_use]
    pub fn tracker(&self) -> &Tracker {
        &self.tracker
    }

    /// Writes a row through to the disk. The step the row protects comes after this returns.
    ///
    /// # Errors
    ///
    /// Returns an error, and writes nothing, when the row may not come now; and an error, with the
    /// journal closed, when the write or the flush fails.
    pub fn append(&mut self, row: &Row) -> Result<DurableRow, JournalError> {
        if self.closed {
            return Err(JournalError::Closed);
        }
        if let Row::Begin { invocation, .. } = row
            && *invocation != hex::encode(self.invocation.0)
        {
            return Err(OrderError("the row begins another invocation".to_owned()).into());
        }
        let mut next = self.tracker.clone();
        next.apply(row)?;
        let framed = framing::encode(&row.to_bytes())?;
        if let Err(error) = self
            .file
            .write_all(&framed)
            .and_then(|()| self.file.sync_all())
        {
            self.closed = true;
            return Err(error.into());
        }
        self.tracker = next;
        self.rows += 1;
        Ok(DurableRow { rows: self.rows })
    }

    /// Writes the primary child's row and, once it is durable, makes the leave to resume that child.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is not durable; no leave is made then.
    pub fn append_process_started(
        &mut self,
        child: &SuspendedChild,
    ) -> Result<ResumePermit, JournalError> {
        self.append(&Row::ProcessStarted {
            pid: child.pid,
            creation_time: child.creation_time,
        })?;
        Ok(ResumePermit::for_invocation(self.invocation, child))
    }
}

impl RootRows for Journal {
    fn intent(&mut self, path: &Path) -> Result<(), RootError> {
        self.append(&Row::RootIntent {
            path: path.display().to_string(),
        })
        .map(|_| ())
        .map_err(|error| RootError::Journal(error.to_string()))
    }

    fn made(&mut self, path: &Path, key: &FileKey) -> Result<(), RootError> {
        self.append(&Row::RootMade {
            path: path.display().to_string(),
            key: *key,
        })
        .map(|_| ())
        .map_err(|error| RootError::Journal(error.to_string()))
    }

    fn removed(&mut self) -> Result<(), RootError> {
        self.append(&Row::RootRemoved)
            .map(|_| ())
            .map_err(|error| RootError::Journal(error.to_string()))
    }
}

/// Reads every journal in the directory and returns the invocations that did not finish: those that
/// did not end, those that ended with a leftover that holds the tree's slot, those whose end is not
/// proved and those whose file cannot be read. A file whose first row is missing made nothing and is
/// left out. `current_boot` is the boot marker now, which each invocation's own is compared with.
///
/// # Errors
///
/// Returns an error when the directory cannot be listed or a file cannot be read.
pub fn replay(dir: &Path, current_boot: &str) -> Result<Vec<Invocation>, JournalError> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let bytes = std::fs::read(&path)?;
        if let Reading::Invocation(invocation) = replay::read_file(id, &bytes, current_boot)
            && invocation.standing != Standing::Finished
        {
            found.push(*invocation);
        }
    }
    found.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(found)
}
