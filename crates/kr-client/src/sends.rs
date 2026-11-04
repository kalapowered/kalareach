//! The sends of a kept answer: the action identifiers its answer went out under.
//!
//! An answer whose reply was lost may have been taken. The host knows an answer by the identifier
//! it arrived under, so a client that kept only the answer cannot ask. This record is kept beside
//! the answer, `kept-answers/<question>.send`, and names every send of that answer whose outcome
//! the client does not yet know, oldest first. A reconnect asks the host about each
//! ([`crate::answers`]).
//!
//! The record is bound to the answer it describes by the SHA-256 digest of the answer file's
//! bytes, so a record that names no answer on disk describes no row: it is ignored, and the next
//! reconcile removes it. During a replacement the record names the answer on disk and the one being
//! written, so a failure or a crash between the two renames leaves a record that still matches the
//! answer that is there.
//!
//! A release before this one lists the answers only. It replaces or removes an answer and leaves
//! the record, which names nothing on disk and is swept.

use std::path::Path;

use kr_ipc::install::Written;
use kr_protocol::ids::ActionId;
use kr_protocol::scalars::{Digest256, TimestampMs};
use serde::{Deserialize, Serialize};

use crate::answers::{AnswerError, LOCK_NAME, Result};
use crate::shown::{IoFault, Shown};

/// The extension a record of sends carries.
pub(crate) const EXTENSION: &str = "send";

/// The format of a record of sends this build writes, recorded in it as `version`.
pub const SEND_FORMAT: u32 = 1;

/// The records of sends, as a release's manifest lists them and at the format this build writes
/// them.
pub const WRITTEN: Written = Written::new("answer-sends", SEND_FORMAT as u64);

/// The most sends of one answer whose outcome is not known. A ninth is refused: nothing is sent.
pub const MOST_SENDS: usize = 8;

/// The most a record can hold, with room to spare: eight identifiers and two digests.
const RECORD_LIMIT: u64 = 16 * 1024;

/// The sends of one kept answer.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRecord {
    /// The format of the record: [`SEND_FORMAT`]. A record states it, so one that does not is
    /// damaged.
    pub version: u32,
    /// The digests of the answer file's bytes this record is valid for: the answer on disk, and
    /// during a replacement the answer being written.
    pub draft: Vec<Digest256>,
    /// The identifiers of every send of the answer not yet known settled, oldest first.
    pub sends: Vec<ActionId>,
    /// When the newest send was recorded, on this device's clock. Shown, never decided by.
    pub sent_at_ms: TimestampMs,
}

crate::debug_as_name!(SendRecord);

impl SendRecord {
    /// Whether the record's contents are ones this build wrote.
    fn well_formed(&self) -> bool {
        (1..=2).contains(&self.draft.len())
            && (1..=MOST_SENDS).contains(&self.sends.len())
            && self
                .sends
                .iter()
                .enumerate()
                .all(|(at, send)| !self.sends[..at].contains(send))
    }
}

/// A record as it was found on disk: its contents and the digest of its bytes.
pub(crate) struct Found {
    pub(crate) record: SendRecord,
    pub(crate) digest: Digest256,
}

/// The digest of a file's bytes, which is how a record names the answer it is valid for.
pub(crate) fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// A file of this store as a failure may name it: whole when this store wrote its name.
pub(crate) fn stored(path: &Path) -> Shown {
    Shown::stored(
        path,
        &[LOCK_NAME],
        &[crate::answers::EXTENSION, EXTENSION, "partial"],
    )
}

fn unreadable(path: &Path, detail: Shown) -> AnswerError {
    AnswerError::Unreadable {
        path: stored(path),
        detail,
    }
}

/// Reads the record at `path`, when there is one.
///
/// # Errors
///
/// A record that cannot be read, is not a canonical map, is of a later format or holds contents
/// this build did not write is [`AnswerError::Unreadable`]: the answer it describes is closed, not
/// guessed at.
pub(crate) fn read(path: &Path) -> Result<Option<Found>> {
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(path, RECORD_LIMIT)
        .map_err(|error| unreadable(path, Shown::ipc(&error)))?
    else {
        return Ok(None);
    };
    let record: SendRecord = kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| unreadable(path, Shown::cbor(&error)))?;
    if record.version > SEND_FORMAT {
        return Err(unreadable(
            path,
            Shown::said("it was kept by a later release of this client"),
        ));
    }
    if record.version != SEND_FORMAT || !record.well_formed() {
        return Err(unreadable(
            path,
            Shown::said("it is not a record of sends this client wrote"),
        ));
    }
    Ok(Some(Found {
        record,
        digest: digest(&bytes),
    }))
}

/// Writes `record` to `path` the way this crate writes an answer: to a new file of its own, flushed,
/// renamed over the name, and the directory flushed after.
pub(crate) fn write(
    directory: &Path,
    path: &Path,
    unique: &str,
    record: &SendRecord,
) -> Result<()> {
    let store = |error| AnswerError::Store {
        path: stored(path),
        fault: IoFault::from(error),
    };
    let bytes = kr_cbor::to_canonical_vec(record).map_err(|error| {
        AnswerError::Form(crate::shown!(
            "the record of sends cannot be kept: {}",
            Shown::cbor(&error)
        ))
    })?;
    let partial = directory.join(format!(".{unique}.partial"));
    crate::drafts::write_whole(&partial, &bytes).map_err(store)?;
    if let Err(error) = kr_flush::retry_while_held(|| std::fs::rename(&partial, path)) {
        let _ = std::fs::remove_file(&partial);
        return Err(store(error));
    }
    kr_flush::flush_directory(directory, kr_flush::NameKind::File).map_err(store)
}

/// Checks that the record at `path`, if there is one, is one this build may replace: nothing there,
/// a link or a pipe, a record of this format whatever it names, or a file that is no record of any
/// format. One of a later format, or one that cannot be read, is not replaced.
pub(crate) fn replaceable(path: &Path) -> Result<()> {
    let about = match std::fs::symlink_metadata(path) {
        Ok(about) => about,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AnswerError::Store {
                path: stored(path),
                fault: IoFault::from(error),
            });
        }
    };
    if !about.file_type().is_file() {
        return Ok(());
    }
    read(path).map(|_| ())
}

/// The points at which a test ends a write as a crash would, leaving what is on disk then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// After the record that names the answer on disk and the one being written.
    AfterCarry,
    /// After the new answer is in place, before the record that names it alone.
    AfterDraft,
    /// After the answer is removed, before its record is.
    AfterDraftRemoved,
}

#[cfg(test)]
thread_local! {
    static STOP: std::cell::Cell<Option<Stop>> = const { std::cell::Cell::new(None) };
}

/// Arms the stop for this thread: the next write that reaches it ends there.
#[cfg(test)]
pub(crate) fn stop_at(stop: Option<Stop>) {
    STOP.with(|armed| armed.set(stop));
}

/// Ends the write here, as a crash would, when a test armed this point.
#[cfg(test)]
pub(crate) fn reached(point: Stop, directory: &Path) -> Result<()> {
    if STOP.with(std::cell::Cell::get) == Some(point) {
        STOP.with(|armed| armed.set(None));
        return Err(AnswerError::Store {
            path: Shown::root(directory),
            fault: IoFault::from(std::io::Error::other("stopped here by a test")),
        });
    }
    Ok(())
}

/// A write ends nowhere but where it ends.
#[cfg(not(test))]
#[inline]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn reached(_point: Stop, _directory: &Path) -> Result<()> {
    Ok(())
}
