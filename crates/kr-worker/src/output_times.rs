//! When retained output was produced.
//!
//! The spool keeps the raw bytes a program wrote and a cursor for each, and no time: bytes carry
//! none. A recording of the output (an asciicast export), a reader whose rights begin at a moment,
//! and a person asking when something was printed all need the time of a cursor, so the worker
//! keeps a second record beside the spool: a list of intervals of the output's cursors, each with
//! the instant its first byte arrived.
//!
//! # What a row says
//!
//! A row is `[start, end)` of the output, the wall-clock instant the first byte of the interval was
//! written, and whether the worker could prove its wall clock at that moment. Every byte of the
//! interval was written at or after that instant, so a row is a *lower bound* on when each of its
//! bytes was produced. That is the direction a reader deciding what a person may be shown needs: a
//! byte reported earlier than it was is withheld from a reader whose rights begin later, never
//! served to one. Bytes in no row have no recorded time and are never given one.
//!
//! # How it is kept
//!
//! The output path records into memory only: an append that continues the open interval extends it,
//! and one that has lasted long enough closes it and opens the next. Nothing on that path waits for
//! a disk. The worker's maintenance pass writes the closed intervals, and the open one as far as it
//! has got, to a SQLite file of its own ([`TimeIndex::flush`]), after it has let go of the session;
//! the session's closure writes what is left. A crash loses the intervals since the last write: the
//! bytes are still in the spool and read as having no time.
//!
//! The file is `<state>/output-times/<session>.sqlite`, beside the spool and not in it. An earlier
//! release lists a spool's files and counts every one of them against its host cap, and reads the
//! spool by its own rules; it never meets this file, and the file's version is its own.
//!
//! The index is bounded by rows and not by output: [`MAX_ROWS`]. When it is full, output that
//! continues the last interval extends it (its time is then earlier than the truth, the safe
//! direction), and output after a gap has no time.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rusqlite::{OpenFlags, OptionalExtension as _, params};

/// The version of the index file this release writes and reads.
pub const VERSION: i64 = 1;

/// The most rows one session's index holds.
pub const MAX_ROWS: usize = 100_000;

/// The fewest bytes an interval holds before it may close for having lasted long enough.
pub const SPLIT_BYTES: u64 = 256;

/// How long an interval of at least [`SPLIT_BYTES`] lasts before the next output opens a new one.
pub const SPLIT_AFTER: Duration = Duration::from_millis(100);

/// How long any interval lasts before the next output opens a new one.
pub const SPLIT_ALWAYS_AFTER: Duration = Duration::from_secs(2);

/// The most rows one answer carries.
pub const MAX_ANSWER_ROWS: usize = 2048;

/// One interval of the output, and the instant its first byte was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// The first cursor of the interval.
    pub start: u64,
    /// The cursor after its last byte.
    pub end: u64,
    /// The wall-clock reading when its first byte was written, in milliseconds since the epoch.
    pub at_ms: u64,
    /// Whether the worker could prove its wall clock when it took the reading.
    pub proven: bool,
}

/// The interval being extended, and the monotonic instant it was opened at.
#[derive(Debug)]
struct Open {
    mark: Mark,
    since: Instant,
}

#[derive(Debug, Default)]
struct State {
    open: Option<Open>,
    /// Closed intervals the file has not been given.
    closed: Vec<Mark>,
    /// How many rows the file holds, as of the last write.
    rows: usize,
    /// The first cursor the file may still hold a row for.
    prune_below: u64,
    /// Whether the file has been told `prune_below` since it last moved.
    pruned: bool,
    /// Why the last write failed, until one succeeds.
    failure: Option<String>,
}

#[derive(Debug)]
struct Inner {
    path: PathBuf,
    state: Mutex<State>,
    /// Held for the whole of a write, so a discard waits for it and two writes never meet.
    writing: Mutex<()>,
}

/// One session's time index: the intervals not yet written, and the file they are written to.
///
/// A handle is cheap to clone and shared: the output path notes into it, and the maintenance pass
/// writes it with the session let go.
#[derive(Clone, Debug)]
pub struct TimeIndex {
    inner: Arc<Inner>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TimeIndex {
    /// Builds an index that writes to the file at `path`. Nothing is created until a write.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                path: path.into(),
                state: Mutex::new(State::default()),
                writing: Mutex::new(()),
            }),
        }
    }

    /// Returns the file this index writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Notes that `len` bytes of output were written at `start`, at the wall-clock reading `now_ms`.
    ///
    /// It takes a lock held for nothing else and does no I/O. `proven` is whether the worker could
    /// prove its wall clock when it took the reading.
    pub fn note(&self, start: u64, len: u64, now_ms: u64, proven: bool) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        let mut state = locked(&self.inner.state);
        let full = state.rows + state.closed.len() + 1 >= MAX_ROWS;
        if let Some(open) = state.open.as_mut() {
            let contiguous = open.mark.end == start;
            let age = open.since.elapsed();
            let split = age >= SPLIT_ALWAYS_AFTER
                || (age >= SPLIT_AFTER && open.mark.end - open.mark.start >= SPLIT_BYTES)
                // A wall clock that stepped back, or one whose standing changed, opens a new
                // interval: the new time is not a continuation of the old one.
                || now_ms < open.mark.at_ms
                || open.mark.proven != proven;
            if contiguous && (!split || full) {
                open.mark.end = end;
                return;
            }
            if let Some(closed) = state.open.take() {
                state.closed.push(closed.mark);
            }
        }
        if full {
            // No room for another row: this output has no recorded time.
            return;
        }
        state.open = Some(Open {
            mark: Mark {
                start,
                end,
                at_ms: now_ms,
                proven,
            },
            since: Instant::now(),
        });
    }

    /// Says that output before `cursor` is no longer retained, so its rows may go.
    ///
    /// Intervals wholly before it are dropped from memory now and from the file at the next write.
    pub fn forget_before(&self, cursor: u64) {
        let mut state = locked(&self.inner.state);
        if cursor > state.prune_below {
            state.prune_below = cursor;
            state.pruned = false;
        }
        state.closed.retain(|mark| mark.end > cursor);
        if state
            .open
            .as_ref()
            .is_some_and(|open| open.mark.end <= cursor)
        {
            state.open = None;
        }
    }

    /// Returns why the last write failed, when it did and none has succeeded since.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        locked(&self.inner.state).failure.clone()
    }

    /// Writes the closed intervals and the open one as far as it has got, and removes the rows of
    /// output that is no longer retained.
    ///
    /// It does I/O, and takes no lock the output path takes while it does: the intervals are taken
    /// out of memory first and put back if the write fails, to be written by the next. Several
    /// callers are taken one at a time.
    ///
    /// # Errors
    ///
    /// Returns why the file could not be written. The index goes on; the next write tries again.
    pub fn flush(&self) -> Result<(), String> {
        let _writing = locked(&self.inner.writing);
        let (closed, open, prune, prune_owed) = {
            let mut state = locked(&self.inner.state);
            (
                std::mem::take(&mut state.closed),
                state.open.as_ref().map(|open| open.mark),
                state.prune_below,
                !state.pruned && state.prune_below > 0,
            )
        };
        if closed.is_empty() && open.is_none() && !prune_owed {
            return Ok(());
        }
        let written = write(
            &self.inner.path,
            closed.iter().chain(open.as_ref()),
            prune_owed.then_some(prune),
        );
        let mut state = locked(&self.inner.state);
        match written {
            Ok(rows) => {
                state.rows = rows;
                state.failure = None;
                if prune_owed && state.prune_below == prune {
                    state.pruned = true;
                }
                Ok(())
            }
            Err(reason) => {
                // What was taken goes back in front of what has come since, in the order it was
                // noted. It cannot grow past the rows the index holds, because a full index
                // notes nothing more.
                let mut restored = closed;
                restored.append(&mut state.closed);
                state.closed = restored;
                state.failure = Some(reason.clone());
                Err(reason)
            }
        }
    }

    /// Forgets every interval and removes the file and the files SQLite keeps beside it.
    ///
    /// Privacy mode's removal of retained output reaches this: the instants output was produced at
    /// are a record of it. It waits for a write that is in progress.
    ///
    /// # Errors
    ///
    /// Returns what could not be removed.
    pub fn discard(&self) -> Result<(), String> {
        let _writing = locked(&self.inner.writing);
        {
            let mut state = locked(&self.inner.state);
            state.open = None;
            state.closed.clear();
            state.rows = 0;
            state.prune_below = 0;
            state.pruned = false;
            state.failure = None;
        }
        let mut left = Vec::new();
        for name in [
            self.inner.path.clone(),
            beside(&self.inner.path, "-wal"),
            beside(&self.inner.path, "-shm"),
            beside(&self.inner.path, "-journal"),
        ] {
            match std::fs::remove_file(&name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => left.push(format!("{}: {error}", name.display())),
            }
        }
        if left.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "this session's output time index could not be removed: {}",
                left.join("; ")
            ))
        }
    }
}

fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn describe(error: &rusqlite::Error) -> String {
    kr_flush::release::describe(error)
}

fn cursor(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "a cursor is past what the index records".to_owned())
}

/// Writes `rows` and removes the rows before `prune`, in one transaction, and returns how many rows
/// the file holds.
///
/// The file is made when there is a row to write, and is not when there is none: a session that
/// wrote no output has no index.
fn write<'a>(
    path: &Path,
    rows: impl Iterator<Item = &'a Mark>,
    prune: Option<u64>,
) -> Result<usize, String> {
    let rows: Vec<&Mark> = rows.collect();
    let creating = !rows.is_empty();
    if creating
        && let Some(directory) = path.parent()
        && !directory.exists()
    {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("the index directory could not be made: {error}"))?;
    }
    let mut connection = if creating {
        kr_flush::release::open_connection(path, None)
    } else {
        match kr_flush::release::open_connection(
            path,
            Some(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX),
        ) {
            Ok(connection) => Ok(connection),
            // Nothing to write and no file: nothing to remove rows from.
            Err(rusqlite::Error::SqliteFailure(failure, _))
                if failure.code == rusqlite::ErrorCode::CannotOpen && !path.exists() =>
            {
                return Ok(0);
            }
            Err(error) => Err(error),
        }
    }
    .map_err(|error| describe(&error))?;
    connection
        .busy_timeout(kr_flush::release::PATIENCE)
        .map_err(|error| describe(&error))?;
    if creating {
        // Set before anything is written, so a file that is made small gives back what rows it
        // loses. It changes nothing for a file that is already there.
        connection
            .execute_batch("PRAGMA auto_vacuum = FULL;")
            .map_err(|error| describe(&error))?;
    }
    connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| describe(&error))?;
    connection
        .execute_batch("PRAGMA synchronous = NORMAL;")
        .map_err(|error| describe(&error))?;
    let transaction = connection.transaction().map_err(|error| describe(&error))?;
    let recorded = transaction
        .query_row("SELECT version FROM times_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .optional();
    match recorded {
        Ok(Some(VERSION)) => {}
        Ok(Some(other)) => {
            return Err(format!(
                "the index records version {other}, and this release writes version {VERSION}"
            ));
        }
        Ok(None) | Err(_) if creating => {
            transaction
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS times_schema (version INTEGER NOT NULL);
                     CREATE TABLE IF NOT EXISTS marks (
                         start INTEGER PRIMARY KEY,
                         end INTEGER NOT NULL,
                         at_ms INTEGER NOT NULL,
                         proven INTEGER NOT NULL
                     ) WITHOUT ROWID;",
                )
                .map_err(|error| describe(&error))?;
            let present: i64 = transaction
                .query_row("SELECT COUNT(*) FROM times_schema", [], |row| row.get(0))
                .map_err(|error| describe(&error))?;
            if present == 0 {
                transaction
                    .execute("INSERT INTO times_schema (version) VALUES (?1)", [VERSION])
                    .map_err(|error| describe(&error))?;
            }
        }
        Ok(None) => {
            return Err(
                "the index file holds no schema, so it is not one this release wrote".into(),
            );
        }
        Err(error) => return Err(describe(&error)),
    }
    {
        let mut insert = transaction
            .prepare_cached(
                "INSERT OR REPLACE INTO marks (start, end, at_ms, proven) VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|error| describe(&error))?;
        for mark in rows {
            insert
                .execute(params![
                    cursor(mark.start)?,
                    cursor(mark.end)?,
                    cursor(mark.at_ms)?,
                    i64::from(mark.proven)
                ])
                .map_err(|error| describe(&error))?;
        }
    }
    if let Some(below) = prune {
        transaction
            .execute("DELETE FROM marks WHERE end <= ?1", [cursor(below)?])
            .map_err(|error| describe(&error))?;
    }
    let held: i64 = transaction
        .query_row("SELECT COUNT(*) FROM marks", [], |row| row.get(0))
        .map_err(|error| describe(&error))?;
    transaction.commit().map_err(|error| describe(&error))?;
    Ok(usize::try_from(held).unwrap_or(usize::MAX))
}

/// One interval of a read, clipped to the range that was asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedRange {
    /// The first cursor.
    pub from: u64,
    /// The cursor after the last byte.
    pub to: u64,
    /// The wall-clock reading when the first byte of the interval was written.
    pub at_ms: u64,
    /// Whether the worker could prove its wall clock when it took the reading.
    pub proven: bool,
}

/// What a read of the index found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Times {
    /// The intervals that overlap the range, in order, clipped to it.
    pub marks: Vec<TimedRange>,
    /// Where the next read of the same range begins: the end of the last interval returned when
    /// there are more, and the end of the range when there are not.
    pub next_cursor: u64,
    /// Whether nothing is left in the range at or after `next_cursor`.
    pub complete: bool,
}

/// Why an index could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// There is no index: the session wrote its output before indexes were kept, or kept none.
    Missing,
    /// The file records a version this release does not read.
    Version(i64),
    /// The file is there and cannot be read.
    Unreadable(String),
}

impl Unavailable {
    /// Returns a sentence for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Missing => {
                "no record was kept of when this session's output was produced".to_owned()
            }
            Self::Version(found) => format!(
                "the record of when this session's output was produced is version {found}, which \
                 this release does not read"
            ),
            Self::Unreadable(why) => format!(
                "the record of when this session's output was produced could not be read: {why}"
            ),
        }
    }
}

/// Reads the intervals of the output between the cursors `from` and `to`, at most `limit` of them.
///
/// The file is opened for reading and nothing is created. A reader of a session whose worker has
/// gone reads what the worker left, including the log a crash left in it.
///
/// # Errors
///
/// Returns why the index could not be read.
pub fn read(path: &Path, from: u64, to: u64, limit: usize) -> Result<Times, Unavailable> {
    let limit = limit.clamp(1, MAX_ANSWER_ROWS);
    match path.try_exists() {
        Ok(true) => {}
        Ok(false) => return Err(Unavailable::Missing),
        Err(error) => return Err(Unavailable::Unreadable(error.to_string())),
    }
    let unreadable = |error: rusqlite::Error| Unavailable::Unreadable(describe(&error));
    let connection = kr_flush::release::open_connection(
        path,
        Some(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX),
    )
    .map_err(unreadable)?;
    connection
        .busy_timeout(kr_flush::release::PATIENCE)
        .map_err(unreadable)?;
    let version: Option<i64> = connection
        .query_row("SELECT version FROM times_schema", [], |row| row.get(0))
        .optional()
        .map_err(unreadable)?;
    match version {
        Some(VERSION) => {}
        Some(other) => return Err(Unavailable::Version(other)),
        None => {
            return Err(Unavailable::Unreadable(
                "the file holds no schema".to_owned(),
            ));
        }
    }
    if from >= to {
        return Ok(Times {
            marks: Vec::new(),
            next_cursor: to.max(from),
            complete: true,
        });
    }
    let (low, high) = (
        cursor(from).map_err(Unavailable::Unreadable)?,
        cursor(to).map_err(Unavailable::Unreadable)?,
    );
    let mut query = connection
        .prepare(
            "SELECT start, end, at_ms, proven FROM marks
              WHERE start >= COALESCE((SELECT MAX(start) FROM marks WHERE start <= ?1), 0)
                AND start < ?2 AND end > ?1
              ORDER BY start LIMIT ?3",
        )
        .map_err(unreadable)?;
    let found = query
        .query_map(
            params![low, high, i64::try_from(limit + 1).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(unreadable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(unreadable)?;
    let mut marks: Vec<TimedRange> = found
        .into_iter()
        .map(|(start, end, at_ms, proven)| TimedRange {
            from: u64::try_from(start).unwrap_or(0).max(from),
            to: u64::try_from(end).unwrap_or(0).min(to),
            at_ms: u64::try_from(at_ms).unwrap_or(0),
            proven: proven != 0,
        })
        .collect();
    let more = marks.len() > limit;
    marks.truncate(limit);
    let next_cursor = if more {
        marks.last().map_or(to, |last| last.to)
    } else {
        to
    };
    Ok(Times {
        marks,
        next_cursor,
        complete: !more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(name: &str) -> (TimeIndex, PathBuf) {
        let directory =
            std::env::temp_dir().join(format!("kr-times-{name}-{}", kr_ipc::new_uuid()));
        let path = directory.join("output-times").join("session.sqlite");
        (TimeIndex::new(path.clone()), path)
    }

    #[test]
    fn output_that_continues_an_interval_extends_it_and_is_read_back_clipped() {
        let (index, path) = index("continue");
        index.note(0, 10, 1_000, true);
        index.note(10, 10, 1_001, true);
        index.flush().expect("writes");
        let read = read(&path, 5, 15, 16).expect("reads");
        assert_eq!(
            read.marks,
            vec![TimedRange {
                from: 5,
                to: 15,
                at_ms: 1_000,
                proven: true
            }]
        );
        assert!(read.complete);
        assert_eq!(read.next_cursor, 15);
    }

    #[test]
    fn output_after_a_gap_has_a_row_of_its_own_and_the_gap_has_none() {
        let (index, path) = index("gap");
        index.note(0, 4, 1_000, true);
        index.note(100, 4, 2_000, true);
        index.flush().expect("writes");
        let read = read(&path, 0, 200, 16).expect("reads");
        let spans: Vec<_> = read.marks.iter().map(|m| (m.from, m.to, m.at_ms)).collect();
        assert_eq!(spans, vec![(0, 4, 1_000), (100, 104, 2_000)]);
    }

    #[test]
    fn a_clock_that_steps_back_or_changes_its_standing_opens_a_new_interval() {
        let (index, path) = index("step");
        index.note(0, 4, 5_000, true);
        index.note(4, 4, 4_000, true);
        index.note(8, 4, 4_001, false);
        index.flush().expect("writes");
        let read = read(&path, 0, 12, 16).expect("reads");
        let rows: Vec<_> = read
            .marks
            .iter()
            .map(|m| (m.from, m.to, m.at_ms, m.proven))
            .collect();
        assert_eq!(
            rows,
            vec![
                (0, 4, 5_000, true),
                (4, 8, 4_000, true),
                (8, 12, 4_001, false)
            ]
        );
    }

    #[test]
    fn rows_before_the_oldest_retained_cursor_are_removed_at_the_next_write() {
        let (index, path) = index("prune");
        index.note(0, 10, 1_000, true);
        index.note(20, 10, 2_000, true);
        index.flush().expect("writes");
        index.forget_before(10);
        index.flush().expect("writes");
        let read = read(&path, 0, 100, 16).expect("reads");
        let spans: Vec<_> = read.marks.iter().map(|m| (m.from, m.to)).collect();
        assert_eq!(spans, vec![(20, 30)]);
    }

    #[test]
    fn a_read_pages_by_the_limit_and_says_where_it_stopped() {
        let (index, path) = index("pages");
        for step in 0..5_u64 {
            index.note(step * 100, 10, 1_000 + step, true);
        }
        index.flush().expect("writes");
        let first = read(&path, 0, 1_000, 2).expect("reads");
        assert_eq!(first.marks.len(), 2);
        assert!(!first.complete);
        assert_eq!(first.next_cursor, 110);
        let rest = read(&path, first.next_cursor, 1_000, 16).expect("reads");
        assert!(rest.complete);
        assert_eq!(rest.marks.first().map(|m| m.from), Some(200));
    }

    #[test]
    fn a_session_with_no_output_has_no_index_and_a_read_says_so() {
        let (index, path) = index("none");
        index.flush().expect("nothing to write");
        assert_eq!(read(&path, 0, 10, 4), Err(Unavailable::Missing));
    }

    #[test]
    fn discarding_removes_the_file_and_what_was_noted() {
        let (index, path) = index("discard");
        index.note(0, 10, 1_000, true);
        index.flush().expect("writes");
        assert!(path.exists());
        index.discard().expect("removes");
        assert!(!path.exists());
        index.flush().expect("nothing is left to write");
        assert!(!path.exists());
    }

    #[test]
    fn a_failed_write_keeps_the_intervals_for_the_next() {
        let (index, path) = index("retry");
        index.note(0, 10, 1_000, true);
        // A directory where the file belongs: the write cannot be made.
        std::fs::create_dir_all(&path).expect("makes the way impassable");
        assert!(index.flush().is_err());
        assert!(index.failure().is_some());
        std::fs::remove_dir(&path).expect("clears the way");
        index.flush().expect("writes the intervals it kept");
        assert!(index.failure().is_none());
        assert_eq!(read(&path, 0, 10, 4).expect("reads").marks.len(), 1);
    }

    #[test]
    fn many_one_byte_appends_make_a_bounded_number_of_rows() {
        let (index, path) = index("bound");
        for byte in 0..10_000_u64 {
            index.note(byte, 1, 1_000, true);
        }
        index.flush().expect("writes");
        let read = read(&path, 0, 10_000, MAX_ANSWER_ROWS).expect("reads");
        // Appends in one burst continue the open interval: the monotonic clock has not run long
        // enough to close it.
        assert!(read.marks.len() < 10, "{}", read.marks.len());
    }
}
