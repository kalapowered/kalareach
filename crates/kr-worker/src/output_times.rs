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
//! The index is bounded by rows and not by output: [`MAX_ROWS`]. An interval grows longer as the
//! index fills, so a program that prints a little all the time reaches the bound after weeks and
//! not after a day. When it is full, output that continues the last interval extends it, unless the
//! clock stepped back or its standing changed since that interval opened, and other output has no
//! time. An extended interval's time is earlier than the truth, the safe direction.
//!
//! # What proven means here
//!
//! A reading is proven when the worker's time contract trusts the wall clock, which it stops doing
//! when the clock steps back. A step forward is not one of those, and it makes every later reading
//! later than the truth, the direction a reader deciding what a person may be shown cannot accept.
//! So the index watches the wall clock against the host's continuous clock (which counts a
//! suspension, as the wall clock does) between two writes of output, and a reading taken after the
//! wall clock gained more than [`FORWARD_STEP`] on the continuous one, and every reading after it,
//! is recorded as unproven.
//!
//! The comparison needs the two clocks read as one moment. A host suspended between the two reads
//! of one sample would show the next sample a step that did not happen, so the caller reads the
//! continuous clock on both sides of the wall clock ([`read_together`]), and a sample whose reads
//! are far apart is noted as unproven without being compared ([`TimeIndex::note_unpaired`]). The
//! next sample is compared with the last that was read together, over a stretch both clocks counted
//! alike.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

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

/// How many rows the index holds before every limit on an interval doubles ([`SPLIT_BYTES`],
/// [`SPLIT_AFTER`] and [`SPLIT_ALWAYS_AFTER`]): at 30,000 rows an interval lasts eight times as long
/// as the first, and holds eight times the bytes before it may close. A program that prints
/// steadily then keeps its output's times for the seven days output is retained for, inside
/// [`MAX_ROWS`], at any rate: 40 bytes a second reaches 50,000 rows in a week, and a faster writer
/// is held to a shorter retention by the session's own byte cap.
const ROWS_PER_STRETCH: usize = 10_000;

/// How far the wall clock may gain on the continuous clock between two writes of output, beyond the
/// rate the host's time service may adjust them by ([`kr_ipc::clock::RATE_ALLOWANCE_PPM`]), before
/// the wall clock is taken to have stepped forward.
pub const FORWARD_STEP: Duration = Duration::from_secs(2);

/// How far apart the continuous clock may read on the two sides of a wall-clock reading for the two
/// to be taken as read at one moment. A pause of a running thread is shorter than this, and a
/// suspension of the host is longer.
pub const READ_TOGETHER_WITHIN: Duration = Duration::from_secs(1);

/// The most rows one answer carries.
pub const MAX_ANSWER_ROWS: usize = 2048;

/// Whether the continuous clock, read now, is within [`READ_TOGETHER_WITHIN`] of `before_ms`, its
/// reading from before a wall-clock reading was taken: no suspension of the host came between that
/// reading and this one.
#[must_use]
pub fn read_together(before_ms: u64) -> bool {
    kr_ipc::clock::boot_elapsed_ms().saturating_sub(before_ms)
        <= u64::try_from(READ_TOGETHER_WITHIN.as_millis()).unwrap_or(u64::MAX)
}

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

/// The interval being extended, and the reading of the continuous clock it was opened at.
#[derive(Debug)]
struct Open {
    mark: Mark,
    since_ms: u64,
}

#[derive(Debug, Default)]
struct State {
    open: Option<Open>,
    /// Closed intervals the file has not been given.
    closed: Vec<Mark>,
    /// Closed intervals a write has taken and has not finished with: they are in no list and not
    /// yet in the file, and still count against the bound.
    in_flight: usize,
    /// The reading of the wall clock and of the continuous clock at the last output.
    last: Option<(u64, u64)>,
    /// Whether the wall clock has been seen to step forward since this index began.
    stepped_forward: bool,
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
        self.note_at(start, len, now_ms, proven, kr_ipc::clock::boot_elapsed_ms());
    }

    /// Notes output as [`Self::note`] does, for a wall-clock reading that was not read together with
    /// the continuous clock ([`read_together`]) because the host was suspended between the two.
    ///
    /// The reading is a lower bound all the same, and it is recorded unproven: the host cannot say
    /// that the wall clock had not stepped forward at that moment. It is not compared with the last
    /// reading and does not become the last, so a suspension is not read, at the next output, as a
    /// step of the wall clock.
    pub fn note_unpaired(&self, start: u64, len: u64, now_ms: u64) {
        self.note_read(
            start,
            len,
            now_ms,
            false,
            kr_ipc::clock::boot_elapsed_ms(),
            false,
        );
    }

    /// [`Self::note`] with the reading of the continuous clock the output was written at.
    fn note_at(&self, start: u64, len: u64, now_ms: u64, proven: bool, boot_ms: u64) {
        self.note_read(start, len, now_ms, proven, boot_ms, true);
    }

    /// Notes output read at `now_ms` on the wall clock and `boot_ms` on the continuous one, which
    /// `paired` says were read as one moment.
    fn note_read(
        &self,
        start: u64,
        len: u64,
        now_ms: u64,
        proven: bool,
        boot_ms: u64,
        paired: bool,
    ) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        let mut state = locked(&self.inner.state);
        // A wall clock that has gained on the continuous one is taken to have stepped forward, and
        // nothing after it is proven: every later reading is late by the step.
        if paired {
            if let Some((wall, boot)) = state.last {
                let boot_gain = boot_ms.saturating_sub(boot);
                let slack = u64::try_from(FORWARD_STEP.as_millis())
                    .unwrap_or(u64::MAX)
                    .saturating_add(
                        boot_gain.saturating_mul(kr_ipc::clock::RATE_ALLOWANCE_PPM) / 1_000_000,
                    );
                if now_ms.saturating_sub(wall) > boot_gain.saturating_add(slack) {
                    state.stepped_forward = true;
                }
            }
            state.last = Some((now_ms, boot_ms));
        }
        let proven = proven && paired && !state.stepped_forward;
        let held = state.rows + state.closed.len() + state.in_flight;
        let full = held + 1 >= MAX_ROWS;
        // Every limit on an interval doubles for each `ROWS_PER_STRETCH` rows held.
        let stretch: u64 = 1 << (held / ROWS_PER_STRETCH).min(10);
        if let Some(open) = state.open.as_mut() {
            let contiguous = open.mark.end == start;
            let age = boot_ms.saturating_sub(open.since_ms);
            let millis = |limit: Duration| {
                u64::try_from(limit.as_millis())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(stretch)
            };
            // A wall clock that stepped back, or one whose standing changed, closes the interval:
            // the new time is not a continuation of the old one, and no bound lets it be.
            let not_a_continuation = now_ms < open.mark.at_ms || open.mark.proven != proven;
            let lasted = age >= millis(SPLIT_ALWAYS_AFTER)
                || (age >= millis(SPLIT_AFTER)
                    && open.mark.end - open.mark.start >= SPLIT_BYTES.saturating_mul(stretch));
            if contiguous && !not_a_continuation && (!lasted || full) {
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
            since_ms: boot_ms,
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
            let closed = std::mem::take(&mut state.closed);
            state.in_flight = closed.len();
            (
                closed,
                state.open.as_ref().map(|open| open.mark),
                state.prune_below,
                !state.pruned && state.prune_below > 0,
            )
        };
        if closed.is_empty() && open.is_none() && !prune_owed {
            locked(&self.inner.state).in_flight = 0;
            return Ok(());
        }
        let written = write(
            &self.inner.path,
            closed.iter().chain(open.as_ref()),
            prune_owed.then_some(prune),
        );
        let mut state = locked(&self.inner.state);
        state.in_flight = 0;
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
                // noted. It cannot grow past the bound, because what was in flight counted
                // against it all the while.
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
    /// are a record of it. It waits for a write that is in progress. What it has seen of the clock
    /// is not a record of the output, and it keeps it: a wall clock that stepped forward is still
    /// ahead when output is retained again.
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
            state.in_flight = 0;
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
            beside(&self.inner.path, MAKING),
            beside(&beside(&self.inner.path, MAKING), "-journal"),
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

/// The suffix of the file an index is built in before it takes its name.
const MAKING: &str = ".new";

/// Removes what a worker killed part way through making the index file at `path` left: the file it
/// was building beside the name, and the journal SQLite keeps for it.
///
/// The file with the name is never one of these, and nothing else names them. A worker that makes
/// the index again starts over, and the collection of a closed session whose worker never did
/// removes them here.
///
/// # Errors
///
/// Returns what could not be removed.
pub fn remove_unfinished(path: &Path) -> Result<(), String> {
    let building = beside(path, MAKING);
    for left in [building.clone(), beside(&building, "-journal")] {
        match std::fs::remove_file(&left) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", left.display())),
        }
    }
    Ok(())
}

/// Makes the index file at `path` whole: its directory, and the file with its schema, built beside
/// the name and moved to it, so that a file with the name has a version in it and is never half
/// made. A worker killed part way leaves the file it was building, which the next one starts over.
fn make(path: &Path) -> Result<(), String> {
    if let Some(directory) = path.parent()
        && !directory.exists()
    {
        kr_ipc::paths::create_private_directory(directory)
            .map_err(|error| format!("the index directory could not be made: {error}"))?;
    }
    remove_unfinished(path)?;
    let building = beside(path, MAKING);
    {
        let connection = kr_flush::release::open_connection(&building, None)
            .map_err(|error| describe(&error))?;
        // Set before anything is written, so a file that is made small gives back what rows it
        // loses.
        connection
            .execute_batch(
                "PRAGMA auto_vacuum = FULL;
                 CREATE TABLE times_schema (version INTEGER NOT NULL);
                 CREATE TABLE marks (
                     start INTEGER PRIMARY KEY,
                     end INTEGER NOT NULL,
                     at_ms INTEGER NOT NULL,
                     proven INTEGER NOT NULL
                 ) WITHOUT ROWID;",
            )
            .map_err(|error| describe(&error))?;
        connection
            .execute("INSERT INTO times_schema (version) VALUES (?1)", [VERSION])
            .map_err(|error| describe(&error))?;
    }
    std::fs::rename(&building, path).map_err(|error| {
        let _ = std::fs::remove_file(&building);
        format!("the index could not be put in place: {error}")
    })
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
    if !rows.is_empty() && !path.exists() {
        make(path)?;
    }
    let mut connection = match kr_flush::release::open_connection(
        path,
        Some(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX),
    ) {
        Ok(connection) => connection,
        // Nothing to write and no file: nothing to remove rows from.
        Err(rusqlite::Error::SqliteFailure(failure, _))
            if failure.code == rusqlite::ErrorCode::CannotOpen && !path.exists() =>
        {
            return Ok(0);
        }
        Err(error) => return Err(describe(&error)),
    };
    connection
        .busy_timeout(kr_flush::release::PATIENCE)
        .map_err(|error| describe(&error))?;
    connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| describe(&error))?;
    connection
        .execute_batch("PRAGMA synchronous = NORMAL;")
        .map_err(|error| describe(&error))?;
    let transaction = connection.transaction().map_err(|error| describe(&error))?;
    let recorded: Option<i64> = transaction
        .query_row("SELECT version FROM times_schema", [], |row| row.get(0))
        .optional()
        .map_err(|error| describe(&error))?;
    match recorded {
        Some(VERSION) => {}
        Some(other) => {
            return Err(format!(
                "the index records version {other}, and this release writes version {VERSION}"
            ));
        }
        None => {
            return Err(
                "the index file holds no schema, so it is not one this release wrote".into(),
            );
        }
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

    /// An index over a file in a directory of its own, which goes when the third value is dropped.
    fn index(name: &str) -> (TimeIndex, PathBuf, tempfile::TempDir) {
        let directory = tempfile::Builder::new()
            .prefix(&format!("kr-times-{name}-"))
            .tempdir()
            .expect("a directory for the state");
        let path = directory.path().join("output-times").join("session.sqlite");
        (TimeIndex::new(path.clone()), path, directory)
    }

    #[test]
    fn output_that_continues_an_interval_extends_it_and_is_read_back_clipped() {
        let (index, path, _kept) = index("continue");
        index.note_at(0, 10, 1_000, true, 5_000);
        index.note_at(10, 10, 1_001, true, 5_001);
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
        let (index, path, _kept) = index("gap");
        index.note(0, 4, 1_000, true);
        index.note(100, 4, 2_000, true);
        index.flush().expect("writes");
        let read = read(&path, 0, 200, 16).expect("reads");
        let spans: Vec<_> = read.marks.iter().map(|m| (m.from, m.to, m.at_ms)).collect();
        assert_eq!(spans, vec![(0, 4, 1_000), (100, 104, 2_000)]);
    }

    #[test]
    fn a_clock_that_steps_back_or_changes_its_standing_opens_a_new_interval() {
        let (index, path, _kept) = index("step");
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
        let (index, path, _kept) = index("prune");
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
        let (index, path, _kept) = index("pages");
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
        let (index, path, _kept) = index("none");
        index.flush().expect("nothing to write");
        assert_eq!(read(&path, 0, 10, 4), Err(Unavailable::Missing));
    }

    #[test]
    fn discarding_removes_the_file_and_what_was_noted() {
        let (index, path, _kept) = index("discard");
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
        let (index, path, _kept) = index("retry");
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
    fn many_one_byte_appends_in_one_burst_make_one_row() {
        let (index, path, _kept) = index("bound");
        for byte in 0..10_000_u64 {
            index.note_at(byte, 1, 1_000, true, 5_000);
        }
        index.flush().expect("writes");
        let read = read(&path, 0, 10_000, MAX_ANSWER_ROWS).expect("reads");
        assert_eq!(read.marks.len(), 1);
    }

    #[test]
    fn an_interval_lasts_longer_as_the_index_fills() {
        let (empty, _, _kept) = index("stretch");
        empty.note_at(0, 10, 1_000, true, 5_000);
        empty.note_at(10, 10, 3_500, true, 7_500);
        assert_eq!(locked(&empty.inner.state).closed.len(), 1, "an empty index");

        let (fuller, _, _kept) = index("stretch-full");
        locked(&fuller.inner.state).rows = ROWS_PER_STRETCH;
        fuller.note_at(0, 10, 1_000, true, 5_000);
        fuller.note_at(10, 10, 4_000, true, 8_000);
        assert!(
            locked(&fuller.inner.state).closed.is_empty(),
            "a fuller index keeps an interval for longer"
        );
        fuller.note_at(20, 10, 5_500, true, 9_500);
        assert_eq!(locked(&fuller.inner.state).closed.len(), 1);

        // The bytes an interval holds before it may close are stretched as well.
        let (bytes, _, _kept) = index("stretch-bytes");
        locked(&bytes.inner.state).rows = ROWS_PER_STRETCH;
        bytes.note_at(0, SPLIT_BYTES, 1_000, true, 5_000);
        bytes.note_at(SPLIT_BYTES, 10, 1_300, true, 5_300);
        assert!(
            locked(&bytes.inner.state).closed.is_empty(),
            "256 bytes are too few for the second stretch"
        );
        // Two stretches of 256 bytes hold what the second stretch asks for, and the next output
        // opens the next interval.
        bytes.note_at(SPLIT_BYTES + 10, SPLIT_BYTES, 1_600, true, 5_600);
        assert!(locked(&bytes.inner.state).closed.is_empty());
        bytes.note_at(2 * SPLIT_BYTES + 10, 10, 1_900, true, 5_900);
        assert_eq!(locked(&bytes.inner.state).closed.len(), 1);
    }

    #[test]
    fn a_wall_clock_that_stepped_forward_makes_every_later_reading_unproven() {
        let (index, path, _kept) = index("forward");
        index.note_at(0, 4, 1_000, true, 5_000);
        // A second later by the continuous clock, an hour later by the wall clock.
        index.note_at(4, 4, 3_601_000, true, 6_000);
        // The wall clock then keeps pace with the continuous one, and is still an hour late.
        index.note_at(8, 4, 3_602_000, true, 7_000);
        index.note_at(100, 4, 3_603_000, true, 8_000);
        index.flush().expect("writes");
        let rows: Vec<_> = read(&path, 0, 200, 16)
            .expect("reads")
            .marks
            .iter()
            .map(|m| (m.from, m.to, m.proven))
            .collect();
        assert_eq!(
            rows,
            vec![(0, 4, true), (4, 12, false), (100, 104, false)],
            "what was read before the step is as it was; what follows it is not proven"
        );
    }

    #[test]
    fn privacy_mode_taking_the_record_away_does_not_forget_that_the_wall_clock_stepped() {
        let (index, path, _kept) = index("forward-privacy");
        index.note_at(0, 4, 1_000, true, 5_000);
        index.note_at(4, 4, 3_601_000, true, 6_000);
        index.discard().expect("removes the record");
        // Output is retained again, and the wall clock is still an hour ahead.
        index.note_at(100, 4, 3_602_000, true, 7_000);
        index.flush().expect("writes");
        let rows: Vec<_> = read(&path, 0, 200, 16)
            .expect("reads")
            .marks
            .iter()
            .map(|m| (m.from, m.proven))
            .collect();
        assert_eq!(rows, vec![(100, false)]);
    }

    #[test]
    fn a_steady_writer_keeps_its_times_for_as_long_as_its_output_is_kept() {
        // At each rate, two writes a second for as long as output is kept: seven days, or until the
        // session's 128 MiB cap holds, whichever is first. The index is never full, and the last
        // interval is the end of the output.
        for rate in [40_u64, 300, 4_096, 65_536] {
            let kept = (7 * 24 * 3_600).min(128 * 1024 * 1024 / rate);
            let (index, _, _kept) = index("steady");
            let mut cursor = 0;
            for half_second in 0..kept * 2 {
                let boot = 5_000 + half_second * 500;
                index.note_at(cursor, rate / 2, 1_000_000 + boot, true, boot);
                cursor += rate / 2;
            }
            let state = locked(&index.inner.state);
            assert!(
                state.closed.len() + 1 < MAX_ROWS - 1,
                "{rate} bytes a second held {} rows",
                state.closed.len()
            );
            assert_eq!(state.open.as_ref().map(|open| open.mark.end), Some(cursor));
        }
    }

    #[test]
    fn a_host_that_slept_has_not_had_its_wall_clock_stepped() {
        let (index, path, _kept) = index("slept");
        index.note_at(0, 4, 1_000, true, 5_000);
        // Eight hours asleep: the continuous clock counts them, as the wall clock does.
        let night = 8 * 3_600_000;
        index.note_at(4, 4, 1_000 + night, true, 5_000 + night);
        index.flush().expect("writes");
        let proven: Vec<_> = read(&path, 0, 200, 16)
            .expect("reads")
            .marks
            .iter()
            .map(|m| m.proven)
            .collect();
        assert_eq!(proven, vec![true, true]);
    }

    #[test]
    fn a_host_suspended_between_the_two_reads_of_one_sample_has_not_had_its_wall_clock_stepped() {
        let (index, path, _kept) = index("suspended-between");
        index.note_at(0, 4, 1_000, true, 5_000);
        // The wall clock was read, the host slept for an hour, and the continuous clock was read:
        // the two readings of this sample are an hour apart, and it is noted unpaired.
        let hour = 3_600_000;
        index.note_read(4, 4, 2_000, true, 5_000 + hour + 1_000, false);
        // The next sample is read together, after the sleep, and both clocks counted it.
        index.note_at(8, 4, 1_000 + hour + 2_000, true, 5_000 + hour + 2_000);
        index.flush().expect("writes");
        let rows: Vec<_> = read(&path, 0, 200, 16)
            .expect("reads")
            .marks
            .iter()
            .map(|m| (m.from, m.to, m.proven))
            .collect();
        assert_eq!(
            rows,
            vec![(0, 4, true), (4, 8, false), (8, 12, true)],
            "the sample that could not be read together is not proven, and the next is"
        );
    }

    #[test]
    fn a_full_index_extends_an_interval_only_while_the_clock_has_not_stepped_back_or_changed() {
        let full = || {
            let (index, path, kept) = index("full");
            index.note_at(0, 10, 5_000, true, 5_000);
            locked(&index.inner.state).rows = MAX_ROWS - 1;
            (index, path, kept)
        };

        // Longer than any interval may last at the bound, so only a full index extends it.
        let later = 5_000 + 2_000_000;
        let (index, _, _kept) = full();
        index.note_at(10, 10, later, true, later);
        assert_eq!(
            locked(&index.inner.state).open.as_ref().map(|o| o.mark.end),
            Some(20),
            "output that continues it extends it, though it has lasted long enough to close"
        );

        let (index, _, _kept) = full();
        index.note_at(10, 10, 4_000, true, 5_001);
        let state = locked(&index.inner.state);
        assert_eq!(state.closed.len(), 1, "a step back closes it");
        assert!(
            state.open.is_none(),
            "and there is no room for another: this output has no time"
        );
        drop(state);

        let (index, _, _kept) = full();
        index.note_at(10, 10, 5_001, false, 5_001);
        let state = locked(&index.inner.state);
        assert_eq!(state.closed.len(), 1, "a change of standing closes it");
        assert!(state.open.is_none());
    }

    #[test]
    fn rows_a_write_has_taken_still_count_against_the_bound() {
        let (index, _, _kept) = index("in-flight");
        {
            let mut state = locked(&index.inner.state);
            state.rows = MAX_ROWS - 3;
            state.in_flight = 2;
        }
        index.note_at(0, 10, 1_000, true, 5_000);
        assert!(
            locked(&index.inner.state).open.is_none(),
            "the rows in flight leave no room"
        );
    }

    #[test]
    fn a_file_left_half_made_by_a_worker_that_was_killed_is_started_over() {
        let (index, path, _kept) = index("killed");
        let directory = path.parent().expect("a directory").to_path_buf();
        std::fs::create_dir_all(&directory).expect("makes the directory");
        std::fs::write(beside(&path, MAKING), b"part of a database").expect("the leftover");
        index.note(0, 10, 1_000, true);
        index.flush().expect("writes");
        assert_eq!(read(&path, 0, 10, 4).expect("reads").marks.len(), 1);
        assert!(
            !beside(&path, MAKING).exists(),
            "the file that was being made is the one with the name"
        );
    }
}
