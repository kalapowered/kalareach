//! The environment feature store.
//!
//! Section 24 gives attention, quiet hours, escalation, review and visit acknowledgements one
//! owner: an environment feature store with per-actor revisions and consumed event cursors, from
//! which the state is reconstructed idempotently. This is that store: one file of its own, holding
//! every session's conditions and the environment's own.
//!
//! Half of what it holds is a projection of the retained events, and a replay rebuilds it. The
//! other half is not, and no replay restores it: the acknowledgements, the per-actor revisions,
//! the visits and their log views, the quiet-hours window, the identities already given to
//! announcements and revisions, the sessions whose live conditions ended with them, the records of
//! the actions performed on it, and the secret the keys are derived under are records in their own
//! right, and this is where they live.
//!
//! What it does not hold is a session's text. An item and a change keep the record their text
//! comes from, and the text is read from that record's owner when it is served.
//!
//! # What one write changes
//!
//! A change is worked out on a copy of the state, and the write that records it changes exactly the
//! rows that copy differs from the state already written, in one transaction. Opening the store is
//! the one write that replaces every row, because it is the moment the store's rows and this owner's
//! copy are first made the same. One store carries every session, so a write that replaced
//! everything would grow with every session the environment has run; one that changes what changed
//! grows with the change.
//!
//! There is still no partial write to reason about: a transaction commits all of a change or none
//! of it, and an owner that failed to write keeps the state it had, which is still what the rows
//! say.
//!
//! # What is durable, and what is re-anchored
//!
//! Every interval the engine measures is measured on the boot-scoped continuous clock, which means
//! nothing outside its own boot. So the store records two things for each of them - when an item
//! was first seen, when it was last announced, when a request became pending - the wall-clock
//! moment, which says when it happened for a person reading the record, and the anchor: the
//! continuous reading at that moment and the boot it was taken in.
//! [`crate::host::Attention::open`] re-anchors each interval from that anchor when the boot is
//! still this one, which is exact, and starts it again when it is not. A row that carries half an
//! anchor is refused rather than half measured. No interval is worked out from the wall-clock
//! moments: a clock this host trusts is still a clock somebody can set forward, and two readings
//! it vouches for are not two readings on one scale.
//!
//! # One owner
//!
//! Every write is worked out from the copy its owner has been holding, so two owners of one store
//! would each replace the other's work with a picture of the world that predates it. There is one
//! owner instead, and the claim is a **row in the store**: opening it reads that row before it
//! reads anything else and writes its own under the same transaction, so there is nothing to key
//! on but the database itself.
//!
//! A claim from a boot that has ended is taken at once, and so is one whose process the host can
//! see has gone. [`OWNER_LEASE_MS`] decides only a claim whose holder cannot be asked about: ten
//! minutes without a refresh and it is taken. A holder that is still running keeps its store
//! however long it has been idle, and the opener that finds it is told so with
//! [`Error::StoreHeld`].
//!
//! The claim is read again inside every write, under the transaction that write is made in, so an
//! owner whose store was taken while it was away replaces nothing: it is told
//! [`Error::StoreTaken`] and writes no more. Letting go removes that one row and nothing else, so
//! a claim this owner no longer holds is not one it can release.
//!
//! Two things that rests on. Nothing here takes a second handle on the file: on the Unix family,
//! closing any descriptor for a file drops every lock the process holds on it, so a handle opened
//! beside SQLite's own would release the locks another store in the same process holds on it. And
//! a file that more than one name reaches is refused with [`Error::StoreAliased`], because the
//! write-ahead log SQLite keeps beside a database is named after the name the database was opened
//! by: two processes opening one file by two names would journal it twice over, and neither would
//! see the other's claim or the other's writes. The count is of the file this store has open: on
//! Windows it is read from the handle SQLite already holds, and on the Unix family, where nothing
//! safe describes an open file, the name is described without opening it and SQLite is then asked
//! whether the file it has open is still the one that name reaches.
//!
//! # What a stored value may not do
//!
//! It may not come back as a different value. Every integer is written and read without clamping,
//! and a row this build cannot read exactly is [`Error::StoreUnreadable`] rather than a plausible
//! substitute: a current version that collapsed onto an acknowledged one would close review work
//! nobody had done.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::str::FromStr;

use kr_protocol::attention::{
    AttentionAutomationSubject, AttentionGap, AttentionKey, AttentionLevel, AttentionRouting,
    AttentionRule, AttentionSource, LogViewState, NotificationState, QuietHours, ReviewSubject,
    SemanticChangeKind,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentTurnId, CausalRootId, ChangeSetId, GrantId, QuestionId, SessionId, WorkflowId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params};

use crate::engine::{Item, ItemAck, PendingInput, Text};
use crate::error::{Error, Result, StoreFault};
use crate::event::{EventCursor, Origin};
use crate::review::{ReviewAck, Subject, subject_key};
use crate::time::{Anchor, BootMark, Elapsed, HostReading};
use crate::visit::{Change, Omitted, SessionLog, Visit};

/// The schema this build writes and reads.
///
/// A store written under any other version is refused rather than read. Two things in here are
/// derived rather than stored on their own - an item's key, and the order a review page continues
/// by - so a row written under a different derivation would be read under a name that does not
/// describe it, which is worse than not reading it at all. Every row also has to carry the anchor
/// each of its intervals is measured from, and a row that predates those columns carries none.
pub const SCHEMA_VERSION: i64 = 9;

/// How long a write waits for another holder of the same file before it is refused.
pub const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Everything the feature store holds.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StoredState {
    /// The inbox.
    pub(crate) items: Vec<Item>,
    /// Each actor's acknowledgements of items.
    pub(crate) item_acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    /// Each actor's acknowledgement revision.
    pub(crate) revisions: BTreeMap<ActorId, u64>,
    /// The highest sequence consumed from each origin's sources.
    pub(crate) consumed: BTreeMap<(Origin, AttentionSource), u64>,
    /// The ranges of retained events the host can no longer read.
    pub(crate) gaps: Vec<AttentionGap>,
    /// How many items the host has let go of to stay inside its bound.
    pub(crate) dropped: u64,
    /// The secret this store derives its item keys under.
    ///
    /// It is generated once, when a store first has state to write, and read back with the rest.
    /// A store that has never been written gives a fresh one, which is right: it has no keys.
    pub(crate) keys: crate::key::KeySecret,
    /// The highest identity this store has given an announcement.
    ///
    /// It only goes forward, and it outlives the item whose decision it named, so an identity a
    /// delivery consumer recorded never comes back attached to a later decision.
    pub(crate) next_announcement: u64,
    /// The highest revision this store has given an item.
    ///
    /// It only goes forward for the same reason: an acknowledgement recorded at a revision must
    /// never cover a later occurrence that was given the same number.
    pub(crate) next_revision: u64,
    /// The sessions whose live conditions ended with their closure.
    pub(crate) finalised: BTreeSet<SessionId>,
    /// The questions waiting for an answer.
    pub(crate) pending_inputs: BTreeMap<QuestionId, PendingInput>,
    /// The configured quiet-hours window.
    pub(crate) quiet: Option<QuietHours>,
    /// Each review subject at the version the host holds.
    pub(crate) subjects: BTreeMap<String, Subject>,
    /// Each actor's review acknowledgements.
    pub(crate) review_acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>>,
    /// Each session's change log and the visits into it.
    pub(crate) sessions: BTreeMap<SessionId, SessionLog>,
}

/// One action this store performed, recorded in the transaction that performed it.
///
/// A mutation carries an identity its caller chose, and section 9 answers an exact repeat of it
/// from what was recorded rather than by performing it again, and refuses a different request that
/// reuses it. The record is written with the effect, so there is never an effect without a record
/// or a record of an effect that did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRecord {
    /// The verified actor whose action it was.
    pub actor: ActorId,
    /// The identity the actor gave it.
    pub action_id: String,
    /// The method it performed.
    pub method: String,
    /// A digest of the request, which is what tells an exact repeat from a reuse.
    pub digest: Vec<u8>,
    /// What it answered, as its caller encoded it.
    pub answer: Vec<u8>,
    /// When it was recorded, on the wall clock.
    pub recorded_at_ms: u64,
}

/// The environment feature store.
///
/// It is the crate's own: [`crate::Attention`] is the one writer, because a write is only correct
/// under a claim this crate takes and refreshes, and a caller that could write around it could
/// replace an owner's committed work with a state from before it.
#[derive(Debug)]
pub(crate) struct Store {
    connection: Connection,
}

/// What one process must say to own a store, and how long that claim stands unrefreshed.
///
/// The claim is a row in the store itself, so every name for one database reaches one claim by
/// construction: there is nothing to key on but the database. It carries the process that made it,
/// the boot that process is running in, and the continuous reading it was last refreshed at, which
/// is the only clock an interval may be measured on.
///
/// A claim from another boot is stale by definition: that boot has ended and so has its process.
/// A claim from this boot is weighed on what the host can see of the process that made it: one
/// that has gone is stale at once, one that is running holds its store, and one the host cannot
/// ask about stands until its lease runs out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    /// What tells this claim apart from every other, including another in the same process.
    ///
    /// A process identifier cannot do it: two owners inside one process share one, and a process
    /// that died and whose number was given to another is not the owner that number names. This is
    /// random, and one value holds one of them for its life.
    pub(crate) claim: u64,
    /// The process that holds the store, as the kernel described it when the claim was made.
    ///
    /// The number alone would name whoever holds it now, which after a crash is an unrelated
    /// program. The start value is what says this is the same process, and the pair is what the
    /// host asks about.
    pub(crate) process: ProcessStartIdentity,
    /// The boot that process is running in.
    pub(crate) boot: BootMark,
    /// The continuous reading the claim was last refreshed at, within that boot.
    pub(crate) refreshed_ms: u64,
}

/// What the host can see of the process that made a claim.
///
/// The store holds no platform code of its own - it is a state machine over typed events - so the
/// host that opens it answers this, and the store decides what the answer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    /// That exact process is running.
    Running,
    /// It has gone, or its number now belongs to a different process.
    Ended,
    /// The platform would not say, so neither answer is established.
    ///
    /// This is not "gone". An opener that read a refused or failed query as death would take a
    /// store out from under a process that was still writing to it.
    Unknown,
}

/// Who is opening a store, and what it can find out about a claim already on it.
pub struct Claimant<'a> {
    process: ProcessStartIdentity,
    liveness: &'a dyn Fn(&ProcessStartIdentity) -> Liveness,
}

impl<'a> Claimant<'a> {
    /// Names the opening process and how a claim it finds is asked about.
    ///
    /// `liveness` is asked only about a claim made in this same boot, because a claim from any
    /// other boot is stale whatever a process of that number is doing now.
    #[must_use]
    pub fn new(
        process: ProcessStartIdentity,
        liveness: &'a dyn Fn(&ProcessStartIdentity) -> Liveness,
    ) -> Self {
        Self { process, liveness }
    }

    /// Returns the opening process's identity.
    #[must_use]
    pub const fn process(&self) -> &ProcessStartIdentity {
        &self.process
    }

    /// Returns what the host can see of the process `held` names.
    #[must_use]
    pub fn liveness_of(&self, held: &ProcessStartIdentity) -> Liveness {
        (self.liveness)(held)
    }
}

impl core::fmt::Debug for Claimant<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Claimant")
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

/// How long a claim the host cannot ask about stands before another opener may take it.
///
/// Ten minutes against a maintenance loop that writes every minute. It decides nothing about a
/// claim whose process the host can see: one that has gone is taken at once, however recently it
/// wrote, and one that is running keeps its store however long it has been idle. This is for the
/// claim in between, where the platform would not answer.
pub const OWNER_LEASE_MS: u64 = 10 * 60_000;

impl Owner {
    /// Returns `process`'s claim at this reading.
    #[must_use]
    pub(crate) const fn here(
        claim: u64,
        process: ProcessStartIdentity,
        reading: HostReading,
    ) -> Self {
        Self {
            claim,
            process,
            boot: reading.boot,
            refreshed_ms: reading.continuous_ms,
        }
    }

    /// Returns a claim drawn at random.
    ///
    /// Sixty-three bits of it: the store writes an integer it can read back exactly, so the top
    /// bit is dropped rather than stored as a value that would come back negative. Every one of
    /// the sixty-three is random - the fixed version and variant bits of the identifier they are
    /// drawn from are left out.
    ///
    /// **This is an assumption, not a proof.** Two owners that drew the same value would each read
    /// the other's row as its own: the second would open a store the first is holding, and both
    /// would pass the check every write makes. Nothing here can rule that out; what it rests on is
    /// sixty-three bits of a random draw, against the handful of owners one host's stores ever
    /// have.
    #[must_use]
    pub(crate) fn fresh_claim() -> u64 {
        // Bytes six and eight of a version-four identifier carry its version and variant, which
        // are the same in every one of them. These eight do not.
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let drawn = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[7], bytes[9],
        ]);
        drawn >> 1
    }

    /// Whether this claim still stands against an opener whose own claim is `claim`.
    ///
    /// A claim from a boot that has ended is not standing: that boot's processes are gone with it.
    /// One from this boot is put to `liveness`, which is asked at most once: a process that has
    /// gone leaves nothing standing however recently it wrote, one that is running holds its store
    /// however long it has been idle, and one the host cannot ask about stands until
    /// [`OWNER_LEASE_MS`] has run since its last refresh.
    #[must_use]
    pub(crate) fn stands_against(
        &self,
        claim: u64,
        reading: HostReading,
        liveness: impl FnOnce(&ProcessStartIdentity) -> Liveness,
    ) -> bool {
        if self.claim == claim || self.boot != reading.boot {
            return false;
        }
        match liveness(&self.process) {
            Liveness::Running => true,
            Liveness::Ended => false,
            Liveness::Unknown => {
                reading.continuous_ms.saturating_sub(self.refreshed_ms) < OWNER_LEASE_MS
            }
        }
    }
}

/// How a store is opened: a file, never a URI.
///
/// SQLite reads a name beginning `file:` as a URI, and `:memory:` as a database of its own, so the
/// path is resolved before it is handed over and the flags leave URI interpretation out. Neither
/// is what names the owner - the row in the database is - but a string that opened a different
/// file would make a second database rather than a second owner of one.
const FILE_ONLY: rusqlite::OpenFlags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(rusqlite::OpenFlags::SQLITE_OPEN_CREATE)
    .union(rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Returns a path SQLite can be given, resolved and absolute, for a file that may not exist yet.
fn resolve(path: &Path) -> Result<std::path::PathBuf> {
    let unavailable = |error: &dyn core::fmt::Display| Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!("{} cannot be resolved: {error}", path.display()),
    };
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return Ok(resolved);
    }
    let name = path.file_name().ok_or_else(|| Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!("{} names no feature store", path.display()),
    })?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(std::fs::canonicalize(directory)
        .map_err(|error| unavailable(&error))?
        .join(name))
}

/// Refuses a database file that more than one name reaches.
///
/// SQLite names the write-ahead log it keeps beside a database, and the shared memory both are
/// coordinated through, after the name the database was opened by. Two hard links to one file are
/// two names, so two processes opening it by one each would journal the same file twice over:
/// neither would see the other's claim, neither would see the other's writes, and the file would
/// be the loser. A symbolic link is a different thing and is admitted: it is resolved before
/// SQLite is given the path, so every symbolic link to a store reaches the one name it has.
///
/// The count is of **the file SQLite has open**, not of whatever a name reaches now. On the Unix
/// family that takes two answers, because nothing safe here describes an open file: the name is
/// described without opening it - a second descriptor would drop every lock this process holds on
/// the file, the receipt journal's and the question ledger's included - and SQLite is then asked
/// whether the file it has open is still the one that name reaches. On Windows the answer comes
/// from SQLite's own handle, so there is one answer and no name in it at all.
///
/// A platform that will not answer is refused rather than admitted: a store nobody can say is
/// singly named is one two processes may be journalling.
fn one_name(connection: &Connection, file: &Path) -> Result<()> {
    let names = link_count(connection, file)?;
    if names > 1 {
        return Err(Error::StoreAliased { names });
    }
    Ok(())
}

/// Returns how many names reach the file this connection has open.
#[cfg(unix)]
fn link_count(connection: &Connection, file: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;

    let described = std::fs::metadata(file).map_err(|error| Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!("{} cannot be described: {error}", file.display()),
    })?;
    // The count belongs to whatever that name reaches. This is what binds it to the file SQLite
    // has open: SQLite compares its own open file with the one at the name it opened, and says
    // whether they are still the same file.
    if moved(connection)? {
        return Err(Error::StoreUnavailable {
            kind: StoreFault::Other,
            detail: format!(
                "{} no longer reaches the file this store was opened on",
                file.display()
            ),
        });
    }
    Ok(described.nlink())
}

/// Asks SQLite whether the file it has open is still the one its name reaches.
#[cfg(unix)]
fn moved(connection: &Connection) -> Result<bool> {
    let mut answer: std::ffi::c_int = 0;
    let code = file_control(
        connection,
        rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
        &raw mut answer,
    )?;
    if code != rusqlite::ffi::SQLITE_OK {
        return Err(Error::StoreUnavailable {
            kind: StoreFault::Other,
            detail: format!("this store cannot say whether its file has moved ({code})"),
        });
    }
    Ok(answer != 0)
}

/// Returns how many names reach the file this connection has open.
///
/// Windows hands a file's name count out through a handle on the file, and SQLite's own handle is
/// one: this asks for that, so nothing here opens the file a second time and no name comes into
/// the answer at all.
#[cfg(windows)]
fn link_count(connection: &Connection, _file: &Path) -> Result<u64> {
    #![expect(
        unsafe_code,
        reason = "this platform describes an open file only through its handle"
    )]

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut handle: HANDLE = std::ptr::null_mut();
    let code = file_control(
        connection,
        rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
        &raw mut handle,
    )?;
    if code != rusqlite::ffi::SQLITE_OK || handle.is_null() {
        return Err(Error::StoreUnavailable {
            kind: StoreFault::Other,
            detail: format!("this store cannot describe the file it has open ({code})"),
        });
    }
    let mut described = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the call writes one structure of exactly this type through the pointer it is given,
    // and has no other effect; the pointer is to a live local of that type, and what the call did
    // not write the structure's own default left at nought. The handle is SQLite's own, open for
    // the life of this connection: this borrows it for the call and does not close it, because
    // closing it would be closing the file SQLite is working on.
    if unsafe { GetFileInformationByHandle(handle, &raw mut described) } == 0 {
        return Err(Error::StoreUnavailable {
            kind: StoreFault::Other,
            detail: "this store cannot say how many names reach the file it has open".to_owned(),
        });
    }
    Ok(u64::from(described.nNumberOfLinks))
}

/// Returns how many names reach the file this connection has open.
///
/// There is no answer on this platform, and a store nobody can say is singly named is one two
/// processes may be journalling separately, so it is refused rather than admitted.
#[cfg(not(any(unix, windows)))]
fn link_count(_connection: &Connection, file: &Path) -> Result<u64> {
    Err(Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!(
            "this host cannot say how many names reach {}, so it will not journal it",
            file.display()
        ),
    })
}

/// Asks the open database one question about the file underneath it.
///
/// One of the two places in this crate that call a library without a safe interface, the other
/// being the Windows call that reads the file's metadata from the handle this one borrows.
/// `rusqlite` offers no safe way to ask: the questions this needs answered are about the file
/// SQLite has open, and the alternative - opening the file again to look at it - is the thing that
/// must not happen, because on the Unix family closing any descriptor for a file drops every lock
/// this process holds on it.
#[cfg(any(unix, windows))]
fn file_control<T>(connection: &Connection, question: i32, answer: *mut T) -> Result<i32> {
    #![expect(
        unsafe_code,
        reason = "the file under an open database has no safe interface here"
    )]

    // SAFETY: the handle is borrowed for the call and not kept; the database it names is open for
    // the life of `connection`. The call writes one value of the type this question is defined to
    // answer with through the pointer it is given, which is to a live local of that type, and the
    // caller passes the pointer and the question together.
    Ok(unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            question,
            answer.cast(),
        )
    })
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS attention_schema (version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS attention_consumed (
        origin TEXT NOT NULL,
        source TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        PRIMARY KEY (origin, source)
    );
    CREATE TABLE IF NOT EXISTS attention_gaps (
        position INTEGER PRIMARY KEY,
        origin TEXT NOT NULL,
        source TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER
    );
    CREATE TABLE IF NOT EXISTS attention_items (
        key TEXT PRIMARY KEY,
        rule TEXT NOT NULL,
        source TEXT NOT NULL,
        origin TEXT NOT NULL,
        session_id TEXT,
        text_kind TEXT NOT NULL,
        text TEXT,
        record_origin TEXT,
        record_source TEXT,
        record_sequence INTEGER,
        grant_id TEXT,
        automation_kind TEXT,
        automation_object TEXT,
        automation_revision INTEGER,
        revision INTEGER NOT NULL,
        routing TEXT NOT NULL,
        level TEXT NOT NULL,
        steps_taken INTEGER NOT NULL,
        occurrences INTEGER NOT NULL,
        first_seen_ms INTEGER NOT NULL,
        last_seen_ms INTEGER NOT NULL,
        notification TEXT NOT NULL,
        last_notified_ms INTEGER,
        announced_boot TEXT,
        announced_continuous_ms INTEGER,
        anchor_boot TEXT,
        anchor_continuous_ms INTEGER,
        announced_level TEXT,
        announcements INTEGER NOT NULL,
        pending_handoff INTEGER,
        uncertain INTEGER NOT NULL,
        deferred INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_actors (
        actor TEXT PRIMARY KEY,
        revision INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_dropped (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        items INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_owner (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        claim INTEGER NOT NULL,
        pid INTEGER NOT NULL,
        start_source TEXT NOT NULL,
        start_value INTEGER NOT NULL,
        boot TEXT NOT NULL,
        refreshed_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_key_secret (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        secret BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_counters (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        announcements INTEGER NOT NULL,
        revisions INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_finalised (
        session_id TEXT PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS attention_item_acks (
        actor TEXT NOT NULL,
        key TEXT NOT NULL,
        revision INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, key)
    );
    CREATE TABLE IF NOT EXISTS attention_pending_inputs (
        question_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        record_origin TEXT NOT NULL,
        record_source TEXT NOT NULL,
        record_sequence INTEGER NOT NULL,
        pending_since_ms INTEGER NOT NULL,
        reminded INTEGER NOT NULL,
        anchor_boot TEXT,
        anchor_continuous_ms INTEGER
    );
    CREATE TABLE IF NOT EXISTS attention_quiet_hours (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        start_minute INTEGER NOT NULL,
        end_minute INTEGER NOT NULL,
        zone TEXT
    );
    CREATE TABLE IF NOT EXISTS attention_review_subjects (
        key TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        object TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        sequence INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_review_acks (
        actor TEXT NOT NULL,
        subject TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, subject)
    );
    CREATE TABLE IF NOT EXISTS attention_changes (
        session_id TEXT NOT NULL,
        cursor INTEGER NOT NULL,
        kind TEXT NOT NULL,
        text_kind TEXT NOT NULL,
        text TEXT,
        record_origin TEXT,
        record_source TEXT,
        record_sequence INTEGER,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (session_id, cursor)
    );
    CREATE TABLE IF NOT EXISTS attention_change_heads (
        session_id TEXT PRIMARY KEY,
        next_cursor INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_omitted (
        session_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        at_cursor INTEGER NOT NULL,
        source TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        gap_session TEXT,
        to_sequence INTEGER,
        PRIMARY KEY (session_id, position)
    );
    CREATE TABLE IF NOT EXISTS attention_visits (
        actor TEXT NOT NULL,
        session_id TEXT NOT NULL,
        cursor INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        PRIMARY KEY (actor, session_id)
    );
    CREATE TABLE IF NOT EXISTS attention_log_views (
        actor TEXT NOT NULL,
        session_id TEXT NOT NULL,
        view_id TEXT NOT NULL,
        source_offset INTEGER NOT NULL,
        filter TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (actor, session_id, view_id)
    );
    CREATE TABLE IF NOT EXISTS attention_actions (
        actor TEXT NOT NULL,
        action_id TEXT NOT NULL,
        method TEXT NOT NULL,
        digest BLOB NOT NULL,
        answer BLOB NOT NULL,
        recorded_at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, action_id)
    );
    CREATE INDEX IF NOT EXISTS attention_actions_by_age ON attention_actions (recorded_at_ms);
";

/// One table the state is written to: its name, the columns that key a row, and the rest.
struct TableDef {
    name: &'static str,
    keys: &'static [&'static str],
    values: &'static [&'static str],
}

const CONSUMED: TableDef = TableDef {
    name: "attention_consumed",
    keys: &["origin", "source"],
    values: &["sequence"],
};
// A gap is a place in a list rather than a range with an identity of its own: two ranges of one
// source can start at the same record when the first has no known end.
const GAPS: TableDef = TableDef {
    name: "attention_gaps",
    keys: &["position"],
    values: &["origin", "source", "from_sequence", "to_sequence"],
};
const ITEMS: TableDef = TableDef {
    name: "attention_items",
    keys: &["key"],
    values: &[
        "rule",
        "source",
        "origin",
        "session_id",
        "text_kind",
        "text",
        "record_origin",
        "record_source",
        "record_sequence",
        "grant_id",
        "automation_kind",
        "automation_object",
        "automation_revision",
        "revision",
        "routing",
        "level",
        "steps_taken",
        "occurrences",
        "first_seen_ms",
        "last_seen_ms",
        "notification",
        "last_notified_ms",
        "announced_boot",
        "announced_continuous_ms",
        "anchor_boot",
        "anchor_continuous_ms",
        "announced_level",
        "announcements",
        "pending_handoff",
        "uncertain",
        "deferred",
    ],
};
const ACTORS: TableDef = TableDef {
    name: "attention_actors",
    keys: &["actor"],
    values: &["revision"],
};
const DROPPED: TableDef = TableDef {
    name: "attention_dropped",
    keys: &["id"],
    values: &["items"],
};
const KEY_SECRET: TableDef = TableDef {
    name: "attention_key_secret",
    keys: &["id"],
    values: &["secret"],
};
const COUNTERS: TableDef = TableDef {
    name: "attention_counters",
    keys: &["id"],
    values: &["announcements", "revisions"],
};
const FINALISED: TableDef = TableDef {
    name: "attention_finalised",
    keys: &["session_id"],
    values: &[],
};
const ITEM_ACKS: TableDef = TableDef {
    name: "attention_item_acks",
    keys: &["actor", "key"],
    values: &["revision", "at_ms"],
};
const PENDING: TableDef = TableDef {
    name: "attention_pending_inputs",
    keys: &["question_id"],
    values: &[
        "session_id",
        "record_origin",
        "record_source",
        "record_sequence",
        "pending_since_ms",
        "reminded",
        "anchor_boot",
        "anchor_continuous_ms",
    ],
};
const QUIET: TableDef = TableDef {
    name: "attention_quiet_hours",
    keys: &["id"],
    values: &["start_minute", "end_minute", "zone"],
};
const SUBJECTS: TableDef = TableDef {
    name: "attention_review_subjects",
    keys: &["key"],
    values: &[
        "kind",
        "session_id",
        "object",
        "version",
        "at_ms",
        "sequence",
    ],
};
const REVIEW_ACKS: TableDef = TableDef {
    name: "attention_review_acks",
    keys: &["actor", "subject"],
    values: &["version", "at_ms"],
};
const CHANGES: TableDef = TableDef {
    name: "attention_changes",
    keys: &["session_id", "cursor"],
    values: &[
        "kind",
        "text_kind",
        "text",
        "record_origin",
        "record_source",
        "record_sequence",
        "at_ms",
    ],
};
const CHANGE_HEADS: TableDef = TableDef {
    name: "attention_change_heads",
    keys: &["session_id"],
    values: &["next_cursor"],
};
// As with the gaps, an omitted range is a place in the session's list.
const OMITTED: TableDef = TableDef {
    name: "attention_omitted",
    keys: &["session_id", "position"],
    values: &[
        "at_cursor",
        "source",
        "from_sequence",
        "gap_session",
        "to_sequence",
    ],
};
const VISITS: TableDef = TableDef {
    name: "attention_visits",
    keys: &["actor", "session_id"],
    values: &["cursor", "revision"],
};
const LOG_VIEWS: TableDef = TableDef {
    name: "attention_log_views",
    keys: &["actor", "session_id", "view_id"],
    values: &["source_offset", "filter", "position"],
};

/// The tables that hold the environment as a whole, in the order they are written.
const ENVIRONMENT_TABLES: &[&TableDef] = &[
    &CONSUMED,
    &GAPS,
    &ITEMS,
    &ACTORS,
    &DROPPED,
    &KEY_SECRET,
    &COUNTERS,
    &FINALISED,
    &ITEM_ACKS,
    &PENDING,
    &QUIET,
    &SUBJECTS,
    &REVIEW_ACKS,
];

/// The tables that hold one session's change log, its visits and their views.
const SESSION_TABLES: &[&TableDef] = &[&CHANGES, &CHANGE_HEADS, &OMITTED, &VISITS, &LOG_VIEWS];

/// Every table the state lives in, which the opening write replaces together and an empty store
/// holds none of.
///
/// The claim is not one of them. It says who may write the state, not what the state is, and a
/// store nobody has written yet is empty whether or not somebody is holding it open. Nor are the
/// action records: they are what the store did, not what it holds, and a store whose state is
/// replaced has still done what it did.
const STATE_TABLES: &[&str] = &[
    "attention_consumed",
    "attention_gaps",
    "attention_items",
    "attention_actors",
    "attention_dropped",
    "attention_key_secret",
    "attention_counters",
    "attention_finalised",
    "attention_item_acks",
    "attention_pending_inputs",
    "attention_quiet_hours",
    "attention_review_subjects",
    "attention_review_acks",
    "attention_changes",
    "attention_change_heads",
    "attention_omitted",
    "attention_visits",
    "attention_log_views",
];

/// One part of a row's key. A key is compared, so it holds only what compares exactly.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum KeyPart {
    Integer(i64),
    Text(String),
}

impl KeyPart {
    fn value(&self) -> Value {
        match self {
            Self::Integer(value) => Value::Integer(*value),
            Self::Text(value) => Value::Text(value.clone()),
        }
    }
}

/// One table's rows, by key.
type Rows = BTreeMap<Vec<KeyPart>, Vec<Value>>;

/// Returns the stored form of where a process start value came from.
///
/// A start value means nothing without it: one platform counts clock ticks since the boot and
/// another microseconds since the epoch, and a value read under the wrong one would say a process
/// that is running is a different process.
const fn source_text(source: ProcessStartSource) -> &'static str {
    match source {
        ProcessStartSource::LinuxProcStat => "linux_proc_stat",
        ProcessStartSource::MacosProcBsdInfo => "macos_proc_bsd_info",
        ProcessStartSource::WindowsProcessStartSeconds => "windows_process_start_seconds",
    }
}

/// Reads back what [`source_text`] wrote, and refuses anything else.
fn start_source(stored: &str) -> Result<ProcessStartSource> {
    match stored {
        "linux_proc_stat" => Ok(ProcessStartSource::LinuxProcStat),
        "macos_proc_bsd_info" => Ok(ProcessStartSource::MacosProcBsdInfo),
        "windows_process_start_seconds" => Ok(ProcessStartSource::WindowsProcessStartSeconds),
        _ => Err(unreadable("owner process start source")),
    }
}

fn unreadable(field: &'static str) -> Error {
    Error::StoreUnreadable { field }
}

/// Returns the anchor a pair of stored columns holds, or `None` when the row carries none.
///
/// A row with one half of an anchor is refused: an anchor is a continuous reading *and* the boot
/// it was taken in, and half of one would measure an interval against a clock that may have
/// restarted since.
fn anchor(
    boot: Option<&str>,
    continuous: Option<i64>,
    field: &'static str,
) -> Result<Option<Anchor>> {
    match (boot, continuous) {
        (None, None) => Ok(None),
        (Some(boot), Some(continuous)) => Ok(Some(Anchor::new(
            BootMark::from_hex(boot).ok_or_else(|| unreadable(field))?,
            as_u64(continuous, field)?,
        ))),
        _ => Err(unreadable(field)),
    }
}

/// Returns `value` as the integer SQLite stores, refusing one it cannot hold.
///
/// Clamping would be worse than refusing. A version, a cursor or an occurrence count that came
/// back as a different number would read as valid state, and a current version that collapsed onto
/// an acknowledged one would close review work nobody had done.
fn as_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| unreadable(field))
}

/// Returns a stored integer as the unsigned value it was written from, refusing a negative one.
fn as_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| unreadable(field))
}

fn as_index(value: usize, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| unreadable(field))
}

/// The stored form of an origin: the environment's own name, or the session's identifier.
const ENVIRONMENT: &str = "environment";

fn origin_text(origin: &Origin) -> String {
    match origin {
        Origin::Environment => ENVIRONMENT.to_owned(),
        Origin::Session(session_id) => session_id.to_string(),
    }
}

fn origin_from(text: &str, field: &'static str) -> Result<Origin> {
    if text == ENVIRONMENT {
        return Ok(Origin::Environment);
    }
    SessionId::from_str(text)
        .map(Origin::Session)
        .map_err(|_| unreadable(field))
}

fn integer(value: u64, field: &'static str) -> Result<Value> {
    Ok(Value::Integer(as_i64(value, field)?))
}

fn optional_integer(value: Option<u64>, field: &'static str) -> Result<Value> {
    value.map_or(Ok(Value::Null), |value| integer(value, field))
}

fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn optional_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
}

fn flag(value: bool) -> Value {
    Value::Integer(i64::from(value))
}

fn anchor_values(anchor: Option<Anchor>, field: &'static str) -> Result<[Value; 2]> {
    Ok(match anchor {
        Some(anchor) => [
            text(anchor.boot.to_hex()),
            integer(anchor.continuous_ms, field)?,
        ],
        None => [Value::Null, Value::Null],
    })
}

/// The five columns a text is stored in: its kind, the host's words, and the record it is read
/// from.
fn text_values(held: &Text) -> Result<[Value; 5]> {
    Ok(match held {
        Text::Host(words) => [
            text("host"),
            text(words.clone()),
            Value::Null,
            Value::Null,
            Value::Null,
        ],
        Text::Record(cursor) => [
            text("record"),
            Value::Null,
            text(origin_text(&cursor.origin)),
            text(cursor.source.as_str()),
            integer(cursor.sequence, "record sequence")?,
        ],
    })
}

/// Reads a text back from the five columns [`text_values`] wrote.
fn text_from(
    kind: &str,
    words: Option<String>,
    record_origin: Option<String>,
    record_source: Option<String>,
    record_sequence: Option<i64>,
) -> Result<Text> {
    match (kind, words, record_origin, record_source, record_sequence) {
        ("host", Some(words), None, None, None) => Ok(Text::Host(words)),
        ("record", None, Some(origin), Some(source), Some(sequence)) => {
            Ok(Text::Record(EventCursor {
                origin: origin_from(&origin, "record origin")?,
                source: AttentionSource::from_wire(&source)
                    .ok_or_else(|| unreadable("record source"))?,
                sequence: as_u64(sequence, "record sequence")?,
            }))
        }
        _ => Err(unreadable("text")),
    }
}

fn key_text(value: impl Into<String>) -> KeyPart {
    KeyPart::Text(value.into())
}

fn key_integer(value: u64, field: &'static str) -> Result<KeyPart> {
    Ok(KeyPart::Integer(as_i64(value, field)?))
}

/// The key of a table that holds one row.
const SINGLE: KeyPart = KeyPart::Integer(0);

/// Returns the rows of every table that holds the environment as a whole, in
/// [`ENVIRONMENT_TABLES`] order.
#[expect(
    clippy::too_many_lines,
    reason = "one block per table, each naming the columns it writes"
)]
fn environment_rows(state: &StoredState) -> Result<Vec<Rows>> {
    let mut consumed = Rows::new();
    for ((origin, source), sequence) in &state.consumed {
        consumed.insert(
            vec![key_text(origin_text(origin)), key_text(source.as_str())],
            vec![integer(*sequence, "consumed cursor")?],
        );
    }
    let mut gaps = Rows::new();
    for (position, gap) in state.gaps.iter().enumerate() {
        gaps.insert(
            vec![KeyPart::Integer(as_index(position, "gap position")?)],
            vec![
                text(origin_text(&Origin::of(gap.session_id.0))),
                text(gap.source.as_str()),
                integer(gap.from_sequence.get(), "gap start")?,
                optional_integer(gap.to_sequence.0.map(U64::get), "gap end")?,
            ],
        );
    }
    let mut items = Rows::new();
    for item in &state.items {
        let [
            text_kind,
            words,
            record_origin,
            record_source,
            record_sequence,
        ] = text_values(&item.text)?;
        let (automation_kind, automation_object, automation_revision) = match &item.automation {
            None => (Value::Null, Value::Null, Value::Null),
            Some(AttentionAutomationSubject::Workflow {
                workflow_id,
                revision,
            }) => (
                text("workflow"),
                text(workflow_id.to_string()),
                integer(revision.get(), "automation revision")?,
            ),
            Some(AttentionAutomationSubject::CausalChain { causal_root_id }) => {
                (text("chain"), text(causal_root_id.to_string()), Value::Null)
            }
        };
        let [announced_boot, announced_continuous] =
            anchor_values(item.announced_anchor, "announced anchor")?;
        let [anchor_boot, anchor_continuous] = anchor_values(item.anchor, "item anchor")?;
        items.insert(
            vec![key_text(item.key.as_str())],
            vec![
                text(item.rule.as_str()),
                text(item.source.as_str()),
                text(origin_text(&item.origin)),
                optional_text(item.session_id.map(|session| session.to_string())),
                text_kind,
                words,
                record_origin,
                record_source,
                record_sequence,
                optional_text(item.grant.map(|grant| grant.to_string())),
                automation_kind,
                automation_object,
                automation_revision,
                integer(item.revision, "item revision")?,
                text(item.routing.as_str()),
                text(item.level.as_str()),
                Value::Integer(as_index(item.steps_taken, "escalation step")?),
                integer(item.occurrences, "occurrence count")?,
                integer(item.first_seen_ms.get(), "first seen")?,
                integer(item.last_seen_ms.get(), "last seen")?,
                text(item.notification.as_str()),
                optional_integer(
                    item.last_notified_ms.map(TimestampMs::get),
                    "last announced",
                )?,
                announced_boot,
                announced_continuous,
                anchor_boot,
                anchor_continuous,
                optional_text(item.announced_level.map(|level| level.as_str().to_owned())),
                integer(item.announcements, "announcement count")?,
                optional_integer(item.pending_handoff, "announcement number")?,
                flag(item.uncertain),
                flag(item.deferred),
            ],
        );
    }
    let mut actors = Rows::new();
    for (actor, revision) in &state.revisions {
        actors.insert(
            vec![key_text(actor.as_str())],
            vec![integer(*revision, "actor revision")?],
        );
    }
    let mut dropped = Rows::new();
    dropped.insert(vec![SINGLE], vec![integer(state.dropped, "dropped count")?]);
    let mut secret = Rows::new();
    secret.insert(
        vec![SINGLE],
        vec![Value::Blob(state.keys.as_bytes().to_vec())],
    );
    let mut counters = Rows::new();
    counters.insert(
        vec![SINGLE],
        vec![
            integer(state.next_announcement, "announcement counter")?,
            integer(state.next_revision, "revision counter")?,
        ],
    );
    let mut finalised = Rows::new();
    for session_id in &state.finalised {
        finalised.insert(vec![key_text(session_id.to_string())], Vec::new());
    }
    let mut item_acks = Rows::new();
    for (actor, acks) in &state.item_acks {
        for (key, ack) in acks {
            item_acks.insert(
                vec![key_text(actor.as_str()), key_text(key.as_str())],
                vec![
                    integer(ack.revision, "acknowledged revision")?,
                    integer(ack.at_ms.get(), "acknowledged at")?,
                ],
            );
        }
    }
    let mut pending = Rows::new();
    for (question_id, input) in &state.pending_inputs {
        let [anchor_boot, anchor_continuous] = anchor_values(input.anchor, "pending anchor")?;
        pending.insert(
            vec![key_text(question_id.to_string())],
            vec![
                text(input.session_id.to_string()),
                text(origin_text(&input.record.origin)),
                text(input.record.source.as_str()),
                integer(input.record.sequence, "pending record")?,
                integer(input.pending_since_ms.get(), "pending since")?,
                flag(input.reminded),
                anchor_boot,
                anchor_continuous,
            ],
        );
    }
    let mut quiet = Rows::new();
    if let Some(window) = state.quiet.as_ref() {
        quiet.insert(
            vec![SINGLE],
            vec![
                integer(window.start_minute.get(), "quiet start")?,
                integer(window.end_minute.get(), "quiet end")?,
                optional_text(window.zone.0.clone()),
            ],
        );
    }
    let mut subjects = Rows::new();
    for (key, subject) in &state.subjects {
        let (kind, object) = match &subject.subject {
            ReviewSubject::CompletedTurn { turn_id, .. } => ("turn", turn_id.to_string()),
            ReviewSubject::ChangeSet { change_set_id, .. } => {
                ("change_set", change_set_id.to_string())
            }
        };
        subjects.insert(
            vec![key_text(key.clone())],
            vec![
                text(kind),
                text(crate::review::subject_session(&subject.subject).to_string()),
                text(object),
                integer(subject.version, "review version")?,
                integer(subject.at_ms.get(), "review recorded at")?,
                integer(subject.sequence, "review order")?,
            ],
        );
    }
    let mut review_acks = Rows::new();
    for (actor, acks) in &state.review_acks {
        for (subject, ack) in acks {
            review_acks.insert(
                vec![key_text(actor.as_str()), key_text(subject.clone())],
                vec![
                    integer(ack.version, "acknowledged version")?,
                    integer(ack.at_ms.get(), "acknowledged at")?,
                ],
            );
        }
    }
    Ok(vec![
        consumed,
        gaps,
        items,
        actors,
        dropped,
        secret,
        counters,
        finalised,
        item_acks,
        pending,
        quiet,
        subjects,
        review_acks,
    ])
}

/// Returns the rows one session's log is written to, in [`SESSION_TABLES`] order.
fn session_rows(session_id: SessionId, log: &SessionLog) -> Result<Vec<Rows>> {
    let session = session_id.to_string();
    let mut changes = Rows::new();
    for change in log.changes() {
        let [
            text_kind,
            words,
            record_origin,
            record_source,
            record_sequence,
        ] = text_values(&change.text)?;
        changes.insert(
            vec![
                key_text(session.clone()),
                key_integer(change.cursor, "change cursor")?,
            ],
            vec![
                text(change.kind.as_str()),
                text_kind,
                words,
                record_origin,
                record_source,
                record_sequence,
                integer(change.at_ms.get(), "change recorded at")?,
            ],
        );
    }
    let mut heads = Rows::new();
    heads.insert(
        vec![key_text(session.clone())],
        vec![integer(log.head(), "change head")?],
    );
    let mut omitted = Rows::new();
    for (position, held) in log.omitted().iter().enumerate() {
        omitted.insert(
            vec![
                key_text(session.clone()),
                KeyPart::Integer(as_index(position, "omitted order")?),
            ],
            vec![
                integer(held.at_cursor, "omitted position")?,
                text(held.gap.source.as_str()),
                integer(held.gap.from_sequence.get(), "omitted start")?,
                optional_text(held.gap.session_id.0.map(|gap| gap.to_string())),
                optional_integer(held.gap.to_sequence.0.map(U64::get), "omitted end")?,
            ],
        );
    }
    let mut visits = Rows::new();
    let mut views = Rows::new();
    for (actor, visit) in log.visits() {
        visits.insert(
            vec![key_text(actor.as_str()), key_text(session.clone())],
            vec![
                integer(visit.cursor, "visit cursor")?,
                integer(visit.revision, "visit revision")?,
            ],
        );
        for (position, view) in visit.views.iter().enumerate() {
            views.insert(
                vec![
                    key_text(actor.as_str()),
                    key_text(session.clone()),
                    key_text(view.view_id.clone()),
                ],
                vec![
                    integer(view.source_offset.get(), "view offset")?,
                    text(view.filter.clone()),
                    Value::Integer(as_index(position, "view order")?),
                ],
            );
        }
    }
    Ok(vec![changes, heads, omitted, visits, views])
}

/// Writes one row, replacing whatever the table held under its key.
fn upsert(
    connection: &Connection,
    table: &TableDef,
    key: &[KeyPart],
    values: &[Value],
) -> Result<()> {
    let columns: Vec<&str> = table.keys.iter().chain(table.values).copied().collect();
    let slots: Vec<String> = (1..=columns.len()).map(|slot| format!("?{slot}")).collect();
    let mut bound: Vec<Value> = key.iter().map(KeyPart::value).collect();
    bound.extend(values.iter().cloned());
    connection.execute(
        &format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            table.name,
            columns.join(", "),
            slots.join(", ")
        ),
        rusqlite::params_from_iter(bound),
    )?;
    Ok(())
}

/// Removes one row by its key.
fn remove(connection: &Connection, table: &TableDef, key: &[KeyPart]) -> Result<()> {
    let condition: Vec<String> = table
        .keys
        .iter()
        .enumerate()
        .map(|(index, column)| format!("{column} = ?{}", index + 1))
        .collect();
    connection.execute(
        &format!(
            "DELETE FROM {} WHERE {}",
            table.name,
            condition.join(" AND ")
        ),
        rusqlite::params_from_iter(key.iter().map(KeyPart::value)),
    )?;
    Ok(())
}

/// Changes one table from `before` to `after`: removes what went, writes what is new or changed,
/// and leaves every other row as it is.
fn write_rows(
    connection: &Connection,
    table: &TableDef,
    before: &Rows,
    after: &Rows,
) -> Result<()> {
    for key in before.keys() {
        if !after.contains_key(key) {
            remove(connection, table, key)?;
        }
    }
    for (key, values) in after {
        if before.get(key) != Some(values) {
            upsert(connection, table, key, values)?;
        }
    }
    Ok(())
}

/// Changes the stored state from `before` to `after`, row by row.
///
/// A session's log is compared as a whole first, and only a log that changed is turned into rows,
/// so a write about one session does no work for the others.
fn write_state(connection: &Connection, before: &StoredState, after: &StoredState) -> Result<()> {
    let old = environment_rows(before)?;
    let new = environment_rows(after)?;
    for ((table, before), after) in ENVIRONMENT_TABLES.iter().zip(&old).zip(&new) {
        write_rows(connection, table, before, after)?;
    }
    let sessions: BTreeSet<SessionId> = before
        .sessions
        .keys()
        .chain(after.sessions.keys())
        .copied()
        .collect();
    for session_id in sessions {
        let was = before.sessions.get(&session_id);
        let now = after.sessions.get(&session_id);
        if was == now {
            continue;
        }
        let old = match was {
            Some(log) => session_rows(session_id, log)?,
            None => vec![Rows::new(); SESSION_TABLES.len()],
        };
        let new = match now {
            Some(log) => session_rows(session_id, log)?,
            None => vec![Rows::new(); SESSION_TABLES.len()],
        };
        for ((table, before), after) in SESSION_TABLES.iter().zip(&old).zip(&new) {
            write_rows(connection, table, before, after)?;
        }
    }
    Ok(())
}

/// Writes every row of `state` into tables the caller has cleared.
fn write_all(connection: &Connection, state: &StoredState) -> Result<()> {
    for (table, rows) in ENVIRONMENT_TABLES.iter().zip(environment_rows(state)?) {
        for (key, values) in &rows {
            upsert(connection, table, key, values)?;
        }
    }
    for (session_id, log) in &state.sessions {
        for (table, rows) in SESSION_TABLES.iter().zip(session_rows(*session_id, log)?) {
            for (key, values) in &rows {
                upsert(connection, table, key, values)?;
            }
        }
    }
    Ok(())
}

/// Writes the claim, in the transaction the state is written in.
fn write_owner(connection: &Connection, owner: &Owner) -> Result<()> {
    // A write that did not carry the claim forward would leave the store looking unheld to the
    // next opener while this owner was still writing to it.
    connection.execute(
        "INSERT OR REPLACE INTO attention_owner
             (id, claim, pid, start_source, start_value, boot, refreshed_ms)
         VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            as_i64(owner.claim, "owner claim")?,
            as_i64(owner.process.pid.get(), "owner process")?,
            source_text(owner.process.source),
            as_i64(owner.process.start_value.get(), "owner process start")?,
            owner.boot.to_hex(),
            as_i64(owner.refreshed_ms, "owner lease")?
        ],
    )?;
    Ok(())
}

impl Store {
    /// Opens the store at `path`, creating it when it is not there.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreAliased`] when the platform says more than one name reaches the file,
    /// [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be created,
    /// and [`Error::StoreUnreadable`] when the file records a schema this build does not know.
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        // The resolved path, never the name that reached here: SQLite reads a name beginning
        // `file:` as a URI and `:memory:` as a database of its own, and neither is the file this
        // store is meant to be. Who owns the store is a row inside it, not anything about a name.
        let resolved = resolve(path.as_ref())?;
        let connection = Connection::open_with_flags(&resolved, FILE_ONLY)?;
        Self::prepare(connection, Some(resolved.as_path()))
    }

    /// Opens the store at `path`, or in memory when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreAliased`] when the platform says more than one name reaches the file,
    /// [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be created,
    /// and [`Error::StoreUnreadable`] when the file records a schema this build does not know.
    pub(crate) fn beside(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => Self::open(path),
            None => Self::in_memory(),
        }
    }

    /// Opens a store that lives only as long as it is held.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the schema cannot be created.
    pub(crate) fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        Self::prepare(connection, None)
    }

    fn prepare(connection: Connection, file: Option<&Path>) -> Result<Self> {
        // Another process can hold the file for a moment, a reader among them. The wait is
        // bounded: past it the caller is told the store is unavailable rather than left blocked.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        // Before the write-ahead log exists, because it is the write-ahead log that a second name
        // for this file would split in two, and before any claim, because a file this host will
        // not journal is not one to take.
        if let Some(file) = file {
            one_name(&connection, file)?;
        }
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;
        // The recorded version is read before anything is created, because a table that is already
        // there is left alone and would tell this build nothing about which build wrote it.
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS attention_schema (version INTEGER NOT NULL);",
        )?;
        let recorded: Option<i64> = connection
            .query_row("SELECT version FROM attention_schema LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        match recorded {
            Some(version) if version == SCHEMA_VERSION => {}
            Some(_) => return Err(unreadable("schema version")),
            None => {
                connection.execute(
                    "INSERT INTO attention_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
        }
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// Reads the whole state through a connection the caller owns, which may be a transaction.
    fn load_from(connection: &Connection) -> Result<StoredState> {
        let dropped: Option<i64> = connection
            .query_row(
                "SELECT items FROM attention_dropped WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let secret: Option<Vec<u8>> = connection
            .query_row(
                "SELECT secret FROM attention_key_secret WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        // A store that has never been written has no secret and no state, and the fresh secret is
        // the one it starts with. A store that holds state and has lost its secret is a different
        // thing: every key in it was derived under one this build cannot reproduce, so a
        // resolution would look for an item under a name nothing there carries, and the condition
        // would stay outstanding for ever. That is refused rather than served.
        let keys = match secret {
            Some(bytes) => crate::key::KeySecret::from_bytes(
                <[u8; crate::key::SECRET_BYTES]>::try_from(bytes.as_slice())
                    .map_err(|_| unreadable("key secret"))?,
            ),
            None if Self::is_empty(connection)? => crate::key::KeySecret::fresh(),
            None => return Err(unreadable("key secret")),
        };
        let counters: Option<(i64, i64)> = connection
            .query_row(
                "SELECT announcements, revisions FROM attention_counters WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (next_announcement, next_revision) = match counters {
            Some((announcements, revisions)) => (
                as_u64(announcements, "announcement counter")?,
                as_u64(revisions, "revision counter")?,
            ),
            None => (0, 0),
        };
        Ok(StoredState {
            items: Self::load_items(connection)?,
            item_acks: Self::load_item_acks(connection)?,
            revisions: Self::load_revisions(connection)?,
            consumed: Self::load_consumed(connection)?,
            gaps: Self::load_gaps(connection)?,
            dropped: match dropped {
                Some(value) => as_u64(value, "dropped count")?,
                None => 0,
            },
            keys,
            next_announcement,
            next_revision,
            finalised: Self::load_finalised(connection)?,
            pending_inputs: Self::load_pending(connection)?,
            quiet: Self::load_quiet(connection)?,
            subjects: Self::load_subjects(connection)?,
            review_acks: Self::load_review_acks(connection)?,
            sessions: Self::load_sessions(connection)?,
        })
    }

    /// Returns whether this store holds no state at all.
    ///
    /// Every table the state lives in is asked, because a row in any of them was written under a
    /// secret, a key derivation and a schema this build has to be able to read back exactly. It
    /// answers about what is there now rather than about what was ever written: a store whose rows
    /// have all been removed is empty, and nothing in it needs a secret to name.
    fn is_empty(connection: &Connection) -> Result<bool> {
        for table in STATE_TABLES {
            let held: i64 = connection.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )?;
            if held != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Takes the store, reads its state, hands that to `settle`, and writes what comes back, with
    /// nothing able to come between any of it.
    ///
    /// This is what opening the store does. The claim on the store is read first, and `take` says
    /// whether this opener may have it: an opener that may not is refused here, before a single
    /// row of a state it would not be allowed to write has been read. Re-anchoring an interval
    /// then reads the state and writes it again, so another connection that committed between the
    /// read and the write would have its work replaced by the older state this one had read. That
    /// is why the write lock is taken before the read rather than at the write.
    ///
    /// This write replaces every row, which is what makes the rows and the owner's copy the same
    /// from here on; every later write changes only what differs from that copy.
    ///
    /// # Errors
    ///
    /// Returns whatever `take` or `settle` returns, [`Error::StoreUnavailable`] when the
    /// transaction cannot be taken or committed, and [`Error::StoreUnreadable`] for a value this
    /// build cannot read back or write down. Nothing is left half written.
    pub fn recover<T>(
        &mut self,
        take: impl FnOnce(Option<Owner>) -> Result<Owner>,
        settle: impl FnOnce(StoredState) -> Result<(StoredState, T)>,
    ) -> Result<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mine = take(Self::load_owner(&transaction)?)?;
        let stored = Self::load_from(&transaction)?;
        let (state, answer) = settle(stored)?;
        for table in STATE_TABLES {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        write_all(&transaction, &state)?;
        write_owner(&transaction, &mine)?;
        transaction.commit()?;
        Ok(answer)
    }

    /// Changes the stored state from `before`, which is what this owner last wrote, to what
    /// `decide` answers, under `owner`'s claim, in one transaction.
    ///
    /// The claim is read inside that transaction and has to be the one on the store. An owner
    /// whose store was taken while it was away writes nothing: what it holds is the state from
    /// before, and putting that back would undo everything the owner that took it has done.
    /// `admit` is asked after the claim, and `decide` only after `admit`: an action whose admission
    /// lapsed while it waited for this transaction is refused as that, and nothing it asked about
    /// is weighed or answered under the authority it no longer has. `decide` answers the state to
    /// write, the record of the action the write performs, written with it, and the answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreTaken`] when the claim on the store is not this one's, what `admit`
    /// or `decide` returns, [`Error::StoreUnavailable`] when the transaction cannot be committed
    /// and [`Error::StoreUnreadable`] when a value cannot be stored without changing it. Nothing is
    /// left half written: the store is either at the previous state or at this one.
    pub(crate) fn write<T>(
        &mut self,
        owner: &Owner,
        before: &StoredState,
        admit: impl FnOnce() -> Result<()>,
        decide: impl FnOnce() -> Result<(StoredState, Option<ActionRecord>, T)>,
    ) -> Result<(StoredState, T)> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let held = Self::load_owner(&transaction)?;
        if held.is_none_or(|held| held.claim != owner.claim) {
            return Err(Error::StoreTaken);
        }
        admit()?;
        let (after, action, answer) = decide()?;
        write_state(&transaction, before, &after)?;
        write_owner(&transaction, owner)?;
        if let Some(action) = action.as_ref() {
            transaction.execute(
                "INSERT INTO attention_actions
                     (actor, action_id, method, digest, answer, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    action.actor.as_str(),
                    action.action_id,
                    action.method,
                    action.digest,
                    action.answer,
                    as_i64(action.recorded_at_ms, "action recorded at")?
                ],
            )?;
        }
        transaction.commit()?;
        Ok((after, answer))
    }

    /// Returns the record of one actor's action, when this store performed it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the record cannot be read and
    /// [`Error::StoreUnreadable`] when it holds a value this build cannot read.
    pub(crate) fn action(&self, actor: &ActorId, action_id: &str) -> Result<Option<ActionRecord>> {
        let row: Option<(String, Vec<u8>, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT method, digest, answer, recorded_at_ms FROM attention_actions
                 WHERE actor = ?1 AND action_id = ?2",
                params![actor.as_str(), action_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(method, digest, answer, recorded_at_ms)| {
            Ok(ActionRecord {
                actor: actor.clone(),
                action_id: action_id.to_owned(),
                method,
                digest,
                answer,
                recorded_at_ms: as_u64(recorded_at_ms, "action recorded at")?,
            })
        })
        .transpose()
    }

    /// Forgets the action records written before `before_ms`, under `owner`'s claim.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreTaken`] when the claim on the store is not this one's and
    /// [`Error::StoreUnavailable`] when the records cannot be removed.
    pub(crate) fn forget_actions(&mut self, owner: &Owner, before_ms: u64) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let held = Self::load_owner(&transaction)?;
        if held.is_none_or(|held| held.claim != owner.claim) {
            return Err(Error::StoreTaken);
        }
        let removed = transaction.execute(
            "DELETE FROM attention_actions WHERE recorded_at_ms < ?1",
            params![as_i64(before_ms, "action cutoff")?],
        )?;
        write_owner(&transaction, owner)?;
        transaction.commit()?;
        Ok(removed)
    }

    /// Gives up `claim`, so the next opener does not have to work out that nobody is holding it.
    ///
    /// Only that claim: a row this owner no longer holds belongs to whoever took the store, and
    /// removing it would let a third opener in while the second is still writing. The state is not
    /// touched, because the state is not this owner's to restate on the way out.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the row cannot be removed - the file is gone, or
    /// another holder of it kept the write waiting past [`BUSY_TIMEOUT`]. The claim then stays
    /// where it is, and the next opener has to establish that this process has gone: while this
    /// process is still running, no lease will release that claim for it.
    pub(crate) fn release(&mut self, claim: u64) -> Result<()> {
        self.connection.execute(
            "DELETE FROM attention_owner WHERE id = 0 AND claim = ?1",
            params![as_i64(claim, "owner claim")?],
        )?;
        Ok(())
    }

    /// Reads the claim on the store, when there is one.
    fn load_owner(connection: &Connection) -> Result<Option<Owner>> {
        let row: Option<(i64, i64, String, i64, String, i64)> = connection
            .query_row(
                "SELECT claim, pid, start_source, start_value, boot, refreshed_ms
                 FROM attention_owner WHERE id = 0",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((claim, pid, source, start, boot, refreshed)) = row else {
            return Ok(None);
        };
        Ok(Some(Owner {
            claim: as_u64(claim, "owner claim")?,
            process: ProcessStartIdentity::new(
                as_u64(pid, "owner process")?,
                start_source(&source)?,
                as_u64(start, "owner process start")?,
            ),
            boot: BootMark::from_hex(&boot).ok_or_else(|| unreadable("owner boot"))?,
            refreshed_ms: as_u64(refreshed, "owner lease")?,
        }))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one item has many columns, and each is read back and checked"
    )]
    fn load_items(connection: &Connection) -> Result<Vec<Item>> {
        let mut statement = connection.prepare(&format!(
            "SELECT key, {} FROM attention_items ORDER BY first_seen_ms, key",
            ITEMS.values.join(", ")
        ))?;
        let mut rows = statement.query([])?;
        let unanchored = Elapsed::starting(HostReading::new(BootMark::default(), 0, 0, false));
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            let rule: String = row.get(1)?;
            let source: String = row.get(2)?;
            let origin: String = row.get(3)?;
            let session: Option<String> = row.get(4)?;
            let text_kind: String = row.get(5)?;
            let words: Option<String> = row.get(6)?;
            let record_origin: Option<String> = row.get(7)?;
            let record_source: Option<String> = row.get(8)?;
            let record_sequence: Option<i64> = row.get(9)?;
            let grant: Option<String> = row.get(10)?;
            let automation_kind: Option<String> = row.get(11)?;
            let automation_object: Option<String> = row.get(12)?;
            let automation_revision: Option<i64> = row.get(13)?;
            let revision: i64 = row.get(14)?;
            let routing: String = row.get(15)?;
            let level: String = row.get(16)?;
            let steps_taken: i64 = row.get(17)?;
            let occurrences: i64 = row.get(18)?;
            let first_seen: i64 = row.get(19)?;
            let last_seen: i64 = row.get(20)?;
            let notification: String = row.get(21)?;
            let last_notified: Option<i64> = row.get(22)?;
            let announced_boot: Option<String> = row.get(23)?;
            let announced_continuous: Option<i64> = row.get(24)?;
            let anchor_boot: Option<String> = row.get(25)?;
            let anchor_continuous: Option<i64> = row.get(26)?;
            let announced_level: Option<String> = row.get(27)?;
            let announcements: i64 = row.get(28)?;
            let pending_handoff: Option<i64> = row.get(29)?;
            let uncertain: i64 = row.get(30)?;
            let deferred: i64 = row.get(31)?;
            let session_id = session
                .map(|text| SessionId::from_str(&text).map_err(|_| unreadable("session")))
                .transpose()?;
            let automation = match (
                automation_kind.as_deref(),
                automation_object,
                automation_revision,
            ) {
                (None, None, None) => None,
                (Some("workflow"), Some(object), Some(revision)) => {
                    Some(AttentionAutomationSubject::Workflow {
                        workflow_id: WorkflowId::from_str(&object)
                            .map_err(|_| unreadable("workflow"))?,
                        revision: U64::new(as_u64(revision, "automation revision")?),
                    })
                }
                (Some("chain"), Some(object), None) => {
                    Some(AttentionAutomationSubject::CausalChain {
                        causal_root_id: CausalRootId::from_str(&object)
                            .map_err(|_| unreadable("causal root"))?,
                    })
                }
                _ => return Err(unreadable("automation subject")),
            };
            let last_notified_ms = last_notified
                .map(|at| as_u64(at, "last announced").map(TimestampMs::new))
                .transpose()?;
            items.push(Item {
                key: AttentionKey::new(key).map_err(|_| unreadable("item key"))?,
                rule: AttentionRule::from_wire(&rule).ok_or_else(|| unreadable("rule"))?,
                source: AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?,
                origin: origin_from(&origin, "item origin")?,
                session_id,
                text: text_from(
                    &text_kind,
                    words,
                    record_origin,
                    record_source,
                    record_sequence,
                )?,
                grant: grant
                    .map(|text| GrantId::from_str(&text).map_err(|_| unreadable("grant")))
                    .transpose()?,
                automation,
                revision: as_u64(revision, "item revision")?,
                routing: AttentionRouting::from_wire(&routing)
                    .ok_or_else(|| unreadable("routing"))?,
                level: AttentionLevel::from_wire(&level).ok_or_else(|| unreadable("level"))?,
                steps_taken: usize::try_from(steps_taken)
                    .map_err(|_| unreadable("escalation step"))?,
                occurrences: as_u64(occurrences, "occurrence count")?,
                first_seen_ms: TimestampMs::new(as_u64(first_seen, "first seen")?),
                last_seen_ms: TimestampMs::new(as_u64(last_seen, "last seen")?),
                notification: NotificationState::from_wire(&notification)
                    .ok_or_else(|| unreadable("notification"))?,
                last_notified_ms,
                announced_anchor: anchor(
                    announced_boot.as_deref(),
                    announced_continuous,
                    "announced anchor",
                )?,
                announced_level: announced_level
                    .map(|level| {
                        AttentionLevel::from_wire(&level).ok_or_else(|| unreadable("level"))
                    })
                    .transpose()?,
                announcements: as_u64(announcements, "announcement count")?,
                pending_handoff: pending_handoff
                    .map(|number| as_u64(number, "announcement number"))
                    .transpose()?,
                uncertain: uncertain != 0,
                anchor: anchor(anchor_boot.as_deref(), anchor_continuous, "item anchor")?,
                // Both intervals are re-anchored before anything reads them; the values here stand
                // only until `Attention::open` does that.
                age: unanchored,
                since_notified: last_notified_ms.map(|_| unanchored),
                deferred: deferred != 0,
            });
        }
        Ok(items)
    }

    fn load_item_acks(
        connection: &Connection,
    ) -> Result<BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>> {
        let mut statement =
            connection.prepare("SELECT actor, key, revision, at_ms FROM attention_item_acks")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>> = BTreeMap::new();
        for row in rows {
            let (actor, key, revision, at_ms) = row?;
            let actor = ActorId::new(actor).map_err(|_| unreadable("actor"))?;
            let key = AttentionKey::new(key).map_err(|_| unreadable("item key"))?;
            acks.entry(actor).or_default().insert(
                key,
                ItemAck {
                    revision: as_u64(revision, "acknowledged revision")?,
                    at_ms: TimestampMs::new(as_u64(at_ms, "acknowledged at")?),
                },
            );
        }
        Ok(acks)
    }

    fn load_revisions(connection: &Connection) -> Result<BTreeMap<ActorId, u64>> {
        let mut statement = connection.prepare("SELECT actor, revision FROM attention_actors")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut revisions = BTreeMap::new();
        for row in rows {
            let (actor, revision) = row?;
            revisions.insert(
                ActorId::new(actor).map_err(|_| unreadable("actor"))?,
                as_u64(revision, "actor revision")?,
            );
        }
        Ok(revisions)
    }

    fn load_consumed(connection: &Connection) -> Result<BTreeMap<(Origin, AttentionSource), u64>> {
        let mut statement =
            connection.prepare("SELECT origin, source, sequence FROM attention_consumed")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut consumed = BTreeMap::new();
        for row in rows {
            let (origin, source, sequence) = row?;
            let source = AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?;
            consumed.insert(
                (origin_from(&origin, "consumed origin")?, source),
                as_u64(sequence, "consumed cursor")?,
            );
        }
        Ok(consumed)
    }

    fn load_gaps(connection: &Connection) -> Result<Vec<AttentionGap>> {
        let mut statement = connection.prepare(
            "SELECT origin, source, from_sequence, to_sequence FROM attention_gaps
             ORDER BY position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut gaps = Vec::new();
        for row in rows {
            let (origin, source, from, to) = row?;
            gaps.push(AttentionGap {
                source: AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?,
                session_id: Nullable(origin_from(&origin, "gap origin")?.session()),
                from_sequence: U64::new(as_u64(from, "gap start")?),
                to_sequence: Nullable(
                    to.map(|to| as_u64(to, "gap end").map(U64::new))
                        .transpose()?,
                ),
            });
        }
        Ok(gaps)
    }

    fn load_finalised(connection: &Connection) -> Result<BTreeSet<SessionId>> {
        let mut statement = connection.prepare("SELECT session_id FROM attention_finalised")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut finalised = BTreeSet::new();
        for row in rows {
            finalised
                .insert(SessionId::from_str(&row?).map_err(|_| unreadable("finalised session"))?);
        }
        Ok(finalised)
    }

    fn load_pending(connection: &Connection) -> Result<BTreeMap<QuestionId, PendingInput>> {
        let mut statement = connection.prepare(&format!(
            "SELECT question_id, {} FROM attention_pending_inputs",
            PENDING.values.join(", ")
        ))?;
        let mut rows = statement.query([])?;
        let unanchored = Elapsed::starting(HostReading::new(BootMark::default(), 0, 0, false));
        let mut pending = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let question_id: String = row.get(0)?;
            let session: String = row.get(1)?;
            let record_origin: String = row.get(2)?;
            let record_source: String = row.get(3)?;
            let record_sequence: i64 = row.get(4)?;
            let since: i64 = row.get(5)?;
            let reminded: i64 = row.get(6)?;
            let boot: Option<String> = row.get(7)?;
            let continuous: Option<i64> = row.get(8)?;
            pending.insert(
                QuestionId::from_str(&question_id).map_err(|_| unreadable("question"))?,
                PendingInput {
                    session_id: SessionId::from_str(&session).map_err(|_| unreadable("session"))?,
                    record: EventCursor {
                        origin: origin_from(&record_origin, "pending record origin")?,
                        source: AttentionSource::from_wire(&record_source)
                            .ok_or_else(|| unreadable("pending record source"))?,
                        sequence: as_u64(record_sequence, "pending record")?,
                    },
                    pending_since_ms: TimestampMs::new(as_u64(since, "pending since")?),
                    waited: unanchored,
                    reminded: reminded != 0,
                    anchor: anchor(boot.as_deref(), continuous, "pending anchor")?,
                },
            );
        }
        Ok(pending)
    }

    fn load_quiet(connection: &Connection) -> Result<Option<QuietHours>> {
        let row: Option<(i64, i64, Option<String>)> = connection
            .query_row(
                "SELECT start_minute, end_minute, zone FROM attention_quiet_hours WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(start, end, zone)| {
            Ok(QuietHours {
                start_minute: U64::new(as_u64(start, "quiet start")?),
                end_minute: U64::new(as_u64(end, "quiet end")?),
                zone: Nullable(zone),
            })
        })
        .transpose()
    }

    fn load_subjects(connection: &Connection) -> Result<BTreeMap<String, Subject>> {
        let mut statement = connection.prepare(
            "SELECT key, kind, session_id, object, version, at_ms, sequence
             FROM attention_review_subjects",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut subjects = BTreeMap::new();
        for row in rows {
            let (key, kind, session, object, version, at_ms, sequence) = row?;
            let session_id = SessionId::from_str(&session).map_err(|_| unreadable("session"))?;
            let subject = match kind.as_str() {
                "turn" => ReviewSubject::CompletedTurn {
                    session_id,
                    turn_id: AgentTurnId::new(object).map_err(|_| unreadable("turn"))?,
                },
                "change_set" => ReviewSubject::ChangeSet {
                    session_id,
                    change_set_id: ChangeSetId::from_str(&object)
                        .map_err(|_| unreadable("change set"))?,
                },
                _ => return Err(unreadable("review subject kind")),
            };
            // The stored key is checked against the one the subject derives, so a row whose key
            // and subject disagree is refused rather than serving review state under a name that
            // does not describe it.
            if subject_key(&subject) != key {
                return Err(unreadable("review subject key"));
            }
            subjects.insert(
                key,
                Subject {
                    subject,
                    version: as_u64(version, "review version")?,
                    at_ms: TimestampMs::new(as_u64(at_ms, "review recorded at")?),
                    sequence: as_u64(sequence, "review order")?,
                },
            );
        }
        Ok(subjects)
    }

    fn load_review_acks(
        connection: &Connection,
    ) -> Result<BTreeMap<ActorId, BTreeMap<String, ReviewAck>>> {
        let mut statement = connection
            .prepare("SELECT actor, subject, version, at_ms FROM attention_review_acks")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>> = BTreeMap::new();
        for row in rows {
            let (actor, subject, version, at_ms) = row?;
            acks.entry(ActorId::new(actor).map_err(|_| unreadable("actor"))?)
                .or_default()
                .insert(
                    subject,
                    ReviewAck {
                        version: as_u64(version, "acknowledged version")?,
                        at_ms: TimestampMs::new(as_u64(at_ms, "acknowledged at")?),
                    },
                );
        }
        Ok(acks)
    }

    /// Reads every session's change log, its omitted ranges, its visits and their views.
    #[expect(
        clippy::too_many_lines,
        reason = "five tables make one session's log, and each is read back and checked"
    )]
    fn load_sessions(connection: &Connection) -> Result<BTreeMap<SessionId, SessionLog>> {
        struct Parts {
            changes: VecDeque<Change>,
            head: Option<u64>,
            omitted: Vec<Omitted>,
            visits: BTreeMap<ActorId, Visit>,
        }
        fn entry<'a>(
            parts: &'a mut BTreeMap<SessionId, Parts>,
            session: &str,
        ) -> Result<&'a mut Parts> {
            let session_id = SessionId::from_str(session).map_err(|_| unreadable("session"))?;
            Ok(parts.entry(session_id).or_insert_with(|| Parts {
                changes: VecDeque::new(),
                head: None,
                omitted: Vec::new(),
                visits: BTreeMap::new(),
            }))
        }
        let mut parts: BTreeMap<SessionId, Parts> = BTreeMap::new();
        {
            let mut statement = connection.prepare(&format!(
                "SELECT session_id, cursor, {} FROM attention_changes ORDER BY session_id, cursor",
                CHANGES.values.join(", ")
            ))?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let session: String = row.get(0)?;
                let cursor: i64 = row.get(1)?;
                let kind: String = row.get(2)?;
                let text_kind: String = row.get(3)?;
                let words: Option<String> = row.get(4)?;
                let record_origin: Option<String> = row.get(5)?;
                let record_source: Option<String> = row.get(6)?;
                let record_sequence: Option<i64> = row.get(7)?;
                let at_ms: i64 = row.get(8)?;
                let session_id =
                    SessionId::from_str(&session).map_err(|_| unreadable("session"))?;
                entry(&mut parts, &session)?.changes.push_back(Change {
                    cursor: as_u64(cursor, "change cursor")?,
                    kind: SemanticChangeKind::from_wire(&kind)
                        .ok_or_else(|| unreadable("change kind"))?,
                    session_id,
                    text: text_from(
                        &text_kind,
                        words,
                        record_origin,
                        record_source,
                        record_sequence,
                    )?,
                    at_ms: TimestampMs::new(as_u64(at_ms, "change recorded at")?),
                });
            }
        }
        {
            let mut statement =
                connection.prepare("SELECT session_id, next_cursor FROM attention_change_heads")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (session, head) = row?;
                entry(&mut parts, &session)?.head = Some(as_u64(head, "change head")?);
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT session_id, at_cursor, source, from_sequence, gap_session, to_sequence
                 FROM attention_omitted ORDER BY session_id, position",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })?;
            for row in rows {
                let (session, at_cursor, source, from, gap_session, to) = row?;
                let gap_session = gap_session
                    .map(|text| SessionId::from_str(&text).map_err(|_| unreadable("session")))
                    .transpose()?;
                entry(&mut parts, &session)?.omitted.push(Omitted {
                    gap: AttentionGap {
                        source: AttentionSource::from_wire(&source)
                            .ok_or_else(|| unreadable("source"))?,
                        session_id: Nullable(gap_session),
                        from_sequence: U64::new(as_u64(from, "omitted start")?),
                        to_sequence: Nullable(
                            to.map(|to| as_u64(to, "omitted end").map(U64::new))
                                .transpose()?,
                        ),
                    },
                    at_cursor: as_u64(at_cursor, "omitted position")?,
                });
            }
        }
        {
            let mut statement = connection
                .prepare("SELECT actor, session_id, cursor, revision FROM attention_visits")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            for row in rows {
                let (actor, session, cursor, revision) = row?;
                entry(&mut parts, &session)?.visits.insert(
                    ActorId::new(actor).map_err(|_| unreadable("actor"))?,
                    Visit {
                        cursor: as_u64(cursor, "visit cursor")?,
                        views: Vec::new(),
                        revision: as_u64(revision, "visit revision")?,
                    },
                );
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT actor, session_id, view_id, source_offset, filter FROM attention_log_views
                 ORDER BY session_id, actor, position",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (actor, session, view_id, offset, filter) = row?;
                let actor = ActorId::new(actor).map_err(|_| unreadable("actor"))?;
                entry(&mut parts, &session)?
                    .visits
                    .entry(actor)
                    .or_default()
                    .views
                    .push(LogViewState {
                        view_id,
                        source_offset: U64::new(as_u64(offset, "view offset")?),
                        filter,
                    });
            }
        }
        let mut sessions = BTreeMap::new();
        for (session_id, held) in parts {
            let head = match held.head {
                Some(head) => head,
                None => held
                    .changes
                    .back()
                    .map_or(0, |change| change.cursor.saturating_add(1)),
            };
            sessions.insert(
                session_id,
                SessionLog::restored(held.changes, head, held.omitted, held.visits),
            );
        }
        Ok(sessions)
    }
}
