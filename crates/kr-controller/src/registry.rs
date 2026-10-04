//! The environment registry.
//!
//! Everything the control daemon must still know after it restarts lives here, and the order the
//! rows are written in is the whole point.
//!
//! * A **reservation** is recorded before anything is spawned: the actor, the create token, the
//!   payload digest, the allocated session identifier and display number, and the launch phase.
//!   A daemon that crashes between the reservation and the spawn finds the reservation and can
//!   decide what to do; one that spawned first would have a running worker nothing knows about.
//! * **Display numbers** are allocated in increasing order and never reused, so a number that once
//!   named a closed session never names a different one later.
//! * A **worker** row holds the public key the rendezvous established, which is what every later
//!   verification is checked against.
//! * A **tombstone** is the record of a closed session, so a reader is answered rather than being
//!   sent to an endpoint that might start something.
//! * A worker's **desktop identity** is the desktop session and login-session generation the worker
//!   says it is bound to, in its ready report or, for a worker a daemon adopts again after a stop,
//!   in its own description of itself. It is recorded with the worker's row, so a daemon that
//!   starts again on another login still knows which desktop each worker belongs to. A worker
//!   bound to none is recorded with none.
//!
//! # Who runs a migration
//!
//! A daemon's start opens the registry ([`Registry::open`]) and brings it to the schema this build
//! reads, one step per version, each of which commits whole or leaves the registry at the version it
//! began from, so that it can run again. An update does the same for an
//! environment whose daemon is not running ([`Registry::bring_forward`]), with the daemon stopped
//! and the environment's lock held, so that every registry it classes is at the one schema its
//! reader reads. A step therefore runs outside the daemon's start as well, and must not depend on
//! anything else the start does.
//!
//! # Process identities in whole seconds
//!
//! The previous build recorded a Windows process's start in whole seconds, and a worker it started
//! keeps running across an upgrade and keeps stating its identity that way, signed. So a record in
//! whole seconds is still read, and every time this registry is opened each such record the kernel
//! can settle is settled: a process still running is recorded at the resolution this build reads,
//! and one that has gone is marked ended. A record the kernel will not describe is left as it is
//! for the next opening. A worker row also keeps the source the worker itself states, which is how
//! a host can tell whether any running worker still states whole seconds. All of it goes with the
//! whole-seconds source, in the first release after one in which every running worker states the
//! creation time.

use kr_ipc::identity::CurrentProcess;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActorId, AuthorityRevision, BootEpoch, ControllerGeneration, DesktopSessionId, EnvironmentId,
    SessionId,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, TimestampMs, Uuid};
use kr_protocol::session::{ClosureRecord, DisplayNumber, SessionCreateParams, SessionState};
use kr_protocol::worker::ReservationId;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ControllerError, Result};

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 7;

/// How far a reservation has progressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchPhase {
    /// Recorded, nothing spawned.
    Reserved,
    /// The service manager was asked to start a worker. Execution may have begun.
    Spawned,
    /// A worker claimed this reservation. The claim is consumed; no second one is admitted.
    Claimed,
    /// The worker reported its root shell and the session is live.
    Live,
    /// The reservation was fenced and must never be resumed. Its execution is unresolved, so it
    /// still occupies a slot: something may be running that this host did not admit.
    Fenced,
    /// The launch is confirmed not to have produced a running worker. It occupies nothing.
    Failed,
    /// The session closed.
    Closed,
}

impl LaunchPhase {
    /// Returns the stable stored string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Spawned => "spawned",
            Self::Claimed => "claimed",
            Self::Live => "live",
            Self::Fenced => "fenced",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "reserved" => Some(Self::Reserved),
            "spawned" => Some(Self::Spawned),
            "claimed" => Some(Self::Claimed),
            "live" => Some(Self::Live),
            "fenced" => Some(Self::Fenced),
            "failed" => Some(Self::Failed),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

/// The configuration document an environment has applied the effects of.
///
/// The document itself, not a note that one was accepted. What a change owes is derived by
/// comparing the document that arrives with the document that was accepted, and a daemon that came
/// back holding only a revision number could not make that comparison: removing a ceiling, putting
/// an older document back and editing one in place without moving its revision all look like
/// nothing from a number alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptedConfiguration {
    /// The revision whose effects are applied. Zero where this environment has accepted none.
    pub revision: u64,
    /// The document those effects came from, as this host writes one, when there was a usable one.
    pub document: Option<String>,
}

/// One recorded create reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// The reservation identity.
    pub reservation_id: ReservationId,
    /// The actor that asked for the session.
    pub actor_id: ActorId,
    /// The idempotent create token, which is the action identifier of the request.
    pub create_token: Uuid,
    /// The digest of the immutable create payload.
    pub payload_digest: Digest256,
    /// The create request itself, canonically encoded, without the environment its creator sent.
    ///
    /// It is written before anything is spawned. A daemon that restarts mid-create can then say
    /// what the session was going to be instead of holding an identifier with no request behind it.
    /// The creator's environment variables are never part of it: a credential among them would
    /// outlive its session in this file, so the list in a recorded request is always empty and
    /// tells nothing about what the creator sent. The variables are held in memory from the
    /// reservation to the worker's claim, which is the only thing that reads them, and written
    /// nowhere. It is absent only for a reservation an earlier schema recorded without one, or one
    /// whose record no build could read.
    pub create_intent: Option<Vec<u8>>,
    /// The session identifier allocated for it.
    pub session_id: SessionId,
    /// The display number allocated for it.
    pub display_number: DisplayNumber,
    /// How far it has progressed.
    pub phase: LaunchPhase,
    /// The process identity the launcher reported, once one exists.
    pub launcher_identity: Option<ProcessStartIdentity>,
    /// The public key the claiming worker presented, recorded when the claim was consumed.
    ///
    /// This reaches storage before the worker is told anything, so a worker that starts a shell and
    /// then loses its ready report is still a worker this host can authenticate.
    pub claimed_key: Option<AuthorisationKey>,
    /// When it was recorded.
    pub created_at_ms: TimestampMs,
}

/// One worker the registry knows about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerRecord {
    /// The session the worker owns.
    pub session_id: SessionId,
    /// The display number.
    pub display_number: DisplayNumber,
    /// The public key established at rendezvous.
    pub public_key: AuthorisationKey,
    /// The worker's process identity.
    pub process_identity: ProcessStartIdentity,
    /// The worker's private endpoint.
    pub endpoint: String,
    /// How long the execution context lasts.
    pub profile: WorkerProfile,
    /// The lifecycle state as the registry knows it.
    pub state: SessionState,
    /// The authority revision this worker has acknowledged.
    pub acknowledged_revision: AuthorityRevision,
}

/// One clock floor this environment created in a boot ([`kr_ipc::floor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedFloor {
    /// The floor's identity, as its file's header names it.
    pub identity: kr_ipc::floor::FloorIdentity,
    /// Whether it is the boot's floor in force. A floor that is not was lost: its file lost its
    /// name, and a later start created another.
    pub in_force: bool,
}

/// Names a database file to SQLite as immutable: read alone, with no lock, log or shared memory.
///
/// A URI filename escapes the three characters it gives a meaning to, and a Windows path is
/// written with forward slashes after a third slash, as SQLite reads one. A path that is not
/// Unicode has no URI spelling here, and is not named at all.
fn immutable_uri(path: &std::path::Path) -> Option<String> {
    let text = path.to_str()?;
    #[cfg(windows)]
    let text = text.replace('\\', "/");
    let mut uri = String::from("file:");
    if text.starts_with('/') {
        uri.push_str("//");
    } else if cfg!(windows) {
        // `C:/...`, which SQLite reads after an empty authority and a third slash.
        uri.push_str("///");
    }
    for character in text.chars() {
        match character {
            '%' => uri.push_str("%25"),
            '?' => uri.push_str("%3f"),
            '#' => uri.push_str("%23"),
            other => uri.push(other),
        }
    }
    uri.push_str("?immutable=1");
    Some(uri)
}

/// Opens a registry file to read it alone: no lock, no log, no shared memory, and nothing made
/// beside it.
fn open_immutable(path: &std::path::Path) -> Result<Connection> {
    let uri = immutable_uri(path).ok_or_else(|| ControllerError::RegistryUnavailable {
        detail: format!(
            "{} is not a path this build can name to SQLite as a file to read alone",
            path.display()
        ),
    })?;
    Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(ControllerError::registry)
}

/// Every schema version a registry records: one row, in every registry this host wrote.
fn recorded_versions(connection: &Connection) -> Result<Vec<i64>> {
    let mut statement = connection
        .prepare("SELECT version FROM schema_version")
        .map_err(ControllerError::registry)?;
    statement
        .query_map([], |row| row.get(0))
        .map_err(ControllerError::registry)?
        .collect::<rusqlite::Result<_>>()
        .map_err(ControllerError::registry)
}

/// Whether a registry has a table.
fn has_table(connection: &Connection, table: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .map_err(ControllerError::registry)
}

/// The tables whose rows say what a registry's sessions are. Every schema version has had them, and
/// a registry that has lost one is never brought forward, because opening it would make the table
/// again, empty, and a registry that records no worker is the one answer a question about who may
/// still hold a session's stores must never get by accident.
const EVIDENCE_TABLES: [&str; 4] = ["environment", "reservations", "workers", "tombstones"];

/// What tells one regular file from another at the same name, where the platform names one.
fn file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// What [`Registry::bring_forward`] did to a registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carried {
    /// The schema version the registry recorded.
    pub from: i64,
    /// The schema version it records now, the one this build reads.
    pub to: i64,
}

/// The environment registry.
#[derive(Debug)]
pub struct Registry {
    connection: Connection,
    environment_id: EnvironmentId,
    /// Asks the kernel about a recorded process and names it as this build reads it.
    ///
    /// It settles the records the previous build made in whole seconds; a test states what the
    /// kernel says instead.
    current_process: fn(&ProcessStartIdentity) -> CurrentProcess,
}

/// The two columns a worker's desktop identity is kept in.
///
/// The login generation is an unsigned number and the column holds a signed one, so it is kept as
/// the same 64 bits: every generation there can be comes back as it went in.
fn desktop_columns(desktop: &DesktopBinding) -> (Option<String>, Option<i64>) {
    (
        desktop
            .desktop_session_id
            .as_ref()
            .map(|identity| identity.as_str().to_owned()),
        desktop
            .login_generation
            .as_ref()
            .map(|generation| generation.get().cast_signed()),
    )
}

impl Registry {
    /// Opens the registry for an environment, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be opened or
    /// migrated.
    pub fn open(path: impl AsRef<std::path::Path>, environment_id: EnvironmentId) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ControllerError::registry)?;
        Self::prepare(connection, environment_id)
    }

    /// Takes into a registry's own file what a write-ahead log or a rollback journal beside it
    /// holds, as the daemon's clean stop does, and says whether it opened the registry to take a
    /// log in.
    ///
    /// What a daemon that ended by a signal leaves behind: the records are in the log, and
    /// [`Registry::open_to_read`] refuses to read a file that has not taken them in. This changes no
    /// record, migrates nothing and settles nothing: the log is checkpointed and the file closed,
    /// which removes it. The caller holds the environment's singleton lock, so no daemon writes
    /// meanwhile. Only a log or a journal that is a regular file with something in it is opened
    /// for. A file that is not a regular file, and a link, are left as they are and said not to
    /// hold a log: [`Registry::open_to_read`] refuses them, by its own words, before it opens
    /// anything.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the file cannot be looked at, when a
    /// log or a journal beside it is not a regular file, and when the log cannot be taken in.
    pub fn take_in_its_log(path: impl AsRef<std::path::Path>) -> Result<bool> {
        let path = path.as_ref();
        let refuse = |detail: String| ControllerError::RegistryUnavailable { detail };
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Ok(false),
            Err(error) => {
                return Err(refuse(format!(
                    "this registry could not be looked at: {error}"
                )));
            }
        }
        let mut holds = false;
        for suffix in ["-wal", "-journal"] {
            let mut beside = path.as_os_str().to_owned();
            beside.push(suffix);
            match std::fs::symlink_metadata(&beside) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(metadata) if metadata.is_file() => holds |= metadata.len() > 0,
                Ok(_) => {
                    return Err(refuse(format!(
                        "what is beside this registry under the name {} is not a regular file",
                        beside.to_string_lossy()
                    )));
                }
                Err(error) => {
                    return Err(refuse(format!(
                        "what is beside this registry could not be looked at: {error}"
                    )));
                }
            }
        }
        if !holds {
            return Ok(false);
        }
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(ControllerError::registry)?;
        // A journal that a stopped writer left is rolled back by the first read; a log is taken in
        // by the checkpoint, and refused if a reader keeps it from being.
        let _: i64 = connection
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(ControllerError::registry)?;
        let blocked: i64 = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(ControllerError::registry)?;
        if blocked != 0 {
            return Err(refuse(
                "this registry's write-ahead log could not be taken in while another connection uses it"
                    .to_owned(),
            ));
        }
        Ok(true)
    }

    /// Brings a registry that is behind this build's schema forward, as a daemon's start would,
    /// and says what it did; `None` when there was nothing to bring.
    ///
    /// For an update, which carries the registry of an environment whose daemon has not run since
    /// an earlier schema step to the schema its own release reads, so that it can be classed by
    /// [`Registry::open_to_read`], which reads exactly one. The caller holds the environment's
    /// singleton lock, so no daemon writes meanwhile and none can start. It is the one migration
    /// chain of [`Registry::open`]: nothing here migrates by itself.
    ///
    /// What is beside the registry is looked at before anything opens it, and what a daemon that
    /// ended by a signal left in its log is taken in ([`Registry::take_in_its_log`], which opens a
    /// registry whose log or journal holds writes, and no other), so the version is read from what
    /// the registry holds. Only a regular file with exactly one version row, from 1 up to below
    /// this build's, and every table in `EVIDENCE_TABLES`, is migrated. A registry already at this
    /// build's version is not migrated, and neither is one at a later version, one with no version
    /// or several, an empty file, a link or what is not a file: they are left, `None`, for
    /// [`Registry::open_to_read`] to refuse in its own words. A registry that lost an evidence table
    /// is refused here, by the table's name, because opening it would make that table again,
    /// empty. The file is opened for writing without being created, and the name is checked to
    /// still name the file that was looked at and to record the same version on that connection, so
    /// a file replaced by another regular file between the look and the open is refused, and never
    /// made new. A file replaced by another kind of file in that window is the owner's race, as it
    /// is for [`Registry::open_to_read`], which looks at the name and then opens it: the caller
    /// holds the environment's lock, and nothing here closes that window. The log is taken in once
    /// more at the end, so the file alone holds what was written.
    ///
    /// A step commits whole, or leaves the registry at the version it began from with whatever it
    /// did that it can run again over (the step to version 7 rewrites the recorded create requests,
    /// compacts the file and takes the log in before it moves the version), so a failure leaves the
    /// registry at the version of the last step that completed, which this release's own
    /// [`Registry::open`] continues from. This is a step a migration must stay fit for: it also runs
    /// outside the daemon's start, so a step may not depend on anything else the start does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the registry's log or journal cannot be
    /// taken in or is not a regular file, when its `-shm` file is not a regular file, when an
    /// evidence table is missing, when the registry changed while it was opened, and when a step of
    /// the chain or the final log intake fails, naming the schema version it started from.
    pub fn bring_forward(
        path: impl AsRef<std::path::Path>,
        environment_id: EnvironmentId,
    ) -> Result<Option<Carried>> {
        let path = path.as_ref();
        let looked_at = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!("this registry could not be looked at: {error}"),
                });
            }
        };
        let mut shared_memory = path.as_os_str().to_owned();
        shared_memory.push("-shm");
        match std::fs::symlink_metadata(&shared_memory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!(
                        "what is beside this registry under the name {} is not a regular file",
                        shared_memory.to_string_lossy()
                    ),
                });
            }
            Err(error) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!("what is beside this registry could not be looked at: {error}"),
                });
            }
        }
        Self::take_in_its_log(path)?;
        // What an immutable read cannot tell is left for the reader to refuse by its own words.
        let Ok(peek) = open_immutable(path) else {
            return Ok(None);
        };
        let Ok(versions) = recorded_versions(&peek) else {
            return Ok(None);
        };
        let [from] = versions[..] else {
            return Ok(None);
        };
        if !(1..SCHEMA_VERSION).contains(&from) {
            return Ok(None);
        }
        Self::refuse_a_lost_table(&peek, from)?;
        drop(peek);
        // Without the flag that creates a file: a registry removed meanwhile is not made again.
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(ControllerError::registry)?;
        let changed = || ControllerError::RegistryUnavailable {
            detail: format!(
                "this registry changed while it was brought forward from schema version {from}"
            ),
        };
        // The name still names the file that was looked at, and it records what it did.
        match std::fs::symlink_metadata(path) {
            Ok(now) if now.is_file() && file_identity(&now) == file_identity(&looked_at) => {}
            _ => return Err(changed()),
        }
        if recorded_versions(&connection)? != [from] {
            return Err(changed());
        }
        Self::refuse_a_lost_table(&connection, from)?;
        let registry = Self::prepare(connection, environment_id).map_err(|error| {
            let cause = match error {
                ControllerError::RegistryUnavailable { detail } => detail,
                other => other.to_string(),
            };
            ControllerError::RegistryUnavailable {
                detail: format!(
                    "this registry recorded schema version {from} when it was opened and could not \
                     be brought to schema version {SCHEMA_VERSION}: {cause}"
                ),
            }
        })?;
        let blocked: i64 = registry
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(ControllerError::registry)?;
        if blocked != 0 {
            return Err(ControllerError::RegistryUnavailable {
                detail: format!(
                    "this registry was brought forward from schema version {from}, but its \
                     write-ahead log could not be taken in while another connection uses it"
                ),
            });
        }
        drop(registry);
        Ok(Some(Carried {
            from,
            to: SCHEMA_VERSION,
        }))
    }

    /// Refuses a registry that recorded schema version `from` and has lost an evidence table.
    fn refuse_a_lost_table(connection: &Connection, from: i64) -> Result<()> {
        for table in EVIDENCE_TABLES {
            if !has_table(connection, table)? {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!(
                        "this registry recorded schema version {from} and has no {table} table, so \
                         it cannot be brought forward without losing what it held"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Opens a registry that already exists, to read what it records and nothing else.
    ///
    /// Nothing is created, brought forward, repaired or settled, and nothing is written, not even
    /// beside it: SQLite opens a database in write-ahead-logging mode read-only by making its log
    /// and shared-memory files, so the file is read as immutable instead, which makes neither. That
    /// reads the file alone, so a registry whose log holds writes the file has not taken in, or
    /// whose rollback journal is waiting to be rolled back, is refused rather than read as it was
    /// before them. So is a registry reached through a link at its own name: SQLite follows the
    /// link and keeps the log beside the file it reaches, where a log looked for beside the link
    /// would not be. (A link among the directories above it changes nothing: the log is beside the
    /// file either way.) The registry is refused, too, unless it records exactly the schema version
    /// this build reads and holds the tables the workers and the closures are read from: one that
    /// lost either would otherwise read as recording no worker at all, and that is the one answer a
    /// question about who may still hold a session's stores must never get by accident. The
    /// explicit journal import reads its evidence through this, while it holds the environment's
    /// singleton lock, so nothing writes the registry while it is read.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the file is not there, is not a file
    /// or cannot be opened, when a write-ahead log or a rollback journal beside it holds anything,
    /// when it records another schema version or none, and when a table it is read from is
    /// missing.
    pub fn open_to_read(
        path: impl AsRef<std::path::Path>,
        environment_id: EnvironmentId,
    ) -> Result<Self> {
        let path = path.as_ref();
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: "this registry is a link, and it is read only as the file itself, \
                             beside which its write-ahead log is kept"
                        .to_owned(),
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: "this registry is not a file".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!("this registry could not be looked at: {error}"),
                });
            }
        }
        for (suffix, what) in [
            ("-wal", "write-ahead log"),
            ("-journal", "rollback journal"),
        ] {
            let mut beside = path.as_os_str().to_owned();
            beside.push(suffix);
            match std::fs::metadata(&beside) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(metadata) if metadata.len() == 0 => {}
                Ok(_) => {
                    return Err(ControllerError::RegistryUnavailable {
                        detail: format!(
                            "this registry's {what} holds writes its file has not taken in; start \
                             this build's daemon once and stop it again, so they are taken in, \
                             and read it then"
                        ),
                    });
                }
                Err(error) => {
                    return Err(ControllerError::RegistryUnavailable {
                        detail: format!("this registry's {what} could not be looked at: {error}"),
                    });
                }
            }
        }
        let connection = open_immutable(path)?;
        let versions = recorded_versions(&connection)?;
        if versions != [SCHEMA_VERSION] {
            let recorded = match versions.as_slice() {
                [] => "no schema version".to_owned(),
                [version] => format!("schema version {version}"),
                many => format!("{} schema versions", many.len()),
            };
            return Err(ControllerError::RegistryUnavailable {
                detail: format!(
                    "this registry records {recorded}, and this build reads one as it is only at \
                     schema version {SCHEMA_VERSION}"
                ),
            });
        }
        for table in ["workers", "tombstones"] {
            if !has_table(&connection, table)? {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!("this registry has no {table} table"),
                });
            }
        }
        Ok(Self {
            connection,
            environment_id,
            current_process: kr_ipc::identity::current_process,
        })
    }

    /// Opens a registry that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be created.
    pub fn in_memory(environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare(
            Connection::open_in_memory().map_err(ControllerError::registry)?,
            environment_id,
        )
    }

    fn prepare(connection: Connection, environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare_reading(
            connection,
            environment_id,
            kr_ipc::identity::current_process,
        )
    }

    /// Opens the registry as [`Self::prepare`] does, asking `current_process` about recorded
    /// processes.
    fn prepare_reading(
        connection: Connection,
        environment_id: EnvironmentId,
        current_process: fn(&ProcessStartIdentity) -> CurrentProcess,
    ) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        let registry = Self {
            connection,
            environment_id,
            current_process,
        };
        registry.migrate()?;
        registry.settle_whole_seconds()?;
        Ok(registry)
    }

    fn migrate(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS environment (
                     environment_id      BLOB PRIMARY KEY,
                     generation          INTEGER NOT NULL,
                     next_display        INTEGER NOT NULL,
                     session_limit       INTEGER NOT NULL,
                     authority_revision  INTEGER NOT NULL DEFAULT 0,
                     fence_owed_revision INTEGER NOT NULL DEFAULT 0,
                     accepted_revision   INTEGER NOT NULL DEFAULT 0,
                     accepted_document   TEXT
                 );
                 CREATE TABLE IF NOT EXISTS reservations (
                     reservation_id    BLOB PRIMARY KEY,
                     actor_id          TEXT NOT NULL,
                     create_token      BLOB NOT NULL,
                     payload_digest    BLOB NOT NULL,
                     create_intent     BLOB,
                     session_id        BLOB NOT NULL UNIQUE,
                     display_number    INTEGER NOT NULL UNIQUE,
                     phase             TEXT NOT NULL,
                     launcher_pid      INTEGER,
                     launcher_source   TEXT,
                     launcher_start    INTEGER,
                     claimed_key       BLOB,
                     created_at_ms     INTEGER NOT NULL,
                     UNIQUE (actor_id, create_token)
                 );
                 CREATE TABLE IF NOT EXISTS workers (
                     session_id       BLOB PRIMARY KEY,
                     display_number   INTEGER NOT NULL,
                     public_key       BLOB NOT NULL,
                     process_pid      INTEGER NOT NULL,
                     process_source   TEXT NOT NULL,
                     process_start    INTEGER NOT NULL,
                     endpoint         TEXT NOT NULL,
                     profile          TEXT NOT NULL,
                     state            TEXT NOT NULL,
                     acknowledged_revision INTEGER NOT NULL DEFAULT 0,
                     stated_source    TEXT NOT NULL DEFAULT '',
                     desktop_session_id TEXT,
                     login_generation INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS tombstones (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL,
                     closed_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS utc_floors (
                     floor_id      BLOB PRIMARY KEY NOT NULL,
                     boot_epoch    BLOB NOT NULL,
                     in_force      INTEGER NOT NULL,
                     created_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS clock_continuity (
                     boot_epoch        BLOB PRIMARY KEY NOT NULL,
                     lost_at_ms        INTEGER NOT NULL,
                     established_at_ms INTEGER
                 );",
            )
            .map_err(ControllerError::registry)?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(ControllerError::registry)?;
        match recorded {
            None => {
                self.connection
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            Some(1) => {
                self.migrate_1_to_2()?;
                self.migrate_2_to_3()?;
                self.migrate_3_to_4()?;
                self.migrate_4_to_5()?;
                self.migrate_5_to_6()?;
                self.migrate_6_to_7()?;
            }
            Some(2) => {
                self.migrate_2_to_3()?;
                self.migrate_3_to_4()?;
                self.migrate_4_to_5()?;
                self.migrate_5_to_6()?;
                self.migrate_6_to_7()?;
            }
            Some(3) => {
                self.migrate_3_to_4()?;
                self.migrate_4_to_5()?;
                self.migrate_5_to_6()?;
                self.migrate_6_to_7()?;
            }
            Some(4) => {
                self.migrate_4_to_5()?;
                self.migrate_5_to_6()?;
                self.migrate_6_to_7()?;
            }
            Some(5) => {
                self.migrate_5_to_6()?;
                self.migrate_6_to_7()?;
            }
            Some(6) => self.migrate_6_to_7()?,
            Some(version) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!(
                        "this registry is at schema version {version}; this build reads {SCHEMA_VERSION}"
                    ),
                });
            }
        }
        self.connection
            .execute(
                "INSERT OR IGNORE INTO environment
                     (environment_id, generation, next_display, session_limit)
                 VALUES (?1, 0, 1, ?2)",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT)
                        .unwrap_or(128)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 1 registry forward.
    ///
    /// Version 1 recorded a create request's digest but not the request, and recorded the worker's
    /// key only once the session went live. Both columns are added empty: a reservation written by
    /// version 1 genuinely has no recorded request, and recovery treats a missing one as a launch
    /// it cannot resume rather than inventing a session to start.
    ///
    /// Version 1 had no `claimed` phase, so its `spawned` rows cover both "the worker never
    /// reached the rendezvous" and "it did, and may have started a shell". They become `claimed`,
    /// which is the one this host can resolve without assuming the more convenient of the two.
    ///
    /// Version 1 also issued no authority revisions, so the environment and every worker come
    /// forward at revision zero: that is not an assumption about what a worker answered, it is what
    /// a registry with no revisions in it means. The columns are added here rather than left for
    /// the next migration, because every migration after this one reads them.
    ///
    /// This migration goes when there can no longer be a version 1 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_1_to_2(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE reservations ADD COLUMN create_intent BLOB;
                 ALTER TABLE reservations ADD COLUMN claimed_key BLOB;
                 ALTER TABLE environment ADD COLUMN authority_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE workers ADD COLUMN acknowledged_revision INTEGER NOT NULL DEFAULT 0;
                 UPDATE reservations SET phase = 'claimed' WHERE phase = 'spawned';
                 UPDATE schema_version SET version = 2;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 2 registry forward.
    ///
    /// Version 2 recorded the authority revision but not whether the fence that revision raised had
    /// been answered, so a daemon that stopped with a worker still holding withdrawn authority came
    /// back believing the revocation complete. Every environment that has issued a revision comes
    /// forward owing its current one: a version 2 registry cannot say which of its revisions a
    /// worker answered, and the safe answer to a question with no recorded answer is that the debt
    /// stands. One announcement settles it where every worker has in fact answered, and that
    /// announcement happens at the first start after the upgrade.
    ///
    /// Version 2 also recorded nothing about which configuration document this environment had
    /// accepted, so it comes forward having accepted none: the columns stay at their defaults and
    /// the first start after the upgrade puts whatever document it finds through acceptance. That
    /// costs one acceptance of a document that may well already be in force, and the alternative is
    /// a host that treats a document written by a daemon that never finished applying it as
    /// already applied.
    ///
    /// This migration goes when there can no longer be a version 2 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_2_to_3(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE environment ADD COLUMN fence_owed_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE environment ADD COLUMN accepted_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE environment ADD COLUMN accepted_document TEXT;
                 UPDATE environment SET fence_owed_revision = authority_revision
                  WHERE authority_revision > 0;
                 UPDATE schema_version SET version = 3;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 3 registry forward.
    ///
    /// Version 3 recorded the process identity each worker stated and nothing beside it, so what
    /// a worker states was what the row said. Version 4 keeps the two apart, because a worker of
    /// the previous build states its start in whole seconds while its row is settled at the
    /// resolution this build reads: each row comes forward stating the source it recorded.
    ///
    /// This migration goes with the whole-seconds source, in the first release after one in which
    /// every running worker states the creation time: until then a registry the previous build
    /// wrote may still be opened by this one.
    fn migrate_3_to_4(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE workers ADD COLUMN stated_source TEXT NOT NULL DEFAULT '';
                 UPDATE workers SET stated_source = process_source;
                 UPDATE schema_version SET version = 4;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 4 registry forward.
    ///
    /// Version 5 records the clock floors this environment created in each boot, and whether a
    /// boot's clock continuity was lost. A version 4 registry recorded neither, and the two tables
    /// are created with the rest when it opens: empty, which is what a registry that has created no
    /// floor holds. The first start after the upgrade finds its boot's floor file absent and records
    /// the one it creates as the boot's first.
    ///
    /// This migration goes when there can no longer be a version 4 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_4_to_5(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 UPDATE schema_version SET version = 5;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Version 5 to 6: a worker's row gains the desktop identity it is bound to, the desktop
    /// session and the login-session generation, both null.
    ///
    /// A worker an earlier build recorded has none recorded, and reads back as bound to none: the
    /// row's profile still says whether it is a desktop-bound worker, and the identity it was
    /// bound to is what that build never kept.
    ///
    /// This migration goes when there can no longer be a version 5 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_5_to_6(&self) -> Result<()> {
        let has = |column: &str| -> Result<bool> {
            self.connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('workers') WHERE name = ?1",
                    params![column],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| count > 0)
                .map_err(ControllerError::registry)
        };
        let mut statements = String::from("BEGIN;");
        if !has("desktop_session_id")? {
            statements.push_str("ALTER TABLE workers ADD COLUMN desktop_session_id TEXT;");
        }
        if !has("login_generation")? {
            statements.push_str("ALTER TABLE workers ADD COLUMN login_generation INTEGER;");
        }
        statements.push_str("UPDATE schema_version SET version = 6; COMMIT;");
        self.connection
            .execute_batch(&statements)
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Version 6 to 7: a reservation's recorded create request no longer holds the environment its
    /// creator sent.
    ///
    /// An earlier build wrote the whole request, the creator's environment variables included,
    /// into each reservation, and a reservation outlives its session. Every recorded request comes
    /// forward with its variables emptied: the rest of it is what the session was asked to be, and
    /// is read as before. A request in the shape a build before the launch profile recorded is
    /// rewritten in this build's shape, and a record that is neither shape cannot be shown to hold
    /// no variables and becomes none.
    ///
    /// The old bytes outlive an update of the row, in free pages and in the write-ahead log, so the
    /// rewrite is followed by `VACUUM`, which builds the file again from the rows it holds, and by
    /// a truncating checkpoint, which empties the log. Only then does the version move, so a run
    /// that stops part way is made again from the start; the step is idempotent. A `VACUUM` that
    /// cannot finish stops the daemon's start with the cause and what to do about it: keeping the
    /// variables on disk is the worse outcome.
    ///
    /// The file is shared with the grant and device stores, which open after this registry and
    /// are rewritten by `VACUUM` with it; no table in it relies on an implicit row number, which
    /// `VACUUM` may change.
    ///
    /// This migration goes in the first release after every install has opened the registry at
    /// this version: nothing before it is installed anywhere it has to be read from again.
    fn migrate_6_to_7(&self) -> Result<()> {
        self.migrate_6_to_7_compacting(|connection| connection.execute_batch("VACUUM"))
    }

    /// The step of [`Self::migrate_6_to_7`], with the compaction it runs after the rewrite given.
    fn migrate_6_to_7_compacting(
        &self,
        compact: impl FnOnce(&Connection) -> rusqlite::Result<()>,
    ) -> Result<()> {
        // The identifiers alone are read up front: a record holds the creator's whole environment,
        // and a registry that has recorded many creates should not hold them all in memory at once.
        let recorded: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare("SELECT reservation_id FROM reservations WHERE create_intent IS NOT NULL")
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map([], |row| row.get(0))
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<_, _>>()
                .map_err(ControllerError::registry)?
        };
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(ControllerError::registry)?;
        for reservation_id in recorded {
            let intent: Vec<u8> = transaction
                .query_row(
                    "SELECT create_intent FROM reservations WHERE reservation_id = ?1",
                    params![reservation_id],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            let emptied = match without_environment(&intent) {
                Emptied::Unchanged => continue,
                Emptied::Rewritten(bytes) => Some(bytes),
                Emptied::Unreadable => None,
            };
            transaction
                .execute(
                    "UPDATE reservations SET create_intent = ?2 WHERE reservation_id = ?1",
                    params![reservation_id, emptied],
                )
                .map_err(ControllerError::registry)?;
        }
        transaction.commit().map_err(ControllerError::registry)?;
        compact(&self.connection).map_err(not_compacted)?;
        let blocked: i64 = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(not_compacted)?;
        if blocked != 0 {
            return Err(ControllerError::RegistryUnavailable {
                detail: "this registry's recorded create requests were rewritten without the \
                         environment their creators sent, but its write-ahead log still holds the \
                         old copies: it could not be taken in while another connection uses the \
                         registry. Stop whatever else has it open, then start the daemon again"
                    .to_owned(),
            });
        }
        self.connection
            .execute("UPDATE schema_version SET version = 7", [])
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Settles every record of a process in whole seconds that the kernel can settle.
    ///
    /// The previous build recorded a Windows process's start in whole seconds: a worker's launcher
    /// in its reservation and the worker in its row. Each such record is put to the kernel the way
    /// that build read it - the process holding the identifier now, if it was created in that
    /// second - and a process that is still running is recorded at the resolution this build reads,
    /// while one that has gone is marked ended, not rewritten. A record the kernel will not
    /// describe is left in whole seconds, and is read the previous build's way until an opening
    /// settles it. What a worker row says the worker states is left as it was.
    ///
    /// It goes with the whole-seconds source, in the first release after one in which every
    /// running worker states the creation time.
    fn settle_whole_seconds(&self) -> Result<()> {
        let seconds = source_name(ProcessStartSource::WindowsProcessStartSeconds);
        let workers: Vec<(Vec<u8>, i64, i64)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT session_id, process_pid, process_start FROM workers
                     WHERE process_source = ?1",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![seconds], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        for (session, pid, start) in workers {
            if let Some(settled) = self.settled(&in_whole_seconds(pid, start)) {
                self.connection
                    .execute(
                        "UPDATE workers SET process_source = ?2, process_start = ?3
                         WHERE session_id = ?1 AND process_source = ?4",
                        params![
                            session,
                            source_name(settled.source),
                            start_column(settled.start_value.get()),
                            seconds
                        ],
                    )
                    .map_err(ControllerError::registry)?;
            }
        }
        let launches: Vec<(Vec<u8>, i64, i64)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT reservation_id, launcher_pid, launcher_start FROM reservations
                     WHERE launcher_source = ?1
                       AND launcher_pid IS NOT NULL AND launcher_start IS NOT NULL",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![seconds], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        for (reservation, pid, start) in launches {
            if let Some(settled) = self.settled(&in_whole_seconds(pid, start)) {
                self.connection
                    .execute(
                        "UPDATE reservations SET launcher_source = ?2, launcher_start = ?3
                         WHERE reservation_id = ?1 AND launcher_source = ?4",
                        params![
                            reservation,
                            source_name(settled.source),
                            start_column(settled.start_value.get()),
                            seconds
                        ],
                    )
                    .map_err(ControllerError::registry)?;
            }
        }
        Ok(())
    }

    /// What a record of a process in whole seconds becomes, when the kernel says what it is: the
    /// process at the resolution this build reads when it is still running, the ended marker when
    /// it has gone, and nothing when the kernel will not say.
    fn settled(&self, recorded: &ProcessStartIdentity) -> Option<ProcessStartIdentity> {
        match (self.current_process)(recorded) {
            CurrentProcess::Running(current) => Some(current),
            CurrentProcess::Ended => u32::try_from(recorded.pid.get())
                .ok()
                .map(kr_ipc::identity::ended_process_identity),
            CurrentProcess::Unknown { .. } => None,
        }
    }

    /// Returns the identity this registry records for the process a worker states, in the row of
    /// `session_id`.
    ///
    /// The identity itself, unless it is in whole seconds, which a worker of the previous build
    /// states. Then the finer identity this registry already established for that worker's
    /// process is kept: it was proved when it was recorded, and asking the kernel again could only
    /// answer less, or name a later process created in the same second under the identifier. Only
    /// a row with no finer identity for that process is settled now, as the opening settles one.
    fn to_record(
        &self,
        session_id: SessionId,
        stated: &ProcessStartIdentity,
    ) -> Result<ProcessStartIdentity> {
        if stated.source != ProcessStartSource::WindowsProcessStartSeconds {
            return Ok(stated.clone());
        }
        if let Some(established) = self.recorded_process(session_id)?
            && established.source == ProcessStartSource::WindowsProcessCreationTime
            && established.pid == stated.pid
            && established.start_value.get() != kr_ipc::identity::START_VALUE_UNREAD
            && established.start_value.get() / CREATION_TIME_UNITS_PER_SECOND
                == stated.start_value.get()
        {
            return Ok(established);
        }
        Ok(self.settled(stated).unwrap_or_else(|| stated.clone()))
    }

    /// Returns the process identity one worker row records, when there is a row.
    fn recorded_process(&self, session_id: SessionId) -> Result<Option<ProcessStartIdentity>> {
        let row: Option<(i64, String, i64)> = self
            .connection
            .query_row(
                "SELECT process_pid, process_source, process_start FROM workers
                 WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        row.map(|(pid, source, start)| {
            Ok(ProcessStartIdentity {
                pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                source: source_from(&source)?,
                start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
            })
        })
        .transpose()
    }

    /// Returns the environment this registry belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Advances and returns the persistent controller generation.
    ///
    /// A new holder of the singleton lock advances the generation **before** it reconnects to any
    /// worker. That is what makes the previous holder unable to present the current generation:
    /// the number it holds is already behind.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn advance_generation(&mut self) -> Result<ControllerGeneration> {
        self.connection
            .execute(
                "UPDATE environment SET generation = generation + 1 WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        self.generation()
    }

    /// Returns the current generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn generation(&self) -> Result<ControllerGeneration> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT generation FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(ControllerGeneration::new(
            u64::try_from(value).unwrap_or_default(),
        ))
    }

    /// Returns the environment's current authority revision.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn authority_revision(&self) -> Result<AuthorityRevision> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT authority_revision FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(AuthorityRevision::new(
            u64::try_from(value).unwrap_or_default(),
        ))
    }

    /// Advances the environment's authority revision and records the fence it owes.
    ///
    /// Only the host issues revisions, and they only ever increase. A revocation advances this and
    /// is then pending at every worker until each has acknowledged the new number or is confirmed
    /// ended.
    ///
    /// The debt is written by the same statement as the revision, so the two cannot come apart. A
    /// revision that advanced is not a completed revocation, and the daemon that advanced it can
    /// stop between the write and the announcement; recording the debt afterwards, or only once the
    /// effects behind it had landed, is how a host comes back believing a fence held that no worker
    /// ever answered. It is settled by [`Self::settle_fence`] and by nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn advance_authority_revision(&mut self) -> Result<AuthorityRevision> {
        self.connection
            .execute(
                "UPDATE environment
                    SET authority_revision  = authority_revision + 1,
                        fence_owed_revision = authority_revision + 1
                  WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        self.authority_revision()
    }

    /// Returns the revision whose fence this environment still owes, when it owes one.
    ///
    /// The durable answer to "has every worker acknowledged the authority this host withdrew". It
    /// survives a restart, an effect that failed after the fence went up, and a configuration
    /// document that later becomes unusable, because none of those is a worker answering.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn fence_owed(&self) -> Result<Option<AuthorityRevision>> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT fence_owed_revision FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let revision = u64::try_from(value).unwrap_or_default();
        Ok((revision > 0).then(|| AuthorityRevision::new(revision)))
    }

    /// Returns the configuration document this environment has accepted.
    ///
    /// The durable half of acceptance. A document is written before its effects are applied, so the
    /// file on disk says nothing about whether this host ever acted on it: only this record does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn accepted_configuration(&self) -> Result<AcceptedConfiguration> {
        let (revision, document): (i64, Option<String>) = self
            .connection
            .query_row(
                "SELECT accepted_revision, accepted_document FROM environment
                  WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControllerError::registry)?;
        Ok(AcceptedConfiguration {
            revision: u64::try_from(revision).unwrap_or_default(),
            document,
        })
    }

    /// Records the configuration document whose effects this environment has applied.
    ///
    /// Written after the effects have landed and never before: a record written first would tell
    /// the next start that a document had been acted on when the daemon stopped in the middle of
    /// acting on it. The fence a ceiling here raised is recorded the other way round, ahead of its
    /// announcement, because the two answer opposite questions - what this host still owes, and
    /// what it has already done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_accepted_configuration(
        &mut self,
        accepted: &AcceptedConfiguration,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment
                    SET accepted_revision = ?2, accepted_document = ?3
                  WHERE environment_id = ?1",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(accepted.revision).unwrap_or(i64::MAX),
                    accepted.document.as_deref()
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Settles the fence debt up to and including `revision`.
    ///
    /// Called only where every worker has acknowledged that revision or is confirmed ended, which
    /// is what a barrier holding means. A debt raised at a *later* revision is left alone: it
    /// belongs to a revocation this barrier says nothing about.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn settle_fence(&mut self, revision: AuthorityRevision) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment SET fence_owed_revision = 0
                  WHERE environment_id = ?1 AND fence_owed_revision <= ?2",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(revision.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Forgets the clock floors and the clock continuity of every boot but `boot`.
    ///
    /// A floor is the reading of one boot, and a boot that has ended has no process left that maps
    /// its floor, so nothing about it decides anything again.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn forget_other_boots(&mut self, boot: BootEpoch) -> Result<()> {
        let boot = boot.get().to_be_bytes();
        self.connection
            .execute(
                "DELETE FROM utc_floors WHERE boot_epoch != ?1",
                params![boot.as_slice()],
            )
            .map_err(ControllerError::registry)?;
        self.connection
            .execute(
                "DELETE FROM clock_continuity WHERE boot_epoch != ?1",
                params![boot.as_slice()],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns every clock floor this environment created in `boot`, and which is in force.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn floors_of_boot(&self, boot: BootEpoch) -> Result<Vec<RecordedFloor>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT floor_id, in_force FROM utc_floors WHERE boot_epoch = ?1
                  ORDER BY created_at_ms",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map(params![boot.get().to_be_bytes().as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(ControllerError::registry)?;
        let mut floors = Vec::new();
        for row in rows {
            let (identity, in_force) = row.map_err(ControllerError::registry)?;
            let identity: [u8; 16] =
                identity
                    .try_into()
                    .map_err(|_| ControllerError::RegistryUnavailable {
                        detail: "a recorded clock floor identity is not sixteen bytes".to_owned(),
                    })?;
            floors.push(RecordedFloor {
                identity: kr_ipc::floor::FloorIdentity::from_bytes(identity),
                in_force: in_force != 0,
            });
        }
        Ok(floors)
    }

    /// Records `identity` as `boot`'s clock floor in force, and every other floor of the boot as
    /// not in force, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_floor_in_force(
        &mut self,
        boot: BootEpoch,
        identity: kr_ipc::floor::FloorIdentity,
        at_ms: TimestampMs,
    ) -> Result<()> {
        let boot = boot.get().to_be_bytes();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE utc_floors SET in_force = 0 WHERE boot_epoch = ?1",
                params![boot.as_slice()],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO utc_floors (floor_id, boot_epoch, in_force, created_at_ms)
                 VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT (floor_id) DO UPDATE SET in_force = 1",
                params![
                    identity.as_bytes().as_slice(),
                    boot.as_slice(),
                    i64::try_from(at_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that `boot`'s clock continuity is lost: every floor of the boot stops being in
    /// force, and the boot is marked lost until the owner establishes the clock, in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn lose_clock_continuity(&mut self, boot: BootEpoch, at_ms: TimestampMs) -> Result<()> {
        let boot = boot.get().to_be_bytes();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE utc_floors SET in_force = 0 WHERE boot_epoch = ?1",
                params![boot.as_slice()],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO clock_continuity (boot_epoch, lost_at_ms, established_at_ms)
                 VALUES (?1, ?2, NULL)
                 ON CONFLICT (boot_epoch) DO UPDATE
                     SET lost_at_ms = ?2, established_at_ms = NULL",
                params![
                    boot.as_slice(),
                    i64::try_from(at_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Whether `boot`'s clock continuity is lost and the owner has not established the clock
    /// since.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn clock_continuity_lost(&self, boot: BootEpoch) -> Result<bool> {
        let lost: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM clock_continuity
                  WHERE boot_epoch = ?1 AND established_at_ms IS NULL",
                params![boot.get().to_be_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        Ok(lost.is_some())
    }

    /// Records that the owner established the clock at `at_ms`, which ends `boot`'s lost clock
    /// continuity when it was lost.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn establish_clock_continuity(
        &mut self,
        boot: BootEpoch,
        at_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE clock_continuity SET established_at_ms = ?2
                  WHERE boot_epoch = ?1 AND established_at_ms IS NULL",
                params![
                    boot.get().to_be_bytes().as_slice(),
                    i64::try_from(at_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Records the authority revision one worker has acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_acknowledged_revision(
        &mut self,
        session_id: SessionId,
        revision: AuthorityRevision,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE workers SET acknowledged_revision = ?2
                 WHERE session_id = ?1 AND acknowledged_revision < ?2",
                params![
                    session_id.get().as_bytes().as_slice(),
                    i64::try_from(revision.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns the configured admission limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn session_limit(&self) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT session_limit FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(u64::try_from(value).unwrap_or_default())
    }

    /// Sets the admission limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn set_session_limit(&mut self, limit: u64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment SET session_limit = ?2 WHERE environment_id = ?1",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns how many sessions occupy the environment.
    ///
    /// A fenced reservation counts. Fencing means the host stopped trusting a claim, not that the
    /// execution behind it ended; until that is resolved something may be running, and admitting a
    /// new session in its place would put the environment over its limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn occupancy(&self) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM reservations
                 WHERE phase IN ('reserved', 'spawned', 'claimed', 'live', 'fenced')",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(u64::try_from(value).unwrap_or_default())
    }

    /// Returns every reservation in one phase.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservations_in(&self, phase: LaunchPhase) -> Result<Vec<Reservation>> {
        let ids: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT reservation_id FROM reservations WHERE phase = ?1
                     ORDER BY display_number",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![phase.as_str()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        let mut reservations = Vec::new();
        for id in ids {
            let reservation_id = ReservationId::new(uuid_from(&id)?);
            if let Some(reservation) = self.reservation(reservation_id)? {
                reservations.push(reservation);
            }
        }
        Ok(reservations)
    }

    /// Records a reservation, or returns the one this create token already made.
    ///
    /// The whole record is committed in one transaction before anything is spawned. A repeated
    /// token with the same payload returns the original reservation; the same token with a
    /// different payload is a conflict rather than a second session.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::SessionLimit`] when the environment is full,
    /// [`ControllerError::InvalidArgument`] when a token is reused with a different payload, and a
    /// registry failure when the write fails.
    pub fn reserve(
        &mut self,
        actor_id: &ActorId,
        create_token: Uuid,
        payload_digest: Digest256,
        create_intent: &[u8],
        now_ms: TimestampMs,
    ) -> Result<Admission> {
        if let Some(existing) = self.reservation_for_token(actor_id, create_token)? {
            if existing.payload_digest != payload_digest {
                return Err(ControllerError::IdConflict {
                    token: create_token.to_string(),
                });
            }
            return Ok(Admission {
                reservation: existing,
                deduplicated: true,
            });
        }
        let limit = self.session_limit()?;
        let live = self.occupancy()?;
        if live >= limit {
            // Rejected before anything is spawned. Nothing is ever evicted to make room.
            return Err(ControllerError::SessionLimit {
                environment: self.environment_id.to_string(),
                live,
                limit,
            });
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        let next_display: i64 = transaction
            .query_row(
                "SELECT next_display FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE environment SET next_display = next_display + 1 WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        let reservation = Reservation {
            reservation_id: ReservationId::new(kr_ipc::new_uuid()),
            actor_id: actor_id.clone(),
            create_token,
            payload_digest,
            create_intent: Some(create_intent.to_vec()),
            session_id: SessionId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(u64::try_from(next_display).unwrap_or_default()),
            phase: LaunchPhase::Reserved,
            launcher_identity: None,
            claimed_key: None,
            created_at_ms: now_ms,
        };
        transaction
            .execute(
                "INSERT INTO reservations (reservation_id, actor_id, create_token, payload_digest,
                     create_intent, session_id, display_number, phase, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    reservation.reservation_id.get().as_bytes().as_slice(),
                    reservation.actor_id.as_str(),
                    reservation.create_token.as_bytes().as_slice(),
                    reservation.payload_digest.as_bytes().as_slice(),
                    create_intent,
                    reservation.session_id.get().as_bytes().as_slice(),
                    i64::try_from(reservation.display_number.get()).unwrap_or(i64::MAX),
                    reservation.phase.as_str(),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(Admission {
            reservation,
            deduplicated: false,
        })
    }

    /// Records the identity the launcher reported for a spawned reservation.
    ///
    /// The phase is not touched. It moved to `spawned` before the service manager was called, and
    /// a reservation that has since been claimed or fenced must not be moved back by a launcher
    /// report that arrives afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_launch(
        &mut self,
        reservation_id: ReservationId,
        identity: &ProcessStartIdentity,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE reservations SET launcher_pid = ?2, launcher_source = ?3,
                        launcher_start = ?4
                 WHERE reservation_id = ?1",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    i64::try_from(identity.pid.get()).unwrap_or(i64::MAX),
                    source_name(identity.source),
                    start_column(identity.start_value.get()),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Consumes a reservation's single rendezvous admission.
    ///
    /// One launched process, one claim. The phase moves out of `spawned` in the same transaction
    /// that reads it, so two claims arriving together cannot both find it spawned; the second one
    /// finds `claimed` and is fenced. The worker's public key is written here, before the worker is
    /// told anything, so a claim that is admitted is a claim this host can authenticate afterwards
    /// whatever happens next.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RendezvousRefused`] when the reservation is not waiting for a
    /// claim, and a registry failure when the write fails.
    pub fn claim_rendezvous(
        &mut self,
        reservation_id: ReservationId,
        worker_public_key: AuthorisationKey,
    ) -> Result<Reservation> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        let phase: Option<String> = transaction
            .query_row(
                "SELECT phase FROM reservations WHERE reservation_id = ?1",
                params![reservation_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let phase = phase
            .as_deref()
            .and_then(LaunchPhase::parse)
            .ok_or_else(|| ControllerError::rendezvous("no reservation matches this claim"))?;
        if phase != LaunchPhase::Spawned {
            // A second claim on one reservation means the host cannot tell which process owns the
            // session. Fencing it is the only answer that does not hand the session to a guess.
            if matches!(phase, LaunchPhase::Claimed | LaunchPhase::Live) {
                transaction
                    .execute(
                        "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1",
                        params![
                            reservation_id.get().as_bytes().as_slice(),
                            LaunchPhase::Fenced.as_str()
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                transaction.commit().map_err(ControllerError::registry)?;
            }
            return Err(ControllerError::rendezvous(format!(
                "this reservation is {} and accepts no further claim",
                phase.as_str()
            )));
        }
        transaction
            .execute(
                "UPDATE reservations SET phase = ?2, claimed_key = ?3 WHERE reservation_id = ?1",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    LaunchPhase::Claimed.as_str(),
                    worker_public_key.as_bytes().as_slice(),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        self.reservation(reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("the reservation vanished"))
    }

    /// Resolves a reservation as a launch that produced no session, when it is still waiting for
    /// its worker's claim, and says whether it did.
    ///
    /// The phase test and the write are one statement, so a claim that commits first leaves the
    /// reservation as it made it: a row in any other phase is not touched, and the caller goes on
    /// to the claim's own rules, which fence a second claim.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn fail_if_spawned(&mut self, reservation_id: ReservationId) -> Result<bool> {
        let changed = self
            .connection
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1 AND phase = ?3",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    LaunchPhase::Failed.as_str(),
                    LaunchPhase::Spawned.as_str()
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(changed > 0)
    }

    /// Moves a reservation out of `claimed` into a resolved phase.
    ///
    /// Only a claim is resolved this way. A reservation that has been fenced since the claim was
    /// consumed stays fenced: whatever answer arrives afterwards does not tell the host which of
    /// two claimants owns the session.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn resolve_claim(
        &mut self,
        reservation_id: ReservationId,
        phase: LaunchPhase,
    ) -> Result<bool> {
        let changed = self
            .connection
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1 AND phase = ?3",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    phase.as_str(),
                    LaunchPhase::Claimed.as_str()
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(changed > 0)
    }

    /// Fences a reservation, whatever phase it is in.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn fence(&mut self, reservation_id: ReservationId) -> Result<()> {
        self.set_phase(reservation_id, LaunchPhase::Fenced)
    }

    /// Moves a reservation to a new phase.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn set_phase(&mut self, reservation_id: ReservationId, phase: LaunchPhase) -> Result<()> {
        self.connection
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1",
                params![reservation_id.get().as_bytes().as_slice(), phase.as_str()],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Reads one reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservation(&self, reservation_id: ReservationId) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE reservation_id = ?1",
            params![reservation_id.get().as_bytes().as_slice()],
        )
    }

    /// Reads the reservation that allocated a session.
    ///
    /// The reservation row survives closure, so a closed session still has a display number to be
    /// listed under.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservation_for_session(&self, session_id: SessionId) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE session_id = ?1",
            params![session_id.get().as_bytes().as_slice()],
        )
    }

    /// Returns the reservation one actor's create token already named, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub fn reservation_for_token(
        &self,
        actor_id: &ActorId,
        create_token: Uuid,
    ) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE actor_id = ?1 AND create_token = ?2",
            params![actor_id.as_str(), create_token.as_bytes().as_slice()],
        )
    }

    fn read_reservation(
        &self,
        query: &str,
        parameters: impl rusqlite::Params,
    ) -> Result<Option<Reservation>> {
        self.connection
            .query_row(query, parameters, |row| {
                Ok(RawReservation {
                    reservation: row.get(0)?,
                    actor: row.get(1)?,
                    token: row.get(2)?,
                    digest: row.get(3)?,
                    session: row.get(4)?,
                    display: row.get(5)?,
                    phase: row.get(6)?,
                    pid: row.get(7)?,
                    source: row.get(8)?,
                    start: row.get(9)?,
                    created: row.get(10)?,
                    create_intent: row.get(11)?,
                    claimed_key: row.get(12)?,
                })
            })
            .optional()
            .map_err(ControllerError::registry)?
            .map(RawReservation::into_reservation)
            .transpose()
    }

    /// Returns every reservation whose session has closed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn closed_reservations(&self) -> Result<Vec<Reservation>> {
        let sessions: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT session_id FROM reservations WHERE phase = ?1 ORDER BY display_number",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![LaunchPhase::Closed.as_str()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        let mut reservations = Vec::new();
        for session in sessions {
            let session_id = SessionId::new(uuid_from(&session)?);
            if let Some(reservation) = self.reservation_for_session(session_id)? {
                reservations.push(reservation);
            }
        }
        Ok(reservations)
    }

    /// Records a worker inside the reservation-to-live transition, with the desktop it states it is
    /// bound to.
    ///
    /// The public key, the process identity, the live phase and the desktop identity are committed
    /// together: a registry that knows a session is live knows which key answers for it and which
    /// desktop its worker said it was bound to, and reads both back after a restart. A worker bound
    /// to no desktop is recorded with none.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_worker(
        &mut self,
        reservation_id: ReservationId,
        worker: &WorkerRecord,
        desktop: &DesktopBinding,
    ) -> Result<()> {
        let recorded = self.to_record(worker.session_id, &worker.process_identity)?;
        let (desktop_session, login_generation) = desktop_columns(desktop);
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state, stated_source,
                     desktop_session_id, login_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state,
                     stated_source = excluded.stated_source,
                     desktop_session_id = excluded.desktop_session_id,
                     login_generation = excluded.login_generation",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(recorded.pid.get()).unwrap_or(i64::MAX),
                    source_name(recorded.source),
                    start_column(recorded.start_value.get()),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
                    source_name(worker.process_identity.source),
                    desktop_session,
                    login_generation,
                ],
            )
            .map_err(ControllerError::registry)?;
        // Only a consumed claim becomes live. A reservation that was fenced while its worker was
        // reporting stays fenced: the ready report does not answer the question fencing asked.
        let promoted = transaction
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1 AND phase = ?3",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    LaunchPhase::Live.as_str(),
                    LaunchPhase::Claimed.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        if promoted == 0 {
            transaction.rollback().map_err(ControllerError::registry)?;
            return Err(ControllerError::rendezvous(
                "this reservation is no longer waiting for a ready report",
            ));
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Records a worker row without touching any reservation phase, with the desktop it states it
    /// is bound to where it stated one.
    ///
    /// Recovery uses this: the worker already exists and already proved itself, so what is missing
    /// is the daemon's own record of it, not a transition. `desktop` is empty only where nothing
    /// says what the worker is bound to, as when it could not be asked; a row that has an identity
    /// keeps it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn adopt_worker(
        &mut self,
        worker: &WorkerRecord,
        desktop: Option<&DesktopBinding>,
    ) -> Result<()> {
        let recorded = self.to_record(worker.session_id, &worker.process_identity)?;
        let (desktop_session, login_generation) = desktop.map_or((None, None), desktop_columns);
        self.connection
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state, stated_source,
                     desktop_session_id, login_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state,
                     stated_source = excluded.stated_source,
                     desktop_session_id = CASE WHEN ?13 THEN excluded.desktop_session_id
                                               ELSE workers.desktop_session_id END,
                     login_generation = CASE WHEN ?13 THEN excluded.login_generation
                                             ELSE workers.login_generation END",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(recorded.pid.get()).unwrap_or(i64::MAX),
                    source_name(recorded.source),
                    start_column(recorded.start_value.get()),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
                    source_name(worker.process_identity.source),
                    desktop_session,
                    login_generation,
                    desktop.is_some(),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns every worker the registry knows about.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn workers(&self) -> Result<Vec<WorkerRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT session_id, display_number, public_key, process_pid, process_source,
                        process_start, endpoint, profile, state, acknowledged_revision
                 FROM workers ORDER BY display_number",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(ControllerError::registry)?;
        let mut workers = Vec::new();
        for row in rows {
            let (session, display, key, pid, source, start, endpoint, profile, state, revision) =
                row.map_err(ControllerError::registry)?;
            workers.push(WorkerRecord {
                session_id: SessionId::new(uuid_from(&session)?),
                display_number: DisplayNumber::new(u64::try_from(display).unwrap_or_default()),
                public_key: key_from(&key)?,
                process_identity: ProcessStartIdentity {
                    pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                    source: source_from(&source)?,
                    start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
                },
                endpoint,
                profile: profile_from(&profile)?,
                state: state_from(&state)?,
                acknowledged_revision: AuthorityRevision::new(
                    u64::try_from(revision).unwrap_or_default(),
                ),
            });
        }
        Ok(workers)
    }

    /// Returns the desktop identity a session's worker is bound to, or `None` when the registry
    /// holds no worker for the session.
    ///
    /// A worker bound to no desktop, or one an earlier build recorded, reads back as bound to
    /// none.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails or a stored identity
    /// cannot be read.
    pub fn desktop_of(&self, session_id: SessionId) -> Result<Option<DesktopBinding>> {
        let stored: Option<(Option<String>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT desktop_session_id, login_generation FROM workers WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        stored
            .map(|(desktop, generation)| {
                let desktop_session_id =
                    desktop
                        .map(DesktopSessionId::new)
                        .transpose()
                        .map_err(|error| {
                            ControllerError::registry(format!(
                                "a worker's recorded desktop identity cannot be read: {error}"
                            ))
                        })?;
                Ok(DesktopBinding {
                    desktop_session_id: desktop_session_id.into(),
                    login_generation: generation
                        .map(|generation| {
                            kr_protocol::scalars::U64::new(generation.cast_unsigned())
                        })
                        .into(),
                })
            })
            .transpose()
    }

    /// Records a closed session and removes its worker row.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_closure(&mut self, record: &ClosureRecord) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(record).map_err(ControllerError::registry)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO tombstones (session_id, record, closed_at_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (session_id) DO UPDATE SET record = excluded.record",
                params![
                    record.session_id.get().as_bytes().as_slice(),
                    encoded,
                    i64::try_from(record.closed_at_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM workers WHERE session_id = ?1",
                params![record.session_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE session_id = ?1",
                params![
                    record.session_id.get().as_bytes().as_slice(),
                    LaunchPhase::Closed.as_str()
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Reads the closure record of a session that has closed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn closure(&self, session_id: SessionId) -> Result<Option<ClosureRecord>> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT record FROM tombstones WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        encoded
            .map(|bytes| {
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(ControllerError::registry)
            })
            .transpose()
    }
}

impl Registry {
    /// Reads every closure record, with the session it closed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails or a record cannot be
    /// read back.
    pub fn closures(&self) -> Result<Vec<(SessionId, ClosureRecord)>> {
        let mut statement = self
            .connection
            .prepare("SELECT session_id, record FROM tombstones ORDER BY session_id")
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(ControllerError::registry)?;
        let mut closures = Vec::new();
        for row in rows {
            let (session, record) = row.map_err(ControllerError::registry)?;
            let session: [u8; 16] = session.as_slice().try_into().map_err(|_| {
                ControllerError::registry("a closure names a session this build cannot read")
            })?;
            let record: ClosureRecord =
                kr_cbor::from_canonical_slice(&record, &kr_cbor::Limits::DEFAULT)
                    .map_err(ControllerError::registry)?;
            closures.push((
                SessionId::new(kr_protocol::scalars::Uuid::from_bytes(session)),
                record,
            ));
        }
        Ok(closures)
    }
}

struct RawReservation {
    reservation: Vec<u8>,
    actor: String,
    token: Vec<u8>,
    digest: Vec<u8>,
    session: Vec<u8>,
    display: i64,
    phase: String,
    pid: Option<i64>,
    source: Option<String>,
    start: Option<i64>,
    created: i64,
    create_intent: Option<Vec<u8>>,
    claimed_key: Option<Vec<u8>>,
}

impl RawReservation {
    fn into_reservation(self) -> Result<Reservation> {
        Ok(Reservation {
            reservation_id: ReservationId::new(uuid_from(&self.reservation)?),
            actor_id: ActorId::new(self.actor)
                .map_err(|_| ControllerError::registry("a stored actor is not valid"))?,
            create_token: uuid_from(&self.token)?,
            payload_digest: digest_from(&self.digest)?,
            create_intent: self.create_intent,
            session_id: SessionId::new(uuid_from(&self.session)?),
            display_number: DisplayNumber::new(u64::try_from(self.display).unwrap_or_default()),
            phase: LaunchPhase::parse(&self.phase)
                .ok_or_else(|| ControllerError::registry("a stored launch phase is not known"))?,
            launcher_identity: match (self.pid, self.source, self.start) {
                (Some(pid), Some(source), Some(start)) => Some(ProcessStartIdentity {
                    pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                    source: source_from(&source)?,
                    start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
                }),
                _ => None,
            },
            claimed_key: self.claimed_key.as_deref().map(key_from).transpose()?,
            created_at_ms: TimestampMs::new(u64::try_from(self.created).unwrap_or_default()),
        })
    }
}

/// What admitting a create request produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The reservation, new or retained.
    pub reservation: Reservation,
    /// True when an existing reservation was returned rather than a new one recorded.
    pub deduplicated: bool,
}

/// Returns the stored form of where a process start value came from.
const fn source_name(source: ProcessStartSource) -> &'static str {
    match source {
        ProcessStartSource::LinuxProcStat => "linux_proc_stat",
        ProcessStartSource::MacosProcBsdInfo => "macos_proc_bsd_info",
        ProcessStartSource::WindowsProcessCreationTime => "windows_process_creation_time",
        // What a worker of the previous build states, and what this registry recorded for one.
        // It goes with the source itself: in the first release after one in which every running
        // worker states the creation time.
        ProcessStartSource::WindowsProcessStartSeconds => "windows_process_start_seconds",
    }
}

/// Reads back what [`source_name`] wrote, and refuses anything else.
fn source_from(text: &str) -> Result<ProcessStartSource> {
    match text {
        "linux_proc_stat" => Ok(ProcessStartSource::LinuxProcStat),
        "macos_proc_bsd_info" => Ok(ProcessStartSource::MacosProcBsdInfo),
        "windows_process_creation_time" => Ok(ProcessStartSource::WindowsProcessCreationTime),
        "windows_process_start_seconds" => Ok(ProcessStartSource::WindowsProcessStartSeconds),
        _ => Err(ControllerError::registry(
            "a stored process identity source is not known",
        )),
    }
}

/// Returns a start value as a column stores it.
///
/// A column holds a signed integer, and no platform's start value comes near the top of that range:
/// the one value above it is the marker of a process that had ended before anything read it, which
/// is stored as the largest value the column holds and read back by [`start_from_column`] as the
/// marker.
fn start_column(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reads back what [`start_column`] wrote.
fn start_from_column(value: i64) -> u64 {
    if value == i64::MAX {
        kr_ipc::identity::START_VALUE_UNREAD
    } else {
        u64::try_from(value).unwrap_or_default()
    }
}

/// Hundreds of nanoseconds in one second: a Windows creation time's unit.
const CREATION_TIME_UNITS_PER_SECOND: u64 = 10_000_000;

/// A record the previous build made of a Windows process: its creation time in whole seconds.
fn in_whole_seconds(pid: i64, start: i64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        u64::try_from(pid).unwrap_or_default(),
        ProcessStartSource::WindowsProcessStartSeconds,
        start_from_column(start),
    )
}

fn profile_from(text: &str) -> Result<WorkerProfile> {
    match text {
        "desktop_bound" => Ok(WorkerProfile::DesktopBound),
        "headless_user" => Ok(WorkerProfile::HeadlessUser),
        _ => Err(ControllerError::registry(
            "a stored worker profile is not known",
        )),
    }
}

fn state_from(text: &str) -> Result<SessionState> {
    SessionState::ALL
        .iter()
        .copied()
        .find(|state| state.as_str() == text)
        .ok_or_else(|| ControllerError::registry("a stored session state is not known"))
}

/// What a recorded create request comes to once the creator's environment is taken out of it.
enum Emptied {
    /// It held none, in this build's shape.
    Unchanged,
    /// The request as this build records one, with no environment.
    Rewritten(Vec<u8>),
    /// It is in no shape this build reads, so nothing says it holds no environment.
    Unreadable,
}

/// A create request as a build before the launch profile recorded it, which is read once, by the
/// migration that empties its environment, and never again.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EarlierCreate {
    environment_id: EnvironmentId,
    presentation: kr_protocol::session::Presentation,
    shell: kr_protocol::scalars::Nullable<String>,
    shell_mode: kr_protocol::session::ShellMode,
    cwd: kr_protocol::scalars::Nullable<String>,
    dimensions: kr_protocol::scalars::Nullable<kr_protocol::session::Dimensions>,
    worker_profile: WorkerProfile,
    environment_snapshot: Vec<kr_protocol::session::EnvironmentVariable>,
    palette: kr_protocol::scalars::Nullable<kr_protocol::session::PaletteRequest>,
}

impl From<EarlierCreate> for SessionCreateParams {
    /// Gives the launch profile and the terminal selection the defaults that session was created
    /// with.
    fn from(earlier: EarlierCreate) -> Self {
        Self {
            environment_id: earlier.environment_id,
            presentation: earlier.presentation,
            shell: earlier.shell,
            shell_mode: earlier.shell_mode,
            cwd: earlier.cwd,
            dimensions: earlier.dimensions,
            worker_profile: earlier.worker_profile,
            environment_snapshot: earlier.environment_snapshot,
            palette: earlier.palette,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: kr_protocol::scalars::Nullable::null(),
        }
    }
}

/// Takes the creator's environment out of a recorded create request.
fn without_environment(intent: &[u8]) -> Emptied {
    let limits = kr_cbor::Limits::DEFAULT;
    let (mut create, current) =
        match kr_cbor::from_canonical_slice::<SessionCreateParams>(intent, &limits) {
            Ok(create) => (create, true),
            Err(_) => match kr_cbor::from_canonical_slice::<EarlierCreate>(intent, &limits) {
                Ok(earlier) => (earlier.into(), false),
                Err(_) => return Emptied::Unreadable,
            },
        };
    if current && create.environment_snapshot.is_empty() {
        return Emptied::Unchanged;
    }
    create.environment_snapshot.clear();
    kr_cbor::to_canonical_vec(&create).map_or(Emptied::Unreadable, Emptied::Rewritten)
}

/// The error a compaction that did not finish ends the start with: what happened and what to do.
fn not_compacted(error: rusqlite::Error) -> ControllerError {
    let cause = match &error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::DiskFull =>
        {
            "there is no room for it. Free space in the directory that holds the registry and in \
             the directory SQLite keeps temporary files in (on Unix, the first of SQLITE_TMPDIR, \
             TMPDIR, /var/tmp, /usr/tmp, /tmp and the working directory that it can write to; on \
             Windows, the directory that TMP, TEMP or USERPROFILE names, otherwise the Windows \
             directory), each up to the size of the registry file"
                .to_owned()
        }
        other => format!("SQLite said: {other}"),
    };
    ControllerError::RegistryUnavailable {
        detail: format!(
            "this registry's recorded create requests were rewritten without the environment \
             their creators sent, but the registry could not be compacted to remove the old \
             copies: {cause}. Then start the daemon again"
        ),
    }
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(Uuid::from_bytes)
        .map_err(|_| ControllerError::registry("a stored identifier is not 16 bytes"))
}

fn digest_from(bytes: &[u8]) -> Result<Digest256> {
    <[u8; 32]>::try_from(bytes)
        .map(Digest256::from_bytes)
        .map_err(|_| ControllerError::registry("a stored digest is not 32 bytes"))
}

fn key_from(bytes: &[u8]) -> Result<AuthorisationKey> {
    <[u8; 32]>::try_from(bytes)
        .map(AuthorisationKey::from_bytes)
        .map_err(|_| ControllerError::registry("a stored public key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use kr_ipc::identity::START_VALUE_UNREAD;
    use kr_protocol::scalars::U64;

    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([7; 16]))
    }

    /// Hundreds of nanoseconds in one second.
    const PER_SECOND: u64 = 10_000_000;

    /// A second of September 2025, as the previous build recorded a Windows start.
    const SECOND: u64 = 1_758_700_000;

    /// What the kernel says about each process these tests recorded in whole seconds.
    ///
    /// 1001 and 1005 are running, created a moment into that second; 1002 has gone; the kernel will
    /// not describe 1003. Any other process is not one a test recorded in whole seconds, and asking
    /// about it fails the test.
    fn kernel(recorded: &ProcessStartIdentity) -> CurrentProcess {
        assert_eq!(
            recorded.source,
            ProcessStartSource::WindowsProcessStartSeconds,
            "only a record in whole seconds is put to the kernel"
        );
        match recorded.pid.get() {
            pid @ (1001 | 1005) => CurrentProcess::Running(finer(pid)),
            1002 => CurrentProcess::Ended,
            1003 => CurrentProcess::Unknown {
                detail: "Access is denied.".to_owned(),
            },
            other => panic!("process {other} was never recorded in whole seconds"),
        }
    }

    /// The same kernel once process 1003 can be described, and is running.
    fn kernel_later(recorded: &ProcessStartIdentity) -> CurrentProcess {
        match recorded.pid.get() {
            1003 => CurrentProcess::Running(finer(1003)),
            _ => kernel(recorded),
        }
    }

    /// A process created a moment into [`SECOND`], at the resolution this build reads.
    fn finer(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            pid,
            ProcessStartSource::WindowsProcessCreationTime,
            SECOND * PER_SECOND + 1_234_567,
        )
    }

    fn in_seconds(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::WindowsProcessStartSeconds, SECOND)
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// Writes a registry the way the previous build left it: schema version 3, with a worker and
    /// its reservation for each of `workers`, and a spawned reservation with no worker yet for
    /// each of `launches`, every process recorded as given.
    fn previous_build_registry(
        path: &std::path::Path,
        workers: &[(u8, ProcessStartIdentity)],
        launches: &[(u8, ProcessStartIdentity)],
    ) {
        let connection = Connection::open(path).expect("opens");
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (3);
                 CREATE TABLE environment (
                     environment_id      BLOB PRIMARY KEY,
                     generation          INTEGER NOT NULL,
                     next_display        INTEGER NOT NULL,
                     session_limit       INTEGER NOT NULL,
                     authority_revision  INTEGER NOT NULL DEFAULT 0,
                     fence_owed_revision INTEGER NOT NULL DEFAULT 0,
                     accepted_revision   INTEGER NOT NULL DEFAULT 0,
                     accepted_document   TEXT
                 );
                 CREATE TABLE reservations (
                     reservation_id    BLOB PRIMARY KEY,
                     actor_id          TEXT NOT NULL,
                     create_token      BLOB NOT NULL,
                     payload_digest    BLOB NOT NULL,
                     create_intent     BLOB,
                     session_id        BLOB NOT NULL UNIQUE,
                     display_number    INTEGER NOT NULL UNIQUE,
                     phase             TEXT NOT NULL,
                     launcher_pid      INTEGER,
                     launcher_source   TEXT,
                     launcher_start    INTEGER,
                     claimed_key       BLOB,
                     created_at_ms     INTEGER NOT NULL,
                     UNIQUE (actor_id, create_token)
                 );
                 CREATE TABLE workers (
                     session_id       BLOB PRIMARY KEY,
                     display_number   INTEGER NOT NULL,
                     public_key       BLOB NOT NULL,
                     process_pid      INTEGER NOT NULL,
                     process_source   TEXT NOT NULL,
                     process_start    INTEGER NOT NULL,
                     endpoint         TEXT NOT NULL,
                     profile          TEXT NOT NULL,
                     state            TEXT NOT NULL,
                     acknowledged_revision INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE tombstones (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL,
                     closed_at_ms INTEGER NOT NULL
                 );",
            )
            .expect("creates the previous schema");
        let reserve = |byte: u8, phase: &str, process: &ProcessStartIdentity| {
            connection
                .execute(
                    "INSERT INTO reservations (reservation_id, actor_id, create_token,
                         payload_digest, session_id, display_number, phase, launcher_pid,
                         launcher_source, launcher_start, created_at_ms)
                     VALUES (?1, 'local:501', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 100)",
                    params![
                        vec![byte; 16],
                        vec![byte.wrapping_add(100); 16],
                        vec![3_u8; 32],
                        session(byte).get().as_bytes().as_slice(),
                        i64::from(byte),
                        phase,
                        i64::try_from(process.pid.get()).expect("a small identifier"),
                        source_name(process.source),
                        i64::try_from(process.start_value.get()).expect("a small start value"),
                    ],
                )
                .expect("records a reservation the previous build made");
        };
        for (byte, process) in workers {
            reserve(*byte, "live", process);
            connection
                .execute(
                    "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                         process_source, process_start, endpoint, profile, state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'worker', 'headless_user', 'live')",
                    params![
                        session(*byte).get().as_bytes().as_slice(),
                        i64::from(*byte),
                        vec![*byte; 32],
                        i64::try_from(process.pid.get()).expect("a small identifier"),
                        source_name(process.source),
                        i64::try_from(process.start_value.get()).expect("a small start value"),
                    ],
                )
                .expect("records a worker the previous build started");
        }
        for (byte, process) in launches {
            reserve(*byte, "spawned", process);
        }
    }

    fn opened(
        path: &std::path::Path,
        kernel: fn(&ProcessStartIdentity) -> CurrentProcess,
    ) -> Registry {
        Registry::prepare_reading(
            Connection::open(path).expect("opens"),
            environment(),
            kernel,
        )
        .expect("brings the registry forward")
    }

    fn worker(registry: &Registry, byte: u8) -> ProcessStartIdentity {
        registry
            .workers()
            .expect("reads the workers")
            .into_iter()
            .find(|worker| worker.session_id == session(byte))
            .expect("the worker is recorded")
            .process_identity
    }

    fn stated(registry: &Registry, byte: u8) -> String {
        registry
            .connection
            .query_row(
                "SELECT stated_source FROM workers WHERE session_id = ?1",
                params![session(byte).get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("reads what the worker states")
    }

    fn launcher(registry: &Registry, byte: u8) -> ProcessStartIdentity {
        registry
            .reservation_for_session(session(byte))
            .expect("reads the reservation")
            .expect("the reservation is recorded")
            .launcher_identity
            .expect("the launcher is recorded")
    }

    /// A registry the previous build left at version 4 opens at the current version, with no clock
    /// floor and no lost continuity recorded: what a registry that created no floor holds.
    #[test]
    fn a_version_4_registry_opens_with_no_floor_recorded() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        drop(opened(&path, kernel));
        let connection = Connection::open(&path).expect("reopened");
        connection
            .execute_batch(
                "DROP TABLE utc_floors;
                 DROP TABLE clock_continuity;
                 UPDATE schema_version SET version = 4;",
            )
            .expect("the previous schema");
        drop(connection);
        let registry = opened(&path, kernel);
        let version: i64 = registry
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version");
        assert_eq!(version, SCHEMA_VERSION);
        let boot = BootEpoch::new(3);
        assert!(registry.floors_of_boot(boot).expect("readable").is_empty());
        assert!(!registry.clock_continuity_lost(boot).expect("readable"));
    }

    /// Each boot keeps its own floors and its own clock continuity: a later floor of a boot takes
    /// the place in force, a lost continuity stays lost until the owner establishes the clock, and
    /// nothing of another boot survives the start that forgets it.
    #[test]
    fn each_boot_keeps_its_own_floors_and_its_clock_continuity() {
        let directory = tempfile::tempdir().expect("a directory");
        let mut registry = opened(&directory.path().join("registry.sqlite3"), kernel);
        let boot = BootEpoch::new(7);
        let other = BootEpoch::new(8);
        let first = kr_ipc::floor::FloorIdentity::from_bytes([1; 16]);
        let second = kr_ipc::floor::FloorIdentity::from_bytes([2; 16]);
        registry
            .record_floor_in_force(boot, first, TimestampMs::new(1))
            .expect("recorded");
        assert_eq!(
            registry.floors_of_boot(boot).expect("readable"),
            vec![RecordedFloor {
                identity: first,
                in_force: true
            }]
        );

        registry
            .lose_clock_continuity(boot, TimestampMs::new(2))
            .expect("lost");
        registry
            .record_floor_in_force(boot, second, TimestampMs::new(3))
            .expect("recorded");
        assert_eq!(
            registry.floors_of_boot(boot).expect("readable"),
            vec![
                RecordedFloor {
                    identity: first,
                    in_force: false
                },
                RecordedFloor {
                    identity: second,
                    in_force: true
                },
            ]
        );
        assert!(registry.clock_continuity_lost(boot).expect("readable"));
        assert!(!registry.clock_continuity_lost(other).expect("readable"));

        registry
            .establish_clock_continuity(boot, TimestampMs::new(4))
            .expect("established");
        assert!(!registry.clock_continuity_lost(boot).expect("readable"));

        registry
            .record_floor_in_force(
                other,
                kr_ipc::floor::FloorIdentity::from_bytes([3; 16]),
                TimestampMs::new(5),
            )
            .expect("recorded");
        registry.forget_other_boots(other).expect("forgotten");
        assert!(registry.floors_of_boot(boot).expect("readable").is_empty());
        assert_eq!(registry.floors_of_boot(other).expect("readable").len(), 1);
    }

    #[test]
    fn records_the_previous_build_made_in_whole_seconds_are_settled_where_the_kernel_can_say() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let elsewhere = ProcessStartIdentity::new(1004, ProcessStartSource::MacosProcBsdInfo, 9);
        previous_build_registry(
            &path,
            &[
                (1, in_seconds(1001)),
                (2, in_seconds(1002)),
                (3, in_seconds(1003)),
                (4, elsewhere.clone()),
            ],
            &[(5, in_seconds(1005))],
        );

        let registry = opened(&path, kernel);
        let version: i64 = registry
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version");
        assert_eq!(version, SCHEMA_VERSION);
        // Running: recorded at the resolution this build reads, the worker and its launcher alike.
        assert_eq!(worker(&registry, 1), finer(1001));
        assert_eq!(launcher(&registry, 1), finer(1001));
        assert_eq!(launcher(&registry, 5), finer(1005));
        // Gone: marked ended, not rewritten, and read as ended without asking the kernel about
        // whatever holds the identifier now.
        for ended in [worker(&registry, 2), launcher(&registry, 2)] {
            assert_eq!(ended.pid.get(), 1002);
            assert_eq!(ended.start_value.get(), START_VALUE_UNREAD);
            assert_eq!(
                kr_ipc::identity::process_state(&ended),
                kr_ipc::identity::ProcessState::Ended
            );
        }
        // Not described: left as the previous build recorded it, for the next opening.
        assert_eq!(worker(&registry, 3), in_seconds(1003));
        assert_eq!(launcher(&registry, 3), in_seconds(1003));
        // Never in whole seconds: never put to the kernel, and left alone.
        assert_eq!(worker(&registry, 4), elsewhere);
        // What each worker states is what the previous build recorded for it.
        for byte in 1..=3 {
            assert_eq!(stated(&registry, byte), "windows_process_start_seconds");
        }
        assert_eq!(stated(&registry, 4), "macos_proc_bsd_info");
        drop(registry);

        // The next opening asks again about the one record the kernel would not describe, and
        // about nothing else.
        let registry = opened(&path, kernel_later);
        assert_eq!(worker(&registry, 3), finer(1003));
        assert_eq!(launcher(&registry, 3), finer(1003));
        assert_eq!(worker(&registry, 1), finer(1001));
        assert_eq!(stated(&registry, 3), "windows_process_start_seconds");
    }

    /// A create request as this build records one, naming `value` in the creator's environment.
    fn create_naming(value: &str) -> SessionCreateParams {
        SessionCreateParams {
            environment_id: environment(),
            presentation: kr_protocol::session::Presentation::Terminal,
            shell: kr_protocol::scalars::Nullable::some("zsh".to_owned()),
            shell_mode: kr_protocol::session::ShellMode::Managed,
            cwd: kr_protocol::scalars::Nullable::some("/work".to_owned()),
            dimensions: kr_protocol::scalars::Nullable::null(),
            worker_profile: WorkerProfile::DesktopBound,
            environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
                name: "SECRET_NAME".to_owned(),
                value: value.to_owned(),
            }],
            palette: kr_protocol::scalars::Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: kr_protocol::scalars::Nullable::null(),
        }
    }

    /// The same request in the shape a build before the launch profile recorded.
    fn earlier_create_naming(value: &str) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Earlier {
            environment_id: EnvironmentId,
            presentation: kr_protocol::session::Presentation,
            shell: kr_protocol::scalars::Nullable<String>,
            shell_mode: kr_protocol::session::ShellMode,
            cwd: kr_protocol::scalars::Nullable<String>,
            dimensions: kr_protocol::scalars::Nullable<kr_protocol::session::Dimensions>,
            worker_profile: WorkerProfile,
            environment_snapshot: Vec<kr_protocol::session::EnvironmentVariable>,
            palette: kr_protocol::scalars::Nullable<kr_protocol::session::PaletteRequest>,
        }
        let current = create_naming(value);
        kr_cbor::to_canonical_vec(&Earlier {
            environment_id: current.environment_id,
            presentation: current.presentation,
            shell: current.shell,
            shell_mode: current.shell_mode,
            cwd: current.cwd,
            dimensions: current.dimensions,
            worker_profile: current.worker_profile,
            environment_snapshot: current.environment_snapshot,
            palette: current.palette,
        })
        .expect("encodes")
    }

    /// Writes a registry as the build before this one left it, schema version 6, with a
    /// reservation recording each of `intents` (none for a reservation an older schema made
    /// without one), each moved through two phases so that the row is written more than once.
    fn registry_at_version_6(path: &std::path::Path, intents: &[Option<Vec<u8>>]) {
        let mut registry = opened(path, kernel);
        for intent in intents {
            let admission = registry
                .reserve(
                    &ActorId::new("local:501").expect("an actor"),
                    kr_ipc::new_uuid(),
                    Digest256::from_bytes([3; 32]),
                    intent.as_deref().unwrap_or_default(),
                    TimestampMs::new(100),
                )
                .expect("reserves");
            let id = admission.reservation.reservation_id;
            registry.set_phase(id, LaunchPhase::Spawned).expect("moves");
            registry.set_phase(id, LaunchPhase::Failed).expect("moves");
            if intent.is_none() {
                registry
                    .connection
                    .execute(
                        "UPDATE reservations SET create_intent = NULL WHERE reservation_id = ?1",
                        params![id.get().as_bytes().as_slice()],
                    )
                    .expect("clears it");
            }
        }
        registry
            .connection
            .execute("UPDATE schema_version SET version = 6", [])
            .expect("labels it as the build before did");
    }

    /// Everything in the registry's file and the files beside it, as bytes.
    fn bytes_of(path: &std::path::Path) -> Vec<u8> {
        let mut all = std::fs::read(path).expect("the registry's file is read");
        for suffix in ["-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            match std::fs::read(std::path::PathBuf::from(name)) {
                Ok(bytes) => all.extend(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("the registry's {suffix} file could not be read: {error}"),
            }
        }
        all
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    fn recorded_intents(registry: &Registry) -> Vec<Option<Vec<u8>>> {
        let mut statement = registry
            .connection
            .prepare("SELECT create_intent FROM reservations ORDER BY display_number")
            .expect("prepares");
        statement
            .query_map([], |row| row.get(0))
            .expect("reads")
            .collect::<std::result::Result<_, _>>()
            .expect("collects")
    }

    fn version(registry: &Registry) -> i64 {
        registry
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version")
    }

    /// A registry the build before this one wrote opens at the current version with every recorded
    /// request emptied of the creator's environment and still a create request, and none of the
    /// old bytes are in the file, its write-ahead log or its shared-memory file.
    #[test]
    fn a_version_6_registry_comes_forward_without_the_environments_it_recorded() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let none_in_it = {
            let mut create = create_naming("unused");
            create.environment_snapshot.clear();
            kr_cbor::to_canonical_vec(&create).expect("encodes")
        };
        registry_at_version_6(
            &path,
            &[
                Some(kr_cbor::to_canonical_vec(&create_naming("first-secret")).expect("encodes")),
                Some(earlier_create_naming("second-secret")),
                Some(b"third-secret is in no shape".to_vec()),
                Some(none_in_it.clone()),
                None,
            ],
        );
        let before = bytes_of(&path);
        for secret in ["first-secret", "second-secret", "third-secret"] {
            assert!(contains(&before, secret), "{secret} starts in the file");
        }

        let registry = opened(&path, kernel);
        assert_eq!(version(&registry), SCHEMA_VERSION);
        let intents = recorded_intents(&registry);
        let emptied = |bytes: &Option<Vec<u8>>| {
            kr_cbor::from_canonical_slice::<SessionCreateParams>(
                bytes.as_deref().expect("a record"),
                &kr_cbor::Limits::DEFAULT,
            )
            .expect("still reads as a create request")
        };
        for index in [0, 1] {
            let create = emptied(&intents[index]);
            assert!(create.environment_snapshot.is_empty());
            assert_eq!(create.worker_profile, WorkerProfile::DesktopBound);
            assert_eq!(
                create.cwd,
                kr_protocol::scalars::Nullable::some("/work".to_owned())
            );
        }
        assert_eq!(
            intents[2], None,
            "a record in no shape cannot be shown to hold nothing, so it is none"
        );
        assert_eq!(
            intents[3].as_deref(),
            Some(none_in_it.as_slice()),
            "one that held no variables is as it was"
        );
        assert_eq!(intents[4], None, "and none stays none");
        // While the registry is open, with its log in use: the file has been rebuilt and the log
        // emptied, so the old copies are in neither. Closing the last connection would checkpoint
        // and remove the log, and say nothing about a daemon that keeps the registry open.
        let open = bytes_of(&path);
        for secret in [
            "first-secret",
            "second-secret",
            "third-secret",
            "SECRET_NAME",
        ] {
            assert!(
                !contains(&open, secret),
                "{secret} is in the file or the log of a registry that is open"
            );
        }
        // And the log was truncated rather than only checkpointed: after a truncating checkpoint it
        // holds the one write that moved the version, where a checkpoint that keeps the log's
        // frames leaves a frame for each page the compaction wrote.
        let log_length = |suffix: &str| {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            std::fs::metadata(std::path::PathBuf::from(name)).map_or(0, |about| about.len())
        };
        assert!(
            log_length("-wal") < log_length(""),
            "the log of a registry that is open is shorter than its file"
        );
        drop(registry);

        let after = bytes_of(&path);
        for secret in [
            "first-secret",
            "second-secret",
            "third-secret",
            "SECRET_NAME",
        ] {
            assert!(
                !contains(&after, secret),
                "{secret} is still in the registry's file, its log or its shared memory"
            );
        }

        // Opened again, nothing moves: the step is idempotent.
        let again = opened(&path, kernel);
        assert_eq!(version(&again), SCHEMA_VERSION);
        assert_eq!(recorded_intents(&again), intents);
    }

    /// A compaction that fails stops the open with what happened and what to do, leaves the
    /// version where it was and the requests already emptied, and the next open finishes the step.
    #[test]
    fn a_compaction_that_fails_stops_the_open_and_the_next_open_finishes_it() {
        for (failure, wanted) in [
            (
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                "Free space in the directory that holds the registry",
            ),
            (
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                "SQLite said",
            ),
        ] {
            let directory = tempfile::tempdir().expect("a directory");
            let path = directory.path().join("registry.sqlite3");
            registry_at_version_6(
                &path,
                &[Some(
                    kr_cbor::to_canonical_vec(&create_naming("kept-secret")).expect("encodes"),
                )],
            );
            let stopped = Registry {
                connection: Connection::open(&path).expect("opens"),
                environment_id: environment(),
                current_process: kernel,
            };
            let error = stopped
                .migrate_6_to_7_compacting(|_| Err(rusqlite::Error::SqliteFailure(failure, None)))
                .expect_err("a compaction that fails stops the open");
            let said = error.to_string();
            assert!(said.contains(wanted), "{said}");
            assert!(
                said.contains("start the daemon again"),
                "the error names what to do: {said}"
            );
            assert_eq!(version(&stopped), 6, "the version stays where it was");
            assert!(
                matches!(&recorded_intents(&stopped)[0], Some(bytes)
                    if kr_cbor::from_canonical_slice::<SessionCreateParams>(
                        bytes, &kr_cbor::Limits::DEFAULT
                    ).is_ok_and(|create| create.environment_snapshot.is_empty())),
                "the requests were emptied before the compaction was tried"
            );
            drop(stopped);

            let finished = opened(&path, kernel);
            assert_eq!(version(&finished), SCHEMA_VERSION);
            drop(finished);
            assert!(!contains(&bytes_of(&path), "kept-secret"));
        }
    }

    /// A write-ahead log that cannot be emptied, because another connection is reading from it,
    /// stops the open too: the old copies would still be in it.
    #[test]
    fn a_log_that_cannot_be_emptied_stops_the_open() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        registry_at_version_6(
            &path,
            &[Some(
                kr_cbor::to_canonical_vec(&create_naming("logged-secret")).expect("encodes"),
            )],
        );
        // Another connection reading from the log as it stands keeps the rewrite's frames in it.
        let reader = Connection::open(&path).expect("opens");
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM reservations;")
            .expect("starts reading");
        let stopped = Registry {
            connection: Connection::open(&path).expect("opens"),
            environment_id: environment(),
            current_process: kernel,
        };
        let error = stopped
            .migrate_6_to_7_compacting(|_| Ok(()))
            .expect_err("a log that cannot be emptied stops the open");
        let said = error.to_string();
        assert!(said.contains("write-ahead log"), "{said}");
        assert!(said.contains("start the daemon again"), "{said}");
        assert_eq!(version(&stopped), 6);
    }

    /// A kernel that will not describe any process.
    fn kernel_silent(_recorded: &ProcessStartIdentity) -> CurrentProcess {
        CurrentProcess::Unknown {
            detail: "Access is denied.".to_owned(),
        }
    }

    /// A kernel in which the identifier asked about is held by a later process created in the
    /// same second as the one recorded.
    fn kernel_replaced(recorded: &ProcessStartIdentity) -> CurrentProcess {
        let mut later = finer(recorded.pid.get());
        later.start_value = U64::new(later.start_value.get() + 1);
        CurrentProcess::Running(later)
    }

    #[test]
    fn a_worker_that_states_whole_seconds_again_keeps_the_finer_record_and_what_it_states() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        previous_build_registry(&path, &[(1, in_seconds(1001))], &[]);
        let mut registry = opened(&path, kernel);
        assert_eq!(worker(&registry, 1), finer(1001));
        let record = WorkerRecord {
            session_id: session(1),
            display_number: DisplayNumber::new(1),
            public_key: AuthorisationKey::from_bytes([1; 32]),
            process_identity: in_seconds(1001),
            endpoint: "worker".to_owned(),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            acknowledged_revision: AuthorityRevision::new(0),
        };
        // A controller adopts the worker again from its own signed answer, which states whole
        // seconds. The finer identity the opening established is kept whatever the kernel would
        // say now: that it will not describe the process, or that a later process created in the
        // same second holds the identifier.
        for now in [
            kernel_silent as fn(&ProcessStartIdentity) -> CurrentProcess,
            kernel_replaced,
        ] {
            registry.current_process = now;
            registry
                .adopt_worker(&record, Some(&DesktopBinding::none()))
                .expect("adopts");
            assert_eq!(worker(&registry, 1), finer(1001));
            assert_eq!(stated(&registry, 1), "windows_process_start_seconds");
        }
        // A worker with no row yet that states whole seconds is settled as the opening settles
        // one.
        registry.current_process = kernel;
        let arriving = WorkerRecord {
            session_id: session(5),
            display_number: DisplayNumber::new(5),
            process_identity: in_seconds(1005),
            ..record.clone()
        };
        registry
            .adopt_worker(&arriving, Some(&DesktopBinding::none()))
            .expect("adopts");
        assert_eq!(worker(&registry, 5), finer(1005));
        assert_eq!(stated(&registry, 5), "windows_process_start_seconds");
        // One this build started states the creation time, which is recorded as it is.
        let current = WorkerRecord {
            session_id: session(9),
            display_number: DisplayNumber::new(9),
            process_identity: finer(1009),
            ..record
        };
        registry
            .adopt_worker(&current, Some(&DesktopBinding::none()))
            .expect("adopts");
        assert_eq!(worker(&registry, 9), finer(1009));
        assert_eq!(stated(&registry, 9), "windows_process_creation_time");
    }

    /// KR-REQ-24.01: a registry an earlier build wrote records no desktop identity, and reads with
    /// none for the workers it holds; a desktop recorded afterwards is kept across an opening.
    #[test]
    fn an_earlier_registrys_workers_read_with_no_desktop_and_a_recorded_one_is_kept() {
        use kr_protocol::identity::DesktopBinding;
        use kr_protocol::ids::DesktopSessionId;
        use kr_protocol::scalars::Nullable;

        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        previous_build_registry(&path, &[(1, finer(1001))], &[]);
        let mut registry = Registry::open(&path, environment()).expect("brings the registry on");
        assert_eq!(
            registry.desktop_of(session(1)).expect("reads"),
            Some(DesktopBinding::none()),
            "a worker an earlier build recorded is bound to no recorded desktop"
        );
        let desktop = DesktopBinding {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new("desktop-501-boot-9-login-4").expect("a desktop identity"),
            ),
            login_generation: Nullable::some(U64::new(4)),
        };
        let record = WorkerRecord {
            session_id: session(1),
            display_number: DisplayNumber::new(1),
            public_key: AuthorisationKey::from_bytes([1; 32]),
            process_identity: finer(1001),
            endpoint: "worker".to_owned(),
            profile: WorkerProfile::DesktopBound,
            state: SessionState::Live,
            acknowledged_revision: AuthorityRevision::new(0),
        };
        let reservation = registry
            .reservation_for_session(session(1))
            .expect("reads")
            .expect("the worker's reservation")
            .reservation_id;
        // Recording a worker promotes a claim, so the reservation the earlier build left is one.
        registry
            .connection
            .execute("UPDATE reservations SET phase = 'claimed'", [])
            .expect("the reservation is claimed");
        registry
            .record_worker(reservation, &record, &desktop)
            .expect("records the desktop");
        drop(registry);
        let registry = Registry::open(&path, environment()).expect("opens again");
        assert_eq!(
            registry.desktop_of(session(1)).expect("reads"),
            Some(desktop)
        );
    }

    #[test]
    fn a_launcher_that_ended_unread_is_read_back_as_ended() {
        let mut registry = Registry::in_memory(environment()).expect("a registry");
        let reservation = registry
            .reserve(
                &ActorId::new("local:501").expect("a principal"),
                Uuid::from_bytes([2; 16]),
                Digest256::from_bytes([3; 32]),
                b"intent",
                TimestampMs::new(1),
            )
            .expect("reserves")
            .reservation;
        let ended = kr_ipc::identity::ended_process_identity(4242);
        registry
            .record_launch(reservation.reservation_id, &ended)
            .expect("records the launcher");
        let read = registry
            .reservation(reservation.reservation_id)
            .expect("reads")
            .expect("the reservation")
            .launcher_identity
            .expect("the launcher");
        assert_eq!(read, ended, "the ended marker survives the column");
        assert_eq!(read.start_value, U64::new(START_VALUE_UNREAD));
    }

    /// A worker of the previous build still running after an upgrade: this process stands in for
    /// it, recorded in whole seconds as that build recorded it, beside a record of the same
    /// identifier created in another second.
    #[cfg(windows)]
    #[test]
    fn this_process_recorded_in_whole_seconds_is_settled_at_its_creation_time() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let current =
            kr_ipc::identity::current_process_start_identity().expect("this process's identity");
        let seconds = ProcessStartIdentity::new(
            current.pid.get(),
            ProcessStartSource::WindowsProcessStartSeconds,
            current.start_value.get() / PER_SECOND,
        );
        let mut another_second = seconds.clone();
        another_second.start_value = U64::new(seconds.start_value.get() - 1);
        previous_build_registry(&path, &[(1, seconds), (2, another_second)], &[]);

        let registry = Registry::open(&path, environment()).expect("brings the registry forward");
        assert_eq!(worker(&registry, 1), current);
        assert_eq!(launcher(&registry, 1), current);
        assert_eq!(stated(&registry, 1), "windows_process_start_seconds");
        let ended = worker(&registry, 2);
        assert_eq!(ended.start_value.get(), START_VALUE_UNREAD);
        assert_eq!(
            kr_ipc::identity::process_state(&ended),
            kr_ipc::identity::ProcessState::Ended
        );
    }

    /// A worker row of session `byte`, run by process `pid`.
    fn worker_row(byte: u8, pid: u64) -> WorkerRecord {
        WorkerRecord {
            session_id: session(byte),
            display_number: DisplayNumber::new(u64::from(byte)),
            public_key: AuthorisationKey::from_bytes([byte; 32]),
            process_identity: ProcessStartIdentity::new(pid, ProcessStartSource::LinuxProcStat, 7),
            endpoint: format!("/tmp/kr-registry-test-{byte}.sock"),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            acknowledged_revision: AuthorityRevision::new(0),
        }
    }

    #[test]
    fn a_registry_opened_to_read_is_read_as_it_is_or_refused() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        Registry::open_to_read(&path, environment()).expect_err("there is no registry to read");
        assert!(!path.exists(), "reading made no registry");

        Registry::open(&path, environment())
            .expect("a registry")
            .adopt_worker(&worker_row(1, 4_001), Some(&DesktopBinding::none()))
            .expect("records a worker");
        let read = Registry::open_to_read(&path, environment()).expect("a registry reads");
        assert_eq!(
            read.workers().expect("reads the workers"),
            vec![worker_row(1, 4_001)]
        );
        assert_eq!(read.closure(session(1)).expect("reads the closures"), None);
        drop(read);

        // What it is asked is read as it is. Another version is not brought forward to be read,
        // and a table that has gone is not made again, empty, to be read as saying nothing.
        let change = |sql: &str| {
            Connection::open(&path)
                .expect("a second connection")
                .execute_batch(sql)
                .expect("changes the registry");
        };
        change("UPDATE schema_version SET version = version - 1;");
        let refused =
            Registry::open_to_read(&path, environment()).expect_err("another version is refused");
        assert!(refused.to_string().contains("schema version"), "{refused}");
        change("UPDATE schema_version SET version = version + 1;");
        for table in ["tombstones", "workers"] {
            change(&format!("DROP TABLE {table};"));
            let refused = Registry::open_to_read(&path, environment())
                .expect_err("a registry without a table it is read from is refused");
            assert!(refused.to_string().contains(table), "{refused}");
        }
        let tables: i64 = Connection::open(&path)
            .expect("a second connection")
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('tombstones', 'workers')",
                [],
                |row| row.get(0),
            )
            .expect("reads the schema");
        assert_eq!(tables, 0, "reading repaired nothing");
    }

    /// Every file in `directory`, by name, with what it holds.
    fn files_in(directory: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
            .expect("reads the directory")
            .map(|entry| {
                let entry = entry.expect("an entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).expect("reads the file"),
                )
            })
            .collect();
        files.sort();
        files
    }

    #[test]
    fn a_registry_opened_to_read_writes_nothing_and_refuses_writes_its_file_has_not_taken_in() {
        // Reading is evidence-taking, so it leaves the directory exactly as it found it: no
        // write-ahead log or shared-memory file is made beside the registry, and nothing in it
        // changes. A write-ahead log that holds writes is refused rather than ignored or brought
        // in, because bringing it in is a write and ignoring it would read an older registry.
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        Registry::open(&path, environment())
            .expect("a registry")
            .adopt_worker(&worker_row(1, 4_001), Some(&DesktopBinding::none()))
            .expect("records a worker");
        let before = files_in(directory.path());
        assert_eq!(before.len(), 1, "a closed registry is one file: {before:?}");
        let read = Registry::open_to_read(&path, environment()).expect("a registry reads");
        assert_eq!(read.workers().expect("reads the workers").len(), 1);
        assert_eq!(files_in(directory.path()), before, "while it is read");
        drop(read);
        assert_eq!(files_in(directory.path()), before, "after it is read");

        // A writer that has not finished: its log holds a worker the file does not.
        let writer = Connection::open(&path).expect("a writer");
        writer
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("no checkpoint");
        writer
            .execute("DELETE FROM workers", [])
            .expect("the log holds a change");
        let held = files_in(directory.path());
        let refused = Registry::open_to_read(&path, environment())
            .expect_err("writes the file has not taken in are refused");
        assert!(refused.to_string().contains("write-ahead log"), "{refused}");
        assert_eq!(
            files_in(directory.path()),
            held,
            "a refusal changes nothing"
        );
        drop(writer);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_is_named_as_an_immutable_file_with_its_own_characters_escaped() {
        assert_eq!(
            immutable_uri(std::path::Path::new("/state/a b/r?e#g%1\\x.sqlite3")).as_deref(),
            Some("file:///state/a b/r%3fe%23g%251\\x.sqlite3?immutable=1")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_registry_reached_through_a_link_is_refused_rather_than_read_without_its_log() {
        // SQLite follows a link at the database's own name and keeps its write-ahead log beside
        // the file the link reaches, so a log looked for beside the link is not the one that holds
        // the writes. A registry reached that way is refused, and nothing changes.
        let directory = tempfile::tempdir().expect("a directory");
        let actual = directory.path().join("actual.sqlite3");
        Registry::open(&actual, environment())
            .expect("a registry")
            .adopt_worker(&worker_row(1, 4_001), Some(&DesktopBinding::none()))
            .expect("records a worker");
        let link = directory.path().join("registry.sqlite3");
        std::os::unix::fs::symlink(&actual, &link).expect("links the registry");
        // A writer that has not finished: its log, beside the file the link reaches, holds a
        // worker the file does not.
        let writer = Connection::open(&actual).expect("a writer");
        writer
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("no checkpoint");
        writer
            .execute("DELETE FROM workers", [])
            .expect("the log holds a change");
        let held = files_in(directory.path());
        let refused = Registry::open_to_read(&link, environment())
            .expect_err("a registry reached through a link is refused");
        assert!(refused.to_string().contains("link"), "{refused}");
        assert_eq!(
            files_in(directory.path()),
            held,
            "a refusal changes nothing"
        );
        drop(writer);
    }

    /// What a daemon that ended by a signal leaves, a log that holds its last writes, is taken into
    /// the file, and then read: the records are the ones the daemon wrote, and nothing else changed.
    #[test]
    fn a_log_a_daemon_left_is_taken_in_and_then_read() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        drop(Registry::open(&path, environment()).expect("a registry"));
        assert!(
            !Registry::take_in_its_log(&path).expect("nothing to take in"),
            "a closed registry holds no log"
        );
        // A daemon ended by a signal: its connection is never closed, and its log holds the write.
        let mut daemon = Registry::open(&path, environment()).expect("a registry");
        daemon
            .connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("no checkpoint");
        daemon.advance_generation().expect("a write the log holds");
        let refused = Registry::open_to_read(&path, environment()).expect_err("the log holds it");
        assert!(refused.to_string().contains("write-ahead log"), "{refused}");
        assert!(Registry::take_in_its_log(&path).expect("taken in"));
        let read = Registry::open_to_read(&path, environment()).expect("read after it");
        assert_eq!(read.generation().expect("reads").get(), 1);
        drop(read);
        std::mem::forget(daemon);
        // A registry that is a link is not opened: the reader refuses it, by its own words.
        #[cfg(unix)]
        {
            let link = directory.path().join("link.sqlite3");
            std::os::unix::fs::symlink(&path, &link).expect("a link");
            assert!(!Registry::take_in_its_log(&link).expect("left to the reader"));
            let refused = Registry::open_to_read(&link, environment()).expect_err("a link");
            assert!(refused.to_string().contains("link"), "{refused}");
        }
    }

    /// A registry in the shape the previous build left (version 3's), with the version it records
    /// set to `version`, the worker of session 1 and a spawned reservation for session 5. A test
    /// that brings it forward needs `version` to be 3; one that only reads it may say any.
    fn behind_registry(path: &std::path::Path, version: i64) {
        let elsewhere = ProcessStartIdentity::new(1004, ProcessStartSource::MacosProcBsdInfo, 9);
        previous_build_registry(path, &[(1, elsewhere.clone())], &[(5, elsewhere)]);
        Connection::open(path)
            .expect("opens")
            .execute(
                &format!("UPDATE schema_version SET version = {version}"),
                [],
            )
            .expect("a version");
    }

    /// The schema version a registry file records, read as the file alone.
    fn recorded(path: &std::path::Path) -> Vec<i64> {
        let connection = open_immutable(path).expect("reads");
        recorded_versions(&connection).expect("reads the versions")
    }

    /// An update carries the registry of an environment whose daemon did not run forward through the
    /// one chain a daemon's start runs: it reads at this build's schema, every row it held is the
    /// row it holds, and nothing is left beside the file.
    #[test]
    fn a_registry_behind_this_build_is_brought_forward_with_its_rows_and_nothing_beside_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        behind_registry(&path, 3);
        let before: Vec<i64> = {
            let connection = Connection::open(&path).expect("opens");
            let mut statement = connection
                .prepare("SELECT process_pid FROM workers ORDER BY session_id")
                .expect("prepares");
            statement
                .query_map([], |row| row.get(0))
                .expect("reads")
                .collect::<rusqlite::Result<_>>()
                .expect("rows")
        };
        assert_eq!(before, vec![1004]);

        let carried = Registry::bring_forward(&path, environment()).expect("brings it forward");
        assert_eq!(
            carried,
            Some(Carried {
                from: 3,
                to: SCHEMA_VERSION
            })
        );
        assert_eq!(
            files_in(directory.path())
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec!["registry.sqlite3".to_owned()],
            "a closed registry is one file"
        );
        let read = Registry::open_to_read(&path, environment()).expect("reads at this version");
        let workers = read.workers().expect("reads the workers");
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].session_id, session(1));
        assert_eq!(
            workers[0].process_identity,
            ProcessStartIdentity::new(1004, ProcessStartSource::MacosProcBsdInfo, 9)
        );
        assert_eq!(
            read.reservations_in(LaunchPhase::Spawned)
                .expect("reads")
                .len(),
            1,
            "the launch that came to nothing is still recorded"
        );
        drop(read);
        // Once at this version a second call finds nothing to bring.
        assert_eq!(
            Registry::bring_forward(&path, environment()).expect("nothing to do"),
            None
        );
    }

    /// A registry that is at this build's schema is not migrated, and one with no log to take in is
    /// not opened for writing, so it is not changed, and a registry that cannot be brought forward
    /// by this build is left as it is, for the reader to refuse in its own words.
    #[test]
    fn a_registry_that_is_not_behind_this_build_is_left_exactly_as_it_is() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let environment_id = environment();
        let left = |path: &std::path::Path| {
            let before = files_in(path.parent().expect("a directory"));
            assert_eq!(
                Registry::bring_forward(path, environment_id).expect("is left"),
                None
            );
            assert_eq!(files_in(path.parent().expect("a directory")), before);
        };
        // At this version.
        drop(Registry::open(&path, environment_id).expect("a registry"));
        left(&path);
        // At a later one.
        let change = |sql: &str| {
            Connection::open(&path)
                .expect("a second connection")
                .execute_batch(sql)
                .expect("changes the registry");
        };
        change(&format!(
            "UPDATE schema_version SET version = {};",
            SCHEMA_VERSION + 1
        ));
        left(&path);
        assert_eq!(recorded(&path), vec![SCHEMA_VERSION + 1]);
        // With no version, and with two.
        change("DELETE FROM schema_version;");
        left(&path);
        change("INSERT INTO schema_version (version) VALUES (3), (4);");
        left(&path);
        // With a version of 0, below the first.
        change("DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (0);");
        left(&path);
        // An empty file, which SQLite reads as a database with no tables.
        let empty = directory.path().join("empty.sqlite3");
        std::fs::write(&empty, b"").expect("an empty file");
        left(&empty);
        assert!(std::fs::read(&empty).expect("reads").is_empty());
        // A file that is not a database at all.
        let text = directory.path().join("text.sqlite3");
        std::fs::write(&text, b"this is not a database").expect("a file");
        left(&text);
        // None.
        assert_eq!(
            Registry::bring_forward(directory.path().join("none.sqlite3"), environment_id)
                .expect("nothing there"),
            None
        );
        assert!(!directory.path().join("none.sqlite3").exists());
    }

    /// An older registry that lost a table its rows are read from is refused by the table's name and
    /// left as it was: opening it would make the table again, empty, and a registry that records no
    /// worker is the answer a question about who may still hold a session's stores must never get
    /// by accident.
    #[test]
    fn an_older_registry_that_lost_an_evidence_table_is_refused_and_left() {
        for table in EVIDENCE_TABLES {
            let directory = tempfile::tempdir().expect("a directory");
            let path = directory.path().join("registry.sqlite3");
            behind_registry(&path, 4);
            Connection::open(&path)
                .expect("opens")
                .execute_batch(&format!("DROP TABLE {table};"))
                .expect("loses the table");
            let before = files_in(directory.path());
            let refused = Registry::bring_forward(&path, environment())
                .expect_err("a registry that lost a table is not brought forward");
            assert!(
                refused.to_string().contains(&format!("no {table} table")),
                "{refused}"
            );
            assert_eq!(files_in(directory.path()), before, "{table}");
            assert_eq!(recorded(&path), vec![4]);
        }
    }

    /// A step that fails leaves the registry at the version of the last step that committed, whole:
    /// the release that is current continues the chain from it. Labelled version 2 with the columns
    /// of version 3 gone and the column of version 4 already there, its first step commits and its
    /// second adds a column that is already there.
    #[test]
    fn a_step_that_fails_leaves_the_registry_at_the_version_of_the_last_step_that_committed() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        behind_registry(&path, 2);
        Connection::open(&path)
            .expect("opens")
            .execute_batch(
                "ALTER TABLE environment DROP COLUMN fence_owed_revision;
                 ALTER TABLE environment DROP COLUMN accepted_revision;
                 ALTER TABLE environment DROP COLUMN accepted_document;
                 ALTER TABLE workers ADD COLUMN stated_source TEXT NOT NULL DEFAULT '';",
            )
            .expect("the shape");
        let refused = Registry::bring_forward(&path, environment())
            .expect_err("the second step adds a column that is there");
        let said = refused.to_string();
        assert!(
            said.contains("schema version 2")
                && said.contains(&format!("schema version {SCHEMA_VERSION}"))
                && said.contains("stated_source"),
            "{said}"
        );
        assert_eq!(recorded(&path), vec![3], "the first step committed whole");
        let columns: i64 = open_immutable(&path)
            .expect("reads")
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('environment')
                 WHERE name = 'fence_owed_revision'",
                [],
                |row| row.get(0),
            )
            .expect("reads the columns");
        assert_eq!(columns, 1, "and what it did stays");
        // Once the cause is gone the chain goes on from where it stopped, and the rows are carried.
        Connection::open(&path)
            .expect("opens")
            .execute_batch("ALTER TABLE workers DROP COLUMN stated_source;")
            .expect("the cause is removed");
        let carried = Registry::bring_forward(&path, environment()).expect("goes on from there");
        assert_eq!(
            carried,
            Some(Carried {
                from: 3,
                to: SCHEMA_VERSION
            })
        );
        assert_eq!(
            Registry::open_to_read(&path, environment())
                .expect("reads at this version")
                .workers()
                .expect("reads the workers")
                .len(),
            1
        );
        assert!(
            files_in(directory.path()).len() == 1,
            "nothing is left beside the file: {:?}",
            files_in(directory.path())
                .iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>()
        );
    }

    /// What a daemon that ended by a signal left in its log is taken into the file before the
    /// version is read, so an older registry carries what the daemon last wrote.
    #[test]
    fn an_older_registry_with_a_log_a_daemon_left_is_carried_with_what_the_log_holds() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        behind_registry(&path, 3);
        let daemon = Connection::open(&path).expect("a daemon's connection");
        daemon
            .pragma_update(None, "journal_mode", "WAL")
            .expect("write-ahead logging");
        daemon
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("no checkpoint");
        daemon
            .execute("UPDATE workers SET endpoint = 'left in the log'", [])
            .expect("a write the log holds");
        let carried = Registry::bring_forward(&path, environment()).expect("brings it forward");
        assert_eq!(carried.map(|carried| carried.from), Some(3));
        let endpoint: String = open_immutable(&path)
            .expect("reads")
            .query_row("SELECT endpoint FROM workers", [], |row| row.get(0))
            .expect("reads the worker");
        assert_eq!(endpoint, "left in the log");
        std::mem::forget(daemon);
    }

    /// What is beside an older registry is looked at, never opened, before anything is: a pipe at
    /// the log, the journal or the shared-memory name, a link at the registry and a pipe in its
    /// place hold nothing up, and nothing is written.
    #[cfg(unix)]
    #[test]
    fn a_pipe_or_a_link_where_a_registry_or_its_files_are_is_refused_without_being_opened() {
        let make_pipe = |path: &std::path::Path| {
            let made = std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "a pipe is made");
        };
        for suffix in ["-wal", "-journal", "-shm"] {
            let directory = tempfile::tempdir().expect("a directory");
            let path = directory.path().join("registry.sqlite3");
            behind_registry(&path, 4);
            let mut beside = path.as_os_str().to_owned();
            beside.push(suffix);
            make_pipe(std::path::Path::new(&beside));
            // On a thread of its own, so that a wait for a writer fails the test and does not hang
            // it.
            let (sender, receiver) = std::sync::mpsc::channel();
            let at = path.clone();
            std::thread::spawn(move || {
                let _ = sender.send(Registry::bring_forward(&at, environment()));
            });
            let refused = receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("was not held up by a pipe")
                .expect_err("a pipe beside the registry is refused");
            assert!(
                refused.to_string().contains("not a regular file"),
                "{suffix}: {refused}"
            );
            assert_eq!(recorded(&path), vec![4], "{suffix}");
        }
        // A link where the log, the journal or the shared-memory file is named is refused the same
        // way, and nothing is opened.
        for suffix in ["-wal", "-journal", "-shm"] {
            let directory = tempfile::tempdir().expect("a directory");
            let path = directory.path().join("registry.sqlite3");
            behind_registry(&path, 4);
            let mut beside = path.as_os_str().to_owned();
            beside.push(suffix);
            std::os::unix::fs::symlink(directory.path().join("elsewhere"), &beside)
                .expect("a link");
            let refused = Registry::bring_forward(&path, environment())
                .expect_err("a link beside the registry is refused");
            assert!(
                refused.to_string().contains("not a regular file"),
                "{suffix}: {refused}"
            );
            assert_eq!(recorded(&path), vec![4], "{suffix}");
        }
        // A link at the registry, and a pipe in its place, are left for the reader.
        let directory = tempfile::tempdir().expect("a directory");
        let actual = directory.path().join("actual.sqlite3");
        behind_registry(&actual, 4);
        let link = directory.path().join("registry.sqlite3");
        std::os::unix::fs::symlink(&actual, &link).expect("a link");
        assert_eq!(
            Registry::bring_forward(&link, environment()).expect("left"),
            None
        );
        assert_eq!(recorded(&actual), vec![4], "what the link reaches is left");
        let pipe = directory.path().join("pipe.sqlite3");
        make_pipe(&pipe);
        let (sender, receiver) = std::sync::mpsc::channel();
        let at = pipe.clone();
        std::thread::spawn(move || {
            let _ = sender.send(Registry::bring_forward(&at, environment()));
        });
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("was not held up by a pipe")
                .expect("left"),
            None
        );
        let refused =
            Registry::open_to_read(&link, environment()).expect_err("the reader refuses a link");
        assert!(refused.to_string().contains("link"), "{refused}");
    }
}
