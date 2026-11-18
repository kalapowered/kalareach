//! The hold a device's voice start leaves while its outcome may be unknown, kept where a restart
//! finds it.
//!
//! A start that the voice service may have carried out, and whose answer the host never recorded,
//! leaves a call that a second start could repeat and charge for. The host writes one row for the
//! start before it asks the voice service, and removes it when the start's effect is known. While
//! the row stands, an unnamed start from the same device is refused; a start that names the
//! row's action is admitted in its place, and a row past its end is no hold.
//!
//! The row is kept for one paired device (the actor), so a second device never meets it. The
//! record is a database of its own, and not a table of the registry: the registry's schema is one
//! every release before this one has to read, and a hold nothing before this release asks for is
//! not a reason to move it. A release before this one never opens the file, so a rollback loses the
//! hold, and an update again finds the rows the earlier release left.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_protocol::ids::{ActionId, ActorId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::{ControllerError, Result};

/// The file the hold lives in.
pub const VOICE_START_HOLDS_RECORD: &str = "voice-start-holds.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// The hold one device's start left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The action of the start that left the hold.
    pub action: ActionId,
    /// The moment the host read the start, in milliseconds on the host's settled clock.
    pub asked_ms: u64,
    /// The moment after which the hold ends by itself, on the same clock.
    pub ends_ms: u64,
}

/// What `begin` decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The start is admitted and its row is written.
    Admitted,
    /// An earlier start holds the device and this start does not name it: nothing was written.
    Held(Row),
}

/// The holds the host keeps.
#[derive(Debug)]
pub struct Record {
    connection: Mutex<Connection>,
}

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn moment(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl Record {
    /// Opens the record in `state_dir`.
    ///
    /// A database that holds a schema this build does not read is refused before anything is
    /// written to it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection =
            kr_flush::release::open_connection(&state_dir.join(VOICE_START_HOLDS_RECORD), None)
                .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'voice_start_holds_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM voice_start_holds_schema", [], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(ControllerError::registry)?
        } else {
            None
        };
        if let Some(found) = version
            && found != SCHEMA_VERSION
        {
            return Err(ControllerError::registry(format!(
                "the record of voice start holds is at schema {found} and this build reads \
                 {SCHEMA_VERSION}"
            )));
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS voice_start_holds_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS voice_start_holds (
                     actor_id  TEXT PRIMARY KEY NOT NULL,
                     action_id TEXT NOT NULL,
                     asked_ms  INTEGER NOT NULL CHECK (asked_ms >= 0),
                     ends_ms   INTEGER NOT NULL CHECK (ends_ms >= asked_ms)
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO voice_start_holds_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Decides whether the start of `action` by `actor` is admitted, and writes its row when it is.
    ///
    /// One immediate transaction on one connection. A row that stands for `actor` holds the device
    /// unless `supersedes` names its action, or `bound_passed` says that the row's end has passed
    /// by the host's own decision; then the start's row replaces it. Rows past their end are
    /// deleted for every actor, but only where `floor_covers` says that the end is already on disk,
    /// so a sweep never rests on an unrecorded clock reading.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or written, or when `bound_passed` fails: the
    /// transaction is then rolled back and nothing is held.
    pub fn begin(
        &self,
        actor: ActorId,
        action: ActionId,
        supersedes: Option<ActionId>,
        asked_ms: u64,
        ends_ms: u64,
        bound_passed: &dyn Fn(u64) -> Result<bool>,
        floor_covers: &dyn Fn(u64) -> bool,
    ) -> Result<Decision> {
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let standing: Option<(String, i64, i64)> = transaction
            .query_row(
                "SELECT action_id, asked_ms, ends_ms FROM voice_start_holds WHERE actor_id = ?1",
                params![actor.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        if let Some((standing_action, standing_asked, standing_ends)) = standing {
            let names_it = supersedes.is_some_and(|named| named.to_string() == standing_action);
            if !names_it && !bound_passed(moment(standing_ends))? {
                if let Ok(held) = standing_action.parse::<ActionId>() {
                    return Ok(Decision::Held(Row {
                        action: held,
                        asked_ms: moment(standing_asked),
                        ends_ms: moment(standing_ends),
                    }));
                }
            }
        }
        // Rows past their end are deleted, for every actor, where the end is on disk.
        let ended: Vec<(String, i64)> = {
            let mut statement = transaction
                .prepare("SELECT actor_id, ends_ms FROM voice_start_holds")
                .map_err(ControllerError::registry)?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(ControllerError::registry)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ControllerError::registry)?
        };
        for (other, ends) in ended {
            if floor_covers(moment(ends)) {
                transaction
                    .execute(
                        "DELETE FROM voice_start_holds WHERE actor_id = ?1 AND ends_ms = ?2",
                        params![other, ends],
                    )
                    .map_err(ControllerError::registry)?;
            }
        }
        transaction
            .execute(
                "INSERT INTO voice_start_holds (actor_id, action_id, asked_ms, ends_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (actor_id) DO UPDATE SET
                     action_id = excluded.action_id,
                     asked_ms = excluded.asked_ms,
                     ends_ms = excluded.ends_ms",
                params![
                    actor.to_string(),
                    action.to_string(),
                    counter(asked_ms),
                    counter(ends_ms.max(asked_ms))
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(Decision::Admitted)
    }

    /// Ends the hold that the start of `action` left for `actor`. A row another start wrote since is
    /// not touched: the delete names the action.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be written: the row stays until its end or a named
    /// start.
    pub fn end(&self, actor: ActorId, action: ActionId) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        connection
            .execute(
                "DELETE FROM voice_start_holds WHERE actor_id = ?1 AND action_id = ?2",
                params![actor.to_string(), action.to_string()],
            )
            .map(|_| ())
            .map_err(ControllerError::registry)
    }

    /// The row that stands for `actor`, when one does.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn standing(&self, actor: ActorId) -> Result<Option<Row>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let found: Option<(String, i64, i64)> = connection
            .query_row(
                "SELECT action_id, asked_ms, ends_ms FROM voice_start_holds WHERE actor_id = ?1",
                params![actor.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        Ok(found.and_then(|(action, asked, ends)| {
            Some(Row {
                action: action.parse().ok()?,
                asked_ms: moment(asked),
                ends_ms: moment(ends),
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn actor(n: u8) -> ActorId {
        ActorId::new(format!("local:{n}")).expect("an actor")
    }

    fn action(n: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([n; 16]))
    }

    fn never(_: u64) -> Result<bool> {
        Ok(false)
    }

    fn open() -> (tempfile::TempDir, Record) {
        let directory = tempfile::tempdir().expect("a directory");
        let record = Record::open(directory.path()).expect("a new store opens");
        (directory, record)
    }

    /// A new store is created at version 1 and a reopened one keeps its rows.
    #[test]
    fn a_new_store_is_created_at_version_1_and_keeps_its_rows_across_a_reopen() {
        let (directory, record) = open();
        let admitted = record
            .begin(actor(1), action(1), None, 10, 100, &never, &|_| false)
            .expect("begin");
        assert_eq!(admitted, Decision::Admitted);
        drop(record);

        let again = Record::open(directory.path()).expect("reopens");
        let row = again
            .standing(actor(1))
            .expect("reads")
            .expect("the row stands");
        assert_eq!(
            row,
            Row {
                action: action(1),
                asked_ms: 10,
                ends_ms: 100
            }
        );
        let version: i64 = Connection::open(directory.path().join(VOICE_START_HOLDS_RECORD))
            .expect("opens")
            .query_row("SELECT version FROM voice_start_holds_schema", [], |row| {
                row.get(0)
            })
            .expect("a version");
        assert_eq!(version, 1);
    }

    /// A store at another version is refused before any write and left as it was.
    #[test]
    fn a_store_at_another_version_is_refused_before_any_write_and_left_as_it_was() {
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join(VOICE_START_HOLDS_RECORD);
        {
            let connection = Connection::open(&file).expect("creates");
            connection
                .execute_batch(
                    "CREATE TABLE voice_start_holds_schema (version INTEGER NOT NULL);
                     INSERT INTO voice_start_holds_schema (version) VALUES (2);",
                )
                .expect("a store of a later build");
        }
        let before = std::fs::read(&file).expect("reads");

        let refused = Record::open(directory.path()).expect_err("a later schema is refused");

        assert!(refused.to_string().contains("schema 2"), "{refused}");
        assert_eq!(std::fs::read(&file).expect("reads"), before);
    }

    /// A standing row holds the device against an unnamed start and against a start that names
    /// another action, and a start that names its action replaces it. The device's row is its own:
    /// another device is not held.
    #[test]
    fn begin_replaces_a_standing_row_only_for_its_named_action() {
        let (_directory, record) = open();
        record
            .begin(actor(1), action(1), None, 10, 100, &never, &|_| false)
            .expect("the first start");

        let unnamed = record
            .begin(actor(1), action(2), None, 20, 200, &never, &|_| false)
            .expect("begin");
        let misnamed = record
            .begin(
                actor(1),
                action(2),
                Some(action(9)),
                20,
                200,
                &never,
                &|_| false,
            )
            .expect("begin");
        let other_device = record
            .begin(actor(2), action(3), None, 20, 200, &never, &|_| false)
            .expect("begin");

        let held = Decision::Held(Row {
            action: action(1),
            asked_ms: 10,
            ends_ms: 100,
        });
        assert_eq!(unnamed, held);
        assert_eq!(misnamed, held);
        assert_eq!(other_device, Decision::Admitted);
        assert_eq!(
            record
                .standing(actor(1))
                .expect("reads")
                .map(|row| row.action),
            Some(action(1)),
            "a refused start writes nothing"
        );

        let named = record
            .begin(
                actor(1),
                action(2),
                Some(action(1)),
                20,
                200,
                &never,
                &|_| false,
            )
            .expect("begin");
        assert_eq!(named, Decision::Admitted);
        assert_eq!(
            record
                .standing(actor(1))
                .expect("reads")
                .map(|row| row.action),
            Some(action(2))
        );
    }

    /// A row whose end the host's own clock decision says has passed is no hold.
    #[test]
    fn a_row_past_its_end_is_no_hold() {
        let (_directory, record) = open();
        record
            .begin(actor(1), action(1), None, 10, 100, &never, &|_| false)
            .expect("the first start");

        let later = record
            .begin(
                actor(1),
                action(2),
                None,
                200,
                300,
                &|ends| Ok(ends <= 150),
                &|_| false,
            )
            .expect("begin");

        assert_eq!(later, Decision::Admitted);
    }

    /// The delete names the action: a row that another start wrote since stays.
    #[test]
    fn end_names_the_action() {
        let (_directory, record) = open();
        record
            .begin(actor(1), action(1), None, 10, 100, &never, &|_| false)
            .expect("the first start");
        record
            .begin(
                actor(1),
                action(2),
                Some(action(1)),
                20,
                200,
                &never,
                &|_| false,
            )
            .expect("the named start");

        record.end(actor(1), action(1)).expect("ends");
        assert_eq!(
            record
                .standing(actor(1))
                .expect("reads")
                .map(|row| row.action),
            Some(action(2)),
            "the earlier attempt's delete leaves the replacing row"
        );
        record.end(actor(1), action(2)).expect("ends");
        assert_eq!(record.standing(actor(1)).expect("reads"), None);
    }

    /// The sweep deletes only the rows whose end the floor on disk covers, for every actor.
    #[test]
    fn the_sweep_deletes_only_rows_the_floor_on_disk_covers() {
        let (_directory, record) = open();
        record
            .begin(actor(2), action(5), None, 10, 100, &never, &|_| false)
            .expect("a row that ends early");
        record
            .begin(actor(3), action(6), None, 10, 1_000, &never, &|_| false)
            .expect("a row that ends late");

        record
            .begin(actor(1), action(1), None, 500, 600, &never, &|ends| {
                ends <= 500
            })
            .expect("begin");

        assert_eq!(record.standing(actor(2)).expect("reads"), None);
        assert!(record.standing(actor(3)).expect("reads").is_some());
        assert!(record.standing(actor(1)).expect("reads").is_some());
    }
}
