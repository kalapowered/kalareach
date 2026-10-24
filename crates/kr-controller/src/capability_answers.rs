//! What the host answered to a request for the disclosed checks, kept where a restart finds it.
//!
//! Section 9 keeps the record of an action for 30 days, so that a repeat of it is answered from the
//! record, on a later connection, after the window it was sent in has closed and after a restart,
//! and so that the same identifier on a different request is refused as a reused identifier. The
//! answer says where the checks stood when the request was answered. What the checks found is held
//! in memory only, so a daemon that starts again holds none of it, and a repeat is given the answer
//! it was given and no run of its own.
//!
//! The record holds an answer until the host lets go of it: it counts no age of its own. Forgetting
//! is a decision about the clock, which every collection of this host takes through the one check
//! in `crate::service::Controller::forget_old_capability_answers`, and a row that is still here
//! is the record of its action.
//!
//! The record is a database of its own, and not a table of the registry: the registry's schema is
//! one every release before this one has to be able to read, and an answer nothing before this
//! release asks for is not a reason to move it.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_protocol::desktop::CapabilityChecks;
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::scalars::Digest256;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The file the environment's record of answered requests lives in.
pub const CAPABILITY_ANSWERS_RECORD: &str = "capability-answers.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// What the record holds for one actor's action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    /// The digest of the request that was answered, which says whether a repeat is the same
    /// request or a reused identifier.
    pub digest: Digest256,
    /// The answer that was given.
    pub answer: CapabilityChecks,
}

/// The answers the host gave, and when each was given.
#[derive(Debug)]
pub struct Record {
    connection: Mutex<Connection>,
}

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
            kr_flush::release::open_connection(&state_dir.join(CAPABILITY_ANSWERS_RECORD), None)
                .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'capability_answers_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM capability_answers_schema", [], |row| {
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
                "the record of answered capability checks is at schema {found} and this build \
                 reads {SCHEMA_VERSION}"
            )));
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS capability_answers_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS capability_answers (
                     actor_id    TEXT NOT NULL,
                     action_id   TEXT NOT NULL,
                     digest      BLOB NOT NULL,
                     answer      TEXT NOT NULL,
                     answered_ms INTEGER NOT NULL CHECK (answered_ms >= 0),
                     PRIMARY KEY (actor_id, action_id)
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO capability_answers_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Lets go of every answer given before the moment `cutoff` names, and says how many that was.
    ///
    /// The caller has shown that the host's clock has outlived the retention at the reading the
    /// cutoff is counted from, and nothing here looks at a clock. `cutoff` is called with the
    /// record held, so that the moment it counts from is read after every answer written before
    /// the delete is, and no answer can be written between that reading and the delete: a delete
    /// by a predicate over every row is a decision about a moment, and the moment must be the
    /// latest one that can be vouched for when the rows are chosen.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn forget_before(&self, cutoff: impl FnOnce() -> u64) -> Result<usize> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM capability_answers WHERE answered_ms < ?1",
                params![counter(cutoff())],
            )
        })
    }

    /// Whether the record in `state_dir` holds an answer to this actor's request under this action
    /// identifier.
    ///
    /// It is asked through a connection of its own and takes nothing the record holds, so it waits
    /// for no work the record is doing. A record that is not there holds none.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn holds(state_dir: &Path, actor_id: &ActorId, action_id: ActionId) -> Result<bool> {
        kr_flush::release::holds_a_row(
            &state_dir.join(CAPABILITY_ANSWERS_RECORD),
            "SELECT 1 FROM capability_answers WHERE actor_id = ?1 AND action_id = ?2",
            params![actor_id.as_str(), action_id.to_string()],
        )
        .map_err(ControllerError::registry)
    }

    /// What was answered to this actor's request under this action identifier, where the record
    /// still holds one.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read, or holds an answer it cannot read.
    pub fn recall(&self, actor_id: &ActorId, action_id: ActionId) -> Result<Option<Answered>> {
        let row: Option<(Vec<u8>, String)> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT digest, answer FROM capability_answers
                     WHERE actor_id = ?1 AND action_id = ?2",
                    params![actor_id.as_str(), action_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
        })?;
        let Some((digest, answer)) = row else {
            return Ok(None);
        };
        let digest: [u8; 32] = digest.try_into().map_err(|_| {
            ControllerError::registry("the record of answered capability checks holds a bad digest")
        })?;
        let answer = serde_json::from_str(&answer).map_err(|_| {
            ControllerError::registry(
                "the record of answered capability checks holds an answer it cannot read",
            )
        })?;
        Ok(Some(Answered {
            digest: Digest256::from_bytes(digest),
            answer,
        }))
    }

    /// Writes down the answer given to this actor's request at `answered_ms`, the host's reading
    /// of the wall clock. An answer already held for the identifier stays as it was.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn remember(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        digest: &Digest256,
        answer: &CapabilityChecks,
        answered_ms: u64,
    ) -> Result<()> {
        let text = serde_json::to_string(answer).map_err(ControllerError::registry)?;
        self.with(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO capability_answers
                     (actor_id, action_id, digest, answer, answered_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    actor_id.as_str(),
                    action_id.to_string(),
                    digest.as_bytes().as_slice(),
                    text,
                    counter(answered_ms)
                ],
            )?;
            Ok(())
        })
    }

    /// How many answers the record holds. A test reads it; nothing else needs it.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn len(&self) -> Result<usize> {
        self.with(|connection| {
            connection
                .query_row("SELECT count(*) FROM capability_answers", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|count| usize::try_from(count).unwrap_or(0))
        })
    }

    /// Whether the record holds no answer.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|count| count == 0)
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn actor() -> ActorId {
        ActorId::new("local:501").expect("an actor")
    }

    fn action(byte: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn digest(byte: u8) -> Digest256 {
        Digest256::from_bytes([byte; 32])
    }

    const DAY: u64 = 24 * 60 * 60 * 1000;

    /// KR-REQ-03.29: an answer given to an actor's request is held across a restart, and is the
    /// answer to a repeat of the same request, a refusal of a different one under the identifier,
    /// and nothing to another actor.
    #[test]
    fn an_answer_is_held_across_a_restart_and_belongs_to_one_actor_and_one_request() {
        let directory = tempfile::tempdir().expect("a directory");
        let now = 40 * DAY;
        let record = Record::open(directory.path()).expect("opens");
        assert!(record.recall(&actor(), action(1)).expect("reads").is_none());
        record
            .remember(
                &actor(),
                action(1),
                &digest(2),
                &CapabilityChecks::not_run(),
                now,
            )
            .expect("writes");
        drop(record);

        let record = Record::open(directory.path()).expect("opens again");
        let held = record
            .recall(&actor(), action(1))
            .expect("reads")
            .expect("the answer is still held");
        assert_eq!(held.digest, digest(2));
        assert_eq!(held.answer, CapabilityChecks::not_run());
        let other = ActorId::new("local:502").expect("another actor");
        assert!(
            record.recall(&other, action(1)).expect("reads").is_none(),
            "an identifier is an actor's own"
        );
        // A second answer under the same identifier does not replace the first.
        record
            .remember(
                &actor(),
                action(1),
                &digest(3),
                &CapabilityChecks::not_run(),
                now + DAY,
            )
            .expect("writes");
        assert_eq!(
            record
                .recall(&actor(), action(1))
                .expect("reads")
                .expect("held")
                .digest,
            digest(2)
        );
    }

    /// KR-REQ-03.29, KR-REQ-09.14: the record counts no age of its own. A row is the record of its
    /// action, however long ago it was written, until the host lets go of the answers given before
    /// a cutoff it has shown it may count; an answer given at the cutoff stays.
    #[test]
    fn an_answer_is_held_until_the_host_forgets_those_given_before_its_cutoff() {
        let directory = tempfile::tempdir().expect("a directory");
        let given = 100 * DAY;
        let record = Record::open(directory.path()).expect("opens");
        record
            .remember(
                &actor(),
                action(1),
                &digest(2),
                &CapabilityChecks::not_run(),
                given,
            )
            .expect("writes");
        assert_eq!(record.forget_before(|| given).expect("forgets"), 0);
        assert!(
            record.recall(&actor(), action(1)).expect("reads").is_some(),
            "an answer given at the cutoff stays"
        );
        drop(record);
        let record = Record::open(directory.path()).expect("opens again");
        assert!(
            record.recall(&actor(), action(1)).expect("reads").is_some(),
            "and opening the record forgets nothing"
        );
        assert_eq!(record.forget_before(|| given + 1).expect("forgets"), 1);
        assert!(record.is_empty().expect("counts"));
    }

    /// KR-REQ-09.14: the moment a forgetting counts from is read with the record held, so an answer
    /// written after a correction of the clock cannot be chosen by a reading from before it.
    #[test]
    fn the_cutoff_is_counted_with_the_record_held() {
        let directory = tempfile::tempdir().expect("a directory");
        let record = Record::open(directory.path()).expect("opens");
        let mut held = false;
        record
            .forget_before(|| {
                held = record.connection.try_lock().is_err();
                0
            })
            .expect("forgets");
        assert!(held, "the record is held while the cutoff is counted");
    }

    /// A record of a schema this build does not read is refused and left as it is.
    #[test]
    fn a_record_of_another_schema_is_refused_and_left_alone() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join(CAPABILITY_ANSWERS_RECORD);
        {
            let connection = Connection::open(&path).expect("a database");
            connection
                .execute_batch(
                    "CREATE TABLE capability_answers_schema (version INTEGER NOT NULL);
                     INSERT INTO capability_answers_schema (version) VALUES (2);",
                )
                .expect("a newer schema");
        }
        let refused = Record::open(directory.path()).expect_err("another schema");
        assert!(refused.to_string().contains("schema 2"), "{refused}");
        let connection = Connection::open(&path).expect("opens again");
        let tables: i64 = connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .expect("counts");
        assert_eq!(tables, 1, "nothing was added to it");
    }
}
