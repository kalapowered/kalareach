//! What the host answered to a request for the disclosed checks, kept where a restart finds it.
//!
//! Section 9 keeps the record of an action for 30 days, so that a repeat of it is answered from the
//! record, on a later connection, after the window it was sent in has closed and after a restart,
//! and so that the same identifier on a different request is refused as a reused identifier. The
//! answer says where the checks stood when the request was answered; what the checks found stays
//! in memory, because the worker that performed them goes with the daemon, and a repeat is given
//! the answer it was given and no run of its own.
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

/// How long an answer is kept, in milliseconds: 30 days.
pub const RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

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
    /// Opens the record in `state_dir`, forgetting every answer older than [`RETENTION_MS`] at
    /// `now_ms`.
    ///
    /// A database that holds a schema this build does not read is refused before anything is
    /// written to it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path, now_ms: u64) -> Result<Self> {
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
        let record = Self {
            connection: Mutex::new(connection),
        };
        record.forget_the_old(now_ms)?;
        Ok(record)
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Forgets every answer given more than [`RETENTION_MS`] before `now_ms`.
    fn forget_the_old(&self, now_ms: u64) -> Result<()> {
        let oldest = counter(now_ms.saturating_sub(RETENTION_MS));
        self.with(|connection| {
            connection.execute(
                "DELETE FROM capability_answers WHERE answered_ms < ?1",
                params![oldest],
            )?;
            Ok(())
        })
    }

    /// What was answered to this actor's request under this action identifier, where an answer
    /// younger than [`RETENTION_MS`] at `now_ms` is held.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read, or holds an answer it cannot read.
    pub fn recall(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        now_ms: u64,
    ) -> Result<Option<Answered>> {
        let oldest = counter(now_ms.saturating_sub(RETENTION_MS));
        let row: Option<(Vec<u8>, String)> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT digest, answer FROM capability_answers
                     WHERE actor_id = ?1 AND action_id = ?2 AND answered_ms >= ?3",
                    params![actor_id.as_str(), action_id.to_string(), oldest],
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

    /// Writes down the answer given to this actor's request, and forgets what is past its
    /// retention. An answer already held for the identifier stays as it was.
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
        now_ms: u64,
    ) -> Result<()> {
        let text = serde_json::to_string(answer).map_err(ControllerError::registry)?;
        self.forget_the_old(now_ms)?;
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
                    counter(now_ms)
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
        let record = Record::open(directory.path(), now).expect("opens");
        assert!(
            record
                .recall(&actor(), action(1), now)
                .expect("reads")
                .is_none()
        );
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

        let record = Record::open(directory.path(), now + DAY).expect("opens again");
        let held = record
            .recall(&actor(), action(1), now + DAY)
            .expect("reads")
            .expect("the answer is still held");
        assert_eq!(held.digest, digest(2));
        assert_eq!(held.answer, CapabilityChecks::not_run());
        let other = ActorId::new("local:502").expect("another actor");
        assert!(
            record
                .recall(&other, action(1), now + DAY)
                .expect("reads")
                .is_none(),
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
                .recall(&actor(), action(1), now + DAY)
                .expect("reads")
                .expect("held")
                .digest,
            digest(2)
        );
    }

    /// KR-REQ-03.29: an answer is kept for 30 days and not longer, whether the record is read or
    /// opened again after it.
    #[test]
    fn an_answer_is_forgotten_after_thirty_days() {
        let directory = tempfile::tempdir().expect("a directory");
        let given = 100 * DAY;
        let record = Record::open(directory.path(), given).expect("opens");
        record
            .remember(
                &actor(),
                action(1),
                &digest(2),
                &CapabilityChecks::not_run(),
                given,
            )
            .expect("writes");
        assert!(
            record
                .recall(&actor(), action(1), given + 30 * DAY)
                .expect("reads")
                .is_some(),
            "kept for the whole of the thirtieth day"
        );
        assert!(
            record
                .recall(&actor(), action(1), given + 30 * DAY + 1)
                .expect("reads")
                .is_none(),
            "gone once it is older than thirty days"
        );
        drop(record);
        let record = Record::open(directory.path(), given + 31 * DAY).expect("opens");
        assert!(record.is_empty().expect("counts"), "and pruned when opened");
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
        let refused = Record::open(directory.path(), 0).expect_err("another schema");
        assert!(refused.to_string().contains("schema 2"), "{refused}");
        let connection = Connection::open(&path).expect("opens again");
        let tables: i64 = connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .expect("counts");
        assert_eq!(tables, 1, "nothing was added to it");
    }
}
