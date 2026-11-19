//! The file that keeps the host's own-key voice calls.
//!
//! One table in `own-key-calls.sqlite3`, one row per call, written through
//! [`OwnCallLedger`](kr_client::services::OwnCallLedger). It holds no key, no session description
//! and nothing a person said: a call's identifiers, who asked, when, where it stands, and the
//! provider's session id once the host has one. Every change is one transaction on the disk before
//! it is reported, because a call the host asked for and did not write down is one it could not
//! end.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_client::services::{CallRow, CallState, LedgerError, LedgerResult, NewCall, OwnCallLedger};
use kr_protocol::ids::ActionId;
use kr_protocol::scalars::Uuid;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The file name in the state directory.
pub const OWN_KEY_CALLS_RECORD: &str = "own-key-calls.sqlite3";

/// The schema this build writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema this build reads.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// The words a stored row's state carries.
pub const STATES: [&str; 5] = ["creating", "open", "closing", "unresolved", "closed"];

/// The host's own-key call rows.
pub struct OwnKeyCalls {
    connection: Mutex<Connection>,
}

impl std::fmt::Debug for OwnKeyCalls {
    /// That it exists, and never a row.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnKeyCalls")
            .finish_non_exhaustive()
    }
}

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn counter_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn refused(words: &'static str) -> LedgerError {
    LedgerError::said(words)
}

impl OwnKeyCalls {
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
            kr_flush::release::open_connection(&state_dir.join(OWN_KEY_CALLS_RECORD), None)
                .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'own_key_call_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM own_key_call_schema", [], |row| {
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
                "the own-key call record is at schema {found} and this build reads {SCHEMA_VERSION}"
            )));
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS own_key_call_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS own_key_calls (
                     call_id             TEXT PRIMARY KEY,
                     attempt_id          TEXT NOT NULL,
                     action_id           TEXT NOT NULL,
                     device_id           TEXT NOT NULL,
                     state               TEXT NOT NULL CHECK (state IN
                         ('creating', 'open', 'closing', 'unresolved', 'closed')),
                     provider_session_id TEXT,
                     provider_expires_ms INTEGER CHECK (provider_expires_ms >= 0),
                     asked_ms            INTEGER NOT NULL CHECK (asked_ms >= 0),
                     closes_at_ms        INTEGER NOT NULL CHECK (closes_at_ms >= 0),
                     closed_ms           INTEGER CHECK (closed_ms >= 0),
                     CHECK (state NOT IN ('open', 'closing', 'unresolved')
                            OR provider_session_id IS NOT NULL),
                     CHECK ((state = 'closed') = (closed_ms IS NOT NULL))
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO own_key_call_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a row stands for `call_id`.
    fn stands(connection: &Connection, call_id: &str) -> LedgerResult<bool> {
        connection
            .query_row(
                "SELECT count(*) > 0 FROM own_key_calls WHERE call_id = ?1",
                params![call_id],
                |row| row.get(0),
            )
            .map_err(|_| refused("the own-key call record could not read a row"))
    }
}

/// The refusal for a change to a call the record has no row for, or has in another state.
fn no_such_call(words: &'static str) -> LedgerError {
    LedgerError::said(words)
}

impl OwnCallLedger for OwnKeyCalls {
    fn begin(&self, call: &NewCall) -> LedgerResult<()> {
        self.connection()
            .execute(
                "INSERT INTO own_key_calls
                     (call_id, attempt_id, action_id, device_id, state, asked_ms, closes_at_ms)
                 VALUES (?1, ?2, ?3, ?4, 'creating', ?5, ?6)",
                params![
                    call.call_id,
                    call.attempt_id,
                    call.action_id.to_string(),
                    call.device_id,
                    counter(call.asked_ms),
                    counter(call.closes_at_ms),
                ],
            )
            .map(|_| ())
            .map_err(|_| refused("the own-key call record could not write a call"))
    }

    fn record_id(
        &self,
        call_id: &str,
        provider_session_id: &str,
        provider_expires_ms: Option<u64>,
    ) -> LedgerResult<()> {
        let changed = self
            .connection()
            .execute(
                "UPDATE own_key_calls
                 SET state = 'open', provider_session_id = ?2, provider_expires_ms = ?3
                 WHERE call_id = ?1 AND state = 'creating'",
                params![
                    call_id,
                    provider_session_id,
                    provider_expires_ms.map(counter)
                ],
            )
            .map_err(|_| refused("the own-key call record could not write a session id"))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(no_such_call(
                "the own-key call record has no call that was still being created at this step",
            ))
        }
    }

    fn record_state(&self, call_id: &str, state: CallState) -> LedgerResult<()> {
        if !matches!(state, CallState::Closing | CallState::Unresolved) {
            return Err(LedgerError::said(
                "the own-key call record moves a call to closing or unresolved only",
            ));
        }
        let changed = self
            .connection()
            .execute(
                "UPDATE own_key_calls SET state = ?2
                 WHERE call_id = ?1 AND state IN ('open', 'closing', 'unresolved')",
                params![call_id, state.as_str()],
            )
            .map_err(|_| refused("the own-key call record could not write a state"))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(no_such_call(
                "the own-key call record has no call that holds a session and is not closed at this step",
            ))
        }
    }

    fn record_closed(&self, call_id: &str, closed_ms: u64) -> LedgerResult<()> {
        let connection = self.connection();
        let changed = connection
            .execute(
                "UPDATE own_key_calls SET state = 'closed', closed_ms = ?2
                 WHERE call_id = ?1 AND state != 'closed'",
                params![call_id, counter(closed_ms)],
            )
            .map_err(|_| refused("the own-key call record could not write a closure"))?;
        // A closure written twice is one closure: the first mark stands.
        if changed == 1 || Self::stands(&connection, call_id)? {
            Ok(())
        } else {
            Err(no_such_call(
                "the own-key call record has no call that is stored at this step",
            ))
        }
    }

    fn rows(&self) -> LedgerResult<Vec<CallRow>> {
        let connection = self.connection();
        let mut statement = connection
            .prepare(
                "SELECT call_id, attempt_id, action_id, device_id, state, provider_session_id,
                        provider_expires_ms, asked_ms, closes_at_ms, closed_ms
                 FROM own_key_calls ORDER BY asked_ms, call_id",
            )
            .map_err(|_| refused("the own-key call record could not read the calls"))?;
        let read = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                ))
            })
            .map_err(|_| refused("the own-key call record could not read the calls"))?;
        let mut rows = Vec::new();
        for stored in read {
            let (
                call_id,
                attempt_id,
                action,
                device_id,
                state,
                session,
                expires,
                asked,
                closes,
                closed,
            ) = stored.map_err(|_| refused("the own-key call record could not read a call"))?;
            // A row this build cannot read is refused whole, because a call it cannot name is one
            // it cannot end, and a count that skipped it would say there were fewer.
            let unreadable =
                || LedgerError::said("the own-key call record holds a call this build cannot read");
            let action_id = action
                .parse::<Uuid>()
                .map(ActionId::new)
                .map_err(|_| unreadable())?;
            rows.push(CallRow {
                call: NewCall {
                    call_id,
                    attempt_id,
                    action_id,
                    device_id,
                    asked_ms: counter_of(asked),
                    closes_at_ms: counter_of(closes),
                },
                state: CallState::parse(&state).ok_or_else(unreadable)?,
                provider_session_id: session,
                provider_expires_ms: expires.map(counter_of),
                closed_ms: closed.map(counter_of),
            });
        }
        Ok(rows)
    }

    fn delete(&self, call_id: &str) -> LedgerResult<()> {
        self.connection()
            .execute(
                "DELETE FROM own_key_calls WHERE call_id = ?1",
                params![call_id],
            )
            .map(|_| ())
            .map_err(|_| refused("the own-key call record could not delete a call"))
    }

    fn forget_all(&self) -> LedgerResult<u64> {
        self.connection()
            .execute("DELETE FROM own_key_calls", [])
            .map(|count| count as u64)
            .map_err(|_| refused("the own-key call record could not forget the calls"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(byte: u8) -> NewCall {
        NewCall {
            call_id: format!("call-{byte}"),
            attempt_id: format!("attempt-{byte}"),
            action_id: ActionId::new(Uuid::from_bytes([byte; 16])),
            device_id: format!("device-{byte}"),
            asked_ms: 1_000 * u64::from(byte),
            closes_at_ms: 1_000 * u64::from(byte) + 1_800_000,
        }
    }

    fn open(directory: &kr_ipc::testing::PrivateTempDir) -> OwnKeyCalls {
        OwnKeyCalls::open(directory.path()).expect("the record opens")
    }

    /// KR-REQ-15.19: a call is written down before the provider is asked, and read back as it was
    /// written, with no session id because the provider has not answered.
    #[test]
    fn a_call_is_written_before_the_provider_is_asked_and_read_back_as_written() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");

        let rows = record.rows().expect("the rows read");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].call, call(1));
        assert_eq!(rows[0].state, CallState::Creating);
        assert_eq!(rows[0].provider_session_id, None);
        assert_eq!(rows[0].closed_ms, None);
        assert!(
            record.begin(&call(1)).is_err(),
            "a call that stands is not written twice"
        );
    }

    /// The provider's session id is written once, and only for a call that is being created.
    #[test]
    fn the_session_id_is_written_once_and_only_for_a_call_being_created() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");

        record
            .record_id("call-1", "sess_1", Some(5_000))
            .expect("the id is written");
        let row = &record.rows().expect("the rows read")[0];
        assert_eq!(row.state, CallState::Open);
        assert_eq!(row.provider_session_id.as_deref(), Some("sess_1"));
        assert_eq!(row.provider_expires_ms, Some(5_000));

        assert!(
            record.record_id("call-1", "sess_2", None).is_err(),
            "a second id for an open call is refused"
        );
        assert!(
            record.record_id("call-9", "sess_3", None).is_err(),
            "an id for a call the record does not hold is refused"
        );
        assert_eq!(
            record.rows().expect("the rows read")[0]
                .provider_session_id
                .as_deref(),
            Some("sess_1"),
            "the refused writes changed nothing"
        );
    }

    /// A closure is marked before the row goes, a closed row blocks no start, and a second mark
    /// leaves the first closure's time.
    #[test]
    fn a_closure_is_marked_before_the_row_is_deleted_and_a_closed_row_blocks_nothing() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");
        record
            .record_id("call-1", "sess_1", None)
            .expect("the id is written");
        record
            .record_state("call-1", CallState::Closing)
            .expect("closing");
        record
            .record_state("call-1", CallState::Unresolved)
            .expect("unresolved");
        assert!(CallState::Unresolved.blocks_a_start());

        record.record_closed("call-1", 7_000).expect("closed");
        record.record_closed("call-1", 9_000).expect("closed again");
        let row = &record.rows().expect("the rows read")[0];
        assert_eq!(row.state, CallState::Closed);
        assert_eq!(row.closed_ms, Some(7_000), "the first closure stands");
        assert!(!row.state.blocks_a_start());
        assert!(
            record.record_state("call-1", CallState::Closing).is_err(),
            "a closed call does not reopen"
        );

        record.delete("call-1").expect("the row is deleted");
        record
            .delete("call-1")
            .expect("deleting nothing is not an error");
        assert!(record.rows().expect("the rows read").is_empty());
        assert!(
            record.record_closed("call-1", 1).is_err(),
            "a closure for a call the record does not hold is refused"
        );
    }

    /// A call that was refused or given up before it had a session is marked closed too, and has
    /// no session id to hang up.
    #[test]
    fn a_call_with_no_session_can_be_marked_closed_but_not_moved_to_closing() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");

        assert!(
            record.record_state("call-1", CallState::Closing).is_err(),
            "a call with no session cannot be closing: there is nothing to hang up"
        );
        assert!(
            record.record_state("call-1", CallState::Open).is_err(),
            "only closing and unresolved are written here"
        );
        record.record_closed("call-1", 2_000).expect("closed");
        let row = &record.rows().expect("the rows read")[0];
        assert_eq!(row.state, CallState::Closed);
        assert_eq!(row.provider_session_id, None);
    }

    /// Forgetting deletes every row, closed or not, and counts them.
    #[test]
    fn forgetting_deletes_every_row_and_says_how_many_there_were() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        assert_eq!(record.forget_all().expect("nothing to forget"), 0);
        for byte in 1..=3 {
            record.begin(&call(byte)).expect("the call is written");
        }
        record.record_closed("call-2", 1).expect("closed");

        assert_eq!(record.forget_all().expect("forgotten"), 3);
        assert!(record.rows().expect("the rows read").is_empty());
    }

    /// Rows are read oldest first, and they are still there when the record is opened again.
    #[test]
    fn rows_come_back_oldest_first_after_the_record_is_opened_again() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        {
            let record = open(&directory);
            record.begin(&call(3)).expect("the call is written");
            record.begin(&call(1)).expect("the call is written");
            record.begin(&call(2)).expect("the call is written");
        }
        let reopened = open(&directory);
        let order: Vec<String> = reopened
            .rows()
            .expect("the rows read")
            .into_iter()
            .map(|row| row.call.call_id)
            .collect();
        assert_eq!(order, ["call-1", "call-2", "call-3"]);
    }

    /// A record written by a newer build is refused and left as it is.
    #[test]
    fn a_record_of_a_newer_schema_is_refused_and_left_untouched() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        drop(open(&directory));
        let path = directory.path().join(OWN_KEY_CALLS_RECORD);
        Connection::open(&path)
            .expect("the file opens")
            .execute("UPDATE own_key_call_schema SET version = 99", [])
            .expect("the version is raised");

        let error = OwnKeyCalls::open(directory.path()).expect_err("a newer schema is refused");
        assert!(error.to_string().contains("schema 99"), "{error}");
        let version: i64 = Connection::open(&path)
            .expect("the file opens")
            .query_row("SELECT version FROM own_key_call_schema", [], |row| {
                row.get(0)
            })
            .expect("the version reads");
        assert_eq!(version, 99, "the refused open wrote nothing");
    }

    /// A row this build cannot read is refused whole: a count that skipped it would say there were
    /// fewer calls than the owner is being charged for.
    #[test]
    fn a_row_this_build_cannot_read_is_refused_whole() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");
        record
            .connection()
            .execute("UPDATE own_key_calls SET action_id = 'not an action'", [])
            .expect("the row is changed");

        let error = record.rows().expect_err("the row is refused");
        assert!(error.to_string().contains("cannot read"), "{error}");
    }

    /// The record's debug form shows that it exists and no row.
    #[test]
    fn the_debug_form_shows_no_row() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let record = open(&directory);
        record.begin(&call(1)).expect("the call is written");
        let shown = format!("{record:?}");
        assert!(
            !shown.contains("call-1") && !shown.contains("device-1"),
            "{shown}"
        );
    }
}
