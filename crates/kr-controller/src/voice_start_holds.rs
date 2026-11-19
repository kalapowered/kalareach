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
use crate::managed_transport::VOICE_DEADLINES;

/// The file the hold lives in.
pub const VOICE_START_HOLDS_RECORD: &str = "voice-start-holds.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// The longest a managed call lasts, in seconds, whatever length the start asked for.
///
/// The managed service refuses a longer request and fixes a call's end from the moment it first
/// reads the request, so a call this host's start made ends within this many seconds of that
/// reading. It is the managed service's limit: a path to a provider of the person's own would state
/// its own limit and its own test beside this one.
pub const VOICE_CALL_LIMIT_SECONDS: u64 = 1_800;

/// How long a start may wait before its request is written, in milliseconds: the limit the broker
/// client enforces on the continuous clock.
pub const SEND_LIMIT_MS: u64 = 30_000;

/// How long the exchange with the managed service may take, in milliseconds: the host's own total
/// deadline for it, so a change of the deadlines moves the bound with it.
pub const POST_LIMIT_MS: u64 = VOICE_DEADLINES.total.as_millis() as u64;

/// The difference allowed between this host's clock and the managed service's, in milliseconds. An
/// assumption the bound rests on, not a measurement.
pub const SKEW_MS: u64 = 40_000;

/// What the bound adds to the length of the call: the send limit, the exchange and the skew.
pub const HOLD_ALLOWANCE_MS: u64 = SEND_LIMIT_MS + POST_LIMIT_MS + SKEW_MS;

/// The moment a start read at `asked_ms` for `duration_seconds` stops holding its device: after
/// the request is read, the call lasts at most the voice limit, and the allowance covers what comes
/// before the service reads the request.
#[must_use]
pub fn hold_ends_ms(asked_ms: u64, duration_seconds: u32) -> u64 {
    let call = u64::from(duration_seconds).min(VOICE_CALL_LIMIT_SECONDS) * 1_000;
    asked_ms
        .saturating_add(call)
        .saturating_add(HOLD_ALLOWANCE_MS)
}

/// The words of the host's refusal of a start while an earlier one holds the device. `named` is the
/// action the start named, when it named one. The same words are read by the companion, which finds
/// the standing action in them, and are pinned by one fixture both read.
#[must_use]
pub fn hold_words(held: &Row, named: Option<ActionId>) -> String {
    let begun = utc_text(held.asked_ms);
    let clear = utc_text(held.ends_ms.div_ceil(1_000).saturating_mul(1_000));
    let action = held.action;
    match named {
        None => format!(
            "Nothing was started. This host still holds an earlier voice start from this device \
             (action {action}, begun at {begun} by this host's clock), so a call from it may \
             still be running. A second start could be a second charged call. This hold does not \
             stop a start that names action {action}, or a start made at or after {clear} by \
             this host's clock."
        ),
        Some(other) => format!(
            "Nothing was started. This start names action {other}. This host holds an earlier \
             voice start from this device under action {action}, begun at {begun} by this host's \
             clock, so a call from it may still be running. This hold does not stop a start that \
             names action {action}, or a start made at or after {clear} by this host's clock."
        ),
    }
}

/// The words of the refusal of a start whose hold could not be written.
pub const HOLD_NOT_RECORDED_WORDS: &str = "Nothing was started. This host could not record the \
    start before asking the voice service, so it did not ask. A later start can work.";

/// A moment as `YYYY-MM-DD HH:MM:SS UTC`.
fn utc_text(ms: u64) -> String {
    let seconds = ms / 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX / 2);
    let in_day = seconds % 86_400;
    // The civil date of a day count from 1970-01-01 (the proleptic Gregorian calendar).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        in_day / 3_600,
        in_day % 3_600 / 60,
        in_day % 60
    )
}

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
    /// `at_the_lock` gives the start's `(asked_ms, ends_ms)` and is called once, after the write
    /// lock is held, so that the moment it reads includes every wait for the lock. `bound_passed`
    /// is asked about a standing row's end with the `asked_ms` of this start.
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
        at_the_lock: &dyn Fn() -> (u64, u64),
        bound_passed: &dyn Fn(u64, u64) -> Result<bool>,
        floor_covers: &dyn Fn(u64) -> bool,
    ) -> Result<Decision> {
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let (asked_ms, ends_ms) = at_the_lock();
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
            if !names_it && !bound_passed(moment(standing_ends), asked_ms)? {
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

    fn never(_: u64, _: u64) -> Result<bool> {
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
            .begin(actor(1), action(1), None, &|| (10, 100), &never, &|_| false)
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
            .begin(actor(1), action(1), None, &|| (10, 100), &never, &|_| false)
            .expect("the first start");

        let unnamed = record
            .begin(actor(1), action(2), None, &|| (20, 200), &never, &|_| false)
            .expect("begin");
        let misnamed = record
            .begin(
                actor(1),
                action(2),
                Some(action(9)),
                &|| (20, 200),
                &never,
                &|_| false,
            )
            .expect("begin");
        let other_device = record
            .begin(actor(2), action(3), None, &|| (20, 200), &never, &|_| false)
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
                &|| (20, 200),
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
            .begin(actor(1), action(1), None, &|| (10, 100), &never, &|_| false)
            .expect("the first start");

        let later = record
            .begin(
                actor(1),
                action(2),
                None,
                &|| (200, 300),
                &|ends, _| Ok(ends <= 150),
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
            .begin(actor(1), action(1), None, &|| (10, 100), &never, &|_| false)
            .expect("the first start");
        record
            .begin(
                actor(1),
                action(2),
                Some(action(1)),
                &|| (20, 200),
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
            .begin(actor(2), action(5), None, &|| (10, 100), &never, &|_| false)
            .expect("a row that ends early");
        record
            .begin(actor(3), action(6), None, &|| (10, 1_000), &never, &|_| {
                false
            })
            .expect("a row that ends late");

        record
            .begin(actor(1), action(1), None, &|| (500, 600), &never, &|ends| {
                ends <= 500
            })
            .expect("begin");

        assert_eq!(record.standing(actor(2)).expect("reads"), None);
        assert!(record.standing(actor(3)).expect("reads").is_some());
        assert!(record.standing(actor(1)).expect("reads").is_some());
    }

    /// The host's words are the sentences of the fixture the companion reads too: whole-sentence
    /// equality at a fixed clock, with the clear time rounded up to the next second.
    #[test]
    fn the_refusal_words_are_the_sentences_of_the_fixture() {
        let fixture = include_str!("../tests/fixtures/voice_hold_refusals.txt");
        let line = |name: &str| {
            fixture
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                .unwrap_or_else(|| panic!("the fixture has a line for {name}"))
        };
        let held = Row {
            action: action(1),
            asked_ms: 1_700_000_000_000,
            ends_ms: 1_700_000_130_500,
        };
        let named = action(9);
        let render = |template: &str| {
            template
                .replace("{A}", &held.action.to_string())
                .replace("{B}", &named.to_string())
                .replace("{T0}", "2023-11-14 22:13:20 UTC")
                .replace("{T1}", "2023-11-14 22:15:31 UTC")
        };
        assert_eq!(hold_words(&held, None), render(line("unnamed")));
        assert_eq!(hold_words(&held, Some(named)), render(line("named")));
        assert_eq!(HOLD_NOT_RECORDED_WORDS, line("unrecorded"));
        assert_eq!(utc_text(0), "1970-01-01 00:00:00 UTC");
    }

    /// The bound is the call's length, held to the voice limit, and the allowance: the send limit,
    /// the exchange and the skew.
    #[test]
    fn a_requested_length_above_the_voice_limit_is_held_to_it_and_a_shorter_one_sets_the_bound() {
        assert_eq!(POST_LIMIT_MS, 50_000);
        assert_eq!(HOLD_ALLOWANCE_MS, 120_000);
        assert_eq!(hold_ends_ms(1_000, 7_200), 1_000 + 1_800_000 + 120_000);
        assert_eq!(hold_ends_ms(1_000, 600), 1_000 + 600_000 + 120_000);
        assert_eq!(hold_ends_ms(u64::MAX - 5, 600), u64::MAX);
    }
}
