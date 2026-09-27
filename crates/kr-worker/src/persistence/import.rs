//! The explicit importer for a journal older than the migration ladder.
//!
//! Section 24: *restoring an unsupported archive uses an explicit versioned importer or a supported
//! older exporter, never an unannounced partial restore.* A host brings a journal forward in place
//! only from [`crate::persistence::migration::OLDEST_MIGRATABLE`]; a journal older than that is
//! refused where it is opened and named with the command that runs this.
//!
//! What this reads is exactly what the builds recording version 1 wrote - two shapes, the receipt
//! table alone and the receipt table with results and a closure - and nothing else. It reads a
//! journal once, forward only, in one transaction:
//!
//! * the version, and every object in the file against the statement one of those builds ran to
//!   make it, are checked, and anything else is refused by name: a version, an object no build
//!   made, one that is missing, one whose statement differs - a constraint or a column added, an
//!   index on something else;
//! * every row is read as the current build reads it, a receipt through the journal's own reader,
//!   so a row the running host would refuse is refused here instead;
//! * the receipts gain the columns later versions added, every object of the current schema is
//!   created from the journal's own definition of it, the starting privacy record is written and
//!   the version is set;
//! * the result - its tables' columns and every index, its receipts read again - is checked
//!   against a fresh current schema before anything is committed.
//!
//! Any failure rolls the transaction back, so a refused journal is left exactly as it was. An
//! imported journal records the current version, so it is never read in its old shape again.
//!
//! One limit is stated rather than hidden: a journal of the second shape that has lost both its
//! results table and its closure table reads as the first shape, because the first shape is
//! exactly that, and nothing left in the file tells the two apart.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kr_protocol::ids::ActorId;
use kr_protocol::method::MethodName;
use kr_protocol::receipt::{ReceiptState, RejectionReason};
use rusqlite::Connection;

use crate::journal::{create_current_objects, write_starting_privacy};
use crate::persistence::migration::CURRENT;

/// The schema version this importer reads.
pub const IMPORTS: i64 = 1;

/// How long an import waits for another holder of the file before it gives up.
///
/// The importer runs while the environment's daemon is stopped, so nothing should hold the file;
/// a holder that does is answered with a refusal rather than waited for without end.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(feature = "testing")]
thread_local! {
    /// Whether the next import on this thread stops after its changes and before its commit.
    static STOP_BEFORE_THE_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Stops the next import this thread runs after every change it makes and before its commit, as a
/// failure there would, for this host's own tests. It is compiled away in every shipped build.
#[cfg(feature = "testing")]
pub fn stop_the_next_import_before_its_commit() {
    STOP_BEFORE_THE_COMMIT.with(|stop| stop.set(true));
}

/// What importing one journal came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Imported {
    /// The journal was brought from `from` to `to`, the version this build reads.
    Imported {
        /// The version it recorded.
        from: i64,
        /// The version it records now.
        to: i64,
        /// How many receipts it holds, which the import keeps.
        receipts: u64,
    },
    /// The journal records a version the ladder reads, so there was nothing to import.
    NothingToImport {
        /// The version it records.
        version: i64,
    },
}

/// Why a journal was not imported, naming what the importer could not read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportRefusal {
    /// The file could not be opened, read or written as a database.
    #[error("this journal could not be read or written: {detail}")]
    Unreadable {
        /// What the store said.
        detail: String,
    },
    /// The file records no schema version.
    #[error("this file records no schema version, so it is not a journal this importer reads")]
    NoVersion,
    /// A newer build wrote the journal.
    #[error(
        "this journal is at schema version {found}, which is newer than this build's {current}; \
         a newer journal is not imported by an older build"
    )]
    Newer {
        /// The version it records.
        found: i64,
        /// The version this build reads.
        current: i64,
    },
    /// The journal is at a version this importer does not read.
    #[error("this journal is at schema version {found}, and this importer reads version {reads}")]
    Version {
        /// The version it records.
        found: i64,
        /// The version this importer reads.
        reads: i64,
    },
    /// The file holds an object no build recording version 1 made.
    #[error("this journal holds the {kind} {name}, which no build recording version 1 made")]
    UnknownObject {
        /// What kind of object it is.
        kind: String,
        /// Its name.
        name: String,
    },
    /// An object the build that wrote this journal always made is missing.
    #[error("this journal records version 1 and has no {kind} {name}")]
    Missing {
        /// What kind of object it is.
        kind: String,
        /// Its name.
        name: String,
    },
    /// An object is not the one a build recording version 1 made: its statement differs.
    #[error(
        "the {kind} {name} is not the one a build recording version 1 made: it is made by \
         {found:?}"
    )]
    Definition {
        /// What kind of object it is.
        kind: String,
        /// Its name.
        name: String,
        /// The statement that made it, as the file keeps it.
        found: String,
    },
    /// A row cannot be read by this build.
    #[error("a row of the {table} table cannot be read: {detail}")]
    Row {
        /// The table.
        table: String,
        /// What cannot be read.
        detail: String,
    },
    /// The journal the import produced is not the current schema.
    #[error("the imported journal is not the current schema: {detail}")]
    Result {
        /// What differs.
        detail: String,
    },
}

/// Imports one journal in place, once, forward only, in one transaction.
///
/// A journal at a version the ladder reads is left alone and answered with
/// [`Imported::NothingToImport`]. The caller is the one who establishes that nothing else holds
/// the file: the command that runs this holds the environment's singleton lock and refuses a
/// session whose worker may still be there.
///
/// # Errors
///
/// Returns an [`ImportRefusal`] naming what the importer could not read. The journal is then
/// exactly as it was.
pub fn import_journal(path: impl AsRef<Path>) -> Result<Imported, ImportRefusal> {
    let mut connection = Connection::open_with_flags(
        path.as_ref(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(unreadable)?;
    connection.busy_timeout(BUSY_TIMEOUT).map_err(unreadable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unreadable)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(unreadable)?;
    let version = recorded_version(&transaction)?;
    if version > CURRENT {
        return Err(ImportRefusal::Newer {
            found: version,
            current: CURRENT,
        });
    }
    if version >= crate::persistence::migration::OLDEST_MIGRATABLE {
        return Ok(Imported::NothingToImport { version });
    }
    if version != IMPORTS {
        return Err(ImportRefusal::Version {
            found: version,
            reads: IMPORTS,
        });
    }
    let second_shape = check_statements(&transaction)?;
    let receipts = check_receipts(&transaction)?;
    if second_shape {
        check_results(&transaction)?;
        check_closures(&transaction)?;
    }

    transaction
        .execute_batch(
            "ALTER TABLE receipts ADD COLUMN intent BLOB;
             ALTER TABLE receipts ADD COLUMN subject_digest BLOB;
             ALTER TABLE receipts ADD COLUMN created_boot BLOB;
             ALTER TABLE receipts ADD COLUMN created_continuous_ms INTEGER;",
        )
        .map_err(unreadable)?;
    create_current_objects(&transaction).map_err(unreadable)?;
    write_starting_privacy(&transaction, kr_ipc::now_ms()).map_err(unreadable)?;
    transaction
        .execute(
            "UPDATE schema_version SET version = ?1",
            rusqlite::params![CURRENT],
        )
        .map_err(unreadable)?;

    let expected = current_shape().map_err(unreadable)?;
    let produced = shape_of(&transaction).map_err(unreadable)?;
    if produced != expected {
        return Err(ImportRefusal::Result {
            detail: difference(&expected, &produced),
        });
    }
    // Every receipt, read as the running host reads one, in the shape it will be read in.
    let kept =
        crate::journal::read_every_receipt(&transaction).map_err(|detail| ImportRefusal::Row {
            table: "receipts".to_owned(),
            detail,
        })?;
    if kept != receipts {
        return Err(ImportRefusal::Result {
            detail: format!("{receipts} receipts were read and {kept} are there"),
        });
    }
    #[cfg(feature = "testing")]
    if STOP_BEFORE_THE_COMMIT.with(|stop| stop.replace(false)) {
        return Err(ImportRefusal::Unreadable {
            detail: "a test stopped this import after its changes and before its commit".to_owned(),
        });
    }
    transaction.commit().map_err(unreadable)?;
    Ok(Imported::Imported {
        from: IMPORTS,
        to: CURRENT,
        receipts,
    })
}

/// The statement each object of the two version 1 shapes was made by, as the build that made it
/// spelled it. SQLite keeps each statement as it was run, without its `IF NOT EXISTS`, and the
/// comparison reads both with their white space collapsed.
///
/// The first build made the version, the receipts and their index
/// (`927ecc84d5f2ed3575705510bca563f093e031d2`); the second made the same three and added the
/// results and the closure (`a665d5e6cf8f898e03018fccce567abcae83b020`). No other build recorded
/// version 1.
const FIRST_SHAPE: &[(&str, &str, &str)] = &[
    (
        "table",
        "schema_version",
        "CREATE TABLE schema_version (version INTEGER NOT NULL)",
    ),
    (
        "table",
        "receipts",
        "CREATE TABLE receipts (
                     actor_id             TEXT    NOT NULL,
                     action_id            BLOB    NOT NULL,
                     method               TEXT    NOT NULL,
                     method_version       INTEGER NOT NULL,
                     revision             INTEGER NOT NULL,
                     state                TEXT    NOT NULL,
                     reason               TEXT,
                     payload_digest       BLOB    NOT NULL,
                     accepted_deadline_ms INTEGER,
                     error_code           TEXT,
                     error_message        TEXT,
                     created_at_ms        INTEGER NOT NULL,
                     updated_at_ms        INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 )",
    ),
    (
        "index",
        "receipts_created_at",
        "CREATE INDEX receipts_created_at ON receipts (created_at_ms)",
    ),
];

/// What the second build added to [`FIRST_SHAPE`].
const SECOND_SHAPE_ADDS: &[(&str, &str, &str)] = &[
    (
        "table",
        "results",
        "CREATE TABLE results (
                     actor_id  TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     result    BLOB NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 )",
    ),
    (
        "table",
        "closure",
        "CREATE TABLE closure (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL
                 )",
    ),
];

/// A statement with its white space collapsed, which is how two spellings of one are compared.
fn collapsed(statement: &str) -> String {
    statement.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reads the one version the file records.
fn recorded_version(connection: &Connection) -> Result<i64, ImportRefusal> {
    let has_table: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .map_err(unreadable)?;
    if has_table == 0 {
        return Err(ImportRefusal::NoVersion);
    }
    let versions: Vec<i64> = {
        let mut statement = connection
            .prepare("SELECT version FROM schema_version")
            .map_err(unreadable)?;
        statement
            .query_map([], |row| row.get(0))
            .map_err(unreadable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(|error| ImportRefusal::Row {
                table: "schema_version".to_owned(),
                detail: error.to_string(),
            })?
    };
    match versions.as_slice() {
        [version] => Ok(*version),
        [] => Err(ImportRefusal::NoVersion),
        _ => Err(ImportRefusal::Row {
            table: "schema_version".to_owned(),
            detail: format!("it records {} versions rather than one", versions.len()),
        }),
    }
}

/// Checks every object in the file against the statement a build recording version 1 made it
/// by, and says which of the two shapes the file is: `true` for the second.
///
/// SQLite's own objects - its internal tables and the indexes it makes for a key - follow from the
/// tables' statements, so they are not asked about separately.
fn check_statements(connection: &Connection) -> Result<bool, ImportRefusal> {
    let objects: Vec<(String, String, Option<String>)> = {
        let mut statement = connection
            .prepare("SELECT type, name, sql FROM sqlite_master")
            .map_err(unreadable)?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(unreadable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(unreadable)?
    };
    let mut found = BTreeSet::new();
    for (kind, name, made_by) in &objects {
        if name.starts_with("sqlite_") {
            continue;
        }
        let Some((_, _, statement)) = FIRST_SHAPE
            .iter()
            .chain(SECOND_SHAPE_ADDS)
            .find(|(known_kind, known_name, _)| known_kind == kind && known_name == name)
        else {
            return Err(ImportRefusal::UnknownObject {
                kind: kind.clone(),
                name: name.clone(),
            });
        };
        let made_by = made_by.as_deref().unwrap_or_default();
        if collapsed(made_by) != collapsed(statement) {
            return Err(ImportRefusal::Definition {
                kind: kind.clone(),
                name: name.clone(),
                found: collapsed(made_by),
            });
        }
        found.insert(name.as_str());
    }
    // The second shape is the first with both of its additions, because one build made both.
    let second = SECOND_SHAPE_ADDS
        .iter()
        .any(|(_, name, _)| found.contains(name));
    let shape = FIRST_SHAPE
        .iter()
        .chain(if second { SECOND_SHAPE_ADDS } else { &[] });
    for (kind, name, _) in shape {
        if !found.contains(name) {
            return Err(ImportRefusal::Missing {
                kind: (*kind).to_owned(),
                name: (*name).to_owned(),
            });
        }
    }
    Ok(second)
}

/// Checks every receipt reads as this build reads one, and returns how many there are.
fn check_receipts(connection: &Connection) -> Result<u64, ImportRefusal> {
    let refused = |detail: String| ImportRefusal::Row {
        table: "receipts".to_owned(),
        detail,
    };
    let mut statement = connection
        .prepare(
            "SELECT actor_id, action_id, method, method_version, revision, state, reason,
                    payload_digest, accepted_deadline_ms, created_at_ms, updated_at_ms
             FROM receipts",
        )
        .map_err(unreadable)?;
    let mut rows = statement.query([]).map_err(unreadable)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(unreadable)? {
        let read = |detail: rusqlite::Error| refused(detail.to_string());
        let actor: String = row.get(0).map_err(read)?;
        let action: Vec<u8> = row.get(1).map_err(read)?;
        let method: String = row.get(2).map_err(read)?;
        let method_version: i64 = row.get(3).map_err(read)?;
        let revision: i64 = row.get(4).map_err(read)?;
        let state: String = row.get(5).map_err(read)?;
        let reason: Option<String> = row.get(6).map_err(read)?;
        let digest: Vec<u8> = row.get(7).map_err(read)?;
        let deadline: Option<i64> = row.get(8).map_err(read)?;
        let created: i64 = row.get(9).map_err(read)?;
        let updated: i64 = row.get(10).map_err(read)?;
        if ActorId::new(actor.clone()).is_err() {
            return Err(refused(format!("the actor {actor:?} is not valid")));
        }
        if action.len() != 16 {
            return Err(refused(format!(
                "an action identifier of {actor} is {} bytes, not 16",
                action.len()
            )));
        }
        if MethodName::new(method.clone()).is_err() {
            return Err(refused(format!("the method {method:?} is not valid")));
        }
        if u16::try_from(method_version).is_err() || revision < 0 {
            return Err(refused(format!(
                "an action of {actor} has method version {method_version} and revision {revision}"
            )));
        }
        if !ReceiptState::ALL
            .iter()
            .any(|known| known.as_str() == state)
        {
            return Err(refused(format!(
                "the state {state:?} is not in the contract"
            )));
        }
        if let Some(reason) = reason
            && !REJECTION_REASONS
                .iter()
                .any(|known| known.as_str() == reason)
        {
            return Err(refused(format!(
                "the rejection reason {reason:?} is not in the contract"
            )));
        }
        if digest.len() != 32 {
            return Err(refused(format!(
                "a payload digest of {actor} is {} bytes, not 32",
                digest.len()
            )));
        }
        if deadline.is_some_and(|deadline| deadline < 0) || created < 0 || updated < 0 {
            return Err(refused(format!(
                "an action of {actor} records a time before 1970"
            )));
        }
        count += 1;
    }
    Ok(count)
}

/// Every reason a receipt can be rejected for, as a receipt names it.
const REJECTION_REASONS: &[RejectionReason] = &[
    RejectionReason::AdmissionFailed,
    RejectionReason::Expired,
    RejectionReason::Cancelled,
    RejectionReason::Revoked,
    RejectionReason::StalePreconditions,
];

/// Checks every retained result decodes as a result is served.
fn check_results(connection: &Connection) -> Result<(), ImportRefusal> {
    let refused = |detail: String| ImportRefusal::Row {
        table: "results".to_owned(),
        detail,
    };
    let mut statement = connection
        .prepare("SELECT actor_id, action_id, result FROM results")
        .map_err(unreadable)?;
    let mut rows = statement.query([]).map_err(unreadable)?;
    while let Some(row) = rows.next().map_err(unreadable)? {
        let read = |detail: rusqlite::Error| refused(detail.to_string());
        let actor: String = row.get(0).map_err(read)?;
        let action: Vec<u8> = row.get(1).map_err(read)?;
        let result: Vec<u8> = row.get(2).map_err(read)?;
        if ActorId::new(actor.clone()).is_err() || action.len() != 16 {
            return Err(refused(format!(
                "a result names the actor {actor:?} and an identifier of {} bytes",
                action.len()
            )));
        }
        if kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT).is_err() {
            return Err(refused(format!("a result of {actor} does not decode")));
        }
    }
    Ok(())
}

/// Checks every closure record decodes as this build reads one.
fn check_closures(connection: &Connection) -> Result<(), ImportRefusal> {
    let refused = |detail: String| ImportRefusal::Row {
        table: "closure".to_owned(),
        detail,
    };
    let mut statement = connection
        .prepare("SELECT session_id, record FROM closure")
        .map_err(unreadable)?;
    let mut rows = statement.query([]).map_err(unreadable)?;
    while let Some(row) = rows.next().map_err(unreadable)? {
        let read = |detail: rusqlite::Error| refused(detail.to_string());
        let session: Vec<u8> = row.get(0).map_err(read)?;
        let record: Vec<u8> = row.get(1).map_err(read)?;
        if session.len() != 16 {
            return Err(refused(format!(
                "a closure's session identifier is {} bytes, not 16",
                session.len()
            )));
        }
        kr_cbor::from_canonical_slice::<kr_protocol::session::ClosureRecord>(
            &record,
            &kr_cbor::Limits::DEFAULT,
        )
        .map_err(|error| refused(format!("a closure record does not decode: {error}")))?;
    }
    Ok(())
}

/// One column as the comparison reads it: its name, its declared type, whether it is `NOT NULL`,
/// its default, and its place in the primary key.
type ColumnShape = (String, String, bool, Option<String>, i64);

/// One index as the comparison reads it: its table, whether it is unique, how it was made (by a
/// statement, a key or a constraint), whether it is partial, and its columns in order.
type IndexShape = (String, bool, String, bool, Vec<String>);

/// A schema as the comparison reads it: each table's columns, and every index by name, SQLite's
/// own included.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    tables: BTreeMap<String, BTreeSet<ColumnShape>>,
    indexes: BTreeMap<String, IndexShape>,
}

/// The current schema, created fresh, which is what an import has to arrive at.
fn current_shape() -> rusqlite::Result<Shape> {
    let fresh = Connection::open_in_memory()?;
    fresh.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL);")?;
    create_current_objects(&fresh)?;
    shape_of(&fresh)
}

/// Reads the tables a connection's schema holds, SQLite's own left out, and every index of them.
fn shape_of(connection: &Connection) -> rusqlite::Result<Shape> {
    let names: Vec<String> = {
        let mut statement = connection.prepare(
            "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type = 'table'",
        )?;
        statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut shape = Shape {
        tables: BTreeMap::new(),
        indexes: BTreeMap::new(),
    };
    for name in names {
        let listed: Vec<(String, bool, String, bool)> = {
            let mut statement = connection.prepare(&format!("PRAGMA index_list({name})"))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get(3)?,
                        row.get::<_, i64>(4)? != 0,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        for (index, unique, origin, partial) in listed {
            let mut statement = connection.prepare(&format!("PRAGMA index_info({index})"))?;
            let columns = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut columns = columns;
            columns.sort_by_key(|(position, _)| *position);
            shape.indexes.insert(
                index,
                (
                    name.clone(),
                    unique,
                    origin,
                    partial,
                    columns
                        .into_iter()
                        .map(|(_, column)| column.unwrap_or_default())
                        .collect(),
                ),
            );
        }
        let mut statement = connection.prepare(&format!("PRAGMA table_info({name})"))?;
        let columns = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?.to_ascii_uppercase(),
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        shape.tables.insert(name, columns);
    }
    Ok(shape)
}

/// Says the first way `produced` differs from `expected`, for a person.
fn difference(expected: &Shape, produced: &Shape) -> String {
    for (table, columns) in &expected.tables {
        match produced.tables.get(table) {
            None => return format!("it has no {table} table"),
            Some(found) if found != columns => {
                return format!("its {table} table's columns differ");
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = produced
        .tables
        .keys()
        .find(|table| !expected.tables.contains_key(*table))
    {
        return format!("it has a {extra} table the current schema does not");
    }
    for (index, made) in &expected.indexes {
        match produced.indexes.get(index) {
            None => return format!("it has no index {index}"),
            Some(found) if found != made => return format!("its index {index} differs"),
            Some(_) => {}
        }
    }
    match produced
        .indexes
        .keys()
        .find(|index| !expected.indexes.contains_key(*index))
    {
        Some(extra) => format!("it has an index {extra} the current schema does not"),
        None => "it differs from the current schema".to_owned(),
    }
}

fn unreadable(error: rusqlite::Error) -> ImportRefusal {
    ImportRefusal::Unreadable {
        detail: error.to_string(),
    }
}
