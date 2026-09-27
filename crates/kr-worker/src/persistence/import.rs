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
//! * the version, every object in the file, every column of every table and every row are checked
//!   against those shapes, and anything else is refused by name: a version, an object, a column,
//!   a row;
//! * the receipts gain the columns later versions added, every object of the current schema is
//!   created from the journal's own definition of it, the starting privacy record is written and
//!   the version is set;
//! * the result is checked against a fresh current schema before anything is committed.
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
    /// A table version 1 always had is missing.
    #[error("this journal records version 1 and has no {table} table")]
    MissingTable {
        /// The table.
        table: String,
    },
    /// A table's columns are not the ones version 1 made.
    #[error("the {table} table is not the one version 1 made: {detail}")]
    Columns {
        /// The table.
        table: String,
        /// What differs.
        detail: String,
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
    let second_shape = check_objects(&transaction)?;
    check_columns(&transaction, "schema_version", SCHEMA_VERSION_COLUMNS)?;
    check_columns(&transaction, "receipts", RECEIPTS_COLUMNS)?;
    if second_shape {
        check_columns(&transaction, "results", RESULTS_COLUMNS)?;
        check_columns(&transaction, "closure", CLOSURE_COLUMNS)?;
    }
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
    let kept: i64 = transaction
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .map_err(unreadable)?;
    if u64::try_from(kept).unwrap_or(0) != receipts {
        return Err(ImportRefusal::Result {
            detail: format!("{receipts} receipts were read and {kept} are there"),
        });
    }
    transaction.commit().map_err(unreadable)?;
    Ok(Imported::Imported {
        from: IMPORTS,
        to: CURRENT,
        receipts,
    })
}

/// One column as a build recording version 1 made it: its name, its declared type, whether it is
/// `NOT NULL`, and its place in the primary key, nought for none.
type Column = (&'static str, &'static str, bool, i64);

const SCHEMA_VERSION_COLUMNS: &[Column] = &[("version", "INTEGER", true, 0)];

const RECEIPTS_COLUMNS: &[Column] = &[
    ("actor_id", "TEXT", true, 1),
    ("action_id", "BLOB", true, 2),
    ("method", "TEXT", true, 0),
    ("method_version", "INTEGER", true, 0),
    ("revision", "INTEGER", true, 0),
    ("state", "TEXT", true, 0),
    ("reason", "TEXT", false, 0),
    ("payload_digest", "BLOB", true, 0),
    ("accepted_deadline_ms", "INTEGER", false, 0),
    ("error_code", "TEXT", false, 0),
    ("error_message", "TEXT", false, 0),
    ("created_at_ms", "INTEGER", true, 0),
    ("updated_at_ms", "INTEGER", true, 0),
];

const RESULTS_COLUMNS: &[Column] = &[
    ("actor_id", "TEXT", true, 1),
    ("action_id", "BLOB", true, 2),
    ("result", "BLOB", true, 0),
];

const CLOSURE_COLUMNS: &[Column] = &[
    ("session_id", "BLOB", false, 1),
    ("record", "BLOB", true, 0),
];

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

/// Checks every object in the file against the two version 1 shapes, and says which it is.
///
/// SQLite's own objects - its internal tables and the indexes it makes for a primary key - are
/// its, not a build's, and are not asked about.
fn check_objects(connection: &Connection) -> Result<bool, ImportRefusal> {
    let objects: Vec<(String, String, String)> = {
        let mut statement = connection
            .prepare("SELECT type, name, tbl_name FROM sqlite_master")
            .map_err(unreadable)?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(unreadable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(unreadable)?
    };
    let mut tables = BTreeSet::new();
    for (kind, name, table) in &objects {
        if name.starts_with("sqlite_") {
            continue;
        }
        let known = match kind.as_str() {
            "table" => {
                ["schema_version", "receipts", "results", "closure"].contains(&name.as_str())
            }
            "index" => name == "receipts_created_at" && table == "receipts",
            _ => false,
        };
        if !known {
            return Err(ImportRefusal::UnknownObject {
                kind: kind.clone(),
                name: name.clone(),
            });
        }
        if kind == "table" {
            tables.insert(name.as_str());
        }
    }
    if !tables.contains("receipts") {
        return Err(ImportRefusal::MissingTable {
            table: "receipts".to_owned(),
        });
    }
    // The second shape had both tables, because one build made both.
    match (tables.contains("results"), tables.contains("closure")) {
        (true, true) => Ok(true),
        (false, false) => Ok(false),
        (true, false) => Err(ImportRefusal::MissingTable {
            table: "closure".to_owned(),
        }),
        (false, true) => Err(ImportRefusal::MissingTable {
            table: "results".to_owned(),
        }),
    }
}

/// Checks a table's columns against the ones version 1 made, in name, type, nullability and key.
fn check_columns(
    connection: &Connection,
    table: &str,
    expected: &[Column],
) -> Result<(), ImportRefusal> {
    let found: Vec<(String, String, bool, i64)> = {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(unreadable)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(1)?,
                    row.get::<_, String>(2)?.to_ascii_uppercase(),
                    row.get::<_, i64>(3)? != 0,
                    row.get(5)?,
                ))
            })
            .map_err(unreadable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(unreadable)?
    };
    let refused = |detail: String| ImportRefusal::Columns {
        table: table.to_owned(),
        detail,
    };
    for (name, kind, not_null, key) in expected {
        let Some(column) = found.iter().find(|column| column.0 == *name) else {
            return Err(refused(format!("it has no {name} column")));
        };
        if column.1 != *kind || column.2 != *not_null || column.3 != *key {
            return Err(refused(format!(
                "its {name} column is {} {}{}",
                column.1,
                if column.2 { "NOT NULL" } else { "nullable" },
                if column.3 > 0 {
                    ", part of the key"
                } else {
                    ""
                }
            )));
        }
    }
    if let Some(extra) = found
        .iter()
        .find(|column| !expected.iter().any(|(name, ..)| *name == column.0))
    {
        return Err(refused(format!("it has a {} column", extra.0)));
    }
    Ok(())
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

/// A schema as the comparison reads it: each table's columns, and the named indexes.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    tables: BTreeMap<String, BTreeSet<ColumnShape>>,
    indexes: BTreeSet<String>,
}

/// The current schema, created fresh, which is what an import has to arrive at.
fn current_shape() -> rusqlite::Result<Shape> {
    let fresh = Connection::open_in_memory()?;
    fresh.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL);")?;
    create_current_objects(&fresh)?;
    shape_of(&fresh)
}

/// Reads the tables and named indexes a connection's schema holds, SQLite's own left out.
fn shape_of(connection: &Connection) -> rusqlite::Result<Shape> {
    let names: Vec<(String, String)> = {
        let mut statement = connection.prepare(
            "SELECT type, name FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index')",
        )?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut shape = Shape {
        tables: BTreeMap::new(),
        indexes: BTreeSet::new(),
    };
    for (kind, name) in names {
        if kind == "index" {
            shape.indexes.insert(name);
            continue;
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
    format!(
        "its indexes are {:?} and the current schema's are {:?}",
        produced.indexes, expected.indexes
    )
}

fn unreadable(error: rusqlite::Error) -> ImportRefusal {
    ImportRefusal::Unreadable {
        detail: error.to_string(),
    }
}
