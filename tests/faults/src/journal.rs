//! Journals kept as fixtures: a worker's receipt journal as a stored state, with its fault applied
//! when the file is made.
//!
//! A fixture keeps the store as SQL at the schema version the build that wrote it was at, so a
//! person reads what the store held, and the file stays as written when the schema moves on:
//! opening it is then a migration, which the fixture's control has to survive. The fault is not in
//! the SQL. It is applied as the SQL is made into a database, because a damaged page or a torn log
//! is bytes that no SQL states:
//!
//! | Fault | What is done | What it stands for |
//! | --- | --- | --- |
//! | `none` | nothing | a stored state: a dispatch marker with no answer, an intent with no marker |
//! | `root_page_overwritten` | a table's root page is overwritten | damage that stays |
//! | `log_cut_in_last_frame` | the product's journal accepts one more action, its files are copied while it still holds them, and the copy of the log is cut inside its last frame | a crash inside a commit |
//!
//! Every fixture is also made as its control, which is the same file without the fault: the page
//! left alone, the log copied whole.
//!
//! ```json
//! {
//!   "format": "kalareach.journal/1",
//!   "name": "damaged-receipts",
//!   "about": "the receipts table's root page is overwritten",
//!   "schema_version": 6,
//!   "sql": ["CREATE TABLE schema_version (version INTEGER NOT NULL)", "..."],
//!   "fault": { "kind": "root_page_overwritten", "table": "receipts" }
//! }
//! ```

use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use kr_protocol::ids::ActorId;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Digest256, TimestampMs};
use kr_worker::journal::{Journal, Submission};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};

/// The format every fixture names, so a file of another shape is refused rather than misread.
pub const FORMAT: &str = "kalareach.journal/1";

/// The actor every fixture's actions belong to.
pub const ACTOR: &str = "fixture:journal";

/// When a fixture's first action was submitted, in UTC milliseconds.
pub const SUBMITTED_AT_MS: u64 = 1_790_000_000_000;

/// Where the fixtures are kept, from this crate's own directory.
#[must_use]
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/faults/journals")
}

/// A journal kept as a fixture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalFixture {
    /// Always [`FORMAT`].
    pub format: String,
    /// Its name, which is its file's name.
    pub name: String,
    /// What it holds and what is done to it, for a person reading a failure.
    pub about: String,
    /// The schema version the SQL was written at.
    pub schema_version: i64,
    /// The statements that rebuild the store, in order.
    pub sql: Vec<String>,
    /// What is done to the file once it is made.
    pub fault: Fault,
}

/// What is done to a fixture's file once it is made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Fault {
    /// Nothing: what the store holds is the fault.
    None,
    /// A table's root page is overwritten.
    RootPageOverwritten {
        /// The table.
        table: String,
    },
    /// The product's own journal accepts one more action, its files are copied while it still
    /// holds them, and the copy of the log is cut inside its last frame, which is that commit's.
    LogCutInLastFrame {
        /// The action it accepts, as [`submission`] makes it.
        accept: u8,
    },
}

/// Whether a fixture is made with its fault or as its control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Made {
    /// With the fault.
    WithFault,
    /// The same file without it.
    AsControl,
}

impl JournalFixture {
    /// Reads one fixture, which is named by its file.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the file: unreadable, not a fixture, or a name that is not its
    /// file's.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
        let fixture = Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let stem = path.file_stem().and_then(|stem| stem.to_str());
        if stem != Some(fixture.name.as_str()) {
            return Err(format!(
                "{} names itself {:?}; a fixture is named by its file",
                path.display(),
                fixture.name
            ));
        }
        Ok(fixture)
    }

    /// Reads one fixture from its text.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with it: not a fixture, another format, or no statements.
    pub fn parse(text: &str) -> Result<Self, String> {
        let fixture: Self = serde_json::from_str(text)
            .map_err(|error| format!("not a journal fixture: {error}"))?;
        if fixture.format != FORMAT {
            return Err(format!(
                "the format is {:?}, and a journal fixture is {FORMAT:?}",
                fixture.format
            ));
        }
        if fixture.sql.is_empty() {
            return Err("the fixture holds no statements".to_owned());
        }
        Ok(fixture)
    }

    /// Every fixture kept with this crate, in name order.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the first file that cannot be read as a fixture, or with the
    /// directory.
    pub fn all() -> Result<Vec<Self>, String> {
        let directory = directory();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} could not be listed: {error}", directory.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        paths.iter().map(|path| Self::load(path)).collect()
    }

    /// The fixture as a file keeps it.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Makes the store at `path`, which must not exist yet: the SQL, then the fault or its
    /// control.
    ///
    /// # Errors
    ///
    /// Returns the step that failed.
    pub fn make(&self, path: &Path, made: Made) -> Result<(), String> {
        match &self.fault {
            Fault::None => build(path, &self.sql),
            Fault::RootPageOverwritten { table } => {
                build(path, &self.sql)?;
                if made == Made::WithFault {
                    overwrite_root_page(path, table)?;
                }
                Ok(())
            }
            Fault::LogCutInLastFrame { accept } => {
                copy_while_written(path, &self.sql, *accept)?;
                if made == Made::WithFault {
                    cut_inside_last_frame(&log_of(path))?;
                }
                Ok(())
            }
        }
    }
}

/// One of a fixture's actions: `action` submitted by [`ACTOR`], with a payload of its own and a
/// time a second apart from the next.
///
/// # Errors
///
/// Returns what the actor's name was refused for.
pub fn submission(action: u8) -> Result<Submission, String> {
    let now = SUBMITTED_AT_MS + u64::from(action) * 1_000;
    Ok(Submission {
        actor_id: actor()?,
        action_id: kr_worker::journal::action_id_from([action; 16]),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([action; 32]),
        subject_digest: Digest256::from_bytes([action; 32]),
        intent: vec![action],
        accepted_deadline_ms: Some(TimestampMs::new(now + 120_000)),
        now_ms: TimestampMs::new(now),
    })
}

/// The actor every fixture's actions belong to.
///
/// # Errors
///
/// Returns what the name was refused for.
pub fn actor() -> Result<ActorId, String> {
    ActorId::new(ACTOR).map_err(|error| format!("{ACTOR} is not an actor: {error:?}"))
}

/// Makes a database at `path` from `sql` in one transaction, in write-ahead mode as the journal
/// keeps it, and moves the log into the file.
///
/// # Errors
///
/// Returns the statement that failed, or the step.
pub fn build(path: &Path, sql: &[String]) -> Result<(), String> {
    let at = |error: rusqlite::Error| format!("{}: {error}", path.display());
    let connection = Connection::open(path).map_err(at)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(at)?;
    let transaction = connection.unchecked_transaction().map_err(at)?;
    for (index, statement) in sql.iter().enumerate() {
        transaction
            .execute_batch(statement)
            .map_err(|error| format!("statement {index} ({statement}): {error}"))?;
    }
    transaction.commit().map_err(at)?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(at)?;
    connection.close().map_err(|(_, error)| at(error))
}

/// The statements that rebuild the store at `path`: its schema in the order it was made, every
/// table's rows in rowid order, and where each counter stands.
///
/// A statement's whitespace outside its string literals is one space wherever there was any, so
/// the file reads as SQL rather than as the indentation the build wrote it with.
///
/// # Errors
///
/// Returns what the store refused.
pub fn dump(path: &Path) -> Result<Vec<String>, String> {
    let at = |error: rusqlite::Error| format!("{}: {error}", path.display());
    let connection = Connection::open(path).map_err(at)?;
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY rowid",
        )
        .map_err(at)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(at)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(at)?;
    let mut statements: Vec<String> = objects.iter().map(|(_, _, sql)| collapsed(sql)).collect();
    for (_, table, _) in objects.iter().filter(|(kind, ..)| kind == "table") {
        statements.extend(rows(&connection, table).map_err(at)?);
    }
    let counters = connection
        .prepare("SELECT name, seq FROM sqlite_sequence ORDER BY name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()
        });
    // A store with no counting table has nothing to say about its counters.
    if let Ok(counters) = counters
        && !counters.is_empty()
    {
        statements.push("DELETE FROM sqlite_sequence".to_owned());
        statements.extend(counters.into_iter().map(|(name, seq)| {
            format!(
                "INSERT INTO sqlite_sequence (name, seq) VALUES ({}, {seq})",
                literal(ValueRef::Text(name.as_bytes()))
            )
        }));
    }
    Ok(statements)
}

/// One `INSERT` for every row of `table`, in rowid order.
fn rows(connection: &Connection, table: &str) -> Result<Vec<String>, rusqlite::Error> {
    let columns: Vec<String> = connection
        .prepare(&format!("PRAGMA table_info({})", identifier(table)))?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<_, _>>()?;
    let names = columns
        .iter()
        .map(|column| identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = connection.prepare(&format!(
        "SELECT * FROM {} ORDER BY rowid",
        identifier(table)
    ))?;
    let mut rows = statement.query([])?;
    let mut inserts = Vec::new();
    while let Some(row) = rows.next()? {
        let values = (0..columns.len())
            .map(|index| row.get_ref(index).map(literal))
            .collect::<Result<Vec<_>, _>>()?
            .join(", ");
        inserts.push(format!(
            "INSERT INTO {} ({names}) VALUES ({values})",
            identifier(table)
        ));
    }
    Ok(inserts)
}

/// A name as SQL spells it: bare when it is a plain lower-case name, quoted otherwise.
fn identifier(name: &str) -> String {
    let plain = name.starts_with(|character: char| character.is_ascii_lowercase())
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
    if plain {
        name.to_owned()
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

/// A stored value as an SQL literal.
fn literal(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "NULL".to_owned(),
        ValueRef::Integer(integer) => integer.to_string(),
        ValueRef::Real(real) => format!("{real:?}"),
        ValueRef::Text(text) => match std::str::from_utf8(text) {
            Ok(text) => format!("'{}'", text.replace('\'', "''")),
            Err(_) => format!("CAST(X'{}' AS TEXT)", hex::encode_upper(text)),
        },
        ValueRef::Blob(blob) => format!("X'{}'", hex::encode_upper(blob)),
    }
}

/// `sql` with every run of whitespace outside a string literal made one space, and none at the
/// ends.
fn collapsed(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut quoted = false;
    let mut space = false;
    for character in sql.chars() {
        if quoted {
            out.push(character);
            quoted = character != '\'';
            continue;
        }
        if character.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        quoted = character == '\'';
        out.push(character);
    }
    out
}

/// Overwrites the root page of `table` in the file at `path`, whose log has been moved into it.
fn overwrite_root_page(path: &Path, table: &str) -> Result<(), String> {
    let at = |error: rusqlite::Error| format!("{}: {error}", path.display());
    let connection = Connection::open(path).map_err(at)?;
    let root: i64 = connection
        .query_row(
            "SELECT rootpage FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .map_err(|error| format!("{} has no table {table}: {error}", path.display()))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(at)?;
    connection.close().map_err(|(_, error)| at(error))?;
    let (Ok(root), Ok(page_size)) = (u64::try_from(root), usize::try_from(page_size)) else {
        return Err(format!("table {table} has no page to overwrite"));
    };
    let io = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(io)?;
    file.seek(SeekFrom::Start((root - 1) * page_size as u64))
        .map_err(io)?;
    // No page type SQLite knows starts with this byte, so the page reads as damaged, not empty.
    file.write_all(&vec![0xa5; page_size]).map_err(io)?;
    file.sync_all().map_err(io)
}

/// The write-ahead log of the database at `path`.
fn log_of(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

/// Makes the store from `sql` in a directory of its own, has the product's journal accept
/// `accept` there, and copies the database and its log to `path` while the journal still holds
/// them, so the commit is in the log and nothing has moved it into the database.
fn copy_while_written(path: &Path, sql: &[String], accept: u8) -> Result<(), String> {
    let io = |error: std::io::Error| format!("{}: {error}", path.display());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let writer = tempfile::Builder::new()
        .prefix("kr-journal-writer-")
        .tempdir_in(parent)
        .map_err(io)?;
    let written = writer.path().join("journal.sqlite3");
    build(&written, sql)?;
    let mut journal =
        Journal::open(&written).map_err(|error| format!("the journal did not open: {error}"))?;
    let database = std::fs::read(&written).map_err(io)?;
    journal
        .accept(&submission(accept)?)
        .map_err(|error| format!("the journal did not accept action {accept}: {error}"))?;
    // The commit has to be in the log and nowhere else, or cutting the log would not take it
    // away: a checkpoint that moved it into the database file would have changed the file.
    if std::fs::read(&written).map_err(io)? != database {
        return Err(format!(
            "a checkpoint moved the accept of action {accept} into the database file, so cutting \
             the log would not remove it"
        ));
    }
    std::fs::copy(&written, path).map_err(io)?;
    std::fs::copy(log_of(&written), log_of(path)).map_err(io)?;
    drop(journal);
    writer.close().map_err(io)
}

/// Cuts the log at `log` inside its last frame, as a crash part way through writing it leaves it.
fn cut_inside_last_frame(log: &Path) -> Result<(), String> {
    /// A write-ahead log's own header, and each frame's.
    const LOG_HEADER: usize = 32;
    const FRAME_HEADER: usize = 24;
    let io = |error: std::io::Error| format!("{}: {error}", log.display());
    let length = usize::try_from(std::fs::metadata(log).map_err(io)?.len())
        .map_err(|_| format!("{} is too long to read", log.display()))?;
    let mut header = [0_u8; LOG_HEADER];
    std::io::Read::read_exact(&mut std::fs::File::open(log).map_err(io)?, &mut header)
        .map_err(io)?;
    // The page size is at byte 8, big-endian, and 1 stands for 65536.
    let page_size = match u32::from_be_bytes([header[8], header[9], header[10], header[11]]) {
        1 => 65_536,
        size => size as usize,
    };
    let frame = FRAME_HEADER + page_size;
    let frames = length.saturating_sub(LOG_HEADER);
    if frames == 0 || frames % frame != 0 {
        return Err(format!(
            "{} holds {frames} bytes of frames, which is not a whole number of {frame}-byte frames",
            log.display()
        ));
    }
    // A frame that ends a commit records the database's size after it at byte 4 of its header,
    // and every other frame records nought there. The last frame has to end the commit being cut.
    let mut last = [0_u8; FRAME_HEADER];
    let mut reader = std::fs::File::open(log).map_err(io)?;
    reader
        .seek(SeekFrom::Start((length - frame) as u64))
        .map_err(io)?;
    std::io::Read::read_exact(&mut reader, &mut last).map_err(io)?;
    if u32::from_be_bytes([last[4], last[5], last[6], last[7]]) == 0 {
        return Err(format!("{}'s last frame ends no commit", log.display()));
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(log)
        .map_err(io)?;
    file.set_len((length - frame / 2) as u64).map_err(io)?;
    file.sync_all().map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_outside_a_string_is_one_space_and_inside_one_is_kept() {
        assert_eq!(
            collapsed("CREATE TABLE t (\n    a TEXT DEFAULT 'x  y',\n    b INTEGER\n)"),
            "CREATE TABLE t ( a TEXT DEFAULT 'x  y', b INTEGER )"
        );
        assert_eq!(collapsed("  SELECT 'it''s   so'  "), "SELECT 'it''s   so'");
    }

    #[test]
    fn a_value_is_spelled_as_the_literal_that_stores_it_again() {
        assert_eq!(literal(ValueRef::Null), "NULL");
        assert_eq!(literal(ValueRef::Integer(-7)), "-7");
        assert_eq!(literal(ValueRef::Text(b"it's")), "'it''s'");
        assert_eq!(literal(ValueRef::Text(&[0xff])), "CAST(X'FF' AS TEXT)");
        assert_eq!(literal(ValueRef::Blob(&[0x0a, 0xbc])), "X'0ABC'");
        assert_eq!(identifier("receipts"), "receipts");
        assert_eq!(identifier("Odd name"), "\"Odd name\"");
    }
}
