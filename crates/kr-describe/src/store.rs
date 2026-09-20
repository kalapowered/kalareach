//! Names, pins and generated-description provenance.
//!
//! Section 24's ownership table gives *names, pins, generated description provenance* to an
//! environment session-metadata store keyed by context and model revisions, and states the two
//! properties it has to have: *metadata and pins survive closure* and *generated text never
//! overrides current verified state*. This is that store, a small SQLite file of its own under the
//! runtime root the host passes in.
//!
//! # Why it is its own file
//!
//! A pin outlives its session. The session journal does not: it is recovered, retired and
//! eventually collected, and a pin inside it would be collected with it. Keeping the pins in a
//! store the session does not own is what makes *pins survive closure* a property of where they
//! live rather than a rule about what not to delete.
//!
//! # The three-way precedence, in one place
//!
//! [`DescriptionStore::label`] is the only function in this product that decides what a session is
//! called, and it decides in one order: a pin, then a generated description, then the deterministic
//! title. The status beside it never comes from either of the first two, because it is not text and
//! it is passed in. That is section 24's *generated text never overrides current verified state*
//! expressed as one function with one argument that generated text cannot reach.

use std::path::Path;

use kr_protocol::ids::SessionId;
use kr_worker::privacy::PrivacyGeneration;
use rusqlite::{Connection, OptionalExtension, params};

use crate::context::{ContextRevision, CursorInterval};
use crate::error::{DescribeError, Result};
use crate::metadata::{
    ActivityText, LabelSource, SessionFacts, SessionLabel, Title, VerifiedStatus,
    deterministic_title,
};
use crate::output::GeneratedDescription;
use crate::profile::ProfileRevision;

/// The schema version this build writes and reads.
const SCHEMA_VERSION: i64 = 1;

/// A name a person pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The session.
    pub session_id: SessionId,
    /// The name.
    pub title: Title,
    /// Who pinned it.
    pub pinned_by: String,
    /// When.
    pub pinned_at_ms: u64,
}

/// A generated description, with the provenance that says what produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedRecord {
    /// The session.
    pub session_id: SessionId,
    /// The title.
    pub title: Title,
    /// The activity line.
    pub activity: ActivityText,
    /// The context revision it was produced at.
    pub revision: ContextRevision,
    /// The interval of the semantic stream it covers.
    pub cursor: CursorInterval,
    /// The profile that produced it.
    pub profile_id: String,
    /// That profile's revision.
    pub profile_revision: ProfileRevision,
    /// The privacy generation in force when it was produced.
    pub generation: PrivacyGeneration,
    /// When it was produced, on the wall clock.
    pub produced_at_ms: u64,
}

/// What removing generated text took out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovedText {
    /// How many records went.
    pub records: u64,
    /// How many bytes of title and activity text went with them.
    pub bytes: u64,
}

/// The names, pins and provenance store.
#[derive(Debug)]
pub struct DescriptionStore {
    connection: Connection,
}

impl DescriptionStore {
    /// Opens the store under a runtime root, creating it when it is not there.
    ///
    /// The root is the host's, and it belongs on local storage the host owns. Nothing here chooses
    /// a path: a store whose location this crate decided would be a store a packaged host could
    /// not place.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the directory cannot be made, the file cannot be
    /// opened, or the schema cannot be applied.
    pub fn open(runtime_root: &Path) -> Result<Self> {
        std::fs::create_dir_all(runtime_root).map_err(|error| DescribeError::Store {
            detail: format!("the runtime root could not be made: {error}"),
        })?;
        let connection =
            Connection::open(runtime_root.join("descriptions.sqlite3")).map_err(store_error)?;
        Self::apply_schema(&connection)?;
        Ok(Self { connection })
    }

    /// Opens a store that lives only in memory, which is what a test that has no root uses.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the schema cannot be applied.
    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(store_error)?;
        Self::apply_schema(&connection)?;
        Ok(Self { connection })
    }

    fn apply_schema(connection: &Connection) -> Result<()> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS describe_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS describe_pins (
                     session_id   TEXT PRIMARY KEY,
                     title        TEXT NOT NULL,
                     pinned_by    TEXT NOT NULL,
                     pinned_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS describe_generated (
                     session_id        TEXT PRIMARY KEY,
                     title             TEXT NOT NULL,
                     activity          TEXT NOT NULL,
                     context_revision  INTEGER NOT NULL,
                     cursor_from       INTEGER NOT NULL,
                     cursor_to         INTEGER NOT NULL,
                     profile_id        TEXT NOT NULL,
                     profile_revision  INTEGER NOT NULL,
                     privacy_generation INTEGER NOT NULL,
                     produced_at_ms    INTEGER NOT NULL
                 );",
            )
            .map_err(store_error)?;
        let version: Option<i64> = connection
            .query_row("SELECT version FROM describe_schema", [], |row| row.get(0))
            .optional()
            .map_err(store_error)?;
        match version {
            None => {
                connection
                    .execute(
                        "INSERT INTO describe_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(store_error)?;
            }
            Some(found) if found == SCHEMA_VERSION => {}
            Some(found) => {
                return Err(DescribeError::Store {
                    detail: format!(
                        "this store is at schema {found} and this build reads {SCHEMA_VERSION}"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Pins a session's name.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the write fails.
    pub fn pin(
        &self,
        session_id: &SessionId,
        title: &Title,
        pinned_by: &str,
        now_wall_ms: u64,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO describe_pins (session_id, title, pinned_by, pinned_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id) DO UPDATE SET
                     title = excluded.title,
                     pinned_by = excluded.pinned_by,
                     pinned_at_ms = excluded.pinned_at_ms",
                params![
                    session_id.to_string(),
                    title.as_str(),
                    pinned_by,
                    to_sqlite(now_wall_ms, "pin time")?
                ],
            )
            .map_err(store_error)?;
        Ok(())
    }

    /// Clears a session's pin, and returns whether there was one.
    ///
    /// Section 24: pinned labels are retained *unless explicitly cleared*. This is that explicit
    /// clearing, and it is the only thing in this crate that removes a pin.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the write fails.
    pub fn clear_pin(&self, session_id: &SessionId) -> Result<bool> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM describe_pins WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .map_err(store_error)?;
        Ok(removed > 0)
    }

    /// Returns a session's pin, when it has one.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read fails.
    pub fn pinned(&self, session_id: &SessionId) -> Result<Option<Pin>> {
        self.connection
            .query_row(
                "SELECT title, pinned_by, pinned_at_ms FROM describe_pins WHERE session_id = ?1",
                params![session_id.to_string()],
                |row| {
                    let title: String = row.get(0)?;
                    let pinned_by: String = row.get(1)?;
                    let pinned_at_ms: i64 = row.get(2)?;
                    Ok((title, pinned_by, pinned_at_ms))
                },
            )
            .optional()
            .map_err(store_error)?
            .map(|(title, pinned_by, pinned_at_ms)| {
                Ok(Pin {
                    session_id: *session_id,
                    title: Title::new(&title).ok_or_else(|| DescribeError::Store {
                        detail: "a stored pin is not a title this build can show".to_owned(),
                    })?,
                    pinned_by,
                    pinned_at_ms: from_sqlite(pinned_at_ms, "pin time")?,
                })
            })
            .transpose()
    }

    /// Returns how many pins this store holds.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read fails.
    pub fn pin_count(&self) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM describe_pins", [], |row| row.get(0))
            .map_err(store_error)?;
        from_sqlite(count, "pin count")
    }

    /// Returns whether one session has a pin, as a count of nought or one.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read fails.
    pub fn pin_count_for(&self, session_id: &SessionId) -> Result<u64> {
        Ok(u64::from(self.pinned(session_id)?.is_some()))
    }

    /// Records a generated description with its provenance.
    ///
    /// A session with a pin is refused here as well as at validation. The check is duplicated on
    /// purpose: validation is about a result that was in flight while somebody pinned a name, and
    /// this is about the store never holding a generated title for a session a person has named.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the write fails.
    pub fn publish(
        &self,
        session_id: &SessionId,
        description: &GeneratedDescription,
        now_wall_ms: u64,
    ) -> Result<Published> {
        if self.pinned(session_id)?.is_some() {
            return Ok(Published::NamePinned);
        }
        self.connection
            .execute(
                "INSERT INTO describe_generated (
                     session_id, title, activity, context_revision, cursor_from, cursor_to,
                     profile_id, profile_revision, privacy_generation, produced_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(session_id) DO UPDATE SET
                     title = excluded.title,
                     activity = excluded.activity,
                     context_revision = excluded.context_revision,
                     cursor_from = excluded.cursor_from,
                     cursor_to = excluded.cursor_to,
                     profile_id = excluded.profile_id,
                     profile_revision = excluded.profile_revision,
                     privacy_generation = excluded.privacy_generation,
                     produced_at_ms = excluded.produced_at_ms",
                params![
                    session_id.to_string(),
                    description.title.as_str(),
                    description.activity.as_str(),
                    to_sqlite(description.revision.get(), "context revision")?,
                    to_sqlite(description.cursor.from, "cursor")?,
                    to_sqlite(description.cursor.to, "cursor")?,
                    description.produced_under.profile_id,
                    to_sqlite(
                        description.produced_under.profile_revision.get(),
                        "profile revision"
                    )?,
                    to_sqlite(
                        description.produced_under.generation.get(),
                        "privacy generation"
                    )?,
                    to_sqlite(now_wall_ms, "publication time")?,
                ],
            )
            .map_err(store_error)?;
        Ok(Published::Recorded)
    }

    /// Returns a session's generated description, when it has one.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read fails.
    pub fn generated(&self, session_id: &SessionId) -> Result<Option<GeneratedRecord>> {
        let row = self
            .connection
            .query_row(
                "SELECT title, activity, context_revision, cursor_from, cursor_to, profile_id,
                        profile_revision, privacy_generation, produced_at_ms
                 FROM describe_generated WHERE session_id = ?1",
                params![session_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(store_error)?;
        let Some((
            title,
            activity,
            revision,
            cursor_from,
            cursor_to,
            profile_id,
            profile_revision,
            generation,
            produced_at_ms,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(GeneratedRecord {
            session_id: *session_id,
            title: Title::new(&title).ok_or_else(|| DescribeError::Store {
                detail: "a stored description is not a title this build can show".to_owned(),
            })?,
            activity: ActivityText::new(&activity).ok_or_else(|| DescribeError::Store {
                detail: "a stored description is not activity text this build can show".to_owned(),
            })?,
            revision: ContextRevision::new(from_sqlite(revision, "context revision")?),
            cursor: CursorInterval::new(
                from_sqlite(cursor_from, "cursor")?,
                from_sqlite(cursor_to, "cursor")?,
            ),
            profile_id,
            profile_revision: ProfileRevision::new(from_sqlite(
                profile_revision,
                "profile revision",
            )?),
            generation: PrivacyGeneration::new(from_sqlite(generation, "privacy generation")?),
            produced_at_ms: from_sqlite(produced_at_ms, "publication time")?,
        }))
    }

    /// Returns how many generated descriptions this store holds.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read fails.
    pub fn generated_count(&self) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM describe_generated", [], |row| {
                row.get(0)
            })
            .map_err(store_error)?;
        from_sqlite(count, "description count")
    }

    /// Removes every generated description, keeping every pin.
    ///
    /// This is what privacy mode's removal calls. It counts what it removed before removing it, so
    /// the figure reported is of rows that are gone rather than of rows that were asked to go.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read or the write fails.
    pub fn remove_generated(&self) -> Result<RemovedText> {
        self.remove_generated_where("1 = 1", &[])
    }

    /// Removes one session's generated description, keeping its pin.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the read or the write fails.
    pub fn remove_generated_for(&self, session_id: &SessionId) -> Result<RemovedText> {
        let id = session_id.to_string();
        self.remove_generated_where("session_id = ?1", &[&id])
    }

    /// Counts and deletes in one transaction, so the figure reported is of rows that went.
    ///
    /// The byte figure is of bytes: SQLite's `LENGTH` over text counts characters, so a title in a
    /// script that is three bytes a character would be reported as a third of its size. Casting to
    /// a blob first is what makes it the number of bytes this host stopped holding.
    fn remove_generated_where(
        &self,
        predicate: &str,
        parameters: &[&dyn rusqlite::ToSql],
    ) -> Result<RemovedText> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(store_error)?;
        let (records, bytes): (i64, i64) = transaction
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(
                         LENGTH(CAST(title AS BLOB)) + LENGTH(CAST(activity AS BLOB))), 0)
                     FROM describe_generated WHERE {predicate}"
                ),
                parameters,
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(store_error)?;
        let deleted = transaction
            .execute(
                &format!("DELETE FROM describe_generated WHERE {predicate}"),
                parameters,
            )
            .map_err(store_error)?;
        transaction.commit().map_err(store_error)?;
        let records = from_sqlite(records, "description count")?;
        if deleted as u64 != records {
            return Err(DescribeError::Store {
                detail: format!("{records} descriptions were counted and {deleted} were removed"),
            });
        }
        Ok(RemovedText {
            records,
            bytes: from_sqlite(bytes, "description size")?,
        })
    }

    /// Returns the label to show for one session.
    ///
    /// The order is fixed and it is the whole rule: a pin, then a generated description, then the
    /// deterministic title. The status is the caller's in every branch.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when a read fails. A store that cannot be read gives the
    /// deterministic label rather than nothing, but it says so rather than pretending the session
    /// has no pin.
    pub fn label(
        &self,
        session_id: &SessionId,
        facts: &SessionFacts,
        status: VerifiedStatus,
    ) -> Result<SessionLabel> {
        if let Some(pin) = self.pinned(session_id)? {
            return Ok(SessionLabel {
                title: pin.title,
                source: LabelSource::Pinned,
                activity: None,
                status,
            });
        }
        if let Some(generated) = self.generated(session_id)? {
            return Ok(SessionLabel {
                title: generated.title,
                source: LabelSource::Generated,
                activity: Some(generated.activity),
                status,
            });
        }
        Ok(SessionLabel {
            title: deterministic_title(facts),
            source: LabelSource::Metadata,
            activity: None,
            status,
        })
    }
}

/// What publishing a generated description did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    /// It was recorded.
    Recorded,
    /// The session's name is pinned, so nothing was recorded.
    NamePinned,
}

/// Renders a `u64` for SQLite, refusing a value SQLite cannot hold without changing it.
fn to_sqlite(value: u64, what: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| DescribeError::Store {
        detail: format!("a {what} of {value} is larger than this store can hold"),
    })
}

/// Reads a `u64` back, refusing a stored value that is not one.
fn from_sqlite(value: i64, what: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| DescribeError::Store {
        detail: format!("a stored {what} of {value} is not a value this build wrote"),
    })
}

fn store_error(error: rusqlite::Error) -> DescribeError {
    DescribeError::Store {
        detail: error.to_string(),
    }
}
