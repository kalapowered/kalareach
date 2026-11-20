//! `draft-revisions.sqlite3`: the binding revision each draft that names an application was written
//! under, kept beside the transfer journal in a store of its own.
//!
//! A draft that names an application is sent only under the revision it was written under, and
//! the journal ([`crate::store`]) holds no column for it, so a build that reads the journal and
//! not this store keeps reading it as it always did. A draft is bound to its row by three fixed
//! fields, the draft's identifier, the application it names and the time it was made, so a row
//! that belongs to another draft, or to one that a build which does not read this store rewrote,
//! gives no revision. A revision that cannot be read gives none either, and a draft that names an
//! application and holds no revision is not sent: this store never lets a draft go out under a
//! revision it was not written under.
//!
//! The two files cannot commit together. A create writes the row first and then the draft, so a
//! draft never exists without its row having been written; a row left by a create that failed, or
//! by a draft a build that does not read this store discarded, is swept when the journal is opened.

use std::path::{Path, PathBuf};

use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId, DraftId};
use kr_protocol::scalars::TimestampMs;
use rusqlite::{Connection, OptionalExtension, params};

/// The file's name, in the directory of the journal.
pub const FILE_NAME: &str = "draft-revisions.sqlite3";

/// The schema version of this store: the version it is made at and reads.
pub const SCHEMA_VERSION: i64 = 1;

/// One draft's row: the three fields that bind it to its draft, and the revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kept {
    pub(crate) draft_id: DraftId,
    pub(crate) application_instance_id: ApplicationInstanceId,
    pub(crate) created_at_ms: TimestampMs,
    pub(crate) agent_binding_revision: AgentBindingRevision,
}

/// The store, or the reason it is not open.
///
/// A store that cannot be opened is closed, not absent: nothing reads a revision from it, so every
/// draft that names an application is read as one that holds no revision, and nothing writes to it.
#[derive(Debug)]
pub(crate) struct Revisions {
    side: Result<Connection, String>,
}

impl Revisions {
    /// Where the store of the journal at `journal` is.
    pub(crate) fn beside(journal: &Path) -> PathBuf {
        journal.with_file_name(FILE_NAME)
    }

    /// Opens the store at `path`, making it on first use. A store that cannot be opened or is at a
    /// version this build does not read is closed.
    pub(crate) fn open(path: &Path) -> Self {
        let side = kr_flush::release::open_connection(path, None)
            .map_err(|error| kr_flush::release::describe(&error))
            .and_then(Self::prepare);
        Self { side }
    }

    /// A store that exists only for the life of this process.
    pub(crate) fn in_memory() -> Self {
        let side = Connection::open_in_memory()
            .map_err(|error| error.to_string())
            .and_then(Self::prepare);
        Self { side }
    }

    fn prepare(connection: Connection) -> Result<Connection, String> {
        let said = |error: rusqlite::Error| error.to_string();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(said)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(said)?;
        // The tables and the version row are made in one transaction: the store is never at a
        // version with a table missing.
        let transaction = connection.unchecked_transaction().map_err(said)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS draft_revisions_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS draft_revisions (
                     draft_id                BLOB PRIMARY KEY,
                     application_instance_id BLOB NOT NULL,
                     created_at_ms           INTEGER NOT NULL,
                     agent_binding_revision  INTEGER NOT NULL
                 );",
            )
            .map_err(said)?;
        let recorded: Option<i64> = transaction
            .query_row("SELECT version FROM draft_revisions_schema", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(said)?;
        match recorded {
            None => {
                transaction
                    .execute(
                        "INSERT INTO draft_revisions_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(said)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(version) => {
                return Err(format!(
                    "it is at schema version {version}; this build reads {SCHEMA_VERSION}"
                ));
            }
        }
        transaction.commit().map_err(said)?;
        Ok(connection)
    }

    fn connection(&self) -> Result<&Connection, String> {
        self.side
            .as_ref()
            .map_err(|reason| format!("the store of binding revisions is closed: {reason}"))
    }

    /// Writes the rows, in one transaction, replacing a row of the same draft.
    ///
    /// # Errors
    ///
    /// Returns the reason when the store is closed or the write fails; nothing is then written.
    pub(crate) fn keep(&self, rows: &[Kept]) -> Result<(), String> {
        let connection = self.connection()?;
        let said = |error: rusqlite::Error| error.to_string();
        let transaction = connection.unchecked_transaction().map_err(said)?;
        {
            let mut statement = transaction
                .prepare(
                    "INSERT OR REPLACE INTO draft_revisions
                         (draft_id, application_instance_id, created_at_ms, agent_binding_revision)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(said)?;
            for row in rows {
                statement
                    .execute(params![
                        crate::store::uuid_sql(row.draft_id.get()),
                        crate::store::uuid_sql(row.application_instance_id.get()),
                        crate::store::as_i64(row.created_at_ms.get()),
                        crate::store::identity_sql(row.agent_binding_revision.get()),
                    ])
                    .map_err(said)?;
            }
        }
        transaction.commit().map_err(said)
    }

    /// The revision a draft was written under, when a row of this store is bound to the draft by
    /// all three fixed fields. Any failure, a closed store included, gives none.
    pub(crate) fn read(
        &self,
        draft_id: DraftId,
        application_instance_id: ApplicationInstanceId,
        created_at_ms: TimestampMs,
    ) -> Option<AgentBindingRevision> {
        let connection = self.connection().ok()?;
        connection
            .query_row(
                "SELECT agent_binding_revision FROM draft_revisions
                  WHERE draft_id = ?1 AND application_instance_id = ?2 AND created_at_ms = ?3",
                params![
                    crate::store::uuid_sql(draft_id.get()),
                    crate::store::uuid_sql(application_instance_id.get()),
                    crate::store::as_i64(created_at_ms.get()),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|value| AgentBindingRevision::new(crate::store::identity_from_sql(value)))
    }

    /// Deletes a draft's row. A failure is not reported: a row left behind is swept when the
    /// journal is next opened, and a row with no draft is read by nothing.
    pub(crate) fn forget(&self, draft_id: DraftId) {
        if let Ok(connection) = self.connection() {
            let _ = connection.execute(
                "DELETE FROM draft_revisions WHERE draft_id = ?1",
                params![crate::store::uuid_sql(draft_id.get())],
            );
        }
    }

    /// Deletes every row whose draft the journal no longer holds. A failure is not reported, for
    /// the reason [`Self::forget`] gives.
    ///
    /// This runs only when the journal is opened, before anything writes to it, so no create falls
    /// between its two writes.
    pub(crate) fn sweep(&self, journal: &Connection) {
        let Ok(connection) = self.connection() else {
            return;
        };
        let _ = Self::sweep_in(connection, journal);
    }

    fn sweep_in(connection: &Connection, journal: &Connection) -> rusqlite::Result<()> {
        let held: Vec<Vec<u8>> = connection
            .prepare("SELECT draft_id FROM draft_revisions")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let transaction = connection.unchecked_transaction()?;
        for draft in held {
            let present: bool = journal.query_row(
                "SELECT EXISTS (SELECT 1 FROM drafts WHERE draft_id = ?1)",
                params![draft],
                |row| row.get(0),
            )?;
            if !present {
                transaction.execute(
                    "DELETE FROM draft_revisions WHERE draft_id = ?1",
                    params![draft],
                )?;
            }
        }
        transaction.commit()
    }
}
