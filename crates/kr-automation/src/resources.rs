//! What a workflow node's dispatch owns outside the journal.
//!
//! A node that runs a command or creates a session allocates things the journal does not hold: a
//! session, a directory it runs in, a materialisation of the version it tests, a workspace its
//! run is bound to. The journal settles a node when its action's wait ends, and that is not when
//! the allocation ends: a command can outlive its wait, and a daemon can stop between an
//! allocation and the node's settlement. This ledger is where each dispatch writes down what it
//! is about to own, **before** it allocates, so that whatever the dispatch left behind can be
//! found from durable state alone, and released, by the task that owns it while it runs and by a
//! sweep once nothing in this daemon does.
//!
//! One row per node dispatch, keyed by the node's action identifier. A row is `open` until its
//! resources are released and `released` after. A node that creates a session and leaves it
//! running (`create_session`) owns no session: its row records no obligation to close one.

use std::path::Path;
use std::sync::Mutex;

use kr_protocol::automation::WorkflowActionKind;
use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::{
    ActionId, GrantId, MaterialisationId, SessionId, WorkflowRunId, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AutomationError, Result};

/// The ledger's file in the environment's state directory.
pub const RESOURCES_DB_NAME: &str = "workflow-resources.db";

/// The schema version this build writes.
pub const RESOURCES_SCHEMA_VERSION: u32 = 1;

/// The oldest schema version this build reads.
pub const RESOURCES_OLDEST_SCHEMA_VERSION: u32 = 1;

/// Whether a dispatch's resources are still owed their release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedState {
    /// The resources may exist and have not been released.
    Open,
    /// Everything the dispatch allocated has been released.
    Released,
}

impl OwnedState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Released => "released",
        }
    }

    fn from_text(text: &str) -> Option<Self> {
        match text {
            "open" => Some(Self::Open),
            "released" => Some(Self::Released),
            _ => None,
        }
    }
}

/// What one node dispatch owns, or is about to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owned {
    /// The node's journalled action identifier: the create token of its session and the key of
    /// this row.
    pub action_id: ActionId,
    /// The run the dispatch belongs to.
    pub run_id: WorkflowRunId,
    /// The node.
    pub node_id: String,
    /// The node's action kind.
    pub kind: WorkflowActionKind,
    /// The grant the definition acts under, from which the principal its session was created
    /// under is derived.
    pub grant_id: GrantId,
    /// Whether the node closes its session when it settles. A `create_session` node does not: its
    /// session is the node's output and stays.
    pub owns_session: bool,
    /// The materialisation the node's command runs in, whose identifier is chosen before it is
    /// made.
    pub materialisation_id: Option<MaterialisationId>,
    /// The scratch directory the node's command runs in, when it declared no workspace.
    pub scratch: Option<String>,
    /// The identity of that directory (device and inode, as text), written down once it exists
    /// and before the command can start. A directory is removed only when it still has this
    /// identity; one that was never identified is removed only when it is empty.
    pub scratch_identity: Option<String>,
    /// The workspace the run is bound to for this node, when the definition names one.
    pub workspace_id: Option<WorkspaceId>,
    /// The session the dispatch made, once it has made it. A session is also found through the
    /// registry by the dispatch's action identifier; this is what the workspace binding ends by.
    pub session_id: Option<SessionId>,
    /// The process of the session's worker, once the session exists. A closure that could not
    /// account for the worker leaves the row open until the kernel says this process has ended.
    pub worker: Option<ProcessStartIdentity>,
    /// The boot the dispatch began in, which is the boot its session is made in. A worker of an
    /// earlier boot is gone with that boot.
    pub boot: Option<BootIdentity>,
    /// Where the resources stand.
    pub state: OwnedState,
}

/// The ledger of what node dispatches own.
#[derive(Debug)]
pub struct ResourceLedger {
    connection: Mutex<Connection>,
}

impl ResourceLedger {
    /// Opens the ledger in `state_dir`, creating it when there is none.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the file cannot be opened, and a refusal when it was written
    /// to a schema version this build does not read.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let path = state_dir.as_ref().join(RESOURCES_DB_NAME);
        let connection = kr_flush::release::open_connection(&path, None)?;
        Self::around(connection, &path.display().to_string())
    }

    /// Opens an in-memory ledger for tests.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the schema cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::around(Connection::open_in_memory()?, ":memory:")
    }

    fn around(mut connection: Connection, path: &str) -> Result<Self> {
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let found: u32 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let empty: bool = transaction.query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )?;
        if !empty && !(RESOURCES_OLDEST_SCHEMA_VERSION..=RESOURCES_SCHEMA_VERSION).contains(&found)
        {
            return Err(AutomationError::InvalidArgument(format!(
                "the workflow resource ledger at {path} was written to schema version {found}, \
                 and this build reads version {RESOURCES_SCHEMA_VERSION}"
            )));
        }
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS owned (
                action_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                owns_session INTEGER NOT NULL,
                materialisation_id TEXT,
                scratch TEXT,
                scratch_identity TEXT,
                workspace_id TEXT,
                session_id TEXT,
                worker_process TEXT,
                boot TEXT,
                state TEXT NOT NULL,
                began_at_ms INTEGER NOT NULL,
                released_at_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS owned_state ON owned (state);
            ",
        )?;
        transaction.pragma_update(None, "user_version", RESOURCES_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Writes down what a dispatch is about to own, before it allocates any of it.
    ///
    /// A dispatch that is begun again for the same action (a retry that reached the same node) finds
    /// its row and leaves it alone.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn begin(&self, owned: &Owned, now_ms: u64) -> Result<()> {
        self.lock().execute(
            "INSERT OR IGNORE INTO owned
               (action_id, run_id, node_id, kind, grant_id, owns_session, materialisation_id,
                scratch, workspace_id, session_id, boot, state, began_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                owned.action_id.get().to_string(),
                owned.run_id.to_string(),
                owned.node_id,
                owned.kind.as_str(),
                owned.grant_id.to_string(),
                owned.owns_session,
                owned.materialisation_id.map(|id| id.to_string()),
                owned.scratch,
                owned.workspace_id.map(|id| id.to_string()),
                owned.session_id.map(|id| id.to_string()),
                owned.boot.as_ref().map(encoded).transpose()?,
                OwnedState::Open.as_str(),
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            ],
        )?;
        Ok(())
    }

    /// Records the identity of the scratch directory a dispatch made, once it exists and before
    /// the command that runs in it can start.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn note_scratch_identity(&self, action_id: ActionId, identity: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE owned SET scratch_identity = ?2 WHERE action_id = ?1",
            params![action_id.get().to_string(), identity],
        )?;
        Ok(())
    }

    /// Records the session a dispatch made and the process of its worker, which is the process the
    /// launcher started once the registry has one. The boot the row was begun in stays as it was
    /// written: the session is made in the boot its dispatch runs in.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn note_session(
        &self,
        action_id: ActionId,
        session_id: SessionId,
        worker: Option<&ProcessStartIdentity>,
    ) -> Result<()> {
        let worker = worker.map(encoded).transpose()?;
        self.lock().execute(
            "UPDATE owned SET session_id = ?2, worker_process = COALESCE(?3, worker_process)
              WHERE action_id = ?1",
            params![action_id.get().to_string(), session_id.to_string(), worker],
        )?;
        Ok(())
    }

    /// Marks a dispatch's resources released.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn release(&self, action_id: ActionId, now_ms: u64) -> Result<()> {
        self.lock().execute(
            "UPDATE owned SET state = ?2, released_at_ms = ?3 WHERE action_id = ?1",
            params![
                action_id.get().to_string(),
                OwnedState::Released.as_str(),
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            ],
        )?;
        Ok(())
    }

    /// Whether another dispatch of the same run still owes the release of the same workspace.
    ///
    /// The run's hold on a workspace is one hold however many of its nodes ran there, so the hold
    /// ends with the last of them.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn another_holds(
        &self,
        run_id: WorkflowRunId,
        workspace_id: WorkspaceId,
        except: ActionId,
    ) -> Result<bool> {
        Ok(self.lock().query_row(
            "SELECT EXISTS (SELECT 1 FROM owned
                             WHERE run_id = ?1 AND workspace_id = ?2 AND state = ?3
                               AND action_id <> ?4)",
            params![
                run_id.to_string(),
                workspace_id.to_string(),
                OwnedState::Open.as_str(),
                except.get().to_string(),
            ],
            |row| row.get(0),
        )?)
    }

    /// Forgets the rows that were released before `before_ms`.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be removed.
    pub fn forget_released_before(&self, before_ms: u64) -> Result<usize> {
        Ok(self.lock().execute(
            "DELETE FROM owned WHERE state = ?1 AND released_at_ms < ?2",
            params![
                OwnedState::Released.as_str(),
                i64::try_from(before_ms).unwrap_or(i64::MAX),
            ],
        )?)
    }

    /// Reads one dispatch's row.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn get(&self, action_id: ActionId) -> Result<Option<Owned>> {
        let connection = self.lock();
        let row = connection
            .query_row(
                &format!("SELECT {COLUMNS} FROM owned WHERE action_id = ?1"),
                params![action_id.get().to_string()],
                read_row,
            )
            .optional()?;
        row.map(TryInto::try_into).transpose()
    }

    /// Lists every dispatch whose resources are still owed their release, oldest first.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn open_rows(&self) -> Result<Vec<Owned>> {
        let connection = self.lock();
        let mut statement = connection.prepare(&format!(
            "SELECT {COLUMNS} FROM owned WHERE state = ?1 ORDER BY began_at_ms, rowid"
        ))?;
        let rows = statement
            .query_map(params![OwnedState::Open.as_str()], read_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}

const COLUMNS: &str = "action_id, run_id, node_id, kind, grant_id, owns_session, \
                       materialisation_id, scratch, scratch_identity, workspace_id, session_id, \
                       worker_process, boot, state";

/// A row as the database holds it, before its text is read as identifiers.
struct RawRow {
    action_id: String,
    run_id: String,
    node_id: String,
    kind: String,
    grant_id: String,
    owns_session: bool,
    materialisation_id: Option<String>,
    scratch: Option<String>,
    scratch_identity: Option<String>,
    workspace_id: Option<String>,
    session_id: Option<String>,
    worker_process: Option<String>,
    boot: Option<String>,
    state: String,
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        action_id: row.get(0)?,
        run_id: row.get(1)?,
        node_id: row.get(2)?,
        kind: row.get(3)?,
        grant_id: row.get(4)?,
        owns_session: row.get(5)?,
        materialisation_id: row.get(6)?,
        scratch: row.get(7)?,
        scratch_identity: row.get(8)?,
        workspace_id: row.get(9)?,
        session_id: row.get(10)?,
        worker_process: row.get(11)?,
        boot: row.get(12)?,
        state: row.get(13)?,
    })
}

impl TryFrom<RawRow> for Owned {
    type Error = AutomationError;

    fn try_from(raw: RawRow) -> Result<Self> {
        let unreadable = |what: &str| {
            AutomationError::InvalidArgument(format!(
                "the workflow resource ledger holds a row whose {what} is not one"
            ))
        };
        let uuid = |text: &str, what: &str| {
            text.parse::<kr_protocol::scalars::Uuid>()
                .map_err(|_| unreadable(what))
        };
        Ok(Self {
            action_id: ActionId::new(uuid(&raw.action_id, "action identifier")?),
            run_id: WorkflowRunId::new(uuid(&raw.run_id, "run identifier")?),
            node_id: raw.node_id,
            kind: WorkflowActionKind::from_wire(&raw.kind).ok_or_else(|| unreadable("kind"))?,
            grant_id: GrantId::new(uuid(&raw.grant_id, "grant identifier")?),
            owns_session: raw.owns_session,
            materialisation_id: raw
                .materialisation_id
                .as_deref()
                .map(|text| uuid(text, "materialisation identifier").map(MaterialisationId::new))
                .transpose()?,
            scratch: raw.scratch,
            scratch_identity: raw.scratch_identity,
            workspace_id: raw
                .workspace_id
                .as_deref()
                .map(|text| uuid(text, "workspace identifier").map(WorkspaceId::new))
                .transpose()?,
            session_id: raw
                .session_id
                .as_deref()
                .map(|text| uuid(text, "session identifier").map(SessionId::new))
                .transpose()?,
            worker: raw
                .worker_process
                .as_deref()
                .map(|text| decoded(text).ok_or_else(|| unreadable("worker process")))
                .transpose()?,
            boot: raw
                .boot
                .as_deref()
                .map(|text| decoded(text).ok_or_else(|| unreadable("boot")))
                .transpose()?,
            state: OwnedState::from_text(&raw.state).ok_or_else(|| unreadable("state"))?,
        })
    }
}

/// A value as the text the ledger keeps it as.
fn encoded<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| {
        AutomationError::InvalidArgument(format!(
            "a value for the workflow resource ledger could not be written: {error}"
        ))
    })
}

/// A value read back from the text [`encoded`] made.
fn decoded<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_str(text).ok()
}

/// The session a dispatch owns is found through the registry from its action identifier and the
/// principal derived from its grant; this names the pair, so the ledger and the controller agree.
#[must_use]
pub fn session_principal(grant_id: GrantId) -> String {
    format!("workflow:{grant_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn owned(seed: u8, kind: WorkflowActionKind, owns_session: bool) -> Owned {
        let uuid = |offset: u8| Uuid::from_bytes([seed.wrapping_add(offset); 16]);
        Owned {
            action_id: ActionId::new(uuid(0)),
            run_id: WorkflowRunId::new(uuid(1)),
            node_id: format!("node-{seed}"),
            kind,
            grant_id: GrantId::new(uuid(2)),
            owns_session,
            materialisation_id: Some(MaterialisationId::new(uuid(3))),
            scratch: Some("/scratch".to_owned()),
            scratch_identity: None,
            workspace_id: Some(WorkspaceId::new(uuid(4))),
            session_id: None,
            worker: None,
            boot: None,
            state: OwnedState::Open,
        }
    }

    #[test]
    fn a_row_is_written_before_the_allocation_and_listed_until_it_is_released() {
        let ledger = ResourceLedger::in_memory().expect("a ledger");
        let first = owned(1, WorkflowActionKind::RunTests, true);
        let second = owned(2, WorkflowActionKind::CreateSession, false);
        ledger.begin(&first, 10).expect("it begins");
        ledger.begin(&second, 20).expect("it begins");
        // A dispatch begun again for the same action finds its row and leaves it alone.
        ledger.begin(&first, 30).expect("it begins again");

        assert_eq!(
            ledger.open_rows().expect("rows"),
            vec![first.clone(), second.clone()]
        );
        ledger.release(first.action_id, 40).expect("it releases");
        assert_eq!(ledger.open_rows().expect("rows"), vec![second]);
        assert_eq!(
            ledger
                .get(first.action_id)
                .expect("a row")
                .map(|row| row.state),
            Some(OwnedState::Released)
        );
    }

    #[test]
    fn what_a_dispatch_made_is_found_again_from_the_row() {
        let ledger = ResourceLedger::in_memory().expect("a ledger");
        let boot = BootIdentity {
            source: kr_protocol::identity::BootIdentitySource::LinuxBootId,
            value: kr_protocol::scalars::Bytes::new(vec![1, 2, 3]),
        };
        let mut row = owned(3, WorkflowActionKind::ShellCommand, true);
        row.boot = Some(boot.clone());
        ledger.begin(&row, 10).expect("it begins");
        ledger
            .note_scratch_identity(row.action_id, "12:34")
            .expect("the directory is identified");
        let worker = ProcessStartIdentity::new(
            77,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            1_234,
        );
        let session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
        ledger
            .note_session(row.action_id, session, Some(&worker))
            .expect("the session is written down");
        let found = ledger.get(row.action_id).expect("reads").expect("a row");
        assert_eq!(found.scratch_identity.as_deref(), Some("12:34"));
        assert_eq!(found.session_id, Some(session));
        assert_eq!(found.worker, Some(worker));
        assert_eq!(found.boot, Some(boot));
    }

    #[test]
    fn a_runs_hold_on_a_workspace_ends_with_the_last_row_that_holds_it() {
        let ledger = ResourceLedger::in_memory().expect("a ledger");
        let first = owned(5, WorkflowActionKind::ShellCommand, true);
        let mut second = owned(6, WorkflowActionKind::ShellCommand, true);
        second.run_id = first.run_id;
        second.workspace_id = first.workspace_id;
        ledger.begin(&first, 10).expect("it begins");
        ledger.begin(&second, 20).expect("it begins");
        let (run, workspace) = (first.run_id, first.workspace_id.expect("a workspace"));

        assert!(
            ledger
                .another_holds(run, workspace, first.action_id)
                .expect("reads"),
            "the second row still holds it"
        );
        ledger.release(second.action_id, 30).expect("it releases");
        assert!(
            !ledger
                .another_holds(run, workspace, first.action_id)
                .expect("reads"),
            "nothing else holds it, so the first row's release ends the hold"
        );
        assert_eq!(ledger.forget_released_before(31).expect("forgets"), 1);
        assert!(ledger.get(second.action_id).expect("reads").is_none());
        assert!(ledger.get(first.action_id).expect("reads").is_some());
    }

    #[test]
    fn a_ledger_written_to_a_newer_version_is_not_read() {
        let directory = tempfile::tempdir().expect("a directory");
        {
            let connection =
                kr_flush::release::open_connection(&directory.path().join(RESOURCES_DB_NAME), None)
                    .expect("a connection");
            connection
                .execute_batch("CREATE TABLE owned (action_id TEXT); PRAGMA user_version = 99;")
                .expect("a newer ledger");
        }
        ResourceLedger::open(directory.path()).expect_err("a newer ledger is refused");
    }
}
