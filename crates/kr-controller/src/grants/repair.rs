//! The repair of grants rows that cannot be read, and its undo.
//!
//! `kr host repair-grants` runs on the environment's own files with no daemon: the caller holds the
//! environment's singleton lock. The repair never opens the registry through [`Registry::open`] or
//! [`GrantDirectory::open`], which migrate, settle and create tables; it reads and writes the
//! grants tables of a registry that already has this build's shape, and refuses any other.
//!
//! Nothing here widens authority. It removes rows that cannot be read, revokes the live grants that
//! trace to no root, and owes one fence for the change; it writes no grants row that was not there.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use kr_protocol::ids::{EnvironmentId, GrantId};

use crate::error::{ControllerError, DamageClass};
use crate::grants::store::{
    Disposal, GrantDirectory, Plan, Roots, Scan, Scope, next_moment, plan_withdrawal, scan_all,
};
use crate::registry::{LOG_BUSY, RecordedIn, Registry, SCHEMA_VERSION, recorded_version};

/// What the debt a repair writes says it covers.
const COVERS: &str = "the repair of damaged grants rows";

/// Why a repair or an undo changed nothing. Every one of these leaves the registry as it was,
/// except [`Self::ReplacedButNotSynced`], which says the undo replaced it.
#[derive(Debug)]
pub enum Refusal {
    /// The registry's write-ahead log could not be taken in while another connection uses it.
    LogBusy,
    /// The registry records another schema version than the one this build reads.
    OtherBuild {
        /// The version it records.
        version: i64,
    },
    /// The registry records no readable schema version.
    NoVersion,
    /// A grants table lacks a column this build uses.
    WrongShape,
    /// The registry could not be read or written.
    RegistryUnreadable,
    /// The copy of the registry could not be made.
    CopyFailed(std::io::Error),
    /// The copy is not a registry of this build's schema, or does not open.
    CopyUnreadable,
    /// The copy was not made from this environment's registry.
    CopyOfAnotherEnvironment,
    /// The host has run since the copy was made.
    HostRanSinceTheCopy,
    /// A file from an earlier undo stands where the replacement is made.
    LeftoverFile(PathBuf),
    /// The registry could not be replaced by the copy.
    ReplaceFailed(std::io::Error),
    /// The registry was replaced by the copy, and the folder that holds it could not be synced to
    /// disk, so the earlier registry may come back if the computer stops before the disk writes
    /// the folder.
    ReplacedButNotSynced(std::io::Error),
}

/// A row of the registry that cannot be read.
#[derive(Clone, Debug)]
pub struct DamagedRow {
    /// Its place in the table, from 1.
    pub place: u64,
    /// What is wrong with it.
    pub class: DamageClass,
    /// Its key, when the key is a grant identifier.
    pub key: Option<GrantId>,
}

/// What the registry holds that the repair would deal with.
#[derive(Clone, Debug, Default)]
pub struct Found {
    /// The rows that cannot be read.
    pub damaged: Vec<DamagedRow>,
    /// The live grants that trace to no root, which the repair would withdraw.
    pub withdraw: Vec<GrantId>,
}

impl Found {
    /// Whether there is nothing to repair.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.damaged.is_empty() && self.withdraw.is_empty()
    }
}

/// What a repair did.
#[derive(Debug)]
pub struct Repaired {
    /// The folder the copy was made in.
    pub folder: PathBuf,
    /// The copy of the registry, as it was before the repair.
    pub copy: PathBuf,
    /// What was removed and withdrawn.
    pub found: Found,
    /// Whether the repair wrote a fence debt, which the host pays when it starts.
    pub fence_owed: bool,
}

/// The grants an undo would make live again.
#[derive(Debug)]
pub struct UndoPreview {
    /// The live grants of the copy that are not live in the registry.
    pub live_again: Vec<GrantId>,
}

/// The columns each grants table must have: what the build's readers use.
const SHAPE: [(&str, &[&str]); 3] = [
    (
        "grants",
        &[
            "grant_id",
            "parent_grant_id",
            "recipient_device_id",
            "session_id",
            "grant",
            "issued_at_ms",
            "activated_at_ms",
            "revoked_at_ms",
            "revoked_by_parent",
            "expired_at_ms",
        ],
    ),
    ("fence_debt", &["debt_id", "covers", "recorded_at_ms"]),
    (
        "session_invitations",
        &[
            "invitation_id",
            "issuer_device_id",
            "grant_id",
            "recipient_device_id",
            "preview",
            "state",
            "redeemed_by",
            "issued_at_ms",
            "expires_at_ms",
        ],
    ),
];

fn unreadable<T>(_: T) -> Refusal {
    Refusal::RegistryUnreadable
}

/// Takes in the log beside `path`. Only the checkpoint's refusal, while another connection holds
/// the log, says the registry is in use; a registry that cannot be looked at, or a log that is not a
/// regular file, is unreadable.
fn take_in_the_log(path: &Path) -> Result<(), Refusal> {
    Registry::take_in_its_log(path)
        .map(drop)
        .map_err(|error| match error {
            ControllerError::RegistryUnavailable { detail } if detail == LOG_BUSY => {
                Refusal::LogBusy
            }
            _ => Refusal::RegistryUnreadable,
        })
}

/// Opens `path` for reading and writing, which creates nothing.
fn open(path: &Path, writing: bool) -> Result<Connection, Refusal> {
    let flags = if writing {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags).map_err(unreadable)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(unreadable)?;
    Ok(connection)
}

/// The registry at `path`, ready to read and write its grants tables: its log taken in, its
/// version this build's, and every table of the shape this build reads.
fn prepare(path: &Path) -> Result<Connection, Refusal> {
    take_in_the_log(path)?;
    match recorded_version(path, RecordedIn::Table("schema_version")) {
        Ok(Some(version)) if version == SCHEMA_VERSION => {}
        Ok(Some(version)) => return Err(Refusal::OtherBuild { version }),
        Ok(None) | Err(_) => return Err(Refusal::NoVersion),
    }
    let connection = open(path, true)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unreadable)?;
    for (table, columns) in SHAPE {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(unreadable)?;
        let have: BTreeSet<String> = statement
            .query_map([], |row| row.get(1))
            .map_err(unreadable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(unreadable)?;
        if !columns.iter().all(|column| have.contains(*column)) {
            return Err(Refusal::WrongShape);
        }
    }
    Ok(connection)
}

fn found_of(scan: &Scan, plan: &Plan) -> Found {
    Found {
        damaged: scan
            .damaged
            .iter()
            .map(|row| DamagedRow {
                place: row.place,
                class: row.damage.class,
                key: row.damage.key,
            })
            .collect(),
        withdraw: plan
            .subtrees
            .iter()
            .flat_map(|subtree| subtree.rows.iter())
            .filter(|record| record.revoked_at_ms.is_none())
            .map(|record| record.grant.grant_id)
            .collect(),
    }
}

/// What the repair would remove and withdraw, in one read transaction that writes nothing.
///
/// # Errors
///
/// Returns the [`Refusal`] that says why the registry cannot be read as this build reads it.
pub fn preview(registry: &Path) -> Result<Found, Refusal> {
    let connection = prepare(registry)?;
    let transaction = connection.unchecked_transaction().map_err(unreadable)?;
    let scan = scan_all(&transaction).map_err(unreadable)?;
    let plan = plan_withdrawal(&scan, Roots::None, Scope::Host).map_err(unreadable)?;
    Ok(found_of(&scan, &plan))
}

/// Flushes the file at `path` to disk. Windows flushes a file only through a handle that may write
/// it, so the file is opened for writing; nothing is created and nothing is cut.
fn sync_file(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

/// Writes the copy in a fresh private folder beside the registry, and makes its entry durable:
/// the copy, its folder and the folder that holds the folder are synced before the registry is
/// changed, and any failure stops the repair.
fn make_the_copy(registry: &Path, unix_seconds: u64) -> std::io::Result<(PathBuf, PathBuf)> {
    let mut name = registry.as_os_str().to_owned();
    name.push(format!(".grants-repair-{unix_seconds}"));
    let folder = PathBuf::from(name);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&folder)?;
    let copy = folder.join("registry");
    Registry::copy_as_one_state(registry, &copy)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))?;
    }
    sync_file(&copy)?;
    kr_flush::flush_directory(&folder, kr_flush::NameKind::File)?;
    if let Some(parent) = folder.parent() {
        kr_flush::flush_directory(parent, kr_flush::NameKind::Directory)?;
    }
    Ok((folder, copy))
}

/// Removes the rows that cannot be read and withdraws the live grants that trace to no root, in
/// one transaction, after a copy of the registry is made and made durable. `None` when there is
/// nothing to repair, and then nothing is written and no copy is made.
///
/// # Errors
///
/// Returns the [`Refusal`] that says why nothing was changed.
pub fn apply(registry: &Path, now_ms: u64, unix_seconds: u64) -> Result<Option<Repaired>, Refusal> {
    let connection = prepare(registry)?;
    {
        let transaction = connection.unchecked_transaction().map_err(unreadable)?;
        let scan = scan_all(&transaction).map_err(unreadable)?;
        let plan = plan_withdrawal(&scan, Roots::None, Scope::Host).map_err(unreadable)?;
        if found_of(&scan, &plan).is_empty() {
            return Ok(None);
        }
    }
    let (folder, copy) = make_the_copy(registry, unix_seconds).map_err(Refusal::CopyFailed)?;
    let transaction =
        rusqlite::Transaction::new_unchecked(&connection, rusqlite::TransactionBehavior::Immediate)
            .map_err(unreadable)?;
    let scan = scan_all(&transaction).map_err(unreadable)?;
    let plan = plan_withdrawal(&scan, Roots::None, Scope::Host).map_err(unreadable)?;
    let found = found_of(&scan, &plan);
    let now_ms = next_moment(&transaction, now_ms).map_err(unreadable)?;
    // The one debt of the change is written by the write half, whatever it did: a removed row owes a
    // fence under its names or, with none, for the whole host, and a withdrawn grant owes its own.
    // The repair has no running controller, so no close is outstanding at a worker.
    let written = GrantDirectory::write_withdrawal(
        &transaction,
        &scan,
        &plan,
        Roots::None,
        Disposal::Remove,
        now_ms,
        &BTreeSet::new(),
        COVERS,
    )
    .map_err(unreadable)?;
    transaction.commit().map_err(unreadable)?;
    Ok(Some(Repaired {
        folder,
        copy,
        found,
        fence_owed: written.debt.is_some(),
    }))
}

/// The one `environment` row of a registry: its identifier and generation.
fn identity(connection: &Connection) -> Result<(Vec<u8>, i64), Refusal> {
    let mut statement = connection
        .prepare("SELECT environment_id, generation FROM environment")
        .map_err(|_| Refusal::CopyUnreadable)?;
    let rows: Vec<(Vec<u8>, i64)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .and_then(Iterator::collect)
        .map_err(|_| Refusal::CopyUnreadable)?;
    match <[(Vec<u8>, i64); 1]>::try_from(rows) {
        Ok([one]) => Ok(one),
        Err(_) => Err(Refusal::CopyOfAnotherEnvironment),
    }
}

fn leftover(registry: &Path) -> PathBuf {
    let mut name = registry.as_os_str().to_owned();
    name.push(".restoring");
    PathBuf::from(name)
}

/// Checks that `copy` is a registry of this build's schema, made from this environment's registry,
/// before the host has run since, and returns the copy and the registry opened to read.
fn check_the_copy(
    registry: &Path,
    copy: &Path,
    environment_id: EnvironmentId,
) -> Result<(Connection, Connection), Refusal> {
    take_in_the_log(registry)?;
    let held = open(registry, false)?;
    let copied = open(copy, false).map_err(|_| Refusal::CopyUnreadable)?;
    let verdict: String = copied
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| Refusal::CopyUnreadable)?;
    if verdict != "ok" {
        return Err(Refusal::CopyUnreadable);
    }
    let versions: Vec<i64> = copied
        .prepare("SELECT version FROM schema_version")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get(0))
                .and_then(Iterator::collect)
        })
        .map_err(|_| Refusal::CopyUnreadable)?;
    if versions != [SCHEMA_VERSION] {
        return Err(Refusal::CopyUnreadable);
    }
    let (held_id, held_generation) = identity(&held)?;
    let (copied_id, copied_generation) = identity(&copied)?;
    let selected = environment_id.get().as_bytes().to_vec();
    if held_id != selected || copied_id != selected {
        return Err(Refusal::CopyOfAnotherEnvironment);
    }
    if held_generation != copied_generation {
        return Err(Refusal::HostRanSinceTheCopy);
    }
    Ok((held, copied))
}

fn live(connection: &Connection) -> Result<BTreeSet<GrantId>, Refusal> {
    let scan = scan_all(connection).map_err(unreadable)?;
    Ok(scan
        .readable
        .iter()
        .filter(|record| record.revoked_at_ms.is_none())
        .map(|record| record.grant.grant_id)
        .collect())
}

/// What putting `copy` back would make live again, and nothing changed.
///
/// # Errors
///
/// Returns the [`Refusal`] that says why the copy cannot be put back.
pub fn undo_preview(
    registry: &Path,
    copy: &Path,
    environment_id: EnvironmentId,
) -> Result<UndoPreview, Refusal> {
    let (held, copied) = check_the_copy(registry, copy, environment_id)?;
    let now = live(&held)?;
    Ok(UndoPreview {
        live_again: live(&copied)?.difference(&now).copied().collect(),
    })
}

/// Puts `copy` back as the registry: a fresh private file is written from the copy beside the
/// registry, made durable, and renamed over it. Any failure before the rename leaves the registry
/// in place.
///
/// # Errors
///
/// Returns the [`Refusal`] that says why nothing was changed.
pub fn undo_apply(
    registry: &Path,
    copy: &Path,
    environment_id: EnvironmentId,
) -> Result<(), Refusal> {
    let (held, copied) = check_the_copy(registry, copy, environment_id)?;
    let restoring = leftover(registry);
    if std::fs::symlink_metadata(&restoring).is_ok() {
        return Err(Refusal::LeftoverFile(restoring));
    }
    let named = restoring
        .to_str()
        .ok_or_else(|| Refusal::ReplaceFailed(std::io::Error::other("the name is not text")))?;
    copied
        .execute("VACUUM INTO ?1", [named])
        .map_err(|error| Refusal::ReplaceFailed(std::io::Error::other(error.to_string())))?;
    drop(held);
    drop(copied);
    let replaced = (|| -> std::io::Result<()> {
        sync_file(&restoring)?;
        for suffix in ["-wal", "-shm"] {
            let mut beside = registry.as_os_str().to_owned();
            beside.push(suffix);
            match std::fs::remove_file(PathBuf::from(beside)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        std::fs::rename(&restoring, registry)
    })();
    if let Err(error) = replaced {
        // Best effort: a file left here makes the next undo refuse, and says why.
        let _ = std::fs::remove_file(&restoring);
        return Err(Refusal::ReplaceFailed(error));
    }
    // The replacement is made. Whether the folder's entry for it is on disk is a separate fact, and
    // the person is told which of the two failed.
    registry
        .parent()
        .map_or(Ok(()), |folder| {
            kr_flush::flush_directory(folder, kr_flush::NameKind::File)
        })
        .map_err(Refusal::ReplacedButNotSynced)
}

#[cfg(test)]
mod tests {
    use super::*;

    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, DeviceId};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

    struct Fixture {
        temp: kr_ipc::testing::TempHost,
        path: PathBuf,
        /// Open while a case writes grants, and closed before an undo replaces the registry: a
        /// file that a connection holds open cannot be removed or renamed over on Windows.
        directory: Option<GrantDirectory>,
    }

    fn fixture() -> Fixture {
        let temp = kr_ipc::testing::TempHost::create();
        let path = temp.environment().registry_database();
        drop(Registry::open(&path, temp.environment_id()).expect("the registry"));
        drop(
            crate::service::net::devices::DeviceDirectory::open(&path).expect("the devices tables"),
        );
        let directory = GrantDirectory::open(&path).expect("the grants tables");
        let store = Fixture {
            temp,
            path,
            directory: Some(directory),
        };
        store.sql(NEIGHBOURS);
        store
    }

    /// Rows of the tables a repair leaves alone: a claim and a receipt, a paired device, a spent
    /// voice delegation and a host record.
    const NEIGHBOURS: &str = "
        INSERT INTO authority_receipts (actor_id, action_id, payload_digest, claimed_at_ms)
            VALUES ('owner', X'0a0a', X'0b0b', 11);
        INSERT INTO authority_receipts (actor_id, action_id, payload_digest, claimed_at_ms, result,
                                        recorded_at_ms, refusal_code, refusal_detail, withdrawn)
            VALUES ('owner', X'0c0c', X'0d0d', 12, X'0e0e', 13, 'a_code', 'a detail', X'0f0f');
        INSERT INTO network_devices (device_id, endpoint_id, device_key_revision, authorisation_key,
                                     device_name, platform, grant_id, grant, paired_at_ms)
            VALUES (X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', X'1111', 1, X'2222', 'a phone', 'ios',
                    X'3333', X'4444', 14);
        INSERT INTO voice_delegations (device_id, delegation_id, action_id, spent_at_ms)
            VALUES (X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', 'one', X'5555', 15);
        INSERT INTO host_authority (key, value) VALUES ('a_note', X'6666');";

    /// Every column of every row of `table` in the registry at `path`, as SQL text, in rowid order,
    /// leaving out the columns in `skip`.
    fn dump_at(path: &Path, table: &str, skip: &[&str]) -> Vec<String> {
        let connection = Connection::open(path).expect("opens");
        let columns: Vec<String> = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("prepares")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("queries")
            .map(|column| column.expect("a column"))
            .filter(|column| !skip.contains(&column.as_str()))
            .map(|column| format!("quote(\"{column}\")"))
            .collect();
        let mut statement = connection
            .prepare(&format!(
                "SELECT {} FROM \"{table}\" ORDER BY rowid",
                columns.join(" || '|' || ")
            ))
            .expect("prepares");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("queries")
            .map(|row| row.expect("a row"))
            .collect()
    }

    /// Every table of the registry at `path`, whole, by name.
    fn tables_at(path: &Path) -> std::collections::BTreeMap<String, Vec<String>> {
        let connection = Connection::open(path).expect("opens");
        let names: Vec<String> = connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .expect("prepares")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("queries")
            .map(|name| name.expect("a name"))
            .collect();
        names
            .into_iter()
            .map(|name| {
                let rows = dump_at(path, &name, &[]);
                (name, rows)
            })
            .collect()
    }

    fn id(byte: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([byte; 16]))
    }

    fn key(byte: u8) -> String {
        format!("X'{}'", format!("{byte:02x}").repeat(16))
    }

    fn grant_of(byte: u8, parent: Option<u8>, action: ActionRight) -> Grant {
        Grant {
            grant_id: id(byte),
            parent_grant_id: Nullable(parent.map(id)),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([0xe0; 16])),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [action].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::some(TimestampMs::new(1)),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    impl Fixture {
        fn issue(&self, byte: u8, parent: Option<u8>) -> GrantId {
            self.issue_with(byte, parent, ActionRight::SessionView, true)
        }

        /// A grant of the one right `action`, active or still a proposal.
        fn issue_with(
            &self,
            byte: u8,
            parent: Option<u8>,
            action: ActionRight,
            active: bool,
        ) -> GrantId {
            let grant = grant_of(byte, parent, action);
            self.directory
                .as_ref()
                .expect("the grants tables are open")
                .issue(
                    &crate::grants::GrantRecord {
                        grant,
                        session_id: None,
                        issued_at_ms: 1_000,
                        activated_at_ms: active.then_some(1_000),
                        revoked_at_ms: None,
                        revoked_by_parent: None,
                    },
                    || Ok(()),
                )
                .expect("written");
            id(byte)
        }

        fn sql(&self, statements: &str) {
            let connection = Connection::open(&self.path).expect("opens");
            connection
                .busy_timeout(Duration::from_secs(5))
                .expect("waits");
            connection.execute_batch(statements).expect("runs");
        }

        fn close(&mut self) {
            drop(self.directory.take());
        }

        /// Gives the row of grant `byte` a record and a parent column that name `parent`, as a
        /// hand edit can: the way to make a loop that the store itself would not write.
        fn reparent(&self, byte: u8, parent: u8) {
            let encoded =
                kr_cbor::to_canonical_vec(&grant_of(byte, Some(parent), ActionRight::SessionView))
                    .expect("the grant encodes");
            let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
            self.sql(&format!(
                "UPDATE grants SET grant = X'{hex}', parent_grant_id = {} WHERE grant_id = {};",
                key(parent),
                key(byte)
            ));
        }

        /// The moment grant `byte` was revoked at, none while it is live or when no row holds it.
        fn marked_at(&self, byte: u8) -> Option<i64> {
            Connection::open(&self.path)
                .expect("opens")
                .query_row(
                    &format!(
                        "SELECT revoked_at_ms FROM grants WHERE grant_id = {}",
                        key(byte)
                    ),
                    [],
                    |row| row.get(0),
                )
                .ok()
                .flatten()
        }

        /// Every column of every row of every table, as text, in a stable order.
        fn rows(&self) -> Vec<String> {
            tables_at(&self.path)
                .into_iter()
                .flat_map(|(name, rows)| rows.into_iter().map(move |row| format!("{name}|{row}")))
                .collect()
        }

        /// The state of the invitation that waits on the grant `key` names.
        fn invitation_state(&self, key: &str) -> Option<String> {
            Connection::open(&self.path)
                .expect("opens")
                .query_row(
                    &format!("SELECT state FROM session_invitations WHERE grant_id = {key}"),
                    [],
                    |row| row.get(0),
                )
                .ok()
        }

        fn count(&self, table: &str) -> i64 {
            Connection::open(&self.path)
                .expect("opens")
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("counts")
        }

        fn is_live(&self, key: &str) -> Option<bool> {
            Connection::open(&self.path)
                .expect("opens")
                .query_row(
                    &format!("SELECT revoked_at_ms IS NULL FROM grants WHERE grant_id = {key}"),
                    [],
                    |row| row.get(0),
                )
                .ok()
        }

        fn invitation(&self, grant: &str, byte: u8, state: &str) {
            self.sql(&format!(
                "INSERT INTO session_invitations (invitation_id, issuer_device_id, grant_id, \
                 recipient_device_id, preview, state, issued_at_ms, expires_at_ms) VALUES \
                 (X'{}', X'{}', {grant}, X'{}', X'00', '{state}', 1, 9999999999999);",
                format!("{byte:02x}").repeat(16),
                "f0".repeat(16),
                "e0".repeat(16),
            ));
        }
    }

    /// A store with one of each kind of fault, each with a readable child below it: a row whose
    /// record does not decode, a row deleted by hand, and a row with a malformed key.
    fn damaged() -> Fixture {
        let store = fixture();
        store.issue(0x41, None);
        store.issue(0x42, Some(0x41));
        store.issue(0x43, None);
        store.issue(0x44, Some(0x43));
        store.issue(0x45, None);
        store.issue(0x46, Some(0x45));
        store.sql(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};
             DELETE FROM grants WHERE grant_id = {};
             UPDATE grants SET grant_id = X'0102' WHERE grant_id = {};",
            key(0x41),
            key(0x43),
            key(0x45)
        ));
        store
    }

    #[test]
    fn the_repair_without_apply_changes_nothing_and_names_each_damaged_row_and_each_live_grant_it_would_withdraw()
     {
        let store = damaged();
        let before = store.rows();
        let found = preview(&store.path).expect("the preview");
        assert_eq!(store.rows(), before, "every table is as it was");
        let places: Vec<(u64, &str)> = found
            .damaged
            .iter()
            .map(|row| (row.place, row.class.phrase()))
            .collect();
        assert_eq!(
            places,
            [
                (1, "its record does not decode"),
                (4, "its key does not name the grant it holds"),
            ],
            "the rows by their places and classes: {found:?}"
        );
        assert_eq!(
            found.damaged[1].key, None,
            "a malformed key is not an identifier"
        );
        let mut withdraw = found.withdraw.clone();
        withdraw.sort();
        assert_eq!(
            withdraw,
            [id(0x42), id(0x44), id(0x46)],
            "each live grant below a lost row"
        );
    }

    #[test]
    fn the_repair_removes_the_damaged_rows_and_keeps_every_other_row_whole() {
        let store = damaged();
        // A sound grant with an open offer, and an open offer on a row the repair removes.
        store.issue(0x47, None);
        store.invitation(&key(0x47), 7, "open");
        store.invitation(&key(0x41), 4, "open");
        let before = tables_at(&store.path);
        let repaired = apply(&store.path, 5_000, 77)
            .expect("the repair")
            .expect("there was something to repair");
        assert_eq!(repaired.found.damaged.len(), 2);
        let after = tables_at(&store.path);
        // The copy holds the registry as it was, every table whole.
        assert_eq!(
            tables_at(&repaired.copy),
            before,
            "the copy holds the registry as it was"
        );
        // Every table the repair does not write is as it was, row for row.
        for (name, rows) in &before {
            if !["grants", "session_invitations", "fence_debt"].contains(&name.as_str()) {
                assert_eq!(after.get(name), Some(rows), "the table {name} is as it was");
            }
        }
        // The grants: the two damaged rows are removed; each other row keeps every column but the
        // two marks, and the withdrawn ones differ in those alone.
        let marks = ["revoked_at_ms", "revoked_by_parent"];
        let gone = [key(0x41), key(0x45)];
        let kept_before: Vec<String> = dump_at(&repaired.copy, "grants", &marks)
            .into_iter()
            .filter(|row| !gone.iter().any(|name| row.to_lowercase().starts_with(name)))
            .collect();
        assert_eq!(kept_before.len(), 4, "the rows that stay");
        assert_eq!(
            dump_at(&store.path, "grants", &marks),
            kept_before,
            "every kept row holds every column it held, but its marks"
        );
        for withdrawn in [0x42, 0x44, 0x46] {
            assert_eq!(
                store.is_live(&key(withdrawn)),
                Some(false),
                "{withdrawn:x} is revoked"
            );
        }
        assert_eq!(
            store.is_live(&key(0x47)),
            Some(true),
            "a sound grant is untouched"
        );
        // The offers: the one on a removed row reads cancelled and the sound grant's stays open;
        // every other column of every offer is as it was.
        assert_eq!(
            dump_at(&store.path, "session_invitations", &["state"]),
            dump_at(&repaired.copy, "session_invitations", &["state"]),
            "every offer keeps every column but its state"
        );
        assert_eq!(
            store.invitation_state(&key(0x41)).as_deref(),
            Some("cancelled")
        );
        assert_eq!(store.invitation_state(&key(0x47)).as_deref(), Some("open"));
        // The debts: the ones there were stay, and the repair adds one.
        let debts_before = &before["fence_debt"];
        assert_eq!(after["fence_debt"].len(), debts_before.len() + 1);
        assert_eq!(
            &after["fence_debt"][..debts_before.len()],
            &debts_before[..]
        );
    }

    #[test]
    fn the_repair_writes_exactly_one_debt_with_and_without_a_live_grant_to_withdraw() {
        let with = damaged();
        let repaired = apply(&with.path, 5_000, 77).expect("ok").expect("repaired");
        assert!(repaired.fence_owed);
        assert_eq!(with.count("fence_debt"), 1);
        let without = fixture();
        without.issue(0x41, None);
        without.sql(
            "INSERT INTO grants (grant_id, recipient_device_id, grant, issued_at_ms)
             VALUES (X'00', X'11111111111111111111111111111111', X'00', 1);",
        );
        assert_eq!(without.count("grants"), 2);
        apply(&without.path, 5_000, 78)
            .expect("ok")
            .expect("repaired");
        assert_eq!(
            without.count("fence_debt"),
            1,
            "one debt, with no live grant below the row"
        );
        assert_eq!(
            without.is_live(&key(0x41)),
            Some(true),
            "a sound grant is untouched"
        );
    }

    #[test]
    fn the_repair_keeps_the_invitation_of_a_valid_grant_beside_an_alias_and_leaves_no_alias_live() {
        let store = fixture();
        store.issue(0x51, None);
        store.issue(0x61, None);
        // The alias: the row of grant 0x61 filed under key 0x62, which no other row holds.
        store.sql(&format!(
            "UPDATE grants SET grant_id = {} WHERE grant_id = {};",
            key(0x62),
            key(0x61)
        ));
        // A second alias: a row filed under key 0x72 whose record is the readable grant 0x51's.
        store.issue(0x71, None);
        store.sql(&format!(
            "UPDATE grants SET grant = (SELECT grant FROM grants WHERE grant_id = {}), grant_id = {}
              WHERE grant_id = {};",
            key(0x51),
            key(0x72),
            key(0x71)
        ));
        store.invitation(&key(0x51), 1, "open");
        store.invitation(&key(0x62), 2, "open");
        store.invitation(&key(0x72), 3, "open");
        apply(&store.path, 5_000, 79)
            .expect("ok")
            .expect("repaired");
        assert_eq!(store.is_live(&key(0x62)), None, "the alias row is removed");
        assert_eq!(
            store.is_live(&key(0x72)),
            None,
            "the second alias row is removed"
        );
        assert_eq!(
            store.is_live(&key(0x61)),
            None,
            "no row holds the alias's grant"
        );
        assert_eq!(
            store.is_live(&key(0x51)),
            Some(true),
            "the valid grant stays live"
        );
        assert_eq!(
            store.invitation_state(&key(0x51)).as_deref(),
            Some("open"),
            "the valid grant's offer stays open"
        );
        assert_eq!(
            store.invitation_state(&key(0x62)).as_deref(),
            Some("cancelled"),
            "the alias's own offer is cancelled"
        );
        assert_eq!(
            store.invitation_state(&key(0x72)).as_deref(),
            Some("cancelled"),
            "the offer of an alias whose record names a readable grant is cancelled, and that \
             grant's own offer stays open"
        );
    }

    #[test]
    fn the_repair_of_a_sound_store_says_so_and_changes_nothing() {
        let store = fixture();
        store.issue(0x41, None);
        let before = store.rows();
        assert!(preview(&store.path).expect("the preview").is_empty());
        assert!(apply(&store.path, 5_000, 80).expect("ok").is_none());
        assert_eq!(store.rows(), before);
        let mut folder = store.path.as_os_str().to_owned();
        folder.push(".grants-repair-80");
        assert!(
            !PathBuf::from(folder).exists(),
            "no copy is made for nothing"
        );
    }

    #[test]
    fn the_repair_refuses_a_registry_of_another_schema_and_a_grants_table_of_an_older_shape() {
        for version in [14_i64, 16] {
            let store = damaged();
            store.sql(&format!("UPDATE schema_version SET version = {version};"));
            let before = store.rows();
            assert!(
                matches!(preview(&store.path), Err(Refusal::OtherBuild { version: found }) if found == version)
            );
            assert!(matches!(
                apply(&store.path, 1, 81),
                Err(Refusal::OtherBuild { .. })
            ));
            assert_eq!(store.rows(), before);
        }
        let none = damaged();
        none.sql("DELETE FROM schema_version;");
        assert!(matches!(preview(&none.path), Err(Refusal::NoVersion)));
        let older = damaged();
        older.sql("ALTER TABLE grants DROP COLUMN expired_at_ms;");
        Registry::take_in_its_log(&older.path).expect("the log is taken in first");
        let bytes = std::fs::read(&older.path).expect("reads");
        assert!(matches!(preview(&older.path), Err(Refusal::WrongShape)));
        assert!(matches!(
            apply(&older.path, 1, 82),
            Err(Refusal::WrongShape)
        ));
        assert_eq!(
            std::fs::read(&older.path).expect("reads"),
            bytes,
            "the file is byte equal"
        );
    }

    #[test]
    fn the_repair_makes_no_change_after_a_failed_copy_and_the_copy_has_private_modes() {
        let store = damaged();
        let mut folder = store.path.as_os_str().to_owned();
        folder.push(".grants-repair-83");
        std::fs::create_dir(PathBuf::from(&folder)).expect("a folder stands where the copy goes");
        let before = store.rows();
        assert!(matches!(
            apply(&store.path, 1, 83),
            Err(Refusal::CopyFailed(_))
        ));
        assert_eq!(
            store.rows(),
            before,
            "nothing is changed after a failed copy"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let repaired = apply(&store.path, 1, 84).expect("ok").expect("repaired");
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("exists")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&repaired.folder), 0o700);
            assert_eq!(mode(&repaired.copy), 0o600);
        }
    }

    #[test]
    fn the_undo_puts_the_registry_back_and_refuses_after_the_host_has_run() {
        let mut store = damaged();
        let before = store.rows();
        let repaired = apply(&store.path, 5_000, 85)
            .expect("ok")
            .expect("repaired");
        store.close();
        let environment_id = store.temp.environment_id();
        let preview = undo_preview(&store.path, &repaired.copy, environment_id).expect("preview");
        let mut live_again = preview.live_again.clone();
        live_again.sort();
        assert_eq!(live_again, [id(0x42), id(0x44), id(0x46)]);
        // A leftover from an earlier undo stands in the way.
        let leftover = leftover(&store.path);
        std::fs::write(&leftover, b"x").expect("a file");
        assert!(matches!(
            undo_apply(&store.path, &repaired.copy, environment_id),
            Err(Refusal::LeftoverFile(_))
        ));
        std::fs::remove_file(&leftover).expect("removed");
        undo_apply(&store.path, &repaired.copy, environment_id).expect("the undo");
        assert_eq!(store.rows(), before, "the registry is what the copy held");
        // Another environment's copy, at the same generation.
        store.sql(&format!(
            "UPDATE environment SET environment_id = X'{}';",
            "ab".repeat(16)
        ));
        assert!(matches!(
            undo_apply(&store.path, &repaired.copy, environment_id),
            Err(Refusal::CopyOfAnotherEnvironment)
        ));
        store.sql(&format!(
            "UPDATE environment SET environment_id = X'{}', generation = generation + 1;",
            environment_id
                .get()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        assert!(matches!(
            undo_apply(&store.path, &repaired.copy, environment_id),
            Err(Refusal::HostRanSinceTheCopy)
        ));
    }

    /// A connection that reads while the registry's log holds frames keeps the log from being taken
    /// in, so the undo says so and leaves the registry as it was.
    #[test]
    fn the_undo_refuses_when_the_registrys_log_cannot_be_taken_in() {
        let store = damaged();
        let repaired = apply(&store.path, 5_000, 86)
            .expect("ok")
            .expect("repaired");
        let environment_id = store.temp.environment_id();
        let writer = Connection::open(&store.path).expect("a writer");
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .expect("write-ahead logging");
        writer
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("no checkpoint");
        writer
            .execute_batch(
                "UPDATE environment SET generation = generation + 1;
             UPDATE environment SET generation = generation - 1;",
            )
            .expect("a write the log holds");
        let reader = Connection::open(&store.path).expect("a reader");
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM grants;")
            .expect("a read that holds the log");
        let before = store.rows();

        let refused = undo_apply(&store.path, &repaired.copy, environment_id);
        assert!(
            matches!(refused, Err(Refusal::LogBusy)),
            "the log is busy: {refused:?}"
        );
        let previewed = undo_preview(&store.path, &repaired.copy, environment_id);
        assert!(
            matches!(previewed, Err(Refusal::LogBusy)),
            "the preview says so too: {previewed:?}"
        );
        drop(reader);
        drop(writer);
        assert_eq!(store.rows(), before, "the registry is as it was");
        assert!(
            std::fs::symlink_metadata(leftover(&store.path)).is_err(),
            "no replacement file is left"
        );
    }

    /// A registry that cannot be replaced is left in place and usable: the refusal names the
    /// failure and the registry still opens and reads its rows.
    #[cfg(unix)]
    #[test]
    fn the_undo_leaves_the_registry_usable_when_the_replacement_cannot_be_made() {
        use std::os::unix::fs::PermissionsExt as _;

        let mut store = damaged();
        let repaired = apply(&store.path, 5_000, 87)
            .expect("ok")
            .expect("repaired");
        store.close();
        let environment_id = store.temp.environment_id();
        let after_the_repair = store.rows();
        let folder = store.path.parent().expect("a folder").to_owned();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500))
            .expect("the folder cannot be written to");
        let refused = undo_apply(&store.path, &repaired.copy, environment_id);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700))
            .expect("the folder can be written to again");
        assert!(
            matches!(refused, Err(Refusal::ReplaceFailed(_))),
            "the replacement fails: {refused:?}"
        );
        assert_eq!(
            store.rows(),
            after_the_repair,
            "the registry opens and reads the rows it held"
        );
        assert!(
            std::fs::symlink_metadata(leftover(&store.path)).is_err(),
            "no replacement file is left"
        );
        undo_apply(&store.path, &repaired.copy, environment_id)
            .expect("the undo goes on once the folder can be written to");
    }

    /// A folder whose flush fails after the replacement was renamed in: the undo says the registry
    /// is back to what the copy held and that the folder was not synced, where the refusal for a
    /// registry that was not replaced would be untrue. The flush is the platform's own, through
    /// the one call that the product's other stores use, so the case runs on every platform.
    #[test]
    fn the_undo_says_so_when_the_folder_cannot_be_synced_after_the_replacement() {
        let mut store = damaged();
        let before = store.rows();
        let repaired = apply(&store.path, 5_000, 88)
            .expect("ok")
            .expect("repaired");
        let environment_id = store.temp.environment_id();
        store.close();
        let folder = store.path.parent().expect("a folder").to_owned();
        let refused = kr_flush::testing::refuse_flushes_of(folder);
        let undone = undo_apply(&store.path, &repaired.copy, environment_id);
        drop(refused);
        assert!(
            matches!(undone, Err(Refusal::ReplacedButNotSynced(_))),
            "the replacement is made and the folder is not synced: {undone:?}"
        );
        assert_eq!(store.rows(), before, "the registry is what the copy held");
    }

    /// The copy's own folder and the folder that holds it are flushed through the platform's own
    /// call before the registry is changed: a flush that fails stops the repair, on every platform.
    #[test]
    fn the_repair_changes_nothing_when_a_folder_of_the_copy_cannot_be_synced() {
        for (seconds, which) in [
            (90_u64, "the copy's own folder"),
            (91, "the folder that holds it"),
        ] {
            let store = damaged();
            let before = store.rows();
            let refused = if seconds == 90 {
                let mut name = store.path.as_os_str().to_owned();
                name.push(format!(".grants-repair-{seconds}"));
                PathBuf::from(name)
            } else {
                store.path.parent().expect("a folder").to_owned()
            };
            let guard = kr_flush::testing::refuse_flushes_of(refused);
            let result = apply(&store.path, 5_000, seconds);
            drop(guard);
            assert!(
                matches!(result, Err(Refusal::CopyFailed(_))),
                "{which}: {result:?}"
            );
            assert_eq!(store.rows(), before, "{which}: nothing is changed");
        }
    }

    /// Only the checkpoint's refusal says the registry is in use: a registry that is not there is
    /// unreadable.
    #[test]
    fn a_registry_that_cannot_be_looked_at_is_not_said_to_be_in_use() {
        let temp = kr_ipc::testing::TempHost::create();
        let missing = temp.environment().registry_database();
        assert!(!missing.exists(), "nothing stands at the path");
        let previewed = preview(&missing);
        assert!(
            matches!(previewed, Err(Refusal::RegistryUnreadable)),
            "{previewed:?}"
        );
        let applied = apply(&missing, 1, 92);
        assert!(
            matches!(applied, Err(Refusal::RegistryUnreadable)),
            "{applied:?}"
        );
        let undone = undo_preview(
            &missing,
            &missing.with_extension("copy"),
            temp.environment_id(),
        );
        assert!(
            matches!(undone, Err(Refusal::RegistryUnreadable)),
            "{undone:?}"
        );
    }

    /// A revoked row below a damaged one, with a live grant below it; a live top that no row places,
    /// with a revoked middle row and a live grant below that; a loop of three live rows with a live
    /// tail below one of them. The preview names each live grant once, and the repair withdraws
    /// each once, leaving the revoked rows' own moments.
    #[test]
    fn the_repair_withdraws_what_hangs_below_through_a_revoked_middle_row_and_a_cycle_with_a_tail()
    {
        let store = fixture();
        // A damaged row, a revoked row below it, a live grant below that.
        store.issue(0x41, None);
        store.issue(0x42, Some(0x41));
        store.issue(0x43, Some(0x42));
        // A live top whose parent row is gone, a revoked middle row, a live grant below it.
        store.issue(0x60, None);
        store.issue(0x61, Some(0x60));
        store.issue(0x62, Some(0x61));
        store.issue(0x63, Some(0x62));
        // A loop of three, and a tail below one of them.
        store.issue(0x51, None);
        store.issue(0x52, Some(0x51));
        store.issue(0x53, Some(0x52));
        store.issue(0x54, Some(0x52));
        store.reparent(0x51, 0x53);
        store.sql(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};
             DELETE FROM grants WHERE grant_id = {};
             UPDATE grants SET revoked_at_ms = 9 WHERE grant_id IN ({}, {});",
            key(0x41),
            key(0x60),
            key(0x42),
            key(0x62)
        ));
        let expected = [0x43, 0x51, 0x52, 0x53, 0x54, 0x61, 0x63].map(id);
        let found = preview(&store.path).expect("the preview");
        let mut previewed = found.withdraw.clone();
        previewed.sort();
        assert_eq!(previewed, expected, "each live grant once: {found:?}");
        assert_eq!(found.damaged.len(), 1, "the one damaged row");
        let repaired = apply(&store.path, 5_000, 95)
            .expect("ok")
            .expect("repaired");
        let mut withdrawn = repaired.found.withdraw.clone();
        withdrawn.sort();
        assert_eq!(withdrawn, expected, "the repair withdraws each once");
        for byte in [0x43, 0x51, 0x52, 0x53, 0x54, 0x61, 0x63] {
            assert_eq!(
                store.is_live(&key(byte)),
                Some(false),
                "{byte:x} is revoked"
            );
        }
        for byte in [0x42, 0x62] {
            assert_eq!(
                store.marked_at(byte),
                Some(9),
                "{byte:x}, revoked already, keeps its own moment"
            );
        }
        assert_eq!(
            store.is_live(&key(0x41)),
            None,
            "the damaged row is removed"
        );
        assert_eq!(store.count("fence_debt"), 1, "one debt for the change");
    }

    /// A repair that withdraws a grant owes one fence, though the ordinary withdrawal owes none for
    /// a proposal nobody redeemed or for a voice grant, and no damaged row is there to owe one.
    #[test]
    fn the_repair_owes_one_fence_for_an_unplaced_proposal_or_voice_grant_with_no_damaged_row() {
        for (name, action, active) in [
            ("a proposal", ActionRight::SessionView, false),
            ("a voice grant", ActionRight::VoiceUse, true),
        ] {
            let store = fixture();
            store.issue(0x41, None);
            store.issue_with(0x42, Some(0x41), action, active);
            store.sql(&format!(
                "DELETE FROM grants WHERE grant_id = {};",
                key(0x41)
            ));
            let found = preview(&store.path).expect("the preview");
            assert!(found.damaged.is_empty(), "{name}: no row is damaged");
            assert_eq!(found.withdraw, [id(0x42)], "{name}: it is unplaced");
            let repaired = apply(&store.path, 5_000, 93)
                .expect("ok")
                .expect("repaired");
            assert_eq!(
                store.is_live(&key(0x42)),
                Some(false),
                "{name} is withdrawn"
            );
            assert!(
                repaired.fence_owed,
                "{name}: the repair says a fence is owed"
            );
            assert_eq!(store.count("fence_debt"), 1, "{name}: exactly one debt");
        }
    }

    /// A copy of another schema is refused by both modes of the undo, and the registry is as it
    /// was.
    #[test]
    fn the_undo_refuses_a_copy_of_another_schema() {
        let store = damaged();
        let repaired = apply(&store.path, 5_000, 94)
            .expect("ok")
            .expect("repaired");
        Connection::open(&repaired.copy)
            .expect("the copy opens")
            .execute_batch("UPDATE schema_version SET version = version + 1;")
            .expect("the copy takes another schema");
        let environment_id = store.temp.environment_id();
        let before = store.rows();
        let previewed = undo_preview(&store.path, &repaired.copy, environment_id);
        assert!(
            matches!(previewed, Err(Refusal::CopyUnreadable)),
            "the preview: {previewed:?}"
        );
        let undone = undo_apply(&store.path, &repaired.copy, environment_id);
        assert!(
            matches!(undone, Err(Refusal::CopyUnreadable)),
            "the undo: {undone:?}"
        );
        assert_eq!(store.rows(), before, "the registry is as it was");
        assert!(
            std::fs::symlink_metadata(leftover(&store.path)).is_err(),
            "no replacement file is left"
        );
    }
}
