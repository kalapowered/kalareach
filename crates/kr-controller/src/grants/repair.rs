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

use crate::error::DamageClass;
use crate::grants::store::{
    Disposal, GrantDirectory, Plan, Roots, Scan, Scope, next_moment, plan_withdrawal, scan_all,
};
use crate::registry::{RecordedIn, Registry, SCHEMA_VERSION, recorded_version};

/// What the debt a repair writes says it covers.
const COVERS: &str = "the repair of damaged grants rows";

/// Why a repair or an undo changed nothing. Every one of these leaves the registry as it was.
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
    Registry::take_in_its_log(path).map_err(|_| Refusal::LogBusy)?;
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

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Writes the copy in a fresh private folder beside the registry, and makes its entry durable:
/// the copy, its folder and the folder that holds the folder are synced before the registry is
/// changed, and any failure stops the repair.
fn make_the_copy(registry: &Path, unix_seconds: u64) -> std::io::Result<(PathBuf, PathBuf)> {
    let mut name = registry.as_os_str().to_owned();
    name.push(format!(".grants-repair-{unix_seconds}"));
    let folder = PathBuf::from(name);
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
    std::fs::File::open(&copy)?.sync_all()?;
    sync_directory(&folder)?;
    if let Some(parent) = folder.parent() {
        sync_directory(parent)?;
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
    Registry::take_in_its_log(registry).map_err(|_| Refusal::LogBusy)?;
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
        std::fs::File::open(&restoring)?.sync_all()?;
        for suffix in ["-wal", "-shm"] {
            let mut beside = registry.as_os_str().to_owned();
            beside.push(suffix);
            match std::fs::remove_file(PathBuf::from(beside)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        std::fs::rename(&restoring, registry)?;
        registry.parent().map_or(Ok(()), sync_directory)
    })();
    if let Err(error) = replaced {
        // Best effort: a file left here makes the next undo refuse, and says why.
        let _ = std::fs::remove_file(&restoring);
        return Err(Refusal::ReplaceFailed(error));
    }
    Ok(())
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
        directory: GrantDirectory,
    }

    fn fixture() -> Fixture {
        let temp = kr_ipc::testing::TempHost::create();
        let path = temp.environment().registry_database();
        drop(Registry::open(&path, temp.environment_id()).expect("the registry"));
        let directory = GrantDirectory::open(&path).expect("the grants tables");
        Fixture {
            temp,
            path,
            directory,
        }
    }

    fn id(byte: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([byte; 16]))
    }

    fn key(byte: u8) -> String {
        format!("X'{}'", format!("{byte:02x}").repeat(16))
    }

    impl Fixture {
        fn issue(&self, byte: u8, parent: Option<u8>) -> GrantId {
            let grant = Grant {
                grant_id: id(byte),
                parent_grant_id: Nullable(parent.map(id)),
                issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([0xe0; 16])),
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: [ActionRight::SessionView].into_iter().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::some(TimestampMs::new(1)),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            };
            self.directory
                .issue(
                    &crate::grants::GrantRecord {
                        grant,
                        session_id: None,
                        issued_at_ms: 1_000,
                        activated_at_ms: Some(1_000),
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

        /// Every row of the tables the repair touches, as text, in a stable order.
        fn rows(&self) -> Vec<String> {
            let connection = Connection::open(&self.path).expect("opens");
            let mut out = Vec::new();
            for query in [
                "SELECT hex(grant_id) || '|' || hex(grant) || '|' || ifnull(revoked_at_ms, 'null') \
                 || '|' || ifnull(hex(revoked_by_parent), 'null') FROM grants ORDER BY rowid",
                "SELECT hex(invitation_id) || '|' || hex(grant_id) || '|' || state \
                 FROM session_invitations ORDER BY rowid",
                "SELECT hex(debt_id) || '|' || covers FROM fence_debt ORDER BY rowid",
            ] {
                let mut statement = connection.prepare(query).expect("prepares");
                out.extend(
                    statement
                        .query_map([], |row| row.get::<_, String>(0))
                        .expect("queries")
                        .map(|row| row.expect("a row")),
                );
            }
            out
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

    /// A store with one of each kind of fault: a row whose record does not decode, a row deleted
    /// by hand that leaves a readable child, a malformed key with a readable child, and a cycle.
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
        let before = store.rows();
        let repaired = apply(&store.path, 5_000, 77)
            .expect("the repair")
            .expect("there was something to repair");
        assert_eq!(repaired.found.damaged.len(), 2);
        assert_eq!(store.count("grants"), 3, "the two damaged rows are removed");
        for withdrawn in [0x42, 0x44, 0x46] {
            assert_eq!(
                store.is_live(&key(withdrawn)),
                Some(false),
                "{withdrawn:x} is revoked"
            );
        }
        // The copy holds the registry as it was.
        let copied = Connection::open(&repaired.copy).expect("the copy opens");
        let rows: i64 = copied
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
            .expect("counts");
        assert_eq!(rows, 5, "the copy holds the rows the repair removed");
        assert_ne!(store.rows(), before);
    }

    #[test]
    fn the_repair_writes_exactly_one_debt_with_and_without_a_live_grant_to_withdraw() {
        let with = damaged();
        let repaired = apply(&with.path, 5_000, 77).expect("ok").expect("repaired");
        assert!(repaired.fence_owed);
        assert_eq!(with.count("fence_debt"), 1);
        let without = fixture();
        without.issue(0x41, None);
        without.sql(&format!(
            "INSERT INTO grants (grant_id, recipient_device_id, grant, issued_at_ms)
             VALUES (X'00', X'11111111111111111111111111111111', X'00', 1);"
        ));
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
        store.invitation(&key(0x51), 1, "open");
        store.invitation(&key(0x62), 2, "open");
        apply(&store.path, 5_000, 79)
            .expect("ok")
            .expect("repaired");
        assert_eq!(store.is_live(&key(0x62)), None, "the alias row is removed");
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
        let rows = store.rows();
        let state_of = |grant: u8| {
            rows.iter()
                .find(|row| {
                    row.contains(&format!(
                        "|{}|",
                        format!("{grant:02x}").repeat(16).to_uppercase()
                    )) && !row.contains("|DEBT|")
                })
                .and_then(|row| row.rsplit('|').next())
                .map(str::to_owned)
        };
        assert_eq!(
            state_of(0x51).as_deref(),
            Some("open"),
            "the valid grant's offer stays open"
        );
        assert_eq!(
            state_of(0x62).as_deref(),
            Some("cancelled"),
            "the alias's own offer is cancelled"
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
        let store = damaged();
        let before = store.rows();
        let repaired = apply(&store.path, 5_000, 85)
            .expect("ok")
            .expect("repaired");
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
}
