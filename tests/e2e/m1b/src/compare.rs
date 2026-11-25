//! The compare of a run's tree with its record, and the rows that say which changes are allowed.
//!
//! A restarted daemon reads the tree an agent has had the run of. Every entry below the host's two
//! roots is recorded when the agent starts ([`crate::tree::Record`]); at each kill the tree is
//! compared with that record, and before the attempt to start the daemon again with the record made
//! at the kill. A change is allowed only where a row covers the entry:
//!
//! - **The live daemon's own files** ([`Daemon`]): the daemon writes them while it serves or when it
//!   starts, so an agent's write to one of them between the record and a kill cannot be told from
//!   the daemon's. A row lists the writer, when the file changes ([`When`]), which operations are
//!   permitted ([`Operations`]) and what the entry is. Its bytes are not compared; its kind, owner
//!   and permission bits always are, and a replacement of an entry whose writer keeps its object is
//!   refused. Between the kill and the attempt no daemon runs, so a daemon's file may not change at
//!   all.
//! - **Every other entry** is refused when it changes: a changed file, a replaced object, an added
//!   or a gone entry, another kind, owner or permission bits.
//!
//! The rows hold what a survey run of the stand-in found changed
//! (`staged_a::survey_the_files_a_restart_of_the_control_daemon_changes`) and what the writer's code
//! names; an entry that the real run's daemon writes and no row names is refused, and joins a row
//! only with the writer's cite.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kr_ipc::paths::EnvironmentPaths;

use crate::tree::{Change, Kind, Record};

/// Where the host's directories are, relative to the run's directory.
#[derive(Clone, Debug)]
pub struct Layout {
    /// The runtime directory of the environment (`--runtime-dir` and the environment's name).
    pub runtime_dir: PathBuf,
    /// The state directory of the environment (`--state-dir`, `environments` and its name).
    pub state_dir: PathBuf,
}

impl Layout {
    /// The layout of `environment`, a host over the run's directory `run_root`.
    ///
    /// # Panics
    ///
    /// Panics when a directory of the environment is not below the run's directory.
    #[must_use]
    pub fn of(run_root: &Path, environment: &EnvironmentPaths) -> Self {
        let below = |path: &Path| {
            path.strip_prefix(run_root)
                .expect("the environment lies below the run's directory")
                .to_path_buf()
        };
        Self {
            runtime_dir: below(environment.runtime_dir()),
            state_dir: below(environment.state_dir()),
        }
    }
}

/// The two moments a tree is compared at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interval {
    /// At a kill, the record made when the agent started against the tree: the daemon ran until the
    /// kill. `restarted` is whether a daemon has started since that record was made.
    AtTheKill {
        /// Whether a daemon has started since the record.
        restarted: bool,
    },
    /// Before the attempt, the record made at the kill against the tree: no daemon runs.
    BeforeTheAttempt,
}

/// When a live daemon changes an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// While it serves, and at a start: a change is permitted at any kill.
    Serving,
    /// At a start only: a change is permitted at a kill that follows a start since the record was
    /// made, and at no other.
    Start,
}

/// The operations a row permits on its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operations {
    /// A change of the bytes of an entry that keeps its object.
    pub content: bool,
    /// Another object in the entry's place.
    pub replace: bool,
    /// An entry the record does not hold.
    pub create: bool,
    /// An entry the record holds, gone.
    pub remove: bool,
}

impl Operations {
    /// The writer changes the file in place and keeps its object.
    pub const CONTENT: Self = Self {
        content: true,
        replace: false,
        create: false,
        remove: false,
    };
    /// The writer writes the whole file under another name and renames it over the name.
    pub const REPLACE: Self = Self {
        content: true,
        replace: true,
        create: false,
        remove: false,
    };
    /// The writer makes the entry, changes it, and removes it again.
    pub const ALL: Self = Self {
        content: true,
        replace: true,
        create: true,
        remove: true,
    };
}

/// Which names a row covers, beside the file the row is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Names {
    /// The file itself.
    Itself,
    /// The names a SQLite database makes beside itself: `-wal`, `-shm` and `-journal`.
    Sidecars,
    /// The names an owner-only file writer makes beside the file it writes, `.<uuid>.tmp` in the
    /// same directory, and removes or renames.
    Staging,
}

/// The names SQLite makes beside a database.
const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The length of a hyphenated UUID.
const UUID_LEN: usize = 36;

/// A row of the live daemon's class: one entry the daemon writes, and what it may do to it.
#[derive(Clone, Debug)]
pub struct Daemon {
    /// What the entry is, as a refusal says it.
    pub name: &'static str,
    /// The code that writes it.
    pub cite: &'static str,
    /// When the daemon changes it.
    pub when: When,
    /// What the entry is.
    pub kind: Kind,
    /// What may be done to it.
    pub operations: Operations,
    /// The file the row is about, relative to the run's directory.
    path: PathBuf,
    /// The names of the row.
    names: Names,
}

impl Daemon {
    /// Whether the row covers `path`.
    fn covers(&self, path: &Path) -> bool {
        if self.names == Names::Itself {
            return path == self.path;
        }
        if path.parent() != self.path.parent() {
            return false;
        }
        let (Some(name), Some(file)) = (
            path.file_name().and_then(OsStr::to_str),
            self.path.file_name().and_then(OsStr::to_str),
        ) else {
            return false;
        };
        match self.names {
            Names::Itself => false,
            Names::Sidecars => SIDECARS
                .iter()
                .any(|sidecar| name.strip_prefix(file) == Some(sidecar)),
            Names::Staging => {
                name.len() == UUID_LEN + ".tmp".len() + 1
                    && name.starts_with('.')
                    && name.ends_with(".tmp")
            }
        }
    }

    /// Why the row refuses what happened to `path` between the two records, or `None` where it
    /// permits it. `changes` are the changes of that one entry, `uid` the account's.
    fn refuses(&self, changes: &[&Change], interval: Interval, uid: u32) -> Option<String> {
        match interval {
            Interval::BeforeTheAttempt => {
                return Some(format!(
                    "{} is written by the live daemon and no daemon runs between the kill and the \
                     attempt",
                    self.name
                ));
            }
            Interval::AtTheKill { restarted: false } if self.when == When::Start => {
                return Some(format!(
                    "{} changes only when a daemon starts, and none has started since the record \
                     was made",
                    self.name
                ));
            }
            Interval::AtTheKill { .. } => {}
        }
        let permits = |allowed: bool, what: &str| {
            (!allowed).then(|| format!("{} permits no {what}", self.name))
        };
        let mut replaced = false;
        for change in changes {
            let refused = match change {
                Change::Retyped { .. }
                | Change::Target { .. }
                | Change::Owner { .. }
                | Change::Mode { .. } => Some(format!(
                    "{} keeps its kind, its owner and its permission bits",
                    self.name
                )),
                Change::Added { now, .. } => permits(self.operations.create, "creation")
                    .or_else(|| {
                        (now.kind != self.kind).then(|| {
                            format!(
                                "{} holds {}, and this entry is {}",
                                self.name, self.kind, now.kind
                            )
                        })
                    })
                    .or_else(|| {
                        (now.owner != uid || now.mode & 0o077 != 0).then(|| {
                            format!(
                                "a new entry of {} is owned by the account and owner-only; this \
                                 one has owner {} and mode {:04o}",
                                self.name, now.owner, now.mode
                            )
                        })
                    }),
                Change::Gone { .. } => permits(self.operations.remove, "removal"),
                Change::Replaced { .. } => {
                    replaced = true;
                    permits(self.operations.replace, "replacement")
                }
                Change::Bytes { .. } => {
                    permits(self.operations.content || replaced, "change of content")
                }
            };
            if refused.is_some() {
                return refused;
            }
        }
        None
    }
}

/// The rows of the live daemon's class, for the host laid out as `layout`.
///
/// The entries come from what the survey run found changed, and the writer of each is cited. The
/// daemon's databases keep their object when they change; the daemon's sockets and the files an
/// owner-only writer replaces are replaced at a start.
#[must_use]
pub fn daemon_rows(layout: &Layout) -> Vec<Daemon> {
    let state = |name: &str| layout.state_dir.join(name);
    let runtime = |name: &str| layout.runtime_dir.join(name);
    let mut rows = Vec::new();
    // A database the daemon opens: the file keeps its object and changes in place, and SQLite makes
    // and removes its sidecars (SQLite's behaviour, not checked here).
    let mut database = |name: &'static str, cite: &'static str, when: When| {
        let path = state(name);
        rows.push(Daemon {
            name,
            cite,
            when,
            kind: Kind::File,
            operations: Operations::CONTENT,
            path: path.clone(),
            names: Names::Itself,
        });
        rows.push(Daemon {
            name,
            cite,
            when,
            kind: Kind::File,
            operations: Operations::ALL,
            path,
            names: Names::Sidecars,
        });
    };
    // The registry and the attention store are written while the daemon serves.
    database(
        "registry.sqlite",
        "crates/kr-ipc/src/paths.rs:420-424, opened at the start (service/start.rs)",
        When::Serving,
    );
    database(
        "attention.sqlite3",
        "crates/kr-controller/src/attention.rs:913",
        When::Serving,
    );
    // The stores the daemon opens, and migrates or recovers, at its start.
    for (name, cite) in [
        (
            "capability-answers.sqlite3",
            "crates/kr-controller/src/capability_answers.rs:30",
        ),
        (
            "changesets/changesets.sqlite",
            "crates/kr-changeset/src/store.rs:50",
        ),
        (
            "delivery.sqlite3",
            "crates/kr-controller/src/push/mod.rs:256",
        ),
        (
            "descriptions.sqlite3",
            "crates/kr-describe/src/store.rs:141",
        ),
        ("privacy.sqlite3", "crates/kr-controller/src/privacy.rs:82"),
        (
            "projects/projects.sqlite",
            "crates/kr-project/src/store.rs:67",
        ),
        (
            "test-reports.sqlite3",
            "crates/kr-controller/src/test_reports.rs:29",
        ),
        (
            "transfers/draft-revisions.sqlite3",
            "crates/kr-transfer/src/revisions.rs:24",
        ),
        (
            "transfers/transfers.sqlite",
            "crates/kr-transfer/src/staging.rs:46",
        ),
        (
            "voice-start-holds.sqlite3",
            "crates/kr-controller/src/voice_start_holds.rs:26",
        ),
        ("workflows.db", "crates/kr-automation/src/store.rs:51"),
        (
            "workflow-resources.db",
            "crates/kr-automation/src/resources.rs:29",
        ),
    ] {
        database(name, cite, When::Start);
    }
    // A file the daemon writes whole under a staging name and renames over the name.
    let mut replaced = |name: &'static str, cite: &'static str, when: When, path: PathBuf| {
        rows.push(Daemon {
            name,
            cite,
            when,
            kind: Kind::File,
            operations: Operations::REPLACE,
            path: path.clone(),
            names: Names::Itself,
        });
        rows.push(Daemon {
            name,
            cite,
            when,
            kind: Kind::File,
            operations: Operations::ALL,
            path,
            names: Names::Staging,
        });
    };
    replaced(
        "policy-mirror.cbor",
        "crates/kr-controller/src/grants/mirror.rs:58-59; crates/kr-ipc/src/paths.rs:3235",
        When::Serving,
        state("policy-mirror.cbor"),
    );
    replaced(
        "projects/git-profile/temporary-entries",
        "crates/kr-project/src/git.rs:92; crates/kr-ipc/src/paths.rs:3235",
        When::Start,
        state("projects/git-profile/temporary-entries"),
    );
    // The singleton lock the daemon takes at its start.
    rows.push(Daemon {
        name: "controller.lock",
        cite: "crates/kr-ipc/src/paths.rs:414-416",
        when: When::Start,
        kind: Kind::File,
        operations: Operations::CONTENT,
        path: state("controller.lock"),
        names: Names::Itself,
    });
    // The daemon's sockets, bound at its start, and the lock file of each.
    for socket in ["c.sock", "r.sock", "t.sock"] {
        rows.push(Daemon {
            name: socket,
            cite: "crates/kr-ipc/src/paths.rs:366-408",
            when: When::Start,
            kind: Kind::Socket,
            operations: Operations::REPLACE,
            path: runtime(socket),
            names: Names::Itself,
        });
        rows.push(Daemon {
            name: "the lock file of a daemon socket",
            cite: "crates/kr-ipc/src/endpoint/platform/live.rs:41-43",
            when: When::Start,
            kind: Kind::File,
            operations: Operations::CONTENT,
            path: runtime(&format!("{socket}.live")),
            names: Names::Itself,
        });
    }
    rows
}

/// A change the compare refuses, said in one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The entry, relative to the run's directory.
    pub path: PathBuf,
    /// The change and why it is refused.
    pub said: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.said)
    }
}

/// Compares the tree `now` with the record `base`, and returns each change that no row allows.
///
/// `uid` is the account's: a new entry of a daemon row must be owned by it.
#[must_use]
pub fn compare(
    layout: &Layout,
    base: &Record,
    now: &Record,
    interval: Interval,
    uid: u32,
) -> Vec<Refusal> {
    let rows = daemon_rows(layout);
    let changes = base.changes_to(now);
    let mut by_path: BTreeMap<&Path, Vec<&Change>> = BTreeMap::new();
    for change in &changes {
        by_path.entry(change.path()).or_default().push(change);
    }
    let mut refusals = Vec::new();
    for (path, changes) in by_path {
        let said = match rows.iter().find(|row| row.covers(path)) {
            None => Some("no row of the live daemon's files covers this entry".to_owned()),
            Some(row) => row.refuses(&changes, interval, uid),
        };
        if let Some(why) = said {
            let lines: Vec<String> = changes.iter().map(ToString::to_string).collect();
            refusals.push(Refusal {
                path: path.to_path_buf(),
                said: format!("{}; {why}", lines.join("; ")),
            });
        }
    }
    refusals
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    use kr_ipc::paths::HostPaths;

    use super::*;
    use crate::run::RootPin;

    const KILL: Interval = Interval::AtTheKill { restarted: false };
    const LATER_KILL: Interval = Interval::AtTheKill { restarted: true };
    const ATTEMPT: Interval = Interval::BeforeTheAttempt;

    /// A host's two roots in a run directory of this test's own, short enough for a socket.
    struct World {
        root: PathBuf,
        pin: RootPin,
        paths: HostPaths,
        environment: EnvironmentPaths,
        layout: Layout,
    }

    fn world(name: &str) -> World {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        };
        let root = base.join(format!(
            "kc-{name}-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(root.join("r")).expect("a runtime root");
        std::fs::create_dir_all(root.join("s")).expect("a state root");
        for name in ["r", "s"] {
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))
                .expect("owner only");
        }
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("host roots");
        let identity = paths.open_environment_id().expect("an identity");
        let environment = paths.environment(identity);
        environment.create().expect("the environment's directories");
        let pin = RootPin::of(&root).expect("a pin");
        let layout = Layout::of(&root, &environment);
        World {
            root,
            pin,
            paths,
            environment,
            layout,
        }
    }

    impl World {
        fn state(&self, name: &str) -> PathBuf {
            self.environment.state_dir().join(name)
        }

        fn runtime(&self, name: &str) -> PathBuf {
            self.environment.runtime_dir().join(name)
        }

        /// Writes an owner-only file at `path`, making its directories.
        fn put(&self, path: &Path, bytes: &[u8]) {
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(path, bytes).expect("a file");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        }

        fn record(&self) -> Record {
            Record::of(&self.root, &self.pin, &["r", "s"]).expect("a record")
        }

        /// What the compare refuses between `before` and the tree now, one line each.
        fn refused(&self, before: &Record, interval: Interval) -> Vec<String> {
            compare(
                &self.layout,
                before,
                &self.record(),
                interval,
                rustix::process::getuid().as_raw(),
            )
            .iter()
            .map(ToString::to_string)
            .collect()
        }

        /// Puts another object, with the same bytes or others, in the place of the file at `path`.
        fn replace(&self, path: &Path, bytes: &[u8]) {
            let staging = path.with_extension("replacing");
            self.put(&staging, bytes);
            std::fs::rename(&staging, path).expect("renamed over");
        }

        fn clean(self) {
            std::fs::remove_dir_all(&self.root).expect("clean up");
        }
    }

    fn only(refused: &[String], text: &str) {
        assert!(
            refused.len() == 1 && refused[0].contains(text),
            "one refusal that says {text:?}: {refused:#?}"
        );
    }

    /// An entry no row covers is refused when it changes, at the kill, at a later kill and before
    /// the attempt: a changed file, an added entry, a gone entry.
    #[test]
    fn an_entry_that_no_row_covers_is_refused_when_it_changes_at_every_interval() {
        // The entries that no row covers: the identity file, the secret store's members, the
        // configuration, the applied policies, the catalogue and the bridge journals.
        enum Change {
            Rewrite,
            Add,
            Remove,
        }
        let cases = [
            ("the identity file", "environment-id", Change::Rewrite),
            ("a store member", "secrets/member", Change::Rewrite),
            ("an added key member", "secrets/added-key", Change::Add),
            (
                "the configuration document",
                "configuration.json",
                Change::Rewrite,
            ),
            (
                "a changed applied policy",
                "organisation-policy.json",
                Change::Rewrite,
            ),
            (
                "a removed applied policy",
                "organisation-policy.json",
                Change::Remove,
            ),
            ("a catalogue record", "catalogue/record", Change::Rewrite),
            (
                "a bridge journal",
                "native-bridges/journal",
                Change::Rewrite,
            ),
        ];
        for (label, name, change) in cases {
            let world = world("no-row");
            let path = match name {
                "environment-id" => world.paths.environment_id_file(),
                "configuration.json" => kr_worker::config::document_path(&world.environment),
                other => world.state(other),
            };
            if !matches!(change, Change::Add) {
                world.put(&path, b"before");
            }
            let before = world.record();
            match change {
                Change::Rewrite => std::fs::write(&path, b"after!").expect("rewritten"),
                Change::Add => world.put(&path, b"added"),
                Change::Remove => std::fs::remove_file(&path).expect("removed"),
            }
            for interval in [KILL, LATER_KILL, ATTEMPT] {
                let refused = world.refused(&before, interval);
                assert!(
                    refused.len() == 1
                        && refused[0]
                            .contains("no row of the live daemon's files covers this entry"),
                    "{label}, {interval:?}: {refused:#?}"
                );
            }
            world.clean();
        }
    }

    /// A recorded directory replaced by a link or by a file, and a changed owner-only mode, are
    /// refused, in an entry no row covers and in an entry a row covers.
    #[test]
    fn a_retyped_entry_and_a_changed_mode_are_refused_whether_or_not_a_row_covers_the_entry() {
        let world = world("retyped");
        world.put(&world.state("catalogue/record"), b"record");
        world.put(&world.state("bridges/journal"), b"journal");
        world.put(&world.state("registry.sqlite"), b"registry");
        let before = world.record();
        std::fs::remove_dir_all(world.state("catalogue")).expect("removed");
        std::os::unix::fs::symlink(world.state("bridges"), world.state("catalogue"))
            .expect("a link in the directory's place");
        std::fs::remove_dir_all(world.state("bridges")).expect("removed");
        world.put(&world.state("bridges"), b"a file in the directory's place");
        std::fs::set_permissions(
            world.state("registry.sqlite"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("group and other may read");
        let refused = world.refused(&before, KILL);
        let said = |text: &str| refused.iter().any(|line| line.contains(text));
        assert!(
            said("catalogue: it was a directory and is now a link"),
            "{refused:#?}"
        );
        assert!(
            said("bridges: it was a directory and is now a file"),
            "{refused:#?}"
        );
        assert!(said("catalogue/record: gone"), "{refused:#?}");
        assert!(
            said(
                "registry.sqlite: the permission bits were 0600 and are now 0644; registry.sqlite keeps its kind, its owner and its permission bits"
            ),
            "{refused:#?}"
        );
        world.clean();
    }

    /// A database the daemon writes changes in place at a kill, and does not change between the kill
    /// and the attempt; it is not replaced, removed or given another mode; its sidecars are made,
    /// changed, replaced and removed, owner-only; another name beside it is no row's.
    #[test]
    fn a_database_the_daemon_writes_changes_in_place_at_a_kill_and_nowhere_else() {
        let world = world("database");
        let registry = world.state("registry.sqlite");
        world.put(&registry, b"registry");
        world.put(&world.state("registry.sqlite-wal"), b"wal");
        world.put(&world.state("registry.sqlite-journal"), b"journal");
        let before = world.record();
        std::fs::write(&registry, b"registry, written").expect("written in place");
        world.replace(&world.state("registry.sqlite-wal"), b"another wal");
        std::fs::remove_file(world.state("registry.sqlite-journal")).expect("removed");
        world.put(&world.state("registry.sqlite-shm"), b"shm");
        assert_eq!(world.refused(&before, KILL), Vec::<String>::new());
        assert_eq!(world.refused(&before, LATER_KILL), Vec::<String>::new());
        let refused = world.refused(&before, ATTEMPT);
        assert_eq!(refused.len(), 4, "{refused:#?}");
        assert!(
            refused
                .iter()
                .all(|line| line.contains("no daemon runs between the kill and the attempt")),
            "{refused:#?}"
        );
        // Replaced, removed, another mode, another name, a sidecar anyone may read.
        let before = world.record();
        world.replace(&registry, b"registry, replaced");
        let refused = world.refused(&before, KILL);
        only(&refused, "registry.sqlite permits no replacement");
        std::fs::remove_file(&registry).expect("removed");
        only(
            &world.refused(&before, KILL),
            "registry.sqlite permits no removal",
        );
        world.put(&registry, b"registry");
        let before = world.record();
        std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o660))
            .expect("group may write");
        only(
            &world.refused(&before, KILL),
            "registry.sqlite keeps its kind, its owner and its permission bits",
        );
        std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o600)).expect("mode");
        world.put(&world.state("registry.sqlite.bak"), b"a copy");
        only(
            &world.refused(&before, KILL),
            "no row of the live daemon's files covers this entry",
        );
        std::fs::remove_file(world.state("registry.sqlite.bak")).expect("removed");
        world.put(&world.state("registry.sqlite-journal"), b"journal");
        std::fs::set_permissions(
            world.state("registry.sqlite-journal"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("anyone may read");
        only(
            &world.refused(&before, KILL),
            "a new entry of registry.sqlite is owned by the account and owner-only",
        );
        world.clean();
    }

    /// A database the daemon opens at its start changes only at a kill that follows a restart.
    #[test]
    fn a_database_the_daemon_opens_at_a_start_changes_only_at_a_kill_after_a_restart() {
        let world = world("start-database");
        world.put(&world.state("privacy.sqlite3"), b"privacy");
        let before = world.record();
        std::fs::write(world.state("privacy.sqlite3"), b"privacy, written").expect("written");
        world.put(&world.state("privacy.sqlite3-wal"), b"wal");
        let refused = world.refused(&before, KILL);
        assert_eq!(refused.len(), 2, "{refused:#?}");
        assert!(
            refused.iter().all(|line| line.contains(
                "changes only when a daemon starts, and none has started since the record was made"
            )),
            "{refused:#?}"
        );
        assert_eq!(world.refused(&before, LATER_KILL), Vec::<String>::new());
        only(
            &world.refused(&before, ATTEMPT)[..1],
            "no daemon runs between the kill and the attempt",
        );
        // A database file the record does not hold is made by no start of these rows, and a sidecar
        // name that is a directory is not a file.
        let before = world.record();
        world.put(&world.state("workflows.db"), b"new");
        only(
            &world.refused(&before, LATER_KILL),
            "workflows.db permits no creation",
        );
        std::fs::remove_file(world.state("workflows.db")).expect("removed");
        std::fs::create_dir(world.state("privacy.sqlite3-shm")).expect("a directory");
        std::fs::set_permissions(
            world.state("privacy.sqlite3-shm"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("owner only");
        only(
            &world.refused(&before, LATER_KILL),
            "privacy.sqlite3 holds a file, and this entry is a directory",
        );
        world.clean();
    }

    /// The daemon's sockets are bound at its start: a new object is permitted at a kill that follows
    /// a restart, never at the first kill and never before the attempt; the worker's endpoint is
    /// no row's, so a replaced socket of the worker is refused at every interval.
    #[test]
    fn the_daemons_sockets_are_replaced_at_a_start_and_the_workers_endpoint_never() {
        let world = world("sockets");
        let bind = |name: &str| UnixListener::bind(world.runtime(name)).expect("a socket");
        let held = [bind("c.sock"), bind("w1.sock")];
        let before = world.record();
        for name in ["c.sock", "w1.sock"] {
            let staging = world.runtime(&format!("{name}.new"));
            let _fresh = UnixListener::bind(&staging).expect("a socket beside");
            std::fs::rename(&staging, world.runtime(name)).expect("renamed over");
        }
        drop(held);
        let refused = world.refused(&before, KILL);
        assert_eq!(refused.len(), 2, "{refused:#?}");
        let refused_later = world.refused(&before, LATER_KILL);
        only(&refused_later, "w1.sock: another object of the same kind");
        assert!(
            refused_later[0].contains("no row of the live daemon's files covers this entry"),
            "{refused_later:#?}"
        );
        let attempt = world.refused(&before, ATTEMPT);
        assert_eq!(attempt.len(), 2, "{attempt:#?}");
        world.clean();
    }

    /// A file the daemon replaces may be replaced at a kill, with the staging name its writer uses
    /// made and removed beside it; another name beside it, and a staging name beside a file whose
    /// row has none, are refused; a file written at a start only waits for a restart.
    #[test]
    fn a_file_the_daemon_replaces_leaves_its_staging_names_and_a_lock_file_waits_for_a_restart() {
        let world = world("replaced");
        world.put(&world.state("policy-mirror.cbor"), b"mirror");
        world.put(&world.state("controller.lock"), b"1");
        let before = world.record();
        world.replace(&world.state("policy-mirror.cbor"), b"mirror, replaced");
        let staging = format!(".{}.tmp", kr_ipc::new_uuid());
        world.put(&world.state(&staging), b"staged");
        assert_eq!(world.refused(&before, KILL), Vec::<String>::new());
        world.put(&world.state(".not-a-uuid.tmp"), b"staged");
        only(&world.refused(&before, KILL), ".not-a-uuid.tmp: added");
        std::fs::remove_file(world.state(".not-a-uuid.tmp")).expect("removed");
        std::fs::write(world.state("controller.lock"), b"22").expect("written in place");
        only(
            &world.refused(&before, KILL),
            "controller.lock changes only when a daemon starts",
        );
        assert_eq!(world.refused(&before, LATER_KILL), Vec::<String>::new());
        world.replace(&world.state("controller.lock"), b"333");
        only(
            &world.refused(&before, LATER_KILL),
            "controller.lock permits no replacement",
        );
        world.clean();
    }

    /// An entry outside the class that changes after the first restart is refused at the second
    /// kill, in the same compare that permits what a start writes.
    #[test]
    fn a_write_after_the_first_restart_to_the_identity_file_is_refused_at_the_second_kill() {
        let world = world("second-kill");
        let identity = world.paths.environment_id_file();
        world.put(&world.state("privacy.sqlite3"), b"privacy");
        let before = world.record();
        std::fs::write(
            world.state("privacy.sqlite3"),
            b"privacy, opened at the start",
        )
        .expect("what the start wrote");
        std::fs::write(&identity, b"another identity").expect("what the agent wrote");
        let refused = world.refused(&before, LATER_KILL);
        only(&refused, "environment-id: the bytes changed");
        world.clean();
    }

    /// Every row names its entry and the code that writes it.
    #[test]
    fn every_row_of_the_live_daemons_class_cites_its_writer() {
        let world = world("rows");
        let rows = daemon_rows(&world.layout);
        assert!(rows.len() > 30, "{} rows", rows.len());
        for row in &rows {
            assert!(!row.name.is_empty(), "{row:?}");
            assert!(
                row.cite.contains(".rs:"),
                "{} cites no line of the code that writes it: {}",
                row.name,
                row.cite
            );
        }
        world.clean();
    }
}
