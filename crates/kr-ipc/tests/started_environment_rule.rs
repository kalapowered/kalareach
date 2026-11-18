//! A test that starts a daemon, a worker, a `kr` command or a session gives it a home of its own.
//!
//! A session's shell starts as a login shell and reads the startup files of the home folder it is
//! given. A program a test starts inherits the test program's environment, so a harness that does
//! not say otherwise gives the worker's shell the person's real home, and with it the person's
//! profile. A session that a test's own client creates takes the creator's snapshot of the
//! environment and nothing of the daemon's; a snapshot with no `HOME` gives a login shell the
//! account's own home, which the account database names, and neither the test program's home nor
//! a recorder in the case's own home sees that read. This test reads the Rust sources under
//! `crates`, `apps` and `tests` in four readings, each of which names the file and the line of
//! what it refuses:
//!
//! 1. A source that names a program a test starts (the three programs cargo names through
//!    `CARGO_BIN_EXE_*`, a program called by its name, the `kr` crate's `command_binaries()` and
//!    `kr()`, written with or without white space) uses
//!    [`kr_ipc::testing::started_environment::StartedEnvironment`] or clears the inherited
//!    environment and sets `HOME` itself, or has a row in `KEPT` or `INHERITS`.
//! 2. Every place that writes a creator's snapshot of the environment (a field `environment_snapshot:`,
//!    an assignment to it, and the same name written into a JSON text) names the helper's
//!    `snapshot_home()` inside the expression it writes, or its file has a row in `SNAPSHOTS` that
//!    counts the places it excuses.
//! 3. Every start of a daemon in the test's own process (`Controller::start`,
//!    `Controller::start_on_clocks`, `Controller::start_on_timer`,
//!    `Controller::start_on_clocks_and_timer` and `Controller::start_on_clocks_and_timers`)
//!    gives the daemon its host environment in the same function
//!    (`set_host_environment`), or names a worker program that does not exist, or its file has a
//!    row in `DAEMON_STARTS` that counts the starts it excuses.
//! 4. Each row that says a source keeps the real environment on purpose (`INHERITS`) names text
//!    that the source still holds.
//!
//! What it holds: a new place in a test source that writes a snapshot without the helper, or
//! starts a daemon in the test's process that no worker program stops, fails unless a row that
//! counts it exists. A row is by file and by count, so a further place in an excused file fails
//! too, and a row whose count no longer matches fails. Every row gives its reason by the lines and
//! its removal condition, or says why it stays, and the rows of reading 2 and 3 carry a condition
//! that the scan tests on the file.
//!
//! What it does not hold:
//!
//! - Reading 1 is by file: one use of the helper, or one `env_clear` beside a `HOME`, satisfies it
//!   for every program the file starts. A `kr` command or a child daemon in such a file is the
//!   author's to give the environment.
//! - It cannot tell which presentation or shell a create has: a place that names the helper may
//!   still run a shell that reads nothing, and a place that a row excuses may run a login shell
//!   later. The row's reason says what the file does today.
//! - A snapshot written by a name other than the field's (a shorthand `environment_snapshot,`), or
//!   built in a source under `src` that holds test modules, is not seen.
//! - The environment a daemon in the test's own process reads at its start. A run the daemon
//!   resumes from its journal, as well as a trigger that is due, can create a session before the
//!   next line of the harness runs; that session has the test program's environment.
//! - A Windows source is not read: a session's shell there reads the account's PowerShell
//!   profile, which the helper does not give a home to, and the Windows harnesses are the work of
//!   a later change.

use std::path::{Path, PathBuf};

/// The directories the reading covers, under the workspace's root.
const ROOTS: [&str; 3] = ["crates", "apps", "tests"];

/// The text that names a program a test starts.
const NAMES: [&str; 5] = [
    "CARGO_BIN_EXE_kr\"",
    "CARGO_BIN_EXE_kr-controller\"",
    "CARGO_BIN_EXE_kr-worker\"",
    "\"kr-controller\"",
    "\"kr-worker\"",
];

/// The functions a test calls to get a program, written as `name()` with or without white space.
const CALLS: [&str; 2] = ["command_binaries", "kr"];

/// The words that show a file gives what it starts an environment of its own: the helper, or an
/// environment cleared and a home set by the file itself.
const HELPER: &str = "StartedEnvironment";

/// What a place that writes a snapshot names to have the home folder of the case's own tree.
const SNAPSHOT_HOME: &str = "snapshot_home(";

/// The call that gives a daemon in the test's process the environment its sessions start with.
const SETTER: &str = "set_host_environment(";

/// The starts of a daemon in the test's own process.
const DAEMON_STARTS_AT: [&str; 5] = [
    "Controller::start(",
    "Controller::start_on_clocks(",
    "Controller::start_on_timer(",
    "Controller::start_on_clocks_and_timer(",
    "Controller::start_on_clocks_and_timers(",
];

/// The text of a worker program's path that shows the path does not exist, so no worker and no
/// shell can start.
const NO_SUCH_WORKER: [&str; 3] = ["\"/nonexistent/", "\"none\"", "\"no-such-worker\""];

/// A source that is excused from a reading, why, and when the row goes.
struct Row {
    file: &'static str,
    reason: &'static str,
    removal: &'static str,
}

/// A source that is excused from a reading for a number of places, why, when the row goes, and the
/// condition on the source's text that the reason rests on.
struct Counted {
    file: &'static str,
    places: usize,
    reason: &'static str,
    removal: &'static str,
    holds: fn(&str) -> bool,
}

/// Why a source that names a program starts no session: its daemon has no worker program that
/// exists.
const NO_WORKER: &str = "its daemon has no worker program that exists, so no session can start";
const NO_WORKER_REMOVAL: &str = "none while its daemon has no worker program; the row goes when the source places a \
     worker, and the readings of the snapshot and of the daemon's start then read it";

/// Why a source that names a program starts no session: it runs a command against a host that
/// already runs.
const NO_START: &str = "it runs a command against a host that already runs, with an environment of its own, and the \
     command starts no daemon and no session";
const NO_START_REMOVAL: &str =
    "none while its commands start neither a daemon nor a session; the row goes when one does";

/// Why a source that names a program starts no session: it only names it.
const NAMES_ONLY: &str = "it names the programs without starting any";
const NAMES_ONLY_REMOVAL: &str = "none while it only names them";

/// The sources that name a program a test starts and neither use the helper nor build the whole
/// environment themselves. Each starts no session with a shell of a person's home to read.
const KEPT: &[Row] = &[
    Row {
        file: "crates/kr-cli/tests/bridge.rs",
        reason: NO_START,
        removal: NO_START_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/contact.rs",
        reason: NO_START,
        removal: NO_START_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/container.rs",
        reason: NO_START,
        removal: NO_START_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/probe.rs",
        reason: NO_START,
        removal: NO_START_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/retained_surface.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/descriptions.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/host_clock.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/host_network.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/organisation.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/pair.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/agent_tools.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/bridge.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/bundled_agents_default_route.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/bundled_seed.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/configuration.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/configuration_reader.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/destinations.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/managed_storage.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/project.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/storage_account.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/transfer.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/task_supervisor.rs",
        reason: NO_WORKER,
        removal: NO_WORKER_REMOVAL,
    },
    Row {
        file: "crates/kr-controller/tests/spawn_sites.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "tests/conformance/src/plan.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "tests/conformance/src/report.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "crates/kr-cli/tests/support/mod.rs",
        reason: "it places copies of the programs other sources start and starts each copy once with \
                 `--version` to establish that it runs; it creates no session",
        removal: "none while the copies are started only for their version",
    },
    Row {
        file: "crates/kr-controller/tests/plugin_world/mod.rs",
        reason: "its daemon's workers are records that no process backs; it starts plugin services \
                 through the platform's service manager, which the reading of the daemon's start \
                 below shows the file does with no worker program, and the one shell it runs, in \
                 its own process, is a placed script",
        removal: "the row goes when the file starts a worker program or a shell that is not a placed \
                  script",
    },
    Row {
        file: "crates/kr-shell-integration/tests/qualification.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "crates/kr-worker/tests/trusted_core.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "tests/e2e/m1b/src/run.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
    Row {
        file: "tests/e2e/m1b/tests/checkpoint.rs",
        reason: NAMES_ONLY,
        removal: NAMES_ONLY_REMOVAL,
    },
];

/// A source that clears the environment and sets `HOME`, so reading 1 passes it, and yet gives a
/// program the person's own: the text that the reason rests on, the reason, and when the row goes.
struct Inherits {
    file: &'static str,
    mark: &'static str,
    reason: &'static str,
    removal: &'static str,
}

/// The sources that keep a real environment for a program they start, on purpose.
const INHERITS: &[Inherits] = &[
    Inherits {
        file: "crates/kr-cli/tests/bridged_session.rs",
        mark: "\"XDG_RUNTIME_DIR\"",
        reason: "its `kr` command keeps the person's `HOME` and the `XDG` folders, which a rootless \
                 container runtime and the `ssh` stand-ins read, and its daemon is started with the \
                 whole environment of the test program; a session its daemon starts takes the \
                 person's home. The sentinel run of the suite read no startup file in any of its \
                 cases, and no case of it runs a login shell by name",
        removal: "the row goes when the stand-ins and the container runtime read their folders from \
                  a home inside the case's tree; the daemon is then started through the helper",
    },
    Inherits {
        file: "crates/kr-cli/tests/startup.rs",
        mark: "fn service_installation()",
        reason: "the half of the suite that installs a service hands the daemon to the platform's \
                 service manager, which gives it the environment of its own manager; its `kr` \
                 commands clear the environment and set a home in the tree",
        removal: "none while the platform's manager builds the daemon's environment: no test seam \
                  gives a service manager a home",
    },
    Inherits {
        file: "crates/kr-cli/tests/update.rs",
        mark: "async fn a_daemon_the_service_manager_started_is_started_again_by_it()",
        reason: "its cases that install a service have the platform's manager build the daemon's \
                 environment; the daemons its harness starts itself get the helper's, and its `kr` \
                 commands clear the environment and set a home",
        removal: "none while the platform's manager builds the daemon's environment: no test seam \
                  gives a service manager a home",
    },
];

/// Why a source writes a snapshot as data: it builds and reads the parameters of a create for a
/// codec or a store, and starts no program and no daemon.
const DATA_ONLY: &str = "it builds and reads a create's parameters as data for a codec or a store, and starts no \
     program and no daemon";
const DATA_ONLY_REMOVAL: &str =
    "none while it starts neither a program nor a daemon; the condition is tested";

/// Why a source writes a snapshot for a daemon that starts no worker: the daemon's worker program
/// is a path that does not exist, so no session starts and no shell runs.
const NO_WORKER_CREATES: &str = "every daemon it starts names a worker program that does not exist, so a create it \
     sends starts no session and runs no shell";
const NO_WORKER_CREATES_REMOVAL: &str = "none while its daemons name a worker program that does not exist; the condition is \
     tested, and the row goes when a daemon of the source gets a real worker";

/// When the rows of sources that send invisible creates go.
const INVISIBLE_CREATE_REMOVAL: &str =
    "none while the daemon refuses a variable on an invisible create";

/// The sources that write a creator's snapshot of the environment without the helper's home, with
/// the number of places each excuses.
const SNAPSHOTS: &[Counted] = &[
    Counted {
        file: "crates/kr-automation/tests/common/mod.rs",
        places: 1,
        reason: DATA_ONLY,
        removal: DATA_ONLY_REMOVAL,
        holds: starts_nothing,
    },
    Counted {
        file: "crates/kr-automation/tests/definitions.rs",
        places: 7,
        reason: DATA_ONLY,
        removal: DATA_ONLY_REMOVAL,
        holds: starts_nothing,
    },
    Counted {
        file: "crates/kr-automation/tests/durability.rs",
        places: 2,
        reason: DATA_ONLY,
        removal: DATA_ONLY_REMOVAL,
        holds: starts_nothing,
    },
    Counted {
        file: "crates/kr-cli/tests/update.rs",
        places: 2,
        reason: "one place is the bytes of a recorded create that a case writes into a daemon's journal, and no session starts from them; the other is an invisible create, which the daemon refuses when it carries a variable, so its session takes the host's environment of the daemon the case starts with `Host::start_daemon`: a child program started through the helper, whose environment is the home of the case's own tree. The cases that hand the daemon to the platform's service manager give it the manager's environment (see the row of kept real environments) and create no session through this function",
        removal: "none while the function only returns the recorded bytes and the daemon refuses a variable on an invisible create",
        holds: |text| {
            text.contains("fn recorded_create(secret: &str) -> Vec<u8>")
                && text.contains("fn headless_create_params(")
        },
    },
    Counted {
        file: "crates/kr-controller/tests/a_repeat_of_a_create_that_failed.rs",
        places: 1,
        reason: "its create is sent to a host whose workers folder is a file, so no worker can start; \
                 the host is the network suite's, whose daemon names no worker program",
        removal: "none while the host is the network suite's",
        holds: |text| text.contains("mod net_support;"),
    },
    Counted {
        file: "crates/kr-controller/tests/device_errors.rs",
        places: 1,
        reason: "its creates are answered with refusals by a host the network suite makes, whose \
                 daemon names no worker program; no session starts",
        removal: "none while the host is the network suite's",
        holds: |text| text.contains("mod net_support;"),
    },
    Counted {
        file: "crates/kr-controller/tests/automation.rs",
        places: 3,
        reason: "every place is an invisible create (a create-session node, which the product also refuses when it carries a variable, and two creates from the client), so each session takes the host's environment of its file's daemon: the daemons that start workers are started by `working_host_on_clocks` and `working_host_apart_started_by`, and both call `set_host_environment` with the helper's variables, the home of the case's own tree; the daemons that do not call it have a worker program that does not exist",
        removal: INVISIBLE_CREATE_REMOVAL,
        holds: |text| text.contains("fn create_session_node(") && text.contains("fn session_in("),
    },
    Counted {
        file: "crates/kr-controller/tests/barrier.rs",
        places: 6,
        reason: "its daemons name a worker program that does not exist, and the one runtime it runs in \
                 its own process opens a placed script as its shell, not a login shell",
        removal: "none while both hold; the condition is tested",
        holds: |text| every_daemon_has_no_worker(text) && text.contains("posix_script("),
    },
    Counted {
        file: "crates/kr-controller/tests/command_integrations.rs",
        places: 2,
        reason: NO_WORKER_CREATES,
        removal: NO_WORKER_CREATES_REMOVAL,
        holds: every_daemon_has_no_worker,
    },
    Counted {
        file: "crates/kr-controller/tests/contracts.rs",
        places: 1,
        reason: NO_WORKER_CREATES,
        removal: NO_WORKER_CREATES_REMOVAL,
        holds: every_daemon_has_no_worker,
    },
    Counted {
        file: "crates/kr-controller/tests/envelope.rs",
        places: 1,
        reason: NO_WORKER_CREATES,
        removal: NO_WORKER_CREATES_REMOVAL,
        holds: every_daemon_has_no_worker,
    },
    Counted {
        file: "crates/kr-controller/tests/privacy_launch.rs",
        places: 1,
        reason: NO_WORKER_CREATES,
        removal: NO_WORKER_CREATES_REMOVAL,
        holds: every_daemon_has_no_worker,
    },
    Counted {
        file: "crates/kr-controller/tests/voice.rs",
        places: 1,
        reason: NO_WORKER_CREATES,
        removal: NO_WORKER_CREATES_REMOVAL,
        holds: every_daemon_has_no_worker,
    },
    Counted {
        file: "crates/kr-controller/tests/network.rs",
        places: 1,
        reason: "the place is a paired device's create, which sends no environment of its own by \
                 design: the session takes the daemon's, which the harness gives it",
        removal: "none while a device's own environment is never a session's",
        holds: |text| text.contains("..create_params(environment_id, host.tree().root())"),
    },
    Counted {
        file: "crates/kr-controller/tests/plugin_world/mod.rs",
        places: 1,
        reason: "the session's worker is a record that no process backs, and the one shell the file \
                 runs, in its own process, is a placed script",
        removal: "the row goes when the file starts a worker program or runs a shell that is not a \
                  placed script",
        holds: |text| text.contains("posix_script(shell)"),
    },
    Counted {
        file: "crates/kr-controller/tests/recorded_create.rs",
        places: 3,
        reason: "the places are records of an earlier build's creates that the case writes into the \
                 registry and reads back; no session starts from them",
        removal: "none while they are stored records",
        holds: |text| text.contains("fn seed_reservation("),
    },
    Counted {
        file: "crates/kr-controller/tests/shell.rs",
        places: 2,
        reason: "the maker of the file's create parameters is invisible, which the daemon refuses when it carries a variable; the harness without workers starts no session, and the real-worker harness gives its daemon the environment of each case on purpose, which may name the account's own home or none, so a session there can have the account's home; that session runs a placed script that reports its environment and then a shell that is not a login shell, so it reads no startup file even then. The one case that shows its create sets the presentation and the home itself. The other place is the snapshot such a case sends",
        removal: "none while the daemon refuses a variable on an invisible create, and while those cases are about which variables reach the worker",
        holds: |text| {
            text.contains("exec /bin/sh -i")
                && text.contains("request.presentation = Presentation::Terminal;")
        },
    },
    Counted {
        file: "crates/kr-worker/tests/session.rs",
        places: 1,
        reason: "the place is a create request that the case only reads the palette from; the session \
                 it opens runs `sleep 30`, not a shell",
        removal: "none while the case opens that session",
        holds: |text| text.contains("sleep 30"),
    },
    Counted {
        file: "apps/companion/src-tauri/tests/local_host.rs",
        places: 1,
        reason: "the place is what the page writes for an invisible create, and the daemon refuses an \
                 app's snapshot, so it holds none; the session takes the daemon's environment, which \
                 the harness gives it",
        removal: "none while the daemon refuses an app's snapshot",
        holds: |text| text.contains("\"presentation\": \"invisible\""),
    },
    Counted {
        file: "crates/kr-controller/tests/binding.rs",
        places: 2,
        reason: "its places are invisible creates, which the daemon refuses when they carry a variable (a session started with the host's environment carries none), so each session takes the host's environment of its file's daemon: `Hosted::start` calls `set_host_environment` after the daemon starts, so the home is inside the case's own tree",
        removal: INVISIBLE_CREATE_REMOVAL,
        holds: |text| text.contains("Presentation::Invisible"),
    },
    Counted {
        file: "crates/kr-controller/tests/plugin_runtime.rs",
        places: 1,
        reason: "its places are invisible creates, which the daemon refuses when they carry a variable (a session started with the host's environment carries none), so each session takes the host's environment of its file's daemon: the in-process daemon calls `set_host_environment`, and the child daemon is started through the helper's `apply_keeping`, so the home is inside the case's own tree in both",
        removal: INVISIBLE_CREATE_REMOVAL,
        holds: |text| text.contains("Presentation::Invisible"),
    },
    Counted {
        file: "crates/kr-worker/tests/launchd_jobs.rs",
        places: 1,
        reason: "its places are invisible creates, which the daemon refuses when they carry a variable (a session started with the host's environment carries none), so each session takes the host's environment of its file's daemon: `Host::start_with` calls `set_host_environment` after the daemon starts, so the home is inside the case's own tree",
        removal: INVISIBLE_CREATE_REMOVAL,
        holds: |text| text.contains("Presentation::Invisible"),
    },
];

/// Why a source starts a daemon in a child program: the child's own environment is the helper's.
const CHILD_DAEMON: &str = "the daemon runs in a child test program that the parent starts through the helper, so \
     the environment the daemon reads at its start is the helper's";
const CHILD_DAEMON_REMOVAL: &str =
    "none while the parent starts the child through the helper; the condition is tested";

/// The sources that start a daemon in the test's own process without giving it a host environment
/// in the same function, with the number of starts each excuses.
const DAEMON_STARTS: &[Counted] = &[
    Counted {
        file: "crates/kr-controller/tests/automation.rs",
        places: 1,
        reason: "the one function that starts the file's daemons takes the worker program as an \
                 argument: the two callers that give it a real worker set the host environment \
                 before any client endpoint exists, and the others pass a path that does not exist",
        removal: "the row goes when the function takes the environment as an argument",
        holds: |text| {
            text.matches("set_host_environment(").count() == 2
                && text.contains("PathBuf::from(\"/nonexistent/kr-worker\")")
        },
    },
    Counted {
        file: "crates/kr-controller/tests/configuration_reader.rs",
        places: 1,
        reason: "its supervisor starts no worker",
        removal: "none while the supervisor starts no worker",
        holds: |text| text.contains("Box::new(NoWorkers)"),
    },
    Counted {
        file: "crates/kr-controller/tests/net_support/mod.rs",
        places: 3,
        reason: "its three starts (on the clocks, on the clocks and a timer, on the clocks and three timers) share the setup of every host it makes, which names a worker program that does not exist",
        removal: "none while the setup names none; the condition is tested",
        holds: |text| text.contains("\"/nonexistent/kr-worker\""),
    },
    Counted {
        file: "crates/kr-controller/tests/plugin_runtime.rs",
        places: 1,
        reason: CHILD_DAEMON,
        removal: CHILD_DAEMON_REMOVAL,
        holds: |text| text.contains(".apply_keeping(&mut command, &USER_MANAGER_VARIABLES)"),
    },
    Counted {
        file: "crates/kr-controller/tests/plugin_world/mod.rs",
        places: 1,
        reason: "its supervisor records worker launches and starts plugin services, so no worker \
                 process starts, and the one shell the file runs is a placed script",
        removal: "the row goes when the file starts a worker program or runs a shell that is not a \
                  placed script",
        holds: |text| text.contains("posix_script(shell)"),
    },
    Counted {
        file: "crates/kr-controller/tests/task_supervisor.rs",
        places: 1,
        reason: "its supervisor starts no worker",
        removal: "none while the supervisor starts no worker",
        holds: |text| text.contains("Box::new(NoWorkers)"),
    },
    Counted {
        file: "crates/kr-controller/tests/transfer.rs",
        places: 1,
        reason: "the setup it starts the daemon with names a worker program that does not exist",
        removal: "none while the setup names none; the condition is tested",
        holds: |text| text.contains("\"/nonexistent/kr-worker\""),
    },
    Counted {
        file: "apps/companion/src-tauri/tests/transfers.rs",
        places: 1,
        reason: "the setup it starts the daemon with names a worker program that does not exist",
        removal: "none while the setup names none; the condition is tested",
        holds: |text| text.contains("\"/nonexistent/kr-worker\""),
    },
    Counted {
        file: "crates/kr-worker/tests/controller_kill.rs",
        places: 1,
        reason: CHILD_DAEMON,
        removal: CHILD_DAEMON_REMOVAL,
        holds: |text| text.contains("StartedEnvironment::within(host.root()).apply("),
    },
    Counted {
        file: "tests/faults/tests/kills.rs",
        places: 1,
        reason: "its daemon cannot be given a host environment without the controller's `testing` \
                 feature, which builds the daemon with hooks that the kill matrix would then kill; \
                 every session it creates takes the creator's snapshot, which carries the home of \
                 the tree, and runs a placed root program, so no session takes the host's \
                 environment today",
        removal: "the row goes when a setter exists that needs no testing hook",
        holds: |text| text.contains("snapshot_home("),
    },
    Counted {
        file: "tests/perf/tests/stress.rs",
        places: 1,
        reason: "its daemon cannot be given a host environment without the controller's `testing` \
                 feature, which builds the daemon with hooks that the measurement would then \
                 include; every session it creates takes the creator's snapshot, which carries the \
                 home of the tree, so no session takes the host's environment today",
        removal: "the row goes when a setter exists that needs no testing hook",
        holds: |text| text.contains("snapshot_home("),
    },
];

/// The line of a position in a text.
fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// Whether the character before `at` could continue a name, so a match at `at` is the end of a
/// longer name.
fn ends_a_longer_name(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_some_and(|before| before.is_alphanumeric() || before == '_')
}

/// The first place that `name` is called with no argument, written `name()` with white space
/// allowed before the bracket and inside it.
fn bare_call(text: &str, name: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = text[from..].find(name) {
        let at = from + found;
        from = at + name.len();
        if ends_a_longer_name(text, at) {
            continue;
        }
        let rest = text[at + name.len()..].trim_start();
        if let Some(inside) = rest.strip_prefix('(')
            && inside.trim_start().starts_with(')')
        {
            return Some(at);
        }
    }
    None
}

/// The line and the name of the first place the text names a program a test starts, when it does.
fn first_start(text: &str) -> Option<(usize, String)> {
    let mut first: Option<(usize, String)> = None;
    let mut note = |line: usize, name: String| {
        if first.as_ref().is_none_or(|(earlier, _)| line < *earlier) {
            first = Some((line, name));
        }
    };
    for name in NAMES {
        if let Some(at) = text.find(name) {
            note(line_of(text, at), name.to_owned());
        }
    }
    for name in CALLS {
        if let Some(at) = bare_call(text, name) {
            note(line_of(text, at), format!("{name}()"));
        }
    }
    first
}

/// Whether the text gives what it starts an environment of its own.
fn gives_an_environment(text: &str) -> bool {
    text.contains(HELPER) || (text.contains("env_clear()") && text.contains("\"HOME\""))
}

/// The line and the name of the first start in a source that gives its programs no environment, or
/// nothing when it starts none or gives one.
fn offence(text: &str) -> Option<(usize, String)> {
    let code = without_comments(text);
    let start = first_start(&code)?;
    (!gives_an_environment(&code)).then_some(start)
}

/// Where the expression that begins at `from` ends: at the first `,` or `;` outside every
/// bracket, or at the bracket that closes the one it is in. Text in quotes is passed over.
fn expression_end(text: &str, from: usize) -> usize {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, c) in text[from..].char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => match depth.checked_sub(1) {
                Some(rest) => depth = rest,
                None => return from + offset,
            },
            ',' | ';' if depth == 0 => return from + offset,
            _ => {}
        }
    }
    text.len()
}

/// Where the bracket that opens at `open` closes.
fn bracket_end(text: &str, open: usize) -> usize {
    expression_end(text, open + 1)
}

/// The places in the text that write a creator's snapshot: the line, and whether the expression
/// written names the helper's home. A place is a field `environment_snapshot: <value>`, an
/// assignment `.environment_snapshot = <value>` or `["environment_snapshot"] = <value>`, and the
/// name written as a key of a JSON text, with or without escaped quotes. A field that declares the
/// type (`: Vec<...>`) and a pattern or a read is not a place.
fn snapshot_places(text: &str) -> Vec<(usize, bool)> {
    const NAME: &str = "environment_snapshot";
    let mut places = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find(NAME) {
        let at = from + found;
        from = at + NAME.len();
        if ends_a_longer_name(text, at)
            || text[at + NAME.len()..]
                .chars()
                .next()
                .is_some_and(|after| after.is_alphanumeric() || after == '_')
        {
            continue;
        }
        let mut rest = &text[at + NAME.len()..];
        // The name as a string: its closing quote, escaped or not, and the bracket of an index.
        rest = rest
            .strip_prefix("\\\"")
            .or(rest.strip_prefix('"'))
            .unwrap_or(rest);
        let indexed = rest.starts_with(']');
        rest = rest.strip_prefix(']').unwrap_or(rest);
        let spaced = rest.trim_start();
        let value = if let Some(after) = spaced.strip_prefix(':')
            && !after.starts_with(':')
            && !indexed
        {
            after
        } else if let Some(after) = spaced.strip_prefix('=')
            && !after.starts_with('=')
        {
            after
        } else {
            continue;
        };
        let begun = text.len() - value.len();
        if value.trim_start().starts_with("Vec<") {
            continue;
        }
        let end = expression_end(text, begun);
        places.push((line_of(text, at), text[begun..end].contains(SNAPSHOT_HOME)));
    }
    places
}

/// A start of a daemon in the test's own process.
struct DaemonStart {
    line: usize,
    /// The same function gives the daemon its host environment after the start.
    given: bool,
    /// The call names a worker program whose path does not exist.
    no_worker: bool,
}

/// The starts of a daemon in the test's own process.
fn daemon_starts(text: &str) -> Vec<DaemonStart> {
    let mut starts = Vec::new();
    for call in DAEMON_STARTS_AT {
        let mut from = 0;
        while let Some(found) = text[from..].find(call) {
            let at = from + found;
            from = at + call.len();
            let open = at + call.len() - 1;
            let arguments = &text[open..bracket_end(text, open)];
            let function_end = next_function(text, at);
            let worker_program = arguments.find("worker_program:").map(|begun| {
                let begun = begun + "worker_program:".len();
                &arguments[begun..expression_end(arguments, begun)]
            });
            starts.push(DaemonStart {
                line: line_of(text, at),
                given: text[at..function_end].contains(SETTER),
                no_worker: worker_program
                    .is_some_and(|path| NO_SUCH_WORKER.iter().any(|marker| path.contains(marker))),
            });
        }
    }
    starts.sort_unstable_by_key(|start| start.line);
    starts
}

/// The lines of the starts that neither give the daemon its environment nor have no worker.
fn unexcused_starts(text: &str) -> Vec<usize> {
    daemon_starts(text)
        .iter()
        .filter(|start| !start.given && !start.no_worker)
        .map(|start| start.line)
        .collect()
}

/// The lines of the places that write a snapshot without the helper's home.
fn unnamed_snapshot_places(text: &str) -> Vec<usize> {
    snapshot_places(text)
        .iter()
        .filter(|(_, named)| !named)
        .map(|(line, _)| *line)
        .collect()
}

/// A condition of a row: the source starts no program and no daemon.
fn starts_nothing(text: &str) -> bool {
    first_start(text).is_none() && daemon_starts(text).is_empty()
}

/// A condition of a row: every daemon the source starts in its own process has a worker program
/// that does not exist.
fn every_daemon_has_no_worker(text: &str) -> bool {
    daemon_starts(text).iter().all(|start| start.no_worker)
}

/// Where the function that holds `at` ends: at the next line that declares a function, or at the
/// end of the text.
fn next_function(text: &str, at: usize) -> usize {
    let mut position = text[at..]
        .find('\n')
        .map_or(text.len(), |newline| at + newline + 1);
    while position < text.len() {
        let end = text[position..]
            .find('\n')
            .map_or(text.len(), |newline| position + newline + 1);
        let line = text[position..end].trim_start();
        let line = line.strip_prefix("pub").map_or(line, |rest| {
            let rest = rest.trim_start();
            rest.strip_prefix('(')
                .and_then(|inside| inside.split_once(')'))
                .map_or(rest, |(_, after)| after.trim_start())
        });
        let line = line.strip_prefix("async ").unwrap_or(line);
        let line = line.strip_prefix("unsafe ").unwrap_or(line);
        if line.starts_with("fn ") {
            return position;
        }
        position = end;
    }
    text.len()
}

/// The source with its comments removed. Literals are kept, since a program is named in one.
fn without_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut kept = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        let next = chars.get(at + 1).copied();
        if c == '/' && next == Some('/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while at < chars.len() {
                if chars[at] == '/' && chars.get(at + 1) == Some(&'*') {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars.get(at + 1) == Some(&'/') {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[at] == '\n' {
                        kept.push('\n');
                    }
                    at += 1;
                }
            }
        } else if c == '"' {
            let begun = at;
            at += 1;
            while at < chars.len() && chars[at] != '"' {
                at += if chars[at] == '\\' { 2 } else { 1 };
            }
            at = (at + 1).min(chars.len());
            kept.extend(&chars[begun..at]);
        } else if c == '\'' && next == Some('\\') {
            let begun = at;
            at += 2;
            while at < chars.len() && chars[at] != '\'' {
                at += 1;
            }
            at = (at + 1).min(chars.len());
            kept.extend(&chars[begun..at]);
        } else if c == '\'' && chars.get(at + 2) == Some(&'\'') {
            kept.extend(&chars[at..at + 3]);
            at += 3;
        } else {
            kept.push(c);
            at += 1;
        }
    }
    kept
}

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if entry.is_dir() {
            if !matches!(name, "target" | "node_modules" | ".git") {
                sources(&entry, found);
            }
        } else if entry.extension().is_some_and(|extension| extension == "rs") {
            found.push(entry);
        }
    }
}

/// The workspace's root.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace")
}

/// Whether a source, by its place under the workspace, is a test source this reading covers: it
/// is in a `tests` directory, is not this reading itself, and is not a Windows source.
fn is_read(relative: &str) -> bool {
    relative.split('/').any(|part| part == "tests")
        && !relative.contains("windows")
        && relative != "crates/kr-ipc/tests/started_environment_rule.rs"
}

/// Every test source of the workspace, as its place under the root and its text with the comments
/// removed.
fn test_sources() -> Vec<(String, String)> {
    let workspace = workspace();
    let mut files = Vec::new();
    for root in ROOTS {
        sources(&workspace.join(root), &mut files);
    }
    assert!(
        files.len() > 100,
        "the reading finds the workspace's sources"
    );
    files
        .into_iter()
        .filter_map(|file| {
            let relative = file
                .strip_prefix(&workspace)
                .expect("under the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            if !is_read(&relative) {
                return None;
            }
            Some((
                relative,
                without_comments(&std::fs::read_to_string(&file).ok()?),
            ))
        })
        .collect()
}

/// The rows of a counted roster against what the sources hold: a place the roster does not count,
/// a count that is not the one found, a row whose source is gone, and a row whose condition no
/// longer holds, each as a line to print.
fn counted_faults(
    roster: &[Counted],
    sources: &[(String, String)],
    found: impl Fn(&str) -> Vec<usize>,
) -> Vec<String> {
    let mut faults = Vec::new();
    for (file, text) in sources {
        let lines = found(text);
        let row = roster.iter().find(|row| row.file == file);
        match (lines.len(), row) {
            (0, None) => {}
            (_, None) => faults.push(format!(
                "{file}: {} place(s) with no row, at line(s) {lines:?}",
                lines.len()
            )),
            (count, Some(row)) if count != row.places => faults.push(format!(
                "{file}: its row counts {} place(s) and the source has {count}, at line(s) {lines:?} \
                 (the row says: {}; removal: {})",
                row.places, row.reason, row.removal
            )),
            (_, Some(row)) if !(row.holds)(text) => faults.push(format!(
                "{file}: the condition its row rests on no longer holds ({}; removal: {})",
                row.reason, row.removal
            )),
            _ => {}
        }
    }
    for row in roster {
        if !sources.iter().any(|(file, _)| file == row.file) {
            faults.push(format!("{}: a row for a source that is not read", row.file));
        }
    }
    faults
}

#[test]
fn a_test_that_starts_a_program_gives_it_an_environment_of_its_own() {
    let sources = test_sources();
    let found: Vec<(&str, usize, String)> = sources
        .iter()
        .filter_map(|(file, text)| offence(text).map(|(line, name)| (file.as_str(), line, name)))
        .collect();
    let unkept: Vec<String> = found
        .iter()
        .filter(|(file, _, _)| !KEPT.iter().any(|row| row.file == *file))
        .map(|(file, line, name)| format!("{file}:{line}: names {name}"))
        .collect();
    assert!(
        unkept.is_empty(),
        "a program a test starts inherits the test program's environment, and a session's shell \
         reads the startup files of the home it is given, which is then the person's. Give what \
         the test starts `kr_ipc::testing::started_environment::StartedEnvironment`:\n{}",
        unkept.join("\n")
    );
    let stale: Vec<String> = KEPT
        .iter()
        .filter(|row| !found.iter().any(|(file, _, _)| *file == row.file))
        .map(|row| format!("{} ({}; removal: {})", row.file, row.reason, row.removal))
        .collect();
    assert!(
        stale.is_empty(),
        "a source listed as one that starts a program without an environment of its own no longer \
         does:\n{}",
        stale.join("\n")
    );
}

#[test]
fn every_place_that_writes_a_creators_snapshot_has_the_home_of_the_cases_own_tree() {
    let faults = counted_faults(SNAPSHOTS, &test_sources(), unnamed_snapshot_places);
    assert!(
        faults.is_empty(),
        "a session that a test's own client creates takes the creator's snapshot and nothing of the \
         daemon's, and a login shell with no `HOME` reads the account's own startup files. Write \
         `StartedEnvironment::within(<the case's tree>).snapshot_home()` into the snapshot, or give \
         the source a row in `SNAPSHOTS` that counts the places and says why no session of it can \
         read a startup file:\n{}",
        faults.join("\n")
    );
}

#[test]
fn every_daemon_a_test_starts_in_its_own_process_has_a_host_environment_or_no_worker() {
    let faults = counted_faults(DAEMON_STARTS, &test_sources(), unexcused_starts);
    assert!(
        faults.is_empty(),
        "a daemon that runs in the test's own process starts its sessions with the test program's \
         environment unless the test gives it one, and a login shell reads the startup files of the \
         home that environment names. Call `set_host_environment` with \
         `StartedEnvironment::within(<the case's tree>).host_variables()` in the function that starts \
         the daemon, or give the source a row in `DAEMON_STARTS` that counts the starts and says why \
         no session of it can read a startup file:\n{}",
        faults.join("\n")
    );
}

#[test]
fn a_source_that_keeps_the_real_environment_on_purpose_still_says_what_its_row_says() {
    let sources = test_sources();
    let faults: Vec<String> = INHERITS
        .iter()
        .filter(|row| {
            !sources
                .iter()
                .any(|(file, text)| file == row.file && text.contains(row.mark))
        })
        .map(|row| {
            format!(
                "{} no longer holds `{}` ({}; removal: {})",
                row.file, row.mark, row.reason, row.removal
            )
        })
        .collect();
    assert!(
        faults.is_empty(),
        "a source whose row says that it keeps the real environment of the test program no longer \
         holds the text the row rests on:\n{}",
        faults.join("\n")
    );
}

#[test]
fn the_reading_finds_a_start_that_gives_no_environment_however_it_is_written() {
    let named =
        |program: &str| format!("fn daemon() -> Command {{ Command::new(env!(\"{program}\")) }}");
    for program in [
        "CARGO_BIN_EXE_kr",
        "CARGO_BIN_EXE_kr-controller",
        "CARGO_BIN_EXE_kr-worker",
    ] {
        assert!(offence(&named(program)).is_some(), "{program}");
    }
    for text in [
        "let worker = directory.join(\"kr-worker\");",
        "let program = beside_this_test(\"kr-controller\");",
        "let built = support::command_binaries();",
        "let mut command = std::process::Command::new(kr());",
        "let mut command = std::process::Command::new(support::kr());",
        // A call written with white space, or over two lines, is the same call.
        "let mut command = std::process::Command::new(kr ());",
        "let mut command = std::process::Command::new(kr(\n));",
        "let built = support::command_binaries ( );",
        // The helper's name in a comment, or an environment cleared with no home, is not an
        // environment given.
        "// StartedEnvironment\nlet worker = directory.join(\"kr-worker\");",
        "let c = Command::new(kr()).env_clear().env(\"PATH\", \"/usr/bin\");",
    ] {
        assert!(offence(text).is_some(), "{text}");
    }
}

#[test]
fn the_reading_passes_a_start_that_gives_one_and_words_that_are_not_a_start() {
    for text in [
        "let environment = StartedEnvironment::within(root);\nlet worker = directory.join(\"kr-worker\");",
        "let c = Command::new(kr()).env_clear().env(\"HOME\", home);",
        // Names in a comment are not a start, and neither is the end of a longer name.
        "// directory.join(\"kr-worker\")\nlet a = 1;",
        "/* command_binaries() */ let a = 1;",
        "let a = thekr();",
        "let a = kr_other();",
        "let a = \"/*\"; let b = 2;",
    ] {
        assert!(offence(text).is_none(), "{text}");
    }
}

#[test]
fn the_snapshot_reading_finds_every_form_that_writes_one_and_only_those() {
    let code = |text: &str| without_comments(text);
    for text in [
        "let p = P { environment_snapshot: Vec::new(), palette: x };",
        "let p = P { environment_snapshot : vec![v], palette: x };",
        "request.environment_snapshot = snapshot;",
        "params[\"environment_snapshot\"] = serde_json::json!([]);",
        "let t = json!({ \"environment_snapshot\": [] });",
        "text.push_str(\",\\\"environment_snapshot\\\":[]}\");",
        "let p = P { environment_snapshot: if a { Vec::new() } else { vec![v] }, palette: x };",
    ] {
        assert_eq!(unnamed_snapshot_places(&code(text)), vec![1], "{text}");
    }
    for text in [
        // A declaration of the field's type, a pattern, a read, a modification and a list of
        // names write no snapshot.
        "struct S { environment_snapshot: Vec<EnvironmentVariable>, }",
        "let P { environment_snapshot, .. } = p;",
        "assert!(p.environment_snapshot.is_empty());",
        "p.environment_snapshot.push(v);",
        "let names = [\"environment_snapshot\", \"palette\"];",
        "// environment_snapshot: Vec::new()",
        "assert_eq!(p.environment_snapshot, q);",
    ] {
        assert!(unnamed_snapshot_places(&code(text)).is_empty(), "{text}");
    }
    for text in [
        "let p = P { environment_snapshot: StartedEnvironment::within(root).snapshot_home(), a: 1 };",
        "let p = P { environment_snapshot: vec![v].into_iter().chain(e.snapshot_home()).collect(), a: 1 };",
        "request.environment_snapshot = e.snapshot_home();",
    ] {
        let places = snapshot_places(&code(text));
        assert_eq!(places.len(), 1, "{text}");
        assert!(places[0].1, "{text}");
    }
    // The next field's text is not the value of the one before it.
    let text = "P { environment_snapshot: Vec::new(), palette: e.snapshot_home() }";
    assert_eq!(unnamed_snapshot_places(text), vec![1]);
}

#[test]
fn the_daemon_reading_finds_a_start_with_no_environment_and_a_worker_that_may_exist() {
    let setup = |worker: &str| {
        format!(
            "async fn a() {{\n let c = Controller::start(ControllerSetup {{ supervisor: s, \
             worker_program: {worker}, build_id: b }}).await;\n}}\nfn b() {{ c.set_host_environment(v); }}\n"
        )
    };
    assert_eq!(unexcused_starts(&setup("worker.clone()")), vec![2]);
    assert_eq!(
        unexcused_starts(&setup("PathBuf::from(\"/some/kr-worker\")")),
        vec![2]
    );
    // The setter of another function is not this function's.
    assert_eq!(unexcused_starts(&setup("w")).len(), 1);
    for worker in [
        "PathBuf::from(\"/nonexistent/kr-worker\")",
        "root.join(\"none\")",
        "root.join(\"no-such-worker\")",
    ] {
        assert!(unexcused_starts(&setup(worker)).is_empty(), "{worker}");
    }
    // Each of the five spellings of a start is read: with a worker that may exist and no setter it
    // is unexcused; with the setter, or with a worker that does not exist, it is excused.
    for call in [
        "Controller::start(",
        "Controller::start_on_clocks(",
        "Controller::start_on_timer(",
        "Controller::start_on_clocks_and_timer(",
        "Controller::start_on_clocks_and_timers(",
    ] {
        let start = |worker: &str, setter: &str| {
            format!(
                "async fn a() {{\n let c = {call}ControllerSetup {{ worker_program: {worker}, \
                 build_id: b }}, t).await;\n{setter}}}\n"
            )
        };
        assert_eq!(
            unexcused_starts(&start("worker.clone()", "")),
            vec![2],
            "{call}"
        );
        assert!(
            unexcused_starts(&start("worker.clone()", " c.set_host_environment(v);\n")).is_empty(),
            "{call}"
        );
        assert!(
            unexcused_starts(&start("PathBuf::from(\"/nonexistent/kr-worker\")", "")).is_empty(),
            "{call}"
        );
    }
    let given = "async fn a() {\n let c = Controller::start_on_clocks(setup).await;\n \
                 c.set_host_environment(v);\n}\n";
    assert!(unexcused_starts(given).is_empty());
    let after = "async fn a() {\n let c = Controller::start_on_clocks(setup).await;\n}\nfn b() { \
                 set_host_environment(v); }";
    assert_eq!(unexcused_starts(after), vec![2]);
}
