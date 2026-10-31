//! A test's host tree takes every job registered for it with it.
//!
//! A job its service manager keeps outlives the test that registered it, and once the tree is gone
//! the job names a program nothing can find. Each case here registers a real job through the
//! platform's own supervisor, drops the tree, and asks the service manager what it still has. The
//! job's program is the system's own, and everything it is given is inside the tree, on the
//! internal disk.
//!
//! Every job a case registers is removed again when the case ends, however it ends, so a case that
//! fails leaves nothing registered either.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod teardown;

use std::path::PathBuf;
use std::process::{Command, Stdio};

use kr_controller::supervision::{LaunchOutcome, WorkerSupervisor};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::EnvironmentId;

/// A job a case registered, removed from the service manager when the case ends, however it ends.
struct Registered(String);

impl Drop for Registered {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        for domain in ["gui", "user"] {
            let _ = Command::new("/bin/launchctl")
                .arg("bootout")
                .arg(format!(
                    "{domain}/{}/{}",
                    kr_ipc::paths::current_uid(),
                    self.0
                ))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(target_os = "linux")]
        for verb in ["stop", "reset-failed"] {
            let _ = Command::new("systemctl")
                .args(["--user", verb, &format!("{}.service", self.0)])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Whether this user's launchd still has the job `label` loaded, in either of the user's domains.
#[cfg(target_os = "macos")]
fn registered(label: &str) -> bool {
    let uid = kr_ipc::paths::current_uid();
    ["gui", "user"].into_iter().any(|domain| {
        let target = format!("{domain}/{uid}/{label}");
        let status = Command::new("/bin/launchctl")
            .arg("print")
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launchctl runs");
        // 113 is a job the domain does not have, and 112 a domain that is not there.
        match status.code() {
            Some(0) => true,
            Some(112 | 113) => false,
            _ => panic!("launchctl could not say whether {target} is loaded: {status}"),
        }
    })
}

/// Whether this user's service manager still has the unit of the job `label`.
#[cfg(target_os = "linux")]
fn registered(label: &str) -> bool {
    let unit = format!("{label}.service");
    let output = Command::new("systemctl")
        .args(["--user", "show", "--property=LoadState", "--value", &unit])
        .output()
        .expect("systemctl runs");
    assert!(
        output.status.success(),
        "the user manager could not say whether it has {unit}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim() != "not-found"
}

/// Registers a headless worker's job for `environment`, as a daemon of that environment would, and
/// returns the guard that removes it when the case ends.
///
/// Its definition is written into the environment's jobs directory and it is started in this
/// user's background domain. The program is the system's own and ends at once, which leaves the job
/// loaded with no process in it: what a worker's job is once its worker has ended.
#[cfg(target_os = "macos")]
fn register(environment: &EnvironmentPaths) -> Registered {
    use kr_controller::supervision::{LaunchdSupervisor, WorkerLaunch};
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::ids::SessionId;
    use kr_protocol::session::DisplayNumber;
    use kr_protocol::worker::ReservationId;

    assert!(
        LaunchdSupervisor::available(),
        "this user has no graphical launchd domain on this host, so no job can be registered and \
         this check cannot run"
    );
    let launch = WorkerLaunch {
        reservation_id: ReservationId::new(kr_ipc::new_uuid()),
        session_id: SessionId::new(kr_ipc::new_uuid()),
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        program: PathBuf::from("/usr/bin/true"),
        rendezvous: environment.state_dir().join("rendezvous"),
        runtime_directory: environment.runtime_dir().to_path_buf(),
        state_directory: environment.state_dir().to_path_buf(),
        jobs_directory: environment.jobs_dir(),
        working_directory: environment.state_dir().to_path_buf(),
        desktop_environment: Vec::new(),
        profile: WorkerProfile::HeadlessUser,
    };
    let job = Registered(launch.label());
    let outcome = LaunchdSupervisor::new().start(&launch);
    assert!(
        !matches!(outcome, LaunchOutcome::NotStarted { .. }),
        "the job was registered: {outcome:?}"
    );
    job
}

/// Registers a service for `environment` as a transient user unit, as a daemon of that environment
/// would, and returns the guard that removes it when the case ends.
///
/// It runs in the environment's state directory. The program is the system's own and keeps running
/// for five minutes, which keeps its unit: a unit whose process has ended is collected by itself.
#[cfg(target_os = "linux")]
fn register(environment: &EnvironmentPaths) -> Registered {
    use kr_controller::supervision::{ServiceLaunch, SystemdSupervisor};

    assert!(
        SystemdSupervisor::available(),
        "this account has no user service manager to ask, so no unit can be registered and this \
         check cannot run here"
    );
    let label = format!("kr-worker-{}", kr_ipc::new_uuid());
    let job = Registered(label.clone());
    let outcome = SystemdSupervisor::new().start_service(&ServiceLaunch {
        label,
        program: PathBuf::from("/bin/sleep"),
        arguments: vec!["300".to_owned()],
        jobs_directory: environment.jobs_dir(),
        working_directory: environment.state_dir().to_path_buf(),
    });
    assert!(
        !matches!(outcome, LaunchOutcome::NotStarted { .. }),
        "the unit was registered: {outcome:?}"
    );
    job
}

/// A job registered for the environment a tree was created with goes when the tree does.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_a_tree_goes_with_it() {
    let tree = teardown::Tree::create();
    let job = register(&tree.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    drop(tree);
    assert!(
        !registered(&job.0),
        "{} is still registered after the tree it was registered for has gone",
        job.0
    );
}

/// A job registered for another environment in the same tree goes with the tree as well: a tree
/// holds every environment in it, not only the one it was created with.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_another_environment_of_a_tree_goes_with_it() {
    let tree = teardown::Tree::create();
    let other = tree
        .paths()
        .environment(EnvironmentId::new(kr_ipc::new_uuid()));
    other.create().expect("a second environment in the tree");
    let job = register(&other);
    assert!(registered(&job.0), "{} was registered", job.0);

    drop(tree);
    assert!(
        !registered(&job.0),
        "{} is still registered after the tree it was registered for has gone",
        job.0
    );
}

/// A job the tree's test did not register is never touched: one registered for another tree stays
/// registered when this one goes, while this tree's own job goes with it.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_another_tree_is_left_alone() {
    let other = kr_ipc::testing::TempHost::create();
    let theirs = register(&other.environment());
    let tree = teardown::Tree::create();
    let ours = register(&tree.environment());
    assert!(registered(&theirs.0), "{} was registered", theirs.0);
    assert!(registered(&ours.0), "{} was registered", ours.0);

    drop(tree);
    assert!(
        registered(&theirs.0),
        "{} was taken away by a tree it was not registered for",
        theirs.0
    );
    assert!(
        !registered(&ours.0),
        "{} is still registered after the tree it was registered for has gone",
        ours.0
    );
}

/// A user manager that does not answer leaves the tree's units not established as gone, which
/// fails the test holding the tree, rather than passing for a manager with nothing to remove.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
            runner's account does not have; it runs with --ignored on a Linux host whose account \
            has one"]
fn a_manager_that_does_not_answer_leaves_the_trees_units_not_established_as_gone() {
    let tree = teardown::Tree::create();
    let job = register(&tree.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    // The system's own program that answers nothing and fails, in place of the manager's tool.
    let left = teardown::remove_units_through(
        &tree,
        std::path::Path::new("/bin/false"),
        std::time::Duration::from_secs(2),
    );
    assert!(
        left.iter().any(|what| what.contains("could not be listed")),
        "a manager that did not answer was counted as one with nothing to remove: {left:?}"
    );
    assert!(
        registered(&job.0),
        "{} went although the manager was never asked to remove it",
        job.0
    );

    // The manager that answers takes it away with the tree.
    drop(tree);
    assert!(
        !registered(&job.0),
        "{} is still registered after the tree it was registered for has gone",
        job.0
    );
}

/// A stand-in for the manager's tool, in a directory of its own: it hands each question to the real
/// `systemctl` after `before` has run in front of it, a script of the shell's own that sees the
/// question as its arguments and the directory it can keep a mark in as `$here`.
///
/// The program is placed by another process, so that this one holds no open write handle on a file
/// it then starts.
#[cfg(target_os = "linux")]
fn systemctl_after(before: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
    let source = directory.path().join("source");
    std::fs::write(
        &source,
        format!("#!/bin/sh\nhere=\"$(dirname \"$0\")\"\n{before}\nexec systemctl \"$@\"\n"),
    )
    .expect("the script is written");
    let tool = directory.path().join("systemctl");
    kr_ipc::testing::place_program(&source, &tool);
    (directory, tool)
}

/// A question to the manager that fails once, and then is answered late, as a manager busy with
/// every unit a machine's tests have started answers one, is no sign that a unit is left: it is
/// asked again and waited for, and the tree's unit goes. The first question about the units here
/// fails, and every one after it takes longer than the bound a question to a manager that answers
/// is given (`TOOL_BOUND`), so a teardown that ended a question at that bound would never be
/// answered.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
            runner's account does not have; it runs with --ignored on a Linux host whose account \
            has one"]
fn a_question_the_manager_fails_or_answers_late_is_asked_again_and_leaves_no_unit_behind() {
    let tree = teardown::Tree::create();
    let job = register(&tree.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    let (_directory, tool) = systemctl_after(
        "case \"$*\" in *list-units*) \
         if [ ! -e \"$here/failed\" ]; then : > \"$here/failed\"; exit 1; fi; \
         sleep 15;; esac",
    );
    let left = teardown::remove_units_through(&tree, &tool, std::time::Duration::from_secs(60));
    assert!(
        left.is_empty(),
        "a failed or late answer was counted as a unit left behind: {left:?}"
    );
    assert!(
        !registered(&job.0),
        "{} is still registered although the manager answered in the end",
        job.0
    );
    drop(tree);
}

/// A unit the manager still has when the tree's teardown has asked for as long as it will is left,
/// whatever the questions before it came to: asking again hides no unit. The first question about
/// the unit's state here fails, and every answer after it says the unit is loaded.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
            runner's account does not have; it runs with --ignored on a Linux host whose account \
            has one"]
fn a_unit_the_manager_goes_on_having_is_left_however_often_it_is_asked() {
    let tree = teardown::Tree::create();
    let job = register(&tree.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    let (_directory, tool) = systemctl_after(
        "case \"$*\" in *--property=LoadState*) \
         if [ ! -e \"$here/failed\" ]; then : > \"$here/failed\"; exit 1; fi; \
         echo loaded; exit 0;; esac",
    );
    let left = teardown::remove_units_through(&tree, &tool, std::time::Duration::from_secs(3));
    assert!(
        left.iter().any(|what| what.contains("is still loaded")),
        "a unit the manager still had was not counted as left: {left:?}"
    );
    drop(tree);
}

/// A user manager made of files, for the cases that need what the teardown reads from one and not a
/// manager of the machine's own: a runtime directory holding the manager's private socket and its
/// transient unit files, and a tool that answers the teardown's questions from what a case wrote
/// beside it. The tool lists the units in `listed`, answers a unit's working directory from
/// `directory-of-<unit>` (nothing where the file is not there, and a failure where `fail-asking` is),
/// records each unit it is told to stop in `stopped`, and says a unit it has stopped is gone.
#[cfg(target_os = "linux")]
struct StandInManager {
    _directory: tempfile::TempDir,
    runtime: PathBuf,
    tool: PathBuf,
    here: PathBuf,
}

#[cfg(target_os = "linux")]
impl StandInManager {
    fn new() -> Self {
        let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
        let runtime = directory.path().join("runtime");
        std::fs::create_dir_all(runtime.join("systemd/transient")).expect("the manager's files");
        std::fs::write(runtime.join("systemd/private"), "").expect("its socket's place");
        let here = directory.path().join("tool");
        std::fs::create_dir_all(&here).expect("the tool's directory");
        let source = here.join("source");
        std::fs::write(
            &source,
            r#"#!/bin/sh
here="$(dirname "$0")"
unit=""
for argument in "$@"; do unit="$argument"; done
case "$*" in
  *list-units*) cat "$here/listed" 2>/dev/null ;;
  *--property=LoadState*)
    if grep -qx "$unit" "$here/stopped" 2>/dev/null; then echo not-found; else echo loaded; fi ;;
  *--property=WorkingDirectory*)
    [ -e "$here/fail-asking" ] && exit 1
    cat "$here/directory-of-$unit" 2>/dev/null || echo ;;
  *stop*) echo "$unit" >> "$here/stopped" ;;
esac
exit 0
"#,
        )
        .expect("the tool is written");
        let tool = here.join("systemctl");
        kr_ipc::testing::place_program(&source, &tool);
        Self {
            _directory: directory,
            runtime,
            tool,
            here,
        }
    }

    /// Lists `unit` as one of the manager's.
    fn lists(&self, unit: &str) {
        use std::io::Write as _;
        let mut listed = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.here.join("listed"))
            .expect("the list");
        writeln!(listed, "{unit} loaded active running").expect("a line");
    }

    /// Gives `unit` a transient file that says it runs in `directory`, as the manager writes one.
    fn file(&self, unit: &str, directory: &std::path::Path) {
        std::fs::write(
            self.runtime.join("systemd/transient").join(unit),
            format!(
                "[Service]\nWorkingDirectory={}\n",
                directory.display().to_string().replace('%', "%%")
            ),
        )
        .expect("the unit's file");
    }

    /// Makes the manager say that `unit` runs in `directory`, whatever file it has.
    fn says_it_runs_in(&self, unit: &str, directory: &std::path::Path) {
        std::fs::write(
            self.here.join(format!("directory-of-{unit}")),
            format!("{}\n", directory.display()),
        )
        .expect("the manager's answer");
    }

    /// The units the teardown told the manager to stop.
    fn stopped(&self) -> Vec<String> {
        std::fs::read_to_string(self.here.join("stopped"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn remove_through(&self, tree: &kr_ipc::testing::TempHost) -> Vec<String> {
        teardown::remove_units_in(
            &self.runtime,
            tree,
            &self.tool,
            std::time::Duration::from_secs(5),
        )
    }
}

#[cfg(target_os = "linux")]
const A_UNIT: &str = "kr-worker-6f0c2b1e-3a4d-4c5b-8e7f-0a1b2c3d4e5f.service";

/// A unit file writes each `%` of a directory's name twice, since a single one starts a specifier,
/// and the teardown reads the directory back as it was written: a tree whose name holds a `%` is
/// still found.
#[cfg(target_os = "linux")]
#[test]
fn a_unit_that_runs_in_a_tree_whose_name_holds_a_percent_is_stopped() {
    let parent = tempfile::Builder::new()
        .prefix("p%q-")
        .tempdir()
        .expect("a directory with a percent in its name");
    let tree = kr_ipc::testing::TempHost::create_in(parent.path());
    let manager = StandInManager::new();
    manager.lists(A_UNIT);
    manager.file(A_UNIT, &tree.root().join("s"));
    let left = manager.remove_through(&tree);
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(manager.stopped(), [A_UNIT], "the unit was stopped");
}

/// A unit's file that cannot be read says nothing about where the unit runs, so the unit is not
/// established as gone and the teardown says so, instead of passing for a tree with no unit.
#[cfg(target_os = "linux")]
#[test]
fn a_unit_file_that_cannot_be_read_leaves_the_unit_not_established() {
    let tree = kr_ipc::testing::TempHost::create();
    let manager = StandInManager::new();
    manager.lists(A_UNIT);
    // A directory where the file should be: reading it fails, and not because it is missing.
    std::fs::create_dir(manager.runtime.join("systemd/transient").join(A_UNIT))
        .expect("a directory in the file's place");
    let left = manager.remove_through(&tree);
    assert!(
        left.iter().any(|what| what.contains("could not be read")),
        "{left:?}"
    );
}

/// A unit with no file that the manager still holds, running in the tree, shows that the teardown
/// looks for the files in the wrong place: the unit is stopped all the same, and the teardown says
/// where it looked, so the case that ended with units running does not pass.
#[cfg(target_os = "linux")]
#[test]
fn a_unit_in_the_tree_with_no_file_where_the_files_are_read_from_is_stopped_and_reported() {
    let tree = kr_ipc::testing::TempHost::create();
    let manager = StandInManager::new();
    manager.lists(A_UNIT);
    manager.says_it_runs_in(A_UNIT, &tree.root().join("s"));
    let left = manager.remove_through(&tree);
    assert!(
        left.iter().any(|what| what.contains("has no file in")),
        "{left:?}"
    );
    assert_eq!(manager.stopped(), [A_UNIT], "the unit was stopped");
}

/// A unit with no file is left alone when the manager no longer has it, or has it running anywhere
/// but in the tree.
#[cfg(target_os = "linux")]
#[test]
fn a_unit_with_no_file_that_is_gone_or_runs_elsewhere_is_left_alone() {
    let tree = kr_ipc::testing::TempHost::create();
    let elsewhere = kr_ipc::testing::TempHost::create();
    let manager = StandInManager::new();
    let other = "kr-plugin-host-6f0c2b1e-3a4d-4c5b-8e7f-0a1b2c3d4e5f.service";
    manager.lists(A_UNIT);
    manager.lists(other);
    manager.says_it_runs_in(other, elsewhere.root());
    let left = manager.remove_through(&tree);
    assert!(left.is_empty(), "{left:?}");
    assert!(manager.stopped().is_empty(), "{:?}", manager.stopped());
}

/// A manager that cannot say where a unit with no file runs has not shown that the unit is not the
/// tree's, so the teardown counts it as not established.
#[cfg(target_os = "linux")]
#[test]
fn a_unit_with_no_file_that_the_manager_cannot_place_is_not_established() {
    let tree = kr_ipc::testing::TempHost::create();
    let manager = StandInManager::new();
    manager.lists(A_UNIT);
    std::fs::write(manager.here.join("fail-asking"), "").expect("a mark");
    let left = manager.remove_through(&tree);
    assert!(
        left.iter().any(|what| what.contains("could not be asked")),
        "{left:?}"
    );
}
