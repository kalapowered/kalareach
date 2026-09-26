//! `kr host startup` and `kr new` on Windows, where the standalone start is this user's scheduled
//! task for the environment.
//!
//! The Unix twin of these cases is `crates/kr-cli/tests/startup.rs`. On this platform the setup step
//! registers the environment's task, `KalaReach-` and the first eight digits of its identifier, and
//! `kr new` asks the Task Scheduler to run it; the task's starter starts the daemon, so no process
//! of the command's own is the daemon's creator. These run the real `kr` against the real Task
//! Scheduler, with the daemon and the worker the workspace built placed beside `kr` on the internal
//! disk, and each test on a host tree of its own, so each has an environment, and a task name, of
//! its own. Every task a test registers, or has `kr` register, is removed when the test ends, and
//! only while it is still that environment's own.
//!
//! What these establish. KR-REQ-07.12: `kr host startup --set standalone` registers the task to log
//! on where the user is signed in, repairs the environment's own task when an earlier installation
//! left it stale, refuses a task under the name that is not the environment's own with nothing
//! changed, and writes the choice after the task; a choice that cannot be written leaves the task
//! and the choice exactly as they were. `--clear` removes only the environment's own task and
//! reports one it left. `kr host startup` reports whose the task is, whether it is the one this
//! installation registers, and whether a start can use it, apart. KR-REQ-07.13: nothing is
//! registered but by that explicit step.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use kr_controller::supervision::windows::{
    self as scheduled, LogonType, RegisteredTask, Standing, TaskDefinition, decode_output,
};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::testing::TempHost;
use kr_protocol::ids::EnvironmentId;
use serde_json::Value;

mod support;

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}.exe"));
    candidate.is_file().then_some(candidate)
}

/// The installation these tests run: `kr` with the daemon and the worker beside it, on the internal
/// disk, as a package lays them out. The daemon is found there by `kr` and registered as the task's
/// program.
fn installation() -> &'static Path {
    static PLACED: OnceLock<PathBuf> = OnceLock::new();
    PLACED.get_or_init(|| {
        let directory = support::command_binaries().to_path_buf();
        for name in ["kr-controller", "kr-worker"] {
            let built = beside_this_test(name).unwrap_or_else(|| {
                panic!(
                    "{name} is not built beside this test, so this check cannot run; build it with \
                     `cargo build -p {name}` first"
                )
            });
            kr_ipc::testing::place_and_start_once(
                &built,
                &directory.join(format!("{name}.exe")),
                &["--version"],
            );
        }
        directory
    })
}

/// The Task Scheduler's command, from the system directory.
fn schtasks() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("schtasks.exe")
}

/// The task named `name` as the Task Scheduler exports it, when there is one this user can read.
fn exported(name: &str) -> Option<String> {
    let output = Command::new(schtasks())
        .args(["/Query", "/TN", name, "/XML"])
        .output()
        .expect("the Task Scheduler is asked");
    output
        .status
        .success()
        .then(|| decode_output(&output.stdout))
}

/// Removes a task a test registered, however the test ends, and only while it is its environment's
/// own.
struct Registered(TaskDefinition);

impl Drop for Registered {
    fn drop(&mut self) {
        let _ = scheduled::remove(&self.0);
    }
}

/// A host tree of one test's own, and the `kr` that runs against it.
struct Host {
    temp: TempHost,
}

impl Host {
    fn create() -> Self {
        Self {
            temp: TempHost::create(),
        }
    }

    fn environment(&self) -> EnvironmentPaths {
        self.temp.environment()
    }

    /// The task the setup step registers for this environment: this user's, logging on where the
    /// user is signed in, and running the installation's daemon.
    fn definition(&self) -> TaskDefinition {
        TaskDefinition::for_setup(
            kr_ipc::starter::current_user_sid().expect("this account"),
            &self.environment(),
            &installation().join("kr-controller.exe"),
        )
    }

    /// Removes this environment's own task when the test ends, whoever registered it.
    fn removes_its_task(&self) -> Registered {
        Registered(self.definition())
    }

    /// The environment's configuration document.
    fn document(&self) -> PathBuf {
        kr_cli::doctor::configuration::document_path(&self.environment())
    }

    /// Chooses `controller` in the environment's document, as a person's earlier edit left it.
    fn choose(&self, controller: &str) {
        kr_ipc::paths::write_owner_only_file(
            &self.document(),
            format!(
                "{{\"version\": 1, \"revision\": 1, \"startup\": {{\"controller\": \"{controller}\"}}}}"
            )
            .as_bytes(),
        )
        .expect("the document chooses a start");
    }

    /// Runs `kr` with `arguments` against this tree, from the installation's directory.
    fn kr(&self, arguments: &[&str]) -> Output {
        Command::new(support::kr())
            .args(arguments)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.temp.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.temp.paths().state_root(),
            )
            .current_dir(installation())
            .output()
            .expect("kr runs")
    }
}

/// The JSON document a command wrote on its standard output.
fn document(output: &Output, what: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{what} writes a JSON document ({error}); it wrote {} and said {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// KR-REQ-07.12, KR-REQ-07.69: choosing the standalone start registers the environment's task, this
/// user's, logging on where the user is signed in, running this installation's daemon; the choice is
/// then written, and choosing it again changes nothing. KR-REQ-07.13: before the choice nothing is
/// registered.
#[test]
fn choosing_the_standalone_start_registers_the_task_where_the_user_is_signed_in() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let name = host.definition().name;
    assert_eq!(
        exported(&name),
        None,
        "nothing is registered before the choice"
    );

    let output = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    let chosen = document(&output, "kr host startup --set standalone");
    assert!(output.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone");
    assert_eq!(chosen["task_change"]["change"], "registered");
    assert_eq!(chosen["startup"]["task"]["name"], name.as_str());
    assert_eq!(chosen["startup"]["task"]["ownership"], "own");
    assert_eq!(chosen["startup"]["task"]["valid"], true);
    assert_eq!(chosen["startup"]["task"]["program_present"], true);
    assert_eq!(chosen["startup"]["task"]["ends_at_sign_out"], true);
    assert_eq!(
        scheduled::standing(&host.definition()).expect("the task is read"),
        Standing::Owned(Vec::new()),
        "the task is this environment's own and the one this installation registers"
    );
    let registered = RegisteredTask::parse(&exported(&name).expect("the task is there"));
    assert_eq!(registered.logon, Some(LogonType::InteractiveToken));

    let again = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    let chosen_again = document(&again, "choosing it again");
    assert!(again.status.success(), "{chosen_again}");
    assert_eq!(chosen_again["task_change"]["change"], "unchanged");
}

/// KR-REQ-07.12: a task under the environment's name that is not its own, here another
/// environment's whose identity shares the prefix, is refused with nothing changed: the task is
/// exactly as it was, and no choice is written.
#[test]
fn a_task_under_the_name_that_is_not_the_environments_is_refused_and_nothing_changes() {
    let host = Host::create();
    let theirs = TaskDefinition {
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        ..host.definition()
    };
    let _theirs = Registered(theirs.clone());
    // Removes the task a refusal that wrongly took the name would leave, which is this
    // environment's, so a broken copy of the refusal leaves nothing behind either.
    let _ours = host.removes_its_task();
    scheduled::register(&theirs).expect("the other environment's task");
    let before = exported(&theirs.name).expect("the other environment's task is there");

    let output = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    let refused = document(&output, "kr host startup --set standalone");
    assert_eq!(output.status.code(), Some(2), "{refused}");
    assert_eq!(refused["code"], "INVALID_ARGUMENT");
    let message = refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("is not this environment's own")
            && message.contains("it belongs to another environment")
            && message.contains("nothing was changed"),
        "{message}"
    );
    assert_eq!(
        exported(&theirs.name).as_deref(),
        Some(before.as_str()),
        "the other environment's task is exactly as it was"
    );
    assert!(!host.document().exists(), "and no choice was written");
}

/// KR-REQ-07.12: the environment's own task, left by an installation that has since moved, is
/// registered again as this installation registers it.
#[test]
fn the_environments_own_task_from_an_earlier_installation_is_repaired() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let earlier = TaskDefinition {
        starter: host.temp.root().join("earlier").join("kr-controller.exe"),
        ..host.definition()
    };
    scheduled::register(&earlier).expect("the earlier installation's task");
    let Standing::Owned(differences) =
        scheduled::standing(&host.definition()).expect("the task is read")
    else {
        panic!("the earlier installation's task is this environment's own");
    };
    assert_eq!(differences.len(), 1, "its program differs: {differences:?}");

    let output = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    let chosen = document(&output, "kr host startup --set standalone");
    assert!(output.status.success(), "{chosen}");
    assert_eq!(chosen["task_change"]["change"], "repaired");
    assert_eq!(
        scheduled::standing(&host.definition()).expect("the task is read"),
        Standing::Owned(Vec::new()),
        "the task is now this installation's"
    );
}

/// KR-REQ-07.12: a choice that cannot be written, because another writer holds the document, leaves
/// the task and the choice exactly as they were: a task an earlier installation left valid for
/// itself, repaired on the way, is put back as it was, and the earlier choice is untouched; a task
/// registered on the way where there was none is removed again; and a task `--clear` removed on the
/// way is registered again as it was.
#[test]
fn a_choice_that_cannot_be_written_leaves_the_task_and_the_choice_as_they_were() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let name = host.definition().name;

    // Nothing registered, and nothing chosen.
    let held = kr_protocol::hostinfo::configuration::lock(host.environment().state_dir())
        .expect("this test holds the document's lock");
    let output = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    drop(held);
    let refused = document(&output, "a choice that cannot be written");
    assert!(!output.status.success(), "{refused}");
    let message = refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("is as it was") && message.contains("startup.controller is as it was"),
        "{message}"
    );
    assert_eq!(
        exported(&name),
        None,
        "the task registered on the way was removed"
    );
    assert!(!host.document().exists(), "and nothing was chosen");

    // A task an earlier installation left, valid for it, and a choice already written.
    host.choose("standalone");
    let earlier = TaskDefinition {
        starter: host.temp.root().join("earlier").join("kr-controller.exe"),
        ..host.definition()
    };
    scheduled::register(&earlier).expect("the earlier installation's task");
    let task_before = exported(&name).expect("the earlier task");
    let choice_before = std::fs::read(host.document()).expect("the document");
    let held = kr_protocol::hostinfo::configuration::lock(host.environment().state_dir())
        .expect("this test holds the document's lock");
    let output = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    drop(held);
    let refused = document(&output, "a repair whose choice cannot be written");
    assert!(!output.status.success(), "{refused}");
    assert_eq!(
        exported(&name).as_deref(),
        Some(task_before.as_str()),
        "the repaired task is put back exactly as it was"
    );
    assert_eq!(
        std::fs::read(host.document()).expect("the document"),
        choice_before,
        "and the choice is exactly as it was"
    );

    // A task that `--clear` removes on the way.
    let held = kr_protocol::hostinfo::configuration::lock(host.environment().state_dir())
        .expect("this test holds the document's lock");
    let output = host.kr(&["--json", "host", "startup", "--clear"]);
    drop(held);
    let refused = document(&output, "a clear whose choice cannot be written");
    assert!(!output.status.success(), "{refused}");
    assert_eq!(
        exported(&name).as_deref(),
        Some(task_before.as_str()),
        "the removed task is registered again exactly as it was"
    );
    assert_eq!(
        std::fs::read(host.document()).expect("the document"),
        choice_before
    );
}

/// KR-REQ-07.12, KR-REQ-07.13: `--clear` removes the environment's own task and the choice; a task
/// under the name that is not the environment's own is reported and left, and the choice is
/// cleared all the same.
#[test]
fn clearing_removes_only_the_environments_own_task_and_reports_one_it_left() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let name = host.definition().name;
    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));

    let output = host.kr(&["--json", "host", "startup", "--clear"]);
    let cleared = document(&output, "kr host startup --clear");
    assert!(output.status.success(), "{cleared}");
    assert_eq!(cleared["task_change"]["change"], "removed");
    assert_eq!(cleared["task_change"]["left"], false);
    assert_eq!(cleared["startup"]["controller"], Value::Null);
    assert_eq!(exported(&name), None, "the task is gone");

    let theirs = TaskDefinition {
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        ..host.definition()
    };
    let _theirs = Registered(theirs.clone());
    scheduled::register(&theirs).expect("the other environment's task");
    let before = exported(&name).expect("the other environment's task is there");
    host.choose("standalone");
    let output = host.kr(&["host", "startup", "--clear"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains(&format!("left {name}")) && said.contains("is not this environment's own"),
        "the task it left is reported: {said}"
    );
    assert_eq!(
        exported(&name).as_deref(),
        Some(before.as_str()),
        "and left exactly as it was"
    );
    let report = document(&host.kr(&["--json", "host", "startup"]), "kr host startup");
    assert_eq!(
        report["startup"]["controller"],
        Value::Null,
        "the choice is cleared"
    );
}

/// KR-REQ-07.12: `kr host startup` reports whose the environment's task is, whether it is the one
/// this installation registers, and whether a start can use it now, apart, with the last result as
/// one for all of the task's runs and that the daemon ends when the user signs out.
#[test]
fn the_report_says_whose_the_task_is_whether_it_is_valid_and_whether_a_start_can_use_it() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let name = host.definition().name;
    host.choose("standalone");

    let absent = document(&host.kr(&["--json", "host", "startup"]), "kr host startup");
    assert_eq!(absent["startup"]["task"]["ownership"], "absent");
    assert_eq!(absent["startup"]["task"]["valid"], Value::Null);

    let earlier = TaskDefinition {
        starter: host.temp.root().join("earlier").join("kr-controller.exe"),
        ..host.definition()
    };
    scheduled::register(&earlier).expect("the earlier installation's task");
    let stale = document(&host.kr(&["--json", "host", "startup"]), "kr host startup");
    assert_eq!(stale["startup"]["task"]["ownership"], "own");
    assert_eq!(stale["startup"]["task"]["valid"], false);
    assert_eq!(
        stale["startup"]["task"]["differences"],
        serde_json::json!(["it runs another program than this installation's kr-controller"])
    );
    assert_eq!(stale["startup"]["task"]["last_result"], "not_run");

    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));
    let session = kr_ipc::starter::current_session().expect("this session");
    let usable = document(&host.kr(&["--json", "host", "startup"]), "kr host startup");
    let task = &usable["startup"]["task"];
    assert_eq!(task["ownership"], "own");
    assert_eq!(task["valid"], true);
    assert_eq!(task["session"], session);
    assert_eq!(task["interactive"], session != 0);

    let said = String::from_utf8_lossy(&host.kr(&["host", "startup"]).stdout).into_owned();
    for part in [
        "startup: standalone",
        &format!("the scheduled task {name} is this environment's own"),
        "it is the one this installation registers",
        "for all of its runs",
        "signing out ends it and every session",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
}

/// KR-REQ-07.12: the service start is Unix's; on this platform choosing it is refused with the
/// standalone start named, and nothing is registered or written.
#[test]
fn the_service_start_is_refused_here_with_the_standalone_start_named() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let output = host.kr(&["--json", "host", "startup", "--set", "service"]);
    let refused = document(&output, "kr host startup --set service");
    assert_eq!(output.status.code(), Some(2), "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .unwrap_or_default()
            .contains("kr host startup --set standalone"),
        "{refused}"
    );
    assert_eq!(exported(&host.definition().name), None);
    assert!(!host.document().exists());
}
