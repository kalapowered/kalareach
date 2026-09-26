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
use std::time::{Duration, Instant};

use kr_controller::supervision::windows::{
    self as scheduled, LogonType, RegisteredTask, Standing, TaskDefinition, decode_output,
};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::testing::TempHost;
use kr_protocol::ids::EnvironmentId;
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

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

/// KR-REQ-07.12: another environment whose task shares the name cannot take it between a clear and
/// the putting back of a clear whose choice was not written. `kr` holds the name's registration
/// from the removal until the task is put back, so the other environment's registration waits,
/// finds the task put back, and is refused; the task is exactly as it was.
#[test]
fn another_environment_waiting_for_the_name_finds_the_task_put_back_after_a_failed_clear() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let name = host.definition().name;
    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));
    let before = exported(&name).expect("the environment's task");
    let theirs = TaskDefinition {
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        ..host.definition()
    };
    let _theirs = Registered(theirs.clone());

    let held = kr_protocol::hostinfo::configuration::lock(host.environment().state_dir())
        .expect("this test holds the document's lock");
    let clearing = Command::new(support::kr())
        .args(["--json", "host", "startup", "--clear"])
        .env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            host.temp.paths().runtime_root(),
        )
        .env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            host.temp.paths().state_root(),
        )
        .current_dir(installation())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("kr host startup --clear starts");
    // The clear has removed the task, holding the name's registration, and waits for the document.
    let removed = Instant::now();
    while exported(&name).is_some() {
        assert!(
            removed.elapsed() < LIVENESS_DEADLINE,
            "the clear removes the environment's task"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let registering = std::thread::spawn(move || scheduled::register(&theirs));
    let output = finish(clearing, "kr host startup --clear");
    drop(held);
    let registered = registering.join().expect("the other registration ends");
    let refused = document(&output, "a clear whose choice cannot be written");
    assert_eq!(output.status.code(), Some(2), "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .unwrap_or_default()
            .contains("is as it was"),
        "{refused}"
    );
    assert!(
        matches!(registered, Err(scheduled::TaskError::Foreign(_))),
        "the other environment waited, found the task put back and was refused: {registered:?}"
    );
    assert_eq!(
        exported(&name).as_deref(),
        Some(before.as_str()),
        "the task is exactly as it was"
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

// `kr new` through the task.

/// The switch that lets a test have the daemon the task starts keep its key in this account's own
/// credential store, which is where an installed daemon keeps it and where the person's own
/// credentials are. A run sets it only on a machine that is there to be tested.
const PLATFORM_STORE_SWITCH: &str = "KR_TEST_PLATFORM_SECRET_STORE";

/// Stops a test that would have the daemon write to this account's credential store, unless the
/// run says it may.
fn platform_store_allowed() {
    assert_eq!(
        std::env::var(PLATFORM_STORE_SWITCH).as_deref(),
        Ok("1"),
        "the daemon this test has the task start keeps its key in this account's credential store; \
         the test runs only where {PLATFORM_STORE_SWITCH}=1 says it may"
    );
}

/// A program in the system directory.
fn system32(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join(name)
}

/// PowerShell 7, the shell a session here runs.
fn powershell() -> String {
    let base = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
    let candidate = PathBuf::from(base)
        .join("PowerShell")
        .join("7")
        .join("pwsh.exe");
    assert!(
        candidate.is_file(),
        "PowerShell 7, the shell a session here runs, is not installed at {}",
        candidate.display()
    );
    candidate.display().to_string()
}

/// A process of one test's tree, as the process list describes it.
struct Listed {
    pid: u32,
    /// When it was created, as a `FILETIME`, to the microsecond the list gives.
    created: u64,
    /// Whether it is a starter the task ran, rather than a daemon or a worker.
    starter: bool,
}

/// The processes running `image` whose command line names `root`: one test's own starters, daemons
/// and workers, since every one of them is told the test's own tree.
fn listed(image: &str, root: &Path) -> Vec<Listed> {
    let script = format!(
        "Get-CimInstance Win32_Process -Filter \"Name = '{image}'\" | Where-Object {{ \
         $_.CommandLine -and $_.CommandLine.Contains('{}') }} | ForEach-Object {{ '{{0}} {{1}} \
         {{2}}' -f $_.ProcessId, $_.CreationDate.ToFileTimeUtc(), \
         [int]$_.CommandLine.Contains(' --starter ') }}",
        root.display()
    );
    let output = Command::new(system32("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("the processes are listed");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            Some(Listed {
                pid: words.next()?.parse().ok()?,
                created: words.next()?.parse().ok()?,
                starter: words.next()? == "1",
            })
        })
        .collect()
}

/// The daemons, or the workers, running `image` for `root`: the starters the task ran are not
/// counted.
fn processes(image: &str, root: &Path) -> Vec<u32> {
    listed(image, root)
        .into_iter()
        .filter(|process| !process.starter)
        .map(|process| process.pid)
        .collect()
}

/// Ends one listed process, through a handle that is checked to be the process the list described:
/// an identifier that has passed to another process since is left alone.
fn end(process: &Listed) {
    /// The Unix epoch as a `FILETIME`.
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let Ok(identity) = kr_ipc::identity::process_start_identity(process.pid) else {
        return;
    };
    // The identity counts hundreds of nanoseconds since the Unix epoch, and the list gives the
    // creation time to the microsecond.
    let listed = process.created.saturating_sub(UNIX_EPOCH_AS_FILETIME);
    if identity.start_value.get().abs_diff(listed) >= 10 {
        return;
    }
    let _ = kr_ipc::starter::end_process(&identity);
}

/// Ends what the task started for this tree when the test ends however it ends, in the order that
/// lets nothing start again behind it, and then removes the keys the daemon kept in this account's
/// credential store. Only what names this test's own tree is ended.
struct EndsWhatItStarted<'a> {
    host: &'a Host,
}

impl Drop for EndsWhatItStarted<'_> {
    fn drop(&mut self) {
        let root = self.host.temp.root();
        let environment = self.host.environment();
        // No starter runs from here on, and one already running takes nothing: the task goes, and
        // every request left for a starter is withdrawn.
        let _ = scheduled::remove(&self.host.definition());
        for request in self.host.claims().iter().filter_map(|name| {
            name.strip_suffix(".claim")
                .and_then(|request| request.parse().ok())
        }) {
            let _ = kr_ipc::starter::withdraw_claim(&environment, request);
        }
        // A starter ends once it has found nothing to take, or has started what it took.
        let settled = Instant::now();
        while listed("kr-controller.exe", root)
            .iter()
            .any(|process| process.starter)
            && settled.elapsed() < LIVENESS_DEADLINE
        {
            std::thread::sleep(Duration::from_millis(200));
        }
        // Then the daemons, which start workers, and then the workers.
        for image in ["kr-controller.exe", "kr-worker.exe"] {
            let ending = Instant::now();
            loop {
                let left = listed(image, root);
                if left.is_empty() || ending.elapsed() > LIVENESS_DEADLINE {
                    break;
                }
                left.iter().for_each(end);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        // Only now the keys: nothing that writes them is left.
        if let Ok(store) =
            kr_crypto::store::PlatformStore::open(kr_ipc::verify::CONTROLLER_SECRET_SERVICE)
        {
            // The daemon's own keys, and the keys it holds the network with, which it keeps
            // under the environment's identity followed by `/network-device`.
            let environment_id = self.host.temp.environment_id();
            for scope in [
                environment_id.to_string(),
                format!("{environment_id}/network-device"),
            ] {
                for purpose in kr_protocol::pairing::KeyPurpose::ALL {
                    if let Ok(name) = kr_crypto::store::SecretName::device_key(&scope, purpose) {
                        let _ = kr_crypto::store::SecretStore::delete(&store, &name);
                    }
                }
            }
        }
    }
}

/// Commands a test started and has not collected yet. One still here when the test ends is ended
/// and collected, so none of them runs the task behind the test's cleanup.
struct Commands(Vec<std::process::Child>);

impl Commands {
    /// Collects the next command, waiting for it as [`finish`] does.
    fn next(&mut self, what: &str) -> Output {
        finish(self.0.remove(0), what)
    }
}

impl Drop for Commands {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Host {
    /// Has the daemon the task starts for this tree, its workers and its keys go when the test ends.
    fn ends_what_it_started(&self) -> EndsWhatItStarted<'_> {
        EndsWhatItStarted { host: self }
    }

    /// `kr new` for a session of its own, run by `kr` at `program`.
    fn new_session_with(&self, program: &Path) -> Command {
        let cwd = self.temp.root().display().to_string();
        let shell = powershell();
        let mut command = Command::new(program);
        command
            .args([
                "--json",
                "new",
                "--invisible",
                "--headless",
                "--cwd",
                &cwd,
                "--shell",
                &shell,
            ])
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.temp.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.temp.paths().state_root(),
            )
            .current_dir(installation())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    /// `kr new` for a session of its own, run by this installation's `kr`.
    fn new_session(&self) -> Command {
        self.new_session_with(&support::kr())
    }

    /// The requests to start the daemon that are waiting for a starter.
    fn claims(&self) -> Vec<String> {
        std::fs::read_dir(self.environment().start_claims_dir())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// How long a command this file starts is given before the test calls it a failure.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Waits a bounded time for a command this test started, reading both of its pipes as it goes.
fn finish(mut child: std::process::Child, what: &str) -> Output {
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the command's state") {
            break status;
        }
        if started.elapsed() > LIVENESS_DEADLINE {
            let _ = child.kill();
            panic!("{what} did not finish within {LIVENESS_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: stdout.join().expect("standard output is read"),
        stderr: stderr.join().expect("standard error is read"),
    }
}

/// The build identity this test presents to a daemon.
fn build() -> kr_protocol::ids::BuildId {
    kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier")
}

/// Asks an environment's daemon one question.
fn ask<T: kr_protocol::wire::WireMessage>(
    environment: &EnvironmentPaths,
    method: kr_protocol::method::Method,
    params: &impl serde::Serialize,
) -> T {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mut client = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("reaches the daemon");
        client
            .request(method, params)
            .await
            .expect("the call reaches the daemon")
            .expect("the daemon answers")
            .to_typed()
            .expect("decodes")
    })
}

/// The sessions an environment's daemon holds and has not closed.
fn live_sessions(environment: &EnvironmentPaths) -> Vec<String> {
    let listed: kr_protocol::session::SessionListResult = ask(
        environment,
        kr_protocol::method::Method::SessionList,
        &kr_protocol::session::SessionListParams {
            environment_id: kr_protocol::scalars::Nullable::some(environment.environment_id()),
            include_closed: false,
        },
    );
    listed
        .sessions
        .iter()
        .map(|summary| summary.session_id.to_string())
        .collect()
}

/// Closes a session this test created, through the daemon that holds it.
fn close(host: &Host, session: &str) {
    let output = host.kr(&["--json", "close", session]);
    assert!(
        output.status.success(),
        "kr close {session}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// KR-REQ-07.12: with the standalone start chosen and no daemon running, three `kr new` at once
/// each leave a request for the task's starter and run the task; the starters start three daemons,
/// the environment's singleton lock leaves one, and that one serves every caller: each `kr new`
/// succeeds with a live session, and the one daemon still running holds all three, at the
/// environment's first generation. What it writes is in the environment's log. `kr doctor` then
/// reports the task as this environment's own and the one this installation registers.
#[test]
#[ignore = "the daemon the task starts keeps its key in this account's credential store; run with \
            --ignored where KR_TEST_PLATFORM_SECRET_STORE=1"]
fn three_first_invocations_at_once_leave_one_daemon_that_serves_every_caller() {
    platform_store_allowed();
    let host = Host::create();
    let _task = host.removes_its_task();
    let _started = host.ends_what_it_started();
    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));

    let mut running = Commands(
        (0..3)
            .map(|_| host.new_session().spawn().expect("kr new starts"))
            .collect(),
    );
    let outputs: Vec<Output> = (0..3)
        .map(|index| running.next(&format!("kr new {index}")))
        .collect();
    let log = host.environment().state_dir().join("controller.log");
    let mut sessions = Vec::new();
    for (index, output) in outputs.into_iter().enumerate() {
        let what = format!("kr new {index}");
        let created = document(&output, &what);
        assert!(
            output.status.success(),
            "{what} created its session: {created}; it said {}; the daemons wrote: {}",
            String::from_utf8_lossy(&output.stderr),
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        assert_eq!(created["state"], "live", "{what}: {created}");
        sessions.push(
            created["session_id"]
                .as_str()
                .expect("a session identifier")
                .to_owned(),
        );
    }

    let root = host.temp.root();
    let settled = Instant::now();
    while processes("kr-controller.exe", root).len() != 1 {
        assert!(
            settled.elapsed() < LIVENESS_DEADLINE,
            "one daemon of this environment is left running: {:?}",
            processes("kr-controller.exe", root)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let environment = host.environment();
    let info: kr_protocol::hostinfo::HostInfoResult =
        ask(&environment, kr_protocol::method::Method::HostInfo, &());
    assert_eq!(info.environment_id, host.temp.environment_id());
    assert_eq!(
        info.generation.get(),
        1,
        "the environment's generation advanced once, for the one daemon that took it"
    );
    let live = live_sessions(&environment);
    for session in &sessions {
        assert!(
            live.contains(session),
            "{session} is the one daemon's: {live:?}"
        );
    }
    let log =
        std::fs::read_to_string(environment.state_dir().join("controller.log")).unwrap_or_default();
    assert!(
        log.contains(&format!(
            "kr-controller: environment {} generation 1",
            host.temp.environment_id()
        )),
        "what the daemon writes is in the environment's log: {log}"
    );

    let doctor = host.kr(&["--json", "doctor"]);
    let report = document(&doctor, "kr doctor");
    let check = report["doctor"]["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["id"] == "startup-task"))
        .unwrap_or_else(|| panic!("kr doctor reports the task: {report}"));
    assert_eq!(check["status"], "ok", "{check}");

    for session in &sessions {
        close(&host, session);
    }
}

/// KR-REQ-07.12: a log that has grown past its limit is emptied, through the handle `kr new` checked,
/// before the task is asked for anything, and the start goes on: here the task is not registered,
/// which is the failure `kr new` gives, and the log is empty.
#[test]
fn a_log_grown_past_its_limit_is_emptied_before_the_task_is_asked() {
    let host = Host::create();
    let _task = host.removes_its_task();
    host.choose("standalone");
    let log = host.environment().state_dir().join("controller.log");
    kr_ipc::paths::write_owner_only_file(&log, &vec![b'x'; 2 * 1024 * 1024])
        .expect("a log past its limit");
    let output = finish(host.new_session().spawn().expect("kr new"), "kr new");
    let failed = document(&output, "kr new");
    assert_eq!(failed["code"], "HOST_NOT_CONFIGURED", "{failed}");
    assert!(
        failed["message"]
            .as_str()
            .unwrap_or_default()
            .contains("is not registered"),
        "{failed}"
    );
    assert_eq!(
        std::fs::metadata(&log).expect("the log").len(),
        0,
        "the log was emptied"
    );
}

/// The variable that makes the helper test below act, naming the `kr` it runs.
const HELPER: &str = "KR_STARTUP_TEST_KR";

/// Runs `kr new` once its parent has put it in the job the case needs, and reports what it did.
#[test]
#[ignore = "a helper process of the job test below, which starts it itself"]
fn a_kr_new_in_the_job_its_parent_built() {
    use std::io::BufRead as _;

    let Some(kr) = std::env::var_os(HELPER) else {
        return;
    };
    let mut word = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut word)
        .expect("the parent's word that the job is in place");
    // A parent that ended before it gave the word closes this input: nothing is run then.
    if word.trim() != "go" {
        return;
    }
    let host_root = std::env::var_os("KR_STARTUP_TEST_ROOT").expect("the tree's root");
    let shell = powershell();
    let output = Command::new(&kr)
        .args([
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &Path::new(&host_root).display().to_string(),
            "--shell",
            &shell,
        ])
        .current_dir(Path::new(&kr).parent().expect("kr's directory"))
        .output()
        .expect("kr new runs");
    println!(
        "result {} {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).replace(['\r', '\n'], " ")
    );
}

/// KR-REQ-07.12, KR-REQ-07.58: the daemon the task's starter starts is in none of the jobs of the
/// command that asked for it. `kr new` runs inside a job that ends its members when it closes; the
/// job is closed once the command has returned, and the daemon still answers and still holds the
/// session the command created.
#[test]
#[ignore = "the daemon the task starts keeps its key in this account's credential store; run with \
            --ignored where KR_TEST_PLATFORM_SECRET_STORE=1"]
fn the_daemon_the_task_starts_is_in_none_of_the_callers_jobs() {
    use std::io::{BufRead as _, Write as _};
    use std::os::windows::io::AsHandle as _;

    platform_store_allowed();
    let host = Host::create();
    let _task = host.removes_its_task();
    let _started = host.ends_what_it_started();
    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));

    let mut helper = Command::new(std::env::current_exe().expect("this test executable"))
        .args([
            "a_kr_new_in_the_job_its_parent_built",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER, support::kr())
        .env("KR_STARTUP_TEST_ROOT", host.temp.root())
        .env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            host.temp.paths().runtime_root(),
        )
        .env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            host.temp.paths().state_root(),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the helper starts");
    let job = kr_ipc::starter::Job::create(kr_ipc::starter::KILL_ON_JOB_CLOSE)
        .expect("a job that ends its members when it closes");
    job.assign(helper.as_handle())
        .expect("the helper, and the kr it runs, are in it");
    writeln!(helper.stdin.take().expect("the helper's input"), "go").expect("the word is given");
    let lines: Vec<String> = std::io::BufReader::new(helper.stdout.take().expect("its output"))
        .lines()
        .map_while(std::result::Result::ok)
        .collect();
    let status = helper.wait().expect("the helper ends");
    assert!(status.success(), "the helper ran cleanly: {lines:?}");
    let reported = lines
        .iter()
        .find_map(|line| line.find("result ").map(|at| line[at + 7..].to_owned()))
        .unwrap_or_else(|| panic!("the helper reports: {lines:?}"));
    let (code, created) = reported.split_once(' ').expect("a code and a document");
    assert_eq!(code, "0", "kr new created its session: {created}");
    let created: Value = serde_json::from_str(created.trim()).expect("kr new's document");
    let session = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .to_owned();

    drop(job);
    std::thread::sleep(Duration::from_secs(1));
    let environment = host.environment();
    assert!(
        live_sessions(&environment).contains(&session),
        "the daemon outlived the job of the command that asked for it, and holds its session"
    );
    close(&host, &session);
}

/// KR-REQ-07.12, KR-REQ-07.13: with the standalone start chosen, a task that is missing, that is not
/// this environment's own, or that an earlier installation left, and a daemon missing from beside
/// `kr`, each end `kr new` with `HOST_NOT_CONFIGURED` and what to do about it, and the task is not
/// run: no request is left for a starter, and a task that is there has not run.
#[test]
fn a_missing_foreign_or_stale_task_or_a_missing_daemon_is_named_and_nothing_is_run() {
    let host = Host::create();
    let _task = host.removes_its_task();
    host.choose("standalone");
    let name = host.definition().name;
    let refused = |output: Output, what: &str| -> String {
        let failed = document(&output, what);
        assert_eq!(output.status.code(), Some(3), "{what}: {failed}");
        assert_eq!(failed["code"], "HOST_NOT_CONFIGURED", "{what}: {failed}");
        failed["message"].as_str().unwrap_or_default().to_owned()
    };

    let missing = refused(
        finish(host.new_session().spawn().expect("kr new"), "kr new"),
        "missing",
    );
    assert!(
        missing.contains(&format!("the scheduled task {name} is not registered"))
            && missing.contains("run kr host startup --set standalone"),
        "{missing}"
    );
    assert_eq!(host.claims(), Vec::<String>::new(), "no request was left");

    let earlier = TaskDefinition {
        starter: host.temp.root().join("earlier").join("kr-controller.exe"),
        ..host.definition()
    };
    scheduled::register(&earlier).expect("the earlier installation's task");
    let stale = refused(
        finish(host.new_session().spawn().expect("kr new"), "kr new"),
        "stale",
    );
    assert!(
        stale.contains("is not the one this installation registers")
            && stale.contains("it runs another program than this installation's kr-controller")
            && stale.contains("run kr host startup --set standalone to repair it"),
        "{stale}"
    );
    assert_eq!(host.claims(), Vec::<String>::new(), "no request was left");
    assert_eq!(
        scheduled::last_result(&earlier).expect("the task is read"),
        scheduled::LastResult::NotRun,
        "and the task was not run"
    );
    scheduled::remove(&earlier).expect("the earlier task is removed");

    let theirs = TaskDefinition {
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        ..host.definition()
    };
    let _theirs = Registered(theirs.clone());
    scheduled::register(&theirs).expect("the other environment's task");
    let before = exported(&name).expect("the other environment's task is there");
    let foreign = refused(
        finish(host.new_session().spawn().expect("kr new"), "kr new"),
        "foreign",
    );
    assert!(
        foreign.contains("is not this environment's own")
            && foreign.contains("kr neither replaces nor removes it"),
        "{foreign}"
    );
    assert_eq!(host.claims(), Vec::<String>::new(), "no request was left");
    assert_eq!(
        exported(&name).as_deref(),
        Some(before.as_str()),
        "and it is as it was"
    );
    drop(_theirs);

    let lonely = host.temp.root().join("lonely");
    std::fs::create_dir_all(&lonely).expect("an installation with no daemon beside kr");
    let lonely_kr = lonely.join("kr.exe");
    kr_ipc::testing::place_program(&support::kr(), &lonely_kr);
    let gone = refused(
        finish(
            host.new_session_with(&lonely_kr).spawn().expect("kr new"),
            "kr new",
        ),
        "no daemon",
    );
    assert!(gone.contains("and there is none there"), "{gone}");
    assert_eq!(host.claims(), Vec::<String>::new(), "no request was left");
}

impl Host {
    /// An installation of this test's own: `kr`, with a program under the daemon's name beside it
    /// that is not a daemon, the system's `whoami`, which ends at once whatever it is given. The
    /// task registered for it starts nothing, whatever `kr new` does.
    fn installation_without_a_daemon(&self) -> PathBuf {
        let directory = self.temp.root().join("installed");
        std::fs::create_dir_all(&directory).expect("an installation of this test's own");
        kr_ipc::testing::place_program(&support::kr(), &directory.join("kr.exe"));
        kr_ipc::testing::place_program(
            &system32("whoami.exe"),
            &directory.join("kr-controller.exe"),
        );
        directory
    }

    /// Runs the `kr` of `installed` with `arguments` against this tree.
    fn kr_from(&self, installed: &Path, arguments: &[&str]) -> Output {
        Command::new(installed.join("kr.exe"))
            .args(arguments)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.temp.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.temp.paths().state_root(),
            )
            .current_dir(installed)
            .output()
            .expect("kr runs")
    }

    /// The requests left for this environment's starter, as they were written.
    fn requests(&self) -> Vec<kr_ipc::starter::StartClaim> {
        let directory = self.environment().start_claims_dir();
        self.claims()
            .iter()
            .filter(|name| name.ends_with(".claim"))
            .map(|name| {
                let bytes = std::fs::read(directory.join(name)).expect("the request is read");
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .expect("the request decodes")
            })
            .collect()
    }
}

/// A Task Scheduler of this test's own under `root`: it writes each call it is given to `calls`,
/// refuses every run, and answers every other call by running the real one, whose answer it passes
/// on byte for byte. Returns the `SystemRoot` that names it. It is compiled with the .NET
/// Framework's own C# compiler, which every supported Windows has.
fn refusing_task_scheduler(root: &Path, calls: &Path) -> PathBuf {
    let system_root = root.join("system-root");
    let system32 = system_root.join("System32");
    std::fs::create_dir_all(&system32).expect("a system directory of this test's own");
    let real_root = PathBuf::from(std::env::var_os("SystemRoot").expect("the system's root"));
    let source = root.join("refusing.cs");
    std::fs::write(
        &source,
        format!(
            r#"class Refusing {{
    static int Main(string[] words) {{
        System.IO.File.AppendAllText(@"{calls}", "schtasks " + string.Join(" ", words) + "\n");
        if (System.Array.IndexOf(words, "/Run") >= 0) {{
            return 1;
        }}
        var start = new System.Diagnostics.ProcessStartInfo(@"{real}");
        start.Arguments = string.Join(" ", System.Array.ConvertAll(words, word => "\"" + word + "\""));
        start.UseShellExecute = false;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.EnvironmentVariables["SystemRoot"] = @"{real_root}";
        using (var run = System.Diagnostics.Process.Start(start)) {{
            var error = System.Console.OpenStandardError();
            var said = System.Threading.Tasks.Task.Run(() => run.StandardError.BaseStream.CopyTo(error));
            var output = System.Console.OpenStandardOutput();
            run.StandardOutput.BaseStream.CopyTo(output);
            said.Wait();
            run.WaitForExit();
            output.Flush();
            error.Flush();
            return run.ExitCode;
        }}
    }}
}}"#,
            calls = calls.display(),
            real = schtasks().display(),
            real_root = real_root.display()
        ),
    )
    .expect("the Task Scheduler's source");
    let compiler = PathBuf::from(std::env::var_os("WINDIR").expect("the Windows directory"))
        .join("Microsoft.NET")
        .join("Framework64")
        .join("v4.0.30319")
        .join("csc.exe");
    let compiled = Command::new(&compiler)
        .arg("/nologo")
        .arg(format!("/out:{}", system32.join("schtasks.exe").display()))
        .arg(&source)
        .output()
        .unwrap_or_else(|error| panic!("the C# compiler at {} runs: {error}", compiler.display()));
    assert!(
        compiled.status.success(),
        "the Task Scheduler of this test's own is compiled: {}",
        String::from_utf8_lossy(&compiled.stdout)
    );
    system_root
}

/// KR-REQ-07.12: `kr new` has one deadline. However long it waited for the environment's lock, the
/// request it leaves for the task's starter lapses no later than it stops waiting, and it is
/// withdrawn before `kr new` says why no daemon answered, so none can be started for it once the
/// command has given up. The task here runs a program that is not a daemon, so none is.
#[test]
fn a_request_lapses_when_kr_new_stops_waiting_however_long_the_lock_held_it() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let installed = host.installation_without_a_daemon();
    let chose = host.kr_from(
        &installed,
        &["--json", "host", "startup", "--set", "standalone"],
    );
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(
            host.environment()
                .state_dir()
                .join(kr_cli::service_manager::LOCK_FILE),
        )
        .expect("the environment's lock");
    lock.lock().expect("held by this test");
    let started = host
        .new_session_with(&installed.join("kr.exe"))
        .spawn()
        .expect("kr new starts");
    std::thread::sleep(Duration::from_secs(20));
    lock.unlock().expect("let go");
    let output = finish(started, "kr new");
    let stopped = kr_ipc::clock::boot_elapsed_ms();
    let failed = document(&output, "kr new");
    assert_eq!(output.status.code(), Some(1), "{failed}");
    assert_eq!(failed["code"], "ENVIRONMENT_UNAVAILABLE", "{failed}");
    let message = failed["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("its starter did not take the request")
            && message.contains("so the request was withdrawn and no daemon was started for it"),
        "{message}"
    );
    let requests = host.requests();
    assert_eq!(
        requests.len(),
        1,
        "one request was left: {:?}",
        host.claims()
    );
    assert!(
        requests[0].deadline_boot_ms <= stopped,
        "the request lapsed by the time kr new stopped waiting: it lapses at {} and kr new had \
         stopped by {stopped}",
        requests[0].deadline_boot_ms
    );
    assert!(
        host.claims()
            .contains(&format!("{}.taken", requests[0].request)),
        "and it was withdrawn: {:?}",
        host.claims()
    );
}

/// KR-REQ-07.12: a run the Task Scheduler does not make has the request `kr new` left withdrawn at
/// once, so no starter can take it and no daemon is started for it, and the failure says so in
/// kr's own words. The Task Scheduler this test puts under a `SystemRoot` of its own answers every
/// look at the task as the real one does and refuses every run; the task runs a program that is not
/// a daemon.
#[test]
fn a_run_the_task_scheduler_refuses_has_its_request_withdrawn_at_once() {
    let host = Host::create();
    let _task = host.removes_its_task();
    let installed = host.installation_without_a_daemon();
    let chose = host.kr_from(
        &installed,
        &["--json", "host", "startup", "--set", "standalone"],
    );
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));
    let calls = host.temp.root().join("calls.txt");
    let system_root = refusing_task_scheduler(&host.temp.root().join("refusing"), &calls);
    let started = Instant::now();
    let output = finish(
        host.new_session_with(&installed.join("kr.exe"))
            .env("SystemRoot", &system_root)
            .spawn()
            .expect("kr new"),
        "kr new",
    );
    let failed = document(&output, "kr new");
    assert_eq!(output.status.code(), Some(1), "{failed}");
    assert_eq!(failed["code"], "ENVIRONMENT_UNAVAILABLE", "{failed}");
    let message = failed["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("the Task Scheduler did not run the scheduled task")
            && message.contains(
                "the request this command left for its starter was withdrawn, so no control \
                 daemon was started for it"
            ),
        "{message}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "at once, not after the wait: {:?}",
        started.elapsed()
    );
    let asked = std::fs::read_to_string(&calls).unwrap_or_default();
    assert!(asked.contains("/Run"), "the run was asked for: {asked}");
    let boot = kr_ipc::identity::boot_identity().expect("this boot");
    assert!(
        kr_ipc::starter::take_claim(&host.environment(), &boot, kr_ipc::clock::boot_elapsed_ms())
            .expect("the requests are read")
            .is_none(),
        "no starter can take the request: {:?}",
        host.claims()
    );
}

/// KR-REQ-07.12: a task the Task Scheduler does not start, as it starts none that logs on where the
/// user is signed in while the user is signed in nowhere, ends `kr new` once it has waited its
/// bound, with a failure of its own naming where the user has to be signed in; no daemon is
/// started.
#[test]
#[ignore = "it needs an account signed in to no session, which the native run arranges, and the \
            daemon would keep its key in this account's credential store were one started; run with \
            --ignored where KR_TEST_PLATFORM_SECRET_STORE=1"]
fn a_task_the_task_scheduler_does_not_start_is_named_with_where_to_sign_in() {
    platform_store_allowed();
    let host = Host::create();
    let _task = host.removes_its_task();
    let _started = host.ends_what_it_started();
    let chose = host.kr(&["--json", "host", "startup", "--set", "standalone"]);
    assert!(chose.status.success(), "{}", document(&chose, "the choice"));
    let output = finish(host.new_session().spawn().expect("kr new"), "kr new");
    let failed = document(&output, "kr new");
    assert_eq!(output.status.code(), Some(1), "{failed}");
    assert_eq!(failed["code"], "ENVIRONMENT_UNAVAILABLE");
    let message = failed["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("its starter did not take the request to start the control daemon")
            && message.contains("only in a session where you are signed in")
            && message.contains("sign in to this computer"),
        "{message}"
    );
    assert!(
        processes("kr-controller.exe", host.temp.root()).is_empty(),
        "no daemon was started"
    );
}

/// A daemon this test hosts for its own tree, starting each worker through the environment's task
/// as the test helper registered it: with the logon this session allows, `S4U` in session 0, where
/// the task's starter leaves the worker in no job, and `InteractiveToken` where the user is signed
/// in, where it leaves the worker in the task's own job. Its keys are in the tree's own directory.
struct Hosted {
    runtime: tokio::runtime::Runtime,
    controller: Option<std::sync::Arc<kr_controller::service::Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

impl Hosted {
    fn start(
        environment: &EnvironmentPaths,
        supervisor: Box<dyn kr_controller::supervision::WorkerSupervisor>,
    ) -> Self {
        use kr_controller::service::{Controller, ControllerSetup};

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime");
        let environment_id = environment.environment_id();
        let secrets = environment.secrets_dir();
        let setup = ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = kr_crypto::store::open_store_in(&secrets).expect("a secret store");
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    store.store.as_ref(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor,
            worker_program: installation().join("kr-worker.exe"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        };
        let (controller, serving) = runtime.block_on(async {
            let controller = Controller::start(setup).await.expect("the daemon starts");
            let rendezvous = kr_ipc::endpoint::Listener::bind(
                &environment.rendezvous_endpoint().expect("an endpoint"),
            )
            .expect("binds the rendezvous");
            let clients = kr_ipc::endpoint::Listener::bind(
                &environment.controller_endpoint().expect("an endpoint"),
            )
            .expect("binds the client endpoint");
            let serving = vec![
                tokio::spawn(std::sync::Arc::clone(&controller).serve_rendezvous(rendezvous)),
                tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(clients)),
            ];
            (controller, serving)
        });
        Self {
            runtime,
            controller: Some(controller),
            serving,
        }
    }
}

impl Drop for Hosted {
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
        let controller = self.controller.take();
        self.runtime.block_on(async move {
            drop(controller);
        });
    }
}

/// KR-REQ-07.12, KR-REQ-07.69: `kr host startup --clear` removes the environment's task and leaves
/// a worker that task's starter started running, and its session live: removing a task ends nothing
/// it started. The worker is in no job where the task logs on without a session (`S4U`), and in the
/// task's own job where it logs on as the signed-in user (`InteractiveToken`); the run says which.
#[test]
fn clearing_the_start_leaves_a_worker_the_environments_task_started_running() {
    use kr_controller::supervision::windows::testing::{TestTask, built_binary};

    let tree = teardown::Tree::create();
    let environment = tree.environment();
    let starter = built_binary("kr-controller").unwrap_or_else(|missing| panic!("{missing}"));
    let task = TestTask::register(&environment, &starter)
        .unwrap_or_else(|failure| panic!("the environment's task: {failure}"));
    let logon = task.definition().logon;
    let daemon = Hosted::start(
        &environment,
        tree.supervisor(Box::new(task.supervisor(&environment))),
    );
    let kr = |arguments: &[&str]| {
        Command::new(support::kr())
            .args(arguments)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                tree.paths().runtime_root(),
            )
            .env(kr_ipc::paths::STATE_DIR_VARIABLE, tree.paths().state_root())
            .current_dir(installation())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("kr starts")
    };
    let cwd = tree.root().display().to_string();
    let shell = powershell();
    let output = finish(
        kr(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            &shell,
        ]),
        "kr new",
    );
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let session = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .to_owned();
    let worker = kr_ipc::descriptor::read_all(&environment)
        .expect("the descriptors")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id.to_string() == session)
        .expect("the session's worker published itself")
        .process_start_identity;
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running
    );

    let output = finish(
        kr(&["--json", "host", "startup", "--clear"]),
        "kr host startup --clear",
    );
    let cleared = document(&output, "kr host startup --clear");
    assert!(output.status.success(), "{cleared}");
    assert_eq!(cleared["task_change"]["change"], "removed", "{cleared}");
    assert_eq!(
        scheduled::standing(task.definition()).expect("the task is read"),
        Standing::Absent
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "a worker the task started, as {}, keeps running once the task is removed",
        logon.as_str()
    );
    assert!(
        live_sessions(&environment).contains(&session),
        "and its session is live"
    );
    let output = finish(kr(&["--json", "close", &session]), "kr close");
    assert!(output.status.success(), "{}", document(&output, "kr close"));
    drop(daemon);
    println!(
        "the worker the task started, as {}, outlived the task",
        logon.as_str()
    );
}
