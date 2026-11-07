//! A real sign-out ends a `desktop_bound` session, and the session closes with `desktop_lost`.
//!
//! `crates/kr-worker/tests/desktop.rs` ends a login in its harness by binding a session to a
//! desktop no host is in. This ends one on the machine: the first half runs a daemon in a login
//! session, makes a `desktop_bound` session in it and signs the account out; the second half runs in
//! the account's next sign-in, and a daemon started on the first one's state reads what became of
//! the session.
//!
//! Both halves run as a temporary standard account that a run signs in over remote desktop, twice,
//! and removes afterwards; the first one signs the account that runs it out, so it refuses to run
//! unless `KR_ALLOW_SIGN_OUT=1` says that account is disposable, and never as an administrator.
//!
//! What the pair shows is what the system does on this machine for one sign-out and one sign-in: the
//! host reads a login from the logon time the system records for its session, and the guide states
//! that the host does not establish that the system gives a fresh logon time to every sign-in. It
//! does not replace a per-user agent inside the session.

#![cfg(windows)]

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use kr_protocol::identity::{DesktopBinding, ProcessStartIdentity};
use kr_protocol::ids::SessionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{SessionListParams, SessionListResult, SessionSummary};
use kr_worker::desktop::{Presence, recorded_presence};

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use windows_session::{LIVENESS_DEADLINE, Prepared};

/// The switch that says a case may sign the account that runs it out, which is for an account that
/// is disposable.
const SIGN_OUT_SWITCH: &str = "KR_ALLOW_SIGN_OUT";

/// Why the case that signs the account out is ignored in an ordinary run.
macro_rules! signs_out {
    () => {
        "signs the account that runs it out; it runs with --ignored and KR_ALLOW_SIGN_OUT=1 where \
         the account is disposable and a run signs it in again for the case that follows"
    };
}

/// Why the case that follows the sign-out is ignored in an ordinary run.
macro_rules! follows_a_sign_out {
    () => {
        "reads what the case that signs the account out left, in the account's next sign-in; it runs \
         with --ignored after that case, as a run that signs the account in again arranges"
    };
}

/// Why the case that registers a task is ignored in an ordinary run.
macro_rules! registers_a_task {
    () => {
        "registers a scheduled task of the account that runs it for a moment; it runs with --ignored \
         by hand"
    };
}

/// The system directory's own copy of a program, which no search path can stand in for.
fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join(program)
}

/// Where the first half leaves what the second reads: in the account's own temporary directory,
/// which a sign-out keeps.
fn record_path() -> PathBuf {
    std::env::temp_dir().join("kr-desktop-sign-out-record.json")
}

/// Whether a `whoami /groups /fo csv /nh` listing names an integrity level, which it does by the
/// level's SID, a field that begins `S-1-16-`, and not by the group's name, which the system
/// translates.
fn names_an_integrity_level(listing: &str) -> bool {
    listing.contains(",\"S-1-16-")
}

/// Whether this process has the Administrators group.
fn in_administrators() -> bool {
    let output = Command::new(system32("whoami.exe"))
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami runs");
    assert!(output.status.success(), "whoami /groups failed");
    let listing = String::from_utf8_lossy(&output.stdout);
    // Every account's listing names the integrity level it runs at, so a listing without one is not
    // one, and an account is not taken for a standard one on the strength of an answer that is empty.
    assert!(
        names_an_integrity_level(&listing),
        "whoami /groups listed no integrity level: {listing:?}"
    );
    listing.contains("S-1-5-32-544")
}

/// The Windows command shell, which a session's root program may be on any machine.
fn command_shell() -> String {
    system32("cmd.exe").display().to_string()
}

/// The process identity the worker of `session_id` published.
fn worker_of(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> ProcessStartIdentity {
    kr_ipc::descriptor::read_all(environment)
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .expect("the worker published its descriptor")
        .process_start_identity
}

/// The session as the daemon lists it. `kr new` prints the login a session is bound to but not its
/// root shell's process identity, which the daemon's listing names.
async fn listed(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> SessionSummary {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let mut client = kr_ipc::client::LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        windows_session::build(),
    )
    .await
    .expect("reaches the daemon");
    let sessions: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::some(environment.environment_id()),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon answers")
        .to_typed()
        .expect("decodes");
    sessions
        .sessions
        .into_iter()
        .find(|summary| summary.session_id == session_id)
        .unwrap_or_else(|| panic!("the daemon lists the session {session_id}"))
}

/// What a created session's JSON says of the login it is bound to.
fn binding_of(document: &serde_json::Value) -> DesktopBinding {
    serde_json::from_value(document["desktop"].clone())
        .unwrap_or_else(|error| panic!("the session's desktop ({error}): {document}"))
}

/// A process the kernel shows running, by the identity it was started under, in this login session.
fn assert_running_in(session: u32, what: &str, process: &ProcessStartIdentity) {
    let facts = kr_ipc::starter::process_facts(
        u32::try_from(process.pid.get()).expect("a process identifier"),
    )
    .unwrap_or_else(|error| panic!("{what} ({}) is read: {error}", process.pid.get()));
    assert_eq!(
        kr_ipc::identity::process_state(process),
        kr_ipc::identity::ProcessState::Running,
        "{what} is running"
    );
    assert_eq!(
        facts.session,
        session,
        "{what} ({}) is in this login session",
        process.pid.get()
    );
}

/// KR-REQ-03.23, the first half: a `desktop_bound` session is made in a login session on the
/// machine, and the account is signed out.
///
/// The daemon is this test's process, hosted as the other Windows session cases host it: it starts
/// the session's worker through the environment's scheduled task, so the worker is a process of the
/// login session of its own. A session is created with `--desktop` and is shown to be bound to this
/// login: its profile, the worker and the root shell running in this login session, and the platform
/// reading the login the session records as present. The login's session number and the record of
/// the session are kept in the account's temporary directory, nothing this case holds is let go of
/// (so that only the sign-out can end what it started), and the account is signed out, which ends
/// this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = signs_out!()]
async fn a_desktop_bound_session_is_made_and_the_account_signed_out() {
    // Before anything is started: a run of every case in this file at once, or a run as an account
    // whose session others depend on, must not end that session.
    assert!(
        std::env::var(SIGN_OUT_SWITCH).is_ok_and(|value| value == "1"),
        "this case signs the account that runs it out; set {SIGN_OUT_SWITCH}=1 where that account \
         is disposable"
    );
    assert!(
        !in_administrators(),
        "this case signs its account out, and an account in the Administrators group is not one to \
         sign out"
    );
    // A record of an earlier run is not the record of this one.
    match std::fs::remove_file(record_path()) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("the record of an earlier run is not removed: {error}"),
    }

    let host = Prepared::new().start(None).await;
    let environment = host.tree.environment();
    let created = host
        .kr_new_as(
            Some("--desktop"),
            &["--shell-mode", "native_compat", "--shell", &command_shell()],
        )
        .await;
    assert!(
        created.succeeded(),
        "a desktop-bound session is created for an account that is signed in: {}",
        created.said()
    );
    assert_eq!(
        created.document["worker_profile"], "desktop_bound",
        "the session this case is about is bound to the login: {}",
        created.document
    );
    let (session_id, _) = created.session();
    let binding = binding_of(&created.document);
    assert!(
        binding.desktop_session_id.is_present() && binding.login_generation.is_present(),
        "the session records the login it is bound to, and the generation of it: {}",
        created.document
    );

    let login = kr_ipc::starter::current_session().expect("this process's login session");
    let worker = worker_of(&environment, session_id);
    let summary = listed(&environment, session_id).await;
    assert_eq!(
        summary.desktop, binding,
        "the daemon holds the login the session was reported bound to"
    );
    let root: ProcessStartIdentity = summary
        .root_process
        .as_ref()
        .cloned()
        .unwrap_or_else(|| panic!("the session names its root shell: {summary:?}"));
    assert_running_in(login, "the worker", &worker);
    assert_running_in(login, "the root shell", &root);
    assert_eq!(
        recorded_presence(&binding),
        Presence::Present,
        "the platform reads the login the session records as present, before the sign-out"
    );
    eprintln!(
        "before the sign-out: login session {login}; the session {session_id} is desktop_bound to \
         {binding:?}; the worker is process {}, the root shell {}; the login reads as present",
        worker.pid.get(),
        root.pid.get()
    );

    let starter = kr_controller::supervision::windows::testing::built_binary("kr-controller")
        .unwrap_or_else(|missing| panic!("{missing}"));
    let definition =
        kr_controller::supervision::windows::testing::definition(&environment, &starter)
            .expect("the definition this host registers");
    let record = serde_json::json!({
        "login": login,
        "session_id": session_id,
        "binding": binding,
        "worker": worker,
        "root": root,
        "task": definition.name,
        "tree": host.tree.root(),
        "signing_out_at_ms": kr_ipc::now_ms().get(),
    });
    std::fs::write(
        record_path(),
        serde_json::to_vec_pretty(&record).expect("a record"),
    )
    .expect("the record of what the sign-out is about");

    // From here only the sign-out may end what the session started. Nothing this case holds is let
    // go of, so that a sign-out that does not come leaves the processes running and the case
    // failing, and the case that follows, which needs a record, is not run on processes this case
    // ended itself. The entry the host registered is the one exception: the host is forgotten with
    // its hold on the entry, so this guard holds it. The case that follows deletes it, and when
    // the sign-out does not come this case fails and the guard deletes it, since nothing else
    // would.
    let _task = RegisteredTask::new(definition.name.clone());
    std::mem::forget(host);
    eprintln!("signing out login session {login}");
    let signed_out = Command::new(system32("logoff.exe"))
        .status()
        .expect("logoff runs");
    assert!(signed_out.success(), "logoff: {signed_out}");
    // The end of the session ends this process, and nothing after this line runs. There is nothing
    // else to wait for, and a sign-out that does not come is read by the run that signed the account
    // in, which bounds its wait and finds the account's session and processes still there.
    std::future::pending::<()>().await;
}

/// A daemon hosted on a state directory an earlier process left, as the daemon of the account's next
/// sign-in would be.
struct Reopened {
    root: PathBuf,
    environment: kr_ipc::paths::EnvironmentPaths,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
    controller: Option<Arc<kr_controller::service::Controller>>,
}

impl Reopened {
    /// Starts a daemon on the tree under `root`, which a case that ended with its login left. The
    /// environment's task is the first half's, still registered.
    async fn start(root: PathBuf) -> Self {
        use kr_controller::service::{Controller, ControllerSetup};

        let paths =
            kr_ipc::paths::HostPaths::new(root.join("r"), root.join("s")).expect("absolute roots");
        let environment_id = paths
            .open_environment_id()
            .expect("the environment identity the first half made");
        let environment = paths.environment(environment_id);
        let secrets = environment.secrets_dir();
        let starter = kr_controller::supervision::windows::testing::built_binary("kr-controller")
            .unwrap_or_else(|missing| panic!("{missing}"));
        let controller = Controller::start(ControllerSetup {
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
            supervisor: kr_controller::supervision::windows::testing::supervisor_for(
                &environment,
                &starter,
            )
            .expect("the supervisor of the environment's task"),
            worker_program: root.join("kr-worker.exe"),
            build_id: windows_session::build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts on the state the first half left");
        let rendezvous = kr_ipc::endpoint::Listener::bind(
            &environment.rendezvous_endpoint().expect("an endpoint"),
        )
        .expect("binds the rendezvous");
        let clients = kr_ipc::endpoint::Listener::bind(
            &environment.controller_endpoint().expect("an endpoint"),
        )
        .expect("binds the client endpoint");
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        Self {
            root,
            environment,
            serving,
            controller: Some(controller),
        }
    }

    /// Runs `kr --json` against this daemon's directories and returns its exit status and the
    /// document it printed.
    async fn json(&self, arguments: &[&str]) -> (Option<i32>, serde_json::Value) {
        let state = self.root.join("s");
        let runtime = self.root.join("r");
        let arguments: Vec<String> = ["--json"]
            .into_iter()
            .chain(arguments.iter().copied())
            .map(str::to_owned)
            .collect();
        let spoken = arguments.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(support::kr())
                .args(&arguments)
                .env("KR_RUNTIME_DIR", runtime)
                .env("KR_STATE_DIR", state)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("kr runs")
        })
        .await
        .expect("kr is waited for");
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {spoken:?} printed no document ({error}): {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }
}

impl Drop for Reopened {
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
        drop(self.controller.take());
    }
}

/// A scheduled task, deleted when this is dropped, so that a failure anywhere after the entry is
/// known does not leave it registered: removing an account does not remove the tasks it registered.
/// The deletion is tried once; a failure of it is written to the error output, without a panic that
/// would end the process during an unwinding.
struct RegisteredTask {
    name: Option<String>,
}

impl RegisteredTask {
    fn new(name: String) -> Self {
        Self { name: Some(name) }
    }

    /// Deletes the entry now, when it is not deleted yet, and says why it is not when the system
    /// does not.
    fn delete(&mut self) -> Result<(), String> {
        let Some(name) = self.name.take() else {
            return Ok(());
        };
        match Command::new(system32("schtasks.exe"))
            .args(["/Delete", "/TN", &name, "/F"])
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("the entry {name} is not removed: {status}")),
            Err(error) => Err(format!(
                "schtasks does not run for the entry {name}: {error}"
            )),
        }
    }
}

impl Drop for RegisteredTask {
    fn drop(&mut self) {
        if let Err(why) = self.delete() {
            let _ = writeln!(std::io::stderr(), "{why}");
        }
    }
}

/// KR-REQ-03.23, the second half: after the sign-out, the session closes with `desktop_lost`.
///
/// Run in the account's next sign-in, by what the half before recorded. The worker and the root
/// shell, by the identity each was started under, are ended: the sign-out took them. The platform
/// reads the login the session recorded as ended, and a daemon started on the state the first half
/// left, which is what the next sign-in does, gives the session's closure as `desktop_lost` and not
/// as a crash of the worker, recorded after the sign-out began. A session made in this login is
/// the control: it is bound to a different login than the old one, the platform reads it as
/// present, and the old one still as ended. The control session is closed and its processes shown
/// ended before the first half's task is deleted and its tree is removed, as far as the system lets
/// this process remove it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = follows_a_sign_out!()]
async fn after_a_sign_out_the_desktop_bound_session_is_closed_with_desktop_lost() {
    let path = record_path();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "{}: {error}; the case that signs the account out is run first, and this one in \
                 the account's next sign-in",
                path.display()
            )
        }))
        .expect("a record");
    // Deleting the first half's task is tried whichever way this half ends, after the daemon that
    // uses it is let go of.
    let mut task = RegisteredTask::new(record["task"].as_str().expect("a task").to_owned());
    let before_login = record["login"].as_u64().expect("a login session");
    let session_id: SessionId =
        serde_json::from_value(record["session_id"].clone()).expect("a session identifier");
    let binding: DesktopBinding =
        serde_json::from_value(record["binding"].clone()).expect("a binding");
    let now = kr_ipc::starter::current_session().expect("this process's login session");

    // What the sign-out ended: the worker and the root shell, by the identity each was started
    // under.
    for (what, key) in [("the worker", "worker"), ("the root shell", "root")] {
        let process: ProcessStartIdentity =
            serde_json::from_value(record[key].clone()).expect("an identity");
        assert_eq!(
            kr_ipc::identity::process_state(&process),
            kr_ipc::identity::ProcessState::Ended,
            "{what} (process {}) is still there after the sign-out",
            process.pid.get()
        );
    }

    // The platform's answer about the login the session recorded.
    assert_eq!(
        recorded_presence(&binding),
        Presence::Ended,
        "the platform reads the login the session was bound to as still there after the sign-out"
    );
    eprintln!(
        "after the sign-out: login session {now} (the one signed out was {before_login}); the \
         recorded login {binding:?} reads as ended"
    );

    // A daemon on the state the first half left, as the next sign-in's would be.
    let tree = PathBuf::from(record["tree"].as_str().expect("the first half's tree"));
    let daemon_started_at = kr_ipc::now_ms().get();
    let daemon = Reopened::start(tree.clone()).await;
    let (status, document) = daemon.json(&["attach", &session_id.to_string()]).await;
    assert_eq!(
        status,
        Some(8),
        "kr attach on the closed session: {document}"
    );
    assert_eq!(document["code"], "SESSION_CLOSED", "{document}");
    assert_eq!(
        document["closure"]["reason"], "desktop_lost",
        "a sign-out closes a desktop-bound session with desktop_lost: {document}"
    );
    // Once: asked again, it is the same record.
    let (_, again) = daemon.json(&["attach", &session_id.to_string()]).await;
    assert_eq!(again["closure"], document["closure"], "{again}");
    let signing_out_at = record["signing_out_at_ms"].as_u64().expect("a time");
    let closed_at = document["closure"]["closed_at_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("the closure says when it was recorded: {document}"));
    assert!(
        closed_at >= signing_out_at,
        "the closure ({closed_at}) was recorded before the sign-out began ({signing_out_at}): {document}"
    );
    // Said, and not asserted: a closure that was written before the daemon of this sign-in started
    // is the worker's own; one written after it is the daemon's reading of the login.
    eprintln!(
        "after the sign-out: session {session_id} is closed with {} at {closed_at} ms, the sign-out \
         having begun at {signing_out_at} ms and this sign-in's daemon at {daemon_started_at} ms \
         (recorded {} the daemon started)",
        document["closure"]["reason"],
        if closed_at >= daemon_started_at {
            "after"
        } else {
            "before"
        }
    );

    // The control: a session made in this login is bound to this login, which the platform reads as
    // present, while the old one is still ended.
    let cwd = tree.display().to_string();
    let (status, fresh) = daemon
        .json(&[
            "new",
            "--invisible",
            "--desktop",
            "--cwd",
            &cwd,
            "--shell-mode",
            "native_compat",
            "--shell",
            &command_shell(),
        ])
        .await;
    assert_eq!(status, Some(0), "kr new in the new login: {fresh}");
    assert_eq!(fresh["worker_profile"], "desktop_bound", "{fresh}");
    let fresh_binding = binding_of(&fresh);
    assert_ne!(
        fresh_binding, binding,
        "the new login is bound to the login the old session was: {fresh}"
    );
    assert_eq!(recorded_presence(&fresh_binding), Presence::Present);
    assert_eq!(recorded_presence(&binding), Presence::Ended);
    eprintln!(
        "after the sign-out: a session made in login session {now} is bound to {fresh_binding:?}, \
         which reads as present"
    );
    // The control session is closed, and what it started is shown ended before anything is removed
    // under it. A case that fails before this point leaves the control session to the sign-out and
    // the account's removal that follow every run.
    let fresh_id: SessionId = fresh["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("parses");
    let fresh_worker = worker_of(&daemon.environment, fresh_id);
    let fresh_root = listed(&daemon.environment, fresh_id)
        .await
        .root_process
        .as_ref()
        .cloned()
        .expect("the control session names its root shell");
    let (status, closed) = daemon.json(&["close", &fresh_id.to_string()]).await;
    assert_eq!(status, Some(0), "kr close: {closed}");
    let waited = tokio::time::Instant::now();
    for (what, process) in [
        ("the control session's worker", &fresh_worker),
        ("the control session's root shell", &fresh_root),
    ] {
        while kr_ipc::identity::process_state(process) != kr_ipc::identity::ProcessState::Ended {
            assert!(
                waited.elapsed() < LIVENESS_DEADLINE,
                "{what} (process {}) is still there after the session was closed",
                process.pid.get()
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // What the first half left in the account's temporary directory goes, the entry with it.
    drop(daemon);
    task.delete().unwrap_or_else(|why| panic!("{why}"));
    // The tree is in the account's own temporary directory, which the run removes with the
    // account's profile. A file of it that the daemon of this process still holds, which the
    // aborted tasks of the daemon may do until this process ends, keeps it until then, and is said
    // here and not refused.
    if let Err(error) = std::fs::remove_dir_all(&tree) {
        eprintln!("{} is not removed yet: {error}", tree.display());
    }
    std::fs::remove_file(&path).expect("the record is removed");
}

#[test]
fn an_integrity_level_is_named_by_its_sid_whatever_the_language() {
    // The words of the first field are translated and the SID is not. The level's row has no
    // attributes. The first listing has the shape `whoami` prints in English; the second is an example
    // of a translation, not a recording.
    let english = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n\
                   \"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"\"\r\n";
    let translated = "\"Tout le monde\",\"Groupe connu\",\"S-1-1-0\",\"Groupe obligatoire\"\r\n\
                      \"Etiquette obligatoire\\Niveau moyen\",\"Etiquette\",\"S-1-16-8192\",\"\"\r\n";
    assert!(names_an_integrity_level(english));
    assert!(names_an_integrity_level(translated));
    assert!(
        !names_an_integrity_level(""),
        "an empty answer names no level"
    );
    assert!(
        !names_an_integrity_level(
            "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n"
        ),
        "a listing of groups without a level names none"
    );
}

/// The names of the tasks the Task Scheduler lists, which `schtasks` writes one to a line as the
/// first field, a quoted name with the folder in front of it. A listing that does not succeed stops
/// the case: it says nothing about any task.
fn listed_tasks() -> Vec<String> {
    let output = Command::new(system32("schtasks.exe"))
        .args(["/Query", "/FO", "CSV", "/NH"])
        .output()
        .expect("schtasks runs");
    assert!(
        output.status.success(),
        "schtasks /Query did not succeed: {}",
        output.status
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.strip_prefix('"')?
                .split("\",")
                .next()
                .map(str::to_owned)
        })
        .collect()
}

/// The guard deletes the entry of a task when a step after it is registered fails.
#[test]
#[ignore = registers_a_task!()]
fn a_registered_task_is_deleted_when_the_case_that_holds_it_fails() {
    let name = format!("kr-guard-test-{}", std::process::id());
    let listed = format!("\\{name}");
    let created = Command::new(system32("schtasks.exe"))
        .args([
            "/Create",
            "/TN",
            &name,
            "/TR",
            "cmd.exe /c exit 0",
            "/SC",
            "ONCE",
            "/ST",
            "23:59",
            "/F",
        ])
        .output()
        .expect("schtasks runs");
    // The guard is made as soon as the entry may be there, whatever the system answered.
    let seen = std::cell::Cell::new(false);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _task = RegisteredTask::new(name.clone());
        assert!(created.status.success(), "the entry {name} is registered");
        seen.set(listed_tasks().contains(&listed));
        panic!("a step after the entry was registered fails");
    }));
    let left = listed_tasks().contains(&listed);
    if left {
        // A run that is red tries to remove the entry it made.
        let _ = Command::new(system32("schtasks.exe"))
            .args(["/Delete", "/TN", &name, "/F"])
            .output();
    }
    assert!(failed.is_err(), "the step failed");
    assert!(
        seen.get(),
        "the entry {name} was listed while the guard held it"
    );
    assert!(!left, "the entry {name} is left registered");
}
