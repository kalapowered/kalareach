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

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use kr_protocol::identity::{DesktopBinding, ProcessStartIdentity};
use kr_protocol::ids::SessionId;
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

/// Whether this process has the Administrators group.
fn in_administrators() -> bool {
    let output = Command::new(system32("whoami.exe"))
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami runs");
    String::from_utf8_lossy(&output.stdout).contains("S-1-5-32-544")
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
    let root: ProcessStartIdentity =
        serde_json::from_value(created.document["root_process"].clone()).unwrap_or_else(|error| {
            panic!("the session's root process ({error}): {}", created.document)
        });
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
    });
    std::fs::write(
        record_path(),
        serde_json::to_vec_pretty(&record).expect("a record"),
    )
    .expect("the record of what the sign-out is about");

    // From here only the sign-out may end what the session started. Nothing this case holds is let
    // go of, so that a sign-out that does not come leaves the processes running and the case
    // failing, and the case that follows, which needs a record, is not run on processes this case
    // ended itself.
    std::mem::forget(host);
    eprintln!("signing out login session {login}");
    let signed_out = Command::new(system32("logoff.exe"))
        .status()
        .expect("logoff runs");
    assert!(signed_out.success(), "logoff: {signed_out}");
    // The end of the session ends this process, and nothing after this line runs.
    tokio::time::sleep(LIVENESS_DEADLINE).await;
    panic!("login session {login} was not ended within {LIVENESS_DEADLINE:?} of the sign-out");
}

/// A daemon hosted on a state directory an earlier process left, as the daemon of the account's next
/// sign-in would be.
struct Reopened {
    root: PathBuf,
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

/// KR-REQ-03.23, the second half: after the sign-out, the session closes with `desktop_lost`.
///
/// Run in the account's next sign-in, by what the half before recorded. The worker and the root
/// shell, by the identity each was started under, are ended: the sign-out took them, and the worker
/// had no chance to write a closure of its own. The platform reads the login the session recorded
/// as ended, and a daemon started on the state the first half left, which is what the next sign-in
/// does, gives the session's closure as `desktop_lost` and not as a crash of the worker. A session
/// made in this login is the control: it is bound to a different login than the old one, the
/// platform reads it as present, and the old one still as ended.
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
    eprintln!(
        "after the sign-out: session {session_id} is closed with {}",
        document["closure"]["reason"]
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
    let fresh_id = fresh["session_id"].as_str().expect("a session identifier");
    let (status, closed) = daemon.json(&["close", fresh_id]).await;
    assert_eq!(status, Some(0), "kr close: {closed}");

    // What the first half left in the account's temporary directory goes, the entry with it.
    drop(daemon);
    let name = record["task"].as_str().expect("a task");
    let removed = Command::new(system32("schtasks.exe"))
        .args(["/Delete", "/TN", name, "/F"])
        .status()
        .expect("schtasks runs");
    assert!(removed.success(), "the entry {name} is removed: {removed}");
    let _ = std::fs::remove_dir_all(&tree);
    std::fs::remove_file(&path).expect("the record is removed");
}
