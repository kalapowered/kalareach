//! The Windows supervisor against the real Task Scheduler: a launch handed to the environment's
//! scheduled task, created by the task's starter rather than by this process, and every way that
//! can end in nothing started.
//!
//! This test process is itself in `cargo test`'s job, which kills its members when it closes and
//! forbids breakaway: a process this process created could never leave it. The supervisor creates
//! nothing itself, so what it starts is outside that job whatever that job is.
//!
//! The task is registered for the test's own temporary environment, running this build's
//! `kr-controller` as its starter, with the logon the machine's session allows: a session where
//! the user is signed in takes the interactive logon the setup step registers, and session 0,
//! where a test host runs with nobody signed in, takes the logon without a session. Each test
//! removes its task however it ends.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_controller::supervision::windows::{
    LogonType, TaskDefinition, TaskSupervisor, register, remove, run,
};
use kr_controller::supervision::{LaunchOutcome, ServiceLaunch, WorkerSupervisor};
use kr_ipc::starter::{Reached, StartClaim, connect, current_session, in_any_job};
use kr_ipc::testing::TempHost;

/// The environment's task, registered for this test and removed however it ends.
struct Registered(TaskDefinition);

impl Registered {
    fn for_environment(host: &TempHost, starter: &Path) -> Self {
        let logon = if current_session().expect("this session") == 0 {
            LogonType::S4U
        } else {
            LogonType::InteractiveToken
        };
        let definition = TaskDefinition::new(
            kr_ipc::starter::current_user_sid().expect("this account"),
            &host.environment(),
            starter,
            logon,
        );
        register(&definition).expect("the environment's task is registered");
        Self(definition)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let _ = remove(&self.0);
    }
}

/// This build's control daemon, which the task runs as its starter.
fn starter() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kr-controller"))
}

fn system(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join(program)
}

/// A service that runs long enough to be looked at, then ends by itself.
fn waiting_service(host: &TempHost) -> ServiceLaunch {
    ServiceLaunch {
        label: format!("kr-plugin-host-{}", kr_ipc::new_uuid()),
        program: system("PING.EXE"),
        arguments: vec!["-n".to_owned(), "20".to_owned(), "127.0.0.1".to_owned()],
        jobs_directory: host.environment().jobs_dir(),
        working_directory: host.root().to_path_buf(),
    }
}

/// Ends a process this test had started through the task, by the identity it was reported under.
fn end(identity: &kr_protocol::identity::ProcessStartIdentity) {
    if kr_ipc::identity::process_start_identity(u32::try_from(identity.pid.get()).expect("a pid"))
        .is_ok_and(|current| current == *identity)
    {
        let _ = std::process::Command::new(system("taskkill.exe"))
            .args(["/PID", &identity.pid.get().to_string(), "/F"])
            .output();
    }
}

/// A service started through the task is the process the starter reported, runs in this
/// process's login session, is outside every job where the task's own job lets it leave, and the
/// environment's login session is recorded.
#[test]
fn a_service_is_started_by_the_environments_task_and_not_by_this_process() {
    let host = TempHost::create();
    let _task = Registered::for_environment(&host, &starter());
    let supervisor = TaskSupervisor::new(host.environment(), &starter()).expect("the supervisor");
    let outcome = supervisor.start_service(&waiting_service(&host));
    let LaunchOutcome::Started(identity) = outcome else {
        panic!("the service was started: {outcome:?}");
    };
    let pid = u32::try_from(identity.pid.get()).expect("a pid");
    // Everything is read while the service runs, and it is ended before anything is asserted.
    let described = kr_ipc::identity::process_start_identity(pid);
    let facts = kr_ipc::starter::process_facts(pid);
    let in_job = in_any_job(pid);
    end(&identity);
    assert_eq!(
        described.expect("the process can be described"),
        identity,
        "the identity recorded is the process's own"
    );
    let session = current_session().expect("this session");
    assert_eq!(
        facts.expect("the process's facts").session,
        session,
        "the service runs in this session"
    );
    if session == 0 {
        // The logon without a session: the task's job lets its members leave, and the starter
        // requires its child to be in no job at all.
        assert!(
            !in_job.expect("its jobs"),
            "a child of a task whose job lets it leave is in no job"
        );
    }
    let recorded = kr_ipc::starter::recorded_session(&host.environment())
        .expect("the record")
        .expect("a session is recorded");
    assert_eq!(recorded.session, session);
}

/// With no task registered, a start names the setup step and creates nothing: no launch is left
/// waiting for a starter that might come later. This process is in a job that kills on close and
/// forbids breakaway, and the start still does not create anything inside it.
#[test]
fn with_no_task_a_start_names_the_setup_step_and_leaves_nothing_waiting() {
    let host = TempHost::create();
    let supervisor = TaskSupervisor::new(host.environment(), &starter()).expect("the supervisor");
    let outcome = supervisor.start_service(&waiting_service(&host));
    let LaunchOutcome::NotStarted { detail } = outcome else {
        panic!("nothing was started: {outcome:?}");
    };
    assert!(
        detail.contains("kr host startup --set standalone"),
        "the failure names the setup step: {detail}"
    );
    let endpoint = host.environment().starter_endpoint().expect("the name");
    assert!(
        matches!(
            connect(&endpoint, Instant::now() + Duration::from_secs(2)),
            Ok(Reached::NoInstance)
        ),
        "no launch is left waiting"
    );
}

/// A task under the environment's name that runs another program is not this installation's
/// task, and is refused before it is run.
#[test]
fn a_task_that_runs_another_program_is_refused_before_it_is_run() {
    let host = TempHost::create();
    let _task = Registered::for_environment(&host, &system("whoami.exe"));
    let supervisor = TaskSupervisor::new(host.environment(), &starter()).expect("the supervisor");
    let outcome = supervisor.start_service(&waiting_service(&host));
    let LaunchOutcome::NotStarted { detail } = outcome else {
        panic!("nothing was started: {outcome:?}");
    };
    assert!(
        detail.contains("not the one this installation registers")
            && detail.contains("kr host startup --set standalone"),
        "the failure names the difference and the setup step: {detail}"
    );
}

/// A launch the starter cannot create is reported by the starter and is nothing started.
#[test]
fn a_launch_the_starter_cannot_create_is_nothing_started() {
    let host = TempHost::create();
    let _task = Registered::for_environment(&host, &starter());
    let supervisor = TaskSupervisor::new(host.environment(), &starter()).expect("the supervisor");
    let mut launch = waiting_service(&host);
    launch.program = host.root().join("no-such-program.exe");
    let outcome = supervisor.start_service(&launch);
    let LaunchOutcome::NotStarted { detail } = outcome else {
        panic!("nothing was started: {outcome:?}");
    };
    assert!(
        detail.contains("no-such-program.exe"),
        "the starter's refusal names the program: {detail}"
    );
}

/// A starter the task runs with no launch waiting and only a lapsed start claim takes the claim
/// and starts nothing.
#[test]
fn a_starter_with_only_a_lapsed_claim_takes_it_and_starts_nothing() {
    let host = TempHost::create();
    let environment = host.environment();
    let task = Registered::for_environment(&host, &starter());
    let claim = StartClaim {
        request: kr_ipc::new_uuid(),
        boot: kr_ipc::identity::boot_identity().expect("this boot"),
        deadline_boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    };
    kr_ipc::starter::leave_claim(&environment, &claim).expect("a lapsed claim");
    run(&task.0).expect("the task is run");
    let marker = environment
        .start_claims_dir()
        .join(format!("{}.taken", claim.request));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(marker.exists(), "the starter took the claim");
    // A daemon it started would answer on the environment's client endpoint.
    std::thread::sleep(Duration::from_secs(3));
    let endpoint = environment.controller_endpoint().expect("the name");
    let reached = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(kr_ipc::endpoint::Connection::connect(&endpoint));
    assert!(reached.is_err(), "no daemon was started for a lapsed claim");
}
