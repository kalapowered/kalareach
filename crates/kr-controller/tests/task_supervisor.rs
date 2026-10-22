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

use kr_controller::supervision::windows::testing::{
    ProcessInAnotherSession, TestTask, built_binary, definition,
};
use kr_controller::supervision::windows::{TaskSupervisor, run};
use kr_controller::supervision::{LaunchOutcome, ServiceLaunch, WorkerSupervisor};
use kr_ipc::starter::{Reached, StartClaim, connect, current_session, in_any_job};
use kr_ipc::testing::TempHost;

/// The environment's task, registered for this test's environment and removed however it ends.
fn registered(host: &TempHost, starter: &Path) -> TestTask {
    TestTask::register(&host.environment(), starter).expect("the environment's task is registered")
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

/// A suite that is not this package's finds this package's daemon where the build put it, beside
/// its own executable: the same binary the build gave this package's tests.
#[test]
fn a_suite_finds_the_built_daemon_beside_itself() {
    let found = built_binary("kr-controller").expect("the daemon is built");
    assert_eq!(
        std::fs::canonicalize(found).expect("the found binary"),
        std::fs::canonicalize(starter()).expect("the binary the build names")
    );
    assert!(
        built_binary("kr-no-such-binary").is_err(),
        "a binary that was not built is not found"
    );
}

/// A service started through the task is the process the starter reported, runs in this
/// process's login session, is outside every job where the task's own job lets it leave, and the
/// environment's login session is recorded.
#[test]
fn a_service_is_started_by_the_environments_task_and_not_by_this_process() {
    let host = TempHost::create();
    let task = registered(&host, &starter());
    let supervisor = task.supervisor(&host.environment());
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
}

/// A start is carried out when the daemon answers its starter late.
///
/// The task starts its starter while the call that ran the task is still waiting, and the daemon
/// answers the starter only once that call has returned. A Task Scheduler can answer a run later
/// than a starter waits for any one message of the exchange; a starter that waited only that
/// long would go without its launch, and the start would fail although the task had run. Here
/// the daemon takes fourteen seconds to answer a starter whose hello it has received.
#[test]
fn a_start_is_carried_out_when_the_daemon_answers_its_starter_late() {
    let host = TempHost::create();
    let task = registered(&host, &starter());
    let supervisor = task
        .supervisor(&host.environment())
        .answering_late(Duration::from_secs(14));
    let outcome = supervisor.start_service(&waiting_service(&host));
    let LaunchOutcome::Started(identity) = outcome else {
        panic!(
            "the service was started although the daemon answered its starter late: {outcome:?}"
        );
    };
    end(&identity);
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
    let _task = registered(&host, &system("whoami.exe"));
    let expected = definition(&host.environment(), &starter()).expect("the expected task");
    let supervisor = TaskSupervisor::for_definition(host.environment(), expected);
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
    let task = registered(&host, &starter());
    let supervisor = task.supervisor(&host.environment());
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

/// A launch larger than the launch pipe carries is refused before it is handed over, so it is
/// nothing started rather than a launch whose answer was lost.
#[test]
fn a_launch_too_large_for_the_pipe_is_nothing_started() {
    let host = TempHost::create();
    let task = registered(&host, &starter());
    let supervisor = task.supervisor(&host.environment());
    let mut launch = waiting_service(&host);
    launch
        .arguments
        .push("x".repeat(kr_ipc::starter::MAX_LAUNCH_FRAME));
    let outcome = supervisor.start_service(&launch);
    let LaunchOutcome::NotStarted { detail } = outcome else {
        panic!("nothing was started: {outcome:?}");
    };
    assert!(
        detail.contains("more than the"),
        "the refusal names the bound: {detail}"
    );
}

/// A starter the task runs with no launch waiting and only a lapsed start claim takes the claim
/// and starts nothing.
#[test]
fn a_starter_with_only_a_lapsed_claim_takes_it_and_starts_nothing() {
    let host = TempHost::create();
    let environment = host.environment();
    let task = registered(&host, &starter());
    let claim = StartClaim {
        request: kr_ipc::new_uuid(),
        boot: kr_ipc::identity::boot_identity().expect("this boot"),
        deadline_boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    };
    kr_ipc::starter::leave_claim(&environment, &claim).expect("a lapsed claim");
    run(task.definition()).expect("the task is run");
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

/// What a daemon that starts again on an environment is given, with a supervisor that starts
/// nothing: the guard under test decides before anything is started.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &kr_controller::supervision::WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// Starts a daemon on `host`'s environment, and gives back why it did not start.
async fn start_daemon(host: &TempHost) -> Result<(), String> {
    use kr_controller::service::{Controller, ControllerSetup};
    use kr_crypto::store::{StoreSelection, open_store_in};
    use kr_ipc::verify::ControllerIdentity;

    let environment = host.environment();
    let environment_id = host.environment_id();
    let secrets = environment.secrets_dir();
    let worker = host.root().join("kr-worker.exe");
    std::fs::write(&worker, b"").expect("a stand-in for the worker program");
    let started = Controller::start(ControllerSetup {
        paths: environment,
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: worker,
        build_id: kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await;
    match started {
        Ok(controller) => {
            drop(controller);
            Ok(())
        }
        Err(refused) => Err(refused.to_string()),
    }
}

/// What a daemon that ran before this one left in the environment's registry.
#[derive(Clone, Copy, Debug)]
enum Left {
    /// A worker of a live session.
    Worker,
    /// A launch handed to the platform, with the process it reported, and no claim.
    Spawned,
    /// A launch handed to the platform whose process was never reported.
    SpawnedWithNoProcess,
    /// A launch whose worker claimed its reservation, and has not reported a shell.
    Claimed,
    /// A launch that was fenced, which may still be running.
    Fenced,
}

/// Writes into the environment's registry what an earlier daemon would have left, with `process` as
/// the process it started (where there is one).
fn leave(host: &TempHost, left: Left, process: &kr_protocol::identity::ProcessStartIdentity) {
    use kr_controller::registry::{LaunchPhase, Registry, WorkerRecord};
    use kr_protocol::scalars::{AuthorisationKey, Digest256, TimestampMs};

    let mut registry = Registry::open(
        host.environment().registry_database(),
        host.environment_id(),
    )
    .expect("opens the registry");
    let reservation = registry
        .reserve(
            &kr_protocol::ids::ActorId::new("local:501").expect("a principal"),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([1; 32]),
            &[0xa0],
            TimestampMs::new(1),
        )
        .expect("reserves")
        .reservation;
    let id = reservation.reservation_id;
    match left {
        Left::Worker => registry
            .adopt_worker(
                &WorkerRecord {
                    session_id: reservation.session_id,
                    display_number: reservation.display_number,
                    public_key: AuthorisationKey::from_bytes([9; 32]),
                    process_identity: process.clone(),
                    endpoint: "kr-no-such-endpoint".to_owned(),
                    profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    state: kr_protocol::session::SessionState::Live,
                    acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
                },
                None,
            )
            .expect("records the worker"),
        Left::SpawnedWithNoProcess => registry
            .set_phase(id, LaunchPhase::Spawned)
            .expect("spawned"),
        Left::Spawned | Left::Claimed | Left::Fenced => {
            registry
                .set_phase(id, LaunchPhase::Spawned)
                .expect("spawned");
            registry
                .record_launch(id, process)
                .expect("the launcher's process");
            if !matches!(left, Left::Spawned) {
                registry
                    .claim_rendezvous(id, AuthorisationKey::from_bytes([9; 32]))
                    .expect("claims");
            }
            if matches!(left, Left::Fenced) {
                registry.set_phase(id, LaunchPhase::Fenced).expect("fences");
            }
        }
    }
}

/// KR-REQ-07.58: an environment's work stays in one login session. A daemon that starts in a
/// session other than the one where what an earlier daemon left is still running takes none of it
/// over: signing out ends a session's processes, so what keeps running there would be left behind
/// by the wrong sign-out. It refuses, naming the session, for a worker, for a launch that was
/// handed over or claimed and for one that was fenced, and it starts for what has ended, for what
/// runs in its own session and for a launch that reported no process, which no claim can follow.
/// No record of the session is needed: what is running says where.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_does_not_take_over_work_that_runs_in_another_login_session() {
    let scratch = TempHost::create();
    let elsewhere = ProcessInAnotherSession::start(scratch.root())
        .expect("a process of this user in another login session");
    for left in [Left::Worker, Left::Spawned, Left::Claimed, Left::Fenced] {
        let host = TempHost::create();
        leave(&host, left, &elsewhere.identity);
        let refused = start_daemon(&host).await.expect_err(&format!(
            "a daemon took over {left:?} work in another session"
        ));
        assert!(
            refused.contains(&format!("in session {}", elsewhere.session)),
            "the refusal names the session the work is in: {refused}"
        );
    }

    // An earlier record may name the number the process now has, with the start of one that has
    // ended: it is the later record that is work, and the earlier one does not hide it.
    let stale = kr_protocol::identity::ProcessStartIdentity::new(
        elsewhere.identity.pid.get(),
        elsewhere.identity.source,
        elsewhere.identity.start_value.get() - 1,
    );
    let host = TempHost::create();
    leave(&host, Left::Worker, &stale);
    leave(&host, Left::Claimed, &elsewhere.identity);
    start_daemon(&host)
        .await
        .expect_err("a record of an ended process does not hide a record of a live one");

    // What runs in this daemon's own session is its to take over.
    let here = std::process::Command::new(system("PING.EXE"))
        .args(["-n", "600", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("a process in this session");
    let mut here = EndedOnDrop(here);
    let identity = kr_ipc::identity::process_start_identity(here.0.id()).expect("its identity");
    let host = TempHost::create();
    leave(&host, Left::Worker, &identity);
    start_daemon(&host)
        .await
        .expect("a worker in this daemon's own session is taken over");

    // A launch that reported no process cannot be followed by a claim, so it is not work.
    let host = TempHost::create();
    leave(&host, Left::SpawnedWithNoProcess, &identity);
    start_daemon(&host)
        .await
        .expect("a launch with no process is not work in another session");

    // What has ended is not work: after a sign-out nothing of it runs.
    let host = TempHost::create();
    leave(&host, Left::Worker, &elsewhere.identity);
    elsewhere.end();
    until_ended(&elsewhere.identity);
    start_daemon(&host)
        .await
        .expect("a worker that has ended in another session is not work");
    let _ = here.0.kill();
}

/// KR-REQ-07.58: a recorded number that now belongs to a process this account cannot open is not
/// work in another session. The processes of an environment are created by a task of the account
/// that runs its daemon, which can open them, so a number it cannot open is another account's
/// process, and a daemon that refused to start for it could not be cleared by anything but a
/// restart of the machine. The account that runs this finds such a number among the processes of
/// the machine when it has one; a run that is to have one, as the standard account of the sign-out
/// leg does, says so in `KR_EXPECT_UNOPENABLE_PROCESS`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_process_this_account_cannot_open_is_not_work_in_another_session() {
    use kr_ipc::identity::{ProcessState, process_state};
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};

    let unopenable = (4..100_000_u64).step_by(4).find_map(|pid| {
        let recorded =
            ProcessStartIdentity::new(pid, ProcessStartSource::WindowsProcessCreationTime, 1);
        matches!(process_state(&recorded), ProcessState::Unknown { .. }).then_some(recorded)
    });
    let Some(recorded) = unopenable else {
        assert!(
            std::env::var_os("KR_EXPECT_UNOPENABLE_PROCESS").is_none(),
            "this account was to find a process it cannot open and found none"
        );
        return;
    };
    println!(
        "the process this account cannot open: {}",
        recorded.pid.get()
    );
    for left in [Left::Worker, Left::Claimed] {
        let host = TempHost::create();
        leave(&host, left, &recorded);
        start_daemon(&host).await.unwrap_or_else(|refused| {
            panic!("{left:?} work on a number it cannot open: {refused}")
        });
    }
}

/// Ends the process it holds when it is dropped.
struct EndedOnDrop(std::process::Child);

impl Drop for EndedOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until the kernel says the recorded process is gone.
fn until_ended(identity: &kr_protocol::identity::ProcessStartIdentity) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while kr_ipc::identity::process_state(identity) == kr_ipc::identity::ProcessState::Running {
        assert!(Instant::now() < deadline, "the process did not end");
        std::thread::sleep(Duration::from_millis(100));
    }
}
