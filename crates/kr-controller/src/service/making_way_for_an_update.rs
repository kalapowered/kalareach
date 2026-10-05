use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_crypto::store::MemoryStore;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};
use kr_protocol::update::{
    HandoverStep, HostUpdateHandoverParams, HostUpdateHandoverResult, ReleaseName,
};

use crate::service::{Controller, ControllerSetup};
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

use super::host::Handover;

/// How long a wait for something that is going to happen is given.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(60);

/// A supervisor that records every launch it was asked for, and starts nothing.
#[derive(Debug, Default)]
struct Recording {
    asked: Arc<Mutex<Vec<WorkerLaunch>>>,
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(launch.clone());
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that records every launch and starts nothing"
    }
}

fn target() -> ReleaseName {
    ReleaseName::new("0.2.0+4254aa6e62e5").expect("a release")
}

/// Begins an attempt on `handover` that holds for `hold`.
fn begin(handover: &Handover, hold: Duration) -> Uuid {
    handover.close(&target(), hold).expect("an attempt begins")
}

/// A create passes an open gate, is refused by a closed one with the release the host is being
/// updated to, and passes again once the attempt is ended, or once its hold has lapsed.
#[test]
fn a_create_passes_an_open_gate_and_is_refused_by_a_closed_one() {
    let handover = Handover::default();
    drop(handover.admit().expect("the gate is open"));
    let attempt = begin(&handover, Duration::from_secs(300));
    let refused = handover.admit().err().expect("the gate is closed");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(
        refused.to_string().contains("0.2.0+4254aa6e62e5"),
        "{refused}"
    );
    assert_eq!(handover.resume(None).expect("resumes"), Some(attempt));
    drop(handover.admit().expect("the gate is open again"));

    // A hold that lapses opens the gate by itself, and then nothing stops the daemon.
    let lapsed = begin(&handover, Duration::ZERO);
    drop(handover.admit().expect("a lapsed gate is open"));
    assert!(handover.stop(Some(lapsed)).is_err());
}

/// A handover waits for the creates under way, and says how many did not settle in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handover_waits_for_the_creates_under_way() {
    let handover = Arc::new(Handover::default());
    let under_way = handover.admit().expect("admitted");
    begin(&handover, Duration::from_secs(300));
    assert_eq!(
        handover.settle(Duration::from_millis(50)).await,
        1,
        "a create under way is waited for, and the wait ends at its bound"
    );
    // The control: once the create settles, the wait ends with nothing left under way.
    let settling = {
        let handover = Arc::clone(&handover);
        tokio::spawn(async move { handover.settle(LIVENESS_DEADLINE).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(under_way);
    assert_eq!(settling.await.expect("the wait ends"), 0);
}

/// Only a prepared daemon is told to stop; once it is, whoever waits for its stop is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_prepared_daemon_is_told_to_stop() {
    let handover = Arc::new(Handover::default());
    assert!(
        handover.stop(Some(Uuid::from_bytes([1; 16]))).is_err(),
        "an open gate is never stopped"
    );
    let waiting = {
        let handover = Arc::clone(&handover);
        tokio::spawn(async move { handover.stopped().await })
    };
    let attempt = begin(&handover, Duration::from_secs(300));
    assert_eq!(
        handover.stop(None).err().map(|error| error.code()),
        Some(ErrorCode::InvalidArgument),
        "a stop names its attempt"
    );
    handover
        .stop(Some(attempt))
        .expect("a prepared daemon stops");
    tokio::time::timeout(LIVENESS_DEADLINE, waiting)
        .await
        .expect("the stop is seen")
        .expect("the waiter ends");
}

/// A daemon told to stop does not resume or prepare again, and one that has resumed is not
/// stopped: whichever comes first decides, so an updater that sees a daemon resume knows no stop of
/// the attempt will end it.
#[test]
fn a_stopping_daemon_does_not_resume_and_a_resumed_one_does_not_stop() {
    let stopped = Handover::default();
    let attempt = begin(&stopped, Duration::from_secs(300));
    stopped
        .stop(Some(attempt))
        .expect("a prepared daemon stops");
    // Asked again for the same attempt, it stops still: an updater that lost the answer asks again.
    stopped
        .stop(Some(attempt))
        .expect("the same stop is repeated");
    let refused = stopped
        .resume(None)
        .expect_err("a stopping daemon does not resume");
    assert_eq!(refused.code(), ErrorCode::EnvironmentUnavailable);
    let refused = stopped
        .close(&target(), Duration::from_secs(300))
        .expect_err("a stopping daemon does not prepare");
    assert_eq!(refused.code(), ErrorCode::EnvironmentUnavailable);

    // The control: resumed first, it is not stopped, and its gate is open.
    let resumed = Handover::default();
    let attempt = begin(&resumed, Duration::from_secs(300));
    resumed
        .resume(Some(attempt))
        .expect("a prepared daemon resumes");
    assert!(
        resumed.stop(Some(attempt)).is_err(),
        "a resumed daemon is not stopped"
    );
    drop(resumed.admit().expect("its gate is open"));
}

/// A stop belongs to the attempt it names: after its update gave up, whatever came next, a late
/// stop finds its attempt over and ends nothing, while the attempt that is open stops the daemon.
#[test]
fn a_late_stop_of_an_attempt_that_is_over_ends_nothing() {
    let handover = Handover::default();
    let first = begin(&handover, Duration::from_secs(300));
    // The update gave up, and the next one, of the same release, began.
    assert_eq!(handover.resume(None).expect("resumes"), Some(first));
    let second = begin(&handover, Duration::from_secs(300));
    assert_ne!(first, second, "each attempt has an identity of its own");
    let refused = handover
        .stop(Some(first))
        .expect_err("the first attempt is over");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(
        handover.admit().is_err(),
        "the second attempt's gate stays closed"
    );
    // A resume of the first attempt, sent late as well, does not end the second.
    assert_eq!(handover.resume(Some(first)).expect("changes nothing"), None);
    assert!(
        handover.admit().is_err(),
        "the second attempt's gate is still closed"
    );
    // Beginning another supersedes an attempt that never ended, too.
    let third = begin(&handover, Duration::from_secs(300));
    assert!(handover.stop(Some(second)).is_err(), "the second is over");
    handover.stop(Some(third)).expect("the open attempt stops");

    // The control: an attempt whose hold has lapsed is over as well.
    let lapsed = Handover::default();
    let attempt = begin(&lapsed, Duration::ZERO);
    assert!(lapsed.stop(Some(attempt)).is_err());
}

/// A daemon answers a `prepare` as prepared only while its attempt is the gate's: an attempt that
/// was resumed, superseded or lapsed while the daemon waited for its creates is over.
#[test]
fn an_attempt_is_current_only_until_it_is_over() {
    let handover = Handover::default();
    let first = begin(&handover, Duration::from_secs(300));
    assert!(handover.is_current(first));
    handover.resume(Some(first)).expect("resumes");
    assert!(!handover.is_current(first), "a resumed attempt is over");
    let second = begin(&handover, Duration::from_secs(300));
    let third = begin(&handover, Duration::from_secs(300));
    assert!(!handover.is_current(second), "a superseded attempt is over");
    assert!(handover.is_current(third));
    handover.end(third);
    assert!(!handover.is_current(third), "an ended attempt is over");
    // The control: a hold that has lapsed is over as well.
    let lapsed = begin(&handover, Duration::ZERO);
    assert!(!handover.is_current(lapsed));
}

/// A daemon does not answer a `prepare` as prepared when its attempt ended while it waited for the
/// sessions it was creating: the attempt was resumed, so nothing acts on it any more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prepare_whose_attempt_ended_while_it_settled_is_refused() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let (controller, _) = start_controller(&temp).await;
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let serving = tokio::spawn(
        Arc::clone(&controller).serve_clients(Listener::bind(&endpoint).expect("binds")),
    );
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr/0.2.0+4254aa6e62e5").expect("a build"),
    )
    .await
    .expect("reaches the daemon");

    // A create is under way, so a prepare waits for it to settle.
    let under_way = controller.handover.admit().expect("a create is under way");
    let preparing = tokio::spawn(async move {
        client
            .mutate(
                Method::HostUpdateHandover,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &HostUpdateHandoverParams {
                    step: HandoverStep::Prepare,
                    target: target(),
                    attempt: Nullable::null(),
                },
            )
            .await
    });
    // Once its gate is closed, the attempt is begun; it is resumed while the create is still
    // under way, and only then does the create settle.
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    loop {
        match controller.handover.admit() {
            Ok(another) => drop(another),
            Err(_) => break,
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the prepare did not close the gate"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        controller.handover.resume(None).expect("resumes").is_some(),
        "the attempt was open"
    );
    drop(under_way);
    let refused = preparing
        .await
        .expect("the call ends")
        .expect("the call reaches the daemon")
        .expect_err("an attempt that ended is not answered as prepared");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(
        refused.message.contains("ended while it waited"),
        "{}",
        refused.message
    );
    // The control: a prepare with nothing under way is answered.
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr/0.2.0+4254aa6e62e5").expect("a build"),
    )
    .await
    .expect("reaches the daemon");
    let answered: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &HostUpdateHandoverParams {
                step: HandoverStep::Prepare,
                target: target(),
                attempt: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
    assert!(answered.attempt.0.is_some());
    serving.abort();
}

/// KR-REQ-09.07 and 09.16: a step repeated under its action identifier, as by a caller whose
/// answer was lost, is answered with what the first one answered and does not begin another
/// attempt, and an identifier reused for a different step is refused as a reused identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prepare_repeated_under_its_action_identifier_is_answered_with_its_first_attempt() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let (controller, _) = start_controller(&temp).await;
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let serving = tokio::spawn(
        Arc::clone(&controller).serve_clients(Listener::bind(&endpoint).expect("binds")),
    );
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr/0.2.0+4254aa6e62e5").expect("a build"),
    )
    .await
    .expect("reaches the daemon");
    let step = |step: HandoverStep, attempt: Option<Uuid>| HostUpdateHandoverParams {
        step,
        target: target(),
        attempt: Nullable(attempt),
    };

    let action_id = ActionId::new(kr_ipc::new_uuid());
    let prepare = step(HandoverStep::Prepare, None);
    let first: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            action_id,
            ActionTarget::environment(environment_id),
            &prepare,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
    let attempt = first.attempt.0.expect("an attempt");
    let again: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            action_id,
            ActionTarget::environment(environment_id),
            &prepare,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the repeat is answered")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        again.attempt.0,
        Some(attempt),
        "the repeat is the first one's answer, and no other attempt began"
    );
    assert!(
        controller.handover.is_current(attempt),
        "the first attempt is still the gate's"
    );

    let reused = client
        .mutate(
            Method::HostUpdateHandover,
            action_id,
            ActionTarget::environment(environment_id),
            &step(HandoverStep::Resume, Some(attempt)),
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("an identifier reused for another step is refused");
    assert_eq!(reused.code, ErrorCode::IdConflict);
    assert!(
        controller.handover.is_current(attempt),
        "the refused step changed nothing"
    );
    serving.abort();
}

/// A daemon of a release of its own, in this process, over `temp`'s environment, whose supervisor
/// records every launch it is asked for and starts nothing.
async fn start_controller(
    temp: &kr_ipc::testing::TempHost,
) -> (Arc<Controller>, Arc<Mutex<Vec<WorkerLaunch>>>) {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let controller =
        Controller::start(ControllerSetup {
            paths: environment,
            environment_id,
            identity: Box::new(move || {
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    &MemoryStore::new(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(Recording {
                asked: Arc::clone(&asked),
            }),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-controller/0.1.0+aaaaaaaaaaaa").expect("a build"),
            release: "0.1.0+aaaaaaaaaaaa".to_owned(),
            shell_packages: None,
            terminal: Box::new(crate::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
    (controller, asked)
}

/// The whole handover through the daemon's own door: `prepare` answers how the daemon was
/// started and closes the gate, a create is refused while it is closed and started after
/// `resume`, and a second `prepare` and a `stop` end the daemon's service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_makes_way_through_its_own_door() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let (controller, asked) = start_controller(&temp).await;
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let serving = tokio::spawn(
        Arc::clone(&controller).serve_clients(Listener::bind(&endpoint).expect("binds")),
    );
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr/0.2.0+4254aa6e62e5").expect("a build"),
    )
    .await
    .expect("reaches the daemon");

    let step = |step: HandoverStep, attempt: Option<Uuid>| HostUpdateHandoverParams {
        step,
        target: target(),
        attempt: Nullable(attempt),
    };
    let create = SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    let target_of = ActionTarget::environment(environment_id);

    let answered: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Prepare, None),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
    let first = answered.attempt.0.expect("it answers the attempt it began");
    assert_eq!(answered.pid.get(), u64::from(std::process::id()));
    assert_eq!(
        answered.release,
        Nullable::some(ReleaseName::new("0.1.0+aaaaaaaaaaaa").expect("a release"))
    );
    assert_eq!(
        answered.arguments,
        std::env::args().skip(1).collect::<Vec<_>>(),
        "it answers the arguments it was started with"
    );
    assert_eq!(
        std::path::PathBuf::from(&answered.working_directory),
        std::env::current_dir().expect("this process's directory")
    );

    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &create,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("no session starts while the gate is closed");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(
        refused
            .message
            .contains("making way for release 0.2.0+4254aa6e62e5"),
        "{}",
        refused.message
    );
    assert!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "nothing was launched"
    );

    // The control: once the update is not going ahead, a create is started again.
    let resumed: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Resume, Some(first)),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon resumes")
        .to_typed()
        .expect("decodes");
    assert_eq!(resumed.attempt.0, Some(first), "it ended the attempt named");
    let _ = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &create,
        )
        .await
        .expect("the call reaches the daemon");
    assert_eq!(
        asked.lock().unwrap_or_else(PoisonError::into_inner).len(),
        1,
        "the create passed the open gate and asked for a launch"
    );

    // A stop with no attempt open is refused; a stop that names none is refused as well.
    let refused = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Stop, Some(first)),
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("an attempt that is over never stops the daemon");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    let prepared: HostUpdateHandoverResult = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Prepare, None),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares again")
        .to_typed()
        .expect("decodes");
    let second = prepared.attempt.0.expect("it answers the attempt it began");
    assert_ne!(first, second, "each attempt has an identity of its own");
    // The first attempt's stop, arriving late over its own connection, ends nothing now that the
    // second has begun; nor does a stop that names none.
    for late in [Some(first), None] {
        let refused = client
            .mutate(
                Method::HostUpdateHandover,
                ActionId::new(kr_ipc::new_uuid()),
                target_of.clone(),
                &step(HandoverStep::Stop, late),
            )
            .await
            .expect("the call reaches the daemon")
            .expect_err("only the open attempt stops the daemon");
        assert!(
            matches!(
                refused.code,
                ErrorCode::ResourceUnavailable | ErrorCode::InvalidArgument
            ),
            "{refused:?}"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), controller.handed_over())
            .await
            .is_err(),
        "the daemon still serves"
    );
    client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Stop, Some(second)),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the attempt that is open stops the daemon");
    tokio::time::timeout(LIVENESS_DEADLINE, controller.handed_over())
        .await
        .expect("the daemon is told to stop");
    // Still serving while it goes, it answers, and does not resume or prepare.
    for (again, attempt) in [
        (HandoverStep::Resume, None),
        (HandoverStep::Prepare, None),
        (HandoverStep::Resume, Some(second)),
    ] {
        let refused = client
            .mutate(
                Method::HostUpdateHandover,
                ActionId::new(kr_ipc::new_uuid()),
                target_of.clone(),
                &step(again, attempt),
            )
            .await
            .expect("the call reaches the daemon")
            .expect_err("a stopping daemon takes no other step");
        assert_eq!(refused.code, ErrorCode::EnvironmentUnavailable);
    }
    serving.abort();
}
