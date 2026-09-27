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
use kr_protocol::scalars::Nullable;
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

/// A create passes an open gate, is refused by a closed one with the release the host is being
/// updated to, and passes again once the gate is opened, or once its hold has lapsed.
#[test]
fn a_create_passes_an_open_gate_and_is_refused_by_a_closed_one() {
    let handover = Handover::default();
    drop(handover.admit().expect("the gate is open"));
    handover.close(&target(), Duration::from_secs(300));
    let refused = handover.admit().err().expect("the gate is closed");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(
        refused.to_string().contains("0.2.0+4254aa6e62e5"),
        "{refused}"
    );
    handover.open();
    drop(handover.admit().expect("the gate is open again"));

    // A hold that lapses opens the gate by itself, and then nothing stops the daemon.
    handover.close(&target(), Duration::ZERO);
    drop(handover.admit().expect("a lapsed gate is open"));
    assert!(handover.stop().is_err());
}

/// A handover waits for the creates under way, and says how many did not settle in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handover_waits_for_the_creates_under_way() {
    let handover = Arc::new(Handover::default());
    let under_way = handover.admit().expect("admitted");
    handover.close(&target(), Duration::from_secs(300));
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
    assert!(handover.stop().is_err(), "an open gate is never stopped");
    let waiting = {
        let handover = Arc::clone(&handover);
        tokio::spawn(async move { handover.stopped().await })
    };
    handover.close(&target(), Duration::from_secs(300));
    handover.stop().expect("a prepared daemon stops");
    tokio::time::timeout(LIVENESS_DEADLINE, waiting)
        .await
        .expect("the stop is seen")
        .expect("the waiter ends");
}

/// The whole handover through the daemon's own door: `prepare` answers how the daemon was
/// started and closes the gate, a create is refused while it is closed and started after
/// `resume`, and a second `prepare` and a `stop` end the daemon's service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_makes_way_through_its_own_door() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let controller =
        Controller::start(ControllerSetup {
            paths: environment.clone(),
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

    let step = |step: HandoverStep| HostUpdateHandoverParams {
        step,
        target: target(),
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
            &step(HandoverStep::Prepare),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
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
    client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Resume),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon resumes");
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

    // A stop before a prepare is refused, and after one ends the daemon's service.
    let refused = client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            target_of.clone(),
            &step(HandoverStep::Stop),
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("an open gate is never stopped");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    for (step_now, expected) in [
        (HandoverStep::Prepare, "prepares"),
        (HandoverStep::Stop, "stops"),
    ] {
        client
            .mutate(
                Method::HostUpdateHandover,
                ActionId::new(kr_ipc::new_uuid()),
                target_of.clone(),
                &step(step_now),
            )
            .await
            .expect("the call reaches the daemon")
            .unwrap_or_else(|error| panic!("the daemon {expected}: {error:?}"));
    }
    tokio::time::timeout(LIVENESS_DEADLINE, controller.handed_over())
        .await
        .expect("the daemon is told to stop");
    serving.abort();
}
