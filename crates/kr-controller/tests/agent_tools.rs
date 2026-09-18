//! What a refused installation change leaves behind.
//!
//! Installing and removing the contact skill change files, so section 9 applies: a marker is
//! written before the change and an outcome after it, and a marker with no outcome means the change
//! may have happened. What this covers is the other side of that rule. A change the daemon will not
//! make must be refused *before* the marker, or an exact retry would answer `OUTCOME_UNKNOWN` about
//! a change that never began, and the person asking would be told to go and look at files nothing
//! ever touched.
//!
//! The refusal used here is a removal at project scope with no project directory: it is decided
//! from the request alone, so nothing outside this test's own temporary host is read or written.

use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};

/// A supervisor that starts nothing. No worker is needed to ask the daemon to remove a skill.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    state_dir: std::path::PathBuf,
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let state_dir = environment.state_dir().to_path_buf();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store(CONTROLLER_SECRET_SERVICE, &secrets)
                .expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Host {
        _temp: temp,
        _controller: controller,
        environment_id,
        endpoint,
        state_dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_the_daemon_will_not_do_leaves_no_dispatch_marker() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    // A project removal that says nothing about which project. There is no such removal to do.
    let params = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::null(),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());

    let refused = client
        .mutate(Method::AgentToolsRemove, action_id, target.clone(), &params)
        .await
        .expect("the call reaches the daemon")
        .expect_err("and is refused");

    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    let actions = host.state_dir.join("agent-tools/actions");
    assert!(
        !actions.exists()
            || std::fs::read_dir(&actions)
                .expect("reads the directory")
                .next()
                .is_none(),
        "a refusal before the change writes no marker, so an exact retry is refused again rather \
         than answered as an outcome nobody knows"
    );

    // The same request again is refused the same way, not answered with an unknown outcome.
    let again = client
        .mutate(Method::AgentToolsRemove, action_id, target, &params)
        .await
        .expect("the call reaches the daemon")
        .expect_err("and is refused again");
    assert_eq!(again.code, ErrorCode::InvalidArgument, "{again:?}");
}
