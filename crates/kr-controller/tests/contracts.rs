//! The two contracts the transport cannot keep for the host.
//!
//! `docs/transport/README.md` names them under "What the host owes":
//!
//! * **Admission and revocation.** The final validation of a caller's record and the registration
//!   of its connection are one step, and the registration stays revocable for the life of the
//!   session. Section 9's dispatch barrier covers a worker's dispatch; it does not cover a read on
//!   a connection that was authorised a moment before authority was withdrawn.
//! * **Work that must complete.** A durable commit belongs to an owner that outlives the
//!   connection, because a handler is dropped the moment its control stream ends and dropping a
//!   future is a cancellation.
//!
//! Both are observable from outside, and this is where they are observed.

use std::sync::Arc;
use std::time::Duration;

use kr_controller::registry::{LaunchPhase, Registry};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCreateParams, SessionListParams, ShellMode};

/// A supervisor that takes its time and then says it started nothing.
///
/// The delay is what makes the second contract observable: the caller's connection is gone well
/// before the daemon has finished with its request, so whether the work completed says whether the
/// work belonged to the connection or to something that outlives it.
#[derive(Debug)]
struct SlowSupervisor;

/// How long the supervisor takes, which is far longer than dropping a socket takes.
const LAUNCH_DELAY: Duration = Duration::from_millis(700);

impl WorkerSupervisor for SlowSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        std::thread::sleep(LAUNCH_DELAY);
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that takes its time and starts nothing".to_owned()
    }
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    registry_path: std::path::PathBuf,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let registry_path = environment.registry_database();
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
        supervisor: Box::new(SlowSupervisor),
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
        controller,
        environment_id,
        endpoint,
        registry_path,
    }
}

fn create_params(environment_id: EnvironmentId) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_withdraws_a_connection_that_was_already_admitted() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::some(host.environment_id),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("an admitted connection is served");

    // Authority is withdrawn while the connection is open and idle. Nothing about this connection
    // changed; what changed is the authority it was admitted under.
    let status = host
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    assert!(
        status.acknowledged.is_empty() && status.pending.is_empty(),
        "no worker is running, so there is nothing for the revocation to be pending on"
    );

    let refused = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::some(host.environment_id),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon");
    let Err(error) = refused else {
        panic!("a connection whose authority was withdrawn is not served");
    };
    assert_eq!(
        error.code,
        ErrorCode::PermissionDenied,
        "the read is fenced, not merely recorded as fenced: {error:?}"
    );

    // A fresh connection is admitted again, because the operating-system caller's own record is
    // unchanged. The registration is what was withdrawn, not the person's right to use the host.
    let mut reconnected = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reconnects");
    reconnected
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::some(host.environment_id),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("a newly admitted connection is served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_durable_commit_finishes_after_its_caller_has_gone() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let params = ParamsValue::from_typed(&create_params(host.environment_id)).expect("encodes");
    let mutation = MutationRequest {
        request_id: kr_protocol::ids::RequestId::new(1),
        method: Method::SessionCreate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(host.environment_id),
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params,
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");

    // The caller goes away immediately, long before the supervisor has finished. Whether the work
    // completes now says whether it belonged to the connection or to an owner that outlives it.
    drop(client);
    tokio::time::sleep(LAUNCH_DELAY * 3).await;

    let registry = Registry::open(host.registry_path.clone(), host.environment_id)
        .expect("reads the registry");
    let resolved = registry
        .reservations_in(LaunchPhase::Failed)
        .expect("reads the reservations");
    assert_eq!(
        resolved.len(),
        1,
        "the create was carried through to a durable outcome with nobody left to tell"
    );
    assert_eq!(
        resolved[0].create_token,
        action_id.get(),
        "and it is the create the caller asked for"
    );
    let unresolved = registry
        .reservations_in(LaunchPhase::Reserved)
        .expect("reads the reservations");
    assert!(
        unresolved.is_empty(),
        "nothing was left half done at the point the connection ended"
    );
}
