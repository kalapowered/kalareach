//! What the control daemon accepts on its client endpoint.
//!
//! Admission happens before anything is spawned, so the envelope checks are the first thing a
//! create meets. These run the real endpoint, the real handshake and the real envelope path, with
//! a supervisor that starts nothing: a create that reaches the supervisor has passed every check
//! this daemon makes, and a create that is refused before it was refused for a reason named here.

use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::envelope::{ActionTarget, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCloseParams, SessionCreateParams, ShellMode};

/// A supervisor that starts nothing and says so.
#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RefusingSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Host {
        _temp: temp,
        environment_id,
        endpoint,
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
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

async fn client(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_the_command_line_sends_reaches_admission() {
    let host = host().await;
    let mut client = client(&host).await;
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id),
        )
        .await
        .expect("the call reaches the daemon");
    // The supervisor refuses, which is as far as this test goes. What matters is that the envelope
    // checks let the request through to it rather than refusing it first.
    let Err(error) = outcome else {
        panic!("this supervisor starts nothing, so the create cannot succeed");
    };
    assert_eq!(
        error.code,
        ErrorCode::ResourceUnavailable,
        "a valid create is refused by the supervisor, not by the envelope: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_names_a_session_is_refused() {
    let host = host().await;
    let mut client = client(&host).await;
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &create_params(host.environment_id),
        )
        .await
        .expect("the call reaches the daemon");
    assert_eq!(
        outcome.err().map(|error| error.code),
        Some(ErrorCode::InvalidArgument),
        "a create allocates the session it is for, so it names none"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_whose_target_and_parameters_disagree_is_refused() {
    let host = host().await;
    let mut client = client(&host).await;
    let named = SessionId::new(kr_ipc::new_uuid());
    let elsewhere = SessionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(named),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionCloseParams {
                session_id: elsewhere,
            },
        )
        .await
        .expect("the call reaches the daemon");
    assert_eq!(
        outcome.err().map(|error| error.code),
        Some(ErrorCode::InvalidArgument),
        "the session the request points at is the session it acts on"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_that_quotes_an_unknown_window_is_not_admitted() {
    let host = host().await;
    let mut client = client(&host).await;
    let params = ParamsValue::from_typed(&create_params(host.environment_id)).expect("encodes");
    let request_id = kr_protocol::ids::RequestId::new(77);
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(
            kr_protocol::envelope::MutationRequest {
                request_id,
                method: Method::SessionCreate.into(),
                method_version: kr_protocol::method::MethodVersion::V1,
                action_id: ActionId::new(kr_ipc::new_uuid()),
                grant_id: Nullable::null(),
                target: ActionTarget::environment(host.environment_id),
                expected: ParamsValue::empty(),
                action_window_id: kr_protocol::ids::ActionWindowId::new("local:invented")
                    .expect("a window"),
                requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
                params,
            },
        )))
        .await
        .expect("writes the mutation");
    let ControlFrame::Response(response) = client.recv().await.expect("the daemon answers") else {
        panic!("the daemon answered something other than a response");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("a window this connection was never given admits nothing");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_launch_frees_the_slot_it_reserved() {
    let host = host().await;
    let mut client = client(&host).await;
    for _ in 0..3 {
        let outcome = client
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &create_params(host.environment_id),
            )
            .await
            .expect("the call reaches the daemon");
        assert!(outcome.is_err(), "this supervisor starts nothing");
    }
    // A launch that is confirmed not to have started occupies nothing, so the environment reports
    // no live sessions however many creates were refused.
    let info = client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.info succeeds");
    let info: kr_protocol::hostinfo::HostInfoResult = info.to_typed().expect("decodes");
    assert_eq!(info.live_sessions.get(), 0);
}
