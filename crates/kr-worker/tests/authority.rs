//! Controller authority at the worker's endpoint.
//!
//! A worker serves two kinds of caller. The local command line is authenticated by peer
//! credentials. A controller acts for a generation, and a generation that has been superseded, or
//! a connection that has been replaced, must stop working the moment it is fenced. These tests use
//! the real endpoint, the real handshake and the real signatures, because that is where fencing
//! either happens or does not.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Dimensions, DisplayNumber, SessionReadParams, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host(generation: u64) -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store = kr_crypto::store::open_store("KalaReachTest", &environment.secrets_dir())
        .expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts the runtime"));

    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(WorkerService::new(
        Arc::clone(&runtime),
        identity,
        endpoint.clone(),
        ServiceBinding {
            environment_id,
            boot_identity: boot.clone(),
            controller_public_key: *controller.public_key(),
            controller_generation: ControllerGeneration::new(generation),
            build_id: build(),
        },
    ));
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

async fn controller_client(host: &Host, generation: u64) -> LocalClient {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

async fn read_session(
    client: &mut LocalClient,
    session_id: SessionId,
) -> std::result::Result<(), ErrorCode> {
    let outcome = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the worker");
    outcome.map(|_| ()).map_err(|error| error.code)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_controller_connection_stops_being_served() {
    let host = host(1).await;
    let mut first = controller_client(&host, 1).await;
    read_session(&mut first, host.session_id)
        .await
        .expect("the first connection is served");

    // A second connection of the same generation is exactly what a reconnecting daemon makes. It
    // fences the first, and the first must stop working from the reply onwards.
    let mut second = controller_client(&host, 1).await;
    read_session(&mut second, host.session_id)
        .await
        .expect("the replacement connection is served");
    assert_eq!(
        read_session(&mut first, host.session_id).await,
        Err(ErrorCode::PermissionDenied),
        "the fenced connection is refused at dispatch, not merely recorded as fenced"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_superseded_generation_cannot_dispatch_afterwards() {
    let host = host(1).await;
    let mut old = controller_client(&host, 1).await;
    read_session(&mut old, host.session_id)
        .await
        .expect("the first generation is served");
    let mut new = controller_client(&host, 2).await;
    read_session(&mut new, host.session_id)
        .await
        .expect("the higher generation is served");
    assert_eq!(
        read_session(&mut old, host.session_id).await,
        Err(ErrorCode::PermissionDenied),
        "a daemon that lost the lock cannot keep acting through its old connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_controller_that_has_not_proved_a_generation_is_refused() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
    assert_eq!(
        read_session(&mut client, host.session_id).await,
        Err(ErrorCode::PermissionDenied),
        "announcing a controller is not the same as proving which generation it speaks for"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_needs_no_generation() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    read_session(&mut client, host.session_id)
        .await
        .expect("the local caller is served under its own authenticated identity");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_that_quotes_an_unknown_window_is_not_admitted() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let params =
        kr_protocol::envelope::ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: host.session_id,
        })
        .expect("encodes");
    let request_id = kr_protocol::ids::RequestId::new(41);
    let mutation =
        kr_protocol::local::ControlMessage::Mutation(kr_protocol::envelope::MutationRequest {
            request_id,
            method: Method::SessionClose.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: target(host.environment_id, host.session_id),
            expected: kr_protocol::envelope::ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("local:invented")
                .expect("a window"),
            requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
            params,
        });
    client
        .writer()
        .write_message(&mutation)
        .await
        .expect("writes the mutation");
    let reply = client.recv().await.expect("the worker answers");
    let kr_protocol::local::ControlMessage::Response(response) = reply else {
        panic!("the worker answered something other than a response");
    };
    let kr_protocol::envelope::Outcome::Error(error) = response.outcome else {
        panic!("a window this connection was never given must not admit a close");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_for_another_session_is_stale_rather_than_served() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let elsewhere = SessionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(
            Method::SessionClose,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            target(host.environment_id, elsewhere),
            &kr_protocol::session::SessionCloseParams {
                session_id: elsewhere,
            },
        )
        .await
        .expect("the call reaches the worker");
    assert_eq!(
        outcome.err().map(|error| error.code),
        Some(ErrorCode::StaleSession),
        "the envelope's target is checked, not only the parameters"
    );
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

fn target(
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
) -> kr_protocol::envelope::ActionTarget {
    kr_protocol::envelope::ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}
