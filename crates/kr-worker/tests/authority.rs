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
    host_producing(generation, "sleep 30").await
}

async fn host_producing(generation: u64, script: &str) -> Host {
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
            arguments: vec!["-c".to_owned(), script.to_owned()],
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
    let service = Arc::new(
        WorkerService::new(
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
        )
        .expect("a worker service"),
    );
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
    let mutation = kr_protocol::envelope::ControlFrame::Mutation(Box::new(
        kr_protocol::envelope::MutationRequest {
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
        },
    ));
    client
        .writer()
        .write_message(&mutation)
        .await
        .expect("writes the mutation");
    let reply = client.recv().await.expect("the worker answers");
    let kr_protocol::envelope::ControlFrame::Response(response) = reply else {
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

/// Sends one prepared mutation on a live connection and returns what the worker answered.
async fn send_mutation(
    client: &mut LocalClient,
    mutation: kr_protocol::envelope::MutationRequest,
) -> kr_protocol::envelope::Outcome {
    client
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the worker answers") {
            kr_protocol::envelope::ControlFrame::Response(response) => return response.outcome,
            kr_protocol::envelope::ControlFrame::Notification(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

fn close_mutation(
    client: &LocalClient,
    host: &Host,
    ttl_ms: u64,
    expected: kr_protocol::envelope::ParamsValue,
) -> kr_protocol::envelope::MutationRequest {
    kr_protocol::envelope::MutationRequest {
        request_id: kr_protocol::ids::RequestId::new(91),
        method: Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: target(host.environment_id, host.session_id),
        expected,
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(ttl_ms),
        params: kr_protocol::envelope::ParamsValue::from_typed(
            &kr_protocol::session::SessionCloseParams {
                session_id: host.session_id,
            },
        )
        .expect("encodes"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_whose_accepted_lifetime_is_already_spent_is_not_dispatched() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mutation = close_mutation(
        &client,
        &host,
        0,
        kr_protocol::envelope::ParamsValue::empty(),
    );
    let outcome = send_mutation(&mut client, mutation).await;
    let kr_protocol::envelope::Outcome::Error(error) = outcome else {
        panic!("a request with no lifetime left must not close the session");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_precondition_that_names_a_fact_and_says_nothing_about_it_is_refused() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert("session_state".to_owned(), kr_cbor::CanonicalValue::Null)
        .expect("one key");
    let mutation = close_mutation(
        &client,
        &host,
        30_000,
        kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
    );
    let outcome = send_mutation(&mut client, mutation).await;
    let kr_protocol::envelope::Outcome::Error(error) = outcome else {
        panic!("an explicit null is not the same as no precondition");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_precondition_the_subject_no_longer_satisfies_refuses_the_mutation() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "session_state".to_owned(),
            kr_cbor::CanonicalValue::text("closed"),
        )
        .expect("one key");
    let mutation = close_mutation(
        &client,
        &host,
        30_000,
        kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
    );
    let outcome = send_mutation(&mut client, mutation).await;
    let kr_protocol::envelope::Outcome::Error(error) = outcome else {
        panic!("a precondition that does not hold must refuse the mutation");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict);
    assert_eq!(host.service.runtime().state().as_str(), "live");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_is_answered_even_after_its_own_effect_moved_the_subject() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            "session_state".to_owned(),
            kr_cbor::CanonicalValue::text("live"),
        )
        .expect("one key");
    let mutation = close_mutation(
        &client,
        &host,
        30_000,
        kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
    );
    let first = send_mutation(&mut client, mutation.clone()).await;
    assert!(
        matches!(first, kr_protocol::envelope::Outcome::Ok(_)),
        "the close is accepted while the session is live"
    );
    // The close moved the session out of `live`, which is the precondition its own envelope
    // named. The retry must still receive the retained result rather than a refusal.
    let second = send_mutation(&mut client, mutation).await;
    assert!(
        matches!(second, kr_protocol::envelope::Outcome::Ok(_)),
        "an exact retry receives the result the first request produced"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_hello_cannot_change_what_a_connection_is() {
    let host = host(1).await;
    let mut first = controller_client(&host, 1).await;
    let mut second = controller_client(&host, 1).await;
    read_session(&mut second, host.session_id)
        .await
        .expect("the replacement connection is served");
    // The first connection is fenced. Announcing itself as an ordinary local client would be a way
    // round the authority check, so a second hello is refused outright.
    first
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Hello(
            kr_protocol::local::LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Cli,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
            },
        ))
        .await
        .expect("writes the hello");
    let reply = first.recv().await.expect("the worker answers");
    let kr_protocol::envelope::ControlFrame::Response(response) = reply else {
        panic!("a second hello must not be acknowledged");
    };
    assert!(matches!(
        response.outcome,
        kr_protocol::envelope::Outcome::Error(_)
    ));
    assert_eq!(
        read_session(&mut first, host.session_id).await,
        Err(ErrorCode::PermissionDenied)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_controller_that_holds_authority_announces_a_revision() {
    let host = host(1).await;
    let mut cli = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let notice = kr_protocol::worker::AuthorityRevisionNotice {
        environment_id: host.environment_id,
        revision: kr_protocol::ids::AuthorityRevision::new(4),
    };
    cli.writer()
        .write_message(&kr_protocol::envelope::ControlFrame::AuthorityRevision(
            notice,
        ))
        .await
        .expect("writes the notice");
    let reply = cli.recv().await.expect("the worker answers");
    assert!(
        matches!(
            reply,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Error(_),
                ..
            })
        ),
        "an ordinary local caller does not announce the host's authority"
    );
    assert_eq!(host.service.acknowledged_revision(), None);

    let mut controller = controller_client(&host, 1).await;
    controller
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::AuthorityRevision(
            notice,
        ))
        .await
        .expect("writes the notice");
    let reply = controller.recv().await.expect("the worker answers");
    let kr_protocol::envelope::ControlFrame::AuthorityRevisionAck(ack) = reply else {
        panic!("the controller's announcement is acknowledged");
    };
    assert_eq!(ack.revision.get(), 4);
    assert_eq!(ack.session_id, host.session_id);
    assert_eq!(
        host.service.acknowledged_revision().map(|held| held.get()),
        Some(4)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscription_on_a_fenced_connection_stops_delivering() {
    // The transport names this one as the host's own: section 9's dispatch barrier covers a
    // mutation, and it does not cover a read or a subscription that was already running when the
    // authority behind it was withdrawn. Refusing the fenced connection's *next* request would
    // leave its delivery task streaming this session's output for as long as it kept quiet.
    let host = host_producing(1, "while true; do printf 'line\\n'; sleep 1; done").await;
    let mut first = controller_client(&host, 1).await;

    let attached: kr_protocol::attachment::SessionAttachResult = first
        .mutate(
            Method::SessionAttach,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    let mut streams = kr_protocol::scalars::CanonicalSet::new();
    streams.insert(kr_protocol::recovery::EventStream::Output);
    first
        .request(
            Method::EventsSubscribe,
            &kr_protocol::recovery::EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id: attached.attachment.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
    assert!(
        output_within(&mut first, std::time::Duration::from_secs(4)).await,
        "the subscription is delivering before anything is fenced"
    );

    // A replacement daemon binds the authority. The first connection is fenced.
    let mut second = controller_client(&host, 2).await;
    read_session(&mut second, host.session_id)
        .await
        .expect("the replacement connection is served");

    // Whatever the delivery task had already written is in the socket, so it is read off first.
    // What the fence decides is whether anything *new* arrives, and the shell writes a line every
    // second, so three quiet seconds is the answer.
    let _already_in_flight = output_within(&mut first, std::time::Duration::from_millis(500)).await;
    while output_within(&mut first, std::time::Duration::from_millis(200)).await {}
    assert!(
        !output_within(&mut first, std::time::Duration::from_secs(3)).await,
        "the fenced connection's subscription stopped delivering"
    );
    assert_eq!(
        read_session(&mut first, host.session_id).await,
        Err(ErrorCode::PermissionDenied),
        "and its next request says why"
    );
}

/// Returns whether any session output reaches this client inside `window`.
async fn output_within(client: &mut LocalClient, window: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            return false;
        };
        if let kr_protocol::envelope::ControlFrame::Notification(notification) = frame
            && notification.event_type.as_str() == "session.output"
        {
            return true;
        }
    }
    false
}

fn attach_params(session_id: SessionId) -> kr_protocol::attachment::SessionAttachParams {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}
