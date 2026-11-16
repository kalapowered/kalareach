//! Controller authority at the worker's endpoint.
//!
//! A worker serves two kinds of caller. The local command line is authenticated by peer
//! credentials. A controller acts for a generation, and a generation that has been superseded, or
//! a connection that has been replaced, must stop working the moment it is fenced. These tests use
//! the real endpoint, the real handshake and the real signatures, because that is where fencing
//! either happens or does not.

use std::sync::Arc;

use kr_ipc::client::{BoundLink, Client, Codec, LocalClient};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AuthorityRevision, BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Dimensions, DisplayNumber, SessionReadParams, ShellMode};
use kr_protocol::worker::{AuthorityRevisionNotice, RevisionReach};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

struct Host {
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: kr_protocol::ids::EnvironmentId,
    // Ends the serving task when the fixture is dropped, whether or not a case closed it.
    _serving: kr_ipc::testing::Serving,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

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
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    let serving = kr_ipc::testing::Serving::spawn(Arc::clone(&service).serve(listener));
    Host {
        _serving: serving,
        _temp: temp,
        service,
        session_id,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

async fn controller_client(host: &Host, generation: u64) -> BoundLink {
    let mut client = BoundLink::connect(&host.endpoint, build())
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

/// What a test needs to sign a controller's generation token on a task of its own.
struct Signer {
    identity: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

impl Host {
    fn signer(&self) -> Signer {
        Signer {
            identity: Arc::clone(&self.controller),
            boot: self.boot.clone(),
        }
    }
}

/// Answers the challenge `link` was given with a token for `generation`.
async fn present(
    link: &mut BoundLink,
    signer: Signer,
    generation: u64,
) -> kr_ipc::Result<kr_protocol::worker::GenerationAccepted> {
    link.present_generation(move |nonce| {
        signer
            .identity
            .generation_token(ControllerGeneration::new(generation), &signer.boot, nonce)
            .map_err(kr_ipc::IpcError::from)
    })
    .await
}

/// A connection that has said hello and been challenged, is declared for `role`, and has not
/// presented anything.
async fn declared(host: &Host, role: ControllerConnectionRole) -> BoundLink {
    let mut link = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    link.send(&ControlFrame::ControllerRole(role))
        .await
        .expect("declares the role");
    match link.recv().await.expect("the worker answers") {
        ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
        other => panic!("the worker answered {other:?}"),
    }
    link
}

/// A signer whose token the worker cannot authenticate: another controller's key, for this
/// environment or for another one.
fn foreign(host: &Host, for_this_environment: bool) -> Signer {
    let other = kr_ipc::testing::TempHost::create();
    let environment_id = if for_this_environment {
        host.environment_id
    } else {
        other.environment_id()
    };
    let store = kr_crypto::store::open_store_in(&other.environment().secrets_dir())
        .expect("a secret store");
    let identity = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a foreign controller identity");
    Signer {
        identity: Arc::new(identity),
        boot: host.boot.clone(),
    }
}

/// What a presentation that a later connection's acceptance refused came to.
fn assert_refused_for_order(result: kr_ipc::Result<kr_protocol::worker::GenerationAccepted>) {
    match result {
        Err(kr_ipc::IpcError::IdentityUnavailable { detail, .. }) => assert!(
            detail.contains("a later controller connection"),
            "the refusal says a later connection holds the authority: {detail}"
        ),
        other => panic!("the older presentation was not refused for its order: {other:?}"),
    }
}

/// What a refused read came to.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// An answer that refuses this request, on a link that is still good.
    Request(ErrorCode),
    /// The connection no longer speaks for the generation that holds the worker's authority: the
    /// refusal is a failure of the link, as a controller reads it.
    Link(ErrorCode),
}

async fn read_session(
    client: &mut Client<impl Codec>,
    session_id: SessionId,
) -> std::result::Result<(), Refused> {
    match client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
    {
        Ok(outcome) => outcome
            .map(|_| ())
            .map_err(|error| Refused::Request(error.code)),
        Err(error @ kr_ipc::IpcError::LinkFenced { .. }) => Err(Refused::Link(error.code())),
        Err(error) => panic!("the call did not reach the worker: {error}"),
    }
}

/// KR-REQ-02.05: a worker serves one controller connection at a time: a newer connection fences
/// the one before it, which stops being served at dispatch.
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
        Err(Refused::Link(ErrorCode::PermissionDenied)),
        "the fenced connection is refused at dispatch, not merely recorded as fenced"
    );
}

/// How long a test waits for a worker to reach a state it waits for by condition, and fails after.
/// Nothing is decided by it: a worker that never gets there is the one thing that runs it out.
const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// KR-REQ-02.05: a connection whose presentation reaches the worker after a newer connection's
/// does not take the authority from it, even when the older connection's daemon is still there to
/// be answered and the newer one was opened after it.
///
/// The older presentation is held where it waits for the dispatch boundary, and its client stays
/// connected: a presentation whose peer has gone is not decided at all, so the order of the two
/// connections is only what keeps a living one from fencing the other. The newer connection is
/// opened, presents, and is served. The older presentation is then let go and refused for its
/// order, and the newer connection is served again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_presentation_that_is_decided_late_does_not_fence_a_newer_connection() {
    let host = host(1).await;
    let kr_worker::service::PresentationPause {
        arrived,
        release,
        decided,
    } = host.service.pause_before_presentation();

    let mut older = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    let signer = host.signer();
    let presenting = tokio::spawn(async move { present(&mut older, signer, 1).await });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT))
        .await
        .expect("the wait ends")
        .expect("the older presentation reaches the worker's pause");

    let mut newer = controller_client(&host, 1).await;
    read_session(&mut newer, host.session_id)
        .await
        .expect("the newer connection is served");

    release.send(()).expect("the older presentation goes on");
    tokio::task::spawn_blocking(move || decided.recv_timeout(WAIT))
        .await
        .expect("the wait ends")
        .expect("the older presentation is decided");
    assert_refused_for_order(
        tokio::time::timeout(WAIT, presenting)
            .await
            .expect("the older client is answered")
            .expect("the older client's task ends"),
    );
    read_session(&mut newer, host.session_id)
        .await
        .expect("the newer connection is still served once the older presentation is decided");
}

/// KR-REQ-02.05: inside one generation, a role goes to the connection whose hello the worker
/// answered last, whichever presentation is decided last: a connection that said hello before one
/// already accepted for its role is refused, for each role that one connection holds at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_said_hello_before_an_accepted_one_is_refused_for_every_replacing_role() {
    let host = host(1).await;
    for role in [
        ControllerConnectionRole::Authority,
        ControllerConnectionRole::Attention,
        ControllerConnectionRole::Descriptions,
        ControllerConnectionRole::Checks,
    ] {
        let mut older = declared(&host, role).await;
        let mut newer = declared(&host, role).await;
        present(&mut newer, host.signer(), 1)
            .await
            .unwrap_or_else(|error| panic!("the later {role:?} connection is accepted: {error}"));
        assert_refused_for_order(present(&mut older, host.signer(), 1).await);
        if role == ControllerConnectionRole::Authority {
            read_session(&mut newer, host.session_id)
                .await
                .expect("the later connection is still served");
            assert_eq!(
                read_session(&mut older, host.session_id).await,
                Err(Refused::Link(ErrorCode::PermissionDenied)),
                "the refused connection holds nothing"
            );
        }
    }
}

/// KR-REQ-02.05: each role keeps a record of its own, so a connection accepted for one role never
/// refuses a connection of another, whatever the order of their hellos.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_record_of_one_role_refuses_no_connection_of_another() {
    let host = host(1).await;
    let mut checks = declared(&host, ControllerConnectionRole::Checks).await;
    let mut descriptions = declared(&host, ControllerConnectionRole::Descriptions).await;
    let mut attention = declared(&host, ControllerConnectionRole::Attention).await;
    let mut authority = declared(&host, ControllerConnectionRole::Authority).await;
    for link in [
        &mut authority,
        &mut attention,
        &mut descriptions,
        &mut checks,
    ] {
        present(link, host.signer(), 1)
            .await
            .expect("a connection of a role nothing was accepted for is accepted");
    }
    read_session(&mut authority, host.session_id)
        .await
        .expect("the authority connection is served");
}

/// KR-REQ-02.05: proxy connections of one generation are a set and are not ordered: the one that
/// said hello first may present last, after a proxy and an authority connection that said hello
/// after it, and every one of them is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_connections_of_one_generation_coexist_whatever_the_order_of_their_hellos() {
    let host = host(1).await;
    let mut first = declared(&host, ControllerConnectionRole::Proxy).await;
    let mut second = declared(&host, ControllerConnectionRole::Proxy).await;
    let mut authority = declared(&host, ControllerConnectionRole::Authority).await;
    present(&mut authority, host.signer(), 1)
        .await
        .expect("the authority connection is accepted");
    present(&mut second, host.signer(), 1)
        .await
        .expect("the later proxy is accepted");
    present(&mut first, host.signer(), 1)
        .await
        .expect("the earlier proxy is accepted after the later one");
    for link in [&mut first, &mut second, &mut authority] {
        read_session(link, host.session_id)
            .await
            .expect("the connection is served");
    }
}

/// KR-REQ-02.05: a higher generation takes every role at once, whatever the order of its
/// connection: it fences the connection of the lower generation even though that one said hello
/// after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_higher_generation_installs_whatever_the_order_of_its_connection() {
    let host = host(1).await;
    let mut for_the_higher = declared(&host, ControllerConnectionRole::Authority).await;
    let mut for_the_lower = declared(&host, ControllerConnectionRole::Authority).await;
    present(&mut for_the_lower, host.signer(), 1)
        .await
        .expect("the lower generation is accepted");
    read_session(&mut for_the_lower, host.session_id)
        .await
        .expect("the lower generation is served");
    present(&mut for_the_higher, host.signer(), 2)
        .await
        .expect("the higher generation installs although its connection said hello first");
    read_session(&mut for_the_higher, host.session_id)
        .await
        .expect("the higher generation is served");
    assert_eq!(
        read_session(&mut for_the_lower, host.session_id).await,
        Err(Refused::Link(ErrorCode::PermissionDenied)),
        "the lower generation is fenced"
    );
}

/// KR-REQ-02.05: the records of every role begin again with a higher generation, including when a
/// proxy connection is the one that presents it first: an attention connection that said hello
/// before the one accepted for the lower generation is accepted for the higher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_records_begin_again_with_a_higher_generation_that_a_proxy_presents_first() {
    let host = host(1).await;
    let mut waiting = declared(&host, ControllerConnectionRole::Attention).await;
    let mut accepted = declared(&host, ControllerConnectionRole::Attention).await;
    let mut proxy = declared(&host, ControllerConnectionRole::Proxy).await;
    present(&mut accepted, host.signer(), 1)
        .await
        .expect("the attention connection is accepted for the lower generation");
    present(&mut proxy, host.signer(), 2)
        .await
        .expect("a proxy presents the higher generation");
    present(&mut waiting, host.signer(), 2)
        .await
        .expect("the earlier attention connection is accepted for the higher generation");
}

/// KR-REQ-02.05: a connection that proves nothing moves no record: one that said hello and never
/// presented, one whose token another key signed, and one whose token is another environment's
/// leave an earlier connection of the same role accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_proves_nothing_moves_no_record() {
    for proof in ["nothing", "another key", "another environment"] {
        let host = host(1).await;
        let mut older = declared(&host, ControllerConnectionRole::Authority).await;
        let mut unproved = declared(&host, ControllerConnectionRole::Authority).await;
        match proof {
            "another key" => assert!(
                present(&mut unproved, foreign(&host, true), 1)
                    .await
                    .is_err(),
                "a token another key signed is refused"
            ),
            "another environment" => assert!(
                present(&mut unproved, foreign(&host, false), 1)
                    .await
                    .is_err(),
                "another environment's token is refused"
            ),
            _ => {}
        }
        present(&mut older, host.signer(), 1)
            .await
            .unwrap_or_else(|error| {
                panic!("after {proof} the earlier connection is accepted: {error}")
            });
        read_session(&mut older, host.session_id)
            .await
            .expect("the earlier connection is served");
    }
}

/// KR-REQ-02.05: the record outlives its connection: once the later connection has ended, the
/// earlier one that is still waiting to present is refused all the same.
///
/// The worker serves a bounded number of connections, and the test fills it, so that the end of
/// the later connection is a condition it can wait for: a further connection is admitted once the
/// worker has finished with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_connection_stays_refused_after_the_newer_one_has_ended() {
    let host = host(1).await;
    let mut older = declared(&host, ControllerConnectionRole::Authority).await;
    let mut newer = declared(&host, ControllerConnectionRole::Authority).await;
    present(&mut newer, host.signer(), 1)
        .await
        .expect("the later connection is accepted");
    read_session(&mut newer, host.session_id)
        .await
        .expect("the later connection is served");

    let mut fillers = Vec::new();
    while fillers.len() < kr_worker::service::MAX_CONNECTIONS - 2 {
        fillers.push(
            BoundLink::connect(&host.endpoint, build())
                .await
                .expect("the worker admits the connection"),
        );
    }
    assert!(
        BoundLink::connect(&host.endpoint, build()).await.is_err(),
        "the worker admits no more than its bound"
    );
    drop(newer);
    let deadline = tokio::time::Instant::now() + WAIT;
    let _admitted = loop {
        match BoundLink::connect(&host.endpoint, build()).await {
            Ok(link) => break link,
            Err(_) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the worker did not finish with the ended connection within {WAIT:?}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    };
    assert_refused_for_order(present(&mut older, host.signer(), 1).await);
}

/// KR-REQ-02.05: a controller connection from a generation a newer daemon has replaced cannot
/// dispatch anything afterwards.
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
        Err(Refused::Link(ErrorCode::PermissionDenied)),
        "a daemon that lost the lock cannot keep acting through its old connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_controller_that_has_not_proved_a_generation_is_refused() {
    let host = host(1).await;
    let mut client = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    assert_eq!(
        read_session(&mut client, host.session_id).await,
        Err(Refused::Link(ErrorCode::PermissionDenied)),
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

/// KR-REQ-02.07: a command line on this machine is authenticated by its operating-system peer
/// credentials: what it does is recorded under the user the kernel names for its connection, and
/// nothing it sends names anyone else. The worker still checks the scope of every request itself,
/// so a mutation aimed at another session is refused rather than served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_is_the_user_its_peer_credentials_name_and_its_scope_is_checked() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    client
        .mutate(
            Method::SessionAttach,
            action_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds");
    let user = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let receipt = host
        .service
        .runtime()
        .session()
        .journal()
        .expect("a journal")
        .read(user, action_id)
        .expect("reads the journal");
    assert!(
        receipt.is_some(),
        "the attach is recorded under the user the kernel named for this connection"
    );

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
        "an authenticated local caller is still held to the scope of this session"
    );
    assert_eq!(host.service.runtime().state().as_str(), "live");
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
    client.send(&mutation).await.expect("writes the mutation");
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
    client: &mut Client<impl Codec>,
    mutation: kr_protocol::envelope::MutationRequest,
) -> kr_protocol::envelope::Outcome {
    client
        .send(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
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
    // The close was asked for above: its own steps, the drain among them, end before the
    // fixture's directory is removed.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        host.service.runtime().wait_closed(),
    )
    .await
    .expect("the session's closure finishes after the close was accepted");
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
        .send(&kr_protocol::envelope::ControlFrame::Hello(
            kr_protocol::local::LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Cli,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
                origin: None,
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
        Err(Refused::Link(ErrorCode::PermissionDenied))
    );
}

/// KR-REQ-09.12: a read the daemon admitted under an authority revision this worker has installed
/// past is refused as an ordinary refusal of authority and its link is kept: the connection still
/// speaks for the generation that holds the worker, and only the one request lost its authority.
/// The control for the refusals above, which end their link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_admitted_under_a_revision_the_worker_has_passed_keeps_its_link() {
    use kr_protocol::actor::{ActorEnvelope, ActorIngress};
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
    use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId};
    use kr_protocol::local::ForwardedRequest;

    let host = host(1).await;
    let mut controller = controller_client(&host, 1).await;
    controller
        .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: host.environment_id,
            revision: AuthorityRevision::new(2),
            reach: kr_protocol::worker::RevisionReach::Host,
            evidence_from: 0,
        })
        .await
        .expect("the worker installs the revision");

    let read = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id: kr_protocol::ids::RequestId::new(900),
            method: Method::SessionRead.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params: ParamsValue::from_typed(&SessionReadParams {
                session_id: host.session_id,
            })
            .expect("encodes"),
        },
        actor: ActorEnvelope {
            actor_id: ActorId::new("local:test").expect("a principal"),
            ingress: ActorIngress::LocalIpc,
            device_id: Nullable::null(),
            grant_id: Nullable::null(),
            grant_revision: Nullable::some(AuthorityRevision::new(1)),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(kr_ipc::new_uuid()),
        },
        authority_deadline_boot_ms: Nullable::null(),
        history: None,
    }));
    controller.send(&read).await.expect("writes the read");
    let ControlFrame::Response(response) = controller.recv().await.expect("the worker answers")
    else {
        panic!("a read is answered with a response");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("a read admitted under a revision the worker has passed is refused");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        !error.link_fenced,
        "the request lost its authority, not the connection: {error:?}"
    );
    read_session(&mut controller, host.session_id)
        .await
        .expect("the connection is still served");
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
        reach: kr_protocol::worker::RevisionReach::Host,
        evidence_from: 0,
    };
    cli.send(&kr_protocol::envelope::ControlFrame::AuthorityRevision(
        notice.clone(),
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
        .send(&kr_protocol::envelope::ControlFrame::AuthorityRevision(
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
    expect_output_within(
        &mut first,
        LIVENESS_DEADLINE,
        "the subscription is delivering before anything is fenced",
    )
    .await;

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
        Err(Refused::Link(ErrorCode::PermissionDenied)),
        "and its next request says why"
    );
}

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never happens. The
/// windows these waits had were inside the range the slowest reference hosts reach when several
/// suites share them; two minutes is outside it, and the poll intervals are unchanged, so a wait
/// that succeeds costs what it always did. The short windows that assert output *never* arrives are
/// deliberately left as they are: they are not waiting for anything.
const LIVENESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Waits for session output to reach this client, and fails with how long it waited when none does.
async fn expect_output_within(
    client: &mut Client<impl Codec>,
    window: std::time::Duration,
    what: &str,
) {
    let started = tokio::time::Instant::now();
    assert!(
        output_within(client, window).await,
        "{what}: waited {:?} for a session.output notification",
        started.elapsed()
    );
}

/// Returns whether any session output reaches this client inside `window`.
async fn output_within(client: &mut Client<impl Codec>, window: std::time::Duration) -> bool {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_that_reuses_an_earlier_action_identifier_conflicts_rather_than_stopping() {
    let host = host(1).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    // An ordinary attachment, recorded under this identifier in a journal that is working.
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    client
        .mutate(
            Method::SessionAttach,
            action_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds");

    // The same identifier, a different payload. Section 9 answers that with `ID_CONFLICT` whatever
    // the method is: a stop is not a reason to act on an identifier that already belongs to
    // somebody else's action.
    let mut mutation = close_mutation(
        &client,
        &host,
        30_000,
        kr_protocol::envelope::ParamsValue::empty(),
    );
    mutation.action_id = action_id;
    let outcome = send_mutation(&mut client, mutation).await;
    let kr_protocol::envelope::Outcome::Error(error) = outcome else {
        panic!("a reused action identifier must not close the session");
    };
    assert_eq!(error.code, ErrorCode::IdConflict);
    assert_eq!(
        host.service.runtime().state().as_str(),
        "live",
        "a conflicting close neither dispatches nor settles"
    );
    assert!(
        host.service.runtime().session().journal_failure().is_none(),
        "and a healthy journal is not marked as having failed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdrawal_completes_while_the_peer_has_stopped_reading() {
    // The case the transport's contract is about: a peer that stops reading. Its socket fills, the
    // worker's write for it waits, and everything that connection still holds (its subscription,
    // its attachments, its authority) would wait with it. Withdrawal has to end all of that
    // without asking that peer for anything.
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
    expect_output_within(
        &mut first,
        LIVENESS_DEADLINE,
        "the subscription is delivering before anything is withdrawn",
    )
    .await;
    assert_eq!(
        host.service.runtime().session().attachments().len(),
        1,
        "and the connection owns its attachment"
    );

    // From here this peer reads nothing, and it keeps asking. The worker answers until the socket
    // will take no more, and its loop is then inside a write that nobody is going to read.
    let saturated = saturate(&mut first, host.session_id).await;
    assert!(
        saturated,
        "the peer stopped reading and the worker's replies filled the socket"
    );

    // A replacement daemon binds the authority, which withdraws the first connection.
    let mut second = controller_client(&host, 2).await;
    read_session(&mut second, host.session_id)
        .await
        .expect("the replacement connection is served");

    // The attachment goes with the withdrawal, not with the socket.
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    loop {
        if host.service.runtime().session().attachments().is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {:?} for withdrawal to take the connection's attachments back without \
             waiting for its peer",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // And nothing protected reaches that peer afterwards. What was already in the socket is read
    // off first; after it, the shell is still writing and none of it arrives.
    while output_within(&mut first, std::time::Duration::from_millis(200)).await {}
    assert!(
        !output_within(&mut first, std::time::Duration::from_secs(3)).await,
        "no output is delivered to a withdrawn connection"
    );
}

/// Asks the worker for more than the connection can carry, and stops reading the answers.
///
/// Returns whether the pipeline filled: the worker's replies no longer fit in the socket, so its
/// connection loop is waiting inside a write, and this client's own writes stop going through too.
async fn saturate(client: &mut Client<impl Codec>, session_id: SessionId) -> bool {
    let params = kr_protocol::envelope::ParamsValue::from_typed(&SessionReadParams { session_id })
        .expect("encodes");
    for index in 0..20_000_u64 {
        let request =
            kr_protocol::envelope::ControlFrame::Request(kr_protocol::envelope::Request {
                request_id: kr_protocol::ids::RequestId::new(1_000 + index),
                method: Method::SessionRead.into(),
                method_version: kr_protocol::method::MethodVersion::V1,
                params: params.clone(),
            });
        let written =
            tokio::time::timeout(std::time::Duration::from_millis(500), client.send(&request))
                .await;
        match written {
            // This client's own write is now waiting, which means the worker has stopped reading,
            // which means the worker is waiting inside a write of its own.
            Err(_) => return true,
            Ok(Err(_)) => return false,
            Ok(Ok(())) => {}
        }
    }
    false
}

/// How long a test waits for a count to settle before it reads the count and asserts it. Nothing
/// is decided by it: the assertion that follows names the count that did not settle.
const SETTLE: std::time::Duration = std::time::Duration::from_secs(15);

/// Waits until `settled` holds, or `SETTLE` has passed, and says whether it held.
async fn settle(mut settled: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + SETTLE;
    while !settled() {
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    true
}

/// Holds one of the worker's locks on a thread of its own until it is released: the dispatch
/// boundary, or the authority record.
struct Held {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Held {
    async fn boundary(host: &Host) -> Self {
        Self::take(host, false).await
    }

    /// The authority record, which a generation that is being decided holds while it reads the
    /// journal.
    async fn authority(host: &Host) -> Self {
        Self::take(host, true).await
    }

    async fn take(host: &Host, authority: bool) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let service = Arc::clone(&host.service);
        let thread = std::thread::spawn(move || {
            let _boundary = (!authority).then(|| service.hold_the_dispatch_boundary());
            let _authority = authority.then(|| service.hold_the_authority_for_tests());
            let _ = held.send(());
            let _ = wait.recv();
        });
        tokio::time::timeout(WAIT, confirmed)
            .await
            .expect("the lock is held in time")
            .expect("the holder ended without holding the lock");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }

    fn release(mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the holding thread finishes");
        }
    }
}

/// What a presentation on a task of its own came to: the link, and the worker's answer.
type Presented = (
    BoundLink,
    kr_ipc::Result<kr_protocol::worker::GenerationAccepted>,
);

/// A connection that says hello and presents `generation`, on a task of its own that owns the link.
/// Ending the task is the daemon going away.
fn presenting(host: &Host, generation: u64) -> tokio::task::JoinHandle<Presented> {
    let endpoint = host.endpoint.clone();
    let signer = host.signer();
    tokio::spawn(async move {
        let mut link = BoundLink::connect(&endpoint, build())
            .await
            .expect("connects");
        let answer = present(&mut link, signer, generation).await;
        (link, answer)
    })
}

fn presenting_many(
    host: &Host,
    count: usize,
    generation: u64,
) -> Vec<tokio::task::JoinHandle<Presented>> {
    (0..count).map(|_| presenting(host, generation)).collect()
}

/// Ends the tasks, which closes each presentation's link: its daemon has gone.
async fn peers_go(peers: Vec<tokio::task::JoinHandle<Presented>>) {
    for peer in &peers {
        peer.abort();
    }
    for peer in peers {
        let _ = peer.await;
    }
}

/// Presentations whose peers have gone do not keep the worker's connections while its dispatch
/// boundary is held.
///
/// Three rounds of thirty connections say hello and present, and their tasks end while the
/// boundary is still held. Each round's connections are given back before the next round
/// begins, so the third finds the worker where the first did, and nothing was decided for any of
/// them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presentations_whose_peers_have_gone_do_not_keep_their_connections_while_the_boundary_is_held()
 {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let start = service.connections_held_for_tests();
    let accepted = service.accepted_generation();
    for round in 1..=3 {
        let peers = presenting_many(&host, 30, 2);
        settle(|| service.presentations_waiting_for_tests() == 30).await;
        assert_eq!(
            service.presentations_waiting_for_tests(),
            30,
            "round {round}: the presentations wait at the held boundary"
        );
        peers_go(peers).await;
        settle(|| {
            service.connections_held_for_tests() == start
                && service.presentations_waiting_for_tests() == 0
        })
        .await;
        assert_eq!(
            service.connections_held_for_tests(),
            start,
            "round {round}: the connections of the peers that went are given back while the boundary is still held"
        );
        assert_eq!(
            service.presentations_waiting_for_tests(),
            0,
            "round {round}: no presentation of a peer that went still waits"
        );
    }
    assert_eq!(
        service.accepted_generation(),
        accepted,
        "nothing was decided for a peer that was not there"
    );
    boundary.release();
}

/// A presentation whose peer is there waits through a long hold and is answered when it ends, while
/// the presentations of the peers that went beside it are given up.
///
/// The living one is found by its answer and by what it is served as: it holds the authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_living_presentation_waits_through_a_long_hold_and_is_answered() {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let start = service.connections_held_for_tests();
    let accepted = service.accepted_generation();
    let living = presenting(&host, 2);
    let dead = presenting_many(&host, 8, 2);
    settle(|| service.presentations_waiting_for_tests() == 9).await;
    assert_eq!(service.presentations_waiting_for_tests(), 9);
    peers_go(dead).await;
    settle(|| {
        service.presentations_waiting_for_tests() == 1
            && service.connections_held_for_tests() == start + 1
    })
    .await;
    assert_eq!(
        service.presentations_waiting_for_tests(),
        1,
        "the living presentation is the one that waits"
    );
    assert_eq!(
        service.connections_held_for_tests(),
        start + 1,
        "the living presentation keeps its connection and the dead ones' are given back"
    );

    // The living presentation tries the boundary again and again before it is free.
    let before = service.presentation_tries_for_tests();
    settle(|| service.presentation_tries_for_tests() >= before + 8).await;
    assert!(
        service.presentation_tries_for_tests() >= before + 8,
        "the living presentation found the boundary held again and again"
    );
    assert!(!living.is_finished(), "it waits for the hold");
    assert_eq!(service.accepted_generation(), accepted);

    boundary.release();
    let (mut link, answer) = tokio::time::timeout(WAIT, living)
        .await
        .expect("the living presentation is answered once the boundary is free")
        .expect("the task ends");
    answer.expect("the living presentation is accepted");
    assert_eq!(
        service.accepted_generation(),
        Some(ControllerGeneration::new(2))
    );
    read_session(&mut link, host.session_id)
        .await
        .expect("the connection that waited is the one that holds the authority");
}

/// A presentation with a frame behind its token is not taken for a peer that has gone.
///
/// The frame sits unread in the worker's socket while the presentation waits, which is what the
/// system reports as bytes waiting and not as an end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presentation_with_a_frame_behind_its_token_is_not_taken_for_gone() {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let mut link = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    // The link hands the challenge's nonce to the signing step. Failing it there leaves the token
    // to be sent by hand, so that a frame can follow it.
    let mut nonce = None;
    link.present_generation(|challenge| {
        nonce = Some(*challenge);
        Err(kr_ipc::IpcError::UnexpectedMessage(
            "the test sends the token itself",
        ))
    })
    .await
    .expect_err("the signing step is failed on purpose");
    let signer = host.signer();
    let token = signer
        .identity
        .generation_token(
            ControllerGeneration::new(1),
            &signer.boot,
            &nonce.expect("the link issued a challenge"),
        )
        .expect("signs");
    link.send(&ControlFrame::GenerationToken(Box::new(token)))
        .await
        .expect("sends the token");
    settle(|| service.presentations_waiting_for_tests() == 1).await;
    assert_eq!(service.presentations_waiting_for_tests(), 1);
    link.send(&ControlFrame::Event(
        kr_protocol::envelope::ControlEvent::Keepalive,
    ))
    .await
    .expect("sends a frame behind the token");

    let before = service.presentation_tries_for_tests();
    settle(|| service.presentation_tries_for_tests() >= before + 8).await;
    assert!(service.presentation_tries_for_tests() >= before + 8);
    assert_eq!(
        service.presentations_waiting_for_tests(),
        1,
        "a peer with bytes behind its token is there"
    );
    assert_eq!(service.connections_held_for_tests(), 1);

    boundary.release();
    match tokio::time::timeout(WAIT, link.recv())
        .await
        .expect("the worker answers once the boundary is free")
        .expect("the answer arrives")
    {
        ControlFrame::GenerationAccepted(accepted) => {
            assert_eq!(accepted.generation, ControllerGeneration::new(1));
        }
        other => panic!("the worker answered {other:?}"),
    }
}

/// The owner's own connection is admitted while presentations of peers that have gone wait at a
/// held boundary: they do not take the worker's connections to its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owners_own_connection_is_admitted_while_dead_presentations_wait() {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let peers = presenting_many(&host, kr_worker::service::MAX_CONNECTIONS, 1);
    settle(|| service.presentations_waiting_for_tests() == kr_worker::service::MAX_CONNECTIONS)
        .await;
    assert_eq!(
        service.presentations_waiting_for_tests(),
        kr_worker::service::MAX_CONNECTIONS,
        "every connection the worker admits is a presentation that waits"
    );
    assert_eq!(
        service.connections_held_for_tests(),
        kr_worker::service::MAX_CONNECTIONS
    );
    peers_go(peers).await;
    settle(|| service.connections_held_for_tests() == 0).await;
    assert_eq!(
        service.connections_held_for_tests(),
        0,
        "the connections of the peers that went are given back"
    );
    tokio::time::timeout(
        WAIT,
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
    )
    .await
    .expect("the owner's connection is answered while the boundary is held")
    .expect("the owner's connection is admitted");
    boundary.release();
}

/// A presentation whose peer goes as the hold ends has no effect.
///
/// A connection holds the authority of generation 1 with an acknowledged revision, and a connection
/// that said hello before it is on record as the earlier of the two. A presentation of generation 2
/// takes the boundary the moment the holder lets go, and stops inside it. Its peer goes there,
/// between its last try and the take. What the worker asks once more under the boundary keeps the
/// acceptance from running at all, and an acceptance of a higher generation changes the records
/// one after the other: the record of the hello order, the acknowledgement and the binding, and
/// then the generation. So every one of them must stand: the order record, which refuses the
/// earlier connection's presentation still; the acknowledged revision; the binding, which serves
/// its connection still; and the accepted generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presentation_whose_peer_goes_as_the_hold_ends_has_no_effect() {
    let host = host(1).await;
    let service = &host.service;
    let mut earlier = declared(&host, ControllerConnectionRole::Authority).await;
    let mut holder = controller_client(&host, 1).await;
    let acknowledged = holder
        .announce_revision(AuthorityRevisionNotice {
            environment_id: host.environment_id,
            revision: AuthorityRevision::new(3),
            reach: RevisionReach::Host,
            evidence_from: 0,
        })
        .await
        .expect("the worker acknowledges the revision");
    assert_eq!(acknowledged.revision, AuthorityRevision::new(3));
    read_session(&mut holder, host.session_id)
        .await
        .expect("the connection that holds the authority is served");
    let start = service.connections_held_for_tests();
    assert_eq!(
        service.accepted_generation(),
        Some(ControllerGeneration::new(1))
    );
    assert_eq!(
        service.acknowledgement_for_tests(),
        Some((ControllerGeneration::new(1), AuthorityRevision::new(3)))
    );

    let boundary = Held::boundary(&host).await;
    let (arrived, go) = service.pause_inside_presentation();
    let peer = presenting(&host, 2);
    settle(|| service.presentations_waiting_for_tests() == 1).await;
    assert_eq!(service.presentations_waiting_for_tests(), 1);

    boundary.release();
    tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT))
        .await
        .expect("the wait ends")
        .expect("the presentation takes the boundary once it is free");
    peers_go(vec![peer]).await;
    go.send(true)
        .expect("the presentation goes on, once the system says its peer has gone");
    settle(|| {
        service.presentations_waiting_for_tests() == 0
            && service.connections_held_for_tests() == start
    })
    .await;
    assert_eq!(service.connections_held_for_tests(), start);
    assert_eq!(
        service.accepted_generation(),
        Some(ControllerGeneration::new(1)),
        "no generation was accepted for a peer that had gone"
    );
    assert_eq!(
        service.acknowledgement_for_tests(),
        Some((ControllerGeneration::new(1), AuthorityRevision::new(3))),
        "the acknowledgement was not cleared for a peer that had gone"
    );
    read_session(&mut holder, host.session_id)
        .await
        .expect("the connection that held the authority still holds it");
    assert_refused_for_order(present(&mut earlier, host.signer(), 1).await);
}

/// A presentation whose peer has gone fences nobody, whether it comes from a newer connection of
/// the generation that holds the authority or from a higher generation.
///
/// A connection holds the authority. Two presentations wait at a held boundary, one after the
/// other, and their peers go before it is free. The connection that held the authority still holds
/// it, and is served, afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_presentation_does_not_fence_a_living_older_binding() {
    let host = host(1).await;
    let service = &host.service;
    let mut older = controller_client(&host, 1).await;
    read_session(&mut older, host.session_id)
        .await
        .expect("the older connection is served");
    let start = service.connections_held_for_tests();
    let boundary = Held::boundary(&host).await;
    for generation in [2, 1] {
        let peer = presenting(&host, generation);
        settle(|| service.presentations_waiting_for_tests() == 1).await;
        assert_eq!(service.presentations_waiting_for_tests(), 1);
        peers_go(vec![peer]).await;
        settle(|| {
            service.presentations_waiting_for_tests() == 0
                && service.connections_held_for_tests() == start
        })
        .await;
        assert_eq!(
            service.connections_held_for_tests(),
            start,
            "the presentation of generation {generation} is given up while the boundary is held"
        );
    }
    boundary.release();
    assert_eq!(
        service.accepted_generation(),
        Some(ControllerGeneration::new(1))
    );
    read_session(&mut older, host.session_id)
        .await
        .expect("the connection that held the authority is served still");
}

/// A presentation that never took authority does not wait for authority when its connection ends.
///
/// Presentations wait at a held boundary. A generation that is being decided holds the authority
/// record while it reads the journal, and while it does, the peers of the waiting presentations
/// go. Their connections are given back with the record still held, because a connection that was
/// never bound has nothing to remove from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_presentation_that_never_took_authority_ends_while_another_holds_the_authority() {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let start = service.connections_held_for_tests();
    let peers = presenting_many(&host, 3, 2);
    settle(|| service.presentations_waiting_for_tests() == 3).await;
    assert_eq!(service.presentations_waiting_for_tests(), 3);
    let record = Held::authority(&host).await;
    peers_go(peers).await;
    settle(|| {
        service.presentations_waiting_for_tests() == 0
            && service.connections_held_for_tests() == start
    })
    .await;
    assert_eq!(
        service.connections_held_for_tests(),
        start,
        "the connections of the peers that went are given back while the authority is held"
    );
    record.release();
    boundary.release();
}

/// A connection that says hello, declares `role` and presents `generation`, on a task of its own
/// that owns the link.
fn presenting_as(
    host: &Host,
    role: ControllerConnectionRole,
    generation: u64,
) -> tokio::task::JoinHandle<Presented> {
    let endpoint = host.endpoint.clone();
    let signer = host.signer();
    tokio::spawn(async move {
        let mut link = BoundLink::connect(&endpoint, build())
            .await
            .expect("connects");
        link.send(&ControlFrame::ControllerRole(role))
            .await
            .expect("declares the role");
        match link.recv().await.expect("the worker answers") {
            ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
            other => panic!("the worker answered {other:?}"),
        }
        let answer = present(&mut link, signer, generation).await;
        (link, answer)
    })
}

/// Several presentations of live proxy connections are all admitted while the boundary is held, and
/// are all accepted once it is free; the connections of the proxies whose processes end are given
/// back while it is held.
///
/// A daemon opens one proxy connection for each caller it forwards, so many wait at once, and none
/// of them is a peer that has gone while its process is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn several_living_proxy_presentations_stay_admitted_through_a_hold_and_go_with_their_peers() {
    let host = host(1).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let start = service.connections_held_for_tests();
    let living: Vec<_> = (0..6)
        .map(|_| presenting_as(&host, ControllerConnectionRole::Proxy, 2))
        .collect();
    let ending: Vec<_> = (0..6)
        .map(|_| presenting_as(&host, ControllerConnectionRole::Proxy, 2))
        .collect();
    settle(|| service.presentations_waiting_for_tests() == 12).await;
    assert_eq!(
        service.presentations_waiting_for_tests(),
        12,
        "every proxy presentation is admitted while the boundary is held"
    );
    peers_go(ending).await;
    settle(|| {
        service.presentations_waiting_for_tests() == 6
            && service.connections_held_for_tests() == start + 6
    })
    .await;
    assert_eq!(
        service.connections_held_for_tests(),
        start + 6,
        "the proxies whose processes ended give their connections back and the others keep theirs"
    );
    assert_eq!(service.presentations_waiting_for_tests(), 6);

    boundary.release();
    for presented in living {
        let (_link, answer) = tokio::time::timeout(WAIT, presented)
            .await
            .expect("each living proxy presentation is answered once the boundary is free")
            .expect("the task ends");
        answer.expect("the proxy is accepted");
    }
    assert_eq!(
        service.accepted_generation(),
        Some(ControllerGeneration::new(2))
    );
}

/// The longest a daemon waits for a presentation to be answered before it gives up on the link: the
/// start's rebuild drops its client after five seconds. A presentation whose peer is there is
/// decided inside it while the boundary is taken again and again.
const PRESENTATION_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// One local client that attaches a terminal and detaches it again, back to back, until `stop` is
/// set: each is a mutation, and each takes the dispatch boundary. It counts the mutations it made.
async fn mutating(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    stop: Arc<std::sync::atomic::AtomicBool>,
    made: Arc<std::sync::atomic::AtomicU64>,
) {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
        SessionDetachParams,
    };
    use kr_protocol::envelope::ActionTarget;
    use kr_protocol::ids::ActionId;

    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let target = || ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the terminal attaches")
            .to_typed()
            .expect("decodes");
        client
            .mutate(
                Method::SessionDetach,
                ActionId::new(kr_ipc::new_uuid()),
                target(),
                &SessionDetachParams {
                    attachment_id: Nullable::some(attached.attachment.attachment_id),
                    line_token: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("detaches");
        made.fetch_add(2, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A presentation whose peer is there gets in while mutations take the dispatch boundary again and
/// again.
///
/// Four local clients attach and detach back to back, so the boundary is free only between one
/// mutation and the next. A presentation that tries the boundary at intervals, and does not queue
/// for it, must still be decided within the time a daemon waits for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_living_presentation_is_decided_while_mutations_take_the_boundary_again_and_again() {
    let host = host(1).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let made = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let streams: Vec<_> = (0..4)
        .map(|_| {
            let (stop, made) = (Arc::clone(&stop), Arc::clone(&made));
            tokio::spawn(mutating(
                host.endpoint.clone(),
                host.environment_id,
                host.session_id,
                stop,
                made,
            ))
        })
        .collect();
    settle(|| made.load(std::sync::atomic::Ordering::SeqCst) >= 20).await;
    assert!(
        made.load(std::sync::atomic::Ordering::SeqCst) >= 20,
        "the mutations are under way"
    );

    let before = made.load(std::sync::atomic::Ordering::SeqCst);
    let living = presenting(&host, 1);
    let decided = tokio::time::timeout(PRESENTATION_BOUND, living).await;
    let during = made.load(std::sync::atomic::Ordering::SeqCst) - before;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    for stream in streams {
        stream.await.expect("the mutating client ends");
    }
    let (mut link, answer) = decided
        .unwrap_or_else(|_| {
            panic!(
                "the living presentation was not decided within {PRESENTATION_BOUND:?} while {during} mutations took the boundary"
            )
        })
        .expect("the task ends");
    answer.expect("the presentation is accepted");
    eprintln!(
        "presentation decided after {} tries while {during} mutations took the boundary",
        host.service.presentation_tries_for_tests()
    );
    read_session(&mut link, host.session_id)
        .await
        .expect("the presenting connection holds the authority");
}

/// A living presentation is decided in a gap that is shorter than its pause between two tries.
///
/// The boundary is held, and the presentation has waited long enough for its pause to have reached
/// its longest. Each time it has just tried and found the boundary held, the boundary is let go of
/// for a tenth of a second and then taken again. A presentation that only tries again when its
/// pause is over finds it held every time; one that is woken when the boundary is let go takes it
/// in the first gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_living_presentation_is_decided_in_a_gap_shorter_than_its_pause() {
    let host = host(1).await;
    let service = &host.service;
    let mut boundary = Some(Held::boundary(&host).await);
    let mut living = presenting(&host, 1);
    settle(|| service.presentations_waiting_for_tests() == 1).await;
    settle(|| service.presentation_tries_for_tests() >= 8).await;
    let mut decided = None;
    for _gap in 0..20 {
        // A try has just found the boundary held, and the next waits out a pause.
        let seen = service.presentation_tries_for_tests();
        settle(|| service.presentation_tries_for_tests() > seen).await;
        boundary
            .take()
            .expect("the boundary is held here")
            .release();
        tokio::select! {
            presented = &mut living => {
                decided = Some(presented.expect("the task ends"));
                break;
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
        boundary = Some(Held::boundary(&host).await);
    }
    let Some((mut link, answer)) = decided else {
        if let Some(held) = boundary.take() {
            held.release();
        }
        panic!(
            "the living presentation was not decided in any of twenty gaps shorter than its pause"
        );
    };
    answer.expect("the presentation is accepted");
    read_session(&mut link, host.session_id)
        .await
        .expect("the presenting connection holds the authority");
}

/// A worker that is stopped while presentations wait does not wait for the hold on their account.
///
/// Presentations whose clients are there wait at a held boundary, on a runtime that this case builds
/// and then drops, which is what a stop of the worker does to its runtime. A holder outside the
/// runtime keeps the boundary throughout, so the drop ends only if the presentations leave the
/// wait. A stop still waits for a hold that a holder inside the runtime has, on a thread of the
/// runtime's own.
#[test]
fn a_worker_stopped_while_presentations_wait_ends_without_the_hold() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let host = runtime.block_on(host(1));
    // The worker's own first maintenance pass takes the boundary as it starts serving, and a hold
    // that came before it would keep that pass, and with it the runtime, waiting for the hold.
    assert!(
        runtime.block_on(settle(|| host.service.maintenance_passes_for_tests() >= 1)),
        "the first maintenance pass finishes"
    );
    let boundary = runtime.block_on(Held::boundary(&host));
    let peers = runtime.block_on(async { presenting_many(&host, 8, 1) });
    let waiting = runtime.block_on(settle(|| {
        host.service.presentations_waiting_for_tests() == 8
    }));
    let (ended, ending) = std::sync::mpsc::channel::<()>();
    let stopping = std::thread::spawn(move || {
        drop(peers);
        drop(runtime);
        let _ = ended.send(());
    });
    let stopped = ending.recv_timeout(SETTLE);
    // The holder is let go whatever came of the stop, so that a stop that waited ends too.
    boundary.release();
    stopping.join().expect("the stopping thread finishes");
    assert!(waiting, "the presentations wait at the held boundary");
    assert!(
        stopped.is_ok(),
        "the runtime ended while the boundary was still held"
    );
}
