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
    // The runtime a host serves on when it has one of its own, ended after the serving task has
    // been asked to stop and before the directory goes.
    _apart: HostRuntime,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
}

/// The runtime that a host serves on when its case gives it one, so that a worker thread that a
/// mutant blocks does not stop the case's own timers.
struct HostRuntime(Option<tokio::runtime::Runtime>);

/// Ended without waiting for a thread that is still blocked in it: the case has failed by then, and
/// its holder has let go.
impl Drop for HostRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host(generation: u64) -> Host {
    host_producing(generation, "sleep 30").await
}

async fn host_producing(generation: u64, script: &str) -> Host {
    host_built(generation, script, false).await
}

/// A host over a session that runs `script`. With `attention_journal` the worker can read the
/// session's journal for the attention link, which an attention link's first statement needs: a
/// worker that cannot read it takes its attention link down as soon as it has written the
/// statement.
async fn host_built(generation: u64, script: &str, attention_journal: bool) -> Host {
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
                journal_path: attention_journal.then(|| environment.journal_database(session_id)),
            },
        )
        .expect("a worker service"),
    );
    let serving = kr_ipc::testing::Serving::spawn(Arc::clone(&service).serve(listener));
    Host {
        _serving: serving,
        _apart: HostRuntime(None),
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
    // Bounded: a worker that takes the presentation for a peer that has gone sends no answer, and a
    // setup that waits for one would stop the program there. At a free boundary the answer takes
    // milliseconds.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        }),
    )
    .await
    .expect("the worker did not answer the presentation of the generation within 10 s")
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

/// What a holder takes, in the order a holder inside the worker takes them: the boundary, then the
/// session or the authority record.
#[derive(Clone, Copy)]
enum Hold {
    Boundary,
    Authority,
    BoundaryAndSession,
    BoundaryAndAuthority,
    Fence,
}

/// Holds some of the worker's locks on a thread of its own until it is released: the dispatch
/// boundary, the authority record or the session.
struct Held {
    release: Option<std::sync::mpsc::Sender<()>>,
    // Whether the attention fence still named a connection when the holder let go of it.
    thread: Option<std::thread::JoinHandle<bool>>,
}

impl Held {
    async fn boundary(host: &Host) -> Self {
        Self::take(host, Hold::Boundary).await
    }

    /// The authority record, which a generation that is being decided holds while it reads the
    /// journal.
    async fn authority(host: &Host) -> Self {
        Self::take(host, Hold::Authority).await
    }

    /// What a mutation holds: the boundary and, inside it, the session.
    async fn boundary_and_session(host: &Host) -> Self {
        Self::take(host, Hold::BoundaryAndSession).await
    }

    /// What a generation that is being decided holds: the boundary and the authority record.
    async fn boundary_and_authority(host: &Host) -> Self {
        Self::take(host, Hold::BoundaryAndAuthority).await
    }

    /// The fence's own lock, which a statement holds while it reads the journal.
    async fn fence(host: &Host) -> Self {
        Self::take(host, Hold::Fence).await
    }

    async fn take(host: &Host, hold: Hold) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let service = Arc::clone(&host.service);
        let thread = std::thread::spawn(move || {
            let _boundary = matches!(
                hold,
                Hold::Boundary | Hold::BoundaryAndSession | Hold::BoundaryAndAuthority
            )
            .then(|| service.hold_the_dispatch_boundary());
            let _session =
                matches!(hold, Hold::BoundaryAndSession).then(|| service.runtime().session());
            let _authority = matches!(hold, Hold::Authority | Hold::BoundaryAndAuthority)
                .then(|| service.hold_the_authority_for_tests());
            let fence =
                matches!(hold, Hold::Fence).then(|| service.hold_the_attention_fence_for_tests());
            let _ = held.send(());
            let _ = wait.recv();
            fence.is_some_and(|fence| fence.current_connection().is_some())
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

    fn release(self) {
        self.release_naming_the_fence();
    }

    /// Lets go, and says whether the fence still named a connection at the moment it was let go.
    fn release_naming_the_fence(mut self) -> bool {
        drop(self.release.take());
        self.thread
            .take()
            .map(|thread| thread.join().expect("the holding thread finishes"))
            .unwrap_or_default()
    }
}

/// A holder that is dropped by a case that failed lets go, so that the worker's threads that wait for
/// it end and the program ends with the case's own message.
impl Drop for Held {
    fn drop(&mut self) {
        drop(self.release.take());
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
/// The frame is larger than 4 KiB and small enough for the connection to hold, so that on every
/// platform some of it stays in the connection while the presentation waits and the worker reads
/// none of it: a Windows pipe's runtime takes the first 4 KiB of what arrives into a buffer of its
/// own, and a smaller frame would leave nothing for the system to count. What the system reports is
/// bytes waiting, and not an end.
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
    let large =
        kr_protocol::envelope::ParamsValue::from_typed(&"x".repeat(5 * 1024)).expect("encodes");
    // Bounded: a connection whose buffer cannot take the whole frame would stop this send until the
    // boundary is released, which only this case does, and the suite would hang with correct code.
    // A send that the connection takes ends in milliseconds.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        link.send(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: kr_protocol::ids::RequestId::new(7),
            method: Method::SessionRead.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params: large,
        })),
    )
    .await
    .expect("the send of the 5 KiB frame behind the token did not complete within 10 s")
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

/// What one mutating client has started and what has been answered to it: a mutation is counted as
/// started before it is written, and as answered when its answer has been read.
#[derive(Default)]
struct Progress {
    started: std::sync::atomic::AtomicU64,
    answered: std::sync::atomic::AtomicU64,
}

impl Progress {
    fn started(&self) -> u64 {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn answered(&self) -> u64 {
        self.answered.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// One local client that attaches a terminal and detaches it again, back to back, until `stop` is
/// set: each is a mutation, and each takes the dispatch boundary. It counts what it started and
/// what was answered.
async fn mutating(
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    stop: Arc<std::sync::atomic::AtomicBool>,
    progress: Arc<Progress>,
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
        progress
            .started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        progress
            .answered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        progress
            .started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        progress
            .answered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits until `ready` holds, and fails with `what` when `WAIT` has passed first. It is for a state
/// that must come: the time it allows is the guard against a hang, and no promise about speed.
async fn await_state(what: &str, mut ready: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + WAIT;
    while !ready() {
        assert!(
            tokio::time::Instant::now() < end,
            "{what} did not come within {WAIT:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Waits until `done` holds, and fails with `what` when `count` has not advanced for `WAIT`: each
/// advance starts the time again, so that a count that goes on advancing never fails the wait, and
/// a count that stops does after one `WAIT`. It is for a state that is reached by steps, where a
/// total of time would be a promise about speed that nothing makes.
async fn await_progress(
    what: &str,
    mut count: impl FnMut() -> u64,
    mut done: impl FnMut() -> bool,
) {
    let mut last = count();
    let mut since = tokio::time::Instant::now();
    while !done() {
        let now = count();
        if now != last {
            last = now;
            since = tokio::time::Instant::now();
        }
        assert!(
            since.elapsed() < WAIT,
            "{what} did not advance for {WAIT:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A living presentation keeps trying while mutations take the dispatch boundary again and again,
/// and is decided once they stop.
///
/// Four local clients attach and detach back to back, so the boundary is free only between one
/// mutation and the next. The case holds the boundary itself first, and starts the presentation,
/// whose first try finds it held whatever the machine does. It starts the clients under the hold:
/// every mutation takes the boundary, so none can be answered before the release, and the case
/// waits until each of the four has started one. It then lets the boundary go, and the stream goes
/// on. The case shows that, while the stream goes on, the presentation stays eligible: it tries
/// again, at a release or at its pause, and its tries advance by twenty or it is decided at one of
/// them. Then the stream stops, and the case shows that the presentation is decided once it has
/// stopped. A wait for a state that must come lasts as long as the suite waits for one, which is a
/// guard against a hang and no time that the presentation is promised. The two waits that count,
/// for the presentation's tries and for the answered mutations, fail only when their count has not
/// advanced for that time, and each advance starts it again.
///
/// It does not show that a stream cannot keep the presentation out. The boundary is an ordinary
/// lock, and a release makes the presentation eligible and promises it nothing: where a mutation
/// always waits, a presentation can find the boundary taken at every try for as long as the stream
/// goes on, and whether and how soon it gets in depends on the lock's policy and on how fast the
/// machine runs. The wake is shown by
/// `a_living_presentation_is_decided_in_a_gap_shorter_than_its_pause`.
///
/// The runtime is the case's own, so that a mutation that never ends, which holds a thread of it,
/// ends the case as a failed assertion and does not keep the runtime's drop waiting.
#[test]
fn a_living_presentation_keeps_trying_through_mutations_and_is_decided_when_they_stop() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(presentation_keeps_trying_through_mutations());
    }));
    runtime.shutdown_background();
    if let Err(failure) = outcome {
        std::panic::resume_unwind(failure);
    }
}

async fn presentation_keeps_trying_through_mutations() {
    // The session's command outlives every wait of the case: the worker closes a session whose
    // command has ended, and the clients' attaches would then fail. The program's exit ends it at
    // the latest.
    let host = host_producing(1, "sleep 3600").await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let first = service.presentation_tries_for_tests();
    let living = presenting(&host, 1);
    await_state("the presentation's first try", || {
        service.presentation_tries_for_tests() > first
    })
    .await;
    assert_eq!(
        service.presentations_waiting_for_tests(),
        1,
        "the presentation waits for the held boundary"
    );

    // Each client has started a mutation that nothing can answer while the boundary is held. This
    // is what the clients' own counts show: it does not show the worker's wait for the boundary.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let progress: Vec<Arc<Progress>> = (0..4).map(|_| Arc::default()).collect();
    let streams: Vec<_> = progress
        .iter()
        .map(|progress| {
            tokio::spawn(mutating(
                host.endpoint.clone(),
                host.environment_id,
                host.session_id,
                Arc::clone(&stop),
                Arc::clone(progress),
            ))
        })
        .collect();
    await_state(
        "a mutation of each of the four clients, started while the boundary is held",
        || progress.iter().all(|client| client.started() >= 1),
    )
    .await;
    assert!(
        progress.iter().all(|client| client.answered() == 0),
        "no mutation is answered while the boundary is held"
    );
    boundary.release();

    // While the stream goes on, the presentation tries again, or has been decided at a release or
    // at its pause.
    let released = service.presentation_tries_for_tests();
    await_progress(
        "the presentation's tries after the release",
        || service.presentation_tries_for_tests(),
        || living.is_finished() || service.presentation_tries_for_tests() >= released + 20,
    )
    .await;
    let made = || progress.iter().map(|client| client.answered()).sum::<u64>();
    await_progress("the mutations answered after the release", made, || {
        made() >= 20
    })
    .await;
    let tries = service.presentation_tries_for_tests();
    let during = made();
    let early = living.is_finished();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);

    // The stream has stopped: each client ends its pair, and the boundary is then free.
    let (mut link, answer) = tokio::time::timeout(WAIT, living)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the presentation was not decided within {WAIT:?} of the stream's stop, \
                 with {tries} tries and {during} mutations before it"
            )
        })
        .expect("the task ends");
    for stream in streams {
        tokio::time::timeout(WAIT, stream)
            .await
            .unwrap_or_else(|_| {
                panic!("a mutating client did not end within {WAIT:?} of the stream's stop")
            })
            .expect("the mutating client ends");
    }
    answer.expect("the presentation is accepted");
    eprintln!(
        "presentation decided after {} tries while {during} mutations took the boundary (before the stop: {early})",
        service.presentation_tries_for_tests()
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

// ---- Requests whose clients have gone, and the clean-up of a connection whose peer has gone.

/// As [`host_ready`], serving on a runtime of its own (see [`HostRuntime`]).
async fn host_ready_apart(attention_journal: bool) -> Host {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime for the host");
    let mut host = runtime
        .spawn(host_built(1, "sleep 30", attention_journal))
        .await
        .expect("the host starts");
    host._apart = HostRuntime(Some(runtime));
    assert!(
        settle(|| host.service.maintenance_passes_for_tests() >= 1).await,
        "the first maintenance pass finishes"
    );
    host
}

/// A host whose first maintenance pass has finished: that pass takes the dispatch boundary as the
/// host starts serving, and a hold that came before it would keep it waiting.
async fn host_ready() -> Host {
    let host = host(1).await;
    assert!(
        settle(|| host.service.maintenance_passes_for_tests() >= 1).await,
        "the first maintenance pass finishes"
    );
    host
}

/// A local client that sends one Blocking mutation, an attach, on a task of its own and waits for
/// the answer. Ending the task is the client going away. The whole task is bounded, so a worker
/// that never admits it ends the task and not the program.
fn attaching_once(
    host: &Host,
    action_id: kr_protocol::ids::ActionId,
) -> tokio::task::JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let (environment_id, session_id) = (host.environment_id, host.session_id);
    tokio::spawn(async move {
        let _ = tokio::time::timeout(WAIT, async {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            let _ = client
                .mutate(
                    Method::SessionAttach,
                    action_id,
                    target(environment_id, session_id),
                    &attach_params(session_id),
                )
                .await;
        })
        .await;
    })
}

/// Whether the worker holds a receipt for `action_id`, which a client of its own asks. A request
/// that was dropped before the worker took it into its serial path has none.
async fn receipt_exists(host: &Host, action_id: kr_protocol::ids::ActionId) -> bool {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .request(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await
        .expect("reaches the worker")
        .is_ok()
}

/// Ends the tasks, which closes each client's connection: the clients have gone.
async fn clients_go(clients: Vec<tokio::task::JoinHandle<()>>) {
    for client in &clients {
        client.abort();
    }
    for client in clients {
        let _ = client.await;
    }
}

/// Mutations whose clients have gone do not keep their connections while the boundary is held.
///
/// Three rounds of thirty local clients send a Blocking mutation and go while the boundary is still
/// held. Each round's connections are given back before the next begins, so the third finds the
/// worker where the first did, and nothing was done for any of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutations_whose_clients_have_gone_do_not_keep_their_connections_while_the_boundary_is_held()
 {
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let start = service.connections_held_for_tests();
    let mut asked = Vec::new();
    for round in 1..=3 {
        let ids: Vec<_> = (0..30)
            .map(|_| kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()))
            .collect();
        let clients: Vec<_> = ids.iter().map(|id| attaching_once(&host, *id)).collect();
        asked.extend(ids);
        settle(|| service.mutations_waiting_for_tests() == 30).await;
        assert_eq!(
            service.mutations_waiting_for_tests(),
            30,
            "round {round}: the mutations wait at the held boundary"
        );
        clients_go(clients).await;
        settle(|| {
            service.connections_held_for_tests() == start
                && service.mutations_waiting_for_tests() == 0
        })
        .await;
        assert_eq!(
            service.connections_held_for_tests(),
            start,
            "round {round}: the connections of the clients that went are given back while the boundary is still held"
        );
        assert_eq!(
            service.mutations_waiting_for_tests(),
            0,
            "round {round}: no mutation of a client that went still waits"
        );
    }
    boundary.release();
    for action_id in asked {
        assert!(
            !receipt_exists(&host, action_id).await,
            "a receipt was written for a client that was not there"
        );
    }
}

/// A mutation whose client goes at the pause before the look leaves nothing, and one whose client
/// goes at the pause after it is carried out.
///
/// Both pauses are inside the boundary on a free worker, so the peer is gone when the look comes
/// at the first and gone after it at the second. The look is the check under the boundary, which no
/// try that failed has made: a mutation that took the boundary at once is checked there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_whose_client_goes_before_the_look_is_dropped_and_after_it_is_carried_out() {
    let host = host_ready().await;
    let service = &host.service;
    let start = service.connections_held_for_tests();

    let before = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let (arrived, go) = service.pause_before_the_look();
    let client = attaching_once(&host, before);
    arrived
        .recv_timeout(SETTLE)
        .expect("the mutation reaches the pause before the look");
    clients_go(vec![client]).await;
    // The pause waits, to a bound, for the system to report that the client has gone: a pipe on
    // Windows stays open until its runtime next turns.
    go.send(true).expect("lets the mutation go");
    assert!(
        settle(|| service.connections_held_for_tests() == start).await,
        "the connection of the client that went is given back"
    );
    assert!(
        !receipt_exists(&host, before).await,
        "a client that went before the look has no receipt"
    );

    let after = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let (arrived, go) = service.pause_inside_boundary();
    let client = attaching_once(&host, after);
    arrived
        .recv_timeout(SETTLE)
        .expect("the mutation reaches the pause after the look");
    clients_go(vec![client]).await;
    go.send(()).expect("lets the mutation go");
    // The receipt is the record of the effect that a connection's end does not undo.
    let mut written = false;
    for _ in 0..1500 {
        if receipt_exists(&host, after).await {
            written = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(written, "a client that went after the look has its receipt");
}

/// How a client's end comes behind the request it wrote.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Goes {
    /// It ends what it sends and stays to read the answer. Unix only: a Windows pipe has no half
    /// close, and the case does not use this way there.
    ShutsItsSendingSide,
    /// Its socket is shut down, where the platform can, and dropped.
    Closes,
}

/// A local client that composes one request, writes it, waits for the case's word, ends as `goes`
/// says, and reads what the worker answers if it stays to read. The task ends with the answer, or
/// with none when the worker ended the connection first. The whole task is bounded.
fn writing_then_going<T: serde::Serialize + Send + Sync + 'static>(
    host: &Host,
    method: Method,
    action_id: kr_protocol::ids::ActionId,
    params: T,
    goes: Goes,
    go: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Option<kr_protocol::envelope::Outcome>> {
    let endpoint = host.endpoint.clone();
    let (environment_id, session_id) = (host.environment_id, host.session_id);
    tokio::spawn(async move {
        let mut go = go;
        tokio::time::timeout(WAIT, async move {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            let request = client
                .compose(
                    method,
                    action_id,
                    target(environment_id, session_id),
                    &params,
                )
                .await
                .expect("composes");
            client
                .send(&ControlFrame::Mutation(Box::new(request)))
                .await
                .expect("writes the request");
            go.wait_for(|gone| *gone)
                .await
                .expect("the case lets the client go");
            if goes == Goes::Closes {
                #[cfg(unix)]
                client
                    .writer()
                    .shut_down(std::net::Shutdown::Both)
                    .expect("shuts the client's socket down");
                return None;
            }
            #[cfg(unix)]
            client
                .writer()
                .shut_down(std::net::Shutdown::Write)
                .expect("ends what the client sends");
            while let Ok(frame) = client.recv().await {
                if let ControlFrame::Response(response) = frame {
                    return Some(response.outcome);
                }
            }
            None
        })
        .await
        .unwrap_or_default()
    })
}

/// A cancellation whose client has gone is carried out, and a mutation that starts work whose
/// client has gone is dropped.
///
/// Accepted receipts are made, one for each way a client can go, and the boundary is held. For each
/// way, two clients write behind the boundary and then go: one cancels a receipt, and one attaches.
/// The ways are a client that ends what it sends and stays to read (Unix) and one that closes its
/// socket. The attaches leave the wait at once and nothing is made for them. The cancellations keep
/// their places for as long as the boundary is held, and no longer: at the release each cancels its
/// receipt, the client that stayed is answered, and every connection is given back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancellation_whose_client_has_gone_is_carried_out_and_a_starting_mutation_is_dropped() {
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let user = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let ways: &[Goes] = if cfg!(unix) {
        &[Goes::ShutsItsSendingSide, Goes::Closes]
    } else {
        &[Goes::Closes]
    };
    let offered: Vec<_> = ways
        .iter()
        .map(|_| kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()))
        .collect();
    {
        let mut session = service.runtime().session();
        let journal = session.journal_mut().expect("a journal");
        for action_id in &offered {
            let now_ms = kr_ipc::now_ms();
            journal
                .accept(&kr_worker::journal::Submission {
                    actor_id: user.clone(),
                    action_id: *action_id,
                    method: Method::SessionAttach.into(),
                    method_version: kr_protocol::method::MethodVersion::V1,
                    payload_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
                    subject_digest: kr_protocol::scalars::Digest256::from_bytes([8; 32]),
                    intent: vec![0xa0],
                    accepted_deadline_ms: Some(kr_protocol::scalars::TimestampMs::new(
                        now_ms.get() + 120_000,
                    )),
                    now_ms,
                })
                .expect("accepts the offer");
        }
    }
    let start = service.connections_held_for_tests();
    let boundary = Held::boundary(&host).await;
    let (go, goes) = tokio::sync::watch::channel(false);
    let new_id = || kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let mut cancelling = Vec::new();
    let mut attaching = Vec::new();
    let mut attached = Vec::new();
    for (way, offer) in ways.iter().zip(&offered) {
        cancelling.push((
            *way,
            writing_then_going(
                &host,
                Method::ActionCancel,
                new_id(),
                kr_protocol::receipt::ActionCancelParams { action_id: *offer },
                *way,
                goes.clone(),
            ),
        ));
        let action_id = new_id();
        attached.push(action_id);
        attaching.push(writing_then_going(
            &host,
            Method::SessionAttach,
            action_id,
            attach_params(host.session_id),
            *way,
            goes.clone(),
        ));
    }
    let clients = ways.len();
    // Each client has written its request and waits for the word to go: all of them wait at the
    // held boundary with their peers there.
    assert!(
        settle(|| service.mutations_waiting_for_tests() == 2 * clients).await,
        "the requests wait at the held boundary"
    );
    go.send(true).expect("lets the clients go");
    assert!(
        settle(|| {
            service.mutations_waiting_for_tests() == clients
                && service.connections_held_for_tests() == start + clients
        })
        .await,
        "the attaches leave the wait and give back their connections, and the cancellations keep \
         theirs: {} waiting, {} held",
        service.mutations_waiting_for_tests(),
        service.connections_held_for_tests()
    );
    boundary.release();
    for (way, client) in cancelling {
        let answered = tokio::time::timeout(SETTLE, client)
            .await
            .expect("the client's task ends once the cancellation is carried out")
            .expect("the client's task finishes");
        if way == Goes::ShutsItsSendingSide {
            assert!(
                matches!(answered, Some(kr_protocol::envelope::Outcome::Ok(_))),
                "the cancellation was carried out and answered: {answered:?}"
            );
        }
    }
    for (which, action_id) in offered.iter().enumerate() {
        let cancelled = settle(|| {
            let session = service.runtime().session();
            session
                .journal()
                .expect("a journal")
                .read(user.clone(), *action_id)
                .expect("reads the journal")
                .is_some_and(|receipt| {
                    receipt.reason.as_ref()
                        == Some(&kr_protocol::receipt::RejectionReason::Cancelled)
                })
        })
        .await;
        assert!(cancelled, "offer {which} says cancelled");
    }
    for client in attaching {
        let _ = client.await;
    }
    assert!(
        settle(|| service.connections_held_for_tests() == start).await,
        "every connection is given back"
    );
    for action_id in attached {
        assert!(
            !receipt_exists(&host, action_id).await,
            "a receipt was written for a starting mutation whose client was not there"
        );
    }
}

/// What the requests wait with is a pause that doubles to a quarter of a second and no more.
///
/// A living mutation waits at the held boundary. The case reads the longest pause the wait asked
/// its timer for, which is a value the wait requested and not how long anything took, once it has
/// reached the cap: a cap that stood higher would have asked for more by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_request_asks_its_timer_for_a_quarter_of_a_second_at_most() {
    let host = host_ready().await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let client = attaching_once(&host, kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()));
    settle(|| service.mutations_waiting_for_tests() == 1).await;
    assert_eq!(service.mutations_waiting_for_tests(), 1);
    let reached = settle(|| {
        service.largest_boundary_step_for_tests() >= std::time::Duration::from_millis(250)
    })
    .await;
    assert!(
        reached,
        "the wait never reached the cap: {:?}",
        service.largest_boundary_step_for_tests()
    );
    assert!(
        service.largest_boundary_step_for_tests() <= std::time::Duration::from_millis(250),
        "a pause of more than a quarter of a second was asked for: {:?}",
        service.largest_boundary_step_for_tests()
    );
    boundary.release();
    clients_go(vec![client]).await;
}

/// A controller link that goes does not keep its connection while a holder has the authority
/// record, and its place in the authority record is taken out when the holder lets go.
///
/// The link presents before the hold, as a link does that was admitted before it. The owner does
/// the unbind once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_controller_link_that_goes_while_the_authority_is_held_is_unbound_once_when_it_is_let_go()
{
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let link = controller_client(&host, 1).await;
    assert!(
        service.controller_is_bound_for_tests(),
        "the link is the controller's connection in the authority record"
    );
    let start = service.connections_held_for_tests();
    let holder = Held::boundary_and_authority(&host).await;
    drop(link);
    assert!(
        settle(|| service.connections_held_for_tests() == start - 1).await,
        "the connection of the link that went is given back while the authority is held"
    );
    assert_eq!(
        service.owed_done_for_tests().2,
        0,
        "nothing is unbound while the authority is held"
    );
    holder.release();
    assert!(
        settle(|| !service.controller_is_bound_for_tests()).await,
        "the owner removes the link from the authority record when the authority is let go"
    );
    assert_eq!(
        service.owed_done_for_tests().2,
        1,
        "the owner took the link's entry once"
    );
}

/// Connections that keep identifiers of attachments that another connection detached do not keep
/// their places while the boundary and the session are held.
///
/// Sixty clients each attach in turn, and the owner's own connection detaches each attachment at
/// once, so no more than a few attachments are live while sixty connections keep an identifier. All
/// sixty go under a holder of the boundary and the session. Their connections are given back, and
/// each identifier is detached once, to no effect, when the holder lets go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn connections_that_keep_detached_identifiers_do_not_keep_their_places_while_the_session_is_held()
 {
    use kr_protocol::attachment::{SessionAttachResult, SessionDetachParams};
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let mut owner = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut clients = Vec::new();
    for _ in 0..60 {
        let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                target(host.environment_id, host.session_id),
                &attach_params(host.session_id),
            )
            .await
            .expect("reaches the worker")
            .expect("the terminal attaches")
            .to_typed()
            .expect("decodes");
        owner
            .mutate(
                Method::SessionDetach,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                target(host.environment_id, host.session_id),
                &SessionDetachParams {
                    attachment_id: Nullable::some(attached.attachment.attachment_id),
                    line_token: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the owner detaches it");
        clients.push(client);
    }
    let start = service.connections_held_for_tests() - clients.len();
    let holder = Held::boundary_and_session(&host).await;
    drop(clients);
    assert!(
        settle(|| service.connections_held_for_tests() == start).await,
        "the connections that kept a detached identifier are given back while the session is held: {} of {} still held",
        service.connections_held_for_tests() - start,
        60
    );
    assert_eq!(
        service.owed_done_for_tests().1,
        0,
        "nothing is detached while the session is held"
    );
    holder.release();
    assert!(
        settle(|| service.owed_done_for_tests().1 == 60).await,
        "the owner detaches each identifier once when the session is let go: {:?}",
        service.owed_done_for_tests()
    );
    assert_eq!(service.owed_done_for_tests().1, 60, "once each");
    assert!(
        service.runtime().session().attachments().is_empty(),
        "no attachment is left"
    );
}

/// Connections that keep live attachments do not keep their places while the boundary and the
/// session are held, and the owner detaches each attachment when the session is let go.
///
/// Thirty clients each attach and keep the attachment: nobody detaches, so every identifier a
/// connection keeps names a live attachment. All thirty go under a holder of the boundary and the
/// session. Their connections are given back and nothing is detached while the holder has the
/// session; at its release the owner detaches every one, which the session's own list shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn connections_that_keep_live_attachments_do_not_keep_their_places_while_the_session_is_held()
{
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let mut clients = Vec::new();
    for _ in 0..30 {
        let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .mutate(
                Method::SessionAttach,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                target(host.environment_id, host.session_id),
                &attach_params(host.session_id),
            )
            .await
            .expect("reaches the worker")
            .expect("the terminal attaches");
        clients.push(client);
    }
    assert_eq!(
        service.runtime().session().attachments().len(),
        30,
        "every attachment is live"
    );
    let start = service.connections_held_for_tests() - clients.len();
    let holder = Held::boundary_and_session(&host).await;
    drop(clients);
    assert!(
        settle(|| service.connections_held_for_tests() == start).await,
        "the connections that kept a live attachment are given back while the session is held: {} \
         of 30 still held",
        service.connections_held_for_tests() - start
    );
    assert_eq!(
        service.owed_done_for_tests().1,
        0,
        "nothing is detached while the session is held"
    );
    holder.release();
    assert!(
        settle(|| service.runtime().session().attachments().is_empty()).await,
        "the owner detaches every live attachment when the session is let go: {} left",
        service.runtime().session().attachments().len()
    );
}

/// A presentation whose peer hung up with bytes queued behind its token ends at once on Unix, where
/// the system reports the hang-up beside the bytes.
///
/// The frame is larger than 4 KiB so that on every platform some of it stays in the connection. On
/// Windows the peek counts those bytes as waiting and the peer is taken as there until they are
/// read, which a worker that waits for the boundary does not do, so this case is Unix's alone.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presentation_whose_peer_hung_up_with_bytes_behind_its_token_ends_at_once() {
    let host = host_ready().await;
    let service = &host.service;
    let start = service.connections_held_for_tests();
    let boundary = Held::boundary(&host).await;
    let mut link = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
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
    let large =
        kr_protocol::envelope::ParamsValue::from_typed(&"x".repeat(5 * 1024)).expect("encodes");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        link.send(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: kr_protocol::ids::RequestId::new(7),
            method: Method::SessionRead.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params: large,
        })),
    )
    .await
    .expect("the send of the 5 KiB frame behind the token did not complete within 10 s")
    .expect("sends a frame behind the token");
    drop(link);
    assert!(
        settle(|| service.presentations_waiting_for_tests() == 0
            && service.connections_held_for_tests() == start)
        .await,
        "a presentation whose peer hung up behind its bytes still waits: {} waiting, {} connections over the start",
        service.presentations_waiting_for_tests(),
        service.connections_held_for_tests() - start
    );
    boundary.release();
}

// ---- The fence, a repeat after the clean-up, clients that stay, and the cap.

/// The attention link that goes while the fence's own lock is held gives its connection back, and
/// the fence forgets it when the lock is let go.
///
/// The authority record is free, so the first try of the clean-up removes the link from it, and the
/// fence's lock is what it cannot take: the owner does the whole unbind once the lock is let go.
/// The case waits for the link's first statement before it takes the lock, so that nothing the
/// connection does for its own acceptance meets the held lock, and it reads the fence's state from
/// the holder's own thread, since a read of the fence from the case would wait for the lock too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_link_that_goes_while_the_fence_is_held_is_forgotten_when_it_is_let_go() {
    let host = host_ready_apart(true).await;
    let service = &host.service;
    let mut link = declared(&host, ControllerConnectionRole::Attention).await;
    present(&mut link, host.signer(), 1)
        .await
        .expect("the attention link is accepted");
    let statement = match tokio::time::timeout(SETTLE, link.recv()).await {
        Ok(Ok(ControlFrame::AttentionBarrier(statement))) => statement,
        other => panic!("the link's first statement did not arrive: {other:?}"),
    };
    // The worker's loop for this link waits for the daemon to acknowledge its statement and reads
    // nothing else until then, so a link that goes before the acknowledgement is not seen to go.
    // The acknowledgement, and an answer to a request sent after it, show that the loop is reading.
    link.send(&ControlFrame::AttentionBarrierAcknowledged(
        kr_protocol::attention::AttentionBarrierAcknowledged {
            request_id: statement.request_id,
            sequence: statement.sequence,
        },
    ))
    .await
    .expect("acknowledges the statement");
    link.send(&ControlFrame::Request(kr_protocol::envelope::Request {
        request_id: kr_protocol::ids::RequestId::new(9),
        method: Method::SessionRead.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        params: kr_protocol::envelope::ParamsValue::from_typed(&SessionReadParams {
            session_id: host.session_id,
        })
        .expect("encodes"),
    }))
    .await
    .expect("sends a request");
    loop {
        match tokio::time::timeout(SETTLE, link.recv()).await {
            Ok(Ok(ControlFrame::Response(_))) => break,
            Ok(Ok(_)) => {}
            other => panic!("the link's loop did not answer after the acknowledgement: {other:?}"),
        }
    }
    assert!(
        service.attention_connection_for_tests().is_some(),
        "the fence speaks through the attention link"
    );
    let start = service.connections_held_for_tests();
    let holder = Held::fence(&host).await;
    drop(link);
    let given_back = settle(|| service.connections_held_for_tests() == start - 1).await;
    assert!(
        given_back,
        "the connection of the link that went is given back while the fence is held: {} held, {start} at the start",
        service.connections_held_for_tests()
    );
    assert_eq!(
        service.owed_done_for_tests().2,
        0,
        "nothing is unbound while the fence is held"
    );
    assert!(
        holder.release_naming_the_fence(),
        "the fence still names the link while its lock is held"
    );
    assert!(
        settle(|| service.owed_done_for_tests().2 == 1).await,
        "the owner unbinds the link when the fence's lock is let go: {:?}",
        service.owed_done_for_tests()
    );
    assert!(
        service.attention_connection_for_tests().is_none(),
        "the fence forgets the link when its lock is let go"
    );
    assert_eq!(service.owed_done_for_tests().2, 1, "once");
}

/// A local client that composes one Blocking mutation, hands the composed request to the case,
/// sends it, and waits for the answer. Ending the task is the client going away.
fn composing_once(
    host: &Host,
    action_id: kr_protocol::ids::ActionId,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<kr_protocol::envelope::MutationRequest>,
) {
    let endpoint = host.endpoint.clone();
    let (environment_id, session_id) = (host.environment_id, host.session_id);
    let (kept, composed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = tokio::time::timeout(WAIT, async {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            let mutation = client
                .compose(
                    Method::SessionAttach,
                    action_id,
                    target(environment_id, session_id),
                    &attach_params(session_id),
                )
                .await
                .expect("composes");
            let _ = kept.send(mutation.clone());
            let _ = client
                .send(&ControlFrame::Mutation(Box::new(mutation)))
                .await;
            let _ = client.recv().await;
        })
        .await;
    });
    (task, composed)
}

/// A repeat of a dropped mutation on a new connection is refused, the worker holds no receipt for
/// it, and a new request for the same action is applied once.
///
/// The composed request quotes the window of the connection that went, which the new connection
/// was never given, so a repeat of it is refused with `PERMISSION_DENIED` and nothing is made for
/// it. `action.read` says that the worker holds no receipt, and a request composed on the new
/// connection, with its own window, is admitted for the first time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_after_the_clean_up_is_refused_and_a_new_request_is_applied_once() {
    let host = host_ready().await;
    let service = &host.service;
    let start = service.connections_held_for_tests();
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let boundary = Held::boundary(&host).await;
    let (client, composed) = composing_once(&host, action_id);
    let composed = tokio::time::timeout(SETTLE, composed)
        .await
        .expect("the client composes its request in time")
        .expect("the client hands over its composed request");
    settle(|| service.mutations_waiting_for_tests() == 1).await;
    assert_eq!(
        service.mutations_waiting_for_tests(),
        1,
        "the mutation waits at the held boundary"
    );
    clients_go(vec![client]).await;
    assert!(
        settle(|| service.connections_held_for_tests() == start
            && service.mutations_waiting_for_tests() == 0)
        .await,
        "the connection of the client that went is given back while the boundary is held"
    );
    boundary.release();
    assert!(
        !receipt_exists(&host, action_id).await,
        "a receipt was written for a client that was not there"
    );

    let mut later = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let refused = later
        .repeat(&composed)
        .await
        .expect("the worker answers")
        .expect_err("a repeat quotes the window of the connection that went");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    let read = later
        .request(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await
        .expect("the worker answers")
        .expect_err("the worker holds no receipt");
    assert!(
        read.message.contains("no receipt for action"),
        "the worker's refusal is {read:?}"
    );
    later
        .mutate(
            Method::SessionAttach,
            action_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("the worker answers")
        .expect("a request with the new window is applied");
    assert!(
        receipt_exists(&host, action_id).await,
        "the new request has its receipt"
    );
    assert_eq!(
        service.runtime().session().attachments().len(),
        1,
        "the action was applied once"
    );
}

/// Dead clients' places are given back while a living client waits at the same boundary, and the
/// living client's request is carried out at the release.
///
/// Thirty local clients send a Blocking mutation and go; one stays. The count falls to what the
/// living client keeps, and after the release its request is answered and has its receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_clients_places_are_given_back_while_a_living_client_waits_and_is_served_at_the_release()
 {
    let host = host_ready().await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let living_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let mut living = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mutation = living
        .compose(
            Method::SessionAttach,
            living_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("composes");
    living
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("sends");
    settle(|| service.mutations_waiting_for_tests() == 1).await;
    let start = service.connections_held_for_tests();
    let ids: Vec<_> = (0..30)
        .map(|_| kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()))
        .collect();
    let dead: Vec<_> = ids.iter().map(|id| attaching_once(&host, *id)).collect();
    settle(|| service.mutations_waiting_for_tests() == 31).await;
    assert_eq!(
        service.mutations_waiting_for_tests(),
        31,
        "the living client's request and the thirty others wait at the held boundary"
    );
    clients_go(dead).await;
    assert!(
        settle(|| service.connections_held_for_tests() == start
            && service.mutations_waiting_for_tests() == 1)
        .await,
        "the dead clients' places are given back and the living client's request still waits: {} held, {start} at the start, {} waiting",
        service.connections_held_for_tests(),
        service.mutations_waiting_for_tests()
    );
    boundary.release();
    let answered = tokio::time::timeout(WAIT, living.recv())
        .await
        .expect("the living client is answered after the release")
        .expect("the connection is read");
    let ControlFrame::Response(response) = answered else {
        panic!("the worker answered {answered:?}");
    };
    assert!(
        matches!(response.outcome, kr_protocol::envelope::Outcome::Ok(_)),
        "the living client's request is carried out: {:?}",
        response.outcome
    );
    assert!(
        receipt_exists(&host, living_id).await,
        "the living client's request has its receipt"
    );
    for id in ids {
        assert!(
            !receipt_exists(&host, id).await,
            "a receipt was written for a client that was not there"
        );
    }
}

/// A client that stopped waiting for its answer but keeps its connection still holds its place, and
/// its request is carried out at the release.
///
/// This is the named limit: the worker cannot tell a client that stopped waiting from one that is
/// slow, and a connection that is still there is served. The wait has gone through its tries up to
/// the cap before the holder lets go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stopped_waiting_but_keeps_its_connection_is_served_at_the_release() {
    let host = host_ready().await;
    let service = &host.service;
    let start = service.connections_held_for_tests();
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let boundary = Held::boundary(&host).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mutation = client
        .compose(
            Method::SessionAttach,
            action_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("composes");
    client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("sends");
    settle(|| service.mutations_waiting_for_tests() == 1).await;
    assert_eq!(service.mutations_waiting_for_tests(), 1);
    assert!(
        settle(|| {
            service.largest_boundary_step_for_tests() >= std::time::Duration::from_millis(250)
        })
        .await,
        "the wait never reached the cap: {:?}",
        service.largest_boundary_step_for_tests()
    );
    assert_eq!(
        service.connections_held_for_tests(),
        start + 1,
        "the connection that is still there keeps its place"
    );
    boundary.release();
    assert!(
        settle(|| service.mutations_waiting_for_tests() == 0).await,
        "the request is taken at the release"
    );
    assert!(
        receipt_exists(&host, action_id).await,
        "the request of the client that is still there was carried out"
    );
    drop(client);
}

/// What an Independent mutation whose client has gone comes to while the boundary is held.
///
/// The request is a viewport report, which leaves keys alone, so the loop serves keys beside it
/// with a task that reads the connection ahead. With `blocking_behind` a Blocking mutation follows
/// it, which is where that task stops reading, and the peer's close is then the next thing on the
/// socket. The report waits at the held boundary, and its connection is given back when the client
/// goes, with no receipt for it.
async fn an_independent_mutation_whose_client_goes(blocking_behind: bool) {
    let host = host_ready_apart(false).await;
    let service = &host.service;
    let start = service.connections_held_for_tests();
    let boundary = Held::boundary(&host).await;
    let report_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let behind_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let report = client
        .compose(
            Method::AttachmentViewport,
            report_id,
            target(host.environment_id, host.session_id),
            &kr_protocol::attachment::AttachmentViewportParams {
                attachment_id: kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
                dimensions: Dimensions::new(80, 24),
                position: Nullable::null(),
                column: kr_protocol::scalars::U64::new(0),
            },
        )
        .await
        .expect("composes the report");
    client
        .send(&ControlFrame::Mutation(Box::new(report)))
        .await
        .expect("sends the report");
    settle(|| service.mutations_waiting_for_tests() == 1).await;
    assert_eq!(
        service.mutations_waiting_for_tests(),
        1,
        "the report waits at the held boundary"
    );
    if blocking_behind {
        let behind = client
            .compose(
                Method::SessionAttach,
                behind_id,
                target(host.environment_id, host.session_id),
                &attach_params(host.session_id),
            )
            .await
            .expect("composes the attach");
        client
            .send(&ControlFrame::Mutation(Box::new(behind)))
            .await
            .expect("sends the attach");
    }
    drop(client);
    assert!(
        settle(|| service.connections_held_for_tests() == start
            && service.mutations_waiting_for_tests() == 0)
        .await,
        "the connection of the client that went is given back while the boundary is held: {} held, {start} at the start, {} waiting",
        service.connections_held_for_tests(),
        service.mutations_waiting_for_tests()
    );
    boundary.release();
    assert!(
        !receipt_exists(&host, report_id).await,
        "a receipt was written for the report of a client that was not there"
    );
    assert!(
        !receipt_exists(&host, behind_id).await,
        "a receipt was written for the request behind it"
    );
}

/// An Independent mutation whose client goes is dropped at the held boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_independent_mutation_whose_client_goes_is_dropped() {
    an_independent_mutation_whose_client_goes(false).await;
}

/// An Independent mutation whose reading task stopped at a Blocking mutation behind it is dropped
/// when its client goes.
///
/// Unix only. The Blocking mutation is read by the task that reads ahead or is still queued on the
/// socket when the client closes. A Windows pipe counts what is queued as waiting and takes its
/// peer as there until it is read, which this worker does not do at the wait, so on Windows the
/// request would wait for the release. The rule without a frame behind it is
/// `an_independent_mutation_whose_client_goes_is_dropped`, which holds on every platform.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_independent_mutation_with_a_blocking_one_behind_it_is_dropped_when_its_client_goes() {
    an_independent_mutation_whose_client_goes(true).await;
}

/// A waiting request among a stream of mutations asks for its pause up to the cap, and is taken
/// soon after the release.
///
/// Four clients attach and detach back to back, and a fifth sends one attach, all while the boundary
/// is held. The case waits until the largest pause the wait asked its timer for is the cap, lets go,
/// and takes the time until the fifth is answered. The pause asked for is a value and is asserted;
/// the time to the answer is printed and has only the bound of a liveness check, since it depends
/// on the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_waiting_request_among_a_stream_of_mutations_is_taken_soon_after_the_release() {
    let host = host_ready().await;
    let service = &host.service;
    let boundary = Held::boundary(&host).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let made = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let streams: Vec<_> = (0..4)
        .map(|_| {
            tokio::spawn(mutating(
                host.endpoint.clone(),
                host.environment_id,
                host.session_id,
                Arc::clone(&stop),
                Arc::clone(&made),
            ))
        })
        .collect();
    let mut probe = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let probe_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let composed = probe
        .compose(
            Method::SessionAttach,
            probe_id,
            target(host.environment_id, host.session_id),
            &attach_params(host.session_id),
        )
        .await
        .expect("composes");
    probe
        .send(&ControlFrame::Mutation(Box::new(composed)))
        .await
        .expect("sends");
    settle(|| service.mutations_waiting_for_tests() == 5).await;
    assert_eq!(
        service.mutations_waiting_for_tests(),
        5,
        "the stream and the probe wait at the held boundary"
    );
    assert!(
        settle(|| {
            service.largest_boundary_step_for_tests() >= std::time::Duration::from_millis(250)
        })
        .await,
        "the wait never reached the cap: {:?}",
        service.largest_boundary_step_for_tests()
    );
    let released = tokio::time::Instant::now();
    boundary.release();
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), probe.recv())
        .await
        .expect("the probe is answered within ten seconds of the release")
        .expect("the connection is read");
    eprintln!(
        "the probe was answered {:?} after the release; the stream made {} calls so far",
        released.elapsed(),
        made.load(std::sync::atomic::Ordering::SeqCst)
    );
    let ControlFrame::Response(response) = answered else {
        panic!("the worker answered {answered:?}");
    };
    assert!(matches!(
        response.outcome,
        kr_protocol::envelope::Outcome::Ok(_)
    ));
    assert!(
        service.largest_boundary_step_for_tests() <= std::time::Duration::from_millis(250),
        "a pause of more than a quarter of a second was asked for: {:?}",
        service.largest_boundary_step_for_tests()
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    for stream in streams {
        let _ = tokio::time::timeout(WAIT, stream).await;
    }
}
