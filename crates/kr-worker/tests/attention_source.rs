//! One session's attention sources, read by the control daemon over its attention connection.
//!
//! The environment's attention store is the daemon's; a session's question ledger and host events
//! stay in the session's journal. What is proved here is the session's side: the pages and their
//! heads, the request a worker holds until something is committed, the connection nothing else
//! may use, which text is served under privacy mode, and the fingerprints that keep an item's
//! identity whether or not its text is.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attention::{
    AttentionBarrier, AttentionRecordRef, AttentionSource, AttentionSourcePage,
    AttentionSourcesRequest, AttentionTextAnswer, AttentionTextRequest,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    BuildId, ConnectionId, ControllerGeneration, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Nullable, SecretBytes32, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::journal::Journal;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    host_with(true).await
}

/// A session and its worker, with a journal or, when `journal` is false, with none.
async fn host_with(journal: bool) -> Host {
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
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
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
        journal_path: journal.then(|| journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
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
                controller_generation: ControllerGeneration::new(1),
                journal_path: journal.then(|| journal_path.clone()),
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
        journal_path,
        endpoint,
        controller,
        boot,
    }
}

/// The daemon's end of a connection to the worker, as these tests play it.
///
/// Like the daemon, it records the greatest privacy generation the worker states, pages and
/// answers with, and [`page`] and [`text`] name it on the requests they send.
struct Link {
    client: LocalClient,
    recorded: Option<u64>,
    /// The worker's statements of its privacy fence, in the order they arrived.
    statements: Vec<AttentionBarrier>,
}

impl Link {
    const fn of(client: LocalClient) -> Self {
        Self {
            client,
            recorded: None,
            statements: Vec::new(),
        }
    }

    fn note(&mut self, generation: Nullable<U64>) {
        self.recorded = self.recorded.max(generation.0.map(U64::get));
    }

    /// The recorded generation, as a request names it.
    fn named(&self) -> Nullable<U64> {
        Nullable(self.recorded.map(U64::new))
    }

    /// Reads frames until the next statement of the worker's fence, failing past `bound`.
    async fn statement(&mut self, bound: Duration) -> AttentionBarrier {
        tokio::time::timeout(bound, async {
            loop {
                match self.client.recv().await.expect("the worker answers") {
                    ControlFrame::AttentionBarrier(statement) => {
                        self.note(statement.generation);
                        self.statements.push(statement.clone());
                        return statement;
                    }
                    ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                    other => panic!("expected a statement, got {other:?}"),
                }
            }
        })
        .await
        .expect("the worker states its fence in time")
    }

    /// Acknowledges a statement, as the daemon does once it has applied one.
    async fn acknowledge(&mut self, statement: &AttentionBarrier) {
        self.client
            .writer()
            .write_message(&ControlFrame::AttentionBarrierAcknowledged(
                kr_protocol::attention::AttentionBarrierAcknowledged {
                    request_id: statement.request_id,
                    sequence: statement.sequence,
                },
            ))
            .await
            .expect("acknowledges");
    }
}

impl std::ops::Deref for Link {
    type Target = LocalClient;

    fn deref(&self) -> &LocalClient {
        &self.client
    }
}

impl std::ops::DerefMut for Link {
    fn deref_mut(&mut self) -> &mut LocalClient {
        &mut self.client
    }
}

/// A connection of the daemon's, declared for `role` and speaking for generation one.
async fn daemon(host: &Host, role: ControllerConnectionRole) -> Link {
    daemon_receiving(host, role, kr_protocol::hello::ReceiveLimits::default()).await
}

/// The same, saying it can receive `limits`.
///
/// An attention connection's first frame after the acceptance is the worker's statement of its
/// fence, which is read here as the daemon reads it before anything the connection carries.
async fn daemon_receiving(
    host: &Host,
    role: ControllerConnectionRole,
    limits: kr_protocol::hello::ReceiveLimits,
) -> Link {
    let mut client = LocalClient::connect_receiving(
        &host.endpoint,
        LocalClientKind::Controller,
        build(),
        limits,
    )
    .await
    .expect("connects");
    client
        .writer()
        .write_message(&ControlFrame::ControllerRole(role))
        .await
        .expect("declares the role");
    match client.recv().await.expect("the worker answers") {
        ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
        other => panic!("the worker answered {other:?}"),
    }
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    let mut link = Link::of(client);
    if role == ControllerConnectionRole::Attention {
        let _ = link.statement(Duration::from_secs(5)).await;
    }
    link
}

fn sources(questions_after: u64, host_events_after: u64, wait_ms: u64) -> AttentionSourcesRequest {
    AttentionSourcesRequest {
        request_id: RequestId::new(21),
        questions_after: U64::new(questions_after),
        host_events_after: U64::new(host_events_after),
        max_records: U64::new(64),
        wait_ms: U64::new(wait_ms),
        fingerprint_key: SecretBytes32::from_bytes([9; 32]),
        // The generation a session starts at; [`page`] names what the link has recorded instead.
        recorded_generation: Nullable::some(U64::ZERO),
    }
}

fn texts(records: &[(AttentionSource, u64)]) -> AttentionTextRequest {
    AttentionTextRequest {
        request_id: RequestId::new(22),
        records: records
            .iter()
            .map(|(source, sequence)| AttentionRecordRef {
                source: *source,
                sequence: U64::new(*sequence),
            })
            .collect(),
        // The generation a session starts at; [`text`] names what the link has recorded instead.
        recorded_generation: Nullable::some(U64::ZERO),
    }
}

/// What came back for one attention request.
#[derive(Debug)]
enum Answer {
    Page(Box<AttentionSourcePage>),
    Texts(Box<AttentionTextAnswer>),
    Refused(RequestId, ErrorCode),
}

async fn next_answer(link: &mut Link) -> Answer {
    loop {
        match link.client.recv().await.expect("the worker answers") {
            ControlFrame::AttentionBarrier(statement) => {
                link.note(statement.generation);
                link.statements.push(statement);
            }
            ControlFrame::AttentionSourcePage(page) => {
                link.note(page.privacy_generation);
                return Answer::Page(page);
            }
            ControlFrame::AttentionTextAnswer(answer) => {
                link.note(answer.privacy_generation);
                return Answer::Texts(answer);
            }
            ControlFrame::Response(response) => match response.outcome {
                Outcome::Error(error) => {
                    return Answer::Refused(response.request_id, error.code);
                }
                other => panic!("the worker answered {other:?}"),
            },
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn page(link: &mut Link, request: AttentionSourcesRequest) -> AttentionSourcePage {
    let request = AttentionSourcesRequest {
        recorded_generation: link.named(),
        ..request
    };
    link.writer()
        .write_message(&ControlFrame::AttentionSources(request))
        .await
        .expect("writes the request");
    match next_answer(link).await {
        Answer::Page(page) => *page,
        other => panic!("expected a page, got {other:?}"),
    }
}

async fn text(link: &mut Link, request: AttentionTextRequest) -> AttentionTextAnswer {
    let request = AttentionTextRequest {
        recorded_generation: link.named(),
        ..request
    };
    link.writer()
        .write_message(&ControlFrame::AttentionText(request))
        .await
        .expect("writes the request");
    match next_answer(link).await {
        Answer::Texts(answer) => *answer,
        other => panic!("expected text, got {other:?}"),
    }
}

fn verified_source() -> kr_worker::questions::VerifiedSource {
    kr_worker::questions::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("/bin/agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(kr_ipc::new_uuid()),
    }
}

fn now() -> kr_worker::questions::Now {
    kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

fn ask(host: &Host, request: &str, question: &str) -> kr_protocol::question::Question {
    host.service
        .questions()
        .create(
            &verified_source(),
            &kr_protocol::question::QuestionCreateParams {
                session_id: host.session_id,
                request_id: request.to_owned(),
                agent_name: Nullable::some("an agent".to_owned()),
                context: "two ways to do it".to_owned(),
                question: question.to_owned(),
                kind: kr_protocol::question::QuestionKind::Confirm,
                choices: Vec::new(),
                requested_expiry_ms: Nullable::null(),
                wait_ms: Nullable::null(),
            },
            now(),
        )
        .expect("a verified source creates a question")
        .0
        .question
}

/// Withdraws a question from the answering surface, which records a transition carrying it.
fn cancel(host: &Host, question: &kr_protocol::question::Question) {
    host.service
        .questions()
        .cancel(
            &kr_protocol::question::QuestionCancelParams {
                session_id: host.session_id,
                question_id: question.question_id,
                expected_revision: question.revision,
            },
            now(),
        )
        .expect("the question is withdrawn");
}

/// Records a notification the session printed with no attachment to send it to.
fn notify(host: &Host, body: &str) {
    let mut session = host.service.runtime().session();
    session
        .journal_mut()
        .expect("the harness journals its session")
        .record_host_event(
            &kr_term::sideeffect::SideEffect {
                kind: kr_term::sideeffect::SideEffectKind::Notification {
                    title: None,
                    body: body.to_owned(),
                    id: None,
                    urgency: kr_term::sideeffect::NotificationUrgency::Normal,
                    display: kr_term::sideeffect::NotificationDisplay::Always,
                },
                destination: kr_term::sideeffect::SideEffectDestination::HostEvent,
                at: 0,
            },
            kr_ipc::now_ms(),
        )
        .expect("the journal records it");
}

/// What the journal records a notification as: its urgency, then what it said.
fn said(body: &str) -> String {
    format!("Normal: {body}")
}

fn enable_privacy(host: &Host) {
    host.service
        .runtime()
        .session()
        .enable_privacy(&mut [])
        .expect("privacy mode is enabled");
}

fn disable_privacy(host: &Host) {
    host.service
        .runtime()
        .session()
        .disable_privacy()
        .expect("privacy mode is disabled");
}

fn question_texts(page: &AttentionSourcePage) -> Vec<Option<String>> {
    page.questions
        .records
        .iter()
        .map(|record| record.text.0.clone())
        .collect()
}

fn host_texts(page: &AttentionSourcePage) -> Vec<Option<String>> {
    page.host_events
        .records
        .iter()
        .map(|record| record.text.0.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Pages and heads
// ---------------------------------------------------------------------------------------------

/// KR-REQ-18.01 and KR-REQ-25.03: a page carries each source's records after the cursor it names,
/// up to that source's head, with the text the session serves and a fingerprint for each
/// notification; a page that stops short says so by its head.
#[tokio::test]
async fn a_page_carries_each_source_after_its_cursor_up_to_its_head() {
    let host = host().await;
    ask(&host, "r-1", "which branch?");
    ask(&host, "r-2", "deploy now?");
    notify(&host, "the build finished");
    notify(&host, "the tests passed");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;

    let before = kr_ipc::clock::boot_elapsed_ms();
    let first = page(&mut link, sources(0, 0, 0)).await;
    assert_eq!(first.request_id, RequestId::new(21));
    assert!(first.built_at_boot_ms.get() >= before);
    assert_eq!(first.questions.head, U64::new(2));
    assert_eq!(
        question_texts(&first),
        vec![
            Some("which branch?".to_owned()),
            Some("deploy now?".to_owned())
        ]
    );
    assert!(first.questions.records.iter().all(|record| record.verified));
    assert_eq!(first.host_events.head, U64::new(2));
    assert_eq!(
        host_texts(&first),
        vec![
            Some(said("the build finished")),
            Some(said("the tests passed"))
        ]
    );
    assert!(
        first
            .host_events
            .records
            .iter()
            .all(|record| record.notification && record.fingerprint.is_present())
    );
    assert_eq!(first.privacy_generation, Nullable::some(U64::new(0)));

    // From the heads, nothing more, and the heads are where they were.
    let rest = page(&mut link, sources(2, 2, 0)).await;
    assert!(rest.questions.records.is_empty() && rest.host_events.records.is_empty());
    assert_eq!(
        (rest.questions.head, rest.host_events.head),
        (U64::new(2), U64::new(2))
    );

    // A page that stops short of a head is one the daemon reads again at once.
    let short = page(
        &mut link,
        AttentionSourcesRequest {
            max_records: U64::new(1),
            ..sources(0, 0, 0)
        },
    )
    .await;
    assert_eq!(short.questions.records.len(), 1);
    assert_eq!(short.questions.records[0].sequence, U64::new(1));
    assert!(short.questions.records[0].sequence < short.questions.head);
}

// ---------------------------------------------------------------------------------------------
// The held request
// ---------------------------------------------------------------------------------------------

/// Waits for the next answer on the link, failing if it takes longer than `within`.
async fn within(link: &mut Link, bound: Duration) -> Answer {
    tokio::time::timeout(bound, next_answer(link))
        .await
        .expect("the worker answered in time")
}

/// KR-REQ-25.03: a request with nothing to answer with is held, and a question committed while it
/// is held answers it at once; a text request is served beside it meanwhile.
#[tokio::test]
async fn a_held_page_answers_when_a_question_is_committed() {
    let host = host().await;
    notify(&host, "the build finished");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    link.writer()
        .write_message(&ControlFrame::AttentionSources(sources(0, 1, 20_000)))
        .await
        .expect("writes the request");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_answer(&mut link))
            .await
            .is_err(),
        "nothing past the cursors, so the request is held"
    );

    // The connection goes on serving text while the page is held.
    let served = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    assert_eq!(
        served.texts[0].text,
        Nullable::some(said("the build finished"))
    );

    ask(&host, "r-1", "which branch?");
    let Answer::Page(page) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected the held page");
    };
    assert_eq!(page.questions.records.len(), 1);
    assert_eq!(
        page.questions.records[0].text,
        Nullable::some("which branch?".to_owned())
    );
}

/// KR-REQ-25.03: a host event committed while a request is held answers it at once.
#[tokio::test]
async fn a_held_page_answers_when_a_host_event_is_committed() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    link.writer()
        .write_message(&ControlFrame::AttentionSources(sources(0, 0, 20_000)))
        .await
        .expect("writes the request");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_answer(&mut link))
            .await
            .is_err()
    );
    notify(&host, "the build finished");
    let Answer::Page(page) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected the held page");
    };
    assert_eq!(page.host_events.records.len(), 1);
}

/// KR-REQ-24.11: a privacy transition committed while a request is held answers it at once,
/// under the new generation, though no record was added.
#[tokio::test]
async fn a_held_page_answers_when_privacy_mode_changes() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    link.writer()
        .write_message(&ControlFrame::AttentionSources(sources(0, 0, 20_000)))
        .await
        .expect("writes the request");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_answer(&mut link))
            .await
            .is_err()
    );
    enable_privacy(&host);
    let Answer::Page(page) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected the held page");
    };
    assert_eq!(page.privacy_generation, Nullable::some(U64::new(1)));
}

/// A held request is answered when its bound runs out, with nothing in it.
#[tokio::test]
async fn a_held_page_answers_at_its_bound() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let started = std::time::Instant::now();
    let answered = page(&mut link, sources(0, 0, 400)).await;
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(400));
    assert!(
        waited < Duration::from_secs(5),
        "answered at its bound: {waited:?}"
    );
    assert!(answered.questions.records.is_empty() && answered.host_events.records.is_empty());
}

/// A newer request replaces a held one, which then answers nothing, even when something it
/// would have answered with is committed afterwards.
#[tokio::test]
async fn a_newer_request_replaces_a_held_one() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    link.writer()
        .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
            request_id: RequestId::new(31),
            ..sources(0, 0, 20_000)
        }))
        .await
        .expect("writes the first request");
    link.writer()
        .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
            request_id: RequestId::new(32),
            ..sources(0, 0, 0)
        }))
        .await
        .expect("writes the second request");
    let Answer::Page(page) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected the second request's page");
    };
    assert_eq!(page.request_id, RequestId::new(32));
    notify(&host, "the build finished");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), next_answer(&mut link))
            .await
            .is_err(),
        "the replaced request answers nothing"
    );

    // Nor does one replaced as its bound runs out.
    for round in 0..5_u64 {
        link.writer()
            .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
                request_id: RequestId::new(100 + round),
                ..sources(0, 1, 50)
            }))
            .await
            .expect("writes the held request");
        tokio::time::sleep(Duration::from_millis(50)).await;
        link.writer()
            .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
                request_id: RequestId::new(200 + round),
                ..sources(0, 1, 0)
            }))
            .await
            .expect("writes the replacement");
        let Answer::Page(page) = within(&mut link, Duration::from_secs(5)).await else {
            panic!("expected a page");
        };
        if page.request_id == RequestId::new(100 + round) {
            // The held request's bound ran out before the replacement arrived: it was answered
            // then, and the replacement is answered after it.
            let Answer::Page(replacement) = within(&mut link, Duration::from_secs(5)).await else {
                panic!("expected the replacement's page");
            };
            assert_eq!(replacement.request_id, RequestId::new(200 + round));
        } else {
            assert_eq!(page.request_id, RequestId::new(200 + round));
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_answer(&mut link))
            .await
            .is_err(),
        "nothing else arrives"
    );
}

// ---------------------------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------------------------

/// The attention requests are served only on the daemon's attention connection, and that
/// connection serves nothing else.
#[tokio::test]
async fn the_attention_requests_travel_on_the_attention_connection_alone() {
    let host = host().await;
    for role in [
        ControllerConnectionRole::Authority,
        ControllerConnectionRole::Proxy,
    ] {
        let mut other = daemon(&host, role).await;
        other
            .writer()
            .write_message(&ControlFrame::AttentionSources(sources(0, 0, 0)))
            .await
            .expect("writes");
        assert!(matches!(
            next_answer(&mut other).await,
            Answer::Refused(_, ErrorCode::PermissionDenied)
        ));
        other
            .writer()
            .write_message(&ControlFrame::AttentionText(texts(&[])))
            .await
            .expect("writes");
        assert!(matches!(
            next_answer(&mut other).await,
            Answer::Refused(_, ErrorCode::PermissionDenied)
        ));
    }
    let mut cli = Link::of(
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects"),
    );
    cli.writer()
        .write_message(&ControlFrame::AttentionSources(sources(0, 0, 0)))
        .await
        .expect("writes");
    assert!(matches!(next_answer(&mut cli).await, Answer::Refused(..)));
    cli.writer()
        .write_message(&ControlFrame::AttentionText(texts(&[])))
        .await
        .expect("writes");
    assert!(matches!(next_answer(&mut cli).await, Answer::Refused(..)));

    // And the attention connection is not a way to read anything else.
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    link.writer()
        .write_message(&ControlFrame::Request(Request {
            request_id: RequestId::new(5),
            method: Method::SessionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        }))
        .await
        .expect("writes");
    assert!(
        matches!(
            next_answer(&mut link).await,
            Answer::Refused(id, ErrorCode::PermissionDenied) if id == RequestId::new(5)
        ),
        "refused under the request's own identifier"
    );
}

/// A newer attention connection replaces the one before it.
#[tokio::test]
async fn a_newer_attention_connection_replaces_the_older() {
    let host = host().await;
    let mut older = daemon(&host, ControllerConnectionRole::Attention).await;
    let _ = page(&mut older, sources(0, 0, 0)).await;
    let mut newer = daemon(&host, ControllerConnectionRole::Attention).await;
    let _ = page(&mut newer, sources(0, 0, 0)).await;
    older
        .writer()
        .write_message(&ControlFrame::AttentionSources(sources(0, 0, 0)))
        .await
        .ok();
    let answer = tokio::time::timeout(Duration::from_secs(5), older.recv()).await;
    let refused = match answer {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(ControlFrame::Response(response))) => {
            matches!(response.outcome, Outcome::Error(_))
        }
        Ok(Ok(_)) => false,
    };
    assert!(refused, "the older connection is fenced");
}

// ---------------------------------------------------------------------------------------------
// Privacy mode
// ---------------------------------------------------------------------------------------------

/// KR-REQ-24.11: text from before privacy mode was enabled, and text written while it was on, is
/// never served again, live or from the session's journal, and text written after it was turned
/// off is.
#[tokio::test]
async fn text_from_before_a_privacy_transition_is_never_served_again() {
    let host = host().await;
    ask(&host, "r-1", "before");
    notify(&host, "before");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let open = page(&mut link, sources(0, 0, 0)).await;
    assert_eq!(question_texts(&open), vec![Some("before".to_owned())]);

    enable_privacy(&host);
    ask(&host, "r-2", "while private");
    notify(&host, "while private");
    let private = page(&mut link, sources(0, 0, 0)).await;
    assert!(question_texts(&private).iter().all(Option::is_none));
    assert!(host_texts(&private).iter().all(Option::is_none));

    disable_privacy(&host);
    ask(&host, "r-3", "after");
    notify(&host, "after");
    let reopened = page(&mut link, sources(0, 0, 0)).await;
    assert_eq!(
        question_texts(&reopened),
        vec![None, None, Some("after".to_owned())]
    );
    assert_eq!(host_texts(&reopened), vec![None, None, Some(said("after"))]);
    assert_eq!(reopened.privacy_generation, Nullable::some(U64::new(2)));

    let named = text(
        &mut link,
        texts(&[
            (AttentionSource::Questions, 1),
            (AttentionSource::Questions, 2),
            (AttentionSource::Questions, 3),
            (AttentionSource::HostEvents, 1),
            (AttentionSource::HostEvents, 3),
        ]),
    )
    .await;
    let served: Vec<Option<String>> = named.texts.iter().map(|one| one.text.0.clone()).collect();
    assert_eq!(
        served,
        vec![
            None,
            None,
            Some("after".to_owned()),
            None,
            Some(said("after"))
        ]
    );
    assert_eq!(named.privacy_generation, Nullable::some(U64::new(2)));

    // The session's journal, read on its own, says the same.
    let journal = Journal::open_read_only(&host.journal_path).expect("reads the journal");
    let closed = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(question_texts(&closed), question_texts(&reopened));
    assert_eq!(host_texts(&closed), host_texts(&reopened));
}

/// KR-REQ-24.11: a question's later transitions never serve the wording it was asked with, so a
/// question asked before privacy mode was enabled, or while it was on, and withdrawn after it was
/// turned off serves no text from either record.
#[tokio::test]
async fn a_question_resolved_after_a_privacy_transition_serves_no_earlier_text() {
    let host = host().await;
    let before = ask(&host, "r-1", "asked before");
    enable_privacy(&host);
    let during = ask(&host, "r-2", "asked while private");
    disable_privacy(&host);
    cancel(&host, &before);
    cancel(&host, &during);
    let after = ask(&host, "r-3", "asked after");
    cancel(&host, &after);
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let answered = page(&mut link, sources(0, 0, 0)).await;
    let kinds: Vec<_> = answered
        .questions
        .records
        .iter()
        .map(|record| (record.sequence.get(), record.kind, record.text.0.clone()))
        .collect();
    use kr_protocol::question::QuestionEventKind::{Cancelled, Created};
    assert_eq!(
        kinds,
        vec![
            (1, Created, None),
            (2, Created, None),
            (3, Cancelled, None),
            (4, Cancelled, None),
            (5, Created, Some("asked after".to_owned())),
            (6, Cancelled, None),
        ]
    );
    let named = text(
        &mut link,
        texts(&[
            (AttentionSource::Questions, 3),
            (AttentionSource::Questions, 4),
            (AttentionSource::Questions, 5),
            (AttentionSource::Questions, 6),
        ]),
    )
    .await;
    let served: Vec<Option<String>> = named.texts.iter().map(|one| one.text.0.clone()).collect();
    assert_eq!(
        served,
        vec![None, None, Some("asked after".to_owned()), None]
    );

    // The session's journal, read on its own as a closed session's is, says the same.
    let journal = Journal::open_read_only(&host.journal_path).expect("reads the journal");
    let closed = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(question_texts(&closed), question_texts(&answered));
    let from_journal = kr_worker::attention_source::texts(
        &journal,
        &texts(&[
            (AttentionSource::Questions, 1),
            (AttentionSource::Questions, 2),
            (AttentionSource::Questions, 3),
            (AttentionSource::Questions, 4),
            (AttentionSource::Questions, 5),
            (AttentionSource::Questions, 6),
        ]),
    )
    .expect("reads the text");
    let served: Vec<Option<String>> = from_journal
        .texts
        .iter()
        .map(|one| one.text.0.clone())
        .collect();
    assert_eq!(
        served,
        vec![None, None, None, None, Some("asked after".to_owned()), None]
    );
}

/// A page fits the frame the daemon's connection said it can receive, and a text request whose
/// answer would not fit is refused under its own identifier; a frame too small for even one record
/// refuses the page the same way.
#[tokio::test]
async fn an_answer_fits_the_frame_the_connection_can_receive() {
    let host = host().await;
    for index in 0..40 {
        notify(&host, &format!("{index:03} {}", "x".repeat(400)));
    }
    let small = kr_protocol::hello::ReceiveLimits {
        max_control_frame_len: U64::new(8 * 1024),
        ..kr_protocol::hello::ReceiveLimits::default()
    };
    let mut link = daemon_receiving(&host, ControllerConnectionRole::Attention, small).await;
    let answered = page(&mut link, sources(0, 0, 0)).await;
    let carried = answered.host_events.records.len();
    assert!(
        carried > 0 && carried < 40,
        "a page cut to the frame: {carried} records"
    );
    assert!(
        kr_worker::attention_source::measure(&ControlFrame::AttentionSourcePage(Box::new(
            answered.clone()
        ))) <= 8 * 1024
    );
    // A page read without a budget is cut, not refused: records come off its end until its frame
    // fits, the records nearest the cursor stay, and only a frame too small for one record refuses.
    let journal = Journal::open_read_only(&host.journal_path).expect("reads the journal");
    let mut whole = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, usize::MAX)
        .expect("reads the page");
    assert_eq!(whole.host_events.records.len(), 40);
    assert!(kr_worker::attention_source::fit(&mut whole, 8 * 1024));
    assert!(!whole.host_events.records.is_empty() && whole.host_events.records.len() < 40);
    assert_eq!(whole.host_events.records[0].sequence.get(), 1);
    assert!(
        kr_worker::attention_source::measure(&ControlFrame::AttentionSourcePage(Box::new(
            whole.clone()
        ))) <= 8 * 1024
    );
    let mut cramped_page =
        kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, usize::MAX)
            .expect("reads the page");
    assert!(!kr_worker::attention_source::fit(&mut cramped_page, 300));

    // The next page goes on from where this one stopped.
    let next = page(
        &mut link,
        sources(
            0,
            answered.host_events.records[carried - 1].sequence.get(),
            0,
        ),
    )
    .await;
    assert_eq!(
        next.host_events.records[0].sequence.get(),
        answered.host_events.records[carried - 1].sequence.get() + 1
    );

    let every: Vec<(AttentionSource, u64)> = (1..=40)
        .map(|sequence| (AttentionSource::HostEvents, sequence))
        .collect();
    link.writer()
        .write_message(&ControlFrame::AttentionText(AttentionTextRequest {
            request_id: RequestId::new(41),
            ..texts(&every)
        }))
        .await
        .expect("writes");
    assert!(
        matches!(
            next_answer(&mut link).await,
            Answer::Refused(id, ErrorCode::InvalidArgument) if id == RequestId::new(41)
        ),
        "an answer too big for the frame is refused under the request's identifier"
    );

    let tiny = kr_protocol::hello::ReceiveLimits {
        max_control_frame_len: U64::new(
            u64::try_from(kr_protocol::limits::MAX_STREAM_HEADER_LEN).expect("small") + 300,
        ),
        ..kr_protocol::hello::ReceiveLimits::default()
    };
    let mut cramped = daemon_receiving(&host, ControllerConnectionRole::Attention, tiny).await;
    cramped
        .writer()
        .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
            request_id: RequestId::new(42),
            ..sources(0, 0, 0)
        }))
        .await
        .expect("writes");
    assert!(matches!(
        next_answer(&mut cramped).await,
        Answer::Refused(id, ErrorCode::InvalidArgument) if id == RequestId::new(42)
    ));
}

/// KR-REQ-24.11: a session that never changed privacy mode serves its text, live and from its
/// journal, and a journal whose privacy record is gone serves none.
#[tokio::test]
async fn a_session_that_never_changed_privacy_mode_serves_its_text_and_a_lost_record_serves_none() {
    let host = host().await;
    ask(&host, "r-1", "which branch?");
    notify(&host, "the build finished");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let live = page(&mut link, sources(0, 0, 0)).await;
    assert_eq!(
        question_texts(&live),
        vec![Some("which branch?".to_owned())]
    );
    assert_eq!(host_texts(&live), vec![Some(said("the build finished"))]);

    let journal = Journal::open_read_only(&host.journal_path).expect("reads the journal");
    let closed = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(question_texts(&closed), question_texts(&live));
    assert_eq!(host_texts(&closed), host_texts(&live));
    drop(journal);

    let connection = rusqlite::Connection::open(&host.journal_path).expect("opens the file");
    connection
        .execute_batch("DELETE FROM privacy;")
        .expect("loses the record");
    drop(connection);
    let lost = page(&mut link, sources(0, 0, 0)).await;
    assert!(question_texts(&lost).iter().all(Option::is_none));
    assert!(host_texts(&lost).iter().all(Option::is_none));
    assert_eq!(lost.privacy_generation, Nullable::null());
    let named = text(&mut link, texts(&[(AttentionSource::Questions, 1)])).await;
    assert_eq!(named.texts[0].text, Nullable::null());
}

/// KR-REQ-25.03: a notification's fingerprint is the same whether or not its text is served, so
/// identical notifications are one condition across privacy transitions; the same key makes the
/// same fingerprint from the session's journal once the session is read there, and another key
/// makes another.
#[tokio::test]
async fn a_fingerprint_is_the_same_across_privacy_transitions() {
    let host = host().await;
    notify(&host, "the build finished");
    enable_privacy(&host);
    notify(&host, "the build finished");
    disable_privacy(&host);
    notify(&host, "the build finished");
    notify(&host, "something else");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let answered = page(&mut link, sources(0, 0, 0)).await;
    let fingerprints: Vec<_> = answered
        .host_events
        .records
        .iter()
        .map(|record| {
            record
                .fingerprint
                .0
                .expect("a notification has a fingerprint")
        })
        .collect();
    assert_eq!(fingerprints[0], fingerprints[1]);
    assert_eq!(fingerprints[1], fingerprints[2]);
    assert_ne!(fingerprints[2], fingerprints[3]);
    assert_eq!(host_texts(&answered)[..2], [None, None]);

    let journal = Journal::open_read_only(&host.journal_path).expect("reads the journal");
    let closed = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(
        closed.host_events.records[0].fingerprint.0,
        Some(fingerprints[0])
    );
    let other = kr_worker::attention_source::page(
        &journal,
        &AttentionSourcesRequest {
            fingerprint_key: SecretBytes32::from_bytes([7; 32]),
            ..sources(0, 0, 0)
        },
        0,
        1 << 20,
    )
    .expect("reads the page");
    assert_ne!(
        other.host_events.records[0].fingerprint.0,
        Some(fingerprints[0])
    );
}

// ---------------------------------------------------------------------------------------------
// The journal's privacy record
// ---------------------------------------------------------------------------------------------

/// Turns a current journal back into what the previous version wrote.
fn as_previous_version(path: &std::path::Path) {
    let connection = rusqlite::Connection::open(path).expect("opens the file");
    connection
        .execute_batch(
            "ALTER TABLE privacy DROP COLUMN questions_head;
             ALTER TABLE privacy DROP COLUMN host_events_head;
             UPDATE schema_version SET version = 5;",
        )
        .expect("writes the previous version's shape");
}

/// KR-REQ-24.11: a journal starts with privacy mode off and nothing before it; one the previous
/// version wrote is brought forward with the record it lacks when it never changed privacy mode,
/// and with its sources' present heads when it did, so nothing from before is served for it.
#[tokio::test]
async fn a_journal_is_brought_forward_to_the_privacy_record_it_needs() {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let directory = temp.path();

    let fresh = directory.join("fresh.db");
    let journal = Journal::open(&fresh).expect("creates a journal");
    let record = journal.read_privacy().expect("reads").expect("a record");
    assert_eq!(
        (
            record.generation,
            record.enabled,
            record.questions_head,
            record.host_events_head
        ),
        (0, false, 0, 0)
    );
    drop(journal);

    // Never changed: the record is written for it, and everything it holds is served.
    let never = directory.join("never.db");
    {
        let mut journal = Journal::open(&never).expect("creates a journal");
        record_notice(&mut journal, "held from before");
    }
    as_previous_version(&never);
    rusqlite::Connection::open(&never)
        .expect("opens")
        .execute_batch("DELETE FROM privacy;")
        .expect("the previous version kept no record for it");
    let journal = Journal::open(&never).expect("migrates");
    let record = journal.read_privacy().expect("reads").expect("a record");
    assert_eq!((record.enabled, record.host_events_head), (false, 0));
    let served = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(host_texts(&served), vec![Some(said("held from before"))]);
    drop(journal);

    // Changed before: the heads are where the sources stand, so what it held is not served.
    let changed = directory.join("changed.db");
    {
        let mut journal = Journal::open(&changed).expect("creates a journal");
        record_notice(&mut journal, "held from before");
        journal
            .record_privacy(2, false, kr_ipc::now_ms())
            .expect("records a transition");
    }
    as_previous_version(&changed);
    let journal = Journal::open(&changed).expect("migrates");
    let record = journal.read_privacy().expect("reads").expect("a record");
    assert_eq!((record.generation, record.host_events_head), (2, 1));
    let withheld = kr_worker::attention_source::page(&journal, &sources(0, 0, 0), 0, 1 << 20)
        .expect("reads the page");
    assert_eq!(host_texts(&withheld), vec![None]);
}

fn record_notice(journal: &mut Journal, body: &str) {
    journal
        .record_host_event(
            &kr_term::sideeffect::SideEffect {
                kind: kr_term::sideeffect::SideEffectKind::Notification {
                    title: None,
                    body: body.to_owned(),
                    id: None,
                    urgency: kr_term::sideeffect::NotificationUrgency::Normal,
                    display: kr_term::sideeffect::NotificationDisplay::Always,
                },
                destination: kr_term::sideeffect::SideEffectDestination::HostEvent,
                at: 0,
            },
            kr_ipc::now_ms(),
        )
        .expect("the journal records it");
}

// ---------------------------------------------------------------------------------------------
// The privacy fence
// ---------------------------------------------------------------------------------------------

/// Raises a privacy transition on a task of its own, as the caller that enables privacy mode does.
fn raise(host: &Host) -> tokio::task::JoinHandle<kr_worker::service::PrivacyTransition> {
    let service = Arc::clone(&host.service);
    tokio::spawn(async move { service.raise_privacy_transition().await })
}

/// Enables privacy mode with the worker's attention subsystem among those it drives.
fn enable_with(host: &Host, attention: &mut kr_worker::attention_fence::AttentionPrivacy) {
    host.service
        .runtime()
        .session()
        .enable_privacy(&mut [attention])
        .expect("privacy mode is enabled");
}

fn reconciled(host: &Host, attention: &kr_worker::attention_fence::AttentionPrivacy) -> bool {
    host.service
        .runtime()
        .session()
        .reconcile_privacy(&[attention])
        .is_complete()
}

/// KR-REQ-24.11: each attention connection starts with the worker's statement of its fence, and
/// statements share one order across connections.
#[tokio::test]
async fn each_attention_connection_starts_with_a_statement_of_the_fence() {
    let host = host().await;
    let older = daemon(&host, ControllerConnectionRole::Attention).await;
    let newer = daemon(&host, ControllerConnectionRole::Attention).await;
    let (first, second) = (&older.statements[0], &newer.statements[0]);
    assert!(!first.raised && !second.raised);
    assert_eq!(first.generation, Nullable::some(U64::ZERO));
    assert!(
        first.sequence < second.sequence,
        "one order across connections"
    );
}

/// KR-REQ-24.11: text in flight when privacy mode is enabled, with a daemon that acknowledges the
/// raise. The raise returns at the acknowledgement without waiting out the text already answered
/// with, since that daemon has stopped releasing it; no answer carries text while the transition
/// is raised; and the settling statement carries the generation committed.
#[tokio::test]
async fn an_acknowledged_raise_lets_the_commit_proceed_at_once() {
    let host = host().await;
    notify(&host, "before");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let before = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    assert_eq!(before.texts[0].text, Nullable::some(said("before")));
    let leased_until = before.release_until_boot_ms.get();
    assert!(leased_until > kr_ipc::clock::boot_elapsed_ms());

    let raising = raise(&host);
    let raised = link.statement(Duration::from_secs(5)).await;
    assert!(raised.raised);
    link.acknowledge(&raised).await;
    let transition = tokio::time::timeout(Duration::from_secs(2), raising)
        .await
        .expect("the raise returns at the acknowledgement")
        .expect("the raise finishes");
    assert!(
        kr_ipc::clock::boot_elapsed_ms() < leased_until,
        "it did not wait out the lease the acknowledging daemon covers"
    );

    let during = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    assert_eq!(during.texts[0].text, Nullable::null());
    assert_eq!(during.release_until_boot_ms, U64::ZERO);

    let mut attention = host.service.attention_privacy();
    enable_with(&host, &mut attention);
    transition.settle().await;
    let settled = link.statement(Duration::from_secs(5)).await;
    assert!(!settled.raised);
    assert_eq!(settled.generation, Nullable::some(U64::new(1)));
    assert!(settled.sequence > raised.sequence);
}

/// KR-REQ-24.11: text in flight when privacy mode is enabled, with a daemon that does not answer
/// the raise. The commit waits until every lease the worker issued has ended, so text answered
/// before the raise cannot be released after the commit whatever that daemon holds, and a text
/// request while the transition is raised is answered with none.
#[tokio::test]
async fn without_an_acknowledgement_the_commit_waits_out_the_last_lease() {
    let host = host().await;
    notify(&host, "before");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let before = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    let leased_until = before.release_until_boot_ms.get();
    assert!(leased_until > 0);

    let raising = raise(&host);
    let raised = link.statement(Duration::from_secs(5)).await;
    assert!(raised.raised, "the raise is stated, and never acknowledged");
    let during = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    assert_eq!(during.texts[0].text, Nullable::null());

    let transition = tokio::time::timeout(Duration::from_secs(15), raising)
        .await
        .expect("the raise returns once the lease has ended")
        .expect("the raise finishes");
    let returned = kr_ipc::clock::boot_elapsed_ms();
    assert!(
        returned >= leased_until,
        "returned at {returned}, before the lease ended at {leased_until}"
    );
    assert!(
        returned < leased_until + 2_000,
        "and not long after it: {returned} against {leased_until}"
    );
    transition.settle().await;
    let settled = link.statement(Duration::from_secs(5)).await;
    assert!(!settled.raised);
    assert_eq!(
        settled.generation,
        Nullable::some(U64::ZERO),
        "nothing was committed"
    );
}

/// KR-REQ-24.11: a request that names a generation behind the worker's is answered with no text,
/// compared with the generation that decided the answer, and a held page that does is answered at
/// once, so the daemon learns a transition without waiting for the request's bound.
#[tokio::test]
async fn a_request_behind_the_worker_s_generation_gets_no_text_and_its_page_at_once() {
    let host = host().await;
    enable_privacy(&host);
    disable_privacy(&host);
    notify(&host, "after");
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    assert_eq!(
        link.recorded,
        Some(2),
        "the first statement names the generation"
    );

    link.writer()
        .write_message(&ControlFrame::AttentionText(AttentionTextRequest {
            recorded_generation: Nullable::some(U64::ZERO),
            ..texts(&[(AttentionSource::HostEvents, 1)])
        }))
        .await
        .expect("writes the request");
    let Answer::Texts(behind) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected text");
    };
    assert_eq!(behind.texts[0].text, Nullable::null());
    assert_eq!(behind.privacy_generation, Nullable::some(U64::new(2)));
    let current = text(&mut link, texts(&[(AttentionSource::HostEvents, 1)])).await;
    assert_eq!(current.texts[0].text, Nullable::some(said("after")));

    link.writer()
        .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
            recorded_generation: Nullable::some(U64::new(1)),
            ..sources(0, 1, 20_000)
        }))
        .await
        .expect("writes the request");
    let Answer::Page(page) = within(&mut link, Duration::from_secs(2)).await else {
        panic!("expected the page at once");
    };
    assert_eq!(page.privacy_generation, Nullable::some(U64::new(2)));
}

/// KR-REQ-24.11: privacy mode reports complete only once a request on the current attention
/// connection names the generation it committed; a connection that replaces it starts from none.
#[tokio::test]
async fn privacy_mode_completes_once_the_current_connection_names_the_generation() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let mut attention = host.service.attention_privacy();
    enable_with(&host, &mut attention);
    assert!(
        !reconciled(&host, &attention),
        "the daemon has recorded nothing yet"
    );

    // A request naming the generation before it completes nothing.
    link.writer()
        .write_message(&ControlFrame::AttentionText(texts(&[])))
        .await
        .expect("writes the request");
    let _ = within(&mut link, Duration::from_secs(5)).await;
    assert!(!reconciled(&host, &attention));

    // One naming it does.
    let _ = page(&mut link, sources(0, 0, 0)).await;
    assert_eq!(link.recorded, Some(1));
    let _ = text(&mut link, texts(&[])).await;
    assert!(reconciled(&host, &attention));

    // A newer connection starts from none, and completes it once it names the generation too.
    let mut newer = daemon(&host, ControllerConnectionRole::Attention).await;
    assert!(!reconciled(&host, &attention));
    let _ = text(&mut newer, texts(&[])).await;
    assert!(reconciled(&host, &attention));
}

/// KR-REQ-24.11: one transition is raised at a time. A second raise waits until the first is
/// settled, and a transition dropped without being settled is settled then.
#[tokio::test]
async fn a_dropped_transition_is_settled_and_a_second_raise_waits_for_it() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let raising = raise(&host);
    let first = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&first).await;
    let transition = raising.await.expect("the first raise finishes");

    let second = raise(&host);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), link.client.recv())
            .await
            .is_err(),
        "the second raise states nothing while the first is raised"
    );
    drop(transition);
    let mut stated = [
        link.statement(Duration::from_secs(5)).await,
        link.statement(Duration::from_secs(5)).await,
    ];
    stated.sort_by_key(|statement| statement.sequence);
    assert!(!stated[0].raised, "the dropped transition is settled first");
    assert!(stated[1].raised, "then the second is raised");
    link.acknowledge(&stated[1]).await;
    tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("the second raise returns")
        .expect("the second raise finishes")
        .settle()
        .await;
    assert!(!link.statement(Duration::from_secs(5)).await.raised);
}

/// KR-REQ-24.11: a statement the worker cannot write whole within its bound ends the attention
/// connection, and the next connection's first statement carries the fence as it is by then: the
/// transition still raised, and then its settlement.
#[tokio::test]
async fn a_statement_that_cannot_be_written_ends_the_connection() {
    let host = host().await;
    for index in 0..256 {
        notify(&host, &format!("{index} {}", "x".repeat(600)));
    }
    let mut older = daemon(&host, ControllerConnectionRole::Attention).await;
    // Pages nobody reads, larger together than the socket holds: the connection's writer is held
    // by one the socket will not take, and nothing but a withdrawal ends that wait.
    for round in 0..3_u64 {
        older
            .writer()
            .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
                request_id: RequestId::new(40 + round),
                max_records: U64::new(256),
                ..sources(0, 0, 0)
            }))
            .await
            .expect("writes the request");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let transition = tokio::time::timeout(Duration::from_secs(20), raise(&host))
        .await
        .expect("the raise returns")
        .expect("the raise finishes");
    // The older connection has ended: whatever it still holds, the stream ends.
    tokio::time::timeout(Duration::from_secs(20), async {
        while older.client.recv().await.is_ok() {}
    })
    .await
    .expect("the older connection ends");

    let mut newer = daemon(&host, ControllerConnectionRole::Attention).await;
    assert!(
        newer.statements[0].raised,
        "the next connection's first statement says the transition is still raised"
    );
    transition.settle().await;
    let settled = newer.statement(Duration::from_secs(5)).await;
    assert!(!settled.raised);
}

/// KR-REQ-24.11: a worker that cannot read its journal's privacy generation cannot say where the
/// session stands, so its statement keeps the daemon's barrier raised, and the connection is ended
/// so the next one states the fence again.
#[tokio::test]
async fn a_worker_that_cannot_read_its_generation_keeps_the_barrier() {
    let host = host_with(false).await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let first = &link.statements[0];
    assert!(first.raised, "the barrier stays raised");
    assert_eq!(first.generation, Nullable::null());
    tokio::time::timeout(Duration::from_secs(10), async {
        while link.client.recv().await.is_ok() {}
    })
    .await
    .expect("the connection ends");
}

/// KR-REQ-24.11: a settlement whose caller stops waiting for it while the connection's writer is
/// busy is still stated: the statement is its own task's, not the caller's.
#[tokio::test]
async fn a_settlement_whose_caller_stops_waiting_is_still_stated() {
    let host = host().await;
    for index in 0..256 {
        notify(&host, &format!("{index} {}", "x".repeat(600)));
    }
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let raising = raise(&host);
    let raised = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&raised).await;
    let transition = raising.await.expect("the raise finishes");

    // Pages nobody reads yet hold the connection's writer, so the settlement has to wait for it.
    for round in 0..3_u64 {
        link.writer()
            .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
                request_id: RequestId::new(60 + round),
                max_records: U64::new(256),
                ..sources(0, 0, 0)
            }))
            .await
            .expect("writes the request");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let settling = tokio::spawn(transition.settle());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !settling.is_finished(),
        "the settlement waits for the writer"
    );
    settling.abort();

    // Reading the pages frees the writer; the settlement goes after them.
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match link.client.recv().await.expect("the worker answers") {
                ControlFrame::AttentionBarrier(statement) => return statement,
                ControlFrame::AttentionSourcePage(_)
                | ControlFrame::Notification(_)
                | ControlFrame::Event(_) => {}
                other => panic!("the worker answered {other:?}"),
            }
        }
    })
    .await
    .expect("the settlement is stated");
    assert!(!settled.raised);
    assert_eq!(settled.generation, Nullable::some(U64::ZERO));
}

/// KR-REQ-24.11: a settlement that cannot be written ends the connection, and the next
/// connection's first statement settles the transition at the generation committed.
#[tokio::test]
async fn a_settlement_that_cannot_be_written_is_stated_by_the_next_connection() {
    let host = host().await;
    for index in 0..256 {
        notify(&host, &format!("{index} {}", "x".repeat(600)));
    }
    let mut older = daemon(&host, ControllerConnectionRole::Attention).await;
    let raising = raise(&host);
    let raised = older.statement(Duration::from_secs(5)).await;
    older.acknowledge(&raised).await;
    let transition = raising.await.expect("the raise finishes");
    let mut attention = host.service.attention_privacy();
    enable_with(&host, &mut attention);

    // Pages nobody reads hold the connection's writer past the settlement's bound.
    for round in 0..3_u64 {
        older
            .writer()
            .write_message(&ControlFrame::AttentionSources(AttentionSourcesRequest {
                request_id: RequestId::new(80 + round),
                max_records: U64::new(256),
                ..sources(0, 0, 0)
            }))
            .await
            .expect("writes the request");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    tokio::time::timeout(Duration::from_secs(10), transition.settle())
        .await
        .expect("the settlement gives up at its bound");
    tokio::time::timeout(Duration::from_secs(20), async {
        while older.client.recv().await.is_ok() {}
    })
    .await
    .expect("the older connection ends");

    let newer = daemon(&host, ControllerConnectionRole::Attention).await;
    let first = &newer.statements[0];
    assert!(!first.raised, "the next connection settles the transition");
    assert_eq!(first.generation, Nullable::some(U64::new(1)));
}

/// KR-REQ-24.11: enable, disable and enable in quick succession, each enable raised and
/// acknowledged, are stated in order, each settlement with the generation it committed.
#[tokio::test]
async fn enable_disable_and_enable_are_stated_in_order() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let mut attention = host.service.attention_privacy();

    let raising = raise(&host);
    let first = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&first).await;
    let transition = raising.await.expect("the first raise finishes");
    enable_with(&host, &mut attention);
    transition.settle().await;
    let first_settled = link.statement(Duration::from_secs(5)).await;

    disable_privacy(&host);

    let raising = raise(&host);
    let second = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&second).await;
    let transition = raising.await.expect("the second raise finishes");
    enable_with(&host, &mut attention);
    transition.settle().await;
    let second_settled = link.statement(Duration::from_secs(5)).await;

    let stated: Vec<(bool, Option<u64>)> = [&first, &first_settled, &second, &second_settled]
        .iter()
        .map(|statement| (statement.raised, statement.generation.0.map(U64::get)))
        .collect();
    assert_eq!(
        stated,
        vec![
            (true, Some(0)),
            (false, Some(1)),
            (true, Some(2)),
            (false, Some(3))
        ]
    );
    let sequences: Vec<U64> = [&first, &first_settled, &second, &second_settled]
        .iter()
        .map(|statement| statement.sequence)
        .collect();
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
}

/// KR-REQ-24.11: a disable committed between a raise and its enable leaves the transition raised:
/// no answer carries text until the enable is settled, and the settlement names the generation
/// the enable committed.
#[tokio::test]
async fn a_disable_between_a_raise_and_its_enable_keeps_the_transition_raised() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let raising = raise(&host);
    let raised = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&raised).await;
    let transition = raising.await.expect("the raise finishes");

    disable_privacy(&host);
    notify(&host, "after the disable");
    // Named at the generation the disable committed, so nothing but the raise can withhold it.
    link.writer()
        .write_message(&ControlFrame::AttentionText(AttentionTextRequest {
            recorded_generation: Nullable::some(U64::new(1)),
            ..texts(&[(AttentionSource::HostEvents, 1)])
        }))
        .await
        .expect("writes the request");
    let Answer::Texts(during) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected text");
    };
    assert_eq!(during.privacy_generation, Nullable::some(U64::new(1)));
    assert_eq!(
        during.texts[0].text,
        Nullable::null(),
        "no text while the transition is raised"
    );

    let mut attention = host.service.attention_privacy();
    enable_with(&host, &mut attention);
    transition.settle().await;
    let settled = link.statement(Duration::from_secs(5)).await;
    assert!(!settled.raised);
    assert_eq!(settled.generation, Nullable::some(U64::new(2)));
}

/// The same request once the transition is settled and privacy mode turned off again carries its
/// text, so what withheld it above was the raise.
#[tokio::test]
async fn text_withheld_only_by_a_raise_is_served_once_it_is_settled() {
    let host = host().await;
    let mut link = daemon(&host, ControllerConnectionRole::Attention).await;
    let raising = raise(&host);
    let raised = link.statement(Duration::from_secs(5)).await;
    link.acknowledge(&raised).await;
    let transition = raising.await.expect("the raise finishes");
    disable_privacy(&host);
    notify(&host, "after the disable");
    transition.settle().await;
    let _ = link.statement(Duration::from_secs(5)).await;
    link.writer()
        .write_message(&ControlFrame::AttentionText(AttentionTextRequest {
            recorded_generation: Nullable::some(U64::new(1)),
            ..texts(&[(AttentionSource::HostEvents, 1)])
        }))
        .await
        .expect("writes the request");
    let Answer::Texts(after) = within(&mut link, Duration::from_secs(5)).await else {
        panic!("expected text");
    };
    assert_eq!(
        after.texts[0].text,
        Nullable::some(said("after the disable"))
    );
}
