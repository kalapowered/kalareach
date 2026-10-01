//! One session's description facts, read by the control daemon over its descriptions connection.
//!
//! A description of a session is built from what the session did, so what is proved here is the
//! session's side: what the worker records from the places it already decides something happened
//! (a command block the shell integration reported, a prompt it admitted, an observation an
//! admitted bridge sent) and nothing it is merely sent (keystrokes, a resize, the terminal's
//! answer to a device query), the request the worker holds until a fact changes, the connection
//! nothing else may use, and what privacy mode stops, clears and tells the daemon.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::describe::{
    DescriptionCompletion, DescriptionEventKind, DescriptionFactsPage, DescriptionFactsRequest,
};
use kr_protocol::envelope::{ControlFrame, Outcome};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    AttachmentId, BuildId, ControllerGeneration, EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
use kr_protocol::privacy::PrivacyGenerationNotice;
use kr_protocol::root::{
    CwdRevision, PromptGeneration, RootCommandBlockParams, RootCommandResolveParams,
};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::fence::{CommandHook, Effects, Step};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

/// How long a held request may take to be answered by the change that moves it.
const LIVENESS: Duration = Duration::from_secs(30);

/// The view the session's one attachment is, which holds the input lease.
const VIEW: AttachmentId = AttachmentId::new(Uuid::from_bytes([5; 16]));

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    epoch: u64,
    _view: kr_worker::output::OutputStream,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A session whose root shell runs `script`, with one view that holds the input lease, and its
/// worker serving the local endpoint.
async fn host(script: &str) -> Host {
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
        shell: kr_worker::testing::posix_script(script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Geometry);
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    session.attach(&params, requested, VIEW).expect("attaches");
    let view = session.subscribe(VIEW).expect("subscribes");
    session
        .acquire_input(
            VIEW,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
            None,
        )
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
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
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
        epoch,
        _view: view,
    }
}

/// A connection of the daemon's, declared for `role` and speaking for generation one.
async fn daemon(host: &Host, role: ControllerConnectionRole) -> LocalClient {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
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
    client
}

/// What came back for one facts request.
#[derive(Debug)]
enum Answer {
    Page(Box<DescriptionFactsPage>),
    Refused(RequestId, ErrorCode),
}

async fn next_answer(link: &mut LocalClient) -> Answer {
    loop {
        match link.recv().await.expect("the worker answers") {
            ControlFrame::DescriptionFactsPage(page) => return Answer::Page(page),
            // An attention connection's worker states its privacy fence before anything else.
            ControlFrame::AttentionBarrier(_) => {}
            ControlFrame::Response(response) => match response.outcome {
                Outcome::Error(error) => return Answer::Refused(response.request_id, error.code),
                other => panic!("the worker answered {other:?}"),
            },
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

fn request(id: u64, after: u64, wait_ms: u64, generation: Option<u64>) -> DescriptionFactsRequest {
    DescriptionFactsRequest {
        request_id: RequestId::new(id),
        after: U64::new(after),
        wait_ms: U64::new(wait_ms),
        generation: Nullable(generation.map(U64::new)),
    }
}

async fn send(link: &mut LocalClient, request: DescriptionFactsRequest) {
    link.writer()
        .write_message(&ControlFrame::DescriptionFacts(request))
        .await
        .expect("writes the request");
}

/// Asks once and reads the page that answers, which has to arrive within [`LIVENESS`].
async fn ask(
    link: &mut LocalClient,
    id: u64,
    after: u64,
    wait_ms: u64,
    generation: Option<u64>,
) -> DescriptionFactsPage {
    send(link, request(id, after, wait_ms, generation)).await;
    page(link).await
}

async fn page(link: &mut LocalClient) -> DescriptionFactsPage {
    match tokio::time::timeout(LIVENESS, next_answer(link))
        .await
        .expect("the worker answers in time")
    {
        Answer::Page(page) => *page,
        other => panic!("expected a page, got {other:?}"),
    }
}

/// A command block the shell integration reports, for the line accepted at the first prompt.
fn block(command: &str, cwd: &str, status: Option<u64>) -> RootCommandBlockParams {
    block_at(1, command, cwd, status)
}

/// A command block the shell integration reports, for the line accepted at prompt generation
/// `generation`.
fn block_at(
    generation: u64,
    command: &str,
    cwd: &str,
    status: Option<u64>,
) -> RootCommandBlockParams {
    RootCommandBlockParams {
        session_id: SessionId::new(Uuid::from_bytes([1; 16])),
        prompt_generation: PromptGeneration::new(generation),
        command: command.to_owned(),
        started_at_ms: TimestampMs::new(1),
        duration_ms: Nullable(status.map(|_| DurationMs::new(1))),
        exit_status: Nullable(status.map(U64::new)),
        cwd: cwd.to_owned(),
        cwd_revision: CwdRevision::new(0),
    }
}

/// Reports a command block to the session as the shell integration's hook does.
fn report(host: &Host, block: RootCommandBlockParams) {
    let _ = host.runtime.session().apply_fence_effects(Effects {
        steps: vec![Step::CommandHook(
            RequestId::new(1),
            Box::new(CommandHook::Block(Box::new(block))),
        )],
        ..Effects::default()
    });
}

/// A file that can be run, which is all a resolution has to name for the program to be named: this
/// test's own executable.
fn executable() -> String {
    std::env::current_exe()
        .expect("this test's own executable")
        .to_string_lossy()
        .into_owned()
}

/// Reports the shell's question in front of an interactive command of the line accepted at prompt
/// generation `generation`, as the shell integration's hook does: the program is named from the
/// file the shell's own search resolved the command to.
fn resolved(host: &Host, generation: u64, argv: &[&str], executable: &str) {
    let invocation = RootCommandResolveParams {
        session_id: SessionId::new(Uuid::from_bytes([1; 16])),
        prompt_generation: PromptGeneration::new(generation),
        argv: argv.iter().map(|word| (*word).to_owned()).collect(),
        executable: executable.to_owned(),
        interactive: true,
        cwd: "/home/a/work".to_owned(),
        cwd_revision: CwdRevision::new(0),
    };
    let _ = host.runtime.session().apply_fence_effects(Effects {
        steps: vec![Step::CommandHook(
            RequestId::new(1),
            Box::new(CommandHook::Resolve(invocation)),
        )],
        ..Effects::default()
    });
}

/// Waits until the worker has begun to hold `count` facts requests in all, which is when a change
/// made next is what answers the newest of them: a request that replaced another is one more.
async fn until_held(host: &Host, count: usize) {
    tokio::time::timeout(LIVENESS, async {
        while host.service.facts_holds_begun() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker holds the request");
}

/// Waits until the session's retained output carries `marker` `count` times: the terminal's own
/// echo of what was typed, and the program's answer to it.
async fn until_echoed(host: &Host, marker: &str, count: usize) {
    let marker = marker.as_bytes();
    let deadline = tokio::time::Instant::now() + LIVENESS;
    loop {
        let mut seen = Vec::new();
        let mut cursor = 0_u64;
        loop {
            let page = host
                .runtime
                .session()
                .history_page(cursor, 1024 * 1024)
                .expect("reads the retained output");
            if page.bytes.as_slice().is_empty() {
                break;
            }
            seen.extend_from_slice(page.bytes.as_slice());
            cursor = page.next_cursor.get();
        }
        if seen
            .windows(marker.len())
            .filter(|window| *window == marker)
            .count()
            >= count
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the typed input was not echoed in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Types into the terminal as the view holding the lease does.
fn type_in(host: &mut Host, sequence: u64, bytes: &[u8]) {
    host.runtime
        .session()
        .write_input(
            VIEW,
            host.epoch,
            sequence,
            bytes,
            None,
            std::time::Instant::now(),
        )
        .expect("the input is accepted");
    host.runtime.flush_input();
}

/// Tells the session its privacy generation, on the daemon's authority connection, as the daemon
/// does, and returns once the worker has answered.
async fn tell_privacy(host: &Host, authority: &mut LocalClient, generation: u64, enabled: bool) {
    authority
        .writer()
        .write_message(&ControlFrame::PrivacyGeneration(PrivacyGenerationNotice {
            environment_id: host.environment_id,
            generation: U64::new(generation),
            enabled,
        }))
        .await
        .expect("writes the notice");
    loop {
        match tokio::time::timeout(LIVENESS, authority.recv())
            .await
            .expect("the worker answers in time")
            .expect("the worker answers")
        {
            ControlFrame::PrivacyGenerationAck(ack) => {
                assert_eq!(ack.generation.get(), generation);
                return;
            }
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------------------------

/// The descriptions connection carries the facts request and nothing else: a request for anything
/// the connection was not declared for is refused under its own identifier. A newer connection
/// replaces the one before it, and the attention connection is a different one that it does not
/// displace.
#[tokio::test]
async fn the_descriptions_connection_carries_facts_requests_only_and_a_newer_one_replaces_it() {
    let host = host("exec cat").await;
    let mut older = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let first = ask(&mut older, 1, 0, 0, None).await;
    assert_eq!(first.session_id, host.session_id);
    assert_eq!(first.request_id, RequestId::new(1));

    // Anything else on it is refused, and the refusal names the request: a read the daemon's
    // other connections may make, and an attention request.
    older
        .writer()
        .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: RequestId::new(5),
            method: kr_protocol::method::Method::SessionRead.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params: kr_protocol::envelope::ParamsValue::from_typed(
                &kr_protocol::session::SessionReadParams {
                    session_id: host.session_id,
                },
            )
            .expect("encodes"),
        }))
        .await
        .expect("writes");
    assert!(
        matches!(
            next_answer(&mut older).await,
            Answer::Refused(id, ErrorCode::PermissionDenied) if id == RequestId::new(5)
        ),
        "refused under the request's own identifier"
    );

    // The control: a facts request on a connection declared for attention is refused too.
    let mut attention = daemon(&host, ControllerConnectionRole::Attention).await;
    send(&mut attention, request(6, 0, 0, None)).await;
    assert!(
        matches!(
            next_answer(&mut attention).await,
            Answer::Refused(id, ErrorCode::PermissionDenied) if id == RequestId::new(6)
        ),
        "a facts request is the descriptions connection's alone"
    );

    // A newer descriptions connection replaces the older, and displaces no other.
    let mut newer = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let second = ask(&mut newer, 2, 0, 0, None).await;
    assert_eq!(second.request_id, RequestId::new(2));
    older
        .writer()
        .write_message(&ControlFrame::DescriptionFacts(request(3, 0, 0, None)))
        .await
        .ok();
    // Fenced is an explicit refusal or a closed connection; a connection that says nothing at all
    // is a stalled one, which fences nothing.
    let answer = tokio::time::timeout(LIVENESS, older.recv())
        .await
        .expect("the older connection answers or closes, and does not stall");
    let fenced = match answer {
        Err(_) => true,
        Ok(ControlFrame::Response(response)) => matches!(response.outcome, Outcome::Error(_)),
        Ok(_) => false,
    };
    assert!(fenced, "the older connection is fenced");
}

// ---------------------------------------------------------------------------------------------
// What is recorded
// ---------------------------------------------------------------------------------------------

/// KR-REQ-01.14, KR-REQ-22.05: a command the shell integration reports becomes the directory it
/// ran in, its program name and how it ended, and its arguments are in none of them. A page names
/// the generation the facts were captured under and a revision that rises with each change.
#[tokio::test]
async fn a_command_block_becomes_a_directory_a_program_and_a_completion() {
    let host = host("exec cat").await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let empty = ask(&mut link, 1, 0, 0, Some(0)).await;
    assert_eq!(empty.facts.0, None, "nothing has happened yet");
    assert!(!empty.private);

    resolved(
        &host,
        1,
        &["cargo", "test", "--all", "--token", "hunter2"],
        &executable(),
    );
    report(
        &host,
        block(
            "cargo test --all --token hunter2",
            "/home/a/kalareach",
            None,
        ),
    );
    let started = ask(&mut link, 2, 0, 0, Some(0)).await;
    let facts = started.facts.0.expect("facts");
    assert_eq!(facts.directory.0.as_deref(), Some("kalareach"));
    assert_eq!(facts.application.0.as_deref(), Some("cargo"));
    assert_eq!(facts.completion.0, None);
    assert_eq!(facts.generation.get(), 0);
    assert_eq!(facts.events.len(), 1);
    assert_eq!(facts.events[0].kind, DescriptionEventKind::CommandAccepted);
    let encoded = serde_json::to_string(&facts).expect("facts encode");
    assert!(
        !encoded.contains("hunter2") && !encoded.contains("--all"),
        "a command's arguments are what a person typed: {encoded}"
    );

    report(
        &host,
        block(
            "cargo test --all --token hunter2",
            "/home/a/kalareach",
            Some(0),
        ),
    );
    let ended = ask(&mut link, 3, facts.revision.get(), 0, Some(0)).await;
    let after = ended.facts.0.expect("facts");
    assert_eq!(after.completion.0, Some(DescriptionCompletion::Succeeded));
    assert!(after.revision.get() > facts.revision.get());
}

/// KR-REQ-22.05: a token typed at the prompt as one plain word is recorded as no program: the
/// shell found no file to run, so it asked nothing, and the page names the directory and no
/// program, with no event. The control is a command the shell did resolve to a
/// file, which is recorded under the line's own generation.
#[tokio::test]
async fn a_word_typed_at_the_prompt_is_no_program_and_a_resolved_command_still_is() {
    let host = host("exec cat").await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;

    report(&host, block("kr-9f3a7c1e-token", "/home/a/work", None));
    let pasted = ask(&mut link, 1, 0, 0, Some(0)).await;
    let facts = pasted.facts.0.expect("facts");
    assert_eq!(facts.directory.0.as_deref(), Some("work"));
    assert_eq!(facts.application.0, None, "a pasted word is no program");
    assert!(facts.events.is_empty(), "and no command is announced");
    let encoded = serde_json::to_string(&facts).expect("facts encode");
    assert!(!encoded.contains("9f3a7c1e"), "{encoded}");

    // A shell that asks about a word with slashes in it, found or not, is not believed: the path
    // it names is no file.
    resolved(
        &host,
        2,
        &["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        "/home/a/work/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );
    report(
        &host,
        block_at(
            2,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "/home/a/work",
            None,
        ),
    );
    let slashed = ask(&mut link, 2, 0, 0, Some(0)).await;
    let facts = slashed.facts.0.expect("facts");
    assert_eq!(facts.application.0, None, "a pasted token with slashes");
    assert!(facts.events.is_empty());
    let encoded = serde_json::to_string(&facts).expect("facts encode");
    assert!(!encoded.contains("bPxRfiCY"), "{encoded}");

    resolved(&host, 3, &["make", "all"], &executable());
    report(&host, block_at(3, "make all", "/home/a/work", None));
    let made = ask(&mut link, 3, facts.revision.get(), 0, Some(0)).await;
    let facts = made.facts.0.expect("facts");
    assert_eq!(facts.application.0.as_deref(), Some("make"));
    assert_eq!(facts.events.len(), 1);
}

/// A request the worker holds is answered by the change that moves the facts, and not before:
/// the first frame back is the page of the change, never an earlier empty one. The control is a
/// request that asks for no wait, which is answered at once with nothing.
#[tokio::test]
async fn a_held_request_is_answered_by_the_change_that_moves_the_facts() {
    let host = host("exec cat").await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let base = ask(&mut link, 1, 0, 0, Some(0)).await;
    assert_eq!(base.facts.0, None);
    let current = base.privacy_generation.0.map(U64::get);

    // The control: nothing newer, no wait, answered at once and empty.
    let none = ask(&mut link, 2, 0, 0, current).await;
    assert_eq!(none.facts.0, None);

    // Held for up to five minutes, and answered by the change: the change is made once the worker
    // says it is holding the request, so an answer that came before it would be the first frame.
    send(&mut link, request(3, 0, 300_000, current)).await;
    until_held(&host, 1).await;
    resolved(&host, 1, &["make"], &executable());
    report(&host, block("make", "/home/a/work", None));
    let answered = page(&mut link).await;
    assert_eq!(answered.request_id, RequestId::new(3));
    let changed = answered.facts.0.as_ref().expect("the change's facts");
    assert_eq!(changed.application.0.as_deref(), Some("make"));

    // A newer request replaces a held one: only the newer is answered.
    let revision = changed.revision.get();
    send(&mut link, request(4, revision, 300_000, current)).await;
    until_held(&host, 2).await;
    send(&mut link, request(5, revision, 300_000, current)).await;
    // The first is let go and the second is held in its place.
    until_held(&host, 3).await;
    report(&host, block_at(2, "ls", "/home/a/work", None));
    let replaced = page(&mut link).await;
    assert_eq!(replaced.request_id, RequestId::new(5));
}

/// KR-REQ-01.14, KR-REQ-22.05: keystrokes, a resize and the terminal's answer to a device query
/// move no revision and make no page. The control is a command block, which moves it.
#[tokio::test]
async fn keystrokes_resizes_and_queries_move_no_revision_and_answer_no_page() {
    // The shell asks the terminal what it is, and the terminal answers into the shell's input.
    let mut host = host("printf '\\033[c\\033[6n'; exec cat").await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let base = ask(&mut link, 1, 0, 0, Some(0)).await;
    assert_eq!(base.facts.0, None);

    type_in(&mut host, 0, b"echo hello\n");
    type_in(&mut host, 1, b"\x1b[200~pasted\x1b[201~");
    // The view claims the geometry, so the resize is its own and takes effect.
    {
        let mut session = host.runtime.session();
        session.configure(VIEW, true).expect("claims the geometry");
        let epoch = session.geometry().epoch.get();
        session
            .resize(VIEW, Dimensions::new(100, 30), epoch)
            .expect("the owner resizes");
        assert_eq!(session.geometry().dimensions, Dimensions::new(100, 30));
    }
    // The shell has read the input once its terminal has echoed the line back and the program has
    // answered it: only then is "nothing was recorded" a statement about the input.
    until_echoed(&host, "hello", 2).await;
    let quiet = ask(&mut link, 2, 0, 0, Some(0)).await;
    assert_eq!(quiet.request_id, RequestId::new(2));
    assert_eq!(
        quiet.facts.0, None,
        "nothing a keystroke, a resize or a query did is a fact: {quiet:?}"
    );

    // The control: a command block moves it.
    report(&host, block("ls", "/home/a/work", None));
    let moved = ask(&mut link, 3, 0, 0, Some(0)).await;
    assert!(moved.facts.0.is_some());
}

/// A repository and its branch are read from the `.git` above the command's directory, on a thread
/// of its own, and the page that carries them arrives after the one that carried the command: the
/// hook never waited for the read. A directory outside any repository has none.
#[tokio::test]
async fn the_repository_is_read_off_the_hook_path_and_follows_the_directory() {
    let host = host("exec cat").await;
    let root = tempfile::tempdir().expect("a directory");
    let repository = root.path().join("kalareach");
    let nested = repository.join("crates");
    std::fs::create_dir_all(repository.join(".git")).expect("a git directory");
    std::fs::create_dir_all(&nested).expect("a nested directory");
    std::fs::write(repository.join(".git/HEAD"), "ref: refs/heads/main\n").expect("a HEAD");
    let outside = root.path().join("elsewhere");
    std::fs::create_dir_all(&outside).expect("a directory outside");

    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let base = ask(&mut link, 1, 0, 0, Some(0)).await;
    assert_eq!(base.facts.0, None);

    report(&host, block("ls", &nested.to_string_lossy(), None));
    // The command's page, and then the one the read completes.
    let mut after = 0;
    let mut found = None;
    let mut id = 2;
    while found.is_none() {
        let page = ask(&mut link, id, after, 30_000, Some(0)).await;
        id += 1;
        let facts = page.facts.0.expect("facts");
        after = facts.revision.get();
        found = facts.repository.0.clone();
        assert_eq!(facts.directory.0.as_deref(), Some("crates"));
    }
    let found = found.expect("a repository");
    assert_eq!(found.name, "kalareach");
    assert_eq!(found.branch.0.as_deref(), Some("main"));

    // Leaving the repository leaves its facts behind: the repository goes with the directory.
    report(&host, block("ls", &outside.to_string_lossy(), None));
    let left = ask(&mut link, id, after, 30_000, Some(0)).await;
    let facts = left.facts.0.expect("facts");
    assert_eq!(facts.directory.0.as_deref(), Some("elsewhere"));
    assert_eq!(facts.repository.0, None);
}

/// KR-REQ-01.14, KR-REQ-22.05: a command that ended in another directory than the block says it
/// began in is followed to where the session's shell is now, so a `cd` is described at the prompt
/// and nothing more has to be typed. The shell here really is in that directory: the page names
/// it, and the directory the block carried is not the one that stays.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_command_that_ended_elsewhere_reports_where_the_shell_is_now() {
    let root = tempfile::tempdir().expect("a directory");
    let inside = root.path().join("moved-to");
    std::fs::create_dir_all(&inside).expect("a directory to be in");
    let host = host(&format!("cd '{}' && exec cat", inside.display())).await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    let base = ask(&mut link, 1, 0, 0, Some(0)).await;
    assert_eq!(base.facts.0, None);

    report(&host, block("cd moved-to", "/stale/begun-in", Some(0)));
    let mut after = 0;
    let mut id = 2;
    loop {
        let page = ask(&mut link, id, after, 30_000, Some(0)).await;
        id += 1;
        let facts = page.facts.0.expect("facts");
        after = facts.revision.get();
        if facts.directory.0.as_deref() == Some("moved-to") {
            assert_eq!(facts.completion.0, Some(DescriptionCompletion::Succeeded));
            break;
        }
        assert_eq!(
            facts.directory.0.as_deref(),
            Some("begun-in"),
            "until the shell has been read, the block's own directory stands"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Privacy mode
// ---------------------------------------------------------------------------------------------

/// KR-REQ-24.11: enabling privacy mode stops capture and clears the record, and a held request is
/// answered at once with a page that says the session is private and carries nothing; what happens
/// while it is on is never recorded, and turning it off starts a record of its own under the new
/// generation, with nothing from before.
#[tokio::test]
async fn privacy_mode_stops_capture_clears_the_record_and_tells_the_daemon() {
    let host = host("exec cat").await;
    let mut authority = daemon(&host, ControllerConnectionRole::Authority).await;
    let mut link = daemon(&host, ControllerConnectionRole::Descriptions).await;
    report(&host, block("make", "/home/a/before", None));
    let before = ask(&mut link, 1, 0, 0, Some(0)).await;
    let facts = before.facts.0.expect("facts");
    assert_eq!(facts.directory.0.as_deref(), Some("before"));

    // Held, with the daemon current at generation zero, and answered by the transition.
    send(
        &mut link,
        request(2, facts.revision.get(), 300_000, Some(0)),
    )
    .await;
    until_held(&host, 1).await;
    tell_privacy(&host, &mut authority, 1, true).await;
    let private = page(&mut link).await;
    assert_eq!(private.request_id, RequestId::new(2));
    assert!(private.private, "the session says it is private");
    assert_eq!(private.privacy_generation.0.map(U64::get), Some(1));
    assert_eq!(private.facts.0, None, "and carries no facts");

    // Nothing is captured while it is on, and the daemon, now current, is held rather than spun.
    report(&host, block("secret", "/home/a/while-private", None));
    send(&mut link, request(3, 0, 1_000, Some(1))).await;
    // Held, not answered at once: the worker has begun to hold a second request.
    until_held(&host, 2).await;
    let still = page(&mut link).await;
    assert_eq!(still.request_id, RequestId::new(3));
    assert!(still.private);
    assert_eq!(still.facts.0, None);

    // Turned off: a record of its own, at the new generation, with nothing from before.
    tell_privacy(&host, &mut authority, 2, false).await;
    resolved(&host, 1, &["make"], &executable());
    report(&host, block("make", "/home/a/after", None));
    let after = ask(&mut link, 4, 0, 0, Some(2)).await;
    assert!(!after.private);
    let facts = after.facts.0.expect("facts");
    assert_eq!(facts.generation.get(), 2);
    assert_eq!(facts.directory.0.as_deref(), Some("after"));
    assert_eq!(facts.application.0.as_deref(), Some("make"));
    assert_eq!(
        facts.events.len(),
        1,
        "nothing from before or while private"
    );
}
