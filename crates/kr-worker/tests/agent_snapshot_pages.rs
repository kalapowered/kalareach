//! An agent's shared state, read in parts the reader's connection can carry: `agent.snapshot`.
//!
//! Section 8 bounds a semantic snapshot at 16 MiB across its parts, and exceeding a limit yields a
//! paged or truncated representation with an explicit continuation. A part still travels in one
//! control frame, and a peer says in its hello how large a frame it receives, so a part is cut to
//! what that frame carries once the rest of the answer is in it. These tests read the snapshot on a
//! connection that declared the smallest frame a peer may declare, and hold every answer to that
//! frame as the wire frames it: a history larger than one frame comes back in parts that each fit,
//! and a reader that follows the continuations reads it whole, once and in order; an entry larger
//! than a frame on its own comes back with its text cut; and a history that fits, and one the
//! reader's grant narrows, answer as they did.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-08.72 | `a_history_larger_than_the_frame_is_read_in_parts_that_each_fit`, `an_entry_larger_than_the_frame_is_carried_cut`, `a_snapshot_whose_parts_pass_the_total_is_cut_at_it` |
//! | KR-REQ-23.39 | `a_history_that_fits_one_frame_answers_whole_with_no_continuation`, `a_narrowed_part_counts_what_it_withheld_and_spends_nothing_on_it`, `a_snapshot_under_the_total_is_read_in_parts_that_never_name_it` |

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::agent::{AgentSnapshotEntry, AgentSnapshotParams, AgentSnapshotResult};
use kr_protocol::broker::IntegrationMode;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, AuthorityRevision, BuildId, ConnectionId, ControllerGeneration,
    DeviceId, GrantId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::subject;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

/// The smallest control frame a peer may declare, which every read here declares.
const FRAME: usize = kr_transport::scheduler::MIN_CONTROL_FRAME_LEN;

fn build() -> BuildId {
    BuildId::new("kr-worker-test/0").expect("valid")
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

/// One worker serving a real session, with one agent instance whose history a test writes.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The control daemon's identity, to forward a paired device's read as the daemon does.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let current = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            current,
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
        // A shell that lasts as long as the session does: it ends when the session closes its
        // terminal, not at a time of its own.
        shell: kr_worker::testing::posix_script("exec cat"),
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
    let journal_path = config.journal_path.clone().expect("the harness journals");
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let mut session = TerminalSession::open(config).expect("opens the session");
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
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    service
        .broker()
        .register_instance(instance(), IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        controller,
        boot,
    }
}

/// Records what the agent said, in this order, each at the moment it names.
fn converse(host: &Host, said: &[(&str, u64)]) {
    let broker = host.service.broker();
    for (text, at) in said {
        broker
            .observe(instance(), "message", text, TimestampMs::new(*at))
            .expect("observed");
    }
}

/// Waits for one exchange with the worker, and fails the test naming what it waited for rather
/// than hanging when a handler stops answering.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS_DEADLINE, work)
        .await
        .unwrap_or_else(|_| panic!("{what} within {LIVENESS_DEADLINE:?}"))
}

/// What a peer that receives the smallest frame declares.
fn smallest() -> ReceiveLimits {
    ReceiveLimits {
        max_control_frame_len: U64::new(FRAME as u64),
        ..ReceiveLimits::default()
    }
}

/// The local owner, on the worker's own socket, receiving `limits`.
async fn owner(host: &Host, limits: ReceiveLimits) -> LocalClient {
    within(
        "a local connection",
        LocalClient::connect_receiving(&host.endpoint, LocalClientKind::Cli, build(), limits),
    )
    .await
    .expect("connects")
}

/// Connects as the control daemon declaring what it receives, and proves the generation.
async fn daemon(host: &Host, limits: ReceiveLimits) -> LocalClient {
    let mut daemon = within(
        "the daemon's connection",
        LocalClient::connect_receiving(
            &host.endpoint,
            LocalClientKind::Controller,
            build(),
            limits,
        ),
    )
    .await
    .expect("connects as the daemon");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    within(
        "the worker's acceptance of the generation",
        daemon.present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        }),
    )
    .await
    .expect("the worker accepts the generation");
    daemon
}

/// The envelope the control daemon vouches for a paired device acting under a grant.
fn device() -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::some(AuthorityRevision::new(1)),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
    }
}

/// A grant's history scope reaching back to `lower_bound_ms`.
fn reaching_back_to(lower_bound_ms: u64) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable::some(TimestampMs::new(lower_bound_ms)),
        include_live_screen: true,
        named_questions: kr_protocol::scalars::CanonicalSet::new(),
        named_approvals: kr_protocol::scalars::CanonicalSet::new(),
    }
}

fn params(host: &Host, from_node: Option<u64>) -> AgentSnapshotParams {
    AgentSnapshotParams {
        subject: subject(host.session_id, instance()),
        from_node: Nullable(from_node.map(U64::new)),
    }
}

/// Asserts that an answer, framed as the worker frames it, is inside the frame the peer declared.
///
/// It is framed with the widest request identifier there is, so what it measures does not depend
/// on the identifier this read happened to carry.
fn fits_the_frame(answer: &ParamsValue) {
    fits(answer, FRAME);
}

/// Asserts that an answer, framed as the worker frames it, is inside a frame of `frame` bytes.
fn fits(answer: &ParamsValue, frame: usize) {
    let framed = FrameCodec::new(StreamKind::Control)
        .encode_message(&ControlFrame::Response(Response {
            request_id: RequestId::new(u64::MAX),
            outcome: Outcome::Ok(answer.clone()),
        }))
        .expect("the answer frames");
    assert!(
        framed.len() <= frame,
        "the answer is {} bytes framed, and the peer said it receives {frame}",
        framed.len()
    );
}

/// Reads one part on the owner's own connection, and holds it to the frame.
async fn part(
    client: &mut LocalClient,
    host: &Host,
    from_node: Option<u64>,
) -> AgentSnapshotResult {
    let answer = within(
        "the worker's answer",
        client.request(Method::AgentSnapshot, &params(host, from_node)),
    )
    .await
    .expect("the worker answers")
    .expect("the snapshot is served");
    fits_the_frame(&answer);
    answer.to_typed().expect("the snapshot decodes")
}

/// Reads every part from the first, following each continuation, and returns them in order.
///
/// A continuation that does not move past where its own part started would have the reader ask
/// for the same part for ever, so that fails here rather than looping.
async fn every_part(client: &mut LocalClient, host: &Host) -> Vec<AgentSnapshotResult> {
    let mut parts = Vec::new();
    let mut from = None;
    loop {
        let read = part(client, host, from).await;
        let next = read
            .continuation
            .as_ref()
            .map(|continuation| continuation.from_node.get());
        parts.push(read);
        let Some(next) = next else {
            return parts;
        };
        assert!(
            from.is_none_or(|started| next > started),
            "the part that started at {from:?} continues at {next}, which is no further on"
        );
        from = Some(next);
    }
}

/// The entries of every part, in the order the parts carried them.
fn entries(parts: &[AgentSnapshotResult]) -> Vec<&AgentSnapshotEntry> {
    parts.iter().flat_map(|part| part.entries.iter()).collect()
}

/// KR-REQ-08.72: a history whose entries together are larger than the frame the reader declared
/// comes back in parts, each of which fits that frame as the wire frames it, and a reader that
/// follows the continuations reads every entry once, in the order it was said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_history_larger_than_the_frame_is_read_in_parts_that_each_fit() {
    let host = host().await;
    // Twelve entries of about three KiB each: together a little over twice the frame.
    let said: Vec<String> = (1..=12)
        .map(|index| format!("entry {index}: {}", "x".repeat(3 * 1024)))
        .collect();
    let timed: Vec<(&str, u64)> = said
        .iter()
        .zip(1_000_u64..)
        .map(|(text, at)| (text.as_str(), at))
        .collect();
    converse(&host, &timed);

    let mut reader = owner(&host, smallest()).await;
    let parts = every_part(&mut reader, &host).await;
    assert!(
        parts.len() > 1,
        "a history larger than the frame takes more than one part"
    );
    let read: Vec<&str> = entries(&parts)
        .iter()
        .map(|entry| entry.text.as_str())
        .collect();
    assert_eq!(read, said, "every entry once, in the order it was said");
    for part in &parts {
        assert!(!part.entries.is_empty(), "every part carries an entry");
        assert!(!part.history_gap);
        assert_eq!(part.withheld_entries, U64::new(0));
    }
    assert!(
        entries(&parts)
            .iter()
            .all(|entry| entry.omitted_text_bytes == U64::new(0)),
        "an entry that fits a part is carried whole"
    );
}

/// KR-REQ-08.72: an entry larger than the reader's frame on its own is carried in a part of its
/// own with its text cut, at a character boundary, and says how many bytes of it were left out,
/// rather than ending every part at itself; the entries on either side of it are read whole, once
/// and in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_larger_than_the_frame_is_carried_cut() {
    let host = host().await;
    // Three-byte characters, so a cut that ignored their boundaries would split one.
    let large = "€".repeat(12 * 1024);
    converse(
        &host,
        &[
            ("said before", 1_000),
            (large.as_str(), 1_001),
            ("said after", 1_002),
        ],
    );

    let mut reader = owner(&host, smallest()).await;
    let parts = every_part(&mut reader, &host).await;
    let read = entries(&parts);
    assert_eq!(read.len(), 3, "each entry once: {}", read.len());
    assert_eq!(read[0].text, "said before");
    assert_eq!(read[2].text, "said after");
    let cut = &read[1].text;
    assert!(
        cut.len() < large.len() && large.starts_with(cut.as_str()),
        "the large entry is carried as the start of its text, {} of its {} bytes",
        cut.len(),
        large.len()
    );
    assert_eq!(
        read[1].omitted_text_bytes.get(),
        (large.len() - cut.len()) as u64,
        "it says how many bytes of its text it left out"
    );
    assert_eq!(read[0].omitted_text_bytes, U64::new(0), "a whole text");
    assert_eq!(read[2].omitted_text_bytes, U64::new(0), "a whole text");
}

/// KR-REQ-23.39, the control: a history that fits one frame is answered whole, in one part with no
/// continuation, on a connection that declared the smallest frame and on one that declared the
/// usual limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_history_that_fits_one_frame_answers_whole_with_no_continuation() {
    let host = host().await;
    converse(&host, &[("said early", 1_000), ("said later", 3_000)]);
    for limits in [smallest(), ReceiveLimits::default()] {
        let mut reader = owner(&host, limits).await;
        let whole = part(&mut reader, &host, None).await;
        let read: Vec<&str> = whole
            .entries
            .iter()
            .map(|entry| entry.text.as_str())
            .collect();
        assert_eq!(read, ["said early", "said later"]);
        assert!(!whole.continuation.is_present(), "nothing was left out");
        assert_eq!(whole.withheld_entries, U64::new(0));
    }
}

/// KR-REQ-23.39, the control: a paired device's read, narrowed to its grant's scope, still counts
/// what the scope withheld before anything is spent on the part: what was said before the moment
/// the grant reaches back to, larger together than the frame, is withheld and counted, and what
/// was said since is answered in one part with no continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_narrowed_part_counts_what_it_withheld_and_spends_nothing_on_it() {
    let host = host().await;
    let before = |label: &str| format!("before the grant, {label}: {}", "x".repeat(6 * 1024));
    let (first, between, last) = (before("first"), before("between"), before("last"));
    converse(
        &host,
        &[
            (first.as_str(), 1_000),
            ("under the grant, first", 2_500),
            (between.as_str(), 1_500),
            ("under the grant, second", 3_000),
            (last.as_str(), 1_200),
        ],
    );

    let mut daemon = daemon(&host, smallest()).await;
    let read = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id: RequestId::new(71),
            method: Method::AgentSnapshot.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&params(&host, None)).expect("encodes"),
        },
        authority_deadline_boot_ms: Nullable::some(U64::new(
            kr_ipc::clock::boot_elapsed_ms() + 30_000,
        )),
        actor: device(),
        history: Some(reaching_back_to(2_000)),
    }));
    let outcome = within("the worker's answer", async {
        daemon
            .writer()
            .write_message(&read)
            .await
            .expect("writes the read");
        loop {
            match daemon.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) => return response.outcome,
                ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                other => panic!("the worker answered {other:?}"),
            }
        }
    })
    .await;
    let Outcome::Ok(answer) = outcome else {
        panic!("the device reads the snapshot: {outcome:?}");
    };
    fits_the_frame(&answer);
    let narrowed: AgentSnapshotResult = answer.to_typed().expect("the snapshot decodes");
    let said: Vec<&str> = narrowed
        .entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect();
    assert_eq!(said, ["under the grant, first", "under the grant, second"]);
    assert_eq!(
        narrowed.withheld_entries,
        U64::new(3),
        "the answer says how much it withheld"
    );
    assert!(
        !narrowed.continuation.is_present(),
        "nothing withheld was spent on the part"
    );
}

/// What a connection that declared the usual limits receives in one control frame.
const USUAL_FRAME: usize = kr_protocol::limits::MAX_CONTROL_FRAME_LEN;

/// A text of exactly a million bytes, numbered: one of these fills most of a usual frame, so each
/// part carries one, and sixteen fit section 8's 16 MiB while seventeen do not.
fn million(number: usize) -> String {
    let label = format!("entry {number:>2}: ");
    format!("{label}{}", "x".repeat(1_000_000 - label.len()))
}

/// Reads one part on the owner's own connection, and holds it to the usual frame.
async fn usual_part(
    client: &mut LocalClient,
    host: &Host,
    from_node: Option<u64>,
) -> AgentSnapshotResult {
    let answer = within(
        "the worker's answer",
        client.request(Method::AgentSnapshot, &params(host, from_node)),
    )
    .await
    .expect("the worker answers")
    .expect("the snapshot is served");
    fits(&answer, USUAL_FRAME);
    answer.to_typed().expect("the snapshot decodes")
}

/// Records `count` entries of a million bytes each.
fn converse_millions(host: &Host, count: usize) -> Vec<String> {
    let said: Vec<String> = (1..=count).map(million).collect();
    let timed: Vec<(&str, u64)> = said
        .iter()
        .zip(1_000_u64..)
        .map(|(text, at)| (text.as_str(), at))
        .collect();
    converse(host, &timed);
    said
}

/// KR-REQ-08.72: one snapshot's parts together carry at most section 8's 16 MiB, not 16 MiB each.
///
/// Twenty entries of a million bytes are read on a connection whose frame carries one of them at
/// a time. The parts of the first snapshot carry sixteen, and the part that would have passed the
/// total ends with a continuation that names it, which is what section 8 asks of a limit that is
/// passed. Asked from there, the rest is a snapshot of its own, and a reader that follows both
/// reads every entry once, in the order it was said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_whose_parts_pass_the_total_is_cut_at_it() {
    let host = host().await;
    let said = converse_millions(&host, 20);
    let total = kr_protocol::semantic::MAX_SEMANTIC_SNAPSHOT_BYTES;

    let mut reader = owner(&host, ReceiveLimits::default()).await;
    let mut first = Vec::new();
    let mut from = None;
    let resume_at = loop {
        let part = usual_part(&mut reader, &host, from).await;
        first.extend(part.entries.iter().map(|entry| entry.text.clone()));
        let carried: usize = first.iter().map(String::len).sum();
        assert!(
            u64::try_from(carried).expect("a length") <= total,
            "the parts of one snapshot carried {carried} bytes of text, and section 8's total is \
             {total}"
        );
        let continuation = part
            .continuation
            .0
            .expect("a history larger than the total continues past the first snapshot");
        if continuation.limit_value.get() == total {
            break continuation.from_node.get();
        }
        from = Some(continuation.from_node.get());
    };
    assert_eq!(
        first,
        said[..16],
        "the first snapshot carries the first sixteen, whole"
    );

    let mut rest = Vec::new();
    let mut from = Some(resume_at);
    while let Some(node) = from {
        let part = usual_part(&mut reader, &host, Some(node)).await;
        rest.extend(part.entries.iter().map(|entry| entry.text.clone()));
        from = part
            .continuation
            .as_ref()
            .map(|continuation| continuation.from_node.get());
        assert!(
            from.is_none_or(|next| next > node),
            "the part that started at {node} continues at {from:?}, which is no further on"
        );
    }
    assert_eq!(rest, said[16..], "and asked from there, the rest, whole");
}

/// KR-REQ-23.39, the control: a snapshot whose parts together stay under the total is read as it
/// always was, every part cut to the frame and none naming the total.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_under_the_total_is_read_in_parts_that_never_name_it() {
    let host = host().await;
    let said = converse_millions(&host, 15);
    let total = kr_protocol::semantic::MAX_SEMANTIC_SNAPSHOT_BYTES;

    let mut reader = owner(&host, ReceiveLimits::default()).await;
    let mut read = Vec::new();
    let mut from = None;
    loop {
        let part = usual_part(&mut reader, &host, from).await;
        read.extend(part.entries.iter().map(|entry| entry.text.clone()));
        let Some(continuation) = part.continuation.as_ref() else {
            break;
        };
        assert!(
            continuation.limit_value.get() < total,
            "a part of a snapshot under the total is cut by the frame, not by the total"
        );
        from = Some(continuation.from_node.get());
    }
    assert_eq!(read, said, "every entry once, in the order it was said");
}
