//! The environment's attention store, as the control daemon hosts it.
//!
//! Two kinds of test are here. The store's reading of sessions is proved against real workers in
//! this process: each has its own journal and endpoint, and the store reaches it over an attention
//! connection as the daemon does, so the pages, the held request, the text, a closed session's
//! journal and an unaccounted closure are all the real thing. The group's methods are proved
//! against a whole daemon on its own socket and over the network, where a paired device reads under
//! its grant.

mod net_support;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kr_controller::attention::{AttentionModule, Caller, Reach};
use kr_controller::authority::AdmittedMutation;
use kr_controller::directory::KnownWorker;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionItem, AttentionItemRevision,
    AttentionQuietHoursParams, AttentionQuietHoursResult, AttentionReadParams, AttentionReadResult,
    AttentionRule, AttentionSource, LogViewState, QuietHours, ReviewAcknowledgeParams,
    ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult, ReviewState, ReviewSubject,
    VisitAcknowledgeParams, VisitAcknowledgeResult, VisitChangedParams, VisitChangedResult,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, ParamsValue, Request};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActorId, AgentTurnId, BuildId, ConnectionId, ControllerGeneration, RequestId,
    SessionEpoch, SessionId,
};
use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
use kr_protocol::method::{Method, MethodGroup, MethodVersion, REGISTRY};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

// ---------------------------------------------------------------------------------------------
// Workers in this process
// ---------------------------------------------------------------------------------------------

struct Worker {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    journal_path: PathBuf,
    known: KnownWorker,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn worker() -> Worker {
    worker_for(SessionId::new(kr_ipc::new_uuid())).await
}

/// A worker for the session named, on an environment tree of its own.
async fn worker_for(session_id: SessionId) -> Worker {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
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
        journal_path: Some(journal_path.clone()),
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
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path.clone()),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    let known = KnownWorker {
        descriptor: kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            boot_identity: boot.clone(),
            process_start_identity: process,
            protocol_version: PROTOCOL_VERSION,
            endpoint: endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        },
        endpoint,
    };
    Worker {
        _temp: temp,
        service,
        session_id,
        journal_path,
        known,
        controller,
        boot,
    }
}

fn now() -> kr_worker::questions::Now {
    kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

fn ask(worker: &Worker, request: &str, question: &str) -> kr_protocol::question::Question {
    worker
        .service
        .questions()
        .create(
            &kr_worker::questions::VerifiedSource {
                process: kr_ipc::identity::current_process_start_identity()
                    .expect("a process identity"),
                executable: Some("/bin/agent".to_owned()),
                session_member: true,
                ancestry: true,
                launch_channel: true,
                connection_id: ConnectionId::new(kr_ipc::new_uuid()),
            },
            &kr_protocol::question::QuestionCreateParams {
                session_id: worker.session_id,
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

fn answer(worker: &Worker, question: &kr_protocol::question::Question) {
    worker
        .service
        .questions()
        .answer(
            &owner(),
            None,
            &kr_protocol::question::QuestionAnswerParams {
                session_id: worker.session_id,
                question_id: question.question_id,
                expected_revision: question.revision,
                answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
            },
            now(),
        )
        .expect("a person answers it");
}

fn notify(worker: &Worker, body: &str) {
    notify_titled(worker, None, body);
}

fn notify_titled(worker: &Worker, title: Option<&str>, body: &str) {
    let mut session = worker.service.runtime().session();
    session
        .journal_mut()
        .expect("the harness journals its session")
        .record_host_event(
            &kr_term::sideeffect::SideEffect {
                kind: kr_term::sideeffect::SideEffectKind::Notification {
                    title: title.map(str::to_owned),
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

/// How the store reaches the workers of this suite: over the same attention connection the
/// daemon opens, with a closure's answers set by each test.
#[derive(Default)]
struct TestReach {
    workers: std::sync::Mutex<BTreeMap<SessionId, Reached>>,
    unaccounted: AtomicBool,
    unreadable: AtomicBool,
    /// The oldest output position a closed session's spool retains, as this suite sets it.
    floor: std::sync::atomic::AtomicU64,
    /// A worker endpoint whose connection is never made, as if the worker accepted it and then
    /// said nothing.
    stalled: std::sync::Mutex<Option<String>>,
    /// Speaks for a later daemon generation, as a daemon that has restarted does.
    later: AtomicBool,
    /// How often a closed session's journal was asked for.
    journals_opened: std::sync::atomic::AtomicU64,
}

/// What reaching one worker of this suite takes.
#[derive(Clone)]
struct Reached {
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    journal: PathBuf,
}

impl TestReach {
    fn add(&self, worker: &Worker) {
        self.workers.lock().expect("not poisoned").insert(
            worker.session_id,
            Reached {
                controller: Arc::clone(&worker.controller),
                boot: worker.boot.clone(),
                journal: worker.journal_path.clone(),
            },
        );
    }
}

impl Reach for TestReach {
    fn connect<'a>(
        &'a self,
        worker: &'a KnownWorker,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = kr_controller::error::Result<LocalClient>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let stalled = self
                .stalled
                .lock()
                .expect("not poisoned")
                .as_ref()
                .is_some_and(|endpoint| *endpoint == worker.endpoint.as_text());
            if stalled {
                std::future::pending::<()>().await;
            }
            let Reached {
                controller: identity,
                boot,
                ..
            } = self
                .workers
                .lock()
                .expect("not poisoned")
                .get(&worker.descriptor.session_id)
                .cloned()
                .ok_or_else(|| kr_controller::error::ControllerError::supervision("unknown"))?;
            let mut client =
                LocalClient::connect(&worker.endpoint, LocalClientKind::Controller, build())
                    .await?;
            client
                .writer()
                .write_message(&ControlFrame::ControllerRole(
                    ControllerConnectionRole::Attention,
                ))
                .await?;
            let _ = client.recv().await?;
            let generation = if self.later.load(Ordering::SeqCst) {
                2
            } else {
                1
            };
            client
                .present_generation(move |nonce| {
                    identity
                        .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                        .map_err(kr_ipc::IpcError::from)
                })
                .await?;
            Ok(client)
        })
    }

    fn unaccounted<'a>(
        &'a self,
        _session_id: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let unaccounted = self.unaccounted.load(Ordering::SeqCst);
        Box::pin(async move { unaccounted })
    }

    fn closed_journal(&self, session_id: SessionId) -> Option<kr_worker::journal::Journal> {
        self.journals_opened.fetch_add(1, Ordering::SeqCst);
        if self.unreadable.load(Ordering::SeqCst) {
            return None;
        }
        let path = self
            .workers
            .lock()
            .expect("not poisoned")
            .get(&session_id)
            .map(|reached| reached.journal.clone())?;
        kr_worker::journal::Journal::open_read_only(path).ok()
    }

    fn output_floor(&self, _session_id: SessionId) -> Option<u64> {
        Some(self.floor.load(Ordering::SeqCst))
    }
}

fn store_at(temp: &kr_ipc::testing::TempHost) -> Arc<AttentionModule> {
    Arc::new(
        AttentionModule::open(
            &temp.environment(),
            kr_ipc::identity::boot_identity().expect("a boot identity"),
        )
        .expect("the attention store opens"),
    )
}

/// Opens the store again, as the next daemon does, once the last one's value has gone.
///
/// The store's claim goes with the value that held it; the tasks that read for it hold it only
/// between their waits, so it goes within moments of the last holder letting go.
async fn reopen(temp: &kr_ipc::testing::TempHost) -> Arc<AttentionModule> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match AttentionModule::open(
            &temp.environment(),
            kr_ipc::identity::boot_identity().expect("a boot identity"),
        ) {
            Ok(module) => return Arc::new(module),
            Err(error) => {
                assert!(Instant::now() < deadline, "the store stayed held: {error}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Each item's key, revision and delivery state, in key order.
fn keys(items: &[AttentionItem]) -> Vec<(kr_protocol::attention::AttentionKey, U64, bool)> {
    let mut keys: Vec<_> = items
        .iter()
        .map(|item| (item.key.clone(), item.revision, item.awaiting_delivery))
        .collect();
    keys.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    keys
}

/// Each item's rule, session and text, in a fixed order.
fn texts(items: &[AttentionItem]) -> Vec<(String, Option<SessionId>, Option<String>)> {
    let mut texts: Vec<_> = items
        .iter()
        .map(|item| {
            (
                format!("{:?}", item.rule),
                item.session_id.0,
                item.summary.0.clone(),
            )
        })
        .collect();
    texts.sort();
    texts
}

fn owner() -> ActorId {
    ActorId::new("local:501").expect("an actor")
}

fn read_request(session_id: Option<SessionId>) -> Request {
    Request {
        request_id: RequestId::new(7),
        method: Method::AttentionRead.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&AttentionReadParams {
            session_id: Nullable(session_id),
            include_acknowledged: true,
            max_items: U64::new(100),
            after: Nullable::null(),
        })
        .expect("encodes"),
    }
}

async fn inbox(module: &AttentionModule, reach: &TestReach) -> AttentionReadResult {
    module
        .read(reach, &Caller::Owner, &owner(), &read_request(None))
        .await
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes")
}

/// Reads the inbox until `done` holds, or ten seconds pass.
async fn until(
    module: &AttentionModule,
    reach: &TestReach,
    done: impl Fn(&[AttentionItem]) -> bool,
) -> Vec<AttentionItem> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let items = inbox(module, reach).await.items;
        if done(&items) {
            return items;
        }
        assert!(
            Instant::now() < deadline,
            "the inbox did not get there in ten seconds: {items:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn of_rule(items: &[AttentionItem], rule: AttentionRule) -> Vec<AttentionItem> {
    items
        .iter()
        .filter(|item| item.rule == rule)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Reading sessions
// ---------------------------------------------------------------------------------------------

/// KR-REQ-18.01 and KR-REQ-25.01: one inbox holds two live sessions' work, each item carries its
/// session, and the owner is served each session's text, read from that session when the inbox is
/// served.
#[tokio::test(flavor = "multi_thread")]
async fn one_inbox_holds_two_live_sessions_with_their_text() {
    let one = worker().await;
    let two = worker().await;
    ask(&one, "r-1", "which branch?");
    ask(&two, "r-2", "deploy now?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    reach.add(&two);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, two.known.clone());
    let items = until(&module, &reach, |items| {
        of_rule(items, AttentionRule::PendingInput).len() == 2
    })
    .await;
    let mut asked: Vec<(Option<SessionId>, Option<String>)> =
        of_rule(&items, AttentionRule::PendingInput)
            .into_iter()
            .map(|item| (item.session_id.0, item.summary.0))
            .collect();
    asked.sort();
    let mut expected = vec![
        (Some(one.session_id), Some("which branch?".to_owned())),
        (Some(two.session_id), Some("deploy now?".to_owned())),
    ];
    expected.sort();
    assert_eq!(asked, expected);

    // A filter narrows the one inbox to one session.
    let narrowed: AttentionReadResult = module
        .read(
            &*reach,
            &Caller::Owner,
            &owner(),
            &read_request(Some(one.session_id)),
        )
        .await
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    assert!(
        narrowed
            .items
            .iter()
            .all(|item| item.session_id.0 == Some(one.session_id))
    );
}

/// A question asked in a live session is in the environment's inbox within ten seconds: the
/// worker answers the store's held request as soon as the question is committed, where a store
/// fed by a periodic pass would wait for the pass.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_reaches_the_inbox_within_ten_seconds() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    // Let the link settle into its held request.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let asked_at = Instant::now();
    ask(&one, "r-1", "which branch?");
    let _ = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    assert!(asked_at.elapsed() < Duration::from_secs(10));
}

/// A session the daemon comes to reach at another worker is read from that one: the link to the
/// worker before it stops, and the new worker's records reach the inbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_reached_at_a_new_worker_is_read_from_it() {
    let before = worker().await;
    let after = worker_for(before.session_id).await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&before);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, before.known.clone());
    // Let the link to the first worker settle into its held request.
    tokio::time::sleep(Duration::from_millis(500)).await;
    reach.add(&after);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, after.known.clone());
    ask(&after, "r-1", "which branch?");
    let items = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    assert_eq!(
        of_rule(&items, AttentionRule::PendingInput)[0]
            .summary
            .0
            .as_deref(),
        Some("which branch?")
    );
}

/// A session whose worker is replaced while the connection to the one before it is still being made
/// is read from the new worker at once: the connection being made is given up rather than waited
/// out.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_replaced_while_its_connection_is_being_made_is_given_up() {
    let before = worker().await;
    let after = worker_for(before.session_id).await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&before);
    *reach.stalled.lock().expect("not poisoned") = Some(before.known.endpoint.as_text());
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, before.known.clone());
    // The connection to the first worker is being made, and would never be.
    tokio::time::sleep(Duration::from_millis(300)).await;
    reach.add(&after);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, after.known.clone());
    ask(&after, "r-1", "which branch?");
    let started = Instant::now();
    let _ = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the new worker was read at once, not after the old connection's bound"
    );
}

/// KR-REQ-18.01 and KR-REQ-25.01: the daemon's own store reads two live sessions, and the owner at
/// the daemon's socket is served one inbox holding both, each with its session's text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_serves_two_live_sessions_in_one_inbox_with_their_text() {
    let one = worker().await;
    let two = worker().await;
    ask(&one, "r-1", "which branch?");
    ask(&two, "r-2", "deploy now?");
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    reach.add(&two);
    host.controller()
        .attention()
        .watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    host.controller()
        .attention()
        .watch(Arc::clone(&reach) as Arc<dyn Reach>, two.known.clone());
    let mut control = host.client().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let asked = loop {
        let mut asked: Vec<(Option<SessionId>, Option<String>)> = of_rule(
            &owner_inbox(&mut control).await,
            AttentionRule::PendingInput,
        )
        .into_iter()
        .map(|item| (item.session_id.0, item.summary.0))
        .collect();
        asked.sort();
        if asked.len() == 2 && asked.iter().all(|(_, text)| text.is_some()) {
            break asked;
        }
        assert!(
            Instant::now() < deadline,
            "the inbox did not get there: {asked:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut expected = vec![
        (Some(one.session_id), Some("which branch?".to_owned())),
        (Some(two.session_id), Some("deploy now?".to_owned())),
    ];
    expected.sort();
    assert_eq!(asked, expected);
    host.stop().await;
}

/// KR-REQ-25.03 and KR-REQ-24.11: a store rebuilt from a session's journal, across a privacy enable
/// and disable, folds the session's notices exactly as the store that read them live did, serves
/// the same text for them, and keeps the key it gave them across its own restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_rebuilt_from_the_journal_folds_notices_as_the_live_one_did() {
    let one = worker().await;
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    let live_temp = kr_ipc::testing::TempHost::create();
    let live = {
        let module = store_at(&live_temp);
        module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
        notify(&one, "the build finished");
        let _ = until(&module, &reach, |items| {
            !of_rule(items, AttentionRule::ApplicationNotice).is_empty()
        })
        .await;
        one.service
            .runtime()
            .session()
            .enable_privacy(&mut [])
            .expect("privacy mode is enabled");
        notify(&one, "the build finished");
        one.service
            .runtime()
            .session()
            .disable_privacy()
            .expect("privacy mode is disabled");
        notify(&one, "the build finished");
        let items = until(&module, &reach, |items| {
            of_rule(items, AttentionRule::ApplicationNotice)
                .first()
                .is_some_and(|item| item.occurrences.get() >= 3)
        })
        .await;
        texts(&of_rule(&items, AttentionRule::ApplicationNotice))
            .into_iter()
            .zip(of_rule(&items, AttentionRule::ApplicationNotice))
            .map(|(text, item)| (text, item.occurrences))
            .collect::<Vec<_>>()
    };
    // Only one store reads a worker at a time; the live one has gone.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rebuilt_temp = kr_ipc::testing::TempHost::create();
    let rebuilt = store_at(&rebuilt_temp);
    rebuilt.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let items = until(&rebuilt, &reach, |items| {
        of_rule(items, AttentionRule::ApplicationNotice)
            .first()
            .is_some_and(|item| item.occurrences.get() >= 3)
    })
    .await;
    let notices = of_rule(&items, AttentionRule::ApplicationNotice);
    let folded: Vec<_> = texts(&notices)
        .into_iter()
        .zip(notices.iter().cloned())
        .map(|(text, item)| (text, item.occurrences))
        .collect();
    assert_eq!(folded, live, "one condition, as often, with the same text");
    let key = notices[0].key.clone();
    drop(rebuilt);
    let reopened = reopen(&rebuilt_temp).await;
    let again = inbox(&reopened, &reach).await.items;
    assert_eq!(
        of_rule(&again, AttentionRule::ApplicationNotice)[0].key,
        key
    );
}

/// KR-REQ-25.01: a verified question is trusted pending input under a key that carries nothing the
/// session wrote, and answering it in its session takes it out of the inbox once the store reads
/// the answer.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_question_leaves_the_inbox() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let question = ask(&one, "r-1", "which branch?");
    let items = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    let waiting = of_rule(&items, AttentionRule::PendingInput);
    assert!(waiting[0].trusted);
    assert!(
        !waiting[0]
            .key
            .as_str()
            .contains(&question.question_id.to_string()),
        "nothing the session wrote travels inside the key"
    );
    answer(&one, &question);
    let _ = until(&module, &reach, |items| {
        of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
}

/// KR-REQ-25.01: a question raised and answered before the store read its session owes nothing
/// once the store catches up. The backlog is read as history, and only the question still open is
/// waiting, with no reminder raised by the reading.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_answered_inside_a_backlog_owes_nothing_when_the_store_catches_up() {
    let one = worker().await;
    let answered = ask(&one, "r-1", "which branch?");
    answer(&one, &answered);
    ask(&one, "r-2", "deploy now?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let items = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    let waiting = of_rule(&items, AttentionRule::PendingInput);
    assert_eq!(waiting.len(), 1, "only the open question is waiting");
    assert_eq!(waiting[0].summary.0.as_deref(), Some("deploy now?"));
    assert!(of_rule(&items, AttentionRule::InputIdleReminder).is_empty());
}

/// KR-REQ-25.01: a notification the session printed with nothing attached to take it is an
/// untrusted notice, routed by the owner's notification policy, told to the owner in the
/// session's words, and never an approval.
#[tokio::test(flavor = "multi_thread")]
async fn a_notification_becomes_an_untrusted_notice_and_never_an_approval() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    notify_titled(&one, Some("build"), "finished");
    let items = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::ApplicationNotice).is_empty()
    })
    .await;
    let notice = of_rule(&items, AttentionRule::ApplicationNotice)[0].clone();
    assert!(!notice.trusted, "any process can print one");
    assert_eq!(
        notice.summary.0.as_deref(),
        Some("Normal: build - finished")
    );
    assert_eq!(
        notice.routing,
        kr_protocol::attention::AttentionRouting::OwnerPolicy
    );
    assert!(of_rule(&items, AttentionRule::PendingApproval).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Sessions that end
// ---------------------------------------------------------------------------------------------

/// KR-REQ-24.11 and KR-REQ-25.03: a session whose closure is recorded is read to the end from its
/// journal; its pending question ends with it, its notice stays, and the notice's text is served
/// from the journal afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_is_finished_from_its_journal() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    ask(&one, "r-1", "which branch?");
    let _ = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    // Written after the last page the link read, and read from the journal once the session has
    // ended.
    notify(&one, "the build finished");
    module.session_closed(&*reach, one.session_id).await;
    let items = inbox(&module, &reach).await.items;
    assert!(
        of_rule(&items, AttentionRule::PendingInput).is_empty(),
        "the question ended with its session: {items:?}"
    );
    let notices = of_rule(&items, AttentionRule::ApplicationNotice);
    assert_eq!(notices.len(), 1, "{items:?}");
    assert_eq!(
        notices[0].summary.0.as_deref(),
        Some("Normal: the build finished")
    );
    assert!(!notices[0].uncertain);
}

/// KR-REQ-24.11: a closure over a worker this host could not confirm had ended opens nothing: the
/// session's items stay, uncertain and without text, and none of them ends.
#[tokio::test(flavor = "multi_thread")]
async fn an_unaccounted_closure_keeps_its_items_uncertain_and_without_text() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    ask(&one, "r-1", "which branch?");
    let _ = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    reach.unaccounted.store(true, Ordering::SeqCst);
    module.session_closed(&*reach, one.session_id).await;
    let result = inbox(&module, &reach).await;
    let pending = of_rule(&result.items, AttentionRule::PendingInput);
    assert_eq!(pending.len(), 1, "nothing ended");
    assert!(pending[0].uncertain);
    assert_eq!(pending[0].summary, Nullable::null());
    assert!(
        result
            .gaps
            .iter()
            .any(|gap| gap.session_id.0 == Some(one.session_id) && gap.to_sequence.0.is_none())
    );
}

/// KR-REQ-24.11: a closed session whose journal cannot be read is a gap with no known end in each
/// source, and the session still ends.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_journal_is_a_gap_and_the_session_ends() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    ask(&one, "r-1", "which branch?");
    let _ = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::PendingInput).is_empty()
    })
    .await;
    reach.unreadable.store(true, Ordering::SeqCst);
    module.session_closed(&*reach, one.session_id).await;
    let result = inbox(&module, &reach).await;
    assert!(of_rule(&result.items, AttentionRule::PendingInput).is_empty());
    let gaps: Vec<AttentionSource> = result
        .gaps
        .iter()
        .filter(|gap| gap.session_id.0 == Some(one.session_id) && gap.to_sequence.0.is_none())
        .map(|gap| gap.source)
        .collect();
    assert!(gaps.contains(&AttentionSource::Questions));
    assert!(gaps.contains(&AttentionSource::HostEvents));
}

/// KR-REQ-24.11: a store reopened after the daemon stops holds the same inbox under the same keys,
/// and reopening announces nothing it had not already decided.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_rebuilds_the_same_inbox_and_announces_nothing() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    ask(&one, "r-1", "which branch?");
    notify(&one, "the build finished");
    let before = {
        let module = store_at(&temp);
        module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
        until(&module, &reach, |items| items.len() == 2).await
    };
    let module = reopen(&temp).await;
    let after = inbox(&module, &reach).await.items;
    assert_eq!(keys(&after), keys(&before));
}

/// A session the store has finished is not read again when its closure is handled again, even when
/// its journal has become readable and holds more records than one page carries.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_session_is_not_read_again() {
    let one = worker().await;
    for index in 0..300 {
        notify(&one, &format!("step {index} finished"));
    }
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    reach.unreadable.store(true, Ordering::SeqCst);
    module.session_closed(&*reach, one.session_id).await;
    let finished = inbox(&module, &reach).await.items;
    reach.unreadable.store(false, Ordering::SeqCst);
    let opened = reach.journals_opened.load(Ordering::SeqCst);
    let again = {
        let module = Arc::clone(&module);
        let reach = Arc::clone(&reach);
        let session_id = one.session_id;
        tokio::spawn(async move { module.session_closed(&*reach, session_id).await })
    };
    tokio::time::timeout(Duration::from_secs(10), again)
        .await
        .expect("handling the closure again ends")
        .expect("the task finishes");
    assert_eq!(
        reach.journals_opened.load(Ordering::SeqCst),
        opened,
        "a finished session's journal is not read again"
    );
    assert_eq!(keys(&inbox(&module, &reach).await.items), keys(&finished));
}

/// More records than one text request carries are read from a finished session's journal in
/// batches, each answered where it stood, and text read from the journal after a verified closure
/// needs no release lease.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_session_s_journal_serves_text_in_batches() {
    let one = worker().await;
    for index in 1..=300 {
        notify(&one, &format!("step {index} finished"));
    }
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.session_closed(&*reach, one.session_id).await;
    let records: Vec<kr_attention::EventCursor> = (1..=300)
        .map(|sequence| {
            kr_attention::EventCursor::in_session(
                one.session_id,
                AttentionSource::HostEvents,
                sequence,
            )
        })
        .collect();
    let (texts, ticket) = module.delivery_texts(&*reach, &records).await;
    assert_eq!(texts.len(), 300);
    for (index, text) in texts.iter().enumerate() {
        assert_eq!(
            text.as_deref(),
            Some(format!("Normal: step {} finished", index + 1).as_str())
        );
    }
    assert!(
        ticket.is_empty(),
        "text from a finished journal carries no lease"
    );
}

/// KR-REQ-24.11: the environment's store has one owner. While a daemon holds it, another opener is
/// refused rather than handed a state it could not write back, and once the holder is gone the
/// next daemon opens it.
#[tokio::test(flavor = "multi_thread")]
async fn one_daemon_owns_the_store_at_a_time() {
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let refused = AttentionModule::open(
        &temp.environment(),
        kr_ipc::identity::boot_identity().expect("a boot identity"),
    );
    assert!(refused.is_err(), "a second owner is refused");
    drop(module);
    let _ = reopen(&temp).await;
}

/// KR-REQ-24.11, KR-REQ-25.01 and KR-REQ-25.03: a daemon that stops part way through finishing
/// sessions leaves each to the next start, wherever it stopped.
///
/// One session stops before its tail is read and the other after, and the daemon records neither
/// as finished. The next start finds both unfinished, reads the first one's tail from its journal,
/// ends both questions and keeps the completed turn waiting for review. A start after that finds
/// nothing left to finish, still serves the finished sessions' text from their journals, and
/// finishing a session again changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_finishes_a_closure_wherever_the_last_daemon_stopped() {
    let before_tail = worker().await;
    let after_tail = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let reach = Arc::new(TestReach::default());
    reach.add(&before_tail);
    reach.add(&after_tail);
    ask(&before_tail, "r-1", "which branch?");
    ask(&after_tail, "r-2", "deploy now?");
    notify(&after_tail, "the tests passed");
    {
        let module = store_at(&temp);
        module.watch(
            Arc::clone(&reach) as Arc<dyn Reach>,
            before_tail.known.clone(),
        );
        module.watch(
            Arc::clone(&reach) as Arc<dyn Reach>,
            after_tail.known.clone(),
        );
        let _ = until(&module, &reach, |items| items.len() == 3).await;
        module
            .observe(&[completed_turn(before_tail.session_id).0])
            .expect("the store records the turn");
        // The daemon stops here, before it handles either closure.
    }
    let module = reopen(&temp).await;
    // Written once nothing reads the session live: the tail only its journal holds.
    notify(&before_tail, "the build finished");
    let mut unfinished = module.open_sessions();
    unfinished.sort();
    let mut both = vec![before_tail.session_id, after_tail.session_id];
    both.sort();
    assert_eq!(unfinished, both);
    module.session_closed(&*reach, before_tail.session_id).await;
    module.session_closed(&*reach, after_tail.session_id).await;
    let finished = inbox(&module, &reach).await.items;
    assert!(
        of_rule(&finished, AttentionRule::PendingInput).is_empty(),
        "both questions ended with their sessions: {finished:?}"
    );
    let mut notices: Vec<(Option<SessionId>, Option<String>)> =
        of_rule(&finished, AttentionRule::ApplicationNotice)
            .into_iter()
            .map(|item| (item.session_id.0, item.summary.0))
            .collect();
    notices.sort();
    let mut expected = vec![
        (
            Some(before_tail.session_id),
            Some("Normal: the build finished".to_owned()),
        ),
        (
            Some(after_tail.session_id),
            Some("Normal: the tests passed".to_owned()),
        ),
    ];
    expected.sort();
    assert_eq!(notices, expected);
    assert_eq!(
        of_rule(&finished, AttentionRule::ReviewReady).len(),
        1,
        "the completed turn outlives its session: {finished:?}"
    );
    drop(module);

    let module = reopen(&temp).await;
    assert!(
        module.open_sessions().is_empty(),
        "nothing is left to finish"
    );
    let again = inbox(&module, &reach).await.items;
    assert_eq!(keys(&again), keys(&finished));
    assert_eq!(texts(&again), texts(&finished));
    module.session_closed(&*reach, before_tail.session_id).await;
    let repeated = inbox(&module, &reach).await.items;
    assert_eq!(keys(&repeated), keys(&finished));
    assert_eq!(texts(&repeated), texts(&finished));
}

/// KR-REQ-25.03 and KR-REQ-24.11: the same notice before privacy mode, while it is on and after
/// it is off is one condition, under one key, whose text is served only from records written after
/// the last transition.
#[tokio::test(flavor = "multi_thread")]
async fn a_notice_keeps_its_key_across_privacy_mode() {
    let one = worker().await;
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    notify(&one, "the build finished");
    let first = until(&module, &reach, |items| {
        !of_rule(items, AttentionRule::ApplicationNotice).is_empty()
    })
    .await;
    let key = of_rule(&first, AttentionRule::ApplicationNotice)[0]
        .key
        .clone();
    one.service
        .runtime()
        .session()
        .enable_privacy(&mut [])
        .expect("privacy mode is enabled");
    notify(&one, "the build finished");
    one.service
        .runtime()
        .session()
        .disable_privacy()
        .expect("privacy mode is disabled");
    let items = until(&module, &reach, |items| {
        of_rule(items, AttentionRule::ApplicationNotice)
            .first()
            .is_some_and(|item| item.occurrences.get() >= 2)
    })
    .await;
    let notices = of_rule(&items, AttentionRule::ApplicationNotice);
    assert_eq!(notices.len(), 1, "one condition: {items:?}");
    assert_eq!(notices[0].key, key, "under the key it had before");
    assert_eq!(
        notices[0].summary,
        Nullable::null(),
        "the latest record was written while privacy mode was on"
    );
}

// ---------------------------------------------------------------------------------------------
// The group's methods at the daemon
// ---------------------------------------------------------------------------------------------

fn approval(session_id: SessionId, request: &str) -> kr_attention::SourceEvent {
    approval_at(session_id, 1, request)
}

fn approval_at(session_id: SessionId, sequence: u64, request: &str) -> kr_attention::SourceEvent {
    kr_attention::SourceEvent::new(
        kr_attention::EventCursor::in_session(session_id, AttentionSource::Receipts, sequence),
        TimestampMs::new(kr_ipc::now_ms().get()),
        kr_attention::EventKind::ApprovalRequested {
            request_id: kr_protocol::ids::ApprovalRequestId::new(request).expect("an identifier"),
            session_id,
            summary: String::new(),
        },
    )
}

/// KR-REQ-18.01 and KR-REQ-23.45: the owner reads the environment's inbox at the daemon's own
/// socket, with no session named, and acknowledges an item at the revision it saw; a revision it
/// did not see is stale and records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_reads_and_acknowledges_the_inbox_at_the_daemon() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[approval(session_id, "req-1")])
        .expect("the store records the approval");
    let mut control = host.client().await;
    let read: AttentionReadResult = control
        .request(
            Method::AttentionRead,
            &AttentionReadParams {
                session_id: Nullable::null(),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    assert_eq!(read.items.len(), 1);
    let item = read.items[0].clone();
    assert_eq!(item.rule, AttentionRule::PendingApproval);

    let stale: AttentionAcknowledgeResult = control
        .mutate(
            Method::AttentionAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionAcknowledgeParams {
                items: vec![AttentionItemRevision {
                    key: item.key.clone(),
                    revision: U64::new(item.revision.get().saturating_sub(1)),
                }],
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the acknowledgement is answered")
        .to_typed()
        .expect("decodes");
    assert!(stale.acknowledged.is_empty());
    assert_eq!(stale.stale, vec![item.key.clone()]);

    let acknowledged: AttentionAcknowledgeResult = control
        .mutate(
            Method::AttentionAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionAcknowledgeParams {
                items: vec![AttentionItemRevision {
                    key: item.key.clone(),
                    revision: item.revision,
                }],
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the acknowledgement is answered")
        .to_typed()
        .expect("decodes");
    assert_eq!(acknowledged.acknowledged, vec![item.key.clone()]);
    host.stop().await;
}

/// Every method of the group is served at the daemon's own socket, where nothing forwards it to a
/// worker: review state and its acknowledgement, a visit and the changed view, and the quiet-hours
/// window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_method_of_the_group_is_served_at_the_daemon_s_socket() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (turn, subject) = completed_turn(session_id);
    host.controller()
        .attention()
        .observe(&[turn])
        .expect("the store records the turn");
    let mut control = host.client().await;

    let reviews = owner_reviews(&mut control, session_id).await;
    assert!(
        reviews
            .iter()
            .any(|state| state.subject == subject && state.outstanding),
        "{reviews:?}"
    );
    let reviewed: ReviewAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::ReviewAcknowledge,
        &ReviewAcknowledgeParams {
            session_id,
            subject: subject.clone(),
            version: U64::new(1),
        },
    )
    .await;
    assert!(!reviewed.review.outstanding);

    let visited: VisitAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: U64::new(0),
            views: Vec::new(),
        },
    )
    .await;
    assert_eq!(visited.acknowledged_cursor, U64::new(0));
    let _: VisitChangedResult = control
        .request(
            Method::VisitChanged,
            &VisitChangedParams {
                session_id,
                max_changes: U64::new(50),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the changed view is served")
        .to_typed()
        .expect("decodes");

    let quiet: AttentionQuietHoursResult = owner_mutation(
        &mut control,
        &host,
        Method::AttentionQuietHours,
        &AttentionQuietHoursParams {
            quiet_hours: Nullable::some(night()),
        },
    )
    .await;
    assert_eq!(quiet.quiet_hours, Nullable::some(night()));
    host.stop().await;
}

/// KR-REQ-23.45 and KR-REQ-25.04: a paired device is served the group under its grant, over the
/// network. A grant with `session.view` over every session is shown each session's items and no
/// session text; its review, visit and item acknowledgements are its own and change nothing the
/// owner sees; and without `host.manage` it sets no quiet hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_served_the_group_under_its_grant() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (turn, subject) = completed_turn(session_id);
    host.controller()
        .attention()
        .observe(&[approval(session_id, "req-1"), turn])
        .expect("the store records the approval and the turn");

    let (_viewer, viewing) =
        net_support::paired_device(&host, &owner_keys, &[ActionRight::SessionView]).await;
    let read = device_inbox(&viewing).await;
    assert_eq!(read.items.len(), 2, "its grant admits every session");
    assert!(
        read.items.iter().all(|item| item.summary.0.is_none()),
        "and no session text"
    );
    let reviews: ReviewReadResult = viewing
        .read(
            Method::ReviewRead,
            &ReviewReadParams {
                session_id: Nullable::null(),
                subject: Nullable::null(),
                max_reviews: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("a device's review read is served");
    assert!(reviews.reviews.iter().any(|state| state.subject == subject));
    let _: VisitChangedResult = viewing
        .read(
            Method::VisitChanged,
            &VisitChangedParams {
                session_id,
                max_changes: U64::new(50),
            },
        )
        .await
        .expect("a device's changed view is served");

    let approval_item = of_rule(&read.items, AttentionRule::PendingApproval)[0].clone();
    let acknowledged: AttentionAcknowledgeResult = device_mutation(
        &viewing,
        ActionTarget::environment(host.environment_id),
        Method::AttentionAcknowledge,
        &AttentionAcknowledgeParams {
            items: vec![AttentionItemRevision {
                key: approval_item.key.clone(),
                revision: approval_item.revision,
            }],
        },
    )
    .await
    .expect("a device's acknowledgement is served");
    assert_eq!(acknowledged.acknowledged, vec![approval_item.key.clone()]);
    let reviewed: ReviewAcknowledgeResult = device_mutation(
        &viewing,
        session_target(&host, session_id),
        Method::ReviewAcknowledge,
        &ReviewAcknowledgeParams {
            session_id,
            subject: subject.clone(),
            version: U64::new(1),
        },
    )
    .await
    .expect("a device's review acknowledgement is served");
    assert!(!reviewed.review.outstanding);
    let _: VisitAcknowledgeResult = device_mutation(
        &viewing,
        session_target(&host, session_id),
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: U64::new(0),
            views: Vec::new(),
        },
    )
    .await
    .expect("a device's visit is served");

    // Each acknowledgement was the device's own.
    let mut control = host.client().await;
    let owner_items = owner_inbox(&mut control).await;
    assert!(
        owner_items.iter().all(|item| !item.acknowledged),
        "{owner_items:?}"
    );
    assert!(
        owner_reviews(&mut control, session_id)
            .await
            .iter()
            .any(|state| state.subject == subject && state.outstanding)
    );

    let refused = device_mutation::<AttentionQuietHoursResult>(
        &viewing,
        ActionTarget::environment(host.environment_id),
        Method::AttentionQuietHours,
        &AttentionQuietHoursParams {
            quiet_hours: Nullable::some(night()),
        },
    )
    .await
    .expect_err("quiet hours are the host's to manage");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    host.stop().await;
}

/// KR-REQ-23.45: a batch that names items of two sessions, from a device whose grant admits one of
/// them, acknowledges the item it can see and answers the other as stale, recording nothing about
/// it and saying nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_s_batch_acknowledges_only_what_its_grant_shows_it() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let admitted = SessionId::new(kr_ipc::new_uuid());
    let other = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[approval(admitted, "req-1"), approval(other, "req-2")])
        .expect("the store records both approvals");
    let mut control = host.client().await;
    let everything = owner_inbox(&mut control).await;
    assert_eq!(everything.len(), 2);

    let mut proposal = net_support::proposal(&[ActionRight::SessionView]);
    proposal.session_selector = SessionSelector::These {
        session_ids: [admitted].into_iter().collect(),
    };
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner_keys, proposal).await;
    let viewing = net_support::connect(&host, &device, &record).await;
    let seen = device_inbox(&viewing).await;
    assert_eq!(seen.items.len(), 1);
    assert_eq!(seen.items[0].session_id, Nullable::some(admitted));

    let batch: AttentionAcknowledgeResult = device_mutation(
        &viewing,
        ActionTarget::environment(host.environment_id),
        Method::AttentionAcknowledge,
        &AttentionAcknowledgeParams {
            items: everything
                .iter()
                .map(|item| AttentionItemRevision {
                    key: item.key.clone(),
                    revision: item.revision,
                })
                .collect(),
        },
    )
    .await
    .expect("the batch is answered");
    let hidden = everything
        .iter()
        .find(|item| item.session_id == Nullable::some(other))
        .expect("the other session's item")
        .key
        .clone();
    assert_eq!(batch.acknowledged, vec![seen.items[0].key.clone()]);
    assert_eq!(batch.stale, vec![hidden]);
    host.stop().await;
}

/// KR-REQ-23.45: a device whose grant carries `host.manage` and no `session.view` sees none of a
/// session's items, an acknowledgement naming one is stale, and it may set the quiet hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_only_host_manage_sees_no_session_item_and_sets_quiet_hours() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[approval(session_id, "req-1")])
        .expect("the store records the approval");
    let mut control = host.client().await;
    let item = owner_inbox(&mut control).await[0].clone();
    let (_manager, managing) =
        net_support::paired_device(&host, &owner_keys, &[ActionRight::HostManage]).await;
    let managed = device_inbox(&managing).await;
    assert!(managed.items.is_empty(), "{managed:?}");
    let blind: AttentionAcknowledgeResult = device_mutation(
        &managing,
        ActionTarget::environment(host.environment_id),
        Method::AttentionAcknowledge,
        &AttentionAcknowledgeParams {
            items: vec![AttentionItemRevision {
                key: item.key.clone(),
                revision: item.revision,
            }],
        },
    )
    .await
    .expect("the acknowledgement is answered");
    assert!(blind.acknowledged.is_empty());
    assert_eq!(blind.stale, vec![item.key]);
    let quiet: AttentionQuietHoursResult = device_mutation(
        &managing,
        ActionTarget::environment(host.environment_id),
        Method::AttentionQuietHours,
        &AttentionQuietHoursParams {
            quiet_hours: Nullable::some(night()),
        },
    )
    .await
    .expect("a host manager sets the quiet hours");
    assert_eq!(quiet.quiet_hours, Nullable::some(night()));
    host.stop().await;
}

/// KR-REQ-23.45: a device whose grant carries only `automation.manage` sees none of a session's
/// items and sets no quiet hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_only_automation_manage_sees_no_session_item() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[approval(session_id, "req-1")])
        .expect("the store records the approval");
    let (_automator, automating) =
        net_support::paired_device(&host, &owner_keys, &[ActionRight::AutomationManage]).await;
    let seen = device_inbox(&automating).await;
    assert!(seen.items.is_empty(), "{seen:?}");
    let refused = device_mutation::<AttentionQuietHoursResult>(
        &automating,
        ActionTarget::environment(host.environment_id),
        Method::AttentionQuietHours,
        &AttentionQuietHoursParams {
            quiet_hours: Nullable::some(night()),
        },
    )
    .await
    .expect_err("quiet hours are the host's to manage");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    host.stop().await;
}

/// KR-REQ-24.11: the daemon finishes a session as soon as it records the session's closure, and the
/// closure decides how. One that names no unaccounted worker ends the session's pending approval;
/// one written over a worker this host could not confirm had ended ends nothing, and the approval
/// stays, uncertain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_closure_decides_how_the_daemon_finishes_a_session() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let controller = host.controller();
    let ended = SessionId::new(kr_ipc::new_uuid());
    let unconfirmed = SessionId::new(kr_ipc::new_uuid());
    controller
        .attention()
        .observe(&[approval(ended, "req-1"), approval(unconfirmed, "req-2")])
        .expect("the store records both approvals");
    controller
        .retire(&closure(ended, Vec::new()))
        .await
        .expect("the closure is recorded");
    controller
        .retire(&closure(
            unconfirmed,
            vec![kr_protocol::session::SurvivingResource {
                kind: "unaccounted_worker".to_owned(),
                detail: "this host closed the session without confirming that its worker ended"
                    .to_owned(),
            }],
        ))
        .await
        .expect("the closure is recorded");
    let mut control = host.client().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let items = loop {
        let items = owner_inbox(&mut control).await;
        let finished = !items
            .iter()
            .any(|item| item.session_id == Nullable::some(ended));
        let marked = items
            .iter()
            .any(|item| item.session_id == Nullable::some(unconfirmed) && item.uncertain);
        if finished && marked {
            break items;
        }
        assert!(
            Instant::now() < deadline,
            "the closures were not handled in ten seconds: {items:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let kept = of_rule(&items, AttentionRule::PendingApproval);
    assert_eq!(kept.len(), 1, "{items:?}");
    assert_eq!(kept[0].session_id, Nullable::some(unconfirmed));
    host.stop().await;
}

/// An acknowledgement admitted under authority that is withdrawn before the store's transaction
/// writes nothing: the admission is asked again inside it, before the first write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_before_the_store_s_transaction_writes_nothing() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let controller = host.controller();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    controller
        .attention()
        .observe(&[approval(session_id, "req-1")])
        .expect("the store records the approval");
    let mut control = host.client().await;
    let item = owner_inbox(&mut control).await[0].clone();
    let admission = AdmittedMutation {
        connection_id: control.acknowledgement().connection_id,
        admitted_revision: controller.authority_revision().await.expect("the revision"),
        deadline: controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
    };
    let mutation = control
        .compose(
            Method::AttentionAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionAcknowledgeParams {
                items: vec![AttentionItemRevision {
                    key: item.key.clone(),
                    revision: item.revision,
                }],
            },
        )
        .await
        .expect("the mutation is composed");
    controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let refused = controller
        .attention()
        .write(
            controller,
            &Caller::Owner,
            &owner(),
            &mutation,
            Method::AttentionAcknowledge,
            &admission,
        )
        .await
        .expect_err("the admission no longer stands");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    let reach = controller.attention_reach();
    let after: AttentionReadResult = controller
        .attention()
        .read(
            reach.as_ref(),
            &Caller::Owner,
            &owner(),
            &read_request(None),
        )
        .await
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    assert!(after.items.iter().all(|item| !item.acknowledged));
    assert!(
        controller
            .attention()
            .retained(&owner(), &mutation, Method::AttentionAcknowledge)
            .is_none(),
        "no record of the action was kept"
    );
    host.stop().await;
}

/// KR-REQ-14.35: a review acknowledgement binds the version it was made against, and a later
/// version is new review work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_review_acknowledgement_binds_a_version_and_a_later_one_reopens_the_work() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[turn(session_id, 1)])
        .expect("the store records the turn");
    let mut control = host.client().await;
    let reviewed: ReviewAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::ReviewAcknowledge,
        &ReviewAcknowledgeParams {
            session_id,
            subject: turn_subject(session_id),
            version: U64::new(1),
        },
    )
    .await;
    assert!(!reviewed.review.outstanding);
    assert_eq!(
        reviewed.review.acknowledged_version,
        Nullable::some(U64::new(1))
    );
    host.controller()
        .attention()
        .observe(&[turn(session_id, 2)])
        .expect("the store records the next version");
    let reopened = owner_reviews(&mut control, session_id).await;
    let state = reopened
        .iter()
        .find(|state| state.subject == turn_subject(session_id))
        .expect("the turn is a subject");
    assert_eq!(state.current_version, U64::new(2));
    assert!(state.outstanding, "a new change is new review work");
    host.stop().await;
}

/// KR-REQ-14.35: a review acknowledgement names a subject and a version this host holds. Anything
/// else is refused before the store performs anything, so no record of the action is kept, and
/// the same action is decided afresh once the subject exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_review_acknowledgement_names_a_subject_and_a_version_this_host_holds() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut control = host.client().await;
    let first = control
        .compose(
            Method::ReviewAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &ReviewAcknowledgeParams {
                session_id,
                subject: turn_subject(session_id),
                version: U64::new(1),
            },
        )
        .await
        .expect("the mutation is composed");
    let unknown = control
        .repeat(&first)
        .await
        .expect("the call reaches the daemon")
        .expect_err("a subject this host never held cannot be acknowledged");
    assert_eq!(unknown.code, ErrorCode::InvalidArgument);

    host.controller()
        .attention()
        .observe(&[turn(session_id, 1)])
        .expect("the store records the turn");
    let ahead = control
        .mutate(
            Method::ReviewAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &ReviewAcknowledgeParams {
                session_id,
                subject: turn_subject(session_id),
                version: U64::new(2),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a version nobody produced cannot be acknowledged");
    assert_eq!(ahead.code, ErrorCode::DraftConflict);

    let decided: ReviewAcknowledgeResult = control
        .repeat(&first)
        .await
        .expect("the call reaches the daemon")
        .expect("the refused action kept no record, so it is decided afresh")
        .to_typed()
        .expect("decodes");
    assert!(!decided.review.outstanding);
    host.stop().await;
}

/// KR-REQ-14.35: no method of the group asks for a right that changes code, and acknowledging a
/// review moves nothing this host holds about what was reviewed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_method_of_the_group_can_reach_a_right_that_changes_code() {
    for entry in REGISTRY
        .iter()
        .filter(|entry| entry.group == MethodGroup::ReviewAndAttention)
    {
        for required in entry.required_rights {
            let kr_protocol::authority::RequiredAuthority::Right { right } = required.authority
            else {
                continue;
            };
            assert!(
                !matches!(
                    right,
                    ActionRight::FilesApplyDiff
                        | ActionRight::ChangesetCreate
                        | ActionRight::TerminalInput
                        | ActionRight::AgentApprovalRespond
                ),
                "{} would let a review method change something",
                entry.name
            );
        }
    }

    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[turn(session_id, 1)])
        .expect("the store records the turn");
    let mut control = host.client().await;
    let before = owner_reviews(&mut control, session_id).await;
    let _: ReviewAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::ReviewAcknowledge,
        &ReviewAcknowledgeParams {
            session_id,
            subject: turn_subject(session_id),
            version: U64::new(1),
        },
    )
    .await;
    let after = owner_reviews(&mut control, session_id).await;
    assert_eq!(
        after[0].current_version, before[0].current_version,
        "what was reviewed is unchanged by the review"
    );
    host.stop().await;
}

/// KR-REQ-25.27: a visit records the cursor it reached and the log views it had open, and the
/// changed view afterwards has nothing new and gives the views back as they were left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_records_a_cursor_and_the_views_it_had_open() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[turn(session_id, 1)])
        .expect("the store records the turn");
    let mut control = host.client().await;
    let changed = owner_changes(&mut control, session_id).await;
    assert_eq!(changed.from_cursor, U64::new(0));
    assert!(!changed.changes.is_empty());
    assert!(changed.views.is_empty());

    let visit: VisitAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: changed.to_cursor,
            views: vec![LogViewState {
                view_id: "build".to_owned(),
                source_offset: U64::new(4_096),
                filter: "level=error".to_owned(),
            }],
        },
    )
    .await;
    assert_eq!(visit.acknowledged_cursor, changed.to_cursor);
    assert_eq!(visit.views.len(), 1);

    let after = owner_changes(&mut control, session_id).await;
    assert!(after.changes.is_empty(), "everything has been seen");
    assert_eq!(after.views.len(), 1, "and the view came back with it");
    assert_eq!(after.views[0].view.filter, "level=error");
    host.stop().await;
}

/// KR-REQ-25.27: a finished session's log views are measured against the output its spool still
/// retains, since retention goes on after the session ends: a view whose range retention took is
/// served from the oldest byte there is and told about the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finished_session_s_views_are_measured_against_what_its_spool_retains() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let controller = host.controller();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut control = host.client().await;
    let visited: VisitAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: U64::new(0),
            views: vec![LogViewState {
                view_id: "build".to_owned(),
                source_offset: U64::new(50),
                filter: "level=error".to_owned(),
            }],
        },
    )
    .await;
    let reach = TestReach::default();
    reach.floor.store(100, Ordering::SeqCst);
    controller
        .attention()
        .session_closed(&reach, session_id)
        .await;
    let changed: VisitChangedResult = controller
        .attention()
        .read(
            &reach,
            &Caller::Owner,
            &visited.actor_id,
            &Request {
                request_id: RequestId::new(9),
                method: Method::VisitChanged.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::from_typed(&VisitChangedParams {
                    session_id,
                    max_changes: U64::new(50),
                })
                .expect("encodes"),
            },
        )
        .await
        .expect("the changed view is served")
        .to_typed()
        .expect("decodes");
    assert_eq!(changed.views.len(), 1);
    let view = &changed.views[0];
    assert_eq!(view.view.source_offset, U64::new(100));
    assert_eq!(view.view.filter, "level=error");
    assert_eq!(view.requested_offset, Nullable::some(U64::new(50)));
    assert!(view.gap.is_present(), "{view:?}");
    host.stop().await;
}

/// A value the store could not write down as it was given is refused before the store performs
/// anything, and no record of the action is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_value_the_store_could_not_write_down_as_it_was_given_is_refused() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut control = host.client().await;
    let visited: VisitAcknowledgeResult = owner_mutation(
        &mut control,
        &host,
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: U64::new(0),
            views: Vec::new(),
        },
    )
    .await;
    let refused = control
        .compose(
            Method::VisitAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VisitAcknowledgeParams {
                session_id,
                acknowledged_cursor: U64::new(0),
                views: vec![LogViewState {
                    view_id: "build".to_owned(),
                    // One past the largest counter the store writes down.
                    source_offset: U64::new(9_223_372_036_854_775_808),
                    filter: String::new(),
                }],
            },
        )
        .await
        .expect("the mutation is composed");
    let error = control
        .repeat(&refused)
        .await
        .expect("the call reaches the daemon")
        .expect_err("an offset the store could not keep cannot be recorded");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(
        host.controller()
            .attention()
            .retained(&visited.actor_id, &refused, Method::VisitAcknowledge)
            .is_none(),
        "no record of the action was kept"
    );
    host.stop().await;
}

/// One more actor than the store admits is refused before the store performs anything, so
/// nothing anybody has acknowledged is deleted to make room.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_more_actor_than_the_store_admits_is_refused() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let controller = host.controller();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut control = host.client().await;
    let admission = AdmittedMutation {
        connection_id: control.acknowledgement().connection_id,
        admitted_revision: controller.authority_revision().await.expect("the revision"),
        deadline: controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
    };
    let visit = VisitAcknowledgeParams {
        session_id,
        acknowledged_cursor: U64::new(0),
        views: Vec::new(),
    };
    for index in 0..kr_protocol::attention::MAX_RETAINED_ACTORS {
        let mutation = control
            .compose(
                Method::VisitAcknowledge,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &visit,
            )
            .await
            .expect("the mutation is composed");
        controller
            .attention()
            .write(
                controller,
                &Caller::Owner,
                &ActorId::new(format!("device:phone-{index}")).expect("an actor"),
                &mutation,
                Method::VisitAcknowledge,
                &admission,
            )
            .await
            .expect("the store admits an actor inside its bound");
    }
    let refused = control
        .mutate(
            Method::VisitAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &visit,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("an actor past the bound cannot be admitted");
    assert_eq!(refused.code, ErrorCode::QuotaExceeded);
    host.stop().await;
}

/// A daemon whose store was taken from it refuses each action as unavailable rather than
/// answering it as done: the write that finds out is refused, and every later one is refused
/// before the store performs anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_the_store_can_no_longer_record_is_refused() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    // The store is taken from the running daemon: this opener is told the process that claimed it
    // has gone, which is what a daemon that had crashed would leave behind.
    let gone = |_: &kr_protocol::identity::ProcessStartIdentity| kr_attention::Liveness::Ended;
    let taker = kr_attention::Claimant::new(
        kr_ipc::identity::current_process_start_identity().expect("the kernel answers"),
        &gone,
    );
    let _taken = kr_attention::Attention::open(
        host.tree()
            .environment()
            .state_dir()
            .join("attention.sqlite3"),
        kr_attention::HostReading::new(
            kr_attention::time::BootMark::of(b"another daemon"),
            kr_ipc::clock::boot_elapsed_ms(),
            kr_ipc::now_ms().get(),
            true,
        ),
        &taker,
    )
    .expect("the store is taken from a process this opener is told has gone");

    let mut control = host.client().await;
    let discovered = control
        .mutate(
            Method::AttentionQuietHours,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionQuietHoursParams {
                quiet_hours: Nullable::some(night()),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a store this daemon no longer holds records no window");
    assert_eq!(discovered.code, ErrorCode::StorageUnavailable);
    let refused = control
        .mutate(
            Method::VisitAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VisitAcknowledgeParams {
                session_id,
                acknowledged_cursor: U64::new(0),
                views: Vec::new(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a store this daemon knows it lost records nothing");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable);
    host.stop().await;
}

/// An acknowledgement admitted while its deadline stood, whose store transaction begins only after
/// the deadline passed, is refused inside that transaction and writes nothing: the admission is
/// asked again there, before the store's first write.
///
/// The order is made, not hoped for. Another guarded write holds the daemon's registry while the
/// acknowledgement's own checks pass, then sets the store to work on a long batch and lets the
/// registry go: the acknowledgement's admission is asked and stands, and its transaction then waits
/// for the store until the deadline has passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_that_passes_while_the_store_is_busy_refuses_the_action() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let controller = host.controller();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    controller
        .attention()
        .observe(&[approval(session_id, "req-1")])
        .expect("the store records the approval");
    let mut control = host.client().await;
    let item = owner_inbox(&mut control).await[0].clone();
    let mutation = control
        .compose(
            Method::AttentionAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionAcknowledgeParams {
                items: vec![AttentionItemRevision {
                    key: item.key.clone(),
                    revision: item.revision,
                }],
            },
        )
        .await
        .expect("the mutation is composed");
    let admitted_revision = controller.authority_revision().await.expect("the revision");
    let connection_id = control.acknowledgement().connection_id;

    // A long call on another thread holds the store: many records of another session, applied in
    // one call.
    let module = Arc::clone(controller.attention());
    let busy_session = SessionId::new(kr_ipc::new_uuid());
    let burden: Vec<_> = (1..=1_000)
        .map(|sequence| approval_at(busy_session, sequence, &format!("busy-{sequence}")))
        .collect();
    let busy = std::thread::spawn(move || {
        let started = Instant::now();
        module.observe(&burden).expect("the records are applied");
        started.elapsed()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Admitted with half a second to spare, so its first check passes at once; the deadline then
    // passes while it waits for the store.
    let bound = Duration::from_millis(500);
    let admission = AdmittedMutation {
        connection_id,
        admitted_revision,
        deadline: controller.continuous_now().checked_add(bound),
    };
    let started = Instant::now();
    let refused = controller
        .attention()
        .write(
            controller,
            &Caller::Owner,
            &owner(),
            &mutation,
            Method::AttentionAcknowledge,
            &admission,
        )
        .await;
    let waited = started.elapsed();
    let busy_for = busy.join().expect("the busy call finishes");
    assert!(
        busy_for > bound,
        "the store was held past the deadline: {busy_for:?}"
    );
    assert!(
        waited >= bound,
        "the action passed its first check and waited for the store: {waited:?}"
    );
    let refused = refused.expect_err("the deadline passed while the action waited for the store");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    let reach = controller.attention_reach();
    let after: AttentionReadResult = controller
        .attention()
        .read(
            reach.as_ref(),
            &Caller::Owner,
            &owner(),
            &read_request(Some(session_id)),
        )
        .await
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    assert!(after.items.iter().all(|item| !item.acknowledged));
    assert!(
        controller
            .attention()
            .retained(&owner(), &mutation, Method::AttentionAcknowledge)
            .is_none()
    );
    host.stop().await;
}

/// A quiet-hours action answers its repeat exactly as it answered the first time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_quiet_hours_action_answers_what_it_first_answered() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let mut control = host.client().await;
    let composed = control
        .compose(
            Method::AttentionQuietHours,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AttentionQuietHoursParams {
                quiet_hours: Nullable::some(night()),
            },
        )
        .await
        .expect("the mutation is composed");
    let first: AttentionQuietHoursResult = control
        .repeat(&composed)
        .await
        .expect("the call reaches the daemon")
        .expect("the window is set")
        .to_typed()
        .expect("decodes");
    // Another window is set in between; the repeat still answers what the first call did.
    let _: AttentionQuietHoursResult = owner_mutation(
        &mut control,
        &host,
        Method::AttentionQuietHours,
        &AttentionQuietHoursParams {
            quiet_hours: Nullable::null(),
        },
    )
    .await;
    let repeated: AttentionQuietHoursResult = control
        .repeat(&composed)
        .await
        .expect("the call reaches the daemon")
        .expect("the repeat is answered")
        .to_typed()
        .expect("the repeat has the first answer's shape");
    assert_eq!(repeated, first);
    host.stop().await;
}

/// A review acknowledgement names a subject of the session it names: one naming another session's
/// subject is refused and records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_review_acknowledgement_names_a_subject_of_the_session_it_names() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner_keys).await;
    let named = SessionId::new(kr_ipc::new_uuid());
    let other = SessionId::new(kr_ipc::new_uuid());
    host.controller()
        .attention()
        .observe(&[turn(other, 1)])
        .expect("the store records the turn");
    let mut control = host.client().await;
    let refused = control
        .mutate(
            Method::ReviewAcknowledge,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &ReviewAcknowledgeParams {
                session_id: named,
                subject: turn_subject(other),
                version: U64::new(1),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("the subject belongs to another session");
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(
        owner_reviews(&mut control, other)
            .await
            .iter()
            .any(|state| state.subject == turn_subject(other) && state.outstanding)
    );
    host.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Helpers for the group's methods
// ---------------------------------------------------------------------------------------------

/// The closure of a session whose root exited, with the resources named as surviving it.
fn closure(
    session_id: SessionId,
    surviving: Vec<kr_protocol::session::SurvivingResource>,
) -> kr_protocol::session::ClosureRecord {
    kr_protocol::session::ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: kr_protocol::session::ClosureReason::RootExit,
        root_exit_code: Nullable::some(U64::new(0)),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving,
        ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
        durability: kr_protocol::session::Durability::Durable,
        closed_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    }
}

/// A completed turn in a session, as a host observes it, with the review subject it makes.
fn completed_turn(session_id: SessionId) -> (kr_attention::SourceEvent, ReviewSubject) {
    (turn(session_id, 1), turn_subject(session_id))
}

/// One version of a session's completed turn, recorded as the record of that number.
fn turn(session_id: SessionId, version: u64) -> kr_attention::SourceEvent {
    kr_attention::SourceEvent::new(
        kr_attention::EventCursor::in_session(session_id, AttentionSource::Semantic, version),
        TimestampMs::new(kr_ipc::now_ms().get()),
        kr_attention::EventKind::TurnCompleted {
            session_id,
            turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
            version,
            change_set: None,
            summary: String::new(),
        },
    )
}

fn turn_subject(session_id: SessionId) -> ReviewSubject {
    ReviewSubject::CompletedTurn {
        session_id,
        turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
    }
}

async fn owner_changes(control: &mut LocalClient, session_id: SessionId) -> VisitChangedResult {
    control
        .request(
            Method::VisitChanged,
            &VisitChangedParams {
                session_id,
                max_changes: U64::new(50),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the changed view is served")
        .to_typed()
        .expect("decodes")
}

/// A window from ten at night to seven in the morning, UTC.
fn night() -> QuietHours {
    QuietHours {
        start_minute: U64::new(22 * 60),
        end_minute: U64::new(7 * 60),
        zone: Nullable::null(),
    }
}

async fn owner_inbox(control: &mut LocalClient) -> Vec<AttentionItem> {
    let read: AttentionReadResult = control
        .request(
            Method::AttentionRead,
            &AttentionReadParams {
                session_id: Nullable::null(),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the inbox reads")
        .to_typed()
        .expect("decodes");
    read.items
}

async fn owner_reviews(control: &mut LocalClient, session_id: SessionId) -> Vec<ReviewState> {
    let read: ReviewReadResult = control
        .request(
            Method::ReviewRead,
            &ReviewReadParams {
                session_id: Nullable::some(session_id),
                subject: Nullable::null(),
                max_reviews: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("review state reads")
        .to_typed()
        .expect("decodes");
    read.reviews
}

async fn owner_mutation<P, R>(
    control: &mut LocalClient,
    host: &net_support::Host,
    method: Method,
    params: &P,
) -> R
where
    P: serde::Serialize,
    R: kr_protocol::wire::WireMessage,
{
    control
        .mutate(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
        .unwrap_or_else(|error| panic!("{} is served: {error:?}", method.as_str()))
        .to_typed()
        .expect("decodes")
}

async fn device_inbox(device: &kr_client::session::Session) -> AttentionReadResult {
    device
        .read(
            Method::AttentionRead,
            &AttentionReadParams {
                session_id: Nullable::null(),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("a device's attention read is served")
}

/// A target naming one session, as a device's action on a session names it.
fn session_target(host: &net_support::Host, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        ..ActionTarget::environment(host.environment_id)
    }
}

async fn device_mutation<R>(
    device: &kr_client::session::Session,
    target: ActionTarget,
    method: Method,
    params: &impl serde::Serialize,
) -> Result<R, kr_client::error::ClientError>
where
    R: kr_protocol::wire::WireMessage,
{
    device
        .mutate(
            method,
            target,
            None,
            &ParamsValue::empty(),
            params,
            DurationMs::new(120_000),
        )
        .await
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a settled mutation answers with its result")
                .to_typed()
                .expect("decodes")
        })
}

// ---------------------------------------------------------------------------------------------
// The privacy fence
// ---------------------------------------------------------------------------------------------

/// A daemon's attention connection to `worker` that acknowledges nothing, as a daemon that has
/// stopped answering does. It takes the worker's attention link from whichever it replaces.
async fn silent_daemon(worker: &Worker) -> LocalClient {
    let mut client =
        LocalClient::connect(&worker.known.endpoint, LocalClientKind::Controller, build())
            .await
            .expect("connects");
    client
        .writer()
        .write_message(&ControlFrame::ControllerRole(
            ControllerConnectionRole::Attention,
        ))
        .await
        .expect("declares the role");
    let _ = client.recv().await.expect("the role is accepted");
    let identity = Arc::clone(&worker.controller);
    let boot = worker.boot.clone();
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

/// An owner's connection for a read's answer to be written on, and the reader's end of it.
async fn owner_connection(
    temp: &kr_ipc::testing::TempHost,
) -> (kr_ipc::framed::FrameWriter, kr_ipc::framed::FrameReader) {
    let endpoint = temp
        .environment()
        .worker_endpoint(DisplayNumber::new(9))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds");
    let accepting = tokio::spawn(async move { listener.accept().await.expect("accepts").0 });
    let near = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    let far = accepting.await.expect("accepted");
    let (_, writer) = kr_ipc::framed::split(near, kr_protocol::frame::StreamKind::Control);
    let (reader, _) = kr_ipc::framed::split(far, kr_protocol::frame::StreamKind::Control);
    (writer, reader)
}

/// Writes a read's answer as the owner's connection does, and reads the inbox the reader gets.
async fn released_to_the_reader(
    temp: &kr_ipc::testing::TempHost,
    module: &AttentionModule,
    released: kr_controller::attention::Released,
) -> AttentionReadResult {
    let (mut writer, mut reader) = owner_connection(temp).await;
    module
        .write_released(
            &mut writer,
            kr_protocol::frame::StreamKind::Control,
            released,
        )
        .await
        .expect("an answer is written");
    let ControlFrame::Response(response) = reader
        .read_message::<ControlFrame>()
        .await
        .expect("the reader gets the answer")
    else {
        panic!("a response");
    };
    let kr_protocol::envelope::Outcome::Ok(value) = response.outcome else {
        panic!("the read was refused");
    };
    value.to_typed().expect("decodes")
}

fn summaries(read: &AttentionReadResult) -> Vec<Option<String>> {
    read.items
        .iter()
        .map(|item| item.summary.0.clone())
        .collect()
}

/// Enables privacy mode in a worker's session with the worker's attention subsystem driven, and
/// returns the subsystem, which reports whether the daemon has recorded the generation.
fn enable(worker: &Worker) -> kr_worker::attention_fence::AttentionPrivacy {
    let mut attention = worker.service.attention_privacy();
    worker
        .service
        .runtime()
        .session()
        .enable_privacy(&mut [&mut attention])
        .expect("privacy mode is enabled");
    attention
}

fn completed(worker: &Worker, attention: &kr_worker::attention_fence::AttentionPrivacy) -> bool {
    worker
        .service
        .runtime()
        .session()
        .reconcile_privacy(&[attention])
        .is_complete()
}

/// Reads the inbox until the question asked has its text.
async fn with_text(module: &AttentionModule, reach: &TestReach) -> Vec<AttentionItem> {
    until(module, reach, |items| {
        of_rule(items, AttentionRule::PendingInput)
            .iter()
            .any(|item| item.summary.is_present())
    })
    .await
}

/// KR-REQ-24.11: text in flight when privacy mode is enabled and the daemon does not answer. An
/// owner's read the daemon holds across the commit, and a delivery's text it resolved before it,
/// are withheld when released after the commit: the worker committed only once the leases their
/// text carries had ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_held_across_a_commit_the_daemon_never_acknowledged_is_withheld() {
    let one = worker().await;
    ask(&one, "r-1", "which branch?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let _ = with_text(&module, &reach).await;

    let held = module
        .read_released(&*reach, &Caller::Owner, &owner(), &read_request(None))
        .await;
    let question =
        kr_attention::EventCursor::in_session(one.session_id, AttentionSource::Questions, 1);
    let (resolved, ticket) = module.delivery_texts(&*reach, &[question]).await;
    assert_eq!(resolved, vec![Some("which branch?".to_owned())]);
    assert_eq!(
        module.release_delivery(&ticket, || ()).await,
        Some(()),
        "before the commit the delivery goes"
    );

    // The daemon stops answering: a connection that acknowledges nothing takes the worker's link,
    // and the store is kept from making another.
    *reach.stalled.lock().expect("not poisoned") = Some(one.known.endpoint.as_text());
    let _silent = silent_daemon(&one).await;
    let transition = one.service.raise_privacy_transition().await;
    let _attention = enable(&one);
    transition.settle().await;

    assert_eq!(
        module.release_delivery(&ticket, || ()).await,
        None,
        "after the commit it does not"
    );
    let read = released_to_the_reader(&temp, &module, held).await;
    assert!(!read.items.is_empty());
    assert!(
        summaries(&read).iter().all(Option::is_none),
        "{:?}",
        read.items
    );
}

/// KR-REQ-24.11: text in flight when privacy mode is enabled and the transition then fails. The
/// acknowledged barrier withholds text the daemon holds; the worker's settling statement after a
/// commit that did not happen lowers it at the generation it left, and that text goes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_raise_withholds_held_text_until_a_failed_commit_lowers_it() {
    let one = worker().await;
    ask(&one, "r-1", "which branch?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let _ = with_text(&module, &reach).await;
    let first = module
        .read_released(&*reach, &Caller::Owner, &owner(), &read_request(None))
        .await;
    let second = module
        .read_released(&*reach, &Caller::Owner, &owner(), &read_request(None))
        .await;

    let transition = tokio::time::timeout(
        Duration::from_secs(2),
        one.service.raise_privacy_transition(),
    )
    .await
    .expect("the daemon acknowledges the raise at once");
    let during = released_to_the_reader(&temp, &module, first).await;
    assert!(summaries(&during).iter().all(Option::is_none));

    // Nothing is committed; the settlement says so. Once it has reached the daemon, a fresh read
    // serves the text again, and so does the answer held from before the raise.
    transition.settle().await;
    let _ = with_text(&module, &reach).await;
    let after = released_to_the_reader(&temp, &module, second).await;
    assert_eq!(
        summaries(&after),
        vec![Some("which branch?".to_owned())],
        "the lowered barrier releases what was held"
    );
}

/// KR-REQ-24.11: a link replaced during the transition. The barrier the old link raised stands
/// while the link is replaced and the new link states the transition again, and privacy mode
/// completes only once a request on the new connection names the generation committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_replaced_during_the_transition_keeps_the_barrier_until_it_is_settled() {
    let one = worker().await;
    ask(&one, "r-1", "which branch?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let _ = with_text(&module, &reach).await;
    let held = module
        .read_released(&*reach, &Caller::Owner, &owner(), &read_request(None))
        .await;
    let transition = tokio::time::timeout(
        Duration::from_secs(2),
        one.service.raise_privacy_transition(),
    )
    .await
    .expect("the daemon acknowledges the raise at once");

    // The same worker, reached again: the store closes its link and opens another.
    let mut again = one.known.clone();
    again.descriptor.published_at_ms = TimestampMs::new(again.descriptor.published_at_ms.get() + 1);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, again);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let during = released_to_the_reader(&temp, &module, held).await;
    assert!(
        summaries(&during).iter().all(Option::is_none),
        "the barrier stands across the replacement"
    );

    let attention = enable(&one);
    transition.settle().await;
    assert!(!completed(&one, &attention));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !completed(&one, &attention) {
        assert!(
            Instant::now() < deadline,
            "the new connection never named the generation"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// KR-REQ-24.11: a daemon restart during the transition. The new daemon acknowledges the raise at
/// once, and the commit still waits out the text the earlier daemon was given, whose barrier is
/// not the new daemon's to keep; text the new daemon was given later is covered by its own barrier
/// and not waited for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_daemon_s_acknowledgement_waits_out_what_the_earlier_one_was_given() {
    let lease = kr_protocol::attention::ATTENTION_TEXT_LEASE_MS;
    let one = worker().await;
    ask(&one, "r-1", "which branch?");
    let temp = kr_ipc::testing::TempHost::create();
    let earlier = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    earlier.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let _ = with_text(&earlier, &reach).await;
    let asked_at = kr_ipc::clock::boot_elapsed_ms();
    let read = inbox(&earlier, &reach).await;
    let answered_by = kr_ipc::clock::boot_elapsed_ms();
    assert!(read.items.iter().any(|item| item.summary.is_present()));
    drop(earlier);

    // The next daemon speaks for a later generation, opens the same store, and is given text of
    // its own two seconds later, with a lease that ends two seconds after the earlier one.
    let restarted = Arc::new(TestReach::default());
    restarted.later.store(true, Ordering::SeqCst);
    restarted.add(&one);
    let later = reopen(&temp).await;
    later.watch(Arc::clone(&restarted) as Arc<dyn Reach>, one.known.clone());
    while kr_ipc::clock::boot_elapsed_ms() < answered_by + 2_000 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let given_at = kr_ipc::clock::boot_elapsed_ms();
    let _ = with_text(&later, &restarted).await;

    let raised_at = kr_ipc::clock::boot_elapsed_ms();
    assert!(
        raised_at + 500 < asked_at + lease,
        "the earlier daemon's lease still holds when the raise begins"
    );
    let transition = one.service.raise_privacy_transition().await;
    let returned = kr_ipc::clock::boot_elapsed_ms();
    assert!(
        returned >= asked_at + lease,
        "returned at {returned}, before the earlier daemon's lease from {asked_at} ended"
    );
    assert!(
        returned < given_at + lease,
        "returned at {returned}: the later daemon acknowledged, so its own lease from {given_at} \
         was not waited for"
    );
    let _attention = enable(&one);
    transition.settle().await;
}

/// KR-REQ-24.11: text held across enable, disable and enable in quick succession, each enable
/// raised with the daemon and acknowledged, is withheld afterwards: the generation it was decided
/// under is three transitions behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_held_across_enable_disable_and_enable_is_withheld() {
    let one = worker().await;
    ask(&one, "r-1", "which branch?");
    let temp = kr_ipc::testing::TempHost::create();
    let module = store_at(&temp);
    let reach = Arc::new(TestReach::default());
    reach.add(&one);
    module.watch(Arc::clone(&reach) as Arc<dyn Reach>, one.known.clone());
    let _ = with_text(&module, &reach).await;
    let held = module
        .read_released(&*reach, &Caller::Owner, &owner(), &read_request(None))
        .await;

    let first = tokio::time::timeout(
        Duration::from_secs(2),
        one.service.raise_privacy_transition(),
    )
    .await
    .expect("the daemon acknowledges the first raise");
    let _enabled = enable(&one);
    first.settle().await;
    one.service
        .runtime()
        .session()
        .disable_privacy()
        .expect("privacy mode is turned off");
    let second = tokio::time::timeout(
        Duration::from_secs(2),
        one.service.raise_privacy_transition(),
    )
    .await
    .expect("the daemon acknowledges the second raise");
    let _again = enable(&one);
    second.settle().await;

    let read = released_to_the_reader(&temp, &module, held).await;
    assert!(
        summaries(&read).iter().all(Option::is_none),
        "{:?}",
        read.items
    );
}
