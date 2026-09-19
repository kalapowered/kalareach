//! Section 23's review and attention group, served by a real worker over its real endpoint.
//!
//! The engine's own decisions are proved in `kr-attention`, where a test can drive the clock. What
//! is here is the part that needs a worker: that the six methods are reachable, that each answer is
//! the acting actor's own, that the feature store lives in the session's private journal and comes
//! back from it, and that nothing in the group touches anything but review and attention state.

use std::sync::Arc;

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionKey, AttentionReadParams,
    AttentionReadResult, AttentionRule, AttentionSource, LogViewState, QuietHours,
    ReviewAcknowledgeParams, ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult,
    ReviewSubject, VisitAcknowledgeParams, VisitAcknowledgeResult, VisitChangedParams,
    VisitChangedResult,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, AgentTurnId, ApprovalRequestId, BuildId, ChangeSetId,
    ConnectionId, ControllerGeneration, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodGroup, MethodVersion, REGISTRY};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
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
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
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
    // The secret store is the one the test seam opens under the environment's own directory, so
    // nothing here reaches the operating system's login keychain.
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
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
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
                journal_path: Some(journal_path.clone()),
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
        environment_id,
    }
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

async fn controller_client(host: &Host) -> LocalClient {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
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

fn target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

fn mutation(
    window: &ActionWindowId,
    host: &Host,
    method: Method,
    params: ParamsValue,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(7),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: target(host),
        expected: ParamsValue::empty(),
        action_window_id: window.clone(),
        requested_ttl_ms: DurationMs::new(30_000),
        params,
    }
}

/// The window this client was issued, taken before the client is borrowed to send with.
fn window(client: &LocalClient) -> ActionWindowId {
    client.action_window().action_window_id.clone()
}

async fn send_mutation(client: &mut LocalClient, mutation: MutationRequest) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn send_request(client: &mut LocalClient, request: Request) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Request(request))
        .await
        .expect("writes the request");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn send_frame(client: &mut LocalClient, frame: ControlFrame) -> Outcome {
    client
        .writer()
        .write_message(&frame)
        .await
        .expect("writes the frame");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

fn request(method: Method, params: ParamsValue) -> Request {
    Request {
        request_id: RequestId::new(11),
        method: method.into(),
        method_version: MethodVersion::V1,
        params,
    }
}

fn typed<T: serde::Serialize>(value: &T) -> ParamsValue {
    ParamsValue::from_typed(value).expect("encodes")
}

fn ok<T: serde::Serialize + serde::de::DeserializeOwned>(outcome: Outcome) -> T {
    let Outcome::Ok(value) = outcome else {
        panic!("the worker refused: {outcome:?}");
    };
    value.to_typed().expect("decodes")
}

fn read_params(host: &Host) -> AttentionReadParams {
    AttentionReadParams {
        session_id: host.session_id,
        include_acknowledged: true,
        max_items: U64::new(50),
        after: Nullable::null(),
    }
}

/// Puts one condition into the engine, the way a producer inside the worker would.
fn observe(host: &Host, sequence: u64, kind: EventKind) {
    let source = match kind {
        EventKind::ApprovalRequested { .. } | EventKind::ApprovalResolved { .. } => {
            AttentionSource::Receipts
        }
        _ => AttentionSource::Semantic,
    };
    let time = Arc::clone(host.service.runtime().session().time());
    host.service
        .attention()
        .observe(
            &SourceEvent::new(
                EventCursor::new(source, sequence),
                TimestampMs::new(kr_ipc::now_ms().get()),
                kind,
            ),
            &time,
        )
        .expect("the engine records the condition");
}

fn approval(request: &str) -> EventKind {
    EventKind::ApprovalRequested {
        request_id: ApprovalRequestId::new(request).expect("an identifier"),
        session_id: SessionId::new(Uuid::from_bytes([0; 16])),
        summary: "write /etc/hosts".to_owned(),
    }
}

fn turn(session_id: SessionId, version: u64) -> EventKind {
    EventKind::TurnCompleted {
        session_id,
        turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
        version,
        change_set: Some((ChangeSetId::new(Uuid::from_bytes([5; 16])), version)),
        summary: "rewrote the parser".to_owned(),
    }
}

fn turn_subject(session_id: SessionId) -> ReviewSubject {
    ReviewSubject::CompletedTurn {
        session_id,
        turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
    }
}

// ---------------------------------------------------------------------------------------------
// The group, end to end
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_inbox_the_quiet_window_and_an_acknowledgement_travel_over_the_endpoint() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);

    let empty: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    assert!(empty.items.is_empty());
    assert!(!empty.quiet_now);
    assert!(!empty.quiet_hours.is_present());

    // A window either side of whatever hour this is, so the test does not depend on the clock.
    let quiet = QuietHours {
        start_minute: U64::new(0),
        end_minute: U64::new(0),
        zone: Nullable::some("Africa/Johannesburg".to_owned()),
    };
    let set = send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::AttentionQuietHours,
            typed(&kr_protocol::attention::AttentionQuietHoursParams {
                session_id: host.session_id,
                quiet_hours: Nullable::some(quiet.clone()),
            }),
        ),
    )
    .await;
    let set: kr_protocol::attention::AttentionQuietHoursResult = ok(set);
    assert_eq!(set.quiet_hours, Nullable::some(quiet));
    assert_eq!(set.quiet_now, set.quiet_hours_provable);

    observe(&host, 1, approval("req-1"));
    let raised: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    assert_eq!(raised.items.len(), 1);
    let item = &raised.items[0];
    assert_eq!(item.rule, AttentionRule::PendingApproval);
    assert!(item.trusted);
    assert!(!item.acknowledged);
    assert_eq!(
        raised.quiet_now, raised.quiet_hours_provable,
        "a whole-day window covers every hour, and a host that cannot prove its clock is never \
         inside one"
    );

    let acknowledged: AttentionAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::AttentionAcknowledge,
            typed(&AttentionAcknowledgeParams {
                session_id: host.session_id,
                keys: vec![item.key.clone()],
            }),
        ),
    )
    .await);
    assert_eq!(acknowledged.acknowledged, vec![item.key.clone()]);
    assert_eq!(acknowledged.revision, U64::new(1));

    let after: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    assert!(after.items[0].acknowledged);
}

#[tokio::test]
async fn an_acknowledgement_reaches_only_the_actor_that_made_it() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    observe(&host, 1, approval("req-1"));

    let mine: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    let key = mine.items[0].key.clone();
    let _: AttentionAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::AttentionAcknowledge,
            typed(&AttentionAcknowledgeParams {
                session_id: host.session_id,
                keys: vec![key.clone()],
            }),
        ),
    )
    .await);

    // The same read, forwarded by the daemon as somebody else.
    let mut proxy = controller_client(&host).await;
    let forwarded: AttentionReadResult = ok(send_frame(
        &mut proxy,
        ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
            request: request(Method::AttentionRead, typed(&read_params(&host))),
            actor: ActorEnvelope {
                actor_id: ActorId::new("device:phone").expect("a principal"),
                ingress: ActorIngress::PairedDevice,
                device_id: Nullable::some(kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid())),
                grant_id: Nullable::null(),
                grant_revision: Nullable::null(),
                controller_generation: ControllerGeneration::new(1),
                connection_id: ConnectionId::new(kr_ipc::new_uuid()),
            },
            authority_deadline_boot_ms: Nullable::null(),
        })),
    )
    .await);
    assert_eq!(forwarded.items.len(), 1);
    assert!(
        !forwarded.items[0].acknowledged,
        "another actor has not seen it"
    );
    assert_eq!(forwarded.items[0].key, key);
    assert_eq!(
        forwarded.items[0].summary,
        Nullable::null(),
        "and a caller the host cannot narrow gets the record without the session's text"
    );
    assert!(
        mine.items[0].summary.is_present(),
        "while this user's own session tells them what it was about"
    );
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_review_acknowledgement_binds_a_version_and_a_later_one_reopens_the_work() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    observe(&host, 1, turn(host.session_id, 1));

    let params = ReviewReadParams {
        session_id: host.session_id,
        subject: Nullable::null(),
    };
    let state: ReviewReadResult =
        ok(send_request(&mut client, request(Method::ReviewRead, typed(&params))).await);
    assert_eq!(
        state.reviews.len(),
        2,
        "the turn and the change set it captured"
    );
    assert!(state.reviews.iter().all(|review| review.outstanding));

    let acknowledged: ReviewAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::ReviewAcknowledge,
            typed(&ReviewAcknowledgeParams {
                session_id: host.session_id,
                subject: turn_subject(host.session_id),
                version: U64::new(1),
            }),
        ),
    )
    .await);
    assert!(!acknowledged.review.outstanding);
    assert_eq!(
        acknowledged.review.acknowledged_version,
        Nullable::some(U64::new(1))
    );

    observe(&host, 2, turn(host.session_id, 2));
    let reopened: ReviewReadResult =
        ok(send_request(&mut client, request(Method::ReviewRead, typed(&params))).await);
    let turn_state = reopened
        .reviews
        .iter()
        .find(|review| matches!(review.subject, ReviewSubject::CompletedTurn { .. }))
        .expect("the turn is a subject");
    assert_eq!(turn_state.current_version, U64::new(2));
    assert!(turn_state.outstanding, "a new change is new review work");
}

#[tokio::test]
async fn a_review_acknowledgement_names_a_subject_and_a_version_this_session_holds() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);

    let unknown = send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::ReviewAcknowledge,
            typed(&ReviewAcknowledgeParams {
                session_id: host.session_id,
                subject: turn_subject(host.session_id),
                version: U64::new(1),
            }),
        ),
    )
    .await;
    let Outcome::Error(error) = unknown else {
        panic!("a subject this session never held cannot be acknowledged");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    observe(&host, 1, turn(host.session_id, 1));
    let ahead = send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::ReviewAcknowledge,
            typed(&ReviewAcknowledgeParams {
                session_id: host.session_id,
                subject: turn_subject(host.session_id),
                version: U64::new(2),
            }),
        ),
    )
    .await;
    let Outcome::Error(error) = ahead else {
        panic!("a version nobody produced cannot be acknowledged");
    };
    assert_eq!(error.code, ErrorCode::DraftConflict);
}

#[tokio::test]
async fn no_method_of_the_group_can_reach_a_right_that_changes_code() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    observe(&host, 1, turn(host.session_id, 1));

    // The registry is the contract: section 23 gives this row "no code mutation", and the rights
    // its entries ask for are the whole of what a caller has to present.
    for entry in REGISTRY
        .iter()
        .filter(|entry| entry.group == MethodGroup::ReviewAndAttention)
    {
        for right in entry.required_rights {
            let kr_protocol::authority::RequiredAuthority::Right { right } = right.authority else {
                continue;
            };
            assert!(
                !matches!(
                    right,
                    kr_protocol::rights::ActionRight::FilesApplyDiff
                        | kr_protocol::rights::ActionRight::ChangesetCreate
                        | kr_protocol::rights::ActionRight::TerminalInput
                        | kr_protocol::rights::ActionRight::AgentApprovalRespond
                ),
                "{} would let a review method change something",
                entry.name
            );
        }
    }

    // And acknowledging does not move the version the host holds, which is the state a promotion
    // would have moved.
    let params = ReviewReadParams {
        session_id: host.session_id,
        subject: Nullable::some(turn_subject(host.session_id)),
    };
    let before: ReviewReadResult =
        ok(send_request(&mut client, request(Method::ReviewRead, typed(&params))).await);
    let _: ReviewAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::ReviewAcknowledge,
            typed(&ReviewAcknowledgeParams {
                session_id: host.session_id,
                subject: turn_subject(host.session_id),
                version: U64::new(1),
            }),
        ),
    )
    .await);
    let after: ReviewReadResult =
        ok(send_request(&mut client, request(Method::ReviewRead, typed(&params))).await);
    assert_eq!(
        after.reviews[0].current_version, before.reviews[0].current_version,
        "what was reviewed is unchanged by the review"
    );
}

// ---------------------------------------------------------------------------------------------
// Visits
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_visit_records_a_cursor_and_the_views_it_had_open() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    observe(&host, 1, turn(host.session_id, 1));

    let changed: VisitChangedResult = ok(send_request(
        &mut client,
        request(
            Method::VisitChanged,
            typed(&VisitChangedParams {
                session_id: host.session_id,
                max_changes: U64::new(50),
            }),
        ),
    )
    .await);
    assert_eq!(changed.from_cursor, U64::new(0));
    assert_eq!(changed.changes.len(), 2);
    assert!(changed.views.is_empty());

    let visit: VisitAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::VisitAcknowledge,
            typed(&VisitAcknowledgeParams {
                session_id: host.session_id,
                acknowledged_cursor: changed.to_cursor,
                views: vec![LogViewState {
                    view_id: "build".to_owned(),
                    source_offset: U64::new(4_096),
                    filter: "level=error".to_owned(),
                }],
            }),
        ),
    )
    .await);
    assert_eq!(visit.acknowledged_cursor, changed.to_cursor);
    assert_eq!(visit.views.len(), 1);

    let after: VisitChangedResult = ok(send_request(
        &mut client,
        request(
            Method::VisitChanged,
            typed(&VisitChangedParams {
                session_id: host.session_id,
                max_changes: U64::new(50),
            }),
        ),
    )
    .await);
    assert!(after.changes.is_empty(), "everything has been seen");
    assert_eq!(after.views.len(), 1, "and the view came back with it");
    assert_eq!(after.views[0].view.filter, "level=error");
}

// ---------------------------------------------------------------------------------------------
// The retained sources the worker reads from
// ---------------------------------------------------------------------------------------------

fn verified_source(session_member: bool) -> kr_worker::questions::VerifiedSource {
    kr_worker::questions::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("/bin/agent".to_owned()),
        session_member,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(kr_ipc::new_uuid()),
    }
}

fn question_params(host: &Host, request: &str) -> kr_protocol::question::QuestionCreateParams {
    kr_protocol::question::QuestionCreateParams {
        session_id: host.session_id,
        request_id: request.to_owned(),
        agent_name: Nullable::some("an agent".to_owned()),
        context: "two ways to do it".to_owned(),
        question: "which branch?".to_owned(),
        kind: kr_protocol::question::QuestionKind::Confirm,
        choices: Vec::new(),
        requested_expiry_ms: Nullable::null(),
        wait_ms: Nullable::null(),
    }
}

#[tokio::test]
async fn a_question_in_the_ledger_becomes_pending_input_when_the_host_reads_its_sources() {
    let host = host().await;
    let mut client = cli(&host).await;
    let now = kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    };
    let (created, _) = host
        .service
        .questions()
        .create(&verified_source(true), &question_params(&host, "r-1"), now)
        .expect("a verified source creates a question");

    // Nothing has read the sources yet.
    let before: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    assert!(before.items.is_empty());

    host.service.attention_pass();
    let after: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    let item = after
        .items
        .iter()
        .find(|item| item.rule == AttentionRule::PendingInput)
        .expect("the waiting question is in the inbox");
    assert!(item.trusted);
    assert!(
        item.key
            .as_str()
            .contains(&created.question.question_id.to_string()),
        "and it is keyed on the question it is about"
    );

    // Answering it takes it out again.
    host.service
        .questions()
        .answer(
            &ActorId::new("local:501").expect("a principal"),
            None,
            &kr_protocol::question::QuestionAnswerParams {
                session_id: host.session_id,
                question_id: created.question.question_id,
                expected_revision: created.question.revision,
                answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
            },
            now,
        )
        .expect("a person answers it");
    host.service.attention_pass();
    let resolved: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    assert!(
        !resolved
            .items
            .iter()
            .any(|item| item.rule == AttentionRule::PendingInput),
        "nothing is waiting any more"
    );
}

#[tokio::test]
async fn a_notification_with_no_attachment_to_go_to_becomes_an_untrusted_notice() {
    let host = host().await;
    let mut client = cli(&host).await;
    {
        let mut session = host.service.runtime().session();
        let journal = session
            .journal_mut()
            .expect("the harness journals its session");
        journal
            .record_host_event(
                &kr_term::sideeffect::SideEffect {
                    kind: kr_term::sideeffect::SideEffectKind::Notification {
                        title: Some("build".to_owned()),
                        body: "finished".to_owned(),
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
    host.service.attention_pass();
    let read: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    let item = read
        .items
        .iter()
        .find(|item| item.rule == AttentionRule::ApplicationNotice)
        .expect("the notice is retained in Attention");
    assert!(!item.trusted, "any process can print one");
    assert_eq!(
        item.summary.as_ref().map(String::as_str),
        Some("Normal: build - finished"),
        "and this user's own session is told what it said"
    );
    assert_eq!(
        item.routing,
        kr_protocol::attention::AttentionRouting::OwnerPolicy,
        "with no lease holder it goes through the owner's notification policy"
    );
    assert!(
        !read
            .items
            .iter()
            .any(|item| item.rule == AttentionRule::PendingApproval),
        "and it is never an approval"
    );
}

#[tokio::test]
async fn a_refusal_this_host_can_decide_rejects_the_action_rather_than_leaving_it_unknown() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    let refused = mutation(
        &window,
        &host,
        Method::ReviewAcknowledge,
        typed(&ReviewAcknowledgeParams {
            session_id: host.session_id,
            subject: turn_subject(host.session_id),
            version: U64::new(1),
        }),
    );
    let action_id = refused.action_id;
    let answer = send_mutation(&mut client, refused).await;
    let Outcome::Error(error) = answer else {
        panic!("a subject this session never held cannot be acknowledged");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let read: kr_protocol::receipt::ActionReadResult = ok(send_request(
        &mut client,
        request(
            Method::ActionRead,
            typed(&kr_protocol::receipt::ActionReadParams { action_id }),
        ),
    )
    .await);
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Rejected,
        "a refusal this host decided is a rejection, not an outcome nobody can establish"
    );
}

// ---------------------------------------------------------------------------------------------
// The feature store
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_state_lives_in_the_session_s_journal_and_comes_back_from_it() {
    let host = host().await;
    let mut client = cli(&host).await;
    let window = window(&client);
    observe(&host, 1, approval("req-1"));
    let raised: AttentionReadResult = ok(send_request(
        &mut client,
        request(Method::AttentionRead, typed(&read_params(&host))),
    )
    .await);
    let key: AttentionKey = raised.items[0].key.clone();
    let acknowledged: AttentionAcknowledgeResult = ok(send_mutation(
        &mut client,
        mutation(
            &window,
            &host,
            Method::AttentionAcknowledge,
            typed(&AttentionAcknowledgeParams {
                session_id: host.session_id,
                keys: vec![key.clone()],
            }),
        ),
    )
    .await);
    let actor = acknowledged.actor_id;

    // What a restarted worker would read: the same file, opened again.
    let reading = kr_worker::attention::reading(host.service.runtime().session().time());
    let restored = kr_attention::Attention::beside(Some(&host.journal_path), reading)
        .expect("the feature store reopens");
    let items = restored.inbox(&actor, true, kr_attention::Content::Whole);
    assert_eq!(items.len(), 1, "the item is where the journal kept it");
    assert_eq!(items[0].key, key);
    assert!(items[0].acknowledged, "and so is the acknowledgement");
    assert_eq!(
        restored.engine().consumed(AttentionSource::Receipts),
        Some(1),
        "and the consumed cursor, so a replay is still idempotent"
    );
}
