//! A voice start whose hold stands until the start's claim is settled and its deferred call is
//! resolved.
//!
//! The hold a start writes before the managed service is asked ends when the start's effect says
//! that no call of it can still be running unreconciled, and the claim the start answers under has
//! settled, in either order. These cases run starts through the daemon with a service that answers
//! as a script says, one start at a time or held until the case lets it go.

use std::collections::VecDeque;
use std::sync::Arc;

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceMetadata, VoiceRateQuote, VoiceRefusal,
    VoiceRefusalReason, VoiceSession, VoiceSessionRequest, VoiceStart, VoiceStartLatency,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActorId, DeviceId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::voice::{VoiceGrantParams, VoicePrepareParams, VoiceStartParams};

use super::a_close_a_worker_never_answers::Silent;
use super::a_delegation_that_is_asked_again::{
    admitted_for_five_minutes, submitted_under, voice_mutation_of,
};
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, restarted, scripted};
use super::a_voice_grant_on_the_floor::paired;
use crate::service::Controller;

/// What the scripted service answers one start with.
enum Answer {
    /// The service refuses the start once `gate` says so: nothing was created.
    Refuses {
        gate: Option<tokio::sync::oneshot::Receiver<()>>,
    },
    /// The service fails with `code`, as it does when it cannot say what became of the start.
    Fails(ErrorCode),
    /// The service fails with `code` once `gate` says so.
    FailsAfter(ErrorCode, tokio::sync::oneshot::Receiver<()>),
    /// The service answers with the call `call`, once `gate` says so, as the call an earlier
    /// attempt made when `replayed`.
    Call {
        call: &'static str,
        replayed: bool,
        gate: Option<tokio::sync::oneshot::Receiver<()>>,
    },
}

/// A managed service that answers each start as the script says, in the order the starts reach it.
struct ServiceScript {
    answers: std::sync::Mutex<VecDeque<Answer>>,
    /// One permit for each start that has reached the service.
    arrived: tokio::sync::Semaphore,
    closes: std::sync::Mutex<Vec<String>>,
    close_works: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for ServiceScript {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceScript")
            .finish_non_exhaustive()
    }
}

impl ServiceScript {
    fn new(answers: Vec<Answer>, close_works: bool) -> Arc<Self> {
        Arc::new(Self {
            answers: std::sync::Mutex::new(answers.into()),
            arrived: tokio::sync::Semaphore::new(0),
            closes: std::sync::Mutex::new(Vec::new()),
            close_works: std::sync::atomic::AtomicBool::new(close_works),
        })
    }

    /// Waits until one more start has reached the service.
    async fn a_start_arrives(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(30), self.arrived.acquire())
            .await
            .expect("a start reaches the service")
            .expect("the gate stays open")
            .forget();
    }

    /// The calls the service was asked to close, in order.
    fn closes(&self) -> Vec<String> {
        self.closes.lock().expect("the closes").clone()
    }
}

fn session_of(call: &str, replayed: bool) -> VoiceSession {
    VoiceSession {
        call_id: call.to_owned(),
        attempt_id: "attempt-1".to_owned(),
        provider_session_id: "sess_1".to_owned(),
        answer_sdp: "v=0\r\n".to_owned(),
        model: "gpt-live-1".to_owned(),
        closes_at: "2026-09-20T01:00:00Z".to_owned(),
        reservation_ends_at: "2026-09-20T01:00:15Z".to_owned(),
        control_path: format!("/api/voice/sessions/{call}/control"),
        heartbeat_seconds: 20,
        sideband_ready: true,
        hold: VoiceHold {
            reservation_id: "hold-1".to_owned(),
            reserved: "600".to_owned(),
            ceiling: "500".to_owned(),
            deadline: "2026-09-20T01:00:15Z".to_owned(),
        },
        reasoning_hold: None,
        rate: VoiceRateQuote {
            version: "2026-09".to_owned(),
            minor_units_per_second: "1".to_owned(),
            minimum_seconds: 15,
            currency: "USD".to_owned(),
        },
        latency: VoiceStartLatency {
            creation_to_answer_ms: 10,
            sideband_ready_ms: 5,
        },
        replayed,
        disclosure: Vec::new(),
    }
}

impl ManagedVoiceService for ServiceScript {
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        Box::pin(async move { Ok(None) })
    }

    fn call_is_open<'a>(&'a self, _call_id: &'a str) -> ServiceFuture<'a, bool> {
        Box::pin(async move { Ok(true) })
    }

    fn provider(&self) -> String {
        "the scripted service".to_owned()
    }

    fn start<'a>(&'a self, _request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            let answer = self
                .answers
                .lock()
                .expect("the script")
                .pop_front()
                .expect("a start the script answers");
            self.arrived.add_permits(1);
            match answer {
                Answer::Refuses { gate } => {
                    if let Some(gate) = gate {
                        let _ = gate.await;
                    }
                    Ok(VoiceStart::Refused(Box::new(VoiceRefusal {
                        reason: VoiceRefusalReason::ServiceCapacity,
                        message: "Managed capacity is spent.".to_owned(),
                        alternatives: Vec::new(),
                        attempt_id: None,
                        call_id: None,
                    })))
                }
                Answer::Fails(code) => Err(kr_client::error::ClientError::refusal(
                    code,
                    "the service could not say what became of the start".into(),
                )),
                Answer::FailsAfter(code, gate) => {
                    let _ = gate.await;
                    Err(kr_client::error::ClientError::refusal(
                        code,
                        "the service could not say what became of the start".into(),
                    ))
                }
                Answer::Call {
                    call,
                    replayed,
                    gate,
                } => {
                    if let Some(gate) = gate {
                        let _ = gate.await;
                    }
                    Ok(VoiceStart::Started(Box::new(session_of(call, replayed))))
                }
            }
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        let call_id = call_id.to_owned();
        Box::pin(async move {
            self.closes
                .lock()
                .expect("the closes")
                .push(call_id.clone());
            if !self.close_works.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(kr_client::error::ClientError::refusal(
                    ErrorCode::UpstreamUnavailable,
                    "the service cannot be reached".into(),
                ));
            }
            Ok(VoiceClosure {
                call_id,
                state: "finalised".to_owned(),
                usage_seconds: 0,
                usage_provisional: true,
            })
        })
    }
}

/// A standing voice grant for `device_id` over `session_id`, and the start it can make now.
async fn ready(
    controller: &Arc<Controller>,
    device_id: DeviceId,
    session_id: SessionId,
) -> VoiceStartParams {
    let coordinator = controller.voice().coordinator();
    coordinator
        .grant(
            &VoiceGrantParams {
                device_id,
                session_ids: [session_id].into_iter().collect(),
                actions: Nullable::null(),
            },
            controller.policy().authority_revision(),
            kr_ipc::now_ms().get(),
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let prepared = coordinator
        .prepare(
            device_id,
            &VoicePrepareParams {
                session_ids: [session_id].into_iter().collect(),
                selected: CanonicalSet::from_iter([]),
            },
        )
        .await
        .expect("a preparation")
        .prepared;
    VoiceStartParams {
        session_ids: [session_id].into_iter().collect(),
        offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
        duration_seconds: 600,
        reasoning_budget_minor: Nullable::null(),
        prepared,
        expected_rate_version: Nullable::some("2026-09".to_owned()),
    }
}

/// A start of `params` by the device `device_id`, run on a task of its own.
fn starting(
    controller: &Arc<Controller>,
    environment_id: kr_protocol::ids::EnvironmentId,
    actor_id: ActorId,
    device_id: DeviceId,
    params: &VoiceStartParams,
) -> tokio::task::JoinHandle<
    crate::given::Given<crate::error::Result<kr_protocol::envelope::ParamsValue>>,
> {
    let mutation = voice_mutation_of(Method::VoiceStart, environment_id, params);
    starting_under(controller, actor_id, device_id, mutation)
}

/// The start `mutation` by the device `device_id`, run on a task of its own: a repeat of an action
/// sends the same request again.
fn starting_under(
    controller: &Arc<Controller>,
    actor_id: ActorId,
    device_id: DeviceId,
    mutation: kr_protocol::envelope::MutationRequest,
) -> tokio::task::JoinHandle<
    crate::given::Given<crate::error::Result<kr_protocol::envelope::ParamsValue>>,
> {
    let controller = Arc::clone(controller);
    tokio::spawn(async move {
        let carried = admitted_for_five_minutes(&controller).await;
        submitted_under(
            &controller,
            &actor_id,
            device_id,
            Method::VoiceStart,
            &mutation,
            carried,
        )
        .await
    })
}

fn hold_of(controller: &Controller, actor_id: &ActorId) -> Option<crate::voice_start_holds::Row> {
    controller
        .voice_start_holds
        .standing(actor_id.clone())
        .expect("the record reads")
}

/// The start `mutation` by the device `device_id`, run on a task of its own under the admission
/// `carried`, which the case keeps a handle on.
fn starting_carried(
    controller: &Arc<Controller>,
    actor_id: ActorId,
    device_id: DeviceId,
    mutation: kr_protocol::envelope::MutationRequest,
    carried: crate::authority::AdmittedMutation,
) -> tokio::task::JoinHandle<
    crate::given::Given<crate::error::Result<kr_protocol::envelope::ParamsValue>>,
> {
    let controller = Arc::clone(controller);
    tokio::spawn(async move {
        submitted_under(
            &controller,
            &actor_id,
            device_id,
            Method::VoiceStart,
            &mutation,
            carried,
        )
        .await
    })
}

/// `mutation` with the start it replaces named in its preconditions.
fn naming(
    mut mutation: kr_protocol::envelope::MutationRequest,
    earlier: kr_protocol::ids::ActionId,
) -> kr_protocol::envelope::MutationRequest {
    mutation.expected = kr_protocol::envelope::ParamsValue::from_typed(
        &std::collections::BTreeMap::from([(kr_protocol::action::SUPERSEDES_ACTION_KEY, earlier)]),
    )
    .expect("encodes");
    mutation
}

/// A world whose service answers as `answers` say, with one device paired and ready to start.
async fn with_service(
    answers: Vec<Answer>,
    close_works: bool,
    seed: u8,
) -> (
    Silent,
    Arc<ServiceScript>,
    DeviceId,
    ActorId,
    VoiceStartParams,
) {
    let world = scripted(&Scripted::new()).await;
    let service = ServiceScript::new(answers, close_works);
    world
        .controller
        .voice()
        .attach_provider(Some(Arc::clone(&service) as Arc<dyn ManagedVoiceService>));
    let device = paired(&world.controller, seed, None);
    let params = ready(&world.controller, device.device_id, world.session_id).await;
    (world, service, device.device_id, device.principal(), params)
}

/// The registry, held by another writer: the grant store waits no time for it, so what the
/// daemon writes there fails until [`let_the_registry_go`] runs.
fn hold_the_registry(world: &Silent) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(world._temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    world
        .controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::ZERO)
        .expect("the store waits no time for another writer");
    registry
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the store");
    registry
}

fn let_the_registry_go(world: &Silent, registry: &rusqlite::Connection) {
    registry
        .execute_batch("ROLLBACK")
        .expect("the other writer lets the store go");
    world
        .controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::from_secs(5))
        .expect("the store waits as it does");
}

/// A connection to the record of holds, beside the daemon's own.
fn the_record_of_holds(world: &Silent) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(
        world
            ._temp
            .environment()
            .state_dir()
            .join(crate::voice_start_holds::VOICE_START_HOLDS_RECORD),
    )
    .expect("the record opens beside the daemon's own handle");
    connection
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    connection
}

/// KR-REQ-23.24: a start whose answer this host could not keep leaves its hold standing, whatever
/// its effect said. The service refused the start and nothing was created, so the effect ends the
/// row; the claim that could not settle keeps it, and the device's next start, which names no
/// earlier one, is refused in the hold's words without asking the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_whose_answer_could_not_be_kept_leaves_its_hold_standing() {
    let world = scripted(&Scripted::new()).await;
    let controller = Arc::clone(&world.controller);
    let (let_it_answer, gate) = tokio::sync::oneshot::channel();
    let service = ServiceScript::new(vec![Answer::Refuses { gate: Some(gate) }], true);
    controller
        .voice()
        .attach_provider(Some(Arc::clone(&service) as Arc<dyn ManagedVoiceService>));
    let device = paired(&controller, 61, None);
    let actor_id = device.principal();
    let params = ready(&controller, device.device_id, world.session_id).await;
    let registry = rusqlite::Connection::open(world._temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");

    // The start is at the service, and its claim is not settled while the service has not answered.
    let making = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    );
    service.a_start_arrives().await;
    assert!(
        hold_of(&controller, &actor_id).is_some(),
        "the claim has not settled, so the row stands"
    );
    // Another writer holds the store, and the claim's answer cannot be written.
    controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::ZERO)
        .expect("the store waits no time for another writer");
    registry
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the store");
    let _ = let_it_answer.send(());
    let given = making.await.expect("the start ran");
    registry
        .execute_batch("ROLLBACK")
        .expect("the other writer lets the store go");
    controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::from_secs(5))
        .expect("the store waits as it does");

    let unkept = given
        .into_answer_for_test()
        .expect_err("an answer that could not be kept is not told as given");
    assert!(
        matches!(unkept, crate::error::ControllerError::Uncertain { .. }),
        "{unkept}"
    );
    let Some(standing) = hold_of(&controller, &actor_id) else {
        panic!("the row stands after the failed claim");
    };

    let again = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    )
    .await
    .expect("the next start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(again.code(), ErrorCode::DraftConflict, "{again}");
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "the held device's next start did not reach the service"
    );
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        Some(standing.action),
        "the refused start wrote nothing"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a start whose call another start may be about to bind keeps its hold while the
/// call is deferred. The hold ends when the call is resolved: once when it is closed and the
/// service confirms the close, and not when it is not, and without a close when a live session
/// holds the call. One close resolves every start that deferred the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_defers_a_call_keeps_its_hold_until_the_call_is_resolved() {
    // The second start's answer, whether the service confirms a close, whether the first start's
    // hold remains, whether the second start's hold remains, and how many closes were asked.
    for (second_replays, close_works, first_remains, second_remains, closes) in [
        (true, true, false, false, 1_usize),
        (true, false, true, true, 1),
        (false, true, false, false, 0),
    ] {
        let world = scripted(&Scripted::new()).await;
        let controller = Arc::clone(&world.controller);
        let (let_first_go, first_gate) = tokio::sync::oneshot::channel();
        let (let_second_go, second_gate) = tokio::sync::oneshot::channel();
        let service = ServiceScript::new(
            vec![
                Answer::Call {
                    call: "call-9",
                    replayed: true,
                    gate: Some(first_gate),
                },
                Answer::Call {
                    call: "call-9",
                    replayed: second_replays,
                    gate: Some(second_gate),
                },
            ],
            close_works,
        );
        controller
            .voice()
            .attach_provider(Some(Arc::clone(&service) as Arc<dyn ManagedVoiceService>));
        let first = paired(&controller, 71, None);
        let second = paired(&controller, 72, None);
        let first_params = ready(&controller, first.device_id, world.session_id).await;
        let second_params = ready(&controller, second.device_id, world.session_id).await;
        let label = format!("second replays {second_replays}, close works {close_works}");

        let first_start = starting(
            &controller,
            world.environment_id,
            first.principal(),
            first.device_id,
            &first_params,
        );
        service.a_start_arrives().await;
        let second_start = starting(
            &controller,
            world.environment_id,
            second.principal(),
            second.device_id,
            &second_params,
        );
        service.a_start_arrives().await;

        // The first start is answered with a call that the second may be about to bind.
        let _ = let_first_go.send(());
        let _ = first_start.await.expect("the first start ran");
        assert!(
            hold_of(&controller, &first.principal()).is_some(),
            "{label}: the deferred call keeps the first start's hold"
        );
        assert_eq!(
            service.closes(),
            Vec::<String>::new(),
            "{label}: nothing is closed yet"
        );

        let _ = let_second_go.send(());
        let _ = second_start.await.expect("the second start ran");
        assert_eq!(
            hold_of(&controller, &first.principal()).is_some(),
            first_remains,
            "{label}: the first start's hold"
        );
        assert_eq!(
            hold_of(&controller, &second.principal()).is_some(),
            second_remains,
            "{label}: the second start's hold"
        );
        let asked = service.closes();
        assert_eq!(asked.len(), closes, "{label}: closes asked {asked:?}");
        assert!(
            asked.iter().all(|call| call == "call-9"),
            "{label}: {asked:?}"
        );
        world.serving.abort();
    }
}

/// KR-REQ-23.24: a start that reaches the service after a later start of its device has passed
/// and finished still leaves its hold when the service cannot say what became of it. The device's
/// next unnamed start is refused in the first start's words, and the service is not asked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_comes_late_after_another_start_passed_leaves_its_hold_standing() {
    let world = scripted(&Scripted::new()).await;
    let controller = Arc::clone(&world.controller);
    // The service answers in the order the starts reach it: the later start's call first.
    let service = ServiceScript::new(
        vec![
            Answer::Call {
                call: "call-b",
                replayed: false,
                gate: None,
            },
            Answer::Fails(ErrorCode::OutcomeUnknown),
        ],
        true,
    );
    controller
        .voice()
        .attach_provider(Some(Arc::clone(&service) as Arc<dyn ManagedVoiceService>));
    let device = paired(&controller, 62, None);
    let actor_id = device.principal();
    let params = ready(&controller, device.device_id, world.session_id).await;

    // The first start stops before it claims its action, so it has written nothing yet.
    let (arrived, go) = controller.before_a_voice_change_claims.arm();
    let first = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    );
    arrived
        .await
        .expect("the first start stops before its claim");

    // A second start of the device passes, is answered with its call and finishes.
    let second = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    )
    .await
    .expect("the second start ran")
    .into_answer_for_test();
    assert!(second.is_ok(), "{second:?}");
    service.a_start_arrives().await;
    assert!(
        hold_of(&controller, &actor_id).is_none(),
        "the second start's row ended with its bound call"
    );

    // The first start goes on, reaches the service, and the service cannot say what became of it.
    let _ = go.send(());
    let unknown = first
        .await
        .expect("the first start ran")
        .into_answer_for_test();
    assert!(unknown.is_err(), "{unknown:?}");
    service.a_start_arrives().await;
    let Some(standing) = hold_of(&controller, &actor_id) else {
        panic!("the first start's row stands after the service could not say what became of it");
    };

    let third = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    )
    .await
    .expect("the third start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(third.code(), ErrorCode::DraftConflict, "{third}");
    assert!(
        third.to_string().contains(&standing.action.to_string()),
        "the refusal names the first start's action: {third}"
    );
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "the service was asked twice and not for the third start"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a start the hold refused, sent again under the same action, is told the same
/// refusal and asks the service nothing: the refusal is the action's answer, whether the device
/// asks once or twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_the_hold_refused_is_told_the_same_refusal_when_it_is_sent_again() {
    let world = scripted(&Scripted::new()).await;
    let controller = Arc::clone(&world.controller);
    let service = ServiceScript::new(vec![Answer::Fails(ErrorCode::OutcomeUnknown)], true);
    controller
        .voice()
        .attach_provider(Some(Arc::clone(&service) as Arc<dyn ManagedVoiceService>));
    let device = paired(&controller, 63, None);
    let actor_id = device.principal();
    let params = ready(&controller, device.device_id, world.session_id).await;

    // The first start leaves the hold: the service could not say what became of it.
    let first = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    )
    .await
    .expect("the first start ran")
    .into_answer_for_test();
    assert!(first.is_err(), "{first:?}");
    service.a_start_arrives().await;
    assert!(hold_of(&controller, &actor_id).is_some());

    // A second start is refused for the hold, and sent again under its action it is told the same.
    let mutation = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let refused = starting_under(
        &controller,
        actor_id.clone(),
        device.device_id,
        mutation.clone(),
    )
    .await
    .expect("the second start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(refused.code(), ErrorCode::DraftConflict, "{refused}");
    let repeated = starting_under(&controller, actor_id.clone(), device.device_id, mutation)
        .await
        .expect("the repeat ran")
        .into_answer_for_test()
        .expect_err("the repeat is refused as the first send was");
    assert_eq!(repeated.code(), refused.code(), "{repeated}");
    assert_eq!(repeated.to_string(), refused.to_string());
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "neither the refused start nor its repeat reached the service"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a start whose task is dropped while the service holds its request leaves the
/// device held: the claim is unfinished, a repeat of the action is told it cannot be said what
/// came of it, and a fresh start is refused in the hold's words without asking the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_whose_task_is_dropped_holds_the_device() {
    let (keep_waiting, gate) = tokio::sync::oneshot::channel();
    let (world, service, device_id, actor_id, params) = with_service(
        vec![Answer::Call {
            call: "call-1",
            replayed: false,
            gate: Some(gate),
        }],
        true,
        64,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let mutation = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let making = starting_under(&controller, actor_id.clone(), device_id, mutation.clone());
    service.a_start_arrives().await;
    making.abort();
    assert!(
        making
            .await
            .expect_err("the task was dropped")
            .is_cancelled()
    );

    let repeated = starting_under(&controller, actor_id.clone(), device_id, mutation.clone())
        .await
        .expect("the repeat ran")
        .into_answer_for_test()
        .expect_err("the repeat of an unfinished start is not answered as done");
    assert!(
        matches!(repeated, crate::error::ControllerError::Uncertain { .. }),
        "{repeated}"
    );
    let fresh = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the fresh start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(fresh.code(), ErrorCode::DraftConflict, "{fresh}");
    assert_eq!(service.arrived.available_permits(), 0);
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        Some(mutation.action_id)
    );
    drop(keep_waiting);
    world.serving.abort();
}

/// KR-REQ-23.24: the hold is written before the service answers, so it survives a restart of the
/// daemon over the same state: the fresh daemon refuses a start that names nothing in the hold's
/// words and does not ask the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_keeps_a_hold_written_before_the_answer() {
    let (keep_waiting, gate) = tokio::sync::oneshot::channel();
    let (world, service, device_id, actor_id, params) = with_service(
        vec![Answer::Call {
            call: "call-1",
            replayed: false,
            gate: Some(gate),
        }],
        true,
        65,
    )
    .await;
    let mutation = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let making = starting_under(
        &world.controller,
        actor_id.clone(),
        device_id,
        mutation.clone(),
    );
    service.a_start_arrives().await;
    making.abort();
    let _ = making.await;
    drop(keep_waiting);

    let world = restarted(world).await;
    let controller = Arc::clone(&world.controller);
    let after = ServiceScript::new(Vec::new(), true);
    controller
        .voice()
        .attach_provider(Some(Arc::clone(&after) as Arc<dyn ManagedVoiceService>));
    let params = ready(&controller, device_id, world.session_id).await;
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        Some(mutation.action_id),
        "the row written before any answer survives the restart"
    );
    let refused = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(refused.code(), ErrorCode::DraftConflict, "{refused}");
    assert_eq!(after.arrived.available_permits(), 0);
    world.serving.abort();
}

/// A start whose admission ends after the service answered with a call: the host closes the call,
/// and its hold ends only when that close is confirmed.
async fn the_admission_ends_after_the_service_answered(close_works: bool, seed: u8) {
    let (let_it_answer, gate) = tokio::sync::oneshot::channel();
    let (world, service, device_id, actor_id, params) = with_service(
        vec![
            Answer::Call {
                call: "call-1",
                replayed: false,
                gate: Some(gate),
            },
            Answer::Call {
                call: "call-2",
                replayed: false,
                gate: None,
            },
        ],
        close_works,
        seed,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let mutation = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let carried = admitted_for_five_minutes(&controller).await;
    let connection = carried.connection_id;
    let making = starting_carried(
        &controller,
        actor_id.clone(),
        device_id,
        mutation.clone(),
        carried,
    );
    service.a_start_arrives().await;
    controller.deregister(connection);
    let _ = let_it_answer.send(());
    let ended = making
        .await
        .expect("the start ran")
        .into_answer_for_test()
        .expect_err("a start whose admission ended is not given its answer");
    assert_eq!(
        service.closes(),
        vec!["call-1".to_owned()],
        "the host asked the service to close the call it made: {ended}"
    );
    if close_works {
        assert!(
            hold_of(&controller, &actor_id).is_none(),
            "the close was confirmed, so the hold ends"
        );
        let answered = starting(
            &controller,
            world.environment_id,
            actor_id.clone(),
            device_id,
            &params,
        )
        .await
        .expect("the next start ran")
        .into_answer_for_test();
        let Ok(_) = answered else {
            panic!("the device is not held: {answered:?}");
        };
        assert_eq!(service.arrived.available_permits(), 1);
    } else {
        assert_eq!(
            hold_of(&controller, &actor_id).map(|row| row.action),
            Some(mutation.action_id),
            "the close was not confirmed, so the hold stands"
        );
        let held = starting(
            &controller,
            world.environment_id,
            actor_id.clone(),
            device_id,
            &params,
        )
        .await
        .expect("the next start ran")
        .into_answer_for_test()
        .expect_err("the device is held");
        assert_eq!(held.code(), ErrorCode::DraftConflict, "{held}");
        assert_eq!(service.arrived.available_permits(), 0);
    }
    world.serving.abort();
}

/// KR-REQ-23.24: a call the host closed after its admission ended leaves no hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_closed_after_an_admission_ended_leaves_no_hold() {
    the_admission_ends_after_the_service_answered(true, 66).await;
}

/// KR-REQ-23.24: a call the host could not confirm closed after its admission ended holds the
/// device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_not_closed_after_an_admission_ended_holds_the_device() {
    the_admission_ends_after_the_service_answered(false, 67).await;
}

/// KR-REQ-23.24: a refusal that this host cannot record is the caller's answer all the same, and
/// the start's hold ends: the claim settles without a record of the refusal, and the next start
/// that names nothing is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_that_cannot_be_recorded_still_ends_the_hold() {
    let (let_it_answer, gate) = tokio::sync::oneshot::channel();
    let (world, service, device_id, actor_id, params) = with_service(
        vec![
            Answer::FailsAfter(ErrorCode::PermissionDenied, gate),
            Answer::Call {
                call: "call-1",
                replayed: false,
                gate: None,
            },
        ],
        true,
        68,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let making = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    );
    service.a_start_arrives().await;
    let registry = hold_the_registry(&world);
    let _ = let_it_answer.send(());
    let given = making.await.expect("the start ran");
    let_the_registry_go(&world, &registry);
    let refused = given
        .into_answer_for_test()
        .expect_err("the refusal is the answer");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        hold_of(&controller, &actor_id).is_none(),
        "a refusal that left no call ends the hold, recorded or not"
    );
    let answered = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the next start ran")
    .into_answer_for_test();
    let Ok(_) = answered else {
        panic!("the device is not held: {answered:?}");
    };
    assert_eq!(service.arrived.available_permits(), 1);
    world.serving.abort();
}

/// KR-REQ-23.24: a delete that fails keeps the hold, a start that names nothing is refused for
/// it, and a start that names the held one is admitted and ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_that_fails_keeps_the_hold_and_a_named_start_ends_it() {
    let (world, service, device_id, actor_id, params) = with_service(
        vec![
            Answer::Fails(ErrorCode::PermissionDenied),
            Answer::Call {
                call: "call-1",
                replayed: false,
                gate: None,
            },
        ],
        true,
        69,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let record = the_record_of_holds(&world);
    record
        .execute_batch(
            "CREATE TRIGGER keeps_the_row BEFORE DELETE ON voice_start_holds
             BEGIN SELECT RAISE(ABORT, 'the row stays'); END",
        )
        .expect("the store refuses a delete");
    let first = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let first_action = first.action_id;
    starting_under(&controller, actor_id.clone(), device_id, first)
        .await
        .expect("the first start ran")
        .into_answer_for_test()
        .expect_err("the service refused the start");
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        Some(first_action),
        "the delete failed, so the row stands"
    );
    let held = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the unnamed start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(held.code(), ErrorCode::DraftConflict, "{held}");
    service.a_start_arrives().await;
    assert_eq!(service.arrived.available_permits(), 0);

    record
        .execute_batch("DROP TRIGGER keeps_the_row")
        .expect("the store deletes again");
    let named = naming(
        voice_mutation_of(Method::VoiceStart, world.environment_id, &params),
        first_action,
    );
    let answered = starting_under(&controller, actor_id.clone(), device_id, named)
        .await
        .expect("the named start ran")
        .into_answer_for_test();
    let Ok(_) = answered else {
        panic!("a start that names the held one is admitted: {answered:?}");
    };
    assert_eq!(service.arrived.available_permits(), 1);
    assert!(
        hold_of(&controller, &actor_id).is_none(),
        "the named start replaced the row and its own effect ended it"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a start that meets another start's gate on the same device asks nothing and ends
/// nothing: the row of the start in flight stands, and ends when that start does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attempt_that_meets_the_start_gate_ends_nothing() {
    let (let_it_answer, gate) = tokio::sync::oneshot::channel();
    let (world, service, device_id, actor_id, params) = with_service(
        vec![Answer::Call {
            call: "call-1",
            replayed: false,
            gate: Some(gate),
        }],
        true,
        70,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let first = voice_mutation_of(Method::VoiceStart, world.environment_id, &params);
    let first_action = first.action_id;
    let making = starting_under(&controller, actor_id.clone(), device_id, first);
    service.a_start_arrives().await;
    let _ = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the second start ran");
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "the service was asked once"
    );
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        Some(first_action),
        "the start that met the gate ended nothing"
    );
    let _ = let_it_answer.send(());
    making
        .await
        .expect("the first start ran")
        .into_answer_for_test()
        .expect("the first start is answered");
    assert!(
        hold_of(&controller, &actor_id).is_none(),
        "the start in flight ends its own row"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: another device is not held by a device's hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_device_is_not_held() {
    let (world, service, device_id, actor_id, params) = with_service(
        vec![
            Answer::Fails(ErrorCode::OutcomeUnknown),
            Answer::Call {
                call: "call-1",
                replayed: false,
                gate: None,
            },
        ],
        true,
        71,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let other = paired(&controller, 72, None);
    let other_params = ready(&controller, other.device_id, world.session_id).await;
    let first = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &params,
    )
    .await
    .expect("the first start ran")
    .into_answer_for_test();
    assert!(first.is_err(), "{first:?}");
    service.a_start_arrives().await;
    let held = hold_of(&controller, &actor_id).map(|row| row.action);
    assert!(held.is_some());
    let answered = starting(
        &controller,
        world.environment_id,
        other.principal(),
        other.device_id,
        &other_params,
    )
    .await
    .expect("the other device's start ran")
    .into_answer_for_test();
    let Ok(_) = answered else {
        panic!("the other device is not held: {answered:?}");
    };
    assert_eq!(service.arrived.available_permits(), 1);
    assert!(hold_of(&controller, &other.principal()).is_none());
    assert_eq!(
        hold_of(&controller, &actor_id).map(|row| row.action),
        held,
        "the first device's hold is as it was"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a start that fails before the service is asked leaves no hold and asks the
/// service nothing: a changed preparation, and a device that holds no voice grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_before_the_broker_leaves_no_hold() {
    let (world, service, device_id, actor_id, params) = with_service(Vec::new(), true, 73).await;
    let controller = Arc::clone(&world.controller);
    let changed = VoiceStartParams {
        prepared: kr_protocol::scalars::Digest256::from_bytes([9; 32]),
        ..params.clone()
    };
    let _ = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device_id,
        &changed,
    )
    .await
    .expect("the start ran")
    .into_answer_for_test();
    assert!(
        hold_of(&controller, &actor_id).is_none(),
        "a changed preparation writes no hold"
    );
    let stranger = paired(&controller, 74, None);
    let _ = starting(
        &controller,
        world.environment_id,
        stranger.principal(),
        stranger.device_id,
        &params,
    )
    .await
    .expect("the start ran")
    .into_answer_for_test();
    assert!(
        hold_of(&controller, &stranger.principal()).is_none(),
        "a device with no voice grant writes no hold"
    );
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "the service was never asked"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: a deferred call whose close the service does not confirm, after the other start
/// refused with nothing bound, keeps the deferring start's hold: the device's next unnamed start is
/// refused and asks the service nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_close_that_fails_after_the_other_start_refuses_holds_the_device() {
    let (let_first_go, first_gate) = tokio::sync::oneshot::channel();
    let (let_second_go, second_gate) = tokio::sync::oneshot::channel();
    let (world, service, first_id, first_actor, first_params) = with_service(
        vec![
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(first_gate),
            },
            Answer::Refuses {
                gate: Some(second_gate),
            },
        ],
        false,
        75,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let second = paired(&controller, 76, None);
    let second_params = ready(&controller, second.device_id, world.session_id).await;

    let first_start = starting(
        &controller,
        world.environment_id,
        first_actor.clone(),
        first_id,
        &first_params,
    );
    service.a_start_arrives().await;
    let second_start = starting(
        &controller,
        world.environment_id,
        second.principal(),
        second.device_id,
        &second_params,
    );
    service.a_start_arrives().await;
    let _ = let_first_go.send(());
    let _ = first_start.await.expect("the first start ran");
    assert!(
        hold_of(&controller, &first_actor).is_some(),
        "the deferred call keeps the first start's hold"
    );
    let _ = let_second_go.send(());
    let _ = second_start.await.expect("the second start ran");
    assert_eq!(
        service.closes(),
        vec!["call-9".to_owned()],
        "the deferred call was closed once, and the service did not confirm it"
    );
    assert!(
        hold_of(&controller, &second.principal()).is_none(),
        "the refusal bound nothing, so the second start's hold ends"
    );
    assert!(
        hold_of(&controller, &first_actor).is_some(),
        "the close was not confirmed, so the first start's hold stands"
    );
    let held = starting(
        &controller,
        world.environment_id,
        first_actor.clone(),
        first_id,
        &first_params,
    )
    .await
    .expect("the next start ran")
    .into_answer_for_test()
    .expect_err("the device is held");
    assert_eq!(held.code(), ErrorCode::DraftConflict, "{held}");
    assert_eq!(
        service.arrived.available_permits(),
        0,
        "the held device's next start did not reach the service"
    );
    world.serving.abort();
}

/// KR-REQ-23.24: two devices whose starts replay one deferred call each end their own row when
/// the start that was in flight closes the call, and the call is closed once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_that_replay_one_deferred_call_each_end_their_own_row() {
    let (let_first_go, first_gate) = tokio::sync::oneshot::channel();
    let (let_second_go, second_gate) = tokio::sync::oneshot::channel();
    let (let_third_go, third_gate) = tokio::sync::oneshot::channel();
    let (world, service, first_id, first_actor, first_params) = with_service(
        vec![
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(first_gate),
            },
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(second_gate),
            },
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(third_gate),
            },
        ],
        true,
        77,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let second = paired(&controller, 78, None);
    let third = paired(&controller, 79, None);
    let second_params = ready(&controller, second.device_id, world.session_id).await;
    let third_params = ready(&controller, third.device_id, world.session_id).await;

    let first_start = starting(
        &controller,
        world.environment_id,
        first_actor.clone(),
        first_id,
        &first_params,
    );
    service.a_start_arrives().await;
    let second_start = starting(
        &controller,
        world.environment_id,
        second.principal(),
        second.device_id,
        &second_params,
    );
    service.a_start_arrives().await;
    let third_start = starting(
        &controller,
        world.environment_id,
        third.principal(),
        third.device_id,
        &third_params,
    );
    service.a_start_arrives().await;

    let _ = let_first_go.send(());
    let _ = first_start.await.expect("the first start ran");
    let _ = let_second_go.send(());
    let _ = second_start.await.expect("the second start ran");
    assert!(
        hold_of(&controller, &first_actor).is_some(),
        "the first deferred start keeps its hold while the third is in flight"
    );
    assert!(
        hold_of(&controller, &second.principal()).is_some(),
        "the second deferred start keeps its hold while the third is in flight"
    );
    assert_eq!(
        service.closes(),
        Vec::<String>::new(),
        "nothing is closed yet"
    );

    let _ = let_third_go.send(());
    let _ = third_start.await.expect("the third start ran");
    assert_eq!(
        service.closes(),
        vec!["call-9".to_owned()],
        "the call is closed once for the three starts"
    );
    for (who, actor) in [
        ("first", first_actor),
        ("second", second.principal()),
        ("third", third.principal()),
    ] {
        assert!(
            hold_of(&controller, &actor).is_none(),
            "the {who} start's hold ended with the close"
        );
    }
    world.serving.abort();
}

/// KR-REQ-23.24: a deferred closure does not end the row of a start whose claim could not settle:
/// the row stands until the start's claim is settled, whatever the closure says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_closure_does_not_end_a_row_whose_claim_failed_with_uncertain() {
    let (let_first_go, first_gate) = tokio::sync::oneshot::channel();
    let (let_second_go, second_gate) = tokio::sync::oneshot::channel();
    let (world, service, first_id, first_actor, first_params) = with_service(
        vec![
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(first_gate),
            },
            Answer::Call {
                call: "call-9",
                replayed: true,
                gate: Some(second_gate),
            },
        ],
        true,
        80,
    )
    .await;
    let controller = Arc::clone(&world.controller);
    let second = paired(&controller, 81, None);
    let second_params = ready(&controller, second.device_id, world.session_id).await;

    let first_start = starting(
        &controller,
        world.environment_id,
        first_actor.clone(),
        first_id,
        &first_params,
    );
    service.a_start_arrives().await;
    let second_start = starting(
        &controller,
        world.environment_id,
        second.principal(),
        second.device_id,
        &second_params,
    );
    service.a_start_arrives().await;

    // The first start's answer cannot be kept: its claim does not settle, and it defers its call.
    let registry = hold_the_registry(&world);
    let _ = let_first_go.send(());
    let given = first_start.await.expect("the first start ran");
    let_the_registry_go(&world, &registry);
    let unkept = given
        .into_answer_for_test()
        .expect_err("an answer that could not be kept is not told as given");
    assert!(
        matches!(unkept, crate::error::ControllerError::Uncertain { .. }),
        "{unkept}"
    );
    // The second start closes the call, which resolves the first start's closure.
    let _ = let_second_go.send(());
    let _ = second_start.await.expect("the second start ran");
    assert_eq!(service.closes(), vec!["call-9".to_owned()]);
    assert!(
        hold_of(&controller, &first_actor).is_some(),
        "the closure ended the effect, and the claim never settled, so the row stands"
    );
    world.serving.abort();
}
