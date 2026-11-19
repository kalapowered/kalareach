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

use super::a_delegation_that_is_asked_again::{
    admitted_for_five_minutes, submitted_under, voice_mutation_of,
};
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, scripted};
use super::a_voice_grant_on_the_floor::paired;
use crate::service::Controller;

/// What the scripted service answers one start with.
enum Answer {
    /// The service refuses the start: nothing was created.
    Refuses,
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
                Answer::Refuses => Ok(VoiceStart::Refused(Box::new(VoiceRefusal {
                    reason: VoiceRefusalReason::ServiceCapacity,
                    message: "Managed capacity is spent.".to_owned(),
                    alternatives: Vec::new(),
                    attempt_id: None,
                    call_id: None,
                }))),
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
    let controller = Arc::clone(controller);
    let mutation = voice_mutation_of(Method::VoiceStart, environment_id, params);
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

/// KR-REQ-23.24: a start whose answer this host could not keep leaves its hold standing, whatever
/// its effect said. The service refused the start and nothing was created, so the effect ends the
/// row; the claim that could not settle keeps it, and the device's next start, which names no
/// earlier one, is refused in the hold's words without asking the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_whose_answer_could_not_be_kept_leaves_its_hold_standing() {
    let world = scripted(&Scripted::new()).await;
    let controller = Arc::clone(&world.controller);
    let service = ServiceScript::new(vec![Answer::Refuses], true);
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

    // The start is answered and its effect is known; its claim is not yet settled.
    let (arrived, go) = controller.before_a_voice_claim_settles.arm();
    let making = starting(
        &controller,
        world.environment_id,
        actor_id.clone(),
        device.device_id,
        &params,
    );
    arrived.await.expect("the start reaches its settlement");
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
    let _ = go.send(());
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
    let standing = hold_of(&controller, &actor_id).expect("the row stands after the failed claim");

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
