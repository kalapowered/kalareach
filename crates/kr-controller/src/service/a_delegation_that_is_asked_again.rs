//! A delegation this host has already answered, asked for again.
//!
//! Section 23 returns the retained receipt to a duplicate from a still-authorised actor, and has the
//! host check current authority before it does, so that a revoked device cannot use an old action
//! identifier to retrieve what it was told.

use std::sync::Arc;

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceMetadata, VoiceRateQuote, VoiceSession,
    VoiceSessionRequest, VoiceStart, VoiceStartLatency,
};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActionWindowId, RequestId, SessionId, VoiceSessionId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64};
use kr_protocol::voice::{
    VoiceAction, VoiceDelegateParams, VoiceDelegateResult, VoiceDelegationId,
    VoiceDelegationOutcome, VoiceGrantParams, VoicePrepareParams, VoiceStartOutcome,
    VoiceStartParams,
};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, scripted};
use super::a_voice_grant_on_the_floor::{paired, paired_holding};
use super::voice_actions::VoiceIngress;
use crate::grants::{ActionClaim, ActionRecord};
use crate::service::Controller;
use crate::service::net::tests::{daemon_on, manual_clocks};

/// A delegation of `action` to the call `voice_session_id`, as it reaches the host from a device.
fn delegation_of(
    environment_id: kr_protocol::ids::EnvironmentId,
    voice_session_id: VoiceSessionId,
    session_id: SessionId,
    action: VoiceAction,
) -> MutationRequest {
    let params = VoiceDelegateParams {
        voice_session_id,
        delegation_id: VoiceDelegationId::new("item_one").expect("a delegation"),
        offset_ms: U64::new(0),
        action,
        session_id: Nullable::some(session_id),
        spoken_destination: if action == VoiceAction::SubmitPrompt {
            Nullable::some(kr_protocol::voice::SpokenDestination {
                session_id,
                spoken_text: "send it to this session".to_owned(),
            })
        } else {
            Nullable::null()
        },
        approval: Nullable::null(),
        turn_id: Nullable::null(),
        confirmation: Nullable::null(),
    };
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::VoiceDelegate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("device:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    }
}

/// Keeps `receipt` under the device's claim on `mutation`, as the host's own first attempt did.
fn keep(
    controller: &Controller,
    actor_id: &kr_protocol::ids::ActorId,
    mutation: &MutationRequest,
    receipt: &VoiceDelegateResult,
) {
    let now = kr_ipc::now_ms().get();
    let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).expect("a digest");
    let ActionClaim::Claimed { hold } = controller
        .sharing()
        .grants()
        .claim_action(actor_id, mutation.action_id, &digest, now)
        .expect("claims")
    else {
        panic!("the first attempt claims the action");
    };
    controller
        .sharing()
        .grants()
        .retain_result(
            &hold,
            &kr_cbor::encode(
                ParamsValue::from_typed(receipt)
                    .expect("encodes")
                    .as_value(),
            ),
            now,
        )
        .expect("kept");
    drop(hold);
}

/// The delegation asked for again, on a connection this host admitted, as `actor_id`.
async fn ask(
    controller: &Arc<Controller>,
    actor_id: &kr_protocol::ids::ActorId,
    device_id: kr_protocol::ids::DeviceId,
    mutation: &MutationRequest,
) -> crate::error::Result<ParamsValue> {
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let carried =
        crate::service::a_close_a_worker_never_answers::admission(controller, accepted).await;
    let revision = controller.policy().authority_revision();
    controller
        .voice_mutation(
            VoiceIngress {
                actor_id,
                actor: crate::voice::VoiceActor::Device(device_id),
                route: None,
            },
            mutation,
            Method::VoiceDelegate,
            revision,
            carried,
        )
        .await
}

/// A provider that answers without a network call.
#[derive(Debug)]
struct OfflineProvider;

impl ManagedVoiceService for OfflineProvider {
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        Box::pin(async move { Ok(None) })
    }

    fn provider(&self) -> String {
        "the offline provider".to_owned()
    }

    fn start<'a>(&'a self, _request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            Ok(VoiceStart::Started(Box::new(VoiceSession {
                call_id: "call-1".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                provider_session_id: "sess_1".to_owned(),
                answer_sdp: "v=0\r\n".to_owned(),
                model: "gpt-live-1".to_owned(),
                closes_at: "2026-09-20T01:00:00Z".to_owned(),
                reservation_ends_at: "2026-09-20T01:00:15Z".to_owned(),
                control_path: "/api/voice/sessions/call-1/control".to_owned(),
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
                replayed: false,
                disclosure: Vec::new(),
            })))
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        let call_id = call_id.to_owned();
        Box::pin(async move {
            Ok(VoiceClosure {
                call_id,
                state: "finalised".to_owned(),
                usage_seconds: 0,
                usage_provisional: true,
            })
        })
    }
}

/// KR-REQ-09.16 and 23.51: a delegation's retained receipt goes back to the device that was given
/// it for as long as that device is paired, and to nobody once it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegations_receipt_goes_back_only_to_a_device_that_is_still_paired() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(std::sync::atomic::Ordering::SeqCst);
    let device = paired(&controller, 47, None);
    let actor_id = device.principal();
    let mutation = delegation_of(
        temp.environment_id(),
        VoiceSessionId::new(kr_ipc::new_uuid()),
        SessionId::new(kr_ipc::new_uuid()),
        VoiceAction::SubmitPrompt,
    );
    let params: VoiceDelegateParams = mutation.params.to_typed().expect("decodes");

    // What the host answered the first time, and kept under the device's claim.
    let receipt = VoiceDelegateResult {
        delegation_id: params.delegation_id,
        outcome: VoiceDelegationOutcome::Admitted {
            action_id: mutation.action_id,
            note: "admitted".to_owned(),
        },
    };
    keep(&controller, &actor_id, &mutation, &receipt);

    let given = ask(&controller, &actor_id, device.device_id, &mutation)
        .await
        .expect("a paired device is given its receipt");
    assert_eq!(
        given.to_typed::<VoiceDelegateResult>().expect("a result"),
        receipt
    );

    controller
        .devices()
        .revoke(device.device_id, TimestampMs::new(now + 1))
        .expect("the device is revoked");
    let refused = ask(&controller, &actor_id, device.device_id, &mutation)
        .await
        .expect_err("a revoked device is given nothing");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
}

/// A call the device holds over `session_id`, started through the daemon's own voice service and a
/// provider that makes no network call, under a standing voice grant that permits `actions`.
async fn call_over(
    controller: &Arc<Controller>,
    device_id: kr_protocol::ids::DeviceId,
    session_id: SessionId,
    actions: &[VoiceAction],
) -> VoiceSessionId {
    controller.voice().attach_provider(Some(
        Arc::new(OfflineProvider) as Arc<dyn ManagedVoiceService>
    ));
    let coordinator = controller.voice().coordinator();
    let revision = controller.policy().authority_revision();
    let now = kr_ipc::now_ms().get();
    coordinator
        .grant(
            &VoiceGrantParams {
                device_id,
                session_ids: [session_id].into_iter().collect(),
                actions: Nullable::some(actions.iter().copied().collect()),
            },
            revision,
            now,
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
    let started = coordinator
        .start(
            device_id,
            &VoiceStartParams {
                session_ids: [session_id].into_iter().collect(),
                offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
                duration_seconds: 600,
                reasoning_budget_minor: Nullable::null(),
                prepared,
                expected_rate_version: Nullable::some("2026-09".to_owned()),
            },
            revision,
            now,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a call");
    let VoiceStartOutcome::Started { session } = started.outcome else {
        panic!("the call runs");
    };
    session.voice_session_id
}

/// Has the device's own grant reach history from `lower_bound_ms` on, in the record pairing wrote it
/// into.
fn reach_history_from(
    temp: &kr_ipc::testing::TempHost,
    device: &crate::service::net::devices::DeviceRecord,
    lower_bound_ms: u64,
) {
    let mut grant = device.grant.clone();
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(lower_bound_ms));
    let changed = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry")
        .execute(
            "UPDATE network_devices SET grant = ?1 WHERE device_id = ?2",
            rusqlite::params![
                kr_cbor::to_canonical_vec(&grant).expect("encodes"),
                device.device_id.get().as_bytes().as_slice(),
            ],
        )
        .expect("the device's grant is changed");
    assert_eq!(changed, 1);
}

/// KR-REQ-09.16 and 23.51: a read whose first answer carried content is answered again by reading
/// the session again, under the history bound that stands now, and not from the record: with the
/// bound as it was the retry is given the session's description, and once the device's grant
/// reaches only history after the session began, the same retry is given none of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_asked_again_gives_only_what_the_history_bound_admits_now() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let controller = Arc::clone(&world.controller);
    let device = paired(&controller, 49, None);
    let actor_id = device.principal();
    // A grant that reaches all of the history there is.
    reach_history_from(&world._temp, &device, 1);
    let voice_session_id = call_over(
        &controller,
        device.device_id,
        world.session_id,
        &[VoiceAction::Status],
    )
    .await;
    let mutation = delegation_of(
        world.environment_id,
        voice_session_id,
        world.session_id,
        VoiceAction::Status,
    );
    let summary_of = |answer: ParamsValue| match answer
        .to_typed::<VoiceDelegateResult>()
        .expect("a delegation result")
        .outcome
    {
        VoiceDelegationOutcome::Performed { summary, .. } => summary,
        other => panic!("the read is performed: {other:?}"),
    };

    let first = summary_of(
        ask(&controller, &actor_id, device.device_id, &mutation)
            .await
            .expect("the first submission reads the session"),
    );
    assert!(
        first.contains("/bin/zsh"),
        "the first read carries the session's description: {first}"
    );
    let again = summary_of(
        ask(&controller, &actor_id, device.device_id, &mutation)
            .await
            .expect("the repeat is answered"),
    );
    assert_eq!(again, first, "an authorised repeat is given the same read");

    // The device's grant now reaches only history from after the session began. The record is
    // written directly: the narrower grant a device is given later is another grant, and what this
    // proves is the daemon's own filter, applied to a read made again.
    reach_history_from(&world._temp, &device, kr_ipc::now_ms().get() + 3_600_000);
    let narrower = summary_of(
        ask(&controller, &actor_id, device.device_id, &mutation)
            .await
            .expect("the repeat is answered"),
    );
    assert!(
        narrower.contains("does not reach"),
        "the content the first answer carried is not given again: {narrower}"
    );
    assert!(
        !narrower.contains("/bin/zsh") && !narrower.contains("/work"),
        "nothing the first answer carried is in it: {narrower}"
    );
    world.serving.abort();
}

/// KR-REQ-09.16: a receipt for an action that is not a read goes back as it was kept, whatever it
/// says, because a repeat never performs an effect a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receipt_for_an_effect_is_given_back_as_it_was_kept() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired(&controller, 48, None);
    let actor_id = device.principal();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let effect = delegation_of(
        temp.environment_id(),
        VoiceSessionId::new(kr_ipc::new_uuid()),
        session_id,
        VoiceAction::SubmitPrompt,
    );
    let kept = VoiceDelegateResult {
        delegation_id: VoiceDelegationId::new("item_one").expect("a delegation"),
        outcome: VoiceDelegationOutcome::Performed {
            action_id: effect.action_id,
            summary: "sent".to_owned(),
        },
    };
    keep(&controller, &actor_id, &effect, &kept);
    let given = ask(&controller, &actor_id, device.device_id, &effect)
        .await
        .expect("the receipt goes back");
    assert_eq!(
        given.to_typed::<VoiceDelegateResult>().expect("a result"),
        kept
    );
}

/// The device directory's own route for one delegation, watched at the moment it is given back:
/// the claim it was taken beside must still be held then.
struct Route<'a> {
    real: super::voice_actions::DeviceRoute<'a>,
    controller: &'a Controller,
    claim_held_when_given_back: std::sync::atomic::AtomicBool,
}

impl super::voice_actions::ClaimedRoute for Route<'_> {
    fn give_back(&self) -> crate::error::Result<()> {
        let digest = kr_protocol::digest::mutation_digest(self.real.mutation, self.real.actor_id)
            .expect("a digest");
        let held = self
            .controller
            .sharing()
            .grants()
            .recorded_action(self.real.actor_id, self.real.mutation.action_id, &digest)
            .expect("the store answers");
        self.claim_held_when_given_back.store(
            matches!(held, Some(ActionRecord::InFlight)),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.real.give_back()
    }

    fn take_again(&self) {
        self.real.take_again();
    }
}

/// KR-REQ-09.07: the route a delegation's challenge claimed goes back while the voice claim is still
/// held, and the claim goes back after it. The route store and the grant store are the real ones: a
/// request that comes after both takes them afresh, with the signed delegation's other payload, and
/// a route given back is not claimed again by the same payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_challenges_route_goes_back_while_its_claim_is_still_held() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired_holding(
        &controller,
        50,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        None,
    );
    let actor_id = device.principal();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let voice_session_id = call_over(
        &controller,
        device.device_id,
        session_id,
        &[VoiceAction::ShellInput],
    )
    .await;
    let mutation = delegation_of(
        temp.environment_id(),
        voice_session_id,
        session_id,
        VoiceAction::ShellInput,
    );
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
    // What the network ingress does before the voice service: claim the route.
    assert_eq!(
        controller
            .devices()
            .claim_action_route(
                &actor_id,
                mutation.action_id,
                None,
                digest,
                kr_ipc::now_ms(),
            )
            .expect("the route is claimed"),
        crate::service::net::devices::ActionRoute::Recorded
    );
    let route = Route {
        real: super::voice_actions::DeviceRoute {
            devices: controller.devices(),
            actor_id: &actor_id,
            mutation: &mutation,
        },
        controller: &controller,
        claim_held_when_given_back: std::sync::atomic::AtomicBool::new(false),
    };
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let carried =
        crate::service::a_close_a_worker_never_answers::admission(&controller, accepted).await;
    let answered = controller
        .voice_mutation(
            VoiceIngress {
                actor_id: &actor_id,
                actor: crate::voice::VoiceActor::Device(device.device_id),
                route: Some(&route),
            },
            &mutation,
            Method::VoiceDelegate,
            controller.policy().authority_revision(),
            carried,
        )
        .await
        .expect("the first submission is answered");
    assert!(
        matches!(
            answered
                .to_typed::<VoiceDelegateResult>()
                .expect("a result")
                .outcome,
            VoiceDelegationOutcome::ConfirmationRequired { .. }
        ),
        "the challenge is the answer"
    );
    assert!(
        route
            .claim_held_when_given_back
            .load(std::sync::atomic::Ordering::SeqCst),
        "the voice claim was still held when the route went back"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .recorded_action(&actor_id, mutation.action_id, &digest)
            .expect("the store answers")
            .is_none(),
        "the claim goes back too"
    );
    // Both stores are free for the signed delegation, which is the same action with another
    // payload.
    assert_eq!(
        controller
            .devices()
            .claim_action_route(
                &actor_id,
                mutation.action_id,
                None,
                kr_protocol::scalars::Digest256::from_bytes([7; 32]),
                kr_ipc::now_ms(),
            )
            .expect("the route is claimed again"),
        crate::service::net::devices::ActionRoute::Recorded,
        "the identifier is free on the route store"
    );
}
