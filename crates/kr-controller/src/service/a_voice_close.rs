//! A session closed by voice: a spoken "close session N", confirmed by the device that heard it,
//! carried out by the session's worker the way that device's own close is.
//!
//! The daemon is the real one: its own grant store, its own device directory, its own voice
//! service with the product grammar, and a worker that speaks the worker's protocol. The worker is
//! the double the other service tests use; it keeps every frame it is forwarded, so what reached it
//! is read from there.

use std::sync::Arc;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, VoiceSessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::voice::{
    VoiceAction, VoiceConfirmationRequest, VoiceDelegateParams, VoiceDelegateResult,
    VoiceDelegationOutcome, VoiceRefusal, VoiceStopParams,
};

use super::a_delegation_that_is_asked_again::{ask, call_over, call_over_for, delegation_named};
use super::a_floor_owed_its_record::until;
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, scripted};
use super::a_voice_grant_on_the_floor::paired_signing_as;
use super::one_barrier_for_every_restriction::{owed, revision};
use super::voice_actions::VoiceBudgets;
use crate::service::Controller;
use crate::service::net::devices::DeviceRecord;

/// A daemon with a live session behind a worker double, a paired device that may close it, and a
/// call that device holds, whose voice grant may close it.
struct Call {
    script: Arc<Scripted>,
    world: super::a_close_a_worker_never_answers::Silent,
    controller: Arc<Controller>,
    device: DeviceRecord,
    key: AuthorisationKeyPair,
    voice_session_id: VoiceSessionId,
    number: u64,
}

impl Call {
    async fn start() -> Self {
        Self::start_for(600).await
    }

    /// The same, for a call that runs for `duration_seconds`.
    async fn start_for(duration_seconds: u32) -> Self {
        let script = Scripted::new();
        let world = scripted(&script).await;
        let controller = Arc::clone(&world.controller);
        let key = AuthorisationKeyPair::generate().expect("an identity key");
        let device = paired_signing_as(
            &controller,
            61,
            *key.public(),
            &[ActionRight::SessionView, ActionRight::SessionClose],
            None,
        );
        let voice_session_id = call_over_for(
            &controller,
            device.device_id,
            world.session_id,
            &[VoiceAction::CloseSession, VoiceAction::Status],
            duration_seconds,
        )
        .await;
        let number = controller
            .voice_session_number(world.session_id)
            .await
            .expect("the registry reads")
            .expect("the session has a number");
        Self {
            script,
            world,
            controller,
            device,
            key,
            voice_session_id,
            number,
        }
    }

    /// The device's close of the session, said as a person says it.
    fn saying(&self, name: &str) -> MutationRequest {
        delegation_named(
            name,
            self.world.environment_id,
            self.voice_session_id,
            &format!("Close session {}.", self.number),
        )
    }

    /// What the host answers a delegation the device submits.
    async fn submit(&self, mutation: &MutationRequest) -> VoiceDelegateResult {
        ask(
            &self.controller,
            &self.device.principal(),
            self.device.device_id,
            mutation,
        )
        .await
        .expect("the delegation is answered")
        .to_typed()
        .expect("a delegation result")
    }

    /// The challenge the host issues for `mutation`.
    async fn challenge(&self, mutation: &MutationRequest) -> VoiceConfirmationRequest {
        match self.submit(mutation).await.outcome {
            VoiceDelegationOutcome::ConfirmationRequired { request, .. } => *request,
            other => panic!("a close asks for the device's confirmation first: {other:?}"),
        }
    }

    /// `mutation` carrying the device's signature over `request`.
    fn signed(
        &self,
        mutation: &MutationRequest,
        request: &VoiceConfirmationRequest,
    ) -> MutationRequest {
        let mut params: VoiceDelegateParams = mutation.params.to_typed().expect("decodes");
        params.confirmation = Nullable::some(
            kr_voice::sign_confirmation(&self.key, request).expect("the device signs"),
        );
        MutationRequest {
            params: ParamsValue::from_typed(&params).expect("encodes"),
            ..mutation.clone()
        }
    }

    /// The close of `mutation` as the device signs it.
    async fn confirmed(&self, mutation: &MutationRequest) -> MutationRequest {
        let request = self.challenge(mutation).await;
        self.signed(mutation, &request)
    }

    /// The closes the worker was forwarded.
    fn closes(&self) -> Vec<kr_protocol::local::ForwardedMutation> {
        self.script
            .forwarded()
            .into_iter()
            .filter(|forwarded| forwarded.mutation.method == Method::SessionClose.into())
            .collect()
    }

    /// The grant the call runs under.
    fn voice_grant_id(&self) -> kr_protocol::ids::GrantId {
        self.controller
            .sharing()
            .grants()
            .records_for_device(self.device.device_id)
            .expect("the store reads")
            .into_iter()
            .map(|record| record.grant)
            .find(|grant| grant.permits(ActionRight::VoiceUse) && grant.parent_grant_id.0.is_some())
            .expect("the call's own voice grant")
            .grant_id
    }

    /// The close of the call's session, as the coordinator proposes it to the host.
    fn proposal(&self) -> kr_voice::Proposal {
        let delegation_id =
            kr_protocol::voice::VoiceDelegationId::new("item_close").expect("an id");
        let action = VoiceAction::CloseSession;
        kr_voice::Proposal {
            voice_session_id: self.voice_session_id,
            device_id: self.device.device_id,
            voice_grant_id: self.voice_grant_id(),
            environment_id: self.world.environment_id,
            action,
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            session_id: Some(self.world.session_id),
            delegation_id: delegation_id.clone(),
            plan: kr_protocol::voice::VoiceActionPlan {
                voice_session_id: self.voice_session_id,
                action,
                session_id: Nullable::some(self.world.session_id),
                delegation_id: Nullable::some(delegation_id),
                payload_digest: kr_protocol::scalars::Digest256::from_bytes([3; 32]),
            },
            approval: None,
            turn_id: None,
            destination: None,
        }
    }

    /// Stops the call on a task of its own, so a test can watch it wait.
    fn stopping(&self) -> tokio::task::JoinHandle<()> {
        let controller = Arc::clone(&self.controller);
        let device_id = self.device.device_id;
        let voice_session_id = self.voice_session_id;
        tokio::spawn(async move {
            controller
                .voice()
                .coordinator()
                .stop(
                    device_id,
                    &VoiceStopParams { voice_session_id },
                    kr_ipc::now_ms().get(),
                )
                .await
                .expect("the call is stopped");
        })
    }

    async fn stop(&self) {
        let now = kr_ipc::now_ms().get();
        self.controller
            .voice()
            .coordinator()
            .stop(
                self.device.device_id,
                &VoiceStopParams {
                    voice_session_id: self.voice_session_id,
                },
                now,
            )
            .await
            .expect("the call is stopped");
    }
}

fn refusal_of(answered: &VoiceDelegateResult) -> VoiceRefusal {
    match &answered.outcome {
        VoiceDelegationOutcome::Refused { reason, .. } => *reason,
        other => panic!("this delegation is refused, not {other:?}"),
    }
}

/// KR-REQ-15.13: a session is not closed on what was said alone. The first submission of a spoken
/// close is answered with the challenge the device signs on its unlocked screen, the worker is
/// forwarded nothing, and a transcript that says the person agreed is no substitute for it: the
/// words the host reads are the ones it can read, and the agreement is not among them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spoken_close_is_not_done_without_the_devices_signature() {
    let call = Call::start().await;

    let asked = call.submit(&call.saying("item_close")).await;
    assert_eq!(asked.action.0, Some(VoiceAction::CloseSession));
    assert_eq!(asked.session_id.0, Some(call.world.session_id));
    assert!(
        matches!(
            asked.outcome,
            VoiceDelegationOutcome::ConfirmationRequired { .. }
        ),
        "{:?}",
        asked.outcome
    );

    // Words that say the person agreed are not words the host reads as a request, and they do not
    // change what the host asks of the device.
    let said_yes = delegation_named(
        "item_yes",
        call.world.environment_id,
        call.voice_session_id,
        &format!("Yes, I confirm it, close session {}", call.number),
    );
    assert_eq!(
        refusal_of(&call.submit(&said_yes).await),
        VoiceRefusal::NotUnderstood
    );
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13: a signature is over one action and one request. The device's signature over the
/// challenge for one close does not close another session's, and does not carry the same close
/// under another request identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signature_over_one_close_closes_nothing_else() {
    let call = Call::start().await;

    let first = call.saying("item_first");
    let challenge = call.challenge(&first).await;

    // Another delegation of the same words: another plan.
    let other = call.saying("item_other");
    let other_signed = call.signed(&other, &challenge);
    assert_eq!(
        refusal_of(&call.submit(&other_signed).await),
        VoiceRefusal::ConfirmationMismatch
    );

    // The same delegation under another request: another challenge was never issued for it.
    let again = MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        ..call.signed(&first, &challenge)
    };
    assert_eq!(
        refusal_of(&call.submit(&again).await),
        VoiceRefusal::ConfirmationMismatch
    );
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13: a close the device has confirmed closes the session, once. The worker is forwarded
/// one close, as the paired device, under the voice grant the call was admitted under, with the
/// right to close and no voice right, naming the session and nothing else, under the delegation's
/// action identifier; the host reports what the worker answered; and asking again gives the same
/// receipt and closes nothing a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmed_close_closes_the_session_once() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;

    let answered = call.submit(&signed).await;
    let VoiceDelegationOutcome::Performed { action_id, summary } = &answered.outcome else {
        panic!("the close is performed: {:?}", answered.outcome);
    };
    assert_eq!(*action_id, signed.action_id);
    assert!(
        summary.contains(&format!("session {}", call.number)) && summary.contains("closing"),
        "{summary}"
    );

    let closes = call.closes();
    assert_eq!(closes.len(), 1, "one close reached the worker");
    let forwarded = &closes[0];
    assert_eq!(forwarded.mutation.action_id, signed.action_id);
    assert_eq!(
        forwarded.mutation.target.session_id.as_ref(),
        Some(&call.world.session_id)
    );
    assert_eq!(
        forwarded.actor.device_id.as_ref(),
        Some(&call.device.device_id)
    );
    assert_eq!(
        forwarded.actor.ingress,
        kr_protocol::actor::ActorIngress::PairedDevice
    );
    let live = call.controller.voice().coordinator().live_sessions();
    assert_eq!(live, 1, "the call is still running");
    let voice_grant_id = call.voice_grant_id();
    assert_eq!(
        forwarded.actor.grant_id.as_ref(),
        Some(&voice_grant_id),
        "the close travels under the call's voice grant"
    );
    assert_eq!(
        forwarded.mutation.grant_id.as_ref(),
        Some(&voice_grant_id),
        "and the mutation names the same grant"
    );
    assert_eq!(
        forwarded.grant_rights.iter().copied().collect::<Vec<_>>(),
        vec![ActionRight::SessionClose],
        "with the right to close and no voice right"
    );
    assert!(forwarded.accepted_deadline_boot_ms.get() > 0);

    let again = call.submit(&signed).await;
    assert_eq!(again, answered, "a repeat is given the receipt");
    assert_eq!(call.closes().len(), 1, "and closes nothing a second time");

    // The call goes on: a request after the close is read as any other is.
    let status = call
        .submit(&delegation_named(
            "item_status",
            call.world.environment_id,
            call.voice_session_id,
            &format!("status of session {}", call.number),
        ))
        .await;
    assert!(
        matches!(status.outcome, VoiceDelegationOutcome::Performed { .. }),
        "{:?}",
        status.outcome
    );
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 09.07: a close the host has accepted is not called back by the connection that
/// asked for it going away. The attempt owns the delegation's claim and records what the worker
/// answered, so the device that asks again is given that receipt, and the worker is forwarded one
/// close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_outlives_the_connection_that_asked_for_it() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let (arrived, go) = call.script.hold_the_next_close();

    let controller = Arc::clone(&call.controller);
    let principal = call.device.principal();
    let device_id = call.device.device_id;
    let asking = tokio::spawn({
        let signed = signed.clone();
        async move { ask(&controller, &principal, device_id, &signed).await }
    });
    arrived.await.expect("the close reaches the worker");
    // The connection goes away with the close in the worker's hands.
    asking.abort();
    let _ = asking.await;
    go.send(()).expect("the worker goes on");

    let mut receipt = None;
    until("the close is recorded under the delegation", async || {
        match ask(
            &call.controller,
            &call.device.principal(),
            call.device.device_id,
            &signed,
        )
        .await
        {
            Ok(answered) => {
                receipt = Some(answered);
                true
            }
            // The first attempt is still running.
            Err(error) if error.code() == ErrorCode::ResourceUnavailable => false,
            Err(error) => panic!("{error}"),
        }
    })
    .await;
    let receipt: VoiceDelegateResult = receipt
        .expect("a receipt")
        .to_typed()
        .expect("a delegation result");
    assert!(
        matches!(receipt.outcome, VoiceDelegationOutcome::Performed { .. }),
        "{:?}",
        receipt.outcome
    );
    assert_eq!(call.closes().len(), 1, "one close reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13: a worker that does not answer a close inside the time allowed leaves the close
/// uncertain. The device is told so, the close is not sent again by a repeat of the delegation, and
/// the fence it would owe ends with the deadline the close travelled with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_does_not_answer_a_close_leaves_it_uncertain() {
    let call = Call::start().await;
    *call.controller.voice_budgets.lock().expect("the budgets") = VoiceBudgets {
        read: VoiceBudgets::STATED.read,
        close: std::time::Duration::from_millis(300),
    };
    let signed = call.confirmed(&call.saying("item_close")).await;
    // The worker takes the close and never answers it.
    let (arrived, _never) = call.script.hold_the_next_close();

    let error = ask(
        &call.controller,
        &call.device.principal(),
        call.device.device_id,
        &signed,
    )
    .await
    .expect_err("the close is uncertain");
    arrived.await.expect("the close reached the worker");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown, "{error}");

    let repeated = ask(
        &call.controller,
        &call.device.principal(),
        call.device.device_id,
        &signed,
    )
    .await
    .expect_err("the close is not sent again");
    assert_eq!(repeated.code(), ErrorCode::OutcomeUnknown, "{repeated}");
    assert_eq!(call.closes().len(), 1, "one close reached the worker");

    until("the close lets go of its grant", async || {
        call.controller.sharing().grants().closes_held() == 0
    })
    .await;
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 09.12: stopping the call while a close is on its way to the worker owes a fence,
/// which a worker that has installed it answers by refusing the close it had not yet taken up. The
/// session is not closed, and the close stays held against its grant until the deadline it
/// travelled with: a refusal that did not come from the worker is not proof that no worker can
/// still take it up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_while_a_close_is_on_its_way_makes_the_worker_refuse_it() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let before = revision(&call.controller).await;
    let (arrived, go) = call.controller.before_a_proxy_is_opened.arm();

    let controller = Arc::clone(&call.controller);
    let principal = call.device.principal();
    let device_id = call.device.device_id;
    let asking = tokio::spawn({
        let signed = signed.clone();
        async move { ask(&controller, &principal, device_id, &signed).await }
    });
    // The close has been held and its authority read again; it is about to open its link.
    arrived.await.expect("the close reaches the link");
    call.stop().await;

    assert_eq!(
        revision(&call.controller).await,
        before + 1,
        "one barrier retired the debt the stop owed before the stop was answered"
    );
    assert!(owed(&call.controller).is_empty());

    go.send(()).expect("the close goes on");
    let refused = asking
        .await
        .expect("the attempt ends")
        .expect_err("the worker refuses the close");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert_eq!(call.closes().len(), 1, "the close reached the worker");
    assert_eq!(call.script.closes_taken(), 0, "and the worker took none up");
    assert_eq!(call.controller.sharing().grants().closes_held(), 1);
    call.world.serving.abort();
}

/// KR-REQ-15.13: a withdrawal of the voice grant that lands between the moment a close is held and
/// the moment its authority is read again forwards nothing: the read finds the grant gone. The
/// stop owed the fence because the close was already held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_after_the_close_is_held_forwards_nothing() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let before = revision(&call.controller).await;
    let (arrived, go) = call.controller.after_a_voice_close_is_held.arm();

    let controller = Arc::clone(&call.controller);
    let principal = call.device.principal();
    let device_id = call.device.device_id;
    let asking = tokio::spawn({
        let signed = signed.clone();
        async move { ask(&controller, &principal, device_id, &signed).await }
    });
    arrived.await.expect("the close is held");
    call.stop().await;
    until("the barrier for the stop", async || {
        owed(&call.controller).is_empty() && revision(&call.controller).await > before
    })
    .await;

    go.send(()).expect("the close goes on");
    let refused = asking
        .await
        .expect("the attempt ends")
        .expect_err("the grant is gone");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13: a stop owes no fence once the worker has answered the close, and none when no
/// close was ever held: the debt exists only while a worker can still take a close up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_after_the_worker_answered_owes_nothing() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let answered = call.submit(&signed).await;
    assert!(
        matches!(answered.outcome, VoiceDelegationOutcome::Performed { .. }),
        "{:?}",
        answered.outcome
    );
    assert_eq!(call.controller.sharing().grants().closes_held(), 0);
    let before = revision(&call.controller).await;
    let here = admit(&call.controller, call.device.device_id).await;

    call.stop().await;

    assert!(owed(&call.controller).is_empty(), "the stop wrote no debt");
    assert_eq!(revision(&call.controller).await, before, "and no barrier");
    assert!(
        call.controller.admitted_revision(here).is_ok(),
        "and withdrew no connection"
    );
    call.controller
        .check_fence()
        .expect("so no admission is refused");
    call.world.serving.abort();
}

/// KR-REQ-15.13: a challenge outlives nothing. Once the call is stopped, the signature over its
/// challenge closes nothing, and neither does a close of a session the call does not reach or one
/// named by a terminal session's identifier where a voice session's belongs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_the_call_cannot_make_closes_nothing() {
    let call = Call::start().await;

    // A session the call does not reach.
    let elsewhere = delegation_named(
        "item_elsewhere",
        call.world.environment_id,
        call.voice_session_id,
        &format!("close session {}", call.number + 1),
    );
    assert_eq!(
        refusal_of(&call.submit(&elsewhere).await),
        VoiceRefusal::SessionOutsideVoiceSession
    );

    // A terminal session's identifier is not a voice session's.
    let mistaken = delegation_named(
        "item_mistaken",
        call.world.environment_id,
        VoiceSessionId::new(call.world.session_id.get()),
        &format!("close session {}", call.number),
    );
    assert_eq!(
        refusal_of(&call.submit(&mistaken).await),
        VoiceRefusal::UnknownVoiceSession,
        "a terminal session's identifier names no voice session"
    );

    // The call is stopped while the device holds a challenge.
    let signed = call.confirmed(&call.saying("item_close")).await;
    call.stop().await;
    assert_eq!(
        refusal_of(&call.submit(&signed).await),
        VoiceRefusal::UnknownVoiceSession,
        "a stopped call closes nothing"
    );
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// The ceiling this host's configuration puts on the rights a grant may carry, naming the right to
/// use voice and to see a session and not the right to close one.
///
/// The scripted worker gives no evidence of its fence, so the change is written and in force and its
/// barrier is reported as not held, which `apply_configuration` answers as an error. What a test
/// needs is the ceiling in force, and that is what it asks.
async fn without_the_right_to_close(controller: &Arc<Controller>) {
    let _ = controller
        .apply_configuration(&kr_protocol::hostinfo::configuration::Change::GrantRights(
            Some(vec![
                ActionRight::VoiceUse.as_str().to_owned(),
                ActionRight::SessionView.as_str().to_owned(),
            ]),
        ))
        .await;
    assert!(
        controller
            .rights_ceiling
            .lock()
            .expect("the ceiling")
            .as_ref()
            .is_some_and(|ceiling| !ceiling.contains(&ActionRight::SessionClose)),
        "the ceiling is in force"
    );
}

/// KR-REQ-15.13 and 26.16: a right this host's configuration has taken away from every grant is
/// not one a spoken close can use. The device's grant and the call's grant both carry the right to
/// close, and the close is refused before the device is asked to confirm it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_the_configuration_has_taken_the_right_for_is_not_asked_for() {
    let call = Call::start().await;
    without_the_right_to_close(&call.controller).await;

    let asked = call.submit(&call.saying("item_close")).await;

    assert_eq!(refusal_of(&asked), VoiceRefusal::OutsideDeviceGrant);
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 26.16: a ceiling that comes in after the device has signed, and before the
/// close is forwarded, stops the close. The authority is read again at the last moment, under the
/// ceiling then in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ceiling_that_comes_in_after_the_close_is_held_forwards_nothing() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let (arrived, go) = call.controller.after_a_voice_close_is_held.arm();

    let controller = Arc::clone(&call.controller);
    let principal = call.device.principal();
    let device_id = call.device.device_id;
    let asking = tokio::spawn({
        let signed = signed.clone();
        async move { ask(&controller, &principal, device_id, &signed).await }
    });
    arrived.await.expect("the close is held");
    without_the_right_to_close(&call.controller).await;

    go.send(()).expect("the close goes on");
    let refused = asking
        .await
        .expect("the attempt ends")
        .expect_err("the host no longer lets the device close");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(call.closes().is_empty(), "nothing reached the worker");
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 09.12: a stop is answered once the workers hold the revision that makes them
/// refuse a close the stop caught on its way, and not before. A worker that has not been told is
/// one a close could still reach, and a stop that had been answered would be a statement that it
/// could not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_is_answered_only_once_the_worker_holds_the_revision() {
    let call = Call::start().await;
    let signed = call.confirmed(&call.saying("item_close")).await;
    let before = revision(&call.controller).await;
    let (at_the_link, go) = call.controller.before_a_proxy_is_opened.arm();
    let controller = Arc::clone(&call.controller);
    let principal = call.device.principal();
    let device_id = call.device.device_id;
    let asking = tokio::spawn({
        let signed = signed.clone();
        async move { ask(&controller, &principal, device_id, &signed).await }
    });
    at_the_link
        .await
        .expect("the close is about to open its link");
    let (told, install) = call.script.hold_the_next_announcement();

    let stopping = call.stopping();
    told.await.expect("the worker is told the revision");
    assert!(
        !stopping.is_finished(),
        "the stop waits for the worker to hold the revision"
    );
    assert!(
        call.script
            .installed_revision()
            .is_none_or(|held| held.get() <= before),
        "and the worker does not hold it yet"
    );

    install.send(()).expect("the worker installs the revision");
    stopping.await.expect("the stop ends");
    assert_eq!(
        call.script.installed_revision().map(|held| held.get()),
        Some(before + 1),
        "the worker holds the revision the stop's answer stands on"
    );
    assert!(owed(&call.controller).is_empty(), "and nothing is owed");

    go.send(()).expect("the close goes on");
    let _ = asking.await.expect("the attempt ends");
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 09.12: withdrawing a call's grant while a close is on its way raises a barrier
/// that withdraws no connection. The connection of the device that holds the call stays admitted,
/// so the answer to the stop and to every request on that link is delivered, and so does every
/// other device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_while_a_close_is_on_its_way_withdraws_no_connection() {
    let call = Call::start().await;
    let before = revision(&call.controller).await;
    let (here, other) = (
        admit(&call.controller, call.device.device_id).await,
        admit(&call.controller, DeviceId::new(kr_ipc::new_uuid())).await,
    );
    let hold = call
        .controller
        .sharing()
        .grants()
        .hold_close(call.voice_grant_id());

    call.stop().await;

    assert_eq!(
        revision(&call.controller).await,
        before + 1,
        "one barrier retired the debt the stop owed"
    );
    assert!(owed(&call.controller).is_empty());
    assert_eq!(
        call.controller
            .admitted_revision(here)
            .ok()
            .map(|r| r.get()),
        Some(before + 1),
        "the device's connection stays, admitted at the revision now in force"
    );
    assert_eq!(
        call.controller
            .admitted_revision(other)
            .ok()
            .map(|r| r.get()),
        Some(before + 1),
        "and so does every other device's"
    );
    drop(hold);
    call.world.serving.abort();
}

/// KR-REQ-15.13 and 09.12: the owner's revocation of a call's grant while a close is on its way
/// reaches the workers and the connections acting under that grant, which are none, and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_of_a_call_s_grant_while_a_close_is_on_its_way_withdraws_no_connection() {
    let call = Call::start().await;
    let before = revision(&call.controller).await;
    let (here, other) = (
        admit(&call.controller, call.device.device_id).await,
        admit(&call.controller, DeviceId::new(kr_ipc::new_uuid())).await,
    );
    let hold = call
        .controller
        .sharing()
        .grants()
        .hold_close(call.voice_grant_id());

    call.controller
        .revoke_grant(call.voice_grant_id(), super::Audience::Host, None, None)
        .await
        .expect("the owner revokes the call's grant");

    assert_eq!(revision(&call.controller).await, before + 1);
    assert!(owed(&call.controller).is_empty());
    for connection in [here, other] {
        assert_eq!(
            call.controller
                .admitted_revision(connection)
                .ok()
                .map(|r| r.get()),
            Some(before + 1),
            "no connection acts under a call's grant"
        );
    }
    drop(hold);
    call.world.serving.abort();
}

/// An admission that stands, with the time it has left.
#[derive(Debug)]
struct StandingFor(Option<std::time::Duration>);

impl kr_voice::Admission for StandingFor {
    fn still_admitted(&self) -> Result<(), kr_protocol::error::ProtocolError> {
        Ok(())
    }

    fn time_left(&self) -> Option<std::time::Duration> {
        self.0
    }

    fn connection(&self) -> Option<kr_protocol::ids::ConnectionId> {
        Some(kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()))
    }
}

/// How far past the boot clock's reading when the close was performed the worker was told it may
/// take the close up, in milliseconds, for a close performed under an admission with `left` to
/// run.
async fn the_time_a_worker_is_given(call: &Call, left: Option<std::time::Duration>) -> u64 {
    let admission: Arc<dyn kr_voice::Admission> = Arc::new(StandingFor(left));
    call.controller
        .voice_perform(Method::SessionClose, &call.proposal(), &admission)
        .await
        .expect("the close is performed");
    let after = call.controller.shared_clock.boot_elapsed_ms();
    let closes = call.closes();
    assert_eq!(closes.len(), 1, "the worker was forwarded one close");
    let deadline = closes[0].accepted_deadline_boot_ms.get();
    assert!(deadline > 0, "and a deadline");
    deadline.saturating_sub(after)
}

/// KR-REQ-09.16: the deadline a close travels with is the earliest of the close budget, the time
/// the delegation has left and the end of the voice grant, so a worker slow to take it up cannot
/// take it up late. Each bound is the one that decides in one case, and the others are far past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_travels_with_the_earliest_of_its_budget_its_admission_and_its_grant() {
    let ms = |seconds: u64| seconds * 1_000;

    // The budget: the admission and the grant leave far more.
    let call = Call::start().await;
    *call.controller.voice_budgets.lock().expect("the budgets") = VoiceBudgets {
        read: VoiceBudgets::STATED.read,
        close: std::time::Duration::from_secs(7),
    };
    let given = the_time_a_worker_is_given(&call, Some(std::time::Duration::from_secs(300))).await;
    assert!(given <= ms(7), "the budget decides: {given} ms");
    call.world.serving.abort();

    // The time the delegation has left.
    let call = Call::start().await;
    let given = the_time_a_worker_is_given(&call, Some(std::time::Duration::from_secs(3))).await;
    assert!(given <= ms(3), "the admission decides: {given} ms");
    call.world.serving.abort();

    // The end of the voice grant: a call of twenty seconds, against a budget of forty-five.
    let call = Call::start_for(20).await;
    let given = the_time_a_worker_is_given(&call, None).await;
    assert!(given <= ms(20), "the grant decides: {given} ms");
    call.world.serving.abort();

    // And with none of them short of the budget, the worker is given the budget.
    let call = Call::start().await;
    let given = the_time_a_worker_is_given(&call, None).await;
    assert!(
        given > ms(20) && given <= ms(45),
        "the stated budget decides: {given} ms"
    );
    call.world.serving.abort();
}

/// An admission that stands no longer: the connection the delegation arrived on has gone.
#[derive(Debug)]
struct NoLongerStanding(kr_protocol::ids::ConnectionId);

impl kr_voice::Admission for NoLongerStanding {
    fn still_admitted(&self) -> Result<(), kr_protocol::error::ProtocolError> {
        Err(kr_protocol::error::ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the authority this change was admitted under has been withdrawn",
        ))
    }

    fn connection(&self) -> Option<kr_protocol::ids::ConnectionId> {
        Some(self.0)
    }
}

/// KR-REQ-15.13: the admission a delegation arrived under goes with the close to the host, which
/// asks it again before it forwards anything. A close whose admission no longer stands is refused,
/// holds nothing against its grant and reaches no worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_is_not_forwarded_under_an_admission_that_no_longer_stands() {
    let call = Call::start().await;
    let proposal = call.proposal();
    let admission: Arc<dyn kr_voice::Admission> = Arc::new(NoLongerStanding(
        kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
    ));

    let refused = call
        .controller
        .voice_perform(Method::SessionClose, &proposal, &admission)
        .await
        .expect_err("the admission no longer stands");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(call.closes().is_empty(), "nothing reached the worker");
    assert_eq!(call.controller.sharing().grants().closes_held(), 0);
    call.world.serving.abort();
}

/// KR-REQ-15.11: a voice read waits on its worker for a stated time. A worker that answers nothing
/// is an error to the phone once that has passed, and the request is not held for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_of_a_worker_that_answers_nothing_is_an_error_in_time() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let controller = Arc::clone(&world.controller);
    let key = AuthorisationKeyPair::generate().expect("an identity key");
    let device = paired_signing_as(
        &controller,
        62,
        *key.public(),
        &[ActionRight::SessionView],
        None,
    );
    let voice_session_id = call_over(
        &controller,
        device.device_id,
        world.session_id,
        &[VoiceAction::Status],
    )
    .await;
    let number = controller
        .voice_session_number(world.session_id)
        .await
        .expect("the registry reads")
        .expect("the session has a number");
    *controller.voice_budgets.lock().expect("the budgets") = VoiceBudgets {
        read: std::time::Duration::from_millis(200),
        close: VoiceBudgets::STATED.close,
    };
    script.mute_reads(true);

    let asked = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        ask(
            &controller,
            &device.principal(),
            device.device_id,
            &delegation_named(
                "item_status",
                world.environment_id,
                voice_session_id,
                &format!("status of session {number}"),
            ),
        ),
    )
    .await
    .expect("the request is not held for ever");
    let error = asked.expect_err("a worker that answers nothing is an error");
    assert_eq!(error.code(), ErrorCode::ResourceUnavailable, "{error}");
    world.serving.abort();
}

/// KR-REQ-15.20: what a call is told of a session is read within the same time. A worker that
/// answers nothing is an error to the phone once that has passed, and the read is not held for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_context_read_of_a_worker_that_answers_nothing_is_an_error_in_time() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    *world.controller.voice_budgets.lock().expect("the budgets") = VoiceBudgets {
        read: std::time::Duration::from_millis(200),
        close: VoiceBudgets::STATED.close,
    };
    script.mute_reads(true);

    let asked = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        world.controller.voice_session_snapshot(world.session_id),
    )
    .await
    .expect("the read is not held for ever");
    let error = asked.expect_err("a worker that answers nothing is an error");
    assert_eq!(error.code(), ErrorCode::ResourceUnavailable, "{error}");
    world.serving.abort();
}

/// Registers a connection as `device_id`'s, as the network door does for a paired device.
async fn admit(controller: &Controller, device_id: DeviceId) -> kr_protocol::ids::ConnectionId {
    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
    controller
        .admit_connection(
            connection_id,
            &kr_transport::listener::device_principal(&device_id),
            &kr_ipc::peer::PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
            kr_protocol::local::LocalClientKind::Cli,
        )
        .await
        .expect("the connection is registered");
    connection_id
}
