//! A package's component prepares an action's effect, and the worker carries out what it validates
//! and nothing else.
//!
//! A real daemon, this test process as the worker it started (with its own journal and broker), a
//! real plugin host started by the daemon on the worker's request, and a real component that
//! prepares each action in the way its name says. The upstream is the one thing played: a scripted
//! peer on the other end of the production transport, which records the frames the worker writes
//! and answers them as a vendor's server would. Everything between a request and that peer is the
//! product: the receipt journal, the dispatch barrier, the broker, the plugin service protocol and
//! the engine that runs the component.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-23.30 | `plugin.action.invoke` runs the component registered for the binding, validates the plan it proposes against the action, the grant, the effect class and the arguments, transmits the plan that validates once, and rejects every other with a receipt that says it never dispatched |
//! | KR-REQ-11.28, KR-REQ-23.30 | through a connector whose table spells a cancellation, the plan a component prepares for the cancellation it was invited to prepare is validated against the token the host issued and written from the table's template, naming the thread and the running turn; every plan that is not that one, and a component's prompt, which the table spells no source for, is refused before the marker and nothing is written |
//! | KR-REQ-11.31 | a component that faults when asked to prepare an action disables its binding's rich capability, and the native terminal's requests and answers go on before, during and after, on the transport the production gateway uses (not through `kr-hook launch`, whose leg needs a real managed shell) |
//!
//! The scripted peer stands in for a vendor's agent. A test that needs a stopped plugin host stops
//! the real one and lets it go, and every wait is for a condition the product reaches.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_protocol::admission::ComponentState;
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ControllerGeneration, RequestId};
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ActionCancelParams, ActionReadParams, ActionReadResult};
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::scalars::{DurationMs, Nullable, Uuid};

mod plugin_world;

use plugin_world::acting::{
    ACTIONS, Acting, Change, answer, binding, read_receipt, send, signal, until_receipt,
    until_settled,
};
use plugin_world::{PATIENCE, kill};

/// KR-REQ-23.30: the plan a component proposes for the cancellation it was invited to prepare is
/// validated and transmitted once, as the method its action goes out as, and the receipt says the
/// upstream acknowledged it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_component_prepares_a_cancellation_and_the_worker_transmits_it_once() {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut client = acting.client().await;
    let mutation = acting.invocation(&client, "turn.cancel", b"{}");
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the prepared cancellation is carried out: {outcome:?}"
    );
    let frames = acting.frames();
    assert_eq!(frames.len(), 1, "the upstream was written once: {frames:?}");
    let frame: serde_json::Value = serde_json::from_str(&frames[0]).expect("a JSON frame");
    assert_eq!(frame["method"], "turn.cancel");
    assert_eq!(frame["params"]["action"], "turn.cancel");
    assert_eq!(frame["params"]["operation"], "upstream_cancel");
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Applied
    );

    // And the prompt the component prepares as the routed method of its own name.
    let mutation = acting.invocation(&client, "prompt.send", b"{}");
    let sent = send(&mut client, mutation).await;
    assert!(matches!(sent, Outcome::Ok(_)), "{sent:?}");
    assert_eq!(acting.frames().len(), 2, "one more frame, for the prompt");
}

/// KR-REQ-11.28 and KR-REQ-23.30: through a connector whose table spells a cancellation as a
/// template, with a thread bound and a turn running, the plan the real component prepares for the
/// cancellation it was invited to prepare is written from the template, naming the thread and the
/// turn the host read, and the receipt says the upstream acknowledged it. Every plan the component
/// prepares that is not the invitation's own is refused with a receipt that says it never
/// dispatched, and so is a prompt, which the table spells no source for; nothing more is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_28_a_components_cancellation_is_written_from_the_connectors_template_and_no_other_plan_is()
 {
    let Some(acting) = Acting::start_templated().await else {
        return;
    };
    let mut client = acting.client().await;
    let mutation = acting.invocation(&client, "turn.cancel", b"{}");
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the prepared cancellation is carried out: {outcome:?}"
    );
    let frames = acting.frames();
    assert_eq!(frames.len(), 1, "the upstream was written once: {frames:?}");
    let frame: serde_json::Value = serde_json::from_str(&frames[0]).expect("a JSON frame");
    assert_eq!(frame["method"], "turn/interrupt");
    assert_eq!(
        frame["params"],
        serde_json::json!({ "threadId": "thread-1", "turnId": "turn-7" }),
        "the template filled in with what the host read"
    );
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Applied
    );

    // Every plan that is not the invitation's own is refused, as it is without a template, and so
    // is a component's prompt: the table spells nothing a component's text could go into.
    let written = acting.frames().len();
    let refused: Vec<&str> = ACTIONS
        .iter()
        .map(|(action, _)| *action)
        .filter(|action| {
            !["turn.cancel", "cancel.reasoned"].contains(action)
                && !action.starts_with("attach.")
                && ![
                    "cancel.fault",
                    "cancel.loop",
                    "cancel.terminal",
                    "cancel.present",
                ]
                .contains(action)
        })
        .collect();
    assert!(
        refused.contains(&"cancel.other.arguments") && refused.contains(&"prompt.send"),
        "{refused:?}"
    );
    for (request_id, action) in (10..).zip(refused) {
        let mut mutation = acting.invocation(&client, action, b"{}");
        mutation.request_id = RequestId::new(request_id);
        let action_id = mutation.action_id;
        let outcome = send(&mut client, mutation).await;
        let Outcome::Error(error) = outcome else {
            panic!("{action}: a plan that is not the invocation's own was carried: {outcome:?}");
        };
        if action == "prompt.send" {
            assert_eq!(error.code, ErrorCode::UnsupportedCapability, "{error:?}");
            assert!(
                error.message.contains("source"),
                "the refusal names what the table lacks: {}",
                error.message
            );
        }
        assert_eq!(
            read_receipt(&mut client, action_id)
                .await
                .expect("a receipt")
                .state,
            ReceiptState::Rejected,
            "{action}: the action never dispatched"
        );
    }
    assert_eq!(
        acting.frames().len(),
        written,
        "nothing more was written to the upstream"
    );
}

/// KR-REQ-23.30: every plan a component proposes that is not the invocation's own is refused, each
/// for its own reason, with a receipt that says the action never dispatched, and nothing is written
/// to the upstream. A component that declines, and one that never returns, cost their own action.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_plan_that_is_not_the_invocations_own_is_rejected_and_nothing_is_written() {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut client = acting.client().await;
    // The right plan first, so that the binding is shown to prepare before it is shown to refuse.
    let first = acting.invocation(&client, "turn.cancel", b"{}");
    assert!(matches!(send(&mut client, first).await, Outcome::Ok(_)));
    let written = acting.frames().len();

    // Every action but the ones that prepare the right plan and the attachment ones, which need a
    // draft and are shown in `plugin_insertion.rs`: the rest each prepare a plan that is wrong.
    const RIGHT: [&str; 3] = ["turn.cancel", "prompt.send", "cancel.reasoned"];
    let wrong = ACTIONS
        .iter()
        .filter(|(action, _)| !RIGHT.contains(action) && !action.starts_with("attach."));
    for (request_id, (action, _)) in (10..).zip(wrong) {
        let mut mutation = acting.invocation(&client, action, b"{}");
        mutation.request_id = RequestId::new(request_id);
        let action_id = mutation.action_id;
        let outcome = send(&mut client, mutation).await;
        let Outcome::Error(refusal) = outcome else {
            panic!("{action}: a plan that is not the invocation's own was carried: {outcome:?}");
        };
        // A component that does not answer in time is not one that proposed a wrong plan: asking
        // again can succeed.
        let expected = if *action == "cancel.loop" {
            ErrorCode::ResourceUnavailable
        } else {
            ErrorCode::InvalidArgument
        };
        assert_eq!(refusal.code, expected, "{action}: {refusal:?}");
        let receipt = read_receipt(&mut client, action_id)
            .await
            .expect("a receipt");
        assert_eq!(
            receipt.state,
            ReceiptState::Rejected,
            "{action}: the action never dispatched, so it is rejected and not refused or unknown"
        );
    }
    assert_eq!(
        acting.frames().len(),
        written,
        "nothing was written to the upstream for any of them"
    );
}

/// KR-REQ-23.30: an invocation's arguments are the ones its action declares. An argument no
/// declaration names, a required one that is missing and a value of the wrong kind or outside its
/// bounds are each rejected with a receipt before the component is asked, and the arguments that
/// are the declared ones reach the component and the upstream as they were given.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_arguments_other_than_the_declared_ones_are_rejected_before_the_component_is_asked()
 {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut client = acting.client().await;
    for (request_id, (arguments, why)) in (20..).zip([
        (r#"{}"#, "a required parameter is missing"),
        (r#"{"reason":3}"#, "a value of the wrong kind"),
        (
            r#"{"reason":"a reason that is far too long to be accepted"}"#,
            "a value out of bounds",
        ),
        (
            r#"{"reason":"ok","extra":"x"}"#,
            "an argument no declaration names",
        ),
        (r#"{"reason":null}"#, "a null where a value belongs"),
        (r#"["reason"]"#, "arguments that are not an object"),
    ]) {
        let mut mutation = acting.invocation(&client, "cancel.reasoned", arguments.as_bytes());
        mutation.request_id = RequestId::new(request_id);
        let action_id = mutation.action_id;
        let outcome = send(&mut client, mutation).await;
        let Outcome::Error(refusal) = outcome else {
            panic!("{why}: the invocation was carried: {outcome:?}");
        };
        assert_eq!(
            refusal.code,
            ErrorCode::InvalidArgument,
            "{why}: {refusal:?}"
        );
        assert_eq!(
            read_receipt(&mut client, action_id)
                .await
                .expect("a receipt")
                .state,
            ReceiptState::Rejected,
            "{why}"
        );
    }
    assert!(
        acting.frames().is_empty(),
        "nothing was written: {:?}",
        acting.frames()
    );

    let mut mutation = acting.invocation(&client, "cancel.reasoned", br#"{"reason":"because"}"#);
    mutation.request_id = RequestId::new(30);
    let outcome = send(&mut client, mutation).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    let frames = acting.frames();
    assert_eq!(frames.len(), 1, "{frames:?}");
    let frame: serde_json::Value = serde_json::from_str(&frames[0]).expect("a JSON frame");
    assert_eq!(frame["params"]["parameters"]["reason"], "because");
}

/// KR-REQ-23.30: an action whose component is being asked has a receipt that says so. An exact
/// repeat is answered with it and prepares nothing a second time; the connection goes on serving
/// the same client meanwhile; a cancellation rejects the action; and the action that comes back
/// from its preparation transmits nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_action_waiting_for_its_component_can_be_read_repeated_and_cancelled() {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut asking = acting.client().await;
    let mut other = acting.client().await;
    let mutation = acting.invocation(&asking, "turn.cancel", b"{}");
    let action_id = mutation.action_id;

    acting.stop_host();
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation.clone())))
        .await
        .expect("writes the mutation");
    // The action is accepted and waiting: its receipt says so, and nothing has been dispatched.
    let waiting = until_receipt(&mut other, action_id, ReceiptState::Accepted).await;
    assert_eq!(waiting.state, ReceiptState::Accepted);

    // The same connection still serves its client while the action waits: a read is answered
    // before the action is.
    let own = read_receipt(&mut asking, action_id)
        .await
        .expect("the action's own connection answers a read");
    assert_eq!(own.state, ReceiptState::Accepted);

    // An exact repeat, from another connection, is answered with the receipt as it stands.
    let repeated = send(&mut other, mutation.clone()).await;
    let Outcome::Ok(value) = repeated else {
        panic!("a repeat is answered with the receipt: {repeated:?}");
    };
    assert!(
        format!("{:?}", value.as_value()).contains("accepted"),
        "{value:?}"
    );

    // A cancellation rejects the action before it is dispatched.
    let mut cancel = acting.invocation(&other, "turn.cancel", b"{}");
    cancel.method = Method::ActionCancel.into();
    cancel.action_id = ActionId::new(kr_ipc::new_uuid());
    cancel.target = ActionTarget {
        environment_id: acting.hosted.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    cancel.params = ParamsValue::from_typed(&ActionCancelParams { action_id }).expect("encodes");
    let cancelled = send(&mut other, cancel).await;
    assert!(matches!(cancelled, Outcome::Ok(_)), "{cancelled:?}");
    let rejected = until_receipt(&mut other, action_id, ReceiptState::Rejected).await;
    assert_eq!(
        rejected.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::Cancelled)
    );

    // The host is let go. The preparation ends, the action comes back for its marker, finds its
    // receipt is no longer accepted, and transmits nothing.
    let host = acting.hosted.published().expect("the host is published");
    signal(&host, rustix::process::Signal::CONT);
    let finished = answer(&mut asking, Some(1)).await;
    let Outcome::Ok(value) = finished else {
        panic!("a cancelled action is answered with the receipt it has: {finished:?}");
    };
    assert!(
        format!("{:?}", value.as_value()).contains("rejected"),
        "{value:?}"
    );
    assert_eq!(
        read_receipt(&mut other, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Rejected
    );
    assert!(
        acting.frames().is_empty(),
        "a cancelled action wrote nothing to the upstream: {:?}",
        acting.frames()
    );
}

/// Accepts one action, holds its component, makes `change`, lets the component go and shows the
/// action rejected with nothing written to the upstream. Returns the rejected receipt, or nothing
/// where the test components are not built.
async fn rejected_after(change: Change) -> Option<Receipt> {
    let acting = Acting::start().await?;
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.invocation(&asking, "turn.cancel", b"{}");
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;
    let mut asking = Some(asking);
    acting.change(change, "turn.cancel", &mut asking).await;
    signal(&host, rustix::process::Signal::CONT);
    // The action has come back from its component and been answered, so that what was not written
    // was left unwritten by the second pass and not by a preparation still waiting.
    if let Some(asking) = asking.as_mut() {
        answer(asking, Some(1)).await;
    }
    // Any final state, so that an action that was dispatched fails here at once and not after a
    // wait for a rejection that never comes.
    let receipt = until_settled(&mut watcher, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert!(receipt.reason.is_present(), "{receipt:?}");
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
    Some(receipt)
}

/// KR-REQ-23.30: the grant an action was accepted under is checked again when it comes back from
/// its component.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_grant_withdrawn_while_the_component_prepared_rejects_the_action() {
    let Some(receipt) = rejected_after(Change::Grant).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::AdmissionFailed),
        "{receipt:?}"
    );
}

/// KR-REQ-23.30: the declaration an action was accepted under is the one in force when it comes
/// back from its component. An action registered again as another class its component prepares is
/// a different action.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_declaration_replaced_while_the_component_prepared_rejects_the_action() {
    let Some(receipt) = rejected_after(Change::Declaration).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::StalePreconditions),
        "{receipt:?}"
    );
}

/// KR-REQ-23.30: an action registered again as one the host carries out itself, by redrawing the
/// package's own document, would be applied if the plan prepared for the first were not held to
/// the first's declaration. It is rejected, whichever route its new declaration names.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_action_registered_as_a_presentation_while_prepared_is_not_applied() {
    let Some(receipt) = rejected_after(Change::Presentation).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::StalePreconditions),
        "{receipt:?}"
    );
}

/// KR-REQ-23.30 and KR-REQ-11.28: the binding revision an action was invoked under is the one in
/// force when it comes back from its component, and an action whose binding moved while it was
/// prepared is rejected as stale.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_binding_that_moved_while_the_component_prepared_rejects_the_action() {
    let Some(receipt) = rejected_after(Change::Binding).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::StalePreconditions),
        "{receipt:?}"
    );
    assert_eq!(
        receipt.error.as_ref().map(|error| error.code),
        Some(ErrorCode::StaleSession),
        "{receipt:?}"
    );
}

/// KR-REQ-23.30 and KR-REQ-09.12: an authority revision the daemon announces while an action's
/// component prepares it revokes the action, which never dispatches.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_authority_revision_announced_while_the_component_prepared_revokes_the_action()
 {
    let Some(receipt) = rejected_after(Change::Authority).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::Revoked),
        "{receipt:?}"
    );
}

/// A paired device, as the daemon vouches for it to a worker whose daemon is of `generation`, with
/// a grant it checked at authority revision 1.
fn a_paired_device(generation: ControllerGeneration) -> kr_protocol::actor::ActorEnvelope {
    kr_protocol::actor::ActorEnvelope {
        actor_id: kr_protocol::ids::ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: kr_protocol::actor::ActorIngress::PairedDevice,
        device_id: Nullable::some(kr_protocol::ids::DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::some(kr_protocol::ids::AuthorityRevision::new(1)),
        controller_generation: generation,
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
    }
}

/// The daemon's announcement to the worker of authority revision `revision`, over its authority
/// connection, which the worker acknowledges.
async fn announce(authority: &mut kr_ipc::client::BoundLink, acting: &Acting, revision: u64) {
    authority
        .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: acting.hosted.environment_id,
            revision: kr_protocol::ids::AuthorityRevision::new(revision),
            reach: kr_protocol::worker::RevisionReach::Host,
            evidence_from: 0,
        })
        .await
        .expect("the worker installs the revision");
}

/// Reads `action_id`'s receipt for the device over its proxy until it is `accepted`, which is
/// when the daemon's action is waiting for its component.
async fn until_the_devices_action_is_accepted(
    proxy: &mut kr_ipc::client::BoundLink,
    device: &kr_protocol::actor::ActorEnvelope,
    action_id: ActionId,
) {
    for _ in 0..2_400 {
        proxy
            .send(&ControlFrame::ForwardedRead(Box::new(
                kr_protocol::local::ForwardedRequest {
                    request: kr_protocol::envelope::Request {
                        request_id: RequestId::new(900),
                        method: Method::ActionRead.into(),
                        method_version: MethodVersion::V1,
                        params: ParamsValue::from_typed(&ActionReadParams {
                            action_id,
                            session_id: None,
                        })
                        .expect("encodes"),
                    },
                    actor: device.clone(),
                    authority_deadline_boot_ms: Nullable::null(),
                    history: None,
                },
            )))
            .await
            .expect("writes the read");
        if let Outcome::Ok(value) = answer(proxy, Some(900)).await
            && value
                .to_typed::<ActionReadResult>()
                .expect("decodes")
                .receipt
                .state
                == ReceiptState::Accepted
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the forwarded action was never accepted");
}

/// KR-REQ-23.30 and KR-REQ-09.12: an action the daemon forwarded for a paired device, revoked
/// while its component prepares it, is answered to the daemon with the rejected receipt, and
/// nothing is written to the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_forwarded_action_revoked_while_the_component_prepared_is_answered_with_its_receipt()
 {
    let Some(acting) = Acting::start().await else {
        return;
    };
    // The daemon forwards a paired device's action over a proxy of that device's own, and announces
    // authority revisions over its authority connection.
    let mut proxy = acting
        .hosted
        .daemon_connection(ControllerConnectionRole::Proxy)
        .await;
    let mut authority = acting
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    let device = a_paired_device(acting.hosted.controller_generation);
    // The worker has acknowledged the revision the device's grant was checked at, as a daemon
    // makes sure of before it takes the lease the action travels with.
    announce(&mut authority, &acting, 1).await;
    let mutation = acting.invocation(&proxy, "turn.cancel", b"{}");
    let request_id = mutation.request_id.get();
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    proxy
        .send(&ControlFrame::Forwarded(Box::new(
            kr_protocol::local::ForwardedMutation {
                mutation,
                actor: device.clone(),
                grant_rights: [kr_protocol::rights::ActionRight::AgentCancel]
                    .into_iter()
                    .collect(),
                accepted_deadline_boot_ms: kr_protocol::scalars::U64::new(
                    kr_ipc::clock::boot_elapsed_ms() + 30_000,
                ),
                history: None,
                screen_basis: None,
                workflow_run_id: None,
                lease: Some(a_lease(&acting, 1, 5_000)),
            },
        )))
        .await
        .expect("writes the forwarded mutation");
    // The action is accepted and being prepared when the daemon revokes what its device held: it
    // announces the next authority revision over the connection it holds the worker's authority
    // by. The device reads its own receipt through the daemon to know.
    until_the_devices_action_is_accepted(&mut proxy, &device, action_id).await;
    announce(&mut authority, &acting, 2).await;
    signal(&host, rustix::process::Signal::CONT);
    // A retained answer, which the daemon holds back from a device whose authority has moved: a
    // plain response would reach the device unchecked.
    let response = loop {
        match proxy.recv().await.expect("the worker answers") {
            ControlFrame::RetainedResponse(response) if response.request_id.get() == request_id => {
                break *response;
            }
            ControlFrame::Response(response) if response.request_id.get() == request_id => {
                panic!("a fenced action was answered as if it had been performed: {response:?}");
            }
            _ => {}
        }
    };
    let Outcome::Ok(value) = response.outcome else {
        panic!("a revoked action is answered with its receipt: {response:?}");
    };
    assert!(
        format!("{:?}", value.as_value()).contains("rejected"),
        "{value:?}"
    );
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
}

/// A remote dispatch lease of the worker's generation for revision `revision` that ends `ms` from
/// now on the machine's clock.
fn a_lease(acting: &Acting, revision: u64, ms: u64) -> kr_protocol::local::ForwardedLease {
    kr_protocol::local::ForwardedLease {
        lease_id: kr_protocol::ids::RemoteDispatchLeaseId::new(kr_ipc::new_uuid()),
        controller_generation: acting.hosted.controller_generation,
        authority_revision: kr_protocol::ids::AuthorityRevision::new(revision),
        deadline_boot_ms: kr_protocol::scalars::U64::new(kr_ipc::clock::boot_elapsed_ms() + ms),
    }
}

/// KR-REQ-09.10: the lease a paired device's action was accepted under is checked again when it
/// comes back from its component. The lease ends while the component prepares the action, the
/// accepted deadline is still thirty seconds off, and the worker rejects the action as expired
/// without a dispatch marker and writes nothing to the upstream.
///
/// The worker's deadlines are measured on a clock the test moves, so the lease ends because the
/// test moved the clock past it and not because the test waited for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_09_10_a_lease_that_ends_while_the_component_prepared_rejects_the_action() {
    let clock = kr_transport::clock::ManualClock::new();
    let Some(acting) = Acting::start_on(Arc::new(clock.clone())).await else {
        return;
    };
    let mut proxy = acting
        .hosted
        .daemon_connection(ControllerConnectionRole::Proxy)
        .await;
    let mut authority = acting
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    let device = a_paired_device(acting.hosted.controller_generation);
    announce(&mut authority, &acting, 1).await;
    let mutation = acting.invocation(&proxy, "turn.cancel", b"{}");
    let request_id = mutation.request_id.get();
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    proxy
        .send(&ControlFrame::Forwarded(Box::new(
            kr_protocol::local::ForwardedMutation {
                mutation,
                actor: device.clone(),
                grant_rights: [kr_protocol::rights::ActionRight::AgentCancel]
                    .into_iter()
                    .collect(),
                accepted_deadline_boot_ms: kr_protocol::scalars::U64::new(
                    kr_ipc::clock::boot_elapsed_ms() + 30_000,
                ),
                history: None,
                screen_basis: None,
                // Three seconds, against an accepted deadline of thirty.
                workflow_run_id: None,
                lease: Some(a_lease(&acting, 1, 3_000)),
            },
        )))
        .await
        .expect("writes the forwarded mutation");
    // The action is accepted, and its lease is good: it waits for its component.
    until_the_devices_action_is_accepted(&mut proxy, &device, action_id).await;
    // Only the lease ends: the clock passes it, and the accepted deadline has twenty-six seconds.
    clock.advance(Duration::from_secs(4));
    signal(&host, rustix::process::Signal::CONT);
    let response = loop {
        match proxy.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) if response.request_id.get() == request_id => {
                break response;
            }
            ControlFrame::RetainedResponse(response) if response.request_id.get() == request_id => {
                panic!("the action was answered from a receipt it should not have: {response:?}");
            }
            _ => {}
        }
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("an action whose lease ended is refused: {response:?}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    // Its receipt says it was rejected as expired, and was never dispatched.
    proxy
        .send(&ControlFrame::ForwardedRead(Box::new(
            kr_protocol::local::ForwardedRequest {
                request: kr_protocol::envelope::Request {
                    request_id: RequestId::new(901),
                    method: Method::ActionRead.into(),
                    method_version: MethodVersion::V1,
                    params: ParamsValue::from_typed(&ActionReadParams {
                        action_id,
                        session_id: None,
                    })
                    .expect("encodes"),
                },
                actor: device,
                authority_deadline_boot_ms: Nullable::null(),
                history: None,
            },
        )))
        .await
        .expect("writes the read");
    let Outcome::Ok(read) = answer(&mut proxy, Some(901)).await else {
        panic!("the device reads its own receipt");
    };
    let receipt = read
        .to_typed::<ActionReadResult>()
        .expect("decodes")
        .receipt;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::Expired),
        "{receipt:?}"
    );
    assert!(!receipt.state.has_dispatch_marker());
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
}

/// KR-REQ-23.30: an action whose connection ended while its component prepared it can be
/// dispatched by nothing, and is rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_connection_that_ended_while_the_component_prepared_rejects_the_action() {
    let Some(receipt) = rejected_after(Change::Connection).await else {
        return;
    };
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::AdmissionFailed),
        "{receipt:?}"
    );
}

/// KR-REQ-23.30: an action is answered within its own deadline whatever its component does. With
/// the plugin host stopped, a call that is never answered is given up on, and the action is
/// rejected, while the host is still stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_component_that_does_not_answer_costs_its_action_and_nothing_else() {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut client = acting.client().await;
    let mut mutation = acting.invocation(&client, "turn.cancel", b"{}");
    mutation.requested_ttl_ms = DurationMs::new(1_500);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(refusal) = outcome else {
        panic!("an action whose component is silent was carried: {outcome:?}");
    };
    // The host has not been let go: the answer came from the bound on the call, and it is a
    // rejection either way, for the call that was given up on or for the deadline that passed.
    let receipt = read_receipt(&mut client, action_id)
        .await
        .expect("a receipt");
    assert_eq!(receipt.state, ReceiptState::Rejected, "{refusal:?}");
    assert!(
        matches!(
            receipt.reason.as_ref(),
            Some(
                kr_protocol::receipt::RejectionReason::Expired
                    | kr_protocol::receipt::RejectionReason::AdmissionFailed
            )
        ),
        "{receipt:?}"
    );
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
    signal(&host, rustix::process::Signal::CONT);
}

/// KR-REQ-23.30: a plugin runtime that ends while an action's component is being asked costs the
/// action the code that says asking again can succeed, as one that was gone before the call does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_runtime_that_ends_during_the_call_costs_its_action_a_retryable_code() {
    let Some(acting) = Acting::start().await else {
        return;
    };
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.invocation(&asking, "turn.cancel", b"{}");
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;
    kill(&host);
    let Outcome::Error(refusal) = answer(&mut asking, Some(1)).await else {
        panic!("an action whose runtime ended was carried");
    };
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable, "{refusal:?}");
    assert_eq!(
        read_receipt(&mut watcher, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Rejected
    );
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
}

/// KR-REQ-23.30: a component that is not there to ask costs its action the code that says whether
/// asking again can succeed. One the link has not yet registered, one still being registered and
/// one the runtime lost can be asked again; one the worker has disabled cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_action_whose_component_is_not_there_is_rejected_for_the_reason_it_is_not()
{
    let Some(acting) = Acting::start_with(false).await else {
        return;
    };
    let broker = acting.hosted._service.broker();
    let mut client = acting.client().await;
    let mut request_id = 40;
    let mut invoke = async |acting: &Acting, client: &mut LocalClient| {
        request_id += 1;
        let mut mutation = acting.invocation(client, "turn.cancel", b"{}");
        mutation.request_id = RequestId::new(request_id);
        let action_id = mutation.action_id;
        let Outcome::Error(refusal) = send(client, mutation).await else {
            panic!("an action with no component to prepare it was carried");
        };
        assert_eq!(
            read_receipt(client, action_id)
                .await
                .expect("a receipt")
                .state,
            ReceiptState::Rejected
        );
        refusal.code
    };
    assert_eq!(
        invoke(&acting, &mut client).await,
        ErrorCode::ResourceUnavailable,
        "a binding the link has not got to yet"
    );
    broker.set_component_state(binding(), ComponentState::Pending, None);
    assert_eq!(
        invoke(&acting, &mut client).await,
        ErrorCode::ResourceUnavailable,
        "a component being registered"
    );
    broker.set_component_state(
        binding(),
        ComponentState::Unavailable,
        Some("the plugin runtime ended"),
    );
    assert_eq!(
        invoke(&acting, &mut client).await,
        ErrorCode::ResourceUnavailable,
        "a runtime that is gone"
    );
    broker.disable_rich(binding(), "its component faulted too often");
    assert_eq!(
        invoke(&acting, &mut client).await,
        ErrorCode::UnsupportedCapability,
        "a component the worker disabled"
    );
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
}

/// KR-REQ-11.31: a component that faults disables the rich capability of its binding without
/// stalling the native terminal's traffic.
///
/// The worker's own link runs, so the plugin runtime's notice that it disabled a binding reaches the
/// broker, and the plugin host's epoch runs, so the component that never returns is stopped by its
/// deadline. A native terminal is served on the transport the production gateway uses: its requests
/// are carried upstream and answered, before the component is asked, while the plugin host is held
/// with a call to the component waiting on it, between the faults, and after the binding is
/// disabled. Once it is, a rich action is refused and nothing is written to the upstream for it.
///
/// Not claimed: a launch through `kr-hook launch` (the terminal here is the transport's client end,
/// not a program in a managed shell), and Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_31_a_component_that_faults_disables_its_binding_and_the_native_terminal_goes_on()
{
    let Some(acting) = Acting::start_faulting().await else {
        return;
    };
    let broker = acting.hosted._service.broker();
    let mut client = acting.client().await;
    let mut native = 0_u64;

    // The terminal's traffic goes on while the link registers the component, and a rich action is
    // carried as soon as it has.
    native += 1;
    acting.native_round_trip(native).await;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut number = 0_u64;
    loop {
        number += 1;
        let mut mutation = acting.invocation(&client, "turn.cancel", b"{}");
        mutation.request_id = RequestId::new(number);
        match send(&mut client, mutation).await {
            Outcome::Ok(_) => break,
            Outcome::Error(refusal) => assert_eq!(
                refusal.code,
                ErrorCode::ResourceUnavailable,
                "an action that cannot be prepared yet can be asked again: {refusal:?}"
            ),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {PATIENCE:?} for the component to prepare an action"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        broker.rich_disabled(binding()).is_none(),
        "the binding works before it faults"
    );
    let rich_frames = acting.frames().len() - native as usize;
    assert_eq!(
        rich_frames,
        1,
        "one rich action went: {:?}",
        acting.frames()
    );

    // The first fault is asked while the plugin host is held: the call waits on the host, the
    // terminal's request is carried and answered meanwhile, and the call faults when the host runs.
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mut mutation = acting.invocation(&asking, "cancel.loop", b"{}");
    mutation.request_id = RequestId::new(1);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;
    native += 1;
    acting.native_round_trip(native).await;
    signal(&host, rustix::process::Signal::CONT);
    let Outcome::Error(refusal) = answer(&mut asking, Some(1)).await else {
        panic!("an action whose component never returns was carried");
    };
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable, "{refusal:?}");

    // More faults, with the terminal's traffic between them, until the runtime disables the
    // binding and the link tells the broker.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while broker.rich_disabled(binding()).is_none() {
        number += 1;
        let mut mutation = acting.invocation(&client, "cancel.loop", b"{}");
        mutation.request_id = RequestId::new(number);
        let outcome = send(&mut client, mutation).await;
        assert!(
            matches!(outcome, Outcome::Error(_)),
            "an action whose component never returns was carried: {outcome:?}"
        );
        native += 1;
        acting.native_round_trip(native).await;
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {PATIENCE:?} for the binding to be disabled"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reason = broker
        .rich_disabled(binding())
        .expect("the binding is disabled");
    assert!(!reason.is_empty(), "and it says why");

    // Rich is refused, the terminal goes on, and nothing was written for the faulted actions.
    number += 1;
    let mut mutation = acting.invocation(&client, "turn.cancel", b"{}");
    mutation.request_id = RequestId::new(number);
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("a rich action was carried by a binding the worker disabled");
    };
    assert_eq!(
        refusal.code,
        ErrorCode::UnsupportedCapability,
        "{refusal:?}"
    );
    native += 1;
    acting.native_round_trip(native).await;
    let frames = acting.frames();
    assert_eq!(
        frames.len(),
        native as usize + rich_frames,
        "the upstream was written the terminal's requests and the one rich action that prepared: \
         {frames:?}"
    );
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame.contains("session/prompt"))
            .count(),
        native as usize
    );
}
