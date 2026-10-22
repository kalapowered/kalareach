//! A revocation committed while a paired device's accepted action is held.
//!
//! Section 9 draws the sequence this suite plays: a worker has durably accepted a device's intent
//! and has not dispatched it, the device's authority is revoked while the intent is held, and when
//! the worker goes on, the intent never executes. A real daemon, this test process as the worker it
//! started, a real plugin host started on the worker's request and a scripted upstream behind the
//! production transport, as the plugin-action suites have them (`plugin_world`).
//!
//! The action is held in its preparation. A plugin action is prepared by its package's component
//! outside the worker's dispatch boundary, after the worker has accepted the intent durably and
//! before it writes the dispatch marker; the plugin host is stopped, so the intent waits there,
//! while the worker goes on answering the daemon over the connections the daemon holds. That is a
//! worker paused after durable acceptance with its control path live, which is what lets the
//! revocation's barrier be reached while the intent is held.

#![cfg(unix)]

use kr_protocol::envelope::Outcome;
use kr_protocol::ids::ActionId;
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::receipt::ReceiptState;

mod plugin_world;

use plugin_world::acting::{
    Acting, a_lease, a_paired_device, announce, signal, until_the_devices_receipt_is,
};

/// A paired device's action, forwarded by the daemon and accepted by the worker, held while its
/// component prepares it.
///
/// The plugin host is stopped, so the action has a receipt that says `accepted`, no dispatch marker
/// and nothing written to the upstream.
struct HeldDeviceAction {
    acting: Acting,
    proxy: kr_ipc::client::BoundLink,
    authority: kr_ipc::client::BoundLink,
    device: kr_protocol::actor::ActorEnvelope,
    request_id: u64,
    action_id: ActionId,
    host: kr_protocol::identity::ProcessStartIdentity,
}

impl HeldDeviceAction {
    /// Holds a device's `turn.cancel` in its preparation, or nothing where the test components
    /// are not built.
    async fn begin() -> Option<Self> {
        let acting = Acting::start().await?;
        let mut proxy = acting
            .hosted
            .daemon_connection(ControllerConnectionRole::Proxy)
            .await;
        let mut authority = acting
            .hosted
            .daemon_connection(ControllerConnectionRole::Authority)
            .await;
        let device = a_paired_device(acting.hosted.controller_generation);
        // The worker has acknowledged the revision the device's grant was checked at.
        announce(&mut authority, &acting, 1).await;
        let mutation = acting.invocation(&proxy, "turn.cancel", b"{}");
        let request_id = mutation.request_id.get();
        let action_id = mutation.action_id;
        let host = acting.stop_host();
        proxy
            .send(&kr_protocol::envelope::ControlFrame::Forwarded(Box::new(
                kr_protocol::local::ForwardedMutation {
                    mutation,
                    actor: device.clone(),
                    grant_rights: [kr_protocol::rights::ActionRight::AgentCancel]
                        .into_iter()
                        .collect(),
                    accepted_deadline_boot_ms: kr_protocol::scalars::U64::new(
                        kr_ipc::clock::boot_elapsed_ms() + 60_000,
                    ),
                    history: None,
                    screen_basis: None,
                    workflow_run_id: None,
                    lease: Some(a_lease(&acting, 1, 60_000)),
                },
            )))
            .await
            .expect("writes the forwarded mutation");
        let accepted =
            until_the_devices_receipt_is(&mut proxy, &device, action_id, ReceiptState::Accepted)
                .await;
        assert!(
            !accepted.state.has_dispatch_marker(),
            "the held action has no dispatch marker: {accepted:?}"
        );
        assert!(
            acting.frames().is_empty(),
            "the held action has written nothing to the upstream: {:?}",
            acting.frames()
        );
        Some(Self {
            acting,
            proxy,
            authority,
            device,
            request_id,
            action_id,
            host,
        })
    }

    /// Lets the plugin host go on, and reads the daemon's answer to the forwarded action, with
    /// whether the worker sent it retained: the daemon holds a retained answer back from a device
    /// whose authority has moved, where a plain response would reach the device unchecked.
    async fn resumed(&mut self) -> (kr_protocol::envelope::Response, bool) {
        signal(&self.host, rustix::process::Signal::CONT);
        loop {
            match self.proxy.recv().await.expect("the worker answers") {
                kr_protocol::envelope::ControlFrame::RetainedResponse(response)
                    if response.request_id.get() == self.request_id =>
                {
                    return (*response, true);
                }
                kr_protocol::envelope::ControlFrame::Response(response)
                    if response.request_id.get() == self.request_id =>
                {
                    return (response, false);
                }
                _ => {}
            }
        }
    }

    /// The receipt the worker's journal holds for the device's action: the device's own reads are
    /// refused once its authority has moved, so what the worker kept is read where it keeps it.
    fn receipt_kept(&self) -> kr_protocol::receipt::Receipt {
        let mut session = self.acting.hosted._runtime.session();
        session
            .journal_mut()
            .expect("a journal")
            .read(self.device.actor_id.clone(), self.action_id)
            .expect("the journal reads")
            .expect("the worker kept the action's receipt")
    }
}

/// KR-ACC-022: a paired device's intent that the worker accepted durably and has not dispatched is
/// taken back by a revocation committed while it is held, and never executes.
///
/// The sequence is section 9's. The device's action is accepted and held: its receipt says
/// `accepted`, with no dispatch marker, and nothing is written to the upstream. The revocation is
/// committed while it is held, as the daemon's next authority revision announced over the
/// connection the worker answers on, and the worker's acknowledgement carries the fence's
/// evidence, which names the action as one it took back, under the device that made it, and none
/// as one that may have executed. The worker then resumes, and the action is answered with the
/// rejected receipt, its dispatch never marked and the upstream never written. The control below
/// holds the same action, resumes it the same way and revokes nothing; it executes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_acc_022_a_paired_devices_held_action_is_taken_back_by_a_revocation_and_never_executes()
{
    let Some(mut held) = HeldDeviceAction::begin().await else {
        return;
    };
    let ack = held
        .authority
        .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: held.acting.hosted.environment_id,
            revision: kr_protocol::ids::AuthorityRevision::new(2),
            reach: kr_protocol::worker::RevisionReach::Host,
            evidence_from: 0,
        })
        .await
        .expect("the worker acknowledges the revision while its plugin host is held");
    assert_eq!(ack.revision, kr_protocol::ids::AuthorityRevision::new(2));
    let fence = ack.fence.expect("the worker reports what its fence did");
    assert_eq!(
        fence.rejected_actions,
        vec![kr_protocol::action::FencedAction {
            actor_id: held.device.actor_id.clone(),
            action_id: held.action_id,
        }],
        "the fence took back the device's intent, under the device that made it"
    );
    assert!(
        fence.possibly_executed.is_empty(),
        "nothing had won the race to its dispatch marker: {:?}",
        fence.possibly_executed
    );
    assert!(
        held.acting.frames().is_empty(),
        "the revocation was acknowledged before anything reached the upstream"
    );

    let (response, retained) = held.resumed().await;
    assert!(
        retained,
        "the answer to a device whose authority moved is held back by the daemon"
    );
    let Outcome::Ok(value) = response.outcome else {
        panic!("a revoked action is answered with its receipt: {response:?}");
    };
    assert!(
        format!("{:?}", value.as_value()).contains("rejected"),
        "{value:?}"
    );
    let receipt = held.receipt_kept();
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::Revoked),
        "{receipt:?}"
    );
    assert!(
        !receipt.state.has_dispatch_marker(),
        "a taken-back intent was never marked dispatched: {receipt:?}"
    );
    assert!(
        held.acting.frames().is_empty(),
        "and it never reached the upstream: {:?}",
        held.acting.frames()
    );
}

/// The control of the case above: the same device's action, held the same way and with its host
/// resumed the same way, executes when nothing revokes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_paired_devices_held_action_that_nothing_revokes_executes_once_its_host_resumes() {
    let Some(mut held) = HeldDeviceAction::begin().await else {
        return;
    };
    let (response, _) = held.resumed().await;
    assert!(
        matches!(response.outcome, Outcome::Ok(_)),
        "the held action is carried out: {response:?}"
    );
    let receipt = held.receipt_kept();
    assert_eq!(receipt.state, ReceiptState::Applied, "{receipt:?}");
    assert!(receipt.state.has_dispatch_marker(), "{receipt:?}");
    assert_eq!(
        held.acting.frames().len(),
        1,
        "the upstream was written once: {:?}",
        held.acting.frames()
    );
}
