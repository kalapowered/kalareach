//! The answer to a revocation made by a paired device.
//!
//! The barrier a revocation raises is host-wide: it names every worker the host holds, a worker's
//! session, and the actions its fence named. A device may know of the sessions its grants reach and
//! no others, so the answer it is given names the workers of the sessions the grant it revoked
//! covers, whichever way it is answered: first, again, or after an attempt that ended unrecorded.

use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, DeviceId, GrantId, RequestId, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::{GrantRevokeParams, RevocationResult};

use super::a_transfer_left_unanswered::{daemon, numbered_owner_share};
use super::a_voice_grant_on_the_floor::paired;
use super::{Audience, Controller};
use crate::grants::ActionClaim;

/// A worker recorded for a new session, whose process is this one: alive, answering nobody, so its
/// barrier is pending whoever asks.
async fn recorded_worker(controller: &Controller, temp: &kr_ipc::testing::TempHost) -> SessionId {
    let environment_id = temp.environment_id();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let process = kr_ipc::identity::current_process_start_identity().expect("this process");
    let mut registry = controller.registry.lock().await;
    let reservation = registry
        .reserve(
            &actor_id,
            kr_ipc::new_uuid(),
            kr_protocol::scalars::Digest256::from_bytes([0x6e; 32]),
            &kr_cbor::to_canonical_vec(&super::a_create_that_launches_nothing::create_params(
                environment_id,
            ))
            .expect("encodes"),
            kr_ipc::now_ms(),
        )
        .expect("reserves")
        .reservation;
    registry
        .record_launch(reservation.reservation_id, &process)
        .expect("records the launcher");
    registry
        .set_phase(
            reservation.reservation_id,
            crate::registry::LaunchPhase::Spawned,
        )
        .expect("spawned");
    let key = *kr_crypto::keys::AuthorisationKeyPair::generate()
        .expect("a key")
        .public();
    registry
        .claim_rendezvous(reservation.reservation_id, key)
        .expect("claims");
    registry
        .record_worker(
            reservation.reservation_id,
            &crate::registry::WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: key,
                process_identity: process,
                endpoint: temp
                    .environment()
                    .worker_endpoint(reservation.display_number)
                    .expect("an endpoint")
                    .as_text(),
                profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                state: kr_protocol::session::SessionState::Live,
                acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
            },
            &kr_protocol::identity::DesktopBinding::none(),
        )
        .expect("records the worker");
    reservation.session_id
}

/// KR-REQ-23.49: a device that revokes a share it delegated is told of the workers of the sessions
/// that share covers and of no other session, and the owner who revokes the same is told of every
/// worker. The control is the owner's answer, which names both sessions' workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_revokes_is_told_of_the_workers_of_its_own_sessions_only() {
    let (temp, controller) = daemon().await;
    let ours = recorded_worker(&controller, &temp).await;
    let elsewhere = recorded_worker(&controller, &temp).await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let device_share = numbered_owner_share(&controller, ours, holder, 1);
    let owner_share = numbered_owner_share(&controller, ours, holder, 3);
    assert_ne!(ours, elsewhere);

    let sessions = |answer: &kr_protocol::sharing::RevocationResult| {
        let mut named: Vec<SessionId> = answer
            .barrier
            .workers
            .iter()
            .map(|worker| worker.session_id)
            .collect();
        named.sort();
        named
    };
    let told_to_a_device = controller
        .revoke_grant(device_share.grant_id, Audience::Device, None, None)
        .await
        .expect("the device revokes");
    assert_eq!(sessions(&told_to_a_device), vec![ours]);
    assert_eq!(told_to_a_device.barrier.workers_total.get(), 1);

    let told_to_the_owner = controller
        .revoke_grant(owner_share.grant_id, Audience::Host, None, None)
        .await
        .expect("the owner revokes");
    let mut both = vec![ours, elsewhere];
    both.sort();
    assert_eq!(sessions(&told_to_the_owner), both);
}

/// A `grant.revoke` of `grant_id` under a fresh action.
fn revoke_request(temp: &kr_ipc::testing::TempHost, grant_id: GrantId) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::GrantRevoke.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&GrantRevokeParams { grant_id }).expect("encodes"),
    }
}

fn sessions(answer: &RevocationResult) -> Vec<SessionId> {
    let mut named: Vec<SessionId> = answer
        .barrier
        .workers
        .iter()
        .map(|worker| worker.session_id)
        .collect();
    named.sort();
    named
}

/// KR-REQ-23.49: an attempt that withdrew a share and ended before it recorded its answer is
/// answered to its retry from the claim, and the answer names the workers its actor may know of: a
/// device's, the sessions the share covers; the owner's, every worker. Whichever route reaches the
/// answer, the audience is the actor's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_of_an_unfinished_revocation_is_told_what_its_actor_may_know() {
    let (temp, controller) = daemon().await;
    let ours = recorded_worker(&controller, &temp).await;
    let elsewhere = recorded_worker(&controller, &temp).await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let device_share = numbered_owner_share(&controller, ours, holder, 1);
    let owner_share = numbered_owner_share(&controller, ours, holder, 3);
    let mut both = vec![ours, elsewhere];
    both.sort();

    for (actor_id, share, expected) in [
        (
            kr_transport::listener::device_principal(&holder),
            device_share,
            vec![ours],
        ),
        (
            ActorId::new("local:test").expect("a principal"),
            owner_share,
            both,
        ),
    ] {
        let mutation = revoke_request(&temp, share.grant_id);
        let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
        let now_ms = kr_ipc::now_ms().get();
        let ActionClaim::Claimed { hold } = controller
            .sharing()
            .grants()
            .claim_action(&actor_id, mutation.action_id, &digest, now_ms)
            .expect("the claim is written")
        else {
            panic!("the first claim of an action is this attempt's");
        };
        controller
            .sharing()
            .revoke(share.grant_id, now_ms + 1, || Ok(()), Some(&hold))
            .expect("the share is withdrawn beside the claim");
        drop(hold);

        let ControlFrame::Response(response) = controller
            .retained_authority_answer(&actor_id, &mutation)
            .await
            .expect("this host holds the claim")
        else {
            panic!("a retry is answered with a response");
        };
        let Outcome::Ok(value) = response.outcome else {
            panic!("a withdrawn share is answered: {response:?}");
        };
        let answered: RevocationResult = value.to_typed().expect("decodes");
        assert!(answered.revoked_grants.contains(&share.grant_id));
        assert_eq!(sessions(&answered), expected, "{actor_id:?}");
    }
}

/// KR-REQ-23.49: a device that revokes a share again, which withdraws nothing, is told of the same
/// workers as the first time, and a barrier still pending for them is still read as pending: it is
/// not told that nothing is left to wait for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_that_withdraws_nothing_still_reports_the_workers_that_are_pending() {
    let (temp, controller) = daemon().await;
    let ours = recorded_worker(&controller, &temp).await;
    let _elsewhere = recorded_worker(&controller, &temp).await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let share = numbered_owner_share(&controller, ours, holder, 1);

    let first = controller
        .revoke_grant(share.grant_id, Audience::Device, None, None)
        .await
        .expect("the device revokes");
    assert_eq!(sessions(&first), vec![ours]);
    assert!(!first.barrier.holds(), "the worker has not acknowledged");

    let again = controller
        .revoke_grant(share.grant_id, Audience::Device, None, None)
        .await
        .expect("and again, under another action");
    assert!(again.revoked_grants.is_empty(), "nothing more is withdrawn");
    assert_eq!(sessions(&again), vec![ours]);
    assert!(
        !again.barrier.holds(),
        "and it is still told the worker is pending"
    );
}

/// KR-REQ-23.49: a revocation a device makes through the daemon (its claim, its check that it holds
/// a share above the grant, its withdrawal and its answer) is answered with the workers of the
/// sessions the grant covers, and a repeat of the action is answered the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_revokes_through_the_daemon_is_told_of_its_own_sessions_only() {
    use kr_protocol::sharing::{AuthorityNotice, RoleSelection, SessionRole};

    let (temp, controller) = daemon().await;
    let ours = recorded_worker(&controller, &temp).await;
    let _elsewhere = recorded_worker(&controller, &temp).await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let friend: DeviceId = paired(&controller, 2, None).device_id;
    let share = numbered_owner_share(&controller, ours, holder, 1);
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let delegated = controller
        .sharing()
        .share(
            &crate::sharing::ShareRequest {
                invitation_id: kr_protocol::ids::InvitationId::new(
                    kr_protocol::scalars::Uuid::from_bytes([7; 16]),
                ),
                grant_id: GrantId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16])),
                environment_id: controller.paths().environment_id(),
                session_id: ours,
                issuer_device_id: holder,
                recipient_device_id: friend,
                parent_grant_id: Some(share.grant_id),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Some(600_000),
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: controller.policy().authority_revision(),
                owner_confirmed: false,
                now_ms: kr_ipc::now_ms().get(),
            },
            || Ok(()),
        )
        .expect("the device delegates a viewer's share");

    let actor_id = kr_transport::listener::device_principal(&holder);
    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
    controller
        .admit_connection(
            connection_id,
            &actor_id,
            &kr_ipc::peer::PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
            kr_protocol::local::LocalClientKind::Cli,
        )
        .await
        .expect("the connection is registered");
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller.leases.authority_revision(),
        deadline: None,
    };
    let mutation = revoke_request(&temp, delegated.grant.grant_id);
    let answer = controller
        .authority_change(
            &actor_id,
            super::authority_changes::AuthorityCaller::Device(holder),
            &mutation,
            Method::GrantRevoke,
            carried,
        )
        .await
        .expect("the device revokes what it delegated");
    let revoked: RevocationResult = answer.to_typed().expect("decodes");
    assert!(revoked.revoked_grants.contains(&delegated.grant.grant_id));
    assert_eq!(sessions(&revoked), vec![ours]);

    // The same action sent again is answered with the same answer, from the record.
    let again = controller
        .authority_change(
            &actor_id,
            super::authority_changes::AuthorityCaller::Device(holder),
            &mutation,
            Method::GrantRevoke,
            carried,
        )
        .await
        .expect("a repeat of the action is answered");
    assert_eq!(
        again.to_typed::<RevocationResult>().expect("decodes"),
        revoked
    );
}

/// An answer goes to the owner's view only to the caller at this machine over its own socket, and
/// to anyone the host cannot recognise as that caller in a device's: the answer that withholds.
#[test]
fn only_the_owners_own_socket_is_answered_as_the_owner() {
    let owner = ActorId::new("local:501").expect("a principal");
    let device = kr_transport::listener::device_principal(&DeviceId::new(
        kr_protocol::scalars::Uuid::from_bytes([3; 16]),
    ));
    let unknown = ActorId::new("service:backup").expect("a principal");
    assert_eq!(Audience::of(&owner), Audience::Host);
    assert_eq!(Audience::of(&device), Audience::Device);
    assert_eq!(Audience::of(&unknown), Audience::Device);
}

/// KR-REQ-23.49: the revocation of a device and the transfer of control are the owner's at this
/// machine, and their answers are written for the owner, so a device that reaches the daemon with
/// either is refused before anything is claimed, and its action is not spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_what_only_the_owner_at_this_machine_does() {
    let (temp, controller) = daemon().await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let actor_id = kr_transport::listener::device_principal(&holder);
    let mutation = revoke_request(&temp, GrantId::new(kr_ipc::new_uuid()));
    for method in [Method::DeviceRevoke, Method::GrantTransfer] {
        let carried = crate::authority::AdmittedMutation {
            connection_id: kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
            admitted_revision: controller.leases.authority_revision(),
            deadline: None,
        };
        let refused = controller
            .authority_change(
                &actor_id,
                super::authority_changes::AuthorityCaller::Device(holder),
                &mutation,
                method,
                carried,
            )
            .await
            .expect_err("a device does not make what the owner at this machine makes");
        assert_eq!(
            refused.code(),
            kr_protocol::error::ErrorCode::PermissionDenied,
            "{method:?}: {refused}"
        );
    }
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
    assert!(
        controller
            .sharing()
            .grants()
            .recorded_action(&actor_id, mutation.action_id, &digest)
            .expect("readable")
            .is_none(),
        "nothing was claimed for the action"
    );
}
