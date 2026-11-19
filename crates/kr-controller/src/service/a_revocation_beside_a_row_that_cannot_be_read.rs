//! A revocation beside a grants row that cannot be read, at the controller's own entry points.
//!
//! A row that cannot be read gives no authority and is not an obstacle to withdrawing any: the
//! owner's revocation takes every grant it can read and marks each row it cannot, a paired
//! device's takes its own subtree and nothing more, and the fence a revocation owes reaches the
//! whole host only when a marked row names no grant.

use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};
use kr_protocol::sharing::RevocationResult;
use kr_protocol::worker::RevisionReach;

use super::a_revocation_answered_to_a_device::revoke_request;
use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::paired;
use super::one_barrier_for_every_restriction::{beside, owed, revision};
use super::{Audience, Controller};

pub(super) fn grant_id(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

pub(super) fn device_id(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

/// A row held by `recipient`, active, beneath `parent` when it has one.
pub(super) fn issue(
    controller: &Controller,
    byte: u8,
    parent: Option<u8>,
    recipient: DeviceId,
) -> GrantId {
    let grant = Grant {
        grant_id: grant_id(byte),
        parent_grant_id: Nullable(parent.map(grant_id)),
        issuer_device_id: device_id(0xf0),
        recipient_device_id: recipient,
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1)),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant,
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("written");
    grant_id(byte)
}

pub(super) fn key(grant: GrantId) -> String {
    let hex: String = grant
        .get()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("X'{hex}'")
}

/// Makes the row of `grant` one that names no grant: a key of the wrong length and a record that
/// does not decode.
pub(super) fn make_nameless(temp: &kr_ipc::testing::TempHost, grant: GrantId) {
    beside(temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant_id = X'00', grant = X'00' WHERE grant_id = {};",
            key(grant)
        ))
        .expect("the row is damaged");
}

/// Whether the row under `key_literal` is still live.
pub(super) fn is_live(temp: &kr_ipc::testing::TempHost, key_literal: &str) -> bool {
    beside(temp)
        .query_row(
            &format!("SELECT revoked_at_ms IS NULL FROM grants WHERE grant_id = {key_literal}"),
            [],
            |row| row.get(0),
        )
        .expect("the row reads")
}

/// The reach the fence of the last revocation carries to a worker that has fenced nothing.
async fn reach_of_the_last_revocation(controller: &Controller) -> RevisionReach {
    let revision = AuthorityRevision::new(revision(controller).await);
    controller
        .revision_notice(revision, AuthorityRevision::new(0), 0)
        .reach
}

/// A device's own `grant.revoke` of a share it delegated, beside another device's live grant that
/// hangs below a row nobody holds and a row that names no grant: the owner's revocation takes
/// those, a device's takes its subtree and nothing more, and fences only that subtree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_revoking_its_own_delegation_beside_another_devices_unplaced_grant_withdraws_only_its_own()
 {
    let (temp, controller) = daemon().await;
    let holder = paired(&controller, 1, None).device_id;
    let friend = paired(&controller, 2, None).device_id;
    let stranger = device_id(0xe5);
    issue(&controller, 0x41, None, holder);
    let delegated = issue(&controller, 0x42, Some(0x41), friend);
    issue(&controller, 0x45, None, stranger);
    let unplaced = issue(&controller, 0x43, Some(0x45), stranger);
    beside(&temp)
        .execute_batch(&format!(
            "DELETE FROM grants WHERE grant_id = {};",
            key(grant_id(0x45))
        ))
        .expect("the parent row is gone");
    let nameless = issue(&controller, 0x44, None, stranger);
    make_nameless(&temp, nameless);

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
    let answer = controller
        .authority_change(
            &actor_id,
            super::authority_changes::AuthorityCaller::Device(holder),
            &revoke_request(&temp, delegated),
            Method::GrantRevoke,
            carried,
        )
        .await
        .into_given()
        .into_answer_for_test()
        .expect("the device revokes what it delegated");
    let revoked: RevocationResult = answer.to_typed().expect("decodes");
    assert_eq!(
        revoked.revoked_grants.iter().copied().collect::<Vec<_>>(),
        vec![delegated],
        "the answer names the subtree and no other grant"
    );
    assert!(
        is_live(&temp, &key(unplaced)),
        "another device's unplaced grant is not the device's to withdraw"
    );
    assert!(
        is_live(&temp, "X'00'"),
        "the row that names no grant is not marked by a device's revocation"
    );
    let RevisionReach::Within { grants, .. } = reach_of_the_last_revocation(&controller).await
    else {
        panic!("a device's revocation does not fence the whole host");
    };
    assert!(grants.contains(&delegated));
    assert!(!grants.contains(&unplaced));
}

/// An owner's revocation of a device beside a row that names no grant fences the whole host: the
/// row cannot show which connections acted under it. The row is marked revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_damaged_row_with_no_name_fences_the_whole_host() {
    let (temp, controller) = daemon().await;
    let held = paired(&controller, 1, None).device_id;
    issue(&controller, 0x41, None, held);
    let nameless = issue(&controller, 0x44, None, device_id(0xe5));
    make_nameless(&temp, nameless);

    controller
        .revoke_device_authority(held, None, None)
        .await
        .expect("a row that cannot be read does not stop the revocation");
    assert!(!is_live(&temp, "X'00'"), "the row is marked revoked");
    assert!(
        reach_of_the_last_revocation(&controller).await.is_host(),
        "the fence reaches every connection"
    );
}

/// The owner's `grant.revoke` beside a row that names no grant reaches the whole host too, apart
/// from the device revocation's own flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owners_grant_revocation_beside_a_row_with_no_name_fences_the_whole_host() {
    let (temp, controller) = daemon().await;
    let root = issue(&controller, 0x41, None, device_id(0xe1));
    let nameless = issue(&controller, 0x44, None, device_id(0xe5));
    make_nameless(&temp, nameless);

    controller
        .revoke_grant(root, Audience::Host, None, None)
        .await
        .expect("a row that cannot be read does not stop the revocation");
    assert!(
        reach_of_the_last_revocation(&controller).await.is_host(),
        "the fence reaches every connection"
    );
}

/// A row that cannot be read but has a key is named in the fence of the revocation that marks it,
/// so the connections and the worker leases held under it are reached by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fence_of_a_revocation_names_the_key_of_each_damaged_row_it_marks() {
    let (temp, controller) = daemon().await;
    let held = paired(&controller, 1, None).device_id;
    issue(&controller, 0x41, None, held);
    let below = issue(&controller, 0x42, Some(0x41), device_id(0xe5));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET parent_grant_id = X'00' WHERE grant_id = {};",
            key(below)
        ))
        .expect("the parent column no longer matches the record");

    controller
        .revoke_device_authority(held, None, None)
        .await
        .expect("a row that cannot be read does not stop the revocation");
    assert!(!is_live(&temp, &key(below)), "the row is marked revoked");
    let RevisionReach::Within { grants, .. } = reach_of_the_last_revocation(&controller).await
    else {
        panic!("a named row is fenced by name");
    };
    assert!(grants.contains(&below), "the marked row's key is named");
    assert!(grants.contains(&grant_id(0x41)), "and the device's grant");
}

/// An admission that lapsed before the call marks nothing beside a damaged row, and its refusal is
/// the admission's own and not the fence's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_admission_marks_nothing_beside_a_damaged_row() {
    let (temp, controller) = daemon().await;
    let held = paired(&controller, 1, None).device_id;
    issue(&controller, 0x41, None, held);
    let nameless = issue(&controller, 0x44, None, device_id(0xe5));
    make_nameless(&temp, nameless);
    let lapsed = crate::authority::AdmittedMutation {
        connection_id: kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
        admitted_revision: controller.leases.authority_revision(),
        deadline: None,
    };

    let refused = controller
        .revoke_device_authority(held, Some(&lapsed), None)
        .await
        .expect_err("a connection that is not registered has no admission");
    assert_eq!(
        refused.to_string(),
        super::footing::admission_refusal(crate::authority::AdmissionLapse::Deregistered)
            .to_string()
    );
    assert_ne!(
        refused.to_string(),
        super::barrier::fence_owed_refusal().to_string()
    );
    assert!(is_live(&temp, "X'00'"), "the damaged row is not marked");
    assert!(owed(&controller).is_empty(), "no fence is owed");
    assert!(
        controller
            .devices()
            .record_for_device(held)
            .expect("the directory reads")
            .expect("the device is recorded")
            .revoked_at_ms
            .is_none(),
        "the device is not revoked"
    );
}

/// A grants table that cannot be read at all is a failure of the revocation, and it leaves the
/// device's record alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grants_table_that_cannot_be_read_at_all_leaves_the_device_record_alone() {
    let (temp, controller) = daemon().await;
    let held = paired(&controller, 1, None).device_id;
    let registry = beside(&temp);
    registry
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read");
    let failed = controller
        .revoke_device_authority(held, None, None)
        .await
        .is_err();
    registry
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    assert!(failed, "the revocation fails");
    assert!(
        controller
            .devices()
            .record_for_device(held)
            .expect("the directory reads")
            .expect("the device is recorded")
            .revoked_at_ms
            .is_none(),
        "the device is not revoked"
    );
}

/// A second revocation of a device whose first has finished writes no second fence and moves no
/// revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_device_revocation_after_the_damage_is_marked_owes_nothing_more() {
    let (temp, controller) = daemon().await;
    let held = paired(&controller, 1, None).device_id;
    issue(&controller, 0x41, None, held);
    let nameless = issue(&controller, 0x44, None, device_id(0xe5));
    make_nameless(&temp, nameless);
    controller
        .revoke_device_authority(held, None, None)
        .await
        .expect("the first revocation");
    let after_the_first = revision(&controller).await;

    controller
        .revoke_device_authority(held, None, None)
        .await
        .expect("the repeat");
    assert_eq!(revision(&controller).await, after_the_first);
    assert!(owed(&controller).is_empty(), "nothing is owed");
}
