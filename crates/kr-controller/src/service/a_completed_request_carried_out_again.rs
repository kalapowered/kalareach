//! What a request the feed shows complete is carried out again for.
//!
//! The feed judges nothing and could show any request as complete, so a host carries one out
//! again only when it could have carried it out: its issuer is a device this host holds that is
//! not revoked, signed with the key it holds for it, and its pairing grant holds the right to
//! manage the host and a ceiling leaves it. A request whose issuer the host cannot show, naming
//! something live here, is neither carried out nor dismissed.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::pairing::{RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

use super::Controller;
use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::{paired, paired_signing_as, paired_signing_as_at};
use super::remote_revocation::{Ground, Judged, Replay};
use crate::grants::GrantRecord;
use crate::grants::restored::Target;
use kr_client::services::authority::RejectionReason;

/// A revocation of `target`, signed by `key` as `issuer` for this host.
fn signed(
    controller: &Controller,
    key: &AuthorisationKeyPair,
    issuer: DeviceId,
    target: DeviceId,
    id: u8,
) -> RevocationRequest {
    kr_pairing::grants::sign_revocation_request(
        key,
        RevocationRequestId::new(Uuid::from_bytes([id; 16])),
        issuer,
        controller.host_device_id(),
        RevocationTarget::Devices {
            device_ids: [target].into_iter().collect::<CanonicalSet<_>>(),
        },
        TimestampMs::new(1_000),
    )
    .expect("a signed request")
}

fn is_revoked(controller: &Controller, device: DeviceId) -> bool {
    controller
        .devices
        .record_for_device(device)
        .expect("the directory reads")
        .expect("the device is recorded")
        .revoked_at_ms
        .is_some()
}

/// KR-REQ-24.15: a completed request is carried out again for an issuer that could manage the host,
/// dismissed for one this host holds that could not, and left unverified for one it does not hold.
/// The feed could name any request as complete, and a viewer's request or a stranger's would
/// otherwise revoke what they name. An owner paired again under a new device identity is found by
/// the key the request names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_is_carried_out_again_only_when_its_issuer_could_manage_the_host() {
    let (_temp, controller) = daemon().await;
    let manager_key = AuthorisationKeyPair::generate().expect("a key");
    let viewer_key = AuthorisationKeyPair::generate().expect("a key");
    let stranger_key = AuthorisationKeyPair::generate().expect("a key");
    let manager = paired_signing_as(
        &controller,
        1,
        *manager_key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let viewer = paired_signing_as(
        &controller,
        2,
        *viewer_key.public(),
        &[ActionRight::SessionView],
        None,
    );
    let withdrawn = paired(&controller, 3, None);
    let kept = paired(&controller, 4, None);
    let withdrawn_by_the_paired_again = paired(&controller, 5, None);

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &manager_key,
                    manager.device_id,
                    withdrawn.device_id,
                    7,
                ),
                1
            )
            .await
            .expect("the manager's request is carried out again"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, withdrawn.device_id),
        "the control: a request its issuer could have carried out is carried out again"
    );

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &viewer_key,
                    viewer.device_id,
                    kept.device_id,
                    8,
                ),
                1
            )
            .await
            .expect("the viewer's request is passed over"),
        Replay::Done,
        "a known issuer that could not manage the host is dismissed"
    );
    assert!(
        !is_revoked(&controller, kept.device_id),
        "a request of a device that could not manage the host is not carried out"
    );

    let stranger = DeviceId::new(Uuid::from_bytes([9; 16]));
    let request = signed(&controller, &stranger_key, stranger, kept.device_id, 9);
    let Replay::Unverified(found) = controller
        .replay_feed_request(&request, 1)
        .await
        .expect("the stranger's request is passed over")
    else {
        panic!("an issuer this host does not hold is neither obeyed nor dismissed");
    };
    assert_eq!(
        found.issuers,
        [(stranger, request.issuer_key_id)].into_iter().collect(),
        "it names the issuer it says made the request"
    );
    assert_eq!(
        found.devices,
        [(kept.device_id, 1)].into_iter().collect(),
        "and the device it would withdraw"
    );
    assert!(
        !is_revoked(&controller, kept.device_id),
        "a request of a device this host does not hold is not carried out"
    );

    // The owner paired again holds the key under another device identity: the request is the
    // owner's, and is carried out.
    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &manager_key,
                    DeviceId::new(Uuid::from_bytes([10; 16])),
                    withdrawn_by_the_paired_again.device_id,
                    10,
                ),
                1
            )
            .await
            .expect("the request of an owner paired again is carried out"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, withdrawn_by_the_paired_again.device_id),
        "an owner paired again is found by the key the request names"
    );
}

/// KR-REQ-24.15: the issuer of a completed request that the registry holds as revoked proves
/// nothing. In a history that is linear its request took effect before the revocation, so a
/// registry that holds the revocation holds what it withdrew, and carrying the request out again
/// would revoke a device on the word of a key the host has since revoked, a lost phone's for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_of_an_owner_the_host_revoked_is_dismissed() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    controller
        .devices
        .revoke(owner.device_id, TimestampMs::new(2))
        .expect("the owner is revoked");

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(&controller, &key, owner.device_id, named.device_id, 7),
                1
            )
            .await
            .expect("the request is passed over"),
        Replay::Done
    );
    assert!(
        !is_revoked(&controller, named.device_id),
        "a request of a revoked owner is not carried out again"
    );
}

/// KR-REQ-24.15: the owner of a completed request is found among the devices that hold the key it
/// names by one that could have made it, and not by the first in pairing order: an older pairing of
/// the key without the right to manage the host does not dismiss a real withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_is_attributed_to_the_pairing_of_its_key_that_could_make_it() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let _weaker = paired_signing_as_at(
        &controller,
        1,
        *key.public(),
        &[ActionRight::SessionView],
        1,
    );
    let _owner = paired_signing_as_at(&controller, 2, *key.public(), &[ActionRight::HostManage], 2);
    let named = paired(&controller, 3, None);

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &key,
                    DeviceId::new(Uuid::from_bytes([9; 16])),
                    named.device_id,
                    8,
                ),
                1
            )
            .await
            .expect("the request is carried out"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, named.device_id),
        "the pairing that could make the request is the owner"
    );
}

/// KR-REQ-24.15: a completed request is judged by the rights ceiling this host's configuration puts
/// in force, as a new request is: an issuer whose grant holds the right to manage the host but whose
/// ceiling takes it away is dismissed. The control: before the ceiling, its request is carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_is_dismissed_when_the_ceiling_leaves_its_issuer_no_right_to_manage() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let before = paired(&controller, 2, None);
    let after = paired(&controller, 3, None);

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(&controller, &key, owner.device_id, before.device_id, 7),
                1
            )
            .await
            .expect("the request is carried out"),
        Replay::Done
    );
    assert!(is_revoked(&controller, before.device_id), "the control");

    *controller
        .rights_ceiling
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some([ActionRight::SessionView].into_iter().collect());
    assert_eq!(
        controller
            .replay_feed_request(
                &signed(&controller, &key, owner.device_id, after.device_id, 8),
                1
            )
            .await
            .expect("the request is passed over"),
        Replay::Done
    );
    assert!(
        !is_revoked(&controller, after.device_id),
        "the ceiling takes the issuer's right away"
    );
}

/// KR-REQ-24.15: a key that only a revoked device holds says nothing of who signed a request that
/// names a device of another identity. An owner paired again keeps its key under a new identity,
/// and a registry restored to a point between the revocation of the first pairing and the second
/// holds only the first, so the host cannot tell whose request it was and neither carries it out
/// nor dismisses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_whose_key_only_a_revoked_device_holds_is_left_unverified() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let first = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    controller
        .devices
        .revoke(first.device_id, TimestampMs::new(2))
        .expect("the first pairing is revoked");

    assert!(
        matches!(
            controller
                .replay_feed_request(
                    &signed(
                        &controller,
                        &key,
                        DeviceId::new(Uuid::from_bytes([10; 16])),
                        named.device_id,
                        9,
                    ),
                    1
                )
                .await
                .expect("the request is left"),
            Replay::Unverified(_)
        ),
        "the host cannot place the key"
    );
    assert!(
        !is_revoked(&controller, named.device_id),
        "nothing is carried out on the word of a key the host cannot place"
    );
}

/// KR-REQ-24.15: an owner whose grant ran out after its request took effect, and who is not
/// revoked, did make the request: a restored registry that lost it carries it out again. The
/// request took effect when it did, so the clock is not asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_of_an_owner_whose_grant_ran_out_since_is_carried_out_again() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    controller
        .devices
        .record_expiry(owner.device_id, TimestampMs::new(2))
        .expect("the expiry is recorded");

    assert_eq!(
        controller
            .replay_feed_request(
                &signed(&controller, &key, owner.device_id, named.device_id, 7),
                1
            )
            .await
            .expect("the request is carried out"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, named.device_id),
        "an expired owner that was not revoked is still the issuer of what it withdrew"
    );
}

/// KR-REQ-24.15: while a wait for a restored policy stands, a completed request is dismissed only
/// on what its issuer's own record fixes (the key it holds did not sign it, or its grant never held
/// the right to manage the host), and what it names is owed when the registry says the issuer is
/// revoked now or the ceiling removes the right now: a restore and the person's later acts can
/// change both. With no wait standing those two dismiss as they always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_is_owed_on_what_a_restore_can_change_and_dismissed_on_what_it_cannot()
{
    let (_temp, controller) = daemon().await;
    let signer = AuthorisationKeyPair::generate().expect("a key");
    let other = AuthorisationKeyPair::generate().expect("a key");
    let viewer = AuthorisationKeyPair::generate().expect("a key");
    let revoked_key = AuthorisationKeyPair::generate().expect("a key");
    let held_key = paired_signing_as(
        &controller,
        1,
        *signer.public(),
        &[ActionRight::HostManage],
        None,
    );
    let no_right = paired_signing_as(
        &controller,
        2,
        *viewer.public(),
        &[ActionRight::SessionView],
        None,
    );
    let revoked = paired_signing_as(
        &controller,
        3,
        *revoked_key.public(),
        &[ActionRight::HostManage],
        None,
    );
    controller
        .devices
        .revoke(revoked.device_id, TimestampMs::new(2))
        .expect("the issuer is revoked");
    let named: Vec<_> = (10..=14)
        .map(|byte| paired(&controller, byte, None))
        .collect();

    // One request per row: signed by the key `held_key` does not hold, by a device whose grant
    // lacks the right, and by a revoked owner. Each names a device of its own.
    let wrong_key = signed(
        &controller,
        &other,
        held_key.device_id,
        named[0].device_id,
        1,
    );
    let lacking_the_right = signed(
        &controller,
        &viewer,
        no_right.device_id,
        named[1].device_id,
        2,
    );
    let revoked_owner = signed(
        &controller,
        &revoked_key,
        revoked.device_id,
        named[2].device_id,
        3,
    );
    for (request, dismissed_now) in [
        (&wrong_key, true),
        (&lacking_the_right, true),
        (&revoked_owner, true),
    ] {
        assert_eq!(
            controller
                .replay_feed_request(request, 1)
                .await
                .expect("answered"),
            Replay::Done,
            "with no wait standing it is dismissed ({dismissed_now})"
        );
    }
    for device in &named[..3] {
        assert!(!is_revoked(&controller, device.device_id));
    }

    controller
        .find_the_policy_restored()
        .await
        .expect("the finding is written down");
    assert!(controller.restored_policy_waits());
    assert_eq!(
        controller
            .replay_feed_request(&wrong_key, 1)
            .await
            .expect("answered"),
        Replay::Done,
        "the key the registry holds for the issuer did not sign it: no restore changes that"
    );
    assert_eq!(
        controller
            .replay_feed_request(&lacking_the_right, 1)
            .await
            .expect("answered"),
        Replay::Done,
        "the issuer's grant never held the right: no restore changes that"
    );
    assert_eq!(
        controller
            .replay_feed_request(&revoked_owner, 1)
            .await
            .expect("answered"),
        Replay::Owed,
        "a revocation may be the person's act after the restore, and says nothing of the request"
    );
    for device in &named[..3] {
        assert!(
            !is_revoked(&controller, device.device_id),
            "nothing is carried out for any of them"
        );
    }

    // A request nothing live is left to withdraw owes nothing, and one its issuer could make is
    // carried out.
    let withdrawn = paired(&controller, 20, None);
    controller
        .devices
        .revoke(withdrawn.device_id, TimestampMs::new(3))
        .expect("the device is revoked");
    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &revoked_key,
                    revoked.device_id,
                    withdrawn.device_id,
                    4
                ),
                1
            )
            .await
            .expect("answered"),
        Replay::Done,
        "a request of a revoked issuer that names nothing live owes nothing"
    );
    assert_eq!(
        controller
            .replay_feed_request(
                &signed(
                    &controller,
                    &signer,
                    held_key.device_id,
                    named[3].device_id,
                    5
                ),
                1
            )
            .await
            .expect("answered"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, named[3].device_id),
        "the control: a request its issuer could make is carried out in a wait"
    );
}

/// KR-REQ-24.15: a request whose issuer the ceiling now takes the right from is owed while a wait
/// stands, and dismissed otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_the_ceiling_now_removes_the_right_of_is_owed_in_a_wait() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    *controller
        .rights_ceiling
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some([ActionRight::SessionView].into_iter().collect());
    let request = signed(&controller, &key, owner.device_id, named.device_id, 7);
    assert_eq!(
        controller
            .replay_feed_request(&request, 1)
            .await
            .expect("answered"),
        Replay::Done
    );
    controller
        .find_the_policy_restored()
        .await
        .expect("the finding is written down");
    assert_eq!(
        controller
            .replay_feed_request(&request, 1)
            .await
            .expect("answered"),
        Replay::Owed
    );
    assert!(!is_revoked(&controller, named.device_id));
}

/// KR-REQ-24.15: the registry's refusal of a request is evidence about that request only: a note
/// that holds another request under the same identifier dismisses nothing and is not written
/// over, and a refusal note of the very request that the feed's acknowledgement contradicts is
/// held and owed while a wait stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_for_another_request_under_the_same_identifier_is_no_evidence_and_is_not_written() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let host = controller.host_device_id();
    let first_target = paired(&controller, 2, None);
    let second_target = paired(&controller, 3, None);
    let first = signed(
        &controller,
        &key,
        owner.device_id,
        first_target.device_id,
        7,
    );
    controller
        .authority_feed_begin(first.clone(), "feed", AuthorityRevision::new(0), 1)
        .await
        .expect("the host takes the request");
    controller
        .authority_feed_refusal_noted(&first, host)
        .expect("the refusal is noted");
    let note = controller.authority_feed_record(first.request_id);
    assert!(note.as_ref().is_some_and(|note| note.is_refused_by(host)));

    // The feed dropped the first request and holds another under its identifier.
    let second = signed(
        &controller,
        &key,
        owner.device_id,
        second_target.device_id,
        7,
    );
    assert_ne!(first, second);
    assert_eq!(
        controller
            .replay_feed_request(&second, 1)
            .await
            .expect("answered"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, second_target.device_id),
        "the note of the first request is no reason to dismiss the second"
    );
    controller.authority_feed_settled(&second, host);
    controller
        .authority_feed_refusal_noted(&second, host)
        .expect("nothing to note");
    assert_eq!(
        controller.authority_feed_record(first.request_id),
        note,
        "a note is changed only for the request it holds"
    );

    // The same request: no wait dismisses it on the host's own note; a wait holds it and owes what
    // it names, since the feed's acknowledgement of it contradicts the refusal.
    assert_eq!(
        controller
            .replay_feed_request(&first, 1)
            .await
            .expect("answered"),
        Replay::Done
    );
    assert!(!is_revoked(&controller, first_target.device_id));
    controller
        .find_the_policy_restored()
        .await
        .expect("the finding is written down");
    assert_eq!(
        controller
            .replay_feed_request(&first, 1)
            .await
            .expect("answered"),
        Replay::Owed
    );
    assert!(!is_revoked(&controller, first_target.device_id));
}

/// KR-REQ-24.15: the issuer of a Pending request whose grant ran out since is one that could have
/// made it: the whole request is applied again and the barrier it reports is the one that stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_request_of_an_owner_whose_grant_ran_out_since_is_carried_out_again() {
    use kr_protocol::pairing::RevocationCompletion;

    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    controller
        .devices
        .record_expiry(owner.device_id, TimestampMs::new(2))
        .expect("the expiry is recorded");
    let request = signed(&controller, &key, owner.device_id, named.device_id, 7);
    assert_eq!(
        controller
            .replay_a_pending_request(&request, 1)
            .await
            .expect("answered"),
        Replay::Applied(RevocationCompletion::Complete)
    );
    assert!(
        is_revoked(&controller, named.device_id),
        "the request took effect when it did, and the clock is not asked"
    );
    // Applied again, it withdraws nothing and reports the barrier as it stands.
    assert_eq!(
        controller
            .replay_a_pending_request(&request, 1)
            .await
            .expect("answered"),
        Replay::Applied(RevocationCompletion::Complete)
    );
}

/// KR-REQ-24.15: what a request is refused for is either a fact its issuer's own record fixes or a
/// fact about the registry as it stands, and only the first is a ground the host may send to the
/// feed while a wait stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_is_on_immutable_ground_only_when_the_issuers_record_fixes_it() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let other = AuthorisationKeyPair::generate().expect("a key");
    let viewer = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let viewing = paired_signing_as(
        &controller,
        2,
        *viewer.public(),
        &[ActionRight::SessionView],
        None,
    );
    let expired = paired_signing_as(
        &controller,
        3,
        *other.public(),
        &[ActionRight::HostManage],
        None,
    );
    controller
        .devices
        .record_expiry(expired.device_id, TimestampMs::new(2))
        .expect("the expiry is recorded");
    let revoked_key = AuthorisationKeyPair::generate().expect("a key");
    let revoked = paired_signing_as(
        &controller,
        4,
        *revoked_key.public(),
        &[ActionRight::HostManage],
        None,
    );
    controller
        .devices
        .revoke(revoked.device_id, TimestampMs::new(2))
        .expect("the issuer is revoked");
    let named = paired(&controller, 10, None);
    let nobody = DeviceId::new(Uuid::from_bytes([9; 16]));
    let now = controller.wall_now_ms();
    let judged = |request: &RevocationRequest| {
        controller
            .judge_feed_request(request, now, 1)
            .expect("judged")
    };
    let refused = |reason, ground| Judged::Refuse(reason, ground);

    // Immutable: the request is addressed to another host; the key the registry holds for the
    // issuer did not sign it; its grant does not hold the right to manage the host; and the same
    // facts of a device that is revoked now, since they were the issuer's from the day it paired.
    let elsewhere = kr_pairing::grants::sign_revocation_request(
        &key,
        RevocationRequestId::new(Uuid::from_bytes([1; 16])),
        owner.device_id,
        DeviceId::new(Uuid::from_bytes([8; 16])),
        RevocationTarget::Devices {
            device_ids: [named.device_id].into_iter().collect::<CanonicalSet<_>>(),
        },
        TimestampMs::new(1_000),
    )
    .expect("a signed request");
    assert_eq!(
        judged(&elsewhere),
        refused(RejectionReason::UnknownTarget, Ground::Immutable)
    );
    assert_eq!(
        judged(&signed(
            &controller,
            &other,
            owner.device_id,
            named.device_id,
            2
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Immutable),
        "a key that did not sign"
    );
    assert_eq!(
        judged(&signed(
            &controller,
            &viewer,
            viewing.device_id,
            named.device_id,
            3
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Immutable),
        "a grant without the right to manage the host"
    );
    assert_eq!(
        judged(&signed(
            &controller,
            &key,
            revoked.device_id,
            named.device_id,
            4
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Immutable),
        "the key of a revoked device that did not sign, which is the same fact"
    );

    // The grant's own fact holds of a viewer that is revoked now as it did the day it paired.
    let former_viewer_key = AuthorisationKeyPair::generate().expect("a key");
    let former_viewer = paired_signing_as(
        &controller,
        5,
        *former_viewer_key.public(),
        &[ActionRight::SessionView],
        None,
    );
    controller
        .devices
        .revoke(former_viewer.device_id, TimestampMs::new(2))
        .expect("the viewer is revoked");
    assert_eq!(
        judged(&signed(
            &controller,
            &former_viewer_key,
            former_viewer.device_id,
            named.device_id,
            11
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Immutable),
        "a revoked device whose grant never held the right to manage the host"
    );

    // Mutable: no device of that identity; a device that is no longer paired, revoked or expired;
    // and a request that names nothing the registry holds.
    assert_eq!(
        judged(&signed(&controller, &key, nobody, named.device_id, 5)),
        refused(RejectionReason::NoOwnerAuthority, Ground::Mutable),
        "no such device"
    );
    assert_eq!(
        judged(&signed(
            &controller,
            &revoked_key,
            revoked.device_id,
            named.device_id,
            6
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Mutable),
        "a revoked device that did sign it"
    );
    assert_eq!(
        judged(&signed(
            &controller,
            &other,
            expired.device_id,
            named.device_id,
            7
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Mutable),
        "a device whose pairing ran out"
    );
    assert_eq!(
        judged(&signed(&controller, &key, owner.device_id, nobody, 8)),
        refused(RejectionReason::UnknownTarget, Ground::Mutable),
        "a request that names nothing this host holds"
    );
    *controller
        .rights_ceiling
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some([ActionRight::SessionView].into_iter().collect());
    assert_eq!(
        judged(&signed(
            &controller,
            &key,
            owner.device_id,
            named.device_id,
            9
        )),
        refused(RejectionReason::NoOwnerAuthority, Ground::Mutable),
        "a ceiling that now removes the right, which a configuration change can undo"
    );
}

/// KR-REQ-24.15: a request names the devices and grants it states, read from nothing but the
/// request, and a target is live while the registry holds a device unrevoked, a pairing grant a
/// device unrevoked holds, or a stored grant unrevoked; a target it does not hold is not live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_names_what_it_states_and_a_target_is_live_while_the_registry_holds_it_unrevoked()
{
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let device = paired(&controller, 2, None);
    let elsewhere_id = DeviceId::new(Uuid::from_bytes([9; 16]));
    assert_eq!(
        controller.named_targets_of(&signed(
            &controller,
            &key,
            owner.device_id,
            device.device_id,
            1
        )),
        vec![Target::Device(device.device_id)]
    );
    let grants = kr_pairing::grants::sign_revocation_request(
        &key,
        RevocationRequestId::new(Uuid::from_bytes([2; 16])),
        owner.device_id,
        controller.host_device_id(),
        RevocationTarget::Grants {
            grant_ids: [device.grant.grant_id]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
        },
        TimestampMs::new(1_000),
    )
    .expect("a signed request");
    assert_eq!(
        controller.named_targets_of(&grants),
        vec![Target::Grant(device.grant.grant_id)]
    );
    let to_another_host = kr_pairing::grants::sign_revocation_request(
        &key,
        RevocationRequestId::new(Uuid::from_bytes([3; 16])),
        owner.device_id,
        elsewhere_id,
        RevocationTarget::Devices {
            device_ids: [device.device_id].into_iter().collect::<CanonicalSet<_>>(),
        },
        TimestampMs::new(1_000),
    )
    .expect("a signed request");
    assert!(
        controller.named_targets_of(&to_another_host).is_empty(),
        "a request for another host names nothing"
    );

    // A stored grant, and one that is then revoked.
    let stored = || {
        let mut grant = device.grant.clone();
        grant.grant_id = kr_protocol::ids::GrantId::new(kr_ipc::new_uuid());
        let record = GrantRecord {
            grant,
            session_id: None,
            issued_at_ms: 1,
            activated_at_ms: Some(1),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        controller
            .sharing()
            .grants()
            .issue(&record, || Ok(()))
            .expect("the grant is written");
        record.grant.grant_id
    };
    let live_share = stored();
    let revoked_share = stored();
    controller
        .sharing()
        .grants()
        .revoke(revoked_share, 5, || Ok(()))
        .expect("the share is revoked");

    let live = controller.target_liveness();
    assert!(live(&Target::Device(device.device_id)));
    assert!(
        live(&Target::Grant(device.grant.grant_id)),
        "a pairing grant"
    );
    assert!(live(&Target::Grant(live_share)), "a stored grant");
    assert!(!live(&Target::Grant(revoked_share)));
    assert!(!live(&Target::Device(elsewhere_id)));
    drop(live);

    controller
        .devices
        .revoke(device.device_id, TimestampMs::new(3))
        .expect("the device is revoked");
    let live = controller.target_liveness();
    assert!(!live(&Target::Device(device.device_id)));
    assert!(
        !live(&Target::Grant(device.grant.grant_id)),
        "a pairing grant is revoked by revoking the device"
    );
}

/// KR-REQ-24.15: a request is acknowledged in the registry's own record only once it took effect: an
/// acknowledged note without a revision reads as a refusal, so a request carried out again over a
/// note that was never numbered is not written down as acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_is_acknowledged_only_once_it_is_numbered() {
    let (_temp, controller) = daemon().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        &controller,
        1,
        *key.public(),
        &[ActionRight::HostManage],
        None,
    );
    let named = paired(&controller, 2, None);
    let host = controller.host_device_id();
    let request = signed(&controller, &key, owner.device_id, named.device_id, 7);
    controller
        .authority_feed_begin(request.clone(), "feed", AuthorityRevision::new(0), 1)
        .await
        .expect("the host takes the request");

    controller.authority_feed_settled(&request, host);
    let note = controller
        .authority_feed_record(request.request_id)
        .expect("the note");
    assert!(
        !note.is_refused_by(host) && !note.acknowledged_by.contains(&host),
        "an unnumbered note is left as it is: acknowledged, it would read as a refusal"
    );

    controller
        .authority_feed_took_effect(request.request_id, AuthorityRevision::new(1))
        .expect("the revision is written down");
    controller.authority_feed_settled(&request, host);
    let note = controller
        .authority_feed_record(request.request_id)
        .expect("the note");
    assert!(note.acknowledged_by.contains(&host) && !note.is_refused_by(host));
}
