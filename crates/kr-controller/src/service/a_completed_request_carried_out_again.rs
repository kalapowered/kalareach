//! What a request the feed shows complete is carried out again for.
//!
//! The feed judges nothing and could show any request as complete, so a host carries one out
//! again only when it could have carried it out: its issuer is a device this host holds that is
//! not revoked, signed with the key it holds for it, and its pairing grant holds the right to
//! manage the host and a ceiling leaves it. A request whose issuer the host cannot show, naming
//! something live here, is neither carried out nor dismissed.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::{DeviceId, RevocationRequestId};
use kr_protocol::pairing::{RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

use super::Controller;
use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::{paired, paired_signing_as, paired_signing_as_at};
use super::remote_revocation::Replay;

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
            .replay_feed_request(&signed(
                &controller,
                &manager_key,
                manager.device_id,
                withdrawn.device_id,
                7,
            ))
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
            .replay_feed_request(&signed(
                &controller,
                &viewer_key,
                viewer.device_id,
                kept.device_id,
                8,
            ))
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
        .replay_feed_request(&request)
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
        [kept.device_id].into_iter().collect(),
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
            .replay_feed_request(&signed(
                &controller,
                &manager_key,
                DeviceId::new(Uuid::from_bytes([10; 16])),
                withdrawn_by_the_paired_again.device_id,
                10,
            ))
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
            .replay_feed_request(&signed(
                &controller,
                &key,
                owner.device_id,
                named.device_id,
                7
            ))
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
            .replay_feed_request(&signed(
                &controller,
                &key,
                DeviceId::new(Uuid::from_bytes([9; 16])),
                named.device_id,
                8,
            ))
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
            .replay_feed_request(&signed(
                &controller,
                &key,
                owner.device_id,
                before.device_id,
                7
            ))
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
            .replay_feed_request(&signed(
                &controller,
                &key,
                owner.device_id,
                after.device_id,
                8
            ))
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
                .replay_feed_request(&signed(
                    &controller,
                    &key,
                    DeviceId::new(Uuid::from_bytes([10; 16])),
                    named.device_id,
                    9,
                ))
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
            .replay_feed_request(&signed(
                &controller,
                &key,
                owner.device_id,
                named.device_id,
                7
            ))
            .await
            .expect("the request is carried out"),
        Replay::Done
    );
    assert!(
        is_revoked(&controller, named.device_id),
        "an expired owner that was not revoked is still the issuer of what it withdrew"
    );
}
