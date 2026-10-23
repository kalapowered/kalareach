//! What a request the feed shows complete is carried out again for.
//!
//! The feed judges nothing and could show any request as complete, so a host carries one out
//! again only when it could have carried it out: its issuer is a device this host holds, signed
//! with the key it holds for it, and its pairing grant holds the right to manage the host. A
//! request whose issuer the host does not hold, naming something live here, is neither carried out
//! nor dismissed.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::{DeviceId, RevocationRequestId};
use kr_protocol::pairing::{RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

use super::Controller;
use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::{paired, paired_signing_as};
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

    assert_eq!(
        controller
            .replay_feed_request(&signed(
                &controller,
                &stranger_key,
                DeviceId::new(Uuid::from_bytes([9; 16])),
                kept.device_id,
                9,
            ))
            .await
            .expect("the stranger's request is passed over"),
        Replay::Unverified,
        "an issuer this host does not hold is neither obeyed nor dismissed"
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
