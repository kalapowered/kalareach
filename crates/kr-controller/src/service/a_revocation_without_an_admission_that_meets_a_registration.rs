//! A revocation that carries no admission, the feed's, against a push registration that holds the
//! registry between its last read of the device and its write of the device's destination.

use kr_delivery::destination::{DeliveryRule, DestinationId, PreviewKeys, PushDestination};
use kr_protocol::ids::{InstallationId, PushSenderRecordId};
use kr_protocol::scalars::Uuid;

use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::paired;

/// A revocation of a device that carries no admission waits for a registration that holds the
/// registry, and ends the destination the registration wrote. Run at once, it would mark the
/// device and end a destination that is not written yet, and the registration would then write one
/// for a device that is no longer paired, with a credential a start loads and nothing ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_without_an_admission_leaves_no_destination_a_registration_wrote_meanwhile() {
    let (_temp, controller) = daemon().await;
    let device = paired(&controller, 1, None);
    let id = DestinationId::new(device.device_id.to_string()).expect("an identifier");

    // The registration holds the registry from its re-read of the device to its write.
    let registration = controller.registry.lock().await;
    let mut revoking = Box::pin(controller.revoke_device_authority(device.device_id, None, None));
    tokio::select! {
        biased;
        _ = &mut revoking => panic!("the revocation finished while a registration held the registry"),
        () = std::future::ready(()) => {}
    }
    let preview = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a key")
        .public();
    let destination = crate::push::DeliveryModule::push_destination(
        id.clone(),
        PushDestination {
            installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
            preview_keys: PreviewKeys::only(preview, 1),
            previews_enabled: true,
            mailbox_key: None,
        },
        DeliveryRule {
            name: "the paired device's own grant".to_owned(),
            grant_id: Some(device.grant.grant_id),
        },
        1,
    );
    controller
        .delivery
        .configure(&destination)
        .expect("the registration writes its destination");
    drop(registration);

    revoking.await.expect("the revocation completes");
    assert!(
        controller
            .devices
            .record_for_device(device.device_id)
            .expect("the directory reads")
            .expect("the device is recorded")
            .revoked_at_ms
            .is_some(),
        "the device is revoked"
    );
    let left = controller
        .delivery
        .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
        .expect("the journal reads");
    assert!(
        left.is_none_or(|left| !left.enabled && left.rule.is_none()),
        "no destination is left in service for a device that is not paired"
    );
}
