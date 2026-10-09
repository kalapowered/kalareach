//! What this host keeps of a request it took from its authority feed, before the request takes
//! effect.

use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::pairing::RevocationTarget;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

/// A request is written down when the host begins to apply it, before it takes effect, and not
/// only by the barrier that follows the revocation: a host that stops after the revocation
/// committed and before anything else is written finds the request as its own, and neither takes
/// it for new nor numbers it a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_is_in_the_registry_as_soon_as_the_host_begins_to_apply_it() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let host = controller.sharing().host_device_id();
    let owner = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key");
    let request = kr_pairing::grants::sign_revocation_request(
        &owner,
        RevocationRequestId::new(Uuid::from_bytes([7; 16])),
        DeviceId::new(Uuid::from_bytes([8; 16])),
        host,
        RevocationTarget::Devices {
            device_ids: [DeviceId::new(Uuid::from_bytes([9; 16]))]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
        },
        TimestampMs::new(1_000),
    )
    .expect("a signed request");

    assert!(
        controller
            .sharing()
            .grants()
            .stored_feed()
            .expect("the record reads")
            .is_none_or(|stored| stored.records.is_empty()),
        "the control: nothing is written down before the host begins"
    );
    controller
        .authority_feed_begin(request.clone(), AuthorityRevision::new(0), 2_000)
        .expect("the host begins to apply the request");

    let stored = controller
        .sharing()
        .grants()
        .stored_feed()
        .expect("the record reads")
        .expect("the record exists");
    assert_eq!(
        stored
            .records
            .iter()
            .map(|record| record.request.request_id)
            .collect::<Vec<_>>(),
        vec![request.request_id],
        "the request is on disk before anything it names is withdrawn"
    );
}
