//! Another device's authority, withdrawn the way a device revocation withdraws it.
//!
//! A device that the host pairs and then revokes withdraws the connections that act under that
//! device and stamps every other registration with the revision the revocation made. The
//! connections of the owner stand and no fence is owed: only what an answer was admitted under has
//! changed, which is what a copy is told under and a first answer is not.

#![allow(dead_code)]

use kr_controller::service::Controller;
use kr_controller::service::net::devices::DeviceRecord;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{DeviceId, EnvironmentId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, EndpointKey, Nullable, TimestampMs};

/// Pairs a device with `controller`'s host, as a completed pairing records one, and revokes its
/// authority through the public revocation, returning the device.
///
/// # Panics
///
/// Panics when the record cannot be written or the revocation fails.
pub async fn another_devices_authority_is_revoked(
    controller: &Controller,
    environment_id: EnvironmentId,
) -> DeviceId {
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let grant = Grant {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        parent_grant_id: Nullable::null(),
        issuer_device_id: controller.sharing().host_device_id(),
        recipient_device_id: device_id,
        authority_revision: controller.policy().authority_revision(),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [environment_id].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: CanonicalSet::from_iter([]),
        },
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1)),
            include_live_screen: false,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    controller
        .devices()
        .commit(&DeviceRecord {
            device_id,
            endpoint_id: EndpointKey::from_bytes(kr_cbor::sha256(device_id.get().as_bytes())),
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
            authorisation: AuthorisationKey::from_bytes([2; 32]),
            stored_envelope: None,
            notification_preview: None,
            device_name: kr_protocol::pairing::DeviceName::new("phone").expect("a name"),
            platform: kr_protocol::pairing::DevicePlatform::Ios,
            grant,
            paired_at_ms: TimestampMs::new(1),
            revoked_at_ms: None,
            committed_invitation_id: None,
            expired_at_ms: None,
        })
        .expect("the device is paired");
    controller
        .revoke_device_authority(device_id, None, None)
        .await
        .expect("another device's authority is revoked");
    device_id
}
