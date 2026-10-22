//! What a device's revocation takes from the devices it does not name.
//!
//! One real daemon on the loopback network with a real worker it adopts, and paired devices that
//! attach to the worker's session and claim its size. The size claims are read from the worker's
//! own session.

#![cfg(unix)]

mod net_support;

use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::ids::{ActionId, AttachmentId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::Dimensions;
use net_support::environment::{Environment, Paired, from};

/// Pairs a device that may view the session and hold its size, has it attach a terminal of
/// `dimensions` that claims the size, and returns it with its attachment.
async fn claiming(environment: &Environment, dimensions: Dimensions) -> (Paired, AttachmentId) {
    let device = environment
        .device(from(
            &[ActionRight::SessionView, ActionRight::TerminalGeometry],
            1,
        ))
        .await;
    let attached: SessionAttachResult = device
        .connection
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &SessionAttachParams {
                session_id: environment.worker.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: true,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: [
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Geometry,
                ]
                .into_iter()
                .collect(),
            },
        )
        .await
        .expect("the device attaches")
        .to_typed()
        .expect("an attachment");
    (device, attached.attachment.attachment_id)
}

/// Whether the attachment is still the worker's and still claims the size.
fn claims_the_size(environment: &Environment, attachment_id: AttachmentId) -> bool {
    environment
        .worker
        .runtime()
        .session()
        .attachments()
        .iter()
        .any(|summary| summary.attachment_id == attachment_id && summary.claim_geometry)
}

/// The attachment that owns the size of the worker's session.
fn owner_of_the_size(environment: &Environment) -> Option<AttachmentId> {
    environment.worker.runtime().session().geometry().owner.0
}

/// KR-REQ-10.45: revoking a device takes the size claims of that device and of nobody else's, so a
/// phone that keeps its authority keeps its claim, and the size passes to it when the revoked
/// device owned it.
///
/// Three phones claim the size in turn, the first owning it. The owner's device is revoked: its
/// claim is gone, and the claims of the other two stand, the second owning the size now. The third
/// phone's device is then revoked, which owns no size: the second keeps the size.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn revoking_one_device_leaves_another_devices_size_claim_in_force() {
    let environment = Environment::start().await;
    let (first, firsts) = claiming(&environment, Dimensions::new(100, 40)).await;
    let (second, seconds) = claiming(&environment, Dimensions::new(90, 30)).await;
    let (third, thirds) = claiming(&environment, Dimensions::new(80, 25)).await;
    assert_eq!(owner_of_the_size(&environment), Some(firsts));

    let mut owner = environment.host.client().await;
    let revoked: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        environment.environment_id(),
        &mut owner,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: first._record.device_id,
        },
    )
    .await
    .expect("the owner unpairs the first device");
    assert!(revoked.barrier.holds(), "{revoked:?}");

    assert!(
        !claims_the_size(&environment, firsts),
        "the revoked device holds no claim"
    );
    assert!(
        claims_the_size(&environment, seconds) && claims_the_size(&environment, thirds),
        "the claims of the devices that were not revoked stand"
    );
    assert_eq!(
        owner_of_the_size(&environment),
        Some(seconds),
        "the size passed to the oldest claim left"
    );

    // The other direction: a device that does not own the size is revoked, and the owner keeps it.
    let revoked: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        environment.environment_id(),
        &mut owner,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: third._record.device_id,
        },
    )
    .await
    .expect("the owner unpairs the third device");
    assert!(revoked.barrier.holds(), "{revoked:?}");
    assert!(!claims_the_size(&environment, thirds));
    assert!(claims_the_size(&environment, seconds));
    assert_eq!(owner_of_the_size(&environment), Some(seconds));

    drop((first, second, third));
    environment.stop().await;
}
