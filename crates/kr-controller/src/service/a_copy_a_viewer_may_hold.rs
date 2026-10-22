//! The copies that authorised viewers may hold, listed among what has left the host.
//!
//! Section 24: copies held by authorised viewers are not retroactively erased, and they are shown
//! as retained artifacts. This is `privacy.status` from a real daemon whose grant store holds the
//! grants of devices that have been let see its sessions.

use kr_protocol::grant::GrantExpiry;
use kr_protocol::ids::DeviceId;
use kr_protocol::privacy::PrivacyReport;
use kr_protocol::rights::ActionRight;

use crate::grants::GrantRecord;
use crate::service::net::tests::{daemon, granted};

/// A grant to a new device, active from `activated` unless it is a proposal nobody has redeemed.
fn issued(
    controller: &crate::service::Controller,
    device: DeviceId,
    activated: Option<u64>,
    revoked: bool,
    actions: &[ActionRight],
) {
    let (mut grant, _) = granted(GrantExpiry::Never, controller.policy().authority_revision());
    grant.recipient_device_id = device;
    grant.actions = actions.iter().copied().collect();
    controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: activated,
                revoked_at_ms: revoked.then_some(9),
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
}

async fn report(controller: &std::sync::Arc<crate::service::Controller>) -> PrivacyReport {
    controller
        .privacy_status()
        .await
        .expect("the report is made")
        .to_typed()
        .expect("it is a report")
}

/// KR-REQ-24.29: each device that has held a grant with the right to view is listed once, with the
/// moment it first could, whether the grant is in force or was revoked. A grant nobody has redeemed
/// authorises nothing and puts nothing on a device, and a grant that cannot view lets none be seen.
/// None of them can be deleted from here, and the list says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_was_let_view_is_listed_once_as_a_place_a_copy_may_be() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let before = report(&controller).await;
    let known = before.exported.len();

    let (watching, revoked, proposal, controlling) = (
        DeviceId::new(kr_ipc::new_uuid()),
        DeviceId::new(kr_ipc::new_uuid()),
        DeviceId::new(kr_ipc::new_uuid()),
        DeviceId::new(kr_ipc::new_uuid()),
    );
    let view = [ActionRight::SessionView];
    issued(&controller, watching, Some(50), false, &view);
    issued(&controller, watching, Some(30), false, &view);
    issued(&controller, revoked, Some(70), true, &view);
    issued(&controller, proposal, None, false, &view);
    issued(
        &controller,
        controlling,
        Some(10),
        false,
        &[ActionRight::SessionClose],
    );

    let after = report(&controller).await;
    let listed: Vec<_> = after.exported.iter().skip(known).collect();
    let references: Vec<&str> = listed.iter().map(|copy| copy.reference.as_str()).collect();
    assert_eq!(listed.len(), 2, "{references:?}");
    let of = |device: DeviceId| {
        listed
            .iter()
            .find(|copy| copy.reference.contains(&device.to_string()))
            .unwrap_or_else(|| panic!("{device} is listed: {references:?}"))
    };
    assert_eq!(
        of(watching).left_at_ms.get(),
        30,
        "once, with the moment it first could"
    );
    assert_eq!(
        of(revoked).left_at_ms.get(),
        70,
        "a revoked grant's copy is not recalled"
    );
    for copy in &listed {
        assert!(!copy.deletable, "{copy:?}");
    }
    assert!(after.unlisted.is_empty(), "{:?}", after.unlisted);
}
