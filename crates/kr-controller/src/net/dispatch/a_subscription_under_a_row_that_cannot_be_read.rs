//! A subscription held under a delegated grant whose row cannot be read.
//!
//! A batch of a subscription is decided, as a request is, under the grant its connection acts under
//! for the session. A device's revocation withdraws the connections that acted under a grant it
//! reached, and a row that cannot be read is reached by the key it still has. These tests open real
//! links on played workers and read what the revocation did to them.

use std::sync::{Arc, Mutex};

use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::grant::{Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::{DeviceId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::question::QuestionReadParams;
use kr_protocol::scalars::{Nullable, Uuid};

use super::a_share_a_device_holds::paired;
use super::a_share_that_names_a_current_decision::{
    Holding, device_read, holds_question_reads, serving,
};
use crate::grants::GrantRecord;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::service::a_revocation_beside_a_row_that_cannot_be_read::key;
use crate::service::one_barrier_for_every_restriction::beside;

/// KR-REQ-10.45 and KR-REQ-25.10: a device's revocation ends the subscription of a connection that
/// acts under a grant delegated from the device's own, when the delegated row cannot be read, and
/// leaves the subscription of a connection that acts under another device's share.
///
/// Three paired devices, each holding only a share of the screen. The holder's share has a
/// delegation to the second device, and the third device's share is of another tree. The second and
/// third open a link and are written a batch. The delegated row's mark of revocation is then made
/// text, which the store cannot read as a moment. The revocation names that row by its key, so the
/// second device's connection is withdrawn and its next batch is not written, and the third
/// device's is neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscription_under_a_delegation_whose_row_cannot_be_read_ends_with_its_holders_device() {
    let holding = Arc::new(Mutex::new(Holding::default()));
    let world =
        fake::fake_world_on(None, serving(Arc::clone(&holding), holds_question_reads())).await;
    fake::acknowledged(&world.controller, world.session_id);
    let holder = paired(&world.controller, 41, SessionSelector::None);
    let delegate = paired(&world.controller, 42, SessionSelector::None);
    let bystander = paired(&world.controller, 43, SessionSelector::None);

    // A share of the screen, which is what a subscription needs, written through the store.
    let share = |byte: u8, parent: Option<GrantId>, issuer: DeviceId, recipient: DeviceId| {
        let (mut grant, _) = crate::service::net::tests::granted(
            GrantExpiry::Never,
            world.controller.policy().authority_revision(),
        );
        grant.grant_id = GrantId::new(Uuid::from_bytes([byte; 16]));
        grant.parent_grant_id = Nullable(parent);
        grant.issuer_device_id = issuer;
        grant.recipient_device_id = recipient;
        grant.session_selector = SessionSelector::These {
            session_ids: [world.session_id].into_iter().collect(),
        };
        grant.history.include_live_screen = true;
        world
            .controller
            .sharing()
            .grants()
            .issue(
                &GrantRecord {
                    grant: grant.clone(),
                    session_id: Some(world.session_id),
                    issued_at_ms: 1,
                    activated_at_ms: Some(2),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the share is written");
        grant
    };
    let host = world.controller.sharing().host_device_id();
    let root: Grant = share(0x71, None, host, holder.device_id);
    let below = share(
        0x72,
        Some(root.grant_id),
        holder.device_id,
        delegate.device_id,
    );
    let unrelated = share(0x73, None, host, bystander.device_id);

    let ends = super::RemoteConnection::for_test(&world.controller, delegate);
    let stays = super::RemoteConnection::for_test(&world.controller, bystander);
    let batch = ControlFrame::Event(kr_protocol::envelope::ControlEvent::Keepalive);
    for (request_id, connection) in [(1, &ends), (2, &stays)] {
        // A forwarded read opens the connection's link to the session under its share.
        let opened = connection
            .read(&device_read(
                request_id,
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id: world.session_id,
                    question_id: Nullable::null(),
                    include_resolved: true,
                },
            ))
            .await;
        assert!(
            matches!(
                &opened,
                ControlFrame::Response(Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "{opened:?}"
        );
        assert!(
            connection.relay(&batch).await,
            "a batch goes while the share holds"
        );
    }
    assert!(
        world
            .controller
            .noted_grants(ends.connection_id)
            .contains(&below.grant_id),
        "the connection acts under the delegated share"
    );
    assert!(
        world
            .controller
            .noted_grants(stays.connection_id)
            .contains(&unrelated.grant_id),
        "the other connection acts under the share of another tree"
    );

    beside(&world._temp)
        .execute_batch(&format!(
            "UPDATE grants SET revoked_at_ms = 'text' WHERE grant_id = {};",
            key(below.grant_id)
        ))
        .expect("the mark of the delegated row is damaged");
    world
        .controller
        .revoke_device_authority(holder.device_id, None, None)
        .await
        .expect("a row that cannot be read does not stop the revocation");

    assert!(
        !world
            .controller
            .admitted_read()
            .contains_key(&ends.connection_id),
        "the connection that acted under the row that cannot be read is withdrawn"
    );
    assert!(
        !ends.relay(&batch).await,
        "no batch goes under the delegated share once its row is withdrawn"
    );
    assert!(
        world
            .controller
            .admitted_read()
            .contains_key(&stays.connection_id),
        "a connection that acted under no revoked grant keeps its registration"
    );
    assert!(stays.relay(&batch).await, "and its batch is written");
    world.serving.abort();
}
