//! A send the host refuses for now stays a send a client can try again, over real connections.
//!
//! A host's answer to a send is one of three kinds: a definite word (it did not happen and will
//! not), a refusal for now (nothing took effect, and the same send may be tried again and may yet
//! land), and an outcome it cannot establish. A client settles a send only on the first kind. The
//! host here is kr-controller's in-process daemon, and the refusal for now is a real fault in its
//! registry: it cannot write the claim of an action, and says `STORAGE_UNAVAILABLE`, a transient
//! code. Clearing the fault is the only thing that changes between the refusal and the send that
//! lands; nothing here waits for time to pass.

mod net_support;

use std::time::Duration;

use kr_client::{ClientError, Settled};
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_protocol::ids::{ActionId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::{
    GrantListParams, GrantListResult, GrantRedeemParams, GrantRedeemResult, GrantState,
    RoleSelection, SessionRole,
};
use net_support::{Device, Host, an_open_session, connect, on_the_host, recipient, share_with};

const TTL: DurationMs = DurationMs::new(120_000);

/// A fault in the daemon's registry that refuses to record the claim of any action, until it is
/// cleared. The host cannot record an action, so it takes none, and says so as a transient failure.
struct ClaimsRefused {
    registry: rusqlite::Connection,
}

impl ClaimsRefused {
    fn put_in(host: &Host) -> Self {
        let registry =
            rusqlite::Connection::open(host.registry_database()).expect("opens the registry");
        registry
            .busy_timeout(Duration::from_secs(5))
            .expect("waits for the daemon's writes");
        registry
            .execute_batch(
                "CREATE TRIGGER refuse_claims BEFORE INSERT ON authority_receipts
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            )
            .expect("the fault is in place");
        Self { registry }
    }

    fn clear(self) {
        self.registry
            .execute_batch("DROP TRIGGER refuse_claims;")
            .expect("the fault is cleared");
    }
}

/// What the host lists for one session, resolved grants included.
async fn listed(host: &Host, session_id: SessionId) -> GrantListResult {
    net_support::pairing::read(
        &mut host.client().await,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: true,
        },
    )
    .await
    .expect("the list is read")
}

/// A share of a session to a device, the invitation to redeem it and the device that redeems it.
struct Offered {
    device: Device,
    record: DeviceRecord,
    session_id: SessionId,
    invitation_id: InvitationId,
    // Declared last: the directory is removed after every field above has let go of its files.
    host: Host,
}

async fn offered() -> Offered {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let issued = share_with(
        &host,
        session_id,
        record.device_id,
        RoleSelection::plain(SessionRole::Viewer),
        None,
    )
    .await
    .expect("the share is written");
    Offered {
        host,
        device,
        record,
        session_id,
        invitation_id: issued.preview.invitation_id,
    }
}

/// How many grants of the session are active for the device that redeems.
async fn active(offered: &Offered) -> usize {
    listed(&offered.host, offered.session_id)
        .await
        .grants
        .iter()
        .filter(|grant| grant.state == GrantState::Active)
        .count()
}

/// A refusal for now keeps the send on the client's book, and sending it again under its own
/// identifier lands it once. The book settles by itself on the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_refused_for_now_stays_and_lands_once_when_sent_again() {
    let offered = offered().await;
    let session = connect(&offered.host, &offered.device, &offered.record).await;
    let redeem = GrantRedeemParams {
        invitation_id: offered.invitation_id,
    };

    let fault = ClaimsRefused::put_in(&offered.host);
    let refused = session
        .mutate(
            Method::GrantRedeem,
            on_the_host(&offered.host),
            None,
            &ParamsValue::empty(),
            &redeem,
            TTL,
        )
        .await
        .expect_err("the host cannot record the action now");
    assert!(
        matches!(&refused, ClientError::Host(error)
            if error.code == ErrorCode::StorageUnavailable
                && error.code.retry_category() == RetryCategory::Transient),
        "{refused:?}"
    );
    let kept = session.submitted_actions().await;
    assert_eq!(
        kept.len(),
        1,
        "a refusal for now decides nothing, so the send stays"
    );
    assert!(!kept[0].held, "it is a send its caller does not hold");
    assert_eq!(active(&offered).await, 0, "nothing took effect");

    fault.clear();
    let action_id = kept[0].action_id;
    let landed = session
        .mutate_continuing(
            action_id,
            Method::GrantRedeem,
            on_the_host(&offered.host),
            None,
            &ParamsValue::empty(),
            &redeem,
            TTL,
        )
        .await
        .expect("the same send lands once the host can record it");
    let Settled::Result(value) = landed else {
        panic!("the redemption's own result");
    };
    let result: GrantRedeemResult = value.to_typed().expect("a result");
    assert_eq!(result.invitation_id, offered.invitation_id);
    assert!(
        session.submitted_actions().await.is_empty(),
        "a result settles the send"
    );
    assert_eq!(active(&offered).await, 1, "it landed once");

    session.close();
    offered.host.stop().await;
}

/// A refusal in the host's definite word settles the send by itself, as a result does, and a
/// refusal for now does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_definite_refusal_settles_the_send_and_a_refusal_for_now_does_not() {
    let offered = offered().await;
    let session = connect(&offered.host, &offered.device, &offered.record).await;

    // An invitation the host never made: the host's own word that nothing happens.
    let stranger = GrantRedeemParams {
        invitation_id: InvitationId::new(kr_ipc::new_uuid()),
    };
    let refused = session
        .mutate(
            Method::GrantRedeem,
            on_the_host(&offered.host),
            None,
            &ParamsValue::empty(),
            &stranger,
            TTL,
        )
        .await
        .expect_err("a definite refusal");
    assert!(
        matches!(&refused, ClientError::Host(error)
            if error.code == ErrorCode::PermissionDenied),
        "{refused:?}"
    );
    assert!(
        session.submitted_actions().await.is_empty(),
        "a definite refusal settles the send"
    );

    let fault = ClaimsRefused::put_in(&offered.host);
    let for_now = session
        .mutate(
            Method::GrantRedeem,
            on_the_host(&offered.host),
            None,
            &ParamsValue::empty(),
            &stranger,
            TTL,
        )
        .await
        .expect_err("a refusal for now");
    assert!(
        matches!(&for_now, ClientError::Host(error)
            if error.code.retry_category() == RetryCategory::Transient),
        "{for_now:?}"
    );
    assert_eq!(
        session.submitted_actions().await.len(),
        1,
        "a refusal for now does not"
    );
    fault.clear();
    session.close();
    offered.host.stop().await;
}

/// A send its caller holds is never settled by an answer, whatever the answer was: only its
/// caller settles it, and sends the same request again, which the host performs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_send_refused_for_now_is_sent_again_by_its_caller_and_lands_once() {
    let offered = offered().await;
    let session = connect(&offered.host, &offered.device, &offered.record).await;
    let redeem = GrantRedeemParams {
        invitation_id: offered.invitation_id,
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let composed = session
        .compose(
            Method::GrantRedeem,
            action_id,
            on_the_host(&offered.host),
            None,
            &ParamsValue::empty(),
            &redeem,
            TTL,
        )
        .await
        .expect("composed");

    let fault = ClaimsRefused::put_in(&offered.host);
    let refused = session.send(&composed).await.expect_err("refused for now");
    assert_eq!(refused.code(), ErrorCode::StorageUnavailable);
    assert_eq!(
        session.submitted_actions().await.len(),
        1,
        "the caller holds it"
    );
    fault.clear();
    session.settle(action_id).await;
    let landed = session
        .send(&composed)
        .await
        .expect("the same request lands");
    assert!(landed.result().is_some());
    assert_eq!(active(&offered).await, 1, "it landed once");
    session.settle(action_id).await;

    // Sent again from another connection, it is answered from the host's record.
    let other = connect(&offered.host, &offered.device, &offered.record).await;
    let asked = other
        .repeat(&composed)
        .await
        .expect("answered from the record");
    assert!(asked.result().is_some());
    assert_eq!(active(&offered).await, 1, "and did not land twice");
    other.settle(action_id).await;

    session.close();
    other.close();
    offered.host.stop().await;
}
