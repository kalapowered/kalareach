//! What a paired device is told when the host carried its action out and could not keep the answer.
//!
//! One real daemon on the loopback network, and a paired device over the transport. The device
//! delegates a share, which the host writes with its invitation in one commit, and the registry then
//! refuses the update that would keep the answer under the action. The share exists, so the device
//! is not told the registry is unavailable, which is a transient word and says nothing took effect:
//! it is told the outcome is unknown, and a client keeps the action it sent. The control is the same
//! delegation with the registry whole.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::{AuthorityNotice, GrantCreateParams, RoleSelection, SessionRole};

use net_support::{Host, an_open_session, on_the_session, owned_by, recipient, refusal};

/// KR-REQ-09.09: a delegation the host carried out and could not record the answer of.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_delegation_whose_answer_cannot_be_kept_is_told_the_outcome_is_unknown() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let (_friend, friend_record) = recipient(&host, &owner).await;
    let session = an_open_session(&host).0;
    let (above, boss_connection) = owned_by(&host, session, &boss, &boss_record).await;
    let delegation = || {
        let selection = RoleSelection::plain(SessionRole::Owner);
        GrantCreateParams {
            session_id: session,
            recipient_device_id: friend_record.device_id,
            parent_grant_id: Nullable::some(above.grant.grant_id),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: Nullable::some(DurationMs::new(600_000)),
            owner_confirmation: Nullable::null(),
        }
    };

    let kept = ActionId::new(kr_ipc::new_uuid());
    boss_connection
        .mutate(
            Method::GrantCreate,
            kept,
            on_the_session(&host, session),
            &delegation(),
        )
        .await
        .expect("the delegation is answered while the registry keeps answers");

    let registry = rusqlite::Connection::open(host.registry_database()).expect("the registry");
    registry
        .execute_batch(
            "CREATE TRIGGER the_answer_is_not_kept BEFORE UPDATE ON authority_receipts
             BEGIN SELECT RAISE(ABORT, 'the registry keeps no answer'); END;",
        )
        .expect("the registry is made to refuse the update that keeps an answer");
    let action = ActionId::new(kr_ipc::new_uuid());
    let told = refusal(
        boss_connection
            .mutate(
                Method::GrantCreate,
                action,
                on_the_session(&host, session),
                &delegation(),
            )
            .await,
    );
    registry
        .execute_batch("DROP TRIGGER the_answer_is_not_kept;")
        .expect("the registry keeps answers again");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    // The share was written, which is why the transient word was not the host's to give.
    let (written, _) =
        kr_protocol::sharing::share_identities(&boss_record.principal(), action.get());
    assert!(
        host.controller()
            .sharing()
            .grants()
            .record(written)
            .expect("the grants are readable")
            .is_some(),
        "the host wrote the share before it could not keep the answer"
    );
    boss_connection.close();
    host.stop().await;
}
