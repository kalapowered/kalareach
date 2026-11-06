//! What a repeat of an action is told when the record of its first attempt cannot be read.
//!
//! One real daemon on the loopback network and the owner at its own socket. The registry keeps a
//! receipt for each authority change the host performed, and a repeat is answered from it. A
//! registry that cannot read the receipt is not one that holds none: the change may have been made,
//! so the repeat is told that what became of it is not known, and not a transient word, which says
//! that nothing took effect and has the change sent again as though nothing had.

#![cfg(unix)]

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacySetParams};
use net_support::Host;

/// KR-REQ-09.09: a repeat of an authority change, asked of a registry that cannot read the receipt
/// of the first attempt, is told the outcome is unknown, and once the receipt can be read it is
/// answered from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_authority_change_whose_receipt_cannot_be_read_is_told_the_outcome_is_unknown()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let original = client
        .compose(
            Method::PrivacySet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &PrivacySetParams { enabled: true },
        )
        .await
        .expect("the mutation is composed");
    let first: PrivacyReport = client
        .repeat(&original)
        .await
        .expect("the call reaches the daemon")
        .expect("privacy mode is set")
        .to_typed()
        .expect("decodes");
    assert!(first.enabled);

    // The table that holds the receipts is moved aside, as a registry that fails to read it would
    // leave it.
    let registry =
        rusqlite::Connection::open(host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    registry
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the receipts cannot be read");
    let told = client
        .repeat(&original)
        .await
        .expect("the call reaches the daemon")
        .expect_err("a receipt that cannot be read does not answer the repeat");
    registry
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the receipts can be read again");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    let again: PrivacyReport = client
        .repeat(&original)
        .await
        .expect("the call reaches the daemon")
        .expect("the repeat is answered once the receipt can be read")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        again.generation, first.generation,
        "the change was made once"
    );
    host.stop().await;
}
