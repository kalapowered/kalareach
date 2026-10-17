//! What settings sync's collections answer this crate's client, held to the contract and the
//! Worker's collection: the stand-in the daemon's and the companion's tests talk to.
//!
//! Every case drives the real client over the real signed call, against the stand-in in process.
//! Nothing here is a scripted answer.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.13, compare and swap, the refused content kept for the person | `a_stale_write_is_refused_and_its_content_is_kept_for_the_person` |
//! | KR-REQ-20.13, a copy nobody chose against is never dropped | `a_collection_never_drops_a_copy_nobody_chose_against` |
//! | KR-REQ-20.13, a write retried or lost | `a_request_identity_is_answered_from_its_receipt_and_a_fence_ends_it` |
//!
//! The whole of the route, member by member, is held to a recording by `settings_answers.rs`; the
//! cases here are the ones that need the bytes of a sealed object, which a recording keeps no
//! copy of, and a spent allowance, which a local Worker cannot be made to have.

use std::sync::Arc;

use kr_client::ClientError;
use kr_client::services::{
    ManagedSyncService, ServiceHttp, SyncBackupService, SyncExchanged, SyncRequestFence,
    SyncRequestStatus,
};
use kr_client::sync::sync_collection;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::secret::Secret;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{SyncConflictId, SyncObjectId};
use kr_protocol::scalars::Uuid;
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_protocol::sync::{MAX_SYNC_CONFLICT_COPIES, SyncObjectKind};
use kr_service_stand_in::ServiceWeb;

mod recording;

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

fn identity() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("an identity")
}

/// A real sealed object, under a key the service never sees, as the bytes a sealer hands over.
fn sealed(plaintext: &[u8]) -> Vec<u8> {
    let object = kr_crypto::envelope::seal_sync_object(&Secret::from_bytes([0x5a; 32]), plaintext)
        .expect("a sealed object");
    kr_cbor::to_canonical_vec(&object).expect("canonical bytes")
}

/// One device: its keys and the client it reaches the service with.
struct Device {
    keys: DeviceKeys,
    service: Arc<ManagedSyncService>,
}

impl Device {
    fn on(web: &Arc<ServiceWeb>) -> Self {
        let keys = DeviceKeys::generate().expect("a device's keys");
        // The client signs with the authorisation key the device's keys name.
        let signer = Arc::new(recording::Keyed {
            key: keys.authorisation.clone(),
            signer: ServiceRequestSigner::Installation,
        });
        let service = ManagedSyncService::new(
            GatewayOrigin::new(web.origin()).expect("an origin"),
            Arc::clone(web) as Arc<dyn ServiceHttp>,
            signer as _,
        );
        Self {
            keys,
            service: Arc::new(service),
        }
    }
}

fn settings_collection(object: Uuid) -> String {
    sync_collection(SyncObjectKind::Settings, SyncObjectId::new(object))
}

/// What an exchange applied, or a failure of the test.
fn applied(answer: Result<SyncExchanged, ClientError>) -> kr_client::services::SyncPosition {
    match answer {
        Ok(SyncExchanged::Applied { position }) => position,
        other => panic!("the write was not applied: {other:?}"),
    }
}

/// The copy a refused write was kept as, and where the object stood.
fn refused(
    answer: Result<SyncExchanged, ClientError>,
) -> (
    Option<SyncConflictId>,
    Option<kr_client::services::SyncPosition>,
) {
    match answer {
        Ok(SyncExchanged::Refused {
            retained, current, ..
        }) => (retained, current),
        other => panic!("the write was not refused: {other:?}"),
    }
}

/// A write that loses its comparison is refused, and what it carried is kept beside the object for
/// the person to choose between. Nothing is chosen by a clock: the object stays what it was until
/// a write that names its revision replaces it.
#[tokio::test]
async fn a_stale_write_is_refused_and_its_content_is_kept_for_the_person() {
    let web = Arc::new(ServiceWeb::new());
    let device = Device::on(&web);
    let collection = settings_collection(identity());
    let (mine, theirs, later) = (sealed(b"dark"), sealed(b"light"), sealed(b"system"));

    let first = applied(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), None, &mine)
            .await,
    );
    assert_eq!(first.write_sequence, 1);

    // Another device that had not seen the first write names no revision either.
    let (copy, current) = refused(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), None, &theirs)
            .await,
    );
    let copy = copy.expect("a refused write with content is kept as a copy");
    assert_eq!(current, Some(first));

    let found = device
        .service
        .compare(&collection, true, None)
        .await
        .expect("a comparison");
    assert_eq!(found.objects.len(), 1);
    assert_eq!(found.objects[0].ciphertext, mine, "the object is unchanged");
    assert_eq!(found.copies.len(), 1);
    assert_eq!(found.copies[0].conflict_id, copy);
    assert_eq!(found.copies[0].ciphertext, theirs);
    assert_eq!(found.stored.conflicts.get(), 1);

    // The person's choice goes to the service, which drops the copy and nothing else.
    assert!(
        device
            .service
            .resolve(&collection, copy)
            .await
            .expect("a resolution")
    );
    let found = device
        .service
        .compare(&collection, true, None)
        .await
        .expect("a comparison");
    assert!(found.copies.is_empty());
    assert_eq!(found.objects[0].ciphertext, mine);

    // A write that names the revision it replaces is applied at the next place in the order.
    let second = applied(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), Some(first), &later)
            .await,
    );
    assert_eq!(second.write_sequence, 2);
}

/// An object holds at most as many copies as the service keeps. The write past them is refused
/// outright: dropping the oldest to make room would choose by the clock, which settings sync never
/// does, so every copy stays until the person has chosen against it.
#[tokio::test]
async fn a_collection_never_drops_a_copy_nobody_chose_against() {
    let web = Arc::new(ServiceWeb::new());
    let device = Device::on(&web);
    let collection = settings_collection(identity());
    applied(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), None, &sealed(b"base"))
            .await,
    );
    let mut kept = Vec::new();
    for at in 0..MAX_SYNC_CONFLICT_COPIES {
        let (copy, _) = refused(
            device
                .service
                .compare_exchange(
                    &collection,
                    identity(),
                    now_ms(),
                    None,
                    &sealed(format!("copy {at}").as_bytes()),
                )
                .await,
        );
        kept.push(copy.expect("a copy"));
    }

    let error = device
        .service
        .compare_exchange(
            &collection,
            identity(),
            now_ms(),
            None,
            &sealed(b"one more"),
        )
        .await
        .expect_err("the write past the copies is refused");
    assert_eq!(error.code(), ErrorCode::QuotaExceeded);

    let found = device
        .service
        .compare(&collection, true, None)
        .await
        .expect("a comparison");
    let held: Vec<SyncConflictId> = found.copies.iter().map(|copy| copy.conflict_id).collect();
    assert_eq!(held, kept, "every copy is still there, the oldest included");

    // Control: once a choice drops one, the next refused write is kept again.
    assert!(
        device
            .service
            .resolve(&collection, kept[0])
            .await
            .expect("a resolution")
    );
    let (copy, _) = refused(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), None, &sealed(b"room"))
            .await,
    );
    assert!(copy.is_some());
}

/// A request identity is a write's name. Asked again it is answered what it was, though the object
/// has moved on; other content under it is refused; a status query and a fence settle one whose
/// answer was lost, and a fenced identity is never carried out.
#[tokio::test]
async fn a_request_identity_is_answered_from_its_receipt_and_a_fence_ends_it() {
    let web = Arc::new(ServiceWeb::new());
    let device = Device::on(&web);
    let collection = settings_collection(identity());
    let name = identity();
    let signed = now_ms();
    // A sealer draws a fresh nonce for each object, so a retry sends the bytes of the first attempt.
    let write_a = sealed(b"a");

    let first = applied(
        device
            .service
            .compare_exchange(&collection, name, signed, None, &write_a)
            .await,
    );
    let second = applied(
        device
            .service
            .compare_exchange(
                &collection,
                identity(),
                now_ms(),
                Some(first),
                &sealed(b"b"),
            )
            .await,
    );
    assert_eq!(second.write_sequence, 2);

    // The same write again: what the first attempt was told, not where the object stands now.
    let again = applied(
        device
            .service
            .compare_exchange(&collection, name, now_ms(), None, &write_a)
            .await,
    );
    assert_eq!(again, first);
    let other = device
        .service
        .compare_exchange(&collection, name, now_ms(), None, &sealed(b"c"))
        .await
        .expect_err("other content under a used identity");
    assert_eq!(other.code(), ErrorCode::IdConflict);

    assert_eq!(
        device
            .service
            .request_status(&collection, name)
            .await
            .expect("a status"),
        SyncRequestStatus::Applied { position: first }
    );

    // An identity nothing was recorded for is unknown until it is fenced, and then never runs.
    let lost = identity();
    assert!(matches!(
        device
            .service
            .request_status(&collection, lost)
            .await
            .expect("a status"),
        SyncRequestStatus::Unknown { .. }
    ));
    let fenced = device
        .service
        .fence_request(&collection, lost, signed, signed)
        .await
        .expect("a fence");
    assert!(matches!(
        fenced,
        SyncRequestFence::Fenced {
            never_ran: true,
            ..
        }
    ));
    let late = device
        .service
        .compare_exchange(&collection, lost, now_ms(), Some(second), &sealed(b"late"))
        .await
        .expect_err("a fenced identity is not carried out");
    assert_eq!(late.code(), ErrorCode::PermissionDenied);
    let found = device
        .service
        .compare(&collection, false, None)
        .await
        .expect("a comparison");
    assert_eq!(
        found.objects[0].position, second,
        "the late write changed nothing"
    );

    // A fence at a write the service already applied finds its outcome and changes nothing.
    assert_eq!(
        device
            .service
            .fence_request(&collection, name, signed, signed)
            .await
            .expect("a fence"),
        SyncRequestFence::Applied { position: first }
    );
}

/// A principal whose settings-sync allowance is spent is refused a write, and says what an
/// exhausted allowance says; the same write is applied when the allowance is there again.
///
/// Source only: a local deployment has no ledger to spend (`sync/collection.ts`, the hold), so no
/// recording can show it.
#[tokio::test]
async fn a_principal_with_no_allowance_is_refused_a_write() {
    let web = Arc::new(ServiceWeb::new());
    let device = Device::on(&web);
    let collection = settings_collection(identity());
    let object = sealed(b"dark");

    web.refuse_settings_writes(true);
    let refused = device
        .service
        .compare_exchange(&collection, identity(), now_ms(), None, &object)
        .await
        .expect_err("a write the allowance does not admit");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);

    web.refuse_settings_writes(false);
    applied(
        device
            .service
            .compare_exchange(&collection, identity(), now_ms(), None, &object)
            .await,
    );
}
