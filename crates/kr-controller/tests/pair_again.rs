//! A device that was paired with a host pairs with it again.
//!
//! One real daemon on the loopback network, a device that holds nothing of the host, and an owner
//! device that issues and confirms each invitation, as a person's would. A record of the device
//! has ended, by a revocation or by the end of its grant, and the host must give the device a
//! record of its own under a new device identifier while the ended one stays as it was. The cases
//! that need two commitments for one endpoint identity at once, which the host's one open
//! invitation cannot make, are the pairing store's (`pairing_store.rs`).
//!
//! Every wait of a case that does not end by itself goes through a thread of its own with a bound
//! and a message of its own, never through a timer of the runtime the daemon runs on: a failing
//! case ends, it does not stand.

#![cfg(unix)]

mod net_support;

use std::future::Future;
use std::time::{Duration, Instant};

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, InvitationId};
use kr_protocol::invitation::{
    InviteGrantKind, InviteMode, InviteModeKind, PairConfirmParams, PairInviteParams,
    PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing::{self as calls, Signer};
use net_support::worker::Adopted;
use net_support::{Device, Host, Moved, connect, pair_with, paired_dial, proposal};

/// How long a case waits for work that correct code does at speed.
const BOUND: Duration = Duration::from_secs(120);

/// Waits for `future` for at most `bound`, by a thread that does not use the runtime's timers.
///
/// The thread waits on a channel that the case drops when the future is done, so it ends then and
/// holds the runtime's shutdown for nothing.
async fn within<T>(what: &str, bound: Duration, future: impl Future<Output = T>) -> T {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let (expired, expiry) = tokio::sync::oneshot::channel::<()>();
    let watcher = tokio::task::spawn_blocking(move || {
        if finished.recv_timeout(bound) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            let _ = expired.send(());
        }
    });
    let output = tokio::select! {
        output = future => output,
        Ok(()) = expiry => panic!("{what} did not finish within {bound:?}"),
    };
    drop(done);
    watcher.await.expect("the watching thread ends");
    output
}

/// Waits until `check` holds, reading it from a thread of its own at most every twenty
/// milliseconds, for at most [`BOUND`].
async fn until(what: &'static str, check: impl Fn() -> bool + Send + 'static) {
    let held = tokio::task::spawn_blocking(move || {
        let end = Instant::now() + BOUND;
        loop {
            if check() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
    .await
    .expect("the waiting thread ends");
    assert!(held, "{what} did not happen within {BOUND:?}");
}

fn registry(host: &Host) -> rusqlite::Connection {
    let connection =
        rusqlite::Connection::open(host.registry_database()).expect("the registry opens");
    connection
        .busy_timeout(Duration::from_secs(30))
        .expect("waits for the daemon's writes");
    connection
}

fn count(host: &Host, statement: &str) -> i64 {
    registry(host)
        .query_row(statement, [], |row| row.get(0))
        .expect("a count")
}

/// Every column of one device's row, as stored.
fn row_of(host: &Host, device_id: DeviceId) -> Vec<rusqlite::types::Value> {
    let connection = registry(host);
    let mut statement = connection
        .prepare("SELECT * FROM network_devices WHERE device_id = ?1")
        .expect("prepares");
    let columns = statement.column_count();
    statement
        .query_row([device_id.get().as_bytes().as_slice()], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .expect("the device's row")
}

fn expired(path: &std::path::Path, device_id: DeviceId) -> bool {
    let Ok(connection) = rusqlite::Connection::open(path) else {
        return false;
    };
    connection
        .query_row(
            "SELECT expired_at_ms IS NOT NULL FROM network_devices WHERE device_id = ?1",
            [device_id.get().as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn rights() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

/// A grant that lasts past the two days the cases that move the clocks take them on.
fn grant_past_the_moved_clocks() -> ProposedGrant {
    let mut grant = rights();
    grant.expiry = kr_protocol::grant::GrantExpiry::At {
        expires_at_ms: kr_protocol::scalars::TimestampMs::new(
            kr_ipc::now_ms().get() + 3 * 24 * 60 * 60 * 1000,
        ),
    };
    grant
}

fn endpoint_of(device: &Device) -> kr_protocol::scalars::EndpointKey {
    *device.keys().transport.public()
}

/// What the host must show of a pairing again, once it committed: a record of its own for the
/// device, the ended one as it was, and a connection of the device admitted under the new
/// identifier only.
async fn assert_the_device_is_paired_again(
    host: &Host,
    device: &Device,
    first: &DeviceRecord,
    first_row: &[rusqlite::types::Value],
    second: &DeviceRecord,
) {
    assert_ne!(
        second.device_id, first.device_id,
        "the record has a device identifier of its own"
    );
    assert_eq!(
        host.network()
            .devices()
            .record_for_endpoint(&endpoint_of(device))
            .expect("readable")
            .map(|record| record.device_id),
        Some(second.device_id),
        "the endpoint identity reads the record that stands"
    );
    assert_eq!(
        host.network()
            .devices()
            .rows_for_endpoint(&endpoint_of(device))
            .expect("readable")
            .len(),
        2,
        "the ended record and the new one"
    );
    assert_eq!(
        row_of(host, first.device_id),
        first_row,
        "the ended record is as it was"
    );
    assert!(
        paired_dial(host, device, first).try_dial().await.is_err(),
        "a connection under the ended record's identifier is refused"
    );
    let session = within("the connection", BOUND, connect(host, device, second)).await;
    within("the host counting the connection", BOUND, async {
        while host.connections_of(second) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(host.connections_of(first), 0);
    session.close();
}

/// KR-REQ-10.08: a device whose record was revoked, and whose revocation finished its barrier,
/// pairs again through a new invitation. The host writes a record under a new identifier and leaves
/// the revoked one as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_pairs_again_after_its_record_was_revoked() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;

    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the device is revoked");
    assert!(barrier.holds(), "{barrier:?}");
    let revoked = row_of(&host, first.device_id);

    let second = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &phone, &owner, rights()),
    )
    .await;
    assert_the_device_is_paired_again(&host, &phone, &first, &revoked, &second).await;
    host.stop().await;
}

/// As the case above, for a record whose grant ran out: the end of the grant is on record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_pairs_again_after_its_grant_ran_out() {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    // The device is connected, which anchors its grant in this boot. The grant runs out: the
    // watch over the connection's grant finds the end and the host records it.
    let session = within("the connection", BOUND, connect(&host, &phone, &first)).await;
    moved.past_the_grant();
    let path = host.registry_database();
    let device_id = first.device_id;
    until("the end of the grant being on record", move || {
        expired(&path, device_id)
    })
    .await;
    session.close();
    // The end of a grant raises no fence: nothing is owed after it, so the replacement is not held.
    assert_eq!(
        count(
            &host,
            "SELECT COALESCE(MAX(fence_owed_revision), 0) FROM environment"
        ),
        0,
        "an expiry owes no fence"
    );
    let ran_out = row_of(&host, first.device_id);

    let second = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &phone, &owner, grant_past_the_moved_clocks()),
    )
    .await;
    assert_the_device_is_paired_again(&host, &phone, &first, &ran_out, &second).await;
    host.stop().await;
}

/// The invitation of a device being paired, bound to a candidate and waiting for the owner.
struct Bound {
    client: kr_ipc::client::LocalClient,
    invitation_id: InvitationId,
    _connection: iroh::endpoint::Connection,
}

async fn bind(host: &Host, device: &Device, owner: &DeviceKeys) -> Bound {
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(owner),
    )
    .await
    .expect("an invitation");
    let (connection, _candidate, _value) = calls::redeem(&device.candidate(), &invited).await;
    Bound {
        client,
        invitation_id: invited.invitation_id,
        _connection: connection,
    }
}

/// The words a person reads when the host is still finishing the earlier withdrawal of access, and
/// the moment the invitation stays open until, which is five minutes after it was issued.
fn barrier_words(issued_at_ms: i64) -> String {
    let until = jiff::Timestamp::from_millisecond(issued_at_ms + 5 * 60 * 1000)
        .expect("a moment")
        .strftime("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    format!(
        "This host is still finishing an earlier withdrawal of access, so it cannot add this \
         device yet. Ask for a new confirmation in a minute; this invitation stays open until \
         {until}."
    )
}

/// KR-REQ-10.08: the host does not add a device in the place of a record whose withdrawal of
/// access is still being finished. A worker that is registered and does not acknowledge keeps the
/// revocation's fence owed. The confirmation is refused with the fixed words and nothing is
/// consumed, so the same invitation takes a fresh confirmation once the worker has acknowledged;
/// a device with no record of its endpoint identity is added all the while.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_replacement_waits_for_the_barrier_and_a_first_pairing_does_not() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    // Nothing asks the worker again until the case lets it.
    host.controller().hold_the_pass_asks_for_tests(true);
    let worker = &workers[0];
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;

    // The worker is inside its dispatch boundary, so it answers the fence with a refusal and the
    // revocation's barrier does not hold.
    let boundary = worker.hold_the_dispatch_boundary().await;
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the device is revoked");
    assert_eq!(barrier.pending(), vec![worker.session_id], "{barrier:?}");
    assert!(
        count(
            &host,
            "SELECT COALESCE(MAX(fence_owed_revision), 0) FROM environment"
        ) > 0,
        "the revocation's fence is owed"
    );

    // A device with no record of its endpoint identity is added while the fence is owed: the rule
    // is for a replacement only. The host offers one invitation at a time, so it is added first.
    let tablet = Device::create().await;
    let added = within(
        "the first pairing",
        BOUND,
        pair_with(&host, &tablet, &owner, rights()),
    )
    .await;
    assert_eq!(added.endpoint_id, endpoint_of(&tablet));

    // The device with the ended record is bound to a new invitation and the owner confirms it.
    let signer = Signer::OwnerDevice(&owner);
    let mut again = bind(&host, &phone, &owner).await;
    let issued_at_ms: i64 = registry(&host)
        .query_row(
            "SELECT issued_at_ms FROM pairing_invitations WHERE invitation_id = ?1",
            [again.invitation_id.get().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the invitation's issue moment");
    let spent = count(
        &host,
        "SELECT COUNT(*) FROM owner_confirmations WHERE consumed_at_ms IS NOT NULL",
    );
    let events = count(&host, "SELECT COUNT(*) FROM pairing_events");
    let refused = within(
        "the confirmation",
        BOUND,
        calls::confirm_candidate(
            host.environment_id,
            &mut again.client,
            again.invitation_id,
            &signer,
        ),
    )
    .await
    .expect_err("the host is still finishing the earlier withdrawal");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
    assert_eq!(refused.message, barrier_words(issued_at_ms));
    assert_eq!(
        count(
            &host,
            "SELECT COUNT(*) FROM owner_confirmations WHERE consumed_at_ms IS NOT NULL"
        ),
        spent,
        "no confirmation was spent"
    );
    assert_eq!(count(&host, "SELECT COUNT(*) FROM pairing_events"), events);
    assert_eq!(
        host.network()
            .devices()
            .rows_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .len(),
        1,
        "no device row was written"
    );
    let state: (String, Option<String>) = registry(&host)
        .query_row(
            "SELECT state, consumed_reason FROM pairing_invitations WHERE invitation_id = ?1",
            [again.invitation_id.get().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the invitation's state");
    assert_eq!(
        state,
        ("locked".to_owned(), None),
        "the invitation is locked and not consumed"
    );

    // The confirmation that was refused does not work again: its challenge was consumed in memory
    // before the store was asked, and the answer is not kept for a second try.
    let status = calls::owner_status(&mut again.client, again.invitation_id)
        .await
        .expect("the owner's view");
    let approval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("the candidate is still bound");
    let repeated = within(
        "the repeated confirmation",
        BOUND,
        calls::mutate::<_, kr_protocol::invitation::PairConfirmResult>(
            host.environment_id,
            &mut again.client,
            Method::PairConfirm,
            &PairConfirmParams {
                invitation_id: again.invitation_id,
                approval,
            },
        ),
    )
    .await
    .expect_err("the old confirmation is not taken again");
    assert_eq!(
        repeated.code,
        ErrorCode::OwnerConfirmationRequired,
        "the old confirmation is not taken again: {repeated:?}"
    );
    assert_eq!(
        repeated.message,
        "this action needs a fresh owner confirmation naming it"
    );

    // The worker acknowledges, the fence settles, and a fresh confirmation of the same invitation
    // commits.
    boundary.release();
    worker.service.fence_what_is_owed_for_tests();
    host.controller().hold_the_pass_asks_for_tests(false);
    within("the barrier holding", BOUND, async {
        loop {
            let barrier = host
                .controller()
                .announce_authority_revision()
                .await
                .expect("the revision is announced");
            if barrier.holds() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let confirmed = within(
        "the fresh confirmation",
        BOUND,
        calls::confirm_candidate(
            host.environment_id,
            &mut again.client,
            again.invitation_id,
            &signer,
        ),
    )
    .await
    .expect("a fresh confirmation commits once the worker has acknowledged");
    assert_ne!(confirmed.device_id, first.device_id);
    let second = host.record_of(confirmed.device_id);
    assert_eq!(second.endpoint_id, endpoint_of(&phone));
    assert_eq!(
        host.network()
            .devices()
            .record_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .map(|record| record.device_id),
        Some(second.device_id)
    );
    host.stop().await;
}

/// KR-REQ-10.06: the owner's local client carries a proof that an owner device signed, as the
/// owner's does in every pairing here. The confirmation is recorded under the device whose record
/// answered it, though the caller is the host's own account, and the pairing spends it. A rule that
/// matched the confirmation's caller to the standing record would refuse this flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_local_caller_carrying_an_owner_devices_proof_spends_it_and_the_row_names_the_device() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let owner_device = host
        .owner
        .as_ref()
        .expect("the host's owner device")
        .device_id;
    let phone = Device::create().await;
    within(
        "the pairing",
        BOUND,
        pair_with(&host, &phone, &owner, rights()),
    )
    .await;

    let rows: Vec<(Option<Vec<u8>>, String, bool)> = registry(&host)
        .prepare(
            "SELECT signer_device_id, answered_by, consumed_at_ms IS NOT NULL
             FROM owner_confirmations WHERE signer_device_id IS NOT NULL",
        )
        .expect("prepares")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row");
    assert_eq!(
        rows.len(),
        2,
        "the invitation's confirmation and the device's, both answered by the owner device: {rows:?}"
    );
    for (signer, answered_by, spent) in rows {
        assert_eq!(
            signer.as_deref(),
            Some(owner_device.get().as_bytes().as_slice()),
            "the row names the owner device that answered"
        );
        assert!(
            answered_by.starts_with("local:"),
            "the caller is the host's own account: {answered_by}"
        );
        assert!(spent, "the pairing spent the confirmation");
    }
    host.stop().await;
}

/// How many answered confirmations name `device_id` as the record that answered, and how many of
/// those were spent.
fn answers_of(host: &Host, device_id: DeviceId) -> (i64, i64) {
    registry(host)
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(consumed_at_ms IS NOT NULL), 0)
             FROM owner_confirmations WHERE signer_device_id = ?1",
            [device_id.get().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the answers")
}

/// KR-REQ-10.06: an answer that an owner device gave is taken only while the record that gave it
/// stands, not while some record holds the same authorisation key. The owner device answers the
/// confirmation of issuing an invitation and its record is revoked; a record of another endpoint
/// identity then holds the same key. The host does not take the old answer: it refuses the
/// invitation, spends nothing and issues nothing. The new record's own answer is taken, and the old
/// one is passed over without being spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_answer_is_not_taken_once_its_record_ended_though_a_new_record_holds_its_key() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let first = host.owner.clone().expect("the host's owner device");
    let signer = Signer::OwnerDevice(&owner);
    let mut client = host.client().await;
    let subject = || ConfirmationSubject::IssueInvitation {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: rights(),
    };
    let invite = PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: rights(),
    };

    // The owner device answers; nothing spends the answer yet.
    calls::confirm_subject(host.environment_id, &mut client, subject(), &signer)
        .await
        .expect("the owner device answers");
    assert_eq!(answers_of(&host, first.device_id), (1, 0));
    let invitations = count(&host, "SELECT COUNT(*) FROM pairing_invitations");

    // Its record is revoked, and a record of another endpoint identity holds the same key.
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the owner device is revoked");
    assert!(barrier.holds(), "{barrier:?}");
    let mut second = first.clone();
    second.device_id = DeviceId::new(kr_ipc::new_uuid());
    second.endpoint_id = *DeviceKeys::generate().expect("keys").transport.public();
    second.revoked_at_ms = None;
    second.expired_at_ms = None;
    host.network()
        .devices()
        .commit(&second)
        .expect("a record that holds the key of the revoked one");

    let refused = within(
        "the invitation",
        BOUND,
        calls::mutate::<_, PairInviteResult>(
            host.environment_id,
            &mut client,
            Method::PairInvite,
            &invite,
        ),
    )
    .await
    .expect_err("the answer of the ended record is not taken");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    assert!(
        refused.message.contains("no longer holds"),
        "the host says the authority behind the answer has gone: {refused:?}"
    );
    assert_eq!(
        answers_of(&host, first.device_id),
        (1, 0),
        "nothing was spent"
    );
    assert_eq!(
        count(&host, "SELECT COUNT(*) FROM pairing_invitations"),
        invitations,
        "no invitation was issued"
    );

    // The new record answers for itself, with the same key, and is taken; the old answer stays
    // unspent.
    calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &signer,
    )
    .await
    .expect("the new record's answer is taken");
    assert_eq!(answers_of(&host, second.device_id), (1, 1));
    assert_eq!(answers_of(&host, first.device_id), (1, 0));
    host.stop().await;
}

/// KR-REQ-10.06: a proof that was answered once is spent only under the record that answered it,
/// however often it is completed. The owner device answers the confirmation of issuing an
/// invitation, its record is revoked and a record of another endpoint identity holds the same key.
/// The same proof is then completed again, under a new action identifier, which the host accepts
/// as a copy of the answer. The acceptance record still names the record that answered, so the
/// invitation is refused and nothing is spent; the new record's own answer is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_proof_completed_again_is_still_spent_only_under_the_record_that_answered_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let first = host.owner.clone().expect("the host's owner device");
    let signer = Signer::OwnerDevice(&owner);
    let mut client = host.client().await;
    let invite = PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: rights(),
    };

    let challenge = calls::request(
        host.environment_id,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: rights(),
        },
    )
    .await
    .expect("the host describes the invitation");
    let (proof, presented) = calls::sign(&challenge.request, &signer);
    calls::complete(host.environment_id, &mut client, proof.clone(), presented)
        .await
        .expect("the owner device answers");
    assert_eq!(answers_of(&host, first.device_id), (1, 0));
    let invitations = count(&host, "SELECT COUNT(*) FROM pairing_invitations");

    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the owner device is revoked");
    assert!(barrier.holds(), "{barrier:?}");
    let mut second = first.clone();
    second.device_id = DeviceId::new(kr_ipc::new_uuid());
    second.endpoint_id = *DeviceKeys::generate().expect("keys").transport.public();
    second.revoked_at_ms = None;
    second.expired_at_ms = None;
    host.network()
        .devices()
        .commit(&second)
        .expect("a record that holds the key of the revoked one");

    // The same proof again, under a new action identifier: accepted as a copy of the answer, and
    // the record that answered stays the first.
    calls::complete(host.environment_id, &mut client, proof, None)
        .await
        .expect("the same proof is completed again");
    assert_eq!(
        answers_of(&host, first.device_id),
        (1, 0),
        "the acceptance record still names the record that answered"
    );
    assert_eq!(answers_of(&host, second.device_id), (0, 0));

    let refused = within(
        "the invitation",
        BOUND,
        calls::mutate::<_, PairInviteResult>(
            host.environment_id,
            &mut client,
            Method::PairInvite,
            &invite,
        ),
    )
    .await
    .expect_err("the answer of the ended record is not spent under the record that holds its key");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    assert!(
        refused.message.contains("no longer holds"),
        "the host says the authority behind the answer has gone: {refused:?}"
    );
    assert_eq!(
        answers_of(&host, first.device_id),
        (1, 0),
        "nothing was spent"
    );
    assert_eq!(
        count(&host, "SELECT COUNT(*) FROM pairing_invitations"),
        invitations,
        "no invitation was issued"
    );

    // Control: the new record answers for itself and is taken.
    calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &signer,
    )
    .await
    .expect("the new record's own answer is taken");
    assert_eq!(answers_of(&host, second.device_id), (1, 1));
    assert_eq!(answers_of(&host, first.device_id), (1, 0));
    host.stop().await;
}

/// Every row of `table`, as stored.
fn rows_of(host: &Host, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let connection = registry(host);
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .expect("prepares");
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row")
}

/// KR-REQ-10.08: nothing the ended record held carries over to the record that replaces it. The
/// ended record has a route for an action and a deadline for its grant, and the host has an
/// owner. After the device pairs again, the new record's identifier finds no route and no
/// deadline, the old ones are as they were, the ended row is byte for byte what it was when the
/// revocation finished, and the owner is the same one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn nothing_the_ended_record_held_carries_over_to_the_record_that_replaces_it() {
    use kr_controller::service::net::devices::ActionRoute;
    use kr_protocol::scalars::{Digest256, TimestampMs};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let directory = host.network().devices();
    let old_actor = kr_transport::listener::device_principal(&first.device_id);
    let action = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let digest = Digest256::from_bytes([7; 32]);
    let now = TimestampMs::new(kr_ipc::now_ms().get());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    assert_eq!(
        directory
            .claim_action_route(&old_actor, action, None, digest, now)
            .expect("a route"),
        ActionRoute::Recorded
    );
    directory
        .record_grant_deadline(first.device_id, &boot, 123_456)
        .expect("a deadline");

    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the device is revoked");
    assert!(barrier.holds(), "{barrier:?}");
    let revoked = row_of(&host, first.device_id);
    let old_deadline = directory
        .grant_deadline_in(first.device_id, &boot)
        .expect("readable");
    let owner_rows = rows_of(&host, "host_owner");
    assert_eq!(owner_rows.len(), 1, "the host has its owner");

    let second = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &phone, &owner, rights()),
    )
    .await;
    let new_actor = kr_transport::listener::device_principal(&second.device_id);

    // N10: the ended row is as it was when the revocation finished.
    assert_eq!(row_of(&host, first.device_id), revoked);
    // N1: the new identifier is told it is the first to claim the action, and the old route is
    // still the old record's.
    assert_eq!(
        directory
            .claim_action_route(&new_actor, action, None, digest, now)
            .expect("a route"),
        ActionRoute::Recorded,
        "the new record finds no route of the old one"
    );
    assert!(
        matches!(
            directory
                .claim_action_route(&old_actor, action, None, digest, now)
                .expect("a route"),
            ActionRoute::Existing(_)
        ),
        "the old route stands under the old identifier"
    );
    // N7: no deadline for the new identifier, and the old one is as it was.
    assert_eq!(
        directory
            .grant_deadline_in(second.device_id, &boot)
            .expect("readable"),
        None
    );
    assert_eq!(
        directory
            .grant_deadline_in(first.device_id, &boot)
            .expect("readable"),
        old_deadline
    );
    // N9: the owner is the same.
    assert_eq!(rows_of(&host, "host_owner"), owner_rows);
    host.stop().await;
}

/// What a connection that is admitted answers to a read every paired device may make.
async fn is_served(session: &kr_client::session::Session) -> bool {
    let read: Result<kr_protocol::hostinfo::HostDoctorResult, _> =
        session.read(Method::HostDoctor, &()).await;
    read.is_ok()
}

/// KR-REQ-10.08: a connection is the record it was admitted under for its whole life. One device
/// has its grant run out while its connection stays open, and one has its record revoked while
/// its connection is open; both pair again. The expired device's old connection stays open and
/// is refused every request, because its checks read the old record by its identifier and never
/// the new one; the revoked device's old connection is ended by the barrier. The new connections
/// are served and count toward the new identifiers from zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_old_connection_is_served_nothing_under_the_record_that_replaced_its_record() {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let ran_out = Device::create().await;
    let first_ran_out = pair_with(&host, &ran_out, &owner, rights()).await;
    let old_ran_out = within(
        "the connection",
        BOUND,
        connect(&host, &ran_out, &first_ran_out),
    )
    .await;
    assert!(
        is_served(&old_ran_out).await,
        "served while its grant stands"
    );
    moved.past_the_grant();
    let path = host.registry_database();
    let device_id = first_ran_out.device_id;
    until("the end of the grant being on record", move || {
        expired(&path, device_id)
    })
    .await;

    let revoked = Device::create().await;
    let first_revoked = pair_with(&host, &revoked, &owner, grant_past_the_moved_clocks()).await;
    let old_revoked = within(
        "the connection",
        BOUND,
        connect(&host, &revoked, &first_revoked),
    )
    .await;
    assert!(is_served(&old_revoked).await, "served while it stands");
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first_revoked.device_id),
    )
    .await
    .expect("the device is revoked");
    assert!(barrier.holds(), "{barrier:?}");

    let second_ran_out = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &ran_out, &owner, grant_past_the_moved_clocks()),
    )
    .await;
    let second_revoked = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &revoked, &owner, grant_past_the_moved_clocks()),
    )
    .await;

    assert!(
        !is_served(&old_ran_out).await,
        "the connection of the record that ran out is refused every request"
    );
    assert!(
        !is_served(&old_revoked).await,
        "the connection of the revoked record was ended"
    );
    for (device, second) in [(&ran_out, &second_ran_out), (&revoked, &second_revoked)] {
        let session = within("the connection", BOUND, connect(&host, device, second)).await;
        assert!(is_served(&session).await, "the new connection is served");
        within("the host counting the connection", BOUND, async {
            while host.connections_of(second) != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        session.close();
    }
    assert_eq!(
        host.connections_of(&first_revoked),
        0,
        "nothing is counted for the revoked record"
    );
    old_ran_out.close();
    host.stop().await;
}
