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
use kr_protocol::ids::{ActionId, DeviceId, InvitationId};
use kr_protocol::invitation::{
    InviteGrantKind, InviteMode, InviteModeKind, PairConfirmParams, PairConfirmResult,
    PairInviteParams, PairInviteResult, PairingApproval,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{DeviceName, PairStatus, PairingConsumedReason, ProposedGrant};
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
        while host.connections_of(first) + host.connections_of(second) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(
        host.connections_of(second),
        1,
        "the connection counts under the new identifier"
    );
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
    /// The moment the invitation advertised that it stays open until, as the owner was told it.
    expires_at_ms: u64,
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
        expires_at_ms: invited.expires_at_ms.get(),
        _connection: connection,
    }
}

/// The words a person reads when the host is still finishing the earlier withdrawal of access, and
/// the moment the invitation stays open until, which is the expiry the invitation advertised.
fn barrier_words(expires_at_ms: u64) -> String {
    let until = jiff::Timestamp::from_millisecond(i64::try_from(expires_at_ms).expect("a moment"))
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
    assert_eq!(refused.message, barrier_words(again.expires_at_ms));
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

/// KR-REQ-10.08: the moment the refusal names is the moment the invitation advertised, not one
/// rebuilt from when the host stamped the invitation as issued. The host stamps the issue first,
/// and the invitation reads the clock again for the expiry it advertises once its record is
/// written; a wait between the two makes them differ. Here the case holds the registry's write
/// lock for three seconds while the invitation is issued, so the two reads are three seconds
/// apart. The refusal of the confirmation names the advertised expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_barrier_refusal_names_the_expiry_the_invitation_advertised() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    host.controller().hold_the_pass_asks_for_tests(true);
    let worker = &workers[0];
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let boundary = worker.hold_the_dispatch_boundary().await;
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the device is revoked");
    assert_eq!(barrier.pending(), vec![worker.session_id], "{barrier:?}");

    // The owner answers the invitation's challenge, and the case then holds the registry's write
    // lock while the invitation is issued.
    let signer = Signer::OwnerDevice(&owner);
    let mut client = host.client().await;
    // One proposal for the challenge and the invitation: its expiry is read from the clock.
    let proposed = rights();
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: proposed.clone(),
        },
        &signer,
    )
    .await
    .expect("the owner answers");
    let (locked, lock_held) = std::sync::mpsc::channel::<()>();
    let path = host.registry_database();
    let holder = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(path).expect("the registry opens");
        connection
            .busy_timeout(Duration::from_secs(30))
            .expect("waits for the daemon's writes");
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .expect("the write lock is taken");
        locked.send(()).expect("the case is waiting");
        std::thread::sleep(Duration::from_secs(3));
        connection
            .execute_batch("COMMIT")
            .expect("the lock is let go");
    });
    lock_held
        .recv_timeout(BOUND)
        .expect("the case holds the registry's write lock");
    let invited = within(
        "the invitation",
        BOUND,
        calls::mutate::<_, PairInviteResult>(
            host.environment_id,
            &mut client,
            Method::PairInvite,
            &PairInviteParams {
                mode: InviteMode::Direct,
                grant_kind: InviteGrantKind::SessionInvitation,
                proposed_grant: proposed,
            },
        ),
    )
    .await
    .expect("an invitation");
    holder.join().expect("the holding thread ends");
    let (connection, _candidate, _value) = calls::redeem(&phone.candidate(), &invited).await;
    let issued_at_ms: u64 = registry(&host)
        .query_row(
            "SELECT issued_at_ms FROM pairing_invitations WHERE invitation_id = ?1",
            [invited.invitation_id.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .map(|stamped| u64::try_from(stamped).expect("a moment"))
        .expect("the invitation's issue moment");
    let reconstructed = issued_at_ms + 5 * 60 * 1000;
    assert!(
        invited.expires_at_ms.get() >= reconstructed + 2_500,
        "the advertised expiry {} was read after the wait, later than the stamp of the issue \
         {issued_at_ms} says",
        invited.expires_at_ms.get()
    );
    let refused = within(
        "the confirmation",
        BOUND,
        calls::confirm_candidate(
            host.environment_id,
            &mut client,
            invited.invitation_id,
            &signer,
        ),
    )
    .await
    .expect_err("the host is still finishing the earlier withdrawal");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
    assert_eq!(
        refused.message,
        barrier_words(invited.expires_at_ms.get()),
        "the refusal names the moment the invitation advertised"
    );
    assert_ne!(
        refused.message,
        barrier_words(reconstructed),
        "and not one rebuilt from the stamp of the issue"
    );
    boundary.release();
    drop(connection);
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
    let proposal = rights();
    let subject = || ConfirmationSubject::IssueInvitation {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: proposal.clone(),
    };
    let invite = PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: proposal.clone(),
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
    let proposal = rights();
    let invite = PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: proposal.clone(),
    };

    let challenge = calls::request(
        host.environment_id,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: proposal.clone(),
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
/// has its grant run out while its connection is open, and one has its record revoked while its
/// connection is open; both pair again. The host ends each old connection and drops it from the
/// table it counts connections in when its record ends, before any new record exists, so nothing
/// of it can count toward the new identifier or be read under the new record: a request on either
/// old connection after the second pairing is served nothing. The new connections are served and
/// count toward the new identifiers from zero, each under its own identifier.
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
    assert_eq!(host.connections_of(&first_ran_out), 1);
    moved.past_the_grant();
    let path = host.registry_database();
    let device_id = first_ran_out.device_id;
    until("the end of the grant being on record", move || {
        expired(&path, device_id)
    })
    .await;
    within("the host dropping the connection", BOUND, async {
        while host.connections_of(&first_ran_out) != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
    assert_eq!(host.connections_of(&first_revoked), 1);
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first_revoked.device_id),
    )
    .await
    .expect("the device is revoked");
    assert!(barrier.holds(), "{barrier:?}");
    within(
        "the host dropping the revoked record's connection",
        BOUND,
        async {
            while host.connections_of(&first_revoked) != 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await;
    assert_eq!(
        host.connections_of(&first_revoked),
        0,
        "the revoked record's connection was dropped when its record ended"
    );

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
        "the connection of the record that ran out is served nothing"
    );
    assert!(
        !is_served(&old_revoked).await,
        "the connection of the revoked record is served nothing"
    );
    let mut sessions = Vec::new();
    for (device, second) in [(&ran_out, &second_ran_out), (&revoked, &second_revoked)] {
        let session = within("the connection", BOUND, connect(&host, device, second)).await;
        assert!(is_served(&session).await, "the new connection is served");
        sessions.push(session);
    }
    let records = [
        &first_ran_out,
        &first_revoked,
        &second_ran_out,
        &second_revoked,
    ];
    within("the host counting the connections", BOUND, async {
        while records
            .iter()
            .map(|record| host.connections_of(record))
            .sum::<u32>()
            != 2
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(
        records.map(|record| host.connections_of(record)),
        [0, 0, 1, 1],
        "the new connections count under the new identifiers and nothing counts under the old ones"
    );
    for session in sessions {
        session.close();
    }
    host.stop().await;
}

/// Revokes `first` as its owner does, through `device.revoke`, which withdraws every grant the
/// device holds and waits for the withdrawal to finish its barrier, and pairs `device` again under
/// `proposed`: what the cases below do once they have put something in the ended record's name.
/// Returns the new record and what the revocation answered.
async fn replaced_after_a_revocation(
    host: &Host,
    device: &Device,
    owner: &DeviceKeys,
    first: &DeviceRecord,
    proposed: ProposedGrant,
) -> (DeviceRecord, kr_protocol::sharing::RevocationResult) {
    let mut client = host.client().await;
    let revoked: kr_protocol::sharing::RevocationResult = within(
        "the revocation",
        BOUND,
        calls::mutate(
            host.environment_id,
            &mut client,
            Method::DeviceRevoke,
            &kr_protocol::sharing::DeviceRevokeParams {
                device_id: first.device_id,
            },
        ),
    )
    .await
    .expect("the device is revoked");
    assert!(revoked.barrier.holds(), "{:?}", revoked.barrier);
    let second = within(
        "the second pairing",
        BOUND,
        pair_with(host, device, owner, proposed),
    )
    .await;
    (second, revoked)
}

/// The registry's rows of `table` whose `column` holds `device_id`, as stored.
fn rows_naming(
    host: &Host,
    table: &str,
    column: &str,
    device_id: DeviceId,
) -> Vec<Vec<rusqlite::types::Value>> {
    let connection = registry(host);
    let mut statement = connection
        .prepare(&format!(
            "SELECT * FROM {table} WHERE {column} = ?1 ORDER BY 1"
        ))
        .expect("prepares");
    let columns = statement.column_count();
    statement
        .query_map([device_id.get().as_bytes().as_slice()], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row")
}

/// The action identifier the worker's own seed gives its first intent.
fn seeded_action() -> kr_protocol::ids::ActionId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&1_u64.to_be_bytes());
    kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
}

/// What the worker's journal holds for one action of one actor.
fn worker_receipt(
    worker: &net_support::worker::Worker,
    actor: &kr_protocol::ids::ActorId,
    action: kr_protocol::ids::ActionId,
) -> Option<kr_protocol::receipt::Receipt> {
    let mut session = worker.runtime().session();
    session
        .journal_mut()
        .expect("a journal")
        .read(actor.clone(), action)
        .expect("readable")
}

/// KR-REQ-10.08: the answers kept for the ended record's actions stay under its identifier. The
/// host keeps an answer to an action of the ended record's actor, and so does the worker; after
/// the device pairs again, a retry of that action under the old identifier is given the answer it
/// was given, as it stood, and the same action under the new identifier finds none in either
/// store.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_answers_kept_for_the_ended_record_are_found_under_its_identifier_and_not_under_the_new_one()
 {
    use kr_controller::grants::{ActionClaim, ActionRecord, GrantDirectory};
    use kr_protocol::scalars::Digest256;

    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let old_actor = kr_transport::listener::device_principal(&first.device_id);
    let action = seeded_action();
    let digest = Digest256::from_bytes([3; 32]);
    let now = kr_ipc::now_ms().get();

    // The host keeps an answer to the action, and the worker holds a receipt for it.
    let store = GrantDirectory::open(host.registry_database()).expect("the grant store");
    let ActionClaim::Claimed { hold } = store
        .claim_action(&old_actor, action, &digest, now)
        .expect("claimed")
    else {
        panic!("a first claim of the action");
    };
    store
        .retain_result(&hold, b"the answer the ended record was given", now)
        .expect("retained");
    drop(hold);
    worker.seed_undispatched_intents(&old_actor, 1);
    assert!(
        worker_receipt(worker, &old_actor, action).is_some(),
        "the worker holds a receipt for the old actor's action"
    );

    let (second, _) = replaced_after_a_revocation(&host, &phone, &owner, &first, rights()).await;
    let new_actor = kr_transport::listener::device_principal(&second.device_id);

    // The old identifier still finds the host's answer, the bytes it was given.
    assert!(
        matches!(
            store
                .recorded_action(&old_actor, action, &digest)
                .expect("readable"),
            Some(ActionRecord::Answered { ref result, .. })
                if result == b"the answer the ended record was given"
        ),
        "a retry under the old identifier is given the kept answer"
    );
    // The old identifier still finds the worker's receipt.
    assert_eq!(
        worker_receipt(worker, &old_actor, action).map(|receipt| receipt.actor_id),
        Some(old_actor.clone()),
        "the worker's receipt is still the old actor's"
    );
    // The new identifier finds nothing in either store.
    assert_eq!(
        store
            .recorded_action(&new_actor, action, &digest)
            .expect("readable"),
        None,
        "the host holds no answer for the new identifier"
    );
    assert_eq!(
        worker_receipt(worker, &new_actor, action),
        None,
        "the worker holds no receipt for the new identifier"
    );
    host.stop().await;
}

/// A grant of the host's own store: held by `recipient`, issued by `issuer`, under `parent`.
fn stored_grant(
    byte: u8,
    parent: Option<kr_protocol::ids::GrantId>,
    issuer: DeviceId,
    recipient: DeviceId,
) -> kr_controller::grants::GrantRecord {
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::scalars::{CanonicalSet, Nullable};
    kr_controller::grants::GrantRecord {
        grant: Grant {
            grant_id: kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(
                [byte; 16],
            )),
            parent_grant_id: Nullable(parent),
            issuer_device_id: issuer,
            recipient_device_id: recipient,
            authority_revision: kr_protocol::ids::AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::SessionView].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        session_id: Some(kr_protocol::ids::SessionId::new(
            kr_protocol::scalars::Uuid::from_bytes([0xa0; 16]),
        )),
        issued_at_ms: kr_ipc::now_ms().get(),
        activated_at_ms: Some(kr_ipc::now_ms().get()),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

/// KR-REQ-10.08: the grants of the ended record are withdrawn with it and none of them is the new
/// record's. The ended record holds a grant and a grant it delegated to a third device; the
/// revocation withdraws both; after the device pairs again the host's store of grants is as the
/// revocation left it, holds none for the new identifier, and the new record's own grant is
/// exactly the one the invitation proposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_grants_of_the_ended_record_are_withdrawn_and_the_new_record_holds_only_the_grant_it_was_proposed()
 {
    use kr_controller::grants::GrantDirectory;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let host_device = host.owner.clone().expect("the owner device").device_id;
    let third = DeviceId::new(kr_ipc::new_uuid());

    let store = GrantDirectory::open(host.registry_database()).expect("the grant store");
    let held = stored_grant(0x41, None, host_device, first.device_id);
    let delegated = stored_grant(0x42, Some(held.grant.grant_id), first.device_id, third);
    store.issue(&held, || Ok(())).expect("the grant");
    store.issue(&delegated, || Ok(())).expect("its descendant");

    let proposed = rights();
    let (second, revoked) =
        replaced_after_a_revocation(&host, &phone, &owner, &first, proposed.clone()).await;

    // The revocation withdrew both grants, and the pairing wrote nothing to the store of grants.
    for grant_id in [held.grant.grant_id, delegated.grant.grant_id] {
        let record = store
            .record(grant_id)
            .expect("readable")
            .expect("the grant is kept");
        assert!(record.revoked_at_ms.is_some(), "{record:?}");
        assert!(
            revoked.revoked_grants.contains(&grant_id),
            "the revocation names the grant it withdrew"
        );
    }
    assert!(
        store
            .records_for_device(second.device_id)
            .expect("readable")
            .is_empty(),
        "no grant of the store is the new record's"
    );
    assert_eq!(
        store.records().expect("readable").len(),
        2,
        "the store holds the two grants of the ended record and nothing else"
    );
    assert!(
        store
            .records()
            .expect("readable")
            .iter()
            .all(|record| record.grant.grant_id != second.grant.grant_id),
        "the new record's grant is not in the store of grants"
    );
    // The new record's grant is the one proposed, held by the new identifier and by nothing under
    // the old one.
    let given = &second.grant;
    assert_eq!(given.recipient_device_id, second.device_id);
    assert_ne!(given.grant_id, first.grant.grant_id);
    assert_eq!(given.parent_grant_id, proposed.parent_grant_id);
    assert_eq!(given.environment_selector, proposed.environment_selector);
    assert_eq!(given.session_selector, proposed.session_selector);
    assert_eq!(given.actions, proposed.actions);
    // The proposal names no first moment of history, so the commit fixes it at the moment the
    // new record was made: never the ended record's.
    assert_eq!(
        given.history.include_live_screen,
        proposed.history.include_live_screen
    );
    assert_eq!(
        given.history.named_questions,
        proposed.history.named_questions
    );
    assert_eq!(
        given.history.named_approvals,
        proposed.history.named_approvals
    );
    assert!(proposed.history.lower_bound_ms.0.is_none());
    assert!(
        given.history.lower_bound_ms.0.map(|moment| moment.get())
            >= first
                .grant
                .history
                .lower_bound_ms
                .0
                .map(|moment| moment.get()),
        "the new record's history starts at its own moment"
    );
    assert_eq!(
        given.history.lower_bound_ms.0.map(|moment| moment.get()),
        Some(second.paired_at_ms.get()),
        "and that moment is the one the new record was made at"
    );
    assert_eq!(given.expiry, proposed.expiry);
    assert_eq!(given.organisation, proposed.organisation);
    host.stop().await;
}

/// KR-REQ-10.08: the voice delegations the ended record spent and the session invitations it
/// issued stay under its identifier. After the device pairs again the old identifier still holds
/// its spent delegation and its invitation, as the revocation left them, and the new identifier
/// holds neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_voice_delegations_and_invitations_of_the_ended_record_stay_under_its_identifier() {
    use kr_controller::grants::GrantDirectory;
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let host_device = host.owner.clone().expect("the owner device").device_id;
    let third = DeviceId::new(kr_ipc::new_uuid());
    let now = kr_ipc::now_ms().get();

    let store = GrantDirectory::open(host.registry_database()).expect("the grant store");
    // The ended record spent a voice delegation.
    assert!(
        store
            .spend_delegation(
                first.device_id,
                "the delegation",
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                now,
                None,
            )
            .expect("spent"),
        "a first spend"
    );
    // And it issued a session invitation to a third device, under the grant it holds.
    let held = stored_grant(0x51, None, host_device, first.device_id);
    store.issue(&held, || Ok(())).expect("the grant");
    let mut proposal = stored_grant(0x52, Some(held.grant.grant_id), first.device_id, third);
    proposal.activated_at_ms = None;
    let invitation_id = InvitationId::new(kr_ipc::new_uuid());
    let preview = kr_protocol::sharing::InvitationPreview {
        invitation_id,
        session_id: proposal.session_id.expect("a session"),
        environment_id: host.environment_id,
        role: kr_protocol::sharing::SessionRole::Viewer,
        actions: proposal.grant.actions.clone(),
        history: proposal.grant.history.clone(),
        expires_at_ms: TimestampMs::new(now + 60 * 60 * 1000),
        live_screen: Nullable::null(),
        named_questions: Vec::new(),
        named_approvals: Vec::new(),
        notices: CanonicalSet::new(),
        historical_attachment_keys: false,
        single_use: true,
    };
    store
        .issue_shared(&proposal, &preview, first.device_id, now, || Ok(()))
        .expect("the invitation");
    let old_delegations = rows_naming(&host, "voice_delegations", "device_id", first.device_id);
    assert_eq!(old_delegations.len(), 1);
    assert_eq!(
        rows_naming(
            &host,
            "session_invitations",
            "issuer_device_id",
            first.device_id
        )
        .len(),
        1
    );

    let (second, _) = replaced_after_a_revocation(&host, &phone, &owner, &first, rights()).await;

    // The old identifier holds its delegation as it was, and its invitation, which the
    // revocation withdrew with the grant it was issued under.
    assert_eq!(
        rows_naming(&host, "voice_delegations", "device_id", first.device_id),
        old_delegations,
        "the old identifier's spent delegation is as it was"
    );
    assert_eq!(
        rows_naming(
            &host,
            "session_invitations",
            "issuer_device_id",
            first.device_id
        )
        .len(),
        1,
        "the old identifier's invitation is kept"
    );
    // The new identifier holds none of it, as a delegation or as an invitation's issuer or
    // recipient.
    assert!(
        rows_naming(&host, "voice_delegations", "device_id", second.device_id).is_empty(),
        "the new identifier has spent no delegation"
    );
    for column in ["issuer_device_id", "recipient_device_id"] {
        assert!(
            rows_naming(&host, "session_invitations", column, second.device_id).is_empty(),
            "the new identifier is not the invitation's {column}"
        );
    }
    assert!(
        store
            .spend_delegation(
                second.device_id,
                "the delegation",
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                now,
                None,
            )
            .expect("spent"),
        "the same delegation under the new identifier is a first spend"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the deadline of a grant is the record's own. The ended record's grant has a
/// deadline once its device connected. Right after the device pairs again, and before the new
/// record connects, the host holds no deadline for the new identifier and the old one is as it
/// was; once the new record connects, its grant has a deadline of its own and the old one is still
/// as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_deadline_of_the_ended_records_grant_is_not_the_new_records_and_the_new_record_gets_its_own()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let directory = host.network().devices();
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");

    // Connecting anchors the grant in this boot, and its deadline is written down.
    let session = within("the connection", BOUND, connect(&host, &phone, &first)).await;
    {
        let (directory, boot) = (std::sync::Arc::clone(directory), boot.clone());
        let device_id = first.device_id;
        until("the old deadline being on record", move || {
            directory
                .grant_deadline_in(device_id, &boot)
                .is_ok_and(|deadline| deadline.is_some())
        })
        .await;
    }
    session.close();
    let old_deadline = directory
        .grant_deadline_in(first.device_id, &boot)
        .expect("readable")
        .expect("the ended record's deadline");

    let (second, _) = replaced_after_a_revocation(&host, &phone, &owner, &first, rights()).await;
    assert_eq!(
        directory
            .grant_deadline_in(second.device_id, &boot)
            .expect("readable"),
        None,
        "right after the commit the new identifier has no deadline"
    );
    assert_eq!(
        directory
            .grant_deadline_in(first.device_id, &boot)
            .expect("readable"),
        Some(old_deadline),
        "the old deadline is as it was"
    );

    let session = within("the connection", BOUND, connect(&host, &phone, &second)).await;
    {
        let (directory, boot) = (std::sync::Arc::clone(directory), boot.clone());
        let device_id = second.device_id;
        until("the new deadline being on record", move || {
            directory
                .grant_deadline_in(device_id, &boot)
                .is_ok_and(|deadline| deadline.is_some())
        })
        .await;
    }
    session.close();
    assert_eq!(
        directory
            .grant_deadline_in(first.device_id, &boot)
            .expect("readable"),
        Some(old_deadline),
        "the old deadline is still as it was"
    );
    host.stop().await;
}

/// KR-REQ-10.08: a request of the new record that names the old identifier is decided on the old
/// record alone and never reaches the new one. The device holds a share of a session under its new
/// record and asks the host to share it with the old identifier, whose record was revoked or ran
/// out. The host refuses: the old record decides, and it no longer stands. No grant is made for the
/// old identifier, the old record is as it was, the new record's row and its share are as they
/// were, and the new connection is served afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_share_naming_the_old_identifier_is_decided_on_the_old_record_alone() {
    use kr_protocol::grant::SessionSelector;
    use kr_protocol::scalars::{DurationMs, TimestampMs};
    use kr_protocol::sharing::{AuthorityNotice, GrantCreateParams, RoleSelection, SessionRole};

    let reaching_no_session = || {
        let mut grant = rights();
        grant.session_selector = SessionSelector::None;
        grant
    };
    for ended in ["revoked", "ran out"] {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let phone = Device::create().await;
        let session_id = net_support::an_open_session(&host).0;
        let first = pair_with(&host, &phone, &owner, reaching_no_session()).await;
        if ended == "revoked" {
            let barrier = within(
                "the revocation",
                BOUND,
                host.network().revoke_device(first.device_id),
            )
            .await
            .expect("the device is revoked");
            assert!(barrier.holds(), "{barrier:?}");
        } else {
            host.network()
                .devices()
                .record_expiry(first.device_id, TimestampMs::new(kr_ipc::now_ms().get()))
                .expect("the end of the grant is recorded");
        }
        let second = within(
            "the second pairing",
            BOUND,
            pair_with(&host, &phone, &owner, reaching_no_session()),
        )
        .await;
        let (above, raw) = within(
            "the share and the connection",
            BOUND,
            net_support::owned_by(&host, session_id, &phone, &second),
        )
        .await;
        let old_before = row_of(&host, first.device_id);
        let new_before = row_of(&host, second.device_id);
        let store = host.controller().sharing().grants();
        let grants_before = store.records().expect("readable").len();

        let selection = RoleSelection::plain(SessionRole::Viewer);
        let params = GrantCreateParams {
            session_id,
            recipient_device_id: first.device_id,
            parent_grant_id: kr_protocol::scalars::Nullable::some(above.grant.grant_id),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: kr_protocol::scalars::Nullable::some(DurationMs::new(600_000)),
            owner_confirmation: kr_protocol::scalars::Nullable::null(),
        };
        let answer = within(
            "the answer",
            BOUND,
            raw.try_mutate(
                Method::GrantCreate,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_session(&host, session_id),
                &params,
            ),
        )
        .await;
        assert!(
            matches!(answer, Some(Err(_))),
            "{ended}: a share to the identifier of an ended record is refused: {answer:?}"
        );
        assert_eq!(
            store.records().expect("readable").len(),
            grants_before,
            "{ended}: no grant was made"
        );
        assert!(
            store
                .records_for_device(first.device_id)
                .expect("readable")
                .is_empty(),
            "{ended}: the old identifier holds no grant"
        );
        assert_eq!(
            row_of(&host, first.device_id),
            old_before,
            "{ended}: the old record is as it was"
        );
        assert_eq!(
            row_of(&host, second.device_id),
            new_before,
            "{ended}: the new record is as it was"
        );
        assert!(
            net_support::holds(&host, above.grant.grant_id),
            "{ended}: the new record's own share stands"
        );
        assert!(
            within("the read", BOUND, raw.try_read(Method::HostInfo, &()))
                .await
                .is_some_and(|read| read.is_ok()),
            "{ended}: the new connection is served after the request"
        );
        raw.close();
        host.stop().await;
    }
}

/// KR-REQ-10.08: while the host holds a published debt whose barrier has not started, the
/// replacement and any other owner mutation are refused alike, with the words the host says for a
/// fence it owes, and the replacement is not added. The invitation stays locked and unconsumed.
/// Once the debt is gone, a fresh confirmation of the same invitation commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_replacement_and_another_owner_mutation_are_refused_alike_while_a_debt_is_published() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let spare_device = Device::create().await;
    let spare = pair_with(&host, &spare_device, &owner, rights()).await;
    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the device is revoked");
    assert!(barrier.holds(), "{barrier:?}");

    // The device with the ended record is bound to a new invitation, and a debt is published
    // whose barrier has not started.
    let signer = Signer::OwnerDevice(&owner);
    let mut again = bind(&host, &phone, &owner).await;
    host.controller().hold_fence(true);
    let spent = count(
        &host,
        "SELECT COUNT(*) FROM owner_confirmations WHERE consumed_at_ms IS NOT NULL",
    );
    let events = count(&host, "SELECT COUNT(*) FROM pairing_events");

    let replacement = within(
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
    .expect_err("the replacement is refused while a debt is published");
    let mut client = host.client().await;
    let other = within(
        "the other mutation",
        BOUND,
        calls::mutate::<_, kr_protocol::sharing::RevocationResult>(
            host.environment_id,
            &mut client,
            Method::DeviceRevoke,
            &kr_protocol::sharing::DeviceRevokeParams {
                device_id: spare.device_id,
            },
        ),
    )
    .await
    .expect_err("another owner mutation is refused while a debt is published");
    assert_eq!(
        replacement.code,
        ErrorCode::PermissionDenied,
        "{replacement:?}"
    );
    assert!(
        replacement
            .message
            .contains("this host withdrew authority and the fence that withdrawal owes"),
        "{replacement:?}"
    );
    assert_eq!(other.code, replacement.code, "alike: {other:?}");
    assert_eq!(other.message, replacement.message, "alike");

    assert!(
        host.record_of(spare.device_id).is_paired(),
        "the other mutation changed nothing"
    );
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

    // The debt is gone: a fresh confirmation of the same invitation commits.
    host.controller().hold_fence(false);
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
    .expect("a fresh confirmation commits once nothing is owed");
    assert_ne!(confirmed.device_id, first.device_id);
    assert_eq!(
        host.network()
            .devices()
            .record_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .map(|record| record.device_id),
        Some(confirmed.device_id)
    );
    host.stop().await;
}

/// The owner's view of one invitation, read within [`BOUND`].
async fn owner_view(
    client: &mut kr_ipc::client::LocalClient,
    invitation_id: InvitationId,
) -> Result<kr_protocol::preauth::PairStatusResult, kr_protocol::error::ProtocolError> {
    within(
        "the owner's view",
        BOUND,
        calls::owner_status(client, invitation_id),
    )
    .await
}

/// The code of the host's refusal of a pairing request, by its wire name.
fn refusal_code(error: &kr_transport::TransportError) -> &'static str {
    let kr_transport::TransportError::Refused(error) = error else {
        panic!("the host answered with a refusal, not {error:?}");
    };
    error.code.as_str()
}

/// KR-REQ-10.08: a device whose record the host still lists, and which forgot the host, reaches the
/// host's answer instead of failing at the transport. The host refuses it at the redemption, after
/// the proofs and before the owner is shown a candidate, with a code of its own; the invitation
/// ends for that reason and the owner is shown the host's own record of the device, under the name
/// the host recorded and not the one the candidate presented. The record is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_the_host_still_lists_is_refused_at_the_redemption_and_the_owner_is_shown_its_record()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let listed = row_of(&host, first.device_id);
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");

    // The candidate presents another name than the one the host recorded.
    let mut candidate = phone.candidate();
    candidate.declared.device_name =
        DeviceName::new("A name the host never recorded").expect("a name");
    let redeemed = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&candidate, &invited),
    )
    .await;
    let error = redeemed.outcome.as_ref().expect_err("the host refuses");
    assert_eq!(refusal_code(error), "PAIRING_ENDPOINT_PAIRED");

    let status = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the invitation ended for the device that is listed"
    );
    let view = status.owner.0.expect("an owner view");
    assert!(
        view.candidate.0.is_none(),
        "the owner is shown no candidate: the refusal precedes the owner's prompt"
    );
    let existing = view
        .existing
        .as_ref()
        .expect("the view names the record the host lists");
    assert_eq!(
        existing.device_name.as_str(),
        first_name(&host, first.device_id),
        "the name is the host's record's, not the candidate's"
    );
    assert_eq!(existing.paired_at_ms, first.paired_at_ms);
    assert_eq!(
        row_of(&host, first.device_id),
        listed,
        "the listed record is as it was"
    );
    assert_eq!(
        host.network()
            .devices()
            .rows_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .len(),
        1,
        "no row was added"
    );
    host.stop().await;
}

/// The name the host recorded for a device.
fn first_name(host: &Host, device_id: DeviceId) -> String {
    host.record_of(device_id).device_name.as_str().to_owned()
}

/// Makes the host's record of `device_id` unreadable, as a registry that fails a read does, and
/// returns what the record held so that [`readable_again`] puts it back.
fn unreadable(host: &Host, device_id: DeviceId) -> String {
    let connection = registry(host);
    let platform: String = connection
        .query_row(
            "SELECT platform FROM network_devices WHERE device_id = ?1",
            [device_id.get().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the record's platform");
    let changed = connection
        .execute(
            "UPDATE network_devices SET platform = 'not a platform' WHERE device_id = ?1",
            [device_id.get().as_bytes().as_slice()],
        )
        .expect("the record is made unreadable");
    assert_eq!(changed, 1, "one record was made unreadable");
    platform
}

/// Puts back what [`unreadable`] returned.
fn readable_again(host: &Host, device_id: DeviceId, platform: &str) {
    let changed = registry(host)
        .execute(
            "UPDATE network_devices SET platform = ?2 WHERE device_id = ?1",
            rusqlite::params![device_id.get().as_bytes().as_slice(), platform],
        )
        .expect("the record is made readable");
    assert_eq!(changed, 1, "one record was made readable");
}

/// KR-REQ-10.08: the host's refusal of a device it lists is the same whether the request is
/// the first or a repeat, on the same connection or on a new one, so a device whose first answer
/// was lost reads the same code. The invitation's status says the same thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeated_redemption_of_a_listed_device_gets_the_first_refusals_code() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let mut redeemed = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    let first = refusal_code(redeemed.outcome.as_ref().expect_err("the host refuses"));
    assert_eq!(first, "PAIRING_ENDPOINT_PAIRED");

    // The same request again on the same connection.
    let again: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the repeat on the same connection",
        BOUND,
        redeemed
            .candidate
            .call(Method::PairRedeem, &redeemed.request),
    )
    .await;
    assert_eq!(refusal_code(&again.expect_err("refused again")), first);

    // And on a new connection of the same device.
    let fresh = within("a new connection", BOUND, async {
        let candidate = phone.candidate();
        let connection = calls::dial_until_connected(
            candidate.endpoint,
            calls::host_addr(&calls::direct_payload(&invited)),
        )
        .await;
        let surface =
            kr_transport::handshake::connect_unpaired(&connection, candidate.identity).await;
        (connection, surface)
    })
    .await;
    let (_connection, fresh) = fresh;
    let mut fresh = fresh.expect("an unpaired connection");
    let repeated: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the repeat on a new connection",
        BOUND,
        fresh.call(Method::PairRedeem, &redeemed.request),
    )
    .await;
    assert_eq!(refusal_code(&repeated.expect_err("refused again")), first);

    // The candidate reads the same thing from the invitation's status.
    let status: kr_protocol::preauth::PairStatusResult = within(
        "the status",
        BOUND,
        fresh.call(
            Method::PairStatus,
            &kr_protocol::preauth::PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        ),
    )
    .await
    .expect("the host answers the candidate");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        }
    );
    host.stop().await;
}

/// KR-REQ-10.08: the host reads its list of devices before the redemption locks the invitation. A
/// read that fails there answers the candidate with the failure and changes nothing: no lock, no
/// candidate, no prompt for the owner. The same request, made again, completes the check and is
/// refused for the listed device.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_failed_read_of_the_list_at_the_redemption_locks_nothing_and_the_repeat_completes_the_check()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let listed = row_of(&host, first.device_id);
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");

    let platform = unreadable(&host, first.device_id);
    let mut redeemed = within(
        "the redemption while the list cannot be read",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    readable_again(&host, first.device_id, &platform);
    assert_eq!(
        refusal_code(redeemed.outcome.as_ref().expect_err("the read failed")),
        "STORAGE_UNAVAILABLE",
        "the candidate is told that the host could not read its list"
    );

    let status = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert!(
        matches!(status.status, PairStatus::Open { .. }),
        "nothing is locked after the failed read: {:?}",
        status.status
    );
    let view = status.owner.0.expect("an owner view");
    assert!(
        view.candidate.0.is_none(),
        "the owner is shown no candidate after the failed read"
    );

    let again: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the same request again",
        BOUND,
        redeemed
            .candidate
            .call(Method::PairRedeem, &redeemed.request),
    )
    .await;
    assert_eq!(
        refusal_code(&again.expect_err("the repeat completes the check and is refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    let ended = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        ended.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the invitation ended for the device that is listed"
    );
    assert_eq!(
        row_of(&host, first.device_id),
        listed,
        "the listed record is as it was"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the refusal that says the host lists a device is for that device alone. Another
/// device, one the host does not list, that presents the direct invitation after it ended for the
/// listed one is given the general rejection at the challenge and at a proof, like every other
/// ending, and is not told that the host lists it. The listed device still reads its own code.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn another_device_presenting_the_invitation_that_ended_for_a_listed_device_gets_the_general_rejection()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let mut listed = within(
        "the listed device's redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    assert_eq!(
        refusal_code(listed.outcome.as_ref().expect_err("the host refuses")),
        "PAIRING_ENDPOINT_PAIRED"
    );

    // A device the host does not list meets the ended invitation.
    let other = Device::create().await;
    let (_connection, surface) =
        within("an unpaired connection of the other device", BOUND, async {
            let candidate = other.candidate();
            let connection = calls::dial_until_connected(
                candidate.endpoint,
                calls::host_addr(&calls::direct_payload(&invited)),
            )
            .await;
            let surface =
                kr_transport::handshake::connect_unpaired(&connection, candidate.identity).await;
            (connection, surface)
        })
        .await;
    let mut surface = surface.expect("an unpaired connection");
    let challenged: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the other device's challenge",
        BOUND,
        surface.call(
            Method::PairRedeem,
            &kr_protocol::preauth::PairRedeemParams::Challenge {
                invitation_id: invited.invitation_id,
            },
        ),
    )
    .await;
    let challenge_refusal = challenged.expect_err("the ended invitation is refused");
    assert_eq!(
        refusal_code(&challenge_refusal),
        "PAIRING_REJECTED",
        "a device that is not listed is not told that the host lists it"
    );
    let kr_transport::TransportError::Refused(told) = &challenge_refusal else {
        panic!("the host answered with a refusal, not {challenge_refusal:?}");
    };
    assert_eq!(
        told.message, "the invitation is no longer open",
        "the message holds no reason: a device that is not listed is not told why the invitation ended"
    );
    let proved: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the other device's proof",
        BOUND,
        surface.call(Method::PairRedeem, &listed.request),
    )
    .await;
    let proof_refusal = proved.expect_err("the ended invitation is refused");
    assert_eq!(
        refusal_code(&proof_refusal),
        "PAIRING_REJECTED",
        "the same at a proof"
    );
    let kr_transport::TransportError::Refused(told) = &proof_refusal else {
        panic!("the host answered with a refusal, not {proof_refusal:?}");
    };
    assert_eq!(
        told.message, "the invitation is no longer open",
        "the same message at a proof"
    );

    // The listed device reads its own code, as before.
    let again: Result<kr_protocol::preauth::PairRedeemResult, _> = within(
        "the listed device's repeat",
        BOUND,
        listed.candidate.call(Method::PairRedeem, &listed.request),
    )
    .await;
    assert_eq!(
        refusal_code(&again.expect_err("refused again")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    host.stop().await;
}

/// The owner's view of the invitation that the host refused a listed device on, with the member that
/// names the record the host holds.
async fn existing_after_the_refusal(
    client: &mut kr_ipc::client::LocalClient,
    invited: &PairInviteResult,
) -> Option<kr_protocol::invitation::ExistingPairing> {
    let status = owner_view(client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the invitation ended for the device that is listed"
    );
    status.owner.0.expect("an owner view").existing
}

/// KR-REQ-23.19, KR-REQ-10.39: a device that paired with the host and kept its record reaches the
/// pairing surface on a fresh connection, by offering another device identifier than its record's,
/// and reads the status of the invitation that committed its pairing. The host answers from its own
/// record of the commit, to the endpoint that the commit named.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_fresh_unpaired_connection_reads_the_status_of_a_real_commit() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let committed = first
        .committed_invitation_id
        .expect("the record names the invitation that committed it");
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("a later invitation, whose payload addresses the host");

    let (_connection, surface) = within("an unpaired connection", BOUND, async {
        let candidate = phone.candidate();
        let connection = calls::dial_until_connected(
            candidate.endpoint,
            calls::host_addr(&calls::direct_payload(&invited)),
        )
        .await;
        let surface =
            kr_transport::handshake::connect_unpaired(&connection, candidate.identity).await;
        (connection, surface)
    })
    .await;
    let mut surface = surface.expect("the listed endpoint reaches the pairing surface");
    let status: Result<kr_protocol::preauth::PairStatusResult, _> = within(
        "the status read",
        BOUND,
        surface.call(
            Method::PairStatus,
            &kr_protocol::preauth::PairStatusParams {
                invitation_id: committed,
            },
        ),
    )
    .await;
    match status
        .expect("the host answers the status of the invitation that committed it")
        .status
    {
        PairStatus::Committed { device_id, .. } => assert_eq!(
            device_id, first.device_id,
            "the commit names the record the host holds"
        ),
        other => panic!("the invitation that committed the pairing reads as {other:?}"),
    }
    host.stop().await;
}

/// KR-REQ-10.08: the owner's view names the record that the refusal named only while that record is
/// in force. While it is, the view gives its name and date; after the owner removed it, the invitation
/// still reads as ended for a listed device and the view gives no record, so it names no pairing that
/// is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owners_view_gives_no_record_after_the_owner_removed_the_record_it_named() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let refused = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    assert_eq!(
        refusal_code(refused.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    let standing = existing_after_the_refusal(&mut client, &invited)
        .await
        .expect("the record is in force: the view names it");
    assert_eq!(
        standing.device_name.as_str(),
        first_name(&host, first.device_id)
    );

    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the owner removes the device");
    assert!(barrier.holds(), "{barrier:?}");
    assert!(
        existing_after_the_refusal(&mut client, &invited)
            .await
            .is_none(),
        "the record was removed: the view names no pairing"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the same for a record whose grant ran out after the refusal: the end is on the record
/// (the mark the lifetimes write), and the view gives no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owners_view_gives_no_record_after_the_record_it_named_ran_out() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let refused = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    assert_eq!(
        refusal_code(refused.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    assert!(
        existing_after_the_refusal(&mut client, &invited)
            .await
            .is_some(),
        "the record is in force: the view names it"
    );

    let changed = registry(&host)
        .execute(
            "UPDATE network_devices SET expired_at_ms = paired_at_ms + 1 WHERE device_id = ?1",
            [first.device_id.get().as_bytes().as_slice()],
        )
        .expect("the end of the grant is recorded");
    assert_eq!(changed, 1, "one record ended");
    assert!(
        existing_after_the_refusal(&mut client, &invited)
            .await
            .is_none(),
        "the record ran out: the view names no pairing"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the view names a record only while the host lists it, and the host records the end
/// of a grant that ran out before it answers. The clocks pass the grant of the record the view
/// named, with no connection of the device and no device list, so nothing but the view's own read
/// can write the end: the view then gives no record, and the end is on record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owners_view_gives_no_record_after_the_grant_it_named_ran_out_and_nothing_wrote_its_end()
 {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let refused = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    assert_eq!(
        refusal_code(refused.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    assert!(
        existing_after_the_refusal(&mut client, &invited)
            .await
            .is_some(),
        "the grant stands: the view names the record"
    );

    moved.past_the_grant();
    let path = host.registry_database();
    assert!(
        !expired(&path, first.device_id),
        "no end of the grant is on record before the view is read"
    );
    assert!(
        existing_after_the_refusal(&mut client, &invited)
            .await
            .is_none(),
        "the grant ran out: the view names no pairing"
    );
    assert!(
        expired(&path, first.device_id),
        "the view's read recorded the end of the grant"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the view of an invitation that did not end because the device is listed carries no
/// `existing` member, so a reader of the earlier shape reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_invitation_that_did_not_end_for_a_listed_device_has_no_existing_member() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let open = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let view = open.owner.0.expect("an owner view");
    assert!(view.existing.is_none(), "an open invitation");
    calls::cancel(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        false,
    )
    .await
    .expect("the owner withdraws it");
    let ended = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        ended.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::Cancelled
        }
    );
    let view = ended.owner.0.expect("an owner view");
    assert!(view.existing.is_none(), "a withdrawn invitation");
    host.stop().await;
}

use kr_ipc::client::LocalClient;
use kr_protocol::ids::{AttemptId, EnvironmentId};
use kr_protocol::invitation::{InviteEntry, RendezvousMessage};
use kr_protocol::pairing::{QrPayload, RendezvousOrigin};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::rendezvous::{ClientFrame, decode_message};
use kr_protocol::scalars::Nonce256;
use net_support::pairing::Candidate;
use net_support::room::CodeCandidate;

/// Issues a code invitation at the host's default origin, once the owner device has confirmed it.
async fn invite_code(
    environment: EnvironmentId,
    client: &mut LocalClient,
    owner: &DeviceKeys,
) -> PairInviteResult {
    let grant = rights();
    calls::confirm_subject(
        environment,
        client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Code,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
        &Signer::OwnerDevice(owner),
    )
    .await
    .expect("answered");
    calls::mutate(
        environment,
        client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Code {
                rendezvous_origin: Nullable::null(),
            },
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant,
        },
    )
    .await
    .expect("a code invitation")
}

/// The origin and the code that a code invitation's answer shows.
fn code_of(invited: &PairInviteResult) -> (RendezvousOrigin, String) {
    let InviteEntry::Code {
        rendezvous_origin,
        qr_text,
        ..
    } = &invited.entry
    else {
        panic!("a code invitation is offered as a code");
    };
    let QrPayload::Code(payload) = QrPayload::from_text(qr_text.as_str()).expect("a payload")
    else {
        panic!("a code invitation's QR is a code payload");
    };
    (rendezvous_origin.clone(), payload.code.as_str().to_owned())
}

/// A candidate that proved the code through the room and handed the host its bundle, and whose
/// `pair.finish` the case sends. The device holds nothing of the host.
async fn code_candidate<'a>(
    host: &Host,
    presented: Candidate<'a>,
    client: &mut LocalClient,
    owner: &DeviceKeys,
) -> (PairInviteResult, CodeCandidate<'a>) {
    let invited = invite_code(host.environment_id, client, owner).await;
    let (origin, code) = code_of(&invited);
    let mut candidate = within(
        "the room admitting the candidate",
        BOUND,
        CodeCandidate::start(&host.room, presented, &origin, &code),
    )
    .await
    .expect("admitted");
    within("the host's proof of the code", BOUND, candidate.confirm())
        .await
        .expect("the host proved the code");
    within("the bundle", BOUND, candidate.send_bundle())
        .await
        .expect("the host took the bundle");
    (invited, candidate)
}

/// KR-REQ-10.08: as for a direct invitation, a device the host still lists that pairs again
/// through a code reaches the host's answer and is refused at `pair.finish`, after the code and
/// the endpoint were proved and before the owner is shown a candidate. The invitation ends for that
/// reason, the owner is shown the host's own record of the device, and the record is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_the_host_still_lists_is_refused_at_the_code_finish_and_the_owner_is_shown_its_record()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let listed = row_of(&host, first.device_id);
    let mut client = host.client().await;
    // The candidate presents another name than the one the host recorded.
    let mut presented = phone.candidate();
    presented.declared.device_name =
        DeviceName::new("A name the host never recorded").expect("a name");
    let (invited, mut candidate) = code_candidate(&host, presented, &mut client, &owner).await;

    let finished = within("the finish", BOUND, candidate.try_finish()).await;
    assert!(
        finished.outcome.is_err(),
        "the host refuses the finish of a device it lists"
    );
    assert_eq!(
        refusal_code(finished.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );

    let status = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the invitation ended for the device that is listed"
    );
    let view = status.owner.0.expect("an owner view");
    assert!(
        view.candidate.0.is_none(),
        "the owner is shown no candidate: the refusal precedes the owner's prompt"
    );
    let existing = view
        .existing
        .as_ref()
        .expect("the view names the record the host lists");
    assert_eq!(
        existing.device_name.as_str(),
        first_name(&host, first.device_id),
        "the name is the host's record's, not the candidate's"
    );
    assert_eq!(existing.paired_at_ms, first.paired_at_ms);
    assert_eq!(
        row_of(&host, first.device_id),
        listed,
        "the listed record is as it was"
    );
    assert_eq!(
        host.network()
            .devices()
            .rows_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .len(),
        1,
        "no row was added"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the host's refusal of a device it lists through a code is the same whether the
/// finish is the first or a repeat, on the same connection or on a new one, as when the device never
/// read the first answer; the invitation's status says the same thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeated_finish_of_a_listed_device_gets_the_first_refusals_code() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let (invited, mut candidate) =
        code_candidate(&host, phone.candidate(), &mut client, &owner).await;

    let mut first = within("the finish", BOUND, candidate.try_finish()).await;
    assert!(first.outcome.is_err(), "the host refuses the finish");
    let first_code = refusal_code(first.outcome.as_ref().expect_err("refused"));
    assert_eq!(first_code, "PAIRING_ENDPOINT_PAIRED");

    // The same request again on the same connection.
    let same = within(
        "the repeat on the same connection",
        BOUND,
        candidate.finish_over(&mut first.session),
    )
    .await;
    assert!(same.is_err(), "the repeat is refused");
    assert_eq!(
        refusal_code(same.as_ref().expect_err("refused")),
        first_code
    );

    // And on a new connection of the same device.
    let mut fresh = within(
        "the repeat on a new connection",
        BOUND,
        candidate.try_finish(),
    )
    .await;
    assert!(
        fresh.outcome.is_err(),
        "the repeat on a new connection is refused"
    );
    assert_eq!(
        refusal_code(fresh.outcome.as_ref().expect_err("refused")),
        first_code
    );

    // The candidate reads the same thing from the invitation's status.
    let status: Result<PairStatusResult, _> = within(
        "the status",
        BOUND,
        fresh.session.call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        ),
    )
    .await;
    assert!(status.is_ok(), "the host answers the candidate's status");
    assert_eq!(
        status.expect("read above").status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        }
    );
    host.stop().await;
}

/// KR-REQ-10.08: the refusal that says the host lists a device is for that device alone. A room
/// admission that reaches the host after the invitation ended for a listed device, before the room
/// is closed, is refused with the general rejection like every other ending: the host cannot tell
/// who stands behind it, and it names no device.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_room_admission_after_the_invitation_ended_for_a_listed_device_gets_the_general_rejection()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let (invited, mut candidate) =
        code_candidate(&host, phone.candidate(), &mut client, &owner).await;
    let finished = within("the finish", BOUND, candidate.try_finish()).await;
    assert_eq!(
        refusal_code(finished.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED",
        "the listed device reads its own code"
    );

    let frames = host.network().pairing().room_step(
        invited.invitation_id,
        AttemptId::new(kr_ipc::new_uuid()),
        RendezvousMessage::Admit {
            client_nonce: Nonce256::from_bytes([7; 32]),
        },
    );
    let Some(ClientFrame::Relay { payload, .. }) = frames.first() else {
        panic!("a refusal is relayed first: {frames:?}");
    };
    let RendezvousMessage::Refused { code, .. } =
        decode_message(payload.as_slice()).expect("a rendezvous message")
    else {
        panic!("the admission is answered with a refusal");
    };
    assert_eq!(
        code,
        ErrorCode::PairingRejected,
        "an admission is not told that the host lists a device"
    );
    host.stop().await;
}

/// KR-REQ-10.08: as for a direct invitation, the host reads its list of devices before `pair.finish`
/// moves the attempt on. A read that fails there answers the candidate with the failure and changes
/// nothing: the invitation stays locked to the candidate's attempt that proved the code, no device
/// is bound and the owner is shown no candidate. The same finish, made again, completes the check
/// and is refused for the listed device.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_failed_read_of_the_list_at_the_code_finish_moves_nothing_and_the_repeat_completes_the_check()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let listed = row_of(&host, first.device_id);
    let mut client = host.client().await;
    let (invited, mut candidate) =
        code_candidate(&host, phone.candidate(), &mut client, &owner).await;

    let platform = unreadable(&host, first.device_id);
    let mut failed = within(
        "the finish while the list cannot be read",
        BOUND,
        candidate.try_finish(),
    )
    .await;
    readable_again(&host, first.device_id, &platform);
    assert_eq!(
        refusal_code(failed.outcome.as_ref().expect_err("the read failed")),
        "STORAGE_UNAVAILABLE",
        "the candidate is told that the host could not read its list"
    );

    let status = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert!(
        matches!(status.status, PairStatus::Locked { .. }),
        "the attempt has not moved on: {:?}",
        status.status
    );
    let view = status.owner.0.expect("an owner view");
    assert!(
        view.candidate.0.is_none(),
        "the owner is shown no candidate and no approval is asked for after the failed read"
    );

    let again = within(
        "the same finish again",
        BOUND,
        candidate.finish_over(&mut failed.session),
    )
    .await;
    assert_eq!(
        refusal_code(&again.expect_err("the repeat completes the check and is refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );
    let ended = owner_view(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        ended.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the invitation ended for the device that is listed"
    );
    assert_eq!(
        row_of(&host, first.device_id),
        listed,
        "the listed record is as it was"
    );
    host.stop().await;
}

/// KR-REQ-10.08: a device the host lists is told so; the person removes the device at the host with
/// an owner device that reaches it, and the next invitation then gives the device a record under a
/// new identifier while the revoked one stays as it was and stays refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn after_the_owner_removes_a_listed_device_a_new_invitation_pairs_it_under_a_new_identifier()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let refused = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    assert!(
        refused.outcome.is_err(),
        "the host refuses a device it lists"
    );
    assert_eq!(
        refusal_code(refused.outcome.as_ref().expect_err("refused")),
        "PAIRING_ENDPOINT_PAIRED"
    );

    let barrier = within(
        "the revocation",
        BOUND,
        host.network().revoke_device(first.device_id),
    )
    .await
    .expect("the owner removes the device");
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

/// KR-REQ-10.08: a record whose grant ran out, and whose end no one has read or recorded, is found
/// at the binding and recorded there, and the device pairs again under a new identifier. Nothing
/// connected since the grant ran out, so the end is not on record when the second pairing starts.
///
/// This is a flow control: it shows the whole flow with an end that no one had recorded, and the
/// end could also be recorded at the commit. That it is the binding that records it is shown by the
/// store-level case `the_binding_records_a_grant_that_ran_out_unread` in `pairing_store.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_grant_that_ran_out_unread_is_recorded_at_the_binding_and_the_device_pairs_again() {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let phone = Device::create().await;
    let first = pair_with(&host, &phone, &owner, rights()).await;
    moved.past_the_grant();
    let path = host.registry_database();
    assert!(
        !expired(&path, first.device_id),
        "the end of the grant is not on record before the second pairing"
    );
    let unread = row_of(&host, first.device_id);

    let second = within(
        "the second pairing",
        BOUND,
        pair_with(&host, &phone, &owner, grant_past_the_moved_clocks()),
    )
    .await;
    assert!(
        expired(&path, first.device_id),
        "the end of the grant is on record"
    );
    assert_ne!(row_of(&host, first.device_id), unread);
    assert_eq!(
        host.network()
            .devices()
            .record_for_endpoint(&endpoint_of(&phone))
            .expect("readable")
            .map(|record| record.device_id),
        Some(second.device_id),
        "the endpoint identity reads the record that stands"
    );
    host.stop().await;
}

/// Makes the host list the endpoint identity of `phone`, as it is when a device is listed between
/// its redemption and the owner's approval: the record the host holds for `holder` takes the
/// identity, the way a record of another pairing would.
fn list_the_endpoint_of(host: &Host, phone: &Device, holder: DeviceId) {
    let changed = registry(host)
        .execute(
            "UPDATE network_devices SET endpoint_id = ?1 WHERE device_id = ?2",
            rusqlite::params![
                endpoint_of(phone).as_bytes().as_slice(),
                holder.get().as_bytes().as_slice()
            ],
        )
        .expect("the host lists the endpoint identity");
    assert_eq!(changed, 1, "one record took the identity");
}

/// The approval of the candidate bound to `invitation_id`, as the owner's view shows it.
async fn approval_of(client: &mut LocalClient, invitation_id: InvitationId) -> PairingApproval {
    owner_view(client, invitation_id)
        .await
        .expect("the owner's view")
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("a bound candidate the owner can approve")
}

/// The owner's answer to the confirmation of the candidate bound to `invitation_id`, given and not
/// yet spent.
async fn answer_the_confirmation(
    host: &Host,
    client: &mut LocalClient,
    owner: &DeviceKeys,
    invitation_id: InvitationId,
) {
    within(
        "the owner's answer to the confirmation",
        BOUND,
        calls::confirm_subject(
            host.environment_id,
            client,
            ConfirmationSubject::ConfirmDevice { invitation_id },
            &Signer::OwnerDevice(owner),
        ),
    )
    .await
    .expect("the owner's answer is given");
}

/// One `pair.confirm` of `invitation_id` under `action`.
async fn confirm_under(
    host: &Host,
    client: &mut LocalClient,
    invitation_id: InvitationId,
    approval: PairingApproval,
    action: ActionId,
) -> Result<PairConfirmResult, kr_protocol::error::ProtocolError> {
    within(
        "pair.confirm",
        BOUND,
        calls::mutate_as(
            host.environment_id,
            client,
            action,
            Method::PairConfirm,
            &PairConfirmParams {
                invitation_id,
                approval,
            },
        ),
    )
    .await
}

/// How many answers of the owner's are given and not yet spent.
async fn unspent_answers(client: &mut LocalClient) -> usize {
    within(
        "the owner's pending confirmations",
        BOUND,
        calls::pending(client),
    )
    .await
    .expect("the pending confirmations")
    .pending
    .iter()
    .filter(|pending| pending.answered)
    .count()
}

/// KR-REQ-10.08: the owner's repeat of `pair.confirm` after the commit refused a device that became
/// listed is told what became of the invitation, and the answer does not depend on whether the host
/// issued another invitation since: the invitation sits in the host's open slot, ended, and is
/// answered as one that has left it. The same action and a new one get it, and no answer of the
/// owner's is spent by the repeat.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_the_owners_confirmation_after_the_commit_refused_a_listed_device_is_told_the_ending_in_direct_mode()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let other = Device::create().await;
    let holder = pair_with(&host, &other, &owner, rights()).await;
    let phone = Device::create().await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let redeemed = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    redeemed
        .outcome
        .as_ref()
        .expect("the host locks a device it does not list");
    let approval = approval_of(&mut client, invited.invitation_id).await;
    list_the_endpoint_of(&host, &phone, holder.device_id);

    answer_the_confirmation(&host, &mut client, &owner, invited.invitation_id).await;
    let first = ActionId::new(kr_ipc::new_uuid());
    let refused = confirm_under(&host, &mut client, invited.invitation_id, approval, first)
        .await
        .expect_err("the commit is refused for the device the host lists");
    assert_eq!(refused.code.as_str(), "PAIRING_ENDPOINT_PAIRED");

    let same = confirm_under(&host, &mut client, invited.invitation_id, approval, first)
        .await
        .expect_err("the invitation ended");
    assert_eq!(
        same.code.as_str(),
        "PAIRING_REJECTED",
        "the same action is told that the invitation is no longer open"
    );
    assert!(
        same.message.contains("no longer open"),
        "the same action is told how it ended: {}",
        same.message
    );
    let new = ActionId::new(kr_ipc::new_uuid());
    let another = confirm_under(&host, &mut client, invited.invitation_id, approval, new)
        .await
        .expect_err("the invitation ended");
    assert_eq!(
        another.code.as_str(),
        "PAIRING_REJECTED",
        "a new action is told the same"
    );
    assert!(
        another.message.contains("no longer open"),
        "a new action is told how it ended: {}",
        another.message
    );

    answer_the_confirmation(&host, &mut client, &owner, invited.invitation_id).await;
    assert_eq!(
        unspent_answers(&mut client).await,
        1,
        "the owner's answer stands before the repeat"
    );
    let again = confirm_under(
        &host,
        &mut client,
        invited.invitation_id,
        approval,
        ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect_err("the invitation ended");
    assert_eq!(again.code.as_str(), "PAIRING_REJECTED");
    assert_eq!(
        unspent_answers(&mut client).await,
        1,
        "the repeat spent no answer of the owner's"
    );
    host.stop().await;
}

/// KR-REQ-10.08: the same in code mode, where the repeat met a wrong phase before: the invitation
/// ended at the commit, and the same action and a new one are told that. No candidate is bound
/// there any more, so the owner can be given no answer for the repeat to spend.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_the_owners_confirmation_after_the_commit_refused_a_listed_device_is_told_the_ending_in_code_mode()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let other = Device::create().await;
    let holder = pair_with(&host, &other, &owner, rights()).await;
    let phone = Device::create().await;
    let mut client = host.client().await;
    let (invited, mut candidate) =
        code_candidate(&host, phone.candidate(), &mut client, &owner).await;
    let finished = within("the finish", BOUND, candidate.try_finish()).await;
    finished
        .outcome
        .as_ref()
        .expect("the host binds a device it does not list");
    let approval = approval_of(&mut client, invited.invitation_id).await;
    list_the_endpoint_of(&host, &phone, holder.device_id);

    answer_the_confirmation(&host, &mut client, &owner, invited.invitation_id).await;
    let first = ActionId::new(kr_ipc::new_uuid());
    let refused = confirm_under(&host, &mut client, invited.invitation_id, approval, first)
        .await
        .expect_err("the commit is refused for the device the host lists");
    assert_eq!(refused.code.as_str(), "PAIRING_ENDPOINT_PAIRED");

    let same = confirm_under(&host, &mut client, invited.invitation_id, approval, first)
        .await
        .expect_err("the invitation ended");
    assert_eq!(
        same.code.as_str(),
        "PAIRING_REJECTED",
        "the same action is told that the invitation is no longer open"
    );
    assert!(
        same.message.contains("no longer open"),
        "the same action is told how it ended: {}",
        same.message
    );
    let another = confirm_under(
        &host,
        &mut client,
        invited.invitation_id,
        approval,
        ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect_err("the invitation ended");
    assert_eq!(
        another.code.as_str(),
        "PAIRING_REJECTED",
        "a new action is told the same"
    );
    assert!(
        another.message.contains("no longer open"),
        "a new action is told how it ended: {}",
        another.message
    );

    host.stop().await;
}

/// KR-REQ-10.08: another ending that sits in the open slot is answered the same way: an owner that
/// denied the candidate and repeats `pair.confirm` is told that the invitation was denied, with the
/// same action and with a new one, and not that a confirmation is needed or that the phase is wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_the_owners_confirmation_after_the_owner_denied_the_candidate_is_told_it_was_denied()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let phone = Device::create().await;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &rights(),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("an invitation");
    let redeemed = within(
        "the redemption",
        BOUND,
        calls::try_redeem(&phone.candidate(), &invited),
    )
    .await;
    redeemed
        .outcome
        .as_ref()
        .expect("the host locks the candidate");
    let approval = approval_of(&mut client, invited.invitation_id).await;
    let denied = within(
        "the denial",
        BOUND,
        calls::cancel(
            host.environment_id,
            &mut client,
            invited.invitation_id,
            true,
        ),
    )
    .await
    .expect("the owner denies the candidate");
    assert_eq!(
        denied.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::Denied
        }
    );

    let first = ActionId::new(kr_ipc::new_uuid());
    let same = confirm_under(&host, &mut client, invited.invitation_id, approval, first)
        .await
        .expect_err("the invitation was denied");
    assert_eq!(
        same.code.as_str(),
        "PAIRING_REJECTED",
        "the owner is told that the invitation is no longer open"
    );
    assert!(
        same.message.contains("Denied"),
        "the owner is told that it was denied: {}",
        same.message
    );
    let another = confirm_under(
        &host,
        &mut client,
        invited.invitation_id,
        approval,
        ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect_err("the invitation was denied");
    assert_eq!(another.code.as_str(), "PAIRING_REJECTED");
    assert!(
        another.message.contains("Denied"),
        "a new action is told the same: {}",
        another.message
    );
    host.stop().await;
}
