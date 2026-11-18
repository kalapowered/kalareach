//! A device that forgot a host the host still lists, pairing with it again through the product's
//! pairing client.
//!
//! The candidate is kr-client's pairing module, the code a companion application calls, running
//! as a device with keys of its own; the daemon is the same network service and controller the
//! binary runs, on the loopback network. The client's own crate cannot hold this case: the
//! controller's test host is what it pairs with, and the controller depends on the client.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::candidate::{AttemptState, Candidate, CandidateRoom, Pairing};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::invitation::{Invitation, read_invitation};
use kr_client::pairing::link::{EndpointPool, IrohLink};
use kr_client::pairing::paired::{PairedHost, PairedHosts};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_pairing::budget::DurableClientBudgetStore;
use kr_protocol::ids::{BuildId, DeviceId};
use kr_protocol::invitation::{InviteEntry, InviteGrantKind, PairInviteResult};
use kr_protocol::pairing::{
    DeviceName, DevicePlatform, PairStatus, PairingConsumedReason, ProposedGrant,
};
use kr_protocol::rights::ActionRight;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use tokio::sync::watch;

/// How long a case waits for a pairing step before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(60);

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

/// A device that pairs through the product's client: its keys, its records and a link of the
/// product's own.
struct Device {
    pairing: Arc<Pairing>,
    _directory: tempfile::TempDir,
}

impl Device {
    fn new(host: &Host) -> Self {
        let keys = DeviceKeys::generate().expect("keys");
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let budget = Arc::new(
            DurableClientBudgetStore::open(
                directory.path().join("budget"),
                Arc::new(MemoryStore::new()),
                "device",
            )
            .expect("a durable budget"),
        );
        let room: Arc<dyn CandidateRoom> = Arc::new(host.room.clone());
        let pool = EndpointPool::new(keys.transport.clone())
            .bound_to("127.0.0.1:0".parse().expect("loopback"));
        let pairing = Arc::new(Pairing {
            candidate: Candidate::new(
                keys,
                DeviceName::new("A test computer").expect("a name"),
                DevicePlatform::Macos,
                BuildId::new("kr-test/0").expect("a build identifier"),
            ),
            budget,
            clock: Arc::new(DeviceClock::current().expect("a clock")),
            room,
            link: Arc::new(IrohLink::new(Arc::new(pool))),
            hosts: Arc::new(PairedHosts::open(directory.path().join("pairing")).expect("a store")),
        });
        Self {
            pairing,
            _directory: directory,
        }
    }

    /// Redeems the direct invitation `invited` shows, and returns the running attempt and what it
    /// shows.
    fn redeem(
        &self,
        invited: &PairInviteResult,
    ) -> (
        tokio::task::JoinHandle<Result<PairedHost, kr_client::pairing::PairingFailure>>,
        watch::Receiver<AttemptState>,
    ) {
        let InviteEntry::Direct { qr_text } = &invited.entry else {
            panic!("a direct invitation is offered as a QR");
        };
        let Invitation::Direct(payload) = read_invitation(
            qr_text.as_str(),
            &kr_protocol::invitation::default_rendezvous_origin(),
        )
        .expect("an invitation") else {
            panic!("a direct invitation's text reads as a direct invitation");
        };
        let (progress, shown) = watch::channel(AttemptState::Idle);
        let pairing = Arc::clone(&self.pairing);
        let attempt = tokio::spawn(async move { pairing.pair_directly(&payload, &progress).await });
        (attempt, shown)
    }
}

/// Waits for an attempt to end and returns how.
async fn outcome(
    attempt: tokio::task::JoinHandle<Result<PairedHost, kr_client::pairing::PairingFailure>>,
) -> Result<PairedHost, kr_client::pairing::PairingFailure> {
    tokio::time::timeout(WATCHDOG, attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
}

/// Every column of one device's row at the host, as stored.
fn row_of(host: &Host, device_id: DeviceId) -> Vec<rusqlite::types::Value> {
    let connection =
        rusqlite::Connection::open(host.registry_database()).expect("the registry opens");
    connection
        .busy_timeout(Duration::from_secs(30))
        .expect("waits for the daemon's writes");
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

/// KR-REQ-10.08: a device that forgot a host that still lists it, and pairs with it again, ends
/// with the kind that says the host still lists it, and not with the kind that says the host could
/// not be reached. The control is the same attempt before the device forgot the host: the device
/// stops itself, as it did before. The host's record of the device is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_forgot_a_host_that_still_lists_it_is_told_so() {
    let owner_keys = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let device = Device::new(&host);

    // The device pairs with the host, once, with the owner's approval.
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let (attempt, mut shown) = device.redeem(&invited);
    let waiting = tokio::time::timeout(
        WATCHDOG,
        shown.wait_for(|state| {
            matches!(
                state,
                AttemptState::AwaitingApproval { .. } | AttemptState::Ended { .. }
            )
        }),
    )
    .await
    .expect("the attempt reaches the owner")
    .expect("the attempt runs")
    .clone();
    assert!(
        matches!(waiting, AttemptState::AwaitingApproval { .. }),
        "the attempt waits for the owner: {waiting:?}"
    );
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the owner approves");
    let paired = outcome(attempt).await.expect("paired");
    let listed = row_of(&host, paired.device_id);

    // The control: a device that holds the host stops itself, before it asks the host anything.
    let again = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let (attempt, _) = device.redeem(&again);
    let stopped = outcome(attempt).await;
    assert!(
        stopped.is_err(),
        "a device that holds the host stops itself"
    );
    assert_eq!(
        stopped.as_ref().expect_err("stopped").kind,
        FailureKind::AlreadyPaired,
        "{stopped:?}"
    );

    // The host never heard of that attempt, so its invitation is still open: the owner withdraws it.
    calls::cancel(environment, &mut client, again.invitation_id, false)
        .await
        .expect("the owner withdraws the invitation");

    // The device forgets the host, and pairs with it again while the host still lists it.
    let forgotten = device.pairing.hosts.forget(paired.host_device_id);
    assert!(
        forgotten.is_ok(),
        "the device forgets the host: {forgotten:?}"
    );
    assert!(
        device.pairing.hosts.list().expect("readable").is_empty(),
        "the device holds nothing of the host"
    );
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let (attempt, _) = device.redeem(&invited);
    let refused = outcome(attempt).await;
    assert!(refused.is_err(), "the host does not pair a device it lists");
    let kind = refused.as_ref().expect_err("refused").kind;
    assert_ne!(
        kind,
        FailureKind::HostUnreachable,
        "the host was reached: {refused:?}"
    );
    assert_eq!(kind, FailureKind::HostStillListsDevice, "{refused:?}");

    let status = tokio::time::timeout(
        WATCHDOG,
        calls::owner_status(&mut client, invited.invitation_id),
    )
    .await
    .expect("the host answered the owner's status request")
    .expect("the owner's view");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::EndpointPaired
        },
        "the host ended the invitation for the device it lists"
    );
    assert_eq!(
        row_of(&host, paired.device_id),
        listed,
        "the host's record of the device is as it was"
    );
    host.stop().await;
}
