//! The host's relay leases, through a real daemon: a device paired on an authorised connection, the
//! daemon that pairs it, and a lease service that answers as the Worker's relay control plane does.
//!
//! Section 17 puts a pinned relay tier in front of the managed service. The relay carries nothing
//! for a pair of endpoints until it holds a lease the service signed for them, and the host is the
//! paying side of every pair it belongs to. What is held here is the host's part: a paired device
//! is given a lease, the lease is refilled before it runs out and ended when the device is
//! unpaired, a request or an ending whose answer was lost is asked again until it is answered, a
//! spent allowance or a refusal is shown to the owner and is not a fault, and a lease or an ending
//! the host cannot send is not lost in a restart.
//!
//! The service is the stand-in held to the Worker's source. Every wait the daemon asks for is held
//! by the test, and the tests ask the keeper for a pass when they need one.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::relay_leases::{
    BLOCK_BYTES, LEASE_SECONDS, MIN_ASK_GAP, REFILL_WHEN_LEFT, STANDING_RETRY,
};
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::AuthorisationKey;
use kr_service_stand_in::{Moment, RelayLeaseView, RelayPayerRecord, Served, serve};
use net_support::{Device, Host, MovedWall, pair_with, proposal};

const ISSUE: &str = "/api/relay/lease";
const REVOKE: &str = "/api/relay/lease/revoke";

/// The service cannot be reached.
const SERVICE_DOWN: Moment = Moment::Refuse {
    status: 503,
    code: "SERVICE_UNAVAILABLE",
    retry_after_seconds: None,
};

/// The service turns the request back for a reason only the owner can change.
const TURNED_BACK: Moment = Moment::Refuse {
    status: 403,
    code: "FORBIDDEN",
    retry_after_seconds: None,
};

/// The service answers that it does not carry the lease, or that it kept changing.
const NOT_CARRIED: Moment = Moment::Refuse {
    status: 400,
    code: "INVALID_REQUEST",
    retry_after_seconds: None,
};

/// Everything one test holds: a daemon whose configuration selects a lease service and names the
/// account that pays, the service, and the clocks.
struct Rig {
    host: Host,
    served: Served,
    timer: Arc<HeldTimer>,
    wall: MovedWall,
    owner: DeviceKeys,
    host_key: AuthorisationKey,
    payer: RelayPayerRecord,
}

impl Rig {
    /// A daemon that names the account that authorised its key, with the owner's device
    /// paired and holding a lease.
    async fn start() -> Self {
        let rig = Self::start_naming(true).await;
        let owner = rig.owner_device();
        rig.until("the owner's device holds a lease", || rig.holds(&owner))
            .await;
        rig
    }

    /// As [`Self::start`], naming no account when `names_an_account` is false, and not waiting for
    /// a lease.
    async fn start_naming(names_an_account: bool) -> Self {
        Self::start_bounded_naming(names_an_account, 8 * 1024 * 1024).await
    }

    /// A daemon whose account authorised the host's key to hold `bound` bytes outstanding for one
    /// lease, with the owner's device paired and holding a lease.
    async fn start_bounded(bound: u64) -> Self {
        let rig = Self::start_bounded_naming(true, bound).await;
        let owner = rig.owner_device();
        rig.until("the owner's device holds a lease", || rig.holds(&owner))
            .await;
        rig
    }

    async fn start_bounded_naming(names_an_account: bool, bound: u64) -> Self {
        let served = serve().await;
        let timer = HeldTimer::held();
        let wall = MovedWall::new();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host_keys = DeviceKeys::generate().expect("host keys");
        let payer = served
            .web()
            .authorise_relay_payer(host_keys.authorisation.public(), bound);
        let host = Host::start_with_relay(
            &owner,
            &host_keys,
            Some(served.origin()),
            names_an_account
                .then_some((payer.account_id.as_str(), payer.authorisation_id.as_str())),
            Arc::clone(&timer) as _,
            wall.clocks(),
        )
        .await;
        Self {
            host,
            served,
            timer,
            wall,
            owner,
            host_key: *host_keys.authorisation.public(),
            payer,
        }
    }

    fn keeper(&self) -> &kr_controller::relay_leases::RelayKeeper {
        self.host.controller().relay_keeper().expect("a keeper")
    }

    fn owner_device(&self) -> DeviceRecord {
        self.host.owner.clone().expect("an owner")
    }

    /// A device pairs under a grant with the rights named, and has not connected.
    async fn pairs(&self) -> (Device, DeviceRecord) {
        let device = Device::create().await;
        let record = pair_with(
            &self.host,
            &device,
            &self.owner,
            proposal(&[ActionRight::SessionView]),
        )
        .await;
        (device, record)
    }

    /// Waits until the condition holds. It is checked after each pass the keeper finishes, and a
    /// test that went wrong is stopped rather than left to hang.
    async fn until(&self, what: &str, condition: impl Fn() -> bool) {
        let mut passes = self.keeper().passes();
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                if condition() {
                    return;
                }
                passes.changed().await.expect("the keeper runs");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("gave up waiting until {what}"));
    }

    /// Waits until the keeper has finished a pass that began after this call.
    async fn pass(&self) {
        tokio::time::timeout(Duration::from_secs(180), self.keeper().after_a_pass())
            .await
            .expect("the keeper finishes a pass");
    }

    /// The daemon's clock and the service's both move on: the time a lease was issued for passes.
    fn time_passes(&self, by: Duration) {
        self.wall.advance(by);
        self.served.web().advance_relay_clock(by);
    }

    /// The leases the service holds for one device's pair, newest last.
    fn leases_for(&self, device: &DeviceRecord) -> Vec<RelayLeaseView> {
        self.served
            .web()
            .relay_leases()
            .into_iter()
            .filter(|lease| lease.destination == device.endpoint_id)
            .collect()
    }

    /// The live lease the service holds for a device's pair, when it holds one.
    fn live_lease_for(&self, device: &DeviceRecord) -> Option<RelayLeaseView> {
        self.leases_for(device).into_iter().find(|lease| lease.live)
    }

    fn connection(&self) -> rusqlite::Connection {
        let state = self
            .host
            .tree()
            .environment()
            .registry_database()
            .parent()
            .expect("the state directory")
            .to_path_buf();
        rusqlite::Connection::open_with_flags(
            state.join("relay-leases.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the host's record of leases")
    }

    /// The lease the host's own record holds for a device: `None` when the record has no row for
    /// it, and `Some(None)` when it has a row that names no lease.
    fn lease_in_the_record(&self, device: &DeviceRecord) -> Option<Option<String>> {
        self.connection()
            .query_row(
                "SELECT lease_id FROM relay_leases WHERE destination = ?1",
                [device.endpoint_id.as_bytes().as_slice()],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
    }

    /// Whether the host's record names a lease for the device.
    fn holds(&self, device: &DeviceRecord) -> bool {
        matches!(self.lease_in_the_record(device), Some(Some(_)))
    }

    /// The endings the host's record says the service has not answered.
    fn endings_owed(&self) -> usize {
        self.connection()
            .query_row("SELECT count(*) FROM relay_endings", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_or(0, |count| usize::try_from(count).unwrap_or(0))
    }

    /// How many requests of a kind reached the service.
    fn requests(&self, path: &str) -> usize {
        self.served.web().requests_to(path)
    }

    /// The bodies of the requests of one kind, in the order they arrived.
    fn bodies(&self, path: &str) -> Vec<serde_json::Value> {
        self.served
            .web()
            .arrived()
            .into_iter()
            .filter(|arrived| arrived.path == path)
            .map(|arrived| arrived.body)
            .collect()
    }

    /// When the host's record says the latest request for a device was written, in milliseconds.
    fn row_written_at(&self, device: &DeviceRecord) -> Option<u64> {
        self.connection()
            .query_row(
                "SELECT written_at_ms FROM relay_leases WHERE destination = ?1",
                [device.endpoint_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .and_then(|at| u64::try_from(at).ok())
    }

    /// How many lease requests for one device's pair reached the service.
    fn requests_for(&self, device: &DeviceRecord) -> usize {
        let destination = serde_json::to_value(device.endpoint_id).expect("an endpoint");
        self.bodies(ISSUE)
            .iter()
            .filter(|body| body["destination_endpoint_key"] == destination)
            .count()
    }

    /// How many revocations of one lease reached the service.
    fn revocations_of(&self, lease_id: &str) -> usize {
        self.bodies(REVOKE)
            .iter()
            .filter(|body| body["lease_id"] == lease_id)
            .count()
    }

    /// What `kr doctor` says of the keeper.
    async fn check(&self) -> DoctorCheck {
        let mut local = self.host.client().await;
        let doctor: HostDoctorResult =
            net_support::pairing::read(&mut local, Method::HostDoctor, &())
                .await
                .expect("the host's diagnostics");
        doctor
            .checks
            .into_iter()
            .find(|check| check.id() == "relay-leases")
            .expect("the keeper's check")
    }

    /// Stops the daemon and starts it again on its tree, with its document naming `payer`.
    async fn restarted_naming(self, payer: &RelayPayerRecord) -> Self {
        let Self {
            host,
            served,
            owner,
            host_key,
            wall,
            ..
        } = self;
        let stopped = host.shut_down().await;
        net_support::write_relay_document(
            stopped.tree(),
            Some(served.origin()),
            Some((&payer.account_id, &payer.authorisation_id)),
        );
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        Self {
            host,
            served,
            timer,
            wall,
            owner,
            host_key,
            payer: payer.clone(),
        }
    }

    /// Stops the daemon and starts it again on its tree.
    async fn restarted(self) -> Self {
        self.restarted_after(|_| {}).await
    }

    /// Stops the daemon, lets `change` alter its tree, and starts it again on the tree.
    async fn restarted_after(self, change: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        let Self {
            host,
            served,
            owner,
            host_key,
            payer,
            wall,
            ..
        } = self;
        let stopped = host.shut_down().await;
        change(stopped.tree());
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        Self {
            host,
            served,
            timer,
            wall,
            owner,
            host_key,
            payer,
        }
    }
}

/// KR-REQ-17.34, KR-REQ-17.51: a paired device is given a lease for its pair. It binds this host's
/// endpoint and the device's, both ways, and the account the host's configuration names pays, under
/// the authorisation that account gave this host's key. The host's record names the lease the
/// service issued, and the owner's own device has one too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_given_a_lease_for_its_pair() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;

    let lease = rig.live_lease_for(&record).expect("the service holds it");
    assert_eq!(lease.source, rig.host.network().endpoint_id());
    assert_eq!(lease.destination, record.endpoint_id);
    assert_eq!(
        lease.authorisation_id.as_deref(),
        Some(rig.payer.authorisation_id.as_str()),
        "the account the document names pays"
    );
    assert!(lease.byte_ceiling >= BLOCK_BYTES);
    assert_eq!(
        rig.lease_in_the_record(&record),
        Some(Some(lease.lease_id.clone())),
        "the host's record names the lease the service issued"
    );
    let owner = rig.owner_device();
    assert!(
        rig.live_lease_for(&owner).is_some(),
        "the owner's device is a paired device like any other"
    );
    let first = &rig.bodies(ISSUE)[0];
    assert_eq!(first["direction"], "bidirectional");
    assert_eq!(first["duration_seconds"], LEASE_SECONDS);
    assert_eq!(
        first["payer"]["account"]["account_id"],
        rig.payer.account_id
    );
    assert!(
        first["lease_id"].is_null(),
        "a first request names no lease"
    );
}

/// KR-REQ-17.34: a device paired before the daemon selected a lease service is given its lease when
/// the daemon next starts, and a daemon that asked for nothing before asks for one lease for each
/// paired device. A restart finds the leases the record holds and asks for none again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_paired_before_the_daemon_started_is_given_its_lease_at_the_start() {
    let served = serve().await;
    let wall = MovedWall::new();
    let owner = DeviceKeys::generate().expect("owner keys");
    let host_keys = DeviceKeys::generate().expect("host keys");
    let payer = served
        .web()
        .authorise_relay_payer(host_keys.authorisation.public(), 8 * 1024 * 1024);
    let host = Host::start_with_relay(
        &owner,
        &host_keys,
        None,
        None,
        HeldTimer::held() as _,
        wall.clocks(),
    )
    .await;
    assert!(host.controller().relay_keeper().is_none());
    let phone = Device::create().await;
    let paired = pair_with(&host, &phone, &owner, proposal(&[ActionRight::SessionView])).await;
    let stopped = host.shut_down().await;
    net_support::write_relay_document(
        stopped.tree(),
        Some(served.origin()),
        Some((&payer.account_id, &payer.authorisation_id)),
    );
    assert_eq!(
        served.web().requests_to(ISSUE),
        0,
        "nothing was asked before"
    );
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    let rig = Rig {
        host,
        served,
        timer,
        wall,
        owner,
        host_key: *host_keys.authorisation.public(),
        payer,
    };
    let owner_device = rig.owner_device();
    rig.until("both paired devices hold a lease", || {
        rig.holds(&owner_device) && rig.holds(&paired)
    })
    .await;
    assert_eq!(rig.requests(ISSUE), 2, "one for each paired device");

    let rig = rig.restarted().await;
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        2,
        "a lease that is held is not asked for again"
    );
    assert!(rig.holds(&paired));
    assert_eq!(rig.leases_for(&paired).len(), 1);
}

/// KR-REQ-17.34, KR-REQ-17.51: a lease is refilled before it runs out, naming the lease it holds,
/// so the service raises the reservation it has and opens no second one. The service moves a
/// deadline only with a raised ceiling, so an idle pair's refill raises it by a byte, and the
/// ceiling the host asks for follows what the relay counted, as the reservation's cumulative
/// total. A lease that has plenty of its life left is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_is_refilled_before_it_runs_out_and_the_ceiling_follows_what_the_relay_counted() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    let issued = rig.requests(ISSUE);

    // Control: a third of the lease's life has not gone, so the host asks for nothing.
    rig.time_passes(Duration::from_secs(200));
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), issued, "the lease has life to spare");

    // The refill falls due when no more than REFILL_WHEN_LEFT remains.
    let left = Duration::from_secs(u64::from(LEASE_SECONDS)) - Duration::from_secs(200);
    rig.time_passes(left - REFILL_WHEN_LEFT + Duration::from_secs(1));
    rig.served.web().relay_counts(&first.lease_id, 300 * 1024);
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), issued + 1);
    let refilled = rig.live_lease_for(&owner).expect("the same lease");
    assert_eq!(
        refilled.lease_id, first.lease_id,
        "the lease is refilled and not opened again"
    );
    assert_eq!(rig.leases_for(&owner).len(), 1);
    assert!(refilled.revision > first.revision);
    assert!(refilled.expires_at_ms > first.expires_at_ms);
    let sent = rig.bodies(ISSUE);
    assert_eq!(sent.last().expect("a refill")["lease_id"], first.lease_id);
    assert_eq!(
        sent.last().expect("a refill")["byte_ceiling"],
        (first.byte_ceiling + 1).to_string(),
        "the relay had counted nothing the host knew of, so the refill raises the block by a byte"
    );

    // The answer told the host what the relay had counted; the next refill adds a block to it.
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let sent = rig.bodies(ISSUE);
    assert_eq!(
        sent.last().expect("a second refill")["byte_ceiling"],
        (300 * 1024 + BLOCK_BYTES).to_string()
    );
    assert_eq!(
        rig.live_lease_for(&owner).expect("a lease").lease_id,
        first.lease_id
    );
}

/// KR-REQ-17.51: a device that is unpaired has its lease ended, with the reason that the pair is no
/// longer paired, and the host's record forgets it once the service has answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unpaired_device_has_its_lease_ended() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    let lease = rig.live_lease_for(&record).expect("a lease");

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the service has ended the lease", || {
        rig.live_lease_for(&record).is_none() && rig.endings_owed() == 0
    })
    .await;

    let ended = &rig.leases_for(&record)[0];
    assert_eq!(ended.lease_id, lease.lease_id);
    assert_eq!(ended.ended_for, Some("unpaired"));
    assert_eq!(
        rig.lease_in_the_record(&record),
        None,
        "the record keeps nothing for it"
    );
    assert!(
        rig.live_lease_for(&rig.owner_device()).is_some(),
        "the owner's device keeps its lease"
    );
}

/// KR-REQ-17.51: an ending whose answer is lost is owed until the service answers it, across a
/// restart. The first ending never reaches the service; the host is stopped with the ending written
/// down, and the daemon that starts on the same tree sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_whose_answer_was_lost_is_asked_again_until_it_is_answered() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.served.web().fail(REVOKE, 1, Moment::Before);

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the ending is owed", || {
        rig.endings_owed() == 1 && rig.requests(REVOKE) == 1
    })
    .await;
    assert!(
        rig.live_lease_for(&record).is_some(),
        "the service has not heard of it, so the pair is still carried"
    );

    let rig = rig.restarted().await;
    rig.until("the service has ended the lease", || {
        rig.live_lease_for(&record).is_none() && rig.endings_owed() == 0
    })
    .await;
    assert_eq!(
        rig.requests(REVOKE),
        2,
        "the ending was asked for again, once"
    );

    // A lost answer is the other way an ending is not answered: the service acted and the host
    // heard nothing. The host asks again, and the service answers the same.
    let (_second, other) = rig.pairs().await;
    rig.until("the second device holds a lease", || rig.holds(&other))
        .await;
    rig.served.web().fail(REVOKE, 1, Moment::After);
    rig.host
        .network()
        .revoke_device(other.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the service has acted and the host has not heard", || {
        rig.live_lease_for(&other).is_none() && rig.endings_owed() == 1
    })
    .await;
    rig.pass().await;
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.endings_owed(), 0, "the second ask is answered");
    assert_eq!(
        rig.leases_for(&other).len(),
        1,
        "and nothing else was opened"
    );
}

/// KR-REQ-17.51: a lease request whose answer is lost may have issued a lease. The host has not
/// written down a lease it was not told of, so it asks again for the same pair, with the same
/// request, and the service answers with the lease the pair already holds: one lease, not two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_issue_whose_answer_was_lost_is_asked_again_and_the_pair_holds_one_lease() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;
    assert_eq!(rig.leases_for(&record).len(), 1, "the service issued it");

    // The pass that met the lost answer has ended, and the backoff after it has run its course.
    rig.pass().await;
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert!(rig.holds(&record), "asking again taught the host the lease");
    assert_eq!(rig.leases_for(&record).len(), 1, "the pair holds one lease");
    let asked = rig.bodies(ISSUE);
    let (lost, again) = (&asked[asked.len() - 2], &asked[asked.len() - 1]);
    assert_eq!(
        lost, again,
        "the same request, with the same ceiling and no lease named"
    );
}

/// KR-REQ-17.51: the row written before the request is what a restart finds. A daemon that starts
/// on the record of a request whose answer was lost sends it again, as it was, and learns the lease
/// the service issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_issue_whose_answer_was_lost_is_asked_again_by_the_daemon_that_starts_next() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;

    let rig = rig.restarted().await;
    rig.until("the host has learned the lease", || rig.holds(&record))
        .await;
    assert_eq!(rig.leases_for(&record).len(), 1, "the pair holds one lease");
    let asked = rig.bodies(ISSUE);
    let (lost, again) = (&asked[asked.len() - 2], &asked[asked.len() - 1]);
    assert_eq!(lost, again, "the same request, as it was written");
}

/// KR-REQ-17.51: a lease the host was never told of is still ended when its device is unpaired. The
/// host asks again for the pair, which is the only way to learn the lease, and ends what the
/// service answers with, so a lost answer cannot leave a pair carried after it is unpaired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_whose_answer_was_lost_is_still_ended_when_its_device_is_unpaired() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;
    rig.pass().await;

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    // The backoff after a request that went unanswered has run its course.
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until(
        "the service has ended the lease and the host owes nothing",
        || {
            rig.live_lease_for(&record).is_none()
                && rig.endings_owed() == 0
                && rig.lease_in_the_record(&record).is_none()
        },
    )
    .await;
    let leases = rig.leases_for(&record);
    assert_eq!(leases.len(), 1, "asking again opened no second lease");
    assert_eq!(leases[0].ended_for, Some("unpaired"));
}

/// The seconds of grace a doctor line says are left to a connection already running.
fn grace_seconds(detail: &str) -> Option<u64> {
    detail
        .split("already running is ")
        .nth(1)?
        .split(' ')
        .next()?
        .parse()
        .ok()
}

/// KR-REQ-17.40, KR-REQ-17.50, KR-REQ-17.52: an allowance that is spent is an answer about
/// capacity and not a fault. The host holds the leases it has, issues no new one, tells the owner
/// how much grace is left and that a direct connection and a relay of their own still work, asks
/// again no sooner than the standing interval, and issues the lease when the allowance is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allowance_that_is_spent_is_shown_to_the_owner_and_asked_again() {
    let rig = Rig::start().await;
    rig.served.web().exhaust_relay_allowance(true);
    let began = kr_ipc::now_ms().get();
    let (_phone, record) = rig.pairs().await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;

    assert!(rig.live_lease_for(&record).is_none());
    assert_eq!(
        rig.lease_in_the_record(&record),
        Some(None),
        "a request that issued nothing leaves a row that names no lease"
    );
    assert!(
        rig.live_lease_for(&rig.owner_device()).is_some(),
        "a lease that is held is held"
    );
    // The daemon's clock goes on, as it does between the answer and the owner's look.
    let moved = Duration::from_secs(30);
    rig.time_passes(moved);
    let shown = rig.check().await;
    let ended = kr_ipc::now_ms().get();
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(shown.detail().contains("allowance"), "{}", shown.detail());
    // What is shown is what the answer announced less the time that has passed on the daemon's
    // clock since it was read, so it is held to the readings of that clock and not to how long the
    // machine took to get from one to the next.
    let left = grace_seconds(shown.detail());
    let announced = 600;
    let passed_at_least = moved.as_secs();
    let passed_at_most = passed_at_least + (ended - began).div_ceil(1000);
    assert!(
        left.is_some_and(|left| {
            left <= announced - passed_at_least && left + passed_at_most >= announced - 1
        }) && shown.detail().contains("104857600 bytes"),
        "the grace left is shown: {}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("direct connection")),
        "and the paths that still work"
    );

    rig.served.web().exhaust_relay_allowance(false);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert!(rig.holds(&record));
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.35: a host that names no account is turned away by the service, whose reason is that
/// a host key draws on no allowance of its own. That is shown to the owner with what to change. The
/// host asks no oftener than the standing interval, however many devices are paired or unpaired in
/// the meantime, and when it asks again a refusal that two devices meet in one pass ends the pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_names_no_account_is_turned_away_and_the_owner_is_told() {
    let rig = Rig::start_naming(false).await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    assert_eq!(rig.requests(ISSUE), 1);
    assert!(rig.served.web().relay_leases().is_empty());

    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("the account that pays"),
        "{}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("relay.payer")),
        "{:?}",
        shown.remedy()
    );

    // Two more devices are paired. A pairing wakes the keeper, and the keeper asks for nothing: the
    // service is not asked again before the standing interval has passed.
    let (_phone, _first) = rig.pairs().await;
    let (_tablet, _second) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        1,
        "a pairing does not bring a request forward"
    );

    // When the interval has passed the devices are asked for in order, and the second refusal ends
    // the pass: the third device is not asked.
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), 3, "two refusals end the pass");
}

/// KR-REQ-17.51: a lease the service no longer carries is asked for again as a new one. The refill
/// names the lease the host holds, the service answers that it is not carrying it, and the host
/// asks for the pair afresh, which the service answers with a lease of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_the_service_no_longer_carries_is_asked_for_again_as_a_new_one() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().end_relay_lease(&first.lease_id);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let renewed = rig.live_lease_for(&owner).expect("a new lease");
    assert_ne!(renewed.lease_id, first.lease_id);
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(renewed.lease_id))
    );
    // The raise is turned back, the ceiling the lease already holds is asked for to learn whether
    // the lease or only the raise was refused, and the pair is asked for afresh.
    let sent = rig.bodies(ISSUE);
    let (raise, probe, afresh) = (
        &sent[sent.len() - 3],
        &sent[sent.len() - 2],
        &sent[sent.len() - 1],
    );
    assert_eq!(raise["lease_id"], first.lease_id);
    assert_eq!(raise["byte_ceiling"], (first.byte_ceiling + 1).to_string());
    assert_eq!(probe["lease_id"], first.lease_id);
    assert_eq!(probe["byte_ceiling"], first.byte_ceiling.to_string());
    assert!(afresh["lease_id"].is_null());
}

/// KR-REQ-17.35: an authorisation the account withdraws ends the leases issued under it at the
/// service, and the host's next request is refused. The owner is told what to check. The host
/// cannot know that the lease is gone, so its record still names the lease: a daemon started with
/// another authorisation ends it, which is the owner's way out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_authorisation_ends_the_leases_and_the_owner_is_told() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served
        .web()
        .withdraw_relay_authorisation(&rig.payer.authorisation_id);
    assert!(
        rig.live_lease_for(&owner).is_none(),
        "the service fenced it"
    );

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    assert!(
        rig.live_lease_for(&owner).is_none(),
        "nothing is issued under it again"
    );
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(first.lease_id)),
        "the record names the lease the host was told of"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("relay.payer")),
        "{:?}",
        shown.remedy()
    );
}

/// KR-REQ-17.51: the account that pays is part of what a lease was asked for. A host started with
/// another authorisation ends the lease it holds under the old one, with the reason that the payer
/// withdrew, and asks for the pair under the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_payer_ends_the_lease_issued_under_the_old_one() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let old = rig.live_lease_for(&owner).expect("a lease");
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    let Rig {
        host,
        served,
        owner: owner_keys,
        host_key,
        payer,
        wall,
        ..
    } = rig;
    let stopped = host.shut_down().await;
    net_support::write_relay_document(
        stopped.tree(),
        Some(served.origin()),
        Some((&other.account_id, &other.authorisation_id)),
    );
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    let rig = Rig {
        host,
        served,
        timer,
        wall,
        owner: owner_keys,
        host_key,
        payer,
    };

    rig.until("the old lease is ended and a new one is held", || {
        rig.live_lease_for(&owner)
            .is_some_and(|lease| lease.lease_id != old.lease_id)
            && rig.endings_owed() == 0
    })
    .await;
    let leases = rig.leases_for(&owner);
    let ended = leases
        .iter()
        .find(|lease| lease.lease_id == old.lease_id)
        .expect("the old lease");
    assert_eq!(ended.ended_for, Some("payer_withdrew"));
    let live = leases
        .iter()
        .find(|lease| lease.live)
        .expect("the new lease");
    assert_eq!(
        live.authorisation_id.as_deref(),
        Some(other.authorisation_id.as_str())
    );
}

/// KR-REQ-17.51: a service that cannot be reached leaves the leases the host holds alone and is
/// asked again. A refusal that names a delay is waited out: the next wait is at least that long,
/// and the host asks again when the delay has passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_cannot_be_reached_leaves_a_held_lease_alone_and_is_asked_again() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let held = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(7),
        },
    );

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    rig.until("the keeper waits out the delay", || {
        rig.timer.asked_for().contains(&Duration::from_secs(7))
    })
    .await;
    assert!(
        rig.live_lease_for(&owner).is_some(),
        "the lease it holds runs on"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("did not answer"),
        "{}",
        shown.detail()
    );

    rig.timer.advance(Duration::from_secs(8));
    rig.pass().await;
    let refilled = rig.live_lease_for(&owner).expect("a lease");
    assert_eq!(refilled.lease_id, held.lease_id);
    assert!(
        refilled.revision > held.revision,
        "the refill went through when the delay had passed"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.35: what the host holds belongs to the service that issued it. A host started against
/// another service sends it no lease identifier and no ending of the first's, and asks it for the
/// pair afresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_identifier_is_never_sent_to_another_service() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    let before = rig.requests(REVOKE);

    let other = serve().await;
    let account = other
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);
    let Rig {
        host,
        served,
        owner: owner_keys,
        host_key,
        payer,
        wall,
        ..
    } = rig;
    let stopped = host.shut_down().await;
    net_support::write_relay_document(
        stopped.tree(),
        Some(other.origin()),
        Some((&account.account_id, &account.authorisation_id)),
    );
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    let rig = Rig {
        host,
        served: other,
        timer,
        wall,
        owner: owner_keys,
        host_key,
        payer: account,
    };
    rig.until("the second service issues a lease", || {
        rig.live_lease_for(&owner).is_some()
    })
    .await;

    for body in rig.bodies(ISSUE) {
        assert!(
            body["lease_id"].is_null(),
            "no identifier of the first service's is sent"
        );
    }
    assert_eq!(rig.requests(REVOKE), 0, "and nothing is ended there");
    assert_eq!(
        served.web().requests_to(REVOKE),
        before,
        "the first service is not asked either"
    );
    assert!(
        served
            .web()
            .relay_leases()
            .iter()
            .any(|lease| lease.lease_id == first.lease_id)
    );
    drop(payer);
}

/// KR-REQ-17.34: a deadline the service cannot move later, as at the end of a billing period, is
/// not asked for at once again. The refill is answered with the deadline where it was, the lease is
/// still due, and the host asks for it no oftener than the gap, whatever it was answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_that_cannot_move_is_not_asked_for_at_once_again() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().freeze_relay_deadlines(true);
    let issued = rig.requests(ISSUE);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), issued + 1);
    let answered = rig.live_lease_for(&owner).expect("a lease");
    assert_eq!(
        answered.expires_at_ms, first.expires_at_ms,
        "the service left the deadline where it was"
    );

    // The lease is still due, and nothing has been spent since it was asked for.
    rig.pass().await;
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), issued + 1, "not asked again at once");
    rig.time_passes(MIN_ASK_GAP + Duration::from_secs(1));
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        issued + 2,
        "asked again when the gap has passed"
    );
}

/// KR-REQ-17.40, KR-REQ-17.50: a service that could not issue a lease, with its relay withheld or
/// no room for another, is an answer about capacity: the owner is told, the host asks no oftener
/// than the standing interval, and the lease is issued when the service can.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_has_no_room_for_a_lease_says_so_and_is_asked_again_later() {
    let rig = Rig::start().await;
    rig.served.web().withhold_relays(true);
    let (_phone, record) = rig.pairs().await;
    rig.until(
        "the keeper has been answered that no lease can be issued",
        || rig.timer.asked_for().contains(&STANDING_RETRY),
    )
    .await;
    assert!(rig.live_lease_for(&record).is_none());
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("could not issue a lease"),
        "{}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("direct connection")),
        "{:?}",
        shown.remedy()
    );

    rig.served.web().withhold_relays(false);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert!(rig.holds(&record));
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.51: a pairing or a revocation wakes the keeper, and what the service asked the host to
/// wait for is still waited for. Devices paired while the allowance is spent are not asked for
/// until the standing interval has passed, and are given their leases then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_does_not_bring_forward_a_request_the_service_would_refuse_again() {
    let rig = Rig::start().await;
    rig.served.web().exhaust_relay_allowance(true);
    let (_first_phone, first) = rig.pairs().await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    let asked = rig.requests(ISSUE);

    let (_second_phone, second) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        asked,
        "the pairing woke the keeper and sent nothing"
    );

    rig.served.web().exhaust_relay_allowance(false);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert!(rig.holds(&first) && rig.holds(&second));
}

/// KR-REQ-17.51: the relay carrying a lease can be retired. The service then answers a refill that
/// the lease should be revoked and another asked for; the host ends the lease, with the reason that
/// it is finished, and asks for the pair afresh in the same pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_on_a_retired_relay_is_ended_and_asked_for_afresh() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().retire_relay_of(&first.lease_id);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let renewed = rig.live_lease_for(&owner).expect("a new lease");
    assert_ne!(renewed.lease_id, first.lease_id);
    let leases = rig.leases_for(&owner);
    let ended = leases
        .iter()
        .find(|lease| lease.lease_id == first.lease_id)
        .expect("the old lease");
    assert!(!ended.live);
    assert_eq!(ended.ended_for, Some("finished"));
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(renewed.lease_id))
    );
    assert_eq!(rig.endings_owed(), 0);
    // The raise is turned back, and so is the ceiling the lease already holds: it is the relay.
    let sent = rig.bodies(ISSUE);
    let (raise, probe) = (&sent[sent.len() - 3], &sent[sent.len() - 2]);
    assert_eq!(raise["byte_ceiling"], (first.byte_ceiling + 1).to_string());
    assert_eq!(probe["byte_ceiling"], first.byte_ceiling.to_string());
    assert_eq!(rig.requests(REVOKE), 1);
}

/// KR-REQ-17.51: a lease that has run out was settled by the service, and what the relay counted
/// under it belongs to a reservation that is gone. The pair is asked for afresh with the block a
/// new reservation holds, not with the cumulative figures of the old one, which would hold the pair
/// more of the account's aggregate than it needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_has_run_out_is_asked_for_afresh_with_the_figures_of_a_new_reservation() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    // The relay counts all the lease holds, and the refill that follows learns it.
    rig.served.web().relay_counts(&first.lease_id, u64::MAX / 4);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    let counted = rig.live_lease_for(&owner).expect("a lease").bytes_consumed;
    assert!(counted >= BLOCK_BYTES);

    // The service cannot be reached until the lease has run out.
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 1));
    rig.pass().await;
    rig.pass().await;
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;

    let sent = rig.bodies(ISSUE);
    let afresh = sent.last().expect("a request");
    assert!(
        afresh["lease_id"].is_null(),
        "no lease of the old reservation is named"
    );
    assert_eq!(
        afresh["byte_ceiling"],
        BLOCK_BYTES.to_string(),
        "and the figures are a new reservation's"
    );
    let renewed = rig.live_lease_for(&owner).expect("a new lease");
    assert_ne!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.byte_ceiling, BLOCK_BYTES);
    // The lease that ran out is ended at the service before the pair is asked for again.
    assert_eq!(rig.requests(REVOKE), 1);
    let old = rig
        .leases_for(&owner)
        .into_iter()
        .find(|lease| lease.lease_id == first.lease_id)
        .expect("the lease that ran out");
    assert!(!old.live);
}

/// KR-REQ-17.49, KR-REQ-17.51: the bound on a principal's leases is on what is outstanding, the
/// ceiling less what the relay counted, so a pair that carries traffic past 8 MiB is still given
/// the next block. The relay counts all a lease holds at every refill, and the ceiling passes 8
/// MiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_count_beyond_the_aggregate_does_not_stop_a_refill() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    for _ in 0..40 {
        rig.served.web().relay_counts(&first.lease_id, u64::MAX / 4);
        rig.time_passes(Duration::from_secs(301));
        rig.pass().await;
    }
    let carried = rig.live_lease_for(&owner).expect("the same lease");
    assert_eq!(carried.lease_id, first.lease_id);
    assert!(
        carried.byte_ceiling > 8 * 1024 * 1024,
        "the ceiling is {}",
        carried.byte_ceiling
    );
    assert!(carried.bytes_consumed > 8 * 1024 * 1024 - BLOCK_BYTES);
}

/// KR-REQ-17.51: an ending the service answers as a lease it never issued is asked again before it
/// is believed, because the service says the same when a revocation raced a refill. The lease is
/// owed an ending until the third such answer and until the longest a lease lives has passed since
/// the first: before that, a lease the service still carries would be left carrying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_answered_as_never_issued_is_asked_again_before_it_is_believed() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    let lease = rig.live_lease_for(&record).expect("a lease");
    rig.served.web().forget_relay_lease(&lease.lease_id);

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the first answer", || rig.requests(REVOKE) == 1)
        .await;
    // The pass that met it has ended before the timer moves.
    rig.pass().await;
    assert_eq!(rig.endings_owed(), 1, "owed after the first answer");
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.revocations_of(&lease.lease_id), 2);
    assert_eq!(rig.endings_owed(), 1, "owed after the second answer");
    rig.time_passes(Duration::from_secs(60));
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.revocations_of(&lease.lease_id), 3);
    assert_eq!(
        rig.endings_owed(),
        1,
        "not believed at the third answer: the lease may still be alive"
    );
    // The longest a lease lives has passed since the first answer.
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 100));
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.revocations_of(&lease.lease_id), 4);
    assert_eq!(
        rig.endings_owed(),
        0,
        "believed once no lease could be alive"
    );
}

/// KR-REQ-17.51: the service answers a revocation with the same code when the lease kept changing
/// under it and the revocation should be asked again, and the lease is still carried. Three such
/// answers do not prove it absent: the ending is kept, and the lease is ended when the service
/// takes the revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_the_service_keeps_turning_back_as_unknown_is_sent_until_it_takes_it() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    for nth in 1..=3 {
        rig.served.web().fail(
            REVOKE,
            nth,
            Moment::Refuse {
                status: 400,
                code: "INVALID_REQUEST",
                retry_after_seconds: None,
            },
        );
    }
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the first answer", || rig.requests(REVOKE) == 1)
        .await;
    for expected in 2..=3 {
        rig.pass().await;
        rig.time_passes(Duration::from_secs(60));
        rig.timer.advance(Duration::from_secs(60));
        rig.pass().await;
        assert_eq!(rig.requests(REVOKE), expected);
    }

    assert_eq!(rig.endings_owed(), 1, "three answers do not settle it");
    assert!(
        rig.live_lease_for(&record).is_some(),
        "the service still carries the lease"
    );
    rig.time_passes(Duration::from_secs(60));
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 4);
    assert!(rig.live_lease_for(&record).is_none(), "the fourth is taken");
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51, KR-REQ-17.40: a refill the service turns back with `unavailable` is not always
/// about the lease: the raise can pass the aggregate the account holds outstanding. The host asks
/// for the ceiling the lease already holds, finds it carried, keeps it, and tells the owner there
/// is no room; it raises the lease when there is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refill_the_service_has_no_room_for_keeps_the_lease_it_has() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().limit_relay_aggregate(BLOCK_BYTES);
    let issued = rig.requests(ISSUE);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;

    assert_eq!(rig.requests(ISSUE), issued + 2, "the raise and the probe");
    assert_eq!(rig.requests(REVOKE), 0, "the lease is not ended");
    let kept = rig.live_lease_for(&owner).expect("the lease it had");
    assert_eq!(kept.lease_id, first.lease_id);
    assert_eq!(rig.leases_for(&owner).len(), 1);
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("could not raise a lease"),
        "{}",
        shown.detail()
    );

    rig.served.web().limit_relay_aggregate(8 * 1024 * 1024);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    let raised = rig.live_lease_for(&owner).expect("the same lease");
    assert_eq!(raised.lease_id, first.lease_id);
    assert!(raised.expires_at_ms > first.expires_at_ms, "and raised");
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.49: what an authorisation lets one lease hold outstanding bounds the ceiling less the
/// bytes counted, so a bound of exactly one block lets no idle lease be raised, and the service
/// answers the raise as invalid. The host keeps the lease, asks for the ceiling it holds, and tells
/// the owner the bound is too small, instead of opening the pair again and calling it a success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authorisation_too_small_to_raise_a_lease_is_said_so_and_the_lease_is_kept() {
    let rig = Rig::start_bounded(BLOCK_BYTES).await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    let issued = rig.requests(ISSUE);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;

    assert_eq!(rig.requests(ISSUE), issued + 2, "the raise and the probe");
    assert_eq!(rig.leases_for(&owner).len(), 1, "no second lease is opened");
    let kept = rig.live_lease_for(&owner).expect("the lease it had");
    assert_eq!(kept.lease_id, first.lease_id);
    assert_eq!(
        kept.expires_at_ms, first.expires_at_ms,
        "nothing was extended"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning, "{}", shown.detail());
    assert!(
        shown.detail().contains("authorisation lets one lease hold"),
        "{}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("512 KiB")),
        "{:?}",
        shown.remedy()
    );
}

/// KR-REQ-17.51: the service keeps its record of a lease until it is revoked, and turns a pair
/// whose lease sits on a retired relay away for as long as the record stands. A lease that has run
/// out is therefore ended before the pair is asked for again, and the pair is given another.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_runs_out_on_a_retired_relay_is_ended_and_the_pair_is_given_another() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().retire_relay_of(&first.lease_id);
    let before = rig.requests(ISSUE);

    // The host did not refill, and the lease ran out: it slept, or had no network.
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 1));
    rig.pass().await;

    let renewed = rig.live_lease_for(&owner).expect("a new lease");
    assert_ne!(renewed.lease_id, first.lease_id);
    let sent = rig.bodies(ISSUE);
    assert_eq!(
        sent.len(),
        before + 1,
        "a lease the host knows has run out is ended and not refilled"
    );
    assert!(
        sent[before]["lease_id"].is_null(),
        "and the pair is asked for afresh"
    );
    let old = rig
        .leases_for(&owner)
        .into_iter()
        .find(|lease| lease.lease_id == first.lease_id)
        .expect("the lease that ran out");
    assert!(!old.live);
    assert_eq!(old.ended_for, Some("finished"));
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51: a row that names no lease is kept for as long as a lease asked for by its latest
/// request can live, so the time it carries is the time of the latest request and not of the first.
/// Otherwise a pair the service refuses for twenty minutes, and then issues a lease whose answer is
/// lost, would have its row forgotten at once when the device is unpaired, and the lease left
/// carrying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_asked_again_after_a_long_failure_is_written_with_the_time_of_the_new_one() {
    let rig = Rig::start().await;
    for nth in 1..=4 {
        rig.served.web().fail(
            ISSUE,
            nth,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: None,
            },
        );
    }
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None)
    })
    .await;
    rig.pass().await;
    let first = rig.row_written_at(&record).expect("a row");

    // Two minutes later the service still refuses, and the host asks again.
    let asked = rig.requests(ISSUE);
    rig.time_passes(Duration::from_secs(120));
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until("the host asked again", || rig.requests(ISSUE) > asked)
        .await;
    rig.pass().await;

    let second = rig.row_written_at(&record).expect("a row");
    assert!(
        second >= first + 100_000,
        "the row says when the latest request was written: {first} then {second}"
    );
}

impl Rig {
    /// A request for a device's lease is answered by the service and the answer is lost, and the
    /// daemon is started again with a document that names another authorisation: of the same
    /// account when `same_account` is true. The service finds a pair's lease within the account,
    /// and refuses another authorisation of that account for as long as the lease stands.
    async fn payer_changed_over_a_lost_answer(same_account: bool) {
        let rig = Rig::start().await;
        rig.served.web().fail(ISSUE, 1, Moment::After);
        let (_phone, record) = rig.pairs().await;
        rig.until("the host has a row for the pair and no lease in it", || {
            rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
        })
        .await;
        let first = rig
            .live_lease_for(&record)
            .expect("the lease the first request issued");
        let other = if same_account {
            rig.served.web().authorise_relay_payer_in(
                &rig.payer.account_id,
                &rig.host_key,
                8 * 1024 * 1024,
            )
        } else {
            rig.served
                .web()
                .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024)
        };

        let rig = rig.restarted_naming(&other).await;
        rig.until("the pair holds a lease under the new payer", || {
            rig.live_lease_for(&record).is_some_and(|lease| {
                lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
            })
        })
        .await;
        let ended = rig
            .leases_for(&record)
            .into_iter()
            .find(|lease| lease.lease_id == first.lease_id)
            .expect("the lease the first request issued");
        assert!(!ended.live);
        assert_eq!(
            ended.ended_for,
            Some("payer_withdrew"),
            "it was found under the payer it was asked for and ended"
        );
        assert_eq!(rig.endings_owed(), 0);
    }
}

/// KR-REQ-17.51: a request whose answer was lost may have issued a lease under the payer it was
/// asked under. A host started with another payer asks again under the first payer, which finds the
/// lease and ends it, and then asks under the new payer: the pair is given a lease under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payer_changed_over_a_request_whose_answer_was_lost_ends_what_the_first_issued() {
    Rig::payer_changed_over_a_lost_answer(false).await;
}

/// KR-REQ-17.51: the same when the new payer is another authorisation of the same account, which
/// the service refuses for a pair whose lease was issued under the first for as long as it stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_authorisation_of_the_account_is_given_the_pair_once_the_first_lease_is_ended() {
    Rig::payer_changed_over_a_lost_answer(true).await;
}

/// KR-REQ-17.51: the authorisation a request whose answer was lost was made under is withdrawn
/// before the host is started with another. The service turns the old payer back, no lease can be
/// alive under it, and the host lets the row go instead of holding every ask for the standing wait:
/// the pair is given a lease under the new payer at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_payer_over_a_request_whose_answer_was_lost_does_not_hold_the_pair() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;
    rig.served
        .web()
        .withdraw_relay_authorisation(&rig.payer.authorisation_id);
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    let rig = rig.restarted_naming(&other).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.live_lease_for(&record).is_some_and(|lease| {
            lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
        })
    })
    .await;
    assert!(rig.holds(&record));
    assert_eq!(rig.endings_owed(), 0);
}

impl Rig {
    /// A new device pairs, its first request for a lease is answered by the service and the answer
    /// is lost, and the host's record holds a row for the pair that names no lease.
    async fn pairs_and_loses_the_answer(&self) -> (Device, DeviceRecord, RelayLeaseView) {
        self.served.web().fail(ISSUE, 1, Moment::After);
        let (device, record) = self.pairs().await;
        self.until("the host has a row for the pair and no lease in it", || {
            self.lease_in_the_record(&record) == Some(None)
                && self.live_lease_for(&record).is_some()
        })
        .await;
        let issued = self
            .live_lease_for(&record)
            .expect("the lease the first request issued");
        (device, record, issued)
    }

    /// Whether the service holds a live lease for the device's pair that was issued under the
    /// authorisation `payer` names, whatever other leases the pair holds.
    fn holds_a_live_lease_under(&self, device: &DeviceRecord, payer: &RelayPayerRecord) -> bool {
        self.leases_for(device).iter().any(|lease| {
            lease.live && lease.authorisation_id.as_deref() == Some(payer.authorisation_id.as_str())
        })
    }

    /// The payer a row is kept for, in the form the record writes it: `None` when the record has no
    /// row for the device.
    fn row_payer(&self, device: &DeviceRecord) -> Option<Option<String>> {
        self.connection()
            .query_row(
                "SELECT payer FROM relay_leases WHERE destination = ?1",
                [device.endpoint_id.as_bytes().as_slice()],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
    }
}

/// The host's record of leases, opened for writing in a daemon's tree.
fn the_record_in(tree: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
    let state = tree
        .environment()
        .registry_database()
        .parent()
        .expect("the state directory")
        .to_path_buf();
    rusqlite::Connection::open(state.join("relay-leases.sqlite3")).expect("the host's record")
}

/// The form in which the record writes the payer a lease was asked for.
fn written_payer(payer: &RelayPayerRecord) -> String {
    format!("{}/{}", payer.account_id, payer.authorisation_id)
}

/// KR-REQ-17.51: the service refuses another authorisation of an account for a pair whose lease
/// stands, also when the lease has run out and the service has not yet ended it. A daemon that was
/// stopped for longer than a lease lives, after a request whose answer was lost, finds the row
/// older than the longest a lease can live. A device that is still paired is asked once more under
/// the payer the row was kept for, which ends what the service holds, and then under the new payer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_that_aged_before_the_payer_changed_is_asked_under_its_own_payer_once_more() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    let other = rig.served.web().authorise_relay_payer_in(
        &rig.payer.account_id,
        &rig.host_key,
        8 * 1024 * 1024,
    );
    // The lease runs out at the service while the daemon is stopped, and the service keeps it
    // installed until something ends it.
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted_naming(&other).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.live_lease_for(&record).is_some_and(|lease| {
            lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
        })
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .filter(
                |lease| lease.authorisation_id.as_deref() != Some(other.authorisation_id.as_str())
            )
            .all(|lease| !lease.live),
        "no lease of the old payer carries the pair"
    );
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.lease_id != first.lease_id
                && lease.ended_for == Some("payer_withdrew")),
        "the last ask under the old payer found a lease and the host ended it"
    );
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51: the allowance is spent, the service answers the ask of an aged row as capacity,
/// and it answers a lease that ran out before it looks at the allowance, so nothing is left to
/// learn: the row is let go with the answer, also where the new payer is another authorisation of
/// the same account, and the pair is asked for under the new payer once the allowance is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_that_aged_is_let_go_by_the_answer_that_the_allowance_is_spent() {
    let rig = Rig::start().await;
    let (_phone, record, _first) = rig.pairs_and_loses_the_answer().await;
    let other = rig.served.web().authorise_relay_payer_in(
        &rig.payer.account_id,
        &rig.host_key,
        8 * 1024 * 1024,
    );
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
    rig.served.web().exhaust_relay_allowance(true);

    let rig = rig.restarted_naming(&other).await;
    rig.until("the keeper has been told the allowance is spent", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    rig.pass().await;
    assert_eq!(
        rig.lease_in_the_record(&record),
        None,
        "the row was let go with the answer"
    );

    rig.served.web().exhaust_relay_allowance(false);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: a request the service refused for good leaves no time on its row, so a payer
/// that is changed afterwards is not held behind it. The first authorisation bounds one lease at
/// less than the block a new lease holds, so the service refuses every first request; the owner
/// gives another and names it, and the pair is given a lease under it in the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_first_request_does_not_hold_the_pair_when_the_payer_changes() {
    let rig = Rig::start_bounded_naming(true, BLOCK_BYTES / 2).await;
    let owner = rig.owner_device();
    rig.until("the service has turned the owner's device away", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    assert_eq!(rig.lease_in_the_record(&owner), Some(None));
    assert_eq!(
        rig.row_written_at(&owner),
        Some(0),
        "a request the service refused is not one whose answer is missing"
    );
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    let rig = rig.restarted_naming(&other).await;
    rig.until(
        "the owner's device holds a lease under the new payer",
        || {
            rig.live_lease_for(&owner).is_some_and(|lease| {
                lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
            })
        },
    )
    .await;
}

/// KR-REQ-17.51: where the new document names no account, a difference of accounts cannot be read,
/// and a row the service could not answer for is kept: nothing is dropped on the strength of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_stays_when_the_new_document_names_no_account() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    let old = written_payer(&rig.payer);
    rig.served.web().retire_relay_of(&first.lease_id);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
    let origin = rig.served.origin().to_owned();

    let rig = rig
        .restarted_after(|tree| {
            net_support::write_relay_document(tree, Some(origin.as_str()), None);
        })
        .await;
    rig.until(
        "the keeper has been told the service could not issue a lease",
        || rig.timer.asked_for().contains(&STANDING_RETRY),
    )
    .await;
    rig.pass().await;
    assert_eq!(rig.row_payer(&record), Some(Some(old)));
    assert_eq!(rig.lease_in_the_record(&record), Some(None));
}

/// KR-REQ-17.51: the bound of an authorisation is below the block a lease holds, so the service
/// refuses every request under it as invalid, and the first request of a new device never reaches
/// the service. The row is older than a lease lives when the owner names another account's
/// authorisation: that account's payer is not held behind the old one's refusal, and the pair is
/// given a lease under it in the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_under_a_bound_too_small_for_a_block_does_not_hold_another_accounts_payer() {
    let rig = Rig::start_bounded_naming(true, BLOCK_BYTES / 2).await;
    rig.until("the service has turned the owner's device away", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    // The standing wait holds the asks, so the new device's first request is the one that fails.
    let (_phone, record) = rig.pairs().await;
    rig.served.web().fail_matching(
        ISSUE,
        serde_json::json!({ "destination_endpoint_key": record.endpoint_id }),
        1,
        Moment::Before,
    );
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until(
        "the host has a row for the pair and a request it never saw answered",
        || rig.row_written_at(&record).is_some_and(|at| at > 0),
    )
    .await;
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted_naming(&other).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: where the new payer is another authorisation of the same account, the row under a
/// bound too small for a block stays, because the service answers invalid in the same words for a
/// lease in its grace window whose hold passes the bound, and the keeper cannot tell the two
/// apart. The owner clears the row by withdrawing the authorisation replaced: the next ask under
/// it is refused as forbidden, the row goes, and the pair is given a lease under the new payer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_of_the_same_account_stays_until_the_authorisation_it_replaced_is_withdrawn() {
    let rig = Rig::start_bounded_naming(true, BLOCK_BYTES / 2).await;
    rig.until("the service has turned the owner's device away", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    let (_phone, record) = rig.pairs().await;
    rig.served.web().fail_matching(
        ISSUE,
        serde_json::json!({ "destination_endpoint_key": record.endpoint_id }),
        1,
        Moment::Before,
    );
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until(
        "the host has a row for the pair and a request it never saw answered",
        || rig.row_written_at(&record).is_some_and(|at| at > 0),
    )
    .await;
    let old = rig.payer.clone();
    let other =
        rig.served
            .web()
            .authorise_relay_payer_in(&old.account_id, &rig.host_key, 8 * 1024 * 1024);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted_naming(&other).await;
    rig.until("the keeper has been turned back", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    rig.pass().await;
    assert_eq!(rig.row_payer(&record), Some(Some(written_payer(&old))));
    assert!(
        !rig.holds_a_live_lease_under(&record, &other),
        "nothing is asked for the pair under the new payer behind the old one's row"
    );

    rig.served
        .web()
        .withdraw_relay_authorisation(&old.authorisation_id);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: an authorisation that lapsed is let go like one that was withdrawn, and the lease
/// the host never heard of is left to run out: the service ends the leases of a withdrawn
/// authorisation and not those of one that lapses, and the host cannot end a lease it was never
/// told of. The pair is asked for under the new payer, another account's, at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_authorisation_is_let_go_and_its_lease_runs_out_by_itself() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    rig.served
        .web()
        .lapse_relay_authorisation(&rig.payer.authorisation_id);
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    let rig = rig.restarted_naming(&other).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.lease_id == first.lease_id && lease.live),
        "the lease the host never heard of stands until it runs out"
    );
    assert_eq!(rig.row_payer(&record), Some(Some(written_payer(&other))));
}

impl Rig {
    /// A new device's first request is answered and the answer is lost, the relay carrying the
    /// lease is retired, the daemon is stopped for longer than a lease lives, and it is started
    /// again naming a payer: of the same account as the first when `same_account` is true.
    async fn aged_row_of_a_lease_on_a_retired_relay(
        same_account: bool,
    ) -> (
        Self,
        DeviceRecord,
        RelayLeaseView,
        RelayPayerRecord,
        RelayPayerRecord,
    ) {
        let rig = Rig::start().await;
        let old = rig.payer.clone();
        let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
        rig.served.web().retire_relay_of(&first.lease_id);
        let other = if same_account {
            rig.served.web().authorise_relay_payer_in(
                &rig.payer.account_id,
                &rig.host_key,
                8 * 1024 * 1024,
            )
        } else {
            rig.served
                .web()
                .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024)
        };
        rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
        let rig = rig.restarted_naming(&other).await;
        (rig, record, first, old, other)
    }
}

/// KR-REQ-17.51: the service answers a lease whose relay it can no longer bill through that it
/// cannot issue one, before it looks at the lease's deadline, so the last ask of a row that aged
/// does not fence the lease that ran out. Where the new payer is another account that lease is no
/// obstacle and the row is let go at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_the_last_ask_could_not_fence_does_not_hold_another_accounts_payer() {
    let (rig, record, _first, _old, other) =
        Rig::aged_row_of_a_lease_on_a_retired_relay(false).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: where the new payer is another authorisation of the same account, the lease that
/// the last ask could not fence stands in its way, so the row stays: the pair is not given up, and
/// when the service has ended the lease the next ask finds the pair clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_the_last_ask_could_not_fence_keeps_its_row_for_the_same_accounts_payer() {
    let (rig, record, first, old, other) = Rig::aged_row_of_a_lease_on_a_retired_relay(true).await;
    let old = written_payer(&old);
    rig.until(
        "the keeper has been told the service could not issue a lease",
        || rig.timer.asked_for().contains(&STANDING_RETRY),
    )
    .await;
    rig.pass().await;
    assert_eq!(rig.row_payer(&record), Some(Some(old)));
    assert_eq!(rig.lease_in_the_record(&record), Some(None));
    let under_new = |lease: &RelayLeaseView| {
        lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
    };
    assert!(
        !rig.leases_for(&record).iter().any(under_new),
        "nothing was asked for the pair under the new payer"
    );

    rig.served.web().end_relay_lease(&first.lease_id);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.live_lease_for(&record).is_some_and(|lease| {
            lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
        }) && rig.endings_owed() == 0
    })
    .await;
}

/// KR-REQ-17.51: the old payer is asked for the lease a row may stand for, and only a refusal that
/// is about its authorisation proves there is none. The service answers a credential it did not
/// admit with the same protocol code and action as an authorisation it does not hold, and the first
/// says nothing of the pair: the row stays, the owner is told, nothing is asked under the new payer
/// for the pair, and the next ask after the standing wait finds the lease and ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_that_is_not_about_the_old_authorisation_keeps_the_row_for_the_next_ask() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    let old = written_payer(&rig.payer);
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);
    let asked = rig.requests(ISSUE);
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 401,
            code: "UNAUTHENTICATED",
            retry_after_seconds: None,
        },
    );

    let rig = rig.restarted_naming(&other).await;
    rig.until("the ask under the old payer was turned back", || {
        rig.requests(ISSUE) > asked
    })
    .await;
    rig.pass().await;
    assert_eq!(
        rig.row_payer(&record),
        Some(Some(old)),
        "the row is kept for the payer it was asked under"
    );
    assert_eq!(rig.lease_in_the_record(&record), Some(None));
    assert_eq!(
        rig.leases_for(&record).len(),
        1,
        "nothing was asked for the pair under the new payer"
    );
    assert!(rig.live_lease_for(&record).is_some());
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);

    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until(
        "the old lease is ended and the pair holds one under the new payer",
        || {
            rig.live_lease_for(&record).is_some_and(|lease| {
                lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
            }) && rig.endings_owed() == 0
        },
    )
    .await;
    let ended = rig
        .leases_for(&record)
        .into_iter()
        .find(|lease| lease.lease_id == first.lease_id)
        .expect("the lease the first request issued");
    assert_eq!(ended.ended_for, Some("payer_withdrew"));
}

/// KR-REQ-17.51: a lease ended because the payer changed and the request that may have opened its
/// replacement are written in one step. A write the record refuses leaves the lease in its row and
/// owes no ending, so the pass that follows has the whole of it to do again: a stop between the two
/// would owe the ending and forget the request, and the replacement the service may hold could
/// never be found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_for_a_changed_payer_and_the_request_that_may_have_replaced_it_go_together() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let carried = rig.live_lease_for(&owner).expect("a lease");
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&owner, Some(Moment::After))
        .await;
    assert!(
        rig.leases_for(&owner)
            .iter()
            .any(|lease| lease.live && lease.lease_id != carried.lease_id),
        "the service opened a replacement and the host was not told"
    );
    let origin = rig.served.origin().to_owned();
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    // The record refuses a row that names no lease, as a disk with no room for it would.
    let rig = rig
        .restarted_after(|tree| {
            net_support::write_relay_document(
                tree,
                Some(origin.as_str()),
                Some((&other.account_id, &other.authorisation_id)),
            );
            the_record_in(tree)
                .execute_batch(
                    "CREATE TRIGGER no_row_without_a_lease BEFORE INSERT ON relay_leases
                     WHEN NEW.lease_id IS NULL
                     BEGIN SELECT RAISE(ABORT, 'no room'); END;",
                )
                .expect("the trigger");
        })
        .await;
    rig.pass().await;
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(carried.lease_id.clone())),
        "the row still names the lease it named"
    );
    assert_eq!(
        rig.endings_owed(),
        0,
        "and nothing is owed that the row would lose"
    );

    the_record_in(rig.host.tree())
        .execute_batch("DROP TRIGGER no_row_without_a_lease;")
        .expect("the record");
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until(
        "no lease of the old payer carries the pair and the new payer's does",
        || {
            rig.live_lease_for(&owner).is_some_and(|lease| {
                lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
            }) && rig.endings_owed() == 0
        },
    )
    .await;
    assert!(
        rig.leases_for(&owner)
            .iter()
            .filter(
                |lease| lease.authorisation_id.as_deref() != Some(other.authorisation_id.as_str())
            )
            .all(|lease| !lease.live),
        "the replacement was found and ended"
    );
}

/// KR-REQ-17.51: a lease named in a row whose refill was never answered is ended for a changed
/// payer, and the request that may have revised it is asked about under the old payer in the same
/// pass. The old authorisation is withdrawn, the service turns that ask back as forbidden, and the
/// pair is asked for under the new payer at once: the ordinary ask for the pair does not meet the
/// old payer's refusal and hold itself for the standing wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_payer_over_a_refill_whose_answer_was_lost_does_not_hold_the_pair() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let held = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().fail(ISSUE, 1, Moment::After);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(held.lease_id.clone())),
        "the row names the lease the refill was for"
    );
    assert!(
        rig.row_written_at(&owner).is_some_and(|at| at > 0),
        "and says a request of the pair has not been answered"
    );
    rig.served
        .web()
        .withdraw_relay_authorisation(&rig.payer.authorisation_id);
    let other = rig
        .served
        .web()
        .authorise_relay_payer(&rig.host_key, 8 * 1024 * 1024);

    let rig = rig.restarted_naming(&other).await;
    rig.until("the pair holds a lease under the new payer", || {
        rig.live_lease_for(&owner).is_some_and(|lease| {
            lease.authorisation_id.as_deref() == Some(other.authorisation_id.as_str())
        })
    })
    .await;
    assert_eq!(rig.endings_owed(), 0);
    assert_eq!(
        rig.row_payer(&owner),
        Some(Some(written_payer(&other))),
        "the row is the new payer's"
    );
}

/// KR-REQ-17.51: an ending the service turns back for a reason only the owner can change is not
/// sent again by the next signal. The device directory raises one for each pairing and revocation,
/// and the standing wait applies to what is owed as it does to what is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_the_service_turned_back_is_not_sent_again_by_the_next_signal() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.served.web().fail(
        REVOKE,
        1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: None,
        },
    );
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the ending is turned back", || rig.requests(REVOKE) == 1)
        .await;
    rig.pass().await;

    // Another pairing raises the signal, and the pass it wakes sends nothing it was turned back on.
    let (_second, _other) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 1, "held for the standing wait");
    assert_eq!(rig.endings_owed(), 1);

    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 2);
    assert_eq!(rig.endings_owed(), 0);
    assert!(rig.live_lease_for(&record).is_none());
}

/// KR-REQ-17.51: the ask that learns the lease of a device that is no longer paired is held back by
/// the standing wait too, when the service turns it back for a reason only the owner can change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovery_ask_the_service_turned_back_is_not_repeated_by_the_next_signal() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;
    rig.pass().await;
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: None,
        },
    );
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until("the recovery ask is turned back", || {
        rig.requests(ISSUE) == 3
    })
    .await;
    rig.pass().await;
    let asked = rig.requests(ISSUE);

    let (_second, _other) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), asked, "held for the standing wait");

    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the service has ended the lease", || {
        rig.live_lease_for(&record).is_none() && rig.endings_owed() == 0
    })
    .await;
}

/// The doctor says so when no lease service is selected, and a host that selects none sends
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_selects_no_lease_service_says_so() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    assert!(host.controller().relay_keeper().is_none());
    let mut local = host.client().await;
    let doctor: HostDoctorResult = net_support::pairing::read(&mut local, Method::HostDoctor, &())
        .await
        .expect("the host's diagnostics");
    let check = doctor
        .checks
        .into_iter()
        .find(|check| check.id() == "relay-leases")
        .expect("the check is there");
    assert_eq!(check.status, DoctorStatus::NotApplicable);
}

impl Rig {
    /// A device's lease after it has carried traffic through three refills, so that its ceiling is
    /// far above a block.
    async fn lease_that_carried_traffic(&self, device: &DeviceRecord) -> RelayLeaseView {
        for _ in 0..3 {
            let lease = self.live_lease_for(device).expect("a lease");
            self.served
                .web()
                .relay_counts(&lease.lease_id, u64::MAX / 4);
            self.time_passes(Duration::from_secs(301));
            self.pass().await;
        }
        let carried = self.live_lease_for(device).expect("the lease");
        assert!(
            carried.byte_ceiling > 2 * BLOCK_BYTES,
            "the pair has carried traffic: {}",
            carried.byte_ceiling
        );
        carried
    }

    /// The refill of a device's lease falls due while the service cannot be reached; by the time
    /// the host asks again its clock says the lease has a little life left, and the service's,
    /// which runs a few minutes ahead, says it has none. `then` is what happens to the second
    /// refill of that lease, the one that reaches the service. Both are met by the pair and the
    /// lease the request names, whatever else the daemon sends in between.
    async fn refill_reaching_a_service_that_finds_the_lease_expired(
        &self,
        device: &DeviceRecord,
        then: Option<Moment>,
    ) {
        let lease = self.live_lease_for(device).expect("a lease").lease_id;
        let refill = serde_json::json!({
            "destination_endpoint_key": device.endpoint_id,
            "lease_id": lease,
        });
        self.served
            .web()
            .fail_matching(ISSUE, refill.clone(), 1, SERVICE_DOWN);
        if let Some(then) = then {
            self.served.web().fail_matching(ISSUE, refill, 2, then);
        }
        self.time_passes(Duration::from_secs(301));
        self.pass().await;
        self.served
            .web()
            .advance_relay_clock(Duration::from_secs(290));
        self.time_passes(Duration::from_secs(499));
        self.timer.advance(Duration::from_secs(60));
        self.pass().await;
    }

    /// The live leases of a device and the ones the host ended as finished.
    fn live_and_finished(&self, device: &DeviceRecord) -> (Vec<RelayLeaseView>, usize) {
        let leases = self.leases_for(device);
        let finished = leases
            .iter()
            .filter(|lease| lease.ended_for == Some("finished"))
            .count();
        (
            leases.into_iter().filter(|lease| lease.live).collect(),
            finished,
        )
    }
}

/// KR-REQ-17.51: a refill the service finds past its deadline is answered with a new lease, and the
/// service gives that lease the cumulative ceiling the refill asked for, which for a pair that has
/// carried traffic is far more than a new reservation needs. A host whose clock is behind the
/// service's, and whose refill a failure held back, sends such a refill believing the lease has
/// time left. The host ends that lease and asks for the pair afresh, so no pair holds more of the
/// account's aggregate than one block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refill_the_service_finds_expired_does_not_leave_the_old_ceiling_held() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let carried = rig.lease_that_carried_traffic(&owner).await;
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&owner, None)
        .await;

    let (live, finished) = rig.live_and_finished(&owner);
    assert_eq!(live.len(), 1, "one lease carries the pair");
    assert_ne!(live[0].lease_id, carried.lease_id);
    assert_eq!(
        live[0].byte_ceiling, BLOCK_BYTES,
        "and it holds a new reservation's block, not the old ceiling"
    );
    assert_eq!(
        finished, 1,
        "the lease the service opened at the old ceiling was ended"
    );
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(live[0].lease_id.clone()))
    );
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51: the lease the service opens for a refill it finds past its deadline is found again
/// when the answer to that refill is lost: the retry names a lease the service no longer carries,
/// and the request that asks for the pair afresh is answered with the replacement. The host ends it
/// there too, because it holds far more than a new reservation needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_whose_answer_was_lost_is_found_and_ended_too() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let carried = rig.lease_that_carried_traffic(&owner).await;
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&owner, Some(Moment::After))
        .await;
    assert!(
        rig.leases_for(&owner)
            .iter()
            .any(|lease| lease.live && lease.lease_id != carried.lease_id),
        "the service opened the replacement and the host was not told"
    );
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;

    let (live, finished) = rig.live_and_finished(&owner);
    assert_eq!(live.len(), 1, "one lease carries the pair");
    assert_eq!(live[0].byte_ceiling, BLOCK_BYTES);
    assert_eq!(finished, 1, "the replacement was ended");
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(live[0].lease_id.clone()))
    );
}

/// KR-REQ-17.51: a replacement whose opening the host was not told of is ended also when its device
/// is unpaired before the host asks again. The row of the lease the host knew names the request
/// whose answer was lost, so the lease it ends is the old one and the pair is asked for once more,
/// which finds the replacement and ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_whose_answer_was_lost_is_ended_when_its_device_is_unpaired() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    let carried = rig.lease_that_carried_traffic(&record).await;
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&record, Some(Moment::After))
        .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.live && lease.lease_id != carried.lease_id),
        "the service opened the replacement"
    );
    assert_eq!(
        rig.lease_in_the_record(&record),
        Some(Some(carried.lease_id.clone())),
        "and the host still records the lease it knew, not the replacement"
    );
    assert!(
        rig.row_written_at(&record).is_some_and(|at| at > 0),
        "with the time of the request whose answer it has not seen"
    );

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until("no lease carries the pair and nothing is owed", || {
        rig.live_lease_for(&record).is_none()
            && rig.endings_owed() == 0
            && rig.lease_in_the_record(&record).is_none()
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .all(|lease| lease.ended_for.is_some()),
        "every lease the pair held was ended"
    );
}

/// KR-REQ-17.51: when the service does not take the revocation of that replacement, because the
/// lease kept changing under it, the replacement is the lease the pair holds: the host keeps it,
/// owes no ending for it, and asks for nothing else, so that its record and the service agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_the_service_will_not_end_is_kept_and_not_owed_an_ending() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let carried = rig.lease_that_carried_traffic(&owner).await;

    rig.served.web().fail(REVOKE, 1, NOT_CARRIED);
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&owner, None)
        .await;

    assert_eq!(rig.requests(REVOKE), 1);
    let (live, _) = rig.live_and_finished(&owner);
    assert_eq!(live.len(), 1);
    assert_ne!(live[0].lease_id, carried.lease_id, "it is the replacement");
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(live[0].lease_id.clone())),
        "the record names the lease the service carries"
    );
    assert_eq!(rig.endings_owed(), 0, "and owes no ending for it");
}

/// KR-REQ-17.51: what the service answered about the revocation of a replacement the host kept is
/// forgotten with the ending: a lease that was kept, refilled for longer than a lease lives and
/// then unpaired is a new question, and two further answers that it is not carried do not prove it
/// absent while the service still carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_replacement_is_not_believed_absent_on_the_answers_given_before_it_was_kept() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.lease_that_carried_traffic(&record).await;
    rig.served.web().fail(REVOKE, 1, NOT_CARRIED);
    rig.refill_reaching_a_service_that_finds_the_lease_expired(&record, None)
        .await;
    let kept = rig.live_lease_for(&record).expect("the replacement");

    // It is refilled for longer than the longest a lease lives.
    for _ in 0..4 {
        rig.time_passes(Duration::from_secs(301));
        rig.timer.advance(Duration::from_secs(301));
        rig.pass().await;
    }
    assert_eq!(
        rig.live_lease_for(&record).expect("still carried").lease_id,
        kept.lease_id
    );

    rig.served.web().fail(REVOKE, 1, NOT_CARRIED);
    rig.served.web().fail(REVOKE, 2, NOT_CARRIED);
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the first answer", || rig.requests(REVOKE) == 2)
        .await;
    rig.pass().await;
    rig.time_passes(Duration::from_secs(60));
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 3);
    assert_eq!(rig.endings_owed(), 1, "two answers do not prove it absent");
    assert!(rig.live_lease_for(&record).is_some());
}

/// KR-REQ-17.51: a lease the host raised is not a replacement, whichever request returns it. A
/// refill and the request for the ceiling the lease holds are both answered that the lease changed
/// while the request was handled, the pair is asked for afresh, and the service answers with the
/// lease it still carries: the host keeps it and ends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_was_raised_is_kept_when_the_ask_for_the_pair_returns_it() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let carried = rig.lease_that_carried_traffic(&owner).await;

    rig.served.web().fail(ISSUE, 1, NOT_CARRIED);
    rig.served.web().fail(ISSUE, 2, NOT_CARRIED);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;

    assert_eq!(rig.requests(REVOKE), 0, "nothing is ended");
    let kept = rig.live_lease_for(&owner).expect("the lease");
    assert_eq!(kept.lease_id, carried.lease_id);
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(carried.lease_id)),
        "and the record names it again"
    );
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51: an answer only the owner or the calendar can change holds the asks for the
/// standing interval, also when a request to another pair in the same pass got no answer. The pair
/// that was turned back is not asked again at the pace of the other one's backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_met_beside_a_request_that_failed_is_not_asked_again_at_the_backoff() {
    let rig = Rig::start().await;
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    let (_first_phone, first) = rig.pairs().await;
    rig.until("the first pair was asked and not answered", || {
        rig.requests(ISSUE) == 2
    })
    .await;
    rig.pass().await;
    let (_second_phone, second) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), 2, "the backoff holds the second pair");

    // The next pass meets a refusal and then a failure.
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: None,
        },
    );
    rig.served.web().fail(
        ISSUE,
        2,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), 4, "a refusal and a failure");
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("turned this host's request back")
            && !shown.detail().contains("did not answer"),
        "the owner is told of the refusal and not only of the failure: {}",
        shown.detail()
    );

    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        4,
        "the refusal holds the asks for the standing interval, which a backoff does not outlast"
    );
    assert!(
        rig.check()
            .await
            .detail()
            .contains("turned this host's request back"),
        "and is still shown once the failure has passed"
    );

    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert!(rig.holds(&first) && rig.holds(&second));
}

/// KR-REQ-17.40: the allowance warning an answer carries is shown to the owner, and is gone when an
/// answer carries none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allowance_warning_is_shown_until_an_answer_carries_none() {
    let rig = Rig::start().await;
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
    rig.served.web().warn_relay_allowance(Some(80));
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning, "{}", shown.detail());
    assert!(shown.detail().contains("80 percent"), "{}", shown.detail());

    rig.served.web().warn_relay_allowance(None);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.52: the grace a grant carries, for connections already running when the allowance ran
/// out, is shown to the owner as what is left of it, and stops being shown when it has ended or the
/// next grant carries none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_grace_a_grant_carries_is_shown_until_it_ends() {
    let rig = Rig::start().await;
    rig.served.web().enter_relay_grace(true);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("104857600 bytes"),
        "{}",
        shown.detail()
    );

    // The window ends by the host's clock, as the answer said.
    rig.wall.advance(Duration::from_secs(601));
    assert!(
        !rig.check().await.detail().contains("104857600 bytes"),
        "a grace that has ended is not shown"
    );

    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    rig.served.web().enter_relay_grace(false);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;
    assert!(!rig.check().await.detail().contains("104857600 bytes"));
}

/// KR-REQ-17.35: a credential the service will not admit is a refusal about this host's request,
/// and the owner is told the clock and the service origin as well as the payer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_credential_the_service_will_not_admit_names_the_clock_and_the_origin() {
    let rig = Rig::start().await;
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 401,
            code: "UNAUTHENTICATED",
            retry_after_seconds: None,
        },
    );
    let (_phone, _record) = rig.pairs().await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    let remedy = shown.remedy().expect("a remedy");
    assert!(
        remedy.contains("clock") && remedy.contains("relay.origin"),
        "{remedy}"
    );
}

/// KR-REQ-17.35: what the host holds belongs to the key that asked for it. A host that signs with
/// another key sends no lease identifier of the first key's and asks for nothing to be ended: the
/// service would answer that the lease was issued to another caller. It asks for each pair afresh,
/// under the authorisation its account gave the new key, and the leases the first key held run out
/// by themselves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_identifier_is_never_sent_under_another_host_key() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    let revoked = rig.requests(REVOKE);

    let Rig {
        host,
        served,
        owner: owner_keys,
        wall,
        ..
    } = rig;
    let stopped = host.shut_down().await;
    let host_key = net_support::replace_host_authorisation(stopped.tree());
    let payer = served
        .web()
        .authorise_relay_payer(&host_key, 8 * 1024 * 1024);
    net_support::write_relay_document(
        stopped.tree(),
        Some(served.origin()),
        Some((&payer.account_id, &payer.authorisation_id)),
    );
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    let rig = Rig {
        host,
        served,
        timer,
        wall,
        owner: owner_keys,
        host_key,
        payer,
    };
    rig.until("the second key holds a lease for the pair", || {
        rig.leases_for(&owner)
            .iter()
            .any(|lease| lease.live && lease.lease_id != first.lease_id)
    })
    .await;

    for body in &rig.bodies(ISSUE)[1..] {
        assert!(
            body["lease_id"].is_null(),
            "no identifier of the first key's is sent"
        );
    }
    assert_eq!(rig.requests(REVOKE), revoked, "and nothing of it is ended");
    assert!(
        rig.leases_for(&owner)
            .iter()
            .any(|lease| lease.lease_id == first.lease_id && lease.live),
        "the first key's lease is left to run out"
    );
}

/// KR-REQ-17.51: a document this host cannot use leaves the record as it is, so a document that is
/// broken for a day does not cost the host an ending it owes. The ending is sent when the document
/// can be read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_that_cannot_be_used_does_not_cost_an_ending_the_host_owes() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.served.web().fail(REVOKE, 1, Moment::Before);
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the ending is owed", || {
        rig.endings_owed() == 1 && rig.requests(REVOKE) == 1
    })
    .await;

    let rig = rig
        .restarted_after(net_support::write_unusable_document)
        .await;
    assert!(
        rig.host.controller().relay_keeper().is_none(),
        "a document that cannot be used selects no service"
    );
    assert_eq!(rig.endings_owed(), 1, "the ending is still owed");

    let origin = rig.served.origin().to_owned();
    let (account, authorisation) = (
        rig.payer.account_id.clone(),
        rig.payer.authorisation_id.clone(),
    );
    let rig = rig
        .restarted_after(|tree| {
            net_support::write_relay_document(
                tree,
                Some(&origin),
                Some((&account, &authorisation)),
            );
        })
        .await;
    rig.until("the service has ended the lease", || {
        rig.live_lease_for(&record).is_none() && rig.endings_owed() == 0
    })
    .await;
}

/// A record written by a build that reads a newer schema is refused before anything is written to
/// it, so that build still finds it as it left it.
#[test]
fn a_record_of_a_newer_schema_is_refused_before_anything_is_written() {
    use kr_controller::relay_leases::record::{Kept, Record};

    let directory = kr_ipc::testing::PrivateTempDir::create();
    let path = directory.path().join("relay-leases.sqlite3");
    {
        let connection = rusqlite::Connection::open(&path).expect("a database");
        connection
            .execute_batch(
                "CREATE TABLE relay_lease_schema (version INTEGER NOT NULL);
                 INSERT INTO relay_lease_schema (version) VALUES (99);",
            )
            .expect("a newer schema");
    }
    assert!(Record::open(directory.path(), Kept::Nothing).is_err());

    let connection = rusqlite::Connection::open(&path).expect("the database");
    let tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .expect("the tables");
    let version: i64 = connection
        .query_row("SELECT version FROM relay_lease_schema", [], |row| {
            row.get(0)
        })
        .expect("the version");
    assert_eq!((tables, version), (1, 99), "nothing was written");
}

/// KR-REQ-17.51: a row that names no lease is kept while a lease its request may have issued could
/// be alive, and forgotten once the longest a lease lives has passed, because the lease, if there
/// was one, has run out by itself and there is nothing to ask for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_that_names_no_lease_is_forgotten_once_no_lease_it_could_name_is_alive() {
    let rig = Rig::start().await;
    rig.served.web().fail(ISSUE, 1, Moment::After);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None) && rig.live_lease_for(&record).is_some()
    })
    .await;
    rig.pass().await;
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.pass().await;
    assert_eq!(
        rig.lease_in_the_record(&record),
        Some(None),
        "kept while a lease its request issued may be alive"
    );
    let asked = rig.requests_for(&record);
    assert_eq!(asked, 1);

    // The daemon is down for longer than a lease lives, and the service's clock goes on too.
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
    let rig = rig.restarted().await;
    rig.until("the row is forgotten", || {
        rig.lease_in_the_record(&record).is_none()
    })
    .await;
    assert_eq!(
        rig.requests_for(&record),
        asked,
        "nothing is asked for a lease that can no longer be alive"
    );
}

/// KR-REQ-17.51: a device whose grant runs out is no longer paired, and its lease is ended when the
/// directory records that, without waiting for the next time the keeper looks. The device finds
/// its grant has run out on its next request; the record of that wakes the keeper.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_grant_runs_out_has_its_lease_ended() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    let session = net_support::connect(&rig.host, &phone, &record).await;

    // The grant is a day long on this host's clock.
    rig.wall.advance(Duration::from_secs(25 * 60 * 60));
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the grant has run out");

    rig.until("the lease is ended at the service", || {
        rig.leases_for(&record).iter().all(|lease| !lease.live) && rig.endings_owed() == 0
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.ended_for == Some("unpaired")),
        "it is ended as a lease of a pair that is no longer paired"
    );
    assert_eq!(rig.lease_in_the_record(&record), None);
}

/// KR-REQ-17.51: the daemon holds more than one handle on its directory of paired devices, and a
/// grant's end is written through whichever of them finds it first: its own lifetimes write it
/// through the daemon's handle, and a connection through the network's. The lease is ended when
/// either records it, with no other change for the keeper to notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_recorded_as_run_out_through_either_handle_has_its_lease_ended() {
    for through_the_network in [false, true] {
        let which = if through_the_network {
            "the network's handle"
        } else {
            "the daemon's handle"
        };
        let rig = Rig::start().await;
        let (_phone, record) = rig.pairs().await;
        rig.until("the paired device holds a lease", || rig.holds(&record))
            .await;
        // The keeper takes in the pairing and waits with no wake stored: what it hears next is
        // what is written below.
        rig.keeper().until_waiting().await;
        assert!(rig.live_lease_for(&record).is_some(), "{which}");

        let directory = if through_the_network {
            rig.host.network().devices()
        } else {
            rig.host.controller().devices()
        };
        directory
            .record_expiry(record.device_id, kr_ipc::now_ms())
            .expect("the end of the grant is recorded");

        rig.until("the lease is ended at the service", || {
            rig.leases_for(&record).iter().all(|lease| !lease.live) && rig.endings_owed() == 0
        })
        .await;
        assert!(
            rig.leases_for(&record)
                .iter()
                .any(|lease| lease.ended_for == Some("unpaired")),
            "it is ended as a lease of a pair that is no longer paired, through {which}"
        );
        assert_eq!(rig.lease_in_the_record(&record), None, "{which}");
    }
}

/// KR-REQ-17.51: a request for a device that is no longer paired, made to learn a lease the host
/// was never told of, is held back by the standing wait when the service has no room, and it does
/// not make the row younger when it issues nothing: the row is forgotten once no lease its first
/// request could have issued is alive, instead of being asked about until the service has room
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_the_service_cannot_answer_for_is_not_kept_alive_by_asking() {
    let rig = Rig::start().await;
    // The first request never reaches the service, so the host cannot know it issued nothing.
    rig.served.web().fail(ISSUE, 1, Moment::Before);
    let (_phone, record) = rig.pairs().await;
    rig.until("the host has a row for the pair and no lease in it", || {
        rig.lease_in_the_record(&record) == Some(None)
    })
    .await;
    // The pass that met the failure has set its delay before the clocks move.
    rig.pass().await;
    rig.served.web().withhold_relays(true);
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    rig.until("the service has turned the pair away", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    assert_eq!(rig.lease_in_the_record(&record), Some(None));
    let asked = rig.requests_for(&record);
    assert_eq!(asked, 2, "the standing wait holds the recovery ask");

    // The wait passes, the ask is made and turned away, and the row is the age of its first
    // request.
    for _ in 0..3 {
        rig.time_passes(STANDING_RETRY);
        rig.timer.advance(STANDING_RETRY);
        rig.pass().await;
    }
    assert!(rig.lease_in_the_record(&record).is_some());
    assert_eq!(
        rig.requests_for(&record),
        asked + 3,
        "one ask each interval"
    );
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(
        rig.lease_in_the_record(&record),
        None,
        "forgotten once the longest a lease lives has passed since its first request"
    );
    let total = rig.requests_for(&record);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(
        rig.requests_for(&record),
        total,
        "and nothing more is asked"
    );
}

/// KR-REQ-17.51: an ending the service turns back while the host is refilling a lease is held for
/// the standing wait as one met at the start of a pass is: the signal of another pairing does not
/// send it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ending_turned_back_during_a_refill_is_not_sent_again_by_the_next_signal() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().retire_relay_of(&first.lease_id);
    rig.served.web().fail(REVOKE, 1, TURNED_BACK);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 1);
    assert_eq!(rig.endings_owed(), 1);

    let (_phone, _record) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 1, "held for the standing wait");

    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 2);
    assert_eq!(rig.endings_owed(), 0);
    assert!(
        rig.live_lease_for(&owner)
            .is_some_and(|lease| lease.lease_id != first.lease_id)
    );
}

/// KR-REQ-17.51: when an ending is turned back for a reason only the owner can change, the pass
/// asks for nothing else, and every request waits for the standing wait, also when a request that
/// was due would have failed: the backoff of a failure is not the hold of a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turned_back_ending_holds_every_request_whatever_else_is_due() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.served.web().fail(REVOKE, 1, TURNED_BACK);
    rig.served.web().fail(ISSUE, 1, SERVICE_DOWN);
    let issued = rig.requests(ISSUE);
    // The owner's refill falls due, and the phone's device is unpaired in the same pass.
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
    rig.until("the ending is turned back", || rig.requests(REVOKE) == 1)
        .await;
    rig.pass().await;
    assert_eq!(
        rig.requests(ISSUE),
        issued,
        "no refill is tried after a refusal"
    );

    rig.timer.advance(Duration::from_secs(60));
    rig.pass().await;
    assert_eq!(
        rig.requests(REVOKE),
        1,
        "and a backoff does not send the ending again"
    );
    assert_eq!(rig.requests(ISSUE), issued);

    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(rig.requests(REVOKE), 2);
    assert_eq!(rig.endings_owed(), 0);
}

/// KR-REQ-17.51, KR-REQ-17.40: the service has no room for the raise one lease needs, and a lease
/// that needs less is raised all the same. A lease whose raise is turned back does not keep the
/// leases after it from being refilled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_raise_the_service_has_no_room_for_does_not_stop_the_refills_after_it() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let busy = rig.live_lease_for(&owner).expect("a lease");
    let (_phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.served.web().relay_counts(&busy.lease_id, 300 * 1024);

    // The first refill of each learns what the relay counted.
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let idle = rig.live_lease_for(&record).expect("the phone's lease");
    let busy = rig.live_lease_for(&owner).expect("the owner's lease");

    // The busy lease needs most of a block more; there is room for a byte.
    rig.served.web().limit_relay_aggregate(800 * 1024);
    rig.time_passes(Duration::from_secs(301));
    rig.pass().await;

    let after = rig.live_lease_for(&record).expect("the phone's lease");
    assert_eq!(
        after.byte_ceiling,
        idle.byte_ceiling + 1,
        "the lease that needed a byte was raised"
    );
    assert_eq!(
        rig.live_lease_for(&owner)
            .expect("the owner's lease")
            .byte_ceiling,
        busy.byte_ceiling,
        "and the one that needed a block, which the service had no room for, was kept"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(shown.detail().contains("no room"), "{}", shown.detail());
}

/// KR-REQ-17.52: the grace an answer carries is taken from every answer about a lease, also from
/// one that says the service has no room: it is shown while the answers carry it and is gone with
/// the first that does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_grace_an_answer_of_no_room_carries_is_shown_until_one_carries_none() {
    let rig = Rig::start().await;
    rig.served.web().withhold_relays(true);
    rig.served.web().enter_relay_grace(true);
    let (_phone, _record) = rig.pairs().await;
    rig.until("the service has turned the pair away", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("no relay to offer"),
        "{}",
        shown.detail()
    );
    assert!(
        shown.detail().contains("104857600 bytes"),
        "the grace is shown: {}",
        shown.detail()
    );

    rig.served.web().enter_relay_grace(false);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("no relay to offer"),
        "{}",
        shown.detail()
    );
    assert!(
        !shown.detail().contains("104857600 bytes"),
        "{}",
        shown.detail()
    );
}
