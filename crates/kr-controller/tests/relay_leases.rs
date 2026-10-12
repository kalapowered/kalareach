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

use kr_controller::relay_leases::{BLOCK_BYTES, LEASE_SECONDS, REFILL_WHEN_LEFT, STANDING_RETRY};
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
    /// A daemon that names the account the service's console gave its key, with the owner's device
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
        let served = serve().await;
        let timer = HeldTimer::held();
        let wall = MovedWall::new();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host_keys = DeviceKeys::generate().expect("host keys");
        let payer = served
            .web()
            .authorise_relay_payer(host_keys.authorisation.public(), 8 * 1024 * 1024);
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

    /// Stops the daemon and starts it again on its tree.
    async fn restarted(self) -> Self {
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
/// so the service raises the reservation it has and opens no second one. The ceiling the host asks
/// for follows what the relay counted, as the reservation's cumulative total, and a lease that has
/// plenty of its life left is left alone.
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
        first.byte_ceiling.to_string(),
        "the relay had counted nothing the host knew of, so the ceiling is the block it held"
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

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is revoked");
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

/// KR-REQ-17.40, KR-REQ-17.50, KR-REQ-17.52: an allowance that is spent is an answer about
/// capacity and not a fault. The host holds the leases it has, issues no new one, tells the owner
/// how much grace is left and that a direct connection and a relay of their own still work, asks
/// again no sooner than the standing interval, and issues the lease when the allowance is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allowance_that_is_spent_is_shown_to_the_owner_and_asked_again() {
    let rig = Rig::start().await;
    rig.served.web().exhaust_relay_allowance(true);
    let (_phone, record) = rig.pairs().await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;

    assert!(rig.live_lease_for(&record).is_none());
    assert_eq!(
        rig.lease_in_the_record(&record),
        None,
        "a request that issued nothing leaves no row"
    );
    assert!(
        rig.live_lease_for(&rig.owner_device()).is_some(),
        "a lease that is held is held"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(shown.detail().contains("allowance"), "{}", shown.detail());
    assert!(
        shown.detail().contains("600 seconds") && shown.detail().contains("104857600 bytes"),
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
    rig.pass().await;
    assert!(rig.holds(&record));
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.35: a host that names no account is turned away by the service, whose reason is that
/// a host key draws on no allowance of its own. That is shown to the owner with what to change,
/// and the host asks no more often than the standing interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_names_no_account_is_turned_away_and_the_owner_is_told() {
    let rig = Rig::start_naming(false).await;
    rig.until("the keeper has been refused", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    assert_eq!(
        rig.requests(ISSUE),
        1,
        "one refusal is enough to stop asking for the others"
    );
    assert!(rig.served.web().relay_leases().is_empty());

    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("names the account"),
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
    let sent = rig.bodies(ISSUE);
    let (named, afresh) = (&sent[sent.len() - 2], &sent[sent.len() - 1]);
    assert_eq!(named["lease_id"], first.lease_id);
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
    assert!(
        rig.timer.asked_for().contains(&Duration::from_secs(7)),
        "{:?}",
        rig.timer.asked_for()
    );
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

/// The doctor says so when no lease service is selected, and a host that selects none sends nothing.
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
