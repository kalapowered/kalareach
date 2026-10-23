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
// A relay server and a Pkarr relay running in this process. Only this suite needs them, and other
// suites that share `net_support` do not link what they use.
#[path = "net_support/relay.rs"]
mod local_relay;
#[allow(dead_code)]
#[path = "../../kr-transport/tests/support/pkarr.rs"]
mod pkarr;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::account::{IssuedGrant, RefreshToken};
use kr_client::services::{
    AccountToken, ManagedPairingAdmission, PairingAdmissions, ServiceSigner,
};
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
use kr_service_stand_in::{Moment, RelayAuthorisationView, RelayLeaseView, Served, serve};
use local_relay::LocalRelay;
use net_support::{Device, Host, MovedWall, pair_with, proposal};

const ISSUE: &str = "/api/relay/lease";
const REVOKE: &str = "/api/relay/lease/revoke";
const SIGN_IN: &str = "/api/relay/payer-authorisation/sign-in";

/// The scopes a host's sign-in is issued when it asks for the right to bill relay traffic.
const SIGNED_IN_SCOPES: [&str; 2] = ["openid", "relay.lease"];

/// A sign-in of the host: the account, the grant the account system recorded for it, and the
/// access and refresh tokens it holds. A person's next sign-in is another grant, of the same
/// account or of another one.
#[derive(Clone, Debug)]
struct SignIn {
    account: String,
    grant: String,
    access: String,
    refresh: String,
}

impl SignIn {
    /// A sign-in nobody else made: the account is `account` when it is given, and new otherwise.
    fn new(account: Option<&str>) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self {
            account: account.map_or_else(|| format!("account-{n}"), str::to_owned),
            grant: format!("grant-{n}"),
            access: format!("access-{n}"),
            refresh: format!("refresh-{n}"),
        }
    }

    /// What the account system issued, as the host keeps it.
    fn issued(&self) -> IssuedGrant {
        IssuedGrant {
            access_token: AccountToken::new(&self.access).expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new(&self.refresh).expect("a token"),
            scopes: SIGNED_IN_SCOPES.map(str::to_owned).to_vec(),
            subject: self.account.clone(),
        }
    }

    /// The account system issues the tokens, and the service knows the grant.
    fn issue(&self, served: &Served) {
        served
            .web()
            .issue_grant_token(&self.access, &self.account, &self.grant, &SIGNED_IN_SCOPES);
        served.web().issue_grant_refresh(&self.refresh, &self.grant);
    }
}

/// How long the service asks the keeper to leave it alone in the cases that ask for the keeper to be
/// left alone, as the time its timer counts.
const LEFT_ALONE_FOR: Duration = Duration::from_secs(300);

/// How far the timer moves to take a relay past the bound it is given to carry the endpoint: the
/// bound and a second.
const PAST_THE_BOUND: Duration =
    Duration::from_secs(kr_controller::relay_leases::endpoint::REACH_BOUND.as_secs() + 1);

/// How far the timer moves to take a relay that failed to carry the endpoint past the first delay
/// it is left out of the endpoint's map for: the delay and a second.
const PAST_THE_DELAY: Duration =
    Duration::from_secs(kr_controller::relay_leases::endpoint::REACH_RETRY.as_secs() + 1);

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
    /// The sign-in the host was started with.
    sign_in: SignIn,
}

impl Rig {
    /// A daemon whose host is signed in with permission to bill relay traffic to its account, with
    /// the owner's device paired and holding a lease.
    async fn start() -> Self {
        let rig = Self::start_signed_in(true).await;
        let owner = rig.owner_device();
        rig.until("the owner's device holds a lease", || rig.holds(&owner))
            .await;
        rig
    }

    /// As [`Self::start`], with the host signed in only when `signed_in` is true, and not waiting
    /// for a lease.
    async fn start_signed_in(signed_in: bool) -> Self {
        Self::start_bounded_signed_in(signed_in, 8 * 1024 * 1024).await
    }

    /// A daemon whose sign-in opens authorisations that let one lease hold `bound` bytes
    /// outstanding, with the owner's device paired and holding a lease.
    async fn start_bounded(bound: u64) -> Self {
        let rig = Self::start_bounded_signed_in(true, bound).await;
        let owner = rig.owner_device();
        rig.until("the owner's device holds a lease", || rig.holds(&owner))
            .await;
        rig
    }

    async fn start_bounded_signed_in(signed_in: bool, bound: u64) -> Self {
        Self::start_over(signed_in, bound, net_support::loopback(), None).await
    }

    /// As [`Self::start_bounded_signed_in`], over the endpoint `endpoint` names, with the relay
    /// instance the service installs leases on at `relay_url` when one is given.
    async fn start_over(
        signed_in: bool,
        bound: u64,
        endpoint: kr_transport::config::EndpointConfig,
        relay_url: Option<&str>,
    ) -> Self {
        let served = serve().await;
        if let Some(relay_url) = relay_url {
            served.web().name_relay_url(relay_url);
        }
        served.web().bound_relay_sign_ins(bound);
        let timer = HeldTimer::held();
        let wall = MovedWall::new();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host_keys = DeviceKeys::generate().expect("host keys");
        let sign_in = SignIn::new(None);
        sign_in.issue(&served);
        let host = Host::start_with_relay_on(
            &owner,
            &host_keys,
            Some(served.origin()),
            net_support::AccountAt::Origin(served.origin().to_owned()),
            signed_in.then(|| sign_in.issued()),
            endpoint,
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
            sign_in,
        }
    }

    /// The authorisation the sign-in opened, once the host has asked for it.
    fn opened_by(&self, sign_in: &SignIn) -> Option<RelayAuthorisationView> {
        self.served
            .web()
            .relay_sign_ins()
            .into_iter()
            .find(|opened| opened.grant == sign_in.grant)
    }

    /// The authorisation the host's first sign-in opened.
    fn payer(&self) -> RelayAuthorisationView {
        self.opened_by(&self.sign_in)
            .expect("the host has asked for its authorisation")
    }

    /// The host is signed in again, as a person's new sign-in does it: with another grant, of the
    /// same account when `same_account` is true. Nothing wakes the keeper; it finds the sign-in at
    /// its next pass.
    async fn signs_in_again(&self, same_account: bool) -> SignIn {
        let again = SignIn::new(same_account.then_some(self.sign_in.account.as_str()));
        again.issue(&self.served);
        self.host
            .controller()
            .host_account()
            .keep_for_test(again.issued())
            .await;
        again
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

    /// The relays an invitation the owner makes names for the host: the network configuration it
    /// carries.
    fn invitation_relays(&self) -> Vec<iroh::RelayUrl> {
        self.host
            .network()
            .network_config()
            .expect("the network configuration of an invitation")
            .relay_urls
            .iter()
            .map(|hint| hint.as_str().parse().expect("a relay URL"))
            .collect()
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
        self.check_named("relay-leases").await
    }

    /// What `kr doctor` says in the check `id`.
    async fn check_named(&self, id: &str) -> DoctorCheck {
        let mut local = self.host.client().await;
        let doctor: HostDoctorResult =
            net_support::pairing::read(&mut local, Method::HostDoctor, &())
                .await
                .expect("the host's diagnostics");
        doctor
            .checks
            .into_iter()
            .find(|check| check.id() == id)
            .unwrap_or_else(|| panic!("the {id} check"))
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
            sign_in,
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
            sign_in,
        }
    }
}

/// KR-REQ-17.34, KR-REQ-17.51: a paired device is given a lease for its pair. It binds this host's
/// endpoint and the device's, both ways, and the account the host is signed in as pays, under the
/// authorisation that sign-in opened for this host's key. The host's record names the lease the
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
        Some(rig.payer().authorisation_id.as_str()),
        "the account the host is signed in as pays"
    );
    assert_eq!(rig.payer().account_id, rig.sign_in.account);
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
        rig.payer().account_id
    );
    assert_eq!(
        first["payer"]["account"]["authorisation_id"],
        rig.payer().authorisation_id,
        "every lease request names the authorisation the sign-in opened"
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
    let sign_in = SignIn::new(None);
    sign_in.issue(&served);
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
    let mut stopped = host.shut_down().await;
    net_support::write_relay_document(stopped.tree(), Some(served.origin()));
    stopped.account_service_stays_at(served.origin());
    assert_eq!(
        served.web().requests_to(ISSUE),
        0,
        "nothing was asked before"
    );
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    host.controller()
        .host_account()
        .keep_for_test(sign_in.issued())
        .await;
    let rig = Rig {
        host,
        served,
        timer,
        wall,
        owner,
        host_key: *host_keys.authorisation.public(),
        sign_in,
    };
    rig.pass().await;
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
    // Entitlement explains what a call is answered and decides nothing else: the host still holds
    // its lease client, whatever the account's entitlement says.
    let services = rig.check_named("managed-services").await;
    assert!(
        services.detail().contains("relay leases: configured"),
        "{}",
        services.detail()
    );
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

/// Three relay servers: the one the host's configuration lists, the one the service installs its
/// leases on, and one it moves to later.
struct Relays {
    configured: LocalRelay,
    leased: LocalRelay,
    later: LocalRelay,
}

impl Relays {
    async fn spawn() -> Self {
        Self {
            configured: LocalRelay::spawn().await,
            leased: LocalRelay::spawn().await,
            later: LocalRelay::spawn().await,
        }
    }

    fn roots(&self) -> Vec<Vec<u8>> {
        [
            self.configured.ca_roots.clone(),
            self.leased.ca_roots.clone(),
            self.later.ca_roots.clone(),
        ]
        .concat()
    }

    /// The host selects the first relay and has its direct paths.
    fn host(&self) -> kr_transport::config::EndpointConfig {
        kr_transport::config::EndpointConfig {
            relay_urls: vec![self.configured.url.clone()],
            relay_ca_roots: self.roots(),
            ..net_support::loopback()
        }
    }

    /// As [`Self::host`], publishing where it is to the Pkarr relay `pkarr` and resolving from it.
    fn host_resolvable_through(
        &self,
        pkarr: &pkarr::PkarrRelay,
    ) -> kr_transport::config::EndpointConfig {
        kr_transport::config::EndpointConfig {
            discovery: kr_transport::config::DiscoveryConfig {
                pkarr_publisher_url: Some(pkarr.url.clone()),
                pkarr_resolver_url: Some(pkarr.url.clone()),
                ..kr_transport::config::DiscoveryConfig::default()
            },
            ..self.host()
        }
    }

    /// A device whose only route is the second relay.
    fn device(&self) -> kr_transport::config::EndpointConfig {
        kr_transport::config::EndpointConfig {
            relay_urls: vec![self.leased.url.clone()],
            relay_ca_roots: self.roots(),
            relay_only: true,
            ..net_support::loopback()
        }
    }

    /// A daemon that selects the first relay while the service installs leases on the second.
    async fn rig(&self) -> Rig {
        Rig::start_over(
            true,
            8 * 1024 * 1024,
            self.host(),
            Some(self.leased.url.as_str()),
        )
        .await
    }
}

impl Rig {
    /// The relays the host's endpoint is home at and connected to.
    fn homes(&self) -> Vec<iroh::RelayUrl> {
        use iroh::Watcher;
        self.endpoint()
            .home_relay_status()
            .get()
            .iter()
            .filter(|home| home.is_connected())
            .map(|home| home.url().clone())
            .collect()
    }

    fn endpoint(&self) -> iroh::Endpoint {
        self.host
            .network()
            .endpoint_for_tests()
            .expect("the host is on the network")
    }

    /// Waits until the endpoint is no longer connected to `relay` as a home relay.
    ///
    /// It is the endpoint's own connection that is waited for, and for as long as it takes: how
    /// soon an endpoint notices that a relay has stopped is up to the machine it runs on. A test
    /// that went wrong is stopped rather than left to hang.
    async fn until_the_endpoint_has_left(&self, relay: &iroh::RelayUrl) {
        use iroh::Watcher;
        let mut status = self.endpoint().home_relay_status();
        let left = tokio::time::timeout(Duration::from_secs(180), async {
            while self.homes().contains(relay) {
                if status.updated().await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(
            left.is_ok() && !self.homes().contains(relay),
            "the endpoint was still connected to {relay} as its home relay; it was at {:?}",
            self.homes()
        );
    }

    /// Waits until the endpoint is connected to `relay` as its home relay.
    async fn until_the_endpoint_is_at(&self, relay: &iroh::RelayUrl) {
        use iroh::Watcher;
        let mut status = self.endpoint().home_relay_status();
        let arrived = tokio::time::timeout(Duration::from_secs(180), async {
            while !self.homes().contains(relay) {
                if status.updated().await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(
            arrived.is_ok() && self.homes().contains(relay),
            "the endpoint never had {relay} as its home relay; it was at {:?}",
            self.homes()
        );
    }

    /// Has the keeper take one look at the endpoint's relays while the service has asked it to
    /// leave the service alone: the wait it is in ends, and nothing else wakes it. It returns once
    /// the look is done.
    async fn look_while_left_alone(&self) {
        let mut looks = self.keeper().passes();
        let before = *looks.borrow_and_update();
        self.timer.release_held();
        tokio::time::timeout(
            Duration::from_secs(180),
            looks.wait_for(|looked| *looked > before),
        )
        .await
        .expect("the keeper takes the look")
        .expect("the keeper is still there");
    }

    /// As [`Self::until_homed_on`] for the relay the host was held to having gone and the
    /// configured `relay` taking its place, while the keeper is not making a pass because the
    /// service asked it to leave the service alone.
    ///
    /// The look at the relays has to bring the endpoint back to `relay` while the service is still
    /// being left alone, and that is counted in the timer's time. The timer moves only by the
    /// bound the leased relay is given to carry the endpoint, once the keeper has seen the relay
    /// not carry it, so what a loaded machine stretches, how long the endpoint and the keeper take,
    /// costs real time and none of the delay. The endpoint's part is waited for where it happens.
    async fn quietly_until_homed_on(&self, relay: &iroh::RelayUrl, gone: &iroh::RelayUrl) {
        self.until_the_endpoint_has_left(gone).await;
        // The keeper sees that the relay does not carry the endpoint, which is when the bound
        // starts, and the bound passes by the next time it looks. A look that was under way when
        // the endpoint left may not have seen it go and is counted all the same; the look after it
        // begins after it ended, so it is the one that sees the relay not carry the endpoint, and
        // the timer stays where it is until it has.
        self.look_while_left_alone().await;
        self.look_while_left_alone().await;
        self.timer.advance(PAST_THE_BOUND);
        let back = tokio::time::timeout(Duration::from_secs(180), async {
            while self.invitation_relays() != vec![relay.clone()] {
                self.look_while_left_alone().await;
            }
        })
        .await;
        assert!(
            back.is_ok(),
            "the keeper still named {:?} when the bound had passed and the service was still being \
             left alone",
            self.invitation_relays()
        );
        self.until_the_endpoint_is_at(relay).await;
    }

    /// As [`Self::until_held_to`], and then waits for the endpoint to connect to `relay` where it
    /// happens and has the keeper look once more: the leased relay is the only relay the endpoint
    /// has once it is held to it, so it connects without the keeper, and a timer that ran on while
    /// it did would count the time against the bound the relay is given to carry the endpoint.
    async fn until_held_and_at(&self, relay: &iroh::RelayUrl) {
        self.until_held_to(relay).await;
        self.until_the_endpoint_is_at(relay).await;
        self.pass().await;
    }

    /// Lets the keeper look at the relays, with time passing for it, until the endpoint is held
    /// to `relay` alone: the configured relays are set aside, which is what an invitation shows.
    async fn until_held_to(&self, relay: &iroh::RelayUrl) {
        use iroh::Watcher;
        let mut report = self.endpoint().net_report();
        let held = tokio::time::timeout(Duration::from_secs(180), async {
            while self.invitation_relays() != vec![relay.clone()] {
                self.timer.advance(Duration::from_secs(5));
                self.pass().await;
                // The endpoint measures its relays on its own: wait for it to report.
                let _ = tokio::time::timeout(Duration::from_secs(2), report.updated()).await;
            }
        })
        .await;
        assert!(
            held.is_ok(),
            "the endpoint was never held to {relay}; it names {:?}",
            self.invitation_relays()
        );
    }

    /// Lets the keeper look at the relays, with time passing for it, until the doctor no longer
    /// warns: the endpoint connecting to a relay is seen by the doctor at the keeper's next look.
    async fn until_the_doctor_is_ok(&self) {
        use iroh::Watcher;
        let mut report = self.endpoint().net_report();
        let settled = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                if self.check().await.status == DoctorStatus::Ok {
                    return;
                }
                self.timer.advance(Duration::from_secs(5));
                self.pass().await;
                let _ = tokio::time::timeout(Duration::from_secs(2), report.updated()).await;
            }
        })
        .await;
        assert!(settled.is_ok(), "the doctor never went back to Ok");
    }

    /// Takes the leased relay past the bound it is given to carry the endpoint, and lets the keeper
    /// look at the relays until the doctor says the leased relay is not answering. `gone` is the
    /// relay the endpoint was at when it stopped, when it was at one.
    ///
    /// The keeper looks once when the endpoint is not at the relay, which is when the bound
    /// starts, and the timer moves past the bound. The doctor is asked after each look from then
    /// on, so how many looks that takes, and how long each takes on a loaded machine, is not what
    /// the case counts.
    async fn until_the_doctor_warns_of_the_relay(&self, gone: Option<&iroh::RelayUrl>) {
        if let Some(gone) = gone {
            self.until_the_endpoint_has_left(gone).await;
        }
        self.pass().await;
        self.timer.advance(PAST_THE_BOUND);
        let warned = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                self.pass().await;
                let shown = self.check().await;
                if shown.status == DoctorStatus::Warning
                    && shown.detail().contains("network.relay_urls")
                {
                    return;
                }
            }
        })
        .await;
        assert!(
            warned.is_ok(),
            "the doctor never said the relay is not answering"
        );
    }

    /// Lets the keeper look at the relays, with time passing for it, until the endpoint's home
    /// relay is `relay` and it is connected there. A test that went wrong is stopped rather than
    /// left to hang, and says where the endpoint was.
    async fn until_homed_on(&self, relay: &iroh::RelayUrl) {
        use iroh::Watcher;
        let mut status = self.endpoint().home_relay_status();
        let homed = tokio::time::timeout(Duration::from_secs(180), async {
            while !self.homes().contains(relay) {
                self.timer.advance(Duration::from_secs(5));
                self.pass().await;
                // The endpoint moves between relays on its own measurements: wait for it to
                // report, and look again when it does not.
                let _ = tokio::time::timeout(Duration::from_secs(2), status.updated()).await;
            }
        })
        .await;
        assert!(
            homed.is_ok(),
            "the endpoint never had {relay} as its home relay; it was at {:?}",
            self.homes()
        );
    }
}

/// KR-REQ-17.34: the service chooses the relay that carries a pair, installs the lease there and
/// names the relay in the grant, and the pair's relayed traffic flows through that relay. The host
/// selected another relay, so the endpoint has to leave it: a relay forwards for a pair only while
/// it holds the pair's lease, and iroh keeps the home relay it has unless another is much faster. A
/// device with no other route dials the host at the relay the lease names, and the bytes of the
/// exchange cross that relay and not the one the host selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairs_traffic_crosses_the_relay_its_lease_is_installed_on() {
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let (phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    rig.until_homed_on(&relays.leased.url).await;

    // The same device, with the route a phone away from the host's network has: the relay only.
    phone.endpoint().close().await;
    let away = Device::with_keys_on(&relays.device(), phone.keys().clone()).await;
    let before = (relays.configured.forwarded(), relays.leased.forwarded());
    let dial = net_support::paired_dial_through(&rig.host, &away, &record, &relays.leased.url);
    let transport = tokio::time::timeout(Duration::from_secs(120), dial.dial())
        .await
        .expect("the device reaches the host at the relay the lease names");
    assert!(
        relays.leased.forwarded() > before.1,
        "the pair's bytes crossed the relay the lease is installed on"
    );
    assert_eq!(
        relays.configured.forwarded(),
        before.0,
        "and none crossed the relay the host selected"
    );
    drop(transport);
}

/// KR-REQ-17.34: the endpoint is held to the relay the leases are installed on only while the host
/// holds a lease there, and a device that is invited is told the relay the host is at. Once every
/// lease has run out and none is asked for again, the endpoint is at the relays its configuration
/// lists, and the invitation names those. The endpoint's own address, which is what a peer
/// resolves, follows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_is_held_to_the_relay_its_leases_are_on_only_while_it_holds_one() {
    use iroh::Watcher;
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_to(&relays.leased.url).await;
    rig.until_homed_on(&relays.leased.url).await;
    assert_eq!(
        rig.invitation_relays(),
        vec![relays.leased.url.clone()],
        "a device is invited to the relay the host is at"
    );
    assert_eq!(
        rig.endpoint()
            .watch_addr()
            .get()
            .relay_urls()
            .cloned()
            .collect::<Vec<_>>(),
        vec![relays.leased.url.clone()],
        "and a peer that resolves the host finds it there"
    );

    // The service has no relay to offer, and the lease runs out.
    rig.served.web().withhold_relays(true);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 1));
    rig.pass().await;
    assert!(!rig.holds(&owner), "the lease that ran out is not held");
    rig.until_homed_on(&relays.configured.url).await;
    assert_eq!(rig.invitation_relays(), vec![relays.configured.url.clone()]);
    assert_eq!(
        rig.endpoint()
            .watch_addr()
            .get()
            .relay_urls()
            .cloned()
            .collect::<Vec<_>>(),
        vec![relays.configured.url.clone()],
        "a device invited while the lease was held resolves the host where it is now"
    );
}

/// KR-REQ-17.34, KR-REQ-17.45: a device paired while the host's leases were held was told the relay
/// the host was at then, and that bundle goes stale when the lease ends and the host returns to the
/// relays it was configured with. The host publishes where it is now, so the device, dialling at
/// the relay its bundle names with no other route, resolves the pinned host again and reaches it at
/// the relay it is at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_paired_while_a_lease_was_held_reaches_the_host_after_the_lease_ends() {
    let mut relays = Relays::spawn().await;
    let pkarr = pkarr::PkarrRelay::spawn();
    let rig = Rig::start_over(
        true,
        8 * 1024 * 1024,
        relays.host_resolvable_through(&pkarr),
        Some(relays.leased.url.as_str()),
    )
    .await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_to(&relays.leased.url).await;
    rig.until_homed_on(&relays.leased.url).await;
    assert_eq!(
        rig.invitation_relays(),
        vec![relays.leased.url.clone()],
        "the bundle the device is paired with names the relay the host is at while it holds the lease"
    );
    let (phone, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;

    // The lease ends, and the host goes back to the relay it was configured with. The relay the
    // bundle names no longer has the host: it keeps a connection a while after the host left, so
    // the relay is stopped to leave the bundle's hint with no route.
    rig.served.web().withhold_relays(true);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 1));
    rig.pass().await;
    rig.until_homed_on(&relays.configured.url).await;
    relays.leased.stop().await;

    // The device has the stale bundle and no other route than a relay: the one the bundle names.
    phone.endpoint().close().await;
    let away = Device::with_keys_on(
        &kr_transport::config::EndpointConfig {
            discovery: kr_transport::config::DiscoveryConfig {
                pkarr_resolver_url: Some(pkarr.url.clone()),
                ..kr_transport::config::DiscoveryConfig::default()
            },
            ..relays.device()
        },
        phone.keys().clone(),
    )
    .await;
    let before = relays.configured.forwarded();
    let dial = net_support::paired_dial_through(&rig.host, &away, &record, &relays.leased.url);
    let transport = tokio::time::timeout(Duration::from_secs(120), dial.dial())
        .await
        .expect("the device finds the host where it is now");
    assert!(
        relays.configured.forwarded() > before,
        "and its bytes crossed the relay the host is at"
    );
    drop(transport);
}

/// KR-REQ-17.34: the record keeps the relay a lease is installed on, so a host that restarts goes
/// to that relay from the record alone, without asking the service for the lease again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_restarts_is_at_the_relay_its_leases_are_installed_on() {
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    let asked = rig.requests(ISSUE);

    let rig = rig.restarted().await;
    rig.until_homed_on(&relays.leased.url).await;
    assert_eq!(
        rig.requests(ISSUE),
        asked,
        "the host was told where its leases are by its record, and asked for nothing"
    );
}

/// KR-REQ-17.34: the lease is the paid path the service chose, but never at the price of the host
/// having no relay. The relay the leases are installed on stops answering: after the bound the
/// configured relays come back while the lease stays held, the owner is told why, an invitation
/// names the relays the host is at, and the host goes back to the leased relay once it answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_leased_relay_stops_uses_its_configured_relays_and_goes_back_when_it_answers()
{
    let mut relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_and_at(&relays.leased.url).await;
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);

    relays.leased.stop().await;
    rig.until_the_doctor_warns_of_the_relay(Some(&relays.leased.url))
        .await;
    // The keeper has put the configured relays back. The endpoint connects to one on its own, and
    // the timer stays where it is meanwhile: the leased relay is left out of the endpoint's map for
    // a delay that the timer counts, and a timer that ran on while the endpoint connected would end
    // that delay and have the keeper try the leased relay again before the case looked.
    rig.until_the_endpoint_is_at(&relays.configured.url).await;
    assert!(rig.holds(&owner), "the lease stays held");
    assert_eq!(
        rig.invitation_relays(),
        vec![relays.configured.url.clone()],
        "a device is invited to the relay the host is at"
    );

    // The relay is back, and the keeper tries it again when the delay it was left out of the map
    // for has passed, which the timer takes it past at once.
    relays.leased.start_again().await;
    rig.timer.advance(PAST_THE_DELAY);
    rig.until_held_and_at(&relays.leased.url).await;
    rig.until_the_doctor_is_ok().await;
}

/// KR-REQ-17.34: a relay the leases are installed on that has never answered this host does not
/// cost it the relay it was configured with. The configured relays are set aside only once the
/// leased relay has been seen to answer, so the host stays at them, tells the owner why, and goes to
/// the leased relay when it comes up. The port stays the relay's while it is stopped: a connection
/// to it is turned away, and a program that wants it for itself is not given it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leased_relay_that_never_answered_does_not_cost_the_host_its_configured_relay() {
    let mut relays = Relays::spawn().await;
    relays.leased.stop().await;
    let port = relays.leased.url.port().expect("the relay has a port");
    let dialled = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .expect("a stopped relay turns a connection away at once");
    assert!(
        dialled
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused),
        "a connection to the stopped relay was not turned away: {:?}",
        dialled.map(|_| ())
    );
    let wanted = tokio::net::TcpSocket::new_v4()
        .expect("a socket")
        .bind(([127, 0, 0, 1], port).into());
    assert!(
        wanted
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::AddrInUse),
        "a program was given the port of the stopped relay: {wanted:?}"
    );
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;

    rig.until_homed_on(&relays.configured.url).await;
    rig.until_the_doctor_warns_of_the_relay(None).await;
    assert!(
        rig.homes().contains(&relays.configured.url),
        "the host stays at the relay it was configured with: {:?}",
        rig.homes()
    );
    assert!(rig.holds(&owner), "the lease stays held");

    // The relay is up: the keeper has the endpoint measure its relays again once the bound has
    // passed since it last did, which the timer takes it past at once.
    relays.leased.start_again().await;
    rig.timer.advance(PAST_THE_BOUND);
    rig.until_held_and_at(&relays.leased.url).await;
    rig.until_the_doctor_is_ok().await;
}

/// KR-REQ-17.34: the look at the endpoint's relays is the host's own and does not wait on the
/// service. While the service has asked the keeper to leave it alone for minutes, the leased relay
/// stops carrying the endpoint, and the configured relays come back all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_asks_to_be_left_alone_does_not_keep_the_host_from_its_configured_relay() {
    let mut relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_and_at(&relays.leased.url).await;

    // The next refill is turned back with a delay of five minutes.
    rig.served.web().fail(
        ISSUE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(LEFT_ALONE_FOR.as_secs()),
        },
    );
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    let refills = rig.requests_for(&owner);
    rig.pass().await;
    assert_eq!(
        rig.requests_for(&owner),
        refills + 1,
        "the refill was turned back with the delay"
    );
    let asked = rig.requests(ISSUE);

    // Within the delay, which is five minutes of the timer's time, the relay stops and the
    // configured relays come back, and the service is not asked anything meanwhile.
    relays.leased.stop().await;
    rig.quietly_until_homed_on(&relays.configured.url, &relays.leased.url)
        .await;
    assert_eq!(
        rig.requests(ISSUE),
        asked,
        "the service was asked nothing while the delay stood"
    );
    assert!(rig.holds(&owner), "the lease stays held");
}

/// KR-REQ-17.34: a relay that answers an endpoint's measurements and then turns its session away is
/// not held again at once. The host has no relay of its own for the time the hold takes to fail,
/// and the time the leased relay is left alone grows with each failure, so that a relay that keeps
/// refusing costs the host that time less and less often. The endpoint's own account, driven with
/// the clock it is given, against a relay that answers measurements and turns every session away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leased_relay_that_refuses_the_session_is_left_alone_for_longer_each_time() {
    use iroh::Watcher;
    use kr_controller::relay_leases::endpoint::{
        EndpointRelays, HomeRelays, REACH_BOUND, REACH_RETRY,
    };
    let relays = Relays::spawn().await;
    relays.leased.refuse_sessions(true);
    let keys = DeviceKeys::generate().expect("keys");
    let config = relays.host();
    let endpoint = kr_transport::endpoint::bind_dialer(&config, &keys.transport)
        .await
        .expect("an endpoint");
    let held = EndpointRelays::new(endpoint.clone(), &config);
    let leased = relays.leased.url.clone();
    let mut report = endpoint.net_report();
    let mut now = std::time::Instant::now();

    // Looks at the relays as the clock passes, until the endpoint is held to the leased relay: it
    // is, once a measurement has seen the relay answer.
    let mut until_held = async |now: &mut std::time::Instant| {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                held.home_on(Some(leased.as_str()), *now).await;
                if held.selected() == vec![leased.clone()] {
                    return;
                }
                let _ = tokio::time::timeout(Duration::from_secs(2), report.updated()).await;
                *now += Duration::from_secs(5);
            }
        })
        .await
        .expect("the leased relay is held once it has answered");
    };

    let mut delays = Vec::new();
    let mut away = None;
    for _ in 0..4 {
        until_held(&mut now).await;
        if let Some(away) = away {
            delays.push(now.saturating_duration_since(away));
        }
        // The relay never carries the endpoint: after the bound the configured relays are back.
        now += REACH_BOUND + Duration::from_secs(1);
        held.home_on(Some(relays.leased.url.as_str()), now).await;
        assert_eq!(
            held.selected(),
            vec![relays.configured.url.clone()],
            "the configured relays are back after the bound"
        );
        away = Some(now);
    }
    assert_eq!(delays.len(), 3);
    for (round, delay) in delays.iter().enumerate() {
        let least = REACH_RETRY * 2_u32.pow(u32::try_from(round).expect("a small number"));
        assert!(
            *delay >= least && *delay < least + Duration::from_secs(40),
            "the relay was left alone for {delay:?} the {round}th time, not {least:?}"
        );
    }
    endpoint.close().await;
}

/// KR-REQ-17.34: a leased relay that the configuration also lists is out of the endpoint's map
/// for the delay too, so that the endpoint's home relay is a configured relay that carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leased_relay_the_configuration_also_lists_is_left_out_while_it_refuses_the_session() {
    use iroh::Watcher;
    use kr_controller::relay_leases::endpoint::{EndpointRelays, HomeRelays, REACH_BOUND};
    let relays = Relays::spawn().await;
    relays.leased.refuse_sessions(true);
    let keys = DeviceKeys::generate().expect("keys");
    let config = kr_transport::config::EndpointConfig {
        relay_urls: vec![relays.configured.url.clone(), relays.leased.url.clone()],
        ..relays.host()
    };
    let endpoint = kr_transport::endpoint::bind_dialer(&config, &keys.transport)
        .await
        .expect("an endpoint");
    let held = EndpointRelays::new(endpoint.clone(), &config);
    let leased = relays.leased.url.clone();
    let mut report = endpoint.net_report();
    let mut now = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(120), async {
        while held.selected() != vec![leased.clone()] {
            held.home_on(Some(leased.as_str()), now).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), report.updated()).await;
            now += Duration::from_secs(5);
        }
    })
    .await
    .expect("the leased relay is held once it has answered");

    // It never carries the endpoint: after the bound it is out, and the configured relay carries
    // the endpoint for the whole delay.
    now += REACH_BOUND + Duration::from_secs(1);
    held.home_on(Some(leased.as_str()), now).await;
    let mut status = endpoint.home_relay_status();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !status
            .get()
            .iter()
            .any(|home| home.url() == &relays.configured.url && home.is_connected())
        {
            let _ = tokio::time::timeout(Duration::from_secs(2), status.updated()).await;
        }
    })
    .await
    .expect("the configured relay carries the endpoint");
    assert!(
        status.get().iter().all(|home| home.url() != &leased),
        "the relay that refuses is not a home relay"
    );
    assert!(
        endpoint.remove_relay(&leased).await.is_none(),
        "and it is out of the endpoint's map, so that it cannot be chosen"
    );
    endpoint.close().await;
}

/// KR-REQ-17.34: the service installs a new lease on the relay it selects when the lease is issued,
/// and a refill keeps the relay its lease was issued on. When the selection moves, one host's
/// leases are on two relays, and a device whose lease is on a relay other than the one the host is
/// at has no lease where it reaches the host. The host keeps all its leases on the relay new leases
/// land on: it replaces a lease on any other relay with a new one, after ending the old one, and is
/// at that relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_keeps_its_leases_on_the_relay_new_leases_land_on() {
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    let first = rig.live_lease_for(&owner).expect("a lease");
    assert_eq!(first.relay_url, relays.leased.url.as_str());
    rig.until_homed_on(&relays.leased.url).await;

    // The service selects another relay for the leases it issues from now on.
    rig.served.web().name_relay_url(relays.later.url.as_str());
    let (_phone, record) = rig.pairs().await;
    rig.until("the new device holds a lease", || rig.holds(&record))
        .await;
    assert_eq!(
        rig.live_lease_for(&record).expect("a lease").relay_url,
        relays.later.url.as_str(),
        "a new lease lands on the relay selected now"
    );

    // The owner's lease is on the old relay until the keeper asks for it again.
    let on_the_new_relay = |rig: &Rig| {
        let live: Vec<_> = rig
            .leases_for(&owner)
            .into_iter()
            .filter(|lease| lease.live)
            .collect();
        live.len() == 1 && live[0].relay_url == relays.later.url.as_str()
    };
    for _ in 0..8 {
        if on_the_new_relay(&rig) {
            break;
        }
        rig.time_passes(MIN_ASK_GAP + Duration::from_secs(1));
        rig.pass().await;
    }
    assert!(
        on_the_new_relay(&rig),
        "the owner's lease was replaced by one on the relay new leases land on: {:?}",
        rig.leases_for(&owner)
    );
    assert!(
        rig.leases_for(&owner)
            .iter()
            .any(|lease| lease.lease_id == first.lease_id && lease.ended_for == Some("finished")),
        "and the lease on the old relay was ended"
    );
    assert!(rig.holds(&owner));
    rig.until_homed_on(&relays.later.url).await;
}

/// KR-REQ-17.34: when the host restarts with leases on two relays, before the leases on the older
/// one were replaced, it does not forget which relay new leases land on. It holds its endpoint to
/// one of them, replaces each lease on the other with one the service installs where it installs
/// new leases, and the first of those sets where the rest go: all end on that relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_restarts_with_leases_on_two_relays_ends_with_them_on_one() {
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.served.web().name_relay_url(relays.later.url.as_str());
    let (_phone, record) = rig.pairs().await;
    rig.until("the new device holds a lease", || rig.holds(&record))
        .await;
    assert_eq!(
        rig.live_lease_for(&owner).expect("a lease").relay_url,
        relays.leased.url.as_str(),
        "the owner's lease is still on the old relay"
    );

    let rig = rig.restarted().await;
    let on_one_relay = |rig: &Rig| {
        [&owner, &record].iter().all(|device| {
            let live: Vec<_> = rig
                .leases_for(device)
                .into_iter()
                .filter(|lease| lease.live)
                .collect();
            live.len() == 1 && live[0].relay_url == relays.later.url.as_str()
        })
    };
    for _ in 0..8 {
        if on_one_relay(&rig) {
            break;
        }
        rig.time_passes(MIN_ASK_GAP + Duration::from_secs(1));
        rig.pass().await;
    }
    assert!(
        on_one_relay(&rig),
        "the leases were not all moved to the relay new leases land on: {:?} {:?}",
        rig.leases_for(&owner),
        rig.leases_for(&record)
    );
    rig.until_homed_on(&relays.later.url).await;
}

/// KR-REQ-17.51: a host that signed out refills the leases it holds and replaces nothing: a lease
/// on another relay than new leases land on stays where it is, because the replacement would be a
/// new lease with no account to bill it to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_signed_out_does_not_replace_a_lease_on_another_relay() {
    let relays = Relays::spawn().await;
    let rig = relays.rig().await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served.web().name_relay_url(relays.later.url.as_str());
    let (_phone, record) = rig.pairs().await;
    rig.until("the new device holds a lease", || rig.holds(&record))
        .await;

    rig.host
        .controller()
        .host_account()
        .sign_out()
        .await
        .expect("the host signs out");
    let asked = rig.requests_for(&owner);
    let revoked = rig.requests(REVOKE);
    rig.time_passes(MIN_ASK_GAP + Duration::from_secs(1));
    rig.pass().await;
    rig.pass().await;

    assert_eq!(
        rig.requests_for(&owner),
        asked,
        "nothing was asked for the pair"
    );
    assert_eq!(rig.requests(REVOKE), revoked, "and nothing was ended");
    assert_eq!(
        rig.live_lease_for(&owner).map(|lease| lease.lease_id),
        Some(first.lease_id),
        "the lease stays where it is"
    );
}

/// KR-REQ-17.51: a daemon that starts holds no authorisation, and the question about one can fail
/// for a reason that passes. The leases it holds are refilled all the same under the authorisation
/// their rows name, as they are when the authorisation was held in memory; no new lease is asked
/// for until the question is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_that_cannot_ask_for_its_authorisation_yet_refills_what_it_holds() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let before = rig.live_lease_for(&owner).expect("a lease");
    let asked = rig.requests(SIGN_IN);
    rig.served.web().fail(SIGN_IN, 1, SERVICE_DOWN);
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );

    let rig = rig.restarted().await;
    rig.until("the lease is refilled while the question fails", || {
        rig.live_lease_for(&owner)
            .is_some_and(|lease| lease.expires_at_ms > before.expires_at_ms)
    })
    .await;
    assert_eq!(
        rig.requests(SIGN_IN),
        asked + 1,
        "the question was asked, and failed"
    );
    let (_phone, record) = rig.pairs().await;
    rig.pass().await;
    assert!(
        rig.live_lease_for(&record).is_none(),
        "no lease is asked for a new device before the question is answered"
    );
}

/// KR-REQ-17.34: a host whose configuration lists no relay chose not to use one, and the relay a
/// grant names does not change that: its endpoint is left as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endpoint_that_uses_no_relay_is_left_alone() {
    let chosen: iroh::RelayUrl = "https://127.0.0.1:11".parse().expect("a relay URL");
    let rig = Rig::start_over(
        true,
        8 * 1024 * 1024,
        net_support::loopback(),
        Some(chosen.as_str()),
    )
    .await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    // The pass that wrote the lease may not have finished: one that began after it has.
    rig.pass().await;

    let endpoint = rig
        .host
        .network()
        .endpoint_for_tests()
        .expect("the host is on the network");
    assert!(endpoint.remove_relay(&chosen).await.is_none());
}

/// KR-REQ-17.35: a host that is not signed in has no account to bill, so it asks the service for
/// nothing, and the owner is told to sign it in. A sign-in made without the right to bill relay
/// traffic is the same: the application's own sign-in before it asked for that right. Either way
/// the host asks the service as soon as the person has signed it in, without a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_is_not_signed_in_asks_for_nothing_and_the_owner_is_told() {
    let rig = Rig::start_signed_in(false).await;
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), 0);
    assert_eq!(rig.requests(SIGN_IN), 0, "there is no token to ask with");

    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("not signed in"),
        "{}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("kr account sign-in")),
        "{:?}",
        shown.remedy()
    );

    // A grant from before the application asked for the right to bill relay traffic lacks the
    // scope, and a refresh cannot add it.
    let before = SignIn::new(None);
    before.issue(&rig.served);
    let mut grant = before.issued();
    grant.scopes = vec!["openid".to_owned()];
    rig.host
        .controller()
        .host_account()
        .keep_for_test(grant)
        .await;
    rig.pass().await;
    assert_eq!(rig.requests(ISSUE), 0);
    assert_eq!(
        rig.requests(SIGN_IN),
        0,
        "a token without the scope is not sent"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Warning);

    // The person signs the host in again, and the next pass asks.
    let after = rig.signs_in_again(false).await;
    rig.pass().await;
    rig.until("the owner's device holds a lease", || {
        rig.holds(&rig.owner_device())
    })
    .await;
    assert_eq!(
        rig.opened_by(&after).map(|opened| opened.account_id),
        Some(after.account.clone())
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.35: a host presents its account token only to the account service. A relay lease
/// service that is another service gives the host no account to name: the daemon starts, sends that
/// service no sign-in, no token and no lease request, and `kr doctor` says what to change. The host
/// here is signed in and selects a storage service that is the account service, so that it could
/// present its account, and the lease service is a second server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_service_that_is_not_the_account_service_is_sent_no_token_and_asked_for_no_lease() {
    let account = serve().await;
    let lease_service = serve().await;
    let sign_in = SignIn::new(None);
    sign_in.issue(&account);
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.storage.origin = kr_protocol::scalars::Nullable::some(account.origin().to_owned());
    document.relay.origin = kr_protocol::scalars::Nullable::some(lease_service.origin().to_owned());
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document,
        net_support::AccountAt::Origin(account.origin().to_owned()),
    )
    .await;
    host.controller()
        .host_account()
        .keep_for_test(sign_in.issued())
        .await;
    tokio::time::timeout(
        Duration::from_secs(180),
        host.controller()
            .relay_keeper()
            .expect("a keeper")
            .after_a_pass(),
    )
    .await
    .expect("the keeper finishes a pass");

    let web = lease_service.web();
    assert_eq!(web.requests_to(SIGN_IN), 0);
    assert_eq!(web.requests_to(ISSUE), 0);
    assert!(
        web.arrived().iter().all(|arrived| arrived.token.is_none()),
        "the account token went to no request of the lease service"
    );
    let mut local = host.client().await;
    let doctor: HostDoctorResult = net_support::pairing::read(&mut local, Method::HostDoctor, &())
        .await
        .expect("the host's diagnostics");
    let shown = doctor
        .checks
        .into_iter()
        .find(|check| check.id() == "relay-leases")
        .expect("the keeper's check");
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("relay.origin"),
        "{}",
        shown.detail()
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
/// service, and the host's next request is refused. The service refuses the same sign-in for ever,
/// so the host takes a fresh token once, is refused again, and tells the owner to sign it in. The
/// host cannot know that the lease is gone, so its record still names the lease. A new sign-in is
/// the owner's way out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_authorisation_ends_the_leases_and_the_owner_is_told_to_sign_in() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served
        .web()
        .withdraw_relay_authorisation(&rig.payer().authorisation_id);
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
            .is_some_and(|remedy| remedy.contains("withdrawn")),
        "{:?}",
        shown.remedy()
    );

    // The standing wait has passed: the sign-in is asked for again, the service refuses it, and the
    // host takes one fresh token for it and no more.
    let refreshes = rig.served.web().token_refreshes();
    let asked = rig.requests(SIGN_IN);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    assert_eq!(
        rig.requests(SIGN_IN),
        asked + 2,
        "the sign-in and the one repeat"
    );
    assert_eq!(rig.served.web().token_refreshes(), refreshes + 1);
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("kr account sign-in")),
        "{:?}",
        shown.remedy()
    );
}

/// KR-REQ-17.51: the lease a host holds was asked for under an authorisation the account then
/// withdrew, and the service fenced it. The person signs the host in again, which is another grant.
/// The next refill names the lease and the withdrawn authorisation, the service turns it back as
/// forbidden, and the host ends the lease and asks for the pair afresh under the new sign-in,
/// before the lease would have run out of itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_asked_for_under_a_withdrawn_authorisation_is_replaced_under_the_new_sign_in() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.served
        .web()
        .withdraw_relay_authorisation(&rig.payer().authorisation_id);

    // The first refill is turned back: nothing under the withdrawn authorisation is accepted.
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    assert!(rig.live_lease_for(&owner).is_none());

    let again = rig.signs_in_again(true).await;
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    assert_eq!(
        rig.lease_in_the_record(&owner),
        Some(Some(first.lease_id)),
        "the lease has not run out, so only the refill can replace it"
    );
    rig.pass().await;
    rig.until(
        "the owner's device holds a lease under the new sign-in",
        || rig.holds_a_live_lease_under(&owner, &again),
    )
    .await;
}

/// KR-REQ-17.51: the account that pays is part of what a lease was asked for. A host signed in as
/// another account ends the lease it holds under the first account, with the reason that the payer
/// withdrew, and asks for the pair under the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_signed_in_as_another_account_ends_the_lease_issued_under_the_first() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let old = rig.live_lease_for(&owner).expect("a lease");
    let another = rig.signs_in_again(false).await;
    rig.pass().await;

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
        rig.opened_by(&another)
            .map(|opened| opened.authorisation_id)
            .as_deref()
    );
}

/// KR-REQ-17.51: a new sign-in of the same account opens another authorisation, and a lease keeps
/// the one it was asked for under for as long as it lives: its refills name the authorisation it
/// was issued under, and are accepted, with no ending and no second lease. The pairs the host
/// leases from then on are asked for under the new sign-in's authorisation, and the host stops
/// presenting the previous sign-in, so its authorisation is not renewed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_sign_in_leaves_a_running_lease_under_the_authorisation_it_was_asked_for() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.payer();
    let held = rig.live_lease_for(&owner).expect("a lease");
    let revoked = rig.requests(REVOKE);

    let again = rig.signs_in_again(true).await;
    let (_phone, record) = rig.pairs().await;
    rig.until("the new device holds a lease under the new sign-in", || {
        rig.opened_by(&again).is_some_and(|opened| {
            rig.live_lease_for(&record).is_some_and(|lease| {
                lease.authorisation_id.as_deref() == Some(opened.authorisation_id.as_str())
            })
        })
    })
    .await;
    let second = rig.opened_by(&again).expect("the new authorisation");
    assert_ne!(second.authorisation_id, first.authorisation_id);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let refilled = rig.live_lease_for(&owner).expect("the lease");
    assert_eq!(refilled.lease_id, held.lease_id, "the lease is kept");
    assert!(
        refilled.expires_at_ms > held.expires_at_ms,
        "and refilled: {} then {}",
        held.expires_at_ms,
        refilled.expires_at_ms
    );
    assert_eq!(
        refilled.authorisation_id.as_deref(),
        Some(first.authorisation_id.as_str())
    );
    assert!(
        !held.sponsored && !refilled.sponsored,
        "the role the lease was issued with is kept, though the authorisation is no longer the default"
    );
    let refill = rig
        .bodies(ISSUE)
        .into_iter()
        .rfind(|body| body["lease_id"] == held.lease_id)
        .expect("the refill");
    assert_eq!(
        refill["payer"]["account"]["authorisation_id"], first.authorisation_id,
        "the refill names the authorisation the lease was issued under"
    );
    assert_eq!(rig.requests(REVOKE), revoked, "nothing was ended");
    assert_eq!(
        rig.leases_for(&owner).len(),
        1,
        "and no second lease opened"
    );
    assert_eq!(
        rig.payer().valid_until_ms,
        first.valid_until_ms,
        "the previous sign-in is no longer presented, so its authorisation is not renewed"
    );
}

/// KR-REQ-17.51: a lease that stays under the authorisation of an earlier sign-in is renewed by
/// nothing, so near the end of that authorisation its refills move no deadline and the lease ends
/// where the authorisation does. The keeper looks again at that deadline, and asks for the pair
/// under the new sign-in's authorisation as soon as the lease has ended, not at its next poll.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keeper_looks_again_where_a_lease_under_an_earlier_sign_in_ends() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.payer();
    let again = rig.signs_in_again(true).await;
    rig.pass().await;

    // Time goes on until the first authorisation is near its end: the lease is refilled under it
    // and its deadline is the authorisation's.
    let step = Duration::from_secs(u64::from(LEASE_SECONDS) - REFILL_WHEN_LEFT.as_secs() + 1);
    let mut steps = 0;
    while rig
        .live_lease_for(&owner)
        .is_none_or(|lease| lease.expires_at_ms != first.valid_until_ms)
    {
        steps += 1;
        assert!(
            steps < 20,
            "the lease never reached the end of its authorisation"
        );
        rig.time_passes(step);
        rig.pass().await;
    }

    // Twenty seconds before it ends, the refill moves nothing, and the keeper waits for the end.
    let left = |rig: &Rig| {
        let lease = rig.live_lease_for(&owner).expect("a lease");
        lease.expires_at_ms.saturating_sub(rig.wall.now_ms())
    };
    rig.time_passes(Duration::from_millis(left(&rig) - 20_000));
    let waits = rig.timer.asked_for().len();
    rig.pass().await;
    rig.until("the keeper waits for the end of the lease", || {
        rig.timer.asked_for()[waits..]
            .iter()
            .any(|wait| *wait <= Duration::from_secs(21))
    })
    .await;

    // The lease ends, and the pair is given another under the new sign-in at that pass.
    rig.time_passes(Duration::from_secs(21));
    rig.pass().await;
    assert!(
        rig.holds_a_live_lease_under(&owner, &again),
        "the pair is asked for under the authorisation now in force as soon as the lease ends"
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
    let second_sign_in = SignIn::new(None);
    second_sign_in.issue(&other);
    let Rig {
        host,
        served,
        owner: owner_keys,
        host_key,
        wall,
        ..
    } = rig;
    let mut stopped = host.shut_down().await;
    net_support::write_relay_document(stopped.tree(), Some(other.origin()));
    stopped.account_service_stays_at(other.origin());
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    host.controller()
        .host_account()
        .keep_for_test(second_sign_in.issued())
        .await;
    let rig = Rig {
        host,
        served: other,
        timer,
        wall,
        owner: owner_keys,
        host_key,
        sign_in: second_sign_in,
    };
    rig.pass().await;
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
            .is_some_and(|remedy| remedy.contains("asks the service again")),
        "{:?}",
        shown.remedy()
    );
}

/// KR-REQ-17.51: the authorisation a sign-in opens lasts an hour from each time it is asked for.
/// The host asks again once fewer than half an hour remains, and is answered with the same
/// authorisation, so the lease billed under it is refilled in place and keeps its identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authorisation_is_asked_for_again_once_less_than_half_its_hour_remains() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.payer();
    let held = rig.live_lease_for(&owner).expect("a lease");
    assert_eq!(rig.requests(SIGN_IN), 1);

    let step =
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1);
    for _ in 0..5 {
        rig.time_passes(step);
        rig.pass().await;
    }
    assert_eq!(
        rig.requests(SIGN_IN),
        1,
        "twenty-five minutes in, more than half an hour remains"
    );

    rig.time_passes(step);
    rig.pass().await;
    assert_eq!(rig.requests(SIGN_IN), 2);
    let renewed = rig.payer();
    assert_eq!(renewed.authorisation_id, first.authorisation_id);
    assert!(renewed.valid_until_ms > first.valid_until_ms);
    let lease = rig.live_lease_for(&owner).expect("the lease");
    assert_eq!(lease.lease_id, held.lease_id, "refilled in place");
    assert_eq!(
        lease.authorisation_id.as_deref(),
        Some(first.authorisation_id.as_str())
    );
}

/// KR-REQ-17.51: a host that did not ask for more than an hour, as one that was asleep does not,
/// finds the authorisation it holds has lapsed. It asks for the authorisation again before it asks
/// for a lease, and the service brings it back in place, so the pair is leased under the same
/// authorisation. A request for a lease under one that is no longer in force would be refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_authorisation_is_asked_for_again_before_the_next_lease_request() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.payer();
    let held = rig.live_lease_for(&owner).expect("a lease");
    let before = rig.served.web().arrived().len();

    rig.time_passes(Duration::from_secs(3 * 3600 / 2 + 200));
    rig.pass().await;
    let after: Vec<String> = rig
        .served
        .web()
        .arrived()
        .into_iter()
        .skip(before)
        .map(|arrived| arrived.path)
        .collect();
    assert_eq!(
        after.first().map(String::as_str),
        Some(SIGN_IN),
        "{after:?}"
    );
    assert!(after.iter().any(|path| path == ISSUE), "{after:?}");
    let renewed = rig.payer();
    assert_eq!(renewed.authorisation_id, first.authorisation_id);
    assert!(renewed.valid_until_ms > first.valid_until_ms);
    let lease = rig.live_lease_for(&owner).expect("a lease");
    assert_ne!(lease.lease_id, held.lease_id, "the first ran out meanwhile");
    assert_eq!(
        lease.authorisation_id.as_deref(),
        Some(first.authorisation_id.as_str()),
        "the same authorisation, brought back in place"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.51: the question about the authorisation fails, as it does when the account system
/// cannot be reached, while the authorisation the host holds has half an hour left. The leases the
/// host holds are refilled under it all the same, and the question is asked again, not at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_question_about_the_authorisation_that_fails_does_not_stop_the_refills() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let held = rig.live_lease_for(&owner).expect("a lease");
    let step =
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1);
    for _ in 0..5 {
        rig.time_passes(step);
        rig.pass().await;
    }
    let asked = rig.requests(SIGN_IN);
    let before = rig.live_lease_for(&owner).expect("a lease");
    let refills = rig.requests_for(&owner);
    rig.served.web().fail(SIGN_IN, 1, SERVICE_DOWN);

    // Half an hour is left: the host asks, is not answered, and refills under what it holds.
    rig.time_passes(step);
    rig.pass().await;
    assert_eq!(rig.requests(SIGN_IN), asked + 1);
    assert!(
        rig.requests_for(&owner) > refills,
        "the lease was refilled in the pass in which the question failed"
    );
    let refilled = rig.live_lease_for(&owner).expect("the lease");
    assert_eq!(refilled.lease_id, held.lease_id);
    assert!(
        refilled.expires_at_ms > before.expires_at_ms,
        "and its deadline moved"
    );
    rig.pass().await;
    assert_eq!(
        rig.requests(SIGN_IN),
        asked + 1,
        "and the question waits before it is asked again"
    );
}

/// KR-REQ-17.51: a host that signs out and then loses the lease the service ended asks for nothing:
/// the replacement it would ask for has no account to be billed to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_signed_out_does_not_ask_for_the_lease_the_service_ended() {
    let rig = Rig::start().await;
    let owner = rig.owner_device();
    let first = rig.live_lease_for(&owner).expect("a lease");
    rig.host
        .controller()
        .host_account()
        .sign_out()
        .await
        .expect("the host signs out");
    rig.served.web().end_relay_lease(&first.lease_id);
    let asked = rig.requests(ISSUE);

    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    assert!(
        rig.live_lease_for(&owner).is_none(),
        "no replacement was asked for"
    );
    assert!(
        rig.requests(ISSUE) <= asked + 2,
        "only the refill and the probe reached the service"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Warning);
}

/// KR-REQ-17.51: the service answers `REAUTHENTICATION_REQUIRED` for a token that ended in transit
/// as it does for a sign-in that ended. The host takes a fresh token once and asks again, and does
/// not ask the person while that mends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_the_service_turns_back_is_refreshed_once_before_the_person_is_asked() {
    let rig = Rig::start().await;
    let again = rig.signs_in_again(true).await;
    rig.served.web().expire_token(&again.access);
    let refreshes = rig.served.web().token_refreshes();
    let asked = rig.requests(SIGN_IN);

    rig.pass().await;
    assert_eq!(rig.served.web().token_refreshes(), refreshes + 1);
    assert_eq!(
        rig.requests(SIGN_IN),
        asked + 2,
        "turned back, then answered"
    );
    assert!(rig.opened_by(&again).is_some());
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// KR-REQ-17.51: the host's own sign-in asks for the right to bill relay traffic to the account
/// when the relay lease service is the account service, so the sign-in a person makes is the one
/// the service accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_sign_in_asks_for_the_right_to_bill_relay_traffic() {
    use kr_protocol::envelope::ActionTarget;
    use kr_protocol::host_account::{
        AccountReport, AccountSignInParams, AccountState, AccountStatusParams,
    };
    use kr_protocol::ids::ActionId;

    let rig = Rig::start_signed_in(false).await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port")
        .local_addr()
        .expect("an address")
        .port();
    rig.host
        .controller()
        .host_account()
        .listen_on(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    let mut local = rig.host.client().await;
    local
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(rig.host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon starts the sign-in");
    let report: AccountReport = local
        .request(Method::AccountStatus, &AccountStatusParams {})
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon reports")
        .to_typed()
        .expect("a report");
    let AccountState::WaitingForBrowser { authorise_url, .. } = report.state else {
        panic!("a sign-in is waiting for the browser: {:?}", report.state);
    };
    let scope = authorise_url
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("scope="))
        .expect("the address names the scopes");
    assert!(
        scope.split('+').any(|asked| asked == "relay.lease"),
        "{scope}"
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
    /// host is signed in again, as the same account when `same_account` is true, and the daemon is
    /// started again. The service finds a pair's lease within the account, and refuses another
    /// authorisation of that account for as long as the lease stands.
    async fn signed_in_again_over_a_lost_answer(same_account: bool) {
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
        let other = rig.signs_in_again(same_account).await;

        let rig = rig.restarted().await;
        rig.until("the pair holds a lease under the new sign-in", || {
            rig.holds_a_live_lease_under(&record, &other)
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
/// asked under. A host signed in as another account asks again under the first payer, which finds
/// the lease and ends it, and then asks under the second: the pair is given a lease under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_account_over_a_request_whose_answer_was_lost_ends_what_the_first_issued() {
    Rig::signed_in_again_over_a_lost_answer(false).await;
}

/// KR-REQ-17.51: the same when the new sign-in is the same account's, which opens another
/// authorisation that the service refuses for a pair whose lease was issued under the first for as
/// long as it stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_sign_in_of_the_account_is_given_the_pair_once_the_first_lease_is_ended() {
    Rig::signed_in_again_over_a_lost_answer(true).await;
}

/// KR-REQ-17.51: the authorisation a request whose answer was lost was made under is withdrawn
/// before the host is signed in again. The service turns the old payer back, no lease can be alive
/// under it, and the host lets the row go instead of holding every ask for the standing wait: the
/// pair is given a lease under the new sign-in at once.
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
        .withdraw_relay_authorisation(&rig.payer().authorisation_id);
    let other = rig.signs_in_again(true).await;

    let rig = rig.restarted().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
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
    /// authorisation `sign_in` opened, whatever other leases the pair holds.
    fn holds_a_live_lease_under(&self, device: &DeviceRecord, sign_in: &SignIn) -> bool {
        self.opened_by(sign_in).is_some_and(|opened| {
            self.leases_for(device).iter().any(|lease| {
                lease.live
                    && lease.authorisation_id.as_deref() == Some(opened.authorisation_id.as_str())
            })
        })
    }

    /// The form in which the record writes the payer a lease was asked for under `sign_in`.
    fn written_for(&self, sign_in: &SignIn) -> Option<String> {
        self.opened_by(sign_in).map(|opened| written_payer(&opened))
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
fn written_payer(payer: &RelayAuthorisationView) -> String {
    format!("{}/{}", payer.account_id, payer.authorisation_id)
}

/// KR-REQ-17.51: the service refuses another authorisation of an account for a pair whose lease
/// stands, also when the lease has run out and the service has not yet ended it. A daemon that was
/// stopped for longer than a lease lives, after a request whose answer was lost, finds the row
/// older than the longest a lease can live. A device that is still paired is asked once more under
/// the payer the row was kept for, which ends what the service holds, and then under the new
/// sign-in's authorisation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_that_aged_before_the_sign_in_changed_is_asked_under_its_own_payer_once_more() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    let other = rig.signs_in_again(true).await;
    // The lease runs out at the service while the daemon is stopped, and the service keeps it
    // installed until something ends it.
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
    let opened = rig.opened_by(&other).expect("the new authorisation");
    assert!(
        rig.leases_for(&record)
            .iter()
            .filter(
                |lease| lease.authorisation_id.as_deref() != Some(opened.authorisation_id.as_str())
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
/// learn: the row is let go with the answer, also where the new sign-in is the same account's, and
/// the pair is asked for under the new sign-in once the allowance is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_that_aged_is_let_go_by_the_answer_that_the_allowance_is_spent() {
    let rig = Rig::start().await;
    let (_phone, record, _first) = rig.pairs_and_loses_the_answer().await;
    let other = rig.signs_in_again(true).await;
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
    rig.served.web().exhaust_relay_allowance(true);

    let rig = rig.restarted().await;
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
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: a request the service refused for good leaves no time on its row, so a sign-in
/// that is made afterwards is not held behind it. The first authorisation bounds one lease at less
/// than the block a new lease holds, so the service refuses every first request; the person signs
/// the host in again, and the pair is given a lease under the new sign-in in the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_first_request_does_not_hold_the_pair_when_the_host_signs_in_again() {
    let rig = Rig::start_bounded_signed_in(true, BLOCK_BYTES / 2).await;
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
    rig.served.web().bound_relay_sign_ins(8 * 1024 * 1024);
    let other = rig.signs_in_again(false).await;

    let rig = rig.restarted().await;
    rig.until(
        "the owner's device holds a lease under the new sign-in",
        || rig.holds_a_live_lease_under(&owner, &other),
    )
    .await;
}

/// KR-REQ-17.51: where the host is signed out, no account can be named and a difference of
/// accounts cannot be read, and a row the service could not answer for is kept: nothing is asked
/// for it and nothing is dropped on the strength of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_stays_while_the_host_is_signed_out() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    let old = written_payer(&rig.payer());
    rig.served.web().retire_relay_of(&first.lease_id);
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
    rig.host
        .controller()
        .host_account()
        .sign_out()
        .await
        .expect("the host signs out");
    let asked = rig.requests(ISSUE);

    let rig = rig.restarted().await;
    rig.pass().await;
    assert_eq!(rig.row_payer(&record), Some(Some(old)));
    assert_eq!(rig.lease_in_the_record(&record), Some(None));
    assert_eq!(
        rig.requests(ISSUE),
        asked,
        "nothing is asked for a pair while there is no account to name"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Warning);
}

/// KR-REQ-17.51: the bound of an authorisation is below the block a lease holds, so the service
/// refuses every request under it as invalid, and the first request of a new device never reaches
/// the service. The row is older than a lease lives when the person signs the host in as another
/// account: that account's payer is not held behind the old one's refusal, and the pair is given a
/// lease under it in the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_under_a_bound_too_small_for_a_block_does_not_hold_another_accounts_payer() {
    let rig = Rig::start_bounded_signed_in(true, BLOCK_BYTES / 2).await;
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
    rig.served.web().bound_relay_sign_ins(8 * 1024 * 1024);
    let other = rig.signs_in_again(false).await;
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: where the new sign-in is the same account's, the row under a bound too small for
/// a block stays, because the service answers invalid in the same words for a lease in its grace
/// window whose hold passes the bound, and the keeper cannot tell the two apart. The owner clears
/// the row by withdrawing the authorisation replaced: the next ask under it is refused as
/// forbidden, the row goes, and the pair is given a lease under the new sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aged_row_of_the_same_account_stays_until_the_authorisation_it_replaced_is_withdrawn() {
    let rig = Rig::start_bounded_signed_in(true, BLOCK_BYTES / 2).await;
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
    let old = rig.payer();
    rig.served.web().bound_relay_sign_ins(8 * 1024 * 1024);
    let other = rig.signs_in_again(true).await;
    rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));

    let rig = rig.restarted().await;
    rig.until("the keeper has been turned back", || {
        rig.timer.asked_for().contains(&STANDING_RETRY)
    })
    .await;
    rig.pass().await;
    assert_eq!(rig.row_payer(&record), Some(Some(written_payer(&old))));
    assert!(
        !rig.holds_a_live_lease_under(&record, &other),
        "nothing is asked for the pair under the new sign-in behind the old one's row"
    );

    rig.served
        .web()
        .withdraw_relay_authorisation(&old.authorisation_id);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: an authorisation that lapsed is let go like one that was withdrawn, and the lease
/// the host never heard of is left to run out: the service ends the leases of a withdrawn
/// authorisation and not those of one that lapses, and the host cannot end a lease it was never
/// told of. The pair is asked for under the new sign-in, another account's, at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_authorisation_is_let_go_and_its_lease_runs_out_by_itself() {
    let rig = Rig::start().await;
    let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
    rig.served
        .web()
        .lapse_relay_authorisation(&rig.payer().authorisation_id);
    let other = rig.signs_in_again(false).await;

    let rig = rig.restarted().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.lease_id == first.lease_id && lease.live),
        "the host was never told of the lease, so it is not ended: it is left to run out"
    );
    assert_eq!(
        rig.row_payer(&record),
        Some(rig.written_for(&other)),
        "the row is the new sign-in's"
    );
}

impl Rig {
    /// A new device's first request is answered and the answer is lost, the relay carrying the
    /// lease is retired, the daemon is stopped for longer than a lease lives, and it is started
    /// again with the host signed in again: as the same account as the first when `same_account`
    /// is true.
    async fn aged_row_of_a_lease_on_a_retired_relay(
        same_account: bool,
    ) -> (Self, DeviceRecord, RelayLeaseView, SignIn, SignIn) {
        let rig = Rig::start().await;
        let old = rig.sign_in.clone();
        let (_phone, record, first) = rig.pairs_and_loses_the_answer().await;
        rig.served.web().retire_relay_of(&first.lease_id);
        let other = rig.signs_in_again(same_account).await;
        rig.time_passes(Duration::from_secs(u64::from(LEASE_SECONDS) + 200));
        let rig = rig.restarted().await;
        (rig, record, first, old, other)
    }
}

/// KR-REQ-17.51: where the new sign-in is another account's, a lease that ran out on a relay the
/// service can no longer bill through is no obstacle to the new payer, and the pair is given a lease
/// under it at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_ran_out_on_a_retired_relay_does_not_hold_another_accounts_payer() {
    let (rig, record, _first, _old, other) =
        Rig::aged_row_of_a_lease_on_a_retired_relay(false).await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other)
    })
    .await;
}

/// KR-REQ-17.51: the service reads a lease's deadline before it asks whether the relay carrying the
/// lease can still be billed through, so the last ask under the old payer fences the lease that
/// ran out and the host ends what that ask finds. Where the new sign-in is the same account's, the
/// pair is given a lease under it at once, with no lease of the old authorisation in its way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_ran_out_on_a_retired_relay_does_not_hold_the_same_accounts_new_sign_in() {
    let (rig, record, first, _old, other) = Rig::aged_row_of_a_lease_on_a_retired_relay(true).await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&record, &other) && rig.endings_owed() == 0
    })
    .await;
    assert!(
        rig.leases_for(&record)
            .iter()
            .any(|lease| lease.lease_id == first.lease_id && !lease.live),
        "the lease that ran out was fenced by the ask"
    );
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
    let old = written_payer(&rig.payer());
    let other = rig.signs_in_again(false).await;
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

    let rig = rig.restarted().await;
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
        || rig.holds_a_live_lease_under(&record, &other) && rig.endings_owed() == 0,
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
    let other = rig.signs_in_again(false).await;

    // The record refuses a row that names no lease, as a disk with no room for it would.
    let rig = rig
        .restarted_after(|tree| {
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
        || rig.holds_a_live_lease_under(&owner, &other) && rig.endings_owed() == 0,
    )
    .await;
    let opened = rig.opened_by(&other).expect("the new authorisation");
    assert!(
        rig.leases_for(&owner)
            .iter()
            .filter(
                |lease| lease.authorisation_id.as_deref() != Some(opened.authorisation_id.as_str())
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
        .withdraw_relay_authorisation(&rig.payer().authorisation_id);
    let other = rig.signs_in_again(false).await;

    let rig = rig.restarted().await;
    rig.until("the pair holds a lease under the new sign-in", || {
        rig.holds_a_live_lease_under(&owner, &other)
    })
    .await;
    assert_eq!(rig.endings_owed(), 0);
    assert_eq!(
        rig.row_payer(&owner),
        Some(rig.written_for(&other)),
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
/// service would answer that the lease was issued to another caller. A sign-in belongs to the first
/// key that presented it, so the service refuses it for the new key; the host takes a fresh token
/// once, is refused again, and the person signs the host in again, as another account here because
/// the service refuses a pair that holds a live lease of the first key to any other key of the same
/// account. It then asks for each pair afresh, under the authorisation that sign-in opened for the
/// new key, and the leases the first key held run out by themselves.
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
        sign_in,
        wall,
        ..
    } = rig;
    let stopped = host.shut_down().await;
    let host_key = net_support::replace_host_authorisation(stopped.tree());
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    let rig = Rig {
        host,
        served,
        timer,
        wall,
        owner: owner_keys,
        host_key,
        sign_in,
    };
    rig.until("the service has refused the first key's sign-in", || {
        rig.requests(SIGN_IN) >= 3
    })
    .await;
    assert_eq!(
        rig.requests(ISSUE),
        1,
        "nothing is asked for a pair that no sign-in of this key pays for"
    );
    let second = rig.signs_in_again(false).await;
    rig.pass().await;
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
    assert!(rig.opened_by(&second).is_some());
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
    let rig = rig
        .restarted_after(|tree| {
            net_support::write_relay_document(tree, Some(&origin));
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

/* -------------------------------------------------------------------------- */
/* A device that has never paired with the host reaches it through the relay   */
/* -------------------------------------------------------------------------- */

/// A device's own key signing a service request as an installation.
#[derive(Debug)]
struct DeviceSigner(kr_crypto::keys::AuthorisationKeyPair);

impl ServiceSigner for DeviceSigner {
    fn signer(&self) -> kr_protocol::service::ServiceRequestSigner {
        kr_protocol::service::ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<kr_protocol::scalars::Signature64> {
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            self.signer().domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(kr_crypto::sign::sign(&self.0, &transcript).expect("a signature"))
    }
}

/// A device running the product's pairing client, with its records on the internal disk, that asks
/// the managed service for an admission as it dials.
struct NewDevice {
    pairing: Arc<kr_client::pairing::candidate::Pairing>,
    _directory: tempfile::TempDir,
}

impl NewDevice {
    /// A device that reaches hosts through relays whose certificates `roots` hold, asks the service
    /// the rig stands in for for an admission when `asks`, and pairs through the rig host's room.
    fn start(rig: &Rig, roots: Vec<Vec<u8>>, asks: bool) -> Self {
        let http =
            asks.then(|| Arc::clone(rig.served.web()) as Arc<dyn kr_client::services::ServiceHttp>);
        Self::start_over(rig, roots, http)
    }

    /// As [`Self::start`], asking the service through the product's own transport to the rig's
    /// loopback listener, which holds a request a test holds open, as the in-process stand-in
    /// cannot: it answers a held request with a dropped connection at once. The transport's
    /// deadlines are longer than any test waits.
    fn start_over_the_listener(rig: &Rig, roots: Vec<Vec<u8>>) -> Self {
        let origin = kr_protocol::service::GatewayOrigin::new(rig.served.origin())
            .expect("the service's origin");
        let http = kr_client::services::HttpService::with(
            origin,
            kr_client::services::HttpDeadlines {
                connect: Duration::from_secs(10),
                read: Duration::from_secs(600),
                total: Duration::from_secs(600),
            },
            kr_client::services::managed_response_limits(),
        )
        .expect("a transport to the service");
        Self::start_over(rig, roots, Some(Arc::new(http)))
    }

    /// A device that asks through `http`, when it asks.
    fn start_over(
        rig: &Rig,
        roots: Vec<Vec<u8>>,
        http: Option<Arc<dyn kr_client::services::ServiceHttp>>,
    ) -> Self {
        use kr_client::pairing::candidate::{Candidate, CandidateRoom, Pairing};
        use kr_client::pairing::link::{EndpointPool, HostLink, IrohLink};
        use kr_client::pairing::paired::PairedHosts;
        use kr_protocol::pairing::{DeviceName, DevicePlatform};

        let keys = DeviceKeys::generate().expect("a device's keys");
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let budget = Arc::new(
            kr_pairing::budget::DurableClientBudgetStore::open(
                directory.path().join("budget"),
                Arc::new(kr_crypto::store::MemoryStore::new()),
                "device",
            )
            .expect("a durable budget"),
        );
        let pool = EndpointPool::new(keys.transport.clone())
            .bound_to("127.0.0.1:0".parse().expect("loopback"))
            .through_relays_only()
            .trusting_relays(roots);
        let mut link = IrohLink::new(Arc::new(pool));
        if let Some(http) = http {
            let origin = kr_protocol::service::GatewayOrigin::new(rig.served.origin())
                .expect("the service's origin");
            let admit = ManagedPairingAdmission::new(
                origin.clone(),
                http,
                Arc::new(DeviceSigner(keys.authorisation.clone())),
            );
            link = link.admitted_by(Arc::new(
                PairingAdmissions::new(Arc::new(admit), &origin).expect("admissions"),
            ));
        }
        let room: Arc<dyn CandidateRoom> = Arc::new(rig.host.room.clone());
        let pairing = Arc::new(Pairing {
            candidate: Candidate::new(
                keys,
                DeviceName::new("A new computer").expect("a name"),
                DevicePlatform::Macos,
                kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
            ),
            budget,
            clock: Arc::new(kr_client::pairing::clock::DeviceClock::current().expect("a clock")),
            room,
            link: Arc::new(link) as Arc<dyn HostLink>,
            hosts: Arc::new(PairedHosts::open(directory.path().join("pairing")).expect("a store")),
        });
        Self {
            pairing,
            _directory: directory,
        }
    }

    /// The same device, with a link that counts what the host answers it and the connections it
    /// opens.
    fn counting(
        mut self,
        answered: &Arc<tokio::sync::watch::Sender<usize>>,
        opened: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        let pairing = Arc::get_mut(&mut self.pairing).expect("a device nothing has started");
        let inner = Arc::clone(&pairing.link);
        pairing.link = Arc::new(Counting {
            inner,
            answered: Arc::clone(answered),
            opened: Arc::clone(opened),
        });
        self
    }

    /// Redeems the direct invitation `text`.
    fn redeem(
        &self,
        text: &str,
    ) -> (
        tokio::task::JoinHandle<
            Result<kr_client::pairing::paired::PairedHost, kr_client::pairing::PairingFailure>,
        >,
        tokio::sync::watch::Receiver<kr_client::pairing::candidate::AttemptState>,
    ) {
        use kr_client::pairing::invitation::{Invitation, read_invitation};
        let Invitation::Direct(payload) =
            read_invitation(text, &kr_protocol::invitation::default_rendezvous_origin())
                .expect("an invitation")
        else {
            panic!("a direct invitation's text reads as a direct invitation");
        };
        let (progress, shown) =
            tokio::sync::watch::channel(kr_client::pairing::candidate::AttemptState::Idle);
        let pairing = Arc::clone(&self.pairing);
        let attempt = tokio::spawn(async move { pairing.pair_directly(&payload, &progress).await });
        (attempt, shown)
    }

    /// Enters the code of a code invitation through the host's room.
    fn enter(
        &self,
        origin: &kr_protocol::pairing::RendezvousOrigin,
        code: &str,
    ) -> tokio::task::JoinHandle<
        Result<kr_client::pairing::paired::PairedHost, kr_client::pairing::PairingFailure>,
    > {
        let (progress, _) =
            tokio::sync::watch::channel(kr_client::pairing::candidate::AttemptState::Idle);
        let pairing = Arc::clone(&self.pairing);
        let origin = origin.clone();
        let code = kr_pairing::code::EnteredCode::parse(code).expect("a code");
        tokio::spawn(async move { pairing.pair_by_code(&origin, &code, &progress).await })
    }

    fn endpoint(&self) -> kr_protocol::scalars::EndpointKey {
        self.pairing.candidate.endpoint_id()
    }
}

impl Rig {
    /// The owner issues a direct invitation for a viewer, and returns its answer and its QR text.
    async fn direct_invitation(&self) -> (kr_protocol::invitation::PairInviteResult, String) {
        use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
        let mut client = self.host.client().await;
        let owner = net_support::pairing::Signer::OwnerDevice(&self.owner);
        let invited = net_support::pairing::invite_direct(
            self.host.environment_id,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView]),
            &owner,
        )
        .await
        .expect("a direct invitation");
        let InviteEntry::Direct { qr_text } = &invited.entry else {
            panic!("a direct invitation is offered as a QR");
        };
        let text = qr_text.as_str().to_owned();
        (invited, text)
    }

    /// The owner issues a code invitation for a viewer, and returns the origin and the code.
    async fn code_invitation(&self) -> (kr_protocol::pairing::RendezvousOrigin, String) {
        use kr_protocol::confirmation::ConfirmationSubject;
        use kr_protocol::invitation::{
            InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams,
        };
        let mut client = self.host.client().await;
        let owner = net_support::pairing::Signer::OwnerDevice(&self.owner);
        let grant = proposal(&[ActionRight::SessionView]);
        net_support::pairing::confirm_subject(
            self.host.environment_id,
            &mut client,
            ConfirmationSubject::IssueInvitation {
                mode: InviteModeKind::Code,
                rendezvous_origin: kr_protocol::scalars::Nullable::null(),
                grant_kind: InviteGrantKind::SessionInvitation,
                proposed_grant: grant.clone(),
            },
            &owner,
        )
        .await
        .expect("answered");
        let invited: kr_protocol::invitation::PairInviteResult = net_support::pairing::mutate(
            self.host.environment_id,
            &mut client,
            Method::PairInvite,
            &PairInviteParams {
                mode: InviteMode::Code {
                    rendezvous_origin: kr_protocol::scalars::Nullable::null(),
                },
                grant_kind: InviteGrantKind::SessionInvitation,
                proposed_grant: grant,
            },
        )
        .await
        .expect("a code invitation");
        let InviteEntry::Code {
            rendezvous_origin,
            code,
            ..
        } = &invited.entry
        else {
            panic!("a code invitation is offered as a code");
        };
        (rendezvous_origin.clone(), code.as_str().to_owned())
    }

    /// The owner approves the device that redeemed `invited`.
    async fn approves(&self, invited: &kr_protocol::invitation::PairInviteResult) {
        let mut client = self.host.client().await;
        let owner = net_support::pairing::Signer::OwnerDevice(&self.owner);
        net_support::pairing::confirm_candidate(
            self.host.environment_id,
            &mut client,
            invited.invitation_id,
            &owner,
        )
        .await
        .expect("the owner approves");
    }
}

/// Waits until an attempt shows the value both devices display, or ends.
async fn shows_the_value(
    shown: &mut tokio::sync::watch::Receiver<kr_client::pairing::candidate::AttemptState>,
) {
    use kr_client::pairing::candidate::AttemptState;
    tokio::time::timeout(
        Duration::from_secs(120),
        shown.wait_for(|state| {
            matches!(
                state,
                AttemptState::AwaitingApproval { .. } | AttemptState::Ended { .. }
            )
        }),
    )
    .await
    .expect("the attempt reaches the owner")
    .expect("the attempt runs");
}

/// KR-REQ-10.39, KR-REQ-17.40, KR-REQ-10.54: a device that has never paired with the host pairs with
/// it through the managed relay while the host holds a lease for another device. The relay carries a
/// lease's pair and nothing else, so this device asks the service for the admission that lets the
/// relay forward its pairing, as it dials, and the pairing completes for a device that has no direct
/// path to the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_through_the_managed_relay_while_the_host_holds_a_lease() {
    let relays = Relays::spawn().await;
    let rig = Rig::start_over(
        true,
        8 * 1024 * 1024,
        relays.host(),
        Some(relays.leased.url.as_str()),
    )
    .await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_to(&relays.leased.url).await;
    rig.until_homed_on(&relays.leased.url).await;

    let (invited, text) = rig.direct_invitation().await;
    assert_eq!(
        rig.invitation_relays(),
        vec![relays.leased.url.clone()],
        "the invitation names the relay the host's lease is on"
    );

    let device = NewDevice::start(&rig, relays.roots(), true);
    let before = relays.leased.forwarded();
    let (attempt, mut shown) = device.redeem(&text);
    shows_the_value(&mut shown).await;
    rig.approves(&invited).await;
    let paired = tokio::time::timeout(Duration::from_secs(120), attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect("the device paired with the host");
    assert_eq!(paired.host_endpoint_id, rig.host.network().endpoint_id());

    // It asked the service for this pair at that relay, and the pairing crossed that relay.
    let asked = rig.served.web().relay_admission_requests();
    assert!(
        asked
            .iter()
            .any(|asked| asked.host == paired.host_endpoint_id
                && asked.candidate == device.endpoint()
                && asked.relay_url.trim_end_matches('/')
                    == relays.leased.url.as_str().trim_end_matches('/')),
        "no request for this host, this device and the relay it dialled: {asked:?}"
    );
    assert!(
        relays.leased.forwarded() > before,
        "the pairing crossed the relay"
    );
}

/// KR-REQ-10.39: a service that takes the request for an admission and never answers does not hold a
/// pairing up. The device asks as it dials, waits a short bound for the answer and goes on, and
/// the relay here carries what it is given, so the pairing completes with the request still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_never_answers_for_an_admission_does_not_stop_a_pairing() {
    const ADMISSION: &str = "/api/relay/admission";

    let relays = Relays::spawn().await;
    let rig = Rig::start_over(
        true,
        8 * 1024 * 1024,
        relays.host(),
        Some(relays.leased.url.as_str()),
    )
    .await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_to(&relays.leased.url).await;
    rig.until_homed_on(&relays.leased.url).await;
    let (invited, text) = rig.direct_invitation().await;

    rig.served.web().fail(ADMISSION, 1, Moment::Hold);
    let device = NewDevice::start_over_the_listener(&rig, relays.roots());
    let (attempt, mut shown) = device.redeem(&text);
    shows_the_value(&mut shown).await;
    rig.approves(&invited).await;
    let paired = tokio::time::timeout(Duration::from_secs(120), attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect("the device paired with the host");
    assert_eq!(paired.host_endpoint_id, rig.host.network().endpoint_id());

    // The service was asked, and was still holding the request when the pairing was done: it has
    // answered nothing, so the pairing did not wait for it.
    assert!(
        rig.served.web().requests_to(ADMISSION) >= 1,
        "the device never asked the service"
    );
    rig.served.web().release_held();
}

/// KR-REQ-10.39, KR-REQ-17.48, KR-REQ-10.54: a device that is refused free capacity is told so when
/// it could not pair for it, not that the host is out of reach, by an invitation (the next case is
/// the code). The relay here carries nothing for it, as one that has no admission for a device does,
/// so the dial ends by its own deadline, and what the person is told turns on what the service said.
/// With the service's budget available the same failure is the host being unreachable, which is the
/// control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_is_refused_free_capacity_is_told_so_when_it_cannot_pair() {
    use kr_client::pairing::failure::FailureKind;

    let relays = Relays::spawn().await;
    let rig = Rig::start_over(false, 8 * 1024 * 1024, relays.host(), None).await;
    rig.until_homed_on(&relays.configured.url).await;
    // The service carries that relay, so it answers for it.
    rig.served.web().carry_relay(
        relays.configured.url.as_str(),
        kr_service_stand_in::AdmissionBehaviour::Admit,
    );
    // The relay takes no new session from the device, as one that has no admission for it does not.
    relays.configured.refuse_sessions(true);

    // The control: the service has capacity, and the host is still out of reach.
    let (_, text) = rig.direct_invitation().await;
    let device = NewDevice::start(&rig, relays.roots(), true);
    let (attempt, _) = device.redeem(&text);
    let failure = tokio::time::timeout(Duration::from_secs(120), attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect_err("a relay that takes no session carries nothing");
    assert_eq!(failure.kind, FailureKind::HostUnreachable);

    // The service has none to give. The invitation is the same: a dial that reached nothing spent
    // nothing of it.
    rig.served.web().spend_admission_budget(true);
    let device = NewDevice::start(&rig, relays.roots(), true);
    let (attempt, _) = device.redeem(&text);
    let failure = tokio::time::timeout(Duration::from_secs(120), attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect_err("a relay that takes no session carries nothing");
    assert_eq!(failure.kind, FailureKind::RelayCapacity);
}

/// KR-REQ-10.54: a device that pairs by code and is refused free capacity is told that the managed
/// capacity is unavailable, not that the host is out of reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_is_refused_free_capacity_is_told_so_when_it_pairs_by_code() {
    use kr_client::pairing::failure::FailureKind;

    let relays = Relays::spawn().await;
    let rig = Rig::start_over(false, 8 * 1024 * 1024, relays.host(), None).await;
    rig.until_homed_on(&relays.configured.url).await;
    rig.served.web().carry_relay(
        relays.configured.url.as_str(),
        kr_service_stand_in::AdmissionBehaviour::Admit,
    );
    relays.configured.refuse_sessions(true);
    let (origin, code) = rig.code_invitation().await;

    // The service has none to give.
    rig.served.web().spend_admission_budget(true);
    let device = NewDevice::start(&rig, relays.roots(), true);
    let failure = tokio::time::timeout(Duration::from_secs(120), device.enter(&origin, &code))
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect_err("a relay that takes no session carries nothing");
    assert_eq!(failure.kind, FailureKind::RelayCapacity);
}

/// A link that counts what the host answers a device on the connections it opens, and the
/// connections it opens, and otherwise is the product's.
struct Counting {
    inner: Arc<dyn kr_client::pairing::link::HostLink>,
    answered: Arc<tokio::sync::watch::Sender<usize>>,
    opened: Arc<std::sync::atomic::AtomicUsize>,
}

impl kr_client::pairing::link::HostLink for Counting {
    fn dial<'a>(
        &'a self,
        network: &'a kr_protocol::pairing::NetworkConfig,
        endpoint: &'a kr_protocol::scalars::EndpointKey,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<iroh::endpoint::Connection, kr_client::pairing::link::LinkError>,
    > {
        self.inner.dial(network, endpoint)
    }

    fn relay_capacity_refused(
        &self,
        network: &kr_protocol::pairing::NetworkConfig,
        endpoint: &kr_protocol::scalars::EndpointKey,
    ) -> bool {
        self.inner.relay_capacity_refused(network, endpoint)
    }

    fn open_unpaired<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
        identity: &'a kr_transport::handshake::LocalIdentity,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<Box<dyn kr_client::pairing::link::Preauth>, kr_client::pairing::link::LinkError>,
    > {
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let inner = self.inner.open_unpaired(connection, identity).await?;
            Ok(Box::new(CountedAnswers {
                inner,
                answered: Arc::clone(&self.answered),
            }) as Box<dyn kr_client::pairing::link::Preauth>)
        })
    }

    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a kr_client::pairing::paired::PairedHost,
        identity: &'a kr_transport::handshake::LocalIdentity,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<
            Arc<dyn kr_client::transport::ControlTransport>,
            kr_client::pairing::link::LinkError,
        >,
    > {
        self.inner.connect_paired_transport(host, identity)
    }

    fn visit_paired_transport<'a>(
        &'a self,
        host: &'a kr_client::pairing::paired::PairedHost,
        identity: &'a kr_transport::handshake::LocalIdentity,
        in_use: &'a kr_client::pairing::link::HostInUse<'a>,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<
            Arc<dyn kr_client::transport::ControlTransport>,
            kr_client::pairing::link::LinkError,
        >,
    > {
        self.inner.visit_paired_transport(host, identity, in_use)
    }

    fn hold<'a>(
        &'a self,
        network: &'a kr_protocol::pairing::NetworkConfig,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<kr_client::pairing::link::EndpointHold, kr_client::pairing::link::LinkError>,
    > {
        self.inner.hold(network)
    }
}

/// A pre-authorisation surface that counts the host's answers.
struct CountedAnswers {
    inner: Box<dyn kr_client::pairing::link::Preauth>,
    answered: Arc<tokio::sync::watch::Sender<usize>>,
}

impl kr_client::pairing::link::Preauth for CountedAnswers {
    fn selection(&self) -> &kr_protocol::hello::HostSelection {
        self.inner.selection()
    }

    fn finish<'a>(
        &'a mut self,
        request: &'a kr_protocol::pairing::PairFinishRequest,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<kr_protocol::preauth::PairFinishResult, kr_client::pairing::link::LinkError>,
    > {
        Box::pin(async move {
            let answer = self.inner.finish(request).await;
            self.answered.send_modify(|count| *count += 1);
            answer
        })
    }

    fn redeem<'a>(
        &'a mut self,
        params: &'a kr_protocol::preauth::PairRedeemParams,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<kr_protocol::preauth::PairRedeemResult, kr_client::pairing::link::LinkError>,
    > {
        Box::pin(async move {
            let answer = self.inner.redeem(params).await;
            self.answered.send_modify(|count| *count += 1);
            answer
        })
    }

    fn status<'a>(
        &'a mut self,
        params: &'a kr_protocol::preauth::PairStatusParams,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<kr_protocol::preauth::PairStatusResult, kr_client::pairing::link::LinkError>,
    > {
        Box::pin(async move {
            let answer = self.inner.status(params).await;
            self.answered.send_modify(|count| *count += 1);
            answer
        })
    }
}

/// KR-REQ-10.39, KR-REQ-17.40: the ceiling an admission carries is enough for a whole attempt. A device
/// pairs through the relay with the owner's approval held until the host has answered it more times
/// than one connection allows, which is when the device moves to a fresh connection, and the bytes
/// the relay carried from the first dial to the paired connection stay under what the service signs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_pairing_through_a_relay_fits_in_the_admission_ceiling() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let relays = Relays::spawn().await;
    let rig = Rig::start_over(
        true,
        8 * 1024 * 1024,
        relays.host(),
        Some(relays.leased.url.as_str()),
    )
    .await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_held_to(&relays.leased.url).await;
    rig.until_homed_on(&relays.leased.url).await;
    let (invited, text) = rig.direct_invitation().await;

    let device = NewDevice::start(&rig, relays.roots(), true);
    let answered = Arc::new(tokio::sync::watch::channel(0usize).0);
    let opened = Arc::new(AtomicUsize::new(0));
    let device = device.counting(&answered, &opened);

    // The host's request for a lease for this device is not begun on until the pairing is over, so
    // that nothing but the admission can have carried it: the worst case, and the one the ceiling
    // has to hold for.
    rig.served.web().fail_matching(
        ISSUE,
        serde_json::json!({ "destination_endpoint_key": device.endpoint() }),
        1,
        Moment::Gate,
    );
    let before = relays.leased.forwarded();
    let (attempt, mut shown) = device.redeem(&text);
    shows_the_value(&mut shown).await;
    // The owner takes their time: the host has answered the device more often than one connection
    // allows, so the device has moved to another.
    let in_all = kr_transport::preauth::PreAuthLimits::default().max_requests;
    tokio::time::timeout(
        Duration::from_secs(300),
        answered.subscribe().wait_for(|count| *count > in_all),
    )
    .await
    .expect("the device is answered more times than one connection allows")
    .expect("the count is kept");
    rig.approves(&invited).await;
    let paired = tokio::time::timeout(Duration::from_secs(120), attempt)
        .await
        .expect("the attempt ends")
        .expect("the attempt ran")
        .expect("the device paired with the host");
    assert_eq!(paired.host_endpoint_id, rig.host.network().endpoint_id());

    // The host's request for a lease for the new device has reached the stand-in's gate, so the
    // pairing was over before it was begun on. It is released now, and the final sample is taken once
    // the service has recorded the lease: the paired connection is inside the window, and the lease
    // the host takes for it is what carries it from here.
    let destination = serde_json::json!(device.endpoint());
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            // The count is read before the arrivals are looked at, so a request that comes between
            // the two is one the wait for the next does not miss.
            let asked = rig.served.web().requests_to(ISSUE);
            if rig.served.web().arrived().iter().any(|arrived| {
                arrived.path == ISSUE && arrived.body["destination_endpoint_key"] == destination
            }) {
                break;
            }
            rig.served.web().requests_reach(ISSUE, asked + 1).await;
        }
    })
    .await
    .expect("the host's request for the new device's lease reaches the service");
    rig.served.web().release_held();
    rig.until(
        "the service has recorded the host's lease for the new device",
        || {
            rig.served.web().relay_leases().iter().any(|lease| {
                lease.source == device.endpoint() || lease.destination == device.endpoint()
            })
        },
    )
    .await;
    let carried = relays.leased.forwarded() - before;
    assert!(
        opened.load(Ordering::SeqCst) >= 2,
        "the device moved to a fresh connection while it waited"
    );
    assert!(
        carried < kr_service_stand_in::ADMISSION_BYTES,
        "a whole pairing carried {carried} bytes through the relay, and an admission allows {}",
        kr_service_stand_in::ADMISSION_BYTES
    );
    println!("== a whole pairing carried {carried} bytes through the relay");
}
