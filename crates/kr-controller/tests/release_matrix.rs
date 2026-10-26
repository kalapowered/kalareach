//! The host reading the signed release matrix, through a real daemon: a managed service that
//! publishes it signed, a lease keeper that asks the service for leases, and `kr doctor`.
//!
//! KR-REQ-17.46: client, relay and discovery compatibility are explicit in the signed release
//! matrix, and unsupported skew returns a route error with the configured alternatives and never
//! resets host authority or terminates a worker. What is held here is the daemon's part: it reads
//! the matrix when it starts and on a schedule, keeps the newest accepted copy in a file, refuses a
//! build the verified matrix lists no tier for a new lease with the route error, and leaves
//! everything else going: a lease it holds is refilled, a paired device's connection is as it was,
//! and a reply that is not accepted, a service that does not answer and a copy it cannot trust
//! change nothing.
//!
//! The service is the stand-in held to the Worker's source, signing the matrix with a key the test
//! makes and the daemon is given to pin. Every wait the daemon asks for is held by the test, and
//! what each case decides on is what the stand-in saw arrive, by path.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::AccountToken;
use kr_client::services::account::{IssuedGrant, RefreshToken};
use kr_client::services::matrix::{Pins, Saved};
use kr_controller::relay_leases::{LEASE_SECONDS, REFILL_WHEN_LEFT, STANDING_RETRY};
use kr_controller::release_matrix::{DOCTOR_READ_BOUND, PERIOD, RETRIES, STALE_AFTER};
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_service_stand_in::{Moment, RelayLeaseView, Served, serve, signed_release_matrix};
use net_support::{Device, Host, MovedWall, ReleaseMatrixStage, pair_with, proposal};
use serde_json::{Value, json};
use tokio::sync::watch;

const ISSUE: &str = "/api/relay/lease";
const SIGN_IN: &str = "/api/relay/payer-authorisation/sign-in";
const MATRIX: &str = "/api/release-matrix";

/// The scopes a host's sign-in is issued when it asks for the right to bill relay traffic.
const SIGNED_IN_SCOPES: [&str; 2] = ["openid", "relay.lease"];

/// A sign-in of the host: the account, the grant the account system recorded for it, and the access
/// and refresh tokens it holds.
#[derive(Clone, Debug)]
struct SignIn {
    account: String,
    grant: String,
    access: String,
    refresh: String,
}

impl SignIn {
    fn new() -> Self {
        Self {
            account: "account-matrix".to_owned(),
            grant: "grant-matrix".to_owned(),
            access: "access-matrix".to_owned(),
            refresh: "refresh-matrix".to_owned(),
        }
    }

    fn issued(&self) -> IssuedGrant {
        IssuedGrant {
            access_token: AccountToken::new(&self.access).expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new(&self.refresh).expect("a token"),
            scopes: SIGNED_IN_SCOPES.map(str::to_owned).to_vec(),
            subject: self.account.clone(),
        }
    }

    fn issue(&self, served: &Served) {
        served
            .web()
            .issue_grant_token(&self.access, &self.account, &self.grant, &SIGNED_IN_SCOPES);
        served.web().issue_grant_refresh(&self.refresh, &self.grant);
    }
}

/// A matrix whose two tiers list the clients from 0.1.0 up to `highest`.
fn matrix(revision: &str, highest: PackageVersion) -> Value {
    let tier = |id: &str, compatible: bool| {
        json!({
            "id": id,
            "compatible": compatible,
            "note": "",
            "client": { "minimum": "0.1.0", "maximum": highest.to_string() },
            "relay": { "minimum": "1.2.0", "maximum": "1.2.99" },
            "discovery": { "minimum": "1.2.0", "maximum": "1.2.99" },
        })
    };
    json!({
        "schemaVersion": 1,
        "revision": revision,
        "issuedAt": "2026-10-27",
        "installedClientWindowDays": 90,
        "alternatives": ["direct", "self-hosted-relay", "self-hosted-discovery"],
        "tiers": [tier("compatible", true), tier("current", false)],
    })
}

/// A matrix that lists the build that is running: it reaches the end of its minor number.
fn supporting(revision: &str) -> Value {
    matrix(
        revision,
        PackageVersion::new(PACKAGE_VERSION.major, PACKAGE_VERSION.minor, 99),
    )
}

/// A matrix that lists every build before this one's minor number, and so not this one.
fn skewing(revision: &str) -> Value {
    matrix(
        revision,
        PackageVersion::new(
            PACKAGE_VERSION.major,
            PACKAGE_VERSION.minor.saturating_sub(1),
            99,
        ),
    )
}

/// Everything one test holds: a daemon whose lease service is the stand-in, which also publishes
/// the signed release matrix, and the clocks.
struct Rig {
    host: Host,
    served: Served,
    timer: Arc<HeldTimer>,
    matrix_timer: Arc<HeldTimer>,
    wall: MovedWall,
    owner: DeviceKeys,
    matrix_key: AuthorisationKeyPair,
    sign_in: SignIn,
}

impl Rig {
    /// A daemon signed in with permission to bill relay traffic, over a service that publishes
    /// `published`, whose first read of the matrix has ended.
    async fn start(published: Option<&Value>) -> Self {
        let rig = Self::start_without_waiting(published, None).await;
        rig.until_a_matrix_pass(1).await;
        rig
    }

    /// As [`Self::start`], not waiting for the first read, with the configuration document sending
    /// the daemon's requests through `proxy` when one is given.
    async fn start_without_waiting(published: Option<&Value>, proxy: Option<String>) -> Self {
        let served = serve().await;
        served.web().bound_relay_sign_ins(8 * 1024 * 1024);
        let matrix_key = AuthorisationKeyPair::generate().expect("a key pair");
        if let Some(published) = published {
            served.web().publish_release_matrix(
                &serde_json::to_vec(&signed_release_matrix(published, &matrix_key))
                    .expect("a reply"),
            );
        }
        let timer = HeldTimer::held();
        let matrix_timer = HeldTimer::held();
        let wall = MovedWall::new();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host_keys = DeviceKeys::generate().expect("host keys");
        let sign_in = SignIn::new();
        sign_in.issue(&served);
        let host = Host::start_with_relay_and_matrix(
            &owner,
            &host_keys,
            Some(served.origin()),
            net_support::AccountAt::Origin(served.origin().to_owned()),
            Some(sign_in.issued()),
            net_support::loopback(),
            Arc::clone(&timer) as _,
            wall.clocks(),
            Some(ReleaseMatrixStage {
                timer: Arc::clone(&matrix_timer),
                pins: Pins::of(vec![*matrix_key.public()]),
                proxy_url: proxy,
            }),
        )
        .await;
        Self {
            host,
            served,
            timer,
            matrix_timer,
            wall,
            owner,
            matrix_key,
            sign_in,
        }
    }

    fn publish(&self, matrix: &Value) {
        self.served.web().publish_release_matrix(
            &serde_json::to_vec(&signed_release_matrix(matrix, &self.matrix_key)).expect("a reply"),
        );
    }

    fn keeper(&self) -> &kr_controller::relay_leases::RelayKeeper {
        self.host.controller().relay_keeper().expect("a keeper")
    }

    fn passes_of_the_matrix(&self) -> watch::Receiver<u64> {
        self.host
            .controller()
            .release_matrix()
            .expect("a reader of the release matrix")
            .passes()
    }

    /// Waits until the reader of the matrix has finished `count` reads.
    async fn until_a_matrix_pass(&self, count: u64) {
        let mut passes = self.passes_of_the_matrix();
        tokio::time::timeout(
            Duration::from_secs(180),
            passes.wait_for(|made| *made >= count),
        )
        .await
        .expect("the reader finishes a read")
        .expect("the reader runs");
    }

    /// The period passes for the reader of the matrix, and it reads once more.
    async fn the_matrix_is_read_again(&self) {
        let before = *self.passes_of_the_matrix().borrow();
        self.matrix_timer.advance(PERIOD);
        self.matrix_timer.release_held();
        self.until_a_matrix_pass(before + 1).await;
    }

    async fn pass(&self) {
        tokio::time::timeout(Duration::from_secs(180), self.keeper().after_a_pass())
            .await
            .expect("the keeper finishes a pass");
    }

    /// Waits until the condition holds, checked after each pass the keeper finishes.
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

    fn owner_device(&self) -> DeviceRecord {
        self.host.owner.clone().expect("an owner")
    }

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

    fn time_passes(&self, by: Duration) {
        self.wall.advance(by);
        self.served.web().advance_relay_clock(by);
    }

    fn live_lease_for(&self, device: &DeviceRecord) -> Option<RelayLeaseView> {
        self.served
            .web()
            .relay_leases()
            .into_iter()
            .find(|lease| lease.destination == device.endpoint_id && lease.live)
    }

    fn state_dir(&self) -> std::path::PathBuf {
        self.host
            .tree()
            .environment()
            .registry_database()
            .parent()
            .expect("the state directory")
            .to_path_buf()
    }

    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.state_dir().join("relay-leases.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the host's record of leases")
    }

    /// Whether the host's record names a lease for the device.
    fn holds(&self, device: &DeviceRecord) -> bool {
        self.connection()
            .query_row(
                "SELECT lease_id FROM relay_leases WHERE destination = ?1",
                [device.endpoint_id.as_bytes().as_slice()],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .is_some()
    }

    fn bodies(&self, path: &str) -> Vec<Value> {
        self.served
            .web()
            .arrived()
            .into_iter()
            .filter(|arrived| arrived.path == path)
            .map(|arrived| arrived.body)
            .collect()
    }

    /// How many lease requests for one device's pair reached the service.
    fn requests_for(&self, device: &DeviceRecord) -> usize {
        let destination = serde_json::to_value(device.endpoint_id).expect("an endpoint");
        self.bodies(ISSUE)
            .iter()
            .filter(|body| body["destination_endpoint_key"] == destination)
            .count()
    }

    async fn check(&self, id: &str) -> DoctorCheck {
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

    /// Stops the daemon, lets `change` alter its tree, and starts it again on the tree.
    async fn restarted_after(self, change: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        let Self {
            host,
            served,
            owner,
            matrix_key,
            sign_in,
            wall,
            matrix_timer,
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
            matrix_timer,
            wall,
            owner,
            matrix_key,
            sign_in,
        }
    }
}

fn kept_file(tree: &kr_ipc::testing::TempHost) -> std::path::PathBuf {
    tree.environment()
        .registry_database()
        .parent()
        .expect("the state directory")
        .join(kr_controller::release_matrix::record::FILE_NAME)
}

/* -------------------------------------------------------------------------- */
/* C5: a skewed host loses only new leases                                     */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: a build the verified matrix lists no tier for is refused a new lease with the
/// route error and everything else goes on: the lease the host holds is refilled, a paired
/// device's connection answers as before, and the doctor names the skew. A matrix revision that
/// lists the build gives the new leases back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_skewed_host_is_refused_new_leases_keeps_its_working_route_and_gets_new_leases_back() {
    let rig = Rig::start(Some(&supporting("1"))).await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Ok,
        "a build the matrix lists is served"
    );
    let (device, record) = rig.pairs().await;
    rig.until("the paired device holds a lease", || rig.holds(&record))
        .await;
    let session = net_support::connect(&rig.host, &device, &record).await;
    let held = rig.live_lease_for(&owner).expect("the owner's lease");

    // The matrix drops this build, and the host reads it.
    rig.publish(&skewing("2"));
    rig.the_matrix_is_read_again().await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "the doctor names the skew"
    );

    // A new device is refused its lease: nothing reaches the service for it, and the keeper says
    // so. The payer's sign-in goes on.
    let signed_in = rig.bodies(SIGN_IN).len();
    let (_other_device, other) = rig.pairs().await;
    rig.pass().await;
    assert!(!rig.holds(&other));
    assert_eq!(
        rig.requests_for(&other),
        0,
        "no lease request left the host"
    );
    let keeper = rig.check("relay-leases").await;
    assert_eq!(keeper.status, DoctorStatus::Warning);
    assert!(
        keeper.detail().contains("release matrix"),
        "the keeper names the matrix as the reason and not an unreachable service"
    );
    assert!(rig.bodies(SIGN_IN).len() >= signed_in);

    // The lease the host holds is refilled, naming itself.
    let issued = rig.bodies(ISSUE).len();
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.pass().await;
    let sent = rig.bodies(ISSUE);
    assert_eq!(sent.len(), issued + 1, "only the refill was sent");
    assert_eq!(sent.last().expect("a refill")["lease_id"], held.lease_id);
    assert_eq!(rig.requests_for(&other), 0);

    // The paired device's connection is as before.
    let doctor: HostDoctorResult = session
        .read(Method::HostDoctor, &())
        .await
        .expect("the device is still served");
    assert!(!doctor.checks.is_empty());

    // A revision that lists the build opens the gate again.
    rig.publish(&supporting("3"));
    rig.the_matrix_is_read_again().await;
    assert_eq!(rig.check("release-matrix").await.status, DoctorStatus::Ok);
    rig.time_passes(STANDING_RETRY);
    rig.pass().await;
    rig.until("the new device holds a lease", || rig.holds(&other))
        .await;
}

/* -------------------------------------------------------------------------- */
/* C6: offline, stale, the kept file and the origin rule                       */
/* -------------------------------------------------------------------------- */

/// A kept copy of `published`, as an earlier run of this build would have written it for `origin`.
fn kept_copy(
    published: &Value,
    key: &AuthorisationKeyPair,
    origin: &str,
    read_by: &str,
    fetched_at_ms: u64,
) -> Vec<u8> {
    let body = serde_json::to_string(&signed_release_matrix(published, key)).expect("a reply");
    serde_json::to_vec(&Saved {
        origin: origin.to_owned(),
        read_by: read_by.to_owned(),
        fetched_at_ms,
        body,
    })
    .expect("a file")
}

/// KR-REQ-17.46: a copy an earlier run kept, verified again at the start, decides before the service
/// is read, and a service that does not answer leaves it deciding. A host with a held skew is told
/// the refusal even though it has no authorisation cached yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_skew_gates_the_first_lease_request_and_a_service_that_is_down_leaves_it_deciding() {
    let rig = Rig::start(Some(&skewing("2"))).await;
    let file = kept_file(rig.host.tree());
    assert!(file.exists(), "the accepted copy was kept");

    // The service publishes nothing when the daemon starts again, and holds the answer.
    rig.served.web().withdraw_release_matrix();
    let rig = rig.restarted_after(|_| {}).await;
    rig.until_a_matrix_pass(1).await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "the kept copy decides"
    );
    assert!(
        file.exists(),
        "a read that failed leaves the file as it was"
    );

    // A device paired now is refused before the service is asked, though this daemon holds no
    // authorisation yet, and the keeper says why.
    let (_device, record) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests_for(&record), 0);
    let keeper = rig.check("relay-leases").await;
    assert_eq!(keeper.status, DoctorStatus::Warning);
    assert!(keeper.detail().contains("release matrix"));
}

/// KR-REQ-17.46: a host with no copy asks nothing of the matrix, says it has not read it, and warns
/// once a read has failed; the lease requests go on throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_copy_nothing_is_gated_and_the_check_says_the_matrix_is_not_read() {
    let rig = Rig::start_without_waiting(None, None).await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    rig.until_a_matrix_pass(1).await;
    let check = rig.check("release-matrix").await;
    assert_eq!(
        check.status,
        DoctorStatus::Warning,
        "the service publishes none, and the host asks again by itself"
    );
    assert!(rig.holds(&owner), "and the lease request was never gated");
    assert!(!kept_file(rig.host.tree()).exists(), "nothing was kept");
}

/// KR-REQ-17.46: a kept copy that cannot be trusted is no copy: signed by a key this build does not
/// pin, read from another origin, read by another build, damaged, or lacking a member. Nothing is
/// gated, and the next accepted read writes the file again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_copy_that_cannot_be_trusted_is_no_copy_and_is_written_again() {
    let stranger = AuthorisationKeyPair::generate().expect("a key pair");
    let build = PACKAGE_VERSION.to_string();
    for variant in [
        "signed by a key this build does not pin",
        "read from another origin",
        "read by another build",
        "damaged",
        "lacking a member",
    ] {
        let rig = Rig::start(Some(&supporting("2"))).await;
        let origin = rig.served.origin().to_owned();
        let skew = skewing("9");
        let content: Vec<u8> = match variant {
            "signed by a key this build does not pin" => {
                kept_copy(&skew, &stranger, &origin, &build, 1)
            }
            "read from another origin" => kept_copy(
                &skew,
                &rig.matrix_key,
                "https://elsewhere.example",
                &build,
                1,
            ),
            // A skew an older build found does not close the gate for this one.
            "read by another build" => kept_copy(&skew, &rig.matrix_key, &origin, "0.1.0", 1),
            "damaged" => b"{ this is not a kept copy".to_vec(),
            _ => br#"{"origin":"x","read_by":"0.1.0"}"#.to_vec(),
        };
        // The service is down when the daemon starts again, so only the file can speak.
        rig.served.web().withdraw_release_matrix();
        let rig = rig
            .restarted_after(|tree| {
                std::fs::write(kept_file(tree), &content).expect("a file");
            })
            .await;
        rig.until_a_matrix_pass(1).await;
        let (_device, record) = rig.pairs().await;
        rig.until("the new device holds a lease", || rig.holds(&record))
            .await;
        assert_ne!(
            rig.check("release-matrix").await.status,
            DoctorStatus::Ok,
            "{variant}: the failed read is said"
        );

        // The service publishes again: the next accepted read writes the file.
        rig.publish(&supporting("3"));
        rig.the_matrix_is_read_again().await;
        let kept: Saved =
            serde_json::from_slice(&std::fs::read(kept_file(rig.host.tree())).expect("a file"))
                .unwrap_or_else(|_| panic!("{variant}: the file is a kept copy again"));
        assert_eq!(kept.origin, origin, "{variant}");
    }
}

/// KR-REQ-17.46: a reply that is not accepted leaves the file as it was, and a copy that cannot be
/// written still decides in memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_reply_leaves_the_file_and_a_failed_write_leaves_the_copy_deciding() {
    let rig = Rig::start(Some(&supporting("5"))).await;
    let file = kept_file(rig.host.tree());
    let before = std::fs::read(&file).expect("a kept copy");

    // An older revision, and a reply signed by a key this build does not pin.
    rig.publish(&supporting("4"));
    rig.the_matrix_is_read_again().await;
    assert_eq!(std::fs::read(&file).expect("a file"), before);
    let stranger = AuthorisationKeyPair::generate().expect("a key pair");
    rig.served.web().publish_release_matrix(
        &serde_json::to_vec(&signed_release_matrix(&skewing("6"), &stranger)).expect("a reply"),
    );
    rig.the_matrix_is_read_again().await;
    assert_eq!(std::fs::read(&file).expect("a file"), before);
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "the refusal is said"
    );

    // The file cannot be replaced: a directory stands in its place. The accepted skew still gates.
    std::fs::remove_file(&file).expect("the file goes");
    std::fs::create_dir(&file).expect("a directory");
    rig.publish(&skewing("7"));
    rig.the_matrix_is_read_again().await;
    let (_device, record) = rig.pairs().await;
    rig.pass().await;
    assert_eq!(rig.requests_for(&record), 0, "the copy in memory decides");
}

/// A listener that counts the connections made to it and refuses every one.
struct Refusing {
    port: u16,
    connections: Arc<std::sync::atomic::AtomicUsize>,
}

impl Refusing {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let port = listener.local_addr().expect("an address").port();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, connections }
    }

    fn count(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// KR-REQ-17.46: a daemon built for tests never reads the managed service's own origin. The
/// configuration sends every request through a listener that counts and refuses, so a daemon that
/// did read it would show as a connection here and never reach a real service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_test_build_never_reads_the_managed_origin_itself() {
    let refusing = Refusing::start().await;
    let served = serve().await;
    let matrix_key = AuthorisationKeyPair::generate().expect("a key pair");
    let owner = DeviceKeys::generate().expect("owner keys");
    let host_keys = DeviceKeys::generate().expect("host keys");
    let host = Host::start_with_relay_and_matrix(
        &owner,
        &host_keys,
        Some(kr_client::services::account::ACCOUNT_ORIGIN),
        net_support::AccountAt::Managed,
        None,
        net_support::loopback(),
        HeldTimer::held(),
        MovedWall::new().clocks(),
        Some(ReleaseMatrixStage {
            timer: HeldTimer::held(),
            pins: Pins::of(vec![*matrix_key.public()]),
            proxy_url: Some(format!("http://127.0.0.1:{}", refusing.port)),
        }),
    )
    .await;
    assert!(host.controller().release_matrix().is_none());
    assert_eq!(refusing.count(), 0);
    assert_eq!(served.web().requests_to(MATRIX), 0);
    let mut local = host.client().await;
    let doctor: HostDoctorResult = net_support::pairing::read(&mut local, Method::HostDoctor, &())
        .await
        .expect("diagnostics");
    let check = doctor
        .checks
        .into_iter()
        .find(|check| check.id() == "release-matrix")
        .expect("the check");
    assert_eq!(check.status, DoctorStatus::NotApplicable);
}

/* -------------------------------------------------------------------------- */
/* C7: the moments                                                             */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: the matrix is read once when the daemon starts, again only when the period has
/// passed, and after a read that did not succeed at 15 minutes, then an hour, then the period. The
/// kept copy speaks before the first read of a restart ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_matrix_is_read_at_start_and_on_its_schedule() {
    let rig = Rig::start(Some(&skewing("2"))).await;
    assert_eq!(rig.served.web().requests_to(MATRIX), 1, "one read at start");
    let asked = rig.matrix_timer.asked_for();
    assert!(
        asked
            .first()
            .is_some_and(|wait| *wait >= PERIOD && *wait <= PERIOD + PERIOD / 10),
        "the wait after a read that succeeded is the period and a tenth at most: {asked:?}"
    );

    // Nothing is read until the period is released. Then the service publishes nothing, and each
    // read that fails waits as the schedule says.
    rig.served.web().withdraw_release_matrix();
    rig.the_matrix_is_read_again().await;
    assert_eq!(rig.served.web().requests_to(MATRIX), 2);
    for _ in 0..2 {
        let before = *rig.passes_of_the_matrix().borrow();
        rig.matrix_timer.advance(Duration::from_secs(60 * 60));
        rig.matrix_timer.release_held();
        rig.until_a_matrix_pass(before + 1).await;
    }
    let asked = rig.matrix_timer.asked_for();
    assert_eq!(asked[1], RETRIES[0], "the first failure waits 15 minutes");
    assert_eq!(asked[2], RETRIES[1], "the second waits an hour");
    assert!(asked[3] >= PERIOD, "and then the period: {asked:?}");

    // On a restart the kept copy speaks while the first read is held.
    rig.publish(&skewing("2"));
    rig.served.web().fail(MATRIX, 1, Moment::Gate);
    let rig = rig.restarted_after(|_| {}).await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "the kept copy decides before the first read ends"
    );
    rig.served.web().release_held();
}

/// KR-REQ-17.46: `kr doctor` reads the matrix when the held copy is older than a quarter of an
/// hour, never twice at once, and a read that ends in an accepted reply makes the copy recent, so
/// the next doctor asks for none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_doctors_at_once_share_one_read_and_a_recent_copy_asks_for_none() {
    let rig = Rig::start(Some(&supporting("2"))).await;
    assert_eq!(rig.served.web().requests_to(MATRIX), 1);
    rig.check("release-matrix").await;
    assert_eq!(
        rig.served.web().requests_to(MATRIX),
        1,
        "a copy a moment old asks for no read"
    );

    // The copy is old: both doctors find it so, and the service holds its answer.
    rig.wall.advance(STALE_AFTER + Duration::from_secs(1));
    rig.matrix_timer.advance(Duration::from_secs(61));
    rig.served.web().fail(MATRIX, 1, Moment::Gate);
    let release = async {
        rig.served.web().requests_reach(MATRIX, 2).await;
        rig.served.web().release_held();
    };
    let (first, second, ()) = tokio::join!(
        rig.check("release-matrix"),
        rig.check("release-matrix"),
        release
    );
    assert_eq!(
        (first.status, second.status),
        (DoctorStatus::Ok, DoctorStatus::Ok)
    );
    assert_eq!(
        rig.served.web().requests_to(MATRIX),
        2,
        "the two doctors shared one read"
    );

    // The read made the copy recent, so a doctor right after asks no read.
    rig.check("release-matrix").await;
    assert_eq!(rig.served.web().requests_to(MATRIX), 2);
}

/// KR-REQ-17.46: a doctor's read ends at its bound when the service holds the answer, and the
/// doctor answers from what the host holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_doctor_read_ends_at_its_bound_when_the_service_holds_the_answer() {
    let rig = Rig::start(Some(&skewing("2"))).await;
    rig.wall.advance(STALE_AFTER + Duration::from_secs(1));
    rig.matrix_timer.advance(Duration::from_secs(61));
    rig.served.web().fail(MATRIX, 1, Moment::Hold);
    let doctor = rig.check("release-matrix");
    let released = async {
        let (wait, release) = rig.matrix_timer.next_wait_under(PERIOD).await;
        assert_eq!(wait, DOCTOR_READ_BOUND);
        release.notify_one();
    };
    let (check, ()) = tokio::join!(doctor, released);
    assert_eq!(
        check.status,
        DoctorStatus::Warning,
        "the doctor answers from the copy it holds"
    );
    rig.served.web().release_held();
}
