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
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult, HostInfoResult};
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult, GrantListParams, GrantListResult};
use kr_service_stand_in::{Moment, RelayLeaseView, Served, serve, signed_release_matrix};
use net_support::worker::{Adopted, Worker};
use net_support::{Device, Host, MovedWall, ReleaseMatrixStage, pair_with, proposal};
use serde_json::{Value, json};
use tokio::sync::watch;

const ISSUE: &str = "/api/relay/lease";
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
        Self::start_configured(1, false, published, proxy).await
    }

    /// As [`Self::start_without_waiting`], for a host that reads no revision below
    /// `first_revision` and, when `relay_only` is set, whose configuration document says it uses
    /// relays only.
    async fn start_configured(
        first_revision: u64,
        relay_only: bool,
        published: Option<&Value>,
        proxy: Option<String>,
    ) -> Self {
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
                pins: Pins::of(vec![*matrix_key.public()]).from_revision(first_revision),
                proxy_url: proxy,
                relay_only,
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

    /// Stops the daemon, starts a session worker on its tree, and starts the daemon again, which
    /// adopts the worker. Waits until the daemon serves the session and has read the matrix.
    async fn with_a_session_worker(self) -> (Self, Worker) {
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
        let worker = Worker::start_reserved(stopped.tree(), 1).await;
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        let adopted = Adopted {
            host,
            owner,
            workers: vec![worker],
        };
        adopted.until_adopted(&adopted.workers[0]).await;
        let Adopted {
            host,
            owner,
            mut workers,
        } = adopted;
        let rig = Self {
            host,
            served,
            timer,
            matrix_timer,
            wall,
            owner,
            matrix_key,
            sign_in,
        };
        rig.until_a_matrix_pass(1).await;
        (rig, workers.remove(0))
    }

    async fn session_of(
        &self,
        session_id: SessionId,
    ) -> Result<SessionReadResult, kr_protocol::error::ProtocolError> {
        let mut local = self.host.client().await;
        net_support::pairing::read(
            &mut local,
            Method::SessionRead,
            &SessionReadParams { session_id },
        )
        .await
    }

    /// What the host says of its authority and of one session's worker, in the answers of
    /// `host.info`, `grant.list`, `device.list` and `session.read`: the controller generation, the
    /// grants, the row of the device `device`, the worker's epoch, state and root process, and, when
    /// `with_revision` is set, the authority revision. Nothing in it moves with time.
    async fn standing_of(
        &self,
        session_id: SessionId,
        device: kr_protocol::ids::DeviceId,
        with_revision: bool,
    ) -> Value {
        let mut local = self.host.client().await;
        let info: HostInfoResult = net_support::pairing::read(&mut local, Method::HostInfo, &())
            .await
            .expect("host.info");
        let grants: GrantListResult = net_support::pairing::read(
            &mut local,
            Method::GrantList,
            &GrantListParams {
                session_id: kr_protocol::scalars::Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("grant.list");
        let devices: DeviceListResult = net_support::pairing::read(
            &mut local,
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        )
        .await
        .expect("device.list");
        let row = devices
            .devices
            .iter()
            .find(|summary| summary.device_id == device);
        let worker = match self.session_of(session_id).await {
            Ok(read) => json!({
                "epoch": read.session.session_epoch,
                "state": read.session.state,
                "root_process": read.session.root_process,
                "closure": read.session.closure,
            }),
            Err(error) => json!({ "refused": format!("{:?}", error.code) }),
        };
        json!({
            "generation": info.generation,
            "started_at_ms": info.started_at_ms,
            "live_sessions": info.live_sessions,
            "grants": grants,
            "device": row,
            "authority_revision": with_revision.then_some(devices.authority_revision),
            "worker": worker,
        })
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
    let held = [
        rig.live_lease_for(&owner).expect("the owner's lease"),
        rig.live_lease_for(&record)
            .expect("the paired device's lease"),
    ];

    // The matrix drops this build, and the host reads it.
    rig.publish(&skewing("2"));
    rig.the_matrix_is_read_again().await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "the doctor names the skew"
    );

    // A service that then serves an older revision does not reopen the gate, and the check says
    // what the last read met beside the skew.
    rig.publish(&supporting("1"));
    rig.the_matrix_is_read_again().await;
    let check = rig.check("release-matrix").await;
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(check.detail().contains("older"), "{}", check.detail());

    // A new device is refused its lease: nothing reaches the service for it, and the keeper says
    // so.
    let (other_device, other) = rig.pairs().await;
    rig.pass().await;
    assert!(!rig.holds(&other));
    assert_eq!(
        rig.requests_for(&other),
        0,
        "no lease request left the host"
    );
    assert!(
        rig.timer.asked_for().contains(&STANDING_RETRY),
        "the keeper waits out the standing interval on its clock and does not ask again at once"
    );
    let keeper = rig.check("relay-leases").await;
    assert_eq!(keeper.status, DoctorStatus::Warning);
    assert!(
        keeper.detail().contains("release matrix"),
        "the keeper names the matrix as the reason and not an unreachable service"
    );

    // The leases the host holds are refilled, each naming itself, when the standing interval is
    // over and before the pair with none is asked for again.
    let issued = rig.bodies(ISSUE).len();
    rig.time_passes(
        Duration::from_secs(u64::from(LEASE_SECONDS)) - REFILL_WHEN_LEFT + Duration::from_secs(1),
    );
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    let sent = rig.bodies(ISSUE);
    assert_eq!(sent.len(), issued + 2, "only the two refills were sent");
    for lease in &held {
        assert!(
            sent[issued..]
                .iter()
                .any(|body| body["lease_id"] == lease.lease_id),
            "the lease is refilled by name"
        );
    }
    assert_eq!(rig.requests_for(&other), 0);

    // The paired device's connection is as before, and the device paired while the gate was closed
    // connects under the host's authority and is served.
    let doctor: HostDoctorResult = session
        .read(Method::HostDoctor, &())
        .await
        .expect("the device is still served");
    assert!(!doctor.checks.is_empty());
    let fresh = net_support::connect(&rig.host, &other_device, &other).await;
    let doctor: HostDoctorResult = fresh
        .read(Method::HostDoctor, &())
        .await
        .expect("a device paired under the closed gate is served");
    assert!(!doctor.checks.is_empty());

    // A revision that lists the build opens the gate again.
    rig.publish(&supporting("3"));
    rig.the_matrix_is_read_again().await;
    assert_eq!(rig.check("release-matrix").await.status, DoctorStatus::Ok);
    rig.time_passes(STANDING_RETRY);
    rig.timer.advance(STANDING_RETRY);
    rig.pass().await;
    rig.until("the new device holds a lease", || rig.holds(&other))
        .await;
}

/// KR-REQ-17.46: a skew never resets host authority and never ends a worker. A host runs a real
/// session worker and has a device paired and a session shared with it. The matrix drops the
/// host's build and the gate closes. A device paired under the closed gate meets the refusal: no
/// lease request for it leaves the host. What `host.info`, `grant.list`, `device.list` and
/// `session.read` say of the controller generation, the grants, the first device's row and the
/// worker's epoch, state and root process is what they said before the skew; the first device is
/// served on the connection it had; and the answers, with the authority revision, are the same
/// again when a revision that lists the build reopens the gate. The comparison is shown to see a
/// change: a grant withdrawn makes it differ, and so does a worker that ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_skew_leaves_the_hosts_authority_and_its_session_worker_as_they_were() {
    let rig = Rig::start(Some(&supporting("2"))).await;
    let (rig, worker) = rig.with_a_session_worker().await;
    let session_id = worker.session_id;
    let (device, record) = rig.pairs().await;
    let share = net_support::worker::share(
        &rig.host,
        session_id,
        &device,
        &record,
        kr_protocol::sharing::RoleSelection::plain(kr_protocol::sharing::SessionRole::Viewer),
    )
    .await;
    let session = net_support::connect(&rig.host, &device, &record).await;
    let gate = rig
        .host
        .controller()
        .release_matrix()
        .expect("a reader of the release matrix")
        .gate();
    assert!(
        gate.closed().is_none(),
        "a build the matrix lists is served"
    );
    let before = rig.standing_of(session_id, record.device_id, false).await;
    let running = rig
        .session_of(session_id)
        .await
        .expect("the session is served")
        .session;
    assert_eq!(running.state, SessionState::Live, "the worker is running");
    assert!(
        running.root_process.0.is_some(),
        "the worker reports the process it runs the shell in, which the comparison holds"
    );

    // The matrix drops this build, and the host reads it: the gate is closed.
    rig.publish(&skewing("3"));
    rig.the_matrix_is_read_again().await;
    assert!(gate.closed().is_some(), "the build is in no tier");
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning
    );

    // A device paired now meets the closed gate: the keeper's pass sends nothing for it.
    let (_other_device, other) = rig.pairs().await;
    rig.pass().await;
    assert!(!rig.holds(&other));
    assert_eq!(
        rig.requests_for(&other),
        0,
        "no lease request left the host"
    );

    // Nothing the host says of its authority or of the worker has moved, and the device that was
    // paired before is served on the connection it had.
    assert_eq!(
        rig.standing_of(session_id, record.device_id, false).await,
        before
    );
    let doctor: HostDoctorResult = session
        .read(Method::HostDoctor, &())
        .await
        .expect("the device is still served");
    assert!(!doctor.checks.is_empty());
    let closed = rig.standing_of(session_id, record.device_id, true).await;

    // A revision that lists the build opens the gate, and the answers are the same again.
    rig.publish(&supporting("4"));
    rig.the_matrix_is_read_again().await;
    assert!(gate.closed().is_none());
    assert_eq!(
        rig.standing_of(session_id, record.device_id, true).await,
        closed
    );

    // The comparison sees what it claims to: a grant withdrawn changes the answers.
    net_support::worker::revoke(&rig.host, share.grant_id).await;
    let after_revoking = rig.standing_of(session_id, record.device_id, true).await;
    assert_ne!(after_revoking["grants"], closed["grants"]);

    // And a worker that ends: the daemon no longer reports the worker it reported.
    worker.stop().await;
    assert_ne!(
        rig.standing_of(session_id, record.device_id, true).await["worker"],
        closed["worker"]
    );
}

/// KR-REQ-17.46: a service rolled back to the publication that listed no build of this product
/// gates nothing on a host that holds no copy: the check says the reply was not accepted, the lease
/// requests go on, nothing is kept, and the first revision the host reads is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_publication_below_the_first_revision_a_host_reads_gates_nothing() {
    let rig = Rig::start_configured(2, false, Some(&skewing("1")), None).await;
    rig.until_a_matrix_pass(1).await;
    let owner = rig.owner_device();
    rig.until("the owner's device holds a lease", || rig.holds(&owner))
        .await;
    assert_eq!(
        rig.check("release-matrix").await.status,
        DoctorStatus::Warning,
        "a reply that is not accepted is said, and the host asks again by itself"
    );
    assert!(!kept_file(rig.host.tree()).exists(), "nothing was kept");
    let (_device, record) = rig.pairs().await;
    rig.pass().await;
    rig.until("the new device holds a lease", || rig.holds(&record))
        .await;

    // The first revision the host reads decides, as any other does.
    rig.publish(&skewing("2"));
    rig.the_matrix_is_read_again().await;
    assert!(kept_file(rig.host.tree()).exists(), "revision 2 is kept");
    let (_other_device, other) = rig.pairs().await;
    rig.pass().await;
    assert!(!rig.holds(&other), "a skew at the first revision gates");
    assert_eq!(rig.requests_for(&other), 0);
}

/// KR-REQ-17.46: what the lease check offers a skewed host in place of a lease is a path that host
/// can use. A host that uses relays only is not told to connect directly; a host that does not is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_skewed_host_is_offered_only_the_paths_it_can_use() {
    for relay_only in [false, true] {
        let rig = Rig::start_configured(1, relay_only, Some(&skewing("2")), None).await;
        rig.until_a_matrix_pass(1).await;
        let (_device, record) = rig.pairs().await;
        rig.pass().await;
        assert_eq!(rig.requests_for(&record), 0, "the gate is closed");
        let keeper = rig.check("relay-leases").await;
        assert_eq!(keeper.status, DoctorStatus::Warning);
        let remedy = keeper
            .remedy()
            .expect("the check offers a remedy")
            .to_owned();
        assert!(
            remedy.contains("relay you run yourself"),
            "relay_only {relay_only}: {remedy}"
        );
        assert_eq!(
            remedy.contains("directly"),
            !relay_only,
            "relay_only {relay_only}: {remedy}"
        );
    }
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

        // The service publishes a revision above the one the file claimed: the next accepted read
        // writes the file again, as this build's own.
        rig.publish(&supporting("10"));
        rig.the_matrix_is_read_again().await;
        let kept: Saved =
            serde_json::from_slice(&std::fs::read(kept_file(rig.host.tree())).expect("a file"))
                .unwrap_or_else(|_| panic!("{variant}: the file is a kept copy again"));
        assert_eq!(kept.origin, origin, "{variant}");
        assert_eq!(kept.read_by, build, "{variant}: read by this build");
        assert_ne!(kept.fetched_at_ms, 1, "{variant}: written afresh");
        let body: Value = serde_json::from_str(&kept.body).expect("the kept reply");
        assert_eq!(body["matrix"]["revision"], "10", "{variant}");
    }
}

/// KR-REQ-17.46: the file never holds a copy the daemon then refuses to read. The largest reply the
/// transport reads, made of the bytes JSON writes longest, is written and read back, so an accepted
/// revision is not lost at the next start.
#[test]
fn the_largest_reply_the_transport_reads_is_kept_and_read_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let file = kr_controller::release_matrix::record::File::in_dir(directory.path());
    let saved = Saved {
        origin: "https://reach.kala.to".to_owned(),
        read_by: PACKAGE_VERSION.to_string(),
        fetched_at_ms: 7,
        body: "\u{1}".repeat(
            usize::try_from(kr_client::services::matrix::MAX_ANSWER_BYTES).expect("a size"),
        ),
    };
    file.write(&saved).expect("the copy is written");
    assert!(file.load().is_some_and(|loaded| loaded == saved));
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
            relay_only: false,
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
