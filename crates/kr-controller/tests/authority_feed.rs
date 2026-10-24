//! The host's half of the remote authority feed, through a real daemon: a paired device on an
//! authorised connection, a remote owner publishing to a feed that answers as the Worker does, and
//! the host that reads it.
//!
//! Section 10 divides remote revocation between the owner who publishes, the host that judges and
//! carries it out, and the feed that stores both and judges nothing. What is held here is the
//! host's part: a revocation the feed holds reaches a device before the device's first request is
//! answered, not only at the next poll; a request is judged from the host's own records; a host
//! that stops between carrying a request out and acknowledging it finishes it once; the keys that
//! may remove the feed are the owners the host is paired with; and a feed that answers that it
//! removed the host refuses the grants that rest on it, shows it, tells the owner, and leaves the
//! rest.
//!
//! The feed is the stand-in held to a recording of a local Worker. Every wait the daemon asks for
//! is held by the test.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::authority::{AuthorityFeedClient, AuthorityFeedState, RejectionReason};
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_controller::authority_feed::FeedRuntime;
use kr_controller::service::Clocks;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::attention::{AttentionReadParams, AttentionReadResult, AttentionRule};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::ids::{DeviceId, RevocationRequestId};
use kr_protocol::method::Method;
use kr_protocol::pairing::{RevocationCompletion, RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, KeyId, Nullable, Signature64, U64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult, OfflineValidityPolicy};
use kr_service_stand_in::{Moment, Served, serve};
use net_support::{Device, Host, MovedWall, connect, pair_with, paired_dial, proposal};

const AUTHORITY: &str = "/api/authority/sync";

/// A remote owner's installation key, signing as one.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl kr_client::services::ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

/// Everything one test holds: a daemon whose configuration selects a feed, the feed, and the remote
/// owner who publishes to it.
struct Rig {
    host: Host,
    served: Served,
    timer: Arc<HeldTimer>,
    owner: DeviceKeys,
    /// The owner, as a remote owner's client reaches the feed.
    remote: AuthorityFeedClient,
}

fn client_for(origin: &str, key: AuthorisationKeyPair) -> AuthorityFeedClient {
    let gateway = GatewayOrigin::new(origin).expect("an origin");
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    AuthorityFeedClient::new(gateway, http, Arc::new(Installation(key)))
}

impl Rig {
    async fn start() -> Self {
        Self::start_on(Clocks::system()).await
    }

    /// As [`Self::start`], on the clocks a test gives the daemon.
    async fn start_on(clocks: Clocks) -> Self {
        let served = serve().await;
        let timer = HeldTimer::held();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host =
            Host::start_with_feed_on(&owner, served.origin(), Arc::clone(&timer) as _, clocks)
                .await;
        let remote = client_for(served.origin(), owner.authorisation.clone());
        let rig = Self {
            host,
            served,
            timer,
            owner,
            remote,
        };
        // Every pass the start and the pairing of the owner asked for has run: the owner's key is
        // named, and the carrier is waiting out the interval the feed states.
        rig.poll().await;
        rig.until_a_pass_waits().await;
        rig
    }

    fn runtime(&self) -> &FeedRuntime {
        self.host.controller().feed_runtime().expect("a carrier")
    }

    fn feed(&self) -> KeyId {
        self.runtime().feed()
    }

    fn host_device(&self) -> DeviceId {
        DeviceId::new(self.host.environment_id.get())
    }

    fn owner_device(&self) -> DeviceId {
        self.host.owner.as_ref().expect("an owner").device_id
    }

    /// Waits until the daemon has asked for the wait between two passes, which it asks for the
    /// length of the poll interval section 10 fixes at thirty seconds, and returns what ends it.
    async fn until_a_pass_waits(&self) -> Arc<tokio::sync::Notify> {
        let (waited, release) =
            within("the carrier waits between passes", self.timer.next_wait()).await;
        assert_eq!(
            waited,
            Duration::from_secs(30),
            "the carrier polls every thirty seconds while online"
        );
        release
    }

    /// Waits until a pass that began after this call has finished: what a connection waits for, and
    /// what a request published before this call is read by. The carrier's waits stay held.
    async fn poll(&self) {
        self.runtime().synchronised_before_serving().await;
    }

    /// Waits until a pass that began after this call has finished, twice over, which leaves no
    /// pass running that began before the first call and none that a wake stored by then would
    /// start: a pass that a wake started after the first call's ticket was taken has ended before
    /// the second call returns. What a connection waits for is exactly such a pass, and the pass
    /// it starts is then the only one that can read what is published afterwards. The wait for a
    /// synchronisation ends silently at its bound, so the bound is made longer than `within`
    /// allows, and the wait can then end only with its pass or fail the case. The bound stays for
    /// the connection's own wait, which `within` limits as well.
    async fn until_the_carrier_is_idle(&self) {
        self.runtime()
            .wait_for_a_synchronisation_at_most(Duration::from_secs(3600));
        within("the passes the setup asked for end", async {
            self.poll().await;
            self.poll().await;
        })
        .await;
    }

    /// A request the owner signs and publishes, naming `target`, under a fixed identity.
    async fn owner_publishes(&self, id: u8, target: RevocationTarget) -> RevocationRequest {
        let request = self.signed_by(&self.owner.authorisation, id, target);
        self.remote
            .publish(self.feed(), &request, None)
            .await
            .expect("the feed stores the request");
        request
    }

    fn signed_by(
        &self,
        key: &AuthorisationKeyPair,
        id: u8,
        target: RevocationTarget,
    ) -> RevocationRequest {
        kr_pairing::grants::sign_revocation_request(
            key,
            RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16])),
            self.owner_device(),
            self.host_device(),
            target,
            kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
        )
        .expect("a signed request")
    }

    /// What the feed holds, as the owner who published sees it.
    async fn feed_as_the_owner_sees_it(&self) -> AuthorityFeedState {
        self.remote
            .read(self.feed(), None, false)
            .await
            .expect("the feed answers the owner")
    }

    /// A device pairs under a grant with the rights named, and has not connected yet.
    async fn pairs(
        &self,
        rights: &[ActionRight],
    ) -> (Device, kr_controller::service::net::devices::DeviceRecord) {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal(rights)).await;
        (device, record)
    }

    async fn doctor_as(
        &self,
        session: &kr_client::session::Session,
    ) -> Result<HostDoctorResult, kr_client::ClientError> {
        session.read(Method::HostDoctor, &()).await
    }

    /// Stops the daemon and starts it again on its tree, after `edit` has changed what the tree
    /// holds, with the feed unreachable for its next four requests when `feed_down`: the start's
    /// read and the reads a connection asks for. A suite closes its clients before it restarts.
    async fn restarted(
        self,
        feed_down: bool,
        edit: impl FnOnce(&kr_ipc::testing::TempHost),
    ) -> Self {
        let Self {
            host,
            served,
            owner,
            remote,
            ..
        } = self;
        if feed_down {
            // The start's read and the reads a connection asks for before it is served.
            for nth in 1..=4 {
                served.web().fail_with_member(
                    AUTHORITY,
                    "read",
                    nth,
                    Moment::Refuse {
                        status: 503,
                        code: "SERVICE_UNAVAILABLE",
                        retry_after_seconds: None,
                    },
                );
            }
        }
        let stopped = host.shut_down().await;
        edit(stopped.tree());
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        Self {
            host,
            served,
            timer,
            owner,
            remote,
        }
    }

    /// Stops the daemon and starts it again with its configuration document selecting `feed`, a
    /// service that holds nothing of this host. A suite closes its clients before it restarts.
    async fn pointed_at(self, feed: Served) -> Self {
        let Self { host, owner, .. } = self;
        let stopped = host.shut_down().await;
        net_support::write_feed_document(stopped.tree(), Some(feed.origin()));
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        let remote = client_for(feed.origin(), owner.authorisation.clone());
        Self {
            host,
            served: feed,
            timer,
            owner,
            remote,
        }
    }

    /// Stops the daemon and starts it again while the feed cannot be reached, so that what it
    /// knows of the feed is what it wrote down. A suite closes its clients before it restarts.
    async fn restarted_while_the_feed_is_down(self) -> (Host, Served) {
        let Self { host, served, .. } = self;
        for nth in 1..=4 {
            served.web().fail_with_member(
                AUTHORITY,
                "read",
                nth,
                Moment::Refuse {
                    status: 503,
                    code: "SERVICE_UNAVAILABLE",
                    retry_after_seconds: None,
                },
            );
        }
        let stopped = host.shut_down().await;
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        (host, served)
    }

    /// Waits until at least `count` requests of one kind have reached the feed in all.
    async fn until_arrivals(&self, operation: &str, count: usize) {
        within("the request reaches the feed", async {
            while self.arrivals(operation) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    /// How many requests of one kind (`read`, `revise`, `acknowledge`, ...) reached the feed.
    fn arrivals(&self, operation: &str) -> usize {
        self.served
            .web()
            .arrived()
            .iter()
            .filter(|arrived| arrived.path == AUTHORITY && arrived.body.get(operation).is_some())
            .count()
    }

    /// What the feed holds of one request, as its publisher reads it.
    async fn held(
        &self,
        request: &RevocationRequest,
    ) -> kr_client::services::authority::AuthorityFeedRecord {
        self.feed_as_the_owner_sees_it()
            .await
            .record(request.request_id)
            .expect("the record")
            .clone()
    }
}

/// A failure guard for a test that waits on a condition: the tests decide on what the daemon did,
/// and this only keeps one that went wrong from hanging.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(180), work)
        .await
        .unwrap_or_else(|_| panic!("gave up waiting for {what}"))
}

fn devices(id: DeviceId) -> RevocationTarget {
    RevocationTarget::Devices {
        device_ids: [id].into_iter().collect::<CanonicalSet<_>>(),
    }
}

/// How a device that connects while the feed holds a revocation for it is kept from the host.
#[derive(Debug, PartialEq, Eq)]
enum Kept {
    /// The host ended the connection before the handshake was over: the revocation was carried
    /// out, and the connection withdrawn, before the device had read that it was accepted, or the
    /// device's record was already withdrawn.
    Out,
    /// The handshake finished, and the first request was refused.
    Refused,
}

/// Whether `error` is the host ending the connection or refusing the device, and nothing else: the
/// stream or the connection closed under the handshake, or a refusal of the device's authority.
fn is_the_host_ending_the_connection(error: &kr_client::ClientError) -> bool {
    match error {
        kr_client::ClientError::Transport(
            kr_transport::TransportError::Stream(_) | kr_transport::TransportError::Closed(_),
        ) => true,
        kr_client::ClientError::Transport(kr_transport::TransportError::Refused(refusal)) => {
            refusal.code == ErrorCode::PermissionDenied
        }
        _ => false,
    }
}

impl Rig {
    /// Connects a device the feed holds a revocation for, and says how the host kept it out.
    ///
    /// Section 10 asks the host to synchronise at reconnect before affected remote access. The host
    /// does that by finding the revocation as the connection is admitted and carrying it out, which
    /// withdraws the connection it came on. Whether the device has read that it was accepted by
    /// then is the order two tasks ran in: a device that has is refused on its first request, and
    /// one that has not finds the connection ended. Both are the host keeping the device from
    /// every request; what neither may be is a request answered.
    async fn connects_while_a_revocation_is_held(
        &self,
        device: &Device,
        record: &kr_controller::service::net::devices::DeviceRecord,
    ) -> Kept {
        let dialled = within(
            "the host answers the device's connection",
            paired_dial(&self.host, device, record).try_dial(),
        )
        .await;
        match dialled {
            Ok(transport) => {
                let session =
                    kr_client::session::Session::start(Arc::new(transport)).expect("a session");
                within(
                    "the host answers the device's first request",
                    self.doctor_as(&session),
                )
                .await
                .expect_err("the revocation reached the host before the first request");
                Kept::Refused
            }
            Err(error) => {
                assert!(
                    is_the_host_ending_the_connection(&error),
                    "the connection ended for another reason: {error:?}"
                );
                Kept::Out
            }
        }
    }

    /// Waits until the host has carried the revocation out and acknowledged it, which a connection
    /// that ended first does not wait for: the pass that withdrew it may still be writing.
    async fn until_the_revocation_is_acknowledged(&self, request: &RevocationRequest) {
        let mut passes = self.runtime().passes();
        within(
            "the host carries the revocation out and acknowledges it",
            async {
                loop {
                    let _ = *passes.borrow_and_update();
                    let taken = self
                        .host
                        .controller()
                        .authority_revision()
                        .await
                        .expect("a revision")
                        .get()
                        > 0;
                    let acknowledged = self
                        .feed_as_the_owner_sees_it()
                        .await
                        .record(request.request_id)
                        .is_some_and(|held| held.acknowledgement.0.is_some());
                    if taken && acknowledged {
                        return;
                    }
                    passes.changed().await.expect("the carrier runs");
                }
            },
        )
        .await;
    }
}

/// KR-REQ-10.46: a device the feed holds a revocation for is kept from the host on its first
/// connection, with polling off: refused on its first request, or out before the handshake is over.
/// Section 10 asks for the synchronisation before affected remote access, so a poll that has not
/// come yet is no window for the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_feed_holds_a_revocation_for_is_kept_out_on_its_first_connection() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    // The pairing woke the carrier, and its pass must end before the request is published: a pass
    // that began after the request was stored would carry it out before the device dials.
    rig.until_the_carrier_is_idle().await;
    let request = rig.owner_publishes(0xa1, devices(record.device_id)).await;

    // The carrier's wait has not ended: nothing but the connection can have taught the host.
    rig.connects_while_a_revocation_is_held(&phone, &record)
        .await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    assert!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision")
            .get()
            > 0,
        "the revocation took effect"
    );

    // The host acknowledged it as complete under the revision it issued, once.
    let held = rig.feed_as_the_owner_sees_it().await;
    let held = held.record(request.request_id).expect("the record");
    let acknowledged = held.acknowledgement.0.as_ref().expect("acknowledged");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    assert_eq!(
        acknowledged.authority_revision,
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision"),
        "the revision the registry allocated"
    );
    let revisions = rig
        .served
        .web()
        .arrived()
        .iter()
        .filter(|arrived| arrived.path == AUTHORITY && arrived.body.get("revise").is_some())
        .count();
    assert_eq!(revisions, 1, "one revision for one request");
}

/// A host that has already carried the revocation out, in a pass the connection did not start, ends
/// the device's connection before the handshake is over. This is the order the first case may meet
/// on a slow machine, made the only one: the device connects after the host's pass, so the host
/// ends the connection and nothing is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_carried_out_before_a_device_connects_ends_its_connection() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let request = rig.owner_publishes(0xa1, devices(record.device_id)).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;

    assert_eq!(
        rig.connects_while_a_revocation_is_held(&phone, &record)
            .await,
        Kept::Out,
        "the connection ended before the handshake was over"
    );
}

/// KR-REQ-10.46: the host polls its feed every thirty seconds while online, and the poll that
/// follows the interval carries out a revocation published while the device stays connected: the
/// device's next request is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_published_while_a_device_is_connected_is_carried_out_at_the_next_poll() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect("the connection is served while nothing is held for it");
    rig.owner_publishes(0xa2, devices(record.device_id)).await;

    // The interval ends, and the pass that follows carries the revocation out.
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    rig.timer.release_held();
    within("a pass finishes", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
    rig.doctor_as(&session)
        .await
        .expect_err("the poll carried the revocation out");
    let held = rig.feed_as_the_owner_sees_it().await;
    assert!(
        held.records.iter().all(|record| record
            .acknowledgement
            .0
            .as_ref()
            .is_some_and(|ack| ack.completion == RevocationCompletion::Complete)),
        "everything the owner published is acknowledged: {held:?}"
    );
}

/// KR-REQ-10.46: a host that stops after it carried a request out and before it acknowledged it
/// finishes the same request the same way on its next start: the acknowledgement is under the
/// revision the host first issued, there is one revision, and the registry advanced once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_between_carrying_a_request_out_and_acknowledging_it_finishes_it_once() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    // Pairing wakes the carrier, and a pass still running when the fault is armed would meet it,
    // and the pass the poll asks for would then acknowledge the request.
    rig.until_the_carrier_is_idle().await;
    let request = rig.owner_publishes(0xa3, devices(record.device_id)).await;

    // The pass reads the request, issues its revision and acknowledges: the acknowledgement never
    // arrives.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "acknowledge", 1, Moment::Before);
    rig.poll().await;
    let held = rig.feed_as_the_owner_sees_it().await;
    assert!(
        held.record(request.request_id)
            .expect("the record")
            .acknowledgement
            .0
            .is_none(),
        "the acknowledgement was lost"
    );
    let revision = held
        .summary
        .authority_revision
        .0
        .expect("a revision was issued");
    assert_eq!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision"),
        revision,
        "the revision the registry allocated is the one issued"
    );

    let Rig {
        host,
        served,
        remote,
        ..
    } = rig;
    let feed = host.controller().feed_runtime().expect("a carrier").feed();
    let stopped = host.shut_down().await;
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    // The pass it makes as it starts.
    within("the carrier waits between passes", timer.next_wait()).await;

    let held = remote
        .read(feed, None, false)
        .await
        .expect("the feed answers");
    let acknowledged = held
        .record(request.request_id)
        .expect("the record")
        .acknowledgement
        .0
        .as_ref()
        .expect("the restarted host acknowledged it");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    assert_eq!(
        acknowledged.authority_revision, revision,
        "under the revision it first issued"
    );
    assert_eq!(held.summary.authority_revision.0, Some(revision));
    assert_eq!(
        host.controller()
            .authority_revision()
            .await
            .expect("a revision"),
        revision,
        "carried out once"
    );
    drop(served);
}

/// A copy of the registry as it stands, taken while the daemon runs: the earlier state a registry
/// is put back to.
fn a_copy_of_the_registry(host: &Host, name: &str) -> std::path::PathBuf {
    let registry = host.tree().environment().registry_database();
    let copy = registry.with_file_name(name);
    rusqlite::Connection::open(registry)
        .expect("the registry opens")
        .execute("VACUUM INTO ?1", [copy.display().to_string()])
        .expect("the registry is copied");
    copy
}

/// Puts a copy of the registry back where the registry stands, with the host stopped.
fn put_the_registry_back(tree: &kr_ipc::testing::TempHost, copy: &std::path::Path) {
    let registry = tree.environment().registry_database();
    for suffix in ["", "-wal", "-shm"] {
        let mut name = registry.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(name));
    }
    std::fs::copy(copy, &registry).expect("the copy is put back");
}

/// Two devices paired, a copy of the registry taken, and the first revoked from the remote owner's
/// feed, carried out and acknowledged as complete: the state a restore of the copy goes back past.
struct Restorable {
    rig: Rig,
    revoked: (Device, kr_controller::service::net::devices::DeviceRecord),
    kept: (Device, kr_controller::service::net::devices::DeviceRecord),
    earlier: std::path::PathBuf,
    revision: kr_protocol::ids::AuthorityRevision,
}

async fn a_revocation_the_registry_will_lose() -> Restorable {
    let rig = Rig::start().await;
    let revoked = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-earlier.sqlite3");
    let request = rig
        .owner_publishes(0xb1, devices(revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    let held = rig.held(&request).await;
    let acknowledged = held.acknowledgement.0.as_ref().expect("acknowledged");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    let revision = acknowledged.authority_revision;
    Restorable {
        rig,
        revoked,
        kept,
        earlier,
        revision,
    }
}

/// KR-REQ-24.15: a registry put back to an earlier state, together with everything else of the
/// host's that it holds, is found behind the feed, which still holds the revision the host issued.
/// The host carries out again what the feed shows complete, raises the registry to the feed's
/// revision in one barrier, and then decides again: the device that was revoked is refused, the one
/// that was not is served, and the next revocation is numbered above everything the host issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registry_put_back_to_an_earlier_state_is_raised_to_the_feed_and_carries_out_what_it_lost()
 {
    let Restorable {
        rig,
        revoked,
        kept,
        earlier,
        revision,
    } = a_revocation_the_registry_will_lose().await;

    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;

    assert!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision")
            >= revision,
        "the registry is raised to the revision the feed holds"
    );
    // Out before the handshake is over, or refused on its first request: never served.
    rig.connects_while_a_revocation_is_held(&revoked.0, &revoked.1)
        .await;
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the device that was not revoked is served");
    let shown = rig.shown().await;
    assert!(
        shown
            .check
            .is_some_and(|check| !check.detail().contains("catching up")),
        "the host has caught up"
    );
}

/// KR-REQ-24.15: a host that cannot finish catching up with its feed refuses every remote grant
/// while it cannot, says so, and decides again at the pass that does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_cannot_finish_catching_up_refuses_remote_access_until_a_pass_does() {
    let Restorable {
        rig, kept, earlier, ..
    } = a_revocation_the_registry_will_lose().await;

    // The restored registry refuses to move its revision, as one that cannot be written does.
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute_batch(
                    "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision
                         ON environment BEGIN SELECT RAISE(ABORT, 'no room'); END;",
                )
                .expect("the fault is in place");
        })
        .await;
    rig.until_the_carrier_is_idle().await;

    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("catching up"),
        "the host says it is catching up"
    );
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("registry")),
        "and says the registry cannot take the write: {:?}",
        check.remedy()
    );
    let outcome = match paired_dial(&rig.host, &kept.0, &kept.1).try_dial().await {
        Ok(transport) => {
            let session =
                kr_client::session::Session::start(Arc::new(transport)).expect("a session");
            within("the host answers", rig.doctor_as(&session))
                .await
                .map(|_| ())
        }
        Err(error) => Err(error),
    };
    assert!(
        outcome
            .as_ref()
            .is_err_and(|error| error.to_string().contains("catching up")),
        "a device is refused, and told why, while the host is behind its feed: {outcome:?}"
    );

    // The feed turns the next read back. What stops the pass now is the feed, and the host has not
    // stopped being behind it, but the registry is not what to look at.
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    rig.served.web().fail(
        AUTHORITY,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.timer.release_held();
    within("a pass ends at the feed", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
    let check = rig.shown().await.check.expect("the feed check");
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| !remedy.contains("registry")),
        "a pass the feed stopped is not put down to the registry: {:?}",
        check.remedy()
    );

    // The fault clears, and the pass that follows finishes what the first could not.
    rusqlite::Connection::open(rig.host.tree().environment().registry_database())
        .expect("the registry opens")
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the fault is cleared");
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    rig.timer.release_held();
    within("a pass finishes", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
    rig.until_the_carrier_is_idle().await;
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the device is served once the host has caught up");
}

/// KR-REQ-24.15: a host whose registry stands at the feed's revision is not behind, and refuses
/// nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_registry_stands_at_its_feed_is_not_behind_it() {
    let Restorable {
        rig,
        kept,
        revision,
        ..
    } = a_revocation_the_registry_will_lose().await;
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    assert_eq!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision"),
        revision,
        "nothing moved the registry"
    );
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session).await.expect("the device is served");
}

/// KR-REQ-24.15: a registry whose revision stands at the feed's but which lost a withdrawal the
/// feed shows complete is no less restored. A restore that stopped after it moved the revision, or
/// a copy taken at a revision the host reached again by other means, leaves the counter where the
/// feed's is and the withdrawal undone, so the host carries out again what the feed shows complete
/// and the registry does not show done, whatever the counter says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registry_whose_revision_stands_at_the_feed_but_lost_a_withdrawal_carries_it_out_again() {
    let Restorable {
        rig,
        revoked,
        kept,
        earlier,
        revision,
    } = a_revocation_the_registry_will_lose().await;

    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute(
                    "UPDATE environment SET authority_revision = ?1",
                    [i64::try_from(revision.get()).expect("a small revision")],
                )
                .expect("the counter is moved to the feed's");
        })
        .await;
    rig.until_the_carrier_is_idle().await;

    // Out before the handshake is over, or refused on its first request: never served.
    rig.connects_while_a_revocation_is_held(&revoked.0, &revoked.1)
        .await;
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the device that was not revoked is served");
}

/// KR-REQ-24.15: a request the owner published while the host catches up with its feed is judged
/// once the host has: it is not refused for the host's being behind, which is no fault of the
/// request, and it is not carried out on a registry the host is about to raise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_feed_holds_while_the_host_catches_up_is_carried_out_after_it_has() {
    let Restorable {
        rig, kept, earlier, ..
    } = a_revocation_the_registry_will_lose().await;
    // Published before the host stops, and read by the pass that follows the restore.
    let request = rig.owner_publishes(0xb2, devices(kept.1.device_id)).await;

    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;

    let held = rig.held(&request).await;
    assert!(
        held.rejected.0.is_none(),
        "the owner's request is not refused for the host's being behind: {held:?}"
    );
    assert_eq!(
        held.acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the host carried the request out: {held:?}"
    );
    rig.connects_while_a_revocation_is_held(&kept.0, &kept.1)
        .await;
}

impl Rig {
    /// Whether a device paired as `record` is answered by the host: its dial and its first request.
    async fn answers(
        &self,
        device: &Device,
        record: &kr_controller::service::net::devices::DeviceRecord,
    ) -> Result<(), kr_client::ClientError> {
        let transport = paired_dial(&self.host, device, record).try_dial().await?;
        let session = kr_client::session::Session::start(Arc::new(transport)).expect("a session");
        within("the host answers", self.doctor_as(&session))
            .await
            .map(|_| ())
    }
}

/// A host whose registry was put back to before an owner was paired, with the feed showing that
/// owner's completed withdrawal of a device the registry holds live.
struct Unverifiable {
    rig: Rig,
    /// The device the withdrawal names.
    victim: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// A device it does not name.
    kept: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The owner the registry no longer holds, who made the withdrawal.
    owner: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// A share of a session that the other device holds, which a second withdrawal names.
    share: kr_protocol::grant::Grant,
}

/// Pairs the device the withdrawal will name with `victim_rights` and one it will not, which is
/// given a share of a session, takes a copy of the registry, pairs another owner, has that owner
/// withdraw the first device and the share from the feed, carries both out, and puts the registry
/// back to the copy. With `list_stays`, the feed turns back every change the host makes to the
/// keys it lists as permitted to remove it, so it lists the keys it listed before the withdrawal.
async fn a_withdrawal_by_an_owner_the_host_does_not_know(
    victim_rights: &[ActionRight],
    list_stays: bool,
) -> Unverifiable {
    let rig = Rig::start().await;
    let victim = rig.pairs(victim_rights).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    let session_id = net_support::an_open_session(&rig.host).0;
    let share = net_support::worker::share(
        &rig.host,
        session_id,
        &kept.0,
        &kept.1,
        kr_protocol::sharing::RoleSelection::plain(kr_protocol::sharing::SessionRole::Viewer),
    )
    .await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");

    // Another owner is paired after the copy, and revokes the first device from the feed.
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    if list_stays {
        // Every change of the list the host makes from here on, before and after the registry is
        // put back, is turned back: the feed keeps the list the host made before the withdrawal.
        for nth in 1..=64 {
            rig.served.web().fail_with_member(
                AUTHORITY,
                "delegate",
                nth,
                Moment::Refuse {
                    status: 503,
                    code: "SERVICE_UNAVAILABLE",
                    retry_after_seconds: None,
                },
            );
        }
    }
    let sign = |id: u8, target: RevocationTarget| {
        kr_pairing::grants::sign_revocation_request(
            &owner.0.keys().authorisation,
            RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16])),
            owner.1.device_id,
            rig.host_device(),
            target,
            kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
        )
        .expect("a signed request")
    };
    let requests = [
        sign(0xc1, devices(victim.1.device_id)),
        sign(
            0xc2,
            RevocationTarget::Grants {
                grant_ids: [share.grant_id].into_iter().collect::<CanonicalSet<_>>(),
            },
        ),
    ];
    // The feed shows each publisher what it published, so the owner reads its own requests.
    let publisher = client_for(rig.served.origin(), owner.0.keys().authorisation.clone());
    for request in &requests {
        publisher
            .publish(rig.feed(), request, None)
            .await
            .expect("the feed stores the request");
    }
    rig.poll().await;
    let mut passes = rig.runtime().passes();
    for request in &requests {
        let completion = within(
            "the host carries the revocation out and acknowledges it",
            async {
                loop {
                    let _ = *passes.borrow_and_update();
                    let state = publisher
                        .read(rig.feed(), None, false)
                        .await
                        .expect("the feed answers the owner");
                    if let Some(acknowledged) = state
                        .record(request.request_id)
                        .and_then(|record| record.acknowledgement.0.as_ref())
                    {
                        return acknowledged.completion;
                    }
                    passes.changed().await.expect("the carrier runs");
                }
            },
        )
        .await;
        assert_eq!(completion, RevocationCompletion::Complete);
    }

    // The registry goes back to before that owner was paired.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    Unverifiable {
        rig,
        victim,
        kept,
        owner,
        share,
    }
}

fn says_an_owner_is_unknown(outcome: &Result<(), kr_client::ClientError>) -> bool {
    outcome.as_ref().is_err_and(|error| {
        error
            .to_string()
            .contains("an owner this host does not know")
    })
}

/// KR-REQ-24.15: a withdrawal the feed shows complete that the host cannot verify keeps remote
/// access refused until the owner at the machine acts.
///
/// The registry is put back to before an owner was paired, and that owner's completed revocation
/// is in the feed. The registry holds the device it named live and no owner to say whose word that
/// was, so the host does not serve the device, and does not serve any other remote device either.
/// Every pass reads the record again. The owner at the machine revokes the device, and the host
/// serves the others again while the device stays revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_by_an_owner_the_host_does_not_know_keeps_remote_access_refused_until_the_owner_at_the_machine_acts()
 {
    let Unverifiable {
        rig,
        victim,
        kept,
        owner,
        share,
    } = a_withdrawal_by_an_owner_the_host_does_not_know(&[ActionRight::SessionView], false).await;

    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "a device the feed does not name is refused, and told why: {refused:?}"
    );
    let refused = rig.answers(&victim.0, &victim.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "the device the withdrawal names is not served: {refused:?}"
    );
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the host says what it is waiting for"
    );
    assert_eq!(
        check.status,
        DoctorStatus::Warning,
        "a refusal that stands is a warning"
    );
    assert!(check.remedy().is_some(), "and it says what to do about it");
    // It names what the owner at the machine acts on: the device and the share the withdrawals
    // name, the owner who made them as the requests say, and that owner's key.
    let issuer_key = owner.0.keys().authorisation.key_id();
    for named in [
        victim.1.device_id.to_string(),
        share.grant_id.to_string(),
        owner.1.device_id.to_string(),
        issuer_key.as_bytes()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    ] {
        assert!(
            check.detail().contains(&named),
            "{named} is not named in: {}",
            check.detail()
        );
    }

    // The owner at this machine revokes the device the withdrawal names.
    let mut local = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: victim.1.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");
    rig.until_the_carrier_is_idle().await;
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "the share the other withdrawal names is still live, so the host still waits: {refused:?}"
    );
    net_support::worker::revoke(&rig.host, share.grant_id).await;
    rig.until_the_carrier_is_idle().await;

    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the other device is served once the owner at the machine has acted");
    rig.connects_while_a_revocation_is_held(&victim.0, &victim.1)
        .await;
    let shown = rig.shown().await;
    assert!(
        shown
            .check
            .is_some_and(|check| !check.detail().contains("an owner this host does not know")),
        "the host no longer waits"
    );
}

/// KR-REQ-24.15: a device a withdrawal the host cannot verify names keeps no standing over the
/// feed. It is not among the keys the host names as permitted to remove the feed, so removing the
/// feed does not end the refusal for it, while another owner's key is named and does. Else the
/// device the withdrawal would take its standing from could lift the refusal itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_an_unverifiable_withdrawal_names_cannot_end_the_refusal_by_removing_the_feed() {
    let Unverifiable {
        rig, victim, kept, ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        false,
    )
    .await;
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(says_an_owner_is_unknown(&refused), "{refused:?}");

    let named = rig.feed_as_the_owner_sees_it().await.summary.removal_keys;
    assert_eq!(
        named,
        vec![rig.owner.authorisation.key_id()],
        "the owner the host knows is named, and the device the withdrawal names is not"
    );
    let named_device = client_for(rig.served.origin(), victim.0.keys().authorisation.clone());
    named_device
        .remove(rig.feed())
        .await
        .expect_err("a key the host does not name cannot remove the feed");
    // A request the device publishes is not heard either: it has no owner authority, whatever the
    // request names. It names a device the host does not hold, so a host that judged the device by
    // its grant would have refused it for that.
    let request = kr_pairing::grants::sign_revocation_request(
        &victim.0.keys().authorisation,
        RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([0xd1; 16])),
        victim.1.device_id,
        rig.host_device(),
        devices(DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [0xee; 16],
        ))),
        kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
    )
    .expect("a signed request");
    named_device
        .publish(rig.feed(), &request, None)
        .await
        .expect("the feed stores the request");
    rig.poll().await;
    let record = named_device
        .read(rig.feed(), None, false)
        .await
        .expect("the feed answers the device")
        .record(request.request_id)
        .expect("the record")
        .clone();
    assert_eq!(
        record.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "a device the withdrawal names has no owner authority over the feed"
    );
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "the refusal stands after the named device tried: {refused:?}"
    );

    // The control: the owner the host knows can remove the feed, and that ends the refusal.
    rig.the_feed_removes_the_host().await;
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the other device is served once the feed is removed");
}

/// KR-REQ-24.15: a refusal a device a withdrawal names would end by removing the feed stands when
/// the feed still lists that device's key. The feed turns back every change the host makes to the
/// list of keys that may remove it, so the list after the registry is put back is the list from
/// before the withdrawal, and the device removes the feed with it. The removal says nothing of an
/// owner having acted, so the host goes on refusing remote access, as it does until the owner at
/// the machine acts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_still_lists_the_key_of_a_device_a_withdrawal_names_does_not_end_the_refusal_when_removed()
 {
    let Unverifiable {
        rig, victim, kept, ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        true,
    )
    .await;
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(says_an_owner_is_unknown(&refused), "{refused:?}");
    let listed = rig.feed_as_the_owner_sees_it().await.summary.removal_keys;
    assert!(
        listed.contains(&victim.0.keys().authorisation.key_id()),
        "the feed still lists the device's key: {listed:?}"
    );

    client_for(rig.served.origin(), victim.0.keys().authorisation.clone())
        .remove(rig.feed())
        .await
        .expect("the feed takes the removal from a key it lists");
    rig.poll().await;
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "a removal by a key the withdrawal takes the right from does not end the refusal: {refused:?}"
    );
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the host still says what it waits for: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: a request on a page the scan has left behind is judged before the feed counts as
/// read. A scan of more than one pass puts requests off while the host is behind, and the scan
/// that raises the registry is not the synchronisation a connection waits for: another begins,
/// reads the feed from the first request put off, and judges them in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_on_an_earlier_page_is_carried_out_before_the_feed_counts_as_read() {
    let Restorable { rig, kept, .. } = a_revocation_the_registry_will_lose().await;
    rig.until_the_carrier_is_idle().await;
    rig.runtime().read_at_most_pages(1);

    // The owner's request naming the kept device is the first of the feed that is not complete.
    // Others follow it, enough that the feed holds a second page of 64: the feed keeps a publisher
    // to 32 of what the host has not finished with, so strangers publish most of them.
    let request = rig.owner_publishes(0xb3, devices(kept.1.device_id)).await;
    let unknown = |id: u8| {
        devices(DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [id; 16],
        )))
    };
    let strangers = [
        AuthorisationKeyPair::generate().expect("a key"),
        AuthorisationKeyPair::generate().expect("a key"),
    ];
    for id in 1..=65_u8 {
        let (key, client) = match id {
            1..=31 => (&rig.owner.authorisation, &rig.remote),
            32..=63 => (
                &strangers[0],
                &client_for(rig.served.origin(), strangers[0].clone()),
            ),
            _ => (
                &strangers[1],
                &client_for(rig.served.origin(), strangers[1].clone()),
            ),
        };
        client
            .publish(rig.feed(), &rig.signed_by(key, id, unknown(id)), None)
            .await
            .expect("the feed stores the request");
    }

    // The registry falls behind the feed while the host runs.
    rusqlite::Connection::open(rig.host.tree().environment().registry_database())
        .expect("the registry opens")
        .execute("UPDATE environment SET authority_revision = 0", [])
        .expect("the counter is put back");
    rig.poll().await;

    let held = rig.held(&request).await;
    assert_eq!(
        held.acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the request on the first page was carried out before the feed counted as read: {held:?}"
    );
    rig.connects_while_a_revocation_is_held(&kept.0, &kept.1)
        .await;
}

/// A different request under an identity the host already applied is refused as superseded once
/// the feed has dropped the original, and nothing it names is withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_request_under_an_identity_the_host_applied_is_refused_as_superseded() {
    let rig = Rig::start().await;
    let (_first, first_record) = rig.pairs(&[ActionRight::SessionView]).await;
    let (second, second_record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xa4, devices(first_record.device_id))
        .await;
    rig.poll().await;

    // A week later the feed has dropped what the host finished with, and the owner's device (or
    // anything holding its key) publishes another request under the same identity.
    rig.served.web().a_week_passes_in_the_feeds();
    let again = rig
        .owner_publishes(0xa4, devices(second_record.device_id))
        .await;
    rig.poll().await;

    let held = rig.feed_as_the_owner_sees_it().await;
    assert_eq!(
        held.record(again.request_id)
            .expect("the record")
            .rejected
            .0,
        Some(RejectionReason::Superseded)
    );
    let session = connect(&rig.host, &second, &second_record).await;
    rig.doctor_as(&session)
        .await
        .expect("what the second request named was not withdrawn");
}

/// A request is judged from the host's own records: a stranger's, a paired device's that holds no
/// right to manage the host, one addressed to another host and one that names nothing the host
/// knows are each refused with a reason their publisher reads, and withdraw nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_is_judged_from_the_hosts_own_records() {
    let rig = Rig::start().await;
    let (viewer, viewer_record) = rig.pairs(&[ActionRight::SessionView]).await;
    let owner_session = connect(
        &rig.host,
        rig.host.owner_device.as_ref().expect("the owner device"),
        rig.host.owner.as_ref().expect("the owner"),
    )
    .await;
    let target = devices(rig.owner_device());
    let uuid = |byte: u8| kr_protocol::scalars::Uuid::from_bytes([byte; 16]);
    let now = || kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get());

    let stranger = AuthorisationKeyPair::generate().expect("a key");
    let by_a_stranger = rig.signed_by(&stranger, 0xb1, target.clone());
    // A paired device that may view a session and not manage the host.
    let by_a_viewer = kr_pairing::grants::sign_revocation_request(
        &viewer.keys().authorisation,
        RevocationRequestId::new(uuid(0xb2)),
        viewer_record.device_id,
        rig.host_device(),
        target.clone(),
        now(),
    )
    .expect("a signed request");
    let elsewhere = kr_pairing::grants::sign_revocation_request(
        &rig.owner.authorisation,
        RevocationRequestId::new(uuid(0xb3)),
        rig.owner_device(),
        DeviceId::new(uuid(0xee)),
        target.clone(),
        now(),
    )
    .expect("a signed request");
    let nothing = rig.signed_by(
        &rig.owner.authorisation,
        0xb4,
        devices(DeviceId::new(uuid(0xdd))),
    );

    let as_stranger = client_for(rig.served.origin(), stranger.clone());
    let as_viewer = client_for(rig.served.origin(), viewer.keys().authorisation.clone());
    for (client, request) in [
        (&as_stranger, &by_a_stranger),
        (&as_viewer, &by_a_viewer),
        (&rig.remote, &elsewhere),
        (&rig.remote, &nothing),
    ] {
        client
            .publish(rig.feed(), request, None)
            .await
            .expect("the feed stores what any key publishes");
    }
    rig.poll().await;

    let reason = |state: &AuthorityFeedState, request: &RevocationRequest| {
        state
            .record(request.request_id)
            .expect("the record")
            .rejected
            .0
    };
    let seen_by_a_stranger = as_stranger
        .read(rig.feed(), None, false)
        .await
        .expect("a read");
    assert_eq!(
        reason(&seen_by_a_stranger, &by_a_stranger),
        Some(RejectionReason::NoOwnerAuthority)
    );
    let seen_by_a_viewer = as_viewer
        .read(rig.feed(), None, false)
        .await
        .expect("a read");
    assert_eq!(
        reason(&seen_by_a_viewer, &by_a_viewer),
        Some(RejectionReason::NoOwnerAuthority)
    );
    let seen_by_the_owner = rig.feed_as_the_owner_sees_it().await;
    assert_eq!(
        reason(&seen_by_the_owner, &elsewhere),
        Some(RejectionReason::UnknownTarget)
    );
    assert_eq!(
        reason(&seen_by_the_owner, &nothing),
        Some(RejectionReason::UnknownTarget)
    );
    rig.doctor_as(&owner_session)
        .await
        .expect("nothing the owner holds was withdrawn");
    assert_eq!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision"),
        kr_protocol::ids::AuthorityRevision::new(0),
        "a request that is refused advances no revision"
    );
}

/// What the owner at this machine had already withdrawn is covered, not applied a second time: the
/// request is refused as covered by an earlier revocation and issues no revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_for_what_the_owner_at_the_machine_already_withdrew_issues_no_revision() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let mut local = rig.host.client().await;
    let revoked: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: record.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");

    let request = rig.owner_publishes(0xa5, devices(record.device_id)).await;
    rig.poll().await;

    let held = rig.feed_as_the_owner_sees_it().await;
    assert_eq!(
        held.record(request.request_id)
            .expect("the record")
            .rejected
            .0,
        Some(RejectionReason::Superseded)
    );
    assert_eq!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision"),
        revoked.authority_revision,
        "no revision was issued for it"
    );
    assert_eq!(held.summary.authority_revision.0, None);
}

/// What the owner at this machine is shown of the feed, on the local socket.
struct Shown {
    list: DeviceListResult,
    removal_item: Option<kr_protocol::attention::AttentionItem>,
    check: Option<kr_protocol::hostinfo::DoctorCheck>,
}

impl Rig {
    async fn shown(&self) -> Shown {
        let mut local = self.host.client().await;
        let list: DeviceListResult = net_support::pairing::read(
            &mut local,
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: false,
            },
        )
        .await
        .expect("the device list");
        let inbox: AttentionReadResult = net_support::pairing::read(
            &mut local,
            Method::AttentionRead,
            &AttentionReadParams {
                session_id: Nullable::null(),
                include_acknowledged: true,
                max_items: U64::new(100),
                after: Nullable::null(),
            },
        )
        .await
        .expect("the attention inbox");
        let doctor: HostDoctorResult =
            net_support::pairing::read(&mut local, Method::HostDoctor, &())
                .await
                .expect("the host's diagnostics");
        Shown {
            list,
            removal_item: inbox
                .items
                .into_iter()
                .find(|item| item.rule == AttentionRule::AuthorityFeedRemoved),
            check: doctor
                .checks
                .into_iter()
                .find(|check| check.id() == "authority-feed"),
        }
    }

    /// A key the host named removes the feed, and the host reads that.
    async fn the_feed_removes_the_host(&self) {
        self.remote
            .remove(self.feed())
            .await
            .expect("a key the host named removes the feed");
        self.poll().await;
    }

    /// The owner chooses a bounded offline-validity policy, measured from now.
    fn the_owner_bounds_offline_validity(&self) {
        let now = kr_ipc::now_ms().get();
        self.host
            .controller()
            .update_policy(|policy| {
                policy.set_offline_validity(Some(OfflineValidityPolicy {
                    maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
                    last_synchronised_at_ms: Nullable::some(
                        kr_protocol::scalars::TimestampMs::new(now),
                    ),
                }));
            })
            .expect("the owner chooses a bound");
    }
}

/// KR-REQ-10.43 and 10.46: a feed that answers that it removed the host does not refuse the
/// default non-expiring owner grant, which stays account-free and usable without the feed. The
/// removal is shown beside the last synchronisation, and the owner is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_default_owner_grant_stays_usable_after_the_feed_removes_the_host() {
    let rig = Rig::start().await;
    let owner_device = rig.host.owner_device.as_ref().expect("the owner device");
    let owner_record = rig.host.owner.as_ref().expect("the owner");
    let before = rig.shown().await;
    assert!(!before.list.feed_removed);
    assert!(before.removal_item.is_none());
    let synchronised = before
        .list
        .feed_synchronised_at_ms
        .0
        .expect("the host has synchronised the feed");

    rig.the_feed_removes_the_host().await;

    // The default owner grant is account-free: a remote owner connects and is served.
    let session = connect(&rig.host, owner_device, owner_record).await;
    rig.doctor_as(&session)
        .await
        .expect("the default owner grant does not rest on the feed");

    let shown = rig.shown().await;
    assert!(
        shown.list.feed_removed,
        "the device list says the feed removed this host"
    );
    assert_eq!(
        shown.list.feed_synchronised_at_ms.0,
        Some(synchronised),
        "and shows the last successful synchronisation before it, which the removal is not"
    );
    let check = shown.check.expect("the doctor reports the feed");
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(check.detail().contains("removed"), "{}", check.detail());
    let item = shown.removal_item.expect("the owner is told");
    assert!(item.trusted);
    assert_eq!(item.level, kr_protocol::attention::AttentionLevel::Urgent);
    assert!(item.session_id.0.is_none());
}

/// The grants whose validity rests on the feed are refused after it removes the host: here
/// personal remote access under the bounded offline-validity policy the owner chose, inside its
/// bound. The refusal stands across a restart, the person at the machine is never refused, and the
/// owner acts at the host by pointing it at another feed or at none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_rests_on_the_feed_is_refused_after_it_removes_the_host_until_the_owner_acts()
{
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect("inside the bound, with the feed standing");

    rig.the_feed_removes_the_host().await;

    let refused = rig
        .doctor_as(&session)
        .await
        .expect_err("the grant rests on a feed that removed the host");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal and not for something else: {refused}"
    );
    let mut local = rig.host.client().await;
    let at_the_machine: HostDoctorResult =
        net_support::pairing::read(&mut local, Method::HostDoctor, &())
            .await
            .expect("the person at the machine is never refused");
    assert!(!at_the_machine.checks.is_empty());

    // It stands across a restart, for the feed that answered. A suite closes its clients before it
    // restarts.
    session.close();
    drop(session);
    drop(local);
    let (host, served) = rig.restarted_while_the_feed_is_down().await;
    let again = connect(&host, &phone, &record).await;
    let refused = again
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the removal was written down");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal and not for something else: {refused}"
    );
    drop(served);
}

/// The owner acts at the host by naming another feed, or none, in the configuration
/// document; the removal is no removal from that one, the grants that rested on the feed work again
/// at the next start, and the item that told the owner ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_acts_at_the_host_by_pointing_it_at_another_feed_or_at_none() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    let Rig { host, served, .. } = rig;
    let stopped = host.shut_down().await;
    // The owner edits the configuration document: no feed at all.
    net_support::write_feed_document(stopped.tree(), None);
    let host = stopped.start(host_settings()).await;

    let session = connect(&host, &phone, &record).await;
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect("a host with no feed has no feed that removed it");
    let mut local = host.client().await;
    let list: DeviceListResult = net_support::pairing::read(
        &mut local,
        Method::DeviceList,
        &DeviceListParams {
            include_revoked: false,
        },
    )
    .await
    .expect("the device list");
    assert!(!list.feed_removed);
    let inbox: AttentionReadResult = net_support::pairing::read(
        &mut local,
        Method::AttentionRead,
        &AttentionReadParams {
            session_id: Nullable::null(),
            include_acknowledged: true,
            max_items: U64::new(100),
            after: Nullable::null(),
        },
    )
    .await
    .expect("the attention inbox");
    assert!(
        inbox
            .items
            .iter()
            .all(|item| item.rule != AttentionRule::AuthorityFeedRemoved),
        "the owner acted, so the item that told them ends"
    );
    drop(served);
}

fn host_settings() -> kr_controller::service::net::config::NetworkSettings {
    kr_controller::service::net::config::NetworkSettings {
        endpoint: net_support::loopback(),
        ..kr_controller::service::net::config::NetworkSettings::default()
    }
}

/// KR-REQ-10.46: a feed that cannot be reached, or that is slow, is not a removal: nothing is
/// refused, the status is stale, and the connection that waited for it is served after the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_cannot_be_reached_refuses_nothing_and_shows_stale_status() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.served.web().fail_with_member(
        AUTHORITY,
        "read",
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(1),
        },
    );
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect("an unreachable feed does not refuse a grant inside its bound");
    let shown = rig.shown().await;
    assert!(!shown.list.feed_removed);
    assert!(shown.list.feed_stale, "what is shown of the feed is stale");
    let check = shown.check.expect("the doctor reports the feed");
    assert_eq!(check.status, DoctorStatus::Warning);
}

/// The keys the feed may be told can remove the host are the owners the host is paired with now: an
/// owner paired before the host first asked is named, a revoked owner stops being named, and a
/// delegation the feed turns back is sent again by the next pass instead of being left to a person.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keys_that_may_remove_the_feed_are_the_owners_the_host_is_paired_with() {
    let rig = Rig::start().await;
    let named = || async {
        rig.remote
            .read(rig.feed(), None, true)
            .await
            .expect("the feed answers")
            .summary
            .removal_keys
    };
    assert_eq!(
        named().await,
        vec![rig.owner.authorisation.key_id()],
        "the owner paired before the carrier first asked is named"
    );

    // The owner is revoked at the machine while the feed turns the delegation back.
    rig.served.web().fail_with_member(
        AUTHORITY,
        "delegate",
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    // Read before the revocation that wakes the pass, which can end before this test looks.
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    let mut local = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: rig.owner_device(),
        },
    )
    .await
    .expect("the owner at the machine revokes the device");
    within("the pass that was turned back", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
    assert_eq!(
        named().await,
        vec![rig.owner.authorisation.key_id()],
        "the feed turned the delegation back, so it still lists the revoked key"
    );
    let check = rig
        .shown()
        .await
        .check
        .expect("the doctor reports the feed");
    assert_eq!(check.status, DoctorStatus::Warning, "{}", check.detail());

    // The next pass sends it again: no person has to.
    rig.timer.release_held();
    rig.poll().await;
    assert!(
        named().await.is_empty(),
        "a revoked owner is no longer a key that may remove the feed"
    );
}

/// A host that stops after a request took effect and before it was written down as having done so
/// finishes it on the next start: the request was written down before it began, so the host knows
/// it as its own, issues the revision and acknowledges, and does not refuse it as covered by
/// the revocation it made itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_after_a_request_took_effect_and_before_it_was_written_down_finishes_it()
{
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let request = rig.owner_publishes(0xa6, devices(record.device_id)).await;

    let (arrived, _go) = rig
        .host
        .controller()
        .pause_after_a_feed_request_was_carried_out();
    {
        let runtime = rig.runtime();
        let polled = runtime.synchronised_before_serving();
        tokio::pin!(polled);
        tokio::select! {
            () = &mut polled => panic!("the pass stopped where it was held"),
            reached = arrived => reached.expect("the pass reached the point"),
        }
    }
    rig.runtime().crash();
    let revision = rig
        .host
        .controller()
        .authority_revision()
        .await
        .expect("a revision");
    assert!(revision.get() > 0, "the revocation took effect");

    let Rig {
        host,
        served,
        remote,
        ..
    } = rig;
    let feed = host.controller().feed_runtime().expect("a carrier").feed();
    let stopped = host.shut_down().await;
    let timer = HeldTimer::held();
    let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
    within("the carrier waits between passes", timer.next_wait()).await;

    let held = remote
        .read(feed, None, false)
        .await
        .expect("the feed answers");
    let record = held.record(request.request_id).expect("the record");
    assert_eq!(record.rejected.0, None, "not refused as covered by itself");
    let acknowledged = record
        .acknowledgement
        .0
        .as_ref()
        .expect("the restarted host acknowledged it");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    assert_eq!(acknowledged.authority_revision, revision);
    assert_eq!(
        host.controller()
            .authority_revision()
            .await
            .expect("a revision"),
        revision,
        "carried out once"
    );
    drop(served);
}

/// A request the feed holds again after it dropped the original is the request the host already
/// carried out: it is acknowledged under the revision it was first issued, which the feed has long
/// been past, and the requests after it are carried out. Nothing the host issued since can leave a
/// request that was numbered before it unable to be finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_feed_holds_again_is_acknowledged_under_its_first_revision_and_blocks_none() {
    let rig = Rig::start().await;
    let (_first_phone, first_device) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second_device) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_third_phone, third_device) = rig.pairs(&[ActionRight::SessionView]).await;
    let first = rig
        .owner_publishes(0xc1, devices(first_device.device_id))
        .await;
    rig.poll().await;
    let first_revision = rig
        .held(&first)
        .await
        .acknowledgement
        .0
        .expect("acknowledged")
        .authority_revision;
    rig.owner_publishes(0xc2, devices(second_device.device_id))
        .await;
    rig.poll().await;

    // A week later the feed has dropped what the host finished with, and the same signed request
    // is published again, with a new one behind it.
    rig.served.web().a_week_passes_in_the_feeds();
    rig.remote
        .publish(rig.feed(), &first, None)
        .await
        .expect("the feed takes the request again");
    let after = rig
        .owner_publishes(0xc3, devices(third_device.device_id))
        .await;
    rig.poll().await;

    let again = rig
        .held(&first)
        .await
        .acknowledgement
        .0
        .expect("the host acknowledged the request again");
    assert_eq!(again.completion, RevocationCompletion::Complete);
    assert_eq!(
        again.authority_revision, first_revision,
        "under the revision it was first issued"
    );
    let carried = rig
        .held(&after)
        .await
        .acknowledgement
        .0
        .expect("the request behind it was carried out");
    assert_eq!(carried.completion, RevocationCompletion::Complete);
    assert!(carried.authority_revision > first_revision);
}

/// A second request for what an earlier one withdrew is refused as covered, and a refusal that
/// never reached the feed is made again by the next pass: the host issues no revision for it, and
/// the requests after it are carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_request_for_what_was_withdrawn_is_refused_again_when_the_refusal_is_lost() {
    let rig = Rig::start().await;
    let (_first_phone, first_device) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second_device) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xd1, devices(first_device.device_id))
        .await;
    rig.poll().await;
    let again = rig
        .owner_publishes(0xd2, devices(first_device.device_id))
        .await;

    // The pass reads and refuses the second request: the refusal never arrives.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "reject", 1, Moment::Before);
    rig.poll().await;
    assert_eq!(
        rig.held(&again).await.rejected.0,
        None,
        "the refusal was lost"
    );

    let after = rig
        .owner_publishes(0xd3, devices(second_device.device_id))
        .await;
    rig.poll().await;
    assert_eq!(
        rig.held(&again).await.rejected.0,
        Some(RejectionReason::Superseded)
    );
    let carried = rig
        .held(&after)
        .await
        .acknowledgement
        .0
        .expect("the request behind it was carried out");
    assert_eq!(carried.completion, RevocationCompletion::Complete);
    assert_eq!(
        rig.arrivals("revise"),
        2,
        "a revision for each request that withdrew something, and none for the one that did not"
    );
}

/// A pass that fails waits out a backoff before it asks the feed again, as a pass that reads the
/// feed waits out its interval, and the request the failure left is finished by the pass after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_fails_waits_out_a_backoff_and_then_finishes_the_request() {
    let rig = Rig::start().await;
    let (_phone, device) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.poll().await;
    let request = rig.owner_publishes(0xf1, devices(device.device_id)).await;

    // The pass reads, issues its revision and acknowledges: the feed turns the acknowledgement
    // back, naming no delay.
    rig.served.web().fail_with_member(
        AUTHORITY,
        "acknowledge",
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.poll().await;
    let poll_interval = Duration::from_millis(kr_controller::grants::feed::FEED_POLL_INTERVAL_MS);
    let (backoff, release) = within(
        "the carrier asks for a wait shorter than its poll interval",
        rig.timer.next_wait_under(poll_interval),
    )
    .await;
    assert!(backoff > Duration::ZERO);

    release.notify_one();
    rig.poll().await;
    assert_eq!(
        rig.held(&request)
            .await
            .acknowledgement
            .0
            .expect("acknowledged by the pass after the backoff")
            .completion,
        RevocationCompletion::Complete
    );
}

/// The host decides the issuer of a request as it decides whether the same device may manage it: a
/// device whose grant carries the right to manage the host, and that this host's configuration
/// leaves no right to manage with, has no owner authority by the feed either, and what it names is
/// not withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_configuration_leaves_no_right_to_manage_the_host_has_no_authority_by_the_feed()
 {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;

    // The configuration allows a grant to carry the right to view a session and nothing else.
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 2;
    document.authority.origin = Nullable::some(rig.served.origin().to_owned());
    document.ceilings.grant_rights =
        Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]);
    let environment = rig.host.tree().environment();
    let path = kr_worker::config::document_path(&environment);
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
    let effective = rig.host.controller().effective_configuration().await;
    assert!(
        effective.not_in_force.0.is_none(),
        "{:?}",
        effective.not_in_force
    );

    let request = rig.owner_publishes(0xe1, devices(record.device_id)).await;
    rig.poll().await;

    assert_eq!(
        rig.held(&request).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority)
    );
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect("what the request named was not withdrawn");
}

/// A feed longer than a pass reads is read on at its cursor at once, and nothing is a
/// synchronisation until it is read through: a scan that fails half way shows the status stale and
/// not read, and the next pass goes on where it stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_longer_than_a_pass_reads_is_not_a_synchronisation_until_it_is_read_through() {
    let rig = Rig::start().await;
    rig.runtime().read_at_most_pages(1);
    // A connection waits for the first page to be read and the second to be held, which can take
    // longer than the default bound on a loaded machine.
    rig.runtime()
        .wait_for_a_synchronisation_at_most(Duration::from_secs(120));
    let synchronised = rig.shown().await.list.feed_synchronised_at_ms.0;
    assert!(synchronised.is_some(), "the host has read the feed once");

    // One page holds 64 records, and these are 70. The feed keeps a publisher to 32 of what the
    // host has not finished with, so three keys publish them.
    let unknown = |id: u8| {
        devices(DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [id; 16],
        )))
    };
    let strangers = [
        AuthorisationKeyPair::generate().expect("a key"),
        AuthorisationKeyPair::generate().expect("a key"),
    ];
    for id in 1..=70_u8 {
        let (key, client) = match id {
            1..=32 => (&rig.owner.authorisation, &rig.remote),
            33..=64 => (
                &strangers[0],
                &client_for(rig.served.origin(), strangers[0].clone()),
            ),
            _ => (
                &strangers[1],
                &client_for(rig.served.origin(), strangers[1].clone()),
            ),
        };
        let request = rig.signed_by(key, id, unknown(id));
        client
            .publish(rig.feed(), &request, None)
            .await
            .expect("the feed stores the request");
    }
    // The first pass reads a page and refuses its 64 records; the scan then goes on at once with a
    // second read, which the feed holds open. A connection that asked for a synchronisation is not
    // given one by the first page, and what the host shows is not current while the scan is under
    // way.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, Moment::Hold);
    let waiting = rig.runtime().synchronised_before_serving();
    tokio::pin!(waiting);
    tokio::select! {
        () = &mut waiting => panic!("the first page of a feed is no synchronisation"),
        () = rig.until_arrivals("read", reads + 2) => {}
    }
    assert!(
        rig.shown().await.list.feed_stale,
        "a scan under way is not current"
    );
    // The feed lets the read go unanswered, and the scan has stopped half way.
    rig.served.web().release_held();
    within("the connection is served once the read ended", waiting).await;
    let shown = rig.shown().await;
    assert_eq!(
        shown.list.feed_synchronised_at_ms.0, synchronised,
        "a scan that stopped half way is no synchronisation"
    );
    assert!(shown.list.feed_stale);
    let last_publisher = client_for(rig.served.origin(), strangers[1].clone());
    let unread = last_publisher
        .read(rig.feed(), None, false)
        .await
        .expect("the last publisher reads its records");
    assert_eq!(unread.records.len(), 6);
    assert!(
        unread
            .records
            .iter()
            .all(|record| record.rejected.0.is_none()),
        "the scan stopped before the last page"
    );

    // The next pass goes on at the cursor and reads the feed through.
    rig.poll().await;
    assert!(
        last_publisher
            .read(rig.feed(), None, false)
            .await
            .expect("the last publisher reads its records")
            .records
            .iter()
            .all(|record| record.rejected.0.is_some()),
        "the scan went on and read the feed through"
    );
    assert!(!rig.shown().await.list.feed_stale);
}

/// A connection waits for the synchronisation section 10 asks for only as long as the bound: a feed
/// that holds the read open does not hold the device out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_is_served_while_the_feed_holds_the_read_open_past_the_bound() {
    let rig = Rig::start().await;
    rig.runtime()
        .wait_for_a_synchronisation_at_most(Duration::from_millis(100));
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.poll().await;

    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let session = within(
        "the connection is served",
        connect(&rig.host, &phone, &record),
    )
    .await;
    rig.doctor_as(&session)
        .await
        .expect("served while the feed still holds the read");
    // The read is still held: a connection served after the host gave the read up would find the
    // feed unreachable instead.
    assert!(!rig.shown().await.list.feed_stale);
    rig.served.web().release_held();
}

/// A removal the registry cannot take is still in force: what rests on the feed is refused, the
/// carrier asks again, and the removal is written when the registry can. A host that starts again
/// with the feed down keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_the_registry_cannot_take_is_in_force_and_is_written_when_it_can() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect("inside the bound, with the feed standing");

    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_removal BEFORE INSERT ON host_authority
             WHEN NEW.key IN ('feed_removal', 'policy')
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    rig.the_feed_removes_the_host().await;
    let refused = rig
        .doctor_as(&session)
        .await
        .expect_err("the grant rests on a feed that removed the host");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal: {refused}"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_removal")
        .expect("the fault is lifted");
    rig.timer.release_held();
    rig.poll().await;
    session.close();
    drop(session);
    drop(registry);
    let (host, served) = rig.restarted_while_the_feed_is_down().await;
    let again = connect(&host, &phone, &record).await;
    let refused = again
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the removal was written down once the registry could take it");
    assert!(refused.to_string().contains("was removed"), "{refused}");
    drop(served);
}

/// A pass this host could not finish for a reason of its own is no synchronisation either: what is
/// shown of the feed is stale, as it is when the feed cannot be reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_this_host_could_not_finish_leaves_what_is_shown_stale() {
    let rig = Rig::start().await;
    let (_phone, device) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.poll().await;
    assert!(
        !rig.shown().await.list.feed_stale,
        "the control: it is current"
    );

    // The registry cannot take the note this host writes before it carries a request out.
    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_note BEFORE INSERT ON host_authority
             WHEN NEW.key = 'feed'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    rig.owner_publishes(0xf2, devices(device.device_id)).await;
    rig.poll().await;
    assert!(
        rig.shown().await.list.feed_stale,
        "a pass that stopped for a reason of this host's is no synchronisation"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_note")
        .expect("the fault is lifted");
    rig.poll().await;
    assert!(!rig.shown().await.list.feed_stale);
}

/// A bounded offline validity stops personal remote access while the feed cannot be reached, and
/// the host that judges a request has just read the feed: the issuer whose bound has lapsed is
/// judged without it, and the request is carried out in the pass that read it. A device that holds
/// no management right is not named as one that may remove the feed because of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_from_an_issuer_under_a_lapsed_offline_bound_is_carried_out_in_the_pass_that_read_it()
 {
    let rig = Rig::start().await;
    // The viewer stays paired: the request names another device.
    let (_viewer, _) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_phone, device) = rig.pairs(&[ActionRight::SessionView]).await;
    // Every pass the pairing asked for has run, so none renews the bound before the request is
    // judged.
    rig.poll().await;
    rig.poll().await;
    // The owner chose a bound of an hour, and the host last synchronised two hours ago.
    let now = kr_ipc::now_ms().get();
    rig.host
        .controller()
        .update_policy(|policy| {
            policy.set_offline_validity(Some(OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(
                    now - 2 * 60 * 60 * 1000,
                )),
            }));
        })
        .expect("the owner chooses a bound");
    let request = rig.owner_publishes(0xf3, devices(device.device_id)).await;

    rig.poll().await;
    let held = rig.held(&request).await;
    assert_eq!(held.rejected.0, None, "not refused for the bound");
    assert_eq!(
        held.acknowledgement.0.expect("carried out").completion,
        RevocationCompletion::Complete,
        "carried out in the pass that read it"
    );
    let named = rig
        .remote
        .read(rig.feed(), None, true)
        .await
        .expect("the feed answers")
        .summary
        .removal_keys;
    assert_eq!(
        named,
        vec![rig.owner.authorisation.key_id()],
        "the owner is named, and a device that may only view a session is not, whatever its bound"
    );
}

/// The host dates what it shows of the feed by the clock the daemon holds, as it dates every other
/// record of time, and not by a second reading of the machine's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_synchronisation_the_host_shows_is_dated_by_the_clock_the_daemon_holds() {
    let wall = MovedWall::new();
    let rig = Rig::start_on(wall.clocks()).await;
    wall.advance(Duration::from_secs(60 * 60));
    rig.poll().await;

    let synchronised = rig
        .shown()
        .await
        .list
        .feed_synchronised_at_ms
        .0
        .expect("the host has synchronised the feed")
        .get();
    assert!(
        synchronised > kr_ipc::now_ms().get() + 30 * 60 * 1000,
        "dated by the daemon's clock, an hour ahead of the machine's: {synchronised}"
    );
}

/// What a host that has been removed from its feed refuses a device that holds a grant resting on
/// the feed: here the device's request for its own diagnostics.
async fn refused_for_the_removal(
    rig: &Rig,
    phone: &Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
) {
    let session = connect(&rig.host, phone, record).await;
    let refused = session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the grant rests on a feed that removed the host");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal and not for something else: {refused}"
    );
    session.close();
}

/// A configuration document this host cannot use is no choice of another feed: the removal and
/// what it refuses stand, and the item that told the owner stays, until a start reads a document
/// that selects another feed or none. Put right, the document names the feed that removed the
/// host, and a start with that feed unreachable still finds the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_the_host_cannot_use_leaves_the_removal_in_force() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    let rig = rig
        .restarted(false, net_support::write_unusable_document)
        .await;
    refused_for_the_removal(&rig, &phone, &record).await;
    let shown = rig.shown().await;
    assert!(shown.removal_item.is_some(), "the owner is still told");
    let check = shown.check.expect("the doctor reports the feed");
    assert_eq!(check.status, DoctorStatus::Warning, "{}", check.detail());
    assert!(check.detail().contains("removed"), "{}", check.detail());

    let origin = rig.served.origin().to_owned();
    let rig = rig
        .restarted(true, |tree| {
            net_support::write_feed_document(tree, Some(&origin));
        })
        .await;
    refused_for_the_removal(&rig, &phone, &record).await;
    assert!(rig.shown().await.removal_item.is_some());
}

/// A request taken from one feed does not hold up another the host is pointed at: the revisions a
/// request was numbered under are the first feed's, and the second holds none of them. The request
/// published again there is judged afresh, and the one behind it is carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_taken_from_one_feed_does_not_hold_up_the_feed_the_host_is_pointed_at_next() {
    let rig = Rig::start().await;
    let (_first_phone, first) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_third_phone, third) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xb1, devices(first.device_id)).await;
    let numbered_second = rig.owner_publishes(0xb2, devices(second.device_id)).await;
    rig.poll().await;
    assert_eq!(
        rig.held(&numbered_second)
            .await
            .acknowledgement
            .0
            .expect("carried out on the first feed")
            .authority_revision
            .get(),
        2,
        "the second request was numbered after the first"
    );

    let rig = rig.pointed_at(serve().await).await;
    rig.remote
        .publish(rig.feed(), &numbered_second, None)
        .await
        .expect("the second feed takes the request");
    let behind = rig.owner_publishes(0xb3, devices(third.device_id)).await;
    rig.poll().await;

    assert_eq!(
        rig.held(&numbered_second).await.rejected.0,
        Some(RejectionReason::Superseded),
        "what it names was withdrawn already, so it is refused as covered"
    );
    assert_eq!(
        rig.held(&behind)
            .await
            .acknowledgement
            .0
            .expect("the request behind it was carried out")
            .completion,
        RevocationCompletion::Complete
    );
}

/// A request that withdrew nothing is refused however the host was interrupted while it took it:
/// after it wrote the request down and carried it out and stopped before it refused it, and after
/// the write of the request failed. The requests behind it are carried out, and none stops the
/// feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_while_taking_a_request_that_withdrew_nothing_refuses_it_after_it_starts()
{
    let rig = Rig::start().await;
    let (_first_phone, first) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xb4, devices(first.device_id)).await;
    rig.poll().await;
    let again = rig.owner_publishes(0xb5, devices(first.device_id)).await;

    let (arrived, _go) = rig
        .host
        .controller()
        .pause_after_a_feed_request_was_carried_out();
    {
        let polled = rig.runtime().synchronised_before_serving();
        tokio::pin!(polled);
        tokio::select! {
            () = &mut polled => panic!("the pass stopped where it was held"),
            reached = arrived => reached.expect("the pass reached the point"),
        }
    }
    rig.runtime().crash();

    let rig = rig.restarted(false, |_| {}).await;
    within("the carrier waits between passes", rig.timer.next_wait()).await;
    assert_eq!(
        rig.held(&again).await.rejected.0,
        Some(RejectionReason::Superseded),
        "refused as covered after the start"
    );
    let behind = rig.owner_publishes(0xb6, devices(second.device_id)).await;
    rig.poll().await;
    assert_eq!(
        rig.held(&behind)
            .await
            .acknowledgement
            .0
            .expect("the request behind it was carried out")
            .completion,
        RevocationCompletion::Complete
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_withdrew_nothing_is_refused_after_the_write_of_its_note_failed() {
    let rig = Rig::start().await;
    let (_first_phone, first) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xb7, devices(first.device_id)).await;
    rig.poll().await;

    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_note BEFORE INSERT ON host_authority
             WHEN NEW.key = 'feed'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let again = rig.owner_publishes(0xb8, devices(first.device_id)).await;
    rig.poll().await;
    assert_eq!(
        rig.held(&again).await.rejected.0,
        None,
        "the note could not be written, so nothing was said"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_note")
        .expect("the fault is lifted");
    rig.timer.release_held();
    rig.poll().await;
    assert_eq!(
        rig.held(&again).await.rejected.0,
        Some(RejectionReason::Superseded)
    );
    let behind = rig.owner_publishes(0xb9, devices(second.device_id)).await;
    rig.poll().await;
    assert_eq!(
        rig.held(&behind)
            .await
            .acknowledgement
            .0
            .expect("the request behind it was carried out")
            .completion,
        RevocationCompletion::Complete
    );
}

/// A device that holds no right to manage the host is turned away whatever the clock, so it cannot
/// hold up the feed while the clock is unproven: a request from it is refused, and the owner's
/// behind it is carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_may_not_manage_the_host_does_not_hold_up_the_feed_while_the_clock_is_unproven()
 {
    let rig = Rig::start().await;
    let (viewer, viewer_record) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_phone, target) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.poll().await;
    rig.host.controller().utc_floor().lose_continuity();

    let by_a_viewer = kr_pairing::grants::sign_revocation_request(
        &viewer.keys().authorisation,
        RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([0xc1; 16])),
        viewer_record.device_id,
        rig.host_device(),
        devices(target.device_id),
        kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
    )
    .expect("a signed request");
    client_for(rig.served.origin(), viewer.keys().authorisation.clone())
        .publish(rig.feed(), &by_a_viewer, None)
        .await
        .expect("the feed stores what any key publishes");
    let by_the_owner = rig.owner_publishes(0xc2, devices(target.device_id)).await;
    rig.poll().await;

    let seen_by_the_viewer = client_for(rig.served.origin(), viewer.keys().authorisation.clone())
        .read(rig.feed(), None, false)
        .await
        .expect("the viewer reads what it published");
    assert_eq!(
        seen_by_the_viewer
            .record(by_a_viewer.request_id)
            .expect("the record")
            .rejected
            .0,
        Some(RejectionReason::NoOwnerAuthority)
    );
    assert_eq!(
        rig.held(&by_the_owner)
            .await
            .acknowledgement
            .0
            .expect("the owner's request was carried out")
            .completion,
        RevocationCompletion::Complete
    );
}

/// A pass writes the feed's record down when it changed something and not for each record it reads
/// that was settled or refused already: a host that starts reads up to a week of them again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_does_not_write_the_feed_down_again_for_each_settled_record_it_reads() {
    let rig = Rig::start().await;
    let (_first_phone, first) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_second_phone, second) = rig.pairs(&[ActionRight::SessionView]).await;
    let (_third_phone, third) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xd1, devices(first.device_id)).await;
    rig.owner_publishes(0xd2, devices(second.device_id)).await;
    rig.owner_publishes(0xd3, devices(third.device_id)).await;
    rig.owner_publishes(
        0xd4,
        devices(DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [0xdd; 16],
        ))),
    )
    .await;
    rig.poll().await;

    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TABLE feed_writes (n INTEGER);
             CREATE TRIGGER counting AFTER INSERT ON host_authority
             WHEN NEW.key = 'feed'
             BEGIN INSERT INTO feed_writes VALUES (1); END;",
        )
        .expect("the count is in place");
    drop(registry);
    let rig = rig.restarted(false, |_| {}).await;
    within("the carrier waits between passes", rig.timer.next_wait()).await;

    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    let writes: i64 = registry
        .query_row("SELECT COUNT(*) FROM feed_writes", [], |row| row.get(0))
        .expect("counts the writes");
    assert!(
        writes <= 2,
        "the start writes the record once and the synchronisation once, not once for each of \
         four records it read again: {writes}"
    );
}

/// The attention store refuses a notice about the feed that it has not taken yet, as a store does
/// whose disk is full. What it holds stays as it is, so the daemon opens it.
fn the_attention_store_refuses_the_feeds_notices(host: &Host) {
    let store =
        rusqlite::Connection::open(host.attention_database()).expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    store
        .execute_batch(
            "CREATE TABLE notices_taken (n INTEGER);
             INSERT INTO notices_taken
               SELECT COALESCE(MAX(sequence), 0) FROM attention_consumed WHERE source = 'authority';
             CREATE TRIGGER refuse_notice_insert BEFORE INSERT ON attention_consumed
             WHEN NEW.source = 'authority' AND NEW.sequence > (SELECT n FROM notices_taken)
             BEGIN SELECT RAISE(ABORT, 'no room'); END;
             CREATE TRIGGER refuse_notice_update BEFORE UPDATE ON attention_consumed
             WHEN NEW.source = 'authority' AND NEW.sequence > (SELECT n FROM notices_taken)
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
}

fn the_attention_store_takes_the_feeds_notices(host: &Host) {
    let store =
        rusqlite::Connection::open(host.attention_database()).expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    store
        .execute_batch(
            "DROP TRIGGER refuse_notice_insert;
             DROP TRIGGER refuse_notice_update;
             DROP TABLE notices_taken;",
        )
        .expect("the fault is lifted");
}

/// Waits for the task that sees to the notices to have been refused and to ask for its wait, lets
/// the store take notices, and waits until the task has tried again after the wait ends.
async fn the_store_takes_the_notices_the_task_tries_again(rig: &Rig) {
    let poll_interval = Duration::from_millis(kr_controller::grants::feed::FEED_POLL_INTERVAL_MS);
    let (_, release) = within(
        "the task that sees to the notices backs off from the one it owes",
        rig.timer.next_wait_under(poll_interval),
    )
    .await;
    the_attention_store_takes_the_feeds_notices(&rig.host);
    let mut attempts = rig.host.controller().feed_notice_attempts();
    let seen = *attempts.borrow_and_update();
    release.notify_one();
    within("the task tries again", async {
        while *attempts.borrow_and_update() <= seen {
            attempts.changed().await.expect("the daemon is running");
        }
    })
    .await;
}

/// The notice that the feed removed the host is owed to the owner until the attention store takes
/// it. A start that could not give it does not forget it: the host gives it again, when the store
/// can take it, without another start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_notice_the_attention_store_refused_is_given_again_without_a_start() {
    let rig = Rig::start().await;
    the_attention_store_refuses_the_feeds_notices(&rig.host);
    rig.the_feed_removes_the_host().await;
    assert!(
        rig.shown().await.removal_item.is_none(),
        "the store refused the notice"
    );

    let rig = rig.restarted(true, |_| {}).await;
    assert!(rig.shown().await.removal_item.is_none());

    the_store_takes_the_notices_the_task_tries_again(&rig).await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the owner is told once the store can take the notice"
    );
}

/// The notice that the host reads another feed, or none, is owed until the attention store takes
/// it, and a host that reads no feed gives it again without another start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_that_the_owner_acted_is_given_again_by_a_host_that_reads_no_feed() {
    let rig = Rig::start().await;
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    the_attention_store_refuses_the_feeds_notices(&rig.host);
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the store refused the notice that ends it"
    );

    the_store_takes_the_notices_the_task_tries_again(&rig).await;
    assert!(
        rig.shown().await.removal_item.is_none(),
        "the item ends once the store can take the notice"
    );
}

/// Whether the attention store holds the notice is the store's own cursor and not a mark the host
/// kept: a store put back to a copy from before the notice is given the notice again at the next
/// start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_the_attention_store_lost_is_given_again_at_the_next_start() {
    let rig = Rig::start().await;
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    let rig = rig
        .restarted(true, |tree| {
            let store = rusqlite::Connection::open(
                tree.environment().state_dir().join("attention.sqlite3"),
            )
            .expect("opens the attention store");
            store
                .execute_batch(
                    "DELETE FROM attention_items WHERE rule = 'attention.authority_feed_removed';
                     DELETE FROM attention_consumed WHERE source = 'authority';",
                )
                .expect("the store is put back");
        })
        .await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the store lost the notice, and the host gave it again"
    );
}

/// A notice is numbered above every one the attention store has taken, whatever the host kept of
/// its own: a host that lost its record of the feed's removal cannot number the next notice behind
/// the store's cursor, which would have the store drop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_is_numbered_above_what_the_attention_store_took_when_the_hosts_record_is_lost() {
    let rig = Rig::start().await;
    rig.the_feed_removes_the_host().await;
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    assert!(
        rig.shown().await.removal_item.is_none(),
        "the owner acted, so the item ends"
    );

    let origin = rig.served.origin().to_owned();
    let rig = rig
        .restarted(false, |tree| {
            let registry = rusqlite::Connection::open(tree.environment().registry_database())
                .expect("opens the registry");
            registry
                .execute("DELETE FROM host_authority WHERE key = 'feed_removal'", [])
                .expect("the record is lost");
            net_support::write_feed_document(tree, Some(&origin));
        })
        .await;
    rig.poll().await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the feed removes the host again, and the store takes the notice"
    );
}

/// A record of the removal that is behind the attention store's cursor, as when the registry was
/// put back to an earlier copy than the store, is numbered again above the cursor at the next
/// start, so that the notice it holds is given and not taken for one the store has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_recorded_behind_the_attention_stores_cursor_is_numbered_again_at_the_next_start()
{
    let rig = Rig::start().await;
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    let rig = rig
        .restarted(true, |tree| {
            let store = rusqlite::Connection::open(
                tree.environment().state_dir().join("attention.sqlite3"),
            )
            .expect("opens the attention store");
            store
                .execute_batch(
                    "DELETE FROM attention_items WHERE rule = 'attention.authority_feed_removed';
                     UPDATE attention_consumed SET sequence = 100 WHERE source = 'authority';",
                )
                .expect("the store is ahead of the registry");
        })
        .await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the registry says the feed removed the host, and the owner is told"
    );
}

/// A refusal is on disk before it is sent, though its first write failed: the pass that could not
/// write it sent nothing, and the next pass writes it before it says anything to the feed, though
/// it has nothing new to record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_whose_first_write_failed_is_on_disk_before_it_is_sent() {
    let rig = Rig::start().await;
    let (_phone, device) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes(0xe5, devices(device.device_id)).await;
    rig.poll().await;
    let again = rig.owner_publishes(0xe6, devices(device.device_id)).await;

    let (arrived, go) = rig
        .host
        .controller()
        .pause_after_a_feed_request_was_carried_out();
    let registry =
        rusqlite::Connection::open(rig.host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    {
        let polled = rig.runtime().synchronised_before_serving();
        tokio::pin!(polled);
        tokio::select! {
            () = &mut polled => panic!("the pass stopped where it was held"),
            reached = arrived => reached.expect("the pass reached the point"),
        }
        // The note is written. The refusal it is about to write is not.
        registry
            .execute_batch(
                "CREATE TRIGGER refuse_refusal BEFORE INSERT ON host_authority
                 WHEN NEW.key = 'feed'
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            )
            .expect("the fault is in place");
        go.send(()).expect("the pass goes on");
        polled.await;
    }
    assert_eq!(
        rig.held(&again).await.rejected.0,
        None,
        "the refusal could not be written, so it was not sent"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_refusal")
        .expect("the fault is lifted");
    // The next pass reads and refuses the request: the feed holds that answer while the test looks
    // at what the host has on disk.
    let refusals = rig.arrivals("reject");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "reject", 1, Moment::Hold);
    rig.timer.release_held();
    let polled = rig.runtime().synchronised_before_serving();
    tokio::pin!(polled);
    tokio::select! {
        () = &mut polled => panic!("the pass ended before the refusal was held"),
        () = rig.until_arrivals("reject", refusals + 1) => {}
    }
    let stored = rig
        .host
        .controller()
        .sharing()
        .grants()
        .stored_feed()
        .expect("the record reads")
        .expect("the record exists");
    let note = stored
        .records
        .iter()
        .find(|record| record.request.request_id == again.request_id)
        .expect("the request is on disk");
    assert!(
        note.acknowledged_by.contains(&rig.host_device()),
        "the refusal is on disk when the host sends it"
    );
    rig.served.web().release_held();
    polled.await;
}

/// A removal is written down whether or not the attention store can be read when the feed answers:
/// the record is the one thing a restart finds, and without it a host that starts with the feed
/// unreachable serves the grants that rest on the feed again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_is_written_down_though_the_attention_store_cannot_be_read() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.host
        .controller()
        .make_the_notice_cursor_unreadable(true);
    rig.the_feed_removes_the_host().await;

    let rig = rig.restarted(true, |_| {}).await;
    refused_for_the_removal(&rig, &phone, &record).await;
}

/// The notices about the feed are numbered by the order the host gave them in and not by the time
/// they were recorded: a clock put right after it ran ahead does not put the notice that the owner
/// acted behind the one it ends, nor a later removal behind the notice that the owner acted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_notices_about_the_feed_keep_their_order_when_the_clock_is_put_back() {
    let wall = MovedWall::new();
    let rig = Rig::start_on(wall.clocks()).await;
    wall.advance(Duration::from_secs(2 * 60 * 60));
    rig.the_feed_removes_the_host().await;
    assert!(rig.shown().await.removal_item.is_some());

    wall.rewind(Duration::from_secs(2 * 60 * 60));
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    assert!(
        rig.shown().await.removal_item.is_none(),
        "the owner acted, so the item that told them ends"
    );

    let origin = rig.served.origin().to_owned();
    let rig = rig
        .restarted(false, |tree| {
            net_support::write_feed_document(tree, Some(&origin));
        })
        .await;
    rig.poll().await;
    assert!(
        rig.shown().await.removal_item.is_some(),
        "the feed removes the host again, and the owner is told again"
    );
}
