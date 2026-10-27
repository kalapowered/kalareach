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
use kr_controller::grants::restored::{self, Found};
use kr_controller::service::Clocks;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::attention::{AttentionReadParams, AttentionReadResult, AttentionRule};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::method::Method;
use kr_protocol::organisation::{HostPolicyConfirmParams, HostPolicyConfirmResult};
use kr_protocol::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, RevocationAcknowledgement,
    RevocationCompletion, RevocationRequest, RevocationTarget,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, KeyId, Nullable, Signature64, TimestampMs, U64,
};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult, OfflineValidityPolicy};
use kr_service_stand_in::{Moment, Served, serve};
use net_support::{Device, Host, MovedWall, connect, pair_with, paired_dial, proposal};

const AUTHORITY: &str = "/api/authority/sync";

/// A change the feed turns back without acting on it.
const TURNED_BACK: Moment = Moment::Refuse {
    status: 503,
    code: "SERVICE_UNAVAILABLE",
    retry_after_seconds: None,
};

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
    /// The host's own keys, which a case signs with when it makes the feed hold what an earlier run
    /// of the host would have left in it.
    host_keys: DeviceKeys,
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
        let host_keys = DeviceKeys::generate().expect("host keys");
        let host = Host::start_with_feed_keys(
            &owner,
            &host_keys,
            served.origin(),
            Arc::clone(&timer) as _,
            clocks,
        )
        .await;
        wait_for_the_passes(&host);
        let remote = client_for(served.origin(), owner.authorisation.clone());
        let rig = Self {
            host,
            served,
            timer,
            owner,
            host_keys,
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
        within(
            "the pass the case asked for ends",
            self.runtime().synchronised_before_serving(),
        )
        .await;
    }

    /// Waits until a pass that began after this call has finished, twice over, which leaves no
    /// pass running that began before the first call and none that a wake stored by then would
    /// start: a pass that a wake started after the first call's ticket was taken has ended before
    /// the second call returns. What a connection waits for is exactly such a pass, and the pass
    /// it starts is then the only one that can read what is published afterwards. The wait for a
    /// synchronisation ends silently at its bound, so the bound is made longer than `within`
    /// allows, and the wait can then end only with its pass or fail the case. The bound is the one
    /// the start set (`wait_for_the_passes`), which stays for the connection's own wait, and which
    /// `within` limits as well.
    async fn until_the_carrier_is_idle(&self) {
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
            host_keys,
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
        wait_for_the_passes(&host);
        Self {
            host,
            served,
            timer,
            owner,
            host_keys,
            remote,
        }
    }

    /// Stops the daemon and starts it again with its configuration document selecting `feed`, a
    /// service that holds nothing of this host. A suite closes its clients before it restarts.
    async fn pointed_at(self, feed: Served) -> Self {
        let Self {
            host,
            owner,
            host_keys,
            ..
        } = self;
        let stopped = host.shut_down().await;
        net_support::write_feed_document(stopped.tree(), Some(feed.origin()));
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        wait_for_the_passes(&host);
        let remote = client_for(feed.origin(), owner.authorisation.clone());
        Self {
            host,
            served: feed,
            timer,
            owner,
            host_keys,
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
        wait_for_the_passes(&host);
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

/// Lets a connection and a case wait for a pass of the carrier for as long as the pass takes, which
/// `within` limits. The wait for a synchronisation ends silently at its bound, five seconds unless
/// a case sets another, and a machine that is busy takes longer over a pass than that: the wait
/// would then end with the pass unfinished, and what the case reads next would be what the pass had
/// not yet made. Called for every daemon a case starts, before anything is asked of it (one that
/// reads no feed has no carrier and nothing to wait for); a case that is about the bound sets its
/// own afterwards.
fn wait_for_the_passes(host: &Host) {
    if let Some(carrier) = host.controller().feed_runtime() {
        carrier.wait_for_a_synchronisation_at_most(Duration::from_secs(3600));
    }
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
        self.until_the_revocation_is_acknowledged_to(&self.owner.authorisation, request)
            .await;
    }

    /// As [`Self::until_the_revocation_is_acknowledged`], for a request the holder of `key`
    /// published, which only its publisher reads from the feed.
    async fn until_the_revocation_is_acknowledged_to(
        &self,
        key: &AuthorisationKeyPair,
        request: &RevocationRequest,
    ) {
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
                    let acknowledged = client_for(self.served.origin(), key.clone())
                        .read(self.feed(), None, false)
                        .await
                        .expect("the feed answers its publisher")
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
    wait_for_the_passes(&host);
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
    let waits = rig.serves(&kept.0, &kept.1).await;
    assert!(
        is_refused_for_the_restored_policy(&waits),
        "the host has caught up and still waits for the person at the machine: {waits:?}"
    );
    assert!(rig.the_owner_confirms().await.lifted);
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device that was not revoked is served once the person has confirmed");
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
    // The restored-policy check says the same: a catch-up that does not end is not put down to a
    // failed write alone, since the feed can be the cause.
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("cannot be reached")
                && remedy.contains("refused")
                && remedy.contains("kr doctor")),
        "and names the causes of a catch-up that does not end: {:?}",
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
    assert!(
        is_refused_for_the_restored_policy(&rig.serves(&kept.0, &kept.1).await),
        "the host has caught up and still waits for the person at the machine"
    );
    assert!(rig.the_owner_confirms().await.lifted);
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device is served once the host has caught up and the person has confirmed");
}

impl Rig {
    /// The person at this machine confirms the policy the host holds.
    async fn the_owner_confirms(&self) -> HostPolicyConfirmResult {
        let mut local = self.host.client().await;
        net_support::pairing::mutate(
            self.host.environment_id,
            &mut local,
            Method::HostPolicyConfirm,
            &HostPolicyConfirmParams {},
        )
        .await
        .expect("the person at this machine confirms")
    }

    /// The same, when the host may refuse.
    async fn the_owner_tries_to_confirm(
        &self,
    ) -> Result<HostPolicyConfirmResult, kr_protocol::error::ProtocolError> {
        let mut local = self.host.client().await;
        net_support::pairing::mutate(
            self.host.environment_id,
            &mut local,
            Method::HostPolicyConfirm,
            &HostPolicyConfirmParams {},
        )
        .await
    }

    /// What the record of the restore lists as owed.
    fn what_the_record_lists(&self) -> Vec<restored::Target> {
        match self.the_record() {
            Found::Record(record) => record.owed.iter().map(|entry| entry.target).collect(),
            _ => Vec::new(),
        }
    }

    /// The confirmation, which the wait owes something to, and the words it is refused in.
    async fn the_confirmation_is_refused(&self) -> kr_protocol::error::ProtocolError {
        let refused = self
            .the_owner_tries_to_confirm()
            .await
            .expect_err("the wait owes a device that is live");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
        refused
    }

    /// Ends the wait by the route the refusal gives, which removes the record's file by hand while
    /// the daemon is stopped and starts it again. What the host owes is not asked.
    async fn the_wait_is_ended_by_hand(self) -> Self {
        self.restarted(false, |tree| {
            restored::remove(&restored::file_beside(
                &tree.environment().registry_database(),
            ))
            .expect("the record is removed");
        })
        .await
    }

    /// The person at the machine revokes a share.
    async fn revokes_a_share_at_the_machine(&self, grant_id: kr_protocol::ids::GrantId) {
        net_support::worker::revoke(&self.host, grant_id).await;
    }

    /// What the host has written down of a restore.
    fn the_record(&self) -> Found {
        restored::read(&restored::file_beside(
            &self.host.tree().environment().registry_database(),
        ))
    }

    /// Whether the host serves a paired device its doctor, and why not if it does not.
    async fn serves(
        &self,
        device: &Device,
        record: &kr_controller::service::net::devices::DeviceRecord,
    ) -> Result<(), kr_client::ClientError> {
        device_is_served(&self.host, device, record).await
    }

    /// The doctor's check of a restored policy, as the person at this machine reads it.
    async fn the_restored_policy_check(&self) -> Option<kr_protocol::hostinfo::DoctorCheck> {
        let mut local = self.host.client().await;
        let doctor: HostDoctorResult =
            net_support::pairing::read(&mut local, Method::HostDoctor, &())
                .await
                .expect("the host's diagnostics");
        doctor
            .checks
            .into_iter()
            .find(|check| check.id() == "restored-policy")
    }
}

/// Whether `host` serves a paired device its doctor, and why not if it does not.
async fn device_is_served(
    host: &Host,
    device: &Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
) -> Result<(), kr_client::ClientError> {
    match paired_dial(host, device, record).try_dial().await {
        Ok(transport) => {
            let session =
                kr_client::session::Session::start(Arc::new(transport)).expect("a session");
            within("the host answers", async {
                session
                    .read::<(), HostDoctorResult>(Method::HostDoctor, &())
                    .await
            })
            .await
            .map(|_| ())
        }
        Err(error) => Err(error),
    }
}

/// Whether a device was refused for the policy the host found restored.
fn is_refused_for_the_restored_policy(outcome: &Result<(), kr_client::ClientError>) -> bool {
    outcome
        .as_ref()
        .is_err_and(|error| error.to_string().contains("restored from an earlier state"))
}

/// A copy of the policy mirror as it stands, taken while the daemon runs.
fn a_copy_of_the_mirror(host: &Host, name: &str) -> std::path::PathBuf {
    let mirror =
        kr_controller::grants::mirror::file_beside(&host.tree().environment().registry_database());
    let copy = mirror.with_file_name(name);
    std::fs::copy(mirror, &copy).expect("the mirror is copied");
    copy
}

/// Puts a copy of the mirror back where the mirror stands, with the host stopped.
fn put_the_mirror_back(tree: &kr_ipc::testing::TempHost, copy: &std::path::Path) {
    let mirror =
        kr_controller::grants::mirror::file_beside(&tree.environment().registry_database());
    std::fs::copy(copy, mirror).expect("the copy is put back");
}

/// As [`a_revocation_the_registry_will_lose`], with the mirror copied beside the registry, and the
/// owner bounding offline validity after the copy, so that the state the copy holds lacks a
/// restriction the host later gained.
async fn a_policy_the_registry_will_lose() -> (Restorable, std::path::PathBuf) {
    let rig = Rig::start().await;
    let revoked = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-earlier.sqlite3");
    let earlier_mirror = a_copy_of_the_mirror(&rig.host, "mirror-earlier.cbor");
    rig.the_owner_bounds_offline_validity();
    let request = rig
        .owner_publishes(0xb1, devices(revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    let held = rig.held(&request).await;
    let acknowledged = held.acknowledgement.0.as_ref().expect("acknowledged");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    let revision = acknowledged.authority_revision;
    (
        Restorable {
            rig,
            revoked,
            kept,
            earlier,
            revision,
        },
        earlier_mirror,
    )
}

/// KR-REQ-24.15: a host that found its registry put back to an earlier state, with the mirror, has
/// caught up with its feed, and still refuses every grant but the owner's at this machine, because
/// the policy it holds is the restored one and the feed carries withdrawals and no policy. The
/// record of the finding is written, the doctor says the policy waits, the device that was not
/// revoked is refused for the wait, and the person at this machine ends it: the device is served,
/// and the policy in force is still the restored one, which has lost the bound the owner chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_found_restored_waits_for_the_person_at_the_machine_after_the_host_has_caught_up()
{
    let (
        Restorable {
            rig,
            revoked,
            kept,
            earlier,
            revision,
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    assert!(
        rig.host.controller().policy().offline_validity().is_some(),
        "the owner's bound stands before the restore"
    );

    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
        })
        .await;
    rig.until_the_carrier_is_idle().await;

    assert!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision")
            >= revision,
        "the host has caught up with its feed"
    );
    assert!(
        rig.host.controller().policy().offline_validity().is_none(),
        "and the policy it holds is the restored one, without the bound"
    );
    let Found::Record(record) = rig.the_record() else {
        panic!("the finding is written down");
    };
    assert_eq!(
        record.subject,
        restored::subject_of(&rig.host.controller().policy().snapshot()),
        "and names the row the host holds"
    );
    rig.connects_while_a_revocation_is_held(&revoked.0, &revoked.1)
        .await;
    let outcome = rig.serves(&kept.0, &kept.1).await;
    assert!(
        is_refused_for_the_restored_policy(&outcome),
        "the device the restore did not revoke is refused for the wait: {outcome:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the policy waits");
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        rig.shown()
            .await
            .check
            .is_some_and(|check| !check.detail().contains("catching up")),
        "while the feed check says the host has caught up"
    );

    assert!(rig.the_owner_confirms().await.lifted);
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device is served once the person at this machine has confirmed");
    assert!(
        rig.host.controller().policy().offline_validity().is_none(),
        "the confirmation changed nothing: the policy is the restored one"
    );
    assert_eq!(rig.the_record(), Found::Missing);
}

/// KR-REQ-24.15: the finding is on disk before anything is carried out again, so a pass that stops
/// part way, and a restart that cannot reach the feed, still find the restored policy waiting. The
/// registry here cannot take the revocation of the device the restore brought back, which is the
/// first thing the pass carries out, so the pass stops there with the registry still behind its feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_finding_is_written_down_before_anything_is_carried_out_again() {
    let (
        Restorable {
            rig, kept, earlier, ..
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute_batch(
                    "CREATE TRIGGER refuse_revocation BEFORE UPDATE OF revoked_at_ms
                         ON network_devices BEGIN SELECT RAISE(ABORT, 'no room'); END;",
                )
                .expect("the fault is in place");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.shown()
            .await
            .check
            .is_some_and(|check| check.detail().contains("catching up")),
        "the host cannot finish catching up"
    );
    let Found::Record(record) = rig.the_record() else {
        panic!("the finding is written down although nothing was carried out");
    };
    let outcome = rig.the_owner_tries_to_confirm().await;
    assert!(
        outcome.is_err(),
        "the confirmation is refused while the host is behind its feed"
    );

    // The host stops, and starts with the feed down: it makes no comparison, and reads the record.
    let (host, served) = rig.restarted_while_the_feed_is_down().await;
    let outcome = device_is_served(&host, &kept.0, &kept.1).await;
    assert!(
        is_refused_for_the_restored_policy(&outcome),
        "a restart that cannot reach the feed still finds the restored policy waiting: {outcome:?}"
    );
    assert_eq!(
        restored::read(&restored::file_beside(
            &host.tree().environment().registry_database()
        )),
        Found::Record(record),
        "and the record is as it was written"
    );
    drop(served);
}

/// KR-REQ-24.15: the wait outlives the host's having caught up and the feed's being out of reach:
/// with the record on disk and the registry already past the feed, a restart with the feed down, a
/// restart with it up and a restart with no feed chosen all leave the device refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wait_outlives_a_restart_with_the_feed_down_up_or_unchosen() {
    let (
        Restorable {
            rig, kept, earlier, ..
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    let Found::Record(record) = rig.the_record() else {
        panic!("the finding is written down");
    };

    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        is_refused_for_the_restored_policy(&rig.serves(&kept.0, &kept.1).await),
        "a restart with the feed up and the registry past it"
    );
    let (host, served) = rig.restarted_while_the_feed_is_down().await;
    let outcome = device_is_served(&host, &kept.0, &kept.1).await;
    assert!(
        is_refused_for_the_restored_policy(&outcome),
        "a restart with the feed down: {outcome:?}"
    );
    let stopped = host.shut_down().await;
    net_support::write_feed_document(stopped.tree(), None);
    let host = stopped.start_with_timer(HeldTimer::held() as _).await;
    let outcome = device_is_served(&host, &kept.0, &kept.1).await;
    assert!(
        is_refused_for_the_restored_policy(&outcome),
        "a restart with no feed chosen at all: {outcome:?}"
    );
    assert_eq!(
        restored::read(&restored::file_beside(
            &host.tree().environment().registry_database()
        )),
        Found::Record(record),
        "and the record is as it was written"
    );
    drop(served);
}

/// KR-REQ-24.15: a confirmation made before any pass of this run has read the feed would serve the
/// registry as restored, and a device an owner revoked through the feed after the copy is live in
/// it. The host that reads a feed refuses the confirmation until a pass has read the feed through
/// and carried out again what it shows; the device the feed revoked then stays refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_is_refused_until_a_pass_of_this_run_has_read_the_feed() {
    let (
        Restorable {
            rig,
            revoked,
            kept,
            earlier,
            ..
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    // The finding is written down, and the registry cannot take the revocation of the device the
    // restore brought back, so nothing is carried out and the registry stays behind its feed.
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute_batch(
                    "CREATE TRIGGER refuse_revocation BEFORE UPDATE OF revoked_at_ms
                         ON network_devices BEGIN SELECT RAISE(ABORT, 'no room'); END;",
                )
                .expect("the fault is in place");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(matches!(rig.the_record(), Found::Record(_)));

    // The next start can write to the registry, and the feed cannot be reached: nothing in this
    // run has compared the registry with the feed, and the device the feed revoked is live in it.
    let rig = rig
        .restarted(true, |tree| {
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute_batch("DROP TRIGGER refuse_revocation")
                .expect("the fault is gone");
        })
        .await;
    assert!(!rig.runtime().has_read_the_feed_through());
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("a confirmation before the host has read its feed in this run is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains(&revoked.1.device_id.to_string()),
        "and names the device the feed revoked, which the first run wrote down and the registry \
         still holds live: {refused:?}"
    );
    assert!(
        matches!(rig.the_record(), Found::Record(_)),
        "the record stands"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the policy waits");
    assert!(
        check.detail().contains(&revoked.1.device_id.to_string()),
        "and says the confirmation is held for it: {}",
        check.detail()
    );

    // Passes go on until one reads the feed through: the feed's four refusals end, the registry
    // takes the revocation, and the host catches up.
    within("a pass reads the feed through", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(
        rig.the_owner_confirms().await.lifted,
        "once a pass has read the feed, the confirmation ends the wait"
    );
    assert_eq!(rig.the_record(), Found::Missing);
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device the feed did not revoke is served");
    rig.connects_while_a_revocation_is_held(&revoked.0, &revoked.1)
        .await;
    assert!(
        rig.the_restored_policy_check().await.is_none(),
        "and the doctor no longer says the policy waits"
    );
}

/// KR-REQ-24.15: a host whose feed removed it reads no more, so it has nothing to compare and its
/// confirmation is not held for a pass that will not come.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_is_not_held_for_a_feed_that_removed_the_host() {
    let rig = Rig::start().await;
    // A record that names no row this host holds is a wait at the next start, and the feed cannot
    // be reached until the case says so.
    let rig = rig
        .restarted(true, |tree| {
            restored::write(
                &restored::file_beside(&tree.environment().registry_database()),
                &restored::Record::of(
                    kr_protocol::scalars::Digest256::from_bytes([1; 32]),
                    TimestampMs::new(1),
                ),
            )
            .expect("a record");
        })
        .await;
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("the host has not read its feed in this run");
    assert!(
        refused.message.contains("authority.origin"),
        "refused for the comparison it owes, and not for catching up: {refused:?}"
    );
    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    within("a pass finds the feed removed the host", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(rig.shown().await.removal_item.is_some());
    assert!(
        rig.the_owner_confirms().await.lifted,
        "a feed that removed the host is read no more, so there is nothing to wait for"
    );
}

/// KR-REQ-24.15: a request the host has not taken, which it puts off while it is behind its feed and
/// carries out in the scan that follows the catch-up, names a device that is live in the registry
/// as restored. The host wrote what the page names before it put the request off, so the
/// confirmation is refused for that device while the scan that carries it out is still to finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_is_refused_until_a_request_put_off_while_behind_is_carried_out() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    let earlier = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    // An earlier run of the host carried out a request that revoked `earlier` under revision 1,
    // which the registry that runs now never saw, so it stands behind the feed. The owner's request
    // naming `target` is published and the host has not taken it.
    let first = rig.signed_by(&rig.owner.authorisation, 0xa0, devices(earlier.1.device_id));
    rig.published_as(&rig.owner.authorisation, &first).await;
    rig.an_earlier_run_carried_out(&first, 0, 1).await;
    let request = rig.signed_by(&rig.owner.authorisation, 0xa1, devices(target.1.device_id));
    rig.published_as(&rig.owner.authorisation, &request).await;

    // The first scan finds the host behind, writes the finding, puts the request off and catches
    // up. The scan that follows reads the feed, and the feed holds that read open.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, Moment::Hold);
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_arrivals("read", reads + 2).await;
    assert!(matches!(rig.the_record(), Found::Record(_)));
    assert!(
        !rig.has_revoked(target.1.device_id).await,
        "the request was put off, and the scan that carries it out has not read the feed through"
    );
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("the device is live in the registry, and the wait holds it back");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "refused for what the request it put off names, which was written before the scan went on: \
         {refused:?}"
    );

    // The read ends without an answer, and a later scan carries the request out.
    rig.served.web().release_held();
    within("a scan carries the request out", async {
        while !rig.has_revoked(target.1.device_id).await {
            rig.poll().await;
        }
    })
    .await;
    assert!(rig.the_owner_confirms().await.lifted);
    rig.connects_while_a_revocation_is_held(&target.0, &target.1)
        .await;
    rig.connects_while_a_revocation_is_held(&earlier.0, &earlier.1)
        .await;
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device nothing revoked is served");
}

/// KR-REQ-24.15: a withdrawal the feed shows complete that is held behind a request the host cannot
/// judge yet is not carried out, so the comparison with the feed is not done: the confirmation is
/// refused, and names the device whose request waits. Once the clock is decided the scan carries
/// the request out and then the withdrawal, and the confirmation ends the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_is_refused_while_a_withdrawal_is_held_behind_a_request_the_host_cannot_judge()
 {
    let Undecidable {
        rig,
        issuer,
        target,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(&[Then::TheOwnersWithdrawalOfTheIssuer], 0)
        .await;
    // A later run starts on the record of an earlier finding, and its clock is not proven.
    let rig = rig
        .restarted(false, |tree| {
            restored::write(
                &restored::file_beside(&tree.environment().registry_database()),
                &restored::Record::of(
                    kr_protocol::scalars::Digest256::from_bytes([1; 32]),
                    TimestampMs::new(1),
                ),
            )
            .expect("a record");
            let _ = std::fs::remove_file(tree.environment().utc_floor_file());
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        !rig.has_revoked(issuer.1.device_id).await,
        "the withdrawal of the issuer waits behind the issuer's request"
    );
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("the withdrawal is not carried out, and the wait holds the device back");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains(&issuer.1.device_id.to_string()),
        "and names the device whose request waits: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the policy waits");
    assert!(
        check.detail().contains(&issuer.1.device_id.to_string()),
        "the doctor names it too: {}",
        check.detail()
    );

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    assert!(rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.has_revoked(issuer.1.device_id).await,
        "the scan that can judge the request carries it out, and then the withdrawal"
    );
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a pass that found the registry behind the feed and stopped before the catch-up
/// leaves the refusal for being behind up, and a feed that then removes the host is read no more,
/// so nothing ends it. The wait for the restored policy takes its place and the person at this
/// machine ends it, once the device the first scan met and could not revoke is revoked: the pass
/// that stopped on an error kept what it met.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_removes_the_host_before_the_catch_up_leaves_the_confirmation_open() {
    let (
        Restorable {
            rig,
            revoked,
            earlier,
            ..
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
            rusqlite::Connection::open(tree.environment().registry_database())
                .expect("the registry opens")
                .execute_batch(
                    "CREATE TRIGGER refuse_revocation BEFORE UPDATE OF revoked_at_ms
                         ON network_devices BEGIN SELECT RAISE(ABORT, 'no room'); END;",
                )
                .expect("the fault is in place");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("the host is still catching up");
    assert!(
        refused.message.contains("catching up"),
        "refused for the catch-up it cannot finish: {refused:?}"
    );

    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    within("a pass finds the feed removed the host", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&revoked.1.device_id.to_string()),
        "the removal does not end what the scan met and could not carry out: {refused:?}"
    );
    rusqlite::Connection::open(rig.host.tree().environment().registry_database())
        .expect("the registry opens")
        .execute_batch("DROP TRIGGER refuse_revocation;")
        .expect("the fault is cleared");
    rig.revokes_at_the_machine(revoked.1.device_id).await;
    assert!(
        rig.the_owner_confirms().await.lifted,
        "a feed that removed the host is read no more, so no catch-up can end"
    );
    assert_eq!(rig.the_record(), Found::Missing);
}

/// KR-REQ-24.15: a host that cannot write the record of a restore does not carry anything out or
/// move the registry; the pass ends with an error, the host stays behind its feed, and the next
/// pass, once the file can be written, writes it and goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_cannot_write_the_record_carries_nothing_out_until_it_can() {
    let (
        Restorable {
            rig,
            revoked,
            kept,
            earlier,
            revision,
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
            // Something that is not a file stands where the record goes.
            std::fs::create_dir(restored::file_beside(
                &tree.environment().registry_database(),
            ))
            .expect("an obstacle");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    let behind = rig
        .host
        .controller()
        .authority_revision()
        .await
        .expect("a revision");
    assert!(
        behind < revision,
        "nothing was carried out and the registry did not move"
    );
    assert!(
        rig.shown()
            .await
            .check
            .is_some_and(|check| check.detail().contains("catching up")),
        "the host is behind its feed and says so"
    );
    let outcome = rig.serves(&kept.0, &kept.1).await;
    assert!(
        outcome.is_err(),
        "and refuses the device meanwhile: {outcome:?}"
    );

    let record = restored::file_beside(&rig.host.tree().environment().registry_database());
    std::fs::remove_dir(&record).expect("the obstacle goes");
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
    assert!(matches!(rig.the_record(), Found::Record(_)));
    assert!(
        rig.host
            .controller()
            .authority_revision()
            .await
            .expect("a revision")
            >= revision,
        "the next pass wrote the record and caught up"
    );
    rig.connects_while_a_revocation_is_held(&revoked.0, &revoked.1)
        .await;
    assert!(is_refused_for_the_restored_policy(
        &rig.serves(&kept.0, &kept.1).await
    ));
}

/// KR-REQ-24.15: a remote owner's request on the feed is still judged and carried out while the
/// policy waits, and the keys the feed may remove the host by stay the owners' keys. The wait
/// refuses remote grants, and the feed is how a known owner reaches the host then too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_owners_revocation_is_carried_out_while_the_policy_waits() {
    let (
        Restorable {
            rig, kept, earlier, ..
        },
        earlier_mirror,
    ) = a_policy_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            put_the_mirror_back(tree, &earlier_mirror);
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(matches!(rig.the_record(), Found::Record(_)));

    let request = rig.owner_publishes(0xb2, devices(kept.1.device_id)).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    assert_eq!(
        rig.held(&request)
            .await
            .acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the request of an owner the host knows is carried out"
    );
    assert!(
        rig.host
            .controller()
            .devices()
            .record_for_device(kept.1.device_id)
            .expect("readable")
            .is_some_and(|record| record.revoked_at_ms.is_some()),
        "and the device is revoked"
    );
    assert!(
        rig.feed_as_the_owner_sees_it()
            .await
            .summary
            .removal_keys
            .contains(&rig.owner.authorisation.key_id()),
        "while the owner's key stays among the keys that may remove the host from the feed"
    );
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
    /// How many changes to the list of keys that may remove the feed had reached the feed when the
    /// registry was put back, when `delegations` named faults.
    delegated: usize,
}

/// Pairs the device the withdrawal will name with `victim_rights` and one it will not, which is
/// given a share of a session, takes a copy of the registry, pairs another owner, has that owner
/// withdraw the first device and the share from the feed, carries both out, and puts the registry
/// back to the copy.
///
/// `delegations` are faults for the changes the host makes to the keys it lists as permitted to
/// remove the feed, counted from the first change after the other owner is paired: the first of
/// them is the change that follows the withdrawal, and the feed turning it back is what leaves the
/// device's key listed when the registry is put back. The host is then left to run on its own after
/// the restart only when `then_idle`; else the case waits for what it wants to see. The wait for the
/// restored policy that the restore puts on the host stands when `waits`; else the person ends it
/// by the route the refusal gives, which removes the record's file by hand, so that what the case
/// holds is what the feed does beyond that wait.
async fn a_withdrawal_by_an_owner_the_host_does_not_know(
    victim_rights: &[ActionRight],
    delegations: &[(u32, Moment)],
    then_idle: bool,
    waits: bool,
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
    for (nth, moment) in delegations {
        rig.served
            .web()
            .fail_with_member(AUTHORITY, "delegate", *nth, *moment);
    }
    let delegated_before = rig.arrivals("delegate");
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
    if !delegations.is_empty() {
        // The change that follows the withdrawal has reached the feed, which turned it back: the
        // feed still lists the key of the device the withdrawal names.
        rig.until_arrivals("delegate", delegated_before + 1).await;
        let listed = rig.feed_as_the_owner_sees_it().await.summary.removal_keys;
        assert!(
            listed.contains(&victim.0.keys().authorisation.key_id()),
            "the feed still lists the device's key: {listed:?}"
        );
    }
    let delegated = rig.arrivals("delegate");

    // The registry goes back to before that owner was paired.
    let mut rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    if then_idle {
        rig.until_the_carrier_is_idle().await;
        rig.until_the_carrier_is_idle().await;
        // The host found its policy restored with its registry, and waits for the person at the
        // machine as well; what most of these cases hold is what the feed does beyond that wait.
        // A feed that turns the change back keeps the host from finishing its catch-up, and the
        // wait is not ended for that.
        if delegations.is_empty() && !waits {
            rig = rig.the_wait_is_ended_by_hand().await;
            rig.until_the_carrier_is_idle().await;
            rig.until_the_carrier_is_idle().await;
        }
    }
    Unverifiable {
        rig,
        victim,
        kept,
        owner,
        share,
        delegated,
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
        ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::SessionView],
        &[],
        true,
        false,
    )
    .await;

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
    // It says what to do about it: never to revoke the last owner device while the refusal stands,
    // and the route that exists when the withdrawal names every owner device, which is to point
    // `authority.origin` at none.
    let remedy = check.remedy().expect("and it says what to do about it");
    for named in ["last owner device", "authority.origin"] {
        assert!(remedy.contains(named), "{named} is not in: {remedy}");
    }
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

impl Rig {
    /// The rig's owner device signs the confirmation for issuing a session invitation, and the host
    /// is asked to issue it.
    async fn owner_device_invites(
        &self,
        client: &mut kr_ipc::client::LocalClient,
    ) -> Result<kr_protocol::invitation::PairInviteResult, kr_protocol::error::ProtocolError> {
        net_support::pairing::invite_direct(
            self.host.environment_id,
            client,
            kr_protocol::invitation::InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView]),
            &net_support::pairing::Signer::OwnerDevice(&self.owner),
        )
        .await
    }
}

/// KR-REQ-24.15: an owner confirmation a remote owner device signed is not spent while a
/// withdrawal the host cannot verify refuses remote grants: the device's standing is taken away
/// whole, and what it signed waits with it. The owner at the machine ends the refusal by revoking
/// what the withdrawals name, which needs no confirmation, and a confirmation signed after that is
/// spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_confirmation_a_remote_owner_device_signed_is_not_spent_while_the_host_refuses_remote_grants()
 {
    let Unverifiable {
        rig, victim, share, ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::SessionView],
        &[],
        true,
        false,
    )
    .await;
    let mut local = rig.host.client().await;
    let refused = rig
        .owner_device_invites(&mut local)
        .await
        .expect_err("a confirmation is not spent while the host refuses remote grants");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("an owner this host does not know"),
        "refused for the refusal and in its words: {refused:?}"
    );

    // The owner at the machine revokes what the withdrawals name, which needs no confirmation.
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
    net_support::worker::revoke(&rig.host, share.grant_id).await;
    rig.until_the_carrier_is_idle().await;
    rig.owner_device_invites(&mut local)
        .await
        .expect("a confirmation signed once the refusal has ended is spent");
}

/// KR-REQ-24.15: an owner confirmation a remote owner device signed is not spent after the feed
/// removed the host when that device's grant rests on the feed: here the owner bounded offline
/// validity, so the personal grant of the device rests on it. The removal takes the standing of such
/// a device away at the door and where its confirmation is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_confirmation_is_not_spent_after_the_feed_removed_the_host_when_the_signers_grant_rests_on_it()
 {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    rig.the_feed_removes_the_host().await;
    let mut local = rig.host.client().await;
    let refused = rig
        .owner_device_invites(&mut local)
        .await
        .expect_err("a confirmation is not spent under a grant that rests on a removed feed");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("was removed"),
        "refused for the removal and in its words: {refused:?}"
    );
}

/// KR-REQ-24.15: the removal leaves alone an owner device whose grant does not rest on the feed, the
/// default non-expiring owner grant: what it signed is spent after the removal, so the owner who
/// has such a device still confirms without the feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_confirmation_is_spent_after_the_feed_removed_the_host_when_the_signers_grant_does_not_rest_on_it()
 {
    let rig = Rig::start().await;
    rig.the_feed_removes_the_host().await;
    let mut local = rig.host.client().await;
    rig.owner_device_invites(&mut local)
        .await
        .expect("a grant that does not rest on the feed is not refused by its removal");
}

/// KR-REQ-24.15: the terminal confirms the pairing of a host's first owner while the host refuses
/// remote grants, as it does otherwise: a host with no owner has no remote owner device to
/// confirm, and no device to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_terminal_still_confirms_the_first_owner_while_the_host_refuses_remote_grants() {
    let host = Host::start_unowned().await;
    host.controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    assert!(
        host.controller().policy().withdrawal_unverified(),
        "the control: the refusal stands"
    );
    let owner = DeviceKeys::generate().expect("owner keys");
    let (_device, record) = net_support::bootstrap_owner(&host, &owner).await;
    assert!(record.grant.permits(ActionRight::HostManage));
}

/// A withdrawal by an owner the host does not know that names more devices than the doctor says by
/// name is said by name for eight of them, and the rest are counted: a person reads a few names and
/// how many more there are, and not a line as long as the withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_doctor_names_eight_of_the_devices_a_withdrawal_names_and_counts_the_rest() {
    let rig = Rig::start().await;
    let mut named = Vec::new();
    for _ in 0..9 {
        named.push(rig.pairs(&[ActionRight::SessionView]).await.1.device_id);
    }
    let spare = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let stranger = AuthorisationKeyPair::generate().expect("a key");
    let withdrawal = rig.request_of(
        &stranger,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        RevocationTarget::Devices {
            device_ids: named.iter().copied().collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&stranger, &withdrawal).await;
    rig.an_earlier_run_carried_out(&withdrawal, 0, 1).await;
    // The registry stands at the feed's revision, so the host is not behind it and finds the
    // withdrawal complete.
    rig.revokes_at_the_machine(spare.1.device_id).await;
    rig.until_the_carrier_is_idle().await;

    let check = rig.shown().await.check.expect("the feed check");
    let detail = check.detail();
    assert_eq!(
        named
            .iter()
            .filter(|device| detail.contains(&device.to_string()))
            .count(),
        8,
        "eight of the nine devices are named: {detail}"
    );
    assert!(
        detail.contains("; 1 more are not listed"),
        "and the ninth is counted: {detail}"
    );
}

/// KR-REQ-24.15: a withdrawal the feed shows complete that would revoke the issuer of a request the
/// host cannot judge yet is not carried out ahead of that request: the request would be refused
/// later for a revocation that came after it, and what it named would stay live. The pass ends at the
/// withdrawal, as it ends at the request, and the scan after the clock is proven carries the request
/// out and then the withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_that_would_revoke_the_issuer_of_a_request_the_host_cannot_decide_waits_behind_it()
 {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(&[Then::TheOwnersWithdrawalOfTheIssuer], 0)
        .await;
    let key = issuer.0.keys().authorisation.clone();
    assert!(
        !rig.has_revoked(issuer.1.device_id).await,
        "the withdrawal of the issuer is not carried out ahead of the issuer's request"
    );
    assert_eq!(
        rig.held_as(&key, &first).await.rejected.0,
        None,
        "and the request is not refused for it"
    );

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    let carried_out = rig.held_as(&key, &first).await;
    assert_eq!(
        carried_out
            .acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the scan after the clock is proven carries the request out: {carried_out:?}"
    );
    assert!(rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.has_revoked(issuer.1.device_id).await,
        "and then the withdrawal"
    );
}

/// KR-REQ-24.15: a complete record that would revoke the issuer of a request the host cannot judge
/// yet waits for it, and the scan goes on reading: the withdrawal the host cannot verify that comes
/// before it raises its refusal, and the owner at the machine ends that refusal by revoking what it
/// names, with no revocation of the issuer needed. Else the refusal could not end while the clock
/// is unproven, and the confirmation that proves it would be refused for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_held_for_the_issuer_of_a_request_the_host_cannot_decide_does_not_keep_a_refusal_up()
 {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        named,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(
        &[
            Then::AnUnknownOwnersWithdrawal,
            Then::TheOwnersWithdrawalOfTheIssuer,
        ],
        0,
    )
    .await;
    assert!(rig.host.controller().policy().withdrawal_unverified());
    assert!(
        !rig.has_revoked(issuer.1.device_id).await,
        "the withdrawal of the issuer waits behind the issuer's request"
    );

    // The owner at the machine revokes what the withdrawal names, as the doctor says.
    rig.revokes_at_the_machine(named.1.device_id).await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        !rig.host.controller().policy().withdrawal_unverified(),
        "the scan settled the refusal though a record waits"
    );
    assert!(
        !rig.has_revoked(issuer.1.device_id).await,
        "and the issuer did not have to be revoked for it"
    );

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    let key = issuer.0.keys().authorisation.clone();
    assert_eq!(
        rig.held_as(&key, &first)
            .await
            .acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the request is carried out once the clock is proven"
    );
    assert!(rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.has_revoked(issuer.1.device_id).await,
        "and then the withdrawal"
    );
}

/// KR-REQ-24.15: a request behind one the host cannot judge, which is not complete, is held with
/// its issuer: a withdrawal of that issuer is not carried out ahead of it, and the request is
/// carried out once the clock is proven, as it is when nothing waits before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_held_behind_one_the_host_cannot_decide_is_not_refused_for_a_withdrawal_after_it()
{
    let Undecidable {
        rig,
        target,
        named,
        other_owner,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(
        &[
            Then::AWaitingRequestOfTheOtherOwner,
            Then::TheOwnersWithdrawalOfTheOtherOwner,
        ],
        0,
    )
    .await;
    assert!(
        !rig.has_revoked(other_owner.1.device_id).await,
        "the withdrawal of the second request's issuer waits behind its request"
    );

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    assert!(rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.has_revoked(named.1.device_id).await,
        "the second request is carried out: it was made before its issuer was withdrawn"
    );
    assert!(rig.has_revoked(other_owner.1.device_id).await);
}

/// KR-REQ-24.15: a pass that ends because a request cannot be judged still takes the key of an
/// owner it revoked off the list of keys that may remove the feed, and adds no key: else the owner
/// the replay revoked could still remove the host from its feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_ends_undecided_takes_the_key_of_an_owner_it_revoked_off_the_feeds_list() {
    let Undecidable {
        rig, other_owner, ..
    } = a_request_whose_issuer_the_host_cannot_decide(
        &[Then::TheOwnersWithdrawalOfTheOtherOwner],
        0,
    )
    .await;
    assert!(
        rig.has_revoked(other_owner.1.device_id).await,
        "the withdrawal of the second owner was carried out again, which asks no clock"
    );
    let listed = rig.feed_as_the_owner_sees_it().await.summary.removal_keys;
    assert!(
        !listed.contains(&other_owner.0.keys().authorisation.key_id()),
        "the revoked owner can no longer remove the feed: {listed:?}"
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
        &[],
        true,
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
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        !check.detail().contains("an owner this host does not know"),
        "and the host no longer says it waits: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: a refusal a device a withdrawal names would end by removing the feed stands when
/// the feed still lists that device's key. The feed turns back every change the host makes to the
/// list of keys that may remove it, so the list after the registry is put back is the list from
/// before the withdrawal, and the device removes the feed with it. The removal says nothing of an
/// owner having acted, so the host goes on refusing remote access, and says it will until the
/// daemon starts again: a feed that was removed is read no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_still_lists_the_key_of_a_device_a_withdrawal_names_does_not_end_the_refusal_when_removed()
 {
    let turned_back: Vec<(u32, Moment)> = (1..=64).map(|nth| (nth, TURNED_BACK)).collect();
    let Unverifiable {
        rig, victim, kept, ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        &turned_back,
        true,
        false,
    )
    .await;
    assert!(
        rig.answers(&kept.0, &kept.1).await.is_err(),
        "remote access is refused"
    );

    client_for(rig.served.origin(), victim.0.keys().authorisation.clone())
        .remove(rig.feed())
        .await
        .expect("the feed takes the removal from a key it lists");
    rig.poll().await;
    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        refused.is_err(),
        "a removal by a key the withdrawal takes the right from does not end the refusal"
    );
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the host still says what it waits for: {}",
        check.detail()
    );
    assert!(
        check.detail().contains("until the daemon starts again"),
        "and what ends it, which is not the owner at the machine revoking what is named: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: the host takes the key of a device a withdrawal names off the list of keys that
/// may remove the feed when it finds the withdrawal, not when the scan has read the feed through.
/// The list the feed holds when the registry is put back still names the device; the host's
/// change that follows the withdrawal is taken, and the change that ends the scan is turned back,
/// so the scan stops there. The list then lacks the device's key, still names the other owners'
/// as they were, and the device cannot remove the feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_key_of_a_device_a_withdrawal_names_is_taken_off_the_feeds_list_when_it_is_found() {
    // The first change is the one after the withdrawal, turned back; the second is the host's
    // first after the registry is put back, which is the one this case is about, and is taken;
    // every later one is turned back, so the scan ends with the list as that change left it.
    let faults: Vec<(u32, Moment)> = std::iter::once((1, TURNED_BACK))
        .chain((3..=64).map(|nth| (nth, TURNED_BACK)))
        .collect();
    let Unverifiable {
        rig,
        victim,
        kept,
        owner,
        ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        &faults,
        true,
        false,
    )
    .await;

    let listed = rig.feed_as_the_owner_sees_it().await.summary.removal_keys;
    assert!(
        !listed.contains(&victim.0.keys().authorisation.key_id()),
        "the device's key is off the list: {listed:?}"
    );
    assert!(
        listed.contains(&rig.owner.authorisation.key_id())
            && listed.contains(&owner.0.keys().authorisation.key_id()),
        "and the host changed nothing else, as the scan did not end: {listed:?}"
    );
    client_for(rig.served.origin(), victim.0.keys().authorisation.clone())
        .remove(rig.feed())
        .await
        .expect_err("a key taken off the list cannot remove the feed");
    assert!(
        rig.answers(&kept.0, &kept.1).await.is_err(),
        "remote access is refused"
    );
}

/// KR-REQ-24.15: a change to the list of keys that may remove the feed, taken by a feed that was
/// removed while the change waited, does not show the device's key cleared: the device removed the
/// feed with the key the list still held when it did, and the host cannot tell who did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_to_the_feeds_list_taken_after_the_feed_was_removed_does_not_end_the_refusal() {
    // The first change is turned back, as above. The second is the host's first after the registry
    // is put back: the feed holds it until the case lets it go, which is after the device has
    // removed the feed.
    let Unverifiable {
        rig,
        victim,
        kept,
        delegated,
        ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        &[(1, TURNED_BACK), (2, Moment::Gate)],
        false,
        false,
    )
    .await;
    rig.until_arrivals("delegate", delegated + 1).await;
    client_for(rig.served.origin(), victim.0.keys().authorisation.clone())
        .remove(rig.feed())
        .await
        .expect("the feed takes the removal from a key it lists");
    rig.served.web().release_held();
    rig.poll().await;
    rig.poll().await;
    assert!(
        rig.answers(&kept.0, &kept.1).await.is_err(),
        "a change taken after the removal does not end the refusal"
    );
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the host still says what it waits for: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: a change to the list of keys that may remove the feed, which the feed answers by
/// saying it removed this host, ends the pass as the read's own answer does: the grants that rest
/// on the feed are refused when the answer is read, and not when the next read finds the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_to_the_feeds_list_answered_by_its_removal_refuses_the_grants_that_rest_on_it_at_once()
 {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    rig.until_the_carrier_is_idle().await;
    rig.doctor_as(&session)
        .await
        .expect("inside the bound, with the feed standing");

    // The owner paired next changes the list, and the feed holds the change until the key it still
    // lists has removed the feed.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "delegate", 1, Moment::Gate);
    let delegated = rig.arrivals("delegate");
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    let _next_owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_arrivals("delegate", delegated + 1).await;
    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    rig.served.web().release_held();
    within("the pass the change was made in ends", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;

    assert!(
        rig.shown().await.list.feed_removed,
        "the host shows that the feed removed it"
    );
    let refused = rig
        .doctor_as(&session)
        .await
        .expect_err("the grant rests on a feed that removed the host");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal and not for something else: {refused}"
    );
}

/// KR-REQ-24.15: the answer to the host's own revision, when it is the feed's removal of the host,
/// ends the pass as the read's own answer does: the grants that rest on the feed are refused when
/// the answer is read, and not when the next read finds the removal. The feed stores a revision
/// for a host it removed and answers `removed`, where its acknowledgements find no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_answered_by_the_feeds_removal_refuses_the_grants_that_rest_on_it_at_once() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    let (_target, target_record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    rig.doctor_as(&session)
        .await
        .expect("inside the bound, with the feed standing");

    // The feed holds the host's revision of a request it carries out until a key the host named has
    // removed the feed.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "revise", 1, Moment::Gate);
    let revised = rig.arrivals("revise");
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    rig.owner_publishes(0xb7, devices(target_record.device_id))
        .await;
    rig.runtime().wake();
    rig.until_arrivals("revise", revised + 1).await;
    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    rig.served.web().release_held();
    within("the pass the revision was sent in ends", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;

    assert!(
        rig.shown().await.list.feed_removed,
        "the host shows that the feed removed it"
    );
    let refused = rig
        .doctor_as(&session)
        .await
        .expect_err("the grant rests on a feed that removed the host");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused.to_string().contains("was removed"),
        "refused for the feed's removal and not for something else: {refused}"
    );
}

/// KR-REQ-24.15: a refusal that rises waits for every write to the pairing records that was under
/// way, and while it waits `kr doctor` says so: the refusal stands, this host reads no more of the
/// feed until the registry has taken a write, and the check is a warning with a remedy. Another
/// handle on the registry holds its write lock until the case lets it go, and the wait says it goes
/// on once it has waited out the database's busy timeout. When the write ends the wait ends, and the
/// check no longer says it. A wait whose ask for the lock the database has not answered in time
/// names the unanswered ask instead, as a busy machine brings about whether or not a write is
/// held, so the case reads the check until it names the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_doctor_says_that_a_refusal_waits_for_a_write_to_the_pairing_records() {
    const WAITS: &str = "waits for the registry to take a write";
    const HELD: &str = "a write to the pairing records has held the registry's write lock";

    let rig = Rig::start().await;
    // The last pass stopped because the feed turned a request back, and the check carries the advice
    // for that, which the wait for the registry replaces while it goes on.
    for nth in 1..=4 {
        rig.served
            .web()
            .fail_with_member(AUTHORITY, "read", nth, TURNED_BACK);
    }
    rig.poll().await;
    let before = rig.shown().await.check.expect("the feed check");
    assert!(
        before
            .remedy()
            .is_some_and(|remedy| remedy.contains("Until the feed answers")),
        "the control: the stopped pass has its own advice: {:?}",
        before.remedy()
    );
    let writer = rusqlite::Connection::open(rig.host.registry_database()).expect("the registry");
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the write lock is taken");
    let raising = tokio::spawn({
        let controller = Arc::clone(rig.host.controller());
        async move {
            controller.raise_the_unverified_withdrawal_refusal().await;
        }
    });
    let mut said = String::new();
    let naming = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let check = rig.shown().await.check.expect("the feed check");
            if check.detail().contains(HELD) {
                break check;
            }
            said = check.detail().to_owned();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let check = naming.unwrap_or_else(|_| {
        panic!("gave up waiting for the check to name the write that holds the wait: {said}")
    });
    assert_eq!(check.status, DoctorStatus::Warning, "{}", check.detail());
    assert!(
        check.detail().contains(WAITS),
        "it says that the refusal waits: {}",
        check.detail()
    );
    assert!(
        check.remedy().is_some_and(|remedy| {
            remedy.contains("takes a write") && !remedy.contains("Until the feed answers")
        }),
        "and what to do, in place of the stopped pass's advice: {:?}",
        check.remedy()
    );
    assert!(!raising.is_finished(), "the refusal's rise waits meanwhile");

    writer.execute_batch("ROLLBACK").expect("the write ends");
    within("the rise returns", raising)
        .await
        .expect("the rise ends");
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        !check.detail().contains(WAITS),
        "a wait that has ended is not said to go on: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: a withdrawal the host cannot verify takes the keys of the devices it names off the
/// list the feed takes a removal from while a write to the pairing records is held, and not only
/// once the write has ended: the wait of the refusal for the registry does not hold the shorter list
/// back, because the keys are known before the refusal rises. The registry stands at the feed's
/// revision, so the unverified refusal is the first that the pass raises.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_the_host_cannot_verify_takes_its_keys_off_the_feeds_list_while_a_write_is_held()
 {
    let rig = Rig::start().await;
    let named = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let spare = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let key = named.0.keys().authorisation.key_id();
    assert!(
        rig.feed_as_the_owner_sees_it()
            .await
            .summary
            .removal_keys
            .contains(&key),
        "the control: the feed lists the key of the device the withdrawal will name"
    );
    let stranger = AuthorisationKeyPair::generate().expect("a key");
    let withdrawal = rig.request_of(
        &stranger,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        devices(named.1.device_id),
    );
    rig.published_as(&stranger, &withdrawal).await;
    rig.an_earlier_run_carried_out(&withdrawal, 0, 1).await;
    // The pass that the local revocation wakes is held at its read until the write is taken, so
    // that the pass meets the withdrawal with the write held and not before. The registry reaches
    // the feed's revision by that revocation, so the host is not behind its feed.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Gate);
    let reads = rig.arrivals("read");
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
    rig.revokes_at_the_machine(spare.1.device_id).await;
    rig.until_arrivals("read", reads + 1).await;

    let writer = rusqlite::Connection::open(rig.host.registry_database()).expect("the registry");
    writer
        .busy_timeout(Duration::from_secs(5))
        .expect("the writer waits for a write that is under way");
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the write lock is taken");
    rig.served.web().release_held();
    within(
        "the feed lists no key of the device the withdrawal names",
        async {
            while rig
                .feed_as_the_owner_sees_it()
                .await
                .summary
                .removal_keys
                .contains(&key)
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await;
    assert!(
        rig.host.controller().policy().withdrawal_unverified(),
        "the refusal stands meanwhile"
    );
    assert!(
        *passes.borrow() <= seen,
        "and the pass has not ended while the write is held"
    );

    writer.execute_batch("ROLLBACK").expect("the write ends");
    within("the pass ends once the write has", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
}

/// A change to the list of keys that may remove the feed, turned back with a delay, ends the pass:
/// the host asks the feed for nothing more until the delay is over, as it does for any request the
/// feed turns back with one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_to_the_feeds_list_turned_back_with_a_delay_is_the_last_request_of_the_pass() {
    let delayed = Moment::Refuse {
        status: 503,
        code: "SERVICE_UNAVAILABLE",
        retry_after_seconds: Some(120),
    };
    let Unverifiable { rig, delegated, .. } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::HostManage, ActionRight::SessionView],
        &[(1, TURNED_BACK), (2, delayed)],
        false,
        false,
    )
    .await;
    let (waited, _release) = within("the carrier waits", rig.timer.next_wait()).await;
    assert!(
        waited >= Duration::from_secs(120),
        "the carrier waits out the delay the feed asked for: {waited:?}"
    );
    assert_eq!(
        rig.arrivals("delegate"),
        delegated + 1,
        "and the change the feed turned back was the last request of the pass that made it"
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

/// The host, as the feed knows it: requests signed with the host's own key.
#[derive(Debug)]
struct HostAtTheFeed(AuthorisationKeyPair);

impl kr_client::services::ServiceSigner for HostAtTheFeed {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Host
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Host.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

impl Rig {
    /// Makes the feed hold what an earlier run of the host that carried `request` out would have
    /// left in it: revision `number`, issued after `previous`, for that request, and the request
    /// acknowledged complete. The host that runs now has taken none of it.
    async fn an_earlier_run_carried_out(
        &self,
        request: &RevocationRequest,
        previous: u64,
        number: u64,
    ) {
        self.an_earlier_run_acknowledged(request, previous, number, RevocationCompletion::Complete)
            .await;
    }

    /// As [`Self::an_earlier_run_carried_out`], with the request acknowledged as `completion`
    /// says: a revocation whose barrier did not hold for every worker is shown pending.
    async fn an_earlier_run_acknowledged(
        &self,
        request: &RevocationRequest,
        previous: u64,
        number: u64,
        completion: RevocationCompletion,
    ) {
        let gateway = GatewayOrigin::new(self.served.origin()).expect("an origin");
        let http: Arc<dyn ServiceHttp> = Arc::new(
            HttpService::with(
                gateway.clone(),
                HttpDeadlines::default(),
                managed_response_limits(),
            )
            .expect("a transport"),
        );
        let as_the_host = AuthorityFeedClient::new(
            gateway,
            http,
            Arc::new(HostAtTheFeed(self.host_keys.authorisation.clone())),
        );
        let mut revision = AuthorityRevisionRecord {
            host_device_id: self.host_device(),
            authority_revision: AuthorityRevision::new(number),
            previous_revision: AuthorityRevision::new(previous),
            applied_requests: [request.request_id]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
            host_key_id: self.feed(),
            signature: Signature64::from_bytes([0; 64]),
        };
        let input = revision.signing_input().expect("a signing input");
        let transcript = SigningTranscript::from_canonical_bytes(AUTHORITY_REVISION_DOMAIN, input)
            .expect("a transcript");
        revision.signature = sign(&self.host_keys.authorisation, &transcript).expect("a signature");
        as_the_host
            .revise(&revision, None)
            .await
            .expect("the feed takes the revision");
        as_the_host
            .acknowledge(
                &RevocationAcknowledgement {
                    request_id: request.request_id,
                    host_device_id: self.host_device(),
                    authority_revision: AuthorityRevision::new(number),
                    completion,
                    acknowledged_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
                },
                None,
            )
            .await
            .expect("the feed takes the acknowledgement");
    }

    /// A request `issuer` signs with `key`, naming `target`, under a fixed identity.
    fn request_of(
        &self,
        key: &AuthorisationKeyPair,
        issuer: DeviceId,
        id: u8,
        target: RevocationTarget,
    ) -> RevocationRequest {
        kr_pairing::grants::sign_revocation_request(
            key,
            RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16])),
            issuer,
            self.host_device(),
            target,
            TimestampMs::new(kr_ipc::now_ms().get()),
        )
        .expect("a signed request")
    }

    /// Publishes `request` as the holder of `key`, whose key the feed knows it by.
    async fn published_as(&self, key: &AuthorisationKeyPair, request: &RevocationRequest) {
        client_for(self.served.origin(), key.clone())
            .publish(self.feed(), request, None)
            .await
            .expect("the feed stores the request");
    }

    /// What the feed holds of `request`, as the holder of `key` who published it reads it.
    async fn held_as(
        &self,
        key: &AuthorisationKeyPair,
        request: &RevocationRequest,
    ) -> kr_client::services::authority::AuthorityFeedRecord {
        client_for(self.served.origin(), key.clone())
            .read(self.feed(), None, false)
            .await
            .expect("the feed answers its publisher")
            .record(request.request_id)
            .expect("the record")
            .clone()
    }
}

/// A device's request that the host has not taken, ahead in the feed of a withdrawal of that device
/// that an earlier run of the host carried out, and a host that stands behind the feed.
struct PutOff {
    rig: Rig,
    /// The device that made the first request, an owner.
    issuer: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The device the first request names.
    target: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// A device neither request names.
    kept: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The first request.
    first: RevocationRequest,
}

/// Pairs an owner `v`, a device `t` its request will name and a device `k` nothing names, has `v`
/// publish a request naming `t` and then an owner `o` publish a withdrawal of `v`, and makes the feed
/// hold the withdrawal as an earlier run of the host would have left it: carried out, under
/// revision 1. The host that runs now has not taken the first request, and stands at revision 0
/// behind the feed. `o` is an owner it knows when `o_is_paired`, and one a registry put back to
/// before it was paired does not hold otherwise.
async fn a_request_the_host_has_not_taken_ahead_of_a_withdrawal_it_has(
    o_is_paired: bool,
) -> PutOff {
    let rig = Rig::start().await;
    let rights = [ActionRight::HostManage, ActionRight::SessionView];
    let issuer = rig.pairs(&rights).await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    let (o_key, o_device) = if o_is_paired {
        let o = rig.pairs(&rights).await;
        (o.0.keys().authorisation.clone(), o.1.device_id)
    } else {
        (
            AuthorisationKeyPair::generate().expect("a key"),
            DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0e; 16])),
        )
    };
    // Every pass the pairings woke has ended, so none reads the feed before the case has made it.
    rig.until_the_carrier_is_idle().await;
    let issuer_key = issuer.0.keys().authorisation.clone();
    let first = rig.request_of(
        &issuer_key,
        issuer.1.device_id,
        0xe1,
        devices(target.1.device_id),
    );
    let withdrawal = rig.request_of(&o_key, o_device, 0xe2, devices(issuer.1.device_id));
    rig.published_as(&issuer_key, &first).await;
    rig.published_as(&o_key, &withdrawal).await;
    rig.an_earlier_run_carried_out(&withdrawal, 0, 1).await;
    PutOff {
        rig,
        issuer,
        target,
        kept,
        first,
    }
}

/// KR-REQ-24.15: a request the host put off while it was behind its feed is judged by the standing
/// its issuer had at its place in the feed. A withdrawal of the issuer that the host cannot verify
/// comes after the request, so it took nothing from the issuer yet: the request is carried out, and
/// its targets stay withdrawn when the owner at the machine has dealt with the withdrawal, which is
/// what the host refuses remote access for meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_put_off_ahead_of_a_withdrawal_the_host_cannot_verify_is_carried_out() {
    let PutOff {
        rig,
        issuer,
        target,
        kept,
        first,
    } = a_request_the_host_has_not_taken_ahead_of_a_withdrawal_it_has(false).await;
    rig.until_the_carrier_is_idle().await;
    // The withdrawal names the issuer, who is live here: the wait owes it, and the confirmation is
    // refused until the person has revoked it. What this case holds is what the feed does beyond
    // the wait, so the wait is ended by the route that removes the record by hand.
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&issuer.1.device_id.to_string()),
        "and it names the issuer the withdrawal names: {refused:?}"
    );
    let rig = rig.the_wait_is_ended_by_hand().await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;

    let refused = rig.answers(&kept.0, &kept.1).await;
    assert!(
        says_an_owner_is_unknown(&refused),
        "the withdrawal the host cannot verify refuses remote access: {refused:?}"
    );
    let held = rig.held_as(&issuer.0.keys().authorisation, &first).await;
    assert_eq!(
        held.rejected.0, None,
        "the device was an owner where its request stands in the feed: {held:?}"
    );
    assert_eq!(
        held.acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "and the host carried it out: {held:?}"
    );

    // The owner at this machine revokes the device the withdrawal names, as the doctor says.
    let mut local = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: issuer.1.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");
    rig.until_the_carrier_is_idle().await;
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("the other device is served once the owner at the machine has acted");
    rig.connects_while_a_revocation_is_held(&target.0, &target.1)
        .await;
}

/// KR-REQ-24.15: a request put off while the host was behind its feed, whose issuer a later
/// withdrawal by an owner the host knows revoked, is held while the wait stands and owes what it
/// names. The registry holds the issuer revoked, but that may be the person's act after the restore
/// and says nothing of whether the request was made, so the host neither carries it out nor sends
/// the feed a refusal, which a later restore would read as "never applied", and the confirmation is
/// refused for the device it names until the person has revoked it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_put_off_ahead_of_a_withdrawal_the_host_carried_out_again_is_held_and_its_target_owed()
 {
    let PutOff {
        rig,
        issuer,
        target,
        kept,
        first,
    } = a_request_the_host_has_not_taken_ahead_of_a_withdrawal_it_has(true).await;
    rig.until_the_carrier_is_idle().await;

    let held = rig.held_as(&issuer.0.keys().authorisation, &first).await;
    assert_eq!(
        held.rejected.0, None,
        "the issuer is revoked, and the request is held and not refused: {held:?}"
    );
    assert!(rig.has_revoked(issuer.1.device_id).await);
    assert!(!rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(target.1.device_id)),
        "and what it names is written to the record of the restore"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the confirmation is refused for the device the request names: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
    let session = connect(&rig.host, &kept.0, &kept.1).await;
    rig.doctor_as(&session)
        .await
        .expect("a device the request did not name is served");
    rig.connects_while_a_revocation_is_held(&target.0, &target.1)
        .await;
    // The wait is over, and the next scan judges the request as today and refuses it.
    rig.poll().await;
    assert_eq!(
        rig.held_as(&issuer.0.keys().authorisation, &first)
            .await
            .rejected
            .0,
        Some(RejectionReason::NoOwnerAuthority),
        "the first scan after the wait refuses it"
    );
}

/// KR-REQ-24.15: where a withdrawal the host cannot verify stands in the feed is read from the feed
/// by every run, and no state of the run before is needed. The first run puts the request off,
/// because the registry stands behind the feed, and finds the withdrawal; the feed turns back the
/// change the host makes to its list of keys, and the run stops there, before the registry has
/// caught up. The run that follows starts behind its feed as well, finds the withdrawal in its
/// first scan and judges the request in the scan after the catch-up, and carries it out all the
/// same: the issuer is still live where its request stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_ahead_of_a_withdrawal_is_carried_out_by_the_run_that_follows_a_stop_between_them()
 {
    let PutOff {
        rig,
        issuer,
        target,
        kept,
        first,
    } = a_request_the_host_has_not_taken_ahead_of_a_withdrawal_it_has(false).await;
    // The first scan reads the feed, puts the request off and finds the withdrawal, which names a
    // key the feed lists as permitted to remove it; the feed turns the change back, and the host
    // stops there.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "delegate", 1, TURNED_BACK);
    rig.poll().await;
    let stopped = rig.shown().await.check.expect("the feed check");
    assert!(
        stopped.detail().contains("catching up with it"),
        "the registry is still behind the feed when the run stops: {}",
        stopped.detail()
    );
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;

    let held = rig.held_as(&issuer.0.keys().authorisation, &first).await;
    assert_eq!(
        held.rejected.0, None,
        "the run that follows judges the request at its place: {held:?}"
    );
    assert!(
        rig.has_revoked(target.1.device_id).await,
        "and carries it out: {held:?}"
    );
    assert!(!rig.has_revoked(kept.1.device_id).await);
}

/// KR-REQ-24.15: the request of a device the owner at the machine revoked is refused, wherever it
/// stands in the feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_of_a_device_the_owner_revoked_at_the_machine_is_refused() {
    let rig = Rig::start().await;
    let issuer = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let mut local = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: issuer.1.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");
    rig.until_the_carrier_is_idle().await;
    let key = issuer.0.keys().authorisation.clone();
    let request = rig.request_of(&key, issuer.1.device_id, 0xe3, devices(target.1.device_id));
    rig.published_as(&key, &request).await;
    rig.poll().await;

    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "a revoked owner's request is refused"
    );
    let session = connect(&rig.host, &target.0, &target.1).await;
    rig.doctor_as(&session)
        .await
        .expect("what the request named was not withdrawn");
}

/// A device revoked at the machine, a request it published, and the live owner's request naming it
/// after that.
struct RevokedIssuer {
    rig: Rig,
    /// The device revoked at the machine, whose key the request is signed with.
    issuer: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The device its request names.
    target: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The request.
    first: RevocationRequest,
}

/// Pairs an owner `v` and a device `t`, has the owner at the machine revoke `v`, and publishes a
/// request of `v` naming `t` and then the host's owner's request naming `v`. The second is made
/// complete, as an earlier run of the host would have left it, when `complete`.
async fn a_request_of_a_device_revoked_at_the_machine_ahead_of_a_live_owners_withdrawal(
    complete: bool,
) -> RevokedIssuer {
    let rig = Rig::start().await;
    let issuer = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    rig.revokes_at_the_machine(issuer.1.device_id).await;
    rig.until_the_carrier_is_idle().await;
    let key = issuer.0.keys().authorisation.clone();
    let first = rig.request_of(&key, issuer.1.device_id, 0xe4, devices(target.1.device_id));
    rig.published_as(&key, &first).await;
    let second = rig.owner_publishes(0xe5, devices(issuer.1.device_id)).await;
    if complete {
        // The registry stands at the revision the machine's revocation gave it, which is the one
        // the feed holds, so the host is not behind it.
        rig.an_earlier_run_carried_out(&second, 0, 1).await;
    }
    RevokedIssuer {
        rig,
        issuer,
        target,
        first,
    }
}

/// KR-REQ-24.15: the request of a device the owner at the machine revoked is refused after a restart
/// as it is without one, when a live owner's request naming the device follows it in the feed, is
/// not complete, and withdraws nothing, because the device is revoked already. The feed sets the order of its records
/// and a signature does not cover it, so the place a record holds gives a revoked device no
/// standing; a restart that lost the reason it was revoked must not give it one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_request_of_a_device_revoked_at_the_machine_is_refused_after_a_restart() {
    let RevokedIssuer {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_of_a_device_revoked_at_the_machine_ahead_of_a_live_owners_withdrawal(false).await;
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;

    let key = issuer.0.keys().authorisation.clone();
    assert_eq!(
        rig.held_as(&key, &first).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "a revoked device's request is refused wherever the feed puts it"
    );
    assert!(
        !rig.has_revoked(target.1.device_id).await,
        "and what it named is not withdrawn"
    );
}

/// KR-REQ-24.15: the request of a device the owner at the machine revoked is refused when a live
/// owner's complete record that names the device follows it in the feed, as it is without one: the
/// record the host carries out again names a device that is revoked already, and a run that starts
/// with both records in the feed holds nothing in the record's place against the device's standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_request_of_a_device_revoked_at_the_machine_is_refused_ahead_of_a_complete_record_that_names_it()
 {
    let RevokedIssuer {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_of_a_device_revoked_at_the_machine_ahead_of_a_live_owners_withdrawal(true).await;
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;

    let key = issuer.0.keys().authorisation.clone();
    assert_eq!(
        rig.held_as(&key, &first).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "a revoked device's request is refused wherever the feed puts it"
    );
    assert!(
        !rig.has_revoked(target.1.device_id).await,
        "and what it named is not withdrawn"
    );
}

impl Rig {
    /// The owner at the machine revokes a device.
    async fn revokes_at_the_machine(&self, device_id: DeviceId) {
        let mut local = self.host.client().await;
        let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
            self.host.environment_id,
            &mut local,
            Method::DeviceRevoke,
            &kr_protocol::sharing::DeviceRevokeParams { device_id },
        )
        .await
        .expect("the owner at the machine revokes the device");
    }

    /// Whether the host has revoked a device.
    async fn has_revoked(&self, device_id: DeviceId) -> bool {
        let mut local = self.host.client().await;
        let list: DeviceListResult = net_support::pairing::read(
            &mut local,
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        )
        .await
        .expect("the device list");
        list.devices
            .iter()
            .find(|device| device.device_id == device_id)
            .expect("the device is paired")
            .revoked
    }
}

/// A request from an owner whose standing the host cannot decide, because the owner's grant expires
/// and the clock is not proven, with a withdrawal the feed shows complete behind it, and `fillers`
/// requests from strangers between them. The host is not behind its feed.
struct Undecidable {
    rig: Rig,
    /// The owner whose request cannot be judged.
    issuer: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The device that request names.
    target: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// The request that cannot be judged.
    first: RevocationRequest,
    /// The requests of strangers behind it, which are not complete, with the keys that published
    /// them.
    fillers: Vec<(AuthorisationKeyPair, RevocationRequest)>,
    /// A device a withdrawal names, other than the issuer and its target.
    named: (Device, kr_controller::service::net::devices::DeviceRecord),
    /// A second owner, who holds the right to manage the host and is listed to the feed.
    other_owner: (Device, kr_controller::service::net::devices::DeviceRecord),
}

/// What the feed holds behind a request whose issuer cannot be judged, in the order it is
/// published.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Then {
    /// A request of the second owner, which is not complete and names the device `named`.
    AWaitingRequestOfTheOtherOwner,
    /// A withdrawal, shown complete, by an owner the host does not know, of `named`.
    AnUnknownOwnersWithdrawal,
    /// A withdrawal, shown complete, by an owner the host does not know, of the issuer.
    AnUnknownOwnersWithdrawalOfTheIssuer,
    /// A withdrawal, shown complete, by the host's first owner, of the issuer.
    TheOwnersWithdrawalOfTheIssuer,
    /// A withdrawal, shown complete, by the host's first owner, of the second owner.
    TheOwnersWithdrawalOfTheOtherOwner,
}

/// Pairs an owner whose grant expires, a device its request will name, a device other withdrawals
/// name and a second owner, publishes the request, `fillers` requests of strangers and then the
/// records `then` in order, and makes the feed hold each withdrawal among them as an earlier run of
/// the host would have left it. The clock is unproven when the host reads the feed.
async fn a_request_whose_issuer_the_host_cannot_decide(
    then: &[Then],
    fillers: usize,
) -> Undecidable {
    let rig = Rig::start().await;
    let rights = [ActionRight::HostManage, ActionRight::SessionView];
    let issuer = rig.pairs(&rights).await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    let named = rig.pairs(&[ActionRight::SessionView]).await;
    let other_owner = rig.pairs(&rights).await;
    let withdrawals = then
        .iter()
        .filter(|record| **record != Then::AWaitingRequestOfTheOtherOwner)
        .count();
    let mut spares = Vec::new();
    for _ in 0..withdrawals {
        spares.push(rig.pairs(&[ActionRight::SessionView]).await);
    }
    // The registry reaches the revision the feed will hold, so the host is not behind it and
    // judges. The revocations are made while the clock is trusted, which a revocation after the
    // loss of its continuity would not leave settled.
    for spare in &spares {
        rig.revokes_at_the_machine(spare.1.device_id).await;
    }
    // Every pass the pairings and the revocations woke has ended, so none reads the feed before the
    // case has made it.
    rig.until_the_carrier_is_idle().await;
    rig.host.controller().utc_floor().lose_continuity();

    let issuer_key = issuer.0.keys().authorisation.clone();
    let first = rig.request_of(
        &issuer_key,
        issuer.1.device_id,
        0xf1,
        devices(target.1.device_id),
    );
    rig.published_as(&issuer_key, &first).await;
    // The feed keeps a publisher to 32 of what the host has not finished with.
    let strangers: Vec<_> = (0..3)
        .map(|_| AuthorisationKeyPair::generate().expect("a key"))
        .collect();
    let mut published = Vec::new();
    for position in 0..fillers {
        let key = &strangers[position % strangers.len()];
        let id = 0x20 + u8::try_from(position).expect("few fillers");
        let stranger = DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16]));
        let request = rig.request_of(key, stranger, id, devices(named.1.device_id));
        rig.published_as(key, &request).await;
        published.push((key.clone(), request));
    }
    let owner_key = rig.owner.authorisation.clone();
    let other_key = other_owner.0.keys().authorisation.clone();
    let mut completed = 0;
    for (position, record) in then.iter().enumerate() {
        let id = 0xf2 + u8::try_from(position).expect("few records");
        let (key, by, naming) = match record {
            Then::AWaitingRequestOfTheOtherOwner => (
                other_key.clone(),
                other_owner.1.device_id,
                named.1.device_id,
            ),
            Then::AnUnknownOwnersWithdrawal => (
                AuthorisationKeyPair::generate().expect("a key"),
                DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
                named.1.device_id,
            ),
            Then::AnUnknownOwnersWithdrawalOfTheIssuer => (
                AuthorisationKeyPair::generate().expect("a key"),
                DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
                issuer.1.device_id,
            ),
            Then::TheOwnersWithdrawalOfTheIssuer => {
                (owner_key.clone(), rig.owner_device(), issuer.1.device_id)
            }
            Then::TheOwnersWithdrawalOfTheOtherOwner => (
                owner_key.clone(),
                rig.owner_device(),
                other_owner.1.device_id,
            ),
        };
        let request = rig.request_of(&key, by, id, devices(naming));
        rig.published_as(&key, &request).await;
        if *record != Then::AWaitingRequestOfTheOtherOwner {
            rig.an_earlier_run_carried_out(&request, completed, completed + 1)
                .await;
            completed += 1;
        }
    }
    if fillers > 0 {
        // The feed holds a page of 64, and the request is first on it.
        rig.runtime().read_at_most_pages(1);
    }
    rig.until_the_carrier_is_idle().await;
    Undecidable {
        rig,
        issuer,
        target,
        first,
        fillers: published,
        named,
        other_owner,
    }
}

/// KR-REQ-24.15: a request whose issuer's standing the host cannot decide does not stop the scan
/// before a withdrawal behind it that the host cannot verify. The scan carries out again what the
/// feed shows complete, which asks no clock, so the refusal rises; the request waits, and the
/// scan that follows the clock being proven carries it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_host_cannot_decide_does_not_stop_the_scan_before_a_withdrawal_it_cannot_verify()
 {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(&[Then::AnUnknownOwnersWithdrawal], 0).await;

    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the withdrawal behind the request is found: {}",
        check.detail()
    );
    assert!(
        check.detail().contains("could not finish reading"),
        "and the pass says it could not finish: {}",
        check.detail()
    );
    let key = issuer.0.keys().authorisation.clone();
    let waiting = rig.held_as(&key, &first).await;
    assert_eq!(
        (waiting.rejected.0, waiting.acknowledgement.0),
        (None, None),
        "the request is neither refused nor carried out while the clock is unproven"
    );
    assert!(!rig.has_revoked(target.1.device_id).await);

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    let carried_out = rig.held_as(&key, &first).await;
    assert_eq!(
        carried_out
            .acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the scan after the clock is proven judges the request at its place: {carried_out:?}"
    );
    assert!(rig.has_revoked(target.1.device_id).await);
    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the withdrawal the host cannot verify still refuses remote access: {}",
        check.detail()
    );
}

/// KR-REQ-24.15: a withdrawal of the issuer of a waiting request by an owner the host does not know
/// raises the refusal while the clock is unproven. The scan holds a complete record that the host
/// would carry out and that would revoke the waiting issuer, so that the request is judged first;
/// this record is no such record, because the host cannot show who made it, so it is neither held
/// nor carried out. It is found, and the host refuses remote access for it as it does for any
/// withdrawal it cannot verify. Held, it would raise nothing, and the host would withhold nothing
/// for a withdrawal the feed shows complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_owners_withdrawal_of_the_issuer_of_a_waiting_request_raises_the_refusal() {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(
        &[Then::AnUnknownOwnersWithdrawalOfTheIssuer],
        0,
    )
    .await;

    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the withdrawal behind the request is found while the clock is unproven: {}",
        check.detail()
    );
    // The withdrawal names the device that made the request, which waits for the clock: the doctor
    // names it, says that revoking it refuses the request, and says what ends a lost continuity.
    assert!(
        check.detail().contains(&format!(
            "device {} made a request that waits for this host's clock",
            issuer.1.device_id
        )),
        "the doctor names the device whose request waits for the clock: {}",
        check.detail()
    );
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("reboot")),
        "and says that a reboot ends a lost continuity: {:?}",
        check.remedy()
    );
    let waiting = rig.held_as(&issuer.0.keys().authorisation, &first).await;
    assert_eq!(
        (waiting.rejected.0, waiting.acknowledgement.0),
        (None, None),
        "the request is neither refused nor carried out while the clock is unproven"
    );
    assert!(!rig.has_revoked(target.1.device_id).await);
}

/// KR-REQ-24.15: a limit. A request waits for the clock, and a withdrawal the host cannot verify
/// names its issuer. The owner at the machine revokes the issuer, as the doctor says to for what a
/// withdrawal names, and the request is refused: the registry holds its issuer revoked, so what the
/// request named is not withdrawn, and the doctor said so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_the_issuer_of_a_waiting_request_that_a_withdrawal_names_refuses_the_request() {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(
        &[Then::AnUnknownOwnersWithdrawalOfTheIssuer],
        0,
    )
    .await;

    rig.revokes_at_the_machine(issuer.1.device_id).await;
    rig.poll().await;
    let held = rig.held_as(&issuer.0.keys().authorisation, &first).await;
    assert_eq!(
        held.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "the issuer is revoked, so its request is refused: {held:?}"
    );
    assert!(!rig.has_revoked(target.1.device_id).await);
}

/// KR-REQ-24.15: the request that waits for the clock keeps its place across the pages of a scan:
/// the requests of strangers behind it, on its page and on the next, are not judged before it, and
/// the withdrawal on the next page is still found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_host_cannot_decide_holds_the_requests_behind_it_across_the_pages_of_a_scan()
{
    let Undecidable {
        rig,
        issuer,
        first,
        fillers,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(&[Then::AnUnknownOwnersWithdrawal], 70).await;

    let check = rig.shown().await.check.expect("the feed check");
    assert!(
        check.detail().contains("an owner this host does not know"),
        "the withdrawal on the second page is found: {}",
        check.detail()
    );
    for (key, request) in [fillers.first(), fillers.last()].into_iter().flatten() {
        assert_eq!(
            rig.held_as(key, request).await.rejected.0,
            None,
            "a request behind the one that cannot be judged is not judged before it"
        );
    }

    rig.host.controller().utc_floor().establish_continuity();
    rig.poll().await;
    let key = issuer.0.keys().authorisation.clone();
    assert_eq!(
        rig.held_as(&key, &first)
            .await
            .acknowledgement
            .0
            .as_ref()
            .map(|acknowledged| acknowledged.completion),
        Some(RevocationCompletion::Complete),
        "the request is carried out once the clock is proven"
    );
    let (key, request) = fillers.last().expect("fillers");
    assert_eq!(
        rig.held_as(key, request).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "and the requests behind it are judged then, in order"
    );
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
        within("the pass to reach the point", async {
            tokio::select! {
                () = &mut polled => panic!("the pass stopped where it was held"),
                reached = arrived => reached.expect("the pass reached the point"),
            }
        })
        .await;
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
    wait_for_the_passes(&host);
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
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.poll().await;
    // The bound is short only from here: the passes the setup asked for have ended, so what ends at
    // the bound is the connection's wait for the pass that the held read keeps open.
    rig.runtime()
        .wait_for_a_synchronisation_at_most(Duration::from_millis(100));

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
    rig.until_the_carrier_is_idle().await;
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
    rig.until_the_carrier_is_idle().await;

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
        within("the pass to reach the point", async {
            tokio::select! {
                () = &mut polled => panic!("the pass stopped where it was held"),
                reached = arrived => reached.expect("the pass reached the point"),
            }
        })
        .await;
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
    rig.until_the_carrier_is_idle().await;

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
        within("the pass to reach the point", async {
            tokio::select! {
                () = &mut polled => panic!("the pass stopped where it was held"),
                reached = arrived => reached.expect("the pass reached the point"),
            }
        })
        .await;
        // The note is written. The refusal it is about to write is not.
        registry
            .execute_batch(
                "CREATE TRIGGER refuse_refusal BEFORE INSERT ON host_authority
                 WHEN NEW.key = 'feed'
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            )
            .expect("the fault is in place");
        go.send(()).expect("the pass goes on");
        within("the pass to end", polled).await;
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
    within("the pass to end", polled).await;
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

// What a restored policy's wait owes: the devices and shares the requests the feed holds name that
// the host has not carried out or set aside on what a restore cannot change.

type Paired = (Device, kr_controller::service::net::devices::DeviceRecord);

/// Writes a record of a restore that names no row the host holds, so that the next start waits for
/// the person at the machine, level with a feed that holds nothing the registry lacks.
fn a_restore_was_found(tree: &kr_ipc::testing::TempHost) {
    restored::write(
        &restored::file_beside(&tree.environment().registry_database()),
        &restored::Record::of(
            kr_protocol::scalars::Digest256::from_bytes([1; 32]),
            TimestampMs::new(1),
        ),
    )
    .expect("a record");
}

/// A host whose feed holds a request by a key the host does not know that names `target`, and then
/// `fillers` requests of other keys that name nothing the host holds. The host has not read them.
struct Stranger {
    rig: Rig,
    /// The device the request names.
    target: Paired,
    /// A device nothing names.
    kept: Paired,
    /// The key that signed the request.
    key: AuthorisationKeyPair,
    /// The request.
    request: RevocationRequest,
}

async fn a_request_by_a_key_the_host_does_not_know(fillers: usize) -> Stranger {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let request = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        devices(target.1.device_id),
    );
    rig.published_as(&key, &request).await;
    // The feed keeps a publisher to 32 of what the host has not finished with.
    let strangers: Vec<_> = (0..3)
        .map(|_| AuthorisationKeyPair::generate().expect("a key"))
        .collect();
    for position in 0..fillers {
        let id = u8::try_from(position + 1).expect("few fillers");
        let nothing = DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16]));
        let key = &strangers[position / 32];
        let filler = rig.request_of(key, nothing, id, devices(nothing));
        rig.published_as(key, &filler).await;
    }
    Stranger {
        rig,
        target,
        kept,
        key,
        request,
    }
}

/// KR-REQ-24.15: the host writes what a page of the feed names to the record of the restore before
/// it acts on any record of the page, so that a daemon that stops part way through a scan, and
/// starts again with no feed to read, still owes the device the first page named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_is_written_before_the_host_acts_on_it() {
    let Stranger { rig, target, .. } = a_request_by_a_key_the_host_does_not_know(70).await;
    // The first page holds 64 records, and the host reads the second after it has dealt with them;
    // the feed holds that read open.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, Moment::Hold);
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_arrivals("read", reads + 2).await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(target.1.device_id)),
        "the device the first page names is in the record before the scan has read the second"
    );

    // The daemon stops there, and the next start reads no feed.
    rig.runtime().crash();
    rig.served.web().release_held();
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "and a host that reads no feed still owes it: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a feed that answers that it removed the host part way through a scan does not end
/// what the scan met on the pages before: the confirmation is refused for it, and a start after the
/// removal is recorded still refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_removes_the_host_part_way_through_a_scan_does_not_end_what_the_scan_met() {
    let Stranger { rig, target, .. } = a_request_by_a_key_the_host_does_not_know(70).await;
    let reads = rig.arrivals("read");
    // The feed holds the second page's read before it acts on it, and the owner removes the feed
    // meanwhile: the read is answered with the removal.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, Moment::Gate);
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_arrivals("read", reads + 2).await;
    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    rig.served.web().release_held();
    within("a pass finds the feed removed the host", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(rig.shown().await.removal_item.is_some());
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the removal does not end what the scan met: {refused:?}"
    );

    // A start after the removal is recorded still refuses it: the list is on disk.
    let rig = rig.restarted(false, |_| {}).await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "and so does the start that follows: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a host that reads no feed owes what an earlier run of it learned from the feed,
/// which the record keeps: taking `authority.origin` out of the configuration does not end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_started_with_no_feed_still_owes_what_a_scan_found() {
    let Stranger {
        rig, target, kept, ..
    } = a_request_by_a_key_the_host_does_not_know(0).await;
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(target.1.device_id)),
        "the scan wrote what the request names"
    );
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "a host with no feed owes the device the request named: {refused:?}"
    );
    assert!(
        !refused.message.contains(&kept.1.device_id.to_string()),
        "and not one nothing named: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a request published before the run first read the feed, by a key the host does not
/// know, is held while the wait stands and owes what it names; the host sends the feed no refusal,
/// which a later restore would read as "never applied". One published after the run read the feed
/// is judged as today and refused, and holds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_published_before_the_runs_first_reading_is_held_and_owed() {
    let Stranger {
        rig,
        target,
        kept,
        key,
        request,
    } = a_request_by_a_key_the_host_does_not_know(0).await;
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        None,
        "the request is held and not refused"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "and the confirmation is refused for the device it names: {refused:?}"
    );

    // A request published after the run read the feed is refused, and names nothing the host owes.
    let later = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd2,
        devices(kept.1.device_id),
    );
    rig.published_as(&key, &later).await;
    rig.poll().await;
    assert_eq!(
        rig.held_as(&key, &later).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "a request published after the first reading is judged as today"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        !refused.message.contains(&kept.1.device_id.to_string()),
        "and holds the lift for nothing: {refused:?}"
    );

    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
    rig.poll().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "the first scan after the wait refuses what it held"
    );
}

/// KR-REQ-24.15: a stranger's request published after the run first read the feed does not hold the
/// lift, whether or not the refusal reaches the feed: it names what it names, and nothing is owed
/// for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_request_published_after_the_runs_first_reading_does_not_hold_the_lift() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let by = DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16]));
    let request = rig.request_of(&key, by, 0xd3, devices(target.1.device_id));
    rig.published_as(&key, &request).await;
    // The refusal does not reach the feed, and the feed then removes the host.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "reject", 1, TURNED_BACK);
    rig.poll().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        None,
        "the feed turned the refusal back"
    );
    rig.the_feed_removes_the_host().await;
    assert!(
        rig.the_owner_confirms().await.lifted,
        "what a request published after the first reading names is not owed"
    );
}

impl Rig {
    /// The feed's client as the host, which signs with the host's own key.
    fn as_the_host(&self) -> AuthorityFeedClient {
        let gateway = GatewayOrigin::new(self.served.origin()).expect("an origin");
        let http: Arc<dyn ServiceHttp> = Arc::new(
            HttpService::with(
                gateway.clone(),
                HttpDeadlines::default(),
                managed_response_limits(),
            )
            .expect("a transport"),
        );
        AuthorityFeedClient::new(
            gateway,
            http,
            Arc::new(HostAtTheFeed(self.host_keys.authorisation.clone())),
        )
    }
}

/// A host whose registry was put back to before an owner was paired, with a request of that owner
/// that an earlier run of the host carried out and acknowledged as Pending.
struct PendingRequest {
    rig: Rig,
    /// The device the request names.
    target: Paired,
    /// A device nothing names.
    kept: Paired,
    /// The key that signed it, which the restored registry does not hold.
    key: AuthorisationKeyPair,
    /// The request.
    request: RevocationRequest,
}

async fn a_pending_request_of_an_owner_the_restored_registry_lacks() -> PendingRequest {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    let kept = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = owner.0.keys().authorisation.clone();
    let request = rig.request_of(&key, owner.1.device_id, 0xa1, devices(target.1.device_id));
    rig.published_as(&key, &request).await;
    // An earlier run carried it out under revision 1 with a worker still to confirm, so the feed
    // shows it pending, and the registry put back never saw it.
    rig.an_earlier_run_acknowledged(
        &request,
        0,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(1),
        },
    )
    .await;
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    PendingRequest {
        rig,
        target,
        kept,
        key,
        request,
    }
}

/// KR-REQ-24.15: a request the feed shows this host acknowledged as Pending, whose issuer was paired
/// after the copy the registry was put back to, cannot be judged against the registry as restored:
/// the issuer is not in it. The host does not refuse it, which the feed would keep for a week and a
/// later restore would read as "never applied"; it owes the device the request names, writes it to
/// the record, and the confirmation is refused for it until the person has revoked it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acknowledged_pending_request_from_an_issuer_the_restored_registry_lacks_owes_its_target()
 {
    let PendingRequest {
        rig,
        target,
        kept,
        key,
        request,
    } = a_pending_request_of_an_owner_the_restored_registry_lacks().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        None,
        "the request is not refused"
    );
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(target.1.device_id)),
        "the device it names is written to the record of the restore"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the confirmation is refused for it: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    rig.until_the_carrier_is_idle().await;
    assert!(rig.the_owner_confirms().await.lifted);
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device nothing names is served");
}

/// KR-REQ-24.15: a withdrawal the host cannot verify keeps the device it names owed, across a
/// confirmation that is refused and a start with the feed down: the person revokes it, and then the
/// confirmation lifts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_the_host_cannot_verify_keeps_its_device_owed_across_a_confirmation_and_a_restart()
 {
    let Unverifiable {
        rig, victim, share, ..
    } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::SessionView],
        &[],
        true,
        true,
    )
    .await;
    let refused = rig.the_confirmation_is_refused().await;
    for named in [
        format!("device {}", victim.1.device_id),
        format!("share {}", share.grant_id),
    ] {
        assert!(
            refused.message.contains(&named),
            "{named} is not named in: {refused:?}"
        );
    }
    let listed = rig.what_the_record_lists();
    assert!(listed.contains(&restored::Target::Device(victim.1.device_id)));
    assert!(listed.contains(&restored::Target::Grant(share.grant_id)));

    // A start with the feed down reads the list from the record.
    let rig = rig.restarted(true, |_| {}).await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "a host that cannot read its feed still owes the device the feed named: {refused:?}"
    );
    rig.revokes_at_the_machine(victim.1.device_id).await;
    rig.revokes_a_share_at_the_machine(share.grant_id).await;
    within("a scan reads the feed through", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: revoking the issuer of a request the host cannot judge refuses nothing at the feed
/// and ends nothing: the request is held, its target stays owed, and only revoking the target lifts
/// the confirmation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_the_requester_of_a_request_the_host_cannot_judge_does_not_end_the_wait() {
    let Undecidable {
        rig,
        issuer,
        target,
        first,
        ..
    } = a_request_whose_issuer_the_host_cannot_decide(&[], 0).await;
    let rig = rig
        .restarted(false, |tree| {
            a_restore_was_found(tree);
            let _ = std::fs::remove_file(tree.environment().utc_floor_file());
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = issuer.0.keys().authorisation.clone();
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the request waits for the clock, and what it names is owed: {refused:?}"
    );

    // The remedy that was offered: revoke the requester.
    rig.revokes_at_the_machine(issuer.1.device_id).await;
    rig.poll().await;
    assert_eq!(
        rig.held_as(&key, &first).await.rejected.0,
        None,
        "the request of a revoked issuer is held, and not refused"
    );
    assert!(!rig.has_revoked(target.1.device_id).await);
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "and still owes what it names: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a scan clears an entry it wrote when it settles, on evidence, every request that
/// named it, so a device a forged request named does not stay owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_clears_the_entries_of_the_records_it_settled() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    // Signed by a key the registry's device of that identity does not hold: no request that device
    // made, whatever a restore changed.
    let key = AuthorisationKeyPair::generate().expect("a key");
    let request = rig.request_of(&key, rig.owner_device(), 0xd5, devices(target.1.device_id));
    rig.published_as(&key, &request).await;
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "the forgery is refused on what a restore cannot change"
    );
    assert!(
        rig.what_the_record_lists().is_empty(),
        "and the entry the scan wrote for it is cleared"
    );
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a request the feed dropped after its retention keeps its target owed when another
/// request that names the same target is settled: an entry leaves the list only when every request
/// this run met that named it is settled, and an entry an earlier run wrote only when its target is
/// no longer live. Otherwise a stranger could publish a request naming a device the person must
/// revoke, have the host refuse it, and wait for the feed to drop the request that owed the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_feed_dropped_keeps_its_target_owed_when_another_that_names_it_is_settled() {
    let rig = Rig::start().await;
    let victim = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = owner.0.keys().authorisation.clone();
    let withdrawal = rig.request_of(&key, owner.1.device_id, 0xc1, devices(victim.1.device_id));
    rig.published_as(&key, &withdrawal).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &withdrawal)
        .await;
    // A request that names the same device under the identity of an owner the host holds, signed by
    // another key: the host refuses it on what the issuer's own record fixes.
    let forger = AuthorisationKeyPair::generate().expect("a key");
    let forged = rig.request_of(
        &forger,
        rig.owner_device(),
        0xc3,
        devices(victim.1.device_id),
    );
    rig.published_as(&forger, &forged).await;
    rig.poll().await;
    assert_eq!(
        rig.held_as(&forger, &forged).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority)
    );

    // The registry goes back to before the owner was paired: the withdrawal is a request of an
    // owner the host does not know, and owes the device it names.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(victim.1.device_id)),
        "the withdrawal owes the device"
    );

    // The retention of the withdrawal ends and the forged request stays: a scan that meets only the
    // forgery settles it, and does not clear what the withdrawal owed.
    rig.served.web().the_feeds_drop(withdrawal.request_id);
    rig.poll().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "the device stays owed: {refused:?}"
    );

    // A start after that keeps it too: nothing in the record says which request wrote the entry.
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "and so does a later run: {refused:?}"
    );
    rig.revokes_at_the_machine(victim.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: an entry whose target the person revoked stays on the list while the wait stands,
/// because a registry put back again brings the target back: when the feed has dropped the request
/// that owed it by then, the list is all that is left to say the host owes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_restore_brings_back_a_revoked_target_that_the_list_still_owes() {
    let rig = Rig::start().await;
    let victim = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = owner.0.keys().authorisation.clone();
    let withdrawal = rig.request_of(&key, owner.1.device_id, 0xc1, devices(victim.1.device_id));
    rig.published_as(&key, &withdrawal).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &withdrawal)
        .await;

    // The first restore: the owner is unknown to the registry, and the device is owed.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let target = restored::Target::Device(victim.1.device_id);
    assert!(rig.what_the_record_lists().contains(&target));

    // The person revokes it as the refusal says, and the feed's retention ends the request.
    rig.revokes_at_the_machine(victim.1.device_id).await;
    rig.served.web().the_feeds_drop(withdrawal.request_id);
    rig.poll().await;
    assert!(
        rig.what_the_record_lists().contains(&target),
        "an entry whose target is not live stays on the list while the wait stands"
    );

    // The registry is put back again before the person confirmed.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "the device the second restore brought back is owed: {refused:?}"
    );
    rig.revokes_at_the_machine(victim.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a request the host carried out again after the restore does not take its target
/// off the list either: the device is revoked now, but a registry put back again brings it back,
/// and by then the feed may have dropped the request that revoked it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_host_revoked_after_a_restore_stays_owed_when_the_registry_is_put_back_again()
{
    let Restorable {
        rig,
        revoked,
        earlier,
        ..
    } = a_revocation_the_registry_will_lose().await;
    // The request `a_revocation_the_registry_will_lose` published, by its identifier.
    let request_id = RevocationRequestId::new(kr_protocol::scalars::Uuid::from_bytes([0xb1; 16]));
    let target = restored::Target::Device(revoked.1.device_id);

    // The first restore: the host carries the request out again, so the device is revoked.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the host carried the request out again"
    );
    assert!(
        rig.what_the_record_lists().contains(&target),
        "and the device it revoked stays on the list while the wait stands"
    );

    // The feed's retention ends the request, and the registry is put back again.
    rig.served.web().the_feeds_drop(request_id);
    rig.poll().await;
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&revoked.1.device_id.to_string()),
        "the device the second restore brought back is owed: {refused:?}"
    );
    rig.revokes_at_the_machine(revoked.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// A device the feed revoked and one it revoked after, both paired and live in the copy taken
/// first, and the registry as it was after the first revocation in a second copy.
struct TwoRevocations {
    rig: Rig,
    first_revoked: (Device, kr_controller::service::net::devices::DeviceRecord),
    second_revoked: (Device, kr_controller::service::net::devices::DeviceRecord),
    first_request: RevocationRequest,
    second_request: RevocationRequest,
}

/// Two devices paired, the owner's feed revoking the first and then the second, each carried out
/// and acknowledged as complete. `between` runs after the first revocation, with the rig and the
/// two devices, and `before` after both devices are paired and before any revocation.
async fn two_revocations_the_registry_will_lose<B, T>(before: B, between: T) -> TwoRevocations
where
    B: FnOnce(&Rig),
    T: FnOnce(&Rig),
{
    let rig = Rig::start().await;
    let first_revoked = rig.pairs(&[ActionRight::SessionView]).await;
    let second_revoked = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    before(&rig);
    let first_request = rig
        .owner_publishes(0xe1, devices(first_revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&first_request)
        .await;
    between(&rig);
    let second_request = rig
        .owner_publishes(0xe2, devices(second_revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&second_request)
        .await;
    TwoRevocations {
        rig,
        first_revoked,
        second_revoked,
        first_request,
        second_request,
    }
}

impl Rig {
    /// The feed's retention ends both requests, and the registry is put back to `copy`: a second
    /// restore in the same wait, after the requests that owed the first revoked device are gone.
    async fn restored_again_after_the_feed_dropped(
        self,
        requests: [&RevocationRequest; 2],
        copy: &std::path::Path,
    ) -> Self {
        for request in requests {
            self.served.web().the_feeds_drop(request.request_id);
        }
        self.poll().await;
        let rig = self
            .restarted(false, |tree| put_the_registry_back(tree, copy))
            .await;
        rig.until_the_carrier_is_idle().await;
        rig.until_the_carrier_is_idle().await;
        rig
    }

    /// The wait still owes `device`: the confirmation is refused and names it, and revoking what
    /// is owed at the machine ends the wait.
    async fn the_wait_owes_and_the_person_revokes(&self, device: DeviceId, others: &[DeviceId]) {
        let refused = self.the_confirmation_is_refused().await;
        assert!(
            refused.message.contains(&device.to_string()),
            "the device the second restore brought back is owed: {refused:?}"
        );
        self.revokes_at_the_machine(device).await;
        for other in others {
            if !self.has_revoked(*other).await {
                self.revokes_at_the_machine(*other).await;
            }
        }
        assert!(self.the_owner_confirms().await.lifted);
    }
}

/// KR-REQ-24.15: a device the registry of the first copy no longer holds live when the scan writes
/// the request that names it is owed all the same: the feed drops the request, the registry is put
/// back to a copy in which the device is live, and the list is all that says the host owes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_in_the_first_copy_is_owed_when_a_second_copy_holds_it_live() {
    let mut first = None;
    let mut second = None;
    let TwoRevocations {
        rig,
        first_revoked,
        second_revoked,
        first_request,
        second_request,
    } = two_revocations_the_registry_will_lose(
        |rig| first = Some(a_copy_of_the_registry(&rig.host, "registry-live.sqlite3")),
        |rig| {
            second = Some(a_copy_of_the_registry(
                &rig.host,
                "registry-revoked.sqlite3",
            ))
        },
    )
    .await;
    let (first, second) = (first.expect("a copy"), second.expect("a copy"));

    // The first restore is to the copy in which the first device is already revoked.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &second))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(first_revoked.1.device_id)),
        "the device the request names is owed although it is not live in the copy"
    );

    let rig = rig
        .restored_again_after_the_feed_dropped([&first_request, &second_request], &first)
        .await;
    rig.the_wait_owes_and_the_person_revokes(
        first_revoked.1.device_id,
        &[second_revoked.1.device_id],
    )
    .await;
}

/// KR-REQ-24.15: a device the first copy never held is owed when a request names it, and a second
/// copy in which it is live finds it owed after the feed dropped the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_first_copy_never_held_is_owed_when_a_second_copy_holds_it_live() {
    let rig = Rig::start().await;
    let second_revoked = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let without = a_copy_of_the_registry(&rig.host, "registry-without.sqlite3");
    let first_revoked = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let with = a_copy_of_the_registry(&rig.host, "registry-with.sqlite3");
    let first_request = rig
        .owner_publishes(0xe1, devices(first_revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&first_request)
        .await;
    let second_request = rig
        .owner_publishes(0xe2, devices(second_revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&second_request)
        .await;

    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &without))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(first_revoked.1.device_id)),
        "the device the registry does not hold is owed all the same"
    );

    let rig = rig
        .restored_again_after_the_feed_dropped([&first_request, &second_request], &with)
        .await;
    rig.the_wait_owes_and_the_person_revokes(
        first_revoked.1.device_id,
        &[second_revoked.1.device_id],
    )
    .await;
}

/// KR-REQ-24.15: a device the person revoked at the machine before the scan reached the page that
/// names it is owed all the same, and the same copy put back again finds it owed after the feed
/// dropped the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_person_revoked_before_the_scan_reached_its_page_is_owed_when_the_copy_is_put_back_again()
 {
    let mut copy = None;
    let TwoRevocations {
        rig,
        first_revoked,
        second_revoked,
        first_request,
        second_request,
    } = two_revocations_the_registry_will_lose(
        |rig| copy = Some(a_copy_of_the_registry(&rig.host, "registry-live.sqlite3")),
        |_| {},
    )
    .await;
    let copy = copy.expect("a copy");

    // The first read of the run is held while the person revokes the device at the machine.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &copy))
        .await;
    rig.until_arrivals("read", reads + 1).await;
    rig.revokes_at_the_machine(first_revoked.1.device_id).await;
    rig.served.web().release_held();
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(first_revoked.1.device_id)),
        "the device the person revoked is owed although it is not live when its page is written"
    );

    let rig = rig
        .restored_again_after_the_feed_dropped([&first_request, &second_request], &copy)
        .await;
    rig.the_wait_owes_and_the_person_revokes(
        first_revoked.1.device_id,
        &[second_revoked.1.device_id],
    )
    .await;
}

/// KR-REQ-24.15: a request is known by what it says and not by its place and identifier alone. A
/// feed restored to a state from before a request the host holds as undecided serves another
/// request at its place under its identifier; that request's settlement is not the first one's,
/// and the device the first one names stays owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_request_at_the_place_of_one_the_host_holds_does_not_settle_it() {
    let rig = Rig::start().await;
    let victim = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = owner.0.keys().authorisation.clone();
    let withdrawal = rig.request_of(&key, owner.1.device_id, 0xc1, devices(victim.1.device_id));
    rig.published_as(&key, &withdrawal).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &withdrawal)
        .await;

    // The restored registry lacks the owner: the withdrawal cannot be verified and owes the device.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let target = restored::Target::Device(victim.1.device_id);
    assert!(rig.what_the_record_lists().contains(&target));

    // The feed is restored to a state from before the withdrawal, and serves another request at
    // its place under its identifier: one the key of the owner it names did not sign.
    rig.served
        .web()
        .the_feeds_return_to_before(withdrawal.request_id);
    let forger = AuthorisationKeyPair::generate().expect("a key");
    let forged = rig.request_of(
        &forger,
        rig.owner_device(),
        0xc1,
        devices(victim.1.device_id),
    );
    rig.published_as(&forger, &forged).await;
    rig.poll().await;
    rig.poll().await;
    assert_eq!(
        rig.held_as(&forger, &forged).await.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "the other request is refused on what a restore cannot change"
    );
    assert!(
        rig.what_the_record_lists().contains(&target),
        "and the device the withdrawal named stays owed: nothing settled the withdrawal"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "{refused:?}"
    );
    rig.revokes_at_the_machine(victim.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a record of the restore that cannot be read is not written over by a finding
/// either: the registry is behind the feed, the host catches up, and the record stays what it was,
/// so the doctor still says that it cannot be read and the confirmation removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finding_does_not_write_over_a_record_that_cannot_be_read() {
    let Restorable {
        rig,
        revoked,
        earlier,
        ..
    } = a_revocation_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| {
            put_the_registry_back(tree, &earlier);
            std::fs::write(
                restored::file_beside(&tree.environment().registry_database()),
                b"junk",
            )
            .expect("junk");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the host caught up with its feed"
    );
    assert!(
        matches!(rig.the_record(), Found::Unreadable(_)),
        "and the record that cannot be read is still there"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check.detail().contains("cannot be read"),
        "and says it: {}",
        check.detail()
    );
    assert!(rig.the_owner_confirms().await.lifted);
    assert_eq!(rig.the_record(), Found::Missing);
}

/// KR-REQ-24.15: a completed request whose issuer the person revoked at the machine after the
/// restore, before the scan reached it, is not dismissed for that: the registry's revocation may be
/// the person's act and not the issuer's, so what the request names stays owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_issuer_of_a_complete_request_revoked_after_the_restore_does_not_dismiss_it() {
    let rig = Rig::start().await;
    let victim = rig.pairs(&[ActionRight::SessionView]).await;
    let other = rig.pairs(&[ActionRight::SessionView]).await;
    let issuer = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-with-the-issuer.sqlite3");
    let key = issuer.0.keys().authorisation.clone();
    // Two withdrawals, so that the feed is ahead of the registry by more than the person's own
    // revocation of the issuer will move it.
    let request = rig.request_of(&key, issuer.1.device_id, 0xa1, devices(victim.1.device_id));
    rig.published_as(&key, &request).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &request)
        .await;
    let second = rig.request_of(&key, issuer.1.device_id, 0xa2, devices(other.1.device_id));
    rig.published_as(&key, &second).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &second)
        .await;
    assert!(rig.has_revoked(victim.1.device_id).await);
    assert!(rig.has_revoked(other.1.device_id).await);

    // The registry is put back, and the feed holds the first read while the person revokes the
    // issuer, as a lost phone is revoked.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_arrivals("read", reads + 1).await;
    rig.revokes_at_the_machine(issuer.1.device_id).await;
    rig.served.web().release_held();
    rig.poll().await;
    rig.until_the_carrier_is_idle().await;

    for device in [victim.1.device_id, other.1.device_id] {
        assert!(
            !rig.has_revoked(device).await,
            "the requests of a revoked issuer are not carried out again"
        );
    }
    let refused = rig.the_confirmation_is_refused().await;
    for device in [victim.1.device_id, other.1.device_id] {
        assert!(
            refused.message.contains(&device.to_string()),
            "and what they name is owed: {refused:?}"
        );
    }
    rig.revokes_at_the_machine(victim.1.device_id).await;
    rig.revokes_at_the_machine(other.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a feed the person points the host at does not clear what an earlier feed owed: its
/// entries keep the origin that named them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_of_feed_does_not_clear_what_an_earlier_feed_owed() {
    let Stranger { rig, target, .. } = a_request_by_a_key_the_host_does_not_know(0).await;
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(target.1.device_id))
    );
    let rig = rig.pointed_at(serve().await).await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "a feed that holds nothing for the host does not clear what the first one owed: {refused:?}"
    );
}

/// KR-REQ-24.15: a pass that stops because the feed turned a page back keeps what the pages before
/// it named, and a feed that then removes the host does not end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_stops_on_an_error_keeps_what_it_met_when_the_feed_then_removes_the_host() {
    let Stranger { rig, target, .. } = a_request_by_a_key_the_host_does_not_know(70).await;
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, TURNED_BACK);
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_arrivals("read", reads + 2).await;
    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    rig.timer.release_held();
    within("a pass finds the feed removed the host", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the first page was read before the second was turned back: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
}

/// KR-REQ-24.15: a record of the restore that cannot be read is not written over: what the run owes
/// stays in memory, the confirmation names it, and revoking it lets the confirmation remove the
/// record that cannot be read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_record_does_not_empty_what_the_run_owes() {
    let Stranger { rig, target, .. } = a_request_by_a_key_the_host_does_not_know(0).await;
    let rig = rig
        .restarted(false, |tree| {
            std::fs::write(
                restored::file_beside(&tree.environment().registry_database()),
                b"junk",
            )
            .expect("junk");
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        matches!(rig.the_record(), Found::Unreadable(_)),
        "the record is not written over"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "what the run owes is in memory: {refused:?}"
    );
    rig.revokes_at_the_machine(target.1.device_id).await;
    assert!(rig.the_owner_confirms().await.lifted);
    assert_eq!(rig.the_record(), Found::Missing);
}

/// KR-REQ-24.15: a request the feed dropped after its retention leaves its entry where it was: an
/// entry leaves the list when it is cleared or no longer live, and never because no request names
/// it now.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_feed_dropped_after_its_retention_stays_owed() {
    let Unverifiable { rig, victim, .. } = a_withdrawal_by_an_owner_the_host_does_not_know(
        &[ActionRight::SessionView],
        &[],
        true,
        true,
    )
    .await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(victim.1.device_id))
    );
    rig.served.web().a_week_passes_in_the_feeds();
    rig.poll().await;
    rig.poll().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(victim.1.device_id)),
        "the list holds the entry the dropped request made"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&victim.1.device_id.to_string()),
        "and the confirmation is refused for it: {refused:?}"
    );
}

/// KR-REQ-24.15: a request the host carried out and could not acknowledge, a restore, the person's
/// revocation of what it names as the refusal says, and a second restore to the same copy: the host
/// sends the feed no refusal during the wait, so the feed never reads "rejected", and the second
/// finding owes the device again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_restore_in_one_wait_owes_the_target_again_and_no_refusal_reaches_the_feed() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-owner.sqlite3");
    let owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let key = owner.0.keys().authorisation.clone();
    let request = rig.request_of(&key, owner.1.device_id, 0xa1, devices(target.1.device_id));
    rig.published_as(&key, &request).await;
    // The host carries the request out, and the acknowledgement never arrives.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "acknowledge", 1, Moment::Before);
    rig.poll().await;
    assert!(rig.has_revoked(target.1.device_id).await);
    assert!(
        rig.held_as(&key, &request)
            .await
            .acknowledgement
            .0
            .is_none(),
        "the acknowledgement was lost"
    );

    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "the request names a device the restore brought back: {refused:?}"
    );
    // The person revokes it, as the refusal says.
    rig.revokes_at_the_machine(target.1.device_id).await;
    rig.poll().await;
    assert_eq!(
        rig.held_as(&key, &request).await.rejected.0,
        None,
        "the host sends no refusal while the wait stands"
    );

    // The registry is put back to the same copy again, before the person confirmed.
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&target.1.device_id.to_string()),
        "and the second finding owes the device again: {refused:?}"
    );
}

/// KR-REQ-24.15: a request the feed shows this host acknowledged and then refused is carried out
/// again: the refusal is no evidence that the host never applied it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_record_that_holds_the_hosts_acknowledgement_is_carried_out_again() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let request = rig.signed_by(&rig.owner.authorisation, 0xa1, devices(target.1.device_id));
    rig.published_as(&rig.owner.authorisation, &request).await;
    rig.an_earlier_run_acknowledged(
        &request,
        0,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(1),
        },
    )
    .await;
    rig.as_the_host()
        .reject(request.request_id, RejectionReason::Superseded)
        .await
        .expect("the host refuses the record it acknowledged");
    assert!(rig.held(&request).await.rejected.0.is_some());
    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.has_revoked(target.1.device_id).await,
        "the host carried it out again, whatever the feed shows besides"
    );
}

/// KR-REQ-24.15: an acknowledged-Pending request the host carries out again after a restore is
/// acknowledged complete under the revision the feed already holds for it, so the feed stops
/// holding one of its publisher's open records, and the host issues no revision of its own for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acknowledged_pending_request_carried_out_again_is_acknowledged_complete() {
    let rig = Rig::start().await;
    let target = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let request = rig.signed_by(&rig.owner.authorisation, 0xa1, devices(target.1.device_id));
    rig.published_as(&rig.owner.authorisation, &request).await;
    rig.an_earlier_run_acknowledged(
        &request,
        0,
        1,
        RevocationCompletion::Pending {
            pending_workers: U64::new(1),
        },
    )
    .await;
    assert_eq!(
        rig.held(&request)
            .await
            .acknowledgement
            .0
            .as_ref()
            .map(|held| held.completion),
        Some(RevocationCompletion::Pending {
            pending_workers: U64::new(1)
        })
    );
    let revisions = rig.arrivals("revise");

    let rig = rig.restarted(false, |_| {}).await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(rig.has_revoked(target.1.device_id).await);
    let held = rig.held(&request).await;
    let acknowledged = held.acknowledgement.0.as_ref().expect("acknowledged");
    assert_eq!(acknowledged.completion, RevocationCompletion::Complete);
    assert_eq!(
        acknowledged.authority_revision,
        AuthorityRevision::new(1),
        "under the revision the feed already held for it"
    );
    assert_eq!(
        rig.arrivals("revise"),
        revisions,
        "and the host issued no revision of its own"
    );
    let acknowledgements = rig.arrivals("acknowledge");
    rig.poll().await;
    assert_eq!(
        rig.arrivals("acknowledge"),
        acknowledgements,
        "a request the feed shows complete is not acknowledged again"
    );
}

impl Rig {
    /// The registry as an earlier state of it would be, while the daemon runs: the revision counter
    /// back at nothing and `device` not revoked.
    fn the_registry_loses_a_withdrawal(&self, device: DeviceId) {
        let registry =
            rusqlite::Connection::open(self.host.tree().environment().registry_database())
                .expect("the registry opens");
        registry
            .execute("UPDATE environment SET authority_revision = 0", [])
            .expect("the counter is put back");
        registry
            .execute(
                "UPDATE network_devices SET revoked_at_ms = NULL WHERE device_id = ?1",
                [device.get().as_bytes().to_vec()],
            )
            .expect("the device is not revoked");
    }

    /// Publishes `count` requests that name nothing the host holds, from the owner's key and two
    /// strangers', so that the feed holds more than a page of 64: it keeps a publisher to 32 of
    /// what the host has not finished with.
    async fn publishes_filler(&self, count: u8) {
        let strangers = [
            AuthorisationKeyPair::generate().expect("a key"),
            AuthorisationKeyPair::generate().expect("a key"),
        ];
        for id in 1..=count {
            let (key, client) = match id {
                1..=30 => (&self.owner.authorisation, &self.remote),
                31..=62 => (
                    &strangers[0],
                    &client_for(self.served.origin(), strangers[0].clone()),
                ),
                _ => (
                    &strangers[1],
                    &client_for(self.served.origin(), strangers[1].clone()),
                ),
            };
            let nothing = DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([id; 16]));
            client
                .publish(
                    self.feed(),
                    &self.signed_by(key, id, devices(nothing)),
                    None,
                )
                .await
                .expect("the feed stores the request");
        }
    }
}

/// KR-REQ-24.15: a registry put back again while the host runs is a second finding, and the scan
/// that follows starts at the first record: the request the first scan settled is carried out
/// again on a registry that has lost it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_finding_after_a_scan_restarts_it_at_the_first_record() {
    let Restorable {
        rig,
        revoked,
        earlier,
        ..
    } = a_revocation_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the first scan carries the request out again"
    );

    rig.the_registry_loses_a_withdrawal(revoked.1.device_id);
    assert!(!rig.has_revoked(revoked.1.device_id).await);
    rig.poll().await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the second finding starts the scan over, so what the first settled is carried out again"
    );
}

/// KR-REQ-24.15: a registry put back again between two passes of one scan restarts that scan: the
/// pass that finds it does not act on its page, and the next begins at the first record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_finding_between_two_passes_of_a_scan_restarts_it() {
    let Restorable { rig, revoked, .. } = a_revocation_the_registry_will_lose().await;
    rig.until_the_carrier_is_idle().await;
    rig.runtime().read_at_most_pages(1);
    rig.publishes_filler(65).await;

    // The registry is found behind the feed, and the feed holds the second read of the scan.
    rig.the_registry_loses_a_withdrawal(revoked.1.device_id);
    // The first read finds it and is not acted on, the second is the scan's first pass, and the
    // feed holds the third, which is the scan's second.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 3, Moment::Hold);
    rig.runtime().wake();
    rig.until_arrivals("read", reads + 3).await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the first pass of the scan carried the request on the first page out"
    );

    // The registry is put back again before the second pass has looked at its page.
    rig.the_registry_loses_a_withdrawal(revoked.1.device_id);
    rig.served.web().release_held();
    rig.poll().await;
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the second finding restarts the scan at the first record"
    );
}

/// KR-REQ-24.15: a second finding whose record cannot be written is still a finding: the pass that
/// could not write it stops with nothing carried out, and the pass that writes it starts at the
/// first record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_finding_whose_record_was_not_written_still_restarts_the_scan() {
    let Restorable {
        rig,
        revoked,
        earlier,
        ..
    } = a_revocation_the_registry_will_lose().await;
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    assert!(rig.has_revoked(revoked.1.device_id).await);
    assert!(rig.the_owner_confirms().await.lifted);
    assert_eq!(rig.the_record(), Found::Missing);

    // The registry loses the withdrawal again, and something that is not a file stands where the
    // record of the finding goes.
    let record = restored::file_beside(&rig.host.tree().environment().registry_database());
    std::fs::create_dir(&record).expect("an obstacle");
    rig.the_registry_loses_a_withdrawal(revoked.1.device_id);
    rig.poll().await;
    assert!(
        !rig.has_revoked(revoked.1.device_id).await,
        "nothing is carried out while the finding cannot be written down"
    );

    std::fs::remove_dir(&record).expect("the obstacle goes");
    rig.poll().await;
    assert!(matches!(rig.the_record(), Found::Record(_)));
    assert!(
        rig.has_revoked(revoked.1.device_id).await,
        "the pass that writes the finding carries out what the first scan had settled"
    );
}

/// KR-REQ-24.15: a catch-up that takes several passes goes on where it stopped: no pass of it
/// restarts the scan, and what the first page names is in the record when it has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catch_up_across_several_passes_goes_on_and_keeps_what_the_first_met() {
    let Restorable {
        rig, revoked, kept, ..
    } = a_revocation_the_registry_will_lose().await;
    rig.until_the_carrier_is_idle().await;
    rig.runtime().read_at_most_pages(1);
    // A request by a key the host does not know, naming the device nothing else names, on the first
    // page with the one the host carries out again; more than a page follows.
    let key = AuthorisationKeyPair::generate().expect("a key");
    let request = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        devices(kept.1.device_id),
    );
    rig.published_as(&key, &request).await;
    rig.publishes_filler(65).await;

    rig.the_registry_loses_a_withdrawal(revoked.1.device_id);
    let before = rig.served.web().arrived().len();
    rig.poll().await;
    // The first read finds the registry behind the feed and is not acted on; the scan then starts
    // at the first record, and its second pass goes on where the first stopped.
    let asked: Vec<Option<String>> = rig.served.web().arrived()[before..]
        .iter()
        .filter_map(|arrived| arrived.body.get("read"))
        .map(|read| {
            read.get("after_sequence")
                .and_then(|after| after.as_str())
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        asked.get(..3),
        Some(&[Some("1".to_owned()), None, Some("64".to_owned())][..]),
        "no pass of the catch-up starts the scan over: {asked:?}"
    );
    assert!(rig.has_revoked(revoked.1.device_id).await);
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(kept.1.device_id)),
        "what the first page names is in the record"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&kept.1.device_id.to_string()),
        "and the confirmation is refused for it: {refused:?}"
    );
}

/// KR-REQ-24.15: a list at its cap says it is full: the confirmation names what the host knows and
/// says that more may be owed, a start with no feed reads the list as full, and the confirmation is
/// accepted once every listed target is revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_at_the_cap_says_it_is_full() {
    let rig = Rig::start().await;
    let mut named = Vec::new();
    for _ in 0..4 {
        named.push(rig.pairs(&[ActionRight::SessionView]).await);
    }
    rig.until_the_carrier_is_idle().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let request = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        RevocationTarget::Devices {
            device_ids: named
                .iter()
                .map(|paired| paired.1.device_id)
                .collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&key, &request).await;

    // The cap is lowered once the run has started and before its first read is answered.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_arrivals("read", reads + 1).await;
    rig.host.controller().limit_the_owed_list_to(3).await;
    rig.served.web().release_held();
    rig.until_the_carrier_is_idle().await;

    let listed: Vec<DeviceId> = rig
        .what_the_record_lists()
        .into_iter()
        .filter_map(|target| match target {
            restored::Target::Device(device) => Some(device),
            restored::Target::Grant(_) => None,
        })
        .collect();
    assert_eq!(listed.len(), 3, "the list holds as many as the cap allows");
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains("is full"),
        "the refusal says that more may be owed than it names: {refused:?}"
    );
    for paired in &named {
        assert!(
            refused.message.contains(&paired.1.device_id.to_string()),
            "the run still names what it met: {refused:?}"
        );
    }

    // A start with no feed knows only the list, and reads it as full.
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    rig.host.controller().limit_the_owed_list_to(3).await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains("is full"),
        "a list at its cap reads as full after a start: {refused:?}"
    );
    // A host that reads no feed has nothing to make room for, so a revocation does not clear the
    // warning: the target the cap kept out may be live.
    rig.revokes_at_the_machine(listed[0]).await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains("is full"),
        "and still does when one listed target is revoked: {refused:?}"
    );
    for device in &listed[1..] {
        rig.revokes_at_the_machine(*device).await;
    }
    assert!(
        rig.the_owner_confirms().await.lifted,
        "the confirmation is accepted once every listed target is revoked"
    );
}

/// KR-REQ-24.15: an entry whose target the person has revoked counts neither toward the cap nor
/// toward keeping the scan open. The next pass puts the target the cap kept out in a revoked
/// entry's place, the scan counts as read through, the refusal names what is live and no longer
/// says that the list is full, and revoking what is owed ends the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_what_a_full_list_names_makes_room_for_what_the_cap_kept_out() {
    let rig = Rig::start().await;
    let mut named = Vec::new();
    for _ in 0..4 {
        named.push(rig.pairs(&[ActionRight::SessionView]).await);
    }
    rig.until_the_carrier_is_idle().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let request = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        RevocationTarget::Devices {
            device_ids: named
                .iter()
                .map(|paired| paired.1.device_id)
                .collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&key, &request).await;

    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_arrivals("read", reads + 1).await;
    rig.host.controller().limit_the_owed_list_to(3).await;
    rig.served.web().release_held();
    rig.until_the_carrier_is_idle().await;

    let listed: Vec<DeviceId> = rig
        .what_the_record_lists()
        .into_iter()
        .filter_map(|target| match target {
            restored::Target::Device(device) => Some(device),
            restored::Target::Grant(_) => None,
        })
        .collect();
    assert_eq!(listed.len(), 3, "the list holds as many as the cap allows");
    let left_out = named
        .iter()
        .map(|paired| paired.1.device_id)
        .find(|device| !listed.contains(device))
        .expect("the cap kept one device out");
    assert!(
        !rig.runtime().has_read_the_feed_through(),
        "a list the cap kept an entry out of is not the whole of what is owed"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(refused.message.contains("is full"), "{refused:?}");

    for device in &listed {
        rig.revokes_at_the_machine(*device).await;
    }
    within("a pass reads the feed through", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(left_out)),
        "the target the cap kept out took the place of a revoked entry"
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&left_out.to_string()),
        "the refusal names what is live: {refused:?}"
    );
    for device in &listed {
        assert!(
            !refused.message.contains(&device.to_string()),
            "and not what the person revoked: {refused:?}"
        );
    }
    assert!(
        !refused.message.contains("is full"),
        "revoked entries leave room, so the list is not full: {refused:?}"
    );

    rig.revokes_at_the_machine(left_out).await;
    assert!(
        rig.the_owner_confirms().await.lifted,
        "revoking what is owed ends the wait"
    );
}

/// KR-REQ-24.15: a feed that removes the host after the first write of the record failed, which
/// left the refusal for being behind up without the wait, ends that refusal and leaves the wait: the
/// person can confirm once the record can be written, and was never left refused for a catch-up
/// that no pass will end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_removes_the_host_after_the_first_record_write_failed_leaves_the_person_able_to_confirm()
 {
    let Restorable {
        rig, kept, earlier, ..
    } = a_revocation_the_registry_will_lose().await;
    // The feed holds the run's first read while something that is not a file is put where the
    // record goes, so that the finding the read leads to cannot be written down.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_arrivals("read", reads + 1).await;
    let record = restored::file_beside(&rig.host.tree().environment().registry_database());
    std::fs::create_dir(&record).expect("an obstacle");
    rig.served.web().release_held();
    rig.poll().await;
    let refused = rig
        .the_owner_tries_to_confirm()
        .await
        .expect_err("the host is still catching up");
    assert!(
        refused.message.contains("catching up"),
        "refused for the catch-up it cannot begin: {refused:?}"
    );
    assert!(
        refused.message.contains(&record.display().to_string()),
        "and the refusal gives the full path of the record that cannot be written: {refused:?}"
    );

    rig.remote
        .remove(rig.feed())
        .await
        .expect("a key the host named removes the feed");
    within("a pass finds the feed removed the host", async {
        while !rig.runtime().has_read_the_feed_through() {
            rig.poll().await;
        }
    })
    .await;
    assert!(
        is_refused_for_the_restored_policy(&rig.serves(&kept.0, &kept.1).await),
        "the refusal for being behind has ended and the wait for the restored policy stands"
    );

    std::fs::remove_dir(&record).expect("the obstacle goes");
    assert!(
        rig.the_owner_confirms().await.lifted,
        "a feed that removed the host is read no more, so no catch-up can end"
    );
    rig.serves(&kept.0, &kept.1)
        .await
        .expect("the device is served once the person has confirmed");
}

/// Two owner devices and a device that is no owner's, a request by a key the host does not know
/// that names all three, and a host that starts with a restore found: every live owner device is
/// owed. `file` is where the record of the restore is.
struct EveryOwnerOwed {
    rig: Rig,
    /// A second owner device, and a device that is no owner's: the others the request names.
    others: [Paired; 2],
    file: std::path::PathBuf,
}

async fn a_request_that_names_every_owner_device() -> EveryOwnerOwed {
    a_request_that_names_every_owner_device_and_a_record(a_restore_was_found).await
}

/// As [`a_request_that_names_every_owner_device`], with the record `record` puts at its place
/// when the host starts.
async fn a_request_that_names_every_owner_device_and_a_record(
    record: impl FnOnce(&kr_ipc::testing::TempHost),
) -> EveryOwnerOwed {
    let rig = Rig::start().await;
    let second = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let other = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let key = AuthorisationKeyPair::generate().expect("a key");
    let kept_id = rig.owner_device();
    let request = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        RevocationTarget::Devices {
            device_ids: [kept_id, second.1.device_id, other.1.device_id]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&key, &request).await;
    let rig = rig.restarted(false, record).await;
    rig.until_the_carrier_is_idle().await;
    let file = restored::file_beside(&rig.host.tree().environment().registry_database());
    EveryOwnerOwed {
        rig,
        others: [second, other],
        file,
    }
}

/// KR-REQ-24.15: when what the wait owes is every owner device, the refusal and the doctor say so
/// and give the steps that keep one: the person revokes the others, stops the daemon, removes the
/// record by hand and starts it again, and the owner device that was kept confirms the pairing of
/// a new one, which it could not while the wait stood.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn when_every_owner_device_is_owed_the_route_in_the_refusal_keeps_an_owner() {
    let EveryOwnerOwed {
        rig,
        others: [second, other],
        file,
    } = a_request_that_names_every_owner_device().await;
    let kept = rig.owner_device();

    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&file.display().to_string()),
        "the refusal gives the full path of the record to remove: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("restored-policy.cbor")
                && remedy.contains("last owner device")),
        "the doctor gives the steps that keep an owner: {:?}",
        check.remedy()
    );

    // Revoking the others leaves the kept owner owed, and the confirmation is refused for it.
    rig.revokes_at_the_machine(second.1.device_id).await;
    rig.revokes_at_the_machine(other.1.device_id).await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&kept.to_string()),
        "the kept owner is still owed: {refused:?}"
    );

    let rig = rig.the_wait_is_ended_by_hand().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        !rig.host.controller().restored_policy_waits(),
        "with the record gone the host waits for nothing"
    );
    assert!(rig.the_restored_policy_check().await.is_none());
    let new_owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.revokes_at_the_machine(kept).await;
    rig.serves(&new_owner.0, &new_owner.1)
        .await
        .expect("the new owner device is served once the kept one is gone");
}

/// KR-REQ-24.15: after a restart, before this run has compared its registry with its feed, the
/// doctor and the confirmation do not give the steps that remove the record: a host that starts
/// below its feed finds the restore again and writes a new record, whatever the retained one owes.
/// The steps come once this run's scan has read the feed through and the host has caught up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn before_this_run_has_compared_its_feed_the_route_that_keeps_an_owner_is_not_given() {
    let rig = Rig::start().await;
    let revoked = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-earlier.sqlite3");
    let request = rig
        .owner_publishes(0xb1, devices(revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    let kept = rig.owner_device();
    // A request by a key the host does not know that names the only owner device.
    let key = AuthorisationKeyPair::generate().expect("a key");
    let naming_the_owner = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        devices(kept),
    );
    rig.published_as(&key, &naming_the_owner).await;

    // A first run finds a restore and writes down that the only owner device is owed.
    let rig = rig.restarted(false, a_restore_was_found).await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        rig.what_the_record_lists()
            .contains(&restored::Target::Device(kept)),
        "the record owes the only owner device"
    );

    // The registry is put back below the feed and the next run's first read cannot complete.
    let reads = rig.arrivals("read");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 1, Moment::Hold);
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_arrivals("read", reads + 1).await;
    let file = restored::file_beside(&rig.host.tree().environment().registry_database());
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&kept.to_string())
            && !refused.message.contains(&file.display().to_string()),
        "the refusal names what is owed and gives no route before the first comparison: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| !remedy.contains("pair a new owner device")
                && remedy.contains("restored-policy.cbor")),
        "the doctor warns against removing the record and gives no steps: {:?}",
        check.remedy()
    );

    // The read completes, the host catches up, and the steps that keep an owner come.
    rig.served.web().release_held();
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&file.display().to_string()),
        "the refusal gives the route and the record's full path once the host has caught up: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("pair a new owner device")),
        "and the doctor gives the steps: {:?}",
        check.remedy()
    );
}

/// KR-REQ-24.15: a record that cannot be read, with every owner device owed from what the run met,
/// gets the remedy its detail promises: the doctor says the remedy gives the steps that keep an
/// owner device only when the remedy does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_record_with_every_owner_device_owed_is_given_the_steps_its_detail_promises()
{
    let EveryOwnerOwed { rig, file, .. } =
        a_request_that_names_every_owner_device_and_a_record(|tree| {
            std::fs::write(
                restored::file_beside(&tree.environment().registry_database()),
                b"junk",
            )
            .expect("junk");
        })
        .await;
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check.detail().contains("cannot be read"),
        "the record cannot be read: {}",
        check.detail()
    );
    let promises_the_steps = check.detail().contains("the remedy gives the steps");
    let gives_them = check.remedy().is_some_and(|remedy| {
        remedy.contains("restored-policy.cbor") && remedy.contains("last owner device")
    });
    assert!(
        !promises_the_steps || gives_them,
        "the detail promises steps the remedy lacks: {} / {:?}",
        check.detail(),
        check.remedy()
    );
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&file.display().to_string()),
        "the refusal gives the record's full path: {refused:?}"
    );
}

/// KR-REQ-24.15: while the host is behind its feed, the doctor and the confirmation say what keeps
/// the catch-up from ending and how to fix it, and give the steps that keep an owner device only
/// once it has ended: removing the record of the restore while the host is behind writes a new one
/// at the next start. The refusal of the confirmation gives the record's full path in both states.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn while_the_host_is_behind_its_feed_the_route_that_keeps_an_owner_waits_for_the_catch_up() {
    let rig = Rig::start().await;
    let second = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let other = rig.pairs(&[ActionRight::SessionView]).await;
    let revoked = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-earlier.sqlite3");
    let request = rig
        .owner_publishes(0xb1, devices(revoked.1.device_id))
        .await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged(&request).await;
    let kept = rig.owner_device();
    // A request by a key the host does not know that names every owner device of the host.
    let key = AuthorisationKeyPair::generate().expect("a key");
    let naming_every_owner = rig.request_of(
        &key,
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([0x0f; 16])),
        0xd1,
        RevocationTarget::Devices {
            device_ids: [kept, second.1.device_id, other.1.device_id]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&key, &naming_every_owner).await;

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
    let file = restored::file_beside(&rig.host.tree().environment().registry_database());

    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check.detail().contains("catching up"),
        "the doctor says what keeps the host from confirming: {}",
        check.detail()
    );
    assert!(
        check.remedy().is_some_and(|remedy| remedy.contains("disk")
            && remedy.contains("permissions")
            && !remedy.contains("pair a new owner device")),
        "and how to fix it, without the steps that remove the record: {:?}",
        check.remedy()
    );

    // The fault goes, the next pass catches up, and the steps that keep an owner come.
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
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&file.display().to_string()),
        "the refusal gives the full path of the record to remove: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("restored-policy.cbor")
                && remedy.contains("last owner device")),
        "the doctor gives the steps that keep an owner: {:?}",
        check.remedy()
    );
    rig.revokes_at_the_machine(second.1.device_id).await;
    rig.revokes_at_the_machine(other.1.device_id).await;
    let rig = rig.the_wait_is_ended_by_hand().await;
    rig.until_the_carrier_is_idle().await;
    assert!(
        !rig.host.controller().restored_policy_waits(),
        "with the host caught up, the record gone is the end of the wait"
    );
    let new_owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.revokes_at_the_machine(kept).await;
    rig.serves(&new_owner.0, &new_owner.1)
        .await
        .expect("the new owner device is served once the kept one is gone");
}

/// KR-REQ-24.15: when a withdrawal the host cannot verify also names every owner device, the
/// record's removal is not enough: the host still refuses every remote grant, the kept owner's
/// confirmation included, so the route also takes `authority.origin` out until the new owner device
/// is paired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn when_a_withdrawal_the_host_cannot_verify_names_every_owner_device_the_route_takes_the_feed_out()
 {
    let rig = Rig::start().await;
    let second = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    let other = rig.pairs(&[ActionRight::SessionView]).await;
    rig.until_the_carrier_is_idle().await;
    let earlier = a_copy_of_the_registry(&rig.host, "registry-before-the-issuer.sqlite3");
    // An owner is paired after the copy and withdraws every device the registry holds that can
    // manage, and the one that cannot.
    let issuer = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.until_the_carrier_is_idle().await;
    let kept = rig.owner_device();
    let key = issuer.0.keys().authorisation.clone();
    let request = rig.request_of(
        &key,
        issuer.1.device_id,
        0xa1,
        RevocationTarget::Devices {
            device_ids: [kept, second.1.device_id, other.1.device_id]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
        },
    );
    rig.published_as(&key, &request).await;
    rig.poll().await;
    rig.until_the_revocation_is_acknowledged_to(&key, &request)
        .await;
    let origin = rig.served.origin().to_owned();
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.until_the_carrier_is_idle().await;
    let file = restored::file_beside(&rig.host.tree().environment().registry_database());
    let refused = rig.the_confirmation_is_refused().await;
    assert!(
        refused.message.contains(&file.display().to_string())
            && refused.message.contains("authority.origin"),
        "the refusal gives the record's path and says to take the feed out too: {refused:?}"
    );
    assert!(
        refused
            .message
            .contains("everything the withdrawal names is revoked")
            && refused.message.contains("bounds offline validity"),
        "and says when to put it back and to finish inside the offline bound: {refused:?}"
    );
    let check = rig
        .the_restored_policy_check()
        .await
        .expect("the doctor says the host waits");
    assert!(
        check.remedy().is_some_and(|remedy| remedy
            .contains("everything the withdrawal names is revoked")
            && remedy.contains("bounds offline validity")),
        "the doctor's steps say the same: {:?}",
        check.remedy()
    );

    rig.revokes_at_the_machine(second.1.device_id).await;
    rig.revokes_at_the_machine(other.1.device_id).await;
    // The record gone and the feed still read: the host still refuses the kept owner's confirmation.
    let rig = rig.the_wait_is_ended_by_hand().await;
    rig.until_the_carrier_is_idle().await;
    let mut local = rig.host.client().await;
    let refused = rig
        .owner_device_invites(&mut local)
        .await
        .expect_err("the withdrawal the host cannot verify refuses the owner's confirmation");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    drop(local);

    // Taken out of the configuration, the feed is not read, and the owner's confirmation is spent.
    let rig = rig
        .restarted(false, |tree| net_support::write_feed_document(tree, None))
        .await;
    let new_owner = rig
        .pairs(&[ActionRight::HostManage, ActionRight::SessionView])
        .await;
    rig.revokes_at_the_machine(kept).await;
    // Set back, the feed names nothing that is live, and the new owner device is served.
    let rig = rig
        .restarted(false, |tree| {
            net_support::write_feed_document(tree, Some(&origin));
        })
        .await;
    rig.until_the_carrier_is_idle().await;
    rig.serves(&new_owner.0, &new_owner.1)
        .await
        .expect("nothing the withdrawal names is live, so no refusal rises");
}
