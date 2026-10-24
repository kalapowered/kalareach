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
use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::method::Method;
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
/// the restart only when `then_idle`; else the case waits for what it wants to see.
async fn a_withdrawal_by_an_owner_the_host_does_not_know(
    victim_rights: &[ActionRight],
    delegations: &[(u32, Moment)],
    then_idle: bool,
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
    let rig = rig
        .restarted(false, |tree| put_the_registry_back(tree, &earlier))
        .await;
    if then_idle {
        rig.until_the_carrier_is_idle().await;
        rig.until_the_carrier_is_idle().await;
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
    } = a_withdrawal_by_an_owner_the_host_does_not_know(&[ActionRight::SessionView], &[], true)
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
    } = a_withdrawal_by_an_owner_the_host_does_not_know(&[ActionRight::SessionView], &[], true)
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
                    completion: RevocationCompletion::Complete,
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

/// KR-REQ-24.15: a limit. A request put off while the host was behind its feed, whose issuer a later
/// withdrawal by an owner the host knows revoked, is refused: the registry holds the issuer revoked,
/// and the host refuses the request of a revoked issuer wherever the feed puts it, because the feed
/// sets the order and a signature does not cover it. What the request named is not withdrawn. Only
/// a record the host kept of its own that it had begun the request could finish it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_put_off_ahead_of_a_withdrawal_the_host_carried_out_again_is_refused() {
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
        held.rejected.0,
        Some(RejectionReason::NoOwnerAuthority),
        "the issuer is revoked, and its request is refused wherever it stands: {held:?}"
    );
    assert!(rig.has_revoked(issuer.1.device_id).await);
    assert!(!rig.has_revoked(target.1.device_id).await);
    for served in [&target, &kept] {
        let session = connect(&rig.host, &served.0, &served.1).await;
        rig.doctor_as(&session)
            .await
            .expect("a device the request named is served: it was not withdrawn");
    }
}

/// KR-REQ-24.15: where a withdrawal the host cannot verify stands in the feed is read from the feed
/// by every run, and no state of the run before is needed. The host stops after the scan that found
/// the withdrawal and before the scan that judges the request, and the run that follows carries the
/// request out all the same: the issuer is still live where its request stands.
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
    // The first scan reads the feed (1), puts the request off and finds the withdrawal; the feed
    // turns the second scan's read (2) back, and the host stops there.
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "read", 2, TURNED_BACK);
    rig.poll().await;
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
