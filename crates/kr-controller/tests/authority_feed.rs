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
//! The feed is the stand-in held to a recording of a local Worker. Every wait the daemon asks for is
//! held by the test.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::authority::{AuthorityFeedClient, AuthorityFeedState, RejectionReason};
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_controller::authority_feed::FeedRuntime;
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
use net_support::{Device, Host, connect, pair_with, proposal};

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
        let served = serve().await;
        let timer = HeldTimer::held();
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_with_feed(&owner, served.origin(), Arc::clone(&timer) as _).await;
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
    /// length of the poll interval the feed states, and returns what ends it.
    async fn until_a_pass_waits(&self) -> Arc<tokio::sync::Notify> {
        let (waited, release) =
            within("the carrier waits between passes", self.timer.next_wait()).await;
        assert_eq!(
            waited,
            Duration::from_millis(kr_controller::grants::feed::FEED_POLL_INTERVAL_MS),
            "the carrier polls at the interval section 10 fixes"
        );
        release
    }

    /// Waits until a pass that began after this call has finished: what a connection waits for, and
    /// what a request published before this call is read by. The carrier's waits stay held.
    async fn poll(&self) {
        self.runtime().synchronised_before_serving().await;
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

    /// Stops the daemon and starts it again while the feed cannot be reached, so that what it
    /// knows of the feed is what it wrote down. A suite closes its clients before it restarts.
    async fn restarted_while_the_feed_is_down(self) -> (Host, Served) {
        let Self { host, served, .. } = self;
        for nth in 1..=4 {
            served.web().fail(
                AUTHORITY,
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

/// KR-REQ-10.46: a device the feed holds a revocation for is refused on its first request after
/// it connects, with polling off. Section 10 asks for the synchronisation before affected remote
/// access, so a poll that has not come yet is no window for the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_feed_holds_a_revocation_for_is_refused_on_its_first_request() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let request = rig.owner_publishes(0xa1, devices(record.device_id)).await;

    // The carrier's wait has not ended: nothing but the connection can have taught the host.
    let session = connect(&rig.host, &phone, &record).await;
    rig.doctor_as(&session)
        .await
        .expect_err("the revocation reached the host before the first request");
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

/// The poll the feed states carries out a revocation published while the device stays connected.
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

/// A host that stops after it carried a request out and before it acknowledged it finishes the same
/// request the same way on its next start: one revision, and the registry advanced once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_between_carrying_a_request_out_and_acknowledging_it_finishes_it_once() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let request = rig.owner_publishes(0xa3, devices(record.device_id)).await;

    // The pass reads (1), issues its revision (2) and acknowledges (3): the last never arrives.
    rig.served.web().fail(AUTHORITY, 3, Moment::Before);
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

/// A feed that cannot be reached, or that is slow, is not a removal: nothing is refused, the status
/// is stale, and the connection that waited for it is served after the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_cannot_be_reached_refuses_nothing_and_shows_stale_status() {
    let rig = Rig::start().await;
    rig.the_owner_bounds_offline_validity();
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.served.web().fail(
        AUTHORITY,
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
    rig.served.web().fail(
        AUTHORITY,
        2,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
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
    let mut passes = rig.runtime().passes();
    let seen = *passes.borrow_and_update();
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

    // The pass reads (1) and refuses the second request (2): the refusal never arrives.
    rig.served.web().fail(AUTHORITY, 2, Moment::Before);
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

    // The pass reads (1), issues its revision (2) and acknowledges (3): the feed turns the
    // acknowledgement back, naming no delay.
    rig.served.web().fail(
        AUTHORITY,
        3,
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

/// The host decides the issuer of a request as it decides the same device's own revocation: a
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
    // The first pass reads (1) and refuses 64 records (2 to 65); the scan then goes on at once with
    // a second read (66), which the feed turns back.
    rig.served.web().fail(
        AUTHORITY,
        66,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.poll().await;
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

    rig.served.web().fail(AUTHORITY, 1, Moment::Hold);
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
