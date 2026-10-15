//! The host reading its own mailbox, through a real daemon: a remote owner who publishes a change
//! to the host's authority feed and announces it, a mailbox service that answers as the Worker's
//! does, and the host that reads what reaches it.
//!
//! Section 20 gives every mailbox item the same rules on the way in: it opens only against the key
//! of a device the host has paired, the routing record outside it is untrusted, an identifier the
//! host has accepted is refused, and what the host accepted is written down before the service is
//! told it may remove the item. What a host takes from its own mailbox is an announcement that its
//! authority feed changed, which has the carrier read the feed now and not at its next poll; the
//! feed is the record, so what is held here is that a forged, replayed or foreign item changes
//! nothing and that a host that cannot read its mailbox says so.
//!
//! The service is the stand-in held to the Worker's source, and it holds the mailbox at the service
//! the host's authority feed is at. Every wait the daemon asks for is held by the test, which ends
//! the reader's alone. What the carrier is woken for is counted by the carrier itself, so that a
//! wake the reader should not have made shows as a count and not as a pass that had not yet ended.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::authority::{AuthorityFeedClient, FeedAnnouncement, announcement_expiry};
use kr_client::services::mailbox::MailboxClient;
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_controller::mailbox_reader::{MailboxReader, POLL_INTERVAL};
use kr_controller::testing::HeldTimer;
use kr_crypto::envelope::seal_envelope;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys, StoredEnvelopeKeyPair, key_id};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult};
use kr_protocol::ids::{DeviceId, EnvelopeId, RevocationRequestId};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType, SealedEnvelope,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{KeyPurpose, RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, Nullable, Signature64, StoredEnvelopeKey, TimestampMs,
    Uuid,
};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Moment, Served, serve};
use net_support::{Device, Host, MovedWall, connect, pair_with, proposal};

const ACKNOWLEDGE: &str = "/api/mailbox/acknowledge";

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

fn transport(origin: &str) -> (GatewayOrigin, Arc<dyn ServiceHttp>) {
    let gateway = GatewayOrigin::new(origin).expect("an origin");
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    (gateway, http)
}

/// Everything one test holds: a daemon whose configuration selects the authority feed at the
/// stand-in, which also holds the host's mailbox, the stand-in, and the clocks.
struct Rig {
    host: Host,
    served: Served,
    timer: Arc<HeldTimer>,
    wall: MovedWall,
    owner: DeviceKeys,
    host_keys: DeviceKeys,
    /// The owner, as a remote owner's client reaches the feed.
    feed: AuthorityFeedClient,
    /// The owner, as a device that leaves an item in a mailbox reaches the service.
    mailbox: MailboxClient,
}

impl Rig {
    async fn start() -> Self {
        let served = serve().await;
        let owner = DeviceKeys::generate().expect("owner keys");
        let host_keys = DeviceKeys::generate().expect("host keys");
        Self::start_on(served, owner, host_keys).await
    }

    async fn start_on(served: Served, owner: DeviceKeys, host_keys: DeviceKeys) -> Self {
        let timer = HeldTimer::held();
        let wall = MovedWall::new();
        let host = Host::start_with_feed_and_keys(
            &owner,
            &host_keys,
            served.origin(),
            Arc::clone(&timer) as _,
            wall.clocks(),
        )
        .await;
        let (gateway, http) = transport(served.origin());
        let signer = Arc::new(Installation(owner.authorisation.clone()));
        let rig = Self {
            host,
            served,
            timer,
            wall,
            feed: AuthorityFeedClient::new(
                gateway.clone(),
                Arc::clone(&http),
                Arc::clone(&signer) as _,
            ),
            mailbox: MailboxClient::new(gateway, http, signer as _),
            owner,
            host_keys,
        };
        // Every pass the start asked for has run: the reader has claimed the mailbox and found it
        // empty, and waits out its interval.
        rig.the_reader_has_looked().await;
        rig.the_carrier_has_settled().await;
        rig
    }

    fn reader(&self) -> &MailboxReader {
        self.host
            .controller()
            .mailbox_reader()
            .expect("a reader of the host's mailbox")
    }

    /// How many times something has asked the carrier to look again now, since the daemon started.
    fn feed_wakes(&self) -> u64 {
        self.host
            .controller()
            .feed_runtime()
            .expect("a carrier")
            .wakes()
    }

    /// Whether the host has applied a revocation of `device`.
    fn device_is_revoked(&self, device: DeviceId) -> bool {
        self.host
            .controller()
            .devices()
            .devices()
            .expect("the host's devices")
            .into_iter()
            .any(|record| record.device_id == device && record.revoked_at_ms.is_some())
    }

    fn feed_passes(&self) -> u64 {
        *self
            .host
            .controller()
            .feed_runtime()
            .expect("a carrier")
            .passes()
            .borrow()
    }

    /// The host's own stored-envelope key, which is what its mailbox is addressed by.
    fn host_key(&self) -> &StoredEnvelopeKey {
        self.host_keys.stored_envelope.public()
    }

    /// Waits until the carrier has read the feed since the start and the pairing of the owner, and
    /// waits out its interval: what it does from here is what something made it do.
    async fn the_carrier_has_settled(&self) {
        let interval = Duration::from_millis(kr_controller::grants::feed::FEED_POLL_INTERVAL_MS);
        let waits = || {
            self.timer
                .asked_for()
                .iter()
                .filter(|waited| **waited == interval)
                .count()
        };
        let before = waits();
        let carrier = self.host.controller().feed_runtime().expect("a carrier");
        carrier.synchronised_before_serving().await;
        within("the carrier waits out its interval", async {
            while waits() == before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    /// Waits until the reader has finished its first pass, which the start asks for.
    async fn the_reader_has_looked(&self) {
        let mut passes = self.reader().passes();
        within("the reader's first pass finishes", async {
            while *passes.borrow_and_update() == 0 {
                passes.changed().await.expect("the reader is running");
            }
        })
        .await;
    }

    /// Waits until the reader waits between two passes, and returns what ends that wait. The
    /// carrier's waits stay held.
    async fn reader_waits(&self) -> Arc<tokio::sync::Notify> {
        let (waited, release) = within(
            "the reader waits between passes",
            self.timer
                .next_wait_under(POLL_INTERVAL + Duration::from_millis(1)),
        )
        .await;
        assert_eq!(
            waited, POLL_INTERVAL,
            "the reader looks at the interval it states"
        );
        release
    }

    /// The reader's interval ends, and this returns once the pass that follows has finished.
    async fn the_reader_reads(&self) {
        let release = self.reader_waits().await;
        let mut passes = self.reader().passes();
        let seen = *passes.borrow_and_update();
        release.notify_one();
        within("a pass of the reader finishes", async {
            while *passes.borrow_and_update() <= seen {
                passes.changed().await.expect("the reader is running");
            }
        })
        .await;
    }

    /// A device pairs under a grant with the rights named, and has not connected yet.
    async fn pairs(
        &self,
        rights: &[ActionRight],
    ) -> (Device, kr_controller::service::net::devices::DeviceRecord) {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal(rights)).await;
        // The pairing has the carrier name the owners again, which is a pass of its own.
        self.the_carrier_has_settled().await;
        (device, record)
    }

    fn feed_key(&self) -> kr_protocol::scalars::KeyId {
        self.host
            .controller()
            .feed_runtime()
            .expect("a carrier")
            .feed()
    }

    fn host_device(&self) -> DeviceId {
        DeviceId::new(self.host.environment_id.get())
    }

    fn owner_device(&self) -> DeviceId {
        self.host.owner.as_ref().expect("an owner").device_id
    }

    /// A request the owner signs, naming `target`, under a fixed identity.
    fn request(&self, id: u8, target: RevocationTarget) -> RevocationRequest {
        kr_pairing::grants::sign_revocation_request(
            &self.owner.authorisation,
            RevocationRequestId::new(Uuid::from_bytes([id; 16])),
            self.owner_device(),
            self.host_device(),
            target,
            TimestampMs::new(self.now()),
        )
        .expect("a signed request")
    }

    /// The machine's reading of UTC now, which is the daemon's before its clock is moved.
    fn now(&self) -> u64 {
        kr_ipc::now_ms().get()
    }

    /// An announcement that the feed changed, sealed by `from` to the host and expiring in an hour
    /// from the machine's clock.
    fn announcement_from(&self, from: &StoredEnvelopeKeyPair, number: u8) -> FeedAnnouncement {
        FeedAnnouncement {
            recipient_key: *self.host_key(),
            envelope: self.sealed(from, MailboxPayloadType::AuthorityFeedChange, number),
        }
    }

    /// One item of `kind` from `from` to the host, whose identity is `number`.
    fn sealed(
        &self,
        from: &StoredEnvelopeKeyPair,
        kind: MailboxPayloadType,
        number: u8,
    ) -> SealedEnvelope {
        let now = self.now();
        seal_envelope(
            from,
            self.host_key(),
            &EnvelopePlaintext {
                version: EnvelopeVersion::V1,
                envelope_id: EnvelopeId::new(Uuid::from_bytes([number; 16])),
                sender_key_id: key_id(KeyPurpose::StoredEnvelope, from.public().as_bytes()),
                recipient_key_id: key_id(KeyPurpose::StoredEnvelope, self.host_key().as_bytes()),
                payload_type: kind,
                created_at_ms: TimestampMs::new(now),
                expires_at_ms: announcement_expiry(now),
                grant_id: Nullable::null(),
                environment_id: Nullable::null(),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                thread_id: Nullable::null(),
                payload: Bytes::new(vec![number; 32]),
            },
        )
        .expect("a sealed item")
    }

    /// The owner publishes a request to the host's feed and announces the change to the host's
    /// mailbox with it.
    async fn owner_publishes_and_announces(&self, id: u8, target: RevocationTarget) {
        let request = self.request(id, target);
        let announced = self
            .feed
            .publish(
                self.feed_key(),
                &request,
                Some(&self.announcement_from(&self.owner.stored_envelope, id)),
            )
            .await
            .expect("the feed stores the request")
            .announced
            .expect("the feed says what became of the announcement");
        assert_eq!(
            announced.mailbox,
            kr_client::services::authority::AnnouncementPlacement::Stored,
            "the announcement reached the host's mailbox"
        );
    }

    /// The owner publishes a request to the host's feed and says nothing of it to the mailbox.
    async fn owner_publishes(&self, id: u8, target: RevocationTarget) {
        let request = self.request(id, target);
        self.feed
            .publish(self.feed_key(), &request, None)
            .await
            .expect("the feed stores the request");
    }

    /// How many items the host's mailbox holds at the service.
    fn items_held(&self) -> usize {
        self.served.web().mailbox_envelopes(self.host_key()).len()
    }

    /// What `kr doctor` says of the reader.
    async fn check(&self) -> DoctorCheck {
        let mut local = self.host.client().await;
        let doctor: HostDoctorResult =
            net_support::pairing::read(&mut local, Method::HostDoctor, &())
                .await
                .expect("the host's diagnostics");
        doctor
            .checks
            .into_iter()
            .find(|check| check.id() == "mailbox-reader")
            .expect("the reader's check")
    }

    /// Stops the daemon and starts it again on its tree and its service.
    async fn restarted(self) -> Self {
        self.restarted_after(|_| {}).await
    }

    /// Stops the daemon, lets `change` alter its tree, and starts it again on the tree.
    async fn restarted_after(self, change: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        let Self {
            host,
            served,
            wall,
            owner,
            host_keys,
            ..
        } = self;
        let stopped = host.shut_down().await;
        change(stopped.tree());
        let timer = HeldTimer::held();
        let host = stopped.start_with_timer(Arc::clone(&timer) as _).await;
        let (gateway, http) = transport(served.origin());
        let signer = Arc::new(Installation(owner.authorisation.clone()));
        let rig = Self {
            host,
            served,
            timer,
            wall,
            feed: AuthorityFeedClient::new(
                gateway.clone(),
                Arc::clone(&http),
                Arc::clone(&signer) as _,
            ),
            mailbox: MailboxClient::new(gateway, http, signer as _),
            owner,
            host_keys,
        };
        rig.the_reader_has_looked().await;
        rig.the_carrier_has_settled().await;
        rig
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

/// Waits until the carrier of the feed has finished a pass beyond `seen`.
async fn until_the_carrier_passes(rig: &Rig, seen: u64) {
    let mut passes = rig
        .host
        .controller()
        .feed_runtime()
        .expect("a carrier")
        .passes();
    within("a pass of the carrier finishes", async {
        while *passes.borrow_and_update() <= seen {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
}

/// KR-REQ-09.21, KR-REQ-10.46: an announcement in the host's mailbox has the carrier read the feed
/// at once. The carrier's own interval is never ended by the test, so the revocation it carries out
/// is carried out because the host read its mailbox and found the announcement there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announcement_in_the_hosts_mailbox_has_the_feed_read_at_once() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect("the connection is served while nothing is held for it");
    rig.the_carrier_has_settled().await;

    rig.owner_publishes_and_announces(0xa1, devices(record.device_id))
        .await;
    assert_eq!(
        rig.items_held(),
        1,
        "the announcement is waiting for the host"
    );
    let seen = rig.feed_passes();
    let woken = rig.feed_wakes();

    rig.the_reader_reads().await;
    until_the_carrier_passes(&rig, seen).await;
    assert_eq!(rig.feed_wakes(), woken + 1, "one announcement, one wake");

    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the carrier carried the revocation out before its interval ended");
    assert_eq!(
        rig.items_held(),
        0,
        "the host told the service it has the item"
    );
}

/// The control: the same change published with no announcement waits for the carrier's poll,
/// however often the host reads its mailbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_published_with_no_announcement_waits_for_the_poll() {
    let rig = Rig::start().await;
    let (phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    let session = connect(&rig.host, &phone, &record).await;
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect("the connection is served while nothing is held for it");
    rig.the_carrier_has_settled().await;

    rig.owner_publishes(0xa2, devices(record.device_id)).await;
    let seen = rig.feed_passes();
    let woken = rig.feed_wakes();
    rig.the_reader_reads().await;
    rig.the_reader_reads().await;

    assert_eq!(rig.feed_wakes(), woken, "nothing woke the carrier");
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect("the device is still served until the poll");

    rig.timer.release_held();
    until_the_carrier_passes(&rig, seen).await;
    session
        .read::<_, HostDoctorResult>(Method::HostDoctor, &())
        .await
        .expect_err("the poll carried the revocation out");
}

/// An item whose acknowledgement the service did not receive is read again, and the host takes it
/// once: the identifier it accepted is on record, so the second reading is a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_whose_acknowledgement_was_lost_is_taken_once() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.served.web().fail(ACKNOWLEDGE, 1, Moment::Before);
    rig.owner_publishes_and_announces(0xa3, devices(record.device_id))
        .await;

    let seen = rig.feed_passes();
    let woken = rig.feed_wakes();
    rig.the_reader_reads().await;
    until_the_carrier_passes(&rig, seen).await;
    assert_eq!(
        rig.items_held(),
        1,
        "the service never heard that the host has it"
    );
    assert_eq!(rig.reader().record().len().expect("the record"), 1);
    assert_eq!(
        rig.feed_wakes(),
        woken + 1,
        "the announcement woke the carrier"
    );

    // The backoff after a pass that could not finish has run its course, and the item is read
    // again. The carrier is not woken by what it already knows.
    rig.timer.advance(Duration::from_secs(60));
    rig.timer.release_held();
    within("the item is acknowledged", async {
        while rig.items_held() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("1 announcement(s) taken"),
        "{}",
        shown.detail()
    );
    assert_eq!(rig.reader().record().len().expect("the record"), 1);
    // Releasing every held wait lets the carrier poll at its own interval as well, which is no
    // wake: the count holds that the replay asked for none.
    assert_eq!(rig.feed_wakes(), woken + 1, "the replay woke nothing");
}

/// What the host accepted survives a restart: an item the service offers again to a daemon that was
/// stopped before it could say it had the item is refused, not taken a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_taken_before_a_restart_is_not_taken_again_after_it() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    // The service is down for the acknowledgement the first daemon makes.
    rig.served.web().fail(
        ACKNOWLEDGE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.owner_publishes_and_announces(0xa4, devices(record.device_id))
        .await;
    rig.the_reader_reads().await;
    assert_eq!(
        rig.items_held(),
        1,
        "the service still holds what the host took"
    );
    assert_eq!(rig.reader().record().len().expect("the record"), 1);

    let rig = rig.restarted().await;
    // The start read the mailbox and found the item again.
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("0 announcement(s) taken"),
        "the item is a replay after the restart: {}",
        shown.detail()
    );
    assert!(shown.detail().contains("1 dropped"), "{}", shown.detail());
    assert_eq!(rig.feed_wakes(), 0, "the replay woke nothing");
    assert_eq!(
        rig.items_held(),
        0,
        "and the host has told the service it has it"
    );
}

/// An item from a key the host has not paired with opens for nobody: it is dropped, the service is
/// told the host is done with it, and the carrier is not woken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_from_a_key_the_host_has_not_paired_with_is_dropped() {
    let rig = Rig::start().await;
    let stranger = StoredEnvelopeKeyPair::generate().expect("a key");
    rig.mailbox
        .deliver(
            rig.host_key(),
            &rig.sealed(&stranger, MailboxPayloadType::AuthorityFeedChange, 0xb1),
        )
        .await
        .expect("the service takes the item: it cannot read it");
    assert_eq!(rig.items_held(), 1);
    let woken = rig.feed_wakes();

    rig.the_reader_reads().await;

    assert_eq!(rig.items_held(), 0, "the host is done with it");
    assert_eq!(
        rig.feed_wakes(),
        woken,
        "nothing the stranger said woke the carrier"
    );
    let shown = rig.check().await;
    assert!(shown.detail().contains("1 dropped"), "{}", shown.detail());
    assert!(
        rig.reader().record().is_empty().expect("the record"),
        "an item that did not open leaves no identifier"
    );
}

/// A device the host unpaired stops being a sender: what it announced while it was paired woke the
/// carrier, and what it announces after is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_from_a_device_the_host_has_since_unpaired_is_dropped() {
    let rig = Rig::start().await;
    let keys = DeviceKeys::generate().expect("a device's keys");
    let device = Device::with_keys(keys.clone()).await;
    let record = pair_with(
        &rig.host,
        &device,
        &rig.owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let from_the_device = |number: u8| {
        rig.sealed(
            &keys.stored_envelope,
            MailboxPayloadType::AuthorityFeedChange,
            number,
        )
    };

    rig.mailbox
        .deliver(rig.host_key(), &from_the_device(0xe1))
        .await
        .expect("the service takes the item");
    let seen = rig.feed_passes();
    rig.the_reader_reads().await;
    until_the_carrier_passes(&rig, seen).await;

    rig.host
        .network()
        .revoke_device(record.device_id)
        .await
        .expect("the device is unpaired");
    rig.the_carrier_has_settled().await;
    let woken = rig.feed_wakes();
    rig.mailbox
        .deliver(rig.host_key(), &from_the_device(0xe2))
        .await
        .expect("the service takes the item");
    rig.the_reader_reads().await;

    assert_eq!(rig.items_held(), 0);
    assert_eq!(rig.feed_wakes(), woken, "the unpaired device woke nothing");
    let shown = rig.check().await;
    assert!(
        shown.detail().contains("1 announcement(s) taken") && shown.detail().contains("1 dropped"),
        "{}",
        shown.detail()
    );
}

/// A paired device's item that is not an announcement that the feed changed is taken off the
/// service and does nothing: the mailbox carries no command, and the host acts on none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_that_is_not_an_announcement_does_nothing_whoever_sent_it() {
    let rig = Rig::start().await;
    let woken = rig.feed_wakes();
    for (number, kind) in [
        (0xc1, MailboxPayloadType::StateReference),
        (0xc2, MailboxPayloadType::ActionReceipt),
        (0xc3, MailboxPayloadType::SignedAuthorityObject),
    ] {
        rig.mailbox
            .deliver(
                rig.host_key(),
                &rig.sealed(&rig.owner.stored_envelope, kind, number),
            )
            .await
            .expect("the service takes the item");
    }
    assert_eq!(rig.items_held(), 3);

    rig.the_reader_reads().await;

    assert_eq!(rig.items_held(), 0);
    assert_eq!(rig.feed_wakes(), woken, "none of them woke the carrier");
    let shown = rig.check().await;
    assert!(
        shown
            .detail()
            .contains("0 announcement(s) taken, 2 ignored, 1 dropped"),
        "two are ignored once they opened, and the one that claims authority is refused: {}",
        shown.detail()
    );
}

/// A host whose authorisation key changed is refused its mailbox for good, which is shown, and it
/// reads the feed its new key addresses at the feed's own poll: a revocation published there is
/// carried out, and one published to the feed the old key addressed is not read at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_authorisation_key_changed_is_refused_its_mailbox_and_reads_its_new_feed() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
    let old_feed = rig.feed_key();

    // The host's authorisation key is replaced, as a host restored from a backup meets it: the
    // mailbox was claimed by the key it had before.
    let rig = rig
        .restarted_after(|tree| {
            net_support::replace_host_authorisation(tree);
        })
        .await;
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning, "{}", shown.detail());
    assert!(
        shown.detail().contains("turned a request back"),
        "{}",
        shown.detail()
    );
    assert!(
        shown
            .remedy()
            .is_some_and(|remedy| remedy.contains("stays claimed")),
        "the claim is permanent, and the remedy says so: {:?}",
        shown.remedy()
    );
    let new_feed = rig.feed_key();
    assert_ne!(new_feed, old_feed, "the new key addresses another feed");

    // A request at the feed the old key addressed is not read.
    let seen = rig.feed_passes();
    rig.feed
        .publish(
            old_feed,
            &rig.request(0xd4, devices(record.device_id)),
            None,
        )
        .await
        .expect("the service stores the request");
    rig.timer.release_held();
    until_the_carrier_passes(&rig, seen).await;
    rig.the_carrier_has_settled().await;
    assert!(
        !rig.device_is_revoked(record.device_id),
        "the old feed is not the host's feed any more"
    );

    // One at the feed the new key addresses is carried out at the poll, with no announcement and
    // with the mailbox refused.
    let seen = rig.feed_passes();
    rig.feed
        .publish(
            new_feed,
            &rig.request(0xd5, devices(record.device_id)),
            None,
        )
        .await
        .expect("the service stores the request");
    rig.timer.release_held();
    until_the_carrier_passes(&rig, seen).await;
    within("the poll carries the revocation out", async {
        while !rig.device_is_revoked(record.device_id) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(rig.check().await.status, DoctorStatus::Warning);
}

/// An item that is still good when the pass begins but has expired by the time the host opens it
/// is dropped: the clock is read for each item, not once for the pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_that_expires_while_the_pass_waits_on_the_service_is_dropped() {
    let rig = Rig::start().await;
    let (_phone, record) = rig.pairs(&[ActionRight::SessionView]).await;
    rig.owner_publishes_and_announces(0xd6, devices(record.device_id))
        .await;
    let woken = rig.feed_wakes();

    // The service is slow to answer the read: the pass has begun and holds the page it will be
    // given when the answer comes.
    rig.served.web().fail("/api/mailbox/read", 1, Moment::Slow);
    let release = rig.reader_waits().await;
    let reads = rig.served.web().requests_to("/api/mailbox/read");
    let mut passes = rig.reader().passes();
    let finished = *passes.borrow_and_update();
    release.notify_one();
    within("the read reaches the service", async {
        rig.served
            .web()
            .requests_reach("/api/mailbox/read", reads + 1)
            .await;
    })
    .await;
    // The announcement lives for an hour; the host's clock moves past that while the answer is
    // held.
    rig.wall.advance(Duration::from_secs(2 * 60 * 60));
    rig.served.web().release_held();
    within("the pass finishes", async {
        while *passes.borrow_and_update() <= finished {
            passes.changed().await.expect("the reader is running");
        }
    })
    .await;

    let shown = rig.check().await;
    assert!(
        shown
            .detail()
            .contains("0 announcement(s) taken, 0 ignored, 1 dropped"),
        "{}",
        shown.detail()
    );
    assert_eq!(
        rig.feed_wakes(),
        woken,
        "an expired announcement woke nothing"
    );
    assert!(
        rig.reader().record().is_empty().expect("the record"),
        "and left no identifier"
    );
    assert_eq!(rig.items_held(), 0, "the host is done with it");
}

/// A service that cannot be reached is shown, asked again after a backoff, and answered by the host
/// as soon as it can: nothing was lost in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mailbox_that_cannot_be_reached_is_shown_and_read_again() {
    let rig = Rig::start().await;
    // An announcement of a change the feed does not hold, so that reading it withdraws no
    // authority from the connection the check is made over.
    rig.mailbox
        .deliver(
            rig.host_key(),
            &rig.announcement_from(&rig.owner.stored_envelope, 0xd1)
                .envelope,
        )
        .await
        .expect("the service takes the announcement");
    rig.served.web().fail(
        "/api/mailbox/read",
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    rig.the_reader_reads().await;
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning);
    assert!(
        shown.detail().contains("could not be reached"),
        "{}",
        shown.detail()
    );
    assert_eq!(rig.items_held(), 1, "nothing was removed");

    rig.timer.release_held();
    within("the host reads the announcement", async {
        while rig.items_held() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// A mailbox of more than one page is read through in one pass: every page is handled and
/// acknowledged before the next is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mailbox_of_more_than_a_page_is_read_through_in_one_pass() {
    const ITEMS: u8 = 70;
    let rig = Rig::start().await;
    for number in 1..=ITEMS {
        rig.mailbox
            .deliver(
                rig.host_key(),
                &rig.sealed(
                    &rig.owner.stored_envelope,
                    MailboxPayloadType::StateReference,
                    number,
                ),
            )
            .await
            .expect("the service takes the item");
    }
    assert_eq!(rig.items_held(), usize::from(ITEMS));
    let reads = rig.served.web().requests_to("/api/mailbox/read");

    rig.the_reader_reads().await;

    assert_eq!(rig.items_held(), 0, "every page was taken and acknowledged");
    assert!(
        rig.served.web().requests_to("/api/mailbox/read") >= reads + 3,
        "the items took three pages"
    );
    let shown = rig.check().await;
    assert!(
        shown
            .detail()
            .contains("0 announcement(s) taken, 70 ignored, 0 dropped"),
        "{}",
        shown.detail()
    );
}

/// A service that asks to be left alone for a time is left alone for that long, whatever the
/// host's own backoff would have been.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_asks_to_be_left_alone_is_left_alone_for_as_long_as_it_asked() {
    let rig = Rig::start().await;
    rig.served.web().fail(
        "/api/mailbox/read",
        1,
        Moment::Refuse {
            status: 429,
            code: "RATE_LIMITED",
            retry_after_seconds: Some(120),
        },
    );
    rig.the_reader_reads().await;
    within("the reader waits out what the service asked", async {
        while !rig
            .timer
            .asked_for()
            .iter()
            .any(|waited| *waited >= Duration::from_secs(120))
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(rig.check().await.status, DoctorStatus::Warning);
}

/// A write to the record that fails partway down a page stops the pass: nothing on the page is
/// acknowledged, the announcement already written down still has the carrier read the feed, and
/// the next pass takes up where this one stopped without waking it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_the_host_cannot_record_is_read_again_and_an_announcement_before_it_wakes() {
    let rig = Rig::start().await;
    let refused = EnvelopeId::new(Uuid::from_bytes([0xf2; 16]));
    let record_file = rig
        .host
        .controller()
        .paths()
        .state_dir()
        .join(kr_controller::mailbox_reader::record::MAILBOX_REPLAY_RECORD);
    let database = rusqlite::Connection::open(&record_file).expect("the record");
    database
        .execute_batch(&format!(
            "CREATE TRIGGER refuse_one BEFORE INSERT ON mailbox_replay
             WHEN NEW.envelope_id = '{}'
             BEGIN SELECT RAISE(ABORT, 'the disk is full'); END;",
            refused.get()
        ))
        .expect("a trigger that refuses one identifier");
    rig.mailbox
        .deliver(
            rig.host_key(),
            &rig.sealed(
                &rig.owner.stored_envelope,
                MailboxPayloadType::AuthorityFeedChange,
                0xf1,
            ),
        )
        .await
        .expect("the service takes the announcement");
    rig.mailbox
        .deliver(
            rig.host_key(),
            &rig.sealed(
                &rig.owner.stored_envelope,
                MailboxPayloadType::StateReference,
                0xf2,
            ),
        )
        .await
        .expect("the service takes the item the host will not be able to write down");
    let woken = rig.feed_wakes();

    rig.the_reader_reads().await;

    assert_eq!(rig.items_held(), 2, "nothing on the page was acknowledged");
    assert_eq!(rig.reader().record().len().expect("the record"), 1);
    assert_eq!(
        rig.feed_wakes(),
        woken + 1,
        "the announcement that is on record woke the carrier"
    );
    let shown = rig.check().await;
    assert_eq!(shown.status, DoctorStatus::Warning, "{}", shown.detail());
    assert!(
        shown.detail().contains("write its record"),
        "{}",
        shown.detail()
    );

    database
        .execute_batch("DROP TRIGGER refuse_one;")
        .expect("the disk has room again");
    rig.timer.advance(Duration::from_secs(60));
    rig.timer.release_held();
    within("the page is taken and acknowledged", async {
        while rig.items_held() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(rig.reader().record().len().expect("the record"), 2);
    assert_eq!(
        rig.feed_wakes(),
        woken + 1,
        "the announcement read again is a replay and woke nothing"
    );
    assert_eq!(rig.check().await.status, DoctorStatus::Ok);
}

/// A record written by a build that reads a newer schema is refused before anything is written to
/// it, so that build still finds it as it left it.
#[test]
fn a_record_of_a_newer_schema_is_refused_before_anything_is_written() {
    use kr_controller::mailbox_reader::record::Record;

    let directory = kr_ipc::testing::PrivateTempDir::create();
    let path = directory.path().join("mailbox-replay.sqlite3");
    {
        let connection = rusqlite::Connection::open(&path).expect("a database");
        connection
            .execute_batch(
                "CREATE TABLE mailbox_replay_schema (version INTEGER NOT NULL);
                 INSERT INTO mailbox_replay_schema (version) VALUES (99);",
            )
            .expect("a newer schema");
    }
    assert!(Record::open(directory.path()).is_err());

    let connection = rusqlite::Connection::open(&path).expect("the database");
    let tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .expect("the tables");
    let version: i64 = connection
        .query_row("SELECT version FROM mailbox_replay_schema", [], |row| {
            row.get(0)
        })
        .expect("the version");
    assert_eq!((tables, version), (1, 99), "nothing was written");
}

/// An identifier is kept until the item's expiry and a day more, and not an instant longer.
#[test]
fn an_identifier_is_forgotten_a_day_after_the_item_would_have_expired() {
    use kr_controller::mailbox_reader::record::Record;

    let directory = kr_ipc::testing::PrivateTempDir::create();
    let record = Record::open(directory.path()).expect("a record");
    let id = EnvelopeId::new(Uuid::from_bytes([7; 16]));
    let expires = 1_800_000_000_000_u64;
    let until = kr_protocol::mailbox::replay_id_retained_until_ms(expires);
    assert_eq!(until, expires + 24 * 60 * 60 * 1000);
    record.remember(id, until).expect("written down");

    assert!(record.ledger(until - 1).expect("the ledger").contains(id));
    assert!(
        !record.ledger(until).expect("the ledger").contains(id),
        "past its retention it is forgotten"
    );
    assert!(
        record.is_empty().expect("the record"),
        "and it left the file"
    );
}
