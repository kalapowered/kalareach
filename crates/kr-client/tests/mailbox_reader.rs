//! Reading one's own mailbox: what an item has to pass to be taken, and what is written down before
//! the service is told it may remove the page.
//!
//! The service is the stand-in held to the Worker's source, the client is this crate's own
//! `MailboxClient`, and the reader is a small one of the test's own whose records are in memory:
//! what the pass does with the items the service offers is what is under test, not where a host or
//! a device keeps its records. Each reader of the product holds the same rules through its own
//! records, in the host's and the companion's suites.
//!
//! The rules are section 20's. An item opens only against the stored-envelope key of a sender the
//! reader has paired, the routing record outside it is untrusted and must match the box, an
//! identifier accepted before is refused until its retention has ended, and a payload that bears
//! authority is refused whoever sealed it. Each of those drops the item and leaves the service free
//! to remove it; what is accepted is written down first.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_client::mailbox_reader::{MOST_PAGES, Outcome, Page, Reading, Stop, read_mailbox};
use kr_client::services::ServiceSigner;
use kr_client::services::mailbox::{MAILBOX_ITEMS_PER_READ, MailboxClient};
use kr_crypto::envelope::{PairedSenders, ReplayLedger, seal_envelope};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair, key_id};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType, REPLAY_ID_RETENTION_MS, SealedEnvelope,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, Nullable, Signature64, StoredEnvelopeKey, TimestampMs, Uuid,
};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Moment, ServiceWeb};

const ACKNOWLEDGE: &str = "/api/mailbox/acknowledge";
const READ: &str = "/api/mailbox/read";

/// A device signing its requests to the service as an installation does.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl ServiceSigner for Installation {
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

/// The reader under test: whom it has paired, what it has written down, and what it was handed.
struct Reader {
    now: AtomicU64,
    paired: Mutex<Vec<StoredEnvelopeKey>>,
    senders_unreadable: Mutex<bool>,
    record: Mutex<BTreeMap<EnvelopeId, u64>>,
    /// The nth write from now on fails, counting the writes from one.
    failing_write: Mutex<Option<usize>>,
    /// The nth write never finishes: it says it was reached and waits for ever.
    holding_write: Mutex<Option<usize>>,
    reached: tokio::sync::Notify,
    writes: Mutex<usize>,
    handed: Mutex<Vec<Page>>,
}

impl Reader {
    fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
            paired: Mutex::new(Vec::new()),
            senders_unreadable: Mutex::new(false),
            record: Mutex::new(BTreeMap::new()),
            failing_write: Mutex::new(None),
            holding_write: Mutex::new(None),
            reached: tokio::sync::Notify::new(),
            writes: Mutex::new(0),
            handed: Mutex::new(Vec::new()),
        }
    }

    fn pairs_with(&self, key: &StoredEnvelopeKeyPair) {
        self.paired.lock().expect("paired").push(*key.public());
    }

    /// The identifiers written down so far.
    fn written(&self) -> Vec<EnvelopeId> {
        self.record
            .lock()
            .expect("record")
            .keys()
            .copied()
            .collect()
    }

    /// Every item handed over so far, by the number its identifier was made from.
    fn accepted_numbers(&self) -> Vec<u8> {
        self.handed
            .lock()
            .expect("handed")
            .iter()
            .flat_map(|page| page.accepted.iter())
            .map(|item| item.envelope_id.get().as_bytes()[0])
            .collect()
    }

    fn dropped(&self) -> usize {
        self.handed
            .lock()
            .expect("handed")
            .iter()
            .map(|page| page.dropped)
            .sum()
    }
}

/// A failure of the reader's own record.
#[derive(Debug, PartialEq, Eq)]
struct Unwritable;

impl Reading for Reader {
    type Error = Unwritable;

    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    async fn senders(&self) -> Result<PairedSenders, Unwritable> {
        if *self.senders_unreadable.lock().expect("flag") {
            return Err(Unwritable);
        }
        let mut senders = PairedSenders::new();
        for key in self.paired.lock().expect("paired").iter() {
            senders.pair(*key);
        }
        Ok(senders)
    }

    async fn ledger(&self, now_ms: u64) -> Result<ReplayLedger, Unwritable> {
        let mut held = self.record.lock().expect("record");
        held.retain(|_, until| *until > now_ms);
        Ok(ReplayLedger::restore(
            held.iter().map(|(id, until)| (*id, *until)),
        ))
    }

    async fn record(&self, id: EnvelopeId, retained_until_ms: u64) -> Result<(), Unwritable> {
        let nth = {
            let mut writes = self.writes.lock().expect("writes");
            *writes += 1;
            *writes
        };
        if *self.failing_write.lock().expect("failing") == Some(nth) {
            return Err(Unwritable);
        }
        if *self.holding_write.lock().expect("holding") == Some(nth) {
            self.reached.notify_one();
            std::future::pending::<()>().await;
        }
        self.record
            .lock()
            .expect("record")
            .insert(id, retained_until_ms);
        Ok(())
    }

    fn taken(&self, page: Page) {
        self.handed.lock().expect("handed").push(page);
    }
}

/// The service, the reader's mailbox on it, and the keys of the device that holds it.
struct Rig {
    web: Arc<ServiceWeb>,
    origin: GatewayOrigin,
    me: StoredEnvelopeKeyPair,
    /// The installation the reader signs its requests as: the one that claims the mailbox on its
    /// first read, so every pass is made as it.
    device: Arc<Installation>,
    reader: Reader,
    now: u64,
}

impl Rig {
    fn start() -> Self {
        let now = real_now();
        let web = Arc::new(ServiceWeb::new());
        Self {
            origin: GatewayOrigin::new(web.origin()).expect("an origin"),
            web,
            me: StoredEnvelopeKeyPair::generate().expect("a key pair"),
            device: Arc::new(Installation(
                AuthorisationKeyPair::generate().expect("a key pair"),
            )),
            reader: Reader::new(now),
            now,
        }
    }

    /// A client of the service signing as `installation`.
    fn client_as(&self, installation: Arc<Installation>) -> MailboxClient {
        MailboxClient::new(
            self.origin.clone(),
            Arc::clone(&self.web) as Arc<_>,
            installation,
        )
        .leaving_delays_to_the_caller()
    }

    /// The reader's own client.
    fn client(&self) -> MailboxClient {
        self.client_as(Arc::clone(&self.device))
    }

    /// A client that signs as an installation of its own, as each device that leaves an item does.
    fn writer(&self) -> MailboxClient {
        self.client_as(Arc::new(Installation(
            AuthorisationKeyPair::generate().expect("a key pair"),
        )))
    }

    /// One item from `from` to the reader, with an identifier made of `number`, expiring in half
    /// an hour of the rig's time.
    fn item(
        &self,
        from: &StoredEnvelopeKeyPair,
        kind: MailboxPayloadType,
        number: u8,
    ) -> SealedEnvelope {
        self.item_numbered(from, kind, [number; 16])
    }

    fn item_numbered(
        &self,
        from: &StoredEnvelopeKeyPair,
        kind: MailboxPayloadType,
        id: [u8; 16],
    ) -> SealedEnvelope {
        seal_envelope(
            from,
            self.me.public(),
            &EnvelopePlaintext {
                version: EnvelopeVersion::V1,
                envelope_id: EnvelopeId::new(Uuid::from_bytes(id)),
                sender_key_id: key_id(KeyPurpose::StoredEnvelope, from.public().as_bytes()),
                recipient_key_id: self.me.key_id(),
                payload_type: kind,
                created_at_ms: TimestampMs::new(self.now),
                expires_at_ms: TimestampMs::new(self.now + 30 * 60 * 1000),
                grant_id: Nullable::null(),
                environment_id: Nullable::null(),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                thread_id: Nullable::null(),
                payload: Bytes::new(vec![id[0]; 24]),
            },
        )
        .expect("a sealed item")
    }

    async fn deliver(&self, item: &SealedEnvelope) {
        self.writer()
            .deliver(self.me.public(), item)
            .await
            .expect("the service takes the item: it cannot read it");
    }

    fn held(&self) -> usize {
        self.web.mailbox_envelopes(self.me.public()).len()
    }

    async fn pass(&self) -> Result<Outcome, Stop<Unwritable>> {
        read_mailbox(&self.client(), &self.me, &self.reader).await
    }
}

fn real_now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

fn a_sender() -> StoredEnvelopeKeyPair {
    StoredEnvelopeKeyPair::generate().expect("a key pair")
}

/// KR-REQ-20.05: an item opens only against the key of a sender the reader has paired. A stranger's
/// item is dropped and the service is told it may remove it, and it leaves no identifier on record;
/// the item of a paired sender, on the same page, is taken.
#[tokio::test]
async fn kr_req_20_05_an_item_from_a_sender_the_reader_has_not_paired_with_is_dropped() {
    let rig = Rig::start();
    let friend = a_sender();
    let stranger = a_sender();
    rig.reader.pairs_with(&friend);
    rig.deliver(&rig.item(&stranger, MailboxPayloadType::StateReference, 1))
        .await;
    rig.deliver(&rig.item(&friend, MailboxPayloadType::StateReference, 2))
        .await;

    let outcome = rig.pass().await.expect("the pass reads through");

    assert_eq!(outcome, Outcome::ReadThrough);
    assert_eq!(rig.reader.accepted_numbers(), [2]);
    assert_eq!(rig.reader.dropped(), 1);
    assert_eq!(
        rig.reader.written().len(),
        1,
        "only the taken item is on record"
    );
    assert_eq!(rig.held(), 0, "the service may remove both");
}

/// KR-REQ-20.05: the routing record the service stores beside a ciphertext is untrusted and must
/// match what the box authenticated. A record whose expiry was rewritten, with the box intact, is
/// dropped; the same item as it was sealed is taken.
#[tokio::test]
async fn kr_req_20_05_a_routing_record_that_disagrees_with_the_box_is_dropped() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    let honest = rig.item(&friend, MailboxPayloadType::StateReference, 1);
    let mut altered = rig.item(&friend, MailboxPayloadType::StateReference, 2);
    altered.routing.expires_at_ms = TimestampMs::new(altered.routing.expires_at_ms.get() - 1_000);
    rig.deliver(&honest).await;
    rig.deliver(&altered).await;

    rig.pass().await.expect("the pass reads through");

    assert_eq!(rig.reader.accepted_numbers(), [1]);
    assert_eq!(rig.reader.dropped(), 1);
    assert_eq!(rig.held(), 0);
}

/// KR-REQ-20.05: an identifier the reader accepted is refused when the service offers the item
/// again, and is kept until the item's expiry and a day more. The first acknowledgement is lost, so
/// the service offers the item again at the next pass.
#[tokio::test]
async fn kr_req_20_05_an_item_accepted_once_is_refused_when_it_is_offered_again() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    let item = rig.item(&friend, MailboxPayloadType::StateReference, 1);
    rig.deliver(&item).await;
    rig.web.fail(ACKNOWLEDGE, 1, Moment::Before);

    assert!(matches!(rig.pass().await, Err(Stop::Service(_))));
    assert_eq!(
        rig.held(),
        1,
        "the service never heard that the reader has it"
    );
    assert_eq!(rig.reader.accepted_numbers(), [1]);

    rig.pass().await.expect("the next pass reads through");

    assert_eq!(
        rig.reader.accepted_numbers(),
        [1],
        "the item was taken once"
    );
    assert_eq!(
        rig.reader.dropped(),
        1,
        "the second sight of it is a replay"
    );
    assert_eq!(rig.held(), 0);
    let kept = rig.reader.record.lock().expect("record").clone();
    assert_eq!(
        kept.get(&EnvelopeId::new(Uuid::from_bytes([1; 16]))),
        Some(&(item.routing.expires_at_ms.get() + REPLAY_ID_RETENTION_MS)),
        "an identifier is kept until the item's expiry and a day more"
    );
}

/// KR-REQ-20.04: a payload that bears authority is refused whoever sealed it, and its identifier is
/// not recorded. The control is an item of a kind that bears none from the same sender, which is
/// taken.
#[tokio::test]
async fn kr_req_20_04_an_item_that_bears_authority_is_dropped_whoever_sealed_it() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    rig.deliver(&rig.item(&friend, MailboxPayloadType::SignedAuthorityObject, 1))
        .await;
    rig.deliver(&rig.item(&friend, MailboxPayloadType::StateReference, 2))
        .await;

    rig.pass().await.expect("the pass reads through");

    assert_eq!(rig.reader.accepted_numbers(), [2]);
    assert_eq!(rig.reader.dropped(), 1);
    assert_eq!(rig.reader.written().len(), 1);
    assert_eq!(rig.held(), 0);
}

/// KR-REQ-20.05: an item whose identifier was written down is never accepted again, even when the
/// pass that wrote it is dropped before it ends, as a caller's deadline drops it. The pass waits
/// for the write of the second item on the page and is dropped there: the first item is on record
/// and was not handed over, the page was not acknowledged, and the next pass refuses the first as a
/// replay and takes the second.
#[tokio::test]
async fn kr_req_20_05_an_item_written_before_a_pass_was_dropped_is_never_accepted_again() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    for number in 1..=2 {
        rig.deliver(&rig.item(&friend, MailboxPayloadType::StateReference, number))
            .await;
    }
    *rig.reader.holding_write.lock().expect("holding") = Some(2);

    tokio::select! {
        outcome = rig.pass() => panic!("the pass ended with its write held: {outcome:?}"),
        () = rig.reader.reached.notified() => {}
    }

    assert_eq!(rig.reader.written().len(), 1, "the first item is on record");
    assert!(
        rig.reader.accepted_numbers().is_empty(),
        "a dropped pass hands over nothing"
    );
    assert_eq!(rig.held(), 2, "nothing was acknowledged");
    *rig.reader.holding_write.lock().expect("holding") = None;

    rig.pass().await.expect("the next pass reads through");

    assert_eq!(
        rig.reader.accepted_numbers(),
        [2],
        "the first is a replay and the second is taken once"
    );
    assert_eq!(rig.reader.dropped(), 1);
    assert_eq!(rig.held(), 0);
}

/// Section 20 and section 9: what the reader accepted is written down before the service is told
/// the page may be removed. A write that fails ends the pass with nothing acknowledged; the items
/// before it were handed over; the next pass takes the item that could not be written, once, and
/// refuses the ones already on record.
#[tokio::test]
async fn a_write_that_fails_leaves_the_page_unacknowledged_and_the_item_is_read_again() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    for number in 1..=3 {
        rig.deliver(&rig.item(&friend, MailboxPayloadType::StateReference, number))
            .await;
    }
    *rig.reader.failing_write.lock().expect("failing") = Some(2);

    assert!(matches!(rig.pass().await, Err(Stop::Local(Unwritable))));

    assert_eq!(rig.held(), 3, "nothing on the page was acknowledged");
    assert_eq!(rig.web.requests_to(ACKNOWLEDGE), 0);
    assert_eq!(
        rig.reader.accepted_numbers(),
        [1],
        "what was on record was handed over, and no more"
    );

    *rig.reader.failing_write.lock().expect("failing") = None;
    rig.pass().await.expect("the next pass reads through");

    assert_eq!(rig.reader.accepted_numbers(), [1, 2, 3]);
    assert_eq!(rig.reader.dropped(), 1, "item 1 is refused as a replay");
    assert_eq!(rig.held(), 0);
}

/// A reader that cannot read the senders it has paired reads nothing: an empty set from a record
/// that could not be read would drop every item and tell the service to remove it.
#[tokio::test]
async fn a_reader_that_cannot_read_its_senders_asks_the_service_for_nothing() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    rig.deliver(&rig.item(&friend, MailboxPayloadType::StateReference, 1))
        .await;
    *rig.reader.senders_unreadable.lock().expect("flag") = true;

    assert!(matches!(rig.pass().await, Err(Stop::Local(Unwritable))));

    assert_eq!(rig.web.requests_to(READ), 0);
    assert_eq!(rig.held(), 1);
}

/// A mailbox that holds more than a pass reads is read in passes of `MOST_PAGES` pages, so one
/// that fills as fast as it is read does not hold a pass for ever; the next pass goes on.
#[tokio::test]
async fn a_pass_ends_at_the_page_bound_and_the_next_one_goes_on() {
    let rig = Rig::start();
    let friend = a_sender();
    rig.reader.pairs_with(&friend);
    // One writer may leave a mailbox 128 items, which is the bound itself, so two writers leave it
    // more.
    let per_pass = MOST_PAGES * usize::try_from(MAILBOX_ITEMS_PER_READ).expect("a count");
    let extra = 12;
    let (first, second) = (rig.writer(), rig.writer());
    for index in 0..per_pass + extra {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        let writer = if index % 2 == 0 { &first } else { &second };
        writer
            .deliver(
                rig.me.public(),
                &rig.item_numbered(&friend, MailboxPayloadType::StateReference, id),
            )
            .await
            .expect("the service takes the item");
    }
    assert_eq!(rig.held(), per_pass + extra);

    assert_eq!(rig.pass().await.expect("a pass"), Outcome::PageLimit);
    assert_eq!(rig.held(), extra);
    assert_eq!(rig.pass().await.expect("a pass"), Outcome::ReadThrough);
    assert_eq!(rig.held(), 0);
    assert_eq!(rig.reader.written().len(), per_pass + extra);
}
