//! The envelope round trip, against a deployment.
//!
//! Section 20 states what a mailbox envelope is and section 9 states what a mailbox does with one.
//! The two halves meet here: this device seals a real envelope, the deployment stores it, and this
//! device reads it back and opens it. Everything the deployment can see of an item is the routing
//! record, and the rules below are about what that record is allowed to decide.
//!
//! Nothing outside the box is trusted. The routing record selects the sender's key rather than
//! supplying one, so an item naming a sender this device has not paired with stops before any
//! decryption; the record has to match the fields inside the box; a replayed identifier is refused
//! by the reader's own ledger whatever the service says; and the bytes a mailbox counts are the
//! declared bucket rather than the length of the plaintext somebody padded to it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.04 | `kr_req_20_04_an_envelope_is_delivered_read_opened_and_acknowledged`, `kr_req_20_04_a_routing_record_that_disagrees_with_the_box_is_refused` |
//! | KR-REQ-20.05 | `kr_req_20_05_an_unpaired_sender_is_refused_before_anything_is_decrypted`, `kr_req_20_05_a_replayed_envelope_identifier_is_refused_by_the_reader` |
//! | KR-REQ-20.13 | `kr_req_20_13_a_mailbox_counts_the_declared_bucket_rather_than_the_plaintext` |
//! | KR-REQ-09.24 | `kr_req_09_24_an_item_acknowledged_twice_is_answered_the_same_way`, `kr_req_09_24_a_repeated_state_notification_replaces_the_one_it_supersedes`, `kr_req_09_24_a_mailbox_is_served_only_to_the_key_that_claimed_it` |
//! | KR-REQ-23.50 | `kr_req_23_50_a_credential_for_another_gateway_is_refused_by_the_service` |
//!
//! Those rows' acceptance owners are elsewhere; what these legs add is the half nothing had
//! before, which is that the contract holds against a deployment rather than against a mock.

use std::future::Future;
use std::sync::{Arc, Mutex};

use kr_client::services::mailbox::{
    MAILBOX_READ_PATH, MailboxAnswer, MailboxClaimAnswer, MailboxClient, MailboxDeliveryState,
};
use kr_crypto::envelope::{PairedSenders, ReplayLedger, open_delivered_envelope, seal_envelope};
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_crypto::sealed::answer_mailbox_claim;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvelopeId, MailboxThreadId};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, MAX_MAILBOX_ITEM_LIFETIME_MS, MailboxPayloadType,
    SealedEnvelope,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Nonce256, Nullable, StoredEnvelopeKey, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, ServiceRequestSigner,
    canonical_body_digest,
};
use kr_sync_integration::{Deployment, RunKey, fresh_uuid, now_ms, proved};

/// One run's mailboxes, and the two devices that use them.
///
/// Every key is made for the leg. The mailbox a leg reaches is therefore a mailbox that did not
/// exist before it and belongs to nobody else, and the credential that claims it is discarded when
/// the leg ends.
struct Mailboxes {
    deployment: Deployment,
    /// The device whose mailbox this is: the key it is addressed by.
    recipient: StoredEnvelopeKeyPair,
    /// A second mailbox, for the leg that needs two.
    spare: StoredEnvelopeKeyPair,
    /// The paired peer that seals to it.
    sender: StoredEnvelopeKeyPair,
    /// The credential the recipient reads and acknowledges with.
    reader: Arc<RunKey>,
    /// The credential the peer delivers with.
    reading: MailboxClient,
    writing: MailboxClient,
    /// The mailboxes this leg has delivered to, so that what it stored is given back.
    used: Mutex<Vec<StoredEnvelopeKey>>,
}

impl Mailboxes {
    /// The mailboxes this leg runs against, or nothing when this run was given no deployment.
    fn open() -> Option<Self> {
        let deployment = Deployment::from_environment()?;
        let reader = RunKey::installation();
        let writer = RunKey::installation();
        Some(Self {
            reading: deployment.mailbox(&reader),
            writing: deployment.mailbox(&writer),
            deployment,
            recipient: StoredEnvelopeKeyPair::generate().expect("the recipient's key"),
            spare: StoredEnvelopeKeyPair::generate().expect("a second recipient's key"),
            sender: StoredEnvelopeKeyPair::generate().expect("the peer's key"),
            reader,
            used: Mutex::new(Vec::new()),
        })
    }

    /// The paired set the recipient opens against: the one peer it has paired with.
    ///
    /// A key is selected from this set by the identifier the routing record names, and never
    /// supplied by the item, which is what makes an unpaired sender stop before a decryption.
    fn paired(&self) -> PairedSenders {
        let mut senders = PairedSenders::new();
        senders.pair(*self.sender.public());
        senders
    }

    /// One sealed item from the paired peer to `recipient`.
    fn sealed_to(
        &self,
        recipient: &StoredEnvelopeKeyPair,
        payload: &[u8],
        thread: Option<MailboxThreadId>,
    ) -> (EnvelopePlaintext, SealedEnvelope) {
        let sealed_at = now_ms();
        let plaintext = EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: EnvelopeId::new(fresh_uuid()),
            sender_key_id: self.sender.key_id(),
            recipient_key_id: kr_crypto::keys::key_id(
                KeyPurpose::StoredEnvelope,
                recipient.public().as_bytes(),
            ),
            payload_type: MailboxPayloadType::StateReference,
            created_at_ms: TimestampMs::new(sealed_at),
            // Well inside the day section 9 gives an item, so a clock a little out of step with
            // the deployment's is not what decides whether this leg passes.
            expires_at_ms: TimestampMs::new(sealed_at + MAX_MAILBOX_ITEM_LIFETIME_MS / 2),
            grant_id: Nullable(None),
            environment_id: Nullable(None),
            session_id: Nullable(None),
            session_epoch: Nullable(None),
            thread_id: Nullable(thread),
            payload: Bytes::new(payload.to_vec()),
        };
        let envelope =
            seal_envelope(&self.sender, recipient.public(), &plaintext).expect("a sealed item");
        (plaintext, envelope)
    }

    /// Delivers one item, recording the mailbox it went to so the leg can give it back.
    ///
    /// Recorded before the request rather than after it: a delivery whose answer never arrived may
    /// still have stored the item, and a mailbox this leg may have filled is one it has to drain.
    async fn deliver(
        &self,
        recipient: &StoredEnvelopeKey,
        envelope: &SealedEnvelope,
    ) -> kr_client::Result<kr_client::services::MailboxDelivery> {
        {
            let mut used = self.used.lock().expect("the mailboxes this leg used");
            if !used.contains(recipient) {
                used.push(*recipient);
            }
        }
        self.writing.deliver(recipient, envelope).await
    }

    /// The key pair for one of this leg's mailboxes.
    fn key_pair(&self, recipient: &StoredEnvelopeKey) -> &StoredEnvelopeKeyPair {
        if recipient == self.spare.public() {
            &self.spare
        } else {
            &self.recipient
        }
    }

    /// Acknowledges everything this leg delivered, so the service removes it.
    ///
    /// It is how a leg gives back what it took. Every mailbox this leg used is attempted, whatever
    /// happened to the one before it: a failure draining the first must not be why the second
    /// keeps its items. What is left over comes back as a list of what could not be emptied.
    ///
    /// What stays afterwards is the mailbox object with its claim and the replay identifiers of
    /// what was delivered, which section 20 retains until each item's expiry and a day: nothing a
    /// client is allowed to remove.
    async fn drain(&self) -> Vec<String> {
        let used = self
            .used
            .lock()
            .expect("the mailboxes this leg used")
            .clone();
        let mut left = Vec::new();
        for recipient in used {
            if let Err(what) = self.empty(&recipient).await {
                left.push(what);
            }
        }
        left
    }

    /// Empties one mailbox, or says why it is not empty.
    async fn empty(&self, recipient: &StoredEnvelopeKey) -> Result<(), String> {
        let keys = self.key_pair(recipient);
        // A mailbox holds at most 1,000 items and a page carries eight, so this many reads empties
        // a full one. A bound rather than a loop, so a service that always said there was more
        // ends the leg rather than holding it — and running out is a failure, not a quiet stop,
        // because the mailbox still has items in it.
        for _ in 0..200u32 {
            let page = self
                .reading
                .read_as(keys, None)
                .await
                .map_err(|error| format!("a mailbox could not be read: {error}"))?;
            if page.items.is_empty() {
                return Ok(());
            }
            self.reading
                .acknowledge(recipient, page.next_after_sequence.get())
                .await
                .map_err(|error| format!("a mailbox could not be acknowledged: {error}"))?;
        }
        Err("a mailbox still held items after every read this leg is allowed".to_owned())
    }
}

/// Runs one leg and gives back what it took, whether the leg passed or failed.
///
/// The leg's work runs as a task of its own, so a failed assertion ends that task rather than this
/// one: what the leg delivered is acknowledged either way and the failure is raised again
/// afterwards. A leg that panicked without acknowledging would leave items on the deployment until
/// they expired, because the only key that could read them is the one this run discards.
async fn leg<Body, Work>(body: Body)
where
    Body: FnOnce(Arc<Mailboxes>) -> Work + Send + 'static,
    Work: Future<Output = String> + Send + 'static,
{
    let Some(mailboxes) = Mailboxes::open() else {
        return;
    };
    let mailboxes = Arc::new(mailboxes);

    let outcome = tokio::spawn(body(Arc::clone(&mailboxes))).await;
    let left = mailboxes.drain().await;

    match outcome {
        Ok(what) => {
            assert!(
                left.is_empty(),
                "this leg did not give back what it took: {left:?}"
            );
            proved("mailbox", &mailboxes.deployment, &what);
        }
        Err(failed) => {
            for what in left {
                eprintln!("this leg could not give back what it took: {what}");
            }
            std::panic::resume_unwind(failed.into_panic());
        }
    }
}

/// KR-REQ-20.04: an envelope is sealed for one recipient, delivered, read by that recipient,
/// opened against the paired sender key and acknowledged.
#[tokio::test]
async fn kr_req_20_04_an_envelope_is_delivered_read_opened_and_acknowledged() {
    leg(|mailboxes| async move {
        let (plaintext, envelope) =
            mailboxes.sealed_to(&mailboxes.recipient, b"a reference to state", None);

        let delivery = mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the mailbox stored the item");
        assert_eq!(delivery.state, MailboxDeliveryState::Stored);
        assert_eq!(delivery.stored.items.get(), 1);

        // The first read of an unclaimed mailbox is answered with a challenge, and the recipient
        // is the device that can answer it. `read_as` is that exchange.
        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        assert_eq!(page.items.len(), 1);
        let item = &page.items[0];
        assert_eq!(item.sequence, delivery.sequence);
        assert_eq!(
            item.envelope, envelope,
            "the mailbox serves back the item that was sealed"
        );

        // Opened the way a device opens a delivered item: the routing record selects a key out of
        // the paired set, the box authenticates, and every field outside is held to the fields
        // inside.
        let mut ledger = ReplayLedger::new();
        let opened = open_delivered_envelope(
            &mailboxes.recipient,
            &mailboxes.paired(),
            &mut ledger,
            &item.envelope,
            now_ms(),
            |_| Ok(()),
        )
        .expect("the item opens against the paired sender");
        assert_eq!(opened, plaintext);
        assert_eq!(opened.payload.as_slice(), b"a reference to state");

        let settled = mailboxes
            .reading
            .acknowledge(mailboxes.recipient.public(), item.sequence.get())
            .await
            .expect("the recipient acknowledges what it stored");
        assert_eq!(settled.removed.get(), 1);
        assert_eq!(settled.stored.items.get(), 0);

        let after = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads again");
        assert!(
            after.items.is_empty(),
            "an acknowledgement removes what it covers"
        );

        "an envelope sealed by one device is delivered, read by the paired recipient, opened against the paired sender key and acknowledged".to_owned()
    })
    .await;
}

/// KR-REQ-20.04: routing metadata outside the encryption is untrusted and has to match the
/// decrypted fields, so a record that disagrees with the box is refused.
#[tokio::test]
async fn kr_req_20_04_a_routing_record_that_disagrees_with_the_box_is_refused() {
    leg(|mailboxes| async move {
        let (plaintext, sealed) = mailboxes.sealed_to(&mailboxes.recipient, b"a receipt", None);
        assert_eq!(plaintext.payload_type, MailboxPayloadType::StateReference);

        // The record says one thing and the box says another. The service cannot tell: everything
        // it checks without a key still holds, so this is a record it stores and serves back.
        let mut tampered = sealed;
        tampered.routing.payload_type = MailboxPayloadType::ActionReceipt;

        let delivery = mailboxes
            .deliver(mailboxes.recipient.public(), &tampered)
            .await
            .expect("the record is one the service admits");
        assert_eq!(delivery.state, MailboxDeliveryState::Stored);

        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        let item = &page.items[0];
        assert_eq!(
            item.envelope.routing.payload_type,
            MailboxPayloadType::ActionReceipt,
            "the service served back the record it was given"
        );

        let mut ledger = ReplayLedger::new();
        let refused = open_delivered_envelope(
            &mailboxes.recipient,
            &mailboxes.paired(),
            &mut ledger,
            &item.envelope,
            now_ms(),
            |_| Ok(()),
        )
        .expect_err("the record disagrees with the box");
        assert!(
            matches!(refused, kr_crypto::CryptoError::BindingMismatch { .. }),
            "{refused}"
        );
        assert!(
            ledger.is_empty(),
            "a refused item is not recorded as accepted"
        );

        "a routing record that names something other than what the box says is refused by the recipient, and the service that stored it could not have told".to_owned()
    })
    .await;
}

/// KR-REQ-20.05: decryption happens only against previously paired sender keys, so an item whose
/// record names a sender this device has not paired with stops before any decryption.
#[tokio::test]
async fn kr_req_20_05_an_unpaired_sender_is_refused_before_anything_is_decrypted() {
    leg(|mailboxes| async move {
        let (_, envelope) = mailboxes.sealed_to(&mailboxes.recipient, b"a reference", None);
        mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the mailbox stored the item");

        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        let item = &page.items[0];

        // A recipient that has paired with somebody else. The sender's key is not in its set, so
        // the identifier the record names selects nothing.
        let mut elsewhere = PairedSenders::new();
        elsewhere.pair(
            *StoredEnvelopeKeyPair::generate()
                .expect("another peer's key")
                .public(),
        );
        let mut ledger = ReplayLedger::new();
        let refused = open_delivered_envelope(
            &mailboxes.recipient,
            &elsewhere,
            &mut ledger,
            &item.envelope,
            now_ms(),
            |_| Ok(()),
        )
        .expect_err("that sender is not one this device has paired with");
        assert!(
            matches!(refused, kr_crypto::CryptoError::BindingMismatch { .. }),
            "{refused}"
        );

        // The same item, and the same reader, once the sender is paired: the difference is the
        // paired set and nothing else, which is what makes the refusal above about pairing.
        assert!(
            open_delivered_envelope(
                &mailboxes.recipient,
                &mailboxes.paired(),
                &mut ledger,
                &item.envelope,
                now_ms(),
                |_| Ok(()),
            )
            .is_ok(),
            "the same item opens once the sender is a paired one"
        );

        "an envelope whose routing record names a sender this device has not paired with is refused without a decryption attempt".to_owned()
    })
    .await;
}

/// KR-REQ-20.05: replay identifiers are kept until expiry and a day, so an item the recipient has
/// already accepted is refused however many times the service offers it back.
#[tokio::test]
async fn kr_req_20_05_a_replayed_envelope_identifier_is_refused_by_the_reader() {
    leg(|mailboxes| async move {
        let (plaintext, envelope) =
            mailboxes.sealed_to(&mailboxes.recipient, b"a reference", None);

        let first = mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the mailbox stored the item");
        assert_eq!(first.state, MailboxDeliveryState::Stored);

        // The service remembers the identifier as well: the same item under the same identifier is
        // the delivery that already happened rather than a second one.
        let again = mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the same delivery is answered with what the first was told");
        assert_eq!(again.state, MailboxDeliveryState::Duplicate);
        assert_eq!(again.sequence, first.sequence);
        assert_eq!(again.stored.items.get(), 1, "one item, not two");

        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        let item = &page.items[0];

        let mut ledger = ReplayLedger::new();
        let opened = open_delivered_envelope(
            &mailboxes.recipient,
            &mailboxes.paired(),
            &mut ledger,
            &item.envelope,
            now_ms(),
            |_| Ok(()),
        )
        .expect("the item opens the first time");
        assert_eq!(opened.envelope_id, plaintext.envelope_id);
        assert!(ledger.contains(plaintext.envelope_id));

        // The reader's own ledger is what refuses the second one. It would refuse it whatever the
        // service said, which is the point: the record of what has been accepted is the
        // recipient's, not the service's.
        let refused = open_delivered_envelope(
            &mailboxes.recipient,
            &mailboxes.paired(),
            &mut ledger,
            &item.envelope,
            now_ms(),
            |_| Ok(()),
        )
        .expect_err("that identifier has been accepted already");
        assert!(
            matches!(refused, kr_crypto::CryptoError::BindingMismatch { .. }),
            "{refused}"
        );

        "a replayed envelope identifier is refused by the recipient's own replay ledger, and the deployment answers a repeated delivery with the first one's position".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: quota accounting measures the complete stored ciphertext and envelope, which is
/// the declared size bucket rather than the length of the plaintext padded to it.
#[tokio::test]
async fn kr_req_20_13_a_mailbox_counts_the_declared_bucket_rather_than_the_plaintext() {
    leg(|mailboxes| async move {
        // Two plaintexts of very different lengths that round to the same bucket: section 20 pads
        // anything up to 16 KiB to a multiple of a kibibyte, and both of these are inside the
        // first one.
        let (small, small_sealed) = mailboxes.sealed_to(&mailboxes.recipient, b"x", None);
        let (large, large_sealed) = mailboxes.sealed_to(&mailboxes.spare, &vec![b'x'; 400], None);
        assert_ne!(
            small.payload.as_slice().len(),
            large.payload.as_slice().len()
        );
        assert_eq!(
            small_sealed.routing.size_bucket_bytes, large_sealed.routing.size_bucket_bytes,
            "two plaintexts in one band declare one bucket"
        );

        let first = mailboxes
            .deliver(mailboxes.recipient.public(), &small_sealed)
            .await
            .expect("the mailbox stored the smaller item");
        let second = mailboxes
            .deliver(mailboxes.spare.public(), &large_sealed)
            .await
            .expect("the mailbox stored the larger item");

        assert_eq!(
            first.stored.bytes, second.stored.bytes,
            "what a mailbox counts does not depend on how much of the bucket was used"
        );
        assert_eq!(
            first.stored.bytes.get(),
            small_sealed.stored_bytes(),
            "the figure is the stored ciphertext, the nonce and the routing record"
        );
        assert!(
            first.stored.bytes.get() > large.payload.as_slice().len() as u64,
            "and it is not the plaintext's own length"
        );
        assert_eq!(
            first.stored.byte_limit.get(),
            kr_protocol::mailbox::MAX_MAILBOX_BYTES
        );
        assert_eq!(
            first.stored.item_limit.get(),
            kr_protocol::mailbox::MAX_MAILBOX_ITEMS
        );

        "the bytes a mailbox counts are the declared size bucket with the nonce and the routing record, and not the length of the plaintext padded into it".to_owned()
    })
    .await;
}

/// KR-REQ-09.24: an acknowledgement is idempotent, so a recipient unsure whether its
/// acknowledgement arrived asks again rather than assuming.
#[tokio::test]
async fn kr_req_09_24_an_item_acknowledged_twice_is_answered_the_same_way() {
    leg(|mailboxes| async move {
        let (_, envelope) = mailboxes.sealed_to(&mailboxes.recipient, b"a reference", None);
        let delivery = mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the mailbox stored the item");

        // The claim is made by reading; only the reader that has claimed the mailbox may
        // acknowledge, so a caller that has not proved the mailbox is its own cannot delete from
        // it.
        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        assert_eq!(page.items.len(), 1);

        let first = mailboxes
            .reading
            .acknowledge(mailboxes.recipient.public(), delivery.sequence.get())
            .await
            .expect("the recipient acknowledges it");
        assert_eq!(first.removed.get(), 1);

        let repeated = mailboxes
            .reading
            .acknowledge(mailboxes.recipient.public(), delivery.sequence.get())
            .await
            .expect("the same acknowledgement again");
        assert_eq!(
            repeated.removed.get(),
            0,
            "the second removes nothing, because the first removed it"
        );
        assert_eq!(
            repeated.acknowledged_through, first.acknowledged_through,
            "and it reports the same position"
        );
        assert_eq!(repeated.stored.items.get(), 0);

        "an item acknowledged twice is answered idempotently: the second acknowledgement removes nothing and reports the position the first one did".to_owned()
    })
    .await;
}

/// KR-REQ-23.50: a service credential names the gateway it is for, so a request signed for another
/// gateway is refused whatever it carries.
#[tokio::test]
async fn kr_req_23_50_a_credential_for_another_gateway_is_refused_by_the_service() {
    leg(|mailboxes| async move {
        let elsewhere =
            GatewayOrigin::new("https://gateway.invalid").expect("an origin that is not this one");
        assert_ne!(elsewhere.as_str(), mailboxes.deployment.origin().as_str());

        // Built here rather than through the client, because the client signs for the gateway it
        // addresses and could not produce this. The request is otherwise complete: the body is one
        // the service reads, the digest covers it, the signature verifies under the key it names,
        // and the only thing wrong with it is the gateway the credential is for.
        let body = serde_json::json!({
            "recipient_key": mailboxes.recipient.public(),
            "limit": 1,
        });
        let payload = ServiceRequestPayload {
            body_digest: canonical_body_digest(&body).expect("a digest of the body"),
            gateway_origin: elsewhere,
            method: Method::MailboxRead,
            nonce: Nonce256::from_bytes({
                let mut bytes = [0u8; 32];
                kr_crypto::random_bytes(&mut bytes).expect("a nonce for this request");
                bytes
            }),
            signed_at_ms: TimestampMs::new(now_ms()),
        };
        let signer = ServiceRequestSigner::Installation;
        let request = serde_json::to_vec(&serde_json::json!({
            "body": body,
            "signature": ServiceRequestSignature {
                signature: kr_client::services::relay::ServiceSigner::sign(
                    mailboxes.reader.as_ref(),
                    &payload.signing_input(signer).expect("what the credential signs"),
                )
                .expect("a signature"),
                payload,
                signer,
                public_key: kr_client::services::relay::ServiceSigner::public_key(
                    mailboxes.reader.as_ref(),
                ),
            },
        }))
        .expect("a request this leg wrote");

        let answer = mailboxes
            .deployment
            .transport()
            .post_json(
                &format!(
                    "{}{MAILBOX_READ_PATH}",
                    mailboxes.deployment.origin().as_str()
                ),
                &request,
                &[],
            )
            .await
            .expect("the deployment answered");
        let envelope: serde_json::Value =
            serde_json::from_slice(&answer.body).expect("the service's own envelope");
        assert_eq!(
            envelope["ok"], false,
            "a credential for another gateway admits nothing"
        );
        assert_eq!(envelope["error"]["code"], "UNAUTHENTICATED");

        // And the same client against the gateway its credential names reads its own mailbox, so
        // the refusal above is about the gateway and not about the key.
        let admitted = mailboxes
            .reading
            .read(mailboxes.recipient.public(), None, None)
            .await
            .expect("the same key at the gateway it signed for");
        assert!(matches!(
            admitted,
            MailboxAnswer::ClaimRequired(_) | MailboxAnswer::Read(_)
        ));

        "a request signed for another gateway origin is refused by the service, and the same key is admitted at the gateway its credential names".to_owned()
    })
    .await;
}

/// KR-REQ-09.24: repeated state notifications coalesce by opaque thread identifier, and the
/// newest replaces the older unread one from the same writer.
#[tokio::test]
async fn kr_req_09_24_a_repeated_state_notification_replaces_the_one_it_supersedes() {
    leg(|mailboxes| async move {
        let thread = MailboxThreadId::new(fresh_uuid());
        let (_, first) = mailboxes.sealed_to(&mailboxes.recipient, b"waiting", Some(thread));
        let (_, second) = mailboxes.sealed_to(&mailboxes.recipient, b"still waiting", Some(thread));

        let stored = mailboxes
            .deliver(mailboxes.recipient.public(), &first)
            .await
            .expect("the mailbox stored the first");
        assert_eq!(stored.state, MailboxDeliveryState::Stored);
        assert_eq!(stored.replaced_sequence, Nullable(None));

        let coalesced = mailboxes
            .deliver(mailboxes.recipient.public(), &second)
            .await
            .expect("the mailbox stored the second");
        assert_eq!(coalesced.state, MailboxDeliveryState::Coalesced);
        assert_eq!(
            coalesced.replaced_sequence,
            Nullable(Some(stored.sequence)),
            "it says which unread item it replaced"
        );
        assert_eq!(coalesced.stored.items.get(), 1, "one item, not two");

        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0].envelope.routing.envelope_id,
            second.routing.envelope_id,
            "what is waiting is the newest one"
        );

        "a repeated state notification on one thread replaces the older unread one from the same writer, and the mailbox says which position it replaced".to_owned()
    })
    .await;
}

/// KR-REQ-09.24: a mailbox is read by the key that proved it is its own, so a peer that holds the
/// recipient's public key is refused rather than served.
#[tokio::test]
async fn kr_req_09_24_a_mailbox_is_served_only_to_the_key_that_claimed_it() {
    leg(|mailboxes| async move {
        let (_, envelope) = mailboxes.sealed_to(&mailboxes.recipient, b"a reference", None);
        mailboxes
            .deliver(mailboxes.recipient.public(), &envelope)
            .await
            .expect("the mailbox stored the item");

        // A peer that knows the public key the mailbox is addressed by — which every paired peer
        // does, because it is what they seal to — and holds a credential of its own. It asks
        // first, before anybody has claimed the mailbox, which is the case that matters: a service
        // that gave an unclaimed mailbox to its first authenticated reader would serve this one.
        let peer = RunKey::installation();
        let peers_client = mailboxes.deployment.mailbox(&peer);
        let challenged = peers_client
            .read(mailboxes.recipient.public(), None, None)
            .await
            .expect("an unclaimed mailbox hands out a challenge");
        let MailboxAnswer::ClaimRequired(required) = challenged else {
            panic!("an unclaimed mailbox was served to a key that proved nothing");
        };

        // And it answers with everything it could possibly have: the challenge's own key, and the
        // agreement of that key with a key of its own. What it does not have is the private half
        // the mailbox is addressed by, which is the whole of what the challenge asks for.
        let guess = MailboxClaimAnswer {
            ephemeral_key: required.challenge.ephemeral_key,
            claim_value: answer_mailbox_claim(
                &StoredEnvelopeKeyPair::generate().expect("a key of the peer's own"),
                &required.challenge.ephemeral_key,
            )
            .expect("a value the peer can derive"),
        };
        let wrong = peers_client
            .read(mailboxes.recipient.public(), None, Some(&guess))
            .await
            .expect("the service answered");
        assert!(
            matches!(wrong, MailboxAnswer::ClaimRequired(_)),
            "a wrong answer claims nothing and is served nothing"
        );

        // Now the recipient, which can answer, claims it and is served.
        let page = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads its own mailbox");
        assert_eq!(page.items.len(), 1);

        let refused = peers_client
            .read(mailboxes.recipient.public(), None, None)
            .await
            .expect_err("that mailbox belongs to another key");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);

        let cannot_delete = peers_client
            .acknowledge(mailboxes.recipient.public(), page.next_after_sequence.get())
            .await
            .expect_err("and it cannot delete from it either");
        assert_eq!(cannot_delete.code(), ErrorCode::PermissionDenied);

        let still_there = mailboxes
            .reading
            .read_as(&mailboxes.recipient, None)
            .await
            .expect("the recipient reads it again");
        assert_eq!(
            still_there.items.len(),
            1,
            "nothing the other key asked for removed anything"
        );

        "an unclaimed mailbox is served to nobody who cannot answer its challenge, and once the recipient has answered it a peer that knows the key it is addressed by can neither read it nor delete from it".to_owned()
    })
    .await;
}
