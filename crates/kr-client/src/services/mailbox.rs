//! The encrypted mailbox's client.
//!
//! Section 9 gives the mailbox a narrow job: it stores notifications, state references, action
//! receipts, settings and drafts, encrypted, until a device reads them. It queues no keystroke, no
//! shell command, no approval decision and no session closure, and it is not a way to reach a
//! host. What a device leaves here executes nothing.
//!
//! This module carries `mailbox.deliver`, `mailbox.read` and `mailbox.acknowledge` over
//! [`SignedService`]. It seals nothing and opens nothing: [`kr_crypto::envelope`] produces and
//! opens envelopes, and this carries them.
//!
//! # Which mailbox a call reaches
//!
//! A mailbox is addressed by the identifier of the recipient's stored-envelope key, and the
//! service derives that identifier from the key the request names rather than accepting one. So a
//! caller says which mailbox it means by naming a key, and cannot point at a mailbox whose key it
//! does not hold.
//!
//! # Who may read one
//!
//! Every paired peer of a recipient knows that public key: it is what they seal to. Possession of
//! the private half is therefore what distinguishes the recipient, and the first read of an
//! unclaimed mailbox is answered with an X25519 challenge rather than with items.
//! [`MailboxClient::read_as`] answers it with [`kr_crypto::sealed::answer_mailbox_claim`] and
//! reads once more; the private key stays in the caller's own key pair and nothing derived from it
//! but that one value leaves this device.
//!
//! The claim settles on the key that answered, which is the key that signs the credential. A
//! mailbox is therefore read and acknowledged by one device, and a peer that holds the recipient's
//! public key is refused rather than served.
//!
//! # What is never rendered
//!
//! A delivery carries a sealed item, a page carries the items it read, and a claim answer is a
//! proof of possession. Under this module's rule none of them is rendered: each type here writes
//! its own [`std::fmt::Debug`] naming what the item is and how large it is, and nothing it
//! carries.

use std::fmt;
use std::sync::Arc;

use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_protocol::error::ErrorCode;
use kr_protocol::mailbox::{MAX_MAILBOX_ITEM_BYTES, SealedEnvelope};
use kr_protocol::method::Method;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Digest256, Nullable, StoredEnvelopeKey, U64};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{SignedService, malformed, unreadable_answer};
use crate::error::{ClientError, Result};

/// The route every mailbox method is served under.
pub const MAILBOX_ROUTE_PREFIX: &str = "/api/mailbox";

/// Where one sealed item is placed.
pub const MAILBOX_DELIVER_PATH: &str = "/api/mailbox/deliver";

/// Where a recipient reads its own mailbox.
pub const MAILBOX_READ_PATH: &str = "/api/mailbox/read";

/// Where a recipient says what it has stored durably.
pub const MAILBOX_ACKNOWLEDGE_PATH: &str = "/api/mailbox/acknowledge";

/// The most bytes one signed mailbox request may be.
///
/// It is what the service admits for the whole request, credential included. A delivery is what
/// reaches it: one item is at most [`MAX_MAILBOX_ITEM_BYTES`] stored and travels as base64, which
/// costs a third on top. This client refuses a request past the bound rather than sending one the
/// service stops reading part way through.
pub const MAX_MAILBOX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// How many items one read of a mailbox asks for.
///
/// The count is the client's, not the service's default, because the bound an answer is read under
/// has to cover the page that was asked for. Eight is the compromise the two bounds leave: a
/// mailbox holds at most 32 MiB, so a mailbox full of the largest items a section 9 control
/// message may be is drained in a handful of reads, and a mailbox of ordinary notifications is
/// drained in one.
pub const MAILBOX_ITEMS_PER_READ: u32 = 8;

/// How many bytes of a mailbox answer this client reads.
///
/// One read returns at most [`MAILBOX_ITEMS_PER_READ`] items; one item is at most
/// [`MAX_MAILBOX_ITEM_BYTES`] stored, and the ciphertext and the nonce travel as base64 at four
/// bytes for three, with the routing record and the JSON around them on top. Eight kibibytes an
/// item covers that record, which is a closed schema of two identifiers, two key identifiers, a
/// timestamp, a payload kind, an optional thread and a counter, and
/// `the_bound_an_answer_is_read_under_covers_the_page_this_client_asks_for` holds this constant to
/// that arithmetic. It is far above [`super::http::DEFAULT_RESPONSE_LIMIT_BYTES`], which is why a
/// transport that carries this client states it for this path.
pub const MAILBOX_ANSWER_LIMIT_BYTES: u64 = 12 * 1024 * 1024;

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// Place one sealed envelope in a recipient's mailbox.
#[derive(Serialize)]
struct DeliverBody<'a> {
    recipient_key: &'a StoredEnvelopeKey,
    envelope: &'a SealedEnvelope,
}

impl fmt::Debug for DeliverBody<'_> {
    /// What the item is and how large it is. Never the ciphertext, the nonce or the keys.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliverBody")
            .field("payload_type", &self.envelope.routing.payload_type)
            .field(
                "size_bucket_bytes",
                &self.envelope.routing.size_bucket_bytes,
            )
            .finish_non_exhaustive()
    }
}

/// Read a recipient's own mailbox from a cursor.
#[derive(Serialize)]
struct ReadBody<'a> {
    recipient_key: &'a StoredEnvelopeKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_sequence: Option<U64>,
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<&'a MailboxClaimAnswer>,
}

impl fmt::Debug for ReadBody<'_> {
    /// Where the read starts and how much it asks for. Never the claim, which is a proof of
    /// possession, and never the key the mailbox is addressed by.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadBody")
            .field("after_sequence", &self.after_sequence)
            .field("limit", &self.limit)
            .field("claimed", &self.claim.is_some())
            .finish_non_exhaustive()
    }
}

/// Acknowledge what the recipient has stored durably, so the service may remove it.
#[derive(Debug, Serialize)]
struct AcknowledgeBody<'a> {
    recipient_key: &'a StoredEnvelopeKey,
    through_sequence: U64,
}

/// The answer to one mailbox claim challenge.
///
/// It names the challenge it answers, so an answer cannot be presented against another one, and it
/// carries the value derived from the agreement of the two keys.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MailboxClaimAnswer {
    /// The ephemeral key the challenge named.
    pub ephemeral_key: StoredEnvelopeKey,
    /// The value the protocol derives from the agreement of that key with the recipient's own.
    pub claim_value: Digest256,
}

impl fmt::Debug for MailboxClaimAnswer {
    /// Which challenge it answers. Never the value, which is what proves the mailbox is this
    /// device's own.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxClaimAnswer")
            .field("ephemeral_key", &self.ephemeral_key)
            .finish_non_exhaustive()
    }
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// What became of one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxDeliveryState {
    /// The item is in the mailbox.
    Stored,
    /// That envelope identifier has already carried this item.
    Duplicate,
    /// The item is in the mailbox and replaced an unread item of the same thread.
    Coalesced,
}

/// What one device's mailbox holds and what it may hold.
///
/// Quota accounting measures the complete stored ciphertext and envelope rather than the unpadded
/// plaintext, so a sender cannot store more by padding less.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxUsage {
    /// How many items are stored.
    pub items: U64,
    /// How many bytes they occupy.
    pub bytes: U64,
    /// The most items this mailbox holds.
    pub item_limit: U64,
    /// The most bytes this mailbox holds.
    pub byte_limit: U64,
}

/// What `mailbox.deliver` answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDelivery {
    /// Whether the item was stored, already there, or replaced an unread one.
    pub state: MailboxDeliveryState,
    /// The position the item was given, or the position the first delivery was given.
    pub sequence: U64,
    /// The position of the unread item this one replaced, when it replaced one.
    pub replaced_sequence: Nullable<U64>,
    /// How the mailbox stands after the delivery.
    pub stored: MailboxUsage,
}

/// The challenge a read of an unclaimed mailbox is answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxChallenge {
    /// The service's ephemeral X25519 public key, for this challenge and for no other.
    pub ephemeral_key: StoredEnvelopeKey,
    /// When the challenge stops being answerable, in UTC milliseconds.
    pub expires_at_ms: U64,
}

/// What a read is answered with while the mailbox is unclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxClaimRequired {
    /// The challenge to answer.
    pub challenge: MailboxChallenge,
}

/// One stored item, as a reader receives it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxItem {
    /// Its position in this mailbox's order. Cursors are positions, never times.
    pub sequence: U64,
    /// When the service stored it, in UTC milliseconds.
    pub stored_at_ms: U64,
    /// The sealed item, exactly as it was delivered.
    pub envelope: SealedEnvelope,
}

impl fmt::Debug for MailboxItem {
    /// Where the item sits, what it is and how large it is. Never the ciphertext, the nonce or the
    /// keys the routing record names.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxItem")
            .field("sequence", &self.sequence)
            .field("payload_type", &self.envelope.routing.payload_type)
            .field(
                "size_bucket_bytes",
                &self.envelope.routing.size_bucket_bytes,
            )
            .finish_non_exhaustive()
    }
}

/// What `mailbox.read` answers once the reader has proved the mailbox is its own.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxPage {
    /// The items this page carries, oldest first.
    pub items: Vec<MailboxItem>,
    /// The cursor to continue from, which is the position of the last item returned.
    pub next_after_sequence: U64,
    /// Whether more items were waiting than this page carried.
    pub more: bool,
    /// How the mailbox stands.
    pub stored: MailboxUsage,
}

impl fmt::Debug for MailboxPage {
    /// How much came back and where it stands. Never an item, because an item carries a sealed
    /// payload.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxPage")
            .field("items", &self.items.len())
            .field("next_after_sequence", &self.next_after_sequence)
            .field("more", &self.more)
            .field("stored", &self.stored)
            .finish_non_exhaustive()
    }
}

/// What `mailbox.read` answers: the items, or the challenge to answer before them.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MailboxAnswer {
    /// The mailbox is unclaimed and this is the challenge that claims it.
    ClaimRequired(MailboxClaimRequired),
    /// The mailbox is this reader's own, and this is a page of it.
    Read(MailboxPage),
}

/// What `mailbox.acknowledge` answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAcknowledgement {
    /// How many items the acknowledgement removed.
    pub removed: U64,
    /// The position the recipient has acknowledged through.
    pub acknowledged_through: U64,
    /// How the mailbox stands afterwards.
    pub stored: MailboxUsage,
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// The encrypted mailbox's client.
#[derive(Clone, Debug)]
pub struct MailboxClient {
    call: SignedService,
}

impl MailboxClient {
    /// Builds a client against one gateway.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            call: SignedService::new(origin, http, signer),
        }
    }

    /// The gateway this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        self.call.origin()
    }

    /// Places one sealed envelope in a recipient's mailbox.
    ///
    /// The envelope's routing record has to name the mailbox this delivery is addressed to. The
    /// service checks that as well and refuses a mismatch; refusing it here is what stops a client
    /// spending an upload to be told something it could work out from the two values it holds.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope is routed to another recipient, when it is larger than
    /// one stored item may be, when the service refuses it, and when the exchange or the answer
    /// failed.
    pub async fn deliver(
        &self,
        recipient_key: &StoredEnvelopeKey,
        envelope: &SealedEnvelope,
    ) -> Result<MailboxDelivery> {
        let addressed =
            kr_crypto::keys::key_id(KeyPurpose::StoredEnvelope, recipient_key.as_bytes());
        if envelope.routing.recipient_key_id != addressed {
            return Err(malformed(
                "that envelope is routed to a mailbox other than the one this delivery names",
            ));
        }
        let stored = envelope.stored_bytes();
        if stored > MAX_MAILBOX_ITEM_BYTES {
            return Err(malformed(format!(
                "one stored item is at most {MAX_MAILBOX_ITEM_BYTES} bytes and this one is {stored}"
            )));
        }

        let data = self
            .call
            .call(
                MAILBOX_DELIVER_PATH,
                Method::MailboxDeliver,
                &DeliverBody {
                    recipient_key,
                    envelope,
                },
                MAX_MAILBOX_REQUEST_BYTES,
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what a delivery answered", &error))
    }

    /// Reads one page of a mailbox, answering a claim challenge with the given answer.
    ///
    /// This is the call itself. [`Self::read_as`] is what a recipient holding its own key uses:
    /// it derives the answer rather than being handed one.
    ///
    /// # Errors
    ///
    /// Returns an error when the cursor is not a position a mailbox issues, when the service
    /// refuses it, and when the exchange or the answer failed.
    pub async fn read(
        &self,
        recipient_key: &StoredEnvelopeKey,
        after_sequence: Option<u64>,
        claim: Option<&MailboxClaimAnswer>,
    ) -> Result<MailboxAnswer> {
        if let Some(cursor) = after_sequence {
            a_position(cursor)?;
        }
        let data = self
            .call
            .call(
                MAILBOX_READ_PATH,
                Method::MailboxRead,
                &ReadBody {
                    recipient_key,
                    after_sequence: after_sequence.map(U64::new),
                    limit: MAILBOX_ITEMS_PER_READ,
                    claim,
                },
                MAX_MAILBOX_REQUEST_BYTES,
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what a read answered", &error))
    }

    /// Reads one page of the mailbox `recipient` is addressed by, claiming it when it is unclaimed.
    ///
    /// A mailbox is addressed by a key every paired peer knows, so the first read is answered with
    /// a challenge instead of items. This answers it from the private half and reads once more.
    ///
    /// Once, and not in a loop. A second challenge means the claim this read answered is not the
    /// one the mailbox now holds: the challenge lives five minutes and another read replaces it,
    /// so the mailbox handed out a newer one while this exchange was in flight. A mailbox another
    /// key holds is not this case; that is refused rather than challenged.
    ///
    /// # Errors
    ///
    /// Returns an error when the challenge cannot be answered, when the second read is answered
    /// with a challenge again, when the service refuses it, and when the exchange or the answer
    /// failed.
    pub async fn read_as(
        &self,
        recipient: &StoredEnvelopeKeyPair,
        after_sequence: Option<u64>,
    ) -> Result<MailboxPage> {
        let answer = self.read(recipient.public(), after_sequence, None).await?;
        let required = match answer {
            MailboxAnswer::Read(page) => return Ok(page),
            MailboxAnswer::ClaimRequired(required) => required,
        };

        let claim = MailboxClaimAnswer {
            ephemeral_key: required.challenge.ephemeral_key,
            // The failure names the agreement that could not be taken and nothing of the key.
            claim_value: kr_crypto::sealed::answer_mailbox_claim(
                recipient,
                &required.challenge.ephemeral_key,
            )
            .map_err(|_| {
                malformed("the challenge this mailbox handed back is one no key agrees with")
            })?,
        };

        match self
            .read(recipient.public(), after_sequence, Some(&claim))
            .await?
        {
            MailboxAnswer::Read(page) => Ok(page),
            // Transient, and deliberately not a refusal. Nothing about this device needs
            // changing: the challenge that was answered is no longer the one the mailbox holds,
            // and the same call made again is answered with the current one. It is the class
            // this module already gives a managed service that did not answer what the call
            // needed, so `retry` waits and asks again rather than sending a person to their
            // settings.
            MailboxAnswer::ClaimRequired(_) => {
                Err(ClientError::Host(kr_protocol::error::ProtocolError::new(
                    ErrorCode::UpstreamUnavailable,
                    "this mailbox handed out a newer challenge than the one this read answered"
                        .to_owned(),
                )))
            }
        }
    }

    /// Says what the recipient has stored durably, so the service may remove it.
    ///
    /// Every item up to and including `through_sequence` is removed. An item delivered after the
    /// read being acknowledged has a higher position, so it is not removed by an acknowledgement
    /// that never saw it. Only the reader that claimed the mailbox may acknowledge.
    ///
    /// # Errors
    ///
    /// Returns an error when the position is not one a mailbox issues, when the service refuses
    /// it, and when the exchange or the answer failed.
    pub async fn acknowledge(
        &self,
        recipient_key: &StoredEnvelopeKey,
        through_sequence: u64,
    ) -> Result<MailboxAcknowledgement> {
        a_position(through_sequence)?;
        let data = self
            .call
            .call(
                MAILBOX_ACKNOWLEDGE_PATH,
                Method::MailboxAcknowledge,
                &AcknowledgeBody {
                    recipient_key,
                    through_sequence: U64::new(through_sequence),
                },
                MAX_MAILBOX_REQUEST_BYTES,
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what an acknowledgement answered", &error))
    }
}

/// The largest position a mailbox issues.
///
/// The service counts positions in whole numbers its own arithmetic carries exactly, and refuses
/// a cursor or an acknowledgement past that. This client refuses one first, so a caller that
/// carried a figure from somewhere else is told which rule it broke rather than being answered
/// with a refusal about a mailbox.
pub const MAX_MAILBOX_POSITION: u64 = (1 << 53) - 1;

/// Refuses a position no mailbox could have issued, before anything is sent.
fn a_position(sequence: u64) -> Result<()> {
    if sequence > MAX_MAILBOX_POSITION {
        return Err(malformed(format!(
            "a mailbox position is at most {MAX_MAILBOX_POSITION} and this one is {sequence}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::{Step, UserAction};
    use crate::services::ServiceFuture;
    use crate::services::relay::ServiceHttpAnswer;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};
    use kr_crypto::envelope::seal_envelope;
    use kr_protocol::ids::EnvelopeId;
    use kr_protocol::mailbox::{
        EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType, SEAL_OVERHEAD_BYTES,
    };
    use kr_protocol::scalars::{AuthorisationKey, Bytes, Nonce192, Signature64, TimestampMs, Uuid};
    use kr_protocol::service::ServiceRequestSigner;
    use std::sync::Mutex;

    /// A service that records what it was sent and answers with what it was told to.
    ///
    /// It holds whole signed requests, so it writes its own [`fmt::Debug`] like everything else in
    /// this module: a derived one would print those bytes as decimals, which is the same
    /// disclosure the module's rule is about and is not excused by being a test double.
    struct Recorder {
        sent: Mutex<Vec<(String, Vec<u8>)>>,
        answers: Mutex<Vec<ServiceHttpAnswer>>,
    }

    impl fmt::Debug for Recorder {
        /// How many requests it has taken. Never one of them.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("Recorder")
                .field("requests", &self.requests())
                .finish_non_exhaustive()
        }
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                answers: Mutex::new(Vec::new()),
            })
        }

        /// The answers this service gives, in order. The last one is repeated once they run out.
        fn answering(&self, bodies: Vec<serde_json::Value>) {
            *self.answers.lock().expect("the answers") = bodies
                .into_iter()
                .map(|body| ServiceHttpAnswer {
                    status: 200,
                    body: serde_json::to_vec(&body).expect("an answer"),
                })
                .collect();
        }

        fn last(&self) -> (String, serde_json::Value) {
            let sent = self.sent.lock().expect("what was sent");
            let (url, body) = sent.last().expect("one request").clone();
            (
                url,
                serde_json::from_slice(&body).expect("a request this client wrote"),
            )
        }

        fn requests(&self) -> usize {
            self.sent.lock().expect("what was sent").len()
        }
    }

    impl ServiceHttp for Recorder {
        fn post_json<'a>(
            &'a self,
            url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            assert!(
                headers.is_empty(),
                "a signed request sends no extra headers"
            );
            self.sent
                .lock()
                .expect("what was sent")
                .push((url.to_owned(), body.to_vec()));
            let mut answers = self.answers.lock().expect("the answers");
            let answer = if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers.first().expect("an answer").clone()
            };
            Box::pin(async move { Ok(answer) })
        }
    }

    /// One device's authorisation key, held the way a client holds one.
    #[derive(Debug)]
    struct Device {
        pair: kr_crypto::keys::AuthorisationKeyPair,
    }

    impl Device {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                pair: kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key pair"),
            })
        }
    }

    impl ServiceSigner for Device {
        fn signer(&self) -> ServiceRequestSigner {
            ServiceRequestSigner::Installation
        }

        fn public_key(&self) -> AuthorisationKey {
            *self.pair.public()
        }

        fn sign(&self, message: &[u8]) -> Result<Signature64> {
            let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
                ServiceRequestSigner::Installation.domain(),
                message.to_vec(),
            )
            .expect("a domain-tagged transcript");
            Ok(kr_crypto::sign::sign(&self.pair, &transcript).expect("a signature"))
        }
    }

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn mailbox_client() -> (MailboxClient, Arc<Recorder>) {
        let recorder = Recorder::new();
        let client = MailboxClient::new(
            origin(),
            Arc::clone(&recorder) as Arc<_>,
            Device::new() as Arc<_>,
        );
        (client, recorder)
    }

    /// The usage every answer below reports, which no assertion here is about.
    fn usage() -> serde_json::Value {
        serde_json::json!({
            "items": "1",
            "bytes": "1304",
            "item_limit": "1000",
            "byte_limit": "33554432",
        })
    }

    /// One sealed item from `sender` to `recipient`, of the smallest bucket.
    fn sealed(
        sender: &StoredEnvelopeKeyPair,
        recipient: &StoredEnvelopeKeyPair,
        payload: &[u8],
    ) -> SealedEnvelope {
        let now = 1_800_000_000_000;
        let plaintext = EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: EnvelopeId::new(Uuid::from_bytes([0x5a; 16])),
            sender_key_id: sender.key_id(),
            recipient_key_id: kr_crypto::keys::key_id(
                KeyPurpose::StoredEnvelope,
                recipient.public().as_bytes(),
            ),
            payload_type: MailboxPayloadType::StateReference,
            created_at_ms: TimestampMs::new(now),
            expires_at_ms: TimestampMs::new(now + 60 * 60 * 1000),
            grant_id: Nullable(None),
            environment_id: Nullable(None),
            session_id: Nullable(None),
            session_epoch: Nullable(None),
            thread_id: Nullable(None),
            payload: Bytes::new(payload.to_vec()),
        };
        seal_envelope(sender, recipient.public(), &plaintext).expect("a sealed item")
    }

    #[test]
    fn the_bound_an_answer_is_read_under_covers_the_page_this_client_asks_for() {
        // Base64 costs four bytes for every three, and eight kibibytes an item covers the routing
        // record and the JSON around it. A bound under this figure would make a mailbox holding
        // items of the largest size a control message may be unreadable by this client.
        let per_item = MAX_MAILBOX_ITEM_BYTES * 4 / 3 + 8 * 1024;
        let page = per_item * u64::from(MAILBOX_ITEMS_PER_READ);
        assert!(
            MAILBOX_ANSWER_LIMIT_BYTES >= page,
            "a page of {MAILBOX_ITEMS_PER_READ} items needs {page} bytes and the bound is {MAILBOX_ANSWER_LIMIT_BYTES}"
        );
        const {
            assert!(MAILBOX_ANSWER_LIMIT_BYTES > super::super::http::DEFAULT_RESPONSE_LIMIT_BYTES);
        }
    }

    #[tokio::test]
    async fn a_delivery_names_the_mailbox_the_envelope_is_routed_to() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let elsewhere = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let envelope = sealed(&sender, &recipient, b"a notification");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![serde_json::json!({
            "ok": true,
            "data": {
                "state": "stored",
                "sequence": "1",
                "replaced_sequence": null,
                "stored": usage(),
            },
        })]);

        let refused = client
            .deliver(elsewhere.public(), &envelope)
            .await
            .expect_err("that mailbox is not where it is routed");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(recorder.requests(), 0, "nothing left this device");

        let delivery = client
            .deliver(recipient.public(), &envelope)
            .await
            .expect("the mailbox it is routed to");
        assert_eq!(delivery.state, MailboxDeliveryState::Stored);
        assert_eq!(delivery.sequence.get(), 1);
        let (url, body) = recorder.last();
        assert_eq!(url, format!("https://reach.kala.to{MAILBOX_DELIVER_PATH}"));
        assert_eq!(
            body["body"]["recipient_key"],
            serde_json::to_value(recipient.public()).expect("a key")
        );
        assert_eq!(body["signature"]["payload"]["method"], "mailbox.deliver");
    }

    #[tokio::test]
    async fn an_item_larger_than_one_stored_item_may_be_never_leaves_this_device() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let mut envelope = sealed(&sender, &recipient, b"a notification");
        // The ciphertext a bucket that large would produce, without paying to seal one.
        let oversize = usize::try_from(MAX_MAILBOX_ITEM_BYTES).expect("a size this machine holds");
        envelope.ciphertext = Bytes::new(vec![0u8; oversize]);
        envelope.routing.size_bucket_bytes = U64::new(MAX_MAILBOX_ITEM_BYTES - SEAL_OVERHEAD_BYTES);

        let (client, recorder) = mailbox_client();
        let refused = client
            .deliver(recipient.public(), &envelope)
            .await
            .expect_err("that is larger than one item may be");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(recorder.requests(), 0, "nothing left this device");
    }

    #[tokio::test]
    async fn a_first_read_answers_the_challenge_from_the_key_the_mailbox_is_addressed_by() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let ephemeral = StoredEnvelopeKeyPair::generate().expect("the service's challenge key");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![
            serde_json::json!({
                "ok": true,
                "data": {
                    "state": "claim_required",
                    "challenge": {
                        "ephemeral_key": ephemeral.public(),
                        "expires_at_ms": "1800000300000",
                    },
                },
            }),
            serde_json::json!({
                "ok": true,
                "data": {
                    "state": "read",
                    "items": [],
                    "next_after_sequence": "0",
                    "more": false,
                    "stored": usage(),
                },
            }),
        ]);

        let page = client
            .read_as(&recipient, None)
            .await
            .expect("the mailbox this key is addressed by");
        assert!(page.items.is_empty());
        assert_eq!(recorder.requests(), 2, "one challenge and one answer to it");

        let (_, body) = recorder.last();
        let answered = &body["body"]["claim"];
        assert_eq!(
            answered["ephemeral_key"],
            serde_json::to_value(ephemeral.public()).expect("a key"),
            "the answer names the challenge it answers"
        );
        assert_eq!(
            answered["claim_value"],
            serde_json::to_value(
                kr_crypto::sealed::answer_mailbox_claim(&recipient, ephemeral.public())
                    .expect("the value the recipient derives")
            )
            .expect("a value"),
            "the value is the agreement of the challenge with this mailbox's own key"
        );
        assert_eq!(
            body["body"]["limit"],
            serde_json::json!(MAILBOX_ITEMS_PER_READ)
        );
    }

    #[tokio::test]
    async fn a_newer_challenge_is_asked_again_rather_than_sent_to_a_person() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let ephemeral = StoredEnvelopeKeyPair::generate().expect("the service's challenge key");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![serde_json::json!({
            "ok": true,
            "data": {
                "state": "claim_required",
                "challenge": {
                    "ephemeral_key": ephemeral.public(),
                    "expires_at_ms": "1800000300000",
                },
            },
        })]);

        let failed = client
            .read_as(&recipient, None)
            .await
            .expect_err("the claim did not settle");
        assert_eq!(
            recorder.requests(),
            2,
            "the challenge is answered once and not in a loop"
        );

        // The recovery is to ask again, because the challenge this read answered has been
        // replaced by a newer one. Nothing about this device is wrong, so a person is not sent to
        // their settings over it.
        let entry = crate::retry::entry(failed.code());
        assert_eq!(entry.step, Step::Transient);
        assert_eq!(entry.action, UserAction::Wait);
    }

    #[tokio::test]
    async fn a_challenge_key_that_agrees_with_nothing_is_refused_without_a_second_request() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![serde_json::json!({
            "ok": true,
            "data": {
                "state": "claim_required",
                "challenge": {
                    "ephemeral_key": StoredEnvelopeKey::from_bytes([0u8; 32]),
                    "expires_at_ms": "1800000300000",
                },
            },
        })]);

        let refused = client
            .read_as(&recipient, None)
            .await
            .expect_err("no key agrees with that");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(recorder.requests(), 1, "the answer was never sent");
    }

    #[tokio::test]
    async fn an_acknowledgement_names_the_position_it_covers() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![serde_json::json!({
            "ok": true,
            "data": {
                "removed": "3",
                "acknowledged_through": "7",
                "stored": usage(),
            },
        })]);

        let settled = client
            .acknowledge(recipient.public(), 7)
            .await
            .expect("the mailbox removed what it covers");
        assert_eq!(settled.removed.get(), 3);
        assert_eq!(settled.acknowledged_through.get(), 7);
        let (url, body) = recorder.last();
        assert_eq!(
            url,
            format!("https://reach.kala.to{MAILBOX_ACKNOWLEDGE_PATH}")
        );
        assert_eq!(body["body"]["through_sequence"], "7");
        assert_eq!(
            body["signature"]["payload"]["method"],
            "mailbox.acknowledge"
        );
    }

    #[tokio::test]
    async fn a_position_no_mailbox_could_have_issued_never_leaves_this_device() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let (client, recorder) = mailbox_client();

        let refused = client
            .acknowledge(recipient.public(), MAX_MAILBOX_POSITION + 1)
            .await
            .expect_err("no mailbox issues that position");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);

        let cursor = client
            .read(recipient.public(), Some(MAX_MAILBOX_POSITION + 1), None)
            .await
            .expect_err("nor does it continue from one");
        assert_eq!(cursor.code(), ErrorCode::InvalidArgument);
        assert_eq!(recorder.requests(), 0, "nothing left this device");
    }

    #[tokio::test]
    async fn a_rendering_of_the_service_these_tests_send_to_carries_none_of_what_it_was_sent() {
        // The double holds whole signed requests, so it is held to its own permitted field the way
        // the module's own types are. Without this, a later return to a derived `Debug` would pass
        // every other test here while printing a credential and a sealed item as decimals.
        let sender = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let (client, recorder) = mailbox_client();
        recorder.answering(vec![serde_json::json!({
            "ok": true,
            "data": {
                "state": "stored",
                "sequence": "1",
                "replaced_sequence": null,
                "stored": usage(),
            },
        })]);
        client
            .deliver(
                recipient.public(),
                &sealed(&sender, &recipient, NEVER_RENDERED.as_bytes()),
            )
            .await
            .expect("one request to render");

        renders_only(recorder.as_ref(), "Recorder{requests:1,..}");
    }

    #[test]
    fn a_rendering_of_a_request_an_item_or_a_page_carries_neither_a_claim_nor_a_sealed_item() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let envelope = sealed(&sender, &recipient, NEVER_RENDERED.as_bytes());

        renders_only(
            &DeliverBody {
                recipient_key: recipient.public(),
                envelope: &envelope,
            },
            "DeliverBody{payload_type:StateReference,size_bucket_bytes:U64(1024),..}",
        );

        let claim = MailboxClaimAnswer {
            ephemeral_key: StoredEnvelopeKey::from_bytes([0x27; 32]),
            claim_value: Digest256::from_bytes([0x91; 32]),
        };
        renders_only(
            &ReadBody {
                recipient_key: recipient.public(),
                after_sequence: Some(U64::new(4)),
                limit: MAILBOX_ITEMS_PER_READ,
                claim: Some(&claim),
            },
            "ReadBody{after_sequence:Some(U64(4)),limit:8,claimed:true,..}",
        );
        // The claim value is what proves the mailbox is this device's own, so the answer's own
        // rendering is held to the one field it may print. Exactly, rather than "does not contain
        // the value": the value renders as base64url, so looking for its bytes would pass
        // whatever the type printed.
        renders_only(
            &claim,
            &format!(
                "MailboxClaimAnswer{{ephemeral_key:{:?},..}}",
                claim.ephemeral_key
            ),
        );

        let item = MailboxItem {
            sequence: U64::new(12),
            stored_at_ms: U64::new(1_800_000_000_000),
            envelope,
        };
        renders_only(
            &item,
            "MailboxItem{sequence:U64(12),payload_type:StateReference,size_bucket_bytes:U64(1024),..}",
        );

        let stored = MailboxUsage {
            items: U64::new(1),
            bytes: U64::new(1304),
            item_limit: U64::new(1000),
            byte_limit: U64::new(33_554_432),
        };
        renders_only(
            &MailboxPage {
                items: vec![item],
                next_after_sequence: U64::new(12),
                more: false,
                stored,
            },
            "MailboxPage{items:1,next_after_sequence:U64(12),more:false,\
             stored:MailboxUsage{items:U64(1),bytes:U64(1304),item_limit:U64(1000),\
             byte_limit:U64(33554432)},..}",
        );
    }

    #[test]
    fn a_nonce_is_never_part_of_what_an_item_renders() {
        // The nonce travels with the ciphertext and is part of the item; the rendering above is
        // held to exact fields, and this is the marker check that goes with it.
        let sender = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let mut envelope = sealed(&sender, &recipient, b"a notification");
        envelope.nonce = Nonce192::from_bytes([0x7e; 24]);
        let item = MailboxItem {
            sequence: U64::new(1),
            stored_at_ms: U64::new(1_800_000_000_000),
            envelope,
        };
        for rendering in [format!("{item:?}"), format!("{item:#?}")] {
            assert!(!rendering.contains("126"), "{rendering}");
            assert!(!rendering.contains("7e"), "{rendering}");
        }
    }
}
