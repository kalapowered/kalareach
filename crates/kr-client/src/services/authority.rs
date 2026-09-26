//! The durable authority feed's client.
//!
//! Section 10 splits remote revocation between three parties, and the split is the security
//! property. A remote owner publishes a uniquely identified signed [`RevocationRequest`]. The
//! target host validates current owner authority and is the **sole issuer** of its ordered
//! [`AuthorityRevisionRecord`]s and of the [`RevocationAcknowledgement`]s that say what it applied.
//! The service stores both and serves them; it judges no owner's authority, because it holds no
//! host's device records.
//!
//! This module is the host's and the owner's way in. It carries the seven members of
//! `authority.sync` over [`SignedService`] and nothing else: it holds no feed state, decides no
//! ordering and signs no record. The control daemon's `AuthorityFeed` is the host's record of what
//! it has accepted, acknowledged and still owes, and it is what a caller drives with the answers
//! from here.
//!
//! # Which feed a call reaches
//!
//! A feed is addressed by the identifier of the host's own authorisation key. A host-proven request
//! reaches the feed its own key names, whatever the body says, so a host cannot act on another
//! host's feed; an owner names the host it means, which it holds from the pairing exchange that
//! made it a peer. [`kr_crypto::keys::key_id`] with [`KeyPurpose::Authorisation`] is that
//! identifier.
//!
//! # Who may ask for what
//!
//! Issuing a revision, acknowledging, refusing a record and naming the keys that may remove a host
//! are the host's own, so this client refuses them under an installation credential before
//! anything is sent. Publishing and reading need no host key, and a removal is the host's or a key
//! the host named for it, so both signer kinds may ask.
//!
//! # Retention, and what ends it
//!
//! A record has no expiry and is never coalesced. The service keeps it until the host acknowledges
//! it as complete, refuses it, or is removed. An acknowledgement that reports the dispatch barrier
//! as pending is progress rather than completion, so the record stays outstanding: section 9 makes
//! revocation completion a barrier, and until it holds the result is `pending` rather than success.
//!
//! # What is never rendered
//!
//! A published request carries the owner's signature, a revision carries the host's, and an
//! announcement carries a sealed envelope. Under this module's rule none of them is rendered: each
//! type here writes its own [`std::fmt::Debug`] naming what the record is about and nothing it
//! carries.

use std::fmt;
use std::sync::Arc;

use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::mailbox::SealedEnvelope;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    AuthorityRevisionRecord, KeyPurpose, RevocationAcknowledgement, RevocationRequest,
    RevocationTarget,
};
use kr_protocol::scalars::{
    AuthorisationKey, KeyId, Nullable, StoredEnvelopeKey, TimestampMs, U64,
};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{SignedService, malformed, unreadable_answer};
use crate::error::Result;

/// The path every authority-feed member is addressed to.
pub const AUTHORITY_SYNC_PATH: &str = "/api/authority/sync";

/// The most bytes one signed authority-feed request may be.
///
/// It is what the service admits for the whole request, credential included, and a revocation
/// request, a revision and an acknowledgement are all small. What can reach it is an announcement,
/// because that carries a sealed item: this client refuses one past the bound rather than sending
/// a request the service stops reading part way through.
pub const MAX_AUTHORITY_REQUEST_BYTES: usize = 256 * 1024;

/// The most identifiers one revocation request may name.
pub const MAX_REVOCATION_TARGETS: usize = 256;

/// The most requests one revision may say it applied.
pub const MAX_APPLIED_REQUESTS: usize = 256;

/// The most keys a host may name as permitted to remove it.
pub const MAX_REMOVAL_KEYS: usize = 8;

/// How many records one read of a feed returns.
pub const FEED_RECORDS_PER_READ: usize = 64;

/// How many bytes of a feed answer this client reads.
///
/// A read returns at most [`FEED_RECORDS_PER_READ`] records, and the largest a record gets is a
/// revocation request naming [`MAX_REVOCATION_TARGETS`] identifiers: about 10 KiB of identifiers
/// plus the request's own fields, the publisher's key and an acknowledgement. Sixty-four of those
/// is a little over 700 KiB, so a mebibyte covers the largest answer this feed produces and refuses
/// anything past it. It is far above [`super::http::DEFAULT_RESPONSE_LIMIT_BYTES`], which is why a
/// transport that carries this client states it for this path.
pub const AUTHORITY_ANSWER_LIMIT_BYTES: u64 = 1024 * 1024;

/// Why a host will not apply a published request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// The device that published it holds no owner authority on this host.
    NoOwnerAuthority,
    /// It names a grant or a device this host does not know.
    UnknownTarget,
    /// A later request covers it.
    Superseded,
}

/// An announcement to place in a mailbox beside a feed change.
///
/// It announces that the feed changed and carries nothing about what changed: the records
/// themselves live in the feed, which has its own retention and is not coalesced. A host that never
/// sees the announcement still learns the revocation from the feed, which it polls while it is
/// online and reads at reconnect.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct FeedAnnouncement {
    /// The recipient's stored-envelope public key: the host, or the device being answered.
    pub recipient_key: StoredEnvelopeKey,
    /// The sealed item. Its payload type is an authority-feed change and its expiry is held to the
    /// hour an announcement lives for.
    pub envelope: SealedEnvelope,
}

impl fmt::Debug for FeedAnnouncement {
    /// What the item is and how large it is. Never the ciphertext, the nonce or the keys.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeedAnnouncement")
            .field("payload_type", &self.envelope.routing.payload_type)
            .field(
                "size_bucket_bytes",
                &self.envelope.routing.size_bucket_bytes,
            )
            .finish_non_exhaustive()
    }
}

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// One authority-feed request: exactly one member, as the service reads it.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityRequest<'a> {
    Publish(PublishBody<'a>),
    Revise(ReviseBody<'a>),
    Acknowledge(AcknowledgeBody<'a>),
    Reject(RejectBody),
    Delegate(DelegateBody<'a>),
    Read(ReadBody),
    Remove(RemoveBody),
}

impl fmt::Debug for AuthorityRequest<'_> {
    /// Which member was asked for. Never the record, which carries a signature, and never an
    /// announcement, which carries a sealed item.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRequest")
            .field("member", &self.member())
            .finish_non_exhaustive()
    }
}

impl AuthorityRequest<'_> {
    /// The member this request asks for, in the service's own vocabulary.
    const fn member(&self) -> &'static str {
        match self {
            Self::Publish(_) => "publish",
            Self::Revise(_) => "revise",
            Self::Acknowledge(_) => "acknowledge",
            Self::Reject(_) => "reject",
            Self::Delegate(_) => "delegate",
            Self::Read(_) => "read",
            Self::Remove(_) => "remove",
        }
    }
}

/// Publish a signed revocation request to one host's feed.
#[derive(Serialize)]
struct PublishBody<'a> {
    host_key_id: KeyId,
    request: &'a RevocationRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    announce: Option<&'a FeedAnnouncement>,
}

/// Submit the host's own next authority revision.
#[derive(Serialize)]
struct ReviseBody<'a> {
    revision: &'a AuthorityRevisionRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    announce: Option<&'a FeedAnnouncement>,
}

/// Acknowledge one published request with the revision the host issued for it.
#[derive(Serialize)]
struct AcknowledgeBody<'a> {
    acknowledgement: &'a RevocationAcknowledgement,
    #[serde(skip_serializing_if = "Option::is_none")]
    announce: Option<&'a FeedAnnouncement>,
}

/// Retire a record the host has decided it will not apply.
#[derive(Debug, Serialize)]
struct RejectBody {
    request_id: RevocationRequestId,
    reason: RejectionReason,
}

/// Name the keys that may remove this host when the host itself cannot.
#[derive(Debug, Serialize)]
struct DelegateBody<'a> {
    owner_key_ids: &'a [KeyId],
}

/// Read one host's feed.
#[derive(Debug, Serialize)]
struct ReadBody {
    host_key_id: KeyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_sequence: Option<U64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary_only: Option<bool>,
}

/// Remove this host, which ends the retention of everything addressed to it.
#[derive(Debug, Serialize)]
struct RemoveBody {
    host_key_id: KeyId,
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// One stored revocation request, as a reader receives it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFeedRecord {
    /// Where this record sits in the feed's order.
    pub sequence: U64,
    /// The signed request a remote owner published.
    pub request: RevocationRequest,
    /// The authorisation key that published it.
    pub published_by: AuthorisationKey,
    /// When the service stored it, in UTC milliseconds.
    pub published_at_ms: U64,
    /// The host's acknowledgement, once it has made one.
    ///
    /// A pending acknowledgement is progress rather than completion: the record stays outstanding
    /// until the host reports the dispatch barrier complete, because that is when the revocation
    /// has reached every affected worker.
    pub acknowledgement: Nullable<RevocationAcknowledgement>,
    /// Why the host refused it, when it has.
    pub rejected: Nullable<RejectionReason>,
}

impl fmt::Debug for AuthorityFeedRecord {
    /// What the record is and where it stands. Never the request, which carries the owner's
    /// signature, and never the publishing key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityFeedRecord")
            .field("sequence", &self.sequence)
            .field("request_id", &self.request.request_id)
            .field("acknowledged", &self.acknowledgement.0.is_some())
            .field("rejected", &self.rejected.0)
            .finish_non_exhaustive()
    }
}

/// What a device list shows about one host.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFeedSummary {
    /// The highest revision the host has issued, or null before it has issued one.
    pub authority_revision: Nullable<AuthorityRevision>,
    /// When the host last issued a revision, as an RFC 3339 instant.
    pub revised_at: Nullable<String>,
    /// The host's last acknowledgement, whatever it was about.
    pub last_acknowledgement: Nullable<RevocationAcknowledgement>,
    /// When the host last acknowledged anything. Stale status is read from this.
    pub acknowledged_at: Nullable<String>,
    /// How many records are waiting for the host.
    pub outstanding: U64,
    /// Whether the host has been removed, which ends retention for it.
    pub removed: bool,
    /// The keys the host named as permitted to remove it.
    pub removal_keys: Vec<KeyId>,
    /// How often a device polls this feed while it is online.
    pub poll_interval_seconds: u32,
}

/// Where an announcement submitted beside a feed change ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementPlacement {
    /// It was placed in the recipient's mailbox.
    Stored,
    /// It was folded into an announcement already waiting on the same thread.
    Coalesced,
    /// The same item was already there.
    Duplicate,
    /// It was not placed. The feed change still stands.
    Declined,
}

/// What became of an announcement the caller submitted.
///
/// A feed change is the record and an announcement is a nudge, so the service places the
/// announcement after the record has committed and reports what became of it rather than failing
/// the change. A host polls its feed in any case, so an announcement that did not arrive costs that
/// interval rather than the revocation.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnouncementOutcome {
    /// Whether the sealed item reached the recipient's mailbox.
    pub mailbox: AnnouncementPlacement,
    /// Why it did not, when it did not.
    #[serde(default)]
    pub declined_reason: Option<String>,
}

/// What every authority-feed member answers with.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFeedState {
    /// The identifier of the host key this feed belongs to.
    pub host_key_id: KeyId,
    /// The host device the records name, once a record has named one.
    pub host_device_id: Nullable<DeviceId>,
    /// The records this reader may see, oldest first.
    ///
    /// A host sees everything addressed to it. An owner sees what it published itself, because the
    /// feed is where it learns whether the host applied what it asked for and another owner's
    /// request is not its business.
    pub records: Vec<AuthorityFeedRecord>,
    /// The cursor to continue from.
    pub next_after_sequence: U64,
    /// Whether more records follow this page.
    pub more: bool,
    /// The summary a device list shows.
    pub summary: AuthorityFeedSummary,
    /// What the announcement did, when one was submitted.
    #[serde(default)]
    pub announced: Option<AnnouncementOutcome>,
}

impl fmt::Debug for AuthorityFeedState {
    /// How much of the feed came back and where it stands. Never a record, because a record carries
    /// the owner's signature.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityFeedState")
            .field("records", &self.records.len())
            .field("next_after_sequence", &self.next_after_sequence)
            .field("more", &self.more)
            .field("summary", &self.summary)
            .field("announced", &self.announced)
            .finish_non_exhaustive()
    }
}

impl AuthorityFeedState {
    /// The record for one request, when this page carries it.
    #[must_use]
    pub fn record(&self, request_id: RevocationRequestId) -> Option<&AuthorityFeedRecord> {
        self.records
            .iter()
            .find(|record| record.request.request_id == request_id)
    }

    /// Whether this page still carries a record for `request_id` that nothing has finished.
    ///
    /// Retention is what section 10 requires of the service: a record is kept until the host
    /// acknowledges it as complete or refuses it. A record with a pending acknowledgement is still
    /// outstanding, because the dispatch barrier has not held.
    #[must_use]
    pub fn is_outstanding(&self, request_id: RevocationRequestId) -> bool {
        self.record(request_id).is_some_and(|record| {
            record.rejected.0.is_none()
                && !matches!(
                    record.acknowledgement.0.as_ref().map(|ack| ack.completion),
                    Some(kr_protocol::pairing::RevocationCompletion::Complete)
                )
        })
    }
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// The durable authority feed's client.
#[derive(Clone, Debug)]
pub struct AuthorityFeedClient {
    call: SignedService,
}

impl AuthorityFeedClient {
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

    /// The identifier of the feed this caller's own key addresses.
    ///
    /// It is the feed a host-proven request reaches whatever its body says, and it is what an owner
    /// names when it publishes to this host.
    #[must_use]
    pub fn own_feed(&self) -> KeyId {
        kr_crypto::keys::key_id(KeyPurpose::Authorisation, self.call.public_key().as_bytes())
    }

    /// Publishes one signed revocation request to a host's feed.
    ///
    /// The request's issuer key identifier is the identifier of the key that carries it, so a
    /// device publishes as itself or not at all, and the request names no host revision: only the
    /// host issues those.
    ///
    /// # Errors
    ///
    /// Returns an error when the request names more identifiers than one request may, when the
    /// service refuses it, and when the exchange or the answer failed.
    pub async fn publish(
        &self,
        host_key_id: KeyId,
        request: &RevocationRequest,
        announce: Option<&FeedAnnouncement>,
    ) -> Result<AuthorityFeedState> {
        let named = match &request.target {
            RevocationTarget::Grants { grant_ids } => grant_ids.len(),
            RevocationTarget::Devices { device_ids } => device_ids.len(),
        };
        if named > MAX_REVOCATION_TARGETS {
            return Err(malformed(crate::shown!(
                "a revocation request names at most {} identifiers",
                MAX_REVOCATION_TARGETS
            )));
        }

        self.send(AuthorityRequest::Publish(PublishBody {
            host_key_id,
            request,
            announce,
        }))
        .await
    }

    /// Submits the host's own next authority revision.
    ///
    /// The revision follows the one the feed holds and is signed by the host key that carries it.
    ///
    /// # Errors
    ///
    /// Returns an error when this caller does not sign as a host, when the revision names more
    /// applied requests than one revision may, when the service refuses it, and when the exchange
    /// or the answer failed.
    pub async fn revise(
        &self,
        revision: &AuthorityRevisionRecord,
        announce: Option<&FeedAnnouncement>,
    ) -> Result<AuthorityFeedState> {
        self.host_only("issues its own revisions")?;
        if revision.applied_requests.len() > MAX_APPLIED_REQUESTS {
            return Err(malformed(crate::shown!(
                "a revision names at most {} applied requests",
                MAX_APPLIED_REQUESTS
            )));
        }

        self.send(AuthorityRequest::Revise(ReviseBody { revision, announce }))
            .await
    }

    /// Acknowledges one published request with the revision the host issued for it.
    ///
    /// The service checks both halves: the revision is one this host issued, and its applied set
    /// names this request. A completion ends the record's retention; a pending barrier does not.
    ///
    /// # Errors
    ///
    /// Returns an error when this caller does not sign as a host, when the service refuses it, and
    /// when the exchange or the answer failed.
    pub async fn acknowledge(
        &self,
        acknowledgement: &RevocationAcknowledgement,
        announce: Option<&FeedAnnouncement>,
    ) -> Result<AuthorityFeedState> {
        self.host_only("acknowledges what it applied")?;
        self.send(AuthorityRequest::Acknowledge(AcknowledgeBody {
            acknowledgement,
            announce,
        }))
        .await
    }

    /// Retires a record this host has decided it will not apply.
    ///
    /// # Errors
    ///
    /// Returns an error when this caller does not sign as a host, when the service refuses it, and
    /// when the exchange or the answer failed.
    pub async fn reject(
        &self,
        request_id: RevocationRequestId,
        reason: RejectionReason,
    ) -> Result<AuthorityFeedState> {
        self.host_only("refuses a request addressed to it")?;
        self.send(AuthorityRequest::Reject(RejectBody { request_id, reason }))
            .await
    }

    /// Names the keys that may remove this host when the host itself cannot.
    ///
    /// # Errors
    ///
    /// Returns an error when this caller does not sign as a host, when it names more keys than a
    /// host may, when the service refuses it, and when the exchange or the answer failed.
    pub async fn delegate(&self, owner_key_ids: &[KeyId]) -> Result<AuthorityFeedState> {
        self.host_only("names the keys that may remove it")?;
        if owner_key_ids.len() > MAX_REMOVAL_KEYS {
            return Err(malformed(crate::shown!(
                "a host names at most {} keys that may remove it",
                MAX_REMOVAL_KEYS
            )));
        }
        self.send(AuthorityRequest::Delegate(DelegateBody { owner_key_ids }))
            .await
    }

    /// Reads one host's feed from a cursor.
    ///
    /// One call is one page of at most [`FEED_RECORDS_PER_READ`] records; `more` and
    /// `next_after_sequence` say whether to ask again and from where. `summary_only` asks for the
    /// revision, the last acknowledgement and the counts without the records.
    ///
    /// # Errors
    ///
    /// Returns an error when the service refuses it, and when the exchange or the answer failed.
    pub async fn read(
        &self,
        host_key_id: KeyId,
        after_sequence: Option<u64>,
        summary_only: bool,
    ) -> Result<AuthorityFeedState> {
        self.send(AuthorityRequest::Read(ReadBody {
            host_key_id,
            after_sequence: after_sequence.map(U64::new),
            summary_only: summary_only.then_some(true),
        }))
        .await
    }

    /// Removes a host from the feed, which ends the retention of everything addressed to it.
    ///
    /// The host itself removes itself, or a key it named while it still held its own.
    ///
    /// # Errors
    ///
    /// Returns an error when the service refuses it, and when the exchange or the answer failed.
    pub async fn remove(&self, host_key_id: KeyId) -> Result<AuthorityFeedState> {
        self.send(AuthorityRequest::Remove(RemoveBody { host_key_id }))
            .await
    }

    /// Refuses a member only a host may ask for, before anything is sent.
    ///
    /// The service refuses it as well. Refusing here is what stops a client spending a request to
    /// be told something it already knows: the credential it would sign says which kind of key it
    /// holds.
    fn host_only(&self, what: &'static str) -> Result<()> {
        match self.call.signer_kind() {
            ServiceRequestSigner::Host => Ok(()),
            ServiceRequestSigner::Installation => {
                Err(malformed(crate::shown!("only the host {}", what)))
            }
        }
    }

    /// Sends one member and reads the feed state it answers with.
    async fn send(&self, request: AuthorityRequest<'_>) -> Result<AuthorityFeedState> {
        let member = request.member();
        let data = self
            .call
            .call(
                AUTHORITY_SYNC_PATH,
                Method::AuthoritySync,
                &request,
                MAX_AUTHORITY_REQUEST_BYTES,
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|error| unreadable_answer(crate::shown!("what {} answered", member), &error))
    }
}

/// The instant an announcement placed beside a feed change expires.
///
/// An announcement is a nudge rather than a record: the service refuses one that lives longer than
/// an hour, because the revocation itself is in the feed and stays there until the host is finished
/// with it.
pub const ANNOUNCEMENT_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// The expiry an announcement sealed now carries.
#[must_use]
pub const fn announcement_expiry(now_ms: u64) -> TimestampMs {
    TimestampMs::new(now_ms.saturating_add(ANNOUNCEMENT_LIFETIME_MS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ServiceFuture;
    use crate::services::relay::ServiceHttpAnswer;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_crypto::sign::{SigningTranscript, sign};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::GrantId;
    use kr_protocol::pairing::RevocationCompletion;
    use kr_protocol::scalars::{CanonicalSet, Signature64, Uuid};
    use std::sync::Mutex;

    /// A service that records what it was sent and answers with what it was told to.
    #[derive(Debug)]
    struct Recorder {
        sent: Mutex<Vec<(String, Vec<u8>)>>,
        answer: Mutex<ServiceHttpAnswer>,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                answer: Mutex::new(ServiceHttpAnswer {
                    status: 200,
                    body: serde_json::to_vec(&serde_json::json!({
                        "ok": true,
                        "data": state_document(),
                    }))
                    .expect("an answer"),
                }),
            })
        }

        fn answer_with(&self, status: u16, body: serde_json::Value) {
            *self.answer.lock().expect("the answer") = ServiceHttpAnswer {
                status,
                body: serde_json::to_vec(&body).expect("an answer"),
            };
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
            let answer = self.answer.lock().expect("the answer").clone();
            Box::pin(async move { Ok(answer) })
        }
    }

    /// One device's authorisation key, held the way a client holds one.
    #[derive(Debug)]
    struct Device {
        pair: AuthorisationKeyPair,
        kind: ServiceRequestSigner,
    }

    impl Device {
        fn new(kind: ServiceRequestSigner) -> Arc<Self> {
            Arc::new(Self {
                pair: AuthorisationKeyPair::generate().expect("a key pair"),
                kind,
            })
        }
    }

    impl ServiceSigner for Device {
        fn signer(&self) -> ServiceRequestSigner {
            self.kind
        }

        fn public_key(&self) -> AuthorisationKey {
            *self.pair.public()
        }

        fn sign(&self, message: &[u8]) -> Result<Signature64> {
            let transcript =
                SigningTranscript::from_canonical_bytes(self.kind.domain(), message.to_vec())
                    .expect("a domain-tagged transcript");
            Ok(sign(&self.pair, &transcript).expect("a signature"))
        }
    }

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn feed_client(
        kind: ServiceRequestSigner,
    ) -> (AuthorityFeedClient, Arc<Recorder>, Arc<Device>) {
        let http = Recorder::new();
        let device = Device::new(kind);
        (
            AuthorityFeedClient::new(origin(), http.clone(), device.clone()),
            http,
            device,
        )
    }

    fn request(byte: u8) -> RevocationRequest {
        RevocationRequest {
            request_id: RevocationRequestId::new(Uuid::from_bytes([byte; 16])),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            target: RevocationTarget::Grants {
                grant_ids: [GrantId::new(Uuid::from_bytes([4; 16]))]
                    .into_iter()
                    .collect::<CanonicalSet<_>>(),
            },
            issued_at_ms: TimestampMs::new(1_800_000_000_000),
            issuer_key_id: KeyId::from_bytes([5; 32]),
            signature: Signature64::from_bytes([6; 64]),
        }
    }

    fn revision() -> AuthorityRevisionRecord {
        AuthorityRevisionRecord {
            host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            authority_revision: AuthorityRevision::new(4),
            previous_revision: AuthorityRevision::new(3),
            applied_requests: [RevocationRequestId::new(Uuid::from_bytes([1; 16]))]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            issued_at_ms: TimestampMs::new(1_800_000_000_000),
            host_key_id: KeyId::from_bytes([7; 32]),
            signature: Signature64::from_bytes([8; 64]),
        }
    }

    fn acknowledgement() -> RevocationAcknowledgement {
        RevocationAcknowledgement {
            request_id: RevocationRequestId::new(Uuid::from_bytes([1; 16])),
            host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            authority_revision: AuthorityRevision::new(4),
            completion: RevocationCompletion::Complete,
            acknowledged_at_ms: TimestampMs::new(1_800_000_000_500),
        }
    }

    /// The answer shape the service returns for every member.
    fn state_document() -> serde_json::Value {
        serde_json::json!({
            "host_key_id": kr_protocol::scalars::to_base64url(&[9u8; 32]),
            "host_device_id": serde_json::Value::Null,
            "records": [],
            "next_after_sequence": "0",
            "more": false,
            "summary": {
                "authority_revision": serde_json::Value::Null,
                "revised_at": serde_json::Value::Null,
                "last_acknowledgement": serde_json::Value::Null,
                "acknowledged_at": serde_json::Value::Null,
                "outstanding": "0",
                "removed": false,
                "removal_keys": [],
                "poll_interval_seconds": 30
            }
        })
    }

    /// The credential the service rebuilds, recomputed from the body that arrived.
    fn credential_covers_the_body(sent: &serde_json::Value) {
        let digest =
            kr_protocol::service::canonical_body_digest(&sent["body"]).expect("the canonical body");
        let carried = serde_json::from_value::<kr_protocol::scalars::Digest256>(
            sent["signature"]["payload"]["body_digest"].clone(),
        )
        .expect("a digest");
        assert_eq!(
            carried, digest,
            "the credential covers the body that was sent"
        );
    }

    #[tokio::test]
    async fn a_publication_names_the_host_it_is_addressed_to_and_carries_the_owners_request() {
        let (client, http, _) = feed_client(ServiceRequestSigner::Installation);
        let published = request(1);
        client
            .publish(KeyId::from_bytes([9; 32]), &published, None)
            .await
            .expect("the feed answered");

        let (url, sent) = http.last();
        assert_eq!(url, "https://reach.kala.to/api/authority/sync");
        assert_eq!(
            sent["body"]["publish"]["host_key_id"],
            serde_json::to_value(KeyId::from_bytes([9; 32])).expect("a key identifier")
        );
        assert_eq!(
            sent["body"]["publish"]["request"]["request_id"],
            serde_json::json!("01010101-0101-0101-0101-010101010101")
        );
        // A publication with no announcement carries none, rather than carrying a null the service
        // would have to read as one.
        assert!(sent["body"]["publish"].get("announce").is_none());
        assert_eq!(
            sent["signature"]["signer"],
            serde_json::json!("installation")
        );
        assert_eq!(
            sent["signature"]["payload"]["method"],
            serde_json::json!("authority.sync")
        );
        assert_eq!(
            sent["signature"]["payload"]["gateway_origin"],
            serde_json::json!("https://reach.kala.to")
        );
        credential_covers_the_body(&sent);
    }

    #[tokio::test]
    async fn every_member_is_one_member_of_one_request() {
        let (host, http, _) = feed_client(ServiceRequestSigner::Host);
        let feed = KeyId::from_bytes([9; 32]);
        host.revise(&revision(), None).await.expect("a revision");
        assert_eq!(members(&http.last().1), vec!["revise"]);
        host.acknowledge(&acknowledgement(), None)
            .await
            .expect("an acknowledgement");
        assert_eq!(members(&http.last().1), vec!["acknowledge"]);
        host.reject(
            RevocationRequestId::new(Uuid::from_bytes([1; 16])),
            RejectionReason::NoOwnerAuthority,
        )
        .await
        .expect("a refusal");
        assert_eq!(members(&http.last().1), vec!["reject"]);
        assert_eq!(
            http.last().1["body"]["reject"]["reason"],
            serde_json::json!("no_owner_authority")
        );
        host.delegate(&[KeyId::from_bytes([1; 32])])
            .await
            .expect("a delegation");
        assert_eq!(members(&http.last().1), vec!["delegate"]);
        host.read(feed, Some(7), false).await.expect("a read");
        assert_eq!(members(&http.last().1), vec!["read"]);
        assert_eq!(
            http.last().1["body"]["read"]["after_sequence"],
            serde_json::json!("7")
        );
        // A read that asks for everything asks for nothing else: the two optional members are
        // absent rather than null, because the service reads a member that is there.
        host.read(feed, None, false).await.expect("a read");
        assert!(
            http.last().1["body"]["read"]
                .get("after_sequence")
                .is_none()
        );
        assert!(http.last().1["body"]["read"].get("summary_only").is_none());
        host.read(feed, None, true).await.expect("a summary");
        assert_eq!(
            http.last().1["body"]["read"]["summary_only"],
            serde_json::json!(true)
        );
        host.remove(feed).await.expect("a removal");
        assert_eq!(members(&http.last().1), vec!["remove"]);
    }

    /// The members one request body names.
    fn members(sent: &serde_json::Value) -> Vec<String> {
        sent["body"]
            .as_object()
            .expect("a request body")
            .keys()
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn a_host_member_asked_for_under_an_installation_key_is_refused_before_it_is_sent() {
        let (owner, http, _) = feed_client(ServiceRequestSigner::Installation);
        for error in [
            owner
                .revise(&revision(), None)
                .await
                .expect_err("a revision"),
            owner
                .acknowledge(&acknowledgement(), None)
                .await
                .expect_err("an acknowledgement"),
            owner
                .reject(
                    RevocationRequestId::new(Uuid::from_bytes([1; 16])),
                    RejectionReason::Superseded,
                )
                .await
                .expect_err("a refusal"),
            owner
                .delegate(&[KeyId::from_bytes([1; 32])])
                .await
                .expect_err("a delegation"),
        ] {
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(error.to_string().contains("only the host"), "{error}");
        }
        assert_eq!(http.requests(), 0, "nothing was sent");
    }

    #[tokio::test]
    async fn a_request_past_a_bound_the_service_holds_is_refused_before_it_is_sent() {
        let (owner, http, _) = feed_client(ServiceRequestSigner::Installation);
        let mut named = request(1);
        named.target = RevocationTarget::Grants {
            grant_ids: (0..=MAX_REVOCATION_TARGETS)
                .map(|index| {
                    let mut bytes = [0u8; 16];
                    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    GrantId::new(Uuid::from_bytes(bytes))
                })
                .collect::<CanonicalSet<_>>(),
        };
        let error = owner
            .publish(KeyId::from_bytes([9; 32]), &named, None)
            .await
            .expect_err("more identifiers than one request may name");
        assert!(
            error.to_string().contains("at most 256 identifiers"),
            "{error}"
        );

        let (host, host_http, _) = feed_client(ServiceRequestSigner::Host);
        let error = host
            .delegate(&[KeyId::from_bytes([1; 32]); MAX_REMOVAL_KEYS + 1])
            .await
            .expect_err("more keys than a host may name");
        assert!(error.to_string().contains("at most 8 keys"), "{error}");

        assert_eq!(http.requests(), 0, "nothing was sent");
        assert_eq!(host_http.requests(), 0, "nothing was sent");
    }

    #[tokio::test]
    async fn an_announcement_past_what_one_request_may_be_is_refused_before_it_is_sent() {
        let (owner, http, _) = feed_client(ServiceRequestSigner::Installation);
        let announcement = FeedAnnouncement {
            recipient_key: kr_protocol::scalars::StoredEnvelopeKey::from_bytes([3; 32]),
            envelope: SealedEnvelope {
                routing: kr_protocol::mailbox::EnvelopeRouting {
                    envelope_id: kr_protocol::ids::EnvelopeId::new(Uuid::from_bytes([4; 16])),
                    recipient_key_id: KeyId::from_bytes([5; 32]),
                    sender_key_id: KeyId::from_bytes([6; 32]),
                    expires_at_ms: announcement_expiry(1_800_000_000_000),
                    payload_type: kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange,
                    thread_id: Nullable(None),
                    size_bucket_bytes: U64::new(MAX_AUTHORITY_REQUEST_BYTES as u64),
                },
                nonce: kr_protocol::scalars::Nonce192::from_bytes([7; 24]),
                ciphertext: kr_protocol::scalars::Bytes::new(vec![8; MAX_AUTHORITY_REQUEST_BYTES]),
            },
        };

        let error = owner
            .publish(KeyId::from_bytes([9; 32]), &request(1), Some(&announcement))
            .await
            .expect_err("more than one request may carry");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.to_string().contains("at most 262144 bytes"),
            "{error}"
        );
        assert_eq!(http.requests(), 0, "nothing was sent");
    }

    #[tokio::test]
    async fn the_feed_a_caller_addresses_is_the_one_its_own_key_names() {
        let (host, _, device) = feed_client(ServiceRequestSigner::Host);
        assert_eq!(
            host.own_feed(),
            kr_crypto::keys::key_id(KeyPurpose::Authorisation, device.public_key().as_bytes())
        );
    }

    #[tokio::test]
    async fn a_refusal_the_service_named_reaches_the_caller_as_that_refusal() {
        let (host, http, _) = feed_client(ServiceRequestSigner::Host);
        http.answer_with(
            403,
            serde_json::json!({
                "ok": false,
                "error": {
                    "code": "FORBIDDEN",
                    "message": "This feed holds a revision at least as high as that one."
                }
            }),
        );
        let error = host
            .revise(&revision(), None)
            .await
            .expect_err("the feed refused it");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert!(
            error
                .to_string()
                .contains("This feed holds a revision at least as high as that one."),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_answer_this_client_cannot_read_is_an_unknown_outcome() {
        let (host, http, _) = feed_client(ServiceRequestSigner::Host);
        http.answer_with(
            200,
            serde_json::json!({ "ok": true, "data": { "summary": "none" } }),
        );
        let error = host
            .read(KeyId::from_bytes([9; 32]), None, true)
            .await
            .expect_err("that is not a feed state");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    }

    #[test]
    fn a_record_is_outstanding_until_the_barrier_it_names_has_held() {
        let pending = |completion| {
            let mut answer = state_document();
            answer["records"] = serde_json::json!([{
                "sequence": "1",
                "request": serde_json::to_value(request(1)).expect("a request"),
                "published_by": kr_protocol::scalars::to_base64url(&[3u8; 32]),
                "published_at_ms": "1800000000000",
                "acknowledgement": completion,
                "rejected": serde_json::Value::Null
            }]);
            serde_json::from_value::<AuthorityFeedState>(answer).expect("a feed state")
        };
        let request_id = RevocationRequestId::new(Uuid::from_bytes([1; 16]));

        assert!(pending(serde_json::Value::Null).is_outstanding(request_id));

        let mut progress = acknowledgement();
        progress.completion = RevocationCompletion::Pending {
            pending_workers: U64::new(2),
        };
        assert!(
            pending(serde_json::to_value(&progress).expect("an acknowledgement"))
                .is_outstanding(request_id),
            "a pending barrier is progress rather than completion"
        );

        let complete =
            pending(serde_json::to_value(acknowledgement()).expect("an acknowledgement"));
        assert!(!complete.is_outstanding(request_id));
        assert!(complete.record(request_id).is_some());
    }

    #[test]
    fn a_rendering_of_a_request_or_an_answer_carries_neither_a_signature_nor_a_sealed_item() {
        // A signature is 64 bytes and travels as 86 base64url characters, so a rendering that
        // printed one would print the marker spelled in that alphabet.
        let marker = format!("{NEVER_RENDERED}{}", "A".repeat(86 - NEVER_RENDERED.len()));
        let mut published = request(1);
        published.signature = serde_json::from_value(serde_json::json!(marker))
            .expect("a signature of the right length");
        assert!(
            format!("{:?}", published.signature).contains(NEVER_RENDERED),
            "the fixture's signature spells the marker"
        );

        renders_only(
            &AuthorityRequest::Publish(PublishBody {
                host_key_id: KeyId::from_bytes([9; 32]),
                request: &published,
                announce: None,
            }),
            r#"AuthorityRequest{member:"publish",..}"#,
        );

        let mut answer = state_document();
        answer["records"] = serde_json::json!([{
            "sequence": "1",
            "request": serde_json::to_value(&published).expect("a request"),
            "published_by": kr_protocol::scalars::to_base64url(&[3u8; 32]),
            "published_at_ms": "1800000000000",
            "acknowledgement": serde_json::Value::Null,
            "rejected": serde_json::Value::Null
        }]);
        let state: AuthorityFeedState = serde_json::from_value(answer).expect("a feed state");
        for rendering in [format!("{state:?}"), format!("{state:#?}")] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        renders_only(
            &state.records[0],
            concat!(
                r#"AuthorityFeedRecord{sequence:U64(1),"#,
                r#"request_id:RevocationRequestId(Uuid(01010101-0101-0101-0101-010101010101)),"#,
                r#"acknowledged:false,rejected:None,..}"#,
            ),
        );
    }
}
