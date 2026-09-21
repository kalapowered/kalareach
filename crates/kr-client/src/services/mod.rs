//! Replaceable service clients.
//!
//! Section 17: `kr-client` has replaceable service clients for account login, relay leases, push,
//! encrypted sync/backup and managed inference. The boundary matters more than the implementations:
//! all local host and client functionality is open source, the hosted service sells provider usage,
//! storage, relay bandwidth and operation, and a fork can point these traits at its own
//! infrastructure without changing anything else in the client.
//!
//! The traits and one null implementation live here, and six modules hold the managed
//! implementations this crate carries. [`relay`] is the relay-lease client, because a lease is the
//! one managed resource a client cannot do without and still use a relay at all. [`voice`] is the
//! voice broker, because a managed call is created by one request whose exact shape both the host
//! and the companion have to agree on. [`authority`] is the durable authority feed, where a remote
//! owner publishes a signed revocation request and the host that owns the feed acknowledges what it
//! applied. [`mailbox`] is the encrypted mailbox, where a device leaves a sealed item for a peer
//! that is not connected and the peer reads its own. [`signed`] is the one signed call those of
//! them that speak the section 23 `Services` group share, and [`http`] is the exchange underneath
//! all of them: one gateway origin, finite deadlines, bounded answers and no retry of its own. A
//! self-hosted deployment supplies its own, and a client with no managed service configured is a
//! complete client: direct connections, local sessions, plugins, local descriptions and
//! user-operated alternatives need none of these.
//!
//! # What is never rendered
//!
//! A request body carries a credential, a header value can be a token, and an answer carries
//! whatever the thing that answered put in it, including something the request sent. A panic
//! message, a log line or a diagnostic that formatted one of those would be the thing that
//! disclosed it, and `{:?}` is how a value reaches all three.
//!
//! So the rule in this module is a rule about the types rather than about the call sites: **no type
//! here derives [`std::fmt::Debug`] over request or answer bytes, a credential, a signature, a
//! header value or the content of a call.** Each such type writes its own, naming the operation,
//! the class and the length and nothing that travelled:
//!
//! | Type | What it holds | What it prints |
//! | --- | --- | --- |
//! | [`ServiceHttpAnswer`] | An answer's bytes | The status, its class, its length |
//! | [`relay::RelayRequestPayload`] | A credential's nonce and body digest | The method, the gateway |
//! | [`relay::RelayRequestSignature`] | A credential and its signature | The method, the signer kind |
//! | [`relay::SignedRelayRequest`] | A credential and a request body | The method, the signer kind |
//! | [`relay::RelayLeaseGrant`] | A lease signed by the issuer the relay pins | The lease, the relay, the payer |
//! | [`voice::AccountToken`] | A bearer token | A placeholder |
//! | [`voice::StoredAccountToken`], [`voice::AccountTokenFile`] | An address, which may carry a user name and a password before its host | The scheme, the host and the port |
//! | [`voice::VoiceSessionRequest`], [`voice::VoiceSession`] | Session descriptions, which carry the connection's ICE credentials | What the call is and how long it lasts, and the description's length |
//! | [`voice::VoiceContextFrame`] | What a person said to a call | The request, the command, the length |
//! | [`signed::SignedService`] | The key that signs a managed-service call | The gateway, the signer kind |
//! | [`authority::FeedAnnouncement`] | A sealed announcement for a mailbox | What the item is, and its declared size |
//! | [`authority::AuthorityFeedRecord`] | A revocation request signed by a remote owner | The position, the request identity, whether it is finished |
//! | [`authority::AuthorityFeedState`] | Those records | How many came back, the cursor, the summary |
//! | [`mailbox::MailboxClaimAnswer`] | The proof that a mailbox is this device's own | The challenge it answers |
//! | [`mailbox::MailboxItem`] | A sealed item a mailbox served back | Its position, what the item is, its declared size |
//! | [`mailbox::MailboxPage`] | Those items | How many came back, the cursor, what the mailbox holds |
//!
//! A type that holds one of these only through one of these, as [`AccountSession`] holds a token
//! and [`relay::RelayLeaseAnswer`] holds a grant, is safe to derive, because the rendering it
//! composes is the redacted one.
//!
//! Six tests are that rule's proof:
//! `a_rendering_of_a_request_a_credential_or_an_answer_carries_none_of_it` and
//! `a_rendering_of_an_issued_lease_carries_neither_the_lease_nor_its_signature` in [`relay`],
//! `a_rendering_of_a_call_carries_neither_its_offer_its_answer_nor_what_was_said` in [`voice`],
//! `a_rendering_of_a_signed_request_carries_neither_its_body_nor_its_credential` in [`signed`],
//! `a_rendering_of_a_request_or_an_answer_carries_neither_a_signature_nor_a_sealed_item` in
//! [`authority`], and
//! `a_rendering_of_a_request_an_item_or_a_page_carries_neither_a_claim_nor_a_sealed_item` in
//! [`mailbox`].
//! Each holds the type it covers to the exact fields above, in both `{:?}` and `{:#?}`, which is
//! stronger than looking for a marker: a rendering that printed the bytes as decimals would pass a
//! search for text and fail this. The enclosing types that only compose these, such as
//! [`relay::RelayLeaseAnswer`] and [`voice::VoiceStart`], are checked for the marker instead,
//! because what they render is whatever the redacted type gave them.
//!
//! The same rule covers what a failure says. `serde_json`'s own message quotes the value it
//! rejected — `invalid type: string "..."` — so an error that carried that text would print
//! through [`std::fmt::Display`] the very thing the Debug rule keeps out of `{:?}`. Nothing here
//! formats a JSON error into a message: [`json_fault`] is what a caller is told instead, and it
//! carries the class and the position and nothing that was in the document.
//!
//! One thing is deliberately not covered by it. A refusal the service sent carries the service's
//! own message, which is written to be shown to a person, and that message is in the error this
//! client returns. What is never in it is anything else of the answer.

pub mod authority;
pub mod http;
pub mod mailbox;
pub mod relay;
pub mod signed;
pub mod voice;

use std::future::Future;
use std::pin::Pin;

use kr_protocol::ids::{InstallationId, RelayLeaseId, SyncConflictId};
use kr_protocol::scalars::{EndpointKey, Uuid};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

pub use authority::{
    AnnouncementOutcome, AnnouncementPlacement, AuthorityFeedClient, AuthorityFeedRecord,
    AuthorityFeedState, AuthorityFeedSummary, FeedAnnouncement, RejectionReason,
};
pub use http::{HttpDeadlines, HttpService, ResponseLimits};
pub use mailbox::{
    MailboxAcknowledgement, MailboxAnswer, MailboxChallenge, MailboxClaimAnswer,
    MailboxClaimRequired, MailboxClient, MailboxDelivery, MailboxDeliveryState, MailboxItem,
    MailboxPage, MailboxUsage,
};
pub use relay::{
    ManagedRelayLeaseService, RelayAllowance, RelayGraceRemainder, RelayLeaseAnswer,
    RelayLeaseEnding, RelayLeaseGrant, RelayLeaseRefusal, RelayWarning, ServiceHttp,
    ServiceHttpAnswer, ServiceSigner,
};
pub use voice::{
    AccountToken, AccountTokenSource, ManagedVoiceBroker, ManagedVoiceService, VoiceClosure,
    VoiceCommand, VoiceContextFrame, VoiceControlEvent, VoiceRefusal, VoiceRefusalReason,
    VoiceSession, VoiceSessionRequest, VoiceStart,
};

/// A boxed future, so every service client stays usable behind a trait object.
pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What a JSON failure says, with none of the document it was about.
///
/// `serde_json` names the value it rejected in its own message, and that value is a request body,
/// an answer or a stored token. So this is what every failure of this kind in this module says
/// instead: which kind of failure it was, and where in the document it happened. Both are useful
/// to somebody diagnosing a mismatch and neither is anything that travelled.
pub(crate) fn json_fault(error: &serde_json::Error) -> String {
    let what = match error.classify() {
        serde_json::error::Category::Io => "could not be read",
        serde_json::error::Category::Syntax => "is not JSON",
        serde_json::error::Category::Data => "is not the shape this client reads",
        serde_json::error::Category::Eof => "ended early",
    };
    format!(
        "it {what} at line {} column {}",
        error.line(),
        error.column()
    )
}

/// The bounds a transport carrying this crate's managed-service clients reads answers under.
///
/// One figure for every operation would have to be the largest any of them needs, which would let
/// the rest grow to it. So each operation that answers with more than one object states its own
/// bound here, beside the client that asks for it, and everything else keeps
/// [`http::DEFAULT_RESPONSE_LIMIT_BYTES`]. It is what a composition root hands
/// [`HttpService::with`].
#[must_use]
pub fn managed_response_limits() -> ResponseLimits {
    ResponseLimits::default()
        .for_path(
            authority::AUTHORITY_SYNC_PATH,
            authority::AUTHORITY_ANSWER_LIMIT_BYTES,
        )
        .for_path(
            mailbox::MAILBOX_READ_PATH,
            mailbox::MAILBOX_ANSWER_LIMIT_BYTES,
        )
}

/// How this module's rule about what is never rendered is checked.
#[cfg(test)]
pub(crate) mod rendering {
    /// Stands for everything this module must not render. A test puts it where the type under
    /// test holds bytes, a credential, a header value or what a person said.
    pub const NEVER_RENDERED: &str = "a-marker-nobody-should-see";

    /// One rendering with its whitespace removed and the trailing commas the indented form adds
    /// dropped, so a value's two renderings are comparable with each other and with the exact
    /// fields the type is allowed to print.
    fn condensed(rendered: &str) -> String {
        let mut text = rendered.split_whitespace().collect::<String>();
        while text.contains(",}") || text.contains(",)") || text.contains(",]") {
            text = text
                .replace(",}", "}")
                .replace(",)", ")")
                .replace(",]", "]");
        }
        text
    }

    /// Holds both renderings of one value to exactly what it may print.
    ///
    /// Exactly, rather than "does not contain the marker": a rendering that printed the bytes as
    /// decimals would pass a search for the text and fail this.
    pub fn renders_only(value: &impl std::fmt::Debug, expected: &str) {
        let plain = format!("{value:?}");
        let indented = format!("{value:#?}");
        for rendering in [&plain, &indented] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(condensed(&plain), expected);
        assert_eq!(condensed(&indented), expected);
    }
}

/// An account session obtained from the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSession {
    /// The opaque access token. It authorises managed resources only: a host still requires device
    /// pairing and its own grant.
    ///
    /// Held so it cannot reach a log by accident: the token is not in this structure's
    /// [`std::fmt::Debug`] rendering.
    pub access_token: AccountToken,
    /// How many seconds the access token lasts.
    pub expires_in_seconds: u64,
    /// The scopes the token was issued with.
    ///
    /// Each managed resource names its own, and a route refuses a token issued without it. A
    /// client that held a session with no record of its scopes would discover what it may do by
    /// being refused, which is an expensive way to read a field the token already carries.
    pub scopes: Vec<String>,
}

impl AccountSession {
    /// Returns true when this session carries `scope`.
    #[must_use]
    pub fn carries(&self, scope: &str) -> bool {
        self.scopes.iter().any(|held| held == scope)
    }
}

/// Which way a relay lease permits traffic to flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDirection {
    /// From the source endpoint to the destination endpoint only.
    SourceToDestination,
    /// Both ways between the two endpoints.
    Bidirectional,
}

/// What a client asks the service to lease.
///
/// Section 17: before forwarding a peer payload the relay must possess a current signed capability
/// binding the source and destination endpoint keys, the direction, the payer principal and its
/// authorisation, the lease and reservation identities, a byte ceiling, an expiry, the relay scope,
/// the issuer key and a revision. The client's half of that is everything below; the payer, the
/// route, the signature and the revision are the service's, because a client that chose its own
/// metering boundary could choose one that counts nothing.
///
/// The service refuses a request outside these ranges, and it refuses it before anything is held,
/// so a caller that respects them is a caller whose refusals are about capacity:
///
/// - the two endpoints differ;
/// - `byte_ceiling` is at least 64 KiB and at most 2^53 - 1, which is the largest whole number the
///   service's own arithmetic carries exactly, and it is the *cumulative* figure for the
///   reservation rather than an increment;
/// - `duration_seconds` is between 30 and 900;
/// - `payer`, when it names an account, carries that account's identifier and the identifier of the
///   authorisation it gave this caller, which is a lower-case hyphenated UUID;
/// - `lease_id`, when it names one, is a lower-case hyphenated UUID.
///
/// The payer's own bound applies on top: an account authorisation states the most one lease may
/// hold outstanding against that account's allowance, and an installation paying for itself is
/// bounded by the free allowance and by the 8 MiB aggregate section 17 gives every principal. The
/// bounded grace a principal is granted when its allowance runs out is not measured against the
/// authorisation's figure, because it is not taken from the allowance the figure protects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRequest {
    /// The endpoint the traffic comes from.
    pub source: EndpointKey,
    /// The endpoint the traffic goes to.
    pub destination: EndpointKey,
    /// Which way the lease permits traffic to flow.
    pub direction: RelayDirection,
    /// The cumulative bytes the payer is asking to reserve. At least 64 KiB, at most 2^53 - 1.
    pub byte_ceiling: u64,
    /// How long the lease should last, in seconds. Between 30 and 900.
    pub duration_seconds: u32,
    /// The region the requester would rather be carried in, or null for no preference. A hint.
    pub region_preference: Option<String>,
    /// Who pays, or null for the default: the account this caller has selected, else itself.
    pub payer: Option<LeasePayer>,
    /// The lease to refill.
    ///
    /// Null does not mean a new lease. It means the caller is not naming one, and the service then
    /// refills whatever live lease that pair already holds, because one conversation holds one
    /// reservation: a second lease for the same pair would hold bytes from the same aggregate while
    /// knowing nothing about what the first had spent. Naming a lease that is not live, or one
    /// issued to another caller, is refused rather than answered with a new one.
    pub lease_id: Option<RelayLeaseId>,
}

/// Who a client asks to be billed.
///
/// The two cases are written the way every other tagged object of this protocol is: a case that
/// carries nothing is its own name, and a case that carries facts is a map under it. One serde
/// definition therefore produces the JSON the service reads and the canonical bytes the credential
/// covers, which is what keeps the two from drifting.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePayer {
    /// This installation itself, drawing on the free allowance.
    Installation,
    /// An account, under an authorisation that account issued to this caller.
    Account {
        /// The account to bill.
        account_id: String,
        /// The authorisation record that makes it the payer.
        authorisation_id: String,
    },
}

/// Why a client is ending a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEndReason {
    /// The pair is no longer paired, so nothing may be carried for it.
    Unpaired,
    /// The payer withdrew the authorisation the lease was issued under.
    PayerWithdrew,
    /// The traffic is finished and the reservation should be settled.
    Finished,
}

/// A push registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRegistration {
    /// The installation this registration belongs to.
    pub installation_id: InstallationId,
}

/// Where a managed or self-hosted account is signed in.
///
/// Account tokens authorise managed resources only. Nothing here can grant host authority.
pub trait AccountService: Send + Sync + std::fmt::Debug {
    /// Signs in and returns a session.
    fn sign_in<'a>(&'a self, authorisation_code: &'a str) -> ServiceFuture<'a, AccountSession>;

    /// Exchanges a refresh token for a new session.
    fn refresh<'a>(&'a self, refresh_token: &'a str) -> ServiceFuture<'a, AccountSession>;
}

/// Where relay leases are obtained.
///
/// The service holds the ledger the lease spends from, signs the lease with the admission key the
/// relay pins, and tries to install it on the relay before answering. Endpoint admission alone
/// never authorises peer traffic or billing, and nothing a client says decides who pays.
///
/// An answer is not always a lease. An allowance that is spent and a service with no relay to offer
/// are answers about capacity, carrying what is left of the bounded grace and the paths that still
/// work, and [`RelayLeaseAnswer`] is that distinction: section 17 requires an exhausted managed
/// allowance to be reported as unavailable capacity with alternatives rather than as a failure.
///
/// Nor is a lease always installed. `installed` on a grant is the relay's own acknowledgement, and
/// null means the service could not get one: the relay may be carrying the lease and may not, and
/// the service keeps the bytes held either way rather than releasing capacity that might be
/// spending. A client holding such a grant may use it, and should expect the relay to refuse its
/// first payload if the installation never landed; asking again for the same pair is the retry, and
/// it is answered with the lease that is installed rather than a second one.
///
/// A revocation is the same shape. Its settlement can come back `pending`, which means the bytes
/// are still held while the evidence completes: the service settles it from the receipts or charges
/// the remainder at the deadline, without the caller doing anything.
pub trait RelayLeaseService: Send + Sync + std::fmt::Debug {
    /// Obtains a lease for a pair of endpoints, or a refill of the one that pair holds.
    fn issue<'a>(&'a self, request: &'a LeaseRequest) -> ServiceFuture<'a, RelayLeaseAnswer>;

    /// Ends a lease, so the relay stops carrying the pair and the reservation is settled.
    ///
    /// Idempotent: a repeat finishes whatever the first attempt could not, which is why a caller
    /// that is unsure whether its revocation arrived asks again rather than assuming.
    fn revoke<'a>(
        &'a self,
        lease_id: RelayLeaseId,
        reason: LeaseEndReason,
    ) -> ServiceFuture<'a, RelayLeaseEnding>;
}

/// Where a device registers for push.
///
/// Registration uses the installation's own key proof, not a managed-account login, which is what
/// keeps account-free push working.
pub trait PushService: Send + Sync + std::fmt::Debug {
    /// Registers this installation for push.
    fn register<'a>(&'a self, token: &'a str) -> ServiceFuture<'a, PushRegistration>;

    /// Revokes this installation's registration.
    fn revoke<'a>(&'a self, installation_id: InstallationId) -> ServiceFuture<'a, ()>;
}

/// The name a synchronisation service gives one write of one object.
///
/// Opaque, and this client never reads anything out of it. Two revisions are equal or they are not;
/// which of them came first is a question only [`SyncPosition::write_sequence`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncRevision(pub Uuid);

impl SyncRevision {
    /// Wraps the name a service gave one write.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw name.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for SyncRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

/// Where one object stands on a synchronisation service.
///
/// Two facts, because one of them cannot do both jobs. The revision names the write, so a
/// comparison can say *which* state it means; the write sequence orders the writes, so this device
/// can tell a later answer from an earlier one. A service assigns the sequence itself, starting at
/// one and never repeating it for the life of the collection, which is what makes it an order
/// rather than a guess: a client that numbered the answers as they arrived would number a delayed
/// reply after the write that superseded it.
///
/// There is no position that means "nothing is there yet". An object that has never been written
/// has no position at all, and a comparison against it is a comparison against nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPosition {
    /// Where this write falls in the collection's order. The first is one.
    pub write_sequence: u64,
    /// The name the service gave this write.
    pub revision: SyncRevision,
}

impl std::fmt::Display for SyncPosition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "write {} ({})",
            self.write_sequence, self.revision
        )
    }
}

/// What a synchronisation service did with one exchange.
///
/// A refusal is an answer and not a failure, so it comes back as a value: the service compared, the
/// comparison did not hold, and the object was left where it was. Only something that stopped the
/// exchange from being answered at all is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncExchanged {
    /// The service applied the write, leaving the object at this position.
    Applied {
        /// Where the write left the object.
        position: SyncPosition,
    },
    /// The service refused the comparison, so the write did not replace the object.
    Refused {
        /// The copy the service kept of the refused write, when it kept one.
        ///
        /// A refusal establishes that the comparison did not replace the object. It does **not**
        /// establish that the service kept nothing: a service that stores a rejected write as a
        /// conflict copy of its own names that copy here, and the ciphertext it holds is content
        /// this device sent, which section 24 shows rather than pretends away.
        retained: Option<SyncConflictId>,
    },
}

/// What a synchronisation service recorded about one request.
///
/// Section 9 gives every mutation a receipt under the de-duplication key
/// `(verified_actor_id, action_id)` and keeps it for thirty days. That is what makes a lost answer
/// answerable: the device asks about the identity it sent, not about the object, because what the
/// object holds afterwards is a fact about the object rather than about any one write of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncRequestStatus {
    /// The service applied the write, leaving the object at this position.
    Applied {
        /// Where the write left the object, as the receipt recorded it.
        ///
        /// The receipt says where *this write* left the object, not where the object stands now.
        /// A later write of the same object moves the object on and leaves this receipt alone.
        position: SyncPosition,
    },
    /// The service refused the comparison, so this request did not replace the object.
    Refused {
        /// The copy the service kept of the refused write, when it kept one.
        retained: Option<SyncConflictId>,
    },
    /// The service holds no receipt for this request.
    ///
    /// Two different things look like this from here: a request that has not been executed, which
    /// may still be on its way, and a receipt that has passed section 9's thirty-day retention.
    /// Neither establishes that the write did not land, which is why this is one answer rather than
    /// two, and why it settles nothing on its own.
    Unknown,
    /// The request was fenced before the service executed it, so it never will be.
    Fenced,
}

/// What a synchronisation service answered when asked to fence one request.
///
/// Three answers and no fourth, which is the whole point of asking: a fence either finds an outcome
/// the service already recorded or makes one, so it always ends the request. That is what lets a
/// privacy cleanup finish. [`SyncRequestStatus::Unknown`] has no counterpart here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncRequestFence {
    /// The service had already applied the write, leaving the object at this position.
    Applied {
        /// Where the write left the object, as the receipt recorded it.
        position: SyncPosition,
    },
    /// The service had already refused the comparison.
    Refused {
        /// The copy the service kept of the refused write, when it kept one.
        retained: Option<SyncConflictId>,
    },
    /// The request is fenced: the service executed nothing under this identity and never will.
    Fenced,
}

/// Where encrypted settings and backups are exchanged.
///
/// The service stores ciphertext. It never holds the keys, so a compare-and-exchange here is over
/// opaque bytes.
///
/// Every exchange carries an identity for the request itself, and [`Self::request_status`] answers
/// about that identity afterwards. Without it, a device whose answer was lost could not establish
/// whether its write landed: the comparison is about the object, and asking what the object holds
/// later says nothing about one write of it.
///
/// # What an implementation owes
///
/// 1. **The order is the service's, not the caller's.** Every applied write of an object takes the
///    next [`SyncPosition::write_sequence`] of that object's collection, from a counter the service
///    keeps. An implementation numbers nothing itself: numbers assigned in the order answers
///    arrive describe the order they arrived in, and a reply delayed while another device writes
///    would then outrank the write that superseded it.
/// 2. **A receipt is history.** [`Self::request_status`] answers what the receipt recorded, never
///    what the collection holds now, so an applied receipt always names the position that write
///    produced even when a later write has moved the object on. An exchange whose identity already
///    has a receipt is answered from it and applied no second time.
/// 3. **A position is absent only when nothing is there.** [`Self::compare_exchange`] takes no
///    expected position for a first write, and answers a position for every write it applies.
/// 4. **A fence ends a request.** [`Self::fence_request`] never answers that it does not know:
///    either the service has already decided the request, or the fence decides it, and an exchange
///    arriving under a fenced identity afterwards executes nothing.
pub trait SyncBackupService: Send + Sync + std::fmt::Debug {
    /// Publishes an encrypted object, comparing against where the caller last saw the object.
    ///
    /// `expected` is the position this caller is replacing, and `None` says the caller believes
    /// nothing is there yet. The service compares, applies the write and answers the position it
    /// assigned, or refuses because the object is somewhere else.
    ///
    /// `request_id` names this request. It is the de-duplication key of section 9 and it belongs
    /// to the piece of work rather than to the object, so a retry of the same work presents the
    /// same identity and is answered from the receipt instead of being applied twice. Presenting
    /// one identity with different content is refused as `ID_CONFLICT`, and presenting a fenced
    /// identity is refused as `REQUEST_FENCED`.
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged>;

    /// Returns what the service recorded about one request.
    ///
    /// It reads the receipt and nothing else, so the answer is about that request even when the
    /// object has moved on since. A request the service has no receipt for is
    /// [`SyncRequestStatus::Unknown`] rather than a failure: not knowing is an answer, and the
    /// caller decides what to do with it.
    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus>;

    /// Stops one request from ever being executed, and says what became of it.
    ///
    /// It is what a caller asks when it must establish that a request is over and the status query
    /// says only that no receipt exists. A request the service has already decided keeps its
    /// outcome and the fence changes nothing; one it has not decided is fenced, so an exchange that
    /// arrives under that identity afterwards is refused without being executed. Fencing the same
    /// request twice answers the same thing.
    ///
    /// It ends the request in every case, which is the property section 24's cleanup rests on: a
    /// barrier that only a receipt could release would stay shut for a request that was lost on its
    /// way to the service, and a cleanup that dropped such a request instead would report complete
    /// while the service could still run it.
    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestFence>;

    /// Fetches an encrypted object and the position it is held at.
    ///
    /// The position comes back with the bytes because a caller that fetched after losing a
    /// comparison needs it to make the next one: without it, the only way to learn where the object
    /// stands is to lose again.
    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)>;
}

/// One managed service a client may hold an implementation of.
///
/// The set is closed, and it is section 17's: account login, relay leases, push, encrypted sync and
/// backup, and managed inference. A fork points these at its own infrastructure; a self-hosted
/// deployment supplies some and not others; a client with none is a complete client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManagedService {
    /// Account login.
    AccountLogin,
    /// Relay leases.
    RelayLeases,
    /// Push registration.
    Push,
    /// Encrypted sync and backup.
    SyncBackup,
    /// Managed inference.
    ManagedInference,
}

impl ManagedService {
    /// Every managed service, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::AccountLogin,
        Self::RelayLeases,
        Self::Push,
        Self::SyncBackup,
        Self::ManagedInference,
    ];

    /// Returns the name a report uses, which is also the name the null implementation reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountLogin => "account login",
            Self::RelayLeases => "relay leases",
            Self::Push => "push registration",
            Self::SyncBackup => "sync and backup",
            Self::ManagedInference => "managed inference",
        }
    }

    /// Returns what a client does instead when this service is not there.
    ///
    /// Every one of these is a complete way to work rather than a degraded one, which is what
    /// section 17 means by the local product being complete.
    #[must_use]
    pub const fn alternative(self) -> &'static str {
        match self {
            Self::AccountLogin => "pair devices directly and use this host without an account",
            Self::RelayLeases => "connect directly, or run your own relay",
            Self::Push => "open the app to see what is waiting",
            Self::SyncBackup => {
                "keep settings and drafts on each device, and back them up yourself"
            }
            Self::ManagedInference => "use your own provider credentials",
        }
    }
}

/// Whether one managed service has an implementation, and what to do about it when it has not.
///
/// Section 17: client entitlement state explains availability; it does not protect the business
/// model. This is an explanation and only an explanation. Nothing in this library consults it
/// before doing local work, and a client that deleted every field of [`ServiceClients`] would lose
/// the managed resources and keep the product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Availability {
    /// Which service.
    pub service: ManagedService,
    /// Whether an implementation is configured.
    ///
    /// Configured, which is the only thing a client can know without asking. It is not a claim that
    /// the service is reachable, that an account is entitled to it or that a call will succeed:
    /// [`NullService`] is configured and answers nothing. Those answers come from the calls.
    pub configured: bool,
    /// What a person is told: the service, and what they can do instead of it.
    pub explanation: String,
}

/// Every service client one client holds.
///
/// A field left `None` is a service this client does not use. Nothing degrades: the local product
/// is complete without any of them.
#[derive(Debug, Default)]
pub struct ServiceClients {
    /// Account login.
    pub account: Option<std::sync::Arc<dyn AccountService>>,
    /// Relay leases.
    pub relay_leases: Option<std::sync::Arc<dyn RelayLeaseService>>,
    /// Push registration.
    pub push: Option<std::sync::Arc<dyn PushService>>,
    /// Encrypted sync and backup.
    pub sync_backup: Option<std::sync::Arc<dyn SyncBackupService>>,
    /// Managed inference: the voice broker, which is what this product meters inference through.
    pub managed_inference: Option<std::sync::Arc<dyn ManagedVoiceService>>,
}

impl ServiceClients {
    /// Returns a set with no service configured.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns true when no managed service is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        ManagedService::ALL
            .into_iter()
            .all(|service| !self.holds(service))
    }

    /// Returns true when an implementation of `service` is configured.
    #[must_use]
    pub fn holds(&self, service: ManagedService) -> bool {
        match service {
            ManagedService::AccountLogin => self.account.is_some(),
            ManagedService::RelayLeases => self.relay_leases.is_some(),
            ManagedService::Push => self.push.is_some(),
            ManagedService::SyncBackup => self.sync_backup.is_some(),
            ManagedService::ManagedInference => self.managed_inference.is_some(),
        }
    }

    /// Returns what to say about one service.
    #[must_use]
    pub fn availability_of(&self, service: ManagedService) -> Availability {
        let configured = self.holds(service);
        let explanation = if configured {
            format!("A {} service is configured.", service.as_str())
        } else {
            format!(
                "No {} service is configured. You can {}.",
                service.as_str(),
                service.alternative()
            )
        };
        Availability {
            service,
            configured,
            explanation,
        }
    }

    /// Returns what to say about every service, in one shape.
    ///
    /// One shape, because a client that had to ask a different question of each service would end
    /// up with five ways of saying the same thing and five chances to say it differently.
    #[must_use]
    pub fn availability(&self) -> Vec<Availability> {
        ManagedService::ALL
            .into_iter()
            .map(|service| self.availability_of(service))
            .collect()
    }
}

/// A service client that reports that no service is configured.
///
/// It exists so a caller can hold a service client unconditionally and get an honest answer rather
/// than a silent default. It never pretends to succeed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullService;

fn unconfigured<T: Send + 'static>(what: &'static str) -> ServiceFuture<'static, T> {
    Box::pin(async move { Err(ClientError::ServiceNotConfigured(what)) })
}

impl AccountService for NullService {
    fn sign_in<'a>(&'a self, _authorisation_code: &'a str) -> ServiceFuture<'a, AccountSession> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }

    fn refresh<'a>(&'a self, _refresh_token: &'a str) -> ServiceFuture<'a, AccountSession> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }
}

impl RelayLeaseService for NullService {
    fn issue<'a>(&'a self, _request: &'a LeaseRequest) -> ServiceFuture<'a, RelayLeaseAnswer> {
        unconfigured(ManagedService::RelayLeases.as_str())
    }

    fn revoke<'a>(
        &'a self,
        _lease_id: RelayLeaseId,
        _reason: LeaseEndReason,
    ) -> ServiceFuture<'a, RelayLeaseEnding> {
        unconfigured(ManagedService::RelayLeases.as_str())
    }
}

impl PushService for NullService {
    fn register<'a>(&'a self, _token: &'a str) -> ServiceFuture<'a, PushRegistration> {
        unconfigured(ManagedService::Push.as_str())
    }

    fn revoke<'a>(&'a self, _installation_id: InstallationId) -> ServiceFuture<'a, ()> {
        unconfigured(ManagedService::Push.as_str())
    }
}

impl SyncBackupService for NullService {
    fn compare_exchange<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }
}

impl ManagedVoiceService for NullService {
    fn provider(&self) -> String {
        "none".to_owned()
    }

    fn start<'a>(
        &'a self,
        _request: &'a voice::VoiceSessionRequest,
    ) -> ServiceFuture<'a, voice::VoiceStart> {
        unconfigured(ManagedService::ManagedInference.as_str())
    }

    fn close<'a>(&'a self, _call_id: &'a str) -> ServiceFuture<'a, voice::VoiceClosure> {
        unconfigured(ManagedService::ManagedInference.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::error::ErrorCode;

    #[tokio::test]
    async fn the_null_service_says_so_rather_than_pretending() {
        let error = NullService
            .sign_in("code")
            .await
            .expect_err("nothing is configured");
        assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        assert!(error.to_string().contains("account login"));

        let request = LeaseRequest {
            source: EndpointKey::from_bytes([1; 32]),
            destination: EndpointKey::from_bytes([2; 32]),
            direction: RelayDirection::Bidirectional,
            byte_ceiling: 8 * 1024 * 1024,
            duration_seconds: 300,
            region_preference: None,
            payer: None,
            lease_id: None,
        };
        let error = NullService
            .issue(&request)
            .await
            .expect_err("nothing is configured");
        assert!(error.to_string().contains("relay leases"));
    }

    #[test]
    fn a_client_with_no_managed_service_is_still_a_client() {
        let clients = ServiceClients::none();
        assert!(clients.is_empty());
    }

    #[test]
    fn what_a_json_failure_says_carries_none_of_the_document_it_was_about() {
        use rendering::NEVER_RENDERED;

        /// Stands for anything this module reads out of a document.
        #[derive(Debug, serde::Deserialize)]
        struct Shape {
            #[allow(dead_code, reason = "the failure to read it is the subject")]
            member: u8,
        }

        let rejected = serde_json::from_str::<Shape>(&format!(r#""{NEVER_RENDERED}""#))
            .expect_err("that is not the shape");
        // The control: serde's own message really does quote what it rejected, so the assertion
        // below is about what this module says rather than about a message that never had it.
        assert!(rejected.to_string().contains(NEVER_RENDERED), "{rejected}");
        let said = json_fault(&rejected);
        assert!(!said.contains(NEVER_RENDERED), "{said}");
        assert!(
            said.contains("is not the shape this client reads"),
            "{said}"
        );
        assert!(said.contains("line 1"), "{said}");

        let broken = serde_json::from_str::<Shape>("{").expect_err("that is not JSON");
        assert!(json_fault(&broken).contains("ended early"));
    }

    #[test]
    fn an_operation_that_answers_with_a_page_is_read_under_its_own_bound() {
        let limits = managed_response_limits();
        assert_eq!(
            limits.of(authority::AUTHORITY_SYNC_PATH),
            authority::AUTHORITY_ANSWER_LIMIT_BYTES
        );
        assert!(
            limits.of(authority::AUTHORITY_SYNC_PATH) > http::DEFAULT_RESPONSE_LIMIT_BYTES,
            "a feed page is larger than the answer every other operation is read under"
        );
        assert_eq!(
            limits.of(mailbox::MAILBOX_READ_PATH),
            mailbox::MAILBOX_ANSWER_LIMIT_BYTES
        );
        assert_eq!(
            limits.of(mailbox::MAILBOX_DELIVER_PATH),
            http::DEFAULT_RESPONSE_LIMIT_BYTES,
            "a delivery answers with a position and a total, not with a page"
        );
        assert_eq!(
            limits.of(relay::RELAY_LEASE_PATH),
            http::DEFAULT_RESPONSE_LIMIT_BYTES
        );
    }
}
