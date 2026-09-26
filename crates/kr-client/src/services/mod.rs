//! Replaceable service clients.
//!
//! Section 17: `kr-client` has replaceable service clients for account login, relay leases, push,
//! encrypted sync/backup and managed inference. The boundary matters more than the implementations:
//! all local host and client functionality is open source, the hosted service sells provider usage,
//! storage, relay bandwidth and operation, and a fork can point these traits at its own
//! infrastructure without changing anything else in the client.
//!
//! The traits and one null implementation live here, and eleven modules hold the managed
//! implementations this crate carries. [`account`] is the account sign-in: the request a system
//! browser is handed, the checks on what comes back, and the grant a device keeps under one lock,
//! with the account service's trait beside them. [`relay`] is the relay-lease client, because a lease is the
//! one managed resource a client cannot do without and still use a relay at all. [`voice`] is the
//! voice broker, because a managed call is created by one request whose exact shape both the host
//! and the companion have to agree on. [`authority`] is the durable authority feed, where a remote
//! owner publishes a signed revocation request and the host that owns the feed acknowledges what it
//! applied. [`mailbox`] is the encrypted mailbox, where a device leaves a sealed item for a peer
//! that is not connected and the peer reads its own. [`sync`] is settings sync, the
//! compare-and-exchange service settings, a client's position and drafts are kept on. [`storage`] is
//! managed storage, where an account's backup ciphertext is uploaded part by part and read back,
//! and [`backup`] is the backup manifest, where a collection's writer is enrolled and each
//! generation's descriptor is published and fetched. [`signed`] is
//! the one signed call those of them that speak the section 23 `Services` group share, and [`http`]
//! is the exchange underneath all of them: one gateway origin, finite deadlines, bounded answers
//! and no retry of its own. [`json`] is the one reader of what any of them is answered, and it
//! refuses an answer that names a member twice before anything reads it. A self-hosted deployment
//! supplies its own, and a client with no managed service configured is a complete client: direct
//! connections, local sessions, plugins, local descriptions and user-operated alternatives need
//! none of these.
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
//! | [`account::AccountToken`], [`account::RefreshToken`] | A bearer token | A placeholder |
//! | [`account::AuthorisationRequest`], [`account::AuthorisationGrant`] | A state, a verifier, a nonce and a code | The client, the redirect, the attempt |
//! | [`account::IssuedGrant`], [`account::StoredGrant`] | Tokens and a nonce | The lifetime or the grant's identifier and revision, the client, the scopes |
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
//! | [`sync::SyncHeldObject`] | A sealed object a collection holds | The object, its kind, where it stands, its key epoch |
//! | [`sync::SyncHeldCopy`] | A sealed copy of a refused write | The copy, its object and kind, where the object stood, its key epoch |
//! | [`SyncFetched`] | A sealed object one fetch found | Where the object stands, or the history that holds none |
//! | [`storage::UploadPart`] | A part's ciphertext | Its number and length |
//! | [`storage::ObjectRange`] | A range of stored ciphertext | Where it starts and its length |
//! | [`backup::FetchedGeneration`] | A writer's publication: every wrapped manifest key and a signature | The archive and the generation |
//! | `signed::Content` | What a read was answered with: ciphertext | Its length, or the refusal's code and status |
//!
//! A type that holds one of these only through one of these, as [`relay::RelayLeaseAnswer`] holds a
//! grant, is safe to derive, because the rendering it composes is the redacted one.
//!
//! Eleven tests are that rule's proof:
//! `a_rendering_of_a_request_a_grant_or_a_token_carries_none_of_them` in [`account`],
//! `a_rendering_of_a_request_a_credential_or_an_answer_carries_none_of_it` and
//! `a_rendering_of_an_issued_lease_carries_neither_the_lease_nor_its_signature` in [`relay`],
//! `a_rendering_of_a_call_carries_neither_its_offer_its_answer_nor_what_was_said` in [`voice`],
//! `a_rendering_of_a_signed_request_carries_neither_its_body_nor_its_credential` in [`signed`],
//! `a_rendering_of_a_request_or_an_answer_carries_neither_a_signature_nor_a_sealed_item` in
//! [`authority`], and
//! `a_rendering_of_a_request_an_item_or_a_page_carries_neither_a_claim_nor_a_sealed_item` in
//! [`mailbox`],
//! `a_rendering_of_a_request_an_object_or_a_copy_carries_nothing_sealed` in [`sync`],
//! `a_rendering_of_a_part_or_a_range_carries_its_length_and_never_its_ciphertext` in [`storage`],
//! `a_rendering_of_a_fetched_generation_carries_neither_its_publication_nor_its_signature` in
//! [`backup`], and `a_rendering_of_content_carries_its_length_and_never_its_bytes` in [`signed`].
//! Each holds the type it covers to the exact fields above, in both `{:?}` and `{:#?}`, which is
//! stronger than looking for a marker: a rendering that printed the bytes as decimals would pass a
//! search for text and fail this. The enclosing types that only compose these, such as
//! [`relay::RelayLeaseAnswer`] and [`voice::VoiceStart`], are checked for the marker instead,
//! because what they render is whatever the redacted type gave them.
//!
//! The same rule covers what a failure says. `serde_json`'s own message quotes the value it
//! rejected (`invalid type: string "..."`), so an error that carried that text would print
//! through [`std::fmt::Display`] the very thing the Debug rule keeps out of `{:?}`. Nothing here
//! formats a JSON error into a message: [`crate::shown::Shown::json`] is what a caller is told
//! instead, and [`json::Unreadable`] about an answer, and both carry the class and the position and
//! nothing that was in the document.
//!
//! One thing is deliberately not covered by it. A refusal the service sent carries the service's
//! own message, which is written to be shown to a person, and that message is in the error this
//! client returns, through [`crate::shown::Shown::service`], whose one input only this module's
//! refusal readers can make. What is never in it is anything else of the answer. The one refusal whose words
//! are this client's is settings sync's `SIGNED_BEFORE_CUTOFF` outside an exchange, because the
//! service words it for a write and what the person needs is what it means for their request.

pub mod account;
pub mod authority;
pub mod backup;
pub mod http;
pub mod json;
pub mod mailbox;
pub mod relay;
pub mod signed;
pub mod storage;
pub mod sync;
pub mod voice;

use std::future::Future;
use std::pin::Pin;

use kr_protocol::archive::{BackupGenerationPublication, BackupWriterRecord};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, InstallationId, RelayLeaseId, SyncConflictId,
};
use kr_protocol::pairing::GenerationCheckpoint;
use kr_protocol::scalars::{EndpointKey, Nullable, Uuid};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

pub use account::{
    AccountHttp, AccountService, AccountToken, AccountTokenSource, ManagedAccountService,
    SignedInAccount,
};
pub use authority::{
    AnnouncementOutcome, AnnouncementPlacement, AuthorityFeedClient, AuthorityFeedRecord,
    AuthorityFeedState, AuthorityFeedSummary, FeedAnnouncement, RejectionReason,
};
pub use backup::{
    CollectionSummary, Enrolled, FetchedGeneration, GenerationSummary,
    ManagedBackupManifestService, Published, WriterSummary,
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
pub use storage::{
    ArchiveAnswer, BackupState, ManagedStorageService, NewUpload, ObjectDeleted, ObjectRange,
    PartStored, PartTable, RetentionAnswer, RetentionChange, RetentionPolicy, RetentionSet,
    RetentionState, StorageLimits, StoragePrincipal, StorageStatus, StorageUsage, StoredObject,
    UploadAborted, UploadCompleted, UploadCreated, UploadId, UploadPart, UploadProgress,
    upload_parts,
};
pub use sync::{
    Inventory, InventoryCopy, InventoryObject, ManagedSyncService, MembershipListing,
    SyncComparison, SyncHeldCopy, SyncHeldObject, SyncUsage,
};
pub use voice::{
    ManagedVoiceBroker, ManagedVoiceService, VoiceClosure, VoiceCommand, VoiceContextFrame,
    VoiceControlEvent, VoiceRefusal, VoiceRefusalReason, VoiceSession, VoiceSessionRequest,
    VoiceStart,
};

/// A boxed future, so every service client stays usable behind a trait object.
pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

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
        .for_path(sync::SYNC_EXCHANGE_PATH, sync::SYNC_ANSWER_LIMIT_BYTES)
        .for_path(
            storage::STORAGE_READ_PATH,
            storage::STORAGE_READ_ANSWER_LIMIT_BYTES,
        )
        .for_path(
            backup::BACKUP_MANIFEST_PATH,
            backup::BACKUP_ANSWER_LIMIT_BYTES,
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
#[derive(Clone, PartialEq, Eq)]
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
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
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

impl crate::shown::Said for SyncRevision {
    fn said(&self) -> crate::shown::Shown {
        crate::shown!("{}", self.0)
    }
}

crate::display_as_said!(SyncRevision);

/// The identity of one restore of a synchronisation service: the history a collection answers from.
///
/// A place in a collection's order is a place in one history, and a restore rewinds a history. A
/// service put back from an export records the recovery with an identity of its own, and every
/// collection it writes back, and every collection created in it afterwards, names that identity
/// beside every place it answers with. So positions compare only under one identity: a device that
/// holds a position under one and meets another has met a collection that was put back, not one that
/// went backwards or forked, and what it held is not a place in the history it is now reading.
///
/// A service that has never been put back names none, which this client carries as no identity.
/// The identity changes only when a restore writes the collection back, never while it serves, and
/// two identities say nothing about which restore came first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncRecoveryId(pub Uuid);

impl SyncRecoveryId {
    /// Wraps the identity a service's restore recorded.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identity.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl crate::shown::Said for SyncRecoveryId {
    fn said(&self) -> crate::shown::Shown {
        crate::shown!("{}", self.0)
    }
}

crate::display_as_said!(SyncRecoveryId);

/// Whether a stored record's recovery names none, in which case the record leaves the member out.
///
/// A record stored before the member existed is a record in a history never put back, so leaving
/// it out for that history is what keeps such a record the shape it always had: the store's reader
/// re-encodes every record it reads and refuses one that does not come back as the same bytes, and
/// both an old record and a new one in that history do.
pub(crate) const fn names_no_recovery(recovery: &Nullable<SyncRecoveryId>) -> bool {
    !recovery.is_present()
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
/// A removal takes a place in that order as well, and it has no revision, because there is no
/// state of the object for one to name. So a position with no revision is the removal of the
/// object at that place in the order, and it is not the same thing as **no position at all**: that
/// is an object nothing has ever written, which a comparison compares against nothing. A device
/// that forgot the removal's place in the order would read the next answer it saw as a service
/// that had gone back.
///
/// A place in the order is a place in one history, so a position names the history too: the
/// [`SyncRecoveryId`] the answer it came from named, or none for a service never put back. Two
/// positions compare only when they name the same one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPosition {
    /// Where this write falls in the collection's order. The first is one.
    pub write_sequence: u64,
    /// The name the service gave this write, or null where the write was a removal.
    ///
    /// Null is present and null rather than absent: a stored position that simply lacked the field
    /// would be read as a removal, and a record read as something it is not is worse than a record
    /// this build refuses.
    pub revision: Nullable<SyncRevision>,
    /// The history this place is in: the recovery the answer named, or null for a service never put
    /// back.
    ///
    /// Stored only when it names one, so a position in a history never put back keeps the shape it
    /// had before the member existed, and a position stored then reads as null. That is how this
    /// client read every answer then, so it is a statement of what was recorded rather than a
    /// reconstruction of what the service said: a service put back before then names its identity
    /// on its next answer, and that answer reads as a collection put back, which compares nothing
    /// across the two.
    #[serde(default = "Nullable::null", skip_serializing_if = "names_no_recovery")]
    pub recovery: Nullable<SyncRecoveryId>,
}

impl SyncPosition {
    /// The place one write of the object took, under the name the service gave it, in the history
    /// `recovery` names.
    #[must_use]
    pub const fn at(
        write_sequence: u64,
        revision: SyncRevision,
        recovery: Option<SyncRecoveryId>,
    ) -> Self {
        Self {
            write_sequence,
            revision: Nullable::some(revision),
            recovery: Nullable(recovery),
        }
    }

    /// The place the removal of the object took, in the history `recovery` names.
    ///
    /// The object is not there, and this says where in the order it stopped being there. The
    /// comparison that replaces it therefore names no object, and the order it is measured against
    /// carries on from here.
    #[must_use]
    pub const fn removed_at(write_sequence: u64, recovery: Option<SyncRecoveryId>) -> Self {
        Self {
            write_sequence,
            revision: Nullable::null(),
            recovery: Nullable(recovery),
        }
    }

    /// Returns true when this position is the removal of the object rather than a write of it.
    #[must_use]
    pub const fn is_removal(&self) -> bool {
        !self.revision.is_present()
    }

    /// Returns the recovery whose history this place is in, or none for a service never put back.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        self.recovery.0
    }
}

impl crate::shown::Said for SyncPosition {
    fn said(&self) -> crate::shown::Shown {
        let place = match self.revision.as_ref() {
            Some(revision) => crate::shown!("write {} ({})", self.write_sequence, *revision),
            None => crate::shown!("write {} (removed)", self.write_sequence),
        };
        match self.recovery() {
            Some(recovery) => crate::shown!("{} after recovery {}", place, recovery),
            None => place,
        }
    }
}

crate::display_as_said!(SyncPosition);

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
        /// Where the object stood when the refusal was answered: the write that beat this one, or
        /// the place a removal took, and nothing when the collection had never held the object.
        ///
        /// An answer given again from a receipt names where the object stood when the first attempt
        /// was answered, not where it stands now.
        current: Option<SyncPosition>,
        /// The history the refusal was answered in, which [`Self::Refused::current`] names too when
        /// there is one. It is here for the refusal of an object the collection had never held,
        /// which names no place and still says which history of the collection holds nothing.
        recovery: Option<SyncRecoveryId>,
    },
    /// The service refused this attempt as signed before the collection's cutoff.
    ///
    /// A service keeps a receipt for a while and no longer, so a request signed long enough ago
    /// could be one it ran and no longer holds the receipt of. It therefore ran nothing, recorded
    /// nothing, and runs no attempt signed then. That ends the attempt, and the request with it:
    /// presenting the identity again, signed now, could run the work a second time. It says
    /// nothing of an earlier attempt under the same identity, which may have run.
    SignedBeforeCutoff,
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
        /// The history the collection answered from, as it stands now.
        recovery: Option<SyncRecoveryId>,
    },
    /// The service holds no receipt for this request.
    ///
    /// Two different things look like this from here: a request that has not been executed, which
    /// may still be on its way, and a receipt that has passed section 9's thirty-day retention.
    /// Neither establishes that the write did not land, which is why this is one answer rather than
    /// two, and why it settles nothing on its own. A third joins them once a collection has been put
    /// back: a request the replaced history ran and whose receipt no archive brought back.
    Unknown {
        /// The history the collection answered from.
        recovery: Option<SyncRecoveryId>,
    },
    /// The request was fenced before the service executed it, so it never will be.
    Fenced {
        /// Whether the service also established that the request never ran.
        ///
        /// The fence receipt recorded it when the fence was made, and this repeats it, so asking
        /// again about a fenced request concludes exactly what the fence concluded.
        never_ran: bool,
        /// The history the collection answered from, as it stands now.
        recovery: Option<SyncRecoveryId>,
    },
}

impl SyncRequestStatus {
    /// Returns the history this answer came from: the recovery it named, or none for a service
    /// never put back.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Applied { position } => position.recovery(),
            Self::Refused { recovery, .. }
            | Self::Unknown { recovery }
            | Self::Fenced { recovery, .. } => *recovery,
        }
    }
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
        /// The history the collection answered from, as it stands now.
        recovery: Option<SyncRecoveryId>,
    },
    /// The request is fenced: nothing will execute under this identity.
    ///
    /// The service recorded no outcome for the identity and refuses anything that arrives under it
    /// afterwards, which is what ends the request.
    Fenced {
        /// Whether the service also established that the request never ran.
        ///
        /// Two different questions, and the fence answers the second only sometimes. That nothing
        /// *will* run is what the fence itself makes true. That nothing *ran* is a statement about
        /// the past, and the service is what can make it: it holds the receipt of every request it
        /// executed, it knows how far back its own receipts still reach, and it compares the two
        /// against the signing times the fence carried. A caller does no arithmetic of its own
        /// here, because every fact in that comparison is the service's.
        ///
        /// False says only that the service could not establish it, never that the request ran. So
        /// a caller keeps whatever account it owes for content that left the device. A collection
        /// put back answers false for a while for every request signed before the restore, because
        /// the history it replaced may have run them.
        never_ran: bool,
        /// The history the collection answered from, as it stands now. The fence holds in that
        /// history, which is the one the service serves.
        recovery: Option<SyncRecoveryId>,
    },
}

impl SyncRequestFence {
    /// Returns the history this answer came from: the recovery it named, or none for a service
    /// never put back.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Applied { position } => position.recovery(),
            Self::Refused { recovery, .. } | Self::Fenced { recovery, .. } => *recovery,
        }
    }
}

/// What one fetch found in a collection: the object, or that the collection holds none.
///
/// Both answers name a history. An object names it through the place it is held at. An absence
/// names it beside what it says, because a collection that holds nothing is an answer about one
/// history of it: a collection put back from an archive that did not hold the object holds nothing
/// in the history the restore began, and a caller that read that as nothing new would go on
/// comparing against a place, and presenting work attempted in, the history the restore replaced.
///
/// It holds a sealed object, so it writes its own [`std::fmt::Debug`]: where the object stands, or
/// the history that holds none, and nothing sealed.
#[derive(Clone, PartialEq, Eq)]
pub enum SyncFetched {
    /// The collection holds the object.
    Held {
        /// Where the object stands: the write that put it there, and that write's place in the
        /// order.
        position: SyncPosition,
        /// The sealed object, in canonical KR-CBOR-1, which is what a sealer opens.
        ciphertext: Vec<u8>,
    },
    /// The collection holds no object.
    Absent {
        /// The history that holds none: the recovery the service named, or none for a service never
        /// put back.
        recovery: Option<SyncRecoveryId>,
    },
}

impl SyncFetched {
    /// Returns the history this answer came from: the recovery it named, or none for a service
    /// never put back.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Held { position, .. } => position.recovery(),
            Self::Absent { recovery } => *recovery,
        }
    }
}

impl std::fmt::Debug for SyncFetched {
    /// Where the object stands, or the history that holds none. Never the sealed object.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held { position, .. } => formatter
                .debug_struct("Held")
                .field("position", position)
                .finish_non_exhaustive(),
            Self::Absent { recovery } => formatter
                .debug_struct("Absent")
                .field("recovery", recovery)
                .finish(),
        }
    }
}

/// What a caller reports when a collection holds none of what it fetched, in the history of the
/// collection it reads.
///
/// The service answered: the collection holds nothing, so what was asked for by name is unknown to
/// the service. A caller reports it only once it has read the absence against the history of the
/// collection, because an absence in another history says something else.
#[must_use]
pub fn nothing_held(what: impl Into<crate::shown::Shown>) -> ClientError {
    ClientError::refusal(
        kr_protocol::error::ErrorCode::UnknownSession,
        crate::shown!("the service holds no {} in that collection", what.into()),
    )
}

/// What became of one request, for a caller that has to know whether one that went unanswered
/// ever left this device.
///
/// An error beside it is a request that may have left: its answer never came back, or came back in
/// a form nobody can read, and the service may have acted on it.
#[derive(Debug)]
pub enum Dispatched<T> {
    /// The service answered.
    Answered(T),
    /// Refused on this device before anything was sent, so the service cannot have acted on it.
    NotSent(ClientError),
}

/// What became of one exchange, for a caller that has to know whether a request that went
/// unanswered ever left this device.
///
/// An error beside it is a request that may have left: its answer never came back, or came back in
/// a form nobody can read, and the service may have run it.
#[derive(Debug)]
pub enum SyncDispatch {
    /// The service answered.
    Answered(SyncExchanged),
    /// Refused on this device before anything was sent, so nothing can run under the request's
    /// identity.
    NotSent(ClientError),
}

/// Where a shared collection's key records stood when a service answered: the newest record's key
/// epoch and its revision.
///
/// A device that holds an older revision fetches the records after it before it trusts anything
/// sealed under a newer epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyHead {
    /// The epoch of the key the newest record carries.
    pub epoch: u64,
    /// The newest record's revision.
    pub revision: u64,
    /// The history that revision is a place in: the recovery the answer named, or none for a
    /// service never put back. Two revisions compare only under one.
    pub recovery: Option<SyncRecoveryId>,
}

/// What a service answered about one request in a collection two or more devices share.
///
/// Two answers beyond those a collection only its home writes can give. A write sealed under an
/// epoch the collection has retired is refused, stores nothing and holds nothing, and the refusal
/// is that request's receipt. And a collection that does not exist is answered exactly as one whose
/// newest key record does not list the caller, so the two cannot be told apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyed<T> {
    /// The service answered.
    Answered {
        /// What it answered.
        answer: T,
        /// Where the collection's key records stood, as the answer named it. An answer that names
        /// no receipt names no key records either.
        head: Option<KeyHead>,
    },
    /// The request named a key epoch the collection has retired.
    ///
    /// It ends the attempt that met it and says nothing of an earlier attempt under the same
    /// identity: one whose receipt the service no longer holds may have run.
    Retired {
        /// The collection's epoch and revision, as the refusal named them.
        head: KeyHead,
    },
    /// The collection does not exist, or its newest key record does not list this device.
    Absent,
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
/// 3. **A position is absent only when nothing has ever been there.** [`Self::compare_exchange`]
///    takes no expected position for a first write, and answers a position for every write it
///    applies. A removal is a place in the order with no revision
///    ([`SyncPosition::removed_at`]), so a caller replacing what a removal left behind names that
///    position, and the implementation compares it against no object while keeping the order it
///    carries.
/// 4. **A fence ends a request.** [`Self::fence_request`] never answers that it does not know:
///    either the service has already decided the request, or the fence decides it, and an exchange
///    arriving under a fenced identity afterwards executes nothing.
/// 5. **The service says whether the request ran.** A fence answers `never_ran: true` only where
///    the service can establish that no receipt for the identity has ever been removed, and it
///    keeps the fence itself until no attempt the caller named can still become fresh. Both are
///    statements about the service's own records, which is why they are the service's to make: a
///    caller putting its clock against the service's could be wrong about either, and a caller
///    that concluded wrongly would delete the account of content it had uploaded.
/// 6. **A copy goes when the person has chosen.** [`Self::resolve`] drops the copy a refusal
///    named, and answers a copy that is already gone the same way rather than failing, so a caller
///    unsure whether its resolution arrived asks again.
/// 7. **Every answer names its history.** A position carries the [`SyncRecoveryId`] its answer
///    named, and an answer that names no position carries it beside what it says, so a caller can
///    tell a collection put back from one that went backwards or forked. The identity is the
///    service's to state: an implementation passes on the one it was given and invents none, and an
///    answer that states none is not one it can pass on.
pub trait SyncBackupService: Send + Sync + std::fmt::Debug {
    /// Publishes an encrypted object, comparing against where the caller last saw the object.
    ///
    /// `expected` is the position this caller is replacing, and `None` says the caller believes
    /// nothing has ever been there. A position whose revision is null is the removal of the object,
    /// so the comparison it names is against no object while the order it carries is kept. The
    /// service compares, applies the write and answers the position it assigned, or refuses because
    /// the object is somewhere else.
    ///
    /// `request_id` names this request. It is the de-duplication key of section 9 and it belongs
    /// to the piece of work rather than to the object, so a retry of the same work presents the
    /// same identity and is answered from the receipt instead of being applied twice. Presenting
    /// one identity with different content is refused as `ID_CONFLICT`, and presenting a fenced
    /// identity is refused as `REQUEST_FENCED`.
    ///
    /// `signed_at_ms` is the instant this attempt is signed at, and the caller states it rather
    /// than the implementation reading a clock of its own. The service admits a request only within
    /// its freshness window of that instant and checks it again where the request acts, so the
    /// signing time is what bounds when a request can have run. A caller records the instant it
    /// sent and presents it again when it fences the identity, which is what lets the service say
    /// whether anything ran. An implementation signs with this value and does not substitute
    /// another: a retry is a fresh attempt with a fresh signing time the caller supplies, never the
    /// same attempt re-dated.
    ///
    /// An attempt signed before the collection's cutoff is refused without running, and the
    /// refusal is an answer about that attempt: [`SyncExchanged::SignedBeforeCutoff`].
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged>;

    /// Publishes an encrypted object as [`Self::compare_exchange`] does, and says when the request
    /// never left this device.
    ///
    /// A caller that records a write before it sends it needs one fact more than the answer:
    /// whether a request that went unanswered was sent at all. One refused on this device before
    /// anything left cannot run, so its record can be put back as it was; one that may have left
    /// cannot be taken back, and stays outstanding until the service ends it.
    ///
    /// An implementation that can tell answers [`SyncDispatch::NotSent`] for a request it refused
    /// before anything left. The default cannot tell, so it counts every failure as possibly sent,
    /// which is the safe direction.
    fn compare_exchange_dispatched<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncDispatch> {
        Box::pin(async move {
            self.compare_exchange(collection, request_id, signed_at_ms, expected, ciphertext)
                .await
                .map(SyncDispatch::Answered)
        })
    }

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
    ///
    /// It also says whether anything ever ran under the identity, and the service is what says it.
    /// `first_signed_at_ms` and `last_signed_at_ms` are the earliest and the latest instant the
    /// caller signed an attempt at, which is not the same as the first and the last it made: a
    /// device's clock can be corrected between two attempts, so the pair is ordered rather than
    /// sequenced, and `first_signed_at_ms` is never after `last_signed_at_ms`. The service reads
    /// the earliest to decide [`SyncRequestFence::Fenced::never_ran`]: a receipt of any run would
    /// bear an instant no earlier than that signing time less its freshness window, so the service
    /// can say whether a receipt that old would still be there. It reads the latest to keep the
    /// fence itself alive: an attempt can become fresh up to a window after it was signed, so the
    /// fence outlives every attempt the caller made, however wrong this device's clock was when it
    /// signed them.
    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence>;

    /// Fetches an encrypted object and the position it is held at, or the history of a collection
    /// that holds none.
    ///
    /// The position comes back with the bytes because a caller that fetched after losing a
    /// comparison needs it to make the next one: without it, the only way to learn where the object
    /// stands is to lose again. A collection that holds nothing is an answer rather than a failure,
    /// and it names its history for the reason a refusal of an object the collection never held
    /// does: in a history the caller has not met, the collection was put back without the object.
    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched>;

    /// Drops the copy the service kept of one refused write, because the person has chosen.
    ///
    /// `retained` is the copy a refusal named, in [`SyncExchanged::Refused`] or in the receipt
    /// that recorded one. A service that keeps a refused write keeps it for a person to choose
    /// from, and once one object holds as many unresolved copies as it keeps, a write of it that
    /// loses its comparison is refused outright rather than kept. So a choice that stayed on the
    /// device would leave the copy there for good, and this is how the choice reaches the service:
    /// the copy leaves the service as well as the device.
    ///
    /// Returns true when this call dropped the copy, and false when it was already gone. Either
    /// way the service no longer holds it, which is why a repeat is safe and a caller unsure
    /// whether its resolution arrived asks again.
    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool>;
}

/// Where an account's backup ciphertext is stored and read back: managed storage.
///
/// The service holds ciphertext under a key nobody outside it knows, charged to the account whose
/// token the request carried, and it never hands out an address: every byte goes through it.
///
/// # What an implementation owes
///
/// 1. **Nothing is accepted before it is reserved.** An upload declares its maximum and its total
///    and is answered with a part table before any content leaves, and the table is arithmetic: one
///    total gives one table, every part the part size but the last.
/// 2. **A part is idempotent.** The same part sent again is answered as the part it is, and
///    nothing is written or counted twice, so a transfer that stopped goes on at the part after
///    the last one acknowledged.
/// 3. **Completion is the service's, and a repeat is answered the same.** A completion asked for
///    again after its answer was lost gets the result the first one got.
/// 4. **Two answers are about the work.** A collection deleted from the account console takes
///    nothing again, and an upload the service holds none of takes nothing: each is an
///    [`storage::ArchiveAnswer`] rather than an error, because a caller acts on it. A refusal whose
///    code covers several reasons stays the error the service named, and an upload is ended by
///    asking the service to abandon it, whose answer says it is over.
/// 5. **Nothing is sent without the account's proof.** An installation alone holds no backup
///    storage, so an implementation given no account sends no request.
/// 6. **A stale retention change is answered.** A change decided against a revision the record
///    has left is [`storage::RetentionAnswer::Stale`], carrying the retention as it stands, and
///    never an error that asks for an update.
pub trait StorageService: Send + Sync + std::fmt::Debug {
    /// What managed storage the caller's principal holds, whether backup storage is on, and the
    /// revision a change of that is decided against.
    fn status(&self) -> ServiceFuture<'_, storage::StorageStatus>;

    /// Turns backup storage on or off, against the revision the change was decided at.
    ///
    /// Backup storage is off until this turns it on, and turning it off stops new uploads and
    /// deletes nothing. A change decided against a revision the record has left changes nothing,
    /// and its answer is the retention as it stands, [`storage::RetentionAnswer::Stale`], which a
    /// caller shows and decides again against.
    fn set_retention<'a>(
        &'a self,
        change: &'a storage::RetentionChange,
    ) -> ServiceFuture<'a, storage::RetentionAnswer>;

    /// Creates one object's upload: its reservation, its identity and its part table.
    fn create_upload<'a>(
        &'a self,
        upload: &'a storage::NewUpload,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadCreated>>;

    /// Sends one part of an upload, whose bytes the service holds to the length and hash its
    /// signed request declares.
    fn upload_part<'a>(
        &'a self,
        upload_id: &'a storage::UploadId,
        part: storage::UploadPart<'a>,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::PartStored>>;

    /// Completes an upload whose parts the service holds, which stores the object.
    fn complete_upload<'a>(
        &'a self,
        upload_id: &'a storage::UploadId,
        table: &'a storage::PartTable,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadCompleted>>;

    /// Abandons an upload, which the service fences and then cleans up.
    fn abort_upload<'a>(
        &'a self,
        upload_id: &'a storage::UploadId,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadAborted>>;

    /// Reads one range of a stored object's ciphertext.
    fn read_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, storage::ObjectRange>;

    /// Deletes a stored object: a tombstone at once, and its ciphertext removed after the
    /// published window, still charged until then.
    fn delete_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
    ) -> ServiceFuture<'_, storage::ObjectDeleted>;
}

/// Where a backup collection's writer is enrolled and each generation's descriptor is published:
/// the backup manifest.
///
/// The service holds the public half of a generation and never its content, and it holds it to
/// the collection's enrolment: a publication not signed by the writer the owner enrolled, and
/// carried by that writer's own key, is refused.
pub trait BackupManifestService: Send + Sync + std::fmt::Debug {
    /// Enrols, or replaces at a higher revision, the writer that may publish one collection.
    fn enrol<'a>(&'a self, record: &'a BackupWriterRecord) -> ServiceFuture<'a, backup::Enrolled>;

    /// Publishes one generation's descriptor under the enrolled writer's signature.
    ///
    /// The same publication sent again is answered as a duplicate, so a publisher that makes it
    /// the same way every time can ask again after an answer was lost.
    fn publish<'a>(
        &'a self,
        publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<backup::Published>>;

    /// Publishes as [`Self::publish`] does, and says when the request never left this device.
    ///
    /// A publisher that went unanswered has one question: can the publication have landed? One
    /// refused on this device before anything left cannot have, so it is sent again as the first
    /// time; one that may have left is an outcome to establish with a fetch, never by sending it
    /// again in the dark. An implementation that can tell answers [`Dispatched::NotSent`] for a
    /// publication it refused before anything left. The default cannot tell, so it counts every
    /// failure as possibly sent, which is the safe direction.
    fn publish_dispatched<'a>(
        &'a self,
        publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, Dispatched<storage::ArchiveAnswer<backup::Published>>> {
        Box::pin(async move { self.publish(publication).await.map(Dispatched::Answered) })
    }

    /// Fetches one generation, or the newest, held to the checkpoint the caller already has.
    ///
    /// None when the service holds no such generation, or none as new as the checkpoint: a server
    /// that cannot meet a checkpoint answers that rather than an older generation.
    fn fetch<'a>(
        &'a self,
        archive_id: ArchiveId,
        generation: Option<BackupGeneration>,
        checkpoint: Option<&'a GenerationCheckpoint>,
    ) -> ServiceFuture<'a, Option<backup::FetchedGeneration>>;
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
#[derive(Clone, PartialEq, Eq)]
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

crate::debug_fields!(Availability {
    service,
    configured
});

/// Every service client one client holds.
///
/// A field left `None` is a service this client does not use. Nothing degrades: the local product
/// is complete without any of them.
#[derive(Default)]
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
    fn exchange<'a>(
        &'a self,
        _grant: &'a account::AuthorisationGrant,
    ) -> ServiceFuture<'a, account::Exchanged> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }

    fn refresh<'a>(
        &'a self,
        _stored: &'a account::StoredGrant,
    ) -> ServiceFuture<'a, account::Refreshed> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }

    fn revoke<'a>(&'a self, _refresh: &'a account::RefreshToken) -> ServiceFuture<'a, ()> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }

    fn identity<'a>(
        &'a self,
        _access: &'a AccountToken,
    ) -> ServiceFuture<'a, account::AccountIdentity> {
        unconfigured(ManagedService::AccountLogin.as_str())
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, account::AccountUsage> {
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
        _signed_at_ms: u64,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    /// Nothing is configured, so nothing is sent.
    fn compare_exchange_dispatched<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _signed_at_ms: u64,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncDispatch> {
        Box::pin(async move {
            Ok(SyncDispatch::NotSent(ClientError::ServiceNotConfigured(
                ManagedService::SyncBackup.as_str(),
            )))
        })
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
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }
}

impl StorageService for NullService {
    fn status(&self) -> ServiceFuture<'_, storage::StorageStatus> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn set_retention<'a>(
        &'a self,
        _change: &'a storage::RetentionChange,
    ) -> ServiceFuture<'a, storage::RetentionAnswer> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn create_upload<'a>(
        &'a self,
        _upload: &'a storage::NewUpload,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadCreated>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn upload_part<'a>(
        &'a self,
        _upload_id: &'a storage::UploadId,
        _part: storage::UploadPart<'a>,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::PartStored>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn complete_upload<'a>(
        &'a self,
        _upload_id: &'a storage::UploadId,
        _table: &'a storage::PartTable,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadCompleted>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn abort_upload<'a>(
        &'a self,
        _upload_id: &'a storage::UploadId,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<storage::UploadAborted>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn read_object(
        &self,
        _archive_id: ArchiveId,
        _object_id: BackupObjectId,
        _offset: u64,
        _length: u64,
    ) -> ServiceFuture<'_, storage::ObjectRange> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn delete_object(
        &self,
        _archive_id: ArchiveId,
        _object_id: BackupObjectId,
    ) -> ServiceFuture<'_, storage::ObjectDeleted> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }
}

impl BackupManifestService for NullService {
    fn enrol<'a>(&'a self, _record: &'a BackupWriterRecord) -> ServiceFuture<'a, backup::Enrolled> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn publish<'a>(
        &'a self,
        _publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, storage::ArchiveAnswer<backup::Published>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    /// Nothing is configured, so nothing is sent.
    fn publish_dispatched<'a>(
        &'a self,
        _publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, Dispatched<storage::ArchiveAnswer<backup::Published>>> {
        Box::pin(async {
            Ok(Dispatched::NotSent(ClientError::ServiceNotConfigured(
                ManagedService::SyncBackup.as_str(),
            )))
        })
    }

    fn fetch<'a>(
        &'a self,
        _archive_id: ArchiveId,
        _generation: Option<BackupGeneration>,
        _checkpoint: Option<&'a GenerationCheckpoint>,
    ) -> ServiceFuture<'a, Option<backup::FetchedGeneration>> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }
}

impl ManagedVoiceService for NullService {
    fn metadata(&self) -> ServiceFuture<'_, Option<voice::VoiceMetadata>> {
        unconfigured(ManagedService::ManagedInference.as_str())
    }

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
        let error = AccountService::revoke(
            &NullService,
            &account::RefreshToken::new("a-refresh-token").expect("a token"),
        )
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

    /// A client with no sync service sends nothing, so an exchange it is asked for says it never
    /// left, and a caller that recorded the write before sending can take the record back.
    #[tokio::test]
    async fn the_null_service_sends_no_exchange_and_says_so() {
        let dispatched = NullService
            .compare_exchange_dispatched(
                "settings/00000000-0000-4000-8000-000000000001",
                Uuid::from_bytes([1; 16]),
                1,
                None,
                b"sealed",
            )
            .await
            .expect("an answer about the request");
        let SyncDispatch::NotSent(refused) = dispatched else {
            panic!("nothing is configured, so nothing was sent: {dispatched:?}");
        };
        assert_eq!(refused.code(), ErrorCode::HostNotConfigured);
        assert!(refused.to_string().contains("sync and backup"));
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
        let said = crate::shown::Shown::json(&rejected).into_string();
        assert!(!said.contains(NEVER_RENDERED), "{said}");
        assert!(
            said.contains("is not the shape this client reads"),
            "{said}"
        );
        assert!(said.contains("line 1"), "{said}");

        let broken = serde_json::from_str::<Shape>("{").expect_err("that is not JSON");
        assert!(
            crate::shown::Shown::json(&broken)
                .as_str()
                .contains("ended early")
        );
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
        assert_eq!(
            limits.of(sync::SYNC_EXCHANGE_PATH),
            sync::SYNC_ANSWER_LIMIT_BYTES,
            "every settings-sync member shares one path, so the path carries the largest answer"
        );
        assert_eq!(
            limits.of(storage::STORAGE_READ_PATH),
            storage::STORAGE_READ_ANSWER_LIMIT_BYTES,
            "a read answers with up to a whole range of ciphertext"
        );
        const {
            assert!(storage::STORAGE_READ_ANSWER_LIMIT_BYTES > storage::MAX_STORAGE_READ_BYTES);
        }
        assert_eq!(
            limits.of(storage::STORAGE_UPLOAD_PART_PATH),
            http::DEFAULT_RESPONSE_LIMIT_BYTES,
            "a part answers with counts, not with content"
        );
        assert_eq!(
            limits.of(backup::BACKUP_MANIFEST_PATH),
            backup::BACKUP_ANSWER_LIMIT_BYTES,
            "a fetch answers with a whole publication"
        );
    }
}
