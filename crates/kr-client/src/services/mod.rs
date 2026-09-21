//! Replaceable service clients.
//!
//! Section 17: `kr-client` has replaceable service clients for account login, relay leases, push,
//! encrypted sync/backup and managed inference. The boundary matters more than the implementations:
//! all local host and client functionality is open source, the hosted service sells provider usage,
//! storage, relay bandwidth and operation, and a fork can point these traits at its own
//! infrastructure without changing anything else in the client.
//!
//! The traits and one null implementation live here, and three modules hold the managed
//! implementations this crate carries. [`relay`] is the relay-lease client, because a lease is the
//! one managed resource a client cannot do without and still use a relay at all. [`voice`] is the
//! voice broker, because a managed call is created by one request whose exact shape both the host
//! and the companion have to agree on. [`http`] is the exchange underneath them: one gateway
//! origin, finite deadlines, bounded answers and no retry of its own. A self-hosted deployment
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
//! here derives [`std::fmt::Debug`] over request or answer bytes, a credential, a signature or a
//! header value.** Each such type writes its own, naming the operation, the class and the length
//! and nothing that travelled:
//! [`ServiceHttpAnswer`], [`relay::RelayRequestPayload`], [`relay::RelayRequestSignature`],
//! [`relay::SignedRelayRequest`] and [`voice::AccountToken`]. A type that holds one of them only
//! through one of those, as [`AccountSession`] holds a token, is safe to derive, because the
//! rendering it composes is the redacted one.
//!
//! `a_rendering_of_a_request_a_credential_or_an_answer_carries_none_of_it` in [`relay`] is that
//! rule's proof: it formats every one of them, and the error type, around a marker with `{:?}` and
//! `{:#?}` and holds each rendering to the exact fields named above.

pub mod http;
pub mod relay;
pub mod voice;

use std::future::Future;
use std::pin::Pin;

use kr_protocol::ids::{InstallationId, RelayLeaseId};
use kr_protocol::scalars::EndpointKey;

use crate::error::{ClientError, Result};

pub use http::{HttpDeadlines, HttpService, ResponseLimits};
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

/// Where encrypted settings and backups are exchanged.
///
/// The service stores ciphertext. It never holds the keys, so a compare-and-exchange here is over
/// opaque bytes.
pub trait SyncBackupService: Send + Sync + std::fmt::Debug {
    /// Publishes an encrypted object under a compare-and-exchange generation.
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        expected_generation: u64,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, u64>;

    /// Fetches an encrypted object and the generation it is held at.
    ///
    /// The generation comes back with the bytes because a caller that fetched after losing a
    /// comparison needs it to make the next one: without it, the only way to learn where the object
    /// stands is to lose again.
    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (u64, Vec<u8>)>;
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
        _expected_generation: u64,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, u64> {
        unconfigured(ManagedService::SyncBackup.as_str())
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, (u64, Vec<u8>)> {
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
}
