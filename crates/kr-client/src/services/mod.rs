//! Replaceable service clients.
//!
//! Section 17: `kr-client` has replaceable service clients for account login, relay leases, push,
//! encrypted sync/backup and managed inference. The boundary matters more than the implementations:
//! all local host and client functionality is open source, the hosted service sells provider usage,
//! storage, relay bandwidth and operation, and a fork can point these traits at its own
//! infrastructure without changing anything else in the client.
//!
//! The traits and one null implementation live here, and [`relay`] holds the one managed
//! implementation this crate carries: the relay-lease client, because a lease is the one managed
//! resource a client cannot do without and still use a relay at all. A self-hosted deployment
//! supplies its own, and a client with no managed service configured is a complete client: direct
//! connections, local sessions, plugins, local descriptions and user-operated alternatives need
//! none of these.

pub mod relay;

use std::future::Future;
use std::pin::Pin;

use kr_protocol::ids::{InstallationId, RelayLeaseId};
use kr_protocol::scalars::EndpointKey;

use crate::error::{ClientError, Result};

pub use relay::{
    ManagedRelayLeaseService, RelayAllowance, RelayGraceRemainder, RelayLeaseAnswer,
    RelayLeaseEnding, RelayLeaseGrant, RelayLeaseRefusal, RelayWarning, ServiceHttp,
    ServiceHttpAnswer, ServiceSigner,
};

/// A boxed future, so every service client stays usable behind a trait object.
pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// An account session obtained from the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSession {
    /// The opaque access token. It authorises managed resources only: a host still requires device
    /// pairing and its own grant.
    pub access_token: String,
    /// How many seconds the access token lasts.
    pub expires_in_seconds: u64,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRequest {
    /// The endpoint the traffic comes from.
    pub source: EndpointKey,
    /// The endpoint the traffic goes to.
    pub destination: EndpointKey,
    /// Which way the lease permits traffic to flow.
    pub direction: RelayDirection,
    /// The cumulative bytes the payer is asking to reserve.
    pub byte_ceiling: u64,
    /// How long the lease should last, in seconds.
    pub duration_seconds: u32,
    /// The region the requester would rather be carried in, or null for no preference. A hint.
    pub region_preference: Option<String>,
    /// Who pays, or null for the default: the account this caller has selected, else itself.
    pub payer: Option<LeasePayer>,
    /// The lease to refill, or null to ask for a new one.
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
/// relay pins, and installs it on the relay before answering, so what a client receives is a
/// capability that is already in force. Endpoint admission alone never authorises peer traffic or
/// billing, and nothing a client says decides who pays.
///
/// An answer is not always a lease. An allowance that is spent and a service with no relay to offer
/// are answers about capacity, carrying what is left of the bounded grace and the paths that still
/// work, and [`RelayLeaseAnswer`] is that distinction: section 17 requires an exhausted managed
/// allowance to be reported as unavailable capacity with alternatives rather than as a failure.
pub trait RelayLeaseService: Send + Sync + std::fmt::Debug {
    /// Obtains a lease for a pair of endpoints, or a refill of the one that pair holds.
    fn issue<'a>(&'a self, request: &'a LeaseRequest) -> ServiceFuture<'a, RelayLeaseAnswer>;

    /// Ends a lease, so the relay stops carrying the pair and the reservation is settled.
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

    /// Fetches an encrypted object.
    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, Vec<u8>>;
}

/// Where managed inference is brokered.
///
/// The broker sells provider usage. A client using its own provider credential does not go through
/// it at all.
pub trait ManagedInferenceService: Send + Sync + std::fmt::Debug {
    /// Requests a brokered session for a provider profile.
    fn open_session<'a>(&'a self, profile: &'a str) -> ServiceFuture<'a, String>;

    /// Ends a brokered session.
    fn close_session<'a>(&'a self, session: &'a str) -> ServiceFuture<'a, ()>;
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
    /// Managed inference.
    pub managed_inference: Option<std::sync::Arc<dyn ManagedInferenceService>>,
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
        self.account.is_none()
            && self.relay_leases.is_none()
            && self.push.is_none()
            && self.sync_backup.is_none()
            && self.managed_inference.is_none()
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
        unconfigured("account login")
    }

    fn refresh<'a>(&'a self, _refresh_token: &'a str) -> ServiceFuture<'a, AccountSession> {
        unconfigured("account login")
    }
}

impl RelayLeaseService for NullService {
    fn issue<'a>(&'a self, _request: &'a LeaseRequest) -> ServiceFuture<'a, RelayLeaseAnswer> {
        unconfigured("relay leases")
    }

    fn revoke<'a>(
        &'a self,
        _lease_id: RelayLeaseId,
        _reason: LeaseEndReason,
    ) -> ServiceFuture<'a, RelayLeaseEnding> {
        unconfigured("relay leases")
    }
}

impl PushService for NullService {
    fn register<'a>(&'a self, _token: &'a str) -> ServiceFuture<'a, PushRegistration> {
        unconfigured("push registration")
    }

    fn revoke<'a>(&'a self, _installation_id: InstallationId) -> ServiceFuture<'a, ()> {
        unconfigured("push registration")
    }
}

impl SyncBackupService for NullService {
    fn compare_exchange<'a>(
        &'a self,
        _collection: &'a str,
        _expected_generation: u64,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, u64> {
        unconfigured("sync and backup")
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, Vec<u8>> {
        unconfigured("sync and backup")
    }
}

impl ManagedInferenceService for NullService {
    fn open_session<'a>(&'a self, _profile: &'a str) -> ServiceFuture<'a, String> {
        unconfigured("managed inference")
    }

    fn close_session<'a>(&'a self, _session: &'a str) -> ServiceFuture<'a, ()> {
        unconfigured("managed inference")
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
