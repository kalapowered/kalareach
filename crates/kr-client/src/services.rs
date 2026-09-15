//! Replaceable service clients.
//!
//! Section 17: `kr-client` has replaceable service clients for account login, relay leases, push,
//! encrypted sync/backup and managed inference. The boundary matters more than the implementations:
//! all local host and client functionality is open source, the hosted service sells provider usage,
//! storage, relay bandwidth and operation, and a fork can point these traits at its own
//! infrastructure without changing anything else in the client.
//!
//! Only the traits and one null implementation live here. The managed implementations belong to
//! the web-integration work, and a self-hosted deployment supplies its own. A client with no
//! managed service configured is a complete client: direct connections, local sessions, plugins,
//! local descriptions and user-operated alternatives need none of these.

use std::future::Future;
use std::pin::Pin;

use kr_protocol::ids::InstallationId;

use crate::error::{ClientError, Result};

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

/// A relay lease the payer installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayLeaseHandle {
    /// The lease identity the service assigned.
    ///
    /// Opaque here on purpose: the signed lease object is the relay's contract with the service,
    /// and a client only has to name the lease it obtained.
    pub lease_id: String,
    /// The byte ceiling the lease reserved.
    pub byte_ceiling: u64,
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

/// Where relay leases are obtained and installed.
///
/// The payer's client obtains a lease from the service and installs it on the relay. Endpoint
/// admission alone never authorises peer traffic or billing.
pub trait RelayLeaseService: Send + Sync + std::fmt::Debug {
    /// Obtains a lease for a pair of endpoints.
    fn issue(&self, requested_bytes: u64) -> ServiceFuture<'_, RelayLeaseHandle>;

    /// Releases a lease early.
    fn release<'a>(&'a self, lease_id: &'a str) -> ServiceFuture<'a, ()>;
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
    fn issue(&self, _requested_bytes: u64) -> ServiceFuture<'_, RelayLeaseHandle> {
        unconfigured("relay leases")
    }

    fn release<'a>(&'a self, _lease_id: &'a str) -> ServiceFuture<'a, ()> {
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

        let error = NullService
            .issue(1024)
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
