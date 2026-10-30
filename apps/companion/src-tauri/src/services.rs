//! The managed services this application reaches, built where they are chosen.
//!
//! Section 17 gives the client one replaceable client for each managed service (account login,
//! relay leases, push, encrypted sync and backup, managed inference), and the application is
//! usable without any of them. The library names the clients as traits; this module is where the
//! application decides which implementation each use gets. A use that reaches a service whose
//! origin a person or a record chose asks for the client at that origin, so a record made while the
//! sync service was one service keeps talking to it after the setting names another.
//!
//! The production implementations are the library's managed clients over the application's
//! transport. A suite that points the application at another implementation installs its own on
//! [`crate::state::AppState`] before the desks that use them are opened.

use std::sync::Arc;

use kr_client::services::{
    AccountTokenSource, HttpDeadlines, HttpService, ManagedSyncService, ServiceSigner,
    SharedSyncService, managed_response_limits,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::service::GatewayOrigin;

use crate::error::{CommandError, Result};
use crate::recovery::DeviceSigner;

/// How the application gets a client of the sync service at an origin.
///
/// The origin is an argument because it belongs to what the client is for: a record keeps the
/// origin it was made at, and only a new record reads the origin the setting names now.
pub trait SyncServices: Send + Sync + std::fmt::Debug {
    /// The client of the service at `origin`, signing as this installation.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the service cannot be reached from this computer.
    fn installation(&self, origin: &GatewayOrigin) -> Result<Arc<dyn SharedSyncService>>;

    /// As [`Self::installation`], and presenting the account's token held by `tokens` for `scope`
    /// beside the signature of every request about a recovery bundle.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the service cannot be reached from this computer.
    fn presenting(
        &self,
        origin: &GatewayOrigin,
        tokens: Arc<dyn AccountTokenSource>,
        scope: &'static str,
    ) -> Result<Arc<dyn SharedSyncService>>;
}

/// The library's managed sync client over the application's transport, signing with this
/// computer's authorisation key.
pub struct ManagedSyncServices {
    signer: Arc<dyn ServiceSigner>,
}

impl ManagedSyncServices {
    /// The production implementation, signing with `key`.
    #[must_use]
    pub fn new(key: AuthorisationKeyPair) -> Self {
        Self {
            signer: Arc::new(DeviceSigner::new(key)),
        }
    }

    fn client(&self, origin: &GatewayOrigin) -> Result<ManagedSyncService> {
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this computer cannot reach the sync service: {error}"
            ))
        })?;
        Ok(ManagedSyncService::new(
            origin.clone(),
            Arc::new(http),
            Arc::clone(&self.signer),
        ))
    }
}

impl std::fmt::Debug for ManagedSyncServices {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedSyncServices")
            .finish_non_exhaustive()
    }
}

impl SyncServices for ManagedSyncServices {
    fn installation(&self, origin: &GatewayOrigin) -> Result<Arc<dyn SharedSyncService>> {
        Ok(Arc::new(self.client(origin)?))
    }

    fn presenting(
        &self,
        origin: &GatewayOrigin,
        tokens: Arc<dyn AccountTokenSource>,
        scope: &'static str,
    ) -> Result<Arc<dyn SharedSyncService>> {
        Ok(Arc::new(self.client(origin)?.presenting(tokens, scope)))
    }
}
