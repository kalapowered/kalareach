//! The sync service's clients, and the report of which managed service clients are held.
//!
//! Section 17 gives the client one replaceable client for each managed service (account login,
//! relay leases, push, encrypted sync and backup, managed inference), and the application is
//! usable without any of them. The library names the clients as traits. Each use takes its client
//! from the place that decides it: this module for the sync service, `push::Wiring` for the push
//! gateway, `voice::Service` for the voice broker, and `build_account` for the account. A use that
//! reaches a service whose origin a person or a record chose asks for the client at that origin, so
//! a record made while the sync service was one service keeps talking to it after the setting
//! names another.
//!
//! The production implementations are the library's managed clients over the application's
//! transport. A suite that points the sync service at another implementation installs its own on
//! [`crate::state::AppState`] before the desks that use it are opened; the push gateway's and the
//! voice broker's are replaced where `push::Wiring` and `voice::Service` are made.

use std::sync::Arc;

use kr_client::services::voice::ManagedVoiceService;
use kr_client::services::{
    AccountService, AccountTokenSource, HttpDeadlines, HttpService, ManagedService,
    ManagedSyncService, PushService, ServiceClients, ServiceSigner, SharedSyncService,
    SyncBackupService, managed_response_limits,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;

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

/// The managed services this application can hold a client of. A phone holds no relay lease: the
/// host keeps the leases of the pairs it serves, so the application's lines leave that service out.
pub const APPLICABLE: [ManagedService; 4] = [
    ManagedService::AccountLogin,
    ManagedService::Push,
    ManagedService::SyncBackup,
    ManagedService::ManagedInference,
];

/// The clients the Account sheet reports over. The account's is the one the application holds; the
/// others are asked for afresh from the factories the desks use ([`Held::of`]), and a factory may
/// answer with a client a desk holds.
#[derive(Default)]
pub struct Held {
    /// The client of the account service.
    pub account: Option<Arc<dyn AccountService>>,
    /// The client of the sync service the person chose.
    pub sync: Option<Arc<dyn SharedSyncService>>,
    /// The client of the push gateway this phone talks to.
    pub push: Option<Arc<dyn PushService>>,
    /// The client of the voice service's broker.
    pub inference: Option<Arc<dyn ManagedVoiceService>>,
}

impl Held {
    /// The set the library reports availability over. A service left out is not configured, and
    /// nothing here changes what the application does for it.
    #[must_use]
    pub fn into_clients(self) -> ServiceClients {
        let mut clients = ServiceClients::none();
        clients.account = self.account;
        clients.sync_backup = self.sync.map(|sync| sync as Arc<dyn SyncBackupService>);
        clients.push = self.push;
        clients.managed_inference = self.inference;
        clients
    }
}

/// One service, as the page is told of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceLine {
    /// The service's name.
    pub service: String,
    /// Whether this application holds a client of it. That is all a client can know without
    /// asking: whether a call succeeds is what the call says.
    pub configured: bool,
    /// What a person is told: the service, and what they can do instead of it.
    pub explanation: String,
}

/// What to say of each of the services this application can hold, in one shape. It explains and
/// nothing more: no code path consults it before doing local work.
#[must_use]
pub fn lines(clients: &ServiceClients) -> Vec<ServiceLine> {
    APPLICABLE
        .into_iter()
        .map(|service| {
            let availability = clients.availability_of(service);
            ServiceLine {
                service: service.as_str().to_owned(),
                configured: availability.configured,
                explanation: availability.explanation,
            }
        })
        .collect()
}

impl Held {
    /// The account's client, and, where the desk that uses one has been opened, a client of the
    /// sync service from the installed [`SyncServices`] at the origin the setting names now (a
    /// record made earlier may keep another), the push gateway's from the push desk, and the voice
    /// broker's, which `calls` makes for the tokens it is given. The others are asked for afresh.
    /// A desk that is not open gives no client, and neither does a factory that cannot make its
    /// client: the error is dropped, and the line for the service says no client is configured.
    #[must_use]
    pub fn of(
        state: Option<&crate::state::AppState>,
        calls: Option<(&crate::voice::Calls, Arc<dyn AccountTokenSource>)>,
        account: Arc<dyn AccountService>,
    ) -> Self {
        let sync = state.and_then(|state| {
            let chosen = state.sync_service().ok()?.origin();
            state.installed_sync_clients()?.installation(&chosen).ok()
        });
        Self {
            account: Some(account),
            sync,
            push: state
                .and_then(crate::state::AppState::push)
                .and_then(|desk| desk.client()),
            inference: calls.and_then(|(calls, tokens)| calls.broker(tokens)),
        }
    }
}

/// The clients the Account sheet reports over, as [`Held::of`] gets them: the application's state
/// and its voice calls give the others, and `account` is the account's own.
#[must_use]
pub fn held_by<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    account: &crate::account::Account,
) -> Held {
    use tauri::Manager as _;

    let state = app.try_state::<crate::state::AppState>();
    let calls = app.try_state::<crate::voice::Calls>();
    Held::of(
        state.as_deref(),
        calls
            .as_deref()
            .map(|calls| (calls, account.tokens() as Arc<dyn AccountTokenSource>)),
        account.service(),
    )
}
