//! The host's own sign-in to the managed account service.
//!
//! Managed voice spends an account's balance, so the host presents an account token of its own.
//! The daemon alone holds the sign-in: the grant lives in the host's secret store under
//! [`SignedInAccount`], whose refresh token rotates on every use, so a second holder would end it.
//! A person starts the sign-in at this machine (`kr account sign-in`); the daemon listens on the
//! loopback address the desktop client is registered with, the person's browser comes back to it,
//! and the daemon exchanges the answer and keeps the grant.
//!
//! The grant is refreshed when a call needs a token and the one held is about to end, never before,
//! so a host that makes no call spends no refresh token. A token is presented only to the service
//! the sign-in was made at: the service's origin is recorded beside the grant, named by the
//! grant's generation, and a host whose configuration names another broker presents nothing until a
//! person signs in again.
//!
//! The sign-in is at the origin the configuration names as the voice broker, because the account
//! service and the voice service are one deployment: the grant is only ever presented there.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::account::{
    AccountService, AccountStatus, AccountTokenSource, Answer, AnswerFault, AuthorisationGrant,
    AuthorisationRequest, Client, Exchanged, IdentityRead, PendingAuthorisation, Redirect,
    SignedInAccount,
};
use kr_client::services::{AccountToken, ServiceFuture};
use kr_crypto::store::{SecretName, SecretStore};
use kr_loopback::{BindError, Listener};
use kr_protocol::error::ErrorCode;
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInStarted, AccountState,
};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{Nullable, TimestampMs};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::error::{ControllerError, Result};

/// How long the daemon waits for the person's browser to come back.
const WAIT: Duration = Duration::from_secs(15 * 60);

/// The file an earlier version of this host kept an imported account token in, under the runtime
/// root. It held an access token and no refresh credential, so it cannot become a sign-in.
///
/// Removed once, when the daemon starts. Delete this and its removal when no host that ran a
/// version with the import command remains.
const IMPORTED_TOKEN_FILE: &str = "account-token.json";

/// The service a host signs in at: its origin, and the account service there.
pub struct Service {
    /// The origin the host's configuration names as its voice broker.
    pub origin: String,
    /// The account service at that origin.
    pub account: Arc<dyn AccountService>,
}

/// What the daemon records beside the grant: the service it was signed in at, and which grant.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    origin: String,
    generation: String,
}

/// What a finished attempt shows a person's browser.
const fn page(outcome: AccountAttempt) -> &'static str {
    match outcome {
        AccountAttempt::SignedIn => "You are signed in to KalaReach. You can close this tab.",
        AccountAttempt::Refused => "The sign-in was refused. Nothing changed.",
        AccountAttempt::ServiceRefused => "The account service did not sign this host in.",
        AccountAttempt::NotForThisAttempt => {
            "This was not for the sign-in this host is waiting for."
        }
        AccountAttempt::NotKept => "This host could not keep the sign-in.",
        AccountAttempt::Unreachable => "This host could not reach the account service.",
        AccountAttempt::PortBusy | AccountAttempt::TimedOut | AccountAttempt::Superseded => {
            "The sign-in ended. Nothing changed."
        }
    }
}

#[derive(Default)]
enum Phase {
    #[default]
    Idle,
    Waiting {
        url: String,
        address: String,
        expires_at_ms: u64,
    },
    Finishing,
}

#[derive(Default)]
struct State {
    phase: Phase,
    last: Option<AccountAttempt>,
}

/// The attempt that is waiting: how to end it, and the task to wait for.
struct Running {
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct Held {
    origin: String,
    account: Arc<dyn AccountService>,
    signed_in: SignedInAccount,
    record: SecretName,
}

struct Inner {
    store: Arc<dyn SecretStore>,
    held: Option<Held>,
    state: Mutex<State>,
    running: tokio::sync::Mutex<Option<Running>>,
    #[cfg(feature = "testing")]
    loopback: Mutex<Option<std::net::SocketAddr>>,
}

/// The host's sign-in to the managed account service, and the token source its calls present.
#[derive(Clone)]
pub struct HostAccount {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for HostAccount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostAccount")
            .finish_non_exhaustive()
    }
}

impl HostAccount {
    /// The sign-in of one environment, kept in `store`, at `service` where the host's
    /// configuration names one.
    ///
    /// Removes the account token file an earlier version of this host imported, under
    /// `runtime_root`, once.
    #[must_use]
    pub fn new(
        store: Arc<dyn SecretStore>,
        environment_id: EnvironmentId,
        runtime_root: &std::path::Path,
        service: Option<Service>,
    ) -> Self {
        match std::fs::remove_file(runtime_root.join(IMPORTED_TOKEN_FILE)) {
            Ok(()) => eprintln!(
                "kr-controller: removed the account token this host had imported, which held no \
                 refresh credential: sign in with `kr account sign-in`"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "kr-controller: could not remove the account token this host had imported: {error}"
            ),
        }
        let scope = format!("{environment_id}/host-account");
        let held = service.and_then(|service| {
            let record = SecretName::new(format!("{scope}/service"))
                .inspect_err(|error| eprintln!("kr-controller: no host sign-in: {error}"))
                .ok()?;
            let signed_in = SignedInAccount::new(
                Arc::clone(&service.account),
                Arc::clone(&store),
                Client::Desktop,
            )
            .in_scope(scope);
            Some(Held {
                origin: service.origin,
                account: service.account,
                signed_in,
                record,
            })
        });
        Self {
            inner: Arc::new(Inner {
                store,
                held,
                state: Mutex::new(State::default()),
                running: tokio::sync::Mutex::new(None),
                #[cfg(feature = "testing")]
                loopback: Mutex::new(None),
            }),
        }
    }

    /// Listens on `address` instead of the registered loopback address, for a test that runs
    /// several daemons at once.
    #[cfg(feature = "testing")]
    pub fn listen_on(&self, address: std::net::SocketAddr) {
        *self.inner.loopback.lock().expect("the test address") = Some(address);
    }

    /// Keeps a sign-in the service issued, as a finished browser sign-in would, for a test that
    /// is about what a call does with an account rather than about signing in.
    ///
    /// # Panics
    ///
    /// Panics when this host names no service or the store refuses the grant.
    #[cfg(feature = "testing")]
    pub async fn keep_for_test(&self, issued: kr_client::services::account::IssuedGrant) {
        let held = self.inner.held.as_ref().expect("a service to sign in at");
        held.signed_in
            .commit(issued, "a-nonce")
            .await
            .expect("the grant is kept");
        self.inner.record(held).expect("the service is recorded");
    }

    /// The token source a managed call presents: this host's sign-in, for the service it was
    /// signed in at.
    #[must_use]
    pub fn tokens(&self) -> Arc<dyn AccountTokenSource> {
        Arc::new(HostTokens {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Where the host's sign-in stands.
    #[must_use]
    pub fn report(&self) -> AccountReport {
        let (phase, last) = {
            let state = self.inner.state.lock().expect("the sign-in state");
            let phase = match &state.phase {
                Phase::Idle => None,
                Phase::Waiting {
                    url,
                    address,
                    expires_at_ms,
                } => Some(AccountState::WaitingForBrowser {
                    authorise_url: url.clone(),
                    redirect_address: address.clone(),
                    expires_at_ms: TimestampMs::new(*expires_at_ms),
                }),
                Phase::Finishing => Some(AccountState::Finishing),
            };
            (phase, state.last)
        };
        AccountReport {
            service: Nullable::from(self.inner.held.as_ref().map(|held| held.origin.clone())),
            state: phase.unwrap_or_else(|| self.inner.settled()),
            last_attempt: Nullable::from(last),
        }
    }

    /// Starts a sign-in: ends the one that is waiting, listens for the browser's answer and
    /// returns when the daemon is ready for it. The address the person opens is in
    /// [`Self::report`].
    ///
    /// # Errors
    ///
    /// Returns why no sign-in can start: this host names no service to sign in at, a sign-in is
    /// finishing, or another program holds the loopback address.
    pub async fn sign_in(&self) -> Result<AccountSignInStarted> {
        if self.inner.held.is_none() {
            return Err(ControllerError::NotConfigured(
                "this host names no managed service to sign in at: set voice.broker_origin in its \
                 configuration document"
                    .to_owned(),
            ));
        };
        let mut running = self.inner.running.lock().await;
        if matches!(
            self.inner.state.lock().expect("the sign-in state").phase,
            Phase::Finishing
        ) {
            return Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "a sign-in is finishing; ask again when it has".to_owned(),
            });
        }
        if let Some(older) = running.take() {
            let _ = older.cancel.send(true);
            let _ = older.task.await;
        }
        let listener = match self.listener() {
            Ok(listener) => listener,
            Err(error) => {
                let detail = match error {
                    BindError::Busy => "another program holds the loopback address a sign-in \
                                        comes back to"
                        .to_owned(),
                    BindError::Failed(error) => {
                        format!(
                            "the loopback address a sign-in comes back to could not be opened: {error}"
                        )
                    }
                };
                self.inner.state.lock().expect("the sign-in state").last =
                    Some(AccountAttempt::PortBusy);
                return Err(ControllerError::Refused {
                    code: ErrorCode::ResourceUnavailable,
                    detail,
                });
            }
        };
        let request = AuthorisationRequest::asking(
            Client::Desktop,
            Redirect::Loopback,
            &[kr_client::services::voice::VOICE_SCOPE],
        )
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let url = request.url();
        let pending = PendingAuthorisation::new(request);
        let expires_at_ms = kr_ipc::now_ms()
            .get()
            .saturating_add(u64::try_from(WAIT.as_millis()).unwrap_or(u64::MAX));
        self.inner.state.lock().expect("the sign-in state").phase = Phase::Waiting {
            url,
            address: listener.local_address().to_string(),
            expires_at_ms,
        };
        let (cancel, cancelled) = watch::channel(false);
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            inner.attempt(listener, pending, cancelled).await;
        });
        *running = Some(Running { cancel, task });
        Ok(AccountSignInStarted {
            expires_at_ms: TimestampMs::new(expires_at_ms),
        })
    }

    fn listener(&self) -> std::result::Result<Listener, BindError> {
        #[cfg(feature = "testing")]
        if let Some(address) = *self.inner.loopback.lock().expect("the test address") {
            return Listener::open_at(address, "127.0.0.1:0");
        }
        Listener::open()
    }
}

impl Inner {
    /// Where the grant stands when no attempt is running.
    fn settled(&self) -> AccountState {
        let Some(held) = &self.held else {
            return AccountState::SignedOut;
        };
        match held.signed_in.status() {
            Ok(AccountStatus::SignedIn {
                email,
                scopes,
                generation,
                ..
            }) => match self.recorded(held) {
                Some(recorded) if recorded.generation == generation => AccountState::SignedIn {
                    origin: recorded.origin,
                    email: Nullable::from(email),
                    scopes,
                },
                // A grant whose service is not recorded is not one this host can present.
                _ => AccountState::SignedOut,
            },
            Ok(AccountStatus::Ended) => AccountState::Ended,
            Ok(AccountStatus::SignedOut) | Err(_) => AccountState::SignedOut,
        }
    }

    fn recorded(&self, held: &Held) -> Option<Recorded> {
        let bytes = self.store.get(&held.record).ok()??;
        serde_json::from_slice(bytes.expose()).ok()
    }

    /// One attempt: waits for the browser's answer, the person's next attempt or the deadline, and
    /// settles what became of it.
    async fn attempt(
        &self,
        listener: Listener,
        mut pending: PendingAuthorisation,
        mut cancel: watch::Receiver<bool>,
    ) {
        let (outcome, reply) = tokio::select! {
            biased;
            () = ended(&mut cancel) => (AccountAttempt::Superseded, None),
            () = tokio::time::sleep(WAIT) => (AccountAttempt::TimedOut, None),
            (answer, callback) = listener.answered(&mut pending) => {
                (self.answered(answer).await, Some(callback))
            }
        };
        // The state is settled before the browser is told, so a page that says the sign-in ended
        // is never ahead of what the host reports.
        {
            let mut state = self.state.lock().expect("the sign-in state");
            state.phase = Phase::Idle;
            state.last = Some(outcome);
        }
        if let Some(reply) = reply {
            reply.finish(page(outcome)).await;
        }
    }

    async fn answered(&self, answer: Answer) -> AccountAttempt {
        match answer {
            Answer::Granted(grant) => {
                self.state.lock().expect("the sign-in state").phase = Phase::Finishing;
                self.finish(&grant).await
            }
            Answer::Refused => AccountAttempt::Refused,
            Answer::Failed(AnswerFault::ServiceFailure | AnswerFault::NoCode) => {
                AccountAttempt::ServiceRefused
            }
            Answer::Failed(_) | Answer::Dropped(_) => AccountAttempt::NotForThisAttempt,
        }
    }

    /// Exchanges the code, keeps the grant and records the service it belongs to.
    async fn finish(&self, grant: &AuthorisationGrant) -> AccountAttempt {
        let Some(held) = &self.held else {
            return AccountAttempt::Unreachable;
        };
        match held.account.exchange(grant).await {
            Ok(Exchanged::Issued(issued)) => {
                let refresh = issued.refresh_token.clone();
                if let Err(error) = held.signed_in.commit(issued, grant.nonce()).await {
                    eprintln!("kr-controller: a host sign-in could not be kept: {error}");
                    let _ = held.account.revoke(&refresh).await;
                    return AccountAttempt::NotKept;
                }
                if let Ok(IdentityRead::Disagreed) = held.signed_in.complete_identity().await {
                    return AccountAttempt::NotForThisAttempt;
                }
                if self.record(held).is_err() {
                    // A grant that no record names is one this host cannot present, so it is
                    // undone rather than left as a sign-in that does nothing.
                    let _ = held.signed_in.sign_out().await;
                    return AccountAttempt::NotKept;
                }
                AccountAttempt::SignedIn
            }
            Ok(Exchanged::Refused { leftover }) => {
                if let Some(leftover) = leftover {
                    let _ = held.account.revoke(&leftover).await;
                }
                AccountAttempt::ServiceRefused
            }
            Err(error) => {
                eprintln!("kr-controller: a host sign-in's code could not be exchanged: {error}");
                AccountAttempt::Unreachable
            }
        }
    }

    /// Writes the service the grant now held was signed in at, named by the grant's generation.
    fn record(&self, held: &Held) -> std::result::Result<(), ()> {
        let Ok(AccountStatus::SignedIn { generation, .. }) = held.signed_in.status() else {
            return Err(());
        };
        let recorded = Recorded {
            origin: held.origin.clone(),
            generation,
        };
        let bytes = serde_json::to_vec(&recorded).map_err(|_| ())?;
        self.store.set(&held.record, &bytes).map_err(|_| ())
    }
}

/// Waits until the attempt is told to end.
async fn ended(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// The token source a managed call presents.
struct HostTokens {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for HostTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HostTokens").finish_non_exhaustive()
    }
}

impl AccountTokenSource for HostTokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            let Some(held) = &self.inner.held else {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    kr_client::shown::Shown::said(
                        "this host names no managed service, so it presents no account token",
                    ),
                ));
            };
            // The service the grant was signed in at is the one this host is configured to reach,
            // or nothing is presented: a token is a bearer credential for one service.
            if let Ok(AccountStatus::SignedIn { generation, .. }) = held.signed_in.status() {
                let recorded = self.inner.recorded(held);
                let named = recorded
                    .as_ref()
                    .is_some_and(|recorded| recorded.generation == generation);
                if !named || recorded.is_some_and(|recorded| recorded.origin != held.origin) {
                    return Err(kr_client::ClientError::refusal(
                        ErrorCode::HostNotConfigured,
                        kr_client::shown::Shown::said(
                            "the account signed in on this host belongs to another service than \
                             the one its configuration names: sign in again with `kr account \
                             sign-in`",
                        ),
                    ));
                }
            }
            held.signed_in.token(scope).await
        })
    }
}
