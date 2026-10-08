//! The host's own sign-in to the managed account service.
//!
//! Managed voice spends an account's balance, so the host presents an account token of its own.
//! The daemon alone holds the sign-in: the grant lives in the host's secret store under
//! [`SignedInAccount`], whose refresh token rotates on every use, so a second holder would end it.
//! A person starts the sign-in at this machine (`kr account sign-in`); the daemon listens on the
//! loopback address the desktop client is registered with, the person's browser comes back to it,
//! and the daemon exchanges the answer and keeps the grant.
//!
//! # One service, by construction
//!
//! The browser signs in at the account service, and the code it brings back is redeemable there and
//! nowhere else, so the exchange, every refresh and every revocation go to that one service. The
//! host's configuration names a voice broker; the host signs in, and presents a token to the broker,
//! only when the broker is that service. A host whose broker is another service has nothing to sign
//! in to and presents nothing.
//!
//! What the store holds is kept in a scope named by the service. A grant, and a revocation that
//! waits to be sent, can therefore be read only through the service that issued them: a host that
//! is configured for another service finds none of them and sends a token to no one. No check
//! stands between a stored credential and the wrong service, because there is no path from one to
//! the other.
//!
//! The grant is refreshed when a call needs a token and the one held is about to end, never before,
//! so a host that makes no call spends no refresh token.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::account::{
    AccountService, AccountStatus, AccountTokenSource, Answer, AnswerFault, AuthorisationGrant,
    AuthorisationRequest, Client, Exchanged, IdentityRead, PendingAuthorisation, Redirect,
    SignedInAccount,
};
use kr_client::services::{AccountToken, ServiceFuture};
use kr_crypto::store::SecretStore;
use kr_loopback::{BindError, Listener};
use kr_protocol::error::ErrorCode;
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInStarted, AccountState, SignInUnavailable,
};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{Nullable, TimestampMs};
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

/// The account service a host signs in at: its origin, and the client of it.
pub struct Service {
    /// The account service's origin. Everything stored for the sign-in is kept under its name.
    pub origin: String,
    /// The account service at that origin.
    pub account: Arc<dyn AccountService>,
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
        AccountAttempt::CallOpen => {
            "A voice call is open on this host. End it, then sign in again."
        }
        AccountAttempt::PortBusy
        | AccountAttempt::ListenerFailed
        | AccountAttempt::TimedOut
        | AccountAttempt::Superseded => "The sign-in ended. Nothing changed.",
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
}

struct Inner {
    held: Option<Held>,
    unavailable: Option<SignInUnavailable>,
    state: Mutex<State>,
    running: tokio::sync::Mutex<Option<Running>>,
    /// Settled once, before the first token is handed out: a grant whose own revocation was queued
    /// when an earlier run stopped is removed, and every revocation the service has not
    /// acknowledged is sent again.
    recovered: tokio::sync::OnceCell<()>,
    /// Whether a managed call is open on this host, once the voice service exists.
    call_open: std::sync::OnceLock<Box<dyn Fn() -> bool + Send + Sync>>,
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
    /// The sign-in of one environment, kept in `store`, at `service` where this host can sign in,
    /// or why it cannot.
    ///
    /// Removes the account token file an earlier version of this host imported, under
    /// `runtime_root`, once, and starts settling what an earlier run left.
    #[must_use]
    pub fn new(
        store: Arc<dyn SecretStore>,
        environment_id: EnvironmentId,
        runtime_root: &std::path::Path,
        service: std::result::Result<Service, SignInUnavailable>,
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
        let (held, unavailable) = match service {
            Ok(service) => {
                // Everything kept for the sign-in lives under the service that issued it.
                let scope = format!(
                    "{environment_id}/host-account/{}",
                    named_by(&service.origin)
                );
                let signed_in =
                    SignedInAccount::new(Arc::clone(&service.account), store, Client::Desktop)
                        .in_scope(scope);
                (
                    Some(Held {
                        origin: service.origin,
                        account: service.account,
                        signed_in,
                    }),
                    None,
                )
            }
            Err(unavailable) => (None, Some(unavailable)),
        };
        let account = Self {
            inner: Arc::new(Inner {
                held,
                unavailable,
                state: Mutex::new(State::default()),
                running: tokio::sync::Mutex::new(None),
                recovered: tokio::sync::OnceCell::new(),
                call_open: std::sync::OnceLock::new(),
                #[cfg(feature = "testing")]
                loopback: Mutex::new(None),
            }),
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = Arc::clone(&account.inner);
            runtime.spawn(async move { inner.recover().await });
        }
        account
    }

    /// Tells the account how to find out whether a managed call is open on this host, so that a
    /// sign-in never changes the account a call closes under.
    pub fn watch_calls(&self, open: impl Fn() -> bool + Send + Sync + 'static) {
        let _ = self.inner.call_open.set(Box::new(open));
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
    /// Panics when this host can sign in nowhere or the store refuses the grant.
    #[cfg(feature = "testing")]
    pub async fn keep_for_test(&self, issued: kr_client::services::account::IssuedGrant) {
        let held = self.inner.held.as_ref().expect("a service to sign in at");
        held.signed_in
            .commit(issued, "a-nonce")
            .await
            .expect("the grant is kept");
    }

    /// The token source a managed call presents: this host's sign-in at the account service.
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
            unavailable: Nullable::from(self.inner.unavailable),
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
    /// Returns why no sign-in can start: this host's voice broker is not the account service, a
    /// sign-in is finishing, a managed call is open, or another program holds the loopback
    /// address.
    pub async fn sign_in(&self) -> Result<AccountSignInStarted> {
        if self.inner.held.is_none() {
            return Err(ControllerError::NotConfigured(
                match self.inner.unavailable {
                    Some(SignInUnavailable::BrokerIsAnotherService) => {
                        "this host's voice.broker_origin names another service than the managed \
                         account service it signs in at, so there is nothing to sign in to"
                    }
                    Some(SignInUnavailable::NotUsable) => {
                        "this host cannot reach the managed account service the way its \
                         configuration says: see the daemon's log"
                    }
                    Some(SignInUnavailable::NoBroker) | None => {
                        "this host names no managed voice service: set voice.broker_origin in its \
                         configuration document to the managed account service's origin"
                    }
                }
                .to_owned(),
            ));
        }
        if self.inner.a_call_is_open() {
            return Err(Inner::call_is_open());
        }
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
                let (attempt, detail) = match error {
                    BindError::Busy => (
                        AccountAttempt::PortBusy,
                        "another program holds the loopback address a sign-in comes back to"
                            .to_owned(),
                    ),
                    BindError::Failed(error) => (
                        AccountAttempt::ListenerFailed,
                        format!(
                            "the loopback address a sign-in comes back to could not be opened: \
                             {error}"
                        ),
                    ),
                };
                self.inner.state.lock().expect("the sign-in state").last = Some(attempt);
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
            return Listener::open_at(address, &address.to_string());
        }
        Listener::open()
    }
}

/// What a service is named by in the store: a digest of its origin, truncated.
fn named_by(origin: &str) -> String {
    kr_cbor::sha256(origin.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Inner {
    /// Where the grant stands when no attempt is running.
    fn settled(&self) -> AccountState {
        let Some(held) = &self.held else {
            return AccountState::SignedOut;
        };
        match held.signed_in.status() {
            Ok(AccountStatus::SignedIn { email, scopes, .. }) => AccountState::SignedIn {
                origin: held.origin.clone(),
                email: Nullable::from(email),
                scopes,
            },
            Ok(AccountStatus::Ended) => AccountState::Ended,
            Ok(AccountStatus::SignedOut) | Err(_) => AccountState::SignedOut,
        }
    }

    /// Settles what an earlier run left, once: a grant whose own revocation was queued is removed,
    /// and every revocation the service has not acknowledged is sent again. Nothing is handed out
    /// before this has run.
    async fn recover(&self) {
        let Some(held) = &self.held else {
            return;
        };
        self.recovered
            .get_or_init(|| async {
                if let Err(error) = held.signed_in.recover().await {
                    eprintln!("kr-controller: the host's sign-in could not be settled: {error}");
                }
            })
            .await;
    }

    fn a_call_is_open(&self) -> bool {
        self.call_open.get().is_some_and(|open| open())
    }

    fn call_is_open() -> ControllerError {
        ControllerError::Refused {
            code: ErrorCode::ResourceUnavailable,
            detail: "a voice call is open on this host; end it before signing in, because a call \
                     closes under the account it started under"
                .to_owned(),
        }
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

    /// Exchanges the code and keeps the grant.
    async fn finish(&self, grant: &AuthorisationGrant) -> AccountAttempt {
        let Some(held) = &self.held else {
            return AccountAttempt::Unreachable;
        };
        // A call closes under the account it started under. One that opened while the person was
        // in the browser ends this attempt before the code is spent, and the code expires unused.
        if self.a_call_is_open() {
            return AccountAttempt::CallOpen;
        }
        self.recover().await;
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
                        "this host's voice broker is not a service it signs in to, so it presents \
                         no account token",
                    ),
                ));
            };
            self.inner.recover().await;
            held.signed_in.token(scope).await
        })
    }
}
