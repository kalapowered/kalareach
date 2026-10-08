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
//! only when the broker is that service. A host whose broker is another service, or none, signs in
//! nowhere and presents nothing.
//!
//! What the store holds is kept in a scope named by the service. A grant, and a revocation that
//! waits to be sent, can therefore be read only through the service that issued them, and a host
//! never sends a token to a service that did not issue it. A host that is moved off the managed
//! broker still reaches the account service for what it holds: it can see the grant, send the
//! revocations that wait and sign out, because those requests go to the service that issued the
//! grant whatever the broker is. No check stands between a stored credential and the wrong
//! service, because there is no path from one to the other.
//!
//! The grant is refreshed when a call needs a token and the one held is about to end, never before,
//! so a host that makes no call spends no refresh token.
//!
//! # The account never changes under a call
//!
//! A call closes under the account it started under, and a start or a close asks for a token of its
//! own. Signing in or out is refused while a call is open, which includes a start that is waiting on
//! the broker and a close that is not finished (the coordinator counts both). The commit of a
//! sign-in and the removal of a sign-out then take a gate that refuses every token request while
//! they run: a start that begins after the check is refused its token, and one that began before it
//! was counted by the check. No call can hold a token of the old account across the change.
//!
//! Signing out removes the grant and asks the service to end it, under the same scope rule as
//! signing in.

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
    AccountAttempt, AccountReport, AccountSignInStarted, AccountSignedOut, AccountState,
    SignInUnavailable,
};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{Nullable, TimestampMs};
use tokio::sync::watch;

use crate::error::{ControllerError, Result};

/// How long the daemon waits for the person's browser to come back.
const WAIT: Duration = Duration::from_secs(15 * 60);

/// How many times, and how far apart, a refused bind of the loopback address is tried again.
const BIND_TRIES: u32 = 40;
const BIND_PAUSE: Duration = Duration::from_millis(25);

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
    /// Whether a managed call is open on this host, or about to open or close, once the voice
    /// service exists.
    call_open: std::sync::OnceLock<Box<dyn Fn() -> bool + Send + Sync>>,
    /// True while the account is being changed: a request for a token waits until it has been.
    changing: tokio::sync::watch::Sender<bool>,
    /// How many requests for a token are waiting for a change to end, for a test to know that one has
    /// reached the gate.
    #[cfg(feature = "testing")]
    waiting: std::sync::atomic::AtomicUsize,
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
    /// The sign-in of one environment, kept in `store`, at `service` where this host can reach the
    /// account service, or why it cannot. `refused` is why this host neither signs in nor presents
    /// its account, when it does not: its voice broker is not the account service.
    ///
    /// Removes the account token file an earlier version of this host imported, under
    /// `runtime_root`, once, and starts settling what an earlier run left.
    #[must_use]
    pub fn new(
        store: Arc<dyn SecretStore>,
        environment_id: EnvironmentId,
        runtime_root: &std::path::Path,
        service: std::result::Result<Service, SignInUnavailable>,
        refused: Option<SignInUnavailable>,
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
                    refused,
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
                changing: tokio::sync::watch::channel(false).0,
                #[cfg(feature = "testing")]
                waiting: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                loopback: Mutex::new(None),
            }),
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = Arc::clone(&account.inner);
            runtime.spawn(async move {
                if let Err(error) = inner.recover().await {
                    eprintln!("kr-controller: {error}");
                }
            });
        }
        account
    }

    /// Tells the account how to find out whether a managed call is open on this host, so that
    /// signing in or out never changes the account a call closes under. A call is open from the
    /// moment its start asks the broker until its close has been told.
    pub fn watch_calls(&self, open: impl Fn() -> bool + Send + Sync + 'static) {
        let _ = self.inner.call_open.set(Box::new(open));
    }

    /// Listens on `address` instead of the registered loopback address, for a test that runs
    /// several daemons at once.
    #[cfg(feature = "testing")]
    pub fn listen_on(&self, address: std::net::SocketAddr) {
        *self.inner.loopback.lock().expect("the test address") = Some(address);
    }

    /// How many requests for a token are waiting for a change of the account to end, for a test that
    /// holds the change and needs to know a request has reached it.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn token_requests_waiting(&self) -> usize {
        self.inner.waiting.load(std::sync::atomic::Ordering::SeqCst)
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
        self.inner.presenting()?;
        if self.inner.a_call_is_open() {
            return Err(Inner::call_is_open());
        }
        let mut running = self.inner.running.lock().await;
        self.inner.not_finishing()?;
        if let Some(older) = running.take() {
            let _ = older.cancel.send(true);
            let _ = older.task.await;
        }
        let listener = match self.listener().await {
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

    /// Signs the host out: ends the sign-in that is waiting, removes the grant and asks the service
    /// to end it. A host with no account answers that there was none and changes nothing. A host
    /// moved off the managed broker signs out all the same: the account service it keeps its grant
    /// for does not depend on the broker.
    ///
    /// # Errors
    ///
    /// Returns why the host cannot sign out: it cannot reach the account service, a sign-in is
    /// finishing, a managed call is open, or the store could not be changed (the host then keeps
    /// the grant, unless only its deletion failed after its revocation was queued, in which case
    /// the next start removes it).
    pub async fn sign_out(&self) -> Result<AccountSignedOut> {
        let held = self.inner.service()?;
        if self.inner.a_call_is_open() {
            return Err(Inner::call_is_open());
        }
        let mut running = self.inner.running.lock().await;
        self.inner.not_finishing()?;
        if let Some(older) = running.take() {
            let _ = older.cancel.send(true);
            let _ = older.task.await;
        }
        self.inner
            .recover()
            .await
            .map_err(|detail| ControllerError::Storage {
                operation: "settle this host's account before signing it out",
                detail,
            })?;
        let _change = self.inner.begin_change()?;
        let done = held
            .signed_in
            .sign_out()
            .await
            .map_err(|error| ControllerError::Storage {
                operation: "sign this host out",
                detail: error.to_string(),
            })?;
        // What came of earlier attempts says nothing about a host with no account.
        self.inner.state.lock().expect("the sign-in state").last = None;
        Ok(AccountSignedOut {
            was_signed_in: done.was_signed_in,
            service_told: done.service_told,
        })
    }

    /// Binds the address a sign-in comes back to.
    ///
    /// An address that is refused is tried again for a short while before it is called held. The
    /// daemon's own earlier listener on it has been closed, but the kernel lets the address go only
    /// when the last copy of that socket is closed, and a process that another part of this program
    /// is starting at that moment holds a copy until it has started: on a busy machine that is
    /// longer than the close.
    async fn listener(&self) -> std::result::Result<Listener, BindError> {
        let mut tries = 0;
        loop {
            match self.bind() {
                Err(BindError::Busy) if tries < BIND_TRIES => {
                    tries += 1;
                    tokio::time::sleep(BIND_PAUSE).await;
                }
                other => return other,
            }
        }
    }

    fn bind(&self) -> std::result::Result<Listener, BindError> {
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

/// The account being changed: a request for a token waits while this is held.
struct Change<'a> {
    inner: &'a Inner,
}

impl Drop for Change<'_> {
    fn drop(&mut self) {
        self.inner.changing.send_replace(false);
    }
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
    /// before this has run, and a run that failed is tried again by the next caller.
    async fn recover(&self) -> std::result::Result<(), String> {
        let Some(held) = &self.held else {
            return Ok(());
        };
        self.recovered
            .get_or_try_init(|| async {
                held.signed_in
                    .recover()
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("the host's sign-in could not be settled: {error}"))
            })
            .await?;
        Ok(())
    }

    /// The account service, when this host could set up how to reach it, or why it could not.
    fn service(&self) -> Result<&Held> {
        self.held.as_ref().ok_or_else(|| {
            Self::not_configured(self.unavailable.unwrap_or(SignInUnavailable::NotUsable))
        })
    }

    /// The account service, when this host also signs in and presents its account there: its voice
    /// broker is that service.
    fn presenting(&self) -> Result<&Held> {
        let held = self.service()?;
        match self.unavailable {
            Some(reason) => Err(Self::not_configured(reason)),
            None => Ok(held),
        }
    }

    fn not_configured(reason: SignInUnavailable) -> ControllerError {
        ControllerError::NotConfigured(
            match reason {
                SignInUnavailable::BrokerIsAnotherService => {
                    "this host's voice.broker_origin names another service than the managed \
                     account service it signs in at, so there is nothing to sign in to"
                }
                SignInUnavailable::NotUsable => {
                    "this host cannot reach the managed account service the way its \
                     configuration says: see the daemon's log"
                }
                SignInUnavailable::NoBroker => {
                    "this host names no managed voice service: set voice.broker_origin in its \
                     configuration document to the managed account service's origin"
                }
            }
            .to_owned(),
        )
    }

    /// Begins changing the account: a request for a token waits until the returned gate is dropped.
    ///
    /// The gate is raised before the calls are looked at. A start registers itself before it asks
    /// for its token, so it is either counted here or finds the gate up when it asks, and then
    /// waits for the change to end and takes the token of the account the change leaves. A call
    /// this check counts, and so refuses the change for, waits at most as long as the check.
    fn begin_change(&self) -> Result<Change<'_>> {
        if self.changing.send_replace(true) {
            return Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "this host's account is being changed; ask again when it has".to_owned(),
            });
        }
        let change = Change { inner: self };
        if self.a_call_is_open() {
            return Err(Self::call_is_open());
        }
        Ok(change)
    }

    /// Refuses while a sign-in is finishing: its code is spent and its grant is being kept.
    fn not_finishing(&self) -> Result<()> {
        if matches!(
            self.state.lock().expect("the sign-in state").phase,
            Phase::Finishing
        ) {
            return Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "a sign-in is finishing; ask again when it has".to_owned(),
            });
        }
        Ok(())
    }

    /// Whether a call is open, or its start or its close is not finished.
    fn a_call_is_open(&self) -> bool {
        self.call_open.get().is_some_and(|open| open())
    }

    fn call_is_open() -> ControllerError {
        ControllerError::Refused {
            code: ErrorCode::ResourceUnavailable,
            detail:
                "a voice call is open on this host; end it before signing in or out, because a \
                     call closes under the account it started under"
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
        let Ok(held) = self.presenting() else {
            return AccountAttempt::Unreachable;
        };
        // A call closes under the account it started under. One that opened while the person was
        // in the browser ends this attempt before the code is spent, and the code expires unused.
        if self.a_call_is_open() {
            return AccountAttempt::CallOpen;
        }
        if let Err(error) = self.recover().await {
            eprintln!("kr-controller: {error}");
            return AccountAttempt::NotKept;
        }
        match held.account.exchange(grant).await {
            Ok(Exchanged::Issued(issued)) => {
                let refresh = issued.refresh_token.clone();
                // The account changes now. A call that opened while the exchange was out leaves
                // the new grant unused: it is revoked, and nothing the call holds changes.
                // Another change is not one this attempt can be told apart from: a sign-out waits
                // for an attempt, so only a call can refuse it here.
                let Ok(_change) = self.begin_change() else {
                    // Queued before it is sent, so a service that cannot be reached is told again
                    // when the daemon next starts.
                    if let Err(error) = held.signed_in.revoke_unkept(refresh).await {
                        eprintln!("kr-controller: a refused sign-in could not be revoked: {error}");
                    }
                    return AccountAttempt::CallOpen;
                };
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

/// A request for a token that is waiting for a change of the account to end, counted for a test.
#[cfg(feature = "testing")]
struct Waiting<'a>(&'a Inner);

#[cfg(feature = "testing")]
impl<'a> Waiting<'a> {
    fn of(inner: &'a Inner) -> Self {
        inner
            .waiting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(inner)
    }
}

#[cfg(feature = "testing")]
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0
            .waiting
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
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
            let Ok(held) = self.inner.presenting() else {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    kr_client::shown::Shown::said(
                        "this host's voice broker is not a service it signs in to, so it presents \
                         no account token",
                    ),
                ));
            };
            // While the account is being changed a request waits for the change to end, so that a
            // call that starts then is made under the account the change leaves and not under one
            // that is about to go.
            #[cfg(feature = "testing")]
            let _waiting = Waiting::of(&self.inner);
            let _ = self
                .inner
                .changing
                .subscribe()
                .wait_for(|changing| !*changing)
                .await;
            if self.inner.recover().await.is_err() {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::StorageUnavailable,
                    kr_client::shown::Shown::said(
                        "this host's account could not be settled because its secret store failed",
                    ),
                ));
            }
            held.signed_in.token(scope).await
        })
    }
}
