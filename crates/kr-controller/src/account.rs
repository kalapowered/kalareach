//! The host's own sign-ins to account services.
//!
//! Managed voice spends an account's balance, managed relay leases are billed to an account and
//! backup storage keeps an account's backups, so the host presents an account token of its own to
//! each. The daemon alone holds a sign-in: the grant lives in the host's secret store under
//! [`SignedInAccount`], whose refresh token rotates on every use, so a second holder would end it.
//! A person starts the sign-in at this machine (`kr account sign-in`); the daemon listens on the
//! loopback address the desktop client is registered with, the person's browser comes back to it,
//! and the daemon exchanges the answer and keeps the grant.
//!
//! # Two accounts, one for each role
//!
//! A host holds the managed account, for managed voice, the relay lease service and managed
//! storage, and, when its `storage.origin` names a service the person runs, a second account of its
//! own at that service, for storage and for nothing else. Each is a [`HostAccount`] with its own grant in its
//! own scope of the secret store, its own transport, its own sign-in and sign-out. A client is
//! given the account of its role when it is built: the voice client, the relay payer and the call
//! watch are given the managed account and never the storage one, and the storage clients are
//! given the account of the storage service. The storage account also hands out one scope,
//! `backup.write`, on every path that hands a token out, whatever its grant holds, so a service
//! the person runs that grants it `voice` or `relay.lease` as well gets neither token from this
//! host.
//!
//! # One service, by construction
//!
//! The browser signs in at the account service, and the code it brings back is redeemable there and
//! nowhere else, so the exchange, every refresh and every revocation go to that one service. An
//! account is built from one origin ([`Service::at_origin`]): the client of the service, the
//! transport that reaches it and the name its grant is kept under all come from that origin, so no
//! account is paired with another origin's service.
//!
//! The managed account presents a token to the voice broker, the relay lease service and the
//! storage service only when each is the account service, and signs in when it presents to one. A
//! host that selects no storage service of the managed origin and whose broker and relay lease
//! service are other services, or none, has a managed account that signs in nowhere and presents
//! nothing; a storage service the person runs has the account of its own.
//!
//! What the store holds is kept in a scope named by the service. A grant, and a revocation that
//! waits to be sent, can therefore be read only through the service that issued them, and a host
//! never sends a token to a service that did not issue it. A host that is moved off the managed
//! broker still reaches the account service for what it holds: it can see the grant, send the
//! revocations that wait and sign out, because those requests go to the service that issued the
//! grant whatever the broker is. A token source is made for the origin of the service it serves
//! ([`HostAccount::tokens_for`]) and hands out nothing unless that origin is its account's.
//!
//! The grant is refreshed when a call, the storage carrier or `kr doctor` needs a token and the one
//! held is about to end, never before, so a host that does none of them spends no refresh token.
//!
//! # One waiting sign-in
//!
//! Both accounts sign in through the one loopback address the desktop client is registered with,
//! so a host has one waiting sign-in between them. A sign-in that starts ends a waiting one of
//! either account, which then reads superseded; a grant that is held is never ended by it.
//!
//! # The account never changes under a call
//!
//! A call closes under the account it started under, and a start or a close asks for a token of its
//! own. Signing in or out of the managed account is refused while a call is open, which includes a
//! start that is waiting on the broker and a close that is not finished (the coordinator counts
//! both). The commit of a sign-in and the removal of a sign-out then raise a gate that makes every
//! token request wait while they run: a start that begins after the check waits for the change to
//! end and takes the token of the account the change leaves, or is refused when none is left, and
//! one that began before it was counted by the check. No call can hold a token of the old account
//! across the change. No call is made under the storage account, so it has no calls to wait for.
//!
//! A call whose device went silent does not hold the account for good. Before a request is refused
//! for a call, the calls that are over are ended: one past its own deadline, and one the managed
//! service says it no longer holds open (the coordinator asks it). A call the service cannot be
//! asked about is held open until its deadline.
//!
//! Signing out removes the grant and asks the service to end it, under the same scope rule as
//! signing in.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::account::{
    AccountHttp, AccountService, AccountStatus, AccountTokenSource, Answer, AnswerFault,
    AuthorisationGrant, AuthorisationRequest, BACKUP_WRITE_SCOPE, Client, Commit, Exchanged,
    IdentityRead, ManagedAccountService, PendingAuthorisation, RELAY_LEASE_SCOPE, Redirect,
    SignedInAccount, TokenOfAccount, Unrevoked,
};
use kr_client::services::{AccountToken, HttpDeadlines, ServiceFuture};
use kr_crypto::store::SecretStore;
use kr_loopback::{BindError, Listener};
use kr_protocol::error::ErrorCode;
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInStarted, AccountSignedOut, AccountState,
    SignInUnavailable,
};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::service::GatewayOrigin;
use tokio::sync::watch;

use crate::config::Outbound;
use crate::error::{ControllerError, Result};
use crate::grants::policy::HeldBound;
use crate::managed_transport::{ClosedTransport, ManagedTransport};
use crate::service::{Ask, Controller, Footing, LeasedFooting, LeasedLapse};

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
///
/// Built from one origin, so the client, the transport it goes over and the scope the grant is kept
/// in cannot belong to different services.
pub struct Service {
    /// The account service's origin. Everything stored for the sign-in is kept under its name.
    origin: String,
    /// The resource scopes a sign-in asks for: one for each service the host presents its account
    /// to, and none for a service the host does not select.
    scopes: Vec<&'static str>,
    /// The account service at that origin.
    account: Arc<dyn AccountService>,
    /// Why every request to it is turned away, when the host's outbound route is closed: the
    /// account it keeps can be read and ended, and nothing is sent until the route is open.
    closed: Option<String>,
}

impl Service {
    /// The account service at `origin`, reached over `route`, where a sign-in asks for `scopes`.
    ///
    /// A callback and an ID token are checked against `origin`'s own issuer, a code or a stored
    /// grant that names another issuer is neither exchanged nor refreshed at it, and the transport
    /// reaches that origin and no other, so a revocation, an identity read and a usage read go there
    /// too.
    #[must_use]
    pub fn at_origin(origin: &GatewayOrigin, scopes: Vec<&'static str>, route: Outbound) -> Self {
        let (transport, closed): (Arc<dyn AccountHttp>, Option<String>) = match route {
            Outbound::Closed(refusal) => (Arc::new(ClosedTransport), Some(refusal)),
            Outbound::Through(proxy) => (
                Arc::new(ManagedTransport::new(
                    origin.clone(),
                    Some(proxy),
                    HttpDeadlines::default(),
                )),
                None,
            ),
            Outbound::Direct => (
                Arc::new(ManagedTransport::new(
                    origin.clone(),
                    None,
                    HttpDeadlines::default(),
                )),
                None,
            ),
        };
        Self {
            origin: origin.as_str().to_owned(),
            scopes,
            account: Arc::new(ManagedAccountService::at_origin(
                origin.as_str(),
                transport,
                Client::Desktop,
            )),
            closed,
        }
    }
}

/// What a refusal says when the request had already ended the sign-in that was waiting for the
/// browser: that sign-in is not brought back by the refusal.
const EARLIER_SIGN_IN_CANCELLED: &str = "The sign-in that was waiting for the browser was cancelled \
     before this request was refused, and it stays cancelled.";

/// What the browser shows when the person completes a sign-in whose authority ended while it
/// waited: nothing was signed in, and the service's issue is revoked (queued before it is sent, so
/// the page does not say it was).
const AUTHORITY_ENDED_PAGE: &str = "This host's authority for this sign-in ended while the sign-in \
     waited for you. Nothing was signed in. The host revokes what the account service issued. To \
     sign in, start again on the host.";

/// What the browser shows when the same happened and the revocation of what the service issued
/// reached neither the service nor the queue: the token is in the process's memory alone, and is
/// sent again the next time the host uses the account.
const AUTHORITY_ENDED_REVOCATION_OWED_PAGE: &str = "This host's authority for this sign-in ended \
     while the sign-in waited for you. Nothing was signed in. The host could not yet revoke what the \
     account service issued. The host tries again the next time it uses the account, and what was \
     issued ends by itself when it expires. To sign in, start again on the host.";

/// What the browser shows when a call opened while the sign-in's code was exchanged and the
/// revocation of what the service issued reached neither the service nor the queue: the sentences
/// of the page of a call that is open, and of the owed revocation, as they stand there.
const CALL_OPEN_REVOCATION_OWED_PAGE: &str = "A voice call is open on this host. End it, then sign \
     in again. The host could not yet revoke what the account service issued. The host tries again \
     the next time it uses the account, and what was issued ends by itself when it expires.";

/// What the browser shows when the grant could not be kept and the revocation of what the service
/// issued reached neither the service nor the queue: the sentence of the page of a grant that was
/// not kept, and the sentences of the owed revocation, as they stand there.
const NOT_KEPT_REVOCATION_OWED_PAGE: &str = "This host could not keep the sign-in. The host could \
     not yet revoke what the account service issued. The host tries again the next time it uses \
     the account, and what was issued ends by itself when it expires.";

/// What the browser shows when the service did not sign the host in and left a token whose
/// revocation reached neither the service nor the queue: the sentence of the page of a refused
/// sign-in, and the sentences of the owed revocation, as they stand there.
const SERVICE_REFUSED_REVOCATION_OWED_PAGE: &str = "The account service did not sign this host in. \
     The host could not yet revoke what the account service issued. The host tries again the next \
     time it uses the account, and what was issued ends by itself when it expires.";

/// Whose token a failed revocation was of, in each place that ends a token it does not keep: the
/// words of the line begin with them.
const WITHHELD: &str = "a withheld sign-in's";
const CALL_OPEN: &str = "a call-open sign-in's";
const UNKEPT: &str = "an unkept sign-in's";
const REFUSED_EXCHANGE: &str = "a refused exchange's";

/// Writes the line of a failed revocation of `whose` token, where it failed.
fn say_failed_revocation(whose: &str, unrevoked: Option<&Unrevoked>) {
    if let Some(unrevoked) = unrevoked {
        eprintln!("{}", failed_revocation_line(whose, unrevoked));
    }
}

/// Whether the revocation is still owed: neither the queue nor the service took the token, so
/// this process holds it in memory for the next send.
const fn owes(unrevoked: Option<&Unrevoked>) -> bool {
    matches!(unrevoked, Some(Unrevoked::Held(_)))
}

/// The line that records a failed revocation of `whose` token: what the queue and the service are
/// known to have done, and "may" where a step that failed can have done more than it reported (a
/// write that landed before its flush failed, a send that reached the service).
fn failed_revocation_line(whose: &str, unrevoked: &Unrevoked) -> String {
    let (said, error) = match unrevoked {
        Unrevoked::Queued(error) => (
            "the queue took the token and sending the queue failed, and a send of the token \
             alone was not acknowledged; the service may have taken the token, and the queue \
             may still hold its entry",
            error,
        ),
        Unrevoked::Ended(error) => (
            "the service took the token by a send of its own; the queue of revocations failed, \
             and may still hold its entry",
            error,
        ),
        Unrevoked::Held(error) => (
            "queuing the token failed and a send of the token alone was not acknowledged; a \
             write that had begun may have left its entry in place, and the service may have \
             taken the token; the token is held in memory for the next send",
            error,
        ),
    };
    format!("kr-controller: {whose} token: {said}: {error}")
}

/// What a waiting sign-in came to.
#[derive(Clone, Copy)]
enum Outcome {
    /// One of the outcomes a report names.
    Attempt(AccountAttempt),
    /// The host's authority for the sign-in ended while it waited, so no grant was kept. It is
    /// reported as a grant that was not kept ([`AccountAttempt::NotKept`]); the browser is told why.
    AuthorityEnded,
    /// As [`Self::AuthorityEnded`], and the revocation of what the service issued is still owed.
    AuthorityEndedRevocationOwed,
    /// A call opened while the sign-in's code was exchanged, so no grant was kept
    /// ([`AccountAttempt::CallOpen`]); and the revocation of what the service issued is still owed.
    CallOpenRevocationOwed,
    /// The grant could not be kept ([`AccountAttempt::NotKept`]); and the revocation of what the
    /// service issued is still owed.
    NotKeptRevocationOwed,
    /// The service did not sign the host in ([`AccountAttempt::ServiceRefused`]), and left a token
    /// whose revocation is still owed.
    ServiceRefusedRevocationOwed,
}

impl Outcome {
    /// What a sign-in came to when the keep withheld its grant, because the authority it was
    /// started under no longer stood: `commit` says whether the revocation of what the service
    /// issued reached neither the service nor the queue ([`Commit::WithheldOwing`]).
    const fn withheld(commit: Commit) -> Self {
        match commit {
            Commit::WithheldOwing => Self::AuthorityEndedRevocationOwed,
            _ => Self::AuthorityEnded,
        }
    }

    /// What a sign-in came to when a call opened while its code was exchanged: `commit` says
    /// whether the revocation of what the service issued reached neither the service nor the queue
    /// ([`Commit::WithheldOwing`]).
    const fn call_open(commit: Commit) -> Self {
        match commit {
            Commit::WithheldOwing => Self::CallOpenRevocationOwed,
            _ => Self::Attempt(AccountAttempt::CallOpen),
        }
    }

    /// What a sign-in came to when its grant could not be kept: `unrevoked` says whether the
    /// revocation of what the service issued is still owed.
    const fn not_kept(unrevoked: Option<&Unrevoked>) -> Self {
        if owes(unrevoked) {
            Self::NotKeptRevocationOwed
        } else {
            Self::Attempt(AccountAttempt::NotKept)
        }
    }

    /// What a sign-in came to when the service refused it and left a token behind: `unrevoked`
    /// says whether the revocation of that token is still owed.
    const fn service_refused(unrevoked: Option<&Unrevoked>) -> Self {
        if owes(unrevoked) {
            Self::ServiceRefusedRevocationOwed
        } else {
            Self::Attempt(AccountAttempt::ServiceRefused)
        }
    }

    /// What the account's report names.
    const fn attempt(self) -> AccountAttempt {
        match self {
            Self::Attempt(attempt) => attempt,
            Self::AuthorityEnded
            | Self::AuthorityEndedRevocationOwed
            | Self::NotKeptRevocationOwed => AccountAttempt::NotKept,
            Self::CallOpenRevocationOwed => AccountAttempt::CallOpen,
            Self::ServiceRefusedRevocationOwed => AccountAttempt::ServiceRefused,
        }
    }

    /// What the browser is shown.
    const fn page(self) -> &'static str {
        match self {
            Self::Attempt(attempt) => page(attempt),
            Self::AuthorityEnded => AUTHORITY_ENDED_PAGE,
            Self::AuthorityEndedRevocationOwed => AUTHORITY_ENDED_REVOCATION_OWED_PAGE,
            Self::CallOpenRevocationOwed => CALL_OPEN_REVOCATION_OWED_PAGE,
            Self::NotKeptRevocationOwed => NOT_KEPT_REVOCATION_OWED_PAGE,
            Self::ServiceRefusedRevocationOwed => SERVICE_REFUSED_REVOCATION_OWED_PAGE,
        }
    }
}

/// What the authority a sign-in was started under rests on, and what its question is asked with:
/// the host, and the footing with the lease's bound where the sign-in is held to a lease. It is
/// made before the question and the question is asked through it (`Guard::ask`), so that nothing
/// is allocated and nothing is let go of between the question and the write that follows it. The
/// one who asks holds it until that write has returned: letting go of the host or of the bound's
/// last reference can free memory, and the host is not let go of between the ask and the write.
pub struct Guard {
    /// The host, held so that it is not let go of between the question and the write.
    _daemon: Option<Arc<Controller>>,
    /// What the question is asked with.
    standing: Standing,
}

/// What a [`Guard`] asks its question with.
enum Standing {
    /// No host's authority governs the account: the question stands.
    Nothing,
    /// A footing, for a sign-in that no lease holds.
    Open(Footing),
    /// A footing and the bound of the lease that the sign-in is held to.
    Leased(LeasedFooting),
}

impl Guard {
    /// A guard for an account that no host's authority governs: its question always stands.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            _daemon: None,
            standing: Standing::Nothing,
        }
    }

    /// A guard that holds `daemon` and asks with `footing`, and with `bound` where the lease's
    /// reading found one. It allocates nothing: it takes what it is given.
    pub(crate) fn holding(
        daemon: Arc<Controller>,
        footing: Footing,
        bound: Option<HeldBound>,
    ) -> Self {
        Self {
            _daemon: Some(daemon),
            standing: match bound {
                Some(bound) => Standing::Leased(footing.holding(bound)),
                None => Standing::Open(footing),
            },
        }
    }

    /// The footing's question, asked through the guard (`Footing::ask`). No lock is taken and
    /// nothing is awaited. A guard that holds the lease's bound first copies the snapshot its cell
    /// publishes, which can allocate (the first use of a thread) and let go of a reference; it
    /// reads the clocks, and the reading of the UTC clock raises the floor, an atomic raise that
    /// never waits. After those, and on a guard that holds no bound, the question is comparisons
    /// of atomics and clocks: nothing is allocated, freed or written after it.
    ///
    /// # Errors
    ///
    /// Returns the member that refuses, and a bound that moved as itself.
    pub(crate) fn ask(&self, ask: Ask) -> std::result::Result<(), LeasedLapse> {
        match &self.standing {
            Standing::Nothing => Ok(()),
            Standing::Open(footing) => footing.ask(ask).map_err(LeasedLapse::from),
            Standing::Leased(leased) => leased.ask(ask),
        }
    }
}

#[cfg(test)]
impl Guard {
    /// Whether the guard holds the host.
    pub(crate) const fn holds_the_host(&self) -> bool {
        self._daemon.is_some()
    }
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Guard").finish_non_exhaustive()
    }
}

/// Whether the authority a sign-in was started under still stands, asked when the person completes
/// it, after the request that started it has answered and its connection has ended. It asks the
/// fence this host owes and the local owner's membership lease, and neither the request's deadline
/// nor its connection. The [`Guard`] is made before the question and the question is asked through
/// it; where the authority stands, the guard is given to hold until the write has returned.
pub type Lasting = Arc<dyn Fn() -> Result<Guard> + Send + Sync>;

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

/// The attempt that is waiting: whose it is, how to end it, and the task to wait for.
struct Running {
    owner: std::sync::Weak<Inner>,
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Whether this is an attempt of `account`.
    fn is_of(&self, account: &Arc<Inner>) -> bool {
        std::sync::Weak::ptr_eq(&self.owner, &Arc::downgrade(account))
    }

    /// Ends the attempt, and waits until its task has finished.
    async fn end(self) {
        let _ = self.cancel.send(true);
        let _ = self.task.await;
    }
}

/// Why no listener was opened for a sign-in.
enum NoListener {
    /// The address could not be bound.
    Bind(BindError),
    /// The request no longer stands, so the address was not asked for.
    Withheld(ControllerError),
}

/// What the host's two accounts share. Both sign in through the one loopback address the desktop
/// client is registered with, so the sign-in that waits for the browser is one, whichever account
/// it is of.
struct Accounts {
    running: tokio::sync::Mutex<Option<Running>>,
    /// The origin of the storage service the person runs, once the host has an account at it.
    storage_origin: std::sync::OnceLock<String>,
    /// Where this host's own tests stop a sign-in or a sign-out where it asks whether the request
    /// it serves still stands, so that the authority can change in between. Compiled away in every
    /// shipped build.
    #[cfg(feature = "testing")]
    before_it_asks_whether_it_stands: crate::service::ReadPause,
    /// Where this host's own tests stop a sign-in after its last early ask and before it takes the
    /// lock under which it is shown as waiting, so that the authority can change in between.
    /// Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_it_is_shown_as_waiting: crate::service::ReadPause,
    /// Where this host's own tests stop a sign-in immediately before it asks whether its request
    /// still stands for a try to bind the address a sign-in comes back to, so that the authority
    /// can change in that wait. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_it_binds: crate::service::ReadPause,
    /// How many times the address a sign-in comes back to was bound for a sign-in.
    #[cfg(feature = "testing")]
    binds: std::sync::atomic::AtomicUsize,
    /// Where this host's own tests stop a sign-in that has its tokens, immediately before it asks
    /// whether the authority it was started under still stands for the gate that holds other
    /// changes off, so that the authority can change in that wait. Compiled away in every shipped
    /// build.
    #[cfg(feature = "testing")]
    before_the_change_gate: crate::service::ReadPause,
    /// How many times the gate that holds other changes off was raised.
    #[cfg(feature = "testing")]
    change_gates: std::sync::atomic::AtomicUsize,
}

/// Whether the request that asked for a change of the account still stands: the check every
/// service asks of the admission its request carries, asked again where the change is about to
/// land, after the waits that come first.
pub type Stands<'a> = &'a (dyn Fn() -> Result<()> + Send + Sync);

/// The managed calls on this host, as the account needs to know them.
pub trait Calls: Send + Sync {
    /// Whether a managed call is open, or about to open or close.
    fn open(&self) -> bool;

    /// Ends the calls that are over without their device, so that they are no longer open: a call
    /// past its own deadline, and one the managed service no longer holds open.
    fn end_those_that_are_over(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

struct Held {
    origin: String,
    scopes: Vec<&'static str>,
    account: Arc<dyn AccountService>,
    signed_in: SignedInAccount,
}

struct Inner {
    held: Option<Held>,
    unavailable: Option<SignInUnavailable>,
    /// The refusal of a closed outbound route, which a refusal for `NotUsable` then carries.
    closed: Option<String>,
    state: Mutex<State>,
    /// What this host's two accounts share.
    accounts: Arc<Accounts>,
    /// The one scope this account hands out, for the storage account, whatever its grant holds.
    /// The managed account hands out every scope its grant holds that a client asks for.
    only: Option<&'static str>,
    /// The scope of each request for a token this account has been asked for, a refused one
    /// included, for a test that shows which clients ask which account.
    #[cfg(feature = "testing")]
    token_requests: Mutex<Vec<String>>,
    /// Settled once, before the first token is handed out: a grant whose own revocation was queued
    /// when an earlier run stopped is removed, and every revocation the service has not
    /// acknowledged is sent again.
    recovered: tokio::sync::OnceCell<()>,
    /// The managed calls on this host, once the voice service exists.
    calls: std::sync::OnceLock<Arc<dyn Calls>>,
    /// True while the account is being changed: a request for a token waits until it has been.
    changing: tokio::sync::watch::Sender<bool>,
    /// How many requests for a token are waiting for a change to end, for a test to know that one has
    /// reached the gate.
    #[cfg(feature = "testing")]
    waiting: std::sync::atomic::AtomicUsize,
    /// How many requests for a token pass the gate a test raised before the rest wait at it.
    #[cfg(feature = "testing")]
    passing: std::sync::atomic::AtomicUsize,
    /// Whether the gate a test raised holds only the requests made under an account fixed when a
    /// call began, and lets every other request for a token go by.
    #[cfg(feature = "testing")]
    holds_fixed_only: std::sync::atomic::AtomicBool,
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

/// What [`HostAccount::grant_mark`] says of the grant the host holds.
#[derive(Clone, Debug)]
pub struct GrantMark(Option<AccountStatus>);

impl PartialEq for GrantMark {
    fn eq(&self, other: &Self) -> bool {
        matches!((&self.0, &other.0), (Some(held), Some(then)) if held == then)
    }
}

impl HostAccount {
    /// The managed account of one environment, kept in `store`, at `service` where this host can
    /// reach the account service, or why it cannot. `refused` is why this host neither signs in nor
    /// presents its account, when it does not: it selects no storage service of the managed origin
    /// and its voice broker is not the account service.
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
        let accounts = Arc::new(Accounts {
            running: tokio::sync::Mutex::new(None),
            storage_origin: std::sync::OnceLock::new(),
            #[cfg(feature = "testing")]
            before_it_asks_whether_it_stands: crate::service::ReadPause::default(),
            #[cfg(feature = "testing")]
            before_it_is_shown_as_waiting: crate::service::ReadPause::default(),
            #[cfg(feature = "testing")]
            before_it_binds: crate::service::ReadPause::default(),
            #[cfg(feature = "testing")]
            binds: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "testing")]
            before_the_change_gate: crate::service::ReadPause::default(),
            #[cfg(feature = "testing")]
            change_gates: std::sync::atomic::AtomicUsize::new(0),
        });
        Self::build(store, environment_id, service, refused, accounts, None)
    }

    /// The account of the storage service a person runs, beside the managed account `managed`,
    /// kept in `store` in a scope of its own.
    ///
    /// It asks for `backup.write` when a person signs in, and hands out that scope and no other,
    /// whatever its grant holds. A sign-in of either account ends a waiting sign-in of the other,
    /// because the two share the one address a browser comes back to.
    ///
    /// A scope is named by a truncated digest of its service's origin, and a revocation that waits
    /// to be sent holds a grant identifier and a refresh token and no issuer. A storage service
    /// whose scope has the managed account's name would read the managed queue and be sent live
    /// managed refresh tokens, so it is refused here, before the account exists and before
    /// anything is settled in its scope: building the account starts settling at once. The name
    /// is compared with the scope of `managed_origin`, the managed account service's origin, and
    /// not with whatever the managed account holds, so the rule does not depend on how that
    /// account was built.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] naming `storage.origin` when the two scopes have
    /// one name.
    pub fn for_storage(
        managed: &Self,
        store: Arc<dyn SecretStore>,
        environment_id: EnvironmentId,
        managed_origin: &str,
        service: std::result::Result<Service, SignInUnavailable>,
        refused: Option<SignInUnavailable>,
    ) -> Result<Self> {
        if let Ok(service) = &service
            && scope_of(environment_id, &service.origin) == scope_of(environment_id, managed_origin)
        {
            return Err(ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) names a service whose sign-in \
                 would be kept under the same name as the managed account's: name the service by \
                 another origin",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            )));
        }
        let accounts = Arc::clone(&managed.inner.accounts);
        if let Ok(service) = &service {
            let _ = accounts.storage_origin.set(service.origin.clone());
        }
        Ok(Self::build(
            store,
            environment_id,
            service,
            refused,
            accounts,
            Some(BACKUP_WRITE_SCOPE),
        ))
    }

    fn build(
        store: Arc<dyn SecretStore>,
        environment_id: EnvironmentId,
        service: std::result::Result<Service, SignInUnavailable>,
        refused: Option<SignInUnavailable>,
        accounts: Arc<Accounts>,
        only: Option<&'static str>,
    ) -> Self {
        let (held, unavailable, closed) = match service {
            Ok(service) => {
                // Everything kept for the sign-in lives under the service that issued it.
                let signed_in = SignedInAccount::at_origin(
                    &service.origin,
                    Arc::clone(&service.account),
                    store,
                    Client::Desktop,
                )
                .in_scope(scope_of(environment_id, &service.origin));
                (
                    Some(Held {
                        origin: service.origin,
                        scopes: service.scopes,
                        account: service.account,
                        signed_in,
                    }),
                    refused,
                    service.closed,
                )
            }
            Err(unavailable) => (None, Some(unavailable), None),
        };
        let account = Self {
            inner: Arc::new(Inner {
                held,
                unavailable,
                closed,
                state: Mutex::new(State::default()),
                accounts,
                only,
                #[cfg(feature = "testing")]
                token_requests: Mutex::new(Vec::new()),
                recovered: tokio::sync::OnceCell::new(),
                calls: std::sync::OnceLock::new(),
                changing: tokio::sync::watch::channel(false).0,
                #[cfg(feature = "testing")]
                waiting: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                passing: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                holds_fixed_only: std::sync::atomic::AtomicBool::new(false),
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

    /// Whether this is the account of a storage service the person runs, beside the managed one.
    #[must_use]
    pub fn is_storage(&self) -> bool {
        self.inner.only.is_some()
    }

    /// The account service client, when a sign-in can start at it.
    ///
    /// A host that selects no managed service keeps a client to read and end a sign-in it already
    /// holds, and to that client it is not an account login: nothing it does presents an account.
    /// The same holds over a closed route, where nothing is sent.
    #[must_use]
    pub fn account_service(&self) -> Option<Arc<dyn AccountService>> {
        if self.inner.unavailable.is_some() {
            return None;
        }
        self.inner
            .held
            .as_ref()
            .map(|held| Arc::clone(&held.account))
    }

    /// Tells the account where the managed calls on this host are, so that signing in or out never
    /// changes the account a call closes under. A call is open from the moment its start asks the
    /// broker until its close has been told, or until it is over without its device.
    pub fn watch_calls(&self, calls: Arc<dyn Calls>) {
        let _ = self.inner.calls.set(calls);
    }

    /// Listens on `address` instead of the registered loopback address, for a test that runs
    /// several daemons at once. With port 0 the system gives each sign-in a free port when the
    /// daemon binds it, and the report of the waiting sign-in names the address that was bound: a
    /// test reads it from there and never chooses a port itself, which another process can take
    /// between the choice and the bind.
    #[cfg(feature = "testing")]
    pub fn listen_on(&self, address: std::net::SocketAddr) {
        *self.inner.loopback.lock().expect("the test address") = Some(address);
    }

    /// The scope of each request for a token this account has been asked for, in order, whether it
    /// handed one out or refused, for a test that shows which clients ask which account.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn token_scopes_asked(&self) -> Vec<String> {
        self.inner
            .token_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How many requests for a token are waiting for a change of the account to end, for a test that
    /// holds the change and needs to know a request has reached it.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn token_requests_waiting(&self) -> usize {
        self.inner.waiting.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether a change of the account has begun and not ended, for a test that waits for a
    /// sign-out to be past its early asks and on its way to the account's hold.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn is_being_changed(&self) -> bool {
        *self.inner.changing.borrow()
    }

    /// Holds every request for a token at the gate a change of the account raises, until the
    /// returned guard is dropped, for a test that needs a call to be waiting for its token.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_token_requests(&self) -> TokenRequestsHeld {
        self.hold_token_requests_after(0)
    }

    /// As [`Self::hold_token_requests`], after the next `passing` requests for a token have gone
    /// through, for a test that needs a later request in a call to be the one that waits.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_token_requests_after(&self, passing: usize) -> TokenRequestsHeld {
        self.inner
            .passing
            .store(passing, std::sync::atomic::Ordering::SeqCst);
        self.inner.changing.send_replace(true);
        TokenRequestsHeld {
            inner: Arc::clone(&self.inner),
        }
    }

    /// As [`Self::hold_token_requests_after`], for the requests made under an account fixed when a
    /// call began ([`Self::tokens_fixed_to`]) alone: the next `passing` of those go through and the
    /// ones after wait. Every other request for a token goes through, takes none of the `passing`,
    /// and is not counted by [`Self::token_requests_waiting`]: the check of the sign-in that
    /// `backup.status` makes in a task that outlives a look which a bound cut, and the carrier's
    /// requests, can come at any moment. Besides a call's, the only request held is the read of the
    /// storage state that `backup.status` makes, which ends with the look.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_token_requests_fixed_to_an_account(&self, passing: usize) -> TokenRequestsHeld {
        self.inner
            .holds_fixed_only
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.hold_token_requests_after(passing)
    }

    /// How many requests for a token the gate raised with [`Self::hold_token_requests_after`] has
    /// still to let through, for a test that needs to know the request it holds is the one after.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn token_passes_left(&self) -> usize {
        self.inner.passing.load(std::sync::atomic::Ordering::SeqCst)
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
        let committed = held
            .signed_in
            .commit(issued, "a-nonce", || Some(()))
            .await
            .expect("the grant is kept");
        assert_eq!(committed, Commit::Kept);
    }

    /// A mark of the grant this host holds now, for whatever must know that the grant it saw has
    /// not been replaced since.
    ///
    /// Two marks are equal while it is the same grant with the same scopes, address and name: a
    /// refresh keeps all of them.
    /// They differ after a sign-in, a sign-out, a sign-in again of the same account, a grant the
    /// service ended, or a refresh that narrowed the scopes. They read the grant that is kept, and
    /// not the state of a sign-in attempt under way. A store that cannot be read gives a mark that
    /// is equal to none, itself included.
    #[must_use]
    pub fn grant_mark(&self) -> GrantMark {
        GrantMark(match &self.inner.held {
            None => Some(AccountStatus::SignedOut),
            Some(held) => held.signed_in.status().ok(),
        })
    }

    /// The token source a managed call to the service at `origin` presents: this host's sign-in at
    /// the account service, handed out only when `origin` is that service. A token is a bearer
    /// credential for the service that issued it, so a service at any other origin is refused one.
    #[must_use]
    pub fn tokens_for(&self, origin: &str) -> Arc<dyn AccountTokenSource> {
        Arc::new(HostTokens {
            inner: Arc::clone(&self.inner),
            origin: origin.to_owned(),
            held_to: HeldTo::Nothing,
        })
    }

    /// The token this host signs a relay payer request with, and the account it belongs to: its
    /// sign-in at the account service, handed out as any token is and only when `origin` is that
    /// service. With `renew` the access token is replaced by a refresh whether or not it was near
    /// its end.
    ///
    /// # Errors
    ///
    /// Returns why no token can be handed out: the service at `origin` is not the account service,
    /// no account is signed in, the sign-in has ended or was not granted the scope, or the store
    /// or the service failed.
    pub async fn relay_payer_token(
        &self,
        origin: &str,
        renew: bool,
    ) -> kr_client::Result<TokenOfAccount> {
        self.inner.counted(RELAY_LEASE_SCOPE);
        self.inner.allows(RELAY_LEASE_SCOPE)?;
        let tokens = HostTokens {
            inner: Arc::clone(&self.inner),
            origin: origin.to_owned(),
            held_to: HeldTo::Nothing,
        };
        let held = tokens.presented().await?;
        held.signed_in
            .token_of_account(RELAY_LEASE_SCOPE, renew)
            .await
    }

    /// The token source the backup clients present, held to `binding`: it hands out a token only
    /// when the account signed in now is the one the backups belong to, and, for a request made
    /// inside a carrier iteration, only when no replacement of that account committed since the
    /// iteration began.
    ///
    /// With nothing bound it passes through, because nothing is owed to an account yet.
    #[must_use]
    pub fn bound_tokens_for(
        &self,
        origin: &str,
        binding: Arc<crate::backup::binding::Binding>,
    ) -> Arc<dyn AccountTokenSource> {
        Arc::new(HostTokens {
            inner: Arc::clone(&self.inner),
            origin: origin.to_owned(),
            held_to: HeldTo::Cell(binding),
        })
    }

    /// The token source one call presents, fixed to the account whose mark the call took when it
    /// began: it hands out a token only while the account signed in is that one, so a call that
    /// runs for a while never presents the account another sign-in has put in its place.
    #[must_use]
    pub fn tokens_fixed_to(
        &self,
        origin: &str,
        mark: kr_client::services::AccountMark,
    ) -> Arc<dyn AccountTokenSource> {
        Arc::new(HostTokens {
            inner: Arc::clone(&self.inner),
            origin: origin.to_owned(),
            held_to: HeldTo::Account(mark),
        })
    }

    /// The mark of the account signed in now at the service at `origin`, or none when there is
    /// none or the sign-in cannot be read.
    #[must_use]
    pub fn mark_at(&self, origin: &str) -> Option<kr_client::services::AccountMark> {
        let held = self.inner.presenting().ok()?;
        if held.origin != origin {
            return None;
        }
        held.signed_in.mark(origin).ok().flatten()
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

    /// Asks `stands`, after the waits a change has made and before the effect it goes on to. A
    /// request whose authority was withdrawn, or whose deadline passed, while it waited for a call
    /// to settle, for a sign-in to end or for the service changes nothing.
    async fn still_stands(&self, stands: Stands<'_>) -> Result<()> {
        #[cfg(feature = "testing")]
        self.inner
            .accounts
            .before_it_asks_whether_it_stands
            .wait()
            .await;
        stands()
    }

    /// Arms the pause the next sign-in or sign-out stops at where it asks whether its request still
    /// stands, which each does before it ends a waiting sign-in and again before its change lands.
    /// Returns the end that says the call has arrived, and the end that lets it go. The pause fires
    /// once.
    #[cfg(feature = "testing")]
    pub fn pause_before_it_asks_whether_it_stands(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.inner.accounts.before_it_asks_whether_it_stands.arm()
    }

    /// Arms the pause the next sign-in stops at after its last early ask, before it takes the lock
    /// under which it is shown as waiting. Returns the end that says the sign-in has arrived, and the
    /// end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_it_is_shown_as_waiting(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.inner.accounts.before_it_is_shown_as_waiting.arm()
    }

    /// Arms the pause the next sign-in stops at immediately before it asks whether its request still
    /// stands for a try to bind the address a sign-in comes back to. Returns the end that says the
    /// sign-in has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_it_binds(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.inner.accounts.before_it_binds.arm()
    }

    /// How many times the address a sign-in comes back to was bound for a sign-in.
    #[cfg(feature = "testing")]
    pub fn binds_made(&self) -> usize {
        self.inner
            .accounts
            .binds
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Arms the pause the next sign-in that has its tokens stops at immediately before it asks
    /// whether the authority it was started under still stands for the gate that holds other
    /// changes off. Returns the end that says the sign-in has arrived, and the end that lets it go.
    /// The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_the_change_gate(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.inner.accounts.before_the_change_gate.arm()
    }

    /// How many times the gate that holds other changes off was raised.
    #[cfg(feature = "testing")]
    pub fn change_gates_raised(&self) -> usize {
        self.inner
            .accounts
            .change_gates
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Starts a sign-in: ends the one that is waiting, whichever account it is of, listens for the
    /// browser's answer and returns when the daemon is ready for it. The address the person opens is in
    /// [`Self::report`].
    ///
    /// `stands` is asked before the waiting sign-in is ended, immediately before each try to bind
    /// the address the person comes back to, and again, under the lock this one is shown as waiting
    /// under and immediately before it is shown, because the waits between them can outlast the
    /// request's authority: the end of the waiting sign-in, the pause between two tries to bind and
    /// the wait for the lock. A refusal after the waiting sign-in was ended says so (the words of
    /// `EARLIER_SIGN_IN_CANCELLED`).
    ///
    /// # Errors
    ///
    /// Returns why no sign-in can start: this host presents its account to no service, a sign-in is
    /// finishing, a managed call is open, another program holds the loopback address, or the request
    /// no longer stands.
    pub async fn sign_in(
        &self,
        stands: Stands<'_>,
        lasting: Lasting,
    ) -> Result<AccountSignInStarted> {
        let held = self.inner.presenting()?;
        if self.inner.a_call_is_open_after_settling().await {
            return Err(Inner::call_is_open());
        }
        let mut running = self.inner.accounts.running.lock().await;
        // The sign-in that waits is one for both accounts: it is this account's or the other's, and
        // one that is finishing has spent its code and is not ended by either.
        if let Some(older) = running.as_ref().and_then(|older| older.owner.upgrade()) {
            older.not_finishing()?;
        }
        self.inner.not_finishing()?;
        self.still_stands(stands).await?;
        let cancelled = match running.take() {
            Some(older) => {
                older.end().await;
                true
            }
            None => false,
        };
        let started: Result<AccountSignInStarted> = async {
            let listener = match self.listener(stands).await {
                Ok(listener) => listener,
                Err(NoListener::Withheld(error)) => return Err(error),
                Err(NoListener::Bind(error)) => {
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
            self.still_stands(stands).await?;
            #[cfg(feature = "testing")]
            self.inner
                .accounts
                .before_it_is_shown_as_waiting
                .wait()
                .await;
            let request = AuthorisationRequest::asking_at_origin(
                &held.origin,
                Client::Desktop,
                Redirect::Loopback,
                &held.scopes,
            )
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
            let url = request.url();
            let pending = PendingAuthorisation::new(request);
            let expires_at_ms = kr_ipc::now_ms()
                .get()
                .saturating_add(u64::try_from(WAIT.as_millis()).unwrap_or(u64::MAX));
            let address = listener.local_address().to_string();
            {
                // Asked again under the lock the sign-in is shown as waiting under, immediately
                // before it is shown: the earlier ask came before the lock, and the host's
                // authority can end in the wait for it.
                let mut state = self.inner.state.lock().expect("the sign-in state");
                stands()?;
                state.phase = Phase::Waiting {
                    url,
                    address,
                    expires_at_ms,
                };
            }
            let (cancel, cancelled) = watch::channel(false);
            let inner = Arc::clone(&self.inner);
            let task = tokio::spawn(async move {
                inner.attempt(listener, pending, cancelled, lasting).await;
            });
            *running = Some(Running {
                owner: Arc::downgrade(&self.inner),
                cancel,
                task,
            });
            Ok(AccountSignInStarted {
                expires_at_ms: TimestampMs::new(expires_at_ms),
            })
        }
        .await;
        started.map_err(|error| {
            if cancelled {
                error.after_an_effect(EARLIER_SIGN_IN_CANCELLED)
            } else {
                error
            }
        })
    }

    /// Signs the host out: ends this account's waiting sign-in, if it has one (a waiting sign-in of
    /// the host's other account is not this one's to end), removes the grant and asks the service to
    /// end it. A host with no account answers that there was none and changes nothing. A host
    /// moved off the managed broker signs out all the same: the account service it keeps its grant
    /// for does not depend on the broker.
    ///
    /// `stands` is asked before the waiting sign-in is ended, again once the account is settled, and
    /// a last time under the account's own hold, immediately before the revocation is queued and the
    /// grant deleted, because each wait between them can outlast the request's authority: a token
    /// refresh keeps that hold across its request to the service. A refusal after the waiting
    /// sign-in was ended says so (the words of `EARLIER_SIGN_IN_CANCELLED`).
    ///
    /// # Errors
    ///
    /// Returns why the host cannot sign out: it cannot reach the account service, a sign-in is
    /// finishing, a managed call is open, the request no longer stands, or the store could not be
    /// changed (the host then keeps the grant, unless only its deletion failed after its
    /// revocation was queued, in which case the next start removes it).
    pub async fn sign_out(&self, stands: Stands<'_>) -> Result<AccountSignedOut> {
        let held = self.inner.service()?;
        if self.inner.a_call_is_open_after_settling().await {
            return Err(Inner::call_is_open());
        }
        let mut running = self.inner.accounts.running.lock().await;
        self.inner.not_finishing()?;
        self.still_stands(stands).await?;
        // Only this account's waiting sign-in ends with its sign-out.
        let cancelled = if running
            .as_ref()
            .is_some_and(|older| older.is_of(&self.inner))
            && let Some(older) = running.take()
        {
            older.end().await;
            true
        } else {
            false
        };
        // From here the earlier sign-in is ended, and a refusal says so.
        let signed_out: Result<AccountSignedOut> = async {
            self.inner
                .recover()
                .await
                .map_err(|detail| ControllerError::Storage {
                    operation: "settle this host's account before signing it out",
                    detail,
                })?;
            self.still_stands(stands).await?;
            let _change = self.inner.begin_change()?;
            // The account's own hold can be kept across a token refresh's request to the service,
            // and the change waits for it. The last ask is made under that hold, immediately
            // before the revocation is queued and the grant deleted.
            let done = held.signed_in.sign_out(stands).await.map_err(|error| {
                ControllerError::Storage {
                    operation: "sign this host out",
                    detail: error.to_string(),
                }
            })??;
            // What came of earlier attempts says nothing about a host with no account.
            self.inner.state.lock().expect("the sign-in state").last = None;
            Ok(AccountSignedOut {
                was_signed_in: done.was_signed_in,
                service_told: done.service_told,
            })
        }
        .await;
        signed_out.map_err(|error| {
            if cancelled {
                error.after_an_effect(EARLIER_SIGN_IN_CANCELLED)
            } else {
                error
            }
        })
    }

    /// Binds the address a sign-in comes back to, where `stands` says the request still stands.
    ///
    /// An address that is refused is tried again for a short while before it is called held. The
    /// daemon's own earlier listener on it has been closed, but the kernel lets the address go only
    /// when the last copy of that socket is closed, and a process that another part of this program
    /// is starting at that moment holds a copy until it has started: on a busy machine that is
    /// longer than the close. `stands` is asked immediately before each try, since a pause between
    /// tries is a wait in which the request's authority can end, and binding the address takes it
    /// from whoever else would hold it.
    async fn listener(&self, stands: Stands<'_>) -> std::result::Result<Listener, NoListener> {
        let mut tries = 0;
        loop {
            #[cfg(feature = "testing")]
            self.inner.accounts.before_it_binds.wait().await;
            stands().map_err(NoListener::Withheld)?;
            match self.bind() {
                Err(BindError::Busy) if tries < BIND_TRIES => {
                    tries += 1;
                    tokio::time::sleep(BIND_PAUSE).await;
                }
                Err(error) => return Err(NoListener::Bind(error)),
                Ok(listener) => return Ok(listener),
            }
        }
    }

    fn bind(&self) -> std::result::Result<Listener, BindError> {
        #[cfg(feature = "testing")]
        self.inner
            .accounts
            .binds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        #[cfg(feature = "testing")]
        if let Some(address) = *self.inner.loopback.lock().expect("the test address") {
            return Listener::open_at(address, &address.to_string());
        }
        Listener::open()
    }
}

/// The gate a test raised with [`HostAccount::hold_token_requests`] or
/// [`HostAccount::hold_token_requests_fixed_to_an_account`]: the requests for a token that the gate
/// holds wait while this is held.
#[cfg(feature = "testing")]
pub struct TokenRequestsHeld {
    inner: Arc<Inner>,
}

#[cfg(feature = "testing")]
impl std::fmt::Debug for TokenRequestsHeld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenRequestsHeld")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "testing")]
impl Drop for TokenRequestsHeld {
    fn drop(&mut self) {
        self.inner
            .passing
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .holds_fixed_only
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.inner.changing.send_replace(false);
    }
}

/// What a service is named by in the store: a digest of its origin, truncated.
fn named_by(origin: &str) -> String {
    kr_cbor::sha256(origin.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The scope of the secret store that holds the sign-in at the account service at `origin`.
pub(crate) fn scope_of(environment_id: EnvironmentId, origin: &str) -> String {
    format!("{environment_id}/host-account/{}", named_by(origin))
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
    /// Whether a request made under `held_to` goes through the gate a test raised: it is not one the
    /// gate holds, or it is one of the requests the gate was raised to let by.
    #[cfg(feature = "testing")]
    fn lets_by(&self, held_to: &HeldTo) -> bool {
        (self
            .holds_fixed_only
            .load(std::sync::atomic::Ordering::SeqCst)
            && !matches!(held_to, HeldTo::Account(_)))
            || self.lets_one_pass()
    }

    /// Whether this request goes through a gate a test raised with a number of requests to let by.
    #[cfg(feature = "testing")]
    fn lets_one_pass(&self) -> bool {
        self.passing
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |left| left.checked_sub(1),
            )
            .is_ok()
    }

    /// Notes a request for a token for `scope`, for a test.
    fn counted(&self, scope: &str) {
        #[cfg(feature = "testing")]
        self.token_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(scope.to_owned());
        #[cfg(not(feature = "testing"))]
        let _ = scope;
    }

    /// Whether this account hands out a token for `scope`. The storage account hands out its one
    /// scope, whatever its grant holds, and this is read by every path that hands a token out.
    fn allows(&self, scope: &str) -> kr_client::Result<()> {
        match self.only {
            Some(only) if only != scope => Err(kr_client::ClientError::refusal(
                ErrorCode::PermissionDenied,
                kr_client::shown::Shown::said(
                    "this host's storage account hands out the backup.write scope and no other, \
                     so it presents no token for what this call is for",
                ),
            )),
            _ => Ok(()),
        }
    }

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
            self.not_configured(self.unavailable.unwrap_or(SignInUnavailable::NotUsable))
        })
    }

    /// The account service, when this host also signs in and presents its account there: it selects
    /// a storage service, which is that service, or its voice broker is that service.
    fn presenting(&self) -> Result<&Held> {
        let held = self.service()?;
        match self.unavailable {
            Some(reason) => Err(self.not_configured(reason)),
            None => Ok(held),
        }
    }

    fn not_configured(&self, reason: SignInUnavailable) -> ControllerError {
        // A host whose storage service is one the person runs has an account for it, which this
        // account's refusals do not speak for, and its `storage.origin` is not the line to change
        // to reach the managed services: that would move its backups.
        let storage = self.accounts.storage_origin.get();
        ControllerError::NotConfigured(match (reason, &self.closed, storage) {
            (SignInUnavailable::NotUsable, Some(closed), _) => format!(
                "{closed}; this host reaches the account service again when its daemon starts \
                 over a document it can use"
            ),
            (SignInUnavailable::NotUsable, None, _) => "this host cannot reach the account \
                 service the way its configuration says: see the daemon's log"
                .to_owned(),
            (SignInUnavailable::BrokerIsAnotherService, _, None) => "this host's \
                 voice.broker_origin names another service than the managed account service it \
                 signs in at, so there is nothing to sign in to"
                .to_owned(),
            (SignInUnavailable::BrokerIsAnotherService, _, Some(origin)) => format!(
                "this host's voice.broker_origin names another service than the managed account \
                 service it signs in at, so there is nothing to sign in to; its storage.origin \
                 names {origin}, a service you run, and `kr account sign-in --storage` signs this \
                 host in there"
            ),
            (SignInUnavailable::NoManagedService, _, None) => "this host names no managed \
                 service: set voice.broker_origin, storage.origin or relay.origin in its \
                 configuration document to the managed account service's origin"
                .to_owned(),
            (SignInUnavailable::NoManagedService, _, Some(origin)) => format!(
                "this host names no managed service. Its storage.origin names {origin}, a service \
                 you run, and `kr account sign-in --storage` signs this host in there. To use \
                 managed voice or relay leases, set voice.broker_origin or relay.origin to the \
                 managed account service's origin"
            ),
        })
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
        #[cfg(feature = "testing")]
        self.accounts
            .change_gates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        self.calls.get().is_some_and(|calls| calls.open())
    }

    /// Whether a call is open once the calls that are over have been ended.
    ///
    /// Asked at the places a person's request is turned away for a call, so that a call whose
    /// device is gone never turns one away for good. A call that is over only after this has
    /// looked, because its deadline passed while the service was being asked, still counts as open
    /// here and in the check inside the change: the request is turned away once, and the next one
    /// ends the record before it looks. The check inside the change is the plain one, because by
    /// then the account is about to change and every record must have been ended or counted.
    async fn a_call_is_open_after_settling(&self) -> bool {
        let Some(calls) = self.calls.get() else {
            return false;
        };
        calls.end_those_that_are_over().await;
        calls.open()
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
        lasting: Lasting,
    ) {
        let (outcome, reply) = tokio::select! {
            biased;
            () = ended(&mut cancel) => (Outcome::Attempt(AccountAttempt::Superseded), None),
            () = tokio::time::sleep(WAIT) => (Outcome::Attempt(AccountAttempt::TimedOut), None),
            (answer, callback) = listener.answered(&mut pending) => {
                (self.answered(answer, &lasting).await, Some(callback))
            }
        };
        // The state is settled before the browser is told, so a page that says the sign-in ended
        // is never ahead of what the host reports.
        {
            let mut state = self.state.lock().expect("the sign-in state");
            state.phase = Phase::Idle;
            state.last = Some(outcome.attempt());
        }
        if let Some(reply) = reply {
            reply.finish(outcome.page()).await;
        }
    }

    async fn answered(&self, answer: Answer, lasting: &Lasting) -> Outcome {
        match answer {
            Answer::Granted(grant) => {
                self.state.lock().expect("the sign-in state").phase = Phase::Finishing;
                self.finish(&grant, lasting).await
            }
            Answer::Refused => Outcome::Attempt(AccountAttempt::Refused),
            Answer::Failed(AnswerFault::ServiceFailure | AnswerFault::NoCode) => {
                Outcome::Attempt(AccountAttempt::ServiceRefused)
            }
            Answer::Failed(_) | Answer::Dropped(_) => {
                Outcome::Attempt(AccountAttempt::NotForThisAttempt)
            }
        }
    }

    /// Exchanges the code and keeps the grant.
    async fn finish(&self, grant: &AuthorisationGrant, lasting: &Lasting) -> Outcome {
        let Ok(held) = self.presenting() else {
            return Outcome::Attempt(AccountAttempt::Unreachable);
        };
        // A call closes under the account it started under. One that opened while the person was
        // in the browser ends this attempt before the code is spent, and the code expires unused.
        if self.a_call_is_open_after_settling().await {
            return Outcome::Attempt(AccountAttempt::CallOpen);
        }
        if let Err(error) = self.recover().await {
            eprintln!("kr-controller: {error}");
            return Outcome::Attempt(AccountAttempt::NotKept);
        }
        match held.account.exchange(grant).await {
            Ok(Exchanged::Issued(issued)) => {
                let refresh = issued.refresh_token.clone();
                // The account changes now, and the gate that holds other changes off is raised for
                // it. The authority the sign-in was started under is asked immediately before the
                // gate is raised, and its guard is held until the gate is up: the exchange was out
                // and the person was in the browser, and the authority can end in either wait. A
                // call that opened while the exchange was out leaves the new grant unused: it is
                // revoked, and nothing the call holds changes. Another change is not one this
                // attempt can be told apart from: a sign-out waits for an attempt, so only a call
                // can refuse it here.
                #[cfg(feature = "testing")]
                self.accounts.before_the_change_gate.wait().await;
                let Ok(guard) = lasting() else {
                    // The authority the sign-in was started under ended while the person was in the
                    // browser or the exchange was out, so no change is begun: what the service
                    // issued is revoked, queued before it is sent, and nothing is kept. The person
                    // is told as the keep tells them, so a revocation that is still owed is said.
                    let (commit, unrevoked) = held.signed_in.end_withheld(refresh).await;
                    say_failed_revocation(WITHHELD, unrevoked.as_ref());
                    return Outcome::withheld(commit);
                };
                let change = self.begin_change();
                drop(guard);
                let Ok(_change) = change else {
                    // A call opened while the exchange was out. The token is ended as a withheld
                    // sign-in's is, queued before it is sent, and the browser is told of a
                    // revocation that is still owed as it is there.
                    let (commit, unrevoked) = held.signed_in.end_withheld(refresh).await;
                    say_failed_revocation(CALL_OPEN, unrevoked.as_ref());
                    return Outcome::call_open(commit);
                };
                // The sign-in waited for the person, up to the end of its time, and the authority
                // it was started under can have ended in that wait: the fence this host owes and,
                // on a host that is exclusively organisation-managed, the owner's lease. The grant
                // is kept only where they still stand, asked under the account's hold immediately
                // before it is written, because a token refresh in flight can keep that hold across
                // its request to the service. Where they do not stand no grant is kept, and what
                // the service issued is revoked, as a sign-out revokes it. The attempt holds the
                // issue (the tokens the service gave for the spent code) and the account's gate.
                let kept = held
                    .signed_in
                    .keep(issued, grant.nonce(), || lasting().ok())
                    .await;
                match kept.answer {
                    Ok(Commit::Kept) => {}
                    Ok(withheld @ (Commit::Withheld | Commit::WithheldOwing)) => {
                        say_failed_revocation(WITHHELD, kept.unrevoked.as_ref());
                        return Outcome::withheld(withheld);
                    }
                    Ok(Commit::Unsettled) => {
                        // The store reported a failure and then could not say which grant it
                        // held. No token was ended while the store may hold it, and the account
                        // was settled at once: the host is signed out with every token ended or
                        // queued for the service, or the store still cannot be read or changed
                        // and the next recovery, sign-out or replacing sign-in settles it, until
                        // when a grant the store returns is presented as it was found.
                        eprintln!(
                            "kr-controller: the store could not say whether a host sign-in was \
                             kept; the host is signed out, or the account is settled at its next \
                             start, sign-out or sign-in"
                        );
                        return Outcome::Attempt(AccountAttempt::NotKept);
                    }
                    Err(error) => {
                        // The grant is not kept, so its token was ended: queued where the store
                        // allows, and sent once where it does not. Where that failed, the
                        // person is told as the keep tells them.
                        eprintln!("kr-controller: a host sign-in could not be kept: {error}");
                        say_failed_revocation(UNKEPT, kept.unrevoked.as_ref());
                        return Outcome::not_kept(kept.unrevoked.as_ref());
                    }
                }
                if let Ok(IdentityRead::Disagreed) =
                    held.signed_in.complete_identity(|| lasting().ok()).await
                {
                    return Outcome::Attempt(AccountAttempt::NotForThisAttempt);
                }
                Outcome::Attempt(AccountAttempt::SignedIn)
            }
            Ok(Exchanged::Refused { leftover }) => {
                let mut unrevoked = None;
                if let Some(leftover) = leftover {
                    (_, unrevoked) = held.signed_in.end_withheld(leftover).await;
                    say_failed_revocation(REFUSED_EXCHANGE, unrevoked.as_ref());
                }
                Outcome::service_refused(unrevoked.as_ref())
            }
            Err(error) => {
                eprintln!("kr-controller: a host sign-in's code could not be exchanged: {error}");
                Outcome::Attempt(AccountAttempt::Unreachable)
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
struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits until `changing` is down. When `count` is given, the wait is counted in it from the first
/// poll that finds the gate still up, and not before: a request that does not wait is not counted,
/// and neither is a yield the runtime makes of a task that has used up its budget.
async fn until_down(
    count: Option<&std::sync::atomic::AtomicUsize>,
    changing: &mut tokio::sync::watch::Receiver<bool>,
) {
    let mut counted = None;
    // Outside the task's budget: an exhausted budget makes the wait yield before it has looked at
    // the gate, which is not a wait for a change.
    let mut wait = std::pin::pin!(tokio::task::unconstrained(
        changing.wait_for(|changing| !*changing)
    ));
    std::future::poll_fn(|context| {
        let polled = wait.as_mut().poll(context);
        if polled.is_pending()
            && counted.is_none()
            && let Some(count) = count
        {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            counted = Some(Waiting(count));
        }
        polled.map(|_| ())
    })
    .await;
}

/// The token source a managed call presents.
struct HostTokens {
    inner: Arc<Inner>,
    /// The service the call is to.
    origin: String,
    /// The account the token must belong to, for the backup clients.
    held_to: HeldTo,
}

/// What the account a token belongs to is checked against.
enum HeldTo {
    /// Nothing: the call is to a service the host presents its account to, whichever account.
    Nothing,
    /// The account the backups belong to, as the committed setup records it and a replacement
    /// moves it.
    Cell(Arc<crate::backup::binding::Binding>),
    /// One account, fixed when a call began.
    Account(kr_client::services::AccountMark),
}

impl std::fmt::Debug for HostTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HostTokens").finish_non_exhaustive()
    }
}

impl HostTokens {
    /// The sign-in this host presents to the service the call is to, once a change of the account
    /// has ended and what an earlier run left is settled.
    async fn presented(&self) -> kr_client::Result<&Held> {
        let held = match self.inner.presenting() {
            Ok(held) if held.origin == self.origin => held,
            _ => {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    kr_client::shown::Shown::said(
                        "the service this call is to is not the account service this host \
                         signs in at, so it presents no account token",
                    ),
                ));
            }
        };
        // While the account is being changed a request waits for the change to end, so that a
        // call that starts then is made under the account the change leaves and not under one
        // that is about to go.
        let mut changing = self.inner.changing.subscribe();
        if *changing.borrow() {
            #[cfg(feature = "testing")]
            let passes = self.inner.lets_by(&self.held_to);
            #[cfg(not(feature = "testing"))]
            let passes = false;
            if !passes {
                #[cfg(feature = "testing")]
                let count = Some(&self.inner.waiting);
                #[cfg(not(feature = "testing"))]
                let count = None;
                until_down(count, &mut changing).await;
            }
        }
        if self.inner.recover().await.is_err() {
            return Err(kr_client::ClientError::refusal(
                ErrorCode::StorageUnavailable,
                kr_client::shown::Shown::said(
                    "this host's account could not be settled because its secret store failed",
                ),
            ));
        }
        Ok(held)
    }
}

impl AccountTokenSource for HostTokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            self.inner.counted(scope);
            self.inner.allows(scope)?;
            let held = self.presented().await?;
            let binding = match &self.held_to {
                HeldTo::Nothing => return held.signed_in.token(scope).await,
                HeldTo::Account(fixed) => {
                    let (token, mark) = held
                        .signed_in
                        .token_marked(scope, &self.origin, false)
                        .await?;
                    if mark != *fixed {
                        return Err(kr_client::ClientError::refusal(
                            ErrorCode::ResourceUnavailable,
                            kr_client::shown::Shown::said(
                                "this host is signed in as another account than the one this \
                                 call began under",
                            ),
                        ));
                    }
                    return Ok(token);
                }
                HeldTo::Cell(binding) => binding,
            };
            // The mark comes with the token from one read of the grant, and both are compared
            // with the binding after the read returns: a renewal can take seconds, and the binding
            // can be switched while it does.
            let (token, mark) = held
                .signed_in
                .token_marked(scope, &self.origin, false)
                .await?;
            let bound = binding.read();
            let Some(account) = bound.mark else {
                return Ok(token);
            };
            if account != mark {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::ResourceUnavailable,
                    kr_client::shown::Shown::said(
                        "this host is signed in as another account than the one its backups \
                         belong to",
                    ),
                ));
            }
            if crate::backup::binding::ITERATION_EPOCH
                .try_with(|epoch| *epoch != bound.epoch)
                .unwrap_or(false)
            {
                return Err(kr_client::ClientError::refusal(
                    ErrorCode::ResourceUnavailable,
                    kr_client::shown::Shown::said(
                        "the account this host's backups belong to was replaced while this \
                         request waited for its token",
                    ),
                ));
            }
            Ok(token)
        })
    }
}

#[cfg(test)]
mod revocation_orders;

#[cfg(test)]
mod tests {
    /// A sign-in whose authority ended is told so in the browser, and what is said of the
    /// revocation is what the keep did: it is sent or queued (the host revokes what was issued),
    /// or it reached neither the service nor the queue (the host could not yet revoke it, and
    /// tries again the next time it uses the account).
    #[test]
    fn a_sign_in_whose_authority_ended_says_what_became_of_the_revocation() {
        let queued = super::Outcome::withheld(super::Commit::Withheld).page();
        let owed = super::Outcome::withheld(super::Commit::WithheldOwing).page();
        assert!(
            queued.contains("authority for this sign-in ended"),
            "{queued}"
        );
        assert!(queued.contains("The host revokes what the account service issued."));
        assert!(!queued.contains("could not yet revoke"), "{queued}");
        assert!(owed.contains("authority for this sign-in ended"), "{owed}");
        assert!(owed.contains("could not yet revoke what the account service issued"));
        assert!(owed.contains("tries again the next time it uses the account"));
        assert!(!owed.contains("The host revokes what"), "{owed}");
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use super::until_down;

    /// The gate's wait is counted only while the gate is up. A task whose budget is spent has its next
    /// wait on the runtime's own channel cut short before the channel is looked at; that is not a wait
    /// for the gate, and it is not counted.
    #[tokio::test]
    async fn a_task_whose_budget_is_spent_does_not_count_as_waiting_at_a_gate_that_is_down() {
        let count = AtomicUsize::new(0);
        let (_sender, mut gate) = tokio::sync::watch::channel(false);
        let (ready, counted) = std::future::poll_fn(|context| {
            // Spend this poll's budget: the runtime's own yield comes when none is left.
            loop {
                let mut spend = Box::pin(tokio::task::consume_budget());
                if spend.as_mut().poll(context).is_pending() {
                    break;
                }
            }
            let mut wait = Box::pin(until_down(Some(&count), &mut gate));
            let ready = wait.as_mut().poll(context).is_ready();
            Poll::Ready((ready, count.load(Ordering::SeqCst)))
        })
        .await;
        assert!(ready, "the gate is down, so there is nothing to wait for");
        assert_eq!(counted, 0, "nothing waited");
    }

    /// A request that meets a gate that is up is counted while it waits, and not after.
    #[tokio::test]
    async fn a_request_at_a_gate_that_is_up_is_counted_until_the_gate_comes_down() {
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let (sender, gate) = tokio::sync::watch::channel(true);
        let waiting = {
            let count = std::sync::Arc::clone(&count);
            let mut gate = gate;
            tokio::spawn(async move { until_down(Some(&count), &mut gate).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request is counted while it waits");
        sender.send_replace(false);
        waiting.await.expect("the wait ends");
        assert_eq!(count.load(Ordering::SeqCst), 0, "counted no longer");
    }
}
