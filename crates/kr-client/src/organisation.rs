//! A member's device keeps the lease its organisation signed for it on the host it is paired with.
//!
//! A host answers for a device whose grant needs an organisation only while it holds a membership
//! lease the organisation signed for that device's key, and a lease lasts at most fifteen minutes.
//! The [`LeaseKeeper`] gets the lease from the organisation's service, presents it to the host with
//! `membership.present`, and does it again on the interval the service advises, which is five
//! minutes, so a renewal reaches the host about ten minutes before the lease it replaces ends.
//!
//! The first presentation comes before anything else on a connection: the host refuses every other
//! method to such a device until it holds a lease, and no lease survives a host's restart, so a
//! connection that is opened again presents first. The keeper holds the last lease the host took,
//! so a connection made beside the one that keeps it fresh presents that lease again and asks the
//! service for a new one only when the host refuses it, as a host does that restarted or whose
//! clock has passed the lease's end.
//!
//! What it does with a refusal depends on who can mend the cause. A lease that has run out, one the
//! host installed before it restarted, one a newer lease replaced, and one signed by a key the host
//! has not followed are mended by asking again, with the chain of keys beside the lease where that
//! is the cause. A service that is down, a host whose clock is in doubt and a service that asks for
//! a delay are waited out. A device whose account is not signed in, is not a member, or whose lease
//! the host refuses for a reason only an administrator can change is not retried: the keeper stops,
//! says why, and a person mends it.
//!
//! The organisation's service allows an account a hundred and twenty lease requests an hour, and
//! the same account's other devices spend from it. So no failure makes the keeper ask faster than
//! once a minute while it keeps a lease, and a stop that a person or an administrator mends is
//! remembered: the keeper answers a later connection with the same stop and sends nothing until
//! the stop has been held for the time [`LeaseStop::holds_for`] names. The service rejecting the
//! account's token is waited out and tried three times, with the token the account holds, because
//! the token source renews a token by itself as it nears its end and offers no renewal on demand;
//! after the third the person is told to sign in again.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, OrganisationId};
use kr_protocol::method::Method;
use kr_protocol::organisation::{MembershipPresentParams, MembershipPresentResult};
use kr_protocol::scalars::{AuthorisationKey, DurationMs, Nullable};
use kr_transport::reconnect::Backoff;

use crate::error::ClientError;
use crate::retry::UserAction;
use crate::services::MembershipLeaseService;
use crate::session::Session;

/// The shortest the keeper waits between two leases it asks the service for while it keeps one,
/// whatever the service advises and however it fails, so that no failure becomes a loop. The
/// organisation's service limits an account to a hundred and twenty lease requests an hour.
pub const SHORTEST_REFRESH: Duration = Duration::from_secs(60);

/// The longest the keeper waits between two leases, whatever the service advises: section 17's
/// five minutes. A lease lasts three times that, and a service that advised longer could not make
/// this device lose its membership.
pub const LONGEST_REFRESH: Duration =
    Duration::from_secs(kr_protocol::account::MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS / 1000);

/// How long a presentation stays acceptable.
const PRESENT_TTL: DurationMs = DurationMs::new(30_000);

/// How many times in a row the keeper asks again at once for a lease the host says has run out or
/// was installed before its restart, before it treats the host as one that cannot take it.
const IMMEDIATE_RETRIES: u32 = 3;

/// How many times a connection waits and asks again for its first lease before it gives up for now.
const FIRST_LEASE_TRIES: u32 = 3;

/// How many times in a row the host may refuse a lease for a reason the keeper does not know, or
/// the service reject its token, before the keeper stops.
const UNEXPLAINED_REFUSALS: u32 = 3;

/// The longest delay the service may name that a connection waits out: a connection is given
/// twenty seconds, and a longer delay is reported to the person and remembered instead.
const LONGEST_WAIT_AT_CONNECT: Duration = Duration::from_secs(10);

/// How much of a lease must be left, beyond the interval to the next one, for the keeper to
/// present it again rather than ask for another.
const LEASE_MARGIN: Duration = Duration::from_secs(30);

/// How long the keeper sends no request after a stop that an administrator mends.
const HELD_FOR_AN_ADMINISTRATOR: Duration = Duration::from_secs(5 * 60);

/// The longest the keeper sends no request after the service named a delay.
const LONGEST_HOLD: Duration = Duration::from_secs(60 * 60);

/// Time, so that a suite decides when it passes.
pub trait LeaseTimer: Send + Sync + fmt::Debug {
    /// Returns when `duration` has passed.
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// The time now, in UTC milliseconds, by the clock `wait` counts on.
    fn now_ms(&self) -> u64;
}

/// The time of a device that is running: time passes.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealTimer;

impl LeaseTimer for RealTimer {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn now_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

/// Why the keeper stopped. Each is something a person or an administrator mends, or a connection
/// that must be opened again; none is retried at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseStop {
    /// No account is signed in on this device with the right to ask for a lease. The device asked
    /// for nothing: its own account says so.
    SignIn,
    /// The organisation's service does not take the account's token, though the account holds one:
    /// it rejected it three times in a row, or asked for the sign-in to be made again.
    TokenRefused,
    /// The organisation's service says the signed-in account is not a member of the organisation.
    NotAMember,
    /// The host refuses the lease for a reason only a person or an administrator can change: the
    /// name of the host's rule, or what it did not accept.
    Refused(String),
    /// The service refused the request in a way asking again does not change.
    Unusable,
    /// The service asked this device to wait longer than a connection waits, so the connection
    /// reports the delay and the keeper asks again when it is over.
    Later(Duration),
    /// The connection to the host ended, so the lease it held is the host's to forget. A caller
    /// that opens another connection presents again before it asks the host anything.
    ConnectionEnded,
    /// The first lease could not be got in the few tries a connection is given, because the
    /// organisation's service or the host did not answer well enough. A caller that tries again
    /// later may succeed.
    Unreachable,
}

impl LeaseStop {
    /// The protocol code a person-facing failure for this stop carries.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::SignIn | Self::TokenRefused | Self::NotAMember | Self::Refused(_) => {
                ErrorCode::PermissionDenied
            }
            Self::Unusable => ErrorCode::InvalidArgument,
            Self::Later(_) => ErrorCode::RateLimited,
            Self::ConnectionEnded | Self::Unreachable => ErrorCode::ResourceUnavailable,
        }
    }

    /// What the person does about it.
    #[must_use]
    pub const fn user_action(&self) -> UserAction {
        match self {
            Self::SignIn | Self::TokenRefused => UserAction::SignIn,
            Self::NotAMember | Self::Refused(_) => UserAction::Nothing,
            Self::Unusable => UserAction::Update,
            Self::Later(_) | Self::ConnectionEnded | Self::Unreachable => UserAction::Wait,
        }
    }

    /// How long after this stop the keeper sends the service and the host nothing, so that a
    /// device that is stopped for a reason a person must mend does not use the account's allowance
    /// by reconnecting. None for a stop that made no request, or ended with a connection.
    #[must_use]
    pub fn holds_for(&self) -> Duration {
        match self {
            Self::SignIn | Self::ConnectionEnded => Duration::ZERO,
            Self::TokenRefused | Self::Unreachable => SHORTEST_REFRESH,
            Self::NotAMember | Self::Refused(_) | Self::Unusable => HELD_FOR_AN_ADMINISTRATOR,
            Self::Later(delay) => (*delay).min(LONGEST_HOLD),
        }
    }

    /// Whether the lease the keeper holds is no good once this has happened: it was signed for an
    /// account that may no longer be the one signed in, or for a membership that has ended.
    const fn spoils_the_lease(&self) -> bool {
        !matches!(
            self,
            Self::ConnectionEnded | Self::Unreachable | Self::Later(_)
        )
    }
}

/// A delay in words a person reads.
fn in_words(delay: Duration) -> String {
    let seconds = delay.as_secs().max(1);
    if seconds < 60 {
        return format!("{seconds} seconds");
    }
    match seconds.div_ceil(60) {
        1 => "a minute".to_owned(),
        minutes => format!("{minutes} minutes"),
    }
}

impl fmt::Display for LeaseStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignIn => formatter.write_str(
                "sign in to your account again: this device cannot ask your organisation for the \
                 lease that lets it use this host",
            ),
            Self::TokenRefused => formatter.write_str(
                "sign in to your account again: your organisation's service does not take the \
                 sign-in this device holds",
            ),
            Self::NotAMember => formatter
                .write_str("this account is not a member of the organisation this host answers to"),
            Self::Refused(rule) => write!(
                formatter,
                "this host refused the lease your organisation signed ({rule}); ask your \
                 organisation's administrator"
            ),
            Self::Unusable => formatter.write_str(
                "your organisation's service refused the request for a lease; update this app",
            ),
            Self::Later(delay) => write!(
                formatter,
                "your organisation's service asks this device to wait {} before it asks for the \
                 lease this host needs",
                in_words(*delay)
            ),
            Self::ConnectionEnded => {
                formatter.write_str("the connection to this host ended before a lease was held")
            }
            Self::Unreachable => formatter.write_str(
                "your organisation's service did not give this device the lease it needs just \
                 now; this app asks again",
            ),
        }
    }
}

/// What the keeper reports as it goes, for whoever shows it to a person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseEvent {
    /// The host holds a lease until the moment it names, in UTC milliseconds.
    Held {
        /// When the lease the host installed stops being usable.
        expires_at_ms: u64,
    },
    /// The keeper did not get a lease held this time and will try again.
    Retrying,
    /// The keeper stopped.
    Stopped(LeaseStop),
}

/// What one failure calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Next {
    /// Ask again at once for a new lease.
    Now,
    /// Fetch the chain of keys, and ask again at once.
    WithTheChain,
    /// Wait for the delay the service named.
    After(Duration),
    /// Wait out the backoff.
    BackOff,
    /// Wait out the backoff, and carry the chain of keys with the next presentation.
    BackOffWithTheChain,
    /// Wait out the backoff, and stop with this when the same thing has happened
    /// [`UNEXPLAINED_REFUSALS`] times in a row: nothing says what is wrong.
    Doubtful(LeaseStop),
    /// Stop, because only a person can mend this.
    Stop(LeaseStop),
}

/// Whether a lease may be presented again as it is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    /// The lease the host took, while it is not yet due to be replaced, and one the host has not
    /// taken yet.
    Held,
    /// Only a lease the host has not taken yet: this is the refresh.
    Unaccepted,
}

/// A lease the keeper holds, with what travelled beside it.
#[derive(Clone)]
struct Held {
    lease: MembershipLease,
    /// The chain of keys that was presented beside the lease, or fetched for it.
    authority: Option<PolicyAuthority>,
    /// The interval the service advised with the lease.
    advised: Duration,
    /// When the lease is due to be replaced, in UTC milliseconds, once the host has taken it.
    due_at_ms: Option<u64>,
}

impl Held {
    /// Whether this lease is worth presenting again at `now_ms`: it lasts through the interval to
    /// the next, and it is not yet due to be replaced when the host took it already.
    fn usable(&self, now_ms: u64, reuse: Reuse) -> bool {
        let needs = self.advised.max(SHORTEST_REFRESH) + LEASE_MARGIN;
        let lasts = self.lease.payload.expires_at_ms.get()
            > now_ms.saturating_add(u64::try_from(needs.as_millis()).unwrap_or(u64::MAX));
        lasts
            && match (self.due_at_ms, reuse) {
                (None, _) => true,
                (Some(due), Reuse::Held) => due > now_ms,
                (Some(_), Reuse::Unaccepted) => false,
            }
    }
}

/// What the keeper remembers between connections.
#[derive(Default)]
struct Kept {
    /// The highest key revision a lease the host accepted was signed with. A lease signed by a
    /// higher one travels with the chain that brings the revision in.
    followed: u64,
    /// The lease last got, and whether the host took it.
    lease: Option<Held>,
    /// A stop that sends nothing until the moment it names, in UTC milliseconds.
    held_back: Option<(u64, LeaseStop)>,
}

/// Keeps one organisation's lease for one device on one host.
pub struct LeaseKeeper {
    leases: Arc<dyn MembershipLeaseService>,
    timer: Arc<dyn LeaseTimer>,
    organisation: OrganisationId,
    environment: EnvironmentId,
    device_key: AuthorisationKey,
    kept: Mutex<Kept>,
    report: Box<dyn Fn(LeaseEvent) + Send + Sync>,
}

impl fmt::Debug for LeaseKeeper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseKeeper")
            .field("organisation", &self.organisation)
            .finish_non_exhaustive()
    }
}

impl LeaseKeeper {
    /// A keeper that gets the lease for `device_key` from `leases` and presents it to the host
    /// whose environment is `environment`, on the session each call is given.
    #[must_use]
    pub fn new(
        leases: Arc<dyn MembershipLeaseService>,
        timer: Arc<dyn LeaseTimer>,
        organisation: OrganisationId,
        environment: EnvironmentId,
        device_key: AuthorisationKey,
    ) -> Self {
        Self {
            leases,
            timer,
            organisation,
            environment,
            device_key,
            kept: Mutex::new(Kept::default()),
            report: Box::new(|_| {}),
        }
    }

    /// This keeper, telling `report` what it does.
    #[must_use]
    pub fn reporting(mut self, report: impl Fn(LeaseEvent) + Send + Sync + 'static) -> Self {
        self.report = Box::new(report);
        self
    }

    fn kept(&self) -> MutexGuard<'_, Kept> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Presents a lease as the first thing on the connection.
    ///
    /// The lease the host took last is presented again while it is not due to be replaced; the
    /// service is asked only when none is held, or the host refuses the one that is. A failure that
    /// asking again mends is mended here, and one that time mends is waited out.
    ///
    /// # Errors
    ///
    /// Returns why the host does not hold a lease and will not without a person or a new
    /// connection. A stop that a person or an administrator mends is returned again, with nothing
    /// sent, until the time it is held for has passed.
    pub async fn present_first(&self, session: &Session) -> Result<(), LeaseStop> {
        if let Some(stop) = self.held_back() {
            return Err(stop);
        }
        self.until_held(session, &mut Pace::first(), Reuse::Held)
            .await
            .map(|_| ())
    }

    /// Keeps the lease until something stops it. It begins with a wait until the lease the host
    /// holds is due to be replaced, so a lease just presented is not presented again.
    pub async fn keep(&self, session: &Session) -> LeaseStop {
        let mut pace = Pace::keeping();
        let mut wait = self.until_due();
        loop {
            self.timer.wait(wait).await;
            match self.until_held(session, &mut pace, Reuse::Unaccepted).await {
                Ok(advised) => wait = advised,
                Err(stop) => return stop,
            }
        }
    }

    /// How long until the lease the host holds is due to be replaced.
    fn until_due(&self) -> Duration {
        let now = self.timer.now_ms();
        self.kept()
            .lease
            .as_ref()
            .and_then(|held| held.due_at_ms)
            .map_or(SHORTEST_REFRESH, |due| {
                clamp(Duration::from_millis(due.saturating_sub(now)))
            })
    }

    /// The stop that is held, while it is.
    fn held_back(&self) -> Option<LeaseStop> {
        let now = self.timer.now_ms();
        let mut kept = self.kept();
        match &kept.held_back {
            Some((until, stop)) if *until > now => Some(stop.clone()),
            Some(_) => {
                kept.held_back = None;
                None
            }
            None => None,
        }
    }

    /// Asks and presents until the host holds a lease, and returns the interval to wait before the
    /// next.
    async fn until_held(
        &self,
        session: &Session,
        pace: &mut Pace,
        reuse: Reuse,
    ) -> Result<Duration, LeaseStop> {
        loop {
            let next = match self.step(session, pace.chain, reuse).await {
                Ok(advised) => {
                    pace.held();
                    return Ok(clamp(advised));
                }
                Err(next) => next,
            };
            if next == Next::Now {
                // The host will not take this lease again.
                self.kept().lease = None;
            }
            let wait = match next {
                Next::Now => pace.at_once(),
                Next::WithTheChain => {
                    pace.chain = true;
                    pace.at_once()
                }
                Next::After(delay) => {
                    if pace.connecting && delay > LONGEST_WAIT_AT_CONNECT {
                        return Err(self.stopped(LeaseStop::Later(delay)));
                    }
                    Some(delay.max(pace.floor))
                }
                Next::BackOff => Some(pace.backoff.next_delay()),
                Next::BackOffWithTheChain => {
                    pace.chain = true;
                    Some(pace.backoff.next_delay())
                }
                Next::Doubtful(stop) => {
                    pace.doubts += 1;
                    if pace.doubts >= UNEXPLAINED_REFUSALS {
                        return Err(self.stopped(stop));
                    }
                    Some(pace.backoff.next_delay())
                }
                Next::Stop(stop) => return Err(self.stopped(stop)),
            };
            if let Some(wait) = wait {
                if !pace.waits() {
                    return Err(self.stopped(LeaseStop::Unreachable));
                }
                (self.report)(LeaseEvent::Retrying);
                self.timer.wait(wait).await;
            }
        }
    }

    /// Records a stop: what it spoils is dropped, and what it holds back is held back.
    fn stopped(&self, stop: LeaseStop) -> LeaseStop {
        {
            let mut kept = self.kept();
            if stop.spoils_the_lease() {
                kept.lease = None;
            }
            let held = stop.holds_for();
            if !held.is_zero() {
                let until = self
                    .timer
                    .now_ms()
                    .saturating_add(u64::try_from(held.as_millis()).unwrap_or(u64::MAX));
                kept.held_back = Some((until, stop.clone()));
            }
        }
        (self.report)(LeaseEvent::Stopped(stop.clone()));
        stop
    }

    /// One lease presented, got from the service first when none is held to present. Returns the
    /// interval the service advised.
    async fn step(
        &self,
        session: &Session,
        force_chain: bool,
        reuse: Reuse,
    ) -> Result<Duration, Next> {
        let reusable = {
            let now = self.timer.now_ms();
            self.kept()
                .lease
                .as_ref()
                .filter(|held| held.usable(now, reuse))
                .cloned()
        };
        let mut held = match reusable {
            Some(held) => held,
            None => {
                let issued = self
                    .leases
                    .lease(self.organisation, self.device_key)
                    .await
                    .map_err(|error| from_the_service(&error))?;
                let held = Held {
                    lease: issued.lease,
                    authority: None,
                    advised: issued.refresh_after,
                    due_at_ms: None,
                };
                self.kept().lease = Some(held.clone());
                held
            }
        };
        let revision = held.lease.payload.key_revision.get();
        let newer = revision > self.kept().followed;
        // A chain the host refused for being behind is fetched again, not presented as it was.
        if force_chain || (held.authority.is_none() && newer) {
            held.authority = Some(
                self.leases
                    .authority(self.organisation)
                    .await
                    .map_err(|error| from_the_service(&error))?,
            );
        }
        let params = MembershipPresentParams {
            lease: held.lease.clone(),
            authority: held
                .authority
                .clone()
                .map_or_else(Nullable::null, Nullable::some),
        };
        let taken: MembershipPresentResult = session
            .mutate(
                Method::MembershipPresent,
                ActionTarget::environment(self.environment),
                None,
                &ParamsValue::empty(),
                &params,
                PRESENT_TTL,
            )
            .await
            .and_then(|settled| settled.to_typed())
            .map_err(|error| from_the_host(&error))?;
        let now = self.timer.now_ms();
        let advised = clamp(held.advised);
        let due = held.due_at_ms.unwrap_or_else(|| {
            now.saturating_add(u64::try_from(advised.as_millis()).unwrap_or(u64::MAX))
        });
        held.due_at_ms = Some(due);
        {
            let mut kept = self.kept();
            kept.followed = kept.followed.max(taken.key_revision.get()).max(revision);
            kept.lease = Some(held.clone());
        }
        (self.report)(LeaseEvent::Held {
            expires_at_ms: taken.expires_at_ms.get(),
        });
        Ok(held.advised)
    }
}

/// How the keeper paces itself while a lease is being got.
struct Pace {
    backoff: Backoff,
    /// The shortest a delay the service named is waited.
    floor: Duration,
    /// Whether a connection waits for this lease, and so gives up after a few tries and does not
    /// wait out a long delay.
    connecting: bool,
    /// The waits allowed before giving up for now, when there is a limit.
    waits_left: Option<u32>,
    /// Asks made at once in a row.
    immediate: u32,
    /// Failures in a row that nothing explains.
    doubts: u32,
    /// Whether the next presentation travels with the chain of keys.
    chain: bool,
}

impl Pace {
    /// The pace of a connection's first lease, which gives up after a few waits.
    fn first() -> Self {
        Self {
            backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(60)),
            floor: Duration::from_secs(1),
            connecting: true,
            waits_left: Some(FIRST_LEASE_TRIES),
            immediate: 0,
            doubts: 0,
            chain: false,
        }
    }

    /// The pace of the refresh, which never asks oftener than once a minute and goes on until
    /// something stops it.
    fn keeping() -> Self {
        Self {
            backoff: Backoff::new(SHORTEST_REFRESH, LONGEST_REFRESH),
            floor: SHORTEST_REFRESH,
            connecting: false,
            waits_left: None,
            immediate: 0,
            doubts: 0,
            chain: false,
        }
    }

    /// A lease is held: the next failure starts again.
    fn held(&mut self) {
        self.backoff.reset();
        self.immediate = 0;
        self.doubts = 0;
        self.chain = false;
    }

    /// Spends one wait, and says whether there was one to spend.
    fn waits(&mut self) -> bool {
        match &mut self.waits_left {
            Some(0) => false,
            Some(left) => {
                *left -= 1;
                true
            }
            None => true,
        }
    }

    /// How long to wait before asking again for a lease the host said to ask again for: none for
    /// the first few, and the backoff after, so a host that keeps saying it is not asked
    /// for ever.
    fn at_once(&mut self) -> Option<Duration> {
        self.immediate += 1;
        (self.immediate > IMMEDIATE_RETRIES).then(|| self.backoff.next_delay())
    }
}

/// The interval the service advised, held to the keeper's bounds.
fn clamp(advised: Duration) -> Duration {
    advised.clamp(SHORTEST_REFRESH, LONGEST_REFRESH)
}

/// What a refusal from the organisation's service calls for.
fn from_the_service(error: &ClientError) -> Next {
    let ClientError::Refused {
        service_code,
        retry_after_seconds,
        action,
        ..
    } = error
    else {
        return Next::BackOff;
    };
    match (*service_code, retry_after_seconds) {
        (Some("RATE_LIMITED" | "SERVICE_UNAVAILABLE"), Some(seconds)) => {
            Next::After(Duration::from_secs(*seconds))
        }
        (Some("REAUTHENTICATION_REQUIRED"), _) => Next::Stop(LeaseStop::TokenRefused),
        // A token the service rejects may have ended in transit, so the keeper asks again with
        // whatever the account holds now. The account being signed out is for the person.
        (Some("UNAUTHENTICATED"), _) => Next::Doubtful(LeaseStop::TokenRefused),
        (Some("FORBIDDEN"), _) => Next::Stop(LeaseStop::NotAMember),
        (Some("INVALID_REQUEST" | "METHOD_NOT_ALLOWED" | "NOT_FOUND"), _) => {
            Next::Stop(LeaseStop::Unusable)
        }
        // The device's own account named no service: it holds no token to ask with.
        (None, _) if *action == UserAction::SignIn => Next::Stop(LeaseStop::SignIn),
        _ => Next::BackOff,
    }
}

/// What a refusal from the host calls for.
fn from_the_host(error: &ClientError) -> Next {
    match error {
        ClientError::Transport(_)
        | ClientError::Ipc(_)
        | ClientError::ConnectionEnded
        | ClientError::SubmissionUncertain { .. } => Next::Stop(LeaseStop::ConnectionEnded),
        ClientError::Host(refusal) if refusal.code == ErrorCode::PermissionDenied => {
            match rule_of(&refusal.message) {
                Some(rule) => by_rule(rule),
                // A window the host no longer accepts, or a device it no longer answers to: the
                // connection says which when it ends.
                None => Next::Doubtful(LeaseStop::Refused("not explained".to_owned())),
            }
        }
        // A chain that does not verify, or one that is not current yet: time may mend the second,
        // and nothing says which this is.
        ClientError::Host(refusal) if refusal.code == ErrorCode::InvalidArgument => {
            Next::Doubtful(LeaseStop::Refused(
                "the host did not accept the lease or the chain of keys beside it".to_owned(),
            ))
        }
        _ => Next::BackOff,
    }
}

/// The name of the host's rule a refusal ends with, in parentheses.
fn rule_of(message: &str) -> Option<&str> {
    let inner = message.trim_end().strip_suffix(')')?;
    let (_, rule) = inner.rsplit_once('(')?;
    rule.bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        .then_some(rule)
}

/// The rules of a lease the host can refuse, and what each calls for.
const RULES: [(&str, Cure); 18] = [
    ("expired", Cure::Ask),
    ("installed_earlier", Cure::Ask),
    ("ambiguous_issue", Cure::Ask),
    ("superseded", Cure::Ask),
    ("unauthenticated_revision", Cure::Chain),
    ("issued_before_activation", Cure::ChainLater),
    ("signed_after_successor", Cure::ChainLater),
    ("not_yet_valid", Cure::Later),
    ("clock_untrusted", Cure::Later),
    ("floor_unrecorded", Cure::Later),
    ("not_enrolled", Cure::Person),
    ("no_organisation_grant", Cure::Person),
    ("host_not_exclusive", Cure::Person),
    ("bad_signature", Cure::Person),
    ("device_mismatch", Cure::Person),
    ("too_long", Cure::Person),
    ("above_role_ceiling", Cure::Person),
    ("account_mismatch", Cure::Person),
];

/// What mends a refused lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cure {
    /// Asking the service for a new lease: this one is gone, or a newer one is already held.
    Ask,
    /// The chain of keys beside the lease.
    Chain,
    /// Time, and the chain beside the lease.
    ChainLater,
    /// Time, and presenting the same lease again.
    Later,
    /// A person or an administrator.
    Person,
}

fn by_rule(rule: &str) -> Next {
    match RULES.iter().find(|(name, _)| *name == rule) {
        Some((_, Cure::Ask)) => Next::Now,
        Some((_, Cure::Chain)) => Next::WithTheChain,
        Some((_, Cure::ChainLater)) => Next::BackOffWithTheChain,
        Some((_, Cure::Later)) => Next::BackOff,
        Some((_, Cure::Person)) | None => Next::Stop(LeaseStop::Refused(rule.to_owned())),
    }
}

/// Every rule of a lease the host can refuse that this build knows, so that a suite holds the host's
/// list to this one.
#[must_use]
pub fn known_rules() -> Vec<&'static str> {
    RULES.iter().map(|(name, _)| *name).collect()
}
