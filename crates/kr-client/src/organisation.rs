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
//! connection that is opened again presents first. The keeper holds the lease the host took last,
//! so a connection made beside the one that keeps it fresh presents that lease again while it lasts
//! and asks the service for a new one only when none is held or the host refuses the one that is,
//! as a host does that restarted or whose clock has passed the lease's end.
//!
//! What it does with a refusal depends on who can mend the cause. A lease that has run out, one the
//! host installed before it restarted, one a newer lease replaced, and one signed by a key the host
//! has not followed are mended by asking again, with the chain of keys beside the lease where that
//! is the cause; but a lease the service has just signed and the host refuses all the same is not
//! asked for again at once, because the host's clock or records are what differ. A service that is
//! down, a host whose clock is in doubt and a service that asks for a delay are waited out. A
//! device whose account is not signed in, is not a member, or whose lease the host refuses for a
//! reason only an administrator can change is not retried: the keeper stops, says why, and a person
//! mends it.
//!
//! The organisation's service allows an account a hundred and twenty lease requests an hour, and
//! the same account's other devices spend from it. So the keeper sends no lease request sooner than
//! a minute after the last wait it began while it keeps a lease, and no connection asks, for a
//! lease or for the chain of keys, while it waits. A request its caller gave up on counts as one
//! the service did not answer, and the keeper sends none for a minute after it. A stop that a
//! person or an administrator mends is remembered: the keeper answers a later connection with the
//! same stop and sends nothing until the stop has been held for the time [`LeaseStop::holds_for`]
//! names. A hold is against the service: it stops every request to it, the chain of keys asked
//! for by a presentation already under way as much as a lease asked for by one that begins later,
//! and it stops a presentation only when no lease is held that the host would take. A token the
//! service rejects is replaced once by the service client before the keeper hears of it, so a
//! second rejection ends in `TokenRefused`.
//!
//! A connection that is kept beside the one that keeps the lease fresh, as the inbox keeps its
//! visits, presents again only when the lease the host holds is due to be replaced
//! ([`LeaseKeeper::present_if_due`]): every presentation is an action the host records and never
//! removes, so one a pass would write a row on each host for as long as the connection is kept.
//!
//! A keeper belongs to the account that was signed in when it was made. The service client checks
//! which account is signed in before the keeper asks for a lease and again before it presents one,
//! and asks only under that account's token, so a lease that arrives after the account changed is
//! not presented, and a refresh that begins after it does not begin.

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
use crate::services::{AccountNow, MembershipLeaseService};
use crate::session::Session;
use crate::shown::{Said, Shown};

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

/// How many times a connection waits and asks again for its first lease before it gives up for now.
const FIRST_LEASE_TRIES: u32 = 3;

/// How many times in a row the host may refuse a lease for a reason the keeper does not know, or
/// the service reject its token, before the keeper stops.
const UNEXPLAINED_REFUSALS: u32 = 3;

/// The longest delay the service may name that a connection waits out: a visit is given as little
/// as ten seconds, dial and reads included, and a longer delay is reported to the person and
/// remembered instead.
const LONGEST_WAIT_AT_CONNECT: Duration = Duration::from_secs(5);

/// How much of a lease must be left, beyond the interval to the first refresh of the connection
/// that keeps it, for the keeper to present it again rather than ask for another.
const LEASE_MARGIN: Duration = Duration::from_secs(30);

/// The most a connection's first presentation takes in all, counting its requests to the service
/// and its waits. The service client gives each request five seconds at the most, and a presentation
/// can make a request that names a delay, wait the delay out (five seconds at the most) and make the
/// request the delay was named for; a token the service rejects adds a renewal and a second request
/// to either. Ten seconds is less than that, so a service that is slow and names a delay ends the
/// presentation as unreachable, not as a delay. A caller may give less (a visit and a listing give
/// ten seconds for the dial, the presentation and the reads together); a presentation it cuts off
/// while a request is under way holds the service off for itself.
const PRESENT_WITHIN: Duration = Duration::from_secs(10);

/// How much earlier than a wait ends, by the wall clock, a request may go: a clock that was set
/// during the wait is not a reason to wait again.
const CLOCK_SLACK_MS: u64 = 1_000;

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
    /// it rejected a renewed token as well, or asked for the sign-in to be made again.
    TokenRefused,
    /// The organisation's service says the signed-in account is not a member of the organisation.
    NotAMember,
    /// The host refuses the lease for a reason only a person or an administrator can change: the
    /// name of the host's rule that this build knows, or what the host did not accept.
    Refused(&'static str),
    /// The service refused the request in a way asking again does not change.
    Unusable,
    /// The service asked this device to wait longer than a connection waits, so the connection
    /// reports the delay and the keeper asks again when it is over.
    Later(Duration),
    /// The connection to the host ended, so the lease it held is the host's to forget. A caller
    /// that opens another connection presents again before it asks the host anything.
    ConnectionEnded,
    /// The first lease could not be got in the few tries a connection is given, because the
    /// organisation's service or the host did not answer well enough, or a request to the service
    /// was given up on before it answered. A caller that tries again later may succeed.
    Unreachable,
    /// Another account is signed in than the one this keeper asks as. The work begun for the first
    /// ends, and a connection that opens again asks as the second.
    AccountChanged,
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
            Self::ConnectionEnded | Self::Unreachable | Self::AccountChanged => {
                ErrorCode::ResourceUnavailable
            }
        }
    }

    /// What the person does about it.
    #[must_use]
    pub const fn user_action(&self) -> UserAction {
        match self {
            Self::SignIn | Self::TokenRefused => UserAction::SignIn,
            Self::NotAMember | Self::Refused(_) => UserAction::Nothing,
            Self::Unusable => UserAction::Update,
            Self::Later(_) | Self::ConnectionEnded | Self::Unreachable | Self::AccountChanged => {
                UserAction::Wait
            }
        }
    }

    /// How long after this stop the keeper sends the service and the host nothing, so that a
    /// device that is stopped for a reason a person must mend does not use the account's allowance
    /// by reconnecting. None for a stop that made no request, or ended with a connection.
    #[must_use]
    pub fn holds_for(&self) -> Duration {
        match self {
            Self::SignIn | Self::ConnectionEnded | Self::AccountChanged => Duration::ZERO,
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

impl Said for LeaseStop {
    fn said(&self) -> Shown {
        match self {
            Self::SignIn => Shown::said(
                "sign in to your account again: this device cannot ask your organisation for the \
                 lease that lets it use this host",
            ),
            Self::TokenRefused => Shown::said(
                "sign in to your account again: your organisation's service does not take the \
                 sign-in this device holds",
            ),
            Self::NotAMember => {
                Shown::said("this account is not a member of the organisation this host answers to")
            }
            Self::Refused(rule) => crate::shown!(
                "this host refused the lease your organisation signed ({}); ask your \
                 organisation's administrator",
                *rule
            ),
            Self::Unusable => Shown::said(
                "your organisation's service refused the request for a lease; update this app",
            ),
            Self::Later(delay) => {
                let seconds = delay.as_secs().max(1);
                match seconds.div_ceil(60) {
                    _ if seconds < 60 => crate::shown!(
                        "your organisation's service asks this device to wait {} seconds before \
                         it asks for the lease this host needs",
                        seconds
                    ),
                    1 => Shown::said(
                        "your organisation's service asks this device to wait a minute before it \
                         asks for the lease this host needs",
                    ),
                    minutes => crate::shown!(
                        "your organisation's service asks this device to wait {} minutes before \
                         it asks for the lease this host needs",
                        minutes
                    ),
                }
            }
            Self::ConnectionEnded => {
                Shown::said("the connection to this host ended before a lease was held")
            }
            Self::Unreachable => Shown::said(
                "your organisation's service did not give this device the lease it needs just \
                 now; this app asks again",
            ),
            Self::AccountChanged => Shown::said(
                "the account signed in on this device changed; this app asks for the lease again \
                 as the new one",
            ),
        }
    }
}

crate::display_as_said!(LeaseStop);

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
    /// Ask the service for a new lease at once: the host will not take the one it was given.
    Now,
    /// Fetch the chain of keys again, and present the lease with it at once.
    WithTheChain,
    /// Wait for the delay the service named.
    After(Duration),
    /// A stop is held against the service for the time that is left of it: no request goes until it
    /// is over.
    Held(LeaseStop, Duration),
    /// Wait out the backoff.
    BackOff,
    /// Wait out the backoff, and ask the service for a new lease that carries the chain of keys.
    BackOffWithTheChain,
    /// Wait out the backoff, and stop with this when it has happened [`UNEXPLAINED_REFUSALS`] times
    /// since a lease was last held: nothing says what is wrong.
    Doubtful(LeaseStop),
    /// As [`Self::Doubtful`], for a lease the host refused as ended or replaced the moment the
    /// service had signed it: that lease is dropped, and the next is asked for after the wait.
    Mistrusted(LeaseStop),
    /// Stop, because only a person can mend this.
    Stop(LeaseStop),
}

/// What a presentation consisted of, which decides what a refusal of it means.
#[derive(Clone, Copy)]
struct Presented {
    /// The service signed the lease for this presentation, so a host that refuses it as ended or
    /// replaced has not been given a stale one, and asking again would be refused the same way.
    fresh: bool,
    /// The chain of keys was fetched again for this presentation.
    with_chain: bool,
}

/// Whether a lease may be presented again as it is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    /// Any lease that still lasts: the one the host took, or one it has not taken yet.
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
    /// When the lease ends, in UTC milliseconds by this device's clock: its length counted from
    /// when it arrived, so a device whose clock differs from the service's is not misled.
    ends_at_ms: u64,
    /// When the lease is due to be replaced, in UTC milliseconds, once the host has taken it.
    due_at_ms: Option<u64>,
}

impl Held {
    /// Whether this lease is worth presenting again at `now_ms`: it lasts until the first refresh of
    /// the connection that keeps it, which is the wait [`LeaseKeeper::keep`] begins with, and the
    /// margin beyond.
    fn usable(&self, now_ms: u64, reuse: Reuse) -> bool {
        let to_the_first_refresh = match self.due_at_ms {
            Some(due) => clamp(Duration::from_millis(due.saturating_sub(now_ms))),
            None => clamp(self.advised),
        };
        let needs = millis(to_the_first_refresh + LEASE_MARGIN);
        self.ends_at_ms > now_ms.saturating_add(needs)
            && (reuse == Reuse::Held || self.due_at_ms.is_none())
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
    /// Whether the host has taken a lease from this keeper that nothing has spoiled since.
    took_a_lease: bool,
    /// A stop that sends nothing until the moment it names, in UTC milliseconds.
    held_back: Option<(u64, LeaseStop)>,
    /// No request goes to the service before this moment, in UTC milliseconds: the keeper is
    /// waiting out a failure or a delay the service named, and every connection waits with it.
    not_before_ms: u64,
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

/// A duration as milliseconds.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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

    /// Whether the host has taken a lease from this keeper that no stop has spoiled since. A
    /// connection that presents no lease of its own serves the person only while it is.
    #[must_use]
    pub fn took_a_lease(&self) -> bool {
        self.kept().took_a_lease
    }

    /// Why this keeper holds no lease the host took: the stop that is held against the service,
    /// and otherwise that the service has not given one yet.
    #[must_use]
    pub fn why_no_lease(&self) -> LeaseStop {
        self.held_back()
            .map_or(LeaseStop::Unreachable, |(stop, _)| stop)
    }

    /// Presents a lease as the first thing on the connection.
    ///
    /// The lease the host took last is presented again while it lasts, whatever is held against the
    /// service; the service is asked only when none is held, or the host refuses the one that is. A
    /// failure that asking again mends is mended here, and one that time mends is waited out.
    ///
    /// # Errors
    ///
    /// Returns why the host does not hold a lease and will not without a person or a new
    /// connection. A stop that a person or an administrator mends is returned again, with nothing
    /// sent, until the time it is held for has passed.
    pub async fn present_first(&self, session: &Session) -> Result<(), LeaseStop> {
        // The caller's own limit is shorter than a few slow requests add up to, and a hold is
        // recorded only by a stop, so the keeper stops itself first.
        match tokio::time::timeout(
            PRESENT_WITHIN,
            self.until_held(session, &mut Pace::first(), Reuse::Held),
        )
        .await
        {
            Ok(held) => held.map(|_| ()),
            Err(_) => Err(self.stopped(LeaseStop::Unreachable)),
        }
    }

    /// Presents again, over a connection that presented first and is kept, when the lease the host
    /// holds is due to be replaced; sends nothing while it is not.
    ///
    /// A presentation is an action the host records and keeps, so a connection that presented
    /// again at each use would write a row on the host for each. A new lease is asked for once, with
    /// no waits; when it cannot be got while the lease the host holds still lasts, that is no
    /// failure of the connection, and the service is not asked again until what was held against it
    /// is over.
    ///
    /// # Errors
    ///
    /// Returns why the host holds no lease that lasts and will not without a person or a new
    /// connection.
    pub async fn present_if_due(&self, session: &Session) -> Result<(), LeaseStop> {
        if !self.due() {
            return Ok(());
        }
        let stop = match tokio::time::timeout(
            PRESENT_WITHIN,
            self.until_held(session, &mut Pace::once(), Reuse::Unaccepted),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(stop)) => stop,
            Err(_) => self.stopped(LeaseStop::Unreachable),
        };
        let lasts = self
            .left_on_the_lease()
            .is_some_and(|left| left > LEASE_MARGIN);
        if lasts && matches!(stop, LeaseStop::Unreachable | LeaseStop::Later(_)) {
            return Ok(());
        }
        Err(stop)
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

    /// Whether the lease the host holds is due to be replaced: none is held, or the moment to replace
    /// it has come.
    fn due(&self) -> bool {
        let now = self.timer.now_ms();
        self.kept()
            .lease
            .as_ref()
            .is_none_or(|held| held.due_at_ms.is_none_or(|due| due <= now))
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

    /// How long the lease the host holds has left, when it holds one this keeper presented.
    fn left_on_the_lease(&self) -> Option<Duration> {
        let now = self.timer.now_ms();
        self.kept()
            .lease
            .as_ref()
            .filter(|held| held.due_at_ms.is_some())
            .map(|held| Duration::from_millis(held.ends_at_ms.saturating_sub(now)))
    }

    /// The stop that is held, while it is, and the time it still has to run. A held `Later` names
    /// that time as its delay.
    fn held_back(&self) -> Option<(LeaseStop, Duration)> {
        let now = self.timer.now_ms();
        let mut kept = self.kept();
        match &kept.held_back {
            Some((until, stop)) if *until > now => {
                let left = Duration::from_millis(*until - now);
                Some((
                    match stop {
                        LeaseStop::Later(_) => LeaseStop::Later(left),
                        other => other.clone(),
                    },
                    left,
                ))
            }
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
            if matches!(
                next,
                Next::Now | Next::BackOffWithTheChain | Next::Mistrusted(_)
            ) {
                // The host will not take this lease again, with a chain or without.
                self.kept().lease = None;
            }
            let wait = match next {
                Next::Now => None,
                Next::WithTheChain => {
                    pace.chain = true;
                    None
                }
                // What is held against the service ends a presentation that has to ask it, with the
                // stop; a refresh that asks only for a lease the stop did not spoil waits it out.
                Next::Held(stop, _) if pace.connecting || stop.spoils_the_lease() => {
                    return Err(stop);
                }
                Next::After(delay) | Next::Held(_, delay) => {
                    if pace.connecting && delay > LONGEST_WAIT_AT_CONNECT {
                        return Err(self.stopped(LeaseStop::Later(delay)));
                    }
                    let wait = delay.max(pace.floor);
                    self.ask_nothing_for(wait);
                    if !pace.connecting
                        && let Some(left) = self.left_on_the_lease().filter(|left| wait >= *left)
                    {
                        // The host stops answering when the lease it holds ends, which is before
                        // the service lets this device ask: say so when it does.
                        self.timer.wait(left).await;
                        return Err(self.stopped(LeaseStop::Later(delay)));
                    }
                    Some(wait)
                }
                Next::BackOff => Some(pace.backoff.next_delay()),
                Next::BackOffWithTheChain => {
                    pace.chain = true;
                    Some(pace.backoff.next_delay())
                }
                Next::Doubtful(stop) | Next::Mistrusted(stop) => {
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
                self.ask_nothing_for(wait);
                self.timer.wait(wait).await;
            }
        }
    }

    /// No connection asks the service for a lease for `wait`: the keeper waits it out, and so does
    /// every connection beside it.
    fn ask_nothing_for(&self, wait: Duration) {
        let until = self.timer.now_ms().saturating_add(millis(wait));
        let mut kept = self.kept();
        kept.not_before_ms = kept.not_before_ms.max(until);
    }

    /// Records a stop: what it spoils is dropped, and what it holds back is held back.
    fn stopped(&self, stop: LeaseStop) -> LeaseStop {
        {
            let mut kept = self.kept();
            if stop.spoils_the_lease() {
                kept.lease = None;
                kept.took_a_lease = false;
            }
            let held = stop.holds_for();
            if !held.is_zero() {
                let until = self.timer.now_ms().saturating_add(millis(held));
                kept.held_back = Some((until, stop.clone()));
            }
        }
        (self.report)(LeaseEvent::Stopped(stop.clone()));
        stop
    }

    /// Whether the account signed in is still the one this keeper asks as.
    fn account_is_the_same(&self) -> Result<(), Next> {
        match self.leases.account_now() {
            Ok(AccountNow::Same) | Err(_) => Ok(()),
            Ok(AccountNow::Replaced) => Err(Next::Stop(LeaseStop::AccountChanged)),
            Ok(AccountNow::SignedOut) => Err(Next::Stop(LeaseStop::SignIn)),
        }
    }

    /// No request goes to the service while a stop is held against it, or a delay it named, or a
    /// failure the keeper is waiting out, has time to run. Asked before a lease and before the chain
    /// of keys alike, by every connection and by the refresh, however far its presentation has got.
    fn must_wait(&self) -> Result<(), Next> {
        if let Some((stop, left)) = self.held_back() {
            return Err(Next::Held(stop, left));
        }
        let now = self.timer.now_ms();
        let not_before = self.kept().not_before_ms;
        if not_before > now.saturating_add(CLOCK_SLACK_MS) {
            return Err(Next::After(Duration::from_millis(not_before - now)));
        }
        Ok(())
    }

    /// What a refusal from the service calls for. A request that found no token to make may do so
    /// because another account signed in, which is another stop than that the person signs in.
    fn service_refused(&self, error: &ClientError) -> Next {
        let next = from_the_service(error);
        if next == Next::Stop(LeaseStop::SignIn)
            && matches!(self.leases.account_now(), Ok(AccountNow::Replaced))
        {
            return Next::Stop(LeaseStop::AccountChanged);
        }
        next
    }

    /// A request to the service is given up on before it answers: the service did not answer, as
    /// far as the next caller can tell, and is not asked again at once. Only the service is held
    /// off: a connection presents a lease that is held whatever happened to the request.
    fn unanswered(&self) {
        let until = self
            .timer
            .now_ms()
            .saturating_add(millis(LeaseStop::Unreachable.holds_for()));
        let mut kept = self.kept();
        if kept
            .held_back
            .as_ref()
            .is_none_or(|(held, _)| *held < until)
        {
            kept.held_back = Some((until, LeaseStop::Unreachable));
        }
    }

    /// One lease presented, got from the service first when none is held to present. Returns the
    /// interval the service advised.
    async fn step(
        &self,
        session: &Session,
        force_chain: bool,
        reuse: Reuse,
    ) -> Result<Duration, Next> {
        self.account_is_the_same()?;
        let reusable = {
            let now = self.timer.now_ms();
            self.kept()
                .lease
                .as_ref()
                .filter(|held| held.usable(now, reuse))
                .cloned()
        };
        let fresh = reusable.is_none();
        let mut held = if let Some(held) = reusable {
            held
        } else {
            self.must_wait()?;
            let asking = Asking::of(self);
            let issued = self.leases.lease(self.organisation, self.device_key).await;
            asking.answered();
            let issued = issued.map_err(|error| self.service_refused(&error))?;
            let payload = &issued.lease.payload;
            let lasts = payload
                .expires_at_ms
                .get()
                .saturating_sub(payload.issued_at_ms.get());
            let held = Held {
                ends_at_ms: self.timer.now_ms().saturating_add(lasts),
                lease: issued.lease,
                authority: None,
                advised: issued.refresh_after,
                due_at_ms: None,
            };
            self.kept().lease = Some(held.clone());
            held
        };
        let revision = held.lease.payload.key_revision.get();
        let newer = revision > self.kept().followed;
        // A chain the host refused for being behind is fetched again, not presented as it was.
        if force_chain || (held.authority.is_none() && newer) {
            self.must_wait()?;
            let asking = Asking::of(self);
            let chain = self.leases.authority(self.organisation).await;
            asking.answered();
            held.authority = Some(chain.map_err(|error| self.service_refused(&error))?);
        }
        // Whatever was waited for, the lease is presented only for the account that asked for it.
        self.account_is_the_same()?;
        let presented = Presented {
            fresh,
            with_chain: force_chain,
        };
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
            .map_err(|error| from_the_host(&error, presented))?;
        let now = self.timer.now_ms();
        let due = held
            .due_at_ms
            .unwrap_or_else(|| now.saturating_add(millis(clamp(held.advised))));
        held.due_at_ms = Some(due);
        {
            let mut kept = self.kept();
            kept.followed = kept.followed.max(taken.key_revision.get()).max(revision);
            kept.lease = Some(held.clone());
            kept.took_a_lease = true;
        }
        (self.report)(LeaseEvent::Held {
            expires_at_ms: taken.expires_at_ms.get(),
        });
        Ok(held.advised)
    }
}

/// A request to the service that is under way. If it is dropped before [`Self::answered`], its
/// caller gave up on it.
struct Asking<'a> {
    keeper: &'a LeaseKeeper,
    answered: bool,
}

impl<'a> Asking<'a> {
    fn of(keeper: &'a LeaseKeeper) -> Self {
        Self {
            keeper,
            answered: false,
        }
    }

    /// The request ended, with an answer or with a failure.
    fn answered(mut self) {
        self.answered = true;
    }
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        if !self.answered {
            self.keeper.unanswered();
        }
    }
}

/// How the keeper paces itself while a lease is being got.
struct Pace {
    backoff: Backoff,
    /// The shortest a wait is.
    floor: Duration,
    /// Whether a connection waits for this lease, and so gives up after a few tries and does not
    /// wait out a long delay.
    connecting: bool,
    /// The waits allowed before giving up for now, when there is a limit.
    waits_left: Option<u32>,
    /// Failures since a lease was last held that nothing explains.
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
            doubts: 0,
            chain: false,
        }
    }

    /// The pace of a renewal that is tried once: it waits for nothing, and a failure ends it.
    fn once() -> Self {
        Self {
            waits_left: Some(0),
            ..Self::first()
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
            doubts: 0,
            chain: false,
        }
    }

    /// A lease is held: the next failure starts again.
    fn held(&mut self) {
        self.backoff.reset();
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
        // The service client has already asked once more with a renewed token when the first was
        // rejected, so a token it still rejects is the person's to replace.
        (Some("REAUTHENTICATION_REQUIRED" | "UNAUTHENTICATED"), _) => {
            Next::Stop(LeaseStop::TokenRefused)
        }
        (Some("FORBIDDEN"), _) => Next::Stop(LeaseStop::NotAMember),
        (Some("INVALID_REQUEST" | "METHOD_NOT_ALLOWED" | "NOT_FOUND"), _) => {
            Next::Stop(LeaseStop::Unusable)
        }
        // The device's own account named no service: it holds no token to ask with.
        (None, _) if *action == UserAction::SignIn => Next::Stop(LeaseStop::SignIn),
        _ => Next::BackOff,
    }
}

/// What the host says of a lease it was not given a rule for.
const NOT_EXPLAINED: &str = "not explained";

/// What the host says of a lease or chain it refuses as malformed.
const NOT_ACCEPTED: &str = "the host did not accept the lease or the chain of keys beside it";

/// What a stop says of a rule of the host's that this build does not know.
const UNKNOWN_RULE: &str = "a rule this app does not know";

/// What a refusal from the host calls for.
fn from_the_host(error: &ClientError, presented: Presented) -> Next {
    match error {
        ClientError::Transport(_)
        | ClientError::Ipc(_)
        | ClientError::ConnectionEnded
        | ClientError::SubmissionUncertain { .. } => Next::Stop(LeaseStop::ConnectionEnded),
        ClientError::Host(refusal) if refusal.code == ErrorCode::PermissionDenied => {
            match rule_of(&refusal.message) {
                Some(rule) => by_rule(rule, presented),
                // A window the host no longer accepts, or a device it no longer answers to: the
                // connection says which when it ends.
                None => Next::Doubtful(LeaseStop::Refused(NOT_EXPLAINED)),
            }
        }
        // A chain that does not verify, or one that is not current yet: time may mend the second,
        // and nothing says which this is.
        ClientError::Host(refusal) if refusal.code == ErrorCode::InvalidArgument => {
            Next::Doubtful(LeaseStop::Refused(NOT_ACCEPTED))
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

/// Whether a host's refusal says it holds no lease for this device that it will answer under: none,
/// one that ended, or one its pinned authority did not sign. A device that is refused for any other
/// reason is not helped by presenting a lease again, and a presentation is an action the host keeps.
#[must_use]
pub fn lease_is_refused(code: ErrorCode, message: &str) -> bool {
    code == ErrorCode::PermissionDenied && message.contains("membership lease")
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
    /// Asking the service for a new lease: the one presented is gone or replaced.
    Ask,
    /// The chain of keys beside the lease.
    Chain,
    /// Time, and a new lease that carries the chain of keys.
    ChainLater,
    /// Time, and presenting the same lease again.
    Later,
    /// A person or an administrator.
    Person,
}

fn by_rule(rule: &str, presented: Presented) -> Next {
    let Some(&(name, cure)) = RULES.iter().find(|(name, _)| *name == rule) else {
        return Next::Stop(LeaseStop::Refused(UNKNOWN_RULE));
    };
    match cure {
        // A lease the service has just signed is not one the host has seen before: if it refuses
        // that as ended or replaced, asking for another is refused the same way, as it is when
        // this host's clock is far from the service's.
        Cure::Ask if presented.fresh => Next::Mistrusted(LeaseStop::Refused(name)),
        Cure::Ask => Next::Now,
        Cure::Chain if presented.with_chain => Next::Doubtful(LeaseStop::Refused(name)),
        Cure::Chain => Next::WithTheChain,
        Cure::ChainLater => Next::BackOffWithTheChain,
        Cure::Later => Next::BackOff,
        Cure::Person => Next::Stop(LeaseStop::Refused(name)),
    }
}

/// Every rule of a lease the host can refuse that this build knows, so that a suite holds the host's
/// list to this one.
#[must_use]
pub fn known_rules() -> Vec<&'static str> {
    RULES.iter().map(|(name, _)| *name).collect()
}
