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
//! connection that is opened again presents first.
//!
//! What it does with a refusal depends on who can mend the cause. A lease that has run out, one the
//! host installed before it restarted, and one signed by a key the host has not followed are mended
//! by asking again, with the chain of keys beside the lease where that is the cause. A service that
//! is down, a host whose clock is in doubt and a service that asks for a delay are waited out. A
//! device whose account is not signed in, is not a member, or whose lease the host refuses for a
//! reason only an administrator can change is not retried: the keeper stops, says why, and a person
//! mends it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

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

/// The shortest the keeper waits between two leases, whatever the service advises, so that a
/// service that advises nothing does not become a loop. The organisation's service limits an
/// account to a hundred and twenty lease requests an hour.
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

/// How many times in a row the host may refuse a lease for a reason the keeper does not know, or
/// the service reject its token, before the keeper stops.
const UNEXPLAINED_REFUSALS: u32 = 3;

/// Waits, so that a suite decides when time passes.
pub trait LeaseTimer: Send + Sync + fmt::Debug {
    /// Returns when `duration` has passed.
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The wait of a device that is running: time passes.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealTimer;

impl LeaseTimer for RealTimer {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Why the keeper stopped. Each is something a person or an administrator mends, or a connection
/// that must be opened again; none is retried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseStop {
    /// No account is signed in with the right to ask for a lease, or the service no longer takes
    /// its token.
    SignIn,
    /// The organisation's service says the signed-in account is not a member of the organisation.
    NotAMember,
    /// The host refuses the lease for a reason only a person or an administrator can change: the
    /// name of the host's rule.
    Refused(String),
    /// The service refused the request in a way asking again does not change.
    Unusable,
    /// The connection to the host ended, so the lease it held is the host's to forget. A caller
    /// that opens another connection presents again before it asks the host anything.
    ConnectionEnded,
}

impl fmt::Display for LeaseStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignIn => formatter.write_str(
                "sign in to your account again: this device cannot ask your organisation for the \
                 lease that lets it use this host",
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
            Self::ConnectionEnded => {
                formatter.write_str("the connection to this host ended before a lease was held")
            }
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
    /// Keep the schedule: a newer lease is already held.
    OnSchedule,
    /// Wait for the delay the service named.
    After(Duration),
    /// Wait out the backoff.
    BackOff,
    /// Wait out the backoff, and carry the chain of keys with the next lease.
    BackOffWithTheChain,
    /// Wait out the backoff, and stop with this when the same thing has happened
    /// [`UNEXPLAINED_REFUSALS`] times in a row: nothing says what is wrong.
    Doubtful(LeaseStop),
    /// Stop, because only a person can mend this.
    Stop(LeaseStop),
}

/// Keeps one organisation's lease for one device on one host.
pub struct LeaseKeeper {
    leases: Arc<dyn MembershipLeaseService>,
    session: Arc<Session>,
    timer: Arc<dyn LeaseTimer>,
    organisation: OrganisationId,
    environment: EnvironmentId,
    device_key: AuthorisationKey,
    /// The highest key revision a lease the host accepted was signed with. A lease signed by a
    /// higher one travels with the chain that brings the revision in.
    followed: Mutex<u64>,
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
    /// A keeper that gets the lease for `device_key` from `leases` and presents it on `session`,
    /// to the host whose environment is `environment`.
    #[must_use]
    pub fn new(
        leases: Arc<dyn MembershipLeaseService>,
        session: Arc<Session>,
        timer: Arc<dyn LeaseTimer>,
        organisation: OrganisationId,
        environment: EnvironmentId,
        device_key: AuthorisationKey,
    ) -> Self {
        Self {
            leases,
            session,
            timer,
            organisation,
            environment,
            device_key,
            followed: Mutex::new(0),
            report: Box::new(|_| {}),
        }
    }

    /// This keeper, telling `report` what it does.
    #[must_use]
    pub fn reporting(mut self, report: impl Fn(LeaseEvent) + Send + Sync + 'static) -> Self {
        self.report = Box::new(report);
        self
    }

    /// Gets a lease and presents it, as the first thing on the connection, and returns the
    /// interval the service advised before the next.
    ///
    /// A failure that asking again mends is mended here, and one that time mends is waited out.
    ///
    /// # Errors
    ///
    /// Returns why the host does not hold a lease and will not without a person or a new
    /// connection.
    pub async fn present_first(&self) -> Result<Duration, LeaseStop> {
        self.until_held(&mut Pace::new()).await
    }

    /// Keeps the lease until something stops it. It begins with a wait of `advised`, the interval
    /// [`Self::present_first`] returned, so a lease just presented is not presented again.
    pub async fn keep(&self, advised: Duration) -> LeaseStop {
        let mut pace = Pace::new();
        let mut wait = advised;
        loop {
            self.timer.wait(wait).await;
            match self.until_held(&mut pace).await {
                Ok(advised) => wait = advised,
                Err(stop) => return stop,
            }
        }
    }

    /// Asks and presents until the host holds a lease, and returns the interval to wait before the
    /// next.
    async fn until_held(&self, pace: &mut Pace) -> Result<Duration, LeaseStop> {
        loop {
            let next = match self.step(pace.chain).await {
                Ok(advised) => {
                    pace.held();
                    return Ok(clamp(advised));
                }
                Err(next) => next,
            };
            let wait = match next {
                Next::Now => pace.at_once(),
                Next::WithTheChain => {
                    pace.chain = true;
                    pace.at_once()
                }
                Next::OnSchedule => {
                    pace.held();
                    return Ok(LONGEST_REFRESH);
                }
                Next::After(delay) => Some(delay),
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
                (self.report)(LeaseEvent::Retrying);
                self.timer.wait(wait).await;
            }
        }
    }

    fn stopped(&self, stop: LeaseStop) -> LeaseStop {
        (self.report)(LeaseEvent::Stopped(stop.clone()));
        stop
    }

    /// One lease asked for and presented. Returns the interval the service advised.
    async fn step(&self, force_chain: bool) -> Result<Duration, Next> {
        let issued = self
            .leases
            .lease(self.organisation, self.device_key)
            .await
            .map_err(|error| from_the_service(&error))?;
        let revision = issued.lease.payload.key_revision.get();
        let newer = revision > *self.followed.lock().unwrap_or_else(PoisonError::into_inner);
        let authority = if newer || force_chain {
            Some(
                self.leases
                    .authority(self.organisation)
                    .await
                    .map_err(|error| from_the_service(&error))?,
            )
        } else {
            None
        };
        let params = MembershipPresentParams {
            lease: issued.lease,
            authority: authority.map_or_else(Nullable::null, Nullable::some),
        };
        let held: MembershipPresentResult = self
            .session
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
        *self.followed.lock().unwrap_or_else(PoisonError::into_inner) =
            held.key_revision.get().max(revision);
        (self.report)(LeaseEvent::Held {
            expires_at_ms: held.expires_at_ms.get(),
        });
        Ok(issued.refresh_after)
    }
}

/// How the keeper paces itself while a lease is being got.
struct Pace {
    backoff: Backoff,
    /// Asks made at once in a row.
    immediate: u32,
    /// Failures in a row that nothing explains.
    doubts: u32,
    /// Whether the next lease travels with the chain of keys.
    chain: bool,
}

impl Pace {
    fn new() -> Self {
        Self {
            backoff: backoff(),
            immediate: 0,
            doubts: 0,
            chain: false,
        }
    }

    /// A lease is held: the next failure starts again.
    fn held(&mut self) {
        *self = Self::new();
    }

    /// How long to wait before asking again for a lease the host said to ask again for: none for
    /// the first few, and the backoff after, so a host that keeps saying it is not asked
    /// for ever.
    fn at_once(&mut self) -> Option<Duration> {
        self.immediate += 1;
        (self.immediate > IMMEDIATE_RETRIES).then(|| self.backoff.next_delay())
    }
}

fn backoff() -> Backoff {
    Backoff::new(Duration::from_secs(1), Duration::from_secs(60))
}

/// The interval the service advised, held to the keeper's bounds.
fn clamp(advised: Duration) -> Duration {
    advised.clamp(SHORTEST_REFRESH, LONGEST_REFRESH)
}

/// What a refusal from the organisation's service calls for.
fn from_the_service(error: &ClientError) -> Next {
    if error.user_action() == UserAction::SignIn {
        return Next::Stop(LeaseStop::SignIn);
    }
    let ClientError::Refused {
        service_code,
        retry_after_seconds,
        ..
    } = error
    else {
        return Next::BackOff;
    };
    match (*service_code, retry_after_seconds) {
        (Some("RATE_LIMITED" | "SERVICE_UNAVAILABLE"), Some(seconds)) => {
            Next::After(Duration::from_secs(*seconds))
        }
        (Some("REAUTHENTICATION_REQUIRED"), _) => Next::Stop(LeaseStop::SignIn),
        // A token the service rejects may have ended in transit, so the keeper asks again with
        // whatever the account holds now. The account being signed out is for the person.
        (Some("UNAUTHENTICATED"), _) => Next::Doubtful(LeaseStop::SignIn),
        (Some("FORBIDDEN"), _) => Next::Stop(LeaseStop::NotAMember),
        (Some("INVALID_REQUEST" | "METHOD_NOT_ALLOWED" | "NOT_FOUND"), _) => {
            Next::Stop(LeaseStop::Unusable)
        }
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
    ("superseded", Cure::Keep),
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
    /// Asking the service for a new lease.
    Ask,
    /// Nothing: a newer lease is already held.
    Keep,
    /// The chain of keys beside a new lease.
    Chain,
    /// Time, and the chain beside the lease.
    ChainLater,
    /// Time.
    Later,
    /// A person or an administrator.
    Person,
}

fn by_rule(rule: &str) -> Next {
    match RULES.iter().find(|(name, _)| *name == rule) {
        Some((_, Cure::Ask)) => Next::Now,
        Some((_, Cure::Keep)) => Next::OnSchedule,
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
