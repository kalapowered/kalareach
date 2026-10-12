//! The sessions a phone opens on a host it is paired with.
//!
//! A phone has no worker of its own to reach. A session of the host it is paired with is reached
//! over a connection to that host, opened for the one session under the one grant the screen runs
//! under: the device's pairing, or a share it holds. The host decides what that connection may do
//! and says when its grant has ended, and this module keeps the connections and tells the page.
//!
//! * The **main connection** ([`crate::connection`]) is opened for the host alone. It serves the
//!   host's own reads and no session's worker, and a share's end never reaches it.
//! * An **opened link** belongs to one session screen. The page chooses a single-use *opening*
//!   token when the screen mounts, opens the session with it, passes it with every command, and
//!   leaves with it. A command that names another token executes nowhere, so a command prepared
//!   under one share cannot run under the next. One link is held for each session, and a new
//!   opening replaces the one before it.
//! * An **ambient link** serves a command that comes from outside a session screen: the inbox, a
//!   kept answer, a draft's rebind. It is opened under the pairing and never under a share, shared
//!   by the calls for one session, and let go when idle.
//!
//! An opened link is watched. When the connection is lost without the grant having ended, the
//! watch reaches the host again as the same opening and tells the page. When the host says the
//! share has ended, the watch stops, and the link is not replaced by a connection under another
//! grant. Nothing here chooses a share: only the page, from a row the person opened, names one.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kr_client::pairing::link::LinkError;
use kr_client::pairing::paired::PairedHost;
use kr_client::{ClientError, Said as _, Session};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{EnvironmentId, GrantId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    OpenedVia, SessionOpenParams, SessionOpenResult, SessionState, ShareEnd,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter as _};
use tokio::sync::Notify;

use crate::agent::Link;
use crate::device::Device;
use crate::error::{CommandError, Result};

/// The event the backend publishes a change of an opened session's standing on.
pub const STANDING_EVENT: &str = "kr://standing";

/// The most opened links held at once, one for each session.
pub const OPENED_LIMIT: usize = 8;

/// The most ambient links held at once.
pub const AMBIENT_LIMIT: usize = 4;

/// How long an ambient link may sit idle before it is let go.
const AMBIENT_IDLE: Duration = Duration::from_secs(60);

/// The longest an opening token is.
const TOKEN_LIMIT: usize = 64;

/// How many tokens are remembered for each session, the oldest forgotten first. A token is a
/// correlation key and the page never reuses one, so a forgotten token grants nothing.
const SEEN_LIMIT: usize = 256;

/// How long reaching a host and having it open a session may take.
const OPEN_WITHIN: Duration = Duration::from_secs(20);

/// The pause before the first attempt to reach a host again.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// The longest pause between attempts to reach a host again.
const LONGEST_RETRY: Duration = Duration::from_secs(30);

/// The pause after `failures` attempts in a row that did not reach the host.
fn pause(failures: u32) -> Duration {
    FIRST_RETRY
        .saturating_mul(2_u32.saturating_pow(failures.min(16)))
        .min(LONGEST_RETRY)
}

/// What the page is told of an opened session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionStanding {
    /// The host opened the session under a grant, and these are the rights it decided the open
    /// with.
    Open {
        /// Whether the grant is the pairing or a share.
        via: &'static str,
        /// The grant the session runs under.
        grant_id: String,
        /// What the host lets this screen do, in the protocol's names.
        actions: Vec<ActionRight>,
        /// Whether the grant includes the session's live screen.
        includes_live_screen: bool,
        /// How far back the grant's history reaches, in UTC milliseconds, when it reaches back.
        history_from_ms: Option<u64>,
        /// When the grant is scheduled to end, in UTC milliseconds, when it ends.
        ends_at_ms: Option<u64>,
    },
    /// The share this screen runs under has ended.
    Ended {
        /// Why: `revoked` or `expired`.
        reason: &'static str,
    },
    /// The session has closed. What was read stays readable; nothing more can be sent.
    Closed,
    /// The host refused to open the session or to keep it open, in its own words.
    Refused {
        /// The host's code.
        code: ErrorCode,
        /// The host's sentence.
        message: String,
    },
    /// Contact with the session was lost without its grant having ended, and is being taken up
    /// again.
    Reconnecting {
        /// Why, in words a person reads.
        reason: String,
    },
    /// Another opening of the same session took this one's place, or this one was left before it
    /// finished opening.
    Superseded,
}

/// One change of an opened session's standing, as the page receives it.
#[derive(Clone, Debug, Serialize)]
pub struct StandingEvent {
    /// The session.
    pub session_id: String,
    /// The opening it belongs to. The page applies it only when this is the opening it holds.
    pub opening: String,
    /// The new standing.
    pub standing: SessionStanding,
}

/// Tells the page about a change of standing.
type Emitter = Arc<dyn Fn(StandingEvent) + Send + Sync>;

/// A count of the mutations in flight on a link, so a leave can wait for them to answer before it
/// closes the link under them.
#[derive(Debug, Default)]
pub(crate) struct Flight {
    count: AtomicUsize,
    idle: Notify,
}

/// A mutation in flight. It ends when it is dropped.
pub(crate) struct InFlight(Arc<Link>);

impl Flight {
    /// Counts one mutation as in flight on `link` until the guard is dropped.
    pub(crate) fn enter(link: &Arc<Link>) -> InFlight {
        link.flight.count.fetch_add(1, Ordering::SeqCst);
        InFlight(Arc::clone(link))
    }

    /// Resolves once nothing is in flight.
    async fn idle(&self) {
        loop {
            let waiting = self.idle.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            if self.count.load(Ordering::SeqCst) == 0 {
                return;
            }
            waiting.await;
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0.flight.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.flight.idle.notify_waiters();
        }
    }
}

/// How reaching a host, or having it open a session, did not give a link.
#[derive(Debug)]
enum Failure {
    /// The host answered with a refusal.
    Refused(ProtocolError),
    /// The host could not be reached, or the connection to it ended.
    Unreached(String),
}

impl Failure {
    fn command(self) -> CommandError {
        match self {
            Self::Refused(refusal) => CommandError::from(refusal),
            Self::Unreached(reason) => CommandError::unavailable(reason),
        }
    }
}

/// What a host did with a request to open a session.
enum Opening {
    /// The session is open under the grant it names.
    Open(Arc<Link>, SessionStanding),
    /// The share has ended.
    Ended(ShareEnd),
}

/// The host a phone opens sessions on, and what it opens them as.
#[derive(Clone)]
pub struct Dial {
    device: Arc<Device>,
    host: PairedHost,
}

impl Dial {
    /// A dial to `host` as `device`.
    #[must_use]
    pub fn new(device: Arc<Device>, host: PairedHost) -> Self {
        Self { device, host }
    }

    /// Reaches the host on a connection of its own and has it open `session_id` under `grant_id`.
    async fn open(
        &self,
        session_id: SessionId,
        grant_id: Option<GrantId>,
    ) -> std::result::Result<Opening, Failure> {
        let pairing = self.device.pairing();
        let identity = pairing.candidate.paired_identity(self.host.device_id);
        let transport = tokio::time::timeout(
            OPEN_WITHIN,
            pairing.link.connect_paired_transport(&self.host, &identity),
        )
        .await
        .map_err(|_| Failure::Unreached("the host did not answer in time".to_owned()))?
        .map_err(|error| match error {
            LinkError::Refused(refusal) => Failure::Refused(refusal),
            other => Failure::Unreached(other.said().into_string()),
        })?;
        let session = Session::start(transport)
            .map_err(|error| Failure::Unreached(error.said().into_string()))?;
        let opened = tokio::time::timeout(
            OPEN_WITHIN,
            session.read::<_, SessionOpenResult>(
                Method::SessionOpen,
                &SessionOpenParams {
                    session_id: Nullable::some(session_id),
                    grant_id: Nullable(grant_id),
                },
            ),
        )
        .await;
        let opened = match opened {
            Ok(Ok(opened)) => opened,
            Ok(Err(ClientError::Host(refusal))) => {
                session.close();
                return Err(Failure::Refused(refusal));
            }
            Ok(Err(other)) => {
                session.close();
                return Err(Failure::Unreached(other.said().into_string()));
            }
            Err(_) => {
                session.close();
                return Err(Failure::Unreached(
                    "the host did not open the session in time".to_owned(),
                ));
            }
        };
        match opened {
            SessionOpenResult::Ended { reason } => {
                session.close();
                Ok(Opening::Ended(reason))
            }
            SessionOpenResult::InForce {
                session: summary,
                environment_id,
                grant_id,
                via,
                actions,
                includes_live_screen,
                history_from_ms,
                ends_at_ms,
            } => {
                let Some(summary) = summary.0 else {
                    session.close();
                    return Err(Failure::Unreached(
                        "the host opened a connection for no session".to_owned(),
                    ));
                };
                let standing = if summary.state == SessionState::Closed {
                    SessionStanding::Closed
                } else {
                    SessionStanding::Open {
                        via: match via {
                            OpenedVia::Pairing => "pairing",
                            OpenedVia::Share => "share",
                        },
                        grant_id: grant_id.to_string(),
                        actions: actions.iter().copied().collect(),
                        includes_live_screen,
                        history_from_ms: history_from_ms.0.map(|at| at.get()),
                        ends_at_ms: ends_at_ms.0.map(|at| at.get()),
                    }
                };
                let link = Arc::new(Link::paired(
                    session,
                    environment_id,
                    summary.session_id,
                    summary.session_epoch,
                    (via == OpenedVia::Share).then_some(grant_id),
                ));
                Ok(Opening::Open(link, standing))
            }
        }
    }
}

/// Whether a link's connection is still up.
async fn live(link: &Link) -> bool {
    tokio::time::timeout(Duration::ZERO, link.session.closed())
        .await
        .is_err()
}

/// A link for one call, and the claim that keeps an ambient link from being let go under it.
pub(crate) struct Leased {
    link: Arc<Link>,
    _busy: Option<Busy>,
}

impl Leased {
    /// A lease on a link nothing else can let go: a local link, or an opened one.
    #[must_use]
    pub(crate) fn of(link: Arc<Link>) -> Self {
        Self { link, _busy: None }
    }

    /// The link.
    #[must_use]
    pub(crate) fn link(&self) -> &Arc<Link> {
        &self.link
    }
}

impl std::ops::Deref for Leased {
    type Target = Link;

    fn deref(&self) -> &Link {
        &self.link
    }
}

/// An ambient link's claim: it is busy while any call holds one.
struct Busy {
    busy: Arc<AtomicUsize>,
    freed: Arc<Notify>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        if self.busy.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.freed.notify_waiters();
        }
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Link>>>>;

struct AmbientEntry {
    session_id: SessionId,
    slot: Slot,
    busy: Arc<AtomicUsize>,
    last_used: Instant,
}

/// The opening a session's screen holds now, and the number of the call that chose it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Current {
    opening: String,
    attempt: u64,
}

/// One session's opened link.
struct Opened {
    opening: String,
    link: Arc<Link>,
    standing: SessionStanding,
    watch: Option<tauri::async_runtime::JoinHandle<()>>,
}

#[derive(Default)]
struct Inner {
    attempts: u64,
    current: BTreeMap<SessionId, Current>,
    opened: BTreeMap<SessionId, Opened>,
    seen: BTreeMap<SessionId, VecDeque<String>>,
    ambient: Vec<AmbientEntry>,
}

/// The links this application holds to a paired host's sessions.
#[derive(Default)]
pub struct PairedLinks {
    inner: Mutex<Inner>,
    freed: Arc<Notify>,
}

impl std::fmt::Debug for PairedLinks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairedLinks")
            .finish_non_exhaustive()
    }
}

/// Whether a token is one the page may choose: letters, digits and dashes, and not long.
fn well_formed(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_LIMIT
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Whether a refusal says the host is only unable to answer now, so that asking again may be
/// answered differently.
fn transient(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::StorageUnavailable
            | ErrorCode::ClockUntrusted
            | ErrorCode::ResourceUnavailable
            | ErrorCode::UpstreamUnavailable
    )
}

impl PairedLinks {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many sessions have an opened link.
    #[must_use]
    pub fn opened(&self) -> usize {
        self.lock().opened.len()
    }

    /// How many ambient links are held.
    #[must_use]
    pub fn ambient(&self) -> usize {
        self.lock().ambient.len()
    }

    /// Lets every link go and forgets every token: the host has changed.
    pub fn close_all(&self) {
        let (opened, ambient) = {
            let mut inner = self.lock();
            inner.current.clear();
            inner.seen.clear();
            (
                std::mem::take(&mut inner.opened),
                std::mem::take(&mut inner.ambient),
            )
        };
        for (_, opened) in opened {
            opened.end();
        }
        for entry in ambient {
            if let Ok(mut slot) = entry.slot.try_lock()
                && let Some(link) = slot.take()
            {
                link.session.close();
            }
        }
        self.freed.notify_waiters();
    }

    /// Opens `session_id` under `grant_id` (the pairing when none), as the opening the page chose.
    ///
    /// # Errors
    ///
    /// Returns a token the page may not use, a ninth opened session, and the host's refusal or why
    /// it could not be reached.
    pub async fn open(
        self: &Arc<Self>,
        dial: &Dial,
        emit: Emitter,
        session_id: SessionId,
        grant_id: Option<GrantId>,
        opening: &str,
    ) -> Result<SessionStanding> {
        if !well_formed(opening) {
            return Err(CommandError::invalid(
                "an opening is up to 64 letters, digits and dashes",
            ));
        }
        let attempt = {
            let mut inner = self.lock();
            let seen = inner.seen.entry(session_id).or_default();
            if seen.iter().any(|seen| seen == opening) {
                return Err(CommandError::invalid(
                    "that opening has been used; open the session again with a new one",
                ));
            }
            if seen.len() >= SEEN_LIMIT {
                seen.pop_front();
            }
            seen.push_back(opening.to_owned());
            if !inner.opened.contains_key(&session_id) && inner.opened.len() >= OPENED_LIMIT {
                return Err(CommandError::unavailable(
                    "too many sessions are open; leave one first",
                ));
            }
            inner.attempts += 1;
            let attempt = inner.attempts;
            inner.current.insert(
                session_id,
                Current {
                    opening: opening.to_owned(),
                    attempt,
                },
            );
            attempt
        };
        let reached = dial.open(session_id, grant_id).await;
        let mut inner = self.lock();
        let still_mine = inner
            .current
            .get(&session_id)
            .is_some_and(|current| current.opening == opening && current.attempt == attempt);
        let opening_made = match reached {
            Err(failure) => {
                if still_mine {
                    inner.current.remove(&session_id);
                }
                return Err(failure.command());
            }
            Ok(made) => made,
        };
        if !still_mine {
            // Another opening took this one's place, or the screen was left before the host
            // answered. What was made is closed and installs nothing.
            if let Opening::Open(link, _) = opening_made {
                link.session.close();
            }
            return Ok(SessionStanding::Superseded);
        }
        match opening_made {
            Opening::Ended(reason) => {
                inner.current.remove(&session_id);
                let old = inner.opened.remove(&session_id);
                drop(inner);
                if let Some(old) = old {
                    old.end();
                }
                Ok(SessionStanding::Ended {
                    reason: end_reason(reason),
                })
            }
            Opening::Open(link, standing) => {
                let watch = matches!(standing, SessionStanding::Open { .. }).then(|| {
                    tauri::async_runtime::spawn(Arc::clone(self).keep(
                        dial.clone(),
                        emit,
                        session_id,
                        grant_id,
                        opening.to_owned(),
                        Arc::clone(&link),
                    ))
                });
                let replaced = inner.opened.insert(
                    session_id,
                    Opened {
                        opening: opening.to_owned(),
                        link,
                        standing: standing.clone(),
                        watch,
                    },
                );
                drop(inner);
                if let Some(old) = replaced {
                    old.end();
                }
                Ok(standing)
            }
        }
    }

    /// Leaves an opening: stops its watch, refuses its commands from now on, and closes its link
    /// once the mutations in flight on it have answered.
    ///
    /// A leave that arrives before its open marks the token used, so the open that follows
    /// installs no link nobody closes: two calls from the page are not delivered in order.
    pub fn leave(&self, session_id: SessionId, opening: &str) {
        let mut inner = self.lock();
        let current = inner
            .current
            .get(&session_id)
            .is_some_and(|current| current.opening == opening);
        if current {
            inner.current.remove(&session_id);
        }
        let held = inner
            .opened
            .get(&session_id)
            .is_some_and(|held| held.opening == opening);
        if held && let Some(old) = inner.opened.remove(&session_id) {
            drop(inner);
            old.end();
            return;
        }
        if !current && well_formed(opening) {
            let seen = inner.seen.entry(session_id).or_default();
            if !seen.iter().any(|seen| seen == opening) {
                if seen.len() >= SEEN_LIMIT {
                    seen.pop_front();
                }
                seen.push_back(opening.to_owned());
            }
        }
    }

    /// The link of the opening a command names, or the words for why there is none.
    ///
    /// # Errors
    ///
    /// Refuses a token that is not the session's current opening, and says why a current one has
    /// no link to use now.
    pub(crate) fn opened_link(&self, session_id: SessionId, opening: &str) -> Result<Leased> {
        let inner = self.lock();
        let Some(held) = inner
            .opened
            .get(&session_id)
            .filter(|held| held.opening == opening)
        else {
            return Err(CommandError::stated(
                ErrorCode::StaleSession,
                "This screen was replaced by another opening of the session. Go back and open it \
                 again.",
            ));
        };
        match &held.standing {
            SessionStanding::Open { .. } | SessionStanding::Closed => {
                Ok(Leased::of(Arc::clone(&held.link)))
            }
            SessionStanding::Reconnecting { .. } => Err(CommandError::unavailable(
                "Contact with this session was lost. It is being reached again.",
            )),
            SessionStanding::Ended { .. } => Err(CommandError::stated(
                ErrorCode::PermissionDenied,
                "This share has ended.",
            )),
            SessionStanding::Refused { message, .. } => Err(CommandError::stated(
                ErrorCode::PermissionDenied,
                message.clone(),
            )),
            SessionStanding::Superseded => Err(CommandError::stated(
                ErrorCode::StaleSession,
                "This screen was replaced by another opening of the session.",
            )),
        }
    }

    /// The link a command that comes from outside a session screen uses: the opened link when it
    /// runs under the pairing, else an ambient link, opened under the pairing on demand.
    ///
    /// Only an idle ambient link is let go to make room, and a call waits for a place when all
    /// are busy.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, `UNKNOWN_SESSION` among it, or why it could not be reached.
    pub(crate) async fn ambient_link(&self, dial: &Dial, session_id: SessionId) -> Result<Leased> {
        {
            let inner = self.lock();
            if let Some(held) = inner.opened.get(&session_id)
                && matches!(&held.standing, SessionStanding::Open { via: "pairing", .. })
                && held.link.grant_id.is_none()
            {
                return Ok(Leased::of(Arc::clone(&held.link)));
            }
        }
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            let pick = {
                let mut inner = self.lock();
                let now = Instant::now();
                if let Some(entry) = inner
                    .ambient
                    .iter_mut()
                    .find(|entry| entry.session_id == session_id)
                {
                    entry.busy.fetch_add(1, Ordering::SeqCst);
                    entry.last_used = now;
                    Some((Arc::clone(&entry.slot), Arc::clone(&entry.busy)))
                } else {
                    // Links idle past their time go first, then the longest idle when a place is
                    // wanted. A busy link is never let go.
                    let (idle, held): (Vec<_>, Vec<_>) = std::mem::take(&mut inner.ambient)
                        .into_iter()
                        .partition(|entry| {
                            entry.busy.load(Ordering::SeqCst) == 0
                                && now.duration_since(entry.last_used) >= AMBIENT_IDLE
                        });
                    inner.ambient = held;
                    for entry in idle {
                        close_slot(&entry.slot);
                    }
                    if inner.ambient.len() >= AMBIENT_LIMIT {
                        let oldest = inner
                            .ambient
                            .iter()
                            .enumerate()
                            .filter(|(_, entry)| entry.busy.load(Ordering::SeqCst) == 0)
                            .min_by_key(|(_, entry)| entry.last_used)
                            .map(|(index, _)| index);
                        if let Some(index) = oldest {
                            let gone = inner.ambient.remove(index);
                            close_slot(&gone.slot);
                        }
                    }
                    if inner.ambient.len() < AMBIENT_LIMIT {
                        let entry = AmbientEntry {
                            session_id,
                            slot: Slot::default(),
                            busy: Arc::new(AtomicUsize::new(1)),
                            last_used: now,
                        };
                        let picked = (Arc::clone(&entry.slot), Arc::clone(&entry.busy));
                        inner.ambient.push(entry);
                        Some(picked)
                    } else {
                        None
                    }
                }
            };
            let Some((slot, busy)) = pick else {
                freed.await;
                continue;
            };
            let claim = Busy {
                busy,
                freed: Arc::clone(&self.freed),
            };
            let mut held = slot.lock().await;
            if let Some(link) = held.as_ref()
                && live(link).await
            {
                return Ok(Leased {
                    link: Arc::clone(link),
                    _busy: Some(claim),
                });
            }
            let link = match dial.open(session_id, None).await {
                Ok(Opening::Open(link, _)) => link,
                Ok(Opening::Ended(_)) => {
                    return Err(CommandError::stated(
                        ErrorCode::PermissionDenied,
                        "This session is not open to this device.",
                    ));
                }
                Err(failure) => return Err(failure.command()),
            };
            *held = Some(Arc::clone(&link));
            return Ok(Leased {
                link,
                _busy: Some(claim),
            });
        }
    }

    /// Ends the connection of a session's opened link as a lost network would, leaving the opening
    /// in place, so that its watch reaches the host again. For a test of that recovery.
    #[doc(hidden)]
    pub fn lose_connection(&self, session_id: SessionId) {
        let link = self
            .lock()
            .opened
            .get(&session_id)
            .map(|held| Arc::clone(&held.link));
        if let Some(link) = link {
            link.session.close();
        }
    }

    /// Lets an ambient link go, if it is still the one held for `session_id`: a call that failed
    /// on an old link does not take a new one away.
    pub(crate) fn forget_ambient(&self, session_id: SessionId, link: &Arc<Link>) {
        let slot = {
            let inner = self.lock();
            inner
                .ambient
                .iter()
                .find(|entry| entry.session_id == session_id)
                .map(|entry| Arc::clone(&entry.slot))
        };
        if let Some(slot) = slot
            && let Ok(mut held) = slot.try_lock()
            && held.as_ref().is_some_and(|held| Arc::ptr_eq(held, link))
        {
            *held = None;
            link.session.close();
        }
    }

    /// Keeps an opened link: waits for its connection to end, and reaches the host again as the
    /// same opening, telling the page where that stands, until the opening is left, replaced or
    /// the host says it is over.
    async fn keep(
        self: Arc<Self>,
        dial: Dial,
        emit: Emitter,
        session_id: SessionId,
        grant_id: Option<GrantId>,
        opening: String,
        mut link: Arc<Link>,
    ) {
        let tell = |standing: SessionStanding| {
            emit(StandingEvent {
                session_id: session_id.to_string(),
                opening: opening.clone(),
                standing,
            });
        };
        loop {
            link.session.closed().await;
            if !self.set_standing(
                session_id,
                &opening,
                SessionStanding::Reconnecting {
                    reason: "contact with this session was lost".to_owned(),
                },
            ) {
                return;
            }
            tell(SessionStanding::Reconnecting {
                reason: "contact with this session was lost".to_owned(),
            });
            let mut failures: u32 = 0;
            let mut refused: Option<ErrorCode> = None;
            loop {
                tokio::time::sleep(pause(failures)).await;
                if !self.is_current(session_id, &opening) {
                    return;
                }
                match dial.open(session_id, grant_id).await {
                    Ok(Opening::Open(fresh, standing)) => {
                        if !self.reinstall(session_id, &opening, &fresh, &standing) {
                            fresh.session.close();
                            return;
                        }
                        tell(standing);
                        link = fresh;
                        break;
                    }
                    Ok(Opening::Ended(reason)) => {
                        let standing = SessionStanding::Ended {
                            reason: end_reason(reason),
                        };
                        if self.set_standing(session_id, &opening, standing.clone()) {
                            tell(standing);
                        }
                        return;
                    }
                    Err(Failure::Refused(refusal)) if !transient(refusal.code) => {
                        // A refusal is told only once a second probe agrees: a revocation or an
                        // expiry landing between the host's two reads reads as a refusal once.
                        if refused == Some(refusal.code) {
                            let standing = SessionStanding::Refused {
                                code: refusal.code,
                                message: refusal.message,
                            };
                            if self.set_standing(session_id, &opening, standing.clone()) {
                                tell(standing);
                            }
                            return;
                        }
                        refused = Some(refusal.code);
                    }
                    Err(Failure::Refused(refusal)) => {
                        failures = failures.saturating_add(1);
                        let _ = refusal;
                    }
                    Err(Failure::Unreached(reason)) => {
                        failures = failures.saturating_add(1);
                        let standing = SessionStanding::Reconnecting { reason };
                        if self.set_standing(session_id, &opening, standing.clone()) {
                            tell(standing);
                        }
                    }
                }
            }
        }
    }

    fn is_current(&self, session_id: SessionId, opening: &str) -> bool {
        self.lock()
            .current
            .get(&session_id)
            .is_some_and(|current| current.opening == opening)
    }

    /// Changes the standing of the opening's link, if it is still the session's.
    fn set_standing(
        &self,
        session_id: SessionId,
        opening: &str,
        standing: SessionStanding,
    ) -> bool {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening)
        {
            Some(held) => {
                held.standing = standing;
                true
            }
            None => false,
        }
    }

    /// Makes `fresh` the opening's link, with the new epoch and the rights the host just decided,
    /// if the opening is still the session's. The old link is closed.
    fn reinstall(
        &self,
        session_id: SessionId,
        opening: &str,
        fresh: &Arc<Link>,
        standing: &SessionStanding,
    ) -> bool {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening)
        {
            Some(held) => {
                let old = std::mem::replace(&mut held.link, Arc::clone(fresh));
                held.standing = standing.clone();
                old.session.close();
                true
            }
            None => false,
        }
    }
}

fn close_slot(slot: &Slot) {
    if let Ok(mut held) = slot.try_lock()
        && let Some(link) = held.take()
    {
        link.session.close();
    }
}

fn end_reason(reason: ShareEnd) -> &'static str {
    match reason {
        ShareEnd::Revoked => "revoked",
        ShareEnd::Expired => "expired",
    }
}

impl Opened {
    /// Ends the opening: its watch stops, and its link closes once the mutations in flight on it
    /// have answered, within a mutation's lifetime.
    fn end(mut self) {
        if let Some(watch) = self.watch.take() {
            watch.abort();
        }
        let link = self.link;
        tauri::async_runtime::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(crate::commands::MUTATION_TTL.get()),
                link.flight.idle(),
            )
            .await;
            link.session.close();
        });
    }
}

/// The environment, session and epoch a link reaches.
#[derive(Clone, Copy, Debug)]
pub struct LinkIds {
    /// The host's environment.
    pub environment_id: EnvironmentId,
    /// The session.
    pub session_id: SessionId,
    /// Its epoch.
    pub session_epoch: SessionEpoch,
}

/// Opens a session for the page's `opening` and tells it where that stands.
///
/// On the host on this machine (this application is its owner) every right is held and nothing is
/// opened: the descriptor path stays. On a host this device is paired with, the host opens the
/// session on a connection of its own and says what the grant allows.
///
/// # Errors
///
/// Returns an opening the page may not use, why the host could not be reached, or the host's
/// refusal.
pub async fn open_session<R: tauri::Runtime>(
    app: &AppHandle<R>,
    state: &crate::AppState,
    session_id: &str,
    grant_id: Option<&str>,
    opening: &str,
) -> Result<SessionStanding> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    let grant_id: Option<GrantId> = match grant_id {
        Some(text) => Some(
            text.parse()
                .map_err(|_| CommandError::invalid("that is not a grant identifier"))?,
        ),
        None => None,
    };
    let Some(context) = state.paired_context() else {
        if !well_formed(opening) {
            return Err(CommandError::invalid(
                "an opening is up to 64 letters, digits and dashes",
            ));
        }
        return Ok(SessionStanding::Open {
            via: "owner",
            grant_id: String::new(),
            actions: ActionRight::ALL.to_vec(),
            includes_live_screen: true,
            history_from_ms: None,
            ends_at_ms: None,
        });
    };
    let emitter = app.clone();
    let emit: Emitter = Arc::new(move |event| {
        let _ = emitter.emit(STANDING_EVENT, event);
    });
    state
        .paired_links()
        .open(
            &Dial::new(context.device, context.host),
            emit,
            session_id,
            grant_id,
            opening,
        )
        .await
}

/// Leaves the opening of a session. A token that is not the session's current opening is ignored.
///
/// # Errors
///
/// Returns a refusal for a session identifier that is not one.
pub fn leave_session(state: &crate::AppState, session_id: &str, opening: &str) -> Result<()> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    state.paired_links().leave(session_id, opening);
    Ok(())
}
