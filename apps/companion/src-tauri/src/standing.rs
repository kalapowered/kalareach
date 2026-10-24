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
use kr_protocol::error::{ErrorCode, ProtocolError, RetryCategory};
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

/// The longest wait after `failures` attempts in a row: the ceiling of the client library's
/// reconnect ladder (section 23) before its jitter. The recheck of a view that lost its connection
/// waits this long, because the views of one opening are counted by this code and not by a loop.
fn pause(failures: u32) -> Duration {
    let mut ladder = kr_client::reconnect::ReconnectLoop::new();
    for _ in 0..failures.min(16) {
        ladder.disconnected();
    }
    ladder.ceiling()
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
pub(crate) type Emitter = Arc<dyn Fn(StandingEvent) + Send + Sync>;

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
pub(crate) enum Failure {
    /// The host answered with a refusal.
    Refused(ProtocolError),
    /// The host could not be reached, or the connection to it ended.
    Unreached(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(formatter, "The host refused: {}", refusal.message),
            Self::Unreached(reason) => {
                write!(formatter, "The host could not be reached: {reason}")
            }
        }
    }
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

    /// Reaches the host on a connection of its own, as the device it paired as, and returns the
    /// connection's transport with nothing yet said on it.
    pub(crate) async fn transport(
        &self,
    ) -> std::result::Result<Arc<dyn kr_client::transport::ControlTransport>, Failure> {
        let pairing = self.device.pairing();
        let identity = pairing.candidate.paired_identity(self.host.device_id);
        tokio::time::timeout(
            OPEN_WITHIN,
            pairing.link.connect_paired_transport(&self.host, &identity),
        )
        .await
        .map_err(|_| Failure::Unreached("the host did not answer in time".to_owned()))?
        .map_err(|error| match error {
            LinkError::Refused(refusal) => Failure::Refused(refusal),
            other => Failure::Unreached(other.said().into_string()),
        })
    }

    /// Reaches the host on a connection of its own and has it open `session_id` under `grant_id`.
    async fn open(
        &self,
        session_id: SessionId,
        grant_id: Option<GrantId>,
    ) -> std::result::Result<Opening, Failure> {
        let transport = self.transport().await?;
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
                // An account that left ended the connection, and says so.
                let words = session
                    .transport()
                    .ended_by_this_device()
                    .map_or_else(|| other.said().into_string(), |refusal| refusal.message);
                session.close();
                return Err(Failure::Unreached(words));
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
                session: ref summary,
                environment_id,
                grant_id,
                via,
                ..
            } => {
                let standing = standing_of(&opened);
                let Some(summary) = summary.0.clone() else {
                    session.close();
                    return Err(Failure::Unreached(
                        "the host opened a connection for no session".to_owned(),
                    ));
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

/// What the host's answer to `session.open` says of the opening: the rights it decided the open
/// with, that the share has ended, or that the session has closed. The one reading of the answer,
/// for the open that makes a link and the question asked again on one that stands.
fn standing_of(opened: &SessionOpenResult) -> SessionStanding {
    match opened {
        SessionOpenResult::Ended { reason } => SessionStanding::Ended {
            reason: end_reason(*reason),
        },
        SessionOpenResult::InForce {
            session,
            via,
            grant_id,
            actions,
            includes_live_screen,
            history_from_ms,
            ends_at_ms,
            ..
        } => {
            if session
                .0
                .as_ref()
                .is_some_and(|summary| summary.state == SessionState::Closed)
            {
                return SessionStanding::Closed;
            }
            SessionStanding::Open {
                via: match via {
                    OpenedVia::Pairing => "pairing",
                    OpenedVia::Share => "share",
                },
                grant_id: grant_id.to_string(),
                actions: actions.iter().copied().collect(),
                includes_live_screen: *includes_live_screen,
                history_from_ms: history_from_ms.0.map(|at| at.get()),
                ends_at_ms: ends_at_ms.0.map(|at| at.get()),
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
    /// Counts the call as in flight on an opened link from the moment the link is taken, so a
    /// leave that follows waits for it and a leave that came first has already refused the call.
    _flight: Option<InFlight>,
}

impl Leased {
    /// A lease on a link nothing else can let go: a local link, or an opened one.
    #[must_use]
    pub(crate) fn of(link: Arc<Link>) -> Self {
        Self {
            link,
            _busy: None,
            _flight: None,
        }
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

/// The link an ambient entry holds, readable without waiting for the slot a call may hold across
/// its open: a host change closes it through this.
type Held = Arc<Mutex<Option<Arc<Link>>>>;

struct AmbientEntry {
    session_id: SessionId,
    slot: Slot,
    held: Held,
    busy: Arc<AtomicUsize>,
    last_used: Instant,
}

impl AmbientEntry {
    /// Lets the entry's link go, whether or not a call holds the slot.
    fn close(&self) {
        if let Some(link) = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            link.session.close();
        }
        close_slot(&self.slot);
    }
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
    /// The link, or nothing while the host could not be reached for the first time and the watch
    /// is probing.
    link: Option<Arc<Link>>,
    standing: SessionStanding,
    watch: Option<tauri::async_runtime::JoinHandle<()>>,
    /// What closes the raw terminal views opened under this opening, each on a connection of its
    /// own, when the opening ends.
    views: Vec<Box<dyn FnOnce() + Send>>,
    /// How many views of this opening lost their connection since one last drew a screen, so that a
    /// view that cannot hold a connection is not opened again at the speed of the network.
    losses: u32,
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
    /// How many times the host has changed. An ambient open that began under an earlier host
    /// serves nothing.
    generation: std::sync::atomic::AtomicU64,
    /// How many times a view that lost its connection has had the host asked again.
    rechecks: AtomicUsize,
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
/// answered differently: the protocol's own transient category, and a clock the host does not
/// trust yet, which it trusts again later.
pub(crate) fn transient(code: ErrorCode) -> bool {
    code.retry_category() == RetryCategory::Transient || code == ErrorCode::ClockUntrusted
}

impl PairedLinks {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many times the host in use has changed. A call reads it before it reads the host, and
    /// hands its link over only while it has not moved.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Leaves every opening: the page that made them is gone, and it will make its own again with
    /// tokens of its own. What is in flight on each link answers first.
    pub fn leave_all(&self) {
        let opened = {
            let mut inner = self.lock();
            inner.current.clear();
            std::mem::take(&mut inner.opened)
        };
        for (_, opened) in opened {
            opened.end();
        }
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
            // Moved on under the lock an ambient call hands its link over under, so a link is
            // either handed over before this and closed below, or sees the change and closes itself.
            self.generation.fetch_add(1, Ordering::SeqCst);
            inner.current.clear();
            inner.seen.clear();
            (
                std::mem::take(&mut inner.opened),
                std::mem::take(&mut inner.ambient),
            )
        };
        for (_, opened) in opened {
            opened.end_now();
        }
        for entry in ambient {
            entry.close();
        }
        self.freed.notify_waiters();
    }

    /// Opens `session_id` under `grant_id` (the pairing when none), as the opening the page chose.
    ///
    /// The opening is the session's current one from the moment this is called: the session's
    /// earlier opening, if any, is over then, whatever becomes of this one, and a place among the
    /// eight is held for it until it is left.
    ///
    /// A host that cannot be reached, or cannot answer now, does not fail the open: the opening
    /// stands as `reconnecting` and its watch reaches the host as soon as it can.
    ///
    /// # Errors
    ///
    /// Returns a token the page may not use, a ninth opened session, and the host's refusal.
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
        let (attempt, replaced) = {
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
            // A place is held from the call, not from the link: nine opens made together are
            // refused at the ninth whichever has answered.
            if !inner.current.contains_key(&session_id) && inner.current.len() >= OPENED_LIMIT {
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
            (attempt, inner.opened.remove(&session_id))
        };
        // The earlier opening is over now, not when this one has answered: its commands are
        // refused, its watch stops and its link and views close.
        if let Some(old) = replaced {
            old.end_now();
        }
        let reached = dial.open(session_id, grant_id).await;
        let mut inner = self.lock();
        let still_mine = inner
            .current
            .get(&session_id)
            .is_some_and(|current| current.opening == opening && current.attempt == attempt);
        let opening_made = match reached {
            Ok(made) => made,
            Err(failure) => {
                if !still_mine {
                    return Ok(SessionStanding::Superseded);
                }
                let unable = match &failure {
                    Failure::Unreached(_) => true,
                    Failure::Refused(refusal) => transient(refusal.code),
                };
                if !unable {
                    inner.current.remove(&session_id);
                    return Err(failure.command());
                }
                // The host could not be reached or could not say yet: the opening stands, and its
                // watch reaches the host again as the same opening.
                let reason = match failure {
                    Failure::Unreached(reason) => reason,
                    Failure::Refused(refusal) => refusal.message,
                };
                let standing = SessionStanding::Reconnecting { reason };
                let watch = tauri::async_runtime::spawn(Arc::clone(self).keep(
                    dial.clone(),
                    emit,
                    session_id,
                    grant_id,
                    opening.to_owned(),
                    None,
                ));
                inner.opened.insert(
                    session_id,
                    Opened {
                        opening: opening.to_owned(),
                        link: None,
                        standing: standing.clone(),
                        watch: Some(watch),
                        views: Vec::new(),
                        losses: 0,
                    },
                );
                return Ok(standing);
            }
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
                        Some(Arc::clone(&link)),
                    ))
                });
                inner.opened.insert(
                    session_id,
                    Opened {
                        opening: opening.to_owned(),
                        link: Some(link),
                        standing: standing.clone(),
                        watch,
                        views: Vec::new(),
                        losses: 0,
                    },
                );
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
        let reaching = || {
            CommandError::unavailable(
                "Contact with this session was lost. It is being reached again.",
            )
        };
        match &held.standing {
            SessionStanding::Open { .. } | SessionStanding::Closed => held
                .link
                .as_ref()
                .map(|link| Leased {
                    link: Arc::clone(link),
                    _busy: None,
                    // Taken under the same lock the leave takes the link out under.
                    _flight: Some(Flight::enter(link)),
                })
                .ok_or_else(reaching),
            SessionStanding::Reconnecting { .. } => Err(reaching()),
            SessionStanding::Ended { .. } => Err(CommandError::stated(
                ErrorCode::PermissionDenied,
                "This share has ended.",
            )),
            SessionStanding::Refused { code, message } => {
                Err(CommandError::stated(*code, message.clone()))
            }
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
    pub(crate) async fn ambient_link(
        &self,
        dial: &Dial,
        session_id: SessionId,
        generation: u64,
    ) -> Result<Leased> {
        {
            let inner = self.lock();
            if let Some(held) = inner.opened.get(&session_id)
                && matches!(&held.standing, SessionStanding::Open { via: "pairing", .. })
                && let Some(link) = &held.link
                && link.grant_id.is_none()
            {
                return Ok(Leased::of(Arc::clone(link)));
            }
        }
        let host_changed =
            || CommandError::unavailable("The host in use changed while this was being asked.");
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if self.generation.load(Ordering::SeqCst) != generation {
                return Err(host_changed());
            }
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
                    Some((
                        Arc::clone(&entry.slot),
                        Arc::clone(&entry.held),
                        Arc::clone(&entry.busy),
                    ))
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
                        entry.close();
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
                            gone.close();
                        }
                    }
                    if inner.ambient.len() < AMBIENT_LIMIT {
                        let entry = AmbientEntry {
                            session_id,
                            slot: Slot::default(),
                            held: Held::default(),
                            busy: Arc::new(AtomicUsize::new(1)),
                            last_used: now,
                        };
                        let picked = (
                            Arc::clone(&entry.slot),
                            Arc::clone(&entry.held),
                            Arc::clone(&entry.busy),
                        );
                        inner.ambient.push(entry);
                        Some(picked)
                    } else {
                        None
                    }
                }
            };
            let Some((slot, mirror, busy)) = pick else {
                freed.await;
                continue;
            };
            let claim = Busy {
                busy,
                freed: Arc::clone(&self.freed),
            };
            let mut held = slot.lock().await;
            if self.generation.load(Ordering::SeqCst) != generation {
                return Err(host_changed());
            }
            if let Some(link) = held.as_ref()
                && live(link).await
            {
                self.hand_over(generation, &mirror, link)?;
                return Ok(Leased {
                    link: Arc::clone(link),
                    _busy: Some(claim),
                    _flight: None,
                });
            }
            let opened = dial.open(session_id, None).await;
            let link = match opened {
                Ok(Opening::Open(link, _)) => link,
                Ok(Opening::Ended(_)) => {
                    return Err(CommandError::stated(
                        ErrorCode::PermissionDenied,
                        "This session is not open to this device.",
                    ));
                }
                Err(failure) => return Err(failure.command()),
            };
            // A host that changed while this was asked is not the host this was asked of: the
            // link is handed over, or closed, under the lock a host change moves the generation
            // under.
            self.hand_over(generation, &mirror, &link)?;
            *held = Some(Arc::clone(&link));
            return Ok(Leased {
                link,
                _busy: Some(claim),
                _flight: None,
            });
        }
    }

    /// The share an opening runs under, for a raw terminal view opened under it, or the words for
    /// why the opening is not the session's.
    ///
    /// # Errors
    ///
    /// Refuses a token that is not the session's current opening.
    pub(crate) fn opening_grant(
        &self,
        session_id: SessionId,
        opening: &str,
    ) -> Result<Option<GrantId>> {
        Ok(self.opened_link(session_id, opening)?.grant_id)
    }

    /// Ties a raw terminal view to an opening: `close` runs when the opening is left, replaced or
    /// ends. Returns `close` back when the opening is no longer the session's, so the caller ends
    /// the view itself.
    pub(crate) fn attach_view(
        &self,
        session_id: SessionId,
        opening: &str,
        close: Box<dyn FnOnce() + Send>,
    ) -> std::result::Result<(), Box<dyn FnOnce() + Send>> {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening)
        {
            Some(held) => {
                held.views.push(close);
                Ok(())
            }
            None => Err(close),
        }
    }

    /// Asks the host again, on the opening's live link, what it allows, and tells the page: a view
    /// on a connection of its own ended while the link did not, so the host's answer says whether
    /// the share still stands. An answer that it does is `open`, which the page opens a view again
    /// on; the host ending the share is `ended`.
    ///
    /// A host that cannot answer now, or an answer that is late, is asked again after a pause while
    /// the link lives and the opening stands: a prompt in flight on the link is answered first, and
    /// the host answers one request at a time. When the link goes, its watch takes over.
    pub async fn recheck(self: &Arc<Self>, emit: &Emitter, session_id: SessionId, opening: &str) {
        // Paced by the views of this opening that lost their connections without drawing: the
        // first is asked about after the shortest pause, and each one after waits longer, so a view
        // that cannot hold a connection is not opened again as fast as the network goes.
        let losses = self.note_loss(session_id, opening);
        tokio::time::sleep(pause(losses.saturating_sub(1))).await;
        let mut failures: u32 = 0;
        let mut refused: Option<ErrorCode> = None;
        loop {
            let held = {
                let inner = self.lock();
                inner
                    .opened
                    .get(&session_id)
                    .filter(|held| held.opening == opening)
                    .and_then(|held| held.link.clone())
            };
            let Some(link) = held else {
                return;
            };
            if !live(&link).await {
                // The link is gone too, and its watch is already reaching the host again.
                return;
            }
            let asked = tokio::time::timeout(
                OPEN_WITHIN,
                link.session.read::<_, SessionOpenResult>(
                    Method::SessionOpen,
                    &SessionOpenParams {
                        session_id: Nullable::some(session_id),
                        grant_id: Nullable(link.grant_id),
                    },
                ),
            )
            .await;
            let standing = match asked {
                Ok(Ok(opened)) => standing_of(&opened),
                Ok(Err(ClientError::Host(refusal))) if !transient(refusal.code) => {
                    // A refusal is told only once a second ask agrees: a revocation or an expiry
                    // landing between the host's two reads reads as a refusal once, and the typed
                    // answer is what the watch learns when the link closes.
                    if refused != Some(refusal.code) {
                        refused = Some(refusal.code);
                        tokio::time::sleep(pause(0)).await;
                        continue;
                    }
                    SessionStanding::Refused {
                        code: refusal.code,
                        message: refusal.message,
                    }
                }
                // The host could not answer now, or the answer was late.
                _ => {
                    tokio::time::sleep(pause(failures)).await;
                    failures = failures.saturating_add(1);
                    continue;
                }
            };
            self.tell_standing_on(emit, session_id, opening, &link, standing);
            return;
        }
    }

    /// Notes that a view of the opening lost its connection, and answers how many have since one
    /// last drew a screen.
    fn note_loss(&self, session_id: SessionId, opening: &str) -> u32 {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening)
        {
            Some(held) => {
                held.losses = held.losses.saturating_add(1);
                held.losses
            }
            None => 0,
        }
    }

    /// Notes that a view of the opening drew a screen: its connection held.
    pub fn drew(&self, session_id: SessionId, opening: &str) {
        if let Some(held) = self
            .lock()
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening)
        {
            held.losses = 0;
        }
    }

    /// Notes, at once and where the view's end is known, that the host is to be asked again for a
    /// view that lost its connection. A test reads how many.
    pub fn note_recheck(&self) {
        self.rechecks.fetch_add(1, Ordering::SeqCst);
    }

    /// How many views that lost their connection have had the host asked again.
    #[must_use]
    pub fn rechecks(&self) -> usize {
        self.rechecks.load(Ordering::SeqCst)
    }

    /// How many actions the opened link of a session still counts as unresolved, or none when the
    /// opening holds no link. For a test of what the link's book keeps.
    #[doc(hidden)]
    pub async fn unresolved(&self, session_id: SessionId, opening: &str) -> Option<usize> {
        let link = self.opened_link(session_id, opening).ok()?;
        Some(link.session.submitted_actions().await.len())
    }

    /// Ends the connection of a session's opened link as a lost network would, leaving the opening
    /// in place, so that its watch reaches the host again. For a test of that recovery.
    #[doc(hidden)]
    pub fn lose_connection(&self, session_id: SessionId) {
        let link = self
            .lock()
            .opened
            .get(&session_id)
            .and_then(|held| held.link.clone());
        if let Some(link) = link {
            link.session.close();
        }
    }

    /// Hands `link` to a call that began under `generation`, and records it where a host change
    /// finds it, or closes it when the host has changed since.
    fn hand_over(&self, generation: u64, mirror: &Held, link: &Arc<Link>) -> Result<()> {
        let _inner = self.lock();
        if self.generation.load(Ordering::SeqCst) != generation {
            link.session.close();
            return Err(CommandError::unavailable(
                "The host in use changed while this was being asked.",
            ));
        }
        *mirror.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(link));
        Ok(())
    }

    /// Lets an ambient link go, if it is still the one held for `session_id`: a call that failed
    /// on an old link does not take a new one away.
    pub(crate) fn forget_ambient(&self, session_id: SessionId, link: &Arc<Link>) {
        let entry = {
            let inner = self.lock();
            inner
                .ambient
                .iter()
                .find(|entry| entry.session_id == session_id)
                .map(|entry| (Arc::clone(&entry.slot), Arc::clone(&entry.held)))
        };
        if let Some((slot, mirror)) = entry
            && let Ok(mut held) = slot.try_lock()
            && held.as_ref().is_some_and(|held| Arc::ptr_eq(held, link))
        {
            *held = None;
            mirror.lock().unwrap_or_else(PoisonError::into_inner).take();
            link.session.close();
        }
    }

    /// Keeps an opening: waits for its link's connection to end, and reaches the host again as the
    /// same opening, telling the page where that stands, until the opening is left, replaced or the
    /// host says it is over. An opening that has no link yet, because the host could not be reached
    /// when it was made, starts by reaching the host.
    async fn keep(
        self: Arc<Self>,
        dial: Dial,
        emit: Emitter,
        session_id: SessionId,
        grant_id: Option<GrantId>,
        opening: String,
        mut link: Option<Arc<Link>>,
    ) {
        let mut backoff = kr_client::reconnect::ReconnectLoop::new();
        loop {
            if let Some(held) = link.take() {
                backoff.connected();
                held.session.closed().await;
                // An opening that is over, or was left or replaced, is not reached again.
                let lost = SessionStanding::Reconnecting {
                    reason: held.session.transport().ended_by_this_device().map_or_else(
                        || "contact with this session was lost".to_owned(),
                        |refusal| refusal.message,
                    ),
                };
                if !self.tell_standing(&emit, session_id, &opening, lost) {
                    return;
                }
            }
            let mut refused: Option<ErrorCode> = None;
            loop {
                // Jittered, growing while the host does not answer, and starting over only once a
                // link has lasted: a link that opens and closes at once is not reached again at
                // network speed, and a host's openings that lose one network do not all return together.
                tokio::time::sleep(backoff.disconnected()).await;
                if !self.is_current(session_id, &opening) {
                    return;
                }
                match dial.open(session_id, grant_id).await {
                    Ok(Opening::Open(fresh, standing)) => {
                        if !self.tell_reinstall(&emit, session_id, &opening, &fresh, standing) {
                            fresh.session.close();
                            return;
                        }
                        link = Some(fresh);
                        break;
                    }
                    Ok(Opening::Ended(reason)) => {
                        let standing = SessionStanding::Ended {
                            reason: end_reason(reason),
                        };
                        self.tell_standing(&emit, session_id, &opening, standing);
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
                            self.tell_standing(&emit, session_id, &opening, standing);
                            return;
                        }
                        refused = Some(refusal.code);
                    }
                    Err(Failure::Refused(_)) => {}
                    Err(Failure::Unreached(reason)) => {
                        let standing = SessionStanding::Reconnecting { reason };
                        self.tell_standing(&emit, session_id, &opening, standing);
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

    /// Changes the standing of the opening and tells the page, if the opening is still the session's
    /// and nothing has ended it: an opening that has ended, been refused, closed or replaced stays
    /// so. The change and its telling are one step under the lock, so a standing is never told
    /// after one that came later.
    ///
    /// Telling posts the event to the window and waits for nothing. No listener on this side hears
    /// it, and nothing a listener could do here takes this lock again.
    fn tell_standing(
        &self,
        emit: &Emitter,
        session_id: SessionId,
        opening: &str,
        standing: SessionStanding,
    ) -> bool {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening && !is_over(&held.standing))
        {
            Some(held) => {
                held.standing = standing.clone();
                emit(StandingEvent {
                    session_id: session_id.to_string(),
                    opening: opening.to_owned(),
                    standing,
                });
                true
            }
            None => false,
        }
    }

    /// Changes the standing of the opening from what the host answered on `link`, and tells the
    /// page: only while that link is still the opening's and the opening is open, so that a late
    /// answer neither reverses what the watch learned since nor speaks for a link that has been
    /// replaced.
    fn tell_standing_on(
        &self,
        emit: &Emitter,
        session_id: SessionId,
        opening: &str,
        link: &Arc<Link>,
        standing: SessionStanding,
    ) -> bool {
        let mut inner = self.lock();
        match inner.opened.get_mut(&session_id).filter(|held| {
            held.opening == opening
                && matches!(held.standing, SessionStanding::Open { .. })
                && held
                    .link
                    .as_ref()
                    .is_some_and(|held| Arc::ptr_eq(held, link))
        }) {
            Some(held) => {
                held.standing = standing.clone();
                emit(StandingEvent {
                    session_id: session_id.to_string(),
                    opening: opening.to_owned(),
                    standing,
                });
                true
            }
            None => false,
        }
    }

    /// Makes `fresh` the opening's link, with the new epoch and the rights the host just decided,
    /// and tells the page, if the opening is still the session's and not over. The old link is
    /// closed.
    fn tell_reinstall(
        &self,
        emit: &Emitter,
        session_id: SessionId,
        opening: &str,
        fresh: &Arc<Link>,
        standing: SessionStanding,
    ) -> bool {
        let mut inner = self.lock();
        match inner
            .opened
            .get_mut(&session_id)
            .filter(|held| held.opening == opening && !is_over(&held.standing))
        {
            Some(held) => {
                let old = held.link.replace(Arc::clone(fresh));
                held.standing = standing.clone();
                if let Some(old) = old {
                    old.session.close();
                }
                emit(StandingEvent {
                    session_id: session_id.to_string(),
                    opening: opening.to_owned(),
                    standing,
                });
                true
            }
            None => false,
        }
    }
}

/// Whether a standing is one the host (or the page) ended, or that the session closed: nothing
/// changes it afterwards.
fn is_over(standing: &SessionStanding) -> bool {
    matches!(
        standing,
        SessionStanding::Ended { .. }
            | SessionStanding::Refused { .. }
            | SessionStanding::Closed
            | SessionStanding::Superseded
    )
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
    /// Ends the opening: its watch stops, the views opened under it close, and its link closes
    /// once the mutations in flight on it have answered, within a mutation's lifetime. For a
    /// screen that is left.
    fn end(mut self) {
        self.stop();
        let Some(link) = self.link else {
            return;
        };
        tauri::async_runtime::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(crate::commands::MUTATION_TTL.get()),
                link.flight.idle(),
            )
            .await;
            link.session.close();
        });
    }

    /// Ends the opening at once, under a mutation in flight if there is one, which then ends as a
    /// connection that ended does. For an opening that another has replaced, and for a host that
    /// changed.
    fn end_now(mut self) {
        self.stop();
        if let Some(link) = self.link {
            link.session.close();
        }
    }

    fn stop(&mut self) {
        if let Some(watch) = self.watch.take() {
            watch.abort();
        }
        // The views hold the terminal's input lease for as long as they live.
        for close in std::mem::take(&mut self.views) {
            close();
        }
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
