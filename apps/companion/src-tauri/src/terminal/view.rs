//! One raw terminal view's task: its link to the session's worker, its attachment, the screen the
//! client library holds for it, and the size it reports.
//!
//! The task opens the link, a session of the client library in the ordered mode that this view
//! alone consumes, attaches and subscribes, and then serves it in one loop: every report and
//! resubscription is a call whose future the loop owns and polls before it takes the next command,
//! and the answer is matched by the view's own number for the call when its future completes. The
//! loop never awaits a call inside a command, which would keep the page's own close waiting on the
//! host.
//!
//! The view reports its size and where the page moved its window, one report at a time, through
//! [`WindowReports`]: each report is settled by the screen its answer names, and the page is told a
//! move is settled only with a screen that holds it.
//!
//! It takes control of the program when the person asks, and writes the wheel turns, keys, text
//! and pastes they make under the input lease, through [`Lease`], on the session's input lane. A
//! release, a detach and a launch stand behind the typing they follow: on a link that carries the
//! typing as requests they are queued behind it, and on a link with a stream of its own they take
//! the lane's mark first. Each key is spelled by the
//! shared key encoder in the encoding the screen it holds says the program reads (`keys`); a
//! screen that says the program reads a form the view does not produce ends control at once. A
//! change of control is told to the page at once.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
#[cfg(feature = "testing")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt as _, StreamExt as _};
use kr_client::error::{ClientError, HostWord};
use kr_client::input::{EndCause, InputEvent, InputEvents, InputLane, InputRefusal, InputTarget};
use kr_client::ordered::Ordered;
use kr_client::projection::{Applied, Projection, decode, is_projection_event};
use kr_client::session::{Session, Settled};
use kr_client::shown::Shown;
use kr_keys::{KeyEventKind, Modifiers};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentSummary, AttachmentViewportParams,
    AttachmentViewportResult, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::{ActionTarget, Notification, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::ids::{ActionId, BuildId, GrantId, InputLeaseEpoch, RequestId, SessionId};
use kr_protocol::input::{InputAcquireParams, InputBarrier, InputReleaseParams};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::root::{ShellLaunchResult, ShellLaunchSurfaceParams, ShellLaunchSurfaceResult};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::session::{
    Dimensions, SESSION_CLOSED_EVENT, SessionReadParams, SessionReadResult,
};
use kr_protocol::worker::WorkerDescriptor;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::error::TryRecvError;

use crate::connection::{Asked, Unopened};
use crate::error::CommandError;
use crate::launch::{LaunchSurfaceAnswer, Press};

use super::input::{Input, Lease, Owed, PROFILE, Refused, wheel_reports};
use super::keys::{self, KeyAction, Keyboard, Pressed, TypedKey};
use super::link::{self, Answered, Events, Link, Lost, REFUSAL_WAIT};
use super::screen::{TerminalViewState, state_of};
use super::window::{Answer, WindowReports};
use super::{Locate, Publish};

/// What the page asks of a view once it is open.
pub(super) enum Command {
    /// The page's grid is now this size.
    Resize(Dimensions),
    /// The page moved the window.
    Move(super::window::Move),
    /// The person's input, and where to say whether the view took it.
    Input(Input, Taken),
    /// Whether a launch could be made at the session's root editor now, as this view's link reads
    /// it: the link that can hold the session's input, so the answer says whether this view does.
    LaunchSurface(Reply<LaunchSurfaceAnswer>),
    /// A launch pressed on this view's link, and where to say what the session answered.
    Launch(Press, Reply<ShellLaunchResult>),
    /// The connection ends as a lost network would end it, and the page has not asked. For a test.
    Lose,
    /// The page is done with the view.
    Close,
}

/// Where a view says whether it took an input: at once, or why it did not.
pub(super) type Taken = tokio::sync::oneshot::Sender<Result<(), Refused>>;

/// Where a view says what the session answered to a launch surface read or a launch.
pub(super) type Reply<T> = tokio::sync::oneshot::Sender<Result<T, CommandError>>;

/// What a view says to a launch surface read or a launch that reaches it before it is attached.
const STILL_OPENING: &str = "This view is still opening.";

/// What a view says to a launch the session had not answered when the view ended.
const LAUNCH_UNANSWERED: &str =
    "This view ended before the session said whether the launch was installed.";

/// What a launch is told when the lane did not take all the typing before it: nothing of it was sent.
const LAUNCH_NOT_STARTED: &str =
    "The launch was not started: the session had not accepted all the typing before it.";

/// What a launch is told when an earlier launch's hold, or a release that waits, stands in the lane:
/// nothing of it was sent.
const LAUNCH_BEHIND_ANOTHER: &str =
    "The launch was not started: an earlier launch or release of this view stands before it.";

/// How many recoveries in a row may pass without a complete screen before the view ends.
///
/// A recovery asks the session for a fresh screen. A host whose screens never decode would have the
/// view ask for ever, so after this many the view ends and says why, and the person can attach
/// again.
const RECOVERIES: u32 = 3;

/// The event a view is sent when the session asks it to take its screen again.
const RESYNC_EVENT: &str = "session.resync";

/// The event a view is sent when its attachment was ended somewhere else.
const DETACHED_EVENT: &str = "session.detached";

/// What the open answered: the link, what a mutation on it is about, and the attachment.
struct Opened {
    link: Link,
    events: Events,
    target: ActionTarget,
    attached: SessionAttachResult,
    /// Whether the worker stated that it serves the launch surface, when a worker answered the
    /// hello on this link: none on a link to a paired host's daemon.
    serves_launch_surface: Option<bool>,
    /// Whether the worker stated that it takes typing on the session's input lane, which only a
    /// worker on this machine states.
    states_input_lane: bool,
}

/// Where a view's session is reached.
pub(super) enum Reach<'a> {
    /// The worker on this machine, found by its descriptor.
    Local(&'a Locate),
    /// A host this device is paired with, over a connection opened for the view under `grant`
    /// (the pairing when none).
    Paired(&'a crate::standing::Dial, Option<GrantId>),
    /// A connection that a test made, opened as a paired host's is.
    #[cfg(feature = "testing")]
    Over(&'a Arc<dyn kr_client::transport::ControlTransport>),
}

/// Why a view's task ended, for whoever opened it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    /// The page closed the view.
    Closed,
    /// The view's connection went, or could not be used: nothing the session or the host said.
    Lost,
    /// The view ended for another reason, which the page was told: the session closed, the view
    /// was detached, a screen could not be read, or the host refused it.
    Other,
}

/// Why opening a view failed: the words the page is told, and whether it was the connection.
struct OpenFailure {
    reason: String,
    lost: bool,
}

impl OpenFailure {
    /// The connection went part way through the open.
    fn lost(lost: &Lost) -> Self {
        Self {
            reason: lost_words(lost),
            lost: true,
        }
    }

    /// The host or the worker refused, or could not be understood.
    fn refused(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            lost: false,
        }
    }
}

impl From<String> for OpenFailure {
    fn from(reason: String) -> Self {
        Self::refused(reason)
    }
}

/// A way to ask whether a lane has ended, as the lane records it.
#[cfg(feature = "testing")]
type LaneEnded = Arc<dyn Fn() -> bool + Send + Sync>;

/// What a test reads of a view while it runs, and the one thing it can give it: compiled in for the
/// application's own tests and in no shipped build. The fields are shared with the registry's entry
/// for the view, and no line of the view's own decisions reads any of them.
#[cfg(feature = "testing")]
#[derive(Clone, Default)]
pub(super) struct Probe {
    /// The most items the view's queue of what it heard has held at one time.
    pub(super) queue_peak: Arc<AtomicUsize>,
    /// How many barriers the view has taken from its input lane.
    pub(super) barriers: Arc<AtomicUsize>,
    /// How many ends of its input lane the view has served: the lane's own record says that it ended,
    /// and this says that the view read the end and acted on it.
    pub(super) lane_ends: Arc<AtomicUsize>,
    /// The view's session, once its link is open.
    pub(super) session: Arc<std::sync::Mutex<Option<Arc<Session>>>>,
    /// Whether the view's input lane has ended, as the lane records it, once the lane is open.
    pub(super) lane_ended: Arc<std::sync::Mutex<Option<LaneEnded>>>,
    /// Where the lane's waits come from in place of the shipped bounds, for the views that open
    /// after it was given.
    pub(super) lane_bounds: Option<Arc<dyn kr_transport::deadlines::Deadlines>>,
}

#[cfg(feature = "testing")]
impl Probe {
    fn publish_session(&self, session: &Arc<Session>) {
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(session));
    }

    fn publish_lane(&self, lane: &InputLane) {
        *self
            .lane_ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lane.ended_probe());
    }
}

/// Runs one view from its open until it ends or is closed, and says why it ended.
pub(super) async fn run(
    reach: Reach<'_>,
    session_id: SessionId,
    dimensions: Dimensions,
    mut commands: UnboundedReceiver<Command>,
    publish: &Publish,
    #[cfg(feature = "testing")] probe: Probe,
) -> Cause {
    // The window's reports, which take the page's sizes and moves while the view is opening too, and
    // control of the program, which a take made while it opens asks for once it is attached.
    let mut window = WindowReports::new(dimensions);
    let mut lease = Lease::default();
    let opened = {
        let opening = open(&reach, session_id, dimensions);
        tokio::pin!(opening);
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    Some(Command::Resize(size)) => window.measured(size),
                    Some(Command::Move(asked)) => window.take(asked),
                    // Nothing is attached yet, so nothing is controlled and nothing is written.
                    Some(Command::Input(input, answer)) => {
                        let _ = answer.send(match input {
                            Input::Take { number } => {
                                lease.request(number, true);
                                Ok(())
                            }
                            Input::Release { number } => {
                                lease.request(number, false);
                                Ok(())
                            }
                            Input::Wheel { take, .. }
                            | Input::Key { take, .. }
                            | Input::Text { take, .. }
                            | Input::Paste { take, .. } => {
                                lease.write(take).map(|_| ()).map_err(Refused::NotControlling)
                            }
                        });
                    }
                    // Nothing is attached yet, so there is no link that holds the input to read or
                    // press on.
                    Some(Command::LaunchSurface(reply)) => {
                        let _ = reply.send(Err(CommandError::stated(
                            ErrorCode::TerminalUnavailable,
                            STILL_OPENING,
                        )));
                    }
                    Some(Command::Launch(_, reply)) => {
                        let _ = reply.send(Err(CommandError::stated(
                            ErrorCode::TerminalUnavailable,
                            STILL_OPENING,
                        )));
                    }
                    // A close while the view opens cancels the open. The link goes with it, and a
                    // closed connection detaches whatever the attach had made.
                    Some(Command::Close) | None => return Cause::Closed,
                    Some(Command::Lose) => {
                        publish(TerminalViewState::Ended {
                            reason: "The connection to this session ended.".to_owned(),
                        });
                        return Cause::Lost;
                    }
                },
                opened = &mut opening => break opened,
            }
        }
    };
    let opened = match opened {
        Ok(opened) => opened,
        Err(failure) => {
            publish(TerminalViewState::Ended {
                reason: failure.reason,
            });
            return if failure.lost {
                Cause::Lost
            } else {
                Cause::Other
            };
        }
    };
    let networked = opened.link.session().transport().stream_opener().is_some();
    // A view that was granted no right to type takes no control: a take made while it opened is
    // refused before the page shows anything of it, and the view opens no input stream.
    if !opened
        .attached
        .attachment
        .granted
        .contains(&AttachmentCapability::Input)
    {
        lease.without_typing_right();
    }
    let mut view = View {
        link: opened.link,
        events: opened.events,
        networked,
        states_input_lane: opened.states_input_lane,
        lane: None,
        opening: false,
        no_stream: false,
        lane_events: None,
        lane_epoch: None,
        requests: FuturesUnordered::new(),
        keys: BTreeMap::new(),
        proven: Proven::default(),
        endings: Vec::new(),
        holds: BTreeMap::new(),
        next_launch: 0,
        lane_lost: None,
        target: opened.target,
        session_id,
        attachment: opened.attached.attachment,
        projection: Projection::new(),
        next_request: 0,
        window,
        lease,
        resubscription: None,
        serves_launch_surface: opened.serves_launch_surface,
        launch_reads: BTreeMap::new(),
        launches: BTreeMap::new(),
        replaced_stream: false,
        recoveries: 0,
        showing: false,
        held: false,
        drawn: None,
        told: 0,
        last: None,
        heard_in_flight: false,
        heard: VecDeque::new(),
        #[cfg(feature = "testing")]
        probe,
        publish: publish.clone(),
    };
    #[cfg(feature = "testing")]
    view.probe.publish_session(view.link.session());
    view.publish_state();
    if view.lease.has_typing_right() {
        view.open_lane();
    }
    let ended = view.serve(&mut commands).await;
    view.end_launches();
    if let Some(reason) = ended.reason {
        (view.publish)(TerminalViewState::Ended { reason });
    }
    view.finish(ended.detach).await;
    ended.cause
}

/// Opens the link, has the worker prove who it is, attaches and subscribes.
///
/// On a paired host the link is a connection of the view's own, the host opens it for the session
/// under the grant the screen runs under, and the host's own checks stand in for the worker's
/// stated build: it refuses an attach to a worker whose frames the grant cannot be held to.
async fn open(
    reach: &Reach<'_>,
    session_id: SessionId,
    dimensions: Dimensions,
) -> Result<Opened, OpenFailure> {
    let (link, mut events, target, serves_launch_surface, states_input_lane) = match reach {
        Reach::Local(locate) => open_local(locate, session_id).await?,
        Reach::Paired(dial, grant_id) => {
            let transport = dial.transport().await.map_err(not_opened)?;
            let (link, events, target) = open_over(transport, *grant_id, session_id).await?;
            (link, events, target, None, false)
        }
        #[cfg(feature = "testing")]
        Reach::Over(transport) => {
            let (link, events, target) = open_over(Arc::clone(transport), None, session_id).await?;
            (link, events, target, None, false)
        }
    };
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    // Able to take the input lease, which asking for this does not do: only the person's own take
    // does. The view's own profile, which the host has not qualified, so it shows the view a
    // viewport of the session and takes the view to send the ordinary encoding of keys. No geometry
    // claim, so opening a view never takes the session's size from anyone.
    requested.insert(AttachmentCapability::Input);
    let params = SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(dimensions),
        terminal_profile_id: Nullable::some(PROFILE.to_owned()),
        requested,
    };
    let answer = link
        .request(
            &mut events,
            link.mutate(Method::SessionAttach, target.clone(), params),
        )
        .await
        .map_err(|lost| OpenFailure::lost(&lost))?
        .map_err(|refusal| {
            OpenFailure::refused(format!(
                "The session refused this view: {}",
                refusal.message
            ))
        })?;
    let attached: SessionAttachResult = answer.to_typed().map_err(|error| {
        OpenFailure::refused(format!(
            "The session's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })?;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    // From the cursor the attachment was allocated at: the screen the subscription opens with is
    // the session as it is now, and nothing before it is replayed.
    let subscribe = EventsSubscribeParams {
        session_id,
        attachment_id: attached.attachment.attachment_id,
        streams,
        from_cursor: Nullable::some(attached.output_cursor),
    };
    link.request(&mut events, link.read(Method::EventsSubscribe, subscribe))
        .await
        .map_err(|lost| OpenFailure::lost(&lost))?
        .map_err(|refusal| {
            OpenFailure::refused(format!(
                "The session refused this view's screen: {}",
                refusal.message
            ))
        })?;
    Ok(Opened {
        link,
        events,
        target,
        attached,
        serves_launch_surface,
        states_input_lane,
    })
}

/// Reaches the worker on this machine by its descriptor and has it prove who it is.
async fn open_local(
    locate: &Locate,
    session_id: SessionId,
) -> Result<(Link, Events, ActionTarget, Option<bool>, bool), OpenFailure> {
    let paths = locate()?;
    // A descriptor is data on disk. Nothing is sent until the worker behind the endpoint has signed
    // a challenge only the descriptor's key could answer.
    let crate::worker::Reached {
        client,
        descriptor,
        build,
        capabilities,
    } = crate::worker::reach(&paths, session_id)
        .await
        .map_err(crate::worker::Unreached::words)?;
    // The worker has proved who it is, and it says what it is: the attach waits on its screens, so
    // a worker whose screens this view cannot read is refused before it is asked for anything.
    check_build(build.as_ref())?;
    let target = target(&descriptor);
    let serves = kr_protocol::ids::CapabilityId::new(kr_protocol::local::SHELL_LAUNCH_SURFACE_READ)
        .is_ok_and(|read| capabilities.contains(&read));
    let states_input_lane = kr_protocol::ids::CapabilityId::new(kr_protocol::local::INPUT_LANE)
        .is_ok_and(|lane| capabilities.contains(&lane));
    let transport = kr_client::ipc::IpcTransport::over(client).shared();
    let (link, events) = Link::over(transport, None).map_err(|lost| OpenFailure::lost(&lost))?;
    Ok((link, events, target, Some(serves), states_input_lane))
}

/// What a view's opening says of a connection that was not opened, by the cause and not by the code
/// of an error: the cause says whether the host was reached, had no room or refused, and whether
/// that is for now ([`Unopened::for_now`]), in which case the view is lost and the opening's link
/// asks the host again, and a refusal that is not is the host's decision about this view. A
/// connection that the host refused at its admission is lost, with the host's words as the reason.
fn not_opened(unopened: Unopened) -> OpenFailure {
    let for_now = unopened.for_now();
    match unopened {
        Unopened::Unreached(error) => OpenFailure {
            reason: format!(
                "The host could not be reached for this view: {}",
                error.message
            ),
            lost: true,
        },
        Unopened::NotAdmitted(words) => OpenFailure {
            reason: format!("No connection was made for this view: {words}"),
            lost: true,
        },
        Unopened::BudgetFull | Unopened::HostFull => OpenFailure {
            reason: format!(
                "No connection was made for this view: {}",
                unopened.into_error().message
            ),
            lost: true,
        },
        Unopened::Refused(asked, refusal) => {
            let reason = match asked.request() {
                Some(request) => format!(
                    "The host refused to {request} for this view: {}",
                    refusal.message
                ),
                None => format!("No connection was made for this view: {}", refusal.message),
            };
            if for_now {
                OpenFailure { reason, lost: true }
            } else {
                OpenFailure::refused(reason)
            }
        }
    }
}

/// Has a paired host open the session for the view on `transport`, a connection of the view's own,
/// under the share the screen runs under.
async fn open_over(
    transport: Arc<dyn kr_client::transport::ControlTransport>,
    grant_id: Option<GrantId>,
    session_id: SessionId,
) -> Result<(Link, Events, ActionTarget), OpenFailure> {
    use kr_protocol::session::{SessionOpenParams, SessionOpenResult};

    let (link, mut events) =
        Link::over(transport, grant_id).map_err(|lost| OpenFailure::lost(&lost))?;
    let opened = link
        .request(
            &mut events,
            link.read(
                Method::SessionOpen,
                SessionOpenParams {
                    session_id: Nullable::some(session_id),
                    grant_id: Nullable(grant_id),
                },
            ),
        )
        .await
        .map_err(|lost| OpenFailure::lost(&lost))?
        .map_err(|refusal| {
            // The refusal the session kept as the host's answer to the connection is told by its
            // cause, as a refusal of a first call on any connection is; any other is the refusal of
            // this request.
            let failed = ClientError::Host(refusal.clone());
            not_opened(
                Unopened::of_connection(link.session(), &failed).unwrap_or_else(|| {
                    Unopened::Refused(Asked::SessionOpen, CommandError::from(refusal))
                }),
            )
        })?;
    let opened: SessionOpenResult = opened.to_typed().map_err(|error| {
        OpenFailure::refused(format!(
            "The host's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })?;
    match opened {
        SessionOpenResult::InForce {
            session,
            environment_id,
            ..
        } => {
            let Some(summary) = session.0 else {
                return Err(OpenFailure::refused(
                    "The host opened a connection for no session.",
                ));
            };
            let target = ActionTarget {
                environment_id,
                session_id: Nullable::some(summary.session_id),
                session_epoch: Nullable::some(summary.session_epoch),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            };
            Ok((link, events, target))
        }
        SessionOpenResult::Ended { .. } => Err(OpenFailure::refused("This share has ended.")),
    }
}

/// Refuses a worker whose screens this build cannot be sure to read, before the session is asked
/// for anything.
///
/// A worker outlives an upgrade, so the application can meet a worker of an earlier build, or of a
/// later one. It reads a worker's screens when the worker states, in its answer to the hello, a
/// build whose protocol version shares this build's compatibility level
/// ([`kr_protocol::hello::PackageVersion::shares_frames_with`]). A worker that states no build is
/// of a build before that statement. Attaching to either of the others would wait on screens the
/// view cannot draw.
///
/// The refusal is an unsupported schema by kind, and the page is given words and not the code: they
/// name this build and the worker's, with both protocol versions where the worker states its own,
/// and say what to do.
fn check_build(stated: Option<&LocalBuild>) -> Result<(), String> {
    let worker = match stated {
        Some(build) if build.protocol_version.shares_frames_with(PACKAGE_VERSION) => {
            return Ok(());
        }
        Some(build) => format!(
            "runs on {} with protocol {}",
            build_name(&build.build_id),
            build.protocol_version
        ),
        None => "runs on a worker of an earlier build, which does not state its build or its \
                 protocol version"
            .to_owned(),
    };
    let ours = crate::connection::build_id().map_err(|error| error.message)?;
    Err(format!(
        "This session {worker}, and this application is {} with protocol {}: this application \
         cannot show a session whose worker speaks another protocol version. Close the session, \
         or open it with the application of the worker's build.",
        build_name(&ours),
        PACKAGE_VERSION
    ))
}

/// The longest build identifier a refusal names.
const BUILD_NAME_LIMIT: usize = 64;

/// What a build identifier says: the identifier when it is a program's name and a release, such as
/// `kr-worker/0.1.0`, and that it is not one otherwise. A worker states its own, so any other text
/// is replaced rather than repeated.
///
/// The name is lower-case letters, digits and dashes, starting with a letter; the release is
/// numbers separated by dots; the whole is at most [`BUILD_NAME_LIMIT`] bytes.
fn build_name(build_id: &BuildId) -> &str {
    let text = build_id.as_str();
    let named = text.len() <= BUILD_NAME_LIMIT
        && text.split_once('/').is_some_and(|(name, release)| {
            name.starts_with(|first: char| first.is_ascii_lowercase())
                && name.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
                && release.split('.').all(|number| {
                    !number.is_empty() && number.chars().all(|digit| digit.is_ascii_digit())
                })
        });
    if named {
        text
    } else {
        "[a build this application does not name]"
    }
}

/// What the host said to a call that failed, when the failure is the host's answer or says nothing
/// against the connection: the call is refused, and the view goes on. None when the failure is the
/// link's, which the reader's end then tells.
fn refusal_of(failed: &ClientError) -> Option<ProtocolError> {
    match failed {
        ClientError::Host(refusal) | ClientError::OutcomeUnknown { error: refusal, .. } => {
            Some(refusal.clone())
        }
        ClientError::Transport(_)
        | ClientError::Ipc(_)
        | ClientError::ConnectionEnded
        | ClientError::SubmissionUncertain { .. }
        | ClientError::Withheld => None,
        other => Some(ProtocolError::new(other.code(), other.to_string())),
    }
}

/// What the person is told when the lane takes no more typing.
const fn refused_words(refusal: InputRefusal) -> &'static str {
    match refusal {
        InputRefusal::Full => "too much input is waiting to be written",
        InputRefusal::NotNow => "too much input is waiting to be written for it to fit now",
        InputRefusal::TooLarge => "it is longer than one input can carry",
        InputRefusal::Empty => "there is nothing to write",
        InputRefusal::Ending | InputRefusal::Over(_) | InputRefusal::NoEpoch => {
            "this view's input stream takes nothing more under this control"
        }
        InputRefusal::LaunchWaiting | InputRefusal::EpochNotNew | InputRefusal::NotLocal => {
            "this view's input stream could not take it"
        }
    }
}

/// What a link that failed part way says.
fn lost_words(lost: &Lost) -> String {
    format!("The connection to this session ended: {}", lost.0)
}

/// The action target that names the worker's session.
fn target(descriptor: &WorkerDescriptor) -> ActionTarget {
    ActionTarget {
        environment_id: descriptor.environment_id,
        session_id: Nullable::some(descriptor.session_id),
        session_epoch: Nullable::some(descriptor.session_epoch),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// How the loop ended.
struct Ending {
    /// Why, for the page, or nothing when the page itself closed the view.
    reason: Option<String>,
    /// What kind of end it was, for whoever opened the view.
    cause: Cause,
    /// Whether the attachment still stands on a link that still stands, so the view detaches it
    /// before the link closes.
    detach: bool,
}

impl Ending {
    /// The page closed the view.
    const CLOSED: Self = Self {
        reason: None,
        cause: Cause::Closed,
        detach: true,
    };

    /// The view ends, for `reason`, with its attachment and its link still there.
    fn ended(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
            cause: Cause::Other,
            detach: true,
        }
    }

    /// The attachment is already over, for `reason`: the session closed, or it was detached.
    fn over(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
            cause: Cause::Other,
            detach: false,
        }
    }

    /// The link is gone, and the attachment with it. `reason` says why when this device ended it.
    fn lost(reason: Option<String>) -> Self {
        Self {
            cause: Cause::Lost,
            ..Self::over(
                reason.unwrap_or_else(|| "The connection to this session ended.".to_owned()),
            )
        }
    }
}

/// A launch surface read waiting for its answer, and how far it has come.
struct LaunchRead {
    stage: LaunchReadStage,
    reply: Reply<LaunchSurfaceAnswer>,
}

/// What a launch surface read does with an answer: say what it came to, or ask the next question.
enum Step {
    Say(Result<LaunchSurfaceAnswer, CommandError>),
    Ask(LaunchReadStage),
}

/// Which of the questions of a launch surface read is waiting for its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchReadStage {
    /// The read itself.
    Asked,
    /// `session.read`, which tells a host that does not list the read from a grant that lost its
    /// right.
    Probed,
    /// The read, asked once more after `session.read` was answered.
    AskedAgain,
}

/// What a launch surface read does with the answer to the question it had asked.
///
/// A host that does not list the read refuses it as it refuses any method it does not list,
/// `PERMISSION_DENIED`, and a grant that has lost its right is refused the same way. The two are
/// told apart only where the link does not say whether the worker serves the read (`serves` is
/// none, as on a paired host's daemon), by what the same right reads, `session.read`: where that is
/// refused too the refusal is the grant's and is the answer; where it is answered the read is asked
/// once more, and a second refusal means the host does not serve it. A worker that stated that it
/// serves the read is not probed: its refusal is the grant's. A worker that lists the read and is
/// of a release that does not serve it refuses it as an unsupported capability.
fn launch_read_step(stage: LaunchReadStage, serves: Option<bool>, outcome: Outcome) -> Step {
    let not_served = |refusal: &ProtocolError| {
        matches!(
            refusal.code,
            ErrorCode::PermissionDenied | ErrorCode::UnsupportedCapability
        )
    };
    match (stage, outcome) {
        (LaunchReadStage::Probed, Outcome::Ok(value)) => {
            match value.to_typed::<SessionReadResult>() {
                Ok(_) => Step::Ask(LaunchReadStage::AskedAgain),
                Err(error) => Step::Say(Err(CommandError::local_failure(format!(
                    "The session's answer to the check of the grant could not be read: {}",
                    Shown::cbor(&error)
                )))),
            }
        }
        (LaunchReadStage::Probed, Outcome::Error(refusal)) => {
            Step::Say(Err(CommandError::from(refusal)))
        }
        (LaunchReadStage::Asked | LaunchReadStage::AskedAgain, Outcome::Ok(value)) => Step::Say(
            value
                .to_typed::<ShellLaunchSurfaceResult>()
                .map(|surface| LaunchSurfaceAnswer::Served { surface })
                .map_err(|error| {
                    CommandError::local_failure(format!(
                        "The session's launch surface could not be read: {}",
                        Shown::cbor(&error)
                    ))
                }),
        ),
        (LaunchReadStage::Asked, Outcome::Error(refusal))
            if refusal.code == ErrorCode::PermissionDenied && serves.is_none() =>
        {
            Step::Ask(LaunchReadStage::Probed)
        }
        (LaunchReadStage::AskedAgain, Outcome::Error(refusal)) if not_served(&refusal) => {
            Step::Say(Ok(LaunchSurfaceAnswer::NotServed))
        }
        (LaunchReadStage::Asked, Outcome::Error(refusal))
            if refusal.code == ErrorCode::UnsupportedCapability =>
        {
            Step::Say(Ok(LaunchSurfaceAnswer::NotServed))
        }
        (_, Outcome::Error(refusal)) => Step::Say(Err(CommandError::from(refusal))),
    }
}

/// What a call the loop owns came to.
enum Completed {
    /// A call to the session, with its answer or why it failed.
    Call(Answered),
    /// The opening of the input lane, which on a paired host waits for the host's word.
    Lane(Result<InputLane, ClientError>),
}

/// A call of the loop's set: the view's number for it, and what it came to.
type Done = (RequestId, Completed);

/// An ending that waits for the lane to say the host has the typing before it, on a link whose
/// typing has a stream of its own.
struct Barred {
    tag: RequestId,
    barrier: InputBarrier,
    /// Makes the ending's call for the barrier it names: the one it took where the lane reached it,
    /// and where the host did not take the typing before it, what the host did take.
    call: Box<dyn FnOnce(InputBarrier) -> link::Call + Send>,
}

/// What an ending came to when it was asked to start.
enum Started {
    /// Its call is under the view's number.
    Sent(RequestId),
    /// A launch that was not sent, and what the page is told.
    NotStarted(&'static str),
}

/// How many frames of each epoch the host has accepted, as the lane's words told, by the epoch's
/// number: the typing that an ending can name when the host did not take all that was admitted.
#[derive(Default)]
struct Proven(BTreeMap<u64, u64>);

impl Proven {
    /// The host accepted the frames of `epoch` up to the sequence `through`.
    fn accepted(&mut self, epoch: u64, through: u64) {
        let count = self.0.entry(epoch).or_default();
        *count = (*count).max(through.saturating_add(1));
    }

    /// The most frames of `epoch` the host accepted, none where it said nothing.
    fn prefix(&self, epoch: u64) -> u64 {
        self.0.get(&epoch).copied().unwrap_or(0)
    }
}

/// One open, attached view.
struct View {
    link: Link,
    /// The session's notifications, which this view alone consumes.
    events: Events,
    /// Whether the typing has a stream of its own, as on a paired host that opens one, and an
    /// ending then takes the lane's mark; otherwise the typing is requests on the connection and an
    /// ending is queued behind it.
    networked: bool,
    /// Whether the worker stated that it takes typing on the input lane.
    states_input_lane: bool,
    /// The session's input lane, once it is open.
    lane: Option<InputLane>,
    /// Whether the lane is being opened: a take that finds no lane joins the opening.
    opening: bool,
    /// Whether the host stated, by its typed code, that it takes no input stream: it takes none for
    /// the view's life, and a take acquires with no lane.
    no_stream: bool,
    lane_events: Option<InputEvents>,
    /// The lease epoch the lane has begun.
    lane_epoch: Option<InputLeaseEpoch>,
    /// The calls the view has started, which the loop polls before it takes anything else. A call
    /// is never dropped before it completes while the loop runs.
    requests: FuturesUnordered<BoxFuture<'static, Done>>,
    /// Every key the lane has taken and has not said the host settled, in every epoch, by its epoch
    /// and number in it. The lane settles a key when it says the host accepted or refused it. The
    /// value is the view's number for the key, which the lease knows it by, until the lease was
    /// told that the key's epoch is over; the entry itself stays until a later acceptance covers it.
    /// Taking the number out bounds the lease's own record of writes and nothing else.
    keys: BTreeMap<(u64, u64), Option<RequestId>>,
    /// What the host accepted of each epoch.
    proven: Proven,
    /// The endings that wait for the host to have the typing before them.
    endings: Vec<Barred>,
    /// The launches whose later typing the lane holds, by the view's number for the launch, and the
    /// launch's number for the lane.
    holds: BTreeMap<RequestId, u32>,
    next_launch: u32,
    /// Why the input lane could not be opened or ended, when it did.
    lane_lost: Option<String>,
    target: ActionTarget,
    session_id: SessionId,
    attachment: AttachmentSummary,
    projection: Projection,
    /// The last number the view gave one of its calls.
    next_request: u64,
    /// Where the window is, and the reports it owes.
    window: WindowReports,
    /// Whether the view controls the program, and what it owes the session for it.
    lease: Lease,
    /// The resubscription waiting for its answer.
    resubscription: Option<RequestId>,
    /// Whether the worker stated that it serves the launch surface, when one answered the hello.
    serves_launch_surface: Option<bool>,
    /// The launch surface reads waiting for their answers, and how far each has come.
    launch_reads: BTreeMap<RequestId, LaunchRead>,
    /// The launches waiting for the session's answer, and where each says it.
    launches: BTreeMap<RequestId, Reply<ShellLaunchResult>>,
    /// Whether the stream a resubscription replaced is still being dropped: until the new stream's
    /// first notification, at sequence 0, everything of the old one that still arrives is stale.
    replaced_stream: bool,
    /// Recoveries since the last complete screen.
    recoveries: u32,
    /// Whether the page was last told of a screen.
    showing: bool,
    /// Whether the screen the view holds waits for its report's answer before the page is told.
    held: bool,
    /// The revision of the window the screen the page draws was drawn for.
    drawn: Option<u64>,
    /// The newest of its moves the page was last told is settled.
    told: u64,
    /// The state the page was last sent.
    last: Option<TerminalViewState>,
    /// Whether the session said anything since the report in flight was sent.
    heard_in_flight: bool,
    /// What the loop has heard and not yet served, in the order the host sent it.
    heard: VecDeque<Heard>,
    /// The most items the queue has held at one time, which a test reads to see that the queue is
    /// bounded.
    /// What a test reads of the view while it runs.
    #[cfg(feature = "testing")]
    probe: Probe,
    publish: Publish,
}

/// What the loop has heard and not yet served.
enum Heard {
    /// A notification of the session, its end, or none when its channel closed.
    Event(Option<Ordered>),
    /// A call that completed.
    Done(Done),
    /// An event of the lane, or none when the lane's events ended.
    Lane(Option<InputEvent>),
}

/// What the loop's wait ended with.
enum Woke {
    Event(Option<Ordered>),
    Done(Done),
    Lane(Option<InputEvent>),
    Command(Option<Command>),
}

/// Waits for the next of the session's notifications, a call that completed, the lane's event or
/// the page's command. The loop waits only when it has nothing heard and not served.
async fn wake(
    events: &mut Events,
    requests: &mut FuturesUnordered<BoxFuture<'static, Done>>,
    lane_events: &mut Option<InputEvents>,
    commands: &mut UnboundedReceiver<Command>,
) -> Woke {
    tokio::select! {
        biased;
        item = events.recv() => Woke::Event(item),
        Some(done) = requests.next() => Woke::Done(done),
        event = next_lane_event(lane_events) => Woke::Lane(event),
        command = commands.recv() => Woke::Command(command),
    }
}

/// The lane's next event, or never when there is no lane to hear from.
async fn next_lane_event(events: &mut Option<InputEvents>) -> Option<InputEvent> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// Settles the action of an ending that the view composed and sent itself, once the host's word on
/// it is definite: a result, or a refusal that the protocol sorts outside the transient and the
/// unknown-outcome kinds. The session keeps such an action as unresolved until the view says what
/// the answer came to, and a view that never did would reach the bound on unresolved actions and
/// then have every later release, launch and detach refused before any byte went. An answer that
/// is not definite leaves the action as the session's rule has it: asked after, or sent again.
async fn settle_when_definite(
    session: &Session,
    action_id: ActionId,
    answered: &Result<Settled, ClientError>,
) {
    let definite = match answered {
        Ok(Settled::Result(_)) => true,
        Ok(Settled::Receipt(_)) => false,
        Err(ClientError::Host(refusal)) => HostWord::of_refusal(refusal).is_definite(),
        Err(ClientError::ResyncRequired) => true,
        Err(_) => false,
    };
    if definite {
        session.settle(action_id).await;
    }
}

/// Waits until the lane says the host has the typing before `barrier`, or will not have it, or the
/// lane ended, and says whether the host has it. What the host accepts meanwhile is counted in
/// `proven`.
async fn barrier_passed(
    events: &mut InputEvents,
    barrier: &InputBarrier,
    proven: &mut Proven,
) -> bool {
    while let Some(event) = events.recv().await {
        match event {
            InputEvent::Accepted { epoch, through, .. } => {
                proven.accepted(epoch.get(), through.get());
            }
            InputEvent::Reached(reached) if &reached == barrier => return true,
            InputEvent::NotReached {
                barrier: missed, ..
            } if &missed == barrier => return false,
            InputEvent::Ended { .. } => return false,
            _ => {}
        }
    }
    false
}

impl View {
    /// The end of a view whose link is gone, in the account's words when this device ended the
    /// link because the account it was opened under left.
    fn lost(&self) -> Ending {
        Ending::lost(self.link.ended_by_this_device())
    }

    /// Serves what the session says, what the calls the view started came to, the lane's events and
    /// the page's commands until the view ends.
    ///
    /// What the loop has heard waits in its own queue, in the order the host sent it, and the loop
    /// serves it one item a turn and takes one command a turn, so a flood of output holds back
    /// neither an answer nor the page. It looks at the calls and at the lane only when the queue is
    /// empty: whatever completed is taken, and what the session's channel holds at that moment goes
    /// into the queue before it. The queue then holds at most the channel's size and what was ready
    /// in one look, and the channel stays what pushes back on the host. A notification that came
    /// before an answer on the wire is in the channel when the answer's call completes, since the
    /// session's reader hands a notification on before it reads the next frame, so it is served
    /// before that answer.
    async fn serve(&mut self, commands: &mut UnboundedReceiver<Command>) -> Ending {
        loop {
            // What goes next is asked after every event, so nothing owed waits on an event that
            // does not come.
            if let Some(ended) = self.dispatch().await {
                return ended;
            }
            if self.heard.is_empty() {
                self.look();
            }
            if let Some(heard) = self.heard.pop_front() {
                if let Some(ended) = self.serve_heard(heard).await {
                    return ended;
                }
                if let Some(ended) = self.dispatch().await {
                    return ended;
                }
                let command = match commands.try_recv() {
                    Ok(command) => Some(command),
                    Err(TryRecvError::Empty) => continue,
                    Err(TryRecvError::Disconnected) => None,
                };
                if let Some(ended) = self.serve_command(command).await {
                    return ended;
                }
                continue;
            }
            let woke = wake(
                &mut self.events,
                &mut self.requests,
                &mut self.lane_events,
                commands,
            )
            .await;
            match woke {
                Woke::Event(item) => self.queue([Heard::Event(item)]),
                Woke::Done(done) => {
                    self.take_what_the_session_said();
                    self.queue([Heard::Done(done)]);
                }
                Woke::Lane(event) => {
                    self.take_what_the_session_said();
                    self.queue([Heard::Lane(event)]);
                }
                Woke::Command(command) => {
                    if let Some(ended) = self.serve_command(command).await {
                        return ended;
                    }
                }
            }
        }
    }

    /// Takes every call that completed and every event the lane holds, without waiting, and puts
    /// them in the queue behind what the session's channel holds.
    fn look(&mut self) {
        let mut taken = Vec::new();
        while let Some(Some(done)) = self.requests.next().now_or_never() {
            taken.push(Heard::Done(done));
        }
        if let Some(events) = self.lane_events.as_mut() {
            while let Some(event) = events.try_recv() {
                taken.push(Heard::Lane(Some(event)));
            }
        }
        if !taken.is_empty() {
            self.take_what_the_session_said();
            self.queue(taken);
        }
    }

    /// Moves what the session's channel holds now into the queue, without waiting, so that it is
    /// served before the answer or the lane event that was taken after it.
    fn take_what_the_session_said(&mut self) {
        let ready = self.events.ready();
        self.queue(ready.into_iter().map(Heard::Event));
    }

    /// Puts `heard` at the end of the queue.
    fn queue(&mut self, heard: impl IntoIterator<Item = Heard>) {
        self.heard.extend(heard);
        #[cfg(feature = "testing")]
        self.probe
            .queue_peak
            .fetch_max(self.heard.len(), Ordering::Relaxed);
    }

    /// Serves one item of the queue.
    async fn serve_heard(&mut self, heard: Heard) -> Option<Ending> {
        // Whatever the session says lets a size it did not take for now go again.
        let said = match &heard {
            Heard::Done((_, Completed::Call(Ok(_))))
            | Heard::Event(Some(Ordered::Notification(_))) => true,
            Heard::Done((_, Completed::Call(Err(failed)))) => refusal_of(failed).is_some(),
            _ => false,
        };
        if said {
            self.window.heard();
        }
        if matches!(heard, Heard::Event(Some(Ordered::Notification(_)))) {
            self.heard_in_flight = true;
        }
        match heard {
            Heard::Event(Some(Ordered::Notification(notification))) => {
                self.notification(notification)
            }
            Heard::Event(Some(Ordered::Ended(_)) | None) => Some(self.lost()),
            Heard::Lane(Some(event)) => self.lane_event(event),
            Heard::Lane(None) => {
                self.lane_events = None;
                None
            }
            Heard::Done((tag, done)) => self.completed(tag, done).await,
        }
    }

    /// Serves one command of the page, or the end of the page's channel.
    async fn serve_command(&mut self, command: Option<Command>) -> Option<Ending> {
        match command {
            Some(Command::Resize(size)) => {
                self.window.measured(size);
                None
            }
            Some(Command::Move(asked)) => {
                self.window.take(asked);
                None
            }
            Some(Command::Input(input, taken)) => self.input(input, taken),
            Some(Command::LaunchSurface(reply)) => self.launch_surface(reply),
            Some(Command::Launch(press, reply)) => self.launch(press, reply).await,
            Some(Command::Lose) => Some(self.lost()),
            Some(Command::Close) | None => Some(Ending::CLOSED),
        }
    }

    fn notification(&mut self, notification: Notification) -> Option<Ending> {
        let event_type = notification.event_type.as_str();
        // Neither is ever dropped: whichever stream carries them, the attachment is over.
        if event_type == SESSION_CLOSED_EVENT {
            return Some(Ending::over("This session has closed."));
        }
        if event_type == DETACHED_EVENT {
            return Some(Ending::over("This view was detached from the session."));
        }
        if self.replaced_stream {
            // Every delivery on this connection starts its sequence at 0, and a recovery begins
            // only after a notification of the stream it replaces has been read. So the first
            // notification at 0 is the new stream's, whatever it carries and whether or not it
            // decodes; anything before it is the old stream's, and is covered by the new screen.
            if notification.sequence.get() != 0 {
                return None;
            }
            self.replaced_stream = false;
        }
        if event_type == RESYNC_EVENT {
            return self.recover();
        }
        if !is_projection_event(event_type) {
            // The output of a direct presentation and a gap's notice: neither draws anything in a
            // projected view, and neither is sent on to the page.
            return None;
        }
        let Some(event) = decode(event_type, &notification.payload) else {
            return self.recover();
        };
        match self.projection.apply(event) {
            // A reset waits for the snapshot that follows it. Asking again would loop, because
            // every subscription opens with a reset of its own.
            Applied::Reset(_) => {
                self.held = false;
                self.waiting();
                None
            }
            // Nothing is drawn from a snapshot until its last page.
            Applied::Installing => None,
            Applied::Installed => {
                self.recoveries = 0;
                // The screen settles what it can first, and only then is it weighed whether the
                // page may draw it yet.
                if let Some(screen) = self.projection.screen() {
                    self.window.installed(screen);
                    self.held = self.window.holds(screen.window_revision);
                }
                self.screen_changed();
                None
            }
            Applied::Updated(_) => {
                self.screen_changed();
                None
            }
            Applied::Refused(_) => self.recover(),
        }
    }

    /// A call of the loop's set completed: its answer is the one the view's number names.
    async fn completed(&mut self, tag: RequestId, done: Completed) -> Option<Ending> {
        let answered = match done {
            Completed::Lane(opened) => return self.lane_opened(opened),
            Completed::Call(answered) => answered,
        };
        // A launch's hold on the later typing ends with the host's definite word on it: a result, or
        // any refusal that is not the library's "unknown", a transient one and the host's own among
        // them. An unknown word keeps the hold, because the launch may still be before its
        // reservation and typing released now could reach the program first; the lane ends it at the
        // launch's marker, whenever that comes, and at the end of its epoch or its stream. An older
        // launch's word never ends a newer launch's hold: the lane keeps a hold by its launch.
        if let Some(launch) = self.holds.remove(&tag) {
            let unknown = matches!(
                &answered,
                Err(failed) if refusal_of(failed)
                    .is_some_and(|refusal| HostWord::of_refusal(&refusal) == HostWord::Unknown)
            );
            if !unknown && let Some(lane) = &self.lane {
                lane.release_hold(launch);
            }
        }
        let outcome = match answered {
            Ok(value) => Outcome::Ok(value),
            Err(ClientError::Cbor(_)) => {
                return Some(Ending::ended("This view's request could not be written."));
            }
            Err(failed) => match refusal_of(&failed) {
                Some(refusal) => Outcome::Error(refusal),
                // The link failed under the call: what the reader says of the end, and what arrived
                // before it, still counts.
                None => return Some(self.link_failed().await),
            },
        };
        self.response(tag, outcome)
    }

    fn response(&mut self, request_id: RequestId, outcome: Outcome) -> Option<Ending> {
        if self.launch_reads.contains_key(&request_id) {
            return self.launch_surface_answered(request_id, outcome);
        }
        if let Some(reply) = self.launches.remove(&request_id) {
            let _ = reply.send(match outcome {
                Outcome::Ok(value) => value.to_typed::<ShellLaunchResult>().map_err(|error| {
                    CommandError::local_failure(format!(
                        "The session's answer to the launch could not be read: {}",
                        Shown::cbor(&error)
                    ))
                }),
                Outcome::Error(refusal) => Err(CommandError::from(refusal)),
            });
            return None;
        }
        if self.lease.owns(request_id) {
            let outcome = match outcome {
                Outcome::Ok(value) => Ok(value),
                Outcome::Error(refusal) => Err(refusal),
            };
            let held = self.lease.held_epoch();
            let changed = self.lease.answered(request_id, outcome);
            self.sync_epoch();
            // A take the session granted just before the program changed to a form the view does
            // not produce ends as its answer arrives, before the page is told it controls anything.
            let ended = !self.keyboard_supplied() && self.lease.unsupported();
            // A take the session granted after the view's input stream ended holds a lease that
            // nothing can be typed under, and a host that takes a stream will not take the typing
            // without one: control ends as the answer arrives, and the epoch is given back.
            let ended_before = self.lane.is_none()
                && !self.no_stream
                && self.lease.held_epoch() != held
                && self.lease.stream_ended_before_the_answer();
            if changed || ended || ended_before {
                self.control_changed();
            }
            return None;
        }
        if self.window.is_in_flight(request_id) {
            // A definite refusal settles the report and changes nothing; an acceptance settles it
            // once a screen naming its revision has arrived, whichever came first. A refusal for
            // now, or an answer that cannot say what became of the report, settles no size: it is
            // owed again. A screen that waited for this answer is drawn now, with what the answer
            // settled.
            let answer = match outcome {
                Outcome::Ok(value) => match value.to_typed::<AttachmentViewportResult>() {
                    Ok(result) => {
                        // The page shows the presentation and its reason from this summary, and
                        // the report may have changed both: the answer says what they are now.
                        self.attachment.presentation = Nullable::some(result.presentation);
                        self.attachment.presentation_reason = result.presentation_reason.0;
                        Answer::Accepted {
                            window_revision: result.window_revision.get(),
                        }
                    }
                    Err(_) => Answer::Refused,
                },
                Outcome::Error(refusal) if HostWord::of(refusal.code).is_definite() => {
                    Answer::Refused
                }
                Outcome::Error(_) => Answer::NotSettled,
            };
            self.window.answered(answer);
            // A notification and an answer reach the loop by two paths, and the host may have sent
            // the notification after the answer: a word heard while the report was in flight is
            // taken for the word that lets a size the session did not take for now go again.
            if self.heard_in_flight {
                self.window.heard();
            }
            if self.held {
                self.held = false;
                self.show();
            } else {
                self.tell();
            }
            return None;
        }
        if self.resubscription == Some(request_id) {
            self.resubscription = None;
            if let Outcome::Error(refusal) = outcome {
                // The recovery failed while the connection stays open: nothing will ever bring
                // this view a screen again.
                return Some(Ending::ended(format!(
                    "The session refused this view's screen: {}",
                    refusal.message
                )));
            }
        }
        None
    }

    /// Discards the screen and asks the session for a fresh one on this link, once.
    fn recover(&mut self) -> Option<Ending> {
        if self.recoveries >= RECOVERIES {
            return Some(Ending::ended("The session's screen could not be read."));
        }
        self.recoveries += 1;
        self.projection.discard();
        self.held = false;
        self.window.recovering();
        self.waiting();
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        let params = EventsSubscribeParams {
            session_id: self.session_id,
            attachment_id: self.attachment.attachment_id,
            streams,
            from_cursor: Nullable::null(),
        };
        self.resubscription = Some(self.read(Method::EventsSubscribe, params));
        self.replaced_stream = true;
        None
    }

    /// Sends the report the window owes now, if any, and tells the page of the moves that settled
    /// without one.
    async fn dispatch(&mut self) -> Option<Ending> {
        if let Some(sending) = self.window.next(self.projection.screen()) {
            let params = AttachmentViewportParams {
                attachment_id: self.attachment.attachment_id,
                dimensions: sending.dimensions,
                position: Nullable(sending.position),
                column: U64::new(sending.column),
            };
            let request_id = self.mutation(Method::AttachmentViewport, params);
            self.window.sent(request_id);
            self.heard_in_flight = false;
        }
        while let Some(owed) = self.lease.owed() {
            let sent = match owed {
                Owed::Acquire => {
                    // A take that finds no lane opens it first, and acquires once it is open, so
                    // that no key is taken before there is a stream to write it on; a take during
                    // an opening joins it. A host that takes no stream is acquired from with none.
                    if self.lane.is_none() && !self.no_stream {
                        if !self.opening {
                            self.open_lane();
                        }
                        break;
                    }
                    // An immediate takeover: whoever holds the lease loses it, without being asked.
                    let params = InputAcquireParams {
                        session_id: self.session_id,
                        attachment_id: self.attachment.attachment_id,
                        expected_epoch: Nullable::null(),
                    };
                    self.mutation(Method::InputAcquire, params)
                }
                Owed::Release(epoch) => {
                    let session_id = self.session_id;
                    let attachment_id = self.attachment.attachment_id;
                    let ended = self
                        .ending(
                            Method::InputRelease,
                            Some(epoch),
                            None,
                            move |after_input| InputReleaseParams {
                                session_id,
                                attachment_id,
                                epoch,
                                after_input,
                                fenced_report: false,
                            },
                        )
                        .await;
                    match ended {
                        Ok(Started::Sent(request_id)) => request_id,
                        Ok(Started::NotStarted(_)) => continue,
                        Err(ended) => return Some(ended),
                    }
                }
                // The session had not taken all the typing before the release: it goes once more,
                // naming no position, which the session cannot refuse for the typing.
                Owed::ReleaseAgain(epoch) => self.mutation(
                    Method::InputRelease,
                    InputReleaseParams {
                        session_id: self.session_id,
                        attachment_id: self.attachment.attachment_id,
                        epoch,
                        after_input: None,
                        fenced_report: false,
                    },
                ),
            };
            self.lease.sent(owed, sent);
        }
        self.tell();
        None
    }

    /// Takes the person's `input`: a change of control, or a wheel turn or keys, written only while
    /// the view controls the program under the take they name. Says on `taken` whether it took it,
    /// and returns how the loop ended when writing it lost the link.
    fn input(&mut self, input: Input, taken: Taken) -> Option<Ending> {
        match input {
            Input::Take { number } => {
                if self.lease.request(number, true) {
                    self.control_changed();
                }
                let _ = taken.send(Ok(()));
                None
            }
            Input::Release { number } => {
                if self.lease.request(number, false) {
                    self.control_changed();
                }
                let _ = taken.send(Ok(()));
                None
            }
            Input::Wheel {
                take,
                column,
                line,
                turns,
                shift,
                alt,
                control,
            } => {
                if !self.lease.controls(take) {
                    let _ = taken.send(
                        self.lease
                            .write(take)
                            .map(|_| ())
                            .map_err(Refused::NotControlling),
                    );
                    return None;
                }
                // Measured against the newest screen the view holds: the cell and the modes are the
                // session's as they now stand. A turn that reaches no program is no error.
                let modifiers = Modifiers {
                    shift,
                    alt,
                    control,
                    superkey: false,
                };
                let Some(reports) = self
                    .projection
                    .screen()
                    .and_then(|screen| wheel_reports(screen, column, line, turns, modifiers))
                else {
                    let _ = taken.send(Ok(()));
                    return None;
                };
                self.write_input(take, reports, taken)
            }
            Input::Key { take, .. } => {
                let (typed, action) = input.typed_key().expect("a key input names a key");
                self.key(take, &typed, action, taken)
            }
            Input::Text { take, text } => {
                // Text is its UTF-8 in every encoding the view produces; the program's keyboard is
                // read only to know the view may write at all.
                if let Err(refused) = self.keyboard(take, "That text") {
                    let _ = taken.send(Err(refused));
                    return None;
                }
                self.write_or_nothing(take, text.into_bytes(), taken)
            }
            Input::Paste { take, text } => {
                let keyboard = match self.keyboard(take, "That paste") {
                    Ok(keyboard) => keyboard,
                    Err(refused) => {
                        let _ = taken.send(Err(refused));
                        return None;
                    }
                };
                let bytes = kr_keys::paste(text.as_str(), keyboard.bracketed);
                if bytes.is_empty() {
                    let _ = taken.send(Ok(()));
                    return None;
                }
                self.write_paste(take, &bytes, taken)
            }
        }
    }

    /// Takes one of the person's keys: spelled in the encoding the program reads, and written only
    /// while the view controls the program under the take it names. A release is spelled from the
    /// press it ends, which the view recorded as it wrote it, and only where that press's encoding
    /// reports releases.
    fn key(
        &mut self,
        take: u64,
        typed: &TypedKey,
        action: KeyAction,
        taken: Taken,
    ) -> Option<Ending> {
        let keyboard = match self.keyboard(take, "That key") {
            Ok(keyboard) => keyboard,
            Err(refused) => {
                let _ = taken.send(Err(refused));
                return None;
            }
        };
        let spelled = match action {
            KeyAction::Press | KeyAction::Repeat => {
                let kind = if action == KeyAction::Press {
                    KeyEventKind::Press
                } else {
                    KeyEventKind::Repeat
                };
                typed.event(kind).and_then(|event| {
                    let bytes = kr_keys::key(event, keyboard.encoding)?;
                    if kind == KeyEventKind::Press {
                        self.lease.pressed(
                            take,
                            typed.identity(),
                            Pressed {
                                event,
                                reported: kr_keys::release_reported(event, keyboard.encoding),
                            },
                        );
                    }
                    Ok(bytes)
                })
            }
            KeyAction::Release => match self.lease.released(take, &typed.identity()) {
                Some(pressed) if pressed.reported => kr_keys::release(
                    pressed.event,
                    typed.modifiers,
                    typed.locks,
                    keyboard.encoding,
                ),
                // A release of a press that went as text, or that this view never wrote, is
                // nothing.
                _ => Ok(Vec::new()),
            },
        };
        match spelled {
            Ok(bytes) => self.write_or_nothing(take, bytes, taken),
            Err(unsupported) => {
                let _ = taken.send(Err(Refused::Unsent(keys::unsent("That key", unsupported))));
                None
            }
        }
    }

    /// What the program reads keys in, for an input made under `take` that `what` names, or why
    /// the input may not go: the view does not control the program under that take; it holds no
    /// screen of the session to read the program's keyboard from, which keeps control; or the
    /// screen says the program reads a form the view does not produce, which ends control.
    fn keyboard(&mut self, take: u64, what: &str) -> Result<Keyboard, Refused> {
        if !self.lease.controls(take) {
            return Err(Refused::NotControlling(
                self.lease.write(take).err().unwrap_or_default(),
            ));
        }
        let Some(screen) = self.projection.screen() else {
            return Err(Refused::Unsent(keys::unsent(what, keys::NO_SCREEN)));
        };
        let keyboard = Keyboard::of(screen);
        if !keyboard.supplied() {
            self.follow_the_keyboard();
            return Err(Refused::NotControlling(
                self.lease.control().ended.unwrap_or_default(),
            ));
        }
        Ok(keyboard)
    }

    /// Writes `bytes` under the take `take`, or answers at once when there is nothing to write:
    /// nothing takes a number in the view's input stream unless it is written.
    fn write_or_nothing(&mut self, take: u64, bytes: Vec<u8>, taken: Taken) -> Option<Ending> {
        if bytes.is_empty() {
            let _ = taken.send(Ok(()));
            return None;
        }
        self.write_input(take, bytes, taken)
    }

    /// Tells the page of the screen the view now holds, unless it waits for its report's answer.
    /// Control that screen ends goes first, so the page is never told of such a screen with the view
    /// in control: the screen and the end go in one state, or the end alone while the screen waits.
    fn screen_changed(&mut self) {
        let ended = !self.keyboard_supplied() && self.lease.unsupported();
        if !self.held {
            self.show();
        } else if ended {
            self.control_changed();
        }
    }

    /// Ends control at once when the screen the view holds says the program reads keys in a form
    /// the view does not produce: section 8's explicit end of an incompatible lease, rather than a
    /// key written in an encoding the view only advertised. The session has ended the lease on its
    /// side as the program changed; the view gives back the epoch it held, once.
    fn follow_the_keyboard(&mut self) {
        if !self.keyboard_supplied() && self.lease.unsupported() {
            self.control_changed();
        }
    }

    /// Whether the view produces the form the program reads keys in, by the screen it holds. With
    /// no screen nothing says otherwise yet, and the next screen is read as it comes.
    fn keyboard_supplied(&self) -> bool {
        self.projection
            .screen()
            .is_none_or(|screen| Keyboard::of(screen).supplied())
    }

    /// Writes `bytes` to the program under the lease the view holds for the page's take `take`.
    ///
    /// The page is told the input is taken as soon as the lane has admitted it and given it its
    /// place in the stream, before it is written: the write waits on the link, and the page's call
    /// never waits on it.
    fn write_input(&mut self, take: u64, bytes: Vec<u8>, taken: Taken) -> Option<Ending> {
        self.admit(
            take,
            |lane| lane.try_send(&bytes).map(|writing| vec![writing]),
            taken,
        )
    }

    /// Writes a paste to the program under the lease the view holds for the take `take`: the lane
    /// cuts it into frames, and admits all of them or none.
    fn write_paste(&mut self, take: u64, bytes: &[u8], taken: Taken) -> Option<Ending> {
        self.admit(take, |lane| lane.try_send_paste(bytes), taken)
    }

    /// Has the lane admit what `send` gives it, and says on `taken` whether it did.
    fn admit(
        &mut self,
        take: u64,
        send: impl FnOnce(&InputLane) -> Result<Vec<kr_client::input::Writing>, InputRefusal>,
        taken: Taken,
    ) -> Option<Ending> {
        if !self.lease.controls(take) {
            let _ = taken.send(Err(Refused::NotControlling(
                self.lease.write(take).err().unwrap_or_default(),
            )));
            return None;
        }
        let Some(lane) = &self.lane else {
            let _ = taken.send(Err(Refused::Unsent(keys::unsent(
                "That input",
                self.lane_lost
                    .as_deref()
                    .unwrap_or("this view's input stream is not open yet"),
            ))));
            return None;
        };
        let writings = match send(lane) {
            Ok(writings) => writings,
            Err(refusal) => {
                let _ = taken.send(Err(Refused::Unsent(keys::unsent(
                    "That input",
                    refused_words(refusal),
                ))));
                return None;
            }
        };
        let _ = taken.send(Ok(()));
        // The lane gave each frame its number in the epoch, which is the one the host sees; the
        // lease keeps its own count in step.
        for writing in writings {
            let _ = self.lease.write(take);
            let (Some(epoch), Some(sequence)) = (self.lane_epoch, writing.sequence) else {
                continue;
            };
            let tag = self.next_id();
            self.lease.written(tag, epoch);
            self.keys.insert((epoch.get(), sequence.get()), Some(tag));
        }
        None
    }

    /// Begins the lane's epoch for the lease the view holds, once, as the lease first holds it.
    fn sync_epoch(&mut self) {
        let (Some(lane), Some(epoch)) = (&self.lane, self.lease.held_epoch()) else {
            return;
        };
        if self.lane_epoch == Some(epoch) {
            return;
        }
        if lane.begin_epoch(epoch).is_err() {
            return;
        }
        self.lane_epoch = Some(epoch);
        // The lane gives no event for a frame of an older epoch that is answered after this, so
        // the lease is told now that none of them waits for an answer it will read: their request
        // numbers leave the lease's `writes` at once. Without this they would stay there until a
        // later key is accepted, at most the frames that this epoch's begin dropped unsent (the
        // lane's bound of 1,024). No decision and no shown text depends on it: no refusal of an
        // older epoch reaches the lease, and nothing else reads `writes` for a key of the lane.
        for tag in self.keys.range_mut(..(epoch.get(), 0)).map(|(_, tag)| tag) {
            if let Some(tag) = tag.take() {
                self.lease.answered(tag, Ok(ParamsValue::empty()));
            }
        }
    }

    /// Starts the opening of the input lane, which a paired host answers once it has opened its
    /// stream: a call of the loop's set, which no command awaits.
    fn open_lane(&mut self) {
        self.opening = true;
        let target = InputTarget::new(
            self.target.environment_id,
            self.session_id,
            self.attachment.attachment_id,
        )
        .worker_states_input_lane(self.states_input_lane);
        #[cfg(feature = "testing")]
        let target = match &self.probe.lane_bounds {
            Some(bounds) => target.bounded_by(Arc::clone(bounds)),
            None => target,
        };
        let session = Arc::clone(self.link.session());
        let tag = self.next_id();
        self.requests.push(Box::pin(async move {
            (tag, Completed::Lane(session.input_lane(target).await))
        }));
    }

    /// The lane's opening ended: the lane is there to type on, or the words say why it is not.
    fn lane_opened(&mut self, opened: Result<InputLane, ClientError>) -> Option<Ending> {
        self.opening = false;
        match opened {
            Ok(lane) => {
                #[cfg(feature = "testing")]
                self.probe.publish_lane(&lane);
                // What the lane that ended said behind its end is read before the new lane's words.
                if let Some(ended) = self.lane_events.as_mut() {
                    let mut left = Vec::new();
                    while let Some(event) = ended.try_recv() {
                        left.push(Heard::Lane(Some(event)));
                    }
                    self.queue(left);
                }
                self.lane_events = lane.events();
                self.lane = Some(lane);
                self.lane_lost = None;
                self.sync_epoch();
            }
            Err(failed) => {
                self.no_stream = failed.code() == ErrorCode::UnsupportedCapability;
                self.lane_lost = Some(format!("its input stream could not be opened: {failed}"));
                // A take that waits for the stream is refused; a host that takes none lets it
                // acquire with no lane.
                if !self.no_stream && self.lease.stream_refused() {
                    self.control_changed();
                }
            }
        }
        None
    }

    /// What the lane says of the typing and of the endings that wait behind it.
    fn lane_event(&mut self, event: InputEvent) -> Option<Ending> {
        match event {
            InputEvent::Accepted { epoch, through, .. } => {
                self.accepted(epoch, through);
                None
            }
            InputEvent::Refused {
                epoch,
                sequence,
                error,
                ..
            } => {
                // What the host accepted before the refused frame came in the lane's own
                // `Accepted` event, which it says first.
                if self.refused(epoch, sequence, error) {
                    self.control_changed();
                }
                None
            }
            InputEvent::Reached(barrier) => {
                self.send_barred(&barrier, true);
                None
            }
            InputEvent::NotReached { barrier, .. } => {
                self.send_barred(&barrier, false);
                None
            }
            InputEvent::EpochEnded { epoch, .. } => {
                // Control moved while the view held it: it ends as a lost lease ends it, and no key
                // is taken after it.
                if self.lease.epoch_ended(epoch) {
                    self.control_changed();
                }
                None
            }
            InputEvent::LaunchReserved { .. } => None,
            InputEvent::Ended { cause, .. } => {
                // The lane's handle goes, which is what lets its events end, and the reader is kept
                // and read to its end: what the lane says behind its end, the barriers it did not
                // reach, is served as any other word of the lane. The connection's end reaches the
                // loop through the session's own notifications.
                self.lane = None;
                // Whatever ended it, a key typed now is refused for an ended stream, which is what
                // the lane is, and never for one that is not open yet.
                self.lane_lost = Some("its input stream ended".to_owned());
                if matches!(
                    cause,
                    EndCause::Reset | EndCause::Breach(_) | EndCause::Uncertain(_)
                ) {
                    // A view that holds the lease ends control: the keys of a new stream need a new
                    // epoch, and the lease's epoch is given back.
                    if self.lease.stream_ended() {
                        self.control_changed();
                    }
                }
                #[cfg(feature = "testing")]
                self.probe.lane_ends.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// The host accepted the keys of `epoch` up to `through`: each is answered, as accepted. The
    /// lane writes one key at a time and waits for the host's answer to each, so no key before
    /// the accepted one, in this epoch or an older one, is in flight any more: they are settled
    /// with it.
    fn accepted(&mut self, epoch: InputLeaseEpoch, through: kr_protocol::ids::InputSequence) {
        self.proven.accepted(epoch.get(), through.get());
        let accepted: Vec<(u64, u64)> = self
            .keys
            .range(..=(epoch.get(), through.get()))
            .map(|(key, _)| *key)
            .collect();
        for key in accepted {
            if let Some(Some(tag)) = self.keys.remove(&key) {
                self.lease.answered(tag, Ok(ParamsValue::empty()));
            }
        }
    }

    /// The host refused the key `sequence` of `epoch`: it and every later key of the epoch are
    /// settled as refused, and every key before it as answered. Returns whether the lease says
    /// control ended.
    fn refused(
        &mut self,
        epoch: InputLeaseEpoch,
        sequence: kr_protocol::ids::InputSequence,
        error: ProtocolError,
    ) -> bool {
        let at = (epoch.get(), sequence.get());
        let before: Vec<(u64, u64)> = self.keys.range(..at).map(|(key, _)| *key).collect();
        for key in before {
            if let Some(Some(tag)) = self.keys.remove(&key) {
                self.lease.answered(tag, Ok(ParamsValue::empty()));
            }
        }
        let refused = self.keys.remove(&at).flatten();
        let later: Vec<(u64, u64)> = self
            .keys
            .range(at..)
            .map(|(key, _)| *key)
            .filter(|(of, _)| *of == epoch.get())
            .collect();
        // The first refusal ends the epoch, and the frames after it are refused with it.
        let ended = refused.is_some_and(|tag| self.lease.answered(tag, Err(error)));
        for key in later {
            if let Some(Some(tag)) = self.keys.remove(&key) {
                self.lease.answered(tag, Ok(ParamsValue::empty()));
            }
        }
        ended
    }

    /// Starts the ending that waited for `barrier`, which the host has the typing before, or has
    /// not: the host did not take it in time, or the epoch or the stream ended first. An ending
    /// goes either way, and names what the host did accept where it did not take it all; the host
    /// answers for it.
    fn send_barred(&mut self, barrier: &InputBarrier, reached: bool) {
        let Some(at) = self
            .endings
            .iter()
            .position(|barred| &barred.barrier == barrier)
        else {
            return;
        };
        let Barred {
            tag,
            barrier: taken,
            call,
        } = self.endings.remove(at);
        if !reached && let Some(reply) = self.launches.remove(&tag) {
            // A launch is sent only where the host has the typing before it: nothing of it was
            // sent, so the page is told at once that it was not started, in the shape of every
            // launch the view did not send. What the lane holds behind it is released once, for
            // whichever reason the barrier was not reached: the lane releases it in order after a
            // time-out and has already ended it after the others.
            let _ = reply.send(Err(CommandError::stated(
                ErrorCode::TerminalUnavailable,
                LAUNCH_NOT_STARTED,
            )));
            if let Some(launch) = self.holds.remove(&tag)
                && let Some(lane) = &self.lane
            {
                lane.release_hold(launch);
            }
            return;
        }
        let named = if reached {
            taken
        } else {
            let count = U64::new(self.proven.prefix(taken.epoch.get()));
            InputBarrier { count, ..taken }
        };
        let call = call(named);
        self.start(tag, call);
    }

    /// Tells the page that control changed, at once. A screen that waits for its report's answer
    /// is not the page's yet, so the change goes with the state the page was last sent, its screen
    /// and settlement as they were.
    fn control_changed(&mut self) {
        if self.held {
            if let Some(last) = self.last.take() {
                let state = last.with_control(self.lease.control());
                self.last = Some(state.clone());
                (self.publish)(state);
            }
        } else {
            self.publish_state();
        }
    }

    /// Reads the launch surface on this view's link, which can hold the session's input: the read
    /// says whether this view does, and the page's buttons are lit only on that.
    ///
    /// A worker that did not state that it serves the read is not asked.
    fn launch_surface(&mut self, reply: Reply<LaunchSurfaceAnswer>) -> Option<Ending> {
        if self.serves_launch_surface == Some(false) {
            let _ = reply.send(Ok(LaunchSurfaceAnswer::NotServed));
            return None;
        }
        let request_id = self.ask_launch_surface();
        self.launch_reads.insert(
            request_id,
            LaunchRead {
                stage: LaunchReadStage::Asked,
                reply,
            },
        );
        None
    }

    fn ask_launch_surface(&mut self) -> RequestId {
        let params = ShellLaunchSurfaceParams {
            session_id: self.session_id,
        };
        self.read(Method::ShellLaunchSurface, params)
    }

    /// Takes the answer to a launch surface read, or to the read that tells a host that does not
    /// serve it from a grant that lost its right, and asks the next question or says the answer.
    fn launch_surface_answered(
        &mut self,
        request_id: RequestId,
        outcome: Outcome,
    ) -> Option<Ending> {
        let mut read = self.launch_reads.remove(&request_id)?;
        let step = launch_read_step(read.stage, self.serves_launch_surface, outcome);
        let stage = match step {
            Step::Say(answer) => {
                let _ = read.reply.send(answer);
                return None;
            }
            Step::Ask(stage) => stage,
        };
        let asked = if stage == LaunchReadStage::Probed {
            let params = SessionReadParams {
                session_id: self.session_id,
            };
            self.read(Method::SessionRead, params)
        } else {
            self.ask_launch_surface()
        };
        read.stage = stage;
        self.launch_reads.insert(asked, read);
        None
    }

    /// Presses a launch on this view's link. The session accepts it only from the connection whose
    /// attachment holds its input, and refuses a quote of a prompt that has moved before anything
    /// is typed; this view asks and says what the session answered. The launch stands behind the
    /// typing the lane holds, as the lane orders it.
    async fn launch(&mut self, press: Press, reply: Reply<ShellLaunchResult>) -> Option<Ending> {
        let params = press.for_session(self.session_id);
        self.next_launch += 1;
        let launch = self.next_launch;
        let epoch = self.lane_epoch;
        let ended = self
            .ending(
                Method::ShellLaunch,
                epoch,
                Some(launch),
                move |after_input| kr_protocol::root::ShellLaunchParams {
                    after_input,
                    ..params
                },
            )
            .await;
        match ended {
            Ok(Started::Sent(request_id)) => {
                // Kept before the call is polled: a call that failed may have left in part, and the
                // launch is then not known to have failed.
                self.launches.insert(request_id, reply);
                None
            }
            Ok(Started::NotStarted(words)) => {
                let _ = reply.send(Err(CommandError::stated(
                    ErrorCode::TerminalUnavailable,
                    words,
                )));
                None
            }
            Err(ended) => Some(ended),
        }
    }

    /// Answers every launch still waiting when the view ends: the session may have installed one
    /// that was sent before the link went, so it is not known to have failed. A launch that still
    /// waits for the lane to have the typing before it was never sent, and is told so.
    fn end_launches(&mut self) {
        let unsent: Vec<RequestId> = self.endings.iter().map(|barred| barred.tag).collect();
        for (request_id, reply) in std::mem::take(&mut self.launches) {
            let _ = reply.send(Err(if unsent.contains(&request_id) {
                CommandError::stated(ErrorCode::TerminalUnavailable, LAUNCH_NOT_STARTED)
            } else {
                CommandError::stated(ErrorCode::OutcomeUnknown, LAUNCH_UNANSWERED)
            }));
        }
    }

    /// Starts `call` under `tag` and gives its answer back under `tag`.
    ///
    /// The call is polled once here, in the turn that starts it, so that its request is written at
    /// once and not behind what the loop has queued: the session's call takes its lock on the
    /// outcomes and then writes its frame, and a first poll that cannot do either (the lock is held
    /// by the reader at that instant, or the transport does not take the frame yet) leaves the
    /// write to the loop's next look at its calls. A call that completes in that poll (one that
    /// failed before anything was sent) is put in the set as completed, so it is taken as any
    /// answer is, behind what the session's channel held when it was taken.
    fn start(&mut self, tag: RequestId, mut call: link::Call) {
        let mut context = Context::from_waker(Waker::noop());
        match call.as_mut().poll(&mut context) {
            Poll::Ready(answered) => self.requests.push(Box::pin(std::future::ready((
                tag,
                Completed::Call(answered),
            )))),
            Poll::Pending => self
                .requests
                .push(Box::pin(async move { (tag, Completed::Call(call.await)) })),
        }
    }

    /// Starts a mutation on the session's target and returns the view's number for it.
    fn mutation<P>(&mut self, method: Method, params: P) -> RequestId
    where
        P: serde::Serialize + Send + Sync + 'static,
    {
        let call = self.link.mutate(method, self.target.clone(), params);
        let tag = self.next_id();
        self.start(tag, call);
        tag
    }

    /// Starts a read and returns the view's number for it.
    fn read<P>(&mut self, method: Method, params: P) -> RequestId
    where
        P: serde::Serialize + Send + Sync + 'static,
    {
        let call = self.link.read(method, params);
        let tag = self.next_id();
        self.start(tag, call);
        tag
    }

    /// Starts an ending, a release, a detach or a launch, so that it comes after the typing the
    /// view has admitted and before any it admits later, and returns the view's number for it.
    ///
    /// `epoch` is the lease epoch the ending is for. On a link that carries the typing as requests
    /// the ending is queued behind the typing, and nothing is on the wire for it until the lane
    /// takes its turn, which is after the host has answered each key before it. On a link with a
    /// stream of its own the ending takes the lane's mark, and is started once the lane says the host
    /// has accepted the typing before it. Where the lane cannot place it, nothing was queued, and it
    /// is started at once.
    ///
    /// # Errors
    ///
    /// Returns how the view ends when the request cannot be made.
    async fn ending<P>(
        &mut self,
        method: Method,
        epoch: Option<InputLeaseEpoch>,
        launch: Option<u32>,
        params: impl FnOnce(Option<InputBarrier>) -> P + Send + 'static,
    ) -> Result<Started, Ending>
    where
        P: serde::Serialize + Send + Sync + 'static,
    {
        let tag = self.next_id();
        let placed = epoch.is_some() && epoch == self.lane_epoch;
        let Some(lane) = self.lane.as_ref().filter(|_| placed) else {
            let call = self.link.mutate(method, self.target.clone(), params(None));
            self.start(tag, call);
            return Ok(Started::Sent(tag));
        };
        if self.networked {
            let barrier = match lane.mark(launch) {
                Ok(barrier) => barrier,
                // A launch goes only where the lane has the typing before it counted: another
                // launch's hold stands, or a release waits, and the launch is not sent. What stands
                // is kept. The lane's epoch stays in its ending phase after a release that the
                // session refused, until its notice or a new take, though no release waits then:
                // that launch goes as one with no epoch does.
                Err(InputRefusal::LaunchWaiting) if launch.is_some() => {
                    return Ok(Started::NotStarted(LAUNCH_BEHIND_ANOTHER));
                }
                Err(InputRefusal::Ending) if launch.is_some() && self.lease.releases_wait() => {
                    return Ok(Started::NotStarted(LAUNCH_BEHIND_ANOTHER));
                }
                Err(_) => {
                    let call = self.link.mutate(method, self.target.clone(), params(None));
                    self.start(tag, call);
                    return Ok(Started::Sent(tag));
                }
            };
            #[cfg(feature = "testing")]
            self.probe.barriers.fetch_add(1, Ordering::Relaxed);
            if launch.is_some() {
                self.holds.insert(tag, launch.unwrap_or_default());
            }
            let (link, target) = (self.link.clone(), self.target.clone());
            let call = Box::new(move |named: InputBarrier| {
                link.mutate(method, target, params(Some(named)))
            });
            self.endings.push(Barred { tag, barrier, call });
            return Ok(Started::Sent(tag));
        }
        let params = params(None);
        let composed = self
            .link
            .compose(method, self.target.clone(), &params)
            .await
            .map_err(|_| Ending::ended("This view's request could not be written."))?;
        let session = Arc::clone(self.link.session());
        let queued = lane.after_keys({
            let session = Arc::clone(&session);
            let composed = Arc::clone(&composed);
            move |limit| async move { session.send_written(&composed, &limit).await }
        });
        let call: link::Call = match queued {
            Ok(answer) => Box::pin(async move {
                let answered = match answer.await {
                    Ok(Ok(settled)) => Ok(settled),
                    // The lane ended before its turn, or past its bound: the view sends it itself.
                    Ok(Err(ClientError::Withheld)) => session.send(&composed).await,
                    Ok(Err(failed)) => Err(failed),
                    Err(_) => Err(link::unknown()),
                };
                settle_when_definite(&session, composed.action_id(), &answered).await;
                answered?.to_typed::<ParamsValue>()
            }),
            Err(_) => self.link.mutate(method, self.target.clone(), params),
        };
        self.start(tag, call);
        Ok(Started::Sent(tag))
    }

    /// The call that failed took the link with it, or the link failed under it: reads on to the
    /// end of the session, which is where what the host sent before it ended is, and says the view
    /// is lost, with the account's words when this device ended the link. The host's refusal of the
    /// connection comes before the end, and is kept. What the session said that the loop has
    /// queued is read first, in its order.
    async fn link_failed(&mut self) -> Ending {
        let mut queued: VecDeque<Option<Ordered>> = std::mem::take(&mut self.heard)
            .into_iter()
            .filter_map(|heard| match heard {
                Heard::Event(item) => Some(item),
                Heard::Done(_) | Heard::Lane(_) => None,
            })
            .collect();
        let drained = tokio::time::timeout(REFUSAL_WAIT, async {
            loop {
                let item = match queued.pop_front() {
                    Some(item) => item,
                    None => self.events.recv().await,
                };
                match item {
                    Some(Ordered::Notification(notification)) => {
                        if let Some(ended) = self.notification(notification) {
                            return Some(ended);
                        }
                    }
                    Some(Ordered::Ended(_)) | None => return None,
                }
            }
        })
        .await;
        match drained {
            Ok(Some(ended)) => ended,
            Ok(None) | Err(_) => self.lost(),
        }
    }

    /// Ends the view: what the loop started is dropped, the detach is written whole while the
    /// attachment still stands on a link that still stands, and then the session is closed and read
    /// to its end, so that its reader is released.
    async fn finish(&mut self, detach: bool) {
        self.requests = FuturesUnordered::new();
        // What the lane already knows of the typing is applied before the detach is placed, in the
        // order the lane said it: where the host has the typing before the detach, the detach
        // names it.
        tokio::task::yield_now().await;
        for heard in std::mem::take(&mut self.heard) {
            if let Heard::Lane(Some(event)) = heard {
                self.settle(event);
            }
        }
        while let Some(event) = self.lane_events.as_mut().and_then(InputEvents::try_recv) {
            self.settle(event);
        }
        if detach {
            self.detach().await;
        }
        self.link.close();
        self.events.drain().await;
    }

    /// Applies what the lane said of the keys, at the close: an acceptance or a refusal settles keys,
    /// and nothing else of the lane's words matters to a view that ends.
    fn settle(&mut self, event: InputEvent) {
        match event {
            InputEvent::Accepted { epoch, through, .. } => self.accepted(epoch, through),
            InputEvent::Refused {
                epoch,
                sequence,
                error,
                ..
            } => {
                let _ = self.refused(epoch, sequence, error);
            }
            _ => {}
        }
    }

    /// Writes the detach whole, behind the typing the lane holds.
    ///
    /// On a link that carries the typing as requests it is queued behind the keys, and only where
    /// the lane says it has no key queued or in flight, in any epoch, which a lane that has ended
    /// says always: the view waits for the detach to be written. No key stands between the lane's
    /// writer and it, but a request queued among the keys, a release or a launch, can, and each
    /// has the lane's bound of 30 seconds for its own write. Where a key that the host has not
    /// answered holds the writer, nothing is queued, and the connection's end, which the worker
    /// detaches on, is what ends the attachment. On a link with a stream of its own the detach
    /// waits for the lane to say the host has the typing, which the lane bounds. Whatever it waits
    /// for, the view reads and drops what the session says meanwhile, so that the session's reader,
    /// which waits for room in its channel while the view does not read, is never what the wait
    /// waits for.
    async fn detach(&mut self) {
        let attachment_id = self.attachment.attachment_id;
        let params = move |after_input| SessionDetachParams {
            attachment_id: Nullable::some(attachment_id),
            line_token: Nullable::null(),
            after_input,
            fenced_report: false,
        };
        let placed = self.lane_epoch.is_some();
        if self.networked && placed {
            let barrier = self.lane.as_ref().and_then(|lane| lane.mark(None).ok());
            if let Some(barrier) = barrier {
                #[cfg(feature = "testing")]
                self.probe.barriers.fetch_add(1, Ordering::Relaxed);
                // The detach names the barrier where the host has the typing before it, and where it
                // does not, the typing it did accept, counting what it accepts while the close waits.
                let reached = match self.lane_events.as_mut() {
                    Some(lane_events) => {
                        self.events
                            .dropping_during(barrier_passed(
                                lane_events,
                                &barrier,
                                &mut self.proven,
                            ))
                            .await
                    }
                    None => false,
                };
                let barrier = if reached {
                    barrier
                } else {
                    let count = U64::new(self.proven.prefix(barrier.epoch.get()));
                    InputBarrier { count, ..barrier }
                };
                let Ok(composed) = self
                    .link
                    .compose(
                        Method::SessionDetach,
                        self.target.clone(),
                        &params(Some(barrier)),
                    )
                    .await
                else {
                    return;
                };
                let _ = self
                    .events
                    .dropping_during(self.link.send_whole(&composed))
                    .await;
                return;
            }
        }
        let params = params(None);
        let Ok(composed) = self
            .link
            .compose(Method::SessionDetach, self.target.clone(), &params)
            .await
        else {
            return;
        };
        if placed && !self.networked && self.lane.as_ref().is_some_and(InputLane::keys_pending) {
            return;
        }
        let queued = if placed && !self.networked {
            self.lane.as_ref().map(|lane| {
                let (written, wait) = tokio::sync::oneshot::channel::<()>();
                let session = Arc::clone(self.link.session());
                let composed = Arc::clone(&composed);
                let queued = lane.after_keys(move |limit| async move {
                    let sent = session.send_written(&composed, &limit).await;
                    let _ = written.send(());
                    sent
                });
                (queued, wait)
            })
        } else {
            None
        };
        match queued {
            Some((Ok(_answer), wait)) => {
                let _ = self.events.dropping_during(wait).await;
            }
            // Nothing was queued: the lane cannot place it, or there is no lane.
            Some((Err(_), _)) | None => {
                let _ = self
                    .events
                    .dropping_during(self.link.send_whole(&composed))
                    .await;
            }
        }
    }

    fn next_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }

    /// Tells the page the view holds no complete screen, once: the page keeps its last frame.
    fn waiting(&mut self) {
        if self.showing {
            self.showing = false;
            self.publish_state();
        }
    }

    /// Tells the page the screen as it is now.
    fn show(&mut self) {
        self.showing = true;
        self.publish_state();
    }

    /// Tells the page of moves that have settled since it was last told, when the screen it draws
    /// holds them. A screen that waits for its answer is not the page's yet, so nothing is told
    /// with it.
    fn tell(&mut self) {
        if !self.held && self.window.told(self.drawn) != self.told {
            self.publish_state();
        }
    }

    fn publish_state(&mut self) {
        let screen = if self.showing {
            self.projection.screen()
        } else {
            None
        };
        if let Some(screen) = screen {
            self.drawn = Some(screen.window_revision);
        }
        self.told = self.window.told(self.drawn);
        let state = state_of(&self.attachment, screen, self.told, self.lease.control());
        self.last = Some(state.clone());
        (self.publish)(state);
    }
}

#[cfg(test)]
mod tests {
    use super::{LaunchReadStage, Step, build_name, launch_read_step, not_opened};
    use crate::launch::LaunchSurfaceAnswer;
    use kr_protocol::envelope::{Outcome, ParamsValue};
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::ids::BuildId;
    use kr_protocol::scalars::Nullable;

    /// A build identifier is said when it is a program's name and a release, and any other text a
    /// worker states is replaced rather than repeated.
    #[test]
    fn a_build_identifier_is_said_only_when_it_is_a_name_and_a_release() {
        let long = format!("kr-worker/{}1", "1.".repeat(40));
        for text in [
            "kr-worker/0.1.0\u{202e}",
            "kr-worker/0.1.0 with protocol 9.9.9",
            "../kr-worker/0.1.0",
            "Kr-Worker/0.1.0",
            "kr-worker/0.1.0-rc.1",
            "kr-worker/",
            "kr-worker/0..1",
            "1kr/0.1.0",
            "kr-worker",
            long.as_str(),
        ] {
            let id = BuildId::new(text).expect("a build identifier");
            assert_eq!(
                build_name(&id),
                "[a build this application does not name]",
                "{text:?}"
            );
        }
        for text in ["kr-worker/0.1.0", "kalareach-companion/0.49.0"] {
            let id = BuildId::new(text).expect("a build identifier");
            assert_eq!(build_name(&id), text);
        }
    }

    /// The surface a worker answers with, and the answer to the read that tells a host that does
    /// not serve the surface from a grant that lost its right.
    fn surface() -> ParamsValue {
        ParamsValue::from_typed(&kr_protocol::root::ShellLaunchSurfaceResult {
            session_id: kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()),
            editor: kr_protocol::root::LaunchEditor::Unverified {
                reason: kr_protocol::root::LaunchUnverified::StockShell,
            },
            input: kr_protocol::root::LaunchInput::Free,
            shell: Nullable::some(kr_protocol::root::LaunchShell::Sh),
            offers: Vec::new(),
        })
        .expect("a result")
    }

    fn session_read() -> ParamsValue {
        ParamsValue::from_typed(&kr_protocol::session::SessionReadResult {
            session: kr_protocol::session::SessionSummary {
                session_id: kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()),
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                display_number: kr_protocol::session::DisplayNumber::new(1),
                state: kr_protocol::session::SessionState::Live,
                shell_mode: kr_protocol::session::ShellMode::NativeCompat,
                shell_path: "/bin/sh".to_owned(),
                cwd: "/".to_owned(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                desktop: kr_protocol::identity::DesktopBinding::none(),
                created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
                dimensions: kr_protocol::session::Dimensions::new(80, 24),
                attachment_count: kr_protocol::scalars::U64::ZERO,
                application_state: Nullable::null(),
                root_process: Nullable::null(),
                closure: Nullable::null(),
                environment_sources: None,
                root: None,
                application: None,
            },
            endpoint: Nullable::null(),
            launch_profile: Nullable::null(),
            last_command_block: Nullable::null(),
            outstanding_launches: Nullable::null(),
            metrics: None,
        })
        .expect("a result")
    }

    fn refused(code: ErrorCode) -> Outcome {
        Outcome::Error(ProtocolError::new(code, "refused"))
    }

    /// What a step comes to, in a word the table below can read.
    fn said(step: Step) -> String {
        match step {
            Step::Ask(stage) => format!("ask {stage:?}"),
            Step::Say(Ok(LaunchSurfaceAnswer::Served { .. })) => "served".to_owned(),
            Step::Say(Ok(LaunchSurfaceAnswer::NotServed)) => "not served".to_owned(),
            Step::Say(Err(error)) => format!("refused {}", error.code.as_str()),
        }
    }

    /// A paired host's daemon says nothing of whether its worker serves the launch surface, so a
    /// refusal as an unlisted method is told from a grant that lost its right by what the same
    /// right reads; a worker that stated that it serves the read is not asked, since its refusal is
    /// the grant's. The probe's answer is a session read, and anything else is a failure.
    #[test]
    fn a_launch_surface_read_tells_an_unlisted_method_from_a_lost_right_where_the_link_does_not_say()
     {
        use LaunchReadStage::{Asked, AskedAgain, Probed};
        let garbage = || Outcome::Ok(ParamsValue::from_typed(&"neither").expect("a value"));
        let table: Vec<(LaunchReadStage, Option<bool>, Outcome, &str)> = vec![
            (Asked, Some(true), Outcome::Ok(surface()), "served"),
            (Asked, None, Outcome::Ok(surface()), "served"),
            (
                Asked,
                None,
                refused(ErrorCode::PermissionDenied),
                "ask Probed",
            ),
            (
                Asked,
                Some(true),
                refused(ErrorCode::PermissionDenied),
                "refused PERMISSION_DENIED",
            ),
            (
                Asked,
                None,
                refused(ErrorCode::UnsupportedCapability),
                "not served",
            ),
            (
                Asked,
                Some(true),
                refused(ErrorCode::UnsupportedCapability),
                "not served",
            ),
            (
                Asked,
                None,
                refused(ErrorCode::EditorBusy),
                "refused EDITOR_BUSY",
            ),
            (Probed, None, Outcome::Ok(session_read()), "ask AskedAgain"),
            (Probed, None, garbage(), "refused RESOURCE_UNAVAILABLE"),
            (
                Probed,
                None,
                refused(ErrorCode::PermissionDenied),
                "refused PERMISSION_DENIED",
            ),
            (AskedAgain, None, Outcome::Ok(surface()), "served"),
            (
                AskedAgain,
                None,
                refused(ErrorCode::PermissionDenied),
                "not served",
            ),
            (
                AskedAgain,
                None,
                refused(ErrorCode::UnsupportedCapability),
                "not served",
            ),
            (
                AskedAgain,
                None,
                refused(ErrorCode::EditorBusy),
                "refused EDITOR_BUSY",
            ),
        ];
        for (stage, serves, outcome, expected) in table {
            assert_eq!(
                said(launch_read_step(stage, serves, outcome)),
                expected,
                "{stage:?}, serves {serves:?}"
            );
        }
    }

    /// KR-REQ-19.08: what a view says of a connection that was not opened follows from the cause, and
    /// not from the code of the refusal: a refusal of the connection with the code the host's bound
    /// has says the same as one with another code, a refusal that is for now leaves the view lost
    /// and the others end it, and a refusal of a request names the request.
    #[test]
    fn a_view_tells_a_connection_that_was_not_opened_by_its_cause() {
        use crate::connection::{Asked, NotReached, Unopened};
        use crate::error::CommandError;

        let refused = |asked, code| {
            not_opened(Unopened::Refused(
                asked,
                CommandError::new(code, "its words"),
            ))
        };

        // The host's bound and this computer's budget leave the view lost, and say so.
        for full in [Unopened::HostFull, Unopened::BudgetFull] {
            let failure = not_opened(full);
            assert!(failure.lost, "{}", failure.reason);
            assert!(
                failure.reason.starts_with("No connection was made"),
                "{}",
                failure.reason
            );
        }
        // A refusal of the connection says its words and not the host's bound, whatever its code.
        for code in [ErrorCode::ResourceUnavailable, ErrorCode::PermissionDenied] {
            let failure = refused(Asked::Connection, code);
            assert!(
                failure.reason.contains("its words"),
                "{code:?}: {}",
                failure.reason
            );
            assert!(
                !failure.reason.contains("cannot take another"),
                "{code:?}: {}",
                failure.reason
            );
        }
        // For now, the view is lost and asked again; otherwise the host refused it.
        assert!(refused(Asked::SessionOpen, ErrorCode::ResourceUnavailable).lost);
        assert!(!refused(Asked::SessionOpen, ErrorCode::PermissionDenied).lost);
        // A refusal of a request names the request that was refused.
        let failure = refused(Asked::SessionOpen, ErrorCode::PermissionDenied);
        assert!(
            failure.reason.contains("open the session"),
            "{}",
            failure.reason
        );
        // A host that was not reached is not one that refused.
        let failure = not_opened(Unopened::unreached(NotReached::NoAnswerInTime));
        assert!(
            failure.lost && failure.reason.contains("could not be reached"),
            "{}",
            failure.reason
        );
    }
}
