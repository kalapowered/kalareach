//! One raw terminal view's task: its link to the session's worker, its attachment, the screen the
//! client library holds for it, and the size it reports.
//!
//! The task opens the link, attaches and subscribes, and then reads the link in one loop, the way
//! the CLI's attach loop does: every report and resubscription is written without waiting for its
//! answer, and the answer is matched by its request number when it arrives. A call that waited
//! would let an answer to another call arrive first, and would keep the page's own close waiting on
//! the host.
//!
//! The view reports its size and where the page moved its window, one report at a time, through
//! [`WindowReports`]: each report is settled by the screen its answer names, and the page is told a
//! move is settled only with a screen that holds it.
//!
//! It takes control of the program when the person asks, and writes the wheel turns, keys, text
//! and pastes they make under the input lease, through [`Lease`]. Each key is spelled by the
//! client's shared encoder in the encoding the screen it holds says the program reads (`keys`); a
//! screen that says the program reads a form the view does not produce ends control at once. A
//! change of control is told to the page at once.

use std::collections::BTreeMap;

use kr_client::encoder::{self, KeyEventKind, Modifiers};
use kr_client::projection::{Applied, Projection, decode, is_projection_event};
use kr_client::shown::Shown;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentSummary, AttachmentViewportParams,
    AttachmentViewportResult, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, Notification, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::ids::{BuildId, GrantId, RequestId, SessionId};
use kr_protocol::input::{InputAcquireParams, InputReleaseParams, InputWriteParams};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::root::{ShellLaunchResult, ShellLaunchSurfaceParams, ShellLaunchSurfaceResult};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, U64};
use kr_protocol::session::{
    Dimensions, SESSION_CLOSED_EVENT, SessionReadParams, SessionReadResult,
};
use kr_protocol::worker::WorkerDescriptor;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::error::CommandError;
use crate::launch::{LaunchSurfaceAnswer, Press};

use super::input::{Input, Lease, Owed, PROFILE, Refused, wheel_reports};
use super::keys::{self, KeyAction, Keyboard, Pressed, TypedKey};
use super::screen::{TerminalViewState, state_of};
use super::window::{Answer, WindowReports};
use super::wire::{Lost, Paired, Wire};
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

/// How many recoveries in a row may pass without a complete screen before the view ends.
///
/// A recovery asks the session for a fresh screen. A host whose screens never decode would have the
/// view ask for ever, so after this many the view ends and says why, and the person can attach
/// again.
const RECOVERIES: u32 = 3;

/// The first request number the view's own loop uses.
///
/// Numbered apart from the ones the client library gave the attach and the subscription, so an
/// answer the loop reads is never taken for an answer to one of those.
pub(super) const LOOP_REQUESTS: u64 = 1 << 32;

/// The event a view is sent when the session asks it to take its screen again.
const RESYNC_EVENT: &str = "session.resync";

/// The event a view is sent when its attachment was ended somewhere else.
const DETACHED_EVENT: &str = "session.detached";

/// What the open answered: the link, what a mutation on it is about, and the attachment.
struct Opened {
    wire: Wire,
    target: ActionTarget,
    attached: SessionAttachResult,
    /// Whether the worker stated that it serves the launch surface, when a worker answered the
    /// hello on this link: none on a link to a paired host's daemon.
    serves_launch_surface: Option<bool>,
}

/// Where a view's session is reached.
pub(super) enum Reach<'a> {
    /// The worker on this machine, found by its descriptor.
    Local(&'a Locate),
    /// A host this device is paired with, over a connection opened for the view under `grant`
    /// (the pairing when none).
    Paired(&'a crate::standing::Dial, Option<GrantId>),
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

/// Runs one view from its open until it ends or is closed, and says why it ended.
pub(super) async fn run(
    reach: Reach<'_>,
    session_id: SessionId,
    dimensions: Dimensions,
    mut commands: UnboundedReceiver<Command>,
    publish: &Publish,
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
    let next_request = opened.wire.first_loop_request();
    let mut view = View {
        wire: opened.wire,
        target: opened.target,
        session_id,
        attachment: opened.attached.attachment,
        projection: Projection::new(),
        next_request,
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
        publish: publish.clone(),
    };
    view.publish_state();
    let ended = view.serve(&mut commands).await;
    view.end_launches();
    if let Some(reason) = ended.reason {
        (view.publish)(TerminalViewState::Ended { reason });
    }
    if ended.detach {
        view.detach().await;
    }
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
    let (mut wire, target, serves_launch_surface) = match reach {
        Reach::Local(locate) => open_local(locate, session_id).await?,
        Reach::Paired(dial, grant_id) => {
            let (wire, target) = open_paired(dial, *grant_id, session_id).await?;
            (wire, target, None)
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
    let answer = wire
        .mutate(Method::SessionAttach, target.clone(), &params)
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
    wire.request(Method::EventsSubscribe, &subscribe)
        .await
        .map_err(|lost| OpenFailure::lost(&lost))?
        .map_err(|refusal| {
            OpenFailure::refused(format!(
                "The session refused this view's screen: {}",
                refusal.message
            ))
        })?;
    Ok(Opened {
        wire,
        target,
        attached,
        serves_launch_surface,
    })
}

/// Reaches the worker on this machine by its descriptor and has it prove who it is.
async fn open_local(
    locate: &Locate,
    session_id: SessionId,
) -> Result<(Wire, ActionTarget, Option<bool>), String> {
    let paths = locate()?;
    // A descriptor is data on disk. Nothing is sent until the worker behind the endpoint has signed
    // a challenge only the descriptor's key could answer.
    let crate::worker::Reached {
        client,
        descriptor,
        capabilities,
        ..
    } = crate::worker::reach(&paths, session_id)
        .await
        .map_err(crate::worker::Unreached::words)?;
    // The worker has proved who it is, and it says what it is: the attach waits on its screens, so
    // a worker whose screens this view cannot read is refused before it is asked for anything.
    check_build(client.acknowledgement().build.as_ref())?;
    let target = target(&descriptor);
    let serves = kr_protocol::ids::CapabilityId::new(kr_protocol::local::SHELL_LAUNCH_SURFACE_READ)
        .is_ok_and(|read| capabilities.contains(&read));
    Ok((Wire::Local(Box::new(client)), target, Some(serves)))
}

/// Reaches a paired host on a connection of the view's own and has it open the session for the
/// view, under the share the screen runs under.
async fn open_paired(
    dial: &crate::standing::Dial,
    grant_id: Option<GrantId>,
    session_id: SessionId,
) -> Result<(Wire, ActionTarget), OpenFailure> {
    use kr_protocol::session::{SessionOpenParams, SessionOpenResult};

    let transport = dial.transport().await.map_err(|failure| match failure {
        // The host could not be reached for this view's connection: the connection is what was
        // lost, and the host is asked again on the opening's link.
        crate::standing::Failure::Unreached(reason) => OpenFailure {
            reason: format!("The host could not be reached for this view: {reason}"),
            lost: true,
        },
        // A host that cannot answer now has not refused the view: the opening's link asks again.
        crate::standing::Failure::Refused(refusal) if crate::standing::transient(refusal.code) => {
            OpenFailure {
                reason: format!(
                    "The host could not answer for this view now: {}",
                    refusal.message
                ),
                lost: true,
            }
        }
        refused @ crate::standing::Failure::Refused(_) => OpenFailure::refused(refused.to_string()),
    })?;
    let mut wire =
        Wire::Paired(Paired::over(transport, grant_id).map_err(|lost| OpenFailure::lost(&lost))?);
    let opened = wire
        .request(
            Method::SessionOpen,
            &SessionOpenParams {
                session_id: Nullable::some(session_id),
                grant_id: Nullable(grant_id),
            },
        )
        .await
        .map_err(|lost| OpenFailure::lost(&lost))?
        .map_err(|refusal| {
            // A host that cannot answer now has not refused the view: the opening's link asks again.
            if crate::standing::transient(refusal.code) {
                OpenFailure {
                    reason: format!(
                        "The host could not answer for this view now: {}",
                        refusal.message
                    ),
                    lost: true,
                }
            } else {
                OpenFailure::refused(format!("The host refused this view: {}", refusal.message))
            }
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
            Ok((wire, target))
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

/// One open, attached view.
struct View {
    wire: Wire,
    target: ActionTarget,
    session_id: SessionId,
    attachment: AttachmentSummary,
    projection: Projection,
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
    publish: Publish,
}

/// What the loop reads next.
enum Next {
    Command(Option<Command>),
    Frame(Result<ControlFrame, Lost>),
}

impl View {
    /// The end of a view whose link is gone, in the account's words when this device ended the
    /// link because the account it was opened under left.
    fn lost(&self) -> Ending {
        Ending::lost(self.wire.ended_by_this_device())
    }

    /// Reads the link and the page's commands until the view ends.
    async fn serve(&mut self, commands: &mut UnboundedReceiver<Command>) -> Ending {
        loop {
            // What goes next is asked after every event, so nothing owed waits on an event that
            // does not come.
            if let Some(ended) = self.dispatch().await {
                return ended;
            }
            let next = tokio::select! {
                // The page first: a close is answered before anything more is read or drawn.
                biased;
                command = commands.recv() => Next::Command(command),
                frame = self.wire.recv() => Next::Frame(frame),
            };
            let ended = match next {
                Next::Command(Some(Command::Resize(size))) => {
                    self.window.measured(size);
                    None
                }
                Next::Command(Some(Command::Move(asked))) => {
                    self.window.take(asked);
                    None
                }
                Next::Command(Some(Command::Input(input, taken))) => self.input(input, taken).await,
                Next::Command(Some(Command::LaunchSurface(reply))) => {
                    self.launch_surface(reply).await
                }
                Next::Command(Some(Command::Launch(press, reply))) => {
                    self.launch(press, reply).await
                }
                Next::Command(Some(Command::Lose)) => Some(self.lost()),
                Next::Command(Some(Command::Close) | None) => Some(Ending::CLOSED),
                Next::Frame(Ok(ControlFrame::Notification(notification))) => {
                    self.notification(notification).await
                }
                Next::Frame(Ok(ControlFrame::Response(response))) => self.response(response).await,
                Next::Frame(Ok(_)) => None,
                Next::Frame(Err(_)) => Some(self.lost()),
            };
            if let Some(ended) = ended {
                return ended;
            }
        }
    }

    async fn notification(&mut self, notification: Notification) -> Option<Ending> {
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
            return self.recover().await;
        }
        if !is_projection_event(event_type) {
            // The output of a direct presentation and a gap's notice: neither draws anything in a
            // projected view, and neither is sent on to the page.
            return None;
        }
        let Some(event) = decode(event_type, &notification.payload) else {
            return self.recover().await;
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
            Applied::Refused(_) => self.recover().await,
        }
    }

    async fn response(&mut self, response: Response) -> Option<Ending> {
        if self.launch_reads.contains_key(&response.request_id) {
            return self.launch_surface_answered(response).await;
        }
        if let Some(reply) = self.launches.remove(&response.request_id) {
            let _ = reply.send(match response.outcome {
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
        if self.lease.owns(response.request_id) {
            let outcome = match response.outcome {
                Outcome::Ok(value) => Ok(value),
                Outcome::Error(refusal) => Err(refusal),
            };
            let changed = self.lease.answered(response.request_id, outcome);
            // A take the session granted just before the program changed to a form the view does
            // not produce ends as its answer arrives, before the page is told it controls anything.
            let ended = !self.keyboard_supplied() && self.lease.unsupported();
            if changed || ended {
                self.control_changed();
            }
            return None;
        }
        if self.window.is_in_flight(response.request_id) {
            // A refusal settles the report and changes nothing; an acceptance settles it once a
            // screen naming its revision has arrived, whichever came first. A screen that waited
            // for this answer is drawn now, with what the answer settled.
            let answer = match response.outcome {
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
                Outcome::Error(_) => Answer::Refused,
            };
            self.window.answered(answer);
            if self.held {
                self.held = false;
                self.show();
            } else {
                self.tell();
            }
            return None;
        }
        if self.resubscription == Some(response.request_id) {
            self.resubscription = None;
            if let Outcome::Error(refusal) = response.outcome {
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
    async fn recover(&mut self) -> Option<Ending> {
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
        let request_id = self.next_id();
        let Ok(params) = ParamsValue::from_typed(&params) else {
            return Some(Ending::ended("This view's request could not be written."));
        };
        let request = Request {
            request_id,
            method: Method::EventsSubscribe.into(),
            method_version: MethodVersion::V1,
            params,
        };
        if !self.wire.send(&ControlFrame::Request(request)).await {
            return Some(self.lost());
        }
        self.resubscription = Some(request_id);
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
            let request_id = self.next_id();
            if !self
                .mutation(request_id, Method::AttachmentViewport, &params)
                .await
            {
                return Some(self.lost());
            }
            self.window.sent(request_id);
        }
        while let Some(owed) = self.lease.owed() {
            let request_id = self.next_id();
            let sent = match owed {
                Owed::Acquire => {
                    // An immediate takeover: whoever holds the lease loses it, without being asked.
                    let params = InputAcquireParams {
                        session_id: self.session_id,
                        attachment_id: self.attachment.attachment_id,
                        expected_epoch: Nullable::null(),
                    };
                    self.mutation(request_id, Method::InputAcquire, &params)
                        .await
                }
                Owed::Release(epoch) => {
                    let params = InputReleaseParams {
                        session_id: self.session_id,
                        attachment_id: self.attachment.attachment_id,
                        epoch,
                    };
                    self.mutation(request_id, Method::InputRelease, &params)
                        .await
                }
            };
            if !sent {
                return Some(self.lost());
            }
            self.lease.sent(owed, request_id);
        }
        self.tell();
        None
    }

    /// Takes the person's `input`: a change of control, or a wheel turn or keys, written only while
    /// the view controls the program under the take they name. Says on `taken` whether it took it,
    /// and returns how the loop ended when writing it lost the link.
    async fn input(&mut self, input: Input, taken: Taken) -> Option<Ending> {
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
                self.write_input(take, reports, taken).await
            }
            Input::Key { take, .. } => {
                let (typed, action) = input.typed_key().expect("a key input names a key");
                self.key(take, &typed, action, taken).await
            }
            Input::Text { take, text } => {
                // Text is its UTF-8 in every encoding the view produces; the program's keyboard is
                // read only to know the view may write at all.
                if let Err(refused) = self.keyboard(take, "That text") {
                    let _ = taken.send(Err(refused));
                    return None;
                }
                self.write_or_nothing(take, text.into_bytes(), taken).await
            }
            Input::Paste { take, text } => {
                let keyboard = match self.keyboard(take, "That paste") {
                    Ok(keyboard) => keyboard,
                    Err(refused) => {
                        let _ = taken.send(Err(refused));
                        return None;
                    }
                };
                let bytes = encoder::paste(text.as_str(), keyboard.bracketed);
                if bytes.len() > kr_protocol::limits::MAX_INPUT_FRAME_LEN {
                    let _ = taken.send(Err(Refused::Unsent(keys::unsent(
                        "That paste",
                        "it is longer than one input can carry",
                    ))));
                    return None;
                }
                self.write_or_nothing(take, bytes, taken).await
            }
        }
    }

    /// Takes one of the person's keys: spelled in the encoding the program reads, and written only
    /// while the view controls the program under the take it names. A release is spelled from the
    /// press it ends, which the view recorded as it wrote it, and only where that press's encoding
    /// reports releases.
    async fn key(
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
                    let bytes = encoder::key(event, keyboard.encoding)?;
                    if kind == KeyEventKind::Press {
                        self.lease.pressed(
                            take,
                            typed.identity(),
                            Pressed {
                                event,
                                reported: encoder::release_reported(event, keyboard.encoding),
                            },
                        );
                    }
                    Ok(bytes)
                })
            }
            KeyAction::Release => match self.lease.released(take, &typed.identity()) {
                Some(pressed) if pressed.reported => encoder::release(
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
            Ok(bytes) => self.write_or_nothing(take, bytes, taken).await,
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
    async fn write_or_nothing(
        &mut self,
        take: u64,
        bytes: Vec<u8>,
        taken: Taken,
    ) -> Option<Ending> {
        if bytes.is_empty() {
            let _ = taken.send(Ok(()));
            return None;
        }
        self.write_input(take, bytes, taken).await
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
    /// The page is told the input is taken as soon as it has its place in the stream, before it is
    /// written: the write waits on the link, and the page's call never waits on it.
    async fn write_input(&mut self, take: u64, bytes: Vec<u8>, taken: Taken) -> Option<Ending> {
        let writing = match self.lease.write(take) {
            Ok(writing) => writing,
            Err(refusal) => {
                let _ = taken.send(Err(Refused::NotControlling(refusal)));
                return None;
            }
        };
        let _ = taken.send(Ok(()));
        let params = InputWriteParams {
            session_id: self.session_id,
            attachment_id: self.attachment.attachment_id,
            epoch: writing.epoch,
            sequence: writing.sequence,
            bytes: Bytes::new(bytes),
        };
        let Ok(params) = ParamsValue::from_typed(&params) else {
            return Some(Ending::ended("This view's input could not be written."));
        };
        let request_id = self.next_id();
        // Raw input is an ordered stream, not a mutation: it carries no action identifier and gets
        // no receipt, only the session's answer.
        let request = Request {
            request_id,
            method: Method::InputWrite.into(),
            method_version: MethodVersion::V1,
            params,
        };
        if !self.wire.send(&ControlFrame::Request(request)).await {
            return Some(self.lost());
        }
        self.lease.written(request_id, writing.epoch);
        None
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
    async fn launch_surface(&mut self, reply: Reply<LaunchSurfaceAnswer>) -> Option<Ending> {
        if self.serves_launch_surface == Some(false) {
            let _ = reply.send(Ok(LaunchSurfaceAnswer::NotServed));
            return None;
        }
        match self.ask_launch_surface().await {
            Ok(request_id) => {
                self.launch_reads.insert(
                    request_id,
                    LaunchRead {
                        stage: LaunchReadStage::Asked,
                        reply,
                    },
                );
                None
            }
            Err(ended) => Some(ended),
        }
    }

    async fn ask_launch_surface(&mut self) -> Result<RequestId, Ending> {
        let params = ShellLaunchSurfaceParams {
            session_id: self.session_id,
        };
        self.ask(Method::ShellLaunchSurface, &params).await
    }

    /// Takes the answer to a launch surface read, or to the read that tells a host that does not
    /// serve it from a grant that lost its right, and asks the next question or says the answer.
    async fn launch_surface_answered(&mut self, response: Response) -> Option<Ending> {
        let mut read = self.launch_reads.remove(&response.request_id)?;
        let step = launch_read_step(read.stage, self.serves_launch_surface, response.outcome);
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
            self.ask(Method::SessionRead, &params).await
        } else {
            self.ask_launch_surface().await
        };
        match asked {
            Ok(request_id) => {
                read.stage = stage;
                self.launch_reads.insert(request_id, read);
                None
            }
            Err(ended) => Some(ended),
        }
    }

    /// Presses a launch on this view's link. The session accepts it only from the connection whose
    /// attachment holds its input, and refuses a quote of a prompt that has moved before anything
    /// is typed; this view asks and says what the session answered.
    async fn launch(&mut self, press: Press, reply: Reply<ShellLaunchResult>) -> Option<Ending> {
        let params = press.for_session(self.session_id);
        let request_id = self.next_id();
        // Kept before the write: a write that failed may have left in part, and the launch is then
        // not known to have failed.
        self.launches.insert(request_id, reply);
        if !self
            .mutation(request_id, Method::ShellLaunch, &params)
            .await
        {
            return Some(self.lost());
        }
        None
    }

    /// Answers every launch still waiting when the view ends: the session may have installed it
    /// before the link went, so it is not known to have failed.
    fn end_launches(&mut self) {
        for reply in std::mem::take(&mut self.launches).into_values() {
            let _ = reply.send(Err(CommandError::stated(
                ErrorCode::OutcomeUnknown,
                LAUNCH_UNANSWERED,
            )));
        }
    }

    /// Writes one read on the link without waiting for its answer.
    async fn ask<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<RequestId, Ending> {
        let Ok(params) = ParamsValue::from_typed(params) else {
            return Err(Ending::ended("This view's request could not be written."));
        };
        let request_id = self.next_id();
        let request = Request {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            params,
        };
        if !self.wire.send(&ControlFrame::Request(request)).await {
            return Err(self.lost());
        }
        Ok(request_id)
    }

    /// Writes the detach, and leaves the link to close when the view is dropped: the worker
    /// detaches on either.
    async fn detach(&mut self) {
        let params = SessionDetachParams {
            attachment_id: Nullable::some(self.attachment.attachment_id),
            line_token: Nullable::null(),
        };
        let request_id = self.next_id();
        let _ = self
            .mutation(request_id, Method::SessionDetach, &params)
            .await;
    }

    /// Writes one mutation on the link without waiting for its answer. Returns whether it left.
    async fn mutation<T: serde::Serialize>(
        &mut self,
        request_id: RequestId,
        method: Method,
        params: &T,
    ) -> bool {
        let Ok(mutation) = self
            .wire
            .mutation(request_id, method, self.target.clone(), params)
        else {
            return false;
        };
        self.wire
            .send(&ControlFrame::Mutation(Box::new(mutation)))
            .await
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
    use super::{LaunchReadStage, Step, build_name, launch_read_step};
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
}
