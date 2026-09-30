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

use kr_client::encoder::{self, KeyEventKind, Modifiers};
use kr_client::projection::{Applied, Projection, decode, is_projection_event};
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentSummary, AttachmentViewportParams,
    AttachmentViewportResult, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Notification, Outcome, ParamsValue, Request,
    Response,
};
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::ids::{ActionId, BuildId, RequestId, SessionId};
use kr_protocol::input::{InputAcquireParams, InputReleaseParams, InputWriteParams};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{Bytes, CanonicalSet, DurationMs, Nullable, U64};
use kr_protocol::session::{Dimensions, SESSION_CLOSED_EVENT};
use kr_protocol::worker::WorkerDescriptor;
use tokio::sync::mpsc::UnboundedReceiver;

use super::input::{Input, Lease, Owed, PROFILE, Refused, wheel_reports};
use super::keys::{self, KeyAction, Keyboard, Pressed, TypedKey};
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
    /// The page is done with the view.
    Close,
}

/// Where a view says whether it took an input: at once, or why it did not.
pub(super) type Taken = tokio::sync::oneshot::Sender<Result<(), Refused>>;

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
const LOOP_REQUESTS: u64 = 1 << 32;

/// The event a view is sent when the session asks it to take its screen again.
const RESYNC_EVENT: &str = "session.resync";

/// The event a view is sent when its attachment was ended somewhere else.
const DETACHED_EVENT: &str = "session.detached";

/// What the open answered: the link, the worker it reaches, and the attachment.
struct Opened {
    client: LocalClient,
    descriptor: WorkerDescriptor,
    attached: SessionAttachResult,
}

/// Runs one view from its open until it ends or is closed.
pub(super) async fn run(
    locate: &Locate,
    session_id: SessionId,
    dimensions: Dimensions,
    mut commands: UnboundedReceiver<Command>,
    publish: &Publish,
) {
    // The window's reports, which take the page's sizes and moves while the view is opening too, and
    // control of the program, which a take made while it opens asks for once it is attached.
    let mut window = WindowReports::new(dimensions);
    let mut lease = Lease::default();
    let opened = {
        let opening = open(locate, session_id, dimensions);
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
                    // A close while the view opens cancels the open. The link goes with it, and a
                    // closed connection detaches whatever the attach had made.
                    Some(Command::Close) | None => return,
                },
                opened = &mut opening => break opened,
            }
        }
    };
    let opened = match opened {
        Ok(opened) => opened,
        Err(reason) => {
            publish(TerminalViewState::Ended { reason });
            return;
        }
    };
    let mut view = View {
        client: opened.client,
        target: target(&opened.descriptor),
        session_id,
        attachment: opened.attached.attachment,
        projection: Projection::new(),
        next_request: LOOP_REQUESTS,
        window,
        lease,
        resubscription: None,
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
    if let Some(reason) = ended.reason {
        (view.publish)(TerminalViewState::Ended { reason });
    }
    if ended.detach {
        view.detach().await;
    }
}

/// Opens the link, has the worker prove who it is, attaches and subscribes.
async fn open(
    locate: &Locate,
    session_id: SessionId,
    dimensions: Dimensions,
) -> Result<Opened, String> {
    let paths = locate()?;
    // A descriptor is data on disk. Nothing is sent until the worker behind the endpoint has signed
    // a challenge only the descriptor's key could answer.
    let crate::worker::Reached {
        mut client,
        descriptor,
    } = crate::worker::reach(&paths, session_id)
        .await
        .map_err(crate::worker::Unreached::words)?;
    // The worker has proved who it is, and it says what it is: the attach waits on its screens, so
    // a worker whose screens this view cannot read is refused before it is asked for anything.
    check_build(client.acknowledgement().build.as_ref())?;
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
    let answer = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&descriptor),
            &params,
        )
        .await
        .map_err(|error| lost(&error))?
        .map_err(|refusal| format!("The session refused this view: {}", refusal.message))?;
    let attached: SessionAttachResult = answer.to_typed().map_err(|error| {
        format!(
            "The session's answer could not be read: {}",
            Shown::cbor(&error)
        )
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
    client
        .request(Method::EventsSubscribe, &subscribe)
        .await
        .map_err(|error| lost(&error))?
        .map_err(|refusal| {
            format!(
                "The session refused this view's screen: {}",
                refusal.message
            )
        })?;
    Ok(Opened {
        client,
        descriptor,
        attached,
    })
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
fn lost(error: &kr_ipc::IpcError) -> String {
    format!(
        "The connection to this session ended: {}",
        Shown::ipc(error)
    )
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
    /// Whether the attachment still stands on a link that still stands, so the view detaches it
    /// before the link closes.
    detach: bool,
}

impl Ending {
    /// The page closed the view.
    const CLOSED: Self = Self {
        reason: None,
        detach: true,
    };

    /// The view ends, for `reason`, with its attachment and its link still there.
    fn ended(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
            detach: true,
        }
    }

    /// The attachment is already over, for `reason`: the session closed, or it was detached.
    fn over(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
            detach: false,
        }
    }

    /// The link is gone, and the attachment with it.
    fn lost() -> Self {
        Self::over("The connection to this session ended.")
    }
}

/// One open, attached view.
struct View {
    client: LocalClient,
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
    Frame(Result<ControlFrame, kr_ipc::IpcError>),
}

impl View {
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
                frame = self.client.recv() => Next::Frame(frame),
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
                Next::Command(Some(Command::Close) | None) => Some(Ending::CLOSED),
                Next::Frame(Ok(ControlFrame::Notification(notification))) => {
                    self.notification(notification).await
                }
                Next::Frame(Ok(ControlFrame::Response(response))) => self.response(response).await,
                Next::Frame(Ok(_)) => None,
                Next::Frame(Err(_)) => Some(Ending::lost()),
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
        if self
            .client
            .writer()
            .write_message(&ControlFrame::Request(request))
            .await
            .is_err()
        {
            return Some(Ending::lost());
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
                return Some(Ending::lost());
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
                return Some(Ending::lost());
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
        if self
            .client
            .writer()
            .write_message(&ControlFrame::Request(request))
            .await
            .is_err()
        {
            return Some(Ending::lost());
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
        let Ok(params) = ParamsValue::from_typed(params) else {
            return false;
        };
        let mutation = MutationRequest {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: self.target.clone(),
            expected: ParamsValue::empty(),
            action_window_id: self.client.action_window().action_window_id.clone(),
            requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
            params,
        };
        self.client
            .writer()
            .write_message(&ControlFrame::Mutation(Box::new(mutation)))
            .await
            .is_ok()
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
    use super::build_name;
    use kr_protocol::ids::BuildId;

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
}
