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
use kr_protocol::ids::{ActionId, RequestId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64};
use kr_protocol::session::{Dimensions, SESSION_CLOSED_EVENT};
use kr_protocol::worker::WorkerDescriptor;
use tokio::sync::mpsc::UnboundedReceiver;

use super::screen::{TerminalViewState, state_of};
use super::window::{Answer, WindowReports};
use super::{Locate, Publish};

/// What the page asks of a view once it is open.
pub(super) enum Command {
    /// The page's grid is now this size.
    Resize(Dimensions),
    /// The page moved the window.
    Move(super::window::Move),
    /// The page is done with the view.
    Close,
}

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
    // The window's reports, which take the page's sizes and moves while the view is opening too.
    let mut window = WindowReports::new(dimensions);
    let opened = {
        let opening = open(locate, session_id, dimensions);
        tokio::pin!(opening);
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    Some(Command::Resize(size)) => window.measured(size),
                    Some(Command::Move(asked)) => window.take(asked),
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
        resubscription: None,
        replaced_stream: false,
        recoveries: 0,
        showing: false,
        held: false,
        drawn: None,
        told: 0,
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
    let descriptor = kr_ipc::descriptor::read(&paths, session_id)
        .map_err(|error| {
            format!(
                "This session's details could not be read: {}",
                Shown::ipc(&error)
            )
        })?
        .ok_or_else(|| "This session is not running on this computer.".to_owned())?;
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint)
        .map_err(|error| format!("This session could not be reached: {}", Shown::ipc(&error)))?;
    let build_id = crate::connection::build_id().map_err(|error| error.message)?;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build_id)
        .await
        .map_err(|error| format!("This session could not be reached: {}", Shown::ipc(&error)))?;
    // A descriptor is data on disk. Nothing is sent until the worker behind the endpoint has signed
    // a challenge only the descriptor's key could answer.
    client.verify_worker(&descriptor).await.map_err(|error| {
        format!(
            "This session's worker could not prove who it is: {}",
            Shown::ipc(&error)
        )
    })?;
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    // No terminal profile, so the host shows this view a viewport of the session, which is what a
    // terminal nobody has qualified is shown; and no geometry claim, so opening a view never takes
    // the session's size from anyone.
    let params = SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(dimensions),
        terminal_profile_id: Nullable::null(),
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
                if !self.held {
                    self.show();
                }
                None
            }
            Applied::Updated(_) => {
                if !self.held {
                    self.show();
                }
                None
            }
            Applied::Refused(_) => self.recover().await,
        }
    }

    async fn response(&mut self, response: Response) -> Option<Ending> {
        if self.window.is_in_flight(response.request_id) {
            // A refusal settles the report and changes nothing; an acceptance settles it once a
            // screen naming its revision has arrived, whichever came first. A screen that waited
            // for this answer is drawn now, with what the answer settled.
            let answer = match response.outcome {
                Outcome::Ok(value) => {
                    value
                        .to_typed::<AttachmentViewportResult>()
                        .map_or(Answer::Refused, |result| Answer::Accepted {
                            window_revision: result.window_revision.get(),
                        })
                }
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
        self.tell();
        None
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
        (self.publish)(state_of(&self.attachment, screen, self.told));
    }
}
