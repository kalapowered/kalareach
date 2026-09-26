//! One raw terminal view's task: its link to the session's worker, its attachment, the screen the
//! client library holds for it, and the size it reports.
//!
//! The task opens the link, attaches and subscribes, and then reads the link in one loop, the way
//! the CLI's attach loop does: every report and resubscription is written without waiting for its
//! answer, and the answer is matched by its request number when it arrives. A call that waited
//! would let an answer to another call arrive first, and would keep the page's own close waiting on
//! the host.
//!
//! The window stays on the live screen. The view reports only its size: one report at a time, the
//! newest measurement sent once the last report is answered, and a size equal to the one last sent
//! not sent at all.

use kr_client::projection::{Applied, Projection, decode, is_projection_event};
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentSummary, AttachmentViewportParams,
    SessionAttachParams, SessionAttachResult, SessionDetachParams,
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
use super::{Locate, Publish};

/// What the page asks of a view once it is open.
pub(super) enum Command {
    /// The page's grid is now this size.
    Resize(Dimensions),
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
    // The newest size the page measured, which may change while the view is opening.
    let mut wanted = dimensions;
    let opened = {
        let opening = open(locate, session_id, dimensions);
        tokio::pin!(opening);
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    Some(Command::Resize(size)) => wanted = size,
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
        wanted,
        last_sent: dimensions,
        report: None,
        resubscription: None,
        replaced_stream: false,
        recoveries: 0,
        showing: false,
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
    /// The newest size the page measured.
    wanted: Dimensions,
    /// The size of the last report sent, or of the attach before any.
    last_sent: Dimensions,
    /// The report waiting for its answer.
    report: Option<RequestId>,
    /// The resubscription waiting for its answer.
    resubscription: Option<RequestId>,
    /// Whether the stream a resubscription replaced is still being dropped: until the new stream's
    /// first notification, at sequence 0, everything of the old one that still arrives is stale.
    replaced_stream: bool,
    /// Recoveries since the last complete screen.
    recoveries: u32,
    /// Whether the page was last told of a screen.
    showing: bool,
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
        if let Some(ended) = self.report_if_needed().await {
            return ended;
        }
        loop {
            let next = tokio::select! {
                // The page first: a close is answered before anything more is read or drawn.
                biased;
                command = commands.recv() => Next::Command(command),
                frame = self.client.recv() => Next::Frame(frame),
            };
            let ended = match next {
                Next::Command(Some(Command::Resize(size))) => {
                    self.wanted = size;
                    self.report_if_needed().await
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
                self.waiting();
                None
            }
            // Nothing is drawn from a snapshot until its last page.
            Applied::Installing => None,
            Applied::Installed => {
                self.recoveries = 0;
                self.show();
                None
            }
            Applied::Updated(_) => {
                self.show();
                None
            }
            Applied::Refused(_) => self.recover().await,
        }
    }

    async fn response(&mut self, response: Response) -> Option<Ending> {
        if self.report == Some(response.request_id) {
            // Accepted or refused, the report is answered: the newest measurement goes if it
            // differs from the size sent. A refused size is not sent again until another is
            // measured, and a size measured meanwhile is not lost.
            self.report = None;
            return self.report_if_needed().await;
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

    /// Sends the newest measurement, when nothing is outstanding and it differs from the size last
    /// sent. The window stays on the live screen from its first line and column, so a report names
    /// no position and the first column.
    async fn report_if_needed(&mut self) -> Option<Ending> {
        if self.report.is_some() || self.wanted == self.last_sent {
            return None;
        }
        let params = AttachmentViewportParams {
            attachment_id: self.attachment.attachment_id,
            dimensions: self.wanted,
            position: Nullable::null(),
            column: U64::ZERO,
        };
        let request_id = self.next_id();
        if !self
            .mutation(request_id, Method::AttachmentViewport, &params)
            .await
        {
            return Some(Ending::lost());
        }
        self.report = Some(request_id);
        self.last_sent = self.wanted;
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

    fn publish_state(&self) {
        (self.publish)(state_of(&self.attachment, self.projection.screen()));
    }
}
