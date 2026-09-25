//! A paired device's attachment to a session, and the screen it holds.
//!
//! The device attaches in terminal mode, asking to observe and to type, and subscribes to the
//! session's output. What it is sent is one of two things, which the worker decides per
//! attachment: the canonical grid as a projection, or its own byte stream, whose first bytes are a
//! rendering of the screen as it stands. The device holds whichever arrives: a projection through
//! the client library's own [`Projection`], and bytes through the product's terminal engine at the
//! session's canonical size. Either way what the device shows is the screen the session has now,
//! never the history that made it.
//!
//! Typing is explicit. A network client never takes the input lease implicitly: it asks for it,
//! and every write names the lease's epoch and its place in the connection's ordered input stream.

use std::time::Duration;

use kr_client::cursors::{Restoration, StreamCursors};
use kr_client::projection::{Applied, Projection};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    SessionDetachParams, SessionDetachResult,
};
use kr_protocol::envelope::{ActionTarget, Notification};
use kr_protocol::ids::{
    AttachmentId, InputLeaseEpoch, InputSequence, QuestionId, QuestionRevision, SessionEpoch,
    SessionId, StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputWriteParams, InputWriteResult,
};
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionReadParams, QuestionReadResult,
    QuestionResolveResult, QuestionState,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeResult, OutputEvent};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable};
use kr_protocol::session::{ClosureRecord, Dimensions, SESSION_CLOSED_EVENT};

use crate::device::Remote;
use crate::screen::{Terminal, projection_rows};

/// The terminal profile a device's attachment declares.
pub const TERMINAL_PROFILE: &str = "xterm-256color";

/// The stream a session's output travels on.
#[must_use]
pub fn output_stream() -> StreamId {
    StreamId::new("session.output").expect("a stream identifier")
}

/// The target of a request about one session.
#[must_use]
pub fn session_target(remote: &Remote, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id: remote.environment_id(),
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// One attachment and what it has been sent.
pub struct View {
    session_id: SessionId,
    attachment_id: AttachmentId,
    events: tokio::sync::broadcast::Receiver<Notification>,
    projection: Projection,
    direct: Terminal,
    output: Vec<u8>,
    kinds: Vec<String>,
    closed: Option<ClosureRecord>,
    lease: Option<(InputLeaseEpoch, u64)>,
    acknowledged: u64,
    subscribed: EventsSubscribeResult,
}

impl std::fmt::Debug for View {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("View")
            .field("attachment_id", &self.attachment_id)
            .finish_non_exhaustive()
    }
}

impl View {
    /// Attaches to `session_id` with a screen of `dimensions`, and subscribes to its output from
    /// the cursor the device's own cursors hold, or from the session's current one when they hold
    /// none.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn attach(
        remote: &Remote,
        session_id: SessionId,
        dimensions: Dimensions,
        cursors: &StreamCursors,
    ) -> Result<Self, String> {
        // Subscribed to the connection's events before the attachment exists, so nothing the
        // session sends it can arrive before anything is listening.
        let events = remote.session().events();
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: SessionAttachResult = remote
            .mutate(
                Method::SessionAttach,
                session_target(remote, session_id),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    // What the device's keys mean: it types the ordinary terminal encoding, and an
                    // attachment that did not say so could not be given the lease.
                    terminal_profile_id: Nullable::some(TERMINAL_PROFILE.to_owned()),
                    requested,
                },
            )
            .await
            .map_err(|error| format!("session.attach: {error}"))?;
        let attachment_id = attached.attachment.attachment_id;
        let dimensions = attached.geometry.dimensions;
        let columns = u16::try_from(dimensions.columns.get()).unwrap_or(u16::MAX);
        let rows = u16::try_from(dimensions.rows.get()).unwrap_or(u16::MAX);
        // Section 8's order: subscribe from the cursor first; what the subscription returns is
        // then installed, and live output queues behind it.
        let mut restoration = Restoration::start(output_stream(), cursors);
        let mut params = restoration
            .subscribe_params(session_id, attachment_id, &[EventStream::Output])
            .map_err(|error| format!("the restoration's order: {error:?}"))?;
        params.streams.insert(EventStream::SessionState);
        let subscribed: EventsSubscribeResult = remote
            .session()
            .subscribe_events(&params)
            .await
            .map_err(|error| format!("events.subscribe: {error}"))?;
        restoration
            .subscribed()
            .map_err(|error| format!("the restoration's order: {error:?}"))?;
        Ok(Self {
            session_id,
            attachment_id,
            events,
            projection: Projection::new(),
            direct: Terminal::new(columns, rows),
            output: Vec::new(),
            kinds: Vec::new(),
            closed: None,
            lease: None,
            acknowledged: 0,
            subscribed,
        })
    }

    /// The attachment's identifier.
    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.attachment_id
    }

    /// What the subscription returned.
    #[must_use]
    pub const fn subscribed(&self) -> &EventsSubscribeResult {
        &self.subscribed
    }

    /// Every byte of output this attachment was sent.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// The type of every event this attachment was sent, in order.
    #[must_use]
    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }

    /// How the session closed, once the attachment has been told.
    #[must_use]
    pub const fn closed(&self) -> Option<&ClosureRecord> {
        self.closed.as_ref()
    }

    /// How many of this attachment's inputs the host has acknowledged.
    #[must_use]
    pub const fn acknowledged(&self) -> u64 {
        self.acknowledged
    }

    /// Whether the screen this attachment holds is a projection rather than its byte stream.
    #[must_use]
    pub fn projected(&self) -> bool {
        self.projection.screen().is_some()
    }

    /// The screen this attachment holds, as text.
    #[must_use]
    pub fn rows(&mut self) -> Vec<String> {
        projection_rows(&self.projection).unwrap_or_else(|| self.direct.rows())
    }

    /// Applies everything the connection has for this attachment, waiting at most `within` for the
    /// first of it.
    ///
    /// # Errors
    ///
    /// Returns the connection ending, or an update the projection had to refuse and the fresh
    /// screen that was asked for in its place failing.
    pub async fn pump(&mut self, remote: &Remote, within: Duration) -> Result<(), String> {
        let notification = match tokio::time::timeout(within, self.events.recv()).await {
            Err(_) => return Ok(()),
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(missed))) => {
                return Err(format!("the device fell {missed} events behind"));
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err("the connection ended".to_owned());
            }
            Ok(Ok(notification)) => notification,
        };
        self.apply(remote, &notification).await?;
        // Everything already waiting is taken before returning, without waiting for more.
        while let Ok(notification) = self.events.try_recv() {
            self.apply(remote, &notification).await?;
        }
        Ok(())
    }

    async fn apply(&mut self, remote: &Remote, notification: &Notification) -> Result<(), String> {
        let kind = notification.event_type.as_str().to_owned();
        self.kinds.push(kind.clone());
        let stream = output_stream();
        match kind.as_str() {
            "session.output" => {
                let event: OutputEvent = notification
                    .payload
                    .to_typed()
                    .map_err(|error| format!("an output event: {error}"))?;
                self.output.extend_from_slice(event.bytes.as_slice());
                self.direct.feed(event.bytes.as_slice());
                remote
                    .session()
                    .applied_content(&stream, event.cursor)
                    .await;
            }
            SESSION_CLOSED_EVENT => {
                let record: ClosureRecord = notification
                    .payload
                    .to_typed()
                    .map_err(|error| format!("a closure event: {error}"))?;
                self.closed = Some(record);
            }
            other if kr_client::projection::is_projection_event(other) => {
                let Some(event) = kr_client::projection::decode(other, &notification.payload)
                else {
                    return Err(format!("a {other} event this client cannot read"));
                };
                if let Applied::Refused(refusal) = self.projection.apply(event) {
                    // The update continues from a screen this attachment does not hold. A fresh one
                    // is asked for, which is what the contract says to do.
                    eprintln!("the device asks for a fresh screen: {refusal:?}");
                    self.resubscribe(remote).await?;
                }
            }
            _ => {}
        }
        remote
            .session()
            .applied(&stream, notification.sequence)
            .await;
        Ok(())
    }

    async fn resubscribe(&mut self, remote: &Remote) -> Result<(), String> {
        self.projection.discard();
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        streams.insert(EventStream::SessionState);
        self.subscribed = remote
            .session()
            .subscribe_events(&kr_protocol::recovery::EventsSubscribeParams {
                session_id: self.session_id,
                attachment_id: self.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            })
            .await
            .map_err(|error| format!("events.subscribe again: {error}"))?;
        Ok(())
    }

    /// Applies what arrives until the screen shows `needle`, and returns the screen.
    ///
    /// # Errors
    ///
    /// Returns the screen it holds when `needle` has not appeared within `within`.
    pub async fn wait_for(
        &mut self,
        remote: &Remote,
        needle: &str,
        within: Duration,
    ) -> Result<Vec<String>, String> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let rows = self.rows();
            if rows.iter().any(|row| row.contains(needle)) {
                return Ok(rows);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "the device's screen did not show {needle:?} within {within:?}:\n{}",
                    rows.join("\n")
                ));
            }
            self.pump(remote, left.min(Duration::from_millis(500)))
                .await?;
        }
    }

    /// Applies what arrives until the attachment is told the session closed, and returns what it
    /// was told.
    ///
    /// # Errors
    ///
    /// Returns the event types it was sent when no closure arrived within `within`.
    pub async fn wait_until_closed(
        &mut self,
        remote: &Remote,
        within: Duration,
    ) -> Result<ClosureRecord, String> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(closed) = &self.closed {
                return Ok(closed.clone());
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "the device was not told the session closed within {within:?}; it was sent \
                     {:?}",
                    self.kinds
                ));
            }
            match self
                .pump(remote, left.min(Duration::from_millis(500)))
                .await
            {
                Ok(()) => {}
                // The connection ending after the closure arrived is the worker going with it.
                Err(_) if self.closed.is_some() => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Takes the input lease for this attachment.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn acquire(&mut self, remote: &Remote) -> Result<InputAcquireResult, String> {
        let acquired: InputAcquireResult = remote
            .mutate(
                Method::InputAcquire,
                session_target(remote, self.session_id),
                &InputAcquireParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .map_err(|error| format!("input.acquire: {error}"))?;
        self.lease = Some((acquired.lease.epoch, acquired.lease.next_sequence.get()));
        Ok(acquired)
    }

    /// Types `text` under the lease this attachment holds, and requires the host to acknowledge
    /// it: consumed at the place in the connection's ordered input stream it was sent at, with
    /// every byte forwarded to the terminal.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, that this attachment holds no lease, or an acknowledgement that
    /// is not of these bytes.
    pub async fn type_text(
        &mut self,
        remote: &Remote,
        text: &str,
    ) -> Result<InputWriteResult, String> {
        let (epoch, sequence) = self.lease.ok_or("this attachment holds no input lease")?;
        let written = remote
            .session()
            .write_input(&InputWriteParams {
                session_id: self.session_id,
                attachment_id: self.attachment_id,
                epoch,
                sequence: InputSequence::new(sequence),
                bytes: Bytes::new(text.as_bytes().to_vec()),
            })
            .await
            .map_err(|error| format!("input.write: {error}"))?;
        let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
        if written.sequence.get() != sequence || written.forwarded_bytes.get() != length {
            return Err(format!(
                "input {sequence} of {length} bytes was acknowledged as {} with {} bytes forwarded",
                written.sequence.get(),
                written.forwarded_bytes.get()
            ));
        }
        self.acknowledged += 1;
        self.lease = Some((epoch, sequence + 1));
        Ok(written)
    }

    /// Detaches this attachment.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn detach(&self, remote: &Remote) -> Result<SessionDetachResult, String> {
        remote
            .mutate(
                Method::SessionDetach,
                session_target(remote, self.session_id),
                &SessionDetachParams {
                    attachment_id: Nullable::some(self.attachment_id),
                    line_token: Nullable::null(),
                },
            )
            .await
            .map_err(|error| format!("session.detach: {error}"))
    }
}

/// Reads the questions in `session_id` that are still pending, at the revisions the host shows.
///
/// # Errors
///
/// Returns the host's refusal.
pub async fn pending_questions(
    remote: &Remote,
    session_id: SessionId,
) -> Result<Vec<Question>, String> {
    let read: QuestionReadResult = remote
        .read(
            Method::QuestionRead,
            &QuestionReadParams {
                session_id,
                question_id: Nullable::null(),
                include_resolved: false,
            },
        )
        .await
        .map_err(|error| format!("question.read: {error}"))?;
    Ok(read
        .questions
        .into_iter()
        .filter(|question| question.state == QuestionState::Pending)
        .collect())
}

/// Answers one question with free text, against the exact revision named.
///
/// # Errors
///
/// Returns the host's refusal.
pub async fn answer_question(
    remote: &Remote,
    session_id: SessionId,
    question_id: QuestionId,
    revision: QuestionRevision,
    text: &str,
) -> Result<QuestionResolveResult, String> {
    remote
        .mutate(
            Method::QuestionAnswer,
            session_target(remote, session_id),
            &QuestionAnswerParams {
                session_id,
                question_id,
                expected_revision: revision,
                answer: QuestionAnswer::Input {
                    text: text.to_owned(),
                },
            },
        )
        .await
        .map_err(|error| format!("question.answer: {error}"))
}
