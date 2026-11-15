//! A device's typing, sent as its client sends it: through the client's input lane.
//!
//! [`Typing`] opens the lane of one attachment on a connection, begins the lease epoch the
//! attachment holds, sends bytes, and returns once the host has accepted them. A suite that types
//! uses this and nothing else, so that none of them depends on which way the host carries the
//! typing to the worker.

use std::time::{Duration, Instant};

use kr_client::error::ClientError;
use kr_client::input::{
    EndCause, InputEvent, InputEvents, InputLane, InputRefusal, InputTarget, Writing,
};
use kr_client::session::Session;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AttachmentId, EnvironmentId, InputLeaseEpoch, SessionId};
use kr_transport::TransportError;

/// How long [`Typing::type_bytes`] waits for the host to accept what it sent. A host that holds the
/// stream open and accepts nothing would otherwise hold the case for good.
const ACCEPTANCE_WAIT: Duration = Duration::from_secs(60);

/// How long after it began an open may end and still be the host's refusal. The client waits ten
/// seconds for the host's first word and the host's admission ends near ten, so an open that ended
/// later than this ran out of time and was not refused.
const OPEN_REFUSED_WITHIN: Duration = Duration::from_secs(8);

/// How the host turned away typing that names an attachment which the connection did not make.
///
/// The two paths to the worker answer differently, and a case that holds either takes no side. A
/// worker that serves the input lane binds a lane only for an attachment that the connection's own
/// proxy owns, so the host ends the stream before its first word. A worker that does not takes each
/// frame as a request on the proxy's link, refuses it, and the host ends the stream or tells the
/// refusal after the lane has opened.
#[derive(Debug)]
pub enum TurnedAway {
    /// The lane path: the host ended the stream before its first word.
    Open(String),
    /// The serial path: the lane opened and the host turned the frame away.
    Frame(String),
}

impl std::fmt::Display for TurnedAway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(why) => write!(formatter, "the lane path answered: {why}"),
            Self::Frame(why) => write!(formatter, "the serial path answered: {why}"),
        }
    }
}

/// Why bytes were not typed.
#[derive(Debug)]
pub enum NotTyped {
    /// The lane did not open.
    Opening(ClientError),
    /// The lane did not take the bytes or the epoch.
    Admitting(InputRefusal),
    /// The host refused a frame, and with it the rest of the epoch.
    Refused(ProtocolError),
    /// The host said the attachment no longer holds the lease of this epoch.
    LeaseEnded(InputLeaseEpoch),
    /// The lane ended before the host accepted the bytes.
    Ended(EndCause),
    /// The bound ran out. The text says what the wait was for.
    Waited(String),
}

impl NotTyped {
    /// The code the host refused the typing with, when the host's own word says one: its refusal
    /// of the open, or of a frame. A lane that did not open for another reason (the stream was
    /// reset, or the open timed out) gives none, so that a case cannot take it for a refusal.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Opening(ClientError::Host(refusal)) | Self::Refused(refusal) => {
                Some(refusal.code)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for NotTyped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opening(error) => write!(formatter, "the input lane did not open: {error}"),
            Self::Admitting(refusal) => {
                write!(
                    formatter,
                    "the input lane did not take the typing: {refusal:?}"
                )
            }
            Self::Refused(error) => write!(formatter, "the host refused the typing: {error}"),
            Self::LeaseEnded(epoch) => write!(
                formatter,
                "the host said the attachment no longer holds the lease of epoch {}",
                epoch.get()
            ),
            Self::Ended(cause) => {
                write!(
                    formatter,
                    "the input lane ended before the typing was accepted: {}",
                    end_words(cause)
                )
            }
            Self::Waited(what) => write!(formatter, "waited {ACCEPTANCE_WAIT:?} for {what}"),
        }
    }
}

/// What a lane's end says, in words: the cause's own debug text hides what it holds.
fn end_words(cause: &EndCause) -> String {
    match cause {
        EndCause::Reset => "the stream was reset while the connection stood".to_owned(),
        EndCause::Finished => "the lane finished its side".to_owned(),
        EndCause::Connection { refusal: None } => "the connection ended".to_owned(),
        EndCause::Connection {
            refusal: Some(refusal),
        } => format!("the host ended the connection: {refusal}"),
        EndCause::Breach(why) => format!("the host broke the stream's contract: {why}"),
        EndCause::Uncertain(error) => {
            format!("the host's answer does not say whether the typing was accepted: {error}")
        }
        EndCause::Closed => "the lane was dropped".to_owned(),
    }
}

/// The input lane of one attachment, with the events it tells.
#[derive(Debug)]
pub struct Typing {
    lane: InputLane,
    events: InputEvents,
    epoch: Option<InputLeaseEpoch>,
}

impl Typing {
    /// Opens the lane of `attachment_id` on `session`.
    ///
    /// # Errors
    ///
    /// Returns [`NotTyped::Opening`] when the host does not take the lane.
    pub async fn open(
        session: &Session,
        environment_id: EnvironmentId,
        session_id: SessionId,
        attachment_id: AttachmentId,
    ) -> Result<Self, NotTyped> {
        let lane = session
            .input_lane(InputTarget::new(environment_id, session_id, attachment_id))
            .await
            .map_err(NotTyped::Opening)?;
        let events = lane.events().expect("a new lane tells its events once");
        Ok(Self {
            lane,
            events,
            epoch: None,
        })
    }

    /// Opens the lane of `attachment_id` and says, in words, when the host ended the stream before
    /// its first word.
    ///
    /// The connection must have its route to the worker already, which a request that names the
    /// session fixes: without it the host's admission waits for a route and ends near its own
    /// deadline, and that end is no refusal.
    ///
    /// # Errors
    ///
    /// Returns what happened, in words, when the lane opened, when the open ran out of time (the
    /// client's own deadline, or an end later than [`OPEN_REFUSED_WITHIN`]), or when it failed in
    /// any other way.
    pub async fn refused_open(
        session: &Session,
        environment_id: EnvironmentId,
        session_id: SessionId,
        attachment_id: AttachmentId,
    ) -> Result<String, String> {
        match Self::open_judged(session, environment_id, session_id, attachment_id).await? {
            Ok(_lane) => Err("the lane opened".to_owned()),
            Err(ended) => Ok(ended),
        }
    }

    /// Puts typing for an attachment that this connection did not make to the host, under the
    /// lease epoch the attachment held, and says how the host turned it away.
    ///
    /// The connection must have its route to the worker already (see [`Self::refused_open`]).
    ///
    /// # Errors
    ///
    /// Returns what happened, in words, when the typing was not turned away: the lane's open ran
    /// out of time or failed in another way, the host accepted the bytes, or its answer was not a
    /// refusal, an end of the lease or an end of the stream.
    pub async fn replay(
        session: &Session,
        environment_id: EnvironmentId,
        session_id: SessionId,
        attachment_id: AttachmentId,
        epoch: InputLeaseEpoch,
        bytes: &[u8],
    ) -> Result<TurnedAway, String> {
        let mut lane =
            match Self::open_judged(session, environment_id, session_id, attachment_id).await? {
                Ok(lane) => lane,
                Err(ended) => return Ok(TurnedAway::Open(ended)),
            };
        match lane.type_bytes(epoch, bytes).await {
            Ok(written) => Err(format!("the host accepted the typing: {written:?}")),
            Err(NotTyped::Refused(error)) if error.code != ErrorCode::OutcomeUnknown => {
                Ok(TurnedAway::Frame(format!(
                    "the lane opened and the host refused the frame: {error}"
                )))
            }
            Err(NotTyped::LeaseEnded(told)) => Ok(TurnedAway::Frame(format!(
                "the lane opened and the host said the attachment no longer holds the lease of epoch {}",
                told.get()
            ))),
            Err(ended @ NotTyped::Ended(EndCause::Reset)) => Ok(TurnedAway::Frame(format!(
                "the lane opened and the host ended the stream while the connection stood: {ended}"
            ))),
            Err(other) => Err(format!(
                "the lane opened and the typing was not turned away by the host: {other}"
            )),
        }
    }

    /// Opens the lane. The outer error is a failure to turn away in words; the inner one is the
    /// host ending the stream before its first word, in time.
    async fn open_judged(
        session: &Session,
        environment_id: EnvironmentId,
        session_id: SessionId,
        attachment_id: AttachmentId,
    ) -> Result<Result<Self, String>, String> {
        let begun = Instant::now();
        match Self::open(session, environment_id, session_id, attachment_id).await {
            Ok(lane) => Ok(Ok(lane)),
            Err(NotTyped::Opening(ClientError::Transport(TransportError::Stream(why)))) => {
                let took = begun.elapsed();
                if took < OPEN_REFUSED_WITHIN {
                    Ok(Err(format!(
                        "the host ended the stream before its first word, {took:?} after the open began ({why})"
                    )))
                } else {
                    Err(format!(
                        "the open ended {took:?} after it began, near the admission's deadline: it ran out of time and was not refused ({why})"
                    ))
                }
            }
            Err(NotTyped::Opening(ClientError::Transport(TransportError::Deadline(kind)))) => {
                Err(format!(
                    "the open ran out of time ({kind:?} deadline of the client): it was not refused"
                ))
            }
            Err(other) => Err(format!(
                "the lane did not open, and not because the host ended the stream: {other}"
            )),
        }
    }

    /// The lane itself, for a case that needs more of it than typing and waiting.
    #[must_use]
    pub const fn lane(&self) -> &InputLane {
        &self.lane
    }

    /// The events of the lane, for a case that reads them itself.
    pub const fn events(&mut self) -> &mut InputEvents {
        &mut self.events
    }

    /// Sends `bytes` as the next frame of `epoch`, and returns once the host has accepted it.
    ///
    /// `epoch` is the lease epoch the attachment holds. A lane begins an epoch when this is the
    /// first typing under it, and goes on with the sequences of the epoch it has after that.
    ///
    /// # Errors
    ///
    /// Returns what stopped the typing: the lane's refusal of the bytes or of the epoch, the host's
    /// refusal, the end of the epoch's lease or of the lane, or the bound running out.
    pub async fn type_bytes(
        &mut self,
        epoch: InputLeaseEpoch,
        bytes: &[u8],
    ) -> Result<Writing, NotTyped> {
        if self.epoch != Some(epoch) {
            self.lane.begin_epoch(epoch).map_err(NotTyped::Admitting)?;
            self.epoch = Some(epoch);
        }
        let writing = self.lane.try_send(bytes).map_err(NotTyped::Admitting)?;
        let sequence = writing
            .sequence
            .expect("a frame sent with no hold takes its sequence at once");
        let waited = tokio::time::timeout(ACCEPTANCE_WAIT, async {
            loop {
                let Some(event) = self.events.recv().await else {
                    return Err(NotTyped::Ended(EndCause::Closed));
                };
                match event {
                    InputEvent::Accepted {
                        epoch: told,
                        through,
                        ..
                    } if told == epoch && through.get() >= sequence.get() => return Ok(()),
                    InputEvent::Refused {
                        epoch: told, error, ..
                    } if told == epoch => return Err(NotTyped::Refused(error)),
                    InputEvent::EpochEnded { epoch: told, .. } if told == epoch => {
                        return Err(NotTyped::LeaseEnded(told));
                    }
                    InputEvent::Ended { cause, .. } => return Err(NotTyped::Ended(cause)),
                    // An older epoch's words, and what a case that only types has no use for.
                    _ => {}
                }
            }
        })
        .await;
        match waited {
            Ok(accepted) => accepted.map(|()| writing),
            Err(_) => Err(NotTyped::Waited(format!(
                "the host to accept {} bytes of epoch {} as frame {}",
                writing.bytes,
                epoch.get(),
                sequence.get()
            ))),
        }
    }
}
