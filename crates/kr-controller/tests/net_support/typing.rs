//! A device's typing, sent as its client sends it: through the client's input lane.
//!
//! [`Typing`] opens the lane of one attachment on a connection, begins the lease epoch the
//! attachment holds, sends bytes, and returns once the host has accepted them. A suite that types
//! uses this and nothing else, so that none of them depends on which way the host carries the
//! typing to the worker.

use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::input::{
    EndCause, InputEvent, InputEvents, InputLane, InputRefusal, InputTarget, Writing,
};
use kr_client::session::Session;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AttachmentId, EnvironmentId, InputLeaseEpoch, SessionId};

/// How long [`Typing::type_bytes`] waits for the host to accept what it sent. A host that holds the
/// stream open and accepts nothing would otherwise hold the case for good.
const ACCEPTANCE_WAIT: Duration = Duration::from_secs(60);

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
    /// The code the host refused the typing with, when it refused.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Opening(ClientError::Host(refusal)) | Self::Refused(refusal) => {
                Some(refusal.code)
            }
            Self::Opening(error) => Some(error.code()),
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
                    "the input lane ended before the typing was accepted: {cause:?}"
                )
            }
            Self::Waited(what) => write!(formatter, "waited {ACCEPTANCE_WAIT:?} for {what}"),
        }
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
