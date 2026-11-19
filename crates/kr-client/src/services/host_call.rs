//! What the host's call object needs from the provider's side channel.
//!
//! A call on the owner's own provider account is controlled from the host: the host holds the
//! provider's side channel, writes the words the model hears, and learns what the provider says.
//! The provider owns the channel and its tasks; [`HostCallControl`] is the small surface it shows
//! the host's call object, so that the call object decides (who may write, what, and when) and the
//! provider only carries out.
//!
//! The provider's writer takes the six commands of [`VoiceCommand`](super::voice::VoiceCommand) and
//! nothing else: there is no way through this interface to write a raw provider event.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::voice::VoiceContextFrame;

/// A future the host's call object waits on. Its output is the answer itself: nothing here fails
/// the way a request to a service does.
pub type HostFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Where the provider's side channel stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidebandState {
    /// Attached, and the readiness probe was answered under the current ownership revision.
    Ready,
    /// The channel was lost and the host is attaching again by the stored session id. Writes wait.
    Recovering,
    /// The host began to close the call. No further write is taken.
    Closing,
    /// The call is over, and why.
    Closed(SidebandEnd),
}

/// How a call's side channel came to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidebandEnd {
    /// The provider said the session closed (`session.closed`).
    ProviderClosed,
    /// The host closed it: a stop, a deadline or a removal, and the hangup was confirmed.
    HostClosed,
    /// The host lost the channel, could not attach again within the bound, and hung up.
    Lost,
}

/// Why the writer did not take a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The channel is not ready: recovering, closing, or closed.
    NotReady,
    /// The frame was built under an older ownership revision than the channel holds now.
    Stale,
    /// The provider refused the write.
    ProviderRefused,
    /// The channel was lost between taking the frame and writing it.
    Lost,
    /// The call is at the rate the provider holds it to: the write waits for
    /// [`HostCallControl::next_write_at`].
    Rate,
    /// The frame, as it is written, is over the most the provider takes in one message.
    TooLarge,
}

/// Something the provider's side channel reports to the host's call object.
#[derive(Clone, PartialEq, Eq)]
pub enum HostCallEvent {
    /// The provider announced a delegation, and this is where in the call it was heard.
    DelegationHeard {
        /// The provider's identifier for the delegation.
        delegation_id: String,
        /// Where in the call, in milliseconds from its start.
        offset_ms: u64,
    },
    /// The provider refused a write the host had already admitted.
    WriteRefused {
        /// The identifier the write carried.
        write_id: String,
    },
    /// The provider acknowledged a write.
    WriteAcknowledged {
        /// The identifier the write carried.
        write_id: String,
    },
    /// The side channel changed state.
    State(SidebandState),
}

impl fmt::Debug for HostCallEvent {
    /// What happened, and never the delegation's identifier: it is the provider's correlation data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DelegationHeard { offset_ms, .. } => formatter
                .debug_struct("DelegationHeard")
                .field("offset_ms", offset_ms)
                .finish_non_exhaustive(),
            Self::WriteRefused { .. } => formatter.write_str("WriteRefused"),
            Self::WriteAcknowledged { .. } => formatter.write_str("WriteAcknowledged"),
            Self::State(state) => formatter.debug_tuple("State").field(state).finish(),
        }
    }
}

/// Who hears the events of one call's side channel.
pub type HostCallListener = Arc<dyn Fn(HostCallEvent) + Send + Sync>;

/// The provider's side channel for one call, as the host's call object uses it.
pub trait HostCallControl: Send + Sync + fmt::Debug {
    /// Where the channel stands now.
    fn state(&self) -> SidebandState;

    /// The ownership revision the channel holds now. A task of an older revision writes nothing.
    fn revision(&self) -> u64;

    /// Writes one frame under `revision`.
    ///
    /// The frame is written only when the channel is ready and `revision` is the one it holds. An
    /// admission here proves the write reached the provider's socket, and says nothing about the
    /// provider having acted on it: the provider's acknowledgement is a [`HostCallEvent`].
    ///
    /// # Errors
    ///
    /// Returns why the frame was not written.
    fn write<'a>(
        &'a self,
        revision: u64,
        frame: VoiceContextFrame,
    ) -> HostFuture<'a, std::result::Result<(), WriteRefusal>>;

    /// When the next counted write may go: `None` now, or the moment it may. One history serves
    /// every command of the call that the provider counts, whoever sends it, and a write made
    /// before this moment is refused with [`WriteRefusal::Rate`].
    fn next_write_at(&self) -> Option<tokio::time::Instant>;

    /// Where in the call the provider announced `delegation_id`, when it did.
    fn heard(&self, delegation_id: &str) -> Option<u64>;

    /// Waits at most `within` for the provider to announce `delegation_id`, and says where in the
    /// call it was heard, when it was. Waits on the channel's own wake-up, not on a timer's guess.
    fn heard_within<'a>(
        &'a self,
        delegation_id: &'a str,
        within: Duration,
    ) -> HostFuture<'a, Option<u64>>;

    /// Registers the one listener of this call's events, replacing an earlier one.
    fn listen(&self, listener: HostCallListener);
}
