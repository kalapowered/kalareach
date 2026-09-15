//! Reconnecting, and what a reconnect is not allowed to carry across.
//!
//! Section 23: reconnect uses jittered exponential backoff from 250 ms to 30 seconds and resets
//! after a stable connection. It creates a new connection identity and input stream; old raw input
//! is never replayed. The client restores state through cursors and receipts.
//!
//! The backoff itself lives in `kr-transport`. What lives here is what a client carries across a
//! disconnect and what it does not. [`ClientState`] is the carried half: cursors, so the next
//! subscription starts where this one stopped, and receipts, so an action whose outcome is still
//! unresolved is reported rather than resubmitted. Everything else is dropped, including every
//! keystroke that had not been acknowledged.

use std::time::{Duration, Instant};

use kr_transport::reconnect::{Backoff, InputInterruption};

use crate::cursors::{ReceiptTracker, StreamCursors};
use crate::session::Session;

/// What a client keeps when a connection ends.
#[derive(Clone, Debug, Default)]
pub struct ClientState {
    /// Where each subscribed stream had reached.
    pub cursors: StreamCursors,
    /// What each submitted action's receipt last said.
    pub receipts: ReceiptTracker,
    /// What the ended connection left uncertain, when it had an input lane.
    pub interruption: Option<InputInterruption>,
}

impl ClientState {
    /// Takes what a session had reached when it ended.
    ///
    /// The session's connection identity and input lane are deliberately not taken: the next
    /// connection gets its own, and an acknowledgement position belongs to the connection that
    /// produced it.
    pub async fn from_session(session: &Session, interruption: Option<InputInterruption>) -> Self {
        Self {
            cursors: session.cursors().await,
            receipts: session.receipts().await,
            interruption,
        }
    }

    /// Returns true when some input's delivery was left uncertain.
    ///
    /// The client displays an interruption in that case. It never resends.
    #[must_use]
    pub fn delivery_uncertain(&self) -> bool {
        self.interruption
            .is_some_and(|interruption| interruption.delivery_uncertain())
    }

    /// Returns the actions whose outcome is still unresolved.
    #[must_use]
    pub fn unresolved_actions(&self) -> Vec<kr_protocol::ids::ActionId> {
        self.receipts.unresolved()
    }
}

/// Drives the delay between connection attempts.
///
/// It is a thin shell over the transport's backoff: the client's contribution is knowing when a
/// connection counted as stable, which is what resets the ladder.
#[derive(Debug)]
pub struct ReconnectLoop {
    backoff: Backoff,
    connected_at: Option<Instant>,
}

impl Default for ReconnectLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectLoop {
    /// Creates a loop at the shortest delay.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backoff: Backoff::default(),
            connected_at: None,
        }
    }

    /// Records that a connection was established.
    pub fn connected(&mut self) {
        self.connected_at = Some(Instant::now());
    }

    /// Records that the connection ended, and returns how long to wait before the next attempt.
    ///
    /// A connection that lasted long enough to count as stable resets the ladder; one that died
    /// immediately does not, so a host that accepts and then drops is not retried every 250 ms.
    pub fn disconnected(&mut self) -> Duration {
        if let Some(connected_at) = self.connected_at.take() {
            self.backoff.observe_connection(connected_at.elapsed());
        }
        self.backoff.next_delay()
    }

    /// Returns the current ceiling, before jitter.
    #[must_use]
    pub fn ceiling(&self) -> Duration {
        self.backoff.ceiling()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::{ConnectionId, InputLeaseEpoch, InputSequence};
    use kr_protocol::scalars::Uuid;
    use kr_transport::reconnect::{BACKOFF_MAX, BACKOFF_MIN, InputLane};

    #[test]
    fn the_delay_grows_until_a_connection_lasts() {
        let mut loop_ = ReconnectLoop::new();
        assert_eq!(loop_.ceiling(), BACKOFF_MIN);
        for _ in 0..12 {
            let delay = loop_.disconnected();
            assert!(delay >= BACKOFF_MIN && delay <= BACKOFF_MAX);
        }
        assert_eq!(loop_.ceiling(), BACKOFF_MAX);
    }

    #[test]
    fn unacknowledged_input_is_reported_and_never_resent() {
        let mut lane = InputLane::new(
            ConnectionId::new(Uuid::from_bytes([1; 16])),
            InputLeaseEpoch::new(1),
        );
        lane.next_sequence();
        lane.next_sequence();
        lane.acknowledge(InputSequence::new(1));

        let state = ClientState {
            interruption: Some(lane.close()),
            ..ClientState::default()
        };
        assert!(state.delivery_uncertain());
        // Nothing in the carried state can address the old connection's input lane, so there is no
        // way to resend what it dropped.
        assert!(state.cursors.is_empty());
    }

    #[test]
    fn a_fully_acknowledged_lane_is_not_an_interruption() {
        let mut lane = InputLane::new(
            ConnectionId::new(Uuid::from_bytes([1; 16])),
            InputLeaseEpoch::new(1),
        );
        lane.next_sequence();
        lane.acknowledge(InputSequence::new(1));
        let state = ClientState {
            interruption: Some(lane.close()),
            ..ClientState::default()
        };
        assert!(!state.delivery_uncertain());
    }
}
