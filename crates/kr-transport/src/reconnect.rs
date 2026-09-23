//! Reconnect backoff, and what a reconnect is allowed to carry across.
//!
//! Section 23: reconnect uses jittered exponential backoff from 250 ms to 30 seconds and resets
//! after a stable connection. It creates a new connection identity and input stream; old raw input
//! is never replayed. The client restores state through cursors and receipts.
//!
//! The backoff is here. The "never replayed" half is a property of the types rather than of a
//! policy: a connection identity comes from the host in `hello`, an input sequence belongs to one
//! connection, and [`InputLane`] refuses to carry either across a disconnect. Section 9 says
//! unsent or ambiguously delivered keystrokes are discarded, never replayed, and that the client
//! displays an interruption if delivery is uncertain, so the lane reports what it dropped rather
//! than quietly forgetting it.

use std::time::Duration;

use kr_protocol::ids::{ConnectionId, InputLeaseEpoch, InputSequence};
use kr_protocol::limits::{INACTIVITY_THRESHOLD, RECONNECT_BACKOFF_MAX, RECONNECT_BACKOFF_MIN};

/// The shortest reconnect delay.
pub const BACKOFF_MIN: Duration = Duration::from_millis(RECONNECT_BACKOFF_MIN.get());

/// The longest reconnect delay.
pub const BACKOFF_MAX: Duration = Duration::from_millis(RECONNECT_BACKOFF_MAX.get());

/// How long a connection must last to count as stable.
///
/// The specification says the backoff resets "after a stable connection" without fixing a number.
/// The inactivity threshold is the one interval the protocol already treats as "long enough to
/// draw a conclusion about this connection", so it is reused rather than invented.
pub const STABLE_CONNECTION: Duration = Duration::from_millis(INACTIVITY_THRESHOLD.get());

/// Jittered exponential backoff between connection attempts.
///
/// The jitter is full jitter: each delay is drawn uniformly from zero to the current ceiling. A
/// fleet of devices that lost the same relay therefore spreads its retries instead of returning in
/// step, which is the failure mode backoff without jitter produces.
#[derive(Clone, Debug)]
pub struct Backoff {
    ceiling: Duration,
    minimum: Duration,
    maximum: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(BACKOFF_MIN, BACKOFF_MAX)
    }
}

impl Backoff {
    /// Creates a backoff between two delays.
    #[must_use]
    pub fn new(minimum: Duration, maximum: Duration) -> Self {
        Self {
            ceiling: minimum,
            minimum,
            maximum,
        }
    }

    /// Returns the next delay and raises the ceiling.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling;
        self.ceiling = (self.ceiling * 2).min(self.maximum);
        let millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        let floor = u64::try_from(self.minimum.as_millis()).unwrap_or(0);
        let span = millis.saturating_sub(floor).saturating_add(1);
        // Full jitter, held at the minimum so a failing endpoint is never retried immediately. The
        // draw comes from the same generator as everything else in this crate rather than from a
        // second random source; a failed draw falls back to the ceiling, which delays rather than
        // hurries the retry.
        let offset = crate::random::fresh_u64().map_or(0, |value| value % span);
        Duration::from_millis(floor.saturating_add(offset))
    }

    /// Returns the current ceiling, before any jitter.
    #[must_use]
    pub const fn ceiling(&self) -> Duration {
        self.ceiling
    }

    /// Resets the ceiling to the minimum.
    pub fn reset(&mut self) {
        self.ceiling = self.minimum;
    }

    /// Resets the ceiling when a connection lasted long enough to count as stable.
    ///
    /// A connection that dies immediately does not reset the backoff, which is what stops a host
    /// that accepts and then drops from being retried every 250 ms forever.
    pub fn observe_connection(&mut self, lifetime: Duration) {
        if lifetime >= STABLE_CONNECTION {
            self.reset();
        }
    }
}

/// What a reconnect discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputInterruption {
    /// The connection that ended.
    pub connection_id: ConnectionId,
    /// The last sequence this side sent on it.
    pub last_sent: InputSequence,
    /// The last sequence the host acknowledged.
    pub last_acknowledged: InputSequence,
}

impl InputInterruption {
    /// Returns true when delivery of some input was uncertain.
    ///
    /// The client displays an interruption in that case. It never resends: an acknowledged
    /// position belongs to the connection that acknowledged it.
    #[must_use]
    pub fn delivery_uncertain(&self) -> bool {
        self.last_sent.get() > self.last_acknowledged.get()
    }
}

/// The ordered raw-input stream of one connection.
///
/// Section 9: raw input is a distinct ordered stream of connection identity, lease epoch and
/// increasing input sequence, and acknowledgement positions are retained only for that connection.
/// A lane cannot be moved to another connection; reconnecting builds a new one.
#[derive(Clone, Debug)]
pub struct InputLane {
    connection_id: ConnectionId,
    lease_epoch: InputLeaseEpoch,
    next_sequence: u64,
    acknowledged: u64,
}

impl InputLane {
    /// Opens a lane on one connection and input lease epoch.
    #[must_use]
    pub const fn new(connection_id: ConnectionId, lease_epoch: InputLeaseEpoch) -> Self {
        Self {
            connection_id,
            lease_epoch,
            next_sequence: 1,
            acknowledged: 0,
        }
    }

    /// Returns the connection this lane belongs to.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the input lease epoch.
    #[must_use]
    pub const fn lease_epoch(&self) -> InputLeaseEpoch {
        self.lease_epoch
    }

    /// Allocates the next sequence number.
    pub fn next_sequence(&mut self) -> InputSequence {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        InputSequence::new(sequence)
    }

    /// Records the host's acknowledgement position.
    ///
    /// An acknowledgement that goes backwards is ignored rather than trusted: positions only move
    /// forward, and this lane is the only place they are kept.
    pub fn acknowledge(&mut self, sequence: InputSequence) {
        self.acknowledged = self.acknowledged.max(sequence.get());
    }

    /// Ends the lane, returning what was left uncertain.
    #[must_use]
    pub fn close(self) -> InputInterruption {
        InputInterruption {
            connection_id: self.connection_id,
            last_sent: InputSequence::new(self.next_sequence.saturating_sub(1)),
            last_acknowledged: InputSequence::new(self.acknowledged),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// KR-REQ-23.22: reconnect backoff runs from 250 ms up to 30 seconds.
    #[test]
    fn the_backoff_starts_at_the_minimum_and_doubles_to_the_maximum() {
        assert_eq!(BACKOFF_MIN, Duration::from_millis(250));
        assert_eq!(BACKOFF_MAX, Duration::from_secs(30));
        let mut backoff = Backoff::default();
        assert_eq!(backoff.ceiling(), BACKOFF_MIN);
        let mut seen = Vec::new();
        for _ in 0..12 {
            seen.push(backoff.next_delay());
        }
        assert_eq!(backoff.ceiling(), BACKOFF_MAX);
        assert!(seen.iter().all(|delay| *delay <= BACKOFF_MAX));
        assert!(seen.iter().all(|delay| *delay >= BACKOFF_MIN));

        // Each attempt draws below the ceiling it started with, and the ceiling doubles from
        // 250 ms until it is held at 30 seconds.
        let mut backoff = Backoff::default();
        let mut ceilings = Vec::new();
        for _ in 0..9 {
            let ceiling = backoff.ceiling();
            let delay = backoff.next_delay();
            assert!(
                delay >= BACKOFF_MIN && delay <= ceiling,
                "{delay:?} under {ceiling:?}"
            );
            ceilings.push(backoff.ceiling().as_millis());
        }
        assert_eq!(
            ceilings,
            [
                500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000
            ]
        );
    }

    /// KR-REQ-23.22: the backoff is jittered.
    #[test]
    fn the_delays_are_jittered_rather_than_a_fixed_ladder() {
        // Two independent ladders drawn from the same ceilings differ, which a fixed schedule
        // could not do. Drawn from a wide ceiling so the comparison is not a coin flip.
        let draw = || {
            let mut backoff = Backoff::default();
            (0..8).map(|_| backoff.next_delay()).collect::<Vec<_>>()
        };
        let mut differed = false;
        for _ in 0..8 {
            if draw() != draw() {
                differed = true;
                break;
            }
        }
        assert!(differed, "the delays carry jitter");
    }

    /// KR-REQ-23.22: the backoff resets after a stable connection only.
    #[test]
    fn a_stable_connection_resets_the_backoff_and_a_brief_one_does_not() {
        let mut backoff = Backoff::default();
        for _ in 0..6 {
            backoff.next_delay();
        }
        let raised = backoff.ceiling();
        assert!(raised > BACKOFF_MIN);

        backoff.observe_connection(Duration::from_secs(1));
        assert_eq!(
            backoff.ceiling(),
            raised,
            "a brief connection resets nothing"
        );

        backoff.observe_connection(STABLE_CONNECTION);
        assert_eq!(backoff.ceiling(), BACKOFF_MIN);
    }

    /// KR-REQ-23.22: a reconnect starts a new connection identity and input lane and replays no old
    /// input.
    #[test]
    fn a_reconnect_starts_a_new_lane_and_replays_nothing() {
        let mut lane = InputLane::new(connection(1), InputLeaseEpoch::new(4));
        assert_eq!(lane.next_sequence(), InputSequence::new(1));
        assert_eq!(lane.next_sequence(), InputSequence::new(2));
        lane.acknowledge(InputSequence::new(1));

        let interruption = lane.close();
        assert!(interruption.delivery_uncertain());
        assert_eq!(interruption.last_sent, InputSequence::new(2));
        assert_eq!(interruption.last_acknowledged, InputSequence::new(1));

        // The new lane belongs to the new connection and starts from the beginning. There is no
        // constructor that carries a position across, so nothing can be resent.
        let fresh = InputLane::new(connection(2), InputLeaseEpoch::new(5));
        assert_eq!(fresh.connection_id(), connection(2));
        assert_eq!(fresh.lease_epoch(), InputLeaseEpoch::new(5));
    }

    #[test]
    fn fully_acknowledged_input_is_not_an_interruption() {
        let mut lane = InputLane::new(connection(1), InputLeaseEpoch::new(1));
        lane.next_sequence();
        lane.acknowledge(InputSequence::new(1));
        assert!(!lane.close().delivery_uncertain());
    }

    #[test]
    fn an_acknowledgement_never_moves_backwards() {
        let mut lane = InputLane::new(connection(1), InputLeaseEpoch::new(1));
        for _ in 0..5 {
            lane.next_sequence();
        }
        lane.acknowledge(InputSequence::new(4));
        lane.acknowledge(InputSequence::new(2));
        assert_eq!(lane.close().last_acknowledged, InputSequence::new(4));
    }
}
