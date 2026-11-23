//! Reconnecting, and what a reconnect is not allowed to carry across.
//!
//! Section 23: reconnect uses jittered exponential backoff from 250 ms to 30 seconds and resets
//! after a stable connection. It creates a new connection identity and input stream; old raw input
//! is never replayed. The client restores state through cursors and receipts.
//!
//! The backoff itself lives in `kr-transport`. What lives here is the loop that times the delay
//! between attempts and decides when a connection counted as stable. A client carries its cursors
//! across a disconnect ([`crate::session::Session::resume`]), so the next subscription starts where
//! this one stopped, and nothing else: every keystroke that had not been acknowledged is dropped.

use std::time::{Duration, Instant};

use kr_transport::reconnect::Backoff;

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
    use kr_transport::reconnect::{BACKOFF_MAX, BACKOFF_MIN};

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
}
