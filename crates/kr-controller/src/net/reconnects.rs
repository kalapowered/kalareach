//! How long a paired device is without a connection to this host, and which attempt ends it.
//!
//! A gap begins when a device's last connection to this host ends and ends when the host admits
//! its next one, and its length is read on the continuous clock the host measures every other
//! deadline on, so a machine that was suspended in between counts the time it spent suspended. A
//! device the host has not seen since it started has no gap to measure: nothing here knows when it
//! last had a connection.
//!
//! The host sees only the connections that reach it, so an attempt that never got that far is not
//! counted. The attempt a gap reports is the ordinal, among the connections of that device the
//! host admitted or refused since its last one ended, of the one that is reported: a device that
//! was refused twice and then admitted reports a refusal at attempt `1`, a refusal at attempt
//! `2-3` and then the admission at attempt `2-3`, each with the time since its last connection
//! ended. A device that has a connection already is not reconnecting, however many more it opens.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_protocol::ids::DeviceId;
use kr_protocol::metrics::{Attempt, Outcome, Recorder, Transport};
use kr_transport::clock::ContinuousInstant;

/// What the host has seen of one device's connections.
#[derive(Clone, Copy, Debug, Default)]
struct Presence {
    /// How many of its connections the host is serving now.
    live: u32,
    /// When its last connection ended, while it has none and has had one since this host started.
    ended_at: Option<ContinuousInstant>,
    /// How many of its connections the host has admitted or refused since that connection ended.
    seen: u64,
}

/// Counts the gaps between a paired device's connections.
#[derive(Debug)]
pub(crate) struct Reconnects {
    devices: Mutex<BTreeMap<DeviceId, Presence>>,
    recorder: Arc<Recorder>,
}

impl Reconnects {
    /// A counter that reports what it measures to `recorder`.
    pub(crate) fn new(recorder: Arc<Recorder>) -> Self {
        Self {
            devices: Mutex::new(BTreeMap::new()),
            recorder,
        }
    }

    /// Records that a connection of `device` reached the host at `now` over `transport` and was
    /// admitted or refused as `outcome` says.
    pub(crate) fn arrived(
        &self,
        device: DeviceId,
        now: ContinuousInstant,
        transport: Transport,
        outcome: Outcome,
    ) {
        let mut devices = self
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let presence = devices.entry(device).or_default();
        if presence.live == 0 {
            presence.seen = presence.seen.saturating_add(1);
            if let Some(ended_at) = presence.ended_at {
                self.recorder.reconnected(
                    transport,
                    Attempt::of(presence.seen),
                    outcome,
                    now.saturating_duration_since(ended_at),
                );
            }
        }
        if outcome == Outcome::Ok {
            presence.live = presence.live.saturating_add(1);
            presence.ended_at = None;
            presence.seen = 0;
        }
    }

    /// Records that a connection of `device` ended at `now`.
    pub(crate) fn departed(&self, device: DeviceId, now: ContinuousInstant) {
        let mut devices = self
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(presence) = devices.get_mut(&device) else {
            return;
        };
        presence.live = presence.live.saturating_sub(1);
        if presence.live == 0 {
            presence.ended_at = Some(now);
            presence.seen = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kr_protocol::ids::DeviceId;
    use kr_protocol::metrics::{
        Attempt, Environment, Outcome, ReconnectTime, Recorder, Report, Transport,
    };
    use kr_protocol::scalars::{U64, Uuid};
    use kr_transport::clock::{ContinuousClock as _, ManualClock};

    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn world() -> (ManualClock, Arc<Recorder>, Reconnects) {
        let recorder = Arc::new(Recorder::new(Environment::Development));
        (
            ManualClock::new(),
            Arc::clone(&recorder),
            Reconnects::new(recorder),
        )
    }

    fn series(
        transport: Transport,
        attempt: Attempt,
        outcome: Outcome,
        count: u64,
        total_ms: u64,
        longest_ms: u64,
    ) -> ReconnectTime {
        ReconnectTime {
            transport,
            attempt,
            outcome,
            environment: Environment::Development,
            count: U64::new(count),
            total_ms: U64::new(total_ms),
            longest_ms: U64::new(longest_ms),
        }
    }

    /// A device the host has not seen end a connection has no gap, and one that ends a connection
    /// and comes back has the time between: measured on the clock the host's deadlines use.
    #[test]
    fn a_device_that_comes_back_is_counted_with_the_time_it_was_gone() {
        let (clock, recorder, reconnects) = world();
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        assert!(
            recorder.report().is_empty(),
            "the first connection since the host started has no gap before it"
        );
        clock.advance(Duration::from_secs(60));
        reconnects.departed(device(1), clock.now());
        clock.advance(Duration::from_millis(4_500));
        reconnects.arrived(device(1), clock.now(), Transport::Direct, Outcome::Ok);
        assert_eq!(
            recorder.report().reconnect_time,
            [series(
                Transport::Direct,
                Attempt::One,
                Outcome::Ok,
                1,
                4_500,
                4_500
            )]
        );
    }

    /// A device that has a connection already is not reconnecting when it opens another, and its
    /// gap begins only when the last of them ends.
    #[test]
    fn a_gap_begins_when_the_last_connection_of_a_device_ends() {
        let (clock, recorder, reconnects) = world();
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        clock.advance(Duration::from_secs(1));
        reconnects.arrived(device(1), clock.now(), Transport::Direct, Outcome::Ok);
        clock.advance(Duration::from_secs(1));
        reconnects.departed(device(1), clock.now());
        clock.advance(Duration::from_secs(10));
        assert!(
            recorder.report().is_empty(),
            "one of its two connections is still there"
        );
        reconnects.departed(device(1), clock.now());
        clock.advance(Duration::from_secs(7));
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        assert_eq!(
            recorder.report().reconnect_time,
            [series(
                Transport::Relay,
                Attempt::One,
                Outcome::Ok,
                1,
                7_000,
                7_000
            )],
            "the gap is measured from the last connection's end"
        );
    }

    /// Refused attempts after a gap are each counted, with the time since the last connection
    /// ended, and the attempt that finally succeeds reports its ordinal among them.
    #[test]
    fn a_refused_attempt_is_counted_and_the_one_that_succeeds_reports_its_ordinal() {
        let (clock, recorder, reconnects) = world();
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        reconnects.departed(device(1), clock.now());
        for _ in 0..3 {
            clock.advance(Duration::from_secs(2));
            reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Refused);
        }
        clock.advance(Duration::from_secs(2));
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        let report = recorder.report();
        assert_eq!(
            report.reconnect_time,
            [
                series(
                    Transport::Relay,
                    Attempt::One,
                    Outcome::Refused,
                    1,
                    2_000,
                    2_000
                ),
                series(
                    Transport::Relay,
                    Attempt::TwoToThree,
                    Outcome::Refused,
                    2,
                    10_000,
                    6_000
                ),
                series(
                    Transport::Relay,
                    Attempt::FourToEight,
                    Outcome::Ok,
                    1,
                    8_000,
                    8_000
                ),
            ]
        );
        // Admitted, the device has a connection and is no longer counted against a gap.
        clock.advance(Duration::from_secs(1));
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        assert_eq!(recorder.report(), report);
    }

    /// A device that was never connected has no gap to measure, whatever the host did with it, and
    /// two devices are two gaps.
    #[test]
    fn a_device_never_seen_connected_has_no_gap_and_devices_are_counted_apart() {
        let (clock, recorder, reconnects) = world();
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Refused);
        clock.advance(Duration::from_secs(5));
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        assert_eq!(recorder.report(), Report::default());

        reconnects.arrived(device(2), clock.now(), Transport::Relay, Outcome::Ok);
        reconnects.departed(device(1), clock.now());
        reconnects.departed(device(2), clock.now());
        clock.advance(Duration::from_secs(3));
        reconnects.arrived(device(2), clock.now(), Transport::Relay, Outcome::Ok);
        clock.advance(Duration::from_secs(1));
        reconnects.arrived(device(1), clock.now(), Transport::Relay, Outcome::Ok);
        assert_eq!(
            recorder.report().reconnect_time,
            [series(
                Transport::Relay,
                Attempt::One,
                Outcome::Ok,
                2,
                7_000,
                4_000
            )]
        );
        // A departure of a device nobody has seen changes nothing.
        reconnects.departed(device(9), clock.now());
    }
}
