//! Simulated time: one timeline a test drives, and every clock the product takes by injection read
//! from it.
//!
//! The product already takes its decision clocks by injection: a worker's session its
//! [`TimeSources`] (the machine's continuous clock, a clock that stops while the machine sleeps,
//! the wall clock and the platform's time service), a control daemon its
//! [`Clocks`](kr_controller::service::Clocks), the transport its continuous clock. Handed one of
//! each from here, a component decides every deadline, window and expiry on this timeline and on
//! nothing else, so a test moves time by saying so and never by waiting for it:
//!
//! * [`SimulatedTime::advance`] moves every clock by the same amount;
//! * [`SimulatedTime::suspend`] moves the continuous and wall clocks and not the one that stops
//!   while the machine sleeps, which is what a suspension is to a host;
//! * [`SimulatedTime::step_wall`] moves the wall clock alone, forwards or back.
//!
//! A wait for something to happen is not a decision. It stays an event wait under a liveness
//! bound, and it is never a measurement.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_protocol::action::{TimeAdapterReading, TimeSyncSource, TimeSyncStatus};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_worker::action::adapter::TimeAdapter;
use kr_worker::action::time::{ActiveClock, TimeSources, WallClock};

/// Where each clock stands.
#[derive(Clone, Copy, Debug)]
struct Readings {
    /// Milliseconds since this timeline began, counting time the machine slept.
    continuous_ms: u64,
    /// Milliseconds since this timeline began, not counting it.
    active_ms: u64,
    /// The wall clock, in UTC milliseconds.
    wall_ms: u64,
    /// Whether the platform's time service says the wall clock is disciplined.
    synchronised: bool,
}

/// One timeline, and the clocks read from it.
#[derive(Clone, Debug)]
pub struct SimulatedTime {
    readings: Arc<Mutex<Readings>>,
    /// The transport's own clock, moved in step with the continuous one.
    transport: kr_transport::clock::ManualClock,
    /// The moment this timeline began, for a call that takes an [`Instant`].
    origin: Instant,
}

impl SimulatedTime {
    /// A timeline whose wall clock reads `wall_ms`, disciplined by a time service.
    #[must_use]
    pub fn new(wall_ms: u64) -> Self {
        Self {
            readings: Arc::new(Mutex::new(Readings {
                continuous_ms: 0,
                active_ms: 0,
                wall_ms,
                synchronised: true,
            })),
            transport: kr_transport::clock::ManualClock::new(),
            origin: Instant::now(),
        }
    }

    fn readings(&self) -> std::sync::MutexGuard<'_, Readings> {
        self.readings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves every clock by `by`.
    pub fn advance(&self, by: Duration) {
        let by_ms = millis(by);
        {
            let mut readings = self.readings();
            readings.continuous_ms = readings.continuous_ms.saturating_add(by_ms);
            readings.active_ms = readings.active_ms.saturating_add(by_ms);
            readings.wall_ms = readings.wall_ms.saturating_add(by_ms);
        }
        self.transport.advance(by);
    }

    /// The machine sleeps for `by`: the continuous and wall clocks move, and the clock that stops
    /// while the machine sleeps does not.
    pub fn suspend(&self, by: Duration) {
        let by_ms = millis(by);
        {
            let mut readings = self.readings();
            readings.continuous_ms = readings.continuous_ms.saturating_add(by_ms);
            readings.wall_ms = readings.wall_ms.saturating_add(by_ms);
        }
        self.transport.advance(by);
    }

    /// Steps the wall clock by `by_ms`, back when it is negative, and moves nothing else.
    pub fn step_wall(&self, by_ms: i64) {
        let mut readings = self.readings();
        readings.wall_ms = readings.wall_ms.saturating_add_signed(by_ms);
    }

    /// Says whether the platform's time service disciplines the wall clock.
    pub fn set_synchronised(&self, synchronised: bool) {
        self.readings().synchronised = synchronised;
    }

    /// The continuous clock's reading, in milliseconds since this timeline began.
    #[must_use]
    pub fn continuous_ms(&self) -> u64 {
        self.readings().continuous_ms
    }

    /// The wall clock's reading.
    #[must_use]
    pub fn wall_ms(&self) -> u64 {
        self.readings().wall_ms
    }

    /// The continuous clock's reading as an [`Instant`], for a call that takes one.
    #[must_use]
    pub fn instant(&self) -> Instant {
        self.origin + Duration::from_millis(self.continuous_ms())
    }

    /// The clocks and time service a worker's session takes.
    #[must_use]
    pub fn worker_sources(&self) -> TimeSources {
        TimeSources {
            continuous: Arc::new(Continuous(self.clone())),
            active: Arc::new(Active(self.clone())),
            wall: Arc::new(Wall(self.clone())),
            adapter: Arc::new(Service(self.clone())),
            floor: None,
        }
    }

    /// The clocks a control daemon takes.
    #[must_use]
    pub fn daemon_clocks(&self) -> kr_controller::service::Clocks {
        let wall = self.clone();
        kr_controller::service::Clocks {
            continuous: Arc::new(self.transport.clone()),
            wall: kr_controller::service::WallClock::from_fn(move || wall.wall_ms()),
        }
    }

    /// The continuous clock the transport takes.
    #[must_use]
    pub fn transport_clock(&self) -> Arc<dyn kr_transport::clock::ContinuousClock> {
        Arc::new(self.transport.clone())
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug)]
struct Continuous(SimulatedTime);

impl kr_ipc::clock::SharedClock for Continuous {
    fn boot_elapsed_ms(&self) -> u64 {
        self.0.continuous_ms()
    }
}

#[derive(Debug)]
struct Active(SimulatedTime);

impl ActiveClock for Active {
    fn active_elapsed_ms(&self) -> u64 {
        self.0.readings().active_ms
    }
}

#[derive(Debug)]
struct Wall(SimulatedTime);

impl WallClock for Wall {
    fn now_ms(&self) -> TimestampMs {
        TimestampMs::new(self.0.wall_ms())
    }
}

/// The platform's time service, answering with the timeline's wall clock and whether it is
/// disciplined.
#[derive(Debug)]
struct Service(SimulatedTime);

impl TimeAdapter for Service {
    fn read(&self) -> TimeAdapterReading {
        let readings = *self.0.readings();
        if readings.synchronised {
            TimeAdapterReading {
                platform: "simulated".to_owned(),
                api: "simulated".to_owned(),
                source: TimeSyncSource::NetworkTimeService,
                status: TimeSyncStatus::Ok,
                uncertainty_us: Nullable::some(U64::new(1_000)),
                estimated_error_us: Nullable::some(U64::new(500)),
                wall_clock_ms: TimestampMs::new(readings.wall_ms),
            }
        } else {
            TimeAdapterReading {
                platform: "simulated".to_owned(),
                api: "simulated".to_owned(),
                source: TimeSyncSource::Unsynchronised,
                status: TimeSyncStatus::Error,
                uncertainty_us: Nullable::null(),
                estimated_error_us: Nullable::null(),
                wall_clock_ms: TimestampMs::new(readings.wall_ms),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_moves_every_clock_and_suspending_stops_the_active_one() {
        let time = SimulatedTime::new(1_000_000);
        let sources = time.worker_sources();
        let transport = time.transport_clock();
        let before = transport.now();
        time.advance(Duration::from_secs(2));
        time.suspend(Duration::from_secs(10));
        assert_eq!(sources.continuous.boot_elapsed_ms(), 12_000);
        assert_eq!(sources.active.active_elapsed_ms(), 2_000);
        assert_eq!(sources.wall.now_ms().get(), 1_012_000);
        assert_eq!(
            transport.now().saturating_duration_since(before),
            Duration::from_secs(12)
        );
        assert_eq!(time.instant() - time.origin, Duration::from_secs(12));
    }

    #[test]
    fn stepping_the_wall_clock_moves_it_alone() {
        let time = SimulatedTime::new(1_000_000);
        let sources = time.worker_sources();
        time.step_wall(-6_000);
        assert_eq!(sources.wall.now_ms().get(), 994_000);
        assert_eq!(sources.continuous.boot_elapsed_ms(), 0);
        assert!(sources.adapter.read().is_qualified());
        time.set_synchronised(false);
        assert!(!sources.adapter.read().is_qualified());
    }
}
