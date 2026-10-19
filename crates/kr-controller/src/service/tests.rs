use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_transport::clock::{ContinuousInstant, ManualClock};

use super::{ContinuousClock, remaining_deadline, remaining_deadlines};

/// Two clocks with one pause between the first reading and the second.
///
/// Converting a deadline between two clocks is two readings and a subtraction, and what decides
/// whether the conversion can add time is which reading comes first. A pause between them is
/// not something a test can arrange with the real clocks, so this arranges it: whichever side
/// is read first, both clocks move on by `pause` before the other side is read.
#[derive(Debug)]
struct PausedPair {
    shared: kr_ipc::clock::ManualSharedClock,
    process: ManualClock,
    paused: AtomicBool,
    pause: Duration,
}

impl PausedPair {
    fn new(pause: Duration) -> Arc<Self> {
        Arc::new(Self {
            shared: kr_ipc::clock::ManualSharedClock::new(),
            process: ManualClock::new(),
            paused: AtomicBool::new(false),
            pause,
        })
    }

    fn pause_once(&self) {
        if !self.paused.swap(true, Ordering::AcqRel) {
            self.shared.advance(self.pause);
            self.process.advance(self.pause);
        }
    }
}

#[derive(Debug)]
struct SharedSide(Arc<PausedPair>);

impl kr_ipc::clock::SharedClock for SharedSide {
    fn boot_elapsed_ms(&self) -> u64 {
        let reading = kr_ipc::clock::SharedClock::boot_elapsed_ms(&self.0.shared);
        self.0.pause_once();
        reading
    }
}

#[derive(Debug)]
struct ProcessSide(Arc<PausedPair>);

impl ContinuousClock for ProcessSide {
    fn now(&self) -> ContinuousInstant {
        let reading = self.0.process.now();
        self.0.pause_once();
        reading
    }
}

#[test]
fn a_pause_between_the_two_readings_never_lengthens_a_forwarded_deadline() {
    // A hundred milliseconds left, and a second passes between the two clock readings. The
    // deadline is spent by the time the conversion finishes, so nothing is forwarded.
    let pair = PausedPair::new(Duration::from_secs(1));
    let accepted = pair
        .process
        .now()
        .checked_add(Duration::from_millis(100))
        .expect("a deadline a hundred milliseconds out");
    assert_eq!(
        remaining_deadline(
            &SharedSide(Arc::clone(&pair)),
            &ProcessSide(Arc::clone(&pair)),
            accepted,
            None,
        ),
        None,
        "a deadline whose remaining time was spent between the readings is not forwarded"
    );
}

#[test]
fn a_forwarded_deadline_loses_the_pause_rather_than_gaining_it() {
    let pair = PausedPair::new(Duration::from_millis(10));
    let accepted = pair
        .process
        .now()
        .checked_add(Duration::from_millis(100))
        .expect("a deadline a hundred milliseconds out");
    let forwarded = remaining_deadline(
        &SharedSide(Arc::clone(&pair)),
        &ProcessSide(Arc::clone(&pair)),
        accepted,
        None,
    )
    .expect("some of the deadline is left");
    // The machine's clock read zero, and the deadline was a hundred milliseconds away on it.
    // What crosses is ninety: the ten milliseconds spent between the readings are gone.
    assert_eq!(forwarded.get(), 90);
}

#[test]
fn a_lease_shortens_a_forwarded_deadline_and_never_extends_it() {
    let pair = PausedPair::new(Duration::ZERO);
    let accepted = pair
        .process
        .now()
        .checked_add(Duration::from_millis(5_000))
        .expect("a deadline five seconds out");
    let lease = pair
        .process
        .now()
        .checked_add(Duration::from_millis(400))
        .expect("a lease four hundred milliseconds out");
    let forwarded = remaining_deadline(
        &SharedSide(Arc::clone(&pair)),
        &ProcessSide(Arc::clone(&pair)),
        accepted,
        Some(lease),
    )
    .expect("some of the deadline is left");
    assert_eq!(forwarded.get(), 400);
}

/// The daemon's own clock, which moves on a millisecond each time it is read.
#[derive(Debug)]
struct TickingClock(ManualClock);

impl ContinuousClock for TickingClock {
    fn now(&self) -> ContinuousInstant {
        let reading = self.0.now();
        self.0.advance(Duration::from_millis(1));
        reading
    }
}

/// KR-REQ-09.10: the deadline a worker is forwarded, bounded by the lease, is never later than the
/// lease's end that travels beside it, whatever the clocks do between the readings that convert
/// them.
#[test]
fn a_forwarded_deadline_the_lease_bounds_is_never_later_than_the_lease() {
    let clock = TickingClock(ManualClock::new());
    let shared = kr_ipc::clock::ManualSharedClock::new();
    let accepted = clock
        .0
        .now()
        .checked_add(Duration::from_secs(30))
        .expect("a deadline thirty seconds out");
    let lease = clock
        .0
        .now()
        .checked_add(Duration::from_secs(5))
        .expect("a lease five seconds out");
    let (deadline, lease_end) = remaining_deadlines(&shared, &clock, accepted, Some(lease))
        .expect("some of the deadline and the lease is left");
    let lease_end = lease_end.expect("the lease's end crosses with the deadline");
    assert!(
        deadline.get() <= lease_end.get(),
        "the deadline {deadline:?} is later than the lease's end {lease_end:?}"
    );
    assert_eq!(
        deadline.get(),
        5_000,
        "the lease, which ran out first, bounds the deadline"
    );
}
