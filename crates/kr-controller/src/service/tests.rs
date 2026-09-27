use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_transport::clock::{ContinuousInstant, ManualClock};

use super::{ContinuousClock, remaining_deadline};

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
