//! Timestamps along a keystroke's path, for the input measurement.
//!
//! A held prefix reaches the application when the recogniser's timer takes the session at its
//! deadline, and the measurement sees it when its own poll takes the session again. Every one of
//! those acquisitions, and every observation of the session's processes that falls between them,
//! can lengthen the figure, and a figure alone cannot say which. This records, for each
//! acquisition of the session that lies on that path, the instants it began to wait, held the
//! session and let go of it; for the recogniser's timer, when it woke against the deadline it slept
//! for; and for an observation of the session's processes, when it began and ended reading them.
//!
//! All of it is on one monotonic clock in one process, so the intervals can be laid side by side.
//!
//! Nothing is recorded unless the measurement arms it. An unarmed site costs one relaxed load and a
//! branch, and no site allocates. In a shipped build there is no recorder at all: the types below
//! are empty and every call compiles to nothing.

#[cfg(feature = "testing")]
pub use recording::{Acquisition, Event, LockTrace, Recording};

#[cfg(not(feature = "testing"))]
pub use shipped::LockTrace;

/// Where on a keystroke's path an event happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// An input write took the session to accept a batch and feed the recogniser.
    InputAcceptance,
    /// The recogniser's timer took the session to read the deadline of the prefix it holds.
    TimerLook,
    /// The recogniser's timer woke from its sleep, against the deadline it slept for.
    #[cfg_attr(
        not(feature = "testing"),
        expect(dead_code, reason = "only the recorder of a testing build names it")
    )]
    TimerWake,
    /// The recogniser's timer took the session to forward the prefix it held.
    TimerForward,
    /// The output ingest took the session to record what the application wrote.
    Ingest,
    /// The supervision took the session for one wake.
    SupervisionWake,
    /// An observation of the session's processes read them.
    #[cfg_attr(
        not(feature = "testing"),
        expect(dead_code, reason = "only the recorder of a testing build names it")
    )]
    Observation,
}

#[cfg(feature = "testing")]
impl Site {
    /// The code a site is stored as. Never zero: zero marks a slot nothing has finished writing.
    const fn code(self) -> u64 {
        match self {
            Self::InputAcceptance => 1,
            Self::TimerLook => 2,
            Self::TimerWake => 3,
            Self::TimerForward => 4,
            Self::Ingest => 5,
            Self::SupervisionWake => 6,
            Self::Observation => 7,
        }
    }

    /// The site a stored code names.
    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::InputAcceptance,
            2 => Self::TimerLook,
            3 => Self::TimerWake,
            4 => Self::TimerForward,
            5 => Self::Ingest,
            6 => Self::SupervisionWake,
            7 => Self::Observation,
            _ => return None,
        })
    }
}

#[cfg(feature = "testing")]
mod recording {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Instant;

    use super::Site;

    /// The words one event takes: its site, then four instants or values.
    const WORDS: usize = 5;

    /// How many events one recording holds. A recording that is full stops and says so; it never
    /// wraps, so an event that is missing from a recording that overflowed is not evidence that
    /// nothing happened.
    const EVENTS: usize = 400;

    /// One event of a recording, in nanoseconds since the recorder's epoch.
    ///
    /// For an acquisition of the session `begun` is when the wait for it began, `held` when it was
    /// taken and `released` when it was let go. `value` is what the site added: the recogniser's
    /// deadline after an input write, and for a supervision wake whether it observed the session's
    /// processes (see [`crate::runtime::SUPERVISION_OBSERVED`]). For [`Site::TimerWake`],
    /// `begun` is the deadline and `held` is when the timer woke; for [`Site::Observation`],
    /// `begun` and `held` are the start and the end of the reading.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Event {
        /// Where it happened.
        pub site: Site,
        /// The first instant.
        pub begun: u64,
        /// The second instant.
        pub held: u64,
        /// The third instant, or zero where the site has two.
        pub released: u64,
        /// What the site added, or zero.
        pub value: u64,
    }

    /// What a recording holds.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Recording {
        /// The events, in the order they finished.
        pub events: Vec<Event>,
        /// Whether events were lost because the recording was full.
        pub overflowed: bool,
    }

    /// The recorder one session carries.
    #[derive(Debug)]
    pub struct LockTrace {
        epoch: Instant,
        armed: AtomicBool,
        taken: AtomicUsize,
        overflowed: AtomicBool,
        words: OnceLock<Box<[AtomicU64]>>,
    }

    impl Default for LockTrace {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LockTrace {
        /// A recorder that is not armed.
        #[must_use]
        pub fn new() -> Self {
            Self {
                epoch: Instant::now(),
                armed: AtomicBool::new(false),
                taken: AtomicUsize::new(0),
                overflowed: AtomicBool::new(false),
                words: OnceLock::new(),
            }
        }

        /// Starts recording. The first call allocates the space; nothing allocates after it.
        pub fn arm(&self) {
            self.words
                .get_or_init(|| (0..EVENTS * WORDS).map(|_| AtomicU64::new(0)).collect());
            self.restart();
            self.armed.store(true, Ordering::Release);
        }

        /// Stops recording. What was recorded stays until it is read or restarted.
        pub fn disarm(&self) {
            self.armed.store(false, Ordering::Release);
        }

        /// Forgets what has been recorded, so that the next recording begins here.
        pub fn restart(&self) {
            self.overflowed.store(false, Ordering::Relaxed);
            self.taken.store(0, Ordering::Release);
            if let Some(words) = self.words.get() {
                for word in words.iter() {
                    word.store(0, Ordering::Relaxed);
                }
            }
        }

        /// The instant this recorder counts from.
        #[must_use]
        pub const fn epoch(&self) -> Instant {
            self.epoch
        }

        /// How long after the recorder's epoch an instant was, in nanoseconds.
        #[must_use]
        pub fn offset(&self, at: Instant) -> u64 {
            u64::try_from(at.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
        }

        /// What has been recorded since it was armed or restarted.
        #[must_use]
        pub fn recording(&self) -> Recording {
            let mut events = Vec::new();
            if let Some(words) = self.words.get() {
                let used = self.taken.load(Ordering::Acquire).min(EVENTS);
                for slot in words.chunks(WORDS).take(used) {
                    // A slot is whole once its site is stored, which is the last store.
                    let Some(site) = Site::from_code(slot[0].load(Ordering::Acquire)) else {
                        continue;
                    };
                    events.push(Event {
                        site,
                        begun: slot[1].load(Ordering::Relaxed),
                        held: slot[2].load(Ordering::Relaxed),
                        released: slot[3].load(Ordering::Relaxed),
                        value: slot[4].load(Ordering::Relaxed),
                    });
                }
            }
            Recording {
                events,
                overflowed: self.overflowed.load(Ordering::Relaxed),
            }
        }

        /// Whether anything is being recorded.
        fn is_armed(&self) -> bool {
            self.armed.load(Ordering::Relaxed)
        }

        fn now(&self) -> u64 {
            self.offset(Instant::now())
        }

        /// Begins an acquisition of the session, if anything is being recorded.
        ///
        /// The acquisition is recorded when it is dropped, so it is declared before the guard of
        /// the session and ends after the guard has let go.
        pub fn acquisition(&self, site: Site) -> Acquisition<'_> {
            if self.is_armed() {
                Acquisition {
                    recorder: Some(self),
                    site,
                    begun: self.now(),
                    held: 0,
                    value: 0,
                }
            } else {
                Acquisition {
                    recorder: None,
                    site,
                    begun: 0,
                    held: 0,
                    value: 0,
                }
            }
        }

        /// Records that the recogniser's timer woke from its sleep for `deadline`.
        pub fn timer_woke(&self, deadline: Instant) {
            if self.is_armed() {
                self.store(Site::TimerWake, [self.offset(deadline), self.now(), 0, 0]);
            }
        }

        /// Records that an observation of the session's processes read them from `begun` until
        /// now.
        pub fn observed(&self, begun: Instant) {
            if self.is_armed() {
                self.store(Site::Observation, [self.offset(begun), self.now(), 0, 0]);
            }
        }

        /// Stores one event in the next free slot.
        fn store(&self, site: Site, values: [u64; 4]) {
            let Some(words) = self.words.get() else {
                return;
            };
            let slot = self.taken.fetch_add(1, Ordering::AcqRel);
            if slot >= EVENTS {
                self.overflowed.store(true, Ordering::Relaxed);
                return;
            }
            let at = slot * WORDS;
            for (word, value) in words[at + 1..at + WORDS].iter().zip(values) {
                word.store(value, Ordering::Relaxed);
            }
            words[at].store(site.code(), Ordering::Release);
        }
    }

    /// One acquisition of the session, recorded when it ends.
    #[derive(Debug)]
    pub struct Acquisition<'a> {
        recorder: Option<&'a LockTrace>,
        site: Site,
        begun: u64,
        held: u64,
        value: u64,
    }

    impl Acquisition<'_> {
        /// Says that the session is held now.
        pub fn held(&mut self) {
            if let Some(recorder) = self.recorder {
                self.held = recorder.now();
            }
        }

        /// Adds a value to the event: the recogniser's deadline, as an instant, where it has one.
        pub fn deadline(&mut self, deadline: Option<Instant>) {
            if let (Some(recorder), Some(deadline)) = (self.recorder, deadline) {
                self.value = recorder.offset(deadline);
            }
        }

        /// Adds a value to the event, which the site documents.
        pub fn note(&mut self, value: u64) {
            self.value = value;
        }
    }

    impl Drop for Acquisition<'_> {
        fn drop(&mut self) {
            if let Some(recorder) = self.recorder {
                recorder.store(
                    self.site,
                    [self.begun, self.held, recorder.now(), self.value],
                );
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
mod shipped {
    use std::time::Instant;

    use super::Site;

    /// The recorder a shipped build carries, which records nothing.
    #[derive(Debug, Default)]
    pub struct LockTrace;

    impl LockTrace {
        /// A recorder that records nothing.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }

        /// Begins an acquisition, which is not recorded.
        pub const fn acquisition(&self, _site: Site) -> Acquisition {
            Acquisition
        }

        /// Does nothing.
        pub const fn timer_woke(&self, _deadline: Instant) {}

        /// Does nothing.
        pub const fn observed(&self, _begun: Instant) {}
    }

    /// An acquisition that is not recorded.
    #[derive(Debug)]
    pub struct Acquisition;

    impl Acquisition {
        /// Does nothing.
        pub const fn held(&mut self) {}

        /// Does nothing.
        pub const fn deadline(&mut self, _deadline: Option<Instant>) {}

        /// Does nothing.
        pub const fn note(&mut self, _value: u64) {}
    }
}
