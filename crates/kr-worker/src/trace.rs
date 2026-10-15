//! Timestamps along a keystroke's path, for the input measurement.
//!
//! A held prefix reaches the application when the recogniser's timer takes the session at its
//! deadline, and the measurement sees it when its own poll takes the session again. Every one of
//! those acquisitions, and every observation of the session's processes that falls between them,
//! can lengthen the figure, and a figure alone cannot say which. This records, for each
//! acquisition of the session that lies on that path, the instants it began to wait, held the
//! session and let go of it; for the recogniser's timer, when it woke against the deadline it slept
//! for; for an observation of the session's processes, when it began and ended reading them; and
//! for the output ingest, the steps of its work and its write to the spool.
//!
//! All of it is on one monotonic clock in one process, so the intervals can be laid side by side.
//!
//! Nothing is recorded unless the measurement arms it, and no site reads the clock or allocates
//! until it does: an unarmed site costs one relaxed load and a branch. In a shipped build there is
//! no recorder at all: the types below are empty and every call compiles to nothing.

#[cfg(feature = "testing")]
pub use recording::{Acquisition, Event, LockTrace, Recording, Shared};

#[cfg(not(feature = "testing"))]
pub use shipped::{LockTrace, Shared};

/// Where on a keystroke's path an event happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// An input write took the session to accept a batch and feed the recogniser.
    InputAcceptance,
    /// The recogniser's timer took the session to read the deadline of the prefix it holds.
    TimerLook,
    /// The recogniser's timer woke from its sleep, against the deadline it slept for.
    TimerWake,
    /// The recogniser's timer took the session to forward the prefix it held.
    TimerForward,
    /// The output ingest took the session to record what the application wrote.
    Ingest,
    /// The ingest kept a batch in the session's output history, in its resident window and in the
    /// spool's account of it. A span of the work inside [`Site::Ingest`]: `begun` and `held` are
    /// its start and end.
    IngestRetain,
    /// The ingest gave a batch to the terminal engine. A span of the work inside [`Site::Ingest`].
    IngestInterpret,
    /// The ingest handed an interpreted batch to the attachments. A span of the work inside
    /// [`Site::Ingest`].
    IngestDeliver,
    /// The ingest wrote a batch to the spool, after it had let go of the session. A span:
    /// `begun` and `held` are its start and end.
    SpoolWrite,
    /// The supervision took the session for one wake.
    SupervisionWake,
    /// An observation of the session's processes read them, with the session let go.
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
            Self::IngestRetain => 8,
            Self::IngestInterpret => 9,
            Self::IngestDeliver => 10,
            Self::SpoolWrite => 11,
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
            8 => Self::IngestRetain,
            9 => Self::IngestInterpret,
            10 => Self::IngestDeliver,
            11 => Self::SpoolWrite,
            _ => return None,
        })
    }
}

#[cfg(feature = "testing")]
mod recording {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Instant;

    use super::Site;

    /// What a session's tasks share of the recorder.
    pub type Shared = Arc<LockTrace>;

    /// The words one event takes: its site, then four instants or values.
    const WORDS: usize = 5;

    /// How many events a recorder holds in all. A recorder that is full stops and says so; it never
    /// wraps, so an event that is missing from a recording that overflowed is not evidence that
    /// nothing happened.
    pub(super) const EVENTS: usize = 4096;

    /// One event of a recording, in nanoseconds since the recorder's epoch.
    ///
    /// For an acquisition of the session `begun` is when the wait for it began, `held` when it was
    /// taken and `released` when it was let go. `value` is what the site added: the recogniser's
    /// deadline after an input write, and for a supervision wake which part of an observation it
    /// was (see [`crate::runtime::SUPERVISION_COPIED_OUT`]), or zero. For [`Site::TimerWake`],
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
        /// Whether events were lost because the recorder was full.
        pub overflowed: bool,
    }

    /// Marks a slot whose event a recording has already given.
    const GIVEN: u64 = 1 << 63;

    /// The recorder one session carries.
    ///
    /// A slot is reserved once and written by one writer, and no slot is ever reused or cleared, so
    /// a writer that is still storing when a recording is read cannot disturb anyone's event. A
    /// recording is the events stored and not yet given: one whose writer had not finished when the
    /// last recording was read is in the next.
    #[derive(Debug)]
    pub struct LockTrace {
        epoch: Instant,
        armed: AtomicBool,
        /// The slots reserved so far.
        pub(super) taken: AtomicUsize,
        /// The first slot whose event a recording has not yet given.
        unread: AtomicUsize,
        overflowed: AtomicBool,
        pub(super) words: OnceLock<Box<[AtomicU64]>>,
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
                unread: AtomicUsize::new(0),
                overflowed: AtomicBool::new(false),
                words: OnceLock::new(),
            }
        }

        /// A recorder to share between a session's tasks.
        #[must_use]
        pub fn shared() -> Shared {
            Arc::new(Self::new())
        }

        /// Starts recording. The first call allocates the space; nothing allocates after it.
        pub fn arm(&self) {
            self.words
                .get_or_init(|| (0..EVENTS * WORDS).map(|_| AtomicU64::new(0)).collect());
            self.armed.store(true, Ordering::Release);
        }

        /// Stops recording. What was recorded stays until the recorder is dropped. An acquisition
        /// that began before this is still stored when it ends.
        pub fn disarm(&self) {
            self.armed.store(false, Ordering::Release);
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

        /// Gives the events stored since the last time it was called, in the order they finished.
        ///
        /// An event whose writer has not finished is not in it, and is in the next one. One reader
        /// at a time: the measurement that armed the recorder.
        #[must_use]
        pub fn recording(&self) -> Recording {
            let mut events = Vec::new();
            if let Some(words) = self.words.get() {
                let used = self.taken.load(Ordering::Acquire).min(EVENTS);
                let first = self.unread.load(Ordering::Acquire).min(used);
                let mut contiguous = true;
                let mut next = first;
                for (index, slot) in words.chunks(WORDS).enumerate().take(used).skip(first) {
                    // A slot is whole once its site is stored, which is the last store.
                    let word = slot[0].load(Ordering::Acquire);
                    if word == 0 {
                        contiguous = false;
                        continue;
                    }
                    if contiguous {
                        next = index + 1;
                    }
                    if word & GIVEN != 0 {
                        continue;
                    }
                    let Some(site) = Site::from_code(word) else {
                        continue;
                    };
                    events.push(Event {
                        site,
                        begun: slot[1].load(Ordering::Relaxed),
                        held: slot[2].load(Ordering::Relaxed),
                        released: slot[3].load(Ordering::Relaxed),
                        value: slot[4].load(Ordering::Relaxed),
                    });
                    slot[0].store(word | GIVEN, Ordering::Release);
                }
                self.unread.store(next, Ordering::Release);
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

        /// Begins an acquisition of the session, or a span of work, if anything is being recorded.
        ///
        /// It is recorded when it is dropped, so it is declared before the guard of the session and
        /// ends after the guard has let go.
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

    /// One acquisition of the session, or one span of work, recorded when it ends.
    #[derive(Debug)]
    pub struct Acquisition<'a> {
        recorder: Option<&'a LockTrace>,
        site: Site,
        begun: u64,
        held: u64,
        value: u64,
    }

    impl Acquisition<'_> {
        /// Says that the session is held now, or that the span's work has ended.
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

    /// What a session's tasks share of the recorder, which in a shipped build is nothing.
    pub type Shared = LockTrace;

    /// The recorder a shipped build carries, which records nothing.
    #[derive(Clone, Debug, Default)]
    pub struct LockTrace;

    impl LockTrace {
        /// A recorder to share between a session's tasks.
        #[must_use]
        pub const fn shared() -> Shared {
            Self
        }

        /// Begins an acquisition, which is not recorded.
        pub const fn acquisition(&self, _site: Site) -> Acquisition {
            Acquisition
        }

        /// Does nothing.
        pub const fn timer_woke(&self, _deadline: Instant) {}
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

#[cfg(all(test, feature = "testing"))]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{LockTrace, Site};

    fn sites(recording: &super::Recording) -> Vec<Site> {
        recording.events.iter().map(|event| event.site).collect()
    }

    #[test]
    fn a_recording_gives_each_event_once_and_an_event_that_ends_late_is_in_the_next() {
        let trace = LockTrace::new();
        trace.arm();

        let mut late = trace.acquisition(Site::Ingest);
        late.held();
        drop(trace.acquisition(Site::TimerLook));
        assert_eq!(
            sites(&trace.recording()),
            [Site::TimerLook],
            "an acquisition that has not ended is not in it"
        );

        drop(late);
        let second = trace.recording();
        assert_eq!(
            sites(&second),
            [Site::Ingest],
            "and it is in the next, with the instants it kept"
        );
        assert!(second.events[0].begun <= second.events[0].held);
        assert!(
            trace.recording().events.is_empty(),
            "nothing is given twice"
        );
    }

    /// A slot reserved and not yet published, with a later one published before a recording is
    /// read: the earlier one is given once it is published, and the later one is not given twice.
    #[test]
    fn a_slot_reserved_before_a_published_one_is_given_when_it_is_published() {
        let trace = LockTrace::new();
        trace.arm();

        // A writer that has reserved its slot and has not stored its event.
        let reserved = trace.taken.fetch_add(1, Ordering::AcqRel);
        assert_eq!(reserved, 0);
        drop(trace.acquisition(Site::TimerLook));
        assert_eq!(
            sites(&trace.recording()),
            [Site::TimerLook],
            "the slot after the unpublished one is given"
        );

        trace.words.get().expect("armed")[0].store(Site::Ingest.code(), Ordering::Release);
        assert_eq!(
            sites(&trace.recording()),
            [Site::Ingest],
            "and the unpublished one, once it is published, in the next"
        );
        assert!(
            trace.recording().events.is_empty(),
            "and neither of them again"
        );
    }

    #[test]
    fn a_full_recorder_stops_and_says_so_rather_than_wrap() {
        let trace = LockTrace::new();
        trace.arm();
        drop(trace.acquisition(Site::TimerLook));
        for _ in 0..super::recording::EVENTS + 3 {
            drop(trace.acquisition(Site::Ingest));
        }
        let recording = trace.recording();
        assert_eq!(recording.events.len(), super::recording::EVENTS);
        assert_eq!(
            recording.events[0].site,
            Site::TimerLook,
            "the first event is kept, not written over"
        );
        assert!(recording.overflowed, "the loss is marked");
    }

    #[test]
    fn nothing_is_recorded_while_it_is_not_armed() {
        let trace = LockTrace::new();
        trace.arm();
        trace.disarm();
        let mut acquisition = trace.acquisition(Site::Ingest);
        acquisition.held();
        drop(acquisition);
        trace.timer_woke(std::time::Instant::now());
        assert!(trace.recording().events.is_empty());
    }
}
