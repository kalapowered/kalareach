//! A clock and a wait that a case moves, for the cases that hold how long a run waits at the most.
//!
//! Time passes on a [`Made`] clock only when a case moves it or when a wait of its own runs out, so
//! what a run waited is read off the clock by a condition and never measured. Nothing here waits for
//! a duration: a wait that runs out moves the clock to the moment it was asked to wait until, and
//! one that is given a message waits for the message and moves nothing.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::Done;

/// How long a wait that is given a message waits for it, which only ends a case whose message never
/// comes. The wait never takes this long when the run is right.
const MESSAGE_GUARD: Duration = Duration::from_secs(30);

/// What one wait of a run is, in the order the run makes them.
#[derive(Clone, Copy)]
pub(crate) enum Wait {
    /// The thread waited for sends: the wait takes its message, and no time passes.
    Message,
    /// The thread waited for never sends: the clock moves to the moment waited until, and the wait
    /// times out. A wait beyond the ones a case lists runs out.
    RunsOut,
}

/// A clock that stands where it is until it is moved.
pub(crate) struct Made {
    start: Instant,
    passed: Cell<Duration>,
    waits: RefCell<VecDeque<Wait>>,
    asked: RefCell<Vec<Duration>>,
}

impl Made {
    /// A clock at its start, whose waits are the given ones, in the order a run makes them.
    pub(crate) fn new(waits: impl IntoIterator<Item = Wait>) -> Self {
        Self {
            start: Instant::now(),
            passed: Cell::new(Duration::ZERO),
            waits: RefCell::new(waits.into_iter().collect()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// Where the clock began, which is when a case starts its run.
    pub(crate) fn start(&self) -> Instant {
        self.start
    }

    /// The clock's reading.
    pub(crate) fn now(&self) -> Instant {
        self.start + self.passed.get()
    }

    /// How far the clock has moved from its start.
    pub(crate) fn passed(&self) -> Duration {
        self.passed.get()
    }

    /// Moves the clock on: time that something other than a wait takes.
    pub(crate) fn pass(&self, time: Duration) {
        self.passed.set(self.passed.get() + time);
    }

    /// Every moment a run asked a wait to wait until, as how long after the start, in the order it
    /// asked.
    pub(crate) fn asked(&self) -> Vec<Duration> {
        self.asked.borrow().clone()
    }

    /// The wait a run is given: the next one of the clock's list, asked to wait until `by`.
    pub(crate) fn wait(
        &self,
        channel: &Receiver<Done>,
        by: Instant,
    ) -> Result<Done, RecvTimeoutError> {
        let until = by.saturating_duration_since(self.start);
        self.asked.borrow_mut().push(until);
        match self.waits.borrow_mut().pop_front().unwrap_or(Wait::RunsOut) {
            Wait::Message => channel.recv_timeout(MESSAGE_GUARD),
            Wait::RunsOut => {
                self.passed.set(self.passed.get().max(until));
                Err(RecvTimeoutError::Timeout)
            }
        }
    }
}
