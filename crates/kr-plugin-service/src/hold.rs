//! A pause a test puts between two steps of a task of this crate or of the host, so that a case
//! reaches the state between them by a condition and never by a delay.
//!
//! It compiles to nothing without the `testing` feature, and no shipped build enables it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The pause a task takes where a test holds it.
#[derive(Debug, Default)]
pub struct Hold {
    state: Mutex<Option<Arc<HoldState>>>,
    wake: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct HoldState {
    /// How many tasks have stopped at this hold.
    parked: AtomicUsize,
    released: AtomicBool,
}

impl Hold {
    /// Holds the task at its next arrival, and returns the handle that releases it.
    pub fn set(self: &Arc<Self>) -> HoldHandle {
        let state = Arc::new(HoldState::default());
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&state));
        HoldHandle {
            state,
            hold: Arc::clone(self),
        }
    }

    /// Waits while a test holds the task, and records that the task has reached the hold.
    ///
    /// Any number of tasks may wait at one hold, and a release lets every one of them go. A task
    /// stops at the hold it finds and leaves when that hold is released, whatever hold has been set
    /// since: a task a release has woken does not go on to wait at the next one. The wait is made
    /// ready before the hold is looked at, so a release that comes between the look and the wait
    /// reaches it.
    pub async fn pause(&self) {
        let mut stopped_at: Option<Arc<HoldState>> = None;
        loop {
            let woken = self.wake.notified();
            let state = match &stopped_at {
                Some(state) => Arc::clone(state),
                None => {
                    let mut slot = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let Some(state) = slot.as_ref().map(Arc::clone) else {
                        return;
                    };
                    if state.released.load(Ordering::Acquire) {
                        *slot = None;
                        return;
                    }
                    state.parked.fetch_add(1, Ordering::AcqRel);
                    stopped_at = Some(Arc::clone(&state));
                    state
                }
            };
            if state.released.load(Ordering::Acquire) {
                let mut slot = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot.as_ref().is_some_and(|set| Arc::ptr_eq(set, &state)) {
                    *slot = None;
                }
                return;
            }
            woken.await;
        }
    }
}

/// A hold on a task. While it is held the task stops with what it took in hand, and does nothing
/// with it.
#[derive(Debug)]
pub struct HoldHandle {
    state: Arc<HoldState>,
    hold: Arc<Hold>,
}

impl HoldHandle {
    /// Returns true once a task has what it took in hand and has stopped at the hold.
    #[must_use]
    pub fn parked(&self) -> bool {
        self.parked_tasks() > 0
    }

    /// Returns how many tasks have stopped at the hold, for a hold that more than one task reaches.
    #[must_use]
    pub fn parked_tasks(&self) -> usize {
        self.state.parked.load(Ordering::Acquire)
    }

    /// Lets every task that waits at the hold go on, and any that arrives after it.
    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.hold.wake.notify_waiters();
    }
}
