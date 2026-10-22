//! A pause a test puts between two steps of a task of this crate or of the host, so that a case
//! reaches the state between them by a condition and never by a delay.
//!
//! It compiles to nothing without the `testing` feature, and no shipped build enables it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The pause a task takes where a test holds it.
#[derive(Debug, Default)]
pub struct Hold {
    state: Mutex<Option<Arc<HoldState>>>,
    wake: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct HoldState {
    parked: AtomicBool,
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
    pub async fn pause(&self) {
        loop {
            let held = {
                let mut slot = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match slot.as_ref() {
                    None => return,
                    Some(state) if state.released.load(Ordering::Acquire) => {
                        *slot = None;
                        return;
                    }
                    Some(state) => {
                        state.parked.store(true, Ordering::Release);
                        Arc::clone(state)
                    }
                }
            };
            if held.released.load(Ordering::Acquire) {
                continue;
            }
            self.wake.notified().await;
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
    /// Returns true once the task has what it took in hand and has stopped at the hold.
    #[must_use]
    pub fn parked(&self) -> bool {
        self.state.parked.load(Ordering::Acquire)
    }

    /// Lets the task go on.
    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.hold.wake.notify_one();
    }
}
