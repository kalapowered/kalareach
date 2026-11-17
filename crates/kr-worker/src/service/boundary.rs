//! The dispatch boundary and its guard.
//!
//! The guard is made here and nowhere else: its constructor and its fields are private to this
//! module, so no other code can hold a `DispatchGuard` except by taking the boundary with
//! [`DispatchBoundary::lock`] or [`DispatchBoundary::try_lock`]. The functions that run under the
//! boundary take a borrow of the guard as a parameter, so a caller that does not hold the boundary
//! does not compile.

use std::sync::Mutex;

/// The dispatch boundary: a lock that says so when it is let go.
///
/// Every holder takes it as an ordinary lock and drops its guard as one. Letting go wakes the
/// presentations that wait for it, so that each tries at once and none waits out its pause while
/// the boundary stands free between two mutations.
#[derive(Debug)]
pub(super) struct DispatchBoundary {
    lock: Mutex<()>,
    released: tokio::sync::Notify,
}

impl DispatchBoundary {
    pub(super) fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            released: tokio::sync::Notify::new(),
        }
    }

    /// Takes the boundary, waiting for whoever holds it.
    pub(super) fn lock(&self) -> std::sync::LockResult<DispatchGuard<'_>> {
        self.lock
            .lock()
            .map(|guard| DispatchGuard::new(guard, &self.released))
            .map_err(|poisoned| {
                std::sync::PoisonError::new(DispatchGuard::new(
                    poisoned.into_inner(),
                    &self.released,
                ))
            })
    }

    /// Takes the boundary if nobody holds it, and never waits.
    pub(super) fn try_lock(&self) -> std::sync::TryLockResult<DispatchGuard<'_>> {
        self.lock
            .try_lock()
            .map(|guard| DispatchGuard::new(guard, &self.released))
            .map_err(|refused| match refused {
                std::sync::TryLockError::Poisoned(poisoned) => {
                    std::sync::TryLockError::Poisoned(std::sync::PoisonError::new(
                        DispatchGuard::new(poisoned.into_inner(), &self.released),
                    ))
                }
                std::sync::TryLockError::WouldBlock => std::sync::TryLockError::WouldBlock,
            })
    }

    /// Completes when the boundary is next let go. It is created before a try, so a release that
    /// comes between the try and the wait is not missed.
    pub(super) fn released(&self) -> tokio::sync::futures::Notified<'_> {
        self.released.notified()
    }
}

/// The dispatch boundary, held. Letting go of it wakes the presentations waiting for it.
#[derive(Debug)]
pub struct DispatchGuard<'a> {
    guard: Option<std::sync::MutexGuard<'a, ()>>,
    released: &'a tokio::sync::Notify,
}

impl<'a> DispatchGuard<'a> {
    const fn new(guard: std::sync::MutexGuard<'a, ()>, released: &'a tokio::sync::Notify) -> Self {
        Self {
            guard: Some(guard),
            released,
        }
    }
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        // The lock goes first, so that a woken presentation finds it free.
        drop(self.guard.take());
        self.released.notify_waiters();
    }
}
