//! What the host waits by, and what it owes a service that asked to be left alone.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The longest the host leaves a service alone because it asked: an hour.
///
/// A delay is a number the service wrote. The Worker asks for seconds and minutes, and a service
/// that asks for more is asked again after an hour, so that no answer can keep the host from the
/// service for good or overflow a deadline.
pub const LONGEST_DELAY: Duration = Duration::from_secs(60 * 60);

/// What the host waits on between two passes, and what it measures a delay against.
pub trait Timer: Send + Sync + std::fmt::Debug {
    /// A wait of `duration`.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// The time a delay the service named is counted from and against.
    fn now(&self) -> Instant;
}

/// The clock the daemon waits by.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealTimer;

impl Timer for RealTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// When the service said it may be asked again.
///
/// One deadline for everything that asks the service: the uploader's passes, the question the host
/// asks as it starts and the one `kr doctor` asks. A delay the service names is recorded here by
/// whoever met it, and every question that follows waits for it, except the ones a privacy fence
/// owes, whose cleanup ends work in flight whatever the service asked.
#[derive(Debug)]
pub struct Quiet {
    timer: Arc<dyn Timer>,
    until: Mutex<Option<Instant>>,
}

impl Quiet {
    /// A record with nothing owed, counting time by `timer`.
    #[must_use]
    pub fn new(timer: Arc<dyn Timer>) -> Self {
        Self {
            timer,
            until: Mutex::new(None),
        }
    }

    fn until(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.until.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the service asked to be left alone for `delay`, which is no longer owed
    /// than [`LONGEST_DELAY`], and not less than what was already owed.
    pub fn owe(&self, delay: Duration) {
        let now = self.timer.now();
        let Some(until) = now.checked_add(delay.min(LONGEST_DELAY)) else {
            return;
        };
        let mut owed = self.until();
        *owed = Some(owed.map_or(until, |earlier| earlier.max(until)));
    }

    /// What is left of the delay the service asked for, when some is.
    #[must_use]
    pub fn left(&self) -> Option<Duration> {
        let until = (*self.until())?;
        until
            .checked_duration_since(self.timer.now())
            .filter(|left| !left.is_zero())
    }

    /// The deadline as it stands, so that a wait that ends it can tell whether the service asked
    /// for more while it waited.
    #[must_use]
    pub(super) fn deadline(&self) -> Option<Instant> {
        *self.until()
    }

    /// Ends a delay that has passed, unless the service has asked for more since `seen`.
    pub(super) fn passed(&self, seen: Option<Instant>) {
        let mut owed = self.until();
        if *owed == seen {
            *owed = None;
        }
    }
}
