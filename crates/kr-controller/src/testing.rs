//! How this crate's tests, and the suites of the crates above it, start a daemon.
//!
//! Compiled for this crate's own tests and with the `testing` feature, which no build this product
//! ships enables.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::quiet::Timer;

use crate::error::{ControllerError, Result};

/// How long a start is given to take over an environment that is still held.
///
/// A daemon lets go of its environment once nothing of it is left, and its own tasks can hold it
/// for a moment after a suite has let it go: they keep a weak reference and upgrade it to act,
/// which a count of the daemon's references does not see. A daemon a suite killed lets go when its
/// process has ended and the kernel has closed the lock it held. A start can therefore find the
/// environment held. That is a liveness condition: what a suite asserts is that the start takes
/// the environment over, not how soon the holder lets go.
pub const ENVIRONMENT_HANDOVER_DEADLINE: Duration = Duration::from_secs(120);

/// How long a start waits before it tries again.
const RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// Starts a daemon with `start`, and again while the environment is held, until
/// [`ENVIRONMENT_HANDOVER_DEADLINE`] has passed since the first attempt.
///
/// # Errors
///
/// Returns the first failure that is not the environment being held as soon as it happens, and
/// the environment still being held once the deadline has passed.
pub async fn taken_over<T, F, S>(mut start: F) -> Result<T>
where
    F: FnMut() -> S,
    S: Future<Output = Result<T>>,
{
    let begun = std::time::Instant::now();
    loop {
        match start().await {
            Err(ControllerError::AlreadyRunning { .. })
                if begun.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
            outcome => return outcome,
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

/// The wait between two passes of a carrier, held by the test.
///
/// Each wait the daemon asks for is recorded with its length and goes on only when the test
/// releases it, or at once once the test lets the timer run by itself. A timer that runs by itself
/// releases the waits it already holds as well, because the daemon may have asked for one the test
/// has not looked at.
///
/// The clock a delay the service named is counted against stands still too, until the test moves
/// it, so what is left of a delay is exactly what the test made it, however long the test takes.
#[derive(Debug)]
pub struct HeldTimer {
    automatic: AtomicBool,
    waits: Mutex<Vec<Held>>,
    asked: Notify,
    now: Mutex<std::time::Instant>,
}

impl Default for HeldTimer {
    fn default() -> Self {
        Self {
            automatic: AtomicBool::new(false),
            waits: Mutex::default(),
            asked: Notify::new(),
            now: Mutex::new(std::time::Instant::now()),
        }
    }
}

/// One wait the daemon asked for.
#[derive(Debug)]
struct Held {
    duration: Duration,
    release: Arc<Notify>,
    /// Whether the test has taken it from [`HeldTimer::next_wait`].
    taken: bool,
}

impl Timer for HeldTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        // The flag and the list are read and changed under one lock, so a wait is either released
        // by the test or held for it, never both missed.
        let mut waits = self.waits.lock().expect("the waits");
        if self.automatic.load(Ordering::SeqCst) {
            return Box::pin(tokio::task::yield_now());
        }
        let release = Arc::new(Notify::new());
        waits.push(Held {
            duration,
            release: Arc::clone(&release),
            taken: false,
        });
        drop(waits);
        self.asked.notify_one();
        Box::pin(async move { release.notified().await })
    }

    fn now(&self) -> std::time::Instant {
        *self.now.lock().expect("the clock")
    }
}

impl HeldTimer {
    /// A timer that lets every wait end at once.
    pub fn automatic() -> Arc<Self> {
        let timer = Arc::new(Self::default());
        timer.automatic.store(true, Ordering::SeqCst);
        timer
    }

    /// A timer that holds every wait until the test releases it.
    pub fn held() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The next wait the daemon asked for that the test has not looked at, with the means to let
    /// it end.
    pub async fn next_wait(&self) -> (Duration, Arc<Notify>) {
        loop {
            let asked = self.asked.notified();
            if let Some(held) = self
                .waits
                .lock()
                .expect("the waits")
                .iter_mut()
                .find(|held| !held.taken)
            {
                held.taken = true;
                return (held.duration, Arc::clone(&held.release));
            }
            asked.await;
        }
    }

    /// Moves the clock a delay is counted against.
    pub fn advance(&self, by: Duration) {
        *self.now.lock().expect("the clock") += by;
    }

    /// Every wait the daemon has asked for so far.
    pub fn asked_for(&self) -> Vec<Duration> {
        self.waits
            .lock()
            .expect("the waits")
            .iter()
            .map(|held| held.duration)
            .collect()
    }

    /// Lets every wait held now end, and holds those to come.
    pub fn release_held(&self) {
        for held in self.waits.lock().expect("the waits").iter() {
            held.release.notify_one();
        }
    }

    /// Lets every wait, those held and those to come, end at once.
    pub fn run_by_itself(&self) {
        let waits = self.waits.lock().expect("the waits");
        self.automatic.store(true, Ordering::SeqCst);
        for held in waits.iter() {
            held.release.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Controller;
    use crate::service::net::tests::setup;
    use crate::singleton::SingletonLock;

    /// A start that meets its environment held waits, and takes the environment over once the
    /// holder lets go.
    ///
    /// The holder is this test's own, and it lets go the first time the start waits. A daemon takes
    /// the environment's lock before it waits for anything, so that is after the first attempt met
    /// the environment held, and nothing here depends on timing. The control is the same start
    /// without the wait, which meets the environment held and fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_start_takes_the_environment_over_once_its_holder_lets_go() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let lock = SingletonLock::acquire(&environment.singleton_lock(), temp.environment_id())
            .expect("this test holds the environment");

        let Err(ControllerError::AlreadyRunning { .. }) =
            Controller::start(setup(&temp, boot.clone())).await
        else {
            panic!("a start without the wait meets the environment held and fails");
        };

        let attempts = std::cell::Cell::new(0_u32);
        let mut holder = Some(lock);
        let mut start = std::pin::pin!(taken_over(|| {
            attempts.set(attempts.get() + 1);
            Controller::start(setup(&temp, boot.clone()))
        }));
        let started = std::future::poll_fn(|context| {
            let polled = start.as_mut().poll(context);
            if polled.is_pending() {
                holder = None;
            }
            polled
        })
        .await;
        let controller = started.expect("the start takes the environment over once it is let go");
        assert!(holder.is_none(), "the start waited before it took over");
        assert!(
            attempts.get() >= 2,
            "the start met the environment held and tried again: {} attempts",
            attempts.get()
        );
        drop(controller);
    }

    /// The control: a start on an environment nothing holds starts on its first attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_start_with_nothing_held_starts_on_its_first_attempt() {
        let temp = kr_ipc::testing::TempHost::create();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let attempts = std::cell::Cell::new(0_u32);
        let controller = taken_over(|| {
            attempts.set(attempts.get() + 1);
            Controller::start(setup(&temp, boot.clone()))
        })
        .await
        .expect("the daemon starts");
        assert_eq!(attempts.get(), 1);
        drop(controller);
    }
}
