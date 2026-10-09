//! How this crate's tests, and the suites of the crates above it, start a daemon.
//!
//! Compiled for this crate's own tests and with the `testing` feature, which no build this product
//! ships enables.

use std::time::Duration;

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

/// What a test runs once, right after the first stop it supplied an answer to.
type AfterRefusal = Box<dyn FnOnce() + Send>;

/// An answer a test supplies for the stop of one process.
struct Supplied {
    identity: kr_protocol::identity::ProcessStartIdentity,
    /// Whether the answer is "this host could not take a hold on it" the first time only, and
    /// the platform's own after, instead of the kernel's refusal every time.
    unsafe_once: bool,
    then: Option<AfterRefusal>,
}

/// The stops a test has supplied an answer for.
static SUPPLIED_STOPS: std::sync::Mutex<Vec<Supplied>> = std::sync::Mutex::new(Vec::new());

/// Makes the stop of one recorded process answer "operation not permitted", as the kernel does for
/// a process that belongs to another account. Every other stop is the platform's own.
///
/// A test cannot make a real process of its own refuse a signal without an account it does not
/// have, and what the cleanup does with a process it cannot stop is the thing under test: the
/// survivor stays a real running process, and the refusal is the only part supplied.
pub fn refuse_stopping(identity: kr_protocol::identity::ProcessStartIdentity) {
    refuse_stopping_then(identity, || {});
}

/// [`refuse_stopping`], and `then` runs once right after the first refusal: a process that is
/// refused a stop and ends on its own afterwards, as one does that the platform will not let this
/// host signal.
pub fn refuse_stopping_then(
    identity: kr_protocol::identity::ProcessStartIdentity,
    then: impl FnOnce() + Send + 'static,
) {
    SUPPLIED_STOPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Supplied {
            identity,
            unsafe_once: false,
            then: Some(Box::new(then)),
        });
}

/// Makes the first stop of one recorded process answer that this host could not take a hold on
/// it, as a platform does that cannot describe the process at that moment. Every later stop of it
/// is the platform's own.
pub fn fail_taking_a_hold_once(identity: kr_protocol::identity::ProcessStartIdentity) {
    SUPPLIED_STOPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Supplied {
            identity,
            unsafe_once: true,
            then: None,
        });
}

/// The answer a test has supplied for the stop of this process, if it has.
pub(crate) fn supplied_stop(
    identity: &kr_protocol::identity::ProcessStartIdentity,
) -> Option<kr_ipc::identity::Stopped> {
    let (answer, then) = {
        let mut stops = SUPPLIED_STOPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let position = stops
            .iter()
            .position(|supplied| supplied.identity == *identity)?;
        if stops[position].unsafe_once {
            stops.remove(position);
            (
                kr_ipc::identity::Stopped::Unsafe("no hold could be taken".to_owned()),
                None,
            )
        } else {
            (
                kr_ipc::identity::Stopped::Refused("Operation not permitted".to_owned()),
                stops[position].then.take(),
            )
        }
    };
    if let Some(then) = then {
        then();
    }
    Some(answer)
}

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
