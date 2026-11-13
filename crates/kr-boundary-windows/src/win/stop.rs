//! The broker's stop event. Its handle is private to this module, so every wait that includes the
//! stop goes through [`Stop`]: a wait on the stop alone, or on the stop and other objects. A wait
//! that fails is kept for every later reader, which then sees the stop set, and the service ends
//! with that error.

#![allow(unsafe_code)]

use std::ptr::null;
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent};

use super::ffi::{self, Handle, Result, last};

/// How long a wait on the stop waits before it reads the stop's kept failure again. It exists
/// because a stop event that could not be set wakes nobody: the failure is only kept, and only a
/// wait that comes back to read it sees it, so every wait on the stop, whatever its bound, ends
/// within one slice of a failed set. The cost is one idle wake-up a second for each waiter.
pub(super) const STOP_SLICE: Duration = Duration::from_secs(1);

/// An event that, once set, ends every wait of every connection that holds it.
///
/// A wait on the event has three answers: set, not set, and failed. A failed wait says nothing about
/// the event, so it does not count as "not set": it sets the stop for good, which ends the work,
/// and the failure is kept for [`Stop::unread`], which the service reports. Every reader after it
/// sees the stop set, and [`Stop::reason`] says which of the two it is. The same holds where the
/// event cannot be set: no wait would see the stop then, so the failure is kept and every reader
/// takes it as the stop.
pub struct Stop {
    event: Handle,
    unread: std::sync::OnceLock<Failure>,
}

/// What failed first on the stop event: a wait on it, or the call that sets it. The two are told in
/// their own words, since a failed set shows nothing of any wait.
enum Failure {
    /// A wait on the event failed.
    Wait(String),
    /// The event could not be set.
    Set(String),
}

impl Failure {
    fn words(&self) -> &str {
        match self {
            Failure::Wait(words) | Failure::Set(words) => words,
        }
    }
}

impl Stop {
    /// A new stop event, not set.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the event cannot be made.
    pub fn new() -> Result<Arc<Stop>> {
        // SAFETY: a manual-reset event with no name and no security attributes.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        Ok(Arc::new(Stop {
            // text: pipe_new-1
            event: Handle::new(event, "making the stop event")?,
            unread: std::sync::OnceLock::new(),
        }))
    }

    /// Ends every wait. Where the event cannot be set, the failure is kept as the unread stop, so
    /// that every reader sees the stop set through it.
    pub fn set(&self) {
        // SAFETY: the event handle is open.
        if unsafe { SetEvent(self.event.raw()) } == 0 {
            // text: stop_set-1
            let failure = Failure::Set(last("setting the stop event").to_string());
            let _ = self.unread.set(failure);
        }
    }

    /// Makes the set of the event fail for a case, as `set` keeps a set that failed: the failure is
    /// kept and the event is not signalled, so that only a wait that comes back to read the kept
    /// failure sees the stop. For the test build only.
    #[cfg(all(test, feature = "testing"))]
    pub(super) fn fail_the_set_for_a_case(&self) {
        self.unread
            .get_or_init(|| Failure::Set("a case made the set fail".to_owned()));
    }

    /// Whether the event is set, or could not be waited on (see [`Stop::unread`]).
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.waited(0)
    }

    /// The error of a wait on the event that failed, or of a failure to set it, if one did.
    #[must_use]
    // text: unread
    pub fn unread(&self) -> Option<&str> {
        self.unread.get().map(Failure::words)
    }

    /// What ended the work, in words, for a reader that finds the stop set: that the service is
    /// stopping, or, where a wait on the event failed, that the stop could not be read, or, where
    /// the event could not be set, that it could not be set, each with the error. A failed wait or
    /// a failed set is never told as a stop that someone asked for.
    #[must_use]
    // text: stop_reason
    pub fn reason(&self) -> String {
        match self.unread.get() {
            Some(Failure::Wait(unread)) => format!("the stop could not be read ({unread})"),
            Some(Failure::Set(unread)) => format!("the stop could not be set ({unread})"),
            None => "the service is stopping".to_owned(),
        }
    }

    /// Waits on the event for up to the milliseconds. Returns whether it is set, or whether the wait
    /// failed, which is kept in `unread` and sets the event, so that every later wait and every later
    /// reader sees the stop set. The wait is made in slices of [`STOP_SLICE`] at most (see
    /// [`Stop::wait_for`]).
    fn waited(&self, milliseconds: u32) -> bool {
        match self.wait_for(&[], milliseconds, "waiting on the stop event") {
            Ok(ffi::Waited::Signalled(_)) => true,
            Ok(ffi::Waited::TimedOut) => false,
            // The failure was kept by `wait_for`, so every reader sees the stop set and says why.
            Err(_) => true,
        }
    }

    /// Waits for as long as `duration` or until the event is set, and says whether it is set (or
    /// could not be waited on, as [`Stop::is_set`]). A pause of a request's own work that the stop
    /// must be able to end takes this and not a sleep. The wait is made in slices of one second at
    /// most, each of which reads the stop's kept failure, so a stop that could not be set ends a
    /// long pause within a slice.
    #[must_use]
    pub fn wait(&self, duration: Duration) -> bool {
        self.waited(ffi::milliseconds(duration, INFINITE - 1))
    }

    /// Waits for the stop or for one of `others`, for up to `bound` milliseconds (`INFINITE`: no
    /// bound). The stop is the first handle, so a transfer or a child that ended at the same moment
    /// does not win over a stop that is set: the answer is `Signalled(0)` for the stop and
    /// `Signalled(n + 1)` for `others[n]`. This is the one wait on the event that another module
    /// can make. A wait that fails is kept for every later reader, as the unread stop, and sets
    /// the event; its error is returned to the caller as well, so that the caller ends with it.
    ///
    /// The wait is made in slices of [`STOP_SLICE`] at most, whatever the bound, and the kept
    /// failure is read before each slice: where one was kept, by a failed wait or by a set that
    /// failed, the stop is set and the answer is `Signalled(0)` at once, within one slice of the
    /// failure. The bound's total is the caller's: the slices end at the bound, as one wait would.
    ///
    /// # Errors
    ///
    /// Returns the platform's error, in words that start with `what`, when the wait failed.
    pub(super) fn wait_for(
        &self,
        others: &[HANDLE],
        bound: u32,
        what: &str,
    ) -> Result<ffi::Waited> {
        let mut handles = Vec::with_capacity(others.len() + 1);
        handles.push(self.event.raw());
        handles.extend_from_slice(others);
        // Where the bound ends, or none where it is "forever".
        let end =
            (bound != INFINITE).then(|| Instant::now() + Duration::from_millis(u64::from(bound)));
        loop {
            if self.unread.get().is_some() {
                return Ok(ffi::Waited::Signalled(0));
            }
            let slice = end.map_or(STOP_SLICE, |end| {
                end.saturating_duration_since(Instant::now())
                    .min(STOP_SLICE)
            });
            // One less than the longest wait, which means "forever".
            let milliseconds = ffi::milliseconds(slice, INFINITE - 1);
            // text: stop_wait_for-1
            match ffi::wait_any(&handles, milliseconds, what) {
                // A slice that ended with nothing signalled is followed by another while the bound
                // has not run out: the next turn reads the kept failure first.
                Ok(ffi::Waited::TimedOut) if end.is_none_or(|end| Instant::now() < end) => {}
                Ok(waited) => return Ok(waited),
                Err(failure) => {
                    let _ = self.unread.set(Failure::Wait(failure.to_string()));
                    self.set();
                    return Err(failure);
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use super::*;

    /// An event that nothing has signalled, for a wait that stands in for a transfer or a child.
    fn another_event() -> Arc<Handle> {
        // SAFETY: a manual-reset event with no name and no security attributes.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        Arc::new(Handle::new(event, "making a case's event").unwrap())
    }

    /// Runs `wait` while the stop's set fails 300 ms in (the failure is kept and the event is never
    /// signalled), and says how long the wait took and what it answered.
    fn while_the_set_fails<T>(stop: &Arc<Stop>, wait: impl FnOnce() -> T) -> (Duration, T) {
        let late = Arc::clone(stop);
        let failer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            late.fail_the_set_for_a_case();
        });
        let started = Instant::now();
        let answer = wait();
        let took = started.elapsed();
        failer.join().unwrap();
        (took, answer)
    }

    fn the_stop_is_read_as_not_set(stop: &Stop) {
        assert!(
            stop.reason().contains("the stop could not be set"),
            "{}",
            stop.reason()
        );
        assert!(stop.unread().is_some());
    }

    /// A pause that the stop must end, with a bound of fifteen minutes or none, ends within two
    /// slices of a stop that could not be set.
    #[test]
    fn a_wait_on_the_stop_ends_within_two_slices_of_a_stop_that_could_not_be_set() {
        for pause in [
            Duration::from_secs(900),
            Duration::from_secs(u64::from(u32::MAX)),
        ] {
            let stop = Stop::new().unwrap();
            let (took, set) = while_the_set_fails(&stop, || stop.wait(pause));
            assert!(set, "a failed set reads as the stop");
            assert!(took < 2 * STOP_SLICE, "{pause:?}: {took:?}");
            the_stop_is_read_as_not_set(&stop);
        }
    }

    /// The wait that other modules make, on the stop and another handle, with a long bound or none,
    /// ends within two slices of a stop that could not be set, and answers with the stop.
    #[test]
    fn a_wait_on_the_stop_and_another_handle_ends_within_two_slices_of_a_stop_that_could_not_be_set()
     {
        for bound in [900_000, INFINITE] {
            let stop = Stop::new().unwrap();
            let other = another_event();
            let (took, waited) = while_the_set_fails(&stop, || {
                stop.wait_for(&[other.raw()], bound, "waiting in a case")
            });
            assert!(
                matches!(waited, Ok(ffi::Waited::Signalled(0))),
                "{bound}: {waited:?}"
            );
            assert!(took < 2 * STOP_SLICE, "{bound}: {took:?}");
            the_stop_is_read_as_not_set(&stop);
        }
    }

    /// The slices end where the bound ends, and a handle that is signalled in a later slice is
    /// seen: a bound of two and a half seconds waits about that long when nothing comes, a bound of
    /// nothing is a look, and another handle that is signalled in the second slice ends the wait
    /// with its own answer.
    #[test]
    fn the_slices_keep_the_bound_and_see_a_handle_that_is_signalled_in_a_later_slice() {
        let stop = Stop::new().unwrap();
        let started = Instant::now();
        assert!(!stop.wait(Duration::from_millis(2500)));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(2450) && took < Duration::from_millis(3500),
            "{took:?}"
        );
        let started = Instant::now();
        assert!(!stop.is_set());
        assert!(
            matches!(
                stop.wait_for(&[], 0, "looking in a case"),
                Ok(ffi::Waited::TimedOut)
            ),
            "a bound of nothing is one look"
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        let other = another_event();
        let signaller = {
            let other = Arc::clone(&other);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1500));
                // SAFETY: the event handle is open.
                assert_ne!(unsafe { SetEvent(other.raw()) }, 0);
            })
        };
        let started = Instant::now();
        let waited = stop.wait_for(&[other.raw()], 60_000, "waiting in a case");
        let took = started.elapsed();
        signaller.join().unwrap();
        assert!(
            matches!(waited, Ok(ffi::Waited::Signalled(1))),
            "{waited:?}"
        );
        assert!(
            took >= Duration::from_millis(1400) && took < Duration::from_millis(2500),
            "{took:?}"
        );
        assert!(stop.unread().is_none());
    }

    /// A stop that is set ends a wait with a long bound at once, not at the end of a slice.
    #[test]
    fn a_stop_that_is_set_ends_a_long_wait_at_once() {
        let stop = Stop::new().unwrap();
        let late = Arc::clone(&stop);
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            late.set();
        });
        let started = Instant::now();
        assert!(stop.wait(Duration::from_secs(900)));
        let took = started.elapsed();
        setter.join().unwrap();
        assert!(took < STOP_SLICE, "{took:?}");
        assert!(stop.unread().is_none());
    }
}
