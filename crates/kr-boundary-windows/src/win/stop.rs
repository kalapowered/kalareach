//! The broker's stop event. Its handle is private to this module, so every wait that includes the
//! stop goes through [`Stop`]: a wait on the stop alone, or on the stop and other objects. A wait
//! that fails is kept for every later reader, which then sees the stop set, and the service ends
//! with that error.

#![allow(unsafe_code)]

use std::ptr::null;
use std::sync::Arc;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent};

use super::ffi::{self, Handle, Result, last};

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
    /// reader sees the stop set.
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
    /// must be able to end takes this and not a sleep.
    #[must_use]
    pub fn wait(&self, duration: std::time::Duration) -> bool {
        self.waited(ffi::milliseconds(duration, INFINITE - 1))
    }

    /// Waits for the stop or for one of `others`, for up to the milliseconds. The stop is the first
    /// handle, so a transfer or a child that ended at the same moment does not win over a stop that
    /// is set: the answer is `Signalled(0)` for the stop and `Signalled(n + 1)` for `others[n]`.
    /// This is the one wait on the event that another module can make. A wait that fails is kept
    /// for every later reader, as the unread stop, and sets the event; its error is returned to
    /// the caller as well, so that the caller ends with it. Where a failure was kept earlier the
    /// stop is set and the answer is `Signalled(0)` without a wait.
    ///
    /// # Errors
    ///
    /// Returns the platform's error, in words that start with `what`, when the wait failed.
    pub(super) fn wait_for(
        &self,
        others: &[HANDLE],
        milliseconds: u32,
        what: &str,
    ) -> Result<ffi::Waited> {
        if self.unread.get().is_some() {
            return Ok(ffi::Waited::Signalled(0));
        }
        let mut handles = Vec::with_capacity(others.len() + 1);
        handles.push(self.event.raw());
        handles.extend_from_slice(others);
        // text: stop_wait_for-1
        match ffi::wait_any(&handles, milliseconds, what) {
            Ok(waited) => Ok(waited),
            Err(failure) => {
                let _ = self.unread.set(Failure::Wait(failure.to_string()));
                self.set();
                Err(failure)
            }
        }
    }
}
