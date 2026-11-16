//! The call's view as a case reads it: a lock whose release can open a window for one read of the
//! state, at the moment the view first shows a new end.
//!
//! A case arms the window before it makes a call end. The first hold of the view that shows an end
//! the view did not show when the window was armed opens it, as that hold is released and wherever
//! in the supervisor or the owner it is: the writer then waits, with the view free, for the case to
//! say that its read has finished. Where the end and what it owes are written in one hold, the read
//! finds both. Where the end is written in a hold of its own, and what it owes in a later one, the
//! read finds the end without its entry, in every schedule: the writer does not go on until the
//! read has finished, and the read does not wait for anything the writer holds.
//!
//! Compiled only for cases (`cfg(any(test, feature = "testing"))`): a shipped build holds the plain
//! mutex under the same name.

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, LockResult, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::view::VoiceCallState;

/// How long the writer waits in the window for the case's read to finish, at the most. A writer
/// that runs out has not been read in the window, and the case fails: it asks whether this
/// happened ([`ViewLock::writer_gave_up`]) once its read is over. The bound exists so that a case
/// that failed for another reason never leaves a thread waiting for ever.
const READ_WITHIN: Duration = Duration::from_secs(60);

/// Where the window stands.
#[derive(Default)]
struct Window {
    /// The next hold that shows a new end opens the window.
    armed: bool,
    /// The owner of the end the view showed when the window was armed: not a new end.
    seen: Option<u64>,
    /// The window is open.
    open: bool,
    /// The case's read has finished.
    finished: bool,
    /// The writer stopped waiting before the read finished.
    gave_up: bool,
}

/// The call's view, behind a lock that can open the window.
pub(super) struct ViewLock {
    view: Mutex<VoiceCallState>,
    /// Whether the window is armed, read first by every release so that an unarmed lock costs one
    /// load.
    armed: AtomicBool,
    window: Mutex<Window>,
    /// Told when the case's read has finished.
    changed: Condvar,
    /// Told when the window opens.
    opened: tokio::sync::Notify,
}

impl ViewLock {
    pub(super) fn new(state: VoiceCallState) -> Self {
        Self {
            view: Mutex::new(state),
            armed: AtomicBool::new(false),
            window: Mutex::new(Window::default()),
            changed: Condvar::new(),
            opened: tokio::sync::Notify::new(),
        }
    }

    /// Takes the view, as the mutex does.
    pub(super) fn lock(&self) -> LockResult<ViewGuard<'_>> {
        match self.view.lock() {
            Ok(guard) => Ok(ViewGuard::new(guard, self)),
            Err(poisoned) => Err(PoisonError::new(ViewGuard::new(
                poisoned.into_inner(),
                self,
            ))),
        }
    }

    /// Arms the window: the first hold that shows an end other than the one the view shows now
    /// opens it.
    pub(super) fn arm(&self) {
        let seen = self
            .view
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ended
            .as_ref()
            .map(|ended| ended.owner);
        *self.window.lock().expect("the record is not poisoned") = Window {
            armed: true,
            seen,
            ..Window::default()
        };
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Waits until the window is open.
    pub(super) async fn until_open(&self) {
        loop {
            let opened = self.opened.notified();
            tokio::pin!(opened);
            opened.as_mut().enable();
            if self.window.lock().expect("the record is not poisoned").open {
                return;
            }
            opened.await;
        }
    }

    /// Says that the case's read, in the window, has finished.
    pub(super) fn finish(&self) {
        self.window
            .lock()
            .expect("the record is not poisoned")
            .finished = true;
        self.changed.notify_all();
    }

    /// Whether the writer stopped waiting in the window before the case's read had finished.
    pub(super) fn writer_gave_up(&self) -> bool {
        self.window
            .lock()
            .expect("the record is not poisoned")
            .gave_up
    }

    /// Called as a hold of the view is released, with the owner of the end that hold showed. Opens
    /// the window if it is armed and the end is a new one, and waits in it for the case's read.
    fn released(&self, shown: Option<u64>) {
        let Some(owner) = shown else {
            return;
        };
        if std::thread::panicking() {
            return;
        }
        let mut window = self.window.lock().expect("the record is not poisoned");
        if !window.armed || window.seen == Some(owner) {
            return;
        }
        window.armed = false;
        self.armed.store(false, Ordering::SeqCst);
        window.open = true;
        self.opened.notify_waiters();
        let (mut window, timeout) = self
            .changed
            .wait_timeout_while(window, READ_WITHIN, |window| !window.finished)
            .expect("the record is not poisoned");
        if timeout.timed_out() {
            window.gave_up = true;
        }
    }
}

/// A hold of the view. Its release opens the window when it should.
pub(super) struct ViewGuard<'a> {
    guard: Option<MutexGuard<'a, VoiceCallState>>,
    lock: &'a ViewLock,
}

impl<'a> ViewGuard<'a> {
    fn new(guard: MutexGuard<'a, VoiceCallState>, lock: &'a ViewLock) -> Self {
        Self {
            guard: Some(guard),
            lock,
        }
    }
}

impl Deref for ViewGuard<'_> {
    type Target = VoiceCallState;

    fn deref(&self) -> &VoiceCallState {
        self.guard.as_ref().expect("the view is held")
    }
}

impl DerefMut for ViewGuard<'_> {
    fn deref_mut(&mut self) -> &mut VoiceCallState {
        self.guard.as_mut().expect("the view is held")
    }
}

impl Drop for ViewGuard<'_> {
    fn drop(&mut self) {
        let shown = if self.lock.armed.load(Ordering::SeqCst) {
            self.guard
                .as_ref()
                .and_then(|view| view.ended.as_ref().map(|ended| ended.owner))
        } else {
            None
        };
        // The lock is released before the window is entered: the reader reads a free view.
        drop(self.guard.take());
        self.lock.released(shown);
    }
}
