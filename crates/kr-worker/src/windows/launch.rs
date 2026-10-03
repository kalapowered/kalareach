//! Starting an agent on Windows: in its jobs before it runs, with only the handles it is given.

use std::sync::{Mutex, MutexGuard};

/// The lock every start of a process takes while this worker's streams are inheritable.
static INHERITING: Mutex<()> = Mutex::new(());

/// Takes the lock a start holds for as long as a handle of this worker's can be inherited.
///
/// A launch makes the ends of the streams it gives the agent inheritable only for the call that
/// creates it, and a process any other part of this worker creates meanwhile would inherit them
/// too: the backend's write end held by a stranger is a reader that never sees the end of file. The
/// standard library's own lock is private to its calls, so every start this worker makes takes this
/// one.
pub fn inheriting() -> MutexGuard<'static, ()> {
    INHERITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
