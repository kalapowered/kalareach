//! Opening a journal whose previous holder is still letting go of it.
//!
//! A store in write-ahead mode keeps an index in a file of its own, and the first process to open
//! the store after every other holder has gone resets that file. On Windows the reset is refused
//! while any process still has the file mapped, and a process that is ending releases its locks
//! on the index before the system removes its mapping. A process that opens the store in that
//! interval is told `SQLITE_IOERR_TRUNCATE`, which reads as "disk I/O error", although the disk
//! has not failed and the same open succeeds a moment later. The interval is the end of the
//! previous holder: a worker whose session has just closed, or a worker that was ended.
//!
//! SQLite does not retry this on Windows, so the openers do: they ask again for as long as the
//! store gives that answer, and give the answer up once it has lasted [`PATIENCE`], which is the
//! store being held by something that is not letting go. The same code is also what the store
//! says when it cannot extend the index for want of room, and that refusal is then given up after
//! [`PATIENCE`] as it was before the wait.

use std::time::{Duration, Instant};

/// How long an open that is told the previous holder has not let go yet asks again before it
/// reports the refusal.
///
/// The interval is the time the system takes to remove one process's mappings, so a store still
/// refusing after this long is held by a process that is running, not by one that is ending. It
/// is the same bound the stores give a lock another connection holds.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// How long an open waits between two asks.
const BETWEEN_ASKS: Duration = Duration::from_millis(5);

/// Whether the store's answer says its previous holder has not let go of its index yet.
#[must_use]
pub fn is_a_holder_letting_go(error: &rusqlite::Error) -> bool {
    cfg!(windows)
        && matches!(
            error,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.extended_code == rusqlite::ffi::SQLITE_IOERR_TRUNCATE
        )
}

/// Runs `attempt`, again for as long as the store says its previous holder has not let go of it,
/// and returns the first answer that says anything else.
///
/// # Errors
///
/// Returns the store's last refusal when it still says so after [`PATIENCE`], and every other
/// refusal the first time it is given.
pub fn once_the_previous_holder_has_let_go<T>(
    mut attempt: impl FnMut() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        match attempt() {
            Err(error) if is_a_holder_letting_go(&error) && Instant::now() < deadline => {
                #[cfg(feature = "testing")]
                announce_the_wait();
                std::thread::sleep(BETWEEN_ASKS);
            }
            answer => return answer,
        }
    }
}

#[cfg(feature = "testing")]
thread_local! {
    /// What a test runs the next time an open on this thread waits for a previous holder.
    static ON_THE_NEXT_WAIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` the next time an open on this thread is told its previous holder has not let go,
/// once, before the open asks again, for this host's own tests.
///
/// It is how a test lets go of a store at the moment the open is waiting for it, rather than
/// after a time it chose. It belongs to the calling thread, because an open waits on the thread
/// that asked, so a test running beside another one cannot be answered with the other's wait. It
/// is compiled away in every shipped build.
#[cfg(feature = "testing")]
pub fn on_the_next_wait(hook: impl FnOnce() + 'static) {
    ON_THE_NEXT_WAIT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Runs the hook a test left for this thread's next wait, if it left one.
#[cfg(feature = "testing")]
fn announce_the_wait() {
    let hook = ON_THE_NEXT_WAIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
