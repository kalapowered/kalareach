//! The lock a store holds while it changes its files, so that two processes never write one store
//! at once.
//!
//! A lock is taken on a file the store keeps for the purpose and is held by the open file
//! description it was taken on: dropping the last handle to that description releases it, and so
//! does [`release`], which does not wait for the drop. Two handles opened separately on one file
//! are two descriptions, so a lock excludes another thread of the same process as it excludes
//! another process.
//!
//! The standard library's own file lock is not used by any store, because it is not supported on
//! Android: every call answers `Unsupported`, and a store whose lock cannot be taken cannot be
//! opened. On Unix, Android among it, these functions make the same `flock` system call on every
//! target, so what a desktop test runs is the call a phone makes. On Windows they are the standard
//! library's, which locks a region of the file with `LockFileEx`.

use std::fs::{File, TryLockError};

/// Takes the lock on `file` for writing, waiting until no other description of the file holds it,
/// for reading or for writing.
///
/// # Errors
///
/// Returns the operating system's error when the lock cannot be taken.
pub fn exclusive(file: &File) -> std::io::Result<()> {
    platform::exclusive(file)
}

/// Takes the lock on `file` for reading, waiting until no other description of the file holds it for
/// writing. Any number of descriptions hold it for reading at once.
///
/// # Errors
///
/// Returns the operating system's error when the lock cannot be taken.
pub fn shared(file: &File) -> std::io::Result<()> {
    platform::shared(file)
}

/// Takes the lock on `file` for writing if no other description of the file holds it, and does not
/// wait.
///
/// # Errors
///
/// Returns [`TryLockError::WouldBlock`] when another description holds the lock, and
/// [`TryLockError::Error`] with the operating system's error when it cannot be taken.
pub fn try_exclusive(file: &File) -> Result<(), TryLockError> {
    platform::try_exclusive(file)
}

/// Lets go of the lock `file` holds, without waiting for the file to be closed.
///
/// A descriptor copied into a child process keeps the description, and so the lock, alive after the
/// parent closes its own; releasing is what lets go of it at once.
///
/// # Errors
///
/// Returns the operating system's error when the lock cannot be released.
pub fn release(file: &File) -> std::io::Result<()> {
    platform::release(file)
}

#[cfg(unix)]
mod platform {
    use std::fs::{File, TryLockError};

    use rustix::fs::{FlockOperation, flock};
    use rustix::io::Errno;

    /// Runs a lock that waits, again if a signal interrupts the wait.
    fn waiting(file: &File, operation: FlockOperation) -> std::io::Result<()> {
        loop {
            match flock(file, operation) {
                Ok(()) => return Ok(()),
                Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(super) fn exclusive(file: &File) -> std::io::Result<()> {
        waiting(file, FlockOperation::LockExclusive)
    }

    pub(super) fn shared(file: &File) -> std::io::Result<()> {
        waiting(file, FlockOperation::LockShared)
    }

    pub(super) fn try_exclusive(file: &File) -> Result<(), TryLockError> {
        loop {
            match flock(file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(()),
                Err(Errno::INTR) => {}
                Err(Errno::WOULDBLOCK) => return Err(TryLockError::WouldBlock),
                Err(error) => return Err(TryLockError::Error(error.into())),
            }
        }
    }

    pub(super) fn release(file: &File) -> std::io::Result<()> {
        waiting(file, FlockOperation::Unlock)
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{File, TryLockError};

    pub(super) fn exclusive(file: &File) -> std::io::Result<()> {
        file.lock()
    }

    pub(super) fn shared(file: &File) -> std::io::Result<()> {
        file.lock_shared()
    }

    pub(super) fn try_exclusive(file: &File) -> Result<(), TryLockError> {
        file.try_lock()
    }

    pub(super) fn release(file: &File) -> std::io::Result<()> {
        file.unlock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("the lock file")
    }

    /// A lock on a file excludes a second handle on the same file, in this process as in another;
    /// one that waits is let in when the first lets go and not before; readers do not exclude each
    /// other; and dropping the holder frees the lock.
    #[test]
    fn a_lock_excludes_another_handle_on_the_same_file() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};

        let directory = std::env::temp_dir().join(format!("kr-flush-lock-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let path = directory.join("store.lock");
        let (first, second) = (opened(&path), opened(&path));

        try_exclusive(&first).expect("a lock nobody holds is taken");
        assert!(matches!(
            try_exclusive(&second),
            Err(TryLockError::WouldBlock)
        ));

        // The second writer says it is about to wait, and checks on getting in that the first had
        // announced its release: a lock that excluded nothing would let it in before.
        let released = Arc::new(AtomicBool::new(false));
        let (about_to_wait, hears) = mpsc::channel();
        let waiting = std::thread::spawn({
            let released = Arc::clone(&released);
            move || {
                about_to_wait.send(()).expect("the first is listening");
                exclusive(&second).expect("the second writer, in its turn");
                assert!(
                    released.load(Ordering::SeqCst),
                    "the second writer got in while the first held the lock"
                );
                second
            }
        });
        hears.recv().expect("the second writer is about to wait");
        released.store(true, Ordering::SeqCst);
        release(&first).expect("the first lets go");
        let second = waiting.join().expect("the second writer ran");
        assert!(matches!(
            try_exclusive(&first),
            Err(TryLockError::WouldBlock)
        ));

        release(&second).expect("the second lets go");
        shared(&first).expect("a first reader");
        shared(&second).expect("a second reader beside it");
        assert!(matches!(
            try_exclusive(&opened(&path)),
            Err(TryLockError::WouldBlock)
        ));
        release(&first).expect("the first reader lets go");
        release(&second).expect("the second reader lets go");

        // Dropping the holder frees the lock without a release.
        exclusive(&first).expect("the writer");
        drop(first);
        try_exclusive(&second).expect("the lock went with the handle");
        drop(second);
        std::fs::remove_dir_all(&directory).ok();
    }
}
