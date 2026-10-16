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

/// A mapping of a store's index file, held the way a process that is ending holds it: mapped, with
/// no lock on the index, for this host's own tests.
///
/// The system removes a process's mappings after it has released its locks, so for that interval
/// an index nobody has locked is one nobody may reset. A test holds one to stand a store in that
/// interval on purpose. It compiles to nothing without the `testing` feature, and no shipped build
/// enables it.
#[cfg(all(windows, feature = "testing"))]
pub mod held_index {
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
    };
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
        MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
    };

    /// The size of one region of a write-ahead index.
    const REGION: u32 = 32 * 1024;

    /// A file, a mapping of it and a view of the mapping, held until this is dropped.
    ///
    /// The three are kept as integers, which are the system's own values for them and can be
    /// moved into the hook a test leaves for the store's next wait.
    pub struct HeldIndex {
        file: usize,
        mapping: usize,
        view: usize,
    }

    impl HeldIndex {
        /// Maps the index file at `index`, making it if it is not there.
        #[expect(unsafe_code, reason = "mapping a file has no safe form")]
        pub fn on(index: &Path) -> Self {
            let name: Vec<u16> = index
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: `name` is a terminated wide string that outlives the call, and the other
            // arguments are plain values or null.
            let file = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    0xC000_0000,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(file, INVALID_HANDLE_VALUE, "the index file opens");
            // SAFETY: `file` is the open handle above; a mapping with a size extends the file to
            // it.
            let mapping = unsafe {
                CreateFileMappingW(
                    file,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    REGION,
                    std::ptr::null(),
                )
            };
            assert!(!mapping.is_null(), "the index file maps");
            // SAFETY: `mapping` is the mapping above, and the view is of the region it maps.
            let view = unsafe {
                MapViewOfFile(
                    mapping,
                    FILE_MAP_READ | FILE_MAP_WRITE,
                    0,
                    0,
                    REGION as usize,
                )
            };
            assert!(!view.Value.is_null(), "the mapping has a view");
            Self {
                file: file as usize,
                mapping: mapping as usize,
                view: view.Value as usize,
            }
        }
    }

    impl Drop for HeldIndex {
        #[expect(unsafe_code, reason = "releasing a mapping has no safe form")]
        fn drop(&mut self) {
            // SAFETY: each value is the one `on` made, released once and in the order the system
            // needs: the view, then the mapping, then the file.
            unsafe {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view as *mut std::ffi::c_void,
                });
                CloseHandle(self.mapping as *mut std::ffi::c_void);
                CloseHandle(self.file as *mut std::ffi::c_void);
            }
        }
    }
}
