//! Opening a store whose previous holder is still letting go of it.
//!
//! A store in write-ahead mode keeps an index in a file of its own, and the first process to open
//! the store after every other holder has gone resets that file. On Windows the file cannot be
//! truncated while any process still has it mapped, and a process that is ending releases its
//! locks on the index before the system removes its mapping. The interval is the end of the
//! previous holder: a worker whose session has just closed, a daemon that was killed and whose
//! successor took the environment the moment its lock was free, or any process that was ended.
//!
//! SQLite 3.54 and later do not refuse an open in that interval: where they cannot truncate the
//! index they clear its first bytes instead, which has the same effect, and go on. The store opens
//! at once and holds what its previous holder committed. The refusal an earlier SQLite gave there,
//! `SQLITE_IOERR_TRUNCATE`, never kept a second process out of a store that a live process held:
//! the index is reset only by a process that finds nobody else holding the store open.
//!
//! The store still answers `SQLITE_IOERR_TRUNCATE`, which reads as "disk I/O error", when it cannot
//! extend the index for want of room. The openers ask again for as long as the store gives that
//! answer, and give it up once it has lasted [`PATIENCE`], which is a disk that has no room to
//! give.

use std::time::{Duration, Instant};

use rusqlite::Connection;

/// Opens the store at `path`, with `flags` or the ones that create it, and reads its first page.
///
/// The first read is what maps the store's write-ahead index, so it is where a store that cannot
/// make that index ready refuses, and the whole open is asked again for as long as it does
/// ([`while_the_index_cannot_be_made_ready`]). Opening the file alone would not meet the refusal,
/// and the caller's first query would.
///
/// # Errors
///
/// Returns the store's refusal: the last one when it still says its index cannot be made ready
/// after [`PATIENCE`], and any other the first time it is given.
pub fn open_connection(
    path: &std::path::Path,
    flags: Option<rusqlite::OpenFlags>,
) -> rusqlite::Result<Connection> {
    while_the_index_cannot_be_made_ready(|| {
        let connection = match flags {
            Some(flags) => Connection::open_with_flags(path, flags)?,
            None => Connection::open(path)?,
        };
        connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        Ok(connection)
    })
}

/// Whether the store at `path` has a row for `query`, read through a connection of its own.
///
/// For a caller that asks whether a record exists in a store another part of the process holds
/// open and must not wait for: the connection is read-only and takes no lock of the holder's. A
/// store in write-ahead mode answers from what is committed while a writer works, and one that is
/// not waits for a commit at most [`PATIENCE`]. A store that is not there holds no row, and every
/// other refusal is returned, a path that cannot be looked for among them: a store that cannot be
/// read is not one that holds nothing.
///
/// # Errors
///
/// Returns the store's refusal when it cannot be opened or asked.
pub fn holds_a_row(
    path: &std::path::Path,
    query: &str,
    parameters: impl rusqlite::Params,
) -> rusqlite::Result<bool> {
    // A path that cannot be looked for is not a store that is not there.
    if !path.try_exists().map_err(|error| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(error.to_string()),
        )
    })? {
        return Ok(false);
    }
    let connection = open_connection(
        path,
        Some(
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ),
    )?;
    connection.busy_timeout(PATIENCE)?;
    match connection.query_row(query, parameters, |_| Ok(())) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(error) => Err(error),
    }
}

/// How long an open that is told its store's index cannot be made ready asks again before it
/// reports the refusal.
///
/// It is the same bound the stores give a lock another connection holds.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// How long an open waits between two asks.
const BETWEEN_ASKS: Duration = Duration::from_millis(5);

/// Says what one refusal of a store was, for a person and for the record of a fault.
///
/// The store's message names only the family of a failure: "disk I/O error" is what it says for a
/// truncation the system refused as much as for a read that failed. The result code it answered
/// with tells them apart, so it is part of what is said.
#[must_use]
pub fn describe(error: &rusqlite::Error) -> String {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => {
            format!("{error} (result code {})", failure.extended_code)
        }
        other => other.to_string(),
    }
}

/// Whether the store's answer is the one it gives an open whose index it could not make ready:
/// `SQLITE_IOERR_TRUNCATE`, on Windows.
#[must_use]
pub fn is_an_index_that_cannot_be_made_ready(error: &rusqlite::Error) -> bool {
    cfg!(windows)
        && matches!(
            error,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.extended_code == rusqlite::ffi::SQLITE_IOERR_TRUNCATE
        )
}

/// Runs `attempt`, again for as long as the store says its index cannot be made ready, and returns
/// the first answer that says anything else.
///
/// # Errors
///
/// Returns the store's last refusal when it still says so after [`PATIENCE`], and every other
/// refusal the first time it is given.
pub fn while_the_index_cannot_be_made_ready<T>(
    mut attempt: impl FnMut() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        match attempt() {
            Err(error)
                if is_an_index_that_cannot_be_made_ready(&error) && Instant::now() < deadline =>
            {
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
    /// What a test runs the next time an open on this thread is told its store's index cannot be
    /// made ready and asks again.
    static ON_THE_NEXT_WAIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` the next time an open on this thread is told its store's index cannot be made
/// ready, once, before the open asks again, for this host's own tests.
///
/// It is how a test acts at the moment the open asks again, rather than after a time it chose. It
/// belongs to the calling thread, because an open asks again on the thread that opened, so a test
/// running beside another one cannot be answered with the other's refusal. It is compiled away in
/// every shipped build.
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

/// Shows, for a store's own test, that a store whose previous holder is still letting go of its
/// index opens, and holds what that holder committed.
///
/// `open` opens the store at `database` and lets go of it again. It is called once to make the
/// store, then with the store's index held mapped, the way a process that is ending holds it. The
/// store must read as it did, its objects and the version it records, while the index is held, and
/// `open` must succeed then and again once the hold is let go of. SQLite 3.54 and later clear the
/// first bytes of an index they cannot truncate and go on, so the open does not wait; a store that
/// reports a refusal there fails here.
///
/// # Panics
///
/// Panics when the store cannot be read, or reads differently, while its index is held, and when
/// `open` fails while it is held or after it has been let go of.
#[cfg(all(windows, feature = "testing"))]
pub fn assert_an_open_waits_for_the_previous_holder<E: std::fmt::Debug>(
    database: &std::path::Path,
    open: impl Fn() -> Result<(), E>,
) {
    open().expect("the store opens when nothing holds it");
    let committed = what_the_store_holds(database).expect("the store reads when nothing holds it");
    let mut index = database.as_os_str().to_owned();
    index.push("-shm");
    let held = held_index::HeldIndex::on(std::path::Path::new(&index));
    let read = what_the_store_holds(database);
    assert!(
        read.as_ref().is_ok_and(|read| *read == committed),
        "the store reads what its previous holder committed while the index is held: {read:?}"
    );
    open().expect("the open goes on while the previous holder's mapping of the index stands");
    drop(held);
    open().expect("the open goes on once the previous holder has let go");
    let read = what_the_store_holds(database);
    assert!(
        read.as_ref().is_ok_and(|read| *read == committed),
        "the store reads what its previous holder committed after the open: {read:?}"
    );
}

/// What the store at `database` holds, read through a connection of its own: the version it
/// records and every object of its schema, one line each with the statement that made it.
#[cfg(all(windows, feature = "testing"))]
fn what_the_store_holds(database: &std::path::Path) -> rusqlite::Result<(i64, Vec<String>)> {
    let connection =
        Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    let mut statement =
        connection.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")?;
    let objects = statement
        .query_map([], |row| {
            Ok(format!(
                "{} {}: {}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?.unwrap_or_default()
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((version, objects))
}

/// A mapping of a store's index file, held the way a process that is ending holds it: mapped, with
/// no lock on the index, for this host's own tests.
///
/// The system removes a process's mappings after it has released its locks, so for that interval
/// the index is mapped and nobody has it locked. The next process to open the store finds nobody
/// holding it, cannot truncate the index while it is mapped, and clears its first bytes instead. A
/// test holds one to stand a store in that interval on purpose. It compiles to nothing without
/// the `testing` feature, and no shipped build enables it.
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
    /// The three are kept as integers, which are the system's own values for them and let this be
    /// moved between threads.
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
