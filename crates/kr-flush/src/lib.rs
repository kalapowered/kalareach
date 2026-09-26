//! The directory flush every local store makes a name it changed durable with.
//!
//! A file's contents are flushed through the file itself. Its name is an entry in the directory that
//! holds it, so a creation, a replacement or a removal is on disk only once that directory is. Every
//! store on this host flushes its directories here, on every platform, so what a flush opens and
//! what it asks for is decided in one place.
//!
//! This crate depends on no other crate of this host, so every one of them can reach it, the
//! cryptography crate's directory store included.

use std::path::Path;

/// What kind of name a directory flush makes durable.
///
/// Unix flushes a directory the same way whatever changed in it. Windows flushes a directory only
/// through a handle that may change it, and the handle asks for the one right the change used: an
/// account can hold the right to add a directory where it may not add a file, as every account
/// does at the root of the system drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// The name of a file, created, replaced or removed.
    File,
    /// The name of a directory, created.
    Directory,
}

/// Flushes a directory to disk after a name inside it was created, replaced or removed, so the
/// change survives a crash.
///
/// A file's contents are flushed through the file itself. Its name is an entry in the directory,
/// and without this a crash can leave the name missing, or the old name in place, while the
/// contents are safe. On Windows the directory is opened with the backup semantics that let a
/// program open one at all, holding only the right `kind` names, and the flush is then asked of the
/// operating system through that handle, which refuses a handle that may not change the directory.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be opened or flushed.
pub fn flush_directory(directory: &Path, kind: NameKind) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let _ = kind;
        std::fs::File::open(directory)?.sync_all()
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY};

        flush_through(
            directory,
            match kind {
                NameKind::File => FILE_ADD_FILE,
                NameKind::Directory => FILE_ADD_SUBDIRECTORY,
            },
        )
    }
}

/// How long [`retry_while_held`] goes on trying a rename again while another program holds a file
/// it needs, counted on a monotonic clock from the first attempt.
///
/// On a Windows machine where Defender's real-time protection reads each new file, 111 of 113
/// refused replacements of a file that had just been given its name by a link were let through
/// within 1.4 seconds of the first refusal, and 2 were still refused a minute later; files given
/// their names by a rename were not seen held at all. This bound covers the first kind several
/// times over. No bound covers the second, which is why a new file is given its name by
/// [`publish_without_replacing`], not by a link.
pub const HELD_RENAME_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Runs `rename`, which puts a file or a directory in place under its name, and on Windows runs it
/// again while another program holds what it renames or what it replaces.
///
/// Windows refuses a rename with ERROR_SHARING_VIOLATION while another handle holds the file being
/// renamed without sharing its deletion, and with ERROR_ACCESS_DENIED while one holds the file it
/// replaces that way, or anything below a directory being renamed. A program that reads each file
/// as it is written, a scanner above all, holds a new file so for a moment. Those two refusals are
/// tried again after a pause that doubles from 2 ms up to 200 ms and never runs past the deadline,
/// until the rename succeeds, fails any other way, or [`HELD_RENAME_BOUND`] has passed since the
/// first attempt. No attempt starts once it has passed: the last refusal is returned unchanged, so
/// the caller reports it as it always did and nothing was renamed. An access-control list that denies the rename answers
/// ERROR_ACCESS_DENIED too, and waiting changes nothing about it: it is reported once the bound has
/// passed. The bound limits the waiting between attempts, not how long one attempt takes or when
/// the operating system next runs this thread.
///
/// Elsewhere `rename` runs once and its answer is returned: macOS and Linux rename a file however
/// another program holds it.
///
/// What the destination is may change while this waits. A caller that checks something about it
/// just before its rename checks it again inside `rename`, before every attempt.
///
/// # Errors
///
/// Returns `rename`'s error: the last refusal once the bound has passed, and any other error at
/// once.
pub fn retry_while_held(rename: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    retry_while_held_until(std::time::Instant::now() + HELD_RENAME_BOUND, rename)
}

/// [`retry_while_held`] until a deadline the caller took, for a caller whose rename is one part of
/// an operation whose waits all share one bound.
///
/// Such a caller takes its deadline as the operation starts, one [`HELD_RENAME_BOUND`] away, and
/// what it waits for before the rename, a lock among it, spends the same bound. The deadline bounds
/// the waiting and the attempts made again, not how long one attempt or the rest of the operation
/// takes. The first attempt is made whenever this is called, even once the deadline has passed,
/// because a rename nothing holds is made at once; no later attempt starts after the deadline.
///
/// # Errors
///
/// As [`retry_while_held`], with the deadline in place of the bound.
pub fn retry_while_held_until(
    deadline: std::time::Instant,
    mut rename: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        let held = |error: &std::io::Error| {
            error.raw_os_error().is_some_and(|code| {
                code == ERROR_SHARING_VIOLATION.cast_signed()
                    || code == ERROR_ACCESS_DENIED.cast_signed()
            })
        };
        let mut pause = Duration::from_millis(2);
        loop {
            let refused = match rename() {
                Err(error) if held(&error) => error,
                answer => return answer,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if !left.is_zero() {
                std::thread::sleep(pause.min(left));
            }
            // A pause cut short at the deadline ends past it: no attempt starts once it has passed.
            if Instant::now() >= deadline {
                return Err(refused);
            }
            pause = pause.saturating_mul(2).min(Duration::from_millis(200));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = deadline;
        rename()
    }
}

/// Gives the complete file `from` the name `to`, unless something is named `to` already: a first
/// publication, which never replaces what another writer published first.
///
/// On Windows this is a rename that does not replace. A link does the same everywhere, but on
/// Windows a file that has just been given a name by a link can be held by the system, where a
/// scanner such as Defender reads it, for a minute and more (see [`HELD_RENAME_BOUND`]), and a
/// rename over it is refused all that time. Elsewhere it is a link, and `from` keeps its name too
/// until the caller removes it; on Windows `from` no longer names anything once this succeeds.
/// Windows is given each name as the standard library's own file calls give it: a name that holds
/// a NUL is refused, and one past the old limit of 260 characters is made absolute and given the
/// prefix that lifts the limit.
///
/// # Errors
///
/// Returns an error of kind [`std::io::ErrorKind::AlreadyExists`] when something is named `to`,
/// of kind [`std::io::ErrorKind::InvalidInput`] when a name holds a NUL, and the operating
/// system's error when the name cannot be given otherwise.
pub fn publish_without_replacing(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        self::windows::move_without_replacing(from, to)
    }
    #[cfg(not(windows))]
    {
        std::fs::hard_link(from, to)
    }
}

/// Flushes one directory through a handle that holds `right` and nothing more.
///
/// `FlushFileBuffers`, which is what synchronising a handle calls, flushes only through a handle
/// that may write. The handle asks for the one right the change being flushed used and no more:
/// more could be refused, and it could collide with another program's handle on the same
/// directory.
#[cfg(windows)]
fn flush_through(directory: &Path, right: u32) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .access_mode(right)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)?
        .sync_all()
}

/// Flushes a directory this process holds open, after a name inside it was created, replaced or
/// removed, so the change survives a crash.
///
/// [`flush_directory`] for a store that reaches its directories through handles it holds and never
/// through their names again. The directory is opened a second time relative to the handle, so the
/// directory flushed is the one the handle holds even where its name has since been renamed or put
/// somewhere else. On Unix the second descriptor is opened for reading, because the handle may be a
/// reference to the directory rather than a file description, which is what Linux gives for an
/// `O_PATH` open and refuses to flush, and it is synchronised as [`flush_directory`] synchronises
/// the directory it opens by name: on macOS that asks the drive to write out what it holds, not only
/// the kernel. On Windows the second handle holds only the right `kind` names, as
/// [`flush_directory`]'s does, and the flush is asked of the operating system through it.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be opened again or flushed.
#[cfg(unix)]
pub fn flush_held_directory(
    directory: &impl std::os::fd::AsFd,
    kind: NameKind,
) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};

    let _ = kind;
    // `.` is the directory the handle holds, whatever name reaches it by now.
    let flushable = rustix::fs::openat(
        directory.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    std::fs::File::from(flushable).sync_all()
}

/// Flushes a directory this process holds open, after a name inside it was created, replaced or
/// removed, so the change survives a crash.
///
/// [`flush_directory`] for a store that reaches its directories through handles it holds and never
/// through their names again. The directory is opened a second time relative to the handle, so the
/// directory flushed is the one the handle holds even where its name has since been renamed or put
/// somewhere else. On Unix the second descriptor is opened for reading, because the handle may be a
/// reference to the directory rather than a file description, which is what Linux gives for an
/// `O_PATH` open and refuses to flush. On Windows the second handle holds only the right `kind`
/// names, as [`flush_directory`]'s does, and the flush is asked of the operating system through it.
///
/// # Errors
///
/// Returns the operating system's error when the directory cannot be opened again or flushed.
#[cfg(windows)]
pub fn flush_held_directory(
    directory: &impl std::os::windows::io::AsHandle,
    kind: NameKind,
) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY};

    flush_held_through(
        directory.as_handle(),
        match kind {
            NameKind::File => FILE_ADD_FILE,
            NameKind::Directory => FILE_ADD_SUBDIRECTORY,
        },
    )
}

/// Flushes the directory a handle holds through a second handle, opened from it, that holds
/// `right` and nothing more.
///
/// [`flush_through`] for a held directory: the flush is asked of the operating system through the
/// second handle, which it grants only where that handle may write.
#[cfg(windows)]
fn flush_held_through(
    directory: std::os::windows::io::BorrowedHandle<'_>,
    right: u32,
) -> std::io::Result<()> {
    self::windows::reopen_directory(directory, right)?.sync_all()
}

/// The two calls this crate makes that have no safe form: opening a held directory again, and a
/// rename that does not replace.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "opening a directory relative to a handle, and a rename that does not replace, are \
                  native calls, which have no safe interface"
    )]

    use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::NtOpenFile;
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, STATUS_SUCCESS, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// Opens the directory an open handle holds a second time, relative to that handle, holding
    /// `right`.
    ///
    /// The name opened is empty, which the kernel reads as the object the handle holds, so no name
    /// is resolved and the new handle is on that directory wherever its name has gone since. The
    /// operating system checks `right` against the directory's list as it does for an open by name,
    /// and asks for the same backup intent [`super::flush_directory`]'s own open carries. The
    /// Win32 call for a reopen is not used: it refuses a directory whatever right it is asked for.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the directory cannot be opened with that right.
    pub(super) fn reopen_directory(
        directory: BorrowedHandle<'_>,
        right: u32,
    ) -> std::io::Result<std::fs::File> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_SYNCHRONOUS_IO_NONALERT,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, SYNCHRONIZE};

        // A name of no characters. The buffer is live and never read, because the length is zero.
        let mut nothing = [0_u16; 1];
        let object_name = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: nothing.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
            RootDirectory: directory.as_raw_handle(),
            ObjectName: &raw const object_name,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` and `status_block` are live out parameters; `attributes` points at
        // `object_name`, whose buffer is `nothing`, and all three are locals that live to the end
        // of this function, past the call. `directory` is a handle borrowed for this call and used
        // as the object the empty name resolves to. The options open an existing directory only,
        // so the call creates nothing.
        let status = unsafe {
            NtOpenFile(
                &raw mut handle,
                right | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                &raw const attributes,
                &raw mut status_block,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
            )
        };
        if status == STATUS_SUCCESS {
            // SAFETY: the call above filled `handle` with a handle this owns and closes once.
            return Ok(unsafe { std::fs::File::from_raw_handle(handle.cast()) });
        }
        // SAFETY: the status is the one the call returned; this only maps it to a Win32 code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(std::io::Error::from_raw_os_error(code.cast_signed()))
    }

    /// Renames `from` to `to` unless something is named `to`: `MoveFileExW` without the flag that
    /// lets it replace, which answers ERROR_ALREADY_EXISTS then. The standard library's rename
    /// always replaces.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the rename is refused.
    pub(super) fn move_without_replacing(
        from: &std::path::Path,
        to: &std::path::Path,
    ) -> std::io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

        let (from, to) = (native_name(from)?, native_name(to)?);
        // SAFETY: both names are NUL-terminated wide strings with no NUL before their end, and they
        // live past the call, which reads them and keeps neither. With no flags the call moves a
        // name on one volume and never replaces one.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// `path` as a native call reads a name: wide and NUL-terminated, the way the standard library
    /// gives a name to its own file calls.
    ///
    /// A name that holds a NUL is refused, because the call would read it only as far as the NUL,
    /// which can name another file. A name already verbatim (`\\?\` or `\??\`) goes as it is.
    /// Any other name is made absolute; one that reaches the old limit is then given the verbatim
    /// prefix that lifts it: `C:\` becomes `\\?\C:\`, `\\server\share` becomes
    /// `\\?\UNC\server\share`, and a device name `\\.\` becomes `\\?\`.
    ///
    /// # Errors
    ///
    /// Returns an error of kind [`std::io::ErrorKind::InvalidInput`] for a name that holds a NUL
    /// or is empty.
    pub(super) fn native_name(path: &std::path::Path) -> std::io::Result<Vec<u16>> {
        use std::os::windows::ffi::OsStrExt as _;

        /// The length from which the standard library prefixes a name: some calls stop at 248
        /// characters, short of the 260 of the old limit.
        const LEGACY_MAX_PATH: usize = 248;
        /// `\`, `?`, `.`, `:`, and the letters of `UNC`, as UTF-16.
        const SEP: u16 = 0x5C;
        const QUERY: u16 = 0x3F;
        const DOT: u16 = 0x2E;
        const COLON: u16 = 0x3A;
        const UNC: [u16; 3] = [0x55, 0x4E, 0x43];

        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} holds a NUL", path.display()),
            ));
        }
        let verbatim = |name: &[u16]| {
            name.starts_with(&[SEP, SEP, QUERY, SEP]) || name.starts_with(&[SEP, QUERY, QUERY, SEP])
        };
        let mut native = if verbatim(&wide) {
            wide
        } else {
            let absolute: Vec<u16> = std::path::absolute(path)?
                .as_os_str()
                .encode_wide()
                .collect();
            if absolute.len() + 1 < LEGACY_MAX_PATH || verbatim(&absolute) {
                absolute
            } else {
                let prefix = [SEP, SEP, QUERY, SEP];
                match absolute.as_slice() {
                    [_, COLON, SEP, ..] => prefix.iter().chain(&absolute).copied().collect(),
                    [SEP, SEP, DOT, SEP, rest @ ..] => prefix.iter().chain(rest).copied().collect(),
                    [SEP, SEP, rest @ ..] => prefix
                        .iter()
                        .chain(&UNC)
                        .chain(&[SEP])
                        .chain(rest)
                        .copied()
                        .collect(),
                    _ => absolute,
                }
            }
        };
        native.push(0);
        Ok(native)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A directory of this test's own under the system's temporary directory, removed when the
    /// test ends however it ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};

            static NEXT: AtomicU32 = AtomicU32::new(0);
            let unique = format!(
                "kr-flush-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir(&path).expect("a directory of this test's own");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A directory is flushed through a handle of its own for either kind of name. A flush that
    /// did nothing would pass the first two calls; one that opens the directory it flushes cannot
    /// open one that is not there.
    #[cfg(windows)]
    #[test]
    fn a_directory_is_flushed_through_a_handle_of_its_own() {
        let root = Scratch::new("own");
        flush_directory(&root.0, NameKind::File)
            .expect("a directory this account adds files to is flushed");
        flush_directory(&root.0, NameKind::Directory).expect("and one it adds directories to");
        let missing = root.0.join("missing");
        for kind in [NameKind::File, NameKind::Directory] {
            assert_eq!(
                flush_directory(&missing, kind)
                    .expect_err("nothing to flush")
                    .kind(),
                std::io::ErrorKind::NotFound,
                "{kind:?}"
            );
        }
    }

    /// The flush is asked of the operating system, which flushes only through a handle that may
    /// write and says so when it is asked through one that may not.
    #[cfg(windows)]
    #[test]
    fn the_flush_itself_is_asked_of_the_operating_system() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        };

        // A directory opened with nothing more than the right to read its attributes opens, as the
        // first reading shows, so what refuses in the second is the flush: a helper that opened the
        // directory and never asked for the flush would return success instead.
        let root = Scratch::new("asked");
        std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root.0)
            .expect("the directory opens with the right to read its attributes");
        assert_eq!(
            flush_through(&root.0, FILE_READ_ATTRIBUTES)
                .expect_err("a flush through a handle that may not write")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        flush_through(&root.0, FILE_ADD_FILE)
            .expect("and through one that may add a file, the flush is made");
    }

    /// A directory held open is flushed through a descriptor opened from the one held, not through
    /// its name, and a held reference the kernel refuses to flush is flushed that way too.
    #[cfg(unix)]
    #[test]
    fn a_held_directory_is_flushed_through_a_descriptor_opened_from_it() {
        let root = Scratch::new("held");
        let named = root.0.join("held");
        std::fs::create_dir(&named).expect("a directory to hold");
        let held = std::fs::File::open(&named).expect("the directory is held open");
        flush_held_directory(&held, NameKind::File).expect("the held directory is flushed");
        let moved = root.0.join("moved");
        std::fs::rename(&named, &moved).expect("the held directory is renamed");
        flush_held_directory(&held, NameKind::File)
            .expect("the directory the handle holds is flushed wherever its name went");
        // A reference to the directory rather than a file description, which Linux refuses to
        // flush directly.
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags};

            let reference = rustix::fs::open(
                &moved,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("a reference to the directory");
            assert_eq!(
                rustix::fs::fsync(&reference).expect_err("a reference is not flushed directly"),
                rustix::io::Errno::BADF
            );
            flush_held_directory(&reference, NameKind::File)
                .expect("the directory it refers to is flushed");
        }
        drop(held);
    }

    /// A directory held open is flushed through a second handle opened from the one held, not
    /// through its name: after a rename its old name reaches nothing and the flush still goes
    /// through. A handle that shares no writing stops that second open with a sharing violation,
    /// where a flush that did nothing would succeed and one made through the held handle itself
    /// would be refused for want of the right.
    #[cfg(windows)]
    #[test]
    fn a_held_directory_is_flushed_through_a_second_handle_opened_from_it() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
        };

        let root = Scratch::new("held");
        let named = root.0.join("held");
        std::fs::create_dir(&named).expect("a directory to hold");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&named)
            .expect("the directory is held open");
        flush_held_directory(&held, NameKind::File)
            .expect("a directory this account adds files to is flushed");
        flush_held_directory(&held, NameKind::Directory).expect("and one it adds directories to");

        let moved = root.0.join("moved");
        std::fs::rename(&named, &moved).expect("the held directory is renamed");
        assert_eq!(
            flush_directory(&named, NameKind::File)
                .expect_err("its old name reaches nothing")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        flush_held_directory(&held, NameKind::File)
            .expect("the directory the handle holds is flushed wherever its name went");

        let unshared = std::fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&moved)
            .expect("a handle that shares no writing");
        for kind in [NameKind::File, NameKind::Directory] {
            let refused = flush_held_directory(&held, kind)
                .expect_err("the second handle may add to the directory, which that one forbids");
            assert_eq!(
                refused.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION.cast_signed()),
                "{kind:?}: {refused}"
            );
        }
        drop(unshared);
        flush_held_directory(&held, NameKind::File).expect("and with it gone, the flush is made");
        drop(held);
    }

    /// A first publication gives the file its name, and one to a name that is taken answers that
    /// it exists and leaves both files as they were.
    #[test]
    fn a_publication_never_replaces_a_name_that_is_taken() {
        let root = Scratch::new("publication");
        let (first, second, name) = (
            root.0.join("first"),
            root.0.join("second"),
            root.0.join("name"),
        );
        std::fs::write(&first, b"first").expect("the first file");
        std::fs::write(&second, b"second").expect("the second file");
        publish_without_replacing(&first, &name).expect("the name is free");
        assert_eq!(std::fs::read(&name).expect("readable"), b"first");
        // On Windows the name moved, since no link was made; elsewhere the file keeps both names
        // until the caller removes one.
        assert_eq!(first.exists(), !cfg!(windows), "{}", first.display());
        let taken = publish_without_replacing(&second, &name).expect_err("the name is taken");
        assert_eq!(taken.kind(), std::io::ErrorKind::AlreadyExists, "{taken}");
        assert_eq!(std::fs::read(&name).expect("readable"), b"first");
        assert_eq!(std::fs::read(&second).expect("readable"), b"second");
    }

    /// A name that holds a NUL is refused before anything is given a name, on every platform: a
    /// native call reads a name only as far as its first NUL, which can name another file.
    #[test]
    fn a_name_holding_a_nul_is_refused_and_nothing_moves() {
        let root = Scratch::new("nul");
        let (first, name) = (root.0.join("first"), root.0.join("name"));
        std::fs::write(&first, b"first").expect("the file");
        let with_nul = |path: &Path| {
            let mut held = path.as_os_str().to_owned();
            held.push("\0suffix");
            PathBuf::from(held)
        };
        #[cfg_attr(not(windows), expect(unused_mut, reason = "only Windows adds cases"))]
        let mut cases = vec![
            (with_nul(&first), name.clone()),
            (first.clone(), with_nul(&name)),
        ];
        // A verbatim name goes to the native call as it is, without the standard library's
        // conversion, which refuses a NUL on its own.
        #[cfg(windows)]
        {
            let verbatim = |path: &Path| PathBuf::from(format!(r"\\?\{}", path.display()));
            cases.push((with_nul(&verbatim(&first)), verbatim(&name)));
            cases.push((verbatim(&first), with_nul(&verbatim(&name))));
        }
        for (from, to) in cases {
            let refused = publish_without_replacing(&from, &to).expect_err("a NUL in a name");
            assert_eq!(
                refused.kind(),
                std::io::ErrorKind::InvalidInput,
                "{refused}"
            );
            assert_eq!(std::fs::read(&first).expect("readable"), b"first");
            assert!(!name.exists(), "nothing was given the name");
        }
    }

    /// On Windows a name reaches the native call the way the standard library gives names to its
    /// own: a verbatim name as it is, any other made absolute, and from 248 characters with its
    /// NUL given the verbatim prefix that lifts the old limit, for a drive, a share and a device.
    #[cfg(windows)]
    #[test]
    fn a_name_is_given_to_windows_as_the_standard_library_gives_it() {
        let native = |name: &str| {
            let wide = self::windows::native_name(Path::new(name)).expect("a name");
            assert_eq!(wide.last(), Some(&0), "{name}");
            String::from_utf16(&wide[..wide.len() - 1]).expect("the name")
        };
        let long = "a".repeat(300);
        assert_eq!(native(r"C:\short\name"), r"C:\short\name");
        assert_eq!(native(&format!(r"C:\{long}")), format!(r"\\?\C:\{long}"));
        assert_eq!(
            native(&format!(r"\\server\share\{long}")),
            format!(r"\\?\UNC\server\share\{long}")
        );
        assert_eq!(
            native(&format!(r"\\.\C:\{long}")),
            format!(r"\\?\C:\{long}")
        );
        for verbatim in [r"\\?\C:\x", r"\??\C:\x"] {
            assert_eq!(native(verbatim), verbatim);
        }
        // The prefix begins where the name and its NUL reach 248 characters.
        let under = format!(r"C:\{}", "a".repeat(243));
        assert_eq!(under.len(), 246);
        assert_eq!(native(&under), under);
        let at = format!(r"C:\{}", "a".repeat(244));
        assert_eq!(native(&at), format!(r"\\?\{at}"));
    }

    /// On Windows a file is given its name where the names run past the old limit of 260
    /// characters, as the standard library's own file calls manage, and where they are verbatim.
    #[cfg(windows)]
    #[test]
    fn a_name_past_the_old_path_limit_is_given() {
        let root = Scratch::new("long");
        let mut directory = root.0.clone();
        while directory.as_os_str().len() < 300 {
            directory.push("a-directory-of-a-long-name");
        }
        std::fs::create_dir_all(&directory).expect("a deep directory");
        let (first, name) = (directory.join("first"), directory.join("name"));
        std::fs::write(&first, b"first").expect("the file");
        publish_without_replacing(&first, &name).expect("given past the old limit");
        assert_eq!(std::fs::read(&name).expect("readable"), b"first");
        assert!(!first.exists(), "moved");

        let verbatim = |path: &Path| PathBuf::from(format!(r"\\?\{}", path.display()));
        let (second, other) = (root.0.join("second"), root.0.join("other"));
        std::fs::write(&second, b"second").expect("the file");
        publish_without_replacing(&verbatim(&second), &verbatim(&other))
            .expect("given by verbatim names");
        assert_eq!(std::fs::read(&other).expect("readable"), b"second");
    }

    /// [`retry_while_held_until`] with a deadline one `bound` from now, as [`retry_while_held`]
    /// takes one [`HELD_RENAME_BOUND`] from now. These tests shorten it.
    fn retry_within(
        bound: std::time::Duration,
        rename: impl FnMut() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        retry_while_held_until(std::time::Instant::now() + bound, rename)
    }

    /// A deadline that has already passed still has the rename made once, which succeeds where
    /// nothing holds what it needs, and is not made again after a refusal.
    #[test]
    fn a_rename_is_made_once_after_its_deadline() {
        let passed = std::time::Instant::now();
        let mut attempts = 0;
        retry_while_held_until(passed, || {
            attempts += 1;
            Ok(())
        })
        .expect("made at once");
        assert_eq!(attempts, 1);

        let mut attempts = 0;
        let refused = retry_while_held_until(passed, || {
            attempts += 1;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
        assert_eq!(
            refused.expect_err("refused").kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(attempts, 1);
    }

    /// On Windows a hold met after the deadline is answered with its refusal at once: nothing is
    /// tried again.
    #[cfg(windows)]
    #[test]
    fn a_hold_met_after_the_deadline_is_not_tried_again() {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let passed = std::time::Instant::now();
        let mut attempts = 0;
        let refused = retry_while_held_until(passed, || {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(
                ERROR_SHARING_VIOLATION.cast_signed(),
            ))
        });
        assert_eq!(
            refused.expect_err("refused").raw_os_error(),
            Some(ERROR_SHARING_VIOLATION.cast_signed())
        );
        assert_eq!(attempts, 1);
    }

    /// A rename that fails any other way than a hold is answered at once, after one attempt, on
    /// every platform.
    #[test]
    fn a_rename_that_fails_another_way_is_tried_once() {
        let mut attempts = 0;
        let answer = retry_within(std::time::Duration::from_secs(5), || {
            attempts += 1;
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        });
        assert_eq!(
            answer.expect_err("refused").kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(attempts, 1);
    }

    /// Elsewhere than Windows a rename is tried once, whatever it answers.
    #[cfg(not(windows))]
    #[test]
    fn elsewhere_a_refused_rename_is_tried_once() {
        /// Permission denied, as macOS and Linux number it.
        const EACCES: i32 = 13;

        let mut attempts = 0;
        let answer = retry_within(std::time::Duration::from_secs(5), || {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(EACCES))
        });
        assert_eq!(answer.expect_err("refused").raw_os_error(), Some(EACCES));
        assert_eq!(attempts, 1);
    }

    /// A hold that gives way to another error answers with that error at once.
    #[cfg(windows)]
    #[test]
    fn a_hold_followed_by_another_error_answers_with_the_other_error() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

        let mut attempts = 0;
        let answer = retry_within(std::time::Duration::from_secs(5), || {
            attempts += 1;
            if attempts == 1 {
                Err(std::io::Error::from_raw_os_error(
                    ERROR_ACCESS_DENIED.cast_signed(),
                ))
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            }
        });
        assert_eq!(
            answer.expect_err("refused").kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(attempts, 2);
    }

    /// A hold that outlasts the bound is answered with the last refusal, unchanged, once the bound
    /// has passed and not long after.
    #[cfg(windows)]
    #[test]
    fn a_hold_that_outlasts_the_bound_answers_with_its_refusal_unchanged() {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let bound = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let mut attempts = 0;
        let answer = retry_within(bound, || {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(
                ERROR_SHARING_VIOLATION.cast_signed(),
            ))
        });
        let took = started.elapsed();
        assert_eq!(
            answer.expect_err("refused").raw_os_error(),
            Some(ERROR_SHARING_VIOLATION.cast_signed())
        );
        assert!(attempts > 1, "tried again: {attempts}");
        assert!(took >= bound, "{took:?}");
        assert!(took < bound + std::time::Duration::from_secs(2), "{took:?}");
    }

    /// No attempt starts once the bound has passed, although the pause cut short at the bound has
    /// ended past it and an attempt then would succeed: the refusal made within the bound is the
    /// answer, and nothing is renamed after the deadline.
    #[cfg(windows)]
    #[test]
    fn no_attempt_starts_once_the_bound_has_passed() {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let bound = std::time::Duration::from_millis(50);
        let mut attempts = 0;
        let answer = retry_within(bound, || {
            attempts += 1;
            if attempts > 1 {
                return Ok(());
            }
            // The first attempt ends 1.5 ms before the bound, so the pause after it, 2 ms at first,
            // is cut short at the bound.
            let first = std::time::Instant::now();
            while first.elapsed() < bound - std::time::Duration::from_micros(1500) {
                std::hint::spin_loop();
            }
            Err(std::io::Error::from_raw_os_error(
                ERROR_SHARING_VIOLATION.cast_signed(),
            ))
        });
        assert_eq!(attempts, 1, "an attempt started after the bound");
        assert_eq!(
            answer.expect_err("refused within the bound").raw_os_error(),
            Some(ERROR_SHARING_VIOLATION.cast_signed())
        );
    }

    /// Holds `file` with a handle that shares reading and writing but not its deletion, as a
    /// program that reads each file as it is written does for a moment.
    #[cfg(windows)]
    fn hold_without_shared_deletion(file: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(file)
            .expect("the file is held")
    }

    /// A file named `from` and one named `to`, each holding its own name, in a directory of this
    /// test's own.
    #[cfg(windows)]
    fn two_files(name: &str) -> (Scratch, PathBuf, PathBuf) {
        let root = Scratch::new(name);
        let (from, to) = (root.0.join("from"), root.0.join("to"));
        std::fs::write(&from, b"from").expect("the new file");
        std::fs::write(&to, b"to").expect("the file it replaces");
        (root, from, to)
    }

    /// A rename over a file another program holds without sharing its deletion is refused as
    /// access denied, and is made once that program lets go, within the bound. So is a rename of a
    /// file held that way, which is refused as a sharing violation.
    #[cfg(windows)]
    #[test]
    fn a_rename_is_made_once_the_file_it_needs_is_let_go() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        for (held, refused) in [
            ("to", ERROR_ACCESS_DENIED),
            ("from", ERROR_SHARING_VIOLATION),
        ] {
            let (_root, from, to) = two_files(&format!("held-{held}"));
            let holding = hold_without_shared_deletion(if held == "to" { &to } else { &from });
            assert_eq!(
                std::fs::rename(&from, &to)
                    .expect_err("refused while held")
                    .raw_os_error(),
                Some(refused.cast_signed()),
                "{held}"
            );
            let started = std::time::Instant::now();
            let letting_go = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                drop(holding);
            });
            retry_within(std::time::Duration::from_secs(5), || {
                std::fs::rename(&from, &to)
            })
            .unwrap_or_else(|error| panic!("{held}: renamed once let go: {error}"));
            letting_go.join().expect("let go");
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(250),
                "{held}: not renamed before it was let go"
            );
            assert_eq!(std::fs::read(&to).expect("readable"), b"from", "{held}");
        }
    }

    /// A file held past the bound is not replaced: the rename is refused with the refusal Windows
    /// gave, the new file is where it was and the old one holds what it held.
    #[cfg(windows)]
    #[test]
    fn a_file_held_past_the_bound_is_not_replaced() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

        let (_root, from, to) = two_files("held-past");
        let holding = hold_without_shared_deletion(&to);
        let bound = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let refused = retry_within(bound, || std::fs::rename(&from, &to))
            .expect_err("refused for as long as it is held");
        let took = started.elapsed();
        drop(holding);
        assert_eq!(
            refused.raw_os_error(),
            Some(ERROR_ACCESS_DENIED.cast_signed())
        );
        assert!(took >= bound, "{took:?}");
        assert_eq!(std::fs::read(&from).expect("still there"), b"from");
        assert_eq!(std::fs::read(&to).expect("readable"), b"to");
    }

    /// The flush of a held directory is asked of the operating system through the second handle,
    /// which refuses a handle that may not write and flushes through one that may add a file.
    #[cfg(windows)]
    #[test]
    fn the_held_flush_is_asked_of_the_operating_system() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        };

        // The directory opens again with nothing more than the right to read its attributes, as
        // the first call shows, so what refuses in the second is the flush: a flush that opened
        // the second handle and never asked for the flush would return success instead.
        let root = Scratch::new("held-asked");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root.0)
            .expect("the directory is held open");
        super::windows::reopen_directory(held.as_handle(), FILE_READ_ATTRIBUTES)
            .expect("the directory opens again with the right to read its attributes");
        assert_eq!(
            flush_held_through(held.as_handle(), FILE_READ_ATTRIBUTES)
                .expect_err("a flush through a handle that may not write")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        flush_held_through(held.as_handle(), FILE_ADD_FILE)
            .expect("and through one that may add a file, the flush is made");
        drop(held);
    }
}
