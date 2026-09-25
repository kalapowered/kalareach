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

/// The one call this crate makes that has no safe form: opening a held directory again.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "opening a directory relative to a handle is a native call, which has no safe \
                  interface"
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
