//! The host's one reading of UTC in a boot, shared by every host process of an environment.
//!
//! A wall clock can be stepped forward and then back. A host that decides a time bound in more than
//! one process has to decide it from one reading, or a step back lets one process act on a copy of
//! authority another process has already found run out. So the environment keeps one word: the
//! highest UTC reading, in milliseconds, that any of its processes has published in this boot. Every
//! process maps the same file and uses the word through an atomic on the mapping, so a reading one
//! process publishes is the floor every other process decides from, at once and without a lock.
//!
//! # The word and its two companions
//!
//! Publishing a reading is one `fetch_max`, and the reading a process then decides from is the word
//! as that raise left it: the larger of the word's previous value and the sample ([`SharedFloor::raise`]).
//! Neither step waits, so a check inside a poll may take both.
//!
//! Two more words sit beside it. `owed` is the highest floor a lapse decision stood on that is owed
//! its record, and `recorded` is the highest floor the control daemon has written down. A process
//! that finds a copy's deadline passed answers it as an expiry only once `recorded` covers the
//! deadline, and otherwise raises `owed` for the daemon to write: an answer never rests on a
//! reading that a restart, a reboot or a lost file could take away.
//!
//! # The file
//!
//! One file of [`FLOOR_FILE_LEN`] bytes in the environment's owner-only runtime directory: a
//! header naming the format, the environment, the boot and the floor's own identity, then the
//! three words at aligned offsets. A process checks the file before it maps it, as a reader checks
//! a descriptor: not a symbolic link, the user's own file, not readable or writable by anybody
//! else, exactly the right length, and a header naming this environment and this boot. A file that
//! fails a check is no floor, and nothing is mapped from it.
//!
//! Only the control daemon creates one, under a fresh identity, and the whole file is written under
//! a temporary name before it is renamed into place.
//!
//! # A file that lost its name
//!
//! A process keeps the file open for as long as it maps it and remembers which file it opened.
//! Whoever decides from the word loads it and then confirms that the pathname still names that file
//! ([`SharedFloor::named`]): a removed name, a file renamed over it, a renamed directory and a hard
//! link left behind all fail the confirmation. A floor whose name has gone is no longer the host's
//! floor, because a later daemon creates a new one beside it; a process that finds its own floor
//! nameless decides nothing from it. On Windows the file is also opened without delete sharing, so
//! its name cannot be removed while anything maps it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::ids::{BootEpoch, EnvironmentId};

use crate::error::{IpcError, Result};

/// The length of the floor's file: one page of 4 KiB, whatever page size the machine maps it in.
pub const FLOOR_FILE_LEN: usize = 4096;

/// The file's first eight bytes: the format, and the version of it.
const FORMAT: [u8; 8] = *b"KRFLOOR1";
/// Where the environment's identity starts.
const ENVIRONMENT_AT: usize = 8;
/// Where the boot's epoch starts, big-endian.
const BOOT_AT: usize = 24;
/// Where the floor's own identity starts.
const IDENTITY_AT: usize = 32;
/// How much of the file is header.
const HEADER_LEN: usize = 48;
/// The floor itself.
const FLOOR_AT: usize = 64;
/// The highest floor a lapse decision stood on that is owed its record.
const OWED_AT: usize = 72;
/// The highest floor the control daemon has written down.
const RECORDED_AT: usize = 80;

/// The identity of one floor: sixteen random bytes its creating daemon drew.
///
/// Two floors of one boot have two identities, which is how a daemon that finds its floor's file
/// gone tells a lost floor from a first start, and how a worker states which floor it maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FloorIdentity([u8; 16]);

impl FloorIdentity {
    /// Draws a fresh identity from the operating system's random generator.
    ///
    /// # Errors
    ///
    /// Returns an error when the generator does not answer.
    pub fn fresh() -> Result<Self> {
        let mut bytes = [0_u8; 16];
        kr_crypto::random_bytes(&mut bytes).map_err(|error| IpcError::IdentityUnavailable {
            what: "a clock floor identity",
            detail: error.to_string(),
        })?;
        Ok(Self(bytes))
    }

    /// An identity from its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The identity's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Reads an identity written as 32 lowercase hexadecimal digits, and nothing else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in digits.chunks_exact(2).enumerate() {
            bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Some(Self(bytes))
    }
}

impl core::fmt::Display for FloorIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The value of one lowercase hexadecimal digit.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Why a file is not a floor this process maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unusable {
    /// Nothing is at the path.
    pub absent: bool,
    /// What was wrong, for a log line or a refusal's detail.
    pub reason: String,
}

impl Unusable {
    fn absent() -> Self {
        Self {
            absent: true,
            reason: "there is no clock floor file".to_owned(),
        }
    }

    fn because(reason: impl Into<String>) -> Self {
        Self {
            absent: false,
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for Unusable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// Which file a process opened, so a later check can ask whether the name still names it.
///
/// The device and inode on Unix; the volume serial number and file index on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    index: u64,
}

/// The host's clock floor: the word, `owed` and `recorded`.
///
/// Either a mapping of the environment's floor file, which every process of the environment
/// shares, or three words of this process's own, for a caller with no runtime directory (a unit
/// test of something that decides from a floor). Both answer the same way.
pub struct SharedFloor {
    words: Words,
}

enum Words {
    Local(Box<[AtomicU64; 3]>),
    Mapped(Mapped),
}

struct Mapped {
    identity: FloorIdentity,
    path: PathBuf,
    file: FileIdentity,
    view: platform::View,
}

impl core::fmt::Debug for SharedFloor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedFloor")
            .field("identity", &self.identity())
            .field("floor", &self.load())
            .field("owed", &self.owed())
            .field("recorded", &self.recorded())
            .finish()
    }
}

impl SharedFloor {
    /// A floor of this process's own at `floor_ms`, which nothing else can map.
    ///
    /// `recorded` starts where the floor does, because the caller read it back from where it was
    /// written down.
    #[must_use]
    pub fn in_process(floor_ms: u64) -> Self {
        Self {
            words: Words::Local(Box::new([
                AtomicU64::new(floor_ms),
                AtomicU64::new(0),
                AtomicU64::new(floor_ms),
            ])),
        }
    }

    /// Opens and maps the floor at `path`, when it is this environment's floor for this boot.
    ///
    /// # Errors
    ///
    /// Returns why the file is no floor: absent, or failing one of the checks the module states.
    pub fn open(
        path: &Path,
        environment_id: EnvironmentId,
        boot_epoch: BootEpoch,
    ) -> std::result::Result<Self, Unusable> {
        let (view, file) = platform::open(path)?;
        let header = view.header();
        if header[..ENVIRONMENT_AT] != FORMAT {
            return Err(Unusable::because(
                "the clock floor file is not in a format this build reads",
            ));
        }
        if header[ENVIRONMENT_AT..BOOT_AT] != *environment_id.get().as_bytes() {
            return Err(Unusable::because(
                "the clock floor file belongs to another environment",
            ));
        }
        if header[BOOT_AT..IDENTITY_AT] != boot_epoch.get().to_be_bytes() {
            return Err(Unusable::because(
                "the clock floor file belongs to another boot",
            ));
        }
        let mut identity = [0_u8; 16];
        identity.copy_from_slice(&header[IDENTITY_AT..HEADER_LEN]);
        Ok(Self {
            words: Words::Mapped(Mapped {
                identity: FloorIdentity(identity),
                path: path.to_path_buf(),
                file,
                view,
            }),
        })
    }

    /// Creates a new floor at `path` under a fresh identity, its word and `recorded` at
    /// `floor_ms`, and maps it.
    ///
    /// The whole file is written under a temporary name and renamed into place, so no process ever
    /// maps a floor that is half written, and whatever was at `path` before is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written, published or mapped, or when what is at
    /// `path` afterwards is not the floor this call wrote.
    pub fn create(
        path: &Path,
        environment_id: EnvironmentId,
        boot_epoch: BootEpoch,
        floor_ms: u64,
    ) -> Result<Self> {
        let identity = FloorIdentity::fresh()?;
        let mut contents = vec![0_u8; FLOOR_FILE_LEN];
        contents[..ENVIRONMENT_AT].copy_from_slice(&FORMAT);
        contents[ENVIRONMENT_AT..BOOT_AT].copy_from_slice(environment_id.get().as_bytes());
        contents[BOOT_AT..IDENTITY_AT].copy_from_slice(&boot_epoch.get().to_be_bytes());
        contents[IDENTITY_AT..HEADER_LEN].copy_from_slice(identity.as_bytes());
        // The words are read through atomics on the mapping, which are in this machine's own byte
        // order.
        contents[FLOOR_AT..FLOOR_AT + 8].copy_from_slice(&floor_ms.to_ne_bytes());
        contents[RECORDED_AT..RECORDED_AT + 8].copy_from_slice(&floor_ms.to_ne_bytes());
        crate::paths::write_owner_only_file(path, &contents)?;
        let floor = Self::open(path, environment_id, boot_epoch).map_err(|unusable| {
            IpcError::io(
                "map the clock floor",
                path,
                std::io::Error::other(unusable.reason),
            )
        })?;
        if floor.identity() != Some(identity) {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "the clock floor file was replaced while it was being created",
            });
        }
        Ok(floor)
    }

    /// The floor's identity, or none for a floor of this process's own.
    #[must_use]
    pub const fn identity(&self) -> Option<FloorIdentity> {
        match &self.words {
            Words::Local(_) => None,
            Words::Mapped(mapped) => Some(mapped.identity),
        }
    }

    /// Where the floor's file is, or none for a floor of this process's own.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match &self.words {
            Words::Local(_) => None,
            Words::Mapped(mapped) => Some(&mapped.path),
        }
    }

    fn word(&self, at: usize) -> &AtomicU64 {
        match &self.words {
            Words::Local(words) => &words[(at - FLOOR_AT) / 8],
            Words::Mapped(mapped) => mapped.view.word(at),
        }
    }

    /// Publishes `sample` and returns the reading to decide from: the word as the raise left it.
    ///
    /// `fetch_max` returns the word's previous value, so the larger of that and the sample is what
    /// the word holds once the raise has landed. It never waits.
    pub fn raise(&self, sample: u64) -> u64 {
        self.word(FLOOR_AT)
            .fetch_max(sample, Ordering::SeqCst)
            .max(sample)
    }

    /// The word as it stands.
    #[must_use]
    pub fn load(&self) -> u64 {
        self.word(FLOOR_AT).load(Ordering::SeqCst)
    }

    /// Records that a lapse decision stood on the floor at `at_ms` and is owed its record.
    pub fn owe(&self, at_ms: u64) {
        self.word(OWED_AT).fetch_max(at_ms, Ordering::SeqCst);
    }

    /// The highest floor a lapse decision stood on that is owed its record.
    #[must_use]
    pub fn owed(&self) -> u64 {
        self.word(OWED_AT).load(Ordering::SeqCst)
    }

    /// Records that the floor has been written down up to `floor_ms`.
    pub fn record(&self, floor_ms: u64) {
        self.word(RECORDED_AT).fetch_max(floor_ms, Ordering::SeqCst);
    }

    /// The highest floor written down.
    #[must_use]
    pub fn recorded(&self) -> u64 {
        self.word(RECORDED_AT).load(Ordering::SeqCst)
    }

    /// Whether the floor's pathname still names the file this process maps.
    ///
    /// One metadata call on the pathname. A floor of this process's own has no name to lose.
    #[must_use]
    pub fn named(&self) -> bool {
        match &self.words {
            Words::Local(_) => true,
            Words::Mapped(mapped) => {
                platform::identity_at(&mapped.path).is_some_and(|found| found == mapped.file)
            }
        }
    }
}

/// Opening, checking and mapping the file, on Unix.
///
/// One of the four places in this crate that leave safe Rust: a shared mapping of a file has no safe
/// interface, and neither has an atomic placed on one.
#[cfg(unix)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "a shared mapping of the floor's file, and the atomics on it, have no safe interface"
    )]

    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;

    use rustix::fs::{Mode, OFlags};
    use rustix::mm::{MapFlags, ProtFlags};

    use super::{FLOOR_FILE_LEN, FileIdentity, HEADER_LEN, Unusable};

    /// A mapping of the floor's file, with the file held open for as long as it lasts.
    pub(super) struct View {
        _file: std::fs::File,
        base: *mut core::ffi::c_void,
    }

    // SAFETY: the mapping is shared memory that is only ever read through atomics (the words) or
    // copied out (the header, which nothing writes once the file is published). Nothing in it is
    // tied to the thread that mapped it.
    unsafe impl Send for View {}
    // SAFETY: as above; every access through a shared reference is atomic or a copy.
    unsafe impl Sync for View {}

    impl View {
        pub(super) fn word(&self, at: usize) -> &AtomicU64 {
            debug_assert!(at.is_multiple_of(8) && at + 8 <= FLOOR_FILE_LEN);
            // SAFETY: `base` is the page-aligned start of a live shared mapping of exactly
            // FLOOR_FILE_LEN bytes, so `base + at` is inside it and eight-byte aligned. The
            // returned reference borrows `self`, which keeps the mapping alive. Every access to
            // these eight bytes, in this process and in every other one that maps the file, is a
            // 64-bit atomic: the file's initial contents were written before it was published.
            unsafe { AtomicU64::from_ptr(self.base.cast::<u8>().add(at).cast::<u64>()) }
        }

        pub(super) fn header(&self) -> [u8; HEADER_LEN] {
            let mut header = [0_u8; HEADER_LEN];
            // SAFETY: the header lies inside the live mapping, and nothing writes it once the file
            // is published, so copying it out races with nothing.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.base.cast::<u8>(),
                    header.as_mut_ptr(),
                    HEADER_LEN,
                );
            }
            header
        }
    }

    impl Drop for View {
        fn drop(&mut self) {
            // SAFETY: `base` came from `mmap` with this length and is unmapped exactly once. No
            // reference into it outlives `self`, because every one borrows `self`.
            let _ = unsafe { rustix::mm::munmap(self.base, FLOOR_FILE_LEN) };
        }
    }

    pub(super) fn open(path: &Path) -> Result<(View, FileIdentity), Unusable> {
        let file = match rustix::fs::open(
            path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => std::fs::File::from(file),
            Err(rustix::io::Errno::NOENT) => return Err(Unusable::absent()),
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::MLINK) => {
                return Err(Unusable::because(
                    "the clock floor file must not be a symbolic link",
                ));
            }
            Err(error) => {
                return Err(Unusable::because(format!(
                    "the clock floor file cannot be opened: {error}"
                )));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            Unusable::because(format!("the clock floor file cannot be inspected: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(Unusable::because(
                "the clock floor file must be a regular file",
            ));
        }
        if metadata.uid() != crate::paths::current_uid() {
            return Err(Unusable::because(
                "the clock floor file belongs to another user",
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(Unusable::because(
                "the clock floor file may be read or written by another user",
            ));
        }
        if metadata.len() != FLOOR_FILE_LEN as u64 {
            return Err(Unusable::because(
                "the clock floor file is not the length this build writes",
            ));
        }
        let identity = FileIdentity {
            device: metadata.dev(),
            index: metadata.ino(),
        };
        // SAFETY: a fresh shared mapping of a file this process holds open, of the file's whole
        // length, at an address the kernel chooses. Nothing else in this process refers to it.
        let base = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                FLOOR_FILE_LEN,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &file,
                0,
            )
        }
        .map_err(|error| {
            Unusable::because(format!("the clock floor file cannot be mapped: {error}"))
        })?;
        Ok((View { _file: file, base }, identity))
    }

    /// Which file the pathname names now, without following a link.
    pub(super) fn identity_at(path: &Path) -> Option<FileIdentity> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        Some(FileIdentity {
            device: metadata.dev(),
            index: metadata.ino(),
        })
    }
}

/// Opening, checking and mapping the file, on Windows.
///
/// One of the four places in this crate that leave safe Rust: a file mapping, the atomics on it and
/// a file's identity are all calls into `kernel32`, which has no safe interface.
#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "a file mapping, the atomics on it and a file's identity are kernel32 calls, which \
                  have no safe interface"
    )]

    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
        MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
    };

    use super::{FLOOR_FILE_LEN, FileIdentity, HEADER_LEN, Unusable};

    /// A view of the floor's file, with the file and the mapping held for as long as it lasts.
    ///
    /// The file is open without delete sharing, so nothing can remove or replace its name while
    /// this view exists.
    pub(super) struct View {
        _file: std::fs::File,
        mapping: HANDLE,
        base: MEMORY_MAPPED_VIEW_ADDRESS,
    }

    // SAFETY: the view is shared memory that is only ever read through atomics (the words) or
    // copied out (the header, which nothing writes once the file is published), and the mapping
    // handle is a kernel object any thread may close. Nothing is tied to the mapping thread.
    unsafe impl Send for View {}
    // SAFETY: as above; every access through a shared reference is atomic or a copy.
    unsafe impl Sync for View {}

    impl View {
        pub(super) fn word(&self, at: usize) -> &AtomicU64 {
            debug_assert!(at.is_multiple_of(8) && at + 8 <= FLOOR_FILE_LEN);
            // SAFETY: `base` is the start of a live view of exactly FLOOR_FILE_LEN bytes, aligned
            // to the allocation granularity, so `base + at` is inside it and eight-byte aligned.
            // The reference borrows `self`, which keeps the view alive, and every access to these
            // eight bytes in any process is a 64-bit atomic.
            unsafe { AtomicU64::from_ptr(self.base.Value.cast::<u8>().add(at).cast::<u64>()) }
        }

        pub(super) fn header(&self) -> [u8; HEADER_LEN] {
            let mut header = [0_u8; HEADER_LEN];
            // SAFETY: the header lies inside the live view, and nothing writes it once the file is
            // published.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.base.Value.cast::<u8>(),
                    header.as_mut_ptr(),
                    HEADER_LEN,
                );
            }
            header
        }
    }

    impl Drop for View {
        fn drop(&mut self) {
            // SAFETY: the view and the mapping were created by `open` and are released exactly
            // once. No reference into the view outlives `self`.
            unsafe {
                UnmapViewOfFile(self.base);
                CloseHandle(self.mapping);
            }
        }
    }

    fn information(file: &std::fs::File) -> Option<FileIdentity> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is live for the call, and the call writes one structure of exactly
        // this type through the pointer.
        let answered =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
        (answered != 0).then(|| FileIdentity {
            device: u64::from(information.dwVolumeSerialNumber),
            index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    pub(super) fn open(path: &Path) -> Result<(View, FileIdentity), Unusable> {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            // Read and write sharing, and no delete sharing: while this is open, nothing can
            // remove the name or rename another file over it.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Unusable::absent());
            }
            Err(error) => {
                return Err(Unusable::because(format!(
                    "the clock floor file cannot be opened: {error}"
                )));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            Unusable::because(format!("the clock floor file cannot be inspected: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Unusable::because(
                "the clock floor file must be a regular file, not a link",
            ));
        }
        if metadata.len() != FLOOR_FILE_LEN as u64 {
            return Err(Unusable::because(
                "the clock floor file is not the length this build writes",
            ));
        }
        let identity = information(&file)
            .ok_or_else(|| Unusable::because("the clock floor file's identity cannot be read"))?;
        // SAFETY: a mapping of a file this process holds open, of its whole length, with no name
        // and no attributes.
        let mapping = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                0,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(Unusable::because(format!(
                "the clock floor file cannot be mapped: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: a view of the whole mapping just created, readable and writable.
        let base = unsafe {
            MapViewOfFile(
                mapping,
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                FLOOR_FILE_LEN,
            )
        };
        if base.Value.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: the mapping handle was created above and is closed exactly once.
            unsafe {
                CloseHandle(mapping);
            }
            return Err(Unusable::because(format!(
                "the clock floor file cannot be mapped: {error}"
            )));
        }
        Ok((
            View {
                _file: file,
                mapping,
                base,
            },
            identity,
        ))
    }

    /// Which file the pathname names now, without following a link.
    pub(super) fn identity_at(path: &Path) -> Option<FileIdentity> {
        let file = std::fs::OpenOptions::new()
            // No access to the data: only the attributes, which every sharing mode admits.
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .ok()?;
        information(&file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let suffix = crate::new_uuid().to_string();
        let base = std::env::temp_dir().join(format!("kr-floor-{name}-{}", &suffix[..8]));
        crate::paths::create_private_tree(&base, &base).expect("a private directory");
        base
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::new(crate::new_uuid())
    }

    #[test]
    fn two_mappings_of_one_file_are_one_word() {
        let root = directory("one-word");
        let path = root.join("utc-floor");
        let environment_id = environment();
        let boot = BootEpoch::new(7);
        let first = SharedFloor::create(&path, environment_id, boot, 1_000).expect("created");
        let second = SharedFloor::open(&path, environment_id, boot).expect("opened");
        assert_eq!(first.identity(), second.identity());
        assert_eq!(
            second.load(),
            1_000,
            "the word starts at the floor it was created at"
        );
        assert_eq!(second.recorded(), 1_000, "and so does what is written down");
        assert_eq!(second.owed(), 0);

        assert_eq!(first.raise(5_000), 5_000);
        assert_eq!(
            second.load(),
            5_000,
            "one mapping's raise is the other's word at once"
        );
        assert_eq!(
            second.raise(4_000),
            5_000,
            "a lower reading changes nothing, and the answer is the word as it stands"
        );
        assert_eq!(first.load(), 5_000);

        second.owe(4_500);
        assert_eq!(first.owed(), 4_500);
        first.record(4_800);
        first.record(4_700);
        assert_eq!(second.recorded(), 4_800, "the record only rises");
        std::fs::remove_dir_all(&root).expect("removed");
    }

    #[test]
    fn a_floor_of_this_process_answers_as_a_mapping_does() {
        let floor = SharedFloor::in_process(2_000);
        assert_eq!(floor.identity(), None);
        assert_eq!(floor.raise(1_000), 2_000);
        assert_eq!(floor.raise(3_000), 3_000);
        assert_eq!(floor.recorded(), 2_000);
        floor.owe(3_000);
        assert_eq!(floor.owed(), 3_000);
        assert!(floor.named(), "a floor with no file has no name to lose");
    }

    #[test]
    fn a_file_of_another_boot_or_environment_is_no_floor() {
        let root = directory("other");
        let path = root.join("utc-floor");
        let environment_id = environment();
        let _floor =
            SharedFloor::create(&path, environment_id, BootEpoch::new(1), 0).expect("created");
        let other_boot = SharedFloor::open(&path, environment_id, BootEpoch::new(2))
            .expect_err("another boot's floor");
        assert!(!other_boot.absent);
        let other_environment = SharedFloor::open(&path, environment(), BootEpoch::new(1))
            .expect_err("another environment's floor");
        assert!(!other_environment.absent);
        // Control: the right environment and boot open it.
        SharedFloor::open(&path, environment_id, BootEpoch::new(1)).expect("this floor");
        let absent = SharedFloor::open(&root.join("none"), environment_id, BootEpoch::new(1))
            .expect_err("nothing there");
        assert!(absent.absent);
        std::fs::remove_dir_all(&root).expect("removed");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_a_shared_file_or_a_file_of_the_wrong_length_is_no_floor() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = directory("checks");
        let path = root.join("utc-floor");
        let environment_id = environment();
        let boot = BootEpoch::new(3);
        let floor = SharedFloor::create(&path, environment_id, boot, 0).expect("created");
        drop(floor);

        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).expect("a link");
        let refused = SharedFloor::open(&link, environment_id, boot).expect_err("a link");
        assert!(refused.reason.contains("symbolic link"), "{refused}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("widened");
        let refused = SharedFloor::open(&path, environment_id, boot).expect_err("readable");
        assert!(refused.reason.contains("another user"), "{refused}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("narrowed");
        SharedFloor::open(&path, environment_id, boot).expect("the control opens");

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("opened");
        file.set_len(FLOOR_FILE_LEN as u64 + 8).expect("lengthened");
        let refused = SharedFloor::open(&path, environment_id, boot).expect_err("too long");
        assert!(refused.reason.contains("length"), "{refused}");
        std::fs::remove_dir_all(&root).expect("removed");
    }

    #[cfg(unix)]
    #[test]
    fn a_floor_whose_name_is_gone_is_found_at_the_next_check() {
        let environment_id = environment();
        let boot = BootEpoch::new(4);

        // The name removed.
        let root = directory("removed");
        let path = root.join("utc-floor");
        let floor = SharedFloor::create(&path, environment_id, boot, 0).expect("created");
        assert!(floor.named(), "the control: the name names the mapped file");
        std::fs::remove_file(&path).expect("removed");
        assert!(!floor.named());
        std::fs::remove_dir_all(&root).expect("removed");

        // Another file renamed over the name.
        let root = directory("replaced");
        let path = root.join("utc-floor");
        let floor = SharedFloor::create(&path, environment_id, boot, 0).expect("created");
        let other = root.join("other");
        let _replacement = SharedFloor::create(&other, environment_id, boot, 0).expect("created");
        std::fs::rename(&other, &path).expect("renamed over");
        assert!(!floor.named());
        std::fs::remove_dir_all(&root).expect("removed");

        // A hard link left behind before the name goes.
        let root = directory("linked");
        let path = root.join("utc-floor");
        let floor = SharedFloor::create(&path, environment_id, boot, 0).expect("created");
        std::fs::hard_link(&path, root.join("kept")).expect("linked");
        std::fs::remove_file(&path).expect("removed");
        assert!(
            !floor.named(),
            "a link elsewhere keeps the file, not its name"
        );
        std::fs::remove_dir_all(&root).expect("removed");

        // The directory renamed.
        let root = directory("moved");
        let path = root.join("utc-floor");
        let floor = SharedFloor::create(&path, environment_id, boot, 0).expect("created");
        let moved = root.with_extension("moved");
        std::fs::rename(&root, &moved).expect("moved");
        assert!(!floor.named());
        std::fs::remove_dir_all(&moved).expect("removed");
    }

    #[test]
    fn an_identity_is_thirty_two_lowercase_hexadecimal_digits() {
        let identity = FloorIdentity::fresh().expect("drawn");
        let text = identity.to_string();
        assert_eq!(text.len(), 32);
        assert_eq!(FloorIdentity::parse(&text), Some(identity));
        assert_eq!(FloorIdentity::parse(&text.to_uppercase()), None);
        assert_eq!(FloorIdentity::parse(&text[..31]), None);
        assert_ne!(FloorIdentity::fresh().expect("drawn"), identity);
    }
}
