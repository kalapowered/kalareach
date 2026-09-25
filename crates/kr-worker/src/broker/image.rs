//! The executable an integrated invocation runs: the file object that was hashed, and the kernel's
//! own evidence that a process executes it.
//!
//! The identity read opens the executable once and, through that one descriptor, reads its
//! identity, hashes its bytes and, on macOS, reads the code-directory hashes its own signature
//! carries. The check that a registered process executes it asks the kernel about the process's
//! main executable, and never resolves a path:
//!
//! - Linux: the whole identity of `/proc/<pid>/exe`, the kernel's link to the image the process
//!   executed.
//! - macOS: the code-directory hash the kernel holds for the process's main executable, which it
//!   takes from the process's text vnode and not from any mapping. The code directory hashes every
//!   page of the code and the kernel refuses a page that does not match it, so a process whose hash
//!   is one the hashed file's signature carries executes the hashed code, and a process that only
//!   maps that file does not match.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;

/// How many times the identity of a file that changed while it was read is read again.
const IDENTITY_ATTEMPTS: usize = 3;

/// How many times the check that a process executes the hashed code is taken, when what it read
/// changed while it was taken. Only a reading that held still decides.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const IMAGE_ATTEMPTS: usize = 3;

/// A file's identity, as the kernel reports it for one opened file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileIdentity {
    /// The device it is on.
    pub device: u64,
    /// Its inode.
    pub inode: u64,
    /// Its length in bytes.
    pub size: u64,
    /// Its last modification, in nanoseconds.
    pub modified_ns: i128,
    /// Its last status change, in nanoseconds.
    pub changed_ns: i128,
}

impl FileIdentity {
    /// Reads the identity the kernel reports for one file.
    #[cfg(unix)]
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }

    /// A platform without inodes names no identity a file could be held to.
    #[cfg(not(unix))]
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: 0,
            inode: 0,
            size: metadata.len(),
            modified_ns: 0,
            changed_ns: 0,
        }
    }
}

/// One code-directory hash: the first 20 bytes of the hash of one code directory, the value the
/// kernel keeps for a running executable and `codesign` prints as `CDHash`.
pub type CodeDirectoryHash = [u8; 20];

/// What one read of a file object found: its identity, its digest and its code-directory hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashedFile {
    /// The file object that was hashed.
    pub file: FileIdentity,
    /// The SHA-256 digest of its bytes.
    pub digest: Digest256,
    /// The code-directory hashes its own signature carries, on macOS; empty elsewhere.
    pub code_directories: Vec<CodeDirectoryHash>,
}

/// What the backend read about the executable an invocation runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    /// The file object, its digest and its code-directory hashes.
    pub hashed: HashedFile,
    /// The version a signed qualification record names for that digest, where one does.
    pub version: Option<String>,
}

/// The files already read, by identity, so a later launch of the same file costs a lookup.
pub(crate) type HashedFiles = Mutex<BTreeMap<FileIdentity, HashedFile>>;

/// Reads one executable through one opened file: its identity, its digest and its code-directory
/// hashes.
///
/// The identity is read before and after, through the same descriptor, so everything read belongs
/// to the file object the identity names; a file that changed meanwhile is read again, and one that
/// keeps changing is not read at all. A script is refused: the image its process runs is its
/// interpreter, which nothing here could tie to it.
///
/// On macOS the file's own code directories are read first, and the one pass that hashes the file
/// also hashes each directory's pages: only a directory whose every code slot matches the page it
/// names is kept, so a kept hash describes the code this file holds, not a directory copied into it.
///
/// The work is bounded whatever is at the path: the file is opened without waiting and refused
/// unless the opened descriptor is a regular file, no more than the size read at the start is read,
/// and the reading stops as soon as `stop` is set.
pub(crate) fn read_identity(
    path: &Path,
    cache: &HashedFiles,
    stop: &AtomicBool,
) -> Result<HashedFile, String> {
    for _ in 0..IDENTITY_ATTEMPTS {
        let file = open_without_waiting(path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let before = regular_identity(&file, path)?;
        let cached = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&before)
            .cloned();
        if let Some(hashed) = cached {
            return Ok(hashed);
        }
        let directories = directories_of(&file, before.size);
        let Some((digest, code_directories)) =
            hash_file(&file, path, before.size, directories, stop)?
        else {
            continue;
        };
        let after = regular_identity(&file, path)?;
        if before != after {
            continue;
        }
        let hashed = HashedFile {
            file: before,
            digest,
            code_directories,
        };
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(before, hashed.clone());
        return Ok(hashed);
    }
    Err(format!(
        "{} kept changing while it was read",
        path.display()
    ))
}

/// Opens a file to read without waiting for it, whatever the file is: a FIFO or a device in its
/// place cannot hold the reader, and what it is decides afterwards.
fn open_without_waiting(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

/// The identity of an opened file that is a regular file, and a refusal for anything else.
fn regular_identity(file: &std::fs::File, path: &Path) -> Result<FileIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(FileIdentity::of(&metadata))
}

/// Hashes the first `size` bytes of an opened file, feeding each code directory its pages, and
/// returns the digest and the directories that matched; `None` when the file held fewer bytes than
/// that, so it changed.
///
/// # Errors
///
/// Returns why it could not be read: a read that failed, a script, or a stop.
fn hash_file<D: PageCheck>(
    mut file: &std::fs::File,
    path: &Path,
    size: u64,
    mut directories: Vec<D>,
    stop: &AtomicBool,
) -> Result<Option<(Digest256, Vec<CodeDirectoryHash>)>, String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut offset = 0_u64;
    while offset < size {
        if stop.load(Ordering::Relaxed) {
            return Err(format!("the reading of {} was stopped", path.display()));
        }
        let wanted = usize::try_from((size - offset).min(1 << 20)).unwrap_or(1 << 20);
        let read = file
            .read(buffer.get_mut(..wanted).unwrap_or_default())
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        if read == 0 {
            return Ok(None);
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        if offset == 0 && chunk.starts_with(b"#!") {
            return Err(format!(
                "{} is a script, and the program it runs is its interpreter",
                path.display()
            ));
        }
        hasher.update(chunk);
        for directory in &mut directories {
            directory.feed(offset, chunk);
        }
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok(Some((
        Digest256::from_bytes(hasher.finalize().into()),
        directories
            .into_iter()
            .filter_map(PageCheck::kept)
            .collect(),
    )))
}

/// What checks a code directory's pages as the file streams past.
trait PageCheck {
    fn feed(&mut self, offset: u64, chunk: &[u8]);
    fn kept(self) -> Option<CodeDirectoryHash>;
}

#[cfg(target_os = "macos")]
fn directories_of(file: &std::fs::File, size: u64) -> Vec<code_signature::Directory> {
    code_signature::directories(file, size)
}

#[cfg(not(target_os = "macos"))]
fn directories_of(_file: &std::fs::File, _size: u64) -> Vec<NoDirectory> {
    Vec::new()
}

/// A platform whose executables carry no code directory reads none.
#[cfg(not(target_os = "macos"))]
enum NoDirectory {}

#[cfg(not(target_os = "macos"))]
impl PageCheck for NoDirectory {
    fn feed(&mut self, _offset: u64, _chunk: &[u8]) {
        match *self {}
    }

    fn kept(self) -> Option<CodeDirectoryHash> {
        match self {}
    }
}

/// The identities of executables already shown to hold the digest that was hashed, so each is
/// hashed at most once.
pub type VerifiedFiles = Mutex<BTreeSet<FileIdentity>>;

/// Checks, from the kernel's record of the process's main executable, that a registered process
/// executes the code that was hashed.
///
/// Linux reads the file `/proc/<pid>/exe` names, which is the one the process executes even after
/// its path is replaced or removed. It passes when its whole identity, change time included, is the
/// one that was hashed or one already shown to hold the same digest; any other identity is hashed,
/// and passes when its digest is the one that was hashed. An upgrade that unlinks the running file
/// changes its metadata and not its code, and passes; a rewrite of its code does not.
///
/// The link is opened again after each reading. When it names another identity then (the process
/// exec'd, or the file's metadata moved while it was read), the reading is taken again through the
/// newly opened file, at most [`IMAGE_ATTEMPTS`] times, and only a reading that held still decides:
/// an upgrade during a check passes by its content, and a process that exec'd other code is refused.
///
/// The check proves what the process executed when it was read. A process can exec after that and
/// before its bridge is admitted; the next bridge is checked again.
///
/// # Errors
///
/// Returns why the process does not execute it, or why that could not be established.
#[cfg(target_os = "linux")]
pub fn verify_image(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    verified: &VerifiedFiles,
    stop: &AtomicBool,
) -> Result<(), String> {
    verify_opening(process, identity, verified, stop, || {
        OpenedImage::open(process)
    })
}

/// The check of [`verify_image`], with the way the process's image is opened given, so a test can
/// change the file between two openings.
#[cfg(target_os = "linux")]
fn verify_opening(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    verified: &VerifiedFiles,
    stop: &AtomicBool,
    mut open: impl FnMut() -> Result<OpenedImage, String>,
) -> Result<(), String> {
    let mut opened = open()?;
    for _ in 0..IMAGE_ATTEMPTS {
        match opened.check(process, identity, verified, stop, &mut open)? {
            Checked::Holds => return Ok(()),
            Checked::Differs => return Err(other_code(process)),
            Checked::Moved(now) => opened = now,
        }
    }
    Err(format!(
        "the image of process {} kept changing while it was checked",
        process.pid
    ))
}

/// What one reading of a process's image found.
#[cfg(target_os = "linux")]
enum Checked {
    /// The process executes the hashed code, and the reading held still.
    Holds,
    /// It executes other code, and the reading held still.
    Differs,
    /// The link names another identity than the one read: the file it names now, to read again.
    Moved(OpenedImage),
}

/// The file a process executes, opened through `/proc/<pid>/exe`, and its identity then.
#[cfg(target_os = "linux")]
struct OpenedImage {
    link: std::path::PathBuf,
    file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
impl OpenedImage {
    fn open(process: &ProcessStartIdentity) -> Result<Self, String> {
        let link = std::path::PathBuf::from(format!("/proc/{}/exe", process.pid.get()));
        let file = open_without_waiting(&link).map_err(|error| {
            format!(
                "the image of process {} cannot be read: {error}",
                process.pid
            )
        })?;
        let identity = regular_identity(&file, &link)?;
        Ok(Self {
            link,
            file,
            identity,
        })
    }

    /// Reads the opened file against what was hashed, then opens the link again: the reading
    /// decides only when the link still names the identity that was read, so an exec or a change of
    /// the file while it was read shows as [`Checked::Moved`].
    fn check(
        &self,
        process: &ProcessStartIdentity,
        identity: &ExecutableIdentity,
        verified: &VerifiedFiles,
        stop: &AtomicBool,
        open: &mut impl FnMut() -> Result<Self, String>,
    ) -> Result<Checked, String> {
        let before = self.identity;
        let known = before == identity.hashed.file
            || verified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&before);
        // Whether the file holds the hashed code, and nothing when it changed while it was hashed.
        let holds = if known {
            Some(true)
        } else {
            let hashed = hash_file(
                &self.file,
                &self.link,
                before.size,
                Vec::<NoDirectory>::new(),
                stop,
            )?;
            let after = regular_identity(&self.file, &self.link)?;
            hashed
                .filter(|_| after == before)
                .map(|(digest, _)| digest == identity.hashed.digest)
        };
        let now = open()?;
        still_registered(process)?;
        if now.identity != before {
            return Ok(Checked::Moved(now));
        }
        Ok(match holds {
            Some(true) => {
                verified
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(before);
                Checked::Holds
            }
            Some(false) => Checked::Differs,
            None => Checked::Moved(now),
        })
    }
}

/// Checks, from the kernel's record of the process's main executable, that a registered process
/// executes the code that was hashed.
///
/// macOS compares the code-directory hash the kernel keeps for the process's main executable with
/// the ones the hashed file's own signature carries. The hash is read before and after the start
/// check; two readings that differ (an exec between them) are taken again, at most
/// [`IMAGE_ATTEMPTS`] times, and only equal readings decide.
///
/// The check proves what the process executed when it was read. A process can exec after that and
/// before its bridge is admitted; the next bridge is checked again.
///
/// # Errors
///
/// Returns why the process does not execute it, or why that could not be established.
#[cfg(target_os = "macos")]
pub fn verify_image(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    _verified: &VerifiedFiles,
    _stop: &AtomicBool,
) -> Result<(), String> {
    let pid = i32::try_from(process.pid.get())
        .map_err(|_| format!("{} is not a process identifier", process.pid))?;
    verify_reading(process, identity, || code_signature::of_process(pid))
}

/// The check of [`verify_image`], with the reading of the process's code-directory hash given, so a
/// test can present readings that change.
#[cfg(target_os = "macos")]
fn verify_reading(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    mut read: impl FnMut() -> Result<CodeDirectoryHash, String>,
) -> Result<(), String> {
    for _ in 0..IMAGE_ATTEMPTS {
        let running = read()?;
        still_registered(process)?;
        // Read again after the start check: an exec in between shows as another hash.
        if read()? != running {
            continue;
        }
        return if identity.hashed.code_directories.contains(&running) {
            Ok(())
        } else {
            Err(other_code(process))
        };
    }
    Err(format!(
        "the image of process {} kept changing while it was checked",
        process.pid
    ))
}

/// The refusal of a process that executes other code than the file its launch presented.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn other_code(process: &ProcessStartIdentity) -> String {
    format!(
        "process {} executes other code than the file its launch presented",
        process.pid
    )
}

/// No record of a process's image is read on this platform, so nothing here is verified.
///
/// # Errors
///
/// Always: nothing can be established.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn verify_image(
    process: &ProcessStartIdentity,
    _identity: &ExecutableIdentity,
    _verified: &VerifiedFiles,
    _stop: &AtomicBool,
) -> Result<(), String> {
    Err(format!(
        "this platform keeps no record of the image process {} runs",
        process.pid
    ))
}

/// Refuses a process that is no longer the one registered, so a pid reused while the kernel was
/// asked is not taken for it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn still_registered(process: &ProcessStartIdentity) -> Result<(), String> {
    if matches!(
        kr_ipc::identity::process_state(process),
        kr_ipc::identity::ProcessState::Running
    ) {
        Ok(())
    } else {
        Err(format!("process {} is not the one registered", process.pid))
    }
}

/// The code signature of a Mach-O file and of a running process.
#[cfg(target_os = "macos")]
mod code_signature {
    use std::os::unix::fs::FileExt as _;

    use super::CodeDirectoryHash;

    /// A universal file's header, with 32-bit and 64-bit slice records.
    const FAT_MAGIC: u32 = 0xcafe_babe;
    const FAT_MAGIC_64: u32 = 0xcafe_babf;
    /// A Mach-O header, 64-bit and 32-bit, read little-endian as every Apple platform stores it.
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const MH_MAGIC: u32 = 0xfeed_face;
    /// The load command naming the code signature's place in the slice.
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    /// The embedded signature and a code directory in it, both big-endian.
    const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
    /// The slots a code directory can sit in: the primary and the alternates.
    const CSSLOT_CODEDIRECTORY: u32 = 0;
    const CSSLOT_ALTERNATE_CODEDIRECTORIES: std::ops::Range<u32> = 0x1000..0x1005;
    /// The hash types whose directories this reads.
    const CS_HASHTYPE_SHA256: u8 = 2;
    const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
    const CS_HASHTYPE_SHA384: u8 = 4;
    /// The first directory version with a scatter vector, which this does not read, and the first
    /// with a 64-bit code limit.
    const VERSION_SCATTER: u32 = 0x2_0100;
    const VERSION_CODE_LIMIT_64: u32 = 0x2_0300;
    /// The length of a directory's fixed header, up to its first optional field.
    const DIRECTORY_HEADER: usize = 44;
    /// `csops`'s operation that reads the code-directory hash of a process's main executable.
    const CS_OPS_CDHASH: u32 = 5;
    /// Bounds on what is read from a file that may not be what it claims. Each slot is read at most
    /// once and a slice holds at most six, so hashing the pages is at most six passes over the file.
    const MAX_SLICES: usize = 16;
    const MAX_LOAD_COMMANDS_BYTES: usize = 1 << 20;
    const MAX_SIGNATURE_BYTES: usize = 64 << 20;
    const MAX_SIGNATURE_ENTRIES: usize = 64;

    fn read_at(file: &std::fs::File, offset: u64, length: usize) -> Option<Vec<u8>> {
        let mut bytes = vec![0_u8; length];
        file.read_exact_at(&mut bytes, offset).ok()?;
        Some(bytes)
    }

    fn be32(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_be_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    fn be64(bytes: &[u8], at: usize) -> Option<u64> {
        Some(u64::from_be_bytes(
            bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
        ))
    }

    fn le32(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    fn to_usize(value: u32) -> Option<usize> {
        usize::try_from(value).ok()
    }

    /// The hash one directory's pages are hashed with.
    enum PageHasher {
        Sha256(sha2::Sha256),
        Sha384(sha2::Sha384),
    }

    impl PageHasher {
        fn new(hash_type: u8) -> Option<Self> {
            use sha2::Digest as _;
            match hash_type {
                CS_HASHTYPE_SHA256 | CS_HASHTYPE_SHA256_TRUNCATED => {
                    Some(Self::Sha256(sha2::Sha256::new()))
                }
                CS_HASHTYPE_SHA384 => Some(Self::Sha384(sha2::Sha384::new())),
                _ => None,
            }
        }

        fn update(&mut self, bytes: &[u8]) {
            use sha2::Digest as _;
            match self {
                Self::Sha256(hasher) => hasher.update(bytes),
                Self::Sha384(hasher) => hasher.update(bytes),
            }
        }

        /// Finishes one page and starts the next, returning the page's hash.
        fn finish(&mut self) -> Vec<u8> {
            use sha2::Digest as _;
            match self {
                Self::Sha256(hasher) => hasher.finalize_reset().to_vec(),
                Self::Sha384(hasher) => hasher.finalize_reset().to_vec(),
            }
        }
    }

    /// One code directory, and its pages checked as the file streams past.
    pub(super) struct Directory {
        /// The directory's own hash, which the kernel keeps for a process that executes it.
        hash: CodeDirectoryHash,
        /// Where the code it covers starts and ends in the file.
        start: u64,
        end: u64,
        /// The size of one page, the last one ending at `end`.
        page: u64,
        /// The expected hash of each page, in order.
        slots: Vec<Vec<u8>>,
        hasher: PageHasher,
        /// The page being hashed.
        at: usize,
        /// False once a page does not match its slot.
        valid: bool,
    }

    impl super::PageCheck for Directory {
        /// Hashes the part of `chunk`, which starts at `offset` in the file, that this directory's
        /// code covers.
        fn feed(&mut self, offset: u64, chunk: &[u8]) {
            let chunk_end = offset.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            let mut from = offset.max(self.start);
            let until = chunk_end.min(self.end);
            while self.valid && from < until {
                let page_end = self
                    .start
                    .saturating_add(
                        u64::try_from(self.at)
                            .unwrap_or(u64::MAX)
                            .saturating_add(1)
                            .saturating_mul(self.page),
                    )
                    .min(self.end);
                let take = (page_end - from).min(until - from);
                let (Ok(skip), Ok(length)) =
                    (usize::try_from(from - offset), usize::try_from(take))
                else {
                    self.valid = false;
                    return;
                };
                let Some(bytes) = chunk.get(skip..skip + length) else {
                    self.valid = false;
                    return;
                };
                self.hasher.update(bytes);
                from += take;
                if from == page_end {
                    let hashed = self.hasher.finish();
                    let expected = self.slots.get(self.at);
                    if !expected.is_some_and(|expected| hashed.starts_with(expected)) {
                        self.valid = false;
                        return;
                    }
                    self.at += 1;
                }
            }
        }

        /// The directory's hash, when every page was read and matched its slot.
        fn kept(self) -> Option<CodeDirectoryHash> {
            (self.valid && self.at == self.slots.len()).then_some(self.hash)
        }
    }

    /// Reads the code directories of every slice of a Mach-O file of `size` bytes, or none for a
    /// file that is not one, carries no signature, or holds one this does not read strictly.
    pub(super) fn directories(file: &std::fs::File, size: u64) -> Vec<Directory> {
        let mut directories = Vec::new();
        let Some(header) = read_at(file, 0, 8) else {
            return directories;
        };
        let slices: Vec<(u64, u64)> = match be32(&header, 0) {
            Some(magic @ (FAT_MAGIC | FAT_MAGIC_64)) => {
                let wide = magic == FAT_MAGIC_64;
                let record = if wide { 32 } else { 20 };
                let Some(count) = be32(&header, 4).and_then(to_usize) else {
                    return directories;
                };
                if count == 0 || count > MAX_SLICES {
                    return directories;
                }
                let Some(records) = read_at(file, 8, count * record) else {
                    return directories;
                };
                let mut slices = Vec::new();
                for slice in 0..count {
                    let at = slice * record + 8;
                    let place = if wide {
                        be64(&records, at).zip(be64(&records, at + 8))
                    } else {
                        be32(&records, at)
                            .map(u64::from)
                            .zip(be32(&records, at + 4).map(u64::from))
                    };
                    let Some((offset, length)) = place else {
                        return directories;
                    };
                    slices.push((offset, length));
                }
                slices
            }
            _ => vec![(0, size)],
        };
        // Every slice inside the file, none overlapping another.
        let mut sorted = slices.clone();
        sorted.sort_unstable();
        let mut last_end = 0_u64;
        for (offset, length) in &sorted {
            let Some(end) = offset.checked_add(*length) else {
                return directories;
            };
            if *offset < last_end || end > size || *length == 0 {
                return directories;
            }
            last_end = end;
        }
        for (offset, length) in slices {
            read_slice(file, offset, length, &mut directories);
        }
        directories
    }

    /// Reads the code directories of one slice of `length` bytes starting at `base`.
    fn read_slice(file: &std::fs::File, base: u64, length: u64, directories: &mut Vec<Directory>) {
        let Some(header) = read_at(file, base, 28) else {
            return;
        };
        let header_size: u64 = match le32(&header, 0) {
            Some(MH_MAGIC_64) => 32,
            Some(MH_MAGIC) => 28,
            _ => return,
        };
        let (Some(commands), Some(commands_size)) = (
            le32(&header, 16).and_then(to_usize),
            le32(&header, 20).and_then(to_usize),
        ) else {
            return;
        };
        if commands_size > MAX_LOAD_COMMANDS_BYTES
            || commands > commands_size / 8
            || header_size + u64::try_from(commands_size).unwrap_or(u64::MAX) > length
        {
            return;
        }
        let Some(loaded) = read_at(file, base + header_size, commands_size) else {
            return;
        };
        let mut at = 0_usize;
        let mut signature = None;
        for _ in 0..commands {
            let (Some(command), Some(size)) =
                (le32(&loaded, at), le32(&loaded, at + 4).and_then(to_usize))
            else {
                return;
            };
            if size < 8 || at + size > commands_size {
                return;
            }
            if command == LC_CODE_SIGNATURE {
                if signature.is_some() || size < 16 {
                    return;
                }
                signature = le32(&loaded, at + 8).zip(le32(&loaded, at + 12));
            }
            at += size;
        }
        let Some((offset, size)) = signature else {
            return;
        };
        let (offset, Some(size)) = (u64::from(offset), to_usize(size)) else {
            return;
        };
        let within = offset
            .checked_add(u64::try_from(size).unwrap_or(u64::MAX))
            .is_some_and(|end| end <= length);
        if size > MAX_SIGNATURE_BYTES || !within {
            return;
        }
        let Some(signature) = read_at(file, base + offset, size) else {
            return;
        };
        read_signature(&signature, base, offset, directories);
    }

    /// Reads the code directories an embedded signature holds, each slot at most once and no two
    /// overlapping; a signature that breaks either rule yields none.
    fn read_signature(
        signature: &[u8],
        base: u64,
        signature_offset: u64,
        directories: &mut Vec<Directory>,
    ) {
        if be32(signature, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
            return;
        }
        let Some(count) = be32(signature, 8).and_then(to_usize) else {
            return;
        };
        if count > MAX_SIGNATURE_ENTRIES || 12 + count * 8 > signature.len() {
            return;
        }
        let mut slots = Vec::new();
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut found = Vec::new();
        for index in 0..count {
            let (Some(slot), Some(offset)) = (
                be32(signature, 12 + index * 8),
                be32(signature, 16 + index * 8).and_then(to_usize),
            ) else {
                return;
            };
            if slot != CSSLOT_CODEDIRECTORY && !CSSLOT_ALTERNATE_CODEDIRECTORIES.contains(&slot) {
                continue;
            }
            if slots.contains(&slot) {
                return;
            }
            slots.push(slot);
            let Some(length) = be32(signature, offset + 4).and_then(to_usize) else {
                return;
            };
            let Some(end) = offset
                .checked_add(length)
                .filter(|end| *end <= signature.len())
            else {
                return;
            };
            if be32(signature, offset) != Some(CSMAGIC_CODEDIRECTORY)
                || length < DIRECTORY_HEADER
                || spans
                    .iter()
                    .any(|(from, until)| offset < *until && *from < end)
            {
                return;
            }
            spans.push((offset, end));
            if let Some(directory) = signature
                .get(offset..end)
                .and_then(|blob| directory(blob, base, signature_offset))
            {
                found.push(directory);
            }
        }
        directories.extend(found);
    }

    /// Reads one code directory blob into what its pages are checked against, or nothing for one
    /// this does not read: a hash type other than SHA-256 or SHA-384, a scatter vector, a code limit
    /// past the signature, or slots that do not cover the code exactly.
    fn directory(blob: &[u8], base: u64, signature_offset: u64) -> Option<Directory> {
        use sha2::Digest as _;
        let version = be32(blob, 8)?;
        let hash_offset = to_usize(be32(blob, 16)?)?;
        let code_slots = to_usize(be32(blob, 28)?)?;
        let mut code_limit = u64::from(be32(blob, 32)?);
        let hash_size = usize::from(*blob.get(36)?);
        let hash_type = *blob.get(37)?;
        let page_shift = *blob.get(39)?;
        if version >= VERSION_SCATTER && be32(blob, 44).is_some_and(|scatter| scatter != 0) {
            return None;
        }
        if version >= VERSION_CODE_LIMIT_64
            && let Some(wide) = be64(blob, 56).filter(|wide| *wide != 0)
        {
            code_limit = wide;
        }
        let expected_size = match hash_type {
            CS_HASHTYPE_SHA256 => 32,
            CS_HASHTYPE_SHA256_TRUNCATED => 20,
            CS_HASHTYPE_SHA384 => 48,
            _ => return None,
        };
        if hash_size != expected_size || code_limit == 0 || code_limit > signature_offset {
            return None;
        }
        let page = if page_shift == 0 {
            code_limit
        } else {
            1_u64.checked_shl(u32::from(page_shift))?
        };
        let pages = usize::try_from(code_limit.div_ceil(page)).ok()?;
        if pages != code_slots {
            return None;
        }
        let slots_end = hash_offset.checked_add(code_slots.checked_mul(hash_size)?)?;
        let hashes = blob.get(hash_offset..slots_end)?;
        let slots = hashes.chunks_exact(hash_size).map(<[u8]>::to_vec).collect();
        let full: Vec<u8> = match hash_type {
            CS_HASHTYPE_SHA384 => sha2::Sha384::digest(blob).to_vec(),
            _ => sha2::Sha256::digest(blob).to_vec(),
        };
        let hash = CodeDirectoryHash::try_from(full.get(..20)?).ok()?;
        Some(Directory {
            hash,
            start: base,
            end: base.checked_add(code_limit)?,
            page,
            slots,
            hasher: PageHasher::new(hash_type)?,
            at: 0,
            valid: true,
        })
    }

    /// Reads the code-directory hash the kernel keeps for a process's main executable.
    #[expect(
        unsafe_code,
        reason = "csops is libSystem's call for the kernel's code-signing record of a process; the \
                  SDK ships no header for it and the libc crate no binding, so it is declared here \
                  and called once, with a buffer of exactly the length it is told"
    )]
    pub(super) fn of_process(pid: i32) -> Result<CodeDirectoryHash, String> {
        unsafe extern "C" {
            fn csops(
                pid: libc::pid_t,
                ops: u32,
                useraddr: *mut libc::c_void,
                usersize: libc::size_t,
            ) -> libc::c_int;
        }
        let mut hash: CodeDirectoryHash = [0; 20];
        // SAFETY: `hash` is a live, writable buffer of `hash.len()` bytes for the whole call, which
        // writes at most that many bytes into it and keeps no pointer to it afterwards.
        let status = unsafe { csops(pid, CS_OPS_CDHASH, hash.as_mut_ptr().cast(), hash.len()) };
        if status == 0 {
            Ok(hash)
        } else {
            Err(format!(
                "the kernel's code-directory hash of process {pid} cannot be read: {}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;

    fn identity_of(path: &Path) -> ExecutableIdentity {
        let cache = HashedFiles::default();
        ExecutableIdentity {
            hashed: read_identity(path, &cache, &AtomicBool::new(false))
                .expect("its identity is read"),
            version: None,
        }
    }

    /// The kernel's record of this test's own process names this test's own executable, and not a
    /// file it was not started from: this pins the kernel interface on the platform that has it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_process_executes_the_file_it_was_started_from() {
        let exe = std::env::current_exe().expect("this test's executable");
        let identity = identity_of(&exe);
        let me = kr_ipc::identity::current_process_start_identity().expect("this process");
        verify_image(
            &me,
            &identity,
            &VerifiedFiles::default(),
            &AtomicBool::new(false),
        )
        .expect("this process executes its own executable");
        let other = identity_of(Path::new("/bin/sh"));
        assert!(
            verify_image(
                &me,
                &other,
                &VerifiedFiles::default(),
                &AtomicBool::new(false)
            )
            .is_err(),
            "and not a file it was not started from"
        );
    }

    /// Another process of this user is checked against the file it executes: bash, which on macOS
    /// is a platform binary in a universal file.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn another_process_executes_the_shell_it_was_started_from() {
        let mut child = std::process::Command::new("/bin/bash")
            .args(["-c", "sleep 5; exit 0"])
            .spawn()
            .expect("bash starts");
        let process =
            kr_ipc::identity::process_start_identity(child.id()).expect("the child is identified");
        let bash = identity_of(Path::new("/bin/bash"));
        let result = verify_image(
            &process,
            &bash,
            &VerifiedFiles::default(),
            &AtomicBool::new(false),
        );
        let other = verify_image(
            &process,
            &identity_of(&std::env::current_exe().expect("exe")),
            &VerifiedFiles::default(),
            &AtomicBool::new(false),
        );
        let _ = child.kill();
        let _ = child.wait();
        result.expect("the child executes bash");
        assert!(other.is_err(), "and not this test's executable");
    }

    /// A FIFO and a character device at the path are refused at once, by the opened descriptor's
    /// type: neither waits for a writer nor reads without end.
    #[cfg(unix)]
    #[test]
    fn what_is_not_a_regular_file_is_refused_at_once() {
        let directory = std::env::temp_dir().join(format!("kr-fifo-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let fifo = directory.join("claude");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        let started = std::time::Instant::now();
        let cache = HashedFiles::default();
        let refused =
            read_identity(&fifo, &cache, &AtomicBool::new(false)).expect_err("a FIFO is refused");
        assert!(refused.contains("not a regular file"), "{refused}");
        let refused = read_identity(Path::new("/dev/zero"), &cache, &AtomicBool::new(false))
            .expect_err("a device is refused");
        assert!(refused.contains("not a regular file"), "{refused}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A reading that is told to stop stops.
    #[test]
    fn a_stopped_reading_stops() {
        let exe = std::env::current_exe().expect("this test's executable");
        let refused = read_identity(&exe, &HashedFiles::default(), &AtomicBool::new(true))
            .expect_err("stopped");
        assert!(refused.contains("stopped"), "{refused}");
    }

    /// On Linux, a process that execs another program after its image was read and before the link
    /// is opened again is read again, and refused for the other program's code, although the file
    /// read first holds the digest that was hashed.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_exec_during_the_check_is_refused() {
        use std::io::Write as _;
        let mut child = std::process::Command::new("/bin/bash")
            .args(["-c", "read line; exec /bin/sleep 5"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("bash starts");
        let process =
            kr_ipc::identity::process_start_identity(child.id()).expect("the child is identified");
        let bash = identity_of(Path::new("/bin/bash"));
        let link = format!("/proc/{}/exe", child.id());
        let mut input = child.stdin.take().expect("its input");
        let mut opens = 0_u32;
        let result = verify_opening(
            &process,
            &bash,
            &VerifiedFiles::default(),
            &AtomicBool::new(false),
            || {
                opens += 1;
                if opens == 2 {
                    input.write_all(b"go\n").expect("it is told to exec");
                    let started = std::time::Instant::now();
                    while std::fs::read_link(&link).is_ok_and(|target| target.ends_with("bash")) {
                        assert!(
                            started.elapsed() < std::time::Duration::from_secs(10),
                            "it execs"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                OpenedImage::open(&process)
            },
        );
        let _ = child.kill();
        let _ = child.wait();
        let refused = result.expect_err("the process no longer executes what was checked");
        assert!(refused.contains("other code"), "{refused}");
        assert_eq!(
            opens, 3,
            "the other program is read, and its link opened again"
        );
    }

    /// A copy of bash in a fresh directory on this host's temporary disk, and a process running it
    /// that waits on its input until the test ends it.
    #[cfg(target_os = "linux")]
    fn running_copy() -> (std::path::PathBuf, std::process::Child) {
        let directory = std::env::temp_dir().join(format!("kr-image-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let program = directory.join("program");
        std::fs::copy("/bin/bash", &program).expect("a copy of bash");
        let started = std::time::Instant::now();
        let child = loop {
            match std::process::Command::new(&program)
                .args(["-c", "read line"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => break child,
                // The copy stays busy while a child that another test forked holds it open.
                Err(error)
                    if error.raw_os_error() == Some(libc::ETXTBSY)
                        && started.elapsed() < std::time::Duration::from_secs(10) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("the copy runs: {error}"),
            }
        };
        (program, child)
    }

    /// Changes a file's metadata a clock tick after anything before it, so its change time moves.
    #[cfg(target_os = "linux")]
    fn a_tick_later(change: impl FnOnce()) {
        std::thread::sleep(std::time::Duration::from_millis(30));
        change();
    }

    /// On Linux, an upgrade that installs a new file over the running one while a check runs changes
    /// the running file's metadata and not its code: the check, which had passed by the identity it
    /// knew, reads the file again by its content and passes, and a later check passes by the identity
    /// it remembered.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_upgrade_during_the_check_is_decided_again() {
        let (program, mut child) = running_copy();
        let process =
            kr_ipc::identity::process_start_identity(child.id()).expect("the child is identified");
        let hashed = identity_of(&program);
        let verified = VerifiedFiles::default();
        let stop = AtomicBool::new(false);
        let mut opens = 0_u32;
        let upgraded = verify_opening(&process, &hashed, &verified, &stop, || {
            opens += 1;
            if opens == 2 {
                a_tick_later(|| {
                    let staged = program.with_extension("next");
                    std::fs::copy("/bin/bash", &staged).expect("the new version");
                    std::fs::rename(&staged, &program).expect("installed over the running one");
                });
            }
            OpenedImage::open(&process)
        });
        let later = verify_image(&process, &hashed, &verified, &stop);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(program.parent().expect("its directory"));
        upgraded.expect("the upgraded file still holds the hashed code");
        assert_eq!(opens, 3, "the moved file is read again");
        later.expect("a later check passes by the identity it remembered");
    }

    /// On Linux, a hard link made to the running file while a check hashes it moves its change time:
    /// the check reads the file again by its content and passes, and a later check passes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_hard_link_made_during_the_check_is_decided_again() {
        let (program, mut child) = running_copy();
        let process =
            kr_ipc::identity::process_start_identity(child.id()).expect("the child is identified");
        let hashed = identity_of(&program);
        // A first link before the check, so its first reading is not of the identity it hashed and
        // is decided by the content.
        a_tick_later(|| {
            std::fs::hard_link(&program, program.with_extension("first")).expect("a first link");
        });
        let verified = VerifiedFiles::default();
        let stop = AtomicBool::new(false);
        let mut opens = 0_u32;
        let linked = verify_opening(&process, &hashed, &verified, &stop, || {
            opens += 1;
            if opens == 2 {
                a_tick_later(|| {
                    std::fs::hard_link(&program, program.with_extension("second"))
                        .expect("a second link");
                });
            }
            OpenedImage::open(&process)
        });
        let later = verify_image(&process, &hashed, &verified, &stop);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(program.parent().expect("its directory"));
        linked.expect("the linked file still holds the hashed code");
        assert_eq!(opens, 3, "the moved file is read again");
        later.expect("a later check passes by the identity it remembered");
    }

    /// On Linux, a reading whose file keeps moving is refused after three attempts, each with its
    /// link opened again; a check that tried without end would see the file settle and pass.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_reading_that_keeps_changing_is_refused() {
        let (program, mut child) = running_copy();
        let process =
            kr_ipc::identity::process_start_identity(child.id()).expect("the child is identified");
        let hashed = identity_of(&program);
        let mut opens = 0_u64;
        let result = verify_opening(
            &process,
            &hashed,
            &VerifiedFiles::default(),
            &AtomicBool::new(false),
            || {
                opens += 1;
                // Every opening after the first finds another modification time, until the tenth.
                if (2..=10).contains(&opens) {
                    std::fs::File::open(&program)
                        .and_then(|file| {
                            file.set_modified(
                                std::time::UNIX_EPOCH
                                    + std::time::Duration::from_secs(1_000_000 + opens),
                            )
                        })
                        .expect("its time is set");
                }
                OpenedImage::open(&process)
            },
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(program.parent().expect("its directory"));
        let refused = result.expect_err("a reading that never held still is refused");
        assert!(refused.contains("kept changing"), "{refused}");
        assert_eq!(opens, 4, "three readings, each with its link opened again");
    }

    /// On macOS, two readings of the process's code-directory hash that differ (an exec between
    /// them) are taken again and only equal readings decide; readings that never agree are refused
    /// after three attempts, where a check that tried without end would see them settle and pass.
    #[cfg(target_os = "macos")]
    #[test]
    fn readings_that_differ_are_taken_again() {
        let me = kr_ipc::identity::current_process_start_identity().expect("this process");
        let hashed = ExecutableIdentity {
            hashed: HashedFile {
                file: FileIdentity {
                    device: 0,
                    inode: 0,
                    size: 0,
                    modified_ns: 0,
                    changed_ns: 0,
                },
                digest: Digest256::from_bytes([0; 32]),
                code_directories: vec![[1; 20]],
            },
            version: None,
        };
        let mut readings = [[1; 20], [2; 20], [1; 20], [1; 20]].into_iter();
        verify_reading(&me, &hashed, || Ok(readings.next().expect("a reading")))
            .expect("an exec between two readings, then equal readings of the hashed code");
        let mut readings = [[1; 20], [2; 20], [2; 20], [2; 20]].into_iter();
        let refused = verify_reading(&me, &hashed, || Ok(readings.next().expect("a reading")))
            .expect_err("equal readings of other code");
        assert!(refused.contains("other code"), "{refused}");
        let mut count = 0_u8;
        let refused = verify_reading(&me, &hashed, || {
            count += 1;
            Ok(if count <= 6 { [count + 1; 20] } else { [1; 20] })
        })
        .expect_err("readings that never agree");
        assert!(refused.contains("kept changing"), "{refused}");
        assert_eq!(count, 6, "three attempts of two readings");
    }

    #[test]
    fn a_script_is_not_an_executable_this_host_holds() {
        let directory = std::env::temp_dir().join(format!("kr-script-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let script = directory.join("claude");
        std::fs::write(&script, b"#!/bin/sh\nexec true\n").expect("a script");
        let cache = HashedFiles::default();
        let refused = read_identity(&script, &cache, &AtomicBool::new(false))
            .expect_err("a script is refused");
        assert!(refused.contains("script"), "{refused}");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A thin Mach-O of one 4096-byte page and an embedded signature after it, whose code directory
    /// has one code slot per `slots` entry (the page's own hash, or another), each slot entry
    /// placed at the directory offsets `at`.
    #[cfg(target_os = "macos")]
    fn signed(page_hash: Option<[u8; 32]>, at: &[u32]) -> (Vec<u8>, [u8; 20]) {
        use sha2::Digest as _;
        let mut file = vec![0_u8; 4096];
        file[0..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        file[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        file[12..16].copy_from_slice(&2_u32.to_le_bytes());
        file[16..20].copy_from_slice(&1_u32.to_le_bytes());
        file[20..24].copy_from_slice(&16_u32.to_le_bytes());
        file[32..36].copy_from_slice(&0x1d_u32.to_le_bytes());
        file[36..40].copy_from_slice(&16_u32.to_le_bytes());
        file[40..44].copy_from_slice(&4096_u32.to_le_bytes());
        let hash = page_hash.unwrap_or_else(|| sha2::Sha256::digest(&file).into());
        let mut directory = Vec::new();
        directory.extend_from_slice(&0xfade_0c02_u32.to_be_bytes());
        directory.extend_from_slice(&(44_u32 + 32).to_be_bytes());
        directory.extend_from_slice(&0x2_0001_u32.to_be_bytes());
        directory.extend_from_slice(&0_u32.to_be_bytes());
        directory.extend_from_slice(&44_u32.to_be_bytes());
        directory.extend_from_slice(&0_u32.to_be_bytes());
        directory.extend_from_slice(&0_u32.to_be_bytes());
        directory.extend_from_slice(&1_u32.to_be_bytes());
        directory.extend_from_slice(&4096_u32.to_be_bytes());
        directory.extend_from_slice(&[32, 2, 0, 12]);
        directory.extend_from_slice(&0_u32.to_be_bytes());
        directory.extend_from_slice(&hash);
        let entries = u32::try_from(at.len()).expect("few");
        let header = 12 + 8 * entries;
        let mut signature = Vec::new();
        signature.extend_from_slice(&0xfade_0cc0_u32.to_be_bytes());
        signature.extend_from_slice(&(header + 76).to_be_bytes());
        signature.extend_from_slice(&entries.to_be_bytes());
        for offset in at {
            signature.extend_from_slice(&0_u32.to_be_bytes());
            signature.extend_from_slice(&(header + offset).to_be_bytes());
        }
        signature.extend_from_slice(&directory);
        let size = u32::try_from(signature.len()).expect("small");
        file[44..48].copy_from_slice(&size.to_le_bytes());
        // The load command's data size is part of the page the directory hashes.
        let hash = page_hash.unwrap_or_else(|| sha2::Sha256::digest(&file).into());
        let slot = signature.len() - 32;
        signature[slot..].copy_from_slice(&hash);
        let cd_start = usize::try_from(header).expect("small");
        let own: [u8; 32] = sha2::Sha256::digest(&signature[cd_start..cd_start + 76]).into();
        file.extend_from_slice(&signature);
        (file, own[..20].try_into().expect("20 bytes"))
    }

    #[cfg(target_os = "macos")]
    fn written(bytes: &[u8]) -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!("kr-signed-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let path = directory.join("program");
        std::fs::write(&path, bytes).expect("written");
        (directory, path)
    }

    /// A code directory whose slot matches its page is kept, and its hash is the directory's own.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_code_directory_that_matches_its_pages_is_kept() {
        let (file, hash) = signed(None, &[0]);
        let (directory, path) = written(&file);
        let read =
            read_identity(&path, &HashedFiles::default(), &AtomicBool::new(false)).expect("read");
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(read.code_directories, vec![hash]);
    }

    /// A code directory whose slot is not its page's hash, as in a file carrying another file's
    /// directory, is not kept.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_code_directory_that_does_not_match_its_pages_is_not_kept() {
        let (file, _) = signed(Some([7; 32]), &[0]);
        let (directory, path) = written(&file);
        let read =
            read_identity(&path, &HashedFiles::default(), &AtomicBool::new(false)).expect("read");
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            read.code_directories.is_empty(),
            "{:?}",
            read.code_directories
        );
    }

    /// A signature that names the same slot twice is malformed, and nothing of it is kept: no
    /// directory is hashed more than once however many entries name it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_signature_that_repeats_a_slot_yields_nothing() {
        let (file, _) = signed(None, &[0; 40]);
        let (directory, path) = written(&file);
        let read =
            read_identity(&path, &HashedFiles::default(), &AtomicBool::new(false)).expect("read");
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            read.code_directories.is_empty(),
            "{:?}",
            read.code_directories
        );
    }

    /// One changed byte in the code of bash's arm64e slice, the rest of the file as it is: that
    /// slice's directory is no longer kept, and the other slice's still is.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_changed_page_drops_only_its_slice_s_directory() {
        let original = identity_of(Path::new("/bin/bash")).hashed.code_directories;
        let mut bytes = std::fs::read("/bin/bash").expect("bash");
        let count =
            usize::try_from(u32::from_be_bytes(bytes[4..8].try_into().expect("4"))).expect("count");
        let arm = (0..count)
            .map(|slice| 8 + slice * 20)
            .find(|at| {
                u32::from_be_bytes(bytes[*at..*at + 4].try_into().expect("4")) == 0x0100_000c
            })
            .expect("an arm64 slice");
        let offset = usize::try_from(u32::from_be_bytes(
            bytes[arm + 8..arm + 12].try_into().expect("4"),
        ))
        .expect("offset");
        // A byte inside the slice's first page, in its load commands.
        bytes[offset + 40] ^= 0xff;
        let (directory, path) = written(&bytes);
        let read =
            read_identity(&path, &HashedFiles::default(), &AtomicBool::new(false)).expect("read");
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(original.len(), 2, "bash is universal: {original:?}");
        assert_eq!(
            read.code_directories.len(),
            1,
            "{:?}",
            read.code_directories
        );
        assert!(original.contains(&read.code_directories[0]));
    }

    /// The hashes read from a universal file's own signature include the one `codesign` names for
    /// this machine's slice.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_signature_s_code_directory_hashes_are_the_ones_codesign_names() {
        let named = std::process::Command::new("codesign")
            .args(["-d", "-vvv", "/bin/bash"])
            .output()
            .expect("codesign runs");
        let text = String::from_utf8_lossy(&named.stderr);
        let expected = text
            .lines()
            .find_map(|line| line.strip_prefix("CDHash="))
            .expect("codesign names a hash")
            .trim()
            .to_owned();
        let read: Vec<String> = identity_of(Path::new("/bin/bash"))
            .hashed
            .code_directories
            .iter()
            .map(|hash| hash.iter().map(|byte| format!("{byte:02x}")).collect())
            .collect();
        assert!(read.contains(&expected), "{expected} in {read:?}");
    }
}
