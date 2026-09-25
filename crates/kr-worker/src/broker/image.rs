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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;

/// How many times the identity of a file that changed while it was read is read again.
const IDENTITY_ATTEMPTS: usize = 3;

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
pub(crate) fn read_identity(path: &Path, cache: &HashedFiles) -> Result<HashedFile, String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    for _ in 0..IDENTITY_ATTEMPTS {
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let before = file
            .metadata()
            .map(|metadata| FileIdentity::of(&metadata))
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let cached = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&before)
            .cloned();
        if let Some(hashed) = cached {
            return Ok(hashed);
        }
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0_u8; 1 << 20];
        let mut first = true;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
            if read == 0 {
                break;
            }
            let chunk = buffer.get(..read).unwrap_or_default();
            if first && chunk.starts_with(b"#!") {
                return Err(format!(
                    "{} is a script, and the program it runs is its interpreter",
                    path.display()
                ));
            }
            first = false;
            hasher.update(chunk);
        }
        let code_directories = code_directories_of(&file);
        let after = file
            .metadata()
            .map(|metadata| FileIdentity::of(&metadata))
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        if before != after {
            continue;
        }
        let hashed = HashedFile {
            file: before,
            digest: Digest256::from_bytes(hasher.finalize().into()),
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

#[cfg(target_os = "macos")]
fn code_directories_of(file: &std::fs::File) -> Vec<CodeDirectoryHash> {
    code_signature::read(file)
}

#[cfg(not(target_os = "macos"))]
const fn code_directories_of(_file: &std::fs::File) -> Vec<CodeDirectoryHash> {
    Vec::new()
}

/// Checks, from the kernel's record of the process's main executable, that a registered process
/// executes the file object that was hashed.
///
/// Linux compares the whole identity of `/proc/<pid>/exe`, change time included, so a rewrite of
/// the same inode after it was hashed does not pass.
///
/// # Errors
///
/// Returns why the process does not execute it, or why that could not be established.
#[cfg(target_os = "linux")]
pub fn verify_image(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let link = format!("/proc/{}/exe", process.pid.get());
    let executed = std::fs::metadata(&link).map_err(|error| {
        format!(
            "the image of process {} cannot be read: {error}",
            process.pid
        )
    })?;
    let same = FileIdentity::of(&executed) == identity.hashed.file;
    still_registered(process)?;
    if same {
        Ok(())
    } else {
        Err(format!(
            "process {} executes another file than the one its launch presented",
            process.pid
        ))
    }
}

/// Checks, from the kernel's record of the process's main executable, that a registered process
/// executes the code that was hashed.
///
/// macOS compares the code-directory hash the kernel keeps for the process's main executable with
/// the ones the hashed file's own signature carries.
///
/// # Errors
///
/// Returns why the process does not execute it, or why that could not be established.
#[cfg(target_os = "macos")]
pub fn verify_image(
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let pid = i32::try_from(process.pid.get())
        .map_err(|_| format!("{} is not a process identifier", process.pid))?;
    let running = code_signature::of_process(pid)?;
    still_registered(process)?;
    if identity.hashed.code_directories.contains(&running) {
        Ok(())
    } else {
        Err(format!(
            "process {} executes other code than the file its launch presented",
            process.pid
        ))
    }
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
    /// The code directory's hash type, and the types whose hash this reads.
    const HASH_TYPE_OFFSET: usize = 37;
    const CS_HASHTYPE_SHA256: u8 = 2;
    const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
    const CS_HASHTYPE_SHA384: u8 = 4;
    /// `csops`'s operation that reads the code-directory hash of a process's main executable.
    const CS_OPS_CDHASH: u32 = 5;
    /// Bounds on what is read from a file that may not be what it claims.
    const MAX_SLICES: usize = 16;
    const MAX_LOAD_COMMANDS_BYTES: usize = 1 << 20;
    const MAX_SIGNATURE_BYTES: usize = 64 << 20;

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

    /// Reads the code-directory hashes of every slice of a Mach-O file, or none for a file that is
    /// not one or carries no signature.
    pub(super) fn read(file: &std::fs::File) -> Vec<CodeDirectoryHash> {
        let mut hashes = Vec::new();
        let Some(header) = read_at(file, 0, 8) else {
            return hashes;
        };
        match be32(&header, 0) {
            Some(FAT_MAGIC) => {
                let slices = be32(&header, 4)
                    .and_then(to_usize)
                    .unwrap_or(0)
                    .min(MAX_SLICES);
                if let Some(records) = read_at(file, 8, slices * 20) {
                    for slice in 0..slices {
                        if let Some(offset) = be32(&records, slice * 20 + 8) {
                            read_slice(file, u64::from(offset), &mut hashes);
                        }
                    }
                }
            }
            Some(FAT_MAGIC_64) => {
                let slices = be32(&header, 4)
                    .and_then(to_usize)
                    .unwrap_or(0)
                    .min(MAX_SLICES);
                if let Some(records) = read_at(file, 8, slices * 32) {
                    for slice in 0..slices {
                        if let Some(offset) = be64(&records, slice * 32 + 8) {
                            read_slice(file, offset, &mut hashes);
                        }
                    }
                }
            }
            _ => read_slice(file, 0, &mut hashes),
        }
        hashes
    }

    /// Reads the code-directory hashes of one slice starting at `base`.
    fn read_slice(file: &std::fs::File, base: u64, hashes: &mut Vec<CodeDirectoryHash>) {
        let Some(header) = read_at(file, base, 28) else {
            return;
        };
        let header_size: u64 = match le32(&header, 0) {
            Some(MH_MAGIC_64) => 32,
            Some(MH_MAGIC) => 28,
            _ => return,
        };
        let (Some(commands), Some(length)) = (
            le32(&header, 16).and_then(to_usize),
            le32(&header, 20).and_then(to_usize),
        ) else {
            return;
        };
        if length > MAX_LOAD_COMMANDS_BYTES {
            return;
        }
        let Some(loaded) = base
            .checked_add(header_size)
            .and_then(|at| read_at(file, at, length))
        else {
            return;
        };
        let mut at = 0_usize;
        for _ in 0..commands {
            let (Some(command), Some(size)) =
                (le32(&loaded, at), le32(&loaded, at + 4).and_then(to_usize))
            else {
                return;
            };
            if size < 8 {
                return;
            }
            if command == LC_CODE_SIGNATURE {
                let (Some(offset), Some(size)) = (
                    le32(&loaded, at + 8),
                    le32(&loaded, at + 12).and_then(to_usize),
                ) else {
                    return;
                };
                if size <= MAX_SIGNATURE_BYTES
                    && let Some(signature) = base
                        .checked_add(u64::from(offset))
                        .and_then(|at| read_at(file, at, size))
                {
                    read_signature(&signature, hashes);
                }
                return;
            }
            at = match at.checked_add(size) {
                Some(next) => next,
                None => return,
            };
        }
    }

    /// Hashes each code directory an embedded signature holds, in the primary or an alternate slot.
    fn read_signature(signature: &[u8], hashes: &mut Vec<CodeDirectoryHash>) {
        use sha2::Digest as _;
        if be32(signature, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
            return;
        }
        let count = be32(signature, 8).and_then(to_usize).unwrap_or(0);
        for index in 0..count.min(signature.len() / 8) {
            let (Some(slot), Some(offset)) = (
                be32(signature, 12 + index * 8),
                be32(signature, 16 + index * 8).and_then(to_usize),
            ) else {
                return;
            };
            if slot != CSSLOT_CODEDIRECTORY && !CSSLOT_ALTERNATE_CODEDIRECTORIES.contains(&slot) {
                continue;
            }
            if be32(signature, offset) != Some(CSMAGIC_CODEDIRECTORY) {
                continue;
            }
            let Some(directory) = be32(signature, offset + 4)
                .and_then(to_usize)
                .and_then(|length| signature.get(offset..offset.checked_add(length)?))
            else {
                continue;
            };
            let full: Vec<u8> = match directory.get(HASH_TYPE_OFFSET).copied() {
                Some(CS_HASHTYPE_SHA256 | CS_HASHTYPE_SHA256_TRUNCATED) => {
                    sha2::Sha256::digest(directory).to_vec()
                }
                Some(CS_HASHTYPE_SHA384) => sha2::Sha384::digest(directory).to_vec(),
                // A SHA-1 code directory is never the one the kernel keeps when a SHA-256 one is
                // there, and a signature with only SHA-1 is refused.
                _ => continue,
            };
            if let Some(hash) = full
                .get(..20)
                .and_then(|hash| CodeDirectoryHash::try_from(hash).ok())
            {
                hashes.push(hash);
            }
        }
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

    fn identity_of(path: &Path) -> ExecutableIdentity {
        let cache = HashedFiles::default();
        ExecutableIdentity {
            hashed: read_identity(path, &cache).expect("its identity is read"),
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
        verify_image(&me, &identity).expect("this process executes its own executable");
        let other = identity_of(Path::new("/bin/sh"));
        assert!(
            verify_image(&me, &other).is_err(),
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
        let result = verify_image(&process, &bash);
        let other = verify_image(
            &process,
            &identity_of(&std::env::current_exe().expect("exe")),
        );
        let _ = child.kill();
        let _ = child.wait();
        result.expect("the child executes bash");
        assert!(other.is_err(), "and not this test's executable");
    }

    #[test]
    fn a_script_is_not_an_executable_this_host_holds() {
        let directory = std::env::temp_dir().join(format!("kr-script-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let script = directory.join("claude");
        std::fs::write(&script, b"#!/bin/sh\nexec true\n").expect("a script");
        let cache = HashedFiles::default();
        let refused = read_identity(&script, &cache).expect_err("a script is refused");
        assert!(refused.contains("script"), "{refused}");
        let _ = std::fs::remove_dir_all(&directory);
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
