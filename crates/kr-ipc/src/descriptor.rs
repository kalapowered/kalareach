//! Publishing, reading and retiring worker descriptors.
//!
//! A descriptor is how the `kr` command line reaches a worker while the control daemon is
//! restarting. It is published atomically, owner-only, and carries no secret. What it carries is
//! the worker's public key, which is the only part a reader may act on before a challenge: the
//! filename, the endpoint path and the process identifier inside it are hints, and a client that
//! trusted them could be sent anywhere by a file someone else wrote.
//!
//! Retirement removes the file. A closed session's descriptor is gone, so a reader gets the
//! closure record from the registry rather than an endpoint that might start something.

use std::path::Path;

use kr_protocol::ids::SessionId;
use kr_protocol::worker::WorkerDescriptor;

use crate::error::{IpcError, Result};
use crate::paths::{EnvironmentPaths, write_owner_only_file};

/// The largest descriptor this host will read.
///
/// A descriptor is a few hundred bytes. The bound exists so a reader cannot be made to allocate by
/// a file that claims to be one.
pub const MAX_DESCRIPTOR_LEN: u64 = 16 * 1024;

/// Writes a descriptor into the runtime directory, replacing any previous version atomically.
///
/// # Errors
///
/// Returns an error when the descriptor cannot be encoded or the file cannot be published.
pub fn publish(paths: &EnvironmentPaths, descriptor: &WorkerDescriptor) -> Result<()> {
    let bytes = kr_cbor::to_canonical_vec(descriptor)
        .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))?;
    let path = paths.descriptor_file(descriptor.session_id);
    write_owner_only_file(&path, &bytes)
}

/// Reads one session's descriptor, or `None` when there is none.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or is not a canonical descriptor.
pub fn read(paths: &EnvironmentPaths, session_id: SessionId) -> Result<Option<WorkerDescriptor>> {
    let path = paths.descriptor_file(session_id);
    let Some(directory) = DescriptorDirectory::open(&paths.descriptors_dir())? else {
        return Ok(None);
    };
    let Some(descriptor) = directory.read_entry(&path)? else {
        return Ok(None);
    };
    check_identity(&path, &descriptor, Some(session_id), paths.environment_id())?;
    Ok(Some(descriptor))
}

/// Checks a descriptor's contents against the name and directory it was found under.
///
/// The filename is a hint. A descriptor whose contents name a different session or environment is
/// not this session's descriptor, whatever it is called, and this runs wherever a descriptor is
/// read: one file by name, or every file in the directory.
fn check_identity(
    path: &Path,
    descriptor: &WorkerDescriptor,
    named: Option<SessionId>,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Result<()> {
    match named {
        Some(named) if descriptor.session_id != named => {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "the descriptor names a different session from its filename",
            });
        }
        Some(_) => {}
        None => {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor file is named after the session it describes",
            });
        }
    }
    if descriptor.environment_id != environment_id {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "the descriptor names a different environment from its directory",
        });
    }
    Ok(())
}

/// Reads the session identity a descriptor file's name claims.
fn named_session(path: &Path) -> Option<SessionId> {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|stem| stem.parse::<kr_protocol::scalars::Uuid>().ok())
        .map(SessionId::new)
}

/// Reads every descriptor currently published for an environment.
///
/// A file that cannot be parsed is reported rather than skipped silently: a descriptor directory
/// the host cannot read completely is a fact the caller has to act on.
///
/// # Errors
///
/// Returns an error when the directory cannot be listed.
pub fn read_all(paths: &EnvironmentPaths) -> Result<Vec<DescriptorEntry>> {
    let directory = paths.descriptors_dir();
    let Some(handle) = DescriptorDirectory::open(&directory)? else {
        return Ok(Vec::new());
    };
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(IpcError::io("list", directory, error)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| IpcError::io("list", &directory, error))?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "kr") {
            continue;
        }
        // Enumeration performs exactly the checks a read by name performs. A directory listing is
        // not a warrant to trust a file that a direct read would have refused.
        let outcome = handle
            .read_entry(&path)
            .and_then(|descriptor| match descriptor {
                Some(descriptor) => {
                    check_identity(
                        &path,
                        &descriptor,
                        named_session(&path),
                        paths.environment_id(),
                    )?;
                    Ok(Some(descriptor))
                }
                None => Ok(None),
            });
        match outcome {
            Ok(Some(descriptor)) => found.push(DescriptorEntry {
                path: path.clone(),
                descriptor: Ok(descriptor),
            }),
            Ok(None) => {}
            Err(error) => found.push(DescriptorEntry {
                path: path.clone(),
                descriptor: Err(error.to_string()),
            }),
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

/// One descriptor file and what reading it produced.
#[derive(Debug)]
pub struct DescriptorEntry {
    /// The file.
    pub path: std::path::PathBuf,
    /// The descriptor, or why the file could not be read.
    pub descriptor: std::result::Result<WorkerDescriptor, String>,
}

/// Removes a session's descriptor.
///
/// Removing one that is already gone succeeds: retirement is idempotent, and a controller that
/// crashed part way through should be able to finish.
///
/// # Errors
///
/// Returns an error when the file exists and cannot be removed.
pub fn retire(paths: &EnvironmentPaths, session_id: SessionId) -> Result<()> {
    let path = paths.descriptor_file(session_id);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(IpcError::io("retire", path, error)),
    }
}

/// Reads a descriptor file that this user owns, is not a link, and is small enough to be one.
///
/// The public key inside a descriptor decides which worker a client will trust, so the file has to
/// be one this host wrote. A symbolic link, another user's file or a file with group or other
/// permissions is refused: a challenge cannot save a reader that was pointed at an impostor's
/// endpoint *and* handed the impostor's key.
/// A verified handle on the directory descriptors are published in.
///
/// Every descriptor is opened relative to this handle rather than by its full path. Resolving a
/// path component by component gives each parent directory a chance to change between the check
/// and the open; a handle names the directory that was checked, and keeps naming it.
#[derive(Debug)]
pub struct DescriptorDirectory {
    #[cfg(unix)]
    handle: std::os::fd::OwnedFd,
    path: std::path::PathBuf,
}

impl DescriptorDirectory {
    /// Opens and checks the directory, or returns `None` when there is none yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be opened, is a link, or is reachable by anyone
    /// but this user.
    #[cfg(unix)]
    pub fn open(path: &Path) -> Result<Option<Self>> {
        use rustix::fs::{Mode, OFlags};

        let handle = match rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(handle) => handle,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::MLINK) => {
                return Err(IpcError::UntrustedFile {
                    path: path.to_path_buf(),
                    reason: "a descriptor directory must not be a symbolic link",
                });
            }
            Err(error) => return Err(IpcError::io("open", path, std::io::Error::from(error))),
        };
        let metadata = rustix::fs::fstat(&handle)
            .map_err(|error| IpcError::io("inspect", path, std::io::Error::from(error)))?;
        if metadata.st_uid != crate::paths::current_uid() {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor directory must be owned by this user",
            });
        }
        if u32::from(metadata.st_mode) & 0o077 != 0 {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor directory must not be reachable by anyone else",
            });
        }
        Ok(Some(Self {
            handle,
            path: path.to_path_buf(),
        }))
    }

    /// Opens and checks the directory, or returns `None` when there is none yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be inspected.
    #[cfg(not(unix))]
    pub fn open(path: &Path) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(Some(Self {
                path: path.to_path_buf(),
            })),
            Ok(_) => Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor directory must be a directory",
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(IpcError::io("inspect", path, error)),
        }
    }

    /// Returns the directory this handle names.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads one descriptor from inside this directory.
    ///
    /// The public key inside a descriptor decides which worker a client will trust, so the file has
    /// to be one this host wrote: not a symbolic link, not another user's file, not one with group
    /// or other permissions, and not larger than any descriptor this host writes. A challenge
    /// cannot save a reader that was pointed at an impostor's endpoint *and* handed the impostor's
    /// key.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists but is not a descriptor this host would trust.
    pub fn read_entry(&self, path: &Path) -> Result<Option<WorkerDescriptor>> {
        use std::io::Read as _;

        let Some(file) = self.open_entry(path)? else {
            return Ok(None);
        };
        let metadata = file
            .metadata()
            .map_err(|error| IpcError::io("inspect", path, error))?;
        if !metadata.is_file() {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor must be a regular file",
            });
        }
        clear_non_blocking(&file, path)?;
        if metadata.len() > MAX_DESCRIPTOR_LEN {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor is larger than any descriptor this host writes",
            });
        }
        check_owner(path, &metadata)?;
        let mut bytes = Vec::new();
        // Bounded by one byte more than the maximum, so a file that grew between the check and the
        // read is refused rather than read.
        file.take(MAX_DESCRIPTOR_LEN + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| IpcError::io("read", path, error))?;
        if bytes.len() as u64 > MAX_DESCRIPTOR_LEN {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "a descriptor is larger than any descriptor this host writes",
            });
        }
        kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
            .map(Some)
            .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))
    }

    #[cfg(unix)]
    fn open_entry(&self, path: &Path) -> Result<Option<std::fs::File>> {
        use rustix::fs::{Mode, OFlags};

        let name = path.file_name().ok_or_else(|| IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "a descriptor is a file inside the descriptor directory",
        })?;
        // Three flags, each refusing something a check on the path could not refuse without a
        // race. `O_NOFOLLOW` refuses a symbolic link at the open itself. `O_NONBLOCK` refuses to
        // wait, so a named pipe left here cannot hold a daemon's directory rebuild open until
        // somebody writes to it. `O_CLOEXEC` keeps the handle out of anything started later.
        match rustix::fs::openat(
            &self.handle,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => Ok(Some(std::fs::File::from(descriptor))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            // A symbolic link reports `ELOOP` on Linux and `EMLINK` on the BSDs, including macOS.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::MLINK) => {
                Err(IpcError::UntrustedFile {
                    path: path.to_path_buf(),
                    reason: "a descriptor must not be a symbolic link",
                })
            }
            Err(error) => Err(IpcError::io("open", path, std::io::Error::from(error))),
        }
    }

    #[cfg(not(unix))]
    fn open_entry(&self, path: &Path) -> Result<Option<std::fs::File>> {
        use std::os::windows::fs::OpenOptionsExt as _;

        // Windows refuses to open a reparse point when the flag is set, which covers the symbolic
        // links and junctions a planted descriptor could use.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(IpcError::io("open", path, error)),
        }
    }
}

#[cfg(unix)]
fn clear_non_blocking(file: &std::fs::File, path: &Path) -> Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let flags = fcntl_getfl(file)
        .map_err(|error| IpcError::io("inspect", path, std::io::Error::from(error)))?;
    fcntl_setfl(file, flags - OFlags::NONBLOCK)
        .map_err(|error| IpcError::io("inspect", path, std::io::Error::from(error)))
}

#[cfg(not(unix))]
const fn clear_non_blocking(_file: &std::fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_owner(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.uid() != crate::paths::current_uid() {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "a descriptor must be owned by this user",
        });
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "a descriptor must not be readable or writable by anyone else",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    // The Windows qualification pass adds the explicit protected access-control list check here;
    // the directory lives inside the user's own profile.
    Ok(())
}

#[cfg(test)]
mod tests {
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::identity::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
    };
    use kr_protocol::ids::SessionEpoch;
    use kr_protocol::scalars::{AuthorisationKey, Bytes, TimestampMs};
    use kr_protocol::session::DisplayNumber;

    use super::*;
    use crate::testing::TempHost;

    fn descriptor(host: &TempHost, session: u8) -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: SessionId::new(kr_protocol::scalars::Uuid::from_bytes([session; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: DisplayNumber::new(u64::from(session)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"boot".to_vec()),
            },
            process_start_identity: ProcessStartIdentity::new(
                42,
                ProcessStartSource::LinuxProcStat,
                99,
            ),
            protocol_version: PROTOCOL_VERSION,
            endpoint: "/run/w1.sock".to_owned(),
            worker_public_key: AuthorisationKey::from_bytes([session; 32]),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_descriptor_round_trips_and_is_owner_only() {
        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 1);
        publish(&paths, &published).expect("publishes");
        let read_back = read(&paths, published.session_id)
            .expect("reads")
            .expect("present");
        assert_eq!(read_back, published);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(paths.descriptor_file(published.session_id))
                .expect("metadata")
                .mode()
                & 0o777;
            assert_eq!(mode, crate::paths::OWNER_ONLY_FILE_MODE);
        }
    }

    #[test]
    fn republishing_replaces_the_previous_version() {
        let host = TempHost::create();
        let paths = host.environment();
        let mut published = descriptor(&host, 2);
        publish(&paths, &published).expect("publishes");
        published.endpoint = "/run/w2.sock".to_owned();
        publish(&paths, &published).expect("republishes");
        let read_back = read(&paths, published.session_id)
            .expect("reads")
            .expect("present");
        assert_eq!(read_back.endpoint, "/run/w2.sock");
        assert_eq!(read_all(&paths).expect("lists").len(), 1);
    }

    #[test]
    fn a_retired_descriptor_is_gone_and_retiring_again_succeeds() {
        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 3);
        publish(&paths, &published).expect("publishes");
        retire(&paths, published.session_id).expect("retires");
        assert!(read(&paths, published.session_id).expect("reads").is_none());
        retire(&paths, published.session_id).expect("retiring again succeeds");
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_another_user_could_write_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 6);
        publish(&paths, &published).expect("publishes");
        let file = paths.descriptor_file(published.session_id);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let error = read(&paths, published.session_id).expect_err("refuses");
        assert!(matches!(error, IpcError::UntrustedFile { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_that_is_a_symbolic_link_is_refused() {
        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 7);
        publish(&paths, &published).expect("publishes");
        let real = paths.descriptor_file(published.session_id);
        let planted = descriptor(&host, 8);
        let link = paths.descriptor_file(planted.session_id);
        std::os::unix::fs::symlink(&real, &link).expect("links");
        let error = read(&paths, planted.session_id).expect_err("refuses");
        assert!(matches!(error, IpcError::UntrustedFile { .. }));
    }

    #[test]
    fn a_descriptor_whose_contents_name_another_session_is_refused() {
        let host = TempHost::create();
        let paths = host.environment();
        let mut published = descriptor(&host, 9);
        let filename_session = published.session_id;
        published.session_id = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([200; 16]));
        let bytes = kr_cbor::to_canonical_vec(&published).expect("encodes");
        crate::paths::write_owner_only_file(&paths.descriptor_file(filename_session), &bytes)
            .expect("writes");
        let error = read(&paths, filename_session).expect_err("refuses");
        assert!(matches!(error, IpcError::UntrustedFile { .. }));
    }

    #[test]
    fn enumeration_refuses_a_descriptor_a_direct_read_would_refuse() {
        let host = TempHost::create();
        let paths = host.environment();
        let mut planted = descriptor(&host, 11);
        let filename_session = planted.session_id;
        // The file is named after one session and describes another. A reader that trusted the
        // listing would take the contents; a reader that performs the same checks does not.
        planted.session_id = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([201; 16]));
        let bytes = kr_cbor::to_canonical_vec(&planted).expect("encodes");
        crate::paths::write_owner_only_file(&paths.descriptor_file(filename_session), &bytes)
            .expect("writes");
        let entries = read_all(&paths).expect("lists");
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].descriptor.is_err(),
            "enumeration applies the identity checks a read by name applies"
        );
    }

    #[test]
    fn enumeration_refuses_a_descriptor_from_another_environment() {
        let host = TempHost::create();
        let paths = host.environment();
        let mut planted = descriptor(&host, 12);
        planted.environment_id =
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([77; 16]));
        let bytes = kr_cbor::to_canonical_vec(&planted).expect("encodes");
        crate::paths::write_owner_only_file(&paths.descriptor_file(planted.session_id), &bytes)
            .expect("writes");
        let entries = read_all(&paths).expect("lists");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].descriptor.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_in_the_descriptor_directory_does_not_hold_a_reader() {
        let host = TempHost::create();
        let paths = host.environment();
        publish(&paths, &descriptor(&host, 13)).expect("publishes");
        let pipe = paths.descriptors_dir().join("waiting.kr");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("runs mkfifo");
        assert!(made.success(), "creates a named pipe");
        // Nothing will ever write to it. Reading the directory must still finish.
        let entries = read_all(&paths).expect("lists");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.descriptor.is_err())
                .count(),
            1,
            "the pipe is reported as a file this host will not trust"
        );
        std::fs::remove_file(&pipe).ok();
    }

    #[test]
    fn an_unreadable_descriptor_is_reported_rather_than_skipped() {
        let host = TempHost::create();
        let paths = host.environment();
        publish(&paths, &descriptor(&host, 4)).expect("publishes");
        let broken = paths.descriptors_dir().join("broken.kr");
        crate::paths::write_owner_only_file(&broken, b"not canonical cbor").expect("writes");
        let entries = read_all(&paths).expect("lists");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.iter().filter(|e| e.descriptor.is_err()).count(),
            1,
            "the unreadable file is listed with its failure"
        );
    }
}
