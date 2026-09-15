//! Runtime and state directories, and the endpoints inside them.
//!
//! Two directories serve different jobs. The **runtime** directory holds what only makes sense
//! while the host is running: the control socket, the rendezvous socket, each worker's private
//! endpoint and the published worker descriptors. The **state** directory holds what must survive
//! a reboot: the controller registry, each worker's journal and its output spool. Both are
//! owner-only, and both are checked rather than assumed on every open.
//!
//! Unix socket addresses are short. The kernel copies the path into a fixed `sun_path` array of
//! 104 bytes on macOS and 108 on Linux, and a longer path fails at bind time with an error that
//! says nothing useful. Endpoint names here are therefore deliberately terse — an eight-character
//! environment prefix and a display number — and [`EnvironmentPaths`] checks the length itself so
//! the failure names the limit.

use std::path::{Path, PathBuf};

use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::DisplayNumber;

use crate::error::{IpcError, Result};

/// Environment variable that replaces the default runtime root.
pub const RUNTIME_DIR_VARIABLE: &str = "KR_RUNTIME_DIR";

/// Environment variable that replaces the default state root.
pub const STATE_DIR_VARIABLE: &str = "KR_STATE_DIR";

/// The permission bits every KalaReach directory carries.
pub const OWNER_ONLY_DIRECTORY_MODE: u32 = 0o700;

/// The permission bits every KalaReach file carries.
pub const OWNER_ONLY_FILE_MODE: u32 = 0o600;

/// The longest socket path this platform's address family accepts.
///
/// One byte of `sun_path` is the terminator, so the usable length is one less than the array.
#[cfg(target_os = "macos")]
pub const MAX_SOCKET_PATH_LEN: usize = 103;

/// The longest socket path this platform's address family accepts.
#[cfg(all(unix, not(target_os = "macos")))]
pub const MAX_SOCKET_PATH_LEN: usize = 107;

/// The longest endpoint name this platform accepts.
#[cfg(windows)]
pub const MAX_SOCKET_PATH_LEN: usize = 256;

/// The two directory roots one installation uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPaths {
    runtime_root: PathBuf,
    state_root: PathBuf,
}

impl HostPaths {
    /// Builds the roots from explicit paths.
    #[must_use]
    pub fn new(runtime_root: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self {
            runtime_root: runtime_root.into(),
            state_root: state_root.into(),
        }
    }

    /// Resolves the roots for the current user.
    ///
    /// `KR_RUNTIME_DIR` and `KR_STATE_DIR` replace the platform defaults outright. They exist so a
    /// test, a container image or a second installation can be given its own tree; nothing else
    /// changes when they are set.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::IdentityUnavailable`] when neither the platform default nor an override
    /// yields a usable directory.
    pub fn discover() -> Result<Self> {
        let runtime_root = match std::env::var_os(RUNTIME_DIR_VARIABLE) {
            Some(value) => PathBuf::from(value),
            None => default_runtime_root()?,
        };
        let state_root = match std::env::var_os(STATE_DIR_VARIABLE) {
            Some(value) => PathBuf::from(value),
            None => default_state_root()?,
        };
        Ok(Self::new(runtime_root, state_root))
    }

    /// Returns the runtime root.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Returns the state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the file that records this installation's environment identity.
    #[must_use]
    pub fn environment_id_file(&self) -> PathBuf {
        self.state_root.join("environment-id")
    }

    /// Reads this installation's environment identity, allocating one on first use.
    ///
    /// The identity binds one installation and one OS user. It is a random identifier, never a
    /// hardware fingerprint, and it is written once and then only read.
    ///
    /// # Errors
    ///
    /// Returns an error when the state root cannot be created or the file cannot be read or
    /// written.
    pub fn open_environment_id(&self) -> Result<EnvironmentId> {
        create_private_tree(&self.state_root, &self.state_root)?;
        let path = self.environment_id_file();
        // Creation must not replace: two first starts racing here would otherwise each rename
        // their own identity into place and walk away believing different answers, and the
        // per-environment singleton lock cannot undo a split that happened before it existed.
        // Exactly one caller creates the file; every other caller reads what that one wrote.
        match create_new_owner_only_file(
            &path,
            format!("{}\n", EnvironmentId::new(crate::new_uuid())).as_bytes(),
        ) {
            Ok(()) => {}
            Err(IpcError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let text =
            std::fs::read_to_string(&path).map_err(|error| IpcError::io("read", &path, error))?;
        text.trim()
            .parse::<Uuid>()
            .map(EnvironmentId::new)
            .map_err(|error| IpcError::IdentityUnavailable {
                what: "environment identity",
                detail: format!("{}: {error}", path.display()),
            })
    }

    /// Returns the directories one environment uses.
    #[must_use]
    pub fn environment(&self, environment_id: EnvironmentId) -> EnvironmentPaths {
        let prefix = short_prefix(environment_id);
        EnvironmentPaths {
            environment_id,
            runtime_root: self.runtime_root.clone(),
            state_root: self.state_root.clone(),
            runtime_dir: self.runtime_root.join(&prefix),
            state_dir: self.state_root.join("environments").join(&prefix),
        }
    }
}

/// The eight hexadecimal characters that name an environment's directories.
///
/// The full identity stays in the registry and in every descriptor. This prefix only has to be
/// short enough for a socket address and distinct enough for a directory name.
#[must_use]
pub fn short_prefix(environment_id: EnvironmentId) -> String {
    let bytes = environment_id.get();
    let bytes = bytes.as_bytes();
    let mut prefix = String::with_capacity(8);
    for byte in &bytes[..4] {
        prefix.push_str(&format!("{byte:02x}"));
    }
    prefix
}

/// Every path one environment uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentPaths {
    environment_id: EnvironmentId,
    runtime_root: PathBuf,
    state_root: PathBuf,
    runtime_dir: PathBuf,
    state_dir: PathBuf,
}

impl EnvironmentPaths {
    /// Returns the environment these paths belong to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Returns the state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Returns the runtime root these directories were derived from.
    ///
    /// A process that is given the roots can derive every environment's directories itself. A
    /// process given one environment's directory cannot, and would build the prefix twice.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Returns the state root these directories were derived from.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Creates every directory this environment needs, owner-only.
    ///
    /// # Errors
    ///
    /// Returns an error when a directory cannot be created, or when one already exists with wider
    /// permissions or a different owner.
    pub fn create(&self) -> Result<()> {
        for path in [&self.runtime_dir, &self.descriptors_dir()] {
            create_private_tree(&self.runtime_root, path)?;
        }
        for path in [
            &self.state_dir,
            &self.journals_dir(),
            &self.spool_dir(),
            &self.jobs_dir(),
            &self.secrets_dir(),
        ] {
            create_private_tree(&self.state_root, path)?;
        }
        // The directory name is an eight-character prefix, short enough for a socket address but
        // not unique. Each directory therefore carries the complete identity, and a second
        // environment whose identity shares that prefix is refused rather than allowed to open
        // another environment's registry, journals and sockets.
        self.claim_identity(&self.runtime_dir)?;
        self.claim_identity(&self.state_dir)
    }

    fn claim_identity(&self, directory: &Path) -> Result<()> {
        let marker = directory.join(ENVIRONMENT_MARKER);
        match std::fs::read_to_string(&marker) {
            Ok(text) => {
                let recorded = text.trim();
                if recorded == self.environment_id.to_string() {
                    Ok(())
                } else {
                    Err(IpcError::EnvironmentPrefixCollision {
                        path: directory.to_path_buf(),
                        holder: recorded.to_owned(),
                        requested: self.environment_id.to_string(),
                    })
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_owner_only_file(&marker, format!("{}\n", self.environment_id).as_bytes())
            }
            Err(error) => Err(IpcError::io("read", marker, error)),
        }
    }

    /// Returns the directory holding published worker descriptors.
    #[must_use]
    pub fn descriptors_dir(&self) -> PathBuf {
        self.runtime_dir.join("sessions")
    }

    /// Returns the descriptor file of one session.
    #[must_use]
    pub fn descriptor_file(&self, session_id: SessionId) -> PathBuf {
        self.descriptors_dir().join(format!("{session_id}.kr"))
    }

    /// Returns the controller's client endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the path does not fit the platform's socket
    /// address.
    pub fn controller_endpoint(&self) -> Result<Endpoint> {
        self.endpoint("c")
    }

    /// Returns the controller's owner-only rendezvous endpoint.
    ///
    /// Only a worker's startup handshake is accepted there.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the path does not fit the platform's socket
    /// address.
    pub fn rendezvous_endpoint(&self) -> Result<Endpoint> {
        self.endpoint("r")
    }

    /// Returns one worker's private endpoint.
    ///
    /// Display numbers are never reused within an environment, so the name identifies one worker
    /// for the life of the installation. It is still only a hint: a client proves which worker
    /// answers with a fresh challenge.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the path does not fit the platform's socket
    /// address.
    pub fn worker_endpoint(&self, display_number: DisplayNumber) -> Result<Endpoint> {
        self.endpoint(&format!("w{}", display_number.get()))
    }

    /// Returns the controller's singleton lock file.
    #[must_use]
    pub fn singleton_lock(&self) -> PathBuf {
        self.state_dir.join("controller.lock")
    }

    /// Returns the controller registry database.
    #[must_use]
    pub fn registry_database(&self) -> PathBuf {
        self.state_dir.join("registry.sqlite")
    }

    /// Returns the directory holding worker journals.
    #[must_use]
    pub fn journals_dir(&self) -> PathBuf {
        self.state_dir.join("sessions")
    }

    /// Returns one worker's private journal.
    #[must_use]
    pub fn journal_database(&self, session_id: SessionId) -> PathBuf {
        self.journals_dir()
            .join(format!("session-{session_id}.sqlite"))
    }

    /// Returns the directory holding output spools.
    #[must_use]
    pub fn spool_dir(&self) -> PathBuf {
        self.state_dir.join("spool")
    }

    /// Returns one session's output spool.
    #[must_use]
    pub fn session_spool(&self, session_id: SessionId) -> PathBuf {
        self.spool_dir().join(format!("{session_id}.log"))
    }

    /// Returns the directory holding generated per-session job definitions.
    #[must_use]
    pub fn jobs_dir(&self) -> PathBuf {
        self.state_dir.join("jobs")
    }

    /// Returns the directory the secret-store fallback writes to.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    #[cfg(unix)]
    fn endpoint(&self, role: &str) -> Result<Endpoint> {
        Endpoint::from_path(self.runtime_dir.join(format!("{role}.sock")))
    }

    #[cfg(windows)]
    fn endpoint(&self, role: &str) -> Result<Endpoint> {
        // A named pipe lives in the pipe namespace, not the filesystem, so the address is a name
        // rather than a path. It is scoped by the user and the environment for the same reason the
        // Unix socket lives in a per-user, per-environment directory.
        Endpoint::from_name(format!(
            "kalareach-{}-{}-{role}",
            current_uid(),
            short_prefix(self.environment_id)
        ))
    }
}

/// The address of one local endpoint.
///
/// On Unix this is a filesystem path inside the owner-only runtime directory. On Windows it is a
/// named-pipe name; the pipe namespace has no directory permissions to inherit, so the pipe
/// carries an owner-only access-control list instead.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint(PathBuf);

impl Endpoint {
    /// Wraps a path, checking it against the platform's address limit.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the path is too long to bind.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        // A descriptor carries this address as text. A path that is not valid UTF-8 would be
        // published in a different form from the one that was bound, so it is refused here rather
        // than quietly altered by a lossy conversion.
        if path.to_str().is_none() {
            return Err(IpcError::io(
                "bind",
                &path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "an endpoint path must be valid UTF-8",
                ),
            ));
        }
        let len = path.as_os_str().as_encoded_bytes().len();
        if len > MAX_SOCKET_PATH_LEN {
            return Err(IpcError::SocketPathTooLong {
                path,
                len,
                limit: MAX_SOCKET_PATH_LEN,
            });
        }
        Ok(Self(path))
    }

    /// Wraps a namespaced endpoint name.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the name is longer than the platform accepts.
    pub fn from_name(name: impl Into<String>) -> Result<Self> {
        Self::from_path(PathBuf::from(name.into()))
    }

    /// Returns the address as a path.
    ///
    /// On Windows this is the pipe name rather than a filesystem path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Returns the address as text, for a descriptor or a diagnostic.
    ///
    /// The constructor refused a path that is not valid UTF-8, so this is the exact address that
    /// was bound.
    #[must_use]
    pub fn as_text(&self) -> String {
        self.0
            .to_str()
            .expect("an endpoint path was checked for UTF-8 when it was built")
            .to_owned()
    }
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.as_text())
    }
}

/// The file that records which environment owns a directory whose name is only a prefix.
pub const ENVIRONMENT_MARKER: &str = "environment";

/// Creates a KalaReach directory tree owner-only, under a root this installation owns.
///
/// Only the root and the directories below it are KalaReach's. Their parents are not: `/tmp` is
/// world-writable by design, and `~/.cache` and `~/.local/state` are ordinarily group-readable.
/// Demanding 0700 of those would refuse to start on a perfectly normal system, so the boundary is
/// explicit: everything above `root` is created with the platform's ordinary permissions and
/// checked for nothing, and `root` itself and every component below it is created owner-only and
/// verified on every open.
///
/// # Errors
///
/// Returns an error when `path` is not inside `root`, when a directory cannot be created, or when
/// one exists with the wrong owner or wider permissions, or as a symbolic link.
pub fn create_private_tree(root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        IpcError::io(
            "create",
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the path is outside this installation's root",
            ),
        )
    })?;
    if let Some(parent) = root.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| IpcError::io("create", parent, error))?;
    }
    let mut current = root.to_path_buf();
    create_private_directory(&current)?;
    for component in relative.components() {
        current.push(component);
        create_private_directory(&current)?;
    }
    Ok(())
}

/// Creates one directory owner-only, or checks an existing one.
///
/// A directory that already exists with a different owner, wider permissions, or as a symbolic
/// link is an error rather than something to repair silently: the host cannot tell whether it was
/// widened by accident or by someone else, and both answers make the endpoints inside it
/// untrustworthy.
///
/// # Errors
///
/// Returns an error when the directory cannot be created, or when it exists with the wrong owner
/// or permissions.
pub fn create_private_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(IpcError::io(
                "open",
                path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a KalaReach directory must not be a symbolic link",
                ),
            ));
        }
        Ok(metadata) if metadata.is_dir() => return check_owner_only(path, &metadata),
        Ok(_) => {
            return Err(IpcError::io(
                "create",
                path,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "exists and is not a directory",
                ),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(IpcError::io("inspect", path, error)),
    }
    build_owner_only_directory(path)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| IpcError::io("inspect", path, error))?;
    check_owner_only(path, &metadata)
}

#[cfg(unix)]
fn build_owner_only_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    match std::fs::DirBuilder::new()
        .mode(OWNER_ONLY_DIRECTORY_MODE)
        .create(path)
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(IpcError::io("create", path, error)),
    }
}

#[cfg(not(unix))]
fn build_owner_only_directory(path: &Path) -> Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(IpcError::io("create", path, error)),
    }
}

#[cfg(unix)]
fn check_owner_only(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let expected_uid = current_uid();
    let found_uid = metadata.uid();
    let found_mode = metadata.mode() & 0o777;
    if found_uid != expected_uid || found_mode & 0o077 != 0 {
        return Err(IpcError::DirectoryNotOwnerOnly {
            path: path.to_path_buf(),
            expected_uid,
            found_uid,
            found_mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    // Windows has no mode bits. The runtime and state directories live under the user's own
    // profile, and each endpoint carries its own owner-only access-control list; the Windows
    // qualification pass adds an explicit protected access-control list here.
    Ok(())
}

/// Returns the current user's identifier.
#[cfg(unix)]
#[must_use]
pub fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Returns the current user's identifier.
#[cfg(not(unix))]
#[must_use]
pub fn current_uid() -> u32 {
    0
}

/// Writes a file owner-only, replacing any previous contents atomically.
///
/// The temporary file is created in the destination's own directory so the rename cannot cross a
/// filesystem boundary, and it carries the final permissions before it holds any content.
///
/// # Errors
///
/// Returns an error when the file cannot be written or renamed into place.
pub fn write_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = directory.join(format!(".{}.tmp", crate::new_uuid()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(OWNER_ONLY_FILE_MODE);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| IpcError::io("create", &temporary, error))?;
    let written = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| IpcError::io("write", &temporary, error));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(IpcError::io("publish", path, error));
    }
    // The file's own contents are on disk, but the rename that gave it its name is a change to the
    // directory. Without this a crash can leave the name missing while the data is safe.
    sync_directory(directory)
}

/// Writes a file owner-only, failing when it already exists.
///
/// This is the publication a racing caller must lose rather than win. `rename` always replaces, so
/// it cannot answer "who got there first"; an exclusive create can.
///
/// # Errors
///
/// Returns [`IpcError::Io`] with [`std::io::ErrorKind::AlreadyExists`] when the file is present,
/// and any other failure of the write.
pub fn create_new_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(OWNER_ONLY_FILE_MODE);
    }
    let mut file = options
        .open(path)
        .map_err(|error| IpcError::io("create", path, error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| IpcError::io("write", path, error))?;
    drop(file);
    sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// Flushes a directory entry to disk after a file inside it is created or renamed.
fn sync_directory(directory: &Path) -> Result<()> {
    match std::fs::File::open(directory) {
        Ok(handle) => handle
            .sync_all()
            .map_err(|error| IpcError::io("flush", directory, error)),
        // Not every platform lets a directory be opened for synchronisation. Where it cannot be,
        // the rename is still ordered by the filesystem's own rules.
        Err(_) => Ok(()),
    }
}

#[cfg(target_os = "macos")]
fn default_runtime_root() -> Result<PathBuf> {
    // macOS gives each user a private, mode 0700 temporary directory. It is short, which matters
    // for a socket address, and it is per-user, which is what the endpoints need.
    if let Some(value) = std::env::var_os("TMPDIR") {
        return Ok(PathBuf::from(value).join("kalareach"));
    }
    Ok(PathBuf::from(format!("/tmp/kalareach-{}", current_uid())))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_runtime_root() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(value).join("kalareach"));
    }
    let home = home_directory()?;
    Ok(home.join(".cache").join("kalareach").join("run"))
}

#[cfg(windows)]
fn default_runtime_root() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| IpcError::IdentityUnavailable {
        what: "runtime directory",
        detail: "LOCALAPPDATA is not set".to_owned(),
    })?;
    Ok(PathBuf::from(base).join("KalaReach").join("run"))
}

#[cfg(target_os = "macos")]
fn default_state_root() -> Result<PathBuf> {
    Ok(home_directory()?
        .join("Library")
        .join("Application Support")
        .join("KalaReach"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_state_root() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(value).join("kalareach"));
    }
    Ok(home_directory()?
        .join(".local")
        .join("state")
        .join("kalareach"))
}

#[cfg(windows)]
fn default_state_root() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| IpcError::IdentityUnavailable {
        what: "state directory",
        detail: "LOCALAPPDATA is not set".to_owned(),
    })?;
    Ok(PathBuf::from(base).join("KalaReach"))
}

#[cfg(unix)]
fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| IpcError::IdentityUnavailable {
            what: "home directory",
            detail: "HOME is not set".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(name: &str) -> PathBuf {
        let suffix = crate::new_uuid().to_string();
        let base = std::env::temp_dir().join(format!("kr-{name}-{}", &suffix[..6]));
        create_private_tree(&base, &base).expect("temporary directory");
        base
    }

    #[test]
    fn directories_are_created_owner_only() {
        let root = temporary_root("dirs");
        let nested = root.join("a").join("b");
        create_private_tree(&root, &nested).expect("creates");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(&nested).expect("metadata").mode() & 0o777;
            assert_eq!(mode, OWNER_ONLY_DIRECTORY_MODE);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_widened_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temporary_root("widened");
        let target = root.join("run");
        create_private_tree(&root, &target).expect("creates");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let error = create_private_tree(&root, &target).expect_err("refuses");
        assert!(matches!(error, IpcError::DirectoryNotOwnerOnly { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn publication_is_atomic_and_owner_only() {
        let root = temporary_root("publish");
        create_private_tree(&root, &root.join("sessions")).expect("directory");
        let target = root.join("sessions").join("descriptor.kr");
        write_owner_only_file(&target, b"first").expect("writes");
        write_owner_only_file(&target, b"second").expect("replaces");
        assert_eq!(std::fs::read(&target).expect("reads"), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(&target).expect("metadata").mode() & 0o777;
            assert_eq!(mode, OWNER_ONLY_FILE_MODE);
        }
        // No temporary file is left behind.
        let leftovers = std::fs::read_dir(target.parent().expect("parent"))
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(leftovers, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_over_long_socket_path_names_its_limit() {
        let long = PathBuf::from("/".to_owned() + &"x".repeat(MAX_SOCKET_PATH_LEN + 8));
        let error = Endpoint::from_path(long).expect_err("refuses");
        assert!(matches!(error, IpcError::SocketPathTooLong { .. }));
    }

    #[test]
    fn an_environment_identity_is_allocated_once_and_then_read() {
        let root = temporary_root("identity");
        let paths = HostPaths::new(root.join("run"), root.join("state"));
        let first = paths.open_environment_id().expect("allocates");
        let second = paths.open_environment_id().expect("reads");
        assert_eq!(first, second);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_ordinary_parent_directory_is_accepted() {
        // The platform temporary directory is world-writable by design and the user cache
        // directory is usually group-readable. Neither is KalaReach's to change.
        let root = std::env::temp_dir().join(format!("kr-parent-{}", crate::new_uuid()));
        let nested = root.join("run").join("ab12cd34");
        create_private_tree(&root, &nested).expect("creates under an ordinary parent");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_symbolic_link_is_never_used_as_a_private_directory() {
        let root = temporary_root("symlink");
        let elsewhere = root.join("elsewhere");
        create_private_tree(&root, &elsewhere).expect("creates");
        let link = root.join("link");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("links");
        let error = create_private_tree(&root, &link).expect_err("refuses");
        assert!(matches!(error, IpcError::Io { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn one_caller_wins_the_environment_identity() {
        let root = temporary_root("race");
        let paths = HostPaths::new(root.join("r"), root.join("s"));
        let first = paths.open_environment_id().expect("allocates");
        // A second caller that would have generated its own identity must read the winner's.
        let second = paths.open_environment_id().expect("reads");
        assert_eq!(first, second);
        // The file is created exclusively, so a second create attempt is refused rather than
        // replacing the winner.
        let error = create_new_owner_only_file(&paths.environment_id_file(), b"other")
            .expect_err("refuses");
        assert!(matches!(
            error,
            IpcError::Io { ref source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_prefix_collision_is_refused_rather_than_shared() {
        let root = temporary_root("collision");
        let paths = HostPaths::new(root.join("r"), root.join("s"));
        let mut first_bytes = [7_u8; 16];
        first_bytes[15] = 1;
        let mut second_bytes = first_bytes;
        second_bytes[15] = 2;
        let first = paths.environment(EnvironmentId::new(Uuid::from_bytes(first_bytes)));
        let second = paths.environment(EnvironmentId::new(Uuid::from_bytes(second_bytes)));
        assert_eq!(first.runtime_dir(), second.runtime_dir());
        first.create().expect("claims");
        let error = second.create().expect_err("refuses");
        assert!(matches!(error, IpcError::EnvironmentPrefixCollision { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn endpoint_names_stay_inside_the_platform_limit() {
        let root = temporary_root("endpoints");
        let paths = HostPaths::new(root.join("run"), root.join("state"));
        let environment = paths.environment(EnvironmentId::new(Uuid::NIL));
        environment.create().expect("directories");
        environment.controller_endpoint().expect("fits");
        environment.rendezvous_endpoint().expect("fits");
        environment
            .worker_endpoint(DisplayNumber::new(999_999))
            .expect("fits");
        std::fs::remove_dir_all(&root).ok();
    }
}
