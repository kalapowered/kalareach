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

use kr_flush::{NameKind, flush_directory};
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
    ///
    /// A relative root is resolved against the current directory, once, here. Every path an
    /// installation has is derived from these two, and some of them are given to a process that
    /// runs somewhere else: a worker is started in a directory of its own, and a relative root
    /// would mean a different place to it. Resolving them at the top is what keeps one
    /// installation's paths naming the same directories in every process that holds them, and what
    /// lets an endpoint one process signs be the endpoint another compares it with.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Io`] when a root cannot be resolved: an empty path, or a current
    /// directory the operating system will not report. An installation whose roots cannot be
    /// resolved is refused here rather than handing a relative one to another process.
    pub fn new(runtime_root: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            runtime_root: resolve_here(runtime_root.into())?,
            state_root: resolve_here(state_root.into())?,
        })
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
        Self::new(runtime_root, state_root)
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
        // An identity that already exists is read, and nothing else happens. Publishing first and
        // discovering afterwards that the file was there would make reading a perfectly good
        // identity depend on being able to write a new one.
        if let Some(identity) = read_environment_id(&path)? {
            return Ok(identity);
        }
        // Creation must not replace: two first starts racing here would otherwise each publish
        // their own identity and walk away believing different answers, and the per-environment
        // singleton lock cannot undo a split that happened before it existed. Exactly one caller
        // creates the file; every other caller reads what that one wrote.
        match create_new_owner_only_file(
            &path,
            format!("{}\n", EnvironmentId::new(crate::new_uuid())).as_bytes(),
        ) {
            Ok(()) => {}
            Err(IpcError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        read_environment_id(&path)?.ok_or_else(|| IpcError::IdentityUnavailable {
            what: "environment identity",
            detail: format!(
                "{}: the file vanished after it was published",
                path.display()
            ),
        })
    }

    /// Reads this installation's environment identity, when it has one, without allocating one.
    ///
    /// For a process that serves an environment it did not create, such as the starter the
    /// environment's scheduled task runs: an installation with no identity has nothing for it to
    /// serve, and making one would be making an installation.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists and cannot be read, or does not hold an identity.
    pub fn recorded_environment_id(&self) -> Result<Option<EnvironmentId>> {
        read_environment_id(&self.environment_id_file())
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
            &self.workers_dir(),
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

    /// Returns the file that holds this environment's clock floor for the current boot.
    ///
    /// In the runtime directory, beside the endpoints and the descriptors: it is owner-only, it is
    /// on the internal disk, and like them it describes this boot and no other ([`crate::floor`]).
    #[must_use]
    pub fn utc_floor_file(&self) -> PathBuf {
        self.runtime_dir.join("utc-floor")
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

    /// Returns the directory holding one directory per worker.
    #[must_use]
    pub fn workers_dir(&self) -> PathBuf {
        self.state_dir.join("workers")
    }

    /// Returns the directory one worker process runs in.
    ///
    /// A worker is started by the platform's service manager rather than by the daemon, so it
    /// inherits nothing worth having: the launcher's directory belongs to whoever ran the
    /// installer, and a service manager's belongs to the system. It is given a directory of its
    /// own instead, inside the environment it belongs to, which it can be relied on to be able to
    /// read and which no user data is under. Holding it open for the life of the session also
    /// keeps the worker from pinning a directory somebody may want to unmount.
    #[must_use]
    pub fn worker_dir(&self, session_id: SessionId) -> PathBuf {
        self.workers_dir().join(session_id.to_string())
    }

    /// Returns the directory the secret-store fallback writes to.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    /// Returns the endpoint on which this environment's starter takes a launch from the daemon.
    ///
    /// Windows only: there the environment's scheduled task runs a starter, and the starter, not
    /// the daemon, creates each worker ([`crate::starter`]). One instance of this pipe waits for
    /// each launch the daemon has handed over.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::SocketPathTooLong`] when the name does not fit the platform's limit.
    #[cfg(windows)]
    pub fn starter_endpoint(&self) -> Result<Endpoint> {
        self.endpoint("s")
    }

    /// Returns the directory in which a request to start this environment's daemon waits for the
    /// starter that takes it.
    ///
    /// In the runtime directory: a request belongs to one boot, and its deadline is counted on that
    /// boot's clock ([`crate::starter`]).
    #[must_use]
    pub fn start_claims_dir(&self) -> PathBuf {
        self.runtime_dir.join("claims")
    }

    /// Returns the file that records which login session this environment's work runs in.
    ///
    /// In the state directory, because it has to outlive the daemon that wrote it: a replacement
    /// daemon reads it before it takes over anything ([`crate::starter`]).
    #[must_use]
    pub fn session_record(&self) -> PathBuf {
        self.state_dir.join("login-session")
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

/// Returns `path` against the current directory.
///
/// # Errors
///
/// Returns [`IpcError::Io`] when the path is empty or the current directory cannot be read.
pub fn resolve_here(path: PathBuf) -> Result<PathBuf> {
    std::path::absolute(&path).map_err(|error| IpcError::io("resolve", path, error))
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

/// Creates the directory with an access-control list of this host's own.
///
/// The list is protected, so nothing above it in the user profile is inherited into it, and it
/// carries an inherit-only entry for the object's owner, so a file or a directory created beneath
/// it is owner-only without a second call per object.
#[cfg(windows)]
fn build_owner_only_directory(path: &Path) -> Result<()> {
    windows::create_owner_only_directory(path)
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

/// Checks that a directory belongs to this user and that its list names nobody else.
///
/// Windows has no mode bits, so the question the Unix check asks of a mode is asked of the
/// object's access-control list, and it is read from a handle rather than from the name: what
/// answers is the directory that was opened.
///
/// A *protected* list is not demanded here, though every directory this host creates carries one.
/// A KalaReach root can legitimately be created on the way to another - on Windows the runtime
/// root lives inside the state root - and a directory created as a parent is an ordinary one of
/// the user's profile until this host adopts it. Its inherited entries name this user, the local
/// system and the administrators group, all of which already hold the machine, and demanding
/// protection of it would refuse a perfectly ordinary installation for a reason it could not act
/// on. What is refused is a directory owned by another account, or one whose list grants access to
/// anybody but the accounts above. A directory whose list must be proof against the one above it
/// asks for that explicitly, through [`check_access_list`].
#[cfg(windows)]
fn check_owner_only(path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;

    // A directory has no data to read, and Windows will not open one at all without the backup
    // semantics that say so. The open asks for read access, which carries the right to read the
    // object's own security information, and for nothing else.
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| IpcError::io("inspect", path, error))?;
    let what = path.display().to_string();
    match check_access_list(directory.as_handle(), &what, false) {
        Ok(()) => Ok(()),
        Err(AccessListRefusal::Policy(detail)) => Err(IpcError::DirectoryAccessRefused {
            path: path.to_path_buf(),
            detail,
        }),
        Err(AccessListRefusal::Unreadable(detail)) => {
            Err(IpcError::io("inspect", path, std::io::Error::other(detail)))
        }
    }
}

/// The Windows access rules of this host's own directories.
///
/// Windows has no mode bits, so the equivalent of `0700` is the object's access-control list. Two
/// things have to happen to it. A directory is created with a list of this host's own, protected
/// so nothing is inherited into it from the user profile above. Every later open reads the list
/// back from the handle it just opened and refuses one that has been widened, because a directory
/// that already existed is a directory this host did not create.
///
/// This is one of the three places in this crate that leave safe Rust. The list comes from
/// `advapi32` and is applied by `kernel32`, and reading one back is four more calls into the same
/// library.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "an owner-only access-control list, and reading one or a file's whole access back \
                  from an opened handle, are calls into advapi32, which has no safe interface"
    )]

    use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
    use std::path::Path;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtOpenFile,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL,
        GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Foundation::{
        OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ATTRIBUTE_SECURITY_INFORMATION,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetKernelObjectSecurity, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        GetSecurityDescriptorSacl, GetTokenInformation, INHERITED_ACE, IsValidSid,
        LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SCOPE_SECURITY_INFORMATION, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED,
        SE_SACL_AUTO_INHERITED, SE_SACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_ENCRYPTED, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_FILTER_SECURITY_INFORMATION, PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::error::{IpcError, Result};

    /// Opens a name directly inside a directory, from the directory's own open handle.
    ///
    /// This is the [`openat`] of this platform, which has no Win32 call for it. The name is resolved
    /// against the handle in one step, so a directory swapped for another since the handle was
    /// opened is never consulted (its handle still names the directory that was checked), and a file
    /// replaced by a rename while this runs opens as one whole version or the other and never as
    /// nothing. The name carries no separator, so it cannot climb out of the directory. The
    /// reparse-point option opens a link itself rather than following it, so the caller refuses one
    /// by its attributes rather than being sent wherever it points.
    ///
    /// `None` is a name that is not there, which a caller reads as no descriptor rather than a
    /// failure.
    ///
    /// [`openat`]: https://man7.org/linux/man-pages/man2/openat.2.html
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the name cannot be opened for a reason other than
    /// its absence.
    pub fn open_child(
        directory: BorrowedHandle<'_>,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<std::fs::File>> {
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::io::FromRawHandle as _;

        let mut wide: Vec<u16> = name.encode_wide().collect();
        // A name resolved relative to a directory handle is one component, so a separator in it, or
        // the whole-path forms the native call would otherwise read, is refused here rather than
        // resolved. `\` and `/` are both separators to this platform, and a leading `\??\` or `\\`
        // would leave the directory the handle names.
        if wide.is_empty()
            || wide.contains(&(b'\\' as u16))
            || wide.contains(&(b'/' as u16))
            || wide.contains(&0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a name opened relative to a directory is one component",
            ));
        }
        let length = u16::try_from(wide.len() * 2).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "the name is too long")
        })?;
        let object_name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: wide.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
            RootDirectory: directory.as_raw_handle(),
            ObjectName: &raw const object_name,
            // Case-insensitive, as every path on this platform is by default.
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` and `status_block` are live out parameters; `attributes` points at
        // `object_name`, whose buffer is `wide`, and all three are locals that live to the end of
        // this function, past the call. `directory` is a handle borrowed for this call and used as
        // the root the name resolves against. The options open an existing name only, so the call
        // creates nothing.
        let status = unsafe {
            NtOpenFile(
                &raw mut handle,
                FILE_GENERIC_READ,
                &raw const attributes,
                &raw mut status_block,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            )
        };
        if status == STATUS_SUCCESS {
            // SAFETY: the call above filled `handle` with a file handle this owns and closes once.
            return Ok(Some(unsafe {
                std::fs::File::from_raw_handle(handle.cast())
            }));
        }
        if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
            return Ok(None);
        }
        // SAFETY: the status is the one the call returned; this only maps it to a Win32 code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(std::io::Error::from_raw_os_error(code.cast_signed()))
    }

    /// The limit flags of the job this process runs in, or `None` when it runs in no job.
    ///
    /// A daemon reads this to decide whether a worker it starts must break away from its job: a
    /// worker outlives the daemon, so it must not be inside a job that kills its members when the
    /// daemon closes. Where the job does not kill on close, or there is no job, the worker already
    /// outlives the daemon and no breakaway is needed.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the job cannot be queried.
    pub fn current_job_limit_flags() -> std::io::Result<Option<u32>> {
        use windows_sys::Win32::System::JobObjects::{
            IsProcessInJob, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        };

        let mut in_job: windows_sys::core::BOOL = 0;
        // SAFETY: the process handle is a pseudo-handle that needs no release, the second argument
        // is null to ask about any job, and `in_job` is a live out parameter.
        let asked =
            unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &raw mut in_job) };
        if asked == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if in_job == 0 {
            return Ok(None);
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let size =
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0);
        // SAFETY: a null job handle queries the job this process is in, which the call above
        // confirmed it has; `info` is a live buffer of the size passed, and the return length is
        // not wanted.
        let read = unsafe {
            QueryInformationJobObject(
                std::ptr::null_mut(),
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                size,
                std::ptr::null_mut(),
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(info.BasicLimitInformation.LimitFlags))
    }

    /// The object's owner only, with inheritance blocked and children covered.
    ///
    /// `D:P` makes the list protected, so no inherited entry from the user profile widens it.
    /// `(A;;GA;;;OW)` grants everything to OWNER RIGHTS, which resolves to whoever owns the object:
    /// the process that created the directory, which is this user. `(A;OICIIO;GA;;;CO)` is
    /// inherit-only and names CREATOR OWNER, the placeholder that becomes the owner's own entry on
    /// each file and directory created beneath, so a payload file is owner-only without a second call
    /// per file.
    const OWNER_ONLY_DESCRIPTOR: &str = "D:P(A;;GA;;;OW)(A;OICIIO;GA;;;CO)";

    /// The accounts an entry in one of these directories may name.
    ///
    /// `S-1-5-18` is the local system and `S-1-5-32-544` the local administrators group: both already
    /// hold the machine, and nothing this host does can keep them out. `S-1-3-0` is CREATOR OWNER and
    /// `S-1-3-4` is OWNER RIGHTS, the two placeholders that resolve to the object's owner, which is
    /// this user. The owner itself is trusted separately. Every other account is a refusal.
    const TRUSTED_ACCOUNTS: &[&str] = &["S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"];

    /// An entry that grants access.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    /// An entry that denies access, which cannot widen anything.
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    /// An entry that records an access attempt.
    const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
    /// An entry that raises an alarm on an access attempt.
    const SYSTEM_ALARM_ACE_TYPE: u8 = 3;

    /// Why an access-control list was not accepted.
    #[derive(Debug)]
    pub enum AccessListRefusal {
        /// The list could not be read, which is a storage failure rather than a policy one.
        Unreadable(String),
        /// The list was read and does not meet the policy.
        Policy(String),
    }

    /// Creates a directory whose access-control list names its owner and nothing else.
    ///
    /// An existing directory is left alone: the caller checks the list it already carries.
    ///
    /// # Errors
    ///
    /// Returns an error when the list cannot be built or the directory cannot be created.
    pub(super) fn create_owner_only_directory(path: &Path) -> Result<()> {
        create_directory_with_list(path, OWNER_ONLY_DESCRIPTOR)
    }

    /// Creates a directory with one explicit access-control list, written as SDDL.
    ///
    /// # Errors
    ///
    /// Returns an error when the list cannot be built or the directory cannot be created.
    pub(crate) fn create_directory_with_list(path: &Path, descriptor: &str) -> Result<()> {
        let wide_path = wide(path.as_os_str());
        let wide_descriptor = wide_str(descriptor);
        let mut built: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: both pointers are null-terminated wide buffers this function owns for the whole
        // call, `built` is a live out parameter, and the size parameter is optional.
        let parsed = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_descriptor.as_ptr(),
                SDDL_REVISION_1,
                &raw mut built,
                std::ptr::null_mut(),
            )
        };
        if parsed == 0 {
            return Err(IpcError::io(
                "create",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: built,
            bInheritHandle: 0,
        };
        // SAFETY: `wide_path` is a null-terminated wide buffer this function owns, and `attributes`
        // points at a descriptor that stays live until it is freed below.
        let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &raw const attributes) };
        let failure = (created == 0).then(std::io::Error::last_os_error);
        // SAFETY: `built` was allocated by the conversion above and is freed exactly once.
        unsafe {
            LocalFree(built.cast());
        }
        match failure {
            None => Ok(()),
            // An existing staging directory is the ordinary case on every start after the first. Its
            // list is checked by the caller rather than replaced here.
            Some(error) if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.cast_signed()) => {
                Ok(())
            }
            Some(error) => Err(IpcError::io("create", path, error)),
        }
    }

    /// Checks the access-control list of an opened directory.
    ///
    /// `what` names the directory in the refusal. `require_protected` additionally demands a protected
    /// list, which is the check for a boundary directory: nothing above it can widen it later. A
    /// directory beneath one of those inherits the owner entry from it by design, so its list is
    /// checked for the accounts it names and not for protection.
    ///
    /// # Errors
    ///
    /// Returns [`AccessListRefusal::Unreadable`] when the list cannot be read and [`AccessListRefusal::Policy`] when it
    /// names an account this host does not trust.
    pub fn check_access_list(
        handle: BorrowedHandle<'_>,
        what: &str,
        require_protected: bool,
    ) -> std::result::Result<(), AccessListRefusal> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut list: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the handle is borrowed for the whole call and was opened for reading, which on
        // Windows carries the right to read the list. The three out parameters are live, and the two
        // this host does not ask for are null, which the function documents as "do not return this".
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                &raw mut list,
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(AccessListRefusal::Unreadable(format!(
                "the access-control list of {what} could not be read: {}",
                std::io::Error::from_raw_os_error(status.cast_signed())
            )));
        }
        let outcome = evaluate(owner, list, descriptor, what, require_protected);
        // SAFETY: the descriptor came from the call above and is freed exactly once. `owner` and
        // `list` point into it and are not used after this.
        unsafe {
            LocalFree(descriptor.cast());
        }
        outcome
    }

    /// Applies the policy to a list that has been read.
    fn evaluate(
        owner: PSID,
        list: *mut ACL,
        descriptor: PSECURITY_DESCRIPTOR,
        what: &str,
        require_protected: bool,
    ) -> std::result::Result<(), AccessListRefusal> {
        if owner.is_null() {
            return Err(AccessListRefusal::Policy(format!(
                "{what} records no owner"
            )));
        }
        if require_protected {
            let mut control: u16 = 0;
            let mut revision: u32 = 0;
            // SAFETY: the descriptor is the one just read, and both out parameters are live.
            let read = unsafe {
                GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            };
            if read == 0 {
                return Err(AccessListRefusal::Unreadable(format!(
                    "the access-control list of {what} could not be inspected: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if control & SE_DACL_PROTECTED == 0 {
                return Err(AccessListRefusal::Policy(format!(
                    "{what} inherits its access-control list from the directory above it, which can \
                     widen it at any time"
                )));
            }
        }
        // A missing list is not an empty one: an object with no list at all grants every account full
        // access, which is the widest answer Windows has.
        if list.is_null() {
            return Err(AccessListRefusal::Policy(format!(
                "{what} carries no access-control list, which grants every account full access"
            )));
        }
        let accounts = TokenAccounts::read()?;
        let mut trusted = Vec::with_capacity(TRUSTED_ACCOUNTS.len());
        for text in TRUSTED_ACCOUNTS {
            trusted.push(OwnedSid::parse(text)?);
        }
        // Two different rules, so they are two different predicates. The owner has to be an account
        // this process could have created the directory as: its own user, or the owner new objects of
        // this process receive. The machine's own accounts are trusted to *hold* the directory, which
        // nothing can prevent, but a directory owned by one of them is not one this host created.
        let is_owner = |sid: PSID| equal(sid, accounts.user()) || equal(sid, accounts.owner());
        let permitted = |sid: PSID| {
            is_owner(sid) || trusted.iter().any(|account| equal(sid, account.as_psid()))
        };
        if !is_owner(owner) {
            return Err(AccessListRefusal::Policy(format!(
                "{what} belongs to {}, and this host runs as another account",
                describe(owner)
            )));
        }
        // SAFETY: `list` points at the list inside the descriptor read above.
        let count = unsafe { (*list).AceCount };
        for index in 0..u32::from(count) {
            let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `list` is live and `index` is below the entry count it reported.
            let got = unsafe { GetAce(list, index, &raw mut entry) };
            if got == 0 || entry.is_null() {
                return Err(AccessListRefusal::Unreadable(format!(
                    "entry {index} of the access-control list of {what} could not be read: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: every entry in a list begins with its header.
            let header = unsafe { std::ptr::read(entry.cast::<ACE_HEADER>()) };
            match header.AceType {
                // A denial, an audit and an alarm grant nothing.
                ACCESS_DENIED_ACE_TYPE | SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE => continue,
                ACCESS_ALLOWED_ACE_TYPE => {}
                // A callback or conditional entry can grant access on terms this host does not read.
                // Refusing it is the answer that cannot be wrong.
                other => {
                    return Err(AccessListRefusal::Policy(format!(
                        "the access-control list of {what} carries a type-{other} entry, which this \
                         host does not evaluate"
                    )));
                }
            }
            // SAFETY: the identifier of an allowed entry begins at the offset of `SidStart` within it,
            // inside the list this pointer came from.
            let sid: PSID = unsafe {
                entry
                    .cast::<u8>()
                    .add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
            }
            .cast();
            if !permitted(sid) {
                return Err(AccessListRefusal::Policy(format!(
                    "the access-control list of {what} grants access to {}, which is neither its \
                     owner nor an account that already holds this machine",
                    describe(sid)
                )));
            }
        }
        Ok(())
    }

    /// Every class of a file's security descriptor that decides who can reach the file and that
    /// needs no privilege to read: the owner, the discretionary list, the mandatory label, resource
    /// attributes, central access policy identifiers, the process trust label and access filters.
    /// Audit entries are not asked for: reading them needs a privilege, and they grant and deny
    /// nothing.
    const ACCESS_CLASSES: u32 = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION
        | ATTRIBUTE_SECURITY_INFORMATION
        | SCOPE_SECURITY_INFORMATION
        | PROCESS_TRUST_LABEL_SECURITY_INFORMATION.cast_unsigned()
        | ACCESS_FILTER_SECURITY_INFORMATION.cast_unsigned();

    /// Who can reach a file, as its security descriptor and its encryption say.
    ///
    /// A file is replaced by writing a new file in its directory and renaming it over the old one,
    /// and the new file carries what Windows gives a file created there, not what the old one
    /// carried. Two readings are equal when everything that decides access is equal, as the file
    /// system stores it: the owner; the discretionary list's protection, whether it records
    /// inheritance, and its entries in order, each an allow or a deny with its flags, its account
    /// and its rights, generic rights read as the file rights they stand for, or that there is no
    /// list at all; and the system list's protection, whether it records inheritance, and its
    /// mandatory label entries in order, each label's mask read as the policy it is. Nothing else is
    /// compared, because nothing else is read: a file carrying any other control that decides access
    /// is refused instead (see [`FileAccess::read`]).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct FileAccess {
        owner: Account,
        discretionary: AccessList,
        system: SystemList,
    }

    /// The discretionary list: whether it is protected from what its directory passes down and
    /// whether it records which entries it inherited, both of which the descriptor states even
    /// where there is no list, and its entries in the order access is decided by, or `None` for no
    /// list at all, which grants every account everything.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AccessList {
        protected: bool,
        records_inheritance: bool,
        entries: Option<Vec<AccessEntry>>,
    }

    /// The part of the system list that decides access: its protection, whether it records which
    /// labels it inherited, and its mandatory labels in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SystemList {
        protected: bool,
        records_inheritance: bool,
        labels: Vec<AccessEntry>,
    }

    /// One entry of a discretionary list, or one mandatory label.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AccessEntry {
        kind: EntryKind,
        /// The entry's own flags, inheritance among them.
        flags: u8,
        /// The rights an allow or a deny names, generic rights read as file rights; for a label,
        /// its policy, as it is.
        mask: u32,
        account: Account,
    }

    impl AccessEntry {
        /// Returns true when the entry came from the directory above rather than being set here.
        fn is_inherited(&self) -> bool {
            u32::from(self.flags) & INHERITED_ACE != 0
        }
    }

    /// What an entry does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum EntryKind {
        /// It grants the rights it names.
        Allow,
        /// It denies the rights it names.
        Deny,
        /// It is the file's mandatory integrity label.
        Label,
    }

    /// An account, as the bytes of the security identifier that names it.
    #[derive(Clone, PartialEq, Eq)]
    struct Account(Vec<u8>);

    impl std::fmt::Debug for Account {
        /// Written the way Windows writes one, `S-1-5-18`, when the bytes hold one.
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let bytes = &self.0;
            if bytes.len() < 8 || bytes.len() != 8 + 4 * usize::from(bytes[1]) {
                return write!(formatter, "an account of {} bytes", bytes.len());
            }
            let authority = bytes[2..8]
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            write!(formatter, "S-{}-{authority}", bytes[0])?;
            for part in bytes[8..].chunks_exact(4) {
                write!(
                    formatter,
                    "-{}",
                    u32::from_le_bytes([part[0], part[1], part[2], part[3]])
                )?;
            }
            Ok(())
        }
    }

    impl FileAccess {
        /// Reads who can reach the file an open handle holds.
        ///
        /// The handle has to hold `READ_CONTROL` and `FILE_READ_ATTRIBUTES`. Every class
        /// [`ACCESS_CLASSES`] names is asked for in one query, and a query that fails is a read that
        /// failed, never a file that carries nothing.
        ///
        /// # Errors
        ///
        /// Returns [`AccessListRefusal::Unreadable`] when the file's attributes or descriptor cannot
        /// be read, and [`AccessListRefusal::Policy`] when the file carries a control this host does
        /// not evaluate: a discretionary entry other than an allow or a deny (a callback, conditional,
        /// object or compound entry), a resource attribute, a central access policy, a process trust
        /// label, an access filter or any other entry in the system list but a label, or encryption,
        /// because who can read an encrypted file depends on keys no descriptor shows.
        pub fn read(file: &std::fs::File) -> std::result::Result<Self, AccessListRefusal> {
            use std::os::windows::fs::MetadataExt as _;
            use std::os::windows::io::AsHandle as _;

            let attributes = file
                .metadata()
                .map_err(|error| {
                    AccessListRefusal::Unreadable(format!(
                        "its attributes could not be read: {error}"
                    ))
                })?
                .file_attributes();
            if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
                return Err(AccessListRefusal::Policy(
                    "it is encrypted, and who can read an encrypted file depends on keys this host \
                     does not read"
                        .to_owned(),
                ));
            }
            let descriptor = query_descriptor(file.as_handle())?;
            read_descriptor(&descriptor)
        }

        /// Opens the file at `path` with the rights [`FileAccess::read`] needs and nothing more,
        /// sharing everything, and reads it.
        ///
        /// A link at the path is followed, as the readers of the other platforms follow one.
        ///
        /// # Errors
        ///
        /// As [`FileAccess::read`], and [`AccessListRefusal::Unreadable`] when the file cannot be
        /// opened.
        pub fn of(path: &Path) -> std::result::Result<Self, AccessListRefusal> {
            use std::os::windows::fs::OpenOptionsExt as _;

            let file = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path)
                .map_err(|error| {
                    AccessListRefusal::Unreadable(format!(
                        "it could not be opened to read who can reach it: {error}"
                    ))
                })?;
            Self::read(&file)
        }

        /// Returns true when the file's descriptor records nothing set on the file itself: there is
        /// a discretionary list with entries, neither list is protected from the directory, and in
        /// each list that records inheritance every entry is marked inherited.
        ///
        /// That is the shape of what a file created in its directory carries. A list records which
        /// entries it inherited only when it is automatically inherited: one written the older way,
        /// as every file under some profiles is, marks no entry inherited whatever its origin, so
        /// from it this cannot tell, and says nothing against the file. The comparison of a
        /// replacement with the file it replaces decides there, as it does for a directory whose
        /// list changed since the file inherited from it and for a file moved in from elsewhere.
        #[must_use]
        pub fn records_nothing_set_here(&self) -> bool {
            let list = &self.discretionary;
            let Some(entries) = &list.entries else {
                return false;
            };
            let set_here = |recorded: bool, entries: &[AccessEntry]| {
                recorded && entries.iter().any(|entry| !entry.is_inherited())
            };
            !list.protected
                && !entries.is_empty()
                && !self.system.protected
                && !set_here(list.records_inheritance, entries)
                && !set_here(self.system.records_inheritance, &self.system.labels)
        }

        /// Returns true when the file belongs to the account this process gives the files it
        /// creates, which is the owner a replacement written by this process would have.
        ///
        /// # Errors
        ///
        /// Returns [`AccessListRefusal::Unreadable`] when this process's own token cannot be read.
        pub fn is_owned_as_new_files_are(&self) -> std::result::Result<bool, AccessListRefusal> {
            let accounts = TokenAccounts::read()?;
            let owner = account_in(accounts.owner(), &accounts.owner, usize::MAX)?;
            Ok(owner == self.owner)
        }
    }

    /// Reads the security descriptor a handle holds, every class [`ACCESS_CLASSES`] names, into
    /// a buffer aligned for it.
    fn query_descriptor(
        handle: BorrowedHandle<'_>,
    ) -> std::result::Result<Vec<u64>, AccessListRefusal> {
        let mut buffer = vec![0_u64; 128];
        // A descriptor can grow between the call that measures it and the call that reads it, so
        // the read is tried again with the size the last call asked for, a few times and no more.
        for _ in 0..4 {
            let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
            let mut needed: u32 = 0;
            // SAFETY: the handle is borrowed for the call; the buffer holds `length` bytes and is
            // aligned for a descriptor; `needed` is a live out parameter.
            let read = unsafe {
                GetKernelObjectSecurity(
                    handle.as_raw_handle(),
                    ACCESS_CLASSES,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &raw mut needed,
                )
            };
            if read != 0 {
                return Ok(buffer);
            }
            let error = std::io::Error::last_os_error();
            let wanted = usize::try_from(needed).unwrap_or(usize::MAX);
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed())
                || wanted <= buffer.len() * 8
            {
                return Err(AccessListRefusal::Unreadable(format!(
                    "its security descriptor could not be read: {error}"
                )));
            }
            buffer = vec![0_u64; wanted.div_ceil(8)];
        }
        Err(AccessListRefusal::Unreadable(
            "its security descriptor kept growing while it was read".to_owned(),
        ))
    }

    /// Reads what decides access out of a descriptor [`query_descriptor`] returned.
    fn read_descriptor(descriptor: &[u64]) -> std::result::Result<FileAccess, AccessListRefusal> {
        let pointer: PSECURITY_DESCRIPTOR = descriptor.as_ptr().cast_mut().cast();
        let failed = |what: &str| {
            AccessListRefusal::Unreadable(format!(
                "the {what} of its security descriptor could not be read: {}",
                std::io::Error::last_os_error()
            ))
        };
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: the descriptor is the one the kernel wrote into this buffer, and both out
        // parameters are live.
        if unsafe { GetSecurityDescriptorControl(pointer, &raw mut control, &raw mut revision) }
            == 0
        {
            return Err(failed("control"));
        }
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted: windows_sys::core::BOOL = 0;
        // SAFETY: as above; `owner` receives a pointer into the same buffer.
        if unsafe { GetSecurityDescriptorOwner(pointer, &raw mut owner, &raw mut defaulted) } == 0 {
            return Err(failed("owner"));
        }
        if owner.is_null() {
            return Err(AccessListRefusal::Policy("it records no owner".to_owned()));
        }
        let owner = account_in(owner, descriptor, usize::MAX)?;

        let mut present: windows_sys::core::BOOL = 0;
        let mut list: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above; `list` receives a pointer into the same buffer, or null.
        if unsafe {
            GetSecurityDescriptorDacl(pointer, &raw mut present, &raw mut list, &raw mut defaulted)
        } == 0
        {
            return Err(failed("discretionary list"));
        }
        // No list at all grants every account full access, which is not the same as a list with no
        // entries, which grants nothing.
        let discretionary = AccessList {
            protected: control & SE_DACL_PROTECTED != 0,
            records_inheritance: control & SE_DACL_AUTO_INHERITED != 0,
            entries: if present == 0 || list.is_null() {
                None
            } else {
                Some(entries(list, descriptor, false)?)
            },
        };

        let mut system: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above.
        if unsafe {
            GetSecurityDescriptorSacl(
                pointer,
                &raw mut present,
                &raw mut system,
                &raw mut defaulted,
            )
        } == 0
        {
            return Err(failed("system list"));
        }
        let labels = if present == 0 || system.is_null() {
            Vec::new()
        } else {
            entries(system, descriptor, true)?
        };
        Ok(FileAccess {
            owner,
            discretionary,
            system: SystemList {
                protected: control & SE_SACL_PROTECTED != 0,
                records_inheritance: control & SE_SACL_AUTO_INHERITED != 0,
                labels,
            },
        })
    }

    /// Reads every entry of a list inside `descriptor`, refusing one this host does not evaluate.
    ///
    /// `system` says which list it is: the discretionary list holds allows and denies, and the
    /// system list as it was asked for holds labels and the other controls, which are refused.
    fn entries(
        list: *const ACL,
        descriptor: &[u64],
        system: bool,
    ) -> std::result::Result<Vec<AccessEntry>, AccessListRefusal> {
        let name = if system {
            "system list"
        } else {
            "access-control list"
        };
        // SAFETY: `list` points at a list inside the descriptor the kernel wrote into `descriptor`.
        let count = unsafe { (*list).AceCount };
        let mut read = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `list` is live and `index` is below the entry count it reported.
            if unsafe { GetAce(list, index, &raw mut entry) } == 0 || entry.is_null() {
                return Err(AccessListRefusal::Unreadable(format!(
                    "entry {index} of its {name} could not be read: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: every entry in a list begins with its header.
            let header = unsafe { std::ptr::read_unaligned(entry.cast::<ACE_HEADER>()) };
            let kind = entry_kind(header.AceType, system).map_err(|kind| {
                AccessListRefusal::Policy(format!(
                    "its {name} carries {kind}, which this host does not evaluate"
                ))
            })?;
            // An allow, a deny and a label are laid out alike: the header, a mask, and then the
            // account's identifier.
            let mask_at = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
            let account_at = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let size = usize::from(header.AceSize);
            if size < account_at {
                return Err(AccessListRefusal::Unreadable(format!(
                    "entry {index} of its {name} is {size} bytes, too short to name an account"
                )));
            }
            // SAFETY: the entry is at least `account_at` bytes long, so its mask lies inside it.
            let mask =
                unsafe { std::ptr::read_unaligned(entry.cast::<u8>().add(mask_at).cast::<u32>()) };
            // SAFETY: as above; the identifier starts at `account_at` inside the entry.
            let sid: PSID = unsafe { entry.cast::<u8>().add(account_at) }.cast();
            let account = account_in(sid, descriptor, size - account_at)?;
            read.push(AccessEntry {
                kind,
                flags: header.AceFlags,
                mask: if kind == EntryKind::Label {
                    mask
                } else {
                    file_rights(mask)
                },
                account,
            });
        }
        Ok(read)
    }

    /// Says what an entry of this type is, or names it as one this host does not evaluate.
    fn entry_kind(kind: u8, system: bool) -> std::result::Result<EntryKind, String> {
        use windows_sys::Win32::System::SystemServices::{
            SYSTEM_ACCESS_FILTER_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
        };

        let code = u32::from(kind);
        match (system, kind) {
            (false, ACCESS_ALLOWED_ACE_TYPE) => Ok(EntryKind::Allow),
            (false, ACCESS_DENIED_ACE_TYPE) => Ok(EntryKind::Deny),
            (true, _) if code == SYSTEM_MANDATORY_LABEL_ACE_TYPE => Ok(EntryKind::Label),
            (true, _) if code == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
                Err("a resource attribute".to_owned())
            }
            (true, _) if code == SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
                Err("a central access policy".to_owned())
            }
            (true, _) if code == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE => {
                Err("a process trust label".to_owned())
            }
            (true, _) if code == SYSTEM_ACCESS_FILTER_ACE_TYPE => {
                Err("an access filter".to_owned())
            }
            (_, other) => Err(format!("a type-{other} entry")),
        }
    }

    /// Reads a mask of an allow or a deny as the file rights it names, each generic right replaced
    /// by the file rights it stands for, so an entry written with a generic right and one written
    /// with the rights it means read the same.
    fn file_rights(mask: u32) -> u32 {
        let mut rights = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        for (generic, specific) in [
            (GENERIC_READ, FILE_GENERIC_READ),
            (GENERIC_WRITE, FILE_GENERIC_WRITE),
            (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
            (GENERIC_ALL, FILE_ALL_ACCESS),
        ] {
            if mask & generic != 0 {
                rights |= specific;
            }
        }
        rights
    }

    /// Copies the identifier at `sid` out of `buffer`, checking that it is a valid identifier that
    /// lies wholly inside the buffer and inside the `room` its entry leaves for it.
    fn account_in(
        sid: PSID,
        buffer: &[u64],
        room: usize,
    ) -> std::result::Result<Account, AccessListRefusal> {
        let unreadable =
            || AccessListRefusal::Unreadable("it names an account that is not whole".to_owned());
        let start = buffer.as_ptr() as usize;
        let end = start + buffer.len() * 8;
        let at = sid as usize;
        // The fixed part of an identifier is eight bytes, which is as much as the check of its
        // validity reads before it knows how long the identifier is.
        if sid.is_null() || at < start || at.saturating_add(8) > end || room < 8 {
            return Err(unreadable());
        }
        // SAFETY: the identifier's fixed part lies inside the buffer, as checked above.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(unreadable());
        }
        // SAFETY: the identifier is valid, so its length is read from its own fixed part.
        let length = usize::try_from(unsafe { GetLengthSid(sid) }).unwrap_or(usize::MAX);
        if length > room || at.saturating_add(length) > end {
            return Err(unreadable());
        }
        // SAFETY: the identifier's `length` bytes lie inside the buffer, as checked above, and the
        // buffer outlives the copy.
        Ok(Account(
            unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec(),
        ))
    }

    /// A security identifier this module allocated.
    struct OwnedSid(PSID);

    impl OwnedSid {
        /// Resolves one identifier written in the numeric form.
        fn parse(text: &str) -> std::result::Result<Self, AccessListRefusal> {
            let wide = wide_str(text);
            let mut sid: PSID = std::ptr::null_mut();
            // SAFETY: `wide` is a null-terminated wide buffer this function owns for the call, and
            // `sid` is a live out parameter.
            let parsed = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) };
            if parsed == 0 || sid.is_null() {
                return Err(AccessListRefusal::Unreadable(format!(
                    "the account {text} could not be resolved: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self(sid))
        }

        const fn as_psid(&self) -> PSID {
            self.0
        }
    }

    impl Drop for OwnedSid {
        fn drop(&mut self) {
            // SAFETY: the pointer came from the resolution above and is freed exactly once.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }

    /// The two accounts this process could have created a directory as.
    struct TokenAccounts {
        /// The buffer holding this process's user identifier.
        user: Vec<u64>,
        /// The buffer holding the identifier new objects of this process are owned by.
        owner: Vec<u64>,
    }

    impl TokenAccounts {
        /// Reads both from this process's own token.
        fn read() -> std::result::Result<Self, AccessListRefusal> {
            let token = TokenHandle::open()?;
            Ok(Self {
                user: token.information(TokenUser, std::mem::size_of::<TOKEN_USER>())?,
                owner: token.information(TokenOwner, std::mem::size_of::<TOKEN_OWNER>())?,
            })
        }

        /// Returns this process's user, which points into the buffer this holds.
        fn user(&self) -> PSID {
            // SAFETY: the buffer holds a `TOKEN_USER` the kernel wrote, and a `Vec<u64>` is aligned
            // for the pointer inside it.
            unsafe { std::ptr::read(self.user.as_ptr().cast::<TOKEN_USER>()) }
                .User
                .Sid
        }

        /// Returns the owner new objects of this process receive.
        fn owner(&self) -> PSID {
            // SAFETY: the buffer holds a `TOKEN_OWNER` the kernel wrote, aligned as above.
            unsafe { std::ptr::read(self.owner.as_ptr().cast::<TOKEN_OWNER>()) }.Owner
        }
    }

    /// This process's own token, closed when it goes out of scope.
    struct TokenHandle(HANDLE);

    impl TokenHandle {
        /// Opens the token for reading.
        fn open() -> std::result::Result<Self, AccessListRefusal> {
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: the process handle is a pseudo-handle that needs no release, and `token` is a
            // live out parameter.
            let opened =
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
            if opened == 0 || token.is_null() {
                return Err(AccessListRefusal::Unreadable(format!(
                    "this process's own token could not be read: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self(token))
        }

        /// Reads one class of token information into an aligned buffer.
        fn information(
            &self,
            class: TOKEN_INFORMATION_CLASS,
            least: usize,
        ) -> std::result::Result<Vec<u64>, AccessListRefusal> {
            let mut needed: u32 = 0;
            // SAFETY: a null buffer with a zero length asks for the size, which is what this call is
            // for; `needed` is a live out parameter and the failure it returns is expected.
            let _ = unsafe {
                GetTokenInformation(self.0, class, std::ptr::null_mut(), 0, &raw mut needed)
            };
            let bytes = usize::try_from(needed).unwrap_or(0).max(least);
            let mut buffer = vec![0_u64; bytes.div_ceil(8).max(1)];
            let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
            // SAFETY: the buffer holds `length` bytes, which is at least the size the call above
            // reported, and `needed` is a live out parameter.
            let read = unsafe {
                GetTokenInformation(
                    self.0,
                    class,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &raw mut needed,
                )
            };
            if read == 0 {
                return Err(AccessListRefusal::Unreadable(format!(
                    "this process's own accounts could not be read: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if usize::try_from(needed).unwrap_or(0) < least {
                return Err(AccessListRefusal::Unreadable(format!(
                    "this process's own token returned {needed} bytes where {least} were needed"
                )));
            }
            Ok(buffer)
        }
    }

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from the open above and is closed exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// Compares two identifiers, treating a missing one as no match.
    fn equal(left: PSID, right: PSID) -> bool {
        if left.is_null() || right.is_null() {
            return false;
        }
        // SAFETY: both pointers name live identifiers inside buffers this call does not outlive.
        unsafe { EqualSid(left, right) != 0 }
    }

    /// Names one identifier for a refusal.
    fn describe(sid: PSID) -> String {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is live and `text` is a live out parameter.
        let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
        if converted == 0 || text.is_null() {
            return "an account that could not be named".to_owned();
        }
        let mut length = 0_usize;
        // SAFETY: the buffer the conversion allocated is null-terminated, so the scan stops inside it.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: the buffer holds `length` code units before its terminator.
        let described =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: the buffer came from the conversion above and is freed exactly once.
        unsafe {
            LocalFree(text.cast());
        }
        described
    }

    /// Encodes a path for the wide form of a Windows call.
    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt as _;

        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Encodes a string for the wide form of a Windows call.
    fn wide_str(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Creates a file with one explicit security descriptor, written as SDDL.
    ///
    /// For this crate's tests of [`FileAccess`], which need files carrying lists, labels and
    /// entries no ordinary creation gives them. The product writes no list.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the descriptor cannot be built or the file cannot
    /// be created with it.
    #[cfg(test)]
    pub(crate) fn create_file_with_descriptor(
        path: &Path,
        descriptor: &str,
    ) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        };

        let wide_path = wide(path.as_os_str());
        let built = BuiltDescriptor::parse(descriptor)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: built.0,
            bInheritHandle: 0,
        };
        // SAFETY: `wide_path` is a null-terminated wide buffer this function owns for the call, and
        // `attributes` points at a descriptor that lives until `built` is dropped, after the call.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_WRITE,
                0,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the handle came from the creation above and is closed exactly once.
        unsafe {
            CloseHandle(handle);
        }
        Ok(())
    }

    /// Sets a directory's discretionary list, written as SDDL, without carrying it to anything the
    /// directory already holds: the older call used here changes the one object it names.
    ///
    /// For this crate's tests of a file that inherited its list before its directory's changed.
    /// The product writes no list.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the descriptor cannot be built or set.
    #[cfg(test)]
    pub(crate) fn set_list_without_propagation(
        path: &Path,
        descriptor: &str,
    ) -> std::io::Result<()> {
        use windows_sys::Win32::Security::SetFileSecurityW;

        let wide_path = wide(path.as_os_str());
        let built = BuiltDescriptor::parse(descriptor)?;
        // SAFETY: `wide_path` is a null-terminated wide buffer this function owns for the call, and
        // the descriptor lives until `built` is dropped, after the call.
        let set =
            unsafe { SetFileSecurityW(wide_path.as_ptr(), DACL_SECURITY_INFORMATION, built.0) };
        if set == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// A security descriptor built from SDDL, freed when it goes out of scope.
    #[cfg(test)]
    struct BuiltDescriptor(PSECURITY_DESCRIPTOR);

    #[cfg(test)]
    impl BuiltDescriptor {
        fn parse(descriptor: &str) -> std::io::Result<Self> {
            let wide_descriptor = wide_str(descriptor);
            let mut built: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: the text is a null-terminated wide buffer this function owns for the call,
            // `built` is a live out parameter, and the size parameter is optional.
            let parsed = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide_descriptor.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut built,
                    std::ptr::null_mut(),
                )
            };
            if parsed == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(built))
        }
    }

    #[cfg(test)]
    impl Drop for BuiltDescriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor was allocated by the conversion above and is freed once.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// An account the tests name: the local system.
        fn system() -> Account {
            Account(vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
        }

        fn entry(kind: EntryKind, flags: u32, mask: u32) -> AccessEntry {
            AccessEntry {
                kind,
                flags: u8::try_from(flags).expect("an entry's flags fit a byte"),
                mask,
                account: system(),
            }
        }

        /// A generic right reads as the file rights it stands for, and a mask with none reads as
        /// it is.
        #[test]
        fn generic_rights_read_as_the_file_rights_they_stand_for() {
            assert_eq!(file_rights(GENERIC_ALL), FILE_ALL_ACCESS);
            assert_eq!(file_rights(GENERIC_READ), FILE_GENERIC_READ);
            assert_eq!(file_rights(GENERIC_WRITE), FILE_GENERIC_WRITE);
            assert_eq!(file_rights(GENERIC_EXECUTE), FILE_GENERIC_EXECUTE);
            assert_eq!(
                file_rights(GENERIC_READ | GENERIC_EXECUTE),
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            );
            assert_eq!(file_rights(FILE_ALL_ACCESS), FILE_ALL_ACCESS);
            assert_eq!(file_rights(FILE_GENERIC_READ), FILE_GENERIC_READ);
        }

        /// A descriptor records nothing set on the file itself only when a list is present with
        /// entries, neither list is protected, and every entry of a list that records inheritance
        /// is marked inherited: each case below changes one thing from the control, which records
        /// inheritance in both lists. A list written the older way records no inheritance, so an
        /// entry in it that is not marked inherited says nothing either way.
        #[test]
        fn only_a_list_that_records_inheritance_shows_an_entry_set_here() {
            fn entries(access: &mut FileAccess) -> &mut Vec<AccessEntry> {
                access
                    .discretionary
                    .entries
                    .as_mut()
                    .expect("the control has a list")
            }

            let control = FileAccess {
                owner: system(),
                discretionary: AccessList {
                    protected: false,
                    records_inheritance: true,
                    entries: Some(vec![entry(
                        EntryKind::Allow,
                        INHERITED_ACE,
                        FILE_ALL_ACCESS,
                    )]),
                },
                system: SystemList {
                    protected: false,
                    records_inheritance: true,
                    labels: vec![entry(EntryKind::Label, INHERITED_ACE, 1)],
                },
            };
            assert!(control.records_nothing_set_here());

            let changed = |change: &dyn Fn(&mut FileAccess)| {
                let mut access = control.clone();
                change(&mut access);
                access
            };
            for (what, access) in [
                (
                    "a protected list of inherited entries",
                    changed(&|access| access.discretionary.protected = true),
                ),
                (
                    "an entry set here",
                    changed(&|access| {
                        entries(access).push(entry(EntryKind::Deny, 0, FILE_GENERIC_WRITE));
                    }),
                ),
                ("an empty list", changed(&|access| entries(access).clear())),
                (
                    "no list",
                    changed(&|access| access.discretionary.entries = None),
                ),
                (
                    "a protected system list",
                    changed(&|access| access.system.protected = true),
                ),
                (
                    "a label set here",
                    changed(&|access| access.system.labels = vec![entry(EntryKind::Label, 0, 1)]),
                ),
            ] {
                assert!(!access.records_nothing_set_here(), "{what}");
                assert_ne!(access, control, "{what}");
            }
            let absent = changed(&|access| access.discretionary.entries = None);
            assert_ne!(
                absent,
                changed(&|access| entries(access).clear()),
                "no list is not an empty one"
            );

            // Where there is no list, the descriptor still says whether it is protected and
            // whether it records inheritance, and each is compared: the control reads equal.
            let reread = absent.clone();
            assert_eq!(reread, absent);
            let mut protected = absent.clone();
            protected.discretionary.protected = true;
            assert_ne!(protected, absent, "a protected absent list");
            let mut unrecorded = absent.clone();
            unrecorded.discretionary.records_inheritance = false;
            assert_ne!(
                unrecorded, absent,
                "an absent list that records no inheritance"
            );

            // Written the older way, neither list says which of its entries it inherited.
            let older = changed(&|access| {
                access.discretionary.records_inheritance = false;
                *entries(access) = vec![entry(EntryKind::Allow, 0, FILE_ALL_ACCESS)];
                access.system.records_inheritance = false;
                access.system.labels = vec![entry(EntryKind::Label, 0, 1)];
            });
            assert!(older.records_nothing_set_here(), "{older:?}");
            assert_ne!(older, control);
        }

        /// The entry types this host evaluates, and the ones it names and refuses.
        #[test]
        fn only_allows_denies_and_labels_are_evaluated() {
            assert_eq!(entry_kind(0, false), Ok(EntryKind::Allow));
            assert_eq!(entry_kind(1, false), Ok(EntryKind::Deny));
            assert_eq!(entry_kind(0x11, true), Ok(EntryKind::Label));
            for (kind, named) in [
                (0x12, "a resource attribute"),
                (0x13, "a central access policy"),
                (0x14, "a process trust label"),
                (0x15, "an access filter"),
            ] {
                assert_eq!(entry_kind(kind, true), Err(named.to_owned()));
            }
            // A label in the discretionary list, an allow in the system list, and a callback,
            // an object and a compound entry anywhere.
            for (kind, system) in [(0x11, false), (0, true), (9, false), (5, false), (4, false)] {
                assert!(entry_kind(kind, system).is_err(), "{kind} in {system}");
            }
        }

        /// An account is written the way Windows writes one.
        #[test]
        fn an_account_is_written_as_windows_writes_it() {
            assert_eq!(format!("{:?}", system()), "S-1-5-18");
        }
    }
}

#[cfg(windows)]
pub use self::windows::{
    AccessListRefusal, FileAccess, check_access_list, current_job_limit_flags, open_child,
};
/// For this crate's own tests of files a wider list would let another account reach, and of the
/// access reader.
#[cfg(all(windows, test))]
pub(crate) use self::windows::{
    create_directory_with_list, create_file_with_descriptor, set_list_without_propagation,
};

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

/// Reads the environment identity a runtime or state directory records.
///
/// Every directory this host creates for an environment carries the complete identity, because an
/// eight-character prefix is a directory name rather than a name that is unique. A directory whose
/// marker is missing or unreadable is not an environment.
///
/// # Errors
///
/// Returns an error when the marker is missing or does not hold an identity.
pub fn read_environment_marker(directory: &Path) -> Result<EnvironmentId> {
    let path = directory.join(ENVIRONMENT_MARKER);
    let bytes = read_owner_only_file(&path, MAX_ENVIRONMENT_ID_LEN)?.ok_or_else(|| {
        IpcError::IdentityUnavailable {
            what: "environment identity",
            detail: format!("{}: no marker", path.display()),
        }
    })?;
    let text = String::from_utf8(bytes).map_err(|_| IpcError::IdentityUnavailable {
        what: "environment identity",
        detail: format!("{}: the marker is not text", path.display()),
    })?;
    text.trim()
        .parse::<Uuid>()
        .map(EnvironmentId::new)
        .map_err(|error| IpcError::IdentityUnavailable {
            what: "environment identity",
            detail: format!("{}: {error}", path.display()),
        })
}

/// Reads an installation's recorded environment identity, when one exists.
///
/// # Errors
///
/// Returns an error when the file exists and cannot be read, or does not hold an identity.
fn read_environment_id(path: &Path) -> Result<Option<EnvironmentId>> {
    let Some(bytes) = read_owner_only_file(path, MAX_ENVIRONMENT_ID_LEN)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| IpcError::IdentityUnavailable {
        what: "environment identity",
        detail: format!("{}: the file is not text", path.display()),
    })?;
    text.trim()
        .parse::<Uuid>()
        .map(|value| Some(EnvironmentId::new(value)))
        .map_err(|error| IpcError::IdentityUnavailable {
            what: "environment identity",
            detail: format!("{}: {error}", path.display()),
        })
}

/// The largest recorded environment identity this host will read.
const MAX_ENVIRONMENT_ID_LEN: u64 = 128;

/// Reads a small file this user owns, without following a link or waiting for a writer.
///
/// A path check followed by a read checks one file and reads whatever the name points at by then.
/// One handle, checked and read, cannot be swapped underneath. The non-blocking open is what stops
/// a named pipe with the right name from holding a host's startup open indefinitely.
///
/// # Errors
///
/// Returns an error when the file exists but is not one this host wrote.
#[cfg(unix)]
pub fn read_owner_only_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;

    use rustix::fs::{Mode, OFlags};

    let file = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => std::fs::File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::MLINK) => {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "this file must not be a symbolic link",
            });
        }
        Err(error) => return Err(IpcError::io("open", path, std::io::Error::from(error))),
    };
    let metadata = file
        .metadata()
        .map_err(|error| IpcError::io("inspect", path, error))?;
    if !metadata.is_file() {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file must be a regular file",
        });
    }
    check_owner_only(path, &metadata)?;
    if metadata.len() > limit {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file is larger than anything this host writes here",
        });
    }
    let mut bytes = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| IpcError::io("read", path, error))?;
    if bytes.len() as u64 > limit {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file is larger than anything this host writes here",
        });
    }
    Ok(Some(bytes))
}

/// Reads a small file this user owns, checking its access-control list from the handle it opened.
///
/// Windows has no mode bits, so the question the Unix reader asks of an owner and a mode is asked of
/// the file's list, read from the handle rather than from the name: it belongs to this user and
/// grants no account the machine does not already trust. A symbolic link or a junction under the
/// file's name is opened as the link itself and refused by its attributes, never followed. This is
/// what the descriptor reader does for a worker's descriptor; the environment identity is read here.
///
/// # Errors
///
/// Returns an error when the file exists but is not one this host wrote.
#[cfg(not(unix))]
pub fn read_owner_only_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::io::AsHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    // Opened without following a reparse point, so a link planted under this name opens as the link
    // and is refused below rather than sending this read wherever it points.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(IpcError::io("open", path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| IpcError::io("inspect", path, error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file must not be a symbolic link or a junction",
        });
    }
    if !metadata.is_file() {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file must be a regular file",
        });
    }
    if metadata.len() > limit {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file is larger than anything this host writes here",
        });
    }
    match check_access_list(file.as_handle(), &path.display().to_string(), false) {
        Ok(()) => {}
        Err(AccessListRefusal::Policy(_)) => {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "this file's access-control list grants an account this host does not trust",
            });
        }
        Err(AccessListRefusal::Unreadable(detail)) => {
            return Err(IpcError::io("inspect", path, std::io::Error::other(detail)));
        }
    }
    // Bounded by one byte more than the limit, so a file that grew between the check and the read is
    // refused rather than read.
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| IpcError::io("read", path, error))?;
    if bytes.len() as u64 > limit {
        return Err(IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason: "this file is larger than anything this host writes here",
        });
    }
    Ok(Some(bytes))
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

    // The contents are complete and on disk before the name exists. Creating the file at its final
    // name and writing afterwards would let a reader open it in the window where it is empty, and
    // would leave an empty file behind after a crash: for the environment identity that is the
    // difference between reading an identity and reading nothing at all.
    //
    // A hard link publishes it. Unlike a rename it refuses to replace an existing name, so it
    // answers "who got there first" as well as making the publication atomic.
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
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    let linked =
        std::fs::hard_link(&temporary, path).map_err(|error| IpcError::io("publish", path, error));
    let _ = std::fs::remove_file(&temporary);
    linked?;
    sync_directory(directory)
}

/// Flushes the directory a file was just published in, so the name survives a crash.
///
/// A failure here is reported, not swallowed. The caller has been told its file is published; if
/// the directory entry never reached the disk that claim is wrong, and the caller is the only one
/// that can decide what to do about it.
fn sync_directory(directory: &Path) -> Result<()> {
    flush_directory(directory, NameKind::File)
        .map_err(|error| IpcError::io("flush", directory, error))
}

/// How many links the walk over a path follows before it gives up.
///
/// A backstop rather than the rule. Every kernel this runs on applies a limit of its own, usually
/// lower than this, and refuses to open through a longer chain before the walk ever sees it. What
/// this is for is the walk itself: a bound it holds to whatever the filesystem underneath it does.
pub const MAX_PATH_LINKS: usize = 40;

/// Flushes the directory entry of every name a directory's path is made of, and the directory
/// itself.
///
/// A path is a chain of names, and losing any one of them leaves a store nothing reaches.
/// Creating the levels a caller was missing is not enough: another opener may have created one a
/// moment ago and not yet flushed it. The chain is also not only the components a caller spelled.
/// A link is a name in a directory, it leads somewhere, and the rest of the path continues from
/// there, so this resolves the path the way the kernel does, one component at a time, flushing the
/// directory each name lives in and continuing from a link's target when it meets a symbolic link
/// or a junction. Following each link once is what makes [`MAX_PATH_LINKS`] the same kind of bound
/// the kernel applies rather than a count of repeated work.
///
/// A failure is reported: a caller that cannot open the directories its own path is made of cannot
/// establish that the path survives a crash. One failure is not, on Windows: there a directory is
/// flushed only through a handle that may add to it, and a directory this account may not add a
/// directory to, such as `C:\Users` for an account that does not administer the machine, holds no
/// name any caller running as this account made. So a directory on the way whose flush is refused
/// for want of that right is passed over. The directory at the end of the path is not: that is
/// where the caller adds its files.
///
/// # Errors
///
/// Returns the operating system's error when a directory on the path cannot be inspected or
/// flushed, and an error when the path follows more than [`MAX_PATH_LINKS`] links.
pub fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    let resolved = walk_path_names(directory, &|holder| {
        flush_directory(holder, NameKind::Directory)
    })?;
    flush_directory(&resolved, NameKind::File)
}

/// The walk behind [`flush_path_names`]: flushes the directory each name on the path lives in with
/// `flush_holder`, and returns the directory the path resolves to.
fn walk_path_names(
    directory: &Path,
    flush_holder: &dyn Fn(&Path) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    use std::collections::VecDeque;
    use std::path::Component;

    /// One component of a path, owned, so a link's target can be spliced into the walk.
    enum Part {
        /// The root a path starts from, and on Windows its drive or share, which is nobody's name.
        Root(std::ffi::OsString),
        /// `.`, which names nothing.
        Current,
        /// `..`, which leaves the directory reached so far.
        Parent,
        /// A name in the directory reached so far.
        Name(std::ffi::OsString),
    }

    fn parts(path: &Path) -> Vec<Part> {
        path.components()
            .map(|component| match component {
                Component::Prefix(_) | Component::RootDir => {
                    Part::Root(component.as_os_str().to_os_string())
                }
                Component::CurDir => Part::Current,
                Component::ParentDir => Part::Parent,
                Component::Normal(name) => Part::Name(name.to_os_string()),
            })
            .collect()
    }

    // An absolute path keeps its `..` components on Unix, where they are resolved against the
    // directory actually reached, and loses them on Windows, whose own path rules resolve them
    // against the spelling before the filesystem sees the path.
    let mut remaining: VecDeque<Part> = parts(&std::path::absolute(directory)?).into();
    let mut resolved = PathBuf::new();
    let mut flushed: Vec<PathBuf> = Vec::new();
    let mut followed = 0_usize;

    while let Some(part) = remaining.pop_front() {
        let name = match part {
            Part::Root(root) => {
                resolved.push(root);
                continue;
            }
            Part::Current => continue,
            Part::Parent => {
                resolved.pop();
                continue;
            }
            Part::Name(name) => name,
        };
        // The directory this name lives in, which is what holds it.
        let holder = resolved.clone();
        if !flushed.contains(&holder) {
            let outcome = flush_holder(&holder);
            #[cfg(windows)]
            let outcome = match outcome {
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
                other => other,
            };
            outcome?;
            flushed.push(holder.clone());
        }
        resolved.push(&name);
        // A failure here is reported rather than skipped. It can be the filesystem refusing to say,
        // or a name something removed while this walk was going through it; either way, what the
        // walk cannot see it cannot make durable.
        if !std::fs::symlink_metadata(&resolved)?
            .file_type()
            .is_symlink()
        {
            continue;
        }
        followed += 1;
        if followed > MAX_PATH_LINKS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} follows more than {MAX_PATH_LINKS} links",
                    directory.display()
                ),
            ));
        }
        // The rest of the path continues from the target, read the way the link names it: an
        // absolute one starts again at its own root, one that starts at the root of a drive starts
        // at the root of the link's drive, and a relative one continues from the directory the link
        // lives in.
        let target = holder.join(std::fs::read_link(&resolved)?);
        resolved = PathBuf::new();
        for part in parts(&target).into_iter().rev() {
            remaining.push_front(part);
        }
    }
    Ok(resolved)
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

    /// KR-REQ-03.08: an environment identity binds one installation and one operating-system
    /// user. Each installation's state root holds its own random identity, written once and read
    /// back unchanged, so two installations on one machine are two environments rather than one
    /// machine's fingerprint; the identity lives in a file this user owns inside a directory this
    /// user owns, and nobody else is granted either (on Unix the modes are `0600` and `0700`, and
    /// on Windows each access-control list names this user and the machine's own accounts only);
    /// and an installation's default state root is inside this user's own profile.
    #[test]
    fn an_environment_identity_is_one_installations_and_one_users() {
        let root = temporary_root("bound");
        let first = HostPaths::new(root.join("r1"), root.join("s1")).expect("roots");
        let second = HostPaths::new(root.join("r2"), root.join("s2")).expect("roots");
        let one = first.open_environment_id().expect("allocates");
        let other = second.open_environment_id().expect("allocates");
        assert_ne!(one, other, "two installations are two environments");
        assert_eq!(
            HostPaths::new(root.join("r1"), root.join("s1"))
                .expect("roots")
                .open_environment_id()
                .expect("reads"),
            one,
            "an installation keeps its identity"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let file = std::fs::metadata(first.environment_id_file()).expect("the identity file");
            assert_eq!(file.mode() & 0o777, OWNER_ONLY_FILE_MODE);
            assert_eq!(file.uid(), current_uid());
            let directory = std::fs::metadata(first.state_root()).expect("the state root");
            assert_eq!(directory.mode() & 0o777, OWNER_ONLY_DIRECTORY_MODE);
            assert_eq!(directory.uid(), current_uid());
        }
        #[cfg(unix)]
        if cfg!(target_os = "macos") || std::env::var_os("XDG_STATE_HOME").is_none() {
            assert!(
                default_state_root()
                    .expect("a default state root")
                    .starts_with(home_directory().expect("a home directory")),
                "an installation's own state is kept in its user's home"
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle as _;

            // The same question asked of the access-control lists, read back from handles: each
            // is owned by this user and grants nobody but this user and the machine's own
            // accounts, and the state root's list is protected from the directory above it.
            check_access_list(
                opened(first.state_root()).as_handle(),
                "the state root",
                true,
            )
            .expect("the state root is this user's alone");
            let file = std::fs::File::open(first.environment_id_file()).expect("the identity file");
            check_access_list(file.as_handle(), "the identity file", false)
                .expect("the identity file is this user's alone");
            let profile = std::env::var_os("LOCALAPPDATA").expect("this user's local profile");
            assert!(
                default_state_root()
                    .expect("a default state root")
                    .starts_with(profile),
                "an installation's own state is kept in its user's profile"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_environment_identity_is_allocated_once_and_then_read() {
        let root = temporary_root("identity");
        let paths = HostPaths::new(root.join("run"), root.join("state")).expect("roots");
        let first = paths.open_environment_id().expect("allocates");
        let second = paths.open_environment_id().expect("reads");
        assert_eq!(first, second);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A host that was given relative roots holds absolute ones.
    ///
    /// The roots travel: a worker is started in a directory of its own and is told where the
    /// installation is, and a relative root would send it somewhere else. Everything derived from
    /// them travels with them, including the endpoint one process signs and another compares.
    #[test]
    fn a_relative_root_is_resolved_where_the_host_is_built() {
        let paths = HostPaths::new("kr-relative-runtime", "kr-relative-state").expect("roots");
        let here = std::env::current_dir().expect("this process has a directory");
        assert_eq!(paths.runtime_root(), here.join("kr-relative-runtime"));
        assert_eq!(paths.state_root(), here.join("kr-relative-state"));
        let environment = paths.environment(EnvironmentId::new(crate::new_uuid()));
        assert!(environment.runtime_dir().is_absolute());
        assert!(environment.state_dir().is_absolute());
        assert!(
            environment
                .worker_dir(SessionId::new(crate::new_uuid()))
                .starts_with(paths.state_root()),
            "and every path below them stays inside the root it was derived from"
        );
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

    /// Makes `link` a symbolic link to `target`, or says why this machine would not.
    ///
    /// Windows asks for a privilege to create one, held by an elevated account or by a machine in
    /// developer mode and by nothing else. A machine that withholds it is reported rather than
    /// treated as a pass: the check under test is the same on both platforms, and only the making
    /// of the link differs.
    fn link_to(target: &Path, link: &Path) -> std::result::Result<(), String> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).map_err(|error| error.to_string())
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link).map_err(|error| error.to_string())
        }
    }

    #[test]
    fn a_symbolic_link_is_never_used_as_a_private_directory() {
        let root = temporary_root("symlink");
        let elsewhere = root.join("elsewhere");
        create_private_tree(&root, &elsewhere).expect("creates");
        let link = root.join("link");
        match link_to(&elsewhere, &link) {
            Ok(()) => {
                let error = create_private_tree(&root, &link).expect_err("refuses");
                assert!(matches!(error, IpcError::Io { .. }));
            }
            Err(refusal) => {
                // Nothing here is asserted about a link this machine would not make, and a runner
                // hides a printed line unless the test fails. So the refusal is named where a
                // reader will see it: the test's own name says it did not establish what it is
                // for, and the reason says why.
                panic!(
                    "this machine would not create a symbolic link, so the refusal of one was not \
                     exercised. On Windows that needs an elevated account or developer mode; see \
                     docs/host/README.md. The operating system said: {refusal}"
                );
            }
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn one_caller_wins_the_environment_identity() {
        let root = temporary_root("race");
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("roots");
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
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("roots");
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
        let paths = HostPaths::new(root.join("run"), root.join("state")).expect("roots");
        let environment = paths.environment(EnvironmentId::new(Uuid::NIL));
        environment.create().expect("directories");
        environment.controller_endpoint().expect("fits");
        environment.rendezvous_endpoint().expect("fits");
        environment
            .worker_endpoint(DisplayNumber::new(999_999))
            .expect("fits");
        std::fs::remove_dir_all(&root).ok();
    }

    /// Opens a directory the way the owner-only check does.
    #[cfg(windows)]
    fn opened(path: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .expect("opens the directory")
    }

    #[cfg(windows)]
    #[test]
    fn a_private_directory_carries_a_protected_owner_only_list() {
        use std::os::windows::io::AsHandle as _;

        let root = temporary_root("acl-owner");
        let path = root.join("private");
        create_private_directory(&path).expect("creates");

        check_access_list(opened(&path).as_handle(), "the directory", true)
            .expect("the list is this host's own and nothing above it can widen it");

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_directory_that_grants_another_account_is_refused() {
        let root = temporary_root("acl-wide");
        let path = root.join("wide");
        // `WD` is the Everyone group and `GA` is full control.
        windows::create_directory_with_list(&path, "D:P(A;;GA;;;OW)(A;;GA;;;WD)").expect("creates");

        let error = create_private_directory(&path).expect_err("refuses");

        assert!(
            matches!(
                &error,
                IpcError::DirectoryAccessRefused { detail, .. } if detail.contains("grants access to")
            ),
            "a list naming Everyone is refused, got {error}"
        );
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_directory_that_inherits_its_list_is_adopted_but_is_not_a_boundary() {
        use std::os::windows::io::AsHandle as _;

        let root = temporary_root("acl-inherited");
        let path = root.join("inherited");
        // Created without a list of its own, so it inherits the one above it.
        std::fs::create_dir(&path).expect("creates");

        let refusal = check_access_list(opened(&path).as_handle(), "the directory", true)
            .expect_err("a directory that inherits its list is not a boundary");
        assert!(
            matches!(refusal, AccessListRefusal::Policy(detail) if detail.contains("inherits")),
            "the refusal names inheritance"
        );
        // The entries it inherited name this user, the local system and the administrators group,
        // so it is still a directory this host can use.
        create_private_directory(&path).expect("adopts a directory of this user's own");

        std::fs::remove_dir_all(&root).ok();
    }

    /// Runs one command-line tool and fails the test when it fails.
    #[cfg(windows)]
    fn run(program: &str, arguments: &[&std::ffi::OsStr]) -> String {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} starts: {error}"));
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{program} failed: {printed}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        printed
    }

    /// KR-REQ-03.08: the owner-only reader, which reads the environment identity, checks the file's
    /// access-control list, so a file whose list has been widened is refused rather than read. As
    /// written the file is owner-only and reads; granting Everyone makes the next read refuse it.
    #[cfg(windows)]
    #[test]
    fn a_widened_owner_only_file_is_refused_by_the_reader() {
        let root = temporary_root("owner-only-read");
        let path = root.join("run").join("environment");
        create_private_tree(&root, path.parent().expect("a directory")).expect("the tree");
        write_owner_only_file(&path, b"an environment identity").expect("writes");
        assert_eq!(
            read_owner_only_file(&path, 128)
                .expect("reads")
                .expect("present"),
            b"an environment identity",
            "as written it is owner-only and reads"
        );
        run(
            "icacls.exe",
            &[path.as_os_str(), "/grant".as_ref(), "*S-1-1-0:F".as_ref()],
        );
        let error = read_owner_only_file(&path, 128).expect_err("a widened file is refused");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// A directory under the system's temporary directory that inherits its list from the one
    /// above, as a person's own directories do, removed when the test ends however it ends.
    #[cfg(windows)]
    struct Inheriting(PathBuf);

    #[cfg(windows)]
    impl Inheriting {
        fn new(name: &str) -> Self {
            let suffix = crate::new_uuid().to_string();
            let path = std::env::temp_dir().join(format!("kr-access-{name}-{}", &suffix[..8]));
            std::fs::create_dir(&path).expect("a directory that inherits its list");
            Self(path)
        }

        /// A file of this directory's own, made as any program makes one.
        fn file(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, name).expect("a file made in the directory");
            path
        }

        /// A file made with one explicit descriptor.
        fn described(&self, name: &str, descriptor: &str) -> PathBuf {
            let path = self.0.join(name);
            create_file_with_descriptor(&path, descriptor)
                .unwrap_or_else(|error| panic!("{name} is created with {descriptor}: {error}"));
            path
        }
    }

    #[cfg(windows)]
    impl Drop for Inheriting {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Reads who can reach a file, failing the test when it cannot.
    #[cfg(windows)]
    fn access(path: &Path) -> FileAccess {
        FileAccess::of(path)
            .unwrap_or_else(|refusal| panic!("{} is read: {refusal:?}", path.display()))
    }

    /// Two files made in one directory have the same access, which records nothing set on either
    /// file and is owned by the account this process gives new files: what a replacement made
    /// beside a document carries.
    #[cfg(windows)]
    #[test]
    fn two_files_made_in_one_directory_have_the_same_access() {
        let directory = Inheriting::new("same");
        let first = access(&directory.file("first"));
        let second = access(&directory.file("second"));
        assert_eq!(first, second);
        assert!(first.records_nothing_set_here(), "{first:?}");
        assert!(first.is_owned_as_new_files_are().expect("the token"));
    }

    /// An entry set on the file itself, a list protected from its directory, and another owner
    /// each make a file's access another than a new file's beside it, and each is told apart from
    /// a file the directory made; the control is a sibling left as it was made.
    #[cfg(windows)]
    #[test]
    fn an_entry_set_here_a_protected_list_or_another_owner_is_another_access() {
        let directory = Inheriting::new("changed");
        let made = access(&directory.file("control"));
        let granted = directory.file("granted");
        run(
            "icacls.exe",
            &[
                granted.as_os_str(),
                "/grant".as_ref(),
                "*S-1-1-0:(R)".as_ref(),
            ],
        );
        let protected = directory.file("protected");
        run(
            "icacls.exe",
            &[protected.as_os_str(), "/inheritance:d".as_ref()],
        );
        let owned = directory.file("owned");
        run(
            "icacls.exe",
            &[
                owned.as_os_str(),
                "/setowner".as_ref(),
                "*S-1-5-18".as_ref(),
            ],
        );

        let granted = access(&granted);
        let protected = access(&protected);
        let owned = access(&owned);
        for (what, changed) in [
            ("an explicit entry", &granted),
            ("a protected list", &protected),
            ("another owner", &owned),
        ] {
            assert_ne!(changed, &made, "{what}");
        }
        assert!(!granted.records_nothing_set_here(), "{granted:?}");
        assert!(!protected.records_nothing_set_here(), "{protected:?}");
        assert!(
            owned.records_nothing_set_here(),
            "only its owner changed: {owned:?}"
        );
        assert!(!owned.is_owned_as_new_files_are().expect("the token"));
        assert!(made.is_owned_as_new_files_are().expect("the token"));
        assert_eq!(access(&directory.file("again")), made, "the control holds");
    }

    /// A file whose directory passes one entry fewer has another access than one whose directory
    /// passes it, though neither records anything set on the file itself.
    #[cfg(windows)]
    #[test]
    fn a_file_whose_directory_passes_one_entry_fewer_has_another_access() {
        let fewer = Inheriting::new("fewer");
        let more = Inheriting::new("more");
        run(
            "icacls.exe",
            &[
                more.0.as_os_str(),
                "/grant".as_ref(),
                "*S-1-1-0:(OI)(R)".as_ref(),
            ],
        );
        let without = access(&fewer.file("without"));
        let with = access(&more.file("with"));
        assert_ne!(without, with);
        assert!(without.records_nothing_set_here() && with.records_nothing_set_here());
        assert_eq!(access(&fewer.file("control")), without);
    }

    /// Entries are read in their order and with their rights, a generic right as the file rights
    /// it stands for; a file with no list reads as one, and one whose list is empty cannot be
    /// read at all.
    #[cfg(windows)]
    #[test]
    fn order_rights_and_an_absent_list_are_read_as_they_are() {
        let directory = Inheriting::new("described");
        // The deny names writing the contents alone, so that neither order keeps this process from
        // opening the file to read it.
        let allow_deny = "D:P(A;;FR;;;WD)(D;;0x2;;;WD)";
        let first = access(&directory.described("allow-deny", allow_deny));
        assert_eq!(
            access(&directory.described("allow-deny-again", allow_deny)),
            first,
            "the same descriptor reads the same"
        );
        assert_ne!(
            access(&directory.described("deny-allow", "D:P(D;;0x2;;;WD)(A;;FR;;;WD)")),
            first,
            "entries in another order"
        );
        let all = access(&directory.described("all", "D:P(A;;FA;;;WD)"));
        assert_ne!(
            access(&directory.described("read", "D:P(A;;FR;;;WD)")),
            all,
            "other rights"
        );
        assert_eq!(
            access(&directory.described("generic", "D:P(A;;GA;;;WD)")),
            all,
            "a generic right reads as the rights it stands for"
        );
        let absent = access(&directory.described("no-list", "D:NO_ACCESS_CONTROL"));
        assert_ne!(
            absent, all,
            "no list is not read as one that grants everything"
        );
        assert!(!absent.records_nothing_set_here());
        assert_eq!(
            access(&directory.described("no-list-again", "D:NO_ACCESS_CONTROL")),
            absent,
            "the same absent list reads the same"
        );
        assert_ne!(
            access(&directory.described("no-list-recorded", "D:AINO_ACCESS_CONTROL")),
            absent,
            "an absent list that records inheritance"
        );
        assert_ne!(
            access(&directory.described("no-list-protected", "D:PNO_ACCESS_CONTROL")),
            absent,
            "an absent list protected from its directory"
        );
        // An empty list grants nothing, not even the synchronisation every open of a file asks
        // for, so its owner cannot open it to read its descriptor: a read that failed, never a
        // file read as having no list.
        let empty = FileAccess::of(&directory.described("empty-list", "D:P"))
            .expect_err("a file whose list grants nothing cannot be opened");
        assert!(
            matches!(empty, AccessListRefusal::Unreadable(_)),
            "{empty:?}"
        );
    }

    /// A mandatory label is read with its policy: one that forbids reading up is another access
    /// than none, and than one that forbids only writing up; a label set on a file its directory
    /// made is another access than its sibling's.
    #[cfg(windows)]
    #[test]
    fn a_label_is_read_with_the_policy_it_sets() {
        let directory = Inheriting::new("labelled");
        let unlabelled = access(&directory.described("unlabelled", "D:P(A;;FA;;;WD)"));
        let no_read_up = "D:P(A;;FA;;;WD)S:(ML;;NRNW;;;ME)";
        let reading = access(&directory.described("no-read-up", no_read_up));
        assert_ne!(reading, unlabelled);
        assert_eq!(
            access(&directory.described("no-read-up-again", no_read_up)),
            reading
        );
        assert_ne!(
            access(&directory.described("no-write-up", "D:P(A;;FA;;;WD)S:(ML;;NW;;;ME)")),
            reading,
            "another policy"
        );
        let made = access(&directory.file("made"));
        let relabelled = directory.file("relabelled");
        run(
            "icacls.exe",
            &[
                relabelled.as_os_str(),
                "/setintegritylevel".as_ref(),
                "L".as_ref(),
            ],
        );
        assert_ne!(access(&relabelled), made, "a label set on the file");
        assert_eq!(access(&directory.file("sibling")), made, "the control");
    }

    /// Controls this host does not evaluate are refused rather than read: a conditional entry, a
    /// resource attribute and encryption. Beside each, a file without it reads.
    #[cfg(windows)]
    #[test]
    fn controls_this_host_does_not_evaluate_are_refused() {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_ENCRYPTED;

        let directory = Inheriting::new("refused");
        access(&directory.described("plain", "D:P(A;;FR;;;WD)(A;;FA;;;OW)"));
        let conditional = directory.described(
            "conditional",
            "D:P(XA;;FR;;;WD;(@User.Title==\"PM\"))(A;;FA;;;OW)",
        );
        let attribute = directory.described(
            "attribute",
            "D:P(A;;FR;;;WD)(A;;FA;;;OW)S:(RA;;;;;WD;(\"Secrecy\",TU,0x0,3))",
        );
        let encrypted = directory.file("encrypted");
        access(&directory.file("unencrypted"));
        run(
            "cipher.exe",
            &["/e".as_ref(), "/a".as_ref(), encrypted.as_os_str()],
        );
        assert_ne!(
            std::fs::metadata(&encrypted)
                .expect("reads the attributes")
                .file_attributes()
                & FILE_ATTRIBUTE_ENCRYPTED,
            0,
            "the file is encrypted"
        );
        for (what, path) in [
            ("a conditional entry", &conditional),
            ("a resource attribute", &attribute),
            ("encryption", &encrypted),
        ] {
            let refused = FileAccess::of(path).expect_err(what);
            assert!(
                matches!(refused, AccessListRefusal::Policy(_)),
                "{what}: {refused:?}"
            );
        }
    }

    /// A file whose owner may not read its descriptor is a read that failed, never a file with
    /// nothing in its lists; beside it, a file whose owner may read everything reads.
    #[cfg(windows)]
    #[test]
    fn a_descriptor_that_cannot_be_read_is_unreadable() {
        let directory = Inheriting::new("unreadable");
        access(&directory.described("readable", "D:P(A;;FA;;;OW)"));
        // The owner's own entry grants reading its contents and nothing else, which takes away
        // the reading of its descriptor an owner otherwise has.
        let unreadable = directory.described("unreadable", "D:P(A;;0x1;;;OW)");
        let refused = FileAccess::of(&unreadable).expect_err("the descriptor cannot be read");
        assert!(
            matches!(refused, AccessListRefusal::Unreadable(_)),
            "{refused:?}"
        );
    }

    /// A file that inherited its list before its directory's list changed without the change
    /// reaching it has another access than a file made there afterwards, though neither records
    /// anything set on the file itself: what reading a document alone cannot see, and what
    /// comparing the replacement with it does.
    #[cfg(windows)]
    #[test]
    fn a_file_that_inherited_before_its_directory_changed_differs_from_a_new_one() {
        let directory = Inheriting::new("unpropagated");
        let old = directory.file("old");
        let before = access(&old);
        assert_eq!(access(&directory.file("sibling")), before, "the control");
        set_list_without_propagation(
            &directory.0,
            "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;WD)",
        )
        .expect("the directory's list changes and nothing inside it does");
        assert_eq!(access(&old), before, "the file inside kept its list");
        let new = access(&directory.file("new"));
        assert_ne!(new, before);
        assert!(new.records_nothing_set_here() && before.records_nothing_set_here());
    }

    /// A path through a junction is flushed to where the junction leads.
    #[cfg(windows)]
    #[test]
    fn a_path_is_flushed_through_a_junction_to_its_end() {
        let root = temporary_root("flush-junction");
        let target = root.join("elsewhere");
        std::fs::create_dir(&target).expect("a directory to link to");
        let link = root.join("linked");
        // A junction needs no privilege to make, unlike a symbolic link.
        run(
            "cmd.exe",
            &[
                "/d".as_ref(),
                "/c".as_ref(),
                "mklink".as_ref(),
                "/J".as_ref(),
                link.as_os_str(),
                target.as_os_str(),
            ],
        );
        let store = link.join("store").join("inner");
        std::fs::create_dir_all(&store).expect("the levels, through the junction");
        flush_path_names(&store).expect("every name on the way is flushed");
        assert!(
            target.join("store").join("inner").is_dir(),
            "the levels are where the junction leads"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// The walk passes over a directory whose flush is refused for want of the right, and reports
    /// every other failure.
    #[cfg(windows)]
    #[test]
    fn the_walk_passes_over_a_directory_refused_for_want_of_the_right_and_reports_anything_else() {
        // Whether this account is refused a directory is a matter of the directory's list and of
        // the privileges the account holds, which override the list for an account that has them
        // turned on. So the refusal is given to the walk here rather than asked of a list: what is
        // under test is what the walk makes of it.
        let root = temporary_root("flush-walk");
        let refused = std::path::absolute(root.join("refused")).expect("an absolute path");
        let store = refused.join("store");
        std::fs::create_dir_all(&store).expect("two levels");
        let asked = std::cell::RefCell::new(Vec::new());
        let resolved = walk_path_names(&store, &|holder: &Path| {
            asked.borrow_mut().push(holder.to_path_buf());
            if holder == refused {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        })
        .expect("a directory refused for want of the right is passed over");
        assert_eq!(resolved, store, "the walk reaches the directory at the end");
        let asked = asked.into_inner();
        assert!(
            asked.contains(&refused),
            "the refused directory was asked: {asked:?}"
        );
        let above = std::path::absolute(&root).expect("an absolute path");
        assert!(
            asked.contains(&above),
            "and the directory above it was flushed: {asked:?}"
        );

        // Any other failure is reported.
        let failed = walk_path_names(&store, &|holder: &Path| {
            if holder == refused {
                Err(std::io::Error::other("the device did not answer"))
            } else {
                Ok(())
            }
        });
        assert!(
            failed.is_err_and(|error| error.kind() == std::io::ErrorKind::Other),
            "a failure that is not a refusal is the answer"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
