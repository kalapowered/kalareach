//! Where this host's installed releases are, which release a process runs, and the hold that keeps
//! a release on disk for as long as a process runs it.
//!
//! # The store
//!
//! A host installed with `kr host install` keeps every release it runs under one per-user
//! directory, the store, and never changes a release in place:
//!
//! | Path | What it is |
//! | --- | --- |
//! | `versions/<release>/` | One release: `bin/`, `shells/`, `share/` and `release.json`, read-only once it is there |
//! | `current` | A relative symbolic link to the release new processes start from |
//! | `staging/` | A release being unpacked and checked, before it is renamed into `versions/` |
//! | `trash/` | A release being removed, renamed out of `versions/` before anything of it goes |
//! | `roots/` | The runtime and state roots the control daemons of this store have served |
//! | `install.json` | The store's own record, which makes the directory a store |
//! | `update.lock`, `install.lock` | The locks an update and a starting control daemon take |
//!
//! An update puts the new release beside the old ones and renames a new `current` link over the
//! old one, and nothing else changes: whatever must follow an update names its path through
//! `current` ([`Running::stable`]), and whatever starts another process of its own release names
//! its release's own directory ([`Running::own`]).
//!
//! # Which release a process runs
//!
//! The kernel's record of the process's own image says, never the path the process was started
//! through: `proc_pidpath` on macOS, and `/proc/self/exe` on Linux and `GetModuleFileNameW` on
//! Windows, which is what the standard library reads on those two ([`image_path`]). On macOS the
//! standard library returns the path as started, so a `kr` started as `current/bin/kr` moments
//! before an update would resolve `current` afterwards and find the other release's files beside a
//! program of this one. Nothing else in the host's own crates asks where its program is.
//!
//! # The hold
//!
//! Each host executable of a store takes a shared lock on its release's `release.json` when it
//! starts ([`this_process`]) and keeps it until it exits; the kernel lets go of it however the
//! process ends. A release is removed only by whoever takes an exclusive lock on that same file
//! (`Store::retire`, which a Windows build does not have, since it keeps no store), which no
//! running process of the release lets happen, and it is renamed out of `versions/` while that lock
//! is held, before anything is deleted. A process that opened the manifest just as its release was
//! being removed still gets its shared lock once the remover lets go, so after locking it checks
//! that `versions/<release>/release.json` is still the very file it locked, and refuses to run when
//! it is not.
//!
//! A process that starts another from its own release holds the release for it until the other
//! has a hold of its own: the control daemon's hold covers the workers it launches, and an update
//! waits for the daemon's launches to settle before the daemon stops.
//!
//! Windows keeps no store here: a directory link there cannot be replaced in one step by a user
//! who does not administer the machine, so every Windows process runs as a build outside a store.

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
#[cfg(unix)]
use std::time::{Duration, Instant};

use kr_protocol::update::{MANIFEST_FILE, ReleaseManifest, ReleaseName};

/// The store's record, whose presence is what makes a directory a store.
pub const STORE_RECORD: &str = "install.json";

/// The link to the current release.
pub const CURRENT: &str = "current";

/// The directory each release is in.
pub const VERSIONS: &str = "versions";

/// The directory releases are unpacked and checked in.
pub const STAGING: &str = "staging";

/// The directory releases are moved into to be removed.
pub const TRASH: &str = "trash";

/// A host executable, by the name it has in every release's `bin/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Program {
    /// The command line.
    Kr,
    /// The command line's terminal restoration guard.
    AttachGuard,
    /// The control daemon.
    Controller,
    /// The session worker.
    Worker,
    /// The forwarder a native bridge and a launched agent run.
    Hook,
}

impl Program {
    /// The host executables the store names a path for. A release's `bin/` carries two more, the
    /// plugin host and the description process; the daemon finds the description process beside
    /// the worker, so the store is asked for the path of neither.
    pub const ALL: [Self; 5] = [
        Self::Kr,
        Self::AttachGuard,
        Self::Controller,
        Self::Worker,
        Self::Hook,
    ];

    /// The program's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kr => "kr",
            Self::AttachGuard => "kr-attach-guard",
            Self::Controller => "kr-controller",
            Self::Worker => "kr-worker",
            Self::Hook => "kr-hook",
        }
    }

    /// The program's file name on this platform.
    #[must_use]
    pub fn file_name(self) -> String {
        format!("{}{}", self.name(), std::env::consts::EXE_SUFFIX)
    }
}

/// Why a store could not be read or changed, or why a program of it may not run.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// This process's own image could not be read from the operating system.
    #[error("where this program is could not be read from the operating system: {0}")]
    Image(#[source] std::io::Error),
    /// The release this process is in is not the one it started from, or is being removed.
    #[error("{path} {reason}")]
    Replaced {
        /// The release's directory, or its manifest.
        path: PathBuf,
        /// What happened to it.
        reason: &'static str,
    },
    /// A release's manifest is not one this build reads.
    #[error("{path} is not a release manifest this build reads: {source}")]
    Manifest {
        /// The manifest.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: kr_protocol::update::ManifestError,
    },
    /// A file or directory of the store could not be read or changed.
    #[error("{operation} {path}: {source}")]
    Io {
        /// What was being done.
        operation: &'static str,
        /// The path involved.
        path: PathBuf,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },
    /// This platform keeps no store.
    #[error("this host keeps no store of releases on this platform")]
    Unsupported,
}

impl InstallError {
    fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }
}

/// The result of an operation on a store.
pub type Result<T> = std::result::Result<T, InstallError>;

/// Reads this process's own image from the kernel.
///
/// # Errors
///
/// Returns the operating system's error when it does not say.
pub fn image_path() -> std::io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let pid = i32::try_from(std::process::id())
            .map_err(|_| std::io::Error::other("this process's number is out of range"))?;
        libproc::proc_pid::pidpath(pid)
            .map(PathBuf::from)
            .map_err(std::io::Error::other)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // `/proc/self/exe` on Linux and `GetModuleFileNameW` on Windows: the kernel's own record of
        // the image, which is what this module is for.
        std::env::current_exe()
    }
}

/// What this process runs, read once, with its hold taken when it is a release of a store.
///
/// Each host executable calls this first thing, before it does anything a release could matter to,
/// and refuses to run on an error: a program whose release is being removed must not start work
/// the removal would take away from under it. Every later call answers the same.
///
/// # Errors
///
/// Returns the error the first call met: an image the kernel would not describe, a release that
/// was replaced or is being removed, or a manifest this build does not read.
pub fn this_process() -> std::result::Result<&'static Running, &'static InstallError> {
    static RUNNING: OnceLock<Result<Running>> = OnceLock::new();
    RUNNING
        .get_or_init(|| {
            let image = image_path().map_err(InstallError::Image)?;
            Running::of_image(&image)
        })
        .as_ref()
}

/// What a process runs.
#[derive(Debug)]
pub enum Running {
    /// A release of a store, held for as long as this value lives.
    Installed(Box<Installed>),
    /// A build outside any store, whose programs are the ones beside its own.
    Loose {
        /// The directory the process's image is in.
        directory: PathBuf,
    },
}

/// A release of a store, and the hold on it.
#[derive(Debug)]
pub struct Installed {
    store: Store,
    release: ReleaseName,
    manifest: ReleaseManifest,
    /// The manifest, opened and locked shared. Nothing reads it again: holding it is the point.
    _hold: File,
}

impl Running {
    /// Works out what a process whose image is `image` runs, and takes the hold when that is a
    /// release of a store.
    ///
    /// A program at `versions/<release>/bin/` of a directory that holds a store record is that
    /// release's, and is held; anywhere else under `versions/` it is refused, since it would run
    /// from a release without holding it. A program anywhere under `trash/` or `staging/` of a
    /// store is refused: its release is being removed, or is not yet installed. Anything else is a
    /// build outside a store.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Replaced`] for a release being removed or replaced, and
    /// [`InstallError::Manifest`] for a manifest this build does not read.
    pub fn of_image(image: &Path) -> Result<Self> {
        let directory = image.parent().map(Path::to_path_buf).unwrap_or_default();
        let Some(placed) = Placed::of(image) else {
            return Ok(Self::Loose { directory });
        };
        match placed.place {
            Place::Versions if !placed.in_bin => Err(InstallError::Replaced {
                path: image.to_path_buf(),
                reason: "is inside a release of this host's store, and not where a release keeps \
                         its programs, so it does not start",
            }),
            Place::Versions => {
                let release = placed
                    .release_directory_name
                    .to_str()
                    .and_then(|name| ReleaseName::new(name).ok())
                    .ok_or_else(|| InstallError::Replaced {
                        path: placed.release_directory.clone(),
                        reason: "is not named as a release is",
                    })?;
                let (hold, manifest) = hold(&placed.store, &release)?;
                Ok(Self::Installed(Box::new(Installed {
                    store: placed.store,
                    release,
                    manifest,
                    _hold: hold,
                })))
            }
            Place::Trash => Err(InstallError::Replaced {
                path: placed.release_directory,
                reason: "is being removed from this host, so this program of it does not start",
            }),
            Place::Staging => Err(InstallError::Replaced {
                path: placed.release_directory,
                reason: "is still being installed, so this program of it does not start",
            }),
        }
    }

    /// The release, where this is one of a store.
    #[must_use]
    pub const fn release(&self) -> Option<&ReleaseName> {
        match self {
            Self::Installed(installed) => Some(&installed.release),
            Self::Loose { .. } => None,
        }
    }

    /// The release's manifest, where this is one of a store.
    #[must_use]
    pub const fn manifest(&self) -> Option<&ReleaseManifest> {
        match self {
            Self::Installed(installed) => Some(&installed.manifest),
            Self::Loose { .. } => None,
        }
    }

    /// The store, where this is one of a store.
    #[must_use]
    pub const fn store(&self) -> Option<&Store> {
        match self {
            Self::Installed(installed) => Some(&installed.store),
            Self::Loose { .. } => None,
        }
    }

    /// This release's own copy of a program: what a process starts when the program has to be of
    /// the same release as itself, such as the worker a control daemon launches.
    #[must_use]
    pub fn own(&self, program: Program) -> PathBuf {
        match self {
            Self::Installed(installed) => installed
                .store
                .release_directory(&installed.release)
                .join("bin")
                .join(program.file_name()),
            Self::Loose { directory } => directory.join(program.file_name()),
        }
    }

    /// The program an update replaces: the path through `current` that whatever this host
    /// records for later names, such as the service definition that starts the control daemon.
    ///
    /// Outside a store it is the program beside this one, as before.
    #[must_use]
    pub fn stable(&self, program: Program) -> PathBuf {
        match self {
            Self::Installed(installed) => installed.store.stable(program),
            Self::Loose { directory } => directory.join(program.file_name()),
        }
    }

    /// This release's qualified shell packages, where this is a release of a store.
    ///
    /// A build outside a store finds its packages where it always has.
    #[must_use]
    pub fn shells(&self) -> Option<PathBuf> {
        match self {
            Self::Installed(installed) => Some(
                installed
                    .store
                    .release_directory(&installed.release)
                    .join("shells"),
            ),
            Self::Loose { .. } => None,
        }
    }

    /// The release a process of this build states in its build identifier: the release's name in
    /// a store, and `outside` beyond one.
    #[must_use]
    pub fn stated_release<'a>(&'a self, outside: &'a str) -> &'a str {
        self.release().map_or(outside, ReleaseName::as_str)
    }
}

/// Where in a store an image is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// An installed release.
    Versions,
    /// A release being removed.
    Trash,
    /// A release being installed.
    Staging,
}

/// An image that is inside a store.
struct Placed {
    store: Store,
    place: Place,
    /// The directory directly under the place that the image is in: a release's own directory
    /// under `versions/`, and whatever an unpacking or a removal made under the others.
    release_directory: PathBuf,
    release_directory_name: std::ffi::OsString,
    /// Whether the image is directly in the release directory's `bin/`, where a release keeps its
    /// programs.
    in_bin: bool,
}

impl Placed {
    /// Where `image` is in a store: anywhere under the `versions/`, `staging/` or `trash/` of a
    /// directory that holds a store record. The nearest such directory above the image decides.
    fn of(image: &Path) -> Option<Self> {
        if cfg!(windows) {
            return None;
        }
        let mut below = image;
        for holder in image.ancestors().skip(1) {
            let place = match holder.file_name().and_then(OsStr::to_str) {
                Some(VERSIONS) => Some(Place::Versions),
                Some(STAGING) => Some(Place::Staging),
                Some(TRASH) => Some(Place::Trash),
                _ => None,
            };
            if let (Some(place), Some(root)) = (place, holder.parent()) {
                let store = Store::at(root);
                if store.is_store() {
                    return Some(Self {
                        store,
                        place,
                        release_directory: below.to_path_buf(),
                        release_directory_name: below.file_name()?.to_os_string(),
                        in_bin: image.parent() == Some(below.join("bin").as_path()),
                    });
                }
            }
            below = holder;
        }
        None
    }
}

/// How long a starting program waits for a removal or replacement of its release, which holds the
/// release's manifest exclusively while it moves the release, before it refuses to start.
#[cfg(unix)]
const HOLD_WAIT: Duration = Duration::from_secs(30);

/// Opens a file of a release for reading without following a link or waiting for a writer, and
/// checks that it is a regular file: a link or a pipe planted under a release's name would
/// otherwise turn a read into a read of something else, or a wait that never ends.
///
/// # Errors
///
/// Returns the operating system's error, [`std::io::ErrorKind::NotFound`] among them, and an error
/// of kind `InvalidData` for a link and for anything but a regular file.
#[cfg(unix)]
pub fn open_regular_file(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::MLINK => std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "it is a link, and no file of a release is",
        ),
        other => std::io::Error::from(other),
    })?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "it is not a regular file",
        ));
    }
    Ok(file)
}

/// Reads a file of a release whole, refusing what [`open_regular_file`] refuses and one longer
/// than `limit`.
///
/// # Errors
///
/// Returns the failure to open or read it, and `InvalidData` for a file longer than `limit`.
#[cfg(unix)]
pub fn read_regular_file(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    open_regular_file(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the file is larger than any this host reads here",
        ));
    }
    Ok(bytes)
}

/// Opens a release's manifest, takes the shared hold on it, and checks that the file locked is
/// still the release's manifest.
#[cfg(unix)]
fn hold(store: &Store, release: &ReleaseName) -> Result<(File, ReleaseManifest)> {
    let path = store.manifest(release);
    let file = open_regular_file(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            InstallError::Replaced {
                path: path.clone(),
                reason: "is gone: this release was removed from this host after this program \
                         started",
            }
        } else {
            InstallError::io("open", &path, error)
        }
    })?;
    hold_opened(file, path, release)
}

/// Takes the shared hold on a manifest already opened at `path`, checks that `path` still names
/// the file locked, and reads the manifest.
///
/// Separate from the open, because what happens between the two is what the check is for: a
/// release removed after its manifest was opened leaves the open file behind, and the lock on it
/// is granted as soon as the removal lets go.
#[cfg(unix)]
fn hold_opened(
    file: File,
    path: PathBuf,
    release: &ReleaseName,
) -> Result<(File, ReleaseManifest)> {
    hold_opened_within(file, path, release, HOLD_WAIT)
}

/// [`hold_opened`], waiting up to `within` for a removal or replacement of the release to let go
/// of its manifest.
#[cfg(unix)]
fn hold_opened_within(
    file: File,
    path: PathBuf,
    release: &ReleaseName,
    within: Duration,
) -> Result<(File, ReleaseManifest)> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    if !lock_within(
        &file,
        &path,
        rustix::fs::FlockOperation::NonBlockingLockShared,
        within,
    )? {
        return Err(InstallError::Replaced {
            path,
            reason: "is being removed or replaced, and that has not finished: this program of it \
                     does not start",
        });
    }
    let held = file
        .metadata()
        .map_err(|error| InstallError::io("read", &path, error))?;
    let named = std::fs::symlink_metadata(&path).ok();
    if named.is_none_or(|named| named.dev() != held.dev() || named.ino() != held.ino()) {
        return Err(InstallError::Replaced {
            path,
            reason: "is no longer the file this program locked: its release was removed or \
                     replaced while it started",
        });
    }
    let mut bytes = Vec::new();
    let limit = kr_protocol::update::MAX_MANIFEST_LEN;
    (&file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| InstallError::io("read", &path, error))?;
    if bytes.len() as u64 > limit {
        return Err(InstallError::Manifest {
            path,
            source: kr_protocol::update::ManifestError::Malformed(
                "it is larger than any release's manifest".to_owned(),
            ),
        });
    }
    let manifest =
        ReleaseManifest::read_document(&bytes).map_err(|source| InstallError::Manifest {
            path: path.clone(),
            source,
        })?;
    if manifest.release != *release {
        return Err(InstallError::Replaced {
            path,
            reason: "names another release than the directory it is in",
        });
    }
    Ok((file, manifest))
}

#[cfg(not(unix))]
fn hold(_store: &Store, _release: &ReleaseName) -> Result<(File, ReleaseManifest)> {
    Err(InstallError::Unsupported)
}

/// Takes a lock on an open file without blocking, trying again for as long as `within` and when a
/// signal interrupts it, and says whether it was taken. `operation` is a non-blocking one.
#[cfg(unix)]
fn lock_within(
    file: &File,
    path: &Path,
    operation: rustix::fs::FlockOperation,
    within: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + within;
    loop {
        match rustix::fs::flock(file, operation) {
            Ok(()) => return Ok(true),
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(false),
            Err(error) => {
                return Err(InstallError::io("lock", path, std::io::Error::from(error)));
            }
        }
    }
}

/// Takes a lock on an open file, waiting for it, and again if a signal interrupts the wait.
///
/// Only what waits for a bounded section of an update takes a lock this way, a control daemon's
/// start lock; a release's manifest is locked by [`lock_within`].
#[cfg(unix)]
fn lock(file: &File, path: &Path, operation: rustix::fs::FlockOperation) -> Result<()> {
    loop {
        match rustix::fs::flock(file, operation) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => {
                return Err(InstallError::io("lock", path, std::io::Error::from(error)));
            }
        }
    }
}

/// Whether nothing holds the release whose manifest is `file`: the exclusive lock is taken to find
/// out, and let go of by unlocking it. A lock goes with its last descriptor, and a program started
/// meanwhile has a copy of this one until its own program takes over, so closing the file would
/// leave the lock to that program and the question would hold what it asked about.
#[cfg(unix)]
fn probe_is_free(file: &File) -> std::io::Result<bool> {
    match rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock)?;
            Ok(true)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

/// A host's store of installed releases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// The store at `root`, whether or not there is one there yet.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Where this user's store is on this platform, where the platform says where a user's own
    /// data goes: `~/Library/Application Support/KalaReach/host` on macOS,
    /// `$XDG_DATA_HOME/kalareach/host` on Linux (`~/.local/share` when that is unset) and
    /// `%LOCALAPPDATA%\KalaReach\host` on Windows.
    #[must_use]
    pub fn default_root() -> Option<PathBuf> {
        let nonempty = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        if cfg!(windows) {
            return nonempty("LOCALAPPDATA")
                .map(|base| PathBuf::from(base).join("KalaReach").join("host"));
        }
        let home = nonempty("HOME").map(PathBuf::from);
        if cfg!(target_os = "macos") {
            return home.map(|home| {
                home.join("Library")
                    .join("Application Support")
                    .join("KalaReach")
                    .join("host")
            });
        }
        nonempty("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home.map(|home| home.join(".local").join("share")))
            .map(|data| data.join("kalareach").join("host"))
    }

    /// The store's directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the directory is a store: whether it holds a store record.
    #[must_use]
    pub fn is_store(&self) -> bool {
        self.record().is_file()
    }

    /// The store's record.
    #[must_use]
    pub fn record(&self) -> PathBuf {
        self.root.join(STORE_RECORD)
    }

    /// The directory the releases are in.
    #[must_use]
    pub fn versions(&self) -> PathBuf {
        self.root.join(VERSIONS)
    }

    /// One release's directory.
    #[must_use]
    pub fn release_directory(&self, release: &ReleaseName) -> PathBuf {
        self.versions().join(release.as_str())
    }

    /// One release's manifest.
    #[must_use]
    pub fn manifest(&self, release: &ReleaseName) -> PathBuf {
        self.release_directory(release).join(MANIFEST_FILE)
    }

    /// The link to the current release.
    #[must_use]
    pub fn current_link(&self) -> PathBuf {
        self.root.join(CURRENT)
    }

    /// Where releases are unpacked and checked.
    #[must_use]
    pub fn staging(&self) -> PathBuf {
        self.root.join(STAGING)
    }

    /// Where a release goes to be removed.
    #[must_use]
    pub fn trash(&self) -> PathBuf {
        self.root.join(TRASH)
    }

    /// Where the roots this store's daemons served are recorded.
    #[must_use]
    pub fn roots(&self) -> PathBuf {
        self.root.join("roots")
    }

    /// The program an update replaces, through `current`.
    #[must_use]
    pub fn stable(&self, program: Program) -> PathBuf {
        self.current_link().join("bin").join(program.file_name())
    }

    /// The current release's qualified shell packages, through `current`.
    #[must_use]
    pub fn stable_shells(&self) -> PathBuf {
        self.current_link().join("shells")
    }

    /// Creates the store's directories, owner-only, where they are missing. The store record is
    /// the caller's to write: until it exists nothing treats the directory as a store.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when a directory cannot be created, or is not owner-only.
    pub fn create_directories(&self) -> Result<()> {
        for directory in [
            self.root.clone(),
            self.versions(),
            self.staging(),
            self.trash(),
            self.roots(),
        ] {
            crate::paths::create_private_tree(&self.root, &directory).map_err(|error| {
                InstallError::io(
                    "create the store directory",
                    &directory,
                    std::io::Error::other(error),
                )
            })?;
        }
        Ok(())
    }

    /// The release `current` names, where it names one.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the link cannot be read, and [`InstallError::Replaced`]
    /// when it names something other than a release of this store.
    pub fn current(&self) -> Result<Option<ReleaseName>> {
        let link = self.current_link();
        let target = match std::fs::read_link(&link) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(InstallError::io("read the link", &link, error)),
        };
        let mut parts = target.components();
        let release = match (parts.next(), parts.next(), parts.next()) {
            (
                Some(std::path::Component::Normal(versions)),
                Some(std::path::Component::Normal(name)),
                None,
            ) if versions == OsStr::new(VERSIONS) => {
                name.to_str().and_then(|name| ReleaseName::new(name).ok())
            }
            _ => None,
        };
        release.map(Some).ok_or(InstallError::Replaced {
            path: link,
            reason: "names something other than a release of this store",
        })
    }

    /// Every release in `versions/`, by name, in name order.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the directory cannot be read.
    pub fn releases(&self) -> Result<Vec<ReleaseName>> {
        let versions = self.versions();
        let entries = match std::fs::read_dir(&versions) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(InstallError::io("read", &versions, error)),
        };
        let mut releases = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| InstallError::io("read", &versions, error))?;
            if let Some(release) = entry
                .file_name()
                .to_str()
                .and_then(|name| ReleaseName::new(name).ok())
            {
                releases.push(release);
            }
        }
        releases.sort();
        Ok(releases)
    }
}

#[cfg(unix)]
impl Store {
    /// Takes the update lock, which one update holds from its first look at the host to its last
    /// start, when no other update holds it. A first install holds it too, and `current` changes
    /// only under it ([`Self::switch`]).
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the lock file cannot be opened or locked for any reason
    /// but another holder.
    pub fn try_lock_update(&self) -> Result<Option<StoreLock>> {
        StoreLock::try_take(
            &self.root.join("update.lock"),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
    }

    /// Takes the install lock exclusively when nothing holds it, without waiting: nothing starts
    /// a control daemon of this store while it is held, which is what an update switches `current`
    /// under. A control daemon holds it, shared, from its look at `current` until it has taken its
    /// environment, so a caller that has to have it retries for as long as it can afford to wait:
    /// no call takes it exclusively without a bound. A starting daemon, for its part, waits for
    /// [`Self::lock_start`] for as long as an update's own bounded section lasts.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the lock file cannot be opened or locked for any reason
    /// but a holder.
    pub fn try_lock_install(&self) -> Result<Option<StoreLock>> {
        StoreLock::try_take(
            &self.root.join("install.lock"),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
    }

    /// Takes the install lock shared, waiting for it: a control daemon holds it while it starts,
    /// so `current` cannot change between its look at it and its taking the environment.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the lock file cannot be opened or locked.
    pub fn lock_start(&self) -> Result<StoreLock> {
        StoreLock::take(
            &self.root.join("install.lock"),
            rustix::fs::FlockOperation::LockShared,
        )
    }

    /// Makes `release` current: one new link, renamed over `current`, and the store's directory
    /// flushed so the rename survives a crash. Nothing else changes.
    ///
    /// `update` is the update lock, so what `current` names stays what an install or an update
    /// found it to be for as long as that holds it. `install` is the install lock, taken
    /// exclusively: nothing starts a control daemon of this store while `current` changes.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the link cannot be made, renamed or flushed, and
    /// [`InstallError::Replaced`] when the release is not in this store.
    pub fn switch(
        &self,
        release: &ReleaseName,
        update: &StoreLock,
        install: &StoreLock,
    ) -> Result<()> {
        debug_assert_eq!(update.path, self.root.join("update.lock"));
        debug_assert_eq!(install.path, self.root.join("install.lock"));
        if !self.manifest(release).is_file() {
            return Err(InstallError::Replaced {
                path: self.release_directory(release),
                reason: "is not a release of this store",
            });
        }
        let temporary = self.root.join(format!(".{CURRENT}-{}", crate::new_uuid()));
        std::os::unix::fs::symlink(Path::new(VERSIONS).join(release.as_str()), &temporary)
            .map_err(|error| InstallError::io("make the link", &temporary, error))?;
        if let Err(error) = std::fs::rename(&temporary, self.current_link()) {
            let _ = std::fs::remove_file(&temporary);
            return Err(InstallError::io("rename", self.current_link(), error));
        }
        sync_directory(&self.root)
    }

    /// Whether a running process holds `release`.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when its manifest cannot be opened or locked for any reason
    /// but a holder.
    pub fn held(&self, release: &ReleaseName) -> Result<bool> {
        let path = self.manifest(release);
        let file =
            open_regular_file(&path).map_err(|error| InstallError::io("open", &path, error))?;
        probe_is_free(&file)
            .map(|free| !free)
            .map_err(|error| InstallError::io("lock", &path, error))
    }

    /// Removes a release no running process holds, and says whether it did. Whatever else is at
    /// the release's name, a link or a file, is removed as a name only.
    ///
    /// The release's manifest is locked exclusively, which fails while any process holds the
    /// release, and the release is renamed into `trash/` while that lock is held: from then on no
    /// process can take a hold on it, because a hold checks that `versions/<release>/release.json`
    /// is the file it locked. Only then is anything deleted.
    ///
    /// `_held` is the update lock: releases are removed by one update at a time.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the release cannot be locked, moved or deleted.
    pub fn retire(&self, release: &ReleaseName, _held: &StoreLock) -> Result<bool> {
        let directory = self.release_directory(release);
        // A release is a directory. Anything else under its name, a link above all, is not one:
        // the name is taken away and whatever it pointed at is left as it was, never followed.
        let about = std::fs::symlink_metadata(&directory)
            .map_err(|error| InstallError::io("read", &directory, error))?;
        if !about.file_type().is_dir() {
            std::fs::remove_file(&directory)
                .map_err(|error| InstallError::io("remove", &directory, error))?;
            sync_directory(&self.versions())?;
            return Ok(true);
        }
        let path = self.manifest(release);
        let file =
            open_regular_file(&path).map_err(|error| InstallError::io("open", &path, error))?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(false),
            Err(error) => {
                return Err(InstallError::io("lock", &path, std::io::Error::from(error)));
            }
        }
        crate::paths::create_private_directory(&self.trash()).map_err(|error| {
            InstallError::io(
                "create the store directory",
                self.trash(),
                std::io::Error::other(error),
            )
        })?;
        let removed = self
            .trash()
            .join(format!("{release}-{}", crate::new_uuid()));
        // A release is installed read-only, and on some systems a directory moves to another
        // parent only while its own entries can be written.
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                &directory,
                std::fs::Permissions::from_mode(crate::paths::OWNER_ONLY_DIRECTORY_MODE),
            )
            .map_err(|error| InstallError::io("open to removal", &directory, error))?;
        }
        std::fs::rename(&directory, &removed)
            .map_err(|error| InstallError::io("move", &directory, error))?;
        sync_directory(&self.versions())?;
        drop(file);
        remove_tree(&removed)?;
        Ok(true)
    }

    /// Records the runtime and state roots a control daemon of this store serves, so an update
    /// finds every environment this store's daemons have run.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the record cannot be written.
    pub fn record_roots(&self, runtime_root: &Path, state_root: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt as _;

        let roots = self.roots();
        crate::paths::create_private_directory(&roots).map_err(|error| {
            InstallError::io(
                "create the store directory",
                &roots,
                std::io::Error::other(error),
            )
        })?;
        let state = state_root.as_os_str().as_bytes();
        let runtime = runtime_root.as_os_str().as_bytes();
        let digest = kr_cbor::sha256(state);
        let name: String = digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut contents = Vec::with_capacity(runtime.len() + state.len() + 1);
        contents.extend_from_slice(runtime);
        contents.push(0);
        contents.extend_from_slice(state);
        let path = roots.join(format!("{name}.root"));
        crate::paths::write_owner_only_file(&path, &contents)
            .map_err(|error| InstallError::io("write", &path, std::io::Error::other(error)))
    }

    /// Every pair of roots a control daemon of this store has served, in record order.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Io`] when the records cannot be read.
    pub fn recorded_roots(&self) -> Result<Vec<RecordedRoots>> {
        use std::os::unix::ffi::OsStrExt as _;

        let roots = self.roots();
        let entries = match std::fs::read_dir(&roots) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(InstallError::io("read", &roots, error)),
        };
        let mut recorded = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| InstallError::io("read", &roots, error))?;
            let path = entry.path();
            if path.extension() != Some(OsStr::new("root")) {
                continue;
            }
            let Some(contents) = crate::paths::read_owner_only_file(&path, 64 * 1024)
                .map_err(|error| InstallError::io("read", &path, std::io::Error::other(error)))?
            else {
                continue;
            };
            let Some(split) = contents.iter().position(|byte| *byte == 0) else {
                continue;
            };
            recorded.push(RecordedRoots {
                runtime_root: PathBuf::from(OsStr::from_bytes(&contents[..split])),
                state_root: PathBuf::from(OsStr::from_bytes(&contents[split + 1..])),
                record: path,
            });
        }
        recorded.sort_by(|one, other| one.record.cmp(&other.record));
        Ok(recorded)
    }
}

/// The roots one control daemon of a store served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRoots {
    /// The runtime root.
    pub runtime_root: PathBuf,
    /// The state root.
    pub state_root: PathBuf,
    /// The record that says so.
    pub record: PathBuf,
}

/// A lock on one of a store's lock files, released when this is dropped.
#[cfg(unix)]
#[derive(Debug)]
pub struct StoreLock {
    file: File,
    path: PathBuf,
}

#[cfg(unix)]
impl StoreLock {
    fn open(path: &Path) -> Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(crate::paths::OWNER_ONLY_FILE_MODE)
            .open(path)
            .map_err(|error| InstallError::io("open the lock", path, error))
    }

    fn take(path: &Path, operation: rustix::fs::FlockOperation) -> Result<Self> {
        let file = Self::open(path)?;
        lock(&file, path, operation)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    fn try_take(path: &Path, operation: rustix::fs::FlockOperation) -> Result<Option<Self>> {
        let file = Self::open(path)?;
        match rustix::fs::flock(&file, operation) {
            Ok(()) => Ok(Some(Self {
                file,
                path: path.to_path_buf(),
            })),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(error) => Err(InstallError::io("lock", path, std::io::Error::from(error))),
        }
    }
}

#[cfg(unix)]
impl StoreLock {
    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        // The lock belongs to the open file. A process started while it was held may still hold a
        // descriptor onto that file until its own program takes over, so the lock is let go of
        // here rather than left to the close.
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

/// Flushes a directory, so a name just added to it or taken out of it survives a crash.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|opened| opened.sync_all())
        .map_err(|error| InstallError::io("flush", directory, error))
}

/// Deletes a release that was moved out of `versions/`, its directories made writable first, since
/// a release is installed read-only.
#[cfg(unix)]
fn remove_tree(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fn writable(directory: &Path) -> std::io::Result<()> {
        std::fs::set_permissions(
            directory,
            std::fs::Permissions::from_mode(crate::paths::OWNER_ONLY_DIRECTORY_MODE),
        )?;
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                writable(&entry.path())?;
            }
        }
        Ok(())
    }

    writable(directory)
        .and_then(|()| std::fs::remove_dir_all(directory))
        .map_err(|error| InstallError::io("remove", directory, error))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kr_protocol::hello::PackageVersion;
    use kr_protocol::update::{
        CommitId, CompatibilityLevel, FloorSystem, FloorVersion, ManifestKind, OsFloor,
    };

    /// A store of this test's own, removed with it.
    struct TestStore {
        store: Store,
        _root: TempRoot,
    }

    struct TempRoot(PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = remove_tree(&self.0);
        }
    }

    fn test_store() -> TestStore {
        let root = std::env::temp_dir().join(format!("kr-store-{}", crate::new_uuid()));
        let store = Store::at(root.join("host"));
        store.create_directories().expect("the store's directories");
        crate::paths::write_owner_only_file(&store.record(), b"{}\n").expect("a record");
        TestStore {
            store,
            _root: TempRoot(root),
        }
    }

    fn release(name: &str) -> ReleaseName {
        ReleaseName::new(name).expect("a release name")
    }

    /// Makes a named pipe at `path`, which nothing writes to.
    fn make_pipe(path: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe is made at {}", path.display());
    }

    /// How long a test waits for a release to be let go of before it says what still holds it.
    ///
    /// A release is let go of when every descriptor of its hold is closed, and a program that another
    /// test starts at the moment the hold is dropped keeps a copy of the descriptor until its own
    /// program takes over. The wait ends when the release is free, so this is only the bound of a
    /// failure.
    const RELEASE_WAIT: Duration = Duration::from_secs(60);

    /// Asks `released` again until it answers yes, for as long as `within`, and on failure says which
    /// processes still have `manifest` open.
    fn wait_for_release(
        manifest: &Path,
        within: Duration,
        mut released: impl FnMut() -> bool,
    ) -> std::result::Result<(), String> {
        let deadline = Instant::now() + within;
        while !released() {
            if Instant::now() >= deadline {
                return Err(format!(
                    "{} is still held by: {}",
                    manifest.display(),
                    holders_of(manifest)
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// Fails the test, saying what still holds the release, unless `released` answers yes within
    /// [`RELEASE_WAIT`].
    fn assert_released(manifest: &Path, what: &str, released: impl FnMut() -> bool) {
        if let Err(held) = wait_for_release(manifest, RELEASE_WAIT, released) {
            panic!("{what}: {held}");
        }
    }

    /// The processes that have `path` open, each by its number and its program's name.
    #[cfg(target_os = "linux")]
    fn holders_of(path: &Path) -> String {
        let Ok(path) = std::fs::canonicalize(path) else {
            return format!("{} is not there", path.display());
        };
        let mut holders = Vec::new();
        for process in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let Some(number) = process
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let opens = std::fs::read_dir(process.path().join("fd"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|entry| std::fs::read_link(entry.path()).is_ok_and(|to| to == path));
            if opens {
                let program = std::fs::read_to_string(process.path().join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                holders.push(format!("process {number} ({program})"));
            }
        }
        if holders.is_empty() {
            "no process that can be seen".to_owned()
        } else {
            holders.join(", ")
        }
    }

    /// The processes that have `path` open, each by its number and its program's name.
    #[cfg(not(target_os = "linux"))]
    fn holders_of(path: &Path) -> String {
        match std::process::Command::new("/usr/sbin/lsof")
            .args(["-F", "pc", "--"])
            .arg(path)
            .output()
        {
            Ok(output) if output.status.success() => {
                let listing = String::from_utf8_lossy(&output.stdout);
                let mut holders = Vec::new();
                for line in listing.lines() {
                    if let Some(number) = line.strip_prefix('p') {
                        holders.push(format!("process {number}"));
                    } else if let (Some(name), Some(last)) =
                        (line.strip_prefix('c'), holders.last_mut())
                    {
                        last.push_str(&format!(" ({name})"));
                    }
                }
                holders.join(", ")
            }
            Ok(_) => "no process that can be seen".to_owned(),
            Err(error) => format!("lsof did not run: {error}"),
        }
    }

    fn manifest_of(release: &ReleaseName) -> String {
        let manifest = ReleaseManifest {
            kind: ManifestKind::Release,
            release: release.clone(),
            sequence: kr_protocol::scalars::U64::new(1),
            commit: CommitId::new("4254aa6e62e585478ff8dcff5518f23c7263f4ce").expect("a commit"),
            target: "aarch64-apple-darwin".to_owned(),
            os_floor: OsFloor {
                system: FloorSystem::Macos,
                version: FloorVersion {
                    major: 14,
                    minor: 0,
                },
            },
            protocol_version: PackageVersion::new(0, 48, 0),
            public_majors: vec![1],
            retained_levels: vec![CompatibilityLevel::of(PackageVersion::new(0, 48, 0))],
            shells: Vec::new(),
            files: Vec::new(),
        };
        serde_json::json!({ "signed": manifest, "signatures": [] }).to_string()
    }

    /// Puts a release in the store: a program under `bin/` and its manifest.
    fn install(store: &Store, name: &ReleaseName) -> PathBuf {
        let directory = store.release_directory(name);
        std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
        std::fs::write(store.manifest(name), manifest_of(name)).expect("the manifest");
        let program = directory.join("bin").join(Program::Kr.file_name());
        std::fs::write(&program, b"#!/bin/sh\n").expect("a program");
        program
    }

    /// A program under a store's `versions/<release>/bin/` is that release's, held, and names its
    /// own release's programs and the current ones apart; the same layout without a store record
    /// is a build outside a store.
    #[test]
    fn a_program_of_a_release_is_held_and_names_its_own_programs_and_the_current_ones() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let image = install(&test.store, &one);
        let running = Running::of_image(&image).expect("a release of the store");
        assert_eq!(running.release(), Some(&one));
        assert_eq!(running.store(), Some(&test.store));
        assert_eq!(
            running.own(Program::Worker),
            test.store
                .release_directory(&one)
                .join("bin")
                .join(Program::Worker.file_name())
        );
        assert_eq!(
            running.stable(Program::Controller),
            test.store
                .root()
                .join("current/bin")
                .join(Program::Controller.file_name())
        );
        assert_eq!(
            running.shells(),
            Some(test.store.release_directory(&one).join("shells"))
        );
        assert_eq!(running.stated_release("0.1.0"), one.as_str());
        assert!(
            test.store.held(&one).expect("asks"),
            "the program holds its release"
        );
        drop(running);
        assert_released(
            &test.store.manifest(&one),
            "the hold goes with the program",
            || !test.store.held(&one).expect("asks"),
        );

        // The control: the same layout with no store record is not a store.
        std::fs::remove_file(test.store.record()).expect("the record goes");
        let loose = Running::of_image(&image).expect("a build outside a store");
        assert_eq!(loose.release(), None);
        assert_eq!(
            loose.own(Program::Worker),
            image.with_file_name(Program::Worker.file_name())
        );
        assert_eq!(
            loose.stable(Program::Controller),
            image.with_file_name(Program::Controller.file_name())
        );
    }

    /// A held release is never removed; one nobody holds is, and it is moved out of `versions/`
    /// first.
    #[test]
    fn a_held_release_is_never_removed_and_one_nobody_holds_is() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let image = install(&test.store, &one);
        let update = test
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let running = Running::of_image(&image).expect("held");
        assert!(
            !test.store.retire(&one, &update).expect("asks"),
            "a held release stays"
        );
        assert!(test.store.manifest(&one).is_file());
        drop(running);
        assert_released(
            &test.store.manifest(&one),
            "the control: nobody holds it now, and it goes",
            || test.store.retire(&one, &update).expect("removes"),
        );
        assert!(!test.store.release_directory(&one).exists());
        assert_eq!(
            std::fs::read_dir(test.store.trash())
                .expect("the trash")
                .count(),
            0,
            "nothing of it is left in the trash"
        );
    }

    /// A program a test starts, ended and reaped when the test ends. It reads from a pipe this test
    /// holds the other end of, so it also ends when the test's process does, however that ends.
    struct Started(std::process::Child);

    impl Drop for Started {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A program started while a hold is open has a copy of its descriptor, and the release stays
    /// held for as long as that program keeps the copy, whether the holder drops the hold or its
    /// process ends; once the program has let go, the release goes.
    #[test]
    fn a_release_stays_held_while_a_program_started_with_its_hold_keeps_a_copy() {
        use std::process::Stdio;

        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let image = install(&test.store, &one);
        let update = test
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let running = Running::of_image(&image).expect("held");
        let Running::Installed(installed) = &running else {
            panic!("a release of the store");
        };
        let copy = installed
            ._hold
            .try_clone()
            .expect("the descriptor is copied");
        let program = Started(
            std::process::Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::from(copy))
                .stderr(Stdio::null())
                .spawn()
                .expect("the program starts"),
        );
        drop(running);

        assert!(
            test.store.held(&one).expect("asks"),
            "the program's copy holds the release"
        );
        assert!(
            !test.store.retire(&one, &update).expect("asks"),
            "a held release stays"
        );
        // The wait ends at its bound while the copy lives, and names the program that keeps it.
        let manifest = test.store.manifest(&one);
        let still = wait_for_release(&manifest, Duration::from_millis(100), || {
            test.store.retire(&one, &update).expect("asks")
        })
        .expect_err("the copy is still there");
        let (_, holders) = still.split_once("held by: ").expect("it names the holders");
        let number = program.0.id().to_string();
        assert!(
            holders
                .split(|character: char| !character.is_ascii_digit())
                .any(|word| word == number),
            "{still}"
        );
        assert!(manifest.is_file(), "nothing of the release was removed");

        drop(program);
        assert_released(
            &manifest,
            "the control: the program has let go, and the release goes",
            || test.store.retire(&one, &update).expect("removes"),
        );
        assert!(!test.store.release_directory(&one).exists());
    }

    /// Asking whether a release is held takes a lock to find out, and lets go of it at once: a
    /// program started at that moment keeps a copy of the descriptor, and the lock must not go with
    /// the copy, or a question would hold the release it asked about.
    #[test]
    fn asking_whether_a_release_is_held_leaves_nothing_held_though_the_descriptor_is_copied() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        install(&test.store, &one);
        let path = test.store.manifest(&one);
        let asked = File::open(&path).expect("the question opens the manifest");
        let copy = asked.try_clone().expect("a program started now has a copy");

        assert!(probe_is_free(&asked).expect("asks"), "nothing holds it");
        drop(asked);
        let program = File::open(&path).expect("a program opens its manifest");
        assert!(
            rustix::fs::flock(&program, rustix::fs::FlockOperation::NonBlockingLockShared).is_ok(),
            "the copy keeps no lock: a program takes its hold at once"
        );
        drop(program);

        // The control: a hold makes the same question answer that it is held.
        let hold = File::open(&path).expect("a program opens its manifest");
        rustix::fs::flock(&hold, rustix::fs::FlockOperation::NonBlockingLockShared)
            .expect("the hold");
        let again = File::open(&path).expect("the question opens the manifest");
        assert!(!probe_is_free(&again).expect("asks"), "a hold is seen");
        drop(copy);
    }

    /// Removing a release follows no link: a name that is a link is taken away and what it pointed
    /// at is left as it was, and a release whose files are hard links to files elsewhere goes as
    /// names only, those files keeping their contents and their modes.
    #[test]
    fn removing_a_release_follows_no_link_and_touches_nothing_outside_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let test = test_store();
        let update = test
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let outside = test
            .store
            .root()
            .parent()
            .expect("the test's own directory")
            .join("outside");
        std::fs::create_dir_all(outside.join("release/bin")).expect("a directory elsewhere");
        let mode_of =
            |path: &Path| std::fs::metadata(path).expect("there").permissions().mode() & 0o777;

        // A name that is a link to a whole release elsewhere.
        let one = release("0.1.0+aaaaaaaaaaaa");
        std::fs::write(outside.join("release/release.json"), manifest_of(&one)).expect("written");
        std::fs::write(outside.join("release/bin/kr"), b"#!/bin/sh\n").expect("written");
        std::fs::set_permissions(
            outside.join("release"),
            std::fs::Permissions::from_mode(0o555),
        )
        .expect("read-only");
        std::os::unix::fs::symlink(outside.join("release"), test.store.release_directory(&one))
            .expect("a link under the release's name");
        assert!(test.store.retire(&one, &update).expect("removes the name"));
        assert!(
            std::fs::symlink_metadata(test.store.release_directory(&one)).is_err(),
            "the name is gone"
        );
        assert_eq!(mode_of(&outside.join("release")), 0o555, "not followed");
        assert!(outside.join("release/bin/kr").is_file(), "nothing removed");
        std::fs::set_permissions(
            outside.join("release"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("writable again");

        // A release whose program is a hard link to a file elsewhere.
        let two = release("0.2.0+bbbbbbbbbbbb");
        let program = install(&test.store, &two);
        std::fs::write(outside.join("shared"), b"shared contents").expect("written");
        std::fs::set_permissions(
            outside.join("shared"),
            std::fs::Permissions::from_mode(0o444),
        )
        .expect("read-only");
        std::fs::remove_file(&program).expect("the copy goes");
        std::fs::hard_link(outside.join("shared"), &program).expect("a hard link");
        assert!(test.store.retire(&two, &update).expect("removes"));
        assert!(!test.store.release_directory(&two).exists());
        assert_eq!(
            std::fs::read(outside.join("shared")).expect("still there"),
            b"shared contents"
        );
        assert_eq!(mode_of(&outside.join("shared")), 0o444, "its mode is kept");
    }

    /// A release's file that is a link or a pipe is refused at once, never followed or waited for,
    /// and a program whose release is being removed or replaced waits for that a bound only.
    #[test]
    fn a_link_or_a_pipe_is_refused_and_a_removal_that_never_ends_is_waited_for_a_bound() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let image = install(&test.store, &one);
        let path = test.store.manifest(&one);
        let kind_of = |error: Option<std::io::Error>| error.map(|error| error.kind());

        // The control: the regular file opens and reads whole, and a limit is kept.
        assert!(open_regular_file(&path).is_ok());
        assert_eq!(
            read_regular_file(&path, 1 << 20).expect("reads"),
            manifest_of(&one).into_bytes()
        );
        assert_eq!(
            kind_of(read_regular_file(&path, 4).err()),
            Some(std::io::ErrorKind::InvalidData),
            "a file longer than its limit is refused"
        );

        // A link, and a pipe nothing writes to: refused, not followed and not waited for.
        let elsewhere = test.store.root().join("elsewhere.json");
        std::fs::write(&elsewhere, manifest_of(&one)).expect("a file elsewhere");
        let link = test.store.root().join("link.json");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("a link");
        assert_eq!(
            kind_of(open_regular_file(&link).err()),
            Some(std::io::ErrorKind::InvalidData)
        );
        let pipe = test.store.root().join("pipe.json");
        make_pipe(&pipe);
        let began = Instant::now();
        assert_eq!(
            kind_of(open_regular_file(&pipe).err()),
            Some(std::io::ErrorKind::InvalidData)
        );
        assert!(
            kind_of(read_regular_file(&pipe, 1 << 20).err()).is_some(),
            "a pipe is not read"
        );
        assert!(
            began.elapsed() < Duration::from_secs(20),
            "and not waited for"
        );
        // A program whose release has a pipe for its manifest does not start, and does not wait.
        std::fs::remove_file(&path).expect("the manifest goes");
        make_pipe(&path);
        assert!(Running::of_image(&image).is_err());
        assert!(test.store.held(&one).is_err(), "nor is a pipe locked");
        std::fs::remove_file(&path).expect("the pipe goes");
        std::fs::write(&path, manifest_of(&one)).expect("the manifest is back");

        // A removal that holds the manifest and never ends: a start waits its bound and refuses,
        // and once the removal lets go it holds.
        let removal = File::open(&path).expect("the removal opens the manifest");
        rustix::fs::flock(
            &removal,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("the removal holds it");
        let opened = File::open(&path).expect("a program opens its manifest");
        let began = Instant::now();
        assert!(matches!(
            hold_opened_within(opened, path.clone(), &one, Duration::from_millis(200)),
            Err(InstallError::Replaced { .. })
        ));
        assert!(
            began.elapsed() < Duration::from_secs(20),
            "a bound, and no more"
        );
        drop(removal);
        let opened = File::open(&path).expect("a program opens its manifest");
        // A program another test starts while the removal's lock is held keeps a copy of it until
        // its own program takes over, so the start waits for the lock rather than for a time.
        assert!(hold_opened_within(opened, path, &one, RELEASE_WAIT).is_ok());
    }

    /// A program that opened its manifest while its release was being removed does not run: once
    /// its lock is granted, the path no longer names the file it locked.
    #[test]
    fn a_program_whose_release_went_while_it_started_refuses_to_run() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        install(&test.store, &one);
        let path = test.store.manifest(&one);

        // The control: opened and locked with nothing in between, it is the release's manifest.
        let opened = File::open(&path).expect("a program opens its manifest");
        let (held, manifest) = hold_opened(opened, path.clone(), &one).expect("held");
        assert_eq!(manifest.release, one);
        drop(held);

        // Opened, then the release moved out of `versions/` as a removal moves it.
        let opened = File::open(&path).expect("a program opens its manifest");
        let aside = test.store.trash().join("moved");
        std::fs::rename(test.store.release_directory(&one), &aside).expect("moved aside");
        assert!(matches!(
            hold_opened(opened, path.clone(), &one),
            Err(InstallError::Replaced { .. })
        ));

        // Opened, then another manifest put at the same path: the name is the same, the file is
        // not, and the lock is on the file.
        std::fs::rename(&aside, test.store.release_directory(&one)).expect("moved back");
        let opened = File::open(&path).expect("a program opens its manifest");
        std::fs::remove_file(&path).expect("the manifest goes");
        std::fs::write(&path, manifest_of(&one)).expect("another manifest at its path");
        assert!(matches!(
            hold_opened(opened, path, &one),
            Err(InstallError::Replaced { .. })
        ));

        // And a program whose release has gone altogether does not start.
        let image = test
            .store
            .release_directory(&one)
            .join("bin")
            .join(Program::Kr.file_name());
        std::fs::remove_dir_all(test.store.release_directory(&one)).expect("gone");
        std::fs::create_dir_all(image.parent().expect("bin")).expect("an empty bin");
        assert!(matches!(
            Running::of_image(&image),
            Err(InstallError::Replaced { .. })
        ));
    }

    /// The switch replaces `current` in one rename, and names only releases of the store.
    #[test]
    fn the_switch_renames_one_link_over_current() {
        let test = test_store();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let two = release("0.2.0+bbbbbbbbbbbb");
        install(&test.store, &one);
        install(&test.store, &two);
        assert_eq!(test.store.current().expect("reads"), None);
        let update = test
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let held = test
            .store
            .try_lock_install()
            .expect("locks")
            .expect("nothing starts a daemon");
        test.store.switch(&one, &update, &held).expect("switches");
        assert_eq!(test.store.current().expect("reads"), Some(one.clone()));
        test.store.switch(&two, &update, &held).expect("switches");
        assert_eq!(test.store.current().expect("reads"), Some(two.clone()));
        assert_eq!(
            std::fs::read_link(test.store.current_link()).expect("a link"),
            Path::new("versions").join(two.as_str()),
            "the link is relative, so the store can move"
        );
        assert_eq!(
            test.store.releases().expect("lists"),
            vec![one.clone(), two.clone()]
        );
        // The control: a release that is not in the store is never made current.
        let absent = release("0.3.0+cccccccccccc");
        assert!(test.store.switch(&absent, &update, &held).is_err());
        assert_eq!(test.store.current().expect("reads"), Some(two));
        let leftovers: Vec<_> = std::fs::read_dir(test.store.root())
            .expect("the store")
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "no temporary link is left behind");
    }

    /// One update at a time: the update lock is refused while another holds it.
    #[test]
    fn one_update_at_a_time() {
        let test = test_store();
        let first = test.store.try_lock_update().expect("locks").expect("free");
        assert!(test.store.try_lock_update().expect("asks").is_none());
        drop(first);
        assert!(test.store.try_lock_update().expect("asks").is_some());
    }

    /// The roots a daemon records are read back whole, a path of any bytes included.
    #[test]
    fn the_roots_a_daemon_served_are_read_back() {
        use std::os::unix::ffi::OsStrExt as _;

        let test = test_store();
        let odd = PathBuf::from(OsStr::from_bytes(b"/tmp/state-\xff"));
        test.store
            .record_roots(Path::new("/tmp/runtime"), &odd)
            .expect("records");
        test.store
            .record_roots(Path::new("/tmp/runtime-two"), Path::new("/tmp/state-two"))
            .expect("records");
        // The same state root recorded again replaces its record rather than adding one.
        test.store
            .record_roots(Path::new("/tmp/runtime-again"), &odd)
            .expect("records");
        let mut recorded: Vec<(PathBuf, PathBuf)> = test
            .store
            .recorded_roots()
            .expect("reads")
            .into_iter()
            .map(|roots| (roots.runtime_root, roots.state_root))
            .collect();
        recorded.sort();
        assert_eq!(
            recorded,
            vec![
                (PathBuf::from("/tmp/runtime-again"), odd),
                (
                    PathBuf::from("/tmp/runtime-two"),
                    PathBuf::from("/tmp/state-two")
                ),
            ]
        );
    }

    /// A program in a release being installed or removed does not start, however deep in the
    /// staging or the trash it is: an update unpacks under `staging/<run>/<top>/`, and an install
    /// copies under `staging/<run>/release/`.
    #[test]
    fn a_program_in_the_staging_or_the_trash_does_not_start() {
        let test = test_store();
        let kr = Program::Kr.file_name();
        for image in [
            test.store
                .trash()
                .join("0.1.0+aaaaaaaaaaaa-x/bin")
                .join(&kr),
            test.store.staging().join("run/bin").join(&kr),
            test.store
                .staging()
                .join("run/kalareach-aarch64-apple-darwin-0.1.0+aaaaaaaaaaaa/bin")
                .join(&kr),
            test.store.staging().join("run/release/bin").join(&kr),
            test.store.staging().join(&kr),
        ] {
            assert!(
                matches!(
                    Running::of_image(&image),
                    Err(InstallError::Replaced { .. })
                ),
                "{}",
                image.display()
            );
        }
        // A program inside a release but not in its `bin/` would run it without holding it.
        let one = release("0.1.0+aaaaaaaaaaaa");
        install(&test.store, &one);
        let inside = test
            .store
            .release_directory(&one)
            .join("share/bin")
            .join(&kr);
        assert!(matches!(
            Running::of_image(&inside),
            Err(InstallError::Replaced { .. })
        ));
        // The controls: the same layouts without a store record are builds outside a store, and
        // the release's own program is its release's.
        let program = test.store.release_directory(&one).join("bin").join(&kr);
        assert_eq!(
            Running::of_image(&program).expect("held").release(),
            Some(&one)
        );
        std::fs::remove_file(test.store.record()).expect("the record goes");
        for image in [
            test.store.staging().join("run/release/bin").join(&kr),
            inside,
        ] {
            assert!(
                matches!(Running::of_image(&image), Ok(Running::Loose { .. })),
                "{}",
                image.display()
            );
        }
    }
}
