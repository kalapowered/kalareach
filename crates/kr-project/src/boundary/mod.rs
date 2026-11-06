//! The execution boundary every Git invocation runs inside.
//!
//! The restricted profile in [`crate::git`] decides what Git is *asked* to do: which program, which
//! environment, which configuration. It cannot decide what Git *may* do, because a Git invocation
//! resolves the directory it was pointed at for itself and reads the configuration for itself,
//! after this host has read both. A writer under the same operating-system account can put a
//! driver in the repository, or a different tree at the path, in the moment between the reading and
//! the process starting. Re-reading afterwards notices that; it does not undo a helper that ran or
//! a write that landed.
//!
//! So each invocation is also enclosed. The boundary is applied by the operating system, from
//! outside Git, and it holds whatever the repository's configuration says and whoever writes to the
//! repository while Git is running. It enforces three things.
//!
//! 1. **Only Git executes.** The Git program, the helpers under Git's own `--exec-path`, the
//!    approved broker's ssh program for a remote that needs one, and — only for an invocation that
//!    reaches a repository over Git's own transport, whatever that transport is — the shell Git
//!    builds its connection and its call to a credential helper as a command string for.
//!    A driver, filter, hook, credential helper, pager or fsmonitor anywhere else — in the
//!    repository, in the staging directory, in this invocation's private temporary directory —
//!    cannot be executed, whether it was planted before the configuration was read, between the
//!    reading and the spawn, or while Git is running.
//! 2. **Only this operation's network.** A local operation reaches nothing at all. A remote
//!    operation may open outbound connections to the ports its transport uses and resolve the
//!    remote's name, and nothing may listen.
//! 3. **Only this operation's directories are written.** The repository's working tree and its Git
//!    common directory, the destination this operation reserved, and one private temporary
//!    directory made for the invocation. Everything else is read-only. That temporary directory is
//!    taken away again by the record this host wrote before it made it, and `README.md` in this
//!    crate says what is left behind instead, and why.
//!
//! For the owner's own operations reads are not confined on macOS or Linux, and this is deliberate:
//! the owner already holds the account's authority over the owner's own files, and Git reads the
//! system's shared libraries, its locale data and its certificate store, so a read confinement
//! that missed one of those would fail an operation for a reason that has nothing to do with
//! safety. What such an operation can reach by reading is bounded by the account the service runs
//! as, exactly as it was before.
//!
//! An operation performed for a caller bounded by a grant is different, because it may reach only
//! what the owner named. On Linux and on macOS its reads are confined to what the invocation is
//! granted and to a support set named for this host's own Git ([`Reads::Bounded`]), and it is
//! refused when a filesystem is mounted beneath a directory it would be granted. On a platform that
//! does not confine reads it is refused outright. Windows confines reading with everything else,
//! and what an invocation reads outside the directories the operation owns is granted by name.
//!
//! ## Directories, not names
//!
//! Every directory the boundary lets an invocation write in is opened first, and required to be
//! the object the caller holds an identity for: the working tree by the identity the repository's
//! record carries, or, for a checkout handed over by path, by the one this host read from the
//! directory it opened a moment before; the Git common directory by its own; the reserved
//! destination by the identity the reservation returned; and the invocation's own temporary
//! directory by the identity this host read when it made it. A directory the request holds no
//! identity for is held to the object that was opened. The programs an invocation may execute
//! (Git's, the approved ssh program and the shell of point 1) and Git's helper directory under
//! its exec-path are not written in, and nobody holds an identity for them: Linux opens each by
//! its path when it makes its rules, and the profile on macOS names each by its path. After the
//! run the directories it may write in (the working directory, the Git
//! common directory, a destination it reserved and its own temporary directory) are opened again
//! and confirmed against the same identity. The child then does not start at a path either: it
//! moves into the open working directory before the boundary is applied and before Git runs, with
//! `-C .` as its only directory argument. A tree substituted at a name afterwards is therefore
//! neither the tree Git works in nor a tree the boundary was built around.
//!
//! What the kernels enforce is narrower than the sentence above, and is stated as what it is:
//! **opens for writing succeed only inside the granted root objects' subtrees as they stand at open
//! time; execution stays confined; the granted roots are re-confirmed by identity before the spawn
//! and after the run.** Which object a subtree is, is decided by the opened directory on Linux,
//! where Landlock's rules are attached to it, and by the resolved path on macOS, where the profile
//! names it.
//!
//! Neither kernel asks again on each write through a file already open, so a file opened inside a
//! granted subtree that a same-account writer then moves out of it is still written through that
//! descriptor. That is an accepted limit rather than a choice made here: the writer who could move
//! it already holds write access to it. Excluding it needs isolation of another kind.
//!
//! The re-confirmation after the run is **detection**: it says that a root changed, it does not
//! keep one from changing. Two readings cannot tell a change made and undone from no change at all,
//! and waiting for Git establishes that Git has gone rather than that everything it started has.
//!
//! Inside a granted subtree the kernel draws no further line, and this host does not pretend to.
//! A directory put at an unrecorded name *inside* a tree the operation owns is written to as the
//! rest of that tree is, and it is outside the guarantee rather than inside it by accident: the
//! only writer who could put it there is a writer under this same account, who could write those
//! files directly and needs no substitution to do it. What that writer still cannot get is anything
//! executed — the execution list is Git and the helpers under its own exec-path, whatever is
//! planted — or any address the operation was not given.
//!
//! ## What enforces what
//!
//! | Platform | Execution | Network | Writes | Reads for a caller bounded by a grant |
//! | --- | --- | --- | --- | --- |
//! | macOS | A per-invocation sandbox profile, applied by the system's own launcher before it runs Git | The same profile | The same profile | The same profile, with no rule on the whole filesystem: the granted paths, resolved, and the named support set only |
//! | Linux | Landlock, with the execute right only on Git's own program and helper directory | Landlock's TCP rules for a remote operation, and a system-call filter that makes a socket only of what the boundary can account for | Landlock, from the opened directory handles | Landlock, with no rule on the whole filesystem: the granted objects and the named support set only |
//! | Windows: **refused, and never run** | An application container whose grants on the repository carry no execute right | The container's capabilities: none at all for a local operation | The container's grants, inside a job object that ends every descendant | Refused, as every invocation is |
//!
//! The Windows row is what the code there would do. **It has never been executed, and this host
//! runs no repository operation on that platform**: two of the three guarantees are not things an
//! application container can hold, and `README.md` in this crate says which and why.
//!
//! A platform that cannot establish its boundary refuses the invocation. Nothing here falls back to
//! reading the configuration and hoping.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_protocol::ids::EnvironmentId;
use kr_protocol::project::RemoteTransport;
pub use kr_transfer::ObjectIdentity;
use kr_transfer::{AuthorisedDirectory, RecordedIdentity, Settled};

use crate::error::{ProjectError, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use self::linux as platform;
#[cfg(target_os = "macos")]
use self::macos as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use self::unsupported as platform;
#[cfg(windows)]
use self::windows as platform;

#[cfg(all(target_os = "linux", feature = "git-fixtures"))]
pub use self::linux::{with_kernel_interface, with_no_git};
#[cfg(all(target_os = "macos", any(test, feature = "git-fixtures")))]
pub use self::macos::{profile_text, with_launcher_at};
#[cfg(unix)]
pub use self::unix::{Spawned, start};
#[cfg(windows)]
pub use self::windows::{Spawned, start};

/// What mechanism encloses an invocation on this platform, for a person reading a record.
pub const MECHANISM: &str = platform::MECHANISM;

/// Why this platform runs no Git, on a platform that runs none.
///
/// Said before Git is looked for, so that a host that cannot run Git at all answers the same way
/// whether or not one is installed.
pub const NO_GIT: Option<&str> = platform::NO_GIT;

/// Why this platform runs no Git, when it runs none, as a request is told: [`NO_GIT`], except that
/// on Linux a case can force a reason, since the platform's own is empty on every machine this
/// host ships for and a refusal that nothing can reach is a refusal nothing holds.
pub(crate) fn no_git() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        linux::no_git()
    }
    #[cfg(not(target_os = "linux"))]
    {
        NO_GIT
    }
}

/// The refusal a platform that runs no Git gives every request that needs it, with the reason that
/// platform gives for running none.
///
/// The condition does not pass: no wait, no retry and no install changes it. So the refusal says
/// what the platform cannot do and ends with the host to use instead, which each platform's reason
/// names, and it is the one of a host that is not set up for the work, which a client does not send
/// again, and not the one of an upstream that may answer later.
pub(crate) fn no_git_refusal(why: &str) -> ProjectError {
    ProjectError::GitUnavailable {
        detail: format!("Git is not run on this platform: {why}").into(),
    }
}

/// The refusal of a host whose kernel cannot build the boundary around a Git invocation at all,
/// when it cannot.
///
/// Said before Git is looked for, as [`NO_GIT`] is, and for the same reason: a host that cannot run
/// Git answers the same way whether or not one is installed. Nothing the daemon does changes it
/// until the host does (another kernel, Landlock enabled at boot, a filter that allows the call),
/// so it is not an upstream that may answer later. Only Linux asks its kernel; the other platforms'
/// mechanisms need nothing of one.
pub(crate) fn kernel_refusal() -> Option<ProjectError> {
    #[cfg(target_os = "linux")]
    {
        linux::kernel_refusal()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The ports an https remote is reached on.
///
/// Both, because a server may answer an https request with a redirection to the same repository
/// over http and Git follows it; a transport that ends up on neither port is refused by the
/// boundary rather than by a later check.
pub const HTTPS_PORTS: &[u16] = &[80, 443];

/// The port an ssh remote is reached on.
pub const SSH_PORTS: &[u16] = &[22];

/// What one invocation may reach over the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Nothing. No address is connected to and nothing may listen.
    Nothing,
    /// Outbound connections to these ports, and the host's own name resolution. Nothing may listen.
    Outbound(Vec<u16>),
}

impl Reach {
    /// Returns what a request with this transport and this explicit port may reach.
    ///
    /// A local path is a local operation: a clone between two directories of this machine reaches
    /// no address, so a configuration that rewrote its URL into a network one has nothing to reach
    /// through.
    #[must_use]
    pub fn for_transport(transport: Option<RemoteTransport>, port: Option<u16>) -> Self {
        let mut ports = match transport {
            None | Some(RemoteTransport::LocalPath) => return Self::Nothing,
            Some(RemoteTransport::Https) => HTTPS_PORTS.to_vec(),
            Some(RemoteTransport::Ssh) => SSH_PORTS.to_vec(),
        };
        // A remote may name a port of its own, and the URL it named was validated before anything
        // ran. Without it a repository served on another port could not be reached at all.
        if let Some(port) = port
            && !ports.contains(&port)
        {
            ports.push(port);
        }
        Self::Outbound(ports)
    }

    /// Returns the ports outbound connections may go to, which is empty when nothing may be
    /// reached.
    #[must_use]
    pub fn ports(&self) -> &[u16] {
        match self {
            Self::Nothing => &[],
            Self::Outbound(ports) => ports,
        }
    }
}

/// The refusal for a directory that could not be opened: the place, and the reason the system gave
/// for it, in the open's own words. A directory an invocation is enclosed around, a recorded tree
/// and a root no record names are refused in these words alike. A link that cannot be followed
/// reads as the system's reason for it, where the transfer crate's `open_root` words it as a link.
///
/// A host too short of descriptors, processes or memory to open the place has said nothing of the
/// place, so the refusal is a fault that passes, which a client sends the request again after.
/// Any other failure is the caller's argument.
pub(crate) fn unopenable(path: &Path, error: &std::io::Error) -> ProjectError {
    refused_by(
        error,
        format!("{} could not be opened: {error}", path.display()),
    )
}

/// The refusal for a failure to open or to resolve a directory, in `detail`: a fault that passes
/// when the host was too short of descriptors, processes or memory, and the caller's argument
/// otherwise.
pub(crate) fn refused_by(error: &std::io::Error, detail: String) -> ProjectError {
    let detail = crate::git::redact(&detail);
    if crate::git::short_of_resources(error) {
        ProjectError::GitFailed {
            detail: detail.into(),
        }
    } else {
        ProjectError::Destination {
            detail: detail.into(),
        }
    }
}

/// An opened directory, the object it was opened on, and the path that object had.
///
/// The handle is the authority. The path is what two of the three mechanisms write their rules
/// against, because that is what they take, and it is resolved here beside the handle rather than
/// separately from it.
#[derive(Debug)]
pub struct OpenedDirectory {
    environment_id: EnvironmentId,
    directory: AuthorisedDirectory,
    path: PathBuf,
    identity: ObjectIdentity,
    created_at_ms: Option<u64>,
}

impl OpenedDirectory {
    /// Opens one directory and requires it to be the object the caller holds an identity for.
    ///
    /// The identity is the one a record names where a record does. Where none does, as for a
    /// checkout that `project.adopt` is handed by path, or for the invocation's own private
    /// temporary directory, it is the one this host read from the directory it opened a moment
    /// before, and a directory that goes after that is a change just the same. With no identity at
    /// all there is nothing to have changed.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be opened or its path
    /// cannot be resolved, except that a host too short of descriptors, processes or memory to
    /// open it or to resolve its path is [`ProjectError::GitFailed`], a fault that passes, and
    /// [`ProjectError::IdentityChanged`] when the caller holds an identity and the object at the
    /// path is a different one, or the open or the resolution of the path finds nothing there:
    /// the object the identity names is gone, which is a source that changed and not an argument
    /// the caller got wrong. With no identity, a directory that is gone is the caller's argument.
    /// Each step answers for what it found itself, as it does where a recorded tree is first
    /// opened, and nothing looks at the path again to decide. A failure to open is worded by the
    /// open's own error (`unopenable`), so a link that leads round to itself reads as the
    /// system's reason for it and not as a link, as the transfer crate's `open_root` words it. A
    /// platform that reports a parent that is a file as not found, as Windows may, reads it as
    /// nothing there too; that platform runs no Git, so no request reaches it.
    pub fn open(
        environment_id: EnvironmentId,
        path: &Path,
        expected: Option<ObjectIdentity>,
    ) -> Result<Self> {
        let gone = || ProjectError::IdentityChanged {
            detail: format!(
                "{} was identified for this invocation, and it holds nothing now; the invocation \
                 is not enclosed around it",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
        };
        let nothing = |error: &std::io::Error| {
            expected.is_some() && error.kind() == std::io::ErrorKind::NotFound
        };
        let directory = match crate::identity::open_directory(path) {
            Ok(handle) => {
                AuthorisedDirectory::from_handle(environment_id, handle, path.to_path_buf())?
            }
            Err(error) if nothing(&error) => return Err(gone()),
            // The open's own error is the answer and gives the words. Nothing opens the path
            // again, so what is there by then cannot change them.
            Err(error) => return Err(unopenable(path, &error)),
        };
        let identity = directory.identity();
        if let Some(expected) = expected
            && expected != identity
        {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "{} was identified as {expected} for this invocation, and it holds {identity} \
                     now; the invocation is not enclosed around it",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        }
        // Every mechanism's rules are written against a path with no link left in it, so the path
        // is resolved once, here, beside the handle rather than at each rule.
        let resolved = crate::identity::resolve_directory(path).map_err(|error| {
            if nothing(&error) {
                return gone();
            }
            refused_by(
                &error,
                format!(
                    "{} could not be resolved to a directory this invocation may use: {error}",
                    path.display()
                ),
            )
        })?;
        let created_at_ms = created_at_ms(directory.handle());
        Ok(Self {
            environment_id,
            directory,
            path: resolved,
            identity,
            created_at_ms,
        })
    }

    /// Returns the handle. On Linux it is what the rules themselves are attached to.
    #[must_use]
    pub const fn handle(&self) -> &AuthorisedDirectory {
        &self.directory
    }

    /// Returns the resolved path the object had when it was opened.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the object that was opened.
    #[must_use]
    pub const fn identity(&self) -> ObjectIdentity {
        self.identity
    }

    /// Refuses when the path this invocation was started at no longer holds the object that was
    /// opened.
    ///
    /// Where a platform starts a process at a path rather than in an open directory, this is what
    /// answers for the difference: the object at the path is opened again and required to be the
    /// same one, by identity and by the instant the filesystem says it was created. A creation
    /// instant does not change when a directory is written in, so an ordinary operation passes
    /// this and an object made in place of the one that was opened does not.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the object or its creation instant differs,
    /// or when the path no longer opens, and [`ProjectError::GitFailed`], a fault that passes,
    /// when the host is too short of descriptors, processes or memory to open it again.
    pub fn confirm_path(&self) -> Result<()> {
        // The directory is one this invocation was enclosed around: the one it ran in, one it
        // reserved, or its own temporary directory, so the words name the place and no role.
        let shown = crate::git::redact(&self.path.display().to_string());
        // A name that no longer opens at all is the same answer as a name that opens on something
        // else, and it is said the same way rather than as whatever the open failed with.
        let unconfirmed = || ProjectError::IdentityChanged {
            detail: format!(
                "{shown}, a directory this invocation was enclosed around, could not be \
                 confirmed to be the object it was started against, so what it produced is not \
                 served"
            )
            .into(),
        };
        let now = match crate::identity::open_directory(&self.path) {
            Ok(handle) => {
                AuthorisedDirectory::from_handle(self.environment_id, handle, self.path.clone())
                    .map_err(|_| unconfirmed())?
            }
            // A host too short of descriptors, processes or memory to open the directory has said
            // nothing of it, so it is not a directory that changed.
            Err(error) if crate::git::short_of_resources(&error) => {
                return Err(unopenable(&self.path, &error));
            }
            Err(_) => return Err(unconfirmed()),
        };
        if now.identity() != self.identity || created_at_ms(now.handle()) != self.created_at_ms {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "{shown}, a directory this invocation was enclosed around, is not the object \
                     it was started against, so what it produced is not served"
                )
                .into(),
            });
        }
        Ok(())
    }
}

/// Returns the instant the filesystem says a directory was created, where it says.
///
/// Only the creation instant: a modification instant changes whenever the directory is written in,
/// which every ordinary operation does. Where a platform reports no creation instant this is
/// nothing, and the identity alone is the witness, which is what the project service already
/// records elsewhere.
fn created_at_ms(directory: &cap_std::fs::Dir) -> Option<u64> {
    directory
        .dir_metadata()
        .ok()
        .and_then(|metadata| metadata.created().ok())
        .and_then(|instant| {
            instant
                .into_std()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
        })
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// Everything one invocation is allowed to do, as the boundary is built from it.
#[derive(Debug)]
pub struct Confinement {
    /// The Git program the child executes.
    pub program: PathBuf,
    /// Git's own helper directory. Everything Git runs for itself lives under it.
    pub exec_path: PathBuf,
    /// The programs outside Git's own installation this one invocation may execute.
    pub helpers: Vec<PathBuf>,
    /// The directory the child starts in, as the object this host opened.
    pub working: OpenedDirectory,
    /// The other directories this operation owns: a repository's Git common directory, a
    /// destination the operation reserved. Each is the object the identity held for it names.
    pub reserved: Vec<OpenedDirectory>,
    /// The private temporary directory this invocation owns for its own length.
    pub temporary: OpenedDirectory,
    /// Directories the invocation must be able to read where the platform's mechanism confines
    /// reading as well as writing.
    pub readable: Vec<PathBuf>,
    /// What it may reach over the network.
    pub reach: Reach,
    /// What it may read.
    pub reads: Reads,
}

/// What one invocation may read.
#[derive(Clone, Debug)]
pub enum Reads {
    /// Whatever the account this service runs as can read. The owner's own operations: the owner
    /// already holds that authority over the owner's own files, so the boundary takes none of it
    /// away.
    Everywhere,
    /// Only what the invocation is granted, for an operation performed for a caller bounded by a
    /// grant: the directories the operation owns, the ones it is lent to read, Git's own program
    /// and helper directory, the device nodes every process needs, and the support set named for
    /// this host's Git. Nothing else the account can read is readable.
    ///
    /// A support set is named only where the platform confines what a process reads, so an
    /// invocation bounded this way exists only there.
    Bounded(Arc<SupportSet>),
}

/// The system objects this host's Git needs in order to run, named by object.
///
/// Found on the host rather than written down. On Linux: the loader each of Git's programs names
/// for itself, which the kernel opens for execution when it starts the program, and the
/// directories the libraries that loader resolves for it are in, which are read and never executed.
/// On macOS: the directories of the libraries Git loads that the system does not supply from its
/// shared cache, found from the load commands of Git and of each program in its helper directory;
/// there is no loader to name, and a Git that links only the system's libraries has an empty set.
/// A library directory rather than each library, because Git and the libraries it links open
/// further modules by name while running, and those resolve within the same directories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportSet {
    loaders: Vec<PathBuf>,
    libraries: Vec<PathBuf>,
}

impl SupportSet {
    /// Returns the program loaders, each resolved to the object it is.
    #[must_use]
    pub fn loaders(&self) -> &[PathBuf] {
        &self.loaders
    }

    /// Returns the library directories, each resolved to the object it is.
    #[must_use]
    pub fn libraries(&self) -> &[PathBuf] {
        &self.libraries
    }
}

/// Names the support set of the programs an invocation bounded by a grant may execute: the
/// programs given, and every program in Git's own helper directory.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when a program's loader, or a library its loader resolves
/// for it, cannot be named, and on every platform that does not confine what a process reads,
/// where a caller bounded by a grant is not served a Git invocation at all.
pub fn support_set(programs: &[&Path], helper_directory: &Path) -> Result<SupportSet> {
    #[cfg(target_os = "linux")]
    {
        let (loaders, libraries) = linux::support_set(programs, helper_directory)?;
        Ok(SupportSet { loaders, libraries })
    }
    // The loader is the system's own on this platform, and no object a profile could name, so
    // only the libraries the system does not supply are named.
    #[cfg(target_os = "macos")]
    {
        let libraries = macho::support_set(programs, helper_directory)?;
        Ok(SupportSet {
            loaders: Vec::new(),
            libraries,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (programs, helper_directory);
        Err(reads_not_confined())
    }
}

/// The refusal a platform that does not confine what a process reads gives a caller bounded by a
/// grant.
///
/// On Windows no Git runs at all, and no other platform has a boundary. So none can bound what Git
/// reads for such a caller, and the invocation is refused rather than run with the owner's reach.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reads_not_confined() -> ProjectError {
    ProjectError::GitFailed {
        detail: "this platform does not confine what Git reads, so an invocation for a caller \
                 bounded by a grant is not run here"
            .into(),
    }
}

/// Returns the first of these mount points that lies beneath one of these directories, and that
/// directory. A directory that is itself a mount point has nothing mounted beneath it by that.
///
/// Both platforms that confine what a caller bounded by a grant reads compare the same way, each
/// against its own mount table.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn first_mount_beneath(
    points: impl IntoIterator<Item = PathBuf>,
    directories: &[PathBuf],
) -> Option<(PathBuf, &Path)> {
    points.into_iter().find_map(|point| {
        directories
            .iter()
            .find(|directory| point != **directory && point.starts_with(directory))
            .map(|directory| (point.clone(), directory.as_path()))
    })
}

/// The refusal for a filesystem mounted beneath a directory an invocation bounded by a grant would
/// be granted.
///
/// A rule on a directory reaches everything beneath it as the system presents it at each open, and
/// that includes another filesystem mounted there, so such an invocation is not run over it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn mounted_beneath(point: &Path, directory: &Path) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!(
            "a filesystem is mounted at {}, beneath {}, which this invocation would be granted; \
             an invocation for a caller bounded by a grant is not run over a directory with \
             another filesystem inside it",
            crate::git::redact(&point.display().to_string()),
            crate::git::redact(&directory.display().to_string())
        )
        .into(),
    }
}

impl Confinement {
    /// Returns every directory the invocation may write in, in the order the rules are made.
    pub fn written(&self) -> impl Iterator<Item = &OpenedDirectory> {
        std::iter::once(&self.working)
            .chain(self.reserved.iter())
            .chain(std::iter::once(&self.temporary))
    }

    /// Refuses when a granted root this invocation was enclosed around is no longer the object it
    /// was enclosed around.
    ///
    /// This is detection, and the name for it here is detection. It is called after the child has
    /// gone and before its result is given to a caller, and what it produces is this service's
    /// declared honest result rather than a result nobody can account for. Two of the three
    /// mechanisms write their rules against paths, so a directory substituted at one of those names
    /// while Git ran is a directory the rules still permitted, and Git given that name by an
    /// argument would have written there. Reading the identity afterwards says that; it does not
    /// prevent it.
    ///
    /// Two readings cannot tell a change made and undone from no change at all, this covers the
    /// granted roots and not every descendant of them, and waiting for Git does not establish that
    /// every process it started has gone. All three are stated in `crates/kr-project/README.md`
    /// rather than implied.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when any of them differs or no longer opens, and
    /// [`ProjectError::GitFailed`], a fault that passes, when the host is too short of
    /// descriptors, processes or memory to open one again.
    pub fn confirm(&self) -> Result<()> {
        for directory in self.written() {
            directory.confirm_path()?;
        }
        Ok(())
    }

    /// Returns every program the invocation may execute, besides Git's own helper directory.
    #[must_use]
    pub fn executables(&self) -> Vec<&Path> {
        let mut programs: Vec<&Path> = vec![&self.program];
        programs.extend(self.helpers.iter().map(std::path::PathBuf::as_path));
        programs
    }
}

/// The parts of an invocation the boundary starts.
#[derive(Debug)]
pub struct Invocation<'a> {
    /// The program to execute, which is Git.
    pub program: &'a Path,
    /// Its arguments, after the program name.
    pub arguments: &'a [std::ffi::OsString],
    /// The complete environment, built from nothing.
    pub environment: &'a [(std::ffi::OsString, std::ffi::OsString)],
    /// How the invocation reads for a person, for a diagnostic.
    pub described: &'a str,
}

/// Returns the shell Git starts a connection through on this platform.
///
/// Git builds its connection to a repository, and its call to a credential helper, as one command
/// string and starts it through the system shell, so an invocation that reaches a repository over
/// Git's own transport cannot run without one. It is in the execution list for exactly those
/// invocations, and every one of them is a clone that does not check anything out: no attribute is
/// consulted, so no driver, filter or text conversion is looked for, and a hook is looked for in a
/// directory this host owns and keeps empty, which is a fixed override rather than anything the
/// clone decides. So there is nothing in one of those invocations for a repository to reach the
/// shell through. The checkout that follows is a separate invocation, and its list holds no shell
/// at all.
///
/// Every candidate that exists is named, because which of them the system uses is the system's
/// decision rather than this host's: on Apple platforms `/bin/sh` re-executes the shell it is a
/// variant of, and on Windows the shell is the one inside Git's own installation rather than a
/// path this host could write down.
#[must_use]
pub fn connection_shell(exec_path: &Path) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        // Git for Windows ships its own shell inside the installation, and how far the helper
        // directory sits below that installation is the packaging's decision: an ordinary install
        // puts it at `<root>\mingw64\libexec\git-core` and the shell at `<root>\usr\bin\sh.exe`,
        // and other layouts put both one level nearer. So every ancestor is tried rather than a
        // fixed number of them, and only what exists is kept.
        for root in exec_path.ancestors() {
            for relative in ["usr/bin/sh.exe", "bin/sh.exe"] {
                candidates.push(root.join(relative));
            }
        }
    } else {
        candidates.push(PathBuf::from("/bin/sh"));
        if cfg!(target_os = "macos") {
            candidates.push(PathBuf::from("/bin/bash"));
        }
    }
    candidates.retain(|candidate| candidate.is_file());
    candidates
}

/// Copies the handle of a directory this host made, for the three answers below.
///
/// The copy takes a descriptor as an open does. A host too short of descriptors, processes or
/// memory to make it has said nothing of the directory, so the refusal is a fault that passes
/// (`refused_by`), which a client sends the request again after; any other failure is the
/// caller's argument.
fn copied(directory: &cap_std::fs::Dir) -> Result<cap_std::fs::Dir> {
    // A case that asks for it has the copy fail, after that many have been made, as it does for a
    // host that is out of descriptors.
    #[cfg(all(test, unix))]
    let copy = match crate::identity::tests::due(&crate::identity::tests::MADE_DIRECTORY_COPY_FAILS)
    {
        Some(error) => Err(std::io::Error::from(error)),
        None => directory.try_clone(),
    };
    #[cfg(not(all(test, unix)))]
    let copy = directory.try_clone();
    copy.map_err(|error| {
        refused_by(
            &error,
            format!("a directory this host made could not be identified: {error}"),
        )
    })
}

/// Returns the object one opened directory is.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the handle's identity cannot be read, except that a
/// host too short of descriptors, processes or memory to copy it is [`ProjectError::GitFailed`],
/// a fault that passes.
pub fn identity_of_handle(
    environment_id: EnvironmentId,
    directory: &cap_std::fs::Dir,
) -> Result<ObjectIdentity> {
    let handle = copied(directory)?;
    Ok(AuthorisedDirectory::from_handle(environment_id, handle, PathBuf::new())?.identity())
}

/// Returns the object one opened directory is, as the journal records it: with the filesystem it is
/// on.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the handle's identity cannot be read, except that a
/// host too short of descriptors, processes or memory to copy it is [`ProjectError::GitFailed`],
/// a fault that passes.
pub fn recorded_of_handle(
    environment_id: EnvironmentId,
    directory: &cap_std::fs::Dir,
) -> Result<RecordedIdentity> {
    let handle = copied(directory)?;
    Ok(AuthorisedDirectory::from_handle(environment_id, handle, PathBuf::new())?.recorded()?)
}

/// Decides whether one opened directory is the directory a record names, by the rule every
/// recorded directory is decided by.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the handle cannot be read, except that a host too
/// short of descriptors, processes or memory to copy it is [`ProjectError::GitFailed`], a fault
/// that passes, and [`ProjectError::IdentityChanged`] when it is not the recorded directory.
pub fn settle_handle(
    environment_id: EnvironmentId,
    directory: &cap_std::fs::Dir,
    expected: RecordedIdentity,
) -> Result<Settled> {
    let handle = copied(directory)?;
    AuthorisedDirectory::from_handle(environment_id, handle, PathBuf::new())?
        .check_recorded(expected)
        .map_err(|refusal| ProjectError::IdentityChanged {
            detail: refusal.to_string().into(),
        })
}

/// Returns the object one path names now, for a caller that needs to record it.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the directory cannot be opened, except that a host
/// too short of descriptors, processes or memory to open it is [`ProjectError::GitFailed`], a
/// fault that passes.
pub fn identity_of(environment_id: EnvironmentId, path: &Path) -> Result<ObjectIdentity> {
    Ok(crate::identity::open_unrecorded_root(environment_id, path)?.identity())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_operation_reaches_nothing_and_a_remote_one_reaches_its_own_ports() {
        assert_eq!(Reach::for_transport(None, None), Reach::Nothing);
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::LocalPath), None),
            Reach::Nothing
        );
        // A local clone stays local even where a URL named a port, because the transport is what
        // decides whether anything is reached at all.
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::LocalPath), Some(8443)),
            Reach::Nothing
        );
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::Https), None).ports(),
            &[80, 443]
        );
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::Ssh), None).ports(),
            &[22]
        );
    }

    /// A directory the caller holds an identity for, a record's or one this host read from the
    /// directory it opened, that is not there when the invocation opens it is a source that
    /// changed, as one that is another object is, and not an argument the caller got wrong. It is
    /// the state of a tree that goes after the caller opened it and before the invocation does. A
    /// place that cannot be opened for another reason keeps its answer, and so does an open that
    /// holds no identity.
    #[cfg(unix)]
    #[test]
    fn a_recorded_directory_that_is_gone_when_the_invocation_opens_it_is_a_source_that_changed() {
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([13; 16]));
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("tree");
        std::fs::create_dir(&directory).expect("the directory");
        let recorded = AuthorisedDirectory::open_root(environment_id, &directory)
            .expect("the directory opens")
            .identity();
        std::fs::remove_dir(&directory).expect("the directory goes");

        let gone = OpenedDirectory::open(environment_id, &directory, Some(recorded))
            .expect_err("nothing is there to open");
        assert_eq!(
            gone.code(),
            kr_protocol::error::ErrorCode::SourceChanged,
            "{gone}"
        );

        std::os::unix::fs::symlink(root.path().join("nowhere"), &directory)
            .expect("a link to nothing takes the place");
        let dangling = OpenedDirectory::open(environment_id, &directory, Some(recorded))
            .expect_err("a link that leads nowhere is nothing at the place");
        assert_eq!(
            dangling.code(),
            kr_protocol::error::ErrorCode::SourceChanged,
            "{dangling}"
        );

        // With no identity there is no source to have changed, and a parent that is now a file is
        // the caller's to put right whether or not an identity is held for the directory.
        let unrecorded = OpenedDirectory::open(environment_id, &directory, None)
            .expect_err("nothing is there to open");
        assert!(
            matches!(unrecorded, ProjectError::Destination { .. }),
            "{unrecorded:?}"
        );
        let parent = root.path().join("parent");
        std::fs::write(&parent, "a file now").expect("the parent is a regular file");
        let beneath_a_file =
            OpenedDirectory::open(environment_id, &parent.join("tree"), Some(recorded))
                .expect_err("nothing can be below a file");
        assert!(
            matches!(beneath_a_file, ProjectError::Destination { .. }),
            "{beneath_a_file:?}"
        );
    }

    /// A directory that cannot be opened is refused in the open's own words: the place, and the
    /// reason the system gave for it. Nothing opens the place a second time to say them, so a
    /// place that is something else by then does not change them; a link that leads round to
    /// itself is worded as the open found it, as for a recorded tree.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_opened_is_refused_in_the_words_of_the_open_itself() {
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([15; 16]));
        let root = tempfile::tempdir().expect("a temporary directory");
        let (first, second) = (root.path().join("first"), root.path().join("second"));
        std::os::unix::fs::symlink(&second, &first).expect("a link");
        std::os::unix::fs::symlink(&first, &second).expect("and a link back");
        let reason = std::fs::File::open(&first)
            .expect_err("the system cannot follow it either")
            .to_string();
        let recorded = AuthorisedDirectory::open_root(environment_id, root.path())
            .expect("the directory opens")
            .identity();

        for expected in [None, Some(recorded)] {
            let refused = OpenedDirectory::open(environment_id, &first, expected)
                .expect_err("a link that leads to itself cannot be followed");

            assert!(
                matches!(refused, ProjectError::Destination { .. }),
                "{refused:?}"
            );
            let said = refused.to_string();
            assert!(
                said.contains(&reason) && said.contains(&first.display().to_string()),
                "{said}"
            );
        }
    }

    /// A directory this account cannot enter is refused as the caller's argument, though the caller
    /// holds an identity for it: a refused permission is not a directory that went missing.
    #[cfg(unix)]
    #[test]
    fn a_directory_this_account_cannot_enter_is_an_argument_though_an_identity_is_held() {
        use std::os::unix::fs::PermissionsExt as _;

        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([16; 16]));
        let root = tempfile::tempdir().expect("a temporary directory");
        let fenced = root.path().join("fenced");
        std::fs::create_dir(&fenced).expect("the directory above the place");
        let place = fenced.join("tree");
        std::fs::create_dir(&place).expect("the place");
        let held = AuthorisedDirectory::open_root(environment_id, &place)
            .expect("the place opens")
            .identity();
        std::fs::set_permissions(&fenced, std::fs::Permissions::from_mode(0o000))
            .expect("the directory above the place is closed");

        let opened = OpenedDirectory::open(environment_id, &place, Some(held));

        std::fs::set_permissions(&fenced, std::fs::Permissions::from_mode(0o755))
            .expect("and opened again, so that it goes with the case");
        // An account that bypasses the mode (root) enters the place anyway, and there is no
        // refusal for it to be held to.
        let Err(refused) = opened else {
            return;
        };
        assert!(
            matches!(refused, ProjectError::Destination { .. }),
            "{refused:?}"
        );
    }

    /// A recorded directory that goes after the invocation has opened it and before its path is
    /// resolved is a source that changed too: each step of the open answers for what it finds, so
    /// the answer does not depend on which of them the directory went before. On Linux a
    /// directory that is removed while it is held open is still opened by the path the kernel
    /// gives its descriptor, and that path then resolves to nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_recorded_directory_that_goes_before_its_path_is_resolved_is_a_source_that_changed() {
        use std::os::fd::AsRawFd as _;

        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([14; 16]));
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("tree");
        std::fs::create_dir(&directory).expect("the directory");
        let held = std::fs::File::open(&directory).expect("the directory is held open");
        let recorded = AuthorisedDirectory::open_root(environment_id, &directory)
            .expect("the directory opens")
            .identity();
        std::fs::remove_dir(&directory).expect("the directory goes while it is held");
        let by_descriptor = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));

        let gone = OpenedDirectory::open(environment_id, &by_descriptor, Some(recorded))
            .expect_err("the path of a directory that is gone resolves to nothing");

        assert_eq!(
            gone.code(),
            kr_protocol::error::ErrorCode::SourceChanged,
            "{gone}"
        );
    }

    /// A platform that runs no Git refuses every request that needs it under a code a client does
    /// not send again, with the platform's reason and no step to install Git, which would change
    /// nothing there.
    #[test]
    fn a_platform_that_runs_no_git_refuses_under_a_code_a_client_does_not_retry() {
        let refusal = no_git_refusal("a reason of the platform");

        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::HostNotConfigured
        );
        assert!(
            !refusal.code().retry_category().permits_automatic_retry(),
            "{}",
            refusal.code()
        );
        let said = refusal.to_string();
        assert!(said.contains("a reason of the platform"), "{said}");
        assert!(
            !said.contains("try again") && !said.contains("Install"),
            "{said}"
        );
    }

    #[test]
    fn a_remote_that_names_its_own_port_adds_it_once() {
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::Https), Some(8443)).ports(),
            &[80, 443, 8443]
        );
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::Https), Some(443)).ports(),
            &[80, 443]
        );
        assert_eq!(
            Reach::for_transport(Some(RemoteTransport::Ssh), Some(2222)).ports(),
            &[22, 2222]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_mount_point_is_beneath_a_granted_directory_only_when_it_is_inside_it() {
        let directories = vec![PathBuf::from("/work/tree"), PathBuf::from("/work/lib")];
        let beneath = |points: &[&str]| {
            first_mount_beneath(points.iter().map(PathBuf::from), &directories)
                .map(|(point, directory)| (point, directory.to_owned()))
        };
        assert_eq!(
            beneath(&["/", "/work/tree/mounted"]),
            Some((
                PathBuf::from("/work/tree/mounted"),
                PathBuf::from("/work/tree")
            ))
        );
        // A directory that is itself a mount point has nothing mounted beneath it by that, and a
        // neighbour whose name only starts the same way is not inside it.
        assert_eq!(beneath(&["/work/tree", "/work/lib"]), None);
        assert_eq!(beneath(&["/work/tree2", "/work/library/inner"]), None);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn a_platform_that_does_not_confine_reads_names_no_support_set_and_says_why() {
        let refusal = support_set(&[Path::new("/bin/sh")], Path::new("/usr/libexec/git-core"))
            .expect_err("no support set is named where reads are not confined");
        assert_eq!(
            refusal.to_string(),
            "this platform does not confine what Git reads, so an invocation for a caller \
             bounded by a grant is not run here"
        );
    }

    #[test]
    fn the_connection_shell_is_one_this_machine_has() {
        // A machine with no shell at all is one where a local or ssh clone is refused rather than
        // run without its connection; nothing here invents a path.
        for shell in connection_shell(Path::new("/usr/libexec/git-core")) {
            assert!(shell.is_file(), "{} is a program", shell.display());
        }
    }

    /// The copy of the handle of a directory this host made takes a descriptor as an open does,
    /// and the three answers that rest on it are the same: the directory's identity, its identity
    /// as the journal records it, and whether it is the directory a record names. A host out of
    /// descriptors, processes or memory has said nothing of the directory, so each is a fault that
    /// passes, which a client sends the request again after; any other failure of the copy is
    /// still the caller's argument.
    #[cfg(unix)]
    #[test]
    fn a_host_out_of_descriptors_when_the_handle_of_a_directory_this_host_made_is_copied_is_a_fault_that_passes()
     {
        use crate::identity::tests::{MADE_DIRECTORY_COPY_FAILS, OPEN_ERRORS, assert_answered};

        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([14; 16]));
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory =
            cap_std::fs::Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
                .expect("the directory opens");
        let recorded = recorded_of_handle(environment_id, &directory)
            .expect("a directory this host made has an identity");

        for (errno, passes) in OPEN_ERRORS {
            MADE_DIRECTORY_COPY_FAILS.with(|fails| fails.set(Some((0, errno))));
            let answers = [
                (
                    "its identity",
                    identity_of_handle(environment_id, &directory).map(drop),
                ),
                (
                    "its identity as the journal records it",
                    recorded_of_handle(environment_id, &directory).map(drop),
                ),
                (
                    "whether it is the directory a record names",
                    settle_handle(environment_id, &directory, recorded).map(drop),
                ),
            ];
            MADE_DIRECTORY_COPY_FAILS.with(|fails| fails.set(None));

            for (what, answer) in answers {
                let Err(refused) = answer else {
                    panic!("the copy failed ({errno}), and {what} was given");
                };
                assert_answered(
                    &refused,
                    errno,
                    passes,
                    kr_protocol::error::ErrorCode::InvalidArgument,
                    Path::new("a directory this host made"),
                    &format!("{what}, {errno}"),
                );
            }
        }
        identity_of_handle(environment_id, &directory).expect("without a failure it is identified");
    }
}
