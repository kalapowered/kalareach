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
//!    directory that exists for the length of the invocation. Everything else is read-only.
//!
//! Reads are not confined on macOS or Linux, and this is deliberate: Git reads the system's shared
//! libraries, its locale data and its certificate store, and a read confinement that missed one of
//! those would fail an operation for a reason that has nothing to do with safety. What a repository
//! can reach by reading is bounded by the account the service runs as, exactly as it was before.
//! Windows is the exception, because the mechanism there confines reading with everything else, and
//! what an invocation reads outside the directories the operation owns is granted by name.
//!
//! ## Directories, not names
//!
//! Every directory the boundary is built from is opened first and required to be the object the
//! record names: the working tree by the identity the repository's record carries, the Git common
//! directory by its own, the reserved destination by the identity the reservation returned. The
//! child then does not start at a path either: it moves into the open working directory before the
//! boundary is applied and before Git runs, with `-C .` as its only directory argument. A tree
//! substituted at a name afterwards is therefore neither the tree Git works in nor a tree the
//! boundary was built around.
//!
//! What remains is that two of the three mechanisms write their rules against paths, because that
//! is what they take. A substitution after the rules are built moves the verified tree out from
//! under them, so its writes are refused and the run fails with this host's declared result; the
//! substituted tree is not written either, because Git never names it. On Linux the rules are
//! attached to the opened objects themselves, so nothing is left there at all.
//!
//! ## What enforces what
//!
//! | Platform | Execution | Network | Writes |
//! | --- | --- | --- | --- |
//! | macOS | A per-invocation sandbox profile, applied by the system's own launcher before it runs Git | The same profile | The same profile |
//! | Linux | Landlock, with the execute right only on Git's own program and helper directory | Landlock's TCP rules for a remote operation, and a system-call filter that refuses a local one an internet socket | Landlock, from the opened directory handles |
//! | Windows | An application container whose grants on the repository carry no execute right | The container's capabilities: none at all for a local operation | The container's grants, inside a job object that ends every descendant |
//!
//! A platform that cannot establish its boundary refuses the invocation. Nothing here falls back to
//! reading the configuration and hoping.

use std::path::{Path, PathBuf};

use kr_protocol::ids::EnvironmentId;
use kr_protocol::project::RemoteTransport;
use kr_transfer::AuthorisedDirectory;
pub use kr_transfer::ObjectIdentity;

use crate::error::{ProjectError, Result};

#[cfg(target_os = "linux")]
mod linux;
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

#[cfg(all(target_os = "macos", any(test, feature = "git-fixtures")))]
pub use self::macos::profile_text;
#[cfg(unix)]
pub use self::unix::{Spawned, start};
#[cfg(windows)]
pub use self::windows::{Spawned, start};

/// What mechanism encloses an invocation on this platform, for a person reading a record.
pub const MECHANISM: &str = platform::MECHANISM;

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
    /// Opens one directory and requires it to be the object a record names.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be opened or its path
    /// cannot be resolved, and [`ProjectError::IdentityChanged`] when the caller recorded an
    /// identity and the object at the path is a different one.
    pub fn open(
        environment_id: EnvironmentId,
        path: &Path,
        expected: Option<ObjectIdentity>,
    ) -> Result<Self> {
        let directory = AuthorisedDirectory::open_root(environment_id, path)?;
        let identity = directory.identity();
        if let Some(expected) = expected
            && expected != identity
        {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this record names the directory {expected}, and {} holds {identity}; the \
                     invocation is not enclosed around it",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        }
        // Every mechanism's rules are written against a path with no link left in it, so the path
        // is resolved once, here, beside the handle rather than at each rule.
        let resolved = std::fs::canonicalize(path).map_err(|error| ProjectError::Destination {
            detail: format!(
                "{} could not be resolved to a directory this invocation may use: {error}",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
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
    /// Returns [`ProjectError::IdentityChanged`] when the object or its creation instant differs.
    pub fn confirm_path(&self) -> Result<()> {
        let now = AuthorisedDirectory::open_root(self.environment_id, &self.path)?;
        if now.identity() != self.identity || created_at_ms(now.handle()) != self.created_at_ms {
            return Err(ProjectError::IdentityChanged {
                detail: "the directory this invocation ran in is not the object it was started \
                         against, so what it produced is not served"
                    .to_owned()
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
    /// destination the operation reserved. Each is the object its record names.
    pub reserved: Vec<OpenedDirectory>,
    /// The private temporary directory this invocation owns for its own length.
    pub temporary: OpenedDirectory,
    /// Directories the invocation must be able to read where the platform's mechanism confines
    /// reading as well as writing.
    pub readable: Vec<PathBuf>,
    /// What it may reach over the network.
    pub reach: Reach,
}

impl Confinement {
    /// Returns every directory the invocation may write in, in the order the rules are made.
    pub fn written(&self) -> impl Iterator<Item = &OpenedDirectory> {
        std::iter::once(&self.working)
            .chain(self.reserved.iter())
            .chain(std::iter::once(&self.temporary))
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
        // Git for Windows ships its own shell beside its helper directory, under the installation
        // root that `--exec-path` sits inside.
        let root = exec_path.parent().and_then(Path::parent);
        for relative in ["usr/bin/sh.exe", "bin/sh.exe"] {
            if let Some(root) = root {
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

/// Returns the object one path names now, for a caller that needs to record it.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the directory cannot be opened.
pub fn identity_of(environment_id: EnvironmentId, path: &Path) -> Result<ObjectIdentity> {
    Ok(AuthorisedDirectory::open_root(environment_id, path)?.identity())
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

    #[test]
    fn the_connection_shell_is_one_this_machine_has() {
        // A machine with no shell at all is one where a local or ssh clone is refused rather than
        // run without its connection; nothing here invents a path.
        for shell in connection_shell(Path::new("/usr/libexec/git-core")) {
            assert!(shell.is_file(), "{} is a program", shell.display());
        }
    }
}
