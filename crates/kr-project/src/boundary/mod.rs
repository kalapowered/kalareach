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
//! 1. **Only Git executes.** The Git program, the helpers under Git's own `--exec-path`, and the
//!    approved broker's ssh program for a remote that needs one. A driver, filter, hook, credential
//!    helper, pager, fsmonitor or `core.sshCommand` anywhere else — in the repository, in the
//!    staging directory, in this invocation's private temporary directory — cannot be executed,
//!    whether it was planted before the configuration was read, between the reading and the spawn,
//!    or while Git is running.
//! 2. **Only this operation's network.** A local operation reaches nothing at all. A remote
//!    operation may open outbound connections to the ports its transport uses and resolve the
//!    remote's name, and nothing may listen.
//! 3. **Only this operation's directories are written.** The repository's working tree and its Git
//!    common directory, the destination this operation reserved, and one private temporary
//!    directory that exists for the length of the invocation. Everything else is read-only.
//!
//! Reads are not confined, and this is deliberate: Git reads the system's shared libraries, its
//! locale data and its certificate store, and a read confinement that missed one of those would
//! fail an operation for a reason that has nothing to do with safety. What a repository can reach
//! by reading is bounded by the account the service runs as, exactly as it was before.
//!
//! ## The tree the child is given
//!
//! The child does not start at a path. The parent opens the directory, records the object it
//! opened, and the child moves into that open directory before the boundary is applied and before
//! Git runs, with `-C .` as its only directory argument. A tree substituted at the path afterwards
//! is therefore not the tree Git works in. The boundary's own rules do name paths, because that is
//! what the platforms' mechanisms take, so a substitution moves the verified tree out from under
//! them and its writes are refused: the run fails with this host's declared result and the
//! substituted tree is never written.
//!
//! ## What enforces what
//!
//! | Platform | Execution | Network | Writes |
//! | --- | --- | --- | --- |
//! | macOS | A per-invocation sandbox profile compiled in the child before `exec` | The same profile | The same profile |
//! | Linux | Landlock, with the execute right only on Git's own program and helper directory | Landlock's TCP rules for a remote operation, and a seccomp filter that refuses an IP socket to a local one | Landlock |
//! | Windows | An AppContainer whose grants on the repository carry no execute right | The AppContainer's capabilities: none at all for a local operation | The AppContainer's grants, inside a job object that ends every descendant |
//!
//! A platform that cannot establish its boundary refuses the invocation. Nothing here falls back to
//! reading the configuration and hoping.

use std::path::{Path, PathBuf};

use kr_protocol::project::RemoteTransport;
use kr_transfer::{AuthorisedDirectory, ObjectIdentity};

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

#[cfg(unix)]
pub use self::unix::Spawned;
#[cfg(windows)]
pub use self::windows::Spawned;

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

/// The shell Git starts a connection through, and what that shell itself hands off to.
///
/// Git builds its connection to a repository as one command string and starts it through the
/// system shell, so an invocation that reaches a repository over Git's own transport cannot run
/// without one. It is in the execution list for exactly those invocations, and every one of them is
/// a clone that does not check anything out: no attribute is consulted, so no driver, filter or
/// hook is looked for, so there is nothing in one for a repository to reach the shell through. The
/// checkout that follows is a separate invocation, and its list holds no shell at all.
///
/// On this platform `/bin/sh` re-executes the shell it is a variant of, so both are named.
#[cfg(target_os = "macos")]
pub const CONNECTION_SHELL: &[&str] = &["/bin/sh", "/bin/bash"];

/// The shell Git starts a connection through.
#[cfg(not(target_os = "macos"))]
pub const CONNECTION_SHELL: &[&str] = &["/bin/sh"];

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
/// The handle is the authority. The path is what the boundary's own rules are written against,
/// because every platform's mechanism takes paths, and it is recorded here so that the two are
/// resolved at the same moment rather than one after the other.
#[derive(Debug)]
pub struct WorkingDirectory {
    directory: AuthorisedDirectory,
    path: PathBuf,
    identity: ObjectIdentity,
    witnessed_at_ms: Option<u64>,
}

impl WorkingDirectory {
    /// Opens the directory an invocation runs in and records the object that was opened.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be opened or its path
    /// cannot be resolved, and [`ProjectError::IdentityChanged`] when the caller recorded an
    /// identity and the object at the path is a different one.
    pub fn open(
        environment_id: kr_protocol::ids::EnvironmentId,
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
                     invocation is not started against it",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        }
        // Every mechanism's rules are written against a path with no link left in it, so the path
        // is resolved once, here, beside the handle rather than at each rule.
        let resolved = std::fs::canonicalize(path).map_err(|error| ProjectError::Destination {
            detail: format!(
                "{} could not be resolved to the directory the invocation runs in: {error}",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
        })?;
        let witnessed_at_ms = directory
            .handle()
            .dir_metadata()
            .ok()
            .and_then(|metadata| metadata.created().ok().or_else(|| metadata.modified().ok()))
            .and_then(|instant| {
                instant
                    .into_std()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
            })
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX));
        Ok(Self {
            directory,
            path: resolved,
            identity,
            witnessed_at_ms,
        })
    }

    /// Returns the handle the child is started in.
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

    /// Refuses when the object this handle names is no longer the one it was opened on.
    ///
    /// The handle cannot start naming another object, so what this establishes is that the object
    /// is still there and still the same one: an inode reused after the directory was taken away
    /// has a different creation or modification instant, which is the same witness a publication
    /// is reconciled against.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the object or its witness differs.
    pub fn confirm(&self) -> Result<()> {
        self.directory.revalidate()?;
        let now = self
            .directory
            .handle()
            .dir_metadata()
            .ok()
            .and_then(|metadata| metadata.created().ok().or_else(|| metadata.modified().ok()))
            .and_then(|instant| {
                instant
                    .into_std()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
            })
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX));
        if self.witnessed_at_ms.is_some() && now != self.witnessed_at_ms {
            return Err(ProjectError::IdentityChanged {
                detail: "the directory the invocation ran in is no longer the object it was \
                         started in, so what it produced is not served"
                    .to_owned()
                    .into(),
            });
        }
        Ok(())
    }
}

/// Everything one invocation is allowed to do, as the boundary is built from it.
#[derive(Clone, Debug)]
pub struct Confinement {
    /// The Git program the child executes.
    pub program: PathBuf,
    /// Git's own helper directory. Everything Git runs for itself lives under it.
    pub exec_path: PathBuf,
    /// A program the approved broker lends this operation, such as ssh for an ssh remote.
    pub helpers: Vec<PathBuf>,
    /// The directories this invocation may write in, resolved.
    pub writable: Vec<PathBuf>,
    /// The private temporary directory this invocation owns, resolved.
    pub temporary: PathBuf,
    /// What it may reach over the network.
    pub reach: Reach,
}

impl Confinement {
    /// Returns every directory the invocation may write in, the temporary one included.
    #[must_use]
    pub fn written(&self) -> Vec<&Path> {
        let mut written: Vec<&Path> = self
            .writable
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect();
        written.push(&self.temporary);
        written
    }

    /// Returns every program the invocation may execute.
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

/// Starts one Git invocation inside its boundary.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when the boundary cannot be established or the child cannot
/// be started. A platform with no boundary of its own refuses here rather than starting Git
/// without one.
pub fn start(
    invocation: &Invocation<'_>,
    confinement: &Confinement,
    working: &WorkingDirectory,
) -> Result<Spawned> {
    platform::start(invocation, confinement, working)
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
    fn what_is_written_is_the_directories_plus_this_invocations_own_temporary_one() {
        let confinement = Confinement {
            program: PathBuf::from("/usr/bin/git"),
            exec_path: PathBuf::from("/usr/lib/git-core"),
            helpers: vec![PathBuf::from("/usr/bin/ssh")],
            writable: vec![PathBuf::from("/work/tree"), PathBuf::from("/work/tree/.git")],
            temporary: PathBuf::from("/state/git-profile/temporary/one"),
            reach: Reach::Nothing,
        };
        assert_eq!(
            confinement.written(),
            vec![
                Path::new("/work/tree"),
                Path::new("/work/tree/.git"),
                Path::new("/state/git-profile/temporary/one"),
            ]
        );
        assert_eq!(
            confinement.executables(),
            vec![Path::new("/usr/bin/git"), Path::new("/usr/bin/ssh")]
        );
    }
}
