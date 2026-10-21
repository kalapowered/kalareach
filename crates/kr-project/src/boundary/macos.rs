//! The macOS boundary: one sandbox profile per invocation, applied before Git is executed.
//!
//! The profile is written here, as text, from the invocation's own confinement, and it denies
//! everything that is not named. Reads are allowed everywhere, which is the one deliberate
//! exception and is why the table in [`super`] lists three guarantees rather than four. What is
//! named is: the Git program and its own helper directory as the only things that may be executed,
//! the directories this operation owns as the only ones that may be written, and, for a remote
//! operation, outbound connections to the ports its transport uses and the socket this system
//! resolves names through.
//!
//! ## What applies it
//!
//! The platform's own launcher, `/usr/bin/sandbox-exec`, which compiles the profile into itself and
//! then executes Git. The invocation's program becomes the launcher and the profile travels as one
//! of its arguments; everything else about the child — its environment, its directory, its process
//! group, its pipes — is unchanged, and the launcher replaces itself with Git, so the process this
//! host waits on is Git and its exit status is Git's.
//!
//! The profile is an argument rather than a file on purpose. A file would be a second thing for a
//! writer under the same account to reach: a name to plant a link at before this host writes it, and
//! a document to rewrite between the writing and the launcher reading it. An argument vector this
//! process built is reachable by nothing.
//!
//! ## Descriptors
//!
//! Every descriptor the child holds from the fourth on is marked to close when it executes the
//! launcher, in the child before it executes, as the Linux boundary marks them
//! ([`kr_ipc::inheritance`]). The profile is judged when a file is opened, and a descriptor the
//! host opened before the profile is already open: without the mark the launcher, and Git after
//! it, would read through it whatever the profile says.
//!
//! The library call `sandbox_init` would apply the same text without the extra program, and it
//! works on this platform. It is not used, and the reason is where it would have to be called:
//! after `fork` and before `exec`, in a child of a process that has other threads. Compiling a
//! profile there is a library call with no documented guarantee in that state, and a call that
//! blocks there blocks the spawn rather than failing it. The launcher compiles the same profile in
//! a process of its own, before Git exists, with nothing to deadlock against.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::{Confinement, Invocation, Reach};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "a per-invocation macOS sandbox profile, applied by the system's own launcher before it \
     executes Git";

/// The launcher that applies a profile and then executes what it was given.
const LAUNCHER: &str = "/usr/bin/sandbox-exec";

/// The socket this system's name resolution goes through.
///
/// A remote operation has to turn the remote's host name into an address, and on this platform
/// that is a connection to the resolver's own socket rather than a query this process sends. It is
/// named for a remote operation and for nothing else, so a local operation cannot resolve a name
/// either.
const RESOLVER_SOCKET: &str = "/private/var/run/mDNSResponder";

/// The device files a process needs to run at all.
const DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/dtracehelper",
];

/// The profile this invocation runs under, and what the child needs to pass on nothing else.
#[derive(Debug)]
pub struct Prepared {
    profile: String,
    /// The room the child finds its descriptors in, made before the fork because the child may not
    /// allocate.
    room: kr_ipc::inheritance::TableRoom,
}

impl Prepared {
    /// Returns the program the child executes and the arguments it runs with.
    ///
    /// The launcher first, then the profile itself, then Git and its own arguments.
    pub fn command(&self, invocation: &Invocation<'_>) -> (PathBuf, Vec<OsString>) {
        let mut arguments = vec![
            OsString::from("-p"),
            OsString::from(&self.profile),
            invocation.program.as_os_str().to_owned(),
        ];
        arguments.extend(invocation.arguments.iter().cloned());
        (PathBuf::from(LAUNCHER), arguments)
    }

    /// Applies whatever the boundary still needs applying in the child.
    ///
    /// The profile is not among it: the launcher this invocation executes applies that itself,
    /// before Git exists. What is left is the descriptors the host holds. The profile judges a
    /// file when it is opened, so a descriptor that is already open is read through whatever the
    /// profile says, and the launcher would hand it to Git. Every descriptor above the standard
    /// three is marked to close when the launcher executes, as the Linux boundary marks them, and
    /// a system that cannot list them fails the start rather than run Git holding one.
    ///
    /// # Errors
    ///
    /// Returns the system's error when a descriptor cannot be marked or the system will not list
    /// them all.
    pub fn apply(&mut self) -> std::io::Result<()> {
        kr_ipc::inheritance::mark_close_on_exec(&mut self.room)
    }
}

/// Builds the profile one invocation runs under.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when a path cannot be expressed in a profile — a directory
/// that is the root of the filesystem, or a path holding a byte a profile cannot carry — or when
/// this platform has no launcher to apply it with.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
    if !Path::new(LAUNCHER).is_file() {
        return Err(ProjectError::GitFailed {
            detail: "this host has no launcher to apply a boundary with, so Git is not run".into(),
        });
    }
    let mut text = String::from("(version 1)\n(deny default)\n");
    // Reads are not confined; the module documentation says why.
    text.push_str("(allow file-read*)\n");
    // A process that may not fork cannot run Git at all: Git runs its own subcommands as
    // subprocesses. What they may be is the execution list below.
    text.push_str("(allow process-fork)\n");
    text.push_str("(allow sysctl-read)\n");
    // Only this invocation's own processes. The child leads its own process group, so the group is
    // exactly the processes this invocation started.
    text.push_str("(allow signal (target self) (target pgrp))\n");
    text.push_str("(allow file-write* ");
    for device in DEVICES {
        text.push_str(&literal(Path::new(device))?);
    }
    text.push_str(")\n");
    text.push_str("(allow process-exec* ");
    for program in confinement.executables() {
        text.push_str(&literal(program)?);
    }
    text.push_str(&subpath(&confinement.exec_path)?);
    text.push_str(")\n");
    text.push_str("(allow file-write* ");
    for directory in confinement.written() {
        text.push_str(&subpath(directory.path())?);
    }
    text.push_str(")\n");
    match &confinement.reach {
        Reach::Nothing => {}
        Reach::Outbound(ports) => {
            text.push_str("(allow network-outbound ");
            for port in ports {
                text.push_str(&format!("(remote tcp \"*:{port}\") "));
            }
            text.push_str(&literal(Path::new(RESOLVER_SOCKET))?);
            text.push_str(")\n");
        }
    }
    Ok(Prepared {
        profile: text,
        room: kr_ipc::inheritance::TableRoom::make(),
    })
}

/// Returns one path as a profile's literal filter.
fn literal(path: &Path) -> Result<String> {
    Ok(format!("(literal \"{}\") ", quoted(path)?))
}

/// Returns one directory as a profile's subtree filter.
fn subpath(path: &Path) -> Result<String> {
    // A subtree filter names a directory with no trailing separator, and the root is not a subtree
    // anything may be confined to: a profile that named it would confine nothing.
    if path.parent().is_none() {
        return Err(ProjectError::GitFailed {
            detail: "an invocation cannot be confined to the whole filesystem".into(),
        });
    }
    Ok(format!("(subpath \"{}\") ", quoted(path)?))
}

/// Returns one path as the bytes of a profile string, refusing anything a profile cannot carry.
fn quoted(path: &Path) -> Result<String> {
    let bytes = path.as_os_str().as_bytes();
    let text = std::str::from_utf8(bytes).map_err(|_| ProjectError::GitFailed {
        // The path itself is not repeated: it is not text this host can carry, which is the whole
        // of what went wrong.
        detail: "a directory this invocation would run in is named in bytes this host cannot \
                 express in a boundary, so the invocation is refused rather than run without one"
            .into(),
    })?;
    let mut quoted = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    Ok(quoted)
}

/// Returns one invocation's profile as text, for the tests that read it.
///
/// # Errors
///
/// Returns whatever `prepare` would have refused the invocation for.
#[cfg(any(test, feature = "git-fixtures"))]
pub fn profile_text(confinement: &Confinement) -> Result<String> {
    Ok(prepare(confinement)?.profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::OpenedDirectory;

    fn opened(path: &Path) -> OpenedDirectory {
        OpenedDirectory::open(
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16])),
            path,
            None,
        )
        .expect("a directory this test made")
    }

    fn confinement(root: &Path, reach: Reach) -> Confinement {
        let working = root.join("tree");
        let temporary = root.join("temporary");
        for directory in [&working, &temporary] {
            std::fs::create_dir_all(directory).expect("a directory for the test");
        }
        Confinement {
            program: PathBuf::from("/usr/bin/git"),
            exec_path: PathBuf::from("/usr/libexec/git-core"),
            helpers: Vec::new(),
            working: opened(&working),
            reserved: Vec::new(),
            temporary: opened(&temporary),
            readable: Vec::new(),
            reach,
            reads: crate::boundary::Reads::Everywhere,
        }
    }

    #[test]
    fn a_local_operation_names_no_network_at_all() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let confinement = confinement(root.path(), Reach::Nothing);
        let profile = profile_text(&confinement).expect("the profile is built");
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(!profile.contains("network"));
        assert!(profile.contains("(literal \"/usr/bin/git\")"));
        assert!(profile.contains("(subpath \"/usr/libexec/git-core\")"));
        for directory in confinement.written() {
            assert!(
                profile.contains(&format!("(subpath \"{}\")", directory.path().display())),
                "every directory the operation owns is in the profile: {profile}"
            );
        }
    }

    #[test]
    fn a_remote_operation_names_its_ports_and_the_resolver_and_nothing_else() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let profile = profile_text(&confinement(root.path(), Reach::Outbound(vec![22])))
            .expect("the profile is built");
        assert!(profile.contains("(allow network-outbound (remote tcp \"*:22\") "));
        assert!(profile.contains(RESOLVER_SOCKET));
        // Outbound only: nothing in the profile permits a listening socket.
        assert!(!profile.contains("network-inbound"));
        assert!(!profile.contains("network-bind"));
    }

    /// A descriptor the host holds, with nothing to close it when a child executes, is not open in
    /// the Git that is started inside the boundary: it would be read through whatever the profile
    /// says, since the profile judges a file when it is opened and this one is open already. The
    /// child lists its own descriptors, and the control is that it lists the standard three.
    #[test]
    fn a_descriptor_the_host_holds_is_not_open_in_the_git_it_is_started_as() {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        // The system's shell is the program that lists them, and on this platform it executes the
        // shell it is a variant of, which the profile has to allow as well.
        let mut confinement = confinement(root.path(), Reach::Nothing);
        confinement.program = PathBuf::from("/bin/sh");
        confinement.helpers = vec![PathBuf::from("/bin/bash")];

        // Far above any the child's own listing opens, and left open on exec.
        let held = std::fs::File::open("/").expect("a descriptor of the host's");
        let leaked = rustix::io::fcntl_dupfd_cloexec(&held, 100).expect("one high in the table");
        rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).expect("left open on exec");
        let number = leaked.as_raw_fd();

        let arguments = [
            OsString::from("-c"),
            OsString::from("for d in /dev/fd/*; do echo \"${d#/dev/fd/}\"; done"),
        ];
        let environment = [(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];
        let invocation = Invocation {
            program: Path::new("/bin/sh"),
            arguments: &arguments,
            environment: &environment,
            described: "a listing of the descriptors the child holds",
        };
        let mut spawned =
            crate::boundary::start(&invocation, &confinement).expect("the child starts");
        let mut listing = String::new();
        spawned
            .stdout()
            .expect("the child's output")
            .read_to_string(&mut listing)
            .expect("the child's listing");
        while spawned
            .try_wait()
            .expect("the child is waited for")
            .is_none()
        {
            std::thread::yield_now();
        }
        let open: Vec<i32> = listing
            .split_whitespace()
            .filter_map(|number| number.parse().ok())
            .collect();
        for standard in 0..=2 {
            assert!(
                open.contains(&standard),
                "the child lists its own: {listing:?}"
            );
        }
        assert!(
            !open.contains(&number),
            "descriptor {number} of the host's is open in the child: {listing:?}"
        );
    }

    #[test]
    fn a_path_a_profile_could_not_carry_refuses_the_invocation() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        assert!(subpath(Path::new("/")).is_err());
        assert_eq!(
            subpath(Path::new("/work/a\"b\\c")).expect("an awkward name is expressed"),
            "(subpath \"/work/a\\\"b\\\\c\") "
        );
        assert!(subpath(&PathBuf::from(OsString::from_vec(b"/work/\xff".to_vec()))).is_err());
    }
}
