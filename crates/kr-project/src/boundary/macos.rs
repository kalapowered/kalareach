//! The macOS boundary: one sandbox profile per invocation, compiled in the child before `exec`.
//!
//! The profile is written here, as text, from the invocation's own confinement, and it denies
//! everything that is not named. Reads are allowed everywhere, which is the one deliberate
//! exception and is why the table in [`super`] lists three guarantees rather than four. What is
//! named is: the Git program and its own helper directory as the only things that may be executed,
//! the directories this operation owns as the only ones that may be written, and, for a remote
//! operation, outbound connections to the ports its transport uses and the socket this system
//! resolves names through.
//!
//! ## Why the child compiles it
//!
//! `sandbox_init` takes the profile as text and compiles it into the calling process. The call is
//! made in the forked child, after it has moved into the directory handle and before it executes
//! Git, so the profile is already in force when Git exists. Compiling allocates, which is work a
//! forked child of a process with other threads has to be careful about; on this platform `fork`
//! reinitialises the allocator's locks in the child, which is what makes it safe. The alternative
//! is `/usr/bin/sandbox-exec`, which compiles the same text in a process of its own and then
//! executes Git; it is the fallback where the library call is not available, and it is not needed
//! here.

#![expect(
    unsafe_code,
    reason = "applying a sandbox profile is a call into the platform's own library with no safe \
              form; this module holds that one call and nothing else"
)]

use std::ffi::{CString, c_char, c_int};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use super::{Confinement, Reach};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "a per-invocation macOS sandbox profile applied before Git is executed";

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

/// A compiled-in-the-child profile, as the text the child hands to the platform.
#[derive(Debug)]
pub struct Prepared {
    profile: CString,
}

unsafe extern "C" {
    /// Compiles a profile into the calling process. Zero on success.
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
}

impl Prepared {
    /// Applies the boundary to this process.
    ///
    /// Runs in the forked child. A failure returns an error rather than continuing, and the child
    /// never reaches `exec`, so a Git that could not be enclosed does not run.
    ///
    /// # Errors
    ///
    /// Returns the platform's refusal when the profile cannot be compiled or applied.
    pub fn apply(&mut self) -> std::io::Result<()> {
        // SAFETY: the pointer is to this process's own NUL-terminated buffer, which outlives the
        // call. The error buffer is not asked for, because there is nowhere in a forked child to
        // print one and freeing it would be more work in a context that must do as little as
        // possible; the refusal below is what the parent sees.
        let applied = unsafe { sandbox_init(self.profile.as_ptr(), 0, std::ptr::null_mut()) };
        if applied == 0 {
            Ok(())
        } else {
            // No allocation: this is the one error a forked child can build without one.
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        }
    }
}

/// Builds the profile one invocation runs under.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when a path cannot be expressed in a profile: a directory
/// that is the root of the filesystem, or a path holding a byte a profile cannot carry.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
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
        text.push_str(&subpath(directory)?);
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
    let profile = CString::new(text).map_err(|error| ProjectError::GitFailed {
        detail: format!("the boundary for this invocation could not be expressed: {error}").into(),
    })?;
    Ok(Prepared { profile })
}

/// Starts one Git invocation inside its boundary.
///
/// # Errors
///
/// Returns whatever the shared Unix start returned.
pub use super::unix::start;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn confinement(reach: Reach) -> Confinement {
        Confinement {
            program: PathBuf::from("/usr/bin/git"),
            exec_path: PathBuf::from("/usr/libexec/git-core"),
            helpers: Vec::new(),
            writable: vec![PathBuf::from("/work/tree")],
            temporary: PathBuf::from("/state/temporary/one"),
            reach,
        }
    }

    fn text(confinement: &Confinement) -> String {
        prepare(confinement)
            .expect("the profile is built")
            .profile
            .into_string()
            .expect("the profile is text")
    }

    #[test]
    fn a_local_operation_names_no_network_at_all() {
        let profile = text(&confinement(Reach::Nothing));
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(!profile.contains("network"));
        assert!(profile.contains("(subpath \"/work/tree\")"));
        assert!(profile.contains("(subpath \"/state/temporary/one\")"));
        assert!(profile.contains("(literal \"/usr/bin/git\")"));
        assert!(profile.contains("(subpath \"/usr/libexec/git-core\")"));
    }

    #[test]
    fn a_remote_operation_names_its_ports_and_the_resolver_and_nothing_else() {
        let profile = text(&confinement(Reach::Outbound(vec![22])));
        assert!(profile.contains("(allow network-outbound (remote tcp \"*:22\") "));
        assert!(profile.contains(RESOLVER_SOCKET));
        // Outbound only: nothing in the profile permits a listening socket.
        assert!(!profile.contains("network-inbound"));
        assert!(!profile.contains("network-bind"));
    }

    #[test]
    fn a_path_a_profile_could_not_carry_refuses_the_invocation() {
        use std::ffi::OsString;

        let mut awkward = confinement(Reach::Nothing);
        awkward.writable = vec![PathBuf::from("/work/a\"b\\c")];
        assert!(text(&awkward).contains("(subpath \"/work/a\\\"b\\\\c\")"));

        let mut root = confinement(Reach::Nothing);
        root.writable = vec![PathBuf::from("/")];
        assert!(prepare(&root).is_err());

        let mut invalid = confinement(Reach::Nothing);
        invalid.writable = vec![PathBuf::from(OsString::from_vec(b"/work/\xff".to_vec()))];
        assert!(prepare(&invalid).is_err());
    }

    use std::os::unix::ffi::OsStringExt as _;
}
