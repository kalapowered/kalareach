//! The Linux boundary: Landlock for the filesystem and the ports, a small filter for the rest.
//!
//! Landlock is a kernel feature a process uses on itself: it builds a ruleset out of directory
//! handles it already holds, applies it, and from then on nothing it or its descendants do can get
//! back out. That is exactly the shape this needs, because the ruleset is built by the parent from
//! the directories it opened and applied by the child before Git exists.
//!
//! * **Execution.** The execute right is granted on Git's own program and on Git's helper
//!   directory, and on the approved broker's ssh program for a remote that needs one. It is granted
//!   nowhere else, so a driver in the repository, in the staging directory or in this invocation's
//!   own temporary directory cannot be executed however it came to be there.
//! * **Writes.** The write rights are granted on the repository's tree, its Git common directory,
//!   the destination this operation reserved and this invocation's temporary directory, and they
//!   never include the execute right. Reads are granted on the whole filesystem, which the module
//!   documentation in [`super`] explains.
//! * **Network.** A remote operation gets a connect rule per port its transport uses and no bind
//!   rule at all, so nothing can listen. Landlock's network rules arrived in its fourth interface
//!   version, so a kernel older than that cannot enforce them: a remote operation is **refused**
//!   there rather than run with the ports unenforced.
//!
//! Landlock covers TCP and says nothing about the rest, so a local operation would still be able to
//! open a UDP or raw socket and talk through it. A seccomp filter closes that: for a local
//! operation the kernel refuses to create an internet socket at all, and for every operation it
//! refuses to make one listen. The filter is a fixed program built for this machine's own
//! instruction set, and an architecture whose numbers this host does not hold refuses the
//! invocation rather than installing a filter that would not mean what it says.

#![expect(
    unsafe_code,
    reason = "installing a system-call filter is a raw prctl with a pointer argument and has no \
              safe form; this module holds that one call and the constants it needs"
)]

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use super::{Confinement, Reach};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "Landlock rules built from opened directory handles, with a system-call filter for the \
     sockets Landlock does not cover";

/// The interface version at which Landlock can restrict TCP.
const NETWORK_ABI: ABI = ABI::V4;

/// The device files a process needs to run at all.
const DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

/// The boundary as the parent built it, ready for the child to apply.
#[derive(Debug)]
pub struct Prepared {
    ruleset: Option<RulesetCreated>,
    filter: Vec<libc::sock_filter>,
}

impl Prepared {
    /// Applies the boundary to this process.
    ///
    /// Runs in the forked child. A failure returns an error rather than continuing, and the child
    /// never reaches `exec`.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal, or a permission failure when the ruleset was applied without
    /// being fully enforced.
    pub fn apply(&mut self) -> std::io::Result<()> {
        let ruleset = self
            .ruleset
            .take()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EPERM))?;
        let status = ruleset
            .restrict_self()
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EPERM))?;
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        let program = libc::sock_fprog {
            len: u16::try_from(self.filter.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EPERM))?,
            filter: self.filter.as_ptr().cast_mut(),
        };
        // SAFETY: both calls are this process acting on itself. The first takes two scalars. The
        // second takes a pointer to a program this process owns, which outlives the call because
        // it is held in `self` and `self` is held by the hook that is running.
        let installed = unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                std::ptr::from_ref(&program),
            )
        };
        if installed == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// Builds the boundary one invocation runs under.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when this kernel has no Landlock at all, when a remote
/// operation asks for ports a kernel this old cannot enforce, or when a directory the rules are
/// built from cannot be opened.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
    let abi = ABI::new_current();
    if abi < ABI::V1 {
        return Err(ProjectError::GitFailed {
            detail: "this kernel has no Landlock, so a Git invocation cannot be enclosed and is \
                     not run; a host without it runs the service inside a bubblewrap container \
                     instead"
                .into(),
        });
    }
    let remote = !matches!(confinement.reach, Reach::Nothing);
    if remote && abi < NETWORK_ABI {
        return Err(ProjectError::GitFailed {
            detail: "this kernel's Landlock cannot restrict which addresses a process reaches, so \
                     an operation that needs a remote is refused rather than run with its network \
                     unenclosed"
                .into(),
        });
    }
    // Nothing degrades quietly: a right this kernel does not have is a refusal here rather than a
    // ruleset that enforces less than it says.
    let mut ruleset = Ruleset::default();
    ruleset.set_compatibility(CompatLevel::HardRequirement);
    let mut ruleset = ruleset
        .handle_access(AccessFs::from_all(abi))
        .map_err(rules)?;
    if remote {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(NETWORK_ABI))
            .map_err(rules)?;
    }
    let mut created = ruleset.create().map_err(rules)?;
    // Reads everywhere, and the execute right nowhere: this rule is what makes every later rule an
    // addition rather than the only thing that works.
    created = created
        .add_rule(PathBeneath::new(
            opened(Path::new("/"))?,
            AccessFs::ReadFile | AccessFs::ReadDir,
        ))
        .map_err(rules)?;
    for program in confinement.executables() {
        created = created
            .add_rule(PathBeneath::new(
                opened(program)?,
                AccessFs::Execute | AccessFs::ReadFile,
            ))
            .map_err(rules)?;
    }
    created = created
        .add_rule(PathBeneath::new(
            opened(&confinement.exec_path)?,
            AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir,
        ))
        .map_err(rules)?;
    let written = AccessFs::from_write(abi) | AccessFs::ReadFile | AccessFs::ReadDir;
    for directory in confinement.written() {
        created = created
            .add_rule(PathBeneath::new(opened(directory)?, written))
            .map_err(rules)?;
    }
    for device in DEVICES {
        let device = Path::new(device);
        // A machine without one of these is not a machine Git runs on, but the rule is skipped
        // rather than refused: what matters is that nothing else was added.
        if let Ok(handle) = PathFd::new(device) {
            created = created
                .add_rule(PathBeneath::new(
                    handle,
                    AccessFs::from_write(abi) | AccessFs::ReadFile,
                ))
                .map_err(rules)?;
        }
    }
    if let Reach::Outbound(ports) = &confinement.reach {
        for port in ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(rules)?;
        }
    }
    Ok(Prepared {
        ruleset: Some(created),
        filter: filter(remote)?,
    })
}

/// Starts one Git invocation inside its boundary.
pub use super::unix::start;

/// Returns the handle a rule is attached to, refusing a directory that cannot be opened.
fn opened(path: &Path) -> Result<PathFd> {
    PathFd::new(path).map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "{} could not be opened to build this invocation's boundary: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    })
}

/// Returns a ruleset failure as this host's own.
fn rules<E: std::fmt::Display>(error: E) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!("this invocation's boundary could not be built: {error}").into(),
    }
}

/// The instruction set this filter is written for, as the kernel reports it to a filter.
#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: u32 = 0xc000_003e;
/// The instruction set this filter is written for, as the kernel reports it to a filter.
#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: u32 = 0xc000_00b7;

/// The `socket` call's number on this instruction set.
#[cfg(target_arch = "x86_64")]
const SYS_SOCKET: u32 = 41;
/// The `listen` call's number on this instruction set.
#[cfg(target_arch = "x86_64")]
const SYS_LISTEN: u32 = 50;
/// The `socket` call's number on this instruction set.
#[cfg(target_arch = "aarch64")]
const SYS_SOCKET: u32 = 198;
/// The `listen` call's number on this instruction set.
#[cfg(target_arch = "aarch64")]
const SYS_LISTEN: u32 = 201;

/// Loads a word from the call this filter is judging.
const LOAD: u16 = 0x20;
/// Compares the loaded word with a constant.
const COMPARE: u16 = 0x15;
/// Answers.
const ANSWER: u16 = 0x06;

/// The answer for a call this filter will not let happen: the caller is refused permission.
const REFUSED: u32 = 0x0005_0000 | (libc::EACCES as u32);
/// The answer for a call this filter permits.
const PERMITTED: u32 = 0x7fff_0000;
/// The answer for a machine whose calls this filter does not describe: the process ends.
const UNKNOWN_MACHINE: u32 = 0x8000_0000;

/// Builds the filter for one invocation.
///
/// The offsets are counted from the instruction after the branch, which is how this kind of
/// program is read, and the tests below walk it rather than trusting the arithmetic.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] on an instruction set this host holds no call numbers for.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn filter(remote: bool) -> Result<Vec<libc::sock_filter>> {
    let mut program = vec![
        instruction(LOAD, 0, 0, 4),
        instruction(COMPARE, 1, 0, ARCHITECTURE),
        instruction(ANSWER, 0, 0, UNKNOWN_MACHINE),
        instruction(LOAD, 0, 0, 0),
    ];
    if remote {
        // Nothing may listen. Creating a socket and connecting out is what the transport does, and
        // which addresses it reaches is Landlock's rule rather than this one's.
        program.push(instruction(COMPARE, 0, 1, SYS_LISTEN));
        program.push(instruction(ANSWER, 0, 0, REFUSED));
        program.push(instruction(ANSWER, 0, 0, PERMITTED));
    } else {
        // No internet socket at all, and nothing may listen.
        program.push(instruction(COMPARE, 5, 0, SYS_LISTEN));
        program.push(instruction(COMPARE, 0, 5, SYS_SOCKET));
        program.push(instruction(LOAD, 0, 0, 16));
        program.push(instruction(COMPARE, 2, 0, libc::AF_INET as u32));
        program.push(instruction(COMPARE, 1, 0, libc::AF_INET6 as u32));
        program.push(instruction(COMPARE, 0, 1, libc::AF_PACKET as u32));
        program.push(instruction(ANSWER, 0, 0, REFUSED));
        program.push(instruction(ANSWER, 0, 0, PERMITTED));
    }
    Ok(program)
}

/// Builds the filter for one invocation.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`], because this host holds no call numbers for this
/// instruction set and will not install a filter that does not mean what it says.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn filter(_remote: bool) -> Result<Vec<libc::sock_filter>> {
    Err(ProjectError::GitFailed {
        detail: "this host does not hold the system-call numbers for this machine, so a Git \
                 invocation cannot be enclosed and is not run"
            .into(),
    })
}

/// Returns one instruction of the filter.
const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the filter over one call and returns the answer it gives.
    fn judge(program: &[libc::sock_filter], architecture: u32, number: u32, domain: u32) -> u32 {
        let mut at = 0_usize;
        let mut accumulator = 0_u32;
        loop {
            let instruction = program[at];
            match instruction.code {
                LOAD => {
                    accumulator = match instruction.k {
                        0 => number,
                        4 => architecture,
                        16 => domain,
                        other => panic!("the filter loaded {other}, which nothing here means"),
                    };
                    at += 1;
                }
                COMPARE => {
                    let taken = if accumulator == instruction.k {
                        usize::from(instruction.jt)
                    } else {
                        usize::from(instruction.jf)
                    };
                    at += 1 + taken;
                }
                ANSWER => return instruction.k,
                other => panic!("the filter holds {other}, which nothing here means"),
            }
        }
    }

    #[test]
    fn a_local_invocation_cannot_make_an_internet_socket_or_listen() {
        let program = filter(false).expect("a filter for this machine");
        assert_eq!(
            judge(&program, ARCHITECTURE, SYS_SOCKET, libc::AF_INET as u32),
            REFUSED
        );
        assert_eq!(
            judge(&program, ARCHITECTURE, SYS_SOCKET, libc::AF_INET6 as u32),
            REFUSED
        );
        assert_eq!(
            judge(&program, ARCHITECTURE, SYS_SOCKET, libc::AF_PACKET as u32),
            REFUSED
        );
        assert_eq!(judge(&program, ARCHITECTURE, SYS_LISTEN, 0), REFUSED);
        // A local socket is how this machine's own services are reached, and it is not a network.
        assert_eq!(
            judge(&program, ARCHITECTURE, SYS_SOCKET, libc::AF_UNIX as u32),
            PERMITTED
        );
        // Everything else is the ordinary work of running Git.
        assert_eq!(judge(&program, ARCHITECTURE, 1, 0), PERMITTED);
    }

    #[test]
    fn a_remote_invocation_may_connect_out_and_still_cannot_listen() {
        let program = filter(true).expect("a filter for this machine");
        assert_eq!(
            judge(&program, ARCHITECTURE, SYS_SOCKET, libc::AF_INET as u32),
            PERMITTED
        );
        assert_eq!(judge(&program, ARCHITECTURE, SYS_LISTEN, 0), REFUSED);
        assert_eq!(judge(&program, ARCHITECTURE, 1, 0), PERMITTED);
    }

    #[test]
    fn a_machine_this_filter_does_not_describe_ends_the_process() {
        for remote in [false, true] {
            let program = filter(remote).expect("a filter for this machine");
            assert_eq!(judge(&program, 0, SYS_SOCKET, 0), UNKNOWN_MACHINE);
        }
    }
}
