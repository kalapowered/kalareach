//! The Linux boundary: Landlock for the filesystem and the ports, a small filter for the rest.
//!
//! Landlock is a kernel feature a process uses on itself: it builds a ruleset out of handles it
//! already holds, applies it, and from then on nothing it or its descendants do can get back out.
//! That is exactly the shape this needs, and it is the one mechanism here whose rules are attached
//! to the **objects** this host opened rather than to the names they had, so a tree substituted at
//! a name is not covered by them at all.
//!
//! * **Execution.** The execute right is granted on Git's own program and on Git's helper
//!   directory, and on the approved broker's ssh program and the connection shell for an invocation
//!   that needs them. It is granted nowhere else, so a driver in the repository, in the staging
//!   directory or in this invocation's own temporary directory cannot be executed however it came
//!   to be there.
//! * **Writes.** The write rights are granted on the objects this operation owns and never include
//!   the execute right. Reads are granted on the whole filesystem, which the module documentation
//!   in [`super`] explains.
//! * **Network.** A remote operation gets a connect rule per port its transport uses and no bind
//!   rule at all, so nothing can listen.
//!
//! ## What this kernel has to have
//!
//! The rights are required rather than asked for: the ruleset is built as a hard requirement, so a
//! kernel that cannot enforce one of them refuses the invocation instead of enforcing less than
//! this says.
//!
//! * The filesystem confinement requires Landlock's **third** interface version, Linux 6.2. Before
//!   it the kernel does not mediate truncation at all, so a process could shorten a file this
//!   boundary never made writable. An older kernel therefore runs no Git, and putting the service
//!   inside a bubblewrap container does not change that: the refusal is about what this kernel can
//!   enforce rather than about what surrounds the process, so a host on such a kernel needs a
//!   different mechanism rather than a wrapper.
//! * A remote operation requires the **fourth**, Linux 6.7, which is where Landlock gained the
//!   rules that say which addresses a process may reach. Below it a remote operation is refused and
//!   a local one still runs, because a local one reaches nothing through a different mechanism.
//!
//! ## What the system-call filter adds
//!
//! Landlock's rules are about TCP, and a filter reads scalar arguments while an address is behind a
//! pointer, so nothing here could bound where a datagram goes. The answer is not to allow one, and
//! not to name the families to refuse either: a filter that named those would permit whatever it
//! had not heard of. A socket is made only of what this boundary can account for, and the list is
//! short.
//!
//! * **A connected pair of local sockets**, for either kind of operation, of the stream kind and of
//!   no protocol besides. Such a pair is joined to its own other half, cannot be connected again
//!   and cannot be given a destination, so it is not a way to reach anything; it is how a program
//!   talks to a child of its own.
//! * **The internet families**, for a remote operation only, and on those only a stream socket,
//!   which is what every transport here uses and what Landlock's port rules govern. A stream socket
//!   is not the same thing as the protocol those rules are about, so the protocol is checked too: a
//!   stream socket of another protocol is one they would say nothing about and is not made.
//!
//! Nothing else is made at all. Not a single local socket, nor a pair of the kind that carries a
//! destination on every message: those are what a program reaches another program on this machine
//! by name with, and a proxy on one, or a connection handed over one already made, would be a way
//! past every port rule here. Not the family the kernel answers questions about this machine's own
//! addresses on either, because a host that lets an ordinary account make a network namespace of
//! its own gives that account the right to talk over that family to another *program* rather than
//! to the kernel, which is the same way past. Nothing may listen, and a local operation gets no
//! socket with an address of any kind.
//!
//! What that costs is what a C library asks over a local socket or over that family: its name
//! service cache, a resolver's own interface, and the kernel's list of this machine's addresses. A
//! C library falls back from each of them — to the files, to the resolver itself, and to assuming
//! both kinds of address are worth asking about — so a name still resolves over the connection the
//! rules below bound. The child is told to resolve over the same kind of connection it fetches over
//! (`RES_OPTIONS=use-vc`, which the usual C library reads), and the port a resolver answers on is
//! added to the connect rules for a remote operation — on any address, because which machine
//! answers a name is not this host's to decide. **A host whose name service has no fallback to the
//! resolver, or whose resolver does not take that instruction, cannot turn a name into an address
//! inside this boundary**, and the operation fails saying so rather than being given a socket
//! nothing can bound. An address written out in full is reached either way.
//!
//! One more thing follows from refusing a datagram socket, on this platform only. The library Git
//! fetches over https with asks whether this machine has IPv6 by making a datagram socket and
//! throwing it away; refused that question, it answers it "no" and asks the resolver for IPv4
//! addresses alone. A remote whose name has only an IPv6 address is therefore not reached over
//! https inside this boundary. Git's own transport over ssh does not ask that question.
//!
//! The filter is built for this machine's own instruction set, and an architecture whose call
//! numbers this host does not hold refuses the invocation rather than installing a filter that
//! would not mean what it says.

#![expect(
    unsafe_code,
    reason = "installing a system-call filter is a raw prctl with a pointer argument and has no \
              safe form; this module holds that one call and the constants it needs"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use super::{Confinement, Invocation, Reach};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "Landlock rules attached to the directory handles this host opened, \
                             with a system-call filter for the sockets Landlock does not cover";

/// The interface version the filesystem confinement is built against.
///
/// Truncation arrived here. Below it a process could shorten a file this boundary never made
/// writable, so this is the floor rather than a preference.
const FILESYSTEM_ABI: ABI = ABI::V3;

/// The interface version at which Landlock can restrict which addresses a process reaches.
const NETWORK_ABI: ABI = ABI::V4;

/// The device files a process needs to run at all.
const DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

/// The port a resolver answers a name on.
///
/// A remote operation has to turn its remote's name into an address, and inside this boundary it
/// does that over the same kind of connection it fetches over, because a datagram is the one thing
/// here that nothing can bound.
const RESOLVER_PORT: u16 = 53;

/// The program loaders a dynamically linked program is started through.
///
/// The kernel opens a program's interpreter for execution as part of starting the program, and that
/// open is judged by the same right an ordinary `execve` is. So a boundary that granted the execute
/// right on Git alone would refuse to start Git at all. These are named instead of the directories
/// they are in, because a directory of libraries is a great deal more than a loader. One that this
/// machine does not have is skipped; a machine with none of them starts no Git, which is a refusal
/// rather than a boundary that let something else run.
const LOADERS: &[&str] = &[
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux-aarch64.so.1",
    "/lib/ld-linux-x86-64.so.2",
    "/lib/ld-linux.so.2",
    "/lib/ld-musl-x86_64.so.1",
    "/lib/ld-musl-aarch64.so.1",
    "/usr/lib/ld-musl-x86_64.so.1",
    "/usr/lib/ld-musl-aarch64.so.1",
];

/// The boundary as the parent built it, ready for the child to apply.
#[derive(Debug)]
pub struct Prepared {
    ruleset: Option<RulesetCreated>,
    filter: Vec<libc::sock_filter>,
}

impl Prepared {
    /// Returns the program the child executes and the arguments it runs with.
    ///
    /// Git itself: this platform's boundary is applied by the child to itself, so there is nothing
    /// between the two.
    pub fn command(&self, invocation: &Invocation<'_>) -> (PathBuf, Vec<OsString>) {
        (
            invocation.program.to_owned(),
            invocation.arguments.to_owned(),
        )
    }

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
        // Each of these refusals carries a different number, so the failure the parent reports
        // names the step it came from rather than leaving three possibilities.
        let ruleset = self
            .ruleset
            .take()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EPERM))?;
        let status = ruleset
            .restrict_self()
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOLCK))?;
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let program = libc::sock_fprog {
            len: u16::try_from(self.filter.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::E2BIG))?,
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
/// Returns [`ProjectError::GitFailed`] when this kernel cannot enforce the rights this boundary is
/// made of, when a remote operation asks for rules a kernel this old does not have, or when an
/// object the rules are attached to cannot be opened.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
    let remote = !matches!(confinement.reach, Reach::Nothing);
    // Nothing degrades quietly: a right this kernel does not have is a refusal here rather than a
    // ruleset that enforces less than it says.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(FILESYSTEM_ABI))
        .map_err(|error| {
            refused(
                "this kernel cannot enclose a Git invocation's filesystem access, so none is run",
                &error,
            )
        })?;
    if remote {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(NETWORK_ABI))
            .map_err(|error| refused(
                "this kernel cannot restrict which addresses a process reaches, so an operation \
                 that needs a remote is refused rather than run with its network unenclosed",
                &error,
            ))?;
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
    let written = AccessFs::from_write(FILESYSTEM_ABI) | AccessFs::ReadFile | AccessFs::ReadDir;
    for directory in confinement.written() {
        // The rule is attached to the object this host opened and verified, not to the name it had:
        // a directory put at that name afterwards is a different object and this rule does not
        // reach it.
        created = created
            .add_rule(PathBeneath::new(
                std::os::fd::AsFd::as_fd(directory.handle().handle()),
                written,
            ))
            .map_err(rules)?;
    }
    // The loader, so that a dynamically linked Git can be started at all.
    for loader in LOADERS {
        if let Ok(handle) = PathFd::new(Path::new(loader)) {
            created = created
                .add_rule(PathBeneath::new(
                    handle,
                    AccessFs::Execute | AccessFs::ReadFile,
                ))
                .map_err(rules)?;
        }
    }
    for device in DEVICES {
        let device = Path::new(device);
        // The rights a file can carry, and only those: a directory's rights on something that is
        // not a directory are refused by the kernel and would refuse the whole invocation.
        if let Ok(handle) = PathFd::new(device) {
            created = created
                .add_rule(PathBeneath::new(
                    handle,
                    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
                ))
                .map_err(rules)?;
        }
    }
    if let Reach::Outbound(ports) = &confinement.reach {
        for port in ports.iter().chain(std::iter::once(&RESOLVER_PORT)) {
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

/// Returns the handle a rule is attached to, refusing a path that cannot be opened.
fn opened(path: &Path) -> Result<PathFd> {
    PathFd::new(path).map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "{} could not be opened to build this invocation's boundary: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    })
}

/// Returns a refusal this host states in its own words, with the kernel's reason beside it.
fn refused<E: std::fmt::Display>(what: &str, error: &E) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!("{what}: {error}").into(),
    }
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

/// The bit a call number carries when it is the other calling convention of this instruction set.
///
/// One architecture value covers two conventions here, and their call numbers are different. A
/// filter that compared only the numbers would judge one convention's calls by the other's meanings,
/// so a number carrying this bit is refused outright.
#[cfg(target_arch = "x86_64")]
const OTHER_CONVENTION: u32 = 0x4000_0000;
/// The bit a call number carries when it is the other calling convention of this instruction set.
#[cfg(target_arch = "aarch64")]
const OTHER_CONVENTION: u32 = 0x4000_0000;

/// The first of the three calls that set up the kernel's own queued-work interface.
///
/// A process with one of those queues can ask the kernel to make a socket and connect it without
/// making either call itself, so a filter that judged only the calls would not see it. Git does not
/// use the interface; the three numbers are contiguous and are refused together.
const SYS_QUEUED_WORK: u32 = 425;
/// The last of those three.
const SYS_QUEUED_WORK_LAST: u32 = 427;

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
/// The `socketpair` call's number on this instruction set.
///
/// A pair of sockets is made with a family like any other socket, so it is judged by the same
/// families rather than left to a call the family rules never see.
#[cfg(target_arch = "x86_64")]
const SYS_SOCKETPAIR: u32 = 53;
/// The `socketpair` call's number on this instruction set.
#[cfg(target_arch = "aarch64")]
const SYS_SOCKETPAIR: u32 = 199;

/// This filter reads the low half of each of the call's arguments, which is where the half that
/// matters is on a machine that stores the low half first.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const _: () = assert!(
    cfg!(target_endian = "little"),
    "this filter reads the low half of each argument at the argument's own offset, which is only \
     where it is on a machine that stores the low half first"
);

/// Loads a word from the call this filter is judging.
const LOAD: u16 = 0x20;
/// Compares the loaded word with a constant.
const COMPARE: u16 = 0x15;
/// Compares the loaded word with a constant, for greater or equal.
const AT_LEAST: u16 = 0x35;
/// Keeps only the bits of a constant.
const MASK: u16 = 0x54;
/// Answers.
const ANSWER: u16 = 0x06;

/// Where in the call this filter is judging each thing is.
const NUMBER: u32 = 0;
/// Where in the call this filter is judging each thing is.
const MACHINE: u32 = 4;
/// Where in the call this filter is judging each thing is.
const FIRST_ARGUMENT: u32 = 16;
/// Where in the call this filter is judging each thing is.
const SECOND_ARGUMENT: u32 = 24;
/// Where in the call this filter is judging each thing is.
const THIRD_ARGUMENT: u32 = 32;

/// The bits of a socket's kind that name the kind, without the flags that travel beside it.
const KIND: u32 = 0xff;

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
        instruction(LOAD, 0, 0, MACHINE),
        // A machine this filter does not describe, or the other calling convention of this one,
        // ends the process rather than being judged by numbers that mean something else.
        instruction(COMPARE, 1, 0, ARCHITECTURE),
        instruction(ANSWER, 0, 0, UNKNOWN_MACHINE),
        instruction(LOAD, 0, 0, NUMBER),
        instruction(AT_LEAST, 0, 1, OTHER_CONVENTION),
        instruction(ANSWER, 0, 0, UNKNOWN_MACHINE),
    ];
    // The kernel's queued-work interface, refused for every invocation: it is another way to reach
    // the calls below without making them.
    program.extend([
        instruction(AT_LEAST, 0, 2, SYS_QUEUED_WORK),
        instruction(AT_LEAST, 1, 0, SYS_QUEUED_WORK_LAST + 1),
        instruction(ANSWER, 0, 0, REFUSED),
    ]);
    if remote {
        // A socket is made only of what this boundary can account for. A *connected pair* of local
        // sockets has no address to reach anything by, so a pair of those is made; a local socket
        // that can still be given a destination is not, whether that is a single one or a pair of
        // the kind that carries an address on every message, because the kernel's rules say nothing
        // about where one of those goes and a program on the other end of it can reach anything it
        // likes on this child's behalf. What is left is the internet families, on which the only
        // socket is a stream one of the protocol the port rules govern. Nothing may listen.
        program.extend([
            // Index 9, 10, 11: which call this is. A pair goes to the rules at 12, a single socket
            // to those at 19, `listen` is refused, and anything else is the ordinary work of
            // running Git.
            instruction(COMPARE, 2, 0, SYS_SOCKETPAIR),
            instruction(COMPARE, 8, 0, SYS_SOCKET),
            instruction(COMPARE, 16, 17, SYS_LISTEN),
            // 12 to 18: a pair is a local one, of the kind that is connected to its other half and
            // to nothing else, and of no protocol besides.
            instruction(LOAD, 0, 0, FIRST_ARGUMENT),
            instruction(COMPARE, 0, 14, libc::AF_UNIX as u32),
            instruction(LOAD, 0, 0, SECOND_ARGUMENT),
            instruction(MASK, 0, 0, KIND),
            instruction(COMPARE, 0, 11, libc::SOCK_STREAM as u32),
            instruction(LOAD, 0, 0, THIRD_ARGUMENT),
            instruction(COMPARE, 10, 9, 0),
            // 19, 20, 21: an internet family is the one the rules below are about, and a family
            // this filter does not name is refused rather than left alone.
            instruction(LOAD, 0, 0, FIRST_ARGUMENT),
            instruction(COMPARE, 1, 0, libc::AF_INET as u32),
            instruction(COMPARE, 0, 6, libc::AF_INET6 as u32),
            // 22, 23, 24: an internet socket is a stream one, whatever flags travel beside its kind.
            instruction(LOAD, 0, 0, SECOND_ARGUMENT),
            instruction(MASK, 0, 0, KIND),
            instruction(COMPARE, 0, 3, libc::SOCK_STREAM as u32),
            // 25, 26, 27: and its protocol is the one the kernel's own address rules are about.
            // A stream socket of another protocol is a stream socket those rules say nothing about.
            instruction(LOAD, 0, 0, THIRD_ARGUMENT),
            instruction(COMPARE, 2, 0, 0),
            instruction(COMPARE, 1, 0, libc::IPPROTO_TCP as u32),
            // 28, 29.
            instruction(ANSWER, 0, 0, REFUSED),
            instruction(ANSWER, 0, 0, PERMITTED),
        ]);
    } else {
        // No socket with an address at all, and nothing may listen. A local operation resolves no
        // name, so it has no reason for the kernel's own family either; what is left is a connected
        // pair of local sockets, which has no address to reach anything by.
        program.extend([
            // Index 9, 10, 11: which call this is.
            instruction(COMPARE, 2, 0, SYS_SOCKETPAIR),
            instruction(COMPARE, 8, 0, SYS_SOCKET),
            instruction(COMPARE, 7, 8, SYS_LISTEN),
            // 12 to 18: a pair is a local one, of the kind that is connected to its other half and
            // to nothing else, and of no protocol besides.
            instruction(LOAD, 0, 0, FIRST_ARGUMENT),
            instruction(COMPARE, 0, 5, libc::AF_UNIX as u32),
            instruction(LOAD, 0, 0, SECOND_ARGUMENT),
            instruction(MASK, 0, 0, KIND),
            instruction(COMPARE, 0, 2, libc::SOCK_STREAM as u32),
            instruction(LOAD, 0, 0, THIRD_ARGUMENT),
            instruction(COMPARE, 1, 0, 0),
            // 19, 20.
            instruction(ANSWER, 0, 0, REFUSED),
            instruction(ANSWER, 0, 0, PERMITTED),
        ]);
    }
    Ok(program)
}

/// Builds the filter for one invocation.
///
/// # Errors
///
/// Always returns [`ProjectError::GitFailed`]: this host holds no call numbers for this instruction
/// set and will not install a filter that does not mean what it says.
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

    /// One call, as the kernel would hand it to the filter.
    #[derive(Clone, Copy)]
    struct Call {
        machine: u32,
        number: u32,
        family: u32,
        kind: u32,
        protocol: u32,
    }

    /// Runs the filter over one call and returns the answer it gives.
    fn judge(program: &[libc::sock_filter], call: Call) -> u32 {
        let mut at = 0_usize;
        let mut accumulator = 0_u32;
        loop {
            let instruction = program[at];
            match instruction.code {
                LOAD => {
                    accumulator = match instruction.k {
                        NUMBER => call.number,
                        MACHINE => call.machine,
                        FIRST_ARGUMENT => call.family,
                        SECOND_ARGUMENT => call.kind,
                        THIRD_ARGUMENT => call.protocol,
                        other => panic!("the filter loaded {other}, which nothing here means"),
                    };
                    at += 1;
                }
                MASK => {
                    accumulator &= instruction.k;
                    at += 1;
                }
                COMPARE | AT_LEAST => {
                    let matched = if instruction.code == COMPARE {
                        accumulator == instruction.k
                    } else {
                        accumulator >= instruction.k
                    };
                    let taken = if matched {
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

    fn call(number: u32, family: u32, kind: u32) -> Call {
        Call {
            machine: ARCHITECTURE,
            number,
            family,
            kind,
            protocol: 0,
        }
    }

    fn call_with(number: u32, family: u32, kind: u32, protocol: u32) -> Call {
        Call {
            protocol,
            ..call(number, family, kind)
        }
    }

    #[test]
    fn a_local_invocation_makes_no_socket_with_an_address_and_cannot_listen() {
        let program = filter(false).expect("a filter for this machine");
        // Every family, including the local one: a single socket is how a program reaches another
        // by name, and a local operation has no reason to reach anything.
        for family in [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_PACKET,
            libc::AF_NETLINK,
            libc::AF_VSOCK,
            libc::AF_BLUETOOTH,
        ] {
            assert_eq!(
                judge(&program, call(SYS_SOCKET, family as u32, 1)),
                REFUSED,
                "a local operation makes no socket of family {family}"
            );
        }
        assert_eq!(judge(&program, call(SYS_LISTEN, 0, 0)), REFUSED);
        // A pair has no address, so it is not a way to reach anything.
        assert_eq!(
            judge(&program, call(SYS_SOCKETPAIR, libc::AF_UNIX as u32, 1)),
            PERMITTED
        );
        for family in [libc::AF_INET, libc::AF_NETLINK, libc::AF_VSOCK] {
            assert_eq!(
                judge(&program, call(SYS_SOCKETPAIR, family as u32, 1)),
                REFUSED,
                "and a pair of family {family} is not one"
            );
        }
        // Everything else is the ordinary work of running Git.
        assert_eq!(judge(&program, call(1, 0, 0)), PERMITTED);
    }

    #[test]
    fn a_remote_invocation_may_connect_out_and_still_cannot_listen_or_go_below_its_protocol() {
        let program = filter(true).expect("a filter for this machine");
        assert_eq!(
            judge(
                &program,
                call(SYS_SOCKET, libc::AF_INET as u32, libc::SOCK_STREAM as u32)
            ),
            PERMITTED
        );
        assert_eq!(
            judge(
                &program,
                call(SYS_SOCKET, libc::AF_INET6 as u32, libc::SOCK_STREAM as u32)
            ),
            PERMITTED
        );
        // A datagram is the one thing nothing here could bound, so there is not one; the module
        // documentation says what that costs and what it is answered with.
        for family in [libc::AF_INET, libc::AF_INET6] {
            assert_eq!(
                judge(
                    &program,
                    call(SYS_SOCKET, family as u32, libc::SOCK_DGRAM as u32)
                ),
                REFUSED
            );
            assert_eq!(
                judge(
                    &program,
                    call(SYS_SOCKET, family as u32, libc::SOCK_RAW as u32)
                ),
                REFUSED
            );
        }
        // The flags a socket carries beside its kind do not change what kind it is.
        assert_eq!(
            judge(
                &program,
                call(
                    SYS_SOCKET,
                    libc::AF_INET as u32,
                    libc::SOCK_RAW as u32 | 0o4000
                )
            ),
            REFUSED
        );
        // A stream socket of a protocol the kernel's address rules say nothing about is one those
        // rules would not bound, so it is not made either.
        assert_eq!(
            judge(
                &program,
                call_with(
                    SYS_SOCKET,
                    libc::AF_INET as u32,
                    libc::SOCK_STREAM as u32,
                    libc::IPPROTO_SCTP as u32
                )
            ),
            REFUSED
        );
        assert_eq!(
            judge(
                &program,
                call_with(
                    SYS_SOCKET,
                    libc::AF_INET as u32,
                    libc::SOCK_STREAM as u32,
                    libc::IPPROTO_TCP as u32
                )
            ),
            PERMITTED
        );
        // The family the kernel answers questions about this machine's own addresses on is not
        // made either: on a host that lets an ordinary account make a network namespace of its
        // own, a socket of that family reaches another program rather than the kernel.
        for protocol in [libc::NETLINK_ROUTE, libc::NETLINK_KOBJECT_UEVENT] {
            assert_eq!(
                judge(
                    &program,
                    call_with(
                        SYS_SOCKET,
                        libc::AF_NETLINK as u32,
                        libc::SOCK_RAW as u32,
                        protocol as u32
                    )
                ),
                REFUSED,
                "a remote operation makes no socket of the kernel's own family, protocol {protocol}"
            );
        }
        // A single local socket is how a program reaches another by name, and where that one goes
        // is not something any rule here could bound. A connected pair has no address at all, and
        // a pair of the kind that carries a destination on every message is not a pair like that.
        assert_eq!(
            judge(
                &program,
                call(SYS_SOCKET, libc::AF_UNIX as u32, libc::SOCK_STREAM as u32)
            ),
            REFUSED
        );
        assert_eq!(
            judge(
                &program,
                call(
                    SYS_SOCKETPAIR,
                    libc::AF_UNIX as u32,
                    libc::SOCK_STREAM as u32
                )
            ),
            PERMITTED
        );
        for kind in [libc::SOCK_DGRAM, libc::SOCK_SEQPACKET] {
            assert_eq!(
                judge(
                    &program,
                    call(SYS_SOCKETPAIR, libc::AF_UNIX as u32, kind as u32)
                ),
                REFUSED,
                "a pair of kind {kind} carries a destination on every message"
            );
        }
        assert_eq!(
            judge(
                &program,
                call_with(
                    SYS_SOCKETPAIR,
                    libc::AF_UNIX as u32,
                    libc::SOCK_STREAM as u32,
                    libc::IPPROTO_TCP as u32
                )
            ),
            REFUSED,
            "and a pair of a protocol this filter does not name is not one"
        );
        // A family this filter does not name is refused rather than left alone, whichever call
        // makes it: the machine this one runs inside is reached on a stream socket whose ports
        // have nothing to do with the ports a remote operation is bounded to.
        for family in [
            libc::AF_VSOCK,
            libc::AF_BLUETOOTH,
            libc::AF_ALG,
            libc::AF_PACKET,
            libc::AF_NETLINK,
        ] {
            for number in [SYS_SOCKET, SYS_SOCKETPAIR] {
                assert_eq!(
                    judge(
                        &program,
                        call(number, family as u32, libc::SOCK_STREAM as u32)
                    ),
                    REFUSED,
                    "a remote operation makes no socket of family {family}"
                );
            }
        }
        assert_eq!(judge(&program, call(SYS_LISTEN, 0, 0)), REFUSED);
        assert_eq!(judge(&program, call(1, 0, 0)), PERMITTED);
    }

    #[test]
    fn no_invocation_may_set_up_a_queue_that_makes_calls_for_it() {
        for remote in [false, true] {
            let program = filter(remote).expect("a filter for this machine");
            for number in SYS_QUEUED_WORK..=SYS_QUEUED_WORK_LAST {
                assert_eq!(
                    judge(&program, call(number, 0, 0)),
                    REFUSED,
                    "a queue that makes calls on a process's behalf is refused"
                );
            }
            // The numbers either side of them are ordinary calls.
            assert_eq!(judge(&program, call(SYS_QUEUED_WORK - 1, 0, 0)), PERMITTED);
            assert_eq!(
                judge(&program, call(SYS_QUEUED_WORK_LAST + 1, 0, 0)),
                PERMITTED
            );
        }
    }

    /// The walk above reads the call through the same constants the program does, so a constant
    /// that named the wrong place would agree with itself. These are checked against the structure
    /// the kernel hands a filter and the numbers this machine's C library holds.
    #[test]
    fn the_filter_reads_the_call_where_the_kernel_puts_it() {
        use std::mem::offset_of;

        assert_eq!(
            usize::try_from(NUMBER),
            Ok(offset_of!(libc::seccomp_data, nr))
        );
        assert_eq!(
            usize::try_from(MACHINE),
            Ok(offset_of!(libc::seccomp_data, arch))
        );
        let arguments = offset_of!(libc::seccomp_data, args);
        assert_eq!(usize::try_from(FIRST_ARGUMENT), Ok(arguments));
        assert_eq!(usize::try_from(SECOND_ARGUMENT), Ok(arguments + 8));
        assert_eq!(usize::try_from(THIRD_ARGUMENT), Ok(arguments + 16));

        assert_eq!(Ok(SYS_SOCKET), u32::try_from(libc::SYS_socket));
        assert_eq!(Ok(SYS_SOCKETPAIR), u32::try_from(libc::SYS_socketpair));
        assert_eq!(Ok(SYS_LISTEN), u32::try_from(libc::SYS_listen));
        assert_eq!(Ok(SYS_QUEUED_WORK), u32::try_from(libc::SYS_io_uring_setup));
        assert_eq!(
            Ok(SYS_QUEUED_WORK_LAST),
            u32::try_from(libc::SYS_io_uring_register)
        );
    }

    #[test]
    fn a_machine_this_filter_does_not_describe_ends_the_process() {
        for remote in [false, true] {
            let program = filter(remote).expect("a filter for this machine");
            let mut other = call(SYS_SOCKET, 0, 0);
            other.machine = 0;
            assert_eq!(judge(&program, other), UNKNOWN_MACHINE);
            // The other calling convention of this same machine, whose numbers mean other calls.
            let mut convention = call(SYS_SOCKET | OTHER_CONVENTION, 0, 0);
            convention.machine = ARCHITECTURE;
            assert_eq!(judge(&program, convention), UNKNOWN_MACHINE);
        }
    }
}
