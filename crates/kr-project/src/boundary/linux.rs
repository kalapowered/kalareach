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
//!   the execute right.
//! * **Reads.** For the owner's own operations, on the whole filesystem, which the module
//!   documentation in [`super`] explains. For an operation performed for a caller bounded by a
//!   grant, only on what the invocation is granted: the directories the operation owns, the ones
//!   it is lent to read, Git's own program and helper directory, the four device nodes, and the
//!   support set named for this host's Git. That is one ruleset without the whole-filesystem rule,
//!   not a second ruleset over the first: rules in one ruleset add up, so a narrow read beside the
//!   whole filesystem would take nothing away. Such an invocation reaches no remote, and it is
//!   refused when a filesystem is mounted beneath a directory it would be granted.
//! * **Descriptors.** Every descriptor the child holds from the fourth on is marked to close when
//!   it executes Git, after the rules are applied, so a descriptor this service left open to
//!   something outside them is not one Git inherits. A kernel rule on reading is judged when a file
//!   is opened, and a descriptor opened before the rules is already open.
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
//! throwing it away; refused that question, the affected builds answer it "no" and ask the resolver
//! for IPv4 addresses alone, so a name that has only an IPv6 address fails that lookup inside this
//! boundary. An address written out in full does not go through it, and neither does `localhost`,
//! which that library answers out of its own head. Git's own transport over ssh does not ask the
//! question at all, and a build whose question is asked on a stream socket would not be refused.
//!
//! The filter is built for this machine's own instruction set, and an architecture whose call
//! numbers this host does not hold refuses the invocation rather than installing a filter that
//! would not mean what it says.

#![expect(
    unsafe_code,
    reason = "installing a system-call filter is a raw prctl with a pointer argument, and marking \
              every descriptor to close on execution is a raw system call; neither has a safe \
              form, and this module holds those calls and the constants they need"
)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use super::{Confinement, Invocation, Reach, Reads, SupportSet};
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

    /// Applies the boundary to this process, and then marks its descriptors to close when it
    /// executes Git.
    ///
    /// Runs in the forked child. A failure of either returns an error rather than continuing, and
    /// the child never reaches `exec`.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal, or a permission failure when the ruleset was applied without
    /// being fully enforced.
    pub fn apply(&mut self) -> std::io::Result<()> {
        self.confine()?;
        pin_descriptors()
    }

    /// Applies the rules and the filter to this process, and nothing else.
    fn confine(&mut self) -> std::io::Result<()> {
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

/// Marks every descriptor from the fourth on to close when this process executes its program.
///
/// Runs in the forked child, after the rules and the filter. It marks rather than closes: the
/// descriptor the standard library reports a failed execution on has to stay open until the
/// execution, and it is already marked, as is every descriptor this service opens. What this
/// catches is one that is not, which Git would otherwise inherit together with whatever it was
/// opened on, rules or none. A kernel that cannot mark them fails the spawn, so Git never runs
/// holding one.
fn pin_descriptors() -> std::io::Result<()> {
    // SAFETY: one system call on this process's own descriptor table, taking three scalars.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            libc::c_long::from(3_u32),
            libc::c_long::from(u32::MAX),
            libc::c_long::from(libc::CLOSE_RANGE_CLOEXEC),
        )
    };
    if marked == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Builds the boundary one invocation runs under.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when this kernel cannot enforce the rights this boundary is
/// made of, when a remote operation asks for rules a kernel this old does not have, or when an
/// object the rules are attached to cannot be opened. An invocation whose reads are bounded is
/// also refused when it would reach a remote, when a support object is missing, and when a
/// filesystem is mounted beneath a directory it would be granted.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
    let remote = !matches!(confinement.reach, Reach::Nothing);
    if remote && matches!(confinement.reads, Reads::Bounded(_)) {
        return Err(ProjectError::GitFailed {
            detail: "an invocation for a caller bounded by a grant reaches no remote: a location \
                     says nothing about which providers this host may reach for it, and its reads \
                     name no certificate store and no resolver file"
                .into(),
        });
    }
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
    created = match &confinement.reads {
        // Reads everywhere, and the execute right nowhere: this rule is what makes every later
        // rule an addition rather than the only thing that works. The owner already holds that
        // authority over the owner's own files, so the boundary takes none of it away.
        Reads::Everywhere => created
            .add_rule(PathBeneath::new(
                opened(Path::new("/"))?,
                AccessFs::ReadFile | AccessFs::ReadDir,
            ))
            .map_err(rules)?,
        // No rule on the whole filesystem, rather than one with narrower rules beside it: rules
        // in one ruleset add up, so a narrow read next to the whole filesystem would take nothing
        // away.
        Reads::Bounded(support) => bounded(created, confinement, support)?,
    };
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
                directory.handle().handle().as_fd(),
                written,
            ))
            .map_err(rules)?;
    }
    if matches!(confinement.reads, Reads::Everywhere) {
        // The loader, so that a dynamically linked Git can be started at all. An invocation whose
        // reads are bounded has the loaders its own programs name, in its support set.
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

/// Adds what an invocation bounded by a grant may read: the directories it is lent to read, and
/// the support set named for this host's Git.
///
/// The directories the operation owns are readable through their own rules, and Git's program and
/// helper directory through theirs. Every object here is opened before any rule is made, and the
/// mount check is made against those opened objects, so what is checked is what the rules are
/// attached to.
fn bounded(
    mut created: RulesetCreated,
    confinement: &Confinement,
    support: &SupportSet,
) -> Result<RulesetCreated> {
    let mut reads: Vec<(PathFd, BitFlags<AccessFs>)> = Vec::new();
    let mut directories: Vec<PathBuf> = Vec::new();
    for path in &confinement.readable {
        let handle = opened(path)?;
        // A directory's rights on a file are refused by the kernel, so a file is lent the right to
        // be read and nothing else.
        if is_directory(&handle, path)? {
            directories.push(current_path(handle.as_fd(), path)?);
            reads.push((handle, AccessFs::ReadFile | AccessFs::ReadDir));
        } else {
            reads.push((handle, AccessFs::ReadFile.into()));
        }
    }
    for loader in support.loaders() {
        // The kernel opens a program's loader for execution when it starts the program, and that
        // open is judged by the execute right.
        reads.push((
            support_object(loader)?,
            AccessFs::Execute | AccessFs::ReadFile,
        ));
    }
    for library in support.libraries() {
        let handle = support_object(library)?;
        directories.push(current_path(handle.as_fd(), library)?);
        reads.push((handle, AccessFs::ReadFile | AccessFs::ReadDir));
    }
    let helpers = opened(&confinement.exec_path)?;
    directories.push(current_path(helpers.as_fd(), &confinement.exec_path)?);
    for directory in confinement.written() {
        directories.push(current_path(
            directory.handle().handle().as_fd(),
            directory.path(),
        )?);
    }
    refuse_mounts_beneath(&directories)?;
    for (handle, access) in reads {
        created = created
            .add_rule(PathBeneath::new(handle, access))
            .map_err(rules)?;
    }
    Ok(created)
}

/// Refuses when a filesystem is mounted beneath a directory an invocation bounded by a grant
/// would be granted.
///
/// A rule on a directory reaches everything beneath it as the kernel presents it at each open,
/// and that includes another filesystem mounted there and a second view of one bound there. So
/// such an invocation is not run over a granted directory that has a mount point beneath it. It is
/// read from this process's own mount table immediately before each invocation, and it narrows
/// rather than closes: a mount made, or a directory holding one moved beneath a granted directory,
/// after this reading and while Git runs is read as part of the tree, which is the limit
/// `README.md` in this crate states in what such a caller is promised.
fn refuse_mounts_beneath(directories: &[PathBuf]) -> Result<()> {
    let table = std::fs::read("/proc/self/mountinfo").map_err(|error| {
        refused(
            "this host's mount table could not be read, so an invocation for a caller bounded \
             by a grant is not run",
            &error,
        )
    })?;
    for line in table.split(|byte| *byte == b'\n') {
        let Some(point) = mount_point(line) else {
            continue;
        };
        for directory in directories {
            if point != *directory && point.starts_with(directory) {
                return Err(ProjectError::GitFailed {
                    detail: format!(
                        "a filesystem is mounted at {}, beneath {}, which this invocation would be \
                         granted; an invocation for a caller bounded by a grant is not run over a \
                         directory with another filesystem inside it",
                        crate::git::redact(&point.display().to_string()),
                        crate::git::redact(&directory.display().to_string())
                    )
                    .into(),
                });
            }
        }
    }
    Ok(())
}

/// Returns the mount point one line of the mount table names, with the table's escapes undone.
///
/// The fifth field, in which a space, a tab, a line break and a backslash are written as a
/// backslash and three octal digits.
fn mount_point(line: &[u8]) -> Option<PathBuf> {
    let field = line.split(|byte| *byte == b' ').nth(4)?;
    let mut bytes = Vec::with_capacity(field.len());
    let mut at = 0;
    while let Some(&byte) = field.get(at) {
        if byte == b'\\'
            && let Some(digits) = field.get(at + 1..at + 4)
            && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
            && let Ok(decoded) = u8::try_from(
                digits
                    .iter()
                    .fold(0_u32, |value, digit| value * 8 + u32::from(digit - b'0')),
            )
        {
            bytes.push(decoded);
            at += 4;
        } else {
            bytes.push(byte);
            at += 1;
        }
    }
    Some(PathBuf::from(OsString::from_vec(bytes)))
}

/// Returns whether an opened object is a directory.
fn is_directory(handle: &PathFd, path: &Path) -> Result<bool> {
    let stat = rustix::fs::fstat(handle).map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "{} could not be examined to build this invocation's boundary: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    })?;
    Ok(rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory)
}

/// Returns where an opened object is now, as the kernel names it.
fn current_path(handle: BorrowedFd<'_>, path: &Path) -> Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", handle.as_raw_fd())).map_err(|error| {
        ProjectError::GitFailed {
            detail: format!(
                "where {} is now could not be read, so an invocation for a caller bounded by a \
                 grant is not run: {error}",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
        }
    })
}

/// Returns the handle a support rule is attached to, refusing the invocation by the object's
/// name when it is missing.
fn support_object(path: &Path) -> Result<PathFd> {
    PathFd::new(path).map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "the support object {} is missing or cannot be opened ({}), so an invocation for a \
             caller bounded by a grant is not run",
            crate::git::redact(&path.display().to_string()),
            unopened(&error)
        )
        .into(),
    })
}

/// Returns why an object could not be opened, in the system's own words.
///
/// The library's own text repeats the path in quotation marks, and a message holding a character
/// this host does not repeat is replaced whole, name and all. The path is named by the message this
/// host composes instead.
fn unopened(error: &landlock::PathFdError) -> String {
    std::error::Error::source(error)
        .map_or_else(|| "it could not be opened".to_owned(), ToString::to_string)
}

/// The kind of program header that names the loader a program is started through.
const PT_INTERP: u32 = 3;

/// How long a program header of a sixty-four-bit program is, at the least.
const PROGRAM_HEADER: usize = 56;

/// How long a loader's name may be before this host stops believing it.
const MAX_LOADER_NAME: u64 = 4096;

/// Names the loaders and the library directories of the programs given and of every program in
/// Git's helper directory, each resolved to the object it is.
///
/// Each program is read for the loader it names for itself, and that loader is asked which
/// libraries it resolves for the program, with an environment of nothing so that no variable
/// changes the answer. A file that is not a program, such as a script, names no loader and is
/// passed over: a script's interpreter is either one of the programs given or not executed at
/// all. One object reached by several names is read once.
///
/// Asking runs the loader, outside any boundary. So only the loaders the programs given name for
/// themselves are ever run, and a program in the helper directory that names another loader is a
/// refusal rather than a loader this host starts because a file said so.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] naming the object that could not be named.
pub fn support_set(
    programs: &[&Path],
    helper_directory: &Path,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut candidates: Vec<(PathBuf, bool)> = programs
        .iter()
        .map(|program| ((*program).to_owned(), true))
        .collect();
    let entries =
        std::fs::read_dir(helper_directory).map_err(|error| unnamed(helper_directory, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| unnamed(helper_directory, &error))?;
        candidates.push((entry.path(), false));
    }
    let mut seen = BTreeSet::new();
    let mut loaders = BTreeSet::new();
    let mut libraries = BTreeSet::new();
    for (candidate, required) in &candidates {
        let metadata = match std::fs::metadata(candidate) {
            Ok(metadata) => metadata,
            // A name in the helper directory that leads nowhere is nothing Git can start.
            Err(_) if !required => continue,
            Err(error) => return Err(unnamed(candidate, &error)),
        };
        if !metadata.is_file() || !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        let Some(loader) = interpreter(candidate)? else {
            continue;
        };
        let resolved = std::fs::canonicalize(&loader).map_err(|error| unnamed(&loader, &error))?;
        if !required && !loaders.contains(&resolved) {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} names the loader {}, which neither Git nor its connection shell is started \
                     through, so the support set of an invocation for a caller bounded by a grant \
                     cannot be named",
                    crate::git::redact(&candidate.display().to_string()),
                    crate::git::redact(&loader.display().to_string())
                )
                .into(),
            });
        }
        for library in listed(&loader, candidate)? {
            let resolved =
                std::fs::canonicalize(&library).map_err(|error| unnamed(&library, &error))?;
            if let Some(directory) = resolved.parent() {
                libraries.insert(directory.to_owned());
            }
        }
        loaders.insert(resolved);
    }
    Ok((
        loaders.into_iter().collect(),
        libraries.into_iter().collect(),
    ))
}

/// Returns the loader a program names for itself, or nothing for a file that is not a dynamically
/// linked program.
///
/// Read from the program's own headers, which is where the kernel reads it when it starts the
/// program. The kind of program this machine runs is the kind read: sixty-four bits, the low byte
/// of each number first. A program of another kind is a refusal rather than a guess.
fn interpreter(program: &Path) -> Result<Option<PathBuf>> {
    let file = std::fs::File::open(program).map_err(|error| unnamed(program, &error))?;
    let mut header = [0_u8; 64];
    if file.read_exact_at(&mut header, 0).is_err() || header[..4] != *b"\x7fELF" {
        return Ok(None);
    }
    let unread = |why: &str| ProjectError::GitFailed {
        detail: format!(
            "{} is {why}, so the support set of an invocation for a caller bounded by a grant \
             cannot be named",
            crate::git::redact(&program.display().to_string())
        )
        .into(),
    };
    if header[4] != 2 || header[5] != 1 {
        return Err(unread("a program of a kind this host does not read"));
    }
    let table = le64(&header[0x20..0x28]);
    let size = u16::from_le_bytes([header[0x36], header[0x37]]);
    let count = u16::from_le_bytes([header[0x38], header[0x39]]);
    if usize::from(size) < PROGRAM_HEADER {
        return Err(unread("a program whose headers this host cannot read"));
    }
    for index in 0..u64::from(count) {
        let mut entry = [0_u8; PROGRAM_HEADER];
        let at = index
            .checked_mul(u64::from(size))
            .and_then(|offset| offset.checked_add(table))
            .ok_or_else(|| unread("a program whose headers this host cannot read"))?;
        file.read_exact_at(&mut entry, at)
            .map_err(|error| unnamed(program, &error))?;
        if u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) != PT_INTERP {
            continue;
        }
        let offset = le64(&entry[8..16]);
        let length = le64(&entry[32..40]);
        if length == 0 || length > MAX_LOADER_NAME {
            return Err(unread("a program whose loader this host cannot read"));
        }
        let mut name = vec![0_u8; usize::try_from(length).unwrap_or(0)];
        file.read_exact_at(&mut name, offset)
            .map_err(|error| unnamed(program, &error))?;
        while name.last() == Some(&0) {
            name.pop();
        }
        let loader = PathBuf::from(OsString::from_vec(name));
        if !loader.is_absolute() {
            return Err(unread("a program whose loader is not named absolutely"));
        }
        return Ok(Some(loader));
    }
    Ok(None)
}

/// Returns the libraries a program's loader resolves for it, each by the path the loader gives.
///
/// The loader is asked with an environment of nothing, which is the environment every Git child
/// has as far as a loader is concerned: nothing this host sets names a library.
fn listed(loader: &Path, program: &Path) -> Result<Vec<PathBuf>> {
    let output = std::process::Command::new(loader)
        .arg("--list")
        .arg(program)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| unnamed(loader, &error))?;
    if !output.status.success() {
        return Err(ProjectError::GitFailed {
            detail: format!(
                "{} could not say which libraries {} loads, so the support set of an invocation \
                 for a caller bounded by a grant cannot be named",
                crate::git::redact(&loader.display().to_string()),
                crate::git::redact(&program.display().to_string())
            )
            .into(),
        });
    }
    let mut libraries = Vec::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        // Each library is `name => path (address)`. The loader itself and the kernel's own shared
        // object are named without an arrow, and neither is a library to read.
        let line = line.trim_ascii();
        let Some(arrow) = line.windows(4).position(|window| window == b" => ") else {
            continue;
        };
        let target = &line[arrow + 4..];
        let target = target
            .windows(2)
            .position(|window| window == b" (")
            .map_or(target, |end| &target[..end]);
        if target.first() != Some(&b'/') {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} loads {}, which {} does not find, so the support set of an invocation for \
                     a caller bounded by a grant cannot be named",
                    crate::git::redact(&program.display().to_string()),
                    crate::git::redact(&String::from_utf8_lossy(&line[..arrow])),
                    crate::git::redact(&loader.display().to_string())
                )
                .into(),
            });
        }
        libraries.push(PathBuf::from(std::ffi::OsStr::from_bytes(target)));
    }
    Ok(libraries)
}

/// Reads eight bytes as a number, the low byte first.
fn le64(bytes: &[u8]) -> u64 {
    let mut word = [0_u8; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(word)
}

/// Returns a refusal naming the object that could not be named for a support set.
fn unnamed(path: &Path, error: &std::io::Error) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!(
            "{} could not be read to name the support set of an invocation for a caller bounded by \
             a grant: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    }
}

/// Returns the handle a rule is attached to, refusing a path that cannot be opened.
fn opened(path: &Path) -> Result<PathFd> {
    PathFd::new(path).map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "{} could not be opened to build this invocation's boundary: {}",
            crate::git::redact(&path.display().to_string()),
            unopened(&error)
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

    use std::io::Read as _;
    use std::sync::Arc;

    use crate::boundary::OpenedDirectory;

    /// A confinement around one program, with its own working, temporary and helper directories.
    fn confinement_in(root: &Path, program: &Path, reach: Reach, reads: Reads) -> Confinement {
        let environment_id =
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([5; 16]));
        let working = root.join("working");
        let temporary = root.join("temporary");
        let helpers = root.join("helpers");
        for directory in [&working, &temporary, &helpers] {
            std::fs::create_dir_all(directory).expect("a directory for the test");
        }
        Confinement {
            program: program.to_owned(),
            exec_path: helpers,
            helpers: Vec::new(),
            working: OpenedDirectory::open(environment_id, &working, None)
                .expect("the working directory opens"),
            reserved: Vec::new(),
            temporary: OpenedDirectory::open(environment_id, &temporary, None)
                .expect("the temporary directory opens"),
            readable: Vec::new(),
            reach,
            reads,
        }
    }

    /// The support set of one program, named the way the profile names Git's.
    fn support_of(program: &Path) -> SupportSet {
        let nothing = tempfile::TempDir::new().expect("an empty helper directory");
        let (loaders, libraries) =
            support_set(&[program], nothing.path()).expect("the program's support set is named");
        SupportSet { loaders, libraries }
    }

    #[test]
    fn the_support_set_names_a_programs_own_loader_and_library_directories_and_nothing_broad() {
        let shell = Path::new("/bin/sh");
        let Some(loader) = interpreter(shell).expect("the shell's headers read") else {
            println!("not exercised: this host's shell is not dynamically linked");
            return;
        };
        let support = support_of(shell);
        assert!(
            support
                .loaders()
                .contains(&std::fs::canonicalize(&loader).expect("the loader resolves")),
            "the loader the shell names for itself is in the set: {support:?}"
        );
        assert!(
            !support.libraries().is_empty(),
            "and its libraries' directories"
        );
        for directory in support.libraries() {
            assert!(directory.is_dir(), "{} is a directory", directory.display());
            for broad in [
                "/", "/usr", "/etc", "/proc", "/sys", "/dev", "/dev/shm", "/tmp",
            ] {
                assert_ne!(
                    directory,
                    Path::new(broad),
                    "the set names no broad system directory"
                );
            }
        }
        // A file that is not a program names no loader and is passed over.
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let script = root.path().join("script");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").expect("a script");
        assert_eq!(interpreter(&script).expect("the script reads"), None);
    }

    #[test]
    fn the_loader_needs_the_execute_right_and_the_libraries_only_reading() {
        let shell = Path::new("/bin/sh");
        let Some(loader) = interpreter(shell).expect("the shell's headers read") else {
            println!("not exercised: this host's shell is not dynamically linked");
            return;
        };
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let named = support_of(shell);
        let arguments = [OsString::from("-c"), OsString::from("echo started")];
        let start = |support: SupportSet, readable: Vec<PathBuf>| {
            let mut confinement = confinement_in(
                root.path(),
                shell,
                Reach::Nothing,
                Reads::Bounded(Arc::new(support)),
            );
            confinement.readable = readable;
            crate::boundary::start(
                &Invocation {
                    program: shell,
                    arguments: &arguments,
                    environment: &[],
                    described: "a shell started under the named set",
                },
                &confinement,
            )
        };
        // The set as it is named: the loader may be executed and the libraries only read.
        let (status, stdout, _) = output_of(start(named.clone(), Vec::new()).expect("it starts"));
        assert_eq!(
            (status, stdout.as_str()),
            (Some(0), "started\n"),
            "the shell runs"
        );
        // The loader readable but not executable: the kernel will not start the program.
        let refusal = start(
            SupportSet {
                loaders: Vec::new(),
                libraries: named.libraries.clone(),
            },
            vec![loader.clone()],
        )
        .expect_err("a program whose loader may not be executed does not start");
        assert!(
            refusal.to_string().contains("Permission denied"),
            "the kernel refused to execute the loader: {refusal}"
        );
        // The library directories withheld: the loader runs and cannot load what the shell links.
        let (status, stdout, stderr) = output_of(
            start(
                SupportSet {
                    loaders: named.loaders.clone(),
                    libraries: Vec::new(),
                },
                Vec::new(),
            )
            .expect("the loader starts"),
        );
        assert_eq!(status, Some(127), "the program cannot be loaded");
        assert!(stdout.is_empty(), "and never ran");
        assert!(
            stderr.contains("error while loading shared libraries"),
            "the loader says so: {stderr}"
        );
    }

    #[test]
    fn a_helper_that_names_another_loader_is_refused_and_that_loader_never_runs() {
        let shell = Path::new("/bin/sh");
        let Some(loader) = interpreter(shell).expect("the shell's headers read") else {
            println!("not exercised: this host's shell is not dynamically linked");
            return;
        };
        // A program that records its own run, at a name no longer than the loader's, so it can be
        // written into a copy of the shell in the loader's place.
        let marker = PathBuf::from(format!("/tmp/krl-{}", std::process::id()));
        let sentinel = PathBuf::from(format!("/tmp/krl-{}-ran", std::process::id()));
        if marker.as_os_str().len() > loader.as_os_str().len() {
            println!("not exercised: this host's loader has too short a name to write over");
            return;
        }
        std::fs::write(
            &marker,
            format!("#!/bin/sh\necho ran > {}\n", sentinel.display()),
        )
        .expect("a program that records its run");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o700))
                .expect("it is marked executable");
        }
        let helpers = tempfile::TempDir::new().expect("a helper directory");
        let bytes = std::fs::read(shell).expect("the shell reads");
        // The control: an ordinary copy of the shell names the shell's own loader, and the set is
        // named.
        std::fs::write(helpers.path().join("git-ordinary"), &bytes).expect("a copy of the shell");
        support_set(&[shell], helpers.path()).expect("an ordinary helper is named");
        // The same copy, naming the recording program as its loader.
        let named = loader.as_os_str().as_bytes();
        let at = bytes
            .windows(named.len())
            .position(|window| window == named)
            .expect("the loader's name is in the program");
        let mut planted = bytes.clone();
        planted[at..at + named.len()].fill(0);
        planted[at..at + marker.as_os_str().len()].copy_from_slice(marker.as_os_str().as_bytes());
        std::fs::write(helpers.path().join("git-planted"), &planted).expect("a planted helper");
        assert_eq!(
            interpreter(&helpers.path().join("git-planted")).expect("the planted headers read"),
            Some(marker.clone()),
            "the planted helper names the recording program as its loader"
        );
        let refusal = support_set(&[shell], helpers.path())
            .expect_err("a helper naming another loader is refused");
        std::fs::remove_file(&marker).expect("the recording program goes");
        assert!(
            refusal.to_string().contains("git-planted"),
            "the refusal names the helper: {refusal}"
        );
        assert!(
            std::fs::symlink_metadata(&sentinel).is_err(),
            "and the loader it named was never run"
        );
    }

    #[test]
    fn a_support_object_that_is_gone_refuses_the_invocation_by_its_name() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let shell = Path::new("/bin/sh");
        let mut support = support_of(shell);
        // The control first: the set as it was named builds a boundary.
        prepare(&confinement_in(
            root.path(),
            shell,
            Reach::Nothing,
            Reads::Bounded(Arc::new(support.clone())),
        ))
        .expect("the named set builds a boundary");
        support
            .libraries
            .push(root.path().join("a-library-directory-that-went"));
        let refusal = prepare(&confinement_in(
            root.path(),
            shell,
            Reach::Nothing,
            Reads::Bounded(Arc::new(support)),
        ))
        .expect_err("a support object that is gone refuses the invocation");
        let said = refusal.to_string();
        assert!(
            said.contains("the support object") && said.contains("a-library-directory-that-went"),
            "the refusal names the object: {said}"
        );
    }

    #[test]
    fn an_invocation_whose_reads_are_bounded_reaches_no_remote() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let shell = Path::new("/bin/sh");
        let refusal = prepare(&confinement_in(
            root.path(),
            shell,
            Reach::Outbound(vec![443]),
            Reads::Bounded(Arc::new(support_of(shell))),
        ))
        .expect_err("a bounded invocation that would reach a remote is refused");
        assert!(
            refusal.to_string().contains("reaches no remote"),
            "and says why: {refusal}"
        );
    }

    #[test]
    fn a_mount_point_is_read_with_the_tables_escapes_undone() {
        let line = |point: &str| {
            format!("36 35 98:0 /root {point} rw,noatime master:1 - ext4 /dev/root rw").into_bytes()
        };
        assert_eq!(
            mount_point(&line("/mnt/plain")),
            Some(PathBuf::from("/mnt/plain"))
        );
        assert_eq!(
            mount_point(&line("/mnt/a\\040space\\011tab\\012line\\134slash")),
            Some(PathBuf::from("/mnt/a space\ttab\nline\\slash"))
        );
        // Something that only looks like an escape is kept as it is.
        assert_eq!(
            mount_point(&line("/mnt/not\\9an\\08escape")),
            Some(PathBuf::from("/mnt/not\\9an\\08escape"))
        );
        assert_eq!(
            mount_point(b"36 35 98:0"),
            None,
            "a line too short names none"
        );
    }

    /// Runs one enclosed shell's output to its end.
    fn output_of(mut spawned: crate::boundary::Spawned) -> (Option<i32>, String, String) {
        let mut stdout = String::new();
        spawned
            .stdout()
            .expect("the output")
            .read_to_string(&mut stdout)
            .expect("the output reads");
        let mut stderr = String::new();
        spawned
            .stderr()
            .expect("the error")
            .read_to_string(&mut stderr)
            .expect("the error reads");
        let status = loop {
            if let Some(status) = spawned.try_wait().expect("the child can be waited on") {
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        (status.code(), stdout, stderr)
    }

    #[test]
    fn a_descriptor_left_open_before_the_rules_is_not_one_the_child_inherits() {
        let bash = Path::new("/bin/bash");
        if !bash.is_file() {
            println!("not exercised: this host has no bash to read a descriptor by its number");
            return;
        }
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let secret = root.path().join("secret");
        std::fs::write(&secret, "read-through-a-descriptor\n").expect("a file outside every grant");
        // Opened the way a library that forgot close-on-exec would leave it: inheritable.
        let leaked = std::fs::File::open(&secret).expect("the file opens");
        rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty())
            .expect("the descriptor is made inheritable");
        let number = leaked.as_raw_fd();
        let arguments = [
            OsString::from("-c"),
            OsString::from(format!(
                "IFS= read -r line <&{number} && printf '%s' \"$line\""
            )),
        ];
        let confinement = confinement_in(
            root.path(),
            bash,
            Reach::Nothing,
            Reads::Bounded(Arc::new(support_of(bash))),
        );
        // The launcher: the rules, the filter, and the descriptors pinned.
        let (status, stdout, stderr) = output_of(
            crate::boundary::start(
                &Invocation {
                    program: bash,
                    arguments: &arguments,
                    environment: &[],
                    described: "a reader of one descriptor",
                },
                &confinement,
            )
            .expect("the reader starts"),
        );
        assert_ne!(status, Some(0), "the reader finds nothing to read");
        assert!(
            !stdout.contains("read-through-a-descriptor"),
            "the file was not read through the descriptor"
        );
        assert!(
            stderr.contains("Bad file descriptor"),
            "because the descriptor was not there: {stderr}"
        );
        // The control: the same rules and the same filter with the pin lifted, and the file is read
        // through the descriptor it inherited, although no rule grants it.
        let mut prepared = prepare(&confinement).expect("the boundary is built");
        let mut command = std::process::Command::new(bash);
        command
            .args(&arguments)
            .env_clear()
            .stdin(std::process::Stdio::null());
        {
            use std::os::unix::process::CommandExt as _;
            // SAFETY: the hook applies a ruleset and a filter this process built, as the launcher's
            // own hook does, and nothing else.
            unsafe {
                command.pre_exec(move || prepared.confine());
            }
        }
        let output = command.output().expect("the reader starts");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "read-through-a-descriptor",
            "without the pin the descriptor is inherited and read: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(leaked);
    }

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
