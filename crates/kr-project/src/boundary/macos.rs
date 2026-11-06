//! The macOS boundary: one sandbox profile per invocation, applied before Git is executed.
//!
//! The profile is written here, as text, from the invocation's own confinement, and it denies
//! everything that is not named. What is named is: the Git program and its own helper directory as
//! the only things that may be executed, the directories this operation owns as the only ones that
//! may be written, and, for a remote operation, outbound connections to the ports its transport
//! uses and the socket this system resolves names through.
//!
//! ## What an invocation may read
//!
//! For the owner's own operations reads are allowed everywhere, which is why the table in
//! [`super`] says such an operation's reads are not confined: the owner already holds that
//! authority over the owner's own files.
//!
//! For an operation performed for a caller bounded by a grant the profile allows no read it does
//! not name. It names the directories the operation owns, the paths the invocation is lent, Git's
//! program, the device nodes, and the libraries the system does not supply (the support set).
//! Git's helper directory is named for execution only. The system's own libraries need no rule:
//! the loader maps them from its shared cache without opening the files they would be in.
//!
//! Three reads go past those names, and each tells a name or an attribute and no content. The
//! root directory is read, because the loader will not start a program without it; it lists the
//! names at the top of the filesystem and nothing beneath them. A symbolic link may be read
//! wherever it is, which tells what it points at, because a name that goes through one is resolved
//! by reading it. The directories above each granted path may be examined, which tells that they
//! exist and what their attributes are, because Git resolves a name one directory at a time. The
//! profile also allows `sysctl-read` without a filter, as the owner's profile does: it is a
//! question to the kernel and not the read of a file, and this boundary does not narrow it.
//!
//! A profile judges the path a file has, not the name it was opened by, so every path it names is
//! resolved first, and a link inside a granted directory that leads outside it is refused at the
//! file it leads to. The data volume's own name for a file reaches the same path and is refused the
//! same way.
//!
//! The rules are names, not objects, which is the difference from the Linux boundary: a granted
//! directory that is renamed or replaced by a writer under the same account while Git runs is read
//! under the name the profile holds. After the run this host opens again the directories the
//! operation owns and reports one that is not the object it started against; a change made and
//! undone between the two readings is not told from none. The paths the invocation is lent and the
//! support set are held by name alone, so one of them replaced while Git runs is read under its
//! name and nothing detects it, and a mount at a lent directory itself is no mount beneath it, so
//! it is neither refused nor reported. Nothing here prevents any of it. A filesystem mounted
//! beneath a granted directory would be read under a granted name too, so such an invocation is
//! refused, from the table of mounted filesystems read just before the child starts.
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

#![expect(
    unsafe_code,
    reason = "the table of mounted filesystems is asked of the kernel with a raw system call that \
              fills a buffer, which has no safe form here; this module holds that one call"
)]

use std::ffi::{CStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::{Confinement, Invocation, Reach, Reads, SupportSet};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "a per-invocation macOS sandbox profile, applied by the system's own launcher before it \
     executes Git";

/// This platform has a boundary an invocation runs inside.
pub const NO_GIT: Option<&str> = None;

/// The launcher that applies a profile and then executes what it was given.
const LAUNCHER: &str = "/usr/bin/sandbox-exec";

#[cfg(any(test, feature = "git-fixtures"))]
thread_local! {
    /// Where this thread looks for the launcher instead of [`LAUNCHER`], when a case forces a
    /// host that has none.
    static LAUNCHER_AT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Runs `run` with this thread looking for the launcher at `path`, as a host whose launcher is
/// somewhere else, or gone, does. The launcher ships with every macOS this host runs on, so a case
/// that shows what its absence does could not otherwise reach it.
///
/// Nothing on the machine changes: it is the answer to where the launcher is that is replaced, on
/// this thread only.
#[cfg(any(test, feature = "git-fixtures"))]
pub fn with_launcher_at<R>(path: &Path, run: impl FnOnce() -> R) -> R {
    struct Restore(Option<PathBuf>);

    impl Drop for Restore {
        fn drop(&mut self) {
            LAUNCHER_AT.with(|at| *at.borrow_mut() = self.0.take());
        }
    }

    let _restore = Restore(LAUNCHER_AT.with(|at| at.replace(Some(path.to_owned()))));
    run()
}

/// Returns whether this host has the launcher: the system's, or where a case on this thread says
/// it is.
fn has_launcher() -> bool {
    #[cfg(any(test, feature = "git-fixtures"))]
    if let Some(forced) = LAUNCHER_AT.with(|at| at.borrow().clone()) {
        return forced.is_file();
    }
    Path::new(LAUNCHER).is_file()
}

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
/// that is the root of the filesystem, or a path holding a byte a profile cannot carry — when this
/// platform has no launcher to apply it with, or, for an invocation whose reads are bounded, when
/// it would reach a remote, when a path it is lent cannot be opened, when the table of mounted
/// filesystems cannot be read, and when a filesystem is mounted beneath a directory it would be
/// granted.
pub fn prepare(confinement: &Confinement) -> Result<Prepared> {
    if !has_launcher() {
        return Err(ProjectError::GitFailed {
            detail: "this host has no launcher to apply a boundary with, so Git is not run".into(),
        });
    }
    let mut text = String::from("(version 1)\n(deny default)\n");
    // The directories the profile names by subtree for reading, which the mount check is made
    // against.
    let mut readable_directories: Vec<PathBuf> = Vec::new();
    // The programs the invocation may execute, as the profile names them. A profile is judged
    // against the path a program has, so for an invocation whose reads are bounded each is
    // resolved first, as every other path it names is.
    let mut programs: Vec<PathBuf> = confinement
        .executables()
        .into_iter()
        .map(Path::to_owned)
        .collect();
    match &confinement.reads {
        // The owner's own operations read what the account can read, which the module
        // documentation says is deliberate.
        Reads::Everywhere => text.push_str("(allow file-read*)\n"),
        Reads::Bounded(support) => {
            if matches!(confinement.reach, Reach::Outbound(_)) {
                return Err(ProjectError::GitFailed {
                    detail: "an invocation for a caller bounded by a grant reaches no remote: a \
                             location says nothing about which providers this host may reach for \
                             it, and its reads name no certificate store and no resolver file"
                        .into(),
                });
            }
            for program in &mut programs {
                *program = opened(program)?.0;
            }
            text.push_str(&bounded_reads(
                confinement,
                support,
                &programs,
                &mut readable_directories,
            )?);
        }
    }
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
    for program in &programs {
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
    if matches!(confinement.reads, Reads::Bounded(_)) {
        // Read immediately before the child starts, so that what is checked is the table the
        // child starts under. A mount made after this reading, while Git runs, is read as part of
        // the tree, which the documents state.
        refuse_mounts_beneath(&readable_directories)?;
    }
    Ok(Prepared {
        profile: text,
        room: kr_ipc::inheritance::TableRoom::make(),
    })
}

/// Returns the rules that say what an invocation bounded by a grant may read, and adds the
/// directories they name by subtree to `directories`.
///
/// The directories the operation owns, the paths it is lent, Git's program and the device nodes are
/// readable; the support set is readable and may be mapped as code, which
/// is what a loader asks of a library it did not find in the shared cache. Every path is resolved
/// first: the profile is judged against the path a file has, so a name that goes through a link
/// would never match the path the file is opened at.
fn bounded_reads(
    confinement: &Confinement,
    support: &SupportSet,
    programs: &[PathBuf],
    directories: &mut Vec<PathBuf>,
) -> Result<String> {
    let mut text = String::new();
    // Every path the rules below name, resolved, for the rule about the directories above them.
    let mut named: Vec<PathBuf> = Vec::new();
    // The loader opens the root to start any program. It lists the names at the top of the
    // filesystem and reaches nothing beneath them.
    text.push_str("(allow file-read-data (literal \"/\"))\n");
    // A name that goes through a symbolic link is resolved by reading the link, and the link is
    // not inside any directory granted here: `/var` and `/tmp` lead into `/private`, and a
    // packaging of Git reaches its libraries through links of its own. Reading a link tells what
    // it points at and nothing of what is there, so the file it leads to is judged by the path it
    // has, as every other is.
    text.push_str("(allow file-read-metadata file-test-existence (vnode-type SYMLINK))\n");
    text.push_str("(allow file-read* ");
    for device in DEVICES {
        text.push_str(&literal(Path::new(device))?);
    }
    for program in programs {
        text.push_str(&literal(program)?);
        named.push(program.clone());
    }
    // Git's helper directory is executed from and not read: executing a program needs no read of
    // it. It is still a directory the profile grants, so it is held to the mount check and the
    // directories above it may be examined.
    directories.push(confinement.exec_path.clone());
    named.push(confinement.exec_path.clone());
    for directory in confinement.written() {
        text.push_str(&subpath(directory.path())?);
        directories.push(directory.path().to_owned());
        named.push(directory.path().to_owned());
    }
    for lent in &confinement.readable {
        let (resolved, is_directory) = opened(lent)?;
        if is_directory {
            text.push_str(&subpath(&resolved)?);
            directories.push(resolved.clone());
        } else {
            text.push_str(&literal(&resolved)?);
        }
        named.push(resolved);
    }
    text.push_str(")\n");
    if !support.loaders().is_empty() || !support.libraries().is_empty() {
        text.push_str("(allow file-read* file-map-executable ");
        for loader in support.loaders() {
            text.push_str(&literal(loader)?);
            named.push(loader.clone());
        }
        for library in support.libraries() {
            text.push_str(&subpath(library)?);
            directories.push(library.clone());
            named.push(library.clone());
        }
        text.push_str(")\n");
    }
    // Git resolves the names it is given one directory at a time, and asks about each. A directory
    // above a granted path may be examined, so that it can be found and told apart from a link,
    // and its contents may not be listed: of everything above a granted path, only its existence
    // and its attributes are told.
    text.push_str("(allow file-read-metadata file-test-existence ");
    for path in &named {
        text.push_str(&format!("(path-ancestors \"{}\") ", quoted(path)?));
    }
    text.push_str(")\n");
    Ok(text)
}

/// Resolves one path a profile is to name, and says whether it is a directory. A path that cannot
/// be opened refuses the invocation, as the same path does on Linux.
fn opened(path: &Path) -> Result<(PathBuf, bool)> {
    let refused = |error: std::io::Error| ProjectError::GitFailed {
        detail: format!(
            "{} could not be opened to build this invocation's boundary: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    };
    let resolved = std::fs::canonicalize(path).map_err(refused)?;
    let is_directory = std::fs::metadata(&resolved).map_err(refused)?.is_dir();
    Ok((resolved, is_directory))
}

/// Refuses when a filesystem is mounted beneath a directory an invocation bounded by a grant would
/// be granted.
///
/// A rule on a directory reaches everything beneath it as the system presents it at each open, and
/// that includes another filesystem mounted there: a disk image, a network share or a user-space
/// volume that any program of the account can attach to a directory it owns. It compares paths, as
/// the profile does, and it is read immediately before each invocation, so it narrows rather than
/// closes: a mount made while Git runs is read as part of the tree.
fn refuse_mounts_beneath(directories: &[PathBuf]) -> Result<()> {
    let points = mount_points().map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "this host's table of mounted filesystems could not be read, so an invocation for a \
             caller bounded by a grant is not run: {error}"
        )
        .into(),
    })?;
    match super::first_mount_beneath(points, directories) {
        Some((point, directory)) => Err(super::mounted_beneath(&point, directory)),
        None => Ok(()),
    }
}

/// Returns where each filesystem this host has mounted is mounted, as the system presents it.
///
/// The table is read without asking any filesystem to answer for itself, so a network share that
/// has stopped answering cannot hold the invocation.
fn mount_points() -> std::io::Result<Vec<PathBuf>> {
    // The table can grow between asking how long it is and reading it, so a reading that fills the
    // room it was given is made again with more.
    for _ in 0..8 {
        // SAFETY: with no buffer the call only counts the filesystems; it writes nowhere.
        let counted = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        let counted = usize::try_from(counted).map_err(|_| std::io::Error::last_os_error())?;
        let room = counted + 16;
        let bytes = i32::try_from(room * std::mem::size_of::<libc::statfs>())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::E2BIG))?;
        let mut table: Vec<libc::statfs> = Vec::with_capacity(room);
        // SAFETY: the buffer has room for `room` entries, and `bytes` is exactly that many.
        let filled = unsafe { libc::getfsstat(table.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
        let filled = usize::try_from(filled).map_err(|_| std::io::Error::last_os_error())?;
        if filled >= room {
            continue;
        }
        // SAFETY: the call initialised `filled` entries from the start of the buffer.
        unsafe { table.set_len(filled) };
        return Ok(table
            .iter()
            .map(|entry| {
                // SAFETY: the kernel ends the name it writes with a zero byte, inside the field.
                let name = unsafe { CStr::from_ptr(entry.f_mntonname.as_ptr()) };
                PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes()))
            })
            .collect());
    }
    Err(std::io::Error::other(
        "the table of mounted filesystems kept changing",
    ))
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

    /// How long a case waits for a child it started before it calls the child hung.
    const LIVENESS: std::time::Duration = std::time::Duration::from_secs(60);

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

    /// A confinement whose reads are bounded, lent these paths, with this support set.
    fn bounded(
        root: &Path,
        reach: Reach,
        readable: Vec<PathBuf>,
        libraries: Vec<PathBuf>,
    ) -> Confinement {
        let mut confinement = confinement(root, reach);
        confinement.readable = readable;
        confinement.reads = Reads::Bounded(std::sync::Arc::new(SupportSet {
            loaders: Vec::new(),
            libraries,
        }));
        confinement
    }

    /// Returns the rules of a profile that allow reading.
    fn read_rules(profile: &str) -> String {
        profile
            .lines()
            .filter(|line| {
                line.starts_with("(allow file-read* ") || line.starts_with("(allow file-read-data")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_owners_profile_reads_everywhere_and_a_bounded_one_reads_only_what_it_names() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let owner = profile_text(&confinement(root.path(), Reach::Nothing))
            .expect("the owner's profile is built");
        assert!(owner.contains("(allow file-read*)\n"));
        assert!(!owner.contains("file-map-executable") && !owner.contains("path-ancestors"));

        let library = root.path().join("lib");
        let lent = root.path().join("lent");
        std::fs::create_dir_all(&library).expect("a library directory");
        std::fs::create_dir_all(&lent).expect("a lent directory");
        let lent_file = root.path().join("lent.config");
        std::fs::write(&lent_file, "").expect("a lent file");
        let confinement = bounded(
            root.path(),
            Reach::Nothing,
            vec![lent.clone(), lent_file.clone()],
            vec![library.clone()],
        );
        let profile = profile_text(&confinement).expect("the bounded profile is built");
        assert!(
            !profile.contains("(allow file-read*)"),
            "nothing is readable but what is named: {profile}"
        );
        assert!(profile.contains("(allow file-read-data (literal \"/\"))"));
        let reads = read_rules(&profile);
        let resolved = |path: &Path| std::fs::canonicalize(path).expect("the path resolves");
        for directory in confinement.written() {
            assert!(reads.contains(&format!("(subpath \"{}\")", directory.path().display())));
        }
        assert!(reads.contains(&format!("(subpath \"{}\")", resolved(&lent).display())));
        assert!(reads.contains(&format!("(literal \"{}\")", resolved(&lent_file).display())));
        assert!(reads.contains(&format!(
            "(allow file-read* file-map-executable (subpath \"{}\")",
            library.display()
        )));
        assert!(profile.contains(&format!(
            "(path-ancestors \"{}\")",
            resolved(&lent).display()
        )));
        // The directories above a granted path may be examined and not read.
        assert!(
            profile.lines().any(|line| {
                line.starts_with("(allow file-read-metadata file-test-existence ")
                    && line.contains("(path-ancestors ")
            }),
            "{profile}"
        );
    }

    #[test]
    fn an_invocation_whose_reads_are_bounded_reaches_no_remote() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let refusal = prepare(&bounded(
            root.path(),
            Reach::Outbound(vec![443]),
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("a bounded invocation that would reach a remote is refused");
        assert!(
            refusal.to_string().contains("reaches no remote"),
            "and says why: {refusal}"
        );
    }

    #[test]
    fn a_lent_path_that_is_not_there_refuses_the_invocation_by_its_name() {
        let root = tempfile::TempDir::new().expect("a directory on the internal disk");
        let missing = root.path().join("not-there");
        let refusal = prepare(&bounded(
            root.path(),
            Reach::Nothing,
            vec![missing.clone()],
            Vec::new(),
        ))
        .expect_err("a path that cannot be opened cannot be granted");
        assert!(
            refusal.to_string().contains("not-there"),
            "and the refusal names it: {refusal}"
        );
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
        // The child's listing is read where a hung child cannot hold this case: the case ends the
        // child's group and fails when the child does not close its output or does not exit in
        // time. A child that is not hung costs what it costs.
        let mut output = spawned.stdout().expect("the child's output");
        let (listed, reading) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut listing = String::new();
            let read = output.read_to_string(&mut listing);
            let _ = listed.send(read.map(|_| listing));
        });
        let listing = match reading.recv_timeout(LIVENESS) {
            Ok(read) => read.expect("the child's listing"),
            Err(_) => {
                spawned.end();
                panic!("the child kept its output open for {LIVENESS:?}");
            }
        };
        let hung = std::time::Instant::now() + LIVENESS;
        while spawned
            .try_wait()
            .expect("the child is waited for")
            .is_none()
        {
            if std::time::Instant::now() >= hung {
                spawned.end();
                panic!("the child closed its output and was still running after {LIVENESS:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
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
