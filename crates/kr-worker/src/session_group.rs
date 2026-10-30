//! The control group a session's processes are placed in, below the service the worker runs in.
//!
//! Section 7 places the worker and its owned descendants in a dedicated delegated control group
//! where one is available. A worker the daemon starts through a user service manager is the only
//! process of its own service, and the manager hands that service's control group to it (the
//! daemon starts the unit with `Delegate=yes`), so the worker can make groups below it. The session
//! gets one: the root shell is placed in it before it runs, so everything the shell starts is in it
//! by inheritance, including a process that leaves the shell's session, its process group or its
//! parent. The group is what the session's ownership then rests on, and ending it ends what is in
//! it without the worker's own process, which stays in the service's group.
//!
//! Where there is no such group to make, because the worker is not the process of a service of its
//! own, the control groups are not the unified hierarchy, or the worker may not make a group below
//! its service, there is none, and the session rests on its terminal and process group as before.

use std::path::{Path, PathBuf};

/// Where the unified control group hierarchy is mounted.
pub const CONTROL_GROUP_ROOT: &str = "/sys/fs/cgroup";

/// The name of the group a session's processes are placed in, below its worker's service.
pub const SESSION_GROUP: &str = "session";

/// How many control groups a listing reads before it says it could not read them all.
///
/// A person's own commands can make groups below the session's, since the group is theirs to make
/// groups in, and a listing that followed a tree without a bound would be the one a hostile
/// session made it follow for ever. Groups are counted as the listing queues them, so a directory
/// with more groups in it than this is refused before they are all held.
pub const GROUP_BUDGET: usize = 4096;

/// A session's control group, made but not yet known to hold the root shell.
#[derive(Debug)]
pub struct SessionGroup {
    /// The group's directory in the control group file system.
    path: PathBuf,
    /// The group as `/proc/<pid>/cgroup` names it: the path below the file system's root.
    relative: String,
    /// The group's `cgroup.procs`, open for writing, which the root shell writes itself into
    /// between its fork and its exec.
    #[cfg(target_os = "linux")]
    procs: std::fs::File,
}

/// Whether a control group is the service of a worker: the last name is `kr-worker-<id>.service`.
///
/// A worker that was started in any other way (a terminal's login session, a scope, a service of
/// another name) shares its group with processes that are not the session's, and a group below it
/// would claim a boundary that does not hold.
#[must_use]
pub fn is_a_workers_service(control_group: &str) -> bool {
    control_group
        .rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.starts_with("kr-worker-") && leaf.ends_with(".service"))
}

/// The service whose session a control group is, or is below: the group cut at the `session`
/// component that follows a worker's service. Any other group is its own.
///
/// A session's processes are in the group their worker made below its service, and in any group
/// they made below that one, and they are the service's all the same: the manager's end of the
/// service ends them.
#[must_use]
pub fn service_of(group: &str) -> &str {
    let marker = format!("/{SESSION_GROUP}");
    let mut from = 0;
    while let Some(found) = group[from..].find(&marker) {
        let at = from + found;
        let after = at + marker.len();
        if (after == group.len() || group[after..].starts_with('/'))
            && is_a_workers_service(&group[..at])
        {
            return &group[..at];
        }
        from = at + 1;
    }
    group
}

impl SessionGroup {
    /// Makes the group below this worker's own service, when the worker runs in one it may make
    /// groups below.
    ///
    /// # Errors
    ///
    /// Returns why the group could not be made or used when the worker is the process of a service
    /// of its own, which is where one is owed. A worker that is not the process of such a service,
    /// or a platform with no such group, is owed none and gives no group and no error.
    pub fn make() -> Result<Option<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            let Some(service) = crate::ownership::own_cgroup() else {
                return Ok(None);
            };
            Self::make_below(Path::new(CONTROL_GROUP_ROOT), &service)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(None)
        }
    }

    /// Makes the group below the service `service`, a path as `/proc/<pid>/cgroup` names it,
    /// under the control group file system mounted at `root`.
    #[cfg(target_os = "linux")]
    fn make_below(root: &Path, service: &str) -> Result<Option<Self>, String> {
        if !is_a_workers_service(service) {
            return Ok(None);
        }
        let relative = format!("{}/{SESSION_GROUP}", service.trim_end_matches('/'));
        let path = root.join(relative.trim_start_matches('/'));
        // A group that is not new is not this session's: a worker makes it once, for one session.
        std::fs::create_dir(&path)
            .map_err(|error| format!("{} could not be made: {error}", path.display()))?;
        match std::fs::OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))
        {
            Ok(procs) => Ok(Some(Self {
                path,
                relative,
                procs,
            })),
            Err(error) => {
                let _ = std::fs::remove_dir(&path);
                Err(format!(
                    "{} cannot be written to: {error}",
                    path.join("cgroup.procs").display()
                ))
            }
        }
    }

    /// Makes the group and has the terminal's next start place the root shell in it, or does
    /// neither where there is no group to make.
    ///
    /// # Errors
    ///
    /// Returns why a group that was owed could not be made, as [`Self::make`] does.
    pub fn prepare(terminal: &mut crate::pty::Pty) -> Result<Option<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            let Some(group) = Self::make()? else {
                return Ok(None);
            };
            match group.procs() {
                Ok(procs) => {
                    terminal.place_the_shell_in(procs);
                    Ok(Some(group))
                }
                Err(error) => {
                    let why = format!("{} could not be used: {error}", group.path.display());
                    group.discard();
                    Err(why)
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = terminal;
            Ok(None)
        }
    }

    /// The group's directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The group's `cgroup.procs`, a duplicate of the open file, for the child to write itself
    /// into.
    #[cfg(target_os = "linux")]
    pub fn procs(&self) -> std::io::Result<std::os::fd::OwnedFd> {
        Ok(self.procs.try_clone()?.into())
    }

    /// Whether the process is in this group, or in one below it, now. A process that has gone, or
    /// whose group cannot be read, is not shown to be in it.
    #[must_use]
    pub fn holds(&self, pid: u32) -> bool {
        in_group(pid, &self.relative)
    }

    /// Removes a group that no process ever entered.
    pub fn discard(self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Whether the process is in the group named `relative`, or in one below it.
#[must_use]
pub fn in_group(pid: u32, relative: &str) -> bool {
    kr_ipc::identity::control_group_of(pid).is_some_and(|group| {
        group == relative
            || group
                .strip_prefix(relative)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// The group as `/proc/<pid>/cgroup` names it, for a directory of the control group file system.
#[must_use]
pub fn relative(path: &Path) -> Option<String> {
    let below = path.strip_prefix(CONTROL_GROUP_ROOT).ok()?;
    Some(format!("/{}", below.display()))
}

/// What reading the process list of one control group came to.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub enum List {
    /// The group's processes, as numbers.
    Read(Vec<u32>),
    /// The group went while the walk was under way, and holds nothing.
    Gone,
    /// A threaded group: its processes are listed by the group above it that is its thread root,
    /// which the walk has read or reads.
    Threaded,
}

/// What the kernel's answer to reading a group's `cgroup.procs` says.
///
/// A group removed while it is read answers that the file is not there or that the device is gone;
/// a group of threads answers that the operation is not supported.
///
/// # Errors
///
/// Returns why the list is not one: a failure to read it, or a line that is not a process number.
#[cfg(target_os = "linux")]
pub fn list_of(read: std::io::Result<String>) -> Result<List, String> {
    match read {
        Ok(text) => {
            let mut numbers = Vec::new();
            for line in text.lines() {
                let number: u32 = line
                    .trim()
                    .parse()
                    .map_err(|_| format!("a line of the list is not a process number: {line:?}"))?;
                // A process the kernel cannot map into this process's namespace is listed as zero.
                // It is held by the group and cannot be described, so the list is not whole.
                if number == 0 {
                    return Err("the list holds a process this host cannot name (0)".to_owned());
                }
                numbers.push(number);
            }
            Ok(List::Read(numbers))
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(rustix::io::Errno::NODEV.raw_os_error()) =>
        {
            Ok(List::Gone)
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::OPNOTSUPP.raw_os_error()) => {
            Ok(List::Threaded)
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Every process in the control group at `directory` and in every group below it, which is what
/// the kernel's end of the group reaches, once each.
///
/// The kernel writes each `cgroup.procs` in one reading and lists a process in the group it is in
/// now; one that moves while this walks can be read twice or not at all, which only the group's
/// `populated` line, never this list, answers for. A group below that is removed while the walk is
/// under way holds nothing and is skipped, and one of threads is listed by the group above it. The
/// group itself that is not there holds nothing, if its parent is there to say the file system
/// answers, because the kernel removes only an empty group.
///
/// # Errors
///
/// Returns why the walk could not read all of them: a list or a directory the kernel would not
/// give, a process it would not name, a group of threads at the top, or more groups than
/// [`GROUP_BUDGET`]. A list that is not whole is an error and never a shorter list.
#[cfg(target_os = "linux")]
pub fn members(directory: &Path) -> Result<Vec<u32>, String> {
    use std::io::ErrorKind::NotFound;

    let mut pids = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    let mut queued = 1_usize;
    while let Some(group) = pending.pop() {
        match list_of(std::fs::read_to_string(group.join("cgroup.procs"))) {
            Ok(List::Read(procs)) => pids.extend(procs),
            Ok(List::Gone) if group == directory => {
                if directory.parent().is_some_and(Path::is_dir) {
                    continue;
                }
                return Err(format!(
                    "{} and its parent are not there",
                    directory.display()
                ));
            }
            Ok(List::Gone) => continue,
            // The top group has to be listed: its processes are in no group above it to be read
            // from.
            Ok(List::Threaded) if group == directory => {
                return Err(format!(
                    "{}: the group is a group of threads",
                    group.display()
                ));
            }
            Ok(List::Threaded) => {}
            Err(why) => return Err(format!("{}: {why}", group.display())),
        }
        let entries = match std::fs::read_dir(&group) {
            Ok(entries) => entries,
            Err(error) if error.kind() == NotFound => continue,
            Err(error) => return Err(format!("{}: {error}", group.display())),
        };
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", group.display()))?;
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {
                    queued += 1;
                    if queued > GROUP_BUDGET {
                        return Err(format!(
                            "the control group and the groups below it are more than the \
                             {GROUP_BUDGET} the walk reads"
                        ));
                    }
                    pending.push(entry.path());
                }
                Ok(_) => {}
                Err(error) if error.kind() == NotFound => {}
                Err(error) => return Err(format!("{}: {error}", entry.path().display())),
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

/// Every process in the group: not possible off Linux, where no such group is made.
///
/// # Errors
///
/// Always: this platform makes no session group.
#[cfg(not(target_os = "linux"))]
pub fn members(_path: &Path) -> Result<Vec<u32>, String> {
    Err("this platform makes no session group".to_owned())
}

/// Ends every process in the group and in the groups below it, at once.
///
/// `cgroup.kill` does it in one write, including a process that is starting while it is written;
/// it is the kernel's from version 5.14. The file is opened as it is and never created, so a kernel
/// without it answers that the file is not there.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::NotFound`] where the kernel has no `cgroup.kill`, and the
/// operating system's error where the write was refused.
#[cfg(target_os = "linux")]
pub fn kill(path: &Path) -> std::io::Result<()> {
    use std::io::Write as _;

    std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.kill"))?
        .write_all(b"1")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// KR-REQ-07.60: only the service of a worker is given a group of the session's own. A login
    /// session's scope, a daemon's scope, another service of this host and a unit of any other name
    /// share their group with processes that are not the session's, and a boundary drawn below them
    /// would claim more than it holds.
    #[test]
    fn only_a_workers_own_service_is_given_a_session_group() {
        let reservation = "kr-worker-01010101-0101-0101-0101-010101010101.service";
        assert!(is_a_workers_service(&format!("/user.slice/{reservation}")));
        for other in [
            "/user.slice/user-1000.slice/session-3.scope",
            "/user.slice/kr-daemon-01010101.scope",
            "/user.slice/kr-plugin-host-01010101-0101-0101-0101-010101010101.service",
            "/user.slice/ssh.service",
            "/",
        ] {
            assert!(!is_a_workers_service(other), "{other}");
        }
    }

    /// KR-REQ-07.60: a process in the session's group, or in a group its commands made below it, is
    /// in the worker's service for everything that asks which service a process is in; a group
    /// that is only named like the session's, or sits below another service, is its own.
    #[test]
    fn the_session_group_and_every_group_below_it_belong_to_the_workers_service() {
        let service = "/user.slice/user-1000.slice/user@1000.service/app.slice/kr-worker-01010101-0101-0101-0101-010101010101.service";
        assert_eq!(service_of(service), service);
        assert_eq!(service_of(&format!("{service}/session")), service);
        assert_eq!(
            service_of(&format!("{service}/session/sandbox/inner")),
            service
        );
        for other in [
            format!("{service}/sessions"),
            format!("{service}/other/session"),
            "/user.slice/user-1000.slice/session-3.scope".to_owned(),
            "/user.slice/ssh.service/session".to_owned(),
        ] {
            assert_eq!(service_of(&other), other, "{other}");
        }
    }

    /// KR-REQ-07.60: a group is made once, below a worker's service, and not below any other
    /// group; where the kernel's control file is not there to write the shell into, nothing is
    /// made and nothing is left behind, and the reason is given.
    #[test]
    fn a_group_is_made_only_below_a_workers_service_and_left_nowhere_it_cannot_be_used() {
        let root = tempfile::tempdir().expect("a directory");
        let service = "/user.slice/kr-worker-01010101-0101-0101-0101-010101010101.service";
        assert!(
            SessionGroup::make_below(root.path(), "/user.slice/session-3.scope")
                .expect("a login scope is owed no group, and so no reason")
                .is_none(),
            "a login scope is given no group"
        );
        std::fs::create_dir_all(root.path().join(service.trim_start_matches('/')))
            .expect("the service's directory");
        // A directory has no `cgroup.procs` to write the shell into, which is how a service the
        // worker may not make a group in looks.
        let refused = SessionGroup::make_below(root.path(), service)
            .expect_err("a group that was owed and could not be used says why");
        assert!(refused.contains("cgroup.procs"), "{refused}");
        assert!(
            !root
                .path()
                .join(service.trim_start_matches('/'))
                .join(SESSION_GROUP)
                .exists(),
            "and the group that could not be used is removed"
        );
    }

    /// KR-REQ-07.60: what a group holds is every process listed in it and in the groups below it,
    /// once each. A group below that went while the walk was under way holds nothing and does not
    /// void what the rest listed; the group itself that is not there holds nothing only when its
    /// parent is; and a list that cannot be read is an error and not an empty group.
    #[test]
    fn a_group_holds_what_it_and_the_groups_below_it_list_and_an_unreadable_one_is_an_error() {
        let root = tempfile::tempdir().expect("a directory");
        let group = root.path().join("session");
        let below = group.join("a").join("b");
        std::fs::create_dir_all(&below).expect("groups below the session's");
        std::fs::write(group.join("cgroup.procs"), "30\n10\n").expect("the group's list");
        std::fs::write(group.join("a").join("cgroup.procs"), "20\n").expect("a list");
        std::fs::write(below.join("cgroup.procs"), "10\n40\n").expect("a list");
        // A group below with no list is one the kernel removed between the listing of the
        // directory and the reading of its list.
        std::fs::create_dir(group.join("removed")).expect("a group that went");
        assert_eq!(members(&group).expect("lists"), vec![10, 20, 30, 40]);

        assert_eq!(
            members(&root.path().join("gone")).expect("a group that is gone holds nothing"),
            Vec::<u32>::new()
        );
        assert!(
            members(&root.path().join("no-parent").join("gone")).is_err(),
            "unless its parent is not there either, which says nothing about the group"
        );

        let unreadable = root.path().join("unreadable");
        std::fs::create_dir_all(unreadable.join("cgroup.procs"))
            .expect("a list that is a directory");
        assert!(
            members(&unreadable).is_err(),
            "a list that cannot be read is not an empty group"
        );
    }

    /// KR-REQ-07.60: the walk reads at most [`GROUP_BUDGET`] groups, counting the ones it has
    /// queued: a directory with more groups in it than that is refused before they are all held,
    /// and one with exactly that many is read.
    #[test]
    fn a_tree_of_groups_larger_than_a_session_makes_is_refused_as_it_is_queued() {
        let root = tempfile::tempdir().expect("a directory");
        let group = root.path().join("session");
        std::fs::create_dir(&group).expect("the session's group");
        std::fs::write(group.join("cgroup.procs"), "").expect("a list");
        for number in 0..GROUP_BUDGET - 1 {
            std::fs::create_dir(group.join(format!("below{number}"))).expect("a group");
        }
        assert!(
            members(&group).is_ok(),
            "the group and {} groups below it are the budget",
            GROUP_BUDGET - 1
        );
        std::fs::create_dir(group.join("one-more")).expect("a group");
        let refused = members(&group).expect_err("one group more is refused");
        assert!(refused.contains("more than"), "{refused}");
    }

    /// What the kernel answers when a group's list is read as the group is removed, or when the
    /// group is one of threads, is told from a failure: the first is a group that holds nothing, the
    /// second a list some other group gives.
    #[test]
    fn a_groups_list_that_cannot_be_read_is_told_from_one_that_is_not_there() {
        use rustix::io::Errno;

        let raw = |errno: Errno| Err(std::io::Error::from_raw_os_error(errno.raw_os_error()));
        assert_eq!(list_of(raw(Errno::NODEV)), Ok(List::Gone));
        assert_eq!(list_of(raw(Errno::NOENT)), Ok(List::Gone));
        assert_eq!(list_of(raw(Errno::OPNOTSUPP)), Ok(List::Threaded));
        assert!(list_of(raw(Errno::ACCESS)).is_err());
        assert_eq!(
            list_of(Ok("12\n34\n".to_owned())),
            Ok(List::Read(vec![12, 34]))
        );
        assert!(list_of(Ok("12\nx\n".to_owned())).is_err());
        assert!(
            list_of(Ok("12\n0\n".to_owned())).is_err(),
            "a process this host cannot name leaves the list not whole"
        );
    }

    /// KR-REQ-07.60: the session rests on its control group only when the root shell is shown to be
    /// in it. A shell outside it, or one that has gone so that nothing can say where it was, leaves
    /// the session on the boundary a host without a group has, and the group nothing entered is
    /// removed.
    #[test]
    fn the_session_rests_on_its_group_only_when_the_shell_is_shown_to_be_in_it() {
        let own = std::process::id();
        let identity = kr_ipc::identity::process_lineage(own)
            .expect("this process's lineage")
            .identity;
        let in_a_group = |relative: String| {
            let root = tempfile::tempdir().expect("a directory");
            let path = root.path().join("session");
            std::fs::create_dir(&path).expect("the group's directory");
            // The kernel's group directory holds its control files and is removed with them; this
            // one holds nothing, and the list the shell would write to is a file beside it.
            let procs = std::fs::File::create(root.path().join("cgroup.procs")).expect("its list");
            let group = SessionGroup {
                path: path.clone(),
                relative,
                procs,
            };
            let boundary = crate::ownership::boundary_after_placement(None, &identity, Some(group));
            (root, path, boundary)
        };

        let here = kr_ipc::identity::control_group_of(own).expect("this process's group");
        let (_root, path, boundary) = in_a_group(here);
        assert_eq!(
            boundary,
            crate::ownership::OwnershipBoundary::ControlGroup { path },
            "a shell in the group is held by it"
        );

        let (_root, path, boundary) = in_a_group("/nowhere/this/process/is/session".to_owned());
        assert!(
            !matches!(
                boundary,
                crate::ownership::OwnershipBoundary::ControlGroup { .. }
            ),
            "a shell not shown to be in the group is not held by it: {boundary:?}"
        );
        assert!(!path.exists(), "and the group nothing entered is removed");
    }

    /// KR-REQ-07.60: the end of a group is a write to a file that is opened as it is. On a kernel
    /// without `cgroup.kill` the file is not there and the open says so, where creating it would
    /// answer that it may not be made.
    #[test]
    fn ending_a_group_never_creates_the_file_that_ends_it() {
        let root = tempfile::tempdir().expect("a directory");
        let error = kill(root.path()).expect_err("there is no such file to write");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!root.path().join("cgroup.kill").exists());
    }
}
