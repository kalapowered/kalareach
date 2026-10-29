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

/// The most groups a listing walks below the session's, and how deep.
///
/// A person's own commands can make groups below the session's, since the group is theirs to make
/// groups in, and a listing that followed a tree without a bound would be the one a hostile
/// session made it follow for ever.
#[cfg(target_os = "linux")]
const MOST_GROUPS: usize = 4096;
#[cfg(target_os = "linux")]
const MOST_DEPTH: usize = 16;

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

impl SessionGroup {
    /// Makes the group below this worker's own service, when the worker runs in one it may make
    /// groups below.
    #[must_use]
    pub fn make() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::make_below(
                Path::new(CONTROL_GROUP_ROOT),
                &crate::ownership::own_cgroup()?,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Makes the group below the service `service`, a path as `/proc/<pid>/cgroup` names it,
    /// under the control group file system mounted at `root`.
    #[cfg(target_os = "linux")]
    fn make_below(root: &Path, service: &str) -> Option<Self> {
        if !is_a_workers_service(service) {
            return None;
        }
        let relative = format!("{}/{SESSION_GROUP}", service.trim_end_matches('/'));
        let path = root.join(relative.trim_start_matches('/'));
        // A group that is not new is not this session's: a worker makes it once, for one session.
        std::fs::create_dir(&path).ok()?;
        let procs = std::fs::OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"));
        match procs {
            Ok(procs) => Some(Self {
                path,
                relative,
                procs,
            }),
            Err(_) => {
                let _ = std::fs::remove_dir(&path);
                None
            }
        }
    }

    /// Makes the group and has the terminal's next start place the root shell in it, or does
    /// neither where there is no group to make.
    #[must_use]
    pub fn prepare(terminal: &mut crate::pty::Pty) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let group = Self::make()?;
            match group.procs() {
                Ok(procs) => {
                    terminal.place_the_shell_in(procs);
                    Some(group)
                }
                Err(_) => {
                    group.discard();
                    None
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = terminal;
            None
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

    /// Where the process is relative to this group: in it now, outside it now, or nowhere because
    /// the process has gone and can no longer be asked.
    #[must_use]
    pub fn placement(&self, pid: u32) -> Option<bool> {
        kr_ipc::identity::control_group_of(pid).map(|_| in_group(pid, &self.relative))
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

/// Every process in the group and in the groups below it.
///
/// The kernel writes each `cgroup.procs` in one reading and lists a process in the group it is in
/// now; one that moves while this walks may be listed twice, and a list is only a set of hints.
/// A group that cannot be read is an error, and not an empty group.
///
/// # Errors
///
/// Returns the error of the first listing that failed, or of a tree that is larger than any session
/// makes.
#[cfg(target_os = "linux")]
pub fn members(path: &Path) -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    let mut groups = vec![(path.to_path_buf(), 0_usize)];
    let mut walked = 0_usize;
    while let Some((group, depth)) = groups.pop() {
        walked += 1;
        if walked > MOST_GROUPS || depth > MOST_DEPTH {
            return Err(std::io::Error::other(
                "the session's control group has more groups below it than a session makes",
            ));
        }
        for line in std::fs::read_to_string(group.join("cgroup.procs"))?.lines() {
            if let Ok(pid) = line.trim().parse::<u32>() {
                pids.push(pid);
            }
        }
        for entry in std::fs::read_dir(&group)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                groups.push((entry.path(), depth + 1));
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

/// Every process in the group, or none where the group is gone.
///
/// The kernel removes a control group only when it is empty, so a group that is not there holds
/// nothing. Any other failure to list it is an error, and not an empty group.
///
/// # Errors
///
/// Returns the error of the first listing that failed, other than the group's not being there.
#[cfg(target_os = "linux")]
pub fn members_or_none_if_gone(path: &Path) -> std::io::Result<Vec<u32>> {
    match members(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        other => other,
    }
}

/// Every process in the group: not possible off Linux, where no such group is made.
#[cfg(not(target_os = "linux"))]
pub fn members(_path: &Path) -> std::io::Result<Vec<u32>> {
    Err(std::io::Error::other(
        "this platform makes no session group",
    ))
}

/// Ends every process in the group and in the groups below it, at once.
///
/// `cgroup.kill` does it in one write, including a process that is starting while it is written;
/// it is the kernel's from version 5.14.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::NotFound`] where the kernel has no `cgroup.kill`, and the
/// operating system's error where the write was refused.
#[cfg(target_os = "linux")]
pub fn kill(path: &Path) -> std::io::Result<()> {
    std::fs::write(path.join("cgroup.kill"), b"1")
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

    /// KR-REQ-07.60: a group is made once, below a worker's service, and not below any other
    /// group; where the kernel's control file is not there to write the shell into, nothing is
    /// made and nothing is left behind.
    #[test]
    fn a_group_is_made_only_below_a_workers_service_and_left_nowhere_it_cannot_be_used() {
        let root = tempfile::tempdir().expect("a directory");
        let service = "/user.slice/kr-worker-01010101-0101-0101-0101-010101010101.service";
        assert!(
            SessionGroup::make_below(root.path(), "/user.slice/session-3.scope").is_none(),
            "a login scope is given no group"
        );
        std::fs::create_dir_all(root.path().join(service.trim_start_matches('/')))
            .expect("the service's directory");
        // A directory has no `cgroup.procs` to write the shell into, which is how a service the
        // worker may not make a group in looks.
        assert!(SessionGroup::make_below(root.path(), service).is_none());
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
    /// once each; a group that is gone holds nothing, and one that cannot be read is an error and
    /// not an empty group.
    #[test]
    fn a_group_holds_what_it_and_the_groups_below_it_list_and_an_unreadable_one_is_an_error() {
        let root = tempfile::tempdir().expect("a directory");
        let group = root.path().join("session");
        let below = group.join("a").join("b");
        std::fs::create_dir_all(&below).expect("groups below the session's");
        std::fs::write(group.join("cgroup.procs"), "30\n10\n").expect("the group's list");
        std::fs::write(group.join("a").join("cgroup.procs"), "20\n").expect("a list");
        std::fs::write(below.join("cgroup.procs"), "10\n40\n").expect("a list");
        assert_eq!(members(&group).expect("lists"), vec![10, 20, 30, 40]);

        let gone = root.path().join("gone");
        assert_eq!(
            members_or_none_if_gone(&gone).expect("a group that is gone holds nothing"),
            Vec::<u32>::new()
        );
        assert!(
            members(&gone).is_err(),
            "and is not listed as if it were there"
        );

        let unreadable = root.path().join("unreadable");
        std::fs::create_dir_all(unreadable.join("cgroup.procs"))
            .expect("a list that is a directory");
        assert!(
            members_or_none_if_gone(&unreadable).is_err(),
            "a list that cannot be read is not an empty group"
        );
    }

    /// KR-REQ-07.60: a tree of groups larger than any session makes is refused, not followed.
    #[test]
    fn a_tree_of_groups_larger_than_a_session_makes_is_not_followed() {
        let root = tempfile::tempdir().expect("a directory");
        let mut deep = root.path().join("session");
        std::fs::create_dir_all(&deep).expect("the session's group");
        std::fs::write(deep.join("cgroup.procs"), "").expect("a list");
        for level in 0..=MOST_DEPTH + 1 {
            deep = deep.join(format!("g{level}"));
            std::fs::create_dir(&deep).expect("a group below");
            std::fs::write(deep.join("cgroup.procs"), "").expect("a list");
        }
        assert!(members(&root.path().join("session")).is_err());
    }
}
