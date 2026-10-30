//! What a create needs of the host before anything is spawned.
//!
//! Section 7 makes admission "constrained by available PTY/process/storage resources" and says to
//! reject before spawn with `RESOURCE_UNAVAILABLE`. A create that is accepted on a host that cannot
//! hold it does not fail cleanly: it starts a worker, the worker fails on its first write or cannot
//! open its terminal, and the person sees a session that closed itself a moment after it began. So
//! the three resources a session cannot start without are measured first, and a create that finds
//! one short is refused, naming it, before a reservation is recorded.
//!
//! The limits are constants and not configuration, because a limit the owner could lower would be a
//! setting that lets a create through on a host that cannot hold it. They do not narrow the session
//! number (`session_limit`): that is the most sessions an environment admits, and these are what one
//! more session needs on this host at this moment.
//!
//! Each measurement is a function the daemon holds in [`HostResources`], so a test can stand in for
//! a resource that cannot be made scarce without harm to the machine it runs on. The measurements
//! this host makes itself are [`HostResources::measured`]. A measurement that cannot be made says
//! nothing about the resource, and the create goes on: only a reading that is short refuses, and
//! the one exception is the terminal, where the failure to open one is itself the reading. Storage
//! is read on every platform; terminals and processes are read where the platform has them to
//! read, and not on Windows.

use std::path::Path;

/// The free space the state directory's filesystem must have for a create to be accepted.
///
/// A session writes its retained history, its journal and the worker's own record under the state
/// directory from its first moments, and closing it has to write the final status there. A
/// filesystem with less than this left accepts the create and then fails the worker's first write,
/// so the session closes itself. 64 MiB is several times what a session writes before its first
/// prompt, and small enough that no healthy host is ever near it.
pub(crate) const MINIMUM_FREE_STORAGE_BYTES: u64 = 64 * 1024 * 1024;

/// The number of processes the account must still be allowed to start for a create to be accepted.
///
/// A session starts a worker and a root shell at once, and the shell's startup files, the person's
/// first commands and an agent's tools start more. A create accepted with the account at its limit
/// would have the worker's launch fail partway. 64 covers that start with room, and is a fraction of
/// any limit a healthy account has.
pub(crate) const MINIMUM_PROCESS_HEADROOM: u64 = 64;

/// A resource a create found short.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Shortfall {
    /// Which resource: `storage`, `terminals` or `processes`.
    pub(crate) resource: &'static str,
    /// What was found and what a create needs.
    pub(crate) detail: String,
}

/// How this host reads the resources a create needs.
#[derive(Clone, Copy)]
pub(crate) struct HostResources {
    /// The bytes free to this account on the filesystem that holds a directory, when it can be said.
    pub(crate) free_storage: fn(&Path) -> Option<u64>,
    /// Opens a pseudo-terminal and closes it again.
    pub(crate) open_terminal: fn() -> std::io::Result<()>,
    /// How many more processes this account may start, or `None` when it has no limit.
    pub(crate) process_headroom: fn() -> std::io::Result<Option<u64>>,
    /// The free storage a create needs.
    pub(crate) minimum_free_storage: u64,
    /// The process headroom a create needs.
    pub(crate) minimum_process_headroom: u64,
}

impl HostResources {
    /// The measurements this host makes of itself, against the limits above.
    #[must_use]
    pub(crate) const fn measured() -> Self {
        Self {
            free_storage: kr_describe::resource::platform::free_space,
            open_terminal: measure_terminal,
            process_headroom: measure_process_headroom,
            minimum_free_storage: MINIMUM_FREE_STORAGE_BYTES,
            minimum_process_headroom: MINIMUM_PROCESS_HEADROOM,
        }
    }

    /// Finds the first resource a create would be short of, or none.
    ///
    /// This does file-system and process-table work, so it is called on a thread that may block.
    pub(crate) fn shortfall(&self, state_directory: &Path) -> Option<Shortfall> {
        if let Some(free) = (self.free_storage)(state_directory)
            && free < self.minimum_free_storage
        {
            return Some(Shortfall {
                resource: "storage",
                detail: format!(
                    "the state directory's filesystem has {free} bytes free and a session needs \
                     at least {}",
                    self.minimum_free_storage
                ),
            });
        }
        if let Err(error) = (self.open_terminal)() {
            return Some(Shortfall {
                resource: "terminals",
                detail: format!("this host cannot open another pseudo-terminal: {error}"),
            });
        }
        if let Ok(Some(headroom)) = (self.process_headroom)()
            && headroom < self.minimum_process_headroom
        {
            return Some(Shortfall {
                resource: "processes",
                detail: format!(
                    "this account may start {headroom} more processes and a session needs at least {}",
                    self.minimum_process_headroom
                ),
            });
        }
        None
    }
}

/// Opens a pseudo-terminal pair and closes it again.
///
/// The worker opens a pair for the root shell: the master, then the slave once the master is
/// granted and unlocked. Whether this host can do all of it is the reading: a host out of
/// terminals, or of descriptors to open them with, says so here and not in a worker that has
/// already been started.
#[cfg(unix)]
fn measure_terminal() -> std::io::Result<()> {
    open_pair().map(drop)
}

/// A pseudo-terminal pair, the master first, with both ends closed on exec.
///
/// Closed on exec, as the worker's own are: this daemon starts programs from other threads, and
/// one that started while a pair was open would hold the terminal for its whole life.
#[cfg(unix)]
fn open_pair() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    #[cfg(target_os = "linux")]
    let master = rustix::pty::openpt(
        rustix::pty::OpenptFlags::RDWR
            | rustix::pty::OpenptFlags::NOCTTY
            | rustix::pty::OpenptFlags::CLOEXEC,
    )?;
    // `posix_openpt` takes no such flag here, and it opens this file.
    #[cfg(not(target_os = "linux"))]
    let master = rustix::fs::open(
        "/dev/ptmx",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    rustix::pty::grantpt(&master)?;
    rustix::pty::unlockpt(&master)?;
    let name = rustix::pty::ptsname(&master, Vec::new())?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    Ok((master, slave))
}

/// A Windows worker's console is not measured here.
#[cfg(not(unix))]
fn measure_terminal() -> std::io::Result<()> {
    Ok(())
}

/// How many more processes this account may start under its own limit.
///
/// The limit is this daemon's own soft `RLIMIT_NPROC`, counted against every task the account
/// holds. An account with no limit has no headroom to measure, and says so with `None`; so does the
/// superuser, whom the kernel does not hold to the limit.
#[cfg(unix)]
fn measure_process_headroom() -> std::io::Result<Option<u64>> {
    if rustix::process::getuid().is_root() {
        return Ok(None);
    }
    let Some(limit) = rustix::process::getrlimit(rustix::process::Resource::Nproc).current else {
        return Ok(None);
    };
    let tasks = kr_ipc::identity::account_tasks(rustix::process::getuid().as_raw())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(Some(limit.saturating_sub(tasks)))
}

/// Windows has no per-account process limit.
#[cfg(not(unix))]
fn measure_process_headroom() -> std::io::Result<Option<u64>> {
    Ok(None)
}

#[cfg(test)]
impl super::Controller {
    /// Stands a reading in for what this daemon measures of its host.
    pub(super) fn use_host_resources(&self, resources: HostResources) {
        *self
            .host_resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resources;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measurements this host makes of itself read this machine: a directory with free
    /// space, a terminal that opens, and a headroom that is a number or no limit. This is the
    /// control for the cases that stand a scarce reading in for each: a create on a healthy
    /// host is not refused.
    #[test]
    fn a_healthy_host_is_short_of_nothing() {
        let directory = std::env::temp_dir();
        let host = HostResources::measured();
        assert_eq!(
            (host.free_storage)(&directory).map(|free| free > 0),
            Some(true)
        );
        assert!((host.open_terminal)().is_ok());
        assert!((host.process_headroom)().is_ok());
        assert_eq!(host.shortfall(&directory), None);
    }

    /// The terminal the probe opens is a pair: the master and a slave that is a terminal, both
    /// closed on exec. The probe is the pair's opening, so a host that can open a master and not
    /// the slave it grants is short of terminals.
    #[cfg(unix)]
    #[test]
    fn the_terminal_the_probe_opens_is_a_pair_closed_on_exec() {
        use std::os::fd::AsFd as _;

        let (master, slave) = open_pair().expect("this host opens a terminal pair");
        for end in [&master, &slave] {
            let flags = rustix::io::fcntl_getfd(end).expect("reads the descriptor's flags");
            assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "{end:?}");
        }
        assert!(
            rustix::termios::isatty(slave.as_fd()),
            "the slave end is a terminal"
        );
    }

    /// The filesystem's own reading, against a limit no filesystem meets, names storage. The
    /// create-level case stands a reading in, so that it runs where the reading cannot be made;
    /// this is the reading itself, and `a_healthy_host_is_short_of_nothing` is the control.
    #[cfg(unix)]
    #[test]
    fn the_filesystems_own_reading_is_short_of_a_limit_no_filesystem_meets() {
        let directory = std::env::temp_dir();
        let mut host = HostResources::measured();
        host.minimum_free_storage = u64::MAX;
        assert_eq!(
            host.shortfall(&directory).map(|short| short.resource),
            Some("storage")
        );
    }
}
