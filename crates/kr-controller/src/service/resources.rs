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
//! the one exception is the terminal, where the failure to open one is itself the reading.

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
    /// The bytes free to this account on the filesystem that holds a directory.
    pub(crate) free_storage: fn(&Path) -> std::io::Result<u64>,
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
            free_storage: measure_free_storage,
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
        if let Ok(free) = (self.free_storage)(state_directory)
            && free < self.minimum_free_storage
        {
            return Some(Shortfall {
                resource: "storage",
                detail: format!(
                    "{} has {free} bytes free and a session needs at least {}",
                    state_directory.display(),
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

/// The bytes free to this account on the filesystem that holds `directory`.
#[cfg(unix)]
fn measure_free_storage(directory: &Path) -> std::io::Result<u64> {
    let stat = rustix::fs::statvfs(directory)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// Windows is not measured here: a create goes on, as it does for any measurement that cannot be made.
#[cfg(not(unix))]
fn measure_free_storage(_directory: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
}

/// Opens a pseudo-terminal and closes it again.
///
/// The worker opens one for the root shell. Whether this host can is the reading: a host out of
/// terminals, or of descriptors to open one with, says so here and not in a worker that has already
/// been started.
#[cfg(unix)]
fn measure_terminal() -> std::io::Result<()> {
    let master =
        rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)?;
    drop(master);
    Ok(())
}

/// A Windows worker's console is not measured here.
#[cfg(not(unix))]
fn measure_terminal() -> std::io::Result<()> {
    Ok(())
}

/// How many more processes this account may start under its own limit.
///
/// The limit is the soft `RLIMIT_NPROC`, counted against every task the account holds. An account
/// with no limit has no headroom to measure, and says so with `None`.
#[cfg(unix)]
fn measure_process_headroom() -> std::io::Result<Option<u64>> {
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
            (host.free_storage)(&directory).map(|free| free > 0).ok(),
            Some(true)
        );
        assert!((host.open_terminal)().is_ok());
        assert!((host.process_headroom)().is_ok());
        assert_eq!(host.shortfall(&directory), None);
    }
}
