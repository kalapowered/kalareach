//! The per-environment singleton lock and the generation it guards.
//!
//! Only one control daemon may own an environment at a time. On Unix the lock is an exclusive
//! advisory lock on a file the environment owns; on Windows it is an exclusive open of that file
//! with no sharing. Either way the operating system releases it when the holder's process ends,
//! however it ends, so a lock file left behind by a crash is not an obstacle: the next daemon
//! takes the lock because nothing holds it.
//!
//! A daemon that gives the environment up while it goes on running releases the lock itself, at
//! the moment its hold on the environment ends. Leaving that to the descriptor going out of scope
//! would put it later: a process the daemon started while the lock was held holds a descriptor
//! onto the same open file until its own program takes over, and the lock lives on the open file.
//!
//! Everything the environment owns is taken under this lock: the persistent identity, the
//! generation and the directory of workers. Creating the identity outside it would let two daemons
//! starting together both decide they were the first.
//!
//! Taking the lock is the moment the generation advances. A daemon that has lost the lock cannot
//! present the current generation to a worker, because the number it holds is already behind, and
//! a worker refuses a generation below the one it has accepted.

use std::fs::File;
use std::path::{Path, PathBuf};

use kr_protocol::ids::{ControllerGeneration, EnvironmentId};

use crate::error::{ControllerError, Result};
use crate::registry::Registry;

/// The lock one control daemon holds for its environment.
#[derive(Debug)]
pub struct SingletonLock {
    file: File,
    path: PathBuf,
    environment_id: EnvironmentId,
    generation: ControllerGeneration,
}

impl SingletonLock {
    /// Takes the environment's lock and advances its generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::AlreadyRunning`] when another daemon holds the environment, and
    /// a registry failure when the generation cannot be advanced.
    pub fn acquire(path: &Path, environment_id: EnvironmentId) -> Result<Self> {
        let file = Self::open(path, environment_id)?;
        Self::lock(&file, environment_id)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            environment_id,
            generation: ControllerGeneration::new(0),
        })
    }

    /// Advances the environment's persistent generation under this lock.
    ///
    /// The registry is opened, created and migrated under the lock as well, so two first starts
    /// cannot both run the schema creation.
    ///
    /// # Errors
    ///
    /// Returns a registry failure when the generation cannot be advanced.
    pub fn advance(&mut self, registry: &mut Registry) -> Result<ControllerGeneration> {
        if registry.environment_id() != self.environment_id {
            return Err(ControllerError::registry(
                "this registry belongs to another environment",
            ));
        }
        // The generation advances while the lock is held, before anything reconnects to a worker.
        self.generation = registry.advance_generation()?;
        Ok(self.generation)
    }

    /// Returns the generation this daemon speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
    }

    /// Returns the environment this lock covers.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn open(path: &Path, _environment_id: EnvironmentId) -> Result<File> {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|error| {
                ControllerError::Ipc(kr_ipc::IpcError::io("open the singleton lock", path, error))
            })
    }

    #[cfg(unix)]
    fn lock(file: &File, environment_id: EnvironmentId) -> Result<()> {
        use rustix::fs::{FlockOperation, flock};

        flock(file, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            ControllerError::AlreadyRunning {
                environment: environment_id.to_string(),
            }
        })
    }

    #[cfg(windows)]
    fn open(path: &Path, environment_id: EnvironmentId) -> Result<File> {
        use std::os::windows::fs::OpenOptionsExt as _;

        // Windows has no advisory lock on a file the way `flock` does. What it has is the share
        // mode: opening with no sharing bits set grants this handle exclusive access, and every
        // later open of the same path fails with a sharing violation until the handle is closed.
        // The operating system closes it when the process ends, however it ends, so a lock file
        // left behind by a crash is not an obstacle either.
        const NO_SHARING: u32 = 0;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .share_mode(NO_SHARING)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::PermissionDenied => ControllerError::AlreadyRunning {
                    environment: environment_id.to_string(),
                },
                _ => ControllerError::Ipc(kr_ipc::IpcError::io(
                    "open the singleton lock",
                    path,
                    error,
                )),
            })
    }

    #[cfg(windows)]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the open itself is the lock on this platform; the signature is shared"
    )]
    const fn lock(_file: &File, _environment_id: EnvironmentId) -> Result<()> {
        // Exclusivity was obtained by the open above. There is nothing further to take.
        Ok(())
    }

    #[cfg(unix)]
    fn release(file: &File) {
        use rustix::fs::{FlockOperation, flock};

        // The lock belongs to the open file rather than to this descriptor. A process this daemon
        // started while it held the lock was given a second descriptor onto that same open file,
        // and one of those stays there until the started program takes over, so closing this
        // descriptor is not on its own the end of the lock. Releasing it says so outright: the
        // lock on the open file ends here, whatever else still names it, and the next daemon takes
        // the environment the moment this one gives it up.
        let _ = flock(file, FlockOperation::Unlock);
    }

    #[cfg(windows)]
    const fn release(_file: &File) {
        // Exclusivity here is the open itself, which the close below ends. A started program is
        // given no handle it was not passed, so nothing else holds this one.
    }
}

impl Drop for SingletonLock {
    fn drop(&mut self) {
        Self::release(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generation_advances_each_time_the_lock_is_taken() {
        let host = kr_ipc::testing::TempHost::create();
        let paths = host.environment();
        let mut registry = Registry::open(paths.registry_database(), host.environment_id())
            .expect("opens the registry");
        let mut first = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id())
            .expect("takes the lock");
        assert_eq!(first.advance(&mut registry).expect("advances").get(), 1);
        drop(first);
        let mut second = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id())
            .expect("takes the lock again");
        assert_eq!(second.advance(&mut registry).expect("advances").get(), 2);
    }

    /// The environment is free the moment its holder lets go, whatever else still names the file.
    ///
    /// A process a daemon starts while it holds the lock is given a descriptor onto the same open
    /// file, and keeps it for as long as it runs. The lock lives on that open file, so a holder
    /// that only let its own descriptor go would leave the environment locked by a process that
    /// has nothing to do with it. Here the started process is given exactly such a descriptor, so
    /// what the next acquire reports is the release itself and not the timing of a close.
    #[cfg(unix)]
    #[test]
    fn the_environment_is_free_once_its_holder_lets_go_though_a_started_process_still_names_it() {
        let host = kr_ipc::testing::TempHost::create();
        let paths = host.environment();
        let held = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id())
            .expect("takes the lock");
        let inherited = held
            .file
            .try_clone()
            .expect("a second descriptor onto the locked file");
        let mut started = std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdin(std::process::Stdio::from(inherited))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("starts a process while the lock is held");
        drop(held);
        let taken = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id());
        // Ended before the verdict, so a refusal leaves nothing running behind it.
        let _ = started.kill();
        let _ = started.wait();
        taken.expect("the environment is free once its holder has let go");
    }

    #[cfg(unix)]
    #[test]
    fn a_second_daemon_is_refused_while_the_first_holds_the_environment() {
        let host = kr_ipc::testing::TempHost::create();
        let paths = host.environment();
        let _held = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id())
            .expect("takes the lock");
        let error = SingletonLock::acquire(&paths.singleton_lock(), host.environment_id())
            .expect_err("refuses the second");
        assert!(matches!(error, ControllerError::AlreadyRunning { .. }));
    }
}
