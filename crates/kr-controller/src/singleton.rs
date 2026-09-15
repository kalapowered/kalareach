//! The per-environment singleton lock and the generation it guards.
//!
//! Only one control daemon may own an environment at a time. On Unix the lock is an exclusive
//! advisory lock on a file the environment owns; on Windows it is an exclusive open of that file
//! with no sharing. Either way the operating system releases it when the holder's process ends,
//! however it ends, so a lock file left behind by a crash is not an obstacle: the next daemon
//! takes the lock because nothing holds it.
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
    _file: File,
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
    pub fn acquire(path: &Path, registry: &mut Registry) -> Result<Self> {
        let file = Self::open(path, registry.environment_id())?;
        Self::lock(&file, registry.environment_id())?;
        // The generation advances while the lock is held, before anything reconnects to a worker.
        let generation = registry.advance_generation()?;
        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
            environment_id: registry.environment_id(),
            generation,
        })
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
        let first =
            SingletonLock::acquire(&paths.singleton_lock(), &mut registry).expect("takes the lock");
        assert_eq!(first.generation().get(), 1);
        drop(first);
        let second = SingletonLock::acquire(&paths.singleton_lock(), &mut registry)
            .expect("takes the lock again");
        assert_eq!(second.generation().get(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_second_daemon_is_refused_while_the_first_holds_the_environment() {
        let host = kr_ipc::testing::TempHost::create();
        let paths = host.environment();
        let mut registry = Registry::open(paths.registry_database(), host.environment_id())
            .expect("opens the registry");
        let _held =
            SingletonLock::acquire(&paths.singleton_lock(), &mut registry).expect("takes the lock");
        let error = SingletonLock::acquire(&paths.singleton_lock(), &mut registry)
            .expect_err("refuses the second");
        assert!(matches!(error, ControllerError::AlreadyRunning { .. }));
    }
}
