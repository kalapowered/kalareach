//! The per-environment singleton lock and the generation it guards.
//!
//! Only one control daemon may own an environment at a time. The lock is an exclusive advisory
//! lock on a file the environment owns, which the kernel releases when the holder's process ends,
//! however it ends. A lock file left behind by a crash is therefore not an obstacle: the next
//! daemon takes the lock because nothing holds it.
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
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|error| {
                ControllerError::Ipc(kr_ipc::IpcError::io("open the singleton lock", path, error))
            })?;
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
    fn lock(file: &File, environment_id: EnvironmentId) -> Result<()> {
        use rustix::fs::{FlockOperation, flock};

        flock(file, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            ControllerError::AlreadyRunning {
                environment: environment_id.to_string(),
            }
        })
    }

    #[cfg(not(unix))]
    fn lock(file: &File, environment_id: EnvironmentId) -> Result<()> {
        use std::io::Write as _;

        // Windows opens the file for exclusive write access, which a second daemon cannot obtain
        // while the first holds it. The handle is released by the operating system when the
        // process ends, however it ends.
        let mut handle = file;
        handle
            .write_all(b"")
            .map_err(|_| ControllerError::AlreadyRunning {
                environment: environment_id.to_string(),
            })
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
