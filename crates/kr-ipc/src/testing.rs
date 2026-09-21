//! A disposable host tree for tests.
//!
//! Every host crate needs the same thing from a test: a runtime and state directory that belong to
//! this user, are short enough for a socket address, and disappear afterwards. Building that by
//! hand in each crate invites the two mistakes this type removes — a directory created with the
//! process umask instead of owner-only, and a path long enough that `bind` fails for a reason that
//! has nothing to do with the test.

use std::path::{Path, PathBuf};

use kr_protocol::ids::EnvironmentId;

use crate::paths::{EnvironmentPaths, HostPaths};

/// A host tree that removes itself when it is dropped.
#[derive(Debug)]
pub struct TempHost {
    root: PathBuf,
    paths: HostPaths,
    environment_id: EnvironmentId,
}

impl TempHost {
    /// Creates a fresh tree under the platform's temporary directory.
    ///
    /// # Panics
    ///
    /// Panics when the directories cannot be created, which in a test means the environment is
    /// unusable rather than that the case under test failed.
    #[must_use]
    pub fn create() -> Self {
        // Short on purpose: a Unix socket address is 104 bytes on macOS, and a temporary directory
        // there already spends about half of that.
        let suffix = crate::new_uuid().to_string();
        let root = std::env::temp_dir().join(format!("kr-{}", &suffix[..8]));
        crate::paths::create_private_tree(&root, &root).expect("owner-only temporary root");
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("absolute roots");
        let environment_id = paths.open_environment_id().expect("environment identity");
        paths
            .environment(environment_id)
            .create()
            .expect("environment directories");
        Self {
            root,
            paths,
            environment_id,
        }
    }

    /// Returns the roots.
    #[must_use]
    pub const fn paths(&self) -> &HostPaths {
        &self.paths
    }

    /// Returns the environment identity allocated for this tree.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the directories of this tree's environment.
    #[must_use]
    pub fn environment(&self) -> EnvironmentPaths {
        self.paths.environment(self.environment_id)
    }

    /// Returns the root of the tree.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempHost {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Returns the program that copies a file on this system.
///
/// The usual two places first, then the search path, and a clear refusal when there is none. A
/// system without one cannot place a program this way, and saying so here is better than a failure
/// later that reads like the test's own.
///
/// # Panics
///
/// Panics when this system has no copying program.
#[cfg(unix)]
fn copying_program() -> PathBuf {
    // A name on the search path this user cannot run is not the program being looked for, and
    // stopping at it would hide the one further along that can be run. The operating system is
    // asked, against this process's own credentials: a mode bit on its own says whose permission
    // it is rather than whether it is this process's.
    fn runnable(candidate: &Path) -> bool {
        std::fs::metadata(candidate).is_ok_and(|about| about.is_file())
            && rustix::fs::access(candidate, rustix::fs::Access::EXEC_OK).is_ok()
    }

    for usual in ["/bin/cp", "/usr/bin/cp"] {
        let candidate = Path::new(usual);
        if runnable(candidate) {
            return candidate.to_path_buf();
        }
    }
    let searched = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&searched) {
        let candidate = directory.join("cp");
        if runnable(&candidate) {
            return candidate;
        }
    }
    panic!(
        "a program cannot be placed on this system: it has no copying program that can be run, at \
         /bin/cp, at /usr/bin/cp or anywhere on the search path"
    );
}

/// Places a program where a test can start it, and leaves nothing holding it open for writing.
///
/// A test binary runs its cases on several threads. The moment one thread starts a child process,
/// that child is handed a copy of every descriptor the process had open at that instant, including
/// one another thread has open for writing, and it keeps the copy until its own program takes
/// over. No program can be started while any descriptor anywhere holds it open for writing, so a
/// thread that writes a program and then starts it is racing every other thread in the process:
/// the more the machine has to do, the longer a child takes to reach its own program, and the
/// wider the window in which the write is still visible to it.
///
/// So the bytes are not written by this process at all. Writing them from a process that starts
/// nothing keeps a writing descriptor out of this process's hands altogether, and no child of this
/// test can be handed one it was never given. The placed program is the caller's to start from
/// that moment on, however loaded the machine is and whatever else the test is doing beside it.
///
/// # Panics
///
/// Panics when the program cannot be placed, which in a test means the environment is unusable
/// rather than that the case under test failed.
pub fn place_program(source: &Path, destination: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let copier = copying_program();
        let status = std::process::Command::new(&copier)
            .arg(source)
            .arg(destination)
            .status()
            .unwrap_or_else(|error| {
                panic!(
                    "{} could not be started to place the program at {} at {}: {error}",
                    copier.display(),
                    source.display(),
                    destination.display()
                )
            });
        assert!(
            status.success(),
            "{} did not place the program at {} at {}: {status}",
            copier.display(),
            source.display(),
            destination.display()
        );
        // Owner-only and runnable: a test's own copy of a program is nobody else's business, and
        // the mode a copy is given depends on the person's file-creation mask.
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| {
                panic!(
                    "the program placed at {} could not be made runnable: {error}",
                    destination.display()
                )
            });
    }
    #[cfg(windows)]
    {
        // A program here is held open by the handle that started it rather than by one that wrote
        // it, and a write that has been closed leaves nothing behind for a start to trip over.
        std::fs::copy(source, destination).unwrap_or_else(|error| {
            panic!(
                "the program at {} could not be placed at {}: {error}",
                source.display(),
                destination.display()
            )
        });
    }
}
