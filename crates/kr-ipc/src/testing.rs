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
        crate::paths::create_owner_only_directory(&root).expect("owner-only temporary root");
        let paths = HostPaths::new(root.join("r"), root.join("s"));
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
