//! The file that keeps the newest accepted copy of the release matrix between runs.
//!
//! `release-matrix.json` has no version and nothing else reads it: it is a re-fetchable copy of a
//! public document, verified again against the pinned key every time it is loaded. A file that
//! cannot be read, does not parse, lacks a member or fails verification is no copy, and the next
//! accepted read writes it again; a member this build does not know is ignored. Because it has no
//! version and no manifest lists it, it is a leaf that the update check never reads, so a damaged
//! file can never refuse an update or a rollback.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use kr_client::services::matrix::{MAX_ANSWER_BYTES, Saved};

/// The file's name in the environment's state directory.
pub const FILE_NAME: &str = "release-matrix.json";

/// The most the file is read as: the published reply is bounded and is kept as a JSON string, which
/// writes a byte as six at most (`\u0001`), and the rest is a few members.
const MAX_FILE_BYTES: u64 = 6 * MAX_ANSWER_BYTES + 4 * 1024;

/// Where the copy is kept.
#[derive(Debug, Clone)]
pub struct File {
    path: PathBuf,
}

impl File {
    /// The file in `state_dir`.
    #[must_use]
    pub fn in_dir(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(FILE_NAME),
        }
    }

    /// The copy an earlier run kept, or nothing when the file is absent, too large, unreadable, not
    /// JSON, or lacks a member. Whether the copy verifies is the loader's to decide.
    #[must_use]
    pub fn load(&self) -> Option<Saved> {
        let file = std::fs::File::open(&self.path).ok()?;
        if file.metadata().ok()?.len() > MAX_FILE_BYTES {
            return None;
        }
        serde_json::from_reader(std::io::BufReader::new(file)).ok()
    }

    /// Keeps `saved`, through a temporary name in the same directory and a rename, so that a failure
    /// part way through cannot truncate the copy that was there.
    ///
    /// # Errors
    ///
    /// Returns the failure of the write or the rename. The temporary file is removed.
    pub fn write(&self, saved: &Saved) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(saved).map_err(std::io::Error::other)?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temporary = parent.join(format!(".{FILE_NAME}.{}.tmp", kr_ipc::new_uuid()));
        let written = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            kr_flush::retry_while_held(|| std::fs::rename(&temporary, &self.path))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        written
    }
}
