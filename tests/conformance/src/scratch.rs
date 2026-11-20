//! The run's scratch directory: one directory for the whole run, under the directory the run keeps
//! its own files in and outside the evidence directory, that a step reaches as `{scratch}` and
//! that is removed when the run ends.
//!
//! What a step writes there is not evidence. A set-up step that makes a file for a later step
//! leaves it here, and the result keeps nothing of it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many scratch directories this process has named, so that two made in one clock tick differ.
static NAMED: AtomicU64 = AtomicU64::new(0);

/// A scratch directory that exists, and is removed with everything in it when this is dropped.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

/// The path a scratch directory made under `base` has, which is not made yet. `base` is resolved
/// when it can be, so the path is the one the directory has once it is made.
#[must_use]
pub fn path_in(base: &Path) -> PathBuf {
    let base = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let count = NAMED.fetch_add(1, Ordering::Relaxed);
    base.join(format!(
        "kr-conformance-scratch-{stamp}-{}-{count}",
        std::process::id()
    ))
}

impl Scratch {
    /// Makes the directory at `path`, which [`path_in`] gave, and which may not lie inside
    /// `evidence`.
    ///
    /// # Errors
    ///
    /// Says why the directory cannot be made, or that it would lie in the evidence directory.
    pub fn make(path: PathBuf, evidence: &Path) -> Result<Self, String> {
        let evidence = evidence
            .canonicalize()
            .unwrap_or_else(|_| evidence.to_path_buf());
        if path.starts_with(&evidence) {
            return Err(format!(
                "the scratch directory {} would lie inside the evidence directory {}: the \
                 directory the run keeps its files in may not",
                path.display(),
                evidence.display()
            ));
        }
        std::fs::create_dir(&path)
            .map_err(|error| format!("{} could not be made: {error}", path.display()))?;
        Ok(Self { path })
    }

    /// The directory's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A directory that cannot be removed is left where it is: the run's result is made.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_directory_is_new_for_each_name_and_gone_when_it_is_dropped() {
        let base = tempfile::tempdir().expect("a directory");
        let evidence = tempfile::tempdir().expect("a directory");
        let first = path_in(base.path());
        let second = path_in(base.path());
        assert_ne!(first, second);
        let made = Scratch::make(first.clone(), evidence.path()).expect("a scratch directory");
        std::fs::write(made.path().join("file"), "x").expect("a file");
        assert!(first.is_dir());
        drop(made);
        assert!(!first.exists());
    }

    #[test]
    fn a_scratch_directory_is_not_made_over_a_directory_that_exists_and_that_stays() {
        let base = tempfile::tempdir().expect("a directory");
        let evidence = tempfile::tempdir().expect("a directory");
        let held = path_in(base.path());
        std::fs::create_dir(&held).expect("a directory that is there already");
        std::fs::write(held.join("file"), "x").expect("a file");
        let error = Scratch::make(held.clone(), evidence.path()).expect_err("refused");
        assert!(error.contains("could not be made"), "{error}");
        assert!(held.join("file").is_file());
    }

    #[test]
    fn a_scratch_directory_inside_the_evidence_directory_is_refused_and_not_made() {
        let evidence = tempfile::tempdir().expect("a directory");
        let path = path_in(evidence.path());
        let error = Scratch::make(path.clone(), evidence.path()).expect_err("refused");
        assert!(error.contains("evidence directory"), "{error}");
        assert!(!path.exists());
    }
}
