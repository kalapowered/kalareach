//! The report's own program, copied to where no step builds.
//!
//! Cargo runs every test binary through the report's program, for each listing and each run, and
//! the steps that build the workspace link that same program again. A program linked on a runner
//! whose disk fails to write a page can be left empty or cut short, so the report would then fail on
//! its own runner and not on a test. The report copies its program into a directory of its own,
//! compares the bytes, and hands Cargo the copy.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many bytes are read or written at a time.
const CHUNK: usize = 1 << 16;

/// How many directories this process has named, so that two copies made in one clock tick differ.
static MADE: AtomicU64 = AtomicU64::new(0);

/// Copies `original` into a new directory made under `base`, and returns the copy's path.
///
/// `outside` holds every directory a step builds in; `base` may not lie inside any of them. The
/// copy's path has no space in it, because Cargo's runner is one word. A copy that cannot be made,
/// or whose bytes differ from the original's, is an error: the report does not fall back to the
/// original.
///
/// # Errors
///
/// Says why the copy could not be made, or why it is not equal to the original.
pub fn private_copy(original: &Path, base: &Path, outside: &[PathBuf]) -> Result<PathBuf, String> {
    private_copy_with(original, base, outside, &copy_bytes)
}

fn private_copy_with(
    original: &Path,
    base: &Path,
    outside: &[PathBuf],
    copier: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> Result<PathBuf, String> {
    let name = original
        .file_name()
        .ok_or_else(|| format!("{} names no file to copy", original.display()))?;
    let base = base
        .canonicalize()
        .map_err(|error| format!("{} cannot be read: {error}", base.display()))?;
    for directory in outside {
        let directory = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.clone());
        if base.starts_with(&directory) {
            return Err(format!(
                "{} lies inside {}, where a step builds, so the report's program is not copied there",
                base.display(),
                directory.display()
            ));
        }
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let count = MADE.fetch_add(1, Ordering::Relaxed);
    let directory = base.join(format!(
        "kr-conformance-runner-{}-{stamp}-{count}",
        std::process::id()
    ));
    let copy = directory.join(name);
    if copy
        .to_str()
        .is_none_or(|path| path.chars().any(char::is_whitespace))
    {
        return Err(format!(
            "{} cannot be Cargo's runner: its path has a space in it",
            copy.display()
        ));
    }
    std::fs::create_dir(&directory)
        .map_err(|error| format!("{} could not be made: {error}", directory.display()))?;
    copier(original, &copy).map_err(|error| {
        format!(
            "{} could not be copied to {}: {error}",
            original.display(),
            copy.display()
        )
    })?;
    match first_difference(original, &copy) {
        Ok(None) => Ok(copy),
        Ok(Some(offset)) => Err(format!(
            "the copy {} of {} differs from it at byte {offset}",
            copy.display(),
            original.display()
        )),
        Err(error) => Err(format!(
            "{} and its copy {} could not be compared: {error}",
            original.display(),
            copy.display()
        )),
    }
}

/// Writes the bytes of `from` to a new file `to`, with the same permissions, and has them written
/// out before it returns.
fn copy_bytes(from: &Path, to: &Path) -> io::Result<()> {
    let mut source = File::open(from)?;
    let permissions = source.metadata()?.permissions();
    let mut target = OpenOptions::new().write(true).create_new(true).open(to)?;
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        target.write_all(&buffer[..read])?;
    }
    target.sync_all()?;
    drop(target);
    std::fs::set_permissions(to, permissions)
}

/// Reads into `buffer` until it is full or the file ends, and returns how many bytes it holds.
fn fill(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut held = 0;
    while held < buffer.len() {
        match file.read(&mut buffer[held..]) {
            Ok(0) => break,
            Ok(read) => held += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(held)
}

/// The offset of the first byte at which two files differ, or where the shorter one ends; `None`
/// when they are equal.
fn first_difference(a: &Path, b: &Path) -> io::Result<Option<u64>> {
    let (mut a, mut b) = (File::open(a)?, File::open(b)?);
    let (mut left, mut right) = (vec![0_u8; CHUNK], vec![0_u8; CHUNK]);
    let mut offset = 0_u64;
    loop {
        let (held_left, held_right) = (fill(&mut a, &mut left)?, fill(&mut b, &mut right)?);
        let shared = held_left.min(held_right);
        if let Some(at) = (0..shared).find(|at| left[*at] != right[*at]) {
            return Ok(Some(offset + at as u64));
        }
        if held_left != held_right {
            return Ok(Some(offset + shared as u64));
        }
        if held_left < CHUNK {
            return Ok(None);
        }
        offset += CHUNK as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn the_copy_is_a_new_file_of_the_same_bytes_in_a_directory_made_for_it() {
        let held = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0..CHUNK * 2 + 7).map(|at| (at % 251) as u8).collect();
        let original = written(held.path(), "program", &bytes);
        let copy = private_copy(&original, held.path(), &[]).unwrap();
        assert_ne!(copy, original);
        assert_eq!(std::fs::read(&copy).unwrap(), bytes);
        assert_eq!(copy.file_name(), original.file_name());
        assert_ne!(copy.parent(), original.parent());
        let again = private_copy(&original, held.path(), &[]).unwrap();
        assert_ne!(
            again.parent(),
            copy.parent(),
            "each run has a directory of its own"
        );
    }

    #[test]
    fn a_copy_that_does_not_hold_the_original_s_bytes_is_refused() {
        let held = tempfile::tempdir().unwrap();
        let original = written(held.path(), "program", &vec![7; CHUNK + 10]);
        let flipping = |from: &Path, to: &Path| {
            let mut bytes = std::fs::read(from)?;
            bytes[CHUNK + 3] ^= 1;
            std::fs::write(to, bytes)
        };
        let shortening = |from: &Path, to: &Path| {
            let mut bytes = std::fs::read(from)?;
            bytes.truncate(CHUNK);
            std::fs::write(to, bytes)
        };
        let extending = |from: &Path, to: &Path| {
            let mut bytes = std::fs::read(from)?;
            bytes.push(0);
            std::fs::write(to, bytes)
        };
        for (what, copier, at) in [
            (
                "flips a byte",
                &flipping as &dyn Fn(&Path, &Path) -> io::Result<()>,
                CHUNK + 3,
            ),
            ("ends early", &shortening, CHUNK),
            ("holds one more", &extending, CHUNK + 10),
        ] {
            let problem = private_copy_with(&original, held.path(), &[], copier).unwrap_err();
            assert!(
                problem.contains(&format!("differs from it at byte {at}")),
                "{what}: {problem}"
            );
        }
    }

    #[test]
    fn a_program_that_cannot_be_read_or_a_copy_that_cannot_be_written_is_refused() {
        let held = tempfile::tempdir().unwrap();
        let problem = private_copy(&held.path().join("missing"), held.path(), &[]).unwrap_err();
        assert!(problem.contains("could not be copied"), "{problem}");
        let original = written(held.path(), "program", b"x");
        let refusing = |_: &Path, _: &Path| Err(io::Error::other("the disk is full"));
        let problem = private_copy_with(&original, held.path(), &[], &refusing).unwrap_err();
        assert!(problem.contains("the disk is full"), "{problem}");
        let problem =
            private_copy(&original, &held.path().join("no-such-directory"), &[]).unwrap_err();
        assert!(problem.contains("cannot be read"), "{problem}");
    }

    #[test]
    fn a_directory_a_step_builds_in_is_not_where_the_copy_goes() {
        let held = tempfile::tempdir().unwrap();
        let original = written(held.path(), "program", b"x");
        let target = held.path().join("target");
        let inside = target.join("tmp");
        std::fs::create_dir_all(&inside).unwrap();
        let problem = private_copy(&original, &inside, std::slice::from_ref(&target)).unwrap_err();
        assert!(problem.contains("where a step builds"), "{problem}");
        assert!(
            std::fs::read_dir(&inside).unwrap().next().is_none(),
            "nothing was made there"
        );
        let beside = private_copy(&original, held.path(), std::slice::from_ref(&target)).unwrap();
        assert!(beside.exists());
    }

    #[test]
    fn a_path_with_a_space_cannot_be_cargo_s_runner_and_is_refused_before_anything_is_made() {
        let held = tempfile::tempdir().unwrap();
        let original = written(held.path(), "program", b"x");
        let spaced = held.path().join("with space");
        std::fs::create_dir(&spaced).unwrap();
        let problem = private_copy(&original, &spaced, &[]).unwrap_err();
        assert!(problem.contains("has a space in it"), "{problem}");
        assert!(std::fs::read_dir(&spaced).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_keeps_the_original_s_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let held = tempfile::tempdir().unwrap();
        let original = written(held.path(), "program", b"x");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o750)).unwrap();
        let copy = private_copy(&original, held.path(), &[]).unwrap();
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o750);
    }
}
