//! The files of a release tree, as the manifest lists them.
//!
//! A release holds regular files and nothing else: no links, no devices, no empty directories, no
//! file with a second name. A tree that holds anything else is refused before it is listed, because
//! the host that installs it refuses the archive made from it.

use std::path::Path;

use kr_protocol::update::{MANIFEST_FILE, required_programs};

use crate::refusal::{Result, digest_file, refuse, unreadable};

/// One regular file of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeFile {
    /// Where it is, relative to the release's directory, its parts separated by `/`.
    pub path: String,
    /// Its length in bytes.
    pub length: u64,
    /// Its SHA-256 digest.
    pub sha256: [u8; 32],
    /// Whether it is a program.
    pub executable: bool,
}

/// Lists every file of the tree but its manifest, sorted by path.
///
/// A file is a program when it is one of the release's executables in `bin/`, or one of the files
/// in a shell package's own `bin/`. Nothing here asks the file system whether a file is executable:
/// the file system of a runner that built the tree is not what the release says.
///
/// # Errors
///
/// Returns a refusal naming the first link, device, file with a second name or empty directory,
/// and any file that cannot be read.
pub fn files(tree: &Path, target: &str) -> Result<Vec<TreeFile>> {
    let mut found = Vec::new();
    walk(tree, tree, target, &mut found)?;
    found.sort_by(|first: &TreeFile, second| first.path.cmp(&second.path));
    Ok(found)
}

fn walk(tree: &Path, directory: &Path, target: &str, found: &mut Vec<TreeFile>) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| unreadable(directory, &error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| unreadable(directory, &error))?;
    if entries.is_empty() && directory != tree {
        refuse!(
            "{} is an empty directory, which a release does not hold",
            relative(tree, directory)
        );
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = std::fs::symlink_metadata(&path).map_err(|error| unreadable(&path, &error))?;
        let shown = relative(tree, &path);
        if kind.file_type().is_symlink() {
            refuse!("{shown} is a link, which a release does not hold");
        }
        if kind.is_dir() {
            walk(tree, &path, target, found)?;
            continue;
        }
        if !kind.is_file() {
            refuse!("{shown} is neither a file nor a directory");
        }
        if directory == tree && entry.file_name() == MANIFEST_FILE {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if kind.nlink() > 1 {
                refuse!(
                    "{shown} has {} names, and an archive writes the second as a link, which a \
                     release does not hold",
                    kind.nlink()
                );
            }
        }
        found.push(TreeFile {
            executable: is_program(&shown, target),
            length: kind.len(),
            sha256: digest_file(&path)?,
            path: shown,
        });
    }
    Ok(())
}

/// Where `path` is in `tree`, with its parts separated by `/`.
fn relative(tree: &Path, path: &Path) -> String {
    path.strip_prefix(tree)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether the release says `path` is a program.
fn is_program(path: &str, target: &str) -> bool {
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    if let Some(name) = path.strip_prefix("bin/") {
        return required_programs(target).any(|program| name == format!("{program}{suffix}"));
    }
    let mut parts = path.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("shells"), Some(_), Some(_), Some("bin"))
    ) && path.matches('/').count() == 4
}
