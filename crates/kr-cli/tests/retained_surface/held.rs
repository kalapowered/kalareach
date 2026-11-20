//! The releases of a level, read for the held check of the narrower table.
//!
//! `kr-protocol-gen --level-releases` lists the releases at the level of the checkout, one
//! `<tag> <commit>` line each. For each of them this puts a tree on disk that holds the manifests
//! of every crate and the `src` of the crates the entries' rules are made of, and nothing else, so
//! that [`super::walker::Tree`] reads the root and the helpers of an entry as that release had
//! them. A crate's `src` is extracted once for each crate, path and subtree id, and shared by the
//! releases that have it as it is: the digest of an item holds the path of its file, so the same
//! subtree at a new path is read again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::Root;
use super::narrower::{Narrower, Reader, check_held};
use super::walker::Tree;

/// A release of the list: its tag and its full commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub tag: String,
    pub commit: String,
}

/// Reads the list `kr-protocol-gen --level-releases` prints: `<tag> <commit>` lines.
///
/// # Errors
///
/// A line that is not two words.
pub fn parse_list(text: &str) -> Result<Vec<Listed>, String> {
    let mut listed = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [tag, commit] = words[..] else {
            return Err(format!(
                "line {} of the list of releases is not `<tag> <commit>`: {line:?}",
                at + 1
            ));
        };
        listed.push(Listed {
            tag: tag.to_owned(),
            commit: commit.to_owned(),
        });
    }
    Ok(listed)
}

/// Where the files of a release come from: git for the check, a counting stand-in for its cases.
pub trait Extract {
    /// Writes the `Cargo.toml` of each crate under `crates/` of `commit` into `into`, at the
    /// path they have in the repository.
    fn manifests(&self, commit: &str, into: &Path) -> Result<(), String>;
    /// The id of the subtree `path` of `commit`: the same for the same contents.
    fn subtree(&self, commit: &str, path: &str) -> Result<String, String>;
    /// Writes the files of `path` of `commit` into `into`, at the path they have in the
    /// repository.
    fn files(&self, commit: &str, path: &str, into: &Path) -> Result<(), String>;
}

/// The crates an entry's rule is made of: its root's and its helpers'.
fn crates_of_the_rules<'a>(entries: &'a [Narrower], roots: &'a [Root]) -> BTreeSet<&'a str> {
    let mut crates = BTreeSet::new();
    for entry in entries {
        if let Some(root) = roots.iter().find(|root| root.label == entry.root) {
            crates.insert(root.krate);
        }
        crates.extend(entry.helpers.iter().map(|helper| helper.krate));
    }
    crates
}

/// The directory of each crate whose manifest `folder` holds, by the name its code uses: the
/// package of `crates/<directory>/Cargo.toml`, as the walker names it.
fn crate_paths(folder: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut paths = BTreeMap::new();
    let crates = folder.join("crates");
    for entry in
        std::fs::read_dir(&crates).map_err(|error| format!("{}: {error}", crates.display()))?
    {
        let directory = entry.map_err(|error| error.to_string())?.file_name();
        let Some(directory) = directory.to_str() else {
            continue;
        };
        let manifest = crates.join(directory).join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let package = text
            .lines()
            .skip_while(|line| line.trim() != "[package]")
            .find_map(|line| line.trim().strip_prefix("name = "))
            .map(|name| name.trim_matches('"').replace('-', "_"));
        if let Some(name) = package {
            paths.insert(name, format!("crates/{directory}"));
        }
    }
    Ok(paths)
}

/// Puts each release of `listed` on disk under `work` and reads it: a tree whose crates are the
/// ones the entries' rules are made of. Nothing is extracted when no entry exists.
///
/// # Errors
///
/// When a release cannot be extracted.
pub fn read_releases(
    entries: &[Narrower],
    roots: &[Root],
    listed: &[Listed],
    extract: &dyn Extract,
    work: &Path,
) -> Result<Vec<(String, Tree)>, String> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let wanted = crates_of_the_rules(entries, roots);
    let mut stored: BTreeMap<(String, String, String), PathBuf> = BTreeMap::new();
    let mut trees = Vec::new();
    for (at, release) in listed.iter().enumerate() {
        let folder = work.join(format!("release-{at}"));
        extract
            .manifests(&release.commit, &folder)
            .map_err(|error| format!("{}: {error}", release.tag))?;
        let paths = crate_paths(&folder).map_err(|error| format!("{}: {error}", release.tag))?;
        for krate in &wanted {
            // A release without the crate is a lookup that says so.
            let Some(path) = paths.get(*krate) else {
                continue;
            };
            let subtree = extract
                .subtree(&release.commit, path)
                .map_err(|error| format!("{}: {error}", release.tag))?;
            let key = ((*krate).to_owned(), path.clone(), subtree);
            let kept = match stored.get(&key) {
                Some(kept) => kept.clone(),
                None => {
                    let kept = work.join(format!("crate-{}", stored.len()));
                    extract
                        .files(&release.commit, &format!("{path}/src"), &kept)
                        .map_err(|error| format!("{}: {error}", release.tag))?;
                    stored.insert(key, kept.clone());
                    kept
                }
            };
            std::os::unix::fs::symlink(kept.join(path).join("src"), folder.join(path).join("src"))
                .map_err(|error| format!("{}: {path}/src: {error}", release.tag))?;
        }
        trees.push((
            release.tag.clone(),
            Tree::at(&folder).map_err(|error| format!("{}: {error}", release.tag))?,
        ));
    }
    Ok(trees)
}

/// What the held check found over the releases of a list.
pub struct Held {
    pub entries: usize,
    pub releases: usize,
    pub problems: Vec<String>,
}

/// Reads each release of `listed` and holds the rules of the entries to it.
///
/// # Errors
///
/// When a release cannot be extracted.
pub fn hold_releases(
    entries: &[Narrower],
    roots: &[Root],
    listed: &[Listed],
    extract: &dyn Extract,
    work: &Path,
) -> Result<Held, String> {
    let trees = read_releases(entries, roots, listed, extract, work)?;
    let releases: Vec<(&str, &dyn Reader)> = trees
        .iter()
        .map(|(tag, tree)| (tag.as_str(), tree as &dyn Reader))
        .collect();
    Ok(Held {
        entries: entries.len(),
        releases: listed.len(),
        problems: check_held(entries, roots, &releases),
    })
}

/// Reads the files of a release out of the repository's own object store.
pub struct Git {
    repository: PathBuf,
}

impl Git {
    pub fn new(repository: PathBuf) -> Self {
        Self { repository }
    }

    /// What `git` prints for `arguments`. Every child's output stays in its pipes, so that none
    /// of it reaches the line a test prints, and a failure is told with its own words.
    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>, String> {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(&self.repository)
            .output()
            .map_err(|error| format!("git {}: {error}", arguments.join(" ")))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!(
                "git {}: {}",
                arguments.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    fn archive(&self, commit: &str, path: &str, into: &Path) -> Result<(), String> {
        let tar = self.run(&["archive", "--format=tar", commit, path])?;
        std::fs::create_dir_all(into).map_err(|error| format!("{}: {error}", into.display()))?;
        tar::Archive::new(tar.as_slice())
            .unpack(into)
            .map_err(|error| format!("unpacking {path} of {commit}: {error}"))
    }
}

impl Extract for Git {
    fn manifests(&self, commit: &str, into: &Path) -> Result<(), String> {
        self.archive(commit, ":(glob)crates/*/Cargo.toml", into)
    }

    fn subtree(&self, commit: &str, path: &str) -> Result<String, String> {
        let id = self.run(&["rev-parse", "--verify", &format!("{commit}:{path}")])?;
        Ok(String::from_utf8_lossy(&id).trim().to_owned())
    }

    fn files(&self, commit: &str, path: &str, into: &Path) -> Result<(), String> {
        self.archive(commit, path, into)
    }
}
