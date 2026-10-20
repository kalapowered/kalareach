//! The releases of a repository: every `packages/v<version>+<commit>` tag, and the list origin has.
//!
//! A release is a commit tagged `packages/v<version>+<first twelve characters of the commit>`.
//! The tags are the record of what was released, so a tool that decides something from them reads
//! all of them, whether or not the checkout's history reaches them, and refuses a tag that is not of
//! the form rather than skipping it.
//!
//! This file is also read by the `kr-cli` upgrade suite, which chooses the release it updates from
//! the same way, so it uses nothing but the standard library, `serde_json` and `kr_protocol`, and
//! names its sibling modules (`public_majors`, which reads Rust source) as `crate::<module>`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use kr_protocol::hello::PackageVersion;
use kr_protocol::update::CompatibilityLevel;

/// A release as its tag names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The tag, `packages/v<version>+<commit>`.
    pub tag: String,
    /// The version the tag states.
    pub version: PackageVersion,
    /// The full commit the tag points at.
    pub commit: String,
}

impl Release {
    /// The compatibility level of the release.
    pub fn level(&self) -> CompatibilityLevel {
        CompatibilityLevel::of(self.version)
    }
}

/// What `git` prints for `arguments` run in `repository`.
pub fn git_in(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

pub fn is_ancestor(repository: &Path, ancestor: &str, descendant: &str) -> Result<bool, String> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .current_dir(repository)
        .status()
        .map_err(|error| format!("git merge-base: {error}"))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!(
            "git merge-base --is-ancestor {ancestor} {descendant} failed"
        )),
    }
}

/// The version `packages/protocol/package.json` states at `commit`.
pub fn package_version_at(repository: &Path, commit: &str) -> Result<PackageVersion, String> {
    let manifest = git_in(
        repository,
        &["show", &format!("{commit}:packages/protocol/package.json")],
    )?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|error| format!("the package manifest at {commit}: {error}"))?;
    let version = manifest["version"]
        .as_str()
        .ok_or_else(|| format!("the package manifest at {commit} states no version"))?;
    version_of(version).ok_or_else(|| format!("{version} at {commit} is not major.minor.patch"))
}

fn version_of(text: &str) -> Option<PackageVersion> {
    let mut parts = text.split('.').map(|part| {
        (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| part.parse::<u16>().ok())
            .flatten()
    });
    let version = PackageVersion::new(parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

/// The name a release tag has, split into its version and the first twelve characters of its
/// commit; none for a name that is not of the form.
fn name_of(tag: &str) -> Option<(PackageVersion, &str)> {
    tag.strip_prefix("packages/v")
        .and_then(|rest| rest.split_once('+'))
        .and_then(|(version, short)| {
            let well_formed = short.len() == 12
                && short
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            well_formed.then_some((version_of(version)?, short))
        })
}

/// The release a tag names, with the commit it points at. A tag that is not of the form, or whose
/// name does not start the commit it points at, is an error and not a tag to skip: the tags are
/// the record of what was released.
pub fn release_of(repository: &Path, tag: &str) -> Result<Release, String> {
    let named = name_of(tag).ok_or_else(|| {
        format!("{tag} is not of the form packages/v<major.minor.patch>+<commit>")
    })?;
    let commit = git_in(
        repository,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/tags/{tag}^{{commit}}"),
        ],
    )?
    .trim()
    .to_owned();
    if !commit.starts_with(named.1) {
        return Err(format!("{tag} points at {commit}, which it does not name"));
    }
    Ok(Release {
        tag: tag.to_owned(),
        version: named.0,
        commit,
    })
}

/// Every release tag this checkout has, whether or not the history of any commit reaches it, in
/// the order of their names.
///
/// # Errors
///
/// When a tag named `packages/v*` is not a release, or points at a commit it does not name.
pub fn inventory(repository: &Path) -> Result<Vec<Release>, String> {
    let tags = git_in(repository, &["tag", "--list", "packages/v*"])?;
    let mut releases = Vec::new();
    for tag in tags.lines() {
        releases.push(release_of(repository, tag)?);
    }
    releases.sort_by(|left, right| left.tag.cmp(&right.tag));
    Ok(releases)
}

/// The text of `path` as `commit` has it; none where the commit has no such file.
///
/// # Errors
///
/// When git cannot be asked, or the file is there and cannot be read.
pub fn file_at(repository: &Path, commit: &str, path: &str) -> Result<Option<String>, String> {
    let listed = git_in(repository, &["ls-tree", "--name-only", commit, "--", path])?;
    if listed.trim().is_empty() {
        return Ok(None);
    }
    git_in(repository, &["show", &format!("{commit}:{path}")]).map(Some)
}

/// The release tags origin has, by name, each with the commit it points at (an annotated tag's own
/// commit, not the tag object).
///
/// # Errors
///
/// When origin cannot be asked: an inventory that cannot be read is not an empty one.
pub fn origin_tags(repository: &Path) -> Result<BTreeMap<String, String>, String> {
    let listing = git_in(
        repository,
        &["ls-remote", "--tags", "origin", "refs/tags/packages/v*"],
    )
    .map_err(|error| format!("origin's release tags cannot be listed: {error}"))?;
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    let mut peeled: BTreeMap<String, String> = BTreeMap::new();
    for line in listing.lines() {
        let (object, reference) = line.split_once('\t').ok_or_else(|| {
            format!("origin's listing has a line that is not a reference: {line}")
        })?;
        let name = reference
            .strip_prefix("refs/tags/")
            .ok_or_else(|| format!("origin's listing names {reference}, which is not a tag"))?;
        match name.strip_suffix("^{}") {
            Some(tag) => peeled.insert(tag.to_owned(), object.to_owned()),
            None => tags.insert(name.to_owned(), object.to_owned()),
        };
    }
    for (tag, commit) in peeled {
        tags.insert(tag, commit);
    }
    Ok(tags)
}

/// Fails unless this checkout's release tags are origin's: the same names, each at the same commit.
/// A tag of either side that points at `head`, the commit being checked, is left out of the
/// comparison on its own side, because the tag a release makes for the commit under test is made
/// after the commit lands and may be on one side only.
///
/// # Errors
///
/// When origin cannot be listed, or the two differ; the message names each difference and how to
/// make the checkout agree.
pub fn agree_with_origin(repository: &Path, local: &[Release], head: &str) -> Result<(), String> {
    let origin = origin_tags(repository)?;
    let mut problems = Vec::new();
    let local: BTreeMap<&str, &str> = local
        .iter()
        .filter(|release| release.commit != head)
        .map(|release| (release.tag.as_str(), release.commit.as_str()))
        .collect();
    let origin: BTreeMap<&str, &str> = origin
        .iter()
        .filter(|(_, commit)| commit.as_str() != head)
        .map(|(tag, commit)| (tag.as_str(), commit.as_str()))
        .collect();
    for (tag, commit) in &origin {
        match local.get(tag) {
            None => problems.push(format!("{tag} is on origin and not in this checkout")),
            Some(here) if here != commit => {
                problems.push(format!("{tag} is at {here} here and at {commit} on origin"))
            }
            Some(_) => {}
        }
    }
    for tag in local.keys() {
        if !origin.contains_key(tag) {
            problems.push(format!("{tag} is in this checkout and not on origin"));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "this checkout's release tags are not origin's:\n  {}\nmake them agree with `git fetch --force \
         --prune origin '+refs/tags/packages/v*:refs/tags/packages/v*'`, which also removes a tag \
         that origin no longer has; a tag only this checkout has is deleted with `git tag -d <tag>`",
        problems.join("\n  ")
    ))
}

/// The roots of the retained surface a release declared in its own source, where it has a source
/// that declares them: `SURFACE_ROOTS` in `crates/kr-protocol/src/retained.rs` at `commit`. None
/// where the release has no such file, which is how a release before the retained levels reads.
///
/// The reader is strict: it knows the one declaration `pub const SURFACE_ROOTS: &[&str] = &[ .. ];`
/// of plain string literals, in any layout, and a source that declares the list otherwise is an
/// error.
///
/// # Errors
///
/// When the file is there and declares the list in another form.
pub fn surface_roots_at(repository: &Path, commit: &str) -> Result<Option<Vec<String>>, String> {
    let path = "crates/kr-protocol/src/retained.rs";
    let Some(source) = file_at(repository, commit, path)
        .map_err(|error| format!("{path} at {commit} cannot be read: {error}"))?
    else {
        return Ok(None);
    };
    // A file that is there and declares no list is not a release from before the retained levels
    // (which has no such file): it is a source this reader does not understand.
    surface_roots_in(&source)
        .map_err(|error| format!("SURFACE_ROOTS at {commit} ({path}): {error}"))?
        .map(Some)
        .ok_or_else(|| format!("{path} at {commit} declares no SURFACE_ROOTS"))
}

/// The roots `SURFACE_ROOTS` lists in `source`; see [`surface_roots_at`]. It is the one reader of
/// Rust source the release tooling has (`public_majors::string_list`), so what is a comment, a
/// string and a declaration is decided in one place.
///
/// # Errors
///
/// When the declaration is there more than once, or is not in the shape the reader knows.
pub fn surface_roots_in(source: &str) -> Result<Option<Vec<String>>, String> {
    crate::public_majors::string_list(source, "SURFACE_ROOTS")
}
