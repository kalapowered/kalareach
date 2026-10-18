//! The release before the one being cut.
//!
//! A release is a commit tagged `packages/v<version>+<first twelve characters of the commit>`.
//! The release before the one at a commit is the newest such tag in that commit's history at the
//! highest compatibility level below the commit's own. A release retains the level of that
//! release and no other, so the newest retained level is its record, and nothing else in the tree
//! says which release that is: the tags do. This reads them, so it needs a checkout that has them.

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

/// The release a tag names, with the commit it points at. A tag that is not of the form, or whose
/// name does not start the commit it points at, is an error and not a tag to skip: the tags are
/// the record of what was released.
fn release_of(repository: &Path, tag: &str) -> Result<Release, String> {
    let named = tag
        .strip_prefix("packages/v")
        .and_then(|rest| rest.split_once('+'))
        .and_then(|(version, short)| {
            let well_formed = short.len() == 12
                && short
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            well_formed.then_some((version_of(version)?, short))
        })
        .ok_or_else(|| {
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

/// The releases before the one at `commit`: those tagged in its history at the highest level below
/// its own, oldest first, so the last is the release before. Releases of a lower level than that
/// are the business of the release that retained them.
///
/// # Errors
///
/// When no release below the commit's level is tagged, when the tags of that level do not lie on
/// one line of history (so none is the newest), when two tags name one commit, or when a tag
/// states another version than its commit's package.
pub fn before(repository: &Path, commit: &str) -> Result<Vec<Release>, String> {
    let level = CompatibilityLevel::of(package_version_at(repository, commit)?);
    let tags = git_in(
        repository,
        &["tag", "--merged", commit, "--list", "packages/v*"],
    )?;
    let mut below = Vec::new();
    for tag in tags.lines() {
        let release = release_of(repository, tag)?;
        if release.level() < level {
            below.push(release);
        }
    }
    let Some(highest) = below.iter().map(Release::level).max() else {
        return Err(format!(
            "no release below level {level} is tagged in the history of {commit}; fetch the \
             release tags (git fetch --tags)"
        ));
    };
    let mut releases = Vec::new();
    for release in below
        .into_iter()
        .filter(|release| release.level() == highest)
    {
        let depth: usize = git_in(repository, &["rev-list", "--count", &release.commit])?
            .trim()
            .parse()
            .map_err(|error| format!("git rev-list --count: {error}"))?;
        let stated = package_version_at(repository, &release.commit)?;
        if stated != release.version {
            return Err(format!(
                "{} states {} and its commit's package is {stated}",
                release.tag, release.version
            ));
        }
        releases.push((depth, release));
    }
    releases.sort_by_key(|(depth, _)| *depth);
    let releases: Vec<Release> = releases.into_iter().map(|(_, release)| release).collect();
    for pair in releases.windows(2) {
        let (older, newer) = (&pair[0], &pair[1]);
        if older.commit == newer.commit {
            return Err(format!(
                "{} and {} tag the same commit",
                older.tag, newer.tag
            ));
        }
        if !is_ancestor(repository, &older.commit, &newer.commit)? {
            return Err(format!(
                "{} is not in the history of {}, so neither is the release before this one",
                older.tag, newer.tag
            ));
        }
    }
    Ok(releases)
}

/// Whether the newest of `retained` is the level of `release`.
///
/// # Errors
///
/// When it is not, naming what to do.
pub fn is_the_newest_retained(
    release: &Release,
    retained: &[CompatibilityLevel],
) -> Result<(), String> {
    let level = release.level();
    let Some(newest) = retained.iter().max() else {
        return Err("this build retains no level".to_owned());
    };
    if *newest == level {
        return Ok(());
    }
    let list = retained
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if retained.contains(&level) {
        return Err(format!(
            "the release before this one is {} at level {level}, and this build retains {list}: \
             {newest} is above it, and no release of that level is tagged below this one",
            release.tag
        ));
    }
    Err(format!(
        "the release before this one is {} at level {level}, and this build retains {list}; \
         retain {level} from it with kr-protocol-gen --retain {level} --commit {}",
        release.tag, release.commit
    ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A repository with a history that has the shapes the tags of this one has: a level released
    /// several times, a later level, a release tagged on a branch that is not in the history, and
    /// the commit being released.
    struct History {
        directory: PathBuf,
    }

    impl History {
        fn new(name: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "kr-protocol-gen-predecessor-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&directory);
            std::fs::create_dir_all(directory.join("packages/protocol")).expect("a directory");
            let history = Self { directory };
            history.git(&["init", "-q", "-b", "main"]);
            history
        }

        /// Runs git in the repository with nothing of the caller's environment, configuration or
        /// hooks: whatever runs these tests, they change this repository and no other.
        fn git(&self, arguments: &[&str]) -> String {
            let output = Command::new("git")
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", &self.directory)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(["-c", "user.name=a", "-c", "user.email=a@example.invalid"])
                .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
                .args(["-c", "core.hooksPath=/dev/null"])
                .args(arguments)
                .current_dir(&self.directory)
                .output()
                .expect("git runs");
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).expect("text")
        }

        /// A commit whose package states `version`; its full hash.
        fn commit(&self, version: &str, note: &str) -> String {
            std::fs::write(
                self.directory.join("packages/protocol/package.json"),
                format!("{{\"version\": \"{version}\"}}\n"),
            )
            .expect("a manifest");
            std::fs::write(self.directory.join(note.replace(' ', "-")), note).expect("a note");
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "-m", note]);
            self.git(&["rev-parse", "HEAD"]).trim().to_owned()
        }

        /// Tags `commit` as the release of `version`, the way the release script names it.
        fn release(&self, version: &str, commit: &str) -> String {
            let tag = format!("packages/v{version}+{}", &commit[..12]);
            self.git(&["tag", &tag, commit]);
            tag
        }

        /// The release before `commit`, and the tags of its level up to it.
        fn before(&self, commit: &str) -> Result<(Release, Vec<String>), String> {
            let mut releases = before(&self.directory, commit)?;
            let tags = releases.iter().map(|release| release.tag.clone()).collect();
            Ok((releases.pop().expect("at least one"), tags))
        }
    }

    impl Drop for History {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn level(minor: u16) -> CompatibilityLevel {
        CompatibilityLevel::of(PackageVersion::new(0, minor, 0))
    }

    /// The release before the one being cut is the newest tag of the highest level below its own
    /// that is in its history: not a release of its own level, not one on a branch that is not
    /// merged, not one after it, not an older level's patch tagged later, and not the older
    /// releases of the level before.
    #[test]
    fn the_release_before_is_the_newest_tag_of_the_highest_lower_level_in_the_history() {
        let history = History::new("newest");
        let older = history.commit("0.73.0", "older");
        history.release("0.73.0", &older);
        let first = history.commit("0.74.0", "first of the level");
        let first_tag = history.release("0.74.0", &first);
        history.git(&["checkout", "-q", "-b", "side"]);
        let aside = history.commit("0.74.0", "released on a branch that is left");
        history.release("0.74.0", &aside);
        history.git(&["checkout", "-q", "main"]);
        let last = history.commit("0.74.0", "last of the level");
        let last_tag = history.release("0.74.0", &last);
        // A fix to the level before that one, released after this level's last release.
        let patch = history.commit("0.73.1", "a patch of the level before");
        history.release("0.73.1", &patch);
        let early = history.commit("0.75.0", "an earlier cut of the level");
        history.release("0.75.0", &early);
        let cut = history.commit("0.75.0", "the release being cut");
        // A release tagged after the commit is not in its history.
        history.release("0.76.0", &history.commit("0.76.0", "a later level"));

        let (found, level_tags) = history.before(&cut).expect("a release before");
        assert_eq!(found.tag, last_tag);
        assert_eq!(found.commit, last);
        assert_eq!(found.level(), level(74));
        assert_eq!(
            level_tags,
            [first_tag, last_tag],
            "every release of the level, oldest first"
        );
        // The commit that is the last of a level has the one before it.
        assert_eq!(history.before(&last).expect("before").0.commit, older);
    }

    /// What cannot name a release before is an error and not a guess.
    #[test]
    fn a_history_that_does_not_name_one_is_refused() {
        let history = History::new("refused");
        let first = history.commit("0.74.0", "no tag yet");
        let cut = history.commit("0.75.0", "cut");
        let error = history.before(&cut).expect_err("no tag");
        assert!(error.contains("no release below level 0.75"), "{error}");
        // A tag of the level being cut is not a release before it.
        history.release("0.75.0", &cut);
        assert!(history.before(&cut).is_err());
        // Nor is a tag that is not of the form,
        history.git(&["tag", "packages/vnext", &first]);
        let error = history.before(&cut).expect_err("a stray tag");
        assert!(error.contains("is not of the form"), "{error}");
        history.git(&["tag", "-d", "packages/vnext"]);
        // or one whose commit part is not the twelve characters the release script gives,
        history.git(&["tag", "packages/v0.74.0+abc", &first]);
        let error = history.before(&cut).expect_err("a short name");
        assert!(error.contains("is not of the form"), "{error}");
        history.git(&["tag", "-d", "packages/v0.74.0+abc"]);
        // or one that names another commit than it points at,
        history.git(&["tag", "packages/v0.74.0+000000000000", &first]);
        let error = history.before(&cut).expect_err("a wrong name");
        assert!(error.contains("which it does not name"), "{error}");
        history.git(&["tag", "-d", "packages/v0.74.0+000000000000"]);
        // or one whose version is not its commit's.
        history.release("0.74.1", &first);
        let error = history.before(&cut).expect_err("a wrong version");
        assert!(error.contains("its commit's package is 0.74.0"), "{error}");
    }

    /// Two releases of the level that neither contains cannot be ordered, so neither is called the
    /// newest; releases of a lower level on a branch that was merged do not matter.
    #[test]
    fn tags_of_the_level_that_are_not_on_one_line_of_history_are_refused() {
        let history = History::new("branches");
        history.commit("0.73.0", "base");
        history.git(&["checkout", "-q", "-b", "side"]);
        let aside = history.commit("0.74.0", "aside");
        history.release("0.74.0", &aside);
        history.git(&["checkout", "-q", "main"]);
        let own = history.commit("0.74.0", "own");
        history.release("0.74.0", &own);
        history.git(&["merge", "-q", "--no-ff", "-m", "merge", "side"]);
        let cut = history.commit("0.75.0", "cut");
        let error = history.before(&cut).expect_err("two lines");
        assert!(error.contains("is not in the history of"), "{error}");
        // Once a later level is released, those two are the business of the release that retained
        // them, and the release before the next cut is the later one.
        let later = history.commit("0.75.0", "later");
        let tag = history.release("0.75.0", &later);
        let next = history.commit("0.76.0", "next cut");
        assert_eq!(history.before(&next).expect("one line").0.tag, tag);
    }

    /// The newest retained level has to be the level of the release before.
    #[test]
    fn the_newest_retained_level_is_the_level_of_the_release_before() {
        let release = Release {
            tag: "packages/v0.74.0+d59b70150cd2".to_owned(),
            version: PackageVersion::new(0, 74, 0),
            commit: "d59b70150cd2259497bb07771f0731008de57ae9".to_owned(),
        };
        assert_eq!(is_the_newest_retained(&release, &[level(74)]), Ok(()));
        let error = is_the_newest_retained(&release, &[level(73)]).expect_err("an older level");
        assert!(
            error.contains("--retain 0.74 --commit d59b70150cd2259497bb07771f0731008de57ae9"),
            "{error}"
        );
        let error =
            is_the_newest_retained(&release, &[level(74), level(75)]).expect_err("a newer level");
        assert!(error.contains("0.75 is above it"), "{error}");
        assert!(is_the_newest_retained(&release, &[]).is_err());
    }
}
