//! The sources the Fish package is compiled from, judged before anything is built.
//!
//! Fish is a Rust shell. Its release names every crate and every git repository the compiler would
//! download, and `scripts/build-shells.sh` replaces all of them with files that
//! `scripts/place-shell-sources.sh` put in the sources cache and that it checked against a pin:
//! the checksum the release's lock holds for a crate, and the revision and tree digest the
//! manifest holds for a repository. These cases run the real scripts over the real placed files
//! with `--check-sources`, which stops once the sources have been judged.
//!
//! The control shows that placed sources are enough: the run has no server to reach, as far as a
//! client that obeys the proxy variables goes. Each mutation then changes one thing a pin covers,
//! and the build must refuse it before it configures anything.
//!
//! They need the archive, the crates and the repositories placed (`scripts/place-shell-sources.sh
//! --fish`), which an ordinary run does not have, so they are left out of one. A run that placed
//! them runs these with `--include-ignored`, as continuous integration's shell-packages job does.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Where `scripts/place-shell-sources.sh` puts the sources by default.
fn placed_sources() -> PathBuf {
    let prefix = if let Some(explicit) = std::env::var_os("KR_SHELL_PREFIX") {
        PathBuf::from(explicit)
    } else {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        if cfg!(target_os = "macos") {
            home.join("Library/Caches/kalareach/shells")
        } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(xdg).join("kalareach/shells")
        } else {
            home.join(".cache/kalareach/shells")
        }
    };
    prefix.join("sources")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_directory(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("a directory to copy into");
    for entry in fs::read_dir(from).expect("a directory to copy") {
        let entry = entry.expect("a directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file to copy");
        }
    }
}

/// A copy of the scripts and the Fish package's files, and a sources directory whose every file is
/// the placed one, so that a case changes the copy it owns and nothing the cache holds.
struct Tree {
    _directory: tempfile::TempDir,
    root: PathBuf,
    sources: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let placed = placed_sources();
        assert!(
            placed.join("fish-4.9.3.tar.xz").is_file(),
            "the Fish sources are not placed in {}; run scripts/place-shell-sources.sh --fish",
            placed.display()
        );
        let directory = tempfile::tempdir().expect("a scratch directory");
        let root = directory.path().join("tree");
        fs::create_dir_all(root.join("scripts")).expect("the scripts directory");
        for script in ["build-shells.sh", "place-shell-sources.sh"] {
            fs::copy(
                repository_root().join("scripts").join(script),
                root.join("scripts").join(script),
            )
            .expect("a script to copy");
        }
        copy_directory(
            &repository_root().join("shells/fish"),
            &root.join("shells/fish"),
        );
        let sources = directory.path().join("prefix/sources");
        fs::create_dir_all(&sources).expect("the sources directory");
        for entry in fs::read_dir(&placed).expect("the placed sources") {
            let entry = entry.expect("a placed file");
            if entry.file_type().expect("a file type").is_file() {
                symlink(entry.path(), sources.join(entry.file_name())).expect("a link to a file");
            }
        }
        Self {
            _directory: directory,
            root,
            sources,
        }
    }

    /// Runs the check with every proxy variable pointing at a port nothing listens on.
    fn check(&self) -> Output {
        let mut command = Command::new("bash");
        command
            .arg("scripts/build-shells.sh")
            .args(["--fish", "--check-sources", "--prefix"])
            .arg(self.sources.parent().expect("the prefix"))
            .current_dir(&self.root)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            command.env(name, "http://127.0.0.1:9");
        }
        command.output().expect("bash to run")
    }

    /// Replaces a placed file by a copy that `edit` has changed.
    fn change_file(&self, name: &str, edit: impl FnOnce(Vec<u8>) -> Vec<u8>) {
        let path = self.sources.join(name);
        let bytes = fs::read(&path).expect("the placed file");
        fs::remove_file(&path).expect("the link to remove");
        fs::write(&path, edit(bytes)).expect("the changed copy");
    }

    /// Changes the Fish manifest this tree's scripts read.
    fn change_manifest(&self, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = self.root.join("shells/fish/manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("the manifest")).expect("JSON");
        edit(&mut manifest);
        fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("JSON"))
            .expect("the manifest");
    }

    /// The name of the one placed file whose name starts with `start` and ends with `end`.
    fn placed_file(&self, start: &str, end: &str) -> String {
        let mut names: Vec<String> = fs::read_dir(&self.sources)
            .expect("the sources")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.starts_with(start) && name.ends_with(end))
            .collect();
        names.sort();
        names
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no placed file {start}*{end}"))
    }
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .output()
        .expect("git to run");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// What the run said, both streams.
fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The build refused: it exited with a failure, said which source and stopped before it
/// configured anything.
fn assert_refused(output: &Output, source: &str) {
    let said = said(output);
    assert!(!output.status.success(), "the build went on: {said}");
    assert!(
        said.contains(source),
        "the refusal does not name {source}: {said}"
    );
    assert!(
        !said.contains("configuring"),
        "the build went on to configure: {said}"
    );
}

/// Sources that are placed are enough: the check passes with no server to ask, and fetches
/// nothing.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn placed_sources_need_no_server() {
    let tree = Tree::new();
    let output = tree.check();
    let said = said(&output);
    assert!(output.status.success(), "the check failed: {said}");
    assert!(!said.contains("fetching"), "the check fetched: {said}");
}

/// A crate whose bytes are not the ones the lock holds a checksum for never reaches cargo.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_crate_with_other_bytes_is_refused() {
    let tree = Tree::new();
    let name = tree.placed_file("", ".crate");
    tree.change_file(&name, |mut bytes| {
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        bytes
    });
    assert_refused(&tree.check(), &name);
}

/// A repository bundle whose commit is not the pinned revision is refused, though its tree is the
/// pinned one: the revision is judged on its own.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_bundle_of_another_commit_with_the_pinned_tree_is_refused() {
    let tree = Tree::new();
    let name = tree.placed_file("fluent-ftl-tools-", ".bundle");
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let repository = scratch.path().join("repository.git");
    git(
        scratch.path(),
        &["init", "--quiet", "--bare", "repository.git"],
    );
    git(
        &repository,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            tree.sources.join(&name).to_str().expect("a path"),
            "refs/heads/pinned:refs/heads/pinned",
        ],
    );
    let pinned_tree = git(&repository, &["rev-parse", "refs/heads/pinned^{tree}"]);
    let other = git(&repository, &["commit-tree", &pinned_tree, "-m", "other"]);
    git(&repository, &["update-ref", "refs/heads/pinned", &other]);
    let bundle = scratch.path().join("other.bundle");
    git(
        &repository,
        &[
            "bundle",
            "create",
            "--quiet",
            bundle.to_str().expect("a path"),
            "refs/heads/pinned",
        ],
    );
    tree.change_file(&name, |_| fs::read(&bundle).expect("the new bundle"));
    assert_refused(&tree.check(), &name);
}

/// A repository whose tree is not the one the manifest pins is refused.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_repository_with_another_tree_digest_is_refused() {
    let tree = Tree::new();
    let name = tree.placed_file("fluent-ftl-tools-", ".bundle");
    tree.change_manifest(|manifest| {
        for entry in manifest["cargo"]["git"].as_array_mut().expect("the pins") {
            if entry["name"] == "fluent-ftl-tools" {
                entry["sha256"] = serde_json::json!("0".repeat(64));
            }
        }
    });
    assert_refused(&tree.check(), &name);
}

/// A repository the lock uses and the manifest does not pin is refused by name, never fetched.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_repository_the_manifest_does_not_pin_is_refused() {
    let tree = Tree::new();
    tree.change_manifest(|manifest| {
        let pins = manifest["cargo"]["git"].as_array_mut().expect("the pins");
        pins.retain(|entry| entry["name"] != "fluent-rs");
    });
    assert_refused(&tree.check(), "cf712bced280b217b6307edabc2089b3e57204ab");
}
