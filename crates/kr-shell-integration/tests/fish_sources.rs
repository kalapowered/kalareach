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
//! and the check must refuse it and name the source. The sources a case changes are the ones the
//! current pins name, taken from the manifest and the release's lock, because a cache that was
//! restored from an older run also holds files no pin names.
//!
//! They need the archive, the crates and the repositories placed (`scripts/place-shell-sources.sh
//! --fish`), which an ordinary run does not have, so they are left out of one. A run that placed
//! them runs these with `--include-ignored`, as continuous integration's shell-packages job does.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest as _, Sha256};

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
        let archive = upstream(&repository_root().join("shells/fish/manifest.json")).0;
        assert!(
            placed.join(archive).is_file(),
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

    /// Replaces the release archive by one whose `Cargo.lock` `edit` has changed, and pins the new
    /// archive's digest in this tree's manifest, so that the lock is the one thing that differs.
    fn change_lock(&self, edit: impl FnOnce(String) -> String) {
        let (archive, directory) = upstream(&self.root.join("shells/fish/manifest.json"));
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let unpacked = Command::new("tar")
            .arg("-x")
            .arg("-f")
            .arg(self.sources.join(&archive))
            .arg("-C")
            .arg(scratch.path())
            .status()
            .expect("tar to run");
        assert!(unpacked.success(), "tar could not unpack {archive}");
        let lock = scratch.path().join(&directory).join("Cargo.lock");
        let text = fs::read_to_string(&lock).expect("the lock");
        fs::write(&lock, edit(text)).expect("the changed lock");
        let packed = scratch.path().join("changed.tar.xz");
        let repacked = Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .env("XZ_OPT", "-1")
            .arg("-c")
            .arg("-J")
            .arg("-f")
            .arg(&packed)
            .arg("-C")
            .arg(scratch.path())
            .arg(&directory)
            .status()
            .expect("tar to run");
        assert!(repacked.success(), "tar could not pack {archive}");
        let bytes = fs::read(&packed).expect("the new archive");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        self.change_file(&archive, |_| bytes);
        self.change_manifest(|manifest| manifest["upstream"]["sha256"] = serde_json::json!(digest));
    }

    fn manifest(&self) -> serde_json::Value {
        let path = self.root.join("shells/fish/manifest.json");
        serde_json::from_slice(&fs::read(path).expect("the manifest")).expect("JSON")
    }

    /// The name of the bundle the manifest pins for the repository `name`, and its revision.
    fn pinned_bundle(&self, name: &str) -> (String, String) {
        let manifest = self.manifest();
        let entry = manifest["cargo"]["git"]
            .as_array()
            .expect("the pins")
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| panic!("the manifest pins no {name}"));
        let revision = entry["revision"].as_str().expect("a revision").to_owned();
        (format!("{name}-{}.bundle", &revision[..12]), revision)
    }

    /// The `.crate` file the lock of the pinned release names first.
    fn locked_crate(&self) -> String {
        let (archive, directory) = upstream(&self.root.join("shells/fish/manifest.json"));
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let lock = format!("{directory}/Cargo.lock");
        let unpacked = Command::new("tar")
            .arg("-x")
            .arg("-f")
            .arg(self.sources.join(archive))
            .arg("-C")
            .arg(scratch.path())
            .arg(&lock)
            .status()
            .expect("tar to run");
        assert!(unpacked.success(), "tar could not read {lock}");
        let text = fs::read_to_string(scratch.path().join(lock)).expect("the lock");
        let (mut name, mut version) = (String::new(), String::new());
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("name = ") {
                name = value.trim_matches('"').to_owned();
            } else if let Some(value) = line.strip_prefix("version = ") {
                version = value.trim_matches('"').to_owned();
            } else if line == "source = \"registry+https://github.com/rust-lang/crates.io-index\"" {
                return format!("{name}-{version}.crate");
            }
        }
        panic!("the lock names no crates.io package");
    }
}

/// The archive file name and the directory it unpacks to, from a manifest.
fn upstream(manifest: &Path) -> (String, String) {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest).expect("the manifest")).expect("JSON");
    let text = |key: &str| manifest["upstream"][key].as_str().expect(key).to_owned();
    (text("archive"), text("directory"))
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

/// The check refused: it exited with a failure and said which source.
fn assert_refused(output: &Output, source: &str) {
    let said = said(output);
    assert!(!output.status.success(), "the check passed: {said}");
    assert!(
        said.contains(source),
        "the refusal does not name {source}: {said}"
    );
}

/// Sources that are placed are enough: the check passes with no server to ask. A fetch would fail
/// against the closed port, so passing is the evidence that nothing was fetched.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn placed_sources_need_no_server() {
    let tree = Tree::new();
    let output = tree.check();
    assert!(
        output.status.success(),
        "the check failed: {}",
        said(&output)
    );
}

/// A crate whose bytes are not the ones the lock holds a checksum for never reaches cargo.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_crate_with_other_bytes_is_refused() {
    let tree = Tree::new();
    let name = tree.locked_crate();
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
    let (name, _) = tree.pinned_bundle("fluent-ftl-tools");
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
    let (name, _) = tree.pinned_bundle("fluent-ftl-tools");
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
    let (_, revision) = tree.pinned_bundle("fluent-rs");
    tree.change_manifest(|manifest| {
        let pins = manifest["cargo"]["git"].as_array_mut().expect("the pins");
        pins.retain(|entry| entry["name"] != "fluent-rs");
    });
    assert_refused(&tree.check(), &revision);
}

/// A lock that takes a crate from a source the build does not place is refused by the source's
/// name, though the archive holding it is the one the manifest pins.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_lock_that_names_another_source_is_refused() {
    let tree = Tree::new();
    tree.change_lock(|lock| {
        lock.replacen(
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"",
            "source = \"sparse+https://example.invalid/index/\"",
            1,
        )
    });
    assert_refused(&tree.check(), "example.invalid");
}

/// A lock written in a form the check does not read is refused, not read around: a dependency list
/// that is closed with a comment is valid TOML, and it must not hide the packages after it.
#[test]
#[ignore = "needs the Fish sources placed; it runs with --include-ignored where they are, as continuous integration's shell-packages job does"]
fn a_lock_the_check_cannot_read_is_refused() {
    let tree = Tree::new();
    tree.change_lock(|lock| {
        let list = lock.find("dependencies = [\n").expect("a dependency list");
        let close = list + lock[list..].find("\n]\n").expect("its end") + 2;
        format!("{} # a note{}", &lock[..close], &lock[close..])
    });
    assert_refused(&tree.check(), "Cargo.lock");
}
