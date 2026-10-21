//! The release record cites what a release was qualified against, and a record that is missing or
//! moved is refused.
//!
//! The repositories cited from are made here: a plugins repository whose commit the bundled
//! catalogue names, and a checkout of the release's own with the files the lock lists.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_release::record::{self, Elsewhere};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repository with one file committed, and the commit.
fn repository_with(file: &str, contents: &str) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().expect("a directory");
    git(directory.path(), &["init", "-q"]);
    git(
        directory.path(),
        &["config", "user.email", "a@example.test"],
    );
    git(directory.path(), &["config", "user.name", "a"]);
    let path = directory.path().join(file);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    std::fs::write(&path, contents).expect("a file");
    git(directory.path(), &["add", "."]);
    git(directory.path(), &["commit", "-q", "-m", "a record"]);
    let commit = git(directory.path(), &["rev-parse", "HEAD"]);
    (directory, commit)
}

/// The notes of the plugins repository, as the lock cites them.
const NOTES: &str = "# Qualification notes\n";

struct Fixture {
    checkout: tempfile::TempDir,
    plugins: tempfile::TempDir,
    commit: String,
}

fn write(checkout: &Path, path: &str, contents: &str) {
    let file = checkout.join(path);
    std::fs::create_dir_all(file.parent().expect("a parent")).expect("a directory");
    std::fs::write(file, contents).expect("a file");
}

/// A checkout with a lock, a bundled catalogue naming the plugins commit and the files the lock
/// lists. `index` is the catalogue's index.
fn fixture(index: &Value) -> Fixture {
    let (plugins, commit) = repository_with("docs/qualification-notes.md", NOTES);
    let checkout = tempfile::tempdir().expect("a directory");
    let root = checkout.path();
    write(root, "Cargo.lock", "# lock\n");
    write(
        root,
        "crates/kr-describe/profiles/small.json",
        &json!({
            "profile_id": "small",
            "model": { "repository": "a/b", "revision": "r1" },
            "conversion": { "revision": "r2" },
            "runtime": { "llama_cpp_revision": "r3" },
            "assets": [{ "file_name": "w.gguf", "sha256": "ab" }],
        })
        .to_string(),
    );
    write(
        root,
        "bundled-plugins.lock",
        &json!({ "source": { "commit": commit } }).to_string(),
    );
    let index_text = index.to_string();
    write(root, "bundled-plugins/targets/index.json", &index_text);
    write(
        root,
        "bundled-plugins/metadata/targets.json",
        &json!({ "signed": { "targets": { "index.json": { "hashes": { "sha256": hex(index_text.as_bytes()) } } } } })
            .to_string(),
    );
    let lock = json!({
        "format": 1,
        "classes": {
            "vendor_routes": { "state": "recorded", "records": [{
                "repository": "https://example.test/kalareach-plugins",
                "revision": commit,
                "path": "docs/qualification-notes.md",
                "sha256": hex(NOTES.as_bytes()),
            }]},
            "dependency_and_runtime_revisions": { "state": "recorded", "records": [{ "path": "Cargo.lock" }] },
            "model_assets": { "state": "recorded", "records": [{ "path": "crates/kr-describe/profiles/*.json" }] },
            "provider_event_schemas": { "state": "unavailable", "capability": "voice.call", "reason": "this release leaves voice calls off" },
            "service_limits": { "state": "unavailable", "capability": "voice.call", "reason": "this release leaves voice calls off" },
        },
    });
    write(root, record::LOCK, &lock.to_string());
    Fixture {
        checkout,
        plugins,
        commit,
    }
}

fn no_builds() -> Value {
    json!({ "entries": [{ "plugin_id": "a/b", "version": "1.0.0", "capabilities": [{ "capability": "x.y" }], "qualification": [] }] })
}

fn edit_lock(fixture: &Fixture, edit: &dyn Fn(&mut Value)) {
    let path = fixture.checkout.path().join(record::LOCK);
    let mut lock: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("a lock")).expect("a lock");
    edit(&mut lock);
    std::fs::write(path, lock.to_string()).expect("the lock");
}

fn elsewhere(fixture: &Fixture) -> Elsewhere {
    Elsewhere {
        plugins: Some(fixture.plugins.path().to_path_buf()),
        web: None,
    }
}

const TARGET: &str = "aarch64-apple-darwin";

/// KR-REQ-01.26: the record lists every class with the digest of each record, the model profiles'
/// revisions and assets among them, and the record the plugins repository holds at the cited
/// commit is read and held to its digest.
#[test]
fn the_record_lists_each_class_with_the_digest_of_every_record() {
    let fixture = fixture(&no_builds());
    let made = record::build(fixture.checkout.path(), TARGET, &elsewhere(&fixture), false)
        .expect("a record");
    let classes = made["classes"].as_array().expect("classes");
    assert_eq!(classes.len(), record::CLASSES.len());
    let vendor = &classes[0]["records"][0];
    assert_eq!(vendor["sha256"], hex(NOTES.as_bytes()));
    assert_eq!(vendor["read"], true, "the plugins repository was at hand");
    let model = &classes[2]["records"][0];
    assert_eq!(model["details"]["model_revision"], "r1");
    assert_eq!(model["details"]["runtime_revision"], "r3");
    assert_eq!(model["details"]["assets"][0]["file_name"], "w.gguf");
    assert_eq!(classes[3]["state"], "unavailable");
    assert_eq!(made["capabilities"], json!([]));

    // Without the repository at hand the record is cited by its digest and says it was not read.
    let cited = record::build(
        fixture.checkout.path(),
        TARGET,
        &Elsewhere::default(),
        false,
    )
    .expect("a record");
    assert_eq!(cited["classes"][0]["records"][0]["read"], false);
}

/// KR-REQ-01.26: a record that is missing or moved is refused.
#[test]
fn a_record_that_is_missing_or_moved_is_refused() {
    let fixture = fixture(&no_builds());
    let built = |fixture: &Fixture| {
        record::build(fixture.checkout.path(), TARGET, &elsewhere(fixture), false)
    };

    // The record is not the one that was cited.
    edit_lock(&fixture, &|lock| {
        lock["classes"]["vendor_routes"]["records"][0]["sha256"] = json!("0".repeat(64));
    });
    assert!(
        built(&fixture)
            .expect_err("a moved record")
            .to_string()
            .contains("not the record that was cited")
    );

    // The path is not in the repository at that commit.
    edit_lock(&fixture, &|lock| {
        lock["classes"]["vendor_routes"]["records"][0]["sha256"] = json!(hex(NOTES.as_bytes()));
        lock["classes"]["vendor_routes"]["records"][0]["path"] = json!("docs/gone.md");
    });
    assert!(
        built(&fixture)
            .expect_err("a missing record")
            .to_string()
            .contains("is missing from")
    );

    // A file of this checkout that is gone.
    edit_lock(&fixture, &|lock| {
        lock["classes"]["vendor_routes"]["records"][0]["path"] =
            json!("docs/qualification-notes.md");
        lock["classes"]["dependency_and_runtime_revisions"]["records"][0]["path"] =
            json!("Cargo.gone");
    });
    assert!(
        built(&fixture)
            .expect_err("a missing file")
            .to_string()
            .contains("is missing")
    );

    // A commit other than the one the bundled catalogue was taken from.
    edit_lock(&fixture, &|lock| {
        lock["classes"]["dependency_and_runtime_revisions"]["records"][0]["path"] =
            json!("Cargo.lock");
        lock["classes"]["vendor_routes"]["records"][0]["revision"] = json!("1".repeat(40));
    });
    assert!(
        built(&fixture)
            .expect_err("another commit")
            .to_string()
            .contains("bundled catalogue")
    );
    let _ = &fixture.commit;
}

/// KR-REQ-01.26: a class that is pending passes a run that proves the pipeline and not a release,
/// and a class that is unavailable names the capability it leaves off.
#[test]
fn a_pending_class_is_not_signed_for_release() {
    let fixture = fixture(&no_builds());
    edit_lock(&fixture, &|lock| {
        lock["classes"]["service_limits"] =
            json!({ "state": "pending", "reason": "not yet recorded" });
    });
    let root = fixture.checkout.path();
    let refused = record::build(root, TARGET, &elsewhere(&fixture), false).expect_err("pending");
    assert!(refused.to_string().contains("pending"), "{refused}");
    let allowed =
        record::build(root, TARGET, &elsewhere(&fixture), true).expect("a development run");
    assert_eq!(allowed["classes"][4]["state"], "pending");

    edit_lock(&fixture, &|lock| {
        lock["classes"]["service_limits"] = json!({ "state": "unavailable" });
    });
    let refused =
        record::build(root, TARGET, &elsewhere(&fixture), false).expect_err("no capability");
    assert!(
        refused.to_string().contains("which capability"),
        "{refused}"
    );

    edit_lock(&fixture, &|lock| {
        lock["classes"]
            .as_object_mut()
            .expect("classes")
            .remove("service_limits");
    });
    assert!(record::build(root, TARGET, &elsewhere(&fixture), false).is_err());
}

/// KR-REQ-12.33, KR-REQ-01.26: every capability a release enables by evidence cites the
/// qualification of its plugin, and a build whose plugin cites none is refused.
#[test]
fn a_build_whose_plugin_cites_no_qualification_enables_nothing() {
    let build = json!({
        "application": "claude", "distribution": "npm", "version": "2.1.278",
        "os": "mac_os", "architecture": "aarch64", "executable_digest": "ab".repeat(32),
    });
    let mut index = no_builds();
    index["entries"][0]["builds"] = json!([build]);
    let fixture = fixture(&index);
    let refused = record::build(fixture.checkout.path(), TARGET, &elsewhere(&fixture), false)
        .expect_err("no evidence");
    assert!(refused.to_string().contains("no evidence"), "{refused}");

    // With a qualification cited, the capability is enabled with it; for another platform's build
    // nothing is enabled.
    let mut index = no_builds();
    index["entries"][0]["builds"] = json!([build]);
    index["entries"][0]["qualification"] = json!([{ "record": "notes#claude" }]);
    let fixture = self::fixture(&index);
    let made = record::build(fixture.checkout.path(), TARGET, &elsewhere(&fixture), false)
        .expect("a record");
    assert_eq!(made["capabilities"][0]["capability"], "x.y");
    assert_eq!(
        made["capabilities"][0]["qualification"][0]["record"],
        "notes#claude"
    );
    let elsewhere_made = record::build(
        fixture.checkout.path(),
        "x86_64-unknown-linux-gnu",
        &elsewhere(&fixture),
        false,
    )
    .expect("a record");
    assert_eq!(elsewhere_made["capabilities"], json!([]));
}

/// The record this repository's lock makes, with no other repository at hand: every class is
/// recorded and every file the lock lists is here.
#[test]
fn this_repository_s_lock_makes_a_record() {
    let checkout: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let made = record::build(&checkout, TARGET, &Elsewhere::default(), false).expect("a record");
    let classes = made["classes"].as_array().expect("classes");
    assert!(classes.iter().all(|class| class["state"] == "recorded"));
    assert!(classes[2]["records"].as_array().expect("profiles").len() >= 2);
}
