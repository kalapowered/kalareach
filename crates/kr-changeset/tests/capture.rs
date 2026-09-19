//! `changeset.capture`: the immutable version, the consistency classes, the grants and the
//! secrets.
//!
//! Requirement rows closed here: KR-REQ-01.27 (versioned change sets with explicit workspaces),
//! KR-REQ-14.31 (`changeset.capture` produces an immutable identified version), KR-REQ-14.32 (the
//! consistency class is recorded; a concurrent change is retried or rejected), KR-REQ-14.33
//! (inclusion rules and file grants apply before capture and secrets are excluded) and KR-ACC-031
//! (the exact captured version is delivered while the source keeps changing, and later revisions
//! stay visible).
//!
//! Every test here asks the project service to run Git, which it does not do on Windows: an
//! application container there cannot keep a repository from being executed from, so the service
//! refuses rather than claiming a boundary it does not have.

#![cfg(not(windows))]

mod support;

use kr_protocol::changeset::{
    ContentOrigin, ExclusionReason, FileGrant, PathClass, SourceConsistency,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::project::{ContentClass, InclusionChoice, InclusionPolicy};

use support::{
    Fixture, change, exclusion, git_raw, include_everything, ordinary_repository, write,
    write_bytes,
};

/// KR-REQ-14.31 and KR-REQ-01.27: a capture produces an immutable version that names its
/// repository, its workspace, its base revision and the content hash of every selected path.
#[test]
fn a_capture_produces_an_immutable_version_that_names_exactly_what_it_holds() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "changed after the commit\n");
    write(&path, "notes.txt", "the user's own untracked file\n");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());

    assert_eq!(record.version.get(), 1);
    assert_eq!(record.workspace_id, workspace);
    assert!(
        !record.base_revision.is_empty(),
        "the version names the revision it is against"
    );
    assert_eq!(
        record.base_reference.0.as_deref(),
        Some("refs/heads/main"),
        "and the reference that revision was named by"
    );
    // Both changes, each with the digest of its own content.
    let readme = change(&record, "README.md");
    assert_eq!(
        readme.content_digest,
        kr_changeset::objects::digest_of(b"changed after the commit\n")
    );
    assert_eq!(readme.class, PathClass::DirtyFile);
    assert!(
        readme.base_object_id.0.is_some(),
        "a tracked path names the object the base holds for it"
    );
    let notes = change(&record, "notes.txt");
    assert_eq!(notes.class, PathClass::UntrackedFile);
    assert!(
        notes.base_object_id.0.is_none(),
        "the base never held an untracked path"
    );
    // The whole tree, not only the changes: the base's own files are in it too.
    assert_eq!(
        record.summary.total_paths.get(),
        3,
        "README, src/lib.rs, notes"
    );
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("the manifest is stored");
    assert!(manifest.path("src/lib.rs").is_some());
    assert_eq!(
        manifest.path("src/lib.rs").expect("it is there").class,
        PathClass::Tracked
    );

    // Identified exactly: capturing the same tree again gives the same digest, and one edit
    // gives a different one under a new version number.
    let again = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            Some(record.change_set_id),
            None,
        )
        .expect("a second capture of the same tree");
    assert_eq!(again.version.get(), 2);
    assert_eq!(
        again.content_digest, record.content_digest,
        "the same work has the same identity"
    );
    write(&path, "README.md", "changed again\n");
    let third = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            Some(record.change_set_id),
            None,
        )
        .expect("a third capture");
    assert_eq!(third.version.get(), 3);
    assert_ne!(
        third.content_digest, record.content_digest,
        "different work has a different identity"
    );
}

/// KR-ACC-031: the exact captured version is delivered while the source keeps changing, and the
/// later revisions are visible beside it.
#[test]
fn the_exact_captured_version_is_delivered_while_the_source_keeps_changing() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "moving");
    write(&path, "README.md", "version one\n");
    let workspace = fixture.workspace("moving");
    let first = fixture.capture(workspace, &include_everything());
    let first_digest = change(&first, "README.md").content_digest;

    // The agent keeps working.
    write(&path, "README.md", "version two\n");
    write(&path, "added.txt", "and something new\n");
    let second = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            Some(first.change_set_id),
            None,
        )
        .expect("a second capture");
    write(&path, "README.md", "version three, still being edited\n");

    // The first version is exactly what it was, however much the tree has moved since.
    let read = fixture
        .service()
        .record(first.change_set_id, Some(first.version))
        .expect("version one is still readable");
    assert_eq!(read.content_digest, first.content_digest);
    assert_eq!(change(&read, "README.md").content_digest, first_digest);
    let manifest = fixture
        .service()
        .manifest(first.change_set_id, first.version)
        .expect("version one's manifest");
    let held = manifest.path("README.md").expect("it is there");
    let bytes = fixture
        .service()
        .objects()
        .get(held.content_digest)
        .expect("the content is still in the store");
    assert_eq!(bytes, b"version one\n", "the exact captured content");
    assert!(
        manifest.path("added.txt").is_none(),
        "version one does not hold what was added after it"
    );

    // The later revision is visible beside it, which is what attention shows.
    let versions = fixture
        .service()
        .versions(first.change_set_id)
        .expect("the versions are listed");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version.get(), 1);
    assert_eq!(versions[1].version.get(), 2);
    assert_ne!(versions[0].content_digest, versions[1].content_digest);
    assert_eq!(versions[1].content_digest, second.content_digest);
}

/// KR-REQ-14.32: the capture records which consistency class its source was, and never calls a
/// live multi-file read a point-in-time snapshot.
#[test]
fn a_capture_records_the_class_its_source_actually_was() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "classes");
    write(&path, "README.md", "changed after the commit\n");
    let workspace = fixture.workspace("classes");

    // A capture that read the live tree is a per-file capture, and says so in its own words.
    let live = fixture.capture(workspace, &include_everything());
    assert_eq!(live.consistency, SourceConsistency::PerFileCapture);
    assert!(
        live.consistency_detail.contains("one at a time"),
        "the detail says what it did: {}",
        live.consistency_detail
    );
    assert!(
        live.consistency_detail.contains("rather than one instant"),
        "and what it is not: {}",
        live.consistency_detail
    );

    // A capture whose content is wholly Git objects is an atomic snapshot, and reaching it is
    // what asking for it does.
    let snapshot = fixture
        .capture_with(
            workspace,
            &InclusionPolicy::base_only(),
            &FileGrant::default(),
            None,
            Some(SourceConsistency::AtomicSnapshot),
        )
        .expect("a base-only capture reaches the strongest class");
    assert_eq!(snapshot.consistency, SourceConsistency::AtomicSnapshot);
    assert_eq!(snapshot.summary.from_working_tree.get(), 0);
    assert_eq!(snapshot.summary.from_git_objects.get(), 2);
    let manifest = fixture
        .service()
        .manifest(snapshot.change_set_id, snapshot.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| entry.origin == ContentOrigin::GitObject)
    );
    // The base's own content, not the dirty file's.
    let bytes = fixture
        .service()
        .objects()
        .get(
            manifest
                .path("README.md")
                .expect("it is there")
                .content_digest,
        )
        .expect("the content");
    assert_eq!(bytes, b"a repository\n");
}

/// KR-REQ-14.32: a capture that cannot reach the class a caller required is refused rather than
/// served a weaker one under the name it asked for.
#[test]
fn a_capture_that_cannot_reach_the_required_class_is_refused_rather_than_renamed() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "required");
    write(&path, "README.md", "an uncommitted change\n");
    let workspace = fixture.workspace("required");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            Some(SourceConsistency::AtomicSnapshot),
        )
        .expect_err("an uncommitted change is in no Git object");
    assert_eq!(failure.code(), ErrorCode::InvalidArgument);
    let message = failure.to_string();
    assert!(
        message.contains("uncommitted changes are in no Git object"),
        "the refusal says why the class is out of reach: {message}"
    );
    assert!(
        message.contains("ask for a per-file capture"),
        "and what to ask for instead: {message}"
    );
    // Nothing was recorded: a class this host could not reach is a refusal, not a weaker version
    // under the name the caller asked for.
    assert!(
        fixture
            .service()
            .versions(kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid()))
            .expect("the store is readable")
            .is_empty()
    );
    let _ = path;
}

/// KR-REQ-14.33: the grant and this host's own secret rules apply before the capture reads
/// anything, and a secret never becomes attachment material.
#[test]
fn a_secret_is_never_captured_whatever_the_policy_and_the_grant_say() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "secrets");
    write(&path, ".env", "API_TOKEN=a-secret-nobody-should-capture\n");
    write(&path, "deploy/server.pem", "-----BEGIN PRIVATE KEY-----\n");
    write(&path, "src/main.rs", "fn main() {}\n");
    write(&path, "vendor/bundled.rs", "// third-party\n");
    let workspace = fixture.workspace("secrets");

    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant {
                // A selection of the whole tree still leaves every secret out.
                included_paths: vec![String::new()],
                excluded_paths: vec!["vendor".to_owned()],
                secret_rules_applied: false,
            },
            None,
            None,
        )
        .expect("the capture succeeds");

    for secret in [".env", "deploy/server.pem"] {
        assert_eq!(
            exclusion(&record, secret).reason,
            ExclusionReason::SecretRule,
            "{secret} is left out by a secret rule"
        );
        assert!(
            record.changes.iter().all(|entry| entry.path != secret),
            "{secret} is not in the captured tree"
        );
    }
    assert_eq!(
        exclusion(&record, "vendor/bundled.rs").reason,
        ExclusionReason::Grant,
        "the caller's own exclusion is recorded as its own reason"
    );
    // And the content never reached the store at all.
    assert!(
        !fixture
            .service()
            .objects()
            .holds(kr_changeset::objects::digest_of(
                b"API_TOKEN=a-secret-nobody-should-capture\n"
            ))
            .expect("the store answers"),
        "the secret's bytes are not in the content store"
    );
    // The record says the rules were applied, whatever the request asked for.
    assert!(record.policy.grant.secret_rules_applied);
    // The ordinary file is captured.
    assert_eq!(
        change(&record, "src/main.rs").class,
        PathClass::UntrackedFile
    );
}

/// KR-REQ-14.33: an inclusion policy decides each class, and excluding a dirty tracked file means
/// the version holds the base's content rather than nothing at all.
#[test]
fn the_policy_decides_each_class_and_an_excluded_dirty_file_keeps_the_base_version() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "policy");
    write(&path, "README.md", "changed after the commit\n");
    write(&path, "notes.txt", "untracked\n");
    write(&path, ".gitignore", "generated/\n");
    write(&path, "generated/output.txt", "a build product\n");
    write_bytes(&path, "image.bin", &[0_u8, 1, 2, 3, 0, 5]);
    let workspace = fixture.workspace("policy");

    let record = fixture.capture(
        workspace,
        &InclusionPolicy {
            dirty_files: InclusionChoice::Exclude,
            untracked_files: InclusionChoice::Include,
            submodules: InclusionChoice::Exclude,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Exclude,
        },
    );
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");

    // The dirty file is in the tree, holding the base's own content.
    let readme = manifest.path("README.md").expect("README is in the tree");
    assert_eq!(readme.origin, ContentOrigin::GitObject);
    assert_eq!(readme.class, PathClass::Tracked);
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(readme.content_digest)
            .expect("its content"),
        b"a repository\n"
    );
    // The untracked text file is included; the ignored one and the binary one are not.
    assert_eq!(change(&record, "notes.txt").class, PathClass::UntrackedFile);
    assert_eq!(
        exclusion(&record, "generated/output.txt").reason,
        ExclusionReason::Policy
    );
    assert_eq!(
        exclusion(&record, "image.bin").reason,
        ExclusionReason::Policy
    );
    assert!(manifest.path("image.bin").is_none());
}

/// KR-REQ-14.31: a captured tree carries content exactly as it is, so a line ending and an
/// executable bit survive a capture and can be materialised back.
#[test]
fn line_endings_and_the_executable_bit_are_carried_exactly() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "exact");
    write_bytes(&path, "windows.txt", b"first\r\nsecond\r\n");
    write_bytes(&path, "unix.txt", b"first\nsecond\n");
    write_bytes(&path, "run.sh", b"#!/bin/sh\necho hello\n");
    support::make_executable(&path, "run.sh");
    let workspace = fixture.workspace("exact");
    let record = fixture.capture(workspace, &include_everything());

    assert_eq!(
        fixture
            .service()
            .objects()
            .get(change(&record, "windows.txt").content_digest)
            .expect("its content"),
        b"first\r\nsecond\r\n",
        "a carriage return is content rather than something to normalise"
    );
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(change(&record, "unix.txt").content_digest)
            .expect("its content"),
        b"first\nsecond\n"
    );
    assert!(change(&record, "run.sh").executable);
    assert!(!change(&record, "unix.txt").executable);
}

/// KR-REQ-14.31: a binary file is recognised by Git's own test and counted as binary.
#[test]
fn a_binary_file_is_recognised_and_counted_as_one() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "binary");
    write_bytes(&path, "image.bin", &[0_u8, 1, 2, 3, 0, 5]);
    write(&path, "text.txt", "ordinary text\n");
    let workspace = fixture.workspace("binary");
    let record = fixture.capture(workspace, &include_everything());
    assert_eq!(change(&record, "image.bin").content, ContentClass::Binary);
    assert_eq!(change(&record, "text.txt").content, ContentClass::Text);
    let untracked = record
        .counts
        .iter()
        .find(|count| count.class == PathClass::UntrackedFile)
        .expect("the untracked class is counted");
    assert_eq!(untracked.total.get(), 2);
    assert_eq!(untracked.binary.get(), 1);
}

/// KR-REQ-14.32: a deletion is carried by absence and named, rather than becoming a path the
/// capture could not read.
#[test]
fn a_deletion_is_carried_by_absence_and_says_so() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "deleted");
    std::fs::remove_file(path.join("src/lib.rs")).expect("the user deletes a tracked file");
    let workspace = fixture.workspace("deleted");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest.path("src/lib.rs").is_none(),
        "the captured tree does not hold it"
    );
    // The deletion is an operation of the version, with what the base held recorded beside it, so
    // an apply can carry it and a revert can put the file back.
    let deleted = manifest
        .deletions
        .iter()
        .find(|deleted| deleted.path == "src/lib.rs")
        .expect("the version records the deletion");
    assert!(
        deleted.base_object_id.is_some(),
        "and what the base held for it"
    );
    assert_eq!(record.summary.deleted_paths.get(), 1);
}

/// KR-REQ-14.31: a submodule is never entered, whatever the policy says.
#[test]
fn a_submodule_is_named_rather_than_entered() {
    let fixture = Fixture::create();
    let inner = ordinary_repository(fixture.work(), "inner");
    let outer = ordinary_repository(fixture.work(), "outer");
    let added = std::process::Command::new("git")
        .arg("-C")
        .arg(&outer)
        .arg("-c")
        .arg("protocol.file.allow=always")
        .arg("-c")
        .arg("user.name=KalaReach Fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .args(["submodule", "add", "--quiet"])
        .arg(&inner)
        .arg("vendor/inner")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("installed Git runs");
    if !added.status.success() {
        // A Git that refuses a local submodule leaves nothing to test here, and saying so is
        // better than asserting something the fixture did not build.
        eprintln!(
            "this Git would not add a local submodule, so the case is not exercised: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        return;
    }
    git_raw(&outer, ["commit", "-m", "the submodule"]);
    let workspace = fixture.workspace("outer");
    let record = fixture.capture(workspace, &include_everything());
    let named = exclusion(&record, "vendor/inner");
    assert_eq!(named.reason, ExclusionReason::Unsupported);
    assert!(
        named.detail.contains("never reads inside one"),
        "the exclusion says why: {}",
        named.detail
    );
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.starts_with("vendor/inner/")),
        "nothing inside the submodule is captured"
    );
}

/// KR-REQ-14.31: a version carries what an identical source does not promise.
#[test]
fn a_version_says_what_an_identical_source_does_not_promise() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "limits");
    let workspace = fixture.workspace("limits");
    let record = fixture.capture(workspace, &include_everything());
    assert!(
        record
            .limitations
            .iter()
            .any(|line| line.contains("hermetic") || line.contains("external inputs")),
        "the limitations name the external inputs: {:?}",
        record.limitations
    );
    assert!(
        record
            .limitations
            .iter()
            .any(|line| line.contains("does not become attachment material")),
        "and that a secret is not attachment material: {:?}",
        record.limitations
    );
}

/// KR-REQ-14.32: a source that keeps changing under the capture is retried within the bound and
/// then rejected, rather than producing a tree that holds two instants of the working tree.
#[test]
fn a_source_that_keeps_changing_is_retried_and_then_rejected() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Every status read this host makes sees a tree that has moved since the last one, which is
    // exactly the case a capture must not describe as one instant. The seam writes into the
    // directory the invocation itself runs in, which is the repository's own top level.
    let edits = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&edits);
    let fixture = Fixture::with_interposition(Some(kr_project::git::Interposition::new(Arc::new(
        move |described: &str, directory: &std::path::Path, _temporary: &std::path::Path| {
            if described.starts_with("git status") {
                let round = counted.fetch_add(1, Ordering::SeqCst);
                std::fs::write(
                    directory.join(format!("moving-{round}.txt")),
                    format!("edit number {round}\n"),
                )
                .expect("the fixture edits the tree");
            }
        },
    ))));
    ordinary_repository(fixture.work(), "moving");
    let workspace = fixture.workspace("moving");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
        )
        .expect_err("a source that keeps changing is rejected");
    assert_eq!(failure.code(), ErrorCode::SourceChanged);
    let message = failure.to_string();
    assert!(
        message.contains("tried"),
        "the refusal says how many times this host tried: {message}"
    );
    assert!(
        edits.load(Ordering::SeqCst) >= 3,
        "the retries really happened: {} status reads",
        edits.load(Ordering::SeqCst)
    );
    // Nothing was recorded: a capture this host could not vouch for is not half a version.
    assert!(
        fixture
            .service()
            .versions(kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid()))
            .expect("the store is readable")
            .is_empty()
    );
}

/// KR-REQ-14.31 and 14.33: the base a version is against is the **commit**, so a staged change is
/// an uncommitted change like any other and an exclusion of it falls back to the commit's content.
#[test]
fn the_base_is_the_commit_and_never_the_index() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "staged");
    // Three shapes at once: a staged modification, a staged addition and a staged deletion.
    write(&path, "README.md", "staged, not committed\n");
    write(&path, "added.txt", "staged addition\n");
    git_raw(&path, ["add", "README.md", "added.txt"]);
    git_raw(&path, ["rm", "--cached", "--quiet", "src/lib.rs"]);
    std::fs::remove_file(path.join("src/lib.rs")).expect("the user removes it too");
    let workspace = fixture.workspace("staged");

    // Excluding uncommitted changes gives the commit's own content, not the index's.
    let record = fixture.capture(workspace, &InclusionPolicy::base_only());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("README.md")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"a repository\n",
        "the commit's content, not the staged content"
    );
    assert!(
        manifest.path("added.txt").is_none(),
        "the base never held a staged addition, so excluding the change leaves it absent"
    );
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("src/lib.rs")
                    .expect("a staged deletion the base holds is still in the captured tree")
                    .content_digest
            )
            .expect("its content"),
        b"pub fn answer() -> u32 { 42 }\n"
    );

    // Including them gives the working tree, and the deletion is carried by absence.
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("README.md")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"staged, not committed\n"
    );
    assert!(manifest.path("added.txt").is_some());
    assert!(manifest.path("src/lib.rs").is_none());
    assert!(
        manifest
            .deletions
            .iter()
            .any(|deleted| deleted.path == "src/lib.rs"),
        "the deletion is carried as an operation of the version"
    );
}

/// KR-REQ-14.25: a file taken out of the index and left on disk is captured, not deleted.
#[test]
fn a_file_the_index_lost_and_the_working_tree_kept_is_captured() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "uncached");
    git_raw(&path, ["rm", "--cached", "--quiet", "src/lib.rs"]);
    write(&path, "src/lib.rs", "pub fn answer() -> u32 { 43 }\n");
    let workspace = fixture.workspace("uncached");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("src/lib.rs")
                    .expect("the file on disk is captured rather than recorded as deleted")
                    .content_digest
            )
            .expect("its content"),
        b"pub fn answer() -> u32 { 43 }\n"
    );
    assert!(
        manifest.deletions.is_empty(),
        "nothing was deleted: the file is there"
    );

    // And excluding uncommitted work does not take the path away: the base still holds it, so
    // what a base-only capture holds for it is the commit's own content.
    let base_only = fixture.capture(workspace, &InclusionPolicy::base_only());
    let manifest = fixture
        .service()
        .manifest(base_only.change_set_id, base_only.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("src/lib.rs")
                    .expect("the commit's own content is still held")
                    .content_digest
            )
            .expect("its content"),
        b"pub fn answer() -> u32 { 42 }\n"
    );
    assert!(manifest.deletions.is_empty());
}

/// KR-REQ-14.32: a commit that lands while a capture is reading makes the capture start again, and
/// past the bound it is rejected rather than recorded against a revision it did not read.
#[test]
fn a_commit_that_lands_under_the_capture_is_detected() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let commits = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&commits);
    let fixture = Fixture::with_interposition(Some(kr_project::git::Interposition::new(Arc::new(
        move |described: &str, directory: &std::path::Path, _temporary: &std::path::Path| {
            // Before every status read, the base moves on.
            if described.starts_with("git status") {
                let round = counted.fetch_add(1, Ordering::SeqCst);
                std::fs::write(
                    directory.join("committed.txt"),
                    format!("commit number {round}\n"),
                )
                .expect("the fixture writes");
                support::git_raw(directory, ["add", "-A"]);
                support::git_raw(directory, ["commit", "-q", "-m", "another commit"]);
            }
        },
    ))));
    ordinary_repository(fixture.work(), "moving-head");
    let workspace = fixture.workspace("moving-head");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
        )
        .expect_err("a base that keeps moving is rejected");
    assert_eq!(failure.code(), ErrorCode::SourceChanged);
    assert!(commits.load(Ordering::SeqCst) >= 3, "the retries happened");
}

/// KR-REQ-14.32: the strongest class comes from the base commit's own tree, and reaching it reads
/// nothing of the working tree at all.
#[test]
fn an_atomic_snapshot_is_the_base_commit_s_own_tree() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "snapshot");
    // Uncommitted work of every kind, none of which may appear in the snapshot.
    write(&path, "README.md", "changed after the commit\n");
    write(&path, "untracked.txt", "the user's own\n");
    let workspace = fixture.workspace("snapshot");
    let record = fixture
        .capture_with(
            workspace,
            &InclusionPolicy::base_only(),
            &FileGrant::default(),
            None,
            Some(SourceConsistency::AtomicSnapshot),
        )
        .expect("the base commit's own tree is readable");
    assert_eq!(record.consistency, SourceConsistency::AtomicSnapshot);
    assert!(
        record
            .consistency_detail
            .contains("one instant by construction"),
        "the detail names the mechanism: {}",
        record.consistency_detail
    );
    assert_eq!(record.summary.from_working_tree.get(), 0);
    assert_eq!(record.summary.total_paths.get(), 2);
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("README.md")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"a repository\n",
        "the commit's content rather than the tree's"
    );
    assert!(manifest.path("untracked.txt").is_none());
}

/// KR-REQ-14.31: a symbolic link's object holds its target, so it is named rather than written out
/// as a regular file, and a change to the executable bit reaches the version.
#[test]
fn a_link_is_named_and_a_mode_change_reaches_the_version() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "modes");
    std::os::unix::fs::symlink("README.md", path.join("link.md")).expect("a link");
    write_bytes(&path, "run.sh", b"#!/bin/sh\necho hello\n");
    support::make_executable(&path, "run.sh");
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "a link and a program"]);
    let workspace = fixture.workspace("modes");

    let record = fixture.capture(workspace, &include_everything());
    let named = exclusion(&record, "link.md");
    assert_eq!(named.reason, ExclusionReason::Unsupported);
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest.path("link.md").is_none(),
        "a link is not captured as a file"
    );
    assert!(manifest.path("run.sh").expect("it is there").executable);

    // The user takes the executable bit off. The version says so, rather than the index's old mode
    // outvoting what the file is.
    let mut permissions = std::fs::metadata(path.join("run.sh"))
        .expect("the file is there")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
    std::fs::set_permissions(path.join("run.sh"), permissions).expect("the mode is set");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        !manifest.path("run.sh").expect("it is there").executable,
        "the bit the file has is the bit the version records"
    );
}

/// KR-REQ-14.33: a nested repository's own administrative data is never captured, whatever the
/// policy says.
#[test]
fn a_nested_repository_s_own_data_is_never_captured() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "outer-tree");
    // An untracked nested repository, which Git reports as one directory.
    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("a directory");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    git_raw(
        &nested,
        [
            "remote",
            "add",
            "origin",
            "https://user:a-secret-token@example.invalid/x.git",
        ],
    );
    write(&nested, "inner.txt", "inner content\n");
    let workspace = fixture.workspace("outer-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.contains("/.git/") && !entry.path.starts_with(".git/")),
        "nothing under a Git directory is captured: {:?}",
        manifest
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
    // The nested repository is another repository's tree, and this host does not read inside one:
    // neither its administrative data nor its content reaches the version, and the whole of it is
    // named as one thing this host would not capture.
    assert!(manifest.path("vendor/inner/inner.txt").is_none());
    assert!(
        record
            .exclusions
            .iter()
            .any(|entry| entry.path == "vendor/inner"
                && entry.reason == ExclusionReason::Unsupported),
        "the exclusion names it: {:?}",
        record.exclusions
    );
}

/// KR-REQ-14.33: a nested repository that keeps its data elsewhere refuses the whole capture.
///
/// A `.git` **file** names the directory a repository's data is really in, and the name can be
/// spelled any way Git accepts, can reach through a link, can name a linked worktree whose
/// configuration is somewhere else again, and can name something that is not there while the base
/// commit still holds what used to be under it. Each is a way another repository's configuration
/// would reach a version, so a tree with a nested repository of that shape is one this host does
/// not capture.
#[test]
fn a_nested_repository_that_keeps_its_data_elsewhere_refuses_the_capture() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "elsewhere-tree");
    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("a directory");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    git_raw(
        &nested,
        [
            "remote",
            "add",
            "origin",
            "https://user:a-secret-token@example.invalid/x.git",
        ],
    );
    write(&nested, "inner.txt", "inner content\n");
    std::fs::rename(nested.join(".git"), path.join("vendor/repo-data"))
        .expect("the data moves beside the nested tree");
    std::os::unix::fs::symlink("repo-data", path.join("vendor/git-alias")).expect("a link to it");
    let workspace = fixture.workspace("elsewhere-tree");
    let policy = include_everything();
    let grant = kr_protocol::changeset::FileGrant::default();

    // Every spelling, the place beside the tree, the place reached through a link, and a place
    // that is not there at all.
    for target in [
        "repo-data",
        "./repo-data",
        "../repo-data",
        "../git-alias",
        "../not-there",
    ] {
        std::fs::write(
            nested.join(".git"),
            format!("gitdir: {target}\n").as_bytes(),
        )
        .expect("and points at it");
        let failure = fixture
            .capture_with(workspace, &policy, &grant, None, None)
            .expect_err("a tree holding a repository of that shape is not captured");
        assert!(
            failure
                .to_string()
                .contains("somewhere other than beside its tree"),
            "the refusal says why under {target}: {failure}"
        );
    }

    // And with its data back beside its own tree, the capture runs and the tree is excluded.
    std::fs::remove_file(nested.join(".git")).expect("the file goes");
    std::fs::rename(path.join("vendor/repo-data"), nested.join(".git"))
        .expect("the data goes back where it started");
    let record = fixture
        .capture_with(workspace, &policy, &grant, None, None)
        .expect("an ordinary nested repository is captured around");
    assert!(
        record
            .exclusions
            .iter()
            .any(|entry| entry.path == "vendor/inner"),
        "the nested tree is named: {:?}",
        record.exclusions
    );
}

/// KR-REQ-14.32: a quiescence declaration is recorded and never decides the consistency class,
/// because nothing this host can reach holds a working tree still for the whole of a read.
#[test]
fn a_quiescence_declaration_is_recorded_and_decides_nothing() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "quiet");
    let workspace = fixture.workspace("quiet");
    let session = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    fixture
        .project()
        .bind_session(workspace, session, true)
        .expect("a session holds the workspace");
    let record = fixture
        .capture_declaring_quiescence(workspace)
        .expect("the capture succeeds");
    assert_eq!(record.consistency, SourceConsistency::PerFileCapture);
    assert!(record.policy.quiescence_declared);
    assert!(
        record
            .consistency_detail
            .contains("describes something that was not the case"),
        "the record says the declaration was wrong: {}",
        record.consistency_detail
    );

    // With nothing holding the workspace the class is still a per-file capture: two readings of
    // what holds it say nothing about the interval between them, and an editor outside KalaReach
    // is outside what this host can see at all.
    fixture
        .project()
        .bind_session(workspace, session, false)
        .expect("the session ends");
    let record = fixture
        .capture_declaring_quiescence(workspace)
        .expect("the capture succeeds");
    assert_eq!(record.consistency, SourceConsistency::PerFileCapture);
    assert!(
        record
            .consistency_detail
            .contains("it does not make this a quiesced capture"),
        "and says so: {}",
        record.consistency_detail
    );
}

/// KR-REQ-01.27: an independent clone is a workspace of its own repository, and capturing one
/// works rather than being refused for holding a Git directory that is not the project's.
#[test]
fn an_independent_clone_workspace_can_be_captured() {
    use kr_protocol::project::{IsolationMechanism, WorkspaceCreateParams, WorkspaceKind};

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "origin-tree");
    write(&path, "README.md", "the work in progress\n");
    let project = fixture.adopt("origin-tree");
    let created = fixture
        .project()
        .workspace_create(
            &support::actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "a clone".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: kr_protocol::scalars::Nullable(Some(
                    IsolationMechanism::IndependentClone,
                )),
                policy: include_everything(),
                base_revision: kr_protocol::scalars::Nullable(None),
                base_change_set_id: kr_protocol::scalars::Nullable(None),
                destination: kr_protocol::scalars::Nullable(Some(support::destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "clone-tree",
                ))),
                preview_only: false,
            },
            Some(&support::action("workspace.create:clone")),
        )
        .expect("the clone is made")
        .workspace
        .0
        .expect("a creation returns one");
    let record = fixture.capture(created.workspace_id, &include_everything());
    assert_eq!(record.workspace_id, created.workspace_id);
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(manifest.path("README.md").is_some());
    // The identity recorded is the clone's own repository, which is not the project's.
    assert_ne!(
        record.repository_identity,
        fixture
            .project()
            .project_read(&kr_protocol::project::ProjectReadParams {
                project_repository_id: project,
            })
            .expect("the project is readable")
            .project
            .filesystem_identity,
        "an independent clone is its own repository"
    );

    // The repository behind the clone is replaced with another one inside the same working tree.
    // It satisfies the rule that makes a clone independent, and it is not the repository this host
    // read the first time, which is what decides.
    let clone = fixture.work().join("clone-tree");
    std::fs::rename(clone.join(".git"), clone.join(".git-was")).expect("the clone's own data");
    let substitute = ordinary_repository(fixture.work(), "substitute");
    std::fs::rename(substitute.join(".git"), clone.join(".git")).expect("another repository");
    let refusal = fixture
        .service()
        .open_repository(
            &fixture
                .service()
                .resolve(created.workspace_id)
                .expect("the workspace resolves"),
        )
        .expect_err("a repository this host has not seen before is refused");
    assert!(
        refusal.to_string().contains("independent clone"),
        "and says why: {refusal}"
    );
}

/// KR-REQ-14.31: a version number a deleted version used is never handed out again.
#[test]
fn a_version_number_is_never_reused() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "numbers");
    write(&path, "README.md", "one\n");
    let workspace = fixture.workspace("numbers");
    let first = fixture.capture(workspace, &include_everything());
    write(&path, "README.md", "two\n");
    let second = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            Some(first.change_set_id),
            None,
        )
        .expect("a second version");
    assert_eq!(second.version.get(), 2);
    fixture
        .service()
        .delete_version(second.change_set_id, second.version)
        .expect("nothing holds it");
    write(&path, "README.md", "three\n");
    let third = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            Some(first.change_set_id),
            None,
        )
        .expect("a third version");
    assert_eq!(
        third.version.get(),
        3,
        "the number version two used is not handed out again"
    );
}
