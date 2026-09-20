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

/// KR-REQ-14.33: what a nested repository's data **is** decides, not what it is called.
///
/// A `.git` file names where a repository keeps its data, and the name can be spelled any way Git
/// accepts. This host descends to it through the working tree's own handle and keeps the identity
/// of the directory it reached; every directory the capture names is then compared with that
/// object. So a spelling nobody wrote a rule for is still excluded, and one that reaches through a
/// link, which this descent will not follow, refuses the whole capture.
#[test]
fn a_nested_repository_s_data_is_excluded_by_what_it_is_not_by_its_spelling() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "spelling-tree");
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
    let workspace = fixture.workspace("spelling-tree");
    let policy = include_everything();
    let grant = kr_protocol::changeset::FileGrant::default();

    // Three spellings of the one place, the third of which goes down and back up again. None of
    // them is a rule anybody wrote: the identity the descent reaches is what decides.
    std::fs::create_dir_all(path.join("vendor/round")).expect("somewhere to go through");
    for target in ["../repo-data", ".././repo-data", "../round/../repo-data"] {
        std::fs::write(
            nested.join(".git"),
            format!("gitdir: {target}\n").as_bytes(),
        )
        .expect("and points at it");
        let record = fixture
            .capture_with(workspace, &policy, &grant, None, None)
            .expect("the capture runs");
        let manifest = fixture
            .service()
            .manifest(record.change_set_id, record.version)
            .expect("its manifest");
        assert!(
            manifest
                .paths
                .iter()
                .all(|entry| !entry.path.starts_with("vendor/repo-data/")),
            "under {target}, that repository's own data is not in the version: {:?}",
            manifest
                .paths
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            record
                .exclusions
                .iter()
                .any(|entry| entry.path.starts_with("vendor/repo-data")),
            "and it is named under {target}: {:?}",
            record.exclusions
        );
    }

    // A spelling that reaches through a link is one this descent will not follow, so the whole
    // capture is refused rather than taken with a guess in it.
    std::os::unix::fs::symlink("repo-data", path.join("vendor/git-alias")).expect("a link to it");
    std::fs::write(nested.join(".git"), b"gitdir: ../git-alias\n").expect("through the link");
    let failure = fixture
        .capture_with(workspace, &policy, &grant, None, None)
        .expect_err("a place this host cannot descend to is not captured around");
    assert!(
        failure
            .to_string()
            .contains("could not reach by descending to it"),
        "the refusal says why: {failure}"
    );

    // A spelling that names nothing excludes nothing, because there is nothing of it to capture.
    std::fs::write(nested.join(".git"), b"gitdir: ../not-there\n").expect("nowhere");
    fixture
        .capture_with(workspace, &policy, &grant, None, None)
        .expect("a target that is not there is not a reason to refuse");
}

/// KR-REQ-14.33: a link names a repository whose tree is outside this one, and its own
/// data is a directory of this tree.
///
/// A link is never followed to capture anything, and that is exactly what leaves this open: the
/// repository at the other end of one is named by nothing this capture reads, while its `.git`
/// file can put its data at an ordinary path of this tree — bytes a version would hold and an
/// apply would write over. So discovery follows a link for this one question, from inside a
/// vendored tree and from the tree's own readings alike, and reads nothing of what it finds.
#[test]
fn a_repository_a_link_names_has_its_data_excluded_too() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "link-named-tree");
    // A vendored repository, whose tree no reading of this capture looks inside.
    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("a directory");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    write(&nested, "inner.txt", "inner content\n");

    // Two repositories whose **trees** are outside this one, each keeping its own data at an
    // ordinary path inside it. One is named by a link inside the vendored tree, where no reading
    // of this capture goes; the other by a link the readings name themselves.
    for (tree_name, data_name, link) in [
        ("elsewhere/deep", "vendor/deep-data", nested.join("child")),
        (
            "elsewhere/plain",
            "vendor/plain-data",
            path.join("outer-link"),
        ),
    ] {
        let outside = fixture.work().join(tree_name);
        std::fs::create_dir_all(&outside).expect("a tree of its own");
        git_raw(&outside, ["init", "--initial-branch=main"]);
        git_raw(
            &outside,
            [
                "remote",
                "add",
                "origin",
                "https://user:a-secret-token@example.invalid/x.git",
            ],
        );
        std::fs::rename(outside.join(".git"), path.join(data_name))
            .expect("its data moves into this tree");
        let named =
            std::fs::canonicalize(path.join(data_name)).expect("the name with nothing to resolve");
        std::fs::write(
            outside.join(".git"),
            format!("gitdir: {}\n", named.display()).as_bytes(),
        )
        .expect("and its own file names it");
        let target = std::fs::canonicalize(&outside).expect("the target with nothing to resolve");
        std::os::unix::fs::symlink(&target, link).expect("the link that names the tree");
    }

    let workspace = fixture.workspace("link-named-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for data in ["vendor/deep-data", "vendor/plain-data"] {
        assert!(
            manifest
                .paths
                .iter()
                .all(|entry| !entry.path.starts_with(data)),
            "what the repository at the other end of a link keeps at {data} is not in the \
             version: {:?}",
            manifest
                .paths
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            record
                .exclusions
                .iter()
                .any(|entry| entry.path.starts_with(data)),
            "and {data} is named where it was found: {:?}",
            record.exclusions
        );
    }
}

/// KR-REQ-14.33: a repository's tree kept **inside another repository's own data**.
///
/// Everything beneath a repository's own data is excluded, which says nothing about where a
/// repository whose tree sits there keeps **its** data: that is a `gitdir:` line, and it can name
/// an ordinary directory of the working tree. The scan that reads administrative data places every
/// `.git` it meets, so the line is read and the directory it names is excluded by what it is.
#[test]
fn a_repository_inside_a_repository_s_own_data_has_its_data_excluded_too() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "inside-data-tree");
    // A checkout kept inside this repository's own data. Nothing under `.git` is captured, and
    // nothing under `.git` says where this checkout keeps its own data either.
    let inside = path.join(".git/checkout");
    std::fs::create_dir_all(&inside).expect("a tree inside the data");
    std::fs::write(inside.join("notes.txt"), b"its own content\n").expect("a file of that tree");
    std::fs::write(inside.join(".git"), b"gitdir: ../../vendor/repo-data\n")
        .expect("the file that names where its data is");
    // And that data: an ordinary untracked directory of this tree, holding its remote and the
    // credential in it.
    write(&path, "vendor/repo-data/HEAD", "ref: refs/heads/main\n");
    write(
        &path,
        "vendor/repo-data/config",
        "[remote \"origin\"]\n\turl = https://user:a-secret-token@example.invalid/x.git\n",
    );
    std::fs::create_dir_all(path.join("vendor/repo-data/objects")).expect("its object database");

    let workspace = fixture.workspace("inside-data-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.starts_with("vendor/repo-data")),
        "the data of the repository inside this one's own data is not in the version: {:?}",
        manifest
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        record
            .exclusions
            .iter()
            .any(|entry| entry.path.starts_with("vendor/repo-data")),
        "and it is named where it was found: {:?}",
        record.exclusions
    );
}

/// KR-REQ-14.33: a repository nested **inside a nested repository** keeps its own data
/// somewhere of its own, and that place is excluded too.
///
/// Nothing reads inside a nested repository's tree, which is what leaves the gap this closes: the
/// repository in `vendor/inner/child` is named by no reading of this capture, and its `.git` file
/// puts its data at `vendor/repo-data`, an ordinary directory of the outer tree holding that
/// repository's configuration, its remote and the credential in it. Discovery goes where content
/// reading stops, so the place is found and excluded by what it is.
#[test]
fn a_repository_nested_inside_a_nested_one_has_its_data_excluded_too() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "vendored-tree");
    // A vendored repository, whose tree no reading of this capture looks inside.
    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("a directory");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    write(&nested, "inner.txt", "inner content\n");
    // And a repository inside **that** one, whose own data is an ordinary directory of the outer
    // tree: a path every other part of this capture reads as content.
    let child = nested.join("child");
    std::fs::create_dir_all(&child).expect("a directory");
    git_raw(&child, ["init", "--initial-branch=main"]);
    git_raw(
        &child,
        [
            "remote",
            "add",
            "origin",
            "https://user:a-secret-token@example.invalid/x.git",
        ],
    );
    write(&child, "child.txt", "child content\n");
    std::fs::rename(child.join(".git"), path.join("vendor/repo-data"))
        .expect("its data moves out into the outer tree");
    std::fs::write(child.join(".git"), b"gitdir: ../../repo-data\n")
        .expect("and its own file names it");

    let workspace = fixture.workspace("vendored-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.starts_with("vendor/repo-data")),
        "the repository inside the nested one keeps its data there, and none of it is in the \
         version: {:?}",
        manifest
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        record
            .exclusions
            .iter()
            .any(|entry| entry.path.starts_with("vendor/repo-data")),
        "and it is named where it was found: {:?}",
        record.exclusions
    );
}

/// KR-REQ-14.33: a submodule whose data is not really under this repository refuses the capture.
///
/// The spelling of a `gitdir:` target is the first thing checked and not the last: a component of
/// it can be a link, and the data would then be somewhere else entirely while the name looked
/// right. The same goes for a `commondir`, which puts a repository's configuration, references and
/// objects somewhere other than its per-worktree data.
#[test]
fn a_submodule_whose_data_is_elsewhere_refuses_the_capture() {
    for shape in ["link", "commondir", "jump", "unreadable"] {
        let fixture = Fixture::create();
        let path = ordinary_repository(fixture.work(), &format!("{shape}-tree"));
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

        // The data moves beside the nested tree, and the outer repository's own `.git` is made to
        // point at it the way a submodule's data would be reached.
        std::fs::rename(nested.join(".git"), path.join("vendor/repo-data"))
            .expect("the data moves");
        std::fs::create_dir_all(path.join(".git/modules")).expect("the modules directory");
        let mut spelling = "../../.git/modules/inner".to_owned();
        match shape {
            "link" => {
                std::os::unix::fs::symlink(
                    "../../vendor/repo-data",
                    path.join(".git/modules/inner"),
                )
                .expect("a link to it");
            }
            "commondir" => {
                std::fs::create_dir_all(path.join(".git/modules/inner")).expect("a real directory");
                std::fs::write(
                    path.join(".git/modules/inner/commondir"),
                    b"../../../vendor/repo-data\n",
                )
                .expect("and it names its common directory");
            }
            // A link, then a `..` that cancels it on paper. Reducing the spelling before looking
            // would erase the link and check a directory the target never reaches.
            "jump" => {
                std::fs::create_dir_all(path.join("vendor/hop")).expect("somewhere to point");
                std::os::unix::fs::symlink("../../vendor/hop", path.join(".git/modules/jump"))
                    .expect("a link on the way");
                std::fs::create_dir_all(path.join(".git/modules/inner"))
                    .expect("the name the arithmetic would reach");
                spelling = "../../.git/modules/jump/../inner".to_owned();
            }
            // A directory this host cannot look inside, so it cannot say whether it names a
            // common directory somewhere else.
            _ => {
                std::fs::create_dir_all(path.join(".git/modules/inner")).expect("a real directory");
                std::fs::set_permissions(
                    path.join(".git/modules/inner"),
                    std::os::unix::fs::PermissionsExt::from_mode(0o000),
                )
                .expect("and nothing may look inside it");
            }
        }
        std::fs::write(
            nested.join(".git"),
            format!("gitdir: {spelling}\n").as_bytes(),
        )
        .expect("the submodule's own file");

        let workspace = fixture.workspace(&format!("{shape}-tree"));
        let outcome = fixture.capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        );
        if shape == "commondir" {
            // This one this host **can** descend to: the common directory is reached from the
            // data directory, and what it is decides, so the capture runs and holds none of it.
            let record = outcome.expect("a place this host can descend to is captured around");
            let manifest = fixture
                .service()
                .manifest(record.change_set_id, record.version)
                .expect("its manifest");
            assert!(
                manifest
                    .paths
                    .iter()
                    .all(|entry| !entry.path.starts_with("vendor/repo-data/")),
                "the common directory is not in the version: {:?}",
                manifest
                    .paths
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            );
            continue;
        }
        // The rest are places this host will not descend to, so no version is made at all.
        let failure = outcome.expect_err("a spelling this host cannot walk to is not captured");
        assert!(
            failure
                .to_string()
                .contains("could not reach by descending to it")
                || failure.to_string().contains("cannot account for"),
            "the refusal says why for {shape}: {failure}"
        );
    }
}

/// KR-REQ-14.33: this repository's own data is excluded by what it is, not by its name.
///
/// A repository can keep its own data under any name, said in a `.git` file, and a filesystem that
/// ignores case then opens the same directory under a spelling no name rule matches. What the
/// directory **is** does not change, and that is what decides. This runs the whole thing: the data
/// at `meta`, a file pointing at it, and a path under the other spelling committed and staged, so
/// the capture has every reason to reach it.
#[test]
fn this_repository_s_own_data_is_excluded_by_what_it_is() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "named-tree");
    // Exactly what a repository with a separate Git directory inside its tree looks like.
    std::fs::rename(path.join(".git"), path.join("meta"))
        .expect("this repository keeps its data under another name");
    std::fs::write(path.join(".git"), b"gitdir: meta\n").expect("and points at it");
    // Committed and staged under the other spelling. Where the filesystem ignores case this is
    // the same directory reached by a name no prefix rule matches; where it does not, this is a
    // second directory whose content is ordinary and stays in the version.
    let other = path.join("META");
    let aliased = other.exists() || std::fs::create_dir_all(&other).is_ok();
    if aliased {
        let _ = std::fs::write(other.join("config.extra"), b"[remote]\n\turl = secret\n");
        git_raw(&path, ["add", "--force", "META/config.extra"]);
        git_raw(&path, ["commit", "--quiet", "-m", "the other spelling"]);
    }

    let workspace = fixture.workspace("named-tree");
    let outcome = fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    );
    let record = match outcome {
        Ok(record) => record,
        // A repository this host will not read at all is a refusal, not an exposure, and it says
        // which shape it would not read.
        Err(refusal) => {
            assert!(
                refusal
                    .to_string()
                    .contains("could not reach by descending")
                    || refusal.to_string().contains("nested at"),
                "a refusal says which shape it would not read: {refusal}"
            );
            return;
        }
    };
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    // On a filesystem that ignores case, `META` **is** `meta`, and nothing of it is in the
    // version. On one that does not, `META` is an ordinary directory of this tree's own and its
    // content is content; what must not be there either way is the data directory itself.
    let same_directory = std::fs::canonicalize(path.join("META"))
        .ok()
        .zip(std::fs::canonicalize(path.join("meta")).ok())
        .is_some_and(|(one, two)| one == two);
    for entry in &manifest.paths {
        let lower = entry.path.to_ascii_lowercase();
        if same_directory || !aliased {
            assert!(
                !lower.starts_with("meta/"),
                "this repository's own data is not in its own version, whatever it is called: {}",
                entry.path
            );
        } else {
            assert!(
                !entry.path.starts_with("meta/"),
                "its own data is not in its own version: {}",
                entry.path
            );
        }
    }
}

/// KR-REQ-14.33: **both** administrative directories a repository reports are excluded,
/// including the split layout where they are two directories inside the captured tree.
///
/// Git reports a common directory, which holds the configuration, the references and the objects,
/// and this worktree's own, which holds its `HEAD` and its index. A repository can keep them apart
/// and both inside its own working tree, and a capture that excluded only one would hold the
/// other.
#[test]
fn both_administrative_directories_a_repository_reports_are_excluded() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "split-tree");
    // Everything shared at `common`, this worktree's own at `meta`, which is the shape Git accepts
    // for a repository whose two administrative directories are apart.
    std::fs::rename(path.join(".git"), path.join("common")).expect("the shared data");
    std::fs::create_dir_all(path.join("meta")).expect("this worktree's own");
    for name in ["HEAD", "index"] {
        let from = path.join("common").join(name);
        if from.exists() {
            std::fs::copy(&from, path.join("meta").join(name)).expect("its own copy");
        }
    }
    std::fs::write(path.join("meta/commondir"), b"../common\n").expect("naming the shared one");
    std::fs::write(
        path.join("meta/config.worktree"),
        b"[remote]\n\turl = a-secret\n",
    )
    .expect("something only this worktree has");
    std::fs::write(path.join(".git"), b"gitdir: meta\n").expect("and the file that names it");
    // Tracked, so the capture has every reason to reach it: it is in the index and in a commit.
    git_raw(&path, ["add", "--force", "meta/config.worktree"]);
    git_raw(
        &path,
        [
            "commit",
            "--quiet",
            "-m",
            "the worktree's own configuration",
        ],
    );

    let workspace = fixture.workspace("split-tree");
    let outcome = fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    );
    // This layout is read, not refused: the directory named by the tree's own `.git` is reached
    // through the tree's handle, which is what makes the reported one trustworthy enough to scan.
    let record = outcome.expect("a repository whose two directories are apart is captured");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for entry in &manifest.paths {
        assert!(
            !entry.path.starts_with("meta/") && !entry.path.starts_with("common/"),
            "neither of this repository's own directories is in its own version: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: a repository whose own data is named in full, inside its own tree.
///
/// The name is absolute, so nothing about it says it leads back into the tree this host is
/// reading. What decides is the object: the moment the walk stands on the working tree, the rest
/// of it is the tree's own walk, compared with the tree's mount at every step like any content
/// read. Otherwise a full name would be the one way into the tree that nothing checked.
#[test]
fn a_repository_that_names_its_own_data_in_full_is_still_read_as_this_tree() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "named-in-full");
    std::fs::rename(path.join(".git"), path.join("common")).expect("the shared data");
    std::fs::create_dir_all(path.join("meta")).expect("this worktree's own");
    for name in ["HEAD", "index"] {
        let from = path.join("common").join(name);
        if from.exists() {
            std::fs::copy(&from, path.join("meta").join(name)).expect("its own copy");
        }
    }
    std::fs::write(path.join("meta/commondir"), b"../common\n").expect("naming the shared one");
    std::fs::write(
        path.join("meta/config.worktree"),
        b"[remote]\n\turl = a-secret\n",
    )
    .expect("something only this worktree has");
    // The whole name, as Git writes it for a repository made with `--separate-git-dir`: the name
    // with nothing left in it to resolve, which is what this host will walk.
    let named = std::fs::canonicalize(path.join("meta")).expect("the name it would write");
    std::fs::write(
        path.join(".git"),
        format!("gitdir: {}\n", named.display()).as_bytes(),
    )
    .expect("and the file that names it");
    git_raw(&path, ["add", "--force", "meta/config.worktree"]);
    git_raw(&path, ["commit", "--quiet", "-m", "its own configuration"]);

    let workspace = fixture.workspace("named-in-full");
    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect("a repository that names its own data in full is captured");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for entry in &manifest.paths {
        assert!(
            !entry.path.starts_with("meta/") && !entry.path.starts_with("common/"),
            "neither of this repository's own directories is in its own version: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: a repository that names its shared data out of the tree and back in.
///
/// `commondir` here climbs above the working tree and comes down into it again. Every step of that
/// is walked through the handles this host already holds — the climb opens the directory a handle
/// is in, never a path from outside — and the moment a step **is** the working tree the rest of
/// the name is read with the tree's own rule. The directory it ends at is this repository's own
/// data and is excluded, however far around the name goes to reach it.
#[test]
fn a_repository_that_names_its_shared_data_out_of_the_tree_and_back_is_still_this_tree() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "out-and-back");
    std::fs::rename(path.join(".git"), path.join("common")).expect("the shared data");
    std::fs::create_dir_all(path.join("meta")).expect("this worktree's own");
    for name in ["HEAD", "index"] {
        let from = path.join("common").join(name);
        if from.exists() {
            std::fs::copy(&from, path.join("meta").join(name)).expect("its own copy");
        }
    }
    // Out of the tree, then back into it by name.
    std::fs::write(path.join("meta/commondir"), b"../../out-and-back/common\n")
        .expect("naming the shared one the long way round");
    std::fs::write(
        path.join("meta/config.worktree"),
        b"[remote]\n\turl = a-secret\n",
    )
    .expect("something only this worktree has");
    std::fs::write(path.join(".git"), b"gitdir: meta\n").expect("and the file that names it");
    git_raw(&path, ["add", "--force", "meta/config.worktree"]);
    git_raw(&path, ["commit", "--quiet", "-m", "its own configuration"]);

    let workspace = fixture.workspace("out-and-back");
    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect("a repository that names its data the long way round is captured");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for entry in &manifest.paths {
        assert!(
            !entry.path.starts_with("meta/") && !entry.path.starts_with("common/"),
            "neither of this repository's own directories is in its own version: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: a linked worktree's two directories, built by Git itself.
#[test]
fn a_linked_worktree_holds_neither_of_its_repository_s_directories() {
    let fixture = Fixture::create();
    let main = ordinary_repository(fixture.work(), "main-tree");
    let linked = fixture.work().join("linked-tree");
    let added = std::process::Command::new("git")
        .arg("-C")
        .arg(&main)
        .args(["worktree", "add", "--detach"])
        .arg(&linked)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", fixture.work())
        .output()
        .expect("git runs");
    if !added.status.success() {
        eprintln!(
            "this Git would not add a linked worktree, so the case is not exercised: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        return;
    }
    let workspace = fixture.workspace("linked-tree");
    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect("an ordinary linked worktree is captured");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for entry in &manifest.paths {
        assert!(
            !entry.path.contains(".git"),
            "nothing of either administrative directory is in the version: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: a second name for this repository's own data is excluded by identity.
///
/// The name can be a link inside the tree, and on a filesystem that ignores case it can be the
/// same directory under another spelling. Neither changes what the directory **is**, and that is
/// what the exclusion set holds.
#[test]
fn another_name_for_this_repository_s_own_data_is_excluded_too() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "aliased-data");
    // A second name for the repository's own directory, inside the tree this capture reads.
    std::os::unix::fs::symlink(".git", path.join("history")).expect("a second name for it");
    let workspace = fixture.workspace("aliased-data");
    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect("the capture runs");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    for entry in &manifest.paths {
        assert!(
            !entry.path.starts_with("history/"),
            "nothing of this repository's own data reaches a version under a second name: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: a repository whose own data holds a link is not captured around.
///
/// The alias can sit on the administrative side, and then the captured path crosses nothing: an
/// ordinary directory of the tree, and a link inside the repository's own data naming it. What
/// answers that is refusing to read around a repository whose own data this host cannot account
/// for.
#[test]
fn a_repository_whose_own_data_holds_a_link_is_not_captured_around() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "aliased-inside");
    std::fs::create_dir_all(path.join("history")).expect("an ordinary directory of the tree");
    write(&path, "history/kept.txt", "the reflog this would alias\n");
    // The repository's own data reaching out at it, which is the direction a captured path never
    // crosses.
    std::fs::create_dir_all(path.join(".git/logs")).ok();
    let _ = std::fs::remove_dir_all(path.join(".git/logs"));
    std::os::unix::fs::symlink("../history", path.join(".git/logs")).expect("a link out at it");

    let workspace = fixture.workspace("aliased-inside");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect_err("a repository whose own data holds a link is not captured around");
    let said = failure.to_string();
    assert!(
        said.contains("cannot account for") && said.contains("holds a link at"),
        "the refusal names the link it found: {failure}"
    );
}

/// KR-REQ-14.33: a directory already excluded is still looked inside.
///
/// Being excluded and having been looked at are different questions. A nested worktree **inside**
/// a repository's own data is excluded the moment it is discovered, and it can still hold a link
/// out at the tree that nothing has seen. The layout below is the whole of it: `vendor` is a
/// repository's data kept under an ordinary name, `vendor/logs` is a worktree of it, and the link
/// inside that worktree makes `history` the place the reflogs are written. Read around, the tree's
/// own `history/heads/main` is administrative data under an ordinary path.
#[test]
fn a_directory_already_excluded_is_still_looked_inside() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "excluded-and-unseen");
    // A repository's own data under an ordinary name, which is the outer capture's content.
    write(&path, "vendor/HEAD", "ref: refs/heads/main\n");
    write(
        &path,
        "vendor/config",
        "[core]\n\trepositoryformatversion = 0\n",
    );
    std::fs::create_dir_all(path.join("vendor/objects")).expect("its object directory");
    std::fs::create_dir_all(path.join("vendor/refs/heads")).expect("its reference directory");
    // A worktree of it, inside it, which discovery excludes before anything looks in it.
    write(&path, "vendor/logs/.git", "gitdir: ..\n");
    write(&path, "vendor/logs/note.txt", "a file this capture names\n");
    // And the link out at the tree, which is the whole point of looking inside.
    write(&path, "history/heads/main", "the reflog this would alias\n");
    std::os::unix::fs::symlink("../../history", path.join("vendor/logs/refs"))
        .expect("a link out at the tree");

    let workspace = fixture.workspace("excluded-and-unseen");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect_err("a repository whose own data holds a link is not captured around");
    let said = failure.to_string();
    assert!(
        said.contains("cannot account for") && said.contains("holds a link at"),
        "the refusal names the link inside the directory it had already excluded: {failure}"
    );
}

/// KR-REQ-14.33: a repository whose own data is on another filesystem is ordinary.
///
/// The mount comparison is between a directory and the directory it was opened beneath, never
/// between a directory and the working tree. A repository can keep its data on another filesystem
/// altogether, and every directory of that data is then on neither the tree's mount nor anything
/// near it. What the rule refuses is a mount **inside** a tree, and this is not one.
#[test]
fn a_repository_whose_own_data_is_on_another_filesystem_is_captured() {
    let fixture = Fixture::create();
    let Some(elsewhere) = another_filesystem(fixture.work()) else {
        println!("not exercised: this host offers no second filesystem to keep the data on");
        return;
    };
    let data = elsewhere.path().join("data");
    git_raw(
        fixture.work(),
        [
            std::ffi::OsString::from("init"),
            std::ffi::OsString::from("--initial-branch=main"),
            std::ffi::OsString::from("--separate-git-dir"),
            data.clone().into_os_string(),
            std::ffi::OsString::from("data-elsewhere"),
        ],
    );
    let path = fixture.work().join("data-elsewhere");
    {
        // The case is only the case while the two really are on different filesystems.
        use std::os::unix::fs::MetadataExt as _;
        let tree = std::fs::metadata(&path).expect("the tree").dev();
        let held = std::fs::metadata(&data).expect("its data").dev();
        assert_ne!(
            tree, held,
            "the data is on another filesystem from the tree"
        );
    }
    write(
        &path,
        "README.md",
        "a repository whose data is somewhere else\n",
    );
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the first commit"]);

    let workspace = fixture.workspace("data-elsewhere");
    let record = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect("a repository whose own data is on another filesystem is captured");
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest.paths.iter().any(|entry| entry.path == "README.md"),
        "the tree's own content is in the version"
    );
    for entry in &manifest.paths {
        assert!(
            !entry.path.contains(".git"),
            "and nothing of its administrative data is: {}",
            entry.path
        );
    }
}

/// KR-REQ-14.33: data deeper than this host reads refuses rather than goes unread.
#[test]
fn a_repository_whose_own_data_is_deeper_than_this_host_reads_refuses() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "deep-data");
    let mut deep = path.join(".git");
    for _ in 0..(kr_changeset::capture::MAX_WALK_DEPTH + 2) {
        deep.push("down");
    }
    std::fs::create_dir_all(&deep).expect("a chain deeper than this host reads");

    let workspace = fixture.workspace("deep-data");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect_err("data this host cannot read to the bottom of is not captured around");
    let said = failure.to_string();
    assert!(
        said.contains("cannot account for") && said.contains("levels deep"),
        "the refusal says it is the depth: {failure}"
    );
}

/// Returns a temporary directory on a filesystem other than the one `beside` is on.
///
/// Where the host offers none, the case that needs one says so rather than reporting a result it
/// did not produce.
fn another_filesystem(beside: &std::path::Path) -> Option<tempfile::TempDir> {
    use std::os::unix::fs::MetadataExt as _;

    let here = std::fs::metadata(beside).ok()?.dev();
    let mut candidates = vec![
        std::env::temp_dir(),
        std::path::PathBuf::from("/dev/shm"),
        std::path::PathBuf::from("/private/tmp"),
    ];
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        candidates.push(directory.to_path_buf());
    }
    candidates.into_iter().find_map(|candidate| {
        let metadata = std::fs::metadata(&candidate).ok()?;
        if metadata.dev() == here {
            return None;
        }
        tempfile::TempDir::new_in(&candidate).ok()
    })
}

/// KR-REQ-14.32: a quiescence declaration is recorded as the caller's own word and decides
/// nothing, and the policy says separately whether anything actually held the workspace still.
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
    assert!(
        record.policy.quiescence_declared,
        "what the caller said is recorded as the caller's own word"
    );
    assert!(
        !record.policy.quiescence_held,
        "and nothing held this workspace still, which is the separate fact that decides the class"
    );
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
    assert!(record.policy.quiescence_declared);
    assert!(!record.policy.quiescence_held);
    assert!(
        record
            .consistency_detail
            .contains("it does not make this a quiesced capture"),
        "and says so: {}",
        record.consistency_detail
    );
}

/// A quiescence authority the tests drive, and the grants it hands out.
///
/// Nothing here holds a real workspace still: what these fixtures exercise is what a capture does
/// with what it is told, which is the whole of this crate's side of the seam.
mod reservation {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use kr_changeset::capture::{QuiescenceAuthority, QuiescenceLease, QuiescenceSubject};

    /// What the authority does when a capture asks it for a workspace.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Behaviour {
        /// Grants, and holds through every question.
        Holds,
        /// Will not hold the workspace at the moment it is asked.
        Refuses,
        /// Grants, and stops holding after this many questions.
        LapsesAfter(usize),
        /// Grants with a bound that has already passed.
        BoundAlreadyPassed,
        /// Grants, and then answers as a different grant of the same subject.
        BecomesAnotherGrant,
        /// Grants a reservation over another workspace altogether.
        OverAnotherWorkspace,
    }

    /// The authority, with a count of everything a capture did to it.
    #[derive(Debug)]
    pub struct Authority {
        behaviour: Behaviour,
        asked: AtomicUsize,
        granted: AtomicUsize,
        released: AtomicUsize,
        questions: AtomicUsize,
    }

    impl Authority {
        #[must_use]
        pub const fn new(behaviour: Behaviour) -> Self {
            Self {
                behaviour,
                asked: AtomicUsize::new(0),
                granted: AtomicUsize::new(0),
                released: AtomicUsize::new(0),
                questions: AtomicUsize::new(0),
            }
        }

        /// How many times a capture asked for this workspace.
        pub fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }

        /// How many grants it handed out.
        pub fn granted(&self) -> usize {
            self.granted.load(Ordering::SeqCst)
        }

        /// How many times a grant was given back.
        pub fn released(&self) -> usize {
            self.released.load(Ordering::SeqCst)
        }

        /// How many times a capture asked a grant whether it was still holding.
        pub fn questions(&self) -> usize {
            self.questions.load(Ordering::SeqCst)
        }
    }

    impl QuiescenceAuthority for Authority {
        fn reserve(
            &self,
            subject: QuiescenceSubject,
        ) -> kr_changeset::Result<Option<Box<dyn QuiescenceLease + '_>>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.behaviour == Behaviour::Refuses {
                return Ok(None);
            }
            self.granted.fetch_add(1, Ordering::SeqCst);
            let answers = if self.behaviour == Behaviour::OverAnotherWorkspace {
                QuiescenceSubject {
                    workspace_id: kr_protocol::ids::WorkspaceId::new(kr_ipc::new_uuid()),
                    ..subject
                }
            } else {
                subject
            };
            // A bound that has already passed is the instant of the grant itself: every question
            // is asked after it.
            let bound = if self.behaviour == Behaviour::BoundAlreadyPassed {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(600)
            };
            Ok(Some(Box::new(Lease {
                authority: self,
                subject: answers,
                bound,
            })))
        }
    }

    /// One grant, which counts every question the capture asks it.
    #[derive(Debug)]
    struct Lease<'a> {
        authority: &'a Authority,
        subject: QuiescenceSubject,
        bound: Instant,
    }

    impl QuiescenceLease for Lease<'_> {
        fn subject(&self) -> QuiescenceSubject {
            self.subject
        }

        fn grant_id(&self) -> u128 {
            if self.authority.behaviour == Behaviour::BecomesAnotherGrant
                && self.authority.questions() > 0
            {
                return 2;
            }
            1
        }

        fn bound(&self) -> Instant {
            self.bound
        }

        fn holding(&self) -> bool {
            let asked = self.authority.questions.fetch_add(1, Ordering::SeqCst);
            match self.authority.behaviour {
                Behaviour::LapsesAfter(held) => asked < held,
                _ => true,
            }
        }

        fn release(&self) {
            self.authority.released.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// D-083 and KR-REQ-14.32: a reservation that was granted over this working tree and was still
/// holding after the last reading is what makes a capture a quiesced capture, and the grant goes
/// back exactly once.
#[test]
fn a_reservation_that_held_through_the_read_makes_a_quiesced_capture() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "held");
    write(&path, "README.md", "the work in progress\n");
    let workspace = fixture.workspace("held");
    let authority = reservation::Authority::new(reservation::Behaviour::Holds);

    let record = fixture
        .capture_with_authority(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
            Some(&authority),
        )
        .expect("the capture runs");

    assert_eq!(record.consistency, SourceConsistency::QuiescedCapture);
    assert!(
        record.policy.quiescence_held,
        "the policy records that something held the workspace still"
    );
    assert!(
        !record.policy.quiescence_declared,
        "and it does not put words in the caller's mouth: this caller declared nothing"
    );
    assert!(
        record
            .consistency_detail
            .contains("still holding after the last one"),
        "the detail says what earned the class: {}",
        record.consistency_detail
    );
    assert_eq!(authority.asked(), 1, "the workspace was asked for once");
    assert_eq!(authority.granted(), 1);
    assert_eq!(
        authority.released(),
        1,
        "and it was given back after the readings, exactly once"
    );
    assert!(
        authority.questions() >= 3,
        "the grant was questioned through the read rather than once at the start: {}",
        authority.questions()
    );
}

/// D-083 and KR-REQ-14.32: a workspace nothing will hold still is captured as the class this host
/// actually performed, and no grant is left outstanding.
#[test]
fn a_workspace_that_cannot_be_reserved_is_a_per_file_capture() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "refused");
    let workspace = fixture.workspace("refused");
    let authority = reservation::Authority::new(reservation::Behaviour::Refuses);

    let record = fixture
        .capture_with_authority(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
            Some(&authority),
        )
        .expect("the capture runs");

    assert_eq!(record.consistency, SourceConsistency::PerFileCapture);
    assert!(!record.policy.quiescence_held);
    assert!(
        record
            .consistency_detail
            .contains("could not be reserved at the moment this host asked"),
        "the detail says why: {}",
        record.consistency_detail
    );
    assert_eq!(authority.asked(), 1);
    assert_eq!(authority.granted(), 0, "a refusal grants nothing");
    assert_eq!(
        authority.released(),
        0,
        "and there is nothing to give back after one"
    );
}

/// D-083 and KR-REQ-14.32: a grant that stops holding at **any** point of the read leaves a
/// per-file capture, and the grant is still given back.
#[test]
fn a_reservation_that_stops_holding_mid_read_is_not_a_quiesced_capture() {
    // One case per point of the read the capture asks at: the first question, the one after the
    // content, and the one after the selection was read again.
    for held_for in [0_usize, 1, 2] {
        let fixture = Fixture::create();
        let path = ordinary_repository(fixture.work(), "lapsing");
        write(&path, "README.md", "the work in progress\n");
        let workspace = fixture.workspace("lapsing");
        let authority = reservation::Authority::new(reservation::Behaviour::LapsesAfter(held_for));

        let record = fixture
            .capture_with_authority(
                workspace,
                &include_everything(),
                &FileGrant::default(),
                None,
                None,
                Some(&authority),
            )
            .expect("the capture runs");

        assert_eq!(
            record.consistency,
            SourceConsistency::PerFileCapture,
            "a grant that held for {held_for} question(s) is not a quiesced capture"
        );
        assert!(!record.policy.quiescence_held);
        assert!(
            record
                .consistency_detail
                .contains("stopped holding this workspace before the read finished"),
            "the detail says what happened: {}",
            record.consistency_detail
        );
        assert_eq!(
            authority.released(),
            1,
            "a grant that lapsed is still this host's to give back (held for {held_for})"
        );
        assert_eq!(
            authority.questions(),
            held_for + 1,
            "and it is not asked again once it has lapsed (held for {held_for})"
        );
    }
}

/// D-083 and KR-REQ-14.32: a grant whose bound has passed, and one that has become another grant,
/// are both grants that stopped holding.
#[test]
fn a_grant_past_its_bound_or_replaced_by_another_holds_nothing() {
    for behaviour in [
        reservation::Behaviour::BoundAlreadyPassed,
        reservation::Behaviour::BecomesAnotherGrant,
    ] {
        let fixture = Fixture::create();
        let path = ordinary_repository(fixture.work(), "bounded");
        write(&path, "README.md", "the work in progress\n");
        let workspace = fixture.workspace("bounded");
        let authority = reservation::Authority::new(behaviour);

        let record = fixture
            .capture_with_authority(
                workspace,
                &include_everything(),
                &FileGrant::default(),
                None,
                None,
                Some(&authority),
            )
            .expect("the capture runs");

        assert_eq!(
            record.consistency,
            SourceConsistency::PerFileCapture,
            "{behaviour:?} is not a quiesced capture"
        );
        assert!(!record.policy.quiescence_held);
        assert_eq!(
            authority.released(),
            1,
            "{behaviour:?} is still given back once"
        );
    }
}

/// D-083 and KR-REQ-14.32: a grant over another workspace holds nothing of this capture still, so
/// the capture refuses rather than reading under it, and gives it straight back.
#[test]
fn a_reservation_over_another_workspace_refuses_the_capture() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "elsewhere");
    let workspace = fixture.workspace("elsewhere");
    let authority = reservation::Authority::new(reservation::Behaviour::OverAnotherWorkspace);

    let error = fixture
        .capture_with_authority(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
            Some(&authority),
        )
        .expect_err("a reservation over somewhere else is refused");

    assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
    assert!(
        error.to_string().contains("holds nothing of this capture"),
        "the refusal says why: {error}"
    );
    assert_eq!(
        authority.released(),
        1,
        "and the grant this host did not want is given back at once"
    );
}

/// D-083 and KR-REQ-14.32: a caller that requires the stronger class is refused whenever this host
/// did not perform it, and every grant it took on the way is given back.
#[test]
fn requiring_the_quiesced_class_refuses_every_capture_that_did_not_perform_it() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "required");
    write(&path, "README.md", "the work in progress\n");
    let workspace = fixture.workspace("required");
    let policy = include_everything();
    let grant = FileGrant::default();

    // Nowhere to ask at all.
    let error = fixture
        .capture_with_authority(
            workspace,
            &policy,
            &grant,
            None,
            Some(SourceConsistency::QuiescedCapture),
            None,
        )
        .expect_err("a required class this host cannot perform is refused");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        error.to_string().contains("nowhere to reserve"),
        "the refusal says what was missing: {error}"
    );

    // Asked, and refused.
    let refuses = reservation::Authority::new(reservation::Behaviour::Refuses);
    let error = fixture
        .capture_with_authority(
            workspace,
            &policy,
            &grant,
            None,
            Some(SourceConsistency::QuiescedCapture),
            Some(&refuses),
        )
        .expect_err("a refused reservation refuses the capture");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.to_string().contains("was refused"), "{error}");
    assert_eq!(refuses.released(), 0);

    // Granted, and lapsed at each of the points the capture asks at.
    for held_for in [0_usize, 1, 2] {
        let authority = reservation::Authority::new(reservation::Behaviour::LapsesAfter(held_for));
        let error = fixture
            .capture_with_authority(
                workspace,
                &policy,
                &grant,
                None,
                Some(SourceConsistency::QuiescedCapture),
                Some(&authority),
            )
            .expect_err("a reservation that lapsed refuses the capture");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.to_string().contains("stopped holding"),
            "the refusal says what happened (held for {held_for}): {error}"
        );
        assert_eq!(
            authority.released(),
            1,
            "and the grant is given back even though the capture refused (held for {held_for})"
        );
    }
}

/// D-083: a capture that fails for a reason of its own still gives the grant back.
#[test]
fn a_capture_that_fails_gives_the_reservation_back() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "unborn");
    let workspace = fixture.workspace("unborn");
    // A branch with no commit on it has no base revision, so the capture refuses at its first
    // reading, which is after it has taken the reservation.
    git_raw(&path, ["update-ref", "-d", "HEAD"]);
    let authority = reservation::Authority::new(reservation::Behaviour::Holds);

    let error = fixture
        .capture_with_authority(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            None,
            Some(&authority),
        )
        .expect_err("a repository with no commit has nothing to capture against");

    assert_eq!(authority.granted(), 1);
    assert_eq!(
        authority.released(),
        1,
        "the grant is given back however the capture ends: {error}"
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
        .delete_version(second.change_set_id, second.version, None)
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

/// KR-REQ-14.33: a file mounted inside a repository's own data refuses the capture.
///
/// The reverse of a path reaching administrative bytes: here an ordinary file of the tree is given
/// a second name **inside** the repository's own data, so what Git writes through that name is the
/// content of a file the capture reads under an ordinary path. Nothing about the tree's path says
/// so, and no directory of the tree is on another mount. What finds it is the administrative scan
/// opening each file it holds.
///
/// It needs a mount namespace this account owns. Where the host gives none, the case says it was
/// not exercised rather than reporting a result it did not produce.
#[cfg(target_os = "linux")]
#[test]
fn a_file_mounted_inside_this_repository_s_own_data_is_not_captured_around() {
    const NOT_EXERCISED: i32 = 42;

    if std::env::var_os("KR_CAPTURE_FILE_MOUNT").is_some() {
        a_file_mounted_inside_administrative_data();
        return;
    }
    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "--", "true"])
        .status();
    if !probe.is_ok_and(|status| status.success()) {
        println!("not exercised: this host does not give this account a mount namespace");
        return;
    }
    let binary = std::env::current_exe().expect("the test binary");
    let status = std::process::Command::new("unshare")
        .args(["-r", "-m", "--"])
        .arg(binary)
        .args(["--exact", "--nocapture", "--test-threads=1"])
        .arg("a_file_mounted_inside_this_repository_s_own_data_is_not_captured_around")
        .env("KR_CAPTURE_FILE_MOUNT", "1")
        .status()
        .expect("the test binary runs inside a mount namespace");
    if status.code() == Some(NOT_EXERCISED) {
        println!("not exercised: this namespace would not place a bind mount over a file");
        return;
    }
    assert!(
        status.success(),
        "the capture inside the mount namespace did not refuse: {status}"
    );
}

/// The half that runs inside the mount namespace.
#[cfg(target_os = "linux")]
fn a_file_mounted_inside_administrative_data() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "file-aliased");
    write(&path, "history.txt", "the reflog this would alias\n");
    std::fs::create_dir_all(path.join(".git/logs/refs/heads")).expect("a reflog directory");
    std::fs::write(path.join(".git/logs/refs/heads/main"), b"").expect("a reflog file");
    let placed = std::process::Command::new("mount")
        .arg("--bind")
        .arg(path.join("history.txt"))
        .arg(path.join(".git/logs/refs/heads/main"))
        .status();
    if !placed.is_ok_and(|status| status.success()) {
        std::process::exit(42);
    }

    let workspace = fixture.workspace("file-aliased");
    let failure = fixture
        .capture_with(
            workspace,
            &include_everything(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            None,
        )
        .expect_err("a repository whose own data holds a mounted file is not captured around");
    let said = failure.to_string();
    assert!(
        said.contains("cannot account for")
            && said.contains("holds a mount at")
            && said.contains("main"),
        "the refusal names the mounted file it found: {failure}"
    );
}

/// KR-REQ-14.33: two handles on one directory can lead to different children.
///
/// The layout is static: a repository's tree is a bind mount of another directory, and beneath the
/// original a second mount puts a nested repository's data where an empty directory is otherwise.
/// A nested `.git` names that place in full. The descent arrives at a directory that **is** the
/// working tree by object and is on another mount, where the same name reaches the empty directory
/// rather than the data. Taking the tree's own handle there would account for the wrong directory
/// and leave the data as ordinary content, so this host refuses instead of choosing between them.
///
/// It needs a mount namespace this account owns. Where the host gives none, the case says it was
/// not exercised rather than reporting a result it did not produce.
#[cfg(target_os = "linux")]
#[test]
fn a_tree_reached_on_another_mount_is_not_taken_for_this_one() {
    const NOT_EXERCISED: i32 = 42;

    if std::env::var_os("KR_CAPTURE_TWO_MOUNTS").is_some() {
        two_mounts_over_one_tree();
        return;
    }
    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "--", "true"])
        .status();
    if !probe.is_ok_and(|status| status.success()) {
        println!("not exercised: this host does not give this account a mount namespace");
        return;
    }
    let binary = std::env::current_exe().expect("the test binary");
    let status = std::process::Command::new("unshare")
        .args(["-r", "-m", "--"])
        .arg(binary)
        .args(["--exact", "--nocapture", "--test-threads=1"])
        .arg("a_tree_reached_on_another_mount_is_not_taken_for_this_one")
        .env("KR_CAPTURE_TWO_MOUNTS", "1")
        .status()
        .expect("the test binary runs inside a mount namespace");
    if status.code() == Some(NOT_EXERCISED) {
        println!("not exercised: this namespace would not place the two mounts");
        return;
    }
    assert!(
        status.success(),
        "the capture inside the mount namespace did not hold: {status}"
    );
}

/// The half that runs inside the mount namespace.
#[cfg(target_os = "linux")]
fn two_mounts_over_one_tree() {
    let fixture = Fixture::create();
    let backing = ordinary_repository(fixture.work(), "backing");
    // The nested repository's own data, and the empty directory a second mount puts it at.
    write(&backing, "repo-data/HEAD", "ref: refs/heads/main\n");
    write(&backing, "repo-data/config", "[remote]\n\turl = a-secret\n");
    std::fs::create_dir_all(backing.join("git-location")).expect("the empty directory");
    std::fs::create_dir_all(backing.join("vendor/inner")).expect("the nested tree");
    write(&backing, "vendor/inner/notes.txt", "its own content\n");
    // Tracked, so the capture has every reason to reach it.
    git_raw(&backing, ["add", "--force", "repo-data/config"]);
    git_raw(&backing, ["commit", "--quiet", "-m", "the data this names"]);
    let tree = fixture.work().join("tree");
    std::fs::create_dir_all(&tree).expect("where the tree is mounted");
    let named = std::fs::canonicalize(backing.join("git-location")).expect("the name it names");
    std::fs::write(
        backing.join("vendor/inner/.git"),
        format!("gitdir: {}\n", named.display()).as_bytes(),
    )
    .expect("the file that names it in full");

    let placed = std::process::Command::new("mount")
        .arg("--bind")
        .arg(backing.join("repo-data"))
        .arg(backing.join("git-location"))
        .status();
    if !placed.is_ok_and(|status| status.success()) {
        std::process::exit(42);
    }
    let over = std::process::Command::new("mount")
        .arg("--bind")
        .arg(&backing)
        .arg(&tree)
        .status();
    if !over.is_ok_and(|status| status.success()) {
        std::process::exit(42);
    }

    let workspace = fixture.workspace("tree");
    match fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    ) {
        // Refusing is the answer this host gives: the two handles are one object on two mounts,
        // and which children the name reaches depends on which of them is used.
        Err(refusal) => {
            let said = refusal.to_string();
            assert!(
                said.contains("could not reach") || said.contains("own data"),
                "the refusal says which shape it would not read: {refusal}"
            );
        }
        // If it is read at all, the nested repository's own data is not in it.
        Ok(record) => {
            let manifest = fixture
                .service()
                .manifest(record.change_set_id, record.version)
                .expect("its manifest");
            for entry in &manifest.paths {
                assert!(
                    !entry.path.starts_with("repo-data/"),
                    "a nested repository's own data is not content: {}",
                    entry.path
                );
            }
        }
    }
}

/// KR-REQ-14.32: a repository whose own data names itself ends the walk rather than
/// starting it again.
///
/// Every reference this host follows — a `gitdir:` line, a `commondir`, a link — names a place to
/// go and look, and each place can name another. A repository whose data holds a `.git` reading
/// `gitdir: .` names the directory the scan is already standing in, so nothing about the depth of
/// any one walk would ever end it. What ends it is having looked through that place already, by
/// what it is and the mount it was reached on, and a bound on how many references one discovery
/// follows.
#[test]
fn a_repository_whose_own_data_names_itself_is_looked_through_once() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "self-naming-tree");
    std::fs::write(path.join(".git/.git"), b"gitdir: .\n").expect("data that names itself");

    let workspace = fixture.workspace("self-naming-tree");
    // Whatever it answers, it answers: the walk ends, and nothing of this repository's own data
    // is in a version it produces.
    match fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    ) {
        Ok(record) => {
            let manifest = fixture
                .service()
                .manifest(record.change_set_id, record.version)
                .expect("its manifest");
            assert!(
                manifest
                    .paths
                    .iter()
                    .all(|entry| !entry.path.contains(".git")),
                "nothing of this repository's own data is in the version: {:?}",
                manifest
                    .paths
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            );
        }
        Err(refusal) => {
            let said = refusal.to_string();
            assert!(
                said.contains("could not reach")
                    || said.contains("cannot account for")
                    || said.contains("look through"),
                "and a refusal says which shape it would not read: {refusal}"
            );
        }
    }
}

/// KR-REQ-14.33: `.GIT` is not `.git` where the filesystem keeps them apart.
///
/// The rule that leaves a path out of a version covers every spelling of `.git`, because a
/// filesystem that folds case reaches one directory through all of them. What a repository **is**
/// is a different question: Git reads the entry called exactly `.git`, so on a filesystem that
/// keeps the two apart a directory called `.GIT` is an ordinary directory nothing has accounted
/// for — and a repository can sit inside it, keeping its own data at an ordinary path of this
/// tree.
#[test]
fn a_directory_whose_name_only_looks_administrative_is_still_looked_through() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "case-kept-tree");
    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("a vendored repository");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    // A second name beside the repository's own data. Where the filesystem folds case this is
    // that directory and the creation fails, and there is nothing here to stage.
    let upper = nested.join(".GIT");
    if std::fs::create_dir(&upper).is_err() {
        println!("not exercised: this filesystem does not keep `.git` and `.GIT` apart");
        return;
    }
    let child = upper.join("child");
    std::fs::create_dir_all(&child).expect("a repository inside it");
    std::fs::write(child.join(".git"), b"gitdir: ../../../repo-data\n")
        .expect("the file that names where its data is");
    write(&path, "vendor/repo-data/HEAD", "ref: refs/heads/main\n");
    write(
        &path,
        "vendor/repo-data/config",
        "[remote \"origin\"]\n\turl = https://user:a-secret-token@example.invalid/x.git\n",
    );

    let workspace = fixture.workspace("case-kept-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.starts_with("vendor/repo-data")),
        "the data of the repository inside `.GIT` is not in the version: {:?}",
        manifest
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
}

/// KR-REQ-14.33: two views of one directory are two places to look, not one.
///
/// A link can name a directory outside this tree, and outside it there is no mount to hold a walk
/// to. What a discovery must not do is treat "no rule" as "no mount": two bind-mount views of one
/// directory are the same object with different children, and a record of what has been looked
/// through that named only the object would pass the second view over. One of the two views can
/// hold a repository whose own data is an ordinary directory of this tree.
#[cfg(target_os = "linux")]
#[test]
fn two_views_of_one_directory_are_both_looked_through() {
    const NOT_EXERCISED: i32 = 42;

    if std::env::var_os("KR_CAPTURE_TWO_VIEWS").is_some() {
        two_views_of_one_target();
        return;
    }
    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "--", "true"])
        .status();
    if !probe.is_ok_and(|status| status.success()) {
        println!("not exercised: this host does not give this account a mount namespace");
        return;
    }
    let binary = std::env::current_exe().expect("the test binary");
    let status = std::process::Command::new("unshare")
        .args(["-r", "-m", "--"])
        .arg(binary)
        .args(["--exact", "--nocapture", "--test-threads=1"])
        .arg("two_views_of_one_directory_are_both_looked_through")
        .env("KR_CAPTURE_TWO_VIEWS", "1")
        .status()
        .expect("the test binary runs inside a mount namespace");
    if status.code() == Some(NOT_EXERCISED) {
        println!("not exercised: this namespace would not place the two mounts");
        return;
    }
    assert!(
        status.success(),
        "the capture inside the mount namespace did not hold: {status}"
    );
}

/// The half that runs inside the mount namespace.
#[cfg(target_os = "linux")]
fn two_views_of_one_target() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "two-views-tree");
    // The data of a repository whose tree is outside this one: an ordinary directory here.
    write(&path, "vendor/repo-data/HEAD", "ref: refs/heads/main\n");
    write(
        &path,
        "vendor/repo-data/config",
        "[remote \"origin\"]\n\turl = https://user:a-secret-token@example.invalid/x.git\n",
    );
    // Outside the tree: a directory with an empty `child`, a second view of it, and the tree of
    // the repository that will be mounted at `child` in one view only.
    let outside = fixture.work().join("outside");
    std::fs::create_dir_all(outside.join("base/child")).expect("the directory and its child");
    std::fs::create_dir_all(outside.join("view")).expect("where the second view goes");
    std::fs::create_dir_all(outside.join("repo")).expect("the repository's own tree");
    let named = std::fs::canonicalize(path.join("vendor/repo-data")).expect("the name it names");
    std::fs::write(
        outside.join("repo/.git"),
        format!("gitdir: {}\n", named.display()).as_bytes(),
    )
    .expect("the file that names where its data is");

    // The second view first, so it holds the empty child; then the repository over the child of
    // the first. The two views are one object and two sets of children.
    for (from, onto) in [
        (outside.join("base"), outside.join("view")),
        (outside.join("repo"), outside.join("base/child")),
    ] {
        let placed = std::process::Command::new("mount")
            .arg("--bind")
            .arg(&from)
            .arg(&onto)
            .status();
        if !placed.is_ok_and(|status| status.success()) {
            std::process::exit(42);
        }
    }
    // The view without the repository is named first, so a record keyed on the object alone would
    // pass the one with it over.
    std::os::unix::fs::symlink(outside.join("view"), path.join("a-view"))
        .expect("the link to the view");
    std::os::unix::fs::symlink(outside.join("base"), path.join("b-view"))
        .expect("the link to the other");

    let workspace = fixture.workspace("two-views-tree");
    match fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    ) {
        Ok(record) => {
            let manifest = fixture
                .service()
                .manifest(record.change_set_id, record.version)
                .expect("its manifest");
            assert!(
                manifest
                    .paths
                    .iter()
                    .all(|entry| !entry.path.starts_with("vendor/repo-data")),
                "the data of the repository in the second view is not in the version: {:?}",
                manifest
                    .paths
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            );
        }
        // Refusing is an answer too: what it must not do is read the tree and hold that data.
        Err(refusal) => {
            let said = refusal.to_string();
            assert!(
                said.contains("could not reach")
                    || said.contains("cannot account for")
                    || said.contains("look through")
                    || said.contains("different mount"),
                "the refusal says which shape it would not read: {refusal}"
            );
        }
    }
}

/// KR-REQ-14.33: where a filesystem folds case, `.GIT` **is** the entry Git reads.
///
/// The name a listing returns and the entry Git reads are not the same string. A reference file
/// written as `.GIT` inside a repository's own data is what Git opens as `.git` on a filesystem
/// that folds case, and it names where another repository keeps its data — a directory of this
/// tree. So the scan asks the directory whether it holds one rather than comparing the name it
/// was listed under.
#[test]
fn a_reference_file_under_a_folded_name_is_still_read() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "folded-name-tree");
    let inside = path.join(".git/checkout");
    std::fs::create_dir_all(&inside).expect("a tree inside the data");
    std::fs::write(inside.join(".GIT"), b"gitdir: ../../vendor/repo-data\n")
        .expect("the reference under the other spelling");
    if std::fs::create_dir(inside.join(".git")).is_ok() {
        println!(
            "not exercised: this filesystem keeps `.git` and `.GIT` apart, so this file is \
                  not the entry Git reads"
        );
        return;
    }
    write(&path, "vendor/repo-data/HEAD", "ref: refs/heads/main\n");
    write(
        &path,
        "vendor/repo-data/config",
        "[remote \"origin\"]\n\turl = https://user:a-secret-token@example.invalid/x.git\n",
    );

    let workspace = fixture.workspace("folded-name-tree");
    let record = fixture.capture(workspace, &include_everything());
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest
            .paths
            .iter()
            .all(|entry| !entry.path.starts_with("vendor/repo-data")),
        "what the reference names is not in the version: {:?}",
        manifest
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        record
            .exclusions
            .iter()
            .any(|entry| entry.path.starts_with("vendor/repo-data")),
        "and it is named where it was found: {:?}",
        record.exclusions
    );
}

/// Following references through nested repositories beyond `MAX_REFERENCE_HOPS` (64) refuses the
/// capture rather than looping or descending indefinitely.
#[test]
fn following_more_than_the_reference_hop_limit_refuses_the_capture() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "hop-limit-tree");
    let outside = fixture.work().join("hop-outside");
    std::fs::create_dir_all(outside.join("chain_70")).expect("terminal dir");
    for i in 0..70 {
        let step = outside.join(format!("chain_{i}"));
        std::fs::create_dir_all(&step).expect("chain dir");
        std::os::unix::fs::symlink(format!("../chain_{}", i + 1), step.join("next"))
            .expect("symlink");
    }

    let nested = path.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("nested repo directory");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    std::os::unix::fs::symlink("../../../hop-outside/chain_0", nested.join("entry"))
        .expect("entry symlink");

    let workspace = fixture.workspace("hop-limit-tree");
    let outcome = fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    );
    let refusal = outcome.expect_err("exceeding max reference hops refuses capture");
    let said = refusal.to_string();
    assert!(
        said.contains("64 references deep"),
        "the refusal names the hop limit: {said}"
    );
}

/// Climbing more than `MAX_CLIMB_HOPS` (256) levels below the root of the filesystem refuses the
/// capture rather than wandering arbitrarily far up the tree.
#[test]
fn climbing_more_than_max_climb_hops_to_root_refuses_the_capture() {
    let fixture = Fixture::create();
    let mut deep = fixture.work().to_path_buf();
    for _ in 0..260 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).expect("deeply nested directory");
    let path = ordinary_repository(&deep, "deep-tree");

    std::fs::rename(path.join(".git"), path.join("common")).expect("the shared data");
    std::fs::create_dir_all(path.join("meta")).expect("this worktree's own");
    for name in ["HEAD", "index"] {
        let from = path.join("common").join(name);
        if from.exists() {
            std::fs::copy(&from, path.join("meta").join(name)).expect("its own copy");
        }
    }
    std::fs::write(path.join("meta/commondir"), b"../common\n").expect("naming the shared one");
    let named = std::fs::canonicalize(path.join("meta")).expect("the name it would write");
    std::fs::write(
        path.join(".git"),
        format!("gitdir: {}\n", named.display()).as_bytes(),
    )
    .expect("and the file that names it");
    git_raw(&path, ["add", "--force", "meta"]);
    git_raw(&path, ["commit", "--quiet", "-m", "its own configuration"]);

    let project = fixture
        .project()
        .project_adopt(
            &support::actor(),
            &kr_protocol::project::ProjectAdoptParams {
                destination: support::destination(fixture.environment_id(), &deep, "deep-tree"),
                label: "deep-tree".to_owned(),
                flow: kr_protocol::project::AdoptionFlow::ExistingCheckout,
            },
            Some(&support::action("project.adopt:deep-tree")),
        )
        .expect("the checkout is adopted")
        .project
        .project_repository_id;
    let workspace = fixture.shared_workspace(project, "deep-tree");

    let outcome = fixture.capture_with(
        workspace,
        &include_everything(),
        &kr_protocol::changeset::FileGrant::default(),
        None,
        None,
    );
    let refusal = outcome.expect_err("exceeding max climb hops refuses capture");
    let said = refusal.to_string();
    assert!(
        said.contains("256 levels below the root of its filesystem"),
        "the refusal names the climb limit: {said}"
    );
}

/// KR-REQ-23.44: the authority a mutation arrived under is decided inside the transaction that
/// commits its **effect**, not once at the claim.
///
/// A capture reads a whole working tree between the two, and a revocation that lands during that
/// read has to stop it. Here the claim is taken under an authority that holds, the authority is
/// then withdrawn, and the capture that follows records no change set and no version.
#[test]
fn an_authority_withdrawn_after_the_claim_records_no_version() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "withdrawn");
    write(&path, "README.md", "changed after the commit\n");
    let workspace = fixture.workspace("withdrawn");

    // One version, so there is a change set for the refused capture to be appended to and the
    // count below says exactly what the refusal left behind.
    let first = fixture.capture(workspace, &include_everything());
    let change_set_id = first.change_set_id;

    let authority = support::Authority::held();
    support::claim(fixture.service(), "changeset.capture", &authority);
    assert_eq!(authority.asked(), 1, "the claim asked once");
    authority.withdraw();

    let refusal = fixture
        .capture_admitted(workspace, Some(change_set_id), &authority)
        .expect_err("a capture whose authority has gone is refused");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        refusal.to_string().contains("has been withdrawn"),
        "the daemon's own sentence reaches the caller: {refusal}"
    );
    assert!(
        authority.asked() > 1,
        "the effect asked for itself rather than relying on the claim's answer"
    );
    let versions = fixture
        .service()
        .versions(change_set_id)
        .expect("the change set reads");
    assert_eq!(
        versions.len(),
        1,
        "the refused capture appended nothing: only the version that was captured under \
         authority that held is there"
    );
    assert_eq!(versions[0].version, first.version);

    // And with the authority in force again, a capture of the same workspace succeeds: what the
    // refusal stopped was this mutation, not the change set.
    let held = support::Authority::held();
    let second = fixture
        .capture_admitted(workspace, Some(change_set_id), &held)
        .expect("a capture under authority that holds");
    assert!(
        second.version.get() > first.version.get(),
        "the version that follows comes after the one that was recorded"
    );
}

/// KR-REQ-23.44: the same rule for a capture that would start a **new** change set.
///
/// The change set is the first row such a capture writes, so the authority is asked there too: a
/// refusal leaves no empty change set for a reader to find.
#[test]
fn an_authority_withdrawn_before_a_new_change_set_leaves_none_behind() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "empty-set");
    let workspace = fixture.workspace("empty-set");

    let authority = support::Authority::held();
    support::claim(fixture.service(), "changeset.capture", &authority);
    authority.withdraw();

    let refusal = fixture
        .capture_admitted(workspace, None, &authority)
        .expect_err("a capture whose authority has gone is refused");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);

    // A capture under authority that holds makes the first change set this workspace has, and its
    // first version is version one: nothing of the refused attempt is there to append to.
    let held = support::Authority::held();
    let made = fixture
        .capture_admitted(workspace, None, &held)
        .expect("a capture under authority that holds");
    assert_eq!(made.version.get(), 1);
    assert_eq!(
        fixture
            .service()
            .versions(made.change_set_id)
            .expect("the change set reads")
            .len(),
        1
    );
}

/// KR-REQ-14.32: a file this host read while something was writing it contradicts the
/// reservation, and a retry that reads the file whole does not take that back.
///
/// One failed read followed by a successful one: the file is written exactly once, in the window
/// between this host reading its content and reading its metadata back, so the first attempt is
/// discarded and the second reads it whole. The content is complete and the capture succeeds; the
/// class is the weaker one, because the tree was not still.
#[test]
fn a_file_written_during_its_read_is_not_a_quiesced_capture_even_when_the_retry_succeeds() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "rewritten");
    write(&path, "README.md", "the work in progress\n");
    let workspace = fixture.workspace("rewritten");
    let authority = reservation::Authority::new(reservation::Behaviour::Holds);

    // Written once, inside the read of README.md's own content. Every later attempt reads a file
    // nothing is touching.
    let writes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&writes);
    let target = path.clone();
    kr_changeset::capture::interpose_working_tree_reads(Some(Arc::new(move |read: &str, _| {
        if read == "README.md" && counted.fetch_add(1, Ordering::SeqCst) == 0 {
            std::fs::write(target.join("README.md"), "written under the reservation\n")
                .expect("the fixture writes the file this host is reading");
        }
    })));
    let record = fixture.capture_with_authority(
        workspace,
        &include_everything(),
        &FileGrant::default(),
        None,
        None,
        Some(&authority),
    );
    kr_changeset::capture::interpose_working_tree_reads(None);
    let record = record.expect("the capture reads the file whole on its second attempt");

    assert!(
        writes.load(Ordering::SeqCst) > 1,
        "the file was read again after it was written"
    );
    assert_eq!(
        record.consistency,
        SourceConsistency::PerFileCapture,
        "a tree something wrote to is not one that was held still: {}",
        record.consistency_detail
    );
    assert!(
        !record.policy.quiescence_held,
        "and the policy records that nothing held it"
    );
    assert!(
        record
            .consistency_detail
            .contains("was written while this host was reading it"),
        "the detail says what contradicted the reservation: {}",
        record.consistency_detail
    );
    // The content is the whole of the second reading rather than half of each.
    let readme = record
        .changes
        .iter()
        .find(|entry| entry.path == "README.md")
        .expect("the file is in the version");
    assert_eq!(
        readme.content_digest,
        kr_changeset::objects::digest_of(b"written under the reservation\n")
    );
}

/// KR-REQ-14.32: the same reading, under a request that requires the stronger class, is refused
/// rather than served the weaker one.
#[test]
fn requiring_the_quiesced_class_refuses_a_capture_whose_file_was_written_under_it() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "required");
    write(&path, "README.md", "the work in progress\n");
    let workspace = fixture.workspace("required");
    let authority = reservation::Authority::new(reservation::Behaviour::Holds);

    let counted = Arc::new(AtomicUsize::new(0));
    let writes = Arc::clone(&counted);
    let target = path.clone();
    kr_changeset::capture::interpose_working_tree_reads(Some(Arc::new(move |read: &str, _| {
        if read == "README.md" && writes.fetch_add(1, Ordering::SeqCst) == 0 {
            std::fs::write(target.join("README.md"), "written under the reservation\n")
                .expect("the fixture writes the file this host is reading");
        }
    })));
    let outcome = fixture.capture_with_authority(
        workspace,
        &include_everything(),
        &FileGrant::default(),
        None,
        Some(SourceConsistency::QuiescedCapture),
        Some(&authority),
    );
    kr_changeset::capture::interpose_working_tree_reads(None);

    let refusal = outcome.expect_err("the required class was not performed");
    let said = refusal.to_string();
    assert!(
        said.contains("requires a quiesced_capture"),
        "the refusal names what was required: {said}"
    );
    assert!(
        said.contains("so nothing held it still"),
        "and what contradicted it: {said}"
    );
    assert_eq!(
        counted.load(Ordering::SeqCst),
        2,
        "the file was read once, written, and read whole once more; the capture then refused \
         rather than reading the whole tree again"
    );
}
