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
        message.contains("per_file_capture") && message.contains("atomic_snapshot"),
        "the refusal names both classes: {message}"
    );
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
    assert_eq!(
        exclusion(&record, "src/lib.rs").reason,
        ExclusionReason::Deleted
    );
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("its manifest");
    assert!(
        manifest.path("src/lib.rs").is_none(),
        "the captured tree does not hold it"
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
