//! `diff.read`, `diff.apply` and `diff.revert`: the destination classes, the preflight and the
//! five outcome classes.
//!
//! Requirement rows closed here: KR-REQ-14.04 (a diff identifies its source revision and an apply
//! checks concurrent changes), KR-REQ-14.25 (read results carry identity, base and head, the
//! tracked, untracked and binary changes and the content revisions), KR-REQ-14.26 (a preflight
//! conflict returns `DRAFT_CONFLICT` with no writes), KR-REQ-14.27 (an apply defaults to an
//! immutable proposal, and a versioned Git reference is compare-and-swap that does not update a
//! dirty working tree), KR-REQ-14.28 (a direct apply to `shared_existing` is best-effort conflict
//! detection with recoverable versions, and its limitation is shown first), KR-REQ-14.29
//! (permissions and line endings preserved, per-path progress, the five outcome classes, and a
//! crash after one file that never yields an atomic-success receipt) and KR-REQ-14.30 (review
//! completion never triggers a commit, a push or a destructive revert).

#![cfg(not(windows))]

mod support;

use std::path::Path;

use kr_changeset::apply::{self, ApplyOrder, Fault};
use kr_protocol::changeset::{
    AffectedVersion, ApplyOutcomeClass, DestinationClass, EvidenceKind, ExpectedReference,
    PathClass, PathProgressState,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::Nullable;

use support::{
    Fixture, expectations, git_raw, include_everything, ordinary_repository, reference, write,
    write_bytes,
};

/// An action claim that remembers whether it was ever asked for.
#[derive(Default)]
struct RecordingClaim {
    asked: std::cell::Cell<bool>,
}

impl RecordingClaim {
    fn taken(&self) -> bool {
        self.asked.get()
    }
}

impl apply::ActionClaim for RecordingClaim {
    fn claim(&self) -> kr_changeset::Result<bool> {
        self.asked.set(true);
        Ok(true)
    }
}

/// KR-REQ-14.04 and 14.25: a read identifies its repository, its workspace, its base and its head,
/// and names every tracked, untracked and binary change with the content revision of each side.
#[test]
fn a_diff_read_carries_identity_base_head_and_both_content_revisions() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "read");
    write(&path, "README.md", "changed after the commit\n");
    write(&path, "notes.txt", "the user's own\n");
    write_bytes(&path, "image.bin", &[0_u8, 1, 2, 0]);
    let workspace = fixture.workspace("read");

    let read = apply::read(fixture.service(), Some(workspace), None).expect("the read succeeds");
    assert_eq!(read.workspace_id, workspace);
    assert_eq!(read.environment_id, fixture.environment_id());
    assert!(!read.base_revision.is_empty());
    assert_eq!(read.base_revision, read.head_revision);
    assert_eq!(read.head_reference.0.as_deref(), Some("refs/heads/main"));
    assert_ne!(read.repository_identity, read.worktree_identity);

    let readme = read
        .tracked
        .iter()
        .find(|entry| entry.path == "README.md")
        .expect("the tracked change is named");
    assert_eq!(readme.class, PathClass::DirtyFile);
    assert!(
        readme.base_object_id.0.is_some(),
        "the base side's content revision"
    );
    assert_eq!(
        readme.content_digest,
        Nullable(Some(support::digest_of_file(&path, "README.md"))),
        "and the other side's"
    );
    let untracked: Vec<&str> = read
        .untracked
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert!(untracked.contains(&"notes.txt"));
    assert!(untracked.contains(&"image.bin"));
    let binary = read
        .untracked
        .iter()
        .find(|entry| entry.path == "image.bin")
        .expect("the binary file is named");
    assert_eq!(binary.content, kr_protocol::project::ContentClass::Binary);
    let counted = read
        .counts
        .iter()
        .find(|count| count.class == PathClass::UntrackedFile)
        .expect("the untracked class is counted");
    assert_eq!(counted.binary.get(), 1);

    // A read of a captured version names the version it is of.
    let record = fixture.capture(workspace, &include_everything());
    let read = apply::read(fixture.service(), None, Some(reference(&record)))
        .expect("a version is readable");
    assert_eq!(read.source_version, Nullable(Some(reference(&record))));
    assert_eq!(read.base_revision, record.base_revision);
}

/// KR-REQ-14.26: a preflight conflict is `DRAFT_CONFLICT` and writes nothing, to the destination
/// or to this host's own journal.
#[test]
fn a_preflight_conflict_returns_draft_conflict_and_writes_nothing() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "conflict");
    write(&path, "README.md", "the version this change is against\n");
    let workspace = fixture.workspace("conflict");
    let record = fixture.capture(workspace, &include_everything());
    let affected = expectations(&path, &["README.md"]);
    // Somebody else writes the destination after the request was composed.
    write(&path, "README.md", "somebody else got here first\n");

    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    // Nothing durable is written for a refused preflight, and the claim on the action is part of
    // that: it is taken only once the preflight has passed, so a host that stops here leaves
    // nothing behind for the next attempt to trip over.
    let claim = RecordingClaim::default();
    let order = ApplyOrder {
        claim: Some(&claim),
        ..order
    };
    let failure = apply::apply(fixture.service(), &order).expect_err("the preflight refuses");
    assert_eq!(failure.code(), ErrorCode::DraftConflict);
    assert!(
        !claim.taken(),
        "a refused preflight never asks for the action's claim"
    );
    assert!(
        failure.to_string().contains("nothing was written"),
        "the refusal says so: {failure}"
    );
    // The destination is exactly as the other writer left it.
    assert_eq!(
        support::read_bytes(&path, "README.md"),
        b"somebody else got here first\n"
    );
    // And this host recorded no apply at all.
    assert!(
        apply::read_apply(fixture.service(), action).is_err(),
        "a preflight conflict leaves no apply record"
    );
    // A preflight that finds the destination as expected has no outcome class, because nothing
    // ran, and it carries the limitations the caller is about to choose under.
    let affected = expectations(&path, &["README.md"]);
    let order = ApplyOrder {
        affected: &affected,
        preflight_only: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let clean = apply::apply(fixture.service(), &order).expect("the preflight passes");
    assert_eq!(clean.outcome, Nullable(None));
    assert_eq!(clean.limitations.len(), 3);
}

/// KR-REQ-14.27: an apply to a proposal records two immutable versions and writes to no working
/// tree at all.
#[test]
fn a_proposal_records_versions_and_writes_no_working_tree() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "proposed");
    write(&path, "README.md", "the change to propose\n");
    let workspace = fixture.workspace("proposed");
    let record = fixture.capture(workspace, &include_everything());
    // The destination moves on, which is what a proposal is for.
    write(&path, "README.md", "the destination as it stands\n");
    let affected = expectations(&path, &["README.md"]);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::Proposal,
        workspace,
        &affected,
        &[],
    );
    let result = apply::apply(fixture.service(), &order).expect("the proposal is recorded");
    assert_eq!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert!(result.changed_paths.is_empty());
    assert_eq!(
        support::read_bytes(&path, "README.md"),
        b"the destination as it stands\n",
        "a proposal writes to no working tree"
    );
    let Nullable(Some(proposal)) = result.proposal_version else {
        panic!("a proposal names the version it recorded");
    };
    let manifest = fixture
        .service()
        .manifest(proposal.change_set_id, proposal.version)
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
        b"the change to propose\n",
        "the proposal holds what would be there"
    );
    // Both recovery objects are named, and the before one is the destination as it stood.
    let Nullable(Some(before)) = result.recovery.before_version else {
        panic!("a proposal records what the destination held");
    };
    let before_manifest = fixture
        .service()
        .manifest(before.change_set_id, before.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                before_manifest
                    .path("README.md")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"the destination as it stands\n"
    );
}

/// KR-REQ-14.27: an apply to a versioned Git reference is compare-and-swap on the reference; a
/// value that does not match is `DRAFT_CONFLICT`, and what this host does not do it says.
#[test]
fn a_versioned_reference_is_compare_and_swap_and_states_what_it_does_not_do() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "reference");
    let head = git_raw(&path, ["rev-parse", "HEAD"]).trim().to_owned();
    write(&path, "README.md", "a change\n");
    let workspace = fixture.workspace("reference");
    let record = fixture.capture(workspace, &include_everything());
    let affected = expectations(&path, &["README.md"]);

    // The value the request expects is not the value the reference holds.
    let wrong = ExpectedReference {
        name: "refs/heads/main".to_owned(),
        expected_old_value: Nullable(Some("0".repeat(40))),
    };
    let order = ApplyOrder {
        expected_reference: Some(&wrong),
        ..support::apply_order(
            reference(&record),
            DestinationClass::VersionedReference,
            workspace,
            &affected,
            &[],
        )
    };
    let failure = apply::apply(fixture.service(), &order).expect_err("the swap does not hold");
    assert_eq!(failure.code(), ErrorCode::DraftConflict);

    // The value it expects is the value the reference holds, and this host says what it will not
    // do rather than doing it under a read-only grant.
    let right = ExpectedReference {
        name: "refs/heads/main".to_owned(),
        expected_old_value: Nullable(Some(head.clone())),
    };
    let order = ApplyOrder {
        expected_reference: Some(&right),
        ..support::apply_order(
            reference(&record),
            DestinationClass::VersionedReference,
            workspace,
            &affected,
            &[],
        )
    };
    let refusal = apply::apply(fixture.service(), &order).expect_err("the limitation is stated");
    assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
    let message = refusal.to_string();
    assert!(
        message.contains("does not move it"),
        "it says what it does not do: {message}"
    );
    assert!(
        message.contains("does not atomically update a dirty working tree"),
        "and what a reference update is not: {message}"
    );
    // The reference is where it was.
    assert_eq!(git_raw(&path, ["rev-parse", "HEAD"]).trim(), head);

    // A preflight returns the outcome of the comparison before the class is acted on.
    let order = ApplyOrder {
        expected_reference: Some(&right),
        preflight_only: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::VersionedReference,
            workspace,
            &affected,
            &[],
        )
    };
    let previewed = apply::apply(fixture.service(), &order).expect("the preflight passes");
    let Nullable(Some(outcome)) = previewed.reference else {
        panic!("a preflight of this class names the reference");
    };
    assert!(outcome.compare_and_swap_held);
    assert!(!outcome.updated);
    assert_eq!(outcome.observed_old_value, Nullable(Some(head)));
}

/// KR-REQ-14.28 and 14.29: a direct apply installs the content, preserves the destination's
/// permissions and the content's line endings, records each path's progress on both sides, and
/// leaves recoverable versions of the tree before and after.
#[test]
fn a_direct_apply_installs_the_content_and_records_what_it_did() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source-tree");
    write_bytes(
        &source,
        "README.md",
        b"the change\r\nwith a carriage return\r\n",
    );
    write(&source, "src/deep/new.rs", "a file in a new directory\n");
    let source_workspace = fixture.workspace("source-tree");
    let record = fixture.capture(source_workspace, &include_everything());

    // The destination is a second checkout of the same commit, with one of the files executable
    // so the apply has a permission to preserve.
    let destination = ordinary_repository(fixture.work(), "destination-tree");
    support::make_executable(&destination, "README.md");
    let workspace = fixture.workspace("destination-tree");
    let affected = expectations(&destination, &["README.md", "src/deep/new.rs"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let result = apply::apply(fixture.service(), &order).expect("the apply runs");

    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "{}: {:?}",
        result.detail,
        result.progress
    );
    assert_eq!(result.changed_paths.len(), 2);
    assert!(result.unresolved_paths.is_empty());
    assert!(result.conflicts.is_empty());
    // The bytes are exactly the version's, carriage returns and all.
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"the change\r\nwith a carriage return\r\n"
    );
    assert_eq!(
        support::read_bytes(&destination, "src/deep/new.rs"),
        b"a file in a new directory\n"
    );
    // The destination's own permission is preserved rather than the version's imposed on it.
    assert!(
        support::is_executable(&destination, "README.md"),
        "the destination was executable and still is"
    );
    // Every path's progress is recorded on both sides.
    for row in &result.progress {
        assert_eq!(row.state, PathProgressState::Written);
        assert!(row.after_digest.0.is_some(), "what is there now");
    }
    let readme = result
        .progress
        .iter()
        .find(|row| row.path == "README.md")
        .expect("the path is named");
    assert!(
        readme.before_digest.0.is_some(),
        "and what was there before"
    );
    // Both recovery objects exist and are materialisable.
    let Nullable(Some(before)) = result.recovery.before_version else {
        panic!("an apply records what the destination held");
    };
    let Nullable(Some(after)) = result.recovery.after_version else {
        panic!("and what it holds now");
    };
    assert_ne!(before, after);
    let before_manifest = fixture
        .service()
        .manifest(before.change_set_id, before.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                before_manifest
                    .path("README.md")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"a repository\n",
        "the destination as it was"
    );
    // The journal says the same as the answer.
    let recorded = apply::read_apply(fixture.service(), action).expect("the apply is recorded");
    assert_eq!(recorded.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(recorded.changed_paths.len(), 2);
    // And the versions on each side are things a deletion has to account for.
    assert!(
        !fixture
            .service()
            .holders(before.change_set_id, before.version)
            .expect("the holders are read")
            .is_empty()
    );
}

/// KR-REQ-14.29: a direct apply preserves an access-control list on the destination.
///
/// An access-control list is protection this host must neither lose silently nor refuse across
/// an apply: the list is read through the destination handle, restored onto the staged copy, and
/// verified on read-back of the published file.
#[test]
fn a_direct_apply_preserves_an_access_control_list_on_the_destination() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source-tree");
    write_bytes(&source, "README.md", b"updated content with ACL\n");
    let source_workspace = fixture.workspace("source-tree");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "destination-tree");
    let readme_path = destination.join("README.md");
    let who = std::env::var("USER").unwrap_or_else(|_| "root".to_owned());
    let given = if cfg!(target_os = "macos") {
        std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(format!("{who} allow read"))
            .arg(&readme_path)
            .status()
    } else {
        std::process::Command::new("setfacl")
            .arg("-m")
            .arg(format!("u:{who}:r"))
            .arg(&readme_path)
            .status()
    };
    match given {
        Ok(status) if status.success() => {
            let authority_before = kr_transfer::AuthorisedDirectory::open_root(
                fixture.service().environment_id(),
                &destination,
            )
            .expect("opens authority before");
            let name = kr_transfer::RelativeName::parse("README.md").expect("valid name");
            let file_before = authority_before
                .open_read(&name, kr_transfer::ObjectPolicy::ReadableFile)
                .expect("opens file before");
            let initial_acl = file_before
                .access_control()
                .expect("reads initial access control");
            assert!(
                initial_acl.has_entries(),
                "the destination initially carries access-control entries"
            );
            drop(file_before);
            drop(authority_before);

            let workspace = fixture.workspace("destination-tree");
            let affected = expectations(&destination, &["README.md"]);
            let limitations = apply::limitations(DestinationClass::SharedExisting);
            let order = support::apply_order(
                reference(&record),
                DestinationClass::SharedExisting,
                workspace,
                &affected,
                &limitations,
            );
            let result = apply::apply(fixture.service(), &order).expect("the apply runs");
            assert_eq!(
                result.outcome,
                Nullable(Some(ApplyOutcomeClass::Applied)),
                "{}: {:?}",
                result.detail,
                result.progress
            );
            assert_eq!(
                support::read_bytes(&destination, "README.md"),
                b"updated content with ACL\n"
            );
            let authority = kr_transfer::AuthorisedDirectory::open_root(
                fixture.service().environment_id(),
                &destination,
            )
            .expect("opens authority");
            let file = authority
                .open_read(&name, kr_transfer::ObjectPolicy::ReadableFile)
                .expect("opens file");
            assert!(
                file.carries_access_control(),
                "the destination still carries its access-control list after apply"
            );
            let acl = file.access_control().expect("reads access control");
            assert_eq!(
                acl, initial_acl,
                "the destination's access-control list matches before apply exactly"
            );
        }
        _ => println!(
            "not exercised: this platform's access-control tool did not run, so the \
             ACL preservation apply test was skipped"
        ),
    }
}

/// An access-control list altered on the staged copy before rename is caught by read-back
/// verification, leaving the result unresolved rather than claiming success under altered permissions.
#[test]
fn an_apply_detects_an_access_control_list_tampered_during_staging_and_refuses() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "tampered-acl-source");
    write_bytes(&source, "README.md", b"tampered ACL content\n");
    let source_workspace = fixture.workspace("tampered-acl-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "tampered-acl-destination");
    let who = std::env::var("USER").unwrap_or_else(|_| "root".to_owned());
    // Destination has no ACL initially.
    let racing = destination.clone();
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: Some(std::sync::Arc::new(move |path: &str| {
            if path == "README.md" {
                let temporary = format!(
                    ".kr-apply-{}",
                    kr_changeset::objects::hex_of(kr_changeset::objects::digest_of(
                        path.as_bytes()
                    ))
                );
                let staged_path = racing.join(temporary);
                let status = if cfg!(target_os = "macos") {
                    std::process::Command::new("/bin/chmod")
                        .arg("+a")
                        .arg(format!("{who} allow read"))
                        .arg(&staged_path)
                        .status()
                } else {
                    std::process::Command::new("setfacl")
                        .arg("-m")
                        .arg(format!("u:{who}:r"))
                        .arg(&staged_path)
                        .status()
                };
                assert!(
                    status.expect("tampering command ran").success(),
                    "tampering staged ACL succeeded"
                );
            }
        })),
        stop: false,
        detail: String::new(),
    }));

    let workspace = fixture.workspace("tampered-acl-destination");
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply runs");
    assert_ne!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "tampered staged ACL must not report Applied"
    );
    assert_eq!(result.unresolved_paths, vec!["README.md".to_owned()]);
    let row = result
        .progress
        .iter()
        .find(|row| row.path == "README.md")
        .expect("the path is named");
    assert_eq!(row.state, PathProgressState::Unresolved);
    assert!(
        row.detail
            .contains("under permissions this host did not set on it"),
        "the row says what happened: {}",
        row.detail
    );
}

/// KR-REQ-14.28: a direct apply is not chosen until its limitation has been shown.
#[test]
fn a_direct_apply_is_refused_until_its_limitation_has_been_shown() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "unshown");
    write(&path, "README.md", "a change\n");
    let workspace = fixture.workspace("unshown");
    let record = fixture.capture(workspace, &include_everything());
    let affected = expectations(&path, &["README.md"]);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &[],
    );
    let failure = apply::apply(fixture.service(), &order).expect_err("the class is not chosen yet");
    assert_eq!(failure.code(), ErrorCode::InvalidArgument);
    assert!(
        failure
            .to_string()
            .contains("best-effort conflict detection"),
        "the refusal shows the limitation it wants back: {failure}"
    );
}

/// KR-REQ-14.29: a crash after one file never yields an atomic-success receipt.
///
/// The apply is stopped exactly where a daemon that died would stop it: after one path has landed
/// and been recorded, and before anything settles the apply. A replacement service on the same
/// journal then reads what is there.
#[test]
fn a_crash_after_one_file_never_yields_an_atomic_success_receipt() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "crash-source");
    write(&source, "README.md", "the first change\n");
    write(&source, "src/lib.rs", "pub fn answer() -> u32 { 43 }\n");
    let source_workspace = fixture.workspace("crash-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "crash-destination");
    let workspace = fixture.workspace("crash-destination");
    let affected = expectations(&destination, &["README.md", "src/lib.rs"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    fixture.service().inject(Some(Fault {
        after_paths: 1,
        act: None,
        before_rename: None,
        stop: true,
        detail: "the daemon stopped after one path".to_owned(),
    }));
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let failure = apply::apply(fixture.service(), &order).expect_err("the apply is stopped");
    assert_eq!(failure.code(), ErrorCode::OutcomeUnknown);

    // A replacement service on the same journal finds an apply nobody decided.
    let replacement = fixture.reopen();
    let open = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        open.outcome,
        Nullable(None),
        "an apply nothing decided has no class"
    );
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);

    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.outcome,
        Nullable(Some(ApplyOutcomeClass::InterruptedApply)),
        "a crash after one file is an interrupted apply and never an applied one"
    );
    assert_ne!(settled.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    // Exactly the path that landed is named as changed, and the one that did not is unresolved.
    assert_eq!(settled.changed_paths.len(), 1);
    assert_eq!(settled.unresolved_paths.len(), 1);
    assert_ne!(settled.changed_paths[0], settled.unresolved_paths[0]);
    // A path whose outcome this host did not establish says exactly that.
    let unresolved = settled
        .progress
        .iter()
        .find(|row| row.state == PathProgressState::Planned)
        .expect("the path it did not finish is still planned");
    assert!(
        unresolved.detail.contains("going to write"),
        "the row says what it means: {}",
        unresolved.detail
    );
    assert!(
        settled
            .detail
            .contains("not the same as ones it did not write"),
        "and so does the apply: {}",
        settled.detail
    );
    // The destination really does hold one of the two.
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"the first change\n"
    );
    assert_eq!(
        support::read_bytes(&destination, "src/lib.rs"),
        b"pub fn answer() -> u32 { 42 }\n",
        "the second path was never written"
    );
}

/// KR-REQ-14.28 and 14.29: an external write between the recheck and the rename is the declared
/// honest outcome, with exactly the paths that landed named.
#[test]
fn an_external_write_between_the_recheck_and_the_rename_is_a_conflict_after_partial_writes() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "racing-source");
    write(&source, "README.md", "the first change\n");
    write(&source, "src/lib.rs", "pub fn answer() -> u32 { 43 }\n");
    let source_workspace = fixture.workspace("racing-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "racing-destination");
    let workspace = fixture.workspace("racing-destination");
    let affected = expectations(&destination, &["README.md", "src/lib.rs"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    // After the first path lands, somebody else writes the second one.
    let racing = destination.clone();
    fixture.service().inject(Some(Fault {
        after_paths: 1,
        act: Some(std::sync::Arc::new(move || {
            std::fs::write(racing.join("src/lib.rs"), b"somebody else wrote this\n")
                .expect("the other writer writes");
        })),
        before_rename: None,
        stop: false,
        detail: String::new(),
    }));
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply reports what happened");
    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::ConflictAfterPartialWrites))
    );
    assert_eq!(result.changed_paths, vec!["README.md".to_owned()]);
    assert_eq!(result.conflicts.len(), 1);
    assert_eq!(result.conflicts[0].path, "src/lib.rs");
    // The other writer's bytes are still there: this host did not write over them.
    assert_eq!(
        support::read_bytes(&destination, "src/lib.rs"),
        b"somebody else wrote this\n"
    );
}

/// KR-REQ-14.30: recording that somebody reviewed a version runs no Git invocation, writes to no
/// working tree, and leaves the repository exactly as it was.
#[test]
fn review_completion_never_commits_pushes_or_reverts() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "reviewed");
    write(&path, "README.md", "work under review\n");
    write(&path, "untracked.txt", "the user's own\n");
    let workspace = fixture.workspace("reviewed");
    let record = fixture.capture(workspace, &include_everything());
    let head = git_raw(&path, ["rev-parse", "HEAD"]).trim().to_owned();
    let status = git_raw(&path, ["status", "--porcelain"]);

    fixture
        .service()
        .record_evidence(
            record.change_set_id,
            record.version,
            EvidenceKind::ReviewAcknowledgement,
            "a reviewer acknowledged this version",
        )
        .expect("the acknowledgement is recorded");

    // Nothing moved: not the reference, not the index, not the working tree.
    assert_eq!(git_raw(&path, ["rev-parse", "HEAD"]).trim(), head);
    assert_eq!(git_raw(&path, ["status", "--porcelain"]), status);
    assert_eq!(
        support::read_bytes(&path, "README.md"),
        b"work under review\n"
    );
    assert_eq!(
        support::read_bytes(&path, "untracked.txt"),
        b"the user's own\n",
        "an untracked file is never cleaned away"
    );
    // The acknowledgement is what it says it is: a record against the version.
    let evidence = fixture
        .service()
        .evidence(record.change_set_id, record.version)
        .expect("the evidence is readable");
    assert!(
        evidence
            .iter()
            .any(|entry| entry.kind == EvidenceKind::ReviewAcknowledgement)
    );
    // And the subcommands that would do any of those things are ones this host cannot run.
    for subcommand in ["commit", "push", "revert", "reset", "clean", "stash"] {
        assert!(
            kr_project::git::check_arguments(&[std::ffi::OsStr::new(subcommand)]).is_err(),
            "git {subcommand} is not a subcommand this host runs"
        );
    }
}

/// KR-REQ-14.28: a revert puts the base's own content back, and never removes a file the base
/// never held.
#[test]
fn a_revert_restores_the_base_and_removes_nothing_of_the_user_s() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "reverted");
    write(&path, "README.md", "the change to revert\n");
    write(&path, "added.txt", "a file the base never held\n");
    let workspace = fixture.workspace("reverted");
    let record = fixture.capture(workspace, &include_everything());
    let affected = expectations(&path, &["README.md", "added.txt"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = ApplyOrder {
        revert: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let result = apply::apply(fixture.service(), &order).expect("the revert runs");
    assert_ne!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "an operation this host refused keeps the apply from being an applied change"
    );
    assert_eq!(
        support::read_bytes(&path, "README.md"),
        b"a repository\n",
        "the base's own content is back"
    );
    assert_eq!(
        support::read_bytes(&path, "added.txt"),
        b"a file the base never held\n",
        "a file the base never held is left exactly as it is"
    );
    assert!(
        result.unresolved_paths.contains(&"added.txt".to_owned()),
        "and it is named as one this host did not resolve: {:?}",
        result.unresolved_paths
    );
}

/// KR-REQ-14.25: an apply that would write a path the request does not describe is refused, so the
/// preflight is never asked to check something it cannot see.
#[test]
fn an_apply_that_names_no_expectation_for_a_path_it_would_write_is_refused() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "unchecked");
    write(&path, "README.md", "a change\n");
    let workspace = fixture.workspace("unchecked");
    let record = fixture.capture(workspace, &include_everything());
    let empty: Vec<AffectedVersion> = Vec::new();
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &empty,
        &limitations,
    );
    let failure = apply::apply(fixture.service(), &order).expect_err("it is refused");
    assert_eq!(failure.code(), ErrorCode::InvalidArgument);
    assert!(
        failure
            .to_string()
            .contains("the preflight cannot check it"),
        "the refusal says why: {failure}"
    );
    let _ = Path::new(&path);
}

/// KR-REQ-14.25 and 14.29: a version whose working tree deleted a path carries that deletion as an
/// operation, and an apply that performs it says so rather than reporting that it applied nothing.
#[test]
fn a_version_that_only_deletes_carries_the_deletion_as_an_operation() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "deleting-source");
    std::fs::remove_file(source.join("src/lib.rs")).expect("the user deletes a tracked file");
    let source_workspace = fixture.workspace("deleting-source");
    let record = fixture.capture(source_workspace, &include_everything());
    assert!(
        record.changes.is_empty(),
        "this version holds no changed content at all"
    );

    let destination = ordinary_repository(fixture.work(), "deleting-destination");
    let workspace = fixture.workspace("deleting-destination");
    let affected = support::expectations(&destination, &["src/lib.rs"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply runs");
    assert_eq!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(result.changed_paths, vec!["src/lib.rs".to_owned()]);
    support::assert_absent(&destination.join("src/lib.rs"));
    // And a path the version does not carry at all is still refused by name.
    let order = ApplyOrder {
        paths: &["README.md".to_owned()],
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let failure = apply::apply(fixture.service(), &order).expect_err("it is refused");
    assert!(
        failure.to_string().contains("no change and no deletion"),
        "the refusal says why: {failure}"
    );
}

/// KR-REQ-14.04 and 14.29: a deletion is reverted from what the version itself holds, and a
/// deletion whose base is not file content is refused rather than written out as a regular file.
#[test]
fn a_deletion_is_reverted_from_the_version_s_own_content() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "revert-source");
    std::fs::remove_file(source.join("src/lib.rs")).expect("the user deletes a tracked file");
    let source_workspace = fixture.workspace("revert-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "revert-destination");
    std::fs::remove_file(destination.join("src/lib.rs")).expect("and it is gone there too");
    let workspace = fixture.workspace("revert-destination");
    let affected = support::expectations(&destination, &["src/lib.rs"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = ApplyOrder {
        revert: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let result = apply::apply(fixture.service(), &order).expect("the revert runs");
    assert_eq!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(
        support::read_bytes(&destination, "src/lib.rs"),
        b"pub fn answer() -> u32 { 42 }\n",
        "the base's own content is back"
    );
}

/// KR-REQ-14.29: what the base holds for a deleted path has to be file content.
#[test]
fn a_deleted_link_is_never_reverted_as_a_regular_file() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "link-source");
    std::os::unix::fs::symlink("README.md", source.join("shortcut")).expect("a link");
    git_raw(&source, ["add", "shortcut"]);
    git_raw(&source, ["commit", "--quiet", "-m", "a link"]);
    std::fs::remove_file(source.join("shortcut")).expect("the user deletes it");
    let source_workspace = fixture.workspace("link-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "link-destination");
    let workspace = fixture.workspace("link-destination");
    let affected = support::expectations(&destination, &["shortcut"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = ApplyOrder {
        revert: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let result = apply::apply(fixture.service(), &order).expect("the revert runs");
    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::UncertainOutcome)),
        "a revert that could not put back what the base holds is not an applied change"
    );
    assert_eq!(result.unresolved_paths, vec!["shortcut".to_owned()]);
    support::assert_absent(&destination.join("shortcut"));
}

/// KR-REQ-14.28 and 14.29: an external write between the recheck and the rename is the window this
/// host states it cannot close. The apply reports what it did, and the version it captured before
/// it is what a person recovers the overwritten content from.
#[test]
fn a_write_in_the_window_this_host_cannot_close_is_recoverable_from_the_before_version() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "window-source");
    write(&source, "README.md", "the change this apply carries\n");
    let source_workspace = fixture.workspace("window-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "window-destination");
    let workspace = fixture.workspace("window-destination");
    let affected = support::expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    // Somebody writes the destination **after** this host's last look at it and before the rename.
    let racing = destination.clone();
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: Some(std::sync::Arc::new(move |path: &str| {
            if path == "README.md" {
                std::fs::write(racing.join("README.md"), b"somebody else wrote this\n")
                    .expect("the other writer writes");
            }
        })),
        stop: false,
        detail: String::new(),
    }));
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply runs");
    // The rename landed. This is the stated limitation, not a defect: a recheck is not a lock.
    assert_eq!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"the change this apply carries\n"
    );
    // What the other writer wrote is gone from the tree, and what was there *before the apply* is
    // recoverable, which is what this host does promise.
    let Nullable(Some(before)) = result.recovery.before_version else {
        panic!("an apply records what the destination held");
    };
    let manifest = fixture
        .service()
        .manifest(before.change_set_id, before.version)
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
        b"a repository\n"
    );
    assert!(
        result
            .limitations
            .iter()
            .any(|line| line.contains("does not claim to have captured every intermediate")),
        "and the answer says what it does not claim: {:?}",
        result.limitations
    );
}

/// KR-REQ-14.29: a rename that installed something other than the validated content is caught
/// rather than recorded as a success.
#[test]
fn a_destination_that_does_not_hold_what_was_installed_is_never_recorded_as_written() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "swapped-source");
    write(&source, "README.md", "the validated content\n");
    let source_workspace = fixture.workspace("swapped-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "swapped-destination");
    let workspace = fixture.workspace("swapped-destination");
    let affected = support::expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    // Somebody replaces the staged copy this host is about to rename into place.
    let racing = destination.clone();
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: Some(std::sync::Arc::new(move |path: &str| {
            if path == "README.md" {
                let temporary = format!(
                    ".kr-apply-{}",
                    kr_changeset::objects::hex_of(kr_changeset::objects::digest_of(
                        path.as_bytes()
                    ))
                );
                std::fs::write(racing.join(temporary), b"something else entirely\n")
                    .expect("the other writer replaces the staged copy");
            }
        })),
        stop: false,
        detail: String::new(),
    }));
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply reports what happened");
    assert_ne!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert!(result.changed_paths.is_empty());
    assert_eq!(result.unresolved_paths, vec!["README.md".to_owned()]);
    let row = result
        .progress
        .iter()
        .find(|row| row.path == "README.md")
        .expect("the path is named");
    assert_eq!(row.state, PathProgressState::Unresolved);
    assert!(
        row.detail
            .contains("other than the content this host installed"),
        "the row says what happened: {}",
        row.detail
    );
}

/// KR-REQ-14.26 and 14.28: this host removes nothing to make room for its own staging, and a name
/// it cannot use is a path it leaves exactly as it is.
#[test]
fn an_occupied_staging_name_is_left_alone_and_the_path_is_reported() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "occupied-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("occupied-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "occupied-destination");
    // Somebody's own file is at the name this host would stage through.
    let temporary = format!(
        ".kr-apply-{}",
        kr_changeset::objects::hex_of(kr_changeset::objects::digest_of(b"README.md"))
    );
    std::fs::write(destination.join(&temporary), b"somebody else's file\n").expect("their file");
    let workspace = fixture.workspace("occupied-destination");
    let affected = support::expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let result = apply::apply(fixture.service(), &order).expect("the apply reports what happened");
    assert_ne!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(result.unresolved_paths, vec!["README.md".to_owned()]);
    assert_eq!(
        support::read_bytes(&destination, &temporary),
        b"somebody else's file\n",
        "nothing of theirs was removed"
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "and the destination is as it was"
    );
}

/// KR-REQ-14.28: a preflight returns the limitations without needing them back, which is how a
/// caller learns what it has to acknowledge.
#[test]
fn a_preflight_returns_the_limitations_a_direct_apply_then_requires() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "shown");
    write(&path, "README.md", "a change\n");
    let workspace = fixture.workspace("shown");
    let record = fixture.capture(workspace, &include_everything());
    let affected = support::expectations(&path, &["README.md"]);
    let order = ApplyOrder {
        preflight_only: true,
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &[],
        )
    };
    let shown =
        apply::apply(fixture.service(), &order).expect("a preflight needs no acknowledgement");
    assert_eq!(shown.outcome, Nullable(None));
    assert_eq!(
        shown.limitations,
        apply::limitations(DestinationClass::SharedExisting)
    );
    // And what it returned is exactly what the apply then accepts.
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &shown.limitations,
    );
    let applied = apply::apply(fixture.service(), &order).expect("the apply runs");
    assert_eq!(applied.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
}

/// KR-REQ-14.28 and KR-REQ-14.33: a path is content or administrative data because of the tree it
/// is being written to, not because of the tree it was captured from.
///
/// The version below holds an ordinary file of its own workspace. At the destination the same path
/// is inside that repository's own administrative data, which every capture excludes — so an apply
/// that wrote it would replace bytes neither recovery version holds. It is refused before anything
/// is read or written, and the destination is left exactly as it was.
#[test]
fn an_apply_never_writes_what_the_destination_keeps_its_own_data_in() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "ordinary-source");
    write(
        &source,
        "meta/config.worktree",
        "[remote]\n\turl = the-change\n",
    );
    let source_workspace = fixture.workspace("ordinary-source");
    let record = fixture.capture(source_workspace, &include_everything());

    // The destination keeps its own administrative data at `meta`, which is a shape Git accepts.
    let destination = ordinary_repository(fixture.work(), "split-destination");
    std::fs::rename(destination.join(".git"), destination.join("common")).expect("the shared data");
    std::fs::create_dir_all(destination.join("meta")).expect("this worktree's own");
    for name in ["HEAD", "index"] {
        let from = destination.join("common").join(name);
        if from.exists() {
            std::fs::copy(&from, destination.join("meta").join(name)).expect("its own copy");
        }
    }
    std::fs::write(destination.join("meta/commondir"), b"../common\n").expect("naming the shared");
    std::fs::write(
        destination.join("meta/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
    )
    .expect("something only this worktree has");
    std::fs::write(destination.join(".git"), b"gitdir: meta\n").expect("the file that names it");

    let workspace = fixture.workspace("split-destination");
    let affected = expectations(&destination, &["meta/config.worktree"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let refusal = apply::apply(fixture.service(), &order)
        .expect_err("an apply into a repository's own data is refused");
    assert!(
        refusal.to_string().contains("own administrative data"),
        "the refusal says what the destination keeps there: {refusal}"
    );
    assert_eq!(
        support::read_bytes(&destination, "meta/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
        "and the destination holds exactly what it held"
    );
}

/// KR-REQ-14.28 and KR-REQ-14.33: the destination's own data is found by looking at the
/// destination, not at the paths a request happens to name.
///
/// Here the administrative directory belongs to a repository **beside** the path being written:
/// `vendor/inner` keeps its data at `vendor/repo-data`, so a request that names only
/// `vendor/repo-data/config.worktree` names nothing that would find the repository that owns it.
/// The apply asks the destination what it holds before it writes anything, so it finds it anyway.
#[test]
fn an_apply_finds_the_destination_s_own_data_under_a_name_it_was_not_asked_about() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "plain-source");
    write(
        &source,
        "vendor/repo-data/config.worktree",
        "[remote]\n\turl = the-change\n",
    );
    let source_workspace = fixture.workspace("plain-source");
    let record = fixture.capture(source_workspace, &include_everything());

    // The destination holds a repository whose own data is at `vendor/repo-data`, under a name
    // nothing about the request mentions.
    let destination = ordinary_repository(fixture.work(), "sibling-destination");
    let data = destination.join("vendor/repo-data");
    std::fs::create_dir_all(&data).expect("the nested repository's data");
    for name in ["HEAD", "config"] {
        let from = destination.join(".git").join(name);
        if from.exists() {
            std::fs::copy(&from, data.join(name)).expect("its own copy");
        }
    }
    std::fs::write(
        data.join("config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
    )
    .expect("something only that repository has");
    std::fs::create_dir_all(destination.join("vendor/inner")).expect("its tree");
    std::fs::write(
        destination.join("vendor/inner/.git"),
        b"gitdir: ../repo-data\n",
    )
    .expect("the file that names it");
    std::fs::write(
        destination.join("vendor/inner/notes.txt"),
        b"its own content\n",
    )
    .expect("a file of that repository's tree");

    let workspace = fixture.workspace("sibling-destination");
    let affected = expectations(&destination, &["vendor/repo-data/config.worktree"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let refusal = apply::apply(fixture.service(), &order)
        .expect_err("an apply into a nested repository's own data is refused");
    assert!(
        refusal.to_string().contains("own administrative data")
            || refusal.to_string().contains("nested in it"),
        "the refusal says what is there: {refusal}"
    );
    assert_eq!(
        support::read_bytes(&destination, "vendor/repo-data/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
        "and the destination holds exactly what it held"
    );
}

/// KR-REQ-14.28, KR-REQ-14.33 and D-098: the repository that owns a destination's own data can sit
/// **inside a nested repository's tree**, where nothing reads.
///
/// `vendor/inner` is a vendored repository, so no reading of the destination looks inside it, and
/// the repository at `vendor/inner/child` keeps its data at `vendor/repo-data` — an ordinary
/// directory of the destination to every other part of this host. Discovery goes where content
/// reading stops, so the apply finds what is there before it writes anything.
#[test]
fn an_apply_finds_the_data_of_a_repository_inside_a_nested_one() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "deep-source");
    write(
        &source,
        "vendor/repo-data/config.worktree",
        "[remote]\n\turl = the-change\n",
    );
    let source_workspace = fixture.workspace("deep-source");
    let record = fixture.capture(source_workspace, &include_everything());

    // The destination holds a vendored repository, and inside **its** tree a repository whose own
    // data is `vendor/repo-data`.
    let destination = ordinary_repository(fixture.work(), "deep-destination");
    let data = destination.join("vendor/repo-data");
    std::fs::create_dir_all(&data).expect("the nested repository's data");
    for name in ["HEAD", "config"] {
        let from = destination.join(".git").join(name);
        if from.exists() {
            std::fs::copy(&from, data.join(name)).expect("its own copy");
        }
    }
    std::fs::write(
        data.join("config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
    )
    .expect("something only that repository has");
    let nested = destination.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("the vendored repository's tree");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    let child = nested.join("child");
    std::fs::create_dir_all(&child).expect("the tree of the repository inside it");
    std::fs::write(child.join(".git"), b"gitdir: ../../repo-data\n")
        .expect("the file that names where its data is");
    std::fs::write(child.join("notes.txt"), b"its own content\n").expect("a file of its tree");

    let workspace = fixture.workspace("deep-destination");
    let affected = expectations(&destination, &["vendor/repo-data/config.worktree"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let refusal = apply::apply(fixture.service(), &order)
        .expect_err("an apply into that repository's own data is refused");
    assert!(
        refusal.to_string().contains("own administrative data")
            || refusal.to_string().contains("nested in it"),
        "the refusal says what is there: {refusal}"
    );
    assert_eq!(
        support::read_bytes(&destination, "vendor/repo-data/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
        "and the destination holds exactly what it held"
    );
}

/// KR-REQ-14.28, KR-REQ-14.33 and D-098a: the repository that owns a destination's data can be at
/// the other end of a **link**, with its tree outside the destination altogether.
#[test]
fn an_apply_finds_the_data_of_a_repository_a_link_names() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "linked-source");
    write(
        &source,
        "vendor/repo-data/config.worktree",
        "[remote]\n\turl = the-change\n",
    );
    let source_workspace = fixture.workspace("linked-source");
    let record = fixture.capture(source_workspace, &include_everything());

    // The destination holds a vendored repository, and inside its tree a link naming a repository
    // whose own tree is elsewhere and whose data is `vendor/repo-data` here.
    let destination = ordinary_repository(fixture.work(), "linked-destination");
    let data = destination.join("vendor/repo-data");
    std::fs::create_dir_all(&data).expect("the other repository's data");
    for name in ["HEAD", "config"] {
        let from = destination.join(".git").join(name);
        if from.exists() {
            std::fs::copy(&from, data.join(name)).expect("its own copy");
        }
    }
    std::fs::write(
        data.join("config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
    )
    .expect("something only that repository has");
    let nested = destination.join("vendor/inner");
    std::fs::create_dir_all(&nested).expect("the vendored repository's tree");
    git_raw(&nested, ["init", "--initial-branch=main"]);
    let outside = fixture.work().join("linked-elsewhere/child");
    std::fs::create_dir_all(&outside).expect("a tree of its own");
    let named = std::fs::canonicalize(&data).expect("the name with nothing to resolve");
    std::fs::write(
        outside.join(".git"),
        format!("gitdir: {}\n", named.display()).as_bytes(),
    )
    .expect("the file that names where its data is");
    let target = std::fs::canonicalize(&outside).expect("the target with nothing to resolve");
    std::os::unix::fs::symlink(&target, nested.join("child")).expect("the link that names it");

    let workspace = fixture.workspace("linked-destination");
    let affected = expectations(&destination, &["vendor/repo-data/config.worktree"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let refusal = apply::apply(fixture.service(), &order)
        .expect_err("an apply into that repository's own data is refused");
    assert!(
        refusal.to_string().contains("own administrative data")
            || refusal.to_string().contains("nested in it"),
        "the refusal says what is there: {refusal}"
    );
    assert_eq!(
        support::read_bytes(&destination, "vendor/repo-data/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
        "and the destination holds exactly what it held"
    );
}

/// KR-REQ-14.28, KR-REQ-14.33 and D-098a: the repository that owns a destination's data can have
/// its tree **inside the destination repository's own data**, where nothing is captured from.
#[test]
fn an_apply_finds_the_data_of_a_repository_inside_its_own_data() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "inside-source");
    write(
        &source,
        "vendor/repo-data/config.worktree",
        "[remote]\n\turl = the-change\n",
    );
    let source_workspace = fixture.workspace("inside-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "inside-destination");
    let data = destination.join("vendor/repo-data");
    std::fs::create_dir_all(&data).expect("the other repository's data");
    for name in ["HEAD", "config"] {
        let from = destination.join(".git").join(name);
        if from.exists() {
            std::fs::copy(&from, data.join(name)).expect("its own copy");
        }
    }
    std::fs::write(
        data.join("config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
    )
    .expect("something only that repository has");
    // Its tree is kept inside the destination repository's own data, which nothing reads.
    let inside = destination.join(".git/checkout");
    std::fs::create_dir_all(&inside).expect("a tree inside the data");
    std::fs::write(inside.join(".git"), b"gitdir: ../../vendor/repo-data\n")
        .expect("the file that names where its data is");

    let workspace = fixture.workspace("inside-destination");
    let affected = expectations(&destination, &["vendor/repo-data/config.worktree"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let refusal = apply::apply(fixture.service(), &order)
        .expect_err("an apply into that repository's own data is refused");
    assert!(
        refusal.to_string().contains("own administrative data")
            || refusal.to_string().contains("nested in it"),
        "the refusal says what is there: {refusal}"
    );
    assert_eq!(
        support::read_bytes(&destination, "vendor/repo-data/config.worktree"),
        b"[remote]\n\turl = the-destination-s-own\n",
        "and the destination holds exactly what it held"
    );
}
