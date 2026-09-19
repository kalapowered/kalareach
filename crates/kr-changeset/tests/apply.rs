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
    let failure = apply::apply(fixture.service(), &order).expect_err("the preflight refuses");
    assert_eq!(failure.code(), ErrorCode::DraftConflict);
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

    assert_eq!(result.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
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
    let recovery = replacement.recover().expect("recovery runs");
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
