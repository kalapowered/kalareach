//! `changeset.materialize`: the independent copy, what a result may attest, and the retention
//! accounting that has to happen before a version goes.
//!
//! Requirement rows closed here: KR-REQ-14.34 (independent materialisations; a modified
//! materialisation recorded as a derived version) and KR-REQ-14.36 (retention accounts for every
//! materialisation and evidence reference before deletion).

#![cfg(not(windows))]

mod support;

use std::path::Path;

use kr_changeset::binding;
use kr_changeset::materialise::{self, RunReport};
use kr_protocol::changeset::{
    EvidenceKind, ExecutionReceipt, MaterialisationPurpose, OutputReference, TestedSource,
    ToolIdentity,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{Nullable, U64};

use support::{Fixture, include_everything, ordinary_repository, reference, write, write_bytes};

/// A run that started before this moment and ended at it.
///
/// The end matters: this host compares it with the instant anything beneath the materialisation
/// was last written, and a file written after the run ended is a file the run did not use.
fn report() -> RunReport {
    let ended = kr_ipc::now_ms();
    RunReport {
        command: "cargo test --workspace".to_owned(),
        profile: "the project's own test profile".to_owned(),
        tool: ToolIdentity {
            name: "cargo".to_owned(),
            version: "1.97.1".to_owned(),
        },
        receipt: ExecutionReceipt {
            started_at_ms: kr_protocol::scalars::TimestampMs::new(
                ended.get().saturating_sub(60_000),
            ),
            ended_at_ms: ended,
            exit_status: Nullable(Some(U64::new(0))),
            stopped: false,
            detail: "every test passed".to_owned(),
        },
        outputs: vec![OutputReference {
            label: "the test log".to_owned(),
            digest: kr_changeset::objects::digest_of(b"the log"),
            byte_len: U64::new(7),
            kind: "log".to_owned(),
        }],
    }
}

/// Binds the run to its copy as it is now, and records the result.
///
/// A test that has changed the copy already has bound it as changed, so the binding says nothing
/// is disturbed and the content decides, as it did before a run was bound. A test of the binding
/// binds first, runs, and records with [`materialise::record_result`] itself.
fn record_a_run(
    fixture: &Fixture,
    id: kr_protocol::ids::MaterialisationId,
    report: &RunReport,
    outputs: &materialise::Outputs,
) -> kr_changeset::Result<kr_protocol::changeset::MaterialisationResult> {
    let binding = binding::bind_run(fixture.service(), id, outputs);
    materialise::record_result(fixture.service(), id, report, outputs, &binding)
}

/// KR-REQ-14.34: a materialisation is an independent copy of one exact version, and the agent
/// whose tree it came from can keep working without changing anybody's inputs.
#[test]
fn a_materialisation_is_independent_of_the_tree_it_came_from() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "work");
    write(&path, "README.md", "the version under test\n");
    write_bytes(&path, "windows.txt", b"first\r\nsecond\r\n");
    write_bytes(&path, "run.sh", b"#!/bin/sh\necho hello\n");
    support::make_executable(&path, "run.sh");
    let workspace = fixture.workspace("work");
    let record = fixture.capture(workspace, &include_everything());

    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the reviewer's copy",
        None,
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    assert_eq!(made.paths_written.get(), record.summary.total_paths.get());
    assert!(made.unapplied.is_empty());
    assert_eq!(made.content_digest, record.content_digest);

    // Every byte exactly as it was, including the line endings and the executable bit.
    assert_eq!(
        std::fs::read(directory.join("README.md")).expect("the file is there"),
        b"the version under test\n"
    );
    assert_eq!(
        std::fs::read(directory.join("windows.txt")).expect("the file is there"),
        b"first\r\nsecond\r\n"
    );
    assert!(support::is_executable(directory, "run.sh"));
    assert!(!support::is_executable(directory, "README.md"));
    // The directories above a path are made for it.
    assert_eq!(
        std::fs::read(directory.join("src/lib.rs")).expect("the nested file is there"),
        b"pub fn answer() -> u32 { 42 }\n"
    );
    // It is not inside the repository it came from.
    assert!(
        !directory.starts_with(&path),
        "a materialisation is not written into the user's own tree: {}",
        made.directory_path
    );

    // The agent keeps working and the materialisation is unmoved.
    write(&path, "README.md", "the agent has moved on\n");
    assert_eq!(
        std::fs::read(directory.join("README.md")).expect("the file is still there"),
        b"the version under test\n"
    );

    // Two materialisations of one version are independent of each other.
    let second = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Review,
        "a second copy",
        None,
    )
    .expect("a second materialisation");
    assert_ne!(second.materialisation_id, made.materialisation_id);
    assert_ne!(second.directory_path, made.directory_path);
    std::fs::write(
        Path::new(&second.directory_path).join("README.md"),
        b"a reviewer scribbled on their own copy\n",
    )
    .expect("the reviewer writes in their own copy");
    assert_eq!(
        std::fs::read(directory.join("README.md")).expect("the first copy is unchanged"),
        b"the version under test\n"
    );
}

/// KR-REQ-14.34: a result about a materialisation that still holds the version attests that
/// version, and records the command, the profile, the environment, the tool and the receipt.
#[test]
fn a_result_about_an_unmodified_materialisation_attests_that_version() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "unchanged");
    let workspace = fixture.workspace("unchanged");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::UnmodifiedVersion);
    assert_eq!(result.tested_version, Nullable(Some(reference(&record))));
    assert_eq!(result.input_version, reference(&record));
    assert_eq!(result.command, "cargo test --workspace");
    assert_eq!(result.profile, "the project's own test profile");
    assert_eq!(result.environment_id, fixture.environment_id());
    assert_eq!(result.tool.name, "cargo");
    assert_eq!(result.receipt.exit_status, Nullable(Some(U64::new(0))));
    assert_eq!(result.outputs.len(), 1);
    assert!(
        result
            .attestation
            .contains("still held exactly the version"),
        "the attestation says what it is about: {}",
        result.attestation
    );
}

/// KR-REQ-14.34: a result about a materialisation somebody changed attests no version at all, and
/// records the **derived** version, with its own identity, beside it as what the directory held.
#[test]
fn a_changed_materialisation_is_recorded_as_a_derived_version() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "derived");
    let workspace = fixture.workspace("derived");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");

    // The test run fixes something in its own copy, which is the case the row exists for.
    let directory = Path::new(&made.directory_path);
    std::fs::write(
        directory.join("src/lib.rs"),
        b"pub fn answer() -> u32 { 43 }\n",
    )
    .expect("the run edits its copy");
    std::fs::write(directory.join("extra.txt"), b"and adds a file\n").expect("the run adds a file");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert_eq!(
        result.tested_version,
        Nullable(None),
        "a changed materialisation attests no version at all"
    );
    let Nullable(Some(derived)) = result.derived_output_version else {
        panic!("a changed materialisation records the version the directory held");
    };
    assert_ne!(derived, reference(&record), "it is not the input version");
    let tested = derived;
    assert_eq!(result.input_version, reference(&record));
    assert!(
        result.attestation.contains("says nothing about version 1"),
        "the attestation refuses the input version by name: {}",
        result.attestation
    );
    // The reading this result carries is held against deletion for as long as the result is: a
    // result that points at a version must not outlive it.
    let held = fixture
        .service()
        .holders(tested.change_set_id, tested.version)
        .expect("what holds it is readable");
    assert!(
        held.iter().any(|what| what.detail.contains("result")),
        "the result holds the version it recorded: {held:?}"
    );
    let refusal = fixture
        .service()
        .delete_version(tested.change_set_id, tested.version, None)
        .expect_err("it is not deleted while the result names it");
    assert!(
        refusal.to_string().contains("result"),
        "the refusal names what holds it: {refusal}"
    );

    // The derived version is a real version: it names its parent and holds what was tested.
    let derived = fixture
        .service()
        .record(tested.change_set_id, Some(tested.version))
        .expect("the derived version is readable");
    assert_eq!(
        derived.provenance.derived_from,
        Nullable(Some(reference(&record)))
    );
    assert_ne!(derived.content_digest, record.content_digest);
    let manifest = fixture
        .service()
        .manifest(tested.change_set_id, tested.version)
        .expect("its manifest");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(
                manifest
                    .path("src/lib.rs")
                    .expect("it is there")
                    .content_digest
            )
            .expect("its content"),
        b"pub fn answer() -> u32 { 43 }\n"
    );
    assert!(manifest.path("extra.txt").is_some());

    // The input version is untouched by all of it.
    let unchanged = fixture
        .service()
        .record(record.change_set_id, Some(record.version))
        .expect("version one is still readable");
    assert_eq!(unchanged.content_digest, record.content_digest);
}

/// KR-REQ-14.34: a result whose tested source cannot be established attests no version at all.
#[test]
fn a_result_whose_source_cannot_be_established_attests_nothing() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "gone");
    let workspace = fixture.workspace("gone");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    // Whatever ran took its own directory away, so what it ran against cannot be established.
    std::fs::remove_dir_all(&made.directory_path).expect("the run removes its copy");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded anyway");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert_eq!(result.tested_version, Nullable(None));
    assert!(
        result.attestation.contains("attests no \nversion")
            || result.attestation.contains("attests no version"),
        "the attestation says it attests nothing: {}",
        result.attestation
    );
}

/// KR-REQ-14.36: retention accounts for every materialisation and every evidence reference before
/// a version can be deleted.
#[test]
fn a_version_is_not_deleted_while_anything_still_names_it() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "retained");
    let workspace = fixture.workspace("retained");
    let record = fixture.capture(workspace, &include_everything());
    let version = reference(&record);

    // Nothing holds it yet.
    assert!(
        fixture
            .service()
            .holders(version.change_set_id, version.version)
            .expect("the holders are read")
            .is_empty()
    );

    let made = materialise::materialise(
        fixture.service(),
        version,
        MaterialisationPurpose::Review,
        "the reviewer's copy",
        None,
    )
    .expect("the version is materialised");
    let held = fixture
        .service()
        .holders(version.change_set_id, version.version)
        .expect("the holders are read");
    assert_eq!(held.len(), 1);
    assert!(
        held[0].detail.contains("materialisation"),
        "the holder is the materialisation: {}",
        held[0].detail
    );
    let refusal = fixture
        .service()
        .delete_version(version.change_set_id, version.version, None)
        .expect_err("a held version is not deleted");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    assert!(
        refusal.to_string().contains("still held"),
        "the refusal says what holds it: {refusal}"
    );

    // A review acknowledgement is evidence too, and it holds the version after the
    // materialisation is released.
    fixture
        .service()
        .record_evidence(
            version.change_set_id,
            version.version,
            EvidenceKind::ReviewAcknowledgement,
            "somebody acknowledged this version",
        )
        .expect("the acknowledgement is recorded");
    materialise::release(fixture.service(), made.materialisation_id)
        .expect("the materialisation is released");
    support::assert_absent(Path::new(&made.directory_path));
    let held = fixture
        .service()
        .holders(version.change_set_id, version.version)
        .expect("the holders are read");
    assert_eq!(held.len(), 1);
    assert!(
        held[0].detail.contains("evidence reference"),
        "the holder is the acknowledgement: {}",
        held[0].detail
    );
    assert!(
        fixture
            .service()
            .delete_version(version.change_set_id, version.version, None)
            .is_err(),
        "the acknowledgement still holds it"
    );

    // The record of the released materialisation and its result survive the release.
    let every = materialise::every(fixture.service(), version.change_set_id, version.version)
        .expect("every materialisation is listed");
    assert_eq!(every.len(), 1);
    assert!(every[0].released_at_ms.0.is_some());
}

/// KR-REQ-14.36: once nothing names it, a version can go, and its evidence goes with it.
#[test]
fn a_version_nothing_names_can_be_deleted() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "unheld");
    let workspace = fixture.workspace("unheld");
    let record = fixture.capture(workspace, &include_everything());
    let version = reference(&record);
    fixture
        .service()
        .delete_version(version.change_set_id, version.version, None)
        .expect("nothing names it, so it goes");
    let failure = fixture
        .service()
        .record(version.change_set_id, Some(version.version))
        .expect_err("it is gone");
    assert_eq!(failure.code(), ErrorCode::ResourceUnavailable);
}

/// KR-REQ-14.36: a pin recorded against the workspace through the project service holds the
/// version too, which is what makes a workspace removal account for it.
#[test]
fn a_pin_against_the_workspace_holds_the_version() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "pinned");
    let workspace = fixture.workspace("pinned");
    let order = kr_changeset::service::CaptureOrder {
        workspace_id: workspace,
        change_set_id: None,
        label: "pinned work",
        request: kr_changeset::capture::CaptureRequest {
            policy: &include_everything(),
            grant: &kr_protocol::changeset::FileGrant::default(),
            quiescence_declared: false,
            required_consistency: None,
            quiescence: None,
        },
        pin: true,
        provenance: support::provenance(),
        admitted: None,
    };
    let (record, pinned) = fixture
        .service()
        .capture(&order)
        .expect("the capture succeeds");
    assert!(pinned);

    // The project service is where the pin lives, so a workspace removal sees it.
    let retained = fixture
        .project()
        .retained(workspace)
        .expect("the project service holds the pin");
    assert!(
        retained.iter().any(|item| {
            item.kind == kr_protocol::project::RetainedKind::PinnedChangeSet
                && item.change_set_id == Some(record.change_set_id)
        }),
        "the pin names the change set: {retained:?}"
    );
    let held = fixture
        .service()
        .holders(record.change_set_id, record.version)
        .expect("the holders are read");
    assert!(
        !held.is_empty(),
        "a pinned version is one a deletion has to account for"
    );
}

/// KR-REQ-14.33 and 14.34: a run that writes a secret into its own copy neither gets it stored nor
/// gets a result that attests a version, because a source this host may not read is a source it
/// cannot establish.
#[test]
fn a_secret_a_run_left_behind_is_neither_stored_nor_attested() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "secretive");
    let workspace = fixture.workspace("secretive");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    std::fs::write(directory.join(".env"), b"API_TOKEN=a-secret-a-run-wrote\n")
        .expect("the run writes a secret");
    std::fs::write(directory.join("README.md"), b"and changes a file\n")
        .expect("the run changes a file");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(
        result.tested_source,
        TestedSource::Indeterminate,
        "a source this host may not read is a source it cannot establish"
    );
    assert_eq!(result.tested_version, Nullable(None));
    assert!(
        result.attestation.contains("would not \nread")
            || result.attestation.contains("would not read"),
        "the attestation says why: {}",
        result.attestation
    );
    assert!(
        !fixture
            .service()
            .objects()
            .holds(kr_changeset::objects::digest_of(
                b"API_TOKEN=a-secret-a-run-wrote\n"
            ))
            .expect("the store answers"),
        "the secret's bytes never reached the content store"
    );
}

/// KR-REQ-14.34: something this host cannot represent in a version makes the tested source
/// indeterminate rather than quietly missing from a derived one.
#[test]
fn a_link_a_run_added_makes_the_tested_source_indeterminate() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "linked");
    let workspace = fixture.workspace("linked");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    std::os::unix::fs::symlink(
        "README.md",
        Path::new(&made.directory_path).join("shortcut.md"),
    )
    .expect("the run adds a link");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert_eq!(result.tested_version, Nullable(None));
    assert!(
        result.attestation.contains("cannot be established"),
        "the attestation says so: {}",
        result.attestation
    );
}

/// KR-REQ-14.31, 14.32 and 14.34: a derived version's own metadata describes the derived version,
/// not the one it came from.
#[test]
fn a_derived_version_describes_itself_rather_than_its_parent() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "describes");
    let workspace = fixture.workspace("describes");
    // The parent is an atomic snapshot of the base commit, which is the strongest class there is.
    let record = fixture
        .capture_with(
            workspace,
            &kr_protocol::project::InclusionPolicy::base_only(),
            &kr_protocol::changeset::FileGrant::default(),
            None,
            Some(kr_protocol::changeset::SourceConsistency::AtomicSnapshot),
        )
        .expect("the snapshot is taken");
    assert_eq!(
        record.consistency,
        kr_protocol::changeset::SourceConsistency::AtomicSnapshot
    );
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    std::fs::write(directory.join("README.md"), b"the run changed it\n")
        .expect("the run changes a file");
    std::fs::remove_file(directory.join("src/lib.rs")).expect("the run removes a file");
    std::fs::write(directory.join("added.txt"), b"and adds one\n").expect("the run adds a file");

    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    let Nullable(Some(observed)) = result.derived_output_version else {
        panic!("a changed materialisation records the version the directory held");
    };
    let derived = fixture
        .service()
        .record(observed.change_set_id, Some(observed.version))
        .expect("the derived version is readable");
    // Its class is the one its own reading was, not the one its parent claimed.
    assert_eq!(
        derived.consistency,
        kr_protocol::changeset::SourceConsistency::PerFileCapture,
        "a version's consistency is a fact about how it was read"
    );
    assert!(
        derived.consistency_detail.contains("one file at a time"),
        "the detail says what was done: {}",
        derived.consistency_detail
    );
    // The change the run made is a change of the derived version.
    let changed = derived
        .changes
        .iter()
        .find(|entry| entry.path == "README.md")
        .expect("the changed file is named as a change");
    assert!(changed.class.is_change());
    // The addition is one too.
    assert!(
        derived
            .changes
            .iter()
            .any(|entry| entry.path == "added.txt"),
        "the added file is a change: {:?}",
        derived
            .changes
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>()
    );
    // And the removal is named rather than silently absent.
    assert_eq!(
        derived.summary.deleted_paths.get(),
        1,
        "the removed file is carried as a deletion of the derived version"
    );
    let manifest = fixture
        .service()
        .manifest(observed.change_set_id, observed.version)
        .expect("the derived manifest");
    assert!(
        manifest
            .deletions
            .iter()
            .any(|deleted| deleted.path == "src/lib.rs"),
        "and it is the file the run removed"
    );
}

/// KR-REQ-14.36: a result that attests nothing still holds the version it ran against, so that
/// version is not deleted while the record of an indeterminate run names it.
#[test]
fn an_indeterminate_result_still_holds_the_version_it_ran_against() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "indeterminate");
    let workspace = fixture.workspace("indeterminate");
    let record = fixture.capture(workspace, &include_everything());
    let version = reference(&record);
    let made = materialise::materialise(
        fixture.service(),
        version,
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    std::fs::remove_dir_all(&made.directory_path).expect("the run removes its copy");
    let result = record_a_run(
        &fixture,
        made.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    // The materialisation is released, so it no longer holds the version; the result still does.
    materialise::release(fixture.service(), made.materialisation_id)
        .expect("the release records itself");
    let held = fixture
        .service()
        .holders(version.change_set_id, version.version)
        .expect("the holders are read");
    assert!(
        !held.is_empty(),
        "the record of a run against this version is something a deletion accounts for"
    );
    assert!(
        fixture
            .service()
            .delete_version(version.change_set_id, version.version, None)
            .is_err(),
        "it is not deleted while that record names it"
    );
}

/// KR-REQ-14.36: a release that finds something other than the object this host made removes
/// nothing and says so, rather than recording a release it did not perform.
#[test]
fn a_release_that_finds_another_directory_removes_nothing() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "substituted");
    let workspace = fixture.workspace("substituted");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    // Somebody puts a different directory at the name, with somebody else's file in it.
    let elsewhere = fixture.work().join("somebody-elses");
    std::fs::create_dir_all(&elsewhere).expect("a directory made elsewhere");
    std::fs::write(elsewhere.join("keep.txt"), b"somebody else's file\n").expect("their file");
    std::fs::remove_dir_all(directory).expect("the materialisation is taken away");
    std::fs::rename(&elsewhere, directory).expect("the substitute is moved in");

    let failure = materialise::release(fixture.service(), made.materialisation_id)
        .expect_err("a substitute is not released");
    assert!(
        failure
            .to_string()
            .contains("not the object this host made"),
        "the refusal says why: {failure}"
    );
    assert_eq!(
        std::fs::read(directory.join("keep.txt")).expect("their file is still there"),
        b"somebody else's file\n",
        "nothing of theirs was removed"
    );
    // And the materialisation still holds its version, because nothing established it is gone.
    assert!(
        !fixture
            .service()
            .holders(record.change_set_id, record.version)
            .expect("the holders are read")
            .is_empty()
    );
}

/// KR-REQ-23.44: a materialisation's authority is decided inside the transaction that records it,
/// which is the row every byte of the directory follows.
///
/// The claim is taken under an authority that holds; the authority is then withdrawn; the
/// materialisation that follows writes no row, no directory and no evidence.
#[test]
fn an_authority_withdrawn_after_the_claim_writes_no_materialisation() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "withdrawn");
    write(&path, "README.md", "changed after the commit\n");
    let workspace = fixture.workspace("withdrawn");
    let record = fixture.capture(workspace, &include_everything());

    let authority = support::Authority::held();
    support::claim(fixture.service(), "changeset.materialize", &authority);
    assert_eq!(authority.asked(), 1, "the claim asked once");
    authority.withdraw();

    let refusal = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the copy nothing admits",
        Some(&authority),
    )
    .expect_err("a materialisation whose authority has gone is refused");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        authority.asked() > 1,
        "the effect asked for itself rather than relying on the claim's answer"
    );
    assert!(
        materialise::every(fixture.service(), record.change_set_id, record.version)
            .expect("the materialisations read")
            .is_empty(),
        "nothing accounts for a directory, because no directory was written"
    );
    assert!(
        fixture
            .service()
            .holders(record.change_set_id, record.version)
            .expect("the holders read")
            .is_empty(),
        "and nothing holds the version the refused materialisation named"
    );

    // Under authority that holds, the same version materialises: what the refusal stopped was the
    // mutation, not the version.
    let held = support::Authority::held();
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the copy under authority that holds",
        Some(&held),
    )
    .expect("a materialisation under authority that holds");
    assert!(Path::new(&made.directory_path).is_dir());
}

/// A materialisation of the fixture's captured version, ready for a run that writes in it.
fn a_copy_to_run_in(
    fixture: &Fixture,
    name: &str,
) -> (
    kr_protocol::changeset::ChangeSetVersionRecord,
    kr_protocol::changeset::MaterialisationRecord,
) {
    ordinary_repository(fixture.work(), name);
    let workspace = fixture.workspace(name);
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    (record, made)
}

/// The declarations of one suite, checked against the version the fixture captured.
fn declared(
    fixture: &Fixture,
    record: &kr_protocol::changeset::ChangeSetVersionRecord,
    paths: &[&str],
) -> Result<materialise::Outputs, String> {
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("the manifest reads");
    let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
    materialise::Outputs::new(&paths, &manifest)
}

/// KR-REQ-25.20: a run that wrote only where its suite declares output attests the version it ran
/// against. The directory it wrote is recorded as one reference that names its listing, and
/// nothing beneath it is read into the content store. A link inside it is an entry and not a
/// failure. The control is the same run without the declaration, which cannot attest the
/// version.
#[test]
fn a_run_that_wrote_only_its_declared_output_attests_the_version() {
    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "built");
    let directory = Path::new(&made.directory_path);
    write(directory, "build/output/artefact.bin", "built things\n");
    write(directory, "build/output/logs/run.log", "a log\n");
    std::os::unix::fs::symlink("/no/such/place", directory.join("build/output/link"))
        .expect("a link in the output");

    let outputs = declared(&fixture, &record, &["build/output"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::UnmodifiedVersion);
    assert_eq!(result.tested_version, Nullable(Some(reference(&record))));
    let listing = result
        .outputs
        .iter()
        .find(|output| output.label == "build/output")
        .expect("the declared output is recorded as a reference");
    assert_eq!(listing.kind, "directory listing");
    assert_eq!(
        listing.byte_len.get(),
        b"built things\n".len() as u64 + b"a log\n".len() as u64,
        "a listing's length is the sum of the lengths it lists"
    );
    assert!(
        result.outputs.iter().any(|output| output.kind == "log"),
        "the outputs the report names are kept beside it"
    );
    assert!(
        !fixture
            .service()
            .objects()
            .holds(kr_changeset::objects::digest_of(b"built things\n"))
            .expect("the store is asked"),
        "nothing an output holds enters the content store"
    );
    assert!(
        result.attestation.contains("build/output"),
        "the result names the path it left out of the comparison: {}",
        result.attestation
    );

    // The control: the same directory without the declaration is source the run added.
    let (_, undeclared) = a_copy_to_run_in(&fixture, "built-undeclared");
    let directory = Path::new(&undeclared.directory_path);
    write(directory, "build/output/artefact.bin", "built things\n");
    let result = record_a_run(
        &fixture,
        undeclared.materialisation_id,
        &report(),
        &materialise::Outputs::none(),
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// KR-REQ-25.20: only the declared path is left out. A path the run added beside it makes the
/// source indeterminate, as it would without any declaration, and the reading is recorded as a
/// derived version. A declared output that is a link is a reference of its own kind and not a
/// failure.
#[test]
fn a_path_beside_a_declared_output_still_changes_the_source() {
    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "beside");
    let directory = Path::new(&made.directory_path);
    write(directory, "build/output/artefact.bin", "built things\n");
    write(directory, "build/input", "the run added this\n");
    let outputs = declared(&fixture, &record, &["build/output"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert!(
        result.derived_output_version.0.is_some(),
        "what the directory held is recorded as a version"
    );

    let (record, made) = a_copy_to_run_in(&fixture, "links");
    let directory = Path::new(&made.directory_path);
    std::os::unix::fs::symlink("/no/such/place", directory.join("report"))
        .expect("an output that is a link");
    let outputs = declared(&fixture, &record, &["report"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::UnmodifiedVersion);
    assert!(
        result
            .outputs
            .iter()
            .any(|output| output.label == "report" && output.kind == "link"),
        "a link as an output is recorded as one: {:?}",
        result.outputs
    );
}

/// A run, as the test plays it: the copy is bound before it, then written in, then recorded.
///
/// `run` is what the command does to the copy. Nothing else happens in between, so the only
/// thing that can tell this from a run that touched nothing is the binding.
fn a_run_in(
    fixture: &Fixture,
    name: &str,
    declared_paths: &[&str],
    run: impl FnOnce(&Path),
) -> kr_protocol::changeset::MaterialisationResult {
    let (record, made) = a_copy_to_run_in(fixture, name);
    let outputs = declared(fixture, &record, declared_paths).expect("the declaration is fine");
    let binding = binding::bind_run(fixture.service(), made.materialisation_id, &outputs);
    run(Path::new(&made.directory_path));
    materialise::record_result(
        fixture.service(),
        made.materialisation_id,
        &report(),
        &outputs,
        &binding,
    )
    .expect("the result is recorded")
}

/// Changes a file to something else and puts back its bytes and the instant it was last modified,
/// as a command can, which leaves a file nothing about is different but its change time.
fn change_and_restore(file: &Path) {
    let before = std::fs::metadata(file).expect("the file is there");
    let bytes = std::fs::read(file).expect("the file reads");
    std::fs::write(file, b"the run's own idea of this file\n").expect("the run changes it");
    std::fs::write(file, &bytes).expect("the run puts it back");
    std::fs::File::options()
        .write(true)
        .open(file)
        .and_then(|handle| handle.set_modified(before.modified().expect("an instant")))
        .expect("the run puts back when it was written");
}

/// KR-REQ-14.34: a result is bound to the run it describes. A run that changed a tested path and
/// restored it, in bytes and in the instant it was last written, leaves a copy that reads as the
/// version, and its result attests nothing; a run that did not touch the copy is attested. A name
/// made and removed again leaves no trace in the content, and is a write too.
#[test]
fn a_run_that_changed_a_tested_path_and_restored_it_attests_nothing() {
    let fixture = Fixture::create();

    // The control: the same run without the change.
    let untouched = a_run_in(&fixture, "untouched", &[], |directory| {
        std::fs::read(directory.join("README.md")).expect("the run reads the file");
    });
    assert_eq!(untouched.tested_source, TestedSource::UnmodifiedVersion);
    assert!(untouched.tested_version.0.is_some());

    let restored = a_run_in(&fixture, "restored", &[], |directory| {
        change_and_restore(&directory.join("README.md"));
    });
    assert_eq!(restored.tested_source, TestedSource::Indeterminate);
    assert!(restored.tested_version.0.is_none(), "it attests no version");
    assert!(
        restored.derived_output_version.0.is_none(),
        "the copy holds the version, so there is nothing to derive"
    );
    assert!(
        restored.attestation.contains("README.md"),
        "it says what was written: {}",
        restored.attestation
    );

    // A name made and removed leaves the content as it was, in the root and beneath it.
    for (name, path) in [
        ("stray-root", "stray.tmp"),
        ("stray-nested", "src/stray.tmp"),
    ] {
        let result = a_run_in(&fixture, name, &[], |directory| {
            std::fs::write(directory.join(path), b"x").expect("the run makes a file");
            std::fs::remove_file(directory.join(path)).expect("and removes it");
        });
        assert_eq!(result.tested_source, TestedSource::Indeterminate, "{path}");
    }
}

/// KR-REQ-14.34 and KR-REQ-25.20: a declared output is the one place a run may write. The
/// directory an output is in cannot tell the output from a name written beside it, so it is
/// watched by name: a file made beside the output and removed again is a write, at the root and
/// beneath it, and the output itself is not.
#[test]
fn a_name_written_beside_a_declared_output_is_a_write() {
    let fixture = Fixture::create();

    let built = a_run_in(&fixture, "builds-at-the-root", &["out"], |directory| {
        write(directory, "out/artefact", "built\n");
    });
    assert_eq!(built.tested_source, TestedSource::UnmodifiedVersion);

    let beside = a_run_in(&fixture, "beside-at-the-root", &["out"], |directory| {
        write(directory, "out/artefact", "built\n");
        std::fs::write(directory.join("conftest.py"), b"x").expect("the run makes a file");
        std::fs::remove_file(directory.join("conftest.py")).expect("and removes it");
    });
    assert_eq!(beside.tested_source, TestedSource::Indeterminate);
    assert!(
        beside.attestation.contains("conftest.py"),
        "{}",
        beside.attestation
    );

    let nested = a_run_in(
        &fixture,
        "builds-beneath-a-directory",
        &["target/debug"],
        |directory| {
            write(directory, "target/debug/artefact", "built\n");
        },
    );
    assert_eq!(nested.tested_source, TestedSource::UnmodifiedVersion);

    let nested_beside = a_run_in(
        &fixture,
        "beside-beneath-a-directory",
        &["target/debug"],
        |directory| {
            write(directory, "target/debug/artefact", "built\n");
            std::fs::write(directory.join("target/scratch"), b"x").expect("the run makes a file");
            std::fs::remove_file(directory.join("target/scratch")).expect("and removes it");
        },
    );
    assert_eq!(nested_beside.tested_source, TestedSource::Indeterminate);
}

/// Changes the mode of `directory` to something else and puts it back.
fn change_the_mode_and_put_it_back(directory: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let before = std::fs::metadata(directory)
        .expect("the directory is there")
        .permissions();
    let mut other = before.clone();
    other.set_mode(before.mode() & !0o077 | 0o050);
    std::fs::set_permissions(directory, other).expect("the run changes the mode");
    std::fs::set_permissions(directory, before).expect("and puts it back");
}

/// Moves `directory` to a name beside it, makes a file there and removes it, and moves it back.
fn move_away_and_back(directory: &Path) {
    let mut name = directory.file_name().expect("a name").to_owned();
    name.push("-away");
    let elsewhere = directory.with_file_name(name);
    std::fs::rename(directory, &elsewhere).expect("the run moves the directory away");
    std::fs::write(elsewhere.join("conftest.py"), b"x").expect("and makes a file in it");
    std::fs::remove_file(elsewhere.join("conftest.py")).expect("and removes it");
    std::fs::rename(&elsewhere, directory).expect("and moves it back");
}

/// KR-REQ-14.34: the record of a directory a declared output is in is the one thing the
/// comparison leaves out, so what is done to the directory itself is reported by the platform and
/// is a write. The control is a run that writes only its outputs, at the copy's root and beneath a
/// directory.
#[test]
fn a_run_that_writes_only_its_outputs_in_two_directories_attests_the_version() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "builds-in-two-directories",
        &["out", "target/debug"],
        |directory| {
            write(directory, "out/artefact", "built\n");
            write(directory, "target/debug/artefact", "built\n");
        },
    );
    assert_eq!(
        result.tested_source,
        TestedSource::UnmodifiedVersion,
        "{}",
        result.attestation
    );
}

/// KR-REQ-14.34: the copy's own directory is a directory an output is in when the output is at
/// its root, and a change of its mode that is put back is a write.
#[test]
fn a_mode_of_the_copy_changed_and_put_back_is_a_write() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "changes-the-mode-of-the-copy",
        &["out"],
        |directory| {
            write(directory, "out/artefact", "built\n");
            change_the_mode_and_put_it_back(directory);
        },
    );
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// KR-REQ-14.34: the same for a directory beneath the copy.
#[test]
fn a_mode_of_a_directory_an_output_is_in_changed_and_put_back_is_a_write() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "changes-the-mode-of-a-parent",
        &["target/debug"],
        |directory| {
            write(directory, "target/debug/artefact", "built\n");
            change_the_mode_and_put_it_back(&directory.join("target"));
        },
    );
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// KR-REQ-14.34: a run that moves its copy away, makes and removes a file in it, and moves it
/// back leaves every recorded entry as it was, and the names it made were never beneath the path
/// the copy has again.
#[test]
fn a_copy_moved_away_and_back_is_a_write() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "moves-the-copy-away-and-back",
        &["out"],
        |directory| {
            write(directory, "out/artefact", "built\n");
            move_away_and_back(directory);
        },
    );
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// KR-REQ-14.34: a directory an output is in that is removed and made again, with the output in
/// it again, is a write.
#[test]
fn a_directory_an_output_is_in_removed_and_made_again_is_a_write() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "removes-a-parent-and-makes-it-again",
        &["out", "target/debug"],
        |directory| {
            write(directory, "target/debug/artefact", "built\n");
            std::fs::remove_dir_all(directory.join("target")).expect("the run removes the parent");
            write(directory, "target/debug/artefact", "built again\n");
        },
    );
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// KR-REQ-14.34: a file beside a declared output is recorded like any other, so a run that
/// changes it and puts it back is a write there too.
#[test]
fn a_file_changed_and_restored_beside_a_declared_output_attests_nothing() {
    let fixture = Fixture::create();
    let result = a_run_in(
        &fixture,
        "restores-beside-an-output",
        &["out"],
        |directory| {
            write(directory, "out/artefact", "built\n");
            change_and_restore(&directory.join("README.md"));
        },
    );
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert!(
        result.attestation.contains("README.md"),
        "{}",
        result.attestation
    );
}

/// KR-REQ-14.34: a result about a run that could not be bound attests nothing, whatever the copy
/// holds.
#[test]
fn a_result_without_a_binding_it_could_establish_attests_nothing() {
    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "unbound");
    let outputs = declared(&fixture, &record, &[]).expect("the declaration is fine");
    // A record of a copy this host does not hold.
    let nowhere = binding::bind_run(
        fixture.service(),
        kr_protocol::ids::MaterialisationId::new(kr_ipc::new_uuid()),
        &outputs,
    );
    let result = materialise::record_result(
        fixture.service(),
        made.materialisation_id,
        &report(),
        &outputs,
        &nowhere,
    )
    .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
    assert!(result.tested_version.0.is_none());
}

/// What a result about a run that wrote tens of thousands of files in one burst must say about the
/// source: that it is the version. FSEvents drops reports when a burst is more than it can
/// deliver, and falls behind by more than the host waits for, and the host then says its watcher
/// cannot be trusted, with the result attesting nothing. That is right, and it is not what these
/// cases are about, so on macOS it is the one other answer that is accepted.
fn assert_the_source_is_not_in_doubt(result: &kr_protocol::changeset::MaterialisationResult) {
    if cfg!(target_os = "macos")
        && result.tested_source == TestedSource::Indeterminate
        && result.attestation.contains("the watcher")
    {
        return;
    }
    assert_eq!(
        result.tested_source,
        TestedSource::UnmodifiedVersion,
        "{}",
        result.attestation
    );
}

/// KR-REQ-25.20: a declared output over a bound is a reference and never a reason to doubt the
/// source. A file over the byte bound is digested up to it and recorded with its whole length, and
/// a directory with more entries than a listing holds is a truncated listing.
#[test]
fn an_output_over_a_bound_is_a_reference_and_never_a_reason_to_doubt_the_source() {
    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "bounds");
    let directory = Path::new(&made.directory_path);
    std::fs::File::create(directory.join("big.bin"))
        .expect("a file")
        .set_len(materialise::MAX_OUTPUT_FILE_BYTES + 1)
        .expect("a sparse file one byte over the bound");
    std::fs::create_dir(directory.join("many")).expect("a directory");
    for number in 0..=materialise::MAX_OUTPUT_ENTRIES {
        std::fs::File::create(directory.join("many").join(format!("f{number}"))).expect("an entry");
    }

    let outputs =
        declared(&fixture, &record, &["big.bin", "many"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_the_source_is_not_in_doubt(&result);
    let big = result
        .outputs
        .iter()
        .find(|output| output.label == "big.bin")
        .expect("the file is recorded");
    assert_eq!(big.kind, "file over the byte bound");
    assert_eq!(big.byte_len.get(), materialise::MAX_OUTPUT_FILE_BYTES + 1);
    assert_eq!(
        big.digest,
        kr_changeset::objects::digest_of(&vec![0_u8; materialise::MAX_OUTPUT_FILE_BYTES as usize]),
        "the digest is of the first bytes up to the bound and no more"
    );
    let many = result
        .outputs
        .iter()
        .find(|output| output.label == "many")
        .expect("the directory is recorded");
    assert_eq!(many.kind, "truncated directory listing");
}

/// KR-REQ-25.20: two directory names that read alike as text are two directories. A name that is
/// not text and one that is text with the replacement character are listed once each, the second
/// is entered and the first is not, and neither is opened as the other, so what one holds is never
/// counted for the other.
#[cfg(target_os = "linux")]
#[test]
fn names_that_read_alike_as_text_are_listed_as_the_directories_they_are() {
    use std::os::unix::ffi::OsStrExt as _;

    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "alike");
    let directory = Path::new(&made.directory_path);
    let not_text = directory
        .join("output")
        .join(std::ffi::OsStr::from_bytes(b"\xff"));
    std::fs::create_dir_all(&not_text).expect("a directory whose name is not text");
    std::fs::write(not_text.join("a"), b"a").expect("one byte in it");
    let replacement = directory.join("output").join("\u{FFFD}");
    std::fs::create_dir_all(&replacement).expect("a directory whose name is the replacement");
    std::fs::write(replacement.join("bb"), b"bb").expect("two bytes in it");

    let outputs = declared(&fixture, &record, &["output"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    let listing = result
        .outputs
        .iter()
        .find(|output| output.label == "output")
        .expect("the output is recorded");
    assert_eq!(
        listing.byte_len.get(),
        2,
        "the directory named in text holds two bytes and is counted once, and the one whose name \
         is not text is listed and not entered"
    );
}

/// KR-REQ-25.20: the bound on a listing holds at an entry that could not be read as well. One
/// directory holds twenty-five thousand directories its owner cannot read; each is an entry and
/// so is the failure to read it, which is one entry more than a listing holds, and the last of
/// them is where the bound is met. The listing is a truncated one and the source is still attested.
#[cfg(unix)]
#[test]
fn an_unreadable_entry_at_the_bound_makes_a_truncated_listing() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        println!("not exercised: this process reads a directory whatever its mode says");
        return;
    }
    /// Gives the unreadable directories back their mode however the case ends, so that the
    /// temporary tree can be removed.
    struct Readable(std::path::PathBuf);
    impl Drop for Readable {
        fn drop(&mut self) {
            for entry in std::fs::read_dir(&self.0).into_iter().flatten().flatten() {
                let _ =
                    std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "unreadable");
    let directory = Path::new(&made.directory_path);
    let output = directory.join("out").join("inner");
    std::fs::create_dir_all(&output).expect("a directory in the output");
    let _readable = Readable(output.clone());
    for number in 0..materialise::MAX_OUTPUT_ENTRIES / 2 {
        let unreadable = output.join(format!("d{number}"));
        std::fs::create_dir(&unreadable).expect("a directory");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
            .expect("its owner cannot read it");
    }

    let outputs = declared(&fixture, &record, &["out"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_the_source_is_not_in_doubt(&result);
    let listing = result
        .outputs
        .iter()
        .find(|output| output.label == "out")
        .expect("the output is recorded");
    assert_eq!(listing.kind, "truncated directory listing");
}

/// KR-REQ-25.20: the bound on a listing holds for the bytes of its paths as well as for its
/// entries. Long names in a deep directory fill the listing's path text with fewer entries than
/// the entry bound allows; the listing is a truncated one and the source is still attested.
#[cfg(unix)]
#[test]
fn an_output_whose_paths_fill_the_listing_is_a_truncated_listing() {
    const DIRECTORY_NAME: usize = 150;
    const FILE_NAME: usize = 255;
    let per_entry = DIRECTORY_NAME + 1 + DIRECTORY_NAME + 1 + FILE_NAME;
    let files = materialise::MAX_OUTPUT_LISTING_PATH_BYTES / per_entry + 10;
    assert!(
        files + 2 < materialise::MAX_OUTPUT_ENTRIES,
        "the entry bound is not the one that is met"
    );

    let fixture = Fixture::create();
    let (record, made) = a_copy_to_run_in(&fixture, "long-paths");
    let directory = Path::new(&made.directory_path);
    let below = directory
        .join("out")
        .join("a".repeat(DIRECTORY_NAME))
        .join("b".repeat(DIRECTORY_NAME));
    std::fs::create_dir_all(&below).expect("a deep directory in the output");
    for number in 0..files {
        std::fs::File::create(below.join(format!("{number:0>FILE_NAME$}")))
            .expect("a file with a long name");
    }

    let outputs = declared(&fixture, &record, &["out"]).expect("the declaration is fine");
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_the_source_is_not_in_doubt(&result);
    let listing = result
        .outputs
        .iter()
        .find(|output| output.label == "out")
        .expect("the output is recorded");
    assert_eq!(listing.kind, "truncated directory listing");
}

/// KR-REQ-25.20: a declared output below a directory the capture's grant keeps out is reached
/// through that directory and nothing else of it is: what a run puts beside the output, in a
/// directory the grant keeps out, is still an input this host cannot account for.
#[test]
fn an_output_below_a_directory_the_grant_keeps_out_is_reached_and_its_neighbours_are_not() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "granted");
    let workspace = fixture.workspace("granted");
    let grant = kr_protocol::changeset::FileGrant {
        included_paths: vec!["src".to_owned()],
        excluded_paths: Vec::new(),
        secret_rules_applied: true,
    };
    let record = fixture
        .capture_with(workspace, &include_everything(), &grant, None, None)
        .expect("the capture succeeds");
    let copy = |label: &str| {
        materialise::materialise(
            fixture.service(),
            reference(&record),
            MaterialisationPurpose::Test,
            label,
            None,
        )
        .expect("the version is materialised")
    };
    let outputs = declared(&fixture, &record, &["target/debug"]).expect("the declaration is fine");

    let made = copy("only the output");
    write(
        Path::new(&made.directory_path),
        "target/debug/artefact",
        "built\n",
    );
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_eq!(
        result.tested_source,
        TestedSource::UnmodifiedVersion,
        "{}",
        result.attestation
    );

    let made = copy("a neighbour of the output");
    write(
        Path::new(&made.directory_path),
        "target/debug/artefact",
        "built\n",
    );
    write(
        Path::new(&made.directory_path),
        "target/other/file",
        "not an output\n",
    );
    let result = record_a_run(&fixture, made.materialisation_id, &report(), &outputs)
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::Indeterminate);
}

/// A materialisation a run left read-only, in a name this host does not accept as input, with a
/// root its owner cannot search, is taken away: the owner's right to change each directory is given
/// back first and each level is removed through its own handle. Without this a copy would hold its
/// version for ever.
#[test]
fn a_materialisation_a_run_left_read_only_is_released() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::create();
    let (_, made) = a_copy_to_run_in(&fixture, "read-only");
    let directory = Path::new(&made.directory_path);
    write(directory, "vendor/module/file.go", "package module\n");
    write(
        directory,
        "vendor/nul/file",
        "a name a Windows device has\n",
    );
    for tree in ["vendor/nul", "vendor/module", "vendor"] {
        std::fs::set_permissions(directory.join(tree), std::fs::Permissions::from_mode(0o555))
            .expect("the tree is read-only");
    }

    // And the root itself can be one its owner cannot search.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o400))
        .expect("the root cannot be searched");

    let released = materialise::release(fixture.service(), made.materialisation_id)
        .expect("a read-only tree is released");
    assert!(released.released_at_ms.0.is_some());
    assert!(!directory.exists(), "the directory is gone");
}

/// KR-REQ-25.20: declarations that contradict each other or the version are refused before a run
/// begins, in words for the person who wrote them.
#[test]
fn declarations_that_the_version_or_each_other_contradict_are_refused() {
    let fixture = Fixture::create();
    let (record, _) = a_copy_to_run_in(&fixture, "declarations");
    for (paths, says) in [
        (&["/build"][..], "relative"),
        (&["build/"][..], "relative"),
        (&["build/../etc"][..], "name"),
        (&["build", "build"][..], "twice"),
        (&["build", "build/output"][..], "holds"),
        (&["src"][..], "version holds"),
        (&["src/lib.rs"][..], "version holds"),
        (&[""][..], "relative"),
    ] {
        let refusal = declared(&fixture, &record, paths).expect_err("the declaration is refused");
        assert!(refusal.contains(says), "{paths:?}: {refusal}");
    }
    let many: Vec<String> = (0..=materialise::MAX_DECLARED_OUTPUTS)
        .map(|number| format!("out{number}"))
        .collect();
    let manifest = fixture
        .service()
        .manifest(record.change_set_id, record.version)
        .expect("the manifest reads");
    materialise::Outputs::new(&many, &manifest).expect_err("too many declarations");
    declared(&fixture, &record, &["build", "dist/assets"]).expect("two separate outputs are fine");
}

/// KR-REQ-25.14: a materialisation made under an identifier its caller chose is found again from
/// that identifier alone. A stop between the directory and its record leaves an empty directory,
/// which is taken away by that identifier and by nothing else; a recorded materialisation is
/// released the ordinary way, and a directory with something in it is never removed.
#[test]
fn a_materialisation_under_a_chosen_identifier_is_found_again_from_it() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "chosen");
    let workspace = fixture.workspace("chosen");
    let record = fixture.capture(workspace, &include_everything());

    let id = kr_protocol::ids::MaterialisationId::new(kr_ipc::new_uuid());
    let made = materialise::materialise_as(
        fixture.service(),
        id,
        reference(&record),
        MaterialisationPurpose::Test,
        "a chosen identifier",
        None,
    )
    .expect("the materialisation is made");
    assert_eq!(made.materialisation_id, id);
    materialise::materialise_as(
        fixture.service(),
        id,
        reference(&record),
        MaterialisationPurpose::Test,
        "the same identifier again",
        None,
    )
    .expect_err("an identifier that was used is refused");
    // A recorded materialisation is not an orphan: this leaves it alone.
    materialise::discard_unrecorded(fixture.service(), id).expect("nothing to discard");
    assert!(Path::new(&made.directory_path).is_dir());
    materialise::release(fixture.service(), id).expect("the ordinary release");
    assert!(!Path::new(&made.directory_path).exists());

    // The stop between the directory and its record: an empty directory with the identifier's name.
    let orphan = kr_protocol::ids::MaterialisationId::new(kr_ipc::new_uuid());
    let beside = Path::new(&made.directory_path)
        .parent()
        .expect("the directory of materialisations")
        .join(orphan.to_string());
    std::fs::create_dir(&beside).expect("the leftover of a stop");
    materialise::discard_unrecorded(fixture.service(), orphan).expect("the leftover is taken away");
    assert!(!beside.exists());
    // Something in a directory nobody recorded is not this host's to remove.
    std::fs::create_dir(&beside).expect("a directory");
    std::fs::write(beside.join("not ours"), b"x").expect("a file");
    materialise::discard_unrecorded(fixture.service(), orphan).expect("left alone");
    assert!(beside.join("not ours").exists());
}
