//! `changeset.materialize`: the independent copy, what a result may attest, and the retention
//! accounting that has to happen before a version goes.
//!
//! Requirement rows closed here: KR-REQ-14.34 (independent materialisations; a modified
//! materialisation recorded as a derived version) and KR-REQ-14.36 (retention accounts for every
//! materialisation and evidence reference before deletion).

#![cfg(not(windows))]

mod support;

use std::path::Path;

use kr_changeset::materialise::{self, RunReport};
use kr_protocol::changeset::{
    EvidenceKind, ExecutionReceipt, MaterialisationPurpose, OutputReference, TestedSource,
    ToolIdentity,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{Nullable, U64};

use support::{Fixture, include_everything, ordinary_repository, reference, write, write_bytes};

fn report() -> RunReport {
    RunReport {
        command: "cargo test --workspace".to_owned(),
        profile: "the project's own test profile".to_owned(),
        tool: ToolIdentity {
            name: "cargo".to_owned(),
            version: "1.97.1".to_owned(),
        },
        receipt: ExecutionReceipt {
            started_at_ms: kr_protocol::scalars::TimestampMs::new(1_000),
            ended_at_ms: kr_protocol::scalars::TimestampMs::new(2_000),
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
    )
    .expect("the version is materialised");

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
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

/// KR-REQ-14.34: a result about a materialisation somebody changed attests a **derived** version
/// with its own identity, and never says the unmodified version passed.
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

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::DerivedVersion);
    let Nullable(Some(tested)) = result.tested_version else {
        panic!("a derived result names the version it attests");
    };
    assert_ne!(tested, reference(&record), "it is not the input version");
    assert_eq!(result.input_version, reference(&record));
    assert!(
        result.attestation.contains("says nothing about version 1"),
        "the attestation refuses the input version by name: {}",
        result.attestation
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
    )
    .expect("the version is materialised");
    // Whatever ran took its own directory away, so what it ran against cannot be established.
    std::fs::remove_dir_all(&made.directory_path).expect("the run removes its copy");

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
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
        .delete_version(version.change_set_id, version.version)
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
            .delete_version(version.change_set_id, version.version)
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
        .delete_version(version.change_set_id, version.version)
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
        },
        pin: true,
        provenance: support::provenance(),
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

/// KR-REQ-14.33: a run that writes a secret into its own copy does not get it stored in a derived
/// version, because the grant and the secret rules apply to the re-read as they do to a capture.
#[test]
fn a_secret_a_run_left_behind_is_not_stored_in_a_derived_version() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "secretive");
    let workspace = fixture.workspace("secretive");
    let record = fixture.capture(workspace, &include_everything());
    let made = materialise::materialise(
        fixture.service(),
        reference(&record),
        MaterialisationPurpose::Test,
        "the test copy",
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    std::fs::write(directory.join(".env"), b"API_TOKEN=a-secret-a-run-wrote\n")
        .expect("the run writes a secret");
    std::fs::write(directory.join("README.md"), b"and changes a file\n")
        .expect("the run changes a file");

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
        .expect("the result is recorded");
    assert_eq!(result.tested_source, TestedSource::DerivedVersion);
    let Nullable(Some(tested)) = result.tested_version else {
        panic!("a derived result names its version");
    };
    let manifest = fixture
        .service()
        .manifest(tested.change_set_id, tested.version)
        .expect("its manifest");
    assert!(
        manifest.path(".env").is_none(),
        "a secret rule covers it in a derived version too"
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
    // The change the run did make is recorded, and it is a change of the derived version.
    let changed = manifest.path("README.md").expect("it is there");
    assert_eq!(
        fixture
            .service()
            .objects()
            .get(changed.content_digest)
            .expect("its content"),
        b"and changes a file\n"
    );
    assert!(changed.class.is_change());
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
    )
    .expect("the version is materialised");
    std::os::unix::fs::symlink(
        "README.md",
        Path::new(&made.directory_path).join("shortcut.md"),
    )
    .expect("the run adds a link");

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
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
    )
    .expect("the version is materialised");
    let directory = Path::new(&made.directory_path);
    std::fs::write(directory.join("README.md"), b"the run changed it\n")
        .expect("the run changes a file");
    std::fs::remove_file(directory.join("src/lib.rs")).expect("the run removes a file");
    std::fs::write(directory.join("added.txt"), b"and adds one\n").expect("the run adds a file");

    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
        .expect("the result is recorded");
    let Nullable(Some(tested)) = result.tested_version else {
        panic!("a derived result names its version");
    };
    let derived = fixture
        .service()
        .record(tested.change_set_id, Some(tested.version))
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
    assert!(
        derived
            .exclusions
            .iter()
            .any(|entry| entry.path == "src/lib.rs"
                && entry.reason == kr_protocol::changeset::ExclusionReason::Deleted),
        "the removed file is named: {:?}",
        derived.exclusions
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
    )
    .expect("the version is materialised");
    std::fs::remove_dir_all(&made.directory_path).expect("the run removes its copy");
    let result = materialise::record_result(fixture.service(), made.materialisation_id, &report())
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
            .delete_version(version.change_set_id, version.version)
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
