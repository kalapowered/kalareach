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
//!
//! Every case here needs a checkout, and this host does not run a repository tool on Windows at
//! all: its application container cannot keep a repository from being executed from, so the
//! boundary refuses rather than claiming one it does not have. The file compiles there, so the
//! cases below that are not gated to another platform are type-checked for Windows and state the
//! refusal at run time instead of passing in silence; a case gated to another platform is not
//! compiled here at all. What an apply carries across on Windows is proved without a checkout in
//! `kr-transfer`'s own authority suite.

#![cfg_attr(windows, allow(dead_code, unused_imports))]

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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
    assert!(
        support::is_executable(&destination, "README.md"),
        "the destination was executable and still is"
    );
    #[cfg(not(unix))]
    println!(
        "not exercised: the executable bit, which this platform has no counterpart for; what this \
         platform carries instead is checked by the access-control cases"
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

/// Puts an access-control list on one file through the file's own descriptor, and returns what the
/// platform reports afterwards.
///
/// The list is built here rather than asked of the platform's command-line tool. That tool is a
/// package a host need not have, and a case that quietly does nothing where the package is missing
/// is a case that proves nothing on the machine that most needs it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn give_an_access_control_list(
    environment: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> Option<kr_transfer::AccessControl> {
    let directory = path.parent()?;
    let leaf = kr_transfer::RelativeName::parse(path.file_name()?.to_str()?).ok()?;
    let authority = kr_transfer::AuthorisedDirectory::open_root(environment, directory).ok()?;
    let file = authority.open_write(&leaf).ok()?;
    #[cfg(target_os = "macos")]
    let wanted = {
        // This platform's external representation: a 44-byte header declaring how many entries
        // follow, then 24 bytes an entry, each one the user or group it applies to (16 bytes),
        // what kind of entry it is, and the rights it decides. Two entries, one allowing and one
        // denying, so a list that lost a kind, a right or an entry would be seen to have. What
        // the second entry denies is deliberately not deletion: this platform checks that right
        // against the file a rename replaces, so denying it would stop the very replacement these
        // cases are about.
        let owner = file.owner().ok()?;
        let mut applicable = [
            0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0, 0, 0, 0,
        ];
        applicable[12..16].copy_from_slice(&owner.user.to_be_bytes());
        let mut raw = vec![0_u8; 44 + 2 * 24];
        raw[0..4].copy_from_slice(&0x012c_c16d_u32.to_ne_bytes());
        raw[36..40].copy_from_slice(&2_u32.to_ne_bytes());
        for (index, (kind, rights)) in [(1_u32, 0x0000_0002_u32), (2, 0x0000_0400)]
            .into_iter()
            .enumerate()
        {
            let at = 44 + index * 24;
            raw[at..at + 16].copy_from_slice(&applicable);
            raw[at + 16..at + 20].copy_from_slice(&kind.to_ne_bytes());
            raw[at + 20..at + 24].copy_from_slice(&rights.to_ne_bytes());
        }
        kr_transfer::AccessControl::Apple(kr_transfer::AppleAcl::from_bytes(&raw).ok()?)
    };
    #[cfg(target_os = "linux")]
    let wanted = {
        // A POSIX list in the attribute's own layout: a version, then one eight-byte entry per
        // row, each a tag, the rights it allows and the user or group it names. Naming a user is
        // what makes the list say more than the mode bits do, and a list that names one carries a
        // mask beside it.
        let owner = file.owner().ok()?;
        let mut raw = Vec::with_capacity(4 + 5 * 8);
        raw.extend_from_slice(&2_u32.to_le_bytes());
        for (tag, rights, who) in [
            (0x0001_u16, 0x0006_u16, u32::MAX),
            (0x0002, 0x0004, owner.user),
            (0x0004, 0x0004, u32::MAX),
            (0x0010, 0x0004, u32::MAX),
            (0x0020, 0x0004, u32::MAX),
        ] {
            raw.extend_from_slice(&tag.to_le_bytes());
            raw.extend_from_slice(&rights.to_le_bytes());
            raw.extend_from_slice(&who.to_le_bytes());
        }
        kr_transfer::AccessControl::Posix(raw)
    };
    file.set_access_control(&wanted).ok()?;
    drop(file);
    let read = authority
        .open_read(&leaf, kr_transfer::ObjectPolicy::ReadableFile)
        .ok()?;
    let carried = read.access_control().ok()?;
    carried.has_entries().then_some(carried)
}

/// Everything an account may do to a file.
#[cfg(windows)]
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
/// Reading a file's content, its attributes and its list.
#[cfg(windows)]
const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// Writing a file's own list, which the service asks for only on a copy it created itself.
#[cfg(windows)]
const WRITE_DAC: u32 = 0x0004_0000;
/// The open flag that says a directory is what is meant.
#[cfg(windows)]
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// The flag on an entry that makes every file created beneath a directory carry it.
#[cfg(windows)]
const OBJECT_INHERIT: u8 = 0x01;

/// Puts a protected access-control list on one file through a handle on that file.
///
/// Two entries, one denying and one allowing, so a list that lost a kind, a right or an entry
/// would be seen to have. What the second entry denies is deliberately not deletion: this platform
/// checks that right against the file a rename replaces, so denying it would stop the very
/// replacement these cases are about.
///
/// The destination is a file the repository made, and putting a list on it needs a handle carrying
/// the right to write one. The service opens such a handle only for a copy it created itself, so
/// the fixture opens one of its own rather than asking the service to widen every open it makes.
#[cfg(windows)]
fn give_an_access_control_list(
    environment: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> Option<kr_transfer::AccessControl> {
    let account = account_of(environment, path)?;
    let wanted = kr_transfer::WindowsAcl::new(
        true,
        vec![
            kr_transfer::AclEntry::new(1, 0, 0x0000_0010, account.clone()),
            kr_transfer::AclEntry::new(0, 0, FILE_ALL_ACCESS, account),
        ],
        Vec::new(),
    );
    write_a_list(path, Some(&wanted))?;
    read_the_list(environment, path)
}

/// Returns the account one file belongs to, read through a handle the authority opened.
#[cfg(windows)]
fn account_of(
    environment: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> Option<kr_transfer::Sid> {
    let directory = path.parent()?;
    let leaf = kr_transfer::RelativeName::parse(path.file_name()?.to_str()?).ok()?;
    let authority = kr_transfer::AuthorisedDirectory::open_root(environment, directory).ok()?;
    let file = authority
        .open_read(&leaf, kr_transfer::ObjectPolicy::ReadableFile)
        .ok()?;
    let owner = file.owner().ok()?;
    Some(owner.account().clone())
}

/// Writes one list onto the object at a path, through a handle carrying the right to write one.
#[cfg(windows)]
fn write_a_list(path: &Path, list: Option<&kr_transfer::WindowsAcl>) -> Option<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | WRITE_DAC);
    if path.is_dir() {
        options.custom_flags(BACKUP_SEMANTICS);
    }
    let handle = options.open(path).ok()?;
    kr_transfer::set_access_control(handle.as_handle(), list).ok()
}

/// Reads back what one file carries of its own, through the authority's own handle.
#[cfg(windows)]
fn read_the_list(
    environment: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> Option<kr_transfer::AccessControl> {
    let directory = path.parent()?;
    let leaf = kr_transfer::RelativeName::parse(path.file_name()?.to_str()?).ok()?;
    let authority = kr_transfer::AuthorisedDirectory::open_root(environment, directory).ok()?;
    let read = authority
        .open_read(&leaf, kr_transfer::ObjectPolicy::ReadableFile)
        .ok()?;
    let carried = read.access_control().ok()?;
    carried.has_entries().then_some(carried)
}

/// Returns nothing: this platform keeps its access-control lists where this host cannot write one.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn give_an_access_control_list(
    _environment: kr_protocol::ids::EnvironmentId,
    _path: &Path,
) -> Option<kr_transfer::AccessControl> {
    None
}

/// KR-REQ-14.29: a direct apply preserves an access-control list on the destination.
///
/// An access-control list is protection this host must neither lose silently nor refuse across
/// an apply: the list is read through the destination handle, restored onto the staged copy, and
/// verified on read-back of the published file.
#[cfg(not(windows))]
#[test]
fn a_direct_apply_preserves_an_access_control_list_on_the_destination() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source-tree");
    write_bytes(&source, "README.md", b"updated content with ACL\n");
    let source_workspace = fixture.workspace("source-tree");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "destination-tree");
    let readme_path = destination.join("README.md");
    let given = give_an_access_control_list(fixture.service().environment_id(), &readme_path);
    match given {
        Some(_) => {
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
        None => println!(
            "not exercised: this platform did not take an access-control list, so the \
             preservation of one across an apply was not checked here"
        ),
    }
}

/// An access-control list altered on the staged copy before rename is caught by read-back
/// verification, leaving the result unresolved rather than claiming success under altered permissions.
#[cfg(not(windows))]
#[test]
fn an_apply_detects_an_access_control_list_tampered_during_staging_and_refuses() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "tampered-acl-source");
    write_bytes(&source, "README.md", b"tampered ACL content\n");
    let source_workspace = fixture.workspace("tampered-acl-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "tampered-acl-destination");
    // The destination starts with no list of its own, so the one this fault puts on the staged
    // copy is protection the file being replaced never had.
    let environment = fixture.service().environment_id();
    let racing = destination.clone();
    let tampered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tampered_by_fault = std::sync::Arc::clone(&tampered);
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
                if give_an_access_control_list(environment, &staged_path).is_some() {
                    tampered_by_fault.store(true, std::sync::atomic::Ordering::SeqCst);
                }
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
    if !tampered.load(std::sync::atomic::Ordering::SeqCst) {
        println!(
            "not exercised: this platform did not take an access-control list, so the read-back \
             of an altered one was not checked here"
        );
        return;
    }
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
        after_claim: None,
        refuse_staging_record: false,
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
#[cfg(not(windows))]
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
        after_claim: None,
        refuse_staging_record: false,
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
// Gated to the platforms that make a link without a privilege: creating one on Windows needs
// either developer mode or an administrator, so a host that has neither would report a failure
// about the fixture rather than about the revert this case is here to check.
#[cfg(unix)]
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
#[cfg(not(windows))]
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
            true
        })),
        after_claim: None,
        refuse_staging_record: false,
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
#[cfg(not(windows))]
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
                std::fs::write(
                    racing.join(temporary).join("content"),
                    b"something else entirely\n",
                )
                .expect("the other writer replaces the staged copy");
            }
            true
        })),
        after_claim: None,
        refuse_staging_record: false,
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
#[cfg(not(windows))]
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

/// KR-REQ-14.28 and KR-REQ-14.33: the repository that owns a destination's own data can sit
/// **inside a nested repository's tree**, where nothing reads.
///
/// `vendor/inner` is a vendored repository, so no reading of the destination looks inside it, and
/// the repository at `vendor/inner/child` keeps its data at `vendor/repo-data` — an ordinary
/// directory of the destination to every other part of this host. Discovery goes where content
/// reading stops, so the apply finds what is there before it writes anything.
#[cfg(not(windows))]
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

/// KR-REQ-14.28 and KR-REQ-14.33: the repository that owns a destination's data can be at
/// the other end of a **link**, with its tree outside the destination altogether.
///
/// Gated to the platforms that make a link without a privilege, for the reason the case above
/// gives.
#[cfg(unix)]
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

/// KR-REQ-14.28 and KR-REQ-14.33: the repository that owns a destination's data can have
/// its tree **inside the destination repository's own data**, where nothing is captured from.
#[cfg(not(windows))]
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

/// Returns a group this host belongs to that is not the one the named file already has.
///
/// A host that belongs to one group only cannot be asked to move a file between two, and the case
/// that needs one says it did not run rather than passing without having checked anything.
#[cfg(unix)]
fn another_group_of_this_host(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let own = std::fs::metadata(path).ok()?.gid();
    let listed = std::process::Command::new("id").arg("-G").output().ok()?;
    if !listed.status.success() {
        return None;
    }
    String::from_utf8(listed.stdout)
        .ok()?
        .split_whitespace()
        .filter_map(|group| group.parse::<u32>().ok())
        .find(|group| *group != own)
}

/// KR-REQ-14.29: a direct apply carries the group the destination belongs to.
///
/// The group is half of what a list and a mode both speak about: the middle digit of a mode and
/// every row of a list that names no user apply to whichever group the file belongs to. Publishing
/// the same bits under another group would hand the file to other people while the protection read
/// back looked identical, so the apply carries the group across or leaves the path alone.
///
/// Gated to the platforms that have one: a Windows object belongs to a single account, which the
/// Windows cases below carry and check in its place.
#[cfg(unix)]
#[test]
fn a_direct_apply_carries_the_group_the_destination_belongs_to() {
    use std::os::unix::fs::MetadataExt as _;

    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "group-source");
    write_bytes(&source, "README.md", b"updated content\n");
    let source_workspace = fixture.workspace("group-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "group-destination");
    let readme_path = destination.join("README.md");
    let Some(group) = another_group_of_this_host(&readme_path) else {
        println!(
            "not exercised: this host belongs to one group only, so an apply across two was not \
             checked here"
        );
        return;
    };
    if std::os::unix::fs::chown(&readme_path, None, Some(group)).is_err() {
        println!(
            "not exercised: this host may not move a file between its groups, so an apply across \
             two was not checked here"
        );
        return;
    }

    let workspace = fixture.workspace("group-destination");
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
        b"updated content\n"
    );
    assert_eq!(
        std::fs::metadata(&readme_path)
            .expect("reads the published file")
            .gid(),
        group,
        "the published file belongs to the group the destination did"
    );
}

/// Applies one path of a source tree over a destination tree and returns what the apply reported.
///
/// Returns nothing where this host does not run a repository tool at all, which is the case on
/// Windows today: its application container cannot keep a repository from being executed from, so
/// the boundary refuses every invocation rather than claiming a guarantee it does not hold. The
/// cases that call this say so rather than passing without having checked anything.
#[cfg(windows)]
fn apply_readme(
    fixture: &Fixture,
    source: &Path,
    destination_name: &str,
) -> Option<kr_protocol::changeset::DiffApplyResult> {
    let source_name = source
        .file_name()
        .expect("the source has a name")
        .to_str()
        .expect("its name is text");
    let source_project = match fixture.try_adopt(source_name) {
        Ok(project) => project,
        Err(refusal) => {
            println!("not exercised: {refusal}");
            return None;
        }
    };
    let source_workspace = fixture.shared_workspace(source_project, source_name);
    let record = fixture.capture(source_workspace, &include_everything());
    let destination = fixture.work().join(destination_name);
    let destination_project = fixture
        .try_adopt(destination_name)
        .expect("the destination is adopted where the source was");
    let workspace = fixture.shared_workspace(destination_project, destination_name);
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    Some(apply::apply(fixture.service(), &order).expect("the apply runs"))
}

/// KR-REQ-14.29: a destination whose whole list comes from the directory above it is published
/// exactly as it was, and the apply invents no difference.
///
/// The copy a replacement stages is created in the same directory, so it receives the same
/// inherited entries by itself. Nothing has to be written, and the read-back has to agree.
#[cfg(windows)]
#[test]
fn a_windows_apply_leaves_an_inherited_list_exactly_as_it_was() {
    let fixture = Fixture::create();
    if let Some(refusal) = fixture.repository_tool_refusal() {
        println!("not exercised: {refusal}");
        return;
    }
    let source = ordinary_repository(fixture.work(), "inherit-source");
    write_bytes(&source, "README.md", b"content under an inherited list\n");

    let destination = ordinary_repository(fixture.work(), "inherit-destination");
    let account = account_of(
        fixture.service().environment_id(),
        &destination.join("README.md"),
    )
    .expect("the destination belongs to an account");
    // An entry on the directory that attaches to every file in it, including the one already there
    // and the copy the apply is about to stage beside it.
    write_a_list(
        &destination,
        Some(&kr_transfer::WindowsAcl::new(
            false,
            vec![kr_transfer::AclEntry::new(
                0,
                OBJECT_INHERIT,
                FILE_ALL_ACCESS,
                account.clone(),
            )],
            Vec::new(),
        )),
    )
    .expect("the directory takes an inheritable entry");

    let environment = fixture.service().environment_id();
    let before = read_whole_list(environment, &destination.join("README.md"));
    assert!(
        !before.is_protected(),
        "a destination that inherits its list is not protected"
    );
    assert!(
        before.explicit().is_empty(),
        "and carries no entry of its own: {before:?}"
    );
    assert!(
        !before.inherited().is_empty(),
        "what it has comes from the directory above it"
    );

    let Some(result) = apply_readme(&fixture, &source, "inherit-destination") else {
        return;
    };
    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "{}: {:?}",
        result.detail,
        result.progress
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"content under an inherited list\n"
    );
    let after = read_whole_list(environment, &destination.join("README.md"));
    assert_eq!(
        after, before,
        "the published file carries what the destination carried"
    );
    assert_eq!(
        after.inherited(),
        before.inherited(),
        "and what it takes from the directory above it is unchanged"
    );
    assert_eq!(
        account_of(environment, &destination.join("README.md")).expect("it still belongs to one"),
        account,
        "and belongs to the same account"
    );
}

/// KR-REQ-14.29: a destination's own entries are what a replacement publishes, and a protected
/// destination stays protected rather than acquiring the directory's inheritable entries.
#[cfg(windows)]
#[test]
fn a_windows_apply_publishes_the_destination_s_own_list_and_not_the_directory_s() {
    let fixture = Fixture::create();
    if let Some(refusal) = fixture.repository_tool_refusal() {
        println!("not exercised: {refusal}");
        return;
    }
    let source = ordinary_repository(fixture.work(), "own-list-source");
    write_bytes(&source, "README.md", b"content under its own list\n");

    let destination = ordinary_repository(fixture.work(), "own-list-destination");
    let environment = fixture.service().environment_id();
    let readme = destination.join("README.md");
    let account = account_of(environment, &readme).expect("the destination belongs to an account");
    // The directory grants one thing to every file in it, and the destination says another about
    // itself, protected so that nothing above it widens what it says.
    write_a_list(
        &destination,
        Some(&kr_transfer::WindowsAcl::new(
            false,
            vec![kr_transfer::AclEntry::new(
                0,
                OBJECT_INHERIT,
                FILE_GENERIC_READ,
                account.clone(),
            )],
            Vec::new(),
        )),
    )
    .expect("the directory takes an inheritable entry");
    give_an_access_control_list(environment, &readme).expect("the destination takes its own list");

    let before = read_whole_list(environment, &readme);
    assert!(before.is_protected(), "the destination's list is protected");
    assert_eq!(
        before.explicit().len(),
        2,
        "both of its own entries: {before:?}"
    );
    assert!(
        before.inherited().is_empty(),
        "a protected list takes nothing from the directory above it"
    );

    let Some(result) = apply_readme(&fixture, &source, "own-list-destination") else {
        return;
    };
    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "{}: {:?}",
        result.detail,
        result.progress
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"content under its own list\n"
    );
    let after = read_whole_list(environment, &readme);
    assert!(
        after.is_protected(),
        "the published file is still protected"
    );
    assert!(
        after.inherited().is_empty(),
        "and did not acquire the directory's inheritable entry: {after:?}"
    );
    assert_eq!(
        after, before,
        "it carries exactly the list the destination had"
    );
}

/// KR-REQ-14.29: a destination this host cannot carry the protection of is left exactly as it was.
///
/// A read-only object on this platform is one a rename cannot replace, and one whose staged copy
/// this host could not remove again if anything later refused. The path is reported unresolved and
/// the destination keeps the bytes it had.
#[cfg(windows)]
#[test]
fn an_apply_to_a_read_only_windows_destination_leaves_it_exactly_as_it_was() {
    let fixture = Fixture::create();
    if let Some(refusal) = fixture.repository_tool_refusal() {
        println!("not exercised: {refusal}");
        return;
    }
    let source = ordinary_repository(fixture.work(), "read-only-source");
    write_bytes(&source, "README.md", b"content that is not published\n");

    let destination = ordinary_repository(fixture.work(), "read-only-destination");
    let readme = destination.join("README.md");
    let held = std::fs::read(&readme).expect("what the destination holds");
    let mut permissions = std::fs::metadata(&readme)
        .expect("reads the destination")
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&readme, permissions).expect("the destination is made read-only");

    let Some(result) = apply_readme(&fixture, &source, "read-only-destination") else {
        return;
    };
    assert_ne!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::Applied)),
        "a destination whose protection cannot be carried is not replaced"
    );
    assert_eq!(result.unresolved_paths, vec!["README.md".to_owned()]);
    let row = result
        .progress
        .iter()
        .find(|row| row.path == "README.md")
        .expect("the path is named");
    assert_eq!(row.state, PathProgressState::Unresolved);
    assert_eq!(
        std::fs::read(&readme).expect("the destination is still there"),
        held,
        "and holds exactly what it held"
    );
    assert!(
        std::fs::metadata(&readme)
            .expect("reads it again")
            .permissions()
            .readonly(),
        "still read-only"
    );
}

/// Reads the whole list an object carries, its own entries and its inherited ones alike.
#[cfg(windows)]
fn read_whole_list(
    environment: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> kr_transfer::WindowsAcl {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;

    let _ = environment;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).access_mode(FILE_GENERIC_READ);
    if path.is_dir() {
        options.custom_flags(BACKUP_SEMANTICS);
    }
    let handle = options.open(path).expect("the object opens for reading");
    kr_transfer::read_access_control(handle.as_handle()).expect("its list is read")
}

/// The single-component name of the directory one destination path is staged through, which is the
/// same name every time that path is applied.
fn staged_entry(path: &str) -> String {
    format!(
        ".kr-apply-{}",
        kr_changeset::objects::hex_of(kr_changeset::objects::digest_of(path.as_bytes()))
    )
}

/// Stops one apply inside the window between staging a path and publishing it, and returns the
/// action it was performed under.
fn stopped_between_staging_and_publishing(
    fixture: &Fixture,
    destination: &Path,
    workspace: kr_protocol::ids::WorkspaceId,
    record: &kr_protocol::changeset::ChangeSetVersionRecord,
) -> kr_protocol::ids::ActionId {
    let affected = expectations(destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: Some(std::sync::Arc::new(|path: &str| path != "README.md")),
        after_claim: None,
        refuse_staging_record: false,
        stop: false,
        detail: "the daemon stopped between staging this path and publishing it".to_owned(),
    }));
    let order = support::apply_order(
        reference(record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let failure = apply::apply(fixture.service(), &order).expect_err("the apply is stopped");
    assert_eq!(failure.code(), ErrorCode::OutcomeUnknown);
    fixture.service().inject(None);
    action
}

/// KR-REQ-14.28: a crash between staging a destination path and publishing it leaves a temporary
/// beside the destination, the journal names it, and the recovery that follows takes away that
/// object and nothing else.
#[test]
fn a_crash_between_staging_and_publishing_is_cleared_up_by_the_recovery() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "staged-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("staged-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "staged-destination");
    let workspace = fixture.workspace("staged-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    // The temporary really is beside the destination, under the name that path is always staged
    // through, and the destination itself is untouched.
    let entry = staged_entry("README.md");
    assert!(
        destination.join(&entry).is_dir(),
        "the staging directory is there, waiting for a rename that never happened"
    );
    assert_eq!(
        support::read_bytes(&destination, &format!("{entry}/content")),
        b"the change\n",
        "and the staged copy is inside it"
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "and nothing was published"
    );

    // A replacement service reads an apply nobody decided, and the journal names what it left.
    let replacement = fixture.reopen();
    let open = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(open.outcome, Nullable(None));
    assert_eq!(
        open.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "the journal names the path whose temporary is still there"
    );

    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(recovery.staged_removed, 1, "it took away its own temporary");
    assert_eq!(recovery.staged_left, 0);
    assert!(
        !destination.join(&entry).exists(),
        "and the name is free again"
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "the destination is exactly as it was"
    );

    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.outcome,
        Nullable(Some(ApplyOutcomeClass::InterruptedApply))
    );
    assert!(settled.recovery.staged_leftovers.is_empty());
    assert!(
        settled.detail.contains("took away the temporaries"),
        "the answer says what it cleared up: {}",
        settled.detail
    );

    // And the path can be applied again, which the occupied name would have prevented.
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let again = apply::apply(
        &replacement,
        &support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        ),
    )
    .expect("the second apply runs");
    assert_eq!(again.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"the change\n"
    );
}

/// KR-REQ-14.28: a file at the staged name that this host cannot prove it made is left exactly as
/// it is, and the answer names the path so a person can look at it.
#[test]
fn a_staged_name_this_host_did_not_make_is_left_where_it_is() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "theirs-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("theirs-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "theirs-destination");
    let workspace = fixture.workspace("theirs-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    // Somebody puts a directory of their own at the staged name, in place of what this host
    // staged, so the object the journal recorded is not what is there any more. Theirs is made
    // **elsewhere and moved in**, so the object this host recorded is still alive under their
    // name and its number cannot be handed to the replacement.
    let entry = staged_entry("README.md");
    let theirs = destination.join("their-own-directory");
    std::fs::create_dir(&theirs).expect("their directory");
    std::fs::write(theirs.join("theirs.txt"), b"somebody else's file\n").expect("their file");
    std::fs::remove_file(destination.join(&entry).join("content")).expect("the staged copy goes");
    std::fs::remove_dir(destination.join(&entry)).expect("and so does the directory it was in");
    std::fs::rename(&theirs, destination.join(&entry)).expect("their editor puts theirs there");

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(
        recovery.staged_removed, 0,
        "this host removes nothing it cannot prove it made"
    );
    assert_eq!(recovery.staged_left, 1);
    assert_eq!(
        support::read_bytes(&destination, &format!("{entry}/theirs.txt")),
        b"somebody else's file\n",
        "their file is exactly as they left it"
    );

    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "and the answer names the path a person has to look at"
    );
    assert!(
        settled.detail.contains("cannot prove it made"),
        "the answer says why it removed nothing: {}",
        settled.detail
    );
}

/// KR-REQ-23.44: an apply's authority is decided inside the transaction that opens its journal,
/// which is the row every write of that apply follows.
///
/// The claim is taken under an authority that holds, the authority is then withdrawn, and the
/// apply that follows opens no journal and writes nothing into the destination's working tree.
#[test]
fn an_authority_withdrawn_after_the_claim_opens_no_apply() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source-tree");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("source-tree");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "destination-tree");
    let before = support::read_bytes(&destination, "README.md");
    let workspace = fixture.workspace("destination-tree");
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);

    let authority = support::Authority::held();
    support::claim(fixture.service(), "diff.apply", &authority);
    assert_eq!(authority.asked(), 1, "the claim asked once");
    authority.withdraw();

    let order = ApplyOrder {
        admitted: Some(&authority),
        ..support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        )
    };
    let action = order.action_id;
    let refusal =
        apply::apply(fixture.service(), &order).expect_err("an apply whose authority has gone");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        authority.asked() > 1,
        "the effect asked for itself rather than relying on the claim's answer"
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        before,
        "the destination's own file is exactly as it was"
    );
    // And no journal was opened, so there is no apply for a reader or a recovery to find.
    let read = apply::read_apply(fixture.service(), action);
    assert!(
        read.is_err(),
        "an apply that never began is not one this host can report on"
    );
    assert!(
        fixture
            .service()
            .recover_before_serving()
            .expect("recovery runs")
            .applies_settled
            == 0,
        "there is no undecided apply to settle"
    );
}

/// KR-REQ-14.28: a staged name this host could not look at keeps its record, the live answer
/// names it, and the recovery that follows takes it up although the apply is settled.
///
/// The temporary is replaced by a **directory** in the window before the rename, so every later
/// look at that name refuses rather than saying it holds nothing: this host can prove neither
/// that its own file is there nor that it is gone. A record cleared on that answer would be an
/// obligation dropped, so it stays, and it is still there for the next daemon to take up.
#[test]
fn a_staged_name_this_host_cannot_look_at_stays_recorded_until_it_is_resolved() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "unreadable-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("unreadable-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "unreadable-destination");
    let workspace = fixture.workspace("unreadable-destination");
    let entry = staged_entry("README.md");
    let at = destination.join(&entry);
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: Some(std::sync::Arc::new(move |path: &str| {
            if path == "README.md" {
                // Somebody takes this host's staging directory away and puts a file of their own
                // at the name. Every later look at that name refuses rather than saying it holds
                // nothing. The apply goes on: what it must not do is publish, and what it must
                // not do afterwards is forget the name.
                std::fs::remove_file(at.join("content")).expect("their editor takes the copy away");
                std::fs::remove_dir(&at).expect("and the directory it was in");
                std::fs::write(&at, b"a file of their own\n").expect("and puts their file there");
            }
            true
        })),
        after_claim: None,
        refuse_staging_record: false,
        stop: false,
        detail: String::new(),
    }));
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let result = apply::apply(fixture.service(), &order).expect("the apply settles");
    fixture.service().inject(None);

    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::UncertainOutcome)),
        "nothing was published: {}",
        result.detail
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "the destination is exactly as it was"
    );
    // The live answer names the path, rather than telling the caller there is nothing to look at.
    assert_eq!(
        result.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "the apply that settled says which name it could not clear"
    );
    assert!(
        destination.join(&entry).is_file(),
        "and it removed nothing it could not prove it made"
    );

    // The apply is settled, so nothing about it is undecided. The record is still an obligation,
    // and the next daemon takes it up for itself.
    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(
        recovery.applies_settled, 0,
        "there is no undecided apply to settle"
    );
    assert_eq!(
        recovery.staged_removed, 0,
        "a directory is not the file this host made"
    );
    assert_eq!(
        recovery.staged_left, 1,
        "and the name is reported rather than dropped"
    );
    assert!(destination.join(&entry).is_file(), "left exactly as it is");
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()]
    );

    // Once the name is free again, the same recovery clears the record: the obligation ends when
    // the name is proved to hold nothing, not when the apply was settled.
    std::fs::remove_file(destination.join(&entry)).expect("the person takes their file away");
    let recovery = replacement
        .recover_before_serving()
        .expect("recovery runs again");
    assert_eq!(recovery.staged_left, 0);
    assert_eq!(recovery.staged_removed, 0, "there was nothing left to take");
    let cleared = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert!(
        cleared.recovery.staged_leftovers.is_empty(),
        "the record is cleared once the name holds nothing"
    );
}

/// KR-REQ-14.28: a temporary this host made and could not take away in the moment is taken away
/// by the recovery that follows, although the apply it belongs to was settled long before.
///
/// The first recovery cannot reach the destination at all, so it settles the interrupted apply
/// and leaves every name it could not look at. The record is what carries the obligation past
/// that settlement.
#[test]
fn a_temporary_left_by_a_settled_apply_is_taken_away_by_a_later_recovery() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "later-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("later-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "later-destination");
    let workspace = fixture.workspace("later-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);
    let entry = staged_entry("README.md");
    assert!(
        destination.join(&entry).join("content").is_file(),
        "the staged copy is there, inside the directory this host made for it"
    );

    // The whole checkout is somewhere else when the daemon starts, which is a workspace this host
    // cannot open. The apply is settled all the same: a recovery runs before anything is served
    // and it never fails to run because a destination moved.
    let moved = fixture.work().join("later-destination-moved");
    std::fs::rename(&destination, &moved).expect("the person moves their checkout");
    let replacement = fixture.reopen();
    let first = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(first.applies_settled, 1);
    assert_eq!(first.staged_removed, 0);
    assert_eq!(
        first.staged_left, 1,
        "the name is reported, because this host could not look at it"
    );
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.outcome,
        Nullable(Some(ApplyOutcomeClass::InterruptedApply)),
        "the apply is decided, and the obligation is not"
    );
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()]
    );

    // The checkout comes back and the next daemon starts. Nothing about this apply is undecided,
    // so only the staging record itself brings this host back to the temporary it left.
    std::fs::rename(&moved, &destination).expect("the person puts their checkout back");
    let later = fixture.reopen();
    let second = later
        .recover_before_serving()
        .expect("the later recovery runs");
    assert_eq!(
        second.applies_settled, 0,
        "there is no undecided apply left to settle"
    );
    assert_eq!(
        second.staged_removed, 1,
        "and the temporary this host made is gone"
    );
    assert_eq!(second.staged_left, 0);
    assert!(
        !destination.join(&entry).exists(),
        "the name is free again for the next apply of that path"
    );
    let cleared = apply::read_apply(&later, action).expect("the apply is recorded");
    assert!(cleared.recovery.staged_leftovers.is_empty());
}

/// KR-REQ-14.28: a staged name that was occupied when this host went to make its own is recorded
/// without an identity, reported while anything is there, and cleared once the name is free.
///
/// The record with no identity is the one this host can prove nothing about. It never removes
/// what is at that name; what it does do is keep asking, so an obligation ends when the name ends
/// rather than staying in the journal for ever.
#[test]
fn a_staged_name_that_was_already_taken_is_recorded_until_the_name_is_free() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "taken-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("taken-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "taken-destination");
    let workspace = fixture.workspace("taken-destination");
    // Somebody's own file is at the name this host would stage this path through, before the
    // apply begins.
    let entry = staged_entry("README.md");
    std::fs::write(destination.join(&entry), b"a file of their own\n").expect("their file");

    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let result = apply::apply(fixture.service(), &order).expect("the apply settles");

    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::UncertainOutcome)),
        "nothing was written: {}",
        result.detail
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "the destination is exactly as it was"
    );
    assert_eq!(
        support::read_bytes(&destination, &entry),
        b"a file of their own\n",
        "and so is their file: this host removes nothing to make room"
    );
    assert_eq!(
        result.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "the answer names the name a person has to look at"
    );

    // The record has no identity, so recovery reports it and removes nothing, however often it
    // runs.
    let replacement = fixture.reopen();
    let first = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(first.staged_removed, 0);
    assert_eq!(first.staged_left, 1);
    assert_eq!(
        support::read_bytes(&destination, &entry),
        b"a file of their own\n"
    );

    // Once the person takes their file away, the name holds nothing and the obligation ends.
    std::fs::remove_file(destination.join(&entry)).expect("the person takes their file away");
    let second = replacement
        .recover_before_serving()
        .expect("recovery runs again");
    assert_eq!(second.staged_removed, 0, "there was nothing of this host's");
    assert_eq!(second.staged_left, 0, "and nothing left to report");
    let cleared = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert!(cleared.recovery.staged_leftovers.is_empty());

    // And the path applies cleanly now that the name is free.
    let affected = expectations(&destination, &["README.md"]);
    let again = apply::apply(
        &replacement,
        &support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        ),
    )
    .expect("the second apply runs");
    assert_eq!(again.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
}

/// KR-REQ-14.28: a journal that will not record what this host has just made leaves nothing of it
/// behind.
///
/// The directory is made before its identity can be recorded, so this is the one failure that
/// could leave a directory of this host's own that nothing could later prove was its own. It is
/// taken away while the handle that made it is still open.
#[test]
fn a_journal_that_refuses_the_staging_record_leaves_no_directory_behind() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "refused-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("refused-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "refused-destination");
    let workspace = fixture.workspace("refused-destination");
    fixture.service().inject(Some(Fault {
        after_paths: usize::MAX,
        act: None,
        before_rename: None,
        after_claim: None,
        refuse_staging_record: true,
        stop: false,
        detail: String::new(),
    }));
    let affected = expectations(&destination, &["README.md"]);
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let order = support::apply_order(
        reference(&record),
        DestinationClass::SharedExisting,
        workspace,
        &affected,
        &limitations,
    );
    let action = order.action_id;
    let result = apply::apply(fixture.service(), &order).expect("the apply settles");
    fixture.service().inject(None);

    assert_eq!(
        result.outcome,
        Nullable(Some(ApplyOutcomeClass::UncertainOutcome)),
        "this path was not written: {}",
        result.detail
    );
    let entry = staged_entry("README.md");
    assert!(
        !destination.join(&entry).exists(),
        "the directory this host made is gone, because it could not prove it made it: {}",
        result.detail
    );
    assert!(
        result.recovery.staged_leftovers.is_empty(),
        "and there is nothing left for a person or a recovery to look at"
    );
    assert_eq!(
        support::read_bytes(&destination, "README.md"),
        b"a repository\n",
        "and the destination is exactly as it was"
    );

    // Nothing is left for a recovery to account for, and the path applies cleanly afterwards.
    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.staged_removed, 0);
    assert_eq!(recovery.staged_left, 0);
    let _ = action;
    let affected = expectations(&destination, &["README.md"]);
    let again = apply::apply(
        &replacement,
        &support::apply_order(
            reference(&record),
            DestinationClass::SharedExisting,
            workspace,
            &affected,
            &limitations,
        ),
    )
    .expect("the second apply runs");
    assert_eq!(again.outcome, Nullable(Some(ApplyOutcomeClass::Applied)));
}

/// KR-REQ-14.28: a file somebody put inside this host's own staging directory is not one this
/// host made, and it is left exactly where it is.
///
/// The directory is the one the journal recorded, so it passes that comparison; the file inside it
/// is not. A cleanup that took the directory on trust would take away a file it never wrote, so
/// the file is compared on its own and the whole obligation is reported instead.
#[test]
fn content_this_host_did_not_write_is_left_inside_its_own_staging_directory() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "replaced-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("replaced-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "replaced-destination");
    let workspace = fixture.workspace("replaced-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    // Somebody replaces the file inside this host's staging directory, leaving the directory
    // itself untouched. Theirs is made elsewhere and moved in, so the object this host recorded
    // stays alive under their name and its number cannot be handed to the replacement.
    let entry = staged_entry("README.md");
    let theirs = destination.join("their-own-file");
    std::fs::write(&theirs, b"somebody else's file\n").expect("their file");
    std::fs::rename(&theirs, destination.join(&entry).join("content")).expect("their editor");

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(
        recovery.staged_removed, 0,
        "this host takes away nothing it cannot prove it wrote"
    );
    assert_eq!(recovery.staged_left, 1);
    assert_eq!(
        support::read_bytes(&destination, &format!("{entry}/content")),
        b"somebody else's file\n",
        "their file is exactly as they left it"
    );
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "and the answer names the path a person has to look at"
    );

    // Once they take their file away, the directory holds nothing of theirs and this host's own
    // obligation ends: it takes its directory away and the record goes with it.
    std::fs::remove_file(destination.join(&entry).join("content")).expect("they take theirs away");
    let later = replacement
        .recover_before_serving()
        .expect("the later recovery runs");
    assert_eq!(later.staged_removed, 1, "its own directory is gone");
    assert_eq!(later.staged_left, 0);
    assert!(!destination.join(&entry).exists());
    let cleared = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert!(cleared.recovery.staged_leftovers.is_empty());
}

/// KR-REQ-14.28: the directory this host stages a path through admits this account and nobody
/// else.
///
/// That is what the removal rests on. The only writer that can put another object at a name inside
/// it is one already running as this account, and a directory that admitted anybody else would
/// widen that to the machine.
#[cfg(unix)]
#[test]
fn the_staging_directory_this_host_makes_admits_nobody_else() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "mode-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("mode-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "mode-destination");
    let workspace = fixture.workspace("mode-destination");
    stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    let entry = staged_entry("README.md");
    let mode = std::fs::metadata(destination.join(&entry))
        .expect("the staging directory is there")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        mode, 0o700,
        "the staging directory admits its owner and nobody else"
    );
}

/// KR-REQ-14.28: a staging directory that admits anybody besides its owner is one this host can
/// promise nothing about, so it is left exactly where it is and reported.
///
/// The identity still matches: this is the same directory this host made. What changed is that
/// another account can now write inside it, which is the one condition that makes the removal a
/// judgement rather than a rule, so the removal refuses until it holds again.
#[cfg(unix)]
#[test]
fn a_staging_directory_that_admits_anybody_else_is_left_where_it_is() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "widened-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("widened-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "widened-destination");
    let workspace = fixture.workspace("widened-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    let entry = staged_entry("README.md");
    let staged = destination.join(&entry);
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
        .expect("somebody widens what this host made");

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(
        recovery.staged_removed, 0,
        "a directory anybody else can write in is not one this host takes away"
    );
    assert_eq!(recovery.staged_left, 1);
    assert_eq!(
        support::read_bytes(&destination, &format!("{entry}/content")),
        b"the change\n",
        "and what it holds is exactly as it was"
    );
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "the answer names the path a person has to look at"
    );

    // Shut again, the directory is the one this host made and holds only what this host wrote, so
    // the obligation ends the ordinary way.
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))
        .expect("it is shut again");
    let later = replacement
        .recover_before_serving()
        .expect("the later recovery runs");
    assert_eq!(later.staged_removed, 1, "its own directory is gone");
    assert_eq!(later.staged_left, 0);
    assert!(!staged.exists());
    let cleared = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert!(cleared.recovery.staged_leftovers.is_empty());
}

/// KR-REQ-14.28: a staged name in a directory every account on the machine may write in is one
/// this host cannot show is still its own, so the name stays and the path is reported.
///
/// The file inside still goes: the staging directory itself is shut, and the removal of what is in
/// it is named against that directory's own handle. What waits is the directory's own name, which
/// lives in a directory this host does not own the rules of.
#[cfg(unix)]
#[test]
fn a_staged_name_in_a_directory_open_to_the_machine_is_left_where_it_is() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "open-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("open-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "open-destination");
    let workspace = fixture.workspace("open-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    let entry = staged_entry("README.md");
    let was = std::fs::metadata(&destination)
        .expect("the destination is there")
        .permissions()
        .mode()
        & 0o7777;
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o777))
        .expect("the destination is opened to the machine");

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(
        recovery.staged_removed, 0,
        "the staged name is not one this host can show is still its own"
    );
    assert_eq!(recovery.staged_left, 1);
    assert!(
        destination.join(&entry).is_dir(),
        "so the directory is exactly where it was"
    );
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()],
        "and the answer names the path a person has to look at"
    );

    // The person's own directory again, and the obligation ends the ordinary way.
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(was))
        .expect("the destination is the person's own again");
    let later = replacement
        .recover_before_serving()
        .expect("the later recovery runs");
    assert_eq!(later.staged_removed, 1);
    assert_eq!(later.staged_left, 0);
    assert!(!destination.join(&entry).exists());
}

/// KR-REQ-14.28: on a platform that keeps protection beside the mode bits, a staging directory
/// that carries a list admitting another account is one this host takes nothing out of.
///
/// The mode still says `0700` and the identity still matches. What the list says is that the mode
/// is not the whole of who may write in there, so the file inside could be another account's and
/// this host cannot show otherwise.
#[cfg(target_os = "macos")]
#[test]
fn a_staging_directory_whose_list_admits_another_account_keeps_what_is_inside_it() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "listed-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("listed-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "listed-destination");
    let workspace = fixture.workspace("listed-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    let entry = staged_entry("README.md");
    let staged = destination.join(&entry);
    let granted = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write,add_file,delete_child"])
        .arg(&staged)
        .status()
        .expect("the platform's own tool runs");
    assert!(
        granted.success(),
        "somebody puts a list on what this host made"
    );

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(
        recovery.staged_removed, 0,
        "a directory whose list admits another account is not one this host removes from"
    );
    assert_eq!(recovery.staged_left, 1);
    assert_eq!(
        support::read_bytes(&destination, &format!("{entry}/content")),
        b"the change\n",
        "and what it holds is exactly as it was"
    );
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert_eq!(
        settled.recovery.staged_leftovers,
        vec!["README.md".to_owned()]
    );

    // With the list taken off, the mode bits are the whole answer again and the obligation ends.
    let withdrawn = std::process::Command::new("/bin/chmod")
        .args(["-a#", "0"])
        .arg(&staged)
        .status()
        .expect("the platform's own tool runs");
    assert!(withdrawn.success(), "the list comes off again");
    let later = replacement
        .recover_before_serving()
        .expect("the later recovery runs");
    assert_eq!(later.staged_removed, 1, "its own directory is gone");
    assert_eq!(later.staged_left, 0);
    assert!(!staged.exists());
}

/// KR-REQ-14.28: a staging directory this host cannot even look inside still goes, once it holds
/// nothing.
///
/// A mode that keeps this host out of its own directory ends the staging, and what must not follow
/// is a name no recovery can ever clear. The empty-directory removal is the answer: it needs
/// nothing of the directory it removes, and anything inside keeps it.
#[cfg(unix)]
#[test]
fn a_staging_directory_this_host_cannot_look_inside_still_goes_once_it_is_empty() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "unreadable-source");
    write(&source, "README.md", "the change\n");
    let source_workspace = fixture.workspace("unreadable-source");
    let record = fixture.capture(source_workspace, &include_everything());

    let destination = ordinary_repository(fixture.work(), "unreadable-destination");
    let workspace = fixture.workspace("unreadable-destination");
    let action = stopped_between_staging_and_publishing(&fixture, &destination, workspace, &record);

    // What a creation mask that took the search bit away would have left: an empty directory this
    // host cannot open a name inside.
    let entry = staged_entry("README.md");
    let staged = destination.join(&entry);
    std::fs::remove_file(staged.join("content")).expect("nothing was ever written inside");
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
        .expect("and this host cannot look inside it");

    let replacement = fixture.reopen();
    let recovery = replacement.recover_before_serving().expect("recovery runs");
    assert_eq!(recovery.applies_settled, 1);
    assert_eq!(recovery.staged_removed, 1, "its own directory is gone");
    assert_eq!(recovery.staged_left, 0);
    assert!(!staged.exists(), "and the name is free again");
    let settled = apply::read_apply(&replacement, action).expect("the apply is recorded");
    assert!(settled.recovery.staged_leftovers.is_empty());
}
