//! `diff.read`, `diff.apply` and `diff.revert`: the destination classes and the five outcomes.
//!
//! # The destination decides the guarantee, and there is no default
//!
//! * [`DestinationClass::Proposal`] writes to no working tree at all. It records an immutable
//!   version of what the destination holds now, overlays the change, and records that as a second
//!   immutable version. A person then decides. This is what an apply does when a caller does not
//!   explicitly ask for something weaker, which is what section 14 means by "apply defaults to an
//!   immutable proposal/change-set result, not blind overwrite of an actively edited worktree".
//! * [`DestinationClass::VersionedReference`] is reference compare-and-swap: the reference is read
//!   and compared with the expected old value, and a mismatch is `DRAFT_CONFLICT`. Moving the
//!   reference itself needs a Git subcommand the project service's restricted execution profile
//!   does not run, so this host **states that limitation instead of executing it**, which is the
//!   rule section 14 gives for a faithful interpretation that needs an ungranted helper. It also
//!   says the thing a caller must not assume: a reference update does not atomically update a
//!   dirty working tree.
//! * [`DestinationClass::SharedExisting`] writes the user's own working tree in place. It is
//!   **best-effort conflict detection**, not universal no-clobber compare-and-swap, and a caller
//!   cannot choose it until it has passed back the limitation this host returns for it.
//!
//! # What a direct apply does, in order
//!
//! 1. The limitation is returned, and the request has to carry it back.
//! 2. The **preflight**: every affected path's current content and index object are compared with
//!    what the request expects. A mismatch is `DRAFT_CONFLICT` and **nothing is written to this
//!    host's own journal either**.
//! 3. A **before version**: an immutable capture of the destination as it stands. That is the
//!    recoverable "before" a person or a revert works from.
//! 4. The content is **staged and validated**: written into a private directory of this host's
//!    own and read back against its digest, so nothing half-written reaches the destination.
//! 5. Per path: `planned` is recorded, the destination is **rechecked as late as the platform
//!    permits** — immediately before the rename — and the staged file is renamed over the
//!    destination through the directory's own handle. Then the outcome replaces the `planned` row.
//! 6. An **after version**, and only then the outcome class.
//!
//! [`ApplyOutcomeClass::Applied`] is recorded once every planned path has been confirmed in the
//! destination. A crash between a write and its record leaves the path `planned` and the apply
//! undecided, and [`recover`] settles it as [`ApplyOutcomeClass::InterruptedApply`] with exactly
//! the paths whose state is known. There is no path through this module that turns a crash after
//! one file into an atomic-success receipt.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write as _;

use kr_project::{OpenedRepository, RestrictedProfile};
use kr_protocol::changeset::{
    AffectedVersion, ApplyOutcomeClass, CapturePolicy, CapturedPath, ChangeSetVersionRecord,
    ContentOrigin, DestinationClass, DiffApplyResult, DiffEntry, DiffReadResult, ExpectedReference,
    FileGrant, MAX_CHANGESET_ENTRIES, PathClass, PathConflict, PathProgress, PathProgressState,
    Provenance, RecoveryObjects, ReferenceOutcome, SourceConsistency, VersionRef,
};
use kr_protocol::ids::{ActionId, WorkspaceId};
use kr_protocol::project::{ChangeKind, ContentClass, InclusionChoice, InclusionPolicy};
use kr_protocol::scalars::{Digest256, Nullable, U64};
use kr_transfer::{AuthorisedDirectory, ObjectPolicy, RelativeName};

use crate::capture::{
    IndexEntry, WorkingRead, read_index, read_object, read_status, read_working_tree,
};
use crate::error::{ChangeSetError, Result};
use crate::objects::{digest_of, hex_of};
use crate::service::{ChangeSetService, STAGING_DIRECTORY};
use crate::store::{ApplyRow, ProgressRow};
use crate::version::Manifest;

/// What one apply or revert is asked to do.
#[derive(Clone, Debug)]
pub struct ApplyOrder<'a> {
    /// The action it is performed under.
    pub action_id: ActionId,
    /// The version whose content it carries.
    pub version: VersionRef,
    /// Where it goes.
    pub destination: DestinationClass,
    /// The workspace the destination names.
    pub workspace_id: Option<WorkspaceId>,
    /// The reference and its expected old value, for a versioned Git reference.
    pub expected_reference: Option<&'a ExpectedReference>,
    /// What the request expects each affected path to hold now.
    pub affected: &'a [AffectedVersion],
    /// Which of the version's changed paths to carry. Empty means all of them.
    pub paths: &'a [String],
    /// Run the preflight and stop.
    pub preflight_only: bool,
    /// The limitations of the chosen destination, as the caller was shown them.
    pub acknowledged_limitations: &'a [String],
    /// True for a revert, which puts the base's own content back.
    pub revert: bool,
    /// Who asked, for the provenance of the versions this records.
    pub provenance: Provenance,
}

/// Where a test stops an apply, so the journal can be read as a crash leaves it.
#[cfg(feature = "fault-injection")]
#[derive(Clone, Debug)]
pub struct Fault {
    /// Stop once this many paths have been written and confirmed.
    pub after_paths: usize,
    /// What the failure says.
    pub detail: String,
}

/// What one apply cannot promise, in this host's own words.
///
/// A caller is shown these **before** it chooses the class: they are what a preflight returns, and
/// a direct apply to a shared working tree is refused until the request carries them back.
#[must_use]
pub fn limitations(destination: DestinationClass) -> Vec<String> {
    match destination {
        DestinationClass::Proposal => vec![
            "a proposal writes to no working tree: it records an immutable version of what the \
             destination holds now and a second one with this change applied, and a person \
             decides what to do with them"
                .to_owned(),
        ],
        DestinationClass::VersionedReference => vec![
            "an expected-old-value update is compare-and-swap on the reference; it does not \
             atomically update a dirty working tree, and a tree with uncommitted work in it is \
             unchanged by one"
                .to_owned(),
            "this host reads the reference and compares it with the value the request expects, \
             and it does not move the reference: its restricted Git execution profile runs no \
             subcommand that writes one, so the limitation is stated rather than the update run \
             under a read-only grant"
                .to_owned(),
        ],
        DestinationClass::SharedExisting => vec![
            "a direct apply to a shared working tree is best-effort conflict detection, not \
             universal no-clobber compare-and-swap: this host rechecks each path as late as the \
             platform permits and an editor or an agent that writes between that recheck and the \
             rename is not excluded by it"
                .to_owned(),
            "an atomic rename protects the destination from holding half of one version and half \
             of another; it does not protect it from an external write, and a lock this host \
             holds does not exclude an editor that does not take it"
                .to_owned(),
            "this host retains an immutable version of the tree before the apply and one after \
             it; it does not claim to have captured every intermediate version, and it cannot \
             undo whatever else a command run in that tree did"
                .to_owned(),
        ],
    }
}

/// Reads a diff: identity, base and head, the tracked, untracked and binary changes, and the
/// content revision of each side.
///
/// # Errors
///
/// Returns whatever the project service returns for the repository, and
/// [`ChangeSetError::UnknownVersion`] when a named version does not exist.
pub fn read(
    service: &ChangeSetService,
    workspace_id: Option<WorkspaceId>,
    version: Option<VersionRef>,
) -> Result<DiffReadResult> {
    match (workspace_id, version) {
        (Some(_), Some(_)) | (None, None) => Err(ChangeSetError::InvalidArgument(
            "a diff read names one subject: a workspace, whose live working tree it reads, or a \
             change-set version, whose captured tree it reads"
                .into(),
        )),
        (Some(workspace_id), None) => read_workspace(service, workspace_id),
        (None, Some(version)) => read_version(service, version),
    }
}

fn read_workspace(service: &ChangeSetService, workspace_id: WorkspaceId) -> Result<DiffReadResult> {
    let resolved = service.resolve(workspace_id)?;
    let repository = service.open_repository(&resolved)?;
    let profile = service.project().profile();
    let (revision, reference) = repository.head(profile)?;
    let Some(head_revision) = revision else {
        return Err(ChangeSetError::InvalidArgument(
            "this repository has no commit yet, so a diff has no base to be against".into(),
        ));
    };
    let index = read_index(profile, &repository)?;
    let status = read_status(profile, &repository, &FileGrant::default())?;
    let mut tracked = Vec::new();
    let mut untracked = Vec::new();
    for entry in &status {
        let content_digest = match read_working_tree(&repository, &entry.path)? {
            WorkingRead::Content { bytes, .. } => Some(digest_of(&bytes)),
            _ => None,
        };
        let byte_len = content_digest.map(|_| ());
        let read = DiffEntry {
            path: entry.path.clone(),
            class: class_of(entry.class),
            change: entry.change,
            content: content_digest.map_or(ContentClass::Unknown, |_| {
                match read_working_tree(&repository, &entry.path) {
                    Ok(WorkingRead::Content { ref bytes, .. }) => {
                        crate::capture::classify_content(bytes)
                    }
                    _ => ContentClass::Unknown,
                }
            }),
            byte_len: Nullable(byte_len.and_then(|()| {
                match read_working_tree(&repository, &entry.path) {
                    Ok(WorkingRead::Content { ref bytes, .. }) => {
                        Some(U64::new(bytes.len() as u64))
                    }
                    _ => None,
                }
            })),
            base_object_id: Nullable(index.get(&entry.path).map(|held| held.object_id.clone())),
            content_digest: Nullable(content_digest),
        };
        if index.contains_key(&entry.path) {
            tracked.push(read);
        } else {
            untracked.push(read);
        }
    }
    let counts = count(tracked.iter().chain(untracked.iter()));
    let omitted = tracked.len().saturating_sub(MAX_CHANGESET_ENTRIES)
        + untracked.len().saturating_sub(MAX_CHANGESET_ENTRIES);
    tracked.truncate(MAX_CHANGESET_ENTRIES);
    untracked.truncate(MAX_CHANGESET_ENTRIES);
    Ok(DiffReadResult {
        environment_id: service.environment_id(),
        project_repository_id: resolved.project_repository_id,
        workspace_id,
        repository_identity: kr_project::identity::wire_identity(repository.identity().git_dir),
        worktree_identity: kr_project::identity::wire_identity(repository.identity().work_tree),
        base_revision: head_revision.clone(),
        base_reference: Nullable(reference.clone()),
        head_revision,
        head_reference: Nullable(reference),
        source_version: Nullable(None),
        tracked,
        untracked,
        omitted_entries: U64::new(omitted as u64),
        counts,
        limitations: vec![
            "this is a reading of a live working tree, so it says what was there when it was \
             taken rather than what is there now; a change set is how work is named exactly"
                .to_owned(),
        ],
        read_at_ms: kr_ipc::now_ms(),
    })
}

fn read_version(service: &ChangeSetService, version: VersionRef) -> Result<DiffReadResult> {
    let record = service.record(version.change_set_id, Some(version.version))?;
    let manifest = service.manifest(version.change_set_id, version.version)?;
    let mut tracked = Vec::new();
    let mut untracked = Vec::new();
    for entry in manifest.changes() {
        let read = DiffEntry {
            path: entry.path.clone(),
            class: entry.class,
            change: entry.change,
            content: entry.content,
            byte_len: Nullable(Some(entry.byte_len)),
            base_object_id: entry.base_object_id.clone(),
            content_digest: Nullable(Some(entry.content_digest)),
        };
        if entry.base_object_id.0.is_some() {
            tracked.push(read);
        } else {
            untracked.push(read);
        }
    }
    let counts = count(tracked.iter().chain(untracked.iter()));
    let omitted = tracked.len().saturating_sub(MAX_CHANGESET_ENTRIES)
        + untracked.len().saturating_sub(MAX_CHANGESET_ENTRIES);
    tracked.truncate(MAX_CHANGESET_ENTRIES);
    untracked.truncate(MAX_CHANGESET_ENTRIES);
    Ok(DiffReadResult {
        environment_id: record.environment_id,
        project_repository_id: record.project_repository_id,
        workspace_id: record.workspace_id,
        repository_identity: record.repository_identity,
        worktree_identity: record.worktree_identity,
        base_revision: record.base_revision.clone(),
        base_reference: record.base_reference.clone(),
        head_revision: record.base_revision,
        head_reference: record.base_reference,
        source_version: Nullable(Some(version)),
        tracked,
        untracked,
        omitted_entries: U64::new(omitted as u64),
        counts,
        limitations: record.limitations,
        read_at_ms: kr_ipc::now_ms(),
    })
}

fn class_of(class: kr_protocol::project::InclusionClass) -> PathClass {
    match class {
        kr_protocol::project::InclusionClass::UntrackedFile => PathClass::UntrackedFile,
        kr_protocol::project::InclusionClass::GeneratedArtefact => PathClass::GeneratedArtefact,
        kr_protocol::project::InclusionClass::Submodule => PathClass::Submodule,
        _ => PathClass::DirtyFile,
    }
}

fn count<'a>(
    entries: impl Iterator<Item = &'a DiffEntry>,
) -> Vec<kr_protocol::changeset::CaptureCount> {
    let mut totals: BTreeMap<PathClass, (u64, u64, u64)> = BTreeMap::new();
    for entry in entries {
        let row = totals.entry(entry.class).or_insert((0, 0, 0));
        row.0 += 1;
        if entry.content == ContentClass::Binary {
            row.1 += 1;
        }
        row.2 = row
            .2
            .saturating_add(entry.byte_len.0.map_or(0, kr_protocol::scalars::U64::get));
    }
    PathClass::EVERY
        .iter()
        .map(|class| {
            let (total, binary, bytes) = totals.get(class).copied().unwrap_or((0, 0, 0));
            kr_protocol::changeset::CaptureCount {
                class: *class,
                total: U64::new(total),
                binary: U64::new(binary),
                byte_len: U64::new(bytes),
            }
        })
        .collect()
}

/// Applies or reverts one version at one destination.
///
/// # Errors
///
/// Returns [`ChangeSetError::DraftConflict`] when the preflight finds the destination is not what
/// the request expects, in which case **nothing is written anywhere**;
/// [`ChangeSetError::InvalidArgument`] when the request does not carry what the destination needs;
/// [`ChangeSetError::Unsupported`] when the destination needs something this host does not do; and
/// [`ChangeSetError::OutcomeUnknown`] when an apply stopped and this host could not establish what
/// the destination holds.
pub fn apply(service: &ChangeSetService, order: &ApplyOrder<'_>) -> Result<DiffApplyResult> {
    let record = service.record(order.version.change_set_id, Some(order.version.version))?;
    let manifest = service.manifest(order.version.change_set_id, order.version.version)?;
    let carried = carried_paths(&manifest, order)?;
    let limitations = limitations(order.destination);
    if order.destination == DestinationClass::SharedExisting {
        for limitation in &limitations {
            if !order
                .acknowledged_limitations
                .iter()
                .any(|shown| shown == limitation)
            {
                return Err(ChangeSetError::InvalidArgument(
                    format!(
                        "a direct apply to a shared working tree is chosen only after this \
                         limitation has been shown, and this request does not carry it back: \
                         {limitation}"
                    )
                    .into(),
                ));
            }
        }
    }
    match order.destination {
        DestinationClass::Proposal => {
            proposal(service, order, &record, &manifest, &carried, &limitations)
        }
        DestinationClass::VersionedReference => reference(service, order, &record, &limitations),
        DestinationClass::SharedExisting => {
            direct(service, order, &record, &manifest, &carried, &limitations)
        }
    }
}

/// Returns exactly the paths this apply carries.
fn carried_paths(manifest: &Manifest, order: &ApplyOrder<'_>) -> Result<Vec<CapturedPath>> {
    let changes: Vec<CapturedPath> = manifest.changes().into_iter().cloned().collect();
    if order.paths.is_empty() {
        return Ok(changes);
    }
    let mut chosen = Vec::new();
    for path in order.paths {
        let found = changes
            .iter()
            .find(|entry| entry.path == *path)
            .ok_or_else(|| {
                ChangeSetError::InvalidArgument(
                    format!(
                        "this version holds no change for {}",
                        kr_project::git::redact(path)
                    )
                    .into(),
                )
            })?;
        chosen.push(found.clone());
    }
    Ok(chosen)
}

/// What the preflight found about one path.
struct Observed {
    worktree_digest: Option<Digest256>,
    index_object_id: Option<String>,
}

/// Reads what the destination holds for every affected path.
fn observe(
    repository: &OpenedRepository,
    index: &BTreeMap<String, IndexEntry>,
    affected: &[AffectedVersion],
) -> Result<BTreeMap<String, Observed>> {
    let mut found = BTreeMap::new();
    for entry in affected {
        let worktree_digest = match read_working_tree(repository, &entry.path)? {
            WorkingRead::Content { bytes, .. } => Some(digest_of(&bytes)),
            WorkingRead::Gone => None,
            WorkingRead::Unsupported(detail) | WorkingRead::Unreadable(detail) => {
                return Err(ChangeSetError::DraftConflict {
                    detail: format!(
                        "this host could not read what {} holds, so it cannot say the destination \
                         is what the request expects: {detail}",
                        kr_project::git::redact(&entry.path)
                    )
                    .into(),
                });
            }
        };
        found.insert(
            entry.path.clone(),
            Observed {
                worktree_digest,
                index_object_id: index.get(&entry.path).map(|held| held.object_id.clone()),
            },
        );
    }
    Ok(found)
}

/// Compares what the destination holds with what the request expects.
fn conflicts(
    affected: &[AffectedVersion],
    observed: &BTreeMap<String, Observed>,
) -> Vec<PathConflict> {
    let mut found = Vec::new();
    for entry in affected {
        let Some(here) = observed.get(&entry.path) else {
            continue;
        };
        let worktree_differs = entry.expected_worktree_digest.0 != here.worktree_digest;
        let index_differs = entry
            .expected_index_object_id
            .0
            .as_ref()
            .is_some_and(|expected| here.index_object_id.as_ref() != Some(expected));
        if worktree_differs || index_differs {
            found.push(PathConflict {
                path: entry.path.clone(),
                expected_worktree_digest: entry.expected_worktree_digest,
                observed_worktree_digest: Nullable(here.worktree_digest),
                expected_index_object_id: entry.expected_index_object_id.clone(),
                observed_index_object_id: Nullable(here.index_object_id.clone()),
                detail: if worktree_differs {
                    "the working tree holds something other than what the request expects"
                        .to_owned()
                } else {
                    "the index holds something other than what the request expects".to_owned()
                },
            });
        }
    }
    found
}

/// The preflight that writes nothing.
fn preflight(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    carried: &[CapturedPath],
) -> Result<(
    OpenedRepository,
    BTreeMap<String, IndexEntry>,
    Vec<PathConflict>,
)> {
    let Some(workspace_id) = order.workspace_id else {
        return Err(ChangeSetError::InvalidArgument(
            "this destination names the workspace it writes to".into(),
        ));
    };
    let resolved = service.resolve(workspace_id)?;
    let repository = service.open_repository(&resolved)?;
    let index = read_index(service.project().profile(), &repository)?;
    // Every path this apply would write has to be one the request says what it expects to find at,
    // because a path the request does not name is a path the preflight cannot check.
    for entry in carried {
        if !order
            .affected
            .iter()
            .any(|affected| affected.path == entry.path)
        {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "this apply would write {} and the request does not say what it expects to \
                     find there, so the preflight cannot check it",
                    kr_project::git::redact(&entry.path)
                )
                .into(),
            ));
        }
    }
    let observed = observe(&repository, &index, order.affected)?;
    let found = conflicts(order.affected, &observed);
    Ok((repository, index, found))
}

/// A proposal: two immutable versions and no write to any working tree.
fn proposal(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    record: &ChangeSetVersionRecord,
    manifest: &Manifest,
    carried: &[CapturedPath],
    limitations: &[String],
) -> Result<DiffApplyResult> {
    let (repository, _index, found) = preflight(service, order, carried)?;
    if !found.is_empty() {
        return Err(conflict_error(&found));
    }
    if order.preflight_only {
        return Ok(clean_preflight(order, limitations));
    }
    let before = capture_destination(service, order, record)?;
    let mut proposed = service.manifest(before.change_set_id, before.version)?;
    overlay(
        &mut proposed,
        carried,
        order.revert,
        service,
        &repository,
        manifest,
    )?;
    proposed.canonicalise();
    let provenance = Provenance {
        derived_from: Nullable(Some(order.version)),
        derivation: format!(
            "an apply of change set {} version {} to a proposal, which wrote to no working tree",
            order.version.change_set_id,
            order.version.version.get()
        ),
        ..order.provenance.clone()
    };
    let proposal = service.derive(
        &before,
        &proposed,
        provenance,
        SourceConsistency::PerFileCapture,
        "this version is a proposal: it is what the destination would hold if this change were \
         applied, recorded rather than written. Its content is what this host read from the \
         destination one file at a time, with this change's own content put over it"
            .to_owned(),
    )?;
    let now = kr_ipc::now_ms();
    let reference = VersionRef {
        change_set_id: proposal.change_set_id,
        version: proposal.version,
    };
    service.locked()?.begin_apply(&ApplyRow {
        action_id: order.action_id,
        change_set_id: order.version.change_set_id,
        version: order.version.version,
        workspace_id: order.workspace_id,
        destination: order.destination,
        outcome: None,
        before_version: Some((before.change_set_id, before.version)),
        after_version: None,
        staged_name: None,
        detail: "a proposal writes nothing".to_owned(),
        started_at_ms: now,
        decided_at_ms: None,
    })?;
    service.locked()?.settle_apply(
        order.action_id,
        ApplyOutcomeClass::Applied,
        Some((reference.change_set_id, reference.version)),
        "the proposal was recorded and no working tree was written",
        now,
    )?;
    service.record_evidence(
        proposal.change_set_id,
        proposal.version,
        kr_protocol::changeset::EvidenceKind::AppliedChange,
        &format!("a proposal from action {}", order.action_id),
    )?;
    Ok(DiffApplyResult {
        action_id: order.action_id,
        outcome: Nullable(Some(ApplyOutcomeClass::Applied)),
        destination: order.destination,
        applied_version: order.version,
        proposal_version: Nullable(Some(reference)),
        reference: Nullable(None),
        changed_paths: Vec::new(),
        unresolved_paths: Vec::new(),
        conflicts: Vec::new(),
        progress: Vec::new(),
        recovery: RecoveryObjects {
            before_version: Nullable(Some(VersionRef {
                change_set_id: before.change_set_id,
                version: before.version,
            })),
            after_version: Nullable(Some(reference)),
            applied_version: Nullable(Some(order.version)),
            staged_path: Nullable(None),
            detail: "the destination as it stands, and the version it would hold; no working tree \
                     was written, so there is nothing to undo"
                .to_owned(),
        },
        limitations: limitations.to_vec(),
        detail: "an immutable proposal was recorded and no working tree was written".to_owned(),
        decided_at_ms: now,
    })
}

/// A versioned Git reference: compare-and-swap, and the limitation stated rather than executed.
fn reference(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    _record: &ChangeSetVersionRecord,
    limitations: &[String],
) -> Result<DiffApplyResult> {
    let Some(expected) = order.expected_reference else {
        return Err(ChangeSetError::InvalidArgument(
            "an apply to a versioned Git reference names the reference and the value it expects \
             it to hold, because that value is what makes the update a compare-and-swap"
                .into(),
        ));
    };
    let Some(workspace_id) = order.workspace_id else {
        return Err(ChangeSetError::InvalidArgument(
            "this destination names the workspace whose repository holds the reference".into(),
        ));
    };
    let resolved = service.resolve(workspace_id)?;
    let repository = service.open_repository(&resolved)?;
    let observed = read_reference(service.project().profile(), &repository, &expected.name)?;
    let held = observed == expected.expected_old_value.0;
    let outcome = ReferenceOutcome {
        name: expected.name.clone(),
        expected_old_value: expected.expected_old_value.clone(),
        observed_old_value: Nullable(observed.clone()),
        compare_and_swap_held: held,
        updated: false,
        limitation: limitations.join(" "),
    };
    if !held {
        return Err(ChangeSetError::DraftConflict {
            detail: format!(
                "the reference {} does not hold the value this request expects, so the \
                 compare-and-swap does not hold and nothing was written",
                kr_project::git::redact(&expected.name)
            )
            .into(),
        });
    }
    if order.preflight_only {
        let mut result = clean_preflight(order, limitations);
        result.reference = Nullable(Some(outcome));
        return Ok(result);
    }
    // Section 14: when faithful interpretation requires an ungranted helper, expose the limitation
    // instead of executing it. Moving a reference needs a Git subcommand this host's restricted
    // execution profile does not run, and widening that profile is not something an apply decides.
    Err(ChangeSetError::Unsupported {
        detail: format!(
            "the reference {} holds the value this request expects, so the compare-and-swap would \
             hold; this host does not move it, because its restricted Git execution profile runs \
             no subcommand that writes a reference. {}",
            kr_project::git::redact(&expected.name),
            limitations.join(" ")
        )
        .into(),
    })
}

/// Reads what one reference holds now.
fn read_reference(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    name: &str,
) -> Result<Option<String>> {
    if name.is_empty()
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err(ChangeSetError::InvalidArgument(
            "a reference is named with letters, digits and `/`, `_`, `-` and `.`, and this is not"
                .into(),
        ));
    }
    let arguments: [&OsStr; 3] = [
        OsStr::new("show-ref"),
        OsStr::new("--verify"),
        OsStr::new(name),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_complete()?;
    if !output.success {
        return Ok(None);
    }
    let text = output.text();
    Ok(text
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .map(std::borrow::ToOwned::to_owned))
}

/// A direct apply to the user's own working tree.
fn direct(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    record: &ChangeSetVersionRecord,
    manifest: &Manifest,
    carried: &[CapturedPath],
    limitations: &[String],
) -> Result<DiffApplyResult> {
    let (repository, _index, found) = preflight(service, order, carried)?;
    if !found.is_empty() {
        return Err(conflict_error(&found));
    }
    if order.preflight_only {
        return Ok(clean_preflight(order, limitations));
    }
    // What goes into the destination, decided before anything is written: a revert puts the base's
    // own content back, an apply puts the version's content in.
    let mut content: Vec<(String, Vec<u8>, bool)> = Vec::new();
    let mut unresolved = Vec::new();
    for entry in carried {
        if order.revert {
            let Nullable(Some(object_id)) = &entry.base_object_id else {
                // The base never held this path, so putting it back would mean removing the file.
                // This host does not remove a user's file to revert a change: the path is reported
                // and left exactly as it is.
                unresolved.push(entry.path.clone());
                continue;
            };
            let bytes = read_object(service.project().profile(), &repository, object_id)?;
            content.push((entry.path.clone(), bytes, entry.executable));
        } else {
            let bytes = service.objects().get(entry.content_digest)?;
            content.push((entry.path.clone(), bytes, entry.executable));
        }
    }
    let _ = manifest;
    let before = capture_destination(service, order, record)?;
    let now = kr_ipc::now_ms();
    let staged_name = format!("apply-{}", order.action_id);
    service.locked()?.begin_apply(&ApplyRow {
        action_id: order.action_id,
        change_set_id: order.version.change_set_id,
        version: order.version.version,
        workspace_id: order.workspace_id,
        destination: order.destination,
        outcome: None,
        before_version: Some((before.change_set_id, before.version)),
        after_version: None,
        staged_name: Some(staged_name.clone()),
        detail: "the destination was as the request expected and the content is being staged"
            .to_owned(),
        started_at_ms: now,
        decided_at_ms: None,
    })?;
    // Staged and validated: every byte is written into a private directory of this host's own and
    // read back against its digest, so nothing half-written can reach the destination.
    let staging = stage(service, &staged_name, &content)?;
    let mut progress: Vec<PathProgress> = Vec::new();
    let mut changed = Vec::new();
    let mut stopped: Option<(ApplyOutcomeClass, String)> = None;
    for (index, (path, bytes, executable)) in content.iter().enumerate() {
        service.locked()?.plan_path(order.action_id, path)?;
        let expected = order
            .affected
            .iter()
            .find(|affected| affected.path == *path);
        // The recheck, as late as the platform permits: immediately before the rename, and on the
        // object the handle names rather than on a path resolved earlier.
        let before_digest = match read_working_tree(&repository, path)? {
            WorkingRead::Content { bytes, .. } => Some(digest_of(&bytes)),
            WorkingRead::Gone => None,
            WorkingRead::Unsupported(detail) | WorkingRead::Unreadable(detail) => {
                let row = ProgressRow {
                    path: path.clone(),
                    state: PathProgressState::Unresolved,
                    before_digest: None,
                    after_digest: None,
                    detail,
                };
                service.locked()?.settle_path(order.action_id, &row)?;
                progress.push(wire_progress(&row));
                stopped = Some((
                    ApplyOutcomeClass::UncertainOutcome,
                    "this host could not read what one destination path holds".to_owned(),
                ));
                break;
            }
        };
        if let Some(expected) = expected
            && expected.expected_worktree_digest.0 != before_digest
        {
            let row = ProgressRow {
                path: path.clone(),
                state: PathProgressState::Conflicted,
                before_digest,
                after_digest: before_digest,
                detail: "something wrote this path between the preflight and the rename, so this \
                         host did not write it"
                    .to_owned(),
            };
            service.locked()?.settle_path(order.action_id, &row)?;
            progress.push(wire_progress(&row));
            stopped = Some((
                ApplyOutcomeClass::ConflictAfterPartialWrites,
                format!(
                    "an external write reached {} between the recheck and the rename, so this \
                     apply stopped with {} paths already changed",
                    kr_project::git::redact(path),
                    changed.len()
                ),
            ));
            break;
        }
        match install(&repository, &staging, path, bytes, *executable) {
            Ok(after) => {
                let row = ProgressRow {
                    path: path.clone(),
                    state: PathProgressState::Written,
                    before_digest,
                    after_digest: Some(after),
                    detail: "the staged content was renamed over the destination".to_owned(),
                };
                service.locked()?.settle_path(order.action_id, &row)?;
                progress.push(wire_progress(&row));
                changed.push(path.clone());
            }
            Err(error) => {
                let row = ProgressRow {
                    path: path.clone(),
                    state: PathProgressState::Unresolved,
                    before_digest,
                    after_digest: None,
                    detail: error.to_string(),
                };
                service.locked()?.settle_path(order.action_id, &row)?;
                progress.push(wire_progress(&row));
                stopped = Some((
                    ApplyOutcomeClass::UncertainOutcome,
                    "a write failed and this host could not establish what the destination holds"
                        .to_owned(),
                ));
                break;
            }
        }
        #[cfg(feature = "fault-injection")]
        if let Some(fault) = service.fault()
            && index + 1 >= fault.after_paths
        {
            // The apply stops here **without** settling, exactly as a daemon that died would leave
            // it. The row stays undecided and the paths after this one keep no row at all, which
            // is what `recover` reads.
            return Err(ChangeSetError::OutcomeUnknown {
                detail: fault.detail.into(),
            });
        }
        let _ = index;
    }
    // Every path the apply did not reach is recorded as one it did not attempt, so the answer
    // lists exactly what is known rather than leaving a reader to infer it.
    for (path, _, _) in content.iter().skip(progress.len()) {
        let row = ProgressRow {
            path: path.clone(),
            state: PathProgressState::Skipped,
            before_digest: None,
            after_digest: None,
            detail: "the apply stopped before it reached this path".to_owned(),
        };
        service.locked()?.settle_path(order.action_id, &row)?;
        progress.push(wire_progress(&row));
    }
    let after = capture_destination(service, order, record)?;
    let (outcome, detail) = stopped.unwrap_or_else(|| {
        (
            ApplyOutcomeClass::Applied,
            format!(
                "every one of the {} paths this apply planned is in the destination and this host \
                 confirmed each one",
                changed.len()
            ),
        )
    });
    let now = kr_ipc::now_ms();
    service.locked()?.settle_apply(
        order.action_id,
        outcome,
        Some((after.change_set_id, after.version)),
        &detail,
        now,
    )?;
    let unresolved_paths: Vec<String> = unresolved
        .into_iter()
        .chain(
            progress
                .iter()
                .filter(|row| {
                    matches!(
                        row.state,
                        PathProgressState::Planned | PathProgressState::Unresolved
                    )
                })
                .map(|row| row.path.clone()),
        )
        .collect();
    let conflicted: Vec<PathConflict> = progress
        .iter()
        .filter(|row| row.state == PathProgressState::Conflicted)
        .map(|row| PathConflict {
            path: row.path.clone(),
            expected_worktree_digest: order
                .affected
                .iter()
                .find(|affected| affected.path == row.path)
                .map_or(Nullable(None), |affected| affected.expected_worktree_digest),
            observed_worktree_digest: row.before_digest,
            expected_index_object_id: Nullable(None),
            observed_index_object_id: Nullable(None),
            detail: row.detail.clone(),
        })
        .collect();
    Ok(DiffApplyResult {
        action_id: order.action_id,
        outcome: Nullable(Some(outcome)),
        destination: order.destination,
        applied_version: order.version,
        proposal_version: Nullable(None),
        reference: Nullable(None),
        changed_paths: changed,
        unresolved_paths,
        conflicts: conflicted,
        progress,
        recovery: RecoveryObjects {
            before_version: Nullable(Some(VersionRef {
                change_set_id: before.change_set_id,
                version: before.version,
            })),
            after_version: Nullable(Some(VersionRef {
                change_set_id: after.change_set_id,
                version: after.version,
            })),
            applied_version: Nullable(Some(order.version)),
            staged_path: Nullable(Some(staged_name)),
            detail: "the destination as it stood before this apply and as it stands after it, \
                     both immutable and both materialisable; what is not claimed is that every \
                     intermediate version was captured"
                .to_owned(),
        },
        limitations: limitations.to_vec(),
        detail,
        decided_at_ms: now,
    })
}

/// Writes the validated content into a private staging directory of this host's own.
fn stage(
    service: &ChangeSetService,
    name: &str,
    content: &[(String, Vec<u8>, bool)],
) -> Result<AuthorisedDirectory> {
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(STAGING_DIRECTORY)?)?;
    let directory = parent.create_subdirectory(&RelativeName::parse(name)?)?;
    for (path, bytes, _) in content {
        let staged = staged_name(path);
        let name = RelativeName::parse(&staged)?;
        let _ = directory.remove(&name);
        let mut file = directory.create_new(&name)?;
        file.handle_mut()
            .write_all(bytes)
            .map_err(ChangeSetError::storage)?;
        file.handle_mut()
            .sync_all()
            .map_err(ChangeSetError::storage)?;
        // Read back against the digest: content that reached the disk as something else never
        // reaches the destination.
        let mut read = directory.open_read(&name, ObjectPolicy::ReadableFile)?;
        let mut back = Vec::new();
        std::io::Read::read_to_end(read.handle_mut(), &mut back)
            .map_err(ChangeSetError::storage)?;
        if digest_of(&back) != digest_of(bytes) {
            return Err(ChangeSetError::StorageUnavailable {
                detail: "staged content did not read back as what this host wrote, so nothing was \
                         installed"
                    .into(),
            });
        }
    }
    directory.sync()?;
    Ok(directory)
}

/// The single-component name one destination path is staged under.
fn staged_name(path: &str) -> String {
    hex_of(digest_of(path.as_bytes()))
}

/// Renames one staged file over its destination, preserving what the destination had.
///
/// The destination's own permissions are read and put on the staged copy before the rename, so a
/// file that was executable stays executable and one that was not does not become one. The bytes
/// are written exactly as the version holds them, so a line ending is whatever the content is.
/// A rename replaces in one step, so the destination is either what it was or the whole new
/// content, never half of each.
fn install(
    repository: &OpenedRepository,
    staging: &AuthorisedDirectory,
    path: &str,
    bytes: &[u8],
    executable: bool,
) -> Result<Digest256> {
    let name = RelativeName::parse(path)?;
    let components = name.components();
    let (leaf, parents) =
        components
            .split_last()
            .ok_or_else(|| ChangeSetError::StorageUnavailable {
                detail: "a destination path has no name".into(),
            })?;
    let mut here = clone_handle(repository.work_tree())?;
    for component in parents {
        here = here.create_subdirectory(&RelativeName::parse(component)?)?;
    }
    let leaf_name = RelativeName::parse(leaf)?;
    let staged = RelativeName::parse(&staged_name(path))?;
    carry_permissions(staging, &staged, &here, &leaf_name, executable)?;
    // The temporary lands beside the destination so the rename is within one directory and cannot
    // cross a filesystem; a rename replaces the name in one step.
    let temporary = RelativeName::parse(&format!(".kr-apply-{}", staged_name(path)))?;
    let _ = here.remove(&temporary);
    staging.rename_into(&staged, &here, &temporary)?;
    here.rename_into(&temporary, &here, &leaf_name)?;
    here.sync()?;
    Ok(digest_of(bytes))
}

/// Puts the destination's own permissions on the staged copy before it is renamed over it.
#[cfg(unix)]
fn carry_permissions(
    staging: &AuthorisedDirectory,
    staged: &RelativeName,
    destination: &AuthorisedDirectory,
    leaf: &RelativeName,
    executable: bool,
) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;
    let existing = destination
        .open_read(leaf, ObjectPolicy::ReadableFile)
        .ok()
        .and_then(|file| file.handle().metadata().ok())
        .map(|metadata| metadata.permissions().mode());
    let mode = existing.unwrap_or(if executable { 0o755 } else { 0o644 });
    let file = staging.open_read(staged, ObjectPolicy::ReadableFile)?;
    file.handle()
        .set_permissions(cap_std::fs::Permissions::from_mode(mode))
        .map_err(ChangeSetError::storage)
}

/// Does nothing: this platform has no mode bits to carry across.
#[cfg(not(unix))]
fn carry_permissions(
    _staging: &AuthorisedDirectory,
    _staged: &RelativeName,
    _destination: &AuthorisedDirectory,
    _leaf: &RelativeName,
    _executable: bool,
) -> Result<()> {
    Ok(())
}

fn clone_handle(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let handle = directory
        .handle()
        .try_clone()
        .map_err(ChangeSetError::storage)?;
    Ok(AuthorisedDirectory::from_handle(
        directory.environment_id(),
        handle,
        directory.display_path().to_path_buf(),
    )?)
}

/// Captures the destination as it stands, so there is a recoverable version of it.
fn capture_destination(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    record: &ChangeSetVersionRecord,
) -> Result<ChangeSetVersionRecord> {
    let Some(workspace_id) = order.workspace_id else {
        return Err(ChangeSetError::InvalidArgument(
            "this destination names the workspace it writes to".into(),
        ));
    };
    // Everything, because a recoverable "before" that left the user's untracked work out would not
    // be what was there.
    let policy = InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    };
    let grant = FileGrant::default();
    let order = crate::service::CaptureOrder {
        workspace_id,
        change_set_id: Some(record.change_set_id),
        label: &record.label,
        request: crate::capture::CaptureRequest {
            policy: &policy,
            grant: &grant,
            quiescence_declared: false,
            required_consistency: None,
        },
        pin: false,
        provenance: Provenance {
            derivation: "a reading of the destination taken so an apply has something recoverable \
                         on each side of it"
                .to_owned(),
            ..order.provenance.clone()
        },
    };
    let (captured, _) = service.capture(&order)?;
    Ok(captured)
}

/// Overlays one apply's content onto a manifest, without writing anything.
fn overlay(
    proposed: &mut Manifest,
    carried: &[CapturedPath],
    revert: bool,
    service: &ChangeSetService,
    repository: &OpenedRepository,
    _source: &Manifest,
) -> Result<()> {
    for entry in carried {
        let content = if revert {
            let Nullable(Some(object_id)) = &entry.base_object_id else {
                // The base never held it, so reverting means the proposal simply does not hold it.
                proposed.paths.retain(|held| held.path != entry.path);
                continue;
            };
            read_object(service.project().profile(), repository, object_id)?
        } else {
            service.objects().get(entry.content_digest)?
        };
        let digest = service.objects().put(&content)?;
        let replacement = CapturedPath {
            path: entry.path.clone(),
            content_digest: digest,
            byte_len: U64::new(content.len() as u64),
            executable: entry.executable,
            content: crate::capture::classify_content(&content),
            origin: ContentOrigin::WorkingTree,
            class: entry.class,
            change: ChangeKind::Present,
            base_object_id: entry.base_object_id.clone(),
        };
        match proposed
            .paths
            .iter_mut()
            .find(|held| held.path == entry.path)
        {
            Some(held) => *held = replacement,
            None => proposed.paths.push(replacement),
        }
    }
    Ok(())
}

fn wire_progress(row: &ProgressRow) -> PathProgress {
    PathProgress {
        path: row.path.clone(),
        state: row.state,
        before_digest: Nullable(row.before_digest),
        after_digest: Nullable(row.after_digest),
        detail: row.detail.clone(),
    }
}

fn conflict_error(found: &[PathConflict]) -> ChangeSetError {
    let named: Vec<String> = found
        .iter()
        .take(16)
        .map(|conflict| kr_project::git::redact(&conflict.path))
        .collect();
    ChangeSetError::DraftConflict {
        detail: format!(
            "the destination is not what this request expects at {} path(s), and nothing was \
             written: {}",
            found.len(),
            named.join(", ")
        )
        .into(),
    }
}

/// The answer a preflight that found nothing gives.
///
/// Its outcome is absent, because the five outcome classes describe an apply that ran and this one
/// did not. What it carries is the limitations of the class the caller is about to choose, which
/// is how a caller is shown them before it chooses.
fn clean_preflight(order: &ApplyOrder<'_>, limitations: &[String]) -> DiffApplyResult {
    DiffApplyResult {
        action_id: order.action_id,
        outcome: Nullable(None),
        destination: order.destination,
        applied_version: order.version,
        proposal_version: Nullable(None),
        reference: Nullable(None),
        changed_paths: Vec::new(),
        unresolved_paths: Vec::new(),
        conflicts: Vec::new(),
        progress: Vec::new(),
        recovery: RecoveryObjects {
            before_version: Nullable(None),
            after_version: Nullable(None),
            applied_version: Nullable(Some(order.version)),
            staged_path: Nullable(None),
            detail: "a preflight writes nothing, so there is nothing to recover from".to_owned(),
        },
        limitations: limitations.to_vec(),
        detail: "the destination holds what this request expects; nothing was written, because \
                 this was a preflight"
            .to_owned(),
        decided_at_ms: kr_ipc::now_ms(),
    }
}

/// Settles every apply an earlier daemon left undecided.
///
/// An apply with no outcome is one this host did not finish. It is settled as
/// [`ApplyOutcomeClass::InterruptedApply`] from the progress rows: a path the journal says was
/// written is a path this host confirmed, and a path still `planned` is one whose state this host
/// did not establish. Neither is turned into a success.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the journal cannot be read or written.
pub fn recover(service: &ChangeSetService) -> Result<crate::service::Recovery> {
    let mut recovery = crate::service::Recovery::default();
    let undecided = service.locked()?.undecided_applies()?;
    for row in undecided {
        let progress = service.locked()?.progress(row.action_id)?;
        let written = progress
            .iter()
            .filter(|entry| entry.state == PathProgressState::Written)
            .count();
        let unresolved = progress
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    PathProgressState::Planned | PathProgressState::Unresolved
                )
            })
            .count();
        service.locked()?.settle_apply(
            row.action_id,
            ApplyOutcomeClass::InterruptedApply,
            None,
            &format!(
                "this apply was interrupted: {written} path(s) are in the destination and this \
                 host confirmed each of them, and {unresolved} path(s) are ones it did not \
                 establish an outcome for, which is not the same as ones it did not write"
            ),
            kr_ipc::now_ms(),
        )?;
        recovery.applies_settled += 1;
    }
    Ok(recovery)
}

/// Returns what one apply came to, as the journal holds it.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownVersion`] when there is no such apply.
pub fn read_apply(service: &ChangeSetService, action_id: ActionId) -> Result<DiffApplyResult> {
    let store = service.locked()?;
    let row = store
        .apply(action_id)?
        .ok_or_else(|| ChangeSetError::UnknownVersion {
            detail: format!("no apply under action {action_id}").into(),
        })?;
    let progress = store.progress(action_id)?;
    drop(store);
    let changed: Vec<String> = progress
        .iter()
        .filter(|entry| entry.state == PathProgressState::Written)
        .map(|entry| entry.path.clone())
        .collect();
    let unresolved: Vec<String> = progress
        .iter()
        .filter(|entry| {
            matches!(
                entry.state,
                PathProgressState::Planned | PathProgressState::Unresolved
            )
        })
        .map(|entry| entry.path.clone())
        .collect();
    Ok(DiffApplyResult {
        action_id,
        outcome: Nullable(row.outcome),
        destination: row.destination,
        applied_version: VersionRef {
            change_set_id: row.change_set_id,
            version: row.version,
        },
        proposal_version: Nullable(None),
        reference: Nullable(None),
        changed_paths: changed,
        unresolved_paths: unresolved,
        conflicts: Vec::new(),
        progress: progress.iter().map(wire_progress).collect(),
        recovery: RecoveryObjects {
            before_version: Nullable(row.before_version.map(|(change_set_id, version)| {
                VersionRef {
                    change_set_id,
                    version,
                }
            })),
            after_version: Nullable(
                row.after_version
                    .map(|(change_set_id, version)| VersionRef {
                        change_set_id,
                        version,
                    }),
            ),
            applied_version: Nullable(Some(VersionRef {
                change_set_id: row.change_set_id,
                version: row.version,
            })),
            staged_path: Nullable(row.staged_name),
            detail: "what this host recorded on each side of the apply".to_owned(),
        },
        limitations: limitations(row.destination),
        detail: row.detail,
        decided_at_ms: row.decided_at_ms.unwrap_or(row.started_at_ms),
    })
}

/// The policy a version is captured under when the capture is of a whole destination.
///
/// Exposed so a caller that wants the same reading a recovery object is taken under can ask for
/// it, rather than guessing which classes a "before" version holds.
#[must_use]
pub fn destination_policy() -> (InclusionPolicy, CapturePolicy) {
    let inclusion = InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    };
    (
        inclusion,
        CapturePolicy {
            inclusion,
            grant: FileGrant {
                included_paths: Vec::new(),
                excluded_paths: Vec::new(),
                secret_rules_applied: true,
            },
            quiescence_declared: false,
            required_consistency: Nullable(None),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_apply_states_what_it_cannot_promise() {
        // Section 14: show this limitation before choosing direct apply. It is returned by
        // `limitations`, carried in every result, and required back in the request.
        let stated = limitations(DestinationClass::SharedExisting);
        assert_eq!(stated.len(), 3);
        assert!(
            stated[0].contains("best-effort conflict detection"),
            "the first limitation names what it is: {}",
            stated[0]
        );
        assert!(
            stated
                .iter()
                .any(|line| line.contains("does not protect it from an external write")),
            "an atomic rename alone is not the guarantee"
        );
        assert!(
            stated
                .iter()
                .any(|line| line.contains("every intermediate version")),
            "this host does not claim to have captured every intermediate version"
        );
    }

    #[test]
    fn a_versioned_reference_says_it_does_not_update_a_dirty_worktree() {
        let stated = limitations(DestinationClass::VersionedReference);
        assert!(
            stated.iter().any(|line| line
                .contains("does not \natomically update a dirty working tree")
                || line.contains("does not atomically update a dirty working tree")),
            "the compare-and-swap limitation is stated: {stated:?}"
        );
        assert!(
            stated
                .iter()
                .any(|line| line.contains("runs no \nsubcommand that writes one")
                    || line.contains("runs no subcommand that writes one")),
            "what this host does not do is stated: {stated:?}"
        );
    }

    #[test]
    fn a_proposal_writes_to_no_working_tree_and_says_so() {
        let stated = limitations(DestinationClass::Proposal);
        assert_eq!(stated.len(), 1);
        assert!(stated[0].contains("writes to no working tree"));
    }

    #[test]
    fn a_staged_name_is_one_component_whatever_the_path_is() {
        // A destination path can hold separators, and the staging area is flat, so the staged name
        // is a digest of the path rather than the path.
        for path in ["a.txt", "src/deep/nested/file.rs", "with space.txt"] {
            let name = staged_name(path);
            assert!(RelativeName::parse(&name).is_ok(), "{name} is a valid name");
            assert!(!name.contains('/'), "{name} is one component");
        }
        assert_ne!(staged_name("a/b"), staged_name("a_b"));
    }

    #[test]
    fn a_reference_name_that_could_be_read_as_an_option_is_refused() {
        // The name reaches an argument vector, so it is checked rather than trusted.
        for name in ["--upload-pack=sh", "-c", "refs/heads/a b", "refs/heads/a;b"] {
            assert!(
                name.is_empty()
                    || name.starts_with('-')
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte)),
                "{name} is refused"
            );
        }
        for name in ["refs/heads/main", "refs/tags/v1.0.0", "refs/heads/a-b_c"] {
            assert!(
                !name.starts_with('-')
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte)),
                "{name} is accepted"
            );
        }
    }

    #[test]
    fn a_conflict_is_found_when_either_side_differs() {
        let path = "README.md".to_owned();
        let here = digest_of(b"what is there");
        let expected = digest_of(b"what the request expects");
        let affected = vec![AffectedVersion {
            path: path.clone(),
            expected_worktree_digest: Nullable(Some(expected)),
            expected_index_object_id: Nullable(Some("abcdef".to_owned())),
        }];
        let mut observed = BTreeMap::new();
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(here),
                index_object_id: Some("abcdef".to_owned()),
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // The working tree agrees and the index does not.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("123456".to_owned()),
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // Both agree.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("abcdef".to_owned()),
            },
        );
        assert!(conflicts(&affected, &observed).is_empty());
        // The request expects the path to be absent and it is there.
        let absent = vec![AffectedVersion {
            path: path.clone(),
            expected_worktree_digest: Nullable(None),
            expected_index_object_id: Nullable(None),
        }];
        assert_eq!(conflicts(&absent, &observed).len(), 1);
    }

    #[test]
    fn a_preflight_that_found_nothing_has_no_outcome_class() {
        // The five classes describe an apply that ran. A preflight did not, so it says so by
        // carrying no class rather than by borrowing one.
        let provenance = Provenance {
            actor_id: kr_protocol::ids::ActorId::new("test").expect("an actor"),
            method: "diff.apply".to_owned(),
            session_id: Nullable(None),
            workflow_run_id: Nullable(None),
            derived_from: Nullable(None),
            derivation: String::new(),
            note: String::new(),
        };
        let order = ApplyOrder {
            action_id: ActionId::new(kr_ipc::new_uuid()),
            version: VersionRef {
                change_set_id: kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid()),
                version: kr_protocol::ids::ChangeSetVersion::new(1),
            },
            destination: DestinationClass::SharedExisting,
            workspace_id: None,
            expected_reference: None,
            affected: &[],
            paths: &[],
            preflight_only: true,
            acknowledged_limitations: &[],
            revert: false,
            provenance,
        };
        let result = clean_preflight(&order, &limitations(DestinationClass::SharedExisting));
        assert_eq!(result.outcome, Nullable(None));
        assert!(result.changed_paths.is_empty());
        assert!(result.recovery.before_version.0.is_none());
        assert_eq!(result.limitations.len(), 3);
    }
}
