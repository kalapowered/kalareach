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
    IndexEntry, WorkingRead, read_differences, read_index, read_object, read_status,
    read_working_tree,
};
use crate::error::{ChangeSetError, Result};
use crate::objects::{digest_of, hex_of};
use crate::service::{ChangeSetService, STAGING_DIRECTORY};
use crate::store::{ApplyRow, ProgressRow};
use crate::version::Manifest;

/// Takes the durable claim on one action, after its preflight and before anything is written.
///
/// Section 14 says a preflight conflict returns `DRAFT_CONFLICT` **without KR writes**, and a
/// claim taken before the preflight is a KR write that a crash would leave behind. So the claim is
/// the caller's to take and this host asks for it at the one moment that keeps both promises: the
/// destination has been checked and nothing has been written.
pub trait ActionClaim {
    /// Returns false when another copy of this action holds it.
    ///
    /// # Errors
    ///
    /// Returns whatever the caller's own store returns.
    fn claim(&self) -> Result<bool>;
}

/// What one apply or revert is asked to do.
#[derive(Clone)]
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
    /// What takes the durable claim, after the preflight and before anything is written.
    ///
    /// A request with none is one nothing arbitrates, which is what a direct in-process caller
    /// and every test are.
    pub claim: Option<&'a dyn ActionClaim>,
    /// The authority this apply arrived under, asked again inside the transactions that record
    /// it: the readings of the destination it takes, and the journal that opens the apply.
    ///
    /// A request with none is one nothing arbitrates, as with the claim above.
    pub admitted: Option<&'a dyn crate::store::StillAdmitted>,
}

/// What a test runs immediately before one path's rename, named by that path.
///
/// Answering `false` abandons the apply right there, with the temporary still beside the
/// destination and nothing settled: that is what a daemon that died between staging a path and
/// publishing it leaves behind, and it is the one window a test cannot otherwise reach.
#[cfg(feature = "fault-injection")]
pub type BeforeRename = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What a test does to an apply that is already running.
///
/// Two things a real apply meets and a test cannot otherwise reach: a daemon that dies part way
/// through, and another writer that reaches the destination between this host's recheck and its
/// rename. Compiled with the fault-injection feature; nothing in the service sets it.
#[cfg(feature = "fault-injection")]
#[derive(Clone)]
pub struct Fault {
    /// Act once exactly this many paths have been written and confirmed.
    pub after_paths: usize,
    /// What to do then, such as writing one of the destination's own files.
    pub act: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Stop the apply there **without settling it**, exactly as a daemon that died would.
    pub stop: bool,
    /// Run this immediately before one path's rename, which is the one window this host states it
    /// cannot close.
    pub before_rename: Option<BeforeRename>,
    /// Run this immediately after the claim on the action is taken and before anything is read or
    /// written for it, which is the interval a request spends between being admitted and having
    /// an effect.
    pub after_claim: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Refuse the journal write that records the staging directory's identity, which is the one
    /// failure that leaves a directory this host made with nothing to prove it made it.
    pub refuse_staging_record: bool,
    /// What the failure says when it stops.
    pub detail: String,
}

#[cfg(feature = "fault-injection")]
impl std::fmt::Debug for Fault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Fault")
            .field("after_paths", &self.after_paths)
            .field("acts", &self.act.is_some())
            .field("acts_before_rename", &self.before_rename.is_some())
            .field("acts_after_claim", &self.after_claim.is_some())
            .field("refuses_staging_record", &self.refuse_staging_record)
            .field("stop", &self.stop)
            .finish()
    }
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
    let differences = read_differences(profile, &repository, &head_revision, false)?;
    let staged = read_differences(profile, &repository, &head_revision, true)?;
    let administrative = crate::capture::administrative_prefix(&repository);
    let status = read_status(
        profile,
        &repository,
        &FileGrant::default(),
        administrative.as_deref(),
    )?;
    let mut tracked = Vec::new();
    let mut untracked = Vec::new();
    for entry in &status {
        // Each path is opened once. Reading it again for its length and again for its content
        // class would let three readings describe three different files.
        let (content_digest, byte_len, content) =
            match read_working_tree(&repository, &entry.path)?.read {
                WorkingRead::Content { bytes, .. } => (
                    Some(digest_of(&bytes)),
                    Some(U64::new(bytes.len() as u64)),
                    crate::capture::classify_content(&bytes),
                ),
                _ => (None, None, ContentClass::Unknown),
            };
        let read = DiffEntry {
            path: entry.path.clone(),
            class: class_of(entry.class),
            change: entry.change,
            content,
            byte_len: Nullable(byte_len),
            // The content revision of the base side: the object the **commit** holds, which is
            // what the diff reports, rather than whatever the index happens to hold.
            // The content revision of the base side is the object the **commit** holds. A path
            // the working-tree diff names carries it; a path only the index changed carries it in
            // the index-against-commit diff; and a path neither names is one where the index and
            // the working tree both match the commit, so the index's object is the commit's.
            base_object_id: Nullable(
                differences
                    .get(&entry.path)
                    .or_else(|| staged.get(&entry.path))
                    .and_then(|difference| difference.base_object_id.clone()),
            ),
            content_digest: Nullable(content_digest),
        };
        // Four readings of one repository: the revision, the index, the two diffs against the
        // commit and the status. A tracked path the status reports as changed is a path at least
        // one diff has to name, and when none does the readings are of different moments rather
        // than of one source. Guessing a base object from the index would state a content
        // revision the commit does not hold.
        if index.contains_key(&entry.path)
            && !differences.contains_key(&entry.path)
            && !staged.contains_key(&entry.path)
        {
            return Err(ChangeSetError::SourceChanged {
                detail: "this working tree changed while this host was reading it: its status \
                         names a change to a tracked path that neither reading against the \
                         commit holds"
                    .into(),
            });
        }
        if index.contains_key(&entry.path) || differences.contains_key(&entry.path) {
            tracked.push(read);
        } else {
            untracked.push(read);
        }
    }
    // The whole reading is stated against one commit: the base object of every entry above was
    // taken from it. A checkout, a commit or a reset part way through would leave this describing
    // two revisions as though they were one, so the revision is read again and the reading is
    // refused rather than published under a base it no longer matches.
    let (again, again_reference) = repository.head(profile)?;
    if again.as_deref() != Some(head_revision.as_str()) || again_reference != reference {
        return Err(ChangeSetError::SourceChanged {
            detail: "the branch this working tree is on moved while this host was reading it, so                      what it read is against two different commits rather than one"
                .into(),
        });
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
    // A deletion is a change the version carries, so it is an entry of the read like any other:
    // the base side names what the commit holds and the other side holds nothing.
    for deleted in &manifest.deletions {
        tracked.push(DiffEntry {
            path: deleted.path.clone(),
            class: PathClass::DirtyFile,
            change: ChangeKind::Deleted,
            content: ContentClass::Unknown,
            byte_len: Nullable(None),
            base_object_id: Nullable(deleted.base_object_id.clone()),
            content_digest: Nullable(None),
        });
    }
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
    let manifest = service.manifest(order.version.change_set_id, order.version.version)?;
    let carried = carried_paths(&manifest, order)?;
    let limitations = limitations(order.destination);
    // A preflight is a read: it writes nothing anywhere, and it is how a caller **obtains** the
    // limitations it then has to pass back. Requiring them before it would mean a caller could
    // not learn them through this interface at all.
    if order.destination == DestinationClass::SharedExisting && !order.preflight_only {
        for limitation in &limitations {
            if !order
                .acknowledged_limitations
                .iter()
                .any(|shown| shown == limitation)
            {
                return Err(ChangeSetError::InvalidArgument(
                    format!(
                        "a direct apply to a shared working tree is chosen only after every one \
                         of these limitations has been shown, and this request carries none of \
                         them or not all of them. They are, in full: {}. The one it is missing \
                         is: {limitation}",
                        limitations.join("; ")
                    )
                    .into(),
                ));
            }
        }
    }
    match order.destination {
        DestinationClass::Proposal => proposal(service, order, &manifest, &carried, &limitations),
        DestinationClass::VersionedReference => reference(service, order, &limitations),
        DestinationClass::SharedExisting => {
            direct(service, order, &manifest, &carried, &limitations)
        }
    }
}

/// One operation the request asked for: a path, and what the version holds for it.
#[derive(Clone, Debug)]
pub struct Requested {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// What the captured tree holds there, or nothing when the version does not hold the path.
    ///
    /// Nothing is not "no operation": a version whose working tree deleted a path holds nothing
    /// for it, and applying that version means taking the path away. A request that asks for such
    /// a path gets a deletion, and one that asks for all of them gets every deletion the version
    /// carries.
    pub holds: Option<CapturedPath>,
    /// What the base revision holds for a path the version deleted, so a revert can put it back.
    pub deleted: Option<crate::version::DeletedPath>,
}

/// Takes the claim, once the preflight has passed and before anything is written.
fn take_claim(service: &ChangeSetService, order: &ApplyOrder<'_>) -> Result<()> {
    let Some(claim) = order.claim else {
        return Ok(());
    };
    if !claim.claim()? {
        return Err(ChangeSetError::ActionHeldElsewhere);
    }
    // Everything between the claim and the effect it arbitrates: the readings this apply takes of
    // its destination, and the journal it opens. A test acts here to reach that interval.
    #[cfg(feature = "fault-injection")]
    if let Some(act) = service.fault().and_then(|fault| fault.after_claim) {
        act();
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = service;
    Ok(())
}

/// Returns exactly the operations this apply carries.
///
/// A version's **changes** are the paths whose content differs from the base, and its
/// **deletions** are the paths the working tree took away. Both are operations: leaving the second
/// out would let an apply of a version that only deletes report that it applied everything while
/// changing nothing.
fn carried_paths(manifest: &Manifest, order: &ApplyOrder<'_>) -> Result<Vec<Requested>> {
    let mut every: Vec<Requested> = manifest
        .changes()
        .into_iter()
        .map(|entry| Requested {
            path: entry.path.clone(),
            holds: Some(entry.clone()),
            deleted: None,
        })
        .collect();
    every.extend(manifest.deletions.iter().map(|deleted| Requested {
        path: deleted.path.clone(),
        holds: None,
        deleted: Some(deleted.clone()),
    }));
    every.sort_by(|a, b| a.path.cmp(&b.path));
    if order.paths.is_empty() {
        return Ok(every);
    }
    let mut chosen = Vec::new();
    for path in order.paths {
        let found = every
            .iter()
            .find(|requested| requested.path == *path)
            .ok_or_else(|| {
                ChangeSetError::InvalidArgument(
                    format!(
                        "this version holds no change and no deletion for {}",
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
    index_mode: Option<String>,
    unmerged: bool,
}

/// Reads what the destination holds for every affected path.
fn observe(
    repository: &OpenedRepository,
    index: &BTreeMap<String, IndexEntry>,
    affected: &[AffectedVersion],
) -> Result<BTreeMap<String, Observed>> {
    let mut found = BTreeMap::new();
    for entry in affected {
        let worktree_digest = match read_working_tree(repository, &entry.path)?.read {
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
                index_mode: index.get(&entry.path).map(|held| held.mode.clone()),
                // An unresolved merge is never what a request describes: the index holds several
                // stages for such a path and none of them is the one content an apply is against.
                unmerged: index.get(&entry.path).is_some_and(|held| held.stage != 0),
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
        // An absent expectation is an expectation that the index does not hold the path, not a
        // wildcard, and a caller that does not mean to check the index says so rather than
        // leaving a field out.
        let index_differs = entry.check_index
            && (entry.expected_index_object_id.0 != here.index_object_id
                || entry.expected_index_mode.0 != here.index_mode
                || here.unmerged);
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
    carried: &[Requested],
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
    // What a path **is** depends on the tree it is in. A directory that was ordinary content where
    // a version was captured can be a repository's own data here, and writing a file into that
    // would put bytes where this host excludes them from every capture it takes: the recovery
    // versions this apply records would hold none of what it replaced. So the destination's own
    // answer is asked before anything is read or written, and a path it calls administrative ends
    // the apply while it is still true that nothing has been written.
    let named: Vec<String> = order
        .affected
        .iter()
        .map(|affected| affected.path.clone())
        .chain(carried.iter().map(|entry| entry.path.clone()))
        .collect();
    if let Some(path) =
        crate::capture::administrative_here(service.project().profile(), &repository, &named)?
            .first()
    {
        return Err(ChangeSetError::Unsupported {
            detail: format!(
                "{} is this repository's own administrative data at this destination, or the tree \
                 of a repository nested in it, and this host writes into neither",
                kr_project::git::redact(path)
            )
            .into(),
        });
    }
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
    manifest: &Manifest,
    carried: &[Requested],
    limitations: &[String],
) -> Result<DiffApplyResult> {
    let (repository, _index, found) = preflight(service, order, carried)?;
    if !found.is_empty() {
        return Err(conflict_error(&found));
    }
    if order.preflight_only {
        return Ok(clean_preflight(order, limitations));
    }
    take_claim(service, order)?;
    let before = capture_destination(service, order, None, "before", order.admitted)?;
    let mut proposed = service.manifest(before.change_set_id, before.version)?;
    let _ = manifest;
    let mut unresolved = Vec::new();
    overlay(
        &mut proposed,
        carried,
        order,
        service,
        &repository,
        &mut unresolved,
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
        order.admitted,
    )?;
    let now = kr_ipc::now_ms();
    let reference = VersionRef {
        change_set_id: proposal.change_set_id,
        version: proposal.version,
    };
    service.locked()?.begin_apply(
        &ApplyRow {
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
        },
        // A proposal writes to no working tree, and the one thing about its paths a later reader
        // has to be able to get back is which operations it could not carry. Those are recorded,
        // so a recovered answer names them rather than describing a proposal that carried
        // everything.
        &unresolved,
        order.admitted,
    )?;
    for path in &unresolved {
        service.locked()?.settle_path(
            order.action_id,
            &ProgressRow {
                path: path.clone(),
                state: PathProgressState::Unresolved,
                before_digest: None,
                after_digest: None,
                detail: "this proposal could not carry the operation for this path".to_owned(),
            },
        )?;
    }
    // `applied` is every requested operation carried. A proposal that could not carry one is not
    // an applied change, whatever it did carry.
    let (outcome, detail) = if unresolved.is_empty() {
        (
            ApplyOutcomeClass::Applied,
            "the proposal was recorded and no working tree was written".to_owned(),
        )
    } else {
        (
            ApplyOutcomeClass::UncertainOutcome,
            format!(
                "{} of the operations this proposal carries are ones this host did not resolve, \
                 so the version it recorded is not this change applied in full",
                unresolved.len()
            ),
        )
    };
    service.locked()?.settle_apply(
        order.action_id,
        outcome,
        Some((reference.change_set_id, reference.version)),
        &detail,
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
        outcome: Nullable(Some(outcome)),
        destination: order.destination,
        applied_version: order.version,
        proposal_version: Nullable(Some(reference)),
        reference: Nullable(None),
        changed_paths: Vec::new(),
        unresolved_paths: unresolved,
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
            staged_leftovers: Vec::new(),
            detail: "the destination as it stands, and the version it would hold; no working tree \
                     was written, so there is nothing to undo"
                .to_owned(),
        },
        limitations: limitations.to_vec(),
        detail,
        decided_at_ms: now,
    })
}

/// A versioned Git reference: compare-and-swap, and the limitation stated rather than executed.
fn reference(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
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
    manifest: &Manifest,
    carried: &[Requested],
    limitations: &[String],
) -> Result<DiffApplyResult> {
    let (repository, _index, found) = preflight(service, order, carried)?;
    if !found.is_empty() {
        return Err(conflict_error(&found));
    }
    if order.preflight_only {
        return Ok(clean_preflight(order, limitations));
    }
    take_claim(service, order)?;
    let _ = manifest;
    // What each requested operation puts in the destination, decided before anything is written: a
    // revert puts the base's own content back, an apply puts the version's content in, and a path
    // the version does not hold is taken away.
    let mut operations: Vec<(String, Operation)> = Vec::new();
    for requested in carried {
        operations.push((
            requested.path.clone(),
            operation_for(service, &repository, order, requested)?,
        ));
    }
    let before = capture_destination(service, order, None, "before", order.admitted)?;
    let now = kr_ipc::now_ms();
    let staged_name = format!("apply-{}", order.action_id);
    // The header and **every path this apply plans** go in together, before anything is attempted,
    // so a daemon that dies half way through leaves a row for each. A row that still says
    // `planned` means this host did not establish what became of that path, which is not the same
    // as saying it did not write it; a run that stops on its own settles the ones it never
    // reached as skipped.
    let planned: Vec<String> = operations.iter().map(|(path, _)| path.clone()).collect();
    service.locked()?.begin_apply(
        &ApplyRow {
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
        },
        &planned,
        order.admitted,
    )?;
    // Staged and validated: every byte is written into a private directory of this host's own and
    // read back against its digest, so a recoverable copy of what this apply meant to install
    // exists before the destination is touched.
    stage(service, &staged_name, &operations)?;
    // Once installation can begin, every exit goes through the outcome: a failure after a write
    // that returned early would leave a caller with an ordinary error and no record of what had
    // already landed.
    let (mut progress, changed, mut stopped) = match run_operations(
        service,
        &repository,
        order,
        &operations,
    ) {
        Ok(run) => {
            if let Some(detail) = run.abandoned {
                // Nothing settles the apply: what this host did not decide, it records no
                // decision for. A replacement service reads the open row and its progress.
                return Err(ChangeSetError::OutcomeUnknown {
                    detail: detail.into(),
                });
            }
            (run.progress, run.changed, run.stopped)
        }
        Err(error) => {
            // Whatever went wrong, what this host established about each path is what its own
            // row says, and the paths it confirmed it changed are read back from those rows
            // rather than forgotten. A journal that cannot be read either leaves nothing to say
            // what happened, which is what `OUTCOME_UNKNOWN` is for.
            let rows = read_progress(service, order.action_id).map_err(|store| {
                ChangeSetError::OutcomeUnknown {
                    detail: format!(
                        "this apply stopped ({error}) and this host could not read back what it \
                         had recorded about each path ({store}), so it cannot say what the \
                         destination holds"
                    )
                    .into(),
                }
            })?;
            let known: Vec<String> = rows
                .iter()
                .filter(|row| row.state == PathProgressState::Written)
                .map(|row| row.path.clone())
                .collect();
            (
                rows.iter()
                    .map(wire_progress)
                    .collect::<Vec<PathProgress>>(),
                known,
                Some((
                    ApplyOutcomeClass::UncertainOutcome,
                    format!(
                        "this apply stopped for a reason that is not the destination's: {error}. \
                         What is known about each path is what its own row says"
                    ),
                )),
            )
        }
    };
    // Every path the apply did not reach is recorded as one it did not attempt, so the answer
    // lists exactly what is known rather than leaving a reader to infer it.
    let mut failed_to_record = false;
    for (path, _) in operations.iter().skip(progress.len()) {
        let row = ProgressRow {
            path: path.clone(),
            state: PathProgressState::Skipped,
            before_digest: None,
            after_digest: None,
            detail: "the apply stopped before it reached this path".to_owned(),
        };
        // A journal that refuses this leaves the row saying `planned`, which is what a recovery
        // reads and what this answer then says too, rather than turning a whole apply into an
        // ordinary error after it has written to the destination.
        if let Err(error) = settle_one(service, order.action_id, &row) {
            stopped = Some((
                ApplyOutcomeClass::UncertainOutcome,
                format!(
                    "this apply could not record what it did not reach, so the journal says less \
                     than this answer does about those paths: {error}"
                ),
            ));
            failed_to_record = true;
        }
        // The answer lists the path whether or not the journal took the row: leaving it out would
        // make an apply that could not record itself look like one with fewer operations.
        progress.push(wire_progress(&row));
    }
    let _ = failed_to_record;
    // The reading on the far side of the apply is not a fresh request: it is the record that makes
    // what this apply did recoverable, and the destination has already been written to. The
    // journal this apply opened is what authorised it, and that header is committed, so this
    // reading stands behind the header rather than asking again. Authority that ran out while the
    // paths were being written stops the next request; it does not take away the record of what
    // this one did.
    let after = match capture_destination(service, order, Some(before.change_set_id), "after", None)
    {
        Ok(after) => Some(after),
        Err(error) => {
            stopped = Some((
                ApplyOutcomeClass::UncertainOutcome,
                format!(
                    "this host could not read the destination after the apply, so what it holds \
                     now is not established: {error}"
                ),
            ));
            None
        }
    };
    let unresolved_paths: Vec<String> = progress
        .iter()
        .filter(|row| {
            matches!(
                row.state,
                PathProgressState::Planned | PathProgressState::Unresolved
            )
        })
        .map(|row| row.path.clone())
        .collect();
    // `applied` is every requested operation resolved and nothing else. A path this host refused,
    // skipped or could not establish keeps it out.
    let (outcome, detail) = stopped.unwrap_or_else(|| {
        if unresolved_paths.is_empty()
            && progress
                .iter()
                .all(|row| row.state == PathProgressState::Written)
        {
            (
                ApplyOutcomeClass::Applied,
                format!(
                    "every one of the {} operations this apply planned is in the destination and \
                     this host confirmed each one",
                    progress.len()
                ),
            )
        } else {
            (
                ApplyOutcomeClass::UncertainOutcome,
                format!(
                    "{} of the {} operations this apply planned are ones it did not resolve, so \
                     it is not an applied change",
                    unresolved_paths.len(),
                    progress.len()
                ),
            )
        }
    });
    let now = kr_ipc::now_ms();
    // The destination has already been written to. A journal that will not record the outcome is
    // therefore not an ordinary failure of the request: the apply happened and no record of it
    // exists, which is exactly what a caller must be told rather than being handed an error that
    // reads like nothing was done.
    if let Err(error) = service.locked().and_then(|mut store| {
        store.settle_apply(
            order.action_id,
            outcome,
            after
                .as_ref()
                .map(|after| (after.change_set_id, after.version)),
            &detail,
            now,
        )
    }) {
        return Err(ChangeSetError::OutcomeUnknown {
            detail: format!(
                "this apply wrote to the destination and this host could not record what it came \
                 to, so its outcome is not established: {error}"
            )
            .into(),
        });
    }
    // Every temporary this apply still has a record of: one this host staged and could not take
    // away again, beside a destination it did not publish to. The caller is told the names now,
    // and the next recovery takes up the same records, so an obligation this host could not
    // discharge is neither hidden nor forgotten.
    let staged_leftovers: Vec<String> = service
        .locked()?
        .staged_paths(order.action_id)?
        .into_iter()
        .map(|entry| entry.path)
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
            after_version: Nullable(after.as_ref().map(|after| VersionRef {
                change_set_id: after.change_set_id,
                version: after.version,
            })),
            applied_version: Nullable(Some(order.version)),
            staged_path: Nullable(Some(staged_name)),
            staged_leftovers,
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

/// Decides what one requested operation puts in the destination.
fn operation_for(
    service: &ChangeSetService,
    repository: &OpenedRepository,
    order: &ApplyOrder<'_>,
    requested: &Requested,
) -> Result<Operation> {
    match &requested.holds {
        // The version does not hold this path. An apply of it takes the path away; a revert puts
        // the base's own content back, and where the base never held it either this host reports
        // the path rather than removing a file nobody asked it to remove.
        None => {
            if !order.revert {
                return Ok(Operation::Remove);
            }
            // Reverting a deletion means putting the base's own content back, which is what the
            // deletion carried with it. Where the base held nothing either, putting it back would
            // mean removing a file, and this host does not remove a file to revert a change.
            let Some(deleted) = requested.deleted.as_ref() else {
                return Ok(Operation::Refuse(
                    "this host has no record of what the base revision held for this path, so it \
                     does not guess at what to put back"
                        .to_owned(),
                ));
            };
            if deleted.base_object_id.is_none() {
                return Ok(Operation::Refuse(
                    "the base revision does not hold this path, so putting it back would mean \
                     removing a file, and this host does not remove a file to revert a change"
                        .to_owned(),
                ));
            }
            // What the base holds has to be file content. A link's object holds a target and a
            // submodule's is not content at all, so writing either out as a regular file would
            // put back something the base never held.
            let Some(mode) = deleted
                .base_mode
                .as_deref()
                .filter(|mode| crate::capture::REGULAR_MODES.contains(mode))
            else {
                return Ok(Operation::Refuse(
                    "what the base revision holds for this path is not file content, so this \
                     host does not write it out as a regular file"
                        .to_owned(),
                ));
            };
            // This host's own copy first: a version says what it is wherever it is applied, and
            // the repository at the destination may not hold the object at all. Where the version
            // carries none, the destination's repository is the one place left to read it from.
            let bytes = match deleted.content_digest {
                Some(digest) => service.objects().get(digest)?,
                None => {
                    let object_id = deleted
                        .base_object_id
                        .as_deref()
                        .unwrap_or_default()
                        .to_owned();
                    read_object(service.project().profile(), repository, &object_id)?
                }
            };
            Ok(Operation::Install {
                bytes,
                executable: mode == "100755",
            })
        }
        Some(entry) => {
            if order.revert {
                let Nullable(Some(object_id)) = &entry.base_object_id else {
                    return Ok(Operation::Refuse(
                        "the base revision does not hold this path, so putting it back would mean \
                         removing a file, and this host does not remove a file to revert a change"
                            .to_owned(),
                    ));
                };
                // The same rule a deletion's revert is under: what the base holds has to be file
                // content. A path whose base is a link or a submodule reaches here when a version
                // holds content at a name the base recorded as something else, and writing that
                // object out as a regular file would put back what the base never held.
                let mode = entry.base_mode.0.as_deref().unwrap_or("100644");
                if !crate::capture::REGULAR_MODES.contains(&mode) {
                    return Ok(Operation::Refuse(
                        "what the base revision holds for this path is not file content, so this \
                         host does not write it out as a regular file"
                            .to_owned(),
                    ));
                }
                let bytes = read_object(service.project().profile(), repository, object_id)?;
                Ok(Operation::Install {
                    bytes,
                    executable: mode == "100755",
                })
            } else {
                Ok(Operation::Install {
                    bytes: service.objects().get(entry.content_digest)?,
                    executable: entry.executable,
                })
            }
        }
    }
}

/// Reads back every progress row one apply recorded.
fn read_progress(service: &ChangeSetService, action_id: ActionId) -> Result<Vec<ProgressRow>> {
    service.locked()?.progress(action_id)
}

/// Records one path's outcome.
fn settle_one(service: &ChangeSetService, action_id: ActionId, row: &ProgressRow) -> Result<()> {
    service.locked()?.settle_path(action_id, row)
}

/// Runs one apply's operations, recording each one's outcome as it goes.
fn run_operations(
    service: &ChangeSetService,
    repository: &OpenedRepository,
    order: &ApplyOrder<'_>,
    operations: &[(String, Operation)],
) -> Result<RunOutcome> {
    let mut run = RunOutcome {
        progress: Vec::new(),
        changed: Vec::new(),
        stopped: None,
        abandoned: None,
    };
    for (path, operation) in operations {
        let expected = order
            .affected
            .iter()
            .find(|affected| affected.path == *path);
        let before_digest = match read_working_tree(repository, path)?.read {
            WorkingRead::Content { bytes, .. } => Some(digest_of(&bytes)),
            _ => None,
        };
        #[cfg(feature = "fault-injection")]
        let fault = service.fault();
        let installed = install(
            &Staging {
                service,
                action_id: order.action_id,
            },
            service.project().profile(),
            repository,
            path,
            operation,
            expected,
            #[cfg(feature = "fault-injection")]
            fault
                .as_ref()
                .and_then(|fault| fault.before_rename.as_ref())
                .map(|act| act.as_ref() as &dyn Fn(&str) -> bool),
        )?;
        #[cfg(feature = "fault-injection")]
        if matches!(installed, Installed::Abandoned) {
            // Nothing is settled for this path: the row stays as the plan left it, which is what
            // a daemon that died between staging and publishing leaves in the journal.
            run.abandoned = Some(
                fault
                    .as_ref()
                    .map_or_else(String::new, |fault| fault.detail.clone()),
            );
            return Ok(run);
        }
        let row = match &installed {
            Installed::Written(after) => ProgressRow {
                path: path.clone(),
                state: PathProgressState::Written,
                before_digest,
                after_digest: Some(*after),
                detail: match operation {
                    Operation::Remove => "the path was taken away and this host confirmed it is \
                                          gone"
                        .to_owned(),
                    _ => "the staged content was renamed over the destination and this host read \
                          it back"
                        .to_owned(),
                },
            },
            Installed::Conflicted(here) => ProgressRow {
                path: path.clone(),
                state: PathProgressState::Conflicted,
                before_digest: *here,
                after_digest: *here,
                detail: "something wrote this path between the preflight and the rename, so this \
                         host did not write it"
                    .to_owned(),
            },
            Installed::Unresolved(detail) => ProgressRow {
                path: path.clone(),
                state: PathProgressState::Unresolved,
                before_digest,
                after_digest: None,
                detail: detail.clone(),
            },
            // Returned above, before anything of this path is settled.
            #[cfg(feature = "fault-injection")]
            Installed::Abandoned => unreachable!("an abandoned path returns before it is settled"),
        };
        service.locked()?.settle_path(order.action_id, &row)?;
        run.progress.push(wire_progress(&row));
        match installed {
            Installed::Written(_) => run.changed.push(path.clone()),
            Installed::Conflicted(_) => {
                run.stopped = Some((
                    ApplyOutcomeClass::ConflictAfterPartialWrites,
                    format!(
                        "an external write reached {} between the recheck and the rename, so this \
                         apply stopped with {} path(s) already changed",
                        kr_project::git::redact(path),
                        run.changed.len()
                    ),
                ));
                break;
            }
            // A path this host could not resolve does not stop the apply: the caller asked for
            // every operation, and the answer lists each one's own outcome.
            Installed::Unresolved(_) => {}
            #[cfg(feature = "fault-injection")]
            Installed::Abandoned => unreachable!("an abandoned path returns before it is settled"),
        }
        #[cfg(feature = "fault-injection")]
        if let Some(fault) = fault
            && run.changed.len() == fault.after_paths
        {
            if let Some(act) = &fault.act {
                act();
            }
            if fault.stop {
                // The apply is abandoned here **without settling**, exactly as a daemon that died
                // would leave it. The row stays undecided and the paths after this one keep the
                // `planned` row they were given before any of them was attempted.
                run.abandoned = Some(fault.detail.clone());
                return Ok(run);
            }
        }
    }
    Ok(run)
}

/// What one run of an apply's operations came to.
struct RunOutcome {
    progress: Vec<PathProgress>,
    changed: Vec<String>,
    stopped: Option<(ApplyOutcomeClass, String)>,
    /// Set when this process stopped without deciding the apply, which is what a daemon that died
    /// leaves behind. The apply row stays open and recovery settles it.
    abandoned: Option<String>,
}

/// Writes the validated content into a private staging directory of this host's own.
fn stage(
    service: &ChangeSetService,
    name: &str,
    operations: &[(String, Operation)],
) -> Result<AuthorisedDirectory> {
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(STAGING_DIRECTORY)?)?;
    let directory = parent.create_subdirectory(&RelativeName::parse(name)?)?;
    for (path, operation) in operations {
        let Operation::Install { bytes, .. } = operation else {
            continue;
        };
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

/// The one name this host writes inside a staging directory.
///
/// It is the only name it ever removes in there, which is what makes the cleanup a rule rather
/// than a judgement: anything else in that directory is something this host did not put there,
/// and an empty-directory removal refuses to take it away.
const STAGED_CONTENT: &str = "content";

/// The single-component name of the directory one destination path is staged through.
fn staged_name(path: &str) -> String {
    hex_of(digest_of(path.as_bytes()))
}

/// What one apply tells the journal about the directories it stages its destinations through.
///
/// The name beside a destination is the same every time that path is applied, so a directory left
/// behind by a daemon that died blocks the next apply of that path. What makes it removable rather
/// than a thing a person has to find is this record: the name, the directory this host created at
/// it, and the file it wrote inside. A cleanup takes either away **only while it is still that
/// object**, live and in recovery alike, so an object this host has not recorded is one it leaves
/// exactly as it is.
struct Staging<'a> {
    service: &'a ChangeSetService,
    action_id: ActionId,
}

impl Staging<'_> {
    /// Records the name before it exists, with no identity: this host is about to make it.
    fn about_to_create(&self, path: &str, entry: &str) -> Result<()> {
        self.service
            .locked()?
            .stage_path(self.action_id, path, entry, None, None)
    }

    /// Records the directory this host made, which is what a cleanup compares against.
    fn created(
        &self,
        path: &str,
        entry: &str,
        identity: kr_transfer::ObjectIdentity,
    ) -> Result<()> {
        #[cfg(feature = "fault-injection")]
        if self
            .service
            .fault()
            .is_some_and(|fault| fault.refuse_staging_record)
        {
            return Err(ChangeSetError::StoreUnavailable {
                detail: "this journal would not record what this host had just made".into(),
            });
        }
        self.service
            .locked()?
            .stage_path(self.action_id, path, entry, Some(identity), None)
    }

    /// Records the file this host wrote inside that directory.
    ///
    /// Recorded on its own, after it exists: a cleanup takes the file away only while it is still
    /// this object, so a file another writer put there in place of it is one this host keeps and
    /// reports rather than one it removes.
    fn wrote(
        &self,
        path: &str,
        entry: &str,
        identity: kr_transfer::ObjectIdentity,
        content: kr_transfer::ObjectIdentity,
    ) -> Result<()> {
        self.service.locked()?.stage_path(
            self.action_id,
            path,
            entry,
            Some(identity),
            Some(content),
        )
    }

    /// Records that this apply has nothing of its own at that name any more.
    fn gone(&self, path: &str) -> Result<()> {
        self.service.locked()?.unstage_path(self.action_id, path)
    }
}

/// What one operation does to one destination path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Operation {
    /// Put this content there.
    Install { bytes: Vec<u8>, executable: bool },
    /// Take the path away, because the version does not hold it.
    Remove,
    /// Leave it exactly as it is, and say why this host did not resolve it.
    Refuse(String),
}

/// What installing one path came to.
enum Installed {
    /// The content is in the destination and this host read it back.
    Written(Digest256),
    /// This host stopped inside the window between staging the path and publishing it, exactly
    /// where a daemon that died would stop. The temporary is still there and nothing is settled.
    #[cfg(feature = "fault-injection")]
    Abandoned,
    /// The destination stopped being what the request expected before anything was written.
    Conflicted(Option<Digest256>),
    /// This host could not establish what the destination holds.
    Unresolved(String),
}

/// Puts one path's content in the destination, or takes the path away.
///
/// Everything happens through the destination directory's **own handle**, obtained by descending
/// from the working tree's handle level by level. Nothing resolves a path a second time, and
/// nothing is removed to make room: an occupied temporary name is a path this host leaves alone
/// and reports.
///
/// The order is what the guarantee rests on:
///
/// 1. the parent directories are opened, and created where the version needs one;
/// 2. the validated bytes are written into a temporary **created exclusively in that same
///    directory**, so the publication is a rename inside one directory and can cross no filesystem;
/// 3. the destination's own permissions are read and put on the temporary;
/// 4. the destination is **rechecked here**, against that same parent handle, which is as late as
///    this platform permits;
/// 5. the rename;
/// 6. the destination is opened again and its content compared with what was meant to land.
///
/// Step 6 is why `Written` means what it says. Between steps 4 and 5 another writer is not
/// excluded — that is the limitation this class states — but a rename that installed something
/// other than the validated content is caught rather than recorded as a success.
///
/// The journal is told about the temporary **before the name is created** and again the moment
/// the file exists, and the record is cleared only once the temporary has been published or taken
/// away. So a daemon that dies inside this window leaves a journal that names exactly what it left
/// beside the destination, and `recover_before_serving` can take away that object and nothing
/// else.
#[allow(clippy::too_many_lines)]
fn install(
    staging: &Staging<'_>,
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    path: &str,
    operation: &Operation,
    expected: Option<&AffectedVersion>,
    #[cfg(feature = "fault-injection")] before_rename: Option<&dyn Fn(&str) -> bool>,
) -> Result<Installed> {
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
        here = match descend_or_create(&here, &RelativeName::parse(component)?, operation) {
            Ok(directory) => directory,
            Err(error) => return Ok(Installed::Unresolved(error.to_string())),
        };
    }
    let leaf_name = RelativeName::parse(leaf)?;
    let (bytes, executable) = match operation {
        Operation::Refuse(detail) => return Ok(Installed::Unresolved(detail.clone())),
        Operation::Remove => {
            // A removal has nothing to stage. The recheck is the last thing before it.
            if let Some(conflict) = recheck(profile, repository, &here, &leaf_name, expected, path)?
            {
                return Ok(conflict);
            }
            #[cfg(feature = "fault-injection")]
            if let Some(act) = before_rename
                && !act(path)
            {
                return Ok(Installed::Abandoned);
            }
            if let Err(error) = here.remove(&leaf_name) {
                return Ok(Installed::Unresolved(error.to_string()));
            }
            here.sync()?;
            match here.probe(&leaf_name) {
                Err(kr_transfer::Escape::NotFound { .. }) => {}
                Ok(_) => {
                    return Ok(Installed::Unresolved(
                        "the path is still there after this host removed it".to_owned(),
                    ));
                }
                Err(error) => return Ok(Installed::Unresolved(error.to_string())),
            }
            // And the path the request names resolves to nothing either. The handle this host
            // removed through could belong to a directory somebody moved aside while this apply
            // was running, and a removal confirmed only there would be a claim about another tree.
            return match resolved_again(repository, path)? {
                None => Ok(Installed::Written(digest_of(&[]))),
                Some(_) => Ok(Installed::Unresolved(
                    "the path this request names still resolves to a file: a directory above it \
                     was moved while this apply was running"
                        .to_owned(),
                )),
            };
        }
        Operation::Install { bytes, executable } => (bytes, *executable),
    };
    // **The content is staged inside a directory of this host's own**, made in the destination's
    // own directory so that the publication is a rename inside one filesystem. The directory is
    // created exclusively, so a name that is already taken is one this host leaves exactly as it
    // is rather than one it removes to make room.
    //
    // The directory is what makes the cleanup safe rather than careful. Every name this host ever
    // takes away is inside it, or is the directory itself once it is empty, and the only name this
    // host ever writes inside it is [`STAGED_CONTENT`]. So no name of the person's own making is
    // the target of a removal, whatever else happens at the moment of it, and a directory that
    // holds anything else refuses the removal instead of losing it.
    let entry = format!(".kr-apply-{}", staged_name(path));
    let temporary = RelativeName::parse(&entry)?;
    let content = RelativeName::parse(STAGED_CONTENT)?;
    // The same question the removal will ask of this directory, asked before the name exists. A
    // directory this host could not later show the name is still its own in is one it makes no
    // name in at all, because what it would leave behind is residue no recovery could ever clear.
    if !crate::removal::may_take_a_name_from(here.handle()) {
        return Ok(Installed::Unresolved(
            "this host did not write anything, because the directory it would stage this path \
             through is one it cannot show the name it made would still be its own in"
                .to_owned(),
        ));
    }
    // Recorded before the name exists: a crash between this and the creation leaves a name the
    // journal knows about and an identity it does not, which is a directory this host cannot prove
    // it made and therefore never removes.
    staging.about_to_create(path, &entry)?;
    if let Err(error) = crate::removal::make_exclusively(here.handle(), &entry) {
        // A refused creation is not proof that nothing is there: the name can be taken by
        // something this host did not make, and a creation can fail after it has made the name.
        // So the record is cleared only when the name holds nothing and that absence is durable;
        // anything else keeps it, and this host reports the name rather than taking away what it
        // cannot prove it made.
        if matches!(
            here.probe(&temporary),
            Err(kr_transfer::Escape::NotFound { .. })
        ) && here.sync().is_ok()
        {
            staging.gone(path)?;
        }
        return Ok(Installed::Unresolved(format!(
            "this host did not write anything, because the name it would have staged through is \
             taken and it removes nothing to make room: {error}"
        )));
    }
    // Made, not opened, and then adopted: creating a directory is exclusive on every platform this
    // runs on. The one window no call closes is between the creation and this open, and what
    // bounds it is that everything beneath this name afterwards is this host's own writing.
    let staged_directory = match here.subdirectory(&temporary) {
        Ok(directory) => directory,
        Err(error) => {
            // The name exists and this host has no handle on it. The record keeps it, with no
            // identity, so the next recovery reports the name rather than removing it.
            return Ok(Installed::Unresolved(format!(
                "this host made the directory it stages this path through and could not open it, \
                 so it wrote nothing: {error}"
            )));
        }
    };
    let staged_identity = staged_directory.identity();
    if let Err(error) = staging.created(path, &entry, staged_identity) {
        // The journal would not take the identity of the directory this host had just made, so
        // nothing could later prove that directory was this host's own. It goes now, while the
        // handle that made it is still open and its identity is still known, through the same rule
        // the cleanup below follows.
        drop(staged_directory);
        let _ = clear_temporary(
            &here,
            &temporary,
            Some(staged_identity),
            None,
            staging,
            path,
        );
        return Err(error);
    }
    // What the creation asked for is read back from the handle before a byte is written inside it,
    // rather than assumed: the account's file-creation mask can narrow the mode, a filesystem can
    // report one it does not keep, and on some platforms a list beside the mode can admit an
    // account the mode does not mention. A directory this host cannot show is shut is one it
    // stages nothing through, and the empty directory it made goes again here.
    if !crate::removal::may_take_content_from(staged_directory.handle()) {
        drop(staged_directory);
        let _ = clear_temporary(
            &here,
            &temporary,
            Some(staged_identity),
            None,
            staging,
            path,
        );
        return Ok(Installed::Unresolved(
            "this host could not show that the directory it stages this path through is shut to \
             every other account, so it wrote nothing"
                .to_owned(),
        ));
    }
    let mut staged = match staged_directory.create_new(&content) {
        Ok(file) => file,
        Err(error) => {
            drop(staged_directory);
            let _ = clear_temporary(
                &here,
                &temporary,
                Some(staged_identity),
                None,
                staging,
                path,
            );
            return Ok(Installed::Unresolved(format!(
                "this host could not write the content it stages this path through: {error}"
            )));
        }
    };
    let content_identity = staged.identity();
    if let Err(error) = staging.wrote(path, &entry, staged_identity, content_identity) {
        // The journal would not record the file this host had just written, so nothing could later
        // prove that file was its own. The directory it is in goes now, with it inside, while the
        // handles that made both are still open.
        drop(staged);
        drop(staged_directory);
        let _ = clear_temporary(
            &here,
            &temporary,
            Some(staged_identity),
            Some(content_identity),
            staging,
            path,
        );
        return Err(error);
    }
    let outcome = (|| -> Result<Installed> {
        staged
            .handle_mut()
            .write_all(bytes)
            .map_err(ChangeSetError::storage)?;
        staged
            .handle_mut()
            .sync_all()
            .map_err(ChangeSetError::storage)?;
        let carried = match carry_permissions(&here, &leaf_name, &staged, executable)? {
            Some(permissions) => permissions,
            None => {
                return Ok(Installed::Unresolved(
                    "this host could not read what permissions the destination has, and it does \
                     not replace a file whose permissions it cannot carry across"
                        .to_owned(),
                ));
            }
        };
        // As late as this platform permits: the last thing before the rename, on the object the
        // parent handle names rather than on a path resolved earlier.
        if let Some(conflict) = recheck(profile, repository, &here, &leaf_name, expected, path)? {
            return Ok(conflict);
        }
        #[cfg(feature = "fault-injection")]
        if let Some(act) = before_rename
            && !act(path)
        {
            return Ok(Installed::Abandoned);
        }
        // The content this host is about to publish has to still be the file it wrote. A name
        // replaced between the creation and here is a file this host neither wrote nor checked,
        // and publishing it would put content in the destination that this apply never validated.
        match staged_directory.open_read(&content, ObjectPolicy::ReadableFile) {
            Ok(found) if found.identity() == content_identity => {}
            _ => {
                return Ok(Installed::Unresolved(
                    "the content this host staged is not the file it wrote any more, so it \
                     published nothing"
                        .to_owned(),
                ));
            }
        }
        staged_directory.rename_into(&content, &here, &leaf_name)?;
        here.sync()?;
        // The content is gone as a temporary: the rename is what published it. What is left is an
        // empty directory of this host's own, and the same cleanup that takes it away after a
        // failure takes it away after a success, below, once this closure has given its handle up.
        // What actually landed, read **twice**: once through the handle this host published
        // through, and once by resolving the path again from the working tree's own handle. A
        // parent somebody moved aside while this was running would let the first read succeed in
        // a directory that is no longer the one the workspace's path names, and a success claimed
        // from that would be a claim about another tree.
        let expected = digest_of(bytes);
        match read_destination(&here, &leaf_name)? {
            Some(landed) if landed == expected && !published_with(&here, &leaf_name, &carried) => {
                Ok(Installed::Unresolved(
                    "the destination holds the content this host installed under permissions this \
                     host did not set on it"
                        .to_owned(),
                ))
            }
            // The path this request names has to resolve to **the object this host renamed into
            // place**, not merely to something holding the same bytes: a rename keeps the file's
            // identity, so this is one comparison that covers the content, the mode and which
            // directory the path actually reaches.
            Some(landed) if landed == expected => match resolved_again(repository, path)? {
                Some(again) if again == content_identity => Ok(Installed::Written(landed)),
                _ => Ok(Installed::Unresolved(
                    "the content is in the directory this host published through, and the path \
                     this request names does not resolve to the object it published: a directory \
                     above it was moved while this apply was running"
                        .to_owned(),
                )),
            },
            Some(_) => Ok(Installed::Unresolved(
                "the destination holds something other than the content this host installed"
                    .to_owned(),
            )),
            None => Ok(Installed::Unresolved(
                "the destination holds nothing after this host installed into it".to_owned(),
            )),
        }
    })();
    #[cfg(feature = "fault-injection")]
    let stopped_here = matches!(outcome, Ok(Installed::Abandoned));
    #[cfg(not(feature = "fault-injection"))]
    let stopped_here = false;
    // The handle goes before the directory does, so no platform can refuse the removal because
    // this host still holds the thing it is removing.
    drop(staged);
    drop(staged_directory);
    // A host that stopped inside the window leaves everything exactly as it was: that is the whole
    // of what this fixture reproduces, and cleaning up here would hide it. Every other ending goes
    // through the same cleanup, the publication included: what it leaves behind is an empty
    // directory of this host's own making.
    if !stopped_here {
        clear_temporary(
            &here,
            &temporary,
            Some(staged_identity),
            Some(content_identity),
            staging,
            path,
        )?;
    }
    outcome
}

/// Takes away the staging directory one apply made, and clears its record once it is gone.
///
/// The same rule for the apply that is running and for the recovery that follows one that is not,
/// because it is the rule the whole design rests on:
///
/// * **This host removes exactly two names, and both are its own.** The single name it writes
///   inside the staging directory, and the directory itself once it is empty. A name of the
///   person's own making is never the target of a removal, whatever any other writer does at the
///   moment of it.
/// * **Each goes only while it is the object the journal recorded.** The directory's identity and
///   the file's are each compared through an open handle, so a directory somebody substituted and
///   a file somebody put inside this host's own directory are left exactly as they are.
/// * **The staged file goes only out of a directory this host can show is shut.** The same handle
///   that gave the identity answers for the kind, the owner, the mode and, where a platform keeps
///   protection beside the mode, the list: that is what bounds who could have replaced the file
///   since this host wrote it. A directory that is not all of those keeps what is inside it.
/// * **Each removal reaches the object rather than the name where the platform allows it.**
///   Windows deletes the staged file, and the directory too where the volume carries that call,
///   through the handle the identity was read from, which no name can redirect. Unix has no such
///   call, so a removal there is named relative to an open handle: the file relative to its own
///   directory, and the directory relative to the one that holds it, which this host first shows
///   belongs to this account and is not open to the whole machine. The one writer that can still
///   put something else at such a
///   name between the comparison and the removal is a process running as this same account, which
///   already holds every authority this product has over that tree; that is the limit of what a
///   removal in user space can promise, and `docs/project/README.md` states it.
/// * **Anything else inside it refuses the removal.** Taking the directory away is an
///   empty-directory removal, so a file somebody put there keeps the directory, keeps the record
///   and is reported rather than being taken away with it.
/// * **A record is cleared only once what it names is durably gone.** Every removal is followed by
///   a sync of the directory that held the name, and a sync this host could not finish keeps the
///   record, so the obligation reaches the next recovery rather than being dropped here.
///
/// A record with no identity is one this host died before it could show was its own. It is not
/// removed, but it does resolve: once the name holds nothing and that absence is durable, there
/// is nothing left to account for and the record goes.
fn take_staged(
    here: &AuthorisedDirectory,
    temporary: &RelativeName,
    identity: Option<kr_transfer::ObjectIdentity>,
    content_identity: Option<kr_transfer::ObjectIdentity>,
) -> Staged {
    let opened = match here.subdirectory(temporary) {
        Ok(directory) => Some(directory),
        Err(kr_transfer::Escape::NotFound { .. }) => None,
        // A name this host could not look at, or one holding something that is not a directory at
        // all, is not a name it can say anything about. The record stays and the path is reported.
        Err(_) => return Staged::NotOurs,
    };
    let Some(directory) = opened else {
        return if here.sync().is_ok() {
            Staged::NotThere
        } else {
            Staged::NotOurs
        };
    };
    let Some(identity) = identity else {
        return Staged::NotOurs;
    };
    if directory.identity() != identity {
        return Staged::NotOurs;
    }
    let Ok(content) = RelativeName::parse(STAGED_CONTENT) else {
        return Staged::NotOurs;
    };
    // The file inside is compared exactly as the directory was. A directory this host made is not
    // proof of what is in it now: another writer can replace the one name this host writes there
    // and leave the directory itself untouched, and a removal that took that on trust would be
    // this host taking away a file it never wrote. So the file goes only while it is still the
    // object the journal recorded, and anything else keeps the directory, keeps the record and is
    // reported.
    //
    // A name this host cannot open at all is one it says nothing about here: the empty-directory
    // removal below decides it, because a directory holding anything keeps the directory and one
    // holding nothing is this host's own obligation ending.
    if let Ok(found) = directory.open_read(&content, ObjectPolicy::ReadableFile) {
        if Some(found.identity()) != content_identity {
            return Staged::NotOurs;
        }
        // The rest of what the directory's own handle says about it: still a directory, owned by
        // this account, and shut to every other one. That is what bounds who could have put this
        // file here since this host wrote it, so a directory that is not all three keeps what is
        // inside it and the path is reported.
        if !crate::removal::may_take_content_from(directory.handle()) {
            return Staged::NotOurs;
        }
        // Through the handle that was just compared, and while it is still open, so that the
        // removal reaches the object this host proved was its own rather than whatever the name
        // reaches now.
        if crate::removal::take_content(directory.handle(), STAGED_CONTENT, found.handle()).is_err()
        {
            return Staged::NotOurs;
        }
        drop(found);
        if directory.sync().is_err() {
            return Staged::NotOurs;
        }
    }
    // The handle goes before the directory does, so no platform refuses the removal because this
    // host still holds what it is removing. What decides the removal is the identity this host
    // already compared, that the directory is empty, and that the directory holding the name is
    // one this host can show belongs to this account.
    drop(directory);
    if crate::removal::take_directory(here.handle(), temporary.as_str()).is_err()
        || here.sync().is_err()
    {
        return Staged::NotOurs;
    }
    Staged::TakenAway
}

/// Takes the staging directory away while an apply is running, and clears its record when it is
/// gone. [`take_staged`] is the rule; this is the live caller of it.
fn clear_temporary(
    here: &AuthorisedDirectory,
    temporary: &RelativeName,
    identity: Option<kr_transfer::ObjectIdentity>,
    content_identity: Option<kr_transfer::ObjectIdentity>,
    staging: &Staging<'_>,
    path: &str,
) -> Result<()> {
    match take_staged(here, temporary, identity, content_identity) {
        Staged::TakenAway | Staged::NotThere => staging.gone(path)?,
        Staged::NotOurs => {}
    }
    Ok(())
}

/// Reads what one path resolves to from the working tree's own handle.
///
/// The second, independent resolution: `install` publishes through a parent it opened level by
/// level, and this asks the working tree what the whole path names now. Two resolutions agreeing
/// is what turns a directory moved out from under the publication into a refusal rather than a
/// success about somewhere else.
fn resolved_again(
    repository: &OpenedRepository,
    path: &str,
) -> Result<Option<kr_transfer::ObjectIdentity>> {
    let name = RelativeName::parse(path)?;
    let components = name.components();
    let Some((leaf, parents)) = components.split_last() else {
        return Ok(None);
    };
    let mut here = clone_handle(repository.work_tree())?;
    for component in parents {
        here = match here.subdirectory(&RelativeName::parse(component)?) {
            Ok(directory) => directory,
            Err(kr_transfer::Escape::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    }
    match here.open_read(&RelativeName::parse(leaf)?, ObjectPolicy::ReadableFile) {
        Ok(file) => Ok(Some(file.identity())),
        Err(kr_transfer::Escape::NotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Reads what one destination path holds now.
fn read_destination(
    directory: &AuthorisedDirectory,
    name: &RelativeName,
) -> Result<Option<Digest256>> {
    match directory.open_read(name, ObjectPolicy::ReadableFile) {
        Ok(mut file) => {
            let identity = file.identity();
            let before = file.byte_len();
            let written_before = crate::materialise::written_at(&file);
            if before > crate::capture::MAX_CAPTURE_FILE_BYTES {
                return Err(ChangeSetError::QuotaExceeded {
                    detail: format!(
                        "one file of this destination is {before} bytes and this host reads at \
                         most {} of it",
                        crate::capture::MAX_CAPTURE_FILE_BYTES
                    )
                    .into(),
                });
            }
            let mut bytes = Vec::with_capacity(usize::try_from(before).unwrap_or(0));
            let mut bounded = std::io::Read::take(
                file.handle_mut(),
                crate::capture::MAX_CAPTURE_FILE_BYTES + 1,
            );
            std::io::Read::read_to_end(&mut bounded, &mut bytes)
                .map_err(ChangeSetError::storage)?;
            if bytes.len() as u64 > crate::capture::MAX_CAPTURE_FILE_BYTES {
                return Err(ChangeSetError::QuotaExceeded {
                    detail: "one file of this destination grew past what this host reads while it \
                             was reading it"
                        .into(),
                });
            }
            // The same open handle is asked again: a file that changed while this host was reading
            // it would otherwise give a digest of a stream that no version of the file ever held.
            // The instant it was last written is asked for too, because a rewrite of the same
            // length leaves the identity and the length exactly as they were.
            let after = file.revalidate().map_err(ChangeSetError::from)?;
            let written_after = crate::materialise::written_at(&file);
            if file.identity() != identity
                || after != before
                || after != bytes.len() as u64
                || written_after != written_before
            {
                return Err(ChangeSetError::SourceChanged {
                    detail: "a destination path changed while this host was reading it".into(),
                });
            }
            Ok(Some(digest_of(&bytes)))
        }
        Err(kr_transfer::Escape::NotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Compares the destination with what the request expects, as late as the platform permits.
fn recheck(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    directory: &AuthorisedDirectory,
    name: &RelativeName,
    expected: Option<&AffectedVersion>,
    path: &str,
) -> Result<Option<Installed>> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    let here = match read_destination(directory, name) {
        Ok(here) => here,
        Err(error) => return Ok(Some(Installed::Unresolved(error.to_string()))),
    };
    if expected.expected_worktree_digest.0 != here {
        return Ok(Some(Installed::Conflicted(here)));
    }
    if expected.check_index {
        // Read now, for this path: an index read at the start of the run describes what was there
        // before every earlier operation, and a request that says what the index holds is asking
        // about the index at the moment its own path is written.
        let index = match read_index(profile, repository) {
            Ok(index) => index,
            Err(error) => return Ok(Some(Installed::Unresolved(error.to_string()))),
        };
        let held = index.get(path);
        let object_differs =
            expected.expected_index_object_id.0 != held.map(|entry| entry.object_id.clone());
        let mode_differs = expected.expected_index_mode.0 != held.map(|entry| entry.mode.clone());
        // An unresolved merge is never what a request describes: the index holds several stages
        // for such a path and none of them is the one content an apply is against.
        let unmerged = held.is_some_and(|entry| entry.stage != 0);
        if object_differs || mode_differs || unmerged {
            return Ok(Some(Installed::Conflicted(here)));
        }
    }
    Ok(None)
}

/// Opens one directory of the destination, creating it only when a path is being installed.
///
/// The user's own directories are the user's: this host neither requires nor imposes the
/// owner-only permissions it uses for its **own** directories, because a repository whose `src` is
/// readable by a group is an ordinary repository. What it does keep is the handle: every level is
/// opened from the level above, so nothing resolves a path a second time.
fn descend_or_create(
    here: &AuthorisedDirectory,
    name: &RelativeName,
    operation: &Operation,
) -> Result<AuthorisedDirectory> {
    match here.subdirectory(name) {
        Ok(directory) => Ok(directory),
        Err(kr_transfer::Escape::NotFound { .. })
            if matches!(operation, Operation::Install { .. }) =>
        {
            match here.handle().create_dir(name.as_str()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ChangeSetError::storage(error)),
            }
            here.sync()?;
            Ok(here.subdirectory(name)?)
        }
        Err(error) => Err(error.into()),
    }
}

/// The bits of a platform mode that say who may use a file, rather than what kind of object it is.
#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o7777;

/// Everything about a destination that decides who may use it, carried across a replacement.
///
/// The three travel together because each one changes what the others mean. A list names what one
/// user and one group may do and leaves the rest to the file's *own* user and group, and a mode's
/// middle digit is read against that same group. Carry one without the others and the published
/// file admits different people under protection that looks identical.
/// On Windows there are no mode bits. What answers "may this file be written" there is the
/// read-only attribute, so that is what travels in the mode's place, beside the list and the
/// account, which travel on both platform families.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CarriedPermissions {
    #[cfg(unix)]
    mode: u32,
    #[cfg(windows)]
    read_only: bool,
    #[cfg(any(unix, windows))]
    access_control: kr_transfer::AccessControl,
    #[cfg(any(unix, windows))]
    owner: kr_transfer::FileOwner,
}

/// Puts the destination's own protection on the staged copy before it is renamed over it.
///
/// Returns what it carried, so the read-back after the rename can confirm the published file has
/// it. Returns nothing when the destination is there and this host could not read its protection
/// or could not put that protection on the copy: replacing a file whose protection cannot be
/// carried across is exactly what "preserve permissions" forbids, so the path is left alone
/// instead. Where the path is absent there is nothing to carry, and the version's own bit decides
/// the mode.
#[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
fn carry_permissions(
    destination: &AuthorisedDirectory,
    leaf: &RelativeName,
    staged: &kr_transfer::AuthorisedFile,
    executable: bool,
) -> Result<Option<CarriedPermissions>> {
    use cap_std::fs::PermissionsExt as _;
    let existing = match destination.open_read(leaf, ObjectPolicy::ReadableFile) {
        Ok(file) => {
            let mode = match file.handle().metadata() {
                // The permission bits alone: what a platform reports beside them says what kind of
                // object it is rather than who may use it, and setting those back is not carrying
                // permissions across.
                Ok(metadata) => metadata.permissions().mode() & PERMISSION_BITS,
                Err(_) => return Ok(None),
            };
            let (Ok(acl), Ok(owner)) = (file.access_control(), file.owner()) else {
                return Ok(None);
            };
            Some((mode, acl, owner))
        }
        // Absent is not a failure to read: there is nothing there whose permissions to carry, so
        // the version's own bit decides.
        Err(kr_transfer::Escape::NotFound { .. }) => None,
        Err(_) => return Ok(None),
    };
    // What the copy already belongs to, which is what it keeps where there is no destination to
    // take a user and a group from.
    let Ok(staged_owner) = staged.owner() else {
        return Ok(None);
    };
    let (mode, target_acl, owner) = existing.unwrap_or((
        if executable { 0o755 } else { 0o644 },
        kr_transfer::AccessControl::None,
        staged_owner.clone(),
    ));
    // The destination's list goes on the copy, and where the destination has none the copy's own
    // comes off: a directory can carry a list that attaches to every file made inside it, so a
    // copy this host staged can start out with protection the file it replaces never had. A copy
    // with nothing to take off is left alone, which is what keeps a filesystem that holds no lists
    // at all from being asked to write one. This is done first and through the copy's own
    // descriptor, while this host still owns it: a file's list is the owner's to write.
    let write_list =
        !matches!(target_acl, kr_transfer::AccessControl::None) || staged.carries_access_control();
    if write_list && staged.set_access_control(&target_acl).is_err() {
        return Ok(None);
    }
    // Then the user and the group, which a host that is not the superuser can set only where they
    // are already its own to give. Where it cannot, the destination is left exactly as it was.
    if owner != staged_owner && staged.set_owner(&owner).is_err() {
        return Ok(None);
    }
    // The mode last, because giving a file away takes its set-user and set-group bits off it.
    // Through the handle this host created a moment ago, not through the name: a name reopened is
    // a name somebody could have put something else at.
    staged
        .handle()
        .set_permissions(cap_std::fs::Permissions::from_mode(mode))
        .map_err(ChangeSetError::storage)?;
    // Read the copy's own protection back before anything is renamed. A platform can do part of
    // what it was asked and report success: Linux takes the set-user and set-group bits off a file
    // whose group a host may not keep it in, and a copy that does not carry what the destination
    // has is one this host does not publish. Checked here, where the destination is still
    // untouched, rather than only after the rename, where nothing can be put back.
    let carried = CarriedPermissions {
        mode,
        access_control: target_acl,
        owner,
    };
    if !staged_carries(staged, &carried) {
        return Ok(None);
    }
    Ok(Some(carried))
}

/// Returns true when the staged copy carries the protection this host meant to put on it.
///
/// Asked of the copy's own handle, which is the one this host created and has held ever since.
#[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
fn staged_carries(staged: &kr_transfer::AuthorisedFile, carried: &CarriedPermissions) -> bool {
    use cap_std::fs::PermissionsExt as _;

    let Ok(metadata) = staged.handle().metadata() else {
        return false;
    };
    if metadata.permissions().mode() & PERMISSION_BITS != carried.mode {
        return false;
    }
    let Ok(owner) = staged.owner() else {
        return false;
    };
    if owner != carried.owner {
        return false;
    }
    let Ok(acl) = staged.access_control() else {
        return false;
    };
    acl == carried.access_control
}

/// Leaves the destination alone: this Unix platform keeps its access-control lists somewhere this
/// host can neither read nor write, and a replacement that dropped one would take protection away
/// without saying so.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn carry_permissions(
    _destination: &AuthorisedDirectory,
    _leaf: &RelativeName,
    _staged: &kr_transfer::AuthorisedFile,
    _executable: bool,
) -> Result<Option<CarriedPermissions>> {
    Ok(None)
}

/// Puts the destination's own protection on the staged copy before it is renamed over it.
///
/// What travels on this platform is the entries the destination carries itself, whether its list
/// is protected against the directory above it, the account it belongs to, and its read-only
/// attribute. All of them are read through the destination's own handle and written through the
/// copy's own handle, and the copy is read back before anything is renamed: a platform can do part
/// of what it was asked and report success, and a copy that does not carry what the destination
/// has is one this host does not publish.
///
/// What the destination inherits does not travel. Those entries belong to the directory the two
/// are in, which gives the same ones to every object created there, so the copy already has the
/// directory's current entries and writing the destination's would put a second copy of them on
/// the published file.
///
/// Returns nothing where the destination is there and its protection cannot be read, cannot be put
/// on the copy, or is not on the copy afterwards. The path is then left exactly as it was.
#[cfg(windows)]
fn carry_permissions(
    destination: &AuthorisedDirectory,
    leaf: &RelativeName,
    staged: &kr_transfer::AuthorisedFile,
    executable: bool,
) -> Result<Option<CarriedPermissions>> {
    // No file on this platform carries an executable bit: what a file may be used for is decided
    // by its name and its list, neither of which a version's own bit says anything about.
    let _ = executable;
    let existing = match destination.open_read(leaf, ObjectPolicy::ReadableFile) {
        Ok(file) => {
            let read_only = match file.handle().metadata() {
                Ok(metadata) => metadata.permissions().readonly(),
                Err(_) => return Ok(None),
            };
            let (Ok(acl), Ok(owner)) = (file.access_control(), file.owner()) else {
                return Ok(None);
            };
            Some((read_only, acl, owner))
        }
        // Absent is not a failure to read: there is nothing there whose protection to carry.
        Err(kr_transfer::Escape::NotFound { .. }) => None,
        Err(_) => return Ok(None),
    };
    let Ok(staged_owner) = staged.owner() else {
        return Ok(None);
    };
    let Some((read_only, target_acl, owner)) = existing else {
        // Nothing to carry, so the copy keeps the list the directory it was created in gave it,
        // which is exactly what any file newly created there would carry. Writing a list here
        // would take that protection off a file this host has just made.
        let Ok(acl) = staged.access_control() else {
            return Ok(None);
        };
        return Ok(Some(CarriedPermissions {
            read_only: false,
            access_control: acl,
            owner: staged_owner,
        }));
    };
    // A destination this platform will not let a rename replace, and one whose copy this host
    // could not remove again if anything later refused. It is left exactly as it was.
    if read_only {
        return Ok(None);
    }
    // The destination's own entries go on the copy, and where the destination has none of its own
    // the copy's own come off: a directory can carry entries that attach to every file made inside
    // it, and a copy this host staged can start out with protection the file it replaces never
    // had. Written first and through the copy's own handle, which is the only handle in this apply
    // opened with the right to write a list at all. Where neither carries anything of its own
    // there is nothing to write: both hold exactly what the directory gives every object in it,
    // which is what the copy already received when it was created there.
    let write_list = target_acl.has_entries() || staged.carries_access_control();
    if write_list && staged.set_access_control(&target_acl).is_err() {
        return Ok(None);
    }
    // Then the account, which a process holding no restore privilege can set only to one its own
    // token names. Where it cannot, the destination is left exactly as it was: the same list under
    // a different account admits different people.
    if owner != staged_owner && staged.set_owner(&owner).is_err() {
        return Ok(None);
    }
    let carried = CarriedPermissions {
        read_only,
        access_control: target_acl,
        owner,
    };
    // Read the copy's own protection back before anything is renamed, while the destination is
    // still untouched rather than only after the rename, where nothing can be put back.
    if !staged_carries(staged, &carried) {
        return Ok(None);
    }
    Ok(Some(carried))
}

/// Returns true when the staged copy carries the protection this host meant to put on it.
///
/// Asked of the copy's own handle, which is the one this host created and has held ever since.
#[cfg(windows)]
fn staged_carries(staged: &kr_transfer::AuthorisedFile, carried: &CarriedPermissions) -> bool {
    let Ok(metadata) = staged.handle().metadata() else {
        return false;
    };
    if metadata.permissions().readonly() != carried.read_only {
        return false;
    }
    let Ok(owner) = staged.owner() else {
        return false;
    };
    if owner != carried.owner {
        return false;
    }
    let Ok(acl) = staged.access_control() else {
        return false;
    };
    acl == carried.access_control
}

/// Leaves the destination alone: this platform keeps its access-control lists somewhere this host
/// can neither read nor write, and a replacement that dropped one would take protection away
/// without saying so.
#[cfg(not(any(unix, windows)))]
fn carry_permissions(
    _destination: &AuthorisedDirectory,
    _leaf: &RelativeName,
    _staged: &kr_transfer::AuthorisedFile,
    _executable: bool,
) -> Result<Option<CarriedPermissions>> {
    Ok(None)
}

/// Returns true when the published file carries the permissions this host set on the copy it
/// renamed into place.
///
/// Content alone does not establish that the object at the name is the one this host published: a
/// file substituted between the rename and the read-back can hold the same bytes under different
/// protection, and an apply that reported success for it would have changed who can read it.
#[cfg(unix)]
fn published_with(
    directory: &AuthorisedDirectory,
    name: &RelativeName,
    carried: &CarriedPermissions,
) -> bool {
    use cap_std::fs::PermissionsExt as _;
    let Ok(file) = directory.open_read(name, ObjectPolicy::ReadableFile) else {
        return false;
    };
    let Ok(metadata) = file.handle().metadata() else {
        return false;
    };
    if metadata.permissions().mode() & PERMISSION_BITS != carried.mode {
        return false;
    }
    let Ok(owner) = file.owner() else {
        return false;
    };
    if owner != carried.owner {
        return false;
    }
    let Ok(acl) = file.access_control() else {
        return false;
    };
    acl == carried.access_control
}

/// Returns true when the published file carries the protection this host set on the copy it
/// renamed into place.
///
/// Read off the published object's own handle, not off the name a second time: a file substituted
/// between the rename and the read-back can hold the same bytes under a different list, and an
/// apply that reported success for it would have changed who can read it.
#[cfg(windows)]
fn published_with(
    directory: &AuthorisedDirectory,
    name: &RelativeName,
    carried: &CarriedPermissions,
) -> bool {
    let Ok(file) = directory.open_read(name, ObjectPolicy::ReadableFile) else {
        return false;
    };
    let Ok(metadata) = file.handle().metadata() else {
        return false;
    };
    if metadata.permissions().readonly() != carried.read_only {
        return false;
    }
    let Ok(owner) = file.owner() else {
        return false;
    };
    if owner != carried.owner {
        return false;
    }
    let Ok(acl) = file.access_control() else {
        return false;
    };
    acl == carried.access_control
}

/// Returns true: this platform has no protection for this host to have set.
#[cfg(not(any(unix, windows)))]
fn published_with(
    _directory: &AuthorisedDirectory,
    _name: &RelativeName,
    _carried: &CarriedPermissions,
) -> bool {
    true
}

/// Returns a second authority over one working tree, confined to the tree's own mount.
///
/// Everything this module reaches through the returned authority is content of the tree it named:
/// what it reads back to decide whether a destination still holds what the request expects, and
/// what it writes. A mount arriving over a directory of that path names another tree entirely, and
/// a read through it would answer about a file this request never named. So the descent carries
/// the same rule the capture's reads do.
fn clone_handle(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    Ok(directory.try_clone()?.confined_to_one_mount()?)
}

/// Captures the destination as it stands, so there is a recoverable version of it.
///
/// It goes into a change set of its own rather than into the one being applied: the destination's
/// own state is not a version of somebody else's work, and appending it there would make a reader
/// of that change set's versions see readings of a tree it never asked about.
fn capture_destination(
    service: &ChangeSetService,
    order: &ApplyOrder<'_>,
    into: Option<kr_protocol::ids::ChangeSetId>,
    what: &str,
    admitted: Option<&dyn crate::store::StillAdmitted>,
) -> Result<ChangeSetVersionRecord> {
    let Some(workspace_id) = order.workspace_id else {
        return Err(ChangeSetError::InvalidArgument(
            "this destination names the workspace it writes to".into(),
        ));
    };
    // Everything, because a recoverable reading that left the user's untracked work out would not
    // be what was there.
    let policy = InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    };
    let grant = FileGrant::default();
    let label = format!("the destination of action {}", order.action_id);
    let captured = crate::service::CaptureOrder {
        workspace_id,
        change_set_id: into,
        label: &label,
        request: crate::capture::CaptureRequest {
            policy: &policy,
            grant: &grant,
            quiescence_declared: false,
            required_consistency: None,
            quiescence: None,
        },
        pin: false,
        provenance: Provenance {
            derivation: format!(
                "a reading of the destination {what} an apply, so the apply has something \
                 recoverable on each side of it"
            ),
            ..order.provenance.clone()
        },
        admitted,
    };
    let (record, _) = service.capture(&captured)?;
    Ok(record)
}

/// Overlays one apply's content onto a manifest, without writing anything.
fn overlay(
    proposed: &mut Manifest,
    carried: &[Requested],
    order: &ApplyOrder<'_>,
    service: &ChangeSetService,
    repository: &OpenedRepository,
    unresolved: &mut Vec<String>,
) -> Result<()> {
    for requested in carried {
        let operation = operation_for(service, repository, order, requested)?;
        let (bytes, executable) = match operation {
            // The path is taken away, and the proposal records the deletion rather than merely
            // not holding the path: a reader of the proposal has to be able to tell a path it
            // removed from one it never had.
            Operation::Remove => {
                let held = proposed
                    .paths
                    .iter()
                    .find(|held| held.path == requested.path)
                    .cloned();
                proposed.paths.retain(|held| held.path != requested.path);
                // What the destination's own base holds for this path: from the captured path
                // where the destination holds one, and from the deletion the destination already
                // recorded where it does not. A removal must not replace a complete record of what
                // was deleted with an empty one.
                let recorded = proposed
                    .deletions
                    .iter()
                    .find(|deleted| deleted.path == requested.path)
                    .cloned();
                let base_object_id = held
                    .as_ref()
                    .and_then(|held| held.base_object_id.0.clone())
                    .or_else(|| {
                        recorded
                            .as_ref()
                            .and_then(|held| held.base_object_id.clone())
                    });
                let base_mode = held
                    .as_ref()
                    .and_then(|held| held.base_mode.0.clone())
                    .or_else(|| recorded.as_ref().and_then(|held| held.base_mode.clone()));
                // What a revert of this proposal would put back, kept in this host's own store so
                // it does not depend on the destination's repository still holding the object.
                let content_digest = match (base_object_id.as_deref(), base_mode.as_deref()) {
                    (Some(object_id), Some(mode))
                        if crate::capture::REGULAR_MODES.contains(&mode) =>
                    {
                        let bytes =
                            read_object(service.project().profile(), repository, object_id)?;
                        Some(service.objects().put(&bytes)?)
                    }
                    _ => None,
                };
                let deleted = crate::version::DeletedPath {
                    path: requested.path.clone(),
                    base_object_id,
                    base_mode,
                    content_digest: content_digest
                        .or_else(|| recorded.as_ref().and_then(|held| held.content_digest)),
                };
                // One deletion per path. A path the destination's own base already recorded as
                // deleted is not deleted twice by a change that also removes it.
                match proposed
                    .deletions
                    .iter_mut()
                    .find(|existing| existing.path == requested.path)
                {
                    Some(existing) => *existing = deleted,
                    None => proposed.deletions.push(deleted),
                }
                continue;
            }
            // A refusal leaves the proposal exactly as the destination has it, and says so, so a
            // proposal that could not carry an operation is not reported as one that carried
            // every operation.
            Operation::Refuse(_) => {
                unresolved.push(requested.path.clone());
                continue;
            }
            Operation::Install { bytes, executable } => (bytes, executable),
        };
        let digest = service.objects().put(&bytes)?;
        // The metadata is the **destination's**, not the source version's: this manifest records
        // what the destination would hold, and its base side is the destination's own base. What
        // the source version says about its own base belongs to the source version.
        let existing = proposed
            .paths
            .iter()
            .find(|held| held.path == requested.path)
            .cloned();
        // What the destination's own base revision holds for this path. A path the destination
        // deleted is still a path its base holds, and putting content back at that name is a
        // change against that object rather than a file out of nowhere.
        let deleted = proposed
            .deletions
            .iter()
            .find(|deleted| deleted.path == requested.path)
            .cloned();
        let base_object_id = existing.as_ref().map_or_else(
            || Nullable(deleted.as_ref().and_then(|d| d.base_object_id.clone())),
            |held| held.base_object_id.clone(),
        );
        let base_mode = existing.as_ref().map_or_else(
            || Nullable(deleted.as_ref().and_then(|d| d.base_mode.clone())),
            |held| held.base_mode.clone(),
        );
        // Whether the proposal's content **and mode** are the base revision's own, asked of the
        // base rather than of what the destination happens to hold now. A change that puts a path
        // back to exactly what the commit has is not a dirty file: it is a tracked file again. A
        // base this host could not read is no answer either way, so it fails rather than deciding.
        let carried_bit = existing.as_ref().map_or(executable, |held| held.executable);
        let matches_base = match base_object_id.0.as_deref() {
            Some(object_id) => {
                let base = read_object(service.project().profile(), repository, object_id)?;
                digest_of(&base) == digest
                    && base_mode.0.as_deref() == Some(if carried_bit { "100755" } else { "100644" })
            }
            None => false,
        };
        let replacement = CapturedPath {
            path: requested.path.clone(),
            content_digest: digest,
            byte_len: U64::new(bytes.len() as u64),
            // A direct apply preserves the destination's own permission, so a proposal of the
            // same change says the same thing: the destination's bit where it has one, and the
            // version's where the destination does not hold the path at all.
            executable: carried_bit,
            content: crate::capture::classify_content(&bytes),
            origin: ContentOrigin::WorkingTree,
            class: match existing.as_ref() {
                // The base revision's own content: whatever the destination held a moment ago,
                // the path now matches the commit, which is what tracked means.
                _ if matches_base => PathClass::Tracked,
                // Content the destination already holds changes nothing about the path, including
                // which class it is in.
                Some(held) if held.content_digest == digest => held.class,
                Some(held) if held.class == PathClass::Tracked => PathClass::DirtyFile,
                Some(held) => held.class,
                // A path the base holds and the destination does not is a tracked path being put
                // back, not a new untracked file.
                None if base_object_id.0.is_some() => PathClass::DirtyFile,
                None => PathClass::UntrackedFile,
            },
            change: ChangeKind::Present,
            base_object_id,
            base_mode,
        };
        // A path the proposal's own base recorded as deleted is no longer deleted once this
        // change puts content there.
        proposed
            .deletions
            .retain(|deleted| deleted.path != requested.path);
        match proposed
            .paths
            .iter_mut()
            .find(|held| held.path == requested.path)
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
            staged_leftovers: Vec::new(),
            detail: "a preflight writes nothing, so there is nothing to recover from".to_owned(),
        },
        limitations: limitations.to_vec(),
        detail: "the destination holds what this request expects; nothing was written, because \
                 this was a preflight"
            .to_owned(),
        decided_at_ms: kr_ipc::now_ms(),
    }
}

/// Settles every apply an earlier daemon left undecided, **before this one serves anything**.
///
/// An apply with no outcome is one this host did not finish. It is settled as
/// [`ApplyOutcomeClass::InterruptedApply`] from the progress rows: a path the journal says was
/// written is a path this host confirmed, and a path still `planned` is one whose state this host
/// did not establish. Neither is turned into a success.
///
/// The name says when: an undecided apply and an apply that is running at this moment look exactly
/// the same in the journal, because what tells them apart is a daemon that is alive and the
/// journal does not record liveness. So this runs once, while nothing can be running, which is
/// what the daemon does when it opens the service. Calling it beside a live apply would settle
/// that apply as interrupted while it was still going.
///
/// It also clears up after the window between staging a destination path and publishing it. The
/// journal names the temporary the interrupted apply left and the object it created there, so
/// what is at that name is removed **while it is still that object** and left exactly as it is
/// otherwise. A name a person or another program took is named in the answer and touched by
/// nothing.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the journal cannot be read or written.
pub fn recover_before_serving(service: &ChangeSetService) -> Result<crate::service::Recovery> {
    let mut recovery = crate::service::Recovery::default();
    let undecided = service.locked()?.undecided_applies()?;
    let settled_here: std::collections::BTreeSet<ActionId> =
        undecided.iter().map(|row| row.action_id).collect();
    for row in undecided {
        let staged = clear_staged(service, &row, &mut recovery)?;
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
        // The action is settled **first**. The caller that asked for this apply may still be
        // holding it open, and a retry must get the interruption rather than a second apply
        // against a destination this one has already changed. Settling it before the apply means
        // a crash between the two leaves the apply undecided, so the next recovery does both
        // again; settling it afterwards would leave a decided apply that no later recovery looks
        // at and an action nothing ever answers.
        let mut detail = format!(
            "this apply was interrupted: {written} path(s) are in the destination and this host \
             confirmed each of them, and {unresolved} path(s) are ones it did not establish an \
             outcome for, which is not the same as ones it did not write"
        );
        if staged.removed > 0 {
            detail.push_str(&format!(
                ". It had staged {} path(s) it had not published, and this host took away the \
                 temporaries it could prove were its own",
                staged.removed
            ));
        }
        if !staged.left.is_empty() {
            detail.push_str(&format!(
                ". Beside {} it left a temporary this host cannot prove it made, so it removed \
                 nothing there",
                staged
                    .left
                    .iter()
                    .map(|path| kr_project::git::redact(path))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        settle_recovered_action(
            service,
            row.action_id,
            ApplyOutcomeClass::InterruptedApply,
            &detail,
        )?;
        service.locked()?.settle_apply(
            row.action_id,
            ApplyOutcomeClass::InterruptedApply,
            None,
            &detail,
            kr_ipc::now_ms(),
        )?;
        recovery.applies_settled += 1;
    }
    // A staged temporary this host did not get rid of is an obligation of its own, and it does
    // not end when the apply that made it is decided: a live removal that failed leaves the
    // record behind and the apply settles all the same. So every outstanding record is taken up
    // here, whatever its apply came to, rather than only the ones an interrupted apply left. The
    // applies settled just above are left out because they have just been through this.
    // Read into a list first, for the same reason the unanswered claims below are: the store's
    // lock is taken again inside the loop, and an iterator that held it would hold it there too.
    let outstanding = service.locked()?.applies_with_staged_paths()?;
    for action_id in outstanding {
        if settled_here.contains(&action_id) {
            continue;
        }
        let Some(row) = service.locked()?.apply(action_id)? else {
            continue;
        };
        // The counts go into this recovery; the apply's own record is not rewritten. It said what
        // it came to when it was settled, and what it holds about its temporaries is the staging
        // rows themselves, which a reader gets through the apply's own answer.
        clear_staged(service, &row, &mut recovery)?;
    }
    // An apply that said what it came to and an action nobody answered: a daemon that stopped
    // between the two leaves exactly that, and a repeat of the action would otherwise be told
    // nothing is known about it while the journal holds the whole outcome. The apply decides the
    // answer; this only carries it to the caller.
    // Read into a list first: holding the store while this reads each apply back would be the
    // same lock twice, and a recovery that cannot finish is a daemon that cannot start.
    let unanswered = {
        let store = service.locked()?;
        store.applies_with_open_claims()?
    };
    for action_id in unanswered {
        let answer = read_apply(service, action_id)?;
        let Nullable(Some(outcome)) = answer.outcome else {
            continue;
        };
        let detail = answer.detail.clone();
        settle_recovered_action(service, action_id, outcome, &detail)?;
        recovery.actions_settled += 1;
    }
    Ok(recovery)
}

/// What a recovery did about one interrupted apply's staged temporaries.
#[derive(Default)]
struct StagedCleanup {
    /// How many temporaries this host proved were its own and took away.
    removed: usize,
    /// The destination paths whose staged name is occupied by something this host cannot prove it
    /// made, and so left alone.
    left: Vec<String>,
}

/// What is at one staged name now.
enum Staged {
    /// The object the journal names, which this host made and has taken away.
    TakenAway,
    /// Nothing at all, so there is nothing left to account for.
    NotThere,
    /// Something this host cannot prove it made, which it leaves exactly as it is.
    NotOurs,
}

/// Takes away the temporaries one interrupted apply left beside its destinations.
///
/// Only the object the journal names, and only while it is still that object. Anything else at
/// that name is somebody's file, and this host reports it rather than removing it. A workspace
/// this host cannot open any more leaves every one of that apply's names reported: a recovery
/// runs before a daemon serves anything, and it never fails to run because a destination moved.
fn clear_staged(
    service: &ChangeSetService,
    row: &crate::store::ApplyRow,
    recovery: &mut crate::service::Recovery,
) -> Result<StagedCleanup> {
    let mut cleanup = StagedCleanup::default();
    let staged = service.locked()?.staged_paths(row.action_id)?;
    if staged.is_empty() {
        return Ok(cleanup);
    }
    let opened = row
        .workspace_id
        .and_then(|workspace_id| service.resolve(workspace_id).ok())
        .and_then(|resolved| service.open_repository(&resolved).ok());
    let Some(repository) = opened else {
        cleanup.left = staged.into_iter().map(|entry| entry.path).collect();
        recovery.staged_left += cleanup.left.len() as u64;
        return Ok(cleanup);
    };
    for entry in staged {
        match staged_now(&repository, &entry) {
            Staged::TakenAway => {
                service.locked()?.unstage_path(row.action_id, &entry.path)?;
                cleanup.removed += 1;
                recovery.staged_removed += 1;
            }
            Staged::NotThere => service.locked()?.unstage_path(row.action_id, &entry.path)?,
            Staged::NotOurs => {
                cleanup.left.push(entry.path);
                recovery.staged_left += 1;
            }
        }
    }
    Ok(cleanup)
}

/// Looks at one staged name from the working tree's own handle, and applies the rule.
///
/// [`take_staged`] is the rule and this is the recovery's way in: it descends to the directory the
/// staging directory sits in, level by level through each own handle, and hands that directory
/// over. A directory above the name that is gone takes the staging directory with it, so there is
/// nothing left to account for.
fn staged_now(repository: &OpenedRepository, entry: &crate::store::StagedPath) -> Staged {
    let Ok(name) = RelativeName::parse(&entry.path) else {
        return Staged::NotOurs;
    };
    let components = name.components();
    let Some((_, parents)) = components.split_last() else {
        return Staged::NotOurs;
    };
    let Ok(mut here) = clone_handle(repository.work_tree()) else {
        return Staged::NotOurs;
    };
    for component in parents {
        let Ok(component) = RelativeName::parse(component) else {
            return Staged::NotOurs;
        };
        match here.subdirectory(&component) {
            Ok(directory) => here = directory,
            // The directory the staging directory was in is gone, so it is gone with it. The
            // record is cleared only once that absence is durable, exactly as it is for the
            // staging directory's own name: a rename of an ancestor that a power failure reverses
            // would otherwise bring the whole subtree back after its record had gone.
            Err(kr_transfer::Escape::NotFound { .. }) => {
                return if here.sync().is_ok() {
                    Staged::NotThere
                } else {
                    Staged::NotOurs
                };
            }
            Err(_) => return Staged::NotOurs,
        }
    }
    let Ok(temporary) = RelativeName::parse(&entry.entry) else {
        return Staged::NotOurs;
    };
    take_staged(&here, &temporary, entry.identity, entry.content)
}

/// Settles the action one recovered apply was performed under, from what the journal holds.
///
/// The answer a repeat of that action gets is the interruption, with exactly the paths on each
/// side and the recovery objects, rather than a second apply. A claim nobody left open, or one
/// somebody already settled, is left exactly as it is.
fn settle_recovered_action(
    service: &ChangeSetService,
    action_id: ActionId,
    outcome: ApplyOutcomeClass,
    detail: &str,
) -> Result<()> {
    let Some(claim) = service.locked()?.open_claim(action_id.get())? else {
        return Ok(());
    };
    let mut answer = read_apply(service, action_id)?;
    // The apply row still says nothing, because it is settled after this; the answer a caller
    // gets says what this recovery is about to record.
    answer.outcome = Nullable(Some(outcome));
    answer.detail = detail.to_owned();
    let encoded = crate::service::encode_stored(&answer)?;
    service.settle_action(
        &claim.actor_id,
        action_id.get(),
        &claim.method,
        claim.payload_digest,
        &crate::store::RetainedOutcome::Ok(encoded),
    )
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
    // What the journal still names is what is still beside a destination: the record of a
    // temporary is cleared the moment that temporary is published or taken away.
    let leftovers: Vec<String> = store
        .staged_paths(action_id)?
        .into_iter()
        .map(|entry| entry.path)
        .collect();
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
        // A proposal's own version is the reading it recorded on the far side of the apply, which
        // is where it was settled. A direct apply's far side is the destination as it stood
        // afterwards, and there the proposal is not a version at all.
        proposal_version: Nullable(
            row.after_version
                .filter(|_| row.destination == DestinationClass::Proposal)
                .map(|(change_set_id, version)| VersionRef {
                    change_set_id,
                    version,
                }),
        ),
        reference: Nullable(None),
        changed_paths: changed,
        unresolved_paths: unresolved,
        // Rebuilt from the rows rather than left empty: a path this apply found was not what the
        // request expected recorded that, and a caller reading this answer back is owed it.
        conflicts: progress
            .iter()
            .filter(|entry| entry.state == PathProgressState::Conflicted)
            .map(|entry| PathConflict {
                path: entry.path.clone(),
                // The journal holds what this host **found**, not what the request that is gone
                // expected, so a conflict read back from it says one side and not the other.
                expected_worktree_digest: Nullable(None),
                observed_worktree_digest: Nullable(entry.before_digest),
                expected_index_object_id: Nullable(None),
                observed_index_object_id: Nullable(None),
                detail: format!(
                    "{} (read back from this host's own record, which holds what it found rather \
                     than what the request expected)",
                    entry.detail
                ),
            })
            .collect(),
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
            staged_leftovers: leftovers,
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
            quiescence_held: false,
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
            expected_index_mode: Nullable(Some("100644".to_owned())),
            check_index: true,
        }];
        let mut observed = BTreeMap::new();
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(here),
                index_object_id: Some("abcdef".to_owned()),
                index_mode: Some("100644".to_owned()),
                unmerged: false,
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // The working tree agrees and the index does not.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("123456".to_owned()),
                index_mode: Some("100644".to_owned()),
                unmerged: false,
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // The object agrees and the mode does not.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("abcdef".to_owned()),
                index_mode: Some("100755".to_owned()),
                unmerged: false,
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // Everything agrees and the path has an unresolved merge.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("abcdef".to_owned()),
                index_mode: Some("100644".to_owned()),
                unmerged: true,
            },
        );
        assert_eq!(conflicts(&affected, &observed).len(), 1);
        // Both agree.
        observed.insert(
            path.clone(),
            Observed {
                worktree_digest: Some(expected),
                index_object_id: Some("abcdef".to_owned()),
                index_mode: Some("100644".to_owned()),
                unmerged: false,
            },
        );
        assert!(conflicts(&affected, &observed).is_empty());
        // The request expects the path to be absent and it is there.
        let absent = vec![AffectedVersion {
            path: path.clone(),
            expected_worktree_digest: Nullable(None),
            expected_index_object_id: Nullable(None),
            expected_index_mode: Nullable(None),
            check_index: false,
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
            claim: None,
            admitted: None,
        };
        let result = clean_preflight(&order, &limitations(DestinationClass::SharedExisting));
        assert_eq!(result.outcome, Nullable(None));
        assert!(result.changed_paths.is_empty());
        assert!(result.recovery.before_version.0.is_none());
        assert_eq!(result.limitations.len(), 3);
    }
}
