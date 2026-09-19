//! Immutable change sets, their materialisations, and the diff read, apply and revert contract.
//!
//! Section 14 adds a first-class change set to the completion, tests, reviewer and attention
//! workflow, so that a test result and a review acknowledgement name **exact work** rather than
//! "the repository as it was at some point". Five properties shape every type here.
//!
//! * **A version is immutable and exactly identified.** [`ChangeSetVersionRecord`] carries the
//!   repository and workspace identity, the base revision, the selected paths' content hashes,
//!   the included dirty, untracked and binary changes, the exclusions, the capture policy and the
//!   provenance. Its [`ChangeSetVersionRecord::content_digest`] is taken over all of that, so two
//!   versions are the same version only when every one of those is the same. New edits produce a
//!   new version; nothing mutates the subject of an earlier test or review.
//! * **A capture says how consistent its source was.** [`SourceConsistency`] has three members and
//!   no default, and a capture that read a live working tree file by file is never described as a
//!   point-in-time snapshot. A workflow that needs the stronger class asks for it with
//!   [`ChangesetCaptureParams::required_consistency`] and is refused rather than served a weaker
//!   one.
//! * **Inclusion rules and file grants apply before the capture, not after it.** A path the policy
//!   excludes, a path the grant leaves out and a path a secret rule covers are never read, and each
//!   appears in [`ChangeSetVersionRecord::exclusions`] with the reason. A secret does not become
//!   attachment material by being in the tree.
//! * **A result names what was actually tested.** [`MaterialisationResult`] records the version,
//!   the executed command or profile, the environment and tool identity, the execution receipt and
//!   the output references. If the materialisation was modified, the result attests a *derived*
//!   version with its own identity; if the tested source cannot be established, it says
//!   [`TestedSource::Indeterminate`] rather than attesting the unmodified version.
//! * **An apply names its destination class and its outcome.** [`DestinationClass`] has three
//!   members, [`ApplyOutcomeClass`] has five, and a crash after one file cannot produce
//!   [`ApplyOutcomeClass::Applied`], because that class is recorded only once every path has
//!   landed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActionId, ActorId, ChangeSetId, ChangeSetVersion, EnvironmentId, MaterialisationId,
    ProjectRepositoryId, SessionId, WorkflowRunId, WorkspaceId,
};
use crate::project::{ChangeKind, ContentClass, FilesystemIdentity, InclusionPolicy};
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};

/// How many entries a change-set record lists before it says how many more there are.
///
/// A captured tree can hold a million paths and a record travels in one control frame, so the
/// lists are bounded and the counts are exact. The whole manifest lives in the host's own
/// content-addressed store, where a materialisation reads it.
pub const MAX_CHANGESET_ENTRIES: usize = 512;

/// Largest total one capture reads into the content-addressed store, in bytes.
///
/// A capture is a copy, and a working tree can hold more than a host should copy without being
/// asked. Above this the capture is refused with the figure rather than filling a disk.
pub const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How many times one path is re-read when it changed while this host was reading it.
///
/// Section 14 asks for concurrently changing files to be detected and retried within a bound or
/// rejected. This is that bound for one path; beyond it the capture is `SOURCE_CHANGED`.
pub const MAX_PATH_RETRIES: u32 = 3;

/// How many times a whole capture is repeated when the selection changed under it.
pub const MAX_CAPTURE_RETRIES: u32 = 2;

/// How consistent the source of one capture was.
///
/// There is no default and no fourth member that means "probably fine". A live multi-file capture
/// is [`Self::PerFileCapture`] unless a real mechanism made it something stronger, which is what
/// section 14 means by never advertising a point-in-time snapshot without one.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceConsistency {
    /// Every captured path's content came from an immutable Git object.
    ///
    /// The object identifiers were listed by one invocation, so they name one point in time, and a
    /// Git object never changes once it exists. That is a real point-in-time snapshot rather than a
    /// claim about timing, and it is the only way a capture reaches this class here: no filesystem
    /// this host runs on offers an unprivileged atomic snapshot of a directory tree.
    AtomicSnapshot,
    /// The caller declared the working tree quiesced and this host observed no change.
    ///
    /// The declaration is the caller's; the verification is this host's. Every file's identity,
    /// size and modification time are read before and after its content, and the selection is read
    /// again at the end. What this class asserts is both facts together, and neither alone.
    QuiescedCapture,
    /// Files were read one at a time from a live working tree.
    ///
    /// Concurrent changes are detected and retried within [`MAX_PATH_RETRIES`] and
    /// [`MAX_CAPTURE_RETRIES`], and beyond that the capture is rejected with `SOURCE_CHANGED`. The
    /// captured tree is still immutable and exactly identified; what it is not is one instant of
    /// the working tree.
    PerFileCapture,
}

impl SourceConsistency {
    /// Every class, strongest first.
    pub const EVERY: &'static [Self] = &[
        Self::AtomicSnapshot,
        Self::QuiescedCapture,
        Self::PerFileCapture,
    ];

    /// Returns the wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtomicSnapshot => "atomic_snapshot",
            Self::QuiescedCapture => "quiesced_capture",
            Self::PerFileCapture => "per_file_capture",
        }
    }

    /// Returns true when this class is at least as strong as the one a caller required.
    ///
    /// The order is the declaration order: an atomic snapshot satisfies a requirement for a
    /// quiesced capture, and a per-file capture satisfies neither.
    #[must_use]
    pub fn satisfies(self, required: Self) -> bool {
        self <= required
    }
}

/// Which part of the working tree one captured path came from.
///
/// The project service's [`crate::project::InclusionClass`] names the four classes a *policy*
/// decides about. A captured tree also holds the ordinary tracked files that no policy decision
/// touches, so this has a member for them: a count of "the tracked files" is what tells a reader
/// how much of the tree is the base's own content.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    /// A tracked file with no uncommitted change: the base's own content.
    Tracked,
    /// A tracked file with an uncommitted change.
    DirtyFile,
    /// A file Git neither tracks nor ignores.
    UntrackedFile,
    /// A file an ignore rule covers, which is what a build usually produces.
    GeneratedArtefact,
    /// A submodule working tree.
    Submodule,
}

impl PathClass {
    /// Every class, in the order a record lists them.
    pub const EVERY: &'static [Self] = &[
        Self::Tracked,
        Self::DirtyFile,
        Self::UntrackedFile,
        Self::GeneratedArtefact,
        Self::Submodule,
    ];

    /// Returns the wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tracked => "tracked",
            Self::DirtyFile => "dirty_file",
            Self::UntrackedFile => "untracked_file",
            Self::GeneratedArtefact => "generated_artefact",
            Self::Submodule => "submodule",
        }
    }

    /// Returns true when a path of this class is a change against the base revision.
    ///
    /// Everything but an ordinary tracked file is. This is what decides which paths a record
    /// lists as changes and which an apply carries.
    #[must_use]
    pub const fn is_change(self) -> bool {
        !matches!(self, Self::Tracked)
    }
}

/// One class's counts in a captured tree or a diff read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureCount {
    /// The class.
    pub class: PathClass,
    /// How many paths belong to it.
    pub total: U64,
    /// How many of those hold content this host classified as binary.
    pub binary: U64,
    /// Their total size in bytes.
    pub byte_len: U64,
}

/// Where one captured path's content came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContentOrigin {
    /// An immutable Git object, named by the index listing this capture read.
    GitObject,
    /// The working tree's own file, read while it was live.
    WorkingTree,
}

/// One path of a captured tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedPath {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// The SHA-256 digest of the content, which is also its name in the store.
    pub content_digest: Digest256,
    /// The content's length in bytes.
    pub byte_len: U64,
    /// True when the file is executable.
    ///
    /// The one permission bit a captured tree carries. A materialisation sets it and a
    /// materialisation of a tree without it never sets it, which is what "permissions preserved"
    /// comes to for content this host copies.
    pub executable: bool,
    /// What the content is, by Git's own test.
    pub content: ContentClass,
    /// Where it was read from.
    pub origin: ContentOrigin,
    /// Which part of the working tree it came from.
    pub class: PathClass,
    /// What change the working tree held for it when it was captured.
    pub change: ChangeKind,
    /// The Git object the base revision holds for this path, when it has one.
    pub base_object_id: Nullable<String>,
}

/// Why one path is not in a captured tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// The inclusion policy's choice for its class left it out.
    Policy,
    /// The caller's file grant did not select it, or excluded it by name.
    Grant,
    /// A secret rule covers it. Such a path is never read at all.
    SecretRule,
    /// It is not file content: a symbolic link, a device, a socket, a submodule's own tree.
    Unsupported,
    /// The working tree has deleted it, so the captured tree does not hold it either.
    ///
    /// A deletion is carried by the path's absence. This says the absence is the user's own edit
    /// rather than something the capture could not read.
    Deleted,
    /// This host could not read it.
    Unreadable,
}

impl ExclusionReason {
    /// Returns the wire name of this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Grant => "grant",
            Self::SecretRule => "secret_rule",
            Self::Unsupported => "unsupported",
            Self::Deleted => "deleted",
            Self::Unreadable => "unreadable",
        }
    }
}

/// One path a capture left out, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Why it is not in the captured tree.
    pub reason: ExclusionReason,
    /// What this host can say about it, in its own words.
    pub detail: String,
}

/// Which paths a caller's grant selects, before the inclusion policy decides anything.
///
/// A grant is applied **before** the capture reads anything, which is what stops a secret becoming
/// attachment material. An empty [`Self::included_paths`] means every path the policy allows; a
/// non-empty one means exactly those prefixes and nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileGrant {
    /// The path prefixes the caller selected. Empty means the policy decides alone.
    pub included_paths: Vec<String>,
    /// The path prefixes the caller excluded, whatever the policy says.
    pub excluded_paths: Vec<String>,
    /// Apply this host's own secret rules as well.
    ///
    /// There is no way to turn them off through the wire. The field exists so a record says the
    /// rules were applied rather than leaving a reader to assume it.
    pub secret_rules_applied: bool,
}

/// The whole policy one capture ran under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturePolicy {
    /// One decision per class of the working tree.
    pub inclusion: InclusionPolicy,
    /// What the caller's grant selected and excluded.
    pub grant: FileGrant,
    /// True when the caller declared the working tree quiesced for the capture.
    ///
    /// A declaration alone never decides the consistency class: this host verifies that nothing it
    /// read changed, and a declaration that fails that verification is a per-file capture.
    pub quiescence_declared: bool,
    /// The class the caller required, when it required one.
    pub required_consistency: Nullable<SourceConsistency>,
}

/// One exact version of one change set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    /// The change set.
    pub change_set_id: ChangeSetId,
    /// The version within it, counting from one.
    pub version: ChangeSetVersion,
}

/// Where one version came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The actor whose request produced it.
    pub actor_id: ActorId,
    /// The method that produced it.
    pub method: String,
    /// The session it was captured for, when it was captured for one.
    pub session_id: Nullable<SessionId>,
    /// The automation run it was captured for, when it was captured for one.
    pub workflow_run_id: Nullable<WorkflowRunId>,
    /// The version this one is derived from, when it is derived.
    ///
    /// A version derived from a modified materialisation names the version that was materialised.
    /// A version derived from an apply names the version that was applied.
    pub derived_from: Nullable<VersionRef>,
    /// Why it is derived, in this host's own words.
    pub derivation: String,
    /// What the caller said about it.
    pub note: String,
}

/// What a captured tree holds, in exact counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TreeSummary {
    /// How many paths the captured tree holds.
    pub total_paths: U64,
    /// Their total size in bytes.
    pub total_bytes: U64,
    /// How many of them came from an immutable Git object.
    pub from_git_objects: U64,
    /// How many of them were read from the live working tree.
    pub from_working_tree: U64,
    /// How many tracked paths the working tree had deleted, so the captured tree does not hold
    /// them.
    pub deleted_paths: U64,
}

/// One immutable change-set version.
///
/// The record a caller receives. The whole manifest is in the host's own content-addressed store;
/// what travels is the identity, the digest, the exact counts and the changes, because a captured
/// tree can hold far more paths than one control frame carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetVersionRecord {
    /// The change set this version belongs to.
    pub change_set_id: ChangeSetId,
    /// Which version it is, counting from one.
    pub version: ChangeSetVersion,
    /// The digest that identifies this version exactly.
    ///
    /// Taken over the repository and workspace identity, the base revision, every captured path
    /// with its content digest and mode, the exclusions and the capture policy. Two versions with
    /// the same digest are the same captured work; a version whose digest differs is different
    /// work, whatever else it shares.
    pub content_digest: Digest256,
    /// The label the caller gave the change set.
    pub label: String,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The repository it was captured from.
    pub project_repository_id: ProjectRepositoryId,
    /// The workspace it was captured from.
    pub workspace_id: WorkspaceId,
    /// The stable filesystem identity of the repository's Git directory.
    pub repository_identity: FilesystemIdentity,
    /// The stable filesystem identity of the working tree it was captured from.
    pub worktree_identity: FilesystemIdentity,
    /// The revision it was captured against.
    pub base_revision: String,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Nullable<String>,
    /// How consistent the source was.
    pub consistency: SourceConsistency,
    /// What decided that class, in this host's own words.
    pub consistency_detail: String,
    /// The policy it was captured under.
    pub policy: CapturePolicy,
    /// Where it came from.
    pub provenance: Provenance,
    /// What the captured tree holds.
    pub summary: TreeSummary,
    /// One row per class, with exact counts over the whole captured tree.
    pub counts: Vec<CaptureCount>,
    /// The paths whose content differs from the base, bounded by [`MAX_CHANGESET_ENTRIES`].
    pub changes: Vec<CapturedPath>,
    /// How many changed paths the list above left out.
    pub omitted_changes: U64,
    /// The paths this capture left out, bounded by [`MAX_CHANGESET_ENTRIES`].
    pub exclusions: Vec<Exclusion>,
    /// How many exclusions the list above left out.
    pub omitted_exclusions: U64,
    /// What this version cannot promise, in the host's own words.
    ///
    /// Identical source does not promise hermetic reproduction: network services, dependencies,
    /// secrets and graphical state are external inputs a captured tree says nothing about.
    pub limitations: Vec<String>,
    /// When it was captured.
    pub captured_at_ms: TimestampMs,
}

/// One version, as a list of them names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetVersionSummary {
    /// The change set.
    pub change_set_id: ChangeSetId,
    /// Which version it is.
    pub version: ChangeSetVersion,
    /// The digest that identifies it exactly.
    pub content_digest: Digest256,
    /// How consistent its source was.
    pub consistency: SourceConsistency,
    /// The revision it was captured against.
    pub base_revision: String,
    /// The version it is derived from, when it is derived.
    pub derived_from: Nullable<VersionRef>,
    /// When it was captured.
    pub captured_at_ms: TimestampMs,
}

/// What a materialisation of a version is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MaterialisationPurpose {
    /// A test run.
    Test,
    /// A reviewer's own copy.
    Review,
    /// Somebody looking at it.
    Inspection,
}

/// One independent materialisation of one exact version.
///
/// It is written from the host's own content-addressed store into a private directory, so the
/// agent whose working tree was captured can keep working without changing anybody's inputs. It
/// touches neither the repository nor the workspace it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialisationRecord {
    /// Its identity.
    pub materialisation_id: MaterialisationId,
    /// The version it holds.
    pub version: VersionRef,
    /// The digest of the version it was written from.
    pub content_digest: Digest256,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// What it is for.
    pub purpose: MaterialisationPurpose,
    /// The label the caller gave it.
    pub label: String,
    /// Where it is, for a person and for a tool the caller runs.
    pub directory_path: String,
    /// The stable filesystem identity of that directory.
    pub filesystem_identity: FilesystemIdentity,
    /// How many paths were written into it.
    pub paths_written: U64,
    /// The paths the version holds that this host could not write.
    pub unapplied: Vec<String>,
    /// When it was made.
    pub created_at_ms: TimestampMs,
    /// When it was released, once it has been.
    pub released_at_ms: Nullable<TimestampMs>,
}

/// What a result was actually run against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestedSource {
    /// The materialisation still held exactly the version, so the result attests that version.
    UnmodifiedVersion,
    /// The materialisation was modified, so the result attests a derived version of its own.
    DerivedVersion,
    /// This host could not establish what was tested, so the result attests nothing.
    ///
    /// A result must not say the unmodified version passed when the tested source cannot be
    /// established. This is what it says instead.
    Indeterminate,
}

/// Which tool produced a result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    /// Its name.
    pub name: String,
    /// Its version, as the tool itself reports it.
    pub version: String,
}

/// What one execution did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    /// When it started.
    pub started_at_ms: TimestampMs,
    /// When it ended.
    pub ended_at_ms: TimestampMs,
    /// Its exit status, when it ended with one.
    pub exit_status: Nullable<U64>,
    /// True when something stopped it rather than it finishing.
    pub stopped: bool,
    /// What the caller says about it.
    pub detail: String,
}

/// One thing an execution produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputReference {
    /// What it is.
    pub label: String,
    /// Its digest.
    pub digest: Digest256,
    /// Its length in bytes.
    pub byte_len: U64,
    /// What kind of thing it is: a log, a report, an artefact.
    pub kind: String,
}

/// What one test or reviewer session did with one materialisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialisationResult {
    /// The materialisation it ran against.
    pub materialisation_id: MaterialisationId,
    /// The version that was materialised.
    pub input_version: VersionRef,
    /// What was actually tested.
    pub tested_source: TestedSource,
    /// The version the result attests, when it attests one.
    ///
    /// The input version for [`TestedSource::UnmodifiedVersion`], the derived version for
    /// [`TestedSource::DerivedVersion`], and nothing at all for [`TestedSource::Indeterminate`].
    pub tested_version: Nullable<VersionRef>,
    /// The command that was executed, as the caller names it.
    pub command: String,
    /// The profile it was executed under, as the caller names it.
    pub profile: String,
    /// The environment it ran in.
    pub environment_id: EnvironmentId,
    /// Which tool produced it.
    pub tool: ToolIdentity,
    /// What the execution did.
    pub receipt: ExecutionReceipt,
    /// What it produced.
    pub outputs: Vec<OutputReference>,
    /// What this result does and does not say, in this host's own words.
    pub attestation: String,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// What kind of evidence names a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A reviewer acknowledged this version.
    ReviewAcknowledgement,
    /// A test result attests this version.
    TestResult,
    /// A materialisation of this version exists.
    Materialisation,
    /// An apply produced or consumed this version.
    AppliedChange,
}

/// One thing that names a version and has to be accounted for before it is deleted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    /// The version it names.
    pub version: VersionRef,
    /// What kind of evidence it is.
    pub kind: EvidenceKind,
    /// What it is, in this host's own words.
    pub detail: String,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// Where an apply or a revert puts what it carries.
///
/// There is no default. Section 14 makes an apply default to an immutable proposal rather than to
/// a blind overwrite of an actively edited working tree, and this type is how that default is
/// expressed: a caller that wants the working tree written names [`Self::SharedExisting`] and is
/// shown its limitation before it can choose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DestinationClass {
    /// An immutable proposal: a new change-set version, and no write to any working tree.
    ///
    /// The default, and the only class that cannot lose somebody's work. What it produces is a
    /// version a reviewer can materialise and a person can decide about.
    Proposal,
    /// A versioned Git reference, updated by expected-old-value compare-and-swap.
    ///
    /// Compare-and-swap on the **reference**. It does not atomically update a dirty working tree,
    /// and this host says so in the result rather than letting a caller assume otherwise.
    VersionedReference,
    /// The user's own working tree, written in place.
    ///
    /// Best-effort conflict detection, not universal no-clobber compare-and-swap. The limitation
    /// travels in [`DiffApplyResult::limitations`] and is returned by a preflight before the class
    /// can be chosen.
    SharedExisting,
}

impl DestinationClass {
    /// Returns the wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::VersionedReference => "versioned_reference",
            Self::SharedExisting => "shared_existing",
        }
    }
}

/// What one apply established about one path before it wrote anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectedVersion {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// The digest of the working-tree file the caller expects to find, or nothing for an absent
    /// path.
    pub expected_worktree_digest: Nullable<Digest256>,
    /// The Git object the caller expects the index to hold for it.
    pub expected_index_object_id: Nullable<String>,
}

/// The reference an apply to a versioned Git reference names, and the value it expects it at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedReference {
    /// The full reference name, such as `refs/heads/main`.
    pub name: String,
    /// The value it is expected to hold, or nothing when it is expected not to exist.
    pub expected_old_value: Nullable<String>,
}

/// What became of a versioned Git reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOutcome {
    /// The reference the request named.
    pub name: String,
    /// The value the request expected.
    pub expected_old_value: Nullable<String>,
    /// The value this host found.
    pub observed_old_value: Nullable<String>,
    /// True when the two agreed, which is what a compare-and-swap requires.
    pub compare_and_swap_held: bool,
    /// True when this host moved the reference.
    pub updated: bool,
    /// What this host did not do, and why, in its own words.
    pub limitation: String,
}

/// What became of one path an apply set out to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathProgressState {
    /// The apply recorded that it was going to write this path and has not established what
    /// became of it.
    ///
    /// This is what a crash between the write and the record leaves, and it means exactly that:
    /// not "unwritten". A person or a later apply decides.
    Planned,
    /// The content is in the destination and this host confirmed it.
    Written,
    /// The destination was not what the request expected, so nothing was written to it.
    Conflicted,
    /// This host could not establish what is at the destination.
    Unresolved,
    /// The path was not attempted, because the apply stopped before reaching it.
    Skipped,
}

impl PathProgressState {
    /// Returns the wire name of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Written => "written",
            Self::Conflicted => "conflicted",
            Self::Unresolved => "unresolved",
            Self::Skipped => "skipped",
        }
    }
}

/// One path's progress, recorded before and after the write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathProgress {
    /// The path.
    pub path: String,
    /// What became of it.
    pub state: PathProgressState,
    /// The digest of what was there before, when this host read it.
    pub before_digest: Nullable<Digest256>,
    /// The digest of what is there now, when this host read it.
    pub after_digest: Nullable<Digest256>,
    /// What this host can say about it.
    pub detail: String,
}

/// One path whose destination was not what the request expected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathConflict {
    /// The path.
    pub path: String,
    /// What the request expected the working tree to hold.
    pub expected_worktree_digest: Nullable<Digest256>,
    /// What this host found.
    pub observed_worktree_digest: Nullable<Digest256>,
    /// What the request expected the index to hold.
    pub expected_index_object_id: Nullable<String>,
    /// What this host found.
    pub observed_index_object_id: Nullable<String>,
    /// What the difference is, in this host's own words.
    pub detail: String,
}

/// What one apply or revert came to.
///
/// Five classes and no sixth. A crash after one file reaches
/// [`Self::InterruptedApply`] rather than [`Self::Applied`], because this host records
/// [`Self::Applied`] only once every path it planned has been confirmed in the destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcomeClass {
    /// The destination was not what the request expected, and nothing was written anywhere.
    PreflightConflict,
    /// Every path landed and this host confirmed each one.
    Applied,
    /// Some paths landed, and then the destination stopped being what the request expected.
    ConflictAfterPartialWrites,
    /// Some paths landed, and this host stopped before finishing.
    InterruptedApply,
    /// This host cannot say what the destination holds.
    UncertainOutcome,
}

impl ApplyOutcomeClass {
    /// Every class an apply distinguishes.
    pub const EVERY: &'static [Self] = &[
        Self::PreflightConflict,
        Self::Applied,
        Self::ConflictAfterPartialWrites,
        Self::InterruptedApply,
        Self::UncertainOutcome,
    ];

    /// Returns the wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreflightConflict => "preflight_conflict",
            Self::Applied => "applied",
            Self::ConflictAfterPartialWrites => "conflict_after_partial_writes",
            Self::InterruptedApply => "interrupted_apply",
            Self::UncertainOutcome => "uncertain_outcome",
        }
    }
}

/// What a person or a later apply can recover from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObjects {
    /// The immutable version of the destination as it stood before the apply.
    ///
    /// Captured before anything is written, so a person can see exactly what was replaced and a
    /// revert has something to put back.
    pub before_version: Nullable<VersionRef>,
    /// The immutable version of the destination as it stands after the apply.
    pub after_version: Nullable<VersionRef>,
    /// The version the apply carried.
    pub applied_version: Nullable<VersionRef>,
    /// The staging directory the validated content was written through, while it is still there.
    pub staged_path: Nullable<String>,
    /// What these objects are and are not, in this host's own words.
    pub detail: String,
}

/// Parameters of `changeset.capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetCaptureParams {
    /// The workspace to capture.
    pub workspace_id: WorkspaceId,
    /// The change set to append a version to, or nothing to start a new one.
    pub change_set_id: Nullable<ChangeSetId>,
    /// The label a new change set is given. Ignored when appending.
    pub label: String,
    /// One decision per class of the working tree.
    pub policy: InclusionPolicy,
    /// What the caller's grant selects and excludes.
    pub grant: FileGrant,
    /// True when the caller has quiesced the working tree for this capture.
    pub quiescence_declared: bool,
    /// The consistency class the caller requires, when it requires one.
    ///
    /// A capture that cannot reach it is refused rather than served a weaker class under a name
    /// the caller asked for.
    pub required_consistency: Nullable<SourceConsistency>,
    /// Pin the version against the workspace, so a removal accounts for it.
    pub pin: bool,
    /// The session this capture belongs to, for the provenance.
    pub session_id: Nullable<SessionId>,
    /// The automation run this capture belongs to, for the provenance.
    pub workflow_run_id: Nullable<WorkflowRunId>,
    /// What the caller wants recorded about it.
    pub note: String,
}

/// Result of `changeset.capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetCaptureResult {
    /// The version that now exists.
    pub version: ChangeSetVersionRecord,
    /// True when the version is pinned against its workspace.
    pub pinned: bool,
}

/// Parameters of `changeset.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetReadParams {
    /// The change set to read.
    pub change_set_id: ChangeSetId,
    /// The version to read, or nothing for the latest.
    pub version: Nullable<ChangeSetVersion>,
}

/// Result of `changeset.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetReadResult {
    /// The version that was asked for.
    pub version: ChangeSetVersionRecord,
    /// Every version of this change set, oldest first.
    ///
    /// This is what attention reads to say "version 3 passed these tests and was reviewed; version
    /// 4 has later changes": the earlier version stays exactly as it was and the later one is
    /// visible beside it.
    pub versions: Vec<ChangeSetVersionSummary>,
    /// The materialisations of the version that was asked for.
    pub materialisations: Vec<MaterialisationRecord>,
    /// The results recorded against those materialisations.
    pub results: Vec<MaterialisationResult>,
    /// Everything that names this version and has to be accounted for before it is deleted.
    pub evidence: Vec<EvidenceReference>,
}

/// Parameters of `changeset.materialize`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetMaterializeParams {
    /// The change set.
    pub change_set_id: ChangeSetId,
    /// The exact version to materialise.
    pub version: ChangeSetVersion,
    /// What the materialisation is for.
    pub purpose: MaterialisationPurpose,
    /// The label the caller gave it.
    pub label: String,
}

/// Result of `changeset.materialize`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesetMaterializeResult {
    /// The materialisation that now exists.
    pub materialisation: MaterialisationRecord,
    /// What an identical source does not promise, in this host's own words.
    pub limitations: Vec<String>,
}

/// Parameters of `diff.read`.
///
/// Exactly one of the two subjects is named: a workspace, which reads its live working tree, or a
/// change-set version, which reads what was captured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffReadParams {
    /// The workspace to read.
    pub workspace_id: Nullable<WorkspaceId>,
    /// The change set to read.
    pub change_set_id: Nullable<ChangeSetId>,
    /// The version of it to read, or nothing for the latest.
    pub version: Nullable<ChangeSetVersion>,
}

/// One path a diff read names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffEntry {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Which part of the working tree it came from.
    pub class: PathClass,
    /// What change is held for it.
    pub change: ChangeKind,
    /// What its content is.
    pub content: ContentClass,
    /// Its size in bytes, when this host could read one.
    pub byte_len: Nullable<U64>,
    /// The immutable Git object the base holds for this path, when it has one.
    ///
    /// This is the content revision of the base side.
    pub base_object_id: Nullable<String>,
    /// The digest of the content the working tree or the captured version holds.
    ///
    /// This is the content revision of the other side.
    pub content_digest: Nullable<Digest256>,
}

/// Result of `diff.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffReadResult {
    /// The environment that owns the subject.
    pub environment_id: EnvironmentId,
    /// The repository it is a read of.
    pub project_repository_id: ProjectRepositoryId,
    /// The workspace it is a read of.
    pub workspace_id: WorkspaceId,
    /// The stable filesystem identity of the repository's Git directory.
    pub repository_identity: FilesystemIdentity,
    /// The stable filesystem identity of the working tree.
    pub worktree_identity: FilesystemIdentity,
    /// The revision the changes are against.
    pub base_revision: String,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Nullable<String>,
    /// The revision `HEAD` names now.
    pub head_revision: String,
    /// The reference `HEAD` is on now, when it is on one.
    pub head_reference: Nullable<String>,
    /// The version this read is of, when it reads a captured version rather than a live tree.
    pub source_version: Nullable<VersionRef>,
    /// The tracked paths with a change, bounded by [`MAX_CHANGESET_ENTRIES`].
    pub tracked: Vec<DiffEntry>,
    /// The untracked and ignored paths, bounded by [`MAX_CHANGESET_ENTRIES`].
    pub untracked: Vec<DiffEntry>,
    /// How many entries the two lists left out. The counts still cover them.
    pub omitted_entries: U64,
    /// One row per class, with exact counts.
    pub counts: Vec<CaptureCount>,
    /// What this read cannot promise, in the host's own words.
    pub limitations: Vec<String>,
    /// When it was taken.
    pub read_at_ms: TimestampMs,
}

/// Parameters of `diff.apply` and `diff.revert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffApplyParams {
    /// The change set whose content is applied.
    pub change_set_id: ChangeSetId,
    /// The exact version of it.
    pub version: ChangeSetVersion,
    /// Where it goes. Explicit, with no default.
    pub destination: DestinationClass,
    /// The workspace the destination names, for every class but a bare proposal.
    pub workspace_id: Nullable<WorkspaceId>,
    /// The reference and its expected old value, for a versioned Git reference.
    pub expected_reference: Nullable<ExpectedReference>,
    /// What the request expects each affected path to hold now.
    ///
    /// The preflight compares every one of these with what is there. A path the request does not
    /// name is a path the preflight cannot check, so a request that names none is refused for a
    /// destination that writes.
    pub affected: Vec<AffectedVersion>,
    /// Which of the version's changed paths to apply. Empty means all of them.
    pub paths: Vec<String>,
    /// Run the preflight and stop, whatever it finds.
    pub preflight_only: bool,
    /// The limitations of the chosen destination, as the caller was shown them.
    ///
    /// A direct apply to a shared working tree is refused until the caller passes back the
    /// limitation this host returned for it, so the limitation is shown before the class is
    /// chosen rather than after.
    pub acknowledged_limitations: Vec<String>,
}

/// Result of `diff.apply` and `diff.revert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffApplyResult {
    /// The action it was performed under.
    pub action_id: ActionId,
    /// Which of the five classes it came to.
    ///
    /// Absent when nothing ran: a preflight that found the destination as the request expects has
    /// not applied anything, and the five classes describe an apply that did. A preflight that
    /// found a conflict is `DRAFT_CONFLICT` rather than a result, which is what section 14 asks
    /// for, so this is absent exactly when the destination was as expected and nothing was
    /// written.
    pub outcome: Nullable<ApplyOutcomeClass>,
    /// Where it was applied.
    pub destination: DestinationClass,
    /// The version the request carried.
    pub applied_version: VersionRef,
    /// The immutable proposal a proposal apply produced.
    pub proposal_version: Nullable<VersionRef>,
    /// What became of the reference, for a versioned Git reference.
    pub reference: Nullable<ReferenceOutcome>,
    /// Exactly the paths this host confirmed it changed.
    pub changed_paths: Vec<String>,
    /// Exactly the paths whose state this host could not establish.
    pub unresolved_paths: Vec<String>,
    /// What the preflight found, when it found anything.
    pub conflicts: Vec<PathConflict>,
    /// Every path's progress, recorded before and after its write.
    pub progress: Vec<PathProgress>,
    /// What a person or a later apply can recover from.
    pub recovery: RecoveryObjects,
    /// What this apply cannot promise, in the host's own words.
    pub limitations: Vec<String>,
    /// Why it came to what it came to.
    pub detail: String,
    /// When it was decided.
    pub decided_at_ms: TimestampMs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stronger_consistency_class_satisfies_a_weaker_requirement() {
        // Section 14 lets a workflow require the stronger source-consistency class. The order is
        // the declaration order, so an atomic snapshot answers every requirement and a per-file
        // capture answers only its own.
        assert!(SourceConsistency::AtomicSnapshot.satisfies(SourceConsistency::PerFileCapture));
        assert!(SourceConsistency::AtomicSnapshot.satisfies(SourceConsistency::QuiescedCapture));
        assert!(SourceConsistency::AtomicSnapshot.satisfies(SourceConsistency::AtomicSnapshot));
        assert!(SourceConsistency::QuiescedCapture.satisfies(SourceConsistency::PerFileCapture));
        assert!(!SourceConsistency::QuiescedCapture.satisfies(SourceConsistency::AtomicSnapshot));
        assert!(!SourceConsistency::PerFileCapture.satisfies(SourceConsistency::QuiescedCapture));
        assert!(!SourceConsistency::PerFileCapture.satisfies(SourceConsistency::AtomicSnapshot));
    }

    #[test]
    fn every_source_consistency_class_the_specification_names_has_a_member_and_a_name() {
        assert_eq!(SourceConsistency::EVERY.len(), 3);
        let names: Vec<&str> = SourceConsistency::EVERY
            .iter()
            .map(|c| c.as_str())
            .collect();
        assert_eq!(
            names,
            ["atomic_snapshot", "quiesced_capture", "per_file_capture"]
        );
    }

    #[test]
    fn every_apply_outcome_class_the_specification_names_has_a_member_and_a_name() {
        // Section 14 paragraph 5: results distinguish preflight conflict, applied, conflict after
        // partial writes, interrupted apply and uncertain outcome. Five, and no sixth that means
        // "probably fine".
        assert_eq!(ApplyOutcomeClass::EVERY.len(), 5);
        let names: Vec<&str> = ApplyOutcomeClass::EVERY
            .iter()
            .map(|class| class.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "preflight_conflict",
                "applied",
                "conflict_after_partial_writes",
                "interrupted_apply",
                "uncertain_outcome"
            ]
        );
    }

    #[test]
    fn a_destination_class_is_named_and_there_is_no_default() {
        // The type has no `Default`, so a caller cannot get a direct apply by leaving a field out.
        assert_eq!(DestinationClass::Proposal.as_str(), "proposal");
        assert_eq!(
            DestinationClass::VersionedReference.as_str(),
            "versioned_reference"
        );
        assert_eq!(DestinationClass::SharedExisting.as_str(), "shared_existing");
        let encoded =
            serde_json::to_string(&DestinationClass::Proposal).expect("a class encodes to JSON");
        assert_eq!(encoded, "\"proposal\"");
    }

    #[test]
    fn a_planned_path_is_not_a_path_that_was_not_written() {
        // The one state whose meaning a reader could get wrong. It says this host did not
        // establish what became of the path, which is what a crash between the write and the
        // record leaves behind.
        assert_eq!(PathProgressState::Planned.as_str(), "planned");
        assert_ne!(PathProgressState::Planned, PathProgressState::Skipped);
        assert_ne!(PathProgressState::Planned, PathProgressState::Unresolved);
    }

    #[test]
    fn every_path_class_has_a_name_and_only_the_tracked_one_is_not_a_change() {
        assert_eq!(PathClass::EVERY.len(), 5);
        let names: Vec<&str> = PathClass::EVERY
            .iter()
            .map(|class| class.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "tracked",
                "dirty_file",
                "untracked_file",
                "generated_artefact",
                "submodule"
            ]
        );
        assert!(!PathClass::Tracked.is_change());
        for class in &PathClass::EVERY[1..] {
            assert!(class.is_change(), "{} is a change", class.as_str());
        }
    }

    #[test]
    fn a_deletion_has_a_reason_of_its_own_rather_than_reading_as_something_unreadable() {
        // A path the user deleted and a path this host could not read are two different facts
        // about a captured tree, and a reader has to be able to tell them apart.
        assert_eq!(ExclusionReason::Deleted.as_str(), "deleted");
        assert_ne!(ExclusionReason::Deleted, ExclusionReason::Unreadable);
        assert_ne!(ExclusionReason::Deleted, ExclusionReason::Unsupported);
    }

    #[test]
    fn a_capture_policy_records_that_the_secret_rules_were_applied() {
        // There is no wire field that turns the host's own secret rules off. The grant says they
        // were applied so a reader does not have to assume it.
        let grant = FileGrant {
            included_paths: Vec::new(),
            excluded_paths: vec!["vendor/".to_owned()],
            secret_rules_applied: true,
        };
        let encoded = serde_json::to_value(&grant).expect("a grant encodes to a JSON object");
        let object = encoded.as_object().expect("it is an object");
        let mut fields: Vec<&String> = object.keys().collect();
        fields.sort();
        assert_eq!(
            fields,
            ["excluded_paths", "included_paths", "secret_rules_applied"]
        );
    }
}
