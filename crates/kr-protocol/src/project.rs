//! Project repositories, workspaces and the operations that create them.
//!
//! Section 14 keeps a *repository* and a *working copy* apart. A repository is an
//! environment-local source tree with a stable identity; a workspace is one selected working copy
//! of it together with the policy that says what a reviewer sees. `project_repository_id` names
//! the first and `workspace_id` names the second, and neither is ever a client-supplied path.
//!
//! Four consequences shape every type here.
//!
//! * **Identity is the object, not the name.** A repository's identity is the stable filesystem
//!   identity of its Git directory: the device and inode on Unix, the volume serial and file index
//!   on Windows. Renaming the checkout, adding a worktree or replacing the directory at the same
//!   path does not extend a grant, because the grant was recorded against the object.
//! * **A destination is authorised before it is written to.** `project.init`, `project.clone` and
//!   `project.adopt` name a parent directory the caller already holds authority over and one
//!   single-component name inside it. New content is staged in a private sibling and published
//!   only once the operation completed.
//! * **A credential is named, never carried.** A network operation names its remote, the provider
//!   that serves it and the approved credential broker. No type here has a field a credential
//!   could travel in, and a URL that carries one is refused rather than redacted after the fact.
//! * **A workspace is selected explicitly.** [`WorkspaceKind`] has two members and no default, and
//!   a creation carries the inclusion preview the user saw. Nothing cleans, stashes or discards
//!   untracked files to start a reviewer.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActionId, ChangeSetId, EnvironmentId, ProjectRepositoryId, SessionId, WorkflowRunId,
    WorkspaceId,
};
use crate::scalars::{DurationMs, Nullable, TimestampMs, U64};

/// How long a repository operation may run before the host stops it.
///
/// A clone reaches the network, so the bound is generous; it exists so a remote that accepts a
/// connection and then sends nothing cannot hold a staging directory open for ever.
pub const OPERATION_DEADLINE: DurationMs = DurationMs::new(30 * 60 * 1000);

/// How long one brokered Git read may run.
///
/// A status or a configuration read is local work on an already-open repository. A minute is far
/// beyond what any of them take and short enough that a wedged subprocess is noticed.
pub const GIT_READ_DEADLINE: DurationMs = DurationMs::new(60 * 1000);

/// Largest output one brokered Git invocation may produce, in bytes.
///
/// Section 14 asks for bounded subprocess output. A repository with a hundred thousand changed
/// paths is a real repository, and a helper that writes without end is not, so the bound is above
/// the first and far below memory.
pub const MAX_GIT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum length of a destination or entry name, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Maximum length of a remote URL, in bytes.
pub const MAX_REMOTE_URL_LEN: usize = 2048;

/// Maximum length of a display label a client shows, in characters.
pub const MAX_LABEL_LEN: usize = 255;

/// How many entries an inclusion preview lists before it says how many more there are.
///
/// The preview travels in one control frame and a working tree can hold a million untracked
/// files, so the list is bounded and the counts are exact. A user deciding whether to include
/// untracked files needs the count and a sample, not every name.
pub const MAX_PREVIEW_ENTRIES: usize = 512;

/// How many paths a preview reads to decide whether their content is binary.
///
/// The counts are exact for every class the status reports, because that costs one read of the
/// repository. Deciding whether a path's *content* is binary costs one file open each, and a
/// working tree with a build directory in it holds hundreds of thousands. Beyond this many the
/// preview says how many it did not read rather than pretending to have read them.
pub const MAX_BINARY_SCAN_ENTRIES: usize = 20_000;

/// The transports a repository operation may use.
///
/// An allowlist, because the question is not which transports Git can be talked into using (a list
/// nobody can close: `ext::`, `file://` to a submodule helper, a remote helper on the path) but
/// which ones this host validated. Everything else is refused with the reason, which is what
/// section 14 means by validating the transport before executing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTransport {
    /// `https://`. The credential broker supplies the authentication.
    Https,
    /// `ssh://`, or the `user@host:path` form. The broker supplies the key.
    Ssh,
    /// A local path on this host, used for a clone between two directories of the same machine.
    ///
    /// The path is an authorised source handle rather than a URL, so a `file://` URL that Git
    /// would hand to a helper never appears.
    LocalPath,
}

impl RemoteTransport {
    /// Returns the scheme this transport is named by in a URL.
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Ssh => "ssh",
            Self::LocalPath => "file",
        }
    }
}

/// A remote a repository operation reaches, and who authenticates it.
///
/// The URL is here; a credential is not, and there is no field one could travel in. What the host
/// records and what a diagnostic shows is this object, so a credential cannot leak through either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSpecification {
    /// The remote's name inside the repository, conventionally `origin`.
    pub remote_name: String,
    /// The validated transport.
    pub transport: RemoteTransport,
    /// The URL, with no user information and no credential.
    pub url: String,
    /// The provider that serves it, as the host resolved it from the host name.
    pub provider: String,
    /// The approved credential broker that authenticates it, when the transport needs one.
    ///
    /// Empty for a transport that needs no credential. A named broker is one the host has, and a
    /// name it does not have is refused before anything is executed.
    pub credential_broker: String,
}

/// What a destination looked like before an operation was allowed to use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DestinationState {
    /// Nothing exists at the name.
    Absent,
    /// A directory exists at the name and holds nothing.
    EmptyDirectory,
    /// A directory exists at the name and holds entries.
    NonEmptyDirectory,
    /// A file, a link or something else exists at the name.
    Occupied,
}

/// The one adoption flow this host supports for a destination that already exists.
///
/// Section 14 rejects a nonempty or existing destination *unless the user explicitly chooses an
/// independently supported adoption flow*, and forbids merging a clone into one. So there is
/// exactly one member: adopting a checkout that is already a Git repository, which reads what is
/// there and writes nothing into the working tree. A second member would have to be a merge, and
/// that is the thing the paragraph forbids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionFlow {
    /// Register an existing Git working tree as a repository, changing nothing inside it.
    ///
    /// The host reads the repository's own configuration under the restricted profile, records its
    /// filesystem identity and its current reference, and adds a row. It does not fetch, does not
    /// check anything out, does not touch the index and does not write into the working tree.
    ExistingCheckout,
}

/// How a repository came to be known to this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectOrigin {
    /// `project.init` created it empty.
    Initialised,
    /// `project.clone` cloned it from a remote.
    Cloned,
    /// `project.adopt` registered an existing checkout.
    Adopted,
}

/// What state one repository record is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectState {
    /// The repository exists and its identity matched the last time it was opened.
    Ready,
    /// The operation that would have created it is still running.
    Creating,
    /// The object the record names is gone, or a different object now holds its path.
    ///
    /// The record is kept rather than deleted: a repository whose disk was unmounted comes back,
    /// and a record that named an object which has been replaced is evidence rather than rubbish.
    /// Nothing is served from it until its identity matches again.
    Detached,
}

/// A repository's stable environment-local identity, as a client may show it.
///
/// The two numbers are the device and the object number of the Git directory: the inode on Unix
/// and the file index on Windows. They are metadata a client can display and compare; they are
/// never an authority, because authority is the opened handle the host holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemIdentity {
    /// The device or volume the object lives on.
    pub device: U64,
    /// The object's number within that device or volume.
    pub file_id: U64,
}

/// One repository, as a scoped read returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectSummary {
    /// Its environment-local identity.
    pub project_repository_id: ProjectRepositoryId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The label the user gave it.
    pub label: String,
    /// How it came to be known here.
    pub origin: ProjectOrigin,
    /// What state the record is in.
    pub state: ProjectState,
    /// The stable filesystem identity of its Git directory.
    pub filesystem_identity: FilesystemIdentity,
    /// The path it was created or adopted at, for a person to read.
    ///
    /// Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
    /// which is why every operation uses the recorded identity and an opened handle instead.
    pub display_path: String,
    /// The remote it was cloned from, when it has one.
    pub remote: Nullable<RemoteSpecification>,
    /// When the record was written.
    pub created_at_ms: TimestampMs,
    /// How many workspaces are selected on it.
    pub workspace_count: U64,
}

/// Which kind of working copy a workspace is.
///
/// There is no default. Section 14 requires the choice to be explicit, because the two have
/// different concurrency and different guarantees, and a host that picked one would be choosing
/// for the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceKind {
    /// The user's own working tree, used where it is.
    ///
    /// Dirty and untracked files stay exactly as they are. Concurrency is the limit of the tree
    /// itself: one working tree, one index, and every session bound to this workspace sees the
    /// other's edits. An apply to it is best-effort conflict detection rather than
    /// compare-and-swap.
    SharedExisting,
    /// A separate working tree materialised from a named base.
    ///
    /// The base is a revision or a change-set version, and what of the user's uncommitted work
    /// comes with it is the explicit inclusion policy. A Git worktree implements the isolation of
    /// working *files*; it shares repository metadata and runs under the same account, so it is not
    /// a security sandbox. Where that matters the host uses an independent clone.
    Isolated,
}

/// How an isolated workspace is separated from the user's own tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMechanism {
    /// A Git worktree: separate working files, shared repository metadata, same account.
    ///
    /// Not a security sandbox. A process in this workspace can read and write the repository's
    /// objects and references, which are the same ones the user's own tree uses.
    GitWorktree,
    /// An independent clone: its own object store and its own references.
    ///
    /// Used where shared metadata is not acceptable. It costs the objects it copies.
    IndependentClone,
}

/// What a workspace does with the user's uncommitted work.
///
/// Every member is a decision the user made, and none of them removes anything from the user's own
/// tree: an exclusion means the new workspace starts without that file, never that the file is
/// cleaned, stashed or discarded where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InclusionChoice {
    /// The workspace starts with this class of file copied in.
    Include,
    /// The workspace starts without it. The original stays where it is, untouched.
    Exclude,
}

/// The inclusion policy of an isolated workspace, one decision per class.
///
/// Section 14 names the five classes explicitly, so they are five fields rather than a list of
/// patterns: a user answering five questions can see what they answered, and a policy that is a
/// pattern language cannot be previewed honestly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InclusionPolicy {
    /// Tracked files with uncommitted modifications.
    pub dirty_files: InclusionChoice,
    /// Files Git does not track and does not ignore.
    pub untracked_files: InclusionChoice,
    /// Submodule working trees.
    pub submodules: InclusionChoice,
    /// Files whose content Git reports as binary.
    pub binary_files: InclusionChoice,
    /// Files an ignore rule covers, which is what a build usually produces.
    pub generated_artefacts: InclusionChoice,
}

impl InclusionPolicy {
    /// The policy that copies nothing uncommitted: a workspace that is exactly its base.
    #[must_use]
    pub const fn base_only() -> Self {
        Self {
            dirty_files: InclusionChoice::Exclude,
            untracked_files: InclusionChoice::Exclude,
            submodules: InclusionChoice::Exclude,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Exclude,
        }
    }

    /// Returns the choice this policy makes for one class.
    #[must_use]
    pub const fn choice(&self, class: InclusionClass) -> InclusionChoice {
        match class {
            InclusionClass::DirtyFile => self.dirty_files,
            InclusionClass::UntrackedFile => self.untracked_files,
            InclusionClass::Submodule => self.submodules,
            InclusionClass::BinaryFile => self.binary_files,
            InclusionClass::GeneratedArtefact => self.generated_artefacts,
        }
    }
}

/// Which class of the working tree one previewed entry belongs to.
///
/// The first four say where a path came from and a path has exactly one of them.
/// [`Self::BinaryFile`] is the exception: it cuts across the others, so it appears in the counts
/// and in [`PreviewEntry::binary`] rather than as a path's own class.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InclusionClass {
    /// A tracked file with uncommitted modifications.
    DirtyFile,
    /// A file Git neither tracks nor ignores.
    UntrackedFile,
    /// A submodule working tree.
    Submodule,
    /// A file whose content Git reports as binary.
    BinaryFile,
    /// A file an ignore rule covers.
    GeneratedArtefact,
}

impl InclusionClass {
    /// Every class a preview counts, in the order a preview lists them.
    pub const EVERY: &'static [Self] = &[
        Self::DirtyFile,
        Self::UntrackedFile,
        Self::Submodule,
        Self::BinaryFile,
        Self::GeneratedArtefact,
    ];

    /// Returns the wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirtyFile => "dirty_file",
            Self::UntrackedFile => "untracked_file",
            Self::Submodule => "submodule",
            Self::BinaryFile => "binary_file",
            Self::GeneratedArtefact => "generated_artefact",
        }
    }
}

/// One path an inclusion preview names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewEntry {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Which class it belongs to: where in the working tree it came from.
    pub class: InclusionClass,
    /// What change the working tree holds for it.
    pub change: ChangeKind,
    /// What its content is.
    ///
    /// This cuts across the other classes rather than replacing them: a dirty file may be binary,
    /// and a policy that includes dirty files and excludes binaries leaves this one out.
    pub content: ContentClass,
    /// Its size in bytes, when the host could read one.
    pub byte_len: Nullable<U64>,
    /// Whether the policy in force would copy it into the new workspace.
    pub included: bool,
}

/// What the working tree holds for one path.
///
/// A copy is not the only way to carry an inclusion: a deletion is carried by removing the path
/// from the new workspace, and a path this host cannot read is carried by neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// The content differs from the base, or the path is new.
    Present,
    /// The path is gone from the working tree and the base still has it.
    Deleted,
    /// The path has an unresolved merge.
    Unmerged,
}

/// What one path's content is, as far as this host read it.
///
/// The test for binary is Git's own: a null byte in the first eight thousand bytes of content as it
/// is stored. [`Self::Unknown`] is the honest third answer, for a path this host did not read
/// because the preview's scan bound was reached, or could not read at all. An unknown path is
/// treated as binary by an exclusion, because excluding what might be binary is the direction that
/// honours the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// Read, and no null byte in the first eight thousand bytes.
    Text,
    /// Read, and a null byte in the first eight thousand bytes.
    Binary,
    /// Not read, so neither.
    Unknown,
}

/// One class's counts in a preview.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewCount {
    /// The class.
    pub class: InclusionClass,
    /// How many paths in the working tree belong to it.
    pub total: U64,
    /// How many of them the policy in force would copy in.
    pub included: U64,
    /// Their total size in bytes, as far as the host could read it.
    pub byte_len: U64,
}

/// What a reviewer would see, before the workspace exists.
///
/// Section 14 requires the create interface to preview what will be included. This is that
/// preview as data: exact counts per class, a bounded sample of paths, and the base the
/// materialisation would start from. It is a read, so it creates nothing and changes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InclusionPreview {
    /// The repository the preview was taken on.
    pub project_repository_id: ProjectRepositoryId,
    /// The kind of workspace it was taken for.
    pub kind: WorkspaceKind,
    /// The policy it was taken under.
    pub policy: InclusionPolicy,
    /// The revision an isolated workspace would start from, as the repository resolved it.
    pub base_revision: String,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Nullable<String>,
    /// The change-set version an isolated workspace would materialise, when it names one.
    pub base_change_set_id: Nullable<ChangeSetId>,
    /// One row per class, with exact counts.
    pub counts: Vec<PreviewCount>,
    /// A bounded sample of the paths, grouped by class in [`InclusionClass::EVERY`] order.
    pub entries: Vec<PreviewEntry>,
    /// How many paths the sample left out. The counts still cover them.
    pub omitted_entries: U64,
    /// How many paths this host could not classify as text or binary.
    ///
    /// Reading every path's first bytes costs an open each, and a working tree with a build
    /// directory in it holds hundreds of thousands. Above [`MAX_BINARY_SCAN_ENTRIES`] the host
    /// stops reading and says how many it did not read rather than calling them text.
    pub unknown_content: U64,
    /// True when every count above is the whole of its class.
    ///
    /// False when a bound was reached: an ignored directory deeper or larger than the walk
    /// covers, or a directory this host could not list. Then each count is a lower bound and the
    /// limitations say which bound was reached.
    pub counts_complete: bool,
    /// What this preview cannot promise, in the host's own words.
    ///
    /// A shared workspace is not a sandbox; a worktree shares repository metadata; a working tree
    /// can change between the preview and the creation. A client shows this rather than deciding
    /// for the user.
    pub limitations: Vec<String>,
    /// When it was taken.
    pub taken_at_ms: TimestampMs,
}

/// What state one workspace is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    /// It exists and can be used.
    Ready,
    /// Its materialisation is still running.
    Materialising,
    /// The user asked for it to be removed and something it holds is retained.
    ///
    /// A workspace reaches this state rather than disappearing when it still holds dirty content,
    /// a pinned change set or review evidence. What is retained is listed, and the removal
    /// finishes when the user approves it.
    RemovalPending,
    /// It is gone. The record stays so a later read says what happened rather than nothing.
    Removed,
}

/// What a workspace removal does with what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    /// Keep everything. The workspace is removed only when it holds nothing.
    ///
    /// The one a client offers first, because it is the only one that cannot lose work. What the
    /// workspace holds is measured rather than assumed: its own uncommitted work as well as the
    /// pins and the review evidence recorded against it. When it holds something, nothing is
    /// removed and the result lists what.
    KeepEverything,
    /// Remove everything, including what is held.
    ///
    /// Section 14 keeps dirty content, pinned change sets and review evidence until the user
    /// approves their removal, so this policy *is* the approval: it follows a
    /// [`Self::KeepEverything`] request that listed what is held, and the result lists what went.
    ///
    /// There is deliberately no third policy that removes the working files while keeping the
    /// dirty content in them. Keeping content means capturing it, and capturing an immutable
    /// version of a workspace is the change-set service's; a policy that claimed to keep what it
    /// had just deleted would be a lie.
    RemoveRetained,
}

/// One thing a workspace holds that its removal would have to account for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedItem {
    /// What kind of thing it is.
    pub kind: RetainedKind,
    /// What it is, in the host's own words.
    pub detail: String,
    /// The change set it belongs to, when it belongs to one.
    pub change_set_id: Nullable<ChangeSetId>,
}

/// What kind of retained thing a workspace holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetainedKind {
    /// Uncommitted work in the workspace's own tree.
    DirtyContent,
    /// A change-set version something has pinned.
    PinnedChangeSet,
    /// Evidence of a review that bound to a version of this workspace.
    ReviewEvidence,
}

/// One workspace, as a scoped read returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSummary {
    /// Its identity.
    pub workspace_id: WorkspaceId,
    /// The repository it is a working copy of.
    pub project_repository_id: ProjectRepositoryId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The label the user gave it.
    pub label: String,
    /// Which kind it is.
    pub kind: WorkspaceKind,
    /// How an isolated workspace is separated, when it is one.
    pub isolation: Nullable<IsolationMechanism>,
    /// The inclusion policy it was created under.
    pub policy: InclusionPolicy,
    /// What state it is in.
    pub state: WorkspaceState,
    /// The revision it started from.
    pub base_revision: String,
    /// The change-set version it materialised, when it named one.
    pub base_change_set_id: Nullable<ChangeSetId>,
    /// The stable filesystem identity of its working tree, once this host has one.
    ///
    /// Absent while the workspace is being materialised, and absent afterwards only when the
    /// materialisation did not get as far as creating the tree. An absent identity is what refuses
    /// a removal: this host does not delete a directory it cannot prove it created.
    pub filesystem_identity: Nullable<FilesystemIdentity>,
    /// The path it was created at, for a person to read.
    pub display_path: String,
    /// Why it is in the state it is in, when it ended up there for a reason.
    pub detail: Nullable<String>,
    /// The sessions bound to it that are still live.
    ///
    /// A removal is refused while this is not empty, whatever retention policy it carries.
    pub bound_sessions: Vec<SessionId>,
    /// The automation runs bound to it that are still live.
    ///
    /// Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
    /// between two sessions or after its last one ended, so it is recorded separately and refuses
    /// a removal in the same way.
    pub bound_runs: Vec<WorkflowRunId>,
    /// What it holds that a removal would have to account for.
    pub retained: Vec<RetainedItem>,
    /// When it was created.
    pub created_at_ms: TimestampMs,
}

/// What state one repository operation is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// It is staging content and has published nothing.
    Staging,
    /// Staging finished, and the publication into the destination is under way.
    ///
    /// A daemon that dies here resolves the publication from the create token rather than starting
    /// another clone: whichever name holds the staged object decides what happened.
    Publishing,
    /// It completed and the repository exists.
    Completed,
    /// The caller cancelled it. The result says which staging paths were removed and which stayed.
    Cancelled,
    /// It failed. The reason is recorded and the staged content is cleaned up.
    Failed,
    /// It ran past [`OPERATION_DEADLINE`].
    Expired,
    /// It was interrupted and this host cannot say whether its publication landed.
    ///
    /// Reconciliation resolves it against the create token; until it does, a repeat of the same
    /// action is answered with this rather than performed again.
    Unknown,
}

/// One repository operation, as a read or a cancellation returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    /// The action that started it. This is the create token a reconciliation is decided against.
    pub action_id: ActionId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The repository it creates, allocated when the operation begins.
    pub project_repository_id: ProjectRepositoryId,
    /// Which method started it.
    pub method: String,
    /// What state it is in.
    pub state: OperationState,
    /// The remote it reaches, when it reaches one.
    pub remote: Nullable<RemoteSpecification>,
    /// The destination's state when the operation was admitted.
    pub destination_state: DestinationState,
    /// The staging paths that still exist, for a person to find.
    pub retained_staging_paths: Vec<String>,
    /// The staging paths this host removed.
    pub removed_staging_paths: Vec<String>,
    /// Why it ended, when it ended for a reason.
    pub detail: Nullable<String>,
    /// When it started.
    pub started_at_ms: TimestampMs,
    /// When it ended, once it has.
    pub ended_at_ms: Nullable<TimestampMs>,
}

/// Parameters of `project.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectListParams {
    /// The environment to list.
    pub environment_id: EnvironmentId,
}

/// Result of `project.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectListResult {
    /// The repositories, oldest first.
    pub projects: Vec<ProjectSummary>,
}

/// Parameters of `project.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectReadParams {
    /// The repository to read.
    pub project_repository_id: ProjectRepositoryId,
}

/// Result of `project.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectReadResult {
    /// The repository.
    pub project: ProjectSummary,
    /// Its workspaces.
    pub workspaces: Vec<WorkspaceSummary>,
    /// The operation that created it, when this host still has the record.
    pub operation: Nullable<OperationRecord>,
}

/// Where a repository operation puts what it creates.
///
/// A parent the caller already holds authority over, and one single-component name inside it. The
/// parent is named by a path the host resolves **once**, with its own ambient authority, into a
/// directory handle; everything after that is relative to the handle. A multi-component name is
/// refused, because the operation that creates the entry must not depend on a prefix resolved
/// after the check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DestinationRequest {
    /// The environment the repository will belong to.
    pub environment_id: EnvironmentId,
    /// The parent directory, as an absolute host path the caller chose.
    pub parent_path: String,
    /// The single name inside it. No separators, no traversal segment, no reserved device name.
    pub name: String,
}

/// Parameters of `project.init`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectInitParams {
    /// Where the repository goes.
    pub destination: DestinationRequest,
    /// The label the user gave it.
    pub label: String,
    /// The name of the initial branch, when the user chose one.
    pub initial_branch: Nullable<String>,
}

/// Result of `project.init`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectInitResult {
    /// The repository that now exists.
    pub project: ProjectSummary,
    /// The operation that created it.
    pub operation: OperationRecord,
}

/// Parameters of `project.clone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCloneParams {
    /// Where the clone goes.
    pub destination: DestinationRequest,
    /// The label the user gave it.
    pub label: String,
    /// The remote to clone, its validated transport, its provider and its credential broker.
    pub remote: RemoteSpecification,
}

/// Result of `project.clone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCloneResult {
    /// The repository that now exists.
    pub project: ProjectSummary,
    /// The operation that created it.
    pub operation: OperationRecord,
}

/// Parameters of `project.adopt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectAdoptParams {
    /// The checkout to adopt, named the same way a destination is.
    pub destination: DestinationRequest,
    /// The label the user gave it.
    pub label: String,
    /// The flow the user explicitly chose.
    ///
    /// There is no default. A destination that already exists is refused unless this names a flow,
    /// which is what section 14 requires.
    pub flow: AdoptionFlow,
}

/// Result of `project.adopt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectAdoptResult {
    /// The repository that is now known here.
    pub project: ProjectSummary,
    /// The operation that registered it.
    pub operation: OperationRecord,
}

/// Parameters of `project.operation.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOperationCancelParams {
    /// The action that started the operation to cancel.
    pub operation_action_id: ActionId,
}

/// Result of `project.operation.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOperationCancelResult {
    /// The operation, with its retained and removed staging paths.
    pub operation: OperationRecord,
    /// How many subprocesses this host owned and stopped.
    pub stopped_processes: U64,
}

/// Parameters of `workspace.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceListParams {
    /// The environment to list.
    pub environment_id: EnvironmentId,
    /// One repository to list, or none for every repository in the environment.
    pub project_repository_id: Nullable<ProjectRepositoryId>,
}

/// Result of `workspace.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceListResult {
    /// The workspaces, oldest first.
    pub workspaces: Vec<WorkspaceSummary>,
}

/// Parameters of `workspace.preview`, which is a read `workspace.create` shares its shape with.
///
/// This is not a method of its own: `workspace.create` carries the same fields and the daemon
/// answers the preview from the create parameters when `preview_only` is set. One shape means a
/// user cannot be shown a preview of a different policy from the one that is then created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCreateParams {
    /// The repository to make a working copy of.
    pub project_repository_id: ProjectRepositoryId,
    /// The label the user gave it.
    pub label: String,
    /// Which kind it is. Explicit, with no default.
    pub kind: WorkspaceKind,
    /// How an isolated workspace is separated. Ignored for a shared one.
    pub isolation: Nullable<IsolationMechanism>,
    /// The inclusion policy, one decision per class.
    pub policy: InclusionPolicy,
    /// The revision an isolated workspace starts from, when it names one directly.
    pub base_revision: Nullable<String>,
    /// The change-set version an isolated workspace materialises, when it names one.
    pub base_change_set_id: Nullable<ChangeSetId>,
    /// Where an isolated workspace's working tree goes.
    ///
    /// A shared workspace names none: it is the repository's own tree.
    pub destination: Nullable<DestinationRequest>,
    /// Return the preview and create nothing.
    ///
    /// The create interface previews first, and the preview is this method with nothing written.
    /// It is still a mutation in the registry, because the parameters are the same object and a
    /// caller that may not create a workspace has no business measuring one.
    pub preview_only: bool,
}

/// Result of `workspace.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCreateResult {
    /// The workspace, or nothing when this was a preview.
    pub workspace: Nullable<WorkspaceSummary>,
    /// What a reviewer would see, always.
    pub preview: InclusionPreview,
    /// The paths the policy included that this host could not carry into the workspace.
    ///
    /// A symbolic link, a device, a submodule's own working tree, and a path whose destination
    /// this host could not replace. The workspace exists and is usable; what it does not hold is
    /// named here rather than left for a reviewer to notice.
    pub unapplied: Vec<String>,
}

/// Parameters of `workspace.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadParams {
    /// The workspace to read.
    pub workspace_id: WorkspaceId,
}

/// Result of `workspace.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadResult {
    /// The workspace.
    pub workspace: WorkspaceSummary,
}

/// Parameters of `workspace.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRemoveParams {
    /// The workspace to remove.
    pub workspace_id: WorkspaceId,
    /// What the removal does with what the workspace holds.
    pub retention: RetentionPolicy,
}

/// Result of `workspace.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRemoveResult {
    /// The workspace, in the state the removal left it.
    pub workspace: WorkspaceSummary,
    /// True when this workspace's own working files are gone.
    ///
    /// Always false for a shared workspace: that tree is the user's own, and removing the selection
    /// removes no file. For an isolated one it means the tree is not there any more, whether this
    /// call removed it or found it already gone.
    pub working_files_removed: bool,
    /// What is still held, and is waiting for the user's approval.
    pub retained: Vec<RetainedItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_that_copies_nothing_excludes_every_class() {
        let policy = InclusionPolicy::base_only();
        for class in InclusionClass::EVERY {
            assert_eq!(
                policy.choice(*class),
                InclusionChoice::Exclude,
                "{} is excluded by the base-only policy",
                class.as_str()
            );
        }
    }

    #[test]
    fn every_inclusion_class_the_specification_names_has_a_field_and_a_name() {
        // Section 14 names five classes an isolated workspace decides about. A class with no field
        // would be a decision the policy cannot express, and one with no name would be a count a
        // client cannot label.
        assert_eq!(InclusionClass::EVERY.len(), 5);
        let mut names: Vec<&str> = InclusionClass::EVERY.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "binary_file",
                "dirty_file",
                "generated_artefact",
                "submodule",
                "untracked_file"
            ]
        );
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Exclude,
            submodules: InclusionChoice::Include,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Include,
        };
        assert_eq!(
            policy.choice(InclusionClass::DirtyFile),
            InclusionChoice::Include
        );
        assert_eq!(
            policy.choice(InclusionClass::UntrackedFile),
            InclusionChoice::Exclude
        );
        assert_eq!(
            policy.choice(InclusionClass::Submodule),
            InclusionChoice::Include
        );
        assert_eq!(
            policy.choice(InclusionClass::BinaryFile),
            InclusionChoice::Exclude
        );
        assert_eq!(
            policy.choice(InclusionClass::GeneratedArtefact),
            InclusionChoice::Include
        );
    }

    #[test]
    fn the_only_adoption_flow_writes_nothing_into_the_tree_it_adopts() {
        // Section 14 forbids merging a clone into an existing destination, so the one supported
        // flow is the one that reads. If a second member is ever added, this assertion is where
        // the reason has to be written down.
        let flow = AdoptionFlow::ExistingCheckout;
        assert_eq!(flow, AdoptionFlow::ExistingCheckout);
        let encoded = serde_json::to_string(&flow).expect("an adoption flow encodes");
        assert_eq!(encoded, "\"existing_checkout\"");
    }

    #[test]
    fn a_remote_specification_has_nowhere_for_a_credential_to_travel() {
        // The type is the contract: a remote names its broker and carries no secret. This test
        // fails the moment a field is added that a password would fit in.
        let remote = RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport: RemoteTransport::Https,
            url: "https://example.invalid/repository.git".to_owned(),
            provider: "example.invalid".to_owned(),
            credential_broker: "os-keychain".to_owned(),
        };
        let encoded =
            serde_json::to_value(&remote).expect("a remote specification encodes to a JSON object");
        let object = encoded.as_object().expect("it is an object");
        let mut fields: Vec<&String> = object.keys().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "credential_broker",
                "provider",
                "remote_name",
                "transport",
                "url"
            ]
        );
    }

    #[test]
    fn a_transport_names_the_scheme_it_is_validated_as() {
        assert_eq!(RemoteTransport::Https.scheme(), "https");
        assert_eq!(RemoteTransport::Ssh.scheme(), "ssh");
        assert_eq!(RemoteTransport::LocalPath.scheme(), "file");
    }
}
