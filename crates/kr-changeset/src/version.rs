//! The manifest of a captured tree, and the digest that identifies one version exactly.
//!
//! A version's identity is not its number. It is a digest taken over everything a reader relies
//! on: which repository and working tree it came from, which revision it is against, how
//! consistent its source was, which policy and grant decided it, every captured path with its
//! content digest and its mode, and every exclusion with its reason. Two versions with the same
//! digest are the same captured work.
//!
//! What the digest deliberately leaves out is the **provenance**: who captured it, in which
//! session, under which action. Two agents capturing the same tree under the same policy have
//! captured the same work, and a digest that said otherwise would make a test result unusable by
//! anybody but the actor that produced it.

use kr_protocol::changeset::{
    CaptureCount, CapturedPath, ContentOrigin, Exclusion, PathClass, SourceConsistency, TreeSummary,
};
use kr_protocol::ids::{EnvironmentId, ProjectRepositoryId, WorkspaceId};
use kr_protocol::project::{
    ChangeKind, ContentClass, FilesystemIdentity, InclusionClass, InclusionPolicy,
};
use kr_protocol::scalars::{Digest256, U64};
use sha2::{Digest as _, Sha256};

use crate::error::{ChangeSetError, Result};

/// The domain this digest is taken in.
///
/// A digest with no domain is a digest that could be mistaken for one of something else. This one
/// names the construction and its revision, so a later shape cannot collide with this one.
const DOMAIN: &[u8] = b"kalareach.changeset.version.v1";

/// The whole of one captured tree, as this service holds it.
///
/// This never travels on the wire: a captured tree can hold far more paths than one control frame
/// carries, so what a caller receives is the identity, the exact counts and the changes, and this
/// is what a materialisation is written from. It is stored beside the version's own row as
/// canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// Every path of the captured tree, sorted by path.
    pub paths: Vec<CapturedPath>,
    /// Every path the capture left out, sorted by path.
    pub exclusions: Vec<Exclusion>,
    /// Every path the working tree deleted, with what the base revision holds for it.
    ///
    /// A deletion is a change like any other: it is an operation an apply performs, an entry a
    /// diff read names, and a thing a revert has to be able to undo. Recording only that the path
    /// is absent would leave a revert with nothing to put back, so the base's own object and mode
    /// travel with it.
    #[serde(default)]
    pub deletions: Vec<DeletedPath>,
}

/// One path the working tree deleted, and what the base revision holds for it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeletedPath {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// The object the base revision holds for it, when this host read one.
    pub base_object_id: Option<String>,
    /// The mode the base revision records for it.
    pub base_mode: Option<String>,
    /// This host's own copy of what the base held, when the base held file content.
    ///
    /// A version is what it says it is wherever it is taken: reading the deleted file back out of
    /// the repository it came from would make a revert at another destination depend on that
    /// repository still holding the object, and on the object meaning the same thing there. So
    /// the content travels in the version's own store, and a base whose mode is not file content
    /// carries none, which is what makes a revert of it refuse rather than write the wrong kind
    /// of object.
    pub content_digest: Option<Digest256>,
}

impl Manifest {
    /// Sorts every list, so a manifest built in any order has one form.
    pub fn canonicalise(&mut self) {
        self.paths.sort_by(|a, b| a.path.cmp(&b.path));
        self.exclusions.sort_by(|a, b| a.path.cmp(&b.path));
        self.deletions.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// Returns the captured path with this name, when the tree holds one.
    #[must_use]
    pub fn path(&self, name: &str) -> Option<&CapturedPath> {
        self.paths
            .binary_search_by(|entry| entry.path.as_str().cmp(name))
            .ok()
            .map(|index| &self.paths[index])
    }

    /// Returns what the captured tree holds, in exact counts.
    #[must_use]
    pub fn summary(&self) -> TreeSummary {
        let mut summary = TreeSummary {
            total_paths: U64::new(self.paths.len() as u64),
            total_bytes: U64::new(0),
            from_git_objects: U64::new(0),
            from_working_tree: U64::new(0),
            deleted_paths: U64::new(self.deletions.len() as u64),
        };
        let mut bytes = 0_u64;
        let mut objects = 0_u64;
        let mut working = 0_u64;
        for entry in &self.paths {
            bytes = bytes.saturating_add(entry.byte_len.get());
            match entry.origin {
                ContentOrigin::GitObject => objects += 1,
                ContentOrigin::WorkingTree => working += 1,
            }
        }
        summary.total_bytes = U64::new(bytes);
        summary.from_git_objects = U64::new(objects);
        summary.from_working_tree = U64::new(working);
        summary
    }

    /// Returns one row per class, with exact counts over the captured tree.
    #[must_use]
    pub fn counts(&self) -> Vec<CaptureCount> {
        PathClass::EVERY
            .iter()
            .map(|class| {
                let mut total = 0_u64;
                let mut binary = 0_u64;
                let mut bytes = 0_u64;
                for entry in self.paths.iter().filter(|entry| entry.class == *class) {
                    total += 1;
                    if entry.content == ContentClass::Binary {
                        binary += 1;
                    }
                    bytes = bytes.saturating_add(entry.byte_len.get());
                }
                CaptureCount {
                    class: *class,
                    total: U64::new(total),
                    binary: U64::new(binary),
                    byte_len: U64::new(bytes),
                }
            })
            .collect()
    }

    /// Returns the paths whose content differs from the base revision.
    ///
    /// These are the included dirty, untracked and binary changes: what a reviewer looks at and
    /// what an apply carries. An ordinary tracked file the base already held is not one of them,
    /// whichever side this host read its content from.
    #[must_use]
    pub fn changes(&self) -> Vec<&CapturedPath> {
        self.paths
            .iter()
            .filter(|entry| entry.class.is_change())
            .collect()
    }

    /// Returns true when every captured path's content came from an immutable Git object.
    ///
    /// This is what an atomic snapshot **is** here: the object identifiers came from one index
    /// listing, which is one instant, and a Git object never changes once it exists. A capture
    /// that read one byte from the live working tree is not one.
    #[must_use]
    pub fn wholly_from_git_objects(&self) -> bool {
        self.paths
            .iter()
            .all(|entry| entry.origin == ContentOrigin::GitObject)
    }

    /// Refuses a manifest whose total exceeds what this host copies.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::QuotaExceeded`] with the figure.
    pub fn check_size(&self, limit: u64) -> Result<()> {
        let total = self.summary().total_bytes.get();
        if total > limit {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would hold {total} bytes and one capture holds at most {limit}"
                )
                .into(),
            });
        }
        Ok(())
    }
}

/// Everything besides the manifest that the identity digest covers.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The repository it was captured from.
    pub project_repository_id: ProjectRepositoryId,
    /// The workspace it was captured from.
    pub workspace_id: WorkspaceId,
    /// The repository's Git directory.
    pub repository_identity: FilesystemIdentity,
    /// The working tree it was captured from.
    pub worktree_identity: FilesystemIdentity,
    /// The revision it is against.
    pub base_revision: &'a str,
    /// How consistent the source was.
    pub consistency: SourceConsistency,
    /// One decision per class.
    pub policy: &'a InclusionPolicy,
    /// The prefixes the caller selected, sorted.
    pub included_paths: &'a [String],
    /// The prefixes the caller excluded, sorted.
    pub excluded_paths: &'a [String],
    /// True when the caller declared the working tree quiesced.
    pub quiescence_declared: bool,
    /// True when a reservation held the workspace still for the whole of the read.
    pub quiescence_held: bool,
}

/// A digest built from length-prefixed fields.
///
/// Every field is preceded by its own length, so no two different field lists produce the same
/// byte stream: a field ending where the next begins cannot be read as one longer field.
struct Absorb(Sha256);

impl Absorb {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update((DOMAIN.len() as u64).to_be_bytes());
        hasher.update(DOMAIN);
        Self(hasher)
    }

    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value);
        self
    }

    fn text(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    fn number(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    fn flag(&mut self, value: bool) -> &mut Self {
        self.number(u64::from(value))
    }

    fn finish(self) -> Digest256 {
        Digest256::from_bytes(self.0.finalize().into())
    }
}

/// Returns the digest that identifies one version exactly.
#[must_use]
pub fn identity_digest(subject: &Subject<'_>, manifest: &Manifest) -> Digest256 {
    let mut absorb = Absorb::new();
    absorb
        .bytes(subject.environment_id.get().as_bytes())
        .bytes(subject.project_repository_id.get().as_bytes())
        .bytes(subject.workspace_id.get().as_bytes())
        .number(subject.repository_identity.device.get())
        .number(subject.repository_identity.file_id.get())
        .number(subject.worktree_identity.device.get())
        .number(subject.worktree_identity.file_id.get())
        .text(subject.base_revision)
        .text(subject.consistency.as_str())
        .flag(subject.quiescence_declared)
        .flag(subject.quiescence_held);
    for class in InclusionClass::EVERY {
        absorb.text(class.as_str());
        absorb
            .flag(subject.policy.choice(*class) == kr_protocol::project::InclusionChoice::Include);
    }
    absorb.number(subject.included_paths.len() as u64);
    for prefix in subject.included_paths {
        absorb.text(prefix);
    }
    absorb.number(subject.excluded_paths.len() as u64);
    for prefix in subject.excluded_paths {
        absorb.text(prefix);
    }
    absorb.number(manifest.paths.len() as u64);
    for entry in &manifest.paths {
        absorb
            .text(&entry.path)
            .bytes(entry.content_digest.as_bytes())
            .number(entry.byte_len.get())
            .flag(entry.executable)
            .text(content_name(entry.content))
            .text(origin_name(entry.origin))
            .text(entry.class.as_str())
            .text(change_name(entry.change))
            .text(entry.base_mode.0.as_deref().unwrap_or(""));
    }
    absorb.number(manifest.exclusions.len() as u64);
    for exclusion in &manifest.exclusions {
        absorb.text(&exclusion.path).text(exclusion.reason.as_str());
    }
    absorb.number(manifest.deletions.len() as u64);
    for deleted in &manifest.deletions {
        // What the deletion restores is part of what the version is: two versions that delete the
        // same path from different base content are not the same version.
        absorb
            .text(&deleted.path)
            .text(deleted.base_object_id.as_deref().unwrap_or(""))
            .text(deleted.base_mode.as_deref().unwrap_or(""));
        match deleted.content_digest {
            Some(digest) => absorb.bytes(digest.as_bytes()),
            None => absorb.bytes(&[]),
        };
    }
    absorb.finish()
}

/// Returns the stable name of one content class.
#[must_use]
pub const fn content_name(content: ContentClass) -> &'static str {
    match content {
        ContentClass::Text => "text",
        ContentClass::Binary => "binary",
        ContentClass::Unknown => "unknown",
    }
}

/// Returns the stable name of one change kind.
#[must_use]
pub const fn change_name(change: ChangeKind) -> &'static str {
    match change {
        ChangeKind::Present => "present",
        ChangeKind::Deleted => "deleted",
        ChangeKind::Unmerged => "unmerged",
    }
}

/// Returns the stable name of one content origin.
#[must_use]
pub const fn origin_name(origin: ContentOrigin) -> &'static str {
    match origin {
        ContentOrigin::GitObject => "git_object",
        ContentOrigin::WorkingTree => "working_tree",
    }
}

/// What an identical source does not promise, in this host's own words.
///
/// Section 14: "Network services, dependencies, secrets and GUI state remain external inputs;
/// identical source alone does not promise hermetic reproduction." A version carries this rather
/// than leaving a reader to work it out.
#[must_use]
pub fn limitations() -> Vec<String> {
    vec![
        "this version identifies the source exactly and promises nothing about network services, \
         installed dependencies, secrets or graphical state, which are external inputs a captured \
         tree cannot hold"
            .to_owned(),
        "a secret or excluded file is not in this version and does not become attachment material \
         by being in the working tree"
            .to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::changeset::ExclusionReason;
    use kr_protocol::scalars::Nullable;

    fn path(name: &str, content: &[u8], origin: ContentOrigin) -> CapturedPath {
        CapturedPath {
            path: name.to_owned(),
            content_digest: crate::objects::digest_of(content),
            byte_len: U64::new(content.len() as u64),
            executable: false,
            content: ContentClass::Text,
            origin,
            class: PathClass::DirtyFile,
            change: ChangeKind::Present,
            base_object_id: Nullable(None),
            base_mode: Nullable(None),
        }
    }

    fn identity(device: u64, file_id: u64) -> FilesystemIdentity {
        FilesystemIdentity {
            device: U64::new(device),
            file_id: U64::new(file_id),
        }
    }

    fn subject<'a>(
        base: &'a str,
        consistency: SourceConsistency,
        policy: &'a InclusionPolicy,
        environment_id: EnvironmentId,
        project: ProjectRepositoryId,
        workspace: WorkspaceId,
    ) -> Subject<'a> {
        Subject {
            environment_id,
            project_repository_id: project,
            workspace_id: workspace,
            repository_identity: identity(1, 2),
            worktree_identity: identity(1, 3),
            base_revision: base,
            consistency,
            policy,
            included_paths: &[],
            excluded_paths: &[],
            quiescence_declared: false,
            quiescence_held: false,
        }
    }

    fn fixture() -> (EnvironmentId, ProjectRepositoryId, WorkspaceId, Manifest) {
        let mut manifest = Manifest {
            paths: vec![
                path("src/main.rs", b"fn main() {}", ContentOrigin::WorkingTree),
                {
                    let mut tracked = path("README.md", b"a repository", ContentOrigin::GitObject);
                    tracked.class = PathClass::Tracked;
                    tracked
                },
            ],
            exclusions: vec![Exclusion {
                path: ".env".to_owned(),
                reason: ExclusionReason::SecretRule,
                detail: "a secret rule covers it".to_owned(),
            }],
            deletions: Vec::new(),
        };
        manifest.canonicalise();
        (
            EnvironmentId::new(kr_ipc::new_uuid()),
            ProjectRepositoryId::new(kr_ipc::new_uuid()),
            WorkspaceId::new(kr_ipc::new_uuid()),
            manifest,
        )
    }

    #[test]
    fn the_same_captured_work_has_the_same_digest() {
        let (environment, project, workspace, manifest) = fixture();
        let policy = InclusionPolicy::base_only();
        let subject = subject(
            "abc123",
            SourceConsistency::PerFileCapture,
            &policy,
            environment,
            project,
            workspace,
        );
        assert_eq!(
            identity_digest(&subject, &manifest),
            identity_digest(&subject, &manifest)
        );
    }

    #[test]
    fn changing_any_one_thing_a_reader_relies_on_changes_the_digest() {
        let (environment, project, workspace, manifest) = fixture();
        let policy = InclusionPolicy::base_only();
        let base = subject(
            "abc123",
            SourceConsistency::PerFileCapture,
            &policy,
            environment,
            project,
            workspace,
        );
        let original = identity_digest(&base, &manifest);

        // A different base revision.
        let mut other = base;
        other.base_revision = "def456";
        assert_ne!(identity_digest(&other, &manifest), original);

        // A different consistency class, which is evidence a reader relies on.
        let mut other = base;
        other.consistency = SourceConsistency::AtomicSnapshot;
        assert_ne!(identity_digest(&other, &manifest), original);

        // A different working tree.
        let mut other = base;
        other.worktree_identity = identity(1, 9);
        assert_ne!(identity_digest(&other, &manifest), original);

        // A different policy.
        let included = kr_protocol::project::InclusionPolicy {
            dirty_files: kr_protocol::project::InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let mut other = base;
        other.policy = &included;
        assert_ne!(identity_digest(&other, &manifest), original);

        // One path's content.
        let mut changed = manifest.clone();
        changed.paths[1] = path(
            "src/main.rs",
            b"fn main() { work() }",
            ContentOrigin::WorkingTree,
        );
        assert_ne!(identity_digest(&base, &changed), original);

        // One path's mode.
        let mut changed = manifest.clone();
        changed.paths[1].executable = true;
        assert_ne!(identity_digest(&base, &changed), original);

        // One exclusion, which is what says a secret was left out.
        let mut changed = manifest.clone();
        changed.exclusions.clear();
        assert_ne!(identity_digest(&base, &changed), original);
    }

    #[test]
    fn who_captured_it_is_not_part_of_what_it_is() {
        // The provenance is recorded and is deliberately outside the digest: two agents capturing
        // the same work under the same policy have captured the same work, and a result about one
        // is a result about the other.
        let (environment, project, workspace, manifest) = fixture();
        let policy = InclusionPolicy::base_only();
        let subject = subject(
            "abc123",
            SourceConsistency::PerFileCapture,
            &policy,
            environment,
            project,
            workspace,
        );
        let first = identity_digest(&subject, &manifest);
        // Nothing about an actor, a session or an action reaches this function at all, which is
        // what the assertion is: the signature cannot carry one.
        let second = identity_digest(&subject, &manifest);
        assert_eq!(first, second);
    }

    #[test]
    fn two_field_lists_that_run_together_do_not_collide() {
        // Every field is length-prefixed, so "ab" then "c" is not "a" then "bc".
        let mut first = Absorb::new();
        first.text("ab").text("c");
        let mut second = Absorb::new();
        second.text("a").text("bc");
        assert_ne!(first.finish(), second.finish());
    }

    #[test]
    fn a_summary_counts_what_the_tree_holds_and_where_it_came_from() {
        let (_, _, _, manifest) = fixture();
        let summary = manifest.summary();
        assert_eq!(summary.total_paths.get(), 2);
        assert_eq!(summary.from_git_objects.get(), 1);
        assert_eq!(summary.from_working_tree.get(), 1);
        assert_eq!(
            summary.total_bytes.get(),
            (b"fn main() {}".len() + b"a repository".len()) as u64
        );
        // The changes are exactly what was read from the live tree.
        let changes = manifest.changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "src/main.rs");
    }

    #[test]
    fn a_capture_larger_than_the_bound_is_refused_with_the_figure() {
        let (_, _, _, manifest) = fixture();
        let failure = manifest
            .check_size(4)
            .expect_err("a tree above the bound is refused");
        assert!(
            failure.to_string().contains("at most 4"),
            "the refusal names the bound: {failure}"
        );
        manifest
            .check_size(u64::MAX)
            .expect("a tree under the bound is accepted");
    }
}
