//! The change-set service of one environment.
//!
//! It owns the versions, their content, their materialisations and the applies. What it does
//! **not** own is anything to do with Git or with a repository's identity: that is the project
//! service's, and every repository this service reads is opened through
//! [`kr_project::OpenedRepository`] under [`kr_project::ProjectService::profile`], inside the
//! execution boundary that profile carries.
//!
//! ```text
//! changeset.capture ─▶ an immutable version ─▶ pinned against its workspace
//!         │                     │
//!         │                     ├─▶ changeset.materialize ─▶ a private directory
//!         │                     │            │
//!         │                     │            └─▶ a result: the version, or a derived
//!         │                     │                 version, or an indeterminate source
//!         │                     │
//!         └─▶ diff.read         └─▶ diff.apply / diff.revert ─▶ one of five outcomes
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use kr_ipc::paths::EnvironmentPaths;
use kr_project::identity::object_identity;
use kr_project::store::RetainedRow;
use kr_project::{OpenedRepository, ProjectService};
use kr_protocol::changeset::{
    ChangeSetVersionRecord, ChangeSetVersionSummary, EvidenceKind, EvidenceReference, Exclusion,
    MAX_CHANGESET_ENTRIES, Provenance, SourceConsistency, VersionRef,
};
use kr_protocol::ids::{
    ChangeSetId, ChangeSetVersion, EnvironmentId, ProjectRepositoryId, WorkspaceId,
};
use kr_protocol::project::{
    FilesystemIdentity, IsolationMechanism, RetainedKind, WorkspaceReadParams, WorkspaceSummary,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_transfer::{AuthorisedDirectory, RelativeName};

use crate::capture::{CaptureRequest, capture};
use crate::error::{ChangeSetError, Result};
use crate::objects::ObjectStore;
use crate::store::{
    CHANGESETS_DIRECTORY, ChangeSetRow, EvidenceRow, STORE_FILE_NAME, Store, VersionRow,
};
use crate::version::{Manifest, Subject, identity_digest};

/// The directory, under this service's own root, that materialisations live in.
pub const MATERIALISATIONS_DIRECTORY: &str = "materialisations";

/// The directory, under this service's own root, that an apply stages validated content in.
pub const STAGING_DIRECTORY: &str = "staging";

/// The bounds a stored record is decoded under.
///
/// A manifest is not a control frame: it holds one entry per path of a captured tree, and a
/// working tree with a hundred thousand files is an ordinary working tree. The wire's own bounds
/// still apply to what a caller receives, which is the bounded record rather than the manifest.
pub fn stored_limits() -> kr_cbor::Limits {
    kr_cbor::Limits {
        max_message_len: 1 << 30,
        max_depth: 32,
        max_items: 64 << 20,
        max_collection_len: 8 << 20,
        max_bytes_len: 1 << 20,
        max_text_len: 1 << 20,
    }
}

/// What one workspace resolves to: where its tree is, and which objects a record named.
#[derive(Clone, Debug)]
pub struct ResolvedWorkspace {
    /// The workspace, as the project service holds it.
    pub summary: WorkspaceSummary,
    /// The repository it is a working copy of.
    pub project_repository_id: ProjectRepositoryId,
    /// The path its working tree is at.
    pub path: PathBuf,
    /// The object the workspace's own working tree is.
    pub work_tree: kr_transfer::ObjectIdentity,
    /// The Git directory the record names, for a workspace that shares the project's repository.
    ///
    /// Absent for an independent clone, which is its own repository: requiring the project's Git
    /// directory there would refuse a workspace this host created itself.
    pub git_dir: Option<kr_transfer::ObjectIdentity>,
}

/// What one capture is asked for.
#[derive(Clone, Debug)]
pub struct CaptureOrder<'a> {
    /// The workspace to capture.
    pub workspace_id: WorkspaceId,
    /// The change set to append a version to, or nothing to start a new one.
    pub change_set_id: Option<ChangeSetId>,
    /// The label a new change set is given.
    pub label: &'a str,
    /// What the capture reads.
    pub request: CaptureRequest<'a>,
    /// Pin the version against the workspace.
    pub pin: bool,
    /// Where it came from.
    pub provenance: Provenance,
}

/// What one recovery resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// How many applies an earlier daemon left undecided and this one settled.
    pub applies_settled: u64,
}

/// The change-set service of one environment.
#[derive(Debug)]
pub struct ChangeSetService {
    environment_id: EnvironmentId,
    project: Arc<ProjectService>,
    store: Mutex<Store>,
    objects: ObjectStore,
    root: AuthorisedDirectory,
    /// Runs immediately after one apply has written this many paths, so a test can stop an apply
    /// where a crash would stop it. Nothing in production sets it.
    #[cfg(feature = "fault-injection")]
    fault: Mutex<Option<crate::apply::Fault>>,
}

impl ChangeSetService {
    /// Opens the service for an environment, creating its store and directories on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StorageUnavailable`] or [`ChangeSetError::StoreUnavailable`] when
    /// either cannot be prepared.
    pub fn open(paths: &EnvironmentPaths, project: Arc<ProjectService>) -> Result<Self> {
        let environment_id = paths.environment_id();
        let root_path = Self::root_of(paths);
        kr_ipc::paths::create_private_tree(paths.state_root(), &root_path)
            .map_err(ChangeSetError::storage)?;
        let root = AuthorisedDirectory::open_root(environment_id, &root_path)?;
        let objects = ObjectStore::open(&root, environment_id)?;
        for name in [MATERIALISATIONS_DIRECTORY, STAGING_DIRECTORY] {
            root.create_subdirectory(&RelativeName::parse(name)?)?;
        }
        let store = Store::open(root_path.join(STORE_FILE_NAME), environment_id)?;
        Ok(Self {
            environment_id,
            project,
            store: Mutex::new(store),
            objects,
            root,
            #[cfg(feature = "fault-injection")]
            fault: Mutex::new(None),
        })
    }

    /// Returns the directory, under the environment's state directory, that this service owns.
    #[must_use]
    pub fn root_of(paths: &EnvironmentPaths) -> PathBuf {
        paths.state_dir().join(CHANGESETS_DIRECTORY)
    }

    /// Returns the environment this service owns.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the project service every repository read goes through.
    #[must_use]
    pub const fn project(&self) -> &Arc<ProjectService> {
        &self.project
    }

    /// Returns the content-addressed store.
    #[must_use]
    pub const fn objects(&self) -> &ObjectStore {
        &self.objects
    }

    /// Returns this service's own directory handle.
    #[must_use]
    pub const fn root(&self) -> &AuthorisedDirectory {
        &self.root
    }

    /// Runs something after one apply has written a given number of paths.
    ///
    /// Compiled with the fault-injection feature, so a test can stop an apply exactly where a
    /// crash would stop it and then prove what the journal says about it. Nothing in the service
    /// sets it.
    #[cfg(feature = "fault-injection")]
    pub fn inject(&self, fault: Option<crate::apply::Fault>) {
        if let Ok(mut held) = self.fault.lock() {
            *held = fault;
        }
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn fault(&self) -> Option<crate::apply::Fault> {
        self.fault.lock().ok().and_then(|held| held.clone())
    }

    pub(crate) fn locked(&self) -> Result<MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| ChangeSetError::StoreUnavailable {
                detail: "the change-set store was left poisoned by an earlier failure".into(),
            })
    }

    // ----- resolving a workspace ---------------------------------------------------------------

    /// Returns where one workspace's tree is and which objects its record named.
    ///
    /// # Errors
    ///
    /// Returns whatever the project service returns for an unknown workspace, and
    /// [`ChangeSetError::WrongState`] when the workspace has no working tree this host can prove
    /// it made.
    pub fn resolve(&self, workspace_id: WorkspaceId) -> Result<ResolvedWorkspace> {
        let read = self
            .project
            .workspace_read(&WorkspaceReadParams { workspace_id })?;
        let summary = read.workspace;
        let project = self
            .project
            .project_read(&kr_protocol::project::ProjectReadParams {
                project_repository_id: summary.project_repository_id,
            })?
            .project;
        let Nullable(Some(tree)) = summary.filesystem_identity else {
            return Err(ChangeSetError::WrongState {
                detail: "this workspace has no working tree this host recorded an identity for, \
                         so there is nothing to capture from"
                    .into(),
            });
        };
        // An independent clone is its own repository, so its Git directory is not the project's
        // and requiring it to be would refuse a workspace this host itself created. A shared tree
        // and a linked worktree do share the project's Git directory, and there the identity is
        // checked as well as the tree's.
        let shares_repository = summary.isolation.0 != Some(IsolationMechanism::IndependentClone);
        Ok(ResolvedWorkspace {
            project_repository_id: summary.project_repository_id,
            path: PathBuf::from(&summary.display_path),
            work_tree: object_identity(tree),
            git_dir: shares_repository.then(|| object_identity(project.filesystem_identity)),
            summary,
        })
    }

    /// Opens one workspace's repository under the project service's profile.
    ///
    /// # Errors
    ///
    /// Returns whatever the project service returns, including `SOURCE_CHANGED` when the objects
    /// at the recorded path are not the ones the record named.
    pub fn open_repository(&self, resolved: &ResolvedWorkspace) -> Result<OpenedRepository> {
        let opened =
            OpenedRepository::open(self.project.profile(), self.environment_id, &resolved.path)?;
        let found = opened.identity();
        if found.work_tree != resolved.work_tree {
            return Err(kr_project::ProjectError::IdentityChanged {
                detail: format!(
                    "this record names the working tree {}, and {} is the working tree {}; a \
                     linked worktree is its own object and a record of one never covers another",
                    resolved.work_tree,
                    kr_project::git::redact(&resolved.path.display().to_string()),
                    found.work_tree
                )
                .into(),
            }
            .into());
        }
        match resolved.git_dir {
            Some(git_dir) if found.git_dir != git_dir => {
                return Err(kr_project::ProjectError::IdentityChanged {
                    detail: format!(
                        "this workspace is a working copy of the repository {git_dir}, and the \
                         tree at its recorded path belongs to the repository {}; a recorded \
                         identity is the object rather than the path",
                        found.git_dir
                    )
                    .into(),
                }
                .into());
            }
            Some(_) => {}
            // An independent clone is its own repository, and the project service records no
            // identity for it, so there is nothing to compare its Git directory with. What is
            // required instead is the thing that makes it an independent clone: its repository is
            // **inside its own working tree**. A `.git` file rewritten to point at somebody else's
            // repository fails that, and so does a working tree whose repository is elsewhere.
            None => {
                if !opened.git_dir_path().starts_with(opened.top_level()) {
                    return Err(kr_project::ProjectError::IdentityChanged {
                        detail: "this workspace is an independent clone, and the tree at its \
                                 recorded path belongs to a repository outside it"
                            .into(),
                    }
                    .into());
                }
            }
        }
        Ok(opened)
    }

    /// Returns true when nothing this host knows of holds one workspace.
    ///
    /// The project service records every session and every automation run bound to a workspace,
    /// and this is the one mechanism behind a quiesced capture that is not a declaration.
    ///
    /// # Errors
    ///
    /// Returns whatever the project service returns for the read.
    pub fn nothing_holds(&self, workspace_id: WorkspaceId) -> Result<bool> {
        let read = self
            .project
            .workspace_read(&WorkspaceReadParams { workspace_id })?;
        Ok(read.workspace.bound_sessions.is_empty() && read.workspace.bound_runs.is_empty())
    }

    // ----- capture ------------------------------------------------------------------------------

    /// Captures one immutable version of one workspace.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::SourceChanged`] when the source kept changing past the bound, and
    /// whatever the project service or the store returns.
    pub fn capture(&self, order: &CaptureOrder<'_>) -> Result<(ChangeSetVersionRecord, bool)> {
        let resolved = self.resolve(order.workspace_id)?;
        let repository = self.open_repository(&resolved)?;
        let workspace_id = order.workspace_id;
        let quiet = || self.nothing_holds(workspace_id);
        let captured = capture(
            self.project.profile(),
            &repository,
            &self.objects,
            &order.request,
            &quiet,
        )?;
        let now = kr_ipc::now_ms();
        let (change_set_id, label) = {
            let store = self.locked()?;
            match order.change_set_id {
                Some(existing) => {
                    let row = store.change_set(existing)?.ok_or_else(|| {
                        ChangeSetError::UnknownVersion {
                            detail: format!("no change set {existing}").into(),
                        }
                    })?;
                    if row.workspace_id != order.workspace_id {
                        return Err(ChangeSetError::InvalidArgument(
                            "this change set was captured from another workspace, and a version \
                             of it is a version of that work rather than of this one"
                                .into(),
                        ));
                    }
                    (existing, row.label)
                }
                None => {
                    let fresh = ChangeSetId::new(kr_ipc::new_uuid());
                    store.insert_change_set(&ChangeSetRow {
                        change_set_id: fresh,
                        environment_id: self.environment_id,
                        project_repository_id: resolved.project_repository_id,
                        workspace_id: order.workspace_id,
                        label: order.label.to_owned(),
                        created_at_ms: now,
                    })?;
                    (fresh, order.label.to_owned())
                }
            }
        };
        // Both identities come from the repository this capture actually read, which for an
        // independent clone is the clone's own Git directory rather than the project's.
        let opened = repository.identity();
        let repository_identity = kr_project::identity::wire_identity(opened.git_dir);
        let worktree_identity = kr_project::identity::wire_identity(opened.work_tree);
        // The number is taken from a counter that only goes up, so a number a deleted version
        // used is never handed out again and two captures never choose the same one.
        let version = self.locked()?.reserve_version(change_set_id)?;
        let policy = kr_protocol::changeset::CapturePolicy {
            inclusion: *order.request.policy,
            grant: crate::grant::recorded(order.request.grant),
            quiescence_declared: order.request.quiescence_declared,
            required_consistency: Nullable(order.request.required_consistency),
        };
        let mut included = policy.grant.included_paths.clone();
        included.sort();
        let mut excluded = policy.grant.excluded_paths.clone();
        excluded.sort();
        let digest = identity_digest(
            &Subject {
                environment_id: self.environment_id,
                project_repository_id: resolved.project_repository_id,
                workspace_id: order.workspace_id,
                repository_identity,
                worktree_identity,
                base_revision: &captured.base_revision,
                consistency: captured.consistency,
                policy: order.request.policy,
                included_paths: &included,
                excluded_paths: &excluded,
                quiescence_declared: order.request.quiescence_declared,
            },
            &captured.manifest,
        );
        let record = self.build_record(
            change_set_id,
            version,
            digest,
            &label,
            &resolved,
            repository_identity,
            worktree_identity,
            &captured,
            policy,
            order.provenance.clone(),
            now,
        );
        let manifest_bytes = encode_stored(&captured.manifest)?;
        let record_bytes = encode_stored(&record)?;
        self.locked()?.insert_version(
            &VersionRow {
                change_set_id,
                version,
                content_digest: digest,
                consistency: captured.consistency,
                base_revision: captured.base_revision.clone(),
                derived_from: order
                    .provenance
                    .derived_from
                    .0
                    .map(|reference| reference.version),
                record: record_bytes,
                manifest: manifest_bytes,
                captured_at_ms: now,
            },
            &captured.objects,
        )?;
        let mut pinned = false;
        if order.pin {
            // The pin goes through the project service, so a workspace removal accounts for it
            // exactly as it accounts for dirty content and review evidence.
            self.project.retain(
                order.workspace_id,
                &RetainedRow {
                    kind: RetainedKind::PinnedChangeSet,
                    detail: format!(
                        "change set {change_set_id} version {} is pinned against this workspace",
                        version.get()
                    ),
                    change_set_id: Some(change_set_id),
                },
            )?;
            pinned = true;
        }
        Ok((record, pinned))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_record(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
        digest: kr_protocol::scalars::Digest256,
        label: &str,
        resolved: &ResolvedWorkspace,
        repository_identity: FilesystemIdentity,
        worktree_identity: FilesystemIdentity,
        captured: &crate::capture::Captured,
        policy: kr_protocol::changeset::CapturePolicy,
        provenance: Provenance,
        now: TimestampMs,
    ) -> ChangeSetVersionRecord {
        let changes: Vec<_> = captured.manifest.changes().into_iter().cloned().collect();
        let omitted_changes = changes.len().saturating_sub(MAX_CHANGESET_ENTRIES);
        let omitted_exclusions = captured
            .manifest
            .exclusions
            .len()
            .saturating_sub(MAX_CHANGESET_ENTRIES);
        ChangeSetVersionRecord {
            change_set_id,
            version,
            content_digest: digest,
            label: label.to_owned(),
            environment_id: self.environment_id,
            project_repository_id: resolved.project_repository_id,
            workspace_id: resolved.summary.workspace_id,
            repository_identity,
            worktree_identity,
            base_revision: captured.base_revision.clone(),
            base_reference: Nullable(captured.base_reference.clone()),
            consistency: captured.consistency,
            consistency_detail: captured.consistency_detail.clone(),
            policy,
            provenance,
            summary: captured.manifest.summary(),
            counts: captured.manifest.counts(),
            changes: changes.into_iter().take(MAX_CHANGESET_ENTRIES).collect(),
            omitted_changes: U64::new(omitted_changes as u64),
            exclusions: captured
                .manifest
                .exclusions
                .iter()
                .take(MAX_CHANGESET_ENTRIES)
                .cloned()
                .collect::<Vec<Exclusion>>(),
            omitted_exclusions: U64::new(omitted_exclusions as u64),
            limitations: crate::version::limitations(),
            captured_at_ms: now,
        }
    }

    // ----- reads ---------------------------------------------------------------------------------

    /// Returns one exact version's record.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::UnknownVersion`] when there is no such version.
    pub fn record(
        &self,
        change_set_id: ChangeSetId,
        version: Option<ChangeSetVersion>,
    ) -> Result<ChangeSetVersionRecord> {
        let store = self.locked()?;
        let version = match version {
            Some(named) => named,
            None => store.latest_version(change_set_id)?.ok_or_else(|| {
                ChangeSetError::UnknownVersion {
                    detail: format!("no change set {change_set_id}").into(),
                }
            })?,
        };
        let row = store.version(change_set_id, version)?.ok_or_else(|| {
            ChangeSetError::UnknownVersion {
                detail: format!("no version {} of change set {change_set_id}", version.get())
                    .into(),
            }
        })?;
        drop(store);
        decode_stored(&row.record)
    }

    /// Returns one exact version's whole manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::UnknownVersion`] when there is no such version.
    pub fn manifest(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Manifest> {
        let row = self
            .locked()?
            .version(change_set_id, version)?
            .ok_or_else(|| ChangeSetError::UnknownVersion {
                detail: format!("no version {} of change set {change_set_id}", version.get())
                    .into(),
            })?;
        decode_stored(&row.manifest)
    }

    /// Returns every version of one change set, oldest first.
    ///
    /// This is what attention reads to say that one version passed its tests and was reviewed
    /// while a later one has changes: the earlier version is exactly as it was, and the later one
    /// is visible beside it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn versions(&self, change_set_id: ChangeSetId) -> Result<Vec<ChangeSetVersionSummary>> {
        Ok(self
            .locked()?
            .versions(change_set_id)?
            .into_iter()
            .map(|row| ChangeSetVersionSummary {
                change_set_id: row.change_set_id,
                version: row.version,
                content_digest: row.content_digest,
                consistency: row.consistency,
                base_revision: row.base_revision,
                derived_from: Nullable(row.derived_from.map(|version| VersionRef {
                    change_set_id: row.change_set_id,
                    version,
                })),
                captured_at_ms: row.captured_at_ms,
            })
            .collect())
    }

    /// Returns everything that names one version and has to be accounted for before it is deleted.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn evidence(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<EvidenceReference>> {
        Ok(self
            .locked()?
            .evidence(change_set_id, version)?
            .into_iter()
            .map(|row| EvidenceReference {
                version: VersionRef {
                    change_set_id: row.change_set_id,
                    version: row.version,
                },
                kind: row.kind,
                detail: row.detail,
                recorded_at_ms: row.recorded_at_ms,
            })
            .collect())
    }

    /// Records one piece of evidence against a version.
    ///
    /// A review acknowledgement arrives here. It records that somebody acknowledged **this
    /// version** and does nothing else: no commit, no push, no revert, and no write to any working
    /// tree. Promotion is [`Self::apply`] under an authority of its own.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::UnknownVersion`] when there is no such version.
    pub fn record_evidence(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
        kind: EvidenceKind,
        detail: &str,
    ) -> Result<()> {
        let store = self.locked()?;
        if store.version(change_set_id, version)?.is_none() {
            return Err(ChangeSetError::UnknownVersion {
                detail: format!("no version {} of change set {change_set_id}", version.get())
                    .into(),
            });
        }
        store.record_evidence(&EvidenceRow {
            change_set_id,
            version,
            kind,
            detail: detail.to_owned(),
            recorded_at_ms: kr_ipc::now_ms(),
        })
    }

    /// Records one version and returns its record, for a version this service derives itself.
    ///
    /// Used by a modified materialisation and by a proposal apply: both produce a version whose
    /// content this host already holds, so there is nothing to read from a working tree.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub(crate) fn derive(
        &self,
        from: &ChangeSetVersionRecord,
        manifest: &Manifest,
        provenance: Provenance,
        consistency: SourceConsistency,
        consistency_detail: String,
    ) -> Result<ChangeSetVersionRecord> {
        let now = kr_ipc::now_ms();
        // From the same counter a capture takes its number from, so a derived version never
        // collides with one and never reuses a number a deleted version used.
        let version = self.locked()?.reserve_version(from.change_set_id)?;
        let mut included = from.policy.grant.included_paths.clone();
        included.sort();
        let mut excluded = from.policy.grant.excluded_paths.clone();
        excluded.sort();
        let digest = identity_digest(
            &Subject {
                environment_id: self.environment_id,
                project_repository_id: from.project_repository_id,
                workspace_id: from.workspace_id,
                repository_identity: from.repository_identity,
                worktree_identity: from.worktree_identity,
                base_revision: &from.base_revision,
                consistency,
                policy: &from.policy.inclusion,
                included_paths: &included,
                excluded_paths: &excluded,
                quiescence_declared: from.policy.quiescence_declared,
            },
            manifest,
        );
        let changes: Vec<_> = manifest.changes().into_iter().cloned().collect();
        let omitted_changes = changes.len().saturating_sub(MAX_CHANGESET_ENTRIES);
        let record = ChangeSetVersionRecord {
            change_set_id: from.change_set_id,
            version,
            content_digest: digest,
            label: from.label.clone(),
            environment_id: self.environment_id,
            project_repository_id: from.project_repository_id,
            workspace_id: from.workspace_id,
            repository_identity: from.repository_identity,
            worktree_identity: from.worktree_identity,
            base_revision: from.base_revision.clone(),
            base_reference: from.base_reference.clone(),
            consistency,
            consistency_detail,
            policy: from.policy.clone(),
            provenance,
            summary: manifest.summary(),
            counts: manifest.counts(),
            changes: changes.into_iter().take(MAX_CHANGESET_ENTRIES).collect(),
            omitted_changes: U64::new(omitted_changes as u64),
            exclusions: manifest
                .exclusions
                .iter()
                .take(MAX_CHANGESET_ENTRIES)
                .cloned()
                .collect(),
            omitted_exclusions: U64::new(
                manifest
                    .exclusions
                    .len()
                    .saturating_sub(MAX_CHANGESET_ENTRIES) as u64,
            ),
            limitations: crate::version::limitations(),
            captured_at_ms: now,
        };
        let objects: Vec<_> = {
            let mut digests: Vec<_> = manifest
                .paths
                .iter()
                .map(|entry| entry.content_digest)
                .collect();
            digests.sort_unstable();
            digests.dedup();
            digests
        };
        self.locked()?.insert_version(
            &VersionRow {
                change_set_id: from.change_set_id,
                version,
                content_digest: digest,
                consistency,
                base_revision: from.base_revision.clone(),
                derived_from: Some(from.version),
                record: encode_stored(&record)?,
                manifest: encode_stored(manifest)?,
                captured_at_ms: now,
            },
            &objects,
        )?;
        Ok(record)
    }
}

/// One thing that still holds a version, so a deletion has to account for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// True when it is a pin the project service holds against the workspace.
    ///
    /// A pin lives in the project service's own store rather than this one, which is why it is
    /// distinguished: it is checked before the transaction that removes a version rather than
    /// inside it.
    pub pinned: bool,
    /// What it is, in this host's own words.
    pub detail: String,
}

impl ChangeSetService {
    /// Returns one action's retained outcome, when this service has one.
    ///
    /// The change-set service keeps its own action record rather than sharing the project
    /// service's: a stored reply is read back through the rule by the code that knows which of its
    /// fields are this host's own explanations, and only this service knows that about its own
    /// results.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::IdConflict`] when the identifier was used for a different
    /// request.
    pub fn retained_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::scalars::Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
    ) -> Result<Option<crate::store::RetainedOutcome>> {
        self.locked()?
            .retained_action(actor_id, action_id, method, payload_digest)
    }

    /// Claims one action before its effect runs, returning true when this caller may act.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::IdConflict`] when the identifier was used for a different
    /// request.
    pub fn claim_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::scalars::Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
    ) -> Result<bool> {
        self.locked()?
            .claim_action(actor_id, action_id, method, payload_digest)
    }

    /// Settles one action this caller claimed.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn settle_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::scalars::Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
        outcome: &crate::store::RetainedOutcome,
    ) -> Result<()> {
        self.locked()?
            .settle_action(actor_id, action_id, method, payload_digest, outcome)
    }

    /// Gives one action's claim back, for an effect that wrote nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn release_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::scalars::Uuid,
    ) -> Result<()> {
        self.locked()?.release_action(actor_id, action_id)
    }

    /// Records one action's outcome, leaving an existing row alone.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn record_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::scalars::Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
        outcome: &crate::store::RetainedOutcome,
    ) -> Result<Option<crate::store::RetainedOutcome>> {
        self.locked()?
            .record_action(actor_id, action_id, method, payload_digest, outcome)
    }

    /// Resolves whatever an earlier daemon left unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn recover(&self) -> Result<Recovery> {
        crate::apply::recover(self)
    }

    /// Returns everything that still holds one version.
    ///
    /// Section 14: retention and pinning account for every materialisation and evidence reference
    /// before deletion. This is that account for a caller that wants to show it. What acts on it
    /// is [`Self::delete_version`], which counts again inside the transaction that removes the
    /// version, so nothing recorded in between is lost.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the journal cannot be read, and whatever
    /// the project service returns when its own pins cannot be read. A pin this host could not
    /// read is never treated as no pin.
    pub fn holders(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<Holder>> {
        let mut held = Vec::new();
        for pin in self.pins(change_set_id)? {
            held.push(Holder {
                pinned: true,
                detail: pin,
            });
        }
        for detail in self.locked()?.held_by_anything(change_set_id, version)? {
            held.push(Holder {
                pinned: false,
                detail,
            });
        }
        Ok(held)
    }

    /// Returns every pin the project service holds against this change set.
    ///
    /// A failure to read them is a failure, never an empty list: treating a store this host could
    /// not reach as one holding nothing is how a pinned version gets deleted.
    fn pins(&self, change_set_id: ChangeSetId) -> Result<Vec<String>> {
        let row = self.locked()?.change_set(change_set_id)?.ok_or_else(|| {
            ChangeSetError::UnknownVersion {
                detail: format!("no change set {change_set_id}").into(),
            }
        })?;
        Ok(self
            .project
            .retained(row.workspace_id)?
            .into_iter()
            .filter(|item| {
                item.kind == RetainedKind::PinnedChangeSet
                    && item.change_set_id == Some(change_set_id)
            })
            .map(|item| item.detail)
            .collect())
    }

    /// Deletes one version, once nothing holds it.
    ///
    /// The pin the project service holds is checked first, because it lives in another store; then
    /// the change-set store counts what it holds and removes the version **in one transaction**,
    /// so a materialisation, a result, an apply or a piece of evidence recorded in between is
    /// counted rather than lost. What is left, and is written down rather than hidden: a pin
    /// recorded in the project service between this host's reading of it and that transaction is
    /// not covered, because the two stores do not share one.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::WrongState`] naming everything that still holds it.
    pub fn delete_version(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<()> {
        let pinned = self.pins(change_set_id)?;
        if !pinned.is_empty() {
            return Err(ChangeSetError::WrongState {
                detail: format!(
                    "this version is pinned against its workspace, so it is not deleted: {}",
                    pinned.join("; ")
                )
                .into(),
            });
        }
        self.locked()?
            .delete_version_if_unheld(change_set_id, version)
    }
}

/// Encodes something this service stores.
pub(crate) fn encode_stored<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(value).map_err(|error| ChangeSetError::StoreUnavailable {
        detail: error.to_string().into(),
    })
}

/// Decodes something this service stored.
pub(crate) fn decode_stored<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T> {
    kr_cbor::from_canonical_slice(bytes, &stored_limits()).map_err(|error| {
        ChangeSetError::StoreUnavailable {
            detail: error.to_string().into(),
        }
    })
}
