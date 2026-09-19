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
use kr_project::{OpenedRepository, ProjectService, RepositoryIdentity};
use kr_protocol::changeset::{
    ChangeSetVersionRecord, ChangeSetVersionSummary, EvidenceKind, EvidenceReference, Exclusion,
    MAX_CHANGESET_ENTRIES, Provenance, VersionRef,
};
use kr_protocol::ids::{
    ChangeSetId, ChangeSetVersion, EnvironmentId, ProjectRepositoryId, WorkspaceId,
};
use kr_protocol::project::{
    FilesystemIdentity, RetainedKind, WorkspaceReadParams, WorkspaceSummary,
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
    /// The two objects a record named.
    pub identity: RepositoryIdentity,
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
        Ok(ResolvedWorkspace {
            project_repository_id: summary.project_repository_id,
            path: PathBuf::from(&summary.display_path),
            identity: RepositoryIdentity {
                git_dir: object_identity(project.filesystem_identity),
                work_tree: object_identity(tree),
            },
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
        Ok(OpenedRepository::open_recorded(
            self.project.profile(),
            self.environment_id,
            &resolved.path,
            resolved.identity,
        )?)
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
        let captured = capture(
            self.project.profile(),
            &repository,
            &self.objects,
            &order.request,
        )?;
        let now = kr_ipc::now_ms();
        let (change_set_id, version, label) = {
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
                    let next = store
                        .latest_version(existing)?
                        .map_or(1, |latest| latest.get() + 1);
                    (existing, ChangeSetVersion::new(next), row.label)
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
                    (fresh, ChangeSetVersion::new(1), order.label.to_owned())
                }
            }
        };
        let repository_identity = kr_project::identity::wire_identity(resolved.identity.git_dir);
        let worktree_identity = kr_project::identity::wire_identity(resolved.identity.work_tree);
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
        consistency_detail: String,
    ) -> Result<ChangeSetVersionRecord> {
        let now = kr_ipc::now_ms();
        let version = {
            let store = self.locked()?;
            ChangeSetVersion::new(
                store
                    .latest_version(from.change_set_id)?
                    .map_or(1, |latest| latest.get() + 1),
            )
        };
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
                consistency: from.consistency,
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
            consistency: from.consistency,
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
                consistency: from.consistency,
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
    /// What kind of thing it is.
    pub kind: EvidenceKind,
    /// What it is, in this host's own words.
    pub detail: String,
}

impl ChangeSetService {
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
    /// before deletion. This is that account, and [`Self::delete_version`] refuses while it is not
    /// empty.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the journal cannot be read.
    pub fn holders(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<Holder>> {
        let mut held = Vec::new();
        for record in crate::materialise::outstanding(
            self,
            VersionRef {
                change_set_id,
                version,
            },
        )? {
            held.push(Holder {
                kind: EvidenceKind::Materialisation,
                detail: format!(
                    "materialisation {} at {} has not been released",
                    record.materialisation_id,
                    kr_project::git::redact(&record.directory_path)
                ),
            });
        }
        for reference in self.evidence(change_set_id, version)? {
            // A materialisation's own evidence row is the materialisation, which is counted above
            // from the materialisations themselves; counting it twice would report one thing as
            // two.
            if reference.kind == EvidenceKind::Materialisation {
                continue;
            }
            held.push(Holder {
                kind: reference.kind,
                detail: reference.detail,
            });
        }
        // A later version derived from this one names it in its own provenance, and a version
        // whose parent is gone cannot say where it came from.
        for summary in self.versions(change_set_id)? {
            if summary.derived_from.0.is_some_and(|parent| {
                parent.change_set_id == change_set_id && parent.version == version
            }) {
                held.push(Holder {
                    kind: EvidenceKind::AppliedChange,
                    detail: format!(
                        "version {} of this change set is derived from this one",
                        summary.version.get()
                    ),
                });
            }
        }
        // A pin recorded against the workspace through the project service holds it too.
        if let Ok(row) = self.locked()?.change_set(change_set_id)
            && let Some(row) = row
            && let Ok(retained) = self.project.retained(row.workspace_id)
        {
            for item in retained {
                if item.kind == RetainedKind::PinnedChangeSet
                    && item.change_set_id == Some(change_set_id)
                {
                    held.push(Holder {
                        kind: EvidenceKind::ReviewAcknowledgement,
                        detail: item.detail,
                    });
                }
            }
        }
        Ok(held)
    }

    /// Deletes one version, once nothing holds it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::WrongState`] naming everything that still holds it.
    pub fn delete_version(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<()> {
        let held = self.holders(change_set_id, version)?;
        if !held.is_empty() {
            let named: Vec<String> = held.iter().map(|holder| holder.detail.clone()).collect();
            return Err(ChangeSetError::WrongState {
                detail: format!(
                    "this version is still held by {} thing(s), so it is not deleted: {}",
                    held.len(),
                    named.join("; ")
                )
                .into(),
            });
        }
        self.locked()?.delete_version(change_set_id, version)
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
