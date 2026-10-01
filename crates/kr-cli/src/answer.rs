//! The host's answers the command line prints whole with `--json`, leaf by leaf.
//!
//! `kr project`, `kr workspace`, `kr changeset`, `kr diff` and `kr plugin` print the host's
//! answer in the shape the protocol gives it. Each leaf of that shape is said by what it is:
//!
//! * a number, a switch, an identifier, a digest and a word of a closed set through the protocol's
//!   own encoding ([`closed`]), which keeps the shape a script reading the protocol expects;
//! * content the person asked for, such as a repository's path, a workspace's label, a plugin's
//!   identifier or a change's paths, as [`Asked`] under the command's [`Request`], as it arrived;
//! * a Git revision, reference or mode and a digest that arrive as text through their grammar,
//!   said only when they match it;
//! * a sentence the host wrote, such as a limitation or an operation's detail, as its class and its
//!   length in the host's own words.
//!
//! A struct whose every leaf is of the first kind is written closed, whole.

use crate::output::{Asked, Document, Request, closed};
use kr_protocol::admission::LiveReleaseSummary;
use kr_protocol::catalogue::CatalogueDelegation;
use kr_protocol::catalogue::CatalogueListResult;
use kr_protocol::catalogue::CataloguePinResult;
use kr_protocol::catalogue::CatalogueRemoveResult;
use kr_protocol::catalogue::CatalogueSummary;
use kr_protocol::catalogue::CatalogueSyncResult;
use kr_protocol::catalogue::PluginAdmission;
use kr_protocol::catalogue::PluginCapabilityGrant;
use kr_protocol::catalogue::PluginEnableResult;
use kr_protocol::catalogue::PluginInstallResult;
use kr_protocol::catalogue::PluginListResult;
use kr_protocol::catalogue::PluginPinResult;
use kr_protocol::catalogue::PluginRemoveResult;
use kr_protocol::catalogue::PluginSummary;
use kr_protocol::changeset::CapturePolicy;
use kr_protocol::changeset::CapturedPath;
use kr_protocol::changeset::ChangeSetVersionRecord;
use kr_protocol::changeset::ChangeSetVersionSummary;
use kr_protocol::changeset::ChangesetCaptureResult;
use kr_protocol::changeset::ChangesetMaterializeResult;
use kr_protocol::changeset::ChangesetReadResult;
use kr_protocol::changeset::DiffApplyResult;
use kr_protocol::changeset::DiffEntry;
use kr_protocol::changeset::DiffReadResult;
use kr_protocol::changeset::EvidenceReference;
use kr_protocol::changeset::Exclusion;
use kr_protocol::changeset::ExecutionReceipt;
use kr_protocol::changeset::FileGrant;
use kr_protocol::changeset::MaterialisationRecord;
use kr_protocol::changeset::MaterialisationResult;
use kr_protocol::changeset::ObservedPath;
use kr_protocol::changeset::OutputReference;
use kr_protocol::changeset::PathConflict;
use kr_protocol::changeset::PathProgress;
use kr_protocol::changeset::Provenance;
use kr_protocol::changeset::RecoveryObjects;
use kr_protocol::changeset::ReferenceOutcome;
use kr_protocol::changeset::ToolIdentity;
use kr_protocol::project::InclusionPreview;
use kr_protocol::project::OperationRecord;
use kr_protocol::project::PreviewEntry;
use kr_protocol::project::ProjectAdoptResult;
use kr_protocol::project::ProjectCloneResult;
use kr_protocol::project::ProjectInitResult;
use kr_protocol::project::ProjectListResult;
use kr_protocol::project::ProjectSummary;
use kr_protocol::project::RemoteSpecification;
use kr_protocol::project::RetainedItem;
use kr_protocol::project::WorkspaceCreateResult;
use kr_protocol::project::WorkspaceListResult;
use kr_protocol::project::WorkspaceRemoveResult;
use kr_protocol::project::WorkspaceSummary;

/// `ChangesetCaptureResult`, in the shape the protocol answers it.
#[must_use]
pub fn changeset_capture_result(value: &ChangesetCaptureResult) -> Document {
    Document::new()
        .with("version", change_set_version_record(&value.version))
        .with("pinned", value.pinned)
        .with("ok", true)
}

/// `ChangeSetVersionRecord`, in the shape the protocol answers it.
fn change_set_version_record(value: &ChangeSetVersionRecord) -> Document {
    Document::new()
        .with("change_set_id", closed(&value.change_set_id))
        .with("version", closed(&value.version))
        .with("content_digest", closed(&value.content_digest))
        .with("label", Asked::text(Request::Changesets, &value.label))
        .with("environment_id", closed(&value.environment_id))
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("workspace_id", closed(&value.workspace_id))
        .with("repository_identity", closed(&value.repository_identity))
        .with("worktree_identity", closed(&value.worktree_identity))
        .with(
            "base_revision",
            crate::shown::git_revision(&value.base_revision),
        )
        .with(
            "base_reference",
            value
                .base_reference
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with("consistency", closed(&value.consistency))
        .with(
            "consistency_detail",
            crate::shown::exported(
                "ChangeSetVersionRecord",
                "consistency_detail",
                &value.consistency_detail,
            ),
        )
        .with("policy", capture_policy(&value.policy))
        .with("provenance", provenance(&value.provenance))
        .with("summary", closed(&value.summary))
        .with("counts", closed(&value.counts))
        .with(
            "changes",
            value.changes.iter().map(captured_path).collect::<Vec<_>>(),
        )
        .with("omitted_changes", closed(&value.omitted_changes))
        .with(
            "exclusions",
            value.exclusions.iter().map(exclusion).collect::<Vec<_>>(),
        )
        .with("omitted_exclusions", closed(&value.omitted_exclusions))
        .with(
            "limitations",
            value
                .limitations
                .iter()
                .map(|text| crate::shown::exported("ChangeSetVersionRecord", "limitations", text))
                .collect::<Vec<_>>(),
        )
        .with("captured_at_ms", closed(&value.captured_at_ms))
}

/// `CapturePolicy`, in the shape the protocol answers it.
fn capture_policy(value: &CapturePolicy) -> Document {
    Document::new()
        .with("inclusion", closed(&value.inclusion))
        .with("grant", file_grant(&value.grant))
        .with("quiescence_declared", value.quiescence_declared)
        .with("quiescence_held", value.quiescence_held)
        .with("required_consistency", closed(&value.required_consistency))
}

/// `FileGrant`, in the shape the protocol answers it.
fn file_grant(value: &FileGrant) -> Document {
    Document::new()
        .with(
            "included_paths",
            value
                .included_paths
                .iter()
                .map(|text| Asked::text(Request::Changesets, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "excluded_paths",
            value
                .excluded_paths
                .iter()
                .map(|text| Asked::text(Request::Changesets, text))
                .collect::<Vec<_>>(),
        )
        .with("secret_rules_applied", value.secret_rules_applied)
}

/// `Provenance`, in the shape the protocol answers it.
fn provenance(value: &Provenance) -> Document {
    Document::new()
        .with(
            "actor_id",
            Asked::text(Request::Changesets, &value.actor_id.to_string()),
        )
        .with("method", Asked::text(Request::Changesets, &value.method))
        .with("session_id", closed(&value.session_id))
        .with("workflow_run_id", closed(&value.workflow_run_id))
        .with("derived_from", closed(&value.derived_from))
        .with(
            "derivation",
            crate::shown::exported("Provenance", "derivation", &value.derivation),
        )
        .with(
            "note",
            crate::shown::exported("Provenance", "note", &value.note),
        )
}

/// `CapturedPath`, in the shape the protocol answers it.
fn captured_path(value: &CapturedPath) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Changesets, &value.path))
        .with("content_digest", closed(&value.content_digest))
        .with("byte_len", closed(&value.byte_len))
        .with("executable", value.executable)
        .with("content", closed(&value.content))
        .with("origin", closed(&value.origin))
        .with("class", closed(&value.class))
        .with("change", closed(&value.change))
        .with(
            "base_object_id",
            value
                .base_object_id
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with(
            "base_mode",
            value
                .base_mode
                .as_ref()
                .map(|text| crate::shown::git_mode(text)),
        )
}

/// `Exclusion`, in the shape the protocol answers it.
fn exclusion(value: &Exclusion) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Changesets, &value.path))
        .with("reason", closed(&value.reason))
        .with(
            "detail",
            crate::shown::exported("Exclusion", "detail", &value.detail),
        )
}

/// `ChangesetReadResult`, in the shape the protocol answers it.
#[must_use]
pub fn changeset_read_result(value: &ChangesetReadResult) -> Document {
    Document::new()
        .with("version", change_set_version_record(&value.version))
        .with(
            "versions",
            value
                .versions
                .iter()
                .map(change_set_version_summary)
                .collect::<Vec<_>>(),
        )
        .with(
            "materialisations",
            value
                .materialisations
                .iter()
                .map(materialisation_record)
                .collect::<Vec<_>>(),
        )
        .with(
            "results",
            value
                .results
                .iter()
                .map(materialisation_result)
                .collect::<Vec<_>>(),
        )
        .with(
            "evidence",
            value
                .evidence
                .iter()
                .map(evidence_reference)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `ChangeSetVersionSummary`, in the shape the protocol answers it.
fn change_set_version_summary(value: &ChangeSetVersionSummary) -> Document {
    Document::new()
        .with("change_set_id", closed(&value.change_set_id))
        .with("version", closed(&value.version))
        .with("content_digest", closed(&value.content_digest))
        .with("consistency", closed(&value.consistency))
        .with(
            "base_revision",
            crate::shown::git_revision(&value.base_revision),
        )
        .with("derived_from", closed(&value.derived_from))
        .with("captured_at_ms", closed(&value.captured_at_ms))
}

/// `MaterialisationRecord`, in the shape the protocol answers it.
fn materialisation_record(value: &MaterialisationRecord) -> Document {
    Document::new()
        .with("materialisation_id", closed(&value.materialisation_id))
        .with("version", closed(&value.version))
        .with("content_digest", closed(&value.content_digest))
        .with("environment_id", closed(&value.environment_id))
        .with("purpose", closed(&value.purpose))
        .with("label", Asked::text(Request::Changesets, &value.label))
        .with(
            "directory_path",
            Asked::text(Request::Changesets, &value.directory_path),
        )
        .with("filesystem_identity", closed(&value.filesystem_identity))
        .with("paths_written", closed(&value.paths_written))
        .with(
            "unapplied",
            value
                .unapplied
                .iter()
                .map(|text| Asked::text(Request::Changesets, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "observed",
            value.observed.iter().map(observed_path).collect::<Vec<_>>(),
        )
        .with("created_at_ms", closed(&value.created_at_ms))
        .with("released_at_ms", closed(&value.released_at_ms))
}

/// `ObservedPath`, in the shape the protocol answers it.
fn observed_path(value: &ObservedPath) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Changesets, &value.path))
        .with("device", closed(&value.device))
        .with("file_id", closed(&value.file_id))
        .with("byte_len", closed(&value.byte_len))
        .with("written_at_nanos", closed(&value.written_at_nanos))
}

/// `MaterialisationResult`, in the shape the protocol answers it.
fn materialisation_result(value: &MaterialisationResult) -> Document {
    Document::new()
        .with("materialisation_id", closed(&value.materialisation_id))
        .with("input_version", closed(&value.input_version))
        .with("tested_source", closed(&value.tested_source))
        .with("tested_version", closed(&value.tested_version))
        .with(
            "derived_output_version",
            closed(&value.derived_output_version),
        )
        .with("command", Asked::text(Request::Changesets, &value.command))
        .with("profile", Asked::text(Request::Changesets, &value.profile))
        .with("environment_id", closed(&value.environment_id))
        .with("tool", tool_identity(&value.tool))
        .with("receipt", execution_receipt(&value.receipt))
        .with(
            "outputs",
            value
                .outputs
                .iter()
                .map(output_reference)
                .collect::<Vec<_>>(),
        )
        .with(
            "attestation",
            crate::shown::exported("MaterialisationResult", "attestation", &value.attestation),
        )
        .with("recorded_at_ms", closed(&value.recorded_at_ms))
}

/// `ToolIdentity`, in the shape the protocol answers it.
fn tool_identity(value: &ToolIdentity) -> Document {
    Document::new()
        .with("name", Asked::text(Request::Changesets, &value.name))
        .with("version", Asked::text(Request::Changesets, &value.version))
}

/// `ExecutionReceipt`, in the shape the protocol answers it.
fn execution_receipt(value: &ExecutionReceipt) -> Document {
    Document::new()
        .with("started_at_ms", closed(&value.started_at_ms))
        .with("ended_at_ms", closed(&value.ended_at_ms))
        .with("exit_status", closed(&value.exit_status))
        .with("stopped", value.stopped)
        .with(
            "detail",
            crate::shown::exported("ExecutionReceipt", "detail", &value.detail),
        )
}

/// `OutputReference`, in the shape the protocol answers it.
fn output_reference(value: &OutputReference) -> Document {
    Document::new()
        .with("label", Asked::text(Request::Changesets, &value.label))
        .with("digest", closed(&value.digest))
        .with("byte_len", closed(&value.byte_len))
        .with("kind", Asked::text(Request::Changesets, &value.kind))
}

/// `EvidenceReference`, in the shape the protocol answers it.
fn evidence_reference(value: &EvidenceReference) -> Document {
    Document::new()
        .with("version", closed(&value.version))
        .with("kind", closed(&value.kind))
        .with(
            "detail",
            crate::shown::exported("EvidenceReference", "detail", &value.detail),
        )
        .with("recorded_at_ms", closed(&value.recorded_at_ms))
}

/// `ChangesetMaterializeResult`, in the shape the protocol answers it.
#[must_use]
pub fn changeset_materialize_result(value: &ChangesetMaterializeResult) -> Document {
    Document::new()
        .with(
            "materialisation",
            materialisation_record(&value.materialisation),
        )
        .with(
            "limitations",
            value
                .limitations
                .iter()
                .map(|text| {
                    crate::shown::exported("ChangesetMaterializeResult", "limitations", text)
                })
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `DiffReadResult`, in the shape the protocol answers it.
#[must_use]
pub fn diff_read_result(value: &DiffReadResult) -> Document {
    Document::new()
        .with("environment_id", closed(&value.environment_id))
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("workspace_id", closed(&value.workspace_id))
        .with("repository_identity", closed(&value.repository_identity))
        .with("worktree_identity", closed(&value.worktree_identity))
        .with(
            "base_revision",
            crate::shown::git_revision(&value.base_revision),
        )
        .with(
            "base_reference",
            value
                .base_reference
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with(
            "head_revision",
            crate::shown::git_revision(&value.head_revision),
        )
        .with(
            "head_reference",
            value
                .head_reference
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with("source_version", closed(&value.source_version))
        .with(
            "tracked",
            value.tracked.iter().map(diff_entry).collect::<Vec<_>>(),
        )
        .with(
            "untracked",
            value.untracked.iter().map(diff_entry).collect::<Vec<_>>(),
        )
        .with("omitted_entries", closed(&value.omitted_entries))
        .with("counts", closed(&value.counts))
        .with(
            "limitations",
            value
                .limitations
                .iter()
                .map(|text| crate::shown::exported("DiffReadResult", "limitations", text))
                .collect::<Vec<_>>(),
        )
        .with("read_at_ms", closed(&value.read_at_ms))
        .with("ok", true)
}

/// `DiffEntry`, in the shape the protocol answers it.
fn diff_entry(value: &DiffEntry) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Diff, &value.path))
        .with("class", closed(&value.class))
        .with("change", closed(&value.change))
        .with("content", closed(&value.content))
        .with("byte_len", closed(&value.byte_len))
        .with(
            "base_object_id",
            value
                .base_object_id
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with("content_digest", closed(&value.content_digest))
}

/// `DiffApplyResult`, in the shape the protocol answers it.
#[must_use]
pub fn diff_apply_result(value: &DiffApplyResult) -> Document {
    Document::new()
        .with("action_id", closed(&value.action_id))
        .with("outcome", closed(&value.outcome))
        .with("destination", closed(&value.destination))
        .with("applied_version", closed(&value.applied_version))
        .with("proposal_version", closed(&value.proposal_version))
        .with("reference", value.reference.as_ref().map(reference_outcome))
        .with(
            "changed_paths",
            value
                .changed_paths
                .iter()
                .map(|text| Asked::text(Request::Diff, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "unresolved_paths",
            value
                .unresolved_paths
                .iter()
                .map(|text| Asked::text(Request::Diff, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "conflicts",
            value
                .conflicts
                .iter()
                .map(path_conflict)
                .collect::<Vec<_>>(),
        )
        .with(
            "progress",
            value.progress.iter().map(path_progress).collect::<Vec<_>>(),
        )
        .with("recovery", recovery_objects(&value.recovery))
        .with(
            "limitations",
            value
                .limitations
                .iter()
                .map(|text| crate::shown::exported("DiffApplyResult", "limitations", text))
                .collect::<Vec<_>>(),
        )
        .with(
            "detail",
            crate::shown::exported("DiffApplyResult", "detail", &value.detail),
        )
        .with("decided_at_ms", closed(&value.decided_at_ms))
        .with("ok", true)
}

/// `ReferenceOutcome`, in the shape the protocol answers it.
fn reference_outcome(value: &ReferenceOutcome) -> Document {
    Document::new()
        .with("name", Asked::text(Request::Diff, &value.name))
        .with(
            "expected_old_value",
            value
                .expected_old_value
                .as_ref()
                .map(|text| Asked::text(Request::Diff, text)),
        )
        .with(
            "observed_old_value",
            value
                .observed_old_value
                .as_ref()
                .map(|text| Asked::text(Request::Diff, text)),
        )
        .with("compare_and_swap_held", value.compare_and_swap_held)
        .with("updated", value.updated)
        .with(
            "limitation",
            crate::shown::exported("ReferenceOutcome", "limitation", &value.limitation),
        )
}

/// `PathConflict`, in the shape the protocol answers it.
fn path_conflict(value: &PathConflict) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Diff, &value.path))
        .with(
            "expected_worktree_digest",
            closed(&value.expected_worktree_digest),
        )
        .with(
            "observed_worktree_digest",
            closed(&value.observed_worktree_digest),
        )
        .with(
            "expected_index_object_id",
            value
                .expected_index_object_id
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with(
            "observed_index_object_id",
            value
                .observed_index_object_id
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with(
            "detail",
            crate::shown::exported("PathConflict", "detail", &value.detail),
        )
}

/// `PathProgress`, in the shape the protocol answers it.
fn path_progress(value: &PathProgress) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Diff, &value.path))
        .with("state", closed(&value.state))
        .with("before_digest", closed(&value.before_digest))
        .with("after_digest", closed(&value.after_digest))
        .with(
            "detail",
            crate::shown::exported("PathProgress", "detail", &value.detail),
        )
}

/// `RecoveryObjects`, in the shape the protocol answers it.
fn recovery_objects(value: &RecoveryObjects) -> Document {
    Document::new()
        .with("before_version", closed(&value.before_version))
        .with("after_version", closed(&value.after_version))
        .with("applied_version", closed(&value.applied_version))
        .with(
            "staged_path",
            value
                .staged_path
                .as_ref()
                .map(|text| Asked::text(Request::Diff, text)),
        )
        .with(
            "staged_leftovers",
            value
                .staged_leftovers
                .iter()
                .map(|text| Asked::text(Request::Diff, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "detail",
            crate::shown::exported("RecoveryObjects", "detail", &value.detail),
        )
}

/// `PluginListResult`, in the shape the protocol answers it.
#[must_use]
pub fn plugin_list_result(value: &PluginListResult) -> Document {
    Document::new()
        .with(
            "plugins",
            value.plugins.iter().map(plugin_summary).collect::<Vec<_>>(),
        )
        .with(
            "live_releases",
            value
                .live_releases
                .iter()
                .map(live_release_summary)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `PluginSummary`, in the shape the protocol answers it.
fn plugin_summary(value: &PluginSummary) -> Document {
    Document::new()
        .with(
            "plugin_id",
            Asked::text(Request::Plugins, &value.plugin_id.to_string()),
        )
        .with(
            "catalogue_id",
            Asked::text(Request::Plugins, &value.catalogue_id),
        )
        .with("version", Asked::text(Request::Plugins, &value.version))
        .with(
            "package_digest",
            crate::shown::git_revision(&value.package_digest),
        )
        .with("environment_id", closed(&value.environment_id))
        .with("enabled", value.enabled)
        .with("pinned", value.pinned)
        .with("revoked", value.revoked)
        .with("live_bindings", closed(&value.live_bindings))
        .with("admission", value.admission.as_ref().map(plugin_admission))
}

/// `LiveReleaseSummary`, in the shape the protocol answers it.
fn live_release_summary(value: &LiveReleaseSummary) -> Document {
    Document::new()
        .with(
            "plugin_id",
            Asked::text(Request::Plugins, &value.plugin_id.to_string()),
        )
        .with("version", Asked::text(Request::Plugins, &value.version))
        .with(
            "package_digest",
            crate::shown::git_revision(&value.package_digest),
        )
        .with(
            "catalogue_id",
            Asked::text(Request::Plugins, &value.catalogue_id),
        )
        .with("live_bindings", closed(&value.live_bindings))
        .with("ending", value.ending)
        .with("revoked", value.revoked)
}

/// `PluginInstallResult`, in the shape the protocol answers it.
#[must_use]
pub fn plugin_install_result(value: &PluginInstallResult) -> Document {
    Document::new()
        .with("plugin", plugin_summary(&value.plugin))
        .with(
            "capabilities",
            value
                .capabilities
                .iter()
                .map(plugin_capability_grant)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `PluginCapabilityGrant`, in the shape the protocol answers it.
fn plugin_capability_grant(value: &PluginCapabilityGrant) -> Document {
    Document::new()
        .with(
            "capability",
            Asked::text(Request::Plugins, &value.capability.to_string()),
        )
        .with("requirement", closed(&value.requirement))
        .with("permitted", value.permitted)
        .with(
            "reason",
            crate::shown::exported("PluginCapabilityGrant", "reason", &value.reason),
        )
}

/// `PluginRemoveResult`, in the shape the protocol answers it.
#[must_use]
pub fn plugin_remove_result(value: &PluginRemoveResult) -> Document {
    Document::new()
        .with(
            "plugin_id",
            Asked::text(Request::Plugins, &value.plugin_id.to_string()),
        )
        .with("affected_bindings", closed(&value.affected_bindings))
        .with("ok", true)
}

/// `PluginPinResult`, in the shape the protocol answers it.
#[must_use]
pub fn plugin_pin_result(value: &PluginPinResult) -> Document {
    Document::new()
        .with("plugin", plugin_summary(&value.plugin))
        .with("ok", true)
}

/// `PluginEnableResult`, in the shape the protocol answers it.
#[must_use]
pub fn plugin_enable_result(value: &PluginEnableResult) -> Document {
    Document::new()
        .with("plugin", plugin_summary(&value.plugin))
        .with("ok", true)
}

/// `CatalogueListResult`, in the shape the protocol answers it.
#[must_use]
pub fn catalogue_list_result(value: &CatalogueListResult) -> Document {
    Document::new()
        .with(
            "catalogues",
            value
                .catalogues
                .iter()
                .map(catalogue_summary)
                .collect::<Vec<_>>(),
        )
        .with("enrolment_budgets", closed(&value.enrolment_budgets))
        .with("ok", true)
}

/// `CatalogueSummary`, in the shape the protocol answers it.
fn catalogue_summary(value: &CatalogueSummary) -> Document {
    Document::new()
        .with(
            "catalogue_id",
            Asked::text(Request::Plugins, &value.catalogue_id),
        )
        .with("kind", closed(&value.kind))
        .with(
            "metadata_url",
            Asked::location(Request::Plugins, &value.metadata_url),
        )
        .with(
            "targets_url",
            Asked::location(Request::Plugins, &value.targets_url),
        )
        .with(
            "root_digest",
            crate::shown::git_revision(&value.root_digest),
        )
        .with("generation", closed(&value.generation))
        .with("pinned_generation", closed(&value.pinned_generation))
        .with("budgets", closed(&value.budgets))
        .with(
            "ceiling",
            value
                .ceiling
                .iter()
                .map(|text| Asked::text(Request::Plugins, text))
                .collect::<Vec<_>>(),
        )
        .with("entries", closed(&value.entries))
        .with("synced_at_ms", closed(&value.synced_at_ms))
}

/// `CatalogueSyncResult`, in the shape the protocol answers it.
#[must_use]
pub fn catalogue_sync_result(value: &CatalogueSyncResult) -> Document {
    Document::new()
        .with("generation", closed(&value.generation))
        .with("entries", closed(&value.entries))
        .with("index_bytes", closed(&value.index_bytes))
        .with("mirrored_payloads", closed(&value.mirrored_payloads))
        .with(
            "delegations",
            value
                .delegations
                .iter()
                .map(catalogue_delegation)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `CatalogueDelegation`, in the shape the protocol answers it.
fn catalogue_delegation(value: &CatalogueDelegation) -> Document {
    Document::new()
        .with("role", Asked::text(Request::Plugins, &value.role))
        .with(
            "publisher_id",
            Asked::text(Request::Plugins, &value.publisher_id),
        )
}

/// `CataloguePinResult`, in the shape the protocol answers it.
#[must_use]
pub fn catalogue_pin_result(value: &CataloguePinResult) -> Document {
    Document::new()
        .with("catalogue", catalogue_summary(&value.catalogue))
        .with("ok", true)
}

/// `CatalogueRemoveResult`, in the shape the protocol answers it.
#[must_use]
pub fn catalogue_remove_result(value: &CatalogueRemoveResult) -> Document {
    Document::new()
        .with(
            "catalogue_id",
            Asked::text(Request::Plugins, &value.catalogue_id),
        )
        .with(
            "installed_packages",
            value
                .installed_packages
                .iter()
                .map(|text| Asked::text(Request::Plugins, &text.to_string()))
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `ProjectListResult`, in the shape the protocol answers it.
#[must_use]
pub fn project_list_result(value: &ProjectListResult) -> Document {
    Document::new()
        .with(
            "projects",
            value
                .projects
                .iter()
                .map(project_summary)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `ProjectSummary`, in the shape the protocol answers it.
fn project_summary(value: &ProjectSummary) -> Document {
    Document::new()
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("environment_id", closed(&value.environment_id))
        .with("label", Asked::text(Request::Repositories, &value.label))
        .with("origin", closed(&value.origin))
        .with("state", closed(&value.state))
        .with("filesystem_identity", closed(&value.filesystem_identity))
        .with(
            "display_path",
            Asked::text(Request::Repositories, &value.display_path),
        )
        .with("remote", value.remote.as_ref().map(remote_specification))
        .with("created_at_ms", closed(&value.created_at_ms))
        .with("workspace_count", closed(&value.workspace_count))
}

/// `RemoteSpecification`, in the shape the protocol answers it.
fn remote_specification(value: &RemoteSpecification) -> Document {
    Document::new()
        .with(
            "remote_name",
            Asked::text(Request::Repositories, &value.remote_name),
        )
        .with("transport", closed(&value.transport))
        .with("url", Asked::location(Request::Repositories, &value.url))
        .with(
            "provider",
            Asked::text(Request::Repositories, &value.provider),
        )
        .with(
            "credential_broker",
            Asked::text(Request::Repositories, &value.credential_broker),
        )
}

/// `ProjectInitResult`, in the shape the protocol answers it.
#[must_use]
pub fn project_init_result(value: &ProjectInitResult) -> Document {
    Document::new()
        .with("project", project_summary(&value.project))
        .with("operation", operation_record(&value.operation))
        .with("ok", true)
}

/// `OperationRecord`, in the shape the protocol answers it.
fn operation_record(value: &OperationRecord) -> Document {
    Document::new()
        .with("action_id", closed(&value.action_id))
        .with("environment_id", closed(&value.environment_id))
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("method", Asked::text(Request::Repositories, &value.method))
        .with("state", closed(&value.state))
        .with("remote", value.remote.as_ref().map(remote_specification))
        .with("destination_state", closed(&value.destination_state))
        .with(
            "retained_staging_paths",
            value
                .retained_staging_paths
                .iter()
                .map(|text| Asked::text(Request::Repositories, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "removed_staging_paths",
            value
                .removed_staging_paths
                .iter()
                .map(|text| Asked::text(Request::Repositories, text))
                .collect::<Vec<_>>(),
        )
        .with(
            "detail",
            value
                .detail
                .as_ref()
                .map(|text| crate::shown::exported("OperationRecord", "detail", text)),
        )
        .with("started_at_ms", closed(&value.started_at_ms))
        .with("ended_at_ms", closed(&value.ended_at_ms))
}

/// `ProjectCloneResult`, in the shape the protocol answers it.
#[must_use]
pub fn project_clone_result(value: &ProjectCloneResult) -> Document {
    Document::new()
        .with("project", project_summary(&value.project))
        .with("operation", operation_record(&value.operation))
        .with("ok", true)
}

/// `ProjectAdoptResult`, in the shape the protocol answers it.
#[must_use]
pub fn project_adopt_result(value: &ProjectAdoptResult) -> Document {
    Document::new()
        .with("project", project_summary(&value.project))
        .with("operation", operation_record(&value.operation))
        .with("ok", true)
}

/// `WorkspaceListResult`, in the shape the protocol answers it.
#[must_use]
pub fn workspace_list_result(value: &WorkspaceListResult) -> Document {
    Document::new()
        .with(
            "workspaces",
            value
                .workspaces
                .iter()
                .map(workspace_summary)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `WorkspaceSummary`, in the shape the protocol answers it.
fn workspace_summary(value: &WorkspaceSummary) -> Document {
    Document::new()
        .with("workspace_id", closed(&value.workspace_id))
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("environment_id", closed(&value.environment_id))
        .with("label", Asked::text(Request::Workspaces, &value.label))
        .with("kind", closed(&value.kind))
        .with("isolation", closed(&value.isolation))
        .with("policy", closed(&value.policy))
        .with("state", closed(&value.state))
        .with(
            "base_revision",
            crate::shown::git_revision(&value.base_revision),
        )
        .with("base_change_set_id", closed(&value.base_change_set_id))
        .with("filesystem_identity", closed(&value.filesystem_identity))
        .with(
            "display_path",
            Asked::text(Request::Workspaces, &value.display_path),
        )
        .with(
            "detail",
            value
                .detail
                .as_ref()
                .map(|text| crate::shown::exported("WorkspaceSummary", "detail", text)),
        )
        .with("bound_sessions", closed(&value.bound_sessions))
        .with("bound_runs", closed(&value.bound_runs))
        .with(
            "retained",
            value.retained.iter().map(retained_item).collect::<Vec<_>>(),
        )
        .with("created_at_ms", closed(&value.created_at_ms))
}

/// `RetainedItem`, in the shape the protocol answers it.
fn retained_item(value: &RetainedItem) -> Document {
    Document::new()
        .with("kind", closed(&value.kind))
        .with(
            "detail",
            crate::shown::exported("RetainedItem", "detail", &value.detail),
        )
        .with("change_set_id", closed(&value.change_set_id))
}

/// `WorkspaceCreateResult`, in the shape the protocol answers it.
#[must_use]
pub fn workspace_create_result(value: &WorkspaceCreateResult) -> Document {
    Document::new()
        .with("workspace", value.workspace.as_ref().map(workspace_summary))
        .with("preview", inclusion_preview(&value.preview))
        .with(
            "unapplied",
            value
                .unapplied
                .iter()
                .map(|text| Asked::text(Request::Workspaces, text))
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// `InclusionPreview`, in the shape the protocol answers it.
fn inclusion_preview(value: &InclusionPreview) -> Document {
    Document::new()
        .with(
            "project_repository_id",
            closed(&value.project_repository_id),
        )
        .with("kind", closed(&value.kind))
        .with("policy", closed(&value.policy))
        .with(
            "base_revision",
            crate::shown::git_revision(&value.base_revision),
        )
        .with(
            "base_reference",
            value
                .base_reference
                .as_ref()
                .map(|text| crate::shown::git_revision(text)),
        )
        .with("base_change_set_id", closed(&value.base_change_set_id))
        .with("counts", closed(&value.counts))
        .with(
            "entries",
            value.entries.iter().map(preview_entry).collect::<Vec<_>>(),
        )
        .with("omitted_entries", closed(&value.omitted_entries))
        .with("unknown_content", closed(&value.unknown_content))
        .with("counts_complete", value.counts_complete)
        .with(
            "limitations",
            value
                .limitations
                .iter()
                .map(|text| crate::shown::exported("InclusionPreview", "limitations", text))
                .collect::<Vec<_>>(),
        )
        .with("taken_at_ms", closed(&value.taken_at_ms))
}

/// `PreviewEntry`, in the shape the protocol answers it.
fn preview_entry(value: &PreviewEntry) -> Document {
    Document::new()
        .with("path", Asked::text(Request::Workspaces, &value.path))
        .with("class", closed(&value.class))
        .with("change", closed(&value.change))
        .with("content", closed(&value.content))
        .with("byte_len", closed(&value.byte_len))
        .with("included", value.included)
}

/// `WorkspaceRemoveResult`, in the shape the protocol answers it.
#[must_use]
pub fn workspace_remove_result(value: &WorkspaceRemoveResult) -> Document {
    Document::new()
        .with("workspace", workspace_summary(&value.workspace))
        .with("working_files_removed", value.working_files_removed)
        .with(
            "retained",
            value.retained.iter().map(retained_item).collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// Whether the admissions in force let new bindings use an installation: `admitted`, or
/// `left_out` with why as a kind and the host's sentence said as its class and its length.
fn plugin_admission(value: &PluginAdmission) -> Document {
    match value {
        PluginAdmission::Admitted => Document::new().with("state", "admitted"),
        PluginAdmission::LeftOut { reason, detail } => Document::new()
            .with("state", "left_out")
            .with("reason", closed(reason))
            .with(
                "detail",
                crate::shown::exported("PluginAdmission", "detail", detail),
            ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use schemars::JsonSchema;
    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::output::planted::{differs_only_where_said, only_asked, planted, planted_text};

    /// Plants text in every leaf of each value of `T` that can hold it, holds each document to the
    /// rule, and returns where the text showed, as asked content.
    fn held<T: JsonSchema + DeserializeOwned + Serialize>(
        label: &str,
        render: fn(&T) -> Document,
    ) -> BTreeSet<String> {
        let mut shown = BTreeSet::new();
        for value in planted::<T>() {
            let document = render(&value);
            shown.extend(only_asked(label, &document));
            differs_only_where_said(
                label,
                &document,
                &serde_json::to_value(&value).expect("the answer encodes"),
                &["ok"],
            );
            assert_eq!(document.json()["ok"], serde_json::json!(true), "{label}");
        }
        shown
    }

    /// KR-REQ-23.25: text planted in every leaf of every answer these commands print whole that
    /// can hold free text shows only as content the person asked for, and every other leaf is what
    /// the protocol encodes or a reducer's words for it.
    #[test]
    fn planted_text_in_every_answer_shows_only_where_it_was_asked_for() {
        let capture = held("kr changeset capture", changeset_capture_result);
        let read = held("kr changeset read", changeset_read_result);
        held("kr changeset materialize", changeset_materialize_result);
        let diff = held("kr diff read", diff_read_result);
        let applied = held("kr diff apply", diff_apply_result);
        let plugins = held("kr plugin list", plugin_list_result);
        held("kr plugin install", plugin_install_result);
        held("kr plugin remove", plugin_remove_result);
        held("kr plugin pin", plugin_pin_result);
        held("kr plugin enable", plugin_enable_result);
        let catalogues = held("kr plugin repo list", catalogue_list_result);
        held("kr plugin repo sync", catalogue_sync_result);
        held("kr plugin repo pin", catalogue_pin_result);
        held("kr plugin repo remove", catalogue_remove_result);
        let projects = held("kr project list", project_list_result);
        let initialised = held("kr project init", project_init_result);
        held("kr project clone", project_clone_result);
        held("kr project adopt", project_adopt_result);
        let workspaces = held("kr workspace list", workspace_list_result);
        let created = held("kr workspace create", workspace_create_result);
        held("kr workspace remove", workspace_remove_result);
        for (shown, asked) in [
            (&capture, "version.label"),
            (&capture, "version.changes[].path"),
            (&capture, "version.policy.grant.included_paths[]"),
            (&read, "materialisations[].directory_path"),
            (&diff, "tracked[].path"),
            (&applied, "changed_paths[]"),
            (&applied, "reference.name"),
            (&plugins, "plugins[].version"),
            (&catalogues, "catalogues[].catalogue_id"),
            (&projects, "projects[].display_path"),
            (&projects, "projects[].label"),
            (&initialised, "operation.retained_staging_paths[]"),
            (&workspaces, "workspaces[].display_path"),
            (&created, "unapplied[]"),
        ] {
            assert!(shown.contains(asked), "{asked} shows what was asked for");
        }
    }

    /// The neutral control: a sentence the host wrote is said as its class and its length, and a
    /// revision that is not one as a placeholder.
    #[test]
    fn a_host_sentence_and_a_revision_that_is_not_one_are_said_by_their_class() {
        let value = planted::<DiffReadResult>().remove(0);
        let document = diff_read_result(&value).json();
        assert_eq!(
            document["limitations"][0],
            serde_json::json!(format!(
                "[message withheld, {} bytes]",
                planted_text().len()
            ))
        );
        assert_eq!(
            document["base_revision"],
            serde_json::json!("[not an identifier]")
        );
    }
}
