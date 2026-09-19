//! Deterministic JSON Schema and method-table generation.
//!
//! Rust is canonical. The TypeScript package is generated from the schema this module produces, so
//! a change to a Rust type flows to the schema, and from the schema to TypeScript. Both steps have
//! a `--check` mode that fails when the committed output no longer matches, which is what keeps
//! the two languages from drifting.
//!
//! The output is byte stable: every object is a sorted map, the indentation is fixed and each file
//! ends with one newline.

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde_json::{Map, Value, json};

use crate::account::{MembershipLease, OrganisationPolicy, PolicyAuthority};
use crate::action::{
    ActionObservation, ExpirationTombstone, FenceEvidence, FencedAction, RetrustEvidence,
    RevocationBarrier, TimeAdapterReading, TimeCheckpoint,
};
use crate::actor::ActorEnvelope;
use crate::agent::{
    AgentApprovalRespondParams, AgentApprovalRespondResult, AgentBindingState, AgentCancelParams,
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentCommandsParams, AgentCommandsResult,
    AgentMutationResult, AgentPromptParams, AgentSnapshotParams, AgentSnapshotResult,
    AgentSteerParams, PluginActionInvokeParams, PluginActionInvokeResult,
};
use crate::archive::{
    ArchiveDescriptor, BackupGenerationPublication, BackupWriterRecord, RecoveryBundle,
    RecoveryKit, SignedArchiveManifest,
};
use crate::attachment::{
    AttachmentConfigureParams, AttachmentSummary, AttachmentViewportParams,
    AttachmentViewportResult, GeometryResult, GeometryState, SessionAttachParams,
    SessionAttachResult, SessionDetachParams, SessionDetachResult, TerminalGeometryTransferParams,
    TerminalResizeParams,
};
use crate::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionGap, AttentionItem,
    AttentionQuietHoursParams, AttentionQuietHoursResult, AttentionReadParams, AttentionReadResult,
    ChangeSummary, LogViewState, QuietHours, RetainedLogView, ReviewAcknowledgeParams,
    ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult, ReviewState, ReviewSubject,
    SemanticChange, VisitAcknowledgeParams, VisitAcknowledgeResult, VisitChangedParams,
    VisitChangedResult,
};
use crate::authority::MethodEntry;
use crate::broker::{
    ActionToken, ActionTokenClaim, CapabilityMap, CapabilityRecord as InstanceCapabilityRecord,
    DecoderLedgerEntry, DecodingTrust, LaunchProfile,
};
use crate::changeset::{
    CaptureCount, ChangeSetVersionRecord, ChangeSetVersionSummary, ChangesetCaptureParams,
    ChangesetCaptureResult, ChangesetMaterializeParams, ChangesetMaterializeResult,
    ChangesetReadParams, ChangesetReadResult, DiffApplyParams, DiffApplyResult, DiffEntry,
    DiffReadParams, DiffReadResult, EvidenceReference, MaterialisationRecord,
    MaterialisationResult, ObservedPath,
};
use crate::describe::{
    DescriptionProvenance, DescriptionSetup, SessionDescribeParams, SessionDescribeResult,
    SessionRenameParams, SessionRenameResult,
};
use crate::desktop::{
    CapabilityRecord, DesktopCapabilityReport, DesktopContext, EnvironmentCapabilitiesParams,
    EnvironmentCapabilitiesResult, SleepInhibitionState,
};
use crate::envelope::{ControlFrame, MutationRequest, Notification, Request, Response};
use crate::error::ProtocolError;
use crate::frame::StreamHeader;
use crate::gateway::{DeclarativeTable, EvidenceGap, PendingResource, RichMethodTable};
use crate::grant::Grant;
use crate::hello::{ActionWindow, ClientOffer, ConnectReply, HelloReply, HostSelection};
use crate::hostinfo::{
    EffectiveConfiguration, EnvironmentListResult, HostDoctorResult, HostInfoResult, SupportBundle,
    configuration::ConfigurationDocument,
};
use crate::identity::{
    BridgeFrame, BridgeHello, BridgeHelloAck, EnvironmentEnrolParams, EnvironmentEnrolResult,
    EnvironmentEnrolment, EnvironmentForgetParams, EnvironmentForgetResult,
    EnvironmentInventoryParams, EnvironmentInventoryResult, EnvironmentInventoryRow,
    EnvironmentRefreshParams, EnvironmentRefreshResult,
};
use crate::ids;
use crate::ids::SessionRef;
use crate::input::{
    InputAcquireParams, InputAcquireResult, InputInterruptParams, InputLeaseResult,
    InputLeaseState, InputReleaseParams, InputWriteParams, InputWriteResult,
};
use crate::local::{
    ControllerConnectionRole, ForwardedMutation, ForwardedRequest, LocalHello, LocalHelloAck,
};
use crate::mailbox::{EnvelopePlaintext, ForwardedAuthority, SealedEnvelope};
use crate::method::{Method, REGISTRY};
use crate::pairing::{
    AuthorityRevisionRecord, DirectChallenge, DirectRedeemProof, GenerationCheckpoint,
    OwnerConfirmationProof, OwnerConfirmationRequest, PairFinishRequest, PairStatus, ProposedGrant,
    RevocationAcknowledgement, RevocationRequest, SignedClientBundle, SignedHostBundle,
};
use crate::preauth::{PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult};
use crate::project::{
    InclusionPreview, OperationRecord, PreviewEntry, ProjectAdoptParams, ProjectAdoptResult,
    ProjectCloneParams, ProjectCloneResult, ProjectInitParams, ProjectInitResult,
    ProjectListParams, ProjectListResult, ProjectOperationCancelParams,
    ProjectOperationCancelResult, ProjectReadParams, ProjectReadResult, ProjectSummary,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceListParams, WorkspaceListResult,
    WorkspaceReadParams, WorkspaceReadResult, WorkspaceRemoveParams, WorkspaceRemoveResult,
    WorkspaceSummary,
};
use crate::projection::{ProjectionDelta, ProjectionReset, ProjectionRowPage, ProjectionSnapshot};
use crate::push::{
    PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushInstallationBinding,
    PushRegistrationAnswer, PushRegistrationChallenge, PushRequest, PushSenderRecord,
    PushSenderRenewal, PushSenderRevocation,
};
use crate::question::{
    Alert, AlertCreateParams, AlertCreateResult, AnswerRecord, Question, QuestionAnswer,
    QuestionAnswerParams, QuestionCancelOwnParams, QuestionCancelParams, QuestionChoice,
    QuestionCreateParams, QuestionCreateResult, QuestionEvent, QuestionOwnResult,
    QuestionReadOwnParams, QuestionReadParams, QuestionReadResult, QuestionResolveResult,
    QuestionSource,
};
use crate::receipt::{
    ActionCancelParams, ActionCancelResult, ActionReadParams, ActionReadResult, Receipt,
    ReceiptResponse,
};
use crate::recovery::{
    EventsSnapshotParams, EventsSnapshotResult, EventsSubscribeParams, EventsSubscribeResult,
    HistoryPageParams, HistoryPageResult, OutputEvent, ResyncRequired,
};
use crate::relay::{
    RelayConsumptionAck, RelayConsumptionReport, RelayLeaseAck, RelayLeaseRequest,
    SignedRelayConsumptionReceipt, SignedRelayInstanceRegistration,
};
use crate::root::{
    EditorBusyEvent, EditorFence, FencePublication, RootCommandAcceptedParams,
    RootCommandAcceptedResult, RootCommandBlockParams, RootCommandBlockResult,
    RootCommandResolveParams, RootCommandResolveResult, RootEditorEnterParams,
    RootEditorEnterResult, RootEditorFenceParams, RootEditorFenceResult, RootEditorLeaveParams,
    RootEditorLeaveResult, RootEofDetachParams, RootEofDetachResult, ShellLaunchParams,
    ShellLaunchResult,
};
use crate::semantic::SemanticContinuation;
use crate::service::ServiceRequestSignature;
use crate::session::{
    ClosureRecord, SessionCloseParams, SessionCloseResult, SessionCreateParams,
    SessionCreateResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, SessionSummary,
};
use crate::sharing::{
    AuthorityFeedStatus, DeviceListParams, DeviceListResult, DevicePreviewKeyUpdateParams,
    DevicePreviewKeyUpdateResult, DeviceRevokeParams, DeviceSummary, GrantCreateParams,
    GrantCreateResult, GrantListParams, GrantListResult, GrantRevokeParams, GrantSummary,
    InvitationPreview, LiveScreenPreview, NamedApprovalPreview, NamedQuestionPreview,
    OfflineValidityPolicy, RevocationResult, RoleSelection,
};
use crate::skill::{
    AgentToolsInstallResult, AgentToolsParams, AgentToolsRemoveResult, AgentToolsStatusResult,
    ChangeManifest, ChangeOperation, InstalledFile,
};
use crate::sync::{SyncConflictCopy, SyncObjectRecord};
use crate::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    AttachmentHandle, AttachmentReadGrant, DownloadBeginParams, DownloadBeginResult,
    DownloadChunkParams, DownloadChunkResult, DownloadPlacement, DraftCreateParams,
    DraftCreateResult, DraftRecord, DraftUpdateParams, DraftUpdateResult, UploadBeginParams,
    UploadBeginResult, UploadCancelParams, UploadCancelResult, UploadChunkParams,
    UploadChunkResult, UploadFinishParams, UploadFinishResult, UploadStatusParams,
    UploadStatusResult,
};
use crate::voice::{
    VoiceActionPlan, VoiceConfirmationProof, VoiceConfirmationRequest, VoiceContextParams,
    VoiceContextResult, VoiceContextSelection, VoiceDelegateParams, VoiceDelegateResult,
    VoiceGrantParams, VoiceGrantResult, VoiceGrantStatement, VoiceInstructions,
    VoiceSessionDescriptor, VoiceStartParams, VoiceStartResult, VoiceStopParams, VoiceStopResult,
};
use crate::worker::{
    AuthorityRevisionAck, AuthorityRevisionNotice, ControllerGenerationToken, GenerationAccepted,
    GenerationChallenge, WorkerDescriptor, WorkerLaunchSpec, WorkerReady, WorkerRendezvous,
    WorkerVerifyChallenge, WorkerVerifyProof,
};

/// The generated JSON Schema bundle.
pub const SCHEMA_FILE_NAME: &str = "kalareach-protocol.schema.json";

/// The generated method and authority table.
pub const METHOD_AUTHORITY_FILE_NAME: &str = "method-authority.json";

/// Adds one root type to the bundle.
macro_rules! roots {
    ($generator:ident, $properties:ident, $($name:literal => $type:ty),+ $(,)?) => {
        $(
            let schema = $generator.subschema_for::<$type>();
            $properties.insert($name.to_owned(), schema.to_value());
        )+
    };
}

/// Builds the JSON Schema bundle for every root protocol message.
///
/// The bundle is one document: a root object whose properties name the root messages and whose
/// `$defs` hold every referenced type exactly once. One document means the generated TypeScript is
/// one module with no duplicated interfaces.
#[must_use]
pub fn protocol_schema() -> Value {
    let mut generator: SchemaGenerator = SchemaSettings::draft2020_12().into_generator();
    let mut properties = Map::new();
    roots! {
        generator, properties,
        "action_cancel_params" => ActionCancelParams,
        "action_observation" => ActionObservation,
        "action_cancel_result" => ActionCancelResult,
        "action_read_params" => ActionReadParams,
        "action_read_result" => ActionReadResult,
        "action_window" => ActionWindow,
        "action_token" => ActionToken,
        "action_token_claim" => ActionTokenClaim,
        "actor_envelope" => ActorEnvelope,
        "agent_approval_respond_params" => AgentApprovalRespondParams,
        "agent_approval_respond_result" => AgentApprovalRespondResult,
        "agent_binding_state" => AgentBindingState,
        "agent_cancel_params" => AgentCancelParams,
        "agent_capabilities_params" => AgentCapabilitiesParams,
        "agent_capabilities_result" => AgentCapabilitiesResult,
        "agent_commands_params" => AgentCommandsParams,
        "agent_commands_result" => AgentCommandsResult,
        "agent_mutation_result" => AgentMutationResult,
        "agent_prompt_params" => AgentPromptParams,
        "agent_snapshot_params" => AgentSnapshotParams,
        "agent_snapshot_result" => AgentSnapshotResult,
        "agent_steer_params" => AgentSteerParams,
        "archive_descriptor" => ArchiveDescriptor,
        "backup_generation_publication" => BackupGenerationPublication,
        "backup_writer_record" => BackupWriterRecord,
        "attachment_configure_params" => AttachmentConfigureParams,
        "attachment_summary" => AttachmentSummary,
        "attachment_viewport_params" => AttachmentViewportParams,
        "attachment_viewport_result" => AttachmentViewportResult,
        "attention_acknowledge_params" => AttentionAcknowledgeParams,
        "attention_acknowledge_result" => AttentionAcknowledgeResult,
        "attention_gap" => AttentionGap,
        "attention_item" => AttentionItem,
        "attention_quiet_hours_params" => AttentionQuietHoursParams,
        "attention_quiet_hours_result" => AttentionQuietHoursResult,
        "attention_read_params" => AttentionReadParams,
        "attention_read_result" => AttentionReadResult,
        "change_summary" => ChangeSummary,
        "log_view_state" => LogViewState,
        "quiet_hours" => QuietHours,
        "retained_log_view" => RetainedLogView,
        "review_acknowledge_params" => ReviewAcknowledgeParams,
        "review_acknowledge_result" => ReviewAcknowledgeResult,
        "review_read_params" => ReviewReadParams,
        "review_read_result" => ReviewReadResult,
        "review_state" => ReviewState,
        "review_subject" => ReviewSubject,
        "semantic_change" => SemanticChange,
        "visit_acknowledge_params" => VisitAcknowledgeParams,
        "visit_acknowledge_result" => VisitAcknowledgeResult,
        "visit_changed_params" => VisitChangedParams,
        "visit_changed_result" => VisitChangedResult,
        "authority_revision_ack" => AuthorityRevisionAck,
        "authority_revision_notice" => AuthorityRevisionNotice,
        "authority_revision_record" => AuthorityRevisionRecord,
        "capability_map" => CapabilityMap,
        "capability_record" => CapabilityRecord,
        "client_offer" => ClientOffer,
        "closure_record" => ClosureRecord,
        "connect_reply" => ConnectReply,
        "control_frame" => ControlFrame,
        "controller_connection_role" => ControllerConnectionRole,
        "controller_generation_token" => ControllerGenerationToken,
        "declarative_table" => DeclarativeTable,
        "decoder_ledger_entry" => DecoderLedgerEntry,
        "decoding_trust" => DecodingTrust,
        "desktop_capability_report" => DesktopCapabilityReport,
        "desktop_context" => DesktopContext,
        "direct_challenge" => DirectChallenge,
        "direct_redeem_proof" => DirectRedeemProof,
        "envelope_plaintext" => EnvelopePlaintext,
        "environment_capabilities_params" => EnvironmentCapabilitiesParams,
        "environment_capabilities_result" => EnvironmentCapabilitiesResult,
        "environment_enrol_params" => EnvironmentEnrolParams,
        "environment_enrol_result" => EnvironmentEnrolResult,
        "environment_enrolment" => EnvironmentEnrolment,
        "environment_forget_params" => EnvironmentForgetParams,
        "environment_forget_result" => EnvironmentForgetResult,
        "environment_inventory_params" => EnvironmentInventoryParams,
        "environment_inventory_result" => EnvironmentInventoryResult,
        "environment_inventory_row" => EnvironmentInventoryRow,
        "environment_refresh_params" => EnvironmentRefreshParams,
        "environment_refresh_result" => EnvironmentRefreshResult,
        "bridge_frame" => BridgeFrame,
        "bridge_hello" => BridgeHello,
        "bridge_hello_ack" => BridgeHelloAck,
        "evidence_gap" => EvidenceGap,
        "expiration_tombstone" => ExpirationTombstone,
        "fence_evidence" => FenceEvidence,
        "fenced_action" => FencedAction,
        "configuration_document" => ConfigurationDocument,
        "effective_configuration" => EffectiveConfiguration,
        "support_bundle" => SupportBundle,
        "environment_list_result" => EnvironmentListResult,
        "events_snapshot_params" => EventsSnapshotParams,
        "events_snapshot_result" => EventsSnapshotResult,
        "events_subscribe_params" => EventsSubscribeParams,
        "events_subscribe_result" => EventsSubscribeResult,
        "forwarded_authority" => ForwardedAuthority,
        "forwarded_mutation" => ForwardedMutation,
        "forwarded_request" => ForwardedRequest,
        "generation_accepted" => GenerationAccepted,
        "generation_challenge" => GenerationChallenge,
        "generation_checkpoint" => GenerationCheckpoint,
        "geometry_result" => GeometryResult,
        "geometry_state" => GeometryState,
        "authority_feed_status" => AuthorityFeedStatus,
        "device_list_params" => DeviceListParams,
        "device_list_result" => DeviceListResult,
        "device_preview_key_update_params" => DevicePreviewKeyUpdateParams,
        "device_preview_key_update_result" => DevicePreviewKeyUpdateResult,
        "device_revoke_params" => DeviceRevokeParams,
        "device_summary" => DeviceSummary,
        "grant" => Grant,
        "grant_create_params" => GrantCreateParams,
        "grant_create_result" => GrantCreateResult,
        "grant_list_params" => GrantListParams,
        "grant_list_result" => GrantListResult,
        "grant_revoke_params" => GrantRevokeParams,
        "grant_summary" => GrantSummary,
        "invitation_preview" => InvitationPreview,
        "live_screen_preview" => LiveScreenPreview,
        "named_approval_preview" => NamedApprovalPreview,
        "named_question_preview" => NamedQuestionPreview,
        "offline_validity_policy" => OfflineValidityPolicy,
        "revocation_result" => RevocationResult,
        "role_selection" => RoleSelection,
        "hello_reply" => HelloReply,
        "history_page_params" => HistoryPageParams,
        "history_page_result" => HistoryPageResult,
        "host_doctor_result" => HostDoctorResult,
        "host_info_result" => HostInfoResult,
        "host_selection" => HostSelection,
        "input_acquire_params" => InputAcquireParams,
        "input_acquire_result" => InputAcquireResult,
        "input_interrupt_params" => InputInterruptParams,
        "input_lease_result" => InputLeaseResult,
        "input_lease_state" => InputLeaseState,
        "input_release_params" => InputReleaseParams,
        "input_write_params" => InputWriteParams,
        "input_write_result" => InputWriteResult,
        "instance_capability_record" => InstanceCapabilityRecord,
        "launch_profile" => LaunchProfile,
        "local_hello" => LocalHello,
        "local_hello_ack" => LocalHelloAck,
        "membership_lease" => MembershipLease,
        "method_entry" => MethodEntry,
        "mutation_request" => MutationRequest,
        "notification" => Notification,
        "organisation_policy" => OrganisationPolicy,
        "output_event" => OutputEvent,
        "policy_authority" => PolicyAuthority,
        "owner_confirmation_proof" => OwnerConfirmationProof,
        "owner_confirmation_request" => OwnerConfirmationRequest,
        "pair_finish_request" => PairFinishRequest,
        "pair_redeem_params" => PairRedeemParams,
        "pair_redeem_result" => PairRedeemResult,
        "pair_status" => PairStatus,
        "pair_status_params" => PairStatusParams,
        "pair_status_result" => PairStatusResult,
        "pending_resource" => PendingResource,
        "plugin_action_invoke_params" => PluginActionInvokeParams,
        "plugin_action_invoke_result" => PluginActionInvokeResult,
        "projection_delta" => ProjectionDelta,
        "projection_reset" => ProjectionReset,
        "projection_row_page" => ProjectionRowPage,
        "projection_snapshot" => ProjectionSnapshot,
        "proposed_grant" => ProposedGrant,
        "protocol_error" => ProtocolError,
        "push_delivery_ack" => PushDeliveryAck,
        "push_delivery_credential" => PushDeliveryCredential,
        "push_delivery_request" => PushDeliveryRequest,
        "push_installation_binding" => PushInstallationBinding,
        "push_registration_answer" => PushRegistrationAnswer,
        "push_registration_challenge" => PushRegistrationChallenge,
        "push_request" => PushRequest,
        "push_sender_record" => PushSenderRecord,
        "push_sender_renewal" => PushSenderRenewal,
        "push_sender_revocation" => PushSenderRevocation,
        "receipt" => Receipt,
        "receipt_response" => ReceiptResponse,
        "recovery_bundle" => RecoveryBundle,
        "recovery_kit" => RecoveryKit,
        "relay_consumption_ack" => RelayConsumptionAck,
        "relay_consumption_report" => RelayConsumptionReport,
        "relay_lease_ack" => RelayLeaseAck,
        "relay_lease_request" => RelayLeaseRequest,
        "request" => Request,
        "response" => Response,
        "resync_required" => ResyncRequired,
        "retrust_evidence" => RetrustEvidence,
        "revocation_acknowledgement" => RevocationAcknowledgement,
        "rich_method_table" => RichMethodTable,
        "revocation_barrier" => RevocationBarrier,
        "revocation_request" => RevocationRequest,
        "root_command_accepted_params" => RootCommandAcceptedParams,
        "root_command_accepted_result" => RootCommandAcceptedResult,
        "root_command_block_params" => RootCommandBlockParams,
        "root_command_block_result" => RootCommandBlockResult,
        "root_command_resolve_params" => RootCommandResolveParams,
        "root_command_resolve_result" => RootCommandResolveResult,
        "root_editor_busy_event" => EditorBusyEvent,
        "root_editor_enter_params" => RootEditorEnterParams,
        "root_editor_enter_result" => RootEditorEnterResult,
        "root_editor_fence" => EditorFence,
        "root_editor_fence_params" => RootEditorFenceParams,
        "root_editor_fence_publication" => FencePublication,
        "root_editor_fence_result" => RootEditorFenceResult,
        "root_editor_leave_params" => RootEditorLeaveParams,
        "root_editor_leave_result" => RootEditorLeaveResult,
        "root_eof_detach_params" => RootEofDetachParams,
        "root_eof_detach_result" => RootEofDetachResult,
        "sealed_envelope" => SealedEnvelope,
        "semantic_continuation" => SemanticContinuation,
        "service_request_signature" => ServiceRequestSignature,
        "session_attach_params" => SessionAttachParams,
        "session_attach_result" => SessionAttachResult,
        "session_close_params" => SessionCloseParams,
        "session_close_result" => SessionCloseResult,
        "session_create_params" => SessionCreateParams,
        "session_create_result" => SessionCreateResult,
        "session_describe_params" => SessionDescribeParams,
        "session_describe_result" => SessionDescribeResult,
        "session_description_provenance" => DescriptionProvenance,
        "session_description_setup" => DescriptionSetup,
        "session_detach_params" => SessionDetachParams,
        "session_detach_result" => SessionDetachResult,
        "session_list_params" => SessionListParams,
        "session_list_result" => SessionListResult,
        "session_read_params" => SessionReadParams,
        "session_read_result" => SessionReadResult,
        "session_ref" => SessionRef,
        "session_rename_params" => SessionRenameParams,
        "session_rename_result" => SessionRenameResult,
        "session_summary" => SessionSummary,
        "shell_launch_params" => ShellLaunchParams,
        "shell_launch_result" => ShellLaunchResult,
        "signed_archive_manifest" => SignedArchiveManifest,
        "sleep_inhibition_state" => SleepInhibitionState,
        "signed_client_bundle" => SignedClientBundle,
        "signed_host_bundle" => SignedHostBundle,
        "signed_relay_consumption_receipt" => SignedRelayConsumptionReceipt,
        "signed_relay_instance_registration" => SignedRelayInstanceRegistration,
        "stream_header" => StreamHeader,
        "sync_conflict_copy" => SyncConflictCopy,
        "sync_object_record" => SyncObjectRecord,
        "time_adapter_reading" => TimeAdapterReading,
        "time_checkpoint" => TimeCheckpoint,
        "terminal_geometry_transfer_params" => TerminalGeometryTransferParams,
        "terminal_resize_params" => TerminalResizeParams,
        "worker_descriptor" => WorkerDescriptor,
        "worker_launch_spec" => WorkerLaunchSpec,
        "worker_ready" => WorkerReady,
        "worker_rendezvous" => WorkerRendezvous,
        "worker_verify_challenge" => WorkerVerifyChallenge,
        "worker_verify_proof" => WorkerVerifyProof,
        // Transfers. The generated document sorts its own properties, so this block is appended
        // rather than interleaved.
        "agent_draft_add_attachment_params" => AgentDraftAddAttachmentParams,
        "agent_draft_add_attachment_result" => AgentDraftAddAttachmentResult,
        "attachment_contribution" => AttachmentContribution,
        "attachment_handle" => AttachmentHandle,
        "attachment_read_grant" => AttachmentReadGrant,
        "download_begin_params" => DownloadBeginParams,
        "download_begin_result" => DownloadBeginResult,
        "download_chunk_params" => DownloadChunkParams,
        "download_chunk_result" => DownloadChunkResult,
        "download_placement" => DownloadPlacement,
        "draft_create_params" => DraftCreateParams,
        "draft_create_result" => DraftCreateResult,
        "draft_record" => DraftRecord,
        "draft_update_params" => DraftUpdateParams,
        "draft_update_result" => DraftUpdateResult,
        "upload_begin_params" => UploadBeginParams,
        "upload_begin_result" => UploadBeginResult,
        "upload_cancel_params" => UploadCancelParams,
        "upload_cancel_result" => UploadCancelResult,
        "upload_chunk_params" => UploadChunkParams,
        "upload_chunk_result" => UploadChunkResult,
        "upload_finish_params" => UploadFinishParams,
        "upload_finish_result" => UploadFinishResult,
        "upload_status_params" => UploadStatusParams,
        "upload_status_result" => UploadStatusResult,
        // Project repositories and workspaces, appended for the same reason.
        "inclusion_preview" => InclusionPreview,
        "preview_entry" => PreviewEntry,
        "operation_record" => OperationRecord,
        "project_adopt_params" => ProjectAdoptParams,
        "project_adopt_result" => ProjectAdoptResult,
        "project_clone_params" => ProjectCloneParams,
        "project_clone_result" => ProjectCloneResult,
        "project_init_params" => ProjectInitParams,
        "project_init_result" => ProjectInitResult,
        "project_list_params" => ProjectListParams,
        "project_list_result" => ProjectListResult,
        "project_operation_cancel_params" => ProjectOperationCancelParams,
        "project_operation_cancel_result" => ProjectOperationCancelResult,
        "project_read_params" => ProjectReadParams,
        "project_read_result" => ProjectReadResult,
        "project_summary" => ProjectSummary,
        "workspace_create_params" => WorkspaceCreateParams,
        "workspace_create_result" => WorkspaceCreateResult,
        "workspace_list_params" => WorkspaceListParams,
        "workspace_list_result" => WorkspaceListResult,
        "workspace_read_params" => WorkspaceReadParams,
        "workspace_read_result" => WorkspaceReadResult,
        "workspace_remove_params" => WorkspaceRemoveParams,
        "workspace_remove_result" => WorkspaceRemoveResult,
        "workspace_summary" => WorkspaceSummary,
        // Immutable change sets: the captured version, its materialisations and the results
        // recorded against them, and the diff read, apply and revert contract. Appended for the
        // same reason: these are independent root messages that no earlier one refers to.
        "capture_count" => CaptureCount,
        "change_set_version_record" => ChangeSetVersionRecord,
        "change_set_version_summary" => ChangeSetVersionSummary,
        "changeset_capture_params" => ChangesetCaptureParams,
        "changeset_capture_result" => ChangesetCaptureResult,
        "changeset_materialize_params" => ChangesetMaterializeParams,
        "changeset_materialize_result" => ChangesetMaterializeResult,
        "changeset_read_params" => ChangesetReadParams,
        "changeset_read_result" => ChangesetReadResult,
        "diff_apply_params" => DiffApplyParams,
        "diff_apply_result" => DiffApplyResult,
        "diff_entry" => DiffEntry,
        "diff_read_params" => DiffReadParams,
        "diff_read_result" => DiffReadResult,
        "evidence_reference" => EvidenceReference,
        "materialisation_record" => MaterialisationRecord,
        "observed_path" => ObservedPath,
        "materialisation_result" => MaterialisationResult,
        // Agent contact: the questions an agent asks the person, the alerts it raises and the
        // installation of the skill that carries them. Appended for the same reason.
        "alert" => Alert,
        "alert_create_params" => AlertCreateParams,
        "alert_create_result" => AlertCreateResult,
        "answer_record" => AnswerRecord,
        "question" => Question,
        "question_answer" => QuestionAnswer,
        "question_answer_params" => QuestionAnswerParams,
        "question_cancel_own_params" => QuestionCancelOwnParams,
        "question_cancel_params" => QuestionCancelParams,
        "question_choice" => QuestionChoice,
        "question_create_params" => QuestionCreateParams,
        "question_create_result" => QuestionCreateResult,
        "question_event" => QuestionEvent,
        "question_own_result" => QuestionOwnResult,
        "question_read_own_params" => QuestionReadOwnParams,
        "question_read_params" => QuestionReadParams,
        "question_read_result" => QuestionReadResult,
        "question_resolve_result" => QuestionResolveResult,
        "question_source" => QuestionSource,
        "agent_tools_params" => AgentToolsParams,
        "agent_tools_install_result" => AgentToolsInstallResult,
        "agent_tools_remove_result" => AgentToolsRemoveResult,
        "agent_tools_status_result" => AgentToolsStatusResult,
        "change_manifest" => ChangeManifest,
        "change_operation" => ChangeOperation,
        "installed_file" => InstalledFile,
        // Voice: the five method shapes, the voice grant's statement and the confirmation a
        // paired device signs on an unlocked screen. Appended for the same reason.
        "voice_action_plan" => VoiceActionPlan,
        "voice_confirmation_proof" => VoiceConfirmationProof,
        "voice_confirmation_request" => VoiceConfirmationRequest,
        "voice_context_params" => VoiceContextParams,
        "voice_context_result" => VoiceContextResult,
        "voice_context_selection" => VoiceContextSelection,
        "voice_delegate_params" => VoiceDelegateParams,
        "voice_delegate_result" => VoiceDelegateResult,
        "voice_grant_params" => VoiceGrantParams,
        "voice_grant_result" => VoiceGrantResult,
        "voice_grant_statement" => VoiceGrantStatement,
        "voice_instructions" => VoiceInstructions,
        "voice_session_descriptor" => VoiceSessionDescriptor,
        "voice_start_params" => VoiceStartParams,
        "voice_start_result" => VoiceStartResult,
        "voice_stop_params" => VoiceStopParams,
        "voice_stop_result" => VoiceStopResult,
    }
    properties.insert(
        "identifiers".to_owned(),
        identifier_vocabulary(&mut generator).to_value(),
    );
    let definitions = generator.take_definitions(true);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KalaReach protocol",
        "description": "Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.",
        "type": "object",
        "properties": Value::Object(properties),
        "$defs": Value::Object(definitions.into_iter().collect()),
    })
}

/// Registers every public identifier so consumers get a named type for each one.
///
/// Most identifiers are reachable from a root message, but not all of them are, and a consumer
/// that has to hand-write `WorkspaceId` has already lost the guarantee this package exists to
/// give. The synthetic root below names them all; the fields are optional because it is a
/// vocabulary, not a message.
fn identifier_vocabulary(generator: &mut SchemaGenerator) -> Schema {
    let mut properties = Map::new();
    macro_rules! vocabulary {
        ($($name:literal => $type:ty),+ $(,)?) => {
            $(properties.insert($name.to_owned(), generator.subschema_for::<$type>().to_value());)+
        };
    }
    vocabulary! {
        // The scalars every identifier is built from.
        "raw_uuid" => crate::scalars::Uuid,
        "raw_u64" => crate::scalars::U64,
        "raw_bytes" => crate::scalars::Bytes,
        "raw_timestamp_ms" => crate::scalars::TimestampMs,
        "raw_duration_ms" => crate::scalars::DurationMs,
        // The identity and object model.
        "account_id" => ids::AccountId,
        "action_id" => ids::ActionId,
        "action_window_id" => ids::ActionWindowId,
        "actor_id" => ids::ActorId,
        "agent_binding_revision" => ids::AgentBindingRevision,
        "action_token_id" => ids::ActionTokenId,
        "agent_thread_id" => ids::AgentThreadId,
        "agent_turn_id" => ids::AgentTurnId,
        "application_instance_id" => ids::ApplicationInstanceId,
        "approval_request_id" => ids::ApprovalRequestId,
        "archive_id" => ids::ArchiveId,
        "attachment_id" => ids::AttachmentId,
        "attachment_ordinal" => ids::AttachmentOrdinal,
        "attempt_id" => ids::AttemptId,
        "authority_revision" => ids::AuthorityRevision,
        "backup_generation" => ids::BackupGeneration,
        "backup_object_id" => ids::BackupObjectId,
        "boot_epoch" => ids::BootEpoch,
        "broker_binding_id" => ids::BrokerBindingId,
        "build_id" => ids::BuildId,
        "capability_id" => ids::CapabilityId,
        "capability_revision" => ids::CapabilityRevision,
        "causal_root_id" => ids::CausalRootId,
        "collapse_id" => ids::CollapseId,
        "change_set_id" => ids::ChangeSetId,
        "change_set_version" => ids::ChangeSetVersion,
        "clock_epoch" => ids::ClockEpoch,
        "confirmation_id" => ids::ConfirmationId,
        "connection_id" => ids::ConnectionId,
        "controller_generation" => ids::ControllerGeneration,
        "desktop_session_id" => ids::DesktopSessionId,
        "device_id" => ids::DeviceId,
        "device_key_revision" => ids::DeviceKeyRevision,
        "diagnostic_id" => ids::DiagnosticId,
        "draft_id" => ids::DraftId,
        "draft_revision" => ids::DraftRevision,
        "envelope_id" => ids::EnvelopeId,
        "environment_id" => ids::EnvironmentId,
        "event_sequence" => ids::EventSequence,
        "event_type" => ids::EventType,
        "gateway_connection_id" => ids::GatewayConnectionId,
        "geometry_epoch" => ids::GeometryEpoch,
        "grant_id" => ids::GrantId,
        "input_lease_epoch" => ids::InputLeaseEpoch,
        "input_sequence" => ids::InputSequence,
        "installation_id" => ids::InstallationId,
        "invitation_id" => ids::InvitationId,
        "launch_profile_id" => ids::LaunchProfileId,
        "machine_id" => ids::MachineId,
        "materialisation_id" => ids::MaterialisationId,
        "method_table_version" => ids::MethodTableVersion,
        "notification_id" => ids::NotificationId,
        "organisation_id" => ids::OrganisationId,
        "pairing_sequence" => ids::PairingSequence,
        "payer_authorisation_id" => ids::PayerAuthorisationId,
        "plugin_id" => ids::PluginId,
        "pending_resource_id" => ids::PendingResourceId,
        "policy_key_revision" => ids::PolicyKeyRevision,
        "publisher_id" => ids::PublisherId,
        "project_repository_id" => ids::ProjectRepositoryId,
        "push_registration_id" => ids::PushRegistrationId,
        "push_sender_record_id" => ids::PushSenderRecordId,
        "push_sender_revision" => ids::PushSenderRevision,
        "question_id" => ids::QuestionId,
        "question_revision" => ids::QuestionRevision,
        "relay_instance_id" => ids::RelayInstanceId,
        "relay_lease_id" => ids::RelayLeaseId,
        "relay_lease_revision" => ids::RelayLeaseRevision,
        "relay_receipt_sequence" => ids::RelayReceiptSequence,
        "relay_region" => ids::RelayRegion,
        "relay_registration_revision" => ids::RelayRegistrationRevision,
        "relay_reservation_id" => ids::RelayReservationId,
        "remote_dispatch_lease_id" => ids::RemoteDispatchLeaseId,
        "repository_generation" => ids::RepositoryGeneration,
        "request_id" => ids::RequestId,
        "revocation_request_id" => ids::RevocationRequestId,
        "session_epoch" => ids::SessionEpoch,
        "session_id" => ids::SessionId,
        "source_event_handle" => ids::SourceEventHandle,
        "source_generation" => ids::SourceGeneration,
        "stream_cursor" => ids::StreamCursor,
        "stream_id" => ids::StreamId,
        "transfer_id" => ids::TransferId,
        "upstream_method" => ids::UpstreamMethod,
        "upstream_request_id" => ids::UpstreamRequestId,
        "voice_delegation_id" => crate::voice::VoiceDelegationId,
        "voice_session_id" => ids::VoiceSessionId,
        "workflow_id" => ids::WorkflowId,
        "workflow_run_id" => ids::WorkflowRunId,
        "workspace_id" => ids::WorkspaceId,
    }
    json_schema!({
        "type": "object",
        "description": "Every identifier in the identity and object model. This is a vocabulary rather than a message: it exists so each identifier has one named type.",
        "properties": Value::Object(properties)
    })
}

/// Builds the method and authority table as data.
///
/// Consumers that are not written in Rust read this file instead of re-deriving the table. Any
/// method that is not listed here is denied.
#[must_use]
pub fn method_authority_table() -> Value {
    json!({
        "description": "One exhaustive authority entry per method. Anything not listed is denied. Generated from crates/kr-protocol; do not edit by hand.",
        "method_count": REGISTRY.len(),
        "unlisted_methods_are_denied": true,
        "methods": REGISTRY,
    })
}

/// Returns every generated file as a name and its exact contents.
///
/// # Panics
///
/// Panics when a generated document cannot be serialised, which would mean a schema type is
/// malformed rather than a runtime condition.
#[must_use]
pub fn generated_files() -> Vec<(&'static str, String)> {
    vec![
        (SCHEMA_FILE_NAME, render(&protocol_schema())),
        (
            METHOD_AUTHORITY_FILE_NAME,
            render(&method_authority_table()),
        ),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

/// Returns the schema name every method uses, for cross-checking the table against the enum.
#[must_use]
pub fn method_names() -> Vec<&'static str> {
    Method::ALL.iter().map(|method| method.as_str()).collect()
}

/// Returns the schema of one type, for tests that assert a single shape.
#[must_use]
pub fn schema_for<T: JsonSchema>() -> Value {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}
