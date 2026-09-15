/* eslint-disable */
/**
 * Generated from schema/kalareach-protocol.schema.json. Do not edit.
 *
 * Rust is canonical: change the types in crates/kr-protocol, run
 * `cargo run -p kr-protocol --bin kr-protocol-gen`, then `pnpm -C packages/protocol generate`.
 */

/**
 * One paired device.
 */
export type DeviceId = string
/**
 * One host-issued authority object.
 */
export type GrantId = string
/**
 * The host's ordered authority revision. Only the host issues its own revisions.
 */
export type AuthorityRevision = string
/**
 * A versioned capability name. Capabilities describe feasibility, never authority.
 */
export type CapabilityId = string
/**
 * One permitted action in a grant.
 */
export type ActionRight =
  | 'session.view'
  | 'terminal.input'
  | 'terminal.geometry'
  | 'terminal.geometry.transfer'
  | 'terminal.palette'
  | 'agent.prompt'
  | 'agent.cancel'
  | 'agent.approval.respond'
  | 'question.respond'
  | 'files.read'
  | 'files.upload'
  | 'files.apply_diff'
  | 'project.create'
  | 'workspace.manage'
  | 'changeset.create'
  | 'session.create'
  | 'session.rename'
  | 'session.close'
  | 'session.share'
  | 'automation.manage'
  | 'host.manage'
/**
 * One installed OS, distribution or container environment and OS user.
 */
export type EnvironmentId = string
/**
 * A UTC timestamp in milliseconds, as a decimal string in JSON.
 */
export type TimestampMs = string
/**
 * An upstream approval request identifier. Opaque to KalaReach.
 */
export type ApprovalRequestId = string
/**
 * One agent-to-user question.
 */
export type QuestionId = string
/**
 * One KalaReach terminal session.
 */
export type SessionId = string
/**
 * One submitted intent and its receipt, generated as a UUIDv4.
 */
export type ActionId = string
/**
 * A host-issued action window identifier, bound to one authenticated connection and host boot.
 */
export type ActionWindowId = string
/**
 * A stable host-issued principal for one verified actor. The caller cannot assert it.
 */
export type ActorId = string
/**
 * Changes when the active upstream execution owner or selected thread changes.
 */
export type AgentBindingRevision = string
/**
 * The upstream agent's conversation identifier, where available. Correlation data, not authority.
 */
export type AgentThreadId = string
/**
 * The upstream agent's current turn identifier, where available.
 */
export type AgentTurnId = string
/**
 * One foreground application within a terminal session.
 */
export type ApplicationInstanceId = string
/**
 * One CLI or application attachment, independently of its device.
 */
export type AttachmentId = string
/**
 * Monotonic attachment join order, used for deterministic geometry-owner succession.
 */
export type AttachmentOrdinal = string
/**
 * One pairing attempt by one candidate: 128 random bits.
 */
export type AttemptId = string
/**
 * The host boot epoch, which binds continuous-time deadlines to one boot.
 */
export type BootEpoch = string
/**
 * A build identifier reported in hello.
 */
export type BuildId = string
/**
 * Current evidence for a versioned capability. Never permission.
 */
export type CapabilityRevision = string
/**
 * The root of a bounded cross-run causal chain.
 */
export type CausalRootId = string
/**
 * One immutable captured change set.
 */
export type ChangeSetId = string
/**
 * The exact version of a change set that was tested or reviewed.
 */
export type ChangeSetVersion = string
/**
 * The host clock epoch, advanced when wall-clock trust changes.
 */
export type ClockEpoch = string
/**
 * One transport connection, allocated by the host during hello.
 */
export type ConnectionId = string
/**
 * The controller's persistent generation, advanced on every controller start.
 */
export type ControllerGeneration = string
/**
 * A host-derived desktop session identity binding OS user, boot identity and login-session generation.
 */
export type DesktopSessionId = string
/**
 * The revision of a device's purpose-separated public keys.
 */
export type DeviceKeyRevision = string
/**
 * An opaque diagnostic identifier. It carries no protocol meaning.
 */
export type DiagnosticId = string
/**
 * One durable device-owned draft, independent of an attachment.
 */
export type DraftId = string
/**
 * The exact version of a draft.
 */
export type DraftRevision = string
/**
 * A position in one notification stream.
 */
export type EventSequence = string
/**
 * The type of one notification event.
 */
export type EventType = string
/**
 * The current geometry-owner epoch, separate from the input lease.
 */
export type GeometryEpoch = string
/**
 * The current input lease epoch.
 */
export type InputLeaseEpoch = string
/**
 * An increasing sequence number inside one raw input stream.
 */
export type InputSequence = string
/**
 * One native application installation registered with a push gateway.
 */
export type InstallationId = string
/**
 * One pairing invitation: 128 random bits, not necessarily a UUIDv4.
 */
export type InvitationId = string
/**
 * A logical machine group. Not a hardware identity.
 */
export type MachineId = string
/**
 * One organisation whose signed policy a host has opted into.
 */
export type OrganisationId = string
/**
 * A plugin identifier from its manifest.
 */
export type PluginId = string
/**
 * One environment-bound source repository.
 */
export type ProjectRepositoryId = string
/**
 * The exact version of a question that a person answers.
 */
export type QuestionRevision = string
/**
 * An opaque byte string. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
 */
export type Bytes = string
/**
 * A duration in milliseconds, as a decimal string in JSON.
 */
export type DurationMs = string
/**
 * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
 */
export type U64 = string
/**
 * A 128-bit identifier. On the wire it is a 16-byte string; in JSON it is the canonical hyphenated lower-case text form.
 */
export type Uuid = string
/**
 * One remote dispatch lease from the current controller generation.
 */
export type RemoteDispatchLeaseId = string
/**
 * The catalogue generation a plugin package was resolved against.
 */
export type RepositoryGeneration = string
/**
 * A request identifier, unique for the lifetime of one connection.
 */
export type RequestId = string
/**
 * The session epoch, fixed at 1 in protocol version 1.
 */
export type SessionEpoch = string
/**
 * A private broker handle for immutable upstream bytes and their execution provenance.
 */
export type SourceEventHandle = string
/**
 * A position in one event stream.
 */
export type StreamCursor = string
/**
 * The name of one event stream.
 */
export type StreamId = string
/**
 * One upload or download transfer.
 */
export type TransferId = string
/**
 * One automation definition.
 */
export type WorkflowId = string
/**
 * One automation run.
 */
export type WorkflowRunId = string
/**
 * One selected working copy and its policy.
 */
export type WorkspaceId = string
/**
 * Where a request entered the host.
 *
 * Ingress is part of every authority entry. A method restricted to private IPC is never reachable
 * through the network or through a plugin component, whatever rights the caller holds.
 */
export type ActorIngress =
  'local_ipc' | 'paired_device' | 'unpaired_peer' | 'workflow' | 'plugin' | 'service_client'
/**
 * Which resource identities a request names and the host resolves before the authority check.
 *
 * An attachment's identifier alone is not permission: it selects a resource, and the rights check
 * still runs against the resolved resource.
 */
export type ResourceSelectorKind =
  | 'host'
  | 'environment'
  | 'session'
  | 'attachment'
  | 'application_instance'
  | 'device'
  | 'grant'
  | 'invitation'
  | 'catalogue'
  | 'plugin'
  | 'question'
  | 'draft'
  | 'transfer'
  | 'project'
  | 'workspace'
  | 'change_set'
  | 'event_stream'
  | 'action'
  | 'workflow'
  | 'installation'
  | 'voice_session'
  | 'mailbox'
  | 'agent_target'
/**
 * Why an action was rejected before dispatch.
 */
export type RejectionReason =
  'admission_failed' | 'expired' | 'cancelled' | 'revoked' | 'stale_preconditions'

/**
 * Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.
 */
export interface KalaReachProtocol {
  actor_envelope?: ActorEnvelope
  client_offer?: ClientOffer
  grant?: Grant
  host_selection?: HostSelection
  /**
   * Every identifier in the identity and object model. This is a vocabulary rather than a message: it exists so each identifier has one named type.
   */
  identifiers?: {
    action_id?: ActionId
    action_window_id?: ActionWindowId
    actor_id?: ActorId
    agent_binding_revision?: AgentBindingRevision
    agent_thread_id?: AgentThreadId
    agent_turn_id?: AgentTurnId
    application_instance_id?: ApplicationInstanceId
    approval_request_id?: ApprovalRequestId
    attachment_id?: AttachmentId
    attachment_ordinal?: AttachmentOrdinal
    attempt_id?: AttemptId
    authority_revision?: AuthorityRevision
    boot_epoch?: BootEpoch
    build_id?: BuildId
    capability_id?: CapabilityId
    capability_revision?: CapabilityRevision
    causal_root_id?: CausalRootId
    change_set_id?: ChangeSetId
    change_set_version?: ChangeSetVersion
    clock_epoch?: ClockEpoch
    connection_id?: ConnectionId
    controller_generation?: ControllerGeneration
    desktop_session_id?: DesktopSessionId
    device_id?: DeviceId
    device_key_revision?: DeviceKeyRevision
    diagnostic_id?: DiagnosticId
    draft_id?: DraftId
    draft_revision?: DraftRevision
    environment_id?: EnvironmentId
    event_sequence?: EventSequence
    event_type?: EventType
    geometry_epoch?: GeometryEpoch
    grant_id?: GrantId
    input_lease_epoch?: InputLeaseEpoch
    input_sequence?: InputSequence
    installation_id?: InstallationId
    invitation_id?: InvitationId
    machine_id?: MachineId
    organisation_id?: OrganisationId
    plugin_id?: PluginId
    project_repository_id?: ProjectRepositoryId
    question_id?: QuestionId
    question_revision?: QuestionRevision
    raw_bytes?: Bytes
    raw_duration_ms?: DurationMs
    raw_timestamp_ms?: TimestampMs
    raw_u64?: U64
    raw_uuid?: Uuid
    remote_dispatch_lease_id?: RemoteDispatchLeaseId
    repository_generation?: RepositoryGeneration
    request_id?: RequestId
    session_epoch?: SessionEpoch
    session_id?: SessionId
    source_event_handle?: SourceEventHandle
    stream_cursor?: StreamCursor
    stream_id?: StreamId
    transfer_id?: TransferId
    workflow_id?: WorkflowId
    workflow_run_id?: WorkflowRunId
    workspace_id?: WorkspaceId
  }
  method_entry?: MethodEntry
  mutation_request?: MutationRequest
  notification?: Notification
  protocol_error?: ProtocolError
  receipt?: Receipt
  receipt_response?: ReceiptResponse
  request?: Request
  response?: Response
  session_ref?: SessionRef
  stream_header?: StreamHeader
}
/**
 * The host-constructed identity of one request.
 *
 * The de-duplication key for a mutation is `(actor_id, action_id)`.
 */
export interface ActorEnvelope {
  /**
   * The stable host-issued principal for this actor.
   */
  actor_id: string
  /**
   * The connection the request arrived on. Closing the control stream revokes every associated
   * data stream.
   */
  connection_id: string
  /**
   * The controller generation that admitted the connection. Remote dispatch is fenced when this
   * generation is replaced.
   */
  controller_generation: string
  /**
   * The paired device, when the ingress is a device.
   */
  device_id: DeviceId | null
  /**
   * The grant the request is being checked against, when one applies.
   */
  grant_id: GrantId | null
  /**
   * The authority revision the grant was validated at.
   */
  grant_revision: AuthorityRevision | null
  /**
   * Where the request entered the host.
   */
  ingress:
    'local_ipc' | 'paired_device' | 'unpaired_peer' | 'workflow' | 'plugin' | 'service_client'
}
/**
 * The client's complete `hello` offer.
 */
export interface ClientOffer {
  /**
   * The client build identity.
   */
  build_id: string
  /**
   * The capabilities the client offers.
   */
  capabilities: CapabilityId[]
  /**
   * A fresh client nonce.
   */
  client_nonce: string
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The revision of that device's purpose-separated keys.
   */
  device_key_revision: string
  max_receive: ReceiveLimits
  /**
   * Every public protocol version the client offers.
   */
  offered_versions: ProtocolVersion[]
}
/**
 * The client's own receive limits.
 */
export interface ReceiveLimits {
  /**
   * Maximum attachment frame payload, in bytes.
   */
  max_attachment_frame_len: string
  /**
   * Maximum control frame payload, in bytes.
   */
  max_control_frame_len: string
  /**
   * Maximum input frame payload, in bytes.
   */
  max_input_frame_len: string
  /**
   * Maximum outstanding mutations per session.
   */
  max_outstanding_mutations: string
  /**
   * Maximum queued bytes before the peer is resynchronised.
   */
  max_send_queue_bytes: string
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion {
  /**
   * The major version. A mismatch is not negotiable.
   */
  major: number
  /**
   * The minor version. A peer selects the highest minor both sides support.
   */
  minor: number
}
/**
 * A host-issued authority object.
 */
export interface Grant {
  /**
   * The actions it permits.
   */
  actions: ActionRight[]
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * Which environments it covers.
   */
  environment_selector:
    | 'any'
    | {
        these: {
          /**
           * The permitted environments.
           */
          environment_ids: EnvironmentId[]
        }
      }
  /**
   * When it stops being valid.
   */
  expiry:
    | 'never'
    | {
        at: {
          /**
           * The deadline in UTC milliseconds.
           */
          expires_at_ms: string
        }
      }
  /**
   * One host-issued authority object.
   */
  grant_id: string
  history: HistoryScope
  /**
   * One paired device.
   */
  issuer_device_id: string
  /**
   * An optional organisation membership requirement.
   */
  organisation: OrganisationRequirement | null
  /**
   * The grant this one was delegated from. Revoking a parent revokes its descendants.
   */
  parent_grant_id: GrantId | null
  /**
   * One paired device.
   */
  recipient_device_id: string
  /**
   * Which sessions it covers.
   */
  session_selector:
    | 'any'
    | {
        these: {
          /**
           * The permitted sessions.
           */
          session_ids: SessionId[]
        }
      }
    | 'none'
}
/**
 * How far back it may see.
 */
export interface HistoryScope {
  /**
   * Whether the currently visible screen is included. This exception never grants inactive
   * screen buffers, scrollback or the backing transcript.
   */
  include_live_screen: boolean
  /**
   * The earliest content this grant may see. Null means no retained history at all.
   */
  lower_bound_ms: TimestampMs | null
  /**
   * Current approval requests named explicitly, on the same terms.
   */
  named_approvals: ApprovalRequestId[]
  /**
   * Current questions named explicitly, even when they were created before the lower bound.
   */
  named_questions: QuestionId[]
}
/**
 * An organisation membership requirement attached to a grant.
 *
 * Organisation leases keep their stricter policy: expired membership blocks further
 * organisation-mediated reads and mutations even while the transport stays connected.
 */
export interface OrganisationRequirement {
  /**
   * The organisation whose membership the recipient must hold.
   */
  organisation_id: string
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  policy_revision: string
}
/**
 * The host's complete `hello` selection.
 *
 * It echoes the client nonce as well as carrying its own, so the transcript binds one exact
 * offer to one exact selection.
 */
export interface HostSelection {
  /**
   * The host boot epoch.
   */
  boot_epoch: string
  /**
   * The capabilities the host selected.
   */
  capabilities: CapabilityId[]
  /**
   * The client nonce this selection answers.
   */
  client_nonce: string
  /**
   * The host clock epoch.
   */
  clock_epoch: string
  /**
   * The connection identity the host allocated.
   */
  connection_id: string
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The revision of the host's purpose-separated keys.
   */
  device_key_revision: string
  /**
   * The host's iroh endpoint identity, validated against the paired record.
   */
  endpoint_id: string
  /**
   * A fresh host nonce.
   */
  host_nonce: string
  limits: ReceiveLimits1
  selected_version: ProtocolVersion1
}
/**
 * The negotiated limits.
 */
export interface ReceiveLimits1 {
  /**
   * Maximum attachment frame payload, in bytes.
   */
  max_attachment_frame_len: string
  /**
   * Maximum control frame payload, in bytes.
   */
  max_control_frame_len: string
  /**
   * Maximum input frame payload, in bytes.
   */
  max_input_frame_len: string
  /**
   * Maximum outstanding mutations per session.
   */
  max_outstanding_mutations: string
  /**
   * Maximum queued bytes before the peer is resynchronised.
   */
  max_send_queue_bytes: string
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion1 {
  /**
   * The major version. A mismatch is not negotiable.
   */
  major: number
  /**
   * The minor version. A peer selects the highest minor both sides support.
   */
  minor: number
}
/**
 * One exhaustive authority entry.
 */
export interface MethodEntry {
  /**
   * Which capability evidence is required, and at which revision.
   */
  capability:
    | 'none'
    | {
        required: {
          /**
           * The capability name.
           */
          capability_id: string
          /**
           * The revision the evidence is bound to.
           */
          revision:
            | 'agent_binding'
            | 'session_epoch'
            | 'input_lease_epoch'
            | 'geometry_epoch'
            | 'question_revision'
            | 'draft_revision'
            | 'change_set_version'
            | 'authority_revision'
            | 'device_key_revision'
            | 'package_hash'
            | 'repository_generation'
            | 'workflow_definition_version'
            | 'root_editor_fence'
            | 'installation_key_revision'
        }
      }
  /**
   * Whether a fresh owner confirmation is required.
   */
  confirmation: 'none' | 'always' | 'when_enlarging_authority'
  /**
   * Read or write.
   */
  effect: 'read' | 'write'
  /**
   * Which freshness context the request must carry.
   */
  freshness:
    | 'current_authority'
    | 'action_window'
    | 'input_lease'
    | 'invitation_deadline'
    | 'service_credential'
  /**
   * The method group from section 23.
   */
  group:
    | 'host_and_environment'
    | 'pairing'
    | 'devices'
    | 'plugin_catalogues'
    | 'plugins'
    | 'plugin_actions'
    | 'question_source'
    | 'question_user_interface'
    | 'skill_setup'
    | 'sessions'
    | 'attachments'
    | 'input'
    | 'root_integration'
    | 'shell_launch'
    | 'agent_state'
    | 'agent_mutations'
    | 'drafts_and_media'
    | 'project_repositories'
    | 'workspaces'
    | 'changes_and_diffs'
    | 'review_and_attention'
    | 'pending_action_control'
    | 'owner_confirmation'
    | 'state_recovery'
    | 'sharing'
    | 'services'
    | 'voice'
    | 'automation'
  /**
   * How the history filter applies to the result.
   */
  history_filter:
    'not_applicable' | 'grant_lower_bound' | 'live_view_only' | 'named_current_resources'
  /**
   * How a repeated request is resolved.
   */
  idempotency:
    | 'idempotent_read'
    | 'action_deduplicated'
    | {
        keyed: {
          /**
           * The key the operation is idempotent under.
           */
          key: string
        }
      }
    | 'ordered_stream'
  /**
   * The only ingress classes that may reach this method.
   */
  ingress: ActorIngress[]
  /**
   * The method this entry governs.
   */
  method:
    | 'host.info'
    | 'environment.list'
    | 'environment.capabilities'
    | 'host.doctor'
    | 'pair.invite'
    | 'pair.redeem'
    | 'pair.finish'
    | 'pair.confirm'
    | 'pair.cancel'
    | 'pair.status'
    | 'device.list'
    | 'device.revoke'
    | 'device.preview_key.update'
    | 'catalogue.list'
    | 'catalogue.add'
    | 'catalogue.sync'
    | 'catalogue.pin'
    | 'catalogue.remove'
    | 'plugin.list'
    | 'plugin.install'
    | 'plugin.remove'
    | 'plugin.pin'
    | 'plugin.enable'
    | 'plugin.disable'
    | 'plugin.grant'
    | 'plugin.capabilities'
    | 'plugin.action.invoke'
    | 'question.create'
    | 'question.read_own'
    | 'question.cancel_own'
    | 'alert.create'
    | 'question.read'
    | 'question.answer'
    | 'question.cancel'
    | 'agent_tools.install'
    | 'agent_tools.status'
    | 'agent_tools.remove'
    | 'session.list'
    | 'session.create'
    | 'session.read'
    | 'session.close'
    | 'session.describe'
    | 'session.rename'
    | 'session.attach'
    | 'session.detach'
    | 'attachment.configure'
    | 'attachment.viewport'
    | 'terminal.resize'
    | 'terminal.geometry.transfer'
    | 'terminal.palette.set'
    | 'input.acquire'
    | 'input.release'
    | 'input.interrupt'
    | 'input.write'
    | 'root.editor.enter'
    | 'root.editor.leave'
    | 'root.editor.fence'
    | 'root.eof.detach'
    | 'root.command.accepted'
    | 'shell.launch'
    | 'agent.capabilities'
    | 'agent.snapshot'
    | 'agent.commands'
    | 'agent.prompt.submit'
    | 'agent.prompt.queue'
    | 'agent.turn.steer'
    | 'agent.turn.cancel'
    | 'agent.approval.respond'
    | 'draft.create'
    | 'draft.update'
    | 'agent.draft.add_attachment'
    | 'upload.begin'
    | 'upload.status'
    | 'upload.chunk'
    | 'upload.finish'
    | 'upload.cancel'
    | 'download.begin'
    | 'download.chunk'
    | 'project.list'
    | 'project.read'
    | 'project.init'
    | 'project.clone'
    | 'project.adopt'
    | 'project.operation.cancel'
    | 'workspace.list'
    | 'workspace.create'
    | 'workspace.read'
    | 'workspace.remove'
    | 'diff.read'
    | 'diff.apply'
    | 'diff.revert'
    | 'changeset.capture'
    | 'changeset.read'
    | 'changeset.materialize'
    | 'review.read'
    | 'review.acknowledge'
    | 'attention.read'
    | 'attention.acknowledge'
    | 'visit.acknowledge'
    | 'action.cancel'
    | 'owner.confirmation.request'
    | 'owner.confirmation.complete'
    | 'events.subscribe'
    | 'events.snapshot'
    | 'history.page'
    | 'action.read'
    | 'grant.create'
    | 'grant.revoke'
    | 'grant.list'
    | 'push.installation.register'
    | 'push.sender.issue'
    | 'push.sender.renew'
    | 'push.sender.revoke'
    | 'mailbox.read'
    | 'authority.sync'
    | 'sync.compare_exchange'
    | 'backup.manifest'
    | 'voice.start'
    | 'voice.stop'
    | 'voice.grant'
    | 'voice.delegate'
    | 'voice.context'
    | 'workflow.install'
    | 'workflow.enable'
    | 'workflow.pause'
    | 'workflow.run'
    | 'workflow.read'
  /**
   * The stable wire name.
   */
  name: string
  /**
   * Everything the actor must present, intersected.
   */
  required_rights: RequiredRight[]
  /**
   * The resources the request names and the host resolves.
   */
  resource_selectors: ResourceSelectorKind[]
  /**
   * What the method does.
   */
  summary: string
  /**
   * The method version this entry describes.
   */
  version: number
}
/**
 * One entry in a method's required-authority list.
 *
 * A composite action intersects every entry whose condition holds. A configuration or role label
 * never short-circuits one of these checks.
 */
export interface RequiredRight {
  /**
   * What must be presented.
   */
  authority:
    | {
        right: {
          /**
           * One permitted action in a grant.
           */
          right:
            | 'session.view'
            | 'terminal.input'
            | 'terminal.geometry'
            | 'terminal.geometry.transfer'
            | 'terminal.palette'
            | 'agent.prompt'
            | 'agent.cancel'
            | 'agent.approval.respond'
            | 'question.respond'
            | 'files.read'
            | 'files.upload'
            | 'files.apply_diff'
            | 'project.create'
            | 'workspace.manage'
            | 'changeset.create'
            | 'session.create'
            | 'session.rename'
            | 'session.close'
            | 'session.share'
            | 'automation.manage'
            | 'host.manage'
        }
      }
    | 'resource_owner'
    | 'pairing_transcript'
    | 'issuing_owner_context'
    | 'voice_grant'
    | 'service_credential'
    | 'plugin_effect_rights'
    | 'local_caller_token'
    | 'issuer_delegation'
    | 'present_view_authority'
  /**
   * When it must be presented.
   */
  when:
    | 'always'
    | 'geometry_claim'
    | 'own_subject'
    | 'other_actor'
    | 'candidate_endpoint'
    | 'issuing_owner'
}
/**
 * A mutation request.
 *
 * The payload digest covers the method and version, the actor and grant, the complete target, the
 * preconditions, the action identifier, the freshness window and time to live, and the
 * parameters. Replacing the window changes the digest, so it is never an automatic retry.
 */
export interface MutationRequest {
  /**
   * The durable operation identity, a cryptographically generated UUIDv4.
   */
  action_id: string
  /**
   * The host-issued action window this first admission is bound to.
   */
  action_window_id: string
  /**
   * The subject preconditions this mutation requires.
   */
  expected: {
    [k: string]: unknown
  }
  /**
   * The grant this mutation is claimed under. A local caller's host-stamped context leaves this
   * null and the host resolves its own owner authority.
   */
  grant_id: GrantId | null
  /**
   * The method name.
   */
  method: string
  /**
   * The method version.
   */
  method_version: number
  /**
   * The method's parameters.
   */
  params: {
    [k: string]: unknown
  }
  /**
   * Correlates the response. Durable operation identity is `action_id`, not this.
   */
  request_id: string
  /**
   * The requested lifetime. The host derives the accepted deadline and may shorten it. This is
   * a duration, not permission to refresh a replay.
   */
  requested_ttl_ms: string
  target: ActionTarget
}
/**
 * The exact subject.
 */
export interface ActionTarget {
  /**
   * The agent binding revision, present exactly when `application_instance_id` is.
   */
  agent_binding_revision: AgentBindingRevision | null
  /**
   * The foreground application instance, when the effect has one.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The environment that owns the effect.
   */
  environment_id: string
  /**
   * The session epoch, present exactly when `session_id` is.
   */
  session_epoch: SessionEpoch | null
  /**
   * The session, when the effect has one.
   */
  session_id: SessionId | null
}
/**
 * One event on a subscribed stream.
 *
 * Stream sequences are application sequence numbers. Transport streams do not replace them, and a
 * client that falls behind receives `RESYNC_REQUIRED` rather than holding the read loop.
 */
export interface Notification {
  /**
   * What happened.
   */
  event_type: string
  /**
   * The event payload.
   */
  payload: {
    [k: string]: unknown
  }
  /**
   * The position of this event in that stream.
   */
  sequence: string
  /**
   * Which stream the event belongs to.
   */
  stream_id: string
}
/**
 * The error object returned in a response or recorded on a receipt.
 *
 * The message is plain text for a person or a log. The user interface translates the code into a
 * direct action and does not display protocol internals by default.
 */
export interface ProtocolError {
  /**
   * The stable code.
   */
  code:
    | 'INVALID_ARGUMENT'
    | 'UNSUPPORTED_SCHEMA'
    | 'UNSUPPORTED_CAPABILITY'
    | 'PERMISSION_DENIED'
    | 'PAIRING_EXPIRED'
    | 'PAIRING_REJECTED'
    | 'PAIRING_AUTH_FAILED'
    | 'PAIRING_ATTEMPTS_EXHAUSTED'
    | 'RENDEZVOUS_UNAVAILABLE'
    | 'RENDEZVOUS_CONFIG_ERROR'
    | 'UNKNOWN_SESSION'
    | 'AMBIGUOUS_SESSION'
    | 'AMBIGUOUS_ATTACHMENT'
    | 'TERMINAL_UNAVAILABLE'
    | 'TERMINAL_PROBE_FAILED'
    | 'INPUT_INCOMPATIBLE'
    | 'SESSION_CLOSED'
    | 'SESSION_LIMIT'
    | 'RESOURCE_UNAVAILABLE'
    | 'HOST_NOT_CONFIGURED'
    | 'ENVIRONMENT_UNAVAILABLE'
    | 'DESKTOP_UNAVAILABLE'
    | 'STALE_SESSION'
    | 'LEASE_LOST'
    | 'GEOMETRY_NOT_OWNER'
    | 'DRAFT_CONFLICT'
    | 'EDITOR_BUSY'
    | 'ID_CONFLICT'
    | 'UPSTREAM_UNAVAILABLE'
    | 'OUTCOME_UNKNOWN'
    | 'RESYNC_REQUIRED'
    | 'QUOTA_EXCEEDED'
    | 'RATE_LIMITED'
    | 'SERVICE_CAPACITY'
    | 'CLOCK_UNTRUSTED'
    | 'STORAGE_UNAVAILABLE'
    | 'SHELL_INTEGRATION_UNSUPPORTED'
    | 'ATTACHMENT_INTEGRITY'
    | 'REPOSITORY_UNTRUSTED'
    | 'PACKAGE_UNAVAILABLE_OFFLINE'
    | 'PLUGIN_GRANT_REQUIRED'
    | 'PLUGIN_DISABLED'
    | 'QUESTION_RESOLVED'
    | 'QUESTION_EXPIRED'
    | 'NOT_IN_KR_SESSION'
    | 'OWNER_CONFIRMATION_REQUIRED'
    | 'CAUSAL_LIMIT'
    | 'SOURCE_CHANGED'
  /**
   * An opaque identifier for correlating this failure with host diagnostics.
   */
  diagnostic_id: DiagnosticId | null
  /**
   * A plain message. It never carries credentials or command text.
   */
  message: string
  /**
   * How the client may react. It must equal [`ErrorCode::retry_category`] for the code.
   */
  retry: 'no_retry' | 'transient' | 'resync' | 'configuration_change' | 'outcome_unknown'
}
/**
 * One action receipt.
 *
 * The de-duplication key is `(actor_id, action_id)`. An exact duplicate returns the stored
 * receipt; a reused identifier with a different payload digest is an `ID_CONFLICT`.
 */
export interface Receipt {
  /**
   * The deadline the host derived at acceptance: the earliest of window expiry, receipt time
   * plus the requested time to live, and any applicable authority or subject deadline. An exact
   * retry never receives a new deadline.
   */
  accepted_deadline_ms: TimestampMs | null
  /**
   * The durable operation identity.
   */
  action_id: string
  /**
   * The verified actor that submitted it.
   */
  actor_id: string
  /**
   * The failure recorded with a refusal, rejection or unknown outcome.
   */
  error: ProtocolError | null
  /**
   * The method and version the digest covers.
   */
  method: string
  /**
   * The method version the digest covers.
   */
  method_version: number
  /**
   * The digest of the submitted payload, used to detect a reused identifier.
   */
  payload_digest: string
  /**
   * Why the action was rejected, when the state is `rejected`.
   */
  reason: RejectionReason | null
  /**
   * A monotonically increasing revision.
   */
  revision: string
  /**
   * The current state.
   */
  state: 'received' | 'accepted' | 'dispatching' | 'applied' | 'refused' | 'rejected' | 'unknown'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * The response to a mutation request.
 *
 * A duplicate request from a still-authorised actor returns the retained receipt without
 * dispatch. The host checks current authority before returning it, so a revoked device cannot use
 * an old action identifier to retrieve protected information.
 */
export interface ReceiptResponse {
  receipt: Receipt1
  /**
   * The request this response correlates with.
   */
  request_id: string
}
/**
 * The current receipt.
 */
export interface Receipt1 {
  /**
   * The deadline the host derived at acceptance: the earliest of window expiry, receipt time
   * plus the requested time to live, and any applicable authority or subject deadline. An exact
   * retry never receives a new deadline.
   */
  accepted_deadline_ms: TimestampMs | null
  /**
   * The durable operation identity.
   */
  action_id: string
  /**
   * The verified actor that submitted it.
   */
  actor_id: string
  /**
   * The failure recorded with a refusal, rejection or unknown outcome.
   */
  error: ProtocolError | null
  /**
   * The method and version the digest covers.
   */
  method: string
  /**
   * The method version the digest covers.
   */
  method_version: number
  /**
   * The digest of the submitted payload, used to detect a reused identifier.
   */
  payload_digest: string
  /**
   * Why the action was rejected, when the state is `rejected`.
   */
  reason: RejectionReason | null
  /**
   * A monotonically increasing revision.
   */
  revision: string
  /**
   * The current state.
   */
  state: 'received' | 'accepted' | 'dispatching' | 'applied' | 'refused' | 'rejected' | 'unknown'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * A read request.
 */
export interface Request {
  /**
   * The method name. A name that is not in the registry is denied.
   */
  method: string
  /**
   * The method version. Schemas are closed for the negotiated version.
   */
  method_version: number
  /**
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings appear as unpadded base64url and cannot be told apart from text.
   */
  params: {
    [k: string]: unknown
  }
  /**
   * Correlates the response. Unique for the lifetime of one connection.
   */
  request_id: string
}
/**
 * A response correlated to one request.
 */
export interface Response {
  /**
   * The result.
   */
  outcome:
    | {
        ok: ParamsValue
      }
    | {
        error: ProtocolError
      }
  /**
   * The request this response answers.
   */
  request_id: string
}
/**
 * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings appear as unpadded base64url and cannot be told apart from text.
 */
export interface ParamsValue {
  [k: string]: unknown
}
/**
 * A session and the epoch it was addressed in.
 */
export interface SessionRef {
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The bounded header every stream sends first.
 */
export interface StreamHeader {
  /**
   * The control connection this stream is validated against.
   */
  connection_id: string
  /**
   * What this stream carries.
   */
  kind: 'control' | 'terminal_output' | 'terminal_input' | 'semantic_updates' | 'attachment_chunks'
  resource: StreamResource
  /**
   * The event stream this data stream corresponds to, where one applies.
   */
  stream_id: StreamId | null
}
/**
 * The authorised resource.
 */
export interface StreamResource {
  /**
   * The attachment, for attachment-scoped terminal streams.
   */
  attachment_id: AttachmentId | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The session, for session streams.
   */
  session_id: SessionId | null
  /**
   * The transfer, for attachment chunk streams.
   */
  transfer_id: TransferId | null
}
