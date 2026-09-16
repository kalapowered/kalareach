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
 * One signed revocation request published by a remote owner.
 */
export type RevocationRequestId = string
/**
 * A versioned capability name. Capabilities describe feasibility, never authority.
 */
export type CapabilityId = string
/**
 * The host's answer to a client proof.
 */
export type ConnectReply =
  | {
      accepted: ConnectAccepted
    }
  | {
      refused: ProtocolError
    }
/**
 * An opaque diagnostic identifier. It carries no protocol meaning.
 */
export type DiagnosticId = string
/**
 * One frame on an authorised control stream.
 *
 * The union is closed. A receiver that cannot name the variant rejects the frame rather than
 * guessing, which is what keeps an unknown method a correlated error instead of a parse failure.
 *
 * Both transports carry these frames: section 23 says local Unix sockets and Windows named pipes
 * carry the same typed frames with local peer authentication. What differs is how the connection
 * is authenticated before the first frame, not what travels afterwards.
 */
export type ControlFrame =
  | {
      request: Request
    }
  | {
      mutation: MutationRequest
    }
  | {
      response: Response
    }
  | {
      receipt: ReceiptResponse
    }
  | {
      notification: Notification
    }
  | {
      event: ControlEvent
    }
/**
 * Changes when the active upstream execution owner or selected thread changes.
 */
export type AgentBindingRevision = string
/**
 * One foreground application within a terminal session.
 */
export type ApplicationInstanceId = string
/**
 * The session epoch, fixed at 1 in protocol version 1.
 */
export type SessionEpoch = string
/**
 * One KalaReach terminal session.
 */
export type SessionId = string
/**
 * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
 */
export type ParamsValue = unknown
/**
 * A UTC timestamp in milliseconds, as a decimal string in JSON.
 */
export type TimestampMs = string
/**
 * Why an action was rejected before dispatch.
 */
export type RejectionReason =
  'admission_failed' | 'expired' | 'cancelled' | 'revoked' | 'stale_preconditions'
/**
 * What the host sends on an authorised control stream outside a response.
 *
 * The control stream carries ordinary [`Notification`] events once the connection is authorised.
 * These two messages are the connection's own, not an application event: the freshness resource
 * and the transport's liveness belong to the connection rather than to any session.
 */
export type ControlEvent =
  | {
      action_window_renewed: ActionWindow
    }
  | 'keepalive'
/**
 * One installed OS, distribution or container environment and OS user.
 */
export type EnvironmentId = string
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
 * An upstream approval request identifier. Opaque to KalaReach.
 */
export type ApprovalRequestId = string
/**
 * One agent-to-user question.
 */
export type QuestionId = string
/**
 * The host's answer to a `hello` offer.
 *
 * A major mismatch answers [`ErrorCode::UnsupportedSchema`] here and the connection carries no
 * session data. Every other refusal before device authorisation answers here too, so a client
 * never has to distinguish a closed stream from a rejected offer.
 */
export type HelloReply =
  | {
      selected: HostSelection
    }
  | {
      refused: ProtocolError
    }
/**
 * A managed account identifier minted by the service. It names the payer; it is not authority.
 */
export type AccountId = string
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
 * The upstream agent's conversation identifier, where available. Correlation data, not authority.
 */
export type AgentThreadId = string
/**
 * The upstream agent's current turn identifier, where available.
 */
export type AgentTurnId = string
/**
 * One backup archive. The service sees only this opaque identifier.
 */
export type ArchiveId = string
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
 * The backup generation an archive belongs to. Only its producer advances it.
 */
export type BackupGeneration = string
/**
 * One encrypted object inside a backup archive.
 */
export type BackupObjectId = string
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
 * The group a notification replaces others in on the device. It reveals no project or session name.
 */
export type CollapseId = string
/**
 * One owner-confirmation challenge: single use and bound to one action digest.
 */
export type ConfirmationId = string
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
 * One durable device-owned draft, independent of an attachment.
 */
export type DraftId = string
/**
 * The exact version of a draft.
 */
export type DraftRevision = string
/**
 * One stored mailbox envelope: 128 random bits.
 */
export type EnvelopeId = string
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
 * One notification, named by the host that produced it. Opaque to the gateway and the provider.
 */
export type NotificationId = string
/**
 * One organisation whose signed policy a host has opted into.
 */
export type OrganisationId = string
/**
 * The sequence number of one message inside a pairing bundle exchange.
 */
export type PairingSequence = string
/**
 * The service record that authorised one principal to pay for another's relay traffic.
 */
export type PayerAuthorisationId = string
/**
 * A plugin identifier from its manifest.
 */
export type PluginId = string
/**
 * The revision of an organisation's policy-signing key, advanced on every rotation.
 */
export type PolicyKeyRevision = string
/**
 * One environment-bound source repository.
 */
export type ProjectRepositoryId = string
/**
 * One attempt to bind a push token to an installation. 128 random bits.
 */
export type PushRegistrationId = string
/**
 * One installation's authorisation of one paired host to send it notifications.
 */
export type PushSenderRecordId = string
/**
 * The revision of one push sender record, advanced by the gateway on every renewal.
 */
export type PushSenderRevision = string
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
 * One relay instance. Stable across rotation of the key it signs receipts with.
 */
export type RelayInstanceId = string
/**
 * One relay lease, covering one endpoint pair for one payer.
 */
export type RelayLeaseId = string
/**
 * The revision of one relay lease. Only the issuing service advances it.
 */
export type RelayLeaseRevision = string
/**
 * The position of one consumption receipt inside its reservation's sequence.
 */
export type RelayReceiptSequence = string
/**
 * The deployment region one relay instance serves.
 */
export type RelayRegion = string
/**
 * The revision of one relay instance's registration. Only the instance advances it.
 */
export type RelayRegistrationRevision = string
/**
 * One reserved block of relay bytes. Consumption receipts are keyed by it.
 */
export type RelayReservationId = string
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
 * What `pair.status` reports.
 *
 * It never reveals secret material, and the host returns it only to the candidate's authenticated
 * endpoint or to the issuing owner.
 */
export type PairStatus =
  | {
      open: {
        /**
         * A UTC timestamp in milliseconds, as a decimal string in JSON.
         */
        expires_at_ms: string
        /**
         * Remaining failed-confirmation allowance on the host.
         */
        remaining_confirmations: number
      }
    }
  | {
      locked: {
        /**
         * The candidate that holds it.
         */
        attempt_id: string
        /**
         * A UTC timestamp in milliseconds, as a decimal string in JSON.
         */
        expires_at_ms: string
      }
    }
  | {
      awaiting_approval: {
        /**
         * The candidate's attempt.
         */
        attempt_id: string
        /**
         * A UTC timestamp in milliseconds, as a decimal string in JSON.
         */
        expires_at_ms: string
        /**
         * The verification value shown on both devices.
         */
        verification_value: string
      }
    }
  | {
      committed: {
        /**
         * One paired device.
         */
        device_id: string
        /**
         * One host-issued authority object.
         */
        grant_id: string
      }
    }
  | {
      consumed: {
        /**
         * Why it was consumed.
         */
        reason: 'denied' | 'expired' | 'cancelled' | 'attempts_exhausted' | 'host_restarted'
      }
    }
/**
 * What the payer's client sends to a relay's control endpoint.
 */
export type RelayLeaseRequest =
  | {
      install: {
        lease: SignedRelayLease
      }
    }
  | {
      revoke: {
        revocation: SignedRelayLeaseRevocation
      }
    }
/**
 * One relay URL, discovery origin or direct-address hint: printable ASCII without spaces, 1 to 253 bytes.
 */
export type NetworkHint = string

/**
 * Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.
 */
export interface KalaReachProtocol {
  action_window?: ActionWindow
  actor_envelope?: ActorEnvelope
  archive_descriptor?: ArchiveDescriptor
  authority_revision_record?: AuthorityRevisionRecord
  client_offer?: ClientOffer
  connect_reply?: ConnectReply
  control_frame?: ControlFrame
  direct_challenge?: DirectChallenge
  direct_redeem_proof?: DirectRedeemProof
  envelope_plaintext?: EnvelopePlaintext
  generation_checkpoint?: GenerationCheckpoint
  grant?: Grant
  hello_reply?: HelloReply
  host_selection?: HostSelection
  /**
   * Every identifier in the identity and object model. This is a vocabulary rather than a message: it exists so each identifier has one named type.
   */
  identifiers?: {
    account_id?: AccountId
    action_id?: ActionId
    action_window_id?: ActionWindowId
    actor_id?: ActorId
    agent_binding_revision?: AgentBindingRevision
    agent_thread_id?: AgentThreadId
    agent_turn_id?: AgentTurnId
    application_instance_id?: ApplicationInstanceId
    approval_request_id?: ApprovalRequestId
    archive_id?: ArchiveId
    attachment_id?: AttachmentId
    attachment_ordinal?: AttachmentOrdinal
    attempt_id?: AttemptId
    authority_revision?: AuthorityRevision
    backup_generation?: BackupGeneration
    backup_object_id?: BackupObjectId
    boot_epoch?: BootEpoch
    build_id?: BuildId
    capability_id?: CapabilityId
    capability_revision?: CapabilityRevision
    causal_root_id?: CausalRootId
    change_set_id?: ChangeSetId
    change_set_version?: ChangeSetVersion
    clock_epoch?: ClockEpoch
    collapse_id?: CollapseId
    confirmation_id?: ConfirmationId
    connection_id?: ConnectionId
    controller_generation?: ControllerGeneration
    desktop_session_id?: DesktopSessionId
    device_id?: DeviceId
    device_key_revision?: DeviceKeyRevision
    diagnostic_id?: DiagnosticId
    draft_id?: DraftId
    draft_revision?: DraftRevision
    envelope_id?: EnvelopeId
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
    notification_id?: NotificationId
    organisation_id?: OrganisationId
    pairing_sequence?: PairingSequence
    payer_authorisation_id?: PayerAuthorisationId
    plugin_id?: PluginId
    policy_key_revision?: PolicyKeyRevision
    project_repository_id?: ProjectRepositoryId
    push_registration_id?: PushRegistrationId
    push_sender_record_id?: PushSenderRecordId
    push_sender_revision?: PushSenderRevision
    question_id?: QuestionId
    question_revision?: QuestionRevision
    raw_bytes?: Bytes
    raw_duration_ms?: DurationMs
    raw_timestamp_ms?: TimestampMs
    raw_u64?: U64
    raw_uuid?: Uuid
    relay_instance_id?: RelayInstanceId
    relay_lease_id?: RelayLeaseId
    relay_lease_revision?: RelayLeaseRevision
    relay_receipt_sequence?: RelayReceiptSequence
    relay_region?: RelayRegion
    relay_registration_revision?: RelayRegistrationRevision
    relay_reservation_id?: RelayReservationId
    remote_dispatch_lease_id?: RemoteDispatchLeaseId
    repository_generation?: RepositoryGeneration
    request_id?: RequestId
    revocation_request_id?: RevocationRequestId
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
  membership_lease?: MembershipLease
  method_entry?: MethodEntry
  mutation_request?: MutationRequest
  notification?: Notification
  owner_confirmation_proof?: OwnerConfirmationProof
  owner_confirmation_request?: OwnerConfirmationRequest1
  pair_finish_request?: PairFinishRequest
  pair_status?: PairStatus
  policy_authority?: PolicyAuthority
  proposed_grant?: ProposedGrant
  protocol_error?: ProtocolError
  push_delivery_ack?: PushDeliveryAck
  push_delivery_credential?: PushDeliveryCredential
  push_delivery_request?: PushDeliveryRequest
  push_installation_binding?: PushInstallationBinding
  push_registration_answer?: PushRegistrationAnswer
  push_registration_challenge?: PushRegistrationChallenge
  push_sender_record?: PushSenderRecord
  push_sender_renewal?: PushSenderRenewal
  push_sender_revocation?: PushSenderRevocation
  receipt?: Receipt1
  receipt_response?: ReceiptResponse
  recovery_bundle?: RecoveryBundle
  recovery_kit?: RecoveryKit
  relay_consumption_ack?: RelayConsumptionAck
  relay_consumption_report?: RelayConsumptionReport
  relay_lease_ack?: RelayLeaseAck
  relay_lease_request?: RelayLeaseRequest
  request?: Request
  response?: Response
  revocation_acknowledgement?: RevocationAcknowledgement
  revocation_request?: RevocationRequest
  sealed_envelope?: SealedEnvelope
  service_request_signature?: ServiceRequestSignature
  session_ref?: SessionRef
  signed_archive_manifest?: SignedArchiveManifest
  signed_client_bundle?: SignedClientBundle
  signed_host_bundle?: SignedHostBundle
  signed_relay_consumption_receipt?: SignedRelayConsumptionReceipt
  signed_relay_instance_registration?: SignedRelayInstanceRegistration
  stream_header?: StreamHeader
}
/**
 * A host-issued action window.
 *
 * Section 9: an original online request carries a window bound to this authenticated connection
 * and to the host's boot identity, and the host derives the accepted deadline from the earliest
 * of window expiry, receipt time plus the requested time to live, and any authority or subject
 * deadline. The window carries a *duration*, not an absolute wall-clock deadline: the client
 * schedules its renewal from that duration, while the host keeps the authoritative deadline on
 * its own suspend-aware continuous clock. `issued_at_ms` is the host's stamp, for display and
 * diagnosis only.
 */
export interface ActionWindow {
  /**
   * The window identity a mutation names.
   */
  action_window_id: string
  /**
   * The host boot the window is bound to. A restart invalidates new admission through it.
   */
  boot_epoch: string
  /**
   * The connection the window is bound to.
   */
  connection_id: string
  /**
   * The host's stamp of when it issued the window, in UTC milliseconds.
   */
  issued_at_ms: string
  /**
   * How long the window stays valid, at most [`crate::limits::MAX_ACTION_WINDOW`].
   */
  valid_for_ms: string
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
 * The public descriptor of one archive.
 *
 * Everything outside it is opaque: the archive identity and encrypted-object references. The
 * descriptor is validated before any object is allocated or written, so an invalid one costs
 * nothing.
 */
export interface ArchiveDescriptor {
  /**
   * The archive.
   */
  archive_id: string
  /**
   * The generation this descriptor points at.
   */
  backup_generation: string
  encrypted_manifest: EncryptedObjectRef
  /**
   * The manifest key, wrapped once per authorised recipient.
   */
  manifest_key_wraps: SealedKeyWrap[]
  /**
   * The descriptor version.
   */
  version: string
}
/**
 * The encrypted manifest object.
 */
export interface EncryptedObjectRef {
  /**
   * The stored size of the encrypted object, in bytes.
   */
  encrypted_len: string
  /**
   * The SHA-256 of the encrypted object, including its `secretstream` header.
   */
  encrypted_object_hash: string
  /**
   * The object identity.
   */
  object_id: string
}
/**
 * One wrapped object key.
 *
 * Every wrap uses a fresh random 24-byte nonce. Reusing stored ciphertext when an upload resumes
 * never reuses a nonce for a new wrap.
 */
export interface SealedKeyWrap {
  /**
   * The `crypto_box_easy` output over the canonical wrap plaintext.
   */
  ciphertext: string
  context: KeyWrapContext
  /**
   * The fresh 24-byte nonce.
   */
  nonce: string
}
/**
 * The fields the wrap authenticates.
 */
export interface KeyWrapContext {
  /**
   * The archive.
   */
  archive_id: string
  /**
   * The backup generation.
   */
  backup_generation: string
  /**
   * The SHA-256 of the encrypted object.
   */
  encrypted_object_hash: string
  /**
   * The wrap format.
   */
  format: 'kr-keywrap/1'
  /**
   * The object the key belongs to.
   */
  object_id: string
  /**
   * What the wrapped key opens.
   */
  purpose: 'manifest_key' | 'object_key'
  /**
   * The recipient's stored-envelope key.
   */
  recipient_key_id: string
  /**
   * The sender's stored-envelope key.
   */
  sender_key_id: string
}
/**
 * One ordered authority revision, issued by the host and by nobody else.
 */
export interface AuthorityRevisionRecord {
  /**
   * The revocation requests this revision applied, in ascending order.
   */
  applied_requests: RevocationRequestId[]
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The key identifier of the host's authorisation key.
   */
  host_key_id: string
  /**
   * When the host issued it, in UTC milliseconds.
   */
  issued_at_ms: string
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  previous_revision: string
  /**
   * The Ed25519 signature over `CBOR(["kr-authority/1", record without this field])`.
   */
  signature: string
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
   * Maximum complete attachment frame, in bytes, length prefix included.
   */
  max_attachment_frame_len: string
  /**
   * Maximum complete control frame, in bytes, length prefix included.
   */
  max_control_frame_len: string
  /**
   * Maximum complete input frame, in bytes, length prefix included.
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
 * What the host returns once both proofs verify.
 */
export interface ConnectAccepted {
  action_window: ActionWindow1
  host_proof: ConnectProof
}
/**
 * The first action window of this connection.
 */
export interface ActionWindow1 {
  /**
   * The window identity a mutation names.
   */
  action_window_id: string
  /**
   * The host boot the window is bound to. A restart invalidates new admission through it.
   */
  boot_epoch: string
  /**
   * The connection the window is bound to.
   */
  connection_id: string
  /**
   * The host's stamp of when it issued the window, in UTC milliseconds.
   */
  issued_at_ms: string
  /**
   * How long the window stays valid, at most [`crate::limits::MAX_ACTION_WINDOW`].
   */
  valid_for_ms: string
}
/**
 * The host's own proof over the same transcript.
 */
export interface ConnectProof {
  /**
   * The signature over the connection transcript, made with the paired authorisation key.
   */
  signature: string
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
   * The method's parameters.
   */
  params: unknown
  /**
   * Correlates the response. Unique for the lifetime of one connection.
   */
  request_id: string
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
  expected: unknown
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
  params: unknown
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
 * The response to a mutation request.
 *
 * A duplicate request from a still-authorised actor returns the retained receipt without
 * dispatch. The host checks current authority before returning it, so a revoked device cannot use
 * an old action identifier to retrieve protected information.
 */
export interface ReceiptResponse {
  receipt: Receipt
  /**
   * The request this response correlates with.
   */
  request_id: string
}
/**
 * The current receipt.
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
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
   */
  payload: unknown
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
 * The host challenge a direct redemption starts from. Single use, and it expires with the
 * invitation.
 */
export interface DirectChallenge {
  /**
   * The revision of those keys.
   */
  device_key_revision: string
  /**
   * The host's iroh endpoint identity.
   */
  endpoint_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  host_keys: DevicePublicKeys
  /**
   * The fresh host nonce.
   */
  host_nonce: string
  /**
   * The invitation.
   */
  invitation_id: string
}
/**
 * The host's complete purpose-key bundle.
 */
export interface DevicePublicKeys {
  /**
   * The Ed25519 authorisation key.
   */
  authorisation: string
  /**
   * The X25519 notification-preview key.
   */
  notification_preview: string
  /**
   * The X25519 stored-envelope key.
   */
  stored_envelope: string
  /**
   * The iroh transport identity.
   */
  transport: string
}
/**
 * The proof a candidate submits in direct mode.
 */
export interface DirectRedeemProof {
  client_keys: DevicePublicKeys1
  /**
   * The candidate's fresh nonce.
   */
  client_nonce: string
  /**
   * The revision of those keys.
   */
  device_key_revision: string
  /**
   * The candidate's display name.
   */
  device_name: string
  /**
   * The host challenge this redemption answers.
   */
  host_nonce: string
  /**
   * The invitation being redeemed.
   */
  invitation_id: string
  /**
   * The candidate's platform.
   */
  platform: 'macos' | 'windows' | 'linux' | 'ios' | 'android'
  /**
   * `HMAC-SHA256(invitation_secret, D)`.
   */
  secret_proof: string
  /**
   * The candidate's Ed25519 signature over `D`.
   */
  signature: string
}
/**
 * The candidate's complete purpose-key bundle.
 */
export interface DevicePublicKeys1 {
  /**
   * The Ed25519 authorisation key.
   */
  authorisation: string
  /**
   * The X25519 notification-preview key.
   */
  notification_preview: string
  /**
   * The X25519 stored-envelope key.
   */
  stored_envelope: string
  /**
   * The iroh transport identity.
   */
  transport: string
}
/**
 * The authenticated plaintext of one mailbox envelope.
 *
 * `crypto_box_easy` authenticates every field below for exactly one recipient. Authorisation-
 * bearing payloads are signed before encryption, so pairwise message authentication never
 * substitutes for an issuer's grant signature.
 */
export interface EnvelopePlaintext {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The envelope identity. It is also the replay identifier.
   */
  envelope_id: string
  /**
   * The environment the payload targets, when it targets one.
   */
  environment_id: EnvironmentId | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The grant the payload acts under, when it has one.
   */
  grant_id: GrantId | null
  /**
   * The payload. An authorisation-bearing payload is a signed object's canonical bytes.
   */
  payload: string
  /**
   * What the payload is.
   */
  payload_type:
    'authority_feed_change' | 'signed_authority_object' | 'notification_preview' | 'sync_change'
  /**
   * The recipient's stored-envelope key.
   */
  recipient_key_id: string
  /**
   * The sender's stored-envelope key.
   */
  sender_key_id: string
  /**
   * The epoch of that session.
   */
  session_epoch: SessionEpoch | null
  /**
   * The session the payload targets, when it targets one.
   */
  session_id: SessionId | null
  /**
   * The envelope format version.
   */
  version: 'kr-mailbox/1'
}
/**
 * A stored backup checkpoint a pairing transfers.
 *
 * A fresh client needs a trusted latest-generation checkpoint to detect a service replaying an
 * older valid backup. Pairing is where that checkpoint moves between devices.
 */
export interface GenerationCheckpoint {
  /**
   * The archive the checkpoint describes.
   */
  archive_id: string
  /**
   * The latest generation the sending device has seen.
   */
  backup_generation: string
  /**
   * The hash of that generation's encrypted manifest.
   */
  encrypted_manifest_hash: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  observed_at_ms: string
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
           * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
   * Maximum complete attachment frame, in bytes, length prefix included.
   */
  max_attachment_frame_len: string
  /**
   * Maximum complete control frame, in bytes, length prefix included.
   */
  max_control_frame_len: string
  /**
   * Maximum complete input frame, in bytes, length prefix included.
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
 * A signed statement that one account held one role in one organisation.
 */
export interface MembershipLease {
  payload: MembershipLeasePayload
  /**
   * The policy-signing key's signature over [`MembershipLeasePayload::signing_input`].
   */
  signature: string
}
/**
 * What the organisation states.
 */
export interface MembershipLeasePayload {
  /**
   * The account it names as a member.
   */
  account_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The policy-key revision that signed it.
   */
  key_revision: string
  /**
   * The most the role may carry. A host intersects this with its own policy.
   */
  maximum_grants: ActionRight[]
  /**
   * The organisation the lease speaks for.
   */
  organisation_id: string
  /**
   * The role that account held when the lease was signed.
   */
  role: 'viewer' | 'reviewer' | 'controller' | 'owner'
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
 * An owner's answer to a confirmation challenge.
 *
 * The verification ceremony itself is platform code; this object records its result and binds it
 * to the exact challenge. The host's acceptance record keeps the user-presence evidence and the
 * challenge-consumption transition together.
 */
export interface OwnerConfirmationProof {
  /**
   * How the confirmation reached the host.
   */
  channel:
    | 'owner_device_presence'
    | 'paired_owner_device'
    | 'enrolled_presence_signer'
    | 'local_bootstrap_terminal'
    | 'session'
    | 'plugin'
    | 'contact_tool'
  request: OwnerConfirmationRequest
  /**
   * The Ed25519 signature over `CBOR(["kr-pair/owner-confirm/1", request, channel])`.
   */
  signature: string
  /**
   * The key identifier of the signer that produced the proof.
   */
  signer_key_id: string
}
/**
 * The challenge this proof answers.
 */
export interface OwnerConfirmationRequest {
  /**
   * What is being confirmed.
   */
  action:
    | 'issue_invitation'
    | 'confirm_device'
    | 'enlarge_grant'
    | 'trust_repository_root'
    | 'grant_executable_capability'
    | 'change_host_authority'
  /**
   * The digest of the exact action. One confirmation authorises one digest.
   */
  action_digest: string
  /**
   * The challenge identity. Single use.
   */
  confirmation_id: string
  /**
   * The keys the action sends authority to. Null when the action has no destination device.
   */
  destination_keys: DevicePublicKeys2 | null
  /**
   * The rights the action would grant.
   */
  destination_rights: ActionRight[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The host's iroh endpoint identity.
   */
  host_endpoint_id: string
  /**
   * The host's fresh challenge nonce.
   */
  nonce: string
}
/**
 * One device's four purpose-separated public keys.
 *
 * An authenticated pairing exchange binds these public keys and their explicit purposes to one
 * device record.
 */
export interface DevicePublicKeys2 {
  /**
   * The Ed25519 authorisation key.
   */
  authorisation: string
  /**
   * The X25519 notification-preview key.
   */
  notification_preview: string
  /**
   * The X25519 stored-envelope key.
   */
  stored_envelope: string
  /**
   * The iroh transport identity.
   */
  transport: string
}
/**
 * A host-issued owner-confirmation challenge.
 */
export interface OwnerConfirmationRequest1 {
  /**
   * What is being confirmed.
   */
  action:
    | 'issue_invitation'
    | 'confirm_device'
    | 'enlarge_grant'
    | 'trust_repository_root'
    | 'grant_executable_capability'
    | 'change_host_authority'
  /**
   * The digest of the exact action. One confirmation authorises one digest.
   */
  action_digest: string
  /**
   * The challenge identity. Single use.
   */
  confirmation_id: string
  /**
   * The keys the action sends authority to. Null when the action has no destination device.
   */
  destination_keys: DevicePublicKeys2 | null
  /**
   * The rights the action would grant.
   */
  destination_rights: ActionRight[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The host's iroh endpoint identity.
   */
  host_endpoint_id: string
  /**
   * The host's fresh challenge nonce.
   */
  nonce: string
}
/**
 * The `pair.finish` request, which binds the pairing transcript to the live iroh identities.
 */
export interface PairFinishRequest {
  /**
   * The attempt.
   */
  attempt_id: string
  /**
   * The tag under the `iroh-bind` key.
   */
  binding_tag: string
  /**
   * The SHA-256 of the canonical client bundle.
   */
  client_bundle_hash: string
  /**
   * The SHA-256 of the canonical host bundle.
   */
  host_bundle_hash: string
  /**
   * The invitation.
   */
  invitation_id: string
  /**
   * The transcript both devices confirmed.
   */
  transcript: string
}
/**
 * An organisation's policy-signing authority as it is published.
 */
export interface PolicyAuthority {
  /**
   * Every revision in order, starting at the first.
   */
  chain: PolicyAuthorityLink[]
  head: PolicyAuthorityHead
  /**
   * The organisation the chain belongs to.
   */
  organisation_id: string
}
/**
 * One step in an organisation's policy-signing authority chain.
 *
 * The first revision signs itself and names no predecessor, which is what a host pins. Every
 * later revision is signed by the revision it names, so a host that pinned the first can follow
 * the chain to the key signing now, and a link cannot be re-parented under a revision it was not
 * issued against.
 *
 * A link carries no expiry, because when a revision stops signing is not known when it is issued.
 * Its successor's `not_before_ms` is when it stopped.
 */
export interface PolicyAuthorityLink {
  payload: PolicyAuthorityLinkPayload
  /**
   * The predecessor's signature over [`PolicyAuthorityLinkPayload::signing_input`], or this
   * revision's own at the first revision.
   */
  signature: string
}
/**
 * What this revision states.
 */
export interface PolicyAuthorityLinkPayload {
  /**
   * The revision this link establishes.
   */
  key_revision: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  not_before_ms: string
  /**
   * The organisation whose chain this link belongs to.
   */
  organisation_id: string
  /**
   * The revision whose key signed it, or null at the first revision, which signs itself.
   */
  previous_key_revision: PolicyKeyRevision | null
  /**
   * The Ed25519 public key of this revision.
   */
  public_key: string
}
/**
 * Which revision signs now, signed by that revision.
 */
export interface PolicyAuthorityHead {
  payload: PolicyAuthorityHeadPayload
  /**
   * The signature of the revision the statement names, over
   * [`PolicyAuthorityHeadPayload::signing_input`].
   */
  signature: string
}
/**
 * What the authority states.
 */
export interface PolicyAuthorityHeadPayload {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The revision of an organisation's policy-signing key, advanced on every rotation.
   */
  key_revision: string
  /**
   * The organisation this statement belongs to.
   */
  organisation_id: string
}
/**
 * The rights an invitation proposes, before the host issues a grant.
 *
 * The client cannot enlarge the grant through its bundle: the host commits the grant it proposed,
 * and the proposal is covered by the transcript both devices confirmed.
 */
export interface ProposedGrant {
  /**
   * The actions it permits.
   */
  actions: ActionRight[]
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
           * A UTC timestamp in milliseconds, as a decimal string in JSON.
           */
          expires_at_ms: string
        }
      }
  history: HistoryScope1
  /**
   * An optional organisation membership requirement.
   */
  organisation: OrganisationRequirement | null
  /**
   * The grant this one will be delegated from, when it is a delegation.
   */
  parent_grant_id: GrantId | null
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
export interface HistoryScope1 {
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
 * The gateway's answer to one delivery request.
 */
export interface PushDeliveryAck {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  decided_at_ms: string
  /**
   * The notification this answers.
   */
  notification_id: string
  /**
   * What became of it.
   */
  state: 'queued' | 'collapsed' | 'duplicate' | 'token_disabled' | 'expired'
  /**
   * What was suppressed, when anything was.
   */
  suppression: PushSuppression | null
}
/**
 * What the gateway suppressed, so the host can record it.
 *
 * The host retains every request it made and reports suppression locally, which is what keeps a
 * suppressed notification from becoming a lost decision: the pending work is still on the host and
 * still visible there.
 */
export interface PushSuppression {
  /**
   * The attention update this collapsed into.
   */
  collapsed_into: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  next_update_at_ms: string
  /**
   * Which allowance was spent.
   */
  reason: 'burst' | 'sustained'
  /**
   * How many notifications have collapsed into the current update, including this one.
   */
  suppressed_count: string
}
/**
 * The bearer a host presents to deliver, and what it is bound to.
 *
 * It is returned to the installation once, at issue and at each renewal, and the installation
 * passes it to the host through the paired encrypted channel. It grants delivery to one
 * destination and nothing else: it is not a session, it reads nothing and it cannot be presented
 * to any other method.
 *
 * The gateway stores [`PushDeliveryCredential::secret_digest`], never the secret. A copy of the
 * database is therefore not a set of working credentials.
 */
export interface PushDeliveryCredential {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The gateway that issued it.
   */
  gateway_origin: string
  /**
   * The destination installation.
   */
  installation_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The revision of the record it was issued against.
   */
  revision: string
  /**
   * The bearer itself. It reaches a log or a debug rendering as a redaction.
   */
  secret: string
  /**
   * The authorisation it delivers under.
   */
  sender_record_id: string
}
/**
 * One notification, as a host hands it to the gateway.
 *
 * The host writes the underlying event first and then sends this, so a notification that is never
 * delivered has already been recorded somewhere the person can find it. Nothing here is plaintext
 * that describes the work: the identifier is opaque, the collapse label names no project, the
 * alert comes from a closed vocabulary, and the preview is sealed to the device.
 *
 * Larger detail does not belong here. Section 16 bounds the preview plaintext to
 * [`MAX_PREVIEW_PLAINTEXT_BYTES`] and the complete provider payload to
 * [`MAX_PROVIDER_PAYLOAD_BYTES`], and says to move the excess into a referenced encrypted object
 * rather than trusting an expansion ratio.
 */
export interface PushDeliveryRequest {
  /**
   * The group this replaces others in on the device.
   */
  collapse_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  hints: PushPlatformHints
  /**
   * The notification's identity. The gateway deduplicates by it and never reads it.
   */
  notification_id: string
  /**
   * The sealed preview envelope, or null when the destination has previews disabled.
   *
   * The bytes are a [`crate::mailbox::SealedEnvelope`] whose payload type is a notification
   * preview. The gateway forwards them; it holds no key that opens them.
   */
  preview: Bytes | null
  /**
   * The authorisation this is delivered under.
   */
  sender_record_id: string
}
/**
 * What to ask each platform for.
 */
export interface PushPlatformHints {
  /**
   * Which generic alert to show.
   */
  alert:
    | 'session_needs_attention'
    | 'approval_waiting'
    | 'question_waiting'
    | 'work_complete'
    | 'host_unreachable'
    | 'attention_update'
  /**
   * How urgently to deliver.
   */
  urgency: 'attention' | 'deferred'
}
/**
 * The canonical active binding of one provider token to one installation.
 *
 * There is exactly one of these per token digest. That is what stops an installation from
 * registering the same token under a second identity to start its rate history again: a second
 * identity for one token is not an additional binding, it is a replacement, and a replacement has
 * to pass its own challenge.
 */
export interface PushInstallationBinding {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  bound_at_ms: string
  /**
   * The gateway holding it.
   */
  gateway_origin: string
  /**
   * The installation the token delivers to.
   */
  installation_id: string
  /**
   * The public key that installation authenticates with.
   */
  installation_key: string
  /**
   * The platform the token belongs to.
   */
  platform: 'android' | 'ios'
  /**
   * The attempt whose answer established it.
   */
  registration_id: string
  /**
   * Whether the provider still delivers to the token.
   */
  state: 'active' | 'disabled'
  /**
   * The token, as the gateway records it.
   */
  token_digest: string
}
/**
 * The receiver's answer to a challenge, signed by the proposed installation key.
 *
 * The receiver answers only for its own locally pending registration and its own public key. It
 * does not sign a challenge that names an attempt it did not start, or an installation identifier
 * that is not the one its key derives, so a challenge aimed at a token in the hope of a reply gets
 * none.
 */
export interface PushRegistrationAnswer {
  /**
   * The public half of the key that answered. Its SHA-256 names the installation.
   */
  installation_key: string
  payload: PushRegistrationAnswerPayload
  /**
   * The signature over [`PushRegistrationAnswerPayload::signing_input`].
   */
  signature: string
}
/**
 * What the receiver states.
 */
export interface PushRegistrationAnswerPayload {
  /**
   * The value that arrived through the provider.
   */
  challenge: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The gateway that issued the challenge.
   */
  gateway_origin: string
  /**
   * The installation the answering key names.
   */
  installation_id: string
  /**
   * The platform the token belongs to.
   */
  platform: 'android' | 'ios'
  /**
   * The attempt being answered.
   */
  registration_id: string
  /**
   * The token the challenge was sent to.
   */
  token_digest: string
}
/**
 * The challenge the gateway sends through the provider to a proposed token.
 *
 * It goes to the token, not to the caller. That is the whole point: an authenticated HTTP request
 * proves the caller holds an installation key, and nothing more. Sending a random value to the
 * token and requiring it back signed proves that the installation which holds the key is also the
 * one the provider delivers that token to. Until that returns, the registration stays pending and
 * no sender credential is issued.
 *
 * The challenge is single use. An answer consumes it, and a second answer, whether the same one
 * replayed or another arriving at the same moment, finds nothing pending to answer.
 */
export interface PushRegistrationChallenge {
  /**
   * The single-use random value the receiver returns.
   */
  challenge: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The gateway that issued it.
   */
  gateway_origin: string
  /**
   * The installation the pending registration is for.
   */
  installation_id: string
  /**
   * The platform the token belongs to.
   */
  platform: 'android' | 'ios'
  /**
   * This attempt, so an answer cannot complete a different one.
   */
  registration_id: string
  /**
   * The token the challenge was sent to.
   */
  token_digest: string
}
/**
 * One installation's authorisation of one host, as the gateway holds it.
 *
 * The authorisation and the credential have different lifetimes on purpose. The authorisation is
 * the installation's decision and lasts until the installation revokes it. The credential is a
 * bearer token that a host keeps on disk, so it expires in thirty days and is renewed by proving
 * possession of the key the installation named. An offline host that comes back after its
 * credential expired still renews, because what it proves has not lapsed.
 */
export interface PushSenderRecord {
  binding: PushSenderBinding
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  credential_expires_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The gateway's revision, advanced on every renewal.
   */
  revision: string
  /**
   * Whether the authorisation still stands.
   */
  state: 'active' | 'revoked'
}
/**
 * What the installation authorised, and what a renewal may not change.
 */
export interface PushSenderBinding {
  /**
   * The gateway holding the authorisation.
   */
  gateway_origin: string
  /**
   * The host's iroh endpoint identity, so the installation knows which peer it authorised.
   */
  host_endpoint_key: string
  /**
   * The host's Ed25519 signing key. Renewal and revocation are proven with it.
   */
  host_signing_key: string
  /**
   * The destination installation.
   */
  installation_id: string
  rate_policy: PushRatePolicy
  /**
   * This authorisation.
   */
  sender_record_id: string
}
/**
 * What that destination may receive.
 */
export interface PushRatePolicy {
  /**
   * How many notifications may arrive in a burst.
   */
  burst: string
  /**
   * How often excess collapses into one attention update.
   */
  collapse_window_ms: string
  /**
   * How many may arrive in one hour.
   */
  sustained_per_hour: string
}
/**
 * A host's proof that it still holds the key the installation authorised.
 */
export interface PushSenderRenewal {
  payload: PushSenderRenewalPayload
  /**
   * The host signing key's signature over [`PushSenderRenewalPayload::signing_input`].
   */
  signature: string
}
/**
 * What the host states.
 */
export interface PushSenderRenewalPayload {
  /**
   * The single-use value the gateway handed out for this renewal.
   */
  gateway_nonce: string
  /**
   * The gateway that issued the nonce.
   */
  gateway_origin: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  requested_at_ms: string
  /**
   * The authorisation being renewed.
   */
  sender_record_id: string
}
/**
 * A host's statement that an authorisation is finished.
 */
export interface PushSenderRevocation {
  payload: PushSenderRevocationPayload
  /**
   * The host signing key's signature over [`PushSenderRevocationPayload::signing_input`].
   */
  signature: string
}
/**
 * What the host states.
 */
export interface PushSenderRevocationPayload {
  /**
   * The single-use value the gateway handed out for this revocation.
   */
  gateway_nonce: string
  /**
   * The gateway that issued the nonce.
   */
  gateway_origin: string
  /**
   * Why the authorisation is ending.
   */
  reason: 'unpaired' | 'host_key_replaced' | 'installation_key_replaced'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  requested_at_ms: string
  /**
   * The authorisation being revoked.
   */
  sender_record_id: string
}
/**
 * One action receipt.
 *
 * The de-duplication key is `(actor_id, action_id)`. An exact duplicate returns the stored
 * receipt; a reused identifier with a different payload digest is an `ID_CONFLICT`.
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
 * The versioned recovery bundle an owner keeps at a stable locator.
 *
 * Enabling a new backup writer or rotating its signing key commits an updated bundle before that
 * writer is declared recovery-enabled.
 */
export interface RecoveryBundle {
  /**
   * The latest generation the owner verified for each archive.
   */
  checkpoints: ArchiveCheckpoint[]
  /**
   * Where the owner's collections live.
   */
  collections: CollectionLocator[]
  /**
   * The bundle revision, advanced on every compare-and-swap write.
   */
  revision: string
  /**
   * The bundle schema version.
   */
  schema_version: string
  /**
   * The writers a restore may trust.
   */
  trusted_writers: TrustedWriter[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  written_at_ms: string
}
/**
 * The latest generation an owner has verified for one archive.
 *
 * A fresh client needs this to detect a service replaying an older valid backup. A recovery-only
 * restore still shows its checkpoint and cannot prove that no newer archive exists.
 */
export interface ArchiveCheckpoint {
  /**
   * The archive.
   */
  archive_id: string
  /**
   * The latest generation the owner verified.
   */
  backup_generation: string
  /**
   * The hash of that generation's encrypted manifest.
   */
  encrypted_manifest_hash: string
  /**
   * When the owner verified it, in UTC milliseconds.
   */
  verified_at_ms: string
}
/**
 * One collection a recovery bundle can find.
 */
export interface CollectionLocator {
  /**
   * The archive the locator points at.
   */
  archive_id: string
  /**
   * The stable opaque locator of the collection.
   */
  locator: string
  /**
   * The service origin the collection lives at.
   */
  service_origin: string
}
/**
 * A backup writer a restore is allowed to trust.
 */
export interface TrustedWriter {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  enrolled_at_ms: string
  /**
   * The writer's Ed25519 signing public key.
   */
  signing_key: string
  /**
   * The writer's signing key identifier.
   */
  writer_key_id: string
}
/**
 * The printable and QR recovery kit.
 *
 * A seed with no way to find the encrypted bundle is not a complete kit, so the kit names the
 * configured service origins and the stable bundle locator alongside the seed.
 *
 * `Debug` is derived, and the seed redacts itself, so a kit can be logged without publishing the
 * owner's recovery authority.
 */
export interface RecoveryKit {
  /**
   * The stable opaque locator of the recovery bundle.
   */
  bundle_locator: string
  /**
   * The kit format and cryptographic profile version.
   */
  profile_version: string
  /**
   * The 256-bit recovery seed. It zeroises when the kit is dropped and never appears in debug
   * output: it is the whole of the owner's recovery authority.
   */
  seed: string
  /**
   * An opaque byte string. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  seed_checksum: string
  /**
   * Each configured service origin.
   */
  service_origins: string[]
}
/**
 * The service's answer to a consumption report.
 *
 * It states what the service has recorded rather than what the report contained, so a relay
 * recovering from a crash learns from one exchange exactly which position to replay from.
 */
export interface RelayConsumptionAck {
  /**
   * True when the service is holding out for receipts it has not been given. The reservation
   * stays outstanding until they arrive or until it is settled conservatively.
   */
  awaiting_receipts: boolean
  /**
   * The cumulative bytes recorded for the reservation.
   */
  bytes_recorded: string
  /**
   * The next sequence the service will accept. A relay resumes from here.
   */
  next_sequence: string
  /**
   * The highest sequence recorded for it, or null when none has been.
   */
  recorded_through: RelayReceiptSequence | null
  /**
   * The reservation the report was about.
   */
  reservation_id: string
}
/**
 * What a relay posts to the service to report consumption.
 *
 * A report carries receipts for one reservation in ascending order. Reporting is idempotent, so a
 * relay that is unsure whether a report arrived sends it again rather than skipping it, and a
 * relay resuming after a restart replays from the last position the service acknowledged.
 */
export interface RelayConsumptionReport {
  /**
   * The receipts, in ascending sequence order.
   */
  receipts: SignedRelayConsumptionReceipt[]
  /**
   * The relay instance reporting.
   */
  relay_instance_id: string
  /**
   * The reservation being reported.
   */
  reservation_id: string
}
/**
 * A receipt and the relay instance signature that authenticates it.
 */
export interface SignedRelayConsumptionReceipt {
  receipt: RelayConsumptionReceipt
  /**
   * The Ed25519 signature over `CBOR(["kr-relay/receipt/1", receipt])`, by the registered key
   * of the receipt's relay instance.
   */
  signature: string
}
/**
 * The receipt.
 */
export interface RelayConsumptionReceipt {
  /**
   * The bytes spent from the reservation so far. Cumulative and never decreasing.
   */
  bytes_consumed: string
  /**
   * The lease revision that was in force when the count was taken.
   */
  lease_revision: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  observed_at_ms: string
  /**
   * The relay instance that counted the bytes.
   */
  relay_instance_id: string
  /**
   * The reservation the bytes were spent from.
   */
  reservation_id: string
  /**
   * The position of one consumption receipt inside its reservation's sequence.
   */
  sequence: string
}
/**
 * A relay's answer to a control request.
 *
 * An exact retry of an installation answers with the same state and the same running figures: the
 * relay keeps what it has counted, so re-sending a lease can never restore a spent ceiling.
 */
export interface RelayLeaseAck {
  /**
   * The cumulative bytes counted for its reservation so far.
   */
  bytes_consumed: string
  /**
   * The bytes still forwardable under it.
   */
  bytes_remaining: string
  /**
   * The milliseconds of grace left, or null when the pair is not in grace. Section 17 requires
   * the remaining interval to be visible before the relay closes.
   */
  grace_remaining_ms: U64 | null
  /**
   * The lease the request named.
   */
  lease_id: string
  /**
   * The revision the relay now holds.
   */
  revision: string
  /**
   * What the relay holds for that lease.
   */
  state: 'installed' | 'superseded' | 'revoked' | 'expired' | 'exhausted'
}
/**
 * The lease to install. Boxed because a lease is much the larger of the two requests and
 * an unboxed variant would make every revocation carry its size.
 */
export interface SignedRelayLease {
  lease: RelayLease
  /**
   * The Ed25519 signature over `CBOR(["kr-relay/lease/1", lease])`, by the lease's issuer key.
   */
  signature: string
}
/**
 * The lease.
 */
export interface RelayLease {
  /**
   * The cumulative bytes this reservation may reach at the metering boundary. A refill raises
   * it; it never falls.
   */
  byte_ceiling: string
  /**
   * The endpoint that may receive.
   */
  destination_endpoint_key: string
  /**
   * Whether the reverse direction is permitted too.
   */
  direction: 'source_to_destination' | 'bidirectional'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The bounded grace this pair is inside, or null when the principal is not in grace.
   */
  grace: RelayGrace | null
  /**
   * The service admission key that signs this lease. A relay accepts it only when the key is
   * one it pins.
   */
  issuer_key: string
  /**
   * The lease identity. One lease covers one endpoint pair for one payer.
   */
  lease_id: string
  /**
   * The relay instance that counts the bytes. One of the two positions in the scope.
   */
  metering_relay_instance_id: string
  /**
   * Which of that instance's own boundaries takes the count.
   */
  metering_role: 'ingress' | 'egress'
  /**
   * Who is billed.
   */
  payer:
    | {
        account: {
          /**
           * The account that is billed.
           */
          account_id: string
        }
      }
    | {
        installation: {
          /**
           * The installation that is billed.
           */
          installation_id: string
        }
      }
  /**
   * Why that principal is the one billed.
   */
  payer_authorisation:
    | 'host_selected'
    | {
        sponsored: {
          /**
           * The sponsor's authorisation record.
           */
          authorisation_id: string
        }
      }
  relay_scope: RelayScope
  /**
   * The reserved block this lease spends from. It is bound for its lifetime to this lease, this
   * payer, this pair and this metering boundary; changing any of them takes a new reservation.
   */
  reservation_id: string
  /**
   * The revision of this lease. Strictly increasing per lease identity; a relay keeps the
   * highest revision it has seen and refuses anything lower, so a replaced lease cannot be
   * rolled back to an earlier ceiling or an earlier deadline.
   */
  revision: string
  /**
   * The endpoint that may send.
   */
  source_endpoint_key: string
}
/**
 * The bounded grace a principal is inside, as the service has told this relay.
 *
 * Section 17 grants a principal up to fifteen minutes or 100 MiB after exhaustion, whichever ends
 * first, shared across every connection of that principal. It starts at the first exhaustion
 * event, and reconnects, new endpoints and other regions cannot restart it: only the service knows
 * when the principal first exhausted its allowance, and a relay only ever receives what is left of
 * one grace period as a slice of it.
 *
 * The slice is expressed as a raised cumulative ceiling on the same reservation, so the relay has
 * one number to compare its running total against whether the lease is in grace or not.
 */
export interface RelayGrace {
  /**
   * The cumulative bytes this reservation may reach inside the grace. Never below the lease's
   * own ceiling, and above it by at most [`MAX_GRACE_BYTES`].
   */
  byte_ceiling: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  ends_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
}
/**
 * The two relay positions this lease is valid at.
 */
export interface RelayScope {
  /**
   * The relay instance the destination endpoint is connected to.
   */
  egress_relay_instance_id: string
  /**
   * The relay instance the source endpoint is connected to.
   */
  ingress_relay_instance_id: string
}
/**
 * The revocation to apply.
 */
export interface SignedRelayLeaseRevocation {
  revocation: RelayLeaseRevocation
  /**
   * The Ed25519 signature over `CBOR(["kr-relay/revoke/1", revocation])`.
   */
  signature: string
}
/**
 * The revocation.
 */
export interface RelayLeaseRevocation {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The service admission key that signs it.
   */
  issuer_key: string
  /**
   * The lease to stop forwarding under.
   */
  lease_id: string
  /**
   * The relay instance this revocation is addressed to, so one relay's copy cannot be replayed
   * at another.
   */
  relay_instance_id: string
  /**
   * The revision this revocation installs. Strictly higher than the revision it fences.
   */
  revision: string
}
/**
 * The host's acknowledgement of one revocation request.
 */
export interface RevocationAcknowledgement {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  acknowledged_at_ms: string
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * Whether the dispatch barrier has completed.
   */
  completion:
    | 'complete'
    | {
        pending: {
          /**
           * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
           */
          pending_workers: string
        }
      }
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * One signed revocation request published by a remote owner.
   */
  request_id: string
}
/**
 * A remote owner's signed revocation request.
 *
 * A device cannot assign a higher host revision to its own request: the record carries no host
 * revision, because only the target host issues ordered authority revisions.
 */
export interface RevocationRequest {
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * One paired device.
   */
  issuer_device_id: string
  /**
   * The key identifier of the issuer's authorisation key.
   */
  issuer_key_id: string
  /**
   * One signed revocation request published by a remote owner.
   */
  request_id: string
  /**
   * The Ed25519 signature over `CBOR(["kr-revocation/1", request without this field])`.
   */
  signature: string
  /**
   * What it revokes.
   */
  target:
    | {
        grants: {
          /**
           * The grants to revoke.
           */
          grant_ids: GrantId[]
        }
      }
    | {
        devices: {
          /**
           * The devices to revoke.
           */
          device_ids: DeviceId[]
        }
      }
}
/**
 * One envelope sealed for one recipient.
 */
export interface SealedEnvelope {
  /**
   * An opaque byte string. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  ciphertext: string
  /**
   * The fresh 24-byte nonce, from libsodium's random generator.
   */
  nonce: string
  routing: EnvelopeRouting
}
/**
 * The routing record the service sees.
 */
export interface EnvelopeRouting {
  /**
   * The envelope identity the service indexes by.
   */
  envelope_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The recipient the service delivers to.
   */
  recipient_key_id: string
  /**
   * The sender, so a recipient can select a paired sender key before attempting to open.
   */
  sender_key_id: string
  /**
   * The declared size bucket, in bytes: the length of the padded plaintext that was encrypted.
   *
   * Quota accounting measures the complete stored ciphertext rather than this figure.
   */
  size_bucket_bytes: string
}
/**
 * One signed service request.
 *
 * It authenticates a request; it authorises nothing by itself. What the caller may do with the
 * method it names is the service's decision, made from the installation record and the records
 * that method reads.
 */
export interface ServiceRequestSignature {
  payload: ServiceRequestPayload
  /**
   * The Ed25519 public key of that signer.
   */
  public_key: string
  /**
   * The signature over [`ServiceRequestPayload::signing_input`].
   */
  signature: string
  /**
   * Which key signed it, and therefore which domain the signature is checked under.
   */
  signer: 'installation' | 'host'
}
/**
 * What was signed.
 */
export interface ServiceRequestPayload {
  /**
   * The SHA-256 of the canonical request body.
   */
  body_digest: string
  /**
   * The origin the request was addressed to.
   */
  gateway_origin: string
  /**
   * The method being called.
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
   * A fresh 32-byte nonce, from the caller's random generator.
   */
  nonce: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  signed_at_ms: string
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
 * A manifest and the backup writer's signature over it.
 */
export interface SignedArchiveManifest {
  manifest: ArchiveManifest
  /**
   * The Ed25519 signature over `CBOR(["kr-archive-manifest/1", manifest])`.
   */
  signature: string
  /**
   * The writer's signing key.
   */
  writer_key_id: string
}
/**
 * The manifest.
 */
export interface ArchiveManifest {
  /**
   * The archive.
   */
  archive_id: string
  /**
   * The generation this manifest describes.
   */
  backup_generation: string
  /**
   * When the producer wrote it, in UTC milliseconds.
   */
  created_at_ms: string
  /**
   * The member objects, in the order the producer wrote them.
   */
  objects: ManifestObject[]
  /**
   * One paired device.
   */
  owner_device_id: string
  /**
   * The manifest schema version.
   */
  schema_version: string
}
/**
 * One member of a manifest.
 */
export interface ManifestObject {
  /**
   * The member's filename. Filenames live inside the encrypted manifest, never outside it.
   */
  filename: string
  object: EncryptedObjectRef1
}
/**
 * The encrypted object this entry describes.
 */
export interface EncryptedObjectRef1 {
  /**
   * The stored size of the encrypted object, in bytes.
   */
  encrypted_len: string
  /**
   * The SHA-256 of the encrypted object, including its `secretstream` header.
   */
  encrypted_object_hash: string
  /**
   * The object identity.
   */
  object_id: string
}
/**
 * A candidate bundle and the authorisation signature that binds its key purposes.
 */
export interface SignedClientBundle {
  bundle: ClientBundle
  /**
   * The Ed25519 signature over `CBOR(["kr-pair/client-bundle/1", bundle, T])`.
   */
  signature: string
  /**
   * The transcript the signature covers.
   */
  transcript: string
}
/**
 * The bundle.
 */
export interface ClientBundle {
  /**
   * The revision of those keys.
   */
  device_key_revision: string
  /**
   * The candidate's display name. Display text, never authority.
   */
  device_name: string
  /**
   * The candidate's iroh endpoint identity.
   */
  endpoint_id: string
  keys: DevicePublicKeys3
  /**
   * The candidate's platform.
   */
  platform: 'macos' | 'windows' | 'linux' | 'ios' | 'android'
}
/**
 * The candidate's purpose-separated public keys.
 */
export interface DevicePublicKeys3 {
  /**
   * The Ed25519 authorisation key.
   */
  authorisation: string
  /**
   * The X25519 notification-preview key.
   */
  notification_preview: string
  /**
   * The X25519 stored-envelope key.
   */
  stored_envelope: string
  /**
   * The iroh transport identity.
   */
  transport: string
}
/**
 * A bundle and the authorisation signature that binds its key purposes.
 *
 * The encryption authenticates the initial bundle; this signature binds the key-purpose
 * declarations to the authorisation key, and covers `T`, so it cannot be replayed from another
 * transcript.
 */
export interface SignedHostBundle {
  bundle: HostBundle
  /**
   * The Ed25519 signature over `CBOR(["kr-pair/host-bundle/1", bundle, T])`.
   */
  signature: string
  /**
   * The transcript the signature covers.
   */
  transcript: string
}
/**
 * The bundle.
 */
export interface HostBundle {
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The revision of the host's purpose-separated keys.
   */
  device_key_revision: string
  /**
   * The host's iroh endpoint identity.
   */
  endpoint_id: string
  /**
   * The invitation this bundle answers.
   */
  invitation_id: string
  keys: DevicePublicKeys4
  network_config: NetworkConfig
  proposed_grant: ProposedGrant1
}
/**
 * The host's purpose-separated public keys.
 */
export interface DevicePublicKeys4 {
  /**
   * The Ed25519 authorisation key.
   */
  authorisation: string
  /**
   * The X25519 notification-preview key.
   */
  notification_preview: string
  /**
   * The X25519 stored-envelope key.
   */
  stored_envelope: string
  /**
   * The iroh transport identity.
   */
  transport: string
}
/**
 * The selected discovery and relay configuration, with current hints.
 */
export interface NetworkConfig {
  /**
   * Current direct-address hints. Hints only: the endpoint identity is what authenticates.
   */
  direct_addresses: NetworkHint[]
  /**
   * The selected DNS origin, or null when DNS lookup is not selected.
   */
  dns_origin: NetworkHint | null
  /**
   * The selected Pkarr publisher URL, or null when publication is not selected.
   */
  pkarr_publisher_url: NetworkHint | null
  /**
   * The selected Pkarr resolver URL, or null when Pkarr resolution is not selected.
   */
  pkarr_resolver_url: NetworkHint | null
  /**
   * The selected relay map, as relay URLs.
   */
  relay_urls: NetworkHint[]
}
/**
 * The rights the invitation proposes.
 */
export interface ProposedGrant1 {
  /**
   * The actions it permits.
   */
  actions: ActionRight[]
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
           * A UTC timestamp in milliseconds, as a decimal string in JSON.
           */
          expires_at_ms: string
        }
      }
  history: HistoryScope1
  /**
   * An optional organisation membership requirement.
   */
  organisation: OrganisationRequirement | null
  /**
   * The grant this one will be delegated from, when it is a delegation.
   */
  parent_grant_id: GrantId | null
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
 * A registration and the instance signature that proves the host holds the key.
 *
 * The operator submits this under service-admin authority. The authority says the submission is
 * permitted; the signature says the key being registered is one a relay host actually has, so a
 * mistyped key cannot become the key every later receipt is checked against.
 */
export interface SignedRelayInstanceRegistration {
  registration: RelayInstanceRegistration
  /**
   * The Ed25519 signature over `CBOR(["kr-relay/instance/1", registration])`, by the instance
   * key the registration currently holds.
   */
  signature: string
}
/**
 * The registration.
 */
export interface RelayInstanceRegistration {
  /**
   * The public half of the key this instance signs receipts with.
   */
  instance_key: string
  /**
   * The deployment region this instance serves.
   */
  region: string
  /**
   * The instance identity. Stable across key rotation.
   */
  relay_instance_id: string
  /**
   * One relay URL, discovery origin or direct-address hint: printable ASCII without spaces, 1 to 253 bytes.
   */
  relay_url: string
  /**
   * The revision of this registration. Strictly increasing per instance, so a registration the
   * instance has replaced cannot be replayed to undo the replacement. The same revision is
   * accepted again only for a byte-identical retry.
   */
  revision: string
  /**
   * The successor key and its overlap window, or null when no rotation is announced.
   */
  successor: RelayKeySuccession | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  valid_from_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  valid_until_ms: string
}
/**
 * A successor key and the window in which both keys are accepted.
 *
 * Rotation cannot be instantaneous: receipts signed before the change are still in flight when the
 * new key starts signing. The overlap is that window, stated in advance and ending at a recorded
 * time rather than whenever somebody remembers to retire the old key.
 */
export interface RelayKeySuccession {
  /**
   * The key that takes over.
   */
  instance_key: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  overlap_from_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  predecessor_retires_at_ms: string
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
