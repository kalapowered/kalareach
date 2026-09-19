/* eslint-disable */
/**
 * Generated from schema/kalareach-protocol.schema.json. Do not edit.
 *
 * Rust is canonical: change the types in crates/kr-protocol, run
 * `cargo run -p kr-protocol --bin kr-protocol-gen`, then `pnpm -C packages/protocol generate`.
 */

/**
 * A UTC timestamp in milliseconds, as a decimal string in JSON.
 */
export type TimestampMs = string
/**
 * An opaque diagnostic identifier. It carries no protocol meaning.
 */
export type DiagnosticId = string
/**
 * Why an action was rejected before dispatch.
 */
export type RejectionReason =
  'admission_failed' | 'expired' | 'cancelled' | 'revoked' | 'stale_preconditions'
/**
 * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
 */
export type U64 = string
/**
 * One KalaReach terminal session.
 */
export type SessionId = string
/**
 * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
 */
export type ParamsValue = unknown
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
 * One foreground application within a terminal session.
 */
export type ApplicationInstanceId = string
/**
 * One change an installation makes, with its inverse implied by its kind.
 */
export type ChangeOperation =
  | {
      operation: 'create_directory'
      /**
       * The absolute path.
       */
      path: string
    }
  | {
      /**
       * The digest of the content written. A removal that finds different content stops.
       */
      digest: string
      operation: 'write_file'
      /**
       * The absolute path.
       */
      path: string
      /**
       * The digest of what was there before, when the file already existed.
       */
      replaced_digest: Digest256 | null
    }
  | {
      /**
       * True when the document did not exist and this installation created it.
       */
      created_document: boolean
      /**
       * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
       */
      digest: string
      /**
       * The dotted location of the entry inside it, for example `mcpServers.kalareach`.
       */
      entry: string
      operation: 'add_configuration_entry'
      /**
       * The absolute path of the document.
       */
      path: string
    }
/**
 * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
 */
export type Digest256 = string
/**
 * Changes when the active upstream execution owner or selected thread changes.
 */
export type AgentBindingRevision = string
/**
 * What an attachment asks to be able to do.
 *
 * A request is not a grant. The host intersects these with the actor's rights, and an attachment
 * identifier is never permission on its own.
 */
export type AttachmentCapability = 'observe_terminal' | 'observe_semantic' | 'input' | 'geometry'
/**
 * How a terminal attachment displays the canonical grid.
 */
export type TerminalPresentationMode = 'direct' | 'viewport'
/**
 * Where an attachment's window sits in the session's rows.
 *
 * A window is normally on the live screen, which is what no position at all means. A client
 * looking through its scrollback names where it is looking instead, and the host installs the
 * history pages that cover it. Scrolling is a presentation choice and never touches the input
 * lease: section 8 puts passive scrollback with focus events and terminal replies.
 */
export type ViewportPosition =
  | {
      row: U64
    }
  | {
      above: U64
    }
/**
 * One CLI or application attachment, independently of its device.
 */
export type AttachmentId = string
/**
 * One attention rule and the subject it was raised about.
 */
export type AttentionKey = string
/**
 * One signed revocation request published by a remote owner.
 */
export type RevocationRequestId = string
/**
 * How long a worker's execution context lasts.
 *
 * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
 * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
 * survives logout where the platform's user service manager does.
 */
export type WorkerProfile = 'desktop_bound' | 'headless_user'
/**
 * What makes a capability record stale.
 */
export type CapabilityInvalidation =
  | 'binary_identity'
  | 'binding_identity'
  | 'package_schema'
  | 'os_permission'
  | 'desktop_generation'
  | 'worker_profile'
/**
 * A host-derived desktop session identity binding OS user, boot identity and login-session generation.
 */
export type DesktopSessionId = string
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
 * One frame on an authorised control stream.
 *
 * The union is closed. A receiver that cannot name the variant rejects the frame rather than
 * guessing, which is what keeps an unknown method a correlated error instead of a parse failure.
 *
 * Both transports carry these frames: section 23 says local Unix sockets and Windows named pipes
 * carry the same typed frames with local peer authentication. What differs is how the connection
 * is authenticated before the first frame, not what travels afterwards. One union rather than two
 * is what makes that true rather than merely stated: a request, a mutation, a response, a receipt
 * and a notification are the same types on a Unix socket as on a QUIC stream, and a host that
 * answered them differently would have two wire contracts to keep in step.
 *
 * Some variants only ever travel between host processes on a local endpoint: the local opening
 * frames, the worker startup handshake, the generation and revision exchange, and a forwarded
 * mutation. They are still part of this union, because a closed union is what makes a frame that
 * does not belong on the ingress it arrived on a *refusal* rather than a parse failure. Each
 * endpoint refuses the variants its role does not serve, which is an admission rule the host
 * applies rather than a shape the wire hides.
 */
export type ControlFrame =
  | {
      hello: LocalHello
    }
  | {
      hello_ack: LocalHelloAck
    }
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
  | {
      rendezvous: WorkerRendezvous
    }
  | {
      launch_spec: WorkerLaunchSpec
    }
  | {
      worker_ready: WorkerReady
    }
  | {
      worker_failed: ProtocolError
    }
  | {
      verify_challenge: WorkerVerifyChallenge
    }
  | {
      verify_proof: WorkerVerifyProof
    }
  | {
      generation_challenge: GenerationChallenge
    }
  | {
      controller_role: ControllerConnectionRole
    }
  | {
      generation_token: ControllerGenerationToken
    }
  | {
      generation_accepted: GenerationAccepted
    }
  | {
      authority_revision: AuthorityRevisionNotice
    }
  | {
      authority_revision_ack: AuthorityRevisionAck
    }
  | {
      forwarded: ForwardedMutation
    }
  | {
      forwarded_read: ForwardedRequest
    }
  | {
      retained_response: Response
    }
  | {
      acceptance_delivered: ActionId
    }
/**
 * The session epoch, fixed at 1 in protocol version 1.
 */
export type SessionEpoch = string
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
 * A palette a session can be started with, chosen before the shell has produced anything.
 *
 * Section 8 fixes the palette at creation and records where it came from. A preset is what a
 * no-probe or invisible creation selects, because neither has a terminal whose colours could be
 * asked for; the probe form carries the foreground and background a client learned from its own
 * bounded probe of the terminal the person is sitting at.
 */
export type PaletteRequest =
  | {
      preset: PalettePreset
    }
  | {
      probe: ProbedPalette
    }
/**
 * One of the two palettes a creation can select without asking a terminal anything.
 */
export type PalettePreset = 'light' | 'dark'
/**
 * What one of the control daemon's connections to a worker is for.
 *
 * A daemon needs more than one connection to a worker, because a worker's attachments,
 * subscriptions and input lane belong to the connection that created them: a device's attachment
 * cannot share a connection with the daemon's own housekeeping. Only one of those connections
 * carries the environment's authority, and a connection says which it is *before* it presents a
 * generation token, so the worker never has to guess and a proxy never displaces the authority.
 *
 * It confers nothing on its own. Every one of these connections still proves which generation it
 * speaks for, and only the holder of the environment's signing key can produce that proof.
 */
export type ControllerConnectionRole = 'authority' | 'proxy'
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
  | 'voice.use'
/**
 * One submitted intent and its receipt, generated as a UUIDv4.
 */
export type ActionId = string
/**
 * One upload or download transfer.
 */
export type TransferId = string
/**
 * Where a download's bytes come from.
 */
export type DownloadSource =
  | {
      attachment: {
        /**
         * One upload or download transfer.
         */
        transfer_id: string
      }
    }
  | {
      scope: {
        /**
         * The path beneath it. Absolute paths, traversal segments, separators the host does not
         * accept and reserved device names are refused.
         */
        relative_path: string
        /**
         * One host-issued authority object.
         */
        scope_id: string
      }
    }
/**
 * One installed OS, distribution or container environment and OS user.
 */
export type EnvironmentId = string
/**
 * The group repeated state notifications coalesce in. The sender derives it; the service only compares it.
 */
export type MailboxThreadId = string
/**
 * Why an assertion is being held.
 *
 * Both are verified conditions rather than a guess about activity: work the host has admitted,
 * and requests it has accepted and not yet answered.
 */
export type InhibitionReason =
  'foreground_work' | 'pending_requests' | 'foreground_work_and_pending_requests'
/**
 * One transport connection, allocated by the host during hello.
 */
export type ConnectionId = string
/**
 * What the foreground of a session is doing.
 *
 * Application state is reported separately from the lifecycle state and from transport
 * reachability; a busy agent and an unreachable client are different facts.
 */
export type ApplicationState = 'shell_ready' | 'agent_busy' | 'awaiting_input' | 'awaiting_approval'
/**
 * The event streams a session publishes.
 */
export type EventStream = 'session_state' | 'output' | 'attachments' | 'input_lease' | 'receipts'
/**
 * Why a range of output is no longer retained.
 */
export type HistoryGapCause =
  'retention' | 'host_capacity' | 'session_capacity' | 'spool_unavailable' | 'archive_incomplete'
/**
 * An upstream approval request identifier. Opaque to KalaReach.
 */
export type ApprovalRequestId = string
/**
 * One agent-to-user question.
 */
export type QuestionId = string
/**
 * One consequence of a grant that the issuer is shown before the grant exists.
 *
 * Section 10 forbids a label that implies a restrictive sandbox the upstream does not enforce, so
 * the host decides which notices a set of actions carries and states each one in fixed words.
 * A surface may translate [`Self::sentence`]; it may not soften it, and it may not decide for
 * itself that an action is harmless.
 */
export type AuthorityNotice =
  'account_access' | 'agent_permissions' | 'environment_writes' | 'delegation'
/**
 * A duration in milliseconds, as a decimal string in JSON.
 */
export type DurationMs = string
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
 * The group a notification replaces others in on the device. 128 bits a host derives from its own secret.
 */
export type CollapseId = string
/**
 * One owner-confirmation challenge: single use and bound to one action digest.
 */
export type ConfirmationId = string
/**
 * The controller's persistent generation, advanced on every controller start.
 */
export type ControllerGeneration = string
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
 * One notification, named by the host that produced it. 128 random bits, opaque to the gateway and the provider.
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
 * An opaque provider delegation identifier. Correlation data, never authority.
 */
export type VoiceDelegationId = string
/**
 * One voice session, independent of the terminal sessions it may reach.
 */
export type VoiceSessionId = string
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
 * The least client version a policy accepts: alphanumeric with dots, hyphens and plus signs.
 */
export type ClientVersion = string
/**
 * The parameters of `pair.redeem`.
 */
export type PairRedeemParams =
  | {
      challenge: {
        /**
         * The invitation the candidate scanned.
         */
        invitation_id: string
      }
    }
  | {
      direct: DirectRedeemProof
    }
/**
 * The result of `pair.redeem`.
 */
export type PairRedeemResult =
  | {
      challenge: DirectChallenge
    }
  | {
      locked: {
        /**
         * The attempt the host locked to this candidate.
         */
        attempt_id: string
        /**
         * The eight hexadecimal characters both devices display.
         */
        verification_value: string
      }
    }
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
 * How an isolated workspace is separated from the user's own tree.
 */
export type IsolationMechanism = 'git_worktree' | 'independent_clone'
/**
 * Every body a signed push method carries.
 *
 * One type, so there is one rule for what a service-request signature covers: the signature's
 * `body_digest` is [`PushRequest::digest`], and the method it names is [`PushRequest::method`]. A
 * body built for one method therefore cannot be presented under another, because the signature
 * covers both the body and the method and a verifier checks that they agree.
 *
 * Delivery is not here. It carries the bearer credential the host was issued rather than a
 * signature, so it has no body digest to cover.
 */
export type PushRequest =
  | {
      installation_register: {
        /**
         * The proposal or the answer.
         */
        request:
          | {
              propose: {
                proposal: PushRegistrationProposal
              }
            }
          | {
              answer: {
                answer: PushRegistrationAnswer1
              }
            }
      }
    }
  | {
      sender_issue: {
        request: PushSenderIssueRequest
      }
    }
  | {
      sender_renew: {
        /**
         * The nonce request or the proof.
         */
        request:
          | {
              begin: {
                request: PushSenderNonceRequest
              }
            }
          | {
              complete: {
                renewal: PushSenderRenewal
              }
            }
      }
    }
  | {
      sender_revoke: {
        /**
         * The nonce request or the statement.
         */
        request:
          | {
              begin: {
                request: PushSenderNonceRequest1
              }
            }
          | {
              complete: {
                revocation: PushSenderRevocation
              }
            }
      }
    }
/**
 * What a person answered.
 *
 * The four arms stay four arms. Section 11 forbids coercing [`Self::Other`] into a listed choice
 * or into a yes, so an answer that arrived as free text is read as free text by whatever consumes
 * it.
 */
export type QuestionAnswer =
  | {
      kind: 'input'
      /**
       * What the person typed.
       */
      text: string
    }
  | {
      /**
       * The choice the person selected.
       */
      choice_id: string
      kind: 'choice'
    }
  | {
      /**
       * True for yes.
       */
      decided: boolean
      kind: 'decision'
    }
  | {
      kind: 'other'
      /**
       * What the person typed instead of choosing.
       */
      text: string
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
 * What is offered as grounds for returning a host's wall clock to trusted.
 */
export type RetrustEvidence =
  | {
      /**
       * The authority as the host's configuration names it.
       */
      authority: string
      kind: 'host_time_authority'
      reading: TimeAdapterReading
    }
  | {
      /**
       * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
       */
      action_digest: string
      kind: 'owner_retrust'
    }
  | {
      /**
       * One paired device.
       */
      device_id: string
      kind: 'paired_peer'
    }
/**
 * What a review acknowledgement is attached to.
 *
 * A subject names what is being reviewed and nothing about which version of it. The version
 * travels beside the subject, in [`ReviewState::current_version`] and
 * [`ReviewAcknowledgeParams::version`], because a subject keeps one identity while its versions
 * move: that is what lets a new change reopen review work an older version had closed.
 *
 * The two are told apart by which variant is present rather than by a tag beside them. An
 * internally tagged union buffers what it decodes before it knows the variant, and buffering is
 * where a format's own representation of an identifier is lost: the canonical wire form encodes
 * one as sixteen bytes, and a buffered decode would ask for a string and refuse it.
 */
export type ReviewSubject =
  | {
      completed_turn: {
        /**
         * One KalaReach terminal session.
         */
        session_id: string
        /**
         * The turn.
         */
        turn_id: string
      }
    }
  | {
      change_set: {
        /**
         * One immutable captured change set.
         */
        change_set_id: string
        /**
         * One KalaReach terminal session.
         */
        session_id: string
      }
    }
/**
 * One published editor fence. An identity from an unacknowledged exchange names no fence.
 */
export type FenceId = string
/**
 * Why an invocation ran exactly as it was typed.
 *
 * Section 12: an absolute-path invocation and a user-disabled integration keep their actual
 * bypassed execution, with only verified observation and the terminal's own capabilities.
 */
export type CommandBypassReason =
  | 'not_integrated'
  | 'disabled'
  | 'absolute_path'
  | 'unmanaged_shell'
  | 'not_interactive'
  | 'backend_unavailable'
  | 'session_closing'
/**
 * What the worker tells the bridge about the fence.
 *
 * The bridge cannot conclude that its acknowledgement published a fence: the hold may have expired
 * while the answer was in flight, and a fence the worker never published must not be quoted in a
 * detach. Nor can it conclude that a fence it was given is still live. So all three are stated
 * rather than inferred, and a bridge holds a fence only between a [`Self::Published`] and the
 * [`Self::Invalidated`] that ends it.
 */
export type FencePublication =
  | {
      published: EditorFence
    }
  | {
      withheld: {
        /**
         * Why not.
         */
        reason:
          | 'exchange_timed_out'
          | 'editor_entered'
          | 'detach_accepted'
          | 'attachment_removed'
          | 'integration_lost'
          | 'queues_not_drained'
          | 'refused'
          | 'reader_moved'
          | 'lease_changed'
          | 'editor_left'
          | 'session_closing'
        /**
         * The state the editor is in now.
         */
        state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
      }
    }
  | {
      invalidated: {
        /**
         * The fence that has gone.
         */
        fence_id: string
        /**
         * Why.
         */
        reason:
          | 'exchange_timed_out'
          | 'editor_entered'
          | 'detach_accepted'
          | 'attachment_removed'
          | 'integration_lost'
          | 'queues_not_drained'
          | 'refused'
          | 'reader_moved'
          | 'lease_changed'
          | 'editor_left'
          | 'session_closing'
        /**
         * The state the editor is in now.
         */
        state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
      }
    }
/**
 * The result of `root.editor.fence`.
 */
export type RootEditorFenceResult =
  | {
      acknowledged: FenceAcknowledgement
    }
  | {
      refused: FenceRefusal
    }
/**
 * One relay URL, discovery origin or direct-address hint: printable ASCII without spaces, 1 to 253 bytes.
 */
export type NetworkHint = string
/**
 * One revision of one synchronised object. A fresh 128-bit value per accepted write.
 */
export type SyncRevisionId = string
/**
 * A class of content the default context excludes.
 */
export type VoiceContextClass =
  'file_contents' | 'environment_variables' | 'terminal_scrollback' | 'attachment_bytes'
/**
 * One thing a voice session may ask the host to do.
 *
 * Section 15 ¶13 divides these three ways, and the divisions are the methods on this type rather
 * than rules restated at each call site:
 *
 * * the default grant permits session navigation, status queries, briefing and prompt
 *   composition, and nothing else ([`Self::in_default_scope`]);
 * * submitting a prompt requires a clear spoken confirmation naming the destination session
 *   ([`Self::needs_spoken_destination`]), and an approval decision requires the verified
 *   request's details and an explicit answer ([`Self::needs_verified_request`]);
 * * session closure, grant changes, arbitrary shell input, diff application and external
 *   delivery require a confirmation on an unlocked screen ([`Self::needs_unlocked_screen`]).
 *
 * [`Self::required_right`] is the other half: every voice action names the ordinary right the
 * host already checks for the same effect, so a voice grant can never reach an effect the device
 * could not reach by typing.
 */
export type VoiceAction =
  | 'navigate'
  | 'status'
  | 'brief'
  | 'compose_prompt'
  | 'submit_prompt'
  | 'answer_approval'
  | 'cancel_turn'
  | 'close_session'
  | 'change_grant'
  | 'shell_input'
  | 'apply_diff'
  | 'deliver_externally'

/**
 * Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.
 */
export interface KalaReachProtocol {
  action_cancel_params?: ActionCancelParams
  action_cancel_result?: ActionCancelResult
  action_observation?: ActionObservation
  action_read_params?: ActionReadParams
  action_read_result?: ActionReadResult
  action_window?: ActionWindow
  actor_envelope?: ActorEnvelope
  agent_draft_add_attachment_params?: AgentDraftAddAttachmentParams
  agent_draft_add_attachment_result?: AgentDraftAddAttachmentResult
  agent_tools_install_result?: AgentToolsInstallResult
  agent_tools_params?: AgentToolsParams
  agent_tools_remove_result?: AgentToolsRemoveResult
  agent_tools_status_result?: AgentToolsStatusResult
  alert?: Alert
  alert_create_params?: AlertCreateParams
  alert_create_result?: AlertCreateResult
  answer_record?: AnswerRecord
  archive_descriptor?: ArchiveDescriptor
  attachment_configure_params?: AttachmentConfigureParams
  attachment_contribution?: AttachmentContribution1
  attachment_handle?: AttachmentHandle1
  attachment_read_grant?: AttachmentReadGrant
  attachment_summary?: AttachmentSummary
  attachment_viewport_params?: AttachmentViewportParams
  attachment_viewport_result?: AttachmentViewportResult
  attention_acknowledge_params?: AttentionAcknowledgeParams
  attention_acknowledge_result?: AttentionAcknowledgeResult
  attention_gap?: AttentionGap
  attention_item?: AttentionItem
  attention_quiet_hours_params?: AttentionQuietHoursParams
  attention_quiet_hours_result?: AttentionQuietHoursResult
  attention_read_params?: AttentionReadParams
  attention_read_result?: AttentionReadResult
  authority_feed_status?: AuthorityFeedStatus
  authority_revision_ack?: AuthorityRevisionAck
  authority_revision_notice?: AuthorityRevisionNotice
  authority_revision_record?: AuthorityRevisionRecord
  backup_generation_publication?: BackupGenerationPublication
  backup_writer_record?: BackupWriterRecord
  capability_record?: CapabilityRecord
  change_manifest?: ChangeManifest1
  change_operation?: ChangeOperation
  change_summary?: ChangeSummary
  client_offer?: ClientOffer
  closure_record?: ClosureRecord
  connect_reply?: ConnectReply
  control_frame?: ControlFrame
  controller_connection_role?: ControllerConnectionRole
  controller_generation_token?: ControllerGenerationToken
  desktop_capability_report?: DesktopCapabilityReport
  desktop_context?: DesktopContext1
  device_list_params?: DeviceListParams
  device_list_result?: DeviceListResult
  device_preview_key_update_params?: DevicePreviewKeyUpdateParams
  device_preview_key_update_result?: DevicePreviewKeyUpdateResult
  device_revoke_params?: DeviceRevokeParams
  device_summary?: DeviceSummary
  direct_challenge?: DirectChallenge
  direct_redeem_proof?: DirectRedeemProof
  download_begin_params?: DownloadBeginParams
  download_begin_result?: DownloadBeginResult
  download_chunk_params?: DownloadChunkParams
  download_chunk_result?: DownloadChunkResult
  download_placement?: DownloadPlacement
  draft_create_params?: DraftCreateParams
  draft_create_result?: DraftCreateResult
  draft_record?: DraftRecord2
  draft_update_params?: DraftUpdateParams
  draft_update_result?: DraftUpdateResult
  envelope_plaintext?: EnvelopePlaintext
  environment_capabilities_params?: EnvironmentCapabilitiesParams
  environment_capabilities_result?: EnvironmentCapabilitiesResult
  environment_list_result?: EnvironmentListResult
  events_snapshot_params?: EventsSnapshotParams
  events_snapshot_result?: EventsSnapshotResult
  events_subscribe_params?: EventsSubscribeParams
  events_subscribe_result?: EventsSubscribeResult
  expiration_tombstone?: ExpirationTombstone
  fence_evidence?: FenceEvidence
  fenced_action?: FencedAction
  forwarded_mutation?: ForwardedMutation
  forwarded_request?: ForwardedRequest
  generation_accepted?: GenerationAccepted
  generation_challenge?: GenerationChallenge
  generation_checkpoint?: GenerationCheckpoint
  geometry_result?: GeometryResult
  geometry_state?: GeometryState3
  grant?: Grant
  grant_create_params?: GrantCreateParams
  grant_create_result?: GrantCreateResult
  grant_list_params?: GrantListParams
  grant_list_result?: GrantListResult
  grant_revoke_params?: GrantRevokeParams
  grant_summary?: GrantSummary
  hello_reply?: HelloReply
  history_page_params?: HistoryPageParams
  history_page_result?: HistoryPageResult
  host_doctor_result?: HostDoctorResult
  host_info_result?: HostInfoResult
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
    voice_delegation_id?: VoiceDelegationId
    voice_session_id?: VoiceSessionId
    workflow_id?: WorkflowId
    workflow_run_id?: WorkflowRunId
    workspace_id?: WorkspaceId
  }
  inclusion_preview?: InclusionPreview
  input_acquire_params?: InputAcquireParams
  input_acquire_result?: InputAcquireResult
  input_interrupt_params?: InputInterruptParams
  input_lease_result?: InputLeaseResult
  input_lease_state?: InputLeaseState3
  input_release_params?: InputReleaseParams
  input_write_params?: InputWriteParams
  input_write_result?: InputWriteResult
  installed_file?: InstalledFile
  invitation_preview?: InvitationPreview1
  live_screen_preview?: LiveScreenPreview
  local_hello?: LocalHello
  local_hello_ack?: LocalHelloAck
  log_view_state?: LogViewState
  membership_lease?: MembershipLease
  method_entry?: MethodEntry
  mutation_request?: MutationRequest
  named_approval_preview?: NamedApprovalPreview
  named_question_preview?: NamedQuestionPreview
  notification?: Notification
  offline_validity_policy?: OfflineValidityPolicy
  operation_record?: OperationRecord
  organisation_policy?: OrganisationPolicy
  output_event?: OutputEvent
  owner_confirmation_proof?: OwnerConfirmationProof
  owner_confirmation_request?: OwnerConfirmationRequest1
  pair_finish_request?: PairFinishRequest
  pair_redeem_params?: PairRedeemParams
  pair_redeem_result?: PairRedeemResult
  pair_status?: PairStatus
  pair_status_params?: PairStatusParams
  pair_status_result?: PairStatusResult
  policy_authority?: PolicyAuthority
  preview_entry?: PreviewEntry
  project_adopt_params?: ProjectAdoptParams
  project_adopt_result?: ProjectAdoptResult
  project_clone_params?: ProjectCloneParams
  project_clone_result?: ProjectCloneResult
  project_init_params?: ProjectInitParams
  project_init_result?: ProjectInitResult
  project_list_params?: ProjectListParams
  project_list_result?: ProjectListResult
  project_operation_cancel_params?: ProjectOperationCancelParams
  project_operation_cancel_result?: ProjectOperationCancelResult
  project_read_params?: ProjectReadParams
  project_read_result?: ProjectReadResult
  project_summary?: ProjectSummary3
  projection_delta?: ProjectionDelta
  projection_reset?: ProjectionReset
  projection_row_page?: ProjectionRowPage
  projection_snapshot?: ProjectionSnapshot
  proposed_grant?: ProposedGrant
  protocol_error?: ProtocolError
  push_delivery_ack?: PushDeliveryAck
  push_delivery_credential?: PushDeliveryCredential
  push_delivery_request?: PushDeliveryRequest
  push_installation_binding?: PushInstallationBinding
  push_registration_answer?: PushRegistrationAnswer
  push_registration_challenge?: PushRegistrationChallenge
  push_request?: PushRequest
  push_sender_record?: PushSenderRecord
  push_sender_renewal?: PushSenderRenewal1
  push_sender_revocation?: PushSenderRevocation1
  question?: Question
  question_answer?: QuestionAnswer
  question_answer_params?: QuestionAnswerParams
  question_cancel_own_params?: QuestionCancelOwnParams
  question_cancel_params?: QuestionCancelParams
  question_choice?: QuestionChoice
  question_create_params?: QuestionCreateParams
  question_create_result?: QuestionCreateResult
  question_event?: QuestionEvent
  question_own_result?: QuestionOwnResult
  question_read_own_params?: QuestionReadOwnParams
  question_read_params?: QuestionReadParams
  question_read_result?: QuestionReadResult
  question_resolve_result?: QuestionResolveResult
  question_source?: QuestionSource2
  quiet_hours?: QuietHours
  receipt?: Receipt3
  receipt_response?: ReceiptResponse
  recovery_bundle?: RecoveryBundle
  recovery_kit?: RecoveryKit
  relay_consumption_ack?: RelayConsumptionAck
  relay_consumption_report?: RelayConsumptionReport
  relay_lease_ack?: RelayLeaseAck
  relay_lease_request?: RelayLeaseRequest
  request?: Request
  response?: Response
  resync_required?: ResyncRequired
  retained_log_view?: RetainedLogView
  retrust_evidence?: RetrustEvidence
  review_acknowledge_params?: ReviewAcknowledgeParams
  review_acknowledge_result?: ReviewAcknowledgeResult
  review_read_params?: ReviewReadParams
  review_read_result?: ReviewReadResult
  review_state?: ReviewState1
  review_subject?: ReviewSubject
  revocation_acknowledgement?: RevocationAcknowledgement
  revocation_barrier?: RevocationBarrier
  revocation_request?: RevocationRequest
  revocation_result?: RevocationResult
  role_selection?: RoleSelection1
  root_command_accepted_params?: RootCommandAcceptedParams
  root_command_accepted_result?: RootCommandAcceptedResult
  root_command_block_params?: RootCommandBlockParams
  root_command_block_result?: RootCommandBlockResult
  root_command_resolve_params?: RootCommandResolveParams
  root_command_resolve_result?: RootCommandResolveResult
  root_editor_busy_event?: EditorBusyEvent
  root_editor_enter_params?: RootEditorEnterParams
  root_editor_enter_result?: RootEditorEnterResult
  root_editor_fence?: EditorFence
  root_editor_fence_params?: RootEditorFenceParams
  root_editor_fence_publication?: FencePublication
  root_editor_fence_result?: RootEditorFenceResult
  root_editor_leave_params?: RootEditorLeaveParams
  root_editor_leave_result?: RootEditorLeaveResult
  root_eof_detach_params?: RootEofDetachParams
  root_eof_detach_result?: RootEofDetachResult
  sealed_envelope?: SealedEnvelope
  semantic_change?: SemanticChange
  semantic_continuation?: SemanticContinuation
  service_request_signature?: ServiceRequestSignature
  session_attach_params?: SessionAttachParams
  session_attach_result?: SessionAttachResult
  session_close_params?: SessionCloseParams
  session_close_result?: SessionCloseResult
  session_create_params?: SessionCreateParams1
  session_create_result?: SessionCreateResult
  session_detach_params?: SessionDetachParams
  session_detach_result?: SessionDetachResult
  session_list_params?: SessionListParams
  session_list_result?: SessionListResult
  session_read_params?: SessionReadParams
  session_read_result?: SessionReadResult
  session_ref?: SessionRef
  session_summary?: SessionSummary2
  shell_launch_params?: ShellLaunchParams
  shell_launch_result?: ShellLaunchResult
  signed_archive_manifest?: SignedArchiveManifest
  signed_client_bundle?: SignedClientBundle
  signed_host_bundle?: SignedHostBundle
  signed_relay_consumption_receipt?: SignedRelayConsumptionReceipt
  signed_relay_instance_registration?: SignedRelayInstanceRegistration
  sleep_inhibition_state?: SleepInhibitionState2
  stream_header?: StreamHeader
  sync_conflict_copy?: SyncConflictCopy
  sync_object_record?: SyncObjectRecord
  terminal_geometry_transfer_params?: TerminalGeometryTransferParams
  terminal_resize_params?: TerminalResizeParams
  time_adapter_reading?: TimeAdapterReading1
  time_checkpoint?: TimeCheckpoint
  upload_begin_params?: UploadBeginParams
  upload_begin_result?: UploadBeginResult
  upload_cancel_params?: UploadCancelParams
  upload_cancel_result?: UploadCancelResult
  upload_chunk_params?: UploadChunkParams
  upload_chunk_result?: UploadChunkResult
  upload_finish_params?: UploadFinishParams
  upload_finish_result?: UploadFinishResult
  upload_status_params?: UploadStatusParams
  upload_status_result?: UploadStatusResult
  visit_acknowledge_params?: VisitAcknowledgeParams
  visit_acknowledge_result?: VisitAcknowledgeResult
  visit_changed_params?: VisitChangedParams
  visit_changed_result?: VisitChangedResult
  voice_action_plan?: VoiceActionPlan
  voice_confirmation_proof?: VoiceConfirmationProof
  voice_confirmation_request?: VoiceConfirmationRequest1
  voice_context_params?: VoiceContextParams
  voice_context_result?: VoiceContextResult
  voice_context_selection?: VoiceContextSelection1
  voice_delegate_params?: VoiceDelegateParams
  voice_delegate_result?: VoiceDelegateResult
  voice_grant_params?: VoiceGrantParams
  voice_grant_result?: VoiceGrantResult
  voice_grant_statement?: VoiceGrantStatement1
  voice_instructions?: VoiceInstructions
  voice_session_descriptor?: VoiceSessionDescriptor
  voice_start_params?: VoiceStartParams
  voice_start_result?: VoiceStartResult
  voice_stop_params?: VoiceStopParams
  voice_stop_result?: VoiceStopResult
  worker_descriptor?: WorkerDescriptor
  worker_launch_spec?: WorkerLaunchSpec
  worker_ready?: WorkerReady
  worker_rendezvous?: WorkerRendezvous
  worker_verify_challenge?: WorkerVerifyChallenge
  worker_verify_proof?: WorkerVerifyProof
  workspace_create_params?: WorkspaceCreateParams
  workspace_create_result?: WorkspaceCreateResult
  workspace_list_params?: WorkspaceListParams
  workspace_list_result?: WorkspaceListResult
  workspace_read_params?: WorkspaceReadParams
  workspace_read_result?: WorkspaceReadResult
  workspace_remove_params?: WorkspaceRemoveParams
  workspace_remove_result?: WorkspaceRemoveResult
  workspace_summary?: WorkspaceSummary
}
/**
 * What `action.cancel` names.
 */
export interface ActionCancelParams {
  /**
   * The action to cancel.
   */
  action_id: string
}
/**
 * The receipt an undispatched action was cancelled into.
 */
export interface ActionCancelResult {
  receipt: Receipt
}
/**
 * The receipt after the cancellation.
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
 * One piece of additive evidence about an action.
 *
 * The word in a user interface is "observed", and it means evidence was observed. It does not
 * mean the mutation is confirmed, which is why every observation carries the provenance a reader
 * needs in order to know which of the two it is looking at.
 */
export interface ActionObservation {
  /**
   * The action the evidence is about.
   */
  action_id: string
  /**
   * What the evidence claims happened.
   */
  claimed_result: 'applied' | 'refused' | 'indeterminate'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  observed_at_ms: string
  /**
   * Where the evidence came from.
   */
  provenance: 'authoritative_interface' | 'upstream_correlation' | 'inferred_screen' | 'user_report'
  /**
   * The position in the source stream the evidence was read from, when there is one.
   */
  source_cursor: U64 | null
  /**
   * The subject the evidence is about, named the way its own interface names it.
   */
  subject: string
  /**
   * The subject's version at the moment of the observation, when the subject has one.
   */
  subject_revision: U64 | null
}
/**
 * What `action.read` names.
 */
export interface ActionReadParams {
  /**
   * The action to read.
   */
  action_id: string
  /**
   * The session whose receipts hold it, when it belongs to one.
   *
   * A worker serves the receipts of the one session it owns, so a request that reaches a
   * worker needs no session. The environment archive serves every closed session's, so a
   * request that reaches the daemon says which one. A receipt for a host effect resolves
   * against the host scope instead and names none.
   *
   * It is absent from the wire when it is absent, so a request built before the archive
   * existed is byte for byte what it was.
   */
  session_id?: SessionId | null
}
/**
 * A retained receipt and the result it produced.
 *
 * Owning an identifier is not authority: the host checks present view authority over the subject
 * the receipt names before it returns either half, which is why a retained result is carried here
 * rather than handed back from the action identifier alone.
 */
export interface ActionReadResult {
  receipt: Receipt1
  /**
   * The result the action produced, when it produced one and it is still retained.
   */
  result: ParamsValue | null
}
/**
 * The receipt as it currently stands.
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
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
 * Parameters of `agent.draft.add_attachment`.
 *
 * This binds a completed handle to a draft and records what the adapter reported. It never
 * submits: `agent.prompt.submit` is a separate action, and a failed insertion keeps both the
 * draft and the upload.
 */
export interface AgentDraftAddAttachmentParams {
  contribution: AttachmentContribution
  /**
   * The draft.
   */
  draft_id: string
  /**
   * The revision the caller expects.
   */
  expected_revision: string
  /**
   * The completed attachment.
   */
  transfer_id: string
}
/**
 * The contribution the integration declared for this operation.
 */
export interface AttachmentContribution {
  /**
   * The media types the installed agent accepts, exactly as declared.
   */
  accepted_media_types: string[]
  /**
   * The external destination bytes reach, when the operation has one. Null means the bytes stay
   * in this environment.
   */
  external_destination: string | null
  /**
   * How the handle reaches the agent.
   */
  insertion_method: 'typed_submission' | 'verified_composer_insertion' | 'manual_terminal_workflow'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_byte_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_count: string
  /**
   * True when the selected model advertises a media capability for these types.
   *
   * An adapter verifies this before offering an image; a false value means the file transfers
   * but is not presented as a model image.
   */
  model_media_capability: boolean
  /**
   * The operation this declaration covers.
   */
  operation_id: string
}
/**
 * The result of `agent.draft.add_attachment`.
 */
export interface AgentDraftAddAttachmentResult {
  attachment: DraftAttachment
  draft: DraftRecord
}
/**
 * The binding this call recorded.
 */
export interface DraftAttachment {
  /**
   * Where the bytes leave this environment for, as the operation declared it.
   *
   * Null means the bytes stay here. A value is a disclosure: it is recorded with the binding so
   * a client can show the destination before the prompt is submitted, and so the draft record
   * still names it afterwards. The host does not resolve it, reach it or check it against
   * anything; what it does is refuse to lose it.
   */
  external_destination: string | null
  /**
   * Why the insertion failed, when it did.
   */
  failure_detail: string | null
  handle: AttachmentHandle
  /**
   * How it was offered to the agent.
   */
  insertion_method: 'typed_submission' | 'verified_composer_insertion' | 'manual_terminal_workflow'
  /**
   * The read grant issued for this binding, when its insertion method needed one.
   */
  read_grant: AttachmentReadGrant | null
  /**
   * What became of the offer.
   */
  state: 'recorded' | 'accepted_by_agent' | 'failed'
  /**
   * The upstream part or native draft binding the adapter reported. Present only for
   * [`InsertionState::AcceptedByAgent`], because nothing else establishes acceptance.
   */
  upstream_evidence: string | null
}
/**
 * The completed attachment.
 */
export interface AttachmentHandle {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * The verified whole-file SHA-256 digest.
   */
  content_digest: string
  /**
   * The media type the client declared. Declared, not sniffed: it says what the client believes
   * it sent.
   */
  declared_media_type: string
  /**
   * The environment that owns the file. A handle never crosses environments.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The original filename, kept as metadata only.
   */
  original_file_name: string
  /**
   * True only when the bytes decoded as one of [`PreviewFormat`]'s formats.
   *
   * Unsupported media transfers as a file and is never presented as a model image, so an adapter
   * reads this rather than guessing from the declared media type or the filename.
   */
  presented_as_image: boolean
  /**
   * The bounded preview, when one could be produced. A failed preview leaves this null and the
   * file itself is unaffected.
   */
  preview: AttachmentPreview | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  published_at_ms: string
  /**
   * The session the upload was bound to, when it had one.
   */
  session_id: SessionId | null
  /**
   * True once a draft binding holding this attachment was submitted.
   */
  submitted: boolean
  /**
   * The transfer that produced it, which is also this attachment's durable identity.
   */
  transfer_id: string
}
/**
 * A bounded thumbnail of a completed attachment.
 */
export interface AttachmentPreview {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  height: string
  /**
   * The format the source was decoded from.
   */
  source_format: 'png' | 'jpeg' | 'webp' | 'gif_first_frame'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  source_height: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  source_width: string
  /**
   * The encoded thumbnail, always PNG, always within [`MAX_PREVIEW_THUMBNAIL_BYTES`].
   */
  thumbnail: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  width: string
}
/**
 * A narrow, expiring read grant over exactly one completed attachment.
 *
 * This is how an adapter reaches a staging file when its insertion method needs a readable path.
 * It covers one file, read only, for one purpose, and it weakens nothing else: the agent's sandbox
 * is unchanged, and no file is placed inside a repository.
 */
export interface AttachmentReadGrant {
  /**
   * The environment the grant is valid in, and only that one.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One host-issued authority object.
   */
  grant_id: string
  /**
   * The environment-local path the agent may read, valid only while this grant is.
   *
   * It is inside the environment's staging area and outside every repository, which is what
   * keeps an upload from becoming a file in the user's working tree.
   */
  host_path: string
  /**
   * The insertion method it was issued for.
   */
  insertion_method: 'typed_submission' | 'verified_composer_insertion' | 'manual_terminal_workflow'
  /**
   * The attachment it covers.
   */
  transfer_id: string
}
/**
 * The draft after the binding.
 */
export interface DraftRecord {
  /**
   * The foreground application it targets.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The attachments bound to it, in binding order.
   */
  attachments: DraftAttachment1[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The device that owns it, when one does.
   */
  device_id: DeviceId | null
  /**
   * The draft's identity.
   */
  draft_id: string
  /**
   * The environment that owns it.
   */
  environment_id: string
  /**
   * Its current revision. Every update names the revision it expects.
   */
  revision: string
  /**
   * The session it targets.
   */
  session_id: SessionId | null
  /**
   * Its state.
   */
  state: 'open' | 'conflicted' | 'orphaned'
  /**
   * The draft text. This is not the native terminal edit buffer.
   */
  text: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * One attachment bound to a draft, and what became of it.
 */
export interface DraftAttachment1 {
  /**
   * Where the bytes leave this environment for, as the operation declared it.
   *
   * Null means the bytes stay here. A value is a disclosure: it is recorded with the binding so
   * a client can show the destination before the prompt is submitted, and so the draft record
   * still names it afterwards. The host does not resolve it, reach it or check it against
   * anything; what it does is refuse to lose it.
   */
  external_destination: string | null
  /**
   * Why the insertion failed, when it did.
   */
  failure_detail: string | null
  handle: AttachmentHandle
  /**
   * How it was offered to the agent.
   */
  insertion_method: 'typed_submission' | 'verified_composer_insertion' | 'manual_terminal_workflow'
  /**
   * The read grant issued for this binding, when its insertion method needed one.
   */
  read_grant: AttachmentReadGrant | null
  /**
   * What became of the offer.
   */
  state: 'recorded' | 'accepted_by_agent' | 'failed'
  /**
   * The upstream part or native draft binding the adapter reported. Present only for
   * [`InsertionState::AcceptedByAgent`], because nothing else establishes acceptance.
   */
  upstream_evidence: string | null
}
/**
 * The result of `agent_tools.install`.
 */
export interface AgentToolsInstallResult {
  /**
   * True when the installation was already present and unchanged.
   */
  already_installed: boolean
  manifest: ChangeManifest
  /**
   * What an earlier attempt may have written and this one could not account for.
   *
   * Empty in the ordinary case. A line here means the installation is not finished: the change
   * it names is neither owned nor undone, and somebody has to look at it.
   */
  unresolved: string[]
}
/**
 * What was changed, and how to undo it.
 */
export interface ChangeManifest {
  /**
   * The agent it was installed for.
   */
  agent: 'codex' | 'claude-code' | 'opencode' | 'gemini-cli' | 'kimi-code-cli' | 'qoder-cli'
  /**
   * The command the agent runs to reach the tools.
   */
  entry_point: string[]
  /**
   * Every change, in the order it was applied.
   *
   * A removal undoes them in the order it can carry out: files and server entries first, then
   * the directories that held them, deepest first.
   */
  operations: ChangeOperation[]
  /**
   * The directory the scope resolved to.
   */
  root: string
  /**
   * The scope it was installed at.
   */
  scope: 'user' | 'project'
  /**
   * The skill version installed.
   */
  skill_version: string
}
/**
 * Parameters of `agent_tools.install`, `agent_tools.status` and `agent_tools.remove`.
 */
export interface AgentToolsParams {
  /**
   * The agent.
   */
  agent: 'codex' | 'claude-code' | 'opencode' | 'gemini-cli' | 'kimi-code-cli' | 'qoder-cli'
  /**
   * The project directory, for project scope.
   */
  project_dir: string | null
  /**
   * The scope.
   */
  scope: 'user' | 'project'
}
/**
 * The result of `agent_tools.remove`.
 */
export interface AgentToolsRemoveResult {
  /**
   * The agent.
   */
  agent: 'codex' | 'claude-code' | 'opencode' | 'gemini-cli' | 'kimi-code-cli' | 'qoder-cli'
  /**
   * What was undone.
   */
  removed: ChangeOperation[]
  /**
   * What was left alone, and why.
   */
  retained: string[]
  /**
   * The scope.
   */
  scope: 'user' | 'project'
}
/**
 * The result of `agent_tools.status`.
 */
export interface AgentToolsStatusResult {
  /**
   * The agent.
   */
  agent: 'codex' | 'claude-code' | 'opencode' | 'gemini-cli' | 'kimi-code-cli' | 'qoder-cli'
  /**
   * What no longer matches the record, in the words a person reads.
   */
  drift: string[]
  /**
   * Each installed file and whether it is still what was written.
   */
  files: InstalledFile[]
  /**
   * True when a recorded installation is present.
   */
  installed: boolean
  /**
   * The operations a removal would run.
   */
  removal: ChangeOperation[]
  /**
   * The directory the scope resolved to.
   */
  root: string
  /**
   * The scope.
   */
  scope: 'user' | 'project'
  /**
   * The version recorded, when there is one.
   */
  skill_version: string | null
}
/**
 * What one installed file looks like now.
 */
export interface InstalledFile {
  /**
   * The digest on disk now, or null when the path is gone.
   */
  actual_digest: Digest256 | null
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  expected_digest: string
  /**
   * The absolute path.
   */
  path: string
}
/**
 * One alert. It reports; it asks for nothing.
 */
export interface Alert {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The source's own de-duplication identifier.
   */
  dedup_id: string
  /**
   * A link into this host's own session, when the source supplied one.
   */
  safe_session_link: string | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How urgent it is.
   */
  severity: 'info' | 'warning' | 'error'
  source: QuestionSource
  /**
   * The concise text.
   */
  text: string
}
/**
 * The verified source, and the unverified label beside it.
 */
export interface QuestionSource {
  /**
   * The agent thread or binding revision, when a qualified bridge supplied one.
   *
   * Null when no bridge did. A null here is not a claim that the thread never changed: without
   * a bridge the question is application-scoped and thread-switch detection is not offered.
   */
  agent_binding_revision: AgentBindingRevision | null
  /**
   * The caller's own label for itself. Unverified, and never part of authority.
   */
  agent_label: string | null
  /**
   * True when the process's parent chain reaches the session's root shell.
   *
   * A checked hint, recorded for diagnostics. Section 11 is explicit that ancestry is not a
   * defence against arbitrary code running under the same account, so nothing is admitted on
   * this alone.
   */
  ancestry: boolean
  /**
   * One foreground application within a terminal session.
   */
  application_instance_id: string
  /**
   * The connection the question was created on.
   */
  connection_id: string
  /**
   * The executable that process is running, where the platform names it.
   */
  executable: string | null
  /**
   * True when the helper presented the private launch channel it inherited.
   *
   * False means the binding rests on the checks below instead; it does not mean the source is
   * less bound, and it is recorded so a reader can tell which evidence was available.
   */
  launch_channel: boolean
  process: ProcessStartIdentity
  /**
   * True when the process is inside the session's own ownership boundary, as the kernel
   * reports it. This is what admits a source.
   */
  session_member: boolean
}
/**
 * The process the kernel reports on the other end of the socket, with its start value.
 */
export interface ProcessStartIdentity {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * Parameters of `alert.create`.
 */
export interface AlertCreateParams {
  /**
   * The caller's label for itself. Unverified.
   */
  agent_name: string | null
  /**
   * The source's de-duplication identifier.
   */
  dedup_id: string
  /**
   * A link into this host's own session, when there is one.
   */
  safe_session_link: string | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How urgent it is.
   */
  severity: 'info' | 'warning' | 'error'
  /**
   * The concise text.
   */
  text: string
}
/**
 * The result of `alert.create`.
 */
export interface AlertCreateResult {
  alert: Alert1
  /**
   * True when an exact duplicate returned the existing alert rather than raising one.
   */
  deduplicated: boolean
}
/**
 * The alert.
 */
export interface Alert1 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The source's own de-duplication identifier.
   */
  dedup_id: string
  /**
   * A link into this host's own session, when the source supplied one.
   */
  safe_session_link: string | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How urgent it is.
   */
  severity: 'info' | 'warning' | 'error'
  source: QuestionSource
  /**
   * The concise text.
   */
  text: string
}
/**
 * The answer, who gave it and against which revision.
 */
export interface AnswerRecord {
  /**
   * The host-verified principal that answered. A caller never asserts its own.
   */
  actor_id: string
  /**
   * What was answered.
   */
  answer:
    | {
        kind: 'input'
        /**
         * What the person typed.
         */
        text: string
      }
    | {
        /**
         * The choice the person selected.
         */
        choice_id: string
        kind: 'choice'
      }
    | {
        /**
         * True for yes.
         */
        decided: boolean
        kind: 'decision'
      }
    | {
        kind: 'other'
        /**
         * What the person typed instead of choosing.
         */
        text: string
      }
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  answered_at_ms: string
  /**
   * The paired device that answered, when the answer came from one.
   */
  device_id: DeviceId | null
  /**
   * The revision of the question the person was shown.
   */
  question_revision: string
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  version: string
}
/**
 * The encrypted manifest object.
 */
export interface EncryptedObjectRef {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  encrypted_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
 * Parameters of `attachment.configure`.
 *
 * Withdrawing or adding an authorised claim does not change the session identity and cannot
 * displace an existing owner.
 */
export interface AttachmentConfigureParams {
  /**
   * The attachment to reconfigure.
   */
  attachment_id: string
  /**
   * Whether it holds a geometry claim after this call.
   */
  claim_geometry: boolean
}
/**
 * What one integration declares it accepts for one operation.
 *
 * Section 11 requires the declaration to exist before anything is offered: accepted media types,
 * the selected model's limits, counts, the insertion method and any external destination. A
 * contribution receives completed opaque handles; it never performs the transfer itself.
 */
export interface AttachmentContribution1 {
  /**
   * The media types the installed agent accepts, exactly as declared.
   */
  accepted_media_types: string[]
  /**
   * The external destination bytes reach, when the operation has one. Null means the bytes stay
   * in this environment.
   */
  external_destination: string | null
  /**
   * How the handle reaches the agent.
   */
  insertion_method: 'typed_submission' | 'verified_composer_insertion' | 'manual_terminal_workflow'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_byte_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_count: string
  /**
   * True when the selected model advertises a media capability for these types.
   *
   * An adapter verifies this before offering an image; a false value means the file transfers
   * but is not presented as a model image.
   */
  model_media_capability: boolean
  /**
   * The operation this declaration covers.
   */
  operation_id: string
}
/**
 * A completed, verified attachment.
 *
 * This is the opaque handle section 14 requires. It names the environment that owns the bytes, the
 * transfer that produced them and the digest that was verified before anything was published. It
 * carries no host path: an adapter that needs a readable location asks for an
 * [`AttachmentReadGrant`] instead.
 */
export interface AttachmentHandle1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * The verified whole-file SHA-256 digest.
   */
  content_digest: string
  /**
   * The media type the client declared. Declared, not sniffed: it says what the client believes
   * it sent.
   */
  declared_media_type: string
  /**
   * The environment that owns the file. A handle never crosses environments.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The original filename, kept as metadata only.
   */
  original_file_name: string
  /**
   * True only when the bytes decoded as one of [`PreviewFormat`]'s formats.
   *
   * Unsupported media transfers as a file and is never presented as a model image, so an adapter
   * reads this rather than guessing from the declared media type or the filename.
   */
  presented_as_image: boolean
  /**
   * The bounded preview, when one could be produced. A failed preview leaves this null and the
   * file itself is unaffected.
   */
  preview: AttachmentPreview | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  published_at_ms: string
  /**
   * The session the upload was bound to, when it had one.
   */
  session_id: SessionId | null
  /**
   * True once a draft binding holding this attachment was submitted.
   */
  submitted: boolean
  /**
   * The transfer that produced it, which is also this attachment's durable identity.
   */
  transfer_id: string
}
/**
 * One attachment of a session.
 */
export interface AttachmentSummary {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  attached_at_ms: string
  /**
   * The attachment identity, independent of the device behind it.
   */
  attachment_id: string
  /**
   * Whether this attachment holds an eligible geometry claim.
   */
  claim_geometry: boolean
  /**
   * The attachment's own physical dimensions, reported even when it is not the owner.
   */
  dimensions: Dimensions | null
  /**
   * The capabilities the host granted, which are the requested ones intersected with the
   * actor's rights.
   */
  granted: AttachmentCapability[]
  /**
   * What this attachment observes.
   */
  mode: 'semantic' | 'terminal'
  /**
   * The monotonic join order that decides size-owner succession.
   */
  ordinal: string
  /**
   * How the attachment displays the canonical grid.
   */
  presentation: TerminalPresentationMode | null
  /**
   * The terminal profile it presents.
   */
  terminal_profile_id: string | null
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * Parameters of `attachment.viewport`.
 *
 * Every terminal attachment reports its own physical dimensions, whether or not it owns the size.
 */
export interface AttachmentViewportParams {
  /**
   * The reporting attachment.
   */
  attachment_id: string
  dimensions: Dimensions1
  /**
   * Where its window sits. Null is the live screen.
   */
  position: ViewportPosition | null
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * The result of `attachment.viewport`.
 */
export interface AttachmentViewportResult {
  geometry: GeometryState
  /**
   * Where the window ended up, as a row identifier, or null for the live screen.
   *
   * A request above the oldest row the session still holds is answered with the oldest one
   * there is rather than refused, and a request at or below the live screen's first row is
   * answered with the live screen. Either way this says where the window actually is.
   */
  position: ViewportPosition | null
  /**
   * How a terminal attachment displays the canonical grid.
   */
  presentation: 'direct' | 'viewport'
}
/**
 * The canonical geometry, which a viewport report never changes.
 */
export interface GeometryState {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * Parameters of `attention.acknowledge`.
 */
export interface AttentionAcknowledgeParams {
  /**
   * The items, by key.
   */
  keys: AttentionKey[]
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `attention.acknowledge`.
 */
export interface AttentionAcknowledgeResult {
  /**
   * The keys that were acknowledged, in the order they were given.
   */
  acknowledged: AttentionKey[]
  /**
   * The actor the acknowledgement belongs to.
   */
  actor_id: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  revision: string
}
/**
 * A range of retained source events the host can no longer read.
 */
export interface AttentionGap {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_sequence: string
  /**
   * Which source the range belongs to.
   */
  source: 'receipts' | 'questions' | 'host_events' | 'semantic'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  to_sequence: string
}
/**
 * One item in the attention inbox.
 */
export interface AttentionItem {
  /**
   * Whether this actor has acknowledged it.
   */
  acknowledged: boolean
  /**
   * Whether a decided announcement is still waiting to be taken by a delivery consumer.
   *
   * The host writes a decision down before it hands it over, and keeps it written down until
   * somebody takes it, so a host that decided an announcement and then died re-offers it rather
   * than losing it. What becomes of the announcement afterwards belongs to the delivery
   * journal, not to the feature store.
   */
  awaiting_delivery: boolean
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  first_seen_ms: string
  /**
   * One attention rule and the subject it was raised about.
   */
  key: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  last_seen_ms: string
  /**
   * What it is asking for now, after any escalation.
   */
  level: 'informational' | 'notable' | 'urgent'
  /**
   * What became of the notification.
   */
  notification: 'pending' | 'delivered' | 'deferred' | 'suppressed'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  occurrences: string
  /**
   * Where the notification went.
   */
  routing: 'lease_holder' | 'owner_policy'
  /**
   * The rule that raised it.
   */
  rule:
    | 'attention.pending_approval'
    | 'attention.pending_input'
    | 'attention.input_idle_reminder'
    | 'attention.command_failed'
    | 'attention.review_ready'
    | 'attention.adapter_failed'
    | 'attention.host_contact_lost'
    | 'attention.application_notice'
  /**
   * The session it belongs to, when it belongs to one.
   */
  session_id: SessionId | null
  /**
   * The retained source the condition was observed in.
   *
   * It is what a gap is weighed against: a range that retention took from this source is a
   * range that could have resolved this item, and a range taken from another source is not.
   */
  source: 'receipts' | 'questions' | 'host_events' | 'semantic'
  /**
   * One line naming the subject, when this caller may be served it.
   *
   * Null means the host withheld it. An item's text comes from retained content - a question's
   * wording, a command line, what an application printed - and a caller whose grant the host
   * cannot narrow that content to is served the item without it rather than more than its grant
   * allows. What is left says which rule, at what level, how often and when, which is the
   * host's own record rather than the session's.
   */
  summary: string | null
  /**
   * Whether the host itself observed the condition.
   *
   * False for an application notice, which any process writing to the terminal can emit. A
   * client must not present an untrusted item as a host decision, and nothing untrusted is ever
   * a pending approval.
   */
  trusted: boolean
  /**
   * Whether a gap in the retained events covers this item's subject.
   *
   * A gap is not a resolution. An item whose resolving event may have been evicted stays in the
   * inbox and says that the host cannot tell, which is section 24's rule that a history gap is
   * never an inferred approval or completion.
   */
  uncertain: boolean
}
/**
 * Parameters of `attention.quiet_hours`.
 */
export interface AttentionQuietHoursParams {
  /**
   * The window, or null to clear it.
   */
  quiet_hours: QuietHours | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The window in which audible delivery is held back.
 *
 * Both bounds are minutes of the UTC day, and a window whose end is at or before its start wraps
 * midnight. A window whose bounds are equal is a whole day of quiet hours, which is a thing a
 * person can choose; a client that means "never" clears the configuration instead.
 */
export interface QuietHours {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  end_minute: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_minute: string
  /**
   * The time zone the client converted from, recorded for the client's own use.
   *
   * The host stores it and gives it back. It never interprets it, which is why the window
   * itself is in UTC: deciding a local window would need a zone database the host does not
   * carry, and guessing one would suppress a notification at the wrong hour.
   */
  zone: string | null
}
/**
 * The result of `attention.quiet_hours`.
 */
export interface AttentionQuietHoursResult {
  /**
   * The window now in force, or null when there is none.
   */
  quiet_hours: QuietHours | null
  /**
   * Whether this host can prove what its wall clock reads.
   */
  quiet_hours_provable: boolean
  /**
   * Whether the host is inside it now.
   */
  quiet_now: boolean
}
/**
 * Parameters of `attention.read`.
 */
export interface AttentionReadParams {
  /**
   * The key to continue after, or null to start at the oldest item.
   */
  after: AttentionKey | null
  /**
   * Whether items this actor has already acknowledged are included.
   */
  include_acknowledged: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_items: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `attention.read`.
 */
export interface AttentionReadResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  dropped: string
  /**
   * The ranges of retained events the host can no longer read.
   */
  gaps: AttentionGap[]
  /**
   * The items, oldest first.
   */
  items: AttentionItem[]
  /**
   * Whether more items remain after the last one in this page.
   */
  more: boolean
  /**
   * The configured quiet hours, when there are any.
   */
  quiet_hours: QuietHours | null
  /**
   * Whether this host can prove what its wall clock reads.
   *
   * Quiet hours are a wall-clock window, so a host that cannot prove its clock cannot prove it
   * is inside one. It delivers rather than suppresses, and says so here, because a suppression
   * decided on an unprovable clock withholds a notification nobody asked to withhold.
   */
  quiet_hours_provable: boolean
  /**
   * Whether the host is inside its quiet hours now.
   */
  quiet_now: boolean
}
/**
 * What this host shows about the remote authority feed.
 */
export interface AuthorityFeedStatus {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  accepted_revision: string
  /**
   * The last successful synchronisation, when there has been one.
   */
  last_synchronised_at_ms: TimestampMs | null
  /**
   * True when the feed could not be reached, so what is shown is stale.
   */
  stale: boolean
  /**
   * How many retained revocation records have not yet been acknowledged by every enrolled host.
   */
  unacknowledged_records: number
}
/**
 * A worker's acknowledgement that it is acting under an authority revision.
 *
 * Section 9 makes the acknowledgement two statements rather than one: the revision is installed,
 * **and** the undispatched actions it affects have been rejected or fenced. The two lists are
 * therefore part of the acknowledgement rather than something a caller has to ask for
 * afterwards. An action whose dispatch transition had already won the serial race is named in
 * `possibly_executed`.
 *
 * The evidence defaults to absent on the wire. A worker keeps running across a controller
 * replacement, so during an update a new daemon can be talking to a worker built before the
 * evidence existed, and architecture decision C keeps local support until the last such worker
 * exits. Defaulting lets that worker's two-field acknowledgement decode instead of failing the
 * revocation outright, and the daemon can still tell it apart from a worker whose fence found
 * nothing, because absent and empty are different values.
 */
export interface AuthorityRevisionAck {
  /**
   * What the fence did, when this worker reports it.
   *
   * Absent is not the same as empty. Empty says the fence ran and found nothing; absent says
   * this worker does not report fence evidence at all, and a daemon that read the two the same
   * way would call a revocation complete on the strength of a worker that never said so.
   */
  fence?: FenceEvidence | null
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  revision: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * What a worker's fence did, as one acknowledgement carries it.
 *
 * The lists are the acknowledgement rather than an addition to it: section 9 makes the
 * acknowledgement a statement that the revision is installed **and** that the undispatched
 * actions it affects have been rejected or named. A worker that reports no evidence at all is a
 * different thing from one that reports empty lists, which is why this travels as a whole.
 */
export interface FenceEvidence {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  omitted: string
  /**
   * The actions whose dispatch transition had already won the serial race, in this page.
   *
   * Each one's receipt state says how much is known about what it did; the list is not only the
   * uncertain ones.
   */
  possibly_executed: PossiblyExecutedAction[]
  /**
   * The undispatched intents the fence rejected, in this page.
   */
  rejected_actions: FencedAction[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  remaining: string
}
/**
 * An action whose dispatch transition had already won the serial race when the fence ran.
 *
 * The set is defined by the race rather than by the outcome, which is what section 9 says: an
 * action whose dispatch transition already won it is named in the result. [`Self::state`] is what
 * says how much is known about what it did, from `dispatching` through `unknown` to an
 * authoritative `applied` or `refused`, so a person reading a revocation sees which operations
 * went out under the authority that has just been withdrawn and which of them are still
 * uncertain.
 */
export interface PossiblyExecutedAction {
  /**
   * The action.
   */
  action_id: string
  /**
   * The actor that submitted it.
   */
  actor_id: string
  /**
   * The method it was submitted under.
   */
  method: string
  /**
   * The receipt state it stood at when the fence ran.
   */
  state: 'received' | 'accepted' | 'dispatching' | 'applied' | 'refused' | 'rejected' | 'unknown'
}
/**
 * One action a fence named, with the actor whose action it was.
 *
 * The actor is part of the name because the de-duplication key is the actor and the action
 * together: two actors may each have used one identifier, and an identifier on its own would name
 * either of them.
 */
export interface FencedAction {
  /**
   * The action.
   */
  action_id: string
  /**
   * The actor whose action it was.
   */
  actor_id: string
}
/**
 * The host's current authority revision, announced to a worker by the controller that holds it.
 *
 * Authority revisions are ordered and only the host issues them. A revocation is not complete
 * when the controller records it: it is complete when every worker that could still act on the
 * revoked authority has acknowledged the revision that removed it. Until then the revocation
 * reports `pending` for that worker, or the worker is confirmed ended, which answers the same
 * question a different way.
 */
export interface AuthorityRevisionNotice {
  /**
   * The environment whose authority changed.
   */
  environment_id: string
  /**
   * How many names of this revision's fence evidence the daemon already has.
   *
   * Nought asks for the first page, which is what a first announcement is. An announcement that
   * carries more is asking for the rest of what the previous answer said remained, from the
   * name after the last one it carried.
   *
   * It is absent from the wire when it is nought, so an announcement that asks for a first page
   * is byte for byte what a worker built before paging existed expects. A daemon only ever
   * sends a continuation to a worker whose own answer reported names remaining, and a worker
   * that reports no evidence at all never does.
   */
  evidence_from?: number
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  revision: string
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
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
 * One published generation and the writer's signature over it.
 */
export interface BackupGenerationPublication {
  payload: BackupGenerationPublicationPayload
  /**
   * The writer's signature over [`BackupGenerationPublicationPayload::signing_input`].
   */
  signature: string
}
/**
 * What the writer published.
 */
export interface BackupGenerationPublicationPayload {
  descriptor: ArchiveDescriptor1
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  published_at_ms: string
  /**
   * The writer's signing key identifier.
   */
  writer_key_id: string
}
/**
 * The public descriptor of this generation.
 */
export interface ArchiveDescriptor1 {
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  version: string
}
/**
 * One collection's writer enrolment, signed by the collection owner's authorisation key.
 */
export interface BackupWriterRecord {
  payload: BackupWriterRecordPayload
  /**
   * The owner's signature over [`BackupWriterRecordPayload::signing_input`].
   */
  signature: string
}
/**
 * What the owner states.
 */
export interface BackupWriterRecordPayload {
  /**
   * The archive whose generations this writer may publish.
   */
  archive_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  enrolled_at_ms: string
  /**
   * The owner's authorisation key identifier.
   */
  owner_key_id: string
  writer: TrustedWriter
  /**
   * The revision of this collection's enrolment. Only the owner advances it.
   */
  writer_revision: string
}
/**
 * The writer the owner enrols.
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
 * One capability, one subject, one answer.
 *
 * This is the shared section 11 record. Capability evidence describes feasibility and never
 * creates authority: every action still checks its grant, and it rechecks this record's revision
 * independently.
 */
export interface CapabilityRecord {
  /**
   * The capability, in the shared versioned namespace.
   */
  capability: string
  /**
   * What a person is told when the capability is not available.
   */
  disabled_reason: string | null
  /**
   * What produced the answer.
   */
  evidence_source:
    'disclosed_probe' | 'platform_query' | 'signed_compatibility_record' | 'not_probed'
  identity: CapabilityIdentity
  /**
   * What makes this record stale, in the order it is written.
   */
  invalidation: CapabilityInvalidation[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  observed_at_ms: string
  /**
   * This record's revision. An action binds to it and rechecks it.
   */
  revision: string
  /**
   * What the capability can currently do.
   */
  state:
    | 'qualified_available'
    | 'missing_installation'
    | 'permission_required'
    | 'incompatible'
    | 'temporarily_unavailable'
    | 'not_tested'
  subject: CapabilitySubject
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  version: string
}
/**
 * The exact thing the answer was established about.
 */
export interface CapabilityIdentity {
  /**
   * The binary that was probed, by absolute path.
   */
  binary: string | null
  /**
   * The package the capability belongs to.
   */
  package: string | null
  /**
   * The execution profile the probe ran under.
   */
  profile: WorkerProfile | null
  /**
   * The schema the binding speaks.
   */
  schema: string | null
  /**
   * That binary's version, as it reported it.
   */
  version: string | null
}
/**
 * What the record is about.
 */
export interface CapabilitySubject {
  /**
   * The application the record is about, where it is one.
   */
  application: string | null
  /**
   * The desktop, where the subject is one.
   */
  desktop_session_id: DesktopSessionId | null
  /**
   * The environment.
   */
  environment_id: string
  /**
   * The session, where the subject is one.
   */
  session_id: SessionId | null
  /**
   * The terminal the record is about, where it is one.
   */
  terminal: string | null
}
/**
 * The exact set of changes one installation made, and how to undo them.
 */
export interface ChangeManifest1 {
  /**
   * The agent it was installed for.
   */
  agent: 'codex' | 'claude-code' | 'opencode' | 'gemini-cli' | 'kimi-code-cli' | 'qoder-cli'
  /**
   * The command the agent runs to reach the tools.
   */
  entry_point: string[]
  /**
   * Every change, in the order it was applied.
   *
   * A removal undoes them in the order it can carry out: files and server entries first, then
   * the directories that held them, deepest first.
   */
  operations: ChangeOperation[]
  /**
   * The directory the scope resolved to.
   */
  root: string
  /**
   * The scope it was installed at.
   */
  scope: 'user' | 'project'
  /**
   * The skill version installed.
   */
  skill_version: string
}
/**
 * A model's summary of an interval, carried beside the authoritative events.
 *
 * Section 25 requires a summary to name its source interval and stay separate from the events. It
 * is never merged into [`VisitChangedResult::changes`] and never stands in for one: a client that
 * ignores it loses nothing authoritative.
 */
export interface ChangeSummary {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  from_ms: string
  /**
   * The model that produced it, as the host recorded it.
   */
  model: string
  /**
   * The summary text.
   */
  text: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  to_cursor: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  to_ms: string
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_attachment_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_control_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_input_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_outstanding_mutations: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
 * The final record of one closed session.
 */
export interface ClosureRecord {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  closed_at_ms: string
  /**
   * Whether the record was written durably.
   */
  durability: 'durable' | 'volatile'
  /**
   * Whether every owned process was accounted for.
   */
  ownership_coverage: 'complete' | 'incomplete'
  /**
   * Why it closed.
   */
  reason:
    | 'close_requested'
    | 'root_exit'
    | 'root_signal'
    | 'root_launch_failed'
    | 'worker_crash'
    | 'desktop_lost'
    | 'host_shutdown'
  /**
   * The root shell's exit status, when it exited normally.
   */
  root_exit_code: U64 | null
  /**
   * The signal that terminated the root shell, when one did, named as the platform names it.
   * The host reports what it was told rather than inventing a number for it.
   */
  root_signal: string | null
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * Resources known to survive, such as an explicitly brokered desktop resource.
   */
  surviving: SurvivingResource[]
  /**
   * The owned processes the closure terminated, with their start identities.
   */
  terminated: TerminatedProcess[]
}
/**
 * A resource the session did not take with it.
 *
 * Most entries are resources that outlive a session by design, such as a brokered desktop
 * resource. An entry is also how a host says it *could not establish* that something ended: a
 * closure written without a confirmed death names the session's own worker here rather than
 * among the processes it terminated, because the host did not terminate it and cannot say it
 * stopped.
 */
export interface SurvivingResource {
  /**
   * A description for the user.
   */
  detail: string
  /**
   * What kind of resource it is.
   */
  kind: string
}
/**
 * One process the closure terminated.
 */
export interface TerminatedProcess {
  /**
   * True when the process needed forced termination after the grace period.
   */
  forced: boolean
  identity: ProcessStartIdentity1
  /**
   * The executable name, for diagnostics.
   */
  name: string | null
}
/**
 * The process and its start identity, so a reused identifier is not mistaken for it.
 */
export interface ProcessStartIdentity1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
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
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
 * The first frame a local client sends.
 */
export interface LocalHello {
  /**
   * The client build.
   */
  build_id: string
  /**
   * The capabilities the client offers.
   */
  capabilities: CapabilityId[]
  /**
   * What kind of client this is. It says how to frame the conversation; it confers nothing.
   */
  client: 'cli' | 'controller' | 'worker'
  max_receive: ReceiveLimits1
  /**
   * Every protocol version the client offers.
   */
  offered_versions: ProtocolVersion[]
}
/**
 * The client's own receive limits.
 */
export interface ReceiveLimits1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_attachment_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_control_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_input_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_outstanding_mutations: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_send_queue_bytes: string
}
/**
 * The first frame the host sends back.
 */
export interface LocalHelloAck {
  action_window: ActionWindow2
  boot_identity: BootIdentity
  /**
   * The capabilities both sides will use.
   */
  capabilities: CapabilityId[]
  /**
   * The connection identity the host assigned.
   */
  connection_id: string
  /**
   * The environment this endpoint belongs to.
   */
  environment_id: string
  max_receive: ReceiveLimits2
  peer: LocalPeer
  /**
   * Which host process answered.
   */
  role: 'controller' | 'worker' | 'rendezvous'
  selected_version: ProtocolVersion1
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
export interface ActionWindow2 {
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
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * How long the window stays valid, at most [`crate::limits::MAX_ACTION_WINDOW`].
   */
  valid_for_ms: string
}
/**
 * The boot the host is running.
 */
export interface BootIdentity {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * The limits both sides will use.
 */
export interface ReceiveLimits2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_attachment_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_control_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_input_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_outstanding_mutations: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_send_queue_bytes: string
}
/**
 * The caller the host authenticated.
 */
export interface LocalPeer {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  gid: string
  /**
   * The caller's process identifier, where the platform reports one. A hint for diagnostics,
   * never authority on its own.
   */
  pid: U64 | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  uid: string
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
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
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
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
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
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
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
  receipt: Receipt2
  /**
   * The request this response correlates with.
   */
  request_id: string
}
/**
 * The current receipt.
 */
export interface Receipt2 {
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
 * A worker's startup claim, signed with the key it just generated.
 */
export interface WorkerRendezvous {
  boot_identity: BootIdentity1
  process_start_identity: ProcessStartIdentity2
  /**
   * The reservation this worker was started for.
   */
  reservation_id: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The signature over [`rendezvous_elements`].
   */
  signature: string
  /**
   * The public half of the worker's new per-session key.
   */
  worker_public_key: string
}
/**
 * The boot the worker started in.
 */
export interface BootIdentity1 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * The worker's own process identity, which the controller compares with what the launcher
 * reported and with the connecting peer.
 */
export interface ProcessStartIdentity2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * What the controller tells a worker to become, over the private rendezvous channel.
 *
 * The job definition that started the worker carries only non-secret facts: the reservation, the
 * rendezvous address and the runtime directory. Everything else arrives here, after the worker
 * has proved which reservation it belongs to, so a creator's environment snapshot never sits in
 * an argument vector or an environment variable where another process could read it.
 */
export interface WorkerLaunchSpec {
  /**
   * The generation that spawned this worker.
   */
  controller_generation: string
  /**
   * The controller's public key, recorded so the worker can check generation tokens.
   */
  controller_public_key: string
  create: SessionCreateParams
  /**
   * The local alias, which also names the worker's endpoint.
   */
  display_number: string
  /**
   * The environment the session belongs to.
   */
  environment_id: string
  /**
   * The release string the session reports as its terminal program version.
   */
  release: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The qualified shell package the controller resolved, as an absolute directory.
   *
   * Null for a create that launches no managed package. Where it is present the worker launches
   * that package and no other: the daemon and the worker can be configured with different
   * package roots, and a session must run the package its create was admitted against rather
   * than whichever one the worker's own environment would have found.
   */
  shell_package: string | null
}
/**
 * The create request the controller admitted.
 */
export interface SessionCreateParams {
  /**
   * The working directory. Null selects the caller's directory from the snapshot.
   */
  cwd: string | null
  /**
   * The starting geometry. Null uses the invisible default of 120x40.
   */
  dimensions: Dimensions | null
  /**
   * The environment to create in.
   */
  environment_id: string
  /**
   * The creator's environment snapshot. The host filters terminal identity and reserved
   * KalaReach variables out of it, and execution-context values take precedence over it.
   */
  environment_snapshot: EnvironmentVariable[]
  launch_profile: LaunchProfile
  /**
   * The palette this session starts with. Null takes the profile default.
   *
   * This is the one moment the palette can be chosen: section 8 fixes it at creation, and
   * afterwards only an authorised explicit change moves it. The provenance is recorded either
   * way, so a palette query can say where the session's colours came from.
   */
  palette: PaletteRequest | null
  /**
   * How the session is presented locally.
   */
  presentation: 'attach' | 'terminal' | 'invisible'
  /**
   * The shell to launch. Null selects the environment's configured default.
   */
  shell: string | null
  /**
   * The shell integration mode.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The terminal application a `terminal` presentation opens in, by its stable identifier.
   *
   * The first step of section 7's order. Null leaves the choice to the host, which detects what
   * is installed; a named application this host does not have is `TERMINAL_UNAVAILABLE` rather
   * than a substitution, because somebody asked for that terminal.
   */
  terminal: string | null
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * One environment variable in a create request's snapshot.
 */
export interface EnvironmentVariable {
  /**
   * The name.
   */
  name: string
  /**
   * The value.
   */
  value: string
}
/**
 * How this session starts its root shell and what may be launched inside it.
 */
export interface LaunchProfile {
  /**
   * The opt-in command integrations this session applies to interactive invocations.
   */
  command_integrations: CommandIntegration[]
  /**
   * Whether a host-authorised `shell.launch` may install a command in this session's editor.
   *
   * A profile that says no keeps everything else a managed session has — the fence, the
   * empty-prompt end-of-file gesture, the attributed acceptance — and refuses the one operation
   * that puts text a person did not type into their editor.
   */
  fenced_launch: boolean
  /**
   * Which startup files the root shell reads.
   */
  startup: 'host_default' | 'interactive' | 'login'
}
/**
 * One agent's opt-in command integration.
 *
 * Section 12: where an agent needs integration flags, an explicitly enabled integration adds them
 * to interactive invocations inside a managed root shell. The command name and the argument
 * vector the person typed are preserved; the flags are added and nothing is removed or reordered.
 */
export interface CommandIntegration {
  /**
   * The command name this integration applies to, as typed.
   */
  command: string
  /**
   * Whether the user has enabled it. A disabled integration changes nothing.
   */
  enabled: boolean
  /**
   * The flags the agent needs, added to an interactive invocation.
   */
  flags: string[]
}
/**
 * The default foreground and background a client's bounded probe established.
 */
export interface ProbedPalette {
  background: Rgb
  foreground: Rgb1
}
/**
 * A direct colour.
 */
export interface Rgb {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb1 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * What a worker reports once its root shell is running.
 */
export interface WorkerReady {
  dimensions: Dimensions3
  /**
   * The worker's private endpoint.
   */
  endpoint: string
  root_process: ProcessStartIdentity3
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The executable actually launched.
   */
  shell_path: string
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions3 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * The root shell's process identity.
 */
export interface ProcessStartIdentity3 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * A fresh challenge sent to a worker's private endpoint.
 */
export interface WorkerVerifyChallenge {
  /**
   * Thirty-two fresh random bytes. A reused challenge proves nothing.
   */
  nonce: string
}
/**
 * A worker's answer to a challenge.
 *
 * The verifier checks the signature against the descriptor's public key **and** compares every
 * identity field with the descriptor. A worker that answers with a different session, epoch, boot
 * or process is not the worker the descriptor named.
 */
export interface WorkerVerifyProof {
  boot_identity: BootIdentity2
  /**
   * The endpoint the challenge arrived on.
   */
  endpoint: string
  process_start_identity: ProcessStartIdentity4
  protocol_version: ProtocolVersion2
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The signature over [`verify_elements`].
   */
  signature: string
}
/**
 * The boot the worker is running in.
 */
export interface BootIdentity2 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * The worker's process identity.
 */
export interface ProcessStartIdentity4 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion2 {
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
 * A worker's challenge to a controller that wants to speak for a generation.
 */
export interface GenerationChallenge {
  /**
   * Thirty-two fresh random bytes, bound to this connection and consumed once.
   */
  nonce: string
}
/**
 * A controller's proof that it speaks for the current generation.
 *
 * The nonce comes from the worker, so a token cannot be replayed onto a later connection. A
 * worker accepts its current generation again only after a fresh challenge, which fences that
 * generation's previous connection; it rejects a lower generation outright and requires a
 * strictly higher one from a replacement.
 */
export interface ControllerGenerationToken {
  boot_identity: BootIdentity3
  /**
   * The environment the controller owns.
   */
  environment_id: string
  /**
   * The generation this controller holds.
   */
  generation: string
  /**
   * The challenge the worker issued.
   */
  nonce: string
  /**
   * The signature over [`generation_elements`].
   */
  signature: string
}
/**
 * The boot the controller is running in.
 */
export interface BootIdentity3 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * A worker's answer to a generation token.
 */
export interface GenerationAccepted {
  /**
   * True when accepting this token fenced an earlier connection of the same generation.
   */
  fenced_previous: boolean
  /**
   * The generation the worker now accepts.
   */
  generation: string
}
/**
 * A mutation the host admitted for a caller, passed to the component that owns its subject.
 *
 * The control daemon owns admission: it authenticates the caller, stamps the freshness window,
 * checks the envelope and derives the accepted deadline. The worker owns the subject. Forwarding
 * carries the caller's mutation to the worker **unchanged**, because the mutation is what the
 * payload digest covers and what the caller will retry with: rewriting any of it would give the
 * worker a different action from the one the caller asked for.
 *
 * What travels beside it is what the worker cannot establish for itself: which principal the host
 * verified, the rights the grant it was checked against carries, and the deadline the host
 * accepted. The worker performs the action under all three.
 */
export interface ForwardedMutation {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  accepted_deadline_boot_ms: string
  actor: ActorEnvelope1
  /**
   * The rights the grant named in the envelope carries, as the host resolved them.
   *
   * Section 8 makes an attachment's granted capabilities the requested ones intersected with
   * the actor's rights, and the worker is where an attachment is admitted. It holds no grants,
   * so the rights travel with the mutation that needs them rather than being asked for again.
   *
   * Empty when the envelope names no grant, which is what a locally authenticated caller's
   * operating-system identity is. The worker narrows nothing for such a caller: there is no
   * grant to narrow by, and its peer credentials already proved it is this user.
   */
  grant_rights: ActionRight[]
  mutation: MutationRequest1
}
/**
 * The actor the host verified, with the ingress it arrived on.
 */
export interface ActorEnvelope1 {
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
 * A mutation request.
 *
 * The payload digest covers the method and version, the actor and grant, the complete target, the
 * preconditions, the action identifier, the freshness window and time to live, and the
 * parameters. Replacing the window changes the digest, so it is never an automatic retry.
 */
export interface MutationRequest1 {
  /**
   * The durable operation identity, a cryptographically generated UUIDv4.
   */
  action_id: string
  /**
   * The host-issued action window this first admission is bound to.
   */
  action_window_id: string
  /**
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
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
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
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
 * A read the host admitted for a caller, passed to the component that owns its subject.
 *
 * A read needs forwarding for the same reason a mutation does, and for one reason more. The
 * subject is the worker's, and the daemon owns admission; but a read is also *attributed*: the
 * de-duplication key of a retained receipt is the verified actor and the action together, so a
 * read that asks about an action has to ask as the caller rather than as the proxy. A plain
 * request carries no actor, and serving one on the proxy's own principal would answer about the
 * proxy's actions instead of the caller's.
 *
 * What travels beside the request is the actor the host verified, including the ingress it
 * arrived on. The worker checks the method against *that* ingress, so a method the registry keeps
 * to private IPC stays unreachable for a paired device even though the frame arrived on a socket.
 */
export interface ForwardedRequest {
  actor: ActorEnvelope2
  /**
   * When the authority behind this request runs out, on the machine's own continuous clock.
   *
   * A read is not a mutation and carries no accepted deadline, but the authority behind it
   * still ends: a grant expires while the request is in the worker's queue, and raw input is a
   * request. The worker compares this inside the boundary that decides what reaches the
   * application, so bytes admitted a moment before an expiry are not written after it. Null
   * when the caller's authority is not something that expires, which is what a locally
   * authenticated caller's operating-system identity is.
   */
  authority_deadline_boot_ms: U64 | null
  request: Request1
}
/**
 * The actor the host verified, with the ingress it arrived on.
 */
export interface ActorEnvelope2 {
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
 * A read request.
 */
export interface Request1 {
  /**
   * The method name. A name that is not in the registry is denied.
   */
  method: string
  /**
   * The method version. Schemas are closed for the negotiated version.
   */
  method_version: number
  /**
   * An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.
   */
  params: unknown
  /**
   * Correlates the response. Unique for the lifetime of one connection.
   */
  request_id: string
}
/**
 * Every capability record for one desktop, with the context they are about.
 */
export interface DesktopCapabilityReport {
  desktop: DesktopContext
  /**
   * The records, ordered by capability name.
   */
  records: CapabilityRecord[]
}
/**
 * The desktop the records are about.
 */
export interface DesktopContext {
  /**
   * Whether the desktop is usable right now, separately from process life.
   */
  availability: 'available' | 'locked' | 'background' | 'ended' | 'unknown'
  boot_identity: BootIdentity4
  /**
   * The desktop environment or compositor the login session runs, where the platform names it.
   */
  compositor: string | null
  /**
   * Whether this context is inside a container or a WSL distribution.
   */
  container: 'host' | 'container' | 'wsl'
  /**
   * The derived name of this whole context, absent when there is no desktop.
   */
  desktop_session_id: DesktopSessionId | null
  /**
   * The display server, where there is one.
   */
  display_server: 'quartz' | 'windows_desktop' | 'x11' | 'wayland' | 'unknown' | 'none'
  /**
   * What the generation was read from.
   */
  generation_source:
    'macos_session_creator' | 'linux_session_leader' | 'windows_session_logon' | 'unavailable'
  /**
   * Whether this context has the login session's graphical access.
   *
   * An invisible session keeps it: presentation does not decide it. A headless user context
   * reports `false`, because it takes no login session; that says none of a desktop reached it
   * and not that the platform has put a desktop beyond its reach.
   */
  graphic_access: boolean
  /**
   * Which platform facility named the login session.
   */
  kind: 'macos_security_session' | 'linux_logind' | 'windows_interactive' | 'none'
  /**
   * The login-session generation, where the platform offers one.
   */
  login_generation: U64 | null
  /**
   * The operating-system user the desktop belongs to.
   */
  os_user: string
  /**
   * The platform's own login-session identifier, exactly as the platform prints it.
   */
  platform_session: string | null
  /**
   * Whether the login session is a remote one, such as a Windows RDP session.
   */
  remote: boolean
  /**
   * That user's numeric identifier, where the platform uses one.
   */
  uid: U64 | null
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * The boot this desktop belongs to.
 */
export interface BootIdentity4 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * The desktop execution context a worker runs in.
 *
 * The identity is the whole record, not the identifier: two contexts are the same desktop only
 * when the user, the platform session, the generation and the boot all agree.
 */
export interface DesktopContext1 {
  /**
   * Whether the desktop is usable right now, separately from process life.
   */
  availability: 'available' | 'locked' | 'background' | 'ended' | 'unknown'
  boot_identity: BootIdentity4
  /**
   * The desktop environment or compositor the login session runs, where the platform names it.
   */
  compositor: string | null
  /**
   * Whether this context is inside a container or a WSL distribution.
   */
  container: 'host' | 'container' | 'wsl'
  /**
   * The derived name of this whole context, absent when there is no desktop.
   */
  desktop_session_id: DesktopSessionId | null
  /**
   * The display server, where there is one.
   */
  display_server: 'quartz' | 'windows_desktop' | 'x11' | 'wayland' | 'unknown' | 'none'
  /**
   * What the generation was read from.
   */
  generation_source:
    'macos_session_creator' | 'linux_session_leader' | 'windows_session_logon' | 'unavailable'
  /**
   * Whether this context has the login session's graphical access.
   *
   * An invisible session keeps it: presentation does not decide it. A headless user context
   * reports `false`, because it takes no login session; that says none of a desktop reached it
   * and not that the platform has put a desktop beyond its reach.
   */
  graphic_access: boolean
  /**
   * Which platform facility named the login session.
   */
  kind: 'macos_security_session' | 'linux_logind' | 'windows_interactive' | 'none'
  /**
   * The login-session generation, where the platform offers one.
   */
  login_generation: U64 | null
  /**
   * The operating-system user the desktop belongs to.
   */
  os_user: string
  /**
   * The platform's own login-session identifier, exactly as the platform prints it.
   */
  platform_session: string | null
  /**
   * Whether the login session is a remote one, such as a Windows RDP session.
   */
  remote: boolean
  /**
   * That user's numeric identifier, where the platform uses one.
   */
  uid: U64 | null
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * Parameters of `device.list`.
 */
export interface DeviceListParams {
  /**
   * Whether revoked devices are included.
   */
  include_revoked: boolean
}
/**
 * The result of `device.list`.
 */
export interface DeviceListResult {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * The devices, ordered by identity.
   */
  devices: DeviceSummary[]
  /**
   * True when the feed is unreachable, so the revocation status shown is stale.
   */
  feed_stale: boolean
  /**
   * The last time this host synchronised the remote authority feed, when it has.
   */
  feed_synchronised_at_ms: TimestampMs | null
}
/**
 * One paired device as `device.list` reports it.
 *
 * Section 10 puts each host's last acknowledgement in the device list, because an offline host
 * cannot apply a revocation it has not received and the person has to be able to see that.
 */
export interface DeviceSummary {
  /**
   * When that acknowledgement arrived.
   */
  acknowledged_at_ms: TimestampMs | null
  /**
   * The last authority revision this device acknowledged.
   */
  acknowledged_revision: AuthorityRevision | null
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The name it was paired under.
   */
  display_name: string
  /**
   * One host-issued authority object.
   */
  grant_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  paired_at_ms: string
  /**
   * Whether the device has been revoked.
   */
  revoked: boolean
}
/**
 * Parameters of `device.preview_key.update`.
 */
export interface DevicePreviewKeyUpdateParams {
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The new notification-preview public key.
   */
  notification_preview: string
}
/**
 * The result of `device.preview_key.update`.
 */
export interface DevicePreviewKeyUpdateResult {
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The key now on record.
   */
  notification_preview: string
}
/**
 * Parameters of `device.revoke`.
 */
export interface DeviceRevokeParams {
  /**
   * One paired device.
   */
  device_id: string
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
 * Parameters of `download.begin`.
 */
export interface DownloadBeginParams {
  /**
   * The device the concurrency limit is counted against.
   */
  device_id: DeviceId | null
  /**
   * The environment that owns the source.
   */
  environment_id: string
  /**
   * The transfer to resume. Resuming addresses the same snapshot and rechecks read authority; a
   * missing or expired snapshot is refused rather than silently replaced.
   */
  resume_transfer_id: TransferId | null
  /**
   * The source, when beginning a new transfer. Ignored when resuming.
   */
  source: DownloadSource | null
}
/**
 * The result of `download.begin`.
 */
export interface DownloadBeginResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * Every chunk's index, length and digest.
   */
  chunks: ChunkDescriptor[]
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  content_digest: string
  /**
   * The environment that owns it.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * How the bytes were made immutable.
   */
  immutability: 'immutable_source' | 'cloned_snapshot' | 'staged_snapshot'
  layout: ChunkLayout
  /**
   * True when this call resumed an existing snapshot rather than creating one.
   */
  resumed: boolean
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * One chunk's index, exact length and digest.
 */
export interface ChunkDescriptor {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  digest: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  index: string
}
/**
 * The chunk layout.
 */
export interface ChunkLayout {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_count: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  last_chunk_len: string
}
/**
 * Parameters of `download.chunk`.
 */
export interface DownloadChunkParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  index: string
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * The result of `download.chunk`.
 */
export interface DownloadChunkResult {
  /**
   * The chunk bytes.
   */
  bytes: string
  chunk: ChunkDescriptor1
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * One chunk's index, exact length and digest.
 */
export interface ChunkDescriptor1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  digest: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  index: string
}
/**
 * How a client publishes a verified download to its own destination.
 *
 * The host never writes to a client destination. This is the contract the client half performs:
 * verify every chunk, the total size and the whole-file digest, write through a temporary file,
 * and refuse an existing destination unless the user has taken an explicit overwrite action for
 * that exact destination.
 */
export interface DownloadPlacement {
  /**
   * True only when the user has taken an explicit overwrite action for this destination.
   *
   * A default value is never true. Without it an existing destination is refused, and the
   * temporary file is removed rather than renamed over anything.
   */
  allow_overwrite: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  content_digest: string
  /**
   * The name inside the client's chosen destination.
   */
  destination_name: string
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * Parameters of `draft.create`.
 */
export interface DraftCreateParams {
  /**
   * The foreground application it targets.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The device that owns it.
   */
  device_id: DeviceId | null
  /**
   * The environment the draft belongs to.
   */
  environment_id: string
  /**
   * The session it targets.
   */
  session_id: SessionId | null
  /**
   * Its initial text.
   */
  text: string
}
/**
 * The result of `draft.create`.
 */
export interface DraftCreateResult {
  draft: DraftRecord1
}
/**
 * The draft.
 */
export interface DraftRecord1 {
  /**
   * The foreground application it targets.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The attachments bound to it, in binding order.
   */
  attachments: DraftAttachment1[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The device that owns it, when one does.
   */
  device_id: DeviceId | null
  /**
   * The draft's identity.
   */
  draft_id: string
  /**
   * The environment that owns it.
   */
  environment_id: string
  /**
   * Its current revision. Every update names the revision it expects.
   */
  revision: string
  /**
   * The session it targets.
   */
  session_id: SessionId | null
  /**
   * Its state.
   */
  state: 'open' | 'conflicted' | 'orphaned'
  /**
   * The draft text. This is not the native terminal edit buffer.
   */
  text: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * A durable device-owned draft.
 *
 * A draft outlives the attachment that displays it: losing a connection removes the association,
 * not the draft. Submission is always a separate action.
 */
export interface DraftRecord2 {
  /**
   * The foreground application it targets.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The attachments bound to it, in binding order.
   */
  attachments: DraftAttachment1[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The device that owns it, when one does.
   */
  device_id: DeviceId | null
  /**
   * The draft's identity.
   */
  draft_id: string
  /**
   * The environment that owns it.
   */
  environment_id: string
  /**
   * Its current revision. Every update names the revision it expects.
   */
  revision: string
  /**
   * The session it targets.
   */
  session_id: SessionId | null
  /**
   * Its state.
   */
  state: 'open' | 'conflicted' | 'orphaned'
  /**
   * The draft text. This is not the native terminal edit buffer.
   */
  text: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * Parameters of `draft.update`.
 */
export interface DraftUpdateParams {
  /**
   * The draft.
   */
  draft_id: string
  /**
   * The revision the caller expects. A mismatch is `DRAFT_CONFLICT` and changes nothing.
   */
  expected_revision: string
  /**
   * The replacement text.
   */
  text: string
}
/**
 * The result of `draft.update`.
 */
export interface DraftUpdateResult {
  draft: DraftRecord3
}
/**
 * The draft after the update.
 */
export interface DraftRecord3 {
  /**
   * The foreground application it targets.
   */
  application_instance_id: ApplicationInstanceId | null
  /**
   * The attachments bound to it, in binding order.
   */
  attachments: DraftAttachment1[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The device that owns it, when one does.
   */
  device_id: DeviceId | null
  /**
   * The draft's identity.
   */
  draft_id: string
  /**
   * The environment that owns it.
   */
  environment_id: string
  /**
   * Its current revision. Every update names the revision it expects.
   */
  revision: string
  /**
   * The session it targets.
   */
  session_id: SessionId | null
  /**
   * Its state.
   */
  state: 'open' | 'conflicted' | 'orphaned'
  /**
   * The draft text. This is not the native terminal edit buffer.
   */
  text: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
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
    | 'authority_feed_change'
    | 'action_receipt'
    | 'state_reference'
    | 'signed_authority_object'
    | 'notification_preview'
    | 'sync_change'
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
   * The thread repeated state notifications coalesce in, when the sender asks for coalescing.
   *
   * It is authenticated here as well as declared in the routing record, so a recipient can see
   * that the value the service coalesced by is the value the sender chose.
   */
  thread_id: MailboxThreadId | null
  /**
   * The envelope format version.
   */
  version: 'kr-mailbox/1'
}
/**
 * Parameters of `environment.capabilities`.
 */
export interface EnvironmentCapabilitiesParams {
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
}
/**
 * The result of `environment.capabilities`.
 *
 * One document: the desktop this environment currently has, what may actually be done on it, the
 * execution profile a session gets when the request does not choose one, what logout does to each
 * profile, and the host's sleep-inhibition state.
 */
export interface EnvironmentCapabilitiesResult {
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  default_worker_profile: 'desktop_bound' | 'headless_user'
  desktop: DesktopCapabilityReport1
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * What logout does to each profile on this platform, in profile order.
   */
  persistence: ProfilePersistence[]
  power: SleepInhibitionState
}
/**
 * The desktop and its capability records.
 */
export interface DesktopCapabilityReport1 {
  desktop: DesktopContext
  /**
   * The records, ordered by capability name.
   */
  records: CapabilityRecord[]
}
/**
 * What the host's per-user service arrangement does at logout.
 */
export interface ProfilePersistence {
  /**
   * What a person is told, including the explicit choice that would change the answer.
   */
  detail: string
  /**
   * The service mechanism the answer is about.
   */
  mechanism: string
  /**
   * What happens to a worker of that profile at logout.
   */
  persistence:
    | 'ends_at_logout'
    | 'survives_logout'
    | 'available_by_choice'
    | 'no_service_manager'
    | 'not_established'
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  profile: 'desktop_bound' | 'headless_user'
}
/**
 * The host's sleep-inhibition state.
 */
export interface SleepInhibitionState {
  /**
   * Whether an assertion is held right now.
   */
  active: boolean
  /**
   * The name the platform shows for the assertion, so a person can find it in the operating
   * system's own listing.
   */
  holder: string | null
  /**
   * The facility holding it.
   */
  mechanism: 'macos_power_assertion' | 'linux_logind_inhibitor' | 'windows_execution_state' | 'none'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pending_requests: string
  /**
   * What the host is running on.
   */
  power_source: 'mains' | 'battery' | 'unknown'
  /**
   * Why it is held, when it is.
   */
  reason: InhibitionReason | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  sessions_with_work: string
  /**
   * The owner's choice.
   */
  setting: 'off' | 'mains_only' | 'battery_too'
  /**
   * When the current assertion was taken.
   */
  since_ms: TimestampMs | null
  /**
   * Why no assertion is held although the setting is on, when that is the case.
   */
  withheld_reason: string | null
}
/**
 * The result of `environment.list`.
 */
export interface EnvironmentListResult {
  /**
   * The environments.
   */
  environments: EnvironmentSummary[]
}
/**
 * One environment this host serves.
 */
export interface EnvironmentSummary {
  /**
   * The processor architecture.
   */
  arch: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * A label for people.
   */
  label: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  live_sessions: string
  /**
   * The operating system.
   */
  os: string
  /**
   * The OS user the environment belongs to.
   */
  os_user: string
  /**
   * The runtime directory holding sockets and worker descriptors.
   */
  runtime_directory: string
  /**
   * The state directory holding the registry, journals and spools.
   */
  state_directory: string
}
/**
 * Parameters of `events.snapshot`.
 */
export interface EventsSnapshotParams {
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `events.snapshot`.
 *
 * Every field is present state, not a replay: installing a snapshot emits no bell, no clipboard
 * write, no notification and no query.
 */
export interface EventsSnapshotResult {
  /**
   * Every current attachment, in join order.
   */
  attachments: AttachmentSummary[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cursor: string
  geometry: GeometryState1
  lease: InputLeaseState
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_cursor: string
  session: SessionSummary
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  taken_at_ms: string
}
/**
 * Who owns the size.
 */
export interface GeometryState1 {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
}
/**
 * Who holds input.
 */
export interface InputLeaseState {
  /**
   * The connection the holder's ordered input stream belongs to.
   */
  connection_id: ConnectionId | null
  /**
   * The current epoch. A takeover advances it and invalidates the previous one.
   */
  epoch: string
  /**
   * The attachment that currently holds input. Null when no attachment holds it.
   */
  holder: AttachmentId | null
  /**
   * The next input sequence the worker expects on that stream.
   */
  next_sequence: string
}
/**
 * The session.
 */
export interface SessionSummary {
  /**
   * What the foreground is doing, where the host knows.
   */
  application_state: ApplicationState | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  attachment_count: string
  /**
   * The final record, once the session has closed.
   */
  closure: ClosureRecord | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The working directory the root shell started in.
   */
  cwd: string
  desktop: DesktopBinding
  dimensions: Dimensions4
  /**
   * The local alias.
   */
  display_number: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The root shell's process identity while the session is running.
   */
  root_process: ProcessStartIdentity5 | null
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How the root shell is integrated. A `native_compat` session is labelled everywhere it is
   * reported.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The executable actually launched as the root shell.
   */
  shell_path: string
  /**
   * The lifecycle state.
   */
  state: 'creating' | 'live' | 'closing' | 'closed'
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * The login session a desktop-bound worker is tied to.
 */
export interface DesktopBinding {
  /**
   * The desktop session this worker is bound to, for a desktop-bound profile.
   */
  desktop_session_id: DesktopSessionId | null
  /**
   * The login-session generation the binding was taken at.
   */
  login_generation: U64 | null
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions4 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * A process and the kernel's record of when it started.
 *
 * Every ownership check compares both fields. A process identifier alone can be reused by an
 * unrelated program within milliseconds of the original exiting, so the host never terminates,
 * adopts or trusts a process on its identifier alone.
 */
export interface ProcessStartIdentity5 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * Parameters of `events.subscribe`.
 */
export interface EventsSubscribeParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The output cursor to resume from. Null starts from the current position.
   */
  from_cursor: U64 | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The streams to receive.
   */
  streams: EventStream[]
}
/**
 * The result of `events.subscribe`.
 */
export interface EventsSubscribeResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * Present when the requested cursor was already evicted, so the client must discard its
   * partial state and install a new snapshot.
   */
  gap: HistoryGap | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_cursor: string
  /**
   * The stream identifier notifications will carry.
   */
  stream_id: string
}
/**
 * A range of output the worker can no longer replay.
 */
export interface HistoryGap {
  /**
   * Why the range is missing, when the host recorded a reason for it.
   *
   * Section 20 asks eviction to leave *explicit* history-gap cursors. The cursors say what is
   * gone; this says which bound took it, so a person looking at a gap can tell their own
   * session's size from a busy host.
   *
   * It is absent from the wire when the host has no reason recorded, so a gap this host
   * reports is byte for byte what a client built before causes existed expects.
   */
  cause?: HistoryGapCause | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  to_cursor: string
}
/**
 * The record an expired object leaves behind.
 *
 * It outlives a retrust deliberately. Section 9 keeps old expiration tombstones when the wall
 * clock becomes trusted again, which is what stops a clock correction from reviving something
 * that had already run out.
 */
export interface ExpirationTombstone {
  boot_identity: BootIdentity5
  /**
   * Whether the object could still be presented in another boot.
   *
   * An object bounded only by a continuous deadline in one boot is refused in that boot by a
   * clock that only moves forward, and in any other boot by the boot identity its deadline
   * belongs to. Nothing but this record refuses one that also carries a trusted UTC deadline,
   * which is why a host that has to bound its tombstone table can let the first kind go and
   * never the second.
   *
   * A record that does not say defaults to `true`, which is the answer that keeps the
   * tombstone: a host reading back a tombstone from a build that did not record this cannot
   * tell which kind it was, and dropping one it should have kept is the failure that matters.
   */
  cross_reboot?: boolean
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expired_at_ms: string
  /**
   * The object, named the way its own store names it.
   */
  object: string
  /**
   * Why it expired.
   */
  reason: 'continuous_deadline' | 'trusted_utc_deadline'
}
/**
 * The boot the expiry was observed in.
 */
export interface BootIdentity5 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  encrypted_manifest_hash: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  observed_at_ms: string
}
/**
 * The result of any operation that can change geometry ownership.
 */
export interface GeometryResult {
  geometry: GeometryState2
}
/**
 * The geometry after the operation.
 */
export interface GeometryState2 {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
}
/**
 * Who owns the session's rows and columns.
 */
export interface GeometryState3 {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
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
 * Parameters of `grant.create`.
 */
export interface GrantCreateParams {
  /**
   * The notices the issuer states it was shown and accepted.
   *
   * The host computes the notices the grant actually carries and refuses the request when the
   * two sets differ. Section 25 makes a controller's terminal input conditional on the issuer
   * accepting its account-level implications, and a surface that showed a softer set than the
   * grant carries therefore cannot get the grant written.
   */
  accepted_notices: AuthorityNotice[]
  /**
   * How long the invitation lasts. Null takes [`DEFAULT_INVITATION_LIFETIME_MS`].
   */
  lifetime_ms: DurationMs | null
  /**
   * The owner's confirmation, when the request enlarges persistent authority.
   */
  owner_confirmation: OwnerConfirmationProof | null
  /**
   * The grant this one is delegated from. Null issues from the issuer's own authority.
   */
  parent_grant_id: GrantId | null
  /**
   * One paired device.
   */
  recipient_device_id: string
  selection: RoleSelection
  /**
   * One KalaReach terminal session.
   */
  session_id: string
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
 * The role and the explicit choices on top of it.
 */
export interface RoleSelection {
  /**
   * Earlier history, from this cursor. Null keeps the recipient to the live screen and what
   * follows it.
   */
  history_from_cursor_ms: TimestampMs | null
  /**
   * Whether the currently visible screen is included, previewed to the issuer.
   *
   * The exception never reaches inactive screen buffers, scrollback or the backing transcript.
   */
  include_live_screen: boolean
  /**
   * Whether a viewer or reviewer also receives `question.respond`.
   *
   * Ignored for controller and owner, which carry it already.
   */
  include_question_respond: boolean
  /**
   * Current approval requests this invitation names explicitly.
   */
  named_approvals: ApprovalRequestId[]
  /**
   * Current questions this invitation names explicitly.
   */
  named_questions: QuestionId[]
  /**
   * The role the issuer chose.
   */
  role: 'viewer' | 'reviewer' | 'controller' | 'owner'
}
/**
 * The result of `grant.create`.
 */
export interface GrantCreateResult {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  grant: Grant1
  preview: InvitationPreview
}
/**
 * The grant that was written.
 */
export interface Grant1 {
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
 * What the issuer was shown before it was written.
 */
export interface InvitationPreview {
  /**
   * The actions the role compiled to. The host authorises from these, never from the role.
   */
  actions: ActionRight[]
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * Always false. A new recipient receives no historical attachment keys.
   */
  historical_attachment_keys: boolean
  history: HistoryScope1
  /**
   * The invitation this preview belongs to.
   */
  invitation_id: string
  /**
   * The live screen as it stands, when the issuer included it.
   */
  live_screen: LiveScreenPreview | null
  /**
   * The current approval requests this invitation names.
   */
  named_approvals: NamedApprovalPreview[]
  /**
   * The current questions this invitation names.
   */
  named_questions: NamedQuestionPreview[]
  /**
   * The notices the actions carry.
   */
  notices: AuthorityNotice[]
  /**
   * The role the issuer chose.
   */
  role: 'viewer' | 'reviewer' | 'controller' | 'owner'
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * Always true. An invitation is redeemed once.
   */
  single_use: boolean
}
/**
 * The history the recipient will reach.
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
 * The live screen as it stands, shown to the issuer before the invitation exists.
 *
 * A shared live screen can contain text printed long before the invitation, so the preview shows
 * the text rather than promising it is recent.
 */
export interface LiveScreenPreview {
  /**
   * The visible lines, top to bottom, as the recipient would first see them.
   */
  lines: string[]
  /**
   * True when the preview was cut to [`MAX_PREVIEW_LINES`] or [`MAX_PREVIEW_LINE_CHARS`].
   */
  truncated: boolean
}
/**
 * One current approval request an invitation names explicitly.
 */
export interface NamedApprovalPreview {
  /**
   * An upstream approval request identifier. Opaque to KalaReach.
   */
  approval_request_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * What the upstream is asking to do.
   */
  summary: string
}
/**
 * One current question an invitation names explicitly.
 */
export interface NamedQuestionPreview {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * The revision the issuer was shown.
   */
  revision: string
}
/**
 * Parameters of `grant.list`.
 */
export interface GrantListParams {
  /**
   * Whether expired and revoked grants are included.
   */
  include_resolved: boolean
  /**
   * One session, or null for every session the caller may see.
   */
  session_id: SessionId | null
}
/**
 * The result of `grant.list`.
 */
export interface GrantListResult {
  /**
   * The grants, ordered by identity.
   */
  grants: GrantSummary[]
}
/**
 * One grant as `grant.list` reports it.
 */
export interface GrantSummary {
  grant: Grant2
  /**
   * When it was revoked, when it was.
   */
  revoked_at_ms: TimestampMs | null
  /**
   * The grant whose revocation revoked this one, when it was a descendant.
   */
  revoked_by_parent: GrantId | null
  /**
   * Where it stands now.
   */
  state: 'pending' | 'active' | 'expired' | 'revoked'
}
/**
 * The grant itself.
 */
export interface Grant2 {
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
 * Parameters of `grant.revoke`.
 */
export interface GrantRevokeParams {
  /**
   * One host-issued authority object.
   */
  grant_id: string
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
   * One transport connection, allocated by the host during hello.
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
  limits: ReceiveLimits3
  selected_version: ProtocolVersion3
}
/**
 * The negotiated limits.
 */
export interface ReceiveLimits3 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_attachment_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_control_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_input_frame_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_outstanding_mutations: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_send_queue_bytes: string
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion3 {
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
 * Parameters of `history.page`.
 */
export interface HistoryPageParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_bytes: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `history.page`.
 */
export interface HistoryPageResult {
  /**
   * The retained bytes. Raw output is a byte string and need not be valid UTF-8.
   */
  bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * Present when the requested range had been evicted. The page states its gap rather than
   * returning a shorter range as if it were complete.
   */
  gap: HistoryGap | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  next_cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_cursor: string
}
/**
 * The result of `host.doctor`.
 */
export interface HostDoctorResult {
  /**
   * Every check, in the order they ran.
   */
  checks: DoctorCheck[]
  /**
   * True when no check failed.
   */
  healthy: boolean
}
/**
 * One diagnostic check.
 */
export interface DoctorCheck {
  /**
   * A plain description of the finding. Credentials are redacted.
   */
  detail: string
  /**
   * A stable identifier for the check.
   */
  id: string
  /**
   * What the user should do, when the check did not pass.
   */
  remedy: string | null
  /**
   * What it found.
   */
  status: 'ok' | 'warning' | 'failed' | 'not_applicable'
  /**
   * What it examines.
   */
  title: string
}
/**
 * The result of `host.info`.
 */
export interface HostInfoResult {
  boot_identity: BootIdentity6
  /**
   * The controller build.
   */
  build_id: string
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  default_worker_profile: 'desktop_bound' | 'headless_user'
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The controller's current generation. A replacement controller uses a strictly higher one.
   */
  generation: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  live_sessions: string
  power: SleepInhibitionState1
  protocol_version: ProtocolVersion4
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  session_limit: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
}
/**
 * The boot this host is running.
 */
export interface BootIdentity6 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * What this host's sleep inhibition is doing, whether it is active or not.
 */
export interface SleepInhibitionState1 {
  /**
   * Whether an assertion is held right now.
   */
  active: boolean
  /**
   * The name the platform shows for the assertion, so a person can find it in the operating
   * system's own listing.
   */
  holder: string | null
  /**
   * The facility holding it.
   */
  mechanism: 'macos_power_assertion' | 'linux_logind_inhibitor' | 'windows_execution_state' | 'none'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pending_requests: string
  /**
   * What the host is running on.
   */
  power_source: 'mains' | 'battery' | 'unknown'
  /**
   * Why it is held, when it is.
   */
  reason: InhibitionReason | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  sessions_with_work: string
  /**
   * The owner's choice.
   */
  setting: 'off' | 'mains_only' | 'battery_too'
  /**
   * When the current assertion was taken.
   */
  since_ms: TimestampMs | null
  /**
   * Why no assertion is held although the setting is on, when that is the case.
   */
  withheld_reason: string | null
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion4 {
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
 * What a reviewer would see, before the workspace exists.
 *
 * Section 14 requires the create interface to preview what will be included. This is that
 * preview as data: exact counts per class, a bounded sample of paths, and the base the
 * materialisation would start from. It is a read, so it creates nothing and changes nothing.
 */
export interface InclusionPreview {
  /**
   * The change-set version an isolated workspace would materialise, when it names one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The reference that revision was named by, when it was named by one.
   */
  base_reference: string | null
  /**
   * The revision an isolated workspace would start from, as the repository resolved it.
   */
  base_revision: string
  /**
   * One row per class, with exact counts.
   */
  counts: PreviewCount[]
  /**
   * True when every count above is the whole of its class.
   *
   * False when a bound was reached: an ignored directory deeper or larger than the walk
   * covers, or a directory this host could not list. Then each count is a lower bound and the
   * limitations say which bound was reached.
   */
  counts_complete: boolean
  /**
   * A bounded sample of the paths, grouped by class in [`InclusionClass::EVERY`] order.
   */
  entries: PreviewEntry[]
  /**
   * The kind of workspace it was taken for.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * What this preview cannot promise, in the host's own words.
   *
   * A shared workspace is not a sandbox; a worktree shares repository metadata; a working tree
   * can change between the preview and the creation. A client shows this rather than deciding
   * for the user.
   */
  limitations: string[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  omitted_entries: string
  policy: InclusionPolicy
  /**
   * The repository the preview was taken on.
   */
  project_repository_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  taken_at_ms: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  unknown_content: string
}
/**
 * One class's counts in a preview.
 */
export interface PreviewCount {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * The class.
   */
  class: 'dirty_file' | 'untracked_file' | 'submodule' | 'binary_file' | 'generated_artefact'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  included: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  total: string
}
/**
 * One path an inclusion preview names.
 */
export interface PreviewEntry {
  /**
   * Its size in bytes, when the host could read one.
   */
  byte_len: U64 | null
  /**
   * What change the working tree holds for it.
   */
  change: 'present' | 'deleted' | 'unmerged'
  /**
   * Which class it belongs to: where in the working tree it came from.
   */
  class: 'dirty_file' | 'untracked_file' | 'submodule' | 'binary_file' | 'generated_artefact'
  /**
   * What its content is.
   *
   * This cuts across the other classes rather than replacing them: a dirty file may be binary,
   * and a policy that includes dirty files and excludes binaries leaves this one out.
   */
  content: 'text' | 'binary' | 'unknown'
  /**
   * Whether the policy in force would copy it into the new workspace.
   */
  included: boolean
  /**
   * The path, relative to the repository's top level.
   */
  path: string
}
/**
 * The policy it was taken under.
 */
export interface InclusionPolicy {
  /**
   * Files whose content Git reports as binary.
   */
  binary_files: 'include' | 'exclude'
  /**
   * Tracked files with uncommitted modifications.
   */
  dirty_files: 'include' | 'exclude'
  /**
   * Files an ignore rule covers, which is what a build usually produces.
   */
  generated_artefacts: 'include' | 'exclude'
  /**
   * Submodule working trees.
   */
  submodules: 'include' | 'exclude'
  /**
   * Files Git does not track and does not ignore.
   */
  untracked_files: 'include' | 'exclude'
}
/**
 * Parameters of `input.acquire`.
 */
export interface InputAcquireParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The epoch the caller believes is current, when it wants the takeover to be conditional.
   */
  expected_epoch: InputLeaseEpoch | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `input.acquire`.
 */
export interface InputAcquireResult {
  /**
   * True when the worker closed an open bracketed paste before handing input over, so the
   * application never sees a paste completed under a different actor's lease.
   */
  closed_open_paste: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  discarded_bytes: string
  lease: InputLeaseState1
}
/**
 * The lease after the takeover.
 */
export interface InputLeaseState1 {
  /**
   * The connection the holder's ordered input stream belongs to.
   */
  connection_id: ConnectionId | null
  /**
   * The current epoch. A takeover advances it and invalidates the previous one.
   */
  epoch: string
  /**
   * The attachment that currently holds input. Null when no attachment holds it.
   */
  holder: AttachmentId | null
  /**
   * The next input sequence the worker expects on that stream.
   */
  next_sequence: string
}
/**
 * Parameters of `input.interrupt`.
 */
export interface InputInterruptParams {
  /**
   * The action. Only the native interrupt is accepted.
   */
  action: 'native_interrupt'
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The current input lease epoch.
   */
  epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `input.interrupt` and `input.release`.
 */
export interface InputLeaseResult {
  lease: InputLeaseState2
}
/**
 * The lease after the operation.
 */
export interface InputLeaseState2 {
  /**
   * The connection the holder's ordered input stream belongs to.
   */
  connection_id: ConnectionId | null
  /**
   * The current epoch. A takeover advances it and invalidates the previous one.
   */
  epoch: string
  /**
   * The attachment that currently holds input. Null when no attachment holds it.
   */
  holder: AttachmentId | null
  /**
   * The next input sequence the worker expects on that stream.
   */
  next_sequence: string
}
/**
 * The current state of the session's single input lease.
 */
export interface InputLeaseState3 {
  /**
   * The connection the holder's ordered input stream belongs to.
   */
  connection_id: ConnectionId | null
  /**
   * The current epoch. A takeover advances it and invalidates the previous one.
   */
  epoch: string
  /**
   * The attachment that currently holds input. Null when no attachment holds it.
   */
  holder: AttachmentId | null
  /**
   * The next input sequence the worker expects on that stream.
   */
  next_sequence: string
}
/**
 * Parameters of `input.release`.
 */
export interface InputReleaseParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The current input lease epoch.
   */
  epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * Parameters of ordered `input.write`.
 */
export interface InputWriteParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The raw bytes. They are not decoded, re-encoded or normalised.
   */
  bytes: string
  /**
   * The current input lease epoch.
   */
  epoch: string
  /**
   * The position of these bytes in this connection's ordered input stream.
   */
  sequence: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `input.write`.
 */
export interface InputWriteResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  forwarded_bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  held_prefix_bytes: string
  /**
   * The sequence the worker has now consumed.
   */
  sequence: string
}
/**
 * What an invitation will share, shown to its issuer before it exists.
 */
export interface InvitationPreview1 {
  /**
   * The actions the role compiled to. The host authorises from these, never from the role.
   */
  actions: ActionRight[]
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * Always false. A new recipient receives no historical attachment keys.
   */
  historical_attachment_keys: boolean
  history: HistoryScope1
  /**
   * The invitation this preview belongs to.
   */
  invitation_id: string
  /**
   * The live screen as it stands, when the issuer included it.
   */
  live_screen: LiveScreenPreview | null
  /**
   * The current approval requests this invitation names.
   */
  named_approvals: NamedApprovalPreview[]
  /**
   * The current questions this invitation names.
   */
  named_questions: NamedQuestionPreview[]
  /**
   * The notices the actions carry.
   */
  notices: AuthorityNotice[]
  /**
   * The role the issuer chose.
   */
  role: 'viewer' | 'reviewer' | 'controller' | 'owner'
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * Always true. An invitation is redeemed once.
   */
  single_use: boolean
}
/**
 * One log view's retained position and filter.
 *
 * Section 25 keeps a log view's source offsets and filtering state across a reconnect, a switch
 * to another view and a retention eviction. The offset is the source's own cursor, so it survives
 * a client that discards everything it was holding.
 */
export interface LogViewState {
  /**
   * The filter the view had applied, in the client's own form.
   */
  filter: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  source_offset: string
  /**
   * The view, as the client names it.
   */
  view_id: string
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
            | 'review_subject_version'
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
    | 'attention.quiet_hours'
    | 'visit.acknowledge'
    | 'visit.changed'
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
    | 'mailbox.deliver'
    | 'mailbox.acknowledge'
    | 'authority.sync'
    | 'sync.compare_exchange'
    | 'backup.manifest'
    | 'storage.status'
    | 'storage.retention.set'
    | 'storage.upload.create'
    | 'storage.upload.part'
    | 'storage.upload.complete'
    | 'storage.upload.abort'
    | 'storage.object.read'
    | 'storage.object.delete'
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
            | 'voice.use'
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
 * A host owner's bounded offline-validity policy for personal remote access.
 *
 * Section 10 makes this optional and explicit. The default personal owner grant stays
 * account-free and non-expiring, so independent operation never depends on a cloud lease; an
 * owner who wants a bound chooses one, and the host shows the feed status and the last successful
 * synchronisation beside it.
 */
export interface OfflineValidityPolicy {
  /**
   * The last successful synchronisation, when there has been one.
   */
  last_synchronised_at_ms: TimestampMs | null
  /**
   * A duration in milliseconds, as a decimal string in JSON.
   */
  maximum_offline_ms: string
}
/**
 * One repository operation, as a read or a cancellation returns it.
 */
export interface OperationRecord {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The destination's state when the operation was admitted.
   */
  destination_state: 'absent' | 'empty_directory' | 'non_empty_directory' | 'occupied'
  /**
   * Why it ended, when it ended for a reason.
   */
  detail: string | null
  /**
   * When it ended, once it has.
   */
  ended_at_ms: TimestampMs | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * Which method started it.
   */
  method: string
  /**
   * The repository it creates, allocated when the operation begins.
   */
  project_repository_id: string
  /**
   * The remote it reaches, when it reaches one.
   */
  remote: RemoteSpecification | null
  /**
   * The staging paths this host removed.
   */
  removed_staging_paths: string[]
  /**
   * The staging paths that still exist, for a person to find.
   */
  retained_staging_paths: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
  /**
   * What state it is in.
   */
  state: 'staging' | 'publishing' | 'completed' | 'cancelled' | 'failed' | 'expired' | 'unknown'
}
/**
 * A remote a repository operation reaches, and who authenticates it.
 *
 * The URL is here; a credential is not, and there is no field one could travel in. What the host
 * records and what a diagnostic shows is this object, so a credential cannot leak through either.
 */
export interface RemoteSpecification {
  /**
   * The approved credential broker that authenticates it, when the transport needs one.
   *
   * Empty for a transport that needs no credential. A named broker is one the host has, and a
   * name it does not have is refused before anything is executed.
   */
  credential_broker: string
  /**
   * The provider that serves it, as the host resolved it from the host name.
   */
  provider: string
  /**
   * The remote's name inside the repository, conventionally `origin`.
   */
  remote_name: string
  /**
   * The validated transport.
   */
  transport: 'https' | 'ssh' | 'local_path'
  /**
   * The URL, with no user information and no credential.
   */
  url: string
}
/**
 * One organisation's host policy, signed by its policy-signing key.
 *
 * A host that pinned the organisation's policy-signing authority follows the chain to the revision
 * signing now and checks this signature against it, so what a host applies is the organisation's
 * own statement rather than the service's word about it.
 */
export interface OrganisationPolicy {
  payload: OrganisationPolicyPayload
  /**
   * The policy-signing key's signature over [`OrganisationPolicyPayload::signing_input`].
   */
  signature: string
}
/**
 * What the organisation states.
 */
export interface OrganisationPolicyPayload {
  /**
   * The adapters members may run, or null for every adapter the host qualifies.
   */
  adapter_allowlist: PluginId[] | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  audit_retention_days: string
  backup: BackupPolicy
  /**
   * What members' clients may reach outside KalaReach.
   */
  external_providers: 'forbidden' | 'organisation_only' | 'any'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  issued_at_ms: string
  /**
   * The policy-key revision that signed it.
   */
  key_revision: string
  /**
   * The longest a grant issued under this organisation may last, or null for the host's own
   * rule.
   */
  maximum_grant_lifetime_ms: DurationMs | null
  /**
   * The least client version the organisation accepts, or null for any.
   */
  minimum_client_version: ClientVersion | null
  /**
   * The organisation the policy belongs to.
   */
  organisation_id: string
  /**
   * The revision this record establishes. A host refuses one below the revision it holds.
   */
  policy_revision: string
}
/**
 * What the organisation requires of backups.
 */
export interface BackupPolicy {
  /**
   * The recipient every archive is also wrapped for, when the organisation names one.
   */
  recovery_recipient: OrganisationRecoveryRecipient | null
  /**
   * Whether a member's host must keep managed backups.
   */
  required: boolean
}
/**
 * The recipient an organisation's archives are also wrapped for.
 *
 * Organisation recovery is optional and never implicit. A policy that carries this names the
 * public key the recipient is, and a host records its own visible enrolment before any archive is
 * wrapped for it: administering billing or membership gives nobody a content key, and an
 * organisation with no named recipient and no enrolment cannot decrypt a personal archive at all.
 */
export interface OrganisationRecoveryRecipient {
  /**
   * A display name for the recipient, so an enrolment can be shown for what it is.
   */
  name: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  named_at_ms: string
  /**
   * The recipient's X25519 public key. Only its public half ever exists in the service.
   */
  recipient_key: string
  /**
   * The recipient's stored-envelope key identifier.
   */
  recipient_key_id: string
}
/**
 * One batch of output bytes on the output stream.
 */
export interface OutputEvent {
  /**
   * The bytes.
   */
  bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cursor: string
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  client_bundle_hash: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  host_bundle_hash: string
  /**
   * The invitation.
   */
  invitation_id: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  transcript: string
}
/**
 * The parameters of `pair.status`.
 *
 * The invitation is named; the candidate is not, and cannot be. The host answers about the
 * attempt the *authenticated endpoint* of this connection is party to, so a caller cannot ask
 * about another candidate's attempt by naming it.
 */
export interface PairStatusParams {
  /**
   * The invitation the candidate is party to.
   */
  invitation_id: string
}
/**
 * The result of `pair.status`.
 */
export interface PairStatusResult {
  /**
   * What the invitation is doing.
   */
  status:
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
 * Parameters of `project.adopt`.
 */
export interface ProjectAdoptParams {
  destination: DestinationRequest
  /**
   * The flow the user explicitly chose.
   *
   * There is no default. A destination that already exists is refused unless this names a flow,
   * which is what section 14 requires.
   */
  flow: 'existing_checkout'
  /**
   * The label the user gave it.
   */
  label: string
}
/**
 * The checkout to adopt, named the same way a destination is.
 */
export interface DestinationRequest {
  /**
   * The environment the repository will belong to.
   */
  environment_id: string
  /**
   * The single name inside it. No separators, no traversal segment, no reserved device name.
   */
  name: string
  /**
   * The parent directory, as an absolute host path the caller chose.
   */
  parent_path: string
}
/**
 * Result of `project.adopt`.
 */
export interface ProjectAdoptResult {
  operation: OperationRecord1
  project: ProjectSummary
}
/**
 * The operation that registered it.
 */
export interface OperationRecord1 {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The destination's state when the operation was admitted.
   */
  destination_state: 'absent' | 'empty_directory' | 'non_empty_directory' | 'occupied'
  /**
   * Why it ended, when it ended for a reason.
   */
  detail: string | null
  /**
   * When it ended, once it has.
   */
  ended_at_ms: TimestampMs | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * Which method started it.
   */
  method: string
  /**
   * The repository it creates, allocated when the operation begins.
   */
  project_repository_id: string
  /**
   * The remote it reaches, when it reaches one.
   */
  remote: RemoteSpecification | null
  /**
   * The staging paths this host removed.
   */
  removed_staging_paths: string[]
  /**
   * The staging paths that still exist, for a person to find.
   */
  retained_staging_paths: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
  /**
   * What state it is in.
   */
  state: 'staging' | 'publishing' | 'completed' | 'cancelled' | 'failed' | 'expired' | 'unknown'
}
/**
 * The repository that is now known here.
 */
export interface ProjectSummary {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The path it was created or adopted at, for a person to read.
   *
   * Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
   * which is why every operation uses the recorded identity and an opened handle instead.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  filesystem_identity: FilesystemIdentity
  /**
   * The label the user gave it.
   */
  label: string
  /**
   * How it came to be known here.
   */
  origin: 'initialised' | 'cloned' | 'adopted'
  /**
   * Its environment-local identity.
   */
  project_repository_id: string
  /**
   * The remote it was cloned from, when it has one.
   */
  remote: RemoteSpecification | null
  /**
   * What state the record is in.
   */
  state: 'ready' | 'creating' | 'detached'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  workspace_count: string
}
/**
 * The stable filesystem identity of its Git directory.
 */
export interface FilesystemIdentity {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  device: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  file_id: string
}
/**
 * Parameters of `project.clone`.
 */
export interface ProjectCloneParams {
  destination: DestinationRequest1
  /**
   * The label the user gave it.
   */
  label: string
  remote: RemoteSpecification1
}
/**
 * Where the clone goes.
 */
export interface DestinationRequest1 {
  /**
   * The environment the repository will belong to.
   */
  environment_id: string
  /**
   * The single name inside it. No separators, no traversal segment, no reserved device name.
   */
  name: string
  /**
   * The parent directory, as an absolute host path the caller chose.
   */
  parent_path: string
}
/**
 * A remote a repository operation reaches, and who authenticates it.
 *
 * The URL is here; a credential is not, and there is no field one could travel in. What the host
 * records and what a diagnostic shows is this object, so a credential cannot leak through either.
 */
export interface RemoteSpecification1 {
  /**
   * The approved credential broker that authenticates it, when the transport needs one.
   *
   * Empty for a transport that needs no credential. A named broker is one the host has, and a
   * name it does not have is refused before anything is executed.
   */
  credential_broker: string
  /**
   * The provider that serves it, as the host resolved it from the host name.
   */
  provider: string
  /**
   * The remote's name inside the repository, conventionally `origin`.
   */
  remote_name: string
  /**
   * The validated transport.
   */
  transport: 'https' | 'ssh' | 'local_path'
  /**
   * The URL, with no user information and no credential.
   */
  url: string
}
/**
 * Result of `project.clone`.
 */
export interface ProjectCloneResult {
  operation: OperationRecord2
  project: ProjectSummary1
}
/**
 * The operation that created it.
 */
export interface OperationRecord2 {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The destination's state when the operation was admitted.
   */
  destination_state: 'absent' | 'empty_directory' | 'non_empty_directory' | 'occupied'
  /**
   * Why it ended, when it ended for a reason.
   */
  detail: string | null
  /**
   * When it ended, once it has.
   */
  ended_at_ms: TimestampMs | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * Which method started it.
   */
  method: string
  /**
   * The repository it creates, allocated when the operation begins.
   */
  project_repository_id: string
  /**
   * The remote it reaches, when it reaches one.
   */
  remote: RemoteSpecification | null
  /**
   * The staging paths this host removed.
   */
  removed_staging_paths: string[]
  /**
   * The staging paths that still exist, for a person to find.
   */
  retained_staging_paths: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
  /**
   * What state it is in.
   */
  state: 'staging' | 'publishing' | 'completed' | 'cancelled' | 'failed' | 'expired' | 'unknown'
}
/**
 * The repository that now exists.
 */
export interface ProjectSummary1 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The path it was created or adopted at, for a person to read.
   *
   * Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
   * which is why every operation uses the recorded identity and an opened handle instead.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  filesystem_identity: FilesystemIdentity
  /**
   * The label the user gave it.
   */
  label: string
  /**
   * How it came to be known here.
   */
  origin: 'initialised' | 'cloned' | 'adopted'
  /**
   * Its environment-local identity.
   */
  project_repository_id: string
  /**
   * The remote it was cloned from, when it has one.
   */
  remote: RemoteSpecification | null
  /**
   * What state the record is in.
   */
  state: 'ready' | 'creating' | 'detached'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  workspace_count: string
}
/**
 * Parameters of `project.init`.
 */
export interface ProjectInitParams {
  destination: DestinationRequest2
  /**
   * The name of the initial branch, when the user chose one.
   */
  initial_branch: string | null
  /**
   * The label the user gave it.
   */
  label: string
}
/**
 * Where the repository goes.
 */
export interface DestinationRequest2 {
  /**
   * The environment the repository will belong to.
   */
  environment_id: string
  /**
   * The single name inside it. No separators, no traversal segment, no reserved device name.
   */
  name: string
  /**
   * The parent directory, as an absolute host path the caller chose.
   */
  parent_path: string
}
/**
 * Result of `project.init`.
 */
export interface ProjectInitResult {
  operation: OperationRecord3
  project: ProjectSummary2
}
/**
 * The operation that created it.
 */
export interface OperationRecord3 {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The destination's state when the operation was admitted.
   */
  destination_state: 'absent' | 'empty_directory' | 'non_empty_directory' | 'occupied'
  /**
   * Why it ended, when it ended for a reason.
   */
  detail: string | null
  /**
   * When it ended, once it has.
   */
  ended_at_ms: TimestampMs | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * Which method started it.
   */
  method: string
  /**
   * The repository it creates, allocated when the operation begins.
   */
  project_repository_id: string
  /**
   * The remote it reaches, when it reaches one.
   */
  remote: RemoteSpecification | null
  /**
   * The staging paths this host removed.
   */
  removed_staging_paths: string[]
  /**
   * The staging paths that still exist, for a person to find.
   */
  retained_staging_paths: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
  /**
   * What state it is in.
   */
  state: 'staging' | 'publishing' | 'completed' | 'cancelled' | 'failed' | 'expired' | 'unknown'
}
/**
 * The repository that now exists.
 */
export interface ProjectSummary2 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The path it was created or adopted at, for a person to read.
   *
   * Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
   * which is why every operation uses the recorded identity and an opened handle instead.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  filesystem_identity: FilesystemIdentity
  /**
   * The label the user gave it.
   */
  label: string
  /**
   * How it came to be known here.
   */
  origin: 'initialised' | 'cloned' | 'adopted'
  /**
   * Its environment-local identity.
   */
  project_repository_id: string
  /**
   * The remote it was cloned from, when it has one.
   */
  remote: RemoteSpecification | null
  /**
   * What state the record is in.
   */
  state: 'ready' | 'creating' | 'detached'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  workspace_count: string
}
/**
 * Parameters of `project.list`.
 */
export interface ProjectListParams {
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
}
/**
 * Result of `project.list`.
 */
export interface ProjectListResult {
  /**
   * The repositories, oldest first.
   */
  projects: ProjectSummary3[]
}
/**
 * One repository, as a scoped read returns it.
 */
export interface ProjectSummary3 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The path it was created or adopted at, for a person to read.
   *
   * Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
   * which is why every operation uses the recorded identity and an opened handle instead.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  filesystem_identity: FilesystemIdentity
  /**
   * The label the user gave it.
   */
  label: string
  /**
   * How it came to be known here.
   */
  origin: 'initialised' | 'cloned' | 'adopted'
  /**
   * Its environment-local identity.
   */
  project_repository_id: string
  /**
   * The remote it was cloned from, when it has one.
   */
  remote: RemoteSpecification | null
  /**
   * What state the record is in.
   */
  state: 'ready' | 'creating' | 'detached'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  workspace_count: string
}
/**
 * Parameters of `project.operation.cancel`.
 */
export interface ProjectOperationCancelParams {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  operation_action_id: string
}
/**
 * Result of `project.operation.cancel`.
 */
export interface ProjectOperationCancelResult {
  operation: OperationRecord4
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  stopped_processes: string
}
/**
 * The operation, with its retained and removed staging paths.
 */
export interface OperationRecord4 {
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The destination's state when the operation was admitted.
   */
  destination_state: 'absent' | 'empty_directory' | 'non_empty_directory' | 'occupied'
  /**
   * Why it ended, when it ended for a reason.
   */
  detail: string | null
  /**
   * When it ended, once it has.
   */
  ended_at_ms: TimestampMs | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * Which method started it.
   */
  method: string
  /**
   * The repository it creates, allocated when the operation begins.
   */
  project_repository_id: string
  /**
   * The remote it reaches, when it reaches one.
   */
  remote: RemoteSpecification | null
  /**
   * The staging paths this host removed.
   */
  removed_staging_paths: string[]
  /**
   * The staging paths that still exist, for a person to find.
   */
  retained_staging_paths: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
  /**
   * What state it is in.
   */
  state: 'staging' | 'publishing' | 'completed' | 'cancelled' | 'failed' | 'expired' | 'unknown'
}
/**
 * Parameters of `project.read`.
 */
export interface ProjectReadParams {
  /**
   * The repository to read.
   */
  project_repository_id: string
}
/**
 * Result of `project.read`.
 */
export interface ProjectReadResult {
  /**
   * The operation that created it, when this host still has the record.
   */
  operation: OperationRecord | null
  project: ProjectSummary4
  /**
   * Its workspaces.
   */
  workspaces: WorkspaceSummary[]
}
/**
 * One repository, as a scoped read returns it.
 */
export interface ProjectSummary4 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The path it was created or adopted at, for a person to read.
   *
   * Diagnostics only. Re-resolving it would let a rename hand a grant to an unrelated tree,
   * which is why every operation uses the recorded identity and an opened handle instead.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  filesystem_identity: FilesystemIdentity
  /**
   * The label the user gave it.
   */
  label: string
  /**
   * How it came to be known here.
   */
  origin: 'initialised' | 'cloned' | 'adopted'
  /**
   * Its environment-local identity.
   */
  project_repository_id: string
  /**
   * The remote it was cloned from, when it has one.
   */
  remote: RemoteSpecification | null
  /**
   * What state the record is in.
   */
  state: 'ready' | 'creating' | 'detached'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  workspace_count: string
}
/**
 * One workspace, as a scoped read returns it.
 */
export interface WorkspaceSummary {
  /**
   * The change-set version it materialised, when it named one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The revision it started from.
   */
  base_revision: string
  /**
   * The automation runs bound to it that are still live.
   *
   * Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
   * between two sessions or after its last one ended, so it is recorded separately and refuses
   * a removal in the same way.
   */
  bound_runs: WorkflowRunId[]
  /**
   * The sessions bound to it that are still live.
   *
   * A removal is refused while this is not empty, whatever retention policy it carries.
   */
  bound_sessions: SessionId[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * Why it is in the state it is in, when it ended up there for a reason.
   */
  detail: string | null
  /**
   * The path it was created at, for a person to read.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The stable filesystem identity of its working tree, once this host has one.
   *
   * Absent while the workspace is being materialised, and absent afterwards only when the
   * materialisation did not get as far as creating the tree. An absent identity is what refuses
   * a removal: this host does not delete a directory it cannot prove it created.
   */
  filesystem_identity: FilesystemIdentity1 | null
  /**
   * How an isolated workspace is separated, when it is one.
   */
  isolation: IsolationMechanism | null
  /**
   * Which kind it is.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * The label the user gave it.
   */
  label: string
  policy: InclusionPolicy1
  /**
   * The repository it is a working copy of.
   */
  project_repository_id: string
  /**
   * What it holds that a removal would have to account for.
   */
  retained: RetainedItem[]
  /**
   * What state it is in.
   */
  state: 'ready' | 'materialising' | 'removal_pending' | 'removed'
  /**
   * Its identity.
   */
  workspace_id: string
}
/**
 * A repository's stable environment-local identity, as a client may show it.
 *
 * The two numbers are the device and the object number of the Git directory: the inode on Unix
 * and the file index on Windows. They are metadata a client can display and compare; they are
 * never an authority, because authority is the opened handle the host holds.
 */
export interface FilesystemIdentity1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  device: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  file_id: string
}
/**
 * The inclusion policy it was created under.
 */
export interface InclusionPolicy1 {
  /**
   * Files whose content Git reports as binary.
   */
  binary_files: 'include' | 'exclude'
  /**
   * Tracked files with uncommitted modifications.
   */
  dirty_files: 'include' | 'exclude'
  /**
   * Files an ignore rule covers, which is what a build usually produces.
   */
  generated_artefacts: 'include' | 'exclude'
  /**
   * Submodule working trees.
   */
  submodules: 'include' | 'exclude'
  /**
   * Files Git does not track and does not ignore.
   */
  untracked_files: 'include' | 'exclude'
}
/**
 * One thing a workspace holds that its removal would have to account for.
 */
export interface RetainedItem {
  /**
   * The change set it belongs to, when it belongs to one.
   */
  change_set_id: ChangeSetId | null
  /**
   * What it is, in the host's own words.
   */
  detail: string
  /**
   * What kind of thing it is.
   */
  kind: 'dirty_content' | 'pinned_change_set' | 'review_evidence'
}
/**
 * A bounded update against a known base.
 *
 * This is what a projected attachment receives per batch of output: the rows that changed and the
 * state that changed with them, never the whole screen.
 */
export interface ProjectionDelta {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  base_cursor: string
  /**
   * Which buffer the rows belong to.
   */
  buffer: 'primary' | 'alternate'
  /**
   * The designated character sets, when they changed.
   */
  charsets: CharsetState | null
  cursor: ProjectedCursor
  /**
   * Whether the session has had to shorten content to stay inside a resident-state bound.
   */
  degraded: boolean
  /**
   * The canonical dimensions, when they changed.
   */
  dimensions: Dimensions | null
  /**
   * Whether rows below `oldest_retained_row` have been evicted.
   */
  evicted: boolean
  /**
   * The open hyperlink, when it changed.
   */
  hyperlink: HyperlinkChange | null
  /**
   * The hyperlink ranges of the rows carried here.
   */
  hyperlinks: HyperlinkRange[]
  /**
   * The keyboard negotiation, when it changed.
   */
  keyboard: ProjectedKeyboard | null
  /**
   * The scroll region, when it changed.
   */
  margins: MarginState | null
  /**
   * The modes that changed since the base.
   */
  modes: ProjectedMode[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  next_cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_row: string
  /**
   * The palette, when an authorised explicit change moved it.
   */
  palette: PaletteState | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  projection_generation: string
  /**
   * The pen, when it changed.
   */
  rendition: CellRendition | null
  /**
   * The rows that changed, by stable identifier. A row not named here is unchanged.
   */
  rows: ProjectedRow[]
  /**
   * The saved cursors, when one was saved or restored.
   */
  saved_cursors: SavedCursorState[] | null
  /**
   * The tab stops, when they changed.
   */
  tab_stops: U64[] | null
  /**
   * The titles, when they changed.
   */
  title: ProjectedTitle | null
  /**
   * The virtual title stack, when the titles changed.
   */
  title_stack: SavedTitleEntry[] | null
  viewport: ProjectedViewport
}
/**
 * The designated character sets and the locking shift.
 */
export interface CharsetState {
  /**
   * The set designated as G0.
   */
  g0: string
  /**
   * The set designated as G1.
   */
  g1: string
  /**
   * Whether the shift-out set is selected.
   */
  shift_out: boolean
}
/**
 * The cursor after the update.
 */
export interface ProjectedCursor {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  column: string
  /**
   * Whether the next printable character wraps before it is placed.
   *
   * The same coordinates mean different things with and without it, so a renderer that left it
   * out would put the next character in the wrong cell.
   */
  pending_wrap: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  style: string
  /**
   * Whether the cursor is shown.
   */
  visible: boolean
}
/**
 * The hyperlink the next character printed belongs to, once it has changed.
 *
 * A null target is an open link that closed. Without the distinction a client could not tell a
 * link that closed from one that was never mentioned.
 */
export interface HyperlinkChange {
  /**
   * The target, or null when no link is open.
   */
  uri: string | null
}
/**
 * A hyperlink over a range of cells.
 *
 * It is inert metadata. A reconnection restores it so a later click still works; nothing here
 * activates anything, and a scheme that would launch an external application needs the client's
 * own policy before anything happens.
 */
export interface HyperlinkRange {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  end_column: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_column: string
  /**
   * The target.
   */
  uri: string
}
/**
 * The keyboard negotiation an input encoder has to reproduce.
 *
 * Each buffer has its own stack, so a full-screen application's negotiation cannot leak into the
 * shell's when it exits. A client that knew only the active one would send the wrong encoding the
 * moment the application quit.
 */
export interface ProjectedKeyboard {
  alternate: KittyKeyboardState
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  modify_other_keys: string
  primary: KittyKeyboardState1
}
/**
 * The alternate buffer's negotiation.
 */
export interface KittyKeyboardState {
  /**
   * The flags in force, when the protocol is in use.
   */
  flags: U64 | null
  /**
   * The flag stack, oldest first.
   */
  stack: U64[]
}
/**
 * The primary buffer's negotiation.
 */
export interface KittyKeyboardState1 {
  /**
   * The flags in force, when the protocol is in use.
   */
  flags: U64 | null
  /**
   * The flag stack, oldest first.
   */
  stack: U64[]
}
/**
 * The scroll region.
 */
export interface MarginState {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  bottom: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  left: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  right: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  top: string
}
/**
 * One tracked mode and its value.
 */
export interface ProjectedMode {
  /**
   * Whether it is set.
   */
  enabled: boolean
  /**
   * Which spelling.
   */
  kind: 'ansi' | 'dec'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  mode: string
}
/**
 * The session's canonical palette and where it came from.
 */
export interface PaletteState {
  background: Rgb2
  cursor: Rgb3
  foreground: Rgb4
  /**
   * The indexed colours that differ from the profile default.
   */
  overrides: PaletteOverride[]
  pointer_background: Rgb6
  pointer_foreground: Rgb7
  selection_background: Rgb8
  selection_foreground: Rgb9
  /**
   * Where this palette came from.
   */
  source:
    'profile_default' | 'client_preference' | 'light_preset' | 'dark_preset' | 'explicit_change'
}
/**
 * A direct colour.
 */
export interface Rgb2 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb3 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb4 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * One indexed colour that differs from the profile default.
 */
export interface PaletteOverride {
  colour: Rgb5
  /**
   * The palette index.
   */
  index: number
}
/**
 * A direct colour.
 */
export interface Rgb5 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb6 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb7 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb8 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * A direct colour.
 */
export interface Rgb9 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * The graphic rendition of a run of cells.
 */
export interface CellRendition {
  /**
   * The cell colour.
   */
  background:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The blink rate.
   */
  blink: 'none' | 'slow' | 'rapid'
  /**
   * Bold.
   */
  bold: boolean
  /**
   * Faint.
   */
  faint: boolean
  /**
   * The text colour.
   */
  foreground:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * Invisible.
   */
  invisible: boolean
  /**
   * Italic.
   */
  italic: boolean
  /**
   * Overlined.
   */
  overline: boolean
  /**
   * Reverse video.
   */
  reverse: boolean
  /**
   * Struck through.
   */
  strikethrough: boolean
  /**
   * The underline style.
   */
  underline: 'none' | 'single' | 'double' | 'curly' | 'dotted' | 'dashed'
  /**
   * The underline colour, where it differs from the text.
   */
  underline_colour:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The position against the baseline.
   */
  vertical_align: 'baseline' | 'superscript' | 'subscript'
}
/**
 * A direct colour.
 */
export interface Rgb10 {
  /**
   * Blue.
   */
  blue: number
  /**
   * Green.
   */
  green: number
  /**
   * Red.
   */
  red: number
}
/**
 * One row of the canonical grid.
 */
export interface ProjectedRow {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  row: string
  /**
   * The runs, left to right.
   */
  runs: CellRun[]
  /**
   * Whether the row ends in a soft wrap rather than a hard line break.
   *
   * A selection that copies two soft-wrapped rows copies one logical line, which is why the
   * marker travels with the row instead of being inferred from its length.
   */
  soft_wrapped: boolean
  /**
   * Whether runs were dropped to keep the row inside a page's byte bound.
   *
   * The degradation is explicit: a client shows what it was given and knows it is not all of
   * the row, rather than drawing a short row as though the application had written one.
   */
  truncated: boolean
}
/**
 * One run of cells that share a rendition and a hyperlink.
 */
export interface CellRun {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cells: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  column: string
  /**
   * The hyperlink this run is inside, as inert metadata.
   */
  hyperlink: string | null
  rendition: CellRendition1
  /**
   * The text.
   */
  text: string
}
/**
 * The rendition.
 */
export interface CellRendition1 {
  /**
   * The cell colour.
   */
  background:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The blink rate.
   */
  blink: 'none' | 'slow' | 'rapid'
  /**
   * Bold.
   */
  bold: boolean
  /**
   * Faint.
   */
  faint: boolean
  /**
   * The text colour.
   */
  foreground:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * Invisible.
   */
  invisible: boolean
  /**
   * Italic.
   */
  italic: boolean
  /**
   * Overlined.
   */
  overline: boolean
  /**
   * Reverse video.
   */
  reverse: boolean
  /**
   * Struck through.
   */
  strikethrough: boolean
  /**
   * The underline style.
   */
  underline: 'none' | 'single' | 'double' | 'curly' | 'dotted' | 'dashed'
  /**
   * The underline colour, where it differs from the text.
   */
  underline_colour:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The position against the baseline.
   */
  vertical_align: 'baseline' | 'superscript' | 'subscript'
}
/**
 * A cursor an application saved, with the pen it saved alongside it.
 */
export interface SavedCursorState {
  /**
   * Which buffer saved it.
   */
  buffer: 'primary' | 'alternate'
  charsets: CharsetDesignations
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  column: string
  /**
   * The hyperlink that was open when it was saved.
   */
  hyperlink: string | null
  /**
   * Whether origin mode was set when it was saved.
   */
  origin_mode: boolean
  /**
   * Whether the saved cursor had a pending wrap.
   */
  pending_wrap: boolean
  rendition: CellRendition2
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  style: string
}
/**
 * The character sets designated when it was saved.
 */
export interface CharsetDesignations {
  /**
   * The set designated as G0.
   */
  g0: string
  /**
   * The set designated as G1.
   */
  g1: string
}
/**
 * The graphic rendition of a run of cells.
 */
export interface CellRendition2 {
  /**
   * The cell colour.
   */
  background:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The blink rate.
   */
  blink: 'none' | 'slow' | 'rapid'
  /**
   * Bold.
   */
  bold: boolean
  /**
   * Faint.
   */
  faint: boolean
  /**
   * The text colour.
   */
  foreground:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * Invisible.
   */
  invisible: boolean
  /**
   * Italic.
   */
  italic: boolean
  /**
   * Overlined.
   */
  overline: boolean
  /**
   * Reverse video.
   */
  reverse: boolean
  /**
   * Struck through.
   */
  strikethrough: boolean
  /**
   * The underline style.
   */
  underline: 'none' | 'single' | 'double' | 'curly' | 'dotted' | 'dashed'
  /**
   * The underline colour, where it differs from the text.
   */
  underline_colour:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The position against the baseline.
   */
  vertical_align: 'baseline' | 'superscript' | 'subscript'
}
/**
 * The current titles.
 */
export interface ProjectedTitle {
  /**
   * The icon title.
   */
  icon: string
  /**
   * The window title.
   */
  window: string
}
/**
 * One entry of the virtual title stack.
 *
 * A push saves only the titles it names, so each field is either a title that was saved or
 * nothing at all. The two are different: a pop leaves the current title alone where nothing was
 * saved for it, and a client that flattened the distinction would show the wrong title after one.
 */
export interface SavedTitleEntry {
  /**
   * The icon title, when this entry saved one.
   */
  icon: string | null
  /**
   * The window title, when this entry saved one.
   */
  window: string | null
}
/**
 * The window this client is showing, which a scroll moves without changing any row.
 */
export interface ProjectedViewport {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  left_column: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  screen_top_row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  top_row: string
}
/**
 * Discard whatever is being shown; a snapshot follows.
 */
export interface ProjectionReset {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  projection_generation: string
  /**
   * Why.
   */
  reason: 'attached' | 'buffer_switch' | 'geometry' | 'replay_gap' | 'repaint' | 'history_evicted'
}
/**
 * One page of rows belonging to one buffer of one snapshot.
 */
export interface ProjectionRowPage {
  /**
   * Which buffer they belong to.
   */
  buffer: 'primary' | 'alternate'
  /**
   * Whether rows below `oldest_retained_row` have been evicted.
   */
  evicted: boolean
  /**
   * Whether more pages of this snapshot follow.
   *
   * A client that has not seen a page with this clear does not yet hold the whole screen, and
   * section 8 forbids mixing live output with an incomplete repaint.
   */
  more: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  output_cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  projection_generation: string
  /**
   * The rows, in stable-identifier order.
   */
  rows: ProjectedRow[]
}
/**
 * Everything a screen is, apart from its rows.
 *
 * The rows follow in [`ProjectionRowPage`]s, because a canonical grid of 2,048 columns by 1,024
 * rows in two buffers is not one message. A client installs the state here, paints the pages as
 * they arrive, and applies deltas from `output_cursor` once the last page has landed.
 */
export interface ProjectionSnapshot {
  /**
   * Which buffer is active.
   */
  active_buffer: 'primary' | 'alternate'
  charsets: CharsetState1
  cursor: ProjectedCursor1
  /**
   * Whether the session has had to shorten content to stay inside a resident-state bound.
   *
   * Section 8 requires truncation to have an explicit projection degradation, and a client in
   * projected mode cannot see it any other way: a cell whose combining marks were dropped at
   * the per-cell bound, a title cut to its limit and a hyperlink the link table refused all
   * arrive looking like content the application wrote. This says they do not.
   */
  degraded: boolean
  dimensions: Dimensions5
  /**
   * Whether rows below `oldest_retained_row` have been evicted.
   */
  evicted: boolean
  /**
   * The hyperlink the next character printed belongs to.
   */
  hyperlink: string | null
  keyboard: ProjectedKeyboard1
  /**
   * Whether the keypad is in application mode.
   */
  keypad_application: boolean
  margins: MarginState1
  /**
   * Every tracked mode.
   */
  modes: ProjectedMode[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  output_cursor: string
  palette: PaletteState1
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  projection_generation: string
  rendition: CellRendition3
  /**
   * The cursor each buffer has saved.
   */
  saved_cursors: SavedCursorState[]
  /**
   * The columns carrying a tab stop.
   */
  tab_stops: U64[]
  title: ProjectedTitle1
  /**
   * The virtual title stack, oldest first.
   */
  title_stack: SavedTitleEntry[]
  viewport: ProjectedViewport1
}
/**
 * The designated character sets and the locking shift.
 */
export interface CharsetState1 {
  /**
   * The set designated as G0.
   */
  g0: string
  /**
   * The set designated as G1.
   */
  g1: string
  /**
   * Whether the shift-out set is selected.
   */
  shift_out: boolean
}
/**
 * The cursor.
 */
export interface ProjectedCursor1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  column: string
  /**
   * Whether the next printable character wraps before it is placed.
   *
   * The same coordinates mean different things with and without it, so a renderer that left it
   * out would put the next character in the wrong cell.
   */
  pending_wrap: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  style: string
  /**
   * Whether the cursor is shown.
   */
  visible: boolean
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions5 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * The keyboard negotiation an input encoder has to reproduce.
 *
 * Each buffer has its own stack, so a full-screen application's negotiation cannot leak into the
 * shell's when it exits. A client that knew only the active one would send the wrong encoding the
 * moment the application quit.
 */
export interface ProjectedKeyboard1 {
  alternate: KittyKeyboardState
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  modify_other_keys: string
  primary: KittyKeyboardState1
}
/**
 * The scroll region.
 */
export interface MarginState1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  bottom: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  left: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  right: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  top: string
}
/**
 * The session's canonical palette and where it came from.
 */
export interface PaletteState1 {
  background: Rgb2
  cursor: Rgb3
  foreground: Rgb4
  /**
   * The indexed colours that differ from the profile default.
   */
  overrides: PaletteOverride[]
  pointer_background: Rgb6
  pointer_foreground: Rgb7
  selection_background: Rgb8
  selection_foreground: Rgb9
  /**
   * Where this palette came from.
   */
  source:
    'profile_default' | 'client_preference' | 'light_preset' | 'dark_preset' | 'explicit_change'
}
/**
 * The graphic rendition of a run of cells.
 */
export interface CellRendition3 {
  /**
   * The cell colour.
   */
  background:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The blink rate.
   */
  blink: 'none' | 'slow' | 'rapid'
  /**
   * Bold.
   */
  bold: boolean
  /**
   * Faint.
   */
  faint: boolean
  /**
   * The text colour.
   */
  foreground:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * Invisible.
   */
  invisible: boolean
  /**
   * Italic.
   */
  italic: boolean
  /**
   * Overlined.
   */
  overline: boolean
  /**
   * Reverse video.
   */
  reverse: boolean
  /**
   * Struck through.
   */
  strikethrough: boolean
  /**
   * The underline style.
   */
  underline: 'none' | 'single' | 'double' | 'curly' | 'dotted' | 'dashed'
  /**
   * The underline colour, where it differs from the text.
   */
  underline_colour:
    | 'default'
    | {
        indexed: number
      }
    | {
        direct: Rgb10
      }
  /**
   * The position against the baseline.
   */
  vertical_align: 'baseline' | 'superscript' | 'subscript'
}
/**
 * The current titles.
 */
export interface ProjectedTitle1 {
  /**
   * The icon title.
   */
  icon: string
  /**
   * The window title.
   */
  window: string
}
/**
 * The window this client is showing.
 */
export interface ProjectedViewport1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  left_column: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  screen_top_row: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  top_row: string
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
  history: HistoryScope2
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
export interface HistoryScope2 {
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
  state:
    | 'queued'
    | 'retrying'
    | 'collapsed'
    | 'duplicate'
    | 'token_disabled'
    | 'refused'
    | 'revoked'
    | 'abandoned'
    | 'expired'
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  suppressed_count: string
}
/**
 * The bearer a host presents to deliver, and what it is bound to.
 *
 * At issue it goes to the installation, which passes it to the host through the paired encrypted
 * channel: the installation is the one authorising, so the first credential travels the way the
 * authorisation does. At renewal it goes straight to the host, in the answer to the renewal the
 * host itself proved, which is what makes renewal work while the phone is asleep or unreachable.
 *
 * It grants delivery to one destination and nothing else: it is not a session, it reads nothing,
 * and it cannot be presented to any other method.
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
 * delivered has already been recorded somewhere the person can find it.
 *
 * Nothing here is a field for plaintext that describes the work. The alert comes from a closed
 * vocabulary, the two identifiers are 128-bit values rather than text, and the preview is a sealed
 * envelope whose shape [`PushDeliveryRequest::preview_is_well_formed`] checks. Those are the
 * checks a gateway can make. What they do not do is inspect a producer: a host that put meaning
 * into its own identifiers, or sealed the wrong thing, has disclosed it to the provider and to the
 * gateway. Keeping the identifiers meaningless and the preview correctly sealed is the producer's
 * obligation, and section 16 places it there.
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
   * The sealed preview, or null when the destination has previews disabled.
   *
   * It is a [`SealedEnvelope`], not opaque bytes, so the gateway can check the shape of what it
   * is forwarding without holding a key that opens it: that the envelope expires when the
   * notification does, and that its ciphertext is a padded plaintext of a notification-sized
   * bucket rather than an arbitrary payload. [`PushDeliveryRequest::preview_is_well_formed`] is
   * that check.
   */
  preview: SealedEnvelope | null
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
 * One envelope sealed for one recipient.
 */
export interface SealedEnvelope {
  /**
   * The `crypto_box_easy` output over the canonical plaintext.
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
   * What the payload is.
   *
   * The service is told the kind so that it can refuse a kind the mailbox does not carry, which
   * is section 9's rule that it queues no keystroke, command, decision or closure. It learns the
   * kind and nothing about the payload; the recipient checks the declaration against the kind
   * the box authenticated and drops the item when the two differ.
   */
  payload_type:
    | 'authority_feed_change'
    | 'action_receipt'
    | 'state_reference'
    | 'signed_authority_object'
    | 'notification_preview'
    | 'sync_change'
  /**
   * The recipient the service delivers to.
   */
  recipient_key_id: string
  /**
   * The sender, so a recipient can select a paired sender key before attempting to open.
   */
  sender_key_id: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  size_bucket_bytes: string
  /**
   * The thread the item coalesces in, when the sender asks for coalescing.
   *
   * Null means the item stands on its own and nothing replaces it. A value is opaque: the
   * service compares it and never derives anything from it.
   */
  thread_id: MailboxThreadId | null
}
/**
 * The canonical active binding of one provider token to one installation.
 *
 * There is exactly one of these per token digest. That is what stops an installation from
 * registering the same token under a second identity to start its rate history again: a second
 * identity for one token is not an additional binding, it is a replacement, and a replacement has
 * to pass its own challenge. The rate history stays with the digest through that replacement, so
 * the alias gains nothing.
 *
 * The token itself is not here. The gateway keeps it where it keeps its own secrets, because it
 * needs the token to deliver; what travels in a record is the digest.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  token_digest: string
}
/**
 * The token and the identity proposed for it.
 */
export interface PushRegistrationProposal {
  /**
   * The public key the installation will authenticate with. Its SHA-256 names the installation.
   */
  installation_key: string
  /**
   * The platform whose payload the gateway should build for this token.
   *
   * It is a claim, not a proof: receiving the challenge says the token reaches this device and
   * nothing about the label beside it. The gateway records it as delivery metadata and never
   * indexes by it.
   */
  platform: 'android' | 'ios'
  /**
   * This attempt. A retry carrying the same value is the same attempt.
   */
  registration_id: string
  /**
   * The provider token being proposed.
   */
  registration_token: string
}
/**
 * The receiver's answer.
 */
export interface PushRegistrationAnswer1 {
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
 * The host being authorised.
 */
export interface PushSenderIssueRequest {
  /**
   * The host's iroh endpoint identity.
   */
  host_endpoint_key: string
  /**
   * The host's Ed25519 signing key, which will prove its renewals and its revocation.
   */
  host_signing_key: string
  /**
   * The authorisation being created. A retry carrying the same value is the same authorisation.
   */
  sender_record_id: string
}
/**
 * The authorisation being renewed.
 */
export interface PushSenderNonceRequest {
  /**
   * The authorisation the host is about to renew or revoke.
   */
  sender_record_id: string
}
/**
 * The host's proof.
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
 * The authorisation being revoked.
 */
export interface PushSenderNonceRequest1 {
  /**
   * The authorisation the host is about to renew or revoke.
   */
  sender_record_id: string
}
/**
 * The host's statement.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  burst: string
  /**
   * A duration in milliseconds, as a decimal string in JSON.
   */
  collapse_window_ms: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  sustained_per_hour: string
}
/**
 * A host's proof that it still holds the key the installation authorised.
 */
export interface PushSenderRenewal1 {
  payload: PushSenderRenewalPayload
  /**
   * The host signing key's signature over [`PushSenderRenewalPayload::signing_input`].
   */
  signature: string
}
/**
 * A host's statement that an authorisation is finished.
 */
export interface PushSenderRevocation1 {
  payload: PushSenderRevocationPayload
  /**
   * The host signing key's signature over [`PushSenderRevocationPayload::signing_input`].
   */
  signature: string
}
/**
 * One durable question.
 *
 * This is the whole public view. The caller token is deliberately not a field: it is returned to
 * the source once, in [`QuestionCreateResult`], and never appears in a read, an event or a log.
 */
export interface Question {
  /**
   * The answer, once there is one.
   */
  answer: AnswerRecord | null
  /**
   * The options, including the free-text one for `select` and `confirm`.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context the source supplied.
   */
  context: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * When it reached a terminal state.
   */
  resolved_at_ms: TimestampMs | null
  /**
   * Its revision. An answer names the exact revision it is answering.
   */
  revision: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  source: QuestionSource1
  /**
   * Where it is in its life.
   */
  state: 'pending' | 'answered' | 'cancelled' | 'expired'
}
/**
 * One option a `select` question offers.
 */
export interface QuestionChoice {
  /**
   * The stable identifier an answer names. It does not change with the label.
   */
  choice_id: string
  /**
   * What the person reads.
   */
  label: string
}
/**
 * The verified source, and the unverified label beside it.
 */
export interface QuestionSource1 {
  /**
   * The agent thread or binding revision, when a qualified bridge supplied one.
   *
   * Null when no bridge did. A null here is not a claim that the thread never changed: without
   * a bridge the question is application-scoped and thread-switch detection is not offered.
   */
  agent_binding_revision: AgentBindingRevision | null
  /**
   * The caller's own label for itself. Unverified, and never part of authority.
   */
  agent_label: string | null
  /**
   * True when the process's parent chain reaches the session's root shell.
   *
   * A checked hint, recorded for diagnostics. Section 11 is explicit that ancestry is not a
   * defence against arbitrary code running under the same account, so nothing is admitted on
   * this alone.
   */
  ancestry: boolean
  /**
   * One foreground application within a terminal session.
   */
  application_instance_id: string
  /**
   * The connection the question was created on.
   */
  connection_id: string
  /**
   * The executable that process is running, where the platform names it.
   */
  executable: string | null
  /**
   * True when the helper presented the private launch channel it inherited.
   *
   * False means the binding rests on the checks below instead; it does not mean the source is
   * less bound, and it is recorded so a reader can tell which evidence was available.
   */
  launch_channel: boolean
  process: ProcessStartIdentity
  /**
   * True when the process is inside the session's own ownership boundary, as the kernel
   * reports it. This is what admits a source.
   */
  session_member: boolean
}
/**
 * Parameters of `question.answer`.
 */
export interface QuestionAnswerParams {
  /**
   * The answer.
   */
  answer:
    | {
        kind: 'input'
        /**
         * What the person typed.
         */
        text: string
      }
    | {
        /**
         * The choice the person selected.
         */
        choice_id: string
        kind: 'choice'
      }
    | {
        /**
         * True for yes.
         */
        decided: boolean
        kind: 'decision'
      }
    | {
        kind: 'other'
        /**
         * What the person typed instead of choosing.
         */
        text: string
      }
  /**
   * The revision the person was shown. A different current revision is refused.
   */
  expected_revision: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * Parameters of `question.cancel_own`.
 */
export interface QuestionCancelOwnParams {
  /**
   * The token issued when it was created.
   */
  caller_token: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * Parameters of `question.cancel`.
 */
export interface QuestionCancelParams {
  /**
   * The revision the person was shown.
   */
  expected_revision: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * Parameters of `question.create`.
 */
export interface QuestionCreateParams {
  /**
   * The caller's label for itself. Unverified.
   */
  agent_name: string | null
  /**
   * The choices, for a `select`. The free-text option is added by the host.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context.
   */
  context: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * The caller's own unpredictable identifier for this request.
   *
   * De-duplication is by the verified originating application and this value together. A caller
   * label is not part of it.
   */
  request_id: string
  /**
   * How long the question should live. Bounded by [`MAX_EXPIRY`] and by the source's own
   * lifetime.
   */
  requested_expiry_ms: DurationMs | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How long to wait for an answer before returning the pending question. Bounded by
   * [`MAX_CREATE_WAIT`].
   */
  wait_ms: DurationMs | null
}
/**
 * The result of `question.create`.
 */
export interface QuestionCreateResult {
  /**
   * The token that lets this source poll and cancel it.
   */
  caller_token: string
  /**
   * True when an exact duplicate returned the existing question rather than creating one.
   */
  deduplicated: boolean
  question: Question1
}
/**
 * The durable question.
 */
export interface Question1 {
  /**
   * The answer, once there is one.
   */
  answer: AnswerRecord | null
  /**
   * The options, including the free-text one for `select` and `confirm`.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context the source supplied.
   */
  context: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * When it reached a terminal state.
   */
  resolved_at_ms: TimestampMs | null
  /**
   * Its revision. An answer names the exact revision it is answering.
   */
  revision: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  source: QuestionSource1
  /**
   * Where it is in its life.
   */
  state: 'pending' | 'answered' | 'cancelled' | 'expired'
}
/**
 * One question transition, as the attention engine reads it.
 *
 * Section 25's idle reminder fires after five minutes of a *verified pending* request, so the
 * event carries the moment the question became pending and whether its source was verified.
 * Nothing here is the reminder itself; the attention engine owns that rule.
 */
export interface QuestionEvent {
  /**
   * What happened.
   */
  kind: 'created' | 'answered' | 'cancelled' | 'expired'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  pending_since_ms: string
  question: Question2
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  recorded_at_ms: string
}
/**
 * The question at this revision.
 */
export interface Question2 {
  /**
   * The answer, once there is one.
   */
  answer: AnswerRecord | null
  /**
   * The options, including the free-text one for `select` and `confirm`.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context the source supplied.
   */
  context: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * When it reached a terminal state.
   */
  resolved_at_ms: TimestampMs | null
  /**
   * Its revision. An answer names the exact revision it is answering.
   */
  revision: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  source: QuestionSource1
  /**
   * Where it is in its life.
   */
  state: 'pending' | 'answered' | 'cancelled' | 'expired'
}
/**
 * The result of `question.read_own` and `question.cancel_own`.
 */
export interface QuestionOwnResult {
  question: Question3
}
/**
 * The question as it now stands.
 */
export interface Question3 {
  /**
   * The answer, once there is one.
   */
  answer: AnswerRecord | null
  /**
   * The options, including the free-text one for `select` and `confirm`.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context the source supplied.
   */
  context: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * When it reached a terminal state.
   */
  resolved_at_ms: TimestampMs | null
  /**
   * Its revision. An answer names the exact revision it is answering.
   */
  revision: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  source: QuestionSource1
  /**
   * Where it is in its life.
   */
  state: 'pending' | 'answered' | 'cancelled' | 'expired'
}
/**
 * Parameters of `question.read_own`.
 */
export interface QuestionReadOwnParams {
  /**
   * The token issued when it was created.
   */
  caller_token: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How long to wait for a change before answering with the question as it stands.
   *
   * A wait that times out returns the same durable question. It does not recreate it, and it
   * does not notify anybody again.
   */
  wait_ms: DurationMs | null
}
/**
 * Parameters of `question.read`.
 */
export interface QuestionReadParams {
  /**
   * True to include questions that have already been resolved.
   */
  include_resolved: boolean
  /**
   * One question, or null for every question this actor may see.
   */
  question_id: QuestionId | null
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `question.read`.
 */
export interface QuestionReadResult {
  /**
   * The questions, oldest first.
   */
  questions: Question[]
}
/**
 * The result of `question.answer` and `question.cancel`.
 */
export interface QuestionResolveResult {
  question: Question4
}
/**
 * One durable question.
 *
 * This is the whole public view. The caller token is deliberately not a field: it is returned to
 * the source once, in [`QuestionCreateResult`], and never appears in a read, an event or a log.
 */
export interface Question4 {
  /**
   * The answer, once there is one.
   */
  answer: AnswerRecord | null
  /**
   * The options, including the free-text one for `select` and `confirm`.
   */
  choices: QuestionChoice[]
  /**
   * The concise decision context the source supplied.
   */
  context: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * What kind of answer it asks for.
   */
  kind: 'input' | 'select' | 'confirm'
  /**
   * The question itself.
   */
  question: string
  /**
   * One agent-to-user question.
   */
  question_id: string
  /**
   * When it reached a terminal state.
   */
  resolved_at_ms: TimestampMs | null
  /**
   * Its revision. An answer names the exact revision it is answering.
   */
  revision: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  source: QuestionSource1
  /**
   * Where it is in its life.
   */
  state: 'pending' | 'answered' | 'cancelled' | 'expired'
}
/**
 * The application the host verified as the source of a question.
 *
 * Everything here except [`Self::agent_label`] comes from the operating system through the
 * worker's private socket. The label comes from the caller and is displayed as unverified, which
 * is the whole of the difference between the two.
 */
export interface QuestionSource2 {
  /**
   * The agent thread or binding revision, when a qualified bridge supplied one.
   *
   * Null when no bridge did. A null here is not a claim that the thread never changed: without
   * a bridge the question is application-scoped and thread-switch detection is not offered.
   */
  agent_binding_revision: AgentBindingRevision | null
  /**
   * The caller's own label for itself. Unverified, and never part of authority.
   */
  agent_label: string | null
  /**
   * True when the process's parent chain reaches the session's root shell.
   *
   * A checked hint, recorded for diagnostics. Section 11 is explicit that ancestry is not a
   * defence against arbitrary code running under the same account, so nothing is admitted on
   * this alone.
   */
  ancestry: boolean
  /**
   * One foreground application within a terminal session.
   */
  application_instance_id: string
  /**
   * The connection the question was created on.
   */
  connection_id: string
  /**
   * The executable that process is running, where the platform names it.
   */
  executable: string | null
  /**
   * True when the helper presented the private launch channel it inherited.
   *
   * False means the binding rests on the checks below instead; it does not mean the source is
   * less bound, and it is recorded so a reader can tell which evidence was available.
   */
  launch_channel: boolean
  process: ProcessStartIdentity
  /**
   * True when the process is inside the session's own ownership boundary, as the kernel
   * reports it. This is what admits a source.
   */
  session_member: boolean
}
/**
 * One action receipt.
 *
 * The de-duplication key is `(actor_id, action_id)`. An exact duplicate returns the stored
 * receipt; a reused identifier with a different payload digest is an `ID_CONFLICT`.
 */
export interface Receipt3 {
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  revision: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  schema_version: string
  /**
   * The writers a restore may trust.
   */
  trusted_writers: TrustedWriter1[]
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  encrypted_manifest_hash: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
export interface TrustedWriter1 {
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  profile_version: string
  /**
   * The 256-bit recovery seed. It zeroises when the kit is dropped and never appears in debug
   * output: it is the whole of the owner's recovery authority.
   */
  seed: string
  /**
   * The seed checksum, so a mistyped kit fails before it is used.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  bytes_consumed: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
 * The event that tells one subscriber to discard its partial state.
 */
export interface ResyncRequired {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cursor: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  oldest_retained_cursor: string
  /**
   * Why.
   */
  reason: 'send_queue_full' | 'history_evicted' | 'projection_reset'
}
/**
 * One retained log view, with the gap retention left in it.
 */
export interface RetainedLogView {
  /**
   * The range retention evicted, when the retained offset is no longer readable.
   */
  gap: HistoryGap | null
  /**
   * The offset the view was left at, when retention has moved past it.
   *
   * Present exactly when [`RetainedLogView::gap`] is: the view keeps saying where it was even
   * though it can no longer be served from there.
   */
  requested_offset: U64 | null
  view: LogViewState1
}
/**
 * The view, at the offset it can be served from now.
 */
export interface LogViewState1 {
  /**
   * The filter the view had applied, in the client's own form.
   */
  filter: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  source_offset: string
  /**
   * The view, as the client names it.
   */
  view_id: string
}
/**
 * The reading it produced.
 */
export interface TimeAdapterReading {
  /**
   * The service or interface the reading came from.
   */
  api: string
  /**
   * The platform's own estimate of its error, in microseconds, when it reports one.
   */
  estimated_error_us: U64 | null
  /**
   * Which platform adapter produced this reading.
   */
  platform: string
  /**
   * What the platform says is disciplining its clock.
   */
  source: 'network_time_service' | 'pulse_per_second' | 'unsynchronised' | 'unclassified'
  /**
   * What the platform says the state of that synchronisation is.
   */
  status:
    | 'ok'
    | 'insert_leap'
    | 'delete_leap'
    | 'leap_in_progress'
    | 'leap_recovering'
    | 'error'
    | 'unavailable'
  /**
   * The platform's own bound on how wrong its clock may be, in microseconds.
   *
   * Null means the platform reported no bound, which is not the same as a bound of zero.
   */
  uncertainty_us: U64 | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  wall_clock_ms: string
}
/**
 * Parameters of `review.acknowledge`.
 */
export interface ReviewAcknowledgeParams {
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * What is being acknowledged.
   */
  subject:
    | {
        completed_turn: {
          /**
           * One KalaReach terminal session.
           */
          session_id: string
          /**
           * The turn.
           */
          turn_id: string
        }
      }
    | {
        change_set: {
          /**
           * One immutable captured change set.
           */
          change_set_id: string
          /**
           * One KalaReach terminal session.
           */
          session_id: string
        }
      }
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  version: string
}
/**
 * The result of `review.acknowledge`.
 *
 * It reports review state and nothing else. Acknowledging approves no command, applies no patch
 * and changes no Git state; section 14 makes promotion a separate authorised action, and this
 * group has no method that performs one.
 */
export interface ReviewAcknowledgeResult {
  /**
   * The actor the acknowledgement belongs to.
   */
  actor_id: string
  review: ReviewState
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  revision: string
}
/**
 * The state of the subject after the acknowledgement.
 */
export interface ReviewState {
  /**
   * When this actor acknowledged it.
   */
  acknowledged_at_ms: TimestampMs | null
  /**
   * The version this actor acknowledged, when it has acknowledged one.
   */
  acknowledged_version: U64 | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  current_version: string
  /**
   * Whether review work is outstanding for this actor.
   *
   * True when nothing has been acknowledged, and true again after a new version appears: a new
   * change is new review work, and an acknowledgement of an earlier version does not cover it.
   */
  outstanding: boolean
  /**
   * What is being reviewed, at the version the host currently holds.
   */
  subject:
    | {
        completed_turn: {
          /**
           * One KalaReach terminal session.
           */
          session_id: string
          /**
           * The turn.
           */
          turn_id: string
        }
      }
    | {
        change_set: {
          /**
           * One immutable captured change set.
           */
          change_set_id: string
          /**
           * One KalaReach terminal session.
           */
          session_id: string
        }
      }
}
/**
 * Parameters of `review.read`.
 */
export interface ReviewReadParams {
  /**
   * The subject to continue after, or null to start at the oldest.
   *
   * A subject this session no longer holds is refused rather than restarting the page, because
   * a page that silently began again would read as the end of the list.
   */
  after: ReviewSubject | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_reviews: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * One subject, or null for a page of every subject this session knows about.
   */
  subject: ReviewSubject | null
}
/**
 * The result of `review.read`.
 */
export interface ReviewReadResult {
  /**
   * The actor this state belongs to.
   */
  actor_id: string
  /**
   * Whether more subjects remain after the last one in this page.
   */
  more: boolean
  /**
   * The review state of each subject, oldest first.
   */
  reviews: ReviewState1[]
}
/**
 * The review state of one subject, for one actor.
 */
export interface ReviewState1 {
  /**
   * When this actor acknowledged it.
   */
  acknowledged_at_ms: TimestampMs | null
  /**
   * The version this actor acknowledged, when it has acknowledged one.
   */
  acknowledged_version: U64 | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  current_version: string
  /**
   * Whether review work is outstanding for this actor.
   *
   * True when nothing has been acknowledged, and true again after a new version appears: a new
   * change is new review work, and an acknowledgement of an earlier version does not cover it.
   */
  outstanding: boolean
  /**
   * What is being reviewed, at the version the host currently holds.
   */
  subject:
    | {
        completed_turn: {
          /**
           * One KalaReach terminal session.
           */
          session_id: string
          /**
           * The turn.
           */
          turn_id: string
        }
      }
    | {
        change_set: {
          /**
           * One immutable captured change set.
           */
          change_set_id: string
          /**
           * One KalaReach terminal session.
           */
          session_id: string
        }
      }
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
 * The result of installing an authority revision across every affected worker.
 *
 * Until every barrier holds, this is `pending` with per-worker status. Cutting a network path or
 * waiting for a lease timer is not completion, because a paused worker could already be inside a
 * dispatch transition, so nothing here treats the absence of an answer as an answer.
 */
export interface RevocationBarrier {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * One entry per affected worker.
   */
  workers: WorkerBarrier[]
}
/**
 * One worker's half of a revocation barrier.
 */
export interface WorkerBarrier {
  /**
   * The revision the worker has installed, when it has installed one.
   */
  acknowledged_revision: AuthorityRevision | null
  /**
   * Why this worker's barrier has not held, or what is still outstanding about one that has.
   */
  detail: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  names_pending: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  omitted_actions: string
  /**
   * The actions whose dispatch transition had already won the serial race.
   *
   * Each one's receipt state says how much is known about what it did; the list is
   * not only the uncertain ones.
   */
  possibly_executed: PossiblyExecutedAction[]
  /**
   * The undispatched intents the fence rejected.
   */
  rejected_actions: FencedAction[]
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * What this worker's barrier has reached.
   */
  state: 'acknowledged' | 'ended' | 'pending'
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
 * The result of `grant.revoke` and `device.revoke`.
 *
 * A revocation is not complete when the host records it. It is complete for a worker once that
 * worker has acknowledged the revision and fenced the undispatched actions it affects, or once
 * the worker is confirmed ended, so the barrier travels with the answer.
 */
export interface RevocationResult {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  barrier: RevocationBarrier1
  /**
   * Every grant it revoked: the named one and its descendants.
   */
  revoked_grants: GrantId[]
}
/**
 * The per-worker completion status.
 */
export interface RevocationBarrier1 {
  /**
   * The host's ordered authority revision. Only the host issues its own revisions.
   */
  authority_revision: string
  /**
   * One entry per affected worker.
   */
  workers: WorkerBarrier[]
}
/**
 * What the issuer chose, on top of the role, before the grant was written.
 *
 * Every field here is an explicit choice. A default-constructed selection adds nothing to the
 * role, which is what section 25 requires: earlier history, the live screen, `question.respond`
 * below controller, and named pre-cutoff resources are each opted into or absent.
 */
export interface RoleSelection1 {
  /**
   * Earlier history, from this cursor. Null keeps the recipient to the live screen and what
   * follows it.
   */
  history_from_cursor_ms: TimestampMs | null
  /**
   * Whether the currently visible screen is included, previewed to the issuer.
   *
   * The exception never reaches inactive screen buffers, scrollback or the backing transcript.
   */
  include_live_screen: boolean
  /**
   * Whether a viewer or reviewer also receives `question.respond`.
   *
   * Ignored for controller and owner, which carry it already.
   */
  include_question_respond: boolean
  /**
   * Current approval requests this invitation names explicitly.
   */
  named_approvals: ApprovalRequestId[]
  /**
   * Current questions this invitation names explicitly.
   */
  named_questions: QuestionId[]
  /**
   * The role the issuer chose.
   */
  role: 'viewer' | 'reviewer' | 'controller' | 'owner'
}
/**
 * Parameters of `root.command.accepted`.
 *
 * Sent from the reader at acceptance, inside the fenced context, before the reader leaves. The
 * order matters: a record sent after the leave would arrive with the fence already invalidated and
 * could only ever say `unverifiable`.
 */
export interface RootCommandAcceptedParams {
  /**
   * The fence the acceptance happened under, when one was live.
   */
  fence_id: FenceId | null
  /**
   * The origin the bridge can prove from its own reader state.
   */
  origin:
    | {
        fenced: {
          /**
           * The attachment that typed it.
           */
          attachment_id: string
          /**
           * The epoch its bytes arrived under.
           */
          input_epoch: string
        }
      }
    | 'mixed'
    | 'unverifiable'
  /**
   * The prompt generation of the accepted line.
   */
  prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `root.command.accepted`.
 */
export interface RootCommandAcceptedResult {
  /**
   * The origin the worker recorded, which is what a later unqualified detach resolves against.
   */
  origin:
    | {
        fenced: {
          /**
           * The attachment that typed it.
           */
          attachment_id: string
          /**
           * The epoch its bytes arrived under.
           */
          input_epoch: string
        }
      }
    | 'mixed'
    | 'unverifiable'
  /**
   * The state after acceptance.
   */
  state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
}
/**
 * Parameters of `root.command.block`.
 *
 * Section 25: the shell adapter reports command blocks with their exit status, duration and
 * working directory, from the same private hooks the fence rests on. All four come from the
 * reader's own boundaries rather than from parsed terminal output.
 */
export interface RootCommandBlockParams {
  /**
   * The command line, exactly as the editor accepted it.
   */
  command: string
  /**
   * The working directory it ran in.
   */
  cwd: string
  /**
   * The working-directory revision at that boundary, which is what a launch is checked against.
   */
  cwd_revision: string
  /**
   * How long it ran. Null while it is still running.
   */
  duration_ms: DurationMs | null
  /**
   * The status it exited with. Null while it is still running.
   */
  exit_status: U64 | null
  /**
   * The prompt generation the command was accepted at.
   */
  prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  started_at_ms: string
}
/**
 * The result of `root.command.block`.
 */
export interface RootCommandBlockResult {
  /**
   * The prompt generation the block was recorded under.
   */
  prompt_generation: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  retained: string
}
/**
 * Parameters of `root.command.resolve`.
 *
 * The integration's pre-execution hook asks the worker what to run, before it runs anything. The
 * command name and the argument vector are the person's; what the answer may do is add flags.
 */
export interface RootCommandResolveParams {
  /**
   * The invocation, split by the shell: the command name first, then its arguments.
   */
  argv: string[]
  /**
   * Whether this is an interactive invocation rather than a line of a script.
   */
  interactive: boolean
  /**
   * The prompt generation the line this invocation came from was accepted at.
   */
  prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `root.command.resolve`.
 */
export interface RootCommandResolveResult {
  /**
   * The flags this answer added. Empty for a bypassed invocation.
   */
  added: string[]
  /**
   * The argument vector to run: what was typed, plus any flags the integration added.
   */
  arguments: string[]
  /**
   * The worker-owned backend, established before this answer was sent. Null for a bypass.
   */
  backend: CommandBackend | null
  /**
   * Why the invocation was left alone, or null when the integration applied.
   */
  bypass: CommandBypassReason | null
}
/**
 * The worker-owned backend an integrated invocation is given.
 *
 * Section 12 requires it to exist *before* the native program starts, which is why it is part of
 * the answer to the hook that runs in front of the command rather than something a detected agent
 * asks for afterwards. There is no other route to one: an agent that is noticed after it started
 * never gets a gateway created for it retroactively.
 */
export interface CommandBackend {
  /**
   * The variables the shell exports for this one invocation.
   *
   * They name this session and the worker's own private endpoint. A bypassed invocation is
   * given none of them, which is what keeps its execution the one the person asked for.
   */
  environment: EnvironmentVariable[]
  /**
   * The prompt generation it is bound to.
   *
   * One backend per accepted line. A second resolve for the same generation is answered with
   * the binding that already exists rather than with another one, and a generation that has
   * moved on has no binding at all: there is no route by which a program that is already
   * running acquires one.
   */
  prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The `EDITOR_BUSY` attachment event.
 *
 * It is an event about the editor, not a failed `input.acquire`: the lease change it follows
 * stands, the epoch below is the one that now holds input, and the released bytes went to the
 * terminal in the order they arrived. The worker retries the fence at the reader's next entry,
 * leave or idle callback.
 */
export interface EditorBusyEvent {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The lease epoch that stands.
   */
  input_epoch: string
  /**
   * Why the editor could not be fenced.
   */
  reason:
    | 'fence_exchange_timed_out'
    | 'fence_refused'
    | 'queues_not_drained'
    | 'launch_reservation_timed_out'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  released_input_bytes: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The state the editor is in now.
   */
  state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
}
/**
 * Parameters of `root.editor.enter`.
 *
 * Sent when the actual primary reader starts, not when a prompt is printed. A prompt hook runs
 * before the reader exists and cannot stand in for this.
 */
export interface RootEditorEnterParams {
  /**
   * The shell's working-directory revision at this boundary.
   */
  cwd_revision: string
  editor: EditorState
  /**
   * The prompt the reader is starting at.
   */
  prompt_generation: string
  /**
   * Which reader started.
   */
  reader_context: 'primary' | 'continuation' | 'read_builtin'
  /**
   * The revision of this reader inside that prompt.
   */
  reader_revision: string
  root_process: ProcessStartIdentity6
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The reader's own initial state, including its keymap.
 */
export interface EditorState {
  /**
   * True when the buffer holds nothing, as the reader itself reports it.
   */
  buffer_empty: boolean
  /**
   * The buffer revision this state was read at.
   */
  buffer_revision: string
  /**
   * The keymap in force.
   */
  keymap: 'emacs' | 'vi_insert' | 'vi_command' | 'custom'
  pending: PendingReaderInput
}
/**
 * What the reader is in the middle of.
 */
export interface PendingReaderInput {
  /**
   * The reader is consuming a macro rather than the terminal.
   */
  macro_input: boolean
  /**
   * A multikey sequence has begun and is waiting for its remaining keys.
   */
  multikey_sequence: boolean
  /**
   * A numeric argument is being accumulated.
   */
  numeric_argument: boolean
  /**
   * A bracketed paste is open.
   */
  paste: boolean
  /**
   * A quoted insertion is waiting for the character to insert literally.
   */
  quoted_insertion: boolean
  /**
   * An incremental or non-incremental search is active.
   */
  search: boolean
  /**
   * A vi motion is waiting for its target.
   */
  vi_motion: boolean
}
/**
 * A process and the kernel's record of when it started.
 *
 * Every ownership check compares both fields. A process identifier alone can be reused by an
 * unrelated program within milliseconds of the original exiting, so the host never terminates,
 * adopts or trusts a process on its identifier alone.
 */
export interface ProcessStartIdentity6 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * The result of `root.editor.enter`.
 */
export interface RootEditorEnterResult {
  /**
   * The fence exchange the worker started, when it started one.
   */
  fence_exchange: FenceId | null
  /**
   * The state after registration. Entry always invalidates the previous fence, so this is
   * `unfenced` until an exchange is acknowledged.
   */
  state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
}
/**
 * The ownership proof for the input delivered during one editor epoch.
 *
 * Every field is evidence rather than inference. The root process says which shell this is, the
 * prompt generation and reader revision say which reader instance, the lease epoch says which
 * client's bytes could have reached it, and the single originating attachment is the one a detach
 * or an accepted line belongs to.
 */
export interface EditorFence {
  /**
   * The fence identity.
   */
  fence_id: string
  /**
   * The input-lease epoch the fenced input belongs to.
   */
  input_epoch: string
  /**
   * One CLI or application attachment, independently of its device.
   */
  originating_attachment: string
  /**
   * The prompt the reader is at.
   */
  prompt_generation: string
  /**
   * The reader revision inside that prompt.
   */
  reader_revision: string
  root_process: ProcessStartIdentity7
}
/**
 * The root shell process, with the kernel's record of when it started.
 */
export interface ProcessStartIdentity7 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * Parameters of `root.editor.fence`: the worker asking the bridge to resolve prior input.
 *
 * The identity travels with the question so the acknowledgement can be matched to it. An
 * acknowledgement that arrives after the deadline names an exchange that no longer exists and
 * publishes nothing.
 */
export interface RootEditorFenceParams {
  /**
   * Why the worker is asking.
   */
  cause: 'editor_entry' | 'lease_change' | 'retry'
  /**
   * A duration in milliseconds, as a decimal string in JSON.
   */
  deadline_ms: string
  /**
   * One published editor fence. An identity from an unacknowledged exchange names no fence.
   */
  fence_id: string
  /**
   * The prompt generation the worker believes the reader is at.
   */
  prompt_generation: string
  /**
   * The reader revision the worker believes is current.
   */
  reader_revision: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The bridge's answer that prior input is resolved.
 *
 * It is evidence, not agreement: the drain report and the snapshot are what the worker checks
 * before it publishes anything.
 */
export interface FenceAcknowledgement {
  /**
   * The shell's working-directory revision at the same instant.
   */
  cwd_revision: string
  editor: EditorState1
  /**
   * The exchange being answered.
   */
  fence_id: string
  /**
   * The prompt generation at the moment of the snapshot.
   */
  prompt_generation: string
  queues: QueueDrainReport
  /**
   * The reader the bridge is answering from.
   */
  reader_context: 'primary' | 'continuation' | 'read_builtin'
  /**
   * The reader revision at the moment of the snapshot.
   */
  reader_revision: string
  snapshot: KeyQueueSnapshot
}
/**
 * The reader's edit-buffer state at the same instant.
 */
export interface EditorState1 {
  /**
   * True when the buffer holds nothing, as the reader itself reports it.
   */
  buffer_empty: boolean
  /**
   * The buffer revision this state was read at.
   */
  buffer_revision: string
  /**
   * The keymap in force.
   */
  keymap: 'emacs' | 'vi_insert' | 'vi_command' | 'custom'
  pending: PendingReaderInput
}
/**
 * Which queues the bridge has cleared.
 */
export interface QueueDrainReport {
  /**
   * No macro input remains.
   */
  macro_input_drained: boolean
  /**
   * No partial key sequence remains.
   */
  partial_key_drained: boolean
  /**
   * The terminal's typeahead has been consumed by this reader.
   */
  tty_typeahead_drained: boolean
}
/**
 * The atomically read key queues behind that report.
 */
export interface KeyQueueSnapshot {
  /**
   * The key sequence that invoked the reader's current operation. Empty between operations.
   */
  keys: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pending_bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  queued_keys: string
}
/**
 * A bridge's refusal to resolve prior input.
 */
export interface FenceRefusal {
  /**
   * The exchange being refused.
   */
  fence_id: string
  /**
   * The reader the refusal came from.
   */
  reader_context: 'primary' | 'continuation' | 'read_builtin'
  /**
   * Why.
   */
  reason: 'reader_busy' | 'queues_not_drained' | 'reader_moved' | 'cancellation_unavailable'
  snapshot: KeyQueueSnapshot1
}
/**
 * What was still in the reader's queues.
 */
export interface KeyQueueSnapshot1 {
  /**
   * The key sequence that invoked the reader's current operation. Empty between operations.
   */
  keys: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pending_bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  queued_keys: string
}
/**
 * Parameters of `root.editor.leave`.
 */
export interface RootEditorLeaveParams {
  /**
   * The prompt the reader was at.
   */
  prompt_generation: string
  /**
   * The revision of the reader that is leaving.
   */
  reader_revision: string
  /**
   * Why it stopped.
   */
  reason: 'command_accepted' | 'preexec' | 'reader_takeover' | 'cancellation' | 'root_exit'
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `root.editor.leave`.
 */
export interface RootEditorLeaveResult {
  /**
   * The state after the reader left. Leaving invalidates the fence.
   */
  state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
}
/**
 * Parameters of `root.eof.detach`.
 *
 * The bridge submits this at an eligible empty primary prompt. Naming the fence, the prompt and
 * the epoch is what makes the request attributable: the worker removes the attachment the fence
 * names, never whichever one holds the lease when the request arrives.
 */
export interface RootEofDetachParams {
  /**
   * One published editor fence. An identity from an unacknowledged exchange names no fence.
   */
  fence_id: string
  /**
   * The current input lease epoch.
   */
  input_epoch: string
  /**
   * The prompt generation the gesture arrived at.
   */
  prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `root.eof.detach`.
 */
export interface RootEofDetachResult {
  /**
   * One CLI or application attachment, independently of its device.
   */
  detached_attachment: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  discarded_input_bytes: string
  /**
   * The state after the detach. The fence is invalidated before this answer is sent.
   */
  state: 'outside' | 'unfenced' | 'fenced' | 'launch_reserved' | 'closing'
}
/**
 * One semantic change in the changed-since-last-visit view.
 */
export interface SemanticChange {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  at_ms: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  cursor: string
  /**
   * What it was.
   */
  kind:
    | 'turn_completed'
    | 'command_completed'
    | 'question_answered'
    | 'change_set_captured'
    | 'adapter_state'
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * One line naming it, when this caller may be served it.
   *
   * Null means the host withheld it, for the same reason an attention item's text is withheld.
   */
  summary: string | null
}
/**
 * Where a reader continues a semantic snapshot that stopped short.
 *
 * It is present exactly when something was left out. A snapshot with no continuation is the whole
 * tree; one with a continuation is a part, and the fields say what to ask for next.
 */
export interface SemanticContinuation {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  bytes: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_node: string
  /**
   * Which limit stopped this part.
   */
  limit: 'bytes' | 'depth' | 'nodes'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  limit_value: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  nodes: string
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
    | 'attention.quiet_hours'
    | 'visit.acknowledge'
    | 'visit.changed'
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
    | 'mailbox.deliver'
    | 'mailbox.acknowledge'
    | 'authority.sync'
    | 'sync.compare_exchange'
    | 'backup.manifest'
    | 'storage.status'
    | 'storage.retention.set'
    | 'storage.upload.create'
    | 'storage.upload.part'
    | 'storage.upload.complete'
    | 'storage.upload.abort'
    | 'storage.object.read'
    | 'storage.object.delete'
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
 * Parameters of `session.attach`.
 *
 * The request does not bypass grants and does not acquire a remote input lease.
 */
export interface SessionAttachParams {
  /**
   * Whether this attachment registers a geometry claim. Semantic mode requires false.
   */
  claim_geometry: boolean
  /**
   * The attachment's physical dimensions, required in terminal mode.
   */
  dimensions: Dimensions | null
  /**
   * What this attachment observes.
   */
  mode: 'semantic' | 'terminal'
  /**
   * The observation and input capabilities the attachment asks for.
   */
  requested: AttachmentCapability[]
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The terminal profile this attachment presents.
   */
  terminal_profile_id: string | null
}
/**
 * The result of `session.attach`.
 */
export interface SessionAttachResult {
  attachment: AttachmentSummary1
  geometry: GeometryState4
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  output_cursor: string
}
/**
 * One attachment of a session.
 */
export interface AttachmentSummary1 {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  attached_at_ms: string
  /**
   * The attachment identity, independent of the device behind it.
   */
  attachment_id: string
  /**
   * Whether this attachment holds an eligible geometry claim.
   */
  claim_geometry: boolean
  /**
   * The attachment's own physical dimensions, reported even when it is not the owner.
   */
  dimensions: Dimensions | null
  /**
   * The capabilities the host granted, which are the requested ones intersected with the
   * actor's rights.
   */
  granted: AttachmentCapability[]
  /**
   * What this attachment observes.
   */
  mode: 'semantic' | 'terminal'
  /**
   * The monotonic join order that decides size-owner succession.
   */
  ordinal: string
  /**
   * How the attachment displays the canonical grid.
   */
  presentation: TerminalPresentationMode | null
  /**
   * The terminal profile it presents.
   */
  terminal_profile_id: string | null
}
/**
 * Who owns the geometry after this attachment joined.
 */
export interface GeometryState4 {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
}
/**
 * Parameters of `session.close`.
 */
export interface SessionCloseParams {
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `session.close`.
 *
 * The initiating request receives this acceptance before the worker's own process can end.
 * Duplicate requests return the existing state rather than a second closure.
 */
export interface SessionCloseResult {
  /**
   * The final record, once closure has finished.
   */
  closure: ClosureRecord | null
  /**
   * Whether the closure was recorded durably.
   */
  durability: 'durable' | 'volatile'
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The state at the moment of the reply.
   */
  state: 'creating' | 'live' | 'closing' | 'closed'
}
/**
 * Parameters of `session.create`.
 */
export interface SessionCreateParams1 {
  /**
   * The working directory. Null selects the caller's directory from the snapshot.
   */
  cwd: string | null
  /**
   * The starting geometry. Null uses the invisible default of 120x40.
   */
  dimensions: Dimensions | null
  /**
   * The environment to create in.
   */
  environment_id: string
  /**
   * The creator's environment snapshot. The host filters terminal identity and reserved
   * KalaReach variables out of it, and execution-context values take precedence over it.
   */
  environment_snapshot: EnvironmentVariable[]
  launch_profile: LaunchProfile
  /**
   * The palette this session starts with. Null takes the profile default.
   *
   * This is the one moment the palette can be chosen: section 8 fixes it at creation, and
   * afterwards only an authorised explicit change moves it. The provenance is recorded either
   * way, so a palette query can say where the session's colours came from.
   */
  palette: PaletteRequest | null
  /**
   * How the session is presented locally.
   */
  presentation: 'attach' | 'terminal' | 'invisible'
  /**
   * The shell to launch. Null selects the environment's configured default.
   */
  shell: string | null
  /**
   * The shell integration mode.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The terminal application a `terminal` presentation opens in, by its stable identifier.
   *
   * The first step of section 7's order. Null leaves the choice to the host, which detects what
   * is installed; a named application this host does not have is `TERMINAL_UNAVAILABLE` rather
   * than a substitution, because somebody asked for that terminal.
   */
  terminal: string | null
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * The result of `session.create`.
 */
export interface SessionCreateResult {
  /**
   * True when this result was replayed for a repeated create token rather than created now.
   */
  deduplicated: boolean
  /**
   * The endpoint the creator can attach to without another controller call. Null when the
   * session has already closed, which a repeated create token can return.
   */
  endpoint: string | null
  /**
   * The presentation failure, when the session was created and its terminal could not be
   * opened. The session above is real and usable; a failed presentation never retries
   * execution and never creates a second session.
   */
  presentation_error: ProtocolError | null
  session: SessionSummary1
}
/**
 * The created session.
 */
export interface SessionSummary1 {
  /**
   * What the foreground is doing, where the host knows.
   */
  application_state: ApplicationState | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  attachment_count: string
  /**
   * The final record, once the session has closed.
   */
  closure: ClosureRecord | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The working directory the root shell started in.
   */
  cwd: string
  desktop: DesktopBinding
  dimensions: Dimensions4
  /**
   * The local alias.
   */
  display_number: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The root shell's process identity while the session is running.
   */
  root_process: ProcessStartIdentity5 | null
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How the root shell is integrated. A `native_compat` session is labelled everywhere it is
   * reported.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The executable actually launched as the root shell.
   */
  shell_path: string
  /**
   * The lifecycle state.
   */
  state: 'creating' | 'live' | 'closing' | 'closed'
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * Parameters of `session.detach`.
 */
export interface SessionDetachParams {
  /**
   * The attachment to remove. Null asks the host for the originating attachment.
   *
   * Section 7's `kr detach` takes no identifier inside its own context, and the host is the
   * only place that knows what that context is: the attachment whose input the root editor
   * accepted the line under, recorded through the fence at acceptance. A caller that names
   * nothing gets that attachment or `AMBIGUOUS_ATTACHMENT`, never a guess and never whichever
   * client happens to hold the input lease when the command runs.
   */
  attachment_id: AttachmentId | null
}
/**
 * The result of `session.detach`.
 */
export interface SessionDetachResult {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  geometry: GeometryState5
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  remaining: string
}
/**
 * Who owns the geometry after succession.
 */
export interface GeometryState5 {
  dimensions: Dimensions2
  /**
   * The epoch, advanced by every ownership change and explicit transfer.
   */
  epoch: string
  /**
   * The current owner. Null when no eligible claim exists and the last geometry is retained.
   */
  owner: AttachmentId | null
}
/**
 * Parameters of `session.list`.
 */
export interface SessionListParams {
  /**
   * Restrict to one environment. Null lists every environment the caller may see.
   */
  environment_id: EnvironmentId | null
  /**
   * Include sessions that have already closed.
   */
  include_closed: boolean
}
/**
 * The result of `session.list`.
 */
export interface SessionListResult {
  /**
   * The sessions, in display-number order.
   */
  sessions: SessionSummary2[]
}
/**
 * What a client knows about one session.
 */
export interface SessionSummary2 {
  /**
   * What the foreground is doing, where the host knows.
   */
  application_state: ApplicationState | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  attachment_count: string
  /**
   * The final record, once the session has closed.
   */
  closure: ClosureRecord | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The working directory the root shell started in.
   */
  cwd: string
  desktop: DesktopBinding
  dimensions: Dimensions4
  /**
   * The local alias.
   */
  display_number: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The root shell's process identity while the session is running.
   */
  root_process: ProcessStartIdentity5 | null
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How the root shell is integrated. A `native_compat` session is labelled everywhere it is
   * reported.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The executable actually launched as the root shell.
   */
  shell_path: string
  /**
   * The lifecycle state.
   */
  state: 'creating' | 'live' | 'closing' | 'closed'
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
}
/**
 * Parameters of `session.read`.
 */
export interface SessionReadParams {
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `session.read`.
 */
export interface SessionReadResult {
  /**
   * The endpoint a local client can attach to, while the session is running.
   */
  endpoint: string | null
  /**
   * The most recent command block the session's private hooks reported.
   *
   * Section 25's typed event: the command, its exit status, how long it ran and where. Null
   * when no hook has reported one, which is every session without a managed root integration.
   */
  last_command_block: RootCommandBlockParams | null
  /**
   * How this session starts its root shell and what may be launched inside it.
   *
   * Null for a session that has already closed, whose profile decides nothing any more.
   */
  launch_profile: LaunchProfile1 | null
  /**
   * How many `shell.launch` confirmations this session is still waiting on its reader for.
   *
   * Work this host has admitted and not finished: a launch is with the reader, and the caller
   * is waiting for the reader's decision. Null and zero are different answers. Null is a
   * session that cannot have one — no managed root editor, or a session that has closed — and
   * says nothing about outstanding work; zero is a session that could have one and has none.
   */
  outstanding_launches: U64 | null
  session: SessionSummary3
}
/**
 * How a session starts its root shell and what may be launched inside it.
 *
 * Section 23 lists the launch profile among `shell.launch`'s preconditions, beside the terminal
 * input right, the current input lease, a qualified root editor, an empty prompt behind a fence
 * and the working-directory revision. It is the one of those six that is a decision about the
 * session rather than a fact about the reader, which is why it is fixed when the session is
 * created and read back wherever the session is described.
 */
export interface LaunchProfile1 {
  /**
   * The opt-in command integrations this session applies to interactive invocations.
   */
  command_integrations: CommandIntegration[]
  /**
   * Whether a host-authorised `shell.launch` may install a command in this session's editor.
   *
   * A profile that says no keeps everything else a managed session has — the fence, the
   * empty-prompt end-of-file gesture, the attributed acceptance — and refuses the one operation
   * that puts text a person did not type into their editor.
   */
  fenced_launch: boolean
  /**
   * Which startup files the root shell reads.
   */
  startup: 'host_default' | 'interactive' | 'login'
}
/**
 * What a client knows about one session.
 */
export interface SessionSummary3 {
  /**
   * What the foreground is doing, where the host knows.
   */
  application_state: ApplicationState | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  attachment_count: string
  /**
   * The final record, once the session has closed.
   */
  closure: ClosureRecord | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * The working directory the root shell started in.
   */
  cwd: string
  desktop: DesktopBinding
  dimensions: Dimensions4
  /**
   * The local alias.
   */
  display_number: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The root shell's process identity while the session is running.
   */
  root_process: ProcessStartIdentity5 | null
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How the root shell is integrated. A `native_compat` session is labelled everywhere it is
   * reported.
   */
  shell_mode: 'managed' | 'native_compat'
  /**
   * The executable actually launched as the root shell.
   */
  shell_path: string
  /**
   * The lifecycle state.
   */
  state: 'creating' | 'live' | 'closing' | 'closed'
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
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
 * Parameters of `shell.launch`.
 */
export interface ShellLaunchParams {
  /**
   * What to install.
   */
  command:
    | {
        arguments: string[]
      }
    | {
        quoted_command: string
      }
  /**
   * The buffer revision the caller expects an empty buffer to be at.
   */
  expected_buffer_revision: string
  /**
   * The prompt generation the caller expects the root editor to be at.
   */
  expected_prompt_generation: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of a `shell.launch` that was installed and submitted.
 *
 * A launch that was not installed is an error rather than a result: `EDITOR_BUSY` when the
 * transaction could not be held, `DRAFT_CONFLICT` when the editor's own state had moved.
 */
export interface ShellLaunchResult {
  /**
   * The buffer revision after the command was installed.
   */
  buffer_revision: string
  /**
   * One published editor fence. An identity from an unacknowledged exchange names no fence.
   */
  fence_id: string
  /**
   * The prompt generation it was accepted at.
   */
  prompt_generation: string
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
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
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
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  encrypted_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
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
 * One device's four purpose-separated public keys.
 *
 * An authenticated pairing exchange binds these public keys and their explicit purposes to one
 * device record.
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
  history: HistoryScope2
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
 * What the host's sleep inhibition is doing.
 *
 * Reported by host status and by `kr status`, whether it is active or not: a setting that is on
 * and holding nothing is as much a fact as one that is holding an assertion.
 */
export interface SleepInhibitionState2 {
  /**
   * Whether an assertion is held right now.
   */
  active: boolean
  /**
   * The name the platform shows for the assertion, so a person can find it in the operating
   * system's own listing.
   */
  holder: string | null
  /**
   * The facility holding it.
   */
  mechanism: 'macos_power_assertion' | 'linux_logind_inhibitor' | 'windows_execution_state' | 'none'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pending_requests: string
  /**
   * What the host is running on.
   */
  power_source: 'mains' | 'battery' | 'unknown'
  /**
   * Why it is held, when it is.
   */
  reason: InhibitionReason | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  sessions_with_work: string
  /**
   * The owner's choice.
   */
  setting: 'off' | 'mains_only' | 'battery_too'
  /**
   * When the current assertion was taken.
   */
  since_ms: TimestampMs | null
  /**
   * Why no assertion is held although the setting is on, when that is the case.
   */
  withheld_reason: string | null
}
/**
 * The bounded header every stream sends first.
 */
export interface StreamHeader {
  /**
   * One transport connection, allocated by the host during hello.
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
/**
 * A write that lost its comparison, kept for the person to choose from.
 *
 * Section 20 keeps conflicting copies for user selection instead of silently choosing by
 * wall-clock time, so the rejected content is retained exactly as it arrived and the revision it
 * expected is retained beside it. Nothing here says which copy is right: the person does.
 */
export interface SyncConflictCopy {
  /**
   * The copy.
   */
  conflict_id: string
  /**
   * The revision the object actually held when the write was refused.
   */
  current_revision: string
  /**
   * The revision the writer expected to replace, or null when it expected the object not to
   * exist.
   */
  expected_revision: SyncRevisionId | null
  /**
   * What kind of object it is.
   */
  kind: 'settings' | 'draft' | 'client_selection'
  object: SealedSyncObject
  /**
   * The object the rejected write was about.
   */
  object_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  recorded_at_ms: string
}
/**
 * The rejected content, unchanged.
 */
export interface SealedSyncObject {
  /**
   * The sealed object.
   */
  ciphertext: string
  /**
   * The fresh 24-byte nonce, from libsodium's random generator.
   */
  nonce: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  size_bucket_bytes: string
}
/**
 * One synchronised object as the service holds it now.
 */
export interface SyncObjectRecord {
  /**
   * The collection it belongs to.
   */
  collection_id: string
  /**
   * What kind of object it is.
   */
  kind: 'settings' | 'draft' | 'client_selection'
  object: SealedSyncObject1
  /**
   * The object.
   */
  object_id: string
  /**
   * One revision of one synchronised object. A fresh 128-bit value per accepted write.
   */
  revision: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  updated_at_ms: string
}
/**
 * The sealed object.
 */
export interface SealedSyncObject1 {
  /**
   * The sealed object.
   */
  ciphertext: string
  /**
   * The fresh 24-byte nonce, from libsodium's random generator.
   */
  nonce: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  size_bucket_bytes: string
}
/**
 * Parameters of `terminal.geometry.transfer`.
 *
 * This is the deliberate "use this terminal's size" action. Ordinary attach and input takeover
 * never move size ownership.
 */
export interface TerminalGeometryTransferParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  /**
   * The geometry epoch the caller believes is current.
   */
  expected_geometry_epoch: string
}
/**
 * Parameters of `terminal.resize`.
 *
 * Only the current geometry owner changes the pseudo-terminal.
 */
export interface TerminalResizeParams {
  /**
   * One CLI or application attachment, independently of its device.
   */
  attachment_id: string
  dimensions: Dimensions6
  /**
   * The geometry epoch the caller believes is current.
   */
  expected_geometry_epoch: string
}
/**
 * A terminal geometry in columns and rows.
 *
 * Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
 * allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
 */
export interface Dimensions6 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  columns: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  rows: string
}
/**
 * One reading of the platform time adapter.
 *
 * Every field is what the operating system reported, classified into this build's vocabulary. No
 * field is a measurement of our own, and nothing here contacts a time server: section 9 requires
 * the actual supported platform service and forbids an invented universal authenticated call.
 */
export interface TimeAdapterReading1 {
  /**
   * The service or interface the reading came from.
   */
  api: string
  /**
   * The platform's own estimate of its error, in microseconds, when it reports one.
   */
  estimated_error_us: U64 | null
  /**
   * Which platform adapter produced this reading.
   */
  platform: string
  /**
   * What the platform says is disciplining its clock.
   */
  source: 'network_time_service' | 'pulse_per_second' | 'unsynchronised' | 'unclassified'
  /**
   * What the platform says the state of that synchronisation is.
   */
  status:
    | 'ok'
    | 'insert_leap'
    | 'delete_leap'
    | 'leap_in_progress'
    | 'leap_recovering'
    | 'error'
    | 'unavailable'
  /**
   * The platform's own bound on how wrong its clock may be, in microseconds.
   *
   * Null means the platform reported no bound, which is not the same as a bound of zero.
   */
  uncertainty_us: U64 | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  wall_clock_ms: string
}
/**
 * A durable mark of what this host's wall clock read, and what stood behind it.
 *
 * The boot identity is part of it because a continuous reading means nothing outside the boot it
 * was taken in: the clock restarts, so a deadline from another boot reads as long past rather
 * than as time remaining.
 */
export interface TimeCheckpoint {
  boot_identity: BootIdentity7
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  continuous_ms: string
  reading: TimeAdapterReading2
  /**
   * Whether the wall clock was trusted at the mark.
   */
  trust: 'trusted' | 'unresolved'
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  wall_clock_ms: string
}
/**
 * The boot the mark was taken in.
 */
export interface BootIdentity7 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * The platform reading that stood behind the mark.
 */
export interface TimeAdapterReading2 {
  /**
   * The service or interface the reading came from.
   */
  api: string
  /**
   * The platform's own estimate of its error, in microseconds, when it reports one.
   */
  estimated_error_us: U64 | null
  /**
   * Which platform adapter produced this reading.
   */
  platform: string
  /**
   * What the platform says is disciplining its clock.
   */
  source: 'network_time_service' | 'pulse_per_second' | 'unsynchronised' | 'unclassified'
  /**
   * What the platform says the state of that synchronisation is.
   */
  status:
    | 'ok'
    | 'insert_leap'
    | 'delete_leap'
    | 'leap_in_progress'
    | 'leap_recovering'
    | 'error'
    | 'unavailable'
  /**
   * The platform's own bound on how wrong its clock may be, in microseconds.
   *
   * Null means the platform reported no bound, which is not the same as a bound of zero.
   */
  uncertainty_us: U64 | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  wall_clock_ms: string
}
/**
 * Parameters of `upload.begin`.
 */
export interface UploadBeginParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  declared_byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  declared_digest: string
  /**
   * The media type the client believes it is sending.
   */
  declared_media_type: string
  /**
   * The device the concurrency limit is counted against.
   */
  device_id: DeviceId | null
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The original filename. Metadata: separators, traversal segments and reserved device names
   * never reach the storage path.
   */
  original_file_name: string
  /**
   * The session the upload is for, when it has one.
   */
  session_id: SessionId | null
}
/**
 * The result of `upload.begin`.
 */
export interface UploadBeginResult {
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  layout: ChunkLayout1
  /**
   * The received-chunk bitmap, empty at this point.
   */
  received_chunks: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  staged_byte_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  staged_byte_limit: string
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * The chunk layout the client must follow.
 */
export interface ChunkLayout1 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_count: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  last_chunk_len: string
}
/**
 * Parameters of `upload.cancel`.
 */
export interface UploadCancelParams {
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * The result of `upload.cancel`.
 */
export interface UploadCancelResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  released_byte_len: string
  /**
   * Its state after the cancellation.
   */
  state: 'receiving' | 'publishing' | 'published' | 'cancelled' | 'invalidated' | 'expired'
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * Parameters of `upload.chunk`.
 *
 * This rides the attachment-chunk stream, whose frame bound is one 1 MiB chunk plus its metadata.
 * A control stream cannot carry it.
 */
export interface UploadChunkParams {
  /**
   * The chunk bytes. Their length must equal the descriptor's exactly.
   */
  bytes: string
  chunk: ChunkDescriptor2
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * One chunk's index, exact length and digest.
 */
export interface ChunkDescriptor2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  digest: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  index: string
}
/**
 * The result of `upload.chunk`.
 */
export interface UploadChunkResult {
  /**
   * True when this chunk was already verified with the same digest, so nothing was rewritten.
   */
  duplicate: boolean
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  index: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  received_byte_len: string
  /**
   * Which chunks are verified now.
   */
  received_chunks: string
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * Parameters of `upload.finish`.
 *
 * The declared size and digest are repeated so the host can refuse a client that has changed its
 * mind about what it was sending. A changed source needs a new upload identifier.
 */
export interface UploadFinishParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  declared_byte_len: string
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  declared_digest: string
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * The result of `upload.finish`.
 */
export interface UploadFinishResult {
  /**
   * True when this call found the attachment already published, which is what a retry after a
   * lost reply sees. No second file is ever created.
   */
  already_published: boolean
  handle: AttachmentHandle2
  /**
   * Why no preview was produced, when none was. The file itself is unaffected.
   */
  preview_unavailable: string | null
}
/**
 * The published attachment.
 */
export interface AttachmentHandle2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  byte_len: string
  /**
   * The verified whole-file SHA-256 digest.
   */
  content_digest: string
  /**
   * The media type the client declared. Declared, not sniffed: it says what the client believes
   * it sent.
   */
  declared_media_type: string
  /**
   * The environment that owns the file. A handle never crosses environments.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The original filename, kept as metadata only.
   */
  original_file_name: string
  /**
   * True only when the bytes decoded as one of [`PreviewFormat`]'s formats.
   *
   * Unsupported media transfers as a file and is never presented as a model image, so an adapter
   * reads this rather than guessing from the declared media type or the filename.
   */
  presented_as_image: boolean
  /**
   * The bounded preview, when one could be produced. A failed preview leaves this null and the
   * file itself is unaffected.
   */
  preview: AttachmentPreview | null
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  published_at_ms: string
  /**
   * The session the upload was bound to, when it had one.
   */
  session_id: SessionId | null
  /**
   * True once a draft binding holding this attachment was submitted.
   */
  submitted: boolean
  /**
   * The transfer that produced it, which is also this attachment's durable identity.
   */
  transfer_id: string
}
/**
 * Parameters of `upload.status`.
 */
export interface UploadStatusParams {
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * The result of `upload.status`.
 *
 * This is how a lost reply to `upload.finish` is resolved. A published upload answers with its
 * handle, so a client that never saw the reply learns the file exists instead of sending it again.
 */
export interface UploadStatusResult {
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * The published handle, once there is one.
   */
  handle: AttachmentHandle1 | null
  /**
   * Why the upload was invalidated, when it was.
   */
  invalid_reason: string | null
  layout: ChunkLayout2
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  received_byte_len: string
  /**
   * Which chunks are verified.
   */
  received_chunks: string
  /**
   * Its state.
   */
  state: 'receiving' | 'publishing' | 'published' | 'cancelled' | 'invalidated' | 'expired'
  /**
   * One upload or download transfer.
   */
  transfer_id: string
}
/**
 * Its chunk layout.
 */
export interface ChunkLayout2 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_count: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  chunk_len: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  last_chunk_len: string
}
/**
 * Parameters of `visit.acknowledge`.
 */
export interface VisitAcknowledgeParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  acknowledged_cursor: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The log views this actor had open, with their offsets and filters.
   */
  views: LogViewState[]
}
/**
 * The result of `visit.acknowledge`.
 */
export interface VisitAcknowledgeResult {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  acknowledged_cursor: string
  /**
   * The actor the visit belongs to.
   */
  actor_id: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  revision: string
  /**
   * The views the host retained, after the per-session bound.
   */
  views: LogViewState[]
}
/**
 * Parameters of `visit.changed`.
 */
export interface VisitChangedParams {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  max_changes: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
}
/**
 * The result of `visit.changed`.
 */
export interface VisitChangedResult {
  /**
   * The actor this view belongs to.
   */
  actor_id: string
  /**
   * The semantic changes after the acknowledged cursor, oldest first.
   */
  changes: SemanticChange[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  from_cursor: string
  /**
   * Whether more changes remain past [`VisitChangedResult::to_cursor`].
   */
  more: boolean
  /**
   * The ranges retention evicted before this view could show them.
   *
   * An omitted range is stated. The view never presents a shorter list as if it were the whole
   * of what happened.
   */
  omitted: AttentionGap[]
  /**
   * The summary of this interval, when one was requested and produced.
   */
  summary: ChangeSummary | null
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  to_cursor: string
  /**
   * The log views this actor retained, with any gap retention left in them.
   */
  views: RetainedLogView[]
}
/**
 * What a voice action is hashed over, so one confirmation authorises one action.
 *
 * The digest is built from the plan rather than from the challenge: a challenge that carried the
 * only copy of what was agreed to would be a challenge an attacker could rewrite.
 */
export interface VoiceActionPlan {
  /**
   * The class of action.
   */
  action:
    | 'navigate'
    | 'status'
    | 'brief'
    | 'compose_prompt'
    | 'submit_prompt'
    | 'answer_approval'
    | 'cancel_turn'
    | 'close_session'
    | 'change_grant'
    | 'shell_input'
    | 'apply_diff'
    | 'deliver_externally'
  /**
   * The delegation it was interpreted from, when a delegation caused it.
   */
  delegation_id: VoiceDelegationId | null
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  payload_digest: string
  /**
   * The session it acts on, when it acts on one.
   */
  session_id: SessionId | null
  /**
   * The voice session proposing it.
   */
  voice_session_id: string
}
/**
 * The paired device's answer to a voice confirmation challenge.
 *
 * The ceremony that produces it is the native client's: device-owner authentication on an
 * unlocked screen. What the host verifies is this object, and a model statement that the user
 * agreed to something cannot produce one.
 */
export interface VoiceConfirmationProof {
  request: VoiceConfirmationRequest
  /**
   * The Ed25519 signature over `CBOR(["kr-voice/confirm/1", request])`.
   */
  signature: string
  /**
   * The key identifier of the device identity key that produced it.
   */
  signer_key_id: string
}
/**
 * The challenge this proof answers, byte for byte.
 */
export interface VoiceConfirmationRequest {
  /**
   * The class of action being confirmed.
   */
  action:
    | 'navigate'
    | 'status'
    | 'brief'
    | 'compose_prompt'
    | 'submit_prompt'
    | 'answer_approval'
    | 'cancel_turn'
    | 'close_session'
    | 'change_grant'
    | 'shell_input'
    | 'apply_diff'
    | 'deliver_externally'
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  action_digest: string
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The challenge identity. Single use.
   */
  confirmation_id: string
  /**
   * One paired device.
   */
  device_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The host's fresh challenge nonce.
   */
  nonce: string
  /**
   * The voice session the action belongs to.
   */
  voice_session_id: string
}
/**
 * A host-issued challenge for one voice action that needs an unlocked screen.
 *
 * This is not a [`SensitiveAction`](crate::pairing::SensitiveAction). The owner-confirmation
 * ceremony of section 10 confirms a change to persistent authority; this confirms one action of
 * one voice session, and binding it to the exact action hash and the current request is what
 * stops a confirmation for one action authorising another.
 *
 * Everything the host relies on is inside the signed bytes. A field beside an unsigned signature
 * would be the signer's unauthenticated claim.
 */
export interface VoiceConfirmationRequest1 {
  /**
   * The class of action being confirmed.
   */
  action:
    | 'navigate'
    | 'status'
    | 'brief'
    | 'compose_prompt'
    | 'submit_prompt'
    | 'answer_approval'
    | 'cancel_turn'
    | 'close_session'
    | 'change_grant'
    | 'shell_input'
    | 'apply_diff'
    | 'deliver_externally'
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  action_digest: string
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The challenge identity. Single use.
   */
  confirmation_id: string
  /**
   * One paired device.
   */
  device_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The host's fresh challenge nonce.
   */
  nonce: string
  /**
   * The voice session the action belongs to.
   */
  voice_session_id: string
}
/**
 * Parameters of `voice.context`.
 */
export interface VoiceContextParams {
  /**
   * The delegation this context belongs to, or null for context that belongs to the call.
   */
  delegation_id: VoiceDelegationId | null
  /**
   * Content classes the person has selected on top of the default.
   *
   * Section 15 ¶12 excludes file contents, environment variables, raw terminal scrollback and
   * attachment bytes unless the user selects them, so selecting one is a field rather than a
   * setting somewhere else.
   */
  selected: VoiceContextClass[]
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The voice session asking.
   */
  voice_session_id: string
}
/**
 * The result of `voice.context`.
 *
 * Section 15 ¶9: selected context and host results return from the paired client to the managed
 * broker as bounded context requests. This is what the host hands back to the paired client; the
 * host never sends it to the broker itself.
 */
export interface VoiceContextResult {
  /**
   * What the person is told before a call about what is sent and who can read it.
   */
  disclosure: string[]
  provenance: VoiceContextProvenance
  selection: VoiceContextSelection
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The voice session it was selected for.
   */
  voice_session_id: string
  /**
   * What the grant's history bound kept out, so a gap is visible rather than silent.
   */
  withheld: VoiceWithheld[]
}
/**
 * The interval and resources the selection was built from.
 *
 * Section 10: derived data identifies its source interval and resources.
 */
export interface VoiceContextProvenance {
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  from_ms: string
  /**
   * The resources read, as the host names them.
   */
  resources: string[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  to_ms: string
}
/**
 * What the coordinator selected, as project text.
 */
export interface VoiceContextSelection {
  /**
   * The active application.
   */
  active_application: string
  /**
   * Summaries of the decisions waiting on a person.
   */
  pending_decisions: string[]
  /**
   * The last semantic messages, oldest first, at most
   * [`VOICE_CONTEXT_MESSAGE_COUNT`] of them.
   */
  recent_messages: string[]
  /**
   * How many secret-looking runs were replaced.
   *
   * Section 15 ¶12: stripping configured secret patterns is a secondary measure. A count above
   * zero says something was replaced; a count of zero says nothing was matched, and neither says
   * the remainder holds no secrets.
   */
  secrets_stripped: number
  /**
   * Content classes the person selected, with what each contributed.
   */
  selected: VoiceSelectedContent[]
  /**
   * The session's description.
   */
  session_description: string
  /**
   * What stripping does and does not establish, carried with every selection.
   */
  stripping_note: string
  /**
   * The upper bound on the text tokens this selection costs, counted against
   * [`VOICE_CONTEXT_TOKEN_CAP`].
   *
   * A bound rather than a measurement: the host cannot run the provider's encoder, so it counts
   * something no byte-level tokenizer can exceed. The selection is therefore never larger than
   * the cap and is often smaller than the figure suggests.
   */
  text_tokens: number
  /**
   * True when the cap cut the selection short.
   */
  truncated: boolean
  /**
   * The current working directory.
   */
  working_directory: string
}
/**
 * One class of content the person selected, and what it contributed.
 */
export interface VoiceSelectedContent {
  /**
   * A class of content the default context excludes.
   */
  class: 'file_contents' | 'environment_variables' | 'terminal_scrollback' | 'attachment_bytes'
  /**
   * The text it contributed, already filtered, capped and stripped.
   */
  text: string
}
/**
 * A run of content the history filter kept out of a selection.
 */
export interface VoiceWithheld {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  count: string
  /**
   * Why it was kept out.
   */
  reason: string
}
/**
 * The default context of section 15 ¶12, bounded and separated from coordinator instructions.
 *
 * Every field here is **project text**: data the coordinator submits, never instructions it
 * follows. The separation is in the types rather than in a comment — nothing in this structure
 * can become an instruction, because the instruction side is [`VoiceInstructions`] and the two
 * never share a field.
 */
export interface VoiceContextSelection1 {
  /**
   * The active application.
   */
  active_application: string
  /**
   * Summaries of the decisions waiting on a person.
   */
  pending_decisions: string[]
  /**
   * The last semantic messages, oldest first, at most
   * [`VOICE_CONTEXT_MESSAGE_COUNT`] of them.
   */
  recent_messages: string[]
  /**
   * How many secret-looking runs were replaced.
   *
   * Section 15 ¶12: stripping configured secret patterns is a secondary measure. A count above
   * zero says something was replaced; a count of zero says nothing was matched, and neither says
   * the remainder holds no secrets.
   */
  secrets_stripped: number
  /**
   * Content classes the person selected, with what each contributed.
   */
  selected: VoiceSelectedContent[]
  /**
   * The session's description.
   */
  session_description: string
  /**
   * What stripping does and does not establish, carried with every selection.
   */
  stripping_note: string
  /**
   * The upper bound on the text tokens this selection costs, counted against
   * [`VOICE_CONTEXT_TOKEN_CAP`].
   *
   * A bound rather than a measurement: the host cannot run the provider's encoder, so it counts
   * something no byte-level tokenizer can exceed. The selection is therefore never larger than
   * the cap and is often smaller than the figure suggests.
   */
  text_tokens: number
  /**
   * True when the cap cut the selection short.
   */
  truncated: boolean
  /**
   * The current working directory.
   */
  working_directory: string
}
/**
 * Parameters of `voice.delegate`.
 *
 * Section 15 ¶7: the delegation event supplies an identifier and a timeline offset, not task
 * text. There is deliberately no field for what the model said the user wants; the coordinator
 * uses the accumulated transcripts and current host state.
 */
export interface VoiceDelegateParams {
  /**
   * The action the device asks the coordinator to propose.
   */
  action:
    | 'navigate'
    | 'status'
    | 'brief'
    | 'compose_prompt'
    | 'submit_prompt'
    | 'answer_approval'
    | 'cancel_turn'
    | 'close_session'
    | 'change_grant'
    | 'shell_input'
    | 'apply_diff'
    | 'deliver_externally'
  /**
   * The approval the answer belongs to, when the action answers one.
   */
  approval: VerifiedApprovalAnswer | null
  /**
   * The confirmation from the device's unlocked screen, when the action needs one.
   */
  confirmation: VoiceConfirmationProof | null
  /**
   * An opaque provider delegation identifier. Correlation data, never authority.
   */
  delegation_id: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  offset_ms: string
  /**
   * The session it acts on, when it acts on one.
   */
  session_id: SessionId | null
  /**
   * The spoken confirmation naming the destination session, when the action needs one.
   */
  spoken_destination: SpokenDestination | null
  /**
   * The turn being cancelled, when the action cancels one.
   */
  turn_id: AgentTurnId | null
  /**
   * The voice session the delegation belongs to.
   */
  voice_session_id: string
}
/**
 * An approval answer, with the details of the request it answers.
 *
 * Section 15 ¶13: an approval decision requires the verified request's details and an explicit
 * answer. The host compares the details against the approval it holds, so a model that invented
 * them is refused rather than believed.
 */
export interface VerifiedApprovalAnswer {
  /**
   * An upstream approval request identifier. Opaque to KalaReach.
   */
  approval_request_id: string
  /**
   * The explicit answer. Nothing is inferred from a transcript.
   */
  approved: boolean
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  details_digest: string
}
/**
 * A spoken confirmation that names the destination session.
 *
 * Section 15 ¶13 requires the confirmation to name the destination, so the host checks the name
 * against the session it is about to submit to rather than accepting that one was given.
 */
export interface SpokenDestination {
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * The words the speaker used, as the transcript recorded them. Data, never authority.
   */
  spoken_text: string
}
/**
 * The result of `voice.delegate`.
 */
export interface VoiceDelegateResult {
  /**
   * An opaque provider delegation identifier. Correlation data, never authority.
   */
  delegation_id: string
  /**
   * What the coordinator proposed and what the host did about it.
   */
  outcome:
    | {
        performed: {
          /**
           * One submitted intent and its receipt, generated as a UUIDv4.
           */
          action_id: string
          /**
           * What the coordinator may say about it, bounded to what a context request carries.
           */
          summary: string
        }
      }
    | {
        admitted: {
          /**
           * One submitted intent and its receipt, generated as a UUIDv4.
           */
          action_id: string
          /**
           * What admission does not establish.
           */
          note: string
        }
      }
    | {
        confirmation_required: {
          /**
           * What a person is told, and what is missing.
           */
          message: string
          request: VoiceConfirmationRequest2
        }
      }
    | {
        refused: {
          /**
           * What a person is told, and what is missing.
           */
          message: string
          /**
           * Which rule refused it.
           */
          reason:
            | 'unknown_voice_session'
            | 'unannounced_delegation'
            | 'outside_voice_grant'
            | 'outside_device_grant'
            | 'no_such_effect'
            | 'confirmation_required'
            | 'confirmation_mismatch'
            | 'confirmation_spent'
            | 'destination_not_named'
            | 'approval_not_verified'
            | 'turn_not_named'
            | 'session_outside_voice_session'
        }
      }
}
/**
 * The challenge the device's ceremony signs.
 */
export interface VoiceConfirmationRequest2 {
  /**
   * The class of action being confirmed.
   */
  action:
    | 'navigate'
    | 'status'
    | 'brief'
    | 'compose_prompt'
    | 'submit_prompt'
    | 'answer_approval'
    | 'cancel_turn'
    | 'close_session'
    | 'change_grant'
    | 'shell_input'
    | 'apply_diff'
    | 'deliver_externally'
  /**
   * A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.
   */
  action_digest: string
  /**
   * One submitted intent and its receipt, generated as a UUIDv4.
   */
  action_id: string
  /**
   * The challenge identity. Single use.
   */
  confirmation_id: string
  /**
   * One paired device.
   */
  device_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  expires_at_ms: string
  /**
   * One paired device.
   */
  host_device_id: string
  /**
   * The host's fresh challenge nonce.
   */
  nonce: string
  /**
   * The voice session the action belongs to.
   */
  voice_session_id: string
}
/**
 * Parameters of `voice.grant`.
 */
export interface VoiceGrantParams {
  /**
   * The actions to permit. Absent takes the default scope of section 15 ¶13.
   */
  actions: VoiceAction[] | null
  /**
   * One paired device.
   */
  device_id: string
  /**
   * The sessions the grant covers. Empty covers every session the device's own grant covers.
   */
  session_ids: SessionId[]
}
/**
 * The result of `voice.grant`.
 */
export interface VoiceGrantResult {
  /**
   * One paired device.
   */
  device_id: string
  /**
   * One host-issued authority object.
   */
  grant_id: string
  /**
   * Actions the request asked for that the device's own grant does not carry.
   *
   * A voice grant is intersected with the device's ordinary grant, so asking for more than the
   * device holds narrows rather than enlarges. Naming what was dropped is what stops a person
   * believing they granted something they did not.
   */
  not_held_by_device: VoiceAction[]
  statement: VoiceGrantStatement
}
/**
 * What it permits, stated action by action.
 */
export interface VoiceGrantStatement {
  /**
   * The actions the grant permits.
   */
  actions: VoiceAction[]
  /**
   * One sentence per action, in the order the actions are listed.
   */
  statements: string[]
  /**
   * The actions that still need a confirmation on an unlocked screen every time they are used.
   *
   * Holding the action in the grant is not holding the confirmation. Section 15 ¶8 makes them
   * two separate things, and this field says so where the person reads the grant.
   */
  unlocked_screen_actions: VoiceAction[]
}
/**
 * What a voice grant permits, as the person who chose it is told.
 *
 * Section 15 ¶13: "the change must state which actions it permits". The statement is computed
 * from the action set rather than written beside it, so a grant and its description cannot drift.
 */
export interface VoiceGrantStatement1 {
  /**
   * The actions the grant permits.
   */
  actions: VoiceAction[]
  /**
   * One sentence per action, in the order the actions are listed.
   */
  statements: string[]
  /**
   * The actions that still need a confirmation on an unlocked screen every time they are used.
   *
   * Holding the action in the grant is not holding the confirmation. Section 15 ¶8 makes them
   * two separate things, and this field says so where the person reads the grant.
   */
  unlocked_screen_actions: VoiceAction[]
}
/**
 * Application-authored instructions, which are never project text.
 *
 * Section 15 ¶9 and ¶12 both ask for this separation. It is a separate type with a separate field
 * on the wire so a coordinator cannot accidentally put a session's text where its own
 * instructions go, and a reader can tell which is which without knowing where the value came
 * from.
 */
export interface VoiceInstructions {
  /**
   * The instruction text the application wrote.
   */
  text: string
}
/**
 * A running voice session, as the paired device needs to see it.
 */
export interface VoiceSessionDescriptor {
  /**
   * The provider's SDP answer, to be applied to the caller's own connection.
   */
  answer_sdp: string
  /**
   * The broker's origin, so the device does not have to be configured with it separately.
   */
  broker_origin: string
  /**
   * The broker's identifier for the call. The control socket is addressed by it.
   */
  call_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  closes_at_ms: string
  /**
   * Path on the broker's origin the control socket is opened on.
   */
  control_path: string
  /**
   * What the provider and the managed operator can see, stated where the choice is made.
   */
  disclosure: string[]
  /**
   * One host-issued authority object.
   */
  grant_id: string
  /**
   * Seconds between heartbeats the device is expected to send.
   */
  heartbeat_seconds: number
  /**
   * The model the call is running on.
   */
  model: string
  /**
   * The provider's own session identifier. Opaque; never parsed or constructed.
   */
  provider_session_id: string
  /**
   * The sessions this voice session may reach.
   */
  session_ids: SessionId[]
  statement: VoiceGrantStatement2
  /**
   * The host's identity for this voice session.
   */
  voice_session_id: string
}
/**
 * What that grant permits, stated action by action.
 */
export interface VoiceGrantStatement2 {
  /**
   * The actions the grant permits.
   */
  actions: VoiceAction[]
  /**
   * One sentence per action, in the order the actions are listed.
   */
  statements: string[]
  /**
   * The actions that still need a confirmation on an unlocked screen every time they are used.
   *
   * Holding the action in the grant is not holding the confirmation. Section 15 ¶8 makes them
   * two separate things, and this field says so where the person reads the grant.
   */
  unlocked_screen_actions: VoiceAction[]
}
/**
 * Parameters of `voice.start`.
 */
export interface VoiceStartParams {
  /**
   * Seconds of call the caller is asking to be authorised for.
   */
  duration_seconds: number
  /**
   * The caller's own SDP offer, as its WebRTC stack produced it.
   *
   * The host forwards it to the managed broker unchanged and terminates no media: audio flows
   * between the device and the provider. The host never generates an offer of its own.
   */
  offer_sdp: string
  /**
   * Minor units to hold for reasoning and tools, held separately from the call.
   */
  reasoning_budget_minor: U64 | null
  /**
   * The sessions this voice session may reach. Empty takes every session the voice grant covers.
   */
  session_ids: SessionId[]
}
/**
 * The result of `voice.start`.
 */
export interface VoiceStartResult {
  /**
   * Which of the three outcomes happened.
   */
  outcome:
    | {
        started: {
          session: VoiceSessionDescriptor1
        }
      }
    | {
        creation_unknown: {
          /**
           * The creation attempt, for a later reconciliation to name.
           */
          attempt_id: string
          /**
           * What a person is told. Never a provider credential and never a blame of the host.
           */
          message: string
        }
      }
    | {
        unavailable: {
          /**
           * Paths that still work. A voice session stopping leaves the agent running.
           */
          alternatives: string[]
          /**
           * What a person is told.
           */
          message: string
          /**
           * The broker's own reason, in its vocabulary.
           */
          reason: string
        }
      }
}
/**
 * Everything the device needs to use it.
 */
export interface VoiceSessionDescriptor1 {
  /**
   * The provider's SDP answer, to be applied to the caller's own connection.
   */
  answer_sdp: string
  /**
   * The broker's origin, so the device does not have to be configured with it separately.
   */
  broker_origin: string
  /**
   * The broker's identifier for the call. The control socket is addressed by it.
   */
  call_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  closes_at_ms: string
  /**
   * Path on the broker's origin the control socket is opened on.
   */
  control_path: string
  /**
   * What the provider and the managed operator can see, stated where the choice is made.
   */
  disclosure: string[]
  /**
   * One host-issued authority object.
   */
  grant_id: string
  /**
   * Seconds between heartbeats the device is expected to send.
   */
  heartbeat_seconds: number
  /**
   * The model the call is running on.
   */
  model: string
  /**
   * The provider's own session identifier. Opaque; never parsed or constructed.
   */
  provider_session_id: string
  /**
   * The sessions this voice session may reach.
   */
  session_ids: SessionId[]
  statement: VoiceGrantStatement2
  /**
   * The host's identity for this voice session.
   */
  voice_session_id: string
}
/**
 * Parameters of `voice.stop`.
 */
export interface VoiceStopParams {
  /**
   * The voice session to end.
   */
  voice_session_id: string
}
/**
 * The result of `voice.stop`.
 */
export interface VoiceStopResult {
  /**
   * Whether the broker was told to finalise the call.
   *
   * False is not a failure of the stop. The grant is gone either way; what the broker does with
   * the money is settled on its own schedule, and a host that waited for it would be holding a
   * revocation open for a reason that has nothing to do with authority.
   */
  broker_notified: boolean
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  revoked_at_ms: string
  /**
   * One host-issued authority object.
   */
  revoked_grant_id: string
  /**
   * The terminal sessions this voice session reached, which keep running.
   *
   * Section 15 ¶1: a voice session is not a shell session, and voice can stop while the agent
   * continues.
   */
  sessions_left_running: SessionId[]
  /**
   * The voice session that ended.
   */
  voice_session_id: string
}
/**
 * What the controller publishes so a client can reach a worker without asking the controller.
 *
 * Section 5 requires this file to be owner-only, published atomically and free of secrets. A
 * filename and a process identifier are hints; the public key here is what a challenge is checked
 * against, and the identity fields are what the challenge's answer must match.
 */
export interface WorkerDescriptor {
  boot_identity: BootIdentity8
  /**
   * The local alias.
   */
  display_number: string
  /**
   * The worker's private endpoint.
   */
  endpoint: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  process_start_identity: ProcessStartIdentity8
  protocol_version: ProtocolVersion5
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  published_at_ms: string
  /**
   * The session epoch, fixed at 1 in protocol version 1.
   */
  session_epoch: string
  /**
   * One KalaReach terminal session.
   */
  session_id: string
  /**
   * How long a worker's execution context lasts.
   *
   * The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
   * is closed with `desktop_lost` when its login-session generation ends, while a headless worker
   * survives logout where the platform's user service manager does.
   */
  worker_profile: 'desktop_bound' | 'headless_user'
  /**
   * The public half of the worker's per-session key. The private half exists only in the
   * worker's memory.
   */
  worker_public_key: string
}
/**
 * The boot the worker started in.
 */
export interface BootIdentity8 {
  /**
   * Where the value came from.
   */
  source: 'linux_boot_id' | 'macos_boot_session_uuid' | 'boot_time'
  /**
   * The opaque value. Compared for equality, never interpreted.
   */
  value: string
}
/**
 * A process and the kernel's record of when it started.
 *
 * Every ownership check compares both fields. A process identifier alone can be reused by an
 * unrelated program within milliseconds of the original exiting, so the host never terminates,
 * adopts or trusts a process on its identifier alone.
 */
export interface ProcessStartIdentity8 {
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  pid: string
  /**
   * Where the start value came from.
   */
  source: 'linux_proc_stat' | 'macos_proc_bsd_info' | 'windows_process_start_seconds'
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  start_value: string
}
/**
 * One public protocol version.
 */
export interface ProtocolVersion5 {
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
 * Parameters of `workspace.preview`, which is a read `workspace.create` shares its shape with.
 *
 * This is not a method of its own: `workspace.create` carries the same fields and the daemon
 * answers the preview from the create parameters when `preview_only` is set. One shape is a
 * convenience rather than a binding: a preview and a creation are two independent requests, and
 * a creation returns the preview it was created under, which is what a client shows.
 */
export interface WorkspaceCreateParams {
  /**
   * The change-set version an isolated workspace materialises, when it names one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The revision an isolated workspace starts from, when it names one directly.
   */
  base_revision: string | null
  /**
   * Where an isolated workspace's working tree goes.
   *
   * A shared workspace names none: it is the repository's own tree.
   */
  destination: DestinationRequest3 | null
  /**
   * How an isolated workspace is separated. Ignored for a shared one.
   */
  isolation: IsolationMechanism | null
  /**
   * Which kind it is. Explicit, with no default.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * The label the user gave it.
   */
  label: string
  policy: InclusionPolicy2
  /**
   * Return the preview and create nothing.
   *
   * The create interface previews first, and the preview is this method with nothing written.
   * It is still a mutation in the registry, because the parameters are the same object and a
   * caller that may not create a workspace has no business measuring one.
   */
  preview_only: boolean
  /**
   * The repository to make a working copy of.
   */
  project_repository_id: string
}
/**
 * Where a repository operation puts what it creates.
 *
 * A parent the caller already holds authority over, and one single-component name inside it. The
 * parent is named by a path the host resolves **once**, with its own ambient authority, into a
 * directory handle; everything after that is relative to the handle. A multi-component name is
 * refused, because the operation that creates the entry must not depend on a prefix resolved
 * after the check.
 */
export interface DestinationRequest3 {
  /**
   * The environment the repository will belong to.
   */
  environment_id: string
  /**
   * The single name inside it. No separators, no traversal segment, no reserved device name.
   */
  name: string
  /**
   * The parent directory, as an absolute host path the caller chose.
   */
  parent_path: string
}
/**
 * The inclusion policy, one decision per class.
 */
export interface InclusionPolicy2 {
  /**
   * Files whose content Git reports as binary.
   */
  binary_files: 'include' | 'exclude'
  /**
   * Tracked files with uncommitted modifications.
   */
  dirty_files: 'include' | 'exclude'
  /**
   * Files an ignore rule covers, which is what a build usually produces.
   */
  generated_artefacts: 'include' | 'exclude'
  /**
   * Submodule working trees.
   */
  submodules: 'include' | 'exclude'
  /**
   * Files Git does not track and does not ignore.
   */
  untracked_files: 'include' | 'exclude'
}
/**
 * Result of `workspace.create`.
 */
export interface WorkspaceCreateResult {
  preview: InclusionPreview1
  /**
   * The paths the policy included that this host could not carry into the workspace.
   *
   * A symbolic link, a device, a submodule's own working tree, and a path whose destination
   * this host could not replace. The workspace exists and is usable; what it does not hold is
   * named here rather than left for a reviewer to notice.
   */
  unapplied: string[]
  /**
   * The workspace, or nothing when this was a preview.
   */
  workspace: WorkspaceSummary | null
}
/**
 * What a reviewer would see, always.
 */
export interface InclusionPreview1 {
  /**
   * The change-set version an isolated workspace would materialise, when it names one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The reference that revision was named by, when it was named by one.
   */
  base_reference: string | null
  /**
   * The revision an isolated workspace would start from, as the repository resolved it.
   */
  base_revision: string
  /**
   * One row per class, with exact counts.
   */
  counts: PreviewCount[]
  /**
   * True when every count above is the whole of its class.
   *
   * False when a bound was reached: an ignored directory deeper or larger than the walk
   * covers, or a directory this host could not list. Then each count is a lower bound and the
   * limitations say which bound was reached.
   */
  counts_complete: boolean
  /**
   * A bounded sample of the paths, grouped by class in [`InclusionClass::EVERY`] order.
   */
  entries: PreviewEntry[]
  /**
   * The kind of workspace it was taken for.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * What this preview cannot promise, in the host's own words.
   *
   * A shared workspace is not a sandbox; a worktree shares repository metadata; a working tree
   * can change between the preview and the creation. A client shows this rather than deciding
   * for the user.
   */
  limitations: string[]
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  omitted_entries: string
  policy: InclusionPolicy
  /**
   * The repository the preview was taken on.
   */
  project_repository_id: string
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  taken_at_ms: string
  /**
   * An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.
   */
  unknown_content: string
}
/**
 * Parameters of `workspace.list`.
 */
export interface WorkspaceListParams {
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * One repository to list, or none for every repository in the environment.
   */
  project_repository_id: ProjectRepositoryId | null
}
/**
 * Result of `workspace.list`.
 */
export interface WorkspaceListResult {
  /**
   * The workspaces, oldest first.
   */
  workspaces: WorkspaceSummary[]
}
/**
 * Parameters of `workspace.read`.
 */
export interface WorkspaceReadParams {
  /**
   * The workspace to read.
   */
  workspace_id: string
}
/**
 * Result of `workspace.read`.
 */
export interface WorkspaceReadResult {
  workspace: WorkspaceSummary1
}
/**
 * One workspace, as a scoped read returns it.
 */
export interface WorkspaceSummary1 {
  /**
   * The change-set version it materialised, when it named one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The revision it started from.
   */
  base_revision: string
  /**
   * The automation runs bound to it that are still live.
   *
   * Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
   * between two sessions or after its last one ended, so it is recorded separately and refuses
   * a removal in the same way.
   */
  bound_runs: WorkflowRunId[]
  /**
   * The sessions bound to it that are still live.
   *
   * A removal is refused while this is not empty, whatever retention policy it carries.
   */
  bound_sessions: SessionId[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * Why it is in the state it is in, when it ended up there for a reason.
   */
  detail: string | null
  /**
   * The path it was created at, for a person to read.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The stable filesystem identity of its working tree, once this host has one.
   *
   * Absent while the workspace is being materialised, and absent afterwards only when the
   * materialisation did not get as far as creating the tree. An absent identity is what refuses
   * a removal: this host does not delete a directory it cannot prove it created.
   */
  filesystem_identity: FilesystemIdentity1 | null
  /**
   * How an isolated workspace is separated, when it is one.
   */
  isolation: IsolationMechanism | null
  /**
   * Which kind it is.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * The label the user gave it.
   */
  label: string
  policy: InclusionPolicy1
  /**
   * The repository it is a working copy of.
   */
  project_repository_id: string
  /**
   * What it holds that a removal would have to account for.
   */
  retained: RetainedItem[]
  /**
   * What state it is in.
   */
  state: 'ready' | 'materialising' | 'removal_pending' | 'removed'
  /**
   * Its identity.
   */
  workspace_id: string
}
/**
 * Parameters of `workspace.remove`.
 */
export interface WorkspaceRemoveParams {
  /**
   * What the removal does with what the workspace holds.
   */
  retention: 'keep_everything' | 'remove_retained'
  /**
   * The workspace to remove.
   */
  workspace_id: string
}
/**
 * Result of `workspace.remove`.
 */
export interface WorkspaceRemoveResult {
  /**
   * What is still held, and is waiting for the user's approval.
   */
  retained: RetainedItem[]
  /**
   * True when this workspace's own working files are gone.
   *
   * Read from the filesystem rather than from what the removal did: the tree is not there any
   * more, whether this call removed it, an earlier one did, or the user did. A removal never
   * touches a *shared* workspace's tree, because that tree is the user's own, so this is
   * ordinarily false for one; it says false whenever the host could not establish that the
   * directory is absent.
   */
  working_files_removed: boolean
  workspace: WorkspaceSummary2
}
/**
 * One workspace, as a scoped read returns it.
 */
export interface WorkspaceSummary2 {
  /**
   * The change-set version it materialised, when it named one.
   */
  base_change_set_id: ChangeSetId | null
  /**
   * The revision it started from.
   */
  base_revision: string
  /**
   * The automation runs bound to it that are still live.
   *
   * Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
   * between two sessions or after its last one ended, so it is recorded separately and refuses
   * a removal in the same way.
   */
  bound_runs: WorkflowRunId[]
  /**
   * The sessions bound to it that are still live.
   *
   * A removal is refused while this is not empty, whatever retention policy it carries.
   */
  bound_sessions: SessionId[]
  /**
   * A UTC timestamp in milliseconds, as a decimal string in JSON.
   */
  created_at_ms: string
  /**
   * Why it is in the state it is in, when it ended up there for a reason.
   */
  detail: string | null
  /**
   * The path it was created at, for a person to read.
   */
  display_path: string
  /**
   * One installed OS, distribution or container environment and OS user.
   */
  environment_id: string
  /**
   * The stable filesystem identity of its working tree, once this host has one.
   *
   * Absent while the workspace is being materialised, and absent afterwards only when the
   * materialisation did not get as far as creating the tree. An absent identity is what refuses
   * a removal: this host does not delete a directory it cannot prove it created.
   */
  filesystem_identity: FilesystemIdentity1 | null
  /**
   * How an isolated workspace is separated, when it is one.
   */
  isolation: IsolationMechanism | null
  /**
   * Which kind it is.
   */
  kind: 'shared_existing' | 'isolated'
  /**
   * The label the user gave it.
   */
  label: string
  policy: InclusionPolicy1
  /**
   * The repository it is a working copy of.
   */
  project_repository_id: string
  /**
   * What it holds that a removal would have to account for.
   */
  retained: RetainedItem[]
  /**
   * What state it is in.
   */
  state: 'ready' | 'materialising' | 'removal_pending' | 'removed'
  /**
   * Its identity.
   */
  workspace_id: string
}
