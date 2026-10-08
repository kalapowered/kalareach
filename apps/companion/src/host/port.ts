/**
 * The one surface the interface talks to.
 *
 * Every screen in this application reads protocol values and writes protocol parameters. It does
 * not hold a connection, a socket or a path: it calls a named command and receives what the host
 * returned. That is what lets the same screens run on the desktop, where the commands reach a
 * native backend, and under test, where they reach a scripted host.
 *
 * The types here are the generated protocol types wherever one exists. Where a shape belongs to
 * this application rather than to the wire, it is declared here and nowhere else.
 */

import type {
  ActionRight,
  AgentApprovalInspectParams,
  AgentApprovalInspectResult,
  AgentApprovalRespondParams,
  AgentApprovalRespondResult,
  AgentCancelParams,
  AgentCapabilitiesParams,
  AgentCapabilitiesResult,
  AgentCommandsParams,
  AgentCommandsResult,
  AgentInstanceList,
  AgentMutationResult,
  AgentPromptParams,
  AgentSnapshotParams,
  AgentSnapshotResult,
  AgentSteerParams,
  AttachmentSummary,
  AttentionAcknowledgeParams,
  AttentionAcknowledgeResult,
  AttentionReadParams,
  AttentionReadResult,
  AuthorityNotice,
  CatalogueListParams,
  CatalogueListResult,
  CellRendition,
  ChangesetReadParams,
  ChangesetReadResult,
  ClosureRecord,
  DescriptionConfigureParams,
  DescriptionDownloadParams,
  DescriptionSetup,
  DeviceListParams,
  DeviceListResult,
  Dimensions,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  GrantCreateParams,
  GrantCreateResult,
  GrantListParams,
  GrantListResult,
  HistoryPageParams,
  HistoryPageResult,
  HostInfoResult,
  PaletteState,
  PendingResource,
  PluginListParams,
  PluginListResult,
  ProjectedHyperlink,
  Receipt,
  ReviewAcknowledgeParams,
  ReviewAcknowledgeResult,
  ReviewReadParams,
  ReviewReadResult,
  RoleSelection,
  SessionCreateParams,
  SessionCreateResult,
  SessionDescribeParams,
  SessionDescribeResult,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult,
  VoiceContextResult,
  VoiceAction,
  VoiceDelegateResult,
  VoiceGrantResult,
  VoicePrepareResult,
  VoiceStartResult,
  VoiceStopResult
} from '@kalareach/protocol'

import type { AccountView, UsageView } from '../model/account'
import type { LaunchSurface } from '../model/pending'

/** A failure a command answered with. */
export interface HostError {
  /** The protocol error code. */
  readonly code: string
  /** Plain text for a person. */
  readonly message: string
  /** What the person can do about it, where the client knows. */
  readonly user_action: string
}

/**
 * What a mutation is about.
 *
 * Section 23 makes every mutation state its exact subject. The interface supplies it because the
 * interface is what read it: it saw the session in a list the host sent, with the epoch beside the
 * identifier. The environment is not the page's to choose and comes from the connection itself.
 */
export interface SessionSubject {
  readonly sessionId?: string
  readonly sessionEpoch?: string
  readonly applicationInstanceId?: string
  readonly agentBindingRevision?: string
}

/** What the backend says about the host connection. */
export interface ConnectionState {
  /** True while a session is live. */
  readonly connected: boolean
  /** The environment the connection belongs to, when there is one. */
  readonly environment_id: string | null
  /**
   * Why there is no connection, in plain words, when there is none. Never blank: a reason that is
   * empty or only spaces says nothing, so the page takes it in as null (`receivedConnection`), and a
   * reader's own words for a loss with no reason show in its place.
   */
  readonly reason: string | null
  /**
   * What this connection may do, while it is live, or null when native code has not said. The
   * host checks every right again when an action arrives; this is what a control's visibility is
   * decided from.
   */
  readonly rights: readonly ActionRight[] | null
}

/**
 * A connection state as the page takes it in: a blank reason is no reason.
 *
 * Every state a port hands the page, read or heard, passes through here, so a reader tells a
 * reason from its absence by null alone. A reason with words is kept exactly as it was sent.
 */
export function receivedConnection(sent: ConnectionState): ConnectionState {
  const words = sent.reason?.trim() ?? ''
  return { ...sent, reason: words.length > 0 ? sent.reason : null }
}

/* ---- First-start setup ------------------------------------------------------------------------
 *
 * Three additions, and they are all reads. Setup is where a person is guided through permissions
 * the operating system grants and this application cannot, so nothing here grants, enables or
 * writes anything: it reads what may be done on this desktop, reads the identity a grant would be
 * recorded against, and opens a settings pane the person asked for.
 */

/** The identity an operating system would record a permission against. */
export interface SetupIdentity {
  /** The bundle identifier this build declares, which is what a grant is filed under. */
  readonly application_id: string
  /** The version this build declares. */
  readonly application_version: string
  /** The executable this application is running from. */
  readonly executable: string | null
  /** Whether that executable sits inside an application bundle. */
  readonly bundled: boolean
  /** The signing identity on that executable, as the platform's own tool names it. */
  readonly signature: SigningIdentity
  /** Whether the identity is the same on the next launch. */
  readonly stable: boolean
  /** Why it is not, when it is not. */
  readonly instability: string | null
  /** What this check did not establish, always stated. */
  readonly unverified: string
  /** The host build this application is in contact with, where there is one. */
  readonly helper_build: string | null
  /** The environment that host owns. */
  readonly helper_environment: string | null
}

/** The signature on the application, as the platform reports it. */
export interface SigningIdentity {
  /** Whether the platform read a signature at all. */
  readonly read: boolean
  /** The authority that signed it, where there is one. Absent for an ad-hoc signature. */
  readonly authority: string | null
  /** The team the signature belongs to, where it carries one. */
  readonly team: string | null
  /** The identifier the signature seals, which is what a grant is filed under. */
  readonly identifier: string | null
  /** Whether the signature is ad-hoc: one this machine made, that nothing else can vouch for. */
  readonly ad_hoc: boolean
  /** Whether the platform verified the signature against what it seals, rather than only read it. */
  readonly valid: boolean
  /** What the platform said, where it would not answer. */
  readonly refusal: string | null
}

/** One settings pane this application will open, by name. */
export interface SettingsPane {
  /** The name the interface asks for. */
  readonly id: string
  /** Where the person is going, in the platform's own words. */
  readonly route: string
  /** The address the platform opens that pane with. */
  readonly url: string
}

/* ---- Pairing ------------------------------------------------------------------------------------
 *
 * This computer pairs with a host in native code. The page types a code or presses a button, and
 * is told where the attempt has got to: never an invitation's text, a secret, a key, a transcript,
 * a challenge or a proof. The one secret the page holds is a code a person types into its field.
 */

/** The service codes go through. */
export interface PairingOrigin {
  readonly origin: string
  readonly host: string
  readonly is_default: boolean
}

/** Which of the outcomes a person is told apart an attempt ended with. */
export type FailureKind =
  | 'malformed'
  | 'device_tries_used'
  | 'service_unreachable'
  | 'service_not_pairing'
  | 'no_host_answered'
  | 'not_authenticated'
  | 'host_tries_used'
  | 'expired'
  | 'timed_out'
  | 'did_not_finish'
  | 'declined'
  | 'withdrawn'
  | 'host_restarted'
  | 'another_device_waiting'
  | 'host_unreachable'
  | 'host_mismatch'
  | 'already_paired'
  | 'not_an_invitation'
  | 'newer_invitation'
  | 'nothing_to_paste'
  | 'store_failed'
  | 'approval_unknown'

/** How an attempt ended, with the tries this computer has left when it was charged. */
export interface PairingFailure {
  readonly kind: FailureKind
  readonly tries_left: number | null
}

/** What a paired host is shown as. */
export interface PairedHostView {
  readonly name: string | null
  readonly owner: boolean
  /** What this computer may do there, in words. */
  readonly authority: string
  readonly grant_expires_at_ms: number | null
}

/** Where an attempt has got to. */
export type AttemptState =
  | { readonly state: 'idle' }
  | {
      readonly state: 'working'
      readonly stage: 'reaching_service' | 'checking_code' | 'reaching_host'
    }
  | {
      readonly state: 'awaiting_approval'
      readonly value: string
      readonly expires_at_ms: number | null
      readonly rights: readonly string[]
      /** What those rights would let this computer do, in words. */
      readonly authority: string
      readonly grant_expires_at_ms: number | null
    }
  | {
      readonly state: 'reconnecting'
      readonly value: string | null
      readonly expires_at_ms: number | null
    }
  | { readonly state: 'paired'; readonly host: PairedHostView }
  | {
      readonly state: 'ended'
      readonly failure: PairingFailure
      /** How the attempt was made: a direct invitation is tried again only by pasting it again. */
      readonly mode: 'code' | 'direct'
      /** The service a code attempt went through, which its failures name, when known. */
      readonly service: string | null
    }

/** What a person is shown of an invitation read from the pasteboard. */
export interface InvitationSummary {
  readonly mode: 'code' | 'direct'
  readonly origin_host: string | null
  readonly names_another_origin: boolean
  readonly rights: readonly string[] | null
  /** What a direct invitation's rights would let this computer do, in words. */
  readonly authority: string | null
  readonly grant_expires_at_ms: number | null
  readonly expires_at_ms: number | null
}

/** One host this computer is paired with. */
export interface HostRow {
  /**
   * What this application names the host by when it is asked to use it. It is made by native code,
   * and says nothing of the host's identity.
   */
  readonly reference: string
  /** True when this application's commands go to this host now. */
  readonly in_use: boolean
  readonly name: string
  readonly owner: boolean
  /** What this computer may do there, in words. */
  readonly authority: string
  readonly grant_expires_at_ms: number | null
  readonly in_contact: boolean | null
}

/** Everything the pairing screen shows. */
export interface PairingView {
  readonly origin: PairingOrigin
  readonly device_name: string
  readonly state: AttemptState
  readonly invitation: InvitationSummary | null
  readonly hosts: readonly HostRow[]
}

/** What reading the pasteboard found. */
export interface PasteView {
  readonly invitation: InvitationSummary | null
  readonly failure: FailureKind | null
  readonly cleared: boolean
  readonly declined: boolean
}

/** The ceremony this computer offers an owner. */
export type CeremonyKind = 'touch_id' | 'password' | 'windows_hello' | 'none'

/** One fact a confirmation names: what it is, and its exact value. */
export interface ConfirmationFact {
  readonly label: string
  readonly value: string
  /** True for an address, a hash or a list of identifiers, which is read character by character. */
  readonly code: boolean
}

/** One confirmation a host this computer owns asks for. */
export interface ConfirmationRequest {
  readonly reference: string
  readonly host_name: string
  readonly title: string
  readonly detail: string | null
  readonly value: string | null
  /** Everything the confirmation covers beyond the sentence, one fact to a line. */
  readonly facts: readonly ConfirmationFact[]
  /** What the host says in its own words about code it would place outside the plugin sandbox. */
  readonly notice: string | null
  /** What the publisher says in its own words about the release, quoted apart from the host's. */
  readonly statement: string | null
  readonly expires_at_ms: number
  readonly checkable: boolean
}

/** The confirmations this computer's hosts ask for. */
export interface OwnerView {
  readonly ceremony: CeremonyKind
  readonly requests: readonly ConfirmationRequest[]
}

/**
 * How a review ended. `unknown` is an answer the host was sent and never acknowledged: it may have
 * taken it, and whether it did shows in what it lists next.
 */
export type ReviewOutcome =
  | 'confirmed'
  | 'not_confirmed'
  | 'expired'
  | 'cannot_check'
  | 'no_ceremony'
  | 'unknown'

/* ---- Voice ------------------------------------------------------------------------------------
 *
 * The page drives a voice call and never carries one. Section 15 ¶2 puts capture, playback and the
 * media path in native code, so what crosses this boundary is a request and an answer: the page
 * asks for a call, the native side makes the offer, sends it to the host and applies what comes
 * back, and the page is told what happened. A screen that held a peer connection would be the
 * `getUserMedia` path that paragraph forbids, wearing a different name.
 */

/** What the page asks for when it starts a call. */
export interface VoiceStartRequest {
  /** The sessions the call may reach, as the preparation the person was shown answered them. */
  readonly sessionIds: readonly string[]
  /**
   * The preparation the person was shown, as the host answered it. The host refuses a start whose
   * preparation no longer describes what the call would reach, do or be carried by.
   */
  readonly prepared: string
  /** Seconds of call to ask the service to authorise. */
  readonly durationSeconds: number
  /** Minor units to hold for reasoning and tools, or null to ask for none. */
  readonly reasoningBudgetMinor: string | null
  /**
   * The version of the managed rate the person was shown, as the host's preparation answered it.
   *
   * A start names it so the call runs under the terms the person saw. The service refuses a
   * version that is no longer current, and the answer carries the rate as it is now.
   */
  readonly expectedRateVersion: string
}

/** One action a voice grant permits by default, as the person is shown it before allowing it. */
export interface VoiceScopeAction {
  readonly action: VoiceAction
  /** The sentence the protocol states the action in. */
  readonly sentence: string
  /** True when using it still takes a confirmation on an unlocked screen every time. */
  readonly needs_unlocked_screen: boolean
}

/** What allowing voice on this device permits when the person chooses nothing further. */
export interface VoiceScope {
  readonly actions: readonly VoiceScopeAction[]
}

/**
 * What allowing voice came to: the sentences the grant states and what it could not carry. The
 * device the grant is for is not in it; native code holds that identity.
 */
export interface VoiceAllowed {
  readonly statement: VoiceGrantResult['statement']
  /** The actions asked for that this device's own access to the host does not include. */
  readonly not_held_by_device: readonly VoiceAction[]
}

/** What the page asks when the person allows voice for some of a host's sessions. */
export interface VoiceAllowRequest {
  /** The sessions a call may reach. A call is bound to sessions the grant names. */
  readonly sessionIds: readonly string[]
  /** The actions to permit, or null for the default scope. */
  readonly actions: readonly VoiceAction[] | null
}

/** Which of the two local silences a control acts on. */
export type VoiceMute = 'microphone' | 'playback'

/**
 * What the native call is doing, as the local side alone can report it.
 *
 * Every field here is read from the call this device is holding, so it stays true when nothing can
 * be reached: KR-REQ-15.17 keeps local mute and closure working when the broker fails, and a
 * screen that learned its own mute state from a service would lose it at exactly the moment it
 * matters.
 */
export interface VoiceCallState {
  /** Whether this device is holding a call at all. */
  readonly running: boolean
  /** What the microphone is doing, in the native layer's own vocabulary. */
  readonly capture: string
  /** Whether the model's voice is coming out of this device. */
  readonly playing: boolean
  /**
   * The call's own control channel to the voice service: `none` when it holds none, `connected`,
   * or `unreachable`. Whether the voice service is answering is read from here and nowhere else.
   */
  readonly control: string
}

/** What ending a call did, locally and on the host. */
export interface VoiceClosure {
  /** Whether this device's own call was closed. True whenever a call was running. */
  readonly closed_locally: boolean
  /** The host's answer, or null when the host could not be told. */
  readonly settled: Settled<VoiceStopResult> | null
  /** Why the host could not be told, when it could not. */
  readonly host_failure: HostError | null
}

/** A link the backend is willing to open. */
export interface ApprovedLink {
  readonly scheme: string
  readonly url: string
  readonly host: string | null
}

/** A completed, verified attachment, as `upload.finish` published it. */
export interface AttachmentHandle {
  readonly transfer_id: string
  readonly environment_id: string
  readonly byte_len: string
  readonly content_digest: string
  readonly declared_media_type: string
  readonly original_file_name: string
  readonly presented_as_image: boolean
}

/** One image the person explicitly imported. */
export interface ImportedImage {
  readonly url: string
  readonly media_type: string
  readonly bytes: number[]
}

/** One thing an export deliberately does not carry. */
export interface Omission {
  readonly kind: string
  readonly detail: string
  readonly count: number
}

/** What an export wrote. */
export interface Written {
  readonly path: string
  readonly byte_len: number
  readonly omissions: readonly Omission[]
}

/** The terminal size an export records. */
export interface ExportDimensions {
  readonly columns: number
  readonly rows: number
}

/** One node as an archive carries it. */
export interface ArchivedNode {
  readonly id: string
  readonly revision: string
  readonly body: unknown
  readonly at_ms: number
}

/** One recorded slice of terminal output. */
export interface RecordedFrame {
  readonly at_ms: number
  readonly text: string
}

/**
 * The answer of a mutation: the receipt, and the method's own result when the host returned one.
 *
 * The receipt is what makes an input state "applied", so it travels beside the value rather than
 * being folded into it.
 */
export interface Settled<T = unknown> {
  readonly receipt: Receipt | null
  readonly value: T | null
  /**
   * The action's durable identity.
   *
   * It exists from the moment the request is submitted, before any receipt, so a submission whose
   * outcome is unknown is still one the interface can ask about rather than resubmit.
   */
  readonly action_id: string | null
}

/** The largest file the page may hand native code as bytes, as native code bounds it. */
export const MAX_HANDED_BYTES = 64 * 1024 * 1024

/** A file the platform gave the page: the name it came with, and its bytes. */
export interface HandedFile {
  readonly name: string
  readonly bytes: Uint8Array
}

/** A session's live agent instances, and every request its agents' broker is still arbitrating. */
export interface SessionAgents {
  readonly instances: AgentInstanceList
  readonly resources: readonly PendingResource[]
}

/** What an invitation would carry, in the host's own terms and words. */
export interface GrantNotices {
  /** The actions its role and choices compile to. The host authorises from these, never a role. */
  readonly actions: readonly ActionRight[]
  /** Every notice those actions carry, with the one sentence that states it. */
  readonly notices: readonly { readonly notice: AuthorityNotice; readonly sentence: string }[]
}

/** One event the host pushed. */
export interface HostEvent {
  /** The stream it belongs to. */
  readonly stream_id: string
  /** Its sequence within that stream. */
  readonly sequence: string
  /** The event body. */
  readonly body: unknown
}

/** A file the person dropped, pasted or picked. */
export interface DroppedFile {
  readonly name: string
  readonly media_type: string
  readonly byte_len: number
  /** The bytes, where the platform gave them to the page rather than to the backend. */
  readonly bytes?: Uint8Array
  /** The path, where the platform gave the backend a path instead. */
  readonly path?: string
}

/**
 * The commands the interface may call.
 *
 * One method per command, named for what the person is doing rather than for the wire. Nothing
 * here takes a method name: a screen cannot reach an operation this list does not carry.
 */
export interface HostPort {
  /** Whether a host connection is live, and why not when it is not. */
  connectionState(): Promise<ConnectionState>
  /**
   * Calls `listener` with the connection's state each time native code publishes it. Resolves once
   * the listener is registered, with the function that stops it: a state read after that cannot
   * miss a change.
   */
  onConnection(listener: (state: ConnectionState) => void): Promise<() => void>

  hostInfo(): Promise<HostInfoResult>
  environmentList(): Promise<EnvironmentListResult>

  /**
   * What may actually be done on one environment's desktop.
   *
   * One document per environment: the desktop itself, one record per capability with the state,
   * what produced it, what it was established about and what makes it stale, what a logout does to
   * each execution profile, and the host's sleep setting. First-start setup is built on this, and
   * it is a read: asking for it grants nothing and changes nothing.
   */
  environmentCapabilities(params: unknown): Promise<EnvironmentCapabilitiesResult>

  /** The identity an operating system would record a permission against. */
  setupIdentity(): Promise<SetupIdentity>

  /**
   * Opens one of the platform's settings panes by name.
   *
   * The interface names a pane the application already knows. It never names an address, and this
   * opens a settings pane rather than pressing anything inside it: a grant that needs System
   * Settings cannot be enabled programmatically and this does not pretend to.
   */
  openSettingsPane(pane: string): Promise<SettingsPane>

  sessionList(params: unknown): Promise<SessionListResult>
  sessionRead(params: unknown): Promise<SessionReadResult>
  /**
   * Creates a session in the environment the parameters name. A managed shell the host cannot
   * qualify is refused with `SHELL_INTEGRATION_UNSUPPORTED`; the host never starts a stock shell in
   * its place.
   */
  sessionCreate(
    params: SessionCreateParams,
    subject: SessionSubject
  ): Promise<Settled<SessionCreateResult>>
  sessionClose(params: unknown, subject: SessionSubject): Promise<Settled<ClosureRecord>>
  /**
   * What one session is called and what it is doing: the title and where it came from, the
   * generated activity line when there is one, and how current it is.
   *
   * The parameters name a session and nothing else. A description cannot be asked for, chosen a
   * model for or produced from here; this reads what the host has, filtered for this device.
   */
  sessionDescribe(params: SessionDescribeParams): Promise<SessionDescribeResult>
  /**
   * What session descriptions offer on this host: the exact size and the sources before anything
   * is fetched, how a fetch is going, the two settings, and why nothing is offered when nothing
   * is. A read: asking grants nothing and changes nothing.
   */
  descriptionSetup(): Promise<DescriptionSetup>
  /**
   * Turns descriptions on or off, or whether they may run on battery. A null leaves a setting as
   * it is. Both apply at once on the host, which answers with its setup as it now stands.
   */
  descriptionConfigure(params: DescriptionConfigureParams): Promise<Settled<DescriptionSetup>>
  /**
   * Starts the fetch of the selected profile's files, or stops one that is running. The page names
   * the action and nothing else: what is fetched and from where are the host's own.
   */
  descriptionDownload(params: DescriptionDownloadParams): Promise<Settled<DescriptionSetup>>

  /**
   * What the launch surface may draw right now.
   *
   * The prompt generation in the answer is the one a launch must name. A button drawn at an older
   * generation is disabled rather than launched against a prompt the person has not seen.
   */
  launchSurface(params: unknown): Promise<LaunchSurface>
  shellLaunch(params: unknown, subject: SessionSubject): Promise<Settled<ShellLaunchResult>>

  /**
   * A session's live agent instances, and every request its agents' broker is still arbitrating.
   *
   * Read on the session's own worker, as every page of one snapshot: the page is given the
   * instances and the requests, never parts of two states.
   */
  sessionAgents(sessionId: string): Promise<SessionAgents>
  /** What one agent instance can do now, with the evidence behind each capability. */
  agentCapabilities(params: AgentCapabilitiesParams): Promise<AgentCapabilitiesResult>
  /**
   * One part of an agent instance's semantic history, from the node the parameters name, filtered
   * as this device's authority requires.
   */
  agentSnapshot(params: AgentSnapshotParams): Promise<AgentSnapshotResult>
  /** The commands an agent instance advertises. */
  agentCommands(params: AgentCommandsParams): Promise<AgentCommandsResult>
  /**
   * What an installed decoder read of one approval request and the decisions it offered, with the
   * request's original bytes.
   */
  approvalInspect(params: AgentApprovalInspectParams): Promise<AgentApprovalInspectResult>
  /**
   * The agent mutations. Each names the session, the instance and the binding revision it was
   * prepared against in its own parameters, and nothing else: native code builds the envelope from
   * exactly those, so the two cannot disagree.
   */
  composerSubmit(params: AgentPromptParams): Promise<Settled<AgentMutationResult>>
  composerQueue(params: AgentPromptParams): Promise<Settled<AgentMutationResult>>
  composerSteer(params: AgentSteerParams): Promise<Settled<AgentMutationResult>>
  composerInterrupt(params: AgentCancelParams): Promise<Settled<AgentMutationResult>>
  approvalRespond(params: AgentApprovalRespondParams): Promise<Settled<AgentApprovalRespondResult>>
  pluginActionInvoke(params: unknown, subject: SessionSubject): Promise<Settled>

  draftCreate(params: unknown, subject: SessionSubject): Promise<Settled>
  draftUpdate(params: unknown, subject: SessionSubject): Promise<Settled>
  /**
   * Sends one dropped file to the host and answers with the verified handle.
   *
   * The page never holds the bytes. The platform gave the backend a path when the person dropped
   * the file on the window; this names that path back, and the backend refuses any other.
   */
  attachmentUpload(path: string, subject: SessionSubject): Promise<AttachmentHandle>
  /**
   * Sends one file the platform gave the page rather than a path, pasted onto the window or
   * picked on a phone, and answers with the verified handle.
   *
   * The page hands the bytes to native code, which sends them through the same upload a dropped
   * file takes. A file larger than {@link MAX_HANDED_BYTES} is refused there.
   */
  attachmentUploadBytes(file: HandedFile, subject: SessionSubject): Promise<AttachmentHandle>
  draftAddAttachment(params: unknown, subject: SessionSubject): Promise<Settled>
  /** Reads the bytes behind one validated attachment handle. */
  attachmentImage(params: unknown): Promise<{ bytes: number[]; media_type: string }>

  /**
   * One page of a session's retained output, from the cursor and within the byte bound the
   * parameters name. A live session's is read on its own worker, and an ended one's from the host's
   * archive.
   */
  historyPage(params: HistoryPageParams): Promise<HistoryPageResult>
  attentionRead(params: AttentionReadParams): Promise<AttentionReadResult>
  /** Records that items were seen, each at the revision shown. An environment's, not a session's. */
  attentionAcknowledge(params: AttentionAcknowledgeParams): Promise<Settled<AttentionAcknowledgeResult>>
  /** Which completed turns and change sets wait for review, at which versions. */
  reviewRead(params: ReviewReadParams): Promise<ReviewReadResult>
  /** Records that one exact version was reviewed. It approves nothing and changes no file. */
  reviewAcknowledge(params: ReviewAcknowledgeParams): Promise<Settled<ReviewAcknowledgeResult>>
  questionRead(params: unknown): Promise<unknown>
  questionAnswer(params: unknown, subject: SessionSubject): Promise<Settled>
  /** The devices paired with this host, which is who an invitation can go to. */
  deviceList(params: DeviceListParams): Promise<DeviceListResult>
  /**
   * What an invitation with this role and these choices would carry: the actions they compile to,
   * and every notice those actions carry in the one sentence that states it. It reaches nothing.
   */
  grantNotices(selection: RoleSelection): Promise<GrantNotices>
  grantCreate(params: GrantCreateParams, subject: SessionSubject): Promise<Settled<GrantCreateResult>>
  grantList(params: GrantListParams): Promise<GrantListResult>

  pluginList(params: PluginListParams): Promise<PluginListResult>
  catalogueList(params: CatalogueListParams): Promise<CatalogueListResult>

  changesetRead(params: ChangesetReadParams): Promise<ChangesetReadResult>

  storageStatus(params: unknown): Promise<unknown>
  storageObjectDelete(params: unknown, subject: SessionSubject): Promise<Settled>

  /**
   * Opens a raw terminal view of one session, `grid` in size. Native code attaches it to the
   * session and holds its screen; every state it is in reaches `listener`, and nothing else does.
   * Resolves with the view as soon as native code holds it, before the host has answered anything.
   * A session identifier native code cannot parse, or a size outside a terminal's bounds, is
   * refused with `INVALID_ARGUMENT`, and nothing opens.
   */
  openTerminalView(
    sessionId: string,
    grid: TerminalGrid,
    listener: (state: TerminalViewState) => void
  ): Promise<TerminalView>

  /**
   * What a voice session started now would be, before one exists.
   *
   * Section 15 ¶12 wants the provider and the selected context scope shown before voice starts.
   * This is the read that can answer it: it creates no provider session, reserves nothing and
   * sends no context, so a person can be told what a call would be and then decline it.
   */
  voicePrepare(params: unknown): Promise<VoicePrepareResult>

  /**
   * What allowing voice permits by default, from the protocol's own table, so the question the
   * person is asked is worded as the host states it.
   */
  voiceScope(): Promise<VoiceScope>

  /**
   * Allows voice on this device for some of the host's sessions. Native code names the device; the
   * answer states every action the grant permits and every one the device's own grant could not
   * carry.
   */
  voiceAllow(request: VoiceAllowRequest, subject: SessionSubject): Promise<Settled<VoiceAllowed>>

  /**
   * Starts a call.
   *
   * The offer is the native layer's, which is why the page passes a request rather than protocol
   * parameters: an offer written by anything that could run in this page would name a transport
   * this page does not have.
   */
  voiceStart(request: VoiceStartRequest, subject: SessionSubject): Promise<Settled<VoiceStartResult>>

  /**
   * Ends the call and revokes its grant.
   *
   * The local call closes first and the host is told after, so hanging up works when nothing can
   * be reached (KR-REQ-15.17). The answer says both halves separately rather than reporting a
   * revocation that may not have happened.
   */
  voiceStop(voiceSessionId: string, subject: SessionSubject): Promise<VoiceClosure>

  /** Submits one delegation the provider announced, with its confirmation when one was asked for. */
  voiceDelegate(params: unknown, subject: SessionSubject): Promise<Settled<VoiceDelegateResult>>

  /** Reads the context the host selected for this call, to be sent on as a bounded request. */
  voiceContext(params: unknown): Promise<VoiceContextResult>

  /** Silences the microphone or the speaker on this device. Reaches no service and cancels nothing. */
  voiceSetMuted(what: VoiceMute, muted: boolean): Promise<VoiceCallState>

  /** What the native call is doing right now. */
  voiceCallState(): Promise<VoiceCallState>

  /**
   * Takes a host this computer is paired with, named by its pairing-screen reference, as the one
   * this application's commands go to. Resolves once the first attempt to reach it has ended, with
   * where the connection stands.
   */
  hostsUse(reference: string): Promise<ConnectionState>

  /** Everything the pairing screen shows. */
  pairingView(): Promise<PairingView>
  /** Changes the service codes go through, before an attempt starts. */
  pairingSetOrigin(origin: string): Promise<PairingOrigin>
  /** Starts pairing with a code the person typed. Native code parses it and never hands it back. */
  pairingStartCode(code: string): Promise<void>
  /** Reads an invitation from the pasteboard in native code, and holds it. */
  pairingPaste(): Promise<PasteView>
  /** Starts pairing with the invitation read from the pasteboard. */
  pairingStartRead(): Promise<void>
  /** Ends the attempt on this computer, or drops a pasted invitation. */
  pairingStop(): Promise<void>
  /**
   * Tells `listener` each time the pairing screen's state changes. Resolves, with the function
   * that stops it, once the listener is registered: nothing published before then reaches it.
   */
  onPairing(listener: (view: PairingView) => void): Promise<() => void>

  /** The confirmations this computer's hosts ask for. */
  ownerConfirmations(): Promise<OwnerView>
  /**
   * Reviews one confirmation: native code checks it, the platform's own ceremony asks the person,
   * and only a confirmed ceremony signs it. The page names the reference and nothing else.
   */
  ownerConfirmationReview(reference: string): Promise<ReviewOutcome>
  /**
   * Tells `listener` each time the confirmations change. Resolves, with the function that stops
   * it, once the listener is registered: nothing published before then reaches it.
   */
  onConfirmations(listener: (view: OwnerView) => void): Promise<() => void>

  openExternal(url: string): Promise<ApprovedLink>
  importRemoteImage(url: string): Promise<ImportedImage>
  exportSemanticJson(request: {
    path: string
    sessionId: string
    exportedAtMs: number
    dimensions: ExportDimensions
    nodes: readonly ArchivedNode[]
    omissions: readonly Omission[]
  }): Promise<Written>
  exportAsciicast(request: {
    path: string
    title: string
    startedAtUnixSeconds: number
    dimensions: ExportDimensions
    frames: readonly RecordedFrame[]
    omissions: readonly Omission[]
  }): Promise<Written>

  /** Asks the platform where to write an export. `null` means the person cancelled. */
  chooseExportPath(suggestedName: string): Promise<string | null>

  /** Where this device stands with an account. */
  accountStatus(): Promise<AccountView>

  /**
   * Signs this device in, and settles when the attempt ends.
   *
   * The backend hands the passkey ceremony to the system browser on reach.kala.to. The page names
   * nothing: not the address the browser opens, and never a code or a token. What comes back is
   * where the device stands.
   */
  accountSignIn(): Promise<AccountView>

  /** Ends the sign-in that is waiting for the browser. */
  accountSignInCancel(): Promise<void>

  /** Signs this device out, and tells the service. */
  accountSignOut(): Promise<AccountView>

  /** The account's usage, and nothing about money. */
  accountUsage(): Promise<UsageView>

  /**
   * Tells `listener` where the device stands each time that changes by itself. Resolves, with the
   * function that stops it, once the listener is registered: nothing published before then
   * reaches it.
   */
  onAccount(listener: (view: AccountView) => void): Promise<() => void>

  /**
   * Tells `listener` each event the host publishes. Resolves, with the function that stops it,
   * once the listener is registered: nothing published before then reaches it. The connection's
   * own changes are `onConnection`'s.
   */
  subscribe(listener: (event: HostEvent) => void): Promise<() => void>

  /**
   * Tells `listener` the files the platform hands this window, as they are dropped. Resolves, with
   * the function that stops it, once the listener is registered.
   */
  onFilesDropped(listener: (files: readonly DroppedFile[]) => void): Promise<() => void>
}

/**
 * A view's listeners, from their registration until they stop, and the reads made meanwhile.
 *
 * A view reads the state its listeners follow only while every one of them is registered, so no
 * change they would hear can fall between a read and them, and it shows a read's answer only while
 * the watch runs and no newer read has been started. `read` holds a view to both: it starts nothing
 * before every listener is registered or once the watch has ended, and it answers the check each
 * answer is shown under.
 */
export interface Watch {
  /** Ends the watch: every listener stops, and no read started in it is answered after this. */
  readonly stop: () => void
  /**
   * Starts a read. Until every listener is registered, and once the watch has ended, there is none
   * to start and this answers null. Otherwise it answers a check that stays true while this is the
   * newest read started and the watch has not ended.
   */
  readonly read: () => (() => boolean) | null
}

/**
 * Listens, and then reads.
 *
 * Every listener the port offers resolves once it is registered. This registers all of
 * `registrations` and, once every one of them is, calls `listening`, where a view starts its first
 * read. `stop` stops them all, including one whose registration completes after it, and `listening`
 * is never called after it. The first registration that fails ends the watch at once, as `stop`
 * does, and goes to `failed`.
 */
export function watch(
  registrations: readonly Promise<() => void>[],
  listening: () => void = () => undefined,
  failed: (failure: unknown) => void = () => undefined
): Watch {
  let stage: 'registering' | 'listening' | 'ended' = 'registering'
  let unregistered = registrations.length
  let newest = 0
  const stops: (() => void)[] = []
  const stop = () => {
    stage = 'ended'
    for (const each of stops.splice(0)) each()
  }
  const registered = () => {
    if (stage !== 'registering') return
    stage = 'listening'
    listening()
  }
  if (unregistered === 0) void Promise.resolve().then(registered)
  for (const registration of registrations) {
    void registration.then(
      (unlisten) => {
        if (stage === 'ended') {
          unlisten()
          return
        }
        stops.push(unlisten)
        unregistered -= 1
        if (unregistered === 0) registered()
      },
      (failure: unknown) => {
        if (stage === 'ended') return
        stop()
        failed(failure)
      }
    )
  }
  return {
    stop,
    read: () => {
      if (stage !== 'listening') return null
      newest += 1
      const started = newest
      return () => stage === 'listening' && started === newest
    }
  }
}

/**
 * Follows one state whose every change carries the state itself.
 *
 * `listen` registers for its changes and `read` asks for it once that registration is complete,
 * so no change falls between the two. `show` is given every change heard, and the read's answer
 * only when no change was heard first: a change heard before the answer is at least as new as it.
 * `failed` is given a failure to register or to read, on the same terms. The returned function
 * stops following, including a registration that completes after it was called.
 */
export function follow<T>(
  listen: (listener: (value: T) => void) => Promise<() => void>,
  read: () => Promise<T>,
  show: (value: T) => void,
  failed: (failure: unknown) => void
): () => void {
  let stopped = false
  let heard = false
  const following: Watch = watch(
    [
      listen((value) => {
        if (stopped) return
        heard = true
        show(value)
      })
    ],
    () => {
      const current = following.read()
      if (current === null) return
      const answered = (settle: () => void) => {
        if (current() && !heard) settle()
      }
      // A port can refuse before it returns a promise; that refusal is an answer like any other.
      void (async () => {
        try {
          const value = await read()
          answered(() => {
            show(value)
          })
        } catch (failure: unknown) {
          answered(() => {
            failed(failure)
          })
        }
      })()
    },
    (failure) => {
      if (!heard) failed(failure)
    }
  )
  return () => {
    stopped = true
    following.stop()
  }
}

/** A raw terminal view's grid: the cells its surface holds at its cell size. */
export interface TerminalGrid {
  readonly columns: number
  readonly rows: number
}

/**
 * What a raw terminal view is, as native code publishes it on the view's own channel.
 *
 * Waiting: attached, with no complete screen to draw, before the first or between the host's reset
 * or resynchronisation and the next. Showing: attached, with a complete screen. Ended: the view is
 * over, for a reason in the host's words or the link's, and every move the page made with it is
 * settled. The attachment's summary, which says how the host presents the view and why, rides on
 * the first two, and so does `settled`: the newest of the page's moves it may take as settled,
 * which native code says only with a screen that holds it. So does `control`: whether the view
 * controls the program, told at once whenever it changes.
 */
export type TerminalViewState =
  | {
      readonly state: 'waiting'
      readonly attachment: AttachmentSummary
      readonly settled: number
      readonly control: TerminalControl
    }
  | {
      readonly state: 'showing'
      readonly attachment: AttachmentSummary
      readonly screen: TerminalScreen
      readonly settled: number
      readonly control: TerminalControl
    }
  | { readonly state: 'ended'; readonly reason: string }

/**
 * Whether a view controls the program: it watches, and nothing of the person's reaches the program;
 * it is taking control, and waits for the session's answer; or it holds the session's input, and the
 * program gets its wheel and keys. `number` is the page's newest control request native code took,
 * and `ended` says why control last ended or was refused, until a newer request.
 */
export interface TerminalControl {
  readonly number: number
  readonly state: 'watching' | 'taking' | 'controlling'
  readonly ended: string | null
}

/**
 * Whether a wheel turn over a screen reaches its program: it reports the mouse in an encoding the
 * view writes, it does not report the mouse, or it reports it in an encoding the view does not
 * write.
 */
export type TerminalWheel = 'reaches' | 'unreported' | 'unwritable'

/**
 * What the page tells a view of the person: taking control or giving it back, numbered in the order
 * the page asks, or a turn of the program's wheel at a cell of the session's grid, a key, text or a
 * paste, each made under the page's take `take`. `turns` go towards the person when positive.
 */
export type TerminalInput =
  | { readonly kind: 'take'; readonly number: number }
  | { readonly kind: 'release'; readonly number: number }
  | ({ readonly take: number } & ProgramInput)

/**
 * What reaches the program while a view controls it: its wheel turned at a cell, a key named as the
 * platform reported it, text that came with no key, or a paste. The page never spells a byte:
 * native code spells each in the encoding the program negotiated.
 */
export type ProgramInput =
  | {
      readonly kind: 'wheel'
      /** The cell's column in the session's grid, from 0. */
      readonly column: number
      /** The cell's line of the live screen, from 0. */
      readonly line: number
      readonly turns: number
      readonly shift: boolean
      readonly alt: boolean
      readonly control: boolean
    }
  | ({ readonly kind: 'key'; readonly event: KeyAction } & TypedKey)
  /** Text an input method, a software keyboard or dictation committed, with no control character. */
  | { readonly kind: 'text'; readonly text: string }
  /** Text the person pasted, as it was on the pasteboard. */
  | { readonly kind: 'paste'; readonly text: string }

/** Whether a key went down, repeated while held, or came up. */
export type KeyAction = 'press' | 'repeat' | 'release'

/**
 * The keys of the numeric keypad native code knows, by the code the platform gives their place on
 * the keyboard.
 */
export const KEYPAD_CODES = [
  'Numpad0',
  'Numpad1',
  'Numpad2',
  'Numpad3',
  'Numpad4',
  'Numpad5',
  'Numpad6',
  'Numpad7',
  'Numpad8',
  'Numpad9',
  'NumpadDecimal',
  'NumpadComma',
  'NumpadDivide',
  'NumpadMultiply',
  'NumpadSubtract',
  'NumpadAdd',
  'NumpadEqual',
  'NumpadEnter'
] as const

/** A key of the numeric keypad, by its code. */
export type KeypadCode = (typeof KEYPAD_CODES)[number]

/** One key as its platform reported it, named rather than spelled. */
export interface TypedKey {
  /** The character it made, never a control character, or the name of a key that makes none. */
  readonly key: string
  /** The character it makes with nothing held, where the platform said; null where it did not. */
  readonly base: string | null
  /** The keypad key it is, or null for a key that is not on the keypad. */
  readonly keypad: KeypadCode | null
  readonly shift: boolean
  readonly alt: boolean
  readonly control: boolean
  readonly caps_lock: boolean
  readonly num_lock: boolean
}

/** The window the host drew for a view: its size in cells, and where it starts. */
export interface TerminalWindow {
  readonly rows: number
  readonly columns: number
  /** The first of the session's columns it shows. */
  readonly column: number
  /** The line of the live screen it starts at; 0 in the history. */
  readonly line: number
  /** How many rows above the live screen's first line it starts; 0 on the live screen. */
  readonly above: number
}

/** How many cells a window can still move each way before it reaches a limit. */
export interface TerminalRoom {
  /** Rows up, back into the session's history. */
  readonly up: number
  /** Rows down, as far as the live screen's last line that still fills the window. */
  readonly down: number
  readonly left: number
  /** Columns to the right, as far as the last that still fills the window. */
  readonly right: number
}

/**
 * One move of a view's window, numbered by the page in the order it makes them: by `across` columns
 * and `down` rows (to the right and down when positive), or back to the live screen.
 */
export type TerminalMove =
  | { readonly number: number; readonly across: number; readonly down: number }
  | { readonly number: number; readonly live: true }

/**
 * The arguments native code's commands take for a view's size, as the page's port sends them for
 * `grid`: the opening's and the resize's, beside the session or the view they name.
 */
export function viewSizeArguments(grid: TerminalGrid): { readonly columns: number; readonly rows: number } {
  return { columns: grid.columns, rows: grid.rows }
}

/**
 * The arguments native code's command for a move takes, as the page's port sends them for `move`,
 * beside the view it names. A move that has `live` goes back to the live screen, whatever else it
 * holds.
 */
export function viewMoveArguments(move: TerminalMove): {
  readonly number: number
  readonly across: number
  readonly down: number
  readonly live: boolean
} {
  return 'live' in move
    ? { number: move.number, across: 0, down: 0, live: true }
    : { number: move.number, across: move.across, down: move.down, live: false }
}

/** The part of a session's screen one view shows, as cells, never bytes. */
export interface TerminalScreen {
  /** The session's own size. */
  readonly dimensions: Dimensions
  /** The window the host drew for this view: its size, and where it starts. */
  readonly window: TerminalWindow
  /** How far the window can still move each way. */
  readonly room: TerminalRoom
  /** Exactly the window's rows, top to bottom. */
  readonly lines: readonly TerminalLine[]
  /** The cursor, or null when it is outside the window. */
  readonly cursor: TerminalCursor | null
  /** The session's palette, with where it came from. */
  readonly palette: PaletteState
  /** Whether the session had to shorten content to stay inside a bound. */
  readonly degraded: boolean
  /** How many runs and clusters could not be placed, and are blank or left out. */
  readonly replaced: number
  /** Whether a wheel turn over the screen reaches the program. */
  readonly wheel: TerminalWheel
}

/** One line of a view's window. */
export interface TerminalLine {
  /** The row's stable identifier in the session. */
  readonly row: string
  readonly soft_wrapped: boolean
  /** Whether the session left runs out of the row to keep it inside a page's bound. */
  readonly truncated: boolean
  /** What is drawn on the line, left to right. A cell no piece covers is blank. */
  readonly pieces: readonly TerminalPiece[]
}

/** Text drawn at one column of a line, never past its cells. */
export interface TerminalPiece {
  /** The column, in the window, of its first cell. */
  readonly column: number
  readonly cells: number
  readonly text: string
  /** How it is drawn, with the screen's reverse video already applied. */
  readonly rendition: CellRendition
  /**
   * The link it is inside, as inert metadata: nothing draws or opens it. Its parameters tell it
   * from another link to the same target.
   */
  readonly hyperlink: ProjectedHyperlink | null
}

/** The cursor, in the window's coordinates. */
export interface TerminalCursor {
  readonly column: number
  readonly line: number
  readonly visible: boolean
  /** The cursor-style number the session set. */
  readonly style: number
}

/** One open raw terminal view. */
export interface TerminalView {
  /**
   * Tells the view the page's grid is now `grid`. A size outside a terminal's bounds is refused
   * with `INVALID_ARGUMENT`, and the grid stays as it was.
   */
  resize(grid: TerminalGrid): Promise<void>
  /** Moves the view's window. A move native code cannot read is refused, and nothing moves. */
  move(move: TerminalMove): Promise<void>
  /**
   * Hands the view the person's input. Resolves once native code has taken it; an input the view may
   * not write, since it does not control the program under the take it names, is refused with
   * `LEASE_LOST`, as is any input once the view has ended, and a shape native code does not read
   * with `INVALID_ARGUMENT`. A key, text or paste that cannot reach the program as it reads keys now,
   * or before the view holds the session's screen, is refused with `INPUT_INCOMPATIBLE` and words
   * that say why, and the view keeps control.
   */
  input(input: TerminalInput): Promise<void>
  /** Closes the view. Resolves once it has ended: nothing it publishes arrives after. */
  close(): Promise<void>
}

/** Whether a value is a host failure rather than an unexpected one. */
export function isHostError(value: unknown): value is HostError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as HostError).code === 'string' &&
    typeof (value as HostError).message === 'string'
  )
}

/**
 * What a person can do about a failure, in words, for each key native code names an action by.
 *
 * Section 23 has the interface translate a code into a direct action rather than show the code.
 * Native code attaches the key of the action a code maps to (`UserAction::as_str` in the client
 * library) to every failure it answers with, and these are the words for each key, the library's own
 * (`UserAction::message`). `nothing` has none: the host's words are all there is to say.
 */
export const USER_ACTIONS: Readonly<Record<string, string>> = {
  pair_again: 'Pair this device with the host again.',
  sign_in: 'Sign in to your account.',
  update: 'Update this app or the host: their versions do not agree.',
  wait: 'Wait a moment and try again.',
  resync: 'Refresh: this view has fallen behind.',
  check_the_outcome: 'Check whether this went through before trying it again.',
  fix_configuration: 'Change a setting on this device or on the host.'
}

/**
 * The message to show for a failure, whatever shape it arrived in, and never an empty one: a
 * failure that came with no words of its own is still a failure, and says so in these. A host
 * failure whose code maps to something the person can do says that after the host's words.
 *
 * The client library says a host's refusal as its code, a colon and the host's words. The words are
 * for the person and the code is not, so the code goes: section 23 has the interface translate a
 * code into a direct action, and not show the code by default.
 */
export function failureMessage(value: unknown): string {
  const said = failureWords(value)
  const key = isHostError(value) ? value.user_action : undefined
  const action = typeof key === 'string' && Object.hasOwn(USER_ACTIONS, key) ? USER_ACTIONS[key] : undefined
  if (action === undefined) return said
  const sentence = said.trimEnd()
  return `${sentence}${/[.!?…]$/.test(sentence) ? '' : '.'} ${action}`
}

/**
 * The words of a failure, without the code the client library puts before a host's and without
 * the action, for a place that says what a person can do about it in its own words, or where
 * nothing can be done.
 */
export function failureWords(value: unknown): string {
  const failure = isHostError(value) ? value : null
  const own = failure !== null ? failure.message : value instanceof Error ? value.message : ''
  const codeFirst = failure === null ? '' : `${failure.code}: `
  const words = codeFirst !== '' && own.startsWith(codeFirst) ? own.slice(codeFirst.length) : own
  return words.trim().length > 0 ? words : 'Something went wrong.'
}

/** The protocol code of a failure, or null when it did not carry one. */
export function failureCode(value: unknown): string | null {
  return isHostError(value) ? value.code : null
}
