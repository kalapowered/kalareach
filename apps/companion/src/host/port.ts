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
  ClosureRecord,
  Dimensions4,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  HostInfoResult,
  Receipt,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult,
  VoiceContextResult,
  VoiceDelegateResult,
  VoicePrepareResult,
  VoiceStartResult,
  VoiceStopResult
} from '@kalareach/protocol'
import type { DocumentNode } from '@kalareach/plugin-sdk'

import type { AccountView, UsageView } from '../model/account'
import type { AttentionInbox, LaunchSurface } from '../model/pending'

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
  /** Why there is no connection, in plain words, when there is none. */
  readonly reason: string | null
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
  | { readonly state: 'ended'; readonly failure: PairingFailure }

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

/** One confirmation a host this computer owns asks for. */
export interface ConfirmationRequest {
  readonly reference: string
  readonly host_name: string
  readonly title: string
  readonly detail: string | null
  readonly value: string | null
  readonly expires_at_ms: number
  readonly checkable: boolean
}

/** The confirmations this computer's hosts ask for. */
export interface OwnerView {
  readonly ceremony: CeremonyKind
  readonly requests: readonly ConfirmationRequest[]
}

/** How a review ended. */
export type ReviewOutcome = 'confirmed' | 'not_confirmed' | 'expired' | 'cannot_check' | 'no_ceremony'

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
  /** Milliseconds from the answer being applied to the first audio out, once there has been one. */
  readonly first_audio_ms: number | null
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
  sessionClose(params: unknown, subject: SessionSubject): Promise<Settled<ClosureRecord>>

  /**
   * What the launch surface may draw right now.
   *
   * The prompt generation in the answer is the one a launch must name. A button drawn at an older
   * generation is disabled rather than launched against a prompt the person has not seen.
   */
  launchSurface(params: unknown): Promise<LaunchSurface>
  shellLaunch(params: unknown, subject: SessionSubject): Promise<Settled<ShellLaunchResult>>

  agentSnapshot(params: unknown): Promise<{ nodes: DocumentNode[] }>
  agentCommands(params: unknown): Promise<unknown>
  composerSubmit(params: unknown, subject: SessionSubject): Promise<Settled>
  composerQueue(params: unknown, subject: SessionSubject): Promise<Settled>
  composerSteer(params: unknown, subject: SessionSubject): Promise<Settled>
  composerInterrupt(params: unknown, subject: SessionSubject): Promise<Settled>
  approvalRespond(params: unknown, subject: SessionSubject): Promise<Settled>
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
  draftAddAttachment(params: unknown, subject: SessionSubject): Promise<Settled>
  /** Reads the bytes behind one validated attachment handle. */
  attachmentImage(params: unknown): Promise<{ bytes: number[]; media_type: string }>

  historyPage(params: unknown): Promise<unknown>
  attentionRead(params: unknown): Promise<AttentionInbox>
  attentionAcknowledge(params: unknown, subject: SessionSubject): Promise<Settled>
  questionRead(params: unknown): Promise<unknown>
  questionAnswer(params: unknown, subject: SessionSubject): Promise<Settled>
  grantList(params: unknown): Promise<unknown>
  grantCreate(params: unknown, subject: SessionSubject): Promise<Settled>

  pluginList(params: unknown): Promise<unknown>
  catalogueList(params: unknown): Promise<unknown>

  changesetRead(params: unknown): Promise<unknown>

  storageStatus(params: unknown): Promise<unknown>
  storageObjectDelete(params: unknown, subject: SessionSubject): Promise<Settled>

  terminalProjection(params: unknown): Promise<ProjectedScreen>
  terminalInput(params: unknown): Promise<unknown>
  attachmentViewport(params: unknown, subject: SessionSubject): Promise<Settled>

  /**
   * What a voice session started now would be, before one exists.
   *
   * Section 15 ¶12 wants the provider and the selected context scope shown before voice starts.
   * This is the read that can answer it: it creates no provider session, reserves nothing and
   * sends no context, so a person can be told what a call would be and then decline it.
   */
  voicePrepare(params: unknown): Promise<VoicePrepareResult>

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

  /** Where the device stands, each time it changes by itself. The returned function unsubscribes. */
  onAccount(listener: (view: AccountView) => void): () => void

  /** Subscribes to the host's events. The returned function unsubscribes. */
  subscribe(listener: (event: HostEvent) => void): () => void

  /** The files the platform handed this window, as they are dropped. */
  onFilesDropped(listener: (files: readonly DroppedFile[]) => void): () => void
}

/** One row of the projected screen, as the raw view draws it. */
export interface ProjectedRow {
  /** The row's stable identity above the live screen. */
  readonly row: number
  /** The cells, already resolved to text and attributes. */
  readonly cells: readonly ProjectedCell[]
}

/** One cell of the projected screen. */
export interface ProjectedCell {
  /** The cluster this cell holds. Empty for a continuation cell of a wide cluster. */
  readonly text: string
  /** How many columns the cluster occupies. */
  readonly width: number
  /** The foreground colour, as a palette index or a hex string. */
  readonly fg?: string
  /** The background colour. */
  readonly bg?: string
  /** True when the cell is bold. */
  readonly bold?: boolean
  /** True when the cell is underlined. */
  readonly underline?: boolean
  /** True when the cell is inverted. */
  readonly inverse?: boolean
  /** The hyperlink this cell carries, where the host reported one. */
  readonly link?: string
}

/** Where the palette a projection is drawn with came from. */
export type PaletteProvenance =
  | 'host_default'
  | 'client_probe'
  | 'client_preset'
  | 'session_create'
  | 'unknown'

/** The projected screen a raw terminal view draws. */
export interface ProjectedScreen {
  /** Columns and rows. */
  readonly dimensions: Dimensions4
  /** The rows the host published. */
  readonly rows: readonly ProjectedRow[]
  /** The cursor's column and row. */
  readonly cursor: { readonly column: number; readonly row: number; readonly visible: boolean }
  /** The first row above the live screen this view is showing, or null while it is at the end. */
  readonly viewport_top_row: number | null
  /** The oldest row the host still retains. */
  readonly oldest_retained_row: number
  /** Where the palette came from. */
  readonly palette_provenance: PaletteProvenance
  /** The sixteen palette entries, as hex strings. */
  readonly palette: readonly string[]
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

/** The message to show for a failure, whatever shape it arrived in. */
export function failureMessage(value: unknown): string {
  if (isHostError(value)) return value.message
  if (value instanceof Error) return value.message
  return 'Something went wrong.'
}

/** The protocol code of a failure, or null when it did not carry one. */
export function failureCode(value: unknown): string | null {
  return isHostError(value) ? value.code : null
}
