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
  AttachmentSummary,
  CellRendition,
  ClosureRecord,
  Dimensions,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  HostInfoResult,
  PaletteState,
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
  /**
   * Why there is no connection, in plain words, when there is none. Never blank: a reason that is
   * empty or only spaces says nothing, so the page takes it in as null (`receivedConnection`), and a
   * reader's own words for a loss with no reason show in its place.
   */
  readonly reason: string | null
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

  /**
   * Opens a raw terminal view of one session, `grid` in size. Native code attaches it to the
   * session and holds its screen; every state it is in reaches `listener`, and nothing else does.
   * Resolves with the view as soon as native code holds it, before the host has answered anything.
   */
  openTerminalView(
    sessionId: string,
    grid: TerminalGrid,
    listener: (state: TerminalViewState) => void
  ): Promise<TerminalView>
  terminalInput(params: unknown): Promise<unknown>

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
 * which native code says only with a screen that holds it.
 */
export type TerminalViewState =
  | { readonly state: 'waiting'; readonly attachment: AttachmentSummary; readonly settled: number }
  | {
      readonly state: 'showing'
      readonly attachment: AttachmentSummary
      readonly screen: TerminalScreen
      readonly settled: number
    }
  | { readonly state: 'ended'; readonly reason: string }

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
  /** The link it is inside, as inert metadata: nothing draws or opens it. */
  readonly hyperlink: string | null
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
  /** Tells the view the page's grid is now `grid`. */
  resize(grid: TerminalGrid): Promise<void>
  /** Moves the view's window. */
  move(move: TerminalMove): Promise<void>
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
 * The message to show for a failure, whatever shape it arrived in, and never an empty one: a
 * failure that came with no words of its own is still a failure, and says so in these.
 */
export function failureMessage(value: unknown): string {
  const own = isHostError(value) || value instanceof Error ? value.message : ''
  return own.trim().length > 0 ? own : 'Something went wrong.'
}

/** The protocol code of a failure, or null when it did not carry one. */
export function failureCode(value: unknown): string | null {
  return isHostError(value) ? value.code : null
}
