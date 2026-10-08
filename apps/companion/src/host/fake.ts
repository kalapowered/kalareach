/**
 * A host that answers, without a host.
 *
 * The interface reads protocol values. This produces protocol values. That is the whole of it: the
 * screens under test are the screens that ship, and nothing about them knows whether the answers
 * came from a paired machine or from here.
 *
 * It is a host, not a mock: it keeps state, it refuses what a real host refuses, and a test that
 * drives it through the interface exercises the same code paths. Its one deliberate difference is
 * that time is a number it is told rather than a clock it reads, so a test never waits.
 *
 * This file is reachable only from the test harness entry. The production bundle has one entry and
 * it does not import this.
 */

import type { DocumentNode } from '@kalareach/plugin-sdk'
import type {
  ActionRight,
  AttachmentSummary,
  CapabilityRecord,
  ClosureRecord,
  DescriptionConfigureParams,
  DescriptionDownloadParams,
  DescriptionSetup,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  HostInfoResult,
  PresentationReason,
  Receipt,
  SessionCreateParams,
  SessionCreateResult,
  SessionDescribeResult,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult,
  VoiceAction,
  VoiceContextResult,
  VoiceManagedTerms,
  VoicePrepareResult,
  VoiceRate,
  TerminalPresentationMode,
  VoiceSessionDescriptor
} from '@kalareach/protocol'

import type { LaunchSurface, RetainedArtefacts } from '../model/pending'
import type { AccountView, UsageView } from '../model/account'
import type {
  ApprovedLink,
  ConnectionState,
  DroppedFile,
  HostEvent,
  HostPort,
  ImportedImage,
  KeyAction,
  KeypadCode,
  OwnerView,
  PairingView,
  PasteView,
  ReviewOutcome,
  Settled,
  SettingsPane,
  SetupIdentity,
  TerminalControl,
  TerminalGrid,
  TerminalInput,
  TerminalLine,
  TerminalMove,
  TerminalRoom,
  TerminalScreen,
  TerminalView,
  TerminalViewState,
  TerminalWheel,
  VoiceAllowed,
  VoiceAllowRequest,
  VoiceCallState,
  VoiceScope,
  VoiceStartRequest,
  Written
} from './port'
import { MAX_HANDED_BYTES, receivedConnection, viewMoveArguments, viewSizeArguments } from './port'
import { codeComplete } from '../pairing/words'
import { AGENT_DRAFT_ADD_ATTACHMENT_PARAMS, decodeParams, STORAGE_OBJECT_DELETE_PARAMS } from './fake-decode'
import { EVERY_RIGHT, ScriptedRecords } from './fake-state'

const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'
const VOICE_SESSION = '6c5d4e30-33cc-4d4e-9f5a-000000000201'
const VOICE_GRANT = '5b4c3d20-44dd-4e5f-8a6b-000000000202'
const VOICE_NOW_MS = 1_763_000_000_000
const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const SESSION_OFFLINE = '8a7b6c50-22bb-4c3d-8e4f-000000000103'

/** The moment every timestamp in this host is measured from, so a run is reproducible. */
export const FAKE_NOW_MS = 1_763_000_000_000

/** What native code says when this host cannot be reached, unless a test gives other words. */
const UNREACHABLE = 'this host cannot be contacted right now'

/** A failure shaped the way a command's failure arrives. */
export class FakeHostError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly user_action = 'nothing'
  ) {
    super(message)
    this.name = 'FakeHostError'
  }

  /** The object a rejected command actually carries, which is data rather than an Error. */
  toPayload(): { code: string; message: string; user_action: string } {
    return { code: this.code, message: this.message, user_action: this.user_action }
  }
}

/**
 * Refuses parameters that name anything but the fields a method's shape declares.
 *
 * The host reads every voice method's parameters strictly and refuses an unknown field, so a
 * scripted host that ignored one would let a page pass tests with a request no real host accepts.
 */
function requireFields(params: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    refuse('INVALID_ARGUMENT', 'The parameters are not an object.')
  }
  const named = params as Record<string, unknown>
  const unknown = Object.keys(named).find((key) => !fields.includes(key))
  if (unknown !== undefined) refuse('INVALID_ARGUMENT', `unknown field \`${unknown}\``)
  const missing = fields.find((key) => !(key in named))
  if (missing !== undefined) refuse('INVALID_ARGUMENT', `missing field \`${missing}\``)
  return named
}

function refuse(code: string, message: string): never {
  // A command's failure arrives as data rather than as an Error, because that is what crosses the
  // boundary from the native backend. A test that saw an Error here would be testing a shape the
  // application never receives.
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- see above
  throw new FakeHostError(code, message).toPayload()
}

function receipt(actionId: string, state: Receipt['state'], method: string): Receipt {
  return {
    accepted_deadline_ms: String(FAKE_NOW_MS + 60_000),
    action_id: actionId,
    actor_id: 'device-1',
    error: null,
    method,
    method_version: 1,
    payload_digest: 'f'.repeat(64),
    reason: null,
    revision: '1',
    state,
    updated_at_ms: String(FAKE_NOW_MS)
  }
}

let actionCounter = 0

/** The action identifiers this host has issued, so a test can name one in a later receipt. */
const issuedActions: string[] = []

/**
 * One settled answer whose receipt and identity agree.
 *
 * Every mutation answers with the action it is about, because that identity is what the interface
 * matches a later receipt against.
 */
function settledAs(method: string, state: Receipt['state']): {
  receipt: Receipt
  value: null
  action_id: string
} {
  const actionId = nextActionId()
  return { receipt: receipt(actionId, state, method), value: null, action_id: actionId }
}

function nextActionId(): string {
  actionCounter += 1
  const actionId = `00000000-0000-4000-8000-${String(actionCounter).padStart(12, '0')}`
  issuedActions.push(actionId)
  return actionId
}

/**
 * The account, as the backend reports it: where the device stands, its usage, and the sign-in the
 * page started, which a test settles with the view the attempt ended in. Nothing here opens a link:
 * the backend hands the ceremony to the system browser, and the page never sees the address.
 */
export interface FakeAccount {
  /** How many sign-ins the page asked for. */
  readonly signIns: number
  /** Sets where the device stands and tells the page, as the backend's event does. */
  set(view: AccountView): void
  /** Settles the sign-in that is waiting for the browser. */
  finishSignIn(view: AccountView): void
  /** Sets what a usage read answers. */
  setUsage(usage: UsageView): void
  /** Holds every usage read from now on until the test answers it. */
  holdUsage(): void
  /** Answers the held usage read at `index`, counting from the first one held. */
  answerUsage(index: number, usage: UsageView): void
  /** Makes the next sign-outs fail the way the backend reports it: still signed in. */
  failSignOut(): void
}

/** What the fake host can be told to do before a test drives the interface. */
export interface FakeHostControls {
  /** The account. */
  readonly account: FakeAccount
  /** Pushes one event to every subscriber. */
  emit(event: HostEvent): void
  /**
   * Hands the page one node of a package's declarative presentation, on the host-event stream.
   *
   * No published method carries a package's document, so the conversation's own content is the
   * agent's snapshot and this is the one way a document node reaches a page.
   */
  appendNode(node: DocumentNode, sessionId?: string): void
  /** The records behind the published methods: each session's agent, attention and the rest. */
  readonly records: ScriptedRecords
  /** Moves the prompt generation on, which disables the launch buttons. */
  changePromptGeneration(): void
  /**
   * Marks the host as unreachable, or reachable again, and says so as native code does. `reason`
   * is native code's words for the loss, which can be blank; without it, the host cannot be
   * contacted right now.
   */
  setConnected(connected: boolean, reason?: string): void
  /**
   * Has the connection go to another host, as choosing one does: the environment the connection
   * belongs to changes and is told, the host lists no sessions of the earlier one, and reads of its
   * sessions or of its environments are refused when `refuseSessionList` or `refuseEnvironmentList`
   * is set.
   */
  switchHost(
    environmentId: string,
    options?: { readonly refuseSessionList?: boolean; readonly refuseEnvironmentList?: boolean }
  ): void
  /** Sets what the connection may do, and says so as native code does. */
  setRights(rights: readonly ActionRight[]): void
  /**
   * Takes this host's qualified shell packages away, so a managed creation is refused the way the
   * host refuses one it cannot qualify: with the reason, and never a stock shell in its place.
   */
  withoutQualifiedShell(): void
  /** Every session creation the interface asked for, as it asked. */
  readonly sessionCreates: readonly SessionCreateParams[]
  /**
   * Changes what the host says one session is called and doing: any of the fields of the answer,
   * as a generated description being published, going stale or being pinned over would.
   */
  describe(sessionId: string, change: Partial<SessionDescribeResult>): void
  /** The sessions the interface asked the host to describe, in order. */
  readonly described: readonly string[]
  /**
   * Adds `count` sessions to the host's list, each in a directory of its own, so a list can be
   * longer than a screen.
   */
  addSessions(count: number): void
  /**
   * Reaches the host as a paired device does: every read answers as before, and the host refuses
   * the two writes of description setup, which only its own socket may make.
   */
  reachAsPairedDevice(): void
  /**
   * Changes what description setup says, as the host would after something outside this device
   * changed it: its offer, its settings or how a fetch is going.
   */
  changeDescriptionSetup(change: Partial<DescriptionSetup>): void
  /** The settings the interface asked the host to change, in order, as it asked. */
  readonly descriptionConfigures: readonly DescriptionConfigureParams[]
  /** The fetches the interface asked the host to start or cancel, in order, as it asked. */
  readonly descriptionDownloads: readonly DescriptionDownloadParams[]
  /**
   * Holds every answer to `read` from now on, as a slow backend would, until the test answers it.
   * Each answer is what the host held when the read was made, a refusal included, so a test can
   * change the host while a read is on its way and answer reads in any order.
   */
  hold(read: HeldRead): HeldReads
  /**
   * Holds the answer to every composer send from now on, as a host does that has the request and has
   * not answered it: the host has acted on each send the moment it arrives, and the page hears
   * nothing until the test releases it.
   */
  holdMutation(): HeldMutations
  /** How many composer sends the host has received, answered or held. */
  readonly submissions: number
  /** Hands the window a set of dropped files. */
  dropFiles(files: readonly DroppedFile[]): void
  /** What the interface asked the platform to save, in order. */
  readonly savedExports: Written[]
  /** Every semantic archive the interface asked native code to write, as it asked. */
  readonly exportedArchives: readonly Parameters<HostPort['exportSemanticJson']>[0][]
  /** Every recording the interface asked native code to write, as it asked. */
  readonly exportedCasts: readonly Parameters<HostPort['exportAsciicast']>[0][]
  /** What the interface asked the platform to open, in order. */
  readonly openedLinks: string[]
  /** What the interface explicitly imported, in order. */
  readonly importedImages: string[]
  /** The files the interface sent to the host, in order. */
  readonly uploaded: string[]
  /** The action identifiers this host has issued, in order. */
  readonly actions: string[]
  /**
   * Grants one capability's permission, the way a person granting it in System Settings would.
   *
   * The record's state changes, its evidence becomes a probe that performed the operation, and the
   * revision advances, because a record whose evidence changed under the old revision would let a
   * reader take a superseded answer for a current one.
   */
  grantPermission(capability: string): void
  /** Takes one capability's permission away again. */
  revokePermission(capability: string): void
  /** Makes this build's identity an unstable one, or a stable one again. */
  setIdentityStable(stable: boolean): void
  /** The settings panes the interface asked the platform to open, in order. */
  readonly openedPanes: string[]
  /**
   * Marks the running call's control channel to the voice service as answering, or not.
   *
   * Separate from the host's own reachability on purpose: they are different connections, and
   * what depends on each has to fail separately (section 15 ¶10). Only the call's own state says
   * what the voice service is doing; a host read never does.
   */
  setVoiceBrokerReachable(reachable: boolean): void
  /**
   * Changes what a call started now would reach or do, as a grant change on the host would.
   *
   * A preparation read afterwards describes the new scope, and a start that names the old one is
   * refused, as the host refuses it.
   */
  changeVoiceScope(): void
  /** Makes the next start answer `unavailable` with this reason, or clears that with null. */
  refuseVoiceStart(reason: string | null): void
  /**
   * Moves the managed rate on, as an operator deploying a new one does.
   *
   * A preparation read afterwards quotes the new rate, and a start that names the old version is
   * refused with the new one, as the service refuses it.
   */
  changeVoiceRate(version: string, minorUnitsPerSecond: string): void
  /**
   * What the managed service tells this host about its terms: published, published with the
   * operator's circuit breaker shut, or not read at all.
   */
  setVoiceTerms(state: VoiceTermsState): void
  /** Every start the page asked for, in order, as it asked for it. */
  readonly voiceStarts: VoiceStartRequest[]
  /** Puts the running call's microphone into one of the states a platform reports. */
  setVoiceCapture(state: string): void
  /**
   * Announces one delegation to the running call, as a provider channel would: its identifier,
   * where in the call it happened, and the action it named, or none when `action` is null.
   */
  announceVoiceDelegation(delegationId: string, action?: string | null): void
  /** Changes what the pairing screen shows, as native code would publish it. */
  setPairing(change: Partial<PairingView>): void
  /** The references the page asked to use as the host its commands go to, in order. */
  readonly usedHosts: string[]
  /**
   * Has the host refuse the voice preparation until the person has allowed voice, as a host that
   * holds no voice grant for this device does; allowing it lifts the refusal. `reason` is the
   * host's own words.
   */
  requireVoiceGrant(reason?: string): void
  /** Every allowance of voice the page asked for, as it asked. */
  readonly voiceAllows: VoiceAllowRequest[]
  /** Makes the next allowance of voice fail with `message`, as a host that refused it would. */
  failNextVoiceAllow(message: string): void
  /**
   * Has the next allowance of voice leave out `actions`, as a host does for actions this device's
   * own access to it does not include, and say so.
   */
  holdBackOnNextVoiceAllow(actions: readonly VoiceAction[]): void
  /** Has the next allowance of voice end without the host confirming it, as a lost answer does. */
  leaveNextVoiceAllowUnconfirmed(): void
  /** What the next paste from the clipboard finds. */
  setPasteboard(result: PasteView): void
  /** The codes the page started pairing with, in order. */
  readonly startedCodes: string[]
  /** Sets the confirmations the hosts ask for, as native code would publish them. */
  setConfirmations(view: OwnerView): void
  /** What the next review answers. */
  setReviewOutcome(outcome: ReviewOutcome): void
  /** The references the page asked to review, in order. */
  readonly reviewed: string[]
  /**
   * Holds every listener the page registers from now on (the connection, host events, the
   * account, pairing, confirmations and dropped files), as the desktop shell's registration does
   * until it completes: nothing published meanwhile reaches it. Returns the function that completes
   * the registrations.
   */
  holdRegistrations(): () => void
  /**
   * Sets how the host presents raw terminal views opened from now on: directly, as a viewport for
   * `reason`, as a viewport with no reason (which is how a worker built before reasons reports every
   * viewport), or with null, not as a terminal at all. A view declares a terminal profile of its own,
   * which no host has qualified, so a host presents it as a viewport for that reason unless a test
   * says otherwise.
   */
  presentTerminal(presentation: TerminalPresentationMode | null, reason?: PresentationReason): void
  /**
   * Sets whether the program of the raw terminal views opened from now on reads the wheel: it
   * reports the mouse in an encoding a view writes (as it does unless a test says otherwise), not at
   * all, or in one a view does not write.
   */
  terminalWheel(wheel: TerminalWheel): void
  /**
   * Holds the control requests of every raw terminal view opened from now on: a take waits, taking
   * control, until the test grants or refuses it on the view.
   */
  holdTerminalControl(): void
  /** Holds every raw terminal view opened from now on: nothing is published until the test says. */
  holdTerminalViews(): void
  /**
   * Holds the moves of every raw terminal view opened from now on: each is recorded and nothing is
   * published for it until the test says, as native code waits for the screen the host names.
   */
  holdTerminalMoves(): void
  /**
   * Holds the answer to every raw terminal view opened from now on until the returned function is
   * called, so the page holds no handle for a view that is still opening.
   */
  holdTerminalOpens(): () => void
  /** The raw terminal views the page has opened, oldest first. */
  readonly terminalViews: readonly FakeTerminalView[]
}

/**
 * One raw terminal view the page opened, as native code holds it: the test publishes its states.
 * Nothing is published once the page has closed it, as native code publishes nothing after a close.
 */
export interface FakeTerminalView {
  readonly sessionId: string
  /** The grid it opened at, then each one the page reported. */
  readonly grids: readonly TerminalGrid[]
  /** Whether the page has closed it. */
  readonly closed: boolean
  /** The summary it attached with. */
  readonly attachment: AttachmentSummary
  /** Every move the page made, in the order it made them. */
  readonly moves: readonly TerminalMove[]
  /** Every input the page sent that the view took, in the order it sent them. */
  readonly inputs: readonly TerminalInput[]
  /** Whether the view controls the program, as native code would say. */
  readonly control: TerminalControl
  /** Grants the take in force, as the session would. */
  grantControl(): void
  /** Refuses the take in force, for `reason`, as the session would. */
  refuseControl(reason: string): void
  /**
   * Ends control as a refused write would: another view took it, or the program changed how it reads
   * keys, unless `reason` says otherwise.
   */
  loseControl(reason?: string): void
  /** Publishes that it attached, with no screen yet. */
  attach(): void
  /**
   * Publishes the session's screen at the view's newest grid and where its window now is, with any
   * of its fields replaced by those `screen` gives, as settling the page's moves up to `settled`
   * (the newest move the view has applied, unless the test says otherwise).
   */
  show(screen?: Partial<TerminalScreen>, settled?: number): void
  /** Publishes that it waits for a screen, as after the host's reset. */
  wait(settled?: number): void
  /** Publishes that it ended, for `reason`. */
  end(reason: string): void
  /** Publishes `state` as it is, a malformed one included. */
  publish(state: TerminalViewState): void
  /**
   * Delivers `state` although the page has closed the view: a state native code published before
   * the close reached it, still on its way to the page.
   */
  deliverInFlight(state: TerminalViewState): void
}

/** A read the fake host can hold, named as the port names it. */
export type HeldRead =
  | 'connectionState'
  | 'accountStatus'
  | 'attentionRead'
  | 'sessionRead'
  | 'launchSurface'
  | 'sessionAgents'
  | 'agentCapabilities'
  | 'agentSnapshot'
  | 'agentCommands'
  | 'approvalInspect'
  | 'historyPage'
  | 'reviewRead'
  | 'sessionList'
  | 'sessionDescribe'
  | 'descriptionSetup'
  | 'hostInfo'
  | 'environmentList'
  | 'changesetRead'
  | 'storageStatus'
  | 'pluginList'
  | 'catalogueList'
  | 'deviceList'
  | 'grantList'
  | 'voiceAllow'

/** The reads of one kind a test is holding. */
export interface HeldReads {
  /** How many reads have been held so far. */
  readonly count: number
  /**
   * Answers the read at `index`, counting from the first one held, with what it read. A read that
   * has not been made yet, or has been answered, is left alone.
   */
  answer(index: number): void
  /** Answers every read still held, oldest first, and holds no more. */
  release(): void
}

/** The sends of one kind a test is holding: the host has each, and has not answered it. */
export interface HeldMutations {
  /** How many sends have been held so far. */
  readonly count: number
  /** Answers every send still held, with what the host did with it, and holds no more. */
  release(): void
}

/** The fake host, and the controls a test drives it with. */
export function fakeHost(): { port: HostPort; controls: FakeHostControls } {
  let connected = true
  /** Native code's words for the loss of the connection, while it is lost. */
  let lostBecause = UNREACHABLE
  let promptGeneration = 7
  let bufferRevision = 12
  let pairing: PairingView = {
    origin: { origin: 'https://reach.kala.to', host: 'reach.kala.to', is_default: true },
    device_name: 'studio-mbp',
    state: { state: 'idle' },
    invitation: null,
    hosts: []
  }
  const pairingListeners = new Set<(view: PairingView) => void>()
  const publishPairing = (change: Partial<PairingView>) => {
    pairing = { ...pairing, ...change }
    for (const listener of pairingListeners) listener(pairing)
  }
  let pasteboard: PasteView = {
    invitation: null,
    failure: 'nothing_to_paste',
    cleared: false,
    declined: false
  }
  const startedCodes: string[] = []
  let owner: OwnerView = { ceremony: 'touch_id', requests: [] }
  const ownerListeners = new Set<(view: OwnerView) => void>()
  const publishOwner = (next: OwnerView) => {
    owner = next
    for (const listener of ownerListeners) listener(owner)
  }
  let reviewOutcome: ReviewOutcome = 'confirmed'
  const reviewed: string[] = []
  let registering: Promise<void> = Promise.resolve()
  /** Adds `listener` to `set` once registration completes, and resolves then with its stop. */
  const register = <T,>(
    set: Set<(value: T) => void>,
    listener: (value: T) => void
  ): Promise<() => void> =>
    registering.then(() => {
      set.add(listener)
      return () => {
        set.delete(listener)
      }
    })
  const listeners = new Set<(event: HostEvent) => void>()
  const dropListeners = new Set<(files: readonly DroppedFile[]) => void>()
  const savedExports: Written[] = []
  // The sessions created here, after the ones the host starts with, and what each creation asked.
  const created: SessionSummaryOf[] = []
  const sessionCreates: SessionCreateParams[] = []
  let qualifiedShell = true
  const listed = (): SessionSummaryOf[] => [...sessions().sessions, ...created]
  const exportedArchives: Parameters<HostPort['exportSemanticJson']>[0][] = []
  const exportedCasts: Parameters<HostPort['exportAsciicast']>[0][] = []
  const openedLinks: string[] = []
  const importedImages: string[] = []
  const uploaded: string[] = []
  // How many presentation nodes the host has published.
  let presentation = 0
  // The host's records for every method whose shape the protocol publishes: each session's agent,
  // the attention inbox, review and change sets, sharing, packages and retained output. They are
  // written against the time the host starts, because a screen says how long ago each one was
  // against the time it reads them.
  const records = new ScriptedRecords({
    environment: ENVIRONMENT,
    sessions: { main: SESSION_MAIN, build: SESSION_BUILD, offline: SESSION_OFFLINE },
    nowMs: Date.now()
  })
  /** The raw terminal views the page has opened, oldest first. */
  const terminalViews: FakeTerminalView[] = []
  let holdingTerminalViews = false
  let holdingTerminalMoves = false
  let terminalOpensAnswer: Promise<void> = Promise.resolve()
  let terminalPresentation: {
    readonly presentation: TerminalPresentationMode | null
    readonly reason: PresentationReason | undefined
  } = { presentation: 'viewport', reason: 'unqualified_terminal_profile' }
  let terminalWheel: TerminalWheel = 'reaches'
  let holdingTerminalControl = false
  const deletedArtefacts = new Set<string>()
  const openedPanes: string[] = []
  let capabilityRevision = 4
  let identityStable = true
  const granted = new Set<string>([
    'desktop.application_launch',
    'desktop.authorised_file_read',
    'desktop.display_server'
  ])

  const seed = voiceSeed()
  const voice: VoiceState = {
    call: null,
    delegations: [],
    brokerReachable: seed.brokerReachable,
    startRefusal: null,
    rate: { ...VOICE_TERMS.rate },
    terms: seed.terms,
    scope: 1,
    startCapture: seed.capture
  }
  const voiceStarts: VoiceStartRequest[] = []
  const voiceAllows: VoiceAllowRequest[] = []
  const usedHosts: string[] = []
  /** The words the host refuses a preparation with while no voice grant stands, or none. */
  let voiceGrantMissing: string | null = null
  let voiceAllowFailure: string | null = null
  let voiceHeldBack: readonly VoiceAction[] = []
  let voiceAllowUnconfirmed = false

  let accountView: AccountView = { state: 'signed_out', outcome: null }
  let accountUsage: UsageView = { state: 'signed_out' }
  let usageHeld = false
  const heldUsage: ((usage: UsageView) => void)[] = []
  let signOutFails = false
  let signIns = 0
  let pendingSignIn: ((view: AccountView) => void) | null = null
  const accountListeners = new Set<(view: AccountView) => void>()
  const setAccount = (view: AccountView) => {
    accountView = view
    for (const listener of accountListeners) listener(view)
  }
  const settleSignIn = (view: AccountView) => {
    const settle = pendingSignIn
    pendingSignIn = null
    settle?.(view)
  }

  const requireConnection = () => {
    if (!connected) {
      refuse('RESOURCE_UNAVAILABLE', 'This host cannot be contacted right now.')
    }
  }

  const emit = (event: HostEvent) => {
    for (const listener of listeners) listener(event)
  }
  // What native code says, taken in the way the desktop port takes it in: a blank reason is none.
  // What the connection may do: the host's owner holds every right, unless a test says otherwise.
  let rights: readonly ActionRight[] = EVERY_RIGHT
  let hostEnvironment: string = ENVIRONMENT
  let anotherHost = false
  let sessionListRefused = false
  let environmentListRefused = false
  const connectionNow = (): ConnectionState =>
    receivedConnection({
      connected,
      environment_id: connected ? hostEnvironment : null,
      reason: connected ? null : lostBecause,
      rights: connected ? rights : null
    })
  const connectionListeners = new Set<(state: ConnectionState) => void>()

  /** The answers each held kind of read is waiting to give, in the order the reads were made. */
  const holds = new Map<HeldRead, (() => void)[]>()
  /** The composer sends the host has received, and the ones whose answer a test is holding. */
  let submissions = 0
  let heldSends: (() => void)[] | null = null
  const answeredWhenReleased = <T>(answer: T): Promise<T> => {
    const waiting = heldSends
    return waiting === null
      ? Promise.resolve(answer)
      : new Promise<T>((resolve) => {
          waiting.push(() => {
            resolve(answer)
          })
        })
  }
  /**
   * Answers a read with what the host holds now: at once, or when the test answers it while it
   * holds this kind of read. A refusal is kept as the answer too, and arrives as a rejection then,
   * as a refusal from native code does.
   */
  const reading = <T,>(read: HeldRead, answer: () => T): Promise<T> => {
    const waiting = holds.get(read)
    if (waiting === undefined) return Promise.resolve(answer())
    let settle: (resolve: (value: T) => void, reject: (reason: unknown) => void) => void
    try {
      const value = answer()
      settle = (resolve) => {
        resolve(value)
      }
    } catch (refusal: unknown) {
      settle = (_, reject) => {
        reject(refusal)
      }
    }
    return new Promise<T>((resolve, reject) => {
      waiting.push(() => {
        settle(resolve, reject)
      })
    })
  }

  // What the host says each session is called, and what description setup says. A session the host
  // has said nothing about is called by its directory, as every host can.
  const describedAs = new Map<string, SessionDescribeResult>()
  const describedBy: string[] = []
  let descriptionSetup: DescriptionSetup = {
    offered: true,
    enabled: false,
    on_battery: false,
    profile_id: 'minicpm5-2b-q4-k-m',
    asset_bytes: '1561318368',
    sources: ['huggingface.co'],
    download: 'not_started',
    fetched_bytes: '0',
    failure: null,
    can_cancel: false,
    can_disable: true,
    needs_hosted_account: false,
    unavailable: null,
    state: 'resource_paused',
    paused: 'disabled'
  } as unknown as DescriptionSetup
  const descriptionConfigures: DescriptionConfigureParams[] = []
  const descriptionDownloads: DescriptionDownloadParams[] = []
  /**
   * Answers a description write with the setup as it now stands. The host's own local writes answer
   * with their result, not a receipt, and the action still has the identity it was submitted under.
   */
  const settledSetup = (): Promise<Settled<DescriptionSetup>> =>
    Promise.resolve({ receipt: null, action_id: nextActionId(), value: { ...descriptionSetup } })
  const requireOwner = () => {
    requireConnection()
    if (!rights.includes('host.manage')) {
      refuse('PERMISSION_DENIED', 'This device may not manage this host.')
    }
  }
  let pairedDevice = false
  /** The two writes of description setup are the host's own to make: a paired device is refused. */
  const requireLocalSocket = (change: 'a setting' | 'the download') => {
    requireOwner()
    if (pairedDevice) {
      refuse(
        'PERMISSION_DENIED',
        `Session descriptions are set up at the host itself: ${change} is not changed from a paired device.`
      )
    }
  }

  const port: HostPort = {
    connectionState: () => reading('connectionState', connectionNow),
    onConnection: (listener) => register(connectionListeners, listener),

    environmentCapabilities: (params) => {
      requireConnection()
      const asked = (params as { environment_id?: string } | null)?.environment_id
      if (asked && asked !== ENVIRONMENT) {
        refuse('NOT_FOUND', 'This host does not own that environment.')
      }
      return Promise.resolve(capabilities(granted, capabilityRevision))
    },

    setupIdentity: () => Promise.resolve(setupIdentity(identityStable, connected)),

    openSettingsPane: (pane) => {
      const found = SETTINGS_PANES.find((each) => each.id === pane)
      if (!found) {
        refuse('PERMISSION_DENIED', `${pane} is not a settings pane this application opens.`)
      }
      openedPanes.push(pane)
      return Promise.resolve(found)
    },

    hostInfo: () =>
      reading('hostInfo', () => {
        requireConnection()
        return hostInfo()
      }),
    environmentList: () =>
      reading('environmentList', () => {
        requireConnection()
        if (environmentListRefused) {
          refuse('PERMISSION_DENIED', 'This device may not list the environments of this host.')
        }
        return environments(hostEnvironment, anotherHost ? 'another host · Linux' : null)
      }),

    sessionList: () =>
      reading('sessionList', () => {
        requireConnection()
        if (sessionListRefused) {
          refuse('PERMISSION_DENIED', 'This device may not list the sessions of this host.')
        }
        return { sessions: anotherHost ? [] : listed() }
      }),
    sessionRead: (params) =>
      reading('sessionRead', () => {
        requireConnection()
        const sessionId = (params as { session_id?: string }).session_id ?? SESSION_MAIN
        const found = listed().find((session) => session.session_id === sessionId)
        if (!found) refuse('UNKNOWN_SESSION', 'That session is not on this host.')
        return { endpoint: null, session: found } as unknown as SessionReadResult
      }),
    sessionCreate: (params) => {
      requireConnection()
      sessionCreates.push(params)
      if (!rights.includes('session.create')) {
        refuse('PERMISSION_DENIED', 'This device may not create sessions on this host.')
      }
      if (params.environment_id !== ENVIRONMENT) {
        refuse('NOT_FOUND', 'This host does not own that environment.')
      }
      if (params.launch_profile.command_integrations.length > 0) {
        refuse('INVALID_ARGUMENT', 'A create request names no command integrations.')
      }
      // A managed session runs a qualified package or nothing: the host names what is missing and
      // never launches a stock shell in its place.
      if (params.shell_mode === 'managed' && !qualifiedShell) {
        refuse(
          'SHELL_INTEGRATION_UNSUPPORTED',
          'no qualified shell packages are installed; KR_SHELL_PACKAGES names none either'
        )
      }
      const summary = createdSession(params, created.length)
      created.push(summary)
      records.startShell(summary.session_id)
      const result: SessionCreateResult = {
        deduplicated: false,
        endpoint: null,
        presentation_error: null,
        session: summary
      }
      return Promise.resolve({
        receipt: receipt(nextActionId(), 'applied', 'session.create'),
        action_id: null,
        value: result
      })
    },
    sessionClose: (params) => {
      requireConnection()
      const sessionId = (params as { session_id?: string }).session_id ?? SESSION_MAIN
      const closure: ClosureRecord = {
        closed_at_ms: String(FAKE_NOW_MS),
        durability: 'durable',
        exit_status: null,
        reason: 'requested'
      } as unknown as ClosureRecord
      emit({
        stream_id: `session_state:${sessionId}`,
        sequence: '1',
        body: { kind: 'session_closed', session_id: sessionId }
      })
      return Promise.resolve({
        receipt: receipt(nextActionId(), 'applied', 'session.close'),
        action_id: null,
        value: closure
      })
    },

    sessionDescribe: (params) =>
      reading('sessionDescribe', () => {
        requireConnection()
        const sessionId = params.session_id
        const found = listed().find((session) => session.session_id === sessionId)
        if (!found) refuse('UNKNOWN_SESSION', 'That session is not on this host.')
        describedBy.push(sessionId)
        return (
          describedAs.get(sessionId) ?? {
            session_id: sessionId,
            title: found.cwd.split('/').filter(Boolean).pop() ?? found.cwd,
            source: 'metadata',
            activity_text: null,
            freshness: 'none',
            provenance: null,
            queued_age_ms: null,
            last_success_ms: null,
            cadence_ms: '30000',
            state: descriptionSetup.state,
            paused: descriptionSetup.paused
          }
        )
      }),
    descriptionSetup: () =>
      reading('descriptionSetup', () => {
        requireOwner()
        return { ...descriptionSetup }
      }),
    descriptionConfigure: (params) => {
      requireLocalSocket('a setting')
      descriptionConfigures.push(params)
      const was = descriptionSetup.enabled
      const enabled = params.enabled ?? descriptionSetup.enabled
      descriptionSetup = {
        ...descriptionSetup,
        enabled,
        on_battery: params.on_battery ?? descriptionSetup.on_battery,
        // Turning descriptions off ends a fetch that is running, as the host does.
        ...(was && !enabled && descriptionSetup.download === 'running'
          ? { download: 'cancelled', fetched_bytes: '0', can_cancel: false }
          : {}),
        ...(enabled ? { paused: null } : { paused: 'disabled' })
      }
      return settledSetup()
    },
    descriptionDownload: (params) => {
      requireLocalSocket('the download')
      descriptionDownloads.push(params)
      if (params.action === 'start') {
        if (!descriptionSetup.offered) {
          refuse('RESOURCE_UNAVAILABLE', 'this host has no model to fetch')
        }
        if (descriptionSetup.download !== 'running' && descriptionSetup.download !== 'verified') {
          descriptionSetup = {
            ...descriptionSetup,
            download: 'running',
            fetched_bytes: '0',
            failure: null,
            can_cancel: true
          }
        }
      } else if (descriptionSetup.download === 'running') {
        descriptionSetup = {
          ...descriptionSetup,
          download: 'cancelled',
          fetched_bytes: '0',
          can_cancel: false
        }
      }
      return settledSetup()
    },
    launchSurface: (params) =>
      reading('launchSurface', () => {
        requireConnection()
        // A stock shell's editor is not the host's to see, so its prompt is never verified empty.
        const sessionId = (params as { session_id?: string } | null)?.session_id
        const stock = listed().some(
          (session) => session.session_id === sessionId && session.shell_mode === 'native_compat'
        )
        return fakeLaunchSurface(!stock, String(promptGeneration))
      }),
    shellLaunch: (params) => {
      requireConnection()
      const asked = params as { expected_prompt_generation?: string; expected_buffer_revision?: string }
      if (asked.expected_prompt_generation !== String(promptGeneration)) {
        refuse('DRAFT_CONFLICT', 'The prompt moved on before the launch was installed.')
      }
      bufferRevision += 1
      const result: ShellLaunchResult = {
        buffer_revision: String(bufferRevision),
        fence_id: '00000000-0000-4000-8000-0000000000ff',
        prompt_generation: String(promptGeneration)
      }
      return Promise.resolve({
        receipt: receipt(nextActionId(), 'applied', 'shell.launch'),
        action_id: null,
        value: result
      })
    },

    // The agent's calls, as the session's own worker answers them.
    sessionAgents: (sessionId) =>
      reading('sessionAgents', () => {
        requireConnection()
        if (!isSessionId(sessionId)) refuse('INVALID_ARGUMENT', 'that is not a session identifier')
        return records.sessionAgents(sessionId)
      }),
    agentCapabilities: (params) =>
      reading('agentCapabilities', () => {
        requireConnection()
        return records.capabilities(params)
      }),
    agentSnapshot: (params) =>
      reading('agentSnapshot', () => {
        requireConnection()
        return records.snapshot(params)
      }),
    agentCommands: (params) =>
      reading('agentCommands', () => {
        requireConnection()
        return records.commands(params)
      }),
    approvalInspect: (params) =>
      reading('approvalInspect', () => {
        requireConnection()
        return records.inspect(params)
      }),
    composerSubmit: (params) => {
      requireConnection()
      submissions += 1
      return answeredWhenReleased(records.prompt(params, false))
    },
    composerQueue: (params) => {
      requireConnection()
      submissions += 1
      return answeredWhenReleased(records.prompt(params, true))
    },
    composerSteer: (params) => {
      requireConnection()
      return Promise.resolve(records.steer(params))
    },
    composerInterrupt: (params) => {
      requireConnection()
      return Promise.resolve(records.cancel(params))
    },
    approvalRespond: (params) => {
      requireConnection()
      return Promise.resolve(records.respond(params))
    },
    pluginActionInvoke: (params) => {
      requireConnection()
      const actionId = (params as { action_id?: string }).action_id ?? 'unknown'
      return Promise.resolve({
        receipt: receipt(nextActionId(), 'applied', 'plugin.action.invoke'),
        action_id: null,
        value: { invoked: actionId }
      })
    },

    draftCreate: () =>
      Promise.resolve(settledAs('draft.create', 'applied')),
    draftUpdate: () =>
      Promise.resolve(settledAs('draft.update', 'applied')),
    attachmentUpload: (path) => {
      requireConnection()
      const name = path.split('/').pop() ?? path
      uploaded.push(path)
      return Promise.resolve({
        transfer_id: '99999999-9999-4999-8999-999999999999',
        environment_id: ENVIRONMENT,
        byte_len: '10',
        content_digest: 'a'.repeat(64),
        declared_media_type: 'image/png',
        original_file_name: name,
        presented_as_image: true
      })
    },
    attachmentUploadBytes: (file) => {
      requireConnection()
      if (file.bytes.length > MAX_HANDED_BYTES) {
        refuse('QUOTA_EXCEEDED', 'a pasted or picked file is at most 64 MiB; drop a larger one on the window')
      }
      // Native code keeps the last component of the name, as metadata.
      const name = file.name.split(/[\\/]/).pop()?.trim() || 'attachment'
      uploaded.push(name)
      return Promise.resolve({
        transfer_id: '99999999-9999-4999-8999-999999999998',
        environment_id: ENVIRONMENT,
        byte_len: String(file.bytes.length),
        content_digest: 'b'.repeat(64),
        declared_media_type: /\.png$/i.test(name) ? 'image/png' : 'application/octet-stream',
        original_file_name: name,
        presented_as_image: /\.png$/i.test(name)
      })
    },
    draftAddAttachment: (params) => {
      requireConnection()
      // Native code reads the method's own parameters, the integration's contribution included,
      // before anything reaches a host.
      const read = decodeParams<{
        contribution: { insertion_method: string }
      }>(params, AGENT_DRAFT_ADD_ATTACHMENT_PARAMS)
      if (read.contribution.insertion_method === 'verified_composer_insertion') {
        // The specification's own rule: a nonempty or unknown buffer returns DRAFT_CONFLICT, the
        // draft is retained, and the person is offered the terminal workflow instead.
        refuse('DRAFT_CONFLICT', 'The agent composer is not at an empty, qualified boundary.')
      }
      return Promise.resolve(settledAs('agent.draft.add_attachment', 'applied'))
    },
    attachmentImage: () =>
      Promise.resolve({
        // A one-pixel PNG, which is what an attachment handle resolves to here.
        bytes: [
          137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8,
          6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 250, 207, 0, 0,
          3, 1, 1, 0, 24, 221, 141, 219, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130
        ],
        media_type: 'image/png'
      }),

    historyPage: (params) =>
      reading('historyPage', () => {
        requireConnection()
        return records.history(params)
      }),
    attentionRead: (params) =>
      reading('attentionRead', () => {
        requireConnection()
        return records.attentionRead(params)
      }),
    attentionAcknowledge: (params) => {
      requireConnection()
      return Promise.resolve(records.attentionAcknowledge(params))
    },
    reviewRead: (params) =>
      reading('reviewRead', () => {
        requireConnection()
        return records.reviewRead(params)
      }),
    reviewAcknowledge: (params) => {
      requireConnection()
      return Promise.resolve(records.reviewAcknowledge(params))
    },
    questionRead: () =>
      Promise.resolve({
        questions: [
          {
            question_id: 'q-1',
            revision: '2',
            prompt: 'Which branch should the release be cut from?',
            options: ['main', 'release/2026-09']
          }
        ]
      }),
    questionAnswer: () =>
      Promise.resolve(settledAs('question.answer', 'applied')),
    deviceList: (params) =>
      reading('deviceList', () => {
        requireConnection()
        return records.deviceList(params)
      }),
    // What an invitation would carry is native code's own reading of the protocol's table, and it
    // reaches no host.
    grantNotices: (selection) => Promise.resolve(records.grantNotices(selection)),
    grantCreate: (params) => {
      requireConnection()
      return Promise.resolve(records.grantCreate(params))
    },
    grantList: (params) =>
      reading('grantList', () => {
        requireConnection()
        return records.grantList(params)
      }),

    pluginList: (params) =>
      reading('pluginList', () => {
        requireConnection()
        return records.pluginList(params)
      }),
    catalogueList: (params) =>
      reading('catalogueList', () => {
        requireConnection()
        return records.catalogueList(params)
      }),

    changesetRead: (params) =>
      reading('changesetRead', () => {
        requireConnection()
        return records.changesetRead(params)
      }),

    storageStatus: () =>
      reading('storageStatus', () => {
        requireConnection()
        return retained(deletedArtefacts)
      }),
    // Read as the request's own type is read, and answered as a rejection: a request that is not the
    // artefact's identifier alone is refused by name, and nothing is deleted by it.
    storageObjectDelete: (params) =>
      Promise.resolve().then(() => {
        const { object_id: id } = decodeParams<{ object_id: string }>(params, STORAGE_OBJECT_DELETE_PARAMS)
        const artefact = retained(new Set()).artefacts.find((each) => each.object_id === id)
        if (artefact?.held_by_other_party) {
          refuse(
            'PERMISSION_DENIED',
            'A copy an authorised viewer holds is not reachable from this host.'
          )
        }
        deletedArtefacts.add(id)
        return settledAs('storage.object.delete', 'applied')
      }),

    // The command the page's port sends, read as native code reads it: its arguments decoded in
    // order, then the session identifier parsed and the size checked, or nothing opens.
    openTerminalView: (sessionId, grid, listener) => {
      const args = { sessionId, ...viewSizeArguments(grid) }
      const undecoded = undecodable('terminal_view_open', args, [
        ['sessionId', aString],
        ['columns', anInteger(U64)],
        ['rows', anInteger(U64)]
      ])
      if (undecoded !== null) return undecoded
      if (!isSessionId(sessionId)) return refused('INVALID_ARGUMENT', 'that is not a session identifier')
      const refusal = sizeRefusal(args.columns, args.rows)
      if (refusal !== null) return refused('INVALID_ARGUMENT', refusal)
      const size = { columns: args.columns, rows: args.rows }
      const view = fakeTerminalView(sessionId, size, listener, terminalPresentation, {
        holdingMoves: holdingTerminalMoves,
        holdingControl: holdingTerminalControl,
        wheel: terminalWheel
      })
      terminalViews.push(view)
      if (!connected) {
        // Native code publishes the failure on the view's channel; the open itself answers.
        setTimeout(() => {
          view.end(`This session could not be reached: ${lostBecause}`)
        }, 0)
      } else if (!holdingTerminalViews) {
        setTimeout(() => {
          view.attach()
          setTimeout(() => {
            view.show()
          }, 0)
        }, 0)
      }
      return terminalOpensAnswer.then(() => view.handle)
    },
    pairingView: () => Promise.resolve(pairing),
    pairingSetOrigin: (origin) => {
      const trimmed = origin.trim().replace(/\/$/, '')
      if (!/^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/.test(trimmed)) {
        refuse('INVALID_ARGUMENT', 'That is not a service this device can use.')
      }
      const host = trimmed.slice('https://'.length).split(':')[0] ?? trimmed
      publishPairing({
        origin: { origin: trimmed, host, is_default: trimmed === 'https://reach.kala.to' }
      })
      return Promise.resolve(pairing.origin)
    },
    pairingStartCode: (code) => {
      if (!codeComplete(code)) {
        refuse('INVALID_ARGUMENT', 'A code has ten characters, and never contains 0, O, I or l.')
      }
      startedCodes.push(code)
      publishPairing({ state: { state: 'working', stage: 'reaching_service' } })
      return Promise.resolve()
    },
    pairingPaste: () => {
      if (pasteboard.invitation !== null) publishPairing({ invitation: pasteboard.invitation })
      return Promise.resolve(pasteboard)
    },
    pairingStartRead: () => {
      if (pairing.invitation === null) refuse('PERMISSION_DENIED', 'No invitation is waiting.')
      publishPairing({ invitation: null, state: { state: 'working', stage: 'reaching_host' } })
      return Promise.resolve()
    },
    pairingStop: () => {
      publishPairing({ invitation: null, state: { state: 'idle' } })
      return Promise.resolve()
    },
    hostsUse: (reference) => {
      if (!pairing.hosts.some((host) => host.reference === reference)) {
        refuse('INVALID_ARGUMENT', 'This computer is not paired with that host.')
      }
      usedHosts.push(reference)
      publishPairing({
        hosts: pairing.hosts.map((host) => ({ ...host, in_use: host.reference === reference }))
      })
      connected = true
      for (const listener of connectionListeners) listener(connectionNow())
      return Promise.resolve(connectionNow())
    },
    onPairing: (listener) => register(pairingListeners, listener),
    ownerConfirmations: () => Promise.resolve(owner),
    ownerConfirmationReview: (reference) => {
      reviewed.push(reference)
      const outcome = reviewOutcome
      if (outcome === 'confirmed') {
        publishOwner({
          ...owner,
          requests: owner.requests.filter((request) => request.reference !== reference)
        })
      }
      return Promise.resolve(outcome)
    },
    onConfirmations: (listener) => register(ownerListeners, listener),

    openExternal: (url) => {
      if (!url.startsWith('https://') && !url.startsWith('mailto:')) {
        refuse('PERMISSION_DENIED', 'That scheme is not one this application opens.')
      }
      openedLinks.push(url)
      const host = url.startsWith('https://')
        ? (url.slice('https://'.length).split('/')[0] ?? null)
        : null
      return Promise.resolve({
        scheme: url.split(':')[0] ?? '',
        url,
        host
      } satisfies ApprovedLink)
    },
    importRemoteImage: (url) => {
      if (!url.startsWith('https://')) {
        refuse('PERMISSION_DENIED', 'An image is imported over https and nothing else.')
      }
      importedImages.push(url)
      return Promise.resolve({
        url,
        media_type: 'image/png',
        bytes: [137, 80, 78, 71]
      } satisfies ImportedImage)
    },
    exportSemanticJson: (request) => {
      exportedArchives.push(request)
      const written: Written = {
        path: request.path,
        byte_len: JSON.stringify(request.nodes).length,
        omissions: request.omissions
      }
      savedExports.push(written)
      return Promise.resolve(written)
    },
    exportAsciicast: (request) => {
      exportedCasts.push(request)
      const written: Written = {
        path: request.path,
        byte_len: request.frames.reduce((total, frame) => total + frame.text.length, 0),
        omissions: request.omissions
      }
      savedExports.push(written)
      return Promise.resolve(written)
    },
    chooseExportPath: (suggestedName) => Promise.resolve(`/tmp/${suggestedName}`),

    /* ---- Voice --------------------------------------------------------------------------------
     *
     * A call this host scripts. The two reachability switches are separate on purpose: the control
     * socket to the voice service and this device's connection to the host are different
     * connections, and section 15 ¶10 asks for local mute and closure to keep working when the
     * first one fails. The mute controls and the closure below therefore touch no switch at all.
     */

    voicePrepare: (params) => {
      requireConnection()
      if (voiceGrantMissing !== null) refuse('PERMISSION_DENIED', voiceGrantMissing)
      const asked = requireFields(params, ['session_ids', 'selected'])
      const selected = Array.isArray(asked.selected) ? (asked.selected as readonly string[]) : []
      const sessions = Array.isArray(asked.session_ids) ? (asked.session_ids as string[]) : []
      return Promise.resolve({
        ...VOICE_SCOPE,
        session_ids: sessions.length > 0 ? sessions : [...VOICE_SCOPE.session_ids],
        prepared: preparedFor(voice),
        selected: VOICE_EXCLUDED_CLASSES.filter((each) => selected.includes(each)),
        managed:
          voice.terms === 'unread'
            ? null
            : { ...VOICE_TERMS, enabled: voice.terms === 'published', rate: { ...voice.rate } },
        managed_unavailable:
          voice.terms === 'unread'
            ? "This host could not read the managed service's terms, so a managed call cannot start from here: the managed service did not answer"
            : null
      })
    },

    voiceScope: () => Promise.resolve(VOICE_DEFAULT_SCOPE),
    voiceAllow: (request) => {
      requireConnection()
      voiceAllows.push(request)
      if (voiceAllowFailure !== null) {
        const message = voiceAllowFailure
        voiceAllowFailure = null
        refuse('PERMISSION_DENIED', message)
      }
      if (voiceAllowUnconfirmed) {
        voiceAllowUnconfirmed = false
        // The host may or may not have written the grant: what the page learns is the action's
        // identity and nothing else.
        return Promise.resolve({ receipt: null, action_id: 'voice-grant-action-1', value: null })
      }
      voiceGrantMissing = null
      const asked: VoiceAction[] = request.actions
        ? [...request.actions]
        : VOICE_DEFAULT_SCOPE.actions.map((each) => each.action)
      const actions = asked.filter((action) => !voiceHeldBack.includes(action))
      const notHeld = asked.filter((action) => voiceHeldBack.includes(action))
      voiceHeldBack = []
      return reading('voiceAllow', () => ({
        receipt: null,
        action_id: null,
        value: {
          statement: {
            actions,
            statements: actions.map(
              (action) =>
                VOICE_DEFAULT_SCOPE.actions.find((each) => each.action === action)?.sentence ?? ''
            ),
            unlocked_screen_actions: []
          },
          not_held_by_device: notHeld
        } satisfies VoiceAllowed
      }))
    },

    voiceStart: (request) => {
      requireConnection()
      voiceStarts.push(request)
      if (voice.call) {
        refuse('PERMISSION_DENIED', 'This device is already holding a voice call.')
      }
      // The host compares the preparation the start names with what the call would be bound to
      // now, before it asks the service for anything.
      if (request.prepared !== preparedFor(voice)) {
        return Promise.resolve({
          receipt: null,
          action_id: null,
          value: {
            outcome: {
              preparation_changed: {
                message:
                  'What this call would reach, what it could do or the service that would carry it changed after it was shown, so nothing was started. Read it again before starting.'
              }
            }
          }
        })
      }
      // The service compares the version the start names with the rate it would charge now, and
      // refuses before anything is held when they differ.
      if (request.expectedRateVersion !== voice.rate.version) {
        return Promise.resolve({
          receipt: null,
          action_id: null,
          value: {
            outcome: {
              rate_changed: {
                rate: { ...voice.rate },
                message:
                  'The rate a call would run under now is not the one this request named, so nothing was started, held or charged. Show the rate this answer carries and ask again with its version to start under it.'
              }
            }
          }
        })
      }
      if (voice.terms === 'closed') {
        return Promise.resolve({
          receipt: null,
          action_id: null,
          value: {
            outcome: {
              unavailable: {
                reason: 'service_capacity',
                message: 'Managed voice is closed at the moment.',
                alternatives: [...VOICE_TERMS.alternatives]
              }
            }
          }
        })
      }
      if (voice.startRefusal) {
        return Promise.resolve({
          receipt: null,
          action_id: null,
          value: {
            outcome: {
              unavailable: {
                reason: voice.startRefusal,
                message: 'Managed voice cannot be started right now.',
                alternatives: ['Type to the session instead.']
              }
            }
          }
        })
      }
      const started = fakeVoiceSession(request.sessionIds, VOICE_NOW_MS + 1_800_000)
      voice.call = { session: started, capture: voice.startCapture, playing: true }
      return Promise.resolve({
        receipt: null,
        action_id: null,
        value: { outcome: { started: { session: started } } }
      })
    },

    voiceStop: (voiceSessionId) => {
      const running = voice.call
      voice.call = null
      voice.delegations = []
      if (!connected) {
        return Promise.resolve({
          closed_locally: running !== null,
          settled: null,
          host_failure: {
            code: 'RESOURCE_UNAVAILABLE',
            // Native code sends a host's refusal as its code, a colon and the host's words.
            message: 'RESOURCE_UNAVAILABLE: This host cannot be contacted right now.',
            user_action: 'wait'
          }
        })
      }
      return Promise.resolve({
        closed_locally: running !== null,
        settled: {
          receipt: null,
          action_id: null,
          value: {
            voice_session_id: voiceSessionId,
            revoked_grant_id: VOICE_GRANT,
            revoked_at_ms: String(VOICE_NOW_MS),
            broker_notified: true,
            sessions_left_running: [SESSION_MAIN]
          }
        },
        host_failure: null
      })
    },

    voiceDelegate: (params) => {
      requireConnection()
      const asked = requireFields(params, [
        'voice_session_id',
        'delegation_id',
        'offset_ms',
        'action',
        'session_id',
        'spoken_destination',
        'approval',
        'turn_id',
        'confirmation'
      ])
      const delegationId = typeof asked.delegation_id === 'string' ? asked.delegation_id : ''
      if (!voice.delegations.includes(delegationId)) {
        refuse('INVALID_ARGUMENT', 'This call was never told about that delegation.')
      }
      return Promise.resolve({
        receipt: null,
        action_id: null,
        value: {
          delegation_id: delegationId,
          outcome: {
            admitted: {
              action_id: nextActionId(),
              note: HOST_ADMISSION_NOTE
            }
          }
        }
      })
    },

    voiceContext: (params) => {
      requireConnection()
      const asked = requireFields(params, [
        'voice_session_id',
        'session_id',
        'selected',
        'delegation_id'
      ])
      return Promise.resolve(
        fakeVoiceContext(String(asked.voice_session_id), String(asked.session_id))
      )
    },

    voiceSetMuted: (what, muted) => {
      const running = voice.call
      if (!running) refuse('PERMISSION_DENIED', 'This device is not holding a voice call.')
      if (what === 'microphone') running.capture = muted ? 'muted_by_person' : 'capturing'
      else running.playing = !muted
      return Promise.resolve(voiceCallState(voice))
    },

    voiceCallState: () => Promise.resolve(voiceCallState(voice)),

    accountStatus: () => reading('accountStatus', () => accountView),
    accountSignIn: () => {
      signIns += 1
      setAccount({ state: 'browser_open' })
      return new Promise<AccountView>((resolve) => {
        pendingSignIn = (view) => {
          setAccount(view)
          resolve(view)
        }
      })
    },
    accountSignInCancel: () => {
      settleSignIn({ state: 'signed_out', outcome: 'cancelled' })
      return Promise.resolve()
    },
    accountSignOut: () => {
      if (signOutFails && accountView.state === 'signed_in') {
        setAccount({ ...accountView, outcome: 'sign_out_failed' })
        return Promise.resolve(accountView)
      }
      accountUsage = { state: 'signed_out' }
      setAccount({ state: 'signed_out', outcome: 'signed_out' })
      return Promise.resolve(accountView)
    },
    accountUsage: () =>
      usageHeld
        ? new Promise<UsageView>((resolve) => {
            heldUsage.push(resolve)
          })
        : Promise.resolve(accountUsage),
    onAccount: (listener) => register(accountListeners, listener),

    subscribe: (listener) => register(listeners, listener),
    onFilesDropped: (listener) => register(dropListeners, listener)
  }

  const controls: FakeHostControls = {
    account: {
      get signIns() {
        return signIns
      },
      set: setAccount,
      finishSignIn: settleSignIn,
      setUsage(usage) {
        accountUsage = usage
      },
      holdUsage() {
        usageHeld = true
      },
      answerUsage(index, usage) {
        heldUsage[index]?.(usage)
      },
      failSignOut() {
        signOutFails = true
      }
    },
    emit,
    appendNode(node, sessionId = SESSION_MAIN) {
      presentation += 1
      emit({
        stream_id: `semantic:${sessionId}`,
        sequence: String(presentation),
        body: { kind: 'node', node }
      })
    },
    records,
    changePromptGeneration() {
      promptGeneration += 1
      emit({
        stream_id: 'session_state',
        sequence: String(promptGeneration),
        body: { kind: 'prompt_generation', prompt_generation: String(promptGeneration) }
      })
    },
    setConnected(next, reason = UNREACHABLE) {
      connected = next
      lostBecause = reason
      for (const listener of connectionListeners) listener(connectionNow())
    },
    switchHost(environmentId, options) {
      hostEnvironment = environmentId
      anotherHost = true
      sessionListRefused = options?.refuseSessionList === true
      environmentListRefused = options?.refuseEnvironmentList === true
      for (const listener of connectionListeners) listener(connectionNow())
    },
    withoutQualifiedShell() {
      qualifiedShell = false
    },
    usedHosts,
    voiceAllows,
    requireVoiceGrant(reason = 'PERMISSION_DENIED: no voice grant covers this device') {
      voiceGrantMissing = reason
    },
    failNextVoiceAllow(message) {
      voiceAllowFailure = message
    },
    holdBackOnNextVoiceAllow(actions) {
      voiceHeldBack = actions
    },
    leaveNextVoiceAllowUnconfirmed() {
      voiceAllowUnconfirmed = true
    },
    sessionCreates,
    describe(sessionId, change) {
      const found = listed().find((session) => session.session_id === sessionId)
      const current: SessionDescribeResult = describedAs.get(sessionId) ?? {
        session_id: sessionId,
        title: found?.cwd.split('/').filter(Boolean).pop() ?? sessionId,
        source: 'metadata',
        activity_text: null,
        freshness: 'none',
        provenance: null,
        queued_age_ms: null,
        last_success_ms: null,
        cadence_ms: '30000',
        state: descriptionSetup.state,
        paused: descriptionSetup.paused
      }
      describedAs.set(sessionId, { ...current, ...change })
    },
    described: describedBy,
    addSessions(count) {
      const first = sessions().sessions[0]
      for (let index = 0; index < count; index += 1) {
        const summary = createdSession(
          {
            cwd: `/Users/rs/work/project-${String(created.length + 1)}`,
            shell_mode: 'managed',
            environment_id: first?.environment_id,
            worker_profile: first?.worker_profile
          } as unknown as SessionCreateParams,
          created.length
        )
        created.push(summary)
        records.startShell(summary.session_id)
      }
    },
    reachAsPairedDevice() {
      pairedDevice = true
    },
    changeDescriptionSetup(change) {
      descriptionSetup = { ...descriptionSetup, ...change }
    },
    descriptionConfigures,
    descriptionDownloads,
    setRights(next) {
      rights = next
      for (const listener of connectionListeners) listener(connectionNow())
    },
    hold(read) {
      const waiting: (() => void)[] = []
      holds.set(read, waiting)
      const answer = (index: number) => {
        if (index < 0 || index >= waiting.length) return
        const settle = waiting[index]
        waiting[index] = answered
        settle()
      }
      return {
        get count() {
          return waiting.length
        },
        answer,
        release() {
          if (holds.get(read) === waiting) holds.delete(read)
          for (let index = 0; index < waiting.length; index += 1) answer(index)
        }
      }
    },
    holdMutation() {
      const waiting: (() => void)[] = []
      heldSends = waiting
      return {
        get count() {
          return waiting.length
        },
        release() {
          if (heldSends === waiting) heldSends = null
          for (const settle of waiting) settle()
        }
      }
    },
    get submissions() {
      return submissions
    },
    dropFiles(files) {
      for (const listener of dropListeners) listener(files)
    },
    savedExports,
    exportedArchives,
    exportedCasts,
    openedLinks,
    importedImages,
    uploaded,
    actions: issuedActions,
    grantPermission(capability) {
      granted.add(capability)
      capabilityRevision += 1
    },
    revokePermission(capability) {
      granted.delete(capability)
      capabilityRevision += 1
    },
    setIdentityStable(stable) {
      identityStable = stable
    },
    openedPanes,
    setVoiceBrokerReachable(reachable) {
      voice.brokerReachable = reachable
    },
    refuseVoiceStart(reason) {
      voice.startRefusal = reason
    },
    changeVoiceScope() {
      voice.scope += 1
    },
    changeVoiceRate(version, minorUnitsPerSecond) {
      voice.rate = { ...voice.rate, version, minor_units_per_second: minorUnitsPerSecond }
    },
    setVoiceTerms(state) {
      voice.terms = state
    },
    voiceStarts,
    setVoiceCapture(state) {
      if (voice.call) voice.call.capture = state
    },
    announceVoiceDelegation(delegationId, action = 'status') {
      voice.delegations.push(delegationId)
      emit({
        stream_id: `voice:${VOICE_SESSION}`,
        sequence: String(voice.delegations.length),
        body: {
          kind: 'voice_delegation',
          delegation_id: delegationId,
          offset_ms: String(1_000 * voice.delegations.length),
          ...(action === null ? {} : { action })
        }
      })
    },
    setPairing(change) {
      publishPairing(change)
    },
    setPasteboard(result) {
      pasteboard = result
    },
    startedCodes,
    setConfirmations(view) {
      publishOwner(view)
    },
    setReviewOutcome(outcome) {
      reviewOutcome = outcome
    },
    reviewed,
    holdRegistrations() {
      let complete = () => {}
      registering = new Promise((resolve) => {
        complete = resolve
      })
      return () => {
        complete()
        registering = Promise.resolve()
      }
    },
    presentTerminal(presentation, reason) {
      terminalPresentation = {
        presentation,
        reason: presentation === 'viewport' ? reason : undefined
      }
    },
    holdTerminalViews() {
      holdingTerminalViews = true
    },
    holdTerminalMoves() {
      holdingTerminalMoves = true
    },
    terminalWheel(wheel) {
      terminalWheel = wheel
    },
    holdTerminalControl() {
      holdingTerminalControl = true
    },
    holdTerminalOpens() {
      let answer = () => {}
      terminalOpensAnswer = new Promise((resolve) => {
        answer = resolve
      })
      return () => {
        answer()
        terminalOpensAnswer = Promise.resolve()
      }
    },
    terminalViews
  }

  return { port: answeringAsNativeCodeDoes(port), controls }
}

/** What a held read's place holds once it has been answered. */
function answered(): void {
  // An answer is given once.
}

/**
 * The port with every refusal delivered the way native code delivers it.
 *
 * A command the desktop shell carries answers with a promise, and a refusal is that promise's
 * rejection: nothing is ever thrown before the promise exists. The methods above refuse by
 * throwing, which is the plainest way to write a refusal, so each is called here and a throw
 * becomes the rejection a page would receive. A scripted host that threw would let a page pass
 * against a failure shape no real host produces.
 */
function answeringAsNativeCodeDoes(port: HostPort): HostPort {
  const answering: Record<string, unknown> = {}
  for (const [name, method] of Object.entries(port) as [string, (...args: unknown[]) => unknown][]) {
    answering[name] = (...args: unknown[]): unknown => {
      try {
        return method(...args)
      } catch (refusal: unknown) {
        return new Promise((_, reject) => {
          // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a refusal is the data native code rejects with, never an Error
          reject(refusal)
        })
      }
    }
  }
  return answering as unknown as HostPort
}

/** The scripted call, held apart from the host's own state because it is this device's. */
interface VoiceState {
  call: {
    session: VoiceSessionDescriptor
    capture: string
    playing: boolean
  } | null
  /** The delegations the provider has announced to this call. */
  delegations: string[]
  /** Whether the control socket to the voice service is carrying requests. */
  brokerReachable: boolean
  /** The reason a start answers `unavailable` with, when one is set. */
  startRefusal: string | null
  /** The rate the service would charge a call started now. */
  rate: VoiceRate
  /** What the service tells this host about its terms. */
  terms: VoiceTermsState
  /** Which scope a call started now would be bound to; a grant change moves it on. */
  scope: number
  /** What the microphone of a call started now reports first. */
  startCapture: string
}

/**
 * The voice state a harness address asks this host to begin in.
 *
 * A browser reached only through an address, such as a simulator's browser opened on a URL with no
 * way to run script in it, can still be shown each state, because what the address configures is
 * this host: the screen still draws only what the host and the call answer. Three names, each
 * optional: `voice_terms` (`closed` or `unread`), `voice_capture` (the state a started call's
 * microphone reports) and `voice_broker` (`unreachable`).
 */
function voiceSeed(): { terms: VoiceTermsState; capture: string; brokerReachable: boolean } {
  const params = new URLSearchParams(typeof window === 'undefined' ? '' : window.location.search)
  const terms = params.get('voice_terms')
  return {
    terms: terms === 'closed' || terms === 'unread' ? terms : 'published',
    capture: params.get('voice_capture') ?? 'capturing',
    brokerReachable: params.get('voice_broker') !== 'unreachable'
  }
}

/**
 * The preparation this host answers for its current scope.
 *
 * The real host digests the sessions, the actions and the provider; this one names the scope's
 * generation, which changes exactly when the scope does.
 */
function preparedFor(voice: VoiceState): string {
  return `scope-${String(voice.scope)}`
}

/** What the managed service tells a host about its terms. */
export type VoiceTermsState = 'published' | 'closed' | 'unread'

/** What the call this device is holding is doing. */
function voiceCallState(voice: VoiceState): VoiceCallState {
  const running = voice.call
  if (!running) {
    return { running: false, capture: 'idle', playing: false, control: 'none' }
  }
  return {
    running: true,
    capture: running.capture,
    playing: running.playing,
    control: voice.brokerReachable ? 'connected' : 'unreachable'
  }
}

/** The content classes section 15 ¶12 leaves out of the default context. */
const VOICE_EXCLUDED_CLASSES = [
  'attachment_bytes',
  'environment_variables',
  'file_contents',
  'terminal_scrollback'
] as const

/**
 * What this host answers before a call exists, apart from the managed service's terms.
 *
 * The scope is the host's own: its grants, its selection and its cap.
 */
const VOICE_SCOPE: Omit<VoicePrepareResult, 'managed' | 'managed_unavailable' | 'prepared'> = {
  session_ids: [SESSION_MAIN],
  statement: {
    actions: ['brief', 'compose_prompt', 'navigate', 'status'],
    statements: [
      'Summarise what a session is doing.',
      'Compose a prompt for you to send.',
      'Move between the sessions this call may reach.',
      'Report the state of a session.'
    ],
    unlocked_screen_actions: []
  },
  excluded: [...VOICE_EXCLUDED_CLASSES],
  selected: [],
  token_cap: 8000,
  message_count: 20,
  broker_origin: 'https://reach.kala.to'
}

/** What allowing voice permits by default, in the protocol's own sentences. */
const VOICE_DEFAULT_SCOPE: VoiceScope = {
  actions: [
    {
      action: 'navigate',
      sentence: 'Move between the sessions this grant covers.',
      needs_unlocked_screen: false
    },
    {
      action: 'status',
      sentence: 'Read what a session is doing.',
      needs_unlocked_screen: false
    },
    {
      action: 'brief',
      sentence: 'Hear a briefing built from the selected context.',
      needs_unlocked_screen: false
    },
    {
      action: 'compose_prompt',
      sentence: 'Compose a prompt without submitting it.',
      needs_unlocked_screen: false
    }
  ]
}

/**
 * The managed service's terms, as the deployed service publishes them.
 *
 * The wordings are the deployment's own and reach the screen through the host unchanged, which is
 * the point: the screen carries no second wording of any of them.
 */
const VOICE_TERMS: VoiceManagedTerms = {
  enabled: true,
  model: 'gpt-live-1',
  disclosure: [
    'Audio travels directly between this device and the provider, not through this service.',
    'The provider and this service can process the speech and the context the host selects.',
    "This service's own channel to the provider still receives transcripts and copies of the audio. They are discarded before telemetry and never stored, which reduces what is kept rather than making it unreadable.",
    'Selected context and host results are sent as bounded requests. What the host selected can include project text, and this service and the provider both see it.',
    'A statement from the model that you confirmed something is not a confirmation. Actions that need one ask for it on the unlocked screen of this device.'
  ],
  admission_note:
    'The model received this context. It is not evidence that a host action ran or that audio was played; host action receipts are the authority for that.',
  delegation_note:
    'A provider delegation identifier is correlation data. It carries no authority and no task text; submit the delegation to the host over the device connection, where it is checked normally.',
  alternatives: [
    'Your own provider credential, configured in the service settings, which uses no managed credit.',
    'The coding agent already running on the host, reached by typing rather than speaking.',
    'The session itself, which is unaffected: a voice session can stop while the agent continues.'
  ],
  rate: { version: '2026-09-a', minor_units_per_second: '1', minimum_seconds: 15, currency: 'usd' },
  maximum_session_seconds: 1800,
  minimum_request_seconds: 60,
  heartbeat_seconds: 20,
  context_bytes: 500
}

/** What this host says when it admits a delegation it has not performed. */
const HOST_ADMISSION_NOTE =
  'The model received this context. It is not evidence that a host action ran or that audio was played; host action receipts are the authority for that.'

/** The running voice session this host answers a start with. */
function fakeVoiceSession(
  sessionIds: readonly string[],
  closesAtMs: number
): VoiceSessionDescriptor {
  return {
    voice_session_id: VOICE_SESSION,
    grant_id: VOICE_GRANT,
    statement: VOICE_SCOPE.statement,
    session_ids: sessionIds.length > 0 ? [...sessionIds] : [SESSION_MAIN],
    call_id: 'call-7f3a',
    provider_session_id: 'sess_7f3a',
    answer_sdp: 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n',
    model: VOICE_TERMS.model,
    control_path: '/api/voice/sessions/call-7f3a/control',
    broker_origin: VOICE_SCOPE.broker_origin,
    heartbeat_seconds: 20,
    closes_at_ms: String(closesAtMs),
    disclosure: VOICE_TERMS.disclosure
  }
}

/** The selection this host hands back for one call to send on. */
function fakeVoiceContext(voiceSessionId: string, sessionId: string): VoiceContextResult {
  return {
    voice_session_id: voiceSessionId,
    session_id: sessionId,
    selection: {
      session_description: 'Building the release',
      working_directory: '~/work/kalareach',
      active_application: 'the agent',
      pending_decisions: ['One approval is waiting.'],
      recent_messages: ['The build finished.'],
      selected: [],
      secrets_stripped: 0,
      stripping_note: '',
      text_tokens: 140,
      truncated: false
    },
    provenance: {
      from_ms: String(VOICE_NOW_MS - 3_600_000),
      to_ms: String(VOICE_NOW_MS),
      resources: [sessionId]
    },
    withheld: [],
    disclosure: VOICE_TERMS.disclosure
  }
}

/** The launch surface this host reports, read by the interface before it draws a button. */
export function fakeLaunchSurface(promptIsEmpty: boolean, promptGeneration: string): LaunchSurface {
  return {
    prompt_is_empty: promptIsEmpty,
    prompt_generation: promptGeneration,
    buffer_revision: '12',
    profiles: [
      { profile_id: 'codex', label: 'Codex', executable: '/usr/local/bin/codex', version: '0.48.2', user_defined: false, arguments: ['codex'] },
      { profile_id: 'claude-code', label: 'Claude Code', executable: '/usr/local/bin/claude', version: '2.8.0', user_defined: false, arguments: ['claude'] },
      { profile_id: 'opencode', label: 'OpenCode', executable: '/usr/local/bin/opencode', version: '1.4.0', user_defined: false, arguments: ['opencode'] },
      { profile_id: 'gemini', label: 'Gemini', executable: '/usr/local/bin/gemini', version: '0.9.3', user_defined: false, arguments: ['gemini'] },
      { profile_id: 'kimi', label: 'Kimi', executable: null, version: null, user_defined: false, arguments: ['kimi'] },
      { profile_id: 'qoder', label: 'Qoder', executable: '/usr/local/bin/qoder', version: '0.6.1', user_defined: false, arguments: ['qoder'] },
      { profile_id: 'named-1', label: 'Run the test suite', executable: '/bin/sh', version: null, user_defined: true, arguments: ['pnpm', 'test'] }
    ]
  }
}

function hostInfo(): HostInfoResult {
  return {
    boot_identity: { source: 'macos_boot_session_uuid', value: 'b-1' },
    build_id: '0.1.0+test',
    default_worker_profile: 'desktop_bound',
    environment_id: ENVIRONMENT,
    generation: '4',
    live_sessions: '3',
    protocol_version: { major: 1, minor: 0 },
    session_limit: '20',
    started_at_ms: String(FAKE_NOW_MS - 7_200_000)
  } as unknown as HostInfoResult
}

function environments(environmentId: string = ENVIRONMENT, label: string | null = null): EnvironmentListResult {
  return {
    environments: [
      {
        arch: 'aarch64',
        environment_id: environmentId,
        label: label ?? 'studio · macOS',
        live_sessions: '3',
        os: 'macos',
        os_user: 'rs',
        runtime_directory: '/Users/rs/Library/Application Support/KalaReach/run',
        state_directory: '/Users/rs/Library/Application Support/KalaReach/state'
      }
    ]
  }
}

function sessions(): SessionListResult {
  const base = {
    closure: null,
    created_at_ms: String(FAKE_NOW_MS - 3_600_000),
    desktop: { bound: true, desktop_session_id: 'd-1' },
    dimensions: { columns: '120', rows: '40' },
    environment_id: ENVIRONMENT,
    root_process: { pid: '4102', started_at_ms: String(FAKE_NOW_MS - 3_600_000) },
    session_epoch: '1',
    shell_mode: 'managed' as const,
    shell_path: '/bin/zsh',
    worker_profile: 'desktop_bound' as const
  }
  return {
    sessions: [
      {
        ...base,
        application_state: 'awaiting_approval',
        attachment_count: '2',
        cwd: '/Users/rs/work/kalareach',
        display_number: '1',
        session_id: SESSION_MAIN,
        state: 'live'
      },
      {
        ...base,
        application_state: 'agent_busy',
        attachment_count: '1',
        cwd: '/Users/rs/work/kalareach-web',
        display_number: '2',
        session_id: SESSION_BUILD,
        state: 'live'
      },
      {
        ...base,
        application_state: null,
        attachment_count: '0',
        cwd: '/Users/rs/work/notes',
        display_number: '3',
        session_id: SESSION_OFFLINE,
        state: 'live'
      }
    ]
  } as unknown as SessionListResult
}

/** One session in a listing. */
type SessionSummaryOf = SessionListResult['sessions'][number]

/**
 * The session a creation made, as the host reports it: running the shell the mode asked for, in
 * the directory the request named, with nothing attached yet.
 */
function createdSession(params: SessionCreateParams, before: number): SessionSummaryOf {
  const number = 4 + before
  return {
    application_state: 'shell_ready',
    attachment_count: '0',
    closure: null,
    created_at_ms: String(FAKE_NOW_MS),
    cwd: params.cwd ?? '/',
    desktop: { bound: true, desktop_session_id: 'd-1' },
    dimensions: params.dimensions ?? { columns: '120', rows: '40' },
    display_number: String(number),
    environment_id: params.environment_id,
    root_process: { pid: String(5000 + number), started_at_ms: String(FAKE_NOW_MS) },
    session_epoch: '1',
    session_id: `8a7b6c50-22bb-4c3d-8e4f-${String(200 + number).padStart(12, '0')}`,
    shell_mode: params.shell_mode,
    // A managed session runs the qualified package; a stock one runs the system's own shell.
    shell_path:
      params.shell_mode === 'managed'
        ? '/Users/rs/Library/Application Support/KalaReach/shells/zsh/bin/zsh'
        : '/bin/zsh',
    state: 'live',
    worker_profile: params.worker_profile
  } as unknown as SessionSummaryOf
}

function retained(deleted: ReadonlySet<string>): RetainedArtefacts {
  const artefacts = [
    {
      object_id: 'obj-1',
      kind: 'archive' as const,
      description: 'Encrypted history archive uploaded before privacy mode',
      location: 'managed storage',
      byte_len: 4_812_390,
      created_at_ms: FAKE_NOW_MS - 172_800_000,
      held_by_other_party: false
    },
    {
      object_id: 'obj-2',
      kind: 'notification' as const,
      description: 'Push notification carrying a turn summary',
      location: 'push service',
      byte_len: 812,
      created_at_ms: FAKE_NOW_MS - 90_000_000,
      held_by_other_party: false
    },
    {
      object_id: 'obj-3',
      kind: 'viewer_copy' as const,
      description: 'A copy an authorised viewer downloaded',
      location: "that viewer's device",
      byte_len: 22_118,
      created_at_ms: FAKE_NOW_MS - 260_000_000,
      held_by_other_party: true
    }
  ]
  return {
    privacy_mode: true,
    privacy_generation: '3',
    artefacts: artefacts.filter((artefact) => !deleted.has(artefact.object_id))
  }
}

/** A fake view, and the handle the page holds for it. */
type HeldTerminalView = FakeTerminalView & { readonly handle: TerminalView }

let terminalViewCount = 0

/** One raw terminal view, publishing to `listener` what the test tells it to. */
function fakeTerminalView(
  sessionId: string,
  grid: TerminalGrid,
  listener: (state: TerminalViewState) => void,
  presented: {
    readonly presentation: TerminalPresentationMode | null
    readonly reason: PresentationReason | undefined
  },
  held: {
    readonly holdingMoves: boolean
    readonly holdingControl: boolean
    readonly wheel: TerminalWheel
  } = { holdingMoves: false, holdingControl: false, wheel: 'reaches' }
): HeldTerminalView {
  terminalViewCount += 1
  const grids: TerminalGrid[] = [grid]
  const moves: TerminalMove[] = []
  const inputs: TerminalInput[] = []
  let closed = false
  let ended = false
  // Where the window is, and the newest move that put it there.
  let place: TerminalPlace = HOME
  let applied = 0
  // Control, kept as native code keeps the session's input lease: the page's newest control request,
  // whether it asks for control and nothing has ended it since, whether the lease is held, whether an
  // acquire is in flight, and why control last ended or was refused.
  let asked = 0
  let wanted = false
  let leased = false
  let acquiring = false
  let endedWhy: string | null = null
  const controlNow = (): TerminalControl => ({
    number: asked,
    state: !wanted ? 'watching' : leased ? 'controlling' : 'taking',
    ended: endedWhy
  })
  const attachment: AttachmentSummary = {
    attached_at_ms: String(FAKE_NOW_MS),
    attachment_id: `a77ac4ed-0000-4000-8000-${String(terminalViewCount).padStart(12, '0')}`,
    claim_geometry: false,
    dimensions: { columns: String(grid.columns), rows: String(grid.rows) },
    granted: ['observe_terminal', 'input'],
    mode: 'terminal',
    ordinal: String(3 + terminalViewCount),
    presentation: presented.presentation,
    // Left out when there is none, as the host writes it.
    ...(presented.reason === undefined ? {} : { presentation_reason: presented.reason }),
    terminal_profile_id: 'kalareach-companion'
  }
  let last: TerminalViewState | null = null
  const publish = (state: TerminalViewState) => {
    if (closed) return
    last = state
    listener(state)
  }
  const screenAt = () => ({ ...terminalScreen(sessionId, grids.at(-1) ?? grid, place), wheel: held.wheel })
  // A change of control is told with the state the page was last sent, once native code's task has
  // taken the request: after the call that made it has answered, as the view's own channel carries it.
  const controlChanged = () => {
    setTimeout(() => {
      if (last === null || last.state === 'ended' || ended) return
      publish({ ...last, control: controlNow() })
    }, 0)
  }
  const answerTake = (granted: boolean, reason = '') => {
    if (!acquiring) return
    acquiring = false
    if (!wanted) return
    if (granted) {
      leased = true
    } else {
      wanted = false
      endedWhy = `This view cannot take control: ${reason}`
    }
    controlChanged()
  }
  return {
    sessionId,
    get grids() {
      return grids
    },
    get closed() {
      return closed
    },
    attachment,
    get moves() {
      return moves
    },
    get inputs() {
      return inputs
    },
    get control() {
      return controlNow()
    },
    grantControl() {
      answerTake(true)
    },
    refuseControl(reason) {
      answerTake(false, reason)
    },
    loseControl(reason = LOST_CONTROL) {
      if (!leased) return
      leased = false
      wanted = false
      endedWhy = reason
      controlChanged()
    },
    attach() {
      publish({ state: 'waiting', attachment, settled: applied, control: controlNow() })
    },
    show(screen, settled) {
      publish({
        state: 'showing',
        attachment,
        screen: { ...screenAt(), ...screen },
        settled: settled ?? applied,
        control: controlNow()
      })
    },
    wait(settled) {
      publish({ state: 'waiting', attachment, settled: settled ?? applied, control: controlNow() })
    },
    end(reason) {
      ended = true
      publish({ state: 'ended', reason })
    },
    publish,
    deliverInFlight: listener,
    handle: {
      // The size the page's port sends, read as native code reads it: one it refuses changes nothing.
      resize: (next) => {
        const args = viewSizeArguments(next)
        const undecoded = undecodable('terminal_view_resize', args, [
          ['columns', anInteger(U64)],
          ['rows', anInteger(U64)]
        ])
        if (undecoded !== null) return undecoded
        const refusal = sizeRefusal(args.columns, args.rows)
        if (refusal !== null) return refused('INVALID_ARGUMENT', refusal)
        const size = { columns: args.columns, rows: args.rows }
        grids.push(size)
        // The host holds the window inside what a window of the new size can reach.
        place = heldInside(sessionId, size, place)
        return Promise.resolve()
      },
      // The move the page's port sends, read as native code reads it: one it refuses is neither
      // recorded nor applied. Native code applies a move, has the host draw the window there, and
      // says the move is settled with that screen. A view whose moves are held records them and
      // waits for the test; a view that has ended, or a move not numbered after the last, takes
      // nothing, and a screen drawn for a view that ends before it is sent is never sent.
      move: (next) => {
        const args = viewMoveArguments(next)
        const undecoded = undecodable('terminal_view_move', args, [
          ['number', anInteger(U64)],
          ['across', anInteger(I64)],
          ['down', anInteger(I64)],
          ['live', aBoolean]
        ])
        if (undecoded !== null) return undecoded
        const asked: TerminalMove = args.live
          ? { number: args.number, live: true }
          : { number: args.number, across: args.across, down: args.down }
        moves.push(asked)
        if (!held.holdingMoves && !closed && !ended && asked.number > applied) {
          place = moved(sessionId, grids.at(-1) ?? grid, place, asked)
          applied = asked.number
          setTimeout(() => {
            if (ended) return
            publish({
              state: 'showing',
              attachment,
              screen: screenAt(),
              settled: applied,
              control: controlNow()
            })
          }, 0)
        }
        return Promise.resolve()
      },
      // Read as native code reads it: anything that is not the view's input shape is refused before
      // anything happens, and a wheel turn, a key, text or a paste only goes while the view controls
      // the program under the take it names. A key, text or paste also needs the session's screen,
      // which says how the program reads keys: before the view holds one it is refused, and the view
      // keeps control.
      input: (next) => {
        const input = readTerminalInput(next)
        if (typeof input === 'string') {
          return refused('INVALID_ARGUMENT', `those are not this operation's parameters: ${input}`)
        }
        if (closed || ended) return refused('LEASE_LOST', 'This view has ended, and took nothing.')
        switch (input.kind) {
          case 'take':
          case 'release': {
            if (input.number <= asked) return Promise.resolve()
            asked = input.number
            wanted = input.kind === 'take'
            endedWhy = null
            if (!wanted) leased = false
            inputs.push(input)
            controlChanged()
            if (wanted && !leased && !acquiring) {
              acquiring = true
              if (!held.holdingControl) {
                setTimeout(() => {
                  answerTake(true)
                }, 0)
              }
            }
            return Promise.resolve()
          }
          case 'wheel':
          case 'key':
          case 'text':
          case 'paste':
            if (!(wanted && leased && input.take === asked)) {
              return refused('LEASE_LOST', 'This view does not control the program.')
            }
            if (input.kind !== 'wheel' && last?.state !== 'showing') {
              const what = input.kind === 'key' ? 'That key' : input.kind === 'text' ? 'That text' : 'That paste'
              return refused(
                'INPUT_INCOMPATIBLE',
                `${what} did not reach the program: the view is waiting for the session's screen.`
              )
            }
            inputs.push(input)
            return Promise.resolve()
        }
      },
      close: () => {
        closed = true
        return Promise.resolve()
      }
    }
  }
}

/** What native code says when control ends at a write the session refused because the lease moved. */
export const LOST_CONTROL = 'Control ended: another view took it, or the program changed how it reads keys.'

/** The most wheel turns one input carries, as native code reads it. */
const MAX_TURNS = 1024

/** The most bytes of text one input carries: one input frame. */
const MAX_TEXT_BYTES = 64 * 1024

/** The most bytes of a paste one input carries: one input frame less bracketed paste's delimiters. */
const MAX_PASTE_BYTES = MAX_TEXT_BYTES - 12

/** The keypad codes native code reads, by the platform's names for them. */
const KEYPAD: readonly string[] = [
  ...Array.from({ length: 10 }, (_, digit) => `Numpad${digit}`),
  'NumpadDecimal',
  'NumpadComma',
  'NumpadDivide',
  'NumpadMultiply',
  'NumpadSubtract',
  'NumpadAdd',
  'NumpadEqual',
  'NumpadEnter'
]

/** Whether a code point is a control character, as native code's `char::is_control` says. */
function controlCharacter(point: number): boolean {
  return point <= 0x1f || (point >= 0x7f && point <= 0x9f)
}

/** A refusal of a view's handle, as native code rejects with it. */
function refused(code: string, message: string): Promise<never> {
  return new Promise((_, reject) => {
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a refusal is the data native code rejects with, never an Error
    reject(new FakeHostError(code, message).toPayload())
  })
}

/** The most columns, rows and cells a terminal may have, all three at once (section 8). */
const MAX_COLUMNS = 2048
const MAX_ROWS = 1024
const MAX_CELLS = 262_144

/** One of native code's integer types, by its name and the least and greatest values it holds. */
interface IntegerType {
  readonly name: string
  readonly least: bigint
  readonly greatest: bigint
}

const U32: IntegerType = { name: 'u32', least: 0n, greatest: 2n ** 32n - 1n }
const U64: IntegerType = { name: 'u64', least: 0n, greatest: 2n ** 64n - 1n }
const I32: IntegerType = { name: 'i32', least: -(2n ** 31n), greatest: 2n ** 31n - 1n }
const I64: IntegerType = { name: 'i64', least: -(2n ** 63n), greatest: 2n ** 63n - 1n }

/**
 * A number as native code's decoder holds the JSON the page's port writes for it: the port writes
 * its shortest decimal form, and digits alone that fit a 64-bit integer, signed or unsigned, are an
 * integer; anything else, a fraction, an exponent or digits past 64 bits, is a floating point
 * number. NaN and the infinities are written as null, which is none.
 */
function asDecoded(value: number): { readonly integer: bigint } | { readonly float: number } | null {
  const text = JSON.stringify(value)
  if (text === 'null') return null
  if (/^-?\d+$/.test(text)) {
    const integer = BigInt(text)
    if (integer >= I64.least && integer <= U64.greatest) return { integer }
  }
  return { float: Number(text) }
}

/**
 * A floating point number in the form native code's decoder writes one: the shortest digits that
 * read back as the number, plain with a decimal point (`1000.0`, `0.00001`) for a magnitude from
 * one hundred thousandth up to but not including 1e16, and otherwise a mantissa and an exponent with
 * its sign (`1e+22`, `1.5e-7`). The digits are JavaScript's shortest form for the number, which are
 * the decoder's, unless the decoder's own reading of the number differs in the last place.
 */
function asFloatWords(value: number): string {
  const magnitude = Math.abs(value)
  const sign = value < 0 || Object.is(value, -0) ? '-' : ''
  const [mantissa = '0', power = '0'] = magnitude.toExponential().split('e')
  const exponent = Number(power)
  if (magnitude !== 0 && (magnitude < 1e-5 || magnitude >= 1e16)) {
    return `${sign}${mantissa}e${exponent < 0 ? '-' : '+'}${Math.abs(exponent)}`
  }
  const digits = mantissa.replace('.', '')
  const point = exponent + 1
  const written =
    point >= digits.length
      ? digits + '0'.repeat(point - digits.length)
      : point <= 0
        ? `0.${'0'.repeat(-point)}${digits}`
        : `${digits.slice(0, point)}.${digits.slice(point)}`
  return `${sign}${written.includes('.') ? written : `${written}.0`}`
}

/**
 * How native code's decoder names a value it did not expect, in its words for every kind of value,
 * with the digits of a floating point number as `asFloatWords` gives them and a string escaped as
 * JSON escapes it, where the decoder escapes a control character in its own way.
 */
function unexpected(value: unknown): string {
  if (typeof value === 'boolean') return `boolean \`${value}\``
  if (typeof value === 'string') return `string ${JSON.stringify(value)}`
  if (typeof value === 'number') {
    const decoded = asDecoded(value)
    if (decoded === null) return 'unit value'
    return 'integer' in decoded
      ? `integer \`${decoded.integer}\``
      : `floating point \`${asFloatWords(decoded.float)}\``
  }
  if (typeof value === 'object' && value !== null) return Array.isArray(value) ? 'sequence' : 'map'
  return 'unit value'
}

/**
 * Why native code's decoder does not read `value` as an integer of `type`, in its words, or null
 * when it does: it takes an integer within the type's range, and a number past
 * Number.MAX_SAFE_INTEGER is read like any other.
 */
function notInteger(type: IntegerType, value: unknown): string | null {
  const decoded = typeof value === 'number' ? asDecoded(value) : null
  if (decoded === null || !('integer' in decoded)) {
    return `invalid type: ${unexpected(value)}, expected ${type.name}`
  }
  if (decoded.integer < type.least || decoded.integer > type.greatest) {
    return `invalid value: integer \`${decoded.integer}\`, expected ${type.name}`
  }
  return null
}

/** How the command layer reads one argument: why it cannot, or null when it can. */
type ArgumentReader = (value: unknown) => string | null

const aString: ArgumentReader = (value) =>
  typeof value === 'string' ? null : `invalid type: ${unexpected(value)}, expected a string`
const aBoolean: ArgumentReader = (value) =>
  typeof value === 'boolean' ? null : `invalid type: ${unexpected(value)}, expected a boolean`
const anInteger =
  (type: IntegerType): ArgumentReader =>
  (value) =>
    notInteger(type, value)

/**
 * The command layer's refusal of the first of `command`'s arguments it cannot decode, taken in the
 * order of the command's parameters, or null when it decodes them all. Native code never sees a
 * call it refuses, so the refusal is the command layer's own words, a string, and not an error of
 * the protocol's; an argument the page's port leaves out, as JSON leaves out one it has no value
 * for, is missing.
 */
function undecodable(
  command: string,
  args: Readonly<Record<string, unknown>>,
  parameters: readonly (readonly [string, ArgumentReader])[]
): Promise<never> | null {
  for (const [key, read] of parameters) {
    const value = args[key]
    const reason =
      value === undefined ? `command ${command} missing required key ${key}` : read(value)
    if (reason !== null) {
      return new Promise((_, reject) => {
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- the command layer rejects with a string of its own
        reject(`invalid args \`${key}\` for command \`${command}\`: ${reason}`)
      })
    }
  }
  return null
}

/** Native code's check of a view's size, in its words, or null when the size is a terminal's. */
function sizeRefusal(columns: number, rows: number): string | null {
  const refusal = "that is not a terminal's size:"
  if (columns === 0 || columns > MAX_COLUMNS) {
    return `${refusal} columns ${columns} must be between 1 and ${MAX_COLUMNS}`
  }
  if (rows === 0 || rows > MAX_ROWS) return `${refusal} rows ${rows} must be between 1 and ${MAX_ROWS}`
  if (columns * rows > MAX_CELLS) return `${refusal} cells ${columns * rows} must not exceed ${MAX_CELLS}`
  return null
}

/**
 * Whether `value` is a session identifier as native code parses one: five groups of 8, 4, 4, 4 and
 * 12 hexadecimal digits, joined by hyphens.
 */
export function isSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  )
}


/** One field of an input, as native code's type for it reads it. */
interface InputField {
  readonly name: string
  /** Why native code's decoder does not read `value` as this field, in its words, or null when it does. */
  readonly problem: (value: unknown) => string | null
  /** A field native code takes as none when it is left out or null. */
  readonly optional?: true
}

/** How native code's decoder names a value it did not expect, inside the parameters it reads. */
const withinParameters = (value: unknown): string => {
  const words = unexpected(value)
  return words === 'unit value' ? 'null' : words
}

/** A whole number of `type`, as native code's decoder reads one inside the parameters it decodes. */
const wholeNumber =
  (type: IntegerType): InputField['problem'] =>
  (value) =>
    notInteger(type, value)?.replace('unit value', 'null') ?? null

const aFlag: InputField['problem'] = (value) =>
  typeof value === 'boolean' ? null : `invalid type: ${withinParameters(value)}, expected a boolean`

/** A string, before native code's own rule for what the string may be. */
const stringThen =
  (rule: (text: string) => string | null): InputField['problem'] =>
  (value) =>
    typeof value === 'string' ? rule(value) : `invalid type: ${withinParameters(value)}, expected a string`

/** A choice among names, as native code's decoder reads a value it takes for one of its variants. */
const oneNamed =
  (names: readonly string[]): InputField['problem'] =>
  (value) => {
    if (typeof value !== 'string') return `invalid type: ${withinParameters(value)}, expected string or map`
    return names.includes(value) ? null : `unknown variant \`${value}\`, expected ${listed(names)}`
  }

/** How the decoder lists what it expected: `a`, `a` or `b`, or one of `a`, `b`, `c`. */
function listed(names: readonly string[]): string {
  const quoted = names.map((name) => `\`${name}\``)
  if (quoted.length === 1) return quoted[0] ?? ''
  if (quoted.length === 2) return `${quoted[0] ?? ''} or ${quoted[1] ?? ''}`
  return `one of ${quoted.join(', ')}`
}

const KEY_ACTIONS = ['press', 'repeat', 'release']

/** A key's name: one character that is not a control character, or the name of a key that makes none. */
const keyName = stringThen((key) => {
  const scalars = [...key]
  if (scalars.length === 1) {
    return controlCharacter(key.codePointAt(0) ?? 0) ? "a key's character is never a control character" : null
  }
  return key.length > 0 && new TextEncoder().encode(key).length <= 32 && /^[A-Za-z0-9]+$/.test(key)
    ? null
    : 'a key is one character or the name of a key'
})

/** The character a key makes with nothing held: one scalar, never a control character. */
const keyCharacter = stringThen((text) => {
  const scalars = [...text]
  if (scalars.length !== 1) return "a key's character is one character"
  return controlCharacter(text.codePointAt(0) ?? 0) ? "a key's character is never a control character" : null
})

const committedText = stringThen((text) => {
  if (text.length === 0) return 'text says something'
  const bytes = new TextEncoder().encode(text).length
  if (bytes > MAX_TEXT_BYTES) return `text carries at most ${MAX_TEXT_BYTES} bytes at once, not ${bytes}`
  return [...text].some((scalar) => controlCharacter(scalar.codePointAt(0) ?? 0))
    ? 'text carries no control character: a key is sent as a key'
    : null
})

const pastedText = stringThen((text) => {
  if (text.length === 0) return 'a paste says something'
  const bytes = new TextEncoder().encode(text).length
  return bytes > MAX_PASTE_BYTES ? `a paste carries at most ${MAX_PASTE_BYTES} bytes at once, not ${bytes}` : null
})

/** How many times a wheel turns: a 32-bit integer, and then between one and the most, either way. */
const turnsOfAWheel: InputField['problem'] = (value) => {
  const read = wholeNumber(I32)(value)
  if (read !== null) return read
  const turns = value as number
  return turns === 0 || Math.abs(turns) > MAX_TURNS
    ? `a wheel turns between 1 and ${MAX_TURNS} times either way, not ${turns}`
    : null
}

/** The variants of an input, in the order native code declares them, each with its fields in order. */
const INPUT_VARIANTS: Readonly<Record<string, readonly InputField[]>> = {
  take: [{ name: 'number', problem: wholeNumber(U64) }],
  release: [{ name: 'number', problem: wholeNumber(U64) }],
  wheel: [
    { name: 'take', problem: wholeNumber(U64) },
    { name: 'column', problem: wholeNumber(U32) },
    { name: 'line', problem: wholeNumber(U32) },
    { name: 'turns', problem: turnsOfAWheel },
    { name: 'shift', problem: aFlag },
    { name: 'alt', problem: aFlag },
    { name: 'control', problem: aFlag }
  ],
  key: [
    { name: 'take', problem: wholeNumber(U64) },
    { name: 'key', problem: keyName },
    { name: 'base', problem: (value) => (value === null ? null : keyCharacter(value)), optional: true },
    { name: 'keypad', problem: (value) => (value === null ? null : oneNamed(KEYPAD)(value)), optional: true },
    { name: 'shift', problem: aFlag },
    { name: 'alt', problem: aFlag },
    { name: 'control', problem: aFlag },
    { name: 'caps_lock', problem: aFlag },
    { name: 'num_lock', problem: aFlag },
    { name: 'event', problem: oneNamed(KEY_ACTIONS) }
  ],
  text: [
    { name: 'take', problem: wholeNumber(U64) },
    { name: 'text', problem: committedText }
  ],
  paste: [
    { name: 'take', problem: wholeNumber(U64) },
    { name: 'text', problem: pastedText }
  ]
}

const INPUT_KINDS = Object.keys(INPUT_VARIANTS)

/** The plural of "element", as the decoder counts a variant's. */
const elements = (count: number): string => `${count} element${count === 1 ? '' : 's'}`

/**
 * The page's input read as native code reads it, or why native code refuses it, in the decoder's own
 * words: the input is one of the variants of an internally tagged type, its fields are read in the
 * order the map holds them (keys sorted, as a map of JSON values holds them), the first that is
 * unknown or wrong ends the reading, and a field left out is the first left out in declaration order,
 * but for a key's unshifted character and keypad key, which are none. A whole number, a flag, text
 * and a choice are read as the field's own type reads them. A value written as a sequence is read
 * field by field in the same order. The words for a number that is not a whole number use the
 * decoder's notation for a floating point number; a map given for a choice, which the decoder reads
 * as a one-entry map, is not modelled and is refused as a choice given by anything but a name.
 */
export function readTerminalInput(value: unknown): TerminalInput | string {
  if (Array.isArray(value)) return readInputSequence(value)
  if (typeof value !== 'object' || value === null) {
    return `invalid type: ${withinParameters(value)}, expected internally tagged enum Input`
  }
  const fields = value as Record<string, unknown>
  if (!('kind' in fields)) return 'missing field `kind`'
  const kind = fields['kind']
  if (typeof kind !== 'string') return `invalid type: ${withinParameters(kind)}, expected variant identifier`
  const declared = INPUT_VARIANTS[kind]
  if (declared === undefined || !Object.hasOwn(INPUT_VARIANTS, kind)) {
    return `unknown variant \`${kind}\`, expected ${listed(INPUT_KINDS)}`
  }
  const names = declared.map((field) => field.name)
  for (const name of Object.keys(fields).sort()) {
    if (name === 'kind') continue
    const field = declared.find((each) => each.name === name)
    if (field === undefined) {
      return `unknown field \`${name}\`, expected ${listed(names)}`
    }
    const problem = field.problem(fields[name])
    if (problem !== null) return problem
  }
  for (const field of declared) {
    if (!(field.name in fields) && field.optional !== true) return `missing field \`${field.name}\``
  }
  return inputOf(kind, (name) => fields[name])
}

/** An input written as a sequence: its variant's name, then its fields in declaration order. */
function readInputSequence(sequence: readonly unknown[]): TerminalInput | string {
  const [kind, ...rest] = sequence
  if (sequence.length === 0) return 'missing field `kind`'
  if (typeof kind !== 'string') return `invalid type: ${withinParameters(kind)}, expected variant identifier`
  const declared = Object.hasOwn(INPUT_VARIANTS, kind) ? INPUT_VARIANTS[kind] : undefined
  if (declared === undefined) return `unknown variant \`${kind}\`, expected ${listed(INPUT_KINDS)}`
  for (const [index, field] of declared.entries()) {
    if (index >= rest.length) {
      return `invalid length ${rest.length}, expected struct variant Input::${kind[0]?.toUpperCase() ?? ''}${kind.slice(1)} with ${elements(declared.length)}`
    }
    const problem = field.problem(rest[index])
    if (problem !== null) return problem
  }
  if (rest.length > declared.length) {
    return `invalid length ${rest.length}, expected ${elements(declared.length)} in sequence`
  }
  return inputOf(kind, (name) => rest[declared.findIndex((field) => field.name === name)])
}

/** The input a kind and its fields make, once every field is read. */
function inputOf(kind: string, field: (name: string) => unknown): TerminalInput {
  const flag = (name: string) => field(name) as boolean
  const whole = (name: string) => field(name) as number
  switch (kind) {
    case 'take':
    case 'release':
      return { kind, number: whole('number') }
    case 'wheel':
      return {
        kind,
        take: whole('take'),
        column: whole('column'),
        line: whole('line'),
        turns: whole('turns'),
        shift: flag('shift'),
        alt: flag('alt'),
        control: flag('control')
      }
    case 'key':
      return {
        kind,
        take: whole('take'),
        key: field('key') as string,
        base: (field('base') ?? null) as string | null,
        keypad: (field('keypad') ?? null) as KeypadCode | null,
        shift: flag('shift'),
        alt: flag('alt'),
        control: flag('control'),
        caps_lock: flag('caps_lock'),
        num_lock: flag('num_lock'),
        event: field('event') as KeyAction
      }
    case 'text':
    case 'paste':
      return { kind, take: whole('take'), text: field('text') as string }
    default:
      throw new Error(`no input of kind ${kind}`)
  }
}

/** Where a view's window starts: its first column, and its line of the live screen or its rows above. */
export interface TerminalPlace {
  readonly column: number
  readonly line: number
  readonly above: number
}

/** The live screen's first line and column, where a window starts until it is moved. */
const HOME: TerminalPlace = { column: 0, line: 0, above: 0 }

/** One session's screen: its size, the history it keeps above the live screen, and the live screen. */
interface FakeScreen {
  readonly columns: number
  readonly rows: number
  /** Oldest first. */
  readonly history: readonly string[]
  readonly live: readonly string[]
}

function fakeScreenOf(sessionId: string): FakeScreen {
  if (sessionId === SESSION_MAIN) {
    return {
      columns: 80,
      rows: 8,
      history: Array.from({ length: 12 }, (_, index) => `$ echo earlier ${index + 1}`),
      live: [
        '$ cargo test -p kr-client',
        '   Compiling kr-client v0.1.0',
        '    Finished test profile in 12.4s',
        'ok    done',
        'test result: ok. 143 passed',
        '$ ',
        '',
        ''
      ]
    }
  }
  return {
    columns: 100,
    rows: 4,
    history: [],
    live: ['$ pnpm -r build', 'apps/companion build: done', '$ ', '']
  }
}

/** The room a window of `grid` at `place` has on `session`'s screen. */
function roomOf(session: FakeScreen, grid: TerminalGrid, place: TerminalPlace): TerminalRoom {
  const rows = Math.min(grid.rows, session.rows)
  const columns = Math.min(grid.columns, session.columns)
  const top = place.above > 0 ? -place.above : place.line
  return {
    up: session.history.length + top,
    down: session.rows - rows - top,
    left: place.column,
    right: session.columns - columns - place.column
  }
}

/** `place`, held inside what a window of `grid` can reach on the session's screen. */
function heldInside(sessionId: string, grid: TerminalGrid, place: TerminalPlace): TerminalPlace {
  const session = fakeScreenOf(sessionId)
  const rows = Math.min(grid.rows, session.rows)
  const columns = Math.min(grid.columns, session.columns)
  const top = Math.min(place.above > 0 ? -place.above : place.line, session.rows - rows)
  return {
    column: Math.min(place.column, session.columns - columns),
    line: top < 0 ? 0 : top,
    above: top < 0 ? -top : 0
  }
}

/** Where `move` takes a window of `grid` at `place`, held to its room, as native code moves it. */
function moved(sessionId: string, grid: TerminalGrid, place: TerminalPlace, move: TerminalMove): TerminalPlace {
  const top = place.above > 0 ? -place.above : place.line
  if ('live' in move) return top < 0 ? { column: place.column, line: 0, above: 0 } : place
  const room = roomOf(fakeScreenOf(sessionId), grid, place)
  const down = Math.min(room.down, Math.max(-room.up, move.down))
  const across = Math.min(room.right, Math.max(-room.left, move.across))
  const next = top + down
  return {
    column: place.column + across,
    line: next < 0 ? 0 : next,
    above: next < 0 ? -next : 0
  }
}

/**
 * A session's screen as native code publishes it for a view of `grid` whose window is at `place`:
 * the part of the session the window holds, as lines of pieces, with where the window starts and
 * how far it can still move.
 *
 * Each session has a screen of its own, so a view that shows one session's screen under another's
 * name is caught by what it draws. The main session keeps some history above its live screen, and
 * its live screen has a run native code could not place: a joined emoji the host measures at two
 * cells, which the pinned width model does not, left blank and counted.
 */
export function terminalScreen(
  sessionId: string,
  grid: TerminalGrid,
  place: TerminalPlace = HOME
): TerminalScreen {
  const main = sessionId === SESSION_MAIN
  const session = fakeScreenOf(sessionId)
  const { columns, rows } = session
  const top = place.above > 0 ? -place.above : place.line
  const window = {
    columns: Math.min(grid.columns, columns),
    rows: Math.min(grid.rows, rows),
    column: place.column,
    line: place.line,
    above: place.above
  }
  const texts = Array.from({ length: window.rows }, (_, offset) => {
    const index = top + offset
    return index < 0 ? (session.history[session.history.length + index] ?? '') : (session.live[index] ?? '')
  })
  const lines: TerminalLine[] = texts.map((text, offset) => {
    const index = top + offset
    const shown = text.slice(place.column, place.column + window.columns)
    const pieces =
      shown.length === 0 ? [] : [{ column: 0, cells: shown.length, text: shown, rendition: PLAIN, hyperlink: null }]
    // Where the emoji was: blank cells of its run, at the column it started at.
    if (main && index === 3 && place.column === 0 && window.columns > 4) {
      pieces.splice(0, pieces.length, {
        column: 0,
        cells: 2,
        text: 'ok',
        rendition: PLAIN,
        hyperlink: null
      }, {
        column: 3,
        cells: 2,
        text: '  ',
        rendition: PLAIN,
        hyperlink: null
      }, {
        column: 6,
        cells: 4,
        text: 'done'.slice(0, Math.max(0, window.columns - 6)),
        rendition: PLAIN,
        hyperlink: null
      })
    }
    return { row: String((main ? 101 : 201) + index), soft_wrapped: false, truncated: false, pieces }
  })
  const cursorLine = (main ? 5 : 2) - top
  const cursorColumn = 2 - place.column
  return {
    dimensions: { columns: String(columns), rows: String(rows) },
    window,
    room: roomOf(session, grid, place),
    lines,
    cursor:
      cursorLine >= 0 && cursorLine < window.rows && cursorColumn >= 0 && cursorColumn < window.columns
        ? { column: cursorColumn, line: cursorLine, visible: true, style: 1 }
        : null,
    palette: {
      source: 'client_preference',
      foreground: { red: 0xdc, green: 0xdc, blue: 0xda },
      background: { red: 0x07, green: 0x12, blue: 0x17 },
      cursor: { red: 0xdc, green: 0xdc, blue: 0xda },
      pointer_foreground: { red: 0xdc, green: 0xdc, blue: 0xda },
      pointer_background: { red: 0x07, green: 0x12, blue: 0x17 },
      selection_background: { red: 0x31, green: 0x5e, blue: 0x4a },
      selection_foreground: { red: 0xff, green: 0xff, blue: 0xff },
      overrides: [{ index: 1, colour: { red: 0xa2, green: 0x35, blue: 0x2e } }]
    },
    degraded: false,
    replaced: main && place.column === 0 && top <= 3 && top + window.rows > 3 ? 1 : 0,
    // The session's program reports the mouse in an encoding a view writes.
    wheel: 'reaches'
  }
}

/** A cell with no attributes, in the session's default colours. */
const PLAIN = {
  background: 'default',
  blink: 'none',
  bold: false,
  faint: false,
  foreground: 'default',
  invisible: false,
  italic: false,
  overline: false,
  reverse: false,
  strikethrough: false,
  underline: 'none',
  underline_colour: 'default',
  vertical_align: 'baseline'
} as const

/* ---- First-start setup --------------------------------------------------------------------- */

/** The settings panes this host says it will open, which is the list the backend holds. */
const SETTINGS_PANES: readonly SettingsPane[] = [
  {
    id: 'accessibility',
    route: 'System Settings → Privacy & Security → Accessibility',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'
  },
  {
    id: 'screen_recording',
    route: 'System Settings → Privacy & Security → Screen & System Audio Recording',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture'
  },
  {
    id: 'full_disk_access',
    route: 'System Settings → Privacy & Security → Full Disk Access',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'
  },
  {
    id: 'automation',
    route: 'System Settings → Privacy & Security → Automation',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_Automation'
  },
  {
    id: 'microphone',
    route: 'System Settings → Privacy & Security → Microphone',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone'
  },
  {
    id: 'remote_desktop',
    route: 'System Settings → Privacy & Security → Remote Desktop',
    url: 'x-apple.systempreferences:com.apple.preference.security?Privacy_RemoteDesktop'
  }
]

/** The identity this host reports for the application asking. */
function setupIdentity(stable: boolean, connected: boolean): SetupIdentity {
  return {
    application_id: 'to.kala.reach',
    application_version: '0.1.0',
    executable: stable
      ? '/Applications/KalaReach.app/Contents/MacOS/kalareach-companion'
      : '/Users/sam/work/kalareach/target/debug/kalareach-companion',
    bundled: stable,
    signature: stable
      ? {
          read: true,
          authority: 'Developer ID Application: Kala',
          team: 'ABCDE12345',
          identifier: 'to.kala.reach',
          ad_hoc: false,
          valid: true,
          refusal: null
        }
      : {
          read: true,
          authority: null,
          team: null,
          identifier: 'kalareach_companion-11a57fcfccad3743',
          ad_hoc: true,
          valid: true,
          refusal: null
        },
    stable,
    instability: stable
      ? null
      : '/Users/sam/work/kalareach/target/debug/kalareach-companion carries an ad-hoc signature, ' +
        'which is one this machine made for this file and nothing else can vouch for. The ' +
        'operating system files a grant against it, and the next build of this application ' +
        'carries a different one, so every grant given now has to be given again. Install a ' +
        'signed build before granting anything.',
    unverified:
      'This reads the identity a grant is filed under, and the signature on it. It cannot tell ' +
      'you a permission has been granted: on this platform the only way to establish that is to ' +
      'perform the operation the permission guards.',
    helper_build: connected ? 'kr-controller 0.1.0+2fe00021' : null,
    helper_environment: connected ? ENVIRONMENT : null
  }
}

/**
 * One capability record, in the shape the host publishes it.
 *
 * A granted capability is one this host performed the operation for; a capability that is not
 * granted is one it performed the operation for and was refused. Both are `disclosed_probe`,
 * because a refusal by the operating system is the operation having been performed and answered.
 */
function capabilityRecord(
  capability: string,
  grantedNow: boolean,
  revision: number,
  detail: { readonly permission: string; readonly binary: string; readonly probed: boolean }
): CapabilityRecord {
  return {
    capability,
    version: '1',
    subject: {
      environment_id: ENVIRONMENT,
      desktop_session_id: 'macos_security_session:user=sam:uid=501:session=100019:generation=42:boot=abcd',
      session_id: null,
      application: null,
      terminal: null
    },
    revision: String(revision),
    state: detail.probed
      ? grantedNow
        ? 'qualified_available'
        : 'permission_required'
      : 'not_tested',
    evidence_source: detail.probed ? 'disclosed_probe' : 'not_probed',
    identity: {
      binary: detail.binary,
      version: '1502942 bytes, digest 8a1f2c3d4e5f6071',
      package: null,
      schema: null,
      profile: 'desktop_bound'
    },
    invalidation: ['binary_identity', 'os_permission', 'desktop_generation', 'worker_profile'],
    disabled_reason: detail.probed
      ? grantedNow
        ? 'this context performed the operation and it worked. That is what establishes it, and it ' +
          'establishes it for this binary and this permission state only'
        : `this context performed the operation and the operating system refused it. ${detail.permission} ` +
          'is granted per signed application, and this one does not hold it'
      : 'this check delivers one keystroke to an application, so it runs only inside a test ' +
        'context of its own. None was supplied, so it was not run and nothing is established ' +
        'either way',
    observed_at_ms: String(FAKE_NOW_MS)
  }
}

/** What this host answers `environment.capabilities` with. */
function capabilities(granted: ReadonlySet<string>, revision: number): EnvironmentCapabilitiesResult {
  const record = (
    capability: string,
    permission: string,
    binary: string,
    probed = true
  ): CapabilityRecord =>
    capabilityRecord(capability, granted.has(capability), revision, { permission, binary, probed })

  return {
    environment_id: ENVIRONMENT,
    default_worker_profile: 'desktop_bound',
    desktop: {
      desktop: {
        desktop_session_id:
          'macos_security_session:user=sam:uid=501:session=100019:generation=42:boot=abcd',
        kind: 'macos_security_session',
        platform_session: '100019',
        login_generation: '42',
        generation_source: 'macos_session_creator',
        os_user: 'sam',
        uid: '501',
        boot_identity: { source: 'macos_boot_session_uuid', value: 'q80=' },
        graphic_access: true,
        remote: false,
        availability: 'available',
        container: 'host',
        display_server: 'quartz',
        compositor: 'Aqua',
        worker_profile: 'desktop_bound'
      },
      records: [
        record('desktop.accessibility', 'Accessibility', '/usr/bin/osascript'),
        record('desktop.application_launch', 'nothing', '/usr/bin/open'),
        record('desktop.authorised_file_read', 'Full Disk Access', '/Users/sam/Documents/kalareach-check.txt'),
        record('desktop.display_server', 'nothing', 'Aqua'),
        record('desktop.input_injection', 'Accessibility', '/usr/bin/osascript', false),
        record('desktop.screen_capture', 'Screen & System Audio Recording', '/usr/sbin/screencapture')
      ]
    },
    persistence: [
      {
        profile: 'desktop_bound',
        persistence: 'ends_at_logout',
        mechanism: 'launchd, a per-user job in the graphical domain',
        detail:
          'A desktop-bound session belongs to one graphical login. It survives losing every ' +
          'attachment and it survives this daemon restarting; it does not survive the login ' +
          'session ending, and it closes with reason desktop_lost when that happens.'
      },
      {
        profile: 'headless_user',
        persistence: 'not_established',
        mechanism: 'launchd, a per-user job in the background domain',
        detail:
          "A headless session's job is loaded into this user's background domain, which outlives " +
          'the graphical login. How long that domain lasts after the last session is the ' +
          "platform's own behaviour and this host does not read it, so what a logout does to a " +
          'headless session here is not established.'
      }
    ],
    power: {
      setting: 'off',
      active: false,
      reason: null,
      mechanism: 'macos_power_assertion',
      holder: null,
      power_source: 'mains',
      withheld_reason: null,
      pending_requests: '0',
      sessions_with_work: '0',
      since_ms: null
    }
  }
}
