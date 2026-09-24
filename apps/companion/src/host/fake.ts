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
  CapabilityRecord,
  ClosureRecord,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  HostInfoResult,
  Receipt,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult,
  VoiceContextResult,
  VoiceManagedTerms,
  VoicePrepareResult,
  VoiceRate,
  VoiceSessionDescriptor
} from '@kalareach/protocol'

import type {
  AttentionInbox,
  ChangeSets,
  IssuedGrants,
  LaunchSurface,
  PackageViews,
  RetainedArtefacts
} from '../model/pending'
import type {
  ApprovedLink,
  DroppedFile,
  HostEvent,
  HostPort,
  ImportedImage,
  OwnerView,
  PairingView,
  PasteView,
  ProjectedScreen,
  ReviewOutcome,
  SettingsPane,
  SetupIdentity,
  VoiceCallState,
  VoiceStartRequest,
  Written
} from './port'
import { codeComplete } from '../pairing/words'

const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'
const VOICE_SESSION = '6c5d4e30-33cc-4d4e-9f5a-000000000201'
const VOICE_GRANT = '5b4c3d20-44dd-4e5f-8a6b-000000000202'
const VOICE_NOW_MS = 1_763_000_000_000
const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const SESSION_OFFLINE = '8a7b6c50-22bb-4c3d-8e4f-000000000103'

/** The moment every timestamp in this host is measured from, so a run is reproducible. */
export const FAKE_NOW_MS = 1_763_000_000_000

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

/** What the fake host can be told to do before a test drives the interface. */
export interface FakeHostControls {
  /** Pushes one event to every subscriber. */
  emit(event: HostEvent): void
  /** Appends one node to a session's conversation and tells the interface about it. */
  appendNode(node: DocumentNode, sessionId?: string): void
  /** Moves the prompt generation on, which disables the launch buttons. */
  changePromptGeneration(): void
  /** Marks the host as unreachable, or reachable again. */
  setConnected(connected: boolean): void
  /** Hands the window a set of dropped files. */
  dropFiles(files: readonly DroppedFile[]): void
  /** What the interface asked the platform to save, in order. */
  readonly savedExports: Written[]
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
}

/** The fake host, and the controls a test drives it with. */
export function fakeHost(): { port: HostPort; controls: FakeHostControls } {
  let connected = true
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
  const listeners = new Set<(event: HostEvent) => void>()
  const dropListeners = new Set<(files: readonly DroppedFile[]) => void>()
  const savedExports: Written[] = []
  const openedLinks: string[] = []
  const importedImages: string[] = []
  const uploaded: string[] = []
  const nodes: DocumentNode[] = startingConversation()
  const acknowledged = new Set<string>()
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

  const requireConnection = () => {
    if (!connected) {
      refuse('RESOURCE_UNAVAILABLE', 'This host cannot be contacted right now.')
    }
  }

  const emit = (event: HostEvent) => {
    for (const listener of listeners) listener(event)
  }

  const port: HostPort = {
    connectionState: () =>
      Promise.resolve({
        connected,
        environment_id: connected ? ENVIRONMENT : null,
        reason: connected ? null : 'this host cannot be contacted right now'
      }),

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

    hostInfo: () => {
      requireConnection()
      return Promise.resolve(hostInfo())
    },
    environmentList: () => {
      requireConnection()
      return Promise.resolve(environments())
    },

    sessionList: () => {
      requireConnection()
      return Promise.resolve(sessions())
    },
    sessionRead: (params) => {
      requireConnection()
      const sessionId = (params as { session_id?: string }).session_id ?? SESSION_MAIN
      const found = sessions().sessions.find((session) => session.session_id === sessionId)
      if (!found) refuse('UNKNOWN_SESSION', 'That session is not on this host.')
      return Promise.resolve({ endpoint: null, session: found } as unknown as SessionReadResult)
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

    launchSurface: () => {
      requireConnection()
      return Promise.resolve(fakeLaunchSurface(true, String(promptGeneration)))
    },
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

    agentSnapshot: () => {
      requireConnection()
      return Promise.resolve({ nodes: [...nodes] })
    },
    agentCommands: () =>
      Promise.resolve({
        commands: [
          { name: '/compact', summary: 'Shorten the conversation so far' },
          { name: '/model', summary: 'Change the model for this session' },
          { name: '/review', summary: 'Review the current change set' }
        ]
      }),
    composerSubmit: (params) => {
      requireConnection()
      const text = (params as { text?: string }).text ?? ''
      const actionId = nextActionId()
      const node: DocumentNode = {
        id: `n-${actionId}`,
        revision: '1',
        body: { kind: 'message', author: 'you', text }
      }
      nodes.push(node)
      emit({
        stream_id: `semantic:${SESSION_MAIN}`,
        sequence: String(nodes.length),
        body: { kind: 'node', node }
      })
      return Promise.resolve({
        receipt: receipt(actionId, 'applied', 'agent.prompt.submit'),
        value: null,
        action_id: actionId
      })
    },
    composerQueue: () => {
      requireConnection()
      return Promise.resolve(settledAs('agent.prompt.queue', 'accepted'))
    },
    composerSteer: () => {
      requireConnection()
      return Promise.resolve(settledAs('agent.turn.steer', 'applied'))
    },
    composerInterrupt: () => {
      requireConnection()
      return Promise.resolve(settledAs('agent.turn.cancel', 'applied'))
    },
    approvalRespond: (params) => {
      requireConnection()
      const decision = (params as { decision?: string }).decision ?? 'deny'
      const actionId = nextActionId()
      emit({
        stream_id: 'receipts',
        sequence: String(actionCounter),
        body: { kind: 'receipt', receipt: receipt(actionId, 'applied', 'agent.approval.respond') }
      })
      return Promise.resolve({
        receipt: receipt(actionId, 'applied', 'agent.approval.respond'),
        value: { decision },
        action_id: actionId
      })
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
    draftAddAttachment: (params) => {
      requireConnection()
      const method = (params as { insertion_method?: string }).insertion_method
      if (!(params as { transfer_id?: string }).transfer_id) {
        refuse('INVALID_ARGUMENT', 'a draft attachment names the transfer that produced it')
      }
      if (method === 'verified_composer_insertion') {
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

    historyPage: () =>
      Promise.resolve({
        rows: [],
        oldest_retained_row: 0,
        eviction_marker: null
      }),
    attentionRead: () => {
      requireConnection()
      return Promise.resolve(attention(acknowledged))
    },
    attentionAcknowledge: (params) => {
      const id = (params as { attention_id?: string }).attention_id
      if (id) acknowledged.add(id)
      return Promise.resolve(settledAs('attention.acknowledge', 'applied'))
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
    grantList: () => Promise.resolve(grants() as unknown),
    grantCreate: (params) => {
      const asked = params as { role?: string; rights?: string[] }
      const wantsAnswering = asked.rights?.includes('question.respond') ?? false
      const isReadOnlyRole = asked.role === 'viewer' || asked.role === 'reviewer'
      const explained = (params as { answering_explained?: boolean }).answering_explained ?? false
      if (wantsAnswering && isReadOnlyRole && !explained) {
        refuse(
          'PERMISSION_DENIED',
          'A viewer or reviewer receives question.respond only through the explained invitation option.'
        )
      }
      return Promise.resolve(settledAs('grant.create', 'applied'))
    },

    pluginList: () => Promise.resolve(packages() as unknown),
    catalogueList: () => Promise.resolve(packages() as unknown),

    changesetRead: () => Promise.resolve(changesets() as unknown),

    storageStatus: () => Promise.resolve(retained(deletedArtefacts) as unknown),
    storageObjectDelete: (params) => {
      const id = (params as { object_id?: string }).object_id
      const artefact = retained(new Set()).artefacts.find((each) => each.object_id === id)
      if (artefact?.held_by_other_party) {
        refuse(
          'PERMISSION_DENIED',
          'A copy an authorised viewer holds is not reachable from this host.'
        )
      }
      if (id) deletedArtefacts.add(id)
      return Promise.resolve(settledAs('storage.object.delete', 'applied'))
    },

    terminalProjection: () => {
      requireConnection()
      return Promise.resolve(projection())
    },
    terminalInput: (params) => {
      requireConnection()
      return Promise.resolve({ accepted: true, sequence: '1', echo: params })
    },
    attachmentViewport: () =>
      Promise.resolve(settledAs('attachment.viewport', 'applied')),

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
    onPairing: (listener) => {
      pairingListeners.add(listener)
      return () => {
        pairingListeners.delete(listener)
      }
    },
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
    onConfirmations: (listener) => {
      ownerListeners.add(listener)
      return () => {
        ownerListeners.delete(listener)
      }
    },

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
      const written: Written = {
        path: request.path,
        byte_len: JSON.stringify(request.nodes).length,
        omissions: request.omissions
      }
      savedExports.push(written)
      return Promise.resolve(written)
    },
    exportAsciicast: (request) => {
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
      voice.call = { session: started, capture: voice.startCapture, playing: true, firstAudioMs: 410 }
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
            message: 'This host cannot be contacted right now.',
            user_action: 'retry'
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

    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    onFilesDropped(listener) {
      dropListeners.add(listener)
      return () => dropListeners.delete(listener)
    }
  }

  const controls: FakeHostControls = {
    emit,
    appendNode(node) {
      nodes.push(node)
      emit({
        stream_id: `semantic:${SESSION_MAIN}`,
        sequence: String(nodes.length),
        body: { kind: 'node', node }
      })
    },
    changePromptGeneration() {
      promptGeneration += 1
      emit({
        stream_id: 'session_state',
        sequence: String(promptGeneration),
        body: { kind: 'prompt_generation', prompt_generation: String(promptGeneration) }
      })
    },
    setConnected(next) {
      connected = next
      emit({
        stream_id: 'session_state',
        sequence: '0',
        body: { kind: 'connection', connected: next }
      })
    },
    dropFiles(files) {
      for (const listener of dropListeners) listener(files)
    },
    savedExports,
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
    reviewed
  }

  return { port, controls }
}

/** The scripted call, held apart from the host's own state because it is this device's. */
interface VoiceState {
  call: {
    session: VoiceSessionDescriptor
    capture: string
    playing: boolean
    firstAudioMs: number | null
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
    return { running: false, capture: 'idle', playing: false, first_audio_ms: null, control: 'none' }
  }
  return {
    running: true,
    capture: running.capture,
    playing: running.playing,
    first_audio_ms: running.firstAudioMs,
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

function environments(): EnvironmentListResult {
  return {
    environments: [
      {
        arch: 'aarch64',
        environment_id: ENVIRONMENT,
        label: 'studio · macOS',
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

function startingConversation(): DocumentNode[] {
  return [
    {
      id: 'n-1',
      revision: '1',
      body: { kind: 'message', author: 'you', text: 'Find why the reconnect test is flaky.' }
    },
    {
      id: 'n-2',
      revision: '1',
      body: {
        kind: 'markdown',
        source:
          'The test waits on a **timer**, not on the subscription.\n\n- the deadline is 2 s\n- the host answers in 1.9 s under load\n\nSee [the reconnect notes](https://docs.example.org/reconnect).'
      }
    },
    {
      id: 'n-3',
      revision: '2',
      body: { kind: 'tool', name: 'read_file', outcome: 'succeeded', summary: 'tests/reconnect.rs' }
    },
    {
      id: 'n-4',
      revision: '1',
      body: {
        kind: 'diff',
        files: [{ path: 'tests/reconnect.rs', added: 6, removed: 2, binary: false }]
      }
    },
    {
      id: 'n-5',
      revision: '1',
      body: { kind: 'approval_ref', approval_request_id: 'ar-1' }
    },
    {
      id: 'n-6',
      revision: '1',
      body: {
        kind: 'action_group',
        label: 'Change set',
        controls: [
          {
            accessible_description: 'Open the change set this turn produced',
            action_id: 'changeset.open',
            disabled_reason: null,
            enabled_when: { op: 'always' },
            icon: 'document',
            id: 'c-open',
            label: 'Open change set',
            parameters: { fields: [] },
            priority: 'primary',
            revision: '1',
            visible_when: { op: 'always' }
          }
        ]
      }
    }
  ] as unknown as DocumentNode[]
}

function attention(acknowledged: ReadonlySet<string>): AttentionInbox {
  const entries = [
    {
      attention_id: 'a-1',
      kind: 'pending_decision' as const,
      title: 'Run the release script',
      detail: 'Codex is asking to run a command that writes outside the repository.',
      host_label: 'studio',
      environment_id: ENVIRONMENT,
      session_id: SESSION_MAIN,
      session_epoch: '1',
      session_display_number: '1',
      application: 'Codex',
      raised_at_ms: FAKE_NOW_MS - 90_000,
      approval_request_id: 'ar-1',
      command_preview: 'scripts/release.sh --publish'
    },
    {
      attention_id: 'a-2',
      kind: 'failed_action' as const,
      title: 'Upload did not finish',
      detail: 'The environment is out of staging space.',
      host_label: 'studio',
      environment_id: ENVIRONMENT,
      session_id: SESSION_BUILD,
      session_epoch: '1',
      session_display_number: '2',
      application: 'Claude Code',
      raised_at_ms: FAKE_NOW_MS - 300_000,
      error_code: 'QUOTA_EXCEEDED'
    },
    {
      attention_id: 'a-3',
      kind: 'awaiting_review' as const,
      title: 'Six files changed',
      detail: 'The reconnect fix is ready to look at.',
      host_label: 'studio',
      environment_id: ENVIRONMENT,
      session_id: SESSION_MAIN,
      session_epoch: '1',
      session_display_number: '1',
      application: 'Codex',
      raised_at_ms: FAKE_NOW_MS - 600_000
    },
    {
      attention_id: 'a-4',
      kind: 'disconnected' as const,
      title: 'laptop has not been in contact',
      detail: 'Its sessions may still be running. Nothing here says they are not.',
      host_label: 'laptop',
      environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000002',
      session_id: null,
      session_epoch: null,
      session_display_number: null,
      application: null,
      raised_at_ms: FAKE_NOW_MS - 1_800_000,
      out_of_contact_ms: 1_800_000
    }
  ]
  return { entries: entries.filter((entry) => !acknowledged.has(entry.attention_id)) }
}

function changesets(): ChangeSets {
  return {
    changesets: [
      {
        changeset_id: 'cs-1',
        title: 'Wait on the subscription rather than a timer',
        session_id: SESSION_MAIN,
        captured_at_ms: FAKE_NOW_MS - 600_000,
        reviewed: false,
        files: [
          {
            path: 'tests/reconnect.rs',
            added: 6,
            removed: 2,
            hunks: [
              {
                header: '@@ -18,7 +18,11 @@',
                lines: [
                  { kind: 'context', text: '    let session = connect().await;' },
                  { kind: 'remove', text: '    sleep(Duration::from_secs(2)).await;' },
                  { kind: 'add', text: '    let screen = session.read_screen().await?;' },
                  { kind: 'add', text: '    assert!(screen.is_drawable());' }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}

function packages(): PackageViews {
  return {
    index_complete: true,
    installed: [
      {
        package_id: 'kala.codex-presentation',
        name: 'Codex presentation',
        publisher: 'Kala Powered',
        version: '1.4.0',
        enabled: true,
        pinned_generation: null,
        capabilities: ['presentation.declarative', 'broker.semantic_events']
      },
      {
        package_id: 'community.tmux-status',
        name: 'tmux status',
        publisher: 'community',
        version: '0.3.1',
        enabled: false,
        pinned_generation: '42',
        capabilities: ['metadata.match']
      }
    ],
    catalogue: [
      {
        package_id: 'kala.codex-presentation',
        name: 'Codex presentation',
        publisher: 'Kala Powered',
        summary: 'Rich presentation for Codex sessions.',
        version: '1.4.0',
        repository_id: 'official',
        installed: true,
        payload_available_offline: true
      },
      {
        package_id: 'kala.gemini-presentation',
        name: 'Gemini presentation',
        publisher: 'Kala Powered',
        summary: 'Rich presentation for Gemini sessions.',
        version: '1.1.0',
        repository_id: 'official',
        installed: false,
        payload_available_offline: false
      },
      {
        package_id: 'community.tmux-status',
        name: 'tmux status',
        publisher: 'community',
        summary: 'Shows the tmux status line in the session header.',
        version: '0.3.1',
        repository_id: 'community',
        installed: true,
        payload_available_offline: true
      }
    ],
    repositories: [
      {
        repository_id: 'official',
        label: 'KalaReach official',
        kind: 'official',
        publisher: 'Kala Powered',
        origin: 'https://packages.kala.to',
        generation: '188',
        synced_at_ms: FAKE_NOW_MS - 3_600_000,
        automatic_matching: true,
        pinned: false,
        metadata_expired: false
      },
      {
        repository_id: 'community',
        label: 'Community mirror',
        kind: 'mirror',
        publisher: 'community',
        origin: 'https://mirror.example.org',
        generation: '42',
        synced_at_ms: FAKE_NOW_MS - 86_400_000,
        automatic_matching: false,
        pinned: true,
        metadata_expired: true
      }
    ]
  }
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

function grants(): IssuedGrants {
  return {
    grants: [
      {
        grant_id: 'g-1',
        role: 'viewer',
        recipient: 'sam@example.org',
        rights: ['session.view'],
        expires_at_ms: FAKE_NOW_MS + 86_400_000
      }
    ]
  }
}

/**
 * A projected screen with the two things the raw view has to get right: a cluster the renderer
 * cannot reproduce, and a viewport above the live end.
 */
function projection(): ProjectedScreen {
  const line = (row: number, text: string) => ({
    row,
    cells: [...text].map((character) => ({ text: character, width: 1 }))
  })
  return {
    dimensions: { columns: '80', rows: '8' },
    rows: [
      line(101, '$ cargo test -p kr-client'),
      line(102, '   Compiling kr-client v0.1.0'),
      line(103, '    Finished test profile in 12.4s'),
      {
        row: 104,
        cells: [
          { text: 'o', width: 1 },
          { text: 'k', width: 1 },
          { text: ' ', width: 1 },
          // A family emoji: one cluster, two columns, and no font here can draw it.
          { text: '\u{1F468}‍\u{1F469}‍\u{1F467}', width: 2 },
          { text: '', width: 0 },
          { text: ' ', width: 1 },
          { text: 'd', width: 1 },
          { text: 'o', width: 1 },
          { text: 'n', width: 1 },
          { text: 'e', width: 1 }
        ]
      },
      line(105, 'test result: ok. 143 passed'),
      line(106, '$ '),
      line(107, ''),
      line(108, '')
    ],
    cursor: { column: 2, row: 106, visible: true },
    viewport_top_row: null,
    oldest_retained_row: 1,
    palette_provenance: 'client_probe',
    palette: [
      '#071217', '#a2352e', '#315e4a', '#7b500d', '#1a57b5', '#6b4d8a', '#2f6f74', '#dcdcda',
      '#585c60', '#faa49c', '#aad2bb', '#e7bf7a', '#8fb8f5', '#c0a6dc', '#8fb4a8', '#ffffff'
    ]
  }
}

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
    application_id: 'to.kala.companion',
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
          identifier: 'to.kala.reach.companion',
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
