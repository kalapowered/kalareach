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
  ClosureRecord,
  EnvironmentListResult,
  HostInfoResult,
  Receipt,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult
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
  OwnerPresence,
  ProjectedScreen,
  RendezvousOrigin,
  ScannedCode,
  Written
} from './port'

const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'
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

/** One field of a scanned payload, as text. */
function asText(value: unknown): string {
  return typeof value === 'string' ? value : ''
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
  return `00000000-0000-4000-8000-${String(actionCounter).padStart(12, '0')}`
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
}

/** The fake host, and the controls a test drives it with. */
export function fakeHost(): { port: HostPort; controls: FakeHostControls } {
  let connected = true
  let promptGeneration = 7
  let bufferRevision = 12
  let rendezvous: RendezvousOrigin = {
    origin: 'https://rendezvous.kala.to',
    host: 'rendezvous.kala.to',
    is_default: true
  }
  const listeners = new Set<(event: HostEvent) => void>()
  const dropListeners = new Set<(files: readonly DroppedFile[]) => void>()
  const savedExports: Written[] = []
  const openedLinks: string[] = []
  const importedImages: string[] = []
  const nodes: DocumentNode[] = startingConversation()
  const acknowledged = new Set<string>()
  const deletedArtefacts = new Set<string>()

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
    draftAddAttachment: (params) => {
      requireConnection()
      const method = (params as { insertion_method?: string }).insertion_method
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

    pairingOrigin: () => Promise.resolve(rendezvous),
    pairingSetOrigin: (origin) => {
      if (!origin.startsWith('https://')) {
        refuse('INVALID_ARGUMENT', 'A rendezvous origin is an https origin.')
      }
      const host = origin.slice('https://'.length).split('/')[0] ?? ''
      rendezvous = {
        origin: `https://${host}`,
        host: host.split(':')[0] ?? host,
        is_default: `https://${host}` === 'https://rendezvous.kala.to'
      }
      return Promise.resolve(rendezvous)
    },
    pairingScan: (payload) => {
      let parsed: Record<string, unknown>
      try {
        parsed = JSON.parse(payload) as Record<string, unknown>
      } catch {
        refuse('INVALID_ARGUMENT', 'That is not a pairing code.')
      }
      if (parsed.mode === 'direct') {
        return Promise.resolve({
          mode: 'direct',
          invitation_id: asText(parsed.invitation_id),
          endpoint_id: asText(parsed.endpoint_id),
          expires_at_ms: asText(parsed.expires_at_ms)
        } satisfies ScannedCode)
      }
      if (parsed.mode !== 'code') {
        refuse('INVALID_ARGUMENT', 'A QR without a supported pairing mode is not an invitation.')
      }
      const origin = asText(parsed.rendezvous_origin)
      const host = origin.slice('https://'.length).split('/')[0] ?? ''
      return Promise.resolve({
        mode: 'code',
        origin: {
          origin,
          host: host.split(':')[0] ?? host,
          is_default: origin === 'https://rendezvous.kala.to'
        },
        code: asText(parsed.code).replace(/[\s-]/g, ''),
        needs_origin_confirmation: origin !== rendezvous.origin
      } satisfies ScannedCode)
    },
    pairingVerifyOwner: (reason) =>
      Promise.resolve({
        verified: true,
        mechanism: 'test.platform_ceremony',
        reason
      } satisfies OwnerPresence),

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
    importedImages
  }

  return { port, controls }
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
