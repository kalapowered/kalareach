/**
 * The scripted host's own records for the methods whose shapes the protocol publishes.
 *
 * Each session's agent as its worker would keep it, the attention inbox, review state and change
 * sets, the devices and grants of sharing, the installed packages and enrolled repositories, and
 * each session's retained output. Every answer here is a published type in the form native code
 * hands the page, and every refusal is the code a real host answers with, in the order it checks:
 * a parameter map the method does not take is refused before anything else, an instance a session
 * does not have is a stale subject, a suspended binding is a conflict, a binding revision that
 * moved on is stale, a turn that is not the one running is a conflict, and a capability that is not
 * usable now is unsupported. A page continues only after a key or subject the host holds.
 *
 * It keeps state and changes it: a prompt starts a turn, a cancellation ends it, an answered
 * approval is resolved and is not answered twice. Time is a number the host is told.
 */

import type {
  ActionRight,
  AgentApprovalInspectParams,
  AgentApprovalInspectResult,
  AgentApprovalRespondParams,
  AgentApprovalRespondResult,
  AgentBindingState,
  AgentCancelParams,
  AgentCapabilitiesParams,
  AgentCapabilitiesResult,
  AgentCommand,
  AgentCommandsParams,
  AgentCommandsResult,
  AgentInstanceSummary,
  AgentMutationResult,
  AgentMutationTarget,
  AgentPromptParams,
  AgentSnapshotEntry,
  AgentSnapshotParams,
  AgentSnapshotResult,
  AgentSteerParams,
  AgentSubject,
  AttentionAcknowledgeParams,
  AttentionAcknowledgeResult,
  AttentionItem,
  AttentionReadParams,
  AttentionReadResult,
  AuthorityNotice,
  CatalogueListResult,
  CatalogueSummary,
  ChangesetReadParams,
  ChangesetReadResult,
  DecoderLedgerEntry,
  DeviceListParams,
  DeviceListResult,
  DeviceSummary,
  GrantCreateParams,
  GrantCreateResult,
  GrantListParams,
  GrantListResult,
  GrantSummary,
  HistoryPageParams,
  HistoryPageResult,
  InstanceCapabilityRecord,
  PendingResource,
  PluginListParams,
  PluginListResult,
  ReviewAcknowledgeParams,
  ReviewAcknowledgeResult,
  ReviewReadParams,
  ReviewReadResult,
  ReviewState,
  RoleSelection
} from '@kalareach/protocol'
import { bytesToBase64Url } from '@kalareach/protocol'

import {
  AGENT_CANCEL_PARAMS,
  AGENT_INSPECT_PARAMS,
  AGENT_PROMPT_PARAMS,
  AGENT_RESPOND_PARAMS,
  AGENT_SNAPSHOT_PARAMS,
  AGENT_STEER_PARAMS,
  AGENT_SUBJECT_PARAMS,
  ATTENTION_ACKNOWLEDGE_PARAMS,
  ATTENTION_READ_PARAMS,
  CHANGESET_READ_PARAMS,
  DEVICE_LIST_PARAMS,
  ENVIRONMENT_PARAMS,
  GRANT_CREATE_PARAMS,
  GRANT_LIST_PARAMS,
  HISTORY_PAGE_PARAMS,
  REVIEW_ACKNOWLEDGE_PARAMS,
  REVIEW_READ_PARAMS,
  ROLE_SELECTION,
  decodeParams
} from './fake-decode'
import type { GrantNotices, SessionAgents, Settled } from './port'

/** A refusal in the form a command's refusal arrives: data rather than an Error. */
function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a command's failure crosses as data
  throw { code, message, user_action: 'nothing' }
}

/** The identities and the clock the records are written against. */
export interface ScriptedIds {
  readonly environment: string
  readonly sessions: { readonly main: string; readonly build: string; readonly offline: string }
  readonly nowMs: number
}

/** The capability each composer action is checked against, as the broker names it. */
const CAPABILITIES = [
  'agent.approval',
  'agent.attachment',
  'agent.cancel',
  'agent.commands',
  'agent.prompt',
  'agent.prompt.queue',
  'agent.steer'
] as const

/** One session's agent, as its worker keeps it. */
interface ScriptedAgent {
  instances: AgentInstanceSummary[]
  sequence: number
  resources: PendingResource[]
  ledger: Map<string, DecoderLedgerEntry>
  binding: AgentBindingState
  capabilities: Map<string, InstanceCapabilityRecord>
  commands: AgentCommand[]
  entries: AgentSnapshotEntry[]
  /** How many of the oldest entries this host's filter withholds from this device. */
  withheld: number
  /** Entries the filter withholds wherever they are in the history, by their number. */
  withheldNodes: Set<string>
  /** The last entry the host let go, or nought while it has kept them all. */
  forgotten: number
  turns: number
}

/** How many entries one part of a snapshot carries here, so a longer history continues. */
export const SNAPSHOT_PART_ENTRIES = 40

/** The most bytes one history page carries, as the host bounds it. */
const MAX_HISTORY_PAGE_BYTES = 1024 * 1024

/** The most attention items one page carries. */
const MAX_ATTENTION_ITEMS = 200

/** Every action a grant can carry, in the host's own order: what the host's owner holds. */
export const EVERY_RIGHT: readonly ActionRight[] = [
  'session.view',
  'terminal.input',
  'terminal.geometry',
  'terminal.geometry.transfer',
  'terminal.palette',
  'agent.prompt',
  'agent.cancel',
  'agent.approval.respond',
  'question.respond',
  'files.read',
  'files.upload',
  'files.apply_diff',
  'project.create',
  'workspace.manage',
  'changeset.create',
  'session.create',
  'session.rename',
  'session.close',
  'session.share',
  'automation.manage',
  'host.manage',
  'voice.use'
]

/** Holds the list above to the protocol's own vocabulary: a right it leaves out fails the build. */
type Unlisted = Exclude<ActionRight, (typeof EVERY_RIGHT)[number]>
export const EVERY_RIGHT_LISTED: [Unlisted] extends [never] ? true : never = true

/** The fixed sentence each notice is stated in, as the host words it. */
export const NOTICE_SENTENCES: Readonly<Record<AuthorityNotice, string>> = {
  account_access:
    'Terminal input runs as your account. Anything this recipient types can do what you can do on this machine.',
  agent_permissions:
    'Prompts, approvals and answers, including free text, are input the agent may act on under its own permissions on this machine. This is not a restricted sandbox.',
  environment_writes: 'This recipient can change files and repositories in this environment.',
  delegation:
    'This recipient can pass on what it holds, narrowed but never enlarged, to somebody else.'
}

/** The actions each role carries by default, as the host compiles a role. */
const ROLE_ACTIONS: Readonly<Record<RoleSelection['role'], readonly ActionRight[]>> = {
  viewer: ['session.view'],
  reviewer: ['session.view', 'files.read'],
  controller: [
    'session.view',
    'files.read',
    'terminal.input',
    'terminal.geometry',
    'agent.prompt',
    'agent.cancel',
    'agent.approval.respond',
    'question.respond'
  ],
  owner: [
    'session.view',
    'files.read',
    'terminal.input',
    'terminal.geometry',
    'terminal.geometry.transfer',
    'terminal.palette',
    'agent.prompt',
    'agent.cancel',
    'agent.approval.respond',
    'question.respond',
    'session.rename',
    'session.close',
    'session.share'
  ]
}

/** The notices a set of actions carries, in the host's order. */
function noticesFor(actions: readonly ActionRight[]): AuthorityNotice[] {
  const carried = new Set<AuthorityNotice>()
  for (const action of actions) {
    if (action === 'terminal.input') carried.add('account_access')
    if (
      action === 'agent.prompt' ||
      action === 'agent.approval.respond' ||
      action === 'question.respond'
    ) {
      carried.add('agent_permissions')
    }
    if (
      action === 'files.upload' ||
      action === 'files.apply_diff' ||
      action === 'project.create' ||
      action === 'workspace.manage' ||
      action === 'changeset.create'
    ) {
      carried.add('environment_writes')
    }
    if (action === 'session.share') carried.add('delegation')
  }
  const order: readonly AuthorityNotice[] = [
    'account_access',
    'agent_permissions',
    'environment_writes',
    'delegation'
  ]
  return order.filter((notice) => carried.has(notice))
}

/** The actions a selection compiles to: the role's, plus the explicit option when asked. */
function actionsOf(selection: RoleSelection): ActionRight[] {
  const actions = new Set<ActionRight>(ROLE_ACTIONS[selection.role])
  if (selection.include_question_respond) actions.add('question.respond')
  return EVERY_RIGHT.filter((right) => actions.has(right))
}

/** The session a review subject belongs to. */
function reviewSession(subject: ReviewState['subject']): string {
  return 'change_set' in subject ? subject.change_set.session_id : subject.completed_turn.session_id
}

/** A hexadecimal digest of `seed`, the length of a SHA-256 one. */
function digestOf(seed: number): string {
  return seed.toString(16).padStart(2, '0').repeat(32).slice(0, 64)
}

/** An identifier in the form the protocol writes one, from a small number. */
function idOf(prefix: string, value: number): string {
  return `${prefix}-0000-4000-8000-${String(value).padStart(12, '0')}`
}

const INSTANCE_MAIN = idOf('a1a1a1a1', 1)
const INSTANCE_BUILD = idOf('a1a1a1a1', 2)
const APPROVAL = idOf('b2b2b2b2', 1)
const CHANGE_SET = idOf('c3c3c3c3', 1)
const PHONE = idOf('d4d4d4d4', 1)
const RETIRED_PHONE = idOf('d4d4d4d4', 2)

/** What the main session's agent has said so far. */
const MAIN_HISTORY: readonly (readonly [string, string])[] = [
  ['thread.started', 'Codex started a conversation in /Users/rs/work/kalareach.'],
  ['message', 'Find why the reconnect test is flaky.'],
  [
    'message',
    'The test waits on a **timer**, not on the subscription.\n\n- the deadline is 2 s\n- the host answers in 1.9 s under load\n\nSee [the reconnect notes](https://docs.example.org/reconnect).'
  ],
  ['tool.finished', 'read_file tests/reconnect.rs'],
  ['notification', 'Codex asks to run scripts/release.sh --publish']
]

/** The main session's retained output: a test run, with the colours and titles a shell writes. */
function mainOutput(): Uint8Array {
  const lines: string[] = ['\u001b]0;kalareach — zsh\u0007$ cargo test -p kr-client --test session']
  for (let index = 0; index < 900; index += 1) {
    lines.push(
      `test reconnect_${String(index).padStart(3, '0')} ... \u001b[32mok\u001b[0m`
    )
  }
  lines.push('\r\u001b[Kfinished 900 tests', '$ ')
  return new TextEncoder().encode(lines.join('\r\n'))
}

/** Where a session's retained output starts: the host let everything before this cursor go. */
const OUTPUT_OLDEST = 2048n

/**
 * How much of a session's newest output the host keeps in memory. A worker reads older output from
 * its spool, and a read from there stops where the memory begins, so a reader gets fewer bytes than
 * it asked for and reads on from where the answer ended.
 */
const OUTPUT_RESIDENT_BYTES = 8192n

/** A session's retained output: the cursor of its first byte, and the bytes from there. */
interface RetainedOutput {
  readonly oldest: bigint
  readonly bytes: Uint8Array
}

/** The scripted host's records, and the host methods that read and change them. */
export class ScriptedRecords {
  readonly #ids: ScriptedIds
  readonly #agents = new Map<string, ScriptedAgent>()
  /** The sessions created here, each running a shell with no agent in it yet. */
  readonly #shells = new Set<string>()
  readonly #output = new Map<string, RetainedOutput>()
  #attention: AttentionItem[]
  #revision = 10
  #reviews: ReviewState[]
  readonly #devices: DeviceSummary[]
  readonly #grants: GrantSummary[] = []
  #actions = 0
  #restarts = 0

  constructor(ids: ScriptedIds) {
    this.#ids = ids
    this.#agents.set(ids.sessions.main, this.#agent(INSTANCE_MAIN, MAIN_HISTORY, true))
    this.#agents.set(
      ids.sessions.build,
      this.#agent(INSTANCE_BUILD, [['thread.started', 'Claude Code started.']], false)
    )
    // The build session's agent takes prompts and nothing else: its upstream offers no queue and
    // no steering, and the page offers neither.
    for (const capability of ['agent.prompt.queue', 'agent.steer'] as const) {
      this.setCapability(ids.sessions.build, capability, 'incompatible')
    }
    this.#output.set(ids.sessions.main, { oldest: OUTPUT_OLDEST, bytes: mainOutput() })
    this.#attention = this.#startingAttention()
    this.#reviews = [
      {
        subject: { change_set: { session_id: ids.sessions.main, change_set_id: CHANGE_SET } },
        current_version: '2',
        acknowledged_version: null,
        acknowledged_at_ms: null,
        outstanding: true
      },
      {
        subject: { completed_turn: { session_id: ids.sessions.main, turn_id: 'turn-3' } },
        current_version: '1',
        acknowledged_version: '1',
        acknowledged_at_ms: String(ids.nowMs - 3_600_000),
        outstanding: false
      }
    ]
    this.#devices = [
      {
        device_id: PHONE,
        display_name: "Sam's iPhone",
        grant_id: idOf('e5e5e5e5', 1),
        paired_at_ms: String(ids.nowMs - 86_400_000),
        acknowledged_revision: '4',
        acknowledged_at_ms: String(ids.nowMs - 60_000),
        revoked: false,
        keys: null,
        manages_host: false
      },
      {
        device_id: RETIRED_PHONE,
        display_name: 'Old phone',
        grant_id: idOf('e5e5e5e5', 2),
        paired_at_ms: String(ids.nowMs - 900_000_000),
        acknowledged_revision: '2',
        acknowledged_at_ms: null,
        revoked: true,
        keys: null,
        manages_host: false
      }
    ]
  }

  #agent(
    instance: string,
    history: readonly (readonly [string, string])[],
    withApproval: boolean
  ): ScriptedAgent {
    const now = this.#ids.nowMs
    const agent: ScriptedAgent = {
      instances: [
        {
          application_instance_id: instance,
          plugin_id: 'openai.codex',
          profile_id: null,
          mode: 'native_bridge',
          bypass: null,
          started_at: String(now - 3_000_000),
          ended_at: null,
          refusal: null
        }
      ],
      sequence: 1,
      resources: [],
      ledger: new Map(),
      binding: {
        binding_revision: '4',
        thread_id: 'thread-7',
        turn_id: withApproval ? 'turn-9' : null,
        profile_id: null,
        mode: 'native_bridge',
        rich_mutations_suspended: false,
        suspension_reason: null
      },
      capabilities: new Map(),
      commands: [
        { name: 'compact', summary: 'Shorten the conversation so far', parameter_encoding: 'none' },
        { name: 'model', summary: 'Change the model for this session', parameter_encoding: 'text' },
        { name: 'review', summary: 'Review the current change set', parameter_encoding: 'none' }
      ],
      entries: history.map(([kind, text], index) => ({
        node: String(index + 1),
        kind,
        text,
        omitted_text_bytes: '0',
        observed_at: String(now - 600_000 + index * 1_000),
        binding_revision: '4',
        turn_id: null
      })),
      withheld: 0,
      withheldNodes: new Set(),
      forgotten: 0,
      turns: 9
    }
    for (const capability of CAPABILITIES) {
      agent.capabilities.set(capability, this.#record(instance, capability, 'qualified_available'))
    }
    if (withApproval) this.#raise(agent, instance, APPROVAL)
    return agent
  }

  #record(
    instance: string,
    capability: string,
    state: InstanceCapabilityRecord['state'],
    reason: string | null = null
  ): InstanceCapabilityRecord {
    return {
      capability_id: capability,
      capability_version: '1',
      application_instance_id: instance,
      identity: {
        binary_digest: null,
        binding_id: null,
        binding_revision: '4',
        desktop_generation: null,
        os_permission_held: null,
        package_digest: null,
        plugin_id: 'openai.codex',
        profile_id: null,
        publisher_id: null,
        qualification_profile_digest: null,
        schema_version: null
      },
      revision: String(++this.#revision),
      state,
      source: state === 'qualified_available' ? 'live_binding' : 'package_declaration',
      invalidated_by: ['binding_changed'],
      disabled_reason:
        state === 'qualified_available'
          ? null
          : (reason ?? 'This agent’s upstream does not offer this.'),
      observed_at: String(this.#ids.nowMs - 60_000)
    }
  }

  /** Raises one approval request on `agent`, with what its decoder read and offered. */
  #raise(agent: ScriptedAgent, instance: string, resource: string): void {
    const now = this.#ids.nowMs
    const request = '{"jsonrpc":"2.0","id":"req-7","method":"execCommandApproval","params":{"command":["scripts/release.sh","--publish"],"cwd":"/Users/rs/work/kalareach"}}'
    agent.resources.push({
      resource_id: resource,
      application_instance_id: instance,
      request: { connection: '1', upstream: '"req-7"' },
      kind: 'approval',
      method: 'execCommandApproval',
      classification: { class: 'mutation', declared: true },
      source_generation: '1',
      state: 'pending',
      durability: 'durable',
      deadline_ms: null,
      recorded_at: String(now - 90_000),
      interpretation_verified: true
    })
    agent.ledger.set(resource, {
      binding_id: idOf('f6f6f6f6', 1),
      plugin_id: 'openai.codex',
      publisher_id: 'openai',
      package_digest: digestOf(7),
      method: 'execCommandApproval',
      upstream_request_id: '"req-7"',
      source_generation: '1',
      source_digest: digestOf(9),
      source_bytes: bytesToBase64Url(new TextEncoder().encode(request)),
      projection: {
        schema_version: '1',
        summary: 'Run scripts/release.sh --publish in /Users/rs/work/kalareach',
        decisions: [
          { option_id: 'approved', label: 'Allow once' },
          { option_id: 'approved_for_session', label: 'Allow for this session' },
          { option_id: 'denied', label: 'Deny' }
        ]
      },
      deadline_ms: null,
      decoded_at: String(now - 89_000)
    })
  }

  #startingAttention(): AttentionItem[] {
    const { sessions, nowMs } = this.#ids
    const item = (
      over: Partial<AttentionItem> & Pick<AttentionItem, 'key' | 'rule'>
    ): AttentionItem => ({
      source: 'semantic',
      level: 'notable',
      session_id: sessions.main,
      summary: null,
      trusted: true,
      routing: 'owner_policy',
      occurrences: '1',
      first_seen_ms: String(nowMs - 90_000),
      last_seen_ms: String(nowMs - 90_000),
      notification: 'delivered',
      awaiting_delivery: false,
      acknowledged: false,
      uncertain: false,
      revision: '3',
      automation: null,
      ...over
    })
    return [
      item({
        key: 'attention.pending_approval|~7f1e2d3c4b5a69788796a5b4c3d2e1f0',
        rule: 'attention.pending_approval',
        level: 'urgent',
        summary: 'Codex asks to run scripts/release.sh --publish'
      }),
      item({
        key: 'attention.command_failed|~0a1b2c3d4e5f60718293a4b5c6d7e8f9',
        rule: 'attention.command_failed',
        source: 'host_events',
        session_id: sessions.build,
        summary: 'pnpm build ended with status 1',
        first_seen_ms: String(nowMs - 300_000),
        last_seen_ms: String(nowMs - 300_000),
        revision: '5'
      }),
      item({
        key: 'attention.review_ready|~1b2c3d4e5f60718293a4b5c6d7e8f90a',
        rule: 'attention.review_ready',
        level: 'informational',
        summary: 'Six files changed in the reconnect fix',
        first_seen_ms: String(nowMs - 600_000),
        last_seen_ms: String(nowMs - 600_000),
        revision: '6'
      }),
      item({
        key: 'attention.host_contact_lost|~2c3d4e5f60718293a4b5c6d7e8f90a1b',
        rule: 'attention.host_contact_lost',
        source: 'receipts',
        session_id: null,
        summary: 'laptop',
        first_seen_ms: String(nowMs - 1_800_000),
        last_seen_ms: String(nowMs - 60_000),
        revision: '7'
      }),
      item({
        key: 'attention.application_notice|~3d4e5f60718293a4b5c6d7e8f90a1b2c',
        rule: 'attention.application_notice',
        source: 'host_events',
        level: 'informational',
        session_id: sessions.build,
        summary: 'Build finished',
        trusted: false,
        routing: 'lease_holder',
        occurrences: '3',
        first_seen_ms: String(nowMs - 900_000),
        last_seen_ms: String(nowMs - 120_000),
        revision: '8'
      }),
      item({
        key: 'attention.pending_input|~4e5f60718293a4b5c6d7e8f90a1b2c3d',
        rule: 'attention.pending_input',
        source: 'questions',
        session_id: sessions.build,
        summary: null,
        first_seen_ms: String(nowMs - 200_000),
        last_seen_ms: String(nowMs - 200_000),
        revision: '9',
        uncertain: true
      })
    ]
  }

  /* ---- The session's agent ------------------------------------------------------------------ */

  /** The agent a session's worker keeps, or the refusal a session with no worker here answers. */
  #agentOf(sessionId: string): ScriptedAgent {
    const agent = this.#agents.get(sessionId)
    if (agent === undefined) {
      if (sessionId === this.#ids.sessions.offline || this.#shells.has(sessionId)) {
        // A session running a shell and nothing else: its worker is there and has no agent.
        const empty: ScriptedAgent = {
          instances: [],
          sequence: 0,
          resources: [],
          ledger: new Map(),
          binding: {
            binding_revision: '0',
            thread_id: null,
            turn_id: null,
            profile_id: null,
            mode: 'native_terminal',
            rich_mutations_suspended: false,
            suspension_reason: null
          },
          capabilities: new Map(),
          commands: [],
          entries: [],
          withheld: 0,
          withheldNodes: new Set(),
          forgotten: 0,
          turns: 0
        }
        this.#agents.set(sessionId, empty)
        return empty
      }
      refuse('UNKNOWN_SESSION', 'This session is not running on this computer.')
    }
    return agent
  }

  /** The agent a subject names, or the stale-subject refusal an instance it does not have gets. */
  #subjectAgent(subject: AgentSubject): ScriptedAgent {
    const agent = this.#agentOf(subject.session_id)
    const live = agent.instances.some(
      (instance) =>
        instance.application_instance_id === subject.application_instance_id &&
        instance.ended_at === null
    )
    if (!live) {
      refuse(
        'STALE_SESSION',
        `instance ${subject.application_instance_id} is not one this worker serves`
      )
    }
    return agent
  }

  /** Refuses a mutation while the binding's rich mutations are suspended, in the host's words. */
  #requireUnsuspended(agent: ScriptedAgent): void {
    if (agent.binding.rich_mutations_suspended) {
      refuse(
        'DRAFT_CONFLICT',
        agent.binding.suspension_reason ?? 'rich mutations are suspended until the binding is verified'
      )
    }
  }

  /**
   * Everything the broker checks before it takes a mutation, in the order it checks it: the
   * instance, its suspension, the binding revision, the turn, and last the capability.
   */
  #admit(target: AgentMutationTarget, capability: string, turn: string | null): ScriptedAgent {
    const agent = this.#subjectAgent(target.subject)
    this.#requireUnsuspended(agent)
    if (target.binding_revision !== agent.binding.binding_revision) {
      refuse(
        'STALE_SESSION',
        `the binding is at revision ${agent.binding.binding_revision}, not ${target.binding_revision}`
      )
    }
    if (turn !== null && turn !== agent.binding.turn_id) {
      refuse('DRAFT_CONFLICT', 'the turn named is not the one running')
    }
    const record = agent.capabilities.get(capability)
    if (record?.state !== 'qualified_available') {
      refuse('UNSUPPORTED_CAPABILITY', record?.disabled_reason ?? `${capability} is not available`)
    }
    return agent
  }

  #performed(agent: ScriptedAgent): Settled<AgentMutationResult> {
    this.#actions += 1
    return {
      receipt: null,
      value: {
        binding_revision: agent.binding.binding_revision,
        provenance: 'upstream_typed_rpc',
        upstream_request_id: `"req-${this.#actions}"`,
        turn_id: agent.binding.turn_id
      },
      action_id: null
    }
  }

  #observe(agent: ScriptedAgent, kind: string, text: string, omitted = 0): void {
    const last = agent.entries.at(-1)
    const node = last === undefined ? agent.forgotten + 1 : Number(last.node) + 1
    agent.entries.push({
      node: String(node),
      kind,
      text,
      omitted_text_bytes: String(omitted),
      observed_at: String(this.#ids.nowMs + node),
      binding_revision: agent.binding.binding_revision,
      turn_id: agent.binding.turn_id
    })
  }

  sessionAgents(sessionId: string): SessionAgents {
    const agent = this.#agentOf(sessionId)
    return {
      instances: { sequence: String(agent.sequence), instances: [...agent.instances] },
      resources: [...agent.resources]
    }
  }

  capabilities(params: unknown): AgentCapabilitiesResult {
    const read = decodeParams<AgentCapabilitiesParams>(params, AGENT_SUBJECT_PARAMS)
    const agent = this.#subjectAgent(read.subject)
    return {
      binding: { ...agent.binding },
      capabilities: {
        records: [...agent.capabilities.values()].sort((left, right) =>
          left.capability_id.localeCompare(right.capability_id)
        )
      }
    }
  }

  commands(params: unknown): AgentCommandsResult {
    const read = decodeParams<AgentCommandsParams>(params, AGENT_SUBJECT_PARAMS)
    const agent = this.#subjectAgent(read.subject)
    return { binding: { ...agent.binding }, commands: [...agent.commands] }
  }

  snapshot(params: unknown): AgentSnapshotResult {
    const read = decodeParams<AgentSnapshotParams>(params, AGENT_SNAPSHOT_PARAMS)
    const agent = this.#subjectAgent(read.subject)
    const from = read.from_node === null ? 1 : Number(read.from_node)
    const first = agent.entries[0] === undefined ? agent.forgotten + 1 : Number(agent.entries[0].node)
    // The filter withholds the oldest entries, as a grant that reaches back only so far does, and
    // what it withholds is not spent on the part.
    const withheld = new Set([
      ...agent.entries.slice(0, agent.withheld).map((entry) => entry.node),
      ...agent.withheldNodes
    ])
    const after = agent.entries.filter((entry) => Number(entry.node) >= from)
    const shown = after.filter((entry) => !withheld.has(entry.node))
    const part = shown.slice(0, SNAPSHOT_PART_ENTRIES)
    const next = shown[SNAPSHOT_PART_ENTRIES]
    // Each part counts what it withheld in the range it covers, which ends where the next begins.
    const end = next === undefined ? Number.POSITIVE_INFINITY : Number(next.node)
    const counted = after.filter((entry) => withheld.has(entry.node) && Number(entry.node) < end)
    return {
      binding: { ...agent.binding },
      entries: part,
      continuation:
        next === undefined
          ? null
          : {
              limit: 'nodes',
              limit_value: String(SNAPSHOT_PART_ENTRIES),
              from_node: next.node,
              nodes: String(part.length),
              bytes: '0'
            },
      history_gap: read.from_node !== null && from < first,
      withheld_entries: String(counted.length)
    }
  }

  inspect(params: unknown): AgentApprovalInspectResult {
    const read = decodeParams<AgentApprovalInspectParams>(params, AGENT_INSPECT_PARAMS)
    const agent = this.#subjectAgent(read.subject)
    const resource = agent.resources.find((each) => each.resource_id === read.resource_id)
    const decoding = agent.ledger.get(read.resource_id)
    if (
      resource === undefined ||
      decoding === undefined ||
      resource.application_instance_id !== read.subject.application_instance_id
    ) {
      refuse('STALE_SESSION', 'this worker holds no such interpreted request for that instance')
    }
    return {
      resource_id: resource.resource_id,
      state: resource.state,
      recorded_at: resource.recorded_at,
      decoding
    }
  }

  prompt(params: unknown, queued: boolean): Settled<AgentMutationResult> {
    const read = decodeParams<AgentPromptParams>(params, AGENT_PROMPT_PARAMS)
    if ((read.draft_id === null) === (read.text === null)) {
      refuse(
        'INVALID_ARGUMENT',
        read.draft_id === null
          ? 'a prompt names either a draft or inline text'
          : 'a prompt names a draft or inline text, not both'
      )
    }
    const agent = this.#admit(read.target, queued ? 'agent.prompt.queue' : 'agent.prompt', null)
    this.#observe(agent, 'message', read.text ?? 'The draft was submitted.')
    if (!queued && agent.binding.turn_id === null) {
      agent.turns += 1
      agent.binding = { ...agent.binding, turn_id: `turn-${agent.turns}` }
    }
    return this.#performed(agent)
  }

  steer(params: unknown): Settled<AgentMutationResult> {
    const read = decodeParams<AgentSteerParams>(params, AGENT_STEER_PARAMS)
    const agent = this.#admit(read.target, 'agent.steer', read.turn_id)
    this.#observe(agent, 'message', read.text)
    return this.#performed(agent)
  }

  cancel(params: unknown): Settled<AgentMutationResult> {
    const read = decodeParams<AgentCancelParams>(params, AGENT_CANCEL_PARAMS)
    const agent = this.#admit(read.target, 'agent.cancel', read.turn_id)
    const settled = this.#performed(agent)
    agent.binding = { ...agent.binding, turn_id: null }
    this.#observe(agent, 'thread.continued', 'The turn was cancelled.')
    return settled
  }

  respond(params: unknown): Settled<AgentApprovalRespondResult> {
    const read = decodeParams<AgentApprovalRespondParams>(params, AGENT_RESPOND_PARAMS)
    const agent = this.#subjectAgent(read.target.subject)
    // The broker checks the resource before anything else about the answer: whose it is, that it
    // is still open and was interpreted. Then the admission every mutation takes, suspension,
    // binding revision and the approval capability, and last the decision.
    const resource = agent.resources.find((each) => each.resource_id === read.resource_id)
    if (resource === undefined) refuse('STALE_SESSION', 'this worker holds no such pending request')
    if (resource.application_instance_id !== read.target.subject.application_instance_id) {
      refuse('PERMISSION_DENIED', `${read.resource_id} belongs to another application instance`)
    }
    if (resource.state !== 'pending') {
      refuse('QUESTION_RESOLVED', `this pending resource is already ${resource.state}`)
    }
    const decoding = agent.ledger.get(read.resource_id)
    if (decoding === undefined) {
      refuse('DRAFT_CONFLICT', `${read.resource_id} has no recorded interpretation to answer`)
    }
    this.#admit(read.target, 'agent.approval', null)
    if (!decoding.projection.decisions.some((decision) => decision.option_id === read.option_id)) {
      refuse('DRAFT_CONFLICT', `${read.option_id} is not one of the decisions this request offered`)
    }
    const mutation = this.#performed(agent).value
    if (mutation === null) refuse('RESOURCE_UNAVAILABLE', 'the answer was not recorded')
    agent.resources = agent.resources.map((each) =>
      each.resource_id === read.resource_id ? { ...each, state: 'resolved' } : each
    )
    this.#attention = this.#attention.filter((item) => item.rule !== 'attention.pending_approval')
    return {
      receipt: null,
      value: { mutation, resource_id: read.resource_id, state: 'resolved' },
      action_id: null
    }
  }

  /* ---- Retained output ----------------------------------------------------------------------- */

  history(params: unknown): HistoryPageResult {
    const read = decodeParams<HistoryPageParams>(params, HISTORY_PAGE_PARAMS)
    this.#agentOf(read.session_id)
    const retained = this.#output.get(read.session_id) ?? { oldest: 0n, bytes: new Uint8Array() }
    const oldest = retained.oldest
    const end = oldest + BigInt(retained.bytes.length)
    const resident = end - OUTPUT_RESIDENT_BYTES > oldest ? end - OUTPUT_RESIDENT_BYTES : oldest
    const asked = BigInt(read.from_cursor)
    const limit = BigInt(read.max_bytes)
    const bound = limit < 1n ? 1n : limit > BigInt(MAX_HISTORY_PAGE_BYTES) ? BigInt(MAX_HISTORY_PAGE_BYTES) : limit
    const start = asked < oldest ? oldest : asked > end ? end : asked
    const wanted = start + bound > end ? end : start + bound
    // A read from the spool stops where the memory begins.
    const stop = start < resident && wanted > resident ? resident : wanted
    const bytes = retained.bytes.slice(Number(start - oldest), Number(stop - oldest))
    return {
      from_cursor: String(start),
      next_cursor: String(stop),
      bytes: bytesToBase64Url(bytes),
      oldest_retained_cursor: String(oldest),
      gap:
        asked < oldest
          ? { from_cursor: String(asked), to_cursor: String(oldest), cause: 'retention' }
          : null
    }
  }

  /* ---- Attention and review ------------------------------------------------------------------ */

  attentionRead(params: unknown): AttentionReadResult {
    const read = decodeParams<AttentionReadParams>(params, ATTENTION_READ_PARAMS)
    const max = Number(read.max_items)
    if (max < 1 || max > MAX_ATTENTION_ITEMS) {
      refuse('INVALID_ARGUMENT', `a page carries 1 to ${MAX_ATTENTION_ITEMS} items`)
    }
    const shown = this.#attention.filter(
      (item) =>
        (read.include_acknowledged || !item.acknowledged) &&
        (read.session_id === null || item.session_id === read.session_id)
    )
    const after = read.after === null ? -1 : shown.findIndex((item) => item.key === read.after)
    if (read.after !== null && after === -1) {
      refuse('DRAFT_CONFLICT', `${read.after} is not one this caller holds, so a page cannot continue after it`)
    }
    const start = after + 1
    const items = shown.slice(start, start + max)
    return {
      items,
      more: start + max < shown.length,
      dropped: '0',
      gaps: [],
      quiet_hours: null,
      quiet_now: false,
      quiet_hours_provable: true
    }
  }

  attentionAcknowledge(params: unknown): Settled<AttentionAcknowledgeResult> {
    const read = decodeParams<AttentionAcknowledgeParams>(params, ATTENTION_ACKNOWLEDGE_PARAMS)
    for (const { key, revision } of read.items) {
      const held = this.#attention.find((item) => item.key === key)
      if (held !== undefined && BigInt(revision) > BigInt(held.revision)) {
        refuse('DRAFT_CONFLICT', `${key} is at revision ${held.revision}, not ${revision}`)
      }
    }
    const acknowledged: string[] = []
    const stale: string[] = []
    for (const { key, revision } of read.items) {
      const held = this.#attention.find((item) => item.key === key)
      if (held === undefined || held.revision !== revision) {
        stale.push(key)
        continue
      }
      acknowledged.push(key)
    }
    this.#attention = this.#attention.map((item) =>
      acknowledged.includes(item.key) ? { ...item, acknowledged: true } : item
    )
    this.#revision += 1
    return {
      receipt: null,
      value: { actor_id: 'owner:local', acknowledged, stale, revision: String(this.#revision) },
      action_id: null
    }
  }

  reviewRead(params: unknown): ReviewReadResult {
    const read = decodeParams<ReviewReadParams>(params, REVIEW_READ_PARAMS)
    const scoped = this.#reviews.filter(
      (review) =>
        (read.session_id === null || reviewSession(review.subject) === read.session_id) &&
        (read.subject === null || JSON.stringify(review.subject) === JSON.stringify(read.subject))
    )
    const after =
      read.after === null
        ? -1
        : scoped.findIndex((review) => JSON.stringify(review.subject) === JSON.stringify(read.after))
    if (read.after !== null && after === -1) {
      refuse('DRAFT_CONFLICT', 'that subject is not one this caller holds, so a page cannot continue after it')
    }
    const max = Number(read.max_reviews)
    const reviews = scoped.slice(after + 1, after + 1 + max)
    return { actor_id: 'owner:local', reviews, more: after + 1 + max < scoped.length }
  }

  reviewAcknowledge(params: unknown): Settled<ReviewAcknowledgeResult> {
    const read = decodeParams<ReviewAcknowledgeParams>(params, REVIEW_ACKNOWLEDGE_PARAMS)
    if (reviewSession(read.subject) !== read.session_id) {
      refuse('INVALID_ARGUMENT', 'the review subject belongs to another session than the one named')
    }
    const same = JSON.stringify(read.subject)
    const held = this.#reviews.find((review) => JSON.stringify(review.subject) === same)
    if (held === undefined) refuse('INVALID_ARGUMENT', 'this host holds no such review subject')
    if (BigInt(read.version) > BigInt(held.current_version)) {
      refuse(
        'DRAFT_CONFLICT',
        `the subject is at version ${held.current_version}, not ${read.version}`
      )
    }
    // An older version than one already acknowledged is not a retreat: the furthest version read
    // is what decides whether work remains.
    const furthest =
      held.acknowledged_version !== null &&
      BigInt(held.acknowledged_version) > BigInt(read.version)
        ? held.acknowledged_version
        : read.version
    const review: ReviewState = {
      ...held,
      acknowledged_version: furthest,
      acknowledged_at_ms: String(this.#ids.nowMs),
      outstanding: BigInt(furthest) < BigInt(held.current_version)
    }
    this.#reviews = this.#reviews.map((each) => (each === held ? review : each))
    this.#revision += 1
    return {
      receipt: null,
      value: { actor_id: 'owner:local', review, revision: String(this.#revision) },
      action_id: null
    }
  }

  changesetRead(params: unknown): ChangesetReadResult {
    const read = decodeParams<ChangesetReadParams>(params, CHANGESET_READ_PARAMS)
    if (read.change_set_id !== CHANGE_SET) {
      refuse('INVALID_ARGUMENT', `this host holds no change set ${read.change_set_id}`)
    }
    const version = read.version ?? '2'
    if (version !== '1' && version !== '2') {
      refuse('INVALID_ARGUMENT', `change set ${CHANGE_SET} has no version ${version}`)
    }
    const { environment, sessions, nowMs } = this.#ids
    const captured = (index: number): string => String(nowMs - 1_200_000 + index * 600_000)
    return {
      version: {
        change_set_id: CHANGE_SET,
        version,
        content_digest: digestOf(Number(version) + 20),
        label: 'Wait on the subscription rather than a timer',
        environment_id: environment,
        project_repository_id: idOf('a7a7a7a7', 1),
        workspace_id: idOf('a8a8a8a8', 1),
        repository_identity: { device: '16777220', file_id: '8812731' },
        worktree_identity: { device: '16777220', file_id: '8812730' },
        base_revision: '9f2c1e7ab35d04c6e8f1a2b3c4d5e6f708192a3b',
        base_reference: 'main',
        consistency: 'quiesced_capture',
        consistency_detail: 'A reservation held the workspace still for the whole read.',
        policy: {
          inclusion: {
            dirty_files: 'include',
            untracked_files: 'include',
            generated_artefacts: 'exclude',
            submodules: 'exclude',
            binary_files: 'include'
          },
          grant: { included_paths: [], excluded_paths: [], secret_rules_applied: true },
          quiescence_declared: true,
          quiescence_held: true,
          required_consistency: null
        },
        provenance: {
          actor_id: 'owner:local',
          method: 'changeset.capture',
          session_id: sessions.main,
          workflow_run_id: null,
          derived_from: version === '2' ? { change_set_id: CHANGE_SET, version: '1' } : null,
          derivation: version === '2' ? 'Captured again after further edits.' : '',
          note: ''
        },
        summary: {
          total_paths: '412',
          total_bytes: '1804233',
          from_git_objects: '406',
          from_working_tree: '6',
          deleted_paths: '1'
        },
        counts: [
          { class: 'tracked', total: '406', binary: '3', byte_len: '1795002' },
          { class: 'dirty_file', total: '5', binary: '0', byte_len: '9011' },
          { class: 'untracked_file', total: '1', binary: '0', byte_len: '220' }
        ],
        changes: [
          {
            path: 'tests/reconnect.rs',
            content_digest: digestOf(31),
            byte_len: '4120',
            executable: false,
            content: 'text',
            origin: 'working_tree',
            class: 'dirty_file',
            change: 'present',
            base_object_id: '3c1d9e0f',
            base_mode: '100644'
          },
          {
            path: 'crates/kr-client/src/reconnect.rs',
            content_digest: digestOf(32),
            byte_len: '18233',
            executable: false,
            content: 'text',
            origin: 'working_tree',
            class: 'dirty_file',
            change: 'present',
            base_object_id: '5e6f7a8b',
            base_mode: '100644'
          },
          {
            path: 'scripts/old-reconnect.sh',
            content_digest: digestOf(33),
            byte_len: '0',
            executable: true,
            content: 'text',
            origin: 'git_object',
            class: 'tracked',
            change: 'deleted',
            base_object_id: '7a8b9c0d',
            base_mode: '100755'
          }
        ],
        omitted_changes: '0',
        exclusions: [
          { path: '.env', reason: 'secret_rule', detail: 'A secret rule covers it, so it was never read.' },
          { path: 'target', reason: 'policy', detail: 'Generated artefacts are left out.' }
        ],
        omitted_exclusions: '0',
        limitations: [
          'Identical source does not reproduce network services, dependencies, secrets or graphical state.'
        ],
        captured_at_ms: captured(Number(version))
      },
      versions: ['1', '2'].map((each) => ({
        change_set_id: CHANGE_SET,
        version: each,
        content_digest: digestOf(Number(each) + 20),
        consistency: 'quiesced_capture',
        base_revision: '9f2c1e7ab35d04c6e8f1a2b3c4d5e6f708192a3b',
        derived_from: each === '2' ? { change_set_id: CHANGE_SET, version: '1' } : null,
        captured_at_ms: captured(Number(each))
      })),
      materialisations: [],
      results: [],
      evidence: []
    }
  }

  /* ---- Sharing -------------------------------------------------------------------------------- */

  deviceList(params: unknown): DeviceListResult {
    const read = decodeParams<DeviceListParams>(params, DEVICE_LIST_PARAMS)
    return {
      devices: this.#devices.filter((device) => read.include_revoked || !device.revoked),
      authority_revision: '4',
      feed_synchronised_at_ms: String(this.#ids.nowMs - 30_000),
      feed_stale: false
    }
  }

  grantNotices(selection: unknown): GrantNotices {
    const read = decodeParams<RoleSelection>(selection, ROLE_SELECTION)
    const actions = actionsOf(read)
    return {
      actions,
      notices: noticesFor(actions).map((notice) => ({ notice, sentence: NOTICE_SENTENCES[notice] }))
    }
  }

  grantCreate(params: unknown): Settled<GrantCreateResult> {
    const read = decodeParams<GrantCreateParams>(params, GRANT_CREATE_PARAMS)
    if (read.owner_confirmation !== null) {
      refuse(
        'INVALID_ARGUMENT',
        'an owner confirmation is completed through the owner-confirmation methods'
      )
    }
    if (read.selection.include_live_screen) {
      refuse(
        'INVALID_ARGUMENT',
        'this host cannot preview the screen this invitation would share, so it does not share it'
      )
    }
    const recipient = this.#devices.find((device) => device.device_id === read.recipient_device_id)
    if (recipient === undefined || recipient.revoked) {
      refuse('PERMISSION_DENIED', 'this host has no paired device with that identity')
    }
    this.#agentOf(read.session_id)
    const actions = actionsOf(read.selection)
    const notices = noticesFor(actions)
    const accepted = [...new Set(read.accepted_notices)].sort()
    if (JSON.stringify(accepted) !== JSON.stringify([...notices].sort())) {
      refuse(
        'PERMISSION_DENIED',
        'the issuer accepted a different set of consequences from the ones this grant carries'
      )
    }
    const lifetime = read.lifetime_ms === null ? 3_600_000 : Number(read.lifetime_ms)
    if (lifetime > 30 * 24 * 3_600_000) {
      refuse('INVALID_ARGUMENT', 'a session invitation lasts at most 30 days')
    }
    this.#actions += 1
    const history = {
      lower_bound_ms: read.selection.history_from_cursor_ms,
      include_live_screen: false,
      named_questions: [],
      named_approvals: []
    }
    const expiresAt = String(this.#ids.nowMs + lifetime)
    const grant: GrantSummary['grant'] = {
      grant_id: idOf('e7e7e7e7', this.#actions),
      parent_grant_id: null,
      issuer_device_id: idOf('e8e8e8e8', 1),
      recipient_device_id: read.recipient_device_id,
      authority_revision: '5',
      environment_selector: { these: { environment_ids: [this.#ids.environment] } },
      session_selector: { these: { session_ids: [read.session_id] } },
      actions,
      history,
      expiry: { at: { expires_at_ms: expiresAt } },
      organisation: null
    }
    this.#grants.push({ grant, state: 'pending', revoked_at_ms: null, revoked_by_parent: null })
    return {
      receipt: null,
      value: {
        grant,
        authority_revision: '5',
        preview: {
          invitation_id: idOf('e9e9e9e9', this.#actions),
          session_id: read.session_id,
          environment_id: this.#ids.environment,
          role: read.selection.role,
          actions,
          history,
          expires_at_ms: expiresAt,
          live_screen: null,
          named_questions: [],
          named_approvals: [],
          notices,
          historical_attachment_keys: false,
          single_use: true
        }
      },
      action_id: null
    }
  }

  grantList(params: unknown): GrantListResult {
    const read = decodeParams<GrantListParams>(params, GRANT_LIST_PARAMS)
    const names = (summary: GrantSummary): boolean => {
      const selector = summary.grant.session_selector
      return (
        read.session_id === null ||
        (typeof selector === 'object' && selector.these.session_ids.includes(read.session_id))
      )
    }
    return {
      grants: this.#grants.filter(
        (summary) =>
          names(summary) &&
          (read.include_resolved || summary.state === 'pending' || summary.state === 'active')
      )
    }
  }

  /* ---- Packages -------------------------------------------------------------------------------- */

  #environmentOf(params: unknown, method: string): void {
    const read = decodeParams<PluginListParams>(params, ENVIRONMENT_PARAMS)
    if (read.environment_id !== this.#ids.environment) {
      refuse('ENVIRONMENT_UNAVAILABLE', `this host does not own that environment (${method})`)
    }
  }

  pluginList(params: unknown): PluginListResult {
    this.#environmentOf(params, 'plugin.list')
    const summary = (
      plugin: string,
      catalogue: string,
      version: string,
      over: Partial<PluginListResult['plugins'][number]> = {}
    ): PluginListResult['plugins'][number] => ({
      plugin_id: plugin,
      catalogue_id: catalogue,
      version,
      package_digest: digestOf(plugin.length),
      environment_id: this.#ids.environment,
      enabled: true,
      pinned: false,
      revoked: false,
      live_bindings: '1',
      admission: { state: 'admitted' },
      ...over
    })
    return {
      plugins: [
        summary('openai.codex', 'official', '1.4.0'),
        summary('community.tmux-status', 'community-mirror', '0.3.1', {
          enabled: false,
          pinned: true,
          live_bindings: '0',
          admission: {
            state: 'left_out',
            reason: 'disabled',
            detail: 'community.tmux-status is disabled here, so no new binding uses it.'
          }
        }),
        summary('vendor.gemini-bridge', 'official', '0.9.0', {
          revoked: true,
          live_bindings: null,
          admission: null
        })
      ],
      live_releases: [
        {
          plugin_id: 'openai.codex',
          catalogue_id: 'official',
          version: '1.3.2',
          package_digest: digestOf(3),
          live_bindings: '1',
          revoked: false,
          ending: true
        }
      ]
    }
  }

  catalogueList(params: unknown): CatalogueListResult {
    this.#environmentOf(params, 'catalogue.list')
    const budgets = {
      metadata_bytes: String(64 * 1024 * 1024),
      metadata_entries: '100000',
      retained_generations: '3',
      retained_metadata_bytes: String(192 * 1024 * 1024),
      payload_cache_bytes: String(1024 * 1024 * 1024),
      full_offline_mirror: false
    }
    const catalogues: CatalogueSummary[] = [
      {
        catalogue_id: 'official',
        kind: 'official',
        metadata_url: 'https://packages.kala.to/metadata',
        targets_url: 'https://packages.kala.to/targets',
        root_digest: digestOf(11),
        generation: '188',
        pinned_generation: null,
        budgets,
        ceiling: ['metadata.match', 'presentation.declarative', 'broker.semantic_events'],
        entries: '1204',
        synced_at_ms: String(this.#ids.nowMs - 3_600_000)
      },
      {
        catalogue_id: 'community-mirror',
        kind: 'mirror',
        metadata_url: 'https://mirror.example.org/metadata',
        targets_url: 'https://mirror.example.org/targets',
        root_digest: digestOf(12),
        generation: '42',
        pinned_generation: '42',
        budgets: { ...budgets, full_offline_mirror: true },
        ceiling: ['metadata.match'],
        entries: '87',
        synced_at_ms: null
      }
    ]
    return { catalogues, enrolment_budgets: budgets }
  }

  /* ---- What a test changes -------------------------------------------------------------------- */

  /**
   * Records one entry a session's agent observed, `omitted` bytes of whose text did not fit what
   * one entry carries.
   */
  appendEntry(sessionId: string, kind: string, text: string, omitted = 0): void {
    this.#observe(this.#agentOf(sessionId), kind, text, omitted)
  }

  /**
   * Ends a session's agent and starts another in its place, as quitting and launching it again
   * does. The ended one's history goes with it. Answers the new instance's identity.
   */
  restartAgent(sessionId: string): string {
    this.#restarts += 1
    const instance = idOf('a1a1a1a1', 100 + this.#restarts)
    this.#agents.set(
      sessionId,
      this.#agent(instance, [['thread.started', 'Codex started a new conversation.']], false)
    )
    return instance
  }

  /** Starts a session that runs a shell and nothing else, as a creation does. */
  startShell(sessionId: string): void {
    this.#shells.add(sessionId)
  }

  /** Records output a session wrote, after what it wrote before. */
  appendOutput(sessionId: string, text: string): void {
    const held = this.#output.get(sessionId) ?? { oldest: 0n, bytes: new Uint8Array() }
    const added = new TextEncoder().encode(text)
    const next = new Uint8Array(held.bytes.length + added.length)
    next.set(held.bytes)
    next.set(added, held.bytes.length)
    this.#output.set(sessionId, { oldest: held.oldest, bytes: next })
  }

  /**
   * Lets a session's output before `cursor` go, as a host's retention does: a read from before it
   * is answered from where the output now begins, with what went and why.
   */
  forgetOutput(sessionId: string, cursor: bigint): void {
    const held = this.#output.get(sessionId)
    if (held === undefined || cursor <= held.oldest) return
    const end = held.oldest + BigInt(held.bytes.length)
    const kept = cursor > end ? end : cursor
    this.#output.set(sessionId, { oldest: kept, bytes: held.bytes.slice(Number(kept - held.oldest)) })
  }

  /** Where a session's output ends now. */
  outputEnd(sessionId: string): bigint {
    const held = this.#output.get(sessionId)
    return held === undefined ? 0n : held.oldest + BigInt(held.bytes.length)
  }

  /** Lets the oldest `count` of a session's entries go, as a host's retention does. */
  forget(sessionId: string, count: number): void {
    const agent = this.#agentOf(sessionId)
    const gone = agent.entries.splice(0, count)
    const last = gone.at(-1)
    if (last !== undefined) agent.forgotten = Number(last.node)
  }

  /** Puts one capability of a session's live agent into a state. */
  setCapability(
    sessionId: string,
    capability: string,
    state: InstanceCapabilityRecord['state'],
    reason: string | null = null
  ): void {
    const agent = this.#agents.get(sessionId)
    const instance = agent?.instances[0]?.application_instance_id
    if (agent === undefined || instance === undefined) return
    agent.capabilities.set(capability, this.#record(instance, capability, state, reason))
  }

  /** Suspends a session's rich mutations for `reason`, or lifts the suspension with null. */
  suspend(sessionId: string, reason: string | null): void {
    const agent = this.#agentOf(sessionId)
    agent.binding = {
      ...agent.binding,
      rich_mutations_suspended: reason !== null,
      suspension_reason: reason
    }
  }

  /**
   * Moves a session's binding to a new revision, as a change of conversation does, which ends the
   * turn that was running.
   */
  moveBinding(sessionId: string): void {
    const agent = this.#agentOf(sessionId)
    agent.binding = {
      ...agent.binding,
      binding_revision: String(Number(agent.binding.binding_revision) + 1),
      turn_id: null
    }
  }

  /** Ends the running turn of a session's agent. */
  endTurn(sessionId: string): void {
    const agent = this.#agentOf(sessionId)
    agent.binding = { ...agent.binding, turn_id: null }
  }

  /** Makes this device's history filter withhold the oldest `count` of a session's entries. */
  withhold(sessionId: string, count: number): void {
    this.#agentOf(sessionId).withheld = count
  }

  /**
   * Makes this device's history filter withhold one entry wherever it is, as a filter that reads
   * each entry's own time does when an entry was observed out of order.
   */
  withholdEntry(sessionId: string, node: number): void {
    this.#agentOf(sessionId).withheldNodes.add(String(node))
  }

  /** Raises `count` notices an application printed in a session, the newest last. */
  raiseNotices(sessionId: string, count: number): void {
    const { nowMs } = this.#ids
    for (let index = 0; index < count; index += 1) {
      this.#revision += 1
      this.#attention.push({
        key: `attention.application_notice|~${String(index).padStart(32, '0')}`,
        rule: 'attention.application_notice',
        source: 'host_events',
        level: 'informational',
        session_id: sessionId,
        summary: `Notice ${index + 1}`,
        trusted: false,
        routing: 'lease_holder',
        occurrences: '1',
        first_seen_ms: String(nowMs - 60_000 + index),
        last_seen_ms: String(nowMs - 60_000 + index),
        notification: 'delivered',
        awaiting_delivery: false,
        acknowledged: false,
        uncertain: false,
        revision: String(this.#revision),
        automation: null
      })
    }
  }

  /** The first item `rule` raised, as the host holds it now. */
  attentionItem(rule: AttentionItem['rule']): AttentionItem {
    const item = this.#attention.find((each) => each.rule === rule)
    if (item === undefined) throw new Error(`the host holds no item raised by ${rule}`)
    return item
  }

  /** The capability records and resources a test reads back. */
  agentOf(sessionId: string): {
    readonly binding: AgentBindingState
    readonly resources: readonly PendingResource[]
    readonly entries: readonly AgentSnapshotEntry[]
  } {
    const agent = this.#agentOf(sessionId)
    return { binding: agent.binding, resources: agent.resources, entries: agent.entries }
  }
}
