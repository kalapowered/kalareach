/**
 * The agent model's rules, and the control state built from what the agent's worker said.
 *
 * A composer offers an action only where the capability the host checks is usable now, the device
 * holds the right, and the binding is verified; a fact nobody has told the device is not guessed.
 * A declarative control is shown when its condition holds and hidden only while a fact it turns on
 * is unknown.
 */

import { describe, expect, it } from 'vitest'

import type {
  AgentBindingState,
  AgentInstanceSummary,
  AgentSnapshotResult,
  InstanceCapabilityRecord,
  PendingResource
} from '@kalareach/protocol'

import {
  actionableApprovals,
  agentEntry,
  bindingStateOf,
  COMPOSER_CAPABILITIES,
  composerOffers,
  foldWithheld,
  liveInstance,
  targetOf,
  withheldTotal
} from '../src/model/agent'
import { controlStateOf, evaluate, visibilityOf, type Control } from '../src/model/controls'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

function instance(id: string, startedAt: string, endedAt: string | null = null): AgentInstanceSummary {
  return {
    application_instance_id: id,
    plugin_id: 'openai.codex',
    profile_id: null,
    mode: 'native_bridge',
    bypass: null,
    started_at: startedAt,
    ended_at: endedAt,
    refusal: null
  }
}

function binding(over: Partial<AgentBindingState> = {}): AgentBindingState {
  return {
    binding_revision: '4',
    thread_id: 'thread-7',
    turn_id: 'turn-9',
    profile_id: null,
    mode: 'native_bridge',
    rich_mutations_suspended: false,
    suspension_reason: null,
    ...over
  }
}

function record(
  capability: string,
  state: InstanceCapabilityRecord['state'] = 'qualified_available',
  reason: string | null = null
): InstanceCapabilityRecord {
  return {
    capability_id: capability,
    capability_version: '1',
    application_instance_id: 'i-1',
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
    revision: '1',
    state,
    source: 'live_binding',
    invalidated_by: [],
    disabled_reason: reason,
    observed_at: '0'
  }
}

/** Every composer capability usable now, and any the test names in another state. */
function capabilities(
  over: Readonly<Record<string, InstanceCapabilityRecord>> = {}
): ReadonlyMap<string, InstanceCapabilityRecord> {
  const records = new Map<string, InstanceCapabilityRecord>()
  for (const capability of Object.values(COMPOSER_CAPABILITIES)) {
    records.set(capability, record(capability))
  }
  for (const [capability, each] of Object.entries(over)) records.set(capability, each)
  return records
}

const EVERY_RIGHT = new Set([
  'agent.prompt',
  'agent.cancel',
  'agent.approval.respond',
  'files.upload'
])

function part(over: Partial<AgentSnapshotResult>): AgentSnapshotResult {
  return {
    binding: binding(),
    entries: [],
    continuation: null,
    history_gap: false,
    withheld_entries: '0',
    ...over
  }
}

describe('the live instance (KR-REQ-11.03)', () => {
  it('is the one started last of those that have not ended', () => {
    const chosen = liveInstance([
      instance('a', '100'),
      instance('b', '300', '400'),
      instance('c', '200')
    ])
    expect(chosen?.application_instance_id).toBe('c')
  })

  it('compares start times as counters', () => {
    const chosen = liveInstance([
      instance('a', '9007199254740993'),
      instance('b', '9007199254740992')
    ])
    expect(chosen?.application_instance_id).toBe('a')
  })

  it('is none when every instance has ended', () => {
    expect(liveInstance([instance('a', '1', '2')])).toBeNull()
    expect(liveInstance([])).toBeNull()
  })

  it('is named with the binding revision the person saw in every mutation', () => {
    expect(targetOf(SESSION, 'i-1', binding({ binding_revision: '12' }))).toEqual({
      subject: { session_id: SESSION, application_instance_id: 'i-1' },
      binding_revision: '12'
    })
  })
})

describe('what the composer offers (KR-REQ-13.12, 11.03)', () => {
  it('offers every action when the capability, the right and the binding allow it', () => {
    const offers = composerOffers({
      binding: binding(),
      capabilities: capabilities(),
      rights: EVERY_RIGHT
    })
    for (const offer of Object.values(offers)) expect(offer).toEqual({ offered: true, reason: null })
  })

  it('offers nothing before the capability records are read', () => {
    const offers = composerOffers({ binding: binding(), capabilities: null, rights: EVERY_RIGHT })
    for (const offer of Object.values(offers)) expect(offer.offered).toBe(false)
  })

  it('offers nothing while no agent is running', () => {
    const offers = composerOffers({ binding: null, capabilities: capabilities(), rights: null })
    expect(offers.submit.reason).toBe('No agent is running in this session.')
  })

  it('offers nothing while the binding is unverified, in the host’s words where it gave any', () => {
    const suspended = composerOffers({
      binding: binding({
        rich_mutations_suspended: true,
        suspension_reason: 'The conversation changed outside this host.'
      }),
      capabilities: capabilities(),
      rights: EVERY_RIGHT
    })
    expect(suspended.submit).toEqual({
      offered: false,
      reason: 'The conversation changed outside this host.'
    })
    const silent = composerOffers({
      binding: binding({ rich_mutations_suspended: true }),
      capabilities: capabilities(),
      rights: EVERY_RIGHT
    })
    expect(silent.queue.reason).toContain('The terminal still works.')
  })

  it('offers steering and interrupting only while a turn is running', () => {
    const idle = composerOffers({
      binding: binding({ turn_id: null }),
      capabilities: capabilities(),
      rights: EVERY_RIGHT
    })
    expect(idle.submit.offered).toBe(true)
    expect(idle.steer).toEqual({ offered: false, reason: 'The agent is not running a turn.' })
    expect(idle.interrupt.offered).toBe(false)
  })

  it('offers queueing and steering only where the upstream does, in its own words', () => {
    const offers = composerOffers({
      binding: binding(),
      capabilities: capabilities({
        'agent.prompt.queue': record('agent.prompt.queue', 'incompatible', 'This upstream has no queue.')
      }),
      rights: EVERY_RIGHT
    })
    expect(offers.queue).toEqual({ offered: false, reason: 'This upstream has no queue.' })
    expect(offers.steer.offered).toBe(true)
  })

  it('offers nothing this device was not granted, and decides nothing on rights it was not told', () => {
    const viewer = composerOffers({
      binding: binding(),
      capabilities: capabilities(),
      rights: new Set(['session.view'])
    })
    expect(viewer.submit).toEqual({ offered: false, reason: 'This device was not granted this.' })
    expect(viewer.attach.offered).toBe(false)
    const untold = composerOffers({ binding: binding(), capabilities: capabilities(), rights: null })
    expect(untold.submit.offered).toBe(true)
  })
})

describe('the requests a person can answer (KR-REQ-11.26)', () => {
  function resource(over: Partial<PendingResource>): PendingResource {
    return {
      resource_id: 'r-1',
      application_instance_id: 'i-1',
      request: { connection: '1', upstream: '"req-1"' },
      kind: 'approval',
      method: 'execCommandApproval',
      classification: { class: 'mutation', declared: true },
      source_generation: '1',
      state: 'pending',
      durability: 'durable',
      deadline_ms: null,
      recorded_at: '0',
      interpretation_verified: true,
      ...over
    }
  }

  it('are the pending approvals a granted decoder verified', () => {
    const answerable = actionableApprovals([
      resource({ resource_id: 'verified' }),
      resource({ resource_id: 'opaque', interpretation_verified: false }),
      resource({ resource_id: 'resolved', state: 'resolved' }),
      resource({ resource_id: 'call', kind: 'reverse_rpc' }),
      resource({ resource_id: 'other', application_instance_id: 'i-2' })
    ])
    expect(answerable.map((each) => each.resource_id)).toEqual(['verified', 'other'])
    expect(
      actionableApprovals([resource({}), resource({ application_instance_id: 'i-2' })], 'i-2')
    ).toHaveLength(1)
  })

  it('make the binding one that waits on a person, and an unverified binding is unknown', () => {
    expect(bindingStateOf(binding(), true)).toBe('awaiting_person')
    expect(bindingStateOf(binding(), false)).toBe('upstream_busy')
    expect(bindingStateOf(binding({ turn_id: null }), false)).toBe('bound')
    expect(bindingStateOf(binding({ rich_mutations_suspended: true }), true)).toBeNull()
    expect(bindingStateOf(null, false)).toBeNull()
  })
})

describe('an entry of the history (KR-REQ-13.15)', () => {
  it('keeps its identity across reads, and a copy carrying more text is the newer', () => {
    const cut = agentEntry('i-1', {
      node: '7',
      kind: 'message',
      text: 'The start',
      omitted_text_bytes: '10',
      observed_at: '0'
    })
    const whole = agentEntry('i-1', {
      node: '7',
      kind: 'message',
      text: 'The start and the rest',
      omitted_text_bytes: '0',
      observed_at: '0'
    })
    expect(cut.id).toBe(whole.id)
    expect(BigInt(whole.revision)).toBeGreaterThan(BigInt(cut.revision))
    // Bytes, not characters: a non-ASCII character is more than one.
    expect(
      agentEntry('i-1', { node: '1', kind: 'message', text: 'é', omitted_text_bytes: '0', observed_at: '0' })
        .revision
    ).toBe('2')
  })
})

describe('what the host withheld, counted once (KR-REQ-25.25)', () => {
  it('replaces the count of a range read again, and keeps a closed range', () => {
    // The first read covers everything from the start and withholds two.
    let count = foldWithheld(undefined, null, [part({ withheld_entries: '2' })])
    expect(withheldTotal(new Map([['i-1', count]]))).toBe(2)
    // Nothing new was shown, so the next read starts at the same place and says the same.
    count = foldWithheld(count, null, [part({ withheld_entries: '2' })])
    expect(withheldTotal(new Map([['i-1', count]]))).toBe(2)
    // A shown entry moved the start on: what was withheld before it stays counted.
    count = foldWithheld(count, '6', [part({ withheld_entries: '0' })])
    expect(withheldTotal(new Map([['i-1', count]]))).toBe(2)
  })

  it('adds a part that stopped at a limit, whose range no later read covers', () => {
    const count = foldWithheld(undefined, null, [
      part({
        withheld_entries: '3',
        continuation: { limit: 'nodes', limit_value: '40', from_node: '44', nodes: '40', bytes: '0' }
      }),
      part({ withheld_entries: '1' })
    ])
    expect(count).toEqual({ settled: 3, tail: { from: '44', count: 1 } })
    expect(withheldTotal(new Map([['i-1', count], ['i-2', { settled: 2, tail: null }]]))).toBe(6)
  })
})

describe('the control state, from what the worker said (KR-REQ-11.48)', () => {
  const facts = {
    capabilities: capabilities({ 'agent.steer': record('agent.steer', 'incompatible') }),
    rights: ['agent.prompt'],
    bindingState: 'upstream_busy',
    waitingOnPerson: true,
    presentNodes: new Set(['n-1']),
    compact: false
  }

  it('answers each fact it was told, and only those', () => {
    const state = controlStateOf(facts)
    expect(evaluate({ op: 'capability', capability: 'agent.prompt', state: 'qualified_available' }, state)).toBe('true')
    expect(evaluate({ op: 'capability', capability: 'agent.steer', state: 'qualified_available' }, state)).toBe('false')
    expect(evaluate({ op: 'capability', capability: 'files.read', state: 'qualified_available' }, state)).toBe('unknown')
    expect(evaluate({ op: 'grant', right: 'agent.prompt' }, state)).toBe('true')
    expect(evaluate({ op: 'grant', right: 'agent.cancel' }, state)).toBe('false')
    expect(evaluate({ op: 'binding', state: 'upstream_busy' }, state)).toBe('true')
    expect(evaluate({ op: 'flag', flag: 'pending_approval' }, state)).toBe('true')
    expect(evaluate({ op: 'flag', flag: 'draft_not_empty' }, state)).toBe('unknown')
    expect(evaluate({ op: 'flag', flag: 'compact_layout' }, state)).toBe('false')
    expect(evaluate({ op: 'flag', flag: 'holds_input_lease' }, state)).toBe('unknown')
    expect(evaluate({ op: 'node_present', node_id: 'n-1' }, state)).toBe('true')
  })

  it('leaves unknown what nobody has said', () => {
    const state = controlStateOf({
      ...facts,
      capabilities: null,
      rights: null,
      bindingState: null,
      waitingOnPerson: null
    })
    expect(evaluate({ op: 'grant', right: 'agent.prompt' }, state)).toBe('unknown')
    expect(evaluate({ op: 'binding', state: 'bound' }, state)).toBe('unknown')
    expect(evaluate({ op: 'flag', flag: 'pending_approval' }, state)).toBe('unknown')
    expect(
      evaluate({ op: 'capability', capability: 'agent.prompt', state: 'qualified_available' }, state)
    ).toBe('unknown')
  })

  it('shows a conditional control once its condition holds, and hides it while it is unknown', () => {
    const control: Control = {
      id: 'c-1',
      revision: '1',
      label: 'Stop the turn',
      accessible_description: 'Stops the turn the agent is running.',
      action_id: 'stop',
      visible_when: {
        op: 'all',
        terms: [
          { op: 'binding', state: 'upstream_busy' },
          { op: 'grant', right: 'agent.prompt' }
        ]
      }
    }
    expect(visibilityOf(control, controlStateOf(facts)).kind).toBe('shown')
    expect(
      visibilityOf(control, controlStateOf({ ...facts, bindingState: null, rights: null }))
    ).toEqual({ kind: 'hidden', because: 'this client does not know whether its condition is met' })
  })
})
