/**
 * A session's agent, as its worker describes it: which instance is live, what it can do now, and
 * what is waiting on a person.
 *
 * Section 12 binds everything to the exact instance, never to "the agent": a read names the
 * instance, and a mutation names the instance and the binding revision it was prepared against, so
 * an answer about a conversation that has since moved is refused rather than applied to the new
 * one. Section 23 gives each action its own capability, and a composer offers an action only where
 * the capability the host checks for it is usable now: an action the host would refuse is not one
 * to put under a person's finger.
 */

import type {
  AgentBindingState,
  AgentInstanceSummary,
  AgentMutationTarget,
  AgentSnapshotEntry,
  AgentSnapshotResult,
  AgentSubject,
  InstanceCapabilityRecord,
  PendingResource
} from '@kalareach/protocol'

/** One entry of an instance's semantic history, as the conversation holds it. */
export interface AgentEntry {
  /** Stable across every read: the instance and the entry's own number in its history. */
  readonly id: string
  /**
   * How much of the entry's text this copy carries. A copy carrying more replaces one carrying
   * less, and an identical copy changes nothing.
   */
  readonly revision: string
  readonly instance: string
  readonly entry: AgentSnapshotEntry
}

/**
 * The instance a session's composer speaks to: of the instances that have not ended, the one
 * started last. A session with none has no agent to speak to.
 */
export function liveInstance(
  instances: readonly AgentInstanceSummary[]
): AgentInstanceSummary | null {
  let newest: AgentInstanceSummary | null = null
  for (const instance of instances) {
    if (instance.ended_at !== null) continue
    if (newest === null || BigInt(instance.started_at) >= BigInt(newest.started_at)) {
      newest = instance
    }
  }
  return newest
}

/** What every agent call about `instance` names. */
export function subjectOf(sessionId: string, instance: string): AgentSubject {
  return { session_id: sessionId, application_instance_id: instance }
}

/** What an agent mutation acts on: the instance at the binding revision the person saw. */
export function targetOf(
  sessionId: string,
  instance: string,
  binding: AgentBindingState
): AgentMutationTarget {
  return { subject: subjectOf(sessionId, instance), binding_revision: binding.binding_revision }
}

/** One entry of `instance`'s history, as the conversation holds it. */
export function agentEntry(instance: string, entry: AgentSnapshotEntry): AgentEntry {
  return {
    id: `${instance}:${entry.node}`,
    revision: String(new TextEncoder().encode(entry.text).length),
    instance,
    entry
  }
}

/** How many of one instance's entries this device's history filter withheld, as its reads said. */
export interface WithheldCount {
  /** Withheld in ranges already counted apart, which no later read covers again. */
  readonly settled: number
  /** The newest read of the history's open end: where it started, and how many it withheld. */
  readonly tail: { readonly from: string | null; readonly count: number } | null
}

/**
 * Folds one read's parts, the first of which started at `from`, into an instance's count.
 *
 * Each part counts what it withheld in the range it covered. A part that stopped at a limit covers
 * a closed range, which ends where the next part begins. A part that did not covers everything from
 * where it started, so its count includes whatever later parts count too: what it withheld on its
 * own is its count less theirs. That is why a read that found entries reads on from after the last
 * one, and why the next read, which starts at the same place as the last part or later, takes the
 * last part's count over. Whatever order the filter withholds entries in, nothing is counted twice.
 * An entry withheld after a read counted the range it falls in can be left out, so the total is a
 * lower bound, and a view says "at least".
 */
export function foldWithheld(
  count: WithheldCount | undefined,
  from: string | null,
  parts: readonly AgentSnapshotResult[]
): WithheldCount {
  if (parts.length === 0) return count ?? { settled: 0, tail: null }
  // The ranges read, in order: the previous open-ended read when this one starts later than it
  // did, then this read's parts. A previous read that started where this one does is read again.
  const previous = count?.tail ?? null
  const ranges: { readonly withheld: number; readonly closed: boolean }[] = []
  if (previous !== null && previous.from !== from) {
    ranges.push({ withheld: previous.count, closed: false })
  }
  let start = from
  let lastStart = from
  for (const part of parts) {
    lastStart = start
    ranges.push({ withheld: Number(part.withheld_entries), closed: part.continuation !== null })
    const last = part.entries.at(-1)
    start =
      part.continuation?.from_node ?? (last === undefined ? start : String(BigInt(last.node) + 1n))
  }
  // From the last range back: a closed range's count is its own, and an open one's is its count
  // less everything after it.
  const own = new Array<number>(ranges.length).fill(0)
  let after = 0
  for (let index = ranges.length - 1; index >= 0; index -= 1) {
    const range = ranges[index]
    if (range === undefined) continue
    own[index] = range.closed ? range.withheld : Math.max(0, range.withheld - after)
    after += own[index] ?? 0
  }
  const openEnded = parts.at(-1)?.continuation === null
  const settledNow = own.slice(0, openEnded ? -1 : undefined).reduce((total, each) => total + each, 0)
  return {
    settled: (count?.settled ?? 0) + settledNow,
    tail: openEnded ? { from: lastStart, count: own.at(-1) ?? 0 } : null
  }
}

/** How many entries of every instance read so far the host withheld from this device. */
export function withheldTotal(counts: ReadonlyMap<string, WithheldCount>): number {
  let total = 0
  for (const count of counts.values()) total += count.settled + (count.tail?.count ?? 0)
  return total
}

/** The capability each record is about, and the record. */
export function capabilityRecords(
  records: readonly InstanceCapabilityRecord[]
): ReadonlyMap<string, InstanceCapabilityRecord> {
  return new Map(records.map((record) => [record.capability_id, record]))
}

/**
 * The capability the host checks for each composer action, as section 23's registry and the
 * broker's admission name them.
 */
export const COMPOSER_CAPABILITIES = {
  submit: 'agent.prompt',
  queue: 'agent.prompt.queue',
  steer: 'agent.steer',
  interrupt: 'agent.cancel',
  attach: 'agent.attachment',
  answer: 'agent.approval'
} as const

/** The right each composer action needs, as section 23 maps methods to rights. */
const COMPOSER_RIGHTS: Readonly<Record<keyof typeof COMPOSER_CAPABILITIES, readonly string[]>> = {
  submit: ['agent.prompt'],
  queue: ['agent.prompt'],
  steer: ['agent.prompt'],
  interrupt: ['agent.cancel'],
  attach: ['files.upload', 'agent.prompt'],
  answer: ['agent.approval.respond']
}

/** Whether one action is offered now, and why not when it is not. */
export interface Offer {
  readonly offered: boolean
  /** Why not, in the host's words where it gave any. Null when the action is offered. */
  readonly reason: string | null
}

/** What the composer offers for the live instance. */
export type ComposerOffers = Readonly<Record<keyof typeof COMPOSER_CAPABILITIES, Offer>>

/** What decides the offers. */
export interface ComposerFacts {
  /** Whether the session's agent has been read at all. */
  readonly known: boolean
  /** The binding in force, or null before one has been read or when no agent is live. */
  readonly binding: AgentBindingState | null
  /** The instance's capability records, or null before they have been read. */
  readonly capabilities: ReadonlyMap<string, InstanceCapabilityRecord> | null
  /** The rights this device holds, or null while it has not been told. */
  readonly rights: ReadonlySet<string> | null
}

const OFFERED: Offer = { offered: true, reason: null }

/**
 * What the composer offers, action by action.
 *
 * An action is offered only when its capability is usable now, this device holds the right it
 * needs, and the binding is one the host has verified. Steering and interrupting also need a turn
 * to be running, since each names that turn. A fact nobody has told this device is not a fact it
 * guesses: until the capability records are read and the connection has said what it may do,
 * nothing is offered.
 */
export function composerOffers({
  known,
  binding,
  capabilities,
  rights
}: ComposerFacts): ComposerOffers {
  const offer = (action: keyof typeof COMPOSER_CAPABILITIES): Offer => {
    if (!known) return { offered: false, reason: 'Reading this session’s agent…' }
    if (binding === null) return { offered: false, reason: 'No agent is running in this session.' }
    if (binding.rich_mutations_suspended) {
      return {
        offered: false,
        reason:
          binding.suspension_reason ??
          'The host could not confirm which conversation this agent is in, so nothing is sent to it from here. The terminal still works.'
      }
    }
    if ((action === 'steer' || action === 'interrupt') && binding.turn_id === null) {
      return { offered: false, reason: 'The agent is not running a turn.' }
    }
    const record = capabilities?.get(COMPOSER_CAPABILITIES[action])
    if (record === undefined) {
      return { offered: false, reason: 'This agent has not said it can do this.' }
    }
    if (record.state !== 'qualified_available') {
      return {
        offered: false,
        reason: record.disabled_reason ?? 'This agent cannot do this right now.'
      }
    }
    if (rights === null) {
      return { offered: false, reason: 'This device does not know yet what it may do here.' }
    }
    if (COMPOSER_RIGHTS[action].some((right) => !rights.has(right))) {
      return { offered: false, reason: 'This device was not granted this.' }
    }
    return OFFERED
  }
  return {
    submit: offer('submit'),
    queue: offer('queue'),
    steer: offer('steer'),
    interrupt: offer('interrupt'),
    attach: offer('attach'),
    answer: offer('answer')
  }
}

/**
 * The requests a person can answer now: approvals whose interpretation a granted decoder verified
 * and that are still pending. Section 11: an opaque request is not an actionable approval until
 * then.
 */
export function actionableApprovals(
  resources: readonly PendingResource[],
  instance: string | null = null
): readonly PendingResource[] {
  return resources.filter(
    (resource) =>
      resource.kind === 'approval' &&
      resource.interpretation_verified &&
      resource.state === 'pending' &&
      (instance === null || resource.application_instance_id === instance)
  )
}

/**
 * The binding's state, as a control's visibility predicate names it, or null while it is not known.
 *
 * A binding whose rich mutations are suspended is one the host could not verify, so its state is
 * unknown here rather than any of the named ones: a control that turns on it stays hidden.
 */
export function bindingStateOf(
  binding: AgentBindingState | null,
  waitingOnPerson: boolean
): 'bound' | 'upstream_busy' | 'awaiting_person' | null {
  if (binding === null || binding.rich_mutations_suspended) return null
  if (waitingOnPerson) return 'awaiting_person'
  if (binding.turn_id !== null) return 'upstream_busy'
  return 'bound'
}
