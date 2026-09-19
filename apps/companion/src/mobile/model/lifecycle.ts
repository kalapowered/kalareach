/**
 * Coming back: after a suspension, after the system reclaimed the process, after the network
 * changed under it, and after a cold start.
 *
 * KR-ACC-012 asks for all four to recover without a lost draft and without a false claim that an
 * action succeeded. Those are two different duties and this module keeps them apart.
 *
 * The draft is durable and the association is not. A draft is this device's own record with its
 * own identity and revision; the attachment that presents it in an editor is a binding that the
 * connection owns. Losing the connection removes the binding and leaves the draft exactly as it
 * was. Coming back offers a rebind, and only the same authorised device against an unchanged
 * target gets one: a changed application or binding revision is a conflict the person resolves,
 * and a session that has gone orphans the draft. Nothing here submits anything.
 *
 * An action is the other way round. The connection coming back is not an outcome. A submission
 * that was in flight when contact was lost is unresolved until a receipt says otherwise, and the
 * one thing this must never do is treat reconnection, or a network acknowledgement, as success.
 */

import { connectionLost, rebind, type Draft, type DraftTarget } from '../../model/drafts'
import { unresolved, type Submission } from '../../model/receipts'
import { DRAFTS_KEY, SUBMISSIONS_KEY, readRecord, writeRecord, type DurableStore } from './store'

/** What put the application back in front of the person. */
export type Resumption =
  /** The process stayed alive; the operating system suspended and resumed it. */
  | 'suspended'
  /** The system reclaimed the process in the background and started it again. */
  | 'terminated'
  /** Wi-Fi became cellular, or the other way round: a new transport, the same process. */
  | 'network_changed'
  /** The person started the application from nothing. */
  | 'cold_start'

/** What the interface says about each. */
export function describeResumption(resumption: Resumption): string {
  switch (resumption) {
    case 'suspended':
      return 'Resumed'
    case 'terminated':
      return 'Started again after the system closed it'
    case 'network_changed':
      return 'The network changed'
    case 'cold_start':
      return 'Started'
  }
}

/** Everything that has to survive a restart. */
export interface DurableState {
  readonly drafts: readonly Draft[]
  readonly submissions: readonly Submission[]
}

/** Nothing kept. */
export const EMPTY_DURABLE_STATE: DurableState = { drafts: [], submissions: [] }

/** Writes the state a restart must find. Only what is unresolved is worth keeping. */
export function persist(store: DurableStore, state: DurableState): void {
  writeRecord(store, DRAFTS_KEY, state.drafts)
  writeRecord(store, SUBMISSIONS_KEY, unresolved(state.submissions))
}

/**
 * Reads what the last run left, and puts it in the state a fresh process is actually in.
 *
 * Nothing is connected yet, so every draft is detached and every submission that was in flight is
 * of unknown outcome. Both are recoveries, not failures, and neither is a claim.
 */
export function restore(store: DurableStore): DurableState {
  const drafts = readRecord<Draft[]>(store, DRAFTS_KEY) ?? []
  const submissions = readRecord<Submission[]>(store, SUBMISSIONS_KEY) ?? []
  return {
    drafts: drafts.map(connectionLost),
    submissions: submissions.map((submission) =>
      submission.state === 'queued' ? submission : { ...submission, state: 'unknown' as const }
    )
  }
}

/**
 * What a resumption does to the state in memory.
 *
 * A suspension and a network change keep the process, so the drafts are already here; what they
 * lose is the connection, and with it every attachment binding. A cold start and a termination
 * have nothing in memory, so they read what was written.
 */
export function onResume(
  resumption: Resumption,
  current: DurableState,
  store: DurableStore
): DurableState {
  if (resumption === 'cold_start' || resumption === 'terminated') return restore(store)
  return {
    drafts: current.drafts.map(connectionLost),
    submissions: current.submissions
  }
}

/** What the host reported about one draft's target when contact came back. */
export interface ObservedTarget {
  readonly draftId: string
  /** The target as it stands now, or null when the session has gone. */
  readonly target: DraftTarget | null
  /** The attachment that would present the draft again. */
  readonly attachmentId: string
}

/**
 * Offers each draft its rebind.
 *
 * This is where the specification's three outcomes are decided, and all three are decided by
 * comparing what the draft was written for with what the host now reports. None of them submits,
 * and none of them edits the text.
 */
export function rebindAll(
  drafts: readonly Draft[],
  observed: readonly ObservedTarget[]
): readonly Draft[] {
  const byId = new Map(observed.map((each) => [each.draftId, each]))
  return drafts.map((draft) => {
    const match = byId.get(draft.draftId)
    if (!match) return draft
    return rebind(draft, match.target, match.attachmentId)
  })
}

/** What a recovery left behind, which is what the banner reports. */
export interface RecoverySummary {
  /** Drafts that came through the break and are waiting to be bound to an editor again. */
  readonly kept: number
  readonly conflicted: number
  readonly orphaned: number
  readonly unresolvedActions: number
}

/**
 * Summarises what is still a consequence of a break.
 *
 * A draft that is bound is not a consequence of anything: it is a draft. Only the ones still
 * detached, conflicted or orphaned, and the actions with no confirmed outcome, are things the
 * person has not yet been told about, so those are the only things counted. A run in which
 * nothing broke therefore summarises to nothing and shows no banner.
 */
export function summarise(state: DurableState): RecoverySummary {
  return {
    kept: state.drafts.filter((draft) => draft.state === 'detached').length,
    conflicted: state.drafts.filter((draft) => draft.state === 'conflicted').length,
    orphaned: state.drafts.filter((draft) => draft.state === 'orphaned').length,
    unresolvedActions: unresolved(state.submissions).length
  }
}

/** What the recovery banner says, or null when there is nothing to say. */
export interface RecoveryBanner {
  readonly tone: 'accent' | 'warning'
  readonly title: string
  readonly detail: string
}

/**
 * The sentence shown after a recovery.
 *
 * It reports drafts and actions separately because they mean different things: a recovered draft
 * is a fact about this device, and an unresolved action is a question about a host. It never
 * reports an action as done.
 */
export function recoveryBanner(
  resumption: Resumption,
  summary: RecoverySummary
): RecoveryBanner | null {
  const parts: string[] = []
  if (summary.kept > 0) {
    parts.push(`${summary.kept} draft${summary.kept === 1 ? '' : 's'} kept`)
  }
  if (summary.conflicted > 0) {
    parts.push(
      `${summary.conflicted} need${summary.conflicted === 1 ? 's' : ''} a new destination`
    )
  }
  if (summary.orphaned > 0) {
    parts.push(`${summary.orphaned} lost ${summary.orphaned === 1 ? 'its' : 'their'} session`)
  }
  if (summary.unresolvedActions > 0) {
    parts.push(
      `${summary.unresolvedActions} action${summary.unresolvedActions === 1 ? '' : 's'} with no confirmed outcome`
    )
  }
  if (parts.length === 0) return null
  const needsAttention = summary.conflicted > 0 || summary.orphaned > 0
  return {
    tone: needsAttention || summary.unresolvedActions > 0 ? 'warning' : 'accent',
    title: describeResumption(resumption),
    detail: `${parts.join(', ')}. Nothing was sent again.`
  }
}
