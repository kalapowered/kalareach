/**
 * What the host last said, in a read, of the actions this window sent, and the quote a later prompt
 * makes of it.
 *
 * A prompt whose outcome nobody could establish is an uncertain outcome. The host refuses a fresh
 * action for the same conversation unless it is an explicit later request that names the earlier
 * action and the revision of its record that the person was shown, so that a client cannot quietly
 * replace an uncertain result with a new identifier. The page shows an action's state from what the
 * host said of it, so the revision it can quote is the one in the newest read it made. This holds
 * those reads for the window. They are kept in memory only: a quote is made from what was shown in
 * this window, and a window that has just started has shown nothing.
 */

import type { Receipt } from '@kalareach/protocol'

import type { Submission } from './receipts'

/** The method whose uncertain outcome a later prompt supersedes. */
export const PROMPT_METHOD = 'agent.prompt.submit'

/** What one read of an action's record said. */
export interface ReceiptRead {
  /** The method the action was made with. */
  readonly method: string
  /** The state the record stood in. */
  readonly state: Receipt['state']
  /** The revision of the record, which is what a later request quotes. */
  readonly revision: string
  /** When that revision was written, which orders two uncertain actions of one conversation. */
  readonly updatedAtMs: string
}

/** The earlier action a later prompt names, and the revision of its record the person was shown. */
export interface Supersession {
  readonly action_id: string
  readonly revision: string
}

/** The conversation a prompt is for. */
export interface Conversation {
  readonly applicationInstanceId: string | null
  readonly agentBindingRevision: string | null
}

/** Compares two numbers a host writes as decimal text without losing precision. */
function later(a: string, b: string): boolean {
  try {
    return BigInt(a) > BigInt(b)
  } catch {
    return false
  }
}

/** The reads this window made, by action, and the screens waiting to read again. */
export class ReceiptReads {
  readonly #reads = new Map<string, ReceiptRead>()
  readonly #again = new Map<string, Set<() => void>>()

  /** Keeps what a read of an action's record said, unless a newer revision has been read. */
  note = (receipt: Receipt): void => {
    const held = this.#reads.get(receipt.action_id)
    if (held !== undefined && later(held.revision, receipt.revision)) return
    this.#reads.set(receipt.action_id, {
      method: receipt.method,
      state: receipt.state,
      revision: receipt.revision,
      updatedAtMs: receipt.updated_at_ms
    })
  }

  /** What the newest read of an action's record said, when there has been one. */
  read = (actionId: string): ReceiptRead | undefined => this.#reads.get(actionId)

  /** Has `read` called when a session's actions should be read again; the result stops it. */
  whenAskedAgain = (sessionId: string, read: () => void): (() => void) => {
    const waiting = this.#again.get(sessionId) ?? new Set<() => void>()
    waiting.add(read)
    this.#again.set(sessionId, waiting)
    return () => {
      waiting.delete(read)
    }
  }

  /** Asks the screens showing a session's actions to read their records now. */
  askAgain = (sessionId: string): void => {
    for (const read of this.#again.get(sessionId) ?? []) read()
  }
}

/**
 * The earlier action a prompt to `to` names, or null when it names none.
 *
 * The host's rule is about the conversation: it compares a later request with the newest uncertain
 * outcome of the same method for the same session, instance and binding revision. So only an action
 * whose newest read said unknown counts, only a prompt, only one sent to this conversation, and the
 * newest of those by the time its record was written. Anything else is sent with no quote: an
 * action the host holds as accepted or dispatching, or one of another method or conversation, does
 * not stand in a prompt's way, and a quote of one would be refused.
 */
export function supersessionFor(
  submissions: readonly Submission[],
  reads: ReceiptReads,
  to: Conversation
): Supersession | null {
  let newest: { readonly action_id: string; readonly read: ReceiptRead } | null = null
  for (const each of submissions) {
    if (each.state !== 'unknown' || each.actionId === null) continue
    if (
      each.sentTo === undefined ||
      each.sentTo.applicationInstanceId !== to.applicationInstanceId ||
      each.sentTo.agentBindingRevision !== to.agentBindingRevision
    ) {
      continue
    }
    const read = reads.read(each.actionId)
    if (read === undefined || read.state !== 'unknown' || read.method !== PROMPT_METHOD) continue
    if (
      newest === null ||
      later(read.updatedAtMs, newest.read.updatedAtMs) ||
      (read.updatedAtMs === newest.read.updatedAtMs && each.actionId > newest.action_id)
    ) {
      newest = { action_id: each.actionId, read }
    }
  }
  return newest === null
    ? null
    : { action_id: newest.action_id, revision: newest.read.revision }
}
