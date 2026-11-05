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
 *
 * Which uncertain action is the newest is the host's to say, by the order it recorded them in, and
 * a read does not carry that order. The page picks by the time of the record, and when the host
 * refuses the quote it names the action it holds as the newest: the next quote is that one.
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

/** An action identifier, as the host writes one in its words. */
const ACTION_ID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/

/** How many actions the host named in a refusal this window keeps. */
const MAX_NAMED = 16

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
  /** How many refusals that name an action this window has kept. */
  #refusals = 0
  /** For each action, how many of those refusals had been kept when its record was first read. */
  readonly #firstRead = new Map<string, number>()
  /** The refusal that last named each action, by its number, the one named last at the end. */
  readonly #named = new Map<string, number>()

  /** Keeps what a read of an action's record said, unless a newer revision has been read. */
  note = (receipt: Receipt): void => {
    if (!this.#firstRead.has(receipt.action_id)) {
      this.#firstRead.set(receipt.action_id, this.#refusals)
    }
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

  /**
   * Keeps the action a host's refusal names, which is the first identifier in its words: the one it
   * holds as the newest uncertain outcome of the conversation, or the one the quote was about.
   */
  noteRefusal = (words: string): void => {
    const named = ACTION_ID.exec(words)?.[0]
    if (named === undefined) return
    this.#refusals += 1
    this.#named.delete(named)
    this.#named.set(named, this.#refusals)
    for (const oldest of this.#named.keys()) {
      if (this.#named.size <= MAX_NAMED) break
      this.#named.delete(oldest)
    }
  }

  /**
   * How late the host's word puts an action: the number of the refusal that last named it, or of
   * the last refusal before its record was first read, whichever is later. An action read after a
   * refusal is newer than what that refusal named, since the host admitted it afterwards. Zero for
   * an action no refusal has bearing on.
   */
  heldAt = (actionId: string): number =>
    Math.max(this.#firstRead.get(actionId) ?? 0, this.#named.get(actionId) ?? 0)

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
 * newest of those: the one the host last named in a refusal, unless an action was read after that,
 * and otherwise the one whose record was written last. Anything else is sent with no quote: an
 * action the host holds as accepted or dispatching, or one of another method or conversation, does
 * not stand in a prompt's way, and a quote of one would be refused.
 */
export function supersessionFor(
  submissions: readonly Submission[],
  reads: ReceiptReads,
  to: Conversation
): Supersession | null {
  let newest: { readonly action_id: string; readonly read: ReceiptRead; readonly held: number } | null =
    null
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
    const held = reads.heldAt(each.actionId)
    if (
      newest === null ||
      held > newest.held ||
      (held === newest.held &&
        (later(read.updatedAtMs, newest.read.updatedAtMs) ||
          (read.updatedAtMs === newest.read.updatedAtMs && each.actionId > newest.action_id)))
    ) {
      newest = { action_id: each.actionId, read, held }
    }
  }
  return newest === null
    ? null
    : { action_id: newest.action_id, revision: newest.read.revision }
}
