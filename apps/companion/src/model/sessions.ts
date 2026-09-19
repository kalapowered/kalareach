/**
 * What the application holds for each session, kept apart from every other session.
 *
 * A person moves between the conversation and the terminal, and between one session and another.
 * None of that is a reason to lose a draft, a position or a pending action, and none of it is a
 * reason for one session's state to appear under another's name. Both follow from the same rule:
 * state belongs to a session identity, not to whichever view happens to be mounted.
 *
 * This is the store behind that rule. It is deliberately small: a map keyed by session, a listener
 * list, and the two reads React needs to subscribe to it.
 */

import { emptyConversation, type ConversationState } from './conversation'
import { startDraft, type Draft } from './drafts'
import type { Submission } from './receipts'

/** Everything one session's views share. */
export interface SessionState {
  /** The document, its window and where the reader is. */
  readonly conversation: ConversationState
  /** What this device has sent, and what became of it. */
  readonly submissions: readonly Submission[]
  /** The draft for this session. */
  readonly draft: Draft
  /** Images the person explicitly imported, by URL. */
  readonly images: ReadonlyMap<string, string>
  /** True once a snapshot has been folded in, so a view knows the difference from empty. */
  readonly loaded: boolean
}

/** The state of a session nothing has happened in yet. */
export function emptySessionState(sessionId: string, now: number): SessionState {
  return {
    conversation: emptyConversation(),
    submissions: [],
    draft: startDraft(
      `draft-${sessionId}`,
      { sessionId, applicationInstanceId: null, agentBindingRevision: null },
      now
    ),
    images: new Map(),
    loaded: false
  }
}

/** The sessions this window is holding state for. */
export class SessionStates {
  #states = new Map<string, SessionState>()
  #listeners = new Set<() => void>()

  /** Reads one session's state, creating it the first time it is asked for. */
  get(sessionId: string): SessionState {
    const held = this.#states.get(sessionId)
    if (held) return held
    const fresh = emptySessionState(sessionId, Date.now())
    this.#states.set(sessionId, fresh)
    return fresh
  }

  /**
   * Replaces one session's state.
   *
   * The update is given the session's own state and nothing else, so an update written for one
   * session cannot reach another's.
   */
  update(sessionId: string, change: (current: SessionState) => SessionState): void {
    const current = this.get(sessionId)
    const next = change(current)
    if (next === current) return
    this.#states.set(sessionId, next)
    for (const listener of this.#listeners) listener()
  }

  /** Forgets a session, for a tab the person closed. */
  forget(sessionId: string): void {
    if (!this.#states.delete(sessionId)) return
    for (const listener of this.#listeners) listener()
  }

  /** Subscribes to every change; the returned function unsubscribes. */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** How many sessions are held, which a test reads to see that nothing leaked. */
  get size(): number {
    return this.#states.size
  }
}

/**
 * Whether an event belongs to a session.
 *
 * The host names a stream after the session it belongs to, so a view showing one session ignores
 * another's events by asking this rather than by assuming every event is its own. An event with no
 * stream is the connection's own and belongs to no session.
 */
export function eventIsFor(streamId: string, sessionId: string): boolean {
  return streamId.length > 0 && streamId.includes(sessionId)
}
