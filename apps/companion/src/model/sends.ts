/**
 * The prompts on their way, and how each one ends.
 *
 * The book that keeps a person's drafts holds the text of a prompt from the press of Send until the
 * prompt has ended, and removes it only when the host took it. A host that answers `accepted` or
 * `dispatching` has not taken it yet: the prompt stays in flight, here, until a receipt (an event
 * on the desktop, a read of the host's record on either screen) says how it ended.
 */

import { sendOutcomeOf, type InputState } from './receipts'
import type { SendOutcome } from './draft-book'

/** The prompts still with the host, by the submission that carries each. */
export class OpenSends {
  readonly #open = new Map<string, (outcome: SendOutcome) => void>()

  /** Holds a prompt until its submission reaches an end. */
  hold(localId: string, end: (outcome: SendOutcome) => void): void {
    this.#open.set(localId, end)
  }

  /** A submission is now in `state`: its prompt ends when the state is one the host will not leave. */
  settled(localId: string, state: InputState): void {
    const outcome = sendOutcomeOf(state)
    if (outcome === null) return
    const end = this.#open.get(localId)
    if (end === undefined) return
    this.#open.delete(localId)
    end(outcome)
  }

  /**
   * The screen that sent them is gone, so nothing can see them end: they end as of unknown outcome,
   * which keeps the text and takes nothing from the host.
   */
  endAll(): void {
    const open = [...this.#open.values()]
    this.#open.clear()
    for (const end of open) end('unknown')
  }
}
