/**
 * The answers people have begun to give, held for the window.
 *
 * A form is the person's own work: what they picked or typed for a question, before they press
 * Send. It belongs to the question, not to the screen that showed it, so the inbox's row going
 * away, or the person leaving for another screen and coming back, loses nothing. It is held for the
 * life of the window, and sent only on a completed press.
 */

import type { Form } from './questions'

/** The forms begun, by the question each answers. */
export type Forms = Readonly<Record<string, Form>>

/** The window's forms, and the listeners told when they change. */
export class QuestionForms {
  #forms: Forms = {}
  readonly #listeners = new Set<() => void>()

  /** Subscribes to every change; the returned function unsubscribes. */
  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** The forms now. The same object until one changes. */
  snapshot = (): Forms => this.#forms

  /** Changes the forms the way a state's update does: from what is held now. */
  update = (change: (current: Forms) => Forms): void => {
    const next = change(this.#forms)
    if (next === this.#forms) return
    this.#forms = next
    for (const listener of this.#listeners) listener()
  }
}
