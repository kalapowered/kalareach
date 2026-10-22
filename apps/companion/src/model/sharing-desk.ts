/**
 * What the page keeps of the host's results for the four sharing actions once it has been told
 * them.
 *
 * Native code keeps an attempt's record until the page has the host's result, and removes it once
 * the page says it has. What the page keeps of a result then has to outlive the screen that
 * showed it: the person can leave the sharing tab, or have the hand-over sheet open, while the
 * host's answer arrives, and a note about a screen or a line about a revocation that went with the
 * screen would be a result nobody was shown. So these live here, for the page's life, by the port
 * the page talks to, and the screens only draw them.
 *
 * A result is taken in once: the roads it can arrive by (the command that sent the action, a
 * repeat made in the background, and the person asking the host) can overlap, and the second
 * delivery changes nothing.
 */

import type { HostPort } from '../host/port'

/** A revocation the page has been told of, kept because the host's list drops resolved grants. */
export interface Revoked {
  readonly grantId: string
  readonly name: string
  readonly atMs: number
  /** The authority revision the host issued for the revocation. */
  readonly revision: string
  readonly pending: number
}

/**
 * A screen the host kept with an invitation that the person has to judge: it differs from the one
 * they were shown, or the one they were shown is no longer here to compare it with.
 */
export interface ScreenNote {
  readonly grantId: string
  readonly sessionId: string
  readonly name: string
  readonly kind: 'changed' | 'unverified'
  readonly lines: readonly string[]
}

/** What the screens draw. A new value each time something changes. */
export interface Kept {
  readonly revoked: readonly Revoked[]
  readonly notes: readonly ScreenNote[]
}

/** Who a revocation was for, and whether it withdrew an invitation. */
interface Meant {
  readonly name: string
  readonly withdrawing: boolean
}

export class SharingDesk {
  #kept: Kept = { revoked: [], notes: [] }
  readonly #listeners = new Set<() => void>()
  readonly #taken = new Set<string>()
  readonly #checks = new Set<string>()
  readonly #shown = new Map<string, readonly string[]>()
  readonly #meant = new Map<string, Meant>()

  /** Tells `listener` when anything the screens draw changes. */
  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** What the screens draw now. */
  readonly snapshot = (): Kept => this.#kept

  /**
   * Whether this is the first time the result of `action` is taken in. The second delivery, by
   * whichever road, is told to stop.
   */
  firstTime(action: string): boolean {
    if (this.#taken.has(action)) return false
    this.#taken.add(action)
    return true
  }

  /**
   * Marks the action of a Check again as one, so that its answer, however late and whether or not
   * the line it checks is still there, is only ever an answer to a check.
   */
  markCheck(action: string): void {
    this.#checks.add(action)
  }

  /** Whether `action` is a Check again. */
  isCheck(action: string): boolean {
    return this.#checks.has(action)
  }

  /** The lines the person was shown with an invitation, kept for the answer that comes later. */
  remember(action: string, lines: readonly string[]): void {
    this.#shown.set(action, lines)
  }

  /** The lines the person was shown with an invitation, once, or none when they are not kept. */
  recall(action: string): readonly string[] | undefined {
    const lines = this.#shown.get(action)
    this.#shown.delete(action)
    return lines
  }

  /** Who a revocation of `grantId` is for, kept for the report of its result. */
  intend(grantId: string, meant: Meant): void {
    this.#meant.set(grantId, meant)
  }

  /** Who a revocation of `grantId` was for, when the page made it. */
  meant(grantId: string): Meant | undefined {
    return this.#meant.get(grantId)
  }

  /**
   * Keeps the line that says a revocation was made, at which authority revision, and how many
   * workers have not confirmed it.
   */
  keepRevocation(grantId: string, name: string, atMs: number, revision: string, pending: number): void {
    this.#change({
      revoked: [
        ...this.#kept.revoked.filter((line) => line.grantId !== grantId),
        { grantId, name, atMs, revision, pending }
      ]
    })
  }

  /** Whether a line for a revocation of `grantId` is kept. */
  has(grantId: string): boolean {
    return this.#kept.revoked.some((line) => line.grantId === grantId)
  }

  /** Says how many workers still have not confirmed a revocation already kept, as of a check. */
  checked(grantId: string, pending: number): void {
    this.#change({
      revoked: this.#kept.revoked.map((line) => (line.grantId === grantId ? { ...line, pending } : line))
    })
  }

  dismissRevocation(grantId: string): void {
    this.#change({ revoked: this.#kept.revoked.filter((line) => line.grantId !== grantId) })
  }

  /** Keeps a note about an invitation's screen, in place of an older one about the same grant. */
  note(next: ScreenNote): void {
    this.#change({
      notes: [...this.#kept.notes.filter((each) => each.grantId !== next.grantId), next]
    })
  }

  dismissNote(grantId: string): void {
    this.#change({ notes: this.#kept.notes.filter((each) => each.grantId !== grantId) })
  }

  #change(next: Partial<Kept>): void {
    this.#kept = { ...this.#kept, ...next }
    for (const listener of this.#listeners) listener()
  }
}

/** One desk for each port the page talks to, for as long as the page lives. */
const desks = new WeakMap<HostPort, SharingDesk>()

/** The desk of a port. */
export function deskOf(port: HostPort): SharingDesk {
  let desk = desks.get(port)
  if (desk === undefined) {
    desk = new SharingDesk()
    desks.set(port, desk)
  }
  return desk
}
