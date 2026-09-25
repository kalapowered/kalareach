/**
 * This computer's owner confirmations, as the page keeps them for as long as it runs.
 *
 * Native code publishes the requests this computer's hosts ask it to confirm. Every screen reads
 * the one store: Attention draws the requests, the sidebar counts them, and a request that arrives
 * is announced once, on whichever screen the person is. What the person does with a request
 * outlives the screen it was done on: a request set aside with "Not now" stays aside until it
 * expires, and one a "Review" asked for is shown with focus once Attention draws it.
 */

import type { ConfirmationRequest, HostPort, OwnerView } from '../host/port'

/** What the store holds at one moment. */
export interface ConfirmationSnapshot {
  /** What native code last published, or null before it has said anything. */
  readonly view: OwnerView | null
  /** The requests to show: every one published, less those set aside. */
  readonly shown: readonly ConfirmationRequest[]
  /** The request a "Review" asked for, until its row has taken focus. */
  readonly focusing: string | null
}

/**
 * Announces the requests that `arrived` together, once, while `waiting` requests are shown in all,
 * with `review`, which shows the first of them in Attention and gives its row focus.
 */
export type Announce = (
  arrived: readonly ConfirmationRequest[],
  waiting: number,
  review: () => void
) => void

export class ConfirmationStore {
  private view: OwnerView | null = null
  private snapshot: ConfirmationSnapshot = { view: null, shown: [], focusing: null }
  /** The requests set aside, each until it expires. */
  private readonly aside = new Map<string, number>()
  /** The requests already announced, each until it expires. */
  private readonly announced = new Map<string, number>()
  private focusing: string | null = null
  private readonly listeners = new Set<() => void>()
  /** Which watch is current: a registration that completes after its watch ended is let go. */
  private generation = 0
  private stop: (() => void) | null = null

  private readonly port: HostPort
  private readonly announce: Announce

  constructor(port: HostPort, announce: Announce) {
    this.port = port
    this.announce = announce
  }

  /** Adds a listener, and watches native code while any listener is present. */
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    if (this.listeners.size === 1) this.watch()
    return () => {
      this.listeners.delete(listener)
      if (this.listeners.size === 0) this.unwatch()
    }
  }

  /** What the store holds now. */
  readonly current = (): ConfirmationSnapshot => this.snapshot

  /** Sets `request` aside until it expires. Nothing is answered: the host keeps asking. */
  setAside(request: ConfirmationRequest): void {
    this.aside.set(request.reference, request.expires_at_ms)
    this.publish()
  }

  /** Brings the request `reference` names back, if it was set aside, and asks for its row. */
  review(reference: string): void {
    this.aside.delete(reference)
    this.focusing = reference
    this.publish()
  }

  /** Says the row a review asked for has taken focus. */
  focused(): void {
    if (this.focusing === null) return
    this.focusing = null
    this.publish()
  }

  private watch(): void {
    const generation = ++this.generation
    // The requests are read once the listener is registered, so none can fall between the two.
    // An event heard before the read answers is at least as new, so the read is let go then.
    let heard = false
    this.port
      .onConfirmations((next) => {
        if (generation !== this.generation) return
        heard = true
        this.apply(next)
      })
      .then(async (unlisten) => {
        if (generation !== this.generation) {
          unlisten()
          return
        }
        this.stop = unlisten
        const current = await this.port.ownerConfirmations()
        if (generation === this.generation && !heard) this.apply(current)
      })
      .catch(() => {
        // A computer that cannot pair has no confirmations to show.
      })
  }

  private unwatch(): void {
    this.generation++
    this.stop?.()
    this.stop = null
  }

  private apply(next: OwnerView): void {
    this.view = next
    const now = Date.now()
    for (const kept of [this.aside, this.announced]) {
      for (const [reference, expires] of kept) {
        if (expires <= now) kept.delete(reference)
      }
    }
    const arrived = next.requests.filter((request) => !this.announced.has(request.reference))
    for (const request of arrived) this.announced.set(request.reference, request.expires_at_ms)
    this.publish()
    const [first] = arrived
    if (first === undefined) return
    this.announce(arrived, this.snapshot.shown.length, () => {
      this.review(first.reference)
    })
  }

  private publish(): void {
    const view = this.view
    this.snapshot = {
      view,
      shown: view === null ? [] : view.requests.filter((request) => !this.aside.has(request.reference)),
      focusing: this.focusing
    }
    for (const listener of this.listeners) listener()
  }
}
