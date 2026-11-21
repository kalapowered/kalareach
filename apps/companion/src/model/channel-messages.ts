/**
 * The messages sent over a channel that confirms nothing, and the records of sends under way, as
 * this device keeps them apart from the drafts (KR-REQ-12.26).
 *
 * The shelf only reads and removes. Nothing here puts a message in a composer or sends it. A read
 * that fails leaves the shelf as it was and says so: a kept message is never taken for an unknown
 * one because a listing failed after the keep had answered.
 */

import {
  failureMessage,
  type ChannelHoldCreate,
  type ChannelMessageKeep,
  type ChannelMessageList,
  type ChannelMessageRemoval,
  type HostPort,
  type StoredChannelMessage,
  type StoredHold,
  type UnreadableCount
} from '../host/port'

/** Whether the shelf has been read, and whether it could be. */
export type ShelfStatus = 'reading' | 'ready' | 'failed'

/** What the shelf holds at one moment. */
export interface ShelfSnapshot {
  readonly status: ShelfStatus
  /** True when the newest read failed after an earlier one had worked: what is shown may be out of date. */
  readonly stale: boolean
  readonly messages: readonly StoredChannelMessage[]
  readonly holds: readonly StoredHold[]
  /** The names of records of a send that are of this layout and do not parse. */
  readonly damagedHolds: readonly string[]
  readonly unreadableMessages: UnreadableCount
  readonly unreadableHolds: UnreadableCount
  readonly used: { readonly entries: number; readonly bytes: number }
  readonly limits: { readonly entries: number; readonly bytes: number; readonly holds: number }
  /** True when the messages carry their text, which a read for the page asks for. */
  readonly withText: boolean
  /** Why the newest read failed, or null. */
  readonly problem: string | null
}

const NONE: UnreadableCount = { layout: 0, now: 0 }

/** What a shelf that has read nothing holds. */
export const EMPTY_SHELF: ShelfSnapshot = {
  status: 'reading',
  stale: false,
  messages: [],
  holds: [],
  damagedHolds: [],
  unreadableMessages: NONE,
  unreadableHolds: NONE,
  used: { entries: 0, bytes: 0 },
  limits: { entries: 10_000, bytes: 64 * 1024 * 1024, holds: 1_000 },
  withText: false,
  problem: null
}

/** The share of a bound at which the shelf says it is nearly full. */
export const NEARLY_FULL = 0.9

/** The holds list is shown above its warning from this many records. */
export const MANY_HOLDS = 900

/** True when the entries or the bytes this device keeps are at 90% of their bound or more. */
export function nearlyFull(shelf: Pick<ShelfSnapshot, 'used' | 'limits'>): boolean {
  return (
    shelf.used.entries >= NEARLY_FULL * shelf.limits.entries ||
    shelf.used.bytes >= NEARLY_FULL * shelf.limits.bytes
  )
}

/** How many records of any kind could not be read. */
export function unreadableTotal(shelf: Pick<ShelfSnapshot, 'unreadableMessages' | 'unreadableHolds' | 'damagedHolds'>): number {
  return (
    shelf.unreadableMessages.layout +
    shelf.unreadableMessages.now +
    shelf.unreadableHolds.layout +
    shelf.unreadableHolds.now +
    shelf.damagedHolds.length
  )
}

export class ChannelShelf {
  readonly #port: HostPort
  readonly #listeners = new Set<() => void>()
  #state: ShelfSnapshot = EMPTY_SHELF
  #withText = false
  #reads = 0
  #pages = 0
  /** True once the book's first read of the drafts has ended: until then no read of the shelf starts. */
  #open = false
  #opens: () => void = () => undefined
  /** The gate of that first read: closed when the shelf is made, whoever asks for a read first. */
  readonly #gate: Promise<void>

  constructor(port: HostPort) {
    this.#port = port
    this.#gate = new Promise<void>((resolve) => {
      this.#opens = () => {
        this.#open = true
        resolve()
      }
    })
  }

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  snapshot = (): ShelfSnapshot => this.#state

  /**
   * Opens the gate when `first`, the book's first read of the drafts, has ended whether or not it
   * worked. The shelf is made with the gate closed and holds every read, whoever asks for it and in
   * whatever order the window's parts start, until then: what the shelf says about the messages and
   * what the book says about the drafts are one moment's, so the shelf is never read before the
   * drafts are. A read asked for while the gate is closed begins when it opens, and only the newest
   * of them is made.
   */
  after(first: Promise<unknown>): void {
    void first.then(this.#opens, this.#opens)
  }

  /**
   * Notes that the page that lists the messages with their text is open, and reads them. Every read
   * until the matching [`closed`] asks for the text; a read made for a line leaves it out.
   */
  opened(): Promise<void> {
    this.#pages += 1
    this.#withText = true
    return this.refresh()
  }

  /** Notes that a page that opened the shelf closed. */
  closed(): void {
    this.#pages = Math.max(0, this.#pages - 1)
    if (this.#pages === 0) this.#withText = false
  }

  /**
   * Reads the shelf again, once the book's first read has ended. A failure leaves what the shelf
   * held, marks it stale, and never throws: a caller that awaits it learns nothing from it, the
   * snapshot says it. An answer that a later read overtook is dropped.
   */
  async refresh(): Promise<void> {
    this.#reads += 1
    const mine = this.#reads
    if (!this.#open) await this.#gate
    if (mine !== this.#reads) return
    const withText = this.#withText
    let listed: ChannelMessageList
    try {
      listed = await this.#port.deviceChannelMessages({ withText })
    } catch (failure) {
      if (mine !== this.#reads) return
      const first = this.#state.status !== 'ready'
      this.#set({
        ...this.#state,
        status: first ? 'failed' : 'ready',
        stale: !first,
        problem: failureMessage(failure)
      })
      return
    }
    if (mine !== this.#reads) return
    this.#set({
      status: 'ready',
      stale: false,
      messages: listed.messages,
      holds: listed.holds,
      damagedHolds: listed.damagedHolds,
      unreadableMessages: listed.unreadableMessages,
      unreadableHolds: listed.unreadableHolds,
      used: listed.used,
      limits: listed.limits,
      withText,
      problem: null
    })
  }

  /**
   * Keeps a message whole. It resolves on the host's answer and never on the listing after it: a
   * listing that fails leaves the shelf stale and does not undo the keep. A refusal rejects.
   */
  async keep(request: ChannelMessageKeep): Promise<void> {
    await this.#port.deviceChannelMessageKeep(request)
    void this.refresh()
  }

  /** Records a send before it is made. */
  async holdCreate(request: ChannelHoldCreate): Promise<void> {
    await this.#port.deviceChannelHoldCreate(request)
  }

  /**
   * Removes the messages with these identities, and no others, and reads the shelf again, after a
   * refusal too: a removal can fail after the file went, so the shelf shows what is on disk. That
   * read is not an answer to the removal: a refused removal is still rejected, and the list that
   * shows the file gone does not say the removal was made durable.
   */
  async remove(removal: ChannelMessageRemoval): Promise<number> {
    let done: { readonly removed: number }
    try {
      done = await this.#port.deviceChannelMessageRemove(removal)
    } catch (failure) {
      await this.refresh()
      throw failure
    }
    await this.refresh()
    return done.removed
  }

  /** Removes a record of a send, whatever it holds, and reads the shelf again, after a refusal too (see [`remove`]). */
  async clearHold(holdId: string): Promise<void> {
    try {
      await this.#port.deviceChannelHoldClear({ holdId })
    } catch (failure) {
      await this.refresh()
      throw failure
    }
    await this.refresh()
  }

  #set(next: ShelfSnapshot): void {
    this.#state = next
    for (const listener of this.#listeners) listener()
  }
}
