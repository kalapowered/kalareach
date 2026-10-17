/**
 * What a phone is offered, holds and used to hold, kept for as long as the application runs.
 *
 * The phone is told by `grant.held` and by nothing else: an invitation naming it before it
 * accepts, and a share it holds after. A read follows every page of both lists or fails whole, so
 * a list that is here is a complete one, and only a complete one is compared with the one before:
 * a share that was held and is no longer listed has ended, and a read that failed says nothing
 * about any share. The host's list says only that a share left it. It does not say whether the
 * share was taken back, ran out or lost its session, so a row for one says only that it ended.
 *
 * This is the page's memory, as the desk of the sharing tab is, and for the same reason: the person
 * moves between the inbox and the sessions, which draw different halves of one read, and what a
 * half has learned (a share that ended, an invitation put off, an arrival already told) must not
 * go with the screen that showed it, and a loss of contact with the host keeps it too. Reads are made
 * while a screen that draws them is shown, on the cadence of the other lists, at once when the
 * connection comes or changes and when the application is shown again. A host that does not know
 * the method is asked once per connection and then left alone, and both halves stay out of sight.
 */

import type { HeldShare, ShareOffer } from '@kalareach/protocol'

import { readOnCadence, type Cadence } from '../app/cadence'
import { failureCode, type AttemptView, type Held, type HostPort } from '../host/port'
import { sessionOfShare } from './shared-with-you'
import { roleOfRights, roleWords } from './sharing'

/** How often what a device holds is read while a screen that draws it is shown. */
export const HELD_READ_CADENCE_MS = 5_000

/** What a host answers to a method it does not serve, and to one it cannot serve this version of. */
const NOT_SERVED: ReadonlySet<string> = new Set([
  'PERMISSION_DENIED',
  'UNSUPPORTED_SCHEMA',
  'UNSUPPORTED_CAPABILITY'
])

/** Whether a refusal of the read says the host does not serve it. */
export function hostDoesNotServeHeld(failure: unknown): boolean {
  const code = failureCode(failure)
  return code !== null && NOT_SERVED.has(code)
}

/** A share the host no longer lists. */
export interface EndedShare {
  readonly grantId: string
  readonly sessionId: string | null
  readonly displayNumber: string
  /** The role it was held as, in words. */
  readonly role: string
  /** When this application read the list that no longer had it, by this computer's clock. */
  readonly seenEndedAtMs: number
}

/** Where the reads stand. */
export type HeldStatus =
  /** Nothing has been read yet, or there is no host this device is paired with to ask. */
  | 'unread'
  /** A complete read is here. */
  | 'ready'
  /** The host does not serve the read, so neither half is drawn. */
  | 'unsupported'

/** What the screens draw. A new value each time something changes. */
export interface HeldView {
  readonly status: HeldStatus
  /** What the host is called here, from this device's own record of the pairing. */
  readonly hostName: string | null
  /** When the list was last read in full, by this computer's clock; the words about time start from it. */
  readonly readAtMs: number
  /** True when the read since the last complete one failed: what is drawn is the host's last list. */
  readonly stale: boolean
  /** The invitations that name this device, the newest first. */
  readonly offers: readonly ShareOffer[]
  /** The invitations the person put off, among those offered. */
  readonly hidden: readonly string[]
  /** The shares held, in the order of their sessions' numbers. */
  readonly shares: readonly HeldShare[]
  /** The shares that were held and are not listed now, the latest to end first. */
  readonly ended: readonly EndedShare[]
  /** The acceptances this application keeps its word about and has not seen to the end. */
  readonly attempts: readonly AttemptView[]
  /**
   * The invitations that arrived since the read before, which a screen tells the person of once.
   * `seq` moves on only when there are some.
   */
  readonly arrived: { readonly seq: number; readonly invitationIds: readonly string[] }
}

const NOTHING: HeldView = {
  status: 'unread',
  hostName: null,
  readAtMs: 0,
  stale: false,
  offers: [],
  hidden: [],
  shares: [],
  ended: [],
  attempts: [],
  arrived: { seq: 0, invitationIds: [] }
}

/** Where the shell's connection stands, as the book needs it. */
export interface Reach {
  readonly connected: boolean
  /** Whether the host reached is one this device is paired with, not the one on this computer. */
  readonly paired: boolean
  /** The environment the connection belongs to, which says which host is reached. */
  readonly environmentId: string | null
}

/**
 * The key of the host a connection reaches, or none when there is no host this device is paired
 * with to ask: the host on this computer holds no share of itself.
 */
function hostKeyOf(reach: Reach): string {
  return reach.paired && reach.environmentId !== null ? `host:${reach.environmentId}` : 'none'
}

/** Newest first, and the invitation's identity when two were issued in one moment. */
function newestFirst(a: ShareOffer, b: ShareOffer): number {
  const by = Number(b.issued_at_ms) - Number(a.issued_at_ms)
  return by !== 0 ? by : a.invitation_id.localeCompare(b.invitation_id)
}

function byNumber(a: HeldShare, b: HeldShare): number {
  const by = Number(a.display_number) - Number(b.display_number)
  return by !== 0 ? by : a.grant.grant_id.localeCompare(b.grant.grant_id)
}

export class HeldBook {
  readonly #port: HostPort
  readonly #cadenceMs: number
  readonly #listeners = new Set<() => void>()
  #view: HeldView = NOTHING
  /** The host this memory is of: what was learned is kept while the same host is reached. */
  #host = 'none'
  /** Whether a connection to that host is up now. A loss of contact keeps what was learned. */
  #online = false
  #attached = 0
  #cadence: Cadence | null = null
  /** Which read is the newest started: an older one that answers after it is dropped. */
  #newest = 0
  /** Whether the next complete read is the first since a screen came: nothing in it is news. */
  #baseline = true
  #known = new Set<string>()
  #putOff = new Set<string>()

  constructor(port: HostPort, cadenceMs: number = HELD_READ_CADENCE_MS) {
    this.#port = port
    this.#cadenceMs = cadenceMs
  }

  /** Tells `listener` when anything the screens draw changes. */
  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** What the screens draw now. */
  readonly snapshot = (): HeldView => this.#view

  /**
   * The shell says where the connection stands, each time it changes, whether or not a screen that
   * draws what is held is shown.
   *
   * A loss of contact keeps what was learned and says the lists are not fresh: a share that ends
   * while the phone is out of contact is found ended by the first complete read after. Reaching
   * another host starts the memory again. A new connection asks a host that did not serve the read
   * once more, since a host can be updated between two connections.
   */
  reach(now: Reach): void {
    if (!now.connected) {
      this.#online = false
      this.#newest += 1
      if (this.#view.status === 'ready' && !this.#view.stale) this.#change({ stale: true })
      return
    }
    const host = hostKeyOf(now)
    const changed = host !== this.#host
    const reconnected = !this.#online
    this.#online = true
    this.#host = host
    if (changed) {
      this.#newest += 1
      this.#known = new Set()
      this.#putOff = new Set()
      this.#baseline = true
      this.#view = { ...NOTHING, arrived: { seq: this.#view.arrived.seq, invitationIds: [] } }
      this.#told()
    } else if (reconnected && this.#view.status === 'unsupported') {
      this.#change({ status: 'unread' })
    }
    if (changed || reconnected) this.#cadence?.now()
  }

  /**
   * A screen that draws what is held is shown: reads begin, and stop when the last one is gone.
   * The first read after a screen comes is a baseline, so what was waiting is not told as news.
   */
  attach(): () => void {
    this.#attached += 1
    if (this.#attached === 1) this.#begin()
    let released = false
    return () => {
      if (released) return
      released = true
      this.#attached -= 1
      if (this.#attached === 0) this.#end()
    }
  }

  /** Reads now, or as soon as the read on its way has answered. */
  refresh(): void {
    this.#cadence?.now()
  }

  /** Reads now and settles once the answer has been taken in or has failed. */
  readNow(): Promise<void> {
    return this.#read()
  }

  /**
   * Takes in an acceptance the page was just told of, so that what is drawn knows of it before the
   * next read lists it.
   */
  keep(attempt: AttemptView): void {
    if (attempt.kind !== 'redeem') return
    this.#change({
      attempts: [...this.#view.attempts.filter((each) => each.action_id !== attempt.action_id), attempt]
    })
  }

  /** The person put an invitation off. It stays offered by the host and is out of sight here. */
  putOff(invitationId: string): void {
    if (this.#putOff.has(invitationId)) return
    this.#putOff.add(invitationId)
    this.#change({ hidden: this.#hiddenOffers(this.#view.offers) })
  }

  /** The person asks to see the invitations they put off. */
  showPutOff(): void {
    this.#putOff = new Set()
    this.#change({ hidden: [] })
  }

  /* ---- Inside ---------------------------------------------------------------------------------- */

  #begin(): void {
    this.#baseline = true
    this.#cadence = readOnCadence(() => this.#read(), this.#cadenceMs)
    if (this.#host !== 'none' && this.#online) this.#cadence.now()
  }

  #end(): void {
    this.#cadence?.stop()
    this.#cadence = null
  }

  async #read(): Promise<void> {
    if (!this.#online || this.#host === 'none' || this.#view.status === 'unsupported') return
    this.#newest += 1
    const mine = this.#newest
    let held: Held
    let attempts: readonly AttemptView[]
    try {
      held = await this.#port.grantHeld()
      attempts = (await this.#port.attemptsList()).attempts.filter((each) => each.kind === 'redeem')
    } catch (failure: unknown) {
      if (mine !== this.#newest) return
      // A host that does not serve the read is asked once. Any other failure says nothing about
      // what is held: the last complete read stands, and nothing is marked as ended.
      if (hostDoesNotServeHeld(failure)) this.#change({ ...NOTHING, status: 'unsupported' })
      else if (!this.#view.stale) this.#change({ stale: true })
      return
    }
    const hostName = await this.#hostName()
    // Only the newest read is taken in: one that was started before a connection changed, or before
    // another read, and answers after, is an older list than the one that is here.
    if (mine !== this.#newest) return
    this.#apply(held, attempts, hostName)
  }

  /** What this device calls the host it is using, from its own record of the pairing. */
  async #hostName(): Promise<string | null> {
    if (this.#view.hostName !== null) return this.#view.hostName
    try {
      const view = await this.#port.pairingView()
      return view.hosts.find((host) => host.in_use)?.name ?? null
    } catch {
      return null
    }
  }

  /** A complete read, taken in. */
  #apply(held: Held, attempts: readonly AttemptView[], hostName: string | null): void {
    const offers = [...held.offers].sort(newestFirst)
    const shares = [...held.shares].sort(byNumber)
    const listed = new Set(shares.map((share) => share.grant.grant_id))
    // A share that was held and is not listed has ended. One that is listed again is not ended.
    const ended: EndedShare[] = this.#view.ended.filter((each) => !listed.has(each.grantId))
    for (const earlier of this.#view.shares) {
      const grantId = earlier.grant.grant_id
      if (listed.has(grantId) || ended.some((each) => each.grantId === grantId)) continue
      ended.unshift({
        grantId,
        sessionId: sessionOfShare(earlier),
        displayNumber: earlier.display_number,
        role: roleWords(roleOfRights(earlier.grant.actions)),
        seenEndedAtMs: Date.now()
      })
    }
    const arrivals = this.#baseline
      ? []
      : offers.map((offer) => offer.invitation_id).filter((id) => !this.#known.has(id))
    this.#baseline = false
    this.#known = new Set(offers.map((offer) => offer.invitation_id))
    // An invitation the person put off that the host no longer offers is forgotten.
    this.#putOff = new Set([...this.#putOff].filter((id) => this.#known.has(id)))
    this.#change({
      status: 'ready',
      hostName,
      readAtMs: Date.now(),
      stale: false,
      offers,
      hidden: this.#hiddenOffers(offers),
      shares,
      ended,
      attempts,
      arrived:
        arrivals.length === 0
          ? this.#view.arrived
          : { seq: this.#view.arrived.seq + 1, invitationIds: arrivals }
    })
  }

  #hiddenOffers(offers: readonly ShareOffer[]): readonly string[] {
    return offers.map((offer) => offer.invitation_id).filter((id) => this.#putOff.has(id))
  }

  #told(): void {
    for (const listener of this.#listeners) listener()
  }

  #change(next: Partial<HeldView>): void {
    this.#view = { ...this.#view, ...next }
    this.#told()
  }
}

/** One book for each port the page talks to, for as long as the page lives. */
const books = new WeakMap<HostPort, HeldBook>()

/** The book of a port. */
export function bookOf(port: HostPort): HeldBook {
  let book = books.get(port)
  if (book === undefined) {
    book = new HeldBook(port)
    books.set(port, book)
  }
  return book
}
