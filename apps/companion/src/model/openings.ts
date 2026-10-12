/**
 * What a session screen holds of the opening it made.
 *
 * A screen opens its session under one grant and the host says what that grant allows. On a host
 * this device is paired with, the opening is a connection of its own, and every command about the
 * session names it. The page keeps the newest opening of each session here, with the standing the
 * host last reported, so a read, an event or a late answer can be told to belong to the opening
 * that is current or to one that was replaced. The answer to a command made under a replaced
 * opening is not the current screen's to show.
 *
 * The rights a screen offers come from the standing: what the host decided for this grant, which
 * for a share can be more than the pairing holds and for a pairing is what the connection holds.
 */

import type { ActionRight } from '@kalareach/protocol'

import { failureWords, type SessionStanding } from '../host/port'

/** A standing in which the host lets the screen act. */
export type OpenStanding = Extract<SessionStanding, { readonly state: 'open' }>

/** One session's newest opening. */
export interface OpeningRecord {
  /** The screen's token for this opening. */
  readonly token: string
  /** The share the opening runs under, or null for the pairing. */
  readonly grantId: string | null
  /** The newest standing the host reported, or null until it has answered. */
  readonly standing: SessionStanding | null
  /** The newest standing in which the session was open, kept while it is not. */
  readonly held: OpenStanding | null
  /** When the page heard the newest standing, in UTC milliseconds. */
  readonly heardAtMs: number
  /** How many standings this opening has been told, which a screen reads as "something was said". */
  readonly told: number
}

/** The sessions this window has an opening for. */
export class Openings {
  #records = new Map<string, OpeningRecord>()
  #grants = new Map<string, string | null>()
  #listeners = new Set<() => void>()

  /** The newest opening of a session, or undefined when the screen has none. */
  get(sessionId: string): OpeningRecord | undefined {
    return this.#records.get(sessionId)
  }

  /** The token commands about the session carry, or undefined when there is no opening. */
  tokenOf(sessionId: string): string | undefined {
    return this.#records.get(sessionId)?.token
  }

  /** Whether `token` is the session's newest opening. */
  isCurrent(sessionId: string, token: string | undefined): boolean {
    return this.#records.get(sessionId)?.token === token
  }

  /**
   * Starts an opening, which replaces the session's earlier one.
   *
   * Answers whether the grant is not the one the session was last open under, so the screen
   * clears what it read under the other.
   */
  begin(sessionId: string, token: string, grantId: string | null, nowMs: number): boolean {
    const known = this.#grants.has(sessionId)
    const changed = known && this.#grants.get(sessionId) !== grantId
    this.#grants.set(sessionId, grantId)
    this.#records.set(sessionId, {
      token,
      grantId,
      standing: null,
      held: null,
      heardAtMs: nowMs,
      told: 0
    })
    this.#changed()
    return changed
  }

  /**
   * Takes in what the host said of `token`'s opening. A standing for an opening that is not the
   * newest is dropped. Answers whether it was kept.
   */
  apply(sessionId: string, token: string, standing: SessionStanding, nowMs: number): boolean {
    const record = this.#records.get(sessionId)
    if (record?.token !== token) return false
    this.#records.set(sessionId, {
      ...record,
      standing,
      held: standing.state === 'open' ? standing : record.held,
      heardAtMs: nowMs,
      told: record.told + 1
    })
    this.#changed()
    return true
  }

  /** Ends `token`'s opening if it is the newest. A replaced opening ends nothing. */
  end(sessionId: string, token: string): void {
    if (this.#records.get(sessionId)?.token !== token) return
    this.#records.delete(sessionId)
    this.#changed()
  }

  /** Forgets which grant a session was last open under, for a tab the person closed. */
  forget(sessionId: string): void {
    this.#grants.delete(sessionId)
  }

  /** Subscribes to every change; the returned function unsubscribes. */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  #changed(): void {
    for (const listener of this.#listeners) listener()
  }
}

/** Whether a standing is one in which nothing more can be sent. */
export function isOver(standing: SessionStanding | null): boolean {
  return (
    standing !== null &&
    (standing.state === 'ended' ||
      standing.state === 'closed' ||
      standing.state === 'refused' ||
      standing.state === 'superseded')
  )
}

/**
 * What a screen with an opening may do, or null while that is not known.
 *
 * Until the host has answered, and while contact with the session is being taken up again, nothing
 * is offered: a fact nobody has told this device is not one it guesses. Once the opening is over,
 * the host lets it do nothing. A share's rights are the share's, whatever the pairing holds. The
 * pairing's own are what the connection holds too, so a change of the connection's rights reaches
 * a screen under the pairing at once, and a connection out of contact offers nothing.
 */
export function rightsOf(
  record: OpeningRecord | undefined,
  connection: readonly ActionRight[] | null
): readonly ActionRight[] | null {
  if (record === undefined) return connection
  const standing = record.standing
  if (standing === null || standing.state === 'reconnecting') return null
  if (standing.state !== 'open') return []
  if (standing.via === 'share') return standing.actions
  return connection === null
    ? null
    : standing.actions.filter((action) => connection.includes(action))
}

/** What a standing that is not open tells the person, in words, and what they may do about it. */
export interface StandingWords {
  readonly tone: 'warning' | 'danger' | 'accent'
  readonly title: string
  readonly detail: string
  /** What the banner offers besides going back. */
  readonly retry: boolean
}

/** The time of day a standing was heard, as a person reads it. */
function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
}

/**
 * The words for a standing that is over, or null for one that is not.
 *
 * `reconnecting` is not said here: it is the connection banner's to say, in its words.
 */
export function wordsFor(record: OpeningRecord): StandingWords | null {
  const standing = record.standing
  if (standing === null) return null
  const heard = `Heard at ${clock(record.heardAtMs)}.`
  switch (standing.state) {
    case 'ended': {
      const scheduled = record.held?.ends_at_ms ?? null
      const why =
        standing.reason === 'revoked'
          ? 'The person who shared it stopped sharing it.'
          : scheduled === null
            ? 'It reached its end.'
            : `It was scheduled to end at ${clock(scheduled)}.`
      return {
        tone: 'warning',
        title: 'This share ended',
        detail: `${why} What you read is still here, and nothing more can be sent. ${heard}`,
        retry: false
      }
    }
    case 'closed':
      return {
        tone: 'warning',
        title: 'This session has closed',
        detail: `What you read is still here, and nothing more can be sent. ${heard}`,
        retry: false
      }
    case 'refused':
      return {
        tone: 'danger',
        title: 'This session is not open to you',
        detail: failureWords(standing),
        retry: true
      }
    case 'superseded':
      return {
        tone: 'warning',
        title: 'This screen was replaced',
        detail: 'Another screen opened this session. Open it again from the list.',
        retry: false
      }
    case 'open':
    case 'reconnecting':
      return null
  }
}

/** What the standing's change is announced as, once, or null when it changed to nothing to say. */
export function announcementFor(record: OpeningRecord | undefined): string {
  if (record === undefined) return ''
  const words = wordsFor(record)
  return words === null ? '' : `${words.title}. ${words.detail}`
}
