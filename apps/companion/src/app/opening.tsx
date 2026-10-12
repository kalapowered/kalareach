/**
 * How a session screen opens its session and hears what the host says of it.
 *
 * A screen makes one opening for the session it shows, with a token of its own. Native code opens
 * the session on a connection of its own under the grant the screen names, and every command the
 * screen makes about the session carries the token, so a command prepared under an opening that
 * was replaced is refused and reaches nothing. The screen leaves the opening when it goes, even
 * when the host has not yet answered the open.
 *
 * Opening the same session again, under another grant or after a refusal, is a new opening with a
 * new token: a token is used once. What the host said of the earlier opening does not carry over,
 * and what was read under another grant is cleared. Drafts and every submission that has not
 * settled are the person's, and stay.
 */

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'

import { useApp } from './state'
import { failureCode, failureWords } from '../host/port'
import { emptyConversation } from '../model/conversation'
import type { OpeningRecord } from '../model/openings'
import { unreadAgent, type SessionState } from '../model/sessions'

/** A token for one opening: unique, and in the alphabet native code accepts. */
function newToken(): string {
  const random = globalThis.crypto as Crypto | undefined
  if (typeof random?.randomUUID === 'function') return random.randomUUID()
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`
}

/**
 * The codes of a host that is only unable to answer now. An open that is answered with one is not
 * a refusal: the host is asked again, backing off as native code does for a link it holds.
 */
const UNABLE_NOW: ReadonlySet<string> = new Set([
  'RESOURCE_UNAVAILABLE',
  'STORAGE_UNAVAILABLE',
  'CLOCK_UNTRUSTED',
  'UPSTREAM_UNAVAILABLE'
])

/** How long after an open that could not be answered the next one is asked: 0.25 s, doubling to 30 s. */
export function retryAfterMs(failures: number): number {
  return Math.min(30_000, 250 * 2 ** Math.min(failures, 16))
}

/** What a session holds of what it read, without what the person made. */
function unread(state: SessionState): SessionState {
  return { ...state, conversation: emptyConversation(), agent: unreadAgent(), loaded: false }
}

/** What a screen is told about its session's opening. */
export interface Opened {
  /** The opening, or undefined before the screen's first effect has made one. */
  readonly record: OpeningRecord | undefined
  /** Opens the session again, as a new opening. */
  readonly retry: () => void
}

/**
 * Opens `sessionId` for the calling screen while it is mounted, under `grantId` (null is the
 * pairing), and follows what the host says of the opening.
 */
export function useSessionOpening(sessionId: string, grantId: string | null): Opened {
  const { port, openings, sessions } = useApp()
  const [attempt, setAttempt] = useState(0)
  // Opens in a row the host could not answer, for the wait before the next.
  const failures = useRef(0)

  useEffect(() => {
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const token = newToken()
    // Another grant than the session was last open under: what was read under it is not this one's.
    if (openings.begin(sessionId, token, grantId, Date.now())) {
      sessions.update(sessionId, unread)
    }
    // An event that arrives before the open is answered is newer than the answer.
    let heard = false
    const listening = port.onStanding((event) => {
      if (event.opening !== token || event.session_id !== sessionId) return
      heard = true
      openings.apply(sessionId, token, event.standing, Date.now())
    })
    // The open is asked once the listener is registered, so no change falls between the two.
    listening
      .then(() => {
        if (!live) return undefined
        return port.openSession({ sessionId, grantId, opening: token }).then(
          (standing) => {
            failures.current = 0
            if (live && !heard) openings.apply(sessionId, token, standing, Date.now())
          },
          (failure: unknown) => {
            if (!live || heard) return
            const code = failureCode(failure) ?? 'REQUEST_FAILED'
            if (UNABLE_NOW.has(code)) {
              // The host could not be reached or could not say yet. That is contact being lost,
              // not a refusal, and the host is asked again.
              openings.apply(
                sessionId,
                token,
                { state: 'reconnecting', reason: failureWords(failure) },
                Date.now()
              )
              const wait = retryAfterMs(failures.current)
              failures.current += 1
              timer = setTimeout(() => {
                setAttempt((count) => count + 1)
              }, wait)
              return
            }
            failures.current = 0
            openings.apply(
              sessionId,
              token,
              { state: 'refused', code, message: failureWords(failure) },
              Date.now()
            )
          }
        )
      })
      .catch(() => undefined)
    return () => {
      live = false
      clearTimeout(timer)
      void listening.then((stop) => {
        stop()
      }, () => undefined)
      openings.end(sessionId, token)
      // Left even when the open has not been answered: native code lets go of what it opens.
      void port.leaveSession(sessionId, token).catch(() => undefined)
    }
  }, [port, openings, sessions, sessionId, grantId, attempt])

  const subscribe = useCallback(
    (listener: () => void) => openings.subscribe(listener),
    [openings]
  )
  const record = useSyncExternalStore(subscribe, () => openings.get(sessionId))
  const retry = useCallback(() => {
    setAttempt((count) => count + 1)
  }, [])
  return { record, retry }
}
