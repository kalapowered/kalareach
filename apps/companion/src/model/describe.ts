/**
 * What a session row says it is, from what the host says about it.
 *
 * Every host has a title for every session: a pinned name, or the deterministic one made from its
 * directory, repository and application. A host that runs a model may also have a generated line
 * about what the session is doing now, and that line is always labelled generated, because it is
 * text a model wrote and not a fact the host observed. How current it is travels with it, so a row
 * never implies that a session is doing what it was doing five minutes ago: a line that has been
 * overtaken says so beside the line.
 *
 * Nothing here asks for a description to be made, or for one to be made sooner. The host's answer
 * is what a row shows, and a row the host has not answered yet shows what every host knows: the
 * directory the session is in.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import type { SessionDescribeResult, SessionListResult } from '@kalareach/protocol'

import { readOnCadence, type Cadence } from '../app/cadence'
import { ask } from '../mobile/model/call'
import type { HostPort } from '../host/port'

/** What a row has been told about one session. */
export type Described = SessionDescribeResult

/** The label a title carries, where it carries one. A deterministic title carries none. */
export function sourceLabel(described: Described | undefined): 'Generated' | 'Pinned' | null {
  switch (described?.source) {
    case 'generated':
      return 'Generated'
    case 'pinned':
      return 'Pinned'
    default:
      return null
  }
}

/**
 * The activity line, when there is one.
 *
 * Only a generated description has one, and a line the host sent beside any other source is not
 * shown: nothing but a generated description says what a session is doing.
 */
export function activityLine(described: Described | undefined): string | null {
  if (described === undefined || described.source !== 'generated') return null
  const line = described.activity_text?.trim() ?? ''
  return line.length > 0 ? line : null
}

/**
 * What a generated line that is not current says about itself, or nothing when it is current or
 * there is no line.
 */
export function freshnessNote(described: Described | undefined): string | null {
  if (activityLine(described) === null) return null
  switch (described?.freshness) {
    case 'delayed':
      return 'A newer description is waiting'
    case 'stale':
      return 'Out of date: the session has moved on'
    default:
      return null
  }
}

/**
 * The application in the foreground of a session, in words: a root shell at its prompt is the
 * shell, and anything else the host reports is an agent.
 */
export function applicationName(session: SessionListResult['sessions'][number]): 'Shell' | 'Agent' {
  return session.application_state === null || session.application_state === 'shell_ready'
    ? 'Shell'
    : 'Agent'
}

/** A directory's own name: its last component, which every host can say of a session. */
export function directoryName(cwd: string): string {
  return cwd.split('/').filter(Boolean).pop() ?? cwd
}

/** The title a row shows: the host's, or the directory's own name until the host has answered. */
export function shownTitle(directoryName: string, described: Described | undefined): string {
  const title = described?.title.trim() ?? ''
  return title.length > 0 ? title : directoryName
}

/** How many descriptions are read at one time. A list of sessions is short; the bound is the host's. */
const READS_AT_ONCE = 4

/**
 * How long before the rows shown are asked about again, in milliseconds: the host's cooldown, under
 * which it describes no session twice. A row left on a screen is read again at that pace, because a
 * line that was current when it was read has not stopped being the host's to age.
 */
const READ_AGAIN_MS = 30_000

/** How far beyond the edge of the list's screen a row still counts as shown, in pixels: about two rows. */
const SHOWN_MARGIN_PX = 160

/** What a screen's reads have done: which sessions were asked about, and which are still to be. */
interface Reads {
  readonly port: HostPort
  /** The sessions asked about in the round that is running, so a session is asked once in it. */
  readonly asked: Set<string>
  /** The sessions waiting to be asked about or waiting for the host, whichever round asked. */
  readonly pending: Set<string>
  readonly queue: string[]
  running: number
  /** False once another host or the screen's going has replaced these reads. */
  live: boolean
  /** Callers waiting for every read to have answered. */
  readonly settled: (() => void)[]
}

function startReads(port: HostPort): Reads {
  return { port, asked: new Set(), pending: new Set(), queue: [], running: 0, live: true, settled: [] }
}

/**
 * Lets the callers waiting for a round go once every session of it has been asked about. A read
 * that has not answered does not hold the round: the sessions that did answer are read again at the
 * next one, and the one that has not is left as it is until it does.
 */
function release(reads: Reads): void {
  if (reads.queue.length > 0 && reads.live) return
  for (const done of reads.settled.splice(0)) done()
}

/** Whether the page is hidden, as a minimised window or a phone app in the background is. */
function hidden(): boolean {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden'
}

/** Starts reads from the queue until `READS_AT_ONCE` are waiting for the host, none while hidden. */
function pump(reads: Reads, answered: (sessionId: string, answer: Described) => void): void {
  while (reads.live && !hidden() && reads.running < READS_AT_ONCE) {
    const sessionId = reads.queue.shift()
    if (sessionId === undefined) return
    reads.running += 1
    ask(() => reads.port.sessionDescribe({ session_id: sessionId }))
      .then((answer) => {
        if (reads.live) answered(sessionId, answer)
      })
      .catch(() => undefined)
      .finally(() => {
        reads.running -= 1
        reads.pending.delete(sessionId)
        pump(reads, answered)
        release(reads)
      })
  }
}

/**
 * Asks about each of `ids` that has not been asked about in this round. A session whose read from
 * an earlier round has not answered is not asked about twice: that read's answer serves.
 */
function want(
  reads: Reads,
  ids: readonly string[],
  answered: (sessionId: string, answer: Described) => void
): void {
  for (const sessionId of ids) {
    if (reads.asked.has(sessionId)) continue
    reads.asked.add(sessionId)
    if (reads.pending.has(sessionId)) continue
    reads.pending.add(sessionId)
    reads.queue.push(sessionId)
  }
  pump(reads, answered)
}

/**
 * Reads the host's description of each session in `ids`, and again as long as the list is shown.
 *
 * `ids` is the sessions a person can see (or is searching among), not every session listed: the
 * host describes what is asked about, and a long list is asked about as it is scrolled. A session
 * is asked about once in a round. A round starts when the list is first shown, when `listing` is a
 * new list, and a cooldown after the last read of the one before has answered, while the page is
 * shown (`readOnCadence`), so a row follows what the host has published and says when its line has
 * aged. At most four reads wait for the host at any time, none starts while the page is hidden, a
 * slow answer is shown when it comes, and a session whose read is still on its way is not asked
 * about again; a read that never answers holds back only its own row. A read that fails leaves its
 * row as it was, because every row has its directory to show. A read for another host, or
 * answering after the screen has gone, changes nothing.
 */
export function useDescriptions(
  port: HostPort,
  ids: readonly string[],
  listing: unknown
): ReadonlyMap<string, Described> {
  const [described, setDescribed] = useState<ReadonlyMap<string, Described>>(new Map())
  const reading = useRef<{ readonly reads: Reads; readonly cadence: Cadence } | null>(null)
  const latest = useRef(ids)
  const listed = useRef(listing)
  const key = ids.join(',')
  useEffect(() => {
    latest.current = ids
  })

  const answered = useCallback((sessionId: string, answer: Described): void => {
    setDescribed((held) => new Map(held).set(sessionId, answer))
  }, [])

  // The reads of one host, and the rounds that start them. Another host starts them over.
  useEffect(() => {
    const reads = startReads(port)
    // A round ends when every session of it has been asked about, or after a cooldown if the host
    // has not answered the ones it holds: one unanswered read never stops the rounds after it.
    const cadence = readOnCadence(
      () =>
        new Promise<void>((resolve) => {
          const bound = setTimeout(done, READ_AGAIN_MS)
          function done(): void {
            clearTimeout(bound)
            const at = reads.settled.indexOf(done)
            if (at >= 0) reads.settled.splice(at, 1)
            resolve()
          }
          reads.asked.clear()
          want(reads, latest.current, answered)
          reads.settled.push(done)
          release(reads)
        }),
      READ_AGAIN_MS
    )
    reading.current = { reads, cadence }
    cadence.now()
    // Reads that were waiting for the page to be shown start when it is.
    const shown = (): void => {
      pump(reads, answered)
    }
    document.addEventListener('visibilitychange', shown)
    return () => {
      document.removeEventListener('visibilitychange', shown)
      reads.live = false
      cadence.stop()
      release(reads)
      reading.current = null
    }
  }, [port, answered])

  // A new list is read at once.
  useEffect(() => {
    if (listed.current === listing) return
    listed.current = listing
    reading.current?.cadence.now()
  }, [listing])

  // A row that has come near the screen is read at once.
  useEffect(() => {
    if (reading.current !== null) want(reading.current.reads, latest.current, answered)
  }, [key, answered])

  return described
}

/** The nearest ancestor that scrolls up and down, or null where the page itself does. */
function scrollParent(element: Element): Element | null {
  for (let node = element.parentElement; node !== null; node = node.parentElement) {
    const { overflowY } = getComputedStyle(node)
    if (overflowY === 'auto' || overflowY === 'scroll') return node
  }
  return null
}

/**
 * Which session rows are on the screen, or within a small margin of it.
 *
 * `track` goes on each row as its `ref`, and the row names its session in `data-session`. The
 * margin is measured from the edge of whatever scrolls the list, so a row about to come into view
 * has been asked about by the time it does.
 */
export function useOnScreen(): {
  readonly onScreen: ReadonlySet<string>
  readonly track: (element: HTMLElement | null) => (() => void) | undefined
} {
  const [onScreen, setOnScreen] = useState<ReadonlySet<string>>(new Set())
  const observers = useRef(new Map<Element | null, IntersectionObserver>())

  const track = useCallback((element: HTMLElement | null) => {
    const sessionId = element?.dataset.session
    if (element === null || sessionId === undefined) return undefined
    const root = scrollParent(element)
    const observer =
      observers.current.get(root) ??
      new IntersectionObserver(
        (entries) => {
          setOnScreen((held) => {
            const next = new Set(held)
            for (const entry of entries) {
              const id = (entry.target as HTMLElement).dataset.session
              if (id === undefined) continue
              if (entry.isIntersecting) next.add(id)
              else next.delete(id)
            }
            return next
          })
        },
        { root, rootMargin: `${String(SHOWN_MARGIN_PX)}px 0px` }
      )
    observers.current.set(root, observer)
    observer.observe(element)
    return () => {
      observer.unobserve(element)
      setOnScreen((held) => {
        if (!held.has(sessionId)) return held
        const next = new Set(held)
        next.delete(sessionId)
        return next
      })
    }
  }, [])

  useEffect(() => {
    const held = observers.current
    return () => {
      for (const observer of held.values()) observer.disconnect()
      held.clear()
    }
  }, [])

  return { onScreen, track }
}
