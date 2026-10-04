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

import type { SessionDescribeResult } from '@kalareach/protocol'

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

/** How far beyond the edge of the list's screen a row still counts as shown, in pixels: about two rows. */
const SHOWN_MARGIN_PX = 160

/** What a listing's reads have done: which sessions were asked about, and which are still to be. */
interface Reads {
  readonly port: HostPort
  readonly listing: unknown
  readonly asked: Set<string>
  readonly queue: string[]
  running: number
  /** False once a newer listing, another host or the screen's going has replaced these reads. */
  live: boolean
}

/** Starts reads from the queue until `READS_AT_ONCE` are waiting for the host. */
function pump(reads: Reads, answered: (sessionId: string, answer: Described) => void): void {
  while (reads.live && reads.running < READS_AT_ONCE) {
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
        pump(reads, answered)
      })
  }
}

/**
 * Reads the host's description of each session in `wanted`, once for each listing.
 *
 * `wanted` is the sessions a person can see (or is searching among), not every session listed: the
 * host describes what is asked about, and a long list is asked about as it is scrolled. A session
 * is asked about once for a listing, and again when `listing` is a new list, so a row follows what
 * the host has published since the last one. A read that fails leaves its row as it was, because
 * every row has its directory to show. The newest listing is the one whose rows are read: a read
 * begun for an older one, or answering after the screen has gone, changes nothing.
 */
export function useDescriptions(
  port: HostPort,
  wanted: readonly string[],
  listing: unknown
): ReadonlyMap<string, Described> {
  const [described, setDescribed] = useState<ReadonlyMap<string, Described>>(new Map())
  const reads = useRef<Reads | null>(null)
  const key = wanted.join(',')

  useEffect(() => {
    let current = reads.current
    if (current === null || current.port !== port || current.listing !== listing) {
      if (current !== null) current.live = false
      current = { port, listing, asked: new Set(), queue: [], running: 0, live: true }
      reads.current = current
    }
    for (const sessionId of key.length === 0 ? [] : key.split(',')) {
      if (current.asked.has(sessionId)) continue
      current.asked.add(sessionId)
      current.queue.push(sessionId)
    }
    pump(current, (sessionId, answer) => {
      setDescribed((held) => new Map(held).set(sessionId, answer))
    })
  }, [port, listing, key])

  useEffect(
    () => () => {
      if (reads.current !== null) reads.current.live = false
      reads.current = null
    },
    []
  )

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
