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

import { useEffect, useState } from 'react'

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

/**
 * Reads the host's description of each session listed, as the list is shown.
 *
 * A read that fails leaves its row as it was, because every row has its directory to show. The
 * newest listing is the one whose rows are read: a read begun for sessions that are no longer
 * listed, or answering after the list has gone, changes nothing. The sessions are read again each
 * time `listing` is a new list, so a row follows what the host has published since the last one.
 */
export function useDescriptions(
  port: HostPort,
  sessionIds: readonly string[],
  listing: unknown
): ReadonlyMap<string, Described> {
  const [described, setDescribed] = useState<ReadonlyMap<string, Described>>(new Map())
  const wanted = sessionIds.join(',')

  useEffect(() => {
    let current = true
    const queue = wanted.length === 0 ? [] : wanted.split(',')
    const next = (): void => {
      const sessionId = queue.shift()
      if (sessionId === undefined || !current) return
      ask(() => port.sessionDescribe({ session_id: sessionId }))
        .then((answer) => {
          if (!current) return
          setDescribed((held) => new Map(held).set(sessionId, answer))
        })
        .catch(() => undefined)
        .finally(next)
    }
    for (let started = 0; started < READS_AT_ONCE; started += 1) next()
    return () => {
      current = false
    }
  }, [port, wanted, listing])

  return described
}
