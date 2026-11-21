/**
 * The hosts the inbox reads beside the one in use.
 *
 * The inbox is one across hosts. The host in use is read with the page's own reads; every other host
 * this phone is paired with is visited by native code over a connection of its own. How contact with
 * each stands, that it answered and refused or that this phone is out of contact with it and since
 * when, is the connection's state, which the owner changes as each visit ends, and every row of
 * contact is drawn from that state alone. What native code holds of each host's inbox arrives from the
 * visits' pass, on a cadence while the inbox is shown and nowhere else, so nothing is asked of a host
 * the person is not looking at.
 *
 * What a pass answers is kept as a cache for each host: the inbox, the epoch it was read under and the
 * order it was read in among every read of every host. A cache is replaced by a read of another epoch
 * whatever its order, because a new pairing's first read is read after the old one and is still below
 * it only when the owner's counter is per host; by a read of the same epoch only with a higher order,
 * so a late answer of an earlier pass changes nothing; and it is shown only while the host's epoch in
 * the connection's state is the one it was read under. A cache of a host the state names neither as
 * the host in use nor among the others is dropped, and a host paired again starts with none.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { readOnCadence } from '../../app/cadence'
import { useApp } from '../../app/state'
import { watch, type ConnectionState, type HostInbox, type OtherHost } from '../../host/port'
import { ATTENTION_READ_CADENCE_MS } from '../../model/attention'

/** What a pass last answered for one host, and what it was read under. */
interface Cached {
  readonly epoch: number
  readonly serial: number
  readonly read: HostInbox
}

/** The other hosts as the connection's state says, with what each pass last read of them. */
export interface OtherHosts {
  /**
   * The latest state of the connection the page has taken in, or null before it has one. Every row
   * of contact, for the host in use and for the others, is drawn from it.
   */
  readonly latest: ConnectionState | null
  /**
   * What native code holds of each host that is not in use, from the cache of each, while the host
   * is one of the others and its epoch is the one the cache was read under; null before the first
   * answer of a pass.
   */
  readonly hosts: readonly HostInbox[] | null
  /** How contact with each host that is not in use stands; a host that holds no outcome is not listed. */
  readonly contacts: readonly OtherHost[]
  /** Looks again now, as after a change of the host in use. */
  readonly again: () => void
}

/** Whether a row replaces what is cached: another epoch always, the same epoch only with a higher order. */
function replaces(row: Cached, held: Cached | undefined): boolean {
  return held === undefined || row.epoch !== held.epoch || row.serial > held.serial
}

/** The caches left once every host the state names neither as in use nor among the others is dropped. */
function pruned(caches: ReadonlyMap<string, Cached>, state: ConnectionState | null): ReadonlyMap<string, Cached> {
  // Nothing is dropped before the page has a state to say which hosts there are.
  if (state === null) return caches
  const named = new Set(state.others.map((each) => each.reference))
  if (state.host?.kind === 'paired') named.add(state.host.reference)
  const kept = [...caches].filter(([reference]) => named.has(reference))
  return kept.length === caches.size ? caches : new Map(kept)
}

/** The caches with what a pass answered taken in. */
function taken(caches: ReadonlyMap<string, Cached>, rows: readonly HostInbox[]): ReadonlyMap<string, Cached> {
  const next = new Map(caches)
  for (const row of rows) {
    if (row.result === null || row.read_serial === null) continue
    const read: Cached = { epoch: row.inbox_epoch, serial: row.read_serial, read: row }
    if (replaces(read, next.get(row.reference))) next.set(row.reference, read)
  }
  return next
}

/** Follows the other paired hosts' inboxes while the inbox is shown. */
export function useOtherHosts(): OtherHosts {
  const { port } = useApp()
  const [latest, setLatest] = useState<ConnectionState | null>(null)
  const [caches, setCaches] = useState<ReadonlyMap<string, Cached>>(new Map())
  const [answered, setAnswered] = useState(false)
  const nudge = useRef<() => void>(() => undefined)

  useEffect(() => {
    let live = true
    const visiting = readOnCadence(() => {
      return port.inboxHosts().then(
        (answer) => {
          if (!live) return
          // A cache is dropped by the state the page holds when the answer arrives, which is newer
          // than the pass that was asked, so a host forgotten since is not put back by its answer.
          const state = port.connectionLatest()
          setCaches((held) => pruned(taken(held, answer.hosts), state))
          setAnswered(true)
        },
        () => undefined
      )
    }, ATTENTION_READ_CADENCE_MS)
    // The pass starts when the registration completes, so the connection it finds is the one it is
    // made for, and again for each change of what a read depends on.
    const connection = watch([port.onConnection(visiting.now)], visiting.now)
    const following = port.watchConnection(
      (state) => {
        if (!live) return
        setCaches((held) => pruned(held, state))
        setLatest(state)
      },
      () => undefined
    )
    nudge.current = visiting.now
    return () => {
      live = false
      visiting.stop()
      connection.stop()
      following()
      nudge.current = () => undefined
    }
  }, [port])

  const again = useCallback(() => {
    nudge.current()
  }, [])

  const hosts = useMemo<readonly HostInbox[] | null>(() => {
    if (!answered || latest === null) return null
    const shown: HostInbox[] = []
    for (const other of latest.others) {
      if (other.contact.state === 'refused') continue
      if (latest.host?.kind === 'paired' && latest.host.reference === other.reference) continue
      const held = caches.get(other.reference)
      if (held !== undefined && held.epoch === other.inbox_epoch) shown.push(held.read)
    }
    return shown
  }, [answered, latest, caches])

  const contacts = useMemo(
    () =>
      latest === null
        ? []
        : latest.others.filter(
            (each) => !(latest.host?.kind === 'paired' && latest.host.reference === each.reference)
          ),
    [latest]
  )
  return { latest, hosts, contacts, again }
}
