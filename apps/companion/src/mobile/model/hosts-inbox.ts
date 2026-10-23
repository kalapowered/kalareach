/**
 * The hosts the inbox reads beside the one in use.
 *
 * The inbox is one across hosts. The host in use is read with the page's own reads; every other host
 * this phone is paired with is visited by native code over a connection of its own, and what each
 * said arrives here whole: its inbox and its sessions' numbers, or that this phone is out of contact
 * with it and since when. The visits are read on a cadence while the inbox is shown, and nowhere
 * else, so nothing is asked of a host the person is not looking at.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import { readOnCadence } from '../../app/cadence'
import { useApp } from '../../app/state'
import { watch, type HostInbox } from '../../host/port'
import { ATTENTION_READ_CADENCE_MS } from '../../model/attention'

/** The other hosts as the last visit found them, and who is in use. */
export interface OtherHosts {
  /** What the last visit found of each host that is not in use; null before the first answer. */
  readonly hosts: readonly HostInbox[] | null
  /**
   * The last time each of those hosts answered, by its reference, kept while it does not: what a
   * host out of contact was last read to hold, which is said to be from then.
   */
  readonly lastRead: ReadonlyMap<string, HostInbox>
  /**
   * The host in use, by reference and name, and how many hosts this phone is paired with; null
   * before the first look, and the host is null while none is in use.
   */
  readonly paired: {
    readonly inUseReference: string | null
    readonly inUseName: string | null
    readonly count: number
  } | null
  /** Looks again now, as after a change of the host in use. */
  readonly again: () => void
}

/** Follows the other paired hosts' inboxes while the inbox is shown. */
export function useOtherHosts(): OtherHosts {
  const { port } = useApp()
  const [hosts, setHosts] = useState<readonly HostInbox[] | null>(null)
  const [lastRead, setLastRead] = useState<ReadonlyMap<string, HostInbox>>(new Map())
  const [paired, setPaired] = useState<OtherHosts['paired']>(null)
  const nudge = useRef<() => void>(() => undefined)

  useEffect(() => {
    let live = true
    const cadence = readOnCadence(async () => {
      // Who is in use is known as soon as the pairing screen's view answers, whatever a slow host
      // has not said yet.
      const looked = port.pairingView().then(
        (view) => {
          if (!live) return
          const listed = view.hosts
          const using = listed.find((each) => each.in_use)
          setPaired({
            inUseReference: using?.reference ?? null,
            inUseName: using?.name ?? null,
            count: listed.length
          })
        },
        () => undefined
      )
      const visited = port.inboxHosts().then(
        (visits) => {
          if (!live) return
          setHosts(visits)
          // A host this phone no longer visits keeps nothing; one that answered replaces what was
          // kept of it; one that did not leaves it as it was.
          setLastRead((held) => {
            const next = new Map<string, HostInbox>()
            for (const each of visits) {
              const kept = each.state === 'read' ? each : held.get(each.reference)
              if (kept !== undefined) next.set(each.reference, kept)
            }
            return next
          })
        },
        () => undefined
      )
      await Promise.all([looked, visited])
    }, ATTENTION_READ_CADENCE_MS)
    // The host in use is the connection's: a change of it is looked at at once, as the inbox's own
    // read is, and not at the next round.
    const connection = watch([
      port.onConnection(() => {
        cadence.now()
      })
    ])
    nudge.current = cadence.now
    cadence.now()
    return () => {
      live = false
      cadence.stop()
      connection.stop()
      nudge.current = () => undefined
    }
  }, [port])

  const again = useCallback(() => {
    nudge.current()
  }, [])
  return { hosts, lastRead, paired, again }
}
