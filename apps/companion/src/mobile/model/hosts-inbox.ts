/**
 * The hosts the inbox reads beside the one in use.
 *
 * The inbox is one across hosts. The host in use is read with the page's own reads; every other host
 * this phone is paired with is visited by native code over a connection of its own. What native code
 * holds of each arrives here whole: its inbox and its sessions' numbers, as the owner last read them.
 * How contact with each stands, that it answered and refused or that this phone is out of contact
 * with it and since when, is the connection's state, which each visit changes as it ends. The visits
 * are read on a cadence while the inbox is shown, and nowhere else, so nothing is asked of a host the
 * person is not looking at.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { readOnCadence } from '../../app/cadence'
import { useApp } from '../../app/state'
import { watch, type HostInbox, type OtherHost } from '../../host/port'
import { ATTENTION_READ_CADENCE_MS } from '../../model/attention'

/** The other hosts as the last visit found them, and who is in use. */
export interface OtherHosts {
  /**
   * What native code held of each host that is not in use when the last pass ended, with the inbox
   * it last read of each; null before the first answer. A host this phone has forgotten since, or is
   * using now, is not among them, whatever the pass found before the page knew.
   */
  readonly hosts: readonly HostInbox[] | null
  /**
   * How contact with each host that is not in use stands, as the connection's state last told it: a
   * host that holds no outcome is not listed.
   */
  readonly contacts: readonly OtherHost[]
  /**
   * The host in use, by reference and name, and how many hosts this phone is paired with; null
   * before the first look, and the host is null while none is in use.
   */
  readonly paired: {
    readonly inUseReference: string | null
    readonly inUseName: string | null
    readonly count: number
    /** Every host this phone is paired with, by reference. */
    readonly references: ReadonlySet<string>
  } | null
  /** Looks again now, as after a change of the host in use. */
  readonly again: () => void
}

/** Follows the other paired hosts' inboxes while the inbox is shown. */
export function useOtherHosts(): OtherHosts {
  const { port } = useApp()
  const [hosts, setHosts] = useState<readonly HostInbox[] | null>(null)
  const [contacts, setContacts] = useState<readonly OtherHost[]>([])
  const [paired, setPaired] = useState<OtherHosts['paired']>(null)
  const nudge = useRef<() => void>(() => undefined)

  useEffect(() => {
    let live = true
    // Which host is in use is its own read, on a cadence of its own: a host that answers its visit
    // slowly holds up the visits, and must not hold up the news of which host is in use.
    const looking = readOnCadence(() => {
      return port.pairingView().then(
        (view) => {
          if (!live) return
          const listed = view.hosts
          const using = listed.find((each) => each.in_use)
          setPaired({
            inUseReference: using?.reference ?? null,
            inUseName: using?.name ?? null,
            count: listed.length,
            references: new Set(listed.map((each) => each.reference))
          })
        },
        () => undefined
      )
    }, ATTENTION_READ_CADENCE_MS)
    const visiting = readOnCadence(() => {
      return port.inboxHosts().then(
        (answer) => {
          if (!live) return
          setHosts(answer.hosts)
        },
        () => undefined
      )
    }, ATTENTION_READ_CADENCE_MS)
    const both = () => {
      looking.now()
      visiting.now()
    }
    // The host in use is the connection's: a change of it is looked at at once, as the inbox's own
    // read is, and not at the next round.
    // The first pass starts when the registration completes, so the connection it finds is the one
    // the pass is made for.
    const connection = watch([port.onConnection(both)], both)
    // Contact with the other hosts is told by the connection's feed as each visit ends.
    const following = port.watchConnection(
      (state) => {
        if (live) setContacts(state.others)
      },
      () => undefined
    )
    nudge.current = both
    return () => {
      live = false
      looking.stop()
      visiting.stop()
      connection.stop()
      following()
      nudge.current = () => undefined
    }
  }, [port])

  const again = useCallback(() => {
    nudge.current()
  }, [])
  // A visit's answer is as old as the visit: the person may have forgotten the host, or begun to use
  // it, since. What the page reads of the pairing is newer, so the answers are weighed against it
  // before anything is shown, and a host it does not list as one of the others shows nothing.
  const current = useMemo(() => {
    if (paired === null) return { hosts, contacts }
    const others = (reference: string) =>
      paired.references.has(reference) && reference !== paired.inUseReference
    return {
      hosts: hosts === null ? null : hosts.filter((each) => others(each.reference)),
      contacts: contacts.filter((each) => others(each.reference))
    }
  }, [hosts, contacts, paired])
  return { hosts: current.hosts, contacts: current.contacts, paired, again }
}
