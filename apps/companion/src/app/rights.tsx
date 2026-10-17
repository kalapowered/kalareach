/**
 * What this connection may do, and whether its host is one this device is paired with, as native
 * code reports it.
 *
 * A control that turns on a right is offered only once the right is known: until the connection has
 * said what it may do, and whenever it is out of contact, the answer is null and nothing that needs
 * a right is offered. The host checks every right again when an action arrives.
 *
 * The application's shell already follows the connection, and hands what it heard to every view
 * under it, so no view reads the connection a second time. A view shown without a shell around it
 * follows the connection itself.
 */

import { createContext, useContext, useEffect, useState } from 'react'

import type { ActionRight } from '@kalareach/protocol'

import { useApp } from './state'
import { follow } from '../host/port'

/** What the live connection may do, and whether its host is paired with this device. */
export interface HeldConnection {
  /** The rights it holds, or null while they are not known. */
  readonly rights: readonly ActionRight[] | null
  /** True while the host is one this device is paired with, not the one on this computer. */
  readonly paired: boolean
}

const NOTHING_KNOWN: HeldConnection = { rights: null, paired: false }

/**
 * What the shell heard, for the views under it: nothing known while the connection has not
 * answered, and undefined outside a shell.
 */
export const ShellConnection = createContext<HeldConnection | undefined>(undefined)

/** What the connection holds now. */
export function useHeldConnection(): HeldConnection {
  const shared = useContext(ShellConnection)
  const { port, rememberRights } = useApp()
  const [own, setOwn] = useState<HeldConnection>(NOTHING_KNOWN)
  useEffect(() => {
    if (shared !== undefined) return
    return follow(
      (listener) => port.onConnection(listener),
      () => port.connectionState(),
      (state) => {
        if (state.connected && state.rights !== null) rememberRights(state.rights)
        setOwn(
          state.connected ? { rights: state.rights, paired: state.paired } : NOTHING_KNOWN
        )
      },
      () => {
        setOwn(NOTHING_KNOWN)
      }
    )
  }, [port, shared, rememberRights])
  return shared === undefined ? own : shared
}

/** The rights the connection holds now, or null while they are not known. */
export function useConnectionRights(): readonly ActionRight[] | null {
  return useHeldConnection().rights
}

/**
 * The rights the connection last held, kept while contact is out.
 *
 * A control that only keeps what a person typed, as an answer to a question does while the worker
 * cannot be reached, is offered on the rights the host last reported: the host checks them again
 * when the answer is sent. Until a connection has reported any, they are not known and null.
 */
export function useLastKnownRights(): readonly ActionRight[] | null {
  const now = useConnectionRights()
  const { lastRights } = useApp()
  // Held above every screen, so a screen opened after contact ended has them too: the shell notes
  // them as it hears the connection, and a view with no shell around it notes them itself.
  return now ?? lastRights
}
