/**
 * What this connection may do, as native code reports it.
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

/**
 * The rights the shell heard, for the views under it: null while none are known, and undefined
 * outside a shell.
 */
export const ShellRights = createContext<readonly ActionRight[] | null | undefined>(undefined)

/** The rights the connection holds now, or null while they are not known. */
export function useConnectionRights(): readonly ActionRight[] | null {
  const shared = useContext(ShellRights)
  const { port } = useApp()
  const [own, setOwn] = useState<readonly ActionRight[] | null>(null)
  useEffect(() => {
    if (shared !== undefined) return
    return follow(
      (listener) => port.onConnection(listener),
      () => port.connectionState(),
      (state) => {
        setOwn(state.connected ? state.rights : null)
      },
      () => {
        setOwn(null)
      }
    )
  }, [port, shared])
  return shared === undefined ? own : shared
}
