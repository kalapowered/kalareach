/**
 * Reading the host's saved launch commands while Settings shows them.
 *
 * The list is read when the section is shown, when the connection changes, and on a cadence, and a
 * write's own answer is adopted at once. A read that started before an adopted answer is never
 * shown over it. A host that does not serve the list, and a connection that may not read it, are
 * remembered until the connection changes, and asked no more.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import type { ShellLaunchCommandsListResult } from '@kalareach/protocol'

import { readOnCadence } from './cadence'
import { ask } from '../mobile/model/call'
import { failureMessage, watch, type HostPort } from '../host/port'

/** How long Settings waits after a read of the list has answered before it reads again. */
export const SAVED_COMMANDS_CADENCE_MS = 5000

/** What Settings knows of the saved launch commands. */
export type SavedCommands =
  /** No read has answered yet. */
  | { readonly state: 'unread' }
  /**
   * The list, and why the newest read of it failed where one did: the older list stays beside the
   * failure.
   */
  | {
      readonly state: 'served'
      readonly list: ShellLaunchCommandsListResult
      readonly unread: string | null
    }
  /** The host is of a release that does not serve the list. */
  | { readonly state: 'not_served' }
  /** This connection may not read the list. */
  | { readonly state: 'refused' }
  /** The list has not been read, and the newest read failed. */
  | { readonly state: 'failed'; readonly unread: string }

/** What the hook gives. */
export interface SavedCommandsReads {
  readonly saved: SavedCommands
  /** Reads now, or as soon as the read on its way has answered. */
  readonly again: () => void
  /** Takes a list that a write answered with, as the newest. */
  readonly adopt: (list: ShellLaunchCommandsListResult) => void
}

/** Reads the saved launch commands while the caller is shown, or nothing where `read` is false. */
export function useSavedCommands(
  port: HostPort,
  read: boolean,
  cadenceMs: number = SAVED_COMMANDS_CADENCE_MS
): SavedCommandsReads {
  const [saved, setSaved] = useState<SavedCommands>({ state: 'unread' })
  const again = useRef<() => void>(() => undefined)
  const started = useRef(0)
  const adoptedAfter = useRef(0)

  useEffect(() => {
    if (!read) return
    let watching: ReturnType<typeof watch> | null = null
    let remembered = false
    // `connection` counts the changes of the connection: an answer to a read that began on an
    // earlier connection says nothing of this one, so it neither shows a list nor remembers a
    // refusal that would stop the reads.
    let connection = 0
    const cadence = readOnCadence(() => {
      const current = watching?.read() ?? null
      if (current === null || remembered) return Promise.resolve()
      started.current += 1
      const number = started.current
      const asked = connection
      return ask(() => port.launchCommands()).then(
        (reading) => {
          if (!current() || number <= adoptedAfter.current || asked !== connection) return
          if (reading.state === 'served') {
            setSaved({ state: 'served', list: reading.list, unread: null })
          } else {
            remembered = true
            setSaved({ state: reading.state })
          }
        },
        (failure: unknown) => {
          if (!current() || number <= adoptedAfter.current) return
          const unread = failureMessage(failure)
          setSaved((was) =>
            was.state === 'served' ? { ...was, unread } : { state: 'failed', unread }
          )
        }
      )
    }, cadenceMs)
    watching = watch(
      [
        port.onConnection((state) => {
          connection += 1
          remembered = false
          if (state.connected) cadence.now()
        })
      ],
      () => {
        cadence.now()
      },
      () => undefined
    )
    again.current = cadence.now
    const watched = watching
    return () => {
      cadence.stop()
      watched.stop()
      again.current = () => undefined
    }
  }, [port, read, cadenceMs])

  const refresh = useCallback(() => {
    again.current()
  }, [])
  const adopt = useCallback((list: ShellLaunchCommandsListResult) => {
    adoptedAfter.current = started.current
    setSaved({ state: 'served', list, unread: null })
  }, [])
  return { saved: read ? saved : { state: 'unread' }, again: refresh, adopt }
}
