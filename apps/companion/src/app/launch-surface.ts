/**
 * Reading a session's launch surface while a view of it is shown.
 *
 * The editor's state changes with no event to say so, so the view reads the surface again on a
 * cadence while the page is shown, at once when the page is shown again, on a change of connection,
 * when the person asks, and after a press. It never reads twice at once, and it shows an answer only
 * while it belongs to the newest read and the watch that started it is still running.
 *
 * The window between a change and the next read is one cadence long. The guarantee is the press, not
 * this read: a button lit a moment too long quotes a prompt the session then refuses.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import { readOnCadence } from './cadence'
import { ask } from '../mobile/model/call'
import { failureMessage, watch, type HostPort, type LaunchSurfaceReading } from '../host/port'

/** How long the view waits after a read has answered before it reads again. */
export const LAUNCH_SURFACE_CADENCE_MS = 2000

/** What a view has read of one launch surface. */
export interface LaunchSurfaceReads {
  /** The newest answer, or null before the first and after a read that failed. */
  readonly reading: LaunchSurfaceReading | null
  /** Why the newest read failed, in words, or null. */
  readonly unread: string | null
  /** Reads now, or as soon as the read on its way has answered. */
  readonly again: () => void
}

/**
 * Reads with `read` while the caller is shown. `scope` names what is read, so an answer for another
 * session or another opening of the view is never shown under this one. A null `read` reads nothing:
 * the view it would read on is not open yet.
 */
export function useLaunchSurface(
  port: HostPort,
  scope: string,
  read: (() => Promise<LaunchSurfaceReading>) | null,
  cadenceMs = LAUNCH_SURFACE_CADENCE_MS
): LaunchSurfaceReads {
  const [held, setHeld] = useState<{
    readonly scope: string
    readonly reading: LaunchSurfaceReading | null
    readonly unread: string | null
  } | null>(null)
  const again = useRef<() => void>(() => undefined)

  useEffect(() => {
    if (read === null) return
    let watching: ReturnType<typeof watch> | null = null
    const cadence = readOnCadence(() => {
      const current = watching?.read() ?? null
      if (current === null) return Promise.resolve()
      return ask(read).then(
        (reading) => {
          if (current()) setHeld({ scope, reading, unread: null })
        },
        (failure: unknown) => {
          if (current()) setHeld({ scope, reading: null, unread: failureMessage(failure) })
        }
      )
    }, cadenceMs)
    watching = watch(
      [
        port.onConnection((state) => {
          if (state.connected) cadence.now()
        })
      ],
      cadence.now,
      (failure) => {
        setHeld({ scope, reading: null, unread: failureMessage(failure) })
      }
    )
    again.current = cadence.now
    const started = watching
    return () => {
      cadence.stop()
      started.stop()
      again.current = () => undefined
    }
  }, [port, scope, read, cadenceMs])

  const refresh = useCallback(() => {
    again.current()
  }, [])

  const own = read !== null && held?.scope === scope ? held : null
  return { reading: own?.reading ?? null, unread: own?.unread ?? null, again: refresh }
}
