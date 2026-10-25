/**
 * Where a phone's notifications stand, for the screen that shows them.
 *
 * Native code does the work: it asks the system, asks the notification service, answers its
 * challenge and hands the host what it needs. This holds what it last said. The application looks
 * again whenever it comes to the front, on whichever screen (`MobileApp`), and what that finds
 * arrives here as a change.
 */

import { useCallback, useEffect, useState } from 'react'

import { useApp } from '../../app/state'
import type { PushView } from '../../host/port'

/** What the Hosts screen is given to show and act on. */
export interface Notifications {
  /** Null until native code has answered once. */
  readonly view: PushView | null
  /** Turns notifications on for the host `reference` names. */
  readonly enable: (reference: string) => Promise<void>
  /** Chooses whether the notifications of the host `reference` names show what needs the person. */
  readonly setPreviews: (reference: string, on: boolean) => Promise<void>
  /** Opens this application's page in the system's settings. */
  readonly openSettings: () => Promise<void>
}

/** Follows where notifications stand. */
export function useNotifications(): Notifications {
  const { port } = useApp()
  const [view, setView] = useState<PushView | null>(null)
  // A view reaches the page by an event or as the answer to a command, and an answer read earlier
  // can arrive after an event read later. The page keeps the view read last, whichever way it came.
  const take = useCallback((next: PushView) => {
    setView((held) => (held !== null && next.revision < held.revision ? held : next))
  }, [])

  useEffect(() => {
    let watching = true
    let stop: (() => void) | null = null
    // The state is read once the listener is registered, so no change can fall between the two.
    void port.onPush((next) => {
      if (watching) take(next)
    }).then((unlisten) => {
      if (!watching) {
        unlisten()
        return
      }
      stop = unlisten
      void port.pushView().then((first) => {
        if (watching) take(first)
      }).catch(() => undefined)
    }).catch(() => undefined)
    return () => {
      watching = false
      stop?.()
    }
  }, [port, take])

  const enable = useCallback(
    async (reference: string) => {
      take(await port.pushEnable(reference))
    },
    [port, take]
  )
  const setPreviews = useCallback(
    async (reference: string, on: boolean) => {
      take(await port.pushPreviews(reference, on))
    },
    [port, take]
  )
  const openSettings = useCallback(() => port.openAppSettings(), [port])
  return { view, enable, setPreviews, openSettings }
}
