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
  /** Opens this application's page in the system's settings. */
  readonly openSettings: () => Promise<void>
}

/** Follows where notifications stand. */
export function useNotifications(): Notifications {
  const { port } = useApp()
  const [view, setView] = useState<PushView | null>(null)

  useEffect(() => {
    let watching = true
    let stop: (() => void) | null = null
    // The state is read once the listener is registered, so no change can fall between the two.
    void port.onPush((next) => {
      if (watching) setView(next)
    }).then((unlisten) => {
      if (!watching) {
        unlisten()
        return
      }
      stop = unlisten
      void port.pushView().then((first) => {
        if (watching) setView((held) => held ?? first)
      }).catch(() => undefined)
    }).catch(() => undefined)
    return () => {
      watching = false
      stop?.()
    }
  }, [port])

  const enable = useCallback(
    async (reference: string) => {
      setView(await port.pushEnable(reference))
    },
    [port]
  )
  const openSettings = useCallback(() => port.openAppSettings(), [port])
  return { view, enable, openSettings }
}
