/**
 * Where a phone's notifications stand, for the screen that shows them.
 *
 * Native code does the work: it asks the system, asks the notification service, answers its
 * challenge and hands the host what it needs. This holds what it last said and asks it to look again
 * whenever the application comes to the front, because a person who left to change the system's
 * notification setting comes back to the screen they left.
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

/**
 * Follows where notifications stand.
 *
 * `resumed` is how many times the application has come to the front: each one is a look, so a
 * permission the person changed in the system's settings is seen on the screen they return to.
 */
export function useNotifications(resumed: number): Notifications {
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

  // A look each time the application is in front again, and once at the start.
  useEffect(() => {
    let watching = true
    port.pushRefresh().then((next) => {
      if (watching) setView(next)
    }).catch(() => undefined)
    return () => {
      watching = false
    }
  }, [port, resumed])

  const enable = useCallback(
    async (reference: string) => {
      setView(await port.pushEnable(reference))
    },
    [port]
  )
  const openSettings = useCallback(() => port.openAppSettings(), [port])
  return { view, enable, openSettings }
}
