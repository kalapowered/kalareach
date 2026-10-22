/**
 * What the system says of the camera, kept for the attachment picker.
 *
 * The state is read when the picker is shown, when the application comes back to the front (the
 * person may have allowed the camera in Settings), and when the camera closes with no picture, which
 * is where a refusal shows. The camera's own button never waits on it: opening the picker has to be
 * the press itself, because a WebView opens a file chooser only for a press.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import { failureMessage, type CameraAccess, type HostPort } from '../../host/port'
import { cameraOffer, type CameraOffer } from './media'

/** What the picker is given to draw and drive the camera's button. */
export interface CameraControl {
  readonly offer: CameraOffer
  /** True once a camera closed with no picture and the permission was read after it. */
  readonly refusedJustNow: boolean
  /** The camera closed with no picture: the state is read again, and a refusal is said. */
  readonly closedEmpty: () => void
  /** A picture came, so whatever was said about the camera before no longer holds. */
  readonly pictured: () => void
  /** Opens this application's page in the system's settings, where the camera is allowed. */
  readonly openSettings: () => void
}

/** The camera's state for the picker of one screen. */
export function useCameraControl(
  port: HostPort,
  say: (message: string, tone: 'danger') => void
): CameraControl {
  const [access, setAccess] = useState<CameraAccess | null>(null)
  const [empty, setEmpty] = useState(false)
  const alive = useRef(true)
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])

  /** Reads the state, and tells `then` what it was, unless the screen has gone. */
  const read = useCallback(
    (then: (access: CameraAccess) => void) => {
      port
        .cameraAccess()
        .then((now) => {
          if (alive.current) then(now)
        })
        // A phone that cannot say leaves the camera offered, and the system answers when it is used.
        .catch(() => undefined)
    },
    [port]
  )

  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState !== 'visible') return
      read((now) => {
        setAccess(now)
        // Allowed in Settings: what was said about a refusal no longer holds.
        if (now === 'granted') setEmpty(false)
      })
    }
    refresh()
    document.addEventListener('visibilitychange', refresh)
    window.addEventListener('focus', refresh)
    return () => {
      document.removeEventListener('visibilitychange', refresh)
      window.removeEventListener('focus', refresh)
    }
  }, [read])

  const closedEmpty = useCallback(() => {
    read((now) => {
      setAccess(now)
      setEmpty(true)
    })
  }, [read])
  const pictured = useCallback(() => {
    setEmpty(false)
  }, [])
  const openSettings = useCallback(() => {
    port.openAppSettings().catch((error: unknown) => {
      say(failureMessage(error), 'danger')
    })
  }, [port, say])

  const offer = cameraOffer(access, empty)
  return { offer, refusedJustNow: empty && offer.notice !== null, closedEmpty, pictured, openSettings }
}
