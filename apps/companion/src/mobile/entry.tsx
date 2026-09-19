/**
 * Which shell this device gets.
 *
 * One bundle serves five platforms. The desktop window and the phone are two layouts of one
 * product, not two products, so the choice is made once, here, from what the platform says it is.
 * A build that is not on a phone never renders a line of the mobile shell.
 */

import type { ReactNode } from 'react'

import { App } from '../App'
import { MobileApp, type MobileBuild } from './MobileApp'
import { detectSurface, isMobileSurface, type Surface } from './platform'

/** Reads the surface from this device, with an override for a test that states one. */
export function surfaceOf(search?: string): Surface {
  const stated = search ? new URLSearchParams(search).get('surface') : null
  if (stated === 'ios' || stated === 'android' || stated === 'desktop') return stated
  return detectSurface(
    typeof navigator === 'undefined' ? '' : navigator.userAgent,
    typeof navigator === 'undefined' ? 0 : navigator.maxTouchPoints
  )
}

/** The shell for a surface. */
export function Shell({
  surface,
  build
}: {
  readonly surface: Surface
  readonly build?: MobileBuild
}): ReactNode {
  return isMobileSurface(surface) ? <MobileApp surface={surface} build={build} /> : <App />
}
