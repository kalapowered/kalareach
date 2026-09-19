/**
 * Which phone this is, and what that platform expects of a control.
 *
 * The two mobile platforms disagree about almost nothing this application cares about, and about
 * two things it does: the smallest a control may be, and which way a person expects to go back.
 * Everything else is one implementation, so the differences live here rather than being spread
 * through the screens as conditionals.
 */

/** The platforms this shell is drawn for. */
export type MobilePlatform = 'ios' | 'android'

/** What the surfaces run on. `desktop` is every other case, including a browser. */
export type Surface = MobilePlatform | 'desktop'

/**
 * Reads the platform from the user agent.
 *
 * The user agent is what a WebView actually tells the page it is running in, on both platforms and
 * in both simulators. It is taken as an argument so a test can state one rather than pretend to be
 * a device.
 */
export function detectSurface(userAgent: string, maxTouchPoints = 0): Surface {
  const agent = userAgent.toLowerCase()
  if (agent.includes('android')) return 'android'
  if (/iphone|ipod/.test(agent)) return 'ios'
  // An iPad reports itself as a Macintosh from iPadOS 13 on. A Macintosh with touch points is one.
  if (agent.includes('ipad') || (agent.includes('macintosh') && maxTouchPoints > 1)) return 'ios'
  return 'desktop'
}

/**
 * The smallest a control may be, in points on iOS and in density-independent pixels on Android.
 *
 * Both platforms state a minimum and the two numbers differ. A CSS pixel is one point on iOS and
 * one density-independent pixel on Android, so the same number in CSS is the right number on each.
 * It applies in both dimensions: a control 48 wide and 30 tall is not a 48 target.
 */
export const TOUCH_TARGET: Readonly<Record<MobilePlatform, number>> = {
  ios: 44,
  android: 48
}

/** The minimum for a surface, using the larger of the two wherever the platform is not known. */
export function minimumTarget(surface: Surface): number {
  return surface === 'desktop' ? TOUCH_TARGET.android : TOUCH_TARGET[surface]
}

/**
 * Where a back action belongs.
 *
 * Android has a system back gesture and a system back affordance, so a second one in the interface
 * is a second way to do the same thing in a different place. iOS has neither, so the screen
 * carries its own.
 */
export function showsBackControl(surface: Surface): boolean {
  return surface !== 'android'
}

/** Whether this build should draw the phone's surfaces rather than the desktop window's. */
export function isMobileSurface(surface: Surface): surface is MobilePlatform {
  return surface === 'ios' || surface === 'android'
}
