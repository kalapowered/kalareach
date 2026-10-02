/**
 * The person's text size, on a phone whose web view does not apply it to the page.
 *
 * Android's web view multiplies the root's 100% by the system's font scale, and does so again when
 * the scale changes, so the page needs nothing there. iOS's does not: the root stays at 16px at
 * every Dynamic Type size. What WebKit does map to Dynamic Type is the font keyword
 * `-apple-system-body`: an element set in it takes the system's body size, and takes the new one
 * the moment the setting changes, with the application running.
 *
 * So a probe, an element set in that keyword, is measured, and the ratio of its size to the size
 * the keyword has at the default setting becomes `--text-scale`, which the root's font size is
 * multiplied by. Everything sized in `rem` then grows by the system's factor: 1 at the default
 * size, a little over 3 at the largest accessibility size, and a fraction at the smallest. The
 * probe is watched, so a change made while the application runs reaches the page without a reload.
 *
 * The keyword alone would put the root at 17px at the default size, a layout a sixteenth larger
 * than the one every screen was drawn and tested at; the ratio keeps the default exactly as it was.
 */

/** The size of the system's body text at the default Dynamic Type setting, in points. */
export const BODY_SIZE_AT_THE_DEFAULT_SETTING = 17

/** What the root's font size is multiplied by. */
export const TEXT_SCALE = '--text-scale'

/**
 * Whether this web view maps a font keyword to the person's text size: iOS's WebKit does. Desktop
 * Safari knows the keyword too, with no Dynamic Type behind it, so `-webkit-touch-callout`, which
 * only the iOS engine has, says which one this is.
 */
export function systemTextSizeIsAvailable(): boolean {
  return (
    typeof CSS !== 'undefined' &&
    CSS.supports('-webkit-touch-callout', 'none') &&
    CSS.supports('font', '-apple-system-body')
  )
}

/** A size in px as a ratio to the default setting's, rounded so a measurement's noise changes nothing. */
function scaleOf(pixels: number): number {
  return Math.round((pixels / BODY_SIZE_AT_THE_DEFAULT_SETTING) * 10_000) / 10_000
}

/**
 * Makes the page's text follow the person's text size, where the web view has one to follow, and
 * answers how to stop. Where it has none, nothing is added and the answer does nothing.
 */
export function followTheSystemTextSize(): () => void {
  if (!systemTextSizeIsAvailable()) return () => undefined
  const root = document.documentElement
  const probe = document.createElement('span')
  probe.setAttribute('aria-hidden', 'true')
  probe.textContent = 'M'
  probe.style.cssText =
    'position:fixed;inset:0 auto auto 0;visibility:hidden;pointer-events:none;white-space:nowrap;font:-apple-system-body;'
  document.body.append(probe)

  const measure = (): void => {
    const size = parseFloat(getComputedStyle(probe).fontSize)
    // A size that is not a number, or not a size, leaves the page at the size it already has.
    if (Number.isFinite(size) && size > 0) root.style.setProperty(TEXT_SCALE, String(scaleOf(size)))
  }
  measure()
  // The probe's box is the keyword's size, so it changes when the setting does.
  const watching = new ResizeObserver(measure)
  watching.observe(probe)
  return () => {
    watching.disconnect()
    probe.remove()
    root.style.removeProperty(TEXT_SCALE)
  }
}
