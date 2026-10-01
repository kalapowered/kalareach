/**
 * Keeping the field a person types into above a software keyboard.
 *
 * The composer is lifted over a keyboard by padding that puts its field at the keyboard's top when
 * the session is laid out whole above it. Where the room above the keyboard cannot hold the
 * session's rows and its chrome (larger text, a phone on its side), the session is taller than the
 * room it has and the page scrolls; the platform's own scroll to the field is undone when the shell
 * goes with the visual viewport, so nothing else brings the field into view. The scrolling areas
 * that hold it are scrolled here by what the field is short of, the nearest first, by setting their
 * position and never by asking the field to scroll into view, which would pan the visual viewport
 * again and have the shell follow it.
 */

/** How far, in pixels, a field may lie under the keyboard before it is moved. */
const TOLERANCE = 0.5

/** Whether an element scrolls up and down by itself. */
function scrollsVertically(element: HTMLElement): boolean {
  const { overflowY } = getComputedStyle(element)
  return (overflowY === 'auto' || overflowY === 'scroll') && element.scrollHeight > element.clientHeight
}

/**
 * Scrolls the areas that hold `field` until its bottom edge is at `visibleBottom` or above, as far
 * as they scroll, and says how far it still lies under it (zero when it is in view).
 */
export function liftAbove(field: HTMLElement, visibleBottom: number, shell: HTMLElement): number {
  let short = field.getBoundingClientRect().bottom - visibleBottom
  for (
    let area: HTMLElement | null = field.parentElement;
    area !== null && short > TOLERANCE;
    area = area === shell ? null : area.parentElement
  ) {
    if (!scrollsVertically(area)) continue
    const before = area.scrollTop
    area.scrollTop = before + short
    short = field.getBoundingClientRect().bottom - visibleBottom
  }
  return Math.max(0, short)
}
