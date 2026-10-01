/**
 * Keeping the field a person types into on the keyboard's top edge.
 *
 * The composer is lifted over a keyboard by padding that puts its field at the keyboard's top when
 * the session is laid out whole above it. Where the room above the keyboard cannot hold the
 * session's rows and its chrome (larger text, a phone on its side), the session is taller than the
 * room it has and the page scrolls; the platform's own scroll to the field is undone when the shell
 * goes with the visual viewport, so nothing else brings the field into view. The scrolling areas
 * that hold it are scrolled here by what the field is off its place by, the nearest first, by
 * setting their position and never by asking the field to scroll into view, which would pan the
 * visual viewport again and have the shell follow it.
 */

/** How far, in pixels, a field may lie from its place before it is moved. */
const TOLERANCE = 0.5

/** Where each area was before it was first moved, so it can be put back when the keyboard goes. */
export type Positions = Map<HTMLElement, number>

/** Whether an element scrolls up and down by itself. */
function scrollsVertically(element: HTMLElement): boolean {
  const { overflowY } = getComputedStyle(element)
  return (overflowY === 'auto' || overflowY === 'scroll') && element.scrollHeight > element.clientHeight
}

/**
 * Scrolls the areas that hold `field` until its bottom edge is at `visibleBottom`, as far as they
 * scroll either way, and says how far it still is from there: above zero while it lies under the
 * keyboard, below zero while there is a gap between it and the keyboard that no scrolling closes.
 */
export function restOn(field: HTMLElement, visibleBottom: number, shell: HTMLElement, moved: Positions): number {
  let off = field.getBoundingClientRect().bottom - visibleBottom
  for (
    let area: HTMLElement | null = field.parentElement;
    area !== null && Math.abs(off) > TOLERANCE;
    area = area === shell ? null : area.parentElement
  ) {
    if (!scrollsVertically(area)) continue
    if (!moved.has(area)) moved.set(area, area.scrollTop)
    area.scrollTop += off
    off = field.getBoundingClientRect().bottom - visibleBottom
  }
  return off
}

/** Puts every area moved by `restOn` back where it was. */
export function putBack(moved: Positions): void {
  for (const [area, top] of moved) area.scrollTop = top
  moved.clear()
}
