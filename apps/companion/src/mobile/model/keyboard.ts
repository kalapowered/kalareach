/**
 * Keeping the field a person types into on the keyboard's top edge.
 *
 * The composer is lifted over a keyboard by padding that puts its field at the keyboard's top when
 * the session is laid out whole above it. Where the room above the keyboard cannot hold the
 * session's rows and its chrome (larger text, a phone on its side), the session is taller than the
 * room it has and the page scrolls; the platform's own scroll to the field is undone when the shell
 * goes with the visual viewport, so nothing else brings the field into view. The shell's scrolling
 * area is scrolled here by what the field is off its place by, by setting its position and never
 * by asking the field to scroll into view, which would pan the visual viewport again and have the
 * shell follow it. The composer's own scrolling is left alone: scrolling it would only move the
 * field up inside a box that clips it.
 */

/** How far, in pixels, a field may lie from its place before it is moved. */
const TOLERANCE = 0.5

/** Where an area was before it was first moved, so it can be put back when the keyboard goes. */
export interface Position {
  area: HTMLElement | null
  top: number
}

/**
 * Scrolls `area` until `field`'s bottom edge is at `visibleBottom`, as far as it scrolls either
 * way, and says how far the field still is from there: above zero while it lies under the keyboard,
 * below zero while there is a gap between it and the keyboard that no scrolling closes.
 */
export function restOn(field: HTMLElement, visibleBottom: number, area: HTMLElement, moved: Position): number {
  let off = field.getBoundingClientRect().bottom - visibleBottom
  if (Math.abs(off) <= TOLERANCE) return off
  if (moved.area !== area) {
    moved.area = area
    moved.top = area.scrollTop
  }
  area.scrollTop += off
  off = field.getBoundingClientRect().bottom - visibleBottom
  return off
}

/** Puts the area moved by `restOn` back where it was. */
export function putBack(moved: Position): void {
  if (moved.area !== null) moved.area.scrollTop = moved.top
  moved.area = null
}
