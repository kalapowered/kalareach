/**
 * The press of a message's links on a phone.
 *
 * A link's words are often smaller than a finger, so each link has a larger target, and the targets
 * of neighbouring links overlap. Which link a press belongs to is decided by `linkAt`, from the
 * rectangles of the links' words when the press starts. This puts the decision to work on a pane:
 *
 * - at the press's start the pressed look appears on the link that the press belongs to;
 * - the link opens when the press ends, by the browser's own `click`, which is redirected to that
 *   link: a press that moves away, a scroll and a long press never make a `click`, and a press that
 *   moved past the platform's slop makes one that is dropped, so they open nothing as on any control;
 * - a click that no pointer made (a keyboard, a screen reader) goes to the element it names, as it is.
 */

import { useEffect, type RefObject } from 'react'

import { linkAt, type Rect } from './link-target'

/** How far a press may move and still be a press, in CSS pixels: the platforms' touch slop is 8 to 10. */
const SLOP = 10

/** How long after a press ends its `click` may still come, in milliseconds. */
const CLICK_WITHIN = 1500

/** What the pane keeps between a press's start and its click. */
interface Press {
  readonly pointer: number
  readonly x: number
  readonly y: number
  /** The link the press belongs to, or null when it belongs to none. */
  readonly link: HTMLElement | null
  moved: boolean
  /** When the pointer was released, or null while it is down. */
  endedAt: number | null
}

/** The message controls that are not links: a link's target never takes a point on their boxes. */
const OTHER_CONTROLS = 'button:not(.md-link), a[href], input, select, textarea, summary'

/**
 * Gives presses on the links in `pane` to the link whose words are nearest, shows the pressed look
 * on it (`data-pressed`) and opens it on the press's click.
 */
export function useLinkPress(pane: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const element = pane.current
    if (element === null) return undefined
    let press: Press | null = null
    let lit: HTMLElement | null = null

    const light = (link: HTMLElement | null): void => {
      if (lit !== null && lit !== link) lit.removeAttribute('data-pressed')
      lit = link
      link?.setAttribute('data-pressed', '')
    }
    const away = (event: PointerEvent): boolean =>
      press !== null && Math.hypot(event.clientX - press.x, event.clientY - press.y) > SLOP

    const move = (event: PointerEvent): void => {
      if (press === null || event.pointerId !== press.pointer || !away(event)) return
      press.moved = true
      light(null)
    }
    const stop = (): void => {
      document.removeEventListener('pointermove', move)
      document.removeEventListener('pointerup', up)
      document.removeEventListener('pointercancel', cancel)
    }
    const up = (event: PointerEvent): void => {
      if (press === null || event.pointerId !== press.pointer) return
      if (away(event)) press.moved = true
      press.endedAt = event.timeStamp
      light(null)
      stop()
    }
    const cancel = (event: PointerEvent): void => {
      if (press === null || event.pointerId !== press.pointer) return
      press = null
      light(null)
      stop()
    }
    const down = (event: PointerEvent): void => {
      stop()
      light(null)
      press = null
      if (!event.isPrimary || event.button !== 0) return
      const link = linkOf(element, event.clientX, event.clientY)
      press = { pointer: event.pointerId, x: event.clientX, y: event.clientY, link, moved: false, endedAt: null }
      light(link)
      document.addEventListener('pointermove', move)
      document.addEventListener('pointerup', up)
      document.addEventListener('pointercancel', cancel)
    }
    const click = (event: MouseEvent): void => {
      const pressed = press
      press = null
      // No pointer before this click: a keyboard or a screen reader. It goes where it was sent.
      if (
        !event.isTrusted ||
        event.detail === 0 ||
        pressed === null ||
        pressed.endedAt === null ||
        event.timeStamp - pressed.endedAt > CLICK_WITHIN
      ) {
        return
      }
      const control = event.target instanceof Element ? event.target.closest('button') : null
      if (pressed.link === null) {
        // The browser would open the link under the pointer, which the press does not belong to.
        if (control?.classList.contains('md-link')) stopped(event)
        return
      }
      stopped(event)
      if (!pressed.moved) pressed.link.click()
    }

    element.addEventListener('pointerdown', down, true)
    element.addEventListener('click', click, true)
    return () => {
      element.removeEventListener('pointerdown', down, true)
      element.removeEventListener('click', click, true)
      stop()
      light(null)
    }
  }, [pane])
}

function stopped(event: Event): void {
  event.preventDefault()
  event.stopPropagation()
}

/** The link of `pane` that a press at (`x`, `y`) belongs to, read from the page as it is laid out now. */
function linkOf(pane: HTMLElement, x: number, y: number): HTMLElement | null {
  const links = Array.from(pane.querySelectorAll<HTMLElement>('.m-node .md-link'))
  const style = links[0] ? getComputedStyle(links[0]) : null
  // The least size and the room beside the words are what the stylesheet gives a link's box.
  const least = style ? parseFloat(style.minWidth) : Number.NaN
  const beside = style ? parseFloat(style.paddingLeft) : Number.NaN
  if (!Number.isFinite(least) || least <= 0 || !Number.isFinite(beside)) return null
  // A link whose box lies farther from the point than a target reaches cannot take it.
  const near = links.filter((link) => {
    const box = link.getBoundingClientRect()
    return (
      x >= box.left - least &&
      x <= box.right + least &&
      y >= box.top - least &&
      y <= box.bottom + least
    )
  })
  const index = linkAt(
    { x, y },
    near.map(wordsOf),
    { least, beside },
    pane.getBoundingClientRect(),
    Array.from(pane.querySelectorAll(OTHER_CONTROLS), (control) => control.getBoundingClientRect())
  )
  return index === null ? null : (near[index] ?? null)
}

/** The rectangles of a link's words, one for each line its label covers. */
function wordsOf(link: HTMLElement): Rect[] {
  const range = document.createRange()
  range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
  return Array.from(range.getClientRects())
    .filter((rect) => rect.width > 0 && rect.height > 0)
    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
}
