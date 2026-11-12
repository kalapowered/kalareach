/**
 * The press of a message's links on a phone.
 *
 * A link's words are often smaller than a finger, so each link has a larger target, and the targets
 * of neighbouring links overlap. Which link a press belongs to is decided by `linkAt`, from the
 * rectangles of the links' words when the press starts. This puts the decision to work on a pane:
 *
 * - at the press's start the pressed look appears on the link that the press belongs to;
 * - the press is decided again where it ends, with the rectangles as they are then: it stands only
 *   where that choice names the same link or control as the choice at its start. The page moving under
 *   a finger at rest (output arriving, the pane scrolling) cancels nothing by itself, and a press
 *   whose link or control is no longer under the finger opens nothing;
 * - the link opens when the press ends, by the browser's own `click`, which is redirected to that
 *   link. Whether a press makes a click at all stays the browser's: a scroll on a phone ends in
 *   `pointercancel` and makes none. A press that moved past the platform's slop makes a click that is
 *   dropped, so it opens nothing;
 * - a press on another control of the message goes to that control, though a link's box lies over it;
 * - a click that no pointer made (a keyboard, a screen reader) goes to the element it names, as it is.
 *
 * The listeners are on the document, not on the pane: a click listener on the pane would make the
 * pane a target of its own for the platforms' accessibility services. On iOS the click for a tap on
 * plain text comes because the page's other listeners (React's, on the root element below the body)
 * count for WebKit as click listeners on the text's ancestors; a listener on the document alone would
 * not count.
 */

import { useEffect, type RefObject } from 'react'

import { linkAt, type Rect } from './link-target'

/** How far a press may move and still be a press, in CSS pixels: the platforms' touch slop is 8 to 10. */
const SLOP = 10

/** How long after a press ends its `click` may still come, in milliseconds. */
const CLICK_WITHIN = 1500

/** The message controls that are not links: a link's target never takes a point on their boxes. */
const OTHER_CONTROLS = 'button:not(.md-link), a[href], input, select, textarea, summary'

/** What a press at one point belongs to. */
interface Choice {
  /** The link the press belongs to, or null when it belongs to none. */
  readonly link: HTMLElement | null
  /** The other control of the message that the press is on, or null. */
  readonly control: HTMLElement | null
}

/** What the pane keeps between a press's start and its click. */
interface Press extends Choice {
  readonly pointer: number
  readonly x: number
  readonly y: number
  /** Whether the press is cancelled: it moved past the slop, or it ended somewhere else than it began. */
  moved: boolean
  /** When the pointer was released (`performance.now()`), or null while it is down. */
  endedAt: number | null
}

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
    const here = (target: EventTarget | null): boolean => target instanceof Node && element.contains(target)
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
      // Decided again where the press ends, on the page as it is now. A press that chose nothing has
      // nothing to keep.
      if (!press.moved && (press.link !== null || press.control !== null)) {
        const end = choose(element, event.clientX, event.clientY)
        if (end.link !== press.link || end.control !== press.control) press.moved = true
      }
      press.endedAt = performance.now()
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
      // A second finger, a pen's barrel and a mouse's other buttons are not the press that is going on.
      if (!event.isPrimary || event.button !== 0) return
      // Every primary press ends the one before it, in the pane or outside it.
      press = null
      stop()
      light(null)
      if (!here(event.target)) return
      const choice = choose(element, event.clientX, event.clientY)
      press = { ...choice, pointer: event.pointerId, x: event.clientX, y: event.clientY, moved: false, endedAt: null }
      light(choice.link)
      document.addEventListener('pointermove', move)
      document.addEventListener('pointerup', up)
      document.addEventListener('pointercancel', cancel)
    }
    const click = (event: MouseEvent): void => {
      // No pointer before this click (a keyboard, a screen reader), or not the browser's own: it goes
      // where it was sent, and a press that is going on is left alone.
      if (!event.isTrusted || event.detail === 0 || !here(event.target)) return
      const recorded = press
      if (recorded !== null && recorded.endedAt === null) return
      press = null
      let pressed: Choice & { readonly moved: boolean }
      if (recorded !== null && performance.now() - (recorded.endedAt ?? 0) <= CLICK_WITHIN) {
        pressed = recorded
      } else {
        // A click with no press before it that has a place of its own: decided as a press at that place.
        const room = element.getBoundingClientRect()
        const placed =
          (event.clientX !== 0 || event.clientY !== 0) &&
          event.clientX >= room.left &&
          event.clientX <= room.right &&
          event.clientY >= room.top &&
          event.clientY <= room.bottom
        if (!placed) return
        pressed = { ...choose(element, event.clientX, event.clientY), moved: false }
      }
      const hit = event.target instanceof Element ? event.target.closest(`.md-link, ${OTHER_CONTROLS}`) : null
      const held = pressed.link ?? pressed.control
      if (held === null) {
        // The browser would open the link under the pointer, which the press does not belong to.
        if (hit?.classList.contains('md-link')) stopped(event)
        return
      }
      // A cancelled press opens and clicks nothing, whichever element the browser's own click went to.
      if (pressed.moved) {
        stopped(event)
        return
      }
      // The browser's own click on the control the press belongs to stands.
      if (pressed.link === null && hit === held) return
      // A link's click goes to the link whichever element the browser sent it to, and a control's goes
      // to the control when a link's box lies over it, if it is still there.
      stopped(event)
      if (held.isConnected && element.contains(held)) activate(held, event)
    }

    document.addEventListener('pointerdown', down, true)
    document.addEventListener('click', click, true)
    return () => {
      document.removeEventListener('pointerdown', down, true)
      document.removeEventListener('click', click, true)
      stop()
      light(null)
    }
  }, [pane])
}

function stopped(event: Event): void {
  event.preventDefault()
  event.stopPropagation()
}

/** Gives `target` what a pointer's press gives: the focus, and a click that counts as a pointer's. */
function activate(target: HTMLElement, from: MouseEvent): void {
  target.focus({ preventScroll: true })
  target.dispatchEvent(
    new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
      composed: true,
      view: window,
      detail: from.detail,
      clientX: from.clientX,
      clientY: from.clientY,
      screenX: from.screenX,
      screenY: from.screenY
    })
  )
}

/** What a press at (`x`, `y`) belongs to, read from the page as it is laid out now. */
function choose(pane: HTMLElement, x: number, y: number): Choice {
  const controls = Array.from(pane.querySelectorAll<HTMLElement>(OTHER_CONTROLS)).map((control) => ({
    control,
    box: control.getBoundingClientRect()
  }))
  const on = controls.find(({ box }) => x >= box.left && x <= box.right && y >= box.top && y <= box.bottom)
  if (on) return { link: null, control: on.control }
  const links = Array.from(pane.querySelectorAll<HTMLElement>('.m-node .md-link'))
  const style = links[0] ? getComputedStyle(links[0]) : null
  // The least size and the room beside the words are what the stylesheet gives a link's box.
  const least = style ? parseFloat(style.minWidth) : Number.NaN
  const beside = style ? parseFloat(style.paddingLeft) : Number.NaN
  if (!Number.isFinite(least) || least <= 0 || !Number.isFinite(beside)) return { link: null, control: null }
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
    near.map((link) => ({ words: wordsOf(link), box: rectsOf(link.getClientRects()) })),
    { least, beside },
    pane.getBoundingClientRect()
  )
  return { link: index === null ? null : (near[index] ?? null), control: null }
}

/** The rectangles of a link's words, one for each line its label covers. */
function wordsOf(link: HTMLElement): Rect[] {
  const range = document.createRange()
  range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
  return rectsOf(range.getClientRects())
}

/** The rectangles of a list that have a size. */
function rectsOf(list: DOMRectList): Rect[] {
  return Array.from(list)
    .filter((rect) => rect.width > 0 && rect.height > 0)
    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
}
