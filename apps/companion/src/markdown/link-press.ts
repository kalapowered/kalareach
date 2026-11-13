/**
 * The tap of a message's links on a phone.
 *
 * A link's words are often smaller than a finger. The link's box is the page's own, as on a desktop,
 * so the browser's hit test decides every click that lands on a link's words or on another control of
 * the message, and nothing here stops or redirects a click. What this adds is one thing: where a
 * touch's or a pen's click lands on plain text near a link's words (the line under them, the words
 * after them), the link gets a click of its own. `decide` says when (see `link-target.ts`).
 *
 * - At a primary pointer down the pane writes a record of the press: its pointer type, the link that
 *   `linkAt` names at that point (the element and what it opens) and where it started. The record ends
 *   at the pointer's cancel and at the next primary pointer down, in the pane or outside it. No match
 *   of pointer numbers is asked of the click: the engines differ, and a click that no pointer made
 *   (a keyboard's, a screen reader's) has a detail of 0 and adds nothing.
 * - The pressed look shows on the link that `linkAt` names at the press's start, until the pointer
 *   comes up or is cancelled. It decides nothing.
 *
 * The listeners are on the document, not on the pane: a click listener on the pane would make the
 * pane a target of its own for the platforms' accessibility services. On iOS the click for a tap on
 * plain text comes because the page's other listeners (React's, on the root element below the body)
 * count for WebKit as click listeners on the text's ancestors; a listener on the document alone would
 * not count.
 */

import { useEffect, type RefObject } from 'react'

import { decide, linkAt, type Layout, type Named, type PaneLink, type Press, type Rect } from './link-target'

/** How far a press may move and still be a tap, in CSS pixels: the platforms' touch slop is 8 to 10. */
const SLOP = 10

/** The message controls that are not links. */
const OTHER_CONTROLS = 'button:not(.md-link), a[href], input, select, textarea, summary'

/** What the pane keeps of the press that is going on or that ended last. */
interface Recorded extends Press<HTMLElement> {
  readonly pointer: number
  readonly x: number
  readonly y: number
  moved: boolean
  upAt: number | null
}

/**
 * Shows the pressed look (`data-pressed`) on the link that a press starts on in `pane`, and gives a
 * link the click of a tap on plain text near its words.
 */
export function useLinkPress(pane: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const element = pane.current
    return element === null ? undefined : startLinkPress(element)
  }, [pane])
}

/** Starts the handling of presses and clicks in `element`; the function it returns ends it. */
export function startLinkPress(element: HTMLElement): () => void {
  let press: Recorded | null = null
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
    if (press !== null && event.pointerId === press.pointer && away(event)) press.moved = true
  }
  const stop = (): void => {
    document.removeEventListener('pointermove', move)
    document.removeEventListener('pointerup', up)
    document.removeEventListener('pointercancel', cancel)
  }
  const up = (event: PointerEvent): void => {
    if (press === null || event.pointerId !== press.pointer) return
    if (away(event)) press.moved = true
    // The release's own time: a page that was busy when the finger came up runs this late, and the
    // click then runs just after it, but the three seconds started at the release. A time after the
    // clock's own reading is no time at all.
    press.upAt = Math.min(event.timeStamp, performance.now())
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
    // A press that starts on a control is the control's.
    const found = namedBy(event.target) === 'control' ? null : linkNear(element, event.clientX, event.clientY)
    press = {
      pointer: event.pointerId,
      pointerType: event.pointerType,
      x: event.clientX,
      y: event.clientY,
      start: found === null ? null : { link: found.id, destination: found.destination },
      moved: false,
      upAt: null
    }
    light(found?.id ?? null)
    document.addEventListener('pointermove', move)
    document.addEventListener('pointerup', up)
    document.addEventListener('pointercancel', cancel)
  }
  const click = (event: MouseEvent): void => {
    if (!here(event.target)) return
    const { clientX: x, clientY: y } = event
    const decision = decide(
      press,
      { trusted: event.isTrusted, detail: event.detail, at: performance.now(), names: namedBy(event.target), point: { x, y } },
      () => layoutNear(element, x, y)
    )
    if (decision.kind !== 'open') return
    activate(decision.link, event)
  }

  document.addEventListener('pointerdown', down, true)
  document.addEventListener('click', click, true)
  return () => {
    document.removeEventListener('pointerdown', down, true)
    document.removeEventListener('click', click, true)
    stop()
    light(null)
  }
}

/** What a click's target is: a link, another control of the message, or neither (plain text). */
function namedBy(target: EventTarget | null): Named {
  const hit = target instanceof Element ? target.closest(`.md-link, ${OTHER_CONTROLS}`) : null
  if (hit === null) return 'neither'
  return hit.classList.contains('md-link') ? 'link' : 'control'
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

/** The link whose words are nearest to (`x`, `y`), where a target of a link holds the point. */
function linkNear(pane: HTMLElement, x: number, y: number): PaneLink<HTMLElement> | null {
  const { links, reach, bounds } = layoutNear(pane, x, y)
  const index = linkAt({ x, y }, links, reach, bounds)
  return index === null ? null : (links[index] ?? null)
}

/** What a layout is where the pane holds no link in a message: nothing to press. */
const NO_LINKS: Layout<HTMLElement> = { links: [], reach: { least: 0, beside: 0 }, bounds: { left: 0, top: 0, right: 0, bottom: 0 } }

/**
 * The links of `pane` that a target could reach (`x`, `y`) from, laid out as they are now. The least
 * size is the stylesheet's `--target`: 44 points on iOS and 48 dp on Android, and half of it lies
 * beside the words.
 *
 * What this reads does not grow with the number of links. Where the pane holds no link in a message
 * (the terminal and the output views, a conversation with no link) it reads no box at all. Otherwise
 * it reads the pane's box, the box of each message that holds a link, and the box of each link of the
 * messages that lie within the least size of the point; of those links only the ones within the least
 * size of the point have their words read.
 */
function layoutNear(pane: HTMLElement, x: number, y: number): Layout<HTMLElement> {
  const all = pane.querySelectorAll<HTMLElement>('.m-node .md-link')
  if (all.length === 0) return NO_LINKS
  const least = parseFloat(getComputedStyle(pane).getPropertyValue('--target'))
  const bounds = pane.getBoundingClientRect()
  if (!Number.isFinite(least) || least <= 0) return { links: [], reach: { least: 0, beside: 0 }, bounds }
  // A box that lies farther from the point than a target reaches holds no link that could hold it.
  const near = (box: DOMRect): boolean => x >= box.left - least && x <= box.right + least && y >= box.top - least && y <= box.bottom + least
  const messages = new Map<Element, boolean>()
  const nearMessage = (link: HTMLElement): boolean => {
    const message = link.closest('.m-node')
    if (message === null) return false
    let answer = messages.get(message)
    if (answer === undefined) {
      answer = near(message.getBoundingClientRect())
      messages.set(message, answer)
    }
    return answer
  }
  const links = Array.from(all)
    .filter((link) => nearMessage(link) && near(link.getBoundingClientRect()))
    .map((link) => ({ id: link, destination: link.title, words: wordsOf(link) }))
  return { links, reach: { least, beside: least / 2 }, bounds }
}

/** The rectangles of a link's words, one for each line its label covers. */
function wordsOf(link: HTMLElement): Rect[] {
  const range = document.createRange()
  range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
  return Array.from(range.getClientRects())
    .filter((rect) => rect.width > 0 && rect.height > 0)
    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
}
