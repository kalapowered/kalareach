/**
 * The tap of a message's links on a phone.
 *
 * A link's words are often smaller than a finger. The link's box is the page's own, as on a desktop,
 * so the browser's hit test decides every click that lands on a link's words or on another control of
 * the message, and nothing here stops or redirects a click. What this adds is one thing: where a
 * touch's or a pen's click lands on plain text near a link's words (the line under them, the words
 * after them), the link gets a click of its own. `decide` says when (see `link-target.ts`).
 *
 * - At a primary pointer down the pane writes a record of the press: its pointer type, where it went
 *   down, and the link it lights, with what that link opens. A press on a link's own element lights that
 *   link, whatever the words' rectangles say, since the browser sends its click to that element; a press
 *   on another control lights nothing; elsewhere `linkAt` names the link at that point. The record ends
 *   at the pointer's cancel and at the next primary pointer down, in the pane or outside it. No match
 *   of pointer numbers is asked of the click: the engines differ, and a click that no pointer made
 *   (a keyboard's, a screen reader's) has a detail of 0 and adds nothing.
 * - The pressed look shows on that link until the pointer comes up or is cancelled. It decides nothing.
 *   The open at the click runs the same rule at the press's own point, so what lights at the press is
 *   what opens at the release.
 *
 * Where the listeners stand: the pointer down is on the document, in the capture phase, because a press
 * outside the pane must end the pane's record and its look; the pointer move, up and cancel are on the
 * document from a press to its end, because a release or a cancel can come outside the pane when the
 * finger slides out. The click is on the pane itself, in the capture phase: every click the decision
 * reads lies in the pane, and a tap on the pane's own area, where no message lies, has the pane as its
 * target.
 *
 * The pane's bounds are its client box: what holds content and can be tapped, with no border and no
 * scroll bar's strip that takes up room. A press or a click outside it lights and opens nothing.
 */

import { useEffect, type RefObject } from 'react'

import { SLOP, contestRadius, decide, linkAt, type Layout, type Named, type PaneLink, type Press, type Rect } from './link-target'

/** The message controls that are not links. */
const OTHER_CONTROLS = 'button:not(.md-link), a[href], input, select, textarea, summary'

/** What the pane keeps of the press that is going on or that ended last. */
interface Recorded extends Press<HTMLElement> {
  readonly pointer: number
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
    press !== null && Math.hypot(event.clientX - press.at.x, event.clientY - press.at.y) > SLOP

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
    const found = pressedLink(element, event)
    press = {
      pointer: event.pointerId,
      pointerType: event.pointerType,
      at: { x: event.clientX, y: event.clientY },
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
    const { clientX: x, clientY: y } = event
    const decision = decide(
      press,
      { trusted: event.isTrusted, detail: event.detail, at: performance.now(), names: namedBy(event.target), point: { x, y } },
      (at) => layoutNear(element, at.x, at.y)
    )
    if (decision.kind !== 'open') return
    // One press gives one open: the click that follows needs a press of its own.
    press = null
    activate(decision.link, event)
  }

  document.addEventListener('pointerdown', down, true)
  element.addEventListener('click', click, true)
  return () => {
    document.removeEventListener('pointerdown', down, true)
    element.removeEventListener('click', click, true)
    stop()
    light(null)
  }
}

/**
 * The link that a press lights and a tap on it opens. A press on a link's own element is that link's,
 * whatever the words' rectangles say: the browser sends its click to that element. A press on another
 * control is the control's. Elsewhere it is the link whose words are nearest, where a target holds the point.
 */
function pressedLink(pane: HTMLElement, event: PointerEvent): { id: HTMLElement; destination: string } | null {
  const target = event.target instanceof Element ? event.target : null
  const named = namedBy(target)
  if (named === 'control') return null
  if (named === 'link') {
    const own = target?.closest<HTMLElement>('.md-link') ?? null
    return own === null ? null : { id: own, destination: own.title }
  }
  return linkNear(pane, event.clientX, event.clientY)
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
 * The links of `pane` that the rule weighs at (`x`, `y`), laid out as they are now: every link whose
 * words lie within `contestRadius` of the point, which holds the links whose areas can hold it and every
 * link whose words can be nearer to it than theirs. The least size is the stylesheet's `--target`: 44
 * points on iOS and 48 dp on Android, and half of it lies beside the words.
 *
 * Where the pane holds no link in a message (the terminal and the output views, a conversation with no
 * link) this reads no box at all. Otherwise it reads the pane's box, the box of each message that holds
 * a link, and the box of each link of the messages that lie within the radius of the point; of those
 * links only the ones within the radius have their words read. The reads grow with the number of
 * messages that hold links and with the links of the messages near the point, so a message of some
 * thousand links reads every one of its link boxes at each press and each click.
 */
function layoutNear(pane: HTMLElement, x: number, y: number): Layout<HTMLElement> {
  const all = pane.querySelectorAll<HTMLElement>('.m-node .md-link')
  if (all.length === 0) return NO_LINKS
  const least = parseFloat(getComputedStyle(pane).getPropertyValue('--target'))
  // What holds content and can be tapped: the pane's client box, with no border and no scroll bar's strip.
  const box = pane.getBoundingClientRect()
  const left = box.left + pane.clientLeft
  const top = box.top + pane.clientTop
  const bounds = { left, top, right: left + pane.clientWidth, bottom: top + pane.clientHeight }
  if (!Number.isFinite(least) || least <= 0) return { links: [], reach: { least: 0, beside: 0 }, bounds }
  const reach = { least, beside: least / 2 }
  const radius = contestRadius(reach)
  // A box that lies farther from the point than the radius holds no link that the rule weighs there.
  const near = (box: DOMRect): boolean => x >= box.left - radius && x <= box.right + radius && y >= box.top - radius && y <= box.bottom + radius
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
  return { links, reach, bounds }
}

/** The rectangles of a link's words, one for each line its label covers. */
function wordsOf(link: HTMLElement): Rect[] {
  const range = document.createRange()
  range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
  return Array.from(range.getClientRects())
    .filter((rect) => rect.width > 0 && rect.height > 0)
    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
}
