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
 *   link for every pointer type, whatever the words' rectangles say, since the browser sends its click to
 *   that element; a press on another control lights nothing; a press on plain text lights the link that
 *   `linkAt` names at that point, and only for a pointer that `opensByRule` (a touch or a pen): a mouse's
 *   click on plain text opens nothing, so its press lights nothing. No match of pointer numbers is asked
 *   of the click: the engines differ, and a click that no pointer made (a keyboard's, a screen reader's)
 *   has a detail of 0 and adds nothing.
 * - A press is live or dead. The pressed look shows on the lit link only while the press lives, and a
 *   dead press opens nothing. It lives from the pointer down to the pointer up, and dies at the first of:
 *   a move past the slop, a pointer cancel, the loss of the pointer's capture, the window's loss of
 *   focus, the page's hiding, the next primary pointer down (in the pane or outside it),
 *   and a scroll of any box or of the visual viewport, or a resize of the viewport, after which a release
 *   at the press's point would no longer open the lit link (`releaseOpens`). At its death the look ends at once. The open at
 *   the click runs the same rule at the press's own point, so for a touch or a pen what lights at the
 *   press is what opens at the release. A layout that moves under a held finger with no scroll (an image
 *   that loads above the link, text that grows above it) ends nothing: the click's own check refuses the
 *   open, and the look stays until the release. Watching the content's size would end presses whenever
 *   an answer streams below the link, which is the usual state.
 *
 * Where the listeners stand: all on the document (the window's blur excepted), in the capture phase for
 * the pointer down and the click. A press outside the pane must end the pane's record and its look, so
 * the pointer down is not on the pane; from a press that lit a link to its end stand the pointer move, up
 * and cancel, the loss of the pointer's capture, the page's visibility change, the window's blur, the
 * scroll of any box (a scroll does not bubble, so only the capture phase on the document hears every box)
 * and the visual viewport's scroll and resize (a release or a cancel can come outside the pane when the
 * finger slides out), and `stop` removes every one of them at every end; a press that lights nothing opens
 * nothing and has no look to keep, so it keeps no record and registers none of them, and no end has to
 * reach it; and the click acts only on a click whose target lies in the pane. A click listener on the
 * pane itself gave no click at any point where the document's gives none: the points that get none in a
 * desktop WebKit are its scroll bar's strip at the pane's right edge, which no listener changes and
 * which the phones do not have. iOS sends a click on plain text because the page's own listeners sit on
 * the root element below the body (React's), which makes the page respond to clicks; a pane mounted
 * outside that root would get no click on plain text, and its taps near a link would open nothing.
 *
 * A link's view is what every box that clips it leaves of the page (see `viewOf`): the pane's client
 * box (what holds content and can be tapped, with no border and no scroll bar's strip), the scrollers
 * inside and outside the pane, and the visual viewport. A press or a click where no link has a view
 * lights and opens nothing. Where a box between a link and the page's root makes a view that cannot be
 * measured (`blocksView`: a transform that is more than a move, a box that contains its paint, a box
 * that skips its content's rendering) the link takes no part: it gets no added area, the rule never
 * lights it and the handler never opens it, and a press on its own element lights nothing, as on a page
 * with no handler. The browser's click on its own element stands.
 */

import { useEffect, type RefObject } from 'react'

import { SLOP, contestRadius, decide, keepsPress, linkAt, opensByRule, type Layout, type Named, type PaneLink, type Press, type Rect } from './link-target'

/** The message controls that are not links. */
const OTHER_CONTROLS = 'button:not(.md-link), a[href], input, select, textarea, summary'

/** What the pane keeps of the press that is going on or that ended last. */
interface Recorded extends Press<HTMLElement> {
  /** The link that the press lit and what a click on it opens: a press that lights nothing keeps no record. */
  readonly start: { readonly link: HTMLElement; readonly destination: string }
  readonly pointer: number
  /** Whether the press went down on the link's own element, which the browser's click opens. */
  readonly own: boolean
  /** Where the press's pointer is now: a mouse's click opens by where it is released, not by where it went down. */
  current: { x: number; y: number }
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

  // A press is live or dead. It lives from a primary pointer down to the pointer's up, and it dies at the
  // first of: a move past the slop, a pointer cancel, the loss of the pointer's capture, the window's loss
  // of focus, the page's hiding, the next primary pointer down, and a scroll or a resize after which a
  // release would no longer open the link it lit. At its death the look ends at once and the record goes,
  // so a dead press opens nothing. The listeners below stand only while a press lives. A release can
  // then never arrive (a lost capture, a window that is no longer in front, a page that is no longer
  // shown), and the look would stay on the link until some later press.
  const die = (): void => {
    press = null
    light(null)
    stop()
  }
  // The slop is measured from the press's first point. A mouse's or a trackpad's click opens by where the
  // button is released, so its look follows the pointer: lit while the pointer lies in the link's own
  // element, out where it has left it, lit again where it is back. For a touch or a pen the rule opens
  // from the first point, and a move within the slop changes nothing.
  const move = (event: PointerEvent): void => {
    if (press === null || event.pointerId !== press.pointer) return
    if (away(event)) {
      die()
      return
    }
    press.current = { x: event.clientX, y: event.clientY }
    if (!opensByRule(press.pointerType)) light(releaseOpens(element, press) ? press.start.link : null)
  }
  // The scroll of any box (scroll events do not bubble, so the capture phase on the document hears them
  // all) and the visual viewport's scroll and resize move the page under a held finger: the look is kept
  // only where a release at the press's point would still open the lit link (`releaseOpens`).
  const recheck = (): void => {
    if (press === null) return
    if (!releaseOpens(element, press)) die()
    else light(press.start.link)
  }
  // The pointer's capture was taken from the pointer, the window is no longer in front or the page is
  // no longer shown: no release will come to this press.
  const lost = (event: PointerEvent): void => {
    if (press !== null && event.pointerId === press.pointer) die()
  }
  const blur = (): void => {
    die()
  }
  const hide = (): void => {
    if (document.hidden) die()
  }
  const stop = (): void => {
    document.removeEventListener('pointermove', move)
    document.removeEventListener('pointerup', up)
    document.removeEventListener('pointercancel', cancel)
    document.removeEventListener('lostpointercapture', lost)
    document.removeEventListener('visibilitychange', hide)
    window.removeEventListener('blur', blur)
    document.removeEventListener('scroll', recheck, true)
    window.visualViewport?.removeEventListener('scroll', recheck)
    window.visualViewport?.removeEventListener('resize', recheck)
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
    die()
  }
  const down = (event: PointerEvent): void => {
    // A second finger, a pen's barrel and a mouse's other buttons are not the press that is going on.
    if (!event.isPrimary || event.button !== 0) return
    // Every primary press ends the one before it, in the pane or outside it.
    die()
    if (!here(event.target)) return
    const found = pressedLink(element, event)
    // A press that lights nothing opens nothing and has no look to keep: it keeps no record and registers
    // no listener, so no end has to reach it (a lost capture, a blur or a hidden page would otherwise
    // leave its listeners standing until the next press).
    if (found === null) return
    press = {
      pointer: event.pointerId,
      pointerType: event.pointerType,
      at: { x: event.clientX, y: event.clientY },
      start: { link: found.id, destination: found.destination },
      own: found.own,
      current: { x: event.clientX, y: event.clientY },
      moved: false,
      upAt: null
    }
    light(found.id)
    document.addEventListener('pointermove', move)
    document.addEventListener('pointerup', up)
    document.addEventListener('pointercancel', cancel)
    document.addEventListener('lostpointercapture', lost)
    document.addEventListener('visibilitychange', hide)
    window.addEventListener('blur', blur)
    document.addEventListener('scroll', recheck, true)
    window.visualViewport?.addEventListener('scroll', recheck)
    window.visualViewport?.addEventListener('resize', recheck)
  }
  const click = (event: MouseEvent): void => {
    if (!here(event.target)) return
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
  document.addEventListener('click', click, true)
  return () => {
    document.removeEventListener('pointerdown', down, true)
    document.removeEventListener('click', click, true)
    stop()
    light(null)
  }
}

/**
 * The link that a press lights and a tap on it opens. A press on a link's own element is that link's,
 * whatever the words' rectangles say: the browser sends its click to that element, for every pointer
 * type. A press on another control is the control's. A press on plain text is the link whose words are
 * nearest, where a target holds the point, and only for a pointer that `opensByRule`: a mouse's click on
 * plain text opens nothing, so its press lights nothing.
 */
function pressedLink(pane: HTMLElement, event: PointerEvent): { id: HTMLElement; destination: string; own: boolean } | null {
  const target = event.target instanceof Element ? event.target : null
  const named = namedBy(target)
  if (named === 'control') return null
  if (named === 'link') {
    const own = target?.closest<HTMLElement>('.md-link') ?? null
    return own === null || unmeasured(own) ? null : { id: own, destination: own.title, own: true }
  }
  if (!opensByRule(event.pointerType)) return null
  const near = linkNear(pane, event.clientX, event.clientY)
  return near === null ? null : { id: near.id, destination: near.destination, own: false }
}

/**
 * Whether a release at the press's point would open the link that the press lit. This is the one
 * predicate of every path that lights or keeps a look, and each of them asks it of the same two things:
 *
 * - the press's own element: the browser sends its click to the link's element, for every pointer type,
 *   while the press's point lies in the part of that element that its view leaves (`liesInView`: the
 *   element's rectangle held to every box that clips it, not the raw rectangle);
 * - the nearest-words rule at the press's point, for a pointer that `opensByRule` (a touch or a pen)
 *   only: a mouse's click on plain text opens nothing.
 *
 * The paths: `pressedLink` at the pointer down (the element under the press, or the rule for a touch or
 * a pen), `recheck` at each scroll or resize while a lit press lives (this function), and `decide` at the
 * click (the rule, with the same pointer test, and the element's own click by the browser).
 */
function releaseOpens(pane: HTMLElement, press: Recorded): boolean {
  const by = opensByRule(press.pointerType)
  // A touch's or a pen's click comes from the press's first point; a mouse's from where it is released.
  if (press.own && liesInView(pane, press.start.link, by ? press.at : press.current)) return true
  if (!by) return false
  // The rule opens a link only from plain text of the pane, as at the pointer down: where a scroll has put
  // another control, another link or an element outside the pane under the point, the click is that
  // element's and the rule adds nothing.
  const hit = document.elementFromPoint(press.at.x, press.at.y)
  if (hit === null || !pane.contains(hit) || namedBy(hit) !== 'neither') return false
  return keepsPress(press, (point) => layoutNear(pane, point.x, point.y))
}

/** Whether `point` lies in the part of `link`'s own element that every box clipping it leaves in view. */
function liesInView(pane: HTMLElement, link: HTMLElement, point: { x: number; y: number }): boolean {
  const view = viewOf(link, ancestorsOf(pane), screenOf())
  if (view === null) return false
  const box = link.getBoundingClientRect()
  const left = Math.max(box.left, view.left)
  const right = Math.min(box.right, view.right)
  const top = Math.max(box.top, view.top)
  const bottom = Math.min(box.bottom, view.bottom)
  return left < right && top < bottom && point.x >= left && point.x <= right && point.y >= top && point.y <= bottom
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
  const { links, reach } = layoutNear(pane, x, y)
  const index = linkAt({ x, y }, links, reach)
  return index === null ? null : (links[index] ?? null)
}

/** What a layout is where the pane holds no link in a message: nothing to press. */
const NO_LINKS: Layout<HTMLElement> = { links: [], reach: { least: 0, beside: 0 } }

/**
 * What a read knows of one ancestor of a link: whether it keeps the view from being measured, and how it
 * clips, by axis (where `x` or `y` is false the box leaves that axis alone), with its client box, which
 * is read when a link first needs it.
 */
interface Ancestor {
  readonly blocks: boolean
  readonly x: boolean
  readonly y: boolean
  box: Rect | null
}

/** The room that nothing clips. */
const OPEN: Rect = { left: -Infinity, top: -Infinity, right: Infinity, bottom: Infinity }

/**
 * The links of `pane` that the rule weighs at (`x`, `y`), laid out as they are now: every link whose
 * words lie within `contestRadius` of the point, which holds the links whose areas can hold it and every
 * link whose words can be nearer to it than theirs, each with its view (`viewOf`). The least size is the
 * stylesheet's `--target`: 44 points on iOS and 48 dp on Android, and half of it lies beside the words.
 *
 * Where the pane holds no link in a message (the terminal and the output views, a conversation with no
 * link) this reads no box at all. Otherwise it reads the pane's box, the box of each message that holds
 * a link, and the box of each link of the messages that are near the point; of those links only the ones
 * within the radius have their words read, and their clipping ancestors, each ancestor once for all of
 * them. The reads grow with the number of messages that hold links and with the links of the messages
 * near the point, so a message of some thousand links reads every one of its link boxes at each press
 * and each click. Besides those boxes, each press and each click finds the message of every link of
 * the pane with `closest`: a walk of the tree, not a layout read. While a press that lit a link lives, each
 * scroll event of any box in the page and each scroll or resize of the visual viewport reads the same again
 * at the press's point, and a press on a link's own element also reads that element's view; moves,
 * the release and a cancel read nothing.
 *
 * A message is near when the point lies within the radius of the message's box on the vertical axis
 * only. All messages share one horizontal extent, the stream's, and a link in a line wider than it
 * (an unbroken run, a wide table) lies outside that box once the pane has scrolled sideways.
 */
function layoutNear(pane: HTMLElement, x: number, y: number): Layout<HTMLElement> {
  const all = pane.querySelectorAll<HTMLElement>('.m-node .md-link')
  if (all.length === 0) return NO_LINKS
  const least = parseFloat(getComputedStyle(pane).getPropertyValue('--target'))
  if (!Number.isFinite(least) || least <= 0) return NO_LINKS
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
      const box = message.getBoundingClientRect()
      answer = y >= box.top - radius && y <= box.bottom + radius
      messages.set(message, answer)
    }
    return answer
  }
  const known = ancestorsOf(pane)
  const screen = screenOf()
  // A link whose view cannot be measured takes no part: it is not in the layout at all.
  const links = Array.from(all)
    .filter((link) => nearMessage(link) && near(link.getBoundingClientRect()))
    .flatMap((link) => {
      const view = viewOf(link, known, screen)
      return view === null ? [] : [{ id: link, destination: link.title, words: wordsOf(link), view }]
    })
  return { links, reach }
}

/**
 * What is known of the ancestors of the links of `pane` in one read, so that each is read once. The
 * pane clips every link in it, whatever its computed overflow says: what holds content and can be
 * tapped is its client box, with no border and no scroll bar's strip.
 */
function ancestorsOf(pane: HTMLElement): Map<Element, Ancestor> {
  return new Map<Element, Ancestor>([[pane, { blocks: blocksView(getComputedStyle(pane)), x: true, y: true, box: clientBoxOf(pane) }]])
}

/** What the visual viewport shows of the page, in the layout viewport's coordinates. */
function screenOf(): Rect {
  const viewport = window.visualViewport
  return viewport === null || viewport === undefined
    ? OPEN
    : { left: viewport.offsetLeft, top: viewport.offsetTop, right: viewport.offsetLeft + viewport.width, bottom: viewport.offsetTop + viewport.height }
}

/**
 * What every box that clips `link` leaves of the page, by axis: the visual viewport `screen`, narrowed by
 * the client box of each ancestor from the link up to the document's root whose computed overflow on that
 * axis is not `visible`. The intersection is taken whole, so a later fit never gives back what an earlier
 * box cut. `known` holds what is read of each ancestor in this read, so that each is read once.
 *
 * It is null where the view cannot be measured: an ancestor whose box keeps the client boxes from being
 * laid over the words' rectangles (`blocksView`). A named limit, not geometry that this models.
 *
 * The walk follows the element tree. It does not model a link taken out of the flow: an absolutely
 * positioned link is clipped by the boxes between it and its containing block, a fixed one by none, and
 * the walk clips both by every ancestor; a clip-path or a mask is not read. In this page's messages
 * links are inline, so none of these holds.
 */
function viewOf(link: HTMLElement, known: Map<Element, Ancestor>, screen: Rect): Rect | null {
  let view = screen
  for (let ancestor = link.parentElement; ancestor !== null; ancestor = ancestor.parentElement) {
    let box = known.get(ancestor)
    if (box === undefined) {
      const style = getComputedStyle(ancestor)
      box = { blocks: blocksView(style), x: style.overflowX !== 'visible', y: style.overflowY !== 'visible', box: null }
      known.set(ancestor, box)
    }
    if (box.blocks) return null
    if (!box.x && !box.y) continue
    box.box ??= clientBoxOf(ancestor)
    view = {
      left: box.x ? Math.max(view.left, box.box.left) : view.left,
      right: box.x ? Math.min(view.right, box.box.right) : view.right,
      top: box.y ? Math.max(view.top, box.box.top) : view.top,
      bottom: box.y ? Math.min(view.bottom, box.box.bottom) : view.bottom
    }
    // Nothing of the link is in view of an empty view, whatever the boxes further up leave.
    if (view.left >= view.right || view.top >= view.bottom) break
  }
  return view
}

/** Whether a box between `link` and the page's root keeps its view from being measured (see `blocksView`). */
function unmeasured(link: HTMLElement): boolean {
  for (let ancestor = link.parentElement; ancestor !== null; ancestor = ancestor.parentElement) {
    if (blocksView(getComputedStyle(ancestor))) return true
  }
  return false
}

/**
 * Whether a box keeps the view of the links under it from being measured: the client boxes of the
 * ancestors are read in the box's own units and its words' rectangles in the page's, and they are laid
 * over each other as they are. That holds where a box only moves its content (a translation: its
 * bounding rectangle moves with it). It does not hold where the box
 *
 * - has a transform that is more than a move (its matrix is not a pure translation) or the separate
 *   `scale` or `rotate` property: the bounding rectangle of the box is not the box;
 * - contains its paint (`contain` with `paint`, `strict` or `content`) or skips its content's rendering
 *   (`content-visibility` other than `visible`): words are hidden with no overflow value that says so.
 *
 * A link under such a box takes no part, so that no hidden link is lit or opened. The product has no
 * such box around a message. Not modelled: what a perspective, a filter, a clip-path or a mask hides.
 */
function blocksView(style: CSSStyleDeclaration): boolean {
  const value = (name: string): string => style.getPropertyValue(name).trim()
  const set = (name: string): boolean => value(name) !== '' && value(name) !== 'none'
  if (!isMove(value('transform')) || set('scale') || set('rotate')) return true
  if (value('contain').split(/\s+/).some((kind) => kind === 'paint' || kind === 'strict' || kind === 'content')) return true
  return value('content-visibility') !== '' && value('content-visibility') !== 'visible'
}

/** The entries of a 2D matrix that a pure translation holds (`NaN`: any value), and those of a 3D one. */
const MOVE_2D = [1, 0, 0, 1, NaN, NaN]
const MOVE_3D = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, NaN, NaN, NaN, 1]

/** Whether a computed `transform` is none or a pure translation. Any other form is not a move. */
function isMove(transform: string): boolean {
  if (transform === '' || transform === 'none') return true
  const parsed = /^matrix(3d)?\(([^)]*)\)$/.exec(transform)
  if (parsed === null) return false
  const wanted = parsed[1] === undefined ? MOVE_2D : MOVE_3D
  const values = (parsed[2] ?? '').split(',').map(Number)
  return values.length === wanted.length && wanted.every((entry, index) => Number.isNaN(entry) || Math.abs((values[index] ?? NaN) - entry) < 1e-9)
}

/** What a box holds of content that can be tapped: its client box, with no border and no scroll bar's strip. */
function clientBoxOf(element: Element): Rect {
  // The root's client box is the viewport's, wherever the page has scrolled.
  if (element === document.documentElement) return { left: 0, top: 0, right: element.clientWidth, bottom: element.clientHeight }
  const box = element.getBoundingClientRect()
  const left = box.left + element.clientLeft
  const top = box.top + element.clientTop
  return { left, top, right: left + element.clientWidth, bottom: top + element.clientHeight }
}

/** The rectangles of a link's words, one for each line its label covers. */
function wordsOf(link: HTMLElement): Rect[] {
  const range = document.createRange()
  range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
  return Array.from(range.getClientRects())
    .filter((rect) => rect.width > 0 && rect.height > 0)
    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
}
