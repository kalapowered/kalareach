/**
 * The room beside a link's words that gives its box the least size across.
 *
 * The box that VoiceOver and TalkBack read for a link of a message is the link's own button. The
 * stylesheet pads it out above and below (`.m-node .md-link`), where what it lacks is the same for every
 * link. How much it lacks across depends on the words: a digit is 8 px wide and a short word 30. So the
 * page measures it. A link narrower than the least size (44 points on iOS, 48 dp on Android) gets the
 * room it lacks as padding on the side or sides that have room, and the stylesheet takes the same room
 * back by a negative margin, so that no line, word or paragraph moves. The padded box takes no tap: the
 * button has no hit of its own, so a tap beside the words is on the text there and `useLinkPress` says
 * which link's it is.
 *
 * Where the room lies:
 *
 * - The box stays in the message's column, so that it never makes the pane scroll sideways, and inside
 *   the box that clips the link where one does (a scroller inside a message keeps the box in its own
 *   scrolled content).
 * - The box does not reach another link's or control's box beside it on the same line or on a line whose
 *   box reaches this one's (the boxes are as high as the least size, so the line above and below count).
 *   A gap between two links that both take room is shared in halves; a gap to a control, or to a link
 *   that is wide enough, is the narrow link's to its edge. A link that the halves leave under the least
 *   size is measured again, with each neighbour that the halves brought to the least size as the box it
 *   is, so that a neighbour that needed less than its half leaves the rest of the gap.
 * - Where the column cuts one side of the room, the other side grows by what was cut (the rule of
 *   `link-target.ts`'s `fit`), so a link at the end of a line is as wide as the least size when the
 *   column has room for it on the other side. Where both sides together lack room (two short links with
 *   a space between them), the box is the room there is: the link is narrower than the least size, and
 *   that is as far as the page can go without a box over another control.
 *
 * Which link opens is not decided here. The padding is measured from the words' own box, which the
 * padding does not move, so a measure of a measured link gives the same answer and a change that adds
 * no new room writes nothing.
 */

import { useEffect, type RefObject } from 'react'

import { OTHER_CONTROLS } from './link-press'
import { fit, type Rect } from './link-target'

/** The room given to a link on each side of its words, in px, by the page's own left and right (the writing's direction does not matter). */
export interface Beside {
  readonly left: number
  readonly right: number
}

/** A box that lies beside a link, and whether it is a link that takes room beside its own words. */
export interface Neighbour {
  readonly box: Rect
  readonly shares: boolean
}

/** What a box has to keep within: the part of the page's width that its words may be padded over. */
export interface Column {
  readonly left: number
  readonly right: number
}

/** The custom properties on a link's element that its padding reads. */
const LEFT = '--md-link-left'
const RIGHT = '--md-link-right'

/** The attributes of a message's elements that move words with no change of the message's size or text: a table cell's alignment is a style. */
const LAYOUT_ATTRIBUTES = ['style', 'class', 'align', 'dir', 'hidden']

/** The grid an engine lays a box out on: a padding is held to it, so a box never ends a rounding past its column. */
const GRID = 64

/** The twentieth of a pixel on each side that keeps an engine's rounding to the grid from leaving the box under the least size. */
const SLACK = 0.05

const NONE: Beside = { left: 0, right: 0 }

/**
 * The room to give a link whose box (as the words have it across and the stylesheet has it down) is `box`.
 * `neighbours` are the other links and controls near it; only those whose box reaches `box`'s height can
 * lie beside it.
 */
export function besideOf(box: Rect, least: number, neighbours: readonly Neighbour[], column: Column): Beside {
  const width = box.right - box.left
  if (width >= least) return NONE
  // The room is the column, held in from each side by the nearest box beside the link: a link whose box
  // already overlaps another's across has no side to keep from it, and a box that lies on the same side
  // (or is only in the way of a part of it) keeps the nearest edge.
  let min = Math.min(column.left, box.left)
  let max = Math.max(column.right, box.right)
  for (const other of neighbours) {
    if (other.box.bottom <= box.top || other.box.top >= box.bottom) continue
    if (other.box.right <= box.left) min = Math.max(min, other.shares ? (other.box.right + box.left) / 2 : other.box.right)
    else if (other.box.left >= box.right) max = Math.min(max, other.shares ? (box.right + other.box.left) / 2 : other.box.left)
  }
  const grow = (least - width) / 2 + SLACK
  const [from, to] = fit(box.left - grow, box.right + grow, min, max)
  return { left: held(box.left - from), right: held(to - box.right) }
}

/** `value` rounded down to the engine's grid, and never below nothing. */
function held(value: number): number {
  return Math.floor(Math.max(0, value) * GRID) / GRID
}

/** What the page has given a link, read from its element. */
function givenTo(link: HTMLElement): Beside {
  const read = (name: string): number => {
    const value = parseFloat(link.style.getPropertyValue(name))
    return Number.isFinite(value) ? value : 0
  }
  return { left: read(LEFT), right: read(RIGHT) }
}

function give(link: HTMLElement, name: string, value: number): void {
  if (value > 0) link.style.setProperty(name, `${String(value)}px`)
  else link.style.removeProperty(name)
}

/** The width of the box that clips `link` sideways inside `message` and its content, or the message's own content box. */
function columnOf(link: HTMLElement, message: Element): Column {
  for (let up = link.parentElement; up !== null && up !== message; up = up.parentElement) {
    if (getComputedStyle(up).overflowX === 'visible') continue
    const left = up.getBoundingClientRect().left + up.clientLeft - up.scrollLeft
    return { left, right: left + Math.max(up.scrollWidth, up.clientWidth) }
  }
  const style = getComputedStyle(message)
  const box = message.getBoundingClientRect()
  const side = (...names: string[]): number => names.reduce((sum, name) => sum + (parseFloat(style.getPropertyValue(name)) || 0), 0)
  return { left: box.left + side('border-left-width', 'padding-left'), right: box.right - side('border-right-width', 'padding-right') }
}

/** The box of an element that is drawn, or null for one that has none (a closed `details`, `display: none`). */
function drawn(element: Element): Rect | null {
  const { left, top, right, bottom } = element.getBoundingClientRect()
  return right > left || bottom > top ? { left, top, right, bottom } : null
}

/**
 * Gives each link of `messages` the room it lacks of the least size beside its words, and takes back
 * the room of a link that no longer needs it. The messages next to each of them are read as well, for the
 * boxes that lie beside a link at the edge of its message. Everything is read before anything is written,
 * and only a link whose room has changed is written, so a read of a page that has not changed makes no
 * layout.
 */
export function fitLinks(pane: HTMLElement, messages: readonly Element[]): void {
  const least = parseFloat(getComputedStyle(pane).getPropertyValue('--target'))
  if (!Number.isFinite(least) || least <= 0) return
  // The elements of the messages and of the ones beside them, once each.
  const near = new Set<Element>()
  for (const message of messages) {
    near.add(message)
    if (message.previousElementSibling?.matches('.m-node') === true) near.add(message.previousElementSibling)
    if (message.nextElementSibling?.matches('.m-node') === true) near.add(message.nextElementSibling)
  }
  const mine = new Set<Element>(messages)
  const boxes: { element: HTMLElement; box: Rect; link: boolean; message: Element }[] = []
  for (const message of near) {
    for (const element of message.querySelectorAll<HTMLElement>(`.md-link, ${OTHER_CONTROLS}`)) {
      const placed = drawn(element)
      const link = element.classList.contains('md-link')
      if (placed === null) {
        if (link && mine.has(message)) boxes.push({ element, box: { left: 0, top: 0, right: 0, bottom: 0 }, link, message })
        continue
      }
      // The box that the words have across: what the page gave the link beside them is not theirs.
      const given = link ? givenTo(element) : NONE
      boxes.push({ element, box: { ...placed, left: placed.left + given.left, right: placed.right - given.right }, link, message })
    }
  }
  const neighbours: Neighbour[] = boxes
    .filter(({ box }) => box.right > box.left)
    .map(({ box, link }) => ({ box, shares: link && box.right - box.left < least }))
  const widthOf = (box: Rect, room: Beside): number => box.right - box.left + room.left + room.right
  // Pass 1: every link takes half of a gap to a short link beside it, as if that link needed all of its half.
  const first = new Map<HTMLElement, Beside>()
  for (const { element, box, link, message } of boxes) {
    if (!link || !mine.has(message)) continue
    const room =
      box.right > box.left
        ? besideOf(
            box,
            least,
            neighbours.filter((other) => other.box !== box),
            columnOf(element, message)
          )
        : NONE
    first.set(element, room)
  }
  // Pass 2: a link that pass 1 left under the least size is measured again with each neighbour that pass 1 brought to the least size
  // as the box it is, not as a short link that takes half of the gap: a neighbour that needed less than its half leaves the rest.
  const rooms = new Map(first)
  for (const { element, box, message } of boxes) {
    const room = first.get(element)
    if (room === undefined || box.right <= box.left || widthOf(box, room) >= least) continue
    const fixed: Neighbour[] = boxes
      .filter((other) => other.box !== box && other.box.right > other.box.left)
      .map((other) => {
        const taken = first.get(other.element)
        if (other.link && taken !== undefined && widthOf(other.box, taken) >= least) {
          return { box: { ...other.box, left: other.box.left - taken.left, right: other.box.right + taken.right }, shares: false }
        }
        return { box: other.box, shares: other.link && other.box.right - other.box.left < least }
      })
    rooms.set(element, besideOf(box, least, fixed, columnOf(element, message)))
  }
  const writes: { link: HTMLElement; room: Beside }[] = []
  for (const [element, room] of rooms) {
    const now = givenTo(element)
    if (Math.abs(room.left - now.left) > 1 / GRID || Math.abs(room.right - now.right) > 1 / GRID) writes.push({ link: element, room })
  }
  for (const { link, room } of writes) {
    give(link, LEFT, room.left)
    give(link, RIGHT, room.right)
  }
}

/** Keeps the room of the links in `pane` as the page lays them out, while the pane is mounted. */
export function useLinkFit(pane: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const element = pane.current
    return element === null ? undefined : startLinkFit(element)
  }, [pane])
}

/**
 * Keeps the room of the links in `pane` as the page lays them out: every message is measured when the
 * pane first shows it and again when its content or its size changes, when the pane is resized and when a
 * font arrives. The function it returns ends it; the room given stays with the links.
 */
export function startLinkFit(pane: HTMLElement): () => void {
  const dirty = new Set<Element>()
  let frame: number | null = null
  const observed = new Set<Element>()

  const run = (): void => {
    frame = null
    const messages = Array.from(dirty).filter((message) => message.isConnected)
    dirty.clear()
    if (messages.length > 0) fitLinks(pane, messages)
  }
  const schedule = (): void => {
    frame ??= requestAnimationFrame(run)
  }
  const mark = (node: Node | null): void => {
    const element = node instanceof Element ? node : (node?.parentElement ?? null)
    const message = element?.closest('.m-node') ?? null
    if (message !== null && pane.contains(message)) dirty.add(message)
  }
  const markAll = (): void => {
    for (const message of pane.querySelectorAll('.m-node')) dirty.add(message)
    schedule()
  }

  const resized =
    typeof ResizeObserver === 'undefined'
      ? null
      : new ResizeObserver((entries) => {
          for (const entry of entries) {
            if (entry.target === pane) {
              markAll()
              return
            }
            mark(entry.target)
          }
          schedule()
        })
  /** Watches the size of each message of the pane and lets go of those that have left it. */
  const watch = (): void => {
    if (resized === null) return
    for (const message of observed) {
      if (!message.isConnected) {
        resized.unobserve(message)
        observed.delete(message)
      }
    }
    for (const message of pane.querySelectorAll('.m-node')) {
      if (observed.has(message)) continue
      observed.add(message)
      resized.observe(message)
    }
  }
  const changed = new MutationObserver((records) => {
    let structure = false
    for (const record of records) {
      if (record.type === 'attributes') {
        // The room that this hook writes is a style of the link itself, and is no change of the message's layout.
        const own = record.attributeName === 'style' && record.target instanceof Element && record.target.classList.contains('md-link')
        if (!own) mark(record.target)
        continue
      }
      structure = true
      mark(record.target)
      for (const node of record.addedNodes) mark(node)
      mark(record.previousSibling)
      mark(record.nextSibling)
    }
    if (structure) watch()
    if (structure || dirty.size > 0) schedule()
  })

  resized?.observe(pane)
  changed.observe(pane, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: LAYOUT_ATTRIBUTES })
  watch()
  markAll()
  const fonts = document.fonts as FontFaceSet | undefined
  fonts?.addEventListener('loadingdone', markAll)

  return () => {
    changed.disconnect()
    resized?.disconnect()
    fonts?.removeEventListener('loadingdone', markAll)
    if (frame !== null) cancelAnimationFrame(frame)
    frame = null
    dirty.clear()
    observed.clear()
  }
}
