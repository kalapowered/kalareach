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
 * The room is one packing of each line's links (`packRooms`). The boxes of a line are intervals that
 * hold their links' words, stay in the message's column (or in the box that clips the link, where one
 * does: a scroller inside a message keeps the box in its own scrolled content), and keep off one another
 * and off the controls beside them. A link that lacks room takes it from the gaps beside it, and the
 * packing completes as many of a line's short links as any assignment of such boxes can: a link is left
 * under the least size only where no assignment gives it the least size together with the other links
 * that the packing completes (the proof is a case that compares the packing with an exhaustive search
 * over many small random lines). A link that is completed has the room it lacks, centred on its words
 * where the neighbours allow it; a link that cannot be completed has all the room that is left, shared in
 * halves with a short neighbour that cannot be completed either.
 *
 * Links on neighbouring lines whose boxes reach each other's height are kept off one another by the
 * middle of the gap between their words (and off a link that is wide enough or a control by its edge):
 * that part is not packed, so a short link beside another line's short link can stay under the least
 * size where a packing of both lines together would give it the least size.
 *
 * Which link opens is not decided here. The padding is measured from the words' own box, which the
 * padding does not move, so a measure of a measured link gives the same answer and a change that adds
 * no new room writes nothing.
 */

import { useEffect, type RefObject } from 'react'

import { OTHER_CONTROLS } from './link-press'
import { type Rect } from './link-target'

/** The room given to a link on each side of its words, in px, by the page's own left and right (the writing's direction does not matter). */
export interface Beside {
  readonly left: number
  readonly right: number
}

/** A link or a control: its box (the words' box across, the stylesheet's box down) and, for a link, the column its box has to keep within. */
export interface Item {
  readonly box: Rect
  readonly link: boolean
  readonly column: Column
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

/** The same line: boxes that are as high as one another, which is how an engine lays out the buttons of a line of text. */
const sameLine = (a: Rect, b: Rect): boolean => Math.abs(a.top - b.top) <= 1 && Math.abs(a.bottom - b.bottom) <= 1

/** What the packing of one line knows of a link: its words, what it lacks, and the room its walls leave on each side. */
interface Slot {
  readonly at: number
  readonly left: number
  readonly right: number
  readonly lack: number
  readonly leftRoom: number
  readonly rightRoom: number
}

/**
 * The room of each of `items`, in order: none for a control and for a link that is as wide as `least`.
 * `slack` is what is added to the room a link lacks on each side (see `SLACK`).
 */
export function packRooms(items: readonly Item[], least: number, slack: number = SLACK): Beside[] {
  const rooms: Beside[] = items.map(() => NONE)
  const width = (item: Item): number => item.box.right - item.box.left
  const short = (item: Item): boolean => item.link && width(item) > 0 && width(item) < least
  // The walls of each short link: its column, and every box on a line that reaches its height that does not lie on its own line.
  const walls = new Map<number, { left: number; right: number }>()
  items.forEach((item, at) => {
    if (!short(item)) return
    let left = Math.min(item.column.left, item.box.left)
    let right = Math.max(item.column.right, item.box.right)
    items.forEach((other, index) => {
      if (index === at || width(other) <= 0) return
      if (other.box.bottom <= item.box.top || other.box.top >= item.box.bottom) return
      if (other.link && sameLine(other.box, item.box)) return
      const middle = other.link && short(other)
      if (other.box.right <= item.box.left) left = Math.max(left, middle ? (other.box.right + item.box.left) / 2 : other.box.right)
      else if (other.box.left >= item.box.right) right = Math.min(right, middle ? (item.box.right + other.box.left) / 2 : other.box.left)
    })
    walls.set(at, { left, right })
  })
  // The lines that hold a short link, each of them packed alone.
  const lines: number[][] = []
  const placed = new Set<number>()
  for (const at of walls.keys()) {
    if (placed.has(at)) continue
    const line = items.flatMap((other, index) => (other.link && width(other) > 0 && sameLine(other.box, (items[at]).box) ? [index] : []))
    line.sort((a, b) => (items[a]).box.left - (items[b]).box.left)
    for (const index of line) placed.add(index)
    lines.push(line)
  }
  for (const line of lines) {
    const slots: Slot[] = line.map((index) => {
      const item = items[index]
      const wall = walls.get(index)
      return {
        at: index,
        left: item.box.left,
        right: item.box.right,
        lack: short(item) ? least - width(item) + 2 * slack : 0,
        leftRoom: wall === undefined ? 0 : Math.max(0, item.box.left - wall.left),
        rightRoom: wall === undefined ? 0 : Math.max(0, wall.right - item.box.right)
      }
    })
    const given = packLine(slots)
    slots.forEach((slot, index) => {
      const own = given[index] ?? NONE
      rooms[slot.at] = { left: held(own.left), right: held(own.right) }
    })
  }
  return rooms
}

const EPSILON = 1e-9

/**
 * Packs one line's links, left to right: which of the short links can all have the room they lack (the most that
 * any assignment allows), and how much of it each takes from each side. Two neighbours share the gap between
 * their words, and a link's room on a side is no more than its wall leaves.
 */
function packLine(slots: readonly Slot[]): Beside[] {
  const count = slots.length
  const gap = (k: number): number => Math.max(0, (slots[k + 1]).left - (slots[k]).right)
  interface State {
    readonly right: number
    readonly took: boolean
  }
  // table[k][c]: after the first k + 1 links, with c of them completed, the least that the last one takes from the gap on its right.
  const table: (State | undefined)[][] = []
  let before: (State | undefined)[] = [{ right: 0, took: false }]
  for (let k = 0; k < count; k += 1) {
    const slot = slots[k]
    const now: (State | undefined)[] = []
    const offer = (completed: number, state: State): void => {
      const own = now[completed]
      if (own === undefined || state.right < own.right - EPSILON || (state.right <= own.right + EPSILON && state.took)) now[completed] = state
    }
    before.forEach((state, completed) => {
      if (state === undefined) return
      offer(completed, { right: 0, took: false })
      if (slot.lack <= 0) return
      const free = k > 0 ? Math.min(slot.leftRoom, gap(k - 1) - state.right) : slot.leftRoom
      const left = Math.min(slot.lack, Math.max(0, free))
      const right = slot.lack - left
      if (right <= Math.min(slot.rightRoom, k < count - 1 ? gap(k) : Infinity) + EPSILON) offer(completed + 1, { right, took: true })
    })
    table.push(now)
    before = now
  }
  const done: boolean[] = new Array<boolean>(count).fill(false)
  let completed = (table[count - 1] ?? []).length - 1
  for (let k = count - 1; k >= 0; k -= 1) {
    const state = table[k]?.[completed]
    if (state?.took === true) {
      done[k] = true
      completed -= 1
    }
  }
  // What each completed link has to take from the gap on its left, at the least, for the links after it to be completed.
  const needs: number[] = new Array<number>(count + 1).fill(0)
  for (let k = count - 1; k >= 0; k -= 1) {
    const slot = slots[k]
    if (!done[k]) continue
    const room = Math.min(slot.rightRoom, k < count - 1 ? gap(k) - (needs[k + 1] ?? 0) : Infinity)
    needs[k] = Math.max(0, slot.lack - room)
  }
  // The completed links, from the left: each takes the half of what it lacks from each side that the others leave it.
  const given: { left: number; right: number }[] = slots.map(() => ({ left: 0, right: 0 }))
  let taken = 0
  for (let k = 0; k < count; k += 1) {
    const slot = slots[k]
    const own = given[k]
    if (!done[k]) {
      taken = 0
      continue
    }
    const free = Math.min(slot.leftRoom, slot.lack, k > 0 ? gap(k - 1) - taken : Infinity)
    own.left = Math.min(Math.max(slot.lack / 2, needs[k] ?? 0), Math.max(0, free))
    own.right = slot.lack - own.left
    taken = own.right
  }
  // The links that cannot be completed have all the room that is left: a gap between two of them is shared in halves.
  const rest = (k: number): number => gap(k) - (done[k] ? (given[k] as { right: number }).right : 0) - (done[k + 1] ? (given[k + 1] as { left: number }).left : 0)
  const open = (k: number): boolean => (slots[k]).lack > 0 && !done[k]
  for (let k = 0; k < count; k += 1) {
    if (!open(k)) continue
    const slot = slots[k]
    const own = given[k]
    if (k === 0) own.left = slot.leftRoom
    else if (!open(k - 1)) own.left = Math.min(slot.leftRoom, Math.max(0, rest(k - 1)))
    if (k === count - 1) own.right = slot.rightRoom
    else if (!open(k + 1)) own.right = Math.min(slot.rightRoom, Math.max(0, rest(k)))
  }
  for (let k = 0; k + 1 < count; k += 1) {
    if (!open(k) || !open(k + 1)) continue
    const space = Math.max(0, rest(k))
    const first = slots[k]
    const second = slots[k + 1]
    let right = Math.min(first.rightRoom, space / 2)
    const left = Math.min(second.leftRoom, space - right)
    right = Math.min(first.rightRoom, space - left)
    ;(given[k] as { right: number }).right = right
    ;(given[k + 1] as { left: number }).left = left
  }
  return given
}

/** `value` rounded down to the engine's grid, and never below nothing. */
function held(value: number): number {
  return Math.floor(Math.max(0, value) * GRID) / GRID
}

/** A link's `style` attribute with the two properties of the room taken out, and the spaces. */
const withoutRoom = (style: string | null): string => (style ?? '').replace(/--md-link-(?:left|right):[^;]*;?/g, '').replace(/\s+/g, '')

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
  // Only a link that lacks room needs its column.
  const items: Item[] = boxes.map(({ element, box, link, message }) => ({
    box,
    link,
    column: link && box.right > box.left && box.right - box.left < least ? columnOf(element, message) : { left: box.left, right: box.right }
  }))
  const rooms = packRooms(items, least)
  const writes: { link: HTMLElement; room: Beside }[] = []
  boxes.forEach(({ element, link, message }, index) => {
    if (!link || !mine.has(message)) return
    const room = rooms[index] ?? NONE
    const now = givenTo(element)
    if (Math.abs(room.left - now.left) > 1 / GRID || Math.abs(room.right - now.right) > 1 / GRID) writes.push({ link: element, room })
  })
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
        // The room that this hook writes is a style of the link itself, and is no change of the message's layout: a style
        // that differs from what it was in more than the two properties of the room is.
        const own =
          record.attributeName === 'style' &&
          record.target instanceof Element &&
          record.target.classList.contains('md-link') &&
          withoutRoom(record.oldValue) === withoutRoom(record.target.getAttribute('style'))
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
  changed.observe(pane, { childList: true, subtree: true, characterData: true, attributes: true, attributeOldValue: true, attributeFilter: LAYOUT_ATTRIBUTES })
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
