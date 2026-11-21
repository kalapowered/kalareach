/**
 * The room that a link of a message is given beside its words, as numbers and as the page applies it.
 *
 * `packRooms` is the rule, over rectangles alone (`besideOf` below is a test helper that packs one link with the boxes near it). `fitLinks` and `startLinkFit` read a page's boxes and write
 * the custom properties that the stylesheet pads and takes back by: jsdom has no layout, so the page's
 * geometry is made here, and the box of a link is its words' box grown by the room it has been given, as the
 * stylesheet grows it. The browser cases (`e2e/accessibility.spec.ts`, "the box of a link in a message") hold
 * what the declarations do to a laid out page in both engines.
 */

import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { fitLinks, packRooms, startLinkFit, type Beside, type Column, type Item } from '../src/markdown/link-fit'

const LEAST = 44

/** A box that lies beside a link, and whether it is a link that takes room beside its own words (a control, or a link that is wide enough, does not). */
interface Neighbour {
  readonly box: { left: number; top: number; right: number; bottom: number }
  readonly shares: boolean
}

/** The room of one link with the boxes of the links and controls near it, as the packing of its line gives it. */
function besideOf(box: Neighbour['box'], least: number, neighbours: readonly Neighbour[], column: Column): Beside {
  const rooms = packRooms([{ box, link: true, column }, ...neighbours.map((other) => ({ box: other.box, link: other.shares, column }))], least)
  return rooms[0] ?? { left: 0, right: 0 }
}
/** A box of 44 px, high enough for the least size: a line with its box padded out above and below. */
const row = (left: number, right: number, top = 100): { left: number; top: number; right: number; bottom: number } => ({ left, top, right, bottom: top + 44 })
const column = { left: 0, right: 390 }

describe('the room beside a link', () => {
  it('is none for a link that is as wide as the least size', () => {
    expect(besideOf(row(100, 144), LEAST, [], column)).toEqual({ left: 0, right: 0 })
    expect(besideOf(row(100, 300), LEAST, [], column)).toEqual({ left: 0, right: 0 })
  })

  it('is half of what the link lacks on each side where the line has room, and a little over so that no rounding leaves it short', () => {
    const room = besideOf(row(100, 110), LEAST, [], column)
    // 34 px lacking: 17 on each side, and a twentieth of a pixel more, held down to 1/64 px.
    expect(room.left).toBeGreaterThanOrEqual(17.05 - 1 / 64)
    expect(room.left).toBeLessThanOrEqual(17.05)
    expect(room.right).toBe(room.left)
    expect(10 + room.left + room.right, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
    expect(room.left * 64, 'the room lies on the engine’s grid').toBe(Math.round(room.left * 64))
  })

  it('takes on the left what the column’s right end cuts, so that a link at the end of a line keeps the least size', () => {
    const room = besideOf(row(380, 390), LEAST, [], column)
    expect(room.right).toBe(0)
    expect(10 + room.left, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
  })

  it('takes on the right what the column’s left end cuts', () => {
    const room = besideOf(row(0, 10), LEAST, [], column)
    expect(room.left).toBe(0)
    expect(10 + room.right, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
  })

  it('is the column when the column is narrower than the least size', () => {
    expect(besideOf(row(10, 20), LEAST, [], { left: 0, right: 30 })).toEqual({ left: 10, right: 10 })
  })

  it('keeps the box off a control beside it, to the control’s own edge', () => {
    const control: Neighbour = { box: row(120, 200), shares: false }
    const room = besideOf(row(100, 110), LEAST, [control], column)
    expect(room.right, 'the gap to the control, none of it left').toBe(10)
    expect(room.left, 'what the right side lacks is given on the left').toBeGreaterThanOrEqual(24)
    expect(10 + room.left + room.right, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
  })

  it('shares a gap with a link that takes room beside its own words in halves, where neither can have the least size', () => {
    const other: Neighbour = { box: row(130, 140), shares: true }
    // The column holds both within 5 px of their words: each lacks 34 px, and the 20 px between them are all there is.
    const room = besideOf(row(100, 110), LEAST, [other], { left: 95, right: 145 })
    expect(room.right, 'half of the 20 px between the words').toBe(10)
    expect(room.left, 'all of the room that the column leaves').toBe(5)
  })

  it('gives each of two short links the least size where the gap between them holds both', () => {
    const other: Neighbour = { box: row(130, 140), shares: true }
    const room = besideOf(row(100, 110), LEAST, [other], column)
    expect(10 + room.left + room.right, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
    expect(room.right, 'what the first takes of the gap, which leaves the second what it lacks of it').toBeLessThanOrEqual(20)
  })

  it('has no room on a side where another box touches the words, and is as wide as the room there is when both sides touch', () => {
    const before: Neighbour = { box: row(90, 100), shares: true }
    const after: Neighbour = { box: row(110, 120), shares: true }
    expect(besideOf(row(100, 110), LEAST, [before, after], column)).toEqual({ left: 0, right: 0 })
  })

  it('ignores a box that is above or below the line and does not reach the height of this one', () => {
    const above: Neighbour = { box: row(120, 200, 20), shares: false }
    const below: Neighbour = { box: row(120, 200, 144), shares: false }
    const room = besideOf(row(100, 110), LEAST, [above, below], column)
    expect(room.right, 'no box beside it on the right').toBeGreaterThan(10)
  })

  it('ignores a box whose words lie over this one’s across, which the room does not put it over any further', () => {
    const over: Neighbour = { box: row(90, 200, 120), shares: false }
    const room = besideOf(row(100, 110), LEAST, [over], column)
    expect(room.left).toBeGreaterThanOrEqual(17)
    expect(room.right).toBeGreaterThanOrEqual(17)
  })

  it('ignores a box whose words lie over this one’s across and reach out to its left, as it does one that reaches out to its right', () => {
    const over: Neighbour = { box: row(50, 120, 120), shares: false }
    const room = besideOf(row(100, 110), LEAST, [over], column)
    expect(room.left).toBeGreaterThanOrEqual(17)
    expect(room.right).toBeGreaterThanOrEqual(17)
  })

  it('does not go past a column that a link already lies outside of', () => {
    const room = besideOf(row(400, 410), LEAST, [], column)
    expect(room.right).toBe(0)
    expect(10 + room.left).toBeGreaterThanOrEqual(LEAST)
  })

  it('gives each link the same room whichever line’s links come first in the list, and the least size to every link of two lines that reach one another', () => {
    // Three links on the line at 20 and two on the line at 44; the boxes are 44 high, so the two lines reach one another and every link is short.
    const word = (left: number, right: number, top: number): Item => ({ box: { left, top, right, bottom: top + 44 }, link: true, column })
    const upper = [word(90.4375, 101.546875, 20), word(130.5625, 138.09375, 20), word(165.453125, 190.765625, 20)]
    const lower = [word(54.09375, 65.390625, 44), word(97.078125, 107.34375, 44)]
    const roomsOf = (items: readonly Item[]): Map<number, Beside> => {
      const rooms = packRooms(items, LEAST)
      return new Map(items.map((item, at) => [item.box.left, rooms[at] ?? { left: 0, right: 0 }]))
    }
    const upperFirst = roomsOf([...upper, ...lower])
    const lowerFirst = roomsOf([...lower, ...upper])
    for (const [order, rooms] of [['upper line first', upperFirst], ['lower line first', lowerFirst]] as const) {
      for (const item of [...upper, ...lower]) {
        const room = rooms.get(item.box.left) ?? { left: 0, right: 0 }
        expect(item.box.right - item.box.left + room.left + room.right, `${order}: the box of the link at ${String(item.box.left)}`).toBeGreaterThanOrEqual(LEAST)
      }
    }
    expect(lowerFirst, 'the rooms with the lower line first').toEqual(upperFirst)
  })
})

/** The words' box of each link and control that the made page has, by element. */
let words = new WeakMap<Element, { left: number; top: number; right: number; bottom: number }>()
/** The values that the made page's elements have for the properties the page reads, by element. */
let computed = new WeakMap<Element, Record<string, string>>()
/** The page's writes of a custom property of a link's room, as `setProperty` has them. */
let setter: MockInstance<(property: string, value: string | null) => void>
const writes = (): string[] =>
  setter.mock.calls.filter(([name]) => name.startsWith('--md-link')).map(([name, value]) => `${name}: ${String(value)}`)

/** What the page lays a link's box out as: its words' box grown by the room it has been given on each side, as the stylesheet grows it. */
function boxOf(element: Element): { left: number; top: number; right: number; bottom: number } {
  const own = words.get(element) ?? { left: 0, top: 0, right: 0, bottom: 0 }
  if (!(element instanceof HTMLElement) || !element.classList.contains('md-link')) return own
  const read = (name: string): number => parseFloat(element.style.getPropertyValue(name)) || 0
  return { ...own, left: own.left - read('--md-link-left'), right: own.right + read('--md-link-right') }
}

beforeEach(() => {
  words = new WeakMap()
  computed = new WeakMap()
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    const { left, top, right, bottom } = boxOf(this)
    return { left, top, right, bottom, x: left, y: top, width: right - left, height: bottom - top } as DOMRect
  })
  vi.spyOn(globalThis, 'getComputedStyle').mockImplementation(
    (element: Element) =>
      ({
        getPropertyValue: (name: string) => computed.get(element)?.[name] ?? (name === '--target' ? '44px' : ''),
        overflowX: computed.get(element)?.['overflow-x'] ?? 'visible'
      }) as unknown as CSSStyleDeclaration
  )
  setter = vi.spyOn(CSSStyleDeclaration.prototype, 'setProperty')
})

afterEach(() => {
  vi.restoreAllMocks()
  document.body.replaceChildren()
})

/** A pane of `rows` messages, 100 px apart, each as wide as the column; `build` puts what a message holds in it. */
function pane(rows: number, build: (message: HTMLElement, index: number) => void): { pane: HTMLElement; messages: HTMLElement[] } {
  const element = document.createElement('div')
  element.className = 'm-pane'
  const messages: HTMLElement[] = []
  for (let index = 0; index < rows; index += 1) {
    const message = document.createElement('div')
    message.className = 'm-node'
    words.set(message, { left: 0, top: index * 100, right: 390, bottom: index * 100 + 90 })
    build(message, index)
    messages.push(message)
    element.append(message)
  }
  document.body.append(element)
  return { pane: element, messages }
}

/** A link in `parent` whose words' box is from `left` to `right`, on the line at `top`; its box is 44 px high, as the stylesheet makes it. */
function link(parent: HTMLElement, left: number, right: number, top = 20): HTMLElement {
  const element = document.createElement('button')
  element.className = 'md-link'
  const base = words.get(parent)?.top ?? 0
  words.set(element, { left, top: base + top, right, bottom: base + top + 44 })
  parent.append(element)
  return element
}

function control(parent: HTMLElement, left: number, right: number, top = 20): HTMLElement {
  const element = document.createElement('button')
  const base = words.get(parent)?.top ?? 0
  words.set(element, { left, top: base + top, right, bottom: base + top + 44 })
  parent.append(element)
  return element
}

const given = (element: HTMLElement): { left: number; right: number } => ({
  left: parseFloat(element.style.getPropertyValue('--md-link-left')) || 0,
  right: parseFloat(element.style.getPropertyValue('--md-link-right')) || 0
})

describe('the room that the page gives the links of a message', () => {
  it('gives a short link the room it lacks of the least size and a wide link none', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      link(message, 200, 300)
    })
    fitLinks(root, messages)
    const [short, wide] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!short || !wide) throw new Error('the made page has no links')
    expect(10 + given(short).left + given(short).right, 'the short link’s box').toBeGreaterThanOrEqual(LEAST)
    expect(given(wide)).toEqual({ left: 0, right: 0 })
    expect(wide.style.getPropertyValue('--md-link-left'), 'a link with no room has no property').toBe('')
  })

  it('reads the words’ box of a link that it has given room before, so that the answer of a second read is the first’s and writes nothing', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      link(message, 130, 140)
      link(message, 380, 390)
    })
    fitLinks(root, messages)
    const first = root.querySelectorAll<HTMLElement>('.md-link')
    const rooms = Array.from(first).map(given)
    setter.mockClear()
    fitLinks(root, messages)
    expect(Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(given)).toEqual(rooms)
    expect(writes(), 'the writes of the second read').toEqual([])
  })

  it('shares the gap between two short links that cannot both have the least size, and keeps both boxes off each other', () => {
    // The first link is at the column's start and the second has a wide link on its other side: each lacks more than the 20 px gap holds.
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 0, 10)
      link(message, 30, 40)
      link(message, 40, 380)
    })
    fitLinks(root, messages)
    const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second) throw new Error('the made page has no links')
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
    expect(given(first).right).toBe(10)
    expect(given(second).left).toBe(10)
  })

  it('gives a short link the rest of a gap that its short neighbour needs less than half of, where a wide link holds its other side', () => {
    // S (30 px of words) needs 7 px on each side; L (9 px) has a wide link touching its right end. Halves of the gap would leave L at 39 px.
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 130)
      link(message, 190, 199)
      link(message, 199, 380)
    })
    fitLinks(root, messages)
    const [short, shared, wide] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!short || !shared || !wide) throw new Error('the made page has no links')
    expect(boxOf(shared).right - boxOf(shared).left, 'the box of the link whose gap its neighbour shares').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(short).right - boxOf(short).left, 'the box of its neighbour').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(short).right, 'the end of the neighbour’s box').toBeLessThanOrEqual(boxOf(shared).left)
    expect(boxOf(shared).right, 'the end of the box, at the wide link’s start').toBeLessThanOrEqual(199)
    expect(given(wide)).toEqual({ left: 0, right: 0 })
    setter.mockClear()
    fitLinks(root, messages)
    expect(writes(), 'the writes of a second read').toEqual([])
  })

  it('gives two short links the least size each where the gap between them holds both, and keeps their boxes apart', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      link(message, 130, 140)
    })
    fitLinks(root, messages)
    const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second) throw new Error('the made page has no links')
    expect(boxOf(first).right - boxOf(first).left, 'the first box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(second).right - boxOf(second).left, 'the second box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
  })

  // The two lines that read 2 of the review of the first fix: a link that the first fix left under the least size where non-overlapping boxes give it.
  it('completes a link that the room another one completed frees (the third link of a row of four)', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 142)
      link(message, 162, 172)
      link(message, 212, 222)
      link(message, 234, 380)
    })
    fitLinks(root, messages)
    const boxes = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
    for (const box of boxes.slice(0, 3)) expect(box.right - box.left, 'the box of a link that a row of four allows the least size').toBeGreaterThanOrEqual(LEAST)
    for (let at = 0; at + 1 < boxes.length; at += 1) expect((boxes[at] as { right: number }).right, `the end of box ${String(at)}`).toBeLessThanOrEqual((boxes[at + 1] as { left: number }).left)
  })

  it('completes both of two links that fit at exactly the least size, though the least size and the slack together would not fit', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 0, 9)
      link(message, 47, 56)
      link(message, 88, 380)
    })
    fitLinks(root, messages)
    const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second) throw new Error('the made page has no links')
    expect(boxOf(first).right - boxOf(first).left, 'the first box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(second).right - boxOf(second).left, 'the second box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
  })

  it('completes two short links on neighbouring lines whose heights reach each other, at 44 and at 48', () => {
    for (const [least, upper, lower] of [
      [44, [0, 9, 20], [58, 67, 44]],
      [48, [0, 9, 20], [58, 67, 44]],
      [44, [70, 79, 20], [0, 9, 42]],
      [48, [70, 79, 20], [0, 9, 42]]
    ] as const) {
      const { pane: root, messages } = pane(1, (message) => {
        link(message, upper[0], upper[1], upper[2])
        link(message, lower[0], lower[1], lower[2])
      })
      computed.set(root, { '--target': `${String(least)}px` })
      fitLinks(root, messages)
      const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
      if (!first || !second) throw new Error('the made page has no links')
      const label = `${String(least)}: words ${String(upper[0])} to ${String(upper[1])} above ${String(lower[0])} to ${String(lower[1])}`
      expect(first.right - first.left, `${label}, the upper box`).toBeGreaterThanOrEqual(least)
      expect(second.right - second.left, `${label}, the lower box`).toBeGreaterThanOrEqual(least)
      expect(first.right <= second.left || second.right <= first.left, `${label}, the boxes keep apart`).toBe(true)
      document.body.replaceChildren()
    }
  })

  it('completes `[2]` under `[1]` where a third link makes the group more than a row, at 44 and at 48', () => {
    // Each layout is the one of the neighbouring lines (`[1]` 70 to 79 above `[2]` 0 to 9) with one more link: over `[2]`, on a third line, or wide.
    const layouts: readonly (readonly (readonly [number, number, number])[])[] = [
      [[70, 79, 20], [0, 9, 42], [0, 30, 20]],
      [[70, 79, 20], [0, 9, 42], [200, 209, 64]],
      [[70, 79, 20], [0, 9, 42], [0, 60, 20]]
    ]
    for (const least of [44, 48]) {
      for (const layout of layouts) {
        const { pane: root, messages } = pane(1, (message) => {
          for (const [left, right, top] of layout) link(message, left, right, top)
        })
        computed.set(root, { '--target': `${String(least)}px` })
        fitLinks(root, messages)
        const boxes = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
        const label = `${String(least)}: ${JSON.stringify(layout)}`
        const [one, two] = [boxes[0], boxes[1]]
        if (!one || !two) throw new Error('the made page has no links')
        expect(one.right - one.left, `${label}, the box of [1]`).toBeGreaterThanOrEqual(least)
        expect(two.right - two.left, `${label}, the box of [2]`).toBeGreaterThanOrEqual(least)
        expect(one.right <= two.left || two.right <= one.left, `${label}, the boxes keep apart`).toBe(true)
        document.body.replaceChildren()
      }
    }
  })

  it('completes all three links of three lines that reach one line at a time (A 0 to 9, B 70 to 79, C 200 to 209), at 44 and at 48', () => {
    for (const [least, tops] of [
      [44, [20, 44, 68]],
      [48, [20, 46, 72]]
    ] as const) {
      const { pane: root, messages } = pane(1, (message) => {
        link(message, 0, 9, tops[0])
        link(message, 70, 79, tops[1])
        link(message, 200, 209, tops[2])
      })
      computed.set(root, { '--target': `${String(least)}px` })
      fitLinks(root, messages)
      const boxes = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
      boxes.forEach((box, at) => expect(box.right - box.left, `${String(least)}: the box of link ${String(at)}`).toBeGreaterThanOrEqual(least))
      for (let at = 0; at + 1 < boxes.length; at += 1) expect((boxes[at] as { right: number }).right, `the end of box ${String(at)}`).toBeLessThanOrEqual((boxes[at + 1] as { left: number }).left)
      document.body.replaceChildren()
    }
  })

  it('writes a change of one grid step in the room, so that a link whose words changed by 1/64 px keeps the least size', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 0, 9)
      link(message, 47, 56)
      link(message, 88, 380)
    })
    fitLinks(root, messages)
    const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second) throw new Error('the made page has no links')
    expect(given(first).right, 'the room of the first link').toBe(35)
    // The first link's words are 1/64 px narrower: it lacks 1/64 px more, and the page writes it.
    words.set(first, { left: 0, top: 20, right: 8.984375, bottom: 64 })
    fitLinks(root, messages)
    expect(given(first).right, 'the room after the words changed by one step').toBe(35.015625)
    expect(boxOf(first).right - boxOf(first).left, 'the box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
  })

  it('gives a completed link the least size where its box and the gap are held to the grid (a wide link over two short ones, a short one beside it)', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 40, 52, 0)
      link(message, 68, 104, 0)
      link(message, 30, 104, 24)
      link(message, 113.015625, 140, 24)
    })
    fitLinks(root, messages)
    const boxes = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
    expect((boxes[1] as { left: number; right: number }).right - (boxes[1] as { left: number }).left, 'the box of the link that the packing completes').toBeGreaterThanOrEqual(LEAST)
  })

  it('gives a completed link the least size where the column starts off the grid (a message padded by 0.3 px), at 44 and at 48', () => {
    // The first link's room on its left is what the column leaves it, 1.121875 px: held to the grid, with what it lacks rounded up to the grid.
    for (const [least, first, second] of [
      [44, [1.421875, 33.4375], [51.125, 67.6875]],
      [48, [1.421875, 37.4375], [55.125, 71.6875]]
    ] as const) {
      const { pane: root, messages } = pane(1, (message) => {
        computed.set(message, { 'padding-left': '0.3px' })
        link(message, first[0], first[1])
        link(message, second[0], second[1])
      })
      computed.set(root, { '--target': `${String(least)}px` })
      fitLinks(root, messages)
      const [one, two] = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
      if (!one || !two) throw new Error('the made page has no links')
      expect(one.right - one.left, `${String(least)}: the box of the first link`).toBeGreaterThanOrEqual(least)
      expect(two.right - two.left, `${String(least)}: the box of the second link`).toBeGreaterThanOrEqual(least)
      expect(one.right, `${String(least)}: the end of the first box`).toBeLessThanOrEqual(two.left)
      document.body.replaceChildren()
    }
  })

  it('gives a completed link the least size where the words are off the 1/64 grid, as a page zoom lays them out (what a link lacks, the gap to its neighbour)', () => {
    // A zoom moves the words off the grid that an engine lays out on. The first layout keeps the least size only where what a link lacks is rounded up to
    // the grid, the second only where the gap between two links is rounded down to it.
    for (const [label, start, words] of [
      ['what a link lacks', 0.4, [[4.3, 27.6], [47.6, 65.5]]],
      ['the gap between two links', 0.7, [[9.1, 24.1], [49.8, 75.8], [99.5, 116.3]]]
    ] as const) {
      const { pane: root, messages } = pane(1, (message) => {
        computed.set(message, { 'padding-left': `${String(start)}px` })
        for (const [left, right] of words) link(message, left, right)
      })
      fitLinks(root, messages)
      const boxes = Array.from(root.querySelectorAll<HTMLElement>('.md-link')).map(boxOf)
      boxes.forEach((box, at) => expect(box.right - box.left, `the rounding of ${label}: the box of link ${String(at)}`).toBeGreaterThanOrEqual(LEAST))
      for (let at = 0; at + 1 < boxes.length; at += 1) expect((boxes[at] as { right: number }).right, `the end of box ${String(at)}`).toBeLessThanOrEqual((boxes[at + 1] as { left: number }).left)
      document.body.replaceChildren()
    }
  })

  it('leaves a short link that cannot be completed the gap that a completed neighbour does not need of it', () => {
    // [8] has a wide link touching its left and 4 px to [9], which is completed and has the rest of the line on its right.
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 0, 100)
      link(message, 100, 108)
      link(message, 112, 121)
    })
    fitLinks(root, messages)
    const [, eight, nine] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!eight || !nine) throw new Error('the made page has no links')
    expect(boxOf(nine).right - boxOf(nine).left, 'the box of the completed link').toBeGreaterThanOrEqual(LEAST)
    expect(given(eight).right, 'the gap to the completed link, which it keeps').toBe(4)
  })

  it('moves a neighbour’s room to its far side where that frees the gap for the link beside a wide link', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 199)
      link(message, 199, 208)
      link(message, 248, 257)
    })
    fitLinks(root, messages)
    const [wide, first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!wide || !first || !second) throw new Error('the made page has no links')
    expect(given(wide)).toEqual({ left: 0, right: 0 })
    expect(boxOf(first).right - boxOf(first).left, 'the first box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(second).right - boxOf(second).left, 'the second box').toBeGreaterThanOrEqual(LEAST)
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
  })

  it('gives two short links at the start of a line the least size at 44 and at 48, the first against the column', () => {
    for (const least of [44, 48]) {
      computed.set(document.body, {})
      const { pane: root, messages } = pane(1, (message) => {
        link(message, 0, 9)
        link(message, 57.6, 66.6)
      })
      computed.set(root, { '--target': `${String(least)}px` })
      fitLinks(root, messages)
      const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
      if (!first || !second) throw new Error('the made page has no links')
      expect(boxOf(first).right - boxOf(first).left, `the first box at ${String(least)}`).toBeGreaterThanOrEqual(least)
      expect(boxOf(second).right - boxOf(second).left, `the second box at ${String(least)}`).toBeGreaterThanOrEqual(least)
      expect(boxOf(first).right, `the end of the first box at ${String(least)}`).toBeLessThanOrEqual(boxOf(second).left)
      document.body.replaceChildren()
    }
  })

  it('keeps a link’s box off a control beside it', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      control(message, 120, 200)
    })
    fitLinks(root, messages)
    const only = root.querySelector<HTMLElement>('.md-link')
    if (!only) throw new Error('the made page has no link')
    expect(boxOf(only).right).toBeLessThanOrEqual(120)
  })

  it('keeps the box inside the message’s column, giving the link at the end of a line what the end cuts on its left', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 380, 390)
    })
    fitLinks(root, messages)
    const only = root.querySelector<HTMLElement>('.md-link')
    if (!only) throw new Error('the made page has no link')
    expect(given(only).right).toBe(0)
    expect(boxOf(only).right - boxOf(only).left, 'the box').toBeGreaterThanOrEqual(LEAST)
  })

  it('keeps the box inside the content of a box that scrolls it sideways, where the link lies in one', () => {
    const { pane: root, messages } = pane(1, (message) => {
      const scroller = document.createElement('div')
      words.set(scroller, { left: 0, top: 0, right: 200, bottom: 90 })
      Object.defineProperty(scroller, 'scrollWidth', { configurable: true, value: 600 })
      Object.defineProperty(scroller, 'clientWidth', { configurable: true, value: 200 })
      computed.set(scroller, { 'overflow-x': 'auto' })
      message.append(scroller)
      link(scroller, 590, 600)
    })
    fitLinks(root, messages)
    const only = root.querySelector<HTMLElement>('.md-link')
    if (!only) throw new Error('the made page has no link')
    expect(given(only).right, 'no room past the end of what the box scrolls').toBe(0)
    expect(boxOf(only).right - boxOf(only).left, 'the box').toBeGreaterThanOrEqual(LEAST)
  })

  it('takes the room back from a link that has grown wide, and from one that is no longer drawn', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      link(message, 300, 310)
    })
    fitLinks(root, messages)
    const [grown, gone] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!grown || !gone) throw new Error('the made page has no links')
    expect(given(grown).left).toBeGreaterThan(0)
    words.set(grown, { left: 100, top: 20, right: 200, bottom: 64 })
    words.set(gone, { left: 0, top: 0, right: 0, bottom: 0 })
    fitLinks(root, messages)
    expect(given(grown), 'the link that has grown wide').toEqual({ left: 0, right: 0 })
    expect(given(gone), 'the link that is not drawn').toEqual({ left: 0, right: 0 })
  })

  it('reads the boxes of the message above and the one below as boxes that lie beside a link at the edge of its own', () => {
    const { pane: root, messages } = pane(2, (message, index) => {
      if (index === 0) control(message, 150, 250, 60)
      else link(message, 100, 110, 0)
    })
    const second = messages[1]
    if (!second) throw new Error('the made page has no second message')
    // The second message is 100 px lower: its link's box (44 high) reaches up to 100, and the control above it down to 104.
    fitLinks(root, [second])
    const only = root.querySelector<HTMLElement>('.md-link')
    if (!only) throw new Error('the made page has no link')
    expect(boxOf(only).right, 'the box ends at the control’s own edge').toBeLessThanOrEqual(150)
  })

  it('writes nothing where the pane has no least size', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
    })
    computed.set(root, { '--target': '' })
    fitLinks(root, messages)
    expect(writes()).toEqual([])
  })
})

describe('the page’s keeping of the room', () => {
  let frames: FrameRequestCallback[] = []
  let resized: ResizeObserverCallback | null = null
  let watched: Element[] = []

  beforeEach(() => {
    frames = []
    resized = null
    watched = []
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => frames.push(callback))
    vi.stubGlobal('cancelAnimationFrame', () => {
      frames = []
    })
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(callback: ResizeObserverCallback) {
          resized = callback
        }
        observe(target: Element): void {
          watched.push(target)
        }
        unobserve(target: Element): void {
          watched = watched.filter((each) => each !== target)
        }
        disconnect(): void {
          watched = []
        }
      }
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const frame = (): void => {
    const now = frames
    frames = []
    for (const callback of now) callback(0)
  }
  const mutations = (): Promise<void> => Promise.resolve()

  it('measures every message when it starts, in the next frame', () => {
    const { pane: root } = pane(2, (message) => {
      link(message, 100, 110)
    })
    const stop = startLinkFit(root)
    expect(given(root.querySelector<HTMLElement>('.md-link') as HTMLElement), 'before the frame').toEqual({ left: 0, right: 0 })
    frame()
    for (const each of root.querySelectorAll<HTMLElement>('.md-link')) expect(given(each).left, 'after the frame').toBeGreaterThan(0)
    stop()
  })

  it('measures a message that is added, and the one whose words change, once for the frame', async () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
    })
    const stop = startLinkFit(root)
    frame()
    setter.mockClear()
    const added = document.createElement('div')
    added.className = 'm-node'
    words.set(added, { left: 0, top: 100, right: 390, bottom: 190 })
    link(added, 200, 210, 20)
    root.append(added)
    await mutations()
    expect(frames.length, 'one frame asked for').toBe(1)
    frame()
    expect(given(added.querySelector<HTMLElement>('.md-link') as HTMLElement).left, 'the added message’s link').toBeGreaterThan(0)
    expect(watched, 'the added message is watched for its size').toContain(added)
    expect(writes().length, 'the writes for the added message’s link').toBeGreaterThan(0)
    // A link that no longer exists is not watched and the messages that are not changed are not read again.
    setter.mockClear()
    messages[0]?.remove()
    await mutations()
    frame()
    expect(watched, 'the message that left').not.toContain(messages[0])
    stop()
  })

  it('measures every message again when the pane is resized, and the one whose size changed alone when it is', () => {
    const { pane: root, messages } = pane(2, (message) => {
      link(message, 100, 110)
    })
    const stop = startLinkFit(root)
    frame()
    const links = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    for (const each of links) words.set(each, { ...(words.get(each) ?? { left: 0, top: 0, right: 0, bottom: 0 }), right: 300 })
    resized?.([{ target: messages[1] } as unknown as ResizeObserverEntry], {} as ResizeObserver)
    frame()
    expect(given(links[1]), 'the link of the message that changed size, now wide').toEqual({ left: 0, right: 0 })
    expect(given(links[0]).left, 'the link of the message that did not change size is left alone').toBeGreaterThan(0)
    resized?.([{ target: root } as unknown as ResizeObserverEntry], {} as ResizeObserver)
    frame()
    expect(given(links[0]), 'the pane resized: every message is read again').toEqual({ left: 0, right: 0 })
    stop()
  })

  it('measures a message again when an attribute moves its words with no change of size or text, and not for its own padding', async () => {
    // The first link is at the column's start and the second has a wide link on its other side: neither has the least size, and the first shares the gap.
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 0, 10)
      link(message, 30, 40)
      link(message, 40, 380)
    })
    const stop = startLinkFit(root)
    frame()
    await mutations()
    expect(frames.length, 'frames asked for by the hook’s own writes to the links’ style').toBe(0)
    const [first, second, wide] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second || !wide) throw new Error('the made page has no links')
    expect(given(first).right, 'the first link shares the gap with the second').toBe(10)
    // A cell's alignment moves the second link's words away with the message's size and text as they were.
    words.set(second, { left: 200, top: 20, right: 210, bottom: 64 })
    words.set(wide, { left: 210, top: 20, right: 380, bottom: 64 })
    messages[0]?.setAttribute('style', 'text-align: right')
    await mutations()
    expect(frames.length, 'one frame asked for by the attribute').toBe(1)
    frame()
    expect(given(first).right, 'the first link now has the room, the second being far').toBeGreaterThan(10)
    await mutations()
    expect(frames.length, 'frames asked for by the room that the hook wrote after the attribute').toBe(0)
    // A style of a link that is not its room is a change of the message's layout.
    first.style.fontSize = '30px'
    await mutations()
    expect(frames.length, 'one frame asked for by a style of the link that is no room').toBe(1)
    stop()
  })

  it('stops: a change after it is made is not measured', async () => {
    const { pane: root } = pane(1, (message) => {
      link(message, 100, 110)
    })
    const stop = startLinkFit(root)
    stop()
    frame()
    const added = document.createElement('div')
    added.className = 'm-node'
    words.set(added, { left: 0, top: 100, right: 390, bottom: 190 })
    link(added, 200, 210, 20)
    root.append(added)
    await mutations()
    expect(frames.length, 'frames asked for after the stop').toBe(0)
    expect(given(added.querySelector<HTMLElement>('.md-link') as HTMLElement)).toEqual({ left: 0, right: 0 })
  })
})
