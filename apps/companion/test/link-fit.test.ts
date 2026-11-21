/**
 * The room that a link of a message is given beside its words, as numbers and as the page applies it.
 *
 * `besideOf` is the rule, over rectangles alone. `fitLinks` and `startLinkFit` read a page's boxes and write
 * the custom properties that the stylesheet pads and takes back by: jsdom has no layout, so the page's
 * geometry is made here, and the box of a link is its words' box grown by the room it has been given, as the
 * stylesheet grows it. The browser cases (`e2e/accessibility.spec.ts`, "the box of a link in a message") hold
 * what the declarations do to a laid out page in both engines.
 */

import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { besideOf, fitLinks, startLinkFit, type Neighbour } from '../src/markdown/link-fit'

const LEAST = 44
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

  it('shares a gap with a link that takes room beside its own words in halves', () => {
    const other: Neighbour = { box: row(130, 140), shares: true }
    const room = besideOf(row(100, 110), LEAST, [other], column)
    expect(room.right, 'half of the 20 px between the words').toBe(10)
    expect(10 + room.left + room.right, 'the width of the box').toBeGreaterThanOrEqual(LEAST)
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

  it('does not go past a column that a link already lies outside of', () => {
    const room = besideOf(row(400, 410), LEAST, [], column)
    expect(room.right).toBe(0)
    expect(10 + room.left).toBeGreaterThanOrEqual(LEAST)
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

  it('shares the gap between two short links and keeps both boxes off each other', () => {
    const { pane: root, messages } = pane(1, (message) => {
      link(message, 100, 110)
      link(message, 130, 140)
    })
    fitLinks(root, messages)
    const [first, second] = Array.from(root.querySelectorAll<HTMLElement>('.md-link'))
    if (!first || !second) throw new Error('the made page has no links')
    expect(boxOf(first).right, 'the end of the first box').toBeLessThanOrEqual(boxOf(second).left)
    expect(given(first).right).toBe(10)
    expect(given(second).left).toBe(10)
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
