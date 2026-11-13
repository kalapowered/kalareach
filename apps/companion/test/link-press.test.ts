/**
 * The handler of a message's links, driven through the listeners it registers on the document.
 *
 * The browser cases run it on real input where an engine gives trusted input; what they cannot reach
 * is stated and held here: a press that moves where WebKit has no tool to move a touch, a click that
 * no press made (no engine sends one), the time a page was busy before the handler saw the release, and
 * the number of boxes the handler reads. The page's geometry is made: a conversation of messages one
 * above the other, each with links in a row, and every box read is counted.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { startLinkPress } from '../src/markdown/link-press'

interface Box {
  readonly left: number
  readonly top: number
  readonly right: number
  readonly bottom: number
}

/** The boxes the made page has, and every element or range whose box was read. */
let boxes = new WeakMap<Element, Box>()
let reads: Element[] = []
/** The listeners the handler has on the document now, by event type. */
const listening = new Map<string, EventListener>()
/** The links the handler opened: the clicks that the link's own element received. */
let opened: HTMLElement[] = []

const rectOf = (box: Box | undefined): DOMRect => {
  const { left, top, right, bottom } = box ?? { left: 0, top: 0, right: 0, bottom: 0 }
  return { left, top, right, bottom, x: left, y: top, width: right - left, height: bottom - top } as DOMRect
}

beforeEach(() => {
  boxes = new WeakMap()
  reads = []
  opened = []
  listening.clear()
  vi.spyOn(document, 'addEventListener').mockImplementation(((type: string, listener: EventListener) => {
    listening.set(type, listener)
  }) as typeof document.addEventListener)
  vi.spyOn(document, 'removeEventListener').mockImplementation(((type: string) => {
    listening.delete(type)
  }))
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    reads.push(this)
    return rectOf(boxes.get(this))
  })
  // jsdom's `MouseEvent` takes only its own window as a view, and the test's global `window` is not it.
  const Made = MouseEvent
  vi.stubGlobal(
    'MouseEvent',
    class extends Made {
      constructor(type: string, init: MouseEventInit = {}) {
        super(type, { ...init, view: null })
      }
    }
  )
  vi.spyOn(globalThis, 'getComputedStyle').mockReturnValue({ getPropertyValue: () => '44px' } as unknown as CSSStyleDeclaration)
  // jsdom has no layout: the words of a link are the box that the made page gives its label.
  Object.defineProperty(Range.prototype, 'getClientRects', {
    configurable: true,
    value(this: Range) {
      const label = this.commonAncestorContainer as Element
      reads.push(label)
      return [rectOf(boxes.get(label))]
    }
  })
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.body.replaceChildren()
})

/** A conversation: `count` messages 100 px apart, each with `each` links in a row 18 px apart. */
function conversation(count: number, each: number): { pane: HTMLElement; messages: HTMLElement[]; links: HTMLElement[][]; texts: HTMLElement[] } {
  const pane = document.createElement('div')
  boxes.set(pane, { left: 0, top: 0, right: 390, bottom: count * 100 })
  clientBox(pane, 390, count * 100)
  const messages: HTMLElement[] = []
  const links: HTMLElement[][] = []
  const texts: HTMLElement[] = []
  for (let m = 0; m < count; m += 1) {
    const message = document.createElement('div')
    message.className = 'm-node'
    boxes.set(message, { left: 0, top: m * 100, right: 390, bottom: m * 100 + 90 })
    const text = document.createElement('p')
    message.append(text)
    const row: HTMLElement[] = []
    for (let l = 0; l < each; l += 1) {
      const link = document.createElement('button')
      link.className = 'md-link'
      link.title = `https://example.org/${String(m)}-${String(l)}`
      const label = document.createElement('span')
      label.className = 'md-link-label'
      link.append(label)
      const box = { left: 10 + l * 18, top: m * 100 + 20, right: 26 + l * 18, bottom: m * 100 + 37 }
      boxes.set(link, box)
      boxes.set(label, box)
      link.addEventListener('click', () => {
        opened.push(link)
      })
      text.append(link)
      row.push(link)
    }
    pane.append(message)
    messages.push(message)
    links.push(row)
    texts.push(text)
  }
  document.body.append(pane)
  return { pane, messages, links, texts }
}

function pointer(target: EventTarget, over: Record<string, unknown> = {}): Event {
  return { isPrimary: true, button: 0, pointerId: 1, pointerType: 'touch', clientX: 4, clientY: 0, timeStamp: 0, target, ...over } as unknown as Event
}

function click(target: EventTarget, over: Record<string, unknown> = {}): Event {
  return { isTrusted: true, detail: 1, clientX: 4, clientY: 0, screenX: 4, screenY: 0, target, ...over } as unknown as Event
}

const fire = (type: string, event: Event): void => {
  ;(listening.get(type) ?? listening.get(`pane ${type}`))?.(event)
}

/** The pane's own client box, as a layout engine has it: the box less a border and a scroll bar's strip. */
function clientBox(pane: HTMLElement, width: number, height: number, border = 0): void {
  Object.defineProperties(pane, {
    clientLeft: { configurable: true, value: border },
    clientTop: { configurable: true, value: border },
    clientWidth: { configurable: true, value: width },
    clientHeight: { configurable: true, value: height }
  })
}

/** Starts the handler on `pane`, and keeps the pane's own listeners where `fire` finds them. */
function start(pane: HTMLElement): () => void {
  vi.spyOn(pane, 'addEventListener').mockImplementation(((type: string, listener: EventListener) => {
    listening.set(`pane ${type}`, listener)
  }) as typeof pane.addEventListener)
  vi.spyOn(pane, 'removeEventListener').mockImplementation(((type: string) => {
    listening.delete(`pane ${type}`)
  }))
  return startLinkPress(pane)
}

/** The clock, as the handler reads it: the next readings are `times`, and the last one stays. */
function clock(...times: number[]): void {
  const queue = [...times]
  vi.spyOn(performance, 'now').mockImplementation(() => (queue.length > 1 ? (queue.shift() ?? 0) : (queue[0] ?? 0)))
}

describe('a tap on plain text beside a link, through the handler', () => {
  // The first link of message 3 has its words at x 10 to 26 and y 320 to 337; the tap is 6 px before it.
  const y = 328

  it('opens the link once for the press, and a second trusted click with no new press opens nothing', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([links[3]?.[0]])
    fire('click', click(texts[3], { clientY: y }))
    expect(opened.length, 'links opened by a second click').toBe(1)
  })

  it('opens nothing for a touch that moved beyond the slop, though no pointer cancel came', () => {
    const { pane, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointermove', pointer(texts[3], { clientY: y - 14 }))
    fire('pointerup', pointer(texts[3], { clientY: y - 14, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('opens nothing for a touch whose release is beyond the slop though no move was seen', () => {
    const { pane, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y - 14, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('opens nothing for a touch that moved and came back within the slop at the release', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointermove', pointer(texts[3], { clientY: y - 14 }))
    fire('pointermove', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened, 'a press that went past the slop is not a tap').toEqual([])
    expect(links.length).toBe(6)
  })

  it('opens nothing after a pointer cancel, and the pressed look goes with it', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    expect(links[3]?.[0]?.hasAttribute('data-pressed'), 'the pressed look during the press').toBe(true)
    fire('pointercancel', pointer(texts[3], { clientY: y }))
    expect(links[3]?.[0]?.hasAttribute('data-pressed'), 'the pressed look after the cancel').toBe(false)
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('opens nothing for a click that no press made', () => {
    const { pane, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })
})

/** One message holding links with the given boxes (the words are the box), in a pane of the phone's size. */
function between(...wordsOf: Box[]): { pane: HTMLElement; text: HTMLElement; links: HTMLElement[] } {
  const pane = document.createElement('div')
  boxes.set(pane, { left: 0, top: 0, right: 390, bottom: 844 })
  clientBox(pane, 390, 844)
  const message = document.createElement('div')
  message.className = 'm-node'
  boxes.set(message, { left: 0, top: 0, right: 390, bottom: 844 })
  const text = document.createElement('p')
  const links = wordsOf.map((box, index) => {
    const link = document.createElement('button')
    link.className = 'md-link'
    link.title = `https://example.org/${String(index)}`
    const label = document.createElement('span')
    label.className = 'md-link-label'
    link.append(label)
    boxes.set(link, box)
    boxes.set(label, box)
    link.addEventListener('click', () => {
      opened.push(link)
    })
    text.append(link)
    return link
  })
  message.append(text)
  pane.append(message)
  document.body.append(pane)
  return { pane, text, links }
}

describe('a tap between two links, through the handler', () => {
  it('lights and opens neither where the words of a link just past the least size are nearer than the words of the link whose area holds the point', () => {
    // Link A's words stand at the pane's corner, so its area is given back to 52 by 44 and holds the
    // point (51, 43), 50.25 px from its words. Link B's words start 47 px to the right of the point,
    // beyond the least size, and its own area does not hold it: B's words are nearer, so the point is no link's.
    const { pane, text, links } = between({ left: 0, top: 0, right: 8, bottom: 17 }, { left: 98, top: 43, right: 106, bottom: 60 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 51, clientY: 43 }))
    expect(links.map((link) => link.hasAttribute('data-pressed')), 'the links lit at the press').toEqual([false, false])
    fire('pointerup', pointer(text, { clientX: 51, clientY: 43, timeStamp: 120 }))
    fire('click', click(text, { clientX: 51, clientY: 43 }))
    expect(opened, 'links opened by the click').toEqual([])
  })

  it('reads the links near the press’s point at the click, though the engine reported the click 20 px from it', () => {
    // The press is at the edge of the corner link's area (50.25 px from its words); the click is reported 20 px farther, where
    // the link's box lies just beyond the radius of 62.2 px: the layout read at the click's point would leave the link out.
    const { pane, text, links } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 51, clientY: 43 }))
    fire('pointerup', pointer(text, { clientX: 51, clientY: 43, timeStamp: 120 }))
    fire('click', click(text, { clientX: 71, clientY: 43 }))
    expect(opened).toEqual([links[0]])
  })

  it('still gives the point to the link at the corner when no other link’s words are nearer', () => {
    const { pane, text, links } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 51, clientY: 43 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit at the press').toBe(true)
    fire('pointerup', pointer(text, { clientX: 51, clientY: 43, timeStamp: 120 }))
    fire('click', click(text, { clientX: 51, clientY: 43 }))
    expect(opened).toEqual([links[0]])
  })
})

describe('where the handler’s listeners stand', () => {
  it('puts every listener on the document: the click, the pointer down, and the move, up and cancel from a press to its end', () => {
    const { pane } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    const stop = start(pane)
    expect([...listening.keys()].sort()).toEqual(['click', 'pointerdown'])
    fire('pointerdown', pointer(pane, { clientX: 51, clientY: 43 }))
    expect([...listening.keys()].sort()).toEqual(['click', 'pointercancel', 'pointerdown', 'pointermove', 'pointerup'])
    stop()
    expect([...listening.keys()]).toEqual([])
  })

  it('opens a link for a tap on the pane’s bare area, where no message lies', () => {
    const { pane, links } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(pane, { clientX: 40, clientY: 30 }))
    fire('pointerup', pointer(pane, { clientX: 40, clientY: 30, timeStamp: 120 }))
    fire('click', click(pane, { clientX: 40, clientY: 30 }))
    expect(opened).toEqual([links[0]])
  })

  it('leaves a click outside the pane alone', () => {
    const { pane, links } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(pane, { clientX: 40, clientY: 30 }))
    fire('pointerup', pointer(pane, { clientX: 40, clientY: 30, timeStamp: 120 }))
    fire('click', click(document.body, { clientX: 40, clientY: 30 }))
    expect(opened).toEqual([])
    expect(links.length).toBe(1)
  })
})

describe('what a press lights', () => {
  // The largest text size: the words of a link are 56 px tall and its button's box is 72 px tall, 8 px
  // more above and below, where the browser still sends the click to the button.
  const words = { left: 100, top: 100, right: 140, bottom: 156 }
  const own = { left: 100, top: 92, right: 140, bottom: 164 }

  it('is the link whose own element the press is on, though the words’ rectangles do not hold the point', () => {
    const { pane, links } = between(words)
    boxes.set(links[0], own)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 120, clientY: 95 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press 5 px above its words, on its own button').toBe(true)
    fire('pointerup', pointer(links[0], { clientX: 120, clientY: 95, timeStamp: 120 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit after the release').toBe(false)
  })

  it('is no link on plain text that the words’ rectangles do not hold', () => {
    const { pane, text, links } = between(words)
    boxes.set(links[0], own)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 120, clientY: 95 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press on plain text above its words').toBe(false)
  })

  it('is nothing for a press on a control of the message', () => {
    const { pane, text, links } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    const control = document.createElement('button')
    text.append(control)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(control, { clientX: 4, clientY: 8 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press on a control').toBe(false)
  })
})

describe('what the handler takes for the pane', () => {
  it('is its client box: a press in the scroll bar’s strip lights nothing and its click opens nothing', () => {
    // The pane's box is 390 wide and the scroll bar takes 15 px of it: the link at the end of a line ends at x 375.
    const { pane, text, links } = between({ left: 340, top: 100, right: 375, bottom: 117 })
    clientBox(pane, 375, 844)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(pane, { clientX: 372, clientY: 108 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press at x 372, inside the client box').toBe(true)
    fire('pointerup', pointer(pane, { clientX: 372, clientY: 108, timeStamp: 120 }))
    fire('click', click(pane, { clientX: 372, clientY: 108 }))
    expect(opened).toEqual([links[0]])
    opened = []
    fire('pointerdown', pointer(pane, { clientX: 380, clientY: 108 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press at x 380, in the scroll bar’s strip').toBe(false)
    fire('pointerup', pointer(pane, { clientX: 380, clientY: 108, timeStamp: 120 }))
    fire('click', click(pane, { clientX: 380, clientY: 108 }))
    expect(opened, 'links opened by a click in the strip').toEqual([])
    expect(text.isConnected).toBe(true)
  })

  it('is placed by the pane’s border: the client box starts inside it', () => {
    const { pane, links } = between({ left: 10, top: 10, right: 40, bottom: 27 })
    boxes.set(pane, { left: 0, top: 0, right: 390, bottom: 844 })
    clientBox(pane, 388, 842, 2)
    start(pane)
    clock(100)
    // The words start 8 px inside the client box's left edge (x 2): a press at x 1 is on the border.
    fire('pointerdown', pointer(pane, { clientX: 1, clientY: 18 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press on the border').toBe(false)
    fire('pointerup', pointer(pane, { clientX: 1, clientY: 18, timeStamp: 120 }))
    fire('pointerdown', pointer(pane, { clientX: 3, clientY: 18 }))
    expect(links[0]?.hasAttribute('data-pressed'), 'the link lit by a press just inside the border').toBe(true)
  })
})

describe('the three seconds after the release', () => {
  const y = 328

  it('count from the release, not from when the handler saw it: a page that was busy for 4 s gives its click no link', () => {
    const { pane, texts } = conversation(6, 3)
    start(pane)
    // The release at 1010 ms, which the busy page's handler sees at 5000 ms; the click comes right after.
    clock(5000, 5001)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 1010 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('give the click a link when the page was busy for less: 1.7 s', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    // The release at 1010 ms, seen at 2710 ms; the click comes right after.
    clock(2710, 2711)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 1010 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([links[3]?.[0]])
  })

  it('take a release stamped after the clock’s own reading as made at that reading', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(1010, 1011)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 9000 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([links[3]?.[0]])
  })
})

describe('the boxes the handler reads', () => {
  const y = 328

  it('are none where the pane holds no message at all: the terminal and the output views', () => {
    const pane = document.createElement('div')
    const rows = document.createElement('div')
    for (let row = 0; row < 200; row += 1) rows.append(document.createElement('div'))
    pane.append(rows)
    document.body.append(pane)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(rows, { clientY: 50 }))
    fire('pointerup', pointer(rows, { clientY: 50, timeStamp: 120 }))
    fire('click', click(rows, { clientY: 50 }))
    expect(reads, 'boxes read for a press and a click on a pane with no message').toEqual([])
    expect(vi.mocked(globalThis.getComputedStyle)).not.toHaveBeenCalled()
  })

  it('are the pane, the messages and the near messages’ links for a conversation of 1200 links, not every link', () => {
    const { pane, messages, links, texts } = conversation(60, 20)
    start(pane)
    clock(100)
    // Message 30 is under the press; message 29 ends 38 px above it, inside the radius of 62.2 px that the rule weighs, and
    // message 31 starts 66 px below.
    fire('pointerdown', pointer(texts[30], { clientY: y + 2700 }))
    // The pane's box, a box for each of the 60 messages, the box of each of the 40 links of messages 29 and 30,
    // and the words of the 4 links of message 30 that lie within the radius beside the press.
    const bound = 1 + messages.length + 2 * 20 + 4
    expect(reads.length, 'boxes read by the press').toBeLessThanOrEqual(bound)
    expect(reads.length, 'boxes read by the press, against every link').toBeLessThan(links.flat().length / 4)
    const readLinks = new Set(reads.filter((each) => each.classList.contains('md-link')))
    // Only the 4 links of message 30 that lie within the radius beside the press have their words read.
    expect(reads.filter((each) => each.classList.contains('md-link-label')).length, 'links whose words were read by the press').toBe(4)
    expect(readLinks.has(links[10]?.[0]), 'a link of a message far from the press').toBe(false)
    expect(readLinks.has(links[31]?.[0]), 'a link of a message beyond the reach under the press').toBe(false)
    fire('pointerup', pointer(texts[30], { clientY: y + 2700, timeStamp: 120 }))
    reads = []
    fire('click', click(texts[30], { clientY: y + 2700 }))
    expect(reads.length, 'boxes read by the click').toBeLessThanOrEqual(bound)
  })

  it('are the pane, the message and each of its links where one message holds 1200 links: the bound is the message’s, not the near links’', () => {
    const { pane, texts } = conversation(1, 1200)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[0], { clientX: 4, clientY: 28 }))
    // The pane's box, the message's box, the box of each of its 1200 links (all of them lie in the message that is near the
    // press), and the words of the 4 links within the radius of 62.2 px of the press: 1206 reads for a press and for a click.
    expect(reads.length, 'boxes read by the press').toBe(1 + 1 + 1200 + 4)
    fire('pointerup', pointer(texts[0], { clientX: 4, clientY: 28, timeStamp: 120 }))
    reads = []
    fire('click', click(texts[0], { clientX: 4, clientY: 28 }))
    expect(reads.length, 'boxes read by the click').toBe(1 + 1 + 1200 + 4)
  })

  it('are none where the conversation holds messages and no link', () => {
    const pane = document.createElement('div')
    for (let m = 0; m < 30; m += 1) {
      const message = document.createElement('div')
      message.className = 'm-node'
      message.append(document.createElement('p'))
      pane.append(message)
    }
    document.body.append(pane)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(pane.querySelector('p') as HTMLElement, { clientY: 50 }))
    expect(reads, 'boxes read for a press on a conversation with no link').toEqual([])
  })
})
