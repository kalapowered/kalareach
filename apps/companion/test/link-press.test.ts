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
/** Whether each of those listeners was added for the capture phase. */
const capturing = new Map<string, boolean>()
/** The links the handler opened: the clicks that the link's own element received. */
let opened: HTMLElement[] = []
/** The overflow that the made page's elements have, by axis; an element not named here does not clip. */
let overflows = new WeakMap<Element, { x: string; y: string }>()
/** The other computed properties that the made page's elements have, by CSS name (`transform`, `contain`, ...). */
let styles = new WeakMap<Element, Record<string, string>>()

const rectOf = (box: Box | undefined): DOMRect => {
  const { left, top, right, bottom } = box ?? { left: 0, top: 0, right: 0, bottom: 0 }
  return { left, top, right, bottom, x: left, y: top, width: right - left, height: bottom - top } as DOMRect
}

beforeEach(() => {
  boxes = new WeakMap()
  overflows = new WeakMap()
  styles = new WeakMap()
  reads = []
  opened = []
  listening.clear()
  capturing.clear()
  Object.defineProperty(window, 'visualViewport', { configurable: true, value: null })
  vi.spyOn(document, 'addEventListener').mockImplementation(((type: string, listener: EventListener, options?: boolean | AddEventListenerOptions) => {
    listening.set(type, listener)
    capturing.set(type, options === true || (typeof options === 'object' && options.capture === true))
  }) as typeof document.addEventListener)
  vi.spyOn(document, 'removeEventListener').mockImplementation(((type: string) => {
    listening.delete(type)
  }))
  // The window's own listeners (the blur) are kept where `fire` finds them; any other goes where it goes.
  const windowAdd = window.addEventListener.bind(window)
  const windowRemove = window.removeEventListener.bind(window)
  vi.spyOn(window, 'addEventListener').mockImplementation(((type: string, listener: EventListener, options?: boolean | AddEventListenerOptions) => {
    if (type === 'blur') listening.set('window blur', listener)
    else windowAdd(type, listener, options)
  }) as typeof window.addEventListener)
  vi.spyOn(window, 'removeEventListener').mockImplementation(((type: string, listener: EventListener, options?: boolean | EventListenerOptions) => {
    if (type === 'blur') listening.delete('window blur')
    else windowRemove(type, listener, options)
  }) as typeof window.removeEventListener)
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
  vi.spyOn(globalThis, 'getComputedStyle').mockImplementation(
    (element: Element) =>
      ({
        getPropertyValue: (name: string) => (name === '--target' ? '44px' : (styles.get(element)?.[name] ?? '')),
        overflowX: overflows.get(element)?.x ?? 'visible',
        overflowY: overflows.get(element)?.y ?? 'visible'
      }) as unknown as CSSStyleDeclaration
  )
  // jsdom has no hit test: the element at a point is the one whose made box holds it.
  Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: hitAt })
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
  Reflect.deleteProperty(document, 'elementFromPoint')
  document.body.replaceChildren()
})

/**
 * What the made page's hit test names at (`x`, `y`): an overlay, a control or a link whose made box holds
 * the point, else the text of a message.
 */
function hitAt(x: number, y: number): Element | null {
  for (const element of document.querySelectorAll('.overlay, .m-other, .md-link')) {
    const box = boxes.get(element)
    if (box !== undefined && x >= box.left && x <= box.right && y >= box.top && y <= box.bottom) return element
  }
  return document.querySelector('.m-node p') ?? document.body
}

/** An element with a made box, put in `parent`: `m-other` is a control that is not a link. */
function placed(parent: HTMLElement, className: string, box: Box, tag = 'button'): HTMLElement {
  const element = document.createElement(tag)
  element.className = className
  boxes.set(element, box)
  parent.append(element)
  return element
}

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

/**
 * Makes `element` clip its content on both axes (`overflow: auto` or `hidden`), with the client box that
 * a layout engine would give it.
 */
function clip(element: HTMLElement, box: Box, overflow = 'auto'): void {
  overflows.set(element, { x: overflow, y: overflow })
  boxes.set(element, box)
  clientBox(element, box.right - box.left, box.bottom - box.top)
}

/** The visual viewport of a page that is zoomed or has the keyboard up, in the layout viewport's coordinates. */
function viewportOf(box: Box): void {
  const target = {
    offsetLeft: box.left,
    offsetTop: box.top,
    width: box.right - box.left,
    height: box.bottom - box.top,
    addEventListener: (type: string, listener: EventListener) => {
      listening.set(`viewport ${type}`, listener)
    },
    removeEventListener: (type: string) => {
      listening.delete(`viewport ${type}`)
    }
  }
  Object.defineProperty(window, 'visualViewport', { configurable: true, value: target })
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
    expect(links[3]?.[0]?.hasAttribute('data-pressed'), 'the look before the move').toBe(true)
    fire('pointermove', pointer(texts[3], { clientY: y - 14 }))
    expect(links[3]?.[0]?.hasAttribute('data-pressed'), 'the look once the finger is past the slop').toBe(false)
    fire('pointermove', pointer(texts[3], { clientY: y }))
    expect(links[3]?.[0]?.hasAttribute('data-pressed'), 'the look when the finger is back where it started').toBe(false)
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
  it('puts every listener on the document: the click, the pointer down, and from a press to its end the move, up, cancel, lost capture, visibility change and scroll, the window’s blur and the visual viewport’s scroll and resize', () => {
    viewportOf({ left: 0, top: 0, right: 390, bottom: 844 })
    const { pane } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    const stop = start(pane)
    expect([...listening.keys()].sort()).toEqual(['click', 'pointerdown'])
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    expect([...listening.keys()].sort()).toEqual([
      'click',
      'lostpointercapture',
      'pointercancel',
      'pointerdown',
      'pointermove',
      'pointerup',
      'scroll',
      'viewport resize',
      'viewport scroll',
      'visibilitychange',
      'window blur'
    ])
    // Scroll events do not bubble, so only the capture phase on the document hears the scroll of every box.
    expect(capturing.get('scroll'), 'the scroll listener is in the capture phase').toBe(true)
    stop()
    expect([...listening.keys()]).toEqual([])
  })

  it('takes the scroll, viewport, capture, visibility and blur listeners off when the press ends: at the release, at a cancel, at a move past the slop, at a lost capture, at a blur and at a hidden page', () => {
    viewportOf({ left: 0, top: 0, right: 390, bottom: 844 })
    const { pane } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    const standing = (): string[] =>
      [...listening.keys()].filter((type) => type === 'scroll' || type.startsWith('viewport') || type === 'lostpointercapture' || type === 'window blur').sort()
    const during = ['lostpointercapture', 'scroll', 'viewport resize', 'viewport scroll', 'window blur']
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    expect(standing(), 'listeners during the press').toEqual(during)
    expect([...listening.keys()], 'the page’s visibility change is heard during the press').toContain('visibilitychange')
    fire('pointerup', pointer(pane, { clientX: 4, clientY: 25, timeStamp: 120 }))
    expect(standing(), 'listeners after the release').toEqual([])
    expect([...listening.keys()], 'visibility listener after the release').not.toContain('visibilitychange')
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    fire('pointercancel', pointer(pane, { clientX: 4, clientY: 25 }))
    expect(standing(), 'listeners after a cancel').toEqual([])
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    fire('pointermove', pointer(pane, { clientX: 4, clientY: 45 }))
    expect(standing(), 'listeners after a move past the slop').toEqual([])
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    fire('lostpointercapture', pointer(pane))
    expect(standing(), 'listeners after a lost capture').toEqual([])
    expect([...listening.keys()], 'visibility listener after a lost capture').not.toContain('visibilitychange')
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    fire('window blur', {} as Event)
    expect(standing(), 'listeners after a blur').toEqual([])
    expect([...listening.keys()], 'visibility listener after a blur').not.toContain('visibilitychange')
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
    fire('visibilitychange', {} as Event)
    expect(standing(), 'listeners after the page was hidden').toEqual([])
    expect([...listening.keys()], 'visibility listener after the page was hidden').not.toContain('visibilitychange')
  })

  it('registers no listener for a press that lights nothing, and the ends of a press leave none of any press standing', () => {
    viewportOf({ left: 0, top: 0, right: 390, bottom: 844 })
    const { pane } = between({ left: 0, top: 0, right: 8, bottom: 17 })
    start(pane)
    clock(100)
    const permanent = ['click', 'pointerdown']
    const standing = (): string[] => [...listening.keys()].sort()
    const unlit = { clientX: 300, clientY: 700 }
    const ends: [string, () => void][] = [
      ['a release', () => fire('pointerup', pointer(pane, { ...unlit, timeStamp: 120 }))],
      ['a cancel', () => fire('pointercancel', pointer(pane, unlit))],
      ['a move past the slop', () => fire('pointermove', pointer(pane, { clientX: 300, clientY: 650 }))],
      ['a lost capture', () => fire('lostpointercapture', pointer(pane))],
      ['a blur', () => fire('window blur', {} as Event)],
      [
        'a hidden page',
        () => {
          vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
          fire('visibilitychange', {} as Event)
        }
      ]
    ]
    for (const [end, make] of ends) {
      fire('pointerdown', pointer(pane, unlit))
      expect(standing(), `listeners during a press that lit nothing, before ${end}`).toEqual(permanent)
      make()
      expect(standing(), `listeners after ${end} of a press that lit nothing`).toEqual(permanent)
    }
    // A mouse press on plain text lights nothing either, and a press that lit a link and is replaced by one that lights nothing leaves no listener.
    fire('pointerdown', pointer(pane, { ...unlit, pointerType: 'mouse' }))
    expect(standing(), 'listeners during a mouse press on plain text').toEqual(permanent)
    fire('pointerdown', pointer(pane, { clientX: 4, clientY: 25 }))
    expect(standing(), 'listeners during a press that lit a link').not.toEqual(permanent)
    fire('pointerdown', pointer(pane, { ...unlit, pointerId: 2 }))
    expect(standing(), 'listeners after a press that lit nothing replaced a lit one').toEqual(permanent)
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

/** Moves every box of the made page up by `by`, as a scroll of the pane does. */
function scrolled(by: number): void {
  for (const element of document.querySelectorAll('.m-node, .md-link, .md-link-label, .m-other')) {
    const box = boxes.get(element)
    if (box !== undefined) boxes.set(element, { ...box, top: box.top - by, bottom: box.bottom - by })
  }
}

/** Moves every box of the made page left by `by`, as a sideways scroll of the pane does. */
function scrolledSideways(by: number): void {
  for (const element of document.querySelectorAll('.m-node, .md-link, .md-link-label, .m-other')) {
    const box = boxes.get(element)
    if (box !== undefined) boxes.set(element, { ...box, left: box.left - by, right: box.right - by })
  }
}

const isLit = (link: HTMLElement | undefined): boolean => link?.hasAttribute('data-pressed') === true

describe('a press for a pointer that can open, and the look it gives', () => {
  // The first link of message 3 has its words at x 10 to 26 and y 320 to 337; the tap is 6 px before it.
  const y = 328

  it('lights nothing for a mouse or trackpad press on plain text, and its click opens nothing', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y, pointerType: 'mouse' }))
    expect(isLit(links[3]?.[0]), 'the look of a mouse press on plain text beside a link').toBe(false)
    fire('pointerup', pointer(texts[3], { clientY: y, pointerType: 'mouse', timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('lights the link for a pen press on plain text beside it, and its click opens it', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y, pointerType: 'pen' }))
    expect(isLit(links[3]?.[0]), 'the look of a pen press').toBe(true)
    fire('pointerup', pointer(texts[3], { clientY: y, pointerType: 'pen', timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([links[3]?.[0]])
  })

  it('lights the link for a mouse press on the link’s own element, where the browser sends its click', () => {
    const { pane, links } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[3]?.[0], { clientX: 18, clientY: 328, pointerType: 'mouse' }))
    expect(isLit(links[3]?.[0]), 'the look of a mouse press on the link').toBe(true)
    fire('pointerup', pointer(links[3]?.[0], { clientX: 18, clientY: 328, pointerType: 'mouse', timeStamp: 120 }))
    expect(isLit(links[3]?.[0]), 'the look after the release').toBe(false)
  })

  it('ends the look of a press at the next primary press, which lights nothing on plain text far from a link', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    expect(isLit(links[3]?.[0]), 'the look of the first press').toBe(true)
    fire('pointerdown', pointer(texts[1], { pointerId: 2, clientX: 300, clientY: 150 }))
    expect(isLit(links[3]?.[0]), 'the look after the next press').toBe(false)
  })

  it('ends the look of a press at a next press outside the pane, and lights nothing for it', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    expect(isLit(links[3]?.[0]), 'the look of the first press').toBe(true)
    fire('pointerdown', pointer(document.body, { pointerId: 2, clientX: 5, clientY: 5 }))
    expect(isLit(links[3]?.[0]), 'the look after a press outside the pane').toBe(false)
  })

  it('clears the record of a press that the engine’s own click handled when the next press comes outside the pane, so a later click on plain text opens nothing', () => {
    // The release's click names a control, so the handler leaves the record in place; the next press, outside
    // the pane, ends it. A trusted click of detail 1 on plain text then, within the three seconds and near the
    // old press (an assistive technology's, which no press precedes), finds no record to use.
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(links[3]?.[1], { clientY: y }))
    expect(opened, 'opens by the handler for a click that named a link').toEqual([])
    fire('pointerdown', pointer(document.body, { clientY: 700 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened, 'links opened by a click on plain text after a press outside the pane').toEqual([])
  })

  it('lights nothing for a press outside the pane, though a link of the pane lies under its point', () => {
    const { pane, links } = between({ left: 100, top: 100, right: 140, bottom: 117 })
    start(pane)
    clock(100)
    const outside = document.createElement('div')
    document.body.append(outside)
    fire('pointerdown', pointer(outside, { clientX: 120, clientY: 125 }))
    expect(isLit(links[0]), 'the look for a press outside the pane').toBe(false)
  })

  it('keeps a press when another pointer moves, and ends it when its own pointer moves past the slop', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointermove', pointer(texts[3], { pointerId: 2, clientY: y - 40 }))
    expect(isLit(links[3]?.[0]), 'the look after another finger moved').toBe(true)
    fire('pointermove', pointer(texts[3], { clientY: y - 40 }))
    expect(isLit(links[3]?.[0]), 'the look after its own finger moved').toBe(false)
  })

  it('keeps a press for a move of 9 px and ends it for a move of 11 px, the slop being 10', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    fire('pointermove', pointer(texts[3], { clientY: y - 9 }))
    expect(isLit(links[3]?.[0]), 'the look after 9 px').toBe(true)
    fire('pointermove', pointer(texts[3], { clientY: y - 11 }))
    expect(isLit(links[3]?.[0]), 'the look after 11 px').toBe(false)
  })
})

describe('the look of a mouse press on a link’s own element as the pointer moves', () => {
  // The words and the element at x 100 to 140, y 100 to 117; the press is 2 px inside the right edge.
  const words = { left: 100, top: 100, right: 140, bottom: 117 }
  const mouse = (x: number, over: Record<string, unknown> = {}): Record<string, unknown> => ({ clientX: x, clientY: 108, pointerType: 'mouse', ...over })

  it('goes out where the pointer leaves the element within the slop, is lit again where it returns, and a release outside opens nothing', () => {
    const { pane, text, links } = between(words)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], mouse(138)))
    expect(isLit(links[0]), 'the look of the press').toBe(true)
    fire('pointermove', pointer(text, mouse(143)))
    expect(isLit(links[0]), 'the look 5 px to the right, outside the element').toBe(false)
    fire('pointermove', pointer(links[0], mouse(138)))
    expect(isLit(links[0]), 'the look back inside the element').toBe(true)
    fire('pointermove', pointer(text, mouse(143)))
    expect(isLit(links[0]), 'the look outside again').toBe(false)
    fire('pointerup', pointer(text, mouse(143, { timeStamp: 120 })))
    fire('click', click(text, { clientX: 143, clientY: 108 }))
    expect(isLit(links[0]), 'the look after the release').toBe(false)
    expect(opened).toEqual([])
  })

  it('measures the slop from the press’s first point, not from the last one', () => {
    const { pane, text, links } = between(words)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], mouse(138)))
    fire('pointermove', pointer(text, mouse(147)))
    expect(isLit(links[0]), 'the look 9 px to the right').toBe(false)
    fire('pointermove', pointer(links[0], mouse(129)))
    expect(isLit(links[0]), 'the look 9 px to the left of the first point, inside the element').toBe(true)
    fire('pointermove', pointer(links[0], mouse(127)))
    expect(isLit(links[0]), 'the look 11 px to the left: the press has ended').toBe(false)
    fire('pointermove', pointer(links[0], mouse(138)))
    expect(isLit(links[0]), 'the look back at the first point: an ended press is not lit again').toBe(false)
  })

  it('goes out where the pointer moves into the part of the element that a box clips, and is lit again where it leaves that part', () => {
    const { pane, text, links } = between(words)
    clip(text, { left: 0, top: 0, right: 120, bottom: 844 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], mouse(116)))
    expect(isLit(links[0]), 'the look of the press inside the clip').toBe(true)
    fire('pointermove', pointer(links[0], mouse(122)))
    expect(isLit(links[0]), 'the look at x 122: inside the element’s rectangle, past the clip').toBe(false)
    fire('pointermove', pointer(links[0], mouse(118)))
    expect(isLit(links[0]), 'the look at x 118, inside the clip').toBe(true)
  })

  it('is lit again where a scroll brings the element under the pointer that left it', () => {
    const { pane, text, links } = between(words)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], mouse(138)))
    fire('pointermove', pointer(text, mouse(143)))
    expect(isLit(links[0]), 'the look outside the element').toBe(false)
    scrolledSideways(-4)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a scroll that put the element’s edge past the pointer').toBe(true)
  })

  for (const pointerType of ['touch', 'pen']) {
    it(`keeps the look of a ${pointerType} press for a move within the slop, where the press’s own element ends: nothing changes for it`, () => {
      const { pane, text, links } = between(words)
      start(pane)
      clock(100)
      fire('pointerdown', pointer(links[0], mouse(138, { pointerType })))
      reads = []
      fire('pointermove', pointer(text, mouse(143, { pointerType })))
      expect(isLit(links[0]), `the look of a ${pointerType} 5 px to the right`).toBe(true)
      expect(reads, `the boxes read at the move of a ${pointerType}`).toEqual([])
      // A release comes from the press's first point: a scroll of 1 px leaves the element under it, though the pointer is past it.
      scrolledSideways(1)
      fire('scroll', {} as Event)
      expect(isLit(links[0]), `the look of a ${pointerType} after a scroll that leaves the element under the first point`).toBe(true)
    })
  }
})

describe('a scroll under a held press', () => {
  const y = 328

  it('ends the look and the press where the link has moved away from the press’s point: nothing opens', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    expect(isLit(links[3]?.[0]), 'the look before the scroll').toBe(true)
    scrolled(200)
    fire('scroll', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after a scroll that moved the link 200 px').toBe(false)
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([])
  })

  it('leaves the look and the open where the link still wins the press’s point: 3 px', () => {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    scrolled(3)
    fire('scroll', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after a scroll of 3 px').toBe(true)
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
    expect(opened).toEqual([links[3]?.[0]])
  })

  it('is asked again for the visual viewport’s scroll and for its resize as for a scroll of a box', () => {
    for (const type of ['viewport scroll', 'viewport resize']) {
      const { pane, links, texts } = conversation(6, 3)
      viewportOf({ left: 0, top: 0, right: 390, bottom: 600 })
      const stop = start(pane)
      clock(100)
      fire('pointerdown', pointer(texts[3], { clientY: y }))
      scrolled(200)
      fire(type, {} as Event)
      expect(isLit(links[3]?.[0]), `the look after the ${type}`).toBe(false)
      stop()
      document.body.replaceChildren()
      listening.clear()
    }
  })

  it('keeps the look of a press on the strip that only the link’s own button holds while the button lies under the point, and ends it when it does not', () => {
    // The largest text size: the words end 8 px above the button's own edge, where the rule holds no point.
    const { pane, links } = between({ left: 100, top: 100, right: 140, bottom: 156 })
    boxes.set(links[0], { left: 100, top: 92, right: 140, bottom: 164 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 120, clientY: 95 }))
    expect(isLit(links[0]), 'the look on the strip').toBe(true)
    scrolled(3)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a scroll of 3 px: the button still lies under the point').toBe(true)
    scrolled(80)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a scroll that took the button away').toBe(false)
  })

  it('ends the look of a press on a link’s own element when the link no longer lies under the press’s point', () => {
    const { pane, links } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[3]?.[0], { clientX: 18, clientY: 328, pointerType: 'mouse' }))
    scrolled(3)
    fire('scroll', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after a scroll of 3 px: the link is still under the point').toBe(true)
    scrolled(200)
    fire('scroll', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after a scroll of 200 px more').toBe(false)
  })

  it('ends the look of a mouse press on a link’s own element at a sideways scroll of 15 px, though the nearest-words rule still holds the point', () => {
    // The words at x 100 to 140, the press 2 px inside their right end. After the scroll the element ends
    // 13 px before the point, inside the 22 px that the rule reaches beside the words, but a mouse's click
    // on plain text opens nothing, so nothing can open from the point.
    const { pane, text, links } = between({ left: 100, top: 100, right: 140, bottom: 117 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 138, clientY: 108, pointerType: 'mouse' }))
    expect(isLit(links[0]), 'the look of the press').toBe(true)
    scrolledSideways(15)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a sideways scroll of 15 px').toBe(false)
    fire('pointerup', pointer(text, { clientX: 138, clientY: 108, pointerType: 'mouse', timeStamp: 120 }))
    fire('click', click(text, { clientX: 138, clientY: 108 }))
    expect(opened).toEqual([])
  })

  it('ends the look of a mouse press on a link’s own element at a vertical scroll of 20 px that leaves the point past the button, under the rule’s added reach', () => {
    // The largest text size: the button (y 96 to 120) is taller than the words (y 100 to 117). The press is at
    // y 108.5. After the scroll the button ends at y 100 and the area of the words still reaches y 110.5.
    const { pane, links } = between({ left: 100, top: 100, right: 140, bottom: 117 })
    boxes.set(links[0], { left: 100, top: 96, right: 140, bottom: 120 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 120, clientY: 108.5, pointerType: 'mouse' }))
    expect(isLit(links[0]), 'the look of the press').toBe(true)
    scrolled(20)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a scroll of 20 px').toBe(false)
  })

  it('ends the look of a press on a link’s own element when an outer scroll takes the point out of the part of the element that is in view', () => {
    // The link (y 150 to 167) is cut at y 155 by its box. The press is at y 152, in view. An outer scroll
    // of 10 px moves the link and its box together: the link's own rectangle still holds y 152, the part of
    // it in view (to y 145) does not.
    const { pane, text, links } = between({ left: 100, top: 150, right: 140, bottom: 167 })
    clip(text, { left: 0, top: 100, right: 390, bottom: 155 }, 'hidden')
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 120, clientY: 152, pointerType: 'mouse' }))
    expect(isLit(links[0]), 'the look of the press').toBe(true)
    scrolled(10)
    clip(text, { left: 0, top: 90, right: 390, bottom: 145 }, 'hidden')
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after an outer scroll that hides the point').toBe(false)
  })

  it('ends the look of a press on a link’s own element when an outer scroll takes the point out of the part of it that the box leaves in view, at the box’s left, right and top edges', () => {
    // Each link straddles its box's edge; the press is in view. An outer scroll moves the link and its box
    // together, so the point stays in the link's own rectangle and leaves what the box shows of it.
    const scenarios = [
      { edge: 'left', words: { left: 100, top: 100, right: 140, bottom: 117 }, box: { left: 110, top: 0, right: 300, bottom: 400 }, at: { clientX: 120, clientY: 108 }, move: () => scrolledSideways(-15), after: { left: 125, top: 0, right: 315, bottom: 400 } },
      { edge: 'right', words: { left: 100, top: 100, right: 140, bottom: 117 }, box: { left: 0, top: 0, right: 130, bottom: 400 }, at: { clientX: 120, clientY: 108 }, move: () => scrolledSideways(15), after: { left: -15, top: 0, right: 115, bottom: 400 } },
      { edge: 'top', words: { left: 100, top: 150, right: 140, bottom: 167 }, box: { left: 0, top: 160, right: 390, bottom: 400 }, at: { clientX: 120, clientY: 162 }, move: () => scrolled(-10), after: { left: 0, top: 170, right: 390, bottom: 410 } }
    ]
    for (const scenario of scenarios) {
      const { pane, text, links } = between(scenario.words)
      clip(text, scenario.box, 'hidden')
      start(pane)
      clock(100)
      fire('pointerdown', pointer(links[0], { ...scenario.at, pointerType: 'mouse' }))
      expect(isLit(links[0]), `the look of the press at the box’s ${scenario.edge} edge`).toBe(true)
      scenario.move()
      clip(text, scenario.after, 'hidden')
      fire('scroll', {} as Event)
      expect(isLit(links[0]), `the look after an outer scroll at the box’s ${scenario.edge} edge`).toBe(false)
      document.body.replaceChildren()
      listening.clear()
    }
  })

  it('ends the look of a press on a link’s own element when a box that the view cannot be measured through comes around it', () => {
    const { pane, text, links } = between({ left: 100, top: 100, right: 140, bottom: 117 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 120, clientY: 108, pointerType: 'mouse' }))
    expect(isLit(links[0]), 'the look of the press').toBe(true)
    styles.set(text.parentElement as HTMLElement, { transform: 'matrix(0.5, 0, 0, 0.5, 0, 0)' })
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after the box was scaled').toBe(false)
  })

  it('keeps the look of a touch press on a link’s own element while the rule still names it, and the release on plain text opens it', () => {
    const { pane, text, links } = between({ left: 100, top: 100, right: 140, bottom: 117 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(links[0], { clientX: 138, clientY: 108 }))
    scrolledSideways(15)
    fire('scroll', {} as Event)
    expect(isLit(links[0]), 'the look after a sideways scroll of 15 px').toBe(true)
    fire('pointerup', pointer(text, { clientX: 138, clientY: 108, timeStamp: 120 }))
    fire('click', click(text, { clientX: 138, clientY: 108 }))
    expect(opened).toEqual([links[0]])
  })

  describe('that puts another element under the point of a touch press on plain text, where the rule still names the link', () => {
    // The words at x 100 to 140, y 100 to 117. The press is on plain text 10 px before them and 6 px above, in
    // the 22 px that the rule reaches. The elements below lie at y 97 to 113, so the point is above them.
    const words = { left: 100, top: 100, right: 140, bottom: 117 }
    const press = { clientX: 90, clientY: 94 }
    const beside = { left: 60, top: 97, right: 96, bottom: 113 }

    it('ends the look where a control that is not a link comes under the point, and keeps it where the control still lies below it: the button of an image that loads', () => {
      const { pane, text, links } = between(words)
      const button = placed(text, 'm-other', beside)
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, press))
      expect(isLit(links[0]), 'the look of the press on plain text').toBe(true)
      scrolled(2)
      fire('scroll', {} as Event)
      expect(isLit(links[0]), 'the look after a scroll of 2 px: the button still lies below the point').toBe(true)
      scrolled(2)
      fire('scroll', {} as Event)
      expect(boxes.get(button)?.top, 'the button’s top after 4 px').toBe(93)
      expect(isLit(links[0]), 'the look after a scroll of 4 px: the button lies under the point').toBe(false)
      fire('pointerup', pointer(button, { ...press, timeStamp: 120 }))
      fire('click', click(button, press))
      expect(opened, 'the click on the button opens no link').toEqual([])
    })

    it('ends the look where another link comes under the point', () => {
      const { pane, text, links } = between(words)
      // A link that no message holds, so the rule does not weigh it.
      const other = placed(pane, 'md-link m-other', beside)
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, press))
      expect(isLit(links[0]), 'the look of the press').toBe(true)
      scrolled(4)
      fire('scroll', {} as Event)
      expect(boxes.get(other)?.top, 'the other link’s top after 4 px').toBe(93)
      expect(isLit(links[0]), 'the look after a scroll that put another link under the point').toBe(false)
    })

    it('ends the look where an element outside the pane comes under the point, since a release there is not the pane’s', () => {
      const { pane, text, links } = between(words)
      const overlay = placed(document.body, 'overlay', { left: 0, top: 200, right: 390, bottom: 844 }, 'div')
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, press))
      expect(isLit(links[0]), 'the look of the press').toBe(true)
      boxes.set(overlay, { left: 0, top: 80, right: 390, bottom: 844 })
      scrolled(2)
      fire('scroll', {} as Event)
      expect(isLit(links[0]), 'the look after an overlay came under the point').toBe(false)
    })
  })
})

describe('a press whose release can no longer come', () => {
  const y = 328

  /** A touch press on plain text beside the first link of message 3, lit. */
  function held(): { links: HTMLElement[][]; texts: HTMLElement[] } {
    const { pane, links, texts } = conversation(6, 3)
    start(pane)
    clock(100)
    fire('pointerdown', pointer(texts[3], { clientY: y }))
    expect(isLit(links[3]?.[0]), 'the look of the press').toBe(true)
    return { links, texts }
  }

  /** The release that follows, and the click that the engine sends for it. */
  function released(texts: HTMLElement[]): void {
    fire('pointerup', pointer(texts[3], { clientY: y, timeStamp: 120 }))
    fire('click', click(texts[3], { clientY: y }))
  }

  it('ends the look when the pointer’s capture is lost, and opens nothing', () => {
    const { links, texts } = held()
    fire('lostpointercapture', pointer(texts[3], { pointerId: 2 }))
    expect(isLit(links[3]?.[0]), 'the look after another pointer lost its capture').toBe(true)
    fire('lostpointercapture', pointer(texts[3]))
    expect(isLit(links[3]?.[0]), 'the look after the press’s own pointer lost its capture').toBe(false)
    released(texts)
    expect(opened).toEqual([])
  })

  it('ends the look when the window loses focus, and opens nothing', () => {
    const { links, texts } = held()
    fire('window blur', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after the window’s blur').toBe(false)
    released(texts)
    expect(opened).toEqual([])
  })

  it('ends the look when the page is hidden, and leaves it for a change that leaves the page shown', () => {
    const { links, texts } = held()
    const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
    fire('visibilitychange', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after a visibility change that leaves the page shown').toBe(true)
    hidden.mockReturnValue(true)
    fire('visibilitychange', {} as Event)
    expect(isLit(links[3]?.[0]), 'the look after the page was hidden').toBe(false)
    released(texts)
    expect(opened).toEqual([])
  })
})

describe('a link’s view: what the boxes that clip it leave of the page', () => {
  it('shows no link whose words an inner box hides wholly, where the pane does not clip them', () => {
    // Pane (0,0) to (390,844); the inner box (40,100) to (350,160); the words (22,120) to (30,137); the tap at (45,145).
    const { pane, text, links } = between({ left: 22, top: 120, right: 30, bottom: 137 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 45, clientY: 145 }))
    expect(isLit(links[0]), 'the look with no inner box: the tap is in the area').toBe(true)
    fire('pointerup', pointer(text, { clientX: 45, clientY: 145, timeStamp: 120 }))
    clip(text, { left: 40, top: 100, right: 350, bottom: 160 }, 'hidden')
    fire('pointerdown', pointer(text, { clientX: 45, clientY: 145 }))
    expect(isLit(links[0]), 'the look with the inner box').toBe(false)
    fire('pointerup', pointer(text, { clientX: 45, clientY: 145, timeStamp: 120 }))
    fire('click', click(text, { clientX: 45, clientY: 145 }))
    expect(opened).toEqual([])
  })

  it('keeps what an inner box leaves of a link that it cuts: a tap in the visible room lights it, a tap in the cut does not', () => {
    const { pane, text, links } = between({ left: 30, top: 120, right: 60, bottom: 137 })
    clip(text, { left: 40, top: 100, right: 350, bottom: 160 }, 'auto')
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 45, clientY: 145 }))
    expect(isLit(links[0]), 'the look for a tap inside the inner box').toBe(true)
    fire('pointerup', pointer(text, { clientX: 45, clientY: 145, timeStamp: 120 }))
    fire('click', click(text, { clientX: 45, clientY: 145 }))
    expect(opened).toEqual([links[0]])
    opened = []
    fire('pointerdown', pointer(text, { clientX: 35, clientY: 128 }))
    expect(isLit(links[0]), 'the look for a tap left of the inner box').toBe(false)
    fire('pointerup', pointer(text, { clientX: 35, clientY: 128, timeStamp: 120 }))
    fire('click', click(text, { clientX: 35, clientY: 128 }))
    expect(opened).toEqual([])
  })

  it('shows no link below an inner box whose bottom lies above the pane’s: the nearest box on each edge clips', () => {
    const { pane, text, links } = between({ left: 100, top: 170, right: 140, bottom: 187 })
    clip(text, { left: 40, top: 100, right: 350, bottom: 160 }, 'hidden')
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 120, clientY: 178 }))
    expect(isLit(links[0]), 'the look for a tap under the inner box').toBe(false)
  })

  it('shows no link beyond an inner box’s right edge or above its top edge, where the pane’s own edges lie farther out', () => {
    for (const [name, words, tap] of [
      ['right of the box', { left: 360, top: 120, right: 380, bottom: 137 }, { clientX: 346, clientY: 128 }],
      ['above the box', { left: 100, top: 70, right: 140, bottom: 87 }, { clientX: 120, clientY: 96 }]
    ] as const) {
      const { pane, text, links } = between(words)
      clip(text, { left: 40, top: 100, right: 350, bottom: 160 }, 'hidden')
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, tap))
      expect(isLit(links[0]), `the look for a tap beside a link ${name}`).toBe(false)
      fire('pointerup', pointer(text, { ...tap, timeStamp: 120 }))
      document.body.replaceChildren()
    }
  })

  it('shows no link that the visual viewport of a zoomed page has left off the screen', () => {
    // Zoomed 2x: the visual viewport shows x 195 to 390 and y 0 to 422 of the layout; the words end at x 191.
    const { pane, text, links } = between({ left: 183, top: 100, right: 191, bottom: 117 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 200, clientY: 108 }))
    expect(isLit(links[0]), 'the look before the page is zoomed').toBe(true)
    fire('pointerup', pointer(text, { clientX: 200, clientY: 108, timeStamp: 120 }))
    viewportOf({ left: 195, top: 0, right: 390, bottom: 422 })
    fire('pointerdown', pointer(text, { clientX: 200, clientY: 108 }))
    expect(isLit(links[0]), 'the look on the zoomed page').toBe(false)
    fire('pointerup', pointer(text, { clientX: 200, clientY: 108, timeStamp: 120 }))
    fire('click', click(text, { clientX: 200, clientY: 108 }))
    expect(opened).toEqual([])
  })

  it('shows no link below the room of a scroller outside the pane, as the keyboard leaves it', () => {
    // The scroller holds the pane and ends at y 500: the keyboard takes the rest. The pane is as tall as before.
    const { pane, text, links } = between({ left: 100, top: 510, right: 140, bottom: 527 }, { left: 100, top: 470, right: 140, bottom: 487 })
    const scroller = document.createElement('div')
    document.body.append(scroller)
    scroller.append(pane)
    clip(scroller, { left: 0, top: 0, right: 390, bottom: 500 }, 'auto')
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 120, clientY: 530 }))
    expect(isLit(links[0]), 'the look for a tap under the hidden link').toBe(false)
    fire('pointerup', pointer(text, { clientX: 120, clientY: 530, timeStamp: 120 }))
    fire('pointerdown', pointer(text, { clientX: 120, clientY: 495 }))
    expect(isLit(links[1]), 'the look for a tap under the link in view').toBe(true)
  })

  it('does not take an ancestor that does not clip for a box, and reads each clipping ancestor once in a read', () => {
    const { pane, text } = between({ left: 100, top: 100, right: 140, bottom: 117 }, { left: 160, top: 100, right: 200, bottom: 117 })
    const wrapper = document.createElement('div')
    text.parentElement?.append(wrapper)
    wrapper.append(text)
    boxes.set(wrapper, { left: 500, top: 500, right: 501, bottom: 501 })
    clip(text, { left: 0, top: 0, right: 390, bottom: 844 }, 'auto')
    start(pane)
    clock(100)
    reads = []
    fire('pointerdown', pointer(text, { clientX: 150, clientY: 125 }))
    expect(reads.filter((read) => read === text).length, 'reads of the clipping ancestor for two links').toBe(1)
    expect(reads.filter((read) => read === wrapper).length, 'reads of an ancestor that does not clip').toBe(0)
    expect(isLit(wrapper.querySelector('.md-link') as HTMLElement)).toBe(true)
  })
})

describe('a link under a box whose view cannot be measured', () => {
  // The words (22,120) to (30,137) in a box of the pane's size; the tap at (45,145) is in their area.
  const words = { left: 22, top: 120, right: 30, bottom: 137 }
  const tap = { clientX: 45, clientY: 145 }

  /** Every kind of box that the view cannot be measured through, by the computed properties it has. */
  const blocking: Record<string, Record<string, string>> = {
    'a scale': { transform: 'matrix(0.5, 0, 0, 0.5, 0, 0)' },
    'a rotation': { transform: 'matrix(0.8, 0.6, -0.6, 0.8, 0, 0)' },
    'a skew': { transform: 'matrix(1, 0, 0.5, 1, 0, 0)' },
    'a 3D scale': { transform: 'matrix3d(0.5, 0, 0, 0, 0, 0.5, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1)' },
    'a 3D rotation': { transform: 'matrix3d(1, 0, 0, 0, 0, 0.8, 0.6, 0, 0, -0.6, 0.8, 0, 0, 0, 0, 1)' },
    'a scale down the page only': { transform: 'matrix(1, 0, 0, 0.5, 0, 0)' },
    'a 3D matrix that scales through its last entry': { transform: 'matrix3d(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2)' },
    'a transform in a form that is not a matrix': { transform: 'scale(0.5)' },
    'the separate scale property': { scale: '0.5' },
    'the separate rotate property': { rotate: '10deg' },
    'contain: paint': { contain: 'paint' },
    'contain: strict': { contain: 'strict' },
    'contain: content': { contain: 'content' },
    'contain: layout paint': { contain: 'layout paint' },
    'content-visibility: auto': { 'content-visibility': 'auto' },
    'content-visibility: hidden': { 'content-visibility': 'hidden' }
  }

  it('gives a hidden link no area, as the scaled box of the review shows: a box of 200 by 100 at half size hides words that its client box would show', () => {
    // The box lies at (40,100) to (140,150) on the screen and has a client box of 200 by 100, so a handler
    // that laid the client size over the screen origin would see (40,100) to (240,200). The hidden words
    // are at (146,120) to (154,129) and the tap at (138,140), in the area that those words would have.
    const { pane, text, links } = between({ left: 146, top: 120, right: 154, bottom: 129 })
    boxes.set(text, { left: 40, top: 100, right: 140, bottom: 150 })
    clientBox(text, 200, 100)
    overflows.set(text, { x: 'hidden', y: 'hidden' })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 138, clientY: 140 }))
    expect(isLit(links[0]), 'the look with a box that has no transform').toBe(true)
    fire('pointerup', pointer(text, { clientX: 138, clientY: 140, timeStamp: 120 }))
    fire('click', click(text, { clientX: 138, clientY: 140 }))
    expect(opened, 'opens with a box that has no transform').toEqual([links[0]])
    opened = []
    styles.set(text, { transform: 'matrix(0.5, 0, 0, 0.5, 0, 0)' })
    fire('pointerdown', pointer(text, { clientX: 138, clientY: 140 }))
    expect(isLit(links[0]), 'the look under the scaled box').toBe(false)
    fire('pointerup', pointer(text, { clientX: 138, clientY: 140, timeStamp: 120 }))
    fire('click', click(text, { clientX: 138, clientY: 140 }))
    expect(opened, 'opens under the scaled box').toEqual([])
  })

  for (const [kind, style] of Object.entries(blocking)) {
    it(`gives a link no area under a box with ${kind}: it never lights by the rule and is never opened`, () => {
      const { pane, text, links } = between(words)
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, tap))
      expect(isLit(links[0]), `the look with no ${kind}`).toBe(true)
      fire('pointerup', pointer(text, { ...tap, timeStamp: 120 }))
      styles.set(text.parentElement as HTMLElement, style)
      fire('pointerdown', pointer(text, tap))
      expect(isLit(links[0]), `the look under ${kind}`).toBe(false)
      fire('pointerup', pointer(text, { ...tap, timeStamp: 120 }))
      fire('click', click(text, tap))
      expect(opened, `opens under ${kind}`).toEqual([])
    })
  }

  it('finds such a box wherever it lies between the link and the root: the pane and the page’s root', () => {
    for (const where of ['the pane', 'the root']) {
      const { pane, text, links } = between(words)
      start(pane)
      clock(100)
      styles.set(where === 'the pane' ? pane : document.documentElement, { contain: 'paint' })
      fire('pointerdown', pointer(text, tap))
      expect(isLit(links[0]), `the look under ${where} with contained paint`).toBe(false)
      styles.delete(document.documentElement)
      document.body.replaceChildren()
      listening.clear()
    }
  })

  it('measures a box that only moves its content: a translation, in 2D and in 3D, lights and opens as a box with no transform', () => {
    for (const transform of ['matrix(1, 0, 0, 1, 12, 8)', 'matrix3d(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 12, 8, 4, 1)', 'none']) {
      const { pane, text, links } = between(words)
      start(pane)
      clock(100)
      styles.set(text.parentElement as HTMLElement, { transform, 'content-visibility': 'visible', contain: 'layout style', scale: 'none', rotate: 'none' })
      fire('pointerdown', pointer(text, tap))
      expect(isLit(links[0]), `the look under ${transform}`).toBe(true)
      fire('pointerup', pointer(text, { ...tap, timeStamp: 120 }))
      fire('click', click(text, tap))
      expect(opened, `opens under ${transform}`).toEqual([links[0]])
      opened = []
      document.body.replaceChildren()
      listening.clear()
    }
  })

  it('leaves a press on the link’s own element as on a page with no handler under such a box: no look, and the click is the browser’s alone', () => {
    const { pane, text, links } = between(words)
    start(pane)
    clock(100)
    styles.set(text.parentElement as HTMLElement, { transform: 'matrix(0.5, 0, 0, 0.5, 0, 0)' })
    fire('pointerdown', pointer(links[0], { clientX: 26, clientY: 128 }))
    expect(isLit(links[0]), 'the look of a press on the link’s own element').toBe(false)
    fire('pointerup', pointer(links[0], { clientX: 26, clientY: 128, timeStamp: 120 }))
    fire('click', click(links[0], { clientX: 26, clientY: 128 }))
    expect(opened, 'the handler’s own opens').toEqual([])
  })
})

describe('a page whose root clips', () => {
  it('takes the root’s client box, wherever the page has scrolled, for what is in view: the root’s own rectangle moves with the page', () => {
    // The page has scrolled by 300 px, so the root's rectangle lies at y -300 to 1544; its client box is the
    // viewport, 390 by 844. A link at y 600 to 617 is in view of the viewport and below the rectangle's client part.
    const root = document.documentElement
    overflows.set(root, { x: 'auto', y: 'auto' })
    boxes.set(root, { left: 0, top: -300, right: 390, bottom: 1544 })
    clientBox(root, 390, 844)
    try {
      const { pane, text, links } = between({ left: 100, top: 600, right: 140, bottom: 617 })
      start(pane)
      clock(100)
      fire('pointerdown', pointer(text, { clientX: 150, clientY: 608 }))
      expect(isLit(links[0]), 'the look of a press beside a link in view of the viewport').toBe(true)
    } finally {
      for (const key of ['clientLeft', 'clientTop', 'clientWidth', 'clientHeight']) Reflect.deleteProperty(root, key)
    }
  })
})

describe('a link in a line wider than its message', () => {
  it('has an area where the pane has been scrolled sideways by more than the reach: the message’s box is tested on the vertical axis only', () => {
    // The message's box is as wide as the stream and the pane has scrolled 200 px to the right: the
    // message now lies at x -200 to 190, and an unbroken run still shows a link at x 300 to 330.
    const { pane, text, links } = between({ left: 300, top: 100, right: 330, bottom: 117 })
    boxes.set(text.parentElement as HTMLElement, { left: -200, top: 0, right: 190, bottom: 844 })
    start(pane)
    clock(100)
    fire('pointerdown', pointer(text, { clientX: 336, clientY: 108 }))
    expect(isLit(links[0]), 'the look for a tap 6 px after the words').toBe(true)
    fire('pointerup', pointer(text, { clientX: 336, clientY: 108, timeStamp: 120 }))
    fire('click', click(text, { clientX: 336, clientY: 108 }))
    expect(opened).toEqual([links[0]])
  })
})
