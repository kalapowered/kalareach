/**
 * The tap record of the test harness.
 *
 * Whether a tap on a message's link opens it depends on the events the platform sends for a finger
 * on the glass: which target the pointer events have, whether a click follows, what it names, with
 * what detail, and from which pointer.
 * A test that drives the application on a device taps by coordinates and cannot see the page's
 * events, so this puts them on the page as text, which the device's accessibility tree carries: the
 * events the page saw, the rectangles of the links' words, the links the host opened and where the
 * focus is. It is started by the strip, which also fills the first session with the messages the taps
 * need. The harness bundle is built only for tests, so none of this ships.
 *
 * The record listens on the document, in the capture phase, as the pane's own tap handling does, so
 * that it adds nothing the platform counts as a click listener on the page's content.
 */

import { useEffect, type ReactNode } from 'react'

import type { FakeHostControls } from './host/fake'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/**
 * What the taps need on the conversation: two table rows, text after a link, a link with another on
 * the next line, the control of an image that has not been loaded with a link on the next line, a link
 * in the middle of a line with no other link near, a link at the start and one at the end of a line,
 * room to scroll, and a link on the conversation's last line.
 */
const TAP_MESSAGES: readonly string[] = [
  ['| Item | Notes |', '| --- | --- |', '| one | [first notes](https://example.org/table-1) |', '| two | [second notes](https://example.org/table-2) |'].join('\n'),
  '[docs](https://example.org/docs) and more words follow the link on this line, which ends the paragraph.',
  '[the upper link](https://example.org/upper)  \n[the lower link](https://example.org/lower) is under it.',
  '![a picture](https://example.org/picture.png)  \n[a link under the image](https://example.org/under-image)',
  'Plain words above a link that has no other link near it, in a paragraph of their own.',
  'Plain words, a second paragraph above the link.',
  'See [it](https://example.org/middle) now',
  'Plain words under the link, a paragraph of their own, with no other link near the one above.',
  '[1](https://example.org/at-start) then plain words after the link at the start of the line.',
  'Plain words before the link at the end of the line, [2](https://example.org/at-end)',
  ...Array.from(
    { length: 16 },
    (_, index) => `Plain words in paragraph ${String(index + 1)}, which holds no link, so that the conversation is longer than the screen and scrolls.`
  ),
  'The last words of the conversation end with [a link](https://example.org/last-line)'
]

/** Puts the messages of the taps on the first session. */
export function fillForTaps(controls: FakeHostControls): void {
  // The link at the end of a line has its words end at the pane's right edge, as a full line's last word does.
  const style = document.createElement('style')
  style.textContent = ".m-node p:has(.md-link[title$='at-end']) { text-align: justify; text-align-last: justify; }"
  document.head.append(style)
  for (const message of TAP_MESSAGES) controls.records.appendEntry(SESSION, 'message', message)
  document.dispatchEvent(new Event('visibilitychange'))
}

/** How many events the record keeps. */
const KEPT = 24

/** The last part of an address, which names a link. */
const nameOf = (address: string): string => address.slice(address.lastIndexOf('/') + 1)

/** What an event's target is, in a few characters: the tag, the first class, and a link's name. */
const describe = (target: EventTarget | null): string => {
  if (!(target instanceof Element)) return 'none'
  const name = target.tagName.toLowerCase() + (target.classList[0] ? `.${target.classList[0]}` : '')
  const link = target.closest<HTMLElement>('.md-link')
  return link ? `${name}(${nameOf(link.title)})` : name
}

const round = (value: number): string => (Math.round(value * 10) / 10).toString()

/** The record, as lines of text on the page: the events, the links' rectangles, the links opened and the focus. */
export function TapRecord({ controls }: { readonly controls: FakeHostControls }): ReactNode {
  useEffect(() => {
    const seen: string[] = []
    let order = 0
    const log = document.getElementById('kr-taps-log')
    const places = document.getElementById('kr-taps-links')
    const opened = document.getElementById('kr-taps-opened')
    const focus = document.getElementById('kr-taps-focus')
    if (!log || !places || !opened || !focus) return undefined
    const show = (): void => {
      const rectangles = Array.from(document.querySelectorAll<HTMLElement>('.m-node .md-link'), (link) => {
        const box = link.getBoundingClientRect()
        const range = document.createRange()
        range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
        const words = Array.from(range.getClientRects())
          .filter((rect) => rect.width > 0 && rect.height > 0)
          .map((rect) => [rect.left, rect.top, rect.right, rect.bottom].map(round).join(' '))
          .join(' ')
        const line = parseFloat(getComputedStyle(link).lineHeight)
        return `L ${nameOf(link.title)} box ${[box.left, box.top, box.right, box.bottom].map(round).join(' ')} words ${words} line ${round(Number.isFinite(line) ? line : 0)}`
      })
      const scroller = document.querySelector('.m-pane')
      const room = scroller?.getBoundingClientRect()
      const pane = room && scroller
        ? `P ${[room.left, room.top, room.right, room.bottom, scroller.scrollTop, scroller.scrollHeight - scroller.clientHeight].map(round).join(' ')}`
        : 'P 0 0 0 0 0 0'
      const texts: [HTMLElement, string][] = [
        [log, `TAPLOG ${seen.join(' ; ')}`],
        [places, `TAPLINKS ${[pane, ...rectangles].join(' ; ')}`],
        [opened, `TAPOPENED ${String(controls.openedLinks.length)} ${controls.openedLinks.join(' ')}`],
        [focus, `TAPFOCUS active=${describe(document.activeElement)}`]
      ]
      for (const [element, text] of texts) if (element.textContent !== text) element.textContent = text
    }
    const note = (event: Event): void => {
      const at = event as MouseEvent
      order += 1
      const pointer = event as PointerEvent
      // The event's class, and the pointer's number and type where the event has them: `-` where it has not.
      seen.push(
        `E ${String(order)} ${event.type} ${describe(event.target)} ${event.isTrusted ? '1' : '0'} ${String(at.detail ?? 0)} ${round(at.clientX ?? 0)} ${round(at.clientY ?? 0)} ${event.constructor.name} ${typeof pointer.pointerId === 'number' ? String(pointer.pointerId) : '-'} ${pointer.pointerType || '-'}`
      )
      if (seen.length > KEPT) seen.shift()
      show()
    }
    const types = ['pointerdown', 'pointerup', 'pointercancel', 'click', 'focusin'] as const
    for (const type of types) document.addEventListener(type, note, true)
    const timer = window.setInterval(show, 400)
    show()
    return () => {
      for (const type of types) document.removeEventListener(type, note, true)
      window.clearInterval(timer)
    }
  }, [controls])
  const style = {
    position: 'fixed',
    insetBlockStart: 'env(safe-area-inset-top, 0px)',
    insetInlineStart: 0,
    inlineSize: '70vw',
    margin: 0,
    zIndex: 2147483646,
    pointerEvents: 'none',
    font: '6px/7px monospace',
    background: 'Canvas',
    color: 'CanvasText',
    opacity: 0.85,
    overflowWrap: 'anywhere'
  } as const
  return (
    <div aria-hidden={false} style={style}>
      <div id="kr-taps-log" />
      <div id="kr-taps-links" />
      <div id="kr-taps-opened" />
      <div id="kr-taps-focus" />
    </div>
  )
}
