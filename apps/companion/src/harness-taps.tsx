/**
 * The tap record of the test harness.
 *
 * Whether a tap on a message's link opens it depends on the events the platform sends for a finger
 * on the glass: which target the pointer events have, whether a click follows, what it names, with
 * what detail, and from which pointer.
 * A test that drives the application on a device taps by coordinates and cannot see the page's
 * events, so this puts them on the page as text, which the device's accessibility tree carries: the
 * events the page saw, the rectangles of the links' words and of what clips them, the links the host opened and where the
 * focus is. It is started by the strip, which also fills the first session with the messages the taps
 * need. The harness bundle is built only for tests, so none of this ships.
 *
 * The record listens on the document, in the capture phase, as the pane's own tap handling does, so
 * that it adds nothing the platform counts as a click listener on the page's content.
 */

import { useEffect, type ReactNode } from 'react'

import type { FakeHostControls } from './host/fake'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
/** The build session, whose conversation the short conversation's one message replaces. */
const SHORT_SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

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

/** A conversation shorter than the pane at either text size: one message, the link alone. */
const SHORT_MESSAGE = '[a short link](https://example.org/short-last)'

/** Puts the messages of the taps on the first session, or the short conversation's one message alone on the second. */
export function fillForTaps(controls: FakeHostControls, short = false): void {
  // The link at the end of a line has its words end at the pane's right edge, as a full line's last word does.
  const style = document.createElement('style')
  style.textContent = ".m-node p:has(.md-link[title$='at-end']) { text-align: justify; text-align-last: justify; }"
  document.head.append(style)
  if (short) controls.records.beginWith(SHORT_SESSION, 'message', SHORT_MESSAGE)
  else for (const message of TAP_MESSAGES) controls.records.appendEntry(SESSION, 'message', message)
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

/**
 * What every box that clips a link leaves of the page, as the record reads it for itself: the visual
 * viewport narrowed, on each axis, by the client box of every ancestor whose computed overflow on that
 * axis is not `visible`.
 */
const viewOf = (link: HTMLElement): readonly number[] => {
  const screen = window.visualViewport
  let [left, top, right, bottom] = screen
    ? [screen.offsetLeft, screen.offsetTop, screen.offsetLeft + screen.width, screen.offsetTop + screen.height]
    : [0, 0, window.innerWidth, window.innerHeight]
  for (let ancestor = link.parentElement; ancestor; ancestor = ancestor.parentElement) {
    const style = getComputedStyle(ancestor)
    const x = style.overflowX !== 'visible'
    const y = style.overflowY !== 'visible'
    if (!x && !y) continue
    const box = ancestor.getBoundingClientRect()
    const own = ancestor === document.documentElement ? { left: 0, top: 0 } : { left: box.left + ancestor.clientLeft, top: box.top + ancestor.clientTop }
    if (x) {
      left = Math.max(left, own.left)
      right = Math.min(right, own.left + ancestor.clientWidth)
    }
    if (y) {
      top = Math.max(top, own.top)
      bottom = Math.min(bottom, own.top + ancestor.clientHeight)
    }
  }
  return [left, top, right, bottom]
}

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
        return `L ${nameOf(link.title)} box ${[box.left, box.top, box.right, box.bottom].map(round).join(' ')} words ${words} line ${round(Number.isFinite(line) ? line : 0)} view ${viewOf(link).map(round).join(' ')}`
      })
      const scroller = document.querySelector('.m-pane')
      const room = scroller?.getBoundingClientRect()
      const pane = room && scroller
        ? `P ${[room.left, room.top, room.right, room.bottom, scroller.scrollTop, scroller.scrollHeight - scroller.clientHeight].map(round).join(' ')}`
        : 'P 0 0 0 0 0 0'
      // Where the layout stands: the panes there are, the links that no pane holds, the page's own scroll, and the box of the
      // scroller that holds the links.
      const holder = document.querySelector('.m-node .md-link')?.closest('.m-pane')
      const held = holder?.getBoundingClientRect()
      const where = `D panes ${String(document.querySelectorAll('.m-pane').length)} outside ${String(document.querySelectorAll('.m-node .md-link').length - document.querySelectorAll('.m-pane .m-node .md-link').length)} scroll ${round(window.scrollY)} holder ${held ? [held.left, held.top, held.right, held.bottom].map(round).join(' ') : 'none'}`
      const texts: [HTMLElement, string][] = [
        [log, `TAPLOG ${seen.join(' ; ')}`],
        [places, `TAPLINKS ${[pane, where, ...rectangles].join(' ; ')}`],
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
      // At a pointer down, the link that the page's press handling lit by then (`-` for none): this runs in
      // the bubble phase, after the handler's own listener on the document has run.
      const lit = event.type === 'pointerdown' ? nameOf(document.querySelector<HTMLElement>('.md-link[data-pressed]')?.title ?? '') || '-' : '-'
      seen.push(
        `E ${String(order)} ${event.type} ${describe(event.target)} ${event.isTrusted ? '1' : '0'} ${String(at.detail ?? 0)} ${round(at.clientX ?? 0)} ${round(at.clientY ?? 0)} ${event.constructor.name} ${typeof pointer.pointerId === 'number' ? String(pointer.pointerId) : '-'} ${pointer.pointerType || '-'} lit=${lit}`
      )
      if (seen.length > KEPT) seen.shift()
      show()
    }
    const types = ['pointerup', 'pointercancel', 'click', 'focusin'] as const
    for (const type of types) document.addEventListener(type, note, true)
    document.addEventListener('pointerdown', note)
    const timer = window.setInterval(show, 400)
    show()
    return () => {
      for (const type of types) document.removeEventListener(type, note, true)
      document.removeEventListener('pointerdown', note)
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
