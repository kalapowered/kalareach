/**
 * What assistive technology finds on the phone's screens, in both engines the page runs in.
 *
 * The role and name locators and the accessibility snapshot are computed from the page by the test
 * runner, the same way in each engine; the browser's own tree is read as well where the engine
 * offers it.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type CDPSession, type Page } from '@playwright/test'

import { CLICK_AWAY } from '../src/markdown/link-target'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** Opens the phone's session on `surface`, on a screen the size of a current phone's. */
async function openSession(page: Page, surface: 'ios' | 'android', width = 390): Promise<void> {
  await page.setViewportSize({ width, height: 844 })
  await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
  await expect(page.getByRole('group', { name: 'Add an attachment' })).toBeVisible()
}

/** The system's text size as the page is given it: a multiple of the default, set before the page loads. */
async function withTextScale(page: Page, ratio: number): Promise<void> {
  await page.addInitScript((value) => {
    const apply = (): boolean => {
      const root = document.documentElement as HTMLElement | null
      if (root === null) return false
      root.style.setProperty('--text-scale', String(value))
      return true
    }
    if (!apply()) {
      new MutationObserver((_, observer) => {
        if (apply()) observer.disconnect()
      }).observe(document, { childList: true })
    }
  }, ratio)
}

// KR-REQ-13.19, KR-REQ-13.17: each of the three ways to attach is one control to assistive
// technology, named for what it does and with the role of a button. The file input under it is not
// a second control: it is out of the accessibility tree and out of the focus order, and the control
// still opens the platform's picker with a touch, with Enter and with Space.
test.describe('the attachment controls', () => {
  const NAMES = ['Take a photo', 'Photo library', 'Files'] as const

  for (const surface of ['ios', 'android'] as const) {
    test(`are one named button each in the accessibility tree on ${surface}`, async ({ page }) => {
      await openSession(page, surface)
      const group = page.getByRole('group', { name: 'Add an attachment' })
      expect(await group.ariaSnapshot()).toBe(
        [
          '- group "Add an attachment":',
          '  - button "Take a photo"',
          '  - button "Photo library"',
          '  - button "Files"'
        ].join('\n')
      )
      for (const name of NAMES) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(1)
      }
      // The three inputs are still in the page, so the platform can open its pickers from them.
      const inputs = page.locator('input[type="file"]')
      await expect(inputs).toHaveCount(3)
      for (const input of await inputs.all()) await expect(input).toBeHidden()
    })

    test(`leave the file inputs out of the browser's own accessibility tree on ${surface}`, async ({
      page,
      browserName
    }) => {
      test.skip(browserName !== 'chromium', 'only this engine hands the page its own tree')
      await openSession(page, surface)
      const session = await page.context().newCDPSession(page)
      const { nodes } = (await session.send('Accessibility.getFullAXTree')) as {
        nodes: {
          ignored?: boolean
          role?: { value: string }
          name?: { value: string }
          backendDOMNodeId?: number
        }[]
      }
      // What each of the page's file inputs is, in that tree: no node, or one it ignores.
      const shown: string[] = []
      for (const node of nodes) {
        if (node.ignored === true || node.backendDOMNodeId === undefined) continue
        const described = await session.send('DOM.describeNode', { backendNodeId: node.backendDOMNodeId })
        const element = described.node
        if (element.nodeName === 'INPUT' && element.attributes?.includes('file')) {
          shown.push(`${node.role?.value ?? '?'} ${node.name?.value ?? ''}`.trim())
        }
      }
      expect(shown, 'file inputs the browser lists as controls').toEqual([])
      const buttons = nodes.filter(
        (node) =>
          node.ignored !== true &&
          node.role?.value === 'button' &&
          (NAMES as readonly string[]).includes(node.name?.value ?? '')
      )
      expect(buttons.map((node) => node.name?.value).sort()).toEqual([...NAMES].sort())
    })

    test(`keep the file inputs out of the focus order and open the picker from each control on ${surface}`, async ({
      page
    }) => {
      await openSession(page, surface)
      // An input the page hides cannot take the focus, so it is no stop for a keyboard or a switch.
      for (const input of await page.locator('input[type="file"]').all()) {
        expect(await input.evaluate((element) => {
          element.focus()
          return document.activeElement === element
        }), 'a file input that takes the focus').toBe(false)
      }

      // The platform's picker, each way a control is used: a touch or click, Enter and Space.
      for (const [name, accept, capture, multiple] of [
        ['Take a photo', 'image/*', 'environment', false],
        ['Photo library', 'image/*,video/*', null, true],
        ['Files', '*/*', null, true]
      ] as const) {
        const control = page.getByRole('button', { name, exact: true })
        for (const press of ['click', 'Enter', 'Space'] as const) {
          const opened = page.waitForEvent('filechooser')
          if (press === 'click') await control.click()
          else {
            await control.focus()
            await page.keyboard.press(press === 'Space' ? ' ' : press)
          }
          const chooser = await opened
          expect(chooser.isMultiple(), `${name} by ${press}: more than one file`).toBe(multiple)
          const input = chooser.element()
          expect(await input.getAttribute('accept'), `${name}: what it accepts`).toBe(accept)
          expect(await input.getAttribute('capture'), `${name}: the camera`).toBe(capture)
        }
      }
    })
  }

  test('hand the picked file to the draft', async ({ page }) => {
    await openSession(page, 'ios')
    const opened = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Files', exact: true }).click()
    const chooser = await opened
    await chooser.setFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('a picked file') })
    await expect(page.getByTestId('draft-attachments')).toContainText('notes.txt')
  })
})

/** The conversation's messages for the press case: what a message can hold that lays links close together. */
const PRESS_MESSAGES: readonly string[] = [
  // Links in one column of two table rows.
  [
    '| Item | Notes |',
    '| --- | --- |',
    '| one | [first notes](https://example.org/table-1) |',
    '| two | [second notes](https://example.org/table-2) |',
    '| three | plain words |'
  ].join('\n'),
  // A link on a quote's first line, and a link on the line above the quote.
  [
    'A line above the quote, with [a link](https://example.org/above-quote) in it.',
    '',
    '> [quoted link](https://example.org/quote) and words after it.'
  ].join('\n'),
  // A list.
  [
    '- [first item](https://example.org/list-1)',
    '- [second item](https://example.org/list-2) and plain words',
    '- plain item',
    '- [third item](https://example.org/list-3)'
  ].join('\n'),
  // A heading with a link, and a link under it.
  ['## [A heading link](https://example.org/heading)', '', '[under the heading](https://example.org/under-heading) and plain words.'].join(
    '\n'
  ),
  // Short links with no separator and with one space.
  'Short: [i](https://example.org/i-1)[i](https://example.org/i-2) and [8](https://example.org/eight) [9](https://example.org/nine) end.',
  // A link that wraps over lines above a short link, and a plain line between two links.
  [
    '[a link whose words run on over two lines of the pane and a little more besides](https://example.org/wrapped)  ',
    '[s](https://example.org/short) is under it.',
    '',
    '[above a plain line](https://example.org/plain-above)  ',
    'A plain line between two links.  ',
    '[below a plain line](https://example.org/plain-below)'
  ].join('\n'),
  // A link at the start and one at the end of a line, alone and with words.
  [
    '[1](https://example.org/at-start) then plain words after the link at the start of the line.',
    '',
    'Plain words before the link at the end of the line, [2](https://example.org/at-end)',
    '',
    '[3](https://example.org/alone-start)',
    '',
    '[4](https://example.org/alone-end)'
  ].join('\n'),
  // Links above and under the control of an image that has not been loaded.
  [
    '[a link above an image](https://example.org/above-image)  ',
    '![a picture](https://example.org/picture.png)',
    '',
    '![a second picture](https://example.org/second.png)  ',
    '[a link under an image, long enough to reach under the control that loads it](https://example.org/under-image)'
  ].join('\n'),
  // A right-to-left paragraph with a link at each end.
  ['[קישור](https://example.org/rtl-start) ואחריו מילים רבות [עוד](https://example.org/rtl-end)', '', 'שלום [שלום](https://example.org/rtl-middle) עולם'].join('\n')
]

/** More messages for the cases of a tap: plain words on the line under a link, and a link in the middle of a line. */
const NEXT_LINE = ['[the lead link](https://example.org/lead)  \nplain words on the next line, inside the reach of the link above.']
/** A link that starts a paragraph, with plain words after it that lie inside the link's reach. */
const TEXT_AFTER_LINK = ['[docs](https://example.org/docs) and more words follow the link on this line, which ends the paragraph.']
const DOCS = 'https://example.org/docs'
const LEAD = 'https://example.org/lead'
const MIDDLE_LINK = 'https://example.org/middle'

/** The text sizes the cases of a link run at, as multiples of the default: the default and the largest. */
const SIZES = [
  ['the default', 1],
  ['the largest', 53 / 17]
] as const

/** What a click was, as the page saw it. `capture` is every click; `bubble` only a click that nothing stopped. */
interface Clicked {
  readonly phase: 'capture' | 'bubble'
  readonly trusted: boolean
  readonly detail: number
  /** What the click names: `link <destination>`, `control <label>` or `text <tag>`. */
  readonly named: string
  readonly x: number
  readonly y: number
  /**
   * The link lit when the click reached the window (null for none). A bubble record is the look at the click:
   * the pane's handler (the document's capture phase) and the page's own listeners have run by then.
   */
  readonly lit: string | null
}

/** What a pointer down found: the link lit then (null for none), what it names, what it landed on and where. */
interface Look {
  readonly lit: string | null
  /** What the pointer down names, as a click's target is named: `link <destination>`, `control <label>` or `text <tag>`. */
  readonly named: string
  readonly target: string
  readonly x: number
  readonly y: number
}

/**
 * Records every click in the page from now on, in `window.clicks`, and what each pointer down names and
 * the link that is lit at it (null for none), in `window.looks`. The look at a pointer down is read by a
 * listener that was added after the pane's own, so the pane's handler has set it by then; the look at a
 * click is read by the window's listener of the bubble phase, after the pane's handler and the page's own.
 * The look at each release (null for none) is read the same way in `window.releases`, before the click that the
 * release makes can change it.
 */
async function watchClicks(page: Page): Promise<void> {
  await page.evaluate(() => {
    const clicks: Clicked[] = []
    ;(window as unknown as { clicks: Clicked[] }).clicks = clicks
    const looks: Look[] = []
    ;(window as unknown as { looks: Look[] }).looks = looks
    const releases: (string | null)[] = []
    ;(window as unknown as { releases: (string | null)[] }).releases = releases
    window.addEventListener('pointerup', () => {
      releases.push(document.querySelector('.md-link[data-pressed]')?.getAttribute('title') ?? null)
    })
    document.addEventListener(
      'pointerdown',
      (event) => {
        const target = event.target instanceof Element ? event.target : null
        looks.push({
          lit: document.querySelector('.md-link[data-pressed]')?.getAttribute('title') ?? null,
          named: nameOf(event.target),
          target: `${target?.tagName.toLowerCase() ?? '-'}${target?.className ? `.${String(target.className)}` : ''}`,
          x: event.clientX,
          y: event.clientY
        })
      },
      true
    )
    const nameOf = (target: EventTarget | null): string => {
      if (!(target instanceof Element)) return 'none'
      const link = target.closest('.md-link')
      if (link) return `link ${link.getAttribute('title') ?? ''}`
      const control = target.closest('button, a[href], input, select, textarea, summary')
      if (control) return `control ${control.textContent?.trim() ?? ''}`
      return `text ${target.tagName.toLowerCase()}`
    }
    for (const phase of ['capture', 'bubble'] as const) {
      window.addEventListener(
        'click',
        (event) => {
          clicks.push({
            phase,
            trusted: event.isTrusted,
            detail: event.detail,
            named: nameOf(event.target),
            x: event.clientX,
            y: event.clientY,
            lit: document.querySelector('.md-link[data-pressed]')?.getAttribute('title') ?? null
          })
        },
        phase === 'capture'
      )
    }
  })
}

const clicksSeen = (page: Page): Promise<Clicked[]> =>
  page.evaluate(() => (window as unknown as { clicks: Clicked[] }).clicks.slice())

/** The link lit at each release of a pointer since the recorder began (null for none). */
const releasesSeen = (page: Page): Promise<(string | null)[]> =>
  page.evaluate(() => (window as unknown as { releases: (string | null)[] }).releases.slice())

/** The clicks the browser made itself, seen before any handler: what the page was given. */
const browsers = (clicks: readonly Clicked[]): Clicked[] => clicks.filter((click) => click.phase === 'capture' && click.trusted)
/** The clicks that a handler of the page made. */
const handlers = (clicks: readonly Clicked[]): Clicked[] => clicks.filter((click) => click.phase === 'capture' && !click.trusted)

/**
 * A pause long enough for a click's record to be old, made by the page being busy as the pointer comes
 * up: in a listener of the window's capture phase, which runs before the pane's handler sees the
 * release (`before`), or in one of its bubble phase, which runs after it (`after`). The page keeps one
 * listener of each phase, and a call sets how long that phase waits (the other phase waits none), so each
 * call is the one pause that it names and an earlier call adds nothing to it.
 */
async function busyAtPointerUp(page: Page, milliseconds: number, where: 'before' | 'after'): Promise<void> {
  await page.evaluate(
    ({ busy, phase }) => {
      const state = window as unknown as { busyFor?: Record<'before' | 'after', number> }
      const installed = state.busyFor !== undefined
      const wait = (state.busyFor ??= { before: 0, after: 0 })
      if (!installed) {
        for (const side of ['before', 'after'] as const) {
          window.addEventListener(
            'pointerup',
            () => {
              const end = performance.now() + wait[side]
              while (performance.now() < end) {
                // Busy.
              }
            },
            side === 'before'
          )
        }
      }
      wait.before = phase === 'before' ? busy : 0
      wait.after = phase === 'after' ? busy : 0
    },
    { busy: milliseconds, phase: where }
  )
}

/**
 * Opens the conversation with the messages of the cases of a link. The pane's own `tabindex` is taken
 * off unless the case is of the pane as it ships: desktop WebKit scrolls a pane that it focuses for a
 * press on text, and a press that scrolls is not a tap.
 */
async function pressPage(
  page: Page,
  surface: 'ios' | 'android',
  options: { shipped?: boolean; extra?: readonly string[]; only?: readonly string[]; scale?: number; width?: number } = {}
): Promise<void> {
  if (options.scale !== undefined) await withTextScale(page, options.scale)
  await openSession(page, surface, options.width)
  await page.evaluate(
    ({ messages, session, shipped }) => {
      for (const message of messages) window.krTestHost?.records.appendEntry(session, 'message', message)
      document.dispatchEvent(new Event('visibilitychange'))
      const pane = document.querySelector<HTMLElement>('.m-pane')
      if (pane) pane.style.overflowAnchor = 'none'
      if (!shipped) pane?.removeAttribute('tabindex')
    },
    { messages: options.only ?? [...PRESS_MESSAGES, ...(options.extra ?? [])], session: SESSION, shipped: options.shipped ?? false }
  )
  await page.locator('.m-node .md-link').last().waitFor({ state: 'attached' })
  // iOS and Android draw a scroll indicator over the content and give it no taps. The desktop engine's
  // overlay scroll bar keeps a strip at the pane's right edge that takes the hit and sends no click (a tap
  // there gets none whichever listeners the page has), and no property of the pane tells the page where
  // it is, so the cases show the page without it.
  await page.addStyleTag({ content: '.m-pane { scrollbar-width: none; }' })
  await watchClicks(page)
}

interface Words {
  readonly x: number
  readonly y: number
  readonly left: number
  readonly top: number
  readonly right: number
  readonly bottom: number
}

/** Scrolls a link to the middle of the pane and gives the rectangle of its `line`th line of words (the last when `line` is -1). */
async function wordsOf(page: Page, href: string, line = 0): Promise<Words> {
  return page.evaluate(
    ({ target, which }) => {
      const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
      const pane = document.querySelector<HTMLElement>('.m-pane')
      if (!link || !pane) throw new Error(`the page shows no link ${target}`)
      link.scrollIntoView({ block: 'center' })
      const range = document.createRange()
      range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
      const read = (): DOMRect => {
        const rects = Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)
        const found = which < 0 ? rects[rects.length - 1] : rects[which]
        if (!found) throw new Error(`the link ${target} has no line ${String(which)}`)
        return found
      }
      // A link of many lines is taller than the pane: bring the line asked for to the middle of it.
      const room = pane.getBoundingClientRect()
      pane.scrollTop += read().top + read().height / 2 - (room.top + room.height / 2)
      const box = read()
      return { x: box.left + box.width / 2, y: box.top + box.height / 2, left: box.left, top: box.top, right: box.right, bottom: box.bottom }
    },
    { target: href, which: line }
  )
}

/** The protocol session of a page in Chromium, and the time of its last touch. */
const touches = new WeakMap<Page, { session: CDPSession; at: number }>()

/** The protocol session of a page in Chromium, made once. */
async function touchSession(page: Page): Promise<{ session: CDPSession; at: number }> {
  let state = touches.get(page)
  if (!state) {
    state = { session: await page.context().newCDPSession(page), at: 0 }
    touches.set(page, state)
  }
  return state
}

/**
 * A touch's tap at a point. Chromium counts a tap that follows another soon and near it as the second
 * of a double tap (the click's `detail` is 2): each tap here carries a time of its own, a second after
 * the one before and never before the real time, so a case that taps many points sees the `detail` a
 * first tap has, and the release's time is a time the page's clock has reached or is about to. WebKit
 * counts no double tap for these.
 */
async function tap(page: Page, x: number, y: number): Promise<void> {
  if (page.context().browser()?.browserType().name() !== 'chromium') {
    await page.touchscreen.tap(x, y)
    return
  }
  const state = await touchSession(page)
  state.at = Math.max(state.at + 1, Date.now() / 1000)
  // Both events go at once: the protocol keeps their order, and the browser takes the release as soon as it has the press, not a round trip later.
  await Promise.all([
    state.session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }], timestamp: state.at }),
    state.session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [], timestamp: state.at + 0.05 })
  ])
}

/** A touch's tap at a point with the real time of the engine's own clock: the release is stamped when it happens. */
async function tapNow(page: Page, x: number, y: number): Promise<void> {
  if (page.context().browser()?.browserType().name() !== 'chromium') {
    await page.touchscreen.tap(x, y)
    return
  }
  const { session } = await touchSession(page)
  await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }] })
  await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
}

/** How many clicks, pointer-down looks and opened links the page has recorded: what a tap's records start after. */
interface Mark {
  readonly clicks: number
  readonly looks: number
  readonly opened: number
}

const marked = (page: Page): Promise<Mark> =>
  page.evaluate(() => ({
    clicks: (window as unknown as { clicks: Clicked[] }).clicks.length,
    looks: (window as unknown as { looks: Look[] }).looks.length,
    opened: window.krTestHost?.openedLinks.length ?? 0
  }))

/**
 * What the page recorded after `mark`, once the browser's own click is in: the page waits for that click
 * itself (a click is a trusted one at the window's capture phase, the same test as `browsers`), for at
 * most `within` ms, and then for the end of that click's dispatch, in which the page's handler makes its
 * own click and opens its link. The lists are cut in the page, so a tap moves only its own records
 * however many taps went before it. `arrived` is false where no click came in time.
 */
const recordedSince = (page: Page, mark: Mark, within: number): Promise<{ arrived: boolean; clicks: Clicked[]; looks: Look[]; opened: string[] }> =>
  page.evaluate(
    async ({ after, limit }) => {
      const records = window as unknown as { clicks: Clicked[]; looks: Look[] }
      const browsersClick = (): boolean => records.clicks.slice(after.clicks).some((click) => click.phase === 'capture' && click.trusted)
      let arrived = browsersClick()
      if (!arrived) {
        arrived = await new Promise<boolean>((resolve) => {
          const listening = new AbortController()
          const timer = window.setTimeout(() => {
            listening.abort()
            resolve(false)
          }, limit)
          // Added after the cases' own listener, so the click is in the list when this one runs.
          window.addEventListener(
            'click',
            () => {
              if (!browsersClick()) return
              window.clearTimeout(timer)
              listening.abort()
              resolve(true)
            },
            { capture: true, signal: listening.signal }
          )
        })
      }
      // The window's capture phase comes first: the page's handler runs later in the same dispatch, which ends before the next task.
      await new Promise<void>((resolve) => {
        window.setTimeout(resolve, 0)
      })
      return {
        arrived,
        clicks: records.clicks.slice(after.clicks),
        looks: records.looks.slice(after.looks),
        opened: window.krTestHost?.openedLinks.slice(after.opened) ?? []
      }
    },
    { after: mark, limit: within }
  )

/**
 * What one tap did: the clicks the page saw, the links the page opened, the link lit at the press (null
 * for none) and the link lit at the browser's click (`litAtClick`, null for none), since the tap began. A
 * tap that gets no click from the browser fails here: no point is left out.
 */
async function tapAndRead(
  page: Page,
  x: number,
  y: number,
  tapper: (page: Page, x: number, y: number) => Promise<void> = tap
): Promise<{ clicks: Clicked[]; opened: string[]; lit: (string | null)[]; litAtClick: (string | null)[]; presses: Look[] }> {
  const mark = await marked(page)
  await tapper(page, x, y)
  const recorded = await recordedSince(page, mark, 5000)
  if (!recorded.arrived) {
    // Say what the point is: the element there and the boxes around it.
    const where = await page.evaluate(
      ([px, py]) => {
        const box = (element: Element | null): string => {
          const r = element?.getBoundingClientRect()
          return r === undefined ? '-' : `${String(r.left)}..${String(r.right)} x ${String(r.top)}..${String(r.bottom)}`
        }
        const hit = document.elementFromPoint(px ?? 0, py ?? 0)
        const pane = document.querySelector<HTMLElement>('.m-pane')
        return `element ${hit?.tagName ?? '-'}.${hit?.className ?? ''} (${box(hit)}), its parent ${hit?.parentElement?.tagName ?? '-'}.${hit?.parentElement?.className ?? ''} (${box(hit?.parentElement ?? null)}), pane box ${box(pane)}, client ${String(pane?.clientWidth)} x ${String(pane?.clientHeight)}, scroll bar ${String((pane?.offsetWidth ?? 0) - (pane?.clientWidth ?? 0))}`
      },
      [x, y]
    )
    throw new Error(`a click for a tap at ${String(Math.round(x))}, ${String(Math.round(y))} did not come; ${where}`)
  }
  const { clicks, looks: presses, opened } = recorded
  noteAway(page, presses, clicks)
  return { clicks, opened, lit: presses.map((look) => look.lit), litAtClick: clicks.filter((click) => click.phase === 'bubble' && click.trusted).map((click) => click.lit), presses }
}

/**
 * The farthest that a browser click lay from its tap's press in a case, in px, by what the click named: plain
 * text (where only the page decides, and the bound is for) or an element (a link's own element or another
 * control, which the browser's own adjustment chose and which stands as the browser made it). Logged, and
 * each is held to the handler's bound.
 */
const farthestAway = new WeakMap<Page, { plain: number; element: number }>()

/** Logs how far the browser's click of a tap lay from its press, and holds it to the bound that the handler uses. */
function noteAway(page: Page, presses: readonly Look[], clicks: readonly Clicked[]): void {
  const press = presses[0]
  if (press === undefined) return
  for (const click of browsers(clicks)) {
    const away = Math.hypot(click.x - press.x, click.y - press.y)
    const farthest = farthestAway.get(page) ?? { plain: -1, element: -1 }
    const kind = click.named.startsWith('text') ? 'plain' : 'element'
    farthestAway.set(page, { ...farthest, [kind]: Math.max(farthest[kind], away) })
    expect(away, `the distance from the press at ${String(press.x)}, ${String(press.y)} to its click (${click.named})`).toBeLessThanOrEqual(CLICK_AWAY)
  }
}

test.afterEach(({ page }, info) => {
  const away = farthestAway.get(page)
  if (away === undefined) return
  const said = (px: number): string => (px < 0 ? '-' : px.toFixed(2))
  info.annotations.push({ type: 'press-to-click', description: `plain text ${said(away.plain)} px, element ${said(away.element)} px (the bound is ${CLICK_AWAY.toFixed(2)})` })
  console.log(`press-to-click ${info.project.name} plain ${said(away.plain)} element ${said(away.element)}`)
})

const openedLinks = (page: Page): Promise<string[]> => page.evaluate(() => window.krTestHost?.openedLinks.slice() ?? [])
const pressedLooks = (page: Page): Promise<number> => page.evaluate(() => document.querySelectorAll('.md-link[data-pressed]').length)

/**
 * A point on the plain text 20 px after a link's words: inside the link's reach (half of the least
 * size, 22 or 24), and past what the engines' own touch adjustment gives to the link's button, so the
 * browser's click names the paragraph and only the pane's handler gives the tap to the link.
 */
async function pointOnTextAfter(page: Page, href: string): Promise<{ x: number; y: number }> {
  const words = await wordsOf(page, href)
  const hit = await page.evaluate(({ x, y }) => document.elementFromPoint(x, y)?.closest('.md-link') ?? null, { x: words.right + 20, y: words.y })
  if (hit !== null) throw new Error('the point 20 px after the words is on a link’s button')
  return { x: words.right + 20, y: words.y }
}

/** A point on a link's own words: the browser's click on it names the link's element. */
async function pointOnWords(page: Page, href: string): Promise<{ x: number; y: number }> {
  const words = await wordsOf(page, href)
  return { x: words.x, y: words.y }
}

const SURFACES = ['ios', 'android'] as const

// KR-REQ-13.19: the layout of the pane's links and controls is the page's own. A link has no enlarged
// box, so the browser's hit test decides every click that lands on a link's words or on another
// control, and a press near one of them is that one's click. Each case counts the clicks the browser
// made and the clicks that a handler of the page added: a press on a link's words or on a control gives
// the one click of the browser and no other.
/** Opens the Terminal view of a session whose terminal has ended: the page offers "Attach again". */
async function endedTerminal(page: Page, surface: 'ios' | 'android'): Promise<void> {
  await openSession(page, surface)
  await page.getByRole('tab', { name: 'Terminal' }).click()
  await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
  await page.evaluate(() => {
    window.krTestHost?.terminalViews.at(-1)?.end('The session ended.')
  })
}

test.describe('the links and the controls of a message in the pane', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      test(`a press on the lower part of an upper link's words, with a link on the next line, is the upper link's own click on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio })
        const upper = 'https://example.org/wrapped'
        const words = await wordsOf(page, upper, -1)
        const x = words.left + Math.min(12, (words.right - words.left) / 2)
        for (const by of ['touch', 'mouse'] as const) {
          const before = (await clicksSeen(page)).length
          if (by === 'touch') await tap(page, x, words.bottom - 2)
          else await page.mouse.click(x, words.bottom - 2)
          await expect.poll(async () => (await clicksSeen(page)).length, `clicks of a ${by} press`).toBeGreaterThan(before)
          const made = (await clicksSeen(page)).slice(before)
          expect(browsers(made).map((click) => click.named), `what the browser's click named for a ${by} press`).toEqual([`link ${upper}`])
          expect(handlers(made), `clicks that the page added to a ${by} press`).toEqual([])
        }
        expect(await openedLinks(page), 'links opened').toEqual([upper, upper])
      })

      test(`a press 1 to 3 px inside the lower edge of "Load this image", with a link on the next line, is one click of the control on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio })
        const control = page.getByRole('button', { name: 'Load this image' }).nth(1)
        await control.scrollIntoViewIfNeeded()
        for (const inside of [1, 2, 3]) {
          const box = await control.boundingBox()
          if (!box) throw new Error('the control has no box')
          const before = (await clicksSeen(page)).length
          await tap(page, box.x + box.width / 2, box.y + box.height - inside)
          await expect.poll(async () => (await clicksSeen(page)).length, `clicks of a press ${String(inside)} px inside`).toBeGreaterThan(before)
          const made = (await clicksSeen(page)).slice(before)
          expect(browsers(made).map((click) => click.named), `what the click named ${String(inside)} px inside the edge`).toEqual(['control Load this image'])
          expect(handlers(made), `clicks that the page added ${String(inside)} px inside the edge`).toEqual([])
        }
        // A press that starts on the control gives the pressed look to no link, though a link's words are near.
        const box = await control.boundingBox()
        if (!box) throw new Error('the control has no box')
        const pressed = await tapAndRead(page, box.x + box.width / 2, box.y + box.height - 2)
        expect(pressed.lit, 'the pressed look of a touch that starts on the control').toEqual([null])
        expect(pressed.litAtClick, 'the look at the click of a touch that starts on the control').toEqual([null])
        expect(await openedLinks(page), 'links opened by presses on the control').toEqual([])
      })
    }

    test(`"Attach again", pressed 2 px inside a side and held 200 ms, attaches on ${surface}`, async ({ page }) => {
      await endedTerminal(page, surface)
      const again = page.getByRole('button', { name: 'Attach again' })
      const box = await again.boundingBox()
      if (!box) throw new Error('Attach again has no box')
      await page.mouse.move(box.x + 2, box.y + box.height / 2)
      await page.mouse.down()
      // Long enough for the pressed look to take hold.
      await page.waitForTimeout(200)
      await page.mouse.up()
      await expect(page.getByTestId('terminal-ended')).toHaveCount(0)
    })

    for (const [size, ratio] of SIZES) {
      test(`"Attach again", tapped 2 px inside a side with a touch, attaches on ${surface} at ${size} text size`, async ({ page }) => {
        await withTextScale(page, ratio)
        await endedTerminal(page, surface)
        const box = await page.getByRole('button', { name: 'Attach again' }).boundingBox()
        if (!box) throw new Error('Attach again has no box')
        await tap(page, box.x + box.width - 2, box.y + box.height / 2)
        await expect(page.getByTestId('terminal-ended')).toHaveCount(0)
      })

      test(`"Attach again", pressed 8 px inside a side with a touch and held 0.4 s, attaches on ${surface} at ${size} text size`, async ({
        page,
        browserName
      }) => {
        test.skip(browserName !== 'chromium', 'a touch is held through the Chromium protocol: WebKit has no tool for a touch that is held')
        await withTextScale(page, ratio)
        await endedTerminal(page, surface)
        const box = await page.getByRole('button', { name: 'Attach again' }).boundingBox()
        if (!box) throw new Error('Attach again has no box')
        const { session } = await touchSession(page)
        const point = { x: box.x + 8, y: box.y + box.height / 2 }
        await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [point] })
        await page.waitForTimeout(400)
        await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
        await expect(page.getByTestId('terminal-ended')).toHaveCount(0)
      })
    }
  }
})

// KR-REQ-13.19: where a touch's click lands on plain text near a link's words, the link opens, once;
// the click on the text stands and the page stops nothing. A mouse's click on plain text opens nothing.
test.describe('a tap on the plain text near a link of a message', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      test(`opens the link once for a tap on the text after it and on the text under it, and nothing for a tap farther off, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, extra: [...TEXT_AFTER_LINK, ...NEXT_LINE] })
        const words = await wordsOf(page, DOCS)
        // From just past what the engines adjust to the link's button, to the end of the link's reach.
        let added = 0
        for (const beside of [10, 12, 14, 16, 18, 20]) {
          await page.evaluate(() => {
            ;(document.activeElement as HTMLElement | null)?.blur()
          })
          const made = await tapAndRead(page, words.right + beside, words.y)
          expect(made.opened, `links opened by a tap ${String(beside)} px after the words`).toEqual([DOCS])
          // The browser's click names the link (the engine's own adjustment) or the text (the page adds the link's click).
          const named = browsers(made.clicks).map((click) => click.named.split(' ')[0])
          expect(handlers(made.clicks).length, `clicks that the page added, for a browser click that named ${named.join()}`).toBe(named[0] === 'text' ? 1 : 0)
          added += handlers(made.clicks).length
          if (named[0] === 'text') {
            // The link's click has the tap's detail and the focus, and the browser's click on the text was stopped by nothing.
            expect(handlers(made.clicks)[0]?.detail, 'the detail of the link’s click').toBe(1)
            expect(
              made.clicks.filter((click) => click.phase === 'bubble' && click.trusted).map((click) => click.named.split(' ')[0]),
              'the browser’s click on the text reached the page'
            ).toEqual(['text'])
            expect(await page.evaluate(() => document.activeElement?.getAttribute('title')), 'the element that has the focus').toBe(DOCS)
          }
        }
        expect(added, 'taps that the page gave to the link, where the browser named the text').toBeGreaterThan(0)
        if (ratio === 1) {
          // The text on the line under the link: within the lower reach, and one line away beyond it.
          const lead = await wordsOf(page, LEAD)
          for (const below of [6, 8, 10, 12]) {
            const made = await tapAndRead(page, lead.left + 8, lead.bottom + below)
            expect(made.opened, `links opened by a tap ${String(below)} px under the words`).toEqual([LEAD])
          }
          const away = await tapAndRead(page, lead.left + 8, lead.bottom + 18)
          expect(away.opened, 'links opened by a tap 18 px under the words, past the reach').toEqual([])
          expect(handlers(away.clicks), 'clicks that the page added past the reach').toEqual([])
        }
        // Farther than the reach beside the words and what the pane's edge gave back (the link starts the line, so the area
        // keeps the least size on its right): the browser's click on the text, and nothing more.
        const past = FINGER[surface] + 12
        const far = await tapAndRead(page, words.right + past, words.y)
        expect(far.opened, `links opened by a tap ${String(past)} px after the words`).toEqual([])
        expect(handlers(far.clicks), `clicks that the page added ${String(past)} px after the words`).toEqual([])
      })

      test(`adds no link click for the second tap of a double tap on ${surface} at ${size} text size`, async ({ page, browserName }) => {
        await pressPage(page, surface, { scale: ratio, extra: TEXT_AFTER_LINK })
        const after = await pointOnTextAfter(page, DOCS)
        // Two quick taps: the engine that counts a double tap gives the second click a detail of 2, one that does not gives each a detail of 1.
        const taps: { named: string; detail: number; added: number; opened: number }[] = []
        for (let each = 0; each < 2; each += 1) {
          const clicksBefore = (await clicksSeen(page)).length
          const openedBefore = (await openedLinks(page)).length
          await page.touchscreen.tap(after.x, after.y)
          await expect.poll(async () => browsers((await clicksSeen(page)).slice(clicksBefore)).length, 'a click for the tap').toBe(1)
          const made = (await clicksSeen(page)).slice(clicksBefore)
          const click = browsers(made)[0]
          taps.push({
            named: click?.named.split(' ')[0] ?? '',
            detail: click?.detail ?? -1,
            added: handlers(made).length,
            opened: (await openedLinks(page)).length - openedBefore
          })
        }
        test.info().annotations.push({ type: 'the two taps', description: JSON.stringify(taps) })
        expect(taps[0], 'the first tap: a click on the text, and the link opened once through the page’s click').toEqual({ named: 'text', detail: 1, added: 1, opened: 1 })
        if (browserName === 'chromium') {
          // Chromium counts the double tap: the second click has a detail of 2, and the page adds nothing to it.
          expect(taps[1], 'the second tap of the double tap').toEqual({ named: 'text', detail: 2, added: 0, opened: 0 })
        } else {
          // WebKit counts none for these: the second tap is a tap of its own, and opens the link as the first did.
          expect(taps[1], 'the second tap, which the engine does not count as a double tap').toEqual({ named: 'text', detail: 1, added: 1, opened: 1 })
        }
      })

      test(`opens nothing for a mouse's click on the text, and nothing for a mouse drag that ends there, and stops neither, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, extra: TEXT_AFTER_LINK })
        const after = await pointOnTextAfter(page, DOCS)
        await page.mouse.click(after.x, after.y)
        await expect.poll(async () => browsers(await clicksSeen(page)).length, 'a mouse click').toBe(1)
        expect(await openedLinks(page), 'links opened by a mouse click on plain text').toEqual([])
        await page.mouse.move(after.x, after.y)
        await page.mouse.down()
        await page.mouse.move(after.x + 14, after.y, { steps: 4 })
        await page.mouse.up()
        await expect.poll(async () => (await clicksSeen(page)).filter((click) => click.phase === 'bubble' && click.trusted).length, 'clicks that reached the page').toBeGreaterThanOrEqual(1)
        expect(await openedLinks(page), 'links opened by a mouse drag that ends on plain text').toEqual([])
        expect(handlers(await clicksSeen(page)), 'clicks that the page added for a mouse').toEqual([])
      })

      test(`goes by the browser's click for Enter and Space on a focused link, with a fresh tap on another link's text before, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, extra: TEXT_AFTER_LINK })
        const after = await pointOnTextAfter(page, DOCS)
        await page.touchscreen.tap(after.x, after.y)
        await expect.poll(() => openedLinks(page), 'the tap').toEqual([DOCS])
        await page.locator('.m-node .md-link[title="https://example.org/list-1"]').evaluate((element) => {
          element.focus({ preventScroll: true })
        })
        await page.keyboard.press('Enter')
        await page.keyboard.press('Space')
        expect(await openedLinks(page), 'links opened by the tap, Enter and Space').toEqual([DOCS, 'https://example.org/list-1', 'https://example.org/list-1'])
        const keyed = browsers(await clicksSeen(page)).filter((click) => click.detail === 0)
        expect(keyed.map((click) => click.named), 'the clicks of the keyboard').toEqual(['link https://example.org/list-1', 'link https://example.org/list-1'])
      })
    }

    for (const where of ['before', 'after'] as const) {
      test(`opens the link though the page is busy for 1.7 s ${where === 'before' ? 'before the handler sees' : 'after the handler saw'} the release, and adds nothing when it is busy for 3.2 s, on ${surface}`, async ({
        page
      }) => {
        await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
        const after = await pointOnTextAfter(page, DOCS)
        await busyAtPointerUp(page, 1700, where)
        // The release is stamped when it happens: a page that is busy runs the handler's listener late, and the three seconds run from the stamp.
        const soon = await tapAndRead(page, after.x, after.y, tapNow)
        expect(soon.opened, 'links opened by a click 1.7 s after the release').toEqual([DOCS])
        expect(handlers(soon.clicks).length, 'clicks that the page added 1.7 s after the release').toBe(browsers(soon.clicks)[0]?.named.startsWith('text') ? 1 : 0)
        await busyAtPointerUp(page, 3200, where)
        const late = await tapAndRead(page, after.x, after.y, tapNow)
        expect(late.opened, 'links opened by a click 3.2 s after the release, by a record that old').toEqual([])
        expect(handlers(late.clicks), 'clicks that the page added to a click that came 3.2 s after the release').toEqual([])
        expect(late.clicks.filter((click) => click.phase === 'bubble' && click.trusted).length, 'the late click reached the page: nothing stopped it').toBe(1)
      })
    }

    test(`does not open a link whose destination changed during the press on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      // After the pane's own handler of the press's start: the page changes what the link opens.
      await page.evaluate((href) => {
        window.addEventListener('pointerdown', () => {
          const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${href}"]`)
          if (link) link.title = 'https://example.org/changed'
        })
      }, DOCS)
      const made = await tapAndRead(page, after.x, after.y)
      expect(made.opened, 'links opened by a press on a link whose destination changed').toEqual([])
      expect(handlers(made.clicks), 'clicks that the page added to a press on a link whose destination changed').toEqual([])
    })

    test(`takes the pressed look off a press on a link's words that the engine cancels as it starts to scroll, and opens nothing, on ${surface}`, async ({
      page,
      browserName
    }) => {
      test.skip(browserName !== 'chromium', 'the touch is moved through the Chromium protocol: WebKit has no tool for a touch that moves')
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnWords(page, DOCS)
      await page.evaluate(() => {
        const seen: string[] = []
        ;(window as unknown as { pointerEnds: string[] }).pointerEnds = seen
        for (const type of ['pointerup', 'pointercancel']) document.addEventListener(type, () => seen.push(type), true)
      })
      const { session } = await touchSession(page)
      const touch = (type: 'touchStart' | 'touchMove' | 'touchEnd', y: number): Promise<unknown> =>
        session.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchEnd' ? [] : [{ x: after.x, y }] })
      await touch('touchStart', after.y)
      expect(await pressedLooks(page), 'the pressed look at the touch’s start').toBe(1)
      await touch('touchMove', after.y - 14)
      await touch('touchMove', after.y - 30)
      // The engine takes the moving touch for a scroll and cancels the pointer. The handler's move past the slop (the
      // first move, 14 px) ends the press and takes the look off before the cancel arrives, so this case holds the move
      // and the cancel together, not each; the held-press case below cancels a touch that made no move.
      await expect.poll(() => pressedLooks(page), 'the pressed look once the engine cancelled the touch').toBe(0)
      await touch('touchEnd', after.y - 30)
      expect(await page.evaluate(() => (window as unknown as { pointerEnds: string[] }).pointerEnds), 'how the pointer ended').toEqual(['pointercancel'])
      await page.waitForTimeout(400)
      expect(await openedLinks(page), 'links opened by a touch that moved').toEqual([])
    })

    test(`shows the look of a mouse press on a link's own element only while the pointer lies in the element, and adds no click for a release on plain text just past it, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      await wordsOf(page, DOCS)
      const box = await boxOf(page, DOCS)
      const y = (box.top + box.bottom) / 2
      await page.mouse.move(box.right - 2, y)
      await page.mouse.down()
      expect(await pressedLooks(page), 'the pressed look of a mouse press on the link’s own element').toBe(1)
      await page.mouse.move(box.right + 3, y)
      expect(await pressedLooks(page), 'the pressed look after a move of 5 px to plain text past the element').toBe(0)
      await page.mouse.move(box.right - 2, y)
      expect(await pressedLooks(page), 'the pressed look after the pointer is back in the element').toBe(1)
      await page.mouse.move(box.right + 3, y)
      expect(await pressedLooks(page), 'the pressed look after the pointer leaves the element again').toBe(0)
      await page.mouse.up()
      await page.waitForTimeout(400)
      expect(handlers(await clicksSeen(page)), 'clicks that the page added for a mouse released on plain text').toEqual([])
      expect(await openedLinks(page), 'links opened by a mouse press on a link released on plain text past it').toEqual([])
    })

    // The held presses below stay down while the page changes under them. Chromium's protocol holds a touch, and a
    // pen through its mouse events; WebKit has no tool for either.
    test(`takes the pressed look off at a pointer cancel that comes with no move, and for a held press at a pen's move, a scroll, a next press and a pen's tap, on ${surface}`, async ({
      page,
      browserName
    }) => {
      test.skip(browserName !== 'chromium', 'the touch and the pen are held through the Chromium protocol: WebKit has no tool for them')
      await pressPage(page, surface, { only: [...Array.from({ length: 12 }, () => PLAIN), ...TEXT_AFTER_LINK, ...Array.from({ length: 12 }, () => PLAIN)] })
      let after = await pointOnWords(page, DOCS)
      const { session } = await touchSession(page)
      const touch = (type: 'touchStart' | 'touchCancel' | 'touchEnd'): Promise<unknown> =>
        session.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchStart' ? [{ x: after.x, y: after.y }] : [] })
      const pen = (type: 'mousePressed' | 'mouseMoved' | 'mouseReleased', y: number): Promise<unknown> =>
        session.send('Input.dispatchMouseEvent', { type, x: after.x, y, button: 'left', buttons: type === 'mouseReleased' ? 0 : 1, clickCount: type === 'mouseMoved' ? 0 : 1, pointerType: 'pen' })
      await page.evaluate(() => {
        const seen = { moves: 0, ends: [] as string[] }
        ;(window as unknown as { held: typeof seen }).held = seen
        document.addEventListener('pointermove', () => (seen.moves += 1), true)
        for (const type of ['pointerup', 'pointercancel']) document.addEventListener(type, () => seen.ends.push(type), true)
      })
      const held = (): Promise<{ moves: number; ends: string[] }> => page.evaluate(() => (window as unknown as { held: { moves: number; ends: string[] } }).held)
      const scrollBy = (by: number): Promise<unknown> => page.evaluate((px) => document.querySelector('.m-pane')?.scrollBy(0, px), by)

      // A touch cancelled with no move. The engine follows the pointer cancel with a lost capture of the same pointer, and
      // the handler ends the press at either, so this case holds the two paths together and cannot tell which ended the
      // press; the unit cases hold the cancel and the lost capture each alone.
      await touch('touchStart')
      expect(await pressedLooks(page), 'the pressed look of a held touch').toBe(1)
      await touch('touchCancel')
      await expect.poll(() => pressedLooks(page), 'the pressed look after a pointer cancel with no move').toBe(0)
      expect(await held(), 'the pointer ended by a cancel after no move').toEqual({ moves: 0, ends: ['pointercancel'] })

      // A held touch and a scroll: 3 px keep the look (the link still wins the press's point), 300 px take it off.
      await touch('touchStart')
      expect(await pressedLooks(page), 'the pressed look of a second held touch').toBe(1)
      await scrollBy(3)
      await page.waitForTimeout(300)
      expect(await pressedLooks(page), 'the pressed look after a scroll of 3 px').toBe(1)
      await scrollBy(300)
      await expect.poll(() => pressedLooks(page), 'the pressed look after a scroll of 300 px').toBe(0)
      await touch('touchEnd')
      await page.waitForTimeout(400)
      expect(await openedLinks(page), 'links opened by a touch whose press a scroll ended').toEqual([])
      await scrollBy(-303)
      await page.waitForTimeout(300)

      // A pen that moves past the slop while it is down: the move ends the press, with no engine cancel to do it.
      after = await pointOnWords(page, DOCS)
      await pen('mousePressed', after.y)
      expect(await pressedLooks(page), 'the pressed look of a pen press').toBe(1)
      await pen('mouseMoved', after.y + 14)
      expect(await pressedLooks(page), 'the pressed look after a pen move of 14 px').toBe(0)
      await pen('mouseReleased', after.y + 14)

      // A next press outside the pane ends a held press, and the pane's record with it.
      await pen('mousePressed', after.y)
      expect(await pressedLooks(page), 'the pressed look of a second pen press').toBe(1)
      const pane = await paneBox(page)
      await page.mouse.move(pane.left + 10, pane.top / 2)
      await page.mouse.down()
      expect(await pressedLooks(page), 'the pressed look after a next press outside the pane').toBe(0)
      await page.mouse.up()
      await pen('mouseReleased', after.y)

      // A pen's tap on plain text beside the link opens it, as a touch's does, and the look comes at the click.
      after = await pointOnTextAfter(page, DOCS)
      const opened = (await openedLinks(page)).length
      await pen('mousePressed', after.y)
      expect(await pressedLooks(page), 'the pressed look of a pen press on plain text').toBe(0)
      await pen('mouseReleased', after.y)
      await expect.poll(async () => (await openedLinks(page)).length - opened, 'links opened by a pen’s tap on plain text beside the link').toBe(1)
      const litAtPenClick = (await clicksSeen(page)).filter((click) => click.phase === 'bubble' && click.trusted).map((click) => click.lit)
      expect(litAtPenClick[litAtPenClick.length - 1], 'the link lit at the click of a pen’s tap on plain text').toBe(DOCS)
    })

    // A box between a link and the root that the view cannot be measured through: the link takes no part, as on a page
    // with no handler, and a box that only moves its content is measured as any other.
    test(`gives a link no area under a box that scales, rotates, contains its paint or skips its rendering, and measures a box that only moves, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const around = async (style: string): Promise<void> => {
        await page.evaluate((css) => {
          const message = document.querySelector('.m-node .md-link[title="https://example.org/docs"]')?.closest<HTMLElement>('.m-node')
          if (message) message.style.cssText = css
        }, style)
      }
      for (const [kind, style] of [
        ['a scale', 'transform: scale(0.99)'],
        ['the scale property', 'scale: 0.99'],
        ['the rotate property', 'rotate: 0.2deg'],
        ['contained paint', 'contain: paint'],
        ['skipped rendering', 'content-visibility: auto']
      ] as const) {
        await around(style)
        const after = await pointOnTextAfter(page, DOCS)
        const made = await tapAndRead(page, after.x, after.y)
        expect(made.lit, `the pressed look under ${kind}`).toEqual([null])
        expect(made.litAtClick, `the look at the click under ${kind}`).toEqual([null])
        expect(handlers(made.clicks), `clicks that the page added under ${kind}`).toEqual([])
        expect(made.opened, `links opened under ${kind}`).toEqual([])
      }
      await around('transform: translate(6px, 3px)')
      const moved = await pointOnTextAfter(page, DOCS)
      const made = await tapAndRead(page, moved.x, moved.y)
      expect(made.lit, 'the pressed look of a press on plain text under a box that only moves').toEqual([null])
      expect(made.litAtClick, 'the look at the click under a box that only moves').toEqual([DOCS])
      expect(made.opened, 'links opened under a box that only moves').toEqual([DOCS])
    })

    test(`gives the pressed look at the click to the link that a touch on plain text near it opens, which ends within 400 ms, and lights nothing where no link's target holds the point, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      const near = await tapAndRead(page, after.x, after.y)
      expect(near.lit, 'the pressed look at the press on plain text').toEqual([null])
      expect(near.litAtClick, 'the look at the click').toEqual([DOCS])
      expect(near.opened, 'links opened by the tap').toEqual([DOCS])
      await page.waitForTimeout(400)
      expect(await pressedLooks(page), 'the pressed look 400 ms after the tap').toBe(0)
      const far = await wordsOf(page, DOCS)
      const none = await tapAndRead(page, far.right + 60, far.y)
      expect(none.lit, 'the pressed look for a press that no link’s target holds').toEqual([null])
      expect(none.litAtClick, 'the look at the click for a press that no link’s target holds').toEqual([null])
      // A press on the link's own words is lit at the touch's start, and the look is the click's link and ends within 400 ms.
      const own = await wordsOf(page, DOCS)
      const words = await tapAndRead(page, own.x, own.y)
      expect(words.lit, 'the pressed look at a press on the link’s own words').toEqual([DOCS])
      expect(words.litAtClick, 'the look at the click on the link’s own words').toEqual([DOCS])
      await page.waitForTimeout(400)
      expect(await pressedLooks(page), 'the pressed look 400 ms after a tap on the link’s own words').toBe(0)
    })

    test(`lights nothing for a mouse press on the plain text near a link, whose click opens nothing, and lights the link for a mouse press on its own element, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      await page.mouse.move(after.x, after.y)
      await page.mouse.down()
      expect(await pressedLooks(page), 'the pressed look of a mouse press on plain text beside the link').toBe(0)
      await page.mouse.up()
      expect(await openedLinks(page), 'links opened by a mouse click on plain text beside the link').toEqual([])
      const own = await wordsOf(page, DOCS)
      await page.mouse.move(own.x, own.y)
      await page.mouse.down()
      expect(await pressedLooks(page), 'the pressed look of a mouse press on the link’s own words').toBe(1)
      const before = (await releasesSeen(page)).length
      await page.mouse.up()
      // The click that the release makes clears the look of a mouse, so the look is read as the release reaches the window.
      expect((await releasesSeen(page)).slice(before), 'the pressed look at the release of a mouse press on the link’s own words').toEqual([null])
      expect(await pressedLooks(page), 'the pressed look after the release').toBe(0)
    })

    test(`leaves a press on something outside the pane alone, though a link of the pane lies under it, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      // A sheet over the pane, with plain words where the pane's link has its reach. It stands in the page's
      // root, as the page's own sheets do. WebKit on Linux sends a click for a tap on plain text only where
      // an element above the words listens for clicks, and a listener on the document is not enough there (it
      // is on macOS); the page's own listeners sit on the root. A sheet appended to the body gets no click on
      // Linux, and the case needs the click to see that the page adds none.
      await page.evaluate(({ x, y }) => {
        const root = document.getElementById('root')
        if (root === null) throw new Error('the page has no root')
        const sheet = document.createElement('div')
        sheet.id = 'case-sheet'
        sheet.style.cssText = 'position: fixed; inset: 0; z-index: 99999; background: white'
        const words = document.createElement('p')
        words.textContent = 'plain words of the sheet'
        words.style.cssText = `position: absolute; left: ${String(x - 40)}px; top: ${String(y - 20)}px; width: 160px; height: 40px; margin: 0`
        sheet.append(words)
        root.append(sheet)
      }, after)
      expect(
        await page.evaluate(({ x, y }) => document.elementFromPoint(x, y)?.textContent, after),
        'what lies at the tap'
      ).toBe('plain words of the sheet')
      const made = await tapAndRead(page, after.x, after.y)
      expect(handlers(made.clicks), 'clicks that the page added to a tap on the sheet').toEqual([])
      expect(await pressedLooks(page), 'the pressed look after the press on the sheet').toBe(0)
      expect(made.opened, 'links of the pane opened by a tap on the sheet').toEqual([])
    })
  }
})

// KR-REQ-13.19, the pane as it ships (with its own `tabindex`): the words of a link open it, and a
// tap on the text after it does.
test.describe('a tap on the pane as it ships', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    test(`opens a link on its words and on the text after it, with the pane's own tabindex, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { shipped: true, extra: TEXT_AFTER_LINK })
      expect(await page.locator('.m-pane').getAttribute('tabindex'), 'the pane as it ships').not.toBeNull()
      const words = await wordsOf(page, 'https://example.org/table-1')
      expect((await tapAndRead(page, words.x, words.y)).opened, 'links opened by a tap on the words').toEqual(['https://example.org/table-1'])
      const text = await pointOnTextAfter(page, DOCS)
      expect((await tapAndRead(page, text.x, text.y)).opened, 'links opened by a tap on the text after a link').toEqual([DOCS])
    })
  }
})

/** What a finger meets, in CSS pixels: 44 points on iOS and 48 dp on Android. */
const FINGER = { ios: 44, android: 48 } as const

const PLAIN = 'Plain words that hold no link, there to give the page room above and below.'
/** A short link at the start of a line and one at the end of a line, each beside the pane's edge, and a link on a conversation's last line. */
const EDGES = [
  ['at the start of a line', 'https://example.org/at-start', ['[1](https://example.org/at-start) then plain words after the link at the start of the line.']],
  ['at the end of a line', 'https://example.org/at-end', ['Plain words before the link at the end of the line, [2](https://example.org/at-end)']]
] as const
/** A link in the middle of a line whose label does not wrap at the largest text size, so that the area is one line's. */
const AREA_MIDDLE = ['Some words before [mid link](https://example.org/middle) and words that follow it to the end of the line.']
const LAST = 'https://example.org/last-line'
const LAST_LINE = 'The last words of the conversation end with [a link](https://example.org/last-line)'
const CLOSE = ['[first](https://example.org/close-1)  \n[second](https://example.org/close-2)']
const ORDER_ONE = 'https://example.org/order-1'
const ORDER_TWO = 'https://example.org/order-2'
/** Two links on one line with a plain run between them: a hair space and a word joiner, which the case repeats until the gap between the words is the one it measures for. */
const ORDER = [`[first](${ORDER_ONE})\u200A\u2060[second](${ORDER_TWO})`]

/** The pane's own client box as the page lays it out now: what holds content and can be tapped, with no scroll bar's strip. */
async function paneBox(page: Page): Promise<{ left: number; top: number; right: number; bottom: number }> {
  return page.evaluate(() => {
    const pane = document.querySelector('.m-pane') as HTMLElement
    const box = pane.getBoundingClientRect()
    const left = box.left + pane.clientLeft
    const top = box.top + pane.clientTop
    return { left, top, right: left + pane.clientWidth, bottom: top + pane.clientHeight }
  })
}

/**
 * The corners and the middles of the sides of the square of the least size about a link's words, one
 * pixel inside it. Where the pane cuts the square on a side, the square slides back inside the pane
 * by what was cut: the area that a tap opens the link in keeps its size there.
 */
function ringPoints(words: Words, pane: { left: number; top: number; right: number; bottom: number }, size: number): { x: number; y: number }[] {
  const slide = (low: number, high: number, min: number, max: number): [number, number] => {
    let from = low
    let to = high
    if (from < min) {
      to += min - from
      from = min
    }
    if (to > max) {
      from -= to - max
      to = max
    }
    return [Math.max(from, min), to]
  }
  const [left, right] = slide(words.x - size / 2, words.x + size / 2, pane.left, pane.right)
  const [top, bottom] = slide(words.y - size / 2, words.y + size / 2, pane.top, pane.bottom)
  const points: { x: number; y: number }[] = []
  for (const y of [top + 1, (top + bottom) / 2, bottom - 1]) {
    for (const x of [left + 1, (left + right) / 2, right - 1]) points.push({ x, y })
  }
  return points
}

/** What a tap at one point did, as the area measure reads it: which link it opened, which it lit, and what it met. */
interface Sampled {
  readonly opened: string | null
  readonly lit: string | null
  readonly note: string
}

/** Reports the page's shape and the browser's ring apart: the shape by rows, and every tap of the ring with its place and kind. */
function reportGrid(area: Area): void {
  const ring = area.grid.ring
  const text = `the page's shape through the words' middle: ${extentsOf(area)}; by rows ${area.grid.shape.join(' | ')}; sides: ${area.grid.sides.join(', ')}; ${String(area.grid.taps)} grid taps; the browser's own opens outside it (the ring): ${ring.length === 0 ? 'none' : `${String(ring.length)} taps`}`
  const name = `${test.info().project.name} ${test.info().title}`
  test.info().annotations.push({ type: 'grid', description: text })
  console.log(`grid ${name}: ${text}`)
  for (const entry of ring) console.log(`grid ring ${name}: ${entry}`)
}

/** Holds an area to the rule: the crosses found nothing wrong, the grid found no hole in its shape, no look that disagrees, no open of the handler outside the shape and no lit tap on the lattice's boundary. */
function expectArea(area: Area): void {
  expect({ different: area.different, unlike: area.unlike, conflicts: area.conflicts, holes: area.holes, grid: area.grid.wrong }, 'taps that opened another link or a link twice, did not light what the handler opened, lit one link and met another element, left a hole, or broke the grid rule').toEqual({ different: [], unlike: [], conflicts: [], holes: [], grid: [] })
  reportGrid(area)
}

/**
 * Holds the area's reach beside the words: half the least size on each side, or the room that the pane
 * leaves on that side where it is less. The measure's own size test (`Math.min(width, height)`) is met by
 * words that are wide enough alone, so it cannot show a reach that is missing.
 */
function expectReach(area: Area, words: Words, pane: { left: number; right: number }, size: number): void {
  expect.soft(words.left - area.left, 'the area’s reach to the left of the words').toBeGreaterThanOrEqual(Math.min(size / 2, words.left - pane.left) - 1)
  expect.soft(area.right - words.right, 'the area’s reach to the right of the words').toBeGreaterThanOrEqual(Math.min(size / 2, pane.right - words.right) - 1)
}

/**
 * What a tap's look says against what its click did, or null when they agree: the light and the opening name
 * the same link at every point, on every engine.
 *
 * - One open of the browser's own click, or none where it names a control; the page's own click inside it
 *   (untrusted) opens the link of a plain-text click, so the opens of a tap are counted, not its clicks.
 * - Where the browser's click names a link, the link opens and has the look at the click; where it names a
 *   control, nothing opens and nothing is lit; where it names plain text, the look at the click is the link the
 *   page opened, and none where it opened none.
 * - The look at the press is none where the pointer down names plain text, and the named link where it names
 *   a link (the browser's own element, retargeted or not); a control lights nothing.
 * - A pointer down on a link whose click names another link or a control is reported as a stop: the plan
 *   rules that no such tap exists, and the build says so where it finds one.
 */
function lookDisagrees(made: { clicks: Clicked[]; opened: string[]; lit: (string | null)[]; litAtClick: (string | null)[]; presses: Look[] }): string | null {
  const problems: string[] = []
  const click = browsers(made.clicks)[0]
  const named = click?.named ?? 'none'
  const atClick = made.litAtClick[0] ?? null
  const atPress = made.lit[0] ?? null
  const pressNamed = made.presses[0]?.named ?? 'none'
  const opened = made.opened.length === 0 ? 'nothing' : made.opened.join(',')
  if (named.startsWith('control')) {
    if (made.opened.length !== 0) problems.push(`the click named ${named} and ${opened} opened`)
    if (atClick !== null) problems.push(`the click named ${named} and ${atClick} was lit at the click`)
  } else if (named.startsWith('link ')) {
    const href = named.slice('link '.length)
    if (made.opened.length !== 1 || made.opened[0] !== href) problems.push(`the click named ${named} and ${opened} opened`)
    if (atClick !== href) problems.push(`the click named ${named} and ${String(atClick)} was lit at the click`)
  } else {
    if (made.opened.length > 1) problems.push(`the click named plain text and ${opened} opened`)
    const open = made.opened[made.opened.length - 1] ?? null
    if (atClick !== open) problems.push(`lit at the click ${String(atClick)}, opened ${String(open)}`)
  }
  if (pressNamed.startsWith('text') && atPress !== null) problems.push(`lit ${atPress} at a press that names plain text`)
  if (pressNamed.startsWith('control') && atPress !== null) problems.push(`lit ${atPress} at a press that names ${pressNamed}`)
  if (pressNamed.startsWith('link ')) {
    if (atPress !== null && pressNamed !== `link ${atPress}`) problems.push(`lit ${atPress} at a press that names ${pressNamed}`)
    if (named !== pressNamed) problems.push(`STOP: the pointer down named ${pressNamed} and the click named ${named}`)
  }
  return problems.length === 0 ? null : problems.join('; ')
}

/**
 * The area in which a tap opens a link, as the grid reports it. `left` and `right` are the ends of the row through
 * the words' middle at which the look lit the link, `top` and `bottom` the ends of the column through it, each end
 * a tap and the next tap past it not lit (`right` and `bottom` one past the last lit pixel), so `width` and `height`
 * are the extents of those two lines. The shape beyond them is `grid.shape`, row by row: it is not always a rectangle.
 */
interface Area {
  readonly left: number
  readonly right: number
  readonly top: number
  readonly bottom: number
  readonly width: number
  readonly height: number
  /** The taps of the crosses that find the grid's whole pixels. */
  readonly taps: number
  /** Cross taps that opened another link, or the link more than once. */
  readonly different: string[]
  /** Cross taps whose click named plain text, so the page's handler decided, at which the look at the press and the open at the release differed. */
  readonly unlike: string[]
  /** Cross taps whose click the browser sent to an element, at which the look lit another link than that one. */
  readonly conflicts: string[]
  /** Cross points inside the area that lights at which the tap opened nothing. */
  readonly holes: string[]
  /** The cross taps near the two ends of the area that opens, with what each lit and opened (L lit, O opened), to read a short side by. */
  readonly edges: string[]
  /** The grid over the area and the room around it. */
  readonly grid: {
    readonly taps: number
    /** Taps that broke the rule: a hole or not exactly one open inside the shape, a look that disagrees with the click, another link opened, a click that the handler made outside the shape, or a lit tap on the lattice's own boundary. */
    readonly wrong: string[]
    /** Taps outside the shape at which the browser's own click opened the link, by place and kind: every one. */
    readonly ring: string[]
    /** The shape the grid found, by rows from the top: each lit row's extent, as offsets from the words' middle, with rows of one extent joined. */
    shape: string[]
    /** For each side: whether the lattice reached one step beyond the lit set, was limited by the pane, or stopped short (which fails the case). */
    sides: string[]
  }
}

/** The distance between the grid's lines, in px: one step. */
const GRID_STEP = 8

/** The area's extents through the words' middle, for a case's note. */
const extentsOf = (area: Area): string => `row ${String(area.width)} px, column ${String(area.height)} px`

/**
 * The area in which a tap opens a link. Two crosses of taps (along the line through the words' middle and
 * along the column through it, 4 px apart and refined to the pixel at each end of what lights) find the
 * grid's whole pixels; each tap must open exactly the link under test or nothing. Then a grid of taps, a
 * step apart and held to the pane, covers the words and the room around them. What it reports is the shape
 * that it found, not a box: the points at which the look lit the link, row by row, and the extent of the
 * row and of the column through the words' middle, each end refined to the pixel by taps along that line.
 * A point lies in the shape where it lies between the first and the last lit point of its row or of its
 * column. Every point in the shape opened the link exactly once and lit it, and one that did not light it
 * is a hole, which fails with its place. At a point outside the shape, in a corner or beyond an edge, no
 * click that the page's handler made may open anything (the handler's click is the one that the harness
 * sees untrusted); an open that the browser's own click made there is the browser's ring, recorded with its
 * place and what it was. The lattice must reach one step beyond the lit set on every side, and the report
 * says for each side whether it did or whether the pane limited it (no step beyond the last lattice line fits
 * in the pane, so no unlit outer line was measured there): a lit point on the lattice's own boundary with room
 * for a step beyond it fails the case. At a point where the click names
 * plain text the page's handler decides, and the look at the press is the open at the release; where the
 * click names an element the browser decides, and the look lit nothing or that same link.
 */
async function areaOf(page: Page, href: string, words: Words, size: number): Promise<Area> {
  const pane = await paneBox(page)
  const different: string[] = []
  const unlike: string[] = []
  const conflicts: string[] = []
  const holes: string[] = []
  const gaps: string[] = []
  const edges: string[] = []
  let taps = 0
  const sample = async (x: number, y: number): Promise<Sampled> => {
    taps += 1
    const made = await tapAndRead(page, x, y)
    // Exactly one open counts as the link's: a tap that opened it twice, or two links, is wrong and opens none here.
    const opened = made.opened.length === 1 ? (made.opened[0] ?? null) : null
    const lit = made.litAtClick[0] ?? null
    const where = `${String(Math.round(x - words.x))}, ${String(Math.round(y - words.y))}`
    if (made.opened.length > 1) different.push(`${where}: opened ${String(made.opened.length)} times: ${made.opened.join(',')}`)
    const press = made.presses[0]
    const capture = made.clicks.filter((click) => click.phase === 'capture')
    const detail = `the press landed on ${press?.target ?? '-'} at ${String(press?.x)}, ${String(press?.y)}; clicks ${capture.map((click) => `${click.trusted ? 'trusted' : 'made'} detail ${String(click.detail)} ${click.named} at ${String(click.x)}, ${String(click.y)}`).join('; ')}`
    const named = capture.find((click) => click.trusted && !click.named.startsWith('text'))?.named ?? null
    if (opened !== null && opened !== href) different.push(`${where}: opened ${opened}`)
    if (named !== null) {
      // The browser's own click names a link or a control: the look at the click is that same link, or none for a control.
      if (named.startsWith('link ') ? named !== `link ${String(lit)}` : lit !== null) conflicts.push(`${where}: lit ${String(lit)} at the click; ${detail}`)
    } else if (lit !== opened) unlike.push(`${where}: lit ${String(lit)}, opened ${String(opened)}; ${detail}`)
    return { opened, lit, note: `pressed ${press?.target ?? '-'}, click ${capture.map((click) => click.named).join('; ')}` }
  }
  const scan = async (
    axis: 'x' | 'y',
    from: number,
    to: number,
    min: number,
    max: number,
    middle: number
  ): Promise<{ open: [number, number]; lit: [number, number] }> => {
    const cache = new Map<number, Sampled>()
    const probe = async (n: number): Promise<Sampled> => {
      let found = cache.get(n)
      if (found === undefined) {
        found = axis === 'x' ? await sample(n, words.y) : await sample(words.x, n)
        cache.set(n, found)
      }
      return found
    }
    const inside: number[] = []
    for (let n = Math.max(from, min); n <= Math.min(to, max); n += 4) if ((await probe(n)).opened === href) inside.push(n)
    const first = inside[0]
    const last = inside[inside.length - 1]
    if (first === undefined || last === undefined) return { open: [Number.NaN, Number.NaN], lit: [Number.NaN, Number.NaN] }
    let low = first
    let high = last
    while (low - 1 >= min && (await probe(low - 1)).opened === href) low -= 1
    while (high + 1 <= max && (await probe(high + 1)).opened === href) high += 1
    // The look's extent from the words' middle outward, then to the pixel.
    const middleAt = Math.round(middle)

    let litLow = middleAt
    let litHigh = middleAt
    while (litLow - 4 >= min && (await probe(litLow - 4)).lit === href) litLow -= 4
    while (litLow - 1 >= min && (await probe(litLow - 1)).lit === href) litLow -= 1
    while (litHigh + 4 <= max && (await probe(litHigh + 4)).lit === href) litHigh += 4
    while (litHigh + 1 <= max && (await probe(litHigh + 1)).lit === href) litHigh += 1
    // A coarse point between the ends where nothing opened is a hole inside the area that lights, and a gap outside it
    // (between the look's area and the browser's own adjustment, where it opens a link further out).
    for (let n = first; n <= last; n += 4) {
      if (inside.includes(n)) continue
      const text = `${axis} ${String(Math.round(n - middle))}: ${(await probe(n)).note}`
      if (n >= litLow && n <= litHigh) holes.push(text)
      else gaps.push(text)
    }
    for (const n of [...cache.keys()].sort((x, y) => x - y)) {
      if (Math.abs(n - low) <= 5 || Math.abs(n - high) <= 5) {
        const found = cache.get(n)
        edges.push(`${axis} ${String(Math.round(n - middle))}${found?.lit === href ? 'L' : '-'}${found?.opened === href ? 'O' : '-'}`)
      }
    }
    return { open: [low, high + 1], lit: [litLow, litHigh + 1] }
  }
  // Taps are at whole pixels, inside the pane; an area of `size` px holds at least `size` of them.
  const reach = size + 20
  await scan('x', Math.floor(words.left - reach), Math.ceil(words.right + reach), Math.ceil(pane.left), Math.ceil(pane.right) - 1, words.x)
  await scan('y', Math.floor(words.top - reach), Math.ceil(words.bottom + reach), Math.ceil(pane.top), Math.ceil(pane.bottom) - 1, words.y)
  // The grid: lines a step apart through the words' middle, over the words and the room around them, held to the pane.
  const lines = (middle: number, from: number, to: number, min: number, max: number): number[] => {
    const at = Math.round(middle)
    const points: number[] = []
    for (let n = at - GRID_STEP * Math.ceil((at - from) / GRID_STEP); n <= to; n += GRID_STEP) if (n >= min && n <= max) points.push(n)
    return points
  }
  const room = size + 16
  const xs = lines(words.x, words.left - room, words.right + room, Math.ceil(pane.left), Math.ceil(pane.right) - 1)
  const ys = lines(words.y, words.top - room, words.bottom + room, Math.ceil(pane.top), Math.ceil(pane.bottom) - 1)
  interface Cell {
    readonly x: number
    readonly y: number
    readonly place: string
    /** The look at the click lit the link. */
    readonly lit: boolean
    /** The press landed on the link's own element, which the browser's hit test chose. */
    readonly own: boolean
    readonly opened: string[]
    /** The page's handler made a click (the one that the harness sees untrusted). */
    readonly handled: boolean
    readonly named: string | null
    readonly disagreement: string | null
    readonly press: Look | undefined
  }
  const cells: Cell[] = []
  const tapCell = async (x: number, y: number): Promise<Cell> => {
    const made = await tapAndRead(page, x, y)
    const press = made.presses[0]
    const cell: Cell = {
      x,
      y,
      place: `${String(Math.round(x - words.x))}, ${String(Math.round(y - words.y))}`,
      lit: made.litAtClick[0] === href,
      own: press?.target.includes('md-link') ?? false,
      opened: made.opened,
      handled: handlers(made.clicks).length > 0,
      named: browsers(made.clicks).find((click) => !click.named.startsWith('text'))?.named ?? null,
      disagreement: lookDisagrees(made),
      press
    }
    cells.push(cell)
    return cell
  }
  for (const y of ys) for (const x of xs) await tapCell(x, y)
  const lattice = cells.length
  // The shape is what the grid found: the points at which the look lit the link, by the page's rule for a press on plain
  // text or because the browser's own hit test put the press on the link's element (the link's box and the adjustment that
  // the engine adds around it, which lights by design and which the browser's click opens). It is not always a rectangle:
  // the button can be taller than the rule's rectangle, and the engine's adjustment is its own. It is reported by rows,
  // each row's own extent, and the extents that are called widths and heights are measured along the two lines through
  // the words' middle, where every end is a tap.
  const member = (cell: Cell): boolean => cell.lit
  const midX = Math.round(words.x)
  const midY = Math.round(words.y)
  const lit = cells.filter(member)
  const grid = { taps: 0, wrong: [] as string[], ring: [] as string[], shape: [] as string[], sides: [] as string[] }
  const onLine = (axis: 'x' | 'y', line: number): Cell[] => lit.filter((cell) => (axis === 'x' ? cell.y : cell.x) === line)
  const along = (axis: 'x' | 'y', line: number): [number, number] | null => {
    const found = onLine(axis, line).map((cell) => cell[axis])
    return found.length === 0 ? null : [Math.min(...found), Math.max(...found)]
  }
  // Each end to the pixel: taps one pixel at a time past the last lit tap of the line, while they stay lit (at most a step
  // less one). The first pixel that is not lit is tapped too, so each reported end has a tap on each side.
  const reachOut = async (axis: 'x' | 'y', sign: 1 | -1, edge: number, across: number): Promise<number> => {
    let found = edge
    for (let n = 1; n < GRID_STEP; n += 1) {
      const at = edge + sign * n
      const inPane = axis === 'x' ? at >= Math.ceil(pane.left) && at <= Math.ceil(pane.right) - 1 : at >= Math.ceil(pane.top) && at <= Math.ceil(pane.bottom) - 1
      if (!inPane) break
      const cell = axis === 'x' ? await tapCell(at, across) : await tapCell(across, at)
      if (!member(cell)) break
      found = at
    }
    return found
  }
  const row = along('x', midY)
  const column = along('y', midX)
  if (lit.length === 0) grid.wrong.push('no tap of the grid was lit by the page’s rule')
  if (lit.length > 0 && (row === null || column === null)) grid.wrong.push(`the row or the column through the words' middle (${String(midX - Math.round(words.x))}, ${String(midY - Math.round(words.y))}) has no lit tap`)
  const left = row === null ? Number.NaN : await reachOut('x', -1, row[0], midY)
  const right = row === null ? Number.NaN : (await reachOut('x', 1, row[1], midY)) + 1
  const top = column === null ? Number.NaN : await reachOut('y', -1, column[0], midX)
  const bottom = column === null ? Number.NaN : (await reachOut('y', 1, column[1], midX)) + 1
  // The lattice must reach one step beyond the lit set on every side, unless the pane ends there: a lit point on the
  // lattice's own boundary means the grid stopped before the shape did.
  const reachedLowX = xs[0] ?? Number.NaN
  const reachedHighX = xs[xs.length - 1] ?? Number.NaN
  const reachedLowY = ys[0] ?? Number.NaN
  const reachedHighY = ys[ys.length - 1] ?? Number.NaN
  // Each side says which of three it is: the lattice reached one step beyond the lit set (no lit point on its outermost
  // line), or a lit point lies on its outermost line and the pane ends there (no step beyond it fits in the pane, so
  // no unlit outer line was measured: the screen limited that side), or a lit point lies on its outermost line with room
  // for a step beyond it, which fails the case.
  const latticeLit = cells.slice(0, lattice).filter(member)
  const sides: [string, (cell: Cell) => boolean, boolean][] = [
    ['left', (cell) => cell.x === reachedLowX, reachedLowX - GRID_STEP >= Math.ceil(pane.left)],
    ['right', (cell) => cell.x === reachedHighX, reachedHighX + GRID_STEP <= Math.ceil(pane.right) - 1],
    ['top', (cell) => cell.y === reachedLowY, reachedLowY - GRID_STEP >= Math.ceil(pane.top)],
    ['bottom', (cell) => cell.y === reachedHighY, reachedHighY + GRID_STEP <= Math.ceil(pane.bottom) - 1]
  ]
  for (const [name, onLast, roomBeyond] of sides) {
    const found = latticeLit.filter(onLast)
    if (found.length === 0) grid.sides.push(`${name} one step beyond`)
    else if (roomBeyond) {
      grid.sides.push(`${name} STOPPED SHORT`)
      for (const cell of found) grid.wrong.push(`${cell.place}: a lit point lies on the lattice's ${name} boundary, which stops short of the shape`)
    } else grid.sides.push(`${name} limited by the pane`)
  }
  // A point lies in the shape where it lies between the first and the last lit tap of its row or of its column. A tap in
  // the shape that did not light the link is a hole. A point outside the shape, in a corner or beyond an edge, is one at
  // which no click of the handler may open anything; the browser's own click there is the ring.
  const spanRow = new Map<number, [number, number]>()
  const spanColumn = new Map<number, [number, number]>()
  for (const cell of cells.filter(member)) {
    const r = spanRow.get(cell.y)
    spanRow.set(cell.y, r === undefined ? [cell.x, cell.x] : [Math.min(r[0], cell.x), Math.max(r[1], cell.x)])
    const c = spanColumn.get(cell.x)
    spanColumn.set(cell.x, c === undefined ? [cell.y, cell.y] : [Math.min(c[0], cell.y), Math.max(c[1], cell.y)])
  }
  const inside = (cell: Cell): boolean => {
    const r = spanRow.get(cell.y)
    const c = spanColumn.get(cell.x)
    return (r !== undefined && cell.x >= r[0] && cell.x <= r[1]) || (c !== undefined && cell.y >= c[0] && cell.y <= c[1])
  }
  for (const cell of cells) {
    const found = `the press on ${cell.press?.target ?? '-'}, the look at the click lit ${String(cell.lit)}, ${String(cell.opened.length)} opens (${cell.opened.join(',') || 'none'}), the click named ${cell.named ?? 'plain text'}`
    if (cell.disagreement !== null) grid.wrong.push(`${cell.place}: ${cell.disagreement}`)
    if (cell.opened.some((opened) => opened !== href)) grid.wrong.push(`${cell.place}: opened another link; ${found}`)
    if (cell.own) {
      // A press on the link's own element lights it, and the browser's click opens it exactly once.
      if (!cell.lit || cell.opened.length !== 1) grid.wrong.push(`${cell.place}: a press on the link's own element did not light it and open it once; ${found}`)
    } else if (inside(cell)) {
      if (!cell.lit) grid.wrong.push(`${cell.place}: a hole in the shape, the look at the click did not light the link; ${found}`)
      else if (cell.opened.length !== 1) grid.wrong.push(`${cell.place}: inside the shape, not exactly one open; ${found}`)
    } else if (cell.handled) {
      grid.wrong.push(`${cell.place}: outside the shape the handler made a click; ${found}`)
    } else if (cell.opened.length > 1) {
      grid.wrong.push(`${cell.place}: outside the shape, more than one open; ${found}`)
    } else if (cell.opened.length === 1) {
      // The browser's own click on the link, past the page's shape: the ring.
      grid.ring.push(`${cell.place} (${found})`)
    }
  }
  // The shape as rows, from the top: each lit row's extent from its first to its last lit tap, as the offsets from the
  // words' middle, with the rows of one extent joined.
  const rows = [...spanRow.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([y, [from, to]]) => ({ y: Math.round(y - words.y), from: Math.round(from - words.x), to: Math.round(to - words.x) }))
  const joined: { top: number; bottom: number; from: number; to: number }[] = []
  for (const next of rows) {
    const last = joined[joined.length - 1]
    if (last !== undefined && last.from === next.from && last.to === next.to) last.bottom = next.y
    else joined.push({ top: next.y, bottom: next.y, from: next.from, to: next.to })
  }
  grid.shape = joined.map((part) => `y ${part.top === part.bottom ? String(part.top) : `${String(part.top)} to ${String(part.bottom)}`}: x ${String(part.from)} to ${String(part.to)}`)
  grid.taps = cells.length
  return { left, right, top, bottom, width: right - left, height: bottom - top, grid, taps, different, unlike, conflicts, holes, edges }
}

/**
 * The points of `ringPoints` at which a tap did not open `href` or, where the handler decided, lit and
 * opened unlike each other, as text. Every point gets a tap and every tap gets the browser's click: none is left out.
 */
async function missedInRing(page: Page, words: Words, size: number, href: string): Promise<string[]> {
  const pane = await paneBox(page)
  const missed: string[] = []
  for (const point of ringPoints(words, pane, size)) {
    const made = await tapAndRead(page, point.x, point.y)
    const label = `${String(Math.round(point.x - words.x))}, ${String(Math.round(point.y - words.y))}`
    if (made.opened.length !== 1 || made.opened[0] !== href) missed.push(`${label}: opened ${made.opened.join(',') || 'nothing'}, where ${href} once was required`)
    // The look at every point: where the click names plain text the look is the open; where the browser's
    // click names an element, the look lit nothing or that same link.
    const disagreement = lookDisagrees(made)
    if (disagreement !== null) missed.push(`${label}: ${disagreement}`)
  }
  return missed
}

// KR-REQ-13.19: the area in which a tap opens a link is at least the size the platform asks for around
// the link's words (44 points on iOS and 48 dp on Android, in every direction), and where two links
// stand closer than that, the nearer words have the area between them. The case taps a ring of points
// around the words of a link in the middle of a line, and every point of the axis between two links
// on neighbouring lines. Where the browser's own hit test names a link's button, that link opens, as
// on a desktop; everywhere else the nearer words win.
test.describe('the area in which a tap opens a link', () => {
  test.use({ hasTouch: true })
  // A grid of taps over the whole area and one step beyond it: some hundreds of taps for the larger areas.
  test.describe.configure({ timeout: 300_000 })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      test(`is at least the least size around a link's words on ${surface} at ${size} text size`, async ({ page }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...AREA_MIDDLE, PLAIN, PLAIN] })
        const words = await wordsOf(page, MIDDLE_LINK)
        const missed = await missedInRing(page, words, FINGER[surface], MIDDLE_LINK)
        expect(missed, 'points of the least size about the words that opened no link').toEqual([])
        const area = await areaOf(page, MIDDLE_LINK, words, FINGER[surface])
        test.info().annotations.push({ type: 'area', description: `middle ${surface} ${size}: ${extentsOf(area)} (least ${String(FINGER[surface])}), ${String(area.taps)} taps` })
        expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(FINGER[surface])
        expectReach(area, words, await paneBox(page), FINGER[surface])
        expectArea(area)
      })

      for (const [where, href, markdown] of EDGES) {
        test(`is the least size for a link ${where}, where the pane's edge cuts one side, on ${surface} at ${size} text size`, async ({ page }) => {
          await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...markdown, PLAIN, PLAIN] })
          if (where === 'at the end of a line') {
            // Every line of the paragraph runs to the pane's right edge, as a full line does: the link's words end at the edge.
            await page.evaluate((target) => {
              const paragraph = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)?.closest('p')
              if (paragraph) {
                paragraph.style.textAlign = 'justify'
                paragraph.style.textAlignLast = 'justify'
              }
            }, href)
          }
          const words = await wordsOf(page, href)
          const pane = await paneBox(page)
          const size = FINGER[surface]
          const room = where === 'at the end of a line' ? pane.right - words.right : words.left - pane.left
          expect(room, `the room the pane gives beside the words ${where}`).toBeLessThan(2)
          const missed = await missedInRing(page, words, size, href)
          expect(missed, 'points of the least size, held inside the pane, that opened no link').toEqual([])
          const area = await areaOf(page, href, words, size)
          test.info().annotations.push({ type: 'area', description: `${where} ${surface} ${ratio === 1 ? 'default' : 'largest'}: ${extentsOf(area)} (least ${String(size)}), ${String(area.taps)} taps` })
          expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(size)
          expectReach(area, words, pane, size)
          expectArea(area)
          // What lights at a click is what opens: the look at the far point of the area, none past it.
          const inside = ringPoints(words, pane, size)
          const far = where === 'at the end of a line' ? inside[0] : inside[inside.length - 1]
          const past = where === 'at the end of a line' ? words.left - size - 12 : words.right + size + 12
          const atFar = await tapAndRead(page, far?.x ?? 0, far?.y ?? 0)
          expect(atFar.lit, 'the pressed look at the press at the far point of the area, which is on plain text').toEqual([null])
          expect(atFar.litAtClick.filter((look) => look === href).length, 'the look at the click at the far point of the area').toBe(1)
          const beyond = await tapAndRead(page, past, words.y)
          expect(beyond.lit, 'the pressed look past the area').toEqual([null])
          expect(beyond.litAtClick, 'the look at the click past the area').toEqual([null])
          expect(beyond.opened, 'links opened by a tap past the area').toEqual([])
        })
      }

      test(`is the least size for a link on the conversation's last line, where the pane's bottom cuts the area below the words, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, only: [...Array.from({ length: 14 }, () => PLAIN), LAST_LINE] })
        const words = await wordsOf(page, LAST)
        await page.evaluate(() => {
          const pane = document.querySelector<HTMLElement>('.m-pane')
          if (pane) pane.scrollTop = pane.scrollHeight
        })
        const settled = await wordsOf(page, LAST)
        const pane = await paneBox(page)
        const size = FINGER[surface]
        expect(settled.top, 'the last line has not moved when the pane is scrolled to its end').toBeGreaterThanOrEqual(words.top - 1)
        // Where the area reaches below the words (the words are shorter than the least size) the pane's bottom cuts it.
        if (settled.bottom - settled.top < size) {
          expect(pane.bottom - settled.bottom, 'the room under the words of the conversation’s last line').toBeLessThan((size - (settled.bottom - settled.top)) / 2)
        }
        const missed = await missedInRing(page, settled, size, LAST)
        expect(missed, 'points of the least size, held inside the pane, that opened no link').toEqual([])
        const area = await areaOf(page, LAST, settled, size)
        test.info().annotations.push({
          type: 'area',
          description: `last line ${surface} ${ratio === 1 ? 'default' : 'largest'}: ${extentsOf(area)} (least ${String(size)}), ${String(area.taps)} taps; room under the words ${String(Math.round((pane.bottom - settled.bottom) * 10) / 10)}`
        })
        expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(size)
        expectReach(area, settled, pane, size)
        expectArea(area)
        const inside = ringPoints(settled, pane, size)
        const top = inside[0]
        const atTop = await tapAndRead(page, top?.x ?? 0, top?.y ?? 0)
        expect(lookDisagrees(atTop), 'the look and the opening at the far point of the area, above the words').toBeNull()
        expect(atTop.litAtClick.filter((look) => look === LAST).length, 'the look at the click at the far point of the area, above the words').toBe(1)
        const above = await tapAndRead(page, settled.x, settled.y - size - 12)
        expect(above.lit, 'the pressed look above the area').toEqual([null])
        expect(above.litAtClick, 'the look at the click above the area').toEqual([null])
        expect(above.opened, 'links opened by a tap above the area').toEqual([])
      })

      test(`agrees between two links on neighbouring lines: the look at the click is the link that opens, at every tap, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...CLOSE, PLAIN, PLAIN] })
        // Reading a link's words scrolls the pane to it, so a position read before the pane settles is stale, and a loop over it taps none of the
        // points between the links. The pane is scrolled to the middle of the space between the two links, which holds both at the largest text
        // size too, and both are read there, with no further scroll.
        await wordsOf(page, 'https://example.org/close-1', -1)
        const apart = (await wordsNow(page, 'https://example.org/close-2')).y - (await wordsNow(page, 'https://example.org/close-1', -1)).y
        await page.evaluate((half) => {
          const pane = document.querySelector<HTMLElement>('.m-pane')
          if (pane) pane.scrollTop += half
        }, apart / 2)
        const first = await wordsNow(page, 'https://example.org/close-1', -1)
        const second = await wordsNow(page, 'https://example.org/close-2')
        const pane = await paneBox(page)
        expect(first.top, 'the first link’s words stand in the pane').toBeGreaterThanOrEqual(pane.top)
        expect(second.bottom, 'the second link’s words stand in the pane').toBeLessThanOrEqual(pane.bottom)
        const wrong: string[] = []
        const kinds = new Map<string, number>()
        // Two axes, a tap every 2 px down each from the middle of the first link's words to the middle of the second's. The first runs through the
        // words and the second past the end of the shorter link's words. Each engine names what it names, at a pointer down and at the click (a
        // pointer down on plain text whose click names a link, a pointer down that the engine moves to a link, plain text at both), and the
        // look and the opening must agree at every tap (`lookDisagrees`). The case needs at least one point that falls on neither link's own
        // element at the tap's point, so that a position that misses the gap fails here and does not pass with no taps in it.
        let between = 0
        for (const [name, x] of [
          ['through the words', first.left + 10],
          ['past the words', Math.min(first.right, second.right) + 8]
        ] as const) {
          for (let y = first.y; y <= second.y; y += 2) {
            const plain = await page.evaluate(({ px, py }) => document.elementFromPoint(px, py)?.closest('.md-link') == null, { px: x, py: y })
            if (plain) between += 1
            const made = await tapAndRead(page, x, y)
            const kind = `press ${made.presses[0]?.named.split(' ')[0] ?? '-'}, click ${browsers(made.clicks)[0]?.named.split(' ')[0] ?? '-'}`
            kinds.set(kind, (kinds.get(kind) ?? 0) + 1)
            const disagreement = lookDisagrees(made)
            if (disagreement !== null) wrong.push(`${name}, y ${String(Math.round(y - first.y))}: ${disagreement}`)
          }
        }
        const counted = [...kinds.entries()].map(([kind, count]) => `${kind}: ${String(count)}`).join('; ')
        test.info().annotations.push({ type: 'taps', description: counted })
        console.log(`taps ${test.info().project.name} ${test.info().title}: ${counted}`)
        expect(between, 'taps on the axes that fall on neither link’s own element').toBeGreaterThanOrEqual(1)
        expect(wrong, 'taps on the axes between the two links where the look and the opening disagree').toEqual([])
        await page.waitForTimeout(400)
        expect(await pressedLooks(page), 'the pressed look 400 ms after the last tap').toBe(0)
      })

      test(`gives the plain text between two links on one line to the nearer words, and the look goes with the open, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        // One line with two links and a plain run between their words: hair spaces joined by word joiners, so that no break opens in the run.
        // The run's length is measured: the case sets the count of hair spaces that makes the gap between the words 36 to 41 px.
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...ORDER, PLAIN, PLAIN] })
        await wordsOf(page, ORDER_ONE)
        const fitted = await page.evaluate(
          ({ one, two, unit }) => {
            const link = (href: string): HTMLElement | null => document.querySelector<HTMLElement>(`.m-node .md-link[title="${href}"]`)
            const words = (href: string): DOMRect[] => {
              const label = link(href)?.querySelector('.md-link-label')
              if (!label) return []
              const range = document.createRange()
              range.selectNodeContents(label)
              return Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)
            }
            const run = link(one)?.nextSibling
            if (!(run instanceof Text)) return { count: 0, gap: Number.NaN, tried: ['the run between the links is not a text node'] }
            const tried: string[] = []
            for (let count = 1; count <= 120; count += 1) {
              run.textContent = unit.repeat(count)
              const left = words(one).at(-1)
              const right = words(two)[0]
              if (!left || !right) return { count: 0, gap: Number.NaN, tried: [...tried, 'a link has no words'] }
              const gap = right.left - left.right
              const sameLine = Math.abs(right.top - left.top) < 2
              tried.push(`${String(count)}: ${gap.toFixed(2)}${sameLine ? '' : ' (not on one line)'}`)
              if (sameLine && gap >= 36 && gap <= 41) return { count, gap, tried: [] }
              if (!sameLine || gap > 41) break
            }
            return { count: 0, gap: Number.NaN, tried }
          },
          { one: ORDER_ONE, two: ORDER_TWO, unit: ' ⁠' }
        )
        expect(fitted.count, `a count of hair spaces that makes a gap of 36 to 41 px between the words (gaps tried ${fitted.tried.join(', ')})`).toBeGreaterThan(0)
        const first = await wordsNow(page, ORDER_ONE, -1)
        const second = await wordsNow(page, ORDER_TWO)
        const reach = FINGER[surface] / 2
        const wrong: string[] = []
        const kinds = new Map<string, number>()
        let nearFirst = 0
        let nearSecond = 0
        // A tap every pixel, from 16 px past the first link's words (past what either engine moves a tap to a link's element) to 16 px before the
        // second's. A tap counts where the pointer down and the click both name plain text and both targets hold the point; the expected link is
        // computed at the pointer down's own point, since the engine may round the tap's and the handler decides there.
        for (let x = Math.ceil(first.right + 16); x <= Math.floor(second.left - 16); x += 1) {
          const made = await tapAndRead(page, x, first.y)
          const press = made.presses[0]
          const click = browsers(made.clicks)[0]
          const kind = `press ${press?.named.split(' ')[0] ?? '-'}, click ${click?.named.split(' ')[0] ?? '-'}`
          kinds.set(kind, (kinds.get(kind) ?? 0) + 1)
          const disagreement = lookDisagrees(made)
          if (disagreement !== null) wrong.push(`x ${String(x - Math.round(first.right))}: ${disagreement}`)
          if (press === undefined || !press.named.startsWith('text') || !(click?.named ?? '').startsWith('text')) continue
          const toFirst = press.x - first.right
          const toSecond = second.left - press.x
          if (toFirst > reach || toSecond > reach) continue
          const expected = toFirst <= toSecond ? ORDER_ONE : ORDER_TWO
          if (expected === ORDER_ONE) nearFirst += 1
          else nearSecond += 1
          if (made.opened.length !== 1 || made.opened[0] !== expected) wrong.push(`x ${String(x - Math.round(first.right))} (pointer down at ${String(press.x)}): opened ${made.opened.join(',') || 'none'}, expected ${expected} once`)
          if (made.litAtClick[0] !== expected) wrong.push(`x ${String(x - Math.round(first.right))}: the look at the click ${String(made.litAtClick[0] ?? null)}, expected ${expected}`)
        }
        const counted = `gap ${fitted.gap.toFixed(2)} px with ${String(fitted.count)} hair spaces; counted taps: ${String(nearFirst)} to the first link, ${String(nearSecond)} to the second; ${[...kinds.entries()].map(([kind, count]) => `${kind}: ${String(count)}`).join('; ')}`
        test.info().annotations.push({ type: 'order', description: counted })
        console.log(`order ${test.info().project.name} ${test.info().title}: ${counted}`)
        expect(nearFirst, 'counted taps that the first link’s words are nearer to').toBeGreaterThanOrEqual(2)
        expect(nearSecond, 'counted taps that the second link’s words are nearer to').toBeGreaterThanOrEqual(2)
        expect(wrong, 'taps between the two links on one line that opened the farther link, or none, or lit another').toEqual([])
        await page.waitForTimeout(400)
        expect(await pressedLooks(page), 'the pressed look 400 ms after the last tap').toBe(0)
      })

      if (ratio === 1) {
        for (const where of ['before', 'after'] as const) {
          test(`opens and lights the link that the browser's click names, though the page is busy for 1.7 s and for 3.2 s ${where === 'before' ? 'before the handler sees' : 'after the handler saw'} the release, on ${surface}`, async ({
            page
          }) => {
            await pressPage(page, surface, { only: [PLAIN, PLAIN, ...CLOSE, PLAIN, PLAIN] })
            await wordsOf(page, 'https://example.org/close-1', -1)
            const apart = (await wordsNow(page, 'https://example.org/close-2')).y - (await wordsNow(page, 'https://example.org/close-1', -1)).y
            await page.evaluate((half) => {
              const pane = document.querySelector<HTMLElement>('.m-pane')
              if (pane) pane.scrollTop += half
            }, apart / 2)
            const first = await wordsNow(page, 'https://example.org/close-1', -1)
            const second = await wordsNow(page, 'https://example.org/close-2')
            // A point where the page's hit test names plain text and the browser's own click names a link (an engine moves a tap to a link: the
            // pointer down names plain text in WebKit and the link's element in Chromium). Found by ordinary taps along the two axes.
            let found: { x: number; y: number; named: string } | null = null
            for (const x of [first.left + 10, Math.min(first.right, second.right) + 8]) {
              for (let y = Math.ceil(first.y); y <= Math.floor(second.y) && found === null; y += 1) {
                const plain = await page.evaluate(({ px, py }) => document.elementFromPoint(px, py)?.closest('.md-link') == null, { px: x, py: y })
                if (!plain) continue
                const made = await tapAndRead(page, x, y)
                const named = browsers(made.clicks)[0]?.named ?? ''
                if (named.startsWith('link ')) found = { x, y, named }
              }
              if (found !== null) break
            }
            expect(found, 'a point at which the page’s hit test names plain text and the browser’s click names a link').not.toBeNull()
            if (found === null) return
            await busyAtPointerUp(page, 1700, where)
            const soon = await tapAndRead(page, found.x, found.y, tapNow)
            expect(lookDisagrees(soon), `the look and the opening of a tap 1.7 s after the release at ${found.named}`).toBeNull()
            expect(soon.opened, 'links opened by the tap 1.7 s after the release').toEqual([found.named.slice('link '.length)])
            expect(soon.litAtClick, 'the look at that click').toEqual([found.named.slice('link '.length)])
            await busyAtPointerUp(page, 3200, where)
            const late = await tapAndRead(page, found.x, found.y, tapNow)
            expect(lookDisagrees(late), `the look and the opening of a tap 3.2 s after the release at ${found.named}`).toBeNull()
            expect(late.opened, 'links opened by the tap 3.2 s after the release, by the browser’s own click').toEqual([found.named.slice('link '.length)])
            expect(late.litAtClick, 'the look at the click 3.2 s after the release').toEqual([found.named.slice('link '.length)])
            expect(handlers(late.clicks), 'clicks that the page added to a click on a link').toEqual([])
            await page.waitForTimeout(400)
            expect(await pressedLooks(page), 'the pressed look 400 ms after the late tap').toBe(0)
          })
        }
      }
    }
  }
})

/** Reads the rectangle of a link's first line of words where the page has it now, with no scrolling. */
async function wordsNow(page: Page, href: string, line = 0): Promise<Words> {
  return page.evaluate(({ target, which }) => {
    const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
    if (!link) throw new Error(`the page shows no link ${target}`)
    const range = document.createRange()
    range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
    const rects = Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)
    const box = which < 0 ? rects[rects.length - 1] : rects[which]
    if (!box) throw new Error(`the link ${target} has no line ${String(which)}`)
    return { x: box.left + box.width / 2, y: box.top + box.height / 2, left: box.left, top: box.top, right: box.right, bottom: box.bottom }
  }, { target: href, which: line })
}

/**
 * Scrolls the pane until the words of a link lie wholly outside one of its edges, `outside` px from it
 * (above the top, below the bottom, or left of the left edge), or until the edge cuts the words through
 * their middle when `outside` is 0. Returns the edge's position and the words where they are now.
 */
async function wordsOutside(page: Page, href: string, edge: 'top' | 'bottom' | 'left', outside: number): Promise<{ edge: number; words: Words }> {
  await wordsOf(page, href)
  // A screen that has just been resized (the keyboard) lays the pane out again: wait until its box holds still.
  await page.waitForFunction(
    () =>
      new Promise<boolean>((resolve) => {
        const pane = document.querySelector<HTMLElement>('.m-pane') as HTMLElement
        const read = (): string => `${String(pane.getBoundingClientRect().bottom)} ${String(pane.clientHeight)}`
        const first = read()
        requestAnimationFrame(() => requestAnimationFrame(() => requestAnimationFrame(() => resolve(read() === first))))
      })
  )
  const box = await paneBox(page)
  const at = edge === 'top' ? box.top : edge === 'bottom' ? box.bottom : box.left
  const view = page.viewportSize()
  if (edge === 'bottom') expect(at, 'the pane’s bottom edge against the screen’s bottom').toBeLessThanOrEqual(view?.height ?? 0)
  await page.evaluate(
    ({ target, edgeAt, side, beyond }) => {
      const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
      const pane = document.querySelector<HTMLElement>('.m-pane')
      if (!link || !pane) throw new Error('the page shows no such link')
      const range = document.createRange()
      range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
      const first = Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)[0]
      if (!first) throw new Error('the link has no words')
      if (side === 'left') {
        pane.scrollLeft += first.left - (beyond === 0 ? edgeAt - first.width / 2 : edgeAt - beyond - first.width)
        return
      }
      const wanted = beyond === 0 ? edgeAt - first.height / 2 : side === 'top' ? edgeAt - beyond - first.height : edgeAt + beyond
      pane.scrollTop += first.top - wanted
    },
    { target: href, edgeAt: at, side: edge, beyond: outside }
  )
  const words = await wordsNow(page, href)
  const gap =
    edge === 'left'
      ? outside === 0
        ? (words.left + words.right) / 2 - at
        : at - words.right
      : outside === 0
        ? (words.top + words.bottom) / 2 - at
        : edge === 'top'
          ? at - words.bottom
          : words.top - at
  expect(Math.abs(gap - outside), `where the scroll left the words of the link against the ${edge} edge`).toBeLessThan(1.5)
  return { edge: at, words }
}

/** The box of a link's own element, which can reach past its words (the line's room at the largest text size). */
async function boxOf(page: Page, href: string): Promise<{ left: number; top: number; right: number; bottom: number }> {
  return page.evaluate((target) => {
    const box = (document.querySelector(`.m-node .md-link[title="${target}"]`) as HTMLElement).getBoundingClientRect()
    return { left: box.left, top: box.top, right: box.right, bottom: box.bottom }
  }, href)
}

// KR-REQ-13.19: the pane scrolls, so its box is the part of the conversation that is in view, and a
// link takes part only by what is in view of its words. Words that the scroll has taken wholly out of
// view (above the pane's top, below its bottom, scrolled up or with the keyboard making the pane
// short) have no area: a tap on the plain text near the edge lights and opens nothing, as on a
// desktop. Words that the edge cuts through keep what is in view of them and their reach, and nothing
// is given back past the edge's own line.
const HIDING = [...Array.from({ length: 12 }, () => PLAIN), ...NEXT_LINE, ...Array.from({ length: 12 }, () => PLAIN)]
/** A run of characters with no place to break, wider than the pane, and a link on the line after it. */
const WIDE = `${'w'.repeat(150)} [a side link](https://example.org/side) and plain words after it on the same line.`
const SIDE = 'https://example.org/side'
test.describe('a link that the scroll has taken out of view or cut', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      for (const edge of ['top', 'bottom'] as const) {
        for (const outside of [10, 30]) {
          test(`has no area when its words are ${String(outside)} px beyond the pane's ${edge} on ${surface} at ${size} text size`, async ({ page }) => {
            await pressPage(page, surface, { scale: ratio, only: HIDING })
            // The bottom edge is the one the keyboard moves: the pane is made short.
            if (edge === 'bottom') await page.setViewportSize({ width: 390, height: 540 })
            const { edge: at, words } = await wordsOutside(page, LEAD, edge, outside)
            const wrong: string[] = []
            for (const inward of [1, 3, 6, 12, 24, 36, 44, 52]) {
              const y = edge === 'top' ? at + inward : at - inward
              const made = await tapAndRead(page, words.x, y)
              const lit = [...made.lit, ...made.litAtClick].find((look) => look !== null) ?? null
              if (lit !== null || made.opened.length > 0) wrong.push(`${String(inward)} px inside the ${edge} (the edge at ${String(at)}): lit ${String(lit)}, opened ${made.opened.join(',') || 'nothing'}`)
            }
            expect(wrong, 'taps on the plain text near the pane’s edge that lit or opened the link whose words are out of view').toEqual([])
          })
        }

        test(`keeps what is in view of a link whose line the pane's ${edge} cuts through, and gives nothing back past the edge, on ${surface} at ${size} text size`, async ({ page }) => {
          await pressPage(page, surface, { scale: ratio, only: HIDING })
          if (edge === 'bottom') await page.setViewportSize({ width: 390, height: 540 })
          const { edge: at, words } = await wordsOutside(page, LEAD, edge, 0)
          const height = words.bottom - words.top
          const reach = Math.max(FINGER[surface], height) / 2
          const sign = edge === 'top' ? 1 : -1
          // On the words that are in view, and on the plain text in the half of the reach that is in view: the link.
          for (const inward of [1, Math.min(height / 2 - 1, reach - 1)]) {
            const y = at + sign * inward
            expect((await tapAndRead(page, words.x, y)).opened, `links opened by a tap ${String(inward)} px inside the ${edge}`).toEqual([LEAD])
          }
          // Past the reach of the words' middle and past the link's own box (the browser's own click goes to
          // that, and the engines adjust a touch by about 8 px more), where the old rule gave back what the
          // edge cut: nothing.
          const own = await boxOf(page, LEAD)
          const inside = Math.max(reach, edge === 'top' ? own.bottom - at : at - own.top)
          const far = at + sign * (inside + 14)
          const made = await tapAndRead(page, words.x, far)
          expect(made.lit, `the pressed look ${String(inside + 14)} px inside the ${edge}`).toEqual([null])
          expect(made.litAtClick, `the look at the click ${String(inside + 14)} px inside the ${edge}`).toEqual([null])
          expect(made.opened, 'links opened past the reach').toEqual([])
        })
      }
    }

    // The pane does scroll sideways: a run of characters with no place to break (a long address in the
    // text, a link whose label has no break) is wider than the pane, and the lines after it start at its left.
    for (const outside of [10, 30]) {
      test(`has no area when its words are ${String(outside)} px beyond the pane's left edge, where the pane scrolls sideways, on ${surface}`, async ({ page }) => {
        await pressPage(page, surface, { only: [PLAIN, WIDE, PLAIN] })
        const room = await page.evaluate(() => {
          const pane = document.querySelector<HTMLElement>('.m-pane') as HTMLElement
          return { scroll: pane.scrollWidth, client: pane.clientWidth }
        })
        expect(room.scroll, 'the pane’s scroll width against its client width, with an unbroken run of characters in a message').toBeGreaterThan(room.client + 100)
        const { edge: at, words } = await wordsOutside(page, SIDE, 'left', outside)
        const wrong: string[] = []
        for (const inward of [1, 3, 6, 12, 24, 36, 44, 52]) {
          const x = at + inward
          const made = await tapAndRead(page, x, words.y)
          const lit = [...made.lit, ...made.litAtClick].find((look) => look !== null) ?? null
          if (lit !== null || made.opened.length > 0) wrong.push(`${String(inward)} px inside the left edge: lit ${String(lit)}, opened ${made.opened.join(',') || 'nothing'}`)
        }
        expect(wrong, 'taps on the plain text near the pane’s left edge that lit or opened the link whose words are out of view').toEqual([])
      })
    }

    test(`keeps what is in view of a link whose line the pane's left edge cuts through, and gives nothing back past the edge, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { only: [PLAIN, WIDE, PLAIN] })
      const { edge: at, words } = await wordsOutside(page, SIDE, 'left', 0)
      const width = words.right - words.left
      const reach = (width + FINGER[surface]) / 2
      for (const inward of [1, Math.min(width / 2 - 1, reach - 1)]) {
        expect((await tapAndRead(page, at + inward, words.y)).opened, `links opened by a tap ${String(inward)} px inside the left edge`).toEqual([SIDE])
      }
      const inside = Math.max(reach, (await boxOf(page, SIDE)).right - at)
      const far = at + inside + 14
      const made = await tapAndRead(page, far, words.y)
      expect(made.lit, `the pressed look ${String(inside + 14)} px inside the left edge`).toEqual([null])
      expect(made.litAtClick, `the look at the click ${String(inside + 14)} px inside the left edge`).toEqual([null])
      expect(made.opened, 'links opened past the reach').toEqual([])
    })
  }
})

// KR-REQ-13.19: a link takes part only by what every box that clips it leaves of the page. The product's
// messages hold no scroller yet, so these cases put the paragraph of a link in a box of 200 px that clips it
// sideways, as the wrapper of a wide table would.
const BOXED = `${'w'.repeat(60)} [a boxed link](https://example.org/boxed) and plain words after it.`
const BOXED_HREF = 'https://example.org/boxed'

/**
 * The room under the line of a box, in px. A box that scrolls sideways has a scroll bar along its lower edge: a
 * system that lays the bar over the content (it shows when the box scrolls, and a press on its track scrolls the
 * box by a page and sends no click) puts it in the lowest rows of the box, and a system that gives the bar room
 * of its own puts it below the box's client area. With this room under the line, a tap on the line lies above
 * the bar of either kind, and the box shows no bar of its own besides.
 */
const BOX_ROOM = 40

/**
 * Puts the paragraph of a link in a box that clips it sideways and scrolls the box until the words end
 * `outside` px before its left client edge, or until that edge cuts through their middle when `outside` is
 * 0. Returns the edge, the words where they are now and where the box is scrolled to.
 */
async function wordsInBox(page: Page, href: string, outside: number): Promise<{ edge: number; words: Words; scroll: number }> {
  await wordsOf(page, href)
  const edge = await page.evaluate(
    ({ target, beyond, room }) => {
      const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
      const paragraph = link?.closest('p')
      if (!link || !paragraph?.parentElement) throw new Error('the page shows no such link')
      const box = document.createElement('div')
      // The box lies 60 px inside the pane, so that its edge clips the words where the pane's own edge does not.
      box.style.cssText = `overflow-x: auto; overflow-y: hidden; width: 200px; margin-left: 60px; padding-bottom: ${String(room)}px; scrollbar-width: none;`
      paragraph.parentElement.insertBefore(box, paragraph)
      box.append(paragraph)
      // The room after the words lets the box scroll them past its left edge.
      paragraph.style.cssText = 'white-space: nowrap; width: max-content; padding-right: 400px;'
      const left = box.getBoundingClientRect().left + box.clientLeft
      const range = document.createRange()
      range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
      const first = Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)[0]
      if (!first) throw new Error('the link has no words')
      box.scrollLeft += first.left - (beyond === 0 ? left - first.width / 2 : left - beyond - first.width)
      return { left, scrolled: box.scrollLeft, scrollWidth: box.scrollWidth, first: first.left }
    },
    { target: href, beyond: outside, room: BOX_ROOM }
  )
  const words = await wordsNow(page, href)
  const gap = outside === 0 ? (words.left + words.right) / 2 - edge.left : edge.left - words.right
  expect(Math.abs(gap - outside), `where the scroll left the words of the link against the box’s left edge (${JSON.stringify({ edge, words })})`).toBeLessThan(1.5)
  return { edge: edge.left, words, scroll: edge.scrolled }
}

/**
 * Asserts that the element at a point inside the box lies in the paragraph of the link. A scroll bar that the
 * box shows over the line, or any other element at the point, fails here with its name, where a tap on it
 * would only show as a tap that got no click.
 */
async function expectParagraphAt(page: Page, href: string, x: number, y: number): Promise<void> {
  const at = await page.evaluate(
    ({ target, px, py }) => {
      const paragraph = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)?.closest('p')
      const hit = document.elementFromPoint(px, py)
      const box = paragraph?.parentElement?.getBoundingClientRect()
      return {
        inside: paragraph !== null && paragraph !== undefined && hit !== null && paragraph.contains(hit),
        named: `${hit?.tagName ?? '-'}.${hit?.className ?? ''}`,
        box: box === undefined ? '-' : `${String(box.left)}..${String(box.right)} x ${String(box.top)}..${String(box.bottom)}`
      }
    },
    { target: href, px: x, py: y }
  )
  expect(at.inside, `the element at ${String(x)}, ${String(y)} in the box (${at.box}) lies in the paragraph of the link, and it is ${at.named}`).toBe(true)
}

/** Asserts that the box has not scrolled since `wordsInBox` left it at `placed`: a press that scrolled it was not a tap on the words. */
async function expectBoxStill(page: Page, href: string, placed: number): Promise<void> {
  const now = await page.evaluate((target) => document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)?.closest('p')?.parentElement?.scrollLeft ?? Number.NaN, href)
  expect(Math.abs(now - placed), `how far the box scrolled, in px, since the words were placed (it was left at ${String(placed)} and stands at ${String(now)})`).toBeLessThan(0.5)
}

test.describe('a link in a box inside a message that clips it', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      for (const outside of [10, 20]) {
        test(`has no area when its words are ${String(outside)} px beyond the box’s left edge on ${surface} at ${size} text size`, async ({ page }) => {
          await pressPage(page, surface, { scale: ratio, only: [PLAIN, BOXED, PLAIN] })
          const { edge, words, scroll } = await wordsInBox(page, BOXED_HREF, outside)
          const wrong: string[] = []
          // Inside the box, and outside it between its edge and the words that it hides.
          for (const inward of [-12, -6, -3, 1, 3, 6, 12, 24, 36, 44, 52]) {
            if (inward > 0) await expectParagraphAt(page, BOXED_HREF, edge + inward, words.y)
            const made = await tapAndRead(page, edge + inward, words.y)
            const lit = [...made.lit, ...made.litAtClick].find((look) => look !== null) ?? null
            if (lit !== null || made.opened.length > 0) wrong.push(`${String(inward)} px inside the box: lit ${String(lit)}, opened ${made.opened.join(',') || 'nothing'}`)
          }
          await expectBoxStill(page, BOXED_HREF, scroll)
          expect(wrong, 'taps near the box’s edge that lit or opened the link whose words the box hides').toEqual([])
        })
      }

      test(`keeps what the box leaves of a link that it cuts through, and gives nothing back past the edge, on ${surface} at ${size} text size`, async ({ page }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, BOXED, PLAIN] })
        const { edge, words, scroll } = await wordsInBox(page, BOXED_HREF, 0)
        const width = words.right - words.left
        const reach = (width + FINGER[surface]) / 2
        for (const inward of [1, Math.min(width / 2 - 1, reach - 1)]) {
          await expectParagraphAt(page, BOXED_HREF, edge + inward, words.y)
          expect((await tapAndRead(page, edge + inward, words.y)).opened, `links opened by a tap ${String(inward)} px inside the box`).toEqual([BOXED_HREF])
        }
        // Outside the box, left of its edge: the words that the box hides take no part, and the target of the part in
        // view is held to the box, so the page adds no click there, though the full words' target would hold the point.
        // Where the browser's own click names the link (WebKit's adjustment reaches the part in view from there) it
        // opens the link, and the look at that click is on it; where the click names plain text nothing opens and
        // nothing is lit. The look and the opening must agree at each tap (`lookDisagrees`).
        for (const outward of [3, 6, 12, 20]) {
          const outside = await tapAndRead(page, edge - outward, words.y)
          expect(handlers(outside.clicks), `clicks that the page added ${String(outward)} px outside the box’s edge`).toEqual([])
          expect(lookDisagrees(outside), `the look and the opening of a tap ${String(outward)} px outside the box’s edge`).toBeNull()
          if (browsers(outside.clicks).every((click) => click.named.startsWith('text'))) {
            expect(outside.litAtClick, `the look at the click ${String(outward)} px outside the box’s edge`).toEqual([null])
            expect(outside.opened, `links opened by a tap ${String(outward)} px outside the box’s edge`).toEqual([])
          }
        }
        const inside = Math.max(reach, (await boxOf(page, BOXED_HREF)).right - edge)
        await expectParagraphAt(page, BOXED_HREF, edge + inside + 14, words.y)
        const made = await tapAndRead(page, edge + inside + 14, words.y)
        await expectBoxStill(page, BOXED_HREF, scroll)
        expect(made.lit, `the pressed look ${String(inside + 14)} px inside the box`).toEqual([null])
        expect(made.litAtClick, `the look at the click ${String(inside + 14)} px inside the box`).toEqual([null])
        expect(made.opened, 'links opened past the reach').toEqual([])
      })
    }
  }
})

