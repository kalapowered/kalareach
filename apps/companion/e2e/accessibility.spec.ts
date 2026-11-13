/**
 * What assistive technology finds on the phone's screens, in both engines the page runs in.
 *
 * The role and name locators and the accessibility snapshot are computed from the page by the test
 * runner, the same way in each engine; the browser's own tree is read as well where the engine
 * offers it.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type CDPSession, type Page } from '@playwright/test'

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
}

/** What a pointer down found: the link lit then (null for none), what it landed on and where. */
interface Look {
  readonly lit: string | null
  readonly target: string
  readonly x: number
  readonly y: number
}

/**
 * Records every click in the page from now on, in `window.clicks`, and the link that is lit at each
 * pointer down (null for none), in `window.looks`. The look is read by a listener that was added after
 * the pane's own, so the pane's handler has set it by then.
 */
async function watchClicks(page: Page): Promise<void> {
  await page.evaluate(() => {
    const clicks: Clicked[] = []
    ;(window as unknown as { clicks: Clicked[] }).clicks = clicks
    const looks: Look[] = []
    ;(window as unknown as { looks: Look[] }).looks = looks
    document.addEventListener(
      'pointerdown',
      (event) => {
        const target = event.target instanceof Element ? event.target : null
        looks.push({
          lit: document.querySelector('.md-link[data-pressed]')?.getAttribute('title') ?? null,
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
          clicks.push({ phase, trusted: event.isTrusted, detail: event.detail, named: nameOf(event.target), x: event.clientX, y: event.clientY })
        },
        phase === 'capture'
      )
    }
  })
}

const clicksSeen = (page: Page): Promise<Clicked[]> =>
  page.evaluate(() => (window as unknown as { clicks: Clicked[] }).clicks.slice())
const looksSeen = (page: Page): Promise<Look[]> => page.evaluate(() => (window as unknown as { looks: Look[] }).looks.slice())

/** The clicks the browser made itself, seen before any handler: what the page was given. */
const browsers = (clicks: readonly Clicked[]): Clicked[] => clicks.filter((click) => click.phase === 'capture' && click.trusted)
/** The clicks that a handler of the page made. */
const handlers = (clicks: readonly Clicked[]): Clicked[] => clicks.filter((click) => click.phase === 'capture' && !click.trusted)

/**
 * A pause long enough for a click's record to be old, made by the page being busy as the pointer comes
 * up: in a listener of the window's capture phase, which runs before the pane's handler sees the
 * release (`before`), or in one of its bubble phase, which runs after it (`after`).
 */
async function busyAtPointerUp(page: Page, milliseconds: number, where: 'before' | 'after'): Promise<void> {
  await page.evaluate(
    ({ busy, capture }) => {
      window.addEventListener(
        'pointerup',
        () => {
          const end = performance.now() + busy
          while (performance.now() < end) {
            // Busy.
          }
        },
        capture
      )
    },
    { busy: milliseconds, capture: where === 'before' }
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
  await state.session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }], timestamp: state.at })
  await state.session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [], timestamp: state.at + 0.05 })
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

/**
 * What one tap did: the clicks the page saw, the links the page opened, and the link lit at the press
 * (null for none), since the tap began. A tap that gets no click from the browser fails here: no point
 * is left out.
 */
async function tapAndRead(
  page: Page,
  x: number,
  y: number,
  tapper: (page: Page, x: number, y: number) => Promise<void> = tap
): Promise<{ clicks: Clicked[]; opened: string[]; lit: (string | null)[]; presses: Look[] }> {
  const clicksBefore = (await clicksSeen(page)).length
  const openedBefore = (await openedLinks(page)).length
  const looksBefore = (await looksSeen(page)).length
  await tapper(page, x, y)
  try {
    await expect.poll(async () => browsers((await clicksSeen(page)).slice(clicksBefore)).length, `a click for a tap at ${String(Math.round(x))}, ${String(Math.round(y))}`).toBeGreaterThan(0)
  } catch (error) {
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
    throw new Error(`${(error as Error).message}; ${where}`, { cause: error })
  }
  return { clicks: (await clicksSeen(page)).slice(clicksBefore), opened: (await openedLinks(page)).slice(openedBefore), lit: (await looksSeen(page)).slice(looksBefore).map((look) => look.lit), presses: (await looksSeen(page)).slice(looksBefore) }
}

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
        expect(late.opened, 'links opened by a click 4.9 s after the release, by a record that old').toEqual([])
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

    test(`takes the pressed look off a touch that the engine cancels as it starts to scroll, and opens nothing, on ${surface}`, async ({
      page,
      browserName
    }) => {
      test.skip(browserName !== 'chromium', 'the touch is moved through the Chromium protocol: WebKit has no tool for a touch that moves')
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
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
      // The engine takes the moving touch for a scroll and cancels the pointer: the handler's own cancel takes the look off, before any release.
      await expect.poll(() => pressedLooks(page), 'the pressed look once the engine cancelled the touch').toBe(0)
      await touch('touchEnd', after.y - 30)
      expect(await page.evaluate(() => (window as unknown as { pointerEnds: string[] }).pointerEnds), 'how the pointer ended').toEqual(['pointercancel'])
      await page.waitForTimeout(400)
      expect(await openedLinks(page), 'links opened by a touch that moved').toEqual([])
    })

    test(`gives the pressed look to the link a touch starts near and takes it off at the release, and lights nothing where no link's target holds the point, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      const near = await tapAndRead(page, after.x, after.y)
      expect(near.lit, 'the pressed look at the press’s start').toEqual([DOCS])
      expect(await pressedLooks(page), 'the pressed look after the release').toBe(0)
      const far = await wordsOf(page, DOCS)
      const none = await tapAndRead(page, far.right + 60, far.y)
      expect(none.lit, 'the pressed look for a press that no link’s target holds').toEqual([null])
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
      await page.mouse.up()
      expect(await pressedLooks(page), 'the pressed look after the release').toBe(0)
    })

    test(`leaves a press on something outside the pane alone, though a link of the pane lies under it, on ${surface}`, async ({ page }) => {
      await pressPage(page, surface, { extra: TEXT_AFTER_LINK })
      const after = await pointOnTextAfter(page, DOCS)
      // A sheet over the pane, with plain words where the pane's link has its reach.
      await page.evaluate(({ x, y }) => {
        const sheet = document.createElement('div')
        sheet.id = 'case-sheet'
        sheet.style.cssText = 'position: fixed; inset: 0; z-index: 99999; background: white'
        const words = document.createElement('p')
        words.textContent = 'plain words of the sheet'
        words.style.cssText = `position: absolute; left: ${String(x - 40)}px; top: ${String(y - 20)}px; width: 160px; height: 40px; margin: 0`
        sheet.append(words)
        document.body.append(sheet)
      }, after)
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
const CLOSE = ['[the first close link](https://example.org/close-1)  \n[the second close link](https://example.org/close-2)']

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

/** What the area measure found. Sizes are in px; the lists are points as offsets from the words' middle. */
interface Area {
  readonly left: number
  readonly right: number
  readonly top: number
  readonly bottom: number
  readonly width: number
  readonly height: number
  readonly taps: number
  /** Taps that opened another link. */
  readonly different: string[]
  /** Taps whose click named plain text, so the page's handler decided, at which the look at the press and the open at the release differed. */
  readonly unlike: string[]
  /** Taps whose click the browser sent to an element, at which the look lit another link than that one. */
  readonly conflicts: string[]
  /** Points inside the area that lights at which the tap opened nothing. */
  readonly holes: string[]
  /** Points between the area that lights and the browser's own adjustment further out at which the tap opened nothing. */
  readonly gaps: string[]
  /** How far the area that opens reaches past the area that lights on each side (px): the browser's own touch adjustment opens a link that the look did not light. */
  readonly ring: { readonly left: number; readonly right: number; readonly top: number; readonly bottom: number }
  /** The taps near the two ends of the area that opens, with what each lit and opened (L lit, O opened), to read a short side by. */
  readonly edges: string[]
}

/**
 * The area in which a tap opens a link, measured by taps that open: the extent, along the line through
 * the words' middle and along the column through it, of the points at which a touch's tap opens `href`,
 * and the extent in which the look lights it. Every tap is a real tap in the pane at a whole pixel
 * (WebKit reports whole pixels) and every one gets the browser's click. Each extent is found from taps
 * 4 px apart and refined to the pixel at each end, inside the pane. At a point where the click names plain
 * text the page's handler decides, and the look at the press is the open at the release (`unlike`). Where
 * the browser's click names an element, the browser decides: the look must have lit nothing or that same
 * link (`conflicts`), and the ring that the open reaches past the look is measured (`ring`).
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
    const opened = made.opened[made.opened.length - 1] ?? null
    const lit = made.lit[0] ?? null
    const where = `${String(Math.round(x - words.x))}, ${String(Math.round(y - words.y))}`
    const press = made.presses[0]
    const capture = made.clicks.filter((click) => click.phase === 'capture')
    const detail = `the press landed on ${press?.target ?? '-'} at ${String(press?.x)}, ${String(press?.y)}; clicks ${capture.map((click) => `${click.trusted ? 'trusted' : 'made'} detail ${String(click.detail)} ${click.named} at ${String(click.x)}, ${String(click.y)}`).join('; ')}`
    const named = capture.find((click) => click.trusted && !click.named.startsWith('text'))?.named ?? null
    if (opened !== null && opened !== href) different.push(`${where}: opened ${opened}`)
    if (named !== null) {
      // The browser's own click names a link or a control: the look lit nothing or that same link.
      if (lit !== null && named !== `link ${lit}`) conflicts.push(`${where}: lit ${lit}; ${detail}`)
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
  const across = await scan('x', Math.floor(words.left - reach), Math.ceil(words.right + reach), Math.ceil(pane.left), Math.ceil(pane.right) - 1, words.x)
  const down = await scan('y', Math.floor(words.top - reach), Math.ceil(words.bottom + reach), Math.ceil(pane.top), Math.ceil(pane.bottom) - 1, words.y)
  const [left, right] = across.open
  const [top, bottom] = down.open
  return {
    left,
    right,
    top,
    bottom,
    width: right - left,
    height: bottom - top,
    taps,
    different,
    unlike,
    conflicts,
    holes,
    gaps,
    ring: { left: across.lit[0] - left, right: right - across.lit[1], top: down.lit[0] - top, bottom: bottom - down.lit[1] },
    edges
  }
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
    const opened = made.opened[made.opened.length - 1] ?? null
    const label = `${String(Math.round(point.x - words.x))}, ${String(Math.round(point.y - words.y))}`
    if (opened !== href) missed.push(`${label}: opened ${String(opened)}`)
    // Where the browser itself sends the click to the link's button the browser decides; elsewhere the handler does, and the look is the open.
    const browser = made.clicks.some((click) => click.phase === 'capture' && click.trusted && click.named.startsWith('link'))
    if (!browser && (made.lit[0] ?? null) !== opened) missed.push(`${label}: lit ${String(made.lit[0] ?? null)}, opened ${String(opened)}`)
  }
  return missed
}

/** Taps one point, and says which link it opened, if any: the link that the page's own opened-links list gained. */
async function tapAt(page: Page, x: number, y: number): Promise<string | null> {
  const made = await tapAndRead(page, x, y)
  return made.opened[made.opened.length - 1] ?? null
}

// KR-REQ-13.19: the area in which a tap opens a link is at least the size the platform asks for around
// the link's words (44 points on iOS and 48 dp on Android, in every direction), and where two links
// stand closer than that, the nearer words have the area between them. The case taps a ring of points
// around the words of a link in the middle of a line, and every point of the axis between two links
// on neighbouring lines. Where the browser's own hit test names a link's button, that link opens, as
// on a desktop; everywhere else the nearer words win.
test.describe('the area in which a tap opens a link', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      test(`is at least the least size around a link's words on ${surface} at ${size} text size`, async ({ page }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...AREA_MIDDLE, PLAIN, PLAIN] })
        const words = await wordsOf(page, MIDDLE_LINK)
        const missed = await missedInRing(page, words, FINGER[surface], MIDDLE_LINK)
        expect(missed, 'points of the least size about the words that opened no link').toEqual([])
        const area = await areaOf(page, MIDDLE_LINK, words, FINGER[surface])
        test.info().annotations.push({ type: 'area', description: `middle ${surface} ${size}: ${String(area.width)} x ${String(area.height)} px (least ${String(FINGER[surface])}), ${String(area.taps)} taps` })
        expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(FINGER[surface])
        expect({ different: area.different, unlike: area.unlike, conflicts: area.conflicts, holes: area.holes }, 'taps across the area that opened another link, did not light what the handler opened, lit one link and met another element, or left a hole').toEqual({ different: [], unlike: [], conflicts: [], holes: [] })
        test.info().annotations.push({ type: 'ring', description: `the browser’s own adjustment opens past the look (px): left ${String(area.ring.left)}, right ${String(area.ring.right)}, top ${String(area.ring.top)}, bottom ${String(area.ring.bottom)}${area.gaps.length > 0 ? `; no open between the look and the adjustment at ${area.gaps.join(' | ')}` : ''}` })
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
          test.info().annotations.push({ type: 'area', description: `${where} ${surface} ${ratio === 1 ? 'default' : 'largest'}: ${String(area.width)} x ${String(area.height)} px (least ${String(size)}), ${String(area.taps)} taps` })
          expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(size)
          expect({ different: area.different, unlike: area.unlike, conflicts: area.conflicts, holes: area.holes }, 'taps across the area that opened another link, did not light what the handler opened, lit one link and met another element, or left a hole').toEqual({ different: [], unlike: [], conflicts: [], holes: [] })
          test.info().annotations.push({ type: 'ring', description: `the browser’s own adjustment opens past the look (px): left ${String(area.ring.left)}, right ${String(area.ring.right)}, top ${String(area.ring.top)}, bottom ${String(area.ring.bottom)}${area.gaps.length > 0 ? `; no open between the look and the adjustment at ${area.gaps.join(' | ')}` : ''}` })
          // What lights at a press is what opens: the pressed look at the far point of the area, none past it.
          const inside = ringPoints(words, pane, size)
          const far = where === 'at the end of a line' ? inside[0] : inside[inside.length - 1]
          const past = where === 'at the end of a line' ? words.left - size - 12 : words.right + size + 12
          const atFar = await tapAndRead(page, far?.x ?? 0, far?.y ?? 0)
          expect(atFar.lit.filter((look) => look !== null).length, 'the pressed look at the far point of the area').toBe(1)
          const beyond = await tapAndRead(page, past, words.y)
          expect(beyond.lit, 'the pressed look past the area').toEqual([null])
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
          description: `last line ${surface} ${ratio === 1 ? 'default' : 'largest'}: ${String(area.width)} x ${String(area.height)} px (least ${String(size)}), ${String(area.taps)} taps; room under the words ${String(Math.round((pane.bottom - settled.bottom) * 10) / 10)}`
        })
        expect.soft(Math.min(area.width, area.height), `the area’s least side, measured by taps that open (taps near the ends: ${area.edges.join(' ')})`).toBeGreaterThanOrEqual(size)
        expect({ different: area.different, unlike: area.unlike, conflicts: area.conflicts, holes: area.holes }, 'taps across the area that opened another link, did not light what the handler opened, lit one link and met another element, or left a hole').toEqual({ different: [], unlike: [], conflicts: [], holes: [] })
        test.info().annotations.push({ type: 'ring', description: `the browser’s own adjustment opens past the look (px): left ${String(area.ring.left)}, right ${String(area.ring.right)}, top ${String(area.ring.top)}, bottom ${String(area.ring.bottom)}${area.gaps.length > 0 ? `; no open between the look and the adjustment at ${area.gaps.join(' | ')}` : ''}` })
        const inside = ringPoints(settled, pane, size)
        const top = inside[0]
        const atTop = await tapAndRead(page, top?.x ?? 0, top?.y ?? 0)
        expect(atTop.lit.filter((look) => look !== null).length, 'the pressed look at the far point of the area, above the words').toBe(1)
        const above = await tapAndRead(page, settled.x, settled.y - size - 12)
        expect(above.lit, 'the pressed look above the area').toEqual([null])
        expect(above.opened, 'links opened by a tap above the area').toEqual([])
      })

      test(`goes between two links on neighbouring lines to the one the browser names, or else the nearer words, on ${surface} at ${size} text size`, async ({
        page
      }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, PLAIN, ...CLOSE, PLAIN, PLAIN] })
        const first = await wordsOf(page, 'https://example.org/close-1')
        const second = await wordsOf(page, 'https://example.org/close-2')
        const x = first.left + 10
        const wrong: string[] = []
        for (let y = first.y; y <= second.y; y += 2) {
          const expected = await page.evaluate(
            ({ px, py }) => {
              const named = document.elementFromPoint(px, py)?.closest('.md-link')
              if (named) return named.getAttribute('title')
              const distance = (href: string): number => {
                const label = document.querySelector(`.m-node .md-link[title="${href}"] .md-link-label`)
                const range = document.createRange()
                if (label) range.selectNodeContents(label)
                const rect = range.getBoundingClientRect()
                return Math.hypot(Math.max(rect.left - px, 0, px - rect.right), Math.max(rect.top - py, 0, py - rect.bottom))
              }
              return distance('https://example.org/close-1') <= distance('https://example.org/close-2')
                ? 'https://example.org/close-1'
                : 'https://example.org/close-2'
            },
            { px: x, py: y }
          )
          const opened = await tapAt(page, x, y)
          if (opened !== expected) wrong.push(`y ${String(Math.round(y - first.y))}: ${String(opened)}, expected ${String(expected)}`)
        }
        expect(wrong, 'taps on the axis between the two links that opened the other link or none').toEqual([])
      })
    }
  }
})

/** Reads the rectangle of a link's first line of words where the page has it now, with no scrolling. */
async function wordsNow(page: Page, href: string): Promise<Words> {
  return page.evaluate((target) => {
    const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
    if (!link) throw new Error(`the page shows no link ${target}`)
    const range = document.createRange()
    range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
    const box = Array.from(range.getClientRects()).filter((rect) => rect.width > 0 && rect.height > 0)[0]
    if (!box) throw new Error(`the link ${target} has no words`)
    return { x: box.left + box.width / 2, y: box.top + box.height / 2, left: box.left, top: box.top, right: box.right, bottom: box.bottom }
  }, href)
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
              const lit = made.lit.find((look) => look !== null) ?? null
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
          const lit = made.lit.find((look) => look !== null) ?? null
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
 * Puts the paragraph of a link in a box that clips it sideways and scrolls the box until the words end
 * `outside` px before its left client edge, or until that edge cuts through their middle when `outside` is
 * 0. Returns the edge and the words where they are now.
 */
async function wordsInBox(page: Page, href: string, outside: number): Promise<{ edge: number; words: Words }> {
  await wordsOf(page, href)
  const edge = await page.evaluate(
    ({ target, beyond }) => {
      const link = document.querySelector<HTMLElement>(`.m-node .md-link[title="${target}"]`)
      const paragraph = link?.closest('p')
      if (!link || !paragraph?.parentElement) throw new Error('the page shows no such link')
      const box = document.createElement('div')
      box.style.cssText = 'overflow-x: auto; overflow-y: hidden; width: 200px;'
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
    { target: href, beyond: outside }
  )
  const words = await wordsNow(page, href)
  const gap = outside === 0 ? (words.left + words.right) / 2 - edge.left : edge.left - words.right
  expect(Math.abs(gap - outside), `where the scroll left the words of the link against the box’s left edge (${JSON.stringify({ edge, words })})`).toBeLessThan(1.5)
  return { edge: edge.left, words }
}

test.describe('a link in a box inside a message that clips it', () => {
  test.use({ hasTouch: true })
  for (const surface of SURFACES) {
    for (const [size, ratio] of SIZES) {
      for (const outside of [10, 20]) {
        test(`has no area when its words are ${String(outside)} px beyond the box’s left edge on ${surface} at ${size} text size`, async ({ page }) => {
          await pressPage(page, surface, { scale: ratio, only: [PLAIN, BOXED, PLAIN] })
          const { edge, words } = await wordsInBox(page, BOXED_HREF, outside)
          const wrong: string[] = []
          for (const inward of [1, 3, 6, 12, 24, 36, 44, 52]) {
            const made = await tapAndRead(page, edge + inward, words.y)
            const lit = made.lit.find((look) => look !== null) ?? null
            if (lit !== null || made.opened.length > 0) wrong.push(`${String(inward)} px inside the box: lit ${String(lit)}, opened ${made.opened.join(',') || 'nothing'}`)
          }
          expect(wrong, 'taps on the plain text inside the box that lit or opened the link whose words the box hides').toEqual([])
        })
      }

      test(`keeps what the box leaves of a link that it cuts through, and gives nothing back past the edge, on ${surface} at ${size} text size`, async ({ page }) => {
        await pressPage(page, surface, { scale: ratio, only: [PLAIN, BOXED, PLAIN] })
        const { edge, words } = await wordsInBox(page, BOXED_HREF, 0)
        const width = words.right - words.left
        const reach = (width + FINGER[surface]) / 2
        for (const inward of [1, Math.min(width / 2 - 1, reach - 1)]) {
          expect((await tapAndRead(page, edge + inward, words.y)).opened, `links opened by a tap ${String(inward)} px inside the box`).toEqual([BOXED_HREF])
        }
        const inside = Math.max(reach, (await boxOf(page, BOXED_HREF)).right - edge)
        const made = await tapAndRead(page, edge + inside + 14, words.y)
        expect(made.lit, `the pressed look ${String(inside + 14)} px inside the box`).toEqual([null])
        expect(made.opened, 'links opened past the reach').toEqual([])
      })
    }
  }
})

