/**
 * What assistive technology finds on the phone's screens, in both engines the page runs in.
 *
 * The role and name locators and the accessibility snapshot are computed from the page by the test
 * runner, the same way in each engine; the browser's own tree is read as well where the engine
 * offers it.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type Page } from '@playwright/test'

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

/** What a finger meets, in CSS pixels: 44 points on iOS and 48 dp on Android. */
const FINGER = { ios: 44, android: 48 } as const

interface Box {
  readonly left: number
  readonly top: number
  readonly width: number
  readonly height: number
}

interface LinkReading {
  readonly label: string
  /** The size of the link's box where a finger can press it: what the pane and the screen leave of it. */
  readonly width: number
  readonly height: number
  /** How far the words after the link moved because of its reach, and the most the room it has lets them move. */
  readonly moved: number
  readonly mostMoved: number
  /** How far the link's own words and the words before it moved sideways because of its reach. */
  readonly wordsMoved: number
  readonly beforeMoved: number
}

interface LinksReading {
  /** What moved up or down when the links' reach was taken away: the same page without it is the control. */
  readonly shifted: readonly string[]
  readonly links: readonly LinkReading[]
  /** How far the box of the link on the conversation's last line lies below the pane at its end. */
  readonly cut: number
  /** The pane and what holds it, when they scroll or clip sideways and have more than they show. */
  readonly overflowing: readonly string[]
}

// KR-REQ-13.19: a link inside a message is a button that is one line tall, and the box that a finger,
// TalkBack and VoiceOver find for it is the size the platform asks for all the same. The box is read
// from the page, which is what the platforms' trees are built from, and cut to what the pane and the
// screen show of it. Taking the reach away shows nothing moves up or down. Sideways, the words around
// a link move only by what the room beside the link cannot give it: a label as wide as the box needs
// moves nothing, and a narrower one moves the words after it by the difference and no more, whether
// it is one character, four narrow ones or one in bold. What is not held, and is not asserted: a line
// with less room than that difference to spare breaks one word earlier.
// A link at the start of a line, at its end and alone on a line shows the box is whole at the pane's
// edges and the conversation does not scroll sideways for it, and a link on the last line shows the
// pane holds its box at the end. Which link a press at a point belongs to is the next case's.
test.describe('a link inside a message', () => {
  for (const surface of ['ios', 'android'] as const) {
    test(`is a full touch target on ${surface} and moves the words after it only as far as a narrow label needs`, async ({ page }) => {
      await openSession(page, surface)
      await page.getByRole('button', { name: 'the reconnect notes' }).scrollIntoViewIfNeeded()
      const reading = await page.evaluate((finger: number): LinksReading | null => {
        const originals = Array.from(document.querySelectorAll<HTMLElement>('.m-node .md-link'))
        const first = originals[0]
        const paragraph = first?.parentElement
        const pane = document.querySelector<HTMLElement>('.m-pane')
        const main = document.querySelector<HTMLElement>('.m-main')
        const nodes = Array.from(document.querySelectorAll<HTMLElement>('.m-node'))
        const lastNode = nodes[nodes.length - 1]
        if (!first || !paragraph || !pane || !main || !lastNode) return null

        const wordsOf = (link: HTMLElement): Range => {
          const range = document.createRange()
          range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
          return range
        }
        const afterOf = (link: HTMLElement): Range | null => {
          const next = link.nextSibling
          if (!next || next.nodeType !== Node.TEXT_NODE || (next.textContent ?? '').length < 1) return null
          const range = document.createRange()
          range.setStart(next, 0)
          range.setEnd(next, 1)
          return range
        }
        const beforeOf = (link: HTMLElement): Range | null => {
          const previous = link.previousSibling
          const length = (previous?.textContent ?? '').length
          if (!previous || previous.nodeType !== Node.TEXT_NODE || length < 1) return null
          const range = document.createRange()
          range.setStart(previous, length - 1)
          range.setEnd(previous, length)
          return range
        }
        const boxOf = (box: DOMRect): Box => ({ left: box.left, top: box.top, width: box.width, height: box.height })

        // More links of the kinds a message can carry, each a copy of the first with other words: on
        // the next line, beside another with one space between, a single character, one in plain
        // lines, one as long as the line, one that ends the conversation, a single character at the
        // start of a line, at its end and alone on a line, one character drawn in bold, four narrow
        // characters, and two one directly under the other.
        const another = (text: string, bold = false): HTMLElement => {
          const link = first.cloneNode(true) as HTMLElement
          const label = link.querySelector('.md-link-label') ?? link
          if (bold) {
            // As `[**1**](...)` is drawn: the words are one character in an element of their own.
            const strong = document.createElement('strong')
            strong.textContent = text
            label.replaceChildren(strong)
          } else {
            label.textContent = text
          }
          return link
        }
        const row = (align: 'left' | 'right', ...parts: (string | HTMLElement)[]): HTMLElement => {
          const line = document.createElement('p')
          line.style.textAlign = align
          line.append(...parts)
          return line
        }
        const second = another('a second link')
        const third = another('1')
        const framedLink = another('a link in plain text')
        const wide = another('a link whose words run the whole width of the line and on to the next ')
        const closing = another('the last link')
        const atStart = another('1')
        const atEnd = another('1')
        const aloneAtStart = another('1')
        const aloneAtEnd = another('1')
        const formatted = another('1', true)
        const narrow = another('iiii')
        const pairAbove = another('the first of two links')
        const pairBelow = another('the second of two links')
        paragraph.append(document.createElement('br'), second, ' ', third, ', and plain words after it.')
        const framed = row(
          'left',
          'A plain line above the link.',
          document.createElement('br'),
          framedLink,
          ', and plain words after it on the same line.',
          document.createElement('br'),
          'A plain line under the link.'
        )
        const edges = [
          row('left', atStart, ', then plain words after the link at the start of the line.'),
          row('right', 'Plain words before the link at the end of the line, ', atEnd),
          row('left', aloneAtStart),
          row('right', aloneAtEnd),
          row('left', formatted, ', formatted words after a link of one character.'),
          row('left', narrow, ', four narrow characters after a link.')
        ]
        const pair = row('left', pairAbove, document.createElement('br'), pairBelow)
        const longer = row('left', wide)
        const ending = row('left', 'The last line of the conversation ends in ', closing)
        paragraph.after(framed, ...edges, pair, longer)
        lastNode.append(ending)
        const links = [...originals, second, third, framedLink, atStart, atEnd, aloneAtStart, aloneAtEnd, formatted, narrow, pairAbove, pairBelow, wide, closing]

        // The control: the same page with the links' reach taken away.
        const gutter = parseFloat(getComputedStyle(main).paddingLeft)
        const places = (): Record<string, Box> => {
          pane.scrollTop = 0
          const boxes: Record<string, Box> = {
            'the first lines': boxOf(paragraph.getBoundingClientRect()),
            'the plain lines': boxOf(framed.getBoundingClientRect()),
            'the long line': boxOf(longer.getBoundingClientRect()),
            'the last message': boxOf(lastNode.getBoundingClientRect())
          }
          links.forEach((link, index) => {
            const name = `"${link.textContent ?? ''}" (${String(index + 1)})`
            boxes[`the words of ${name}`] = boxOf(wordsOf(link).getBoundingClientRect())
            const after = afterOf(link)
            if (after) boxes[`what follows ${name}`] = boxOf(after.getBoundingClientRect())
            const ahead = beforeOf(link)
            if (ahead) boxes[`what precedes ${name}`] = boxOf(ahead.getBoundingClientRect())
          })
          return boxes
        }
        const before = places()
        const bare = document.createElement('style')
        bare.textContent = [
          '.m-pane { padding-inline: 0 !important; margin-inline: 0 !important }',
          '.m-node .md-link { padding: 0 !important; margin: 0 !important; min-inline-size: 0 !important }'
        ].join(' ')
        document.head.append(bare)
        const without = places()
        bare.remove()
        const shifted = Object.keys(before).filter(
          (name) =>
            Math.abs((before[name]?.top ?? 0) - (without[name]?.top ?? 0)) > 0.5 ||
            Math.abs((before[name]?.height ?? 0) - (without[name]?.height ?? 0)) > 0.5
        )

        const paneBox = pane.getBoundingClientRect()
        const room = Math.min(finger / 2, gutter)
        const readings = links.map((link, index): LinkReading => {
          link.scrollIntoView({ block: 'center' })
          const box = link.getBoundingClientRect()
          const name = `"${link.textContent ?? ''}" (${String(index + 1)})`
          const wordsWidth = without[`the words of ${name}`]?.width ?? 0
          const was = without[`what follows ${name}`]
          const is = before[`what follows ${name}`]
          const wordsWas = without[`the words of ${name}`]
          const wordsIs = before[`the words of ${name}`]
          const ahead = [without[`what precedes ${name}`], before[`what precedes ${name}`]] as const
          return {
            label: link.textContent ?? '',
            width: Math.min(box.right, paneBox.right, window.innerWidth) - Math.max(box.left, paneBox.left, 0),
            height: Math.min(box.bottom, paneBox.bottom, window.innerHeight) - Math.max(box.top, paneBox.top, 0),
            moved: was && is ? Math.abs(is.left - was.left) : 0,
            wordsMoved: wordsWas && wordsIs ? Math.abs(wordsIs.left - wordsWas.left) : 0,
            beforeMoved: ahead[0] && ahead[1] ? Math.abs(ahead[1].left - ahead[0].left) : 0,
            mostMoved: Math.max(0, finger - 2 * room - wordsWidth),
          }
        })

        pane.scrollTop = pane.scrollHeight
        const cut = closing.getBoundingClientRect().bottom - pane.getBoundingClientRect().bottom

        // Sideways, from the pane up: nothing that holds the conversation scrolls or clips it for a link's reach.
        const overflowing: string[] = []
        for (let each: HTMLElement | null = pane; each; each = each.parentElement) {
          const holds = each === document.documentElement || getComputedStyle(each).overflowX !== 'visible'
          if (holds && each.scrollWidth > each.clientWidth + 1) overflowing.push(each.className || each.tagName)
        }
        return { shifted, links: readings, cut, overflowing }
      }, FINGER[surface])
      if (!reading) throw new Error('the conversation shows no link')
      expect.soft(reading.shifted, 'what moved up or down when the reach was taken away').toEqual([])
      for (const link of reading.links) {
        expect.soft(link.width, `the width of "${link.label}" where it can be pressed`).toBeGreaterThanOrEqual(FINGER[surface] - 0.5)
        expect.soft(link.height, `the height of "${link.label}" where it can be pressed`).toBeGreaterThanOrEqual(FINGER[surface] - 0.5)
        // Within a pixel: layout rounds a button's width to a fraction of a pixel, and the same label differs by that.
        expect.soft(link.moved, `how far the words after "${link.label}" moved sideways`).toBeLessThanOrEqual(link.mostMoved + 1)
        // The label is centred in the box, so a widened box moves it by half of the difference.
        expect.soft(link.wordsMoved, `how far "${link.label}" moved sideways`).toBeLessThanOrEqual(link.mostMoved / 2 + 1)
        expect.soft(link.beforeMoved, `how far the words before "${link.label}" moved sideways`).toBeLessThanOrEqual(link.mostMoved + 1)
      }
      expect.soft(reading.cut, 'how far the box of the last line’s link lies below the pane at its end').toBeLessThanOrEqual(0.5)
      expect.soft(reading.overflowing, 'what scrolls or clips sideways from the pane up').toEqual([])
    })
  }
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

/** The paragraphs that the press case sets at the end of the line. */
const PRESS_AT_THE_END = ['https://example.org/at-end', 'https://example.org/alone-end']
/** The paragraphs that the press case sets right to left. */
const PRESS_RIGHT_TO_LEFT = ['https://example.org/rtl-start', 'https://example.org/rtl-middle']

/** What a press at one point is expected to do, computed by the case from the rectangles it reads. */
interface PressPoint {
  readonly x: number
  readonly y: number
  /** The link the case's own rule names, by its target, or null. */
  readonly expected: string | null
  /** How far the pane was scrolled when the point was read. */
  readonly scroll: number
  /** Whether the point lies on another control of the message, which then takes the press. */
  readonly control: boolean
}

interface PressMark {
  readonly x: number
  readonly y: number
  /** How many links had been opened when the press began. */
  readonly opened: number
  /** The links that showed the pressed look at the press's start, in the order of the page. */
  readonly pressed: readonly string[]
  /** How far the pane was scrolled at the press's start. */
  readonly scroll: number
  /** How many clicks the message's other controls had had when the press began. */
  readonly clicked: number
}

// KR-REQ-13.19: where a message's links lie close together, the press at a point belongs to the link
// whose words are nearest to it, and a press that no link's area holds opens nothing. The case presses
// a grid of points around every link of a table, a quote, a list, a heading, two short links side by
// side, a link under one that wraps, a link above the control of an image, the pane's edges and a
// right-to-left paragraph, at two widths and three text sizes, and compares the link that opens with
// the link the case names from the rectangles of the words it reads from the page. A link's area is
// its words, grown to the least size the platform asks for and by the room beside the words, held to
// the pane: the rule written again here, a few lines of it, and not the product's function. A point
// on another control of the message is that control's. The pressed look must be on that link at the
// press's start, and on none after the press. A point that the rule decides by less than 1.5 px (an
// equal distance, the edge of an area) is not pressed: layout and the pointer round to a fraction of a
// pixel, and the unit cases of the rule hold those points.
// KR-REQ-13.19: a link opens when its press ends, as a control does. A press that moves away by more
// than the platform's slop opens nothing and takes the pressed look off, a press that stays within the
// slop opens the link, and a click that no pointer made (a keyboard's) goes to the element it names.
test.describe('the end of a press on a link of a message', () => {
  for (const surface of ['ios', 'android'] as const) {
    test(`opens the link, unless the press moved away, and a keyboard opens the link it names on ${surface}`, async ({ page }) => {
      await openSession(page, surface)
      // Messages enough for the conversation to scroll, and a pane that desktop WebKit does not scroll by focusing it.
      await page.evaluate(
        ({ messages, session }) => {
          for (const message of messages) window.krTestHost?.records.appendEntry(session, 'message', message)
          document.dispatchEvent(new Event('visibilitychange'))
          document.querySelector('.m-pane')?.removeAttribute('tabindex')
        },
        { messages: PRESS_MESSAGES, session: SESSION }
      )
      const link = page.getByRole('button', { name: 'the reconnect notes' })
      await link.evaluate((element) => {
        element.scrollIntoView({ block: 'center' })
      })
      const words = await link.evaluate((element) => {
        const range = document.createRange()
        range.selectNodeContents(element.querySelector('.md-link-label') ?? element)
        const box = range.getBoundingClientRect()
        return { x: box.left + box.width / 2, y: box.top + box.height / 2 }
      })
      const opened = (): Promise<number> => page.evaluate(() => window.krTestHost?.openedLinks.length ?? -1)
      const lit = (): Promise<number> => page.evaluate(() => document.querySelectorAll('.md-link[data-pressed]').length)

      // Within the slop: the pressed look at the start, the link opened at the end.
      await page.mouse.move(words.x, words.y)
      await page.mouse.down()
      expect(await lit(), 'the pressed look at the press’s start').toBe(1)
      await page.mouse.move(words.x + 4, words.y + 2)
      expect(await lit(), 'the pressed look after a move within the slop').toBe(1)
      await page.mouse.up()
      expect(await lit(), 'the pressed look after the press').toBe(0)
      expect(await opened(), 'links opened by a press that stayed').toBe(1)

      // Away: the look goes when the press leaves, and nothing opens.
      await page.mouse.move(words.x, words.y)
      await page.mouse.down()
      await page.mouse.move(words.x + 6, words.y - 40, { steps: 4 })
      expect(await lit(), 'the pressed look after a move away').toBe(0)
      await page.mouse.up()
      expect(await opened(), 'links opened by a press that moved away').toBe(1)

      // No pointer: a keyboard's click goes to the focused link, as it is.
      await link.focus()
      await page.keyboard.press('Enter')
      expect(await opened(), 'links opened by Enter').toBe(2)
      await page.keyboard.press('Space')
      expect(await opened(), 'links opened by Space').toBe(3)

      // A press while the conversation scrolls: the link has moved from under the press, so the release opens nothing.
      await link.evaluate((element) => {
        element.scrollIntoView({ block: 'center' })
      })
      const again = await link.evaluate((element) => {
        const range = document.createRange()
        range.selectNodeContents(element.querySelector('.md-link-label') ?? element)
        const box = range.getBoundingClientRect()
        return { x: box.left + box.width / 2, y: box.top + box.height / 2 }
      })
      await page.mouse.move(again.x, again.y)
      await page.mouse.down()
      expect(await lit(), 'the pressed look at the start of a press that is then scrolled').toBe(1)
      const before = await page.evaluate(() => document.querySelector('.m-pane')?.scrollTop ?? 0)
      await page.mouse.wheel(0, 90)
      await expect.poll(() => page.evaluate(() => document.querySelector('.m-pane')?.scrollTop ?? 0)).toBeGreaterThan(before + 40)
      await page.mouse.up()
      expect(await lit(), 'the pressed look after the press').toBe(0)
      expect(await opened(), 'links opened by a press that was scrolled').toBe(3)
    })
  }
})

// KR-REQ-13.19: a touch tap, with its pointer events and the click that follows them, opens the link
// whose words are nearest: on the words, on plain text within the link's area, and not outside it.
test.describe('a tap on a link of a message', () => {
  test.use({ hasTouch: true })
  for (const surface of ['ios', 'android'] as const) {
    test(`opens the link on its words and beside them, and not outside its area on ${surface}`, async ({ page }) => {
      await openSession(page, surface)
      await page.evaluate(
        ({ messages, session }) => {
          for (const message of messages) window.krTestHost?.records.appendEntry(session, 'message', message)
          document.dispatchEvent(new Event('visibilitychange'))
          document.querySelector('.m-pane')?.removeAttribute('tabindex')
        },
        { messages: PRESS_MESSAGES, session: SESSION }
      )
      const link = page.getByRole('button', { name: 'the reconnect notes' })
      const words = await link.evaluate((element) => {
        element.scrollIntoView({ block: 'center' })
        const range = document.createRange()
        range.selectNodeContents(element.querySelector('.md-link-label') ?? element)
        const box = range.getBoundingClientRect()
        return { x: box.left + box.width / 2, y: box.top + box.height / 2, right: box.right, bottom: box.bottom }
      })
      const opened = (): Promise<number> => page.evaluate(() => window.krTestHost?.openedLinks.length ?? -1)
      await page.touchscreen.tap(words.x, words.y)
      await expect.poll(opened, 'links opened by a tap on the words').toBe(1)
      await page.touchscreen.tap(words.x, words.bottom + 8)
      await expect.poll(opened, 'links opened by a tap on plain text under the words').toBe(2)
      await page.touchscreen.tap(words.right + 8, words.y)
      await expect.poll(opened, 'links opened by a tap on plain text beside the words').toBe(3)
      await page.touchscreen.tap(words.right + 60, words.y)
      expect(await opened(), 'links opened by a tap outside the link’s area').toBe(3)
    })
  }
})

test.describe('a press by the links of a message', () => {
  const GRID = 8
  const EDGE = 1.5
  const SIZES = [
    ['the smallest', 14 / 17],
    ['the default', 1],
    ['the largest', 53 / 17]
  ] as const
  for (const surface of ['ios', 'android'] as const) {
    for (const width of [320, 390]) {
      for (const [size, ratio] of SIZES) {
        test(`opens the link whose words are nearest on ${surface}, ${String(width)} px wide at ${size} text size`, async ({ page }) => {
          test.setTimeout(300_000)
          await withTextScale(page, ratio)
          await openSession(page, surface, width)
          await page.evaluate(
            ({ messages, session }) => {
              for (const message of messages) window.krTestHost?.records.appendEntry(session, 'message', message)
              document.dispatchEvent(new Event('visibilitychange'))
            },
            { messages: PRESS_MESSAGES, session: SESSION }
          )
          await page.locator('.m-node .md-link[title="https://example.org/rtl-middle"]').waitFor({ state: 'attached' })
          await page.evaluate(
            ({ atTheEnd, rightToLeft }) => {
              const paragraphOf = (href: string): HTMLElement | null =>
                document.querySelector(`.m-node .md-link[title="${href}"]`)?.closest('p') ?? null
              for (const href of atTheEnd) {
                const paragraph = paragraphOf(href)
                if (paragraph) paragraph.style.textAlign = 'right'
              }
              for (const href of rightToLeft) paragraphOf(href)?.setAttribute('dir', 'rtl')
              // Desktop WebKit scrolls a pane that it focuses for a press on text, which would move the
              // points under the case's feet, and a press that scrolls is not a press: the pane is left
              // unfocusable here. The page's own focus management is not what is checked.
              document.querySelector('.m-pane')?.removeAttribute('tabindex')
              // The clicks that the message's other controls get, counted where the page counts them.
              const counted = window as unknown as { controlClicks: number }
              counted.controlClicks = 0
              for (const control of document.querySelectorAll('.m-pane button:not(.md-link)')) {
                control.addEventListener('click', () => {
                  counted.controlClicks += 1
                })
              }
              // What a press did, read where the page reads it: at the press's start, after the page's own handling.
              const marks: PressMark[] = []
              ;(window as unknown as { pressMarks: PressMark[] }).pressMarks = marks
              document.addEventListener('pointerdown', (event) => {
                marks.push({
                  x: event.clientX,
                  y: event.clientY,
                  opened: window.krTestHost?.openedLinks.length ?? 0,
                  pressed: Array.from(document.querySelectorAll<HTMLElement>('.md-link[data-pressed]'), (link) => link.title),
                  scroll: document.querySelector('.m-pane')?.scrollTop ?? 0,
                  clicked: counted.controlClicks
                })
              })
            },
            { atTheEnd: PRESS_AT_THE_END, rightToLeft: PRESS_RIGHT_TO_LEFT }
          )
          const hrefs = await page.evaluate(() =>
            Array.from(document.querySelectorAll<HTMLElement>('.m-node .md-link'), (link) => link.title)
          )
          expect(hrefs.length, 'the links on the page').toBeGreaterThanOrEqual(27)

          const planned: PressPoint[] = []
          let skipped = 0
          for (const href of hrefs) {
            const plan = await page.evaluate(
              ({ href, finger, grid, edge, scrollbar }) => {
                const links = Array.from(document.querySelectorAll<HTMLElement>('.m-node .md-link'))
                const link = links.find((each) => each.title === href)
                const pane = document.querySelector<HTMLElement>('.m-pane')
                const main = document.querySelector<HTMLElement>('.m-main')
                if (!link || !pane || !main) return null
                link.scrollIntoView({ block: 'center' })
                const room = pane.getBoundingClientRect()
                const beside = Math.min(finger / 2, parseFloat(getComputedStyle(main).paddingLeft))
                interface Area {
                  readonly left: number
                  readonly top: number
                  readonly right: number
                  readonly bottom: number
                }
                const wordsOf = (each: HTMLElement): Area[] => {
                  const range = document.createRange()
                  range.selectNodeContents(each.querySelector('.md-link-label') ?? each)
                  return Array.from(range.getClientRects())
                    .filter((rect) => rect.width > 0 && rect.height > 0)
                    .map((rect) => ({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
                }
                const areaOf = (words: Area): Area => {
                  const wide = Math.max(finger, words.right - words.left + 2 * beside)
                  const tall = Math.max(finger, words.bottom - words.top)
                  const x = (words.left + words.right) / 2
                  const y = (words.top + words.bottom) / 2
                  return {
                    left: Math.max(x - wide / 2, room.left),
                    right: Math.min(x + wide / 2, room.right),
                    top: Math.max(y - tall / 2, room.top),
                    bottom: Math.min(y + tall / 2, room.bottom)
                  }
                }
                const gap = (area: Area, x: number, y: number): number =>
                  Math.hypot(Math.max(area.left - x, 0, x - area.right), Math.max(area.top - y, 0, y - area.bottom))
                // How far inside an area a point is: negative outside it.
                const depth = (area: Area, x: number, y: number): number =>
                  Math.min(x - area.left, area.right - x, y - area.top, area.bottom - y)
                const all = links.map((each) => ({ title: each.title, words: wordsOf(each) }))
                // The message's other controls: a point on one is the control's, whichever link's area holds it.
                const controls = Array.from(pane.querySelectorAll<HTMLElement>('button:not(.md-link)'), (each): Area => {
                  const box = each.getBoundingClientRect()
                  return { left: box.left, top: box.top, right: box.right, bottom: box.bottom }
                })
                // The link the rule names at a point, and whether the point is clear of every edge of the rule.
                const decide = (x: number, y: number): { expected: string | null; clear: boolean; control: boolean } => {
                  if (controls.some((box) => Math.abs(depth(box, x, y)) < edge)) return { expected: null, clear: false, control: false }
                  if (controls.some((box) => depth(box, x, y) >= 0)) return { expected: null, clear: true, control: true }
                  const held = all
                    .map((each) => ({
                      title: each.title,
                      reached: each.words.some((words) => depth(areaOf(words), x, y) >= 0),
                      near: each.words.some((words) => Math.abs(depth(areaOf(words), x, y)) < edge),
                      distance: Math.min(...each.words.map((words) => gap(words, x, y)))
                    }))
                    .filter((each) => each.reached || each.near)
                  const sure = held.filter((each) => each.reached && !each.near)
                  const ranked = [...sure].sort((a, b) => a.distance - b.distance)
                  const unsure = held.some((each) => each.near) || (ranked[1] !== undefined && ranked[1].distance - (ranked[0]?.distance ?? 0) < edge)
                  // The earlier link wins an exact tie, so sorting by distance only keeps the order of the page.
                  return { expected: ranked[0]?.title ?? null, clear: !unsure, control: false }
                }
                const inRoom = (x: number, y: number): boolean => {
                  if (x < 0 || y < 0 || x > window.innerWidth - 1 || y > window.innerHeight - 1) return false
                  if (x >= room.right - scrollbar) return false
                  const found = document.elementFromPoint(x, y)
                  return found !== null && pane.contains(found)
                }
                const seen = new Set<string>()
                const points: { x: number; y: number; expected: string | null; scroll: number; control: boolean }[] = []
                let unclear = 0
                const consider = (x: number, y: number, always: boolean): void => {
                  const px = Math.round(x)
                  const py = Math.round(y)
                  const key = `${String(px)},${String(py)}`
                  if (seen.has(key) || !inRoom(px, py)) return
                  seen.add(key)
                  const verdict = decide(px, py)
                  if (!verdict.clear) {
                    unclear += 1
                    return
                  }
                  // In the open, away from every edge, one point in three says as much as all of them.
                  if (!always && verdict.expected !== null && (px + py) % 3 !== 0) return
                  points.push({ x: px, y: py, expected: verdict.expected, scroll: pane.scrollTop, control: verdict.control })
                }
                // Along the edges of every control that this link's area overlaps, on both sides of each edge.
                const overlapped = controls.filter((box) =>
                  wordsOf(link).some((words) => {
                    const area = areaOf(words)
                    return area.left <= box.right + 6 && area.right >= box.left - 6 && area.top <= box.bottom + 6 && area.bottom >= box.top - 6
                  })
                )
                for (const box of overlapped) {
                  for (const d of [-3, -1, 1, 3]) {
                    for (const across of [0.1, 0.3, 0.5, 0.7, 0.9]) {
                      const x = box.left + (box.right - box.left) * across
                      const y = box.top + (box.bottom - box.top) * across
                      consider(x, box.top + d, true)
                      consider(x, box.bottom + d, true)
                      consider(box.left + d, y, true)
                      consider(box.right + d, y, true)
                    }
                  }
                }
                for (const words of wordsOf(link)) {
                  const area = areaOf(words)
                  const x0 = (words.left + words.right) / 2
                  const y0 = (words.top + words.bottom) / 2
                  const reachX = Math.max(area.right - x0, x0 - area.left) + 6
                  const reachY = Math.max(area.bottom - y0, y0 - area.top) + 6
                  for (let dx = -reachX; dx <= reachX; dx += grid) {
                    for (let dy = -reachY; dy <= reachY; dy += grid) consider(x0 + dx, y0 + dy, false)
                  }
                  // Just beside the words on every side, where a neighbour's area was found to take the press.
                  for (const d of [1, 2, 3, 5]) {
                    for (const across of [0.05, 0.25, 0.5, 0.75, 0.95]) {
                      const x = words.left + (words.right - words.left) * across
                      const y = words.top + (words.bottom - words.top) * across
                      consider(x, words.bottom + d, true)
                      consider(x, words.top - d, true)
                      consider(words.left - d, y, true)
                      consider(words.right + d, y, true)
                    }
                  }
                  consider(x0, y0, true)
                }
                return { points, unclear }
              },
              // Desktop WebKit's overlay scrollbar takes the presses on the pane's last 16 px, and makes no click of them.
              { href, finger: FINGER[surface], grid: GRID, edge: EDGE, scrollbar: test.info().project.name === 'webkit' ? 17 : 0 }
            )
            if (!plan) throw new Error(`the page shows no link ${href}`)
            skipped += plan.unclear
            for (const point of plan.points) {
              planned.push(point)
              await page.mouse.click(point.x, point.y)
            }
          }

          const done = await page.evaluate(() => ({
            marks: (window as unknown as { pressMarks: PressMark[] }).pressMarks,
            opened: window.krTestHost?.openedLinks.slice() ?? [],
            clicked: (window as unknown as { controlClicks: number }).controlClicks,
            left: document.querySelectorAll('.md-link[data-pressed]').length
          }))
          const inside = planned.filter((point) => point.expected !== null).length
          const counts = `${String(planned.length)} presses over ${String(hrefs.length)} links: ${String(inside)} inside a link's area, ${String(planned.length - inside)} outside every area; ${String(skipped)} points within ${String(EDGE)} px of an edge of the rule not pressed`
          test.info().annotations.push({ type: 'presses', description: counts })
          console.log(`link presses on ${surface}, ${String(width)} px, ${size} text size: ${counts}`)
          expect(done.marks.length, 'the presses the page saw, one for each point pressed').toBe(planned.length)
          const wrong: string[] = []
          const unlit: string[] = []
          const drifted: string[] = []
          const unclicked: string[] = []
          planned.forEach((point, index) => {
            const mark = done.marks[index]
            const from = mark?.opened ?? 0
            const to = done.marks[index + 1]?.opened ?? done.opened.length
            const opened = done.opened.slice(from, to)
            const at = `(${String(point.x)}, ${String(point.y)})`
            if (mark !== undefined && Math.abs(mark.scroll - point.scroll) > 0.5) {
              drifted.push(`${at} pressed at scroll ${String(mark.scroll)}, read at ${String(point.scroll)}`)
            }
            const clicks = (done.marks[index + 1]?.clicked ?? done.clicked) - (mark?.clicked ?? 0)
            if (clicks !== (point.control ? 1 : 0)) {
              unclicked.push(`${at} clicked ${String(clicks)} other controls, expected ${point.control ? '1' : '0'}`)
            }
            const expected = point.expected === null ? [] : [point.expected]
            if (opened.join(' ') !== expected.join(' ')) {
              wrong.push(`${at} opened ${opened.join(' ') || 'nothing'}, expected ${expected.join(' ') || 'nothing'}`)
            }
            if ((mark?.pressed ?? []).join(' ') !== expected.join(' ')) {
              unlit.push(`${at} looked pressed on ${(mark?.pressed ?? []).join(' ') || 'nothing'}, expected ${expected.join(' ') || 'nothing'}`)
            }
          })
          expect.soft(drifted.slice(0, 12), 'presses made after the pane had moved from where the point was read').toEqual([])
          expect.soft(unclicked.slice(0, 12), `${String(unclicked.length)} of ${String(planned.length)} presses gave the click to another control or to none`).toEqual([])
          expect.soft(wrong.slice(0, 12), `${String(wrong.length)} of ${String(planned.length)} presses opened another link or none, or one that was not named`).toEqual([])
          expect.soft(unlit.slice(0, 12), `${String(unlit.length)} of ${String(planned.length)} presses showed the pressed look on another link or none`).toEqual([])
          expect.soft(done.left, 'links still looking pressed after the last press').toBe(0)
          expect.soft(
            planned.filter((point) => point.expected !== null).length,
            'presses inside a link’s area'
          ).toBeGreaterThan(planned.length / 6)
          // At the largest size the long link wraps clear of the image's control: there is no overlap to press.
          if (ratio <= 1) {
            expect.soft(planned.filter((point) => point.control).length, 'presses on a control of the message').toBeGreaterThan(10)
          }
          expect.soft(planned.filter((point) => point.expected === null).length, 'presses outside every link’s area').toBeGreaterThan(40)
        })
      }
    }
  }
})
