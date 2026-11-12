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
async function openSession(page: Page, surface: 'ios' | 'android'): Promise<void> {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
  await expect(page.getByRole('group', { name: 'Add an attachment' })).toBeVisible()
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
  /** The points inside the link's own words that another link took the press at. */
  readonly stolen: readonly string[]
  /** The points just inside the link's box, over the plain text around it, that did not reach it. */
  readonly lost: readonly string[]
  /** The points just above and below the link's words, in its own line, that went to another link or to none. */
  readonly nearby: readonly string[]
  /** The points in the reach beside the link's words, low in its line, that went to another link or to none. */
  readonly beside: readonly string[]
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
// Links on the next line, one directly under the other, and beside it show that a press on a link's
// words, just above and below them, and in the reach beside them, is that link's. Plain lines above and
// below a link, and plain words after it, show that a press anywhere in the box is the link's too. A
// link at the start of a line, at its end and alone on a line shows the box is whole at the pane's
// edges and the conversation does not scroll sideways for it, and a link on the last line shows the
// pane holds its box at the end.
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

        const inPlainText = new Set([framedLink])
        const paneBox = pane.getBoundingClientRect()
        const room = Math.min(finger / 2, gutter)
        const readings = links.map((link, index): LinkReading => {
          link.scrollIntoView({ block: 'center' })
          const box = link.getBoundingClientRect()
          const words = wordsOf(link).getClientRects()
          const name = `"${link.textContent ?? ''}" (${String(index + 1)})`
          const wordsWidth = without[`the words of ${name}`]?.width ?? 0
          const stolen: string[] = []
          for (const rect of [words[0], words[words.length - 1]]) {
            if (!rect) continue
            const points: [string, number, number][] = [
              ['the top', rect.left + rect.width / 2, rect.top + 2],
              ['the bottom', rect.left + rect.width / 2, rect.bottom - 2],
              ['the start', rect.left + 1, rect.top + rect.height / 2],
              ['the end', rect.right - 1, rect.top + rect.height / 2]
            ]
            for (const [where, x, y] of points) {
              if (document.elementFromPoint(x, y)?.closest('.md-link') !== link) stolen.push(where)
            }
          }
          const lost: string[] = []
          if (inPlainText.has(link)) {
            const middle = box.top + box.height / 2
            const points: [string, number, number][] = [
              ['the top', box.left + box.width / 2, box.top + 3],
              ['the bottom', box.left + box.width / 2, box.bottom - 3],
              ['the start', box.left + 3, middle],
              ['the end', box.right - 3, middle]
            ]
            for (const [where, x, y] of points) {
              const found = document.elementFromPoint(x, y)
              if (found?.closest('.md-link') !== link) lost.push(`${where}: ${found ? `${found.tagName} ${found.className}` : 'nothing'}`)
            }
          }
          // Just above and just below the words, inside the link's own line: whoever has a box there, the
          // press is this link's, since its words are the nearer.
          const nearby: string[] = []
          const wordsAt = wordsOf(link).getClientRects()
          const top = wordsAt[0]
          const bottom = wordsAt[wordsAt.length - 1]
          const around: [string, DOMRect | undefined, number][] = [
            ['above the words', top, (top?.top ?? 0) - 1.5],
            ['below the words', bottom, (bottom?.bottom ?? 0) + 1.5]
          ]
          for (const [where, rect, y] of around) {
            if (!rect) continue
            const found = document.elementFromPoint(rect.left + rect.width / 2, y)
            if (found?.closest('.md-link') !== link) nearby.push(`${where}: ${found ? `${found.tagName} ${found.className}` : 'nothing'}`)
          }
          // In the reach beside the words, low in the line, where a link on the next line has its box: the
          // press is this link's. Where another link follows on the same line, the later link's area is
          // the one above between their words, so that side is left out.
          const beside: string[] = []
          const lowest = wordsAt[wordsAt.length - 1]
          const first = wordsAt[0]
          if (lowest && first) {
            const y = lowest.bottom + 1.5
            const sides: [string, number][] = [
              ['at the start of the box', box.left + 4],
              ['by the start of the words', first.left - 3],
              ['by the end of the words', lowest.right + 3],
              ['at the end of the box', box.right - 4]
            ]
            for (const [where, x] of sides) {
              if (link === second && where.includes('end')) continue
              if (link === third && where.includes('start')) continue
              const found = document.elementFromPoint(x, y)
              if (found?.closest('.md-link') !== link) beside.push(`${where}: ${found ? `${found.tagName} ${found.className}` : 'nothing'}`)
            }
          }
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
            stolen,
            lost,
            nearby,
            beside
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
        expect.soft(link.stolen, `where a press on the words of "${link.label}" went to another link`).toEqual([])
        expect.soft(link.lost, `where a press inside the box of "${link.label}" did not reach it`).toEqual([])
        expect.soft(link.nearby, `where a press by the words of "${link.label}" went elsewhere`).toEqual([])
        expect.soft(link.beside, `where a press in the reach beside "${link.label}" went elsewhere`).toEqual([])
        // The label is centred in the box, so a widened box moves it by half of the difference.
        expect.soft(link.wordsMoved, `how far "${link.label}" moved sideways`).toBeLessThanOrEqual(link.mostMoved / 2 + 1)
        expect.soft(link.beforeMoved, `how far the words before "${link.label}" moved sideways`).toBeLessThanOrEqual(link.mostMoved + 1)
      }
      expect.soft(reading.cut, 'how far the box of the last line’s link lies below the pane at its end').toBeLessThanOrEqual(0.5)
      expect.soft(reading.overflowing, 'what scrolls or clips sideways from the pane up').toEqual([])
    })
  }
})
