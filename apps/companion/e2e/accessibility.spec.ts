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
  readonly width: number
  readonly height: number
  /** The points inside the link's own words that another link took the press at. */
  readonly stolen: readonly string[]
  /** The points just inside the link's box, over the plain text around it, that did not reach it. */
  readonly lost: readonly string[]
}

interface LinksReading {
  /** What moved when the links' reach was taken away: the same page without it is the control. */
  readonly moved: readonly string[]
  readonly links: readonly LinkReading[]
  /** How far the box of the link on the conversation's last line lies below the pane at its end. */
  readonly cut: number
  /** The ancestors of a link that scroll or clip its content sideways, and have more of it than they show. */
  readonly overflowing: readonly string[]
}

// KR-REQ-13.19: a link inside a message is a button that is one line tall, and the box that a finger,
// TalkBack and VoiceOver find for it is the size the platform asks for all the same. The box is read
// from the page, which is what the platforms' trees are built from. Taking the reach away shows
// nothing moves, whatever the link's words (one character, a whole line, wrapped) and wherever it
// stands. Links on the next line and beside it show that a press on a link's words is that link's;
// plain lines above and below a link and plain words after it show that a press anywhere in the box is
// the link's too; a link on the last line shows the pane holds its box at the end; and a link as wide
// as the line shows the screen does not scroll sideways for the reach.
test.describe('a link inside a message', () => {
  for (const surface of ['ios', 'android'] as const) {
    test(`is a full touch target on ${surface} and leaves the text where it was`, async ({ page }) => {
      await openSession(page, surface)
      await page.getByRole('button', { name: 'the reconnect notes' }).scrollIntoViewIfNeeded()
      const reading = await page.evaluate((): LinksReading | null => {
        const originals = Array.from(document.querySelectorAll<HTMLElement>('.m-node .md-link'))
        const first = originals[0]
        const paragraph = first?.parentElement
        const pane = document.querySelector<HTMLElement>('.m-pane')
        const nodes = Array.from(document.querySelectorAll<HTMLElement>('.m-node'))
        const lastNode = nodes[nodes.length - 1]
        if (!first || !paragraph || !pane || !lastNode) return null

        const wordsOf = (link: HTMLElement): Range => {
          const range = document.createRange()
          range.selectNodeContents(link.querySelector('.md-link-label') ?? link)
          return range
        }
        const boxOf = (box: DOMRect): Box => ({ left: box.left, top: box.top, width: box.width, height: box.height })

        // More links of the kinds a message can carry, each a copy of the first with other words: on
        // the next line, beside another with one space between, a single character, one in plain
        // lines, one as long as the line, and one that ends the conversation.
        const another = (text: string): HTMLElement => {
          const link = first.cloneNode(true) as HTMLElement
          const label = link.querySelector('.md-link-label') ?? link
          label.textContent = text
          return link
        }
        const second = another('a second link')
        const third = another('1')
        // The class the renderer gives a label of a few characters (test/markdown.test.tsx holds that rule).
        third.classList.add('md-link-short')
        const framedLink = another('a link in plain text')
        const wide = another('a link whose words run the whole width of the line and on to the next ')
        const closing = another('the last link')
        paragraph.append(document.createElement('br'), second, ' ', third)
        const framed = document.createElement('p')
        framed.append(
          'A plain line above the link.',
          document.createElement('br'),
          framedLink,
          ' and plain words after it on the same line.',
          document.createElement('br'),
          'A plain line under the link.'
        )
        const longer = document.createElement('p')
        longer.append(wide)
        paragraph.after(framed, longer)
        const ending = document.createElement('p')
        ending.append('The last line of the conversation ends in ', closing)
        lastNode.append(ending)
        const links = [...originals, second, third, framedLink, wide, closing]

        // The control: the same page with the links' reach taken away.
        const places = (): Record<string, Box> => {
          pane.scrollTop = 0
          const boxes: Record<string, Box> = {
            'the first lines': boxOf(paragraph.getBoundingClientRect()),
            'the plain lines': boxOf(framed.getBoundingClientRect()),
            'the long line': boxOf(longer.getBoundingClientRect()),
            'the last message': boxOf(lastNode.getBoundingClientRect())
          }
          links.forEach((link, index) => {
            boxes[`the words of "${link.textContent ?? ''}" (${String(index + 1)})`] = boxOf(wordsOf(link).getBoundingClientRect())
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
        const moved = Object.keys(before).filter((name) =>
          (['left', 'top', 'width', 'height'] as const).some(
            (side) => Math.abs((before[name]?.[side] ?? 0) - (without[name]?.[side] ?? 0)) > 0.5
          )
        )

        const inPlainText = new Set([framedLink])
        const readings = links.map((link): LinkReading => {
          link.scrollIntoView({ block: 'center' })
          const box = link.getBoundingClientRect()
          const words = wordsOf(link).getClientRects()
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
          return { label: link.textContent ?? '', width: box.width, height: box.height, stolen, lost }
        })

        pane.scrollTop = pane.scrollHeight
        const cut = closing.getBoundingClientRect().bottom - pane.getBoundingClientRect().bottom

        const overflowing: string[] = []
        for (let each: HTMLElement | null = wide; each; each = each.parentElement) {
          const holds = each === document.documentElement || getComputedStyle(each).overflowX !== 'visible'
          if (holds && each.scrollWidth > each.clientWidth + 1) overflowing.push(each.className || each.tagName)
        }
        return { moved, links: readings, cut, overflowing }
      })
      if (!reading) throw new Error('the conversation shows no link')
      expect.soft(reading.moved, 'what moved when the reach was taken away').toEqual([])
      for (const link of reading.links) {
        expect.soft(link.width, `the width of "${link.label}"`).toBeGreaterThanOrEqual(FINGER[surface] - 0.5)
        expect.soft(link.height, `the height of "${link.label}"`).toBeGreaterThanOrEqual(FINGER[surface] - 0.5)
        expect.soft(link.stolen, `where a press on the words of "${link.label}" went to another link`).toEqual([])
        expect.soft(link.lost, `where a press inside the box of "${link.label}" did not reach it`).toEqual([])
      }
      expect.soft(reading.cut, 'how far the box of the last line’s link lies below the pane at its end').toBeLessThanOrEqual(0.5)
      expect.soft(reading.overflowing, 'the ancestors that scroll sideways').toEqual([])
    })
  }
})
