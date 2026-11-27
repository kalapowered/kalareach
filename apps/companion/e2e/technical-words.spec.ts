/**
 * A technical word breaks at its separators before it breaks inside a part, in both engines.
 *
 * An application identifier, a path, a command's option and a host name have no space to end a line
 * at, so the engine ended one wherever the line ran out, in the middle of a part: `com.kala` and
 * `reach.co` and `mpanion`, or a pair of hyphens at the end of one line and the option's name on the
 * next. The rule held here: a line ends at a dot (before it where a short part follows, after it where
 * a longer one does), before an at sign and a run of hyphens, and after an underscore, a slash and the
 * other separators; inside a part only when that one part alone is wider than its line; nothing is cut
 * off, clipped by any ancestor or scrolling sideways, a run of hyphens wider than its line included;
 * a quoted word of a command line stays on one line where it fits there; and what a person copies is
 * the source text, character for character.
 *
 * Every reading is of the rendered line boxes (the rectangles of a range over each part), never of a
 * picture. The width is the part's own: each case looks for the width of the real page at which every
 * part fits a line and the whole word does not, rather than naming one.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const SIZES = [
  ['default', 1],
  ['largest', LARGEST]
] as const

/** What the page shows of one word: where its lines fall, what it would take on one line, and the room it has. */
interface Reading {
  readonly word: string
  /** The width the whole word takes on one line. */
  readonly natural: number
  /** The width of its widest part on one line. */
  readonly widest: number
  /** The width of the line it is drawn in. */
  readonly room: number
  /** How many lines the word is drawn on. */
  readonly lines: number
  /** The parts that a line break falls inside. */
  readonly cut: readonly string[]
  /** The parts that are wider than the line they are drawn in. */
  readonly wider: readonly string[]
  /** Whether any of its text lies beyond the line's edges. */
  readonly outside: boolean
  /** How far the element's content runs past its box, and the page past the window. */
  readonly sideways: number
  readonly pageSideways: number
}

/**
 * Reads each of `words` (a word is the list of its parts) in the first element `selector` matches.
 * The parts are looked for in the element's text, in order; a part is cut when the rectangles of the
 * text it is drawn with lie on more than one line.
 */
function read(page: Page, selector: string, words: readonly (readonly string[])[]): Promise<Reading[]> {
  return page.evaluate(
    ({ selector: where, words: asked }) => {
      const root = document.querySelector(where)
      if (root === null) throw new Error(`nothing matches ${where}`)
      const style = getComputedStyle(root)
      const box = root.getBoundingClientRect()
      const left = box.left + parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth)
      const right = box.right - parseFloat(style.paddingRight) - parseFloat(style.borderRightWidth)
      const nodes: { node: Text; start: number }[] = []
      const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      let total = 0
      for (let current = walk.nextNode(); current !== null; current = walk.nextNode()) {
        const node = current as Text
        nodes.push({ node, start: total })
        total += node.length
      }
      const text = nodes.map((entry) => entry.node.data).join('')
      /** The rectangles of the text from `from` to `to`, node by node, so that no element's box is among them. */
      const rectsOf = (from: number, to: number): DOMRect[] => {
        const found: DOMRect[] = []
        for (const { node, start } of nodes) {
          const lo = Math.max(from, start)
          const hi = Math.min(to, start + node.length)
          if (lo >= hi) continue
          const range = document.createRange()
          range.setStart(node, lo - start)
          range.setEnd(node, hi - start)
          for (const rect of Array.from(range.getClientRects())) if (rect.width > 0) found.push(rect)
        }
        return found
      }
      const linesOf = (rects: DOMRect[]): number => {
        const tops: number[] = []
        for (const rect of [...rects].sort((a, b) => a.top - b.top)) {
          const last = tops[tops.length - 1]
          if (last === undefined || rect.top - last > rect.height / 2) tops.push(rect.top)
        }
        return tops.length
      }
      const natural = (words: string): number => {
        const probe = document.createElement('span')
        probe.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;left:0;top:0'
        probe.textContent = words
        root.appendChild(probe)
        const width = probe.getBoundingClientRect().width
        probe.remove()
        return width
      }
      const readings: Reading[] = []
      let cursor = 0
      for (const parts of asked) {
        const word = parts.join('')
        const at = text.indexOf(word, cursor)
        if (at < 0) throw new Error(`${JSON.stringify(word)} is not in the text of ${where}`)
        cursor = at + word.length
        const cut: string[] = []
        const wider: string[] = []
        let widest = 0
        let offset = at
        for (const part of parts) {
          if (linesOf(rectsOf(offset, offset + part.length)) > 1) cut.push(part)
          const width = natural(part)
          if (width > right - left) wider.push(part)
          widest = Math.max(widest, width)
          offset += part.length
        }
        const rects = rectsOf(at, at + word.length)
        readings.push({
          word,
          natural: natural(word),
          widest,
          room: right - left,
          lines: linesOf(rects),
          cut,
          wider,
          outside: rects.some((rect) => rect.left < left - 1 || rect.right > right + 1),
          sideways: Math.max(0, (root as HTMLElement).scrollWidth - (root as HTMLElement).clientWidth),
          pageSideways: Math.max(0, document.documentElement.scrollWidth - window.innerWidth)
        })
      }
      return readings
    },
    { selector, words }
  )
}

/** Lets the layout after a change of window or of text size settle: two frames. */
async function settle(page: Page): Promise<void> {
  await page.evaluate(
    () =>
      new Promise<void>((done) => {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            done()
          })
        })
      })
  )
}

async function setScale(page: Page, ratio: number): Promise<void> {
  await page.evaluate((value) => {
    document.documentElement.style.setProperty('--text-scale', String(value))
  }, ratio)
  await settle(page)
}

/**
 * Which characters of the text in the first element `selector` matches a person cannot see: each
 * character's box is set against the window and against EVERY ancestor that clips what it holds, up
 * to the root, not against the word's own element alone. Sideways, any overflow but visible clips: text
 * is never reached by scrolling along a line. Down the page only hidden and clip do, and not above an
 * ancestor that scrolls, which brings the rest into view. A character is named by itself and by the
 * ancestor that hides it.
 */
function hiddenText(page: Page, selector: string): Promise<{ checked: number; hidden: string[] }> {
  return page.evaluate((where) => {
    const root = document.querySelector(where)
    if (root === null) throw new Error(`nothing matches ${where}`)
    const hidden: string[] = []
    let checked = 0
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
    for (let current = walk.nextNode(); current !== null; current = walk.nextNode()) {
      const node = current as Text
      const clippers: { name: string; left: number; right: number; top: number; bottom: number; x: boolean; y: boolean }[] = []
      let scrolls = false
      for (let up: Element | null = node.parentElement; up !== null; up = up.parentElement) {
        const style = getComputedStyle(up)
        const x = style.overflowX !== 'visible'
        const clipsDown = style.overflowY === 'hidden' || style.overflowY === 'clip'
        const scrollsDown = style.overflowY === 'auto' || style.overflowY === 'scroll'
        // Below an ancestor that scrolls, what lies beyond a clip further up is brought into view by it.
        const y = clipsDown && !scrolls
        if (scrollsDown) scrolls = true
        if (!x && !y) continue
        const box = up.getBoundingClientRect()
        // What overflow clips to is the padding box, inside the border.
        clippers.push({
          name: `${up.tagName.toLowerCase()}.${String(up.getAttribute('class') ?? '').replace(/\s+/g, '.')}`,
          left: box.left + parseFloat(style.borderLeftWidth),
          right: box.right - parseFloat(style.borderRightWidth),
          top: box.top + parseFloat(style.borderTopWidth),
          bottom: box.bottom - parseFloat(style.borderBottomWidth),
          x,
          y
        })
      }
      for (let at = 0; at < node.length; at += 1) {
        if (/\s/u.test(node.data.charAt(at))) continue
        const range = document.createRange()
        range.setStart(node, at)
        range.setEnd(node, at + 1)
        const rect = Array.from(range.getClientRects()).find((one) => one.width > 0)
        if (rect === undefined) continue
        checked += 1
        const slack = 1
        if (rect.left < -slack || rect.right > window.innerWidth + slack) {
          hidden.push(`${node.data.charAt(at)} at ${Math.round(rect.left)} beyond the window`)
          continue
        }
        for (const clip of clippers) {
          const outside =
            (clip.x && (rect.left < clip.left - slack || rect.right > clip.right + slack)) ||
            (clip.y && (rect.top < clip.top - slack || rect.bottom > clip.bottom + slack))
          if (outside) {
            hidden.push(`${node.data.charAt(at)} at ${Math.round(rect.left)} clipped by ${clip.name}`)
            break
          }
        }
      }
    }
    return { checked, hidden: hidden.slice(0, 8) }
  }, selector)
}

/**
 * The first window width, from the phone's narrowest, 320, up, at which the widest part of `parts`
 * fits the line it is drawn in and the whole word does not: the width at which a break must fall
 * between parts.
 */
async function squeeze(page: Page, selector: string, parts: readonly string[], height: number): Promise<number> {
  for (let width = 320; width <= 1400; width += 8) {
    await page.setViewportSize({ width, height })
    await settle(page)
    const [reading] = await read(page, selector, [parts])
    if (reading !== undefined && reading.widest + 1 <= reading.room && reading.room + 1 < reading.natural) return width
  }
  throw new Error(`no window width puts ${parts.join('')} wider than its line and every part inside it`)
}

interface Kind {
  readonly name: string
  /** Opens the page showing `word` at `selector`. */
  open(page: Page, word: string): Promise<void>
  readonly selector: string
  /** The text of the element at `selector` when the word is drawn in it. */
  shown(word: string): string
  /** A word of this kind whose parts each fit a line, and the parts a line may end between. */
  readonly parts: readonly string[]
  /** A word of this kind with one part wider than any line the page has. */
  readonly wide: readonly string[]
  /** A word of this kind with a run of hyphens, between two letters, wider than any line the page has. */
  readonly run: string
  /** A word of this kind short enough to fit on one line at the largest text size in a wide window. */
  readonly short: readonly string[]
}

const HARNESS = '/harness.html'

/** The phone's Account screen with a sync service of the given host written in the change form and saved. */
async function openSyncService(page: Page, host: string): Promise<void> {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${HARNESS}?surface=ios&tab=account`)
  await page.waitForSelector('.m-shell')
  await page.getByTestId('change-sync-service').click()
  await page.getByTestId('sync-service-input').fill(`https://${host}`)
  await page.getByTestId('save-sync-service').click()
  await page.getByTestId('sync-service-changed').waitFor()
}

async function openSetup(page: Page, names: { application_id?: string; executable?: string }): Promise<void> {
  await page.goto(HARNESS)
  await page.waitForSelector('.app-shell')
  await page.evaluate((given) => {
    ;(window as unknown as { krTestHost: { setIdentityNames(names: object): void } }).krTestHost.setIdentityNames(given)
  }, names)
  await page.getByRole('button', { name: 'Set up this Mac' }).click()
  await page.getByTestId('setup-identity').waitFor()
}

/** A saved command whose program and arguments are `words`, listed under Settings, Launch commands. */
async function openLaunchCommands(page: Page, label: string, words: readonly string[]): Promise<void> {
  // A stock shell session is the window that has Settings in it, as the launch commands' own case opens it.
  await page.goto(`${HARNESS}?stock_shell=bash`)
  await page.waitForSelector('.app-shell')
  const [program, ...rest] = words
  await page.evaluate(
    (command) => {
      ;(
        window as unknown as { krTestHost: { launchCommands: { changeElsewhere(commands: readonly unknown[]): void } } }
      ).krTestHost.launchCommands.changeElsewhere([command])
    },
    { label, program, arguments: rest }
  )
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByRole('button', { name: 'New session' }).click()
  const creating = page.getByTestId('sheet')
  await expect(creating).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
  await creating.getByRole('radio', { name: /Stock shell/ }).check()
  await creating.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
  await creating.getByRole('button', { name: 'Create session' }).click()
  await expect(page.getByTestId('launch-instructions')).toBeVisible()
  await expect(creating).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await page.getByRole('button', { name: 'Settings' }).click()
  await expect(page.getByTestId('sheet').last()).toHaveAttribute('data-presentation', 'here', {
    timeout: PRESENTATION_DEADLINE
  })
  await page.getByRole('button', { name: 'Launch commands' }).click()
  await page.getByTestId('launch-commands-list').waitFor()
}

const LONG_PART = 'extraordinarilylongsegmentofaword'

/** A hundred and sixty hyphens: a valid file name, and wider than the phone's line at any text size. */
const HYPHENS = '-'.repeat(160)

// Each is wider than any line the page has at the phone's narrowest, so that a break must fall
// between parts, and each of its parts fits a line at the default text size and at the largest.
const IDENTIFIER = ['com.', 'kalareach.', 'companion.', 'preview.', 'nightly']
const PATH = ['/Users/', 'sam/', 'work/', 'kalareach/', 'target/', 'debug/', 'kalareach', '-companion']
const OPTION = ['"--no', '-color', '-diagnostics', '-and', '-terminal', '-escapes=', 'always"']
const HOST = ['settings.', 'synchronisation.', 'example', '-company', '.com']

const KINDS: readonly Kind[] = [
  {
    name: 'an application identifier',
    open: (page, word) => openSetup(page, { application_id: word }),
    selector: '[data-testid="setup-identity"] h2',
    shown: (word) => word,
    parts: IDENTIFIER,
    wide: ['com.', 'kalareach.', `${LONG_PART}${LONG_PART}`],
    run: `a${HYPHENS}b`,
    short: ['to', '.kala.', 'reach']
  },
  {
    name: 'a path',
    open: (page, word) => openSetup(page, { executable: word }),
    selector: '[data-testid="setup-identity"] dd.mono',
    shown: (word) => word,
    parts: PATH,
    wide: ['/Users/', 'sam/', `${LONG_PART}${LONG_PART}/`, 'bin'],
    run: `/Users/a${HYPHENS}b`,
    short: ['/usr/', 'local/', 'bin/', 'zsh']
  },
  {
    name: "a command's option",
    // The row quotes each word, so the quotes of the word as drawn are not part of the argument.
    open: (page, word) => openLaunchCommands(page, 'Start', ['node', word.slice(1, -1)]),
    selector: '[data-testid="launch-commands-list"] p.mono',
    shown: (word) => `"node" ${word}`,
    parts: OPTION,
    wide: [`"--${LONG_PART}${LONG_PART}"`],
    run: `"a${HYPHENS}b"`,
    short: ['"--inspect"']
  },
  {
    name: 'a host name',
    open: (page, word) => openSyncService(page, word),
    selector: '[data-testid="sync-service-changed"]',
    shown: (word) => word,
    parts: HOST,
    wide: ['sync.', `${LONG_PART}${LONG_PART}`, '.com'],
    run: `a${HYPHENS}b.com`,
    short: ['reach', '.kala', '.to']
  }
]

for (const kind of KINDS) {
  for (const [size, ratio] of SIZES) {
    test.describe(`${kind.name}, ${size} text`, () => {
      test('breaks at a separator and never inside a part where every part fits a line', async ({ page }) => {
        await kind.open(page, kind.parts.join(''))
        await setScale(page, ratio)
        const height = page.viewportSize()?.height ?? 720
        const width = await squeeze(page, kind.selector, kind.parts, height)
        const [reading] = await read(page, kind.selector, [kind.parts])
        expect(reading?.lines, `at ${width} wide the word is drawn on lines`).toBeGreaterThan(1)
        expect(reading?.cut, `parts a line ends inside, at ${width} wide`).toEqual([])
        expect(reading?.outside, 'text beyond the line').toBe(false)
        expect(reading?.sideways, 'content running past its box').toBe(0)
        expect(reading?.pageSideways, 'the page scrolling sideways').toBe(0)
      })

      test('still breaks a part that alone is wider than its line, and cuts nothing off', async ({ page }) => {
        await kind.open(page, kind.wide.join(''))
        await setScale(page, ratio)
        await page.setViewportSize({ width: 320, height: page.viewportSize()?.height ?? 720 })
        await settle(page)
        const [reading] = await read(page, kind.selector, [kind.wide])
        expect(reading?.widest, 'one part is wider than the line').toBeGreaterThan(reading?.room ?? 0)
        const wider = reading?.wider ?? []
        expect(
          reading?.cut.filter((part) => !wider.includes(part)),
          'a part that fits its line is not broken'
        ).toEqual([])
        expect(
          wider.filter((part) => reading?.cut.includes(part) !== true),
          'a part wider than its line is broken inside'
        ).toEqual([])
        expect(reading?.outside, 'text beyond the line').toBe(false)
        expect(reading?.sideways, 'content running past its box').toBe(0)
        expect(reading?.pageSideways, 'the page scrolling sideways').toBe(0)
      })

      test('breaks a run of hyphens wider than its line as the last step, and hides none of it', async ({ page }) => {
        await kind.open(page, kind.run)
        await setScale(page, ratio)
        await page.setViewportSize({ width: 320, height: page.viewportSize()?.height ?? 720 })
        await settle(page)
        const seen = await hiddenText(page, kind.selector)
        expect(seen.checked, 'characters read').toBeGreaterThanOrEqual(kind.shown(kind.run).replace(/\s/gu, '').length)
        expect(seen.hidden, 'characters that a clipping ancestor or the window edge hides').toEqual([])
        const [reading] = await read(page, kind.selector, [[kind.run]])
        expect(reading?.outside, 'text beyond the line').toBe(false)
        expect(reading?.sideways, 'content running past its box').toBe(0)
        expect(reading?.pageSideways, 'the page scrolling sideways').toBe(0)
      })
    })
  }
}

for (const kind of KINDS) {
  test.describe(`${kind.name}, copied and measured`, () => {
    test('is copied as it is written, whole and from the middle of one part to the middle of another', async ({
      page
    }) => {
      const word = kind.parts.join('')
      await kind.open(page, word)
      const seen = await page.evaluate((where) => {
        const root = document.querySelector(where)
        if (root === null) throw new Error(`nothing matches ${where}`)
        const selection = window.getSelection()
        if (selection === null) throw new Error('the page has no selection')
        const whole = document.createRange()
        whole.selectNodeContents(root)
        selection.removeAllRanges()
        selection.addRange(whole)
        const copiedWhole = selection.toString()
        // From the second character of the first text to the one before the last of the last text.
        const texts: Text[] = []
        const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
        for (let current = walk.nextNode(); current !== null; current = walk.nextNode()) texts.push(current as Text)
        const first = texts[0]
        const last = texts[texts.length - 1]
        if (first === undefined || last === undefined) throw new Error('the word has no text')
        const inside = document.createRange()
        inside.setStart(first, 1)
        inside.setEnd(last, last.length - 1)
        selection.removeAllRanges()
        selection.addRange(inside)
        return {
          copiedWhole,
          copiedInside: selection.toString(),
          breakPlaces: root.querySelectorAll('wbr').length
        }
      }, kind.selector)
      const shown = kind.shown(word)
      expect(seen.breakPlaces, 'the word is drawn with places to end a line').toBeGreaterThan(0)
      expect(seen.copiedWhole.trim()).toBe(shown)
      expect(seen.copiedInside).toBe(shown.slice(1, -1))
    })

    for (const [size, ratio] of SIZES) {
      test(`adds nothing to the height of its line or to the baseline of the words round it, ${size} text`, async ({
        page
      }) => {
        await kind.open(page, kind.short.join(''))
        await setScale(page, ratio)
        await page.setViewportSize({ width: 1280, height: page.viewportSize()?.height ?? 720 })
        await settle(page)
        const [alone] = await read(page, kind.selector, [kind.short])
        expect(alone?.lines, 'the word fits on one line').toBe(1)
        const seen = await page.evaluate((where) => {
          const root = document.querySelector<HTMLElement>(where)
          if (root === null) throw new Error(`nothing matches ${where}`)
          const words = Array.from(root.querySelectorAll('.technical-word'))
          // The same element with each technical word as plain text: the line it is drawn on without the component.
          const plain = root.cloneNode(true) as HTMLElement
          for (const word of Array.from(plain.querySelectorAll('.technical-word')))
            word.replaceWith(document.createTextNode(word.textContent ?? ''))
          root.after(plain)
          /** The top and the bottom of each character, against the top of its element, and the element's height. */
          const measure = (element: HTMLElement): number[] => {
            const top = element.getBoundingClientRect().top
            const found: number[] = [element.getBoundingClientRect().height]
            const walk = document.createTreeWalker(element, NodeFilter.SHOW_TEXT)
            for (let current = walk.nextNode(); current !== null; current = walk.nextNode()) {
              const node = current as Text
              for (let at = 0; at < node.length; at += 1) {
                const range = document.createRange()
                range.setStart(node, at)
                range.setEnd(node, at + 1)
                const rect = Array.from(range.getClientRects()).find((one) => one.width > 0)
                if (rect !== undefined) found.push(rect.top - top, rect.bottom - top)
              }
            }
            return found
          }
          const drawn = measure(root)
          const control = measure(plain)
          plain.remove()
          return {
            words: words.length,
            sameShape: drawn.length === control.length,
            worst: drawn.reduce((worst, value, at) => Math.max(worst, Math.abs(value - (control[at] ?? Infinity))), 0)
          }
        }, kind.selector)
        expect(seen.words, 'the word is drawn by the component').toBeGreaterThan(0)
        expect(seen.sameShape, 'the same characters are drawn').toBe(true)
        expect(seen.worst, 'the largest difference in a line or a baseline, in pixels').toBeLessThan(0.5)
      })
    }
  })
}

test('the setup card title of an application identifier, at the largest text size, ends a line only at a dot', async ({
  page
}) => {
  const parts = ['com.', 'kalareach.', 'companion']
  await openSetup(page, { application_id: parts.join('') })
  await setScale(page, LARGEST)
  // The first width, from the phone's narrowest up, where each part fits a line and the whole does not: it
  // is 320 where the face is narrow enough, and a little wider in a face with wider letters.
  const width = await squeeze(page, '[data-testid="setup-identity"] h2', parts, page.viewportSize()?.height ?? 720)
  const [reading] = await read(page, '[data-testid="setup-identity"] h2', [parts])
  expect(reading?.cut, `parts a line ends inside, at ${width} wide`).toEqual([])
  expect(reading?.lines, 'the identifier is drawn on lines').toBeGreaterThan(1)
})

test('is named to a screen reader by the source text of an identifier with hyphens, dots and an underscore in it', async ({
  browserName,
  context,
  page
}) => {
  test.skip(browserName !== 'chromium', "only Chromium lets the test driver read the engine's accessibility tree")
  const identifier = 'com.kala-reach.my-app_x=y'
  await openSetup(page, { application_id: identifier })
  const session = await context.newCDPSession(page)
  await session.send('Accessibility.enable')
  const { nodes } = await session.send('Accessibility.getFullAXTree')
  const heading = nodes.find((node) => node.role?.value === 'heading' && /kala-?reach/.test(String(node.name?.value)))
  expect(heading?.name?.value, 'the name of the heading that holds the identifier').toBe(identifier)
})

/** A saved command, quoted word by word: options with hyphens among words and numbers. */
const COMMAND = [
  'node',
  '--inspect',
  'server.js',
  '--port',
  '8080',
  '--log',
  'debug',
  '--config',
  'prod.json',
  '--env',
  'production',
  '--timeout',
  '30000',
  '--retries',
  '3',
  '--cache',
  'build',
  '--output',
  'build',
  '--verbose'
]

test.describe('a command line quoted word by word', () => {
  for (const [size, ratio] of SIZES) {
    test(`keeps each quoted word on one line where it fits there, ${size} text`, async ({ page }) => {
      // Twenty-eight window widths, each measured word by word: more than the default allowance on a busy machine.
      test.slow()
      await openLaunchCommands(page, 'Start the debug server', COMMAND)
      await setScale(page, ratio)
      const height = page.viewportSize()?.height ?? 720
      const quoted = COMMAND.map((word) => [`"${word}"`])
      const split: string[] = []
      for (let width = 320; width <= 1400; width += 40) {
        await page.setViewportSize({ width, height })
        await settle(page)
        for (const reading of await read(page, '[data-testid="launch-commands-list"] p.mono', quoted)) {
          if (reading.natural <= reading.room && reading.cut.length > 0) split.push(`${width} wide: ${reading.word}`)
          expect(reading.outside, `${reading.word} beyond the line at ${width} wide`).toBe(false)
          expect(reading.pageSideways, `the page scrolling sideways at ${width} wide`).toBe(0)
        }
      }
      expect(
        { count: split.length, first: split.slice(0, 6) },
        'quoted words a line ends inside although each fits a line'
      ).toEqual({ count: 0, first: [] })
    })
  }
})
