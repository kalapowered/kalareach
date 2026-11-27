/**
 * The connection line, while a slow try to reach the host is still running.
 *
 * The line says the application is still trying to reach the host, in a sentence of about sixty
 * characters. On the phone the line is cut to two lines for a host's own words, which can run on;
 * this sentence is the application's own and has no title to fall back on, so it shows whole at
 * every text size, and the bar grows with it. On the desktop it wraps inside the bar. Neither line
 * moves when the sentence appears: it is a text swap, with no transition and no animation, with or
 * without reduced motion.
 *
 * iOS carries the person's text size to the page as `--text-scale`, which this file sets directly,
 * as the text-size tests do. Android's web view scales the text and leaves a length in em where it
 * was, which a root font size of 200 percent does not: the Android case here sets the root's font
 * size to 200 percent instead, so it sets the bar's text smaller than a device does at that
 * setting, and makes no claim about what the device draws. That the real web views give the page
 * the size is held on a simulator and an emulator.
 *
 * In the font of the machine these cases were measured on, the sentence needs two lines at the two
 * largest sizes, so a cut at two lines and the whole wrap look alike there; nothing is claimed for
 * another platform's font. The case that tells them apart widens the face until the sentence needs
 * three lines, and holds the whole of it, inside the bar, with the content below the bar.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

const SAID = 'the relay closed this connection'
const PAIRED = 'this application is still trying to reach the host you chose'
const LOCAL = 'this application is still trying to reach the host on this machine'

/** A host's own words for a refusal, as long as the longest the line has shown. */
const RUNS_ON =
  'this device is not signed in to the organisation that owns this host, so the host refused the connection: ask an owner of the organisation to add this device to its list of devices'

/** The letter spacing, in em, of a face wide enough that the sentence needs three lines at 320 px. */
const WIDE_FACE = 0.4

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/**
 * The text sizes the browser stands in with. The iOS size is `--text-scale`, which the page itself
 * sets from the system's size on iOS; the Android size is a root font size of 200 percent, which
 * only stands in for the Android web view and is not what it does (see the header).
 */
const SIZES = [
  { name: 'default', scale: 1, root: null, surface: 'ios' },
  { name: 'ios-largest', scale: LARGEST, root: null, surface: 'ios' },
  { name: 'android-2.0', scale: 1, root: 200, surface: 'android' }
] as const

/** Sets the browser's stand-ins for a text size, before the page's first frame. */
async function withTextSize(page: Page, scale: number, root: number | null): Promise<void> {
  await page.addInitScript(
    ({ ratio, percent }) => {
      const apply = (): boolean => {
        const element = document.documentElement as HTMLElement | null
        if (element === null) return false
        element.style.setProperty('--text-scale', String(ratio))
        if (percent !== null) element.style.fontSize = `${percent}%`
        return true
      }
      if (!apply()) {
        new MutationObserver((_, observer) => {
          if (apply()) observer.disconnect()
        }).observe(document, { childList: true })
      }
    },
    { ratio: scale, percent: root }
  )
}

/** Loses the connection with a reason, and then marks a slow try for `host`. */
async function slowTry(page: Page, host: 'paired' | 'local'): Promise<void> {
  await page.evaluate(
    ({ reason, to }) => {
      window.krTestHost?.setConnected(false, reason)
      window.krTestHost?.setStillReaching(to)
    },
    { reason: SAID, to: host }
  )
}

/** Whether the words are cut off, how many lines they take, and how tall the bar is. */
function measure(words: Locator): Promise<{ cut: boolean; lines: number; bar: number }> {
  return words.evaluate((element) => ({
    cut: element.scrollHeight > element.clientHeight + 1,
    lines: Math.round(element.getBoundingClientRect().height / parseFloat(getComputedStyle(element).lineHeight)),
    bar: Math.round((element.closest('.m-topbar') as HTMLElement).getBoundingClientRect().height)
  }))
}

/**
 * What the phone's bar does not hold: the connection line's box and every line of its text, held to
 * the bar's box on all four sides, and the content, held to start below the bar. The bar grows with
 * the sentence, so this reads the heights as well as the sides. Empty when everything lies inside.
 */
function outsideTheBar(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const bar = document.querySelector('.m-topbar')
    const line = document.querySelector('.m-connection')
    const content = document.querySelector('.m-main')
    if (bar === null || line === null || content === null) return ['the bar, its line or the content is not on the page']
    const box = bar.getBoundingClientRect()
    const found: string[] = []
    const held = (what: string, rect: { left: number; right: number; top: number; bottom: number }): void => {
      if (rect.left < box.left - 0.5 || rect.right > box.right + 0.5) found.push(`${what}: past the bar's sides`)
      if (rect.top < box.top - 0.5 || rect.bottom > box.bottom + 0.5) found.push(`${what}: past the bar's top or bottom`)
    }
    held('the line', line.getBoundingClientRect())
    const walk = document.createTreeWalker(line, NodeFilter.SHOW_TEXT)
    for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
      const range = document.createRange()
      range.selectNodeContents(node)
      for (const each of Array.from(range.getClientRects())) {
        if (each.width > 0) held(`text "${(node.textContent ?? '').trim().slice(0, 30)}"`, each)
      }
    }
    if (content.getBoundingClientRect().top < box.bottom - 0.5) found.push("the content starts above the bar's bottom edge")
    return found
  })
}

/** What moves around the connection line: the animations under its bar, and the transition each box on the way has. */
function movement(line: Locator): Promise<{ animations: number; bar: string; line: string; words: string; dot: string }> {
  return line.evaluate((element) => {
    const transition = (of: Element): string => getComputedStyle(of).transitionDuration
    const bar = element.closest('.m-topbar, .topbar') as Element
    // The desktop's line holds its words directly; the phone's holds them in the span after the dot.
    const words = element.classList.contains('connection') ? element : (element.lastElementChild as Element)
    return {
      animations: bar.getAnimations({ subtree: true }).length,
      bar: transition(bar),
      line: transition(element),
      words: transition(words),
      dot: transition(element.querySelector('.status-dot') as Element)
    }
  })
}

/** Nothing moves: no animation runs, and no box has a transition. */
const STILL = { animations: 0, bar: '0s', line: '0s', words: '0s', dot: '0s' }

test.describe("the phone's line, while a slow try is still running", () => {
  for (const [size, width] of SIZES.flatMap((each) => [320, 390].map((wide) => [each, wide] as const))) {
    test(`shows the whole sentence at ${size.name} text, ${width} px wide`, async ({ page }) => {
      await withTextSize(page, size.scale, size.root)
      await page.setViewportSize({ width, height: 844 })
      await page.goto(`/harness.html?surface=${size.surface}`)
      const line = page.locator('.m-connection')
      await expect(line).toHaveText('In contact with this host')

      await slowTry(page, 'paired')
      const words = line.locator('span').last()
      await expect(words).toHaveText(PAIRED)
      // The sentence has no title: the line says it, and a title would say it twice.
      expect(await line.getAttribute('title')).toBeNull()

      const whole = await measure(words)
      expect(whole.cut, 'no part of the sentence is cut off').toBe(false)
      test.info().annotations.push({
        type: 'bar height',
        description: `${size.name}, ${width} px wide: ${whole.bar} px, ${whole.lines} lines`
      })
      const outside = await outsideTheBar(page)
      expect(outside, 'the line and its text lie inside the bar, with the content below it').toEqual([])
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
        'the page does not scroll sideways'
      ).toBeLessThanOrEqual(0)
      // The line is what this holds. The bar's title is the bar's own: at the largest sizes on a narrow
      // screen it can run past its box in a wide font, with this sentence or without it.
      expect(
        await overrunning(page, '.m-connection'),
        'lines of the connection line that run past the screen or its box'
      ).toEqual([])
      await page.screenshot({ path: screenshotPath(`kr-slow-try-phone-${size.name}-${width}-${test.info().project.name}`) })

      // The control: the same measure, on a host's own words that run on, sees the two-line cut
      // that holds for every state but this one.
      await page.evaluate((reason) => {
        window.krTestHost?.setStillReaching(null)
        window.krTestHost?.setConnected(false, reason)
      }, RUNS_ON)
      await expect(words).toHaveText(RUNS_ON)
      expect((await measure(words)).cut, 'the measure sees words that are cut to two lines').toBe(true)
      expect(await line.getAttribute('title')).toBe(RUNS_ON)
    })
  }

  // The sentence needs three lines here, which the cut at two lines would take from it. A face this
  // wide is set on the words, as the tab bar's cases do; the cases above hold the same at the
  // two-line size that the measured machine's font gives the sentence.
  test('wraps a sentence that needs three lines in full, inside the bar and above the content', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 844 })
    await page.goto('/harness.html?surface=ios')
    await page.addStyleTag({ content: `.m-connection > span:last-child { letter-spacing: ${WIDE_FACE}em; }` })
    const line = page.locator('.m-connection')
    await expect(line).toHaveText('In contact with this host')

    await slowTry(page, 'paired')
    const words = line.locator('span').last()
    await expect(words).toHaveText(PAIRED)
    expect(await line.getAttribute('title')).toBeNull()
    const shown = await measure(words)
    expect(shown.cut, 'no part of the sentence is cut off').toBe(false)
    expect(shown.lines, 'the whole sentence takes three lines or more in this face').toBeGreaterThanOrEqual(3)
    const outside = await outsideTheBar(page)
    expect(outside, 'the line and its text lie inside the bar, with the content below it').toEqual([])
    const sideways = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(sideways, 'the page does not scroll sideways').toBeLessThanOrEqual(0)
    const overrun = await overrunning(page, '.m-connection')
    expect(overrun, 'lines of the connection line that run past the screen or its box').toEqual([])
    test.info().annotations.push({ type: 'bar height', description: `320 px wide, wide face: ${shown.bar} px, ${shown.lines} lines` })
    await page.screenshot({ path: screenshotPath(`kr-slow-try-phone-wide-face-320-${test.info().project.name}`) })

    // The control: a host's own words that run on are still cut to two lines in this face, and keep their title.
    await page.evaluate((reason) => {
      window.krTestHost?.setStillReaching(null)
      window.krTestHost?.setConnected(false, reason)
    }, RUNS_ON)
    await expect(words).toHaveText(RUNS_ON)
    const control = await measure(words)
    expect(control.cut, 'the measure sees words that are cut to two lines').toBe(true)
    expect(await line.getAttribute('title')).toBe(RUNS_ON)
  })

  test('goes back to the reason, cut to two lines and with its title, when the mark ends', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/harness.html?surface=ios')
    const line = page.locator('.m-connection')
    await expect(line).toHaveText('In contact with this host')
    await slowTry(page, 'paired')
    await expect(line).toHaveText(PAIRED)
    await page.evaluate(() => {
      window.krTestHost?.setStillReaching(null)
    })
    await expect(line).toHaveText(SAID)
    expect(await line.getAttribute('title')).toBe(SAID)
    expect(await line.locator('span').last().getAttribute('class')).toBeNull()
    expect(await line.locator('span').last().evaluate((element) => getComputedStyle(element).overflow)).toBe(
      'hidden'
    )
  })
})

test.describe("the desktop's bar, while a slow try is still running", () => {
  for (const [label, width] of [
    ['desktop width', 1280],
    ['phone width', 390]
  ] as const) {
    for (const [name, host, words] of [
      ['paired', 'paired', PAIRED],
      ['local', 'local', LOCAL]
    ] as const) {
      for (const percent of [100, 200]) {
        test(`shows the sentence for the ${name} host inside the bar at ${percent} percent text, ${label}`, async ({
          page
        }) => {
          await withTextSize(page, 1, percent === 100 ? null : percent)
          await page.setViewportSize({ width, height: 800 })
          await page.goto('/harness.html')
          await page.waitForSelector('.app-shell')
          const line = page.locator('.topbar .connection')
          await expect(line).toHaveText('Connected to this machine')

          await slowTry(page, host)
          await expect(line).toHaveText(words)
          expect(
            await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
            'the page does not scroll sideways'
          ).toBeLessThanOrEqual(0)
          expect(await overrunning(page, '.topbar'), 'lines that run past the screen or the bar').toEqual([])
          const bar = await page.locator('.topbar').evaluate((element) => Math.round(element.getBoundingClientRect().height))
          test.info().annotations.push({ type: 'bar height', description: `${percent} percent, ${label}: ${bar} px` })
        })
      }
    }
  }
})

test.describe('the connection line, when the sentence appears', () => {
  for (const reduced of ['no-preference', 'reduce'] as const) {
    test(`is a text swap with no transition and no animation, with motion ${reduced}`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: reduced })
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto('/harness.html?surface=ios')
      await expect(page.locator('.m-connection')).toHaveText('In contact with this host')
      await slowTry(page, 'paired')
      await expect(page.locator('.m-connection')).toHaveText(PAIRED)
      const phone = await movement(page.locator('.m-connection'))
      expect(phone).toEqual(STILL)

      await page.setViewportSize({ width: 1280, height: 800 })
      await page.goto('/harness.html')
      await page.waitForSelector('.app-shell')
      await expect(page.locator('.topbar .connection')).toHaveText('Connected to this machine')
      await slowTry(page, 'local')
      await expect(page.locator('.topbar .connection')).toHaveText(LOCAL)
      const desktop = await movement(page.locator('.topbar .connection'))
      expect(desktop).toEqual(STILL)
    })
  }
})
