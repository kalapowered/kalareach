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
 * iOS carries the person's text size to the page as `--text-scale`, and Android multiplies the
 * root's font size itself; both are set directly here, as the web view's answer, as the text-size
 * tests do. That the real web views give the page the size is held on a simulator and an emulator.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

const SAID = 'the relay closed this connection'
const PAIRED = 'this application is still trying to reach the host you chose'
const LOCAL = 'this application is still trying to reach the host on this machine'

/** A host's own words for a refusal, as long as the longest the line has shown. */
const RUNS_ON =
  'this device is not signed in to the organisation that owns this host, so the host refused the connection: ask an owner of the organisation to add this device to its list of devices'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** How a phone's web view gives the page the person's text size. */
const SIZES = [
  { name: 'default', scale: 1, root: null, surface: 'ios' },
  { name: 'ios-largest', scale: LARGEST, root: null, surface: 'ios' },
  { name: 'android-2.0', scale: 1, root: 200, surface: 'android' }
] as const

/** Sets the text size the way the web view does, before the page's first frame. */
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

      const measure = () =>
        words.evaluate((element) => ({
          cut: element.scrollHeight > element.clientHeight + 1,
          lines: Math.round(element.getBoundingClientRect().height / parseFloat(getComputedStyle(element).lineHeight)),
          bar: Math.round((element.closest('.m-topbar') as HTMLElement).getBoundingClientRect().height)
        }))
      const whole = await measure()
      expect(whole.cut, 'no part of the sentence is cut off').toBe(false)
      test.info().annotations.push({
        type: 'bar height',
        description: `${size.name}, ${width} px wide: ${whole.bar} px, ${whole.lines} lines`
      })
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
        'the page does not scroll sideways'
      ).toBeLessThanOrEqual(0)
      expect(await overrunning(page, '.m-topbar'), 'lines that run past the screen or the bar').toEqual([])
      await page.screenshot({ path: screenshotPath(`kr-slow-try-phone-${size.name}-${width}-${test.info().project.name}`) })

      // The control: the same measure, on a host's own words that run on, sees the two-line cut
      // that holds for every state but this one.
      await page.evaluate((reason) => {
        window.krTestHost?.setStillReaching(null)
        window.krTestHost?.setConnected(false, reason)
      }, RUNS_ON)
      await expect(words).toHaveText(RUNS_ON)
      expect((await measure()).cut, 'the measure sees words that are cut to two lines').toBe(true)
      expect(await line.getAttribute('title')).toBe(RUNS_ON)
    })
  }

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
      const phone = await page.locator('.m-connection').evaluate((element) => ({
        animations: element.getAnimations({ subtree: true }).length,
        transition: getComputedStyle(element).transitionDuration,
        dot: getComputedStyle(element.querySelector('.status-dot') as Element).transitionDuration
      }))
      expect(phone).toEqual({ animations: 0, transition: '0s', dot: '0s' })

      await page.setViewportSize({ width: 1280, height: 800 })
      await page.goto('/harness.html')
      await page.waitForSelector('.app-shell')
      await expect(page.locator('.topbar .connection')).toHaveText('Connected to this machine')
      await slowTry(page, 'local')
      await expect(page.locator('.topbar .connection')).toHaveText(LOCAL)
      const desktop = await page.locator('.topbar .connection').evaluate((element) => ({
        animations: element.getAnimations({ subtree: true }).length,
        transition: getComputedStyle(element).transitionDuration,
        dot: getComputedStyle(element.querySelector('.status-dot') as Element).transitionDuration
      }))
      expect(desktop).toEqual({ animations: 0, transition: '0s', dot: '0s' })
    })
  }
})
