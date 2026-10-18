/**
 * What a person sees when this device's pairing records could not be opened, in both engines the
 * page runs in: a column of its own where the pairing screen would be, with the words native code
 * says, whole at the default text size and at the largest.
 *
 * The scripted host answers the pairing view with the failure native code gives (`AppState::device`)
 * when the address asks for it (`pairing_records=unavailable`). The words are native code's own, so
 * these tests hold what the page does with them: where they go, that they are announced as an alert
 * and that nothing runs past the screen when the cause is a long path.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The ratio the system gives the page, set before it loads, as a phone that already had it opens it. */
async function withSystemTextScale(page: Page, ratio: number): Promise<void> {
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

/** Where a screenshot goes. */
function shot(name: string): string {
  return `/tmp/kr-pairing-unavailable-${name}-${test.info().project.name}.png`
}

async function holdsTheFailure(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Cannot pair' })).toBeVisible()
  const words = page.getByRole('alert').filter({ hasText: 'pairing records could not be opened' })
  await expect(words).toBeVisible()
  await expect(words).toContainText('Close KalaReach and open it again to try once more.')
  // The failure is stated: it asks the person to wait for nothing.
  await expect(words).not.toContainText('Wait a moment')
  // Nothing to enter a code into when the records are not open.
  await expect(page.getByLabel('Pairing code')).toHaveCount(0)
}

// A phone's hosts tab is where pairing lives on a phone; the desktop has a view of its own.
test.describe('the pairing records could not be opened', () => {
  for (const surface of ['ios', 'android'] as const) {
    for (const [size, ratio] of [
      ['the default text size', 1],
      ['the largest text size', LARGEST]
    ] as const) {
      test(`says why, whole, on the hosts tab of ${surface} at ${size}`, async ({ page }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=hosts&pairing_records=unavailable`)
        await expect(page.locator('.m-shell')).toBeVisible()
        await holdsTheFailure(page)

        const across = await page.evaluate(() => ({
          page: document.documentElement.scrollWidth,
          screen: window.innerWidth
        }))
        expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
        expect(await overrunning(page, '.pairing-column'), 'nothing runs past the screen').toEqual([])
        await page.screenshot({
          path: shot(`hosts-${surface}-${ratio === 1 ? 'default' : 'largest'}`),
          fullPage: true
        })
      })
    }
  }

  test('says why on the pairing view of the desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 760 })
    await page.goto('/harness.html?pairing_records=unavailable')
    await page.waitForSelector('.app-shell')
    await page.getByRole('button', { name: 'Pair with a host' }).click()
    await holdsTheFailure(page)
    expect(await overrunning(page, '.pairing-column')).toEqual([])
    await page.screenshot({ path: shot('desktop'), fullPage: true })
  })
})
