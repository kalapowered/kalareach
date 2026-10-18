/**
 * What a person sees when this device's pairing records are not open, in both engines the page
 * runs in: a column of its own where the pairing screen would be, with the words native code says,
 * whole at the default text size and at the largest.
 *
 * The scripted host answers the pairing view with the failure native code gives (`AppState::device`)
 * when the address asks for it: `pairing_records=unavailable` for records that could not be opened,
 * and `pairing_records=locked` for a phone started before its first unlock. The words are native
 * code's own, so these tests hold what the page does with them: where they go, that they are
 * announced as an alert, that nothing runs past the screen when the cause is a long path, and that
 * a locked device's notice gives way to the pairing screen where it stood when native code opens
 * the records at the unlock, with no reload.
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

async function holdsTheLockedNotice(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Cannot pair' })).toBeVisible()
  const words = page.getByRole('alert').filter({ hasText: 'because it is locked' })
  await expect(words).toBeVisible()
  await expect(words).toContainText('when you unlock it')
  // Closing the application would not unlock the device, so the words do not ask for it.
  await expect(words).not.toContainText('Close KalaReach')
  await expect(page.getByLabel('Pairing code')).toHaveCount(0)
}

/** Native code tries at the unlock and the records are still not open, for a cause that is not the lock. */
async function failsAtTheUnlock(page: Page): Promise<void> {
  await page.evaluate(() => {
    window.krTestHost?.failPairingRecords()
  })
  await holdsTheFailure(page)
  // The device is unlocked, so the words no longer say it is locked.
  await expect(page.getByRole('alert').filter({ hasText: 'because it is locked' })).toHaveCount(0)
}

/** Native code opens the records, as it does at the unlock, and the pairing screen takes the place. */
async function opensAtTheUnlock(page: Page): Promise<void> {
  await page.evaluate(() => {
    window.krTestHost?.openPairingRecords()
  })
  await expect(page.getByLabel('Pairing code')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Cannot pair' })).toHaveCount(0)
  await expect(page.getByTestId('records-failure')).toHaveCount(0)
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

// A phone that iOS started in the background before the first unlock cannot open its records yet,
// and opens them at the unlock. The notice is the column that the pairing screen takes the place of.
test.describe('the device is locked when the application starts', () => {
  for (const surface of ['ios', 'android'] as const) {
    for (const [size, ratio] of [
      ['the default text size', 1],
      ['the largest text size', LARGEST]
    ] as const) {
      test(`says so, then shows the pairing screen at the unlock, on the hosts tab of ${surface} at ${size}`, async ({
        page
      }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=hosts&pairing_records=locked`)
        await expect(page.locator('.m-shell')).toBeVisible()
        await holdsTheLockedNotice(page)
        const label = `${surface}-${ratio === 1 ? 'default' : 'largest'}`
        expect(await overrunning(page, '.pairing-column'), 'nothing runs past the screen').toEqual([])
        await page.screenshot({ path: shot(`locked-${label}`), fullPage: true })

        // This case holds the notice and its giving way, and the page being no wider than the
        // screen when it has: how the pairing screen itself lays out at this size is not its concern.
        // A try at the unlock that fails for another cause changes the words first, in place.
        await failsAtTheUnlock(page)
        expect(await overrunning(page, '.pairing-column'), 'nothing runs past the screen').toEqual([])
        await page.screenshot({ path: shot(`failed-${label}`), fullPage: true })
        await opensAtTheUnlock(page)
        const across = await page.evaluate(() => ({
          page: document.documentElement.scrollWidth,
          screen: window.innerWidth
        }))
        expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
        await page.screenshot({ path: shot(`unlocked-${label}`), fullPage: true })
      })
    }
  }

  test('says so on the pairing view of the desktop, then takes the code at the unlock', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 760 })
    await page.goto('/harness.html?pairing_records=locked')
    await page.waitForSelector('.app-shell')
    await page.getByRole('button', { name: 'Pair with a host' }).click()
    await holdsTheLockedNotice(page)
    await page.screenshot({ path: shot('locked-desktop'), fullPage: true })

    await opensAtTheUnlock(page)
    // The person is looking at this screen, so the field is ready for the code.
    await expect(page.getByLabel('Pairing code')).toBeFocused()
    await page.screenshot({ path: shot('unlocked-desktop'), fullPage: true })
  })
})
