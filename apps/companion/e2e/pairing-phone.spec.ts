/**
 * The pairing column of a phone, in both engines the page runs in, whole at the default text size
 * and at the largest: the scanner, the picker and the pasteboard each a finger tall, the value both
 * devices show wrapping between its groups and never running past the screen, and the words that
 * say a camera is not allowed or that a picture shows no code.
 *
 * The scripted host stands in for native code. It offers the sources the address asks for
 * (`scan=camera`, `scan=photo` or `scan=both`) and answers what a test tells it to, so what these
 * hold is what the page does with them. The native scanner and the system's picker are proved on the
 * phones themselves, in `scripts/e2e-pairing-device.sh`.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** What a finger needs to hit, in points on iOS and density-independent pixels on Android. */
const TARGET = { ios: 44, android: 48 } as const

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

function shot(name: string): string {
  return `/tmp/kr-pairing-phone-${name}-${test.info().project.name}.png`
}

for (const surface of ['ios', 'android'] as const) {
  for (const [size, ratio] of [
    ['the default text size', 1],
    ['the largest text size', LARGEST]
  ] as const) {
    const label = `${surface}-${ratio === 1 ? 'default' : 'largest'}`

    test.describe(`pairing on ${surface} at ${size}`, () => {
      test.beforeEach(async ({ page }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=hosts&scan=both`)
        await expect(page.locator('.m-shell')).toBeVisible()
      })

      test('offers the scanner, the picker and the pasteboard, each a finger tall, and speaks of this phone', async ({
        page
      }) => {
        await expect(page.getByRole('heading', { name: 'Pair with a host' })).toBeVisible()
        for (const name of ['Scan code', 'Pair', 'Choose a photo', 'Paste invitation']) {
          const button = page.getByRole('button', { name, exact: true })
          await expect(button).toBeVisible()
          const box = await button.boundingBox()
          expect(box?.height ?? 0, `${name} is a finger tall`).toBeGreaterThanOrEqual(TARGET[surface] - 1)
        }
        await expect(page.getByText(/Scan the QR code/)).toBeVisible()
        await expect(page.getByTestId('device-name')).toContainText('This phone appears as')
        await page.locator('.pairing-column').screenshot({ path: shot(`entry-${label}`) })
        expect(await overrunning(page, '.pairing-column'), 'nothing runs past the screen').toEqual([])
      })

      test('shows the value whole while the owner decides, and the words when a camera is not allowed', async ({
        page
      }) => {
        await page.evaluate(() => {
          window.krTestHost?.setIntake('camera', {
            invitation: null,
            failure: 'camera_denied',
            cleared: false,
            declined: false,
            cancelled: false
          })
        })
        await page.getByRole('button', { name: 'Scan code', exact: true }).click()
        await expect(page.getByTestId('paste-failure')).toContainText(/camera/)
        const settings = await page.getByTestId('open-settings').boundingBox()
        expect(settings?.height ?? 0, 'Open Settings is a finger tall').toBeGreaterThanOrEqual(TARGET[surface] - 1)
        await page.locator('.pairing-column').screenshot({ path: shot(`denied-${label}`) })
        expect(await overrunning(page, '.pairing-column')).toEqual([])

        await page.evaluate(() => {
          window.krTestHost?.setPairing({
            state: {
              state: 'awaiting_approval',
              value: 'f3c1 46fd',
              expires_at_ms: Date.now() + 4 * 60_000,
              rights: ['session.view'],
              authority: 'view sessions',
              grant_expires_at_ms: null
            }
          })
        })
        await expect(page.getByRole('heading', { name: 'Check this value on the host' })).toBeVisible()
        await expect(page.getByText(/Approve this phone on the host/)).toBeVisible()
        // The value wraps between its groups, and each group stays whole.
        const groups = await page.locator('.verification-group').evaluateAll((all) =>
          all.map((each) => {
            const box = each.getBoundingClientRect()
            return { left: box.left, right: box.right, lines: each.getClientRects().length }
          })
        )
        expect(groups).toHaveLength(2)
        for (const group of groups) {
          expect(group.lines, 'a group is on one line').toBe(1)
          expect(group.right, 'a group is inside the screen').toBeLessThanOrEqual(320)
        }
        await page.locator('.pairing-column').screenshot({ path: shot(`value-${label}`) })
        expect(await overrunning(page, '.pairing-column')).toEqual([])
      })
    })
  }
}

// A request the host asks a phone to confirm keeps the words the whole width of the
// row at the default text size on a phone 390 points wide, and the buttons go under them: beside
// the words they took most of the row, and the title ran a word to a line.
for (const surface of ['ios', 'android'] as const) {
  for (const [ceremony, buttons] of [
    ['face_id', ['Confirm with Face ID', 'Not now']],
    ['none', ['Not now']]
  ] as const) {
    test(`gives the words of a request to confirm the row, with the buttons under them, on ${surface} with ${ceremony === 'none' ? 'no ceremony' : 'a ceremony'}`, async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&tab=attention`)
      await expect(page.locator('.m-shell')).toBeVisible()
      await page.evaluate((kind) => {
        window.krTestHost?.setConfirmations({
          ceremony: kind,
          requests: [
            {
              reference: 'request-1',
              host_name: 'studio',
              title: 'Add a device',
              detail: 'Confirm adding Pixel 8 (Android) to studio, which may view sessions for 60 minutes.',
              value: 'f3c1 46fd',
              facts: [],
              notice: null,
              statement: null,
              reading: null,
              expires_at_ms: Date.now() + 600_000,
              checkable: true
            }
          ]
        })
      }, ceremony)
      const row = page.getByTestId('confirmation-row')
      await expect(row).toBeVisible()
      for (const name of buttons) {
        await expect(row.getByRole('button', { name, exact: true })).toBeVisible()
      }
      const where = await row.evaluate((element) => {
        const words = element.querySelector('.spacer')?.getBoundingClientRect()
        const actions = element.querySelector('.confirmation-actions')?.getBoundingClientRect()
        const whole = element.getBoundingClientRect()
        if (words === undefined || actions === undefined) throw new Error('the row has no words or no buttons')
        return { row: whole.width, words: words.width, wordsBottom: words.bottom, actionsTop: actions.top }
      })
      expect(where.words, 'the words take most of the row').toBeGreaterThan(where.row * 0.8)
      expect(where.actionsTop, 'the buttons are under the words').toBeGreaterThanOrEqual(where.wordsBottom - 1)
      await page.screenshot({ path: shot(`confirmation-${surface}-${ceremony}`) })
      expect(await overrunning(page, '[data-testid="confirmations"]')).toEqual([])
    })
  }
}

// The words about the camera arrive in a region a screen reader watches. With nothing to say, the
// region takes no room and stays in the accessibility tree, so the first words that arrive are heard.
for (const surface of ['ios', 'android'] as const) {
  test(`keeps the camera's status region in the accessibility tree while it is empty, on ${surface}`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=${surface}&session=8a7b6c50-22bb-4c3d-8e4f-000000000101`)
    const region = page.getByTestId('camera-notice')
    await expect(region).toBeEmpty()
    await expect(page.getByRole('status').and(region), 'the empty region is one a screen reader finds').toHaveCount(1)
    const box = await region.boundingBox()
    expect(box?.height ?? 0, 'the empty region takes no room').toBeLessThanOrEqual(2)
  })
}
