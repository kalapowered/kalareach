/**
 * The choice between two versions of the settings, in a real browser engine.
 *
 * Two devices changed how KalaReach looks, and the account sheet's settings card opens a choice in
 * place: each version drawn as the appearance it holds, this device's own first, nothing selected
 * to begin with, and a button that names what it keeps. What a component test cannot hold is
 * layout and motion: that no version is cut at any text size, that a press answers and a reduced
 * motion setting takes the travel out of it, and that the keyboard reaches every version.
 *
 * Every screenshot goes under `/tmp`, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const WAITING = {
  mine: { colour_mode: 'system', updated_at_ms: 1_700_000_000_000 },
  others: [
    { conflict_id: 'copy-1', colour_mode: 'light', updated_at_ms: 1_699_000_000_000 },
    { conflict_id: 'copy-2', colour_mode: 'dark', updated_at_ms: 1_699_500_000_000 }
  ]
} as const

function shot(name: string): string {
  return `/tmp/kr-companion-settings-${name}-${test.info().project.name}.png`
}

/** Sets the phone's text size as the web view would, before the page loads. */
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

/** Opens the harness, tells the fake host two devices changed the colour mode, and opens the choice. */
async function openTheChoice(page: Page, surface: 'desktop' | 'ios', theme: 'light' | 'dark') {
  await page.addInitScript((mode) => {
    window.kalareachSettings = { colour_mode: mode }
  }, theme)
  await page.goto(surface === 'ios' ? '/harness.html?surface=ios' : '/harness.html')
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: /^Account/ }).click()
  await page.evaluate((waiting) => {
    window.krTestHost?.settings.waitingForAChoice(waiting)
    window.krTestHost?.settings.change({
      sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: waiting.others.length }
    })
  }, WAITING)
  const card = page.getByTestId('settings-sync')
  await card.getByTestId('settings-sync-choose').click()
  const choice = card.getByTestId('settings-choice')
  await expect(choice).toBeVisible()
  return choice
}

for (const theme of ['light', 'dark'] as const) {
  // KR-REQ-20.13: the copy a refused write kept is kept for the person to choose from, and the
  // choice is theirs. Every version is whole at the default size and at the largest.
  for (const [surface, size] of [
    ['desktop', 1],
    ['desktop', 2],
    ['ios', 1],
    ['ios', LARGEST]
  ] as const) {
    test(`shows every version whole, ${surface}, text ${size.toFixed(1)}x, ${theme}`, async ({
      page
    }) => {
      if (surface === 'ios') {
        await page.setViewportSize({ width: 390, height: 844 })
        await withTextScale(page, size)
      } else if (size !== 1) {
        // A desktop browser has no system factor; its own text size scales the root.
        await page.addInitScript((factor) => {
          document.addEventListener('DOMContentLoaded', () => {
            document.documentElement.style.fontSize = `${16 * factor}px`
          })
        }, size)
      }
      const choice = await openTheChoice(page, surface, theme)

      const options = choice.getByRole('radio')
      await expect(options).toHaveCount(3)
      for (const option of await options.all()) await expect(option).not.toBeChecked()
      await expect(choice.getByTestId('settings-choice-keep')).toBeDisabled()

      expect(await overrunning(page, '[data-testid="settings-choice"]')).toEqual([])
      for (const label of await choice.locator('.choice-option').all()) {
        const within = await label.evaluate((each) => {
          const box = each.getBoundingClientRect()
          return box.left >= 0 && box.right <= window.innerWidth
        })
        expect(within, 'a version lies inside the screen').toBe(true)
      }
      await page.evaluate(() =>
        Promise.all(document.getAnimations().map((each) => each.finished.catch(() => undefined)))
      )
      await page.screenshot({ path: shot(`${surface}-${size.toFixed(1)}x-${theme}`) })
    })
  }
}

test('is reached and decided from the keyboard alone', async ({ page }) => {
  const choice = await openTheChoice(page, 'desktop', 'light')
  await expect(choice.getByRole('heading', { name: /Which appearance/ })).toBeFocused()

  await page.keyboard.press('Tab')
  await expect(choice.getByRole('radio').first()).toBeFocused()
  await page.keyboard.press('ArrowRight')
  await expect(choice.getByRole('radio').nth(1)).toBeChecked()
  await expect(choice.getByTestId('settings-choice-keep')).toHaveText('Keep Light')

  await choice.getByTestId('settings-choice-keep').focus()
  await page.keyboard.press('Enter')
  await expect(choice).toHaveCount(0)
  expect(await page.evaluate(() => window.krTestHost?.settings.kept)).toEqual([
    { choice: 'copy', conflict_id: 'copy-1' }
  ])
})

// A press on a version answers at once, and a reduced motion setting takes the travel out of the
// answer and leaves the rest.
test('answers a press with a small scale, and not when the person asked for less motion', async ({
  page
}) => {
  const choice = await openTheChoice(page, 'desktop', 'light')
  const preview = choice.locator('.choice-option .theme-preview').first()
  const transformOf = (): Promise<string> =>
    preview.evaluate((each) => getComputedStyle(each).transform)
  const pressOn = async (): Promise<void> => {
    const box = await preview.boundingBox()
    if (box === null) throw new Error('the version is not drawn')
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await page.mouse.down()
  }

  await pressOn()
  await expect.poll(transformOf).toMatch(/^matrix\(0\.9/)
  await page.mouse.up()
  await expect.poll(transformOf).toBe('none')

  await page.emulateMedia({ reducedMotion: 'reduce' })
  await pressOn()
  expect(await transformOf()).toBe('none')
  expect(await preview.evaluate((each) => getComputedStyle(each).transitionDuration)).toBe('0s')
  await page.mouse.up()
})
