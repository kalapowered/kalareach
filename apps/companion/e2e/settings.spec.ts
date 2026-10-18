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

import { overrunning, stopWrapping } from './layout'

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
  await page.waitForSelector(surface === 'ios' ? '.m-shell' : '.app-shell')
  // The phone reaches the account from its tab bar, the desktop from its sidebar.
  const account =
    surface === 'ios'
      ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
      : page.getByRole('button', { name: /^Account/ })
  await account.click()
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
      // The photograph is of the whole choice: the window is made as tall as the choice is, so the
      // phone's tab bar does not lie across it.
      const view = page.viewportSize()
      const height = await choice.evaluate((each) => each.getBoundingClientRect().height)
      if (view !== null) {
        await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
      }
      await choice.screenshot({ path: shot(`${surface}-${size.toFixed(1)}x-${theme}`) })
    })
  }
}

test('is reached and decided from the keyboard alone', async ({ page, browserName }) => {
  const choice = await openTheChoice(page, 'desktop', 'light')
  await expect(choice.getByRole('heading', { name: /Which appearance/ })).toBeFocused()

  // Tab reaches the first version. WebKit on macOS passes over radio buttons unless the system's
  // keyboard setting asks for them, so there the version is focused directly and the arrow keys and
  // Enter are what the case holds to.
  if (browserName === 'chromium') {
    await page.keyboard.press('Tab')
  } else {
    await choice.getByRole('radio').first().focus()
  }
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

// KR-REQ-13.19: at the largest text size on the narrowest screen, nothing runs past the screen's
// edge or its box. The Linux runner draws the page in DejaVu Sans, which sets about a tenth more
// text across a line than the faces of the Mac or the phone do, so a heading that fits there can
// run past its box on the runner. Verdana is as wide and every Mac has it: these cases put the
// page in it, with DejaVu Sans after it for the machine that has none.
const WIDE_FACE =
  ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; ' +
  '--font-mono: Menlo, "DejaVu Sans Mono", monospace !important; }'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** A service host with nothing in it a line may break at, as a company's own might be. */
const LONG_HOST = 'settings.synchronisation.example-company.com'

/** Opens the harness on the narrowest phone at the largest text size, in the widest face. */
async function atTheLargestSizeInAWideFace(page: Page, surface: 'ios' | 'android', address: string) {
  await withTextScale(page, LARGEST)
  await page.setViewportSize({ width: 320, height: 720 })
  await page.goto(`/harness.html?surface=${surface}${address}`)
  await page.addStyleTag({ content: WIDE_FACE })
  await page.waitForSelector('.m-shell')
}

for (const surface of ['ios', 'android'] as const) {
  test(`keeps the settings card, with everything it can say and its choice open, whole at the largest size in a wide face, ${surface}`, async ({
    page
  }) => {
    await atTheLargestSizeInAWideFace(page, surface, '')
    await page
      .getByRole('navigation', { name: 'Sections' })
      .getByRole('button', { name: /^Account/ })
      .click()
    // Before sync is on the card says what it would do and offers to turn it on: the longest of
    // its words are in this state.
    const off = page.getByTestId('settings-sync')
    await expect(off).toHaveAttribute('data-state', 'off')
    await expect(off.getByTestId('settings-sync-turn-on')).toBeVisible()
    expect(await overrunning(page, '[data-testid="settings-sync"]'), 'the card before sync is on').toEqual([])
    await page.evaluate(
      ({ waiting, host }) => {
        window.krTestHost?.settings.waitingForAChoice(waiting)
        window.krTestHost?.settings.change({
          sync: {
            state: 'on',
            kept_at: host,
            outstanding: 1,
            paused: true,
            conflicts: waiting.others.length,
            problem: 'The sync service could not be reached, so nothing was sent or received.'
          }
        })
      },
      { waiting: WAITING, host: LONG_HOST }
    )
    const card = page.getByTestId('settings-sync')
    await card.getByTestId('settings-sync-choose').click()
    await expect(card.getByTestId('settings-choice')).toBeVisible()
    await expect(card.getByTestId('settings-sync-status')).toHaveCSS('font-family', /Verdana/)

    const roots = ['[data-testid="settings-sync"]', '.account-section-title']
    for (const root of roots) {
      expect(await overrunning(page, root), `lines of ${root} that run past the screen or their box`).toEqual([])
    }
    await card.scrollIntoViewIfNeeded()
    await page.screenshot({ path: shot(`wide-card-${surface}`), fullPage: true })
    // The control: with the text kept from wrapping, the same measure sees the card run out.
    await stopWrapping(page, roots)
    expect(await overrunning(page, roots[0] ?? ''), 'the measure sees text that cannot wrap').not.toEqual([])
  })

  test(`keeps the appearance control and what it says of the settings whole at the largest size in a wide face, ${surface}`, async ({
    page
  }) => {
    await atTheLargestSizeInAWideFace(page, surface, `&session=${SESSION}`)
    await page.evaluate(() => {
      window.krTestHost?.settings.change({ sync: { state: 'on', conflicts: 2 } })
      window.krTestHost?.settings.failKeeping(
        'The colour mode could not be kept on this computer, so it is back to what it was.'
      )
    })
    await page.getByRole('button', { name: 'Settings' }).click()
    const sheet = page.getByRole('dialog')
    await expect(sheet).toBeVisible()
    // The keeping fails, so the choice is taken back: pressing the version is what raises the problem.
    await sheet.locator('.theme-option', { hasText: 'Dark' }).click()
    await expect(sheet.getByTestId('theme-problem')).toBeVisible()
    await expect(sheet.getByTestId('theme-waiting')).toBeVisible()
    await expect(sheet.getByTestId('theme-problem')).toHaveCSS('font-family', /Verdana/)

    const roots = ['.settings-content']
    for (const root of roots) {
      expect(await overrunning(page, root), `lines of ${root} that run past the screen or their box`).toEqual([])
    }
    await page.screenshot({ path: shot(`wide-appearance-${surface}`) })
    await stopWrapping(page, roots)
    expect(await overrunning(page, roots[0] ?? ''), 'the measure sees text that cannot wrap').not.toEqual([])
  })
}
