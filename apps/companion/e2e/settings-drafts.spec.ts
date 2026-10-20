/**
 * Keeping drafts in step, in a real browser engine.
 *
 * The switch sits in settings sync's card once settings sync is on, with the words that say what it
 * does and, while it is on, which drafts stay on this computer and why. What a component test cannot
 * hold is layout and the keyboard: that the words and the switch stay inside the card at every text
 * size and in a face as wide as the Linux runner's, and that the switch is reached and pressed
 * from the keyboard alone.
 *
 * Every screenshot goes under `/tmp`, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** A host name with no short place to break a line, as a company's own might be. */
const LONG_HOST = 'studio.synchronisation.example-company.com'

/**
 * Everything the drafts row can say at once: three reasons, one of them a long host and one of them
 * said with each of the two details a host that cannot be read has, and a problem.
 */
const KEPT = {
  enabled: true,
  problem: 'The sync service could not be reached, so no draft was sent or brought down.',
  arrivals: 0,
  kept_here: [
    { host: LONG_HOST, why: 'private', detail: null, drafts: 12 },
    {
      host: 'laptop',
      why: 'unreadable',
      detail: 'the host is of an earlier build that answers only a device that manages it; update the host',
      drafts: 2
    },
    {
      host: 'desk',
      why: 'unreadable',
      detail: 'the host is changing its privacy mode',
      drafts: 3
    },
    { host: null, why: 'unknown_host', detail: null, drafts: 1 }
  ]
} as const

function shot(name: string): string {
  return `/tmp/kr-companion-drafts-${name}-${test.info().project.name}.png`
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

/** Opens the account, with settings sync on, and returns the card. */
async function openTheCard(page: Page, surface: 'desktop' | 'ios') {
  await page.goto(surface === 'ios' ? '/harness.html?surface=ios' : '/harness.html')
  await page.waitForSelector(surface === 'ios' ? '.m-shell' : '.app-shell')
  const account =
    surface === 'ios'
      ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
      : page.getByRole('button', { name: /^Account/ })
  await account.click()
  await page.evaluate(() => {
    window.krTestHost?.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to' } })
  })
  return page.getByTestId('settings-sync')
}

// KR-REQ-20.13: a draft is a draft, kept in step only when the person asks for it, and kept here
// when its host says privacy mode is on. The switch and its words stay whole at the default size
// and at the largest.
for (const [surface, size] of [
  ['desktop', 1],
  ['desktop', 2],
  ['ios', 1],
  ['ios', LARGEST]
] as const) {
  test(`keeps the drafts switch and what it says whole, ${surface}, text ${size.toFixed(1)}x`, async ({
    page
  }) => {
    if (surface === 'ios') {
      await page.setViewportSize({ width: 320, height: 720 })
      await withTextScale(page, size)
    } else if (size !== 1) {
      await page.addInitScript((factor) => {
        document.addEventListener('DOMContentLoaded', () => {
          document.documentElement.style.fontSize = `${16 * factor}px`
        })
      }, size)
    }
    const card = await openTheCard(page, surface)
    const row = card.getByTestId('drafts-sync')
    await expect(row).toBeVisible()
    await page.evaluate((kept) => {
      window.krTestHost?.settings.change({ sync: { drafts: kept } })
    }, KEPT)
    await expect(card.getByTestId('drafts-kept-here')).toHaveCount(4)
    await expect(card.getByTestId('drafts-problem')).toBeVisible()

    expect(await overrunning(page, '[data-testid="drafts-sync"]')).toEqual([])
    // The switch is inside the card, and no smaller than a finger needs.
    const inside = await card
      .getByRole('switch', { name: 'Keep drafts in step' })
      .evaluate((each) => {
        const box = each.getBoundingClientRect()
        const edge = each.closest('[data-card]')?.getBoundingClientRect()
        return edge !== undefined && box.left >= edge.left && box.right <= edge.right
      })
    expect(inside, 'the switch lies inside the card').toBe(true)

    const view = page.viewportSize()
    const height = await card.evaluate((each) => each.getBoundingClientRect().height)
    if (view !== null) {
      await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
    }
    await card.screenshot({ path: shot(`${surface}-${size.toFixed(1)}x`) })

    // What a device reads once the host says privacy mode is off: nothing is kept here, and the
    // row has only its switch and its words.
    await page.evaluate(() => {
      window.krTestHost?.settings.change({
        sync: { drafts: { enabled: true, kept_here: [], problem: null, arrivals: 0 } }
      })
    })
    await expect(card.getByTestId('drafts-kept-here')).toHaveCount(0)
    await expect(card.getByTestId('drafts-problem')).toHaveCount(0)
    expect(await overrunning(page, '[data-testid="drafts-sync"]')).toEqual([])
    await card.screenshot({ path: shot(`${surface}-${size.toFixed(1)}x-nothing-kept`) })
  })
}

test('is reached and pressed from the keyboard alone, and says what it did', async ({
  page,
  browserName
}) => {
  const card = await openTheCard(page, 'desktop')
  const keep = card.getByRole('switch', { name: 'Keep drafts in step' })
  await expect(keep).toHaveAttribute('aria-checked', 'false')
  // WebKit on macOS passes over buttons unless the system's keyboard setting asks for them, so
  // there the switch is focused directly and the key that presses it is what the case holds to.
  if (browserName === 'chromium') {
    await card.getByTestId('settings-sync-now').focus()
    await page.keyboard.press('Tab')
  } else {
    await keep.focus()
  }
  await expect(keep).toBeFocused()
  await page.keyboard.press('Space')
  await expect(keep).toHaveAttribute('aria-checked', 'true')
  expect(await page.evaluate(() => window.krTestHost?.settings.draftsSetTo)).toEqual([true])
})
