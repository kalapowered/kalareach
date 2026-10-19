/**
 * The devices that share the person's settings, in a real browser engine.
 *
 * The card names each device and puts one control beside it. What a component test cannot hold is
 * layout and the keyboard: that the words and the controls stay inside the card at every text size
 * and in a face as wide as the Linux runner's, that no control is smaller than a finger needs, and
 * that a device is shared with, taken out (after one question) and an offer joined from the keyboard
 * alone.
 *
 * Every screenshot goes under `/tmp`, named for the engine and the case.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The Linux runner draws the page in DejaVu Sans, which sets about a tenth more text across a line. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

/** A name with no short place to break a line, as a person's own might be. */
const LONG_NAME = 'studio-workstation-in-the-converted-garage'

/** Everything the card can say at once. */
const EVERYTHING = {
  state: 'on',
  kept_at: 'reach.kala.to',
  devices: {
    can_confirm: true,
    out: false,
    waiting: true,
    members: [
      { reference: 'me', name: 'This computer', this_computer: true, vouched: true },
      { reference: 'a', name: LONG_NAME, this_computer: false, vouched: false },
      { reference: 'b', name: 'the-phone', this_computer: false, vouched: true }
    ],
    candidates: [{ reference: 'c', name: 'the-tablet-in-the-kitchen' }],
    held_out: [{ reference: 'h', name: LONG_NAME }],
    offers: [{ reference: 'o', name: 'the-laptop' }],
    outcomes: [{ what: 'addition', ended: 'refused', name: LONG_NAME }]
  }
} as const

function shot(name: string): string {
  return `/tmp/kr-companion-devices-${name}-${test.info().project.name}.png`
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

/** Opens the account with settings sync on and the card showing everything it can say. */
async function openTheCard(page: Page, surface: 'desktop' | 'ios') {
  await page.goto(surface === 'ios' ? '/harness.html?surface=ios' : '/harness.html')
  await page.waitForSelector(surface === 'ios' ? '.m-shell' : '.app-shell')
  const account =
    surface === 'ios'
      ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
      : page.getByRole('button', { name: /^Account/ })
  await account.click()
  await page.evaluate((view) => {
    window.krTestHost?.settings.change({ sync: view })
  }, EVERYTHING)
  return page.getByTestId('settings-devices')
}

/** Photographs the whole of `element`: the window is made as tall as it is, so no bar lies across it. */
async function photograph(page: Page, element: Locator, path: string): Promise<void> {
  const view = page.viewportSize()
  const height = await element.evaluate((each) => each.getBoundingClientRect().height)
  if (view !== null) await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
  await element.screenshot({ path })
}

// KR-REQ-20.13: the controls of the card stay whole inside it at the default size and the largest, in
// the system's face and in a wide one.
for (const [surface, size, face] of [
  ['desktop', 1, 'system'],
  ['desktop', 2, 'system'],
  ['ios', 1, 'system'],
  ['ios', LARGEST, 'system'],
  ['ios', LARGEST, 'wide']
] as const) {
  test(`keeps the devices card whole, ${surface}, text ${size.toFixed(1)}x, ${face} face`, async ({
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
    if (face === 'wide') await page.addStyleTag({ content: WIDE_FACE })
    await expect(card).toBeVisible()
    await expect(card.getByTestId('settings-devices-outcome')).toBeVisible()
    await expect(card.getByTestId('settings-devices-waiting')).toBeVisible()
    await expect(card.getByTestId('settings-devices-offer')).toBeVisible()
    // A device taken out after a revoke has its own words and a control named for it.
    await expect(card.getByTestId('settings-devices-held-out-note')).toBeVisible()
    await expect(card.getByRole('button', { name: `Share settings with ${LONG_NAME} again` })).toBeVisible()
    // The question about taking a device out is part of the card too, with a long name in it.
    await card.getByRole('button', { name: `Take ${LONG_NAME} out` }).click()
    await expect(card.getByTestId('settings-devices-taking-out')).toBeVisible()

    expect(await overrunning(page, '[data-testid="settings-devices"]')).toEqual([])
    // Every control is inside the card, and no smaller than a finger needs.
    const controls = await card.getByRole('button').evaluateAll((buttons) =>
      buttons.map((each) => {
        const box = each.getBoundingClientRect()
        const edge = each.closest('[data-card]')?.getBoundingClientRect()
        return {
          name: each.getAttribute('aria-label') ?? each.textContent,
          inside: edge !== undefined && box.left >= edge.left && box.right <= edge.right,
          tall: box.height
        }
      })
    )
    expect(controls.length).toBeGreaterThan(4)
    for (const control of controls) {
      expect(control.inside, `${control.name ?? ''} lies inside the card`).toBe(true)
      expect(control.tall, `${control.name ?? ''} is tall enough to press`).toBeGreaterThanOrEqual(
        surface === 'ios' ? 44 : 24
      )
    }
    await photograph(page, card, shot(`${surface}-${size.toFixed(1)}x-${face}`))
  })
}

test('shares with a device, takes one out and joins an offer from the keyboard alone', async ({
  page
}) => {
  const card = await openTheCard(page, 'desktop')
  const press = async (button: Locator) => {
    // WebKit on macOS passes over buttons unless the system's keyboard setting asks for them, so
    // each button is focused directly and the key that presses it is what the case holds to.
    await button.focus()
    await expect(button).toBeFocused()
    await page.keyboard.press('Enter')
  }
  await press(card.getByRole('button', { name: 'Share settings with the-tablet-in-the-kitchen' }))
  await press(card.getByRole('button', { name: 'Take the-phone out' }))
  await press(card.getByRole('button', { name: 'Take the-phone out now' }))
  await press(card.getByRole('button', { name: 'Join the settings started on the-laptop' }))
  await expect
    .poll(() => page.evaluate(() => window.krTestHost?.settings.devicesAsked))
    .toEqual(['refresh', 'share c', 'remove b', 'join o'])
})
