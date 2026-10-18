/**
 * The devices of the hosts this computer owns, in a real browser engine.
 *
 * A component test cannot hold layout, the keyboard or motion. This holds what the screen does when
 * it is full: every host and every standing a request can have, a name with no short place to break
 * a line, a text size twice the default, and the face the Linux runner draws, which sets about a
 * tenth more text across a line. The words and the controls stay inside their cards and no control is
 * smaller than a pointer needs. A device is revoked from the keyboard alone, focus follows the
 * request to the words that say where it stands, and under reduced motion those words do not fade.
 *
 * Every screenshot goes under `/tmp`, named for the engine and the case.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The Linux runner draws the page in DejaVu Sans, which sets about a tenth more text across a line. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

/** A name with no short place to break a line, as a person's own might be. */
const LONG_NAME = 'studio-workstation-in-the-converted-garage'

const AT = Date.UTC(2026, 9, 18, 9, 40)

const device = (reference: string, name: string, standing: object, over: object = {}) => ({
  reference,
  name,
  platform: 'ios',
  manages_host: false,
  this_computer: false,
  standing,
  ...over
})

/** Everything the screen can say at once. */
const EVERYTHING = {
  ceremony: 'touch_id',
  feed_origin: 'a-sync-service-with-a-long-name.example.org:8443',
  hosts: [
    {
      reference: 'studio',
      name: LONG_NAME,
      route: 'feed',
      contact: 'answered',
      listed_at_ms: AT,
      host_synchronised_at_ms: AT,
      host_feed_stale: true,
      feed: {
        read: true,
        problem: null,
        removed: false,
        host_wrote_here: true,
        last_acknowledgement: { at_ms: AT, revision: 12, pending_workers: null },
        outstanding: 2,
        poll_interval_seconds: 30
      },
      devices: [
        device('a', LONG_NAME + '-phone', { state: 'active' }),
        device('b', 'the-tablet', { state: 'sent', at_ms: AT, host_lists_revoked: true }),
        device('c', 'the-watch', { state: 'acknowledged', at_ms: AT, pending_workers: 3 }),
        device('d', 'the-laptop', { state: 'done', at_ms: AT }, { platform: 'macos' }),
        device('e', 'the-old-phone', { state: 'refused', reason: 'unknown_target' }),
        device('f', 'the-spare', { state: 'revoked' }, { platform: 'android' }),
        device(
          'g',
          'this-mac',
          { state: 'active' },
          { platform: 'macos', manages_host: true, this_computer: true }
        )
      ]
    },
    {
      reference: 'attic',
      name: 'the-attic',
      route: 'feed',
      contact: 'silent',
      listed_at_ms: AT,
      host_synchronised_at_ms: null,
      host_feed_stale: false,
      feed: {
        read: true,
        problem: null,
        removed: true,
        host_wrote_here: false,
        last_acknowledgement: null,
        outstanding: 0,
        poll_interval_seconds: 30
      },
      devices: [device('h', 'the-kindle', { state: 'active' })]
    },
    {
      reference: 'here',
      name: 'This computer',
      route: 'direct',
      contact: 'answered',
      listed_at_ms: AT,
      host_synchronised_at_ms: null,
      host_feed_stale: false,
      feed: null,
      devices: [device('i', 'the-phone', { state: 'acknowledged', at_ms: AT, pending_workers: null })]
    }
  ]
} as const

function shot(name: string): string {
  return `/tmp/kr-companion-devices-screen-${name}-${test.info().project.name}.png`
}

/** Opens the Devices screen with the host reporting `view`. */
async function openTheScreen(page: Page, view: object = EVERYTHING) {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.evaluate((next) => {
    window.krTestHost?.revocation.change(next as never)
  }, view)
  await page.getByRole('complementary', { name: 'Workspace navigation' }).getByRole('button', { name: 'Devices' }).click()
  await expect(page.getByTestId('devices-host').first()).toBeVisible()
}

/** Photographs the whole of `element`: the window is made as tall as it is, so no bar lies across it. */
async function photograph(page: Page, element: Locator, path: string): Promise<void> {
  const view = page.viewportSize()
  const height = await element.evaluate((each) => each.getBoundingClientRect().height)
  if (view !== null) await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
  // A fade that has not ended is taken at its end, so the photograph shows the words as they settle.
  await page.screenshot({ path, fullPage: true, animations: 'disabled' })
}

// KR-REQ-10.46: the screen stays whole at the default text size and the largest, in the system's face
// and in a wide one.
for (const [size, face] of [
  [1, 'system'],
  [2, 'system'],
  [2, 'wide']
] as const) {
  test(`keeps the devices screen whole, text ${size.toFixed(1)}x, ${face} face`, async ({ page }) => {
    if (size !== 1) {
      await page.addInitScript((factor) => {
        document.addEventListener('DOMContentLoaded', () => {
          document.documentElement.style.fontSize = `${16 * factor}px`
        })
      }, size)
    }
    await openTheScreen(page)
    if (face === 'wide') await page.addStyleTag({ content: WIDE_FACE })
    const hosts = page.getByTestId('devices-host')
    await expect(hosts).toHaveCount(3)
    // Every standing is said in its row, and none is called revoked but the one the host acknowledged.
    await expect(page.getByTestId('devices-device').filter({ hasText: 'the-tablet' })).toContainText('Sent')
    await expect(page.getByTestId('devices-device').filter({ hasText: 'the-watch' })).toContainText('Acknowledged')
    await expect(page.getByTestId('devices-device').filter({ hasText: 'the-laptop' })).toContainText('Revoked')
    await expect(page.getByTestId('devices-device').filter({ hasText: 'the-old-phone' })).toContainText('Refused')
    expect(await overrunning(page, '[data-testid="devices-host"]')).toEqual([])
    // Every control is inside its card, and no smaller than a pointer needs.
    const controls = await hosts.getByRole('button').evaluateAll((buttons) =>
      buttons.map((each) => {
        const box = each.getBoundingClientRect()
        const edge = each.closest('[data-testid="devices-host"]')?.getBoundingClientRect()
        return {
          name: each.getAttribute('aria-label') ?? each.textContent,
          inside: edge !== undefined && box.left >= edge.left && box.right <= edge.right,
          tall: box.height
        }
      })
    )
    expect(controls.length).toBeGreaterThan(2)
    for (const control of controls) {
      expect(control.inside, `${control.name ?? ''} lies inside the card`).toBe(true)
      expect(control.tall, `${control.name ?? ''} is tall enough to press`).toBeGreaterThanOrEqual(24)
    }
    await photograph(page, page.locator('main'), shot(`${size.toFixed(1)}x-${face}`))
  })
}

test('offers nothing for a host the feed removed, and nothing for this computer', async ({ page }) => {
  await openTheScreen(page)
  const attic = page.getByTestId('devices-host').filter({ hasText: 'the-attic' })
  await expect(attic.getByRole('button')).toHaveCount(0)
  const studio = page.getByTestId('devices-host').filter({ hasText: LONG_NAME }).first()
  await expect(studio.getByTestId('devices-device').filter({ hasText: 'this-mac' }).getByRole('button')).toHaveCount(0)
})

test('revokes a device from the keyboard alone, and focus goes to where the request stands', async ({ page }) => {
  await openTheScreen(page)
  const row = page.getByTestId('devices-device').filter({ hasText: `${LONG_NAME}-phone` })
  const button = row.getByRole('button', { name: new RegExp(`^Revoke ${LONG_NAME}-phone on ${LONG_NAME} with Touch ID$`) })
  // WebKit on macOS passes over buttons unless the system's keyboard setting asks for them, so the
  // button is focused directly and the key that presses it is what the case holds to.
  await button.focus()
  await expect(button).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(row.getByTestId('devices-standing')).toBeFocused()
  await expect(row).toContainText('has not acknowledged it yet')
  await expect(row.getByRole('button')).toHaveCount(0)
  await expect
    .poll(() => page.evaluate(() => window.krTestHost?.revocation.asked))
    .toEqual(['studio a'])
  // The host's acknowledgement arrives on the next look, and the live region says it.
  await page.evaluate(() => {
    window.krTestHost?.revocation.stand('studio', 'a', { state: 'done', at_ms: Date.now() })
  })
  await page.getByTestId('devices-refresh').click()
  await expect(row).toContainText('Revoked')
  await expect(page.getByTestId('devices-heard')).toContainText('is revoked')
})

test('changes its words by fading and never by travelling, with or without reduced motion', async ({ page }) => {
  for (const reducedMotion of ['no-preference', 'reduce'] as const) {
    await page.emulateMedia({ reducedMotion })
    await openTheScreen(page)
    const standing = page.getByTestId('devices-standing').first()
    await expect(standing).toBeVisible()
    const moved = await standing.evaluate((each) => getComputedStyle(each).transitionProperty)
    expect(moved, `${reducedMotion}: only the opacity of the words changes over time`).toBe('opacity')
  }
})
