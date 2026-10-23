/**
 * A paired host's notifications on the Hosts screen of a phone, in both engines the page runs in,
 * whole at the default text size and at the largest, on a screen 320 points wide: what each state
 * says, the one thing the person can do about it a finger tall, and nothing running past the screen.
 *
 * The scripted host stands in for native code and says where notifications stand, as the address
 * asks (`push=working`, `push=stopped`, `push=unreachable`, `push=on`; none is off). The steps native
 * code takes behind the row are proved on the phones themselves, in `scripts/e2e-push-device.sh`.
 */

import { expect, test } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** What a finger needs to hit, in points on iOS and density-independent pixels on Android. */
const TARGET = { ios: 44, android: 48 } as const

const STATES = [
  { name: 'off', query: '', words: 'Notifications are off.', actions: ['Turn on notifications'] },
  { name: 'working', query: '&push=working', words: 'Waiting for the notification service.', actions: [] },
  { name: 'on', query: '&push=on', words: 'Notifications are on.', actions: [] },
  {
    name: 'stopped',
    query: '&push=stopped',
    words: 'Notifications are off for this app.',
    actions: ['Try again', 'Open settings']
  },
  {
    name: 'unreachable',
    query: '&push=unreachable',
    words: 'The notification service could not be reached.',
    actions: ['Try again']
  }
] as const

for (const surface of ['ios', 'android'] as const) {
  for (const [size, ratio] of [
    ['the default text size', 1],
    ['the largest text size', LARGEST]
  ] as const) {
    const label = `${surface}-${ratio === 1 ? 'default' : 'largest'}`
    for (const state of STATES) {
      test(`says notifications are ${state.name} on ${surface} at ${size}, with nothing past the screen`, async ({
        page
      }) => {
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
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=hosts&paired=studio${state.query}`)
        const row = page.getByTestId('host-notifications')
        await expect(row).toBeVisible()
        await expect(row.getByTestId('notifications-words')).toContainText(state.words)
        // The one thing the person can do is a button a finger tall, and a state with nothing to do
        // offers no button.
        const buttons = row.getByRole('button')
        await expect(buttons).toHaveCount(state.actions.length)
        for (const name of state.actions) {
          const button = row.getByRole('button', { name, exact: true })
          await expect(button).toBeVisible()
          const box = await button.boundingBox()
          expect(box?.height ?? 0, `${name} is a finger tall`).toBeGreaterThanOrEqual(TARGET[surface] - 1)
        }
        await row.screenshot({
          path: screenshotPath(`kr-push-notifications-${state.name}-${label}-${test.info().project.name}`)
        })
        expect(await overrunning(page, '[data-testid="host-notifications"]'), 'nothing runs past the screen').toEqual([])
      })
    }
  }
}
