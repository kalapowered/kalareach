/**
 * Deleting the account, in a real browser engine.
 *
 * What a component test cannot hold is layout and motion: that no step is cut at the default text
 * size or the largest, on the desktop's sheet or the phone's screen, that every control is as large
 * as its surface asks, that a change of step is a fade and nothing travels, and that reduced motion
 * leaves the fade alone. The steps are reached the way a person reaches them, through the fake host
 * the harness serves, scripted with the service's answers.
 *
 * Every screenshot goes under the test artefact directory, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  outcome: null
} as const

const OWNED = {
  organisation_id: 'org-1',
  name: 'A very long organisation name that has no place to break except where the card ends',
  members: 4
} as const

function shot(name: string): string {
  return screenshotPath(`kr-companion-account-delete-${name}-${test.info().project.name}`)
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

/** Waits for the step's fade to end, so a screenshot shows what a person settles on. */
async function settled(page: Page): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().every((each) => each.playState !== 'running'))
}

/** Opens the harness signed in and shows the Account panel. */
async function atTheAccount(page: Page, surface: 'desktop' | 'ios', size: number) {
  if (surface === 'ios') {
    await page.setViewportSize({ width: 390, height: 844 })
    await withTextScale(page, size)
  } else if (size !== 1) {
    await page.addInitScript((factor) => {
      document.addEventListener('DOMContentLoaded', () => {
        document.documentElement.style.fontSize = `${16 * factor}px`
      })
    }, size)
  }
  await page.goto(surface === 'ios' ? '/harness.html?surface=ios' : '/harness.html')
  await page.waitForSelector(surface === 'ios' ? '.m-shell' : '.app-shell')
  await page.evaluate((view) => {
    window.krTestHost?.account.set(view)
    window.krTestHost?.account.deletion.answerView({
      state: 'ready',
      preview: {
        address: 's***@example.com',
        warnings: [
          { kind: 'organisation_owner', ...{ organisation_id: 'org-1', name: 'Acme', members: 4 } },
          { kind: 'subscription' },
          { kind: 'credit' },
          { kind: 'money_owed' }
        ],
        deleted: [
          'sign_ins',
          'passkeys_and_address',
          'backup_records',
          'recovery_bundle',
          'relay_and_voice_ended',
          'payment_record',
          'organisation_memberships',
          'device_registrations'
        ],
        kept: [
          'billing_records',
          'relay_records',
          'call_records',
          'reasoning_records',
          'backup_index_rows',
          'organisation_records',
          'device_records',
          'recovery_copies',
          'other_services'
        ],
        unlisted: false,
        kept_records_years: 7,
        backup_file_days: 7,
        code_lifetime_minutes: 5
      }
    })
  }, SIGNED_IN)
  const account =
    surface === 'ios'
      ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
      : page.getByRole('button', { name: /^Account/ })
  await account.click()
  return surface === 'ios' ? page.getByTestId('mobile-account') : page.getByRole('dialog', { name: 'Account' })
}

for (const [surface, size] of [
  ['desktop', 1],
  ['desktop', 2],
  ['ios', 1],
  ['ios', LARGEST]
] as const) {
  test(`shows every step whole, ${surface}, text ${size.toFixed(1)}x`, async ({ page }) => {
    const panel = await atTheAccount(page, surface, size)
    const minimum = 44

    await panel.getByTestId('delete-account-open').click()
    const card = panel.getByTestId('delete-account')
    await expect(panel.getByTestId('delete-account-before')).toBeVisible()
    // The panel's other cards are gone from the page, not drawn behind the step.
    await expect(panel.getByText('Working without an account')).toBeHidden()
    expect(await overrunning(page, '[data-testid="delete-account"]')).toEqual([])
    await settled(page)
    await page.screenshot({ path: shot(`read-${surface}-${size.toFixed(1)}`), fullPage: true })

    const sizes = async (ids: string[]) => {
      for (const id of ids) {
        const box = await panel.getByTestId(id).boundingBox()
        expect(box?.height ?? 0, id).toBeGreaterThanOrEqual(minimum - 1)
      }
    }
    await sizes(['delete-account-send-code', 'delete-account-cancel'])

    await panel.getByTestId('delete-account-send-code').click()
    const field = panel.getByTestId('delete-account-code')
    await expect(field).toBeFocused()
    expect(await overrunning(page, '[data-testid="delete-account"]')).toEqual([])
    await sizes(['delete-account-code', 'delete-account-confirm', 'delete-account-resend'])
    await settled(page)
    await page.screenshot({ path: shot(`code-${surface}-${size.toFixed(1)}`), fullPage: true })

    // A confirmation whose answer is lost is told as not known, with its way out; it is whole at
    // every size.
    await page.evaluate(() => {
      window.krTestHost?.account.deletion.answerConfirm({ state: 'unsettled' })
    })
    await field.fill('12345678')
    await panel.getByTestId('delete-account-confirm').click()
    await expect(panel.getByTestId('delete-account-check')).toBeVisible()
    expect(await overrunning(page, '[data-testid="delete-account"]')).toEqual([])
    await sizes(['delete-account-check', 'delete-account-again', 'delete-account-close'])
    await settled(page)
    await page.screenshot({ path: shot(`unsettled-${surface}-${size.toFixed(1)}`), fullPage: true })
    await panel.getByTestId('delete-account-close').click()
    await expect(panel.getByTestId('delete-account-open')).toBeVisible()
    await panel.getByTestId('delete-account-open').click()
    await expect(panel.getByTestId('delete-account-send-code')).toBeVisible()
    await panel.getByTestId('delete-account-send-code').click()
    await expect(field).toBeFocused()

    await page.evaluate((owned) => {
      window.krTestHost?.account.deletion.answerConfirm(
        { state: 'acknowledge', organisations: [owned] },
        { state: 'closed', finished: false }
      )
    }, OWNED)
    await field.fill('12345678')
    await panel.getByTestId('delete-account-confirm').click()
    await expect(panel.getByTestId('delete-account-organisations')).toBeVisible()
    expect(await overrunning(page, '[data-testid="delete-account"]')).toEqual([])
    await settled(page)
    await page.screenshot({ path: shot(`acknowledge-${surface}-${size.toFixed(1)}`), fullPage: true })

    await panel.getByTestId('delete-account-acknowledge').click()
    await expect(panel.getByTestId('delete-account-done')).toBeVisible()
    expect(await overrunning(page, '[data-testid="delete-account"]')).toEqual([])
    await settled(page)
    await page.screenshot({ path: shot(`result-${surface}-${size.toFixed(1)}`), fullPage: true })
    await expect(card).toHaveAttribute('data-step', 'result')

    await panel.getByTestId('delete-account-done').click()
    await expect(panel.getByRole('button', { name: 'Sign in' })).toBeVisible()
  })
}

test('a change of step is a fade that travels nowhere, and reduced motion leaves it alone', async ({
  page
}) => {
  const panel = await atTheAccount(page, 'ios', 1)
  await panel.getByTestId('delete-account-open').click()
  await expect(panel.getByTestId('delete-account-before')).toBeVisible()
  const state = panel.getByTestId('delete-account').locator('.account-state')
  for (const reduced of [false, true]) {
    await page.emulateMedia({ reducedMotion: reduced ? 'reduce' : 'no-preference' })
    const kinds = await state.evaluate((element) => {
      const style = getComputedStyle(element)
      return {
        properties: style.transitionProperty,
        transform: style.transform
      }
    })
    expect(kinds.properties).toBe('opacity')
    expect(kinds.transform).toBe('none')
  }
})
