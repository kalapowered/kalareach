/**
 * The settings saved with the recovery bundle, in a real browser engine: where they stand in the
 * recovery card, the button that turns saving back on, the card that restores them with the kit,
 * and that none of it is drawn past the sheet. The backend is the scripted host the harness serves.
 *
 * Every screenshot goes under the test artefact directory, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  mark: 'ab'.repeat(32),
  outcome: null
} as const

function shot(name: string): string {
  return screenshotPath(`kr-companion-recovery-settings-${name}-${test.info().project.name}`)
}

/** Opens the harness signed in, with recovery as `state` says, and shows the Account sheet. */
async function atTheAccount(page: Page, state: 'off' | 'stopped' | 'not_saved') {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.evaluate((view) => {
    window.krTestHost?.account.set(view)
  }, SIGNED_IN)
  if (state !== 'off') {
    await page.evaluate((line) => {
      window.krTestHost?.recovery.set({ state: 'on', kept_at: 'reach.kala.to', settings: line })
    }, state === 'stopped' ? ({ state: 'stopped' } as const) : ({ state: 'not_saved', why: 'bundle' } as const))
  }
  await page.getByRole('button', { name: /^Account/ }).click()
  return page.getByRole('dialog', { name: 'Account' })
}

test.describe('the settings saved with the recovery bundle', () => {
  test('say where they stand, and "Save them again" turns saving back on', async ({ page }) => {
    const sheet = await atTheAccount(page, 'stopped')
    const line = sheet.getByTestId('recovery-settings')
    await expect(line).toHaveText('Saving settings with your recovery bundle is off.')
    expect(await overrunning(page, '[role="dialog"]')).toEqual([])
    await page.screenshot({ path: shot('stopped'), fullPage: true })

    await sheet.getByRole('button', { name: 'Save them again' }).click()
    await expect(line).toHaveCount(0)
    expect(await page.evaluate(() => window.krTestHost?.recovery.settingsResumed)).toBe(1)
  })

  test('a reason that is long is said in full inside the sheet', async ({ page }) => {
    const sheet = await atTheAccount(page, 'not_saved')
    await expect(sheet.getByTestId('recovery-settings')).toHaveText(
      "Settings are not saved yet: the recovery bundle at the service does not open with this device's seed."
    )
    expect(await overrunning(page, '[role="dialog"]')).toEqual([])
    await page.screenshot({ path: shot('not-saved'), fullPage: true })
  })
})

test.describe('restoring the settings with the kit', () => {
  test('is offered where recovery is off, asks for the account or the file, and says what came of it', async ({
    page
  }) => {
    const sheet = await atTheAccount(page, 'off')
    const card = sheet.getByTestId('recovery-restore')
    await expect(card).toContainText('Choose the recovery kit you saved.')
    await expect(card.getByLabel('From my account')).toBeChecked()
    expect(await overrunning(page, '[role="dialog"]')).toEqual([])
    await page.screenshot({ path: shot('restore'), fullPage: true })

    await page.evaluate(() => {
      window.krTestHost?.recovery.restoreAnswers({ state: 'already_chosen' })
    })
    await card.getByLabel('From an exported bundle file').check()
    await card.getByRole('button', { name: 'Choose kit and restore' }).click()
    await expect(card.getByTestId('recovery-restore-said')).toContainText(
      'This device already has settings of its own, so nothing was replaced.'
    )
    expect(await page.evaluate(() => window.krTestHost?.recovery.restoresAsked)).toEqual([
      { fromFile: true }
    ])
    expect(await overrunning(page, '[role="dialog"]')).toEqual([])
    await page.screenshot({ path: shot('restore-said'), fullPage: true })
  })
})
