/**
 * The phone's composer carries the desktop composer's controls (KR-REQ-13.12): the agent's slash
 * commands, and Interrupt, Steer and Queue, each a touch target the screen holds, in a real engine
 * and at the sizes of an iPhone and of an Android phone, the narrowest of them included.
 *
 * The scripted host's agent is running a turn, which is what offers Steer and Interrupt.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The phone sizes: both platforms at a common size and at their narrowest and shortest. */
const PHONES = [
  { surface: 'ios', label: 'iOS 390 by 844', width: 390, height: 844, target: 44 },
  { surface: 'ios', label: 'iOS 320 by 568', width: 320, height: 568, target: 44 },
  { surface: 'android', label: 'Android 360 by 800', width: 360, height: 800, target: 48 },
  { surface: 'android', label: 'Android 320 by 640', width: 320, height: 640, target: 48 }
] as const

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return screenshotPath(`kr-companion-phone-composer-${name}-${test.info().project.name}`)
}

/** Opens the session on the phone and waits until the agent has been read: its controls are there. */
async function openSession(page: Page, phone: (typeof PHONES)[number]): Promise<void> {
  await page.setViewportSize({ width: phone.width, height: phone.height })
  await page.goto(`/harness.html?surface=${phone.surface}&session=${SESSION}`)
  await expect(page.getByTestId('composer-interrupt')).toBeVisible()
}

/** Whether a control is a touch target of the platform's size, inside the window's width. */
async function expectTouchTarget(control: Locator, target: number, width: number): Promise<void> {
  await control.scrollIntoViewIfNeeded()
  const box = await control.boundingBox()
  expect(box, 'the control has a box').not.toBeNull()
  expect(box?.height ?? 0).toBeGreaterThanOrEqual(target - 0.5)
  expect(box?.width ?? 0).toBeGreaterThanOrEqual(target - 0.5)
  expect(box?.x ?? -1).toBeGreaterThanOrEqual(-0.5)
  expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(width + 0.5)
}

for (const phone of PHONES) {
  test.describe(`the phone's composer on ${phone.label}`, () => {
    test.beforeEach(async ({ page }) => {
      await openSession(page, phone)
    })

    test('lists the commands the agent advertises under the field, each a touch target, and the chosen one goes in the field', async ({
      page
    }) => {
      const field = page.getByLabel('Message this session')
      await field.fill('/')
      const list = page.getByTestId('slash-commands')
      await expect(list).toBeVisible()
      const commands = list.getByRole('button')
      await expect(commands).toHaveCount(3)
      for (const command of await commands.all()) {
        await expectTouchTarget(command, phone.target, phone.width)
      }
      expect(await overrunning(page, '[data-testid="slash-commands"]'), 'what runs past the window').toEqual([])
      await page.screenshot({ path: shot(`slash-${phone.surface}-${phone.width}`) })

      await field.fill('/re')
      await expect(commands).toHaveCount(1)
      await commands.first().click()
      await expect(field).toHaveValue('/review ')
      await expect(list).toBeHidden()
    })

    test('shows Interrupt, Steer and Queue with Send, each a touch target inside the window', async ({ page }) => {
      await page.getByLabel('Message this session').fill('use the other file')
      const controls = [
        page.getByTestId('composer-interrupt'),
        page.getByTestId('composer-steer'),
        page.getByTestId('composer-queue'),
        page.getByRole('button', { name: 'Send' })
      ]
      for (const control of controls) {
        await expect(control).toBeVisible()
        await expect(control).toBeEnabled()
        await expectTouchTarget(control, phone.target, phone.width)
      }
      expect(await overrunning(page, '.m-composer'), 'what runs past the window or its box').toEqual([])
      await page.screenshot({ path: shot(`actions-${phone.surface}-${phone.width}`) })
    })

    test('queues what was written and clears the field, as Send does', async ({ page }) => {
      const field = page.getByLabel('Message this session')
      await field.fill('then run the linter')
      await page.getByTestId('composer-queue').click()
      await expect(field).toHaveValue('')
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
    })

    test('steers the running turn with what was written and leaves it in the field', async ({ page }) => {
      const field = page.getByLabel('Message this session')
      await field.fill('use the other file')
      await page.getByTestId('composer-steer').click()
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
      await expect(field).toHaveValue('use the other file')
    })

    test('is one line under the terminal, with Send and Interrupt a touch target each inside the window', async ({
      page
    }) => {
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await page.getByLabel('Message this session').fill('ls')
      // The terminal keeps all the room above the line: Steer and Queue are the conversation's.
      await expect(page.getByTestId('composer-steer')).toHaveCount(0)
      await expect(page.getByTestId('composer-queue')).toHaveCount(0)
      const interrupt = page.getByTestId('composer-interrupt')
      await expect(interrupt).toBeVisible()
      for (const control of [interrupt, page.getByRole('button', { name: 'Send' })]) {
        await expectTouchTarget(control, phone.target, phone.width)
      }
      expect(await overrunning(page, '.m-composer-line'), 'what runs past the window or its box').toEqual([])
      await page.screenshot({ path: shot(`terminal-${phone.surface}-${phone.width}`) })

      await interrupt.click()
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
    })

    test('interrupts the running turn, after which the turn controls are gone', async ({ page }) => {
      await page.getByTestId('composer-interrupt').click()
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
      await expect(page.getByTestId('composer-interrupt')).toBeHidden()
      await expect(page.getByTestId('composer-steer')).toBeHidden()
      await expect(page.getByTestId('composer-queue')).toBeVisible()
    })
  })
}
