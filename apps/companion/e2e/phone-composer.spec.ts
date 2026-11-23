/**
 * The phone's composer carries the desktop composer's controls (KR-REQ-13.12): the agent's slash
 * commands, and Interrupt, Steer and Queue, each a touch target the screen holds, in a real engine
 * and at the sizes of an iPhone and of an Android phone, the narrowest of them included.
 *
 * The scripted host's agent is running a turn, which is what offers Steer and Interrupt. A case
 * waits only for the conversation, so that at a build without the controls each case fails at its
 * own assertion and not in the set-up they share.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

// A control that is not there fails its case at once, at the line that asks for it.
test.use({ actionTimeout: 5_000 })

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The phone sizes: both platforms at a common size and at their narrowest and shortest. */
const PHONES = [
  { surface: 'ios', label: 'iOS 390 by 844', width: 390, height: 844, target: 44, keyboard: 336 },
  { surface: 'ios', label: 'iOS 320 by 568', width: 320, height: 568, target: 44, keyboard: 260 },
  { surface: 'android', label: 'Android 360 by 800', width: 360, height: 800, target: 48, keyboard: 320 },
  { surface: 'android', label: 'Android 320 by 640', width: 320, height: 640, target: 48, keyboard: 260 }
] as const

type Phone = (typeof PHONES)[number]

/** A window that holds the session too short for the whole composer: the composer is its line. */
const SHORT = { height: 480 } as const

/** A window tall enough for the whole composer at every width, the shortest phone's included. */
const TALL = { height: 900 } as const

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return screenshotPath(`kr-companion-phone-composer-${name}-${test.info().project.name}`)
}

/** Opens the session on the phone and waits for its conversation, which is read with its agent. */
async function openSession(page: Page, phone: Phone): Promise<void> {
  await page.setViewportSize({ width: phone.width, height: phone.height })
  await page.goto(`/harness.html?surface=${phone.surface}&session=${SESSION}`)
  await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
  await expect(page.getByLabel('Message this session')).toBeVisible()
}

/** Covers the bottom `inset` pixels of the screen, as a software keyboard does. */
async function keyboard(page: Page, inset: number): Promise<void> {
  await page.evaluate((covered) => {
    document.documentElement.style.setProperty('--keyboard', `${covered}px`)
  }, inset)
}

/**
 * How many pixels of each control lie outside what a person sees of it: past the window, behind a
 * keyboard that covers `covered` pixels, or outside a box around it that clips what it holds. It is
 * read once the layout is steady: every control's box and the pixels it lacks have been the same
 * over two frames in a row, and for longer than the session takes to settle after a keyboard
 * (`SETTLE_MS`, 150 ms, in the view), which moves the field again once nothing has changed for that
 * long. A reading taken at the first moment it passes would be one the layout leaves a moment later.
 */
async function hiddenOf(page: Page, controls: readonly Locator[], covered = 0): Promise<number[]> {
  const nodes = await Promise.all(controls.map((control) => control.elementHandle()))
  return page.evaluate(
    ({ elements, inset, still }) =>
      new Promise<number[]>((resolve, reject) => {
        const outside = (node: Element): number => {
          const box = node.getBoundingClientRect()
          let top = 0
          let bottom = window.innerHeight - inset
          let left = 0
          let right = window.innerWidth
          for (let around = node.parentElement; around !== null; around = around.parentElement) {
            const style = getComputedStyle(around)
            if (style.overflowY === 'visible' && style.overflowX === 'visible') continue
            const clip = around.getBoundingClientRect()
            top = Math.max(top, clip.top)
            bottom = Math.min(bottom, clip.bottom)
            left = Math.max(left, clip.left)
            right = Math.min(right, clip.right)
          }
          const lacking =
            Math.max(0, top - box.top) +
            Math.max(0, box.bottom - bottom) +
            Math.max(0, left - box.left) +
            Math.max(0, box.right - right)
          return Math.round(lacking * 10) / 10
        }
        const read = () =>
          elements.map((node) => {
            const box = node.getBoundingClientRect()
            return [box.top, box.bottom, box.left, box.right, outside(node)].join(',')
          })
        const begun = performance.now()
        let last = read().join('|')
        let changedAt = begun
        let framesSame = 0
        const frame = () => {
          const now = read().join('|')
          if (now === last) framesSame += 1
          else {
            last = now
            framesSame = 0
            changedAt = performance.now()
          }
          if (framesSame >= 2 && performance.now() - changedAt >= still) {
            resolve(elements.map(outside))
          } else if (performance.now() - begun > 4_000) {
            reject(new Error('the layout did not become steady within four seconds'))
          } else {
            requestAnimationFrame(frame)
          }
        }
        requestAnimationFrame(frame)
      }),
    { elements: nodes, inset: covered, still: SETTLE_MS + 50 }
  )
}

/**
 * The most a control may lack of being whole in view: 1 px, which nobody sees of a 44 px target.
 *
 * What lacks it is the field, above a keyboard, and nothing else; every button stands whole to the
 * pixel. The view rests the field on the keyboard's top edge and leaves it within half a pixel of
 * it (`TOLERANCE` in `keyboard.ts`): 0.3 to 0.4 px is what 360 by 800 and 320 by 640 show. At 320 by
 * 568 in WebKit it is 0.94 px, and that is not the tolerance: the field's edge falls at a fraction
 * of a pixel (the bar under the session is 85.5 px), WebKit keeps a scroll position in whole pixels
 * and leaves 36 of the 36.94 it is given (Chromium rounds to 37, and lacks 0.06 px), and the lift
 * that would close the rest cannot raise the field, because the conversation is at its floor of
 * three lines: the page grows by what is added instead, which the view's four passes confirm.
 */
const SHORT_OF_VIEW = 1

/** The longest the view waits after a change of the keyboard before it works out the field's rest again. */
const SETTLE_MS = 150

/** Whether a control is a touch target of the platform's size, as it stands, with no scrolling to it. */
async function expectTouchTarget(control: Locator, target: number): Promise<void> {
  const box = await control.boundingBox()
  expect(box, 'the control has a box').not.toBeNull()
  expect(box?.height ?? 0).toBeGreaterThanOrEqual(target - 0.5)
  expect(box?.width ?? 0).toBeGreaterThanOrEqual(target - 0.5)
}

/** Whether every one of `controls` stands whole in what a person sees, none scrolled to, all at once. */
async function expectInView(page: Page, controls: readonly Locator[], covered = 0): Promise<void> {
  for (const control of controls) await expect(control).toBeVisible()
  const lacking = await hiddenOf(page, controls, covered)
  controls.forEach((control, index) => {
    expect(lacking[index], `pixels of ${String(control)} that a person does not see`).toBeLessThanOrEqual(SHORT_OF_VIEW)
  })
}

/**
 * Whether the field stands in view and every command of the list can be reached: whole in view as
 * the screen lies, or, where the list holds more than the room it has, brought into view by scrolling
 * the list, with the field still in view beside it.
 */
async function expectCommandsReachable(page: Page, phone: Phone, covered = 0): Promise<void> {
  const field = page.getByLabel('Message this session')
  const list = page.getByTestId('slash-commands')
  const commands = list.getByRole('button')
  await expect(commands).toHaveCount(THREE_COMMANDS)
  await expectInView(page, [field], covered)
  for (let index = 0; index < THREE_COMMANDS; index += 1) {
    const command = commands.nth(index)
    await expectTouchTarget(command, phone.target)
    const [lacking] = await hiddenOf(page, [command], covered)
    if ((lacking ?? 0) > SHORT_OF_VIEW) {
      // The list is what scrolls, as a finger scrolls it: a deliberate scroll of it brings the command
      // in, and the field stays in view with it.
      expect(await list.evaluate((node) => getComputedStyle(node).overflowY), 'how the list scrolls').toMatch(
        /^(auto|scroll)$/
      )
      await command.scrollIntoViewIfNeeded()
    }
    await expectInView(page, [field, command], covered)
  }
}

/** What the scripted host's agent advertises for a draft that is only a slash. */
const THREE_COMMANDS = 3

/** The vertical middle of an element. */
async function middle(element: Locator): Promise<number> {
  const box = await element.boundingBox()
  return (box?.y ?? Number.NaN) + (box?.height ?? Number.NaN) / 2
}

for (const phone of PHONES) {
  test.describe(`the phone's composer on ${phone.label}`, () => {
    test.beforeEach(async ({ page }) => {
      await openSession(page, phone)
    })

    test('lists the commands the agent advertises, each a touch target in view, and the chosen one goes in the field', async ({
      page
    }) => {
      const field = page.getByLabel('Message this session')
      await field.fill('/re')
      const list = page.getByTestId('slash-commands')
      await expect(list).toBeVisible()
      const commands = list.getByRole('button')
      await expect(commands).toHaveCount(1)
      await expectTouchTarget(commands.first(), phone.target)
      await expectInView(page, [field, commands.first()])
      expect(await overrunning(page, '[data-testid="slash-commands"]'), 'what runs past the window').toEqual([])
      await page.screenshot({ path: shot(`slash-${phone.surface}-${phone.width}`) })

      await commands.first().click()
      await expect(field).toHaveValue('/review ')
      await expect(list).toBeHidden()
      // The field keeps the focus, so the person goes on typing what the command takes.
      await expect(field).toBeFocused()
    })

    test('keeps the field and the commands in view above a keyboard, where the room is smallest', async ({ page }) => {
      const field = page.getByLabel('Message this session')
      await field.focus()
      await keyboard(page, phone.keyboard)
      await field.fill('/re')
      const command = page.getByTestId('slash-commands').getByRole('button')
      await expect(command).toHaveCount(1)
      await expectInView(page, [field, command.first()], phone.keyboard)
      await page.screenshot({ path: shot(`slash-keyboard-${phone.surface}-${phone.width}`) })
    })

    test('keeps the field and the commands in view on a window too short for the whole composer', async ({ page }) => {
      await page.setViewportSize({ width: phone.width, height: SHORT.height })
      await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'line')
      const field = page.getByLabel('Message this session')
      await field.fill('/re')
      const command = page.getByTestId('slash-commands').getByRole('button')
      await expect(command).toHaveCount(1)
      await expectInView(page, [field, command.first()])
      await page.screenshot({ path: shot(`slash-short-${phone.surface}-${phone.width}`) })
    })

    test('keeps the field and the commands in view under the terminal', async ({ page }) => {
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      const field = page.getByLabel('Message this session')
      await field.fill('/re')
      const command = page.getByTestId('slash-commands').getByRole('button')
      await expect(command).toHaveCount(1)
      await expectInView(page, [field, command.first()])
      await keyboard(page, phone.keyboard)
      await expectInView(page, [field, command.first()], phone.keyboard)
      await page.screenshot({ path: shot(`slash-terminal-${phone.surface}-${phone.width}`) })
    })

    test('keeps the field in view and every one of the three commands reachable above a keyboard', async ({ page }) => {
      const field = page.getByLabel('Message this session')
      await field.focus()
      await keyboard(page, phone.keyboard)
      await field.fill('/')
      await expectCommandsReachable(page, phone, phone.keyboard)
      await page.screenshot({ path: shot(`slash-all-keyboard-${phone.surface}-${phone.width}`) })
    })

    test('keeps the field in view and every one of the three commands reachable on a window too short for the whole composer', async ({
      page
    }) => {
      await page.setViewportSize({ width: phone.width, height: SHORT.height })
      await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'line')
      await page.getByLabel('Message this session').fill('/')
      await expectCommandsReachable(page, phone)
      await page.screenshot({ path: shot(`slash-all-short-${phone.surface}-${phone.width}`) })
    })

    test('keeps the field in view and every one of the three commands reachable under the terminal', async ({ page }) => {
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await page.getByLabel('Message this session').fill('/')
      await expectCommandsReachable(page, phone)
      await keyboard(page, phone.keyboard)
      await expectCommandsReachable(page, phone, phone.keyboard)
      await page.screenshot({ path: shot(`slash-all-terminal-${phone.surface}-${phone.width}`) })
    })

    test('shows Interrupt, Steer and Queue with Send, each a touch target', async ({ page }) => {
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
        await expectTouchTarget(control, phone.target)
        const box = await control.boundingBox()
        expect(box?.x ?? -1).toBeGreaterThanOrEqual(-0.5)
        expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(phone.width + 0.5)
      }
      // The field, Send and the three actions stand in view together as the composer lies at rest:
      // nothing is scrolled to.
      await expectInView(page, [page.getByLabel('Message this session'), ...controls])
      expect(await overrunning(page, '.m-composer'), 'what runs past the window or its box').toEqual([])
      await page.screenshot({ path: shot(`actions-${phone.surface}-${phone.width}`) })
    })

    test('shows the three actions above the line, in view, on a window too short for the whole composer', async ({
      page
    }) => {
      await page.setViewportSize({ width: phone.width, height: SHORT.height })
      await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'line')
      await page.getByLabel('Message this session').fill('use the other file')
      const row = page.locator('.m-composer-more')
      await expect(row).toBeVisible()
      const controls = [
        page.getByTestId('composer-interrupt'),
        page.getByTestId('composer-steer'),
        page.getByTestId('composer-queue')
      ]
      for (const control of controls) {
        await expect(row.locator(`[data-testid="${await control.getAttribute('data-testid')}"]`)).toBeVisible()
        await expectTouchTarget(control, phone.target)
      }
      // They stand above the line that holds the field and Send, and all five stand in view at once
      // as the composer lies at rest: nothing is scrolled to.
      const rowBox = await row.boundingBox()
      const lineBox = await page.locator('.m-composer-line').boundingBox()
      expect((rowBox?.y ?? 0) + (rowBox?.height ?? 0)).toBeLessThanOrEqual((lineBox?.y ?? 0) + 0.5)
      await expectInView(page, [
        page.getByLabel('Message this session'),
        page.getByRole('button', { name: 'Send' }),
        ...controls
      ])
      await page.screenshot({ path: shot(`short-${phone.surface}-${phone.width}`) })
    })

    test('is one line under the terminal: the field, Send and Interrupt side by side, all in view at once', async ({
      page
    }) => {
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      const field = page.getByLabel('Message this session')
      await field.fill('ls')
      // The terminal keeps all the room above the line: Steer and Queue are the conversation's.
      await expect(page.getByTestId('composer-steer')).toHaveCount(0)
      await expect(page.getByTestId('composer-queue')).toHaveCount(0)
      const send = page.getByRole('button', { name: 'Send' })
      const interrupt = page.getByTestId('composer-interrupt')
      await expectInView(page, [field, send, interrupt])
      for (const control of [send, interrupt]) await expectTouchTarget(control, phone.target)
      // One row: the three share a middle, to the pixel, and Send comes before Interrupt.
      const middles = [await middle(field), await middle(send), await middle(interrupt)]
      expect(Math.max(...middles) - Math.min(...middles), 'the spread of the three middles').toBeLessThanOrEqual(1)
      const sendBox = await send.boundingBox()
      const interruptBox = await interrupt.boundingBox()
      expect((sendBox?.x ?? 0) + (sendBox?.width ?? 0)).toBeLessThanOrEqual((interruptBox?.x ?? 0) + 0.5)
      expect(await overrunning(page, '.m-composer-line'), 'what runs past the window or its box').toEqual([])
      await keyboard(page, phone.keyboard)
      await expectInView(page, [field, send, interrupt], phone.keyboard)
      await page.screenshot({ path: shot(`terminal-${phone.surface}-${phone.width}`) })
      await keyboard(page, 0)

      await interrupt.click()
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
    })

    test('keeps the focus on an action when the composer changes form', async ({ page }) => {
      await page.setViewportSize({ width: phone.width, height: TALL.height })
      await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'whole')
      await page.getByLabel('Message this session').fill('use the other file')
      for (const id of ['composer-interrupt', 'composer-steer', 'composer-queue']) {
        await page.getByTestId(id).focus()
        await expect(page.getByTestId(id)).toBeFocused()
        // The window grows short and the composer becomes its line, which moves the action to a row
        // of its own above it; then it grows tall and the action goes back among the others.
        await page.setViewportSize({ width: phone.width, height: SHORT.height })
        await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'line')
        await expect(page.getByTestId(id), `${id} after the window became short`).toBeFocused()
        await page.setViewportSize({ width: phone.width, height: TALL.height })
        await expect(page.locator('.m-session')).toHaveAttribute('data-composer', 'whole')
        await expect(page.getByTestId(id), `${id} after the window grew tall`).toBeFocused()
      }
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

    test('interrupts the running turn, after which the turn controls are gone', async ({ page }) => {
      await page.getByTestId('composer-interrupt').click()
      await expect(page.locator('.m-composer').getByText('Applied')).toBeVisible()
      await expect(page.getByTestId('composer-interrupt')).toBeHidden()
      await expect(page.getByTestId('composer-steer')).toBeHidden()
      await expect(page.getByTestId('composer-queue')).toBeVisible()
    })
  })
}
