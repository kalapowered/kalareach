/**
 * The host's saved launch commands, in a real browser engine (KR-REQ-13.11).
 *
 * What a component test cannot hold: that a saved command's button, its program and the line a
 * stock shell shows for it fit inside the window at the default text size and the largest, on a
 * wide window and a narrow one, with a long path and an argument that holds a space, and that the
 * Settings form saves, lists and removes a command with motion reduced and with it left alone.
 *
 * Every screenshot goes under the test artefact directory and is named for the requirement row it evidences.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { screenshotPath } from './evidence'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const LONG_PROGRAM = '/Users/rs/.local/share/very-long-directory-name/bin/a-program-with-a-long-name'

const SAVED = [
  { label: 'Claude Code', program: LONG_PROGRAM, arguments: ['--resume', 'two words', ''] },
  { label: 'Codex CLI', program: 'codex', arguments: [] }
]

interface Controls {
  readonly launchCommands: { changeElsewhere(commands: readonly unknown[]): void }
}

/** A stock shell session, opened as in the launch instructions' own case, with commands saved. */
async function openStockSession(page: Page, shell: string): Promise<void> {
  await page.goto(`/harness.html?stock_shell=${shell}`)
  await page.waitForSelector('.app-shell')
  await page.evaluate((commands) => {
    ;(window as unknown as { krTestHost: Controls }).krTestHost.launchCommands.changeElsewhere(commands)
  }, SAVED)
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByRole('button', { name: 'New session' }).click()
  const sheet = page.getByTestId('sheet')
  await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
  await sheet.getByRole('radio', { name: /Stock shell/ }).check()
  await sheet.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
  await sheet.getByRole('button', { name: 'Create session' }).click()
  await expect(page.getByTestId('launch-instructions')).toBeVisible()
  await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  const dismiss = page.getByRole('button', { name: 'Dismiss' })
  await expect(dismiss).toBeVisible()
  await dismiss.click()
}

for (const [width, height] of [
  [1280, 720],
  [390, 844]
] as const) {
  for (const [size, ratio] of [
    ['default', 1],
    ['largest', LARGEST]
  ] as const) {
    test(`draws a saved command whole under its heading and shows its line quoted at the ${size} text size, ${width} wide`, async ({
      page
    }) => {
      await openStockSession(page, 'bash')
      await page.setViewportSize({ width, height })
      await page.evaluate((value) => {
        document.documentElement.style.setProperty('--text-scale', String(value))
      }, ratio)
      const surface = page.getByTestId('launch-instructions')
      const saved = surface.getByTestId('launch-saved')
      await expect(saved).toBeVisible()
      await expect(saved).toContainText('Saved commands')
      await saved.getByRole('button', { name: /Claude Code/ }).click()
      await expect(page.getByTestId('launch-instruction')).toContainText(
        `Type this at the prompt: '${LONG_PROGRAM}' '--resume' 'two words' ''`
      )
      await page.getByTestId('launch-instruction').scrollIntoViewIfNeeded()
      expect(await overrunning(page, '[data-testid="launch-instructions"]')).toEqual([])
      const box = await surface.boundingBox()
      expect((box?.x ?? 0) + (box?.width ?? 0), 'right edge').toBeLessThanOrEqual(width + 1)
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
      ).toBeLessThanOrEqual(0)
      await surface.screenshot({
        path: screenshotPath(`kr-companion-launch-commands-${size}-${width}-13.11-${test.info().project.name}`)
      })
    })
  }
}

for (const reduced of [false, true]) {
  test.describe(reduced ? 'with reduced motion' : 'with motion', () => {
    test.use({ reducedMotion: reduced ? 'reduce' : 'no-preference' })

    test('saves a command from the Settings form, lists it and removes it', async ({ page }) => {
      await openStockSession(page, 'bash')
      await page.getByRole('button', { name: 'Settings' }).click()
      await expect(page.getByTestId('sheet').last()).toHaveAttribute('data-presentation', 'here', {
        timeout: PRESENTATION_DEADLINE
      })
      await page.getByRole('button', { name: 'Launch commands' }).click()
      const section = page.getByTestId('launch-commands')
      await expect(section.getByTestId('launch-commands-whose')).toContainText(
        "A command is saved as written and shown to this host's owner devices."
      )
      await expect(section.getByTestId('launch-commands-list')).toContainText('Codex CLI')
      await section.getByTestId('launch-commands-name').fill('Agent')
      await section.getByTestId('launch-commands-program').fill('C:\\tools\\agent.exe')
      await section.getByTestId('launch-commands-add-argument').click()
      await section.getByTestId('launch-commands-argument').first().fill('two words')
      await expect(section.getByTestId('launch-commands-preview')).toContainText('"C:\\tools\\agent.exe"')
      await expect(section.getByTestId('launch-commands-preview')).toContainText('"two words"')
      expect(await overrunning(page, '[data-testid="launch-commands"]')).toEqual([])
      await section.getByTestId('launch-commands-save').click()
      const row = section.getByTestId('launch-commands-list').locator('li[data-label="Agent"]')
      await expect(row).toContainText('"C:\\\\tools\\\\agent.exe" "two words"')
      await section.screenshot({
        path: screenshotPath(
          `kr-companion-launch-commands-settings-${reduced ? 'reduced' : 'motion'}-13.11-${test.info().project.name}`
        )
      })
      await row.getByRole('button', { name: 'Remove Agent' }).click()
      await expect(section.getByTestId('launch-commands-list').locator('li[data-label="Agent"]')).toHaveCount(0)
    })
  })
}

/** Every button that starts something on the terminal view, an installed agent's or a saved command's. */
const OFFERED = '[data-testid="launch-surface"] button[data-offer], [data-testid="launch-saved"] button[data-named]'

/** Whether every button that starts something is disabled, or enabled, as the page draws them now. */
async function offered(page: Page): Promise<boolean[]> {
  return page.locator(OFFERED).evaluateAll((buttons) => buttons.map((each) => (each as HTMLButtonElement).disabled))
}

test('typing_in_the_terminal_darkens_the_launch_buttons_in_the_same_frame', async ({ page }) => {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.evaluate((commands) => {
    window.krTestHost?.launchCommands.changeElsewhere(commands)
  }, SAVED)
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
  await page.getByRole('tab', { name: 'Terminal' }).click()
  await page.getByTestId('raw-terminal').waitFor()
  await page.getByRole('button', { name: 'Take control' }).click()
  await expect(page.getByRole('button', { name: 'Look around' })).toBeVisible()
  await expect
    .poll(async () => page.evaluate(() => window.krTestHost?.terminalViews.at(-1)?.control.state))
    .toBe('controlling')

  // Three installed agents and two saved commands, every one of them lit at the empty prompt.
  await expect(page.locator(OFFERED)).toHaveCount(5)
  await expect.poll(async () => offered(page)).toEqual([false, false, false, false, false])

  // From here no read of the surface answers, so nothing but the key can darken a button. The page
  // records the buttons at the first frame after the key, before anything is painted.
  await page.evaluate((selector) => {
    window.krTestHost?.hold('launchSurface')
    window.addEventListener(
      'keydown',
      () => {
        requestAnimationFrame(() => {
          ;(window as unknown as { krFrame?: boolean[] }).krFrame = Array.from(
            document.querySelectorAll<HTMLButtonElement>(selector),
            (each) => each.disabled
          )
        })
      },
      { once: true }
    )
  }, OFFERED)
  await page.getByTestId('terminal-grid').click({ position: { x: 4, y: 4 } })
  await expect(page.getByLabel('Type to the program')).toBeFocused()
  await page.keyboard.press('a')

  await expect
    .poll(async () => page.evaluate(() => (window as unknown as { krFrame?: boolean[] }).krFrame))
    .toEqual([true, true, true, true, true])
  // The key reached the program, and the buttons stay dark while no read has answered after it.
  await expect
    .poll(async () =>
      page.evaluate(
        () => window.krTestHost?.terminalViews.at(-1)?.inputs.filter((input) => input.kind === 'key').length
      )
    )
    .toBeGreaterThan(0)
  expect(await offered(page)).toEqual([true, true, true, true, true])
})
