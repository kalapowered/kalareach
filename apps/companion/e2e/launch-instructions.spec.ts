/**
 * What a stock shell's launch button shows, in a real browser engine (KR-REQ-07.21).
 *
 * The page types nothing into a stock shell, so the command it shows is all a launch gives the
 * person, and it has to be the command for the shell they are in. A PowerShell session's is the
 * longest of the three: a call operator, a path, and quotes doubled. These cover what a component
 * test cannot: that the whole command is drawn inside the window, wrapped where it has to be, at the
 * default text size and the largest, on a wide window and on a narrow one.
 *
 * Every screenshot goes under `/tmp` and is named for the requirement row it evidences.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** What a PowerShell prompt is shown for the fake host's longest saved command. */
const POWERSHELL_COMMAND =
  "& '/Users/rs/My Notes/open-notes' '--title' 'It’’s a draft' '--note=don''t' '--tags=a,b' '@today'"

/** The stock shell's launch instructions, with the longest saved command chosen. */
async function openInstructions(page: Page, shell: string): Promise<void> {
  await page.goto(`/harness.html?stock_shell=${shell}`)
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByRole('button', { name: 'New session' }).click()
  const sheet = page.getByTestId('sheet')
  await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
  await sheet.getByRole('radio', { name: /Stock shell/ }).check()
  await sheet.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
  await sheet.getByRole('button', { name: 'Create session' }).click()
  await expect(page.getByTestId('launch-instructions')).toBeVisible()
  await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  // The notice that the session started is on the screen for a while, over the lower part of the
  // page. The person reads past it or sends it away, and so does this.
  const dismiss = page.getByRole('button', { name: 'Dismiss' })
  await expect(dismiss).toBeVisible()
  await dismiss.click()
  await page.getByTestId('launch-instructions').getByRole('button', { name: /Open my notes/ }).click()
}

for (const [width, height] of [
  [1280, 720],
  [390, 844]
] as const) {
  for (const [size, ratio] of [
    ['default', 1],
    ['largest', LARGEST]
  ] as const) {
    test(`shows a PowerShell session’s command whole at the ${size} text size, ${width} wide`, async ({
      page
    }) => {
      // The window is opened at the desktop's own size, which has the navigation the session is
      // reached through, and is made the size under test once the instructions are on it.
      await openInstructions(page, 'powershell')
      await page.setViewportSize({ width, height })
      await page.evaluate((value) => {
        document.documentElement.style.setProperty('--text-scale', String(value))
      }, ratio)
      expect(
        await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize))
      ).toBeCloseTo(16 * ratio, 1)

      const surface = page.getByTestId('launch-instructions')
      const instruction = page.getByTestId('launch-instruction')
      await expect(instruction).toContainText(`Type this at the prompt: ${POWERSHELL_COMMAND}`)
      await instruction.scrollIntoViewIfNeeded()

      // Every box and every line of text under the instructions lies inside the window and inside
      // the box that lays it out: nothing of the command is cut off or drawn past an edge.
      expect(await overrunning(page, '[data-testid="launch-instructions"]')).toEqual([])
      const box = await surface.boundingBox()
      expect(box, 'the instructions are on the page').not.toBeNull()
      expect((box?.x ?? 0) + (box?.width ?? 0), 'right edge').toBeLessThanOrEqual(width + 1)
      expect(box?.x ?? -1, 'left edge').toBeGreaterThanOrEqual(-1)
      // The page itself does not scroll sideways for it.
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
      ).toBeLessThanOrEqual(0)

      // The whole section, as a person sees it, rather than whatever part of it the window shows.
      await surface.screenshot({
        path: `/tmp/kr-companion-launch-instructions-powershell-${size}-${width}-07.21-${test.info().project.name}.png`
      })
    })
  }
}
