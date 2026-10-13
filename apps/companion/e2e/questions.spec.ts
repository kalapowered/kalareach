/**
 * An agent's question, answered on a phone at the largest text size on the narrowest screen, and an
 * answer kept while the host cannot be reached.
 *
 * The question is the worker's, the answer commits on a completed press, and a kept answer is said
 * to be kept. At the largest size nothing runs past the screen's edge, every control a person
 * touches is at least a finger tall and wide, and every choice is a whole row rather than a small
 * circle.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { overrunning, stopWrapping } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The ratio the system gives the page, set before it loads, as a phone that already had it opens it. */
async function withSystemTextScale(page: Page, ratio: number): Promise<void> {
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

/** Opens the phone's inbox and the sheet of the question waiting in the build session. */
async function openQuestion(page: Page, surface: 'ios' | 'android'): Promise<void> {
  await page.setViewportSize({ width: 320, height: 720 })
  await page.goto(`/harness.html?surface=${surface}&tab=attention`)
  await page.locator('[data-attention^="attention.pending_input"]').click()
  await expect(page.getByTestId('question').first()).toBeVisible()
  // The sheet that holds it arrives on a spring, and a browser that has to draw it for the first
  // time can take seconds over the first frame: nothing is measured or pressed until it is at rest.
  await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
}

for (const surface of ['ios', 'android'] as const) {
  const finger = surface === 'ios' ? 44 : 48

  test.describe(`a question on ${surface} at the largest text size`, () => {
    test('keeps every line inside the screen and every control a finger in both directions', async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await openQuestion(page, surface)

      const across = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth,
        screen: window.innerWidth
      }))
      expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)

      // The sheet that holds the question clips what lies outside it, and a focus or a trial press
      // scrolls it to reach that, which a finger cannot do. So the sheet holds everything in it
      // across its width and down its height, and its body, the part that scrolls, is left room.
      const sheetBox = () =>
        page.locator('.sheet').evaluate((element) => ({
          wide: element.scrollWidth,
          across: element.clientWidth,
          tall: element.scrollHeight,
          high: element.clientHeight,
          left: element.scrollLeft,
          top: element.scrollTop,
          body: element.querySelector<HTMLElement>('.dialog-body')?.clientHeight ?? 0
        }))
      const sheet = await sheetBox()
      expect(sheet.wide, 'the sheet holds everything in it across its width').toBeLessThanOrEqual(sheet.across + 1)
      expect(sheet.tall, 'the sheet holds everything in it down its height').toBeLessThanOrEqual(sheet.high + 1)
      expect(sheet.body, 'the sheet shows at least two fingers of its body').toBeGreaterThanOrEqual(2 * finger)
      expect(await overrunning(page, '.dialog-header'), 'lines of the sheet header that run past it').toEqual([])
      expect(await overrunning(page, '.dialog-footer'), 'lines of the sheet footer that run past it').toEqual([])

      // Everything in a question, and every line of its text, lies inside the screen and inside
      // the question's own box.
      expect(
        await overrunning(page, '[data-testid="question"]'),
        'lines of the question that run past the screen or its box'
      ).toEqual([])

      // Each thing a finger presses: a choice is its whole row, and so is Send.
      const small = await page.evaluate((least) => {
        const pressed = document.querySelectorAll<HTMLElement>(
          '[data-testid="question"] .question-choice, [data-testid="question"] button, [data-testid="question"] textarea'
        )
        return [...pressed]
          .map((element) => ({ box: element.getBoundingClientRect(), name: element.textContent?.slice(0, 30) ?? '' }))
          .filter(({ box }) => box.height + 0.5 < least || box.width + 0.5 < least)
          .map(({ box, name }) => `${name}: ${Math.round(box.width)}×${Math.round(box.height)}`)
      }, finger)
      expect(small, `controls under ${finger} points`).toEqual([])

      // Every enabled control can be reached and pressed: a trial press stops short of the press.
      const controls = page.locator(
        '[data-testid="question"] input:visible:not([disabled]), [data-testid="question"] button:visible:not([disabled]), [data-testid="question"] textarea:visible:not([disabled])'
      )
      const count = await controls.count()
      expect(count, 'controls found on the question').toBeGreaterThan(0)
      for (let index = 0; index < count; index += 1) {
        await controls.nth(index).click({ trial: true, timeout: 2_000 })
      }

      // No press needed the sheet to be scrolled: a finger could not have done it.
      const afterwards = await sheetBox()
      expect(afterwards.left, 'the sheet was not scrolled sideways to reach a control').toBe(0)
      expect(afterwards.top, 'the sheet was not scrolled down to reach a control').toBe(0)

      // The control for the sheet's height: a header whose type grows without bound, as it did,
      // leaves the body no room, or lies below the sheet's own bottom.
      await page.addStyleTag({ content: '.dialog-header h2, .dialog-header p { font-size: 1.1875rem !important }' })
      const unbound = await sheetBox()
      expect(
        unbound.tall > unbound.high + 1 || unbound.body < 2 * finger,
        'the measure sees a header that takes the sheet'
      ).toBe(true)

      // The controls: with the text kept from wrapping, the same measure sees it run out of its box.
      await stopWrapping(page, ['[data-testid="question"]', '.dialog-header', '.dialog-footer'])
      for (const root of ['[data-testid="question"]', '.dialog-header', '.dialog-footer']) {
        expect(await overrunning(page, root), `the measure sees text of ${root} that cannot wrap`).not.toEqual([])
      }
    })

    test('sends nothing until Send is pressed after a choice, and keeps an answer given out of contact', async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await openQuestion(page, surface)
      const question = page.getByTestId('question').first()
      const send = question.getByRole('button', { name: 'Send answer' })
      await expect(send).toBeDisabled()
      await question.getByRole('radio').first().check()
      await expect(send).toBeEnabled()
      expect(await page.evaluate(() => window.krTestHost?.questions.sent.length)).toBe(0)

      // The session's worker goes before the press: the answer is kept, and nothing is sent.
      await page.evaluate(() => {
        window.krTestHost?.questions.setReachable(false)
      })
      await send.click()
      await expect(page.getByTestId('kept-answer')).toBeVisible()
      await expect(page.getByTestId('kept-answer')).toContainText('Answers kept on this device')
      expect(await page.evaluate(() => window.krTestHost?.questions.sent.length)).toBe(0)

      const kept = await page.evaluate(() => {
        const row = document.querySelector<HTMLElement>('[data-testid="kept-answer"]')
        const edge = window.innerWidth
        return {
          past: row === null ? 1 : Math.max(0, row.getBoundingClientRect().right - edge),
          buttons: [...(row?.querySelectorAll('button') ?? [])].map((button) => {
            const box = button.getBoundingClientRect()
            return [Math.round(box.width), Math.round(box.height)]
          })
        }
      })
      expect(kept.past, 'the kept answer runs past the screen').toBeLessThanOrEqual(0.5)
      for (const [width, height] of kept.buttons) {
        expect(Math.min(width ?? 0, height ?? 0), 'a kept answer’s button').toBeGreaterThanOrEqual(finger)
      }
    })
  })
}
