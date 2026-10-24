/**
 * Who asked, photographed on a phone: the program the host verified, and the name it gave itself
 * beside it as the program's own (KR-REQ-11.61).
 *
 * A question comes from a program in the session, and the worker names the program it verified: its
 * executable and its process. What the program calls itself is a label it supplied, which nothing
 * verified, so the phone shows it beside the identity as unverified and never in the identity's
 * place, whatever the label says. These run the page against the scripted host, which gives the
 * program a label that imitates what the host verified; what the worker verifies is the worker's
 * own, and its suites prove it. Every screenshot goes in the run's evidence directory.
 */

import { expect, test } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { screenshotPath } from './evidence'

/** The label a program gives itself to pass for the program the host verified. */
const IMITATION = 'claude (verified by KalaReach)'

for (const surface of ['ios', 'android'] as const) {
  test.describe(`a question on ${surface}`, () => {
    test('names the verified program as the asker and the name it gave itself as its own, unverified', async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&tab=attention`)
      await page.evaluate((label) => {
        for (const question of window.krTestHost?.questions.held() ?? []) {
          window.krTestHost?.questions.callItself(question.question_id, label)
        }
      }, IMITATION)
      await page.locator('[data-attention^="attention.pending_input"]').click()
      await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', {
        timeout: PRESENTATION_DEADLINE
      })
      const asker = page.getByTestId('question-asker').first()
      await expect(asker).toBeVisible()

      // The identity is the executable the worker verified and its process, and only that.
      await expect(asker.locator('strong')).toHaveText('claude')
      await expect(asker).toContainText('process 4242')
      await expect(page.getByTestId('question-asker-path').first()).toHaveText('/usr/local/bin/claude')
      // The label is the program's own words, said to be unverified, and sits after the identity.
      await expect(asker).toContainText(`calls itself “${IMITATION}” (not verified)`)
      const identity = await asker.locator('strong').textContent()
      expect(identity).not.toContain('KalaReach')
      await page.screenshot({
        path: screenshotPath(
          `kr-companion-question-identity-11.61-${surface}-${test.info().project.name}`
        )
      })
    })
  })
}
