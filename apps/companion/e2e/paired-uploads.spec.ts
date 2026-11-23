/**
 * A phone sends a file to the host it is paired with, in both engines the page runs in, on both
 * phones, at the default text size and the largest, on a screen 320 points wide (KR-REQ-13.12):
 * each state says what it is in words, the control the person presses is a finger tall, the long
 * sentences wrap inside the card, the bar moves with the chunks, and with reduced motion the card
 * arrives in place and the bar jumps.
 *
 * The scripted host stands in for native code and keeps an upload open until the case moves it on;
 * what native code does behind the card is proved in `src-tauri/tests/phone_uploads.rs`, and on the
 * phones themselves by the device legs.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** What a finger needs to hit, in points on iOS and density-independent pixels on Android. */
const TARGET = { ios: 44, android: 48 } as const

/** A box is read through floats, so a control of exactly the target can read a few hundred-thousandths short. */
const BOX_TOLERANCE = 0.01

const RIGHTS = ['session.view', 'files.upload', 'agent.prompt', 'terminal.input'] as const

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

/** Opens the first session's composer on a phone paired with a host that lets it send files. */
async function openComposer(page: Page, surface: 'ios' | 'android'): Promise<void> {
  await page.setViewportSize({ width: 320, height: 720 })
  await page.goto(`/harness.html?surface=${surface}`)
  await expect(page.locator('.m-shell')).toBeVisible()
  await page.evaluate((rights) => {
    window.krTestHost?.reachAsPhone({ rights: [...rights] })
  }, RIGHTS)
  await page.getByRole('button', { name: /^Sessions/ }).click()
  await page.getByRole('button', { name: /Session 1/ }).click()
  await expect(page.getByRole('group', { name: 'Add an attachment' })).toBeVisible()
}

async function pickFile(page: Page, name = 'quarterly-report-final-version-two.pdf'): Promise<string> {
  await page.locator('input[type="file"][accept="*/*"]').setInputFiles({
    name,
    mimeType: 'application/pdf',
    buffer: Buffer.from('twelve bytes')
  })
  await expect(page.getByTestId('upload-line')).toBeVisible()
  return await page.evaluate(async () => {
    for (let waited = 0; waited < 5000; waited += 20) {
      const key = window.krTestHost?.pairedUploads.started[0]?.key
      if (key !== undefined) return key
      await new Promise((resolve) => setTimeout(resolve, 20))
    }
    throw new Error('the upload was not started')
  })
}

/** Nothing of the card runs past the screen, and every control in it is a finger tall. */
async function fits(page: Page, surface: 'ios' | 'android'): Promise<void> {
  expect(await overrunning(page, '.m-attachments')).toEqual([])
  for (const button of await page.locator('.m-upload button').all()) {
    const box = await button.boundingBox()
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(TARGET[surface] - BOX_TOLERANCE)
    expect(box?.width ?? 0).toBeGreaterThanOrEqual(TARGET[surface] - BOX_TOLERANCE)
  }
}

for (const surface of ['ios', 'android'] as const) {
  for (const [size, ratio] of [
    ['the default text size', 1],
    ['the largest text size', LARGEST]
  ] as const) {
    test.describe(`a file sent to a paired host on ${surface} at ${size}`, () => {
      test.beforeEach(async ({ page }) => {
        await withSystemTextScale(page, ratio)
        await openComposer(page, surface)
      })

      test('says each state in words, with the bar, and ends added to the draft', async ({ page }) => {
        const key = await pickFile(page)
        const line = page.getByTestId('upload-line')
        await expect(line).toHaveText('Checking with the host')
        await fits(page, surface)

        await page.evaluate((id) => {
          window.krTestHost?.pairedUploads.progress(id, 3, 12)
        }, key)
        await expect(line).toHaveText('Sending, 25%')
        await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '25')
        await fits(page, surface)
        await page.screenshot({ path: screenshotPath(`kr-paired-upload-sending-${surface}-${String(ratio)}-${test.info().project.name}`) })

        await page.evaluate((id) => {
          window.krTestHost?.pairedUploads.pause(id)
        }, key)
        await expect(line).toHaveText('Paused: the host is out of reach. Sending resumes when contact returns.')
        await fits(page, surface)
        await page.evaluate((id) => {
          window.krTestHost?.pairedUploads.resume(id)
        }, key)
        await expect(line).toHaveText('Resuming at chunk 4 of 12')
        await page.evaluate((id) => {
          window.krTestHost?.pairedUploads.finish(id)
        }, key)
        await expect(line).toHaveText('Added to this draft')
        await expect(page.getByRole('progressbar')).toHaveCount(0)
        await fits(page, surface)
        await page.screenshot({ path: screenshotPath(`kr-paired-upload-added-${surface}-${String(ratio)}-${test.info().project.name}`) })
      })

      test('shows a cancel only as the host answers it, and keeps the control where it was', async ({ page }) => {
        await pickFile(page)
        await page.evaluate(() => {
          window.krTestHost?.pairedUploads.holdCancels()
        })
        const cancel = page.getByRole('button', { name: /^Cancel sending/ })
        await cancel.click()
        const line = page.getByTestId('upload-line')
        await expect(line).toHaveText('Cancelling')
        await expect(cancel).toHaveAttribute('aria-disabled', 'true')
        await page.evaluate(() => {
          window.krTestHost?.pairedUploads.releaseCancels()
        })
        await expect(line).toHaveText('Cancelled. The host released 12 bytes.')
        await expect(page.getByRole('button', { name: /^Remove/ })).toBeVisible()
        await fits(page, surface)
      })

      test('wraps the longest refusal inside the card and says what to do', async ({ page }) => {
        await page.evaluate(() => {
          window.krTestHost?.pairedUploads.refuseNext({
            code: 'PERMISSION_DENIED',
            message: 'two files are open on this host already: wait for one to finish, or cancel one'
          })
        })
        await pickFile(page).catch(() => undefined)
        await expect(page.getByTestId('upload-line')).toHaveText(
          'Two files are open on this host already: wait for one to finish, or cancel one'
        )
        await fits(page, surface)
        await page.screenshot({ path: screenshotPath(`kr-paired-upload-refused-${surface}-${String(ratio)}-${test.info().project.name}`) })
      })
    })
  }

  test.describe(`motion of a file sent to a paired host on ${surface}`, () => {
    test('moves the bar and brings the card in, and with reduced motion does neither', async ({ page }) => {
      await openComposer(page, surface)
      const key = await pickFile(page)
      await page.evaluate((id) => {
        window.krTestHost?.pairedUploads.progress(id, 3, 12)
      }, key)
      await expect(page.getByTestId('upload-line')).toHaveText('Sending, 25%')
      const fill = page.locator('.m-progress-fill')
      const card = page.locator('.m-upload')
      const styles = () =>
        page.evaluate(() => {
          const bar = getComputedStyle(document.querySelector('.m-progress-fill') as Element)
          const box = getComputedStyle(document.querySelector('.m-upload') as Element)
          return {
            fill: [bar.transitionProperty, bar.transitionDuration, bar.transitionTimingFunction],
            card: box.transitionProperty
          }
        })
      expect(await styles()).toEqual({
        fill: ['transform', '0.2s', 'linear'],
        card: 'opacity, transform, border-color'
      })
      await expect(fill).toHaveCSS('transform-origin', /^0px /)

      await page.emulateMedia({ reducedMotion: 'reduce' })
      // No transition at all on the bar, and the card changes its border colour and nothing that moves.
      expect(await styles()).toEqual({ fill: ['none', '0s', 'ease'], card: 'border-color' })
      await expect(card).toBeVisible()
    })
  })
}
