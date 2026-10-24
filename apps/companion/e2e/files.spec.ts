/**
 * The desktop's tabs, drag-and-drop, paste and file export, photographed (KR-REQ-13.16).
 *
 * The desktop keeps several sessions in tabs, takes a file dropped on the window or pasted into the
 * composer onto the draft from that moment, and writes its exports where the platform's dialog
 * puts them. These run the page in a real engine against the scripted host: a drop arrives as the
 * paths the shell would hand over, a paste as the clipboard event the engine fires, and an export as
 * the request the page makes of native code. What the shell does with a real drop, a real clipboard
 * and the system's save dialog, and the file that results, is native code's own: the Rust suites
 * for uploads and exports prove it, and a run of the packaged application on a desktop is the
 * photograph that is not taken here. Every screenshot goes in the run's evidence directory.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return screenshotPath(`kr-companion-${name}-${test.info().project.name}`)
}

async function open(page: Page): Promise<void> {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
}

/** Opens a session from the list, the way a person does. */
async function openFromList(page: Page, number: number): Promise<void> {
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId(`session-row-${number}`).click()
  await page.getByTestId('conversation').waitFor()
}

test.describe('the desktop takes sessions in tabs, files on the draft and an export', () => {
  test('keeps two sessions in tabs, takes a dropped and a pasted file, and asks for the export', async ({
    page
  }) => {
    // Tall enough that the whole conversation and its composer are in one photograph.
    await page.setViewportSize({ width: 1280, height: 1400 })
    await open(page)
    await openFromList(page, 1)
    await openFromList(page, 2)
    const tabs = page.getByTestId('session-tabs')
    await expect(tabs.getByRole('tab')).toHaveCount(2)
    // The tab of the session just opened is the active one, and the first is a click away.
    await expect(tabs.getByRole('tab', { selected: true })).toHaveCount(1)
    await tabs.getByRole('tab').first().click()
    await page.getByTestId('conversation').waitFor()
    await expect(tabs.getByRole('tab').first()).toHaveAttribute('aria-selected', 'true')

    // A file dropped on the window is on the draft from that moment.
    await page.evaluate(() => {
      window.krTestHost?.dropFiles([
        {
          name: 'release-notes.png',
          media_type: 'image/png',
          byte_len: 10,
          path: '/tmp/release-notes.png'
        }
      ])
    })
    const attached = page.getByTestId('draft-attachments')
    await expect(attached).toContainText('release-notes.png')
    await expect(attached).toContainText('Uploaded')

    // A file pasted into the composer is on the draft too, and the text the field holds is not
    // taken for it.
    await page.getByTestId('composer-input').fill('look at these')
    await page.evaluate(() => {
      const data = new DataTransfer()
      data.items.add(new File([new Uint8Array([1, 2, 3])], 'pasted-log.txt', { type: 'text/plain' }))
      const field = document.querySelector<HTMLTextAreaElement>('[data-testid="composer-input"]')
      field?.dispatchEvent(
        new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true })
      )
    })
    await expect(attached).toContainText('pasted-log.txt')
    await expect(page.getByTestId('composer-input')).toHaveValue('look at these')
    expect(await page.evaluate(() => window.krTestHost?.uploaded.length)).toBe(2)
    await page.screenshot({ path: shot('files-tabs-13.16') })
    // The two files and the paths the host gave them, with the draft's text, in view.
    await page.getByTestId('composer-input').scrollIntoViewIfNeeded()
    await page.screenshot({ path: shot('files-drop-paste-13.16') })

    // The export is asked for, where the platform's dialog puts it.
    await page.getByTestId('open-settings').click()
    await page.getByRole('button', { name: 'Export' }).click()
    await page.getByTestId('export-json').click()
    await expect
      .poll(() => page.evaluate(() => window.krTestHost?.exportedArchives.length))
      .toBe(1)
    expect(await page.evaluate(() => window.krTestHost?.exportedArchives[0]?.sessionId)).toBe(
      SESSION_MAIN
    )
    await page.screenshot({ path: shot('files-export-13.16') })
  })
})
