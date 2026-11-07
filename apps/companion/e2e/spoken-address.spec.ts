/**
 * A service's address is drawn as it is written and said to a screen reader as words. The words
 * are in the page for the reader and nowhere else: a copy of the sentence that holds the address
 * gives the written address, in both engines the page runs in, and not "reach dot kala dot to"
 * beside it.
 *
 * KR-REQ-11.48: the phone's Hosts screen says which service pairing codes go through, and its
 * Account screen says which service syncs this device.
 */

import { expect, test } from '@playwright/test'

for (const [screen, tab, address, sentence] of [
  ['Hosts', 'hosts', 'pairing-service', 'Codes go through reach.kala.to'],
  ['Account', 'account', 'sync-service', 'This device uses reach.kala.to as its sync service.']
] as const) {
  test.describe(`the address on the phone's ${screen} screen`, () => {
    test('is copied as it is written, and not with the words said in its place', async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=ios&tab=${tab}`)
      await expect(page.locator('.m-shell')).toBeVisible()
      const written = page.getByTestId(address)
      await expect(written).toBeVisible()
      // The selection a drag across the whole sentence makes, as the browser would copy it.
      const seen = await written.evaluate((element) => {
        const paragraph = element.closest('p')
        if (paragraph === null) throw new Error('the address is not in a sentence')
        const range = document.createRange()
        range.selectNodeContents(paragraph)
        const selection = window.getSelection()
        if (selection === null) throw new Error('the page has no selection')
        selection.removeAllRanges()
        selection.addRange(range)
        return { copied: selection.toString().trim(), all: paragraph.textContent ?? '' }
      })
      // The words for a screen reader are in the sentence, so that a copy without them is the rule's doing.
      expect(seen.all, 'the sentence holds the address as words').toContain('reach dot kala dot to')
      expect(seen.copied).toBe(sentence)
    })
  })
}
