/**
 * A software keyboard over the page, as a phone presents one.
 *
 * The visual viewport loses the keyboard's height and says so, and the page measures the keyboard
 * from it (`--keyboard`, written by `useKeyboardInset`). The measure is not written from here: the
 * page writes it again at every event of the visual viewport, from the viewport as it finds it, and
 * WebKit sends one such event soon after a page loads. A value written by hand just ahead of that
 * event was measured away to no keyboard, and the field stood under a keyboard that was no longer
 * there. A viewport that holds the keyboard is measured as holding it by every event after.
 */

import type { Page } from '@playwright/test'

/** Covers the bottom `inset` pixels of the screen, as a software keyboard does. */
export async function keyboard(page: Page, inset: number): Promise<void> {
  await page.evaluate((covered) => {
    const viewport = window.visualViewport
    if (viewport === null) throw new Error('the page has no visual viewport')
    Object.defineProperty(viewport, 'height', { configurable: true, get: () => window.innerHeight - covered })
    viewport.dispatchEvent(new Event('resize'))
  }, inset)
}
