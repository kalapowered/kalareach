/**
 * The desktop shell in a real browser engine: the mark and wordmark in the sidebar, what the
 * window says when the application replaced a connection the host withdrew, and the region a
 * banner's words are said to a screen reader through.
 *
 * What a component test cannot hold is layout at the largest text size and in a face as wide as the
 * Linux runner's, and a message that has to fit the screen it is said on.
 *
 * Every screenshot goes under `/tmp`, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning } from './layout'

/** The Linux runner draws the page in DejaVu Sans, which sets about a tenth more text across a line. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

/** What the window says once for each connection the application replaces: that it was replaced. */
const REPLACED = /connection to this computer was replaced/

function shot(name: string): string {
  return `/tmp/kr-companion-shell-${name}-${test.info().project.name}.png`
}

/** Sets the text size as the desktop shell does, by the size the root is drawn at, before the page loads. */
async function withTextScale(page: Page, factor: number): Promise<void> {
  if (factor === 1) return
  await page.addInitScript((value) => {
    document.addEventListener('DOMContentLoaded', () => {
      document.documentElement.style.fontSize = `${16 * value}px`
    })
  }, factor)
}

async function openTheShell(page: Page, face: 'system' | 'wide'): Promise<void> {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  if (face === 'wide') await page.addStyleTag({ content: WIDE_FACE })
}

// The mark and the wordmark stay whole inside the sidebar at the default text size and
// at twice it, in the system's face and in a wide one: a mark is not text, so the sidebar's width is
// what it fits.
for (const [size, face] of [
  [1, 'system'],
  [1, 'wide'],
  [2, 'system'],
  [2, 'wide']
] as const) {
  test(`keeps the mark and wordmark whole, text ${size.toFixed(1)}x, ${face} face`, async ({ page }) => {
    await withTextScale(page, size)
    await openTheShell(page, face)
    const brand = page.locator('.brand')
    await expect(brand).toBeVisible()

    expect(await overrunning(page, '.brand')).toEqual([])
    const fits = await page.evaluate(() => {
      const sidebar = document.querySelector('.sidebar')
      const word = document.querySelector('.brand-word')
      if (sidebar === null || word === null) return null
      const edge = sidebar.getBoundingClientRect()
      const inner = edge.right - Number.parseFloat(getComputedStyle(sidebar).paddingRight)
      return {
        // The sidebar scrolls only down; a wordmark wider than it would make it scroll across.
        scrollsAcross: sidebar.scrollWidth > sidebar.clientWidth + 1,
        wordPastTheEdge: word.getBoundingClientRect().right - inner
      }
    })
    expect(fits).not.toBeNull()
    expect(fits?.scrollsAcross, 'the sidebar does not scroll across').toBe(false)
    expect(fits?.wordPastTheEdge ?? Infinity, 'the wordmark ends inside the sidebar').toBeLessThanOrEqual(0.5)
    await brand.screenshot({ path: shot(`brand-${size}-${face}`) })
  })
}

// A connection the host withdrew is replaced, and the window says so once for each
// replacement, never for the connection it starts with, and in words that fit the screen.
for (const [size, face] of [
  [1, 'system'],
  [2, 'wide']
] as const) {
  test(`says once that the connection was replaced, text ${size.toFixed(1)}x, ${face} face`, async ({
    page
  }) => {
    await withTextScale(page, size)
    await openTheShell(page, face)
    const toast = page.locator('.toast')
    await expect(toast).toHaveCount(0)

    await page.evaluate(() => {
      window.krTestHost?.replaceConnection()
    })
    await expect(toast).toHaveCount(1)
    await expect(toast).toContainText(REPLACED)
    expect(await overrunning(page, '.toast')).toEqual([])
    // It comes in from below the screen and rests inside it, with every line of its words.
    const height = page.viewportSize()?.height ?? 0
    await expect
      .poll(async () => {
        const box = await toast.boundingBox()
        return box === null ? Infinity : box.y + box.height
      })
      .toBeLessThanOrEqual(height)
    expect((await toast.boundingBox())?.y ?? -1).toBeGreaterThanOrEqual(0)
    await toast.screenshot({ path: shot(`replaced-${size}-${face}`) })

    // A change of the connection that replaced nothing says nothing more.
    await toast.getByRole('button', { name: /dismiss/i }).click()
    await expect(toast).toHaveCount(0)
    await page.evaluate(() => {
      window.krTestHost?.setConnected(false)
      window.krTestHost?.setConnected(true)
    })
    await expect(toast).toHaveCount(0)

    // The next replacement is said again.
    await page.evaluate(() => {
      window.krTestHost?.replaceConnection()
    })
    await expect(toast).toContainText(REPLACED)
  })
}

// A banner's words reach a screen reader through a region that was in the page before the banner,
// and the same region says the next banner's: a region that arrived with its words would say
// nothing in a real engine's accessibility tree.
test('says a banner through the region the page already held', async ({ page }) => {
  await openTheShell(page, 'system')
  // The region of the screen, which is the one outside every dialog.
  const region = page.locator('[data-announcements]:not([role="dialog"] *)')
  await expect(region).toHaveCount(1)
  await expect(page.locator('.banner')).toHaveCount(0)
  await expect(region).toBeEmpty()
  const before = await region.elementHandle()

  // The sessions cannot be listed when the person opens them: a banner comes into the page.
  await page.evaluate(() => {
    window.krTestHost?.failNextSessionList('The host did not answer.')
  })
  await page.getByRole('button', { name: 'Sessions' }).click()
  await expect(page.locator('.banner')).toContainText('This host is not answering')
  await expect(region).toMatchAriaSnapshot('- paragraph: /This host is not answering\\. The host did not answer\\..*/')
  expect(await before?.evaluate((node) => node.isConnected)).toBe(true)
  await expect(region, 'one region says every banner of the screen').toHaveCount(1)

  // The banner goes and its words go from the region with it.
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.locator('.banner')).toHaveCount(0)
  await expect(region).toBeEmpty()
})

// A dialog is modal: a screen reader inside it does not reach a region outside it, so the banners in
// the dialog say their words to a region the dialog holds, and the region outside says none of them.
test('says the banner of a sheet through a region inside the sheet', async ({ page }) => {
  await openTheShell(page, 'system')
  await page.evaluate(() => {
    window.krTestHost?.withoutQualifiedShell()
  })
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByRole('button', { name: 'New session' }).click()
  const sheet = page.getByTestId('sheet')
  await sheet.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
  await sheet.getByRole('button', { name: 'Create session' }).click()
  await expect(sheet.locator('.banner')).toContainText('This host has no managed shell to start')

  const inside = sheet.locator('[data-announcements]')
  await expect(inside).toHaveCount(1)
  await expect(inside).toContainText('This host has no managed shell to start.')
  // The region outside the sheet says none of the sheet's banners.
  const outside = page.locator('[data-announcements]:not([role="dialog"] *)')
  await expect(outside).toHaveCount(1)
  await expect(outside).toBeEmpty()
})
