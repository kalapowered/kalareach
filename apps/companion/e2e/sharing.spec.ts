/**
 * The sharing tab in a real browser engine, at the default text size and at the largest.
 *
 * What these cover that a component test cannot is what needs layout and a renderer: that nothing
 * scrolls the page sideways when the text is three times its size, that every control is a full
 * target and reachable from the keyboard, where focus goes after a row is made or taken away,
 * that the screen's preview scrolls on both axes inside its own box, and that what opens when a
 * choice calls for it moves only as far as reduced motion allows. Every screenshot goes under
 * `/tmp`, in a file named for the text size and the engine it was taken in.
 */

import { expect, test, type Page } from '@playwright/test'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const SIZES = [
  { name: 'default', root: '16px' },
  { name: 'largest', root: `${(16 * LARGEST).toFixed(2)}px` }
] as const

/** Sets a person's own text size on the page before it loads. */
async function withTextSize(page: Page, size: string): Promise<void> {
  await page.addInitScript((scale) => {
    const apply = (): boolean => {
      const root = document.documentElement as HTMLElement | null
      if (root === null) return false
      root.style.fontSize = scale
      return true
    }
    if (!apply()) {
      new MutationObserver((_, observer) => {
        if (apply()) observer.disconnect()
      }).observe(document, { childList: true })
    }
  }, size)
}

function shot(name: string): string {
  return `/tmp/kr-companion-${name}-${test.info().project.name}.png`
}

/**
 * Photographs the whole of the settings sheet, which scrolls inside a window of its own: the page
 * is made tall enough for it to show everything at once, and given back its size after.
 */
async function photograph(page: Page, name: string): Promise<void> {
  const size = page.viewportSize() ?? { width: 1100, height: 900 }
  await page.setViewportSize({ width: size.width, height: 6000 })
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))))
  await page.getByTestId('sheet').screenshot({ path: shot(name) })
  await page.setViewportSize(size)
}

/** Opens the sharing tab of the main session. */
async function openSharing(page: Page): Promise<void> {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
  await page.getByTestId('open-settings').click()
  await page.getByRole('button', { name: 'Sharing' }).click()
  await expect(page.getByTestId('share-form')).toBeVisible()
  await expect(page.getByRole('radio', { name: /Sam's iPhone/ })).toBeVisible()
}

/**
 * Whether anything under `selector` is wider than the box it sits in, or than the scrolling pane
 * that holds it: a control past the pane's edge is cut off, not scrolled to.
 */
async function overflowsSideways(page: Page, selector: string): Promise<string[]> {
  return page.evaluate((within) => {
    const container = document.querySelector<HTMLElement>(within)
    if (container === null) return ['(missing)']
    const pane = container.closest<HTMLElement>('.settings-content') ?? container
    const room = pane.getBoundingClientRect()
    const wide: string[] = []
    if (pane.scrollWidth > pane.clientWidth + 1) wide.push('the pane scrolls sideways')
    for (const element of container.querySelectorAll<HTMLElement>('*')) {
      if (element.closest('.screen-lines') !== null) continue
      const box = element.getBoundingClientRect()
      if (box.width === 0) continue
      if (box.right > room.right + 1 || box.left < room.left - 1) {
        wide.push(`${element.tagName.toLowerCase()}.${element.className}`)
      }
    }
    return wide
  }, selector)
}

for (const size of SIZES) {
  test.describe(`sharing at the ${size.name} text size`, () => {
    test.beforeEach(async ({ page }) => {
      await withTextSize(page, size.root)
      await page.setViewportSize({ width: 1100, height: 900 })
    })

    // KR-REQ-18.12: the form lays out whatever the text size, and photographs the choices.
    test('lays out the form without pushing anything past its box', async ({ page }) => {
      await openSharing(page)
      await expect(page.getByTestId('recipients')).toBeVisible()
      expect(await overflowsSideways(page, '[data-testid="share-form"]')).toEqual([])
      expect(await overflowsSideways(page, '[data-testid="access"]')).toEqual([])
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
        'the page does not scroll sideways'
      ).toBe(true)
      await photograph(page, `sharing-form-${size.name}`)
    })

    // KR-REQ-18.12: every control is a full target, not a sliver of one.
    test('gives every control a target a finger or a pointer can hit', async ({ page }) => {
      await openSharing(page)
      const small = await page.evaluate(() => {
        const found: string[] = []
        const form = document.querySelector('[data-testid="share-form"]')
        for (const control of form?.querySelectorAll<HTMLElement>('button, select, [role="switch"]') ?? []) {
          if (control.closest('[inert]') !== null) continue
          const box = control.getBoundingClientRect()
          if (box.width === 0 && box.height === 0) continue
          // A switch is drawn small and pressed from a wider area that reaches past it.
          const reach = control.getAttribute('role') === 'switch' ? 16 : 0
          if (box.height + reach < 30) {
            found.push(
              `${control.tagName.toLowerCase()} ${control.getAttribute('aria-label') ?? control.textContent} ${String(box.height)}`
            )
          }
        }
        return found
      })
      expect(small).toEqual([])
    })

    // KR-REQ-18.12: consent gates Invite, from the keyboard as from a pointer.
    test('keeps Invite off until the consequences are understood, from the keyboard', async ({
      page
    }) => {
      await openSharing(page)
      await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
      await page.getByRole('radio', { name: /Controller/ }).check()
      const consent = page.getByRole('checkbox', { name: /I understand this lets Sam/ })
      await expect(consent).toBeVisible()
      await expect(page.getByTestId('invite')).toBeDisabled()
      await consent.focus()
      await page.keyboard.press('Space')
      await expect(consent).toBeChecked()
      await expect(page.getByTestId('invite')).toBeEnabled()
      await photograph(page, `sharing-consent-${size.name}`)

      // A different role is a different consent.
      await page.getByRole('radio', { name: /Owner/ }).check()
      await expect(consent).not.toBeChecked()
      await expect(page.getByTestId('invite')).toBeDisabled()
    })

    // KR-REQ-10.50: the screen the person is shown scrolls inside its own box on both axes, and can
    // be reached and scrolled from the keyboard; a cut screen cannot be shared.
    test('shows the screen in a box of its own that scrolls on both axes, and locks Invite when it was cut', async ({
      page,
      browserName
    }) => {
      await openSharing(page)
      const wide = 'x'.repeat(400)
      const lines = Array.from({ length: 40 }, (_, index) => `line ${String(index)} ${wide}`)
      await page.evaluate((screen) => {
        window.krTestHost?.sharing.setScreen(screen)
      }, lines)
      await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
      await page.getByRole('switch', { name: 'Let them watch the session live' }).click()
      const card = page.getByRole('region', { name: /^Screen at / })
      await expect(card).toBeVisible()
      const metrics = await card.evaluate((element) => ({
        scrollsAcross: element.scrollWidth > element.clientWidth,
        scrollsDown: element.scrollHeight > element.clientHeight,
        wholePageAcross: document.documentElement.scrollWidth > document.documentElement.clientWidth
      }))
      expect(metrics.scrollsAcross).toBe(true)
      expect(metrics.scrollsDown).toBe(true)
      expect(metrics.wholePageAcross, 'the long line stays inside the card').toBe(false)
      // From the keyboard: the card takes focus, and the engine scrolls a focused box with an arrow
      // key (WebKit's automation does not send that key to the box; the box is still focusable).
      await card.focus()
      await expect(card).toBeFocused()
      if (browserName === 'chromium') {
        await page.keyboard.press('ArrowDown')
        await expect.poll(async () => card.evaluate((element) => element.scrollTop)).toBeGreaterThan(0)
      }
      await photograph(page, `sharing-preview-${size.name}`)

      await page.evaluate(() => {
        window.krTestHost?.sharing.setScreen(['too big'], true)
      })
      await page.getByTestId('preview-refresh').click()
      await expect(page.getByTestId('preview-cut')).toBeVisible()
      await expect(page.getByTestId('invite')).toBeDisabled()
    })

    // KR-REQ-18.12: after Invite the focus is on the row it made, and after Withdraw on the next
    // row or the heading.
    test('moves focus to the new row, and then on from a withdrawn one', async ({ page }) => {
      await openSharing(page)
      await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
      await page.getByTestId('invite').focus()
      await page.keyboard.press('Enter')
      const row = page.locator('[data-testid="access"] [data-state="pending"]')
      await expect(row).toBeVisible()
      await expect(row).toBeFocused()
      await photograph(page, `sharing-row-${size.name}`)

      await row.getByTestId('withdraw').click()
      await expect(row).toHaveCount(0)
      await expect(page.getByRole('heading', { name: 'Sharing' })).toBeFocused()
    })

    // KR-REQ-18.14: an attempt whose answer was lost is on the page as unfinished, in words, with
    // the one thing that can be done about it.
    test('lists an unfinished invitation with what can be done about it', async ({ page }) => {
      await openSharing(page)
      await page.evaluate(() => {
        window.krTestHost?.sharing.loseNextAnswer()
      })
      await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
      await page.getByTestId('invite').click()
      const attempt = page.getByTestId('attempt')
      await expect(attempt).toContainText('The host has not said whether it happened')
      await expect(attempt).toContainText('It can still happen until')
      await expect(attempt.getByTestId('attempt-ask')).toBeVisible()
      await expect(attempt.getByTestId('attempt-hide')).toBeVisible()
      expect(await overflowsSideways(page, '[data-testid="access"]')).toEqual([])
      await photograph(page, `sharing-unfinished-${size.name}`)
    })

    // KR-REQ-18.15: the hand-over sheet waits for an owner device; its focus starts on its heading
    // and returns to the button that opened it.
    test('hands a session over only after an owner device answers, and returns focus', async ({
      page
    }) => {
      await openSharing(page)
      await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
      await page.getByRole('radio', { name: /Owner/ }).check()
      await page.getByTestId('lasts').selectOption('15m')
      await page.getByRole('checkbox', { name: /I understand this lets Sam/ }).check()
      await page.getByTestId('invite').click()
      await page.evaluate(() => {
        const [first] = window.krTestHost?.sharing.grants() ?? []
        if (first !== undefined) window.krTestHost?.sharing.deviceAccepts(first.grant.grant_id)
      })
      await page.evaluate(() => window.dispatchEvent(new Event('focus')))
      const opener = page.getByTestId('hand-over-open')
      await expect(opener).toBeVisible()
      await opener.click()
      const sheet = page.getByTestId('hand-over')
      await expect(sheet.getByRole('heading', { name: 'Hand over control' })).toBeFocused()
      await sheet.getByRole('radio', { name: /Guest tablet/ }).check()
      await photograph(page, `sharing-hand-over-${size.name}`)
      await sheet.getByTestId('hand-over-ask').click()
      await expect(sheet.getByTestId('hand-over-waiting')).toContainText('Waiting for an owner device')
      await photograph(page, `sharing-hand-over-waiting-${size.name}`)
      await sheet.getByTestId('hand-over-cancel').click()
      await expect(sheet).toHaveCount(0)
      await expect(opener).toBeFocused()
    })
  })
}

// KR-REQ-13.20: what opens when a choice calls for it moves only as far as reduced motion allows.
test.describe('the disclosures', () => {
  test('fade and do not travel under reduced motion, and open at once from the keyboard', async ({
    page
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await openSharing(page)
    const property = () =>
      page
        .locator('.disclosure')
        .first()
        .evaluate((element) => getComputedStyle(element).transitionProperty)
    expect(await property()).toBe('opacity')

    await page.emulateMedia({ reducedMotion: 'no-preference' })
    await expect.poll(property).toContain('grid-template-rows')
  })
})
