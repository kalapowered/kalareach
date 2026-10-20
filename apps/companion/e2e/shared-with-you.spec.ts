/**
 * What is shared with a phone, in a real browser engine, at the default text size and the largest,
 * on the narrowest screen.
 *
 * What these cover that a component test cannot is what needs layout and a renderer: that nothing
 * runs past the screen's edge when the text is three times its size, that every control is a full
 * target and can be reached, that the card an invitation opens scrolls inside itself, and that a
 * new invitation arriving above the part of the inbox a person has scrolled to moves nothing they
 * can see: the rows under their finger keep their place, in WebKit as in Chromium. Every
 * screenshot goes under `/tmp`, in a file named for the text size, the platform and the engine.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning, stopWrapping } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const SIZES = [
  { name: 'default', ratio: 1 },
  { name: 'largest', ratio: LARGEST }
] as const

/**
 * Two moments for the page's clock, in UTC (the pages that use them say so): by day, and in the hour
 * before midnight, when a share that lasts an hour ends on the next day. The end of a share is told
 * with the day's name when it falls on another day, which makes the words of a message about it
 * longer.
 */
const CLOCKS = [
  { name: 'by day', at: '2026-10-18T14:00:00Z' },
  { name: 'in the hour before midnight', at: '2026-10-18T23:30:00Z' }
] as const

/** Stands the page's clock at `at`, from its first frame; timers go on running. */
async function withClockAt(page: Page, at: string): Promise<void> {
  await page.clock.setFixedTime(new Date(at))
}

/**
 * The letters the page is drawn in. The system's own face differs from one platform to the next, and
 * a layout that holds only for the widths of the face it was drawn with does not hold. The second
 * face is Verdana, or DejaVu Sans where Verdana is not installed; DejaVu Sans is also the face the
 * Linux runner draws the page in. Both are wider than the system face of a phone or of a Mac.
 */
const FACES = [
  { suffix: '', shot: '', css: null },
  {
    suffix: ' in a wide face',
    shot: '-wide',
    css: ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'
  }
] as const

/** Sets the page's face from its first frame, where `css` is the rule that says it. */
async function withFace(page: Page, css: string | null): Promise<void> {
  if (css === null) return
  await page.addInitScript((rule) => {
    const apply = (): boolean => {
      const root = document.documentElement as HTMLElement | null
      if (root === null) return false
      const style = document.createElement('style')
      style.textContent = rule
      root.append(style)
      return true
    }
    if (!apply()) {
      new MutationObserver((_, observer) => {
        if (apply()) observer.disconnect()
      }).observe(document, { childList: true })
    }
  }, css)
}

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

function shot(name: string): string {
  return `/tmp/kr-shared-with-you-${name}-${test.info().project.name}.png`
}

/** Opens a phone's screen with the host as a guest's, holding what the test arranges. */
async function open(
  page: Page,
  surface: 'ios' | 'android',
  tab: 'attention' | 'sessions',
  arrange: (page: Page) => Promise<void>
): Promise<void> {
  await page.goto(`/harness.html?surface=${surface}&tab=${tab}`)
  await expect(page.locator('.m-shell')).toBeVisible()
  await arrange(page)
}

/** The host offers three invitations, one of them a controller's with the live screen. */
async function offers(page: Page): Promise<void> {
  await page.evaluate(() => {
    const host = window.krTestHost
    if (host === undefined) throw new Error('no scripted host')
    host.sharing.offer({ session: '3', role: 'controller', live: true })
    host.sharing.offer({ session: '4' })
    host.reachAsPhone({ host: 'studio-with-a-long-name-that-has-to-wrap' })
  })
  await expect(page.getByTestId('offers')).toBeVisible()
}

/** Reads what the host lists now, as the cadence does and as a page shown again does. */
async function readAgain(page: Page): Promise<void> {
  await page.evaluate(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

/** Lets the page draw two frames, in which what was asked of it (a scroll, an insertion) has happened. */
async function drawn(page: Page): Promise<void> {
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))))
}

/**
 * Scrolls the inbox down, to its end or by `depth`, and lets `invitations` new ones arrive above it:
 * the pill is drawn.
 */
async function withPill(page: Page, how: { invitations?: number; depth?: number } = {}): Promise<void> {
  const { invitations = 1, depth } = how
  await open(page, 'ios', 'attention', async (loaded) => {
    await loaded.evaluate(() => {
      window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
    })
  })
  const main = page.locator('.m-main')
  await expect(main.locator('[data-attention]').first()).toBeVisible()
  await main.evaluate((element, to) => {
    element.scrollTop = to ?? element.scrollHeight
  }, depth ?? null)
  await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan((depth ?? 200) / 2)
  await page.evaluate((count) => {
    for (let each = 0; each < count; each += 1) window.krTestHost?.sharing.offer({ session: '4' })
  }, invitations)
  await readAgain(page)
  const words = invitations === 1 ? '1 new invitation' : `${String(invitations)} new invitations`
  await expect(page.getByRole('button', { name: words })).toBeVisible()
  await drawn(page)
}

/** Every control a person can touch under `selector`, scrolled to and pressed in a trial. */
async function unreachable(page: Page, scope: string): Promise<string[]> {
  const controls = page.locator(scope).locator('button:visible:not([disabled])')
  const count = await controls.count()
  expect(count, `controls found under ${scope}`).toBeGreaterThan(0)
  const found: string[] = []
  for (let index = 0; index < count; index += 1) {
    const control = controls.nth(index)
    const label = ((await control.innerText().catch(() => '')) || 'a control with no name')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 40)
    try {
      await control.click({ trial: true, timeout: 2_000 })
    } catch (failure) {
      found.push(`${label}: ${String(failure).split('\n')[0]}`)
    }
  }
  return found
}

for (const surface of ['ios', 'android'] as const) {
  for (const size of SIZES) {
    for (const face of FACES) {
      test.describe(`what is shared with a phone on ${surface} at the ${size.name} text size${face.suffix}`, () => {
        // The words that say when a share ends depend on the day, so the clock stands where this says.
        test.use({ timezoneId: 'UTC' })
        test.beforeEach(async ({ page }) => {
          await withClockAt(page, CLOCKS[0].at)
          await withSystemTextScale(page, size.ratio)
          await withFace(page, face.css)
          await page.setViewportSize({ width: 320, height: 720 })
        })

        // KR-REQ-18.13: the invitations lay out whatever the text size, and every control is reachable.
        test('lays the invitations at the head of the inbox out inside the screen', async ({ page }) => {
          await open(page, surface, 'attention', offers)
          const across = await page.evaluate(() => ({
            page: document.documentElement.scrollWidth,
            screen: window.innerWidth
          }))
          expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
          expect(await overrunning(page, '[data-testid="offers"]')).toEqual([])
          expect(await unreachable(page, '[data-testid="offers"]')).toEqual([])

          // The tab for this screen counts the two invitations, inside the bar and clear of its label.
          await expect(page.locator('.m-tab-badge')).toHaveText('2')
          await expect(page.getByRole('button', { name: /^Attention\s*, 2 waiting for you$/ })).toBeVisible()
          expect(await overrunning(page, '.m-tabbar')).toEqual([])

          // The control: with the text kept from wrapping the same measure sees the rows run out.
          await page.screenshot({ path: shot(`offers-${surface}-${size.name}${face.shot}`) })
          await stopWrapping(page, ['[data-testid="offers"]'])
          expect(await overrunning(page, '[data-testid="offers"]')).not.toEqual([])
        })

        // KR-REQ-18.13: what is drawn under the invitations once some are put off or accepted without
        // the host's answer arriving (the acceptances not settled, and the one that was hidden) lays
        // out whatever the text size and the face, and every control is reachable.
        test('lays the acceptances not settled, and what was put off, out inside the screen', async ({ page }) => {
          await open(page, surface, 'attention', offers)
          await page.evaluate(() => {
            window.krTestHost?.sharing.offer({ session: '5' })
          })
          await readAgain(page)
          await expect(page.locator('[data-offer]')).toHaveCount(3)
          // Two invitations are accepted and the host's answers are lost: two acceptances not settled.
          for (const session of ['3', '4']) {
            await page.evaluate(() => {
              window.krTestHost?.sharing.loseNextAnswer()
            })
            await page.getByRole('button', { name: new RegExp(`shared session ${session} with you`) }).click()
            await page.getByTestId('accept-offer').click()
            await expect(page.getByTestId('sheet')).toBeHidden()
            // The toast that says so lies over the inbox and the body of the next card: it is taken away.
            await page.locator('.toast').getByRole('button', { name: 'Dismiss' }).click()
            await expect(page.locator('.toast')).toBeHidden()
          }
          await expect(page.getByTestId('accept-attempt')).toHaveCount(2)
          // One acceptance is hidden, and the third invitation is put off.
          await page.getByTestId('attempt-hide').first().click()
          await expect(page.getByTestId('hidden-attempts')).toBeVisible()
          await page.getByRole('button', { name: /shared session 5 with you/ }).click()
          await page.getByTestId('not-now').click()
          await expect(page.getByTestId('hidden-offers')).toBeVisible()
          await expect(page.getByTestId('sheet')).toBeHidden()
          // The row that says one is hidden lays its words and its action out as a row of its own.
          await expect(page.getByTestId('hidden-offers')).toHaveCSS('display', 'flex')

          expect(await overrunning(page, '[data-testid="offers"]')).toEqual([])
          expect(await unreachable(page, '[data-testid="offers"]')).toEqual([])
          await page.screenshot({ path: shot(`settled-${surface}-${size.name}${face.shot}`) })
          await stopWrapping(page, ['[data-testid="offers"]'])
          expect(await overrunning(page, '[data-testid="offers"]')).not.toEqual([])
        })

        // KR-REQ-18.13: an invitation the host stopped listing after the phone listed it is still sent
        // to the host, which says why it is gone. The message and the row for the acceptance both
        // give the host's word, neither says the host has not spoken, and both lay out inside the
        // screen whatever the text size and the face.
        test('says why an invitation is gone in the message and in the row for the acceptance', async ({
          page
        }) => {
          await open(page, surface, 'attention', offers)
          const invitation = await page.evaluate(
            () => window.krTestHost?.sharing.offer({ session: '5' }).invitation_id ?? ''
          )
          await readAgain(page)
          await expect(page.locator('[data-offer]')).toHaveCount(3)
          await page.getByRole('button', { name: /shared session 5 with you/ }).click()
          // The issuer withdraws it while the card is open.
          await page.evaluate((id) => {
            window.krTestHost?.sharing.withdrawOffer(id, 'this invitation was withdrawn')
          }, invitation)
          await page.getByTestId('accept-offer').click()
          await expect(page.getByTestId('sheet')).toBeHidden()

          const toast = page.locator('.toast')
          await expect(toast).toContainText('The host said: this invitation was withdrawn')
          const row = page.getByTestId('accept-attempt')
          await expect(row).toHaveCount(1)
          await expect(row).toContainText('The host said: this invitation was withdrawn')
          await expect(row).not.toContainText('has not said')
          expect(await overrunning(page, '[data-testid="offers"]')).toEqual([])
          expect(await overrunning(page, '.toast')).toEqual([])
          await page.screenshot({ path: shot(`gone-${surface}-${size.name}${face.shot}`) })
        })

        test('lays the card an invitation opens out inside the screen, with Accept and Not now reachable', async ({
          page
        }) => {
          await open(page, surface, 'attention', offers)
          await page.getByTestId('offers').getByRole('button').first().click()
          const card = page.getByTestId('offer-card')
          await expect(card).toBeVisible()
          await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here')
          expect(await overrunning(page, '[data-testid="offer-card"]')).toEqual([])
          const accept = page.getByTestId('accept-offer')
          const notNow = page.getByTestId('not-now')
          await accept.scrollIntoViewIfNeeded()
          for (const control of [accept, notNow]) {
            const box = await control.boundingBox()
            const target = surface === 'ios' ? 44 : 48
            expect(box?.width ?? 0, 'target width').toBeGreaterThanOrEqual(target)
            expect(box?.height ?? 0, 'target height').toBeGreaterThanOrEqual(target)
          }
          await accept.click({ trial: true })
          await notNow.click({ trial: true })
          await page.screenshot({ path: shot(`card-${surface}-${size.name}${face.shot}`) })
          await stopWrapping(page, ['[data-testid="offer-card"]'])
          expect(await overrunning(page, '[data-testid="offer-card"]')).not.toEqual([])
        })

        // KR-REQ-18.13: the shares held, and the one that ended, lay out inside the screen.
        test('lays the shares held and the one that ended out inside the screen', async ({ page }) => {
          await open(page, surface, 'sessions', async (loaded) => {
            await loaded.evaluate(() => {
              const host = window.krTestHost
              if (host === undefined) throw new Error('no scripted host')
              host.sharing.offer({ session: '3', role: 'controller' })
              host.sharing.offer({ session: '4' })
              host.reachAsPhone({
                rights: ['session.view'],
                host: 'studio-with-a-long-name-that-has-to-wrap'
              })
            })
          })
          // Accept both, then the host stops listing one.
          await page.getByRole('button', { name: /^Attention\b/ }).click()
          for (const session of ['3', '4']) {
            await page.getByRole('button', { name: new RegExp(`shared session ${session} with you`) }).click()
            await page.getByTestId('accept-offer').click()
            await expect(page.getByTestId('sheet')).toBeHidden()
          }
          // The toast that says so lies over the tab bar: it is taken away.
          await page.locator('.toast').getByRole('button', { name: 'Dismiss' }).click()
          await expect(page.locator('.toast')).toBeHidden()
          await page.getByRole('button', { name: 'Sessions', exact: true }).click()
          const shared = page.getByTestId('shared-with-you')
          await expect(shared.getByRole('button')).toHaveCount(2)
          await page.evaluate(() => {
            const host = window.krTestHost
            const first = host?.sharing.held()[0]
            if (host === undefined || first === undefined) throw new Error('nothing held')
            host.sharing.endShare(first.grant.grant_id)
            host.sharing.failNextHeld('the connection to the host was lost')
          })
          await readAgain(page)
          await expect(shared.getByText(/Not refreshed just now/)).toBeVisible()
          await readAgain(page)
          await expect(page.getByTestId('ended-share')).toHaveCount(1)
          // A share that ended leads nowhere, and is drawn as a row that is not a control.
          await expect(page.getByTestId('ended-share')).toHaveCSS('cursor', 'default')
          await expect(page.getByTestId('ended-share')).toHaveCSS('border-top-style', 'dashed')

          expect(await overrunning(page, '[data-testid="shared-with-you"]')).toEqual([])
          expect(await unreachable(page, '[data-testid="shared-with-you"]')).toEqual([])
          await page.screenshot({ path: shot(`shared-${surface}-${size.name}${face.shot}`) })
          await stopWrapping(page, ['[data-testid="shared-with-you"]'])
          expect(await overrunning(page, '[data-testid="shared-with-you"]')).not.toEqual([])
        })
      })
    }
  }
}

test.describe('a new invitation while the inbox is scrolled', () => {
  test.beforeEach(async ({ page }) => {
    await withSystemTextScale(page, LARGEST)
    await page.setViewportSize({ width: 320, height: 720 })
  })

  /** The place of the first row of the inbox's own list, from the top of the screen. */
  const probe = (page: Page) =>
    page.evaluate(() => document.querySelector('.m-list [data-attention]')?.getBoundingClientRect().top ?? NaN)

  // KR-REQ-18.13: a new invitation is inserted without moving the rows the person is looking at,
  // in either engine, and a pill says that something arrived above.
  test('inserts it above without moving what is under the finger, and says so', async ({ page }) => {
    await open(page, 'ios', 'attention', async (loaded) => {
      await loaded.evaluate(() => {
        window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
      })
    })
    const main = page.locator('.m-main')
    await expect(main.locator('[data-attention]').first()).toBeVisible()
    // The person has scrolled down the inbox.
    await main.evaluate((element) => {
      element.scrollTop = 180
    })
    await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(100)
    await drawn(page)
    const before = { top: await probe(page), scrolled: await main.evaluate((element) => element.scrollTop) }

    await page.evaluate(() => {
      window.krTestHost?.sharing.offer({ session: '4' })
    })
    await readAgain(page)
    await expect(page.getByTestId('offers')).toBeVisible()
    const pill = page.getByRole('button', { name: '1 new invitation' })
    await expect(pill).toBeVisible()

    // Nothing the person can see has moved, though the list grew above it. The browser tells a page
    // what a box's size became just before it draws the next frame, so the place is read after two.
    await drawn(page)
    const after = await page.evaluate(() => ({
      top: document.querySelector('.m-list [data-attention]')?.getBoundingClientRect().top ?? Number.NaN,
      scrolled: document.querySelector('.m-main')?.scrollTop ?? Number.NaN
    }))
    expect(
      Math.abs(after.top - before.top),
      `the row under the finger kept its place (${JSON.stringify({ before, after })})`
    ).toBeLessThanOrEqual(1)
    expect(after.scrolled, 'the scroll position took up the new row').toBeGreaterThan(before.scrolled)
    // It is told once to a screen reader, and a read that finds nothing new says nothing more.
    await expect(page.getByTestId('offers-said')).toHaveText('New invitation. Studio shared session 4 with you.')
    await page.screenshot({ path: shot('pill') })

    // The pill takes the person to it.
    await pill.click()
    await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeLessThanOrEqual(8)
    await expect(pill).toBeHidden()
    await expect(page.locator('[data-offer]').first()).toBeFocused()
  })

  // KR-REQ-18.13: the pill's words are inside the pill and the pill is inside the screen, whatever the
  // text size and the face: its box has no height of its own, and its label must not be the one thing
  // that runs out of it.
  for (const face of FACES) {
    test(`keeps the pill's words inside the pill, and the pill inside the screen${face.suffix}`, async ({
      page
    }) => {
      await withFace(page, face.css)
      await open(page, 'ios', 'attention', async (loaded) => {
        await loaded.evaluate(() => {
          window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
        })
      })
      const main = page.locator('.m-main')
      await expect(main.locator('[data-attention]').first()).toBeVisible()
      await main.evaluate((element) => {
        element.scrollTop = 180
      })
      await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(100)
      await page.evaluate(() => {
        window.krTestHost?.sharing.offer({ session: '4' })
      })
      await readAgain(page)
      await expect(page.getByRole('button', { name: '1 new invitation' })).toBeVisible()
      await drawn(page)
      const fit = await page.evaluate(() => {
        const pill = document.querySelector('.sw-new-button')
        if (pill === null) throw new Error('no pill')
        const box = pill.getBoundingClientRect()
        const range = document.createRange()
        range.selectNodeContents(pill)
        const outside = Array.from(range.getClientRects()).filter(
          (line) =>
            line.width > 0 &&
            (line.top < box.top - 0.5 ||
              line.bottom > box.bottom + 0.5 ||
              line.left < box.left - 0.5 ||
              line.right > box.right + 0.5)
        )
        return { left: box.left, right: box.right, screen: window.innerWidth, outside: outside.length }
      })
      expect(fit.outside, 'lines of the words of the pill outside the pill').toBe(0)
      expect(fit.left, 'the pill starts inside the screen').toBeGreaterThanOrEqual(0)
      expect(fit.right, 'the pill ends inside the screen').toBeLessThanOrEqual(fit.screen)
      await page.screenshot({ path: shot(`pill-fit${face.shot}`) })
    })
  }

  // Reduced motion: the pill's jump does not travel.
  test('jumps to the invitation at once when the person asked for less motion', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await open(page, 'ios', 'attention', async (loaded) => {
      await loaded.evaluate(() => {
        window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
      })
    })
    const main = page.locator('.m-main')
    await expect(main.locator('[data-attention]').first()).toBeVisible()
    await main.evaluate((element) => {
      element.scrollTop = 180
    })
    await page.evaluate(() => {
      window.krTestHost?.sharing.offer({ session: '4' })
    })
    await readAgain(page)
    const pill = page.getByRole('button', { name: '1 new invitation' })
    await expect(pill).toBeVisible()
    await pill.click()
    // At once: the position is at the top by the time the click has returned and a frame has drawn.
    await drawn(page)
    expect(await main.evaluate((element) => element.scrollTop)).toBeLessThanOrEqual(8)
  })

  // At the top nothing is scrolled, so the invitation simply takes the head and no pill is drawn.
  test('draws no pill for an invitation that arrives while the inbox is at its top', async ({ page }) => {
    await open(page, 'ios', 'attention', async (loaded) => {
      await loaded.evaluate(() => {
        window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
      })
    })
    await expect(page.locator('.m-main [data-attention]').first()).toBeVisible()
    await page.evaluate(() => {
      window.krTestHost?.sharing.offer({ session: '4' })
    })
    await readAgain(page)
    await expect(page.getByTestId('offers')).toBeVisible()
    await expect(page.getByRole('button', { name: /new invitation/ })).toHaveCount(0)
    await expect(page.getByTestId('offers-said')).toHaveText('New invitation. Studio shared session 4 with you.')
  })
})

// KR-REQ-13.19, KR-REQ-18.13: a message in passing is drawn inside the card an invitation opens, above
// the footer and not over what accepts or puts off, at every text size and wherever the clock stands,
// and its Dismiss is in the keyboard's path between the card's body and its footer. The words of a
// message about when a share ends are longer when it ends on another day; at the largest size they are
// too many for the message's box, and the message still goes in its time.
test.describe('a message in passing over the card an invitation opens', () => {
  test.use({ timezoneId: 'UTC' })

  /**
   * Accepts invitation 3, holds the message that says so (a `pointerover` event on it, which is what a
   * pointer resting on it does: the engines differ in whether a pointer that is already there counts,
   * so no timer decides the case), and opens invitation 4's card over it. The message moves into the
   * card, where it is drawn anew, so the pointer is put on it again there.
   */
  async function openCardOverMessage(
    page: Page,
    how: {
      surface: 'ios' | 'android'
      ratio: number
      face: (typeof FACES)[number]
      at: string
      reduced?: boolean
      inset?: number
    }
  ) {
    if (how.reduced === true) await page.emulateMedia({ reducedMotion: 'reduce' })
    await withClockAt(page, how.at)
    await withSystemTextScale(page, how.ratio)
    await withFace(page, how.face.css)
    await page.setViewportSize({ width: 320, height: 720 })
    await open(page, how.surface, 'attention', offers)
    // The platform's inset under the card is the page's own property, which a phone's web view fills in.
    if (how.inset !== undefined) {
      await page.evaluate((inset) => {
        document.documentElement.style.setProperty('--safe-bottom', `${String(inset)}px`)
      }, how.inset)
    }
    await page.getByRole('button', { name: /shared session 3 with you/ }).click()
    await page.getByTestId('accept-offer').click()
    await expect(page.getByTestId('sheet')).toBeHidden()
    const toast = page.locator('.toast')
    await expect(toast).toContainText('Session 3 is shared with you until')
    await toast.dispatchEvent('pointerover', { pointerType: 'mouse', pointerId: 1 })
    await page.getByRole('button', { name: /shared session 4 with you/ }).dispatchEvent('click')
    const accept = page.getByTestId('accept-offer')
    const notNow = page.getByTestId('not-now')
    await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here')
    await expect(accept).toBeVisible()
    await expect(toast).toBeVisible()
    await toast.dispatchEvent('pointerover', { pointerType: 'mouse', pointerId: 1 })
    return { toast, accept, notNow }
  }

  /** Where the message rests against the card's footer and its two actions, and that it is the card's own. */
  async function messageOverCard(
    page: Page,
    how: {
      surface: 'ios' | 'android'
      ratio: number
      face: (typeof FACES)[number]
      at: string
      reduced?: boolean
      inset?: number
      /** An inset that comes while the card is open, as the platform's does when the device turns. */
      insetLater?: number
      shot: string
    }
  ): Promise<void> {
    const { toast, accept, notNow } = await openCardOverMessage(page, how)
    if (how.insetLater !== undefined) {
      await page.evaluate((inset) => {
        document.documentElement.style.setProperty('--safe-bottom', `${String(inset)}px`)
      }, how.insetLater)
    }

    // The message does not overlap the footer or either action, and is inside the screen.
    const overlaps = () =>
      page.evaluate(() => {
        const message = document.querySelector('.toast')?.getBoundingClientRect()
        if (message === undefined) return ['no message']
        const found: string[] = []
        if (message.top < 0 || message.bottom > window.innerHeight) found.push('the message is off the screen')
        const meets = (box: DOMRect): boolean =>
          box.left < message.right && box.right > message.left && box.top < message.bottom && box.bottom > message.top
        for (const [name, selector] of [
          ['the footer', '.sheet .dialog-footer'],
          ['accept-offer', '[data-testid="accept-offer"]'],
          ['not-now', '[data-testid="not-now"]']
        ] as const) {
          const box = document.querySelector(selector)?.getBoundingClientRect()
          if (box === undefined) found.push(`no ${name}`)
          else if (meets(box)) found.push(`the message lies over ${name}`)
        }
        return found
      })
    await expect.poll(overlaps, 'where the message and the card overlap').toEqual([])
    // A trial press fails where something else would take it.
    for (const control of [accept, notNow]) await control.click({ trial: true, timeout: 5_000 })
    await page.screenshot({ path: `/tmp/kr-shared-with-you-toast-${how.shot}-${test.info().project.name}.png` })

    // It is the card's own: inside the dialog while the card is open, and back on the screen when the
    // card goes.
    expect(await toast.evaluate((element) => element.closest('[role="dialog"]') !== null)).toBe(true)
    await notNow.click()
    await expect(page.getByTestId('sheet')).toBeHidden()
    expect(await toast.evaluate((element) => element.closest('[role="dialog"]') !== null)).toBe(false)
  }

  for (const surface of ['ios', 'android'] as const) {
    for (const size of SIZES) {
      for (const face of FACES) {
        for (const clock of CLOCKS) {
          test(`rests above the card's footer on ${surface} at the ${size.name} text size${face.suffix}, ${clock.name}`, async ({
            page
          }) => {
            await messageOverCard(page, {
              surface,
              ratio: size.ratio,
              face,
              at: clock.at,
              shot: `${surface}-${size.name}${face.shot}-${clock.name.replace(/ /g, '-')}`
            })
          })
        }
      }
    }
  }

  // The message is inside the dialog, so a keyboard reaches its Dismiss and a screen reader names it:
  // after what the card holds and before its footer, in the order the eye reads them. Focus does not
  // move to it by itself, when it arrives or when the card opens over it.
  for (const size of SIZES) {
    test(`puts Dismiss between the card's body and its footer, named, without taking the focus, at the ${size.name} text size`, async ({
      page,
      browserName
    }) => {
      const { toast, accept } = await openCardOverMessage(page, {
        surface: 'ios',
        ratio: size.ratio,
        face: FACES[1],
        at: CLOCKS[0].at
      })
      const dialog = page.getByRole('dialog')
      const dismiss = dialog.getByRole('button', { name: 'Dismiss' })
      await expect(dismiss, 'the message is in the dialog and its control is named').toBeVisible()
      await expect(toast).not.toBeFocused()
      await expect(dismiss, 'focus does not move to the message by itself').not.toBeFocused()
      // The card's own control has the focus, as it had when the card opened.
      expect(await page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null)).toBe(true)

      // Document order, which is the keyboard's: the body, then the message's Dismiss, then the footer.
      const order = await page.evaluate(() => {
        const sheet = document.querySelector('.sheet')
        const body = sheet?.querySelector('.dialog-body')
        const footer = sheet?.querySelector('.dialog-footer')
        const message = sheet?.querySelector('.toast')
        if (!body || !footer || !message) return null
        const follows = (a: Element, b: Element): boolean =>
          Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)
        return { afterBody: follows(body, message), beforeFooter: follows(message, footer) }
      })
      expect(order, 'the body, the message and the footer are in the dialog').not.toBeNull()
      expect(order?.afterBody, 'the message follows the body').toBe(true)
      expect(order?.beforeFooter, 'and comes before the footer').toBe(true)

      // The keyboard: from the top of the card the stops come in the order of the card: its header,
      // its body, the message (its words where they overflow their box, then its Dismiss), its footer.
      // (WebKit on macOS passes over buttons unless the system's keyboard setting asks for them, so
      // there the order above is what holds.)
      if (browserName === 'chromium') {
        await page.locator('.sheet .dialog-header button').focus()
        const part = (): Promise<string> =>
          page.evaluate(() => {
            const here = document.activeElement
            for (const [name, selector] of [
              ['header', '.dialog-header'],
              ['body', '.dialog-body'],
              ['message', '.toast'],
              ['footer', '.dialog-footer']
            ] as const) {
              if (here?.closest(selector)) return name
            }
            return 'outside'
          })
        const stops: string[] = [await part()]
        for (let press = 0; press < 8 && stops.at(-1) !== 'footer'; press += 1) {
          await page.keyboard.press('Tab')
          stops.push(await part())
        }
        const rank = ['header', 'body', 'message', 'footer']
        expect(stops.at(-1), `the stops: ${stops.join(', ')}`).toBe('footer')
        expect(
          stops.every((each, at) => at === 0 || rank.indexOf(each) >= rank.indexOf(stops[at - 1] ?? 'header')),
          `the stops in the card's order: ${stops.join(', ')}`
        ).toBe(true)
        expect(stops, 'the message is a stop of its own').toContain('message')
        // The footer's control is next after the message's Dismiss, and back from it is Dismiss.
        await expect(accept).toBeFocused()
        await page.keyboard.press('Shift+Tab')
        await expect(dismiss).toBeFocused()
      }
      await dismiss.press('Enter')
      await expect(toast).toHaveCount(0)
    })
  }

  // The two rules that rest the message for a person who asked for less motion are not the others'.
  test('rests above the card’s footer when the person asked for less motion', async ({ page }) => {
    await messageOverCard(page, {
      surface: 'ios',
      ratio: 1,
      face: FACES[0],
      at: CLOCKS[0].at,
      reduced: true,
      shot: 'reduced-motion'
    })
  })

  // A phone pads the foot of the card by the platform's inset (the home indicator), so the footer's
  // top is higher than its height says: the message clears that too.
  test('rests above the card’s footer and the inset that pads it', async ({ page }) => {
    await messageOverCard(page, {
      surface: 'ios',
      ratio: 1,
      face: FACES[0],
      at: CLOCKS[0].at,
      inset: 34,
      shot: 'inset'
    })
  })

  // The inset under the footer changes while the card is open (the device turns): the message goes
  // on resting above the footer, whatever the inset has become.
  test('rests above the card’s footer when the inset under it grows while it is open', async ({ page }) => {
    await messageOverCard(page, {
      surface: 'ios',
      ratio: 1,
      face: FACES[0],
      at: CLOCKS[0].at,
      insetLater: 34,
      shot: 'inset-later'
    })
  })

  // A sheet whose decisions are in its body, above a footer that leads elsewhere, draws the message at
  // the head of its body: a message at the foot would lie over the next request's decisions.
  test('draws no message over the decisions in the sheet that holds an item’s decisions', async ({ page }) => {
    await withClockAt(page, CLOCKS[0].at)
    await page.setViewportSize({ width: 320, height: 720 })
    await open(page, 'ios', 'attention', async (loaded) => {
      // A device that may view sessions has items to act on, and an invitation to accept.
      await loaded.evaluate(() => {
        const host = window.krTestHost
        if (host === undefined) throw new Error('no scripted host')
        host.reachAsPhone({ rights: ['session.view'] })
        host.sharing.offer({ session: '3', role: 'controller', live: true })
      })
      await expect(loaded.getByTestId('offers')).toBeVisible()
    })
    await page.getByRole('button', { name: /shared session 3 with you/ }).click()
    await page.getByTestId('accept-offer').click()
    await expect(page.getByTestId('sheet')).toBeHidden()
    const toast = page.locator('.toast')
    await expect(toast).toContainText('Session 3 is shared with you until')
    // Held where it is, as a pointer resting on it holds it, while an item's card is opened over it.
    await toast.dispatchEvent('pointerover', { pointerType: 'mouse', pointerId: 1 })
    await page.locator('.m-list [data-attention]').first().click()
    await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here')
    await expect(toast).toBeVisible()
    expect(await toast.evaluate((element) => element.closest('[role="dialog"]') !== null)).toBe(true)
    const place = await page.evaluate(() => {
      const message = document.querySelector('.toast')?.getBoundingClientRect()
      const body = document.querySelector('.sheet .dialog-body')?.getBoundingClientRect()
      return message === undefined || body === undefined
        ? null
        : { messageTop: message.top, bodyTop: body.top, bodyBottom: body.bottom }
    })
    expect(place, 'the message and the body are drawn').not.toBeNull()
    expect(place?.messageTop, 'the message is at the head of the body').toBeLessThan(
      (place?.bodyTop ?? 0) + ((place?.bodyBottom ?? 0) - (place?.bodyTop ?? 0)) / 2
    )
  })
})

// KR-REQ-13.19: the pill lies over the inbox, so it is sized as the bars are, and focus that goes to
// what is under it brings that into view clear of it. Each case sets its own text size.
test.describe('the pill for a new invitation', () => {
  // The pill lies over the content, so its type is the bars' own: it holds at one and a half times the
  // base size, and what is under it is not given up to a pill that grows with the text.
  test("sets the pill's type in the bars' unit, which holds at one and a half times the base size", async ({
    context
  }) => {
    const sizeAt = async (ratio: number): Promise<number> => {
      const page = await context.newPage()
      try {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await withPill(page)
        return await page.evaluate(() =>
          parseFloat(getComputedStyle(document.querySelector('.sw-new-button') as Element).fontSize)
        )
      } finally {
        await page.close()
      }
    }
    const atTheBase = await sizeAt(1)
    const atOneAndAHalf = await sizeAt(1.5)
    const atTheLargest = await sizeAt(LARGEST)
    expect(atOneAndAHalf, 'the pill grows with the text up to one and a half times').toBeGreaterThan(atTheBase)
    expect(atTheLargest, 'and holds there').toBeCloseTo(atOneAndAHalf, 0)
  })

  // A control that keyboard focus reaches while the pill shows is wholly in view, below the pill. The
  // inbox is scrolled to its end and each control above is focused in turn, last to first, as Shift+Tab
  // goes (the engines differ in which controls Tab stops at, and not in how a focused control is
  // brought into view). A control taller than the room the pill leaves cannot be wholly in view, and
  // is not held to it; the filters are what the check is made of at every size. Twelve invitations
  // have arrived, as a person finds them who has been away from the inbox for a while.
  for (const size of SIZES) {
    for (const face of FACES) {
      test(`brings a control reached by keyboard wholly into view below the pill at the ${size.name} text size${face.suffix}`, async ({
        page
      }) => {
        await withSystemTextScale(page, size.ratio)
        await withFace(page, face.css)
        await page.setViewportSize({ width: 320, height: 720 })
        await withPill(page, { invitations: 12 })
        const controls = 'button:not(.sw-new-button):not([disabled])'
        const count = await page.locator(`.m-main ${controls}`).count()
        const checked: string[] = []
        const hidden: string[] = []
        for (let index = count - 1; index >= 0; index -= 1) {
          const now = await page.evaluate(
            ([at, selector]) => {
              const control = Array.from(document.querySelectorAll<HTMLElement>(`.m-main ${String(selector)}`))[
                Number(at)
              ]
              const pill = document.querySelector('.sw-new-button')
              const area = document.querySelector<HTMLElement>('.m-main')
              if (control === undefined || pill === null || area === null) return null
              control.focus()
              return { moved: document.activeElement === control }
            },
            [index, controls]
          )
          await drawn(page)
          const where = await page.evaluate(
            ([at, selector]) => {
              const control = Array.from(document.querySelectorAll<HTMLElement>(`.m-main ${String(selector)}`))[
                Number(at)
              ]
              const pill = document.querySelector('.sw-new-button')
              const area = document.querySelector<HTMLElement>('.m-main')
              if (control === undefined || pill === null || area === null) return null
              const box = control.getBoundingClientRect()
              const inline = (value: string): number => Number.parseFloat(value) || 0
              return {
                label: (control.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 30) || control.tagName,
                top: box.top,
                bottom: box.bottom,
                below: pill.getBoundingClientRect().bottom,
                end: area.getBoundingClientRect().bottom,
                // What the engine can give a control: the area, less the padding at its foot and the
                // margin the control keeps above itself.
                room:
                  area.clientHeight -
                  inline(getComputedStyle(area).scrollPaddingBottom) -
                  inline(getComputedStyle(control).scrollMarginTop)
              }
            },
            [index, controls]
          )
          // The pill goes when the inbox is scrolled back to its top: nothing is under it then.
          if (now === null || where === null) break
          expect(now.moved, `focus went to ${where.label}`).toBe(true)
          if (where.bottom - where.top > where.room) continue
          checked.push(where.label)
          if (where.top < where.below - 0.5 || where.bottom > where.end + 0.5) {
            const [top, bottom, below, end] = [where.top, where.bottom, where.below, where.end].map((each) =>
              Math.round(each)
            )
            hidden.push(
              `${where.label}: from ${String(top)} to ${String(bottom)}, in view from ${String(below)} to ${String(end)}`
            )
          }
        }
        expect(checked.length, 'controls that fit below the pill and were reached while it showed').toBeGreaterThanOrEqual(3)
        expect(hidden, 'controls that did not come wholly into view below the pill').toEqual([])
        await page.screenshot({ path: shot(`pill-focus-${size.name}${face.shot}`) })
      })
    }
  }

  // The room is the pill's own, measured: when the pill's words need more lines, the room kept clear of
  // it grows with it, and is still its lower edge and the foot of its margin. The pill is measured at
  // rest, not in its entry.
  test('keeps the room it clears in step with the pill when its words need more lines', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await withSystemTextScale(page, 1)
    await page.setViewportSize({ width: 320, height: 720 })
    await withPill(page)
    const now = () =>
      page.evaluate(() => {
        const pill = document.querySelector<HTMLElement>('.sw-new-button')
        const area = document.querySelector<HTMLElement>('.m-main')
        if (pill === null || area === null) return null
        const words = document.createRange()
        words.selectNodeContents(pill)
        return {
          lines: new Set(Array.from(words.getClientRects()).map((line) => Math.round(line.top))).size,
          room: Number.parseFloat(area.style.getPropertyValue('--pill-room')),
          edge: pill.getBoundingClientRect().bottom - area.getBoundingClientRect().top,
          foot: Number.parseFloat(getComputedStyle(pill).marginBlockEnd)
        }
      })
    const one = await now()
    expect(one?.lines, 'lines of words in the pill').toBe(1)
    // The height is a whole number of pixels, so the room is within one of the edge and the foot.
    expect(Math.abs((one?.room ?? Number.NaN) - (one?.edge ?? Number.NaN) - (one?.foot ?? Number.NaN))).toBeLessThan(1)

    await page.addStyleTag({ content: '.sw-new-button { max-inline-size: 6em !important }' })
    await expect.poll(async () => (await now())?.lines ?? 0, 'lines of words in the pill after it narrowed').toBeGreaterThan(1)
    await expect.poll(async () => (await now())?.room ?? 0, 'the room after the pill grew').toBeGreaterThan((one?.room ?? 0) + 10)
    const more = await now()
    expect(Math.abs((more?.room ?? Number.NaN) - (more?.edge ?? Number.NaN) - (more?.foot ?? Number.NaN))).toBeLessThan(1)
  })

  // A sheet that the inbox has open is drawn in the scrolling area but is over the pill, and scrolls
  // inside itself: what is in it keeps no room above itself for the pill.
  test('keeps no room above what is in a sheet that the inbox has open', async ({ page }) => {
    await withSystemTextScale(page, LARGEST)
    await page.setViewportSize({ width: 320, height: 720 })
    await withPill(page)
    await page.evaluate(() => {
      document.querySelector<HTMLElement>('[data-offer]')?.click()
    })
    await expect(page.getByTestId('offer-card')).toBeVisible()
    const margin = (selector: string) =>
      page.evaluate((each) => {
        const element = document.querySelector(each)
        return element === null ? 'none' : getComputedStyle(element).scrollMarginTop
      }, selector)
    expect(Number.parseFloat(await margin('.m-filter')), 'what is under the pill keeps the room').toBeGreaterThan(0)
    expect(await margin('[data-testid="accept-offer"]'), 'a control in the sheet').toBe('0px')
    expect(await margin('[data-testid="offer-card"] li'), 'the words in the sheet').toBe('0px')
  })

  // The pill itself is in view: focus that goes to it, as a screen reader's or a key's does, leaves the
  // inbox where it is and the pill where it is. The room kept clear of the pill is for what is under it.
  for (const size of SIZES) {
    for (const [where, depth] of [
      ['at the end of the inbox', undefined],
      ['a little way down it', 40]
    ] as const) {
      test(`leaves the inbox where it is when focus goes to the pill ${where} at the ${size.name} text size`, async ({
        page
      }) => {
        await withSystemTextScale(page, size.ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await withPill(page, { depth })
        const main = page.locator('.m-main')
        const pill = page.getByRole('button', { name: '1 new invitation' })
        const before = await main.evaluate((element) => element.scrollTop)
        await pill.focus()
        await drawn(page)
        await expect(pill).toBeFocused()
        expect(await main.evaluate((element) => element.scrollTop), 'where the inbox is scrolled to').toBe(before)
      })
    }
  }
})

test.describe('a share that arrives while the sessions are scrolled', () => {
  test.beforeEach(async ({ page }) => {
    await withSystemTextScale(page, LARGEST)
    await page.setViewportSize({ width: 320, height: 720 })
  })

  // KR-REQ-18.13: a share the host lists on a read is drawn above the phone's own sessions, and what
  // the person has scrolled to stays where it is, in both engines.
  test('keeps the session under the finger where it is when a share is drawn above it', async ({ page }) => {
    await page.goto('/harness.html?surface=ios&tab=sessions&sessions=30')
    await expect(page.locator('.m-shell')).toBeVisible()
    await page.evaluate(() => {
      window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
    })
    const main = page.locator('.m-main')
    await expect(main.locator('[data-session]').first()).toBeVisible()
    await main.evaluate((element) => {
      element.scrollTop = 900
    })
    await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(800)
    await drawn(page)

    // The first session in view, by its identity, and where it is drawn.
    const place = (id: string | null) =>
      page.evaluate((wanted) => {
        const scroller = document.querySelector('.m-main') as HTMLElement
        const edge = scroller.getBoundingClientRect().top
        const rows = Array.from(document.querySelectorAll<HTMLElement>('[data-session]'))
        const row =
          wanted === null
            ? rows.find((each) => each.getBoundingClientRect().bottom > edge + 1)
            : rows.find((each) => each.dataset.session === wanted)
        return row === undefined
          ? null
          : { id: row.dataset.session ?? '', top: row.getBoundingClientRect().top, scrolled: scroller.scrollTop }
      }, id)
    const before = await place(null)
    expect(before).not.toBeNull()

    await page.evaluate(() => {
      window.krTestHost?.sharing.hold({ session: '4' })
    })
    await readAgain(page)
    await expect(page.getByTestId('shared-with-you')).toBeAttached()
    await drawn(page)
    const after = await place(before?.id ?? null)
    expect(after, 'the session is still drawn').not.toBeNull()
    expect(
      Math.abs((after?.top ?? Number.NaN) - (before?.top ?? Number.NaN)),
      `the session under the finger kept its place (${JSON.stringify({ before, after })})`
    ).toBeLessThanOrEqual(1)
    expect(after?.scrolled ?? 0, 'the scroll position took up the new rows').toBeGreaterThan(before?.scrolled ?? 0)
  })

  // KR-REQ-18.13: when the share that is in view is the one that goes, the rows beside it are still
  // where they were: the place is kept by another row that is still there.
  test('keeps the rows in view where they are when the share in view is the one that ends', async ({ page }) => {
    await page.goto('/harness.html?surface=ios&tab=sessions')
    await expect(page.locator('.m-shell')).toBeVisible()
    const ids = await page.evaluate(() => {
      const host = window.krTestHost
      if (host === undefined) throw new Error('no scripted host')
      host.reachAsPhone({ rights: ['session.view'] })
      return [3, 4, 5, 6, 7, 8, 9, 10].map((session) => host.sharing.hold({ session: String(session) }).grant.grant_id)
    })
    const main = page.locator('.m-main')
    await expect(page.getByTestId('shared-with-you').getByRole('button')).toHaveCount(8)
    // The person has scrolled until the third share is the first one in view.
    await page.evaluate((id) => {
      const scroller = document.querySelector('.m-main') as HTMLElement
      const row = document.querySelector<HTMLElement>(`[data-share="${id}"]`)
      if (row === null) throw new Error('no such share')
      scroller.scrollTop += row.getBoundingClientRect().top - scroller.getBoundingClientRect().top + 4
    }, ids[2])
    await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(100)
    await drawn(page)

    const place = (id: string) =>
      page.evaluate((wanted) => {
        const row = document.querySelector<HTMLElement>(`[data-share="${wanted}"]`)
        const scroller = document.querySelector('.m-main') as HTMLElement
        return row === null ? null : row.getBoundingClientRect().top - scroller.getBoundingClientRect().top
      }, id)
    const before = await place(ids[3] ?? '')
    expect(before).not.toBeNull()

    // The share in view ends, and two more are listed above it: the list above the rows in view
    // grows by a row, and the row that was first in view is not there to be kept by.
    await page.evaluate((id) => {
      const host = window.krTestHost
      if (host === undefined) throw new Error('no scripted host')
      host.sharing.endShare(id)
      host.sharing.hold({ session: '1' })
      host.sharing.hold({ session: '2' })
    }, ids[2])
    await readAgain(page)
    await expect(page.getByTestId('ended-share')).toHaveCount(1)
    await drawn(page)
    const after = await place(ids[3] ?? '')
    expect(
      Math.abs((after ?? Number.NaN) - (before ?? Number.NaN)),
      `the share beside it kept its place (${JSON.stringify({ before, after })})`
    ).toBeLessThanOrEqual(1)
  })

  // KR-REQ-18.13: a bar above the list that changes height moves the scrolling area and not the
  // list, so what the list does after it is still judged by where its rows are in the area.
  test('keeps the place when the bar above the list changed height before the list did', async ({ page }) => {
    await page.goto('/harness.html?surface=ios&tab=sessions&sessions=30')
    await expect(page.locator('.m-shell')).toBeVisible()
    await page.evaluate(() => {
      window.krTestHost?.reachAsPhone({ rights: ['session.view'] })
    })
    const main = page.locator('.m-main')
    await expect(main.locator('[data-session]').first()).toBeVisible()
    await main.evaluate((element) => {
      element.scrollTop = 900
    })
    await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(800)
    await drawn(page)

    // The first session in view, by its identity, and where it is in the scrolling area.
    const inTheArea = (id: string | null) =>
      page.evaluate((wanted) => {
        const scroller = document.querySelector('.m-main') as HTMLElement
        const edge = scroller.getBoundingClientRect().top
        const rows = Array.from(document.querySelectorAll<HTMLElement>('[data-session]'))
        const row =
          wanted === null
            ? rows.find((each) => each.getBoundingClientRect().bottom > edge + 1)
            : rows.find((each) => each.dataset.session === wanted)
        return row === undefined ? null : { id: row.dataset.session ?? '', top: row.getBoundingClientRect().top - edge }
      }, id)
    const before = await inTheArea(null)
    expect(before).not.toBeNull()

    // The bar grows: the area moves down and gets shorter, and the list in it is as it was.
    await page.evaluate(() => {
      const bar = document.querySelector<HTMLElement>('.m-topbar')
      if (bar === null) throw new Error('no bar')
      bar.style.paddingBlockEnd = '60px'
    })
    await drawn(page)
    await page.evaluate(() => {
      window.krTestHost?.sharing.hold({ session: '4' })
    })
    await readAgain(page)
    await expect(page.getByTestId('shared-with-you')).toBeAttached()
    await drawn(page)
    const after = await inTheArea(before?.id ?? null)
    expect(
      Math.abs((after?.top ?? Number.NaN) - (before?.top ?? Number.NaN)),
      `the session kept its place in the area (${JSON.stringify({ before, after })})`
    ).toBeLessThanOrEqual(1)
  })
})
