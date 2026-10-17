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
    test.describe(`what is shared with a phone on ${surface} at the ${size.name} text size`, () => {
      test.beforeEach(async ({ page }) => {
        await withSystemTextScale(page, size.ratio)
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

        // The control: with the text kept from wrapping the same measure sees the rows run out.
        await page.screenshot({ path: shot(`offers-${surface}-${size.name}`) })
        await stopWrapping(page, ['[data-testid="offers"]'])
        expect(await overrunning(page, '[data-testid="offers"]')).not.toEqual([])
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
        await page.screenshot({ path: shot(`card-${surface}-${size.name}`) })
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
        await page.getByRole('button', { name: 'Attention', exact: true }).click()
        for (const session of ['3', '4']) {
          await page.getByRole('button', { name: new RegExp(`shared session ${session} with you`) }).click()
          await page.getByTestId('accept-offer').click()
          await expect(page.getByTestId('sheet')).toBeHidden()
        }
        // The toast that says so is held while the pointer rests on it, and it lies over the tab bar.
        await page.mouse.move(2, 2)
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

        expect(await overrunning(page, '[data-testid="shared-with-you"]')).toEqual([])
        expect(await unreachable(page, '[data-testid="shared-with-you"]')).toEqual([])
        await page.screenshot({ path: shot(`shared-${surface}-${size.name}`) })
        await stopWrapping(page, ['[data-testid="shared-with-you"]'])
        expect(await overrunning(page, '[data-testid="shared-with-you"]')).not.toEqual([])
      })
    })
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
})
