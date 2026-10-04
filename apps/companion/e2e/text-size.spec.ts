/**
 * The phone's text follows the person's text size, and every control stays reachable at the
 * largest size, on the narrowest screen.
 *
 * On iOS the web view carries the person's text size to the page as `--text-scale`, the ratio of
 * the system's body text to its size at the default setting (`src/mobile/text-size.ts`), and the
 * root's font size is multiplied by it; on Android the web view multiplies the root itself. These
 * tests set the ratio directly, as the web view's answer, and hold what the page does with it in
 * both engines. That the real web views give the page the size, and a new one when it changes while
 * the application runs, is held on the simulator and the emulator by `e2e/system-text-size.sh` and `e2e/system-text-size-android.sh`.
 */

import { expect, test, type Page } from '@playwright/test'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

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

const rootSize = (page: Page): Promise<number> =>
  page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize))

// KR-REQ-13.19: the root's text is the platform's, multiplied by the system's factor.
test.describe('the page follows the system text size', () => {
  test('keeps the root at the platform’s size at the default and multiplies it by the system’s factor', async ({
    page
  }) => {
    await page.goto('/harness.html?surface=ios')
    expect(await rootSize(page)).toBe(16)
    for (const ratio of [0.8235, 1.1765, 1.6471, LARGEST]) {
      await page.evaluate((value) => {
        document.documentElement.style.setProperty('--text-scale', String(value))
      }, ratio)
      expect(await rootSize(page), `at ${ratio}`).toBeCloseTo(16 * ratio, 1)
    }
    // Taken away again, the root is what it was.
    await page.evaluate(() => {
      document.documentElement.style.removeProperty('--text-scale')
    })
    expect(await rootSize(page)).toBe(16)
  })

  test('grows a line of the conversation with it, from the first frame', async ({ page }) => {
    const line = (): ReturnType<Page['getByText']> =>
      page.getByText('Find why the reconnect test is flaky.')
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
    const normal = (await line().boundingBox())?.height ?? 0
    expect(normal).toBeGreaterThan(0)

    await withSystemTextScale(page, LARGEST)
    await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
    const large = (await line().boundingBox())?.height ?? 0
    expect(large, 'a line of the conversation at the largest size').toBeGreaterThan(normal * 1.3)
    expect(await rootSize(page)).toBeCloseTo(16 * LARGEST, 1)
  })

  test('leaves a desktop browser and the platform’s own scaling alone: it adds no ratio of its own', async ({
    page
  }) => {
    await page.goto('/harness.html?surface=ios')
    expect(await page.evaluate(() => document.documentElement.style.getPropertyValue('--text-scale'))).toBe('')
    expect(await page.evaluate(() => document.body.children.length)).toBeGreaterThan(0)
  })
})

// KR-REQ-13.19: at the largest size on the narrowest screen, nothing runs past the screen's edge,
// every control can be reached and pressed, and the two bars keep room for what they are the bars
// of: they hold their size at one and a half times the base size, as the platforms' own bars do.
test.describe('at the largest text size on a screen 320 points wide', () => {
  const SCREENS: readonly (readonly [string, string, ((page: Page) => Promise<void>) | null])[] = [
    ['the attention inbox', '&tab=attention', null],
    ['the session list', '&tab=sessions', null],
    ['the hosts', '&tab=hosts', null],
    ['the account', '&tab=account', null],
    ['a session’s conversation', `&session=${SESSION}`, null],
    [
      'a session’s terminal',
      `&session=${SESSION}`,
      async (page) => {
        await page.getByRole('tab', { name: 'Terminal' }).click()
        await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      }
    ],
    [
      'the settings over a session',
      `&session=${SESSION}`,
      async (page) => {
        await page.getByRole('button', { name: 'Settings' }).click()
        await expect(page.getByRole('dialog')).toBeVisible()
      }
    ]
  ]

  for (const surface of ['ios', 'android'] as const) {
    for (const [name, address, open] of SCREENS) {
      test(`keeps ${name} whole and every control on it reachable on ${surface}`, async ({ page }) => {
        await withSystemTextScale(page, LARGEST)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}${address}`)
        await expect(page.locator('.m-shell')).toBeVisible()
        if (open !== null) await open(page)

        const across = await page.evaluate(() => ({
          page: document.documentElement.scrollWidth,
          screen: window.innerWidth
        }))
        expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)

        // What a person can touch: the enabled controls the page shows, inside the dialog when one
        // is open. Each is scrolled to, and pressed in a trial that stops short of the press: it
        // fails where something else would take the touch.
        const scope = open !== null && name.startsWith('the settings') ? page.getByRole('dialog') : page.locator('body')
        const controls = scope.locator(
          'button:visible:not([disabled]), a[href]:visible, textarea:visible:not([disabled]), input:visible:not([disabled]), [role="tab"]:visible'
        )
        const count = await controls.count()
        expect(count, 'controls found on the screen').toBeGreaterThan(0)
        const unreachable: string[] = []
        for (let index = 0; index < count; index += 1) {
          const control = controls.nth(index)
          const label = (
            (await control.getAttribute('aria-label')) ??
            (await control.innerText().catch(() => ''))
          )
            .replace(/\s+/g, ' ')
            .trim()
            .slice(0, 40)
          try {
            await control.click({ trial: true, timeout: 2_000 })
          } catch (failure) {
            unreachable.push(`${label || 'a control with no name'}: ${String(failure).split('\n')[0]}`)
          }
        }
        expect(unreachable, 'controls a touch cannot reach').toEqual([])
      })
    }
  }

  // The host's own words are the row's text, and a title or a line can hold a long word: at the
  // largest size on the narrowest screen each line of a described row stays inside the row.
  for (const surface of ['ios', 'android'] as const) {
    test(`keeps what the host says about a session inside its row on ${surface}`, async ({ page }) => {
      await withSystemTextScale(page, LARGEST)
      await page.addInitScript((id) => {
        let held: Window['krTestHost']
        Object.defineProperty(window, 'krTestHost', {
          configurable: true,
          get: () => held,
          set: (controls: Window['krTestHost']) => {
            held = controls
            controls?.describe(id, {
              title: 'Pairing-code-entry-and-host-approval-flow',
              source: 'generated',
              activity_text: 'Checks/the/code-entry/flow/and/host/approval/screen',
              freshness: 'stale'
            })
          }
        })
      }, SESSION)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
      const row = page.locator(`.m-row[data-session="${SESSION}"]`)
      await expect(row.getByTestId('description-freshness')).toBeVisible()
      const outside = await row.evaluate((element) => {
        const edge = element.getBoundingClientRect().right
        return [...element.querySelectorAll('span')]
          .filter((span) => span.getBoundingClientRect().right > edge + 0.5)
          .map((span) => span.textContent?.slice(0, 40) ?? '')
      })
      expect(outside, 'lines of the row that run past its edge').toEqual([])
    })
  }

  // With the text at its largest, Send beside the message field would leave the field a few letters
  // wide: Send goes on a row of its own instead, and the field keeps room to type in.
  for (const surface of ['ios', 'android'] as const) {
    test(`keeps the message field wide enough to type in, with Send on a row of its own, on ${surface}`, async ({ page }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      const field = page.getByLabel('Message this session')
      await field.fill('hello there')
      const send = page.getByRole('button', { name: 'Send' })
      const fieldBox = await field.boundingBox()
      const sendBox = await send.boundingBox()
      expect(fieldBox?.width ?? 0, 'the field is wide enough to read what is typed').toBeGreaterThan(150)
      const fieldTop = fieldBox?.y ?? 0
      const fieldBottom = fieldTop + (fieldBox?.height ?? 0)
      const sendTop = sendBox?.y ?? 0
      const sendBottom = sendTop + (sendBox?.height ?? 0)
      expect(sendTop >= fieldBottom - 1 || sendBottom <= fieldTop + 1, 'Send is not beside the field').toBe(true)
    })
  }

  test('holds the two bars at one and a half times the base size, with the rest of the screen left to the content', async ({
    context
  }) => {
    // Each size gets a page of its own, so the only text size a page has is the one it was asked for.
    const barsAt = async (ratio: number): Promise<{ top: number; bottom: number }> => {
      const page = await context.newPage()
      try {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto('/harness.html?surface=ios&tab=sessions')
        await expect(page.locator('.m-topbar')).toBeVisible()
        expect(await rootSize(page), `the root text at ${ratio}`).toBeCloseTo(16 * ratio, 1)
        return await page.evaluate(() => ({
          top: document.querySelector('.m-topbar')?.getBoundingClientRect().height ?? 0,
          bottom: document.querySelector('.m-tabbar')?.getBoundingClientRect().height ?? 0
        }))
      } finally {
        await page.close()
      }
    }
    const atTheBase = await barsAt(1)
    const atOneAndAHalf = await barsAt(1.5)
    const atTheLargest = await barsAt(LARGEST)
    expect(atOneAndAHalf.top, 'the top bar grows up to one and a half times').toBeGreaterThan(atTheBase.top)
    expect(atTheLargest.top).toBeCloseTo(atOneAndAHalf.top, 0)
    expect(atTheLargest.bottom).toBeCloseTo(atOneAndAHalf.bottom, 0)
    expect(atTheLargest.top + atTheLargest.bottom, 'the bars together').toBeLessThan(720 * 0.4)
  })
})
