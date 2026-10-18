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

import { Buffer } from 'node:buffer'

import { expect, test, type Page } from '@playwright/test'

import { overrunning, stopWrapping } from './layout'

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
    ['the hosts when the pairing records could not be opened', '&tab=hosts&pairing_records=unavailable', null],
    [
      'the hosts with one paired',
      '&tab=hosts',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.setPairing({
            hosts: [
              {
                reference: 'studio-reference',
                in_use: false,
                name: 'studio-with-a-long-name-that-has-to-wrap',
                owner: false,
                authority: 'view sessions',
                grant_expires_at_ms: null,
                in_contact: null
              }
            ]
          })
        })
        await expect(page.getByTestId('use-host')).toBeVisible()
      }
    ],
    [
      'the hosts with the question about forgetting one open',
      '&tab=hosts',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.setPairing({
            hosts: [
              {
                reference: 'studio-reference',
                in_use: true,
                name: 'studio-with-a-long-name-that-has-to-wrap',
                owner: false,
                authority: 'view sessions',
                grant_expires_at_ms: null,
                in_contact: null
              }
            ]
          })
        })
        await page.getByTestId('forget-host').click()
        await expect(page.getByTestId('forget-host-ask')).toBeVisible()
      }
    ],
    [
      'the voice screen',
      '&tab=sessions',
      async (page) => {
        await page.getByTestId('voice-entry').click()
        await expect(page.getByRole('button', { name: 'Start voice session' })).toBeVisible()
      }
    ],
    [
      'the question that allows voice',
      '&tab=sessions',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.requireVoiceGrant('PERMISSION_DENIED: name the sessions this call may reach')
        })
        await page.getByTestId('voice-entry').click()
        await expect(page.getByRole('heading', { name: 'Allow voice on this phone' })).toBeVisible()
        await expect(page.getByTestId('voice-scope')).toBeVisible()
      }
    ],
    ['the account', '&tab=account', null],
    ['a session’s conversation', `&session=${SESSION}`, null],
    [
      'a session after an action nobody knows the end of',
      `&session=${SESSION}`,
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.leaveNextSendUnconfirmed()
        })
        await page.getByLabel('Message this session').fill('run the migration')
        await page.getByRole('button', { name: 'Send', exact: true }).click()
        await expect(page.getByRole('button', { name: 'I checked; send anyway' })).toBeVisible()
      }
    ],
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

  // The reason an action has no confirmed outcome, and the way past it, are long for their screen:
  // at the largest size on the narrowest one they wrap, and the button stays inside the composer.
  for (const surface of ['ios', 'android'] as const) {
    test(`keeps the reason nothing is sent, and the way past it, whole on ${surface}`, async ({ page }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      await page.evaluate(() => {
        window.krTestHost?.leaveNextSendUnconfirmed()
      })
      await page.getByLabel('Message this session').fill('run the migration')
      await page.getByRole('button', { name: 'Send', exact: true }).click()
      const release = page.getByRole('button', { name: 'I checked; send anyway' })
      await expect(release).toBeVisible()
      await expect(release).toBeEnabled()

      await release.scrollIntoViewIfNeeded()
      await page.screenshot({
        path: `/tmp/kr-text-size-send-anyway-${surface}-${test.info().project.name}.png`
      })
      const roots = ['.m-hint', '[data-testid="composer-send-anyway"]']
      for (const root of roots) {
        expect(await overrunning(page, root), `lines of ${root} that run past the screen or their box`).toEqual([])
      }
      // The controls: with the text kept from wrapping, the same measure sees each run out.
      await stopWrapping(page, roots)
      for (const root of roots) {
        expect(await overrunning(page, root), `the measure sees ${root} text that cannot wrap`).not.toEqual([])
      }
    })

    test(`lists the action nobody knows the end of beside the next one, whole, on ${surface}`, async ({ page }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      await page.evaluate(() => {
        window.krTestHost?.leaveNextSendUnconfirmed()
      })
      await page.getByLabel('Message this session').fill('run the migration of a very long database name')
      await page.getByRole('button', { name: 'Send', exact: true }).click()
      await page.getByRole('button', { name: 'I checked; send anyway' }).click()

      // The earlier action keeps its own status beside the one sent after it.
      const earlier = page.getByTestId('earlier-actions')
      await expect(earlier).toBeVisible()
      await expect(earlier).toContainText('Outcome unknown')
      // The start of each part of the entry can be scrolled to, as a person scrolls the composer, and
      // is not under the bar at the foot of the screen.
      for (const part of [earlier.locator('.badge'), earlier.locator('li > span').last()]) {
        const covered = await part.evaluate((element) => {
          const composer = element.closest('.m-composer')
          if (composer === null) return true
          composer.scrollTop += element.getBoundingClientRect().top - composer.getBoundingClientRect().top
          const box = element.getBoundingClientRect()
          const top = document.elementFromPoint(box.left + box.width / 2, box.top + 4)
          return top === null || !element.contains(top)
        })
        expect(covered, 'the start of part of the entry is covered').toBe(false)
      }
      await page.screenshot({
        path: `/tmp/kr-text-size-earlier-actions-${surface}-${test.info().project.name}.png`
      })
      expect(await overrunning(page, '[data-testid="earlier-actions"]'), 'lines of the list that run past the screen or their box').toEqual([])
      await stopWrapping(page, ['[data-testid="earlier-actions"]'])
      expect(
        await overrunning(page, '[data-testid="earlier-actions"]'),
        'the measure sees the list text that cannot wrap'
      ).not.toEqual([])
    })
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
      // Everything in the row, and every line of its text, lies inside the screen and inside the
      // row's own box.
      const described = `.m-row[data-session="${SESSION}"]`
      expect(await overrunning(page, described), 'lines of the row that run past the screen or its box').toEqual([])

      // The control: with the text kept from wrapping, the same measure sees it run out of its box.
      await stopWrapping(page, [described])
      expect(await overrunning(page, described), 'the measure sees text that cannot wrap').not.toEqual([])
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

// KR-REQ-13.19: a message shown in passing takes a part of the screen at every text size.
test.describe('a passing message', () => {
  // A passing message is read in passing: at the largest size on the narrowest screen it takes a
  // part of the screen and no more, its words scroll inside it when they are too many, and Dismiss
  // and the message's action stay on the screen, pressable, whatever the words are.
  const OWNER_REQUEST = (hostName: string) => ({
    ceremony: 'touch_id' as const,
    requests: [
      {
        reference: 'request-1',
        host_name: hostName,
        title: 'Pair a new device',
        detail: null,
        value: 'f3c1 46fd',
        facts: [],
        notice: null,
        statement: null,
        reading: null,
        expires_at_ms: Date.now() + 600_000,
        checkable: true
      }
    ]
  })

  /** What the toast takes of the screen, and whether its controls are inside it and the screen. */
  const toastLayout = (page: Page) =>
    page.evaluate(() => {
      const toast = document.querySelector<HTMLElement>('.toast')
      if (toast === null) return null
      const edge = { width: window.innerWidth, height: window.innerHeight }
      const box = toast.getBoundingClientRect()
      const inside = (outer: DOMRect, inner: { left: number; right: number; top: number; bottom: number }) =>
        inner.left >= outer.left - 0.5 &&
        inner.right <= outer.right + 0.5 &&
        inner.top >= outer.top - 0.5 &&
        inner.bottom <= outer.bottom + 0.5
      const screen = new DOMRect(0, 0, edge.width, edge.height)
      const controls = [...toast.querySelectorAll<HTMLElement>('button')].map((button) => {
        const where = button.getBoundingClientRect()
        return {
          name: button.getAttribute('aria-label') ?? button.textContent ?? '',
          onScreen: inside(screen, where),
          inToast: inside(box, where)
        }
      })
      const words = toast.querySelector<HTMLElement>('.toast-text')
      const controlsBox = toast.querySelector<HTMLElement>('.toast-controls')?.getBoundingClientRect()
      const wordsBox = toast.querySelector<HTMLElement>('.toast-main')?.getBoundingClientRect()
      return {
        controlsBeside:
          controlsBox !== undefined && wordsBox !== undefined && controlsBox.top < wordsBox.bottom - 1,
        height: box.height,
        screenHeight: edge.height,
        onScreen: inside(screen, box),
        controls,
        scrolls: words !== null && words.scrollHeight > words.clientHeight + 1,
        wordsHeight: words?.clientHeight ?? 0
      }
    })

  /** Lays the toast out once it has come to rest, and says what it takes of the screen. */
  const settledToast = async (page: Page) => {
    // The toast arrives from below the screen: it is measured once it has come to rest on it.
    await expect.poll(async () => (await toastLayout(page))?.onScreen, { timeout: 10_000 }).toBe(true)
    return await toastLayout(page)
  }

  for (const surface of ['ios', 'android'] as const) {
    // The phone's passing messages say what became of a file; the file's name is the person's, and
    // can be as long as a file name is.
    const FILE = {
      name: `${'a-long-name-for-a-file '.repeat(20)}.png`,
      mimeType: 'image/png',
      buffer: Buffer.from('a picked file')
    }

    test(`keeps a long passing message to part of the screen, with Dismiss in view, on ${surface}`, async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      const opened = page.waitForEvent('filechooser')
      await page.getByRole('button', { name: 'Files', exact: true }).click()
      await (await opened).setFiles(FILE)
      const toast = page.locator('.toast')
      await expect(toast).toContainText('a-long-name-for-a-file')

      const layout = await settledToast(page)
      expect(layout?.height ?? 720, 'the toast takes under half of the screen').toBeLessThan(720 / 2)
      expect(layout?.scrolls, 'words too many for the box scroll inside it').toBe(true)
      await expect(toast.locator('.toast-text'), 'the words box takes the keyboard').toHaveAttribute('tabindex', '0')
      expect(await overrunning(page, '.toast'), 'lines of the message that run past the screen or its box').toEqual([])
      expect(
        layout?.controls.filter((control) => !control.onScreen || !control.inToast).map((control) => control.name),
        'controls of the message that are out of view'
      ).toEqual([])
      expect(layout?.controls.map((control) => control.name)).toEqual(['Dismiss'])
      await toast.getByRole('button', { name: 'Dismiss' }).click({ trial: true, timeout: 2_000 })

      // The words reach their last line by scrolling the box, and the control stays where it is.
      const before = await toast.getByRole('button', { name: 'Dismiss' }).boundingBox()
      await toast.locator('.toast-text').evaluate((element) => {
        element.scrollTop = element.scrollHeight
      })
      expect(await toast.getByRole('button', { name: 'Dismiss' }).boundingBox()).toEqual(before)

      // The control: with the words kept from wrapping, the same measure sees them run out of the box.
      await stopWrapping(page, ['.toast-text'])
      expect(await overrunning(page, '.toast'), 'the measure sees words that cannot wrap').not.toEqual([])

      await toast.getByRole('button', { name: 'Dismiss' }).click()
      await expect(toast).toHaveCount(0)
    })

    test(`keeps the notice of a file with a short name on a few lines at the largest size on ${surface}`, async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      const opened = page.waitForEvent('filechooser')
      await page.getByRole('button', { name: 'Files', exact: true }).click()
      await (await opened).setFiles({ name: 'notes.png', mimeType: 'image/png', buffer: Buffer.from('a picked file') })
      const toast = page.locator('.toast')
      await expect(toast).toContainText('notes.png')
      const layout = await settledToast(page)
      expect(layout?.scrolls, 'the shortened notice needs no scrolling').toBe(false)
      await expect(toast.locator('.toast-text')).not.toHaveAttribute('tabindex')
      expect(layout?.height ?? 720, 'the notice takes under half of the screen').toBeLessThan(720 / 2)
      expect(await overrunning(page, '.toast')).toEqual([])
      expect(layout?.controls.every((control) => control.onScreen && control.inToast)).toBe(true)
    })
  }

  // The desktop's messages offer an action, and the shared toast keeps it and Dismiss in view on a
  // narrow window too, with its words bounded by the screen.
  const LONG_HOST = 'studio-with-a-name-that-is-long-enough-to-fill-a-narrow-window '.repeat(12)
  for (const [name, viewport, host, scale] of [
    ['one row', { width: 1024, height: 768 }, 'studio', 1],
    ['bounded words', { width: 360, height: 640 }, LONG_HOST, 1],
    // The button that names the action is taller than Dismiss at this size, and the words give up
    // the room it takes: the toast stays under half of the screen with it.
    ['bounded words at the largest size', { width: 360, height: 640 }, LONG_HOST, LARGEST]
  ] as const) {
    test(`keeps a passing message with an action in view: ${name}`, async ({ page }) => {
      await withSystemTextScale(page, scale)
      await page.setViewportSize(viewport)
      await page.goto('/harness.html')
      await page.waitForSelector('.app-shell')
      await page.evaluate((view) => {
        window.krTestHost?.setConfirmations(view)
      }, OWNER_REQUEST(host))
      const toast = page.locator('.toast')
      await expect(toast).toContainText('needs your confirmation')
      const layout = await settledToast(page)
      expect(await overrunning(page, '.toast'), 'lines of the message that run past the screen or its box').toEqual([])
      expect(layout?.controls.map((control) => control.name)).toEqual(['Review', 'Dismiss'])
      expect(layout?.controls.every((control) => control.onScreen && control.inToast)).toBe(true)
      if (name === 'one row') {
        // One row: the controls lie beside the words, not under them.
        expect(layout?.controlsBeside, 'the controls are beside the words').toBe(true)
      } else {
        expect(layout?.height ?? 640, 'the toast takes under half of the screen').toBeLessThan(640 / 2)
        expect(layout?.scrolls).toBe(true)
      }
      for (const control of ['Review', 'Dismiss']) {
        await toast.getByRole('button', { name: control }).click({ trial: true, timeout: 2_000 })
      }
    })
  }
})
