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

declare global {
  interface Window {
    /** Lets the start the harness holds be answered. */
    krReleaseStart?: () => void
  }
}

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

/**
 * Sets the page's face to one as wide as the Linux runner draws with, from the page's first frame.
 * The system's own face differs from one platform to the next, and a layout that holds only for the
 * widths of the face it was drawn with does not hold. DejaVu Sans, which the runner draws the page
 * in, sets the same text about a tenth wider across a line than a phone's or a Mac's face does;
 * Verdana is as wide and every Mac has it, with DejaVu Sans after it for the machine that has none.
 */
async function withWideFace(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const css = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'
    const apply = (): boolean => {
      const root = document.documentElement as HTMLElement | null
      if (root === null) return false
      const style = document.createElement('style')
      style.textContent = css
      root.append(style)
      return true
    }
    if (!apply()) {
      new MutationObserver((_, observer) => {
        if (apply()) observer.disconnect()
      }).observe(document, { childList: true })
    }
  })
}

/**
 * How many lines the text of the first element matching `selector` is set on, counted by the tops
 * of the boxes its text fills. An element that is not on the screen is a failure, not a count.
 */
const lineCount = (page: Page, selector: string): Promise<number> =>
  page.evaluate((target) => {
    const element = document.querySelector(target)
    if (element === null) throw new Error(`${target} is not on the screen`)
    const range = document.createRange()
    range.selectNodeContents(element)
    const tops = Array.from(range.getClientRects())
      .filter((rect) => rect.width > 0)
      .map((rect) => Math.round(rect.top))
    return new Set(tops).size
  }, selector)

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
      'the voice screen with what the last call left',
      '&tab=sessions',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.setVoiceWarning(
            'The last call found that this voice service has no such call for this account. You can start another, and it may end the same way.'
          )
          window.krTestHost?.oweVoice({
            words:
              'The host did not confirm that it withdrew the grant: the host could not be reached in time.'
          })
          window.krTestHost?.oweVoice({
            kind: 'service_close',
            words:
              'The voice service has not confirmed that it closed the call that Your Mac started.'
          })
        })
        await page.getByTestId('voice-entry').click()
        await expect(page.getByRole('status', { name: 'The last call' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Start voice session' })).toBeVisible()
      }
    ],
    [
      'a voice call that is running, with a request it did not act on',
      '&tab=sessions',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.holdAVoiceCall()
          window.krTestHost?.announceVoiceDelegation('item_a1')
          window.krTestHost?.setVoiceHost('lost')
        })
        await page.getByTestId('voice-entry').click()
        await expect(page.getByRole('button', { name: 'End session' })).toBeVisible()
        await expect(page.getByText('Not done. The voice was told so.')).toBeVisible()
      }
    ],
    [
      'the voice screen while the device is setting a call up',
      '&tab=sessions',
      async (page) => {
        await page.evaluate(() => {
          window.krTestHost?.settingUpAVoiceCall()
        })
        await page.getByTestId('voice-entry').click()
        await expect(page.getByRole('button', { name: 'End the call' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Start voice session' })).toHaveCount(0)
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

    // What the last call left, and a call that runs with a request this version did not act on,
    // at the default size and at the largest: every line stays inside its box, and the screenshot
    // is kept for a person to look at.
    for (const [size, ratio] of [['default', 1], ['largest', LARGEST]] as const) {
      test(`keeps the voice screen with what the last call left, and a running voice call, whole at the ${size} size on ${surface}`, async ({
        page
      }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: size === 'default' ? 390 : 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
        await page.evaluate(() => {
          window.krTestHost?.setVoiceWarning(
            'The last call found that this voice service has no such call for this account. You can start another, and it may end the same way.'
          )
          window.krTestHost?.oweVoice({
            words:
              'The host did not confirm that it withdrew the grant: the host could not be reached in time.'
          })
          window.krTestHost?.oweVoice({
            kind: 'service_close',
            words:
              'The voice service has not confirmed that it closed the call that Your Mac started.'
          })
        })
        await page.getByTestId('voice-entry').click()
        const left = page.getByRole('status', { name: 'The last call' })
        await expect(left).toBeVisible()
        await page.screenshot({
          path: `/tmp/kr-voice-aftermath-${size}-${surface}-${test.info().project.name}.png`,
          fullPage: true
        })
        expect(await overrunning(page, '.kr-voice__aftermath'), 'lines of what the last call left that run past their box').toEqual([])
        expect(await overrunning(page, '.kr-voice__note'), 'notes that run past their box').toEqual([])

        // A call is held by the device, so a screen shown now finds it running.
        await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
        await page.evaluate(() => {
          window.krTestHost?.holdAVoiceCall()
          window.krTestHost?.announceVoiceDelegation('item_a1')
          window.krTestHost?.setVoiceHost('lost')
        })
        await page.getByTestId('voice-entry').click()
        const told = page.getByText('Not done. The voice was told so.')
        await expect(told).toBeVisible()
        await told.scrollIntoViewIfNeeded()
        await page.screenshot({
          path: `/tmp/kr-voice-call-${size}-${surface}-${test.info().project.name}.png`,
          fullPage: true
        })
        expect(await overrunning(page, '.kr-voice__delegation'), 'lines of a request row that run past their box').toEqual([])
        expect(await overrunning(page, '.kr-voice__refusal'), 'lines of a notice that run past their box').toEqual([])
      })
    }

    // The screen while the device makes a call that has no name yet, at the default size and at the
    // largest: the line that says so and the one control stay inside their boxes, the control is
    // reachable, and ending it hands the screen back to the choice.
    for (const [size, ratio] of [['default', 1], ['largest', LARGEST]] as const) {
      test(`keeps the voice screen whole while a call is being set up at the ${size} size on ${surface}`, async ({
        page
      }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: size === 'default' ? 390 : 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
        await page.evaluate(() => {
          window.krTestHost?.settingUpAVoiceCall()
        })
        await page.getByTestId('voice-entry').click()
        const end = page.getByRole('button', { name: 'End the call' })
        await expect(end).toBeVisible()
        await page.screenshot({
          path: `/tmp/kr-voice-setup-${size}-${surface}-${test.info().project.name}.png`,
          fullPage: true
        })
        expect(await overrunning(page, '.kr-voice__note'), 'lines of the setup note that run past their box').toEqual([])
        expect(await overrunning(page, '.kr-voice__control'), 'a control label that runs past its box').toEqual([])

        // The end is answered at once and the device is still busy: the screen says so, offers
        // nothing to press, and gives way to the choice when the device is done.
        await end.click()
        await expect(page.getByRole('heading', { name: 'Ending a voice session' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'End the call' })).toHaveCount(0)
        await page.screenshot({
          path: `/tmp/kr-voice-ending-${size}-${surface}-${test.info().project.name}.png`,
          fullPage: true
        })
        expect(await overrunning(page, '.kr-voice__note'), 'lines of the ending note that run past their box').toEqual([])
        await page.evaluate(() => {
          window.krTestHost?.endVoiceCall({ cause: 'requested', words: 'You ended the call.' })
        })
        await expect(page.getByRole('button', { name: 'Start voice session' })).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Start a voice session' })).toBeFocused()
      })
    }

    // The screen's own start while the host has not answered, at the default size and at the
    // largest: the control that gives it up is on screen without scrolling, inside its box, and
    // says the end has begun once it is pressed. The choice is the person's again when the start
    // is over.
    for (const [size, ratio] of [['default', 1], ['largest', LARGEST]] as const) {
      test(`offers the end of its own start while the host has not answered at the ${size} size on ${surface}`, async ({
        page
      }) => {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: size === 'default' ? 390 : 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
        await page.evaluate(() => {
          window.krReleaseStart = window.krTestHost?.holdVoiceStart()
        })
        await page.getByTestId('voice-entry').click()
        const start = page.getByRole('button', { name: 'Start voice session' })
        await start.scrollIntoViewIfNeeded()
        await start.click()

        const end = page.getByRole('button', { name: 'End the call' })
        await expect(end).toBeInViewport()
        await expect(page.getByRole('button', { name: 'Starting…' })).toBeDisabled()
        // The word and its ellipsis are one thing: the ellipsis never sits on a line of its own.
        expect(await lineCount(page, '.kr-voice__start'), 'the start label on one line').toBe(1)
        await page.screenshot({
          path: `/tmp/kr-voice-own-start-${size}-${surface}-${test.info().project.name}.png`
        })
        expect(await overrunning(page, '.kr-voice__control'), 'a control label that runs past its box').toEqual([])
        expect(await overrunning(page, '.kr-voice__start'), 'the start label that runs past its box').toEqual([])

        await end.click()
        const ending = page.getByRole('button', { name: 'Ending…' })
        await expect(ending).toBeDisabled()
        await expect(ending).toBeInViewport()
        // Focus is on the words that say the end has begun, not on the control that was pressed and is
        // now disabled, and the page did not move to put it there.
        await expect(page.getByText('This device is ending its call.')).toBeFocused()
        await expect(page.getByText('This device is ending its call.')).toBeInViewport()
        expect(await overrunning(page, '.kr-voice__note'), 'the ending note that runs past its box').toEqual([])
        await page.screenshot({
          path: `/tmp/kr-voice-own-start-ending-${size}-${surface}-${test.info().project.name}.png`
        })
        expect(await overrunning(page, '.kr-voice__control'), 'the ending label that runs past its box').toEqual([])

        await page.evaluate(() => {
          window.krReleaseStart?.()
        })
        await expect(page.getByRole('button', { name: 'Start voice session' })).toBeEnabled()
        await expect(page.getByRole('button', { name: 'Ending…' })).toHaveCount(0)
        // The words that had focus are gone with the start, and focus is on the control that starts
        // again, not on the page.
        await expect(page.getByRole('button', { name: 'Start voice session' })).toBeFocused()
      })
    }

    // The control that was pressed goes with the screen it was on, and focus left on nothing sends a
    // keyboard or screen-reader user back to the top of the document. In both engines, the call
    // this screen's own start began takes focus on its heading.
    test(`puts focus on the call screen's heading after its own start on ${surface}`, async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
      await page.getByTestId('voice-entry').click()
      const start = page.getByRole('button', { name: 'Start voice session' })
      await start.scrollIntoViewIfNeeded()
      await start.click()

      await expect(page.getByRole('heading', { name: 'Voice session' })).toBeFocused()
    })

    // The same start, in a face as wide as the runner's: the words that say the end has begun take
    // more lines than in a phone's face, and the control that was pressed and the words together are taller than the screen
    // they are on. The control stays on the screen, as the words are brought into view only as far
    // as that allows.
    test(`keeps the control that gives a start up on the screen when the words beside it need more than the screen, in a wide face, on ${surface}`, async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await withWideFace(page)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
      await page.evaluate(() => {
        window.krReleaseStart = window.krTestHost?.holdVoiceStart()
      })
      await page.getByTestId('voice-entry').click()
      const start = page.getByRole('button', { name: 'Start voice session' })
      await start.scrollIntoViewIfNeeded()
      await start.click()

      const end = page.getByRole('button', { name: 'End the call' })
      await expect(end).toBeInViewport()
      await expect(page.getByRole('button', { name: 'Starting…' })).toBeDisabled()
      await page.screenshot({
        path: `/tmp/kr-voice-own-start-wide-${surface}-${test.info().project.name}.png`
      })
      expect(await lineCount(page, '.kr-voice__start'), 'the start label on one line').toBe(1)
      await end.click()
      const ending = page.getByRole('button', { name: 'Ending…' })
      await expect(ending).toBeDisabled()
      const words = page.getByText('This device is ending its call.')
      await expect(words).toBeFocused()

      // The face is the one drawn, not only the one named: a machine with neither face would set the
      // page in the fallback, narrower than either, and would fail further down for its heights, not
      // for its face.
      const drawnWide = await page.evaluate(() => {
        const context = document.createElement('canvas').getContext('2d')
        if (context === null) return false
        const sample = 'This device is ending its call. This screen changes when that is done.'
        context.font = '16px Verdana, "DejaVu Sans", monospace'
        const wide = context.measureText(sample).width
        context.font = '16px monospace'
        return wide !== context.measureText(sample).width
      })
      expect(drawnWide, 'a wide face is installed').toBe(true)
      // The case is the form it says it is: the control and the words together are taller than the
      // part of the screen that scrolls, so it cannot go on passing after it has stopped covering
      // that form. An element that is not there is a failure, not a measure of nothing.
      const room = await page.evaluate(() => {
        const box = (selector: string): DOMRect => {
          const found = document.querySelector(selector)
          if (found === null) throw new Error(`${selector} is not on the screen`)
          return found.getBoundingClientRect()
        }
        const control = box('.kr-voice__control--end')
        const note = box('.kr-voice__note[tabindex="-1"]')
        return { needed: note.bottom - control.top, visible: box('.m-main').height }
      })
      expect(room.needed, 'the control and the words are taller than the part of the screen that scrolls').toBeGreaterThan(
        room.visible
      )

      // Whole, give or take a sub-point.
      await expect(ending).toBeInViewport({ ratio: 0.99 })
      await expect(words).toBeInViewport()
      await page.screenshot({
        path: `/tmp/kr-voice-own-start-ending-wide-${surface}-${test.info().project.name}.png`
      })
      expect(await overrunning(page, '.kr-voice__control'), 'the ending label that runs past its box').toEqual([])

      await page.evaluate(() => {
        window.krReleaseStart?.()
      })
      await expect(page.getByRole('button', { name: 'Start voice session' })).toBeFocused()
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

  // KR-REQ-13.19: the text of a card keeps more than half of a screen 320 points wide at the largest
  // size on every tab. Spacing is measured in the bars' unit, so it grows with the text up to one and a
  // half times the base size and stops there: grown without a bound, the gutters of the screen and the
  // insets of a row take nearly two thirds of the screen, and the words of the row break inside
  // themselves.
  const CARDS = [
    ['the attention inbox', 'attention', '.m-row'],
    ['the session list', 'sessions', '.m-row'],
    ['the hosts', 'hosts', '.m-row'],
    ['the account', 'account', '.account-panel > .card']
  ] as const

  for (const surface of ['ios', 'android'] as const) {
    for (const [name, tab, card] of CARDS) {
      test(`keeps more than half of the screen for the text of a card on ${name} on ${surface}`, async ({ page }) => {
        await withSystemTextScale(page, LARGEST)
        await page.setViewportSize({ width: 320, height: 720 })
        await page.goto(`/harness.html?surface=${surface}&tab=${tab}`)
        await expect(page.locator(card).first()).toBeVisible()
        const column = await page.locator(card).first().evaluate((each) => {
          const style = getComputedStyle(each)
          const around =
            parseFloat(style.paddingLeft) +
            parseFloat(style.paddingRight) +
            parseFloat(style.borderLeftWidth) +
            parseFloat(style.borderRightWidth)
          return each.getBoundingClientRect().width - around
        })
        expect(column / 320, 'the share of the screen the card keeps for its text').toBeGreaterThan(0.5)
        await page.screenshot({ path: `/tmp/kr-text-size-card-${tab}-${surface}-${test.info().project.name}.png` })
      })
    }
  }

  test('stops the gutters of every tab and the insets of its cards at one and a half times the base size', async ({
    context
  }) => {
    // Each size gets a page of its own, so the only text size a page has is the one it was asked for.
    const spacingAt = async (ratio: number): Promise<Record<string, { gutter: number; inset: number }>> => {
      const page = await context.newPage()
      try {
        await withSystemTextScale(page, ratio)
        await page.setViewportSize({ width: 320, height: 720 })
        const found: Record<string, { gutter: number; inset: number }> = {}
        for (const [, tab, card] of CARDS) {
          await page.goto(`/harness.html?surface=ios&tab=${tab}`)
          await expect(page.locator(card).first()).toBeVisible()
          found[tab] = await page.evaluate((selector) => {
            const inline = (element: Element | null): number =>
              element === null ? Number.NaN : parseFloat(getComputedStyle(element).paddingLeft)
            return {
              gutter: inline(document.querySelector('.m-main')),
              inset: inline(document.querySelector(selector))
            }
          }, card)
        }
        return found
      } finally {
        await page.close()
      }
    }
    const atTheBase = await spacingAt(1)
    const atOneAndAHalf = await spacingAt(1.5)
    const atTheLargest = await spacingAt(LARGEST)
    for (const [name, tab] of CARDS) {
      for (const part of ['gutter', 'inset'] as const) {
        const at = (found: typeof atTheBase): number => found[tab]?.[part] ?? Number.NaN
        expect(at(atOneAndAHalf), `the ${part} of ${name} grows with the text up to one and a half times`).toBeGreaterThan(
          at(atTheBase)
        )
        expect(at(atTheLargest), `the ${part} of ${name} holds there`).toBeCloseTo(at(atOneAndAHalf), 0)
      }
    }
  })

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
