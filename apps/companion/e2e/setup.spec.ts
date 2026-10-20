/**
 * The setup assistant in a real browser engine.
 *
 * What these cover that a component test cannot is everything that needs layout and a renderer:
 * the single path through the steps at a real window size and at a narrow one, the disclosure that
 * opens with a row transition, the colour modes, and the focus a sheet takes and gives back.
 *
 * Every screenshot goes under `/tmp` and is named for the requirement row it evidences.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { overrunning } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The windows the layout cases are held in: a desktop's and a phone's. */
const WINDOWS = [
  [1280, 720],
  [390, 844]
] as const

/** The text sizes they are held at. */
const TEXT_SIZES = [
  ['default', 1],
  ['largest', LARGEST]
] as const

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return `/tmp/kr-companion-${name}.png`
}

/**
 * One screenshot of the whole step, as a person sees it.
 *
 * The window is made tall enough to hold the step rather than the page being stitched together,
 * because the controls are a floating bar over the content and a stitched capture would show it
 * somewhere it never is.
 */
async function capture(page: Page, name: string): Promise<void> {
  const size = page.viewportSize() ?? { width: 1280, height: 720 }
  const needed = await page.evaluate(() => document.documentElement.scrollHeight)
  await page.setViewportSize({ width: size.width, height: Math.min(4000, Math.max(size.height, needed + 40)) })
  await page.screenshot({ path: shot(name) })
  await page.setViewportSize(size)
}

/**
 * Where the harness bundle is served from.
 *
 * The suite's own server is the default. `KR_COMPANION_HARNESS_URL` points a run at a bundle
 * somewhere else, which is what a machine running two checkouts of this package at once needs:
 * the preview port is fixed, and a run that reused the other checkout's server would be testing
 * the other checkout's interface.
 *
 * Pick the port with the fetch standard's blocked list in front of you. A browser refuses to
 * navigate to one of those ports at all, and it refuses before anything reaches the server, so the
 * run looks like a server that is not answering while `curl` fetches the same address happily. The
 * engines do not block the same set: 4190 is on WebKit's list and not on Chromium's, which reads
 * as one engine being broken when it is the one following the standard.
 */
const HARNESS =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    ?.KR_COMPANION_HARNESS_URL ?? '/harness.html'

async function openSetup(page: Page): Promise<void> {
  await page.goto(HARNESS)
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: 'Set up this Mac' }).click()
  await page.getByTestId('setup').waitFor()
  await page.getByTestId('setup-identity').waitFor()
}

async function step(page: Page, name: string): Promise<void> {
  await page.getByTestId(`setup-step-${name}`).click()
  await page.getByTestId(`setup-panel-${name}`).waitFor()
}

test.describe('the first-start assistant', () => {
  test('checks the application identity before it guides a single permission', async ({ page }) => {
    await openSetup(page)
    const identity = page.getByTestId('setup-identity')
    await expect(identity.getByRole('heading', { name: 'to.kala.reach', exact: true })).toBeVisible()
    await expect(identity).toContainText('Stable identity')
    await expect(page.getByTestId('setup-ceiling-identity')).toContainText(
      'perform the operation the permission guards'
    )
    // The identity is the first step, and the flow starts on it.
    await expect(page.getByTestId('setup-step-identity')).toHaveAttribute('aria-current', 'step')
    await capture(page, 'setup-identity-03.28')
  })

  test('guides each macOS category separately, with the route and the ceiling', async ({
    page
  }) => {
    await openSetup(page)
    await step(page, 'permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      await expect(page.getByTestId(`setup-permission-${pane}`)).toBeVisible()
      await expect(page.getByTestId(`setup-route-${pane}`)).toContainText('System Settings')
      await expect(page.getByTestId(`setup-route-${pane}`)).toContainText(
        'this switch cannot be set from here'
      )
    }
    await expect(page.getByTestId('setup-caveat-full_disk_access')).toContainText(
      'does not stand in for the others'
    )
    await expect(page.getByTestId('setup-permission-microphone')).toContainText('for voice')
    await expect(page.getByTestId('setup-permission-remote_desktop')).toContainText(
      'System Settings → Privacy & Security → Remote Desktop'
    )
    await capture(page, 'setup-permissions-03.28')
  })

  test('shows a state per capability with what produced it', async ({ page }) => {
    await openSetup(page)
    await step(page, 'capabilities')
    await expect(page.getByTestId('setup-state-desktop.screen_capture')).toHaveText(
      'Permission required'
    )
    await expect(page.getByTestId('setup-state-desktop.application_launch')).toHaveText('Ready')
    await expect(page.getByTestId('setup-state-desktop.input_injection')).toHaveText('Not checked')
    await page.getByTestId('setup-evidence-toggle-desktop.screen_capture').click()
    const evidence = page
      .getByTestId('setup-capability-desktop.screen_capture')
      .locator('.setup-evidence')
    await expect(evidence).toHaveAttribute('data-open', 'true')
    // And while it was closed, nothing in it was in the accessibility tree.
    const hidden = page
      .getByTestId('setup-capability-desktop.accessibility')
      .locator('.setup-evidence')
    await expect(hidden).toHaveAttribute('aria-hidden', 'true')
    await expect(evidence).toContainText('a check run in this execution context')
    await expect(evidence).toContainText('/usr/sbin/screencapture')
    await expect(evidence).toContainText('the tool is replaced')
    // The disclosure is a transition, so the screenshot waits for it to settle rather than
    // catching it halfway and calling that the design.
    await expect
      .poll(async () => evidence.evaluate((node) => getComputedStyle(node).opacity), {
        timeout: PRESENTATION_DEADLINE
      })
      .toBe('1')
    await capture(page, 'setup-capabilities-03.29')
  })

  test('never reports a grant the host cannot see', async ({ page }) => {
    await openSetup(page)
    const tally = page.getByTestId('setup-tally')
    await expect(tally).toContainText('3 of 6 established')
    await expect(tally).toContainText('1 not checked')
    // Granting one does not move any of the others.
    await page.evaluate(() => {
      window.krTestHost?.grantPermission('desktop.screen_capture')
    })
    await step(page, 'capabilities')
    await page.getByTestId('setup-recheck').click()
    await expect(page.getByTestId('setup-state-desktop.screen_capture')).toHaveText('Ready')
    await expect(page.getByTestId('setup-state-desktop.accessibility')).toHaveText(
      'Permission required'
    )
    await expect(page.getByTestId('setup-state-desktop.input_injection')).toHaveText('Not checked')
  })

  test('declares what each check does, and gives the focus back when the sheet closes', async ({
    page
  }) => {
    await openSetup(page)
    await step(page, 'permissions')
    const opener = page.getByTestId('setup-explain-checks')
    // Opened from the keyboard, because that is the path where giving the focus back matters and
    // because one of these engines deliberately does not focus a button that was clicked.
    await opener.focus()
    await page.keyboard.press('Enter')
    const sheet = page.getByTestId('sheet')
    // Arrived, rather than merely present. The engine calls the surface visible from the instant it
    // mounts, while it is still the whole of its own height below the fold, so everything below
    // would otherwise be read off a surface that is still travelling — including the picture.
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    await expect(page.getByTestId('setup-effects')).toContainText('removes it before answering')
    await expect(page.getByTestId('setup-effects')).toContainText(
      'only inside a test context of its own'
    )
    await expect(sheet).toHaveAttribute('aria-modal', 'true')
    // The focus is inside the sheet while it is open. The surface takes it once it is on the
    // screen, which is a moment of the application's choosing, so this asks until it is true.
    await expect
      .poll(async () => sheet.evaluate((node) => node.contains(document.activeElement)))
      .toBe(true)
    await capture(page, 'setup-effects-03.30')

    await page.keyboard.press('Escape')
    // Escape is taken at once and the surface then leaves over as many frames as the machine gives
    // it, so both of these wait for the state that follows rather than for a length of time. A run
    // that reaches the deadline prints the sheet it is still looking at, and its `data-open` and
    // `data-presentation` say whether the dismissal was taken and the surface merely had not
    // finished leaving.
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
    await expect(opener).toBeFocused({ timeout: PRESENTATION_DEADLINE })
  })

  test('asks for no account anywhere on the path', async ({ page }) => {
    await openSetup(page)
    for (const name of ['permissions', 'capabilities', 'host', 'ready']) {
      await step(page, name)
      const text = (await page.getByTestId(`setup-panel-${name}`).textContent()) ?? ''
      expect(text).not.toMatch(/sign in|sign up|create an account|card|subscription/i)
    }
    await expect(page.getByTestId('setup-panel-ready')).toContainText(
      'no Cloudflare, Stripe, Firebase or Apple developer account'
    )
    await capture(page, 'setup-accounts-26.42')
  })

  test('offers the two hosts and the terminal profile separately, all off', async ({ page }) => {
    await openSetup(page)
    await step(page, 'host')
    for (const id of ['gui_host', 'headless_host', 'terminal_profile']) {
      const card = page.getByTestId(`setup-install-${id}`)
      await expect(card.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
    }
    await expect(page.getByTestId('setup-sleep-now')).toContainText('It is off.')
    await expect(page.getByTestId('setup-sleep-off')).toContainText('set now')
    await expect(page.getByTestId('setup-sleep')).toContainText(
      'Setting up KalaReach does not change it'
    )
    await expect(page.getByTestId('setup-model-size')).toContainText('1.6 GB')
    await expect(page.getByTestId('setup-model')).toContainText('Nothing is fetched until you ask')
    await capture(page, 'setup-host-03.28')
  })

  // KR-REQ-22.01, KR-REQ-13.19: the session descriptions card names each control, and a person on
  // the keyboard stays on the control they are on: while the host answers a press, while the card
  // follows a fetch that is running, and when the fetch's button changes what it does.
  test('names the descriptions card’s controls and keeps focus where the person is while the host answers', async ({
    page
  }) => {
    await openSetup(page)
    await step(page, 'host')
    const card = page.getByTestId('setup-model')
    const enable = card.getByRole('switch', { name: 'Describe my sessions' })
    await expect(enable).toBeVisible()
    await expect(card.getByRole('switch', { name: 'Keep going on battery power' })).toBeVisible()

    // The host's answers are held, as a slow host's are, and counted by the page's own reads.
    type Held = { readonly count: number; release(): void }
    const held = (): Promise<number> =>
      page.evaluate(() => (window as unknown as { held?: Held }).held?.count ?? 0)
    const hold = (): Promise<void> =>
      page.evaluate(() => {
        ;(window as unknown as { held?: Held }).held = window.krTestHost?.hold('descriptionSetup')
      })
    const release = (): Promise<void> =>
      page.evaluate(() => {
        ;(window as unknown as { held?: Held }).held?.release()
      })

    // A switch pressed from the keyboard is still the focused control while the host has not yet
    // answered the read that follows the change, and after it has.
    await enable.focus()
    await hold()
    await page.keyboard.press('Space')
    await expect.poll(held).toBeGreaterThan(0)
    await expect(enable).toBeFocused()
    await expect(enable).toBeEnabled()
    await expect(enable).not.toHaveAttribute('aria-disabled', 'true')
    await release()
    await expect(enable).toHaveAttribute('aria-checked', 'true')
    await expect(enable).toBeFocused()

    // The fetch's one button becomes the one that stops it, with the person still on it.
    const fetch = card.getByTestId('setup-model-download')
    await fetch.focus()
    await page.keyboard.press('Enter')
    await expect(card.getByRole('progressbar', { name: 'Download progress' })).toBeVisible()
    const cancel = card.getByRole('button', { name: 'Cancel the download' })
    await expect(cancel).toBeFocused()

    // While the card follows the fetch, each read of its progress leaves the button usable.
    await hold()
    await expect.poll(held).toBeGreaterThan(0)
    await expect(cancel).toBeEnabled()
    await expect(cancel).not.toHaveAttribute('aria-disabled', 'true')
    await expect(cancel).toBeFocused()
    await release()

    await page.keyboard.press('Enter')
    await expect(card.getByRole('button', { name: 'Download it' })).toBeFocused()
  })

  // KR-REQ-13.19: where an answer removes the control a person is on, focus goes to a control the
  // card still has, and not to the page: a fetch that ends, a read that fails, and a retry that
  // succeeds.
  test('moves focus to a control the descriptions card still has when an answer removes the one the person is on', async ({
    page
  }) => {
    await openSetup(page)
    await step(page, 'host')
    const card = page.getByTestId('setup-model')
    const enable = card.getByRole('switch', { name: 'Describe my sessions' })

    // A fetch that ends while the person is on the button that stops it.
    await card.getByTestId('setup-model-download').focus()
    await page.keyboard.press('Enter')
    const cancel = card.getByRole('button', { name: 'Cancel the download' })
    await expect(cancel).toBeFocused()
    await page.evaluate(() => {
      window.krTestHost?.changeDescriptionSetup({
        download: 'verified',
        can_cancel: false,
        fetched_bytes: '1561318368'
      })
    })
    await expect(cancel).toHaveCount(0)
    await expect(enable).toBeFocused()

    // A read that fails while the person is on a switch they pressed.
    await page.evaluate(() => {
      window.krTestHost?.setConnected(false)
    })
    await page.keyboard.press('Space')
    const again = card.getByRole('button', { name: 'Ask again' })
    await expect(again).toBeFocused()

    // A retry that succeeds, pressed with the pointer on the button that already has focus: the
    // press moves no focus, and the repair still knows where the person is.
    await page.evaluate(() => {
      window.krTestHost?.setConnected(true)
    })
    await again.click()
    await expect(again).toHaveCount(0)
    await expect(enable).toBeFocused()

    // A retry from the keyboard that finds the host offers nothing: the card has no control left,
    // and focus goes to the card's heading, not to the page.
    await page.evaluate(() => {
      window.krTestHost?.setConnected(false)
    })
    await page.keyboard.press('Space')
    await expect(again).toBeFocused()
    await page.evaluate(() => {
      window.krTestHost?.setConnected(true)
      window.krTestHost?.changeDescriptionSetup({
        offered: false,
        unavailable: 'this processor lacks AVX2 and BMI2'
      })
    })
    await page.keyboard.press('Enter')
    await expect(card.getByTestId('setup-model-unavailable')).toBeVisible()
    await expect(card.getByRole('heading', { name: 'Session descriptions' })).toBeFocused()
  })

  // KR-REQ-13.19: a switch is drawn smaller than a finger, and a press anywhere across a target of
  // the platform's size around it still lands on it, at the desktop's token and at 44 and 48 px.
  test('takes a press across the full target around each switch', async ({ page }) => {
    await openSetup(page)
    await step(page, 'host')
    const switches = page.getByRole('switch')
    await expect(switches.first()).toBeVisible()
    const shortOf = (size: number): Promise<string[]> =>
      switches.evaluateAll((controls, target) => {
        const short: string[] = []
        for (const control of controls) {
          control.scrollIntoView({ block: 'center', inline: 'center' })
          const box = control.getBoundingClientRect()
          const x = box.left + box.width / 2
          const y = box.top + box.height / 2
          const edge = target / 2 - 0.5
          const points: readonly (readonly [number, number, string])[] = [
            [x, y - edge, 'top'],
            [x, y + edge, 'bottom'],
            [x - edge, y, 'left'],
            [x + edge, y, 'right']
          ]
          for (const [px, py, side] of points) {
            const hit = document.elementFromPoint(px, py)
            if (!hit || !control.contains(hit)) {
              short.push(`${control.getAttribute('aria-label') ?? ''} at its ${side} edge`)
            }
          }
        }
        return short
      }, size)
    const own = await page.evaluate(() =>
      parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--target'))
    )
    expect.soft(await shortOf(own), `the switches at ${own} px`).toEqual([])
    for (const target of [44, 48]) {
      await page.evaluate((size) => {
        document.documentElement.style.setProperty('--target', `${size}px`)
      }, target)
      expect.soft(await shortOf(target), `the switches at ${target} px`).toEqual([])
    }
  })

  test('keeps the path readable on a narrow window', async ({ page }) => {
    await openSetup(page)
    await step(page, 'permissions')
    await page.setViewportSize({ width: 390, height: 900 })
    const card = page.getByTestId('setup-permission-accessibility')
    await expect(card).toBeVisible()
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(overflow).toBeLessThanOrEqual(1)
    // Every control is still a target in both directions. The bound is the token's own 36px, read
    // back with a fraction of a pixel of slack because one of these engines reports a 36px minimum
    // as 35.9999 after its own rounding.
    for (const button of await page.getByTestId('setup-open-accessibility').all()) {
      const box = await button.boundingBox()
      expect(box?.height ?? 0).toBeGreaterThan(35.9)
      expect(box?.width ?? 0).toBeGreaterThan(35.9)
    }
    await capture(page, 'setup-narrow-03.28')
  })

  // KR-REQ-03.29: the checks are asked for from the sheet that lists what each one does and from
  // nowhere else, and the card says where they stand until the host says the run ended.
  test('asks for the checks only from the sheet that lists them, and shows the run until it ends', async ({
    page
  }) => {
    await openSetup(page)
    await step(page, 'capabilities')
    const state = page.getByTestId('setup-checks-state')
    await expect(state).toHaveAttribute('data-state', 'current')
    const runs = (): Promise<number> =>
      page.evaluate(() => window.krTestHost?.checkRuns.length ?? -1)

    // The card's control opens the list and starts nothing.
    const opener = page.getByTestId('setup-run-checks')
    await opener.click()
    const sheet = page.getByTestId('sheet')
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    expect(await runs()).toBe(0)
    await page.getByTestId('setup-checks-not-now').click()
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
    expect(await runs()).toBe(0)

    // The run starts from the sheet's own button, and the card behind it says it is running. From
    // the keyboard, because that is the path where the focus has to come back, and because one of
    // these engines deliberately does not focus a button that was clicked.
    await opener.focus()
    await page.keyboard.press('Enter')
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    await page.getByTestId('setup-checks-run').focus()
    await page.keyboard.press('Enter')
    await expect(state).toHaveAttribute('data-state', 'running')
    expect(await runs()).toBe(1)
    // The list leaves and the focus goes back to the control that opened it, which is still there
    // to be reached from the keyboard; asking again from the list is what is not offered.
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
    await expect(opener).toBeFocused({ timeout: PRESENTATION_DEADLINE })
    await page.keyboard.press('Enter')
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    await expect(page.getByTestId('setup-checks-run')).toBeDisabled()
    expect(await runs()).toBe(1)
    await page.getByTestId('setup-checks-not-now').click()
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })

    // The host ends the run, and the page finds out by asking, not by being told.
    await page.evaluate(() => {
      window.krTestHost?.setChecks({ state: 'current', finished_at_ms: String(Date.now()) })
    })
    await expect(state).toHaveAttribute('data-state', 'current', {
      timeout: PRESENTATION_DEADLINE
    })
    await expect(opener).toBeEnabled()
  })

  // KR-REQ-03.29: at the largest text size, on a wide window and on a narrow one, the controls that
  // run the checks, what the page says about them and the sheet that lists them stay inside the
  // window, and every control is still a target of the token's size.
  for (const [width, height] of [
    [1280, 720],
    [390, 844]
  ] as const) {
    for (const [size, ratio] of [
      ['default', 1],
      ['largest', LARGEST]
    ] as const) {
      test(`keeps the checks card and its sheet inside the window at the ${size} text size, ${width} wide`, async ({
        page
      }) => {
        await openSetup(page)
        await step(page, 'capabilities')
        await page.setViewportSize({ width, height })
        await page.evaluate((value) => {
          document.documentElement.style.setProperty('--text-scale', String(value))
        }, ratio)
        expect(
          await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize))
        ).toBeCloseTo(16 * ratio, 1)

        // The run that found nothing says the most: a line and a banner with the longest reason.
        await page.evaluate(() => {
          window.krTestHost?.setChecks({ state: 'failed', failure: 'no_session' })
        })
        await page.getByTestId('setup-recheck').click()
        await expect(page.getByTestId('setup-checks-state')).toHaveAttribute('data-state', 'failed')
        await expect(page.getByText('The checks did not run')).toBeVisible()

        // What this change put on the page ends inside the window. The step list above it scrolls
        // on its own and is not the checks'.
        const inside = async (name: string, target: Locator, fixed = false): Promise<void> => {
          const box = await target.boundingBox()
          expect(box, `${name} is on the page`).not.toBeNull()
          // Read from the page's own left edge, wherever a press has scrolled it to, except for a
          // surface the window itself holds.
          const scrolled = fixed ? 0 : await page.evaluate(() => window.scrollX)
          const left = (box?.x ?? 0) + scrolled
          expect(left, `${name} left edge`).toBeGreaterThanOrEqual(-1)
          expect(left + (box?.width ?? 0), `${name} right edge`).toBeLessThanOrEqual(width + 1)
        }
        const footer = page.getByTestId('setup-run-checks').locator('xpath=..')
        await inside('the card footer', footer)
        await inside('the line that says where the checks stand', page.getByTestId('setup-checks-state'))
        await inside('the banner', page.getByText('The checks did not run'))
        const footerBox = await footer.boundingBox()
        for (const control of ['setup-recheck', 'setup-run-checks']) {
          const box = await page.getByTestId(control).boundingBox()
          expect(box?.height ?? 0, `${control} height`).toBeGreaterThan(35.9)
          expect(box?.x ?? -1, `${control} left edge`).toBeGreaterThanOrEqual((footerBox?.x ?? 0) - 1)
          expect((box?.x ?? 0) + (box?.width ?? 0), `${control} right edge`).toBeLessThanOrEqual(
            (footerBox?.x ?? 0) + (footerBox?.width ?? 0) + 1
          )
        }
        await capture(page, `setup-checks-failed-${size}-${width}-03.29`)

        await page.getByTestId('setup-run-checks').click()
        const sheet = page.getByTestId('sheet')
        await expect(sheet).toHaveAttribute('data-presentation', 'here', {
          timeout: PRESENTATION_DEADLINE
        })
        // The two buttons that decide are on the screen without scrolling, and the sheet is not
        // wider than the window.
        await expect(page.getByTestId('setup-checks-run')).toBeInViewport()
        await expect(page.getByTestId('setup-checks-not-now')).toBeInViewport()
        await inside('the sheet', sheet, true)
        for (const control of ['setup-checks-run', 'setup-checks-not-now']) {
          const box = await page.getByTestId(control).boundingBox()
          expect(box?.height ?? 0, `${control} height`).toBeGreaterThan(35.9)
          await inside(control, page.getByTestId(control), true)
        }
        await capture(page, `setup-checks-sheet-${size}-${width}-03.29`)
      })
    }
  }

  /**
   * Puts the window and the text size where a layout case holds a surface, in the face the Linux
   * runner draws with. DejaVu Sans, which the runner draws the page in, sets the same text about a
   * tenth wider than a Mac's face does, and a label that fits in the Mac's face is cut off in it.
   * Verdana is as wide and every Mac has it, with DejaVu Sans after it for the machine that has
   * none, so the case measures the runner's widths wherever it runs.
   */
  async function sizeTo(page: Page, width: number, height: number, ratio: number): Promise<void> {
    await page.addStyleTag({
      content: ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'
    })
    await page.setViewportSize({ width, height })
    await page.evaluate((value) => {
      document.documentElement.style.setProperty('--text-scale', String(value))
    }, ratio)
    expect(
      await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize))
    ).toBeCloseTo(16 * ratio, 1)
  }

  /**
   * A card's footer and every control in it lie inside the window, the card does not draw anything
   * past its edge, every control is a target of the token's size with its label inside it, and on a
   * narrow window each control is as wide as the footer's room, so that a long label wraps in its
   * button instead of being cut off at the card's edge.
   */
  async function footerHolds(
    page: Page,
    name: string,
    card: Locator,
    footer: Locator,
    width: number
  ): Promise<void> {
    const box = await footer.boundingBox()
    expect(box, `${name} footer is on the page`).not.toBeNull()
    const scrolled = await page.evaluate(() => window.scrollX)
    const left = (box?.x ?? 0) + scrolled
    expect(left, `${name} footer left edge`).toBeGreaterThanOrEqual(-1)
    expect(left + (box?.width ?? 0), `${name} footer right edge`).toBeLessThanOrEqual(width + 1)
    const room = await footer.evaluate((node) => {
      const style = getComputedStyle(node)
      return node.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)
    })
    const controls = await footer.getByRole('button').all()
    expect(controls.length, `${name} footer has a control`).toBeGreaterThan(0)
    for (const control of controls) {
      const at = await control.boundingBox()
      const label = ((await control.textContent()) ?? '').trim()
      expect(at?.height ?? 0, `${name}: ${label} height`).toBeGreaterThan(35.9)
      expect(at?.x ?? -1, `${name}: ${label} left edge`).toBeGreaterThanOrEqual((box?.x ?? 0) - 1)
      expect((at?.x ?? 0) + (at?.width ?? 0), `${name}: ${label} right edge`).toBeLessThanOrEqual(
        (box?.x ?? 0) + (box?.width ?? 0) + 1
      )
      expect(
        await control.evaluate((node) => node.scrollWidth - node.clientWidth),
        `${name}: ${label} label past its button`
      ).toBeLessThanOrEqual(1)
      if (width < 640) {
        expect(at?.width ?? 0, `${name}: ${label} width against the footer's room`).toBeGreaterThan(
          room - 2
        )
      }
    }
    // Measured from the page's left edge, wherever a press has scrolled it to.
    await page.evaluate(() => {
      window.scrollTo(0, window.scrollY)
    })
    const id = await card.getAttribute('data-testid')
    expect(
      await overrunning(page, `[data-testid="${id ?? ''}"] > footer`),
      `${name} footer draws past its edge`
    ).toEqual([])
  }

  /** Opens the evidence of every capability on the capabilities step and waits for it to draw. */
  async function openEveryEvidence(page: Page): Promise<void> {
    for (const toggle of await page.locator('[data-testid^="setup-evidence-toggle-"]').all()) {
      await toggle.click()
    }
    await expect(page.locator('.setup-evidence[data-open="true"]').last()).toBeVisible()
    await expect
      .poll(
        async () =>
          page
            .locator('.setup-evidence[data-open="true"]')
            .last()
            .evaluate((node) => getComputedStyle(node).opacity),
        { timeout: PRESENTATION_DEADLINE }
      )
      .toBe('1')
  }

  // KR-REQ-03.28: the permission cards' footers say where the switch is and open its pane, and at
  // the largest text size, on a wide window and a narrow one, in the runner's face, the footer and
  // its controls stay inside the card and the window.
  for (const [width, height] of WINDOWS) {
    for (const [size, ratio] of TEXT_SIZES) {
      test(`keeps each permission card's footer inside the window at the ${size} text size, ${width} wide`, async ({
        page
      }) => {
        await openSetup(page)
        await step(page, 'permissions')
        await sizeTo(page, width, height, ratio)
        const opens = page.locator('[data-testid^="setup-open-"]')
        const count = await opens.count()
        expect(count, 'the permission cards that open a pane').toBeGreaterThanOrEqual(4)
        for (let each = 0; each < count; each += 1) {
          const open = opens.nth(each)
          const pane = ((await open.getAttribute('data-testid')) ?? '').replace('setup-open-', '')
          const card = page.getByTestId(`setup-permission-${pane}`)
          await footerHolds(page, `the ${pane} card`, card, open.locator('xpath=..'), width)
        }
        await capture(page, `setup-permissions-footers-${size}-${width}-03.28`)
      })
    }
  }

  // KR-REQ-22.01: the descriptions card's footer holds one control whichever way the fetch stands
  // (the fetch's, or the one that asks the host again), and each of them stays inside the card and
  // the window at the largest text size, on a wide window and a narrow one, in the runner's face.
  for (const [width, height] of WINDOWS) {
    for (const [size, ratio] of TEXT_SIZES) {
      test(`keeps the descriptions card's footer inside the window at the ${size} text size, ${width} wide`, async ({
        page
      }) => {
        await openSetup(page)
        await step(page, 'host')
        await sizeTo(page, width, height, ratio)
        const card = page.getByTestId('setup-model')
        const footer = card.locator('footer')
        const battery = card.getByRole('switch', { name: 'Keep going on battery power' })

        // Before the fetch: the control that starts it.
        await expect(card.getByTestId('setup-model-download')).toHaveText('Download it')
        await footerHolds(page, 'the card before a fetch', card, footer, width)

        // After one that failed: the longest words the control that starts it has.
        await page.evaluate(() => {
          window.krTestHost?.changeDescriptionSetup({
            download: 'failed',
            failure: 'The connection was cut before the files were whole.'
          })
        })
        await battery.click()
        await expect(card.getByTestId('setup-model-download')).toHaveText('Try the download again')
        await footerHolds(page, 'the card after a failed fetch', card, footer, width)

        // While one runs: the control that stops it.
        await card.getByTestId('setup-model-download').click()
        await expect(card.getByTestId('setup-model-cancel')).toHaveText('Cancel the download')
        await footerHolds(page, 'the card during a fetch', card, footer, width)

        // While the host does not answer: the control that asks again.
        await page.evaluate(() => {
          window.krTestHost?.setConnected(false)
        })
        await card.getByTestId('setup-model-cancel').click()
        await expect(card.getByTestId('setup-model-retry')).toHaveText('Ask again')
        await footerHolds(page, 'the card while the host does not answer', card, footer, width)
        await capture(page, `setup-descriptions-footer-${size}-${width}-22.01`)
      })
    }
  }

  // KR-REQ-03.28, KR-REQ-03.29: a detail list keeps a value a readable measure. Beside its label
  // it has the room for all of it on one line, and otherwise it goes under the label and has the
  // list's width, so that no value is wrapped to a few characters a line, at the largest text size
  // on a narrow window and in the runner's face.
  for (const [width, height] of WINDOWS) {
    for (const [size, ratio] of TEXT_SIZES) {
      test(`gives the detail lists' values a readable measure at the ${size} text size, ${width} wide`, async ({
        page
      }) => {
        await openSetup(page)
        await sizeTo(page, width, height, ratio)
        const squeezed = (): Promise<string[]> =>
          page.evaluate(() => {
            const found: string[] = []
            for (const list of document.querySelectorAll('.setup-body .detail-list')) {
              const room = list.getBoundingClientRect().width
              if (room === 0) continue
              for (const part of list.querySelectorAll('dt, dd')) {
                const box = part.getBoundingClientRect()
                if (box.width === 0 || box.height === 0) continue
                const style = getComputedStyle(part)
                const line = parseFloat(style.lineHeight) || parseFloat(style.fontSize) * 1.4
                const lines = Math.round(box.height / line)
                // A part that takes more than a line has most of the list's width.
                if (lines > 1 && box.width < room * 0.8) {
                  const words = (part.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 40)
                  found.push(
                    `${words}: ${String(lines)} lines in ${String(Math.round(box.width))} of ${String(Math.round(room))} px`
                  )
                }
              }
            }
            return found
          })
        // The identity step's two lists.
        expect(await squeezed(), 'the identity step').toEqual([])
        await capture(page, `setup-detail-identity-${size}-${width}-03.28`)
        // The desktop's list, and the evidence each capability opens.
        await step(page, 'capabilities')
        await openEveryEvidence(page)
        expect(await squeezed(), 'the capabilities step').toEqual([])
        await capture(page, `setup-detail-capabilities-${size}-${width}-03.29`)
      })
    }
  }

  // KR-REQ-03.28: the page's title shows each of its words whole, at each text size and on a wide
  // window and a narrow one, in the runner's face. A word broken in the middle of a name reads as a
  // mistake, so at the largest size on a phone the title is set smaller instead of breaking.
  for (const [width, height] of WINDOWS) {
    for (const [size, ratio] of TEXT_SIZES) {
      test(`keeps each word of the page's title whole at the ${size} text size, ${width} wide`, async ({
        page
      }) => {
        await openSetup(page)
        await sizeTo(page, width, height, ratio)
        const broken = await page.evaluate(() => {
          const title = document.querySelector('.setup-heading h1')
          const text = title?.firstChild
          if (!(text instanceof Text)) return ['the title is not a line of text']
          const found: string[] = []
          for (const word of text.data.matchAll(/\S+/g)) {
            const start = word.index ?? 0
            const range = document.createRange()
            range.setStart(text, start)
            range.setEnd(text, start + word[0].length)
            const lines = new Set(Array.from(range.getClientRects()).map((box) => Math.round(box.top)))
            if (lines.size > 1) found.push(word[0])
          }
          return found
        })
        expect(broken, 'words of the title that are broken across lines').toEqual([])
      })
    }
  }

  test('draws in both colour modes from the same tokens', async ({ page }) => {
    await openSetup(page)
    await step(page, 'capabilities')
    for (const mode of ['light', 'dark'] as const) {
      await page.evaluate((next) => {
        document.documentElement.dataset.theme = next
      }, mode)
      const background = await page.evaluate(
        () => getComputedStyle(document.body).backgroundColor
      )
      expect(background).not.toBe('rgba(0, 0, 0, 0)')
      await capture(page, `setup-${mode}-03.29`)
    }
  })

  test('does not animate a step the keyboard moved to', async ({ page }) => {
    await openSetup(page)
    // The step is reached from the keyboard, so nothing about this change came from a pointer.
    await page.getByTestId('setup-step-permissions').focus()
    await page.keyboard.press('Enter')
    await page.getByTestId('setup-panel-permissions').waitFor()
    await expect(page.locator('html')).toHaveAttribute('data-input', 'keyboard')
    const duration = await page
      .getByTestId('setup-panel-permissions')
      .evaluate((node) => getComputedStyle(node).animationDuration)
    expect(duration).toBe('0s')

    // And a pointer-driven step gets its arrival back.
    await page.getByTestId('setup-step-host').click()
    await page.getByTestId('setup-panel-host').waitFor()
    await expect(page.locator('html')).toHaveAttribute('data-input', 'pointer')
  })
})
