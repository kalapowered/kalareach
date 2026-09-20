/**
 * The setup assistant in a real browser engine.
 *
 * What these cover that a component test cannot is everything that needs layout and a renderer:
 * the single path through the steps at a real window size and at a narrow one, the disclosure that
 * opens with a row transition, the colour modes, and the focus a sheet takes and gives back.
 *
 * Every screenshot goes under `/tmp` and is named for the requirement row it evidences.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'

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
    await expect(identity).toContainText('to.kala.companion')
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
    await expect(page.getByTestId('setup-model-size')).toContainText('1.9 GB')
    await expect(page.getByTestId('setup-model')).toContainText(
      'Nothing is downloading while you read this'
    )
    await capture(page, 'setup-host-03.28')
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
