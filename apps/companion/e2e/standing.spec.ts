/**
 * What a phone's session screen shows when the host ends or refuses the session it opened, in both
 * browser engines, at the default text size and at the largest.
 *
 * The screen keeps what it read and turns off what sends. The banner that says why enters with an
 * opacity change of 160 ms, none under a request for less motion and none after a key, takes the
 * focus only when the control the focus was on has been turned off, and stays inside the screen with
 * its buttons a finger tall at the largest size. Screenshots go to `/tmp`.
 */

import { expect, test, type Page } from '@playwright/test'

import { overrunning, stopWrapping } from './layout'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SHARE = '5d0e2a40-77aa-4b2c-9d3e-000000000901'

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

/** Opens the session screen on the narrowest phone, with the host saying `answer` to its open. */
async function openSession(
  page: Page,
  ratio: number,
  answer?: object
): Promise<void> {
  await withSystemTextScale(page, ratio)
  await page.setViewportSize({ width: 320, height: 720 })
  if (answer !== undefined) {
    await page.addInitScript(
      ([session, scripted]) => {
        // The harness builds the host as the page loads, before anything asks it for a session: the
        // host is told what its opens answer the moment it is made.
        let host: unknown
        Object.defineProperty(window, 'krTestHost', {
          configurable: true,
          get: () => host,
          set: (controls: {
            standings: { answerOpens: (session: string, answer: object) => void }
          }) => {
            host = controls
            controls.standings.answerOpens(session, scripted)
          }
        })
      },
      [SESSION, answer] as const
    )
  }
  await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
}

function say(page: Page, standing: object): Promise<void> {
  return page.evaluate(
    ([session, said]) => {
      window.krTestHost?.standings.say(session, said as never)
    },
    [SESSION, standing] as const
  )
}

const shareOf = (more: object = {}): object => ({
  state: 'open',
  via: 'share',
  grant_id: SHARE,
  actions: ['session.view', 'agent.prompt', 'terminal.input'],
  includes_live_screen: true,
  history_from_ms: null,
  ends_at_ms: null,
  ...more
})

for (const size of SIZES) {
  test.describe(`a session screen whose opening is over, at the ${size.name} text size`, () => {
    test('says why in the host’s words, inside the screen, with buttons a finger tall', async ({
      page
    }, info) => {
      await openSession(page, size.ratio, shareOf())
      await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
      await page.getByLabel('Message this session').fill('one more thing')

      await say(page, { state: 'ended', reason: 'revoked' })
      const banner = page.getByTestId('standing-banner')
      await expect(banner).toBeVisible()
      await expect(banner).toContainText('This share ended')
      await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
      await expect(page.getByRole('button', { name: 'Send' })).toBeDisabled()
      await expect(page.getByTestId('standing-status')).toContainText('This share ended')

      const across = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth,
        screen: window.innerWidth
      }))
      expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
      const outside = await banner.evaluate((element) => {
        const edge = window.innerWidth
        return [...element.querySelectorAll('*')]
          .filter((each) => each.getBoundingClientRect().right > edge + 0.5)
          .map((each) => each.textContent?.slice(0, 40) ?? each.tagName)
      })
      expect(outside, 'parts of the banner that run past the screen').toEqual([])
      const small = await banner.locator('button').evaluateAll((buttons) =>
        buttons
          .map((each) => ({ box: each.getBoundingClientRect(), name: each.textContent ?? '' }))
          .filter(({ box }) => box.height + 0.5 < 44)
          .map(({ box, name }) => `${name}: ${Math.round(box.height)}`)
      )
      expect(small, 'buttons shorter than a finger').toEqual([])

      // The banner is the first thing on the screen the person reads: the shot is taken with it in view.
      await banner.scrollIntoViewIfNeeded()
      await page.screenshot({
        path: `/tmp/kr-standing-ended-${info.project.name}-${size.name}.png`
      })
    })

    test('says a refusal in the host’s sentence, and Try again opens the session as a new opening', async ({
      page
    }, info) => {
      await openSession(page, size.ratio, {
        code: 'PERMISSION_DENIED',
        message: 'This device holds no share of that session.'
      })
      const banner = page.getByTestId('standing-banner')
      await expect(banner).toContainText('This device holds no share of that session.')
      await expect(banner.getByRole('button', { name: 'Back' })).toBeVisible()
      await banner.scrollIntoViewIfNeeded()
      await page.screenshot({
        path: `/tmp/kr-standing-refused-${info.project.name}-${size.name}.png`
      })

      await page.evaluate((session) => {
        window.krTestHost?.standings.answerOpens(session, {
          state: 'open',
          via: 'owner',
          grant_id: '',
          actions: ['session.view'],
          includes_live_screen: true,
          history_from_ms: null,
          ends_at_ms: null
        })
      }, SESSION)
      await banner.getByRole('button', { name: 'Try again' }).click()
      await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
      await expect(page.getByTestId('standing-banner')).toHaveCount(0)
      const opens = await page.evaluate(() => window.krTestHost?.standings.opens.length ?? 0)
      expect(opens).toBe(2)
    })

    test('replaces the terminal by one line when the share does not include the live screen', async ({
      page
    }, info) => {
      await openSession(page, size.ratio, shareOf({ includes_live_screen: false }))
      await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('no-live-screen')).toContainText(
        'This share does not include the live screen.'
      )
      await expect(page.getByTestId('mobile-terminal')).toHaveCount(0)
      await page.screenshot({
        path: `/tmp/kr-standing-no-screen-${info.project.name}-${size.name}.png`
      })
    })
  })
}

test.describe('how the banner arrives', () => {
  /** Starts counting the transitions that run, so a test can say whether the banner's was one. */
  async function watchTransitions(page: Page): Promise<void> {
    await page.evaluate(() => {
      const ran: string[] = []
      ;(window as unknown as { krRan: string[] }).krRan = ran
      document.addEventListener(
        'transitionrun',
        (event) => {
          if ((event.target as Element).getAttribute('data-testid') === 'standing-banner') {
            ran.push(event.propertyName)
          }
        },
        true
      )
    })
  }

  const ran = (page: Page): Promise<string[]> =>
    page.evaluate(() => (window as unknown as { krRan: string[] }).krRan)

  test('fades in over 160 ms after a pointer press', async ({ page }) => {
    await openSession(page, 1, shareOf())
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await page.mouse.click(10, 10)
    await watchTransitions(page)
    await say(page, { state: 'closed' })
    await expect(page.getByTestId('standing-banner')).toBeVisible()
    await expect(page.getByTestId('standing-banner')).toHaveCSS('opacity', '1')
    // The opacity change ran, and it is the declared one.
    expect(await ran(page)).toEqual(['opacity'])
    await expect(page.getByTestId('standing-banner')).toHaveCSS('transition-duration', '0.16s')
  })

  test('arrives at once under a request for less motion', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await openSession(page, 1, shareOf())
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await watchTransitions(page)
    await say(page, { state: 'closed' })
    await expect(page.getByTestId('standing-banner')).toBeVisible()
    await expect(page.getByTestId('standing-banner')).toHaveCSS('opacity', '1')
    expect(await ran(page)).toEqual([])
  })

  test('arrives at once after a key', async ({ page }) => {
    await openSession(page, 1, shareOf())
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await page.getByLabel('Message this session').press('a')
    await watchTransitions(page)
    await say(page, { state: 'closed' })
    await expect(page.getByTestId('standing-banner')).toBeVisible()
    await expect(page.getByTestId('standing-banner')).toHaveCSS('opacity', '1')
    expect(await ran(page)).toEqual([])
  })
})

test.describe('where the focus goes', () => {
  test('stays on the field the person is typing in', async ({ page }) => {
    await openSession(page, 1, shareOf())
    const field = page.getByLabel('Message this session')
    await field.fill('hello')
    await field.focus()
    await say(page, { state: 'ended', reason: 'revoked' })
    await expect(page.getByTestId('standing-banner')).toBeVisible()
    await expect(field).toBeFocused()
  })

  test('moves to the banner when the control it was on is turned off', async ({ page }) => {
    await openSession(page, 1, shareOf())
    await page.getByLabel('Message this session').fill('hello')
    const send = page.getByRole('button', { name: 'Send' })
    await send.focus()
    await expect(send).toBeFocused()
    await say(page, { state: 'ended', reason: 'revoked' })
    await expect(page.getByTestId('standing-banner')).toBeFocused()
  })

  test('moves from Try again to the screen it opens, and not to nothing', async ({ page }) => {
    await openSession(page, 1, {
      code: 'PERMISSION_DENIED',
      message: 'This device holds no share of that session.'
    })
    const banner = page.getByTestId('standing-banner')
    await expect(banner).toBeVisible()
    await page.evaluate((session) => {
      window.krTestHost?.standings.answerOpens(session, {
        state: 'open',
        via: 'owner',
        grant_id: '',
        actions: ['session.view'],
        includes_live_screen: true,
        history_from_ms: null,
        ends_at_ms: null
      })
    }, SESSION)
    const retry = banner.getByRole('button', { name: 'Try again' })
    await retry.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await expect(page.locator('.m-pane')).toBeFocused()
  })

  test('moves to the banner when the share ends under a key of the terminal the person is typing with', async ({
    page
  }) => {
    await openSession(page, 1, shareOf())
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByRole('button', { name: 'Take control' })).toBeEnabled()
    await page.getByRole('button', { name: 'Take control' }).click()
    const escape = page.getByRole('button', { name: 'Escape' })
    await expect(escape).toBeEnabled()
    await escape.focus()
    await expect(escape).toBeFocused()

    await say(page, { state: 'ended', reason: 'revoked' })
    await expect(page.getByTestId('standing-banner')).toBeFocused()
  })

  /** Takes control of the program from the terminal pane and puts the focus on a terminal key. */
  async function typingWithAKey(page: Page): Promise<void> {
    await openSession(page, 1, shareOf())
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByRole('button', { name: 'Take control' })).toBeEnabled()
    await page.getByRole('button', { name: 'Take control' }).click()
    const escape = page.getByRole('button', { name: 'Escape' })
    await expect(escape).toBeEnabled()
    await escape.focus()
    await expect(escape).toBeFocused()
  }

  test('stays in the pane when the contact is lost under a key of the terminal', async ({ page }) => {
    await typingWithAKey(page)
    await say(page, { state: 'reconnecting', reason: 'Contact with the session was lost.' })
    await expect(page.getByRole('button', { name: 'Escape' })).toBeDisabled()
    await expect(page.locator('.m-pane')).toBeFocused()
  })

  test('stays in the pane when the host takes the right to type away under a key of the terminal', async ({
    page
  }) => {
    await typingWithAKey(page)
    await say(page, shareOf({ actions: ['session.view', 'agent.prompt'] }))
    await expect(page.getByRole('button', { name: 'Escape' })).toBeDisabled()
    await expect(page.locator('.m-pane')).toBeFocused()
  })
})

test.describe('an earlier action sent under an earlier opening, at the largest text size', () => {
  test('is listed inside the screen with the words that say where it was sent', async ({ page }) => {
    await openSession(page, LARGEST)
    await page.evaluate(() => {
      window.krTestHost?.leaveNextSendUnconfirmed()
    })
    // One long word, as an identifier is: the line can only be kept inside the screen by breaking it.
    await page.getByLabel('Message this session').fill('runthemigrationoftheverylongdatabasenamewithoutabreakanywhere')
    await page.getByRole('button', { name: 'Send', exact: true }).click()
    const release = page.getByRole('button', { name: 'I checked; send anyway' })
    await expect(release).toBeVisible()

    // The host refuses the opening and the person opens the session again: a new opening.
    await say(page, { state: 'refused', code: 'PERMISSION_DENIED', message: 'This share may not do that.' })
    await page.getByRole('button', { name: 'Try again' }).click()
    await expect(page.getByTestId('standing-banner')).toBeHidden()
    await page.getByLabel('Message this session').fill('the next thing')
    await release.click()

    const earlier = page.getByTestId('earlier-actions')
    await expect(earlier).toContainText('Outcome unknown')
    await expect(earlier.getByTestId('earlier-opening')).toBeVisible()
    await page.screenshot({ path: `/tmp/kr-standing-earlier-${test.info().project.name}.png` })
    expect(
      await overrunning(page, '[data-testid="earlier-actions"]'),
      'lines of the list that run past the screen or their box'
    ).toEqual([])
    // The control: with the text kept from wrapping, the same measure sees the list run out.
    await stopWrapping(page, ['[data-testid="earlier-actions"]'])
    expect(
      await overrunning(page, '[data-testid="earlier-actions"]'),
      'the measure sees the list text that cannot wrap'
    ).not.toEqual([])
  })
})
