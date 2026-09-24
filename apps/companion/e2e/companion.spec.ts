/**
 * The interface in a real browser engine, driven the way a person drives it.
 *
 * The bundle under test is the one the desktop shell loads; only the host differs. What these
 * cover that a component test cannot is everything that needs layout and a real renderer: the
 * terminal's cells, the sheet's gesture, the colour modes, and the scroll position that decides
 * whether the view is following.
 *
 * Every screenshot goes under `/tmp`, and each one is named for the requirement row it closes.
 */

import { expect, test, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return `/tmp/kr-companion-${name}.png`
}

async function open(page: Page, hash = ''): Promise<void> {
  await page.goto(`/harness.html${hash}`)
  await page.waitForSelector('.app-shell')
}

async function openSession(page: Page): Promise<void> {
  await open(page)
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
}

test.describe('the attention inbox', () => {
  test('shows the four states and never calls a lost connection a failure', async ({ page }) => {
    await open(page)
    await expect(page.getByTestId('attention-pending_decision')).toBeVisible()
    await expect(page.getByTestId('attention-failed_action')).toBeVisible()
    await expect(page.getByTestId('attention-awaiting_review')).toBeVisible()
    const disconnected = page.getByTestId('attention-disconnected')
    await expect(disconnected).toBeVisible()
    await expect(disconnected).toContainText('does not')
    await expect(disconnected).not.toContainText(/failed|stuck/i)
    await page.screenshot({ path: shot('attention-13.01'), fullPage: true })
  })

  // KR-REQ-13.07: an approval is decided by a completed press. A press that slides off the control
  // decides nothing, including through the click the browser sends after the release, and a
  // completed press decides once.
  test('a press that slides off an approval decides nothing', async ({ page }) => {
    await open(page)
    const allow = page
      .getByTestId('attention-pending_decision')
      .getByRole('button', { name: 'Allow' })
    // Every decision the interface sends is an action the host issues, at the moment it is sent.
    const issued = (): Promise<number> =>
      page.evaluate(() => window.krTestHost?.actions.length ?? -1)
    const before = await issued()
    const box = await allow.boundingBox()
    if (!box) throw new Error('the approval has no control')

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await page.mouse.down()
    await page.mouse.move(box.x + box.width / 2, box.y + box.height + 160, { steps: 6 })
    await page.mouse.up()
    expect(await issued()).toBe(before)

    await allow.click()
    await expect(page.getByText('Allowed.')).toBeVisible()
    expect(await issued()).toBe(before + 1)
  })

  test('shows the command before a decision is allowed', async ({ page }) => {
    await open(page)
    await expect(page.getByTestId('attention-pending_decision')).toContainText(
      'scripts/release.sh --publish'
    )
  })
})

test.describe('sessions', () => {
  test('a row carries the number, the directory, the attachments and the state', async ({
    page
  }) => {
    await open(page)
    await page.getByRole('button', { name: 'Sessions' }).click()
    const row = page.getByTestId('session-row-1')
    await expect(row).toContainText('/Users/rs/work/kalareach')
    await expect(row.getByTestId('attachment-count')).toHaveText('2')
    await expect(row).toContainText('Waiting for you')
    await page.screenshot({ path: shot('sessions-13.10'), fullPage: true })
  })
})

test.describe('the semantic view', () => {
  test('renders the document and keeps the draft across a change of view', async ({ page }) => {
    await openSession(page)
    await expect(page.getByText('Find why the reconnect test is flaky.')).toBeVisible()

    await page.getByTestId('composer-input').fill('half a thought')
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await page.getByTestId('raw-terminal').waitFor()
    await page.getByRole('tab', { name: 'Conversation' }).click()
    await expect(page.getByTestId('composer-input')).toHaveValue('half a thought')
    await page.screenshot({ path: shot('conversation-13.03'), fullPage: true })
  })

  test('a markdown link opens through the backend and never navigates the page', async ({
    page
  }) => {
    await openSession(page)
    const link = page.getByRole('button', { name: 'the reconnect notes' })
    await expect(link).toBeVisible()
    await link.click()
    await expect(page.getByRole('status')).toContainText('docs.example.org')
    expect(page.url()).toContain('/harness.html')
  })

  test('draws the six profiles and disables them when the prompt moves', async ({ page }) => {
    await openSession(page)
    const surface = page.getByTestId('launch-surface')
    for (const label of ['Codex', 'Claude Code', 'OpenCode', 'Gemini', 'Kimi', 'Qoder']) {
      await expect(surface.getByRole('button', { name: new RegExp(label) })).toBeVisible()
    }
    await page.screenshot({ path: shot('launch-13.11'), fullPage: true })

    await page.evaluate(() => {
      window.krTestHost?.changePromptGeneration()
    })
    await expect(page.getByTestId('launch-stale')).toBeVisible()
    await expect(surface.getByRole('button', { name: /Codex/ })).toBeDisabled()
  })

  test('stops following when the reader scrolls up, and follows again at the end', async ({
    page
  }) => {
    await openSession(page)
    await page.evaluate(() => {
      for (let index = 0; index < 400; index += 1) {
        window.krTestHost?.appendNode({
          id: `bulk-${index}`,
          revision: '1',
          body: { kind: 'message', author: 'agent', text: `line ${index}` }
        } as never)
      }
    })
    const scroller = page.getByTestId('conversation-scroll')
    // The burst is folded in on an animation frame, so the view has the content before the scroll
    // position means anything. These two say the folding is over: the last line of the burst is
    // drawn, and the view is still at the live end. Nothing else arrives after that, and the window
    // only changes when the reader scrolls, so the height the scrolls below are measured against
    // has finished moving. The bound is only there to stop a machine that has stopped drawing.
    await expect(page.getByText('line 399')).toBeVisible({ timeout: PRESENTATION_DEADLINE })
    await expect(scroller).toHaveAttribute('data-following', 'true')

    await scroller.evaluate((element) => {
      element.scrollTop = Math.round(element.scrollHeight / 4)
    })
    await expect(scroller).toHaveAttribute('data-following', 'false')

    // Reading at the top brings more of the document in, and the reader keeps their place rather
    // than being thrown to the end of the new window.
    await scroller.evaluate((element) => {
      element.scrollTop = 0
    })
    await expect
      .poll(async () => scroller.evaluate((element) => element.scrollTop), {
        timeout: PRESENTATION_DEADLINE
      })
      .toBeGreaterThan(0)
    await expect(scroller).toHaveAttribute('data-following', 'false')

    // Scrolling down brings the rest of the document in a window at a time. The view follows
    // again when it reaches the live end, and not at the bottom of every window on the way. Each
    // turn of this brings one more window in, so how many turns it takes and how long each one
    // costs are the document's and the machine's answers; the bound below is only a hang bound.
    await expect
      .poll(
        async () => {
          await scroller.evaluate((element) => {
            element.scrollTop = element.scrollHeight
          })
          return scroller.getAttribute('data-following')
        },
        { timeout: PRESENTATION_DEADLINE }
      )
      .toBe('true')
  })
})

test.describe('closing a session', () => {
  test('says what closing does before it is committed', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('close-session').click()
    const consequence = page.getByTestId('close-consequence')
    await expect(consequence).toContainText('Approvals that are waiting are invalidated')
    await expect(consequence).toContainText('Retained history is kept')
    await page.screenshot({ path: shot('close-07.54'), fullPage: true })
  })
})

test.describe('settings over a live session', () => {
  test('opens over the session and can be dragged away', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    const sheet = page.getByTestId('sheet')
    // The surface is still arriving when the engine first calls it visible, and it says which of
    // the three it is doing. Both the picture and the grip's position would otherwise be taken off
    // a surface that is still travelling: where it was, not where the person would grab it.
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    await expect(page.getByTestId('composer')).toBeVisible()
    await page.screenshot({ path: shot('settings-13.09'), fullPage: true })

    const grip = page.getByTestId('sheet-grip')
    const box = await grip.boundingBox()
    if (!box) throw new Error('the sheet has no grip')
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await page.mouse.down()
    await page.mouse.move(box.x + box.width / 2, box.y + 120, { steps: 6 })
    await page.mouse.move(box.x + box.width / 2, box.y + 420, { steps: 6 })
    await page.mouse.up()
    // The flick is taken at once; the surface then leaves over as many frames as the machine gives
    // it, which is what this waits for.
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  })

  test('explains what answering means before a viewer can be given it', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    await page.getByRole('button', { name: 'Sharing' }).click()
    await expect(page.getByTestId('answering-explanation')).toContainText(
      'input the agent may act on'
    )
    await page.screenshot({ path: shot('sharing-25.08'), fullPage: true })
  })
})

test.describe('the raw terminal', () => {
  test('draws the projection and says where its palette came from', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const terminal = page.getByTestId('raw-terminal')
    await expect(terminal).toBeVisible()
    await expect(page.getByTestId('palette-provenance')).toContainText('Probed')
    await expect(page.getByTestId('terminal-surface').locator('.xterm')).toBeVisible()
    await expect(page.getByTestId('terminal-surface')).toContainText('cargo test -p kr-client')
    await page.screenshot({ path: shot('terminal-04.04'), fullPage: true })
  })

  test('gives the wheel to the application in control mode and takes it in view mode', async ({
    page
  }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(page.getByTestId('raw-terminal')).toHaveAttribute('data-mode', 'control')

    await surface.hover()
    await page.mouse.wheel(0, 120)
    await expect(surface).toHaveAttribute('data-wheel-to-application', '1')

    await page.getByRole('tab', { name: 'View' }).click()
    await expect(page.getByTestId('raw-terminal')).toHaveAttribute('data-mode', 'view')
    // Back over the surface first: clicking the tab left the pointer on the header, and a wheel
    // delivered there would never reach the terminal at all.
    await surface.hover()
    // The count standing still says nothing on its own, because it was already standing at one.
    // This watches the wheel itself instead. The view owns the wheel here and cancels it, and the
    // path that would have given it to the application returns before anything is cancelled, so a
    // wheel that was cancelled is a wheel that was not forwarded. This listener sits on the same
    // element and in the same phase as the terminal's own, and was added after it, so it is called
    // second and reads a decision that has already been made.
    await surface.evaluate((element) => {
      const held = window as unknown as { krWheelCancelled?: boolean }
      held.krWheelCancelled = undefined
      element.addEventListener(
        'wheel',
        (event) => {
          held.krWheelCancelled = event.defaultPrevented
        },
        { capture: true, once: true }
      )
    })
    await page.mouse.wheel(0, 120)
    await expect
      .poll(
        async () =>
          page.evaluate(() => (window as unknown as { krWheelCancelled?: boolean }).krWheelCancelled),
        { timeout: PRESENTATION_DEADLINE }
      )
      .toBe(true)
    await expect(surface).toHaveAttribute('data-wheel-to-application', '1')

    // And control mode still gives it away, so the count moves when it is meant to.
    await page.getByRole('tab', { name: 'Control' }).click()
    await expect(page.getByTestId('raw-terminal')).toHaveAttribute('data-mode', 'control')
    await surface.hover()
    await page.mouse.wheel(0, 120)
    await expect(surface).toHaveAttribute('data-wheel-to-application', '2')
    await page.screenshot({ path: shot('terminal-modes-13.18'), fullPage: true })
  })
})

test.describe('packages', () => {
  test('searches the catalogue with no network and says so', async ({ page }) => {
    await open(page)
    await page.getByRole('button', { name: 'Plugins' }).click()
    await expect(page.getByTestId('offline-search-note')).toBeVisible()
    await page.getByRole('tab', { name: 'Catalogue' }).click()
    await page.getByTestId('catalogue-search').fill('gemini')
    await expect(page.getByTestId('catalogue-list')).toContainText('Gemini presentation')
    await expect(page.getByTestId('catalogue-list')).not.toContainText('tmux status')
    await page.screenshot({ path: shot('packages-11.03'), fullPage: true })
  })
})

test.describe('pairing', () => {
  test('pairs from a typed code, shows the value, and names the service first', async ({
    page
  }) => {
    await open(page)
    await page.getByRole('button', { name: 'Pair with a host' }).click()
    await expect(page.getByRole('heading', { name: 'Pair with a host' })).toBeVisible()
    await expect(page.getByTestId('pairing-service')).toHaveText('reach.kala.to')
    await expect(page.getByTestId('change-service')).toBeVisible()
    await page.screenshot({ path: shot('pairing-10.18'), fullPage: true })

    await page.getByLabel('Pairing code').fill('aB3x-Yz7-9Qw')
    await page.getByTestId('pair').click()
    await expect(page.getByTestId('pairing-status')).toHaveText('Reaching the pairing service')
    await page.evaluate(() => {
      window.krTestHost?.setPairing({
        state: {
          state: 'awaiting_approval',
          value: 'f3c1 46fd',
          expires_at_ms: Date.now() + 5 * 60_000,
          rights: ['session.view'],
          authority: 'view sessions',
          grant_expires_at_ms: null
        }
      })
    })
    await expect(page.getByRole('heading', { name: 'Check this value on the host' })).toBeFocused()
    await expect(page.getByTestId('verification-value')).toContainText('f3c1')
    await page.screenshot({ path: shot('pairing-value-10.37'), fullPage: true })
  })

  test('says a pasted text that is not an invitation is not one', async ({ page }) => {
    await open(page)
    await page.getByRole('button', { name: 'Pair with a host' }).click()
    await page.evaluate(() => {
      window.krTestHost?.setPasteboard({
        invitation: null,
        failure: 'not_an_invitation',
        cleared: false,
        declined: false
      })
    })
    await page.getByTestId('paste-invitation').click()
    await expect(page.getByTestId('paste-failure')).toHaveText('That is not a KalaReach invitation.')
    await page.screenshot({ path: shot('pairing-10.17'), fullPage: true })
  })

  test('an owner confirmation heads Attention and is left to this computer to review', async ({
    page
  }) => {
    await open(page)
    await page.evaluate(() => {
      window.krTestHost?.setConfirmations({
        ceremony: 'touch_id',
        requests: [
          {
            reference: 'request-1',
            host_name: 'studio',
            title: 'Pair a new device',
            detail: 'studio will let pixel-8 view sessions, for 1 hour.',
            value: 'f3c1 46fd',
            expires_at_ms: Date.now() + 120_000,
            checkable: true
          },
          {
            reference: 'request-2',
            host_name: 'build-box',
            title: 'Confirm a request from build-box',
            detail: null,
            value: null,
            expires_at_ms: Date.now() + 90_000,
            checkable: false
          }
        ]
      })
    })
    const rows = page.getByTestId('confirmation-row')
    await expect(rows).toHaveCount(2)
    await expect(page.getByRole('heading', { name: 'Your hosts need your confirmation' })).toBeVisible()
    await expect(rows.nth(0).getByTestId('confirm-request')).toHaveText('Confirm with Touch ID')
    await expect(rows.nth(1).getByTestId('cannot-check')).toBeVisible()
    await expect(rows.nth(1).getByTestId('confirm-request')).toHaveCount(0)
    await page.screenshot({
      path: shot('owner-confirmations-10.06'),
      fullPage: true,
      animations: 'disabled'
    })

    await rows.nth(0).getByTestId('confirm-request').click()
    await expect(page.locator('.toast')).toContainText('Confirmed. studio can go ahead.')
    await expect(rows).toHaveCount(1)
    expect(await page.evaluate(() => window.krTestHost?.reviewed ?? [])).toEqual(['request-1'])

    await rows.nth(0).getByTestId('not-now').click()
    await expect(page.getByTestId('confirmations')).toHaveCount(0)
  })
})

test.describe('a control that commits on a completed action', () => {
  // KR-REQ-13.07: in the engine, a key commits an owner's confirmation on its release and no click
  // follows it, so nothing is left waiting for one; a click that counts no press, as WebKit's
  // accessibility activation and a script's `click()` send, then commits it; and the click the
  // engine sends after a pointer's release counts that press. Every commit asks native code for a
  // review, which this host answers "not confirmed" with a toast of its own and the request left
  // in place, so a new toast is a commit.
  test('a key commit leaves nothing behind that a click without a press meets', async ({ page }) => {
    for (const key of ['Enter', 'Space']) {
      await open(page)
      await page.evaluate(() => {
        window.krTestHost?.setReviewOutcome('not_confirmed')
        window.krTestHost?.setConfirmations({
          ceremony: 'touch_id',
          requests: [
            {
              reference: 'request-1',
              host_name: 'studio',
              title: 'Pair a new device',
              detail: null,
              value: 'f3c1 46fd',
              expires_at_ms: Date.now() + 120_000,
              checkable: true
            }
          ]
        })
      })
      const confirm = page.getByTestId('confirm-request')
      await expect(confirm).toHaveText('Confirm with Touch ID')
      await confirm.evaluate((element) => {
        const counts: number[] = []
        element.addEventListener('click', (event) => {
          counts.push((event as MouseEvent).detail)
        })
        ;(window as unknown as { krClickCounts: number[] }).krClickCounts = counts
      })
      const counts = (): Promise<number[]> =>
        page.evaluate(() => (window as unknown as { krClickCounts: number[] }).krClickCounts)
      const fresh = page.locator('.toast:not([data-kr-seen])')
      const committed = async (): Promise<void> => {
        await expect(fresh).toContainText('Not confirmed. Nothing changed.')
        await fresh.evaluate((toast) => {
          toast.setAttribute('data-kr-seen', '')
        })
        await expect(confirm).toBeEnabled()
      }

      await confirm.focus()
      await page.keyboard.press(key)
      await committed()
      expect(await counts(), `${key} is followed by no click`).toEqual([])

      await confirm.evaluate((element) => {
        ;(element as HTMLElement).click()
      })
      await committed()
      expect(await counts(), 'the activation counts no press').toEqual([0])

      await confirm.click()
      await committed()
      expect(await counts(), 'the click after a release counts the press').toEqual([0, 1])

      const reviewed = await page.evaluate(() => window.krTestHost?.reviewed ?? [])
      expect(reviewed, 'each commit asked for one review of the request').toEqual([
        'request-1',
        'request-1',
        'request-1'
      ])
    }
  })
})

test.describe('retained artefacts', () => {
  test('each is deleted on its own, and a copy elsewhere is not offered', async ({ page }) => {
    await open(page)
    await page.getByRole('button', { name: 'Change sets' }).click()
    const retained = page.getByTestId('retained-artefacts')
    await expect(retained).toBeVisible()
    await expect(retained.getByTestId('delete-obj-3')).toBeDisabled()
    await expect(retained.getByTestId('held-elsewhere')).toBeVisible()
    await page.screenshot({ path: shot('privacy-24.29'), fullPage: true })
  })
})

test.describe('appearance', () => {
  test('light, dark and system are all the same interface', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    await page.getByRole('radio', { name: 'Dark' }).check()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    await page.screenshot({ path: shot('appearance-dark-13.04'), fullPage: true })

    await page.getByRole('radio', { name: 'Light' }).check()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
    await page.screenshot({ path: shot('appearance-light-13.04'), fullPage: true })
  })
})

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' })

  test('the sheet still opens, closes and dismisses without travelling', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    const sheet = page.getByTestId('sheet')
    // Read once the surface says it has arrived. Reading it the instant the engine calls the
    // element visible would read the transform before the surface has been placed at all, and an
    // element that has not been placed reports no transform, which passes this for the wrong
    // reason.
    await expect(sheet).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    const transform = await sheet.evaluate((element) => getComputedStyle(element).transform)
    expect(transform === 'none' || transform.includes('matrix(1, 0, 0, 1, 0, 0)')).toBe(true)
    await page.keyboard.press('Escape')
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  })
})

test.describe('the keyboard', () => {
  test('reaches the navigation and the composer without a pointer', async ({ page }) => {
    await open(page)
    // The skip link is the first thing in the document and becomes visible when it has focus.
    // Which key reaches it is the platform's policy, not this application's.
    const skip = page.getByRole('link', { name: 'Skip to content' })
    await skip.focus()
    await expect(skip).toBeInViewport()

    await page.getByRole('button', { name: 'Sessions' }).focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('session-row-1')).toBeVisible()

    await page.getByTestId('session-row-1').focus()
    await page.keyboard.press('Enter')
    const composer = page.getByTestId('composer-input')
    await composer.focus()
    await page.keyboard.type('typed with the keyboard')
    await expect(composer).toHaveValue('typed with the keyboard')
  })

  // KR-REQ-13.20: text streaming into a conversation carries no animation and no transition, of
  // any property, on the text or on anything that contains it, from the moment it is inserted and
  // through every update that follows, so nothing stands between the text and the person reading
  // it.
  test('streamed text is not animated', async ({ page }) => {
    await openSession(page)
    // From here on, every transition and animation the engine starts is recorded with whether it
    // runs on the streamed node, inside it, or on something that contains it; so is every one
    // still running each time the page changes.
    await page.evaluate(() => {
      const streamed = '[data-node-id="streamed-1"]'
      const motion: string[] = []
      const record = (what: string, target: EventTarget | null) => {
        if (!(target instanceof Element)) return
        if (target.closest(streamed) === null && target.querySelector(streamed) === null) return
        motion.push(`${what} on ${target.tagName.toLowerCase()}.${target.className}`)
      }
      for (const type of ['transitionrun', 'animationstart']) {
        document.addEventListener(
          type,
          (event) => {
            const name =
              event instanceof TransitionEvent
                ? event.propertyName
                : (event as AnimationEvent).animationName
            record(`${type} ${name}`, event.target)
          },
          true
        )
      }
      const running = () => {
        for (const animation of document.getAnimations()) {
          const effect = animation.effect
          record(
            `running ${animation.constructor.name}`,
            effect instanceof KeyframeEffect ? effect.target : null
          )
        }
      }
      new MutationObserver(running).observe(document.body, {
        subtree: true,
        childList: true,
        characterData: true,
        attributes: true
      })
      ;(window as unknown as { krMotion: () => string[] }).krMotion = () => {
        running()
        return motion
      }
    })

    // The node arrives, and then its text grows the way a streamed answer does, one revision at a
    // time, each one drawn before the next arrives.
    const words = ['kr-streamed', 'text', 'that', 'keeps', 'arriving']
    for (let revision = 1; revision <= words.length; revision += 1) {
      const text = words.slice(0, revision).join(' ')
      await page.evaluate(
        ({ revision, text }) => {
          window.krTestHost?.appendNode({
            id: 'streamed-1',
            revision: String(revision),
            body: { kind: 'message', author: 'agent', text }
          } as never)
        },
        { revision, text }
      )
      await expect(page.getByText(text, { exact: true })).toBeVisible({
        timeout: PRESENTATION_DEADLINE
      })
    }
    const motion = await page.evaluate(
      () =>
        new Promise<string[]>((resolve) => {
          // Two frames, so anything the last change started has been started and reported.
          requestAnimationFrame(() => {
            requestAnimationFrame(() => {
              resolve((window as unknown as { krMotion: () => string[] }).krMotion())
            })
          })
        })
    )
    expect(motion).toEqual([])

    // The same record sees motion where there is some: a transform eased on the node itself.
    const moved = await page.evaluate(
      () =>
        new Promise<string[]>((resolve) => {
          const node = document.querySelector<HTMLElement>('[data-node-id="streamed-1"]')
          if (!node) {
            resolve([])
            return
          }
          node.style.transition = 'transform 150ms'
          requestAnimationFrame(() => {
            node.style.transform = 'translateY(4px)'
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                resolve((window as unknown as { krMotion: () => string[] }).krMotion())
              })
            })
          })
        })
    )
    expect(moved.some((entry) => entry.includes('transform'))).toBe(true)
  })

  // KR-REQ-13.20: a change the keyboard made is not animated.
  test('a keyboard change is not animated', async ({ page }) => {
    await open(page)
    await page.keyboard.press('Tab')
    await expect(page.locator('html')).toHaveAttribute('data-input', 'keyboard')
    const duration = await page
      .getByRole('button', { name: 'Sessions' })
      .evaluate((element) => getComputedStyle(element).transitionDuration)
    expect(duration.split(',').every((value) => value.trim() === '0s')).toBe(true)
  })
})
