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

import { expect, test, type Locator, type Page } from '@playwright/test'

import { RECORD_VERSION, SUBMISSIONS_KEY } from '../src/mobile/model/store'
import type { Submission } from '../src/model/receipts'

import { PRESENTATION_DEADLINE } from './bounds'

/** Where a screenshot for the evidence goes. */
function shot(name: string): string {
  return `/tmp/kr-companion-${name}.png`
}

/**
 * Takes a screenshot for this browser once every transition on the page has finished or been
 * cancelled, so none is caught halfway. Each engine keeps its own.
 */
async function still(page: Page, name: string): Promise<void> {
  await page.evaluate(() =>
    Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined)))
  )
  await page.screenshot({ path: shot(`${name}-${test.info().project.name}`) })
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

/**
 * Takes control of the open raw view, as the person does, and waits until the session has given
 * it: the mode button looks around, and the scripted host holds the view's take.
 */
async function takeControl(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Take control' }).click()
  await expect(page.getByRole('button', { name: 'Look around' })).toBeVisible()
  await expect
    .poll(async () => page.evaluate(() => window.krTestHost?.terminalViews.at(-1)?.control.state))
    .toBe('controlling')
}

/** Every wheel turn, key, text and paste the newest raw view took for the program, in order. */
async function programInputs(page: Page) {
  return page.evaluate(() =>
    (window.krTestHost?.terminalViews.at(-1)?.inputs ?? []).filter(
      (input) => input.kind !== 'take' && input.kind !== 'release'
    )
  )
}

/**
 * Opens the phone with an action on `sessionId` whose outcome nobody has confirmed, as the device
 * keeps one across a restart. Until a receipt settles it, that session sends nothing more.
 */
async function withUnconfirmedAction(page: Page, sessionId: string): Promise<void> {
  const unconfirmed: Submission = {
    localId: `local:${sessionId}:1`,
    actionId: null,
    label: 'cargo test',
    text: 'cargo test',
    state: 'unknown',
    createdAtMs: 1,
    error: null
  }
  await page.addInitScript(
    ({ key, record }) => {
      localStorage.setItem(key, JSON.stringify(record))
    },
    { key: SUBMISSIONS_KEY, record: { version: RECORD_VERSION, value: [unconfirmed] } }
  )
}

/**
 * Sets a person's own text size on the page before it loads, so the page lays itself out at that
 * size from its first frame, as a phone that already had the setting opens it.
 */
async function withTextSize(page: Page, size: string): Promise<void> {
  await page.addInitScript((scale) => {
    // The document may not have its root element yet: the size goes on it the moment it does.
    const apply = (): boolean => {
      const root = document.documentElement as HTMLElement | null
      if (root === null) return false
      root.style.fontSize = scale
      // What the page's own scripts found on the root before any of them ran, for a test to say.
      ;(window as unknown as { krTextSizeAtLoad?: string }).krTextSizeAtLoad = scale
      return true
    }
    if (!apply()) {
      new MutationObserver((_, observer) => {
        if (apply()) observer.disconnect()
      }).observe(document, { childList: true })
    }
  }, size)
}

/** Where the focus is, as the element's tag and id, or `body` where nothing holds it. */
async function focusedNow(page: Page): Promise<string> {
  return page.evaluate(() =>
    document.activeElement === document.body
      ? 'body'
      : `${document.activeElement?.tagName.toLowerCase()}#${document.activeElement?.id}`
  )
}

/**
 * Where this engine leaves the focus when a button a pointer pressed goes from the page. Engines and
 * their ports differ: some focus a button that a press lands on, so the focus goes with it, and some
 * focus the nearest element that can take it, which stays. What a page leaves alone is therefore
 * found by pressing a stand-in that sits beside `beside`, in the same parent, and taking it away as
 * the page takes a button away.
 */
async function whereAPressedButtonLeavesTheFocus(page: Page, beside: Locator): Promise<string> {
  await beside.evaluate((control) => {
    const standIn = document.createElement('button')
    standIn.type = 'button'
    standIn.id = 'stand-in-for-a-pressed-button'
    standIn.textContent = 'Stand-in'
    control.after(standIn)
  })
  await page.locator('#stand-in-for-a-pressed-button').click()
  await page.evaluate(() => {
    document.getElementById('stand-in-for-a-pressed-button')?.remove()
  })
  return focusedNow(page)
}

/**
 * Holds a test to its text size having been the page's from its first frame: a size set after the
 * page loaded lays the page out once at the base size first, and a layout that only holds after a
 * second pass is not the layout a person with the setting opens.
 */
async function expectTextSizeFromLoad(page: Page, size: string): Promise<void> {
  expect(
    await page.evaluate(() => (window as unknown as { krTextSizeAtLoad?: string }).krTextSizeAtLoad),
    `the text size ${size} is set before the page loads`
  ).toBe(size)
}

/**
 * How far `locator`'s element runs outside what a person sees of it: outside the screen, or
 * outside any box around it that clips what it holds. Zero when it is whole in view.
 */
async function hiddenPart(locator: Locator): Promise<number> {
  return locator.evaluate((element) => {
    const box = element.getBoundingClientRect()
    let top = 0
    let bottom = window.innerHeight
    for (let around = element.parentElement; around !== null; around = around.parentElement) {
      const style = getComputedStyle(around)
      if (style.overflowY === 'visible' && style.overflowX === 'visible') continue
      const clip = around.getBoundingClientRect()
      top = Math.max(top, clip.top)
      bottom = Math.min(bottom, clip.bottom)
    }
    return Math.max(0, top - box.top) + Math.max(0, box.bottom - bottom)
  })
}

/**
 * How far the focus ring around `locator`'s element runs outside what a person sees of it, on its
 * most hidden side: outside the screen, or outside any box around it that clips what it holds.
 * Zero when the whole ring is in view, and endless when the element draws no ring at all.
 */
async function ringHidden(locator: Locator): Promise<number> {
  return locator.evaluate((element) => {
    const style = getComputedStyle(element)
    if (style.outlineStyle === 'none' || !(parseFloat(style.outlineWidth) > 0)) return Infinity
    const ring = Math.max(0, parseFloat(style.outlineWidth) + parseFloat(style.outlineOffset))
    const box = element.getBoundingClientRect()
    const seen = { top: 0, right: window.innerWidth, bottom: window.innerHeight, left: 0 }
    for (let around = element.parentElement; around !== null; around = around.parentElement) {
      const clipping = getComputedStyle(around)
      if (clipping.overflowY === 'visible' && clipping.overflowX === 'visible') continue
      const clip = around.getBoundingClientRect()
      seen.top = Math.max(seen.top, clip.top)
      seen.right = Math.min(seen.right, clip.right)
      seen.bottom = Math.min(seen.bottom, clip.bottom)
      seen.left = Math.max(seen.left, clip.left)
    }
    return Math.max(
      0,
      seen.top - (box.top - ring),
      box.right + ring - seen.right,
      box.bottom + ring - seen.bottom,
      seen.left - (box.left - ring)
    )
  })
}

test.describe('the attention inbox', () => {
  test('shows the four states and never calls a lost connection a failure', async ({ page }) => {
    await open(page)
    await expect(page.getByTestId('attention-pending_decision').first()).toBeVisible()
    await expect(page.getByTestId('attention-failed_action')).toBeVisible()
    await expect(page.getByTestId('attention-awaiting_review')).toBeVisible()
    await expect(page.getByTestId('attention-notice')).toContainText('It is not a request from the host.')
    const disconnected = page.getByTestId('attention-disconnected')
    await expect(disconnected).toBeVisible()
    await expect(disconnected).toContainText('may still be running')
    await expect(disconnected).not.toContainText(/failed|stuck/i)
    await page.screenshot({ path: shot('attention-13.01'), fullPage: true })
  })

  // KR-REQ-13.07: an approval is decided by a completed press. A press that slides off the control
  // decides nothing, including through the click the browser sends after the release, and a
  // completed press decides once.
  test('a press that slides off an approval decides nothing', async ({ page }) => {
    await open(page)
    const allow = page.getByTestId('approval').getByRole('button', { name: 'Allow once' })
    // What the session's worker holds for the request: pending until a decision reaches it.
    const state = (): Promise<string | null> =>
      page.evaluate(
        () =>
          window.krTestHost?.records.agentOf('8a7b6c50-22bb-4c3d-8e4f-000000000101').resources[0]
            ?.state ?? null
      )
    expect(await state()).toBe('pending')
    const box = await allow.boundingBox()
    if (!box) throw new Error('the approval has no control')

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await page.mouse.down()
    await page.mouse.move(box.x + box.width / 2, box.y + box.height + 160, { steps: 6 })
    await page.mouse.up()
    expect(await state()).toBe('pending')

    await allow.click()
    await expect(page.getByText('You chose “Allow once”.')).toBeVisible()
    expect(await state()).toBe('resolved')
  })

  test('shows what a decision is about, and what the agent sent, before it is allowed', async ({
    page
  }) => {
    await open(page)
    const approval = page.getByTestId('approval')
    await expect(approval.getByRole('heading')).toContainText('scripts/release.sh --publish')
    await approval.getByText('What the agent sent').click()
    await expect(approval.getByTestId('approval-source')).toContainText('execCommandApproval')
    await still(page, 'approval-11.26')
  })
})

// KR-REQ-13.15: the conversation keeps up with new entries only while the reader is at its live
// end, leaves a reader who scrolled away where they are, and a change of view and back returns them
// to the same place.
test.describe('the conversation keeps its place', () => {
  const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** Records `count` entries of the main agent, and has the page read them at once. */
  async function written(page: Page, count: number, from: number): Promise<void> {
    await page.evaluate(
      ({ session, count, from }) => {
        for (let index = 0; index < count; index += 1) {
          window.krTestHost?.records.appendEntry(
            session,
            'message',
            `Entry ${from + index}: ${'a line that wraps across the conversation '.repeat(4)}`
          )
        }
        document.dispatchEvent(new Event('visibilitychange'))
      },
      { session: MAIN, count, from }
    )
  }

  /** The node the reader is looking at and how far its top is from the top of the view. */
  const reading = (scroll: Locator) =>
    scroll.evaluate((element) => {
      for (const node of element.querySelectorAll<HTMLElement>('[data-node-id]')) {
        if (node.offsetTop + node.offsetHeight > element.scrollTop) {
          return { id: node.dataset.nodeId ?? '', offset: Math.round(node.offsetTop - element.scrollTop) }
        }
      }
      return null
    })

  const atEnd = (scroll: Locator) =>
    scroll.evaluate((element) => element.scrollHeight - element.scrollTop - element.clientHeight < 4)

  test('follows only at the live end, and returns the reader to their place', async ({ page }) => {
    await openSession(page)
    const scroll = page.getByTestId('conversation-scroll')
    await written(page, 40, 1)
    await expect(scroll.locator('[data-node-id$=":45"]')).toBeAttached()
    await expect.poll(() => atEnd(scroll)).toBe(true)

    // At the live end, a new entry is followed.
    await written(page, 1, 41)
    await expect(scroll.locator('[data-node-id$=":46"]')).toBeAttached()
    await expect.poll(() => atEnd(scroll)).toBe(true)

    // Scrolled away, the reader stays where they are when another arrives.
    await scroll.evaluate((element) => {
      element.scrollTop = element.scrollHeight / 3
    })
    await expect(scroll).toHaveAttribute('data-following', 'false')
    const before = await reading(scroll)
    expect(before).not.toBeNull()
    await written(page, 1, 42)
    await expect(scroll.locator('[data-node-id$=":47"]')).toBeAttached()
    expect(await reading(scroll)).toEqual(before)

    // To the terminal and back: the same node, the same distance from the top.
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await page.getByTestId('raw-terminal').waitFor()
    await page.getByRole('tab', { name: 'Conversation' }).click()
    await expect(scroll).toBeVisible()
    await expect.poll(() => reading(scroll)).toEqual(before)
    await page.screenshot({ path: shot(`conversation-place-13.15-${test.info().project.name}`) })
  })
})

// KR-REQ-13.15: the retained output is read a page at a time with its cursor and byte bound, the
// window moves towards older and newer output with the reader's page kept where it is, and a change
// of view and back returns the reader to the same place.
test.describe("a session's retained output", () => {
  const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** The page the reader is looking at and how far its top is from the top of the view. */
  const reading = (scroll: Locator) =>
    scroll.evaluate((element) => {
      for (const block of element.querySelectorAll<HTMLElement>('[data-from]')) {
        if (block.offsetTop + block.offsetHeight > element.scrollTop) {
          return {
            from: block.dataset.from ?? '',
            offset: Math.round(block.offsetTop - element.scrollTop)
          }
        }
      }
      return null
    })

  test('moves both ways with the reader kept in place, and returns them after a change of view', async ({
    page
  }) => {
    // More output than one page carries.
    await page.goto('/harness.html')
    await page.waitForSelector('.app-shell')
    await page.evaluate((session) => {
      const lines: string[] = []
      for (let index = 0; index < 4000; index += 1) {
        lines.push(`line ${String(index).padStart(4, '0')} \u001b[2m${'of retained output '.repeat(2)}\u001b[0m`)
      }
      window.krTestHost?.records.appendOutput(session, `\r\n${lines.join('\r\n')}\r\n`)
    }, MAIN)
    await page.getByRole('button', { name: 'Sessions' }).click()
    await page.getByTestId('session-row-1').click()
    await page.getByRole('tab', { name: 'Output' }).click()
    const scroll = page.getByTestId('output-scroll')
    await expect(scroll).toContainText('line 3999')
    await expect(scroll).toHaveAttribute('data-following', 'true')
    await expect(scroll).not.toContainText('\u001b')

    // Up to the top of the window: the page before is read, and the reader's page stays put.
    const pages = () => scroll.locator('[data-from]').count()
    const before = await pages()
    const first = (await scroll.locator('[data-from]').first().getAttribute('data-from')) ?? ''
    /** How far the top of the page that begins at `from` is from the top of the view. */
    const placeOf = (from: string) =>
      scroll.evaluate((element, cursor) => {
        const block = element.querySelector<HTMLElement>(`[data-from="${cursor}"]`)
        return block === null ? null : Math.round(block.offsetTop - element.scrollTop)
      }, from)
    // The read the scroll asks for is held until the page's place has been measured.
    await page.evaluate(() => {
      const held = window.krTestHost?.hold('historyPage')
      ;(window as unknown as { heldPages?: typeof held }).heldPages = held
    })
    await scroll.evaluate((element) => {
      element.scrollTop = 0
    })
    const top = await placeOf(first)
    await page.evaluate(() => {
      ;(window as unknown as { heldPages?: { release: () => void } }).heldPages?.release()
    })
    await expect.poll(pages).toBeGreaterThan(before)
    await expect(scroll).toHaveAttribute('data-following', 'false')
    // The page that was at the top is where it was: the older one arrived above it, unseen.
    await expect.poll(() => placeOf(first)).toBe(top)
    const kept = await reading(scroll)

    // To the conversation and back: the same page, the same distance from the top.
    await page.getByRole('tab', { name: 'Conversation' }).click()
    await page.getByTestId('conversation').waitFor()
    await page.getByRole('tab', { name: 'Output' }).click()
    await expect.poll(() => reading(scroll)).toEqual(kept)
    await page.screenshot({ path: shot(`output-13.15-${test.info().project.name}`) })

    // Back down to the live end: newer pages are read and the view keeps up again.
    for (let step = 0; step < 20; step += 1) {
      await scroll.evaluate((element) => {
        element.scrollTop = element.scrollHeight
      })
      if ((await scroll.getAttribute('data-following')) === 'true') break
      await page.waitForTimeout(100)
    }
    await expect(scroll).toHaveAttribute('data-following', 'true')
    await expect(scroll).toContainText('line 3999')
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

test.describe('reading once it is listening', () => {
  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  // KR-REQ-13.11: the surface is read at one prompt generation and answers after the prompt has
  // moved on, so the buttons it draws are disabled.
  test('draws the launch buttons disabled when the prompt moved before the surface answered', async ({
    page
  }) => {
    await open(page)
    const held = await page.evaluateHandle(() => {
      const host = window.krTestHost
      if (!host) throw new Error('the harness has no scripted host')
      return host.hold('launchSurface')
    })
    await page.getByRole('button', { name: 'Sessions' }).click()
    await page.getByTestId('session-row-1').click()
    await page.getByTestId('conversation').waitFor()
    await expect.poll(() => held.evaluate((reads) => reads.count)).toBe(1)

    await page.evaluate(() => {
      window.krTestHost?.changePromptGeneration()
    })
    await held.evaluate((reads) => {
      reads.release()
    })

    const surface = page.getByTestId('launch-surface')
    await expect(page.getByTestId('launch-stale')).toBeVisible()
    await expect(surface.getByRole('button', { name: /Codex/ })).toBeDisabled()
    await page.screenshot({ path: shotFor('launch-13.11-overtaken'), fullPage: true })
  })

  // KR-REQ-13.02: before its first answer the session view claims nothing: no lost contact and no
  // launch button.
  test('the session view claims nothing before its first answer', async ({ page }) => {
    await open(page)
    const complete = await page.evaluateHandle(() => {
      const host = window.krTestHost
      if (!host) throw new Error('the harness has no scripted host')
      return host.holdRegistrations()
    })
    await page.getByRole('button', { name: 'Sessions' }).click()
    await page.getByTestId('session-row-1').click()
    await page.getByTestId('conversation').waitFor()

    await expect(page.getByText('Not in contact with this host')).toHaveCount(0)
    await expect(page.getByTestId('launch-surface')).toHaveCount(0)
    await page.screenshot({ path: shotFor('session-13.02-before-answer'), fullPage: true })

    await complete.evaluate((done) => {
      done()
    })
    await expect(page.getByText('Session 1 · Waiting for you')).toBeVisible()
    await expect(page.getByTestId('launch-surface')).toBeVisible()
    await expect(page.getByText('Not in contact with this host')).toHaveCount(0)
  })

  // KR-REQ-13.02: the phone's shell, its inbox and its account, before and after their first
  // answers. The shell registers as the page loads, so the registrations are held from then.
  test('the phone claims nothing before its first answers', async ({ page }) => {
    await page.addInitScript(() => {
      let host: unknown
      Object.defineProperty(window, 'krTestHost', {
        configurable: true,
        get: () => host,
        set: (controls: { holdRegistrations: () => () => void }) => {
          host = controls
          ;(window as unknown as { krRegistered: () => void }).krRegistered =
            controls.holdRegistrations()
        }
      })
    })
    await page.goto('/harness.html?surface=ios')
    const connection = page.locator('.m-connection')

    // Neither contact nor its loss: the bar says it is checking, with no dot to colour.
    await expect(connection).toHaveText('Checking the connection…')
    await expect(connection.locator('.status-dot')).toHaveCount(0)
    await expect(page.getByText('Reading the inbox…')).toBeVisible()
    await page.screenshot({ path: shotFor('phone-13.02-before-answer'), fullPage: true })
    await page.getByRole('button', { name: /^Account/ }).click()
    await expect(page.getByTestId('account-panel')).toHaveAttribute('aria-busy', 'true')
    await expect(page.getByRole('button', { name: 'Sign in' })).toHaveCount(0)
    await page.screenshot({ path: shotFor('phone-account-before-answer'), fullPage: true })

    await page.evaluate(() => {
      ;(window as unknown as { krRegistered: () => void }).krRegistered()
    })
    await expect(connection).toHaveText('In contact with this host')
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
    await page.getByRole('button', { name: /^Attention/ }).click()
    await expect(page.locator('[data-kind="failed_action"]')).toBeVisible()
    await page.screenshot({ path: shotFor('phone-13.02-after-answer'), fullPage: true })
  })
})

test.describe('nothing claimed before the first answer', () => {
  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /**
   * Holds the shell's first connection read from the moment the scripted host exists, before the
   * page has asked anything, and keeps the held read where the test can answer it.
   */
  async function holdFirstConnectionRead(page: Page): Promise<void> {
    await page.addInitScript(() => {
      let host: unknown
      Object.defineProperty(window, 'krTestHost', {
        configurable: true,
        get: () => host,
        set: (controls: { hold: (read: string) => unknown }) => {
          host = controls
          ;(window as unknown as { krHeldConnection: unknown }).krHeldConnection =
            controls.hold('connectionState')
        }
      })
    })
  }

  /** Answers the held connection read. */
  async function answerConnection(page: Page): Promise<void> {
    await page.evaluate(() => {
      ;(window as unknown as { krHeldConnection: { release: () => void } }).krHeldConnection.release()
    })
  }

  for (const [label, size] of [
    ['desktop', { width: 1280, height: 800 }],
    ['phone-width', { width: 390, height: 844 }]
  ] as const) {
    // KR-REQ-13.02: the desktop bar says neither "connected" nor "not in contact" before the shell
    // has answered; it says it is checking, with no dot.
    test(`the desktop bar claims nothing before its first answer, at ${label} width`, async ({ page }) => {
      await page.setViewportSize(size)
      await holdFirstConnectionRead(page)
      await open(page)
      const connection = page.locator('.topbar .connection')

      await expect(connection).toHaveText('Checking the connection…')
      await expect(connection.locator('.status-dot')).toHaveCount(0)
      await page.screenshot({ path: shotFor(`desktop-13.02-before-answer-${label}`), fullPage: true })

      await answerConnection(page)
      await expect(connection).toHaveText('Connected to this machine')
      await expect(connection.locator('.status-dot')).toHaveCount(1)
    })
  }

  // KR-REQ-13.02: a phone session opened from a notification claims no loss of contact before the
  // shell has answered, and neither does the bar above it.
  test('a phone session opened from a notification claims nothing before its first answer', async ({
    page
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await holdFirstConnectionRead(page)
    await page.goto('/harness.html?surface=ios&session=8a7b6c50-22bb-4c3d-8e4f-000000000101')
    await expect(page.getByLabel('Message this session')).toBeVisible()
    const connection = page.locator('.m-connection')

    await expect(connection).toHaveText('Checking the connection…')
    await expect(connection.locator('.status-dot')).toHaveCount(0)
    await expect(page.getByText('Not in contact with this host')).toHaveCount(0)
    await page.screenshot({ path: shotFor('phone-session-13.02-before-answer'), fullPage: true })

    await answerConnection(page)
    await expect(connection).toHaveText('In contact with this host')
    await expect(page.getByText('Not in contact with this host')).toHaveCount(0)
  })
})

test.describe('closing a session', () => {
  // KR-REQ-07.54: the built application shows what closing does before the close is committed.
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
  // KR-REQ-13.09: the desktop's navigation has Attention, Sessions and Hosts, and its settings open
  // over a live session without leaving it: the conversation and the composer stay behind the
  // sheet, and are there once it goes.
  test('opens over the session and can be dragged away', async ({ page }) => {
    await openSession(page)
    await expect(
      page.getByRole('complementary', { name: 'Workspace navigation' }).locator('nav').getByRole('button')
    ).toContainText(['Attention', 'Sessions', 'Hosts'])
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
    await expect(page.getByTestId('conversation')).toBeVisible()
    await expect(page.getByTestId('composer')).toBeVisible()
  })

  // KR-REQ-25.08: answering a question is explained before a viewer can be given it, and photographed.
  test('explains what answering means before a viewer can be given it', async ({ page }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    await page.getByRole('button', { name: 'Sharing' }).click()
    await expect(page.getByTestId('answering-explanation')).toContainText(
      'input the agent may act on'
    )
    await page.screenshot({ path: shot('sharing-25.08'), fullPage: true })
  })

  // KR-REQ-25.08: an invitation shows what it carries before it exists, and issues exactly that.
  test('shows what an invitation carries before it exists, and issues exactly that', async ({
    page
  }) => {
    await openSession(page)
    await page.getByTestId('open-settings').click()
    await page.getByRole('button', { name: 'Sharing' }).click()
    const carries = page.getByTestId('invitation-carries')
    await expect(carries).toContainText('See what the session shows and does from when they accept')
    await page.getByRole('switch', { name: 'Let a viewer or reviewer answer questions' }).click()
    await expect(carries.locator('[data-notice="agent_permissions"]')).toBeVisible()
    await page.getByRole('radio', { name: /Sam's iPhone/ }).check()
    await still(page, 'sharing-25.08-invitation')
    await page.getByTestId('invite').click()
    await expect(page.getByText(/Invitation issued to Sam's iPhone\. It is used once/)).toBeVisible()
    await expect(page.getByTestId('issued-grants')).toContainText('Waiting to be used')
  })
})

test.describe('the raw terminal', () => {
  test('draws the projection and says where its palette came from', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const terminal = page.getByTestId('raw-terminal')
    await expect(terminal).toBeVisible()
    await expect(page.getByTestId('palette-provenance')).toContainText("the creating terminal's colours")
    await expect(page.getByTestId('terminal-grid')).toBeVisible()
    await expect(page.getByTestId('terminal-surface')).toContainText('cargo test -p kr-client')
    await page.screenshot({ path: shot('terminal-04.04'), fullPage: true })
  })

  test("draws the session's cursor where its screen has it", async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(surface).toContainText('cargo test -p kr-client')
    // The scripted screen's cursor is on its sixth line, just after the prompt's "$ ".
    const cursor = page.getByTestId('terminal-cursor')
    await expect(cursor).toHaveAttribute('data-shape', 'block')
    const offsets = await page.evaluate(() => {
      const grid = document.querySelector<HTMLElement>('[data-testid="terminal-grid"]')
      const mark = document.querySelector<HTMLElement>('[data-testid="terminal-cursor"]')
      if (grid === null || mark === null) return null
      const gridBox = grid.getBoundingClientRect()
      const markBox = mark.getBoundingClientRect()
      const cellWidth = gridBox.width / Number(grid.dataset.columns)
      const cellHeight = gridBox.height / Number(grid.dataset.rows)
      return {
        across: Math.abs(markBox.left - gridBox.left - 2 * cellWidth),
        down: Math.abs(markBox.top - gridBox.top - 5 * cellHeight)
      }
    })
    expect(offsets?.across ?? Number.POSITIVE_INFINITY).toBeLessThan(0.5)
    expect(offsets?.down ?? Number.POSITIVE_INFINITY).toBeLessThan(0.5)
  })

  // KR-REQ-04.04: in a real engine, each piece stays in a box of its own at its canonical cells,
  // clipped to them, and no piece shifts the ones after it.
  test('draws every piece in a box of its own at its cells, whatever the browser makes of its text', async ({
    page
  }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(surface).toContainText('cargo test -p kr-client')
    await page.evaluate(() => {
      const plain = {
        background: 'default',
        blink: 'none',
        bold: false,
        faint: false,
        foreground: 'default',
        invisible: false,
        italic: false,
        overline: false,
        reverse: false,
        strikethrough: false,
        underline: 'none',
        underline_colour: 'default',
        vertical_align: 'baseline'
      } as const
      const at = (column: number, cells: number, text: string, bold = false, invisible = false) => ({
        column,
        cells,
        text,
        rendition: { ...plain, bold, invisible },
        hyperlink: null
      })
      window.krTestHost?.terminalViews[0]?.show({
        dimensions: { columns: '20', rows: '2' },
        window: { columns: 20, rows: 2, column: 0, line: 0, above: 0 },
        lines: [
          {
            row: '1',
            soft_wrapped: false,
            truncated: false,
            // An Arabic symbol an older table calls a mark, a mark with nothing before it, a wide
            // character, an emoji shown as a picture, a man and a joiner then a laptop as native
            // code places a man technologist, an invisible wide character, a Hebrew letter, a
            // heart shown as a picture in one cell, and a bold e.
            pieces: [
              at(0, 1, 'x'),
              at(1, 1, '\u{6de}'),
              at(2, 1, '\u{301}'),
              at(3, 2, '\u{4e2d}'),
              at(5, 2, '\u{1f44d}'),
              at(7, 2, '\u{1f468}\u{200d}'),
              at(9, 2, '\u{1f4bb}'),
              at(11, 2, '\u{4e2d}', false, true),
              at(13, 1, '\u{5e9}'),
              at(14, 1, '\u{2764}\u{fe0f}'),
              at(15, 1, 'e', true),
              at(16, 1, 'y')
            ]
          },
          {
            row: '2',
            soft_wrapped: false,
            truncated: false,
            // Two Arabic semicolons with marks, which a browser lays out right to left when they
            // share a run, then a bold x.
            pieces: [at(0, 1, '\u{61b}\u{64b}'), at(1, 1, '\u{61b}\u{64c}'), at(2, 1, 'x', true)]
          }
        ],
        cursor: null
      })
    })
    await expect(page.locator('[data-testid="terminal-piece"][data-line="0"][data-column="16"]')).toHaveText('y')
    // Every box, measured where the browser put it: at its column and line, exactly its cells wide,
    // and cutting what it holds at its edges.
    const misplaced = await page.evaluate(() => {
      const grid = document.querySelector<HTMLElement>('[data-testid="terminal-grid"]')
      if (grid === null) return ['no grid']
      const gridBox = grid.getBoundingClientRect()
      const cellWidth = gridBox.width / Number(grid.dataset.columns)
      const cellHeight = gridBox.height / Number(grid.dataset.rows)
      const wrong: string[] = []
      for (const box of Array.from(grid.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]'))) {
        const placed = box.getBoundingClientRect()
        const column = Number(box.dataset.column)
        const line = Number(box.dataset.line)
        const cells = Number(box.dataset.cells)
        const style = getComputedStyle(box)
        if (
          Math.abs(placed.left - gridBox.left - column * cellWidth) > 0.5 ||
          Math.abs(placed.top - gridBox.top - line * cellHeight) > 0.5 ||
          Math.abs(placed.width - cells * cellWidth) > 0.5 ||
          style.overflow !== 'hidden' ||
          style.unicodeBidi !== 'isolate'
        ) {
          wrong.push(`${line}:${column} ${box.textContent ?? ''}`)
        }
      }
      return wrong
    })
    expect(misplaced).toEqual([])
  })

  test('copies a selection of the screen as its lines, laid out by their cells', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('cargo test -p kr-client')
    // Text is selected in control mode: in view mode a drag moves the window.
    await takeControl(page)
    const copied = await page.evaluate(() => {
      const grid = document.querySelector('[data-testid="terminal-grid"]')
      if (grid === null) return null
      const range = document.createRange()
      range.selectNodeContents(grid)
      const selection = window.getSelection()
      selection?.removeAllRanges()
      selection?.addRange(range)
      const data = new DataTransfer()
      grid.dispatchEvent(new ClipboardEvent('copy', { clipboardData: data, bubbles: true, cancelable: true }))
      return data.getData('text/plain')
    })
    expect(copied?.split('\n')).toEqual([
      '$ cargo test -p kr-client',
      '   Compiling kr-client v0.1.0',
      '    Finished test profile in 12.4s',
      'ok    done',
      'test result: ok. 143 passed',
      '$'
    ])
  })

  // The same copy as a person makes it: a selection made with the pointer, copied with the keyboard.
  // Chromium's clipboard is read back. A page under test cannot read WebKit's, so there the text the
  // copy put on its clipboard data is read as the copy leaves it.
  test('copies a selection made with the pointer when the keyboard copies it', async ({
    page,
    context,
    browserName
  }) => {
    if (browserName === 'chromium') await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('cargo test -p kr-client')
    // Text is selected in control mode: in view mode a drag moves the window.
    await takeControl(page)
    await page.evaluate(() => {
      window.addEventListener('copy', (event) => {
        Object.assign(window, { krCopied: event.clipboardData?.getData('text/plain') ?? null })
      })
    })
    const piece = (line: number) =>
      page.locator(`[data-testid="terminal-piece"][data-line="${line}"][data-column="0"]`)
    const from = await piece(0).boundingBox()
    const to = await piece(2).boundingBox()
    if (from === null || to === null) throw new Error('the pieces are not laid out')
    await page.mouse.move(from.x + 1, from.y + from.height / 2)
    await page.mouse.down()
    await page.mouse.move(to.x + to.width - 1, to.y + to.height / 2, { steps: 8 })
    await page.mouse.up()
    expect(await page.evaluate(() => getSelection()?.toString() ?? '')).not.toBe('')

    await page.keyboard.press('ControlOrMeta+c')
    const copied = [
      '$ cargo test -p kr-client',
      '   Compiling kr-client v0.1.0',
      '    Finished test profile in 12.4s'
    ].join('\n')
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { krCopied?: string | null }).krCopied))
      .toBe(copied)
    if (browserName === 'chromium') {
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(copied)
    }
  })

  test('opens its view at the grid its surface holds, with no size report after', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('cargo test -p kr-client')
    const grids = await page.evaluate(() => window.krTestHost?.terminalViews[0]?.grids ?? [])
    // The surface here holds far more than the grid a view opens at when nothing can be measured.
    expect(grids[0]).not.toEqual({ columns: 80, rows: 24 })
    expect(grids).toHaveLength(1)
  })

  test('reports the same columns when only the height of its surface changes', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(surface).toContainText('cargo test -p kr-client')
    const reported = () =>
      page.evaluate(() => window.krTestHost?.terminalViews[0]?.grids.at(-1) ?? null)
    const before = await reported()
    if (before === null) throw new Error('the view reported no grid')
    await surface.evaluate((element) => {
      ;(element as HTMLElement).style.minHeight = '520px'
    })
    await expect.poll(async () => (await reported())?.rows).toBeGreaterThan(before.rows)
    expect((await reported())?.columns).toBe(before.columns)
  })

  test("gives the wheel to the program at the session's cell under the pointer once the person takes control", async ({
    page
  }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    const raw = page.getByTestId('raw-terminal')
    await expect(surface).toContainText('$ cargo test -p kr-client')
    // A view opens watching, in view mode: the wheel is the view's, and the program gets nothing.
    await expect(raw).toHaveAttribute('data-mode', 'view')
    await expect(page.getByTestId('terminal-mode')).toHaveText('View')

    // The person takes control, and the program gets the wheel at the cell under the pointer.
    await takeControl(page)
    await expect(raw).toHaveAttribute('data-mode', 'control')
    await expect(page.getByTestId('terminal-mode-sentence')).toHaveText(
      'Your keys go to the program; Control-Tab moves on. The program gets the wheel.'
    )
    const cell = await page.getByTestId('terminal-grid').evaluate((element) => {
      const box = element.getBoundingClientRect()
      const style = (element as HTMLElement).style
      return {
        x: box.x,
        y: box.y,
        width: parseFloat(style.width) / Number(element.getAttribute('data-columns')),
        height: parseFloat(style.lineHeight)
      }
    })
    // Over the session's column 4 and line 2, three rows of wheel towards the person.
    await page.mouse.move(cell.x + 4.5 * cell.width, cell.y + 2.5 * cell.height)
    await page.mouse.wheel(0, 3 * cell.height)
    await expect
      .poll(async () =>
        (await programInputs(page)).reduce((sum, input) => sum + (input.kind === 'wheel' ? input.turns : 0), 0)
      )
      .toBe(3)
    const turned = await programInputs(page)
    for (const input of turned) {
      expect(input).toMatchObject({ kind: 'wheel', take: 1, column: 4, line: 2, shift: false })
    }
    await expect(surface).toHaveAttribute('data-wheel-to-application', String(turned.length))

    // Looking around gives control back at once: the wheel moves the window again, and the program
    // gets nothing more.
    await page.getByRole('button', { name: 'Look around' }).click()
    await expect(raw).toHaveAttribute('data-mode', 'view')
    await page.mouse.move(cell.x + 4.5 * cell.width, cell.y + 2.5 * cell.height)
    await page.mouse.wheel(0, -3 * cell.height)
    await expect(page.getByTestId('terminal-position')).toContainText('Showing the history')
    expect(await programInputs(page)).toEqual(turned)
    await page.screenshot({ path: shot('terminal-modes-13.18'), fullPage: true })
  })
})

// KR-REQ-13.18, 13.17, 08.59, 08.56: while a raw view controls the program, the keys typed in it
// reach the program named, never spelled, Tab included, and Control-Tab moves on; text an input method
// commits goes as text, and a paste as a paste. On the phone the program's keyboard takes the field's
// place, and the terminal keys leave the focus in it.
test.describe("the program's keyboard", () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** A key's press or release under take 1, named as the page names it, with nothing held unless told. */
  const key = (name: string, event: 'press' | 'release', over: Record<string, unknown> = {}) => ({
    kind: 'key',
    take: 1,
    event,
    key: name,
    base: [...name].length === 1 ? name : null,
    keypad: null,
    shift: false,
    alt: false,
    control: false,
    caps_lock: false,
    num_lock: false,
    ...over
  })

  /** Which control has the focus, by its label or its words. */
  const focused = (page: Page) =>
    page.evaluate(() => {
      const active = document.activeElement
      return active?.getAttribute('aria-label') ?? active?.textContent ?? null
    })

  /** A paste of `text` into the focused control, as the platform's paste command fires it. */
  const paste = (page: Page, text: string) =>
    page.evaluate((pasted) => {
      const data = new DataTransfer()
      data.setData('text/plain', pasted)
      const event = new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true })
      document.activeElement?.dispatchEvent(event)
      return event.defaultPrevented
    }, text)

  test("the desktop's keys reach the program named, Tab included, and Control-Tab moves on", async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
    await takeControl(page)
    const keyboard = page.getByLabel('Type to the program')
    // A click on the terminal that selects nothing puts the focus in the program's keyboard, and the
    // terminal shows the ring.
    await page.getByTestId('terminal-grid').click({ position: { x: 4, y: 4 } })
    await expect(keyboard).toBeFocused()
    const surface = page.getByTestId('terminal-surface')
    expect(await surface.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe('solid')
    await page.keyboard.type('ls')
    await page.keyboard.press('Enter')
    await page.keyboard.press('Tab')
    await page.keyboard.press('Shift+Tab')
    await expect(keyboard).toBeFocused()
    await expect.poll(async () => (await programInputs(page)).length).toBe(10)
    expect(await programInputs(page)).toEqual([
      key('l', 'press'),
      key('l', 'release'),
      key('s', 'press'),
      key('s', 'release'),
      key('Enter', 'press'),
      key('Enter', 'release'),
      key('Tab', 'press'),
      key('Tab', 'release'),
      key('Tab', 'press', { shift: true }),
      key('Tab', 'release', { shift: true })
    ])
    // The keyboard's field shows nothing of what went.
    expect(await keyboard.inputValue()).toBe('​')
    await page.screenshot({ path: shot('terminal-keys-13.18'), fullPage: true })
    // Control-Tab moves on past the controls control mode disables; Control-Shift-Tab goes back.
    await page.keyboard.press('Control+Tab')
    await expect(page.getByRole('button', { name: 'Back to the conversation' })).toBeFocused()
    await keyboard.focus()
    await page.keyboard.press('Control+Shift+Tab')
    await expect(page.getByRole('button', { name: 'Look around' })).toBeFocused()
    await expect(surface).not.toHaveCSS('outline-style', 'solid')
    expect(await programInputs(page)).toHaveLength(10)
  })

  test('the desktop sends committed text as text and a paste as a paste, and inserts neither', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
    await takeControl(page)
    const keyboard = page.getByLabel('Type to the program')
    await keyboard.focus()
    // What an input method or dictation commits arrives as an insertion with no key.
    await page.keyboard.insertText('日本語')
    expect(await paste(page, 'echo one\necho two')).toBe(true)
    await expect.poll(async () => (await programInputs(page)).length).toBe(2)
    expect(await programInputs(page)).toEqual([
      { kind: 'text', take: 1, text: '日本語' },
      { kind: 'paste', take: 1, text: 'echo one\necho two' }
    ])
    expect(await keyboard.inputValue()).toBe('​')
    // A paste longer than one input carries says why, and nothing of it goes.
    expect(await paste(page, 'x'.repeat(64 * 1024))).toBe(true)
    await expect(page.getByTestId('terminal-mode-sentence')).toHaveText(
      'That paste did not reach the program: it is longer than one input can carry.'
    )
    await page.keyboard.press('q')
    await expect(page.getByTestId('terminal-mode-sentence')).toHaveText(
      'Your keys go to the program; Control-Tab moves on. The program gets the wheel.'
    )
    expect((await programInputs(page)).filter((input) => input.kind === 'paste')).toHaveLength(1)
  })

  test("the desktop draws an input method's composition at the cursor and sends what it commits once", async ({
    page,
    browserName
  }) => {
    // Only Chromium lets a test drive a real input method's composition.
    test.skip(browserName !== 'chromium', "composition is driven through Chromium's own input method events")
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
    await takeControl(page)
    await page.getByLabel('Type to the program').focus()
    const cdp = await page.context().newCDPSession(page)
    await cdp.send('Input.imeSetComposition', { text: 'にほん', selectionStart: 3, selectionEnd: 3 })
    const composing = page.getByTestId('terminal-composition')
    await expect(composing).toHaveText('にほん')
    const cursor = await page.getByTestId('terminal-cursor').boundingBox()
    const drawn = await composing.boundingBox()
    expect(drawn?.x).toBeCloseTo(cursor?.x ?? -1, 0)
    expect(drawn?.y).toBeCloseTo(cursor?.y ?? -1, 0)
    await page.screenshot({ path: shot('terminal-composition-08.56'), fullPage: true })
    expect(await programInputs(page)).toEqual([])
    await cdp.send('Input.insertText', { text: '日本' })
    await expect(composing).toHaveCount(0)
    await expect.poll(async () => programInputs(page)).toEqual([{ kind: 'text', take: 1, text: '日本' }])
    expect(await page.getByLabel('Type to the program').inputValue()).toBe('​')
  })

  test("the desktop's focus stays where the person left it after the program's keyboard, when control ends", async ({
    page
  }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
    await takeControl(page)
    await page.getByLabel('Type to the program').focus()
    // The person puts the focus on a control outside the view, and lets it go.
    await page.evaluate(() => {
      const elsewhere = document.body.appendChild(document.createElement('button'))
      elsewhere.textContent = 'Elsewhere'
      elsewhere.focus()
      elsewhere.blur()
    })
    await page.evaluate(() => {
      window.krTestHost?.terminalViews.at(-1)?.loseControl()
    })
    await expect(page.getByLabel('Type to the program')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Take control' })).toBeEnabled()
    await expect(page.getByRole('button', { name: 'Take control' })).not.toBeFocused()
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true)
  })

  for (const by of ['pointer', 'keyboard'] as const) {
    test(`the desktop's focus ${by === 'keyboard' ? 'goes to the mode button' : 'stays where a pointer left it'} when Attach again is pressed from the ${by}`, async ({
      page
    }) => {
      await openSession(page)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
      await page.evaluate(() => {
        window.krTestHost?.terminalViews.at(-1)?.end('The session ended.')
      })
      const again = page.getByRole('button', { name: 'Attach again' })
      let leftByEngine = ''
      if (by === 'keyboard') {
        await again.focus()
        await page.keyboard.press('Enter')
      } else {
        leftByEngine = await whereAPressedButtonLeavesTheFocus(page, again)
        await again.click()
      }
      await expect(page.getByTestId('terminal-ended')).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Take control' })).toBeEnabled()
      if (by === 'keyboard') {
        await expect(page.getByRole('button', { name: 'Take control' })).toBeFocused()
      } else {
        await expect(page.getByRole('button', { name: 'Take control' })).not.toBeFocused()
        expect(await focusedNow(page), 'the focus is where this engine leaves a pressed button that goes').toBe(
          leftByEngine
        )
      }
    })

    test(`the phone's focus ${by === 'keyboard' ? 'goes to the mode button' : 'stays where a pointer left it'} when Attach again is pressed from the ${by}`, async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await page.evaluate(() => {
        window.krTestHost?.terminalViews.at(-1)?.end('The session ended.')
      })
      const again = page.getByRole('button', { name: 'Attach again' })
      let leftByEngine = ''
      if (by === 'keyboard') {
        await again.focus()
        await page.keyboard.press('Enter')
      } else {
        leftByEngine = await whereAPressedButtonLeavesTheFocus(page, again)
        await again.click()
      }
      await expect(page.getByTestId('attach-again')).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Take control' })).toBeEnabled()
      if (by === 'keyboard') {
        await expect(page.getByRole('button', { name: 'Take control' })).toBeFocused()
      } else {
        await expect(page.getByRole('button', { name: 'Take control' })).not.toBeFocused()
        expect(await focusedNow(page), 'the focus is where this engine leaves a pressed button that goes').toBe(
          leftByEngine
        )
      }
    })
  }

  test("the phone's focus goes to the mode button once a software keyboard has gone, when control ends under it", async ({
    page
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
    await takeControl(page)
    await page.getByLabel('Type to the program').focus()
    // A software keyboard over the page hides the bar that holds the mode button.
    const cover = (inset: number) =>
      page.evaluate((covered) => {
        document.documentElement.style.setProperty('--keyboard', `${covered}px`)
      }, inset)
    await cover(336)
    await expect(page.locator('.m-terminal-hud')).toBeHidden()
    await page.evaluate(() => {
      window.krTestHost?.terminalViews.at(-1)?.loseControl()
    })
    await expect(page.getByLabel('Type to the program')).toHaveCount(0)
    // The mode button is hidden with the bar, and takes no focus yet.
    await expect(page.getByRole('button', { name: 'Take control', includeHidden: true })).toBeHidden()
    await expect(page.getByRole('button', { name: 'Take control', includeHidden: true })).not.toBeFocused()
    // The field gone, the keyboard goes: the bar is back, and the focus goes to the mode button.
    await cover(0)
    await expect(page.getByRole('button', { name: 'Take control' })).toBeFocused()
  })

  test("the phone's focus stays where the person put it while a software keyboard was up, when control ended under it", async ({
    page
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
    await takeControl(page)
    await page.getByLabel('Type to the program').focus()
    const cover = (inset: number) =>
      page.evaluate((covered) => {
        document.documentElement.style.setProperty('--keyboard', `${covered}px`)
      }, inset)
    await cover(336)
    await expect(page.locator('.m-terminal-hud')).toBeHidden()
    await page.evaluate(() => {
      window.krTestHost?.terminalViews.at(-1)?.loseControl()
    })
    await expect(page.getByLabel('Type to the program')).toHaveCount(0)
    // The person puts the focus on the draft and takes it away again before the bar returns.
    await page.getByLabel('Message this session').evaluate((field) => {
      ;(field as HTMLTextAreaElement).focus()
      ;(field as HTMLTextAreaElement).blur()
    })
    await cover(0)
    await expect(page.getByRole('button', { name: 'Take control' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Take control' })).not.toBeFocused()
  })

  test("the phone's draft field moves on with Control-Tab and back with Control-Shift-Tab while the view watches", async ({
    page
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=android&session=${SESSION}`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
    const field = page.getByLabel('Message this session')
    await field.fill('ls')
    await field.focus()
    await page.keyboard.press('Control+Tab')
    await expect(page.getByRole('button', { name: 'Send' })).toBeFocused()
    await field.focus()
    await page.keyboard.press('Control+Shift+Tab')
    await expect(page.getByRole('button', { name: 'More' })).toBeFocused()
    await expect(field).toHaveValue('ls')
  })

  for (const surface of ['ios', 'android'] as const) {
    test(`the phone's field is the program's keyboard while the view controls it, on ${surface}`, async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await page.getByLabel('Message this session').fill('a draft')
      await takeControl(page)
      const keyboard = page.getByLabel('Type to the program')
      await expect(keyboard).toBeVisible()
      await expect(page.getByLabel('Message this session')).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Send' })).toHaveCount(0)
      await expect(page.locator('.m-program-keyboard-hint')).toHaveText('Type to the program')
      await keyboard.focus()
      await page.keyboard.type('l')
      await page.keyboard.press('Tab')
      // A tap on a terminal key leaves the focus in the field, so a software keyboard stays up.
      await page.getByRole('button', { name: 'Escape' }).click()
      await expect(keyboard).toBeFocused()
      await page.getByRole('button', { name: 'Control, off' }).click()
      await page.keyboard.press('c')
      await expect.poll(async () => (await programInputs(page)).length).toBe(8)
      expect(await programInputs(page)).toEqual([
        key('l', 'press'),
        key('l', 'release'),
        key('Tab', 'press'),
        key('Tab', 'release'),
        key('Escape', 'press'),
        key('Escape', 'release'),
        key('c', 'press', { control: true }),
        key('c', 'release', { control: true })
      ])
      await page.screenshot({ path: shot(`terminal-field-${surface}-13.17`), fullPage: true })
      // Control-Shift-Tab moves back to the last terminal key, sending nothing.
      await page.keyboard.press('Control+Shift+Tab')
      await expect(page.getByRole('button', { name: 'Tilde' })).toBeFocused()
      expect(await focused(page)).toBe('Tilde')
      // Control ends: the draft comes back as it was.
      await page.getByRole('button', { name: 'Look around' }).click()
      await expect(page.getByLabel('Message this session')).toHaveValue('a draft')
      await expect(page.getByLabel('Type to the program')).toHaveCount(0)
      expect(await programInputs(page)).toHaveLength(8)
    })
  }
})

test.describe('how the host presents a raw view', () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /** Opens the harness in one colour mode, whatever the system's. */
  async function inTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.addInitScript((mode) => {
      localStorage.setItem('kalareach-theme', mode)
    }, theme)
  }

  for (const theme of ['light', 'dark'] as const) {
    // KR-REQ-08.02: the desktop raw view says it is a viewport, and why, in the host's words.
    test(`the desktop raw view says how it is presented and why, ${theme}, at 320 px`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await openSession(page)
      await page.evaluate(() => {
        window.krTestHost?.presentTerminal('viewport', 'size_mismatch')
      })
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await page.setViewportSize({ width: 320, height: 720 })

      await expect(page.getByTestId('terminal-presentation')).toHaveText(
        "This view is shown a viewport because its size is not the session's."
      )
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({
        path: shotFor(`terminal-presentation-08.02-desktop-320-${theme}`),
        fullPage: true
      })
    })

    // KR-REQ-08.02: the desktop raw view in a wide window: the screen drawn in the session's own
    // palette, the badges, and the host's words for the viewport.
    test(`the desktop raw view draws its screen and says how it is presented, ${theme}, wide`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await openSession(page)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('terminal-surface')).toContainText('$ cargo test -p kr-client')
      await expect(page.getByTestId('terminal-presentation')).toContainText(
        'the terminal profile its client declared is not one this build has qualified'
      )
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({
        path: shotFor(`terminal-08.02-desktop-wide-${theme}`),
        fullPage: true
      })
    })

    // KR-REQ-08.02: the phone's raw view says the same, in the same words, in its status: the first
    // two lines of it until the person asks for all of it.
    test(`the phone's raw view says how it is presented and why, ${theme}, at 320 px`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
      await page.evaluate(() => {
        window.krTestHost?.presentTerminal('viewport', 'no_terminal_profile')
      })
      await page.getByRole('tab', { name: 'Terminal' }).click()

      await expect(page.getByTestId('terminal-presentation')).toHaveText(
        "This view is shown a viewport because its client declared no terminal profile, so what the session's output would do on its terminal is not known."
      )
      await page.getByRole('button', { name: 'More' }).click()
      await expect(page.getByRole('button', { name: 'Less' })).toHaveAttribute('aria-expanded', 'true')
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({
        path: shotFor(`terminal-presentation-08.02-phone-320-${theme}`),
        fullPage: true
      })
    })

    // KR-REQ-08.02: on a phone with room for the terminal, the session's screen is in view in the
    // terminal pane, with the host's words and the cells left blank counted.
    test(`the phone's raw view draws the session's screen in its pane, ${theme}, at 390 px`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()

      const first = page.getByTestId('mobile-terminal-line').first()
      await expect(first).toContainText('$ cargo test -p kr-client')
      const line = await first.boundingBox()
      const pane = await page.locator('.m-pane').boundingBox()
      if (line === null || pane === null) throw new Error('the terminal pane is not laid out')
      expect(line.height).toBeGreaterThan(0)
      expect(line.y).toBeGreaterThanOrEqual(pane.y)
      expect(line.y + line.height).toBeLessThanOrEqual(pane.y + pane.height)
      await expect(page.getByTestId('terminal-presentation')).toContainText(
        'the terminal profile its client declared is not one this build has qualified'
      )
      await expect(page.getByTestId('substituted-count')).toHaveText('1 left blank')
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({
        path: shotFor(`terminal-08.02-phone-390-${theme}`),
        fullPage: true
      })
    })
  }

  // KR-REQ-13.18: a zoom step answers at once. The last frame is drawn again at the new cell size
  // from its top-left corner, where the host anchors the smaller window, and the view reports the
  // grid its surface now holds; the host's next screen says how much of the session it shows.
  test('a zoom step redraws the last frame at once and reports the new grid', async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(surface).toContainText('$ cargo test -p kr-client')
    const before = await page.evaluate(() => window.krTestHost?.terminalViews[0]?.grids.at(-1))
    expect(before?.columns ?? 0).toBeGreaterThan(20)

    // A view opens in view mode, where the sizes can be pressed.
    for (let step = 0; step < 5; step += 1) await page.getByTestId('zoom-in').click()
    await expect(surface).toContainText('$ cargo test')
    await expect
      .poll(async () => page.evaluate(() => window.krTestHost?.terminalViews[0]?.grids.at(-1)?.columns))
      .toBeLessThan(before?.columns ?? 0)
    // The top-left cell is still the first cell of the session's first line.
    const first = page.locator('[data-testid="terminal-piece"][data-line="0"][data-column="0"]')
    expect((await first.textContent())?.startsWith('$ cargo')).toBe(true)

    // The host's next screen for the smaller grid says how much of the session it shows.
    await page.evaluate(() => {
      window.krTestHost?.terminalViews[0]?.show()
    })
    await expect(page.getByTestId('terminal-position')).toContainText('Showing columns 1–')
    await page.screenshot({ path: shotFor('terminal-zoom-13.18'), fullPage: true })
  })
})

// KR-REQ-13.08: the phone's grid and the desktop's colour a selection in the session's own selection
// colours, as the terminal the session came from shows one, and the rest of the page keeps the
// application's.
test.describe("a raw view's selection", () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** The scripted session's selection colours: #315e4a behind #ffffff. */
  const SESSION = { background: 'rgb(49, 94, 74)', colour: 'rgb(255, 255, 255)' }

  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /** Opens the harness in one colour mode, whatever the system's. */
  async function inTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.addInitScript((mode) => {
      localStorage.setItem('kalareach-theme', mode)
    }, theme)
  }

  /** The colours a selection takes on `locator`'s element, as the browser resolves them. */
  const selected = (locator: Locator) =>
    locator.evaluate((element) => {
      const style = getComputedStyle(element, '::selection')
      return { background: style.backgroundColor, colour: style.color }
    })

  for (const theme of ['light', 'dark'] as const) {
    test(`the phone's grid selects in the session's colours and the page in its own, ${theme}, at 320 px`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
      const heading = page.locator('.m-topbar h1')
      await expect(heading).toBeVisible()
      // The application's own selection colours, before a terminal is drawn.
      const own = await selected(heading)
      expect(own).not.toEqual(SESSION)

      await page.getByRole('tab', { name: 'Terminal' }).click()
      const piece = page.getByTestId('mobile-terminal-line').first().locator('[data-cells]').first()
      await expect(piece).toHaveText('$ cargo test -p kr-client')
      await piece.evaluate((element) => {
        getSelection()?.selectAllChildren(element)
      })
      expect(await selected(piece)).toEqual(SESSION)
      // Everything outside the grid keeps the application's colours.
      expect(await selected(heading)).toEqual(own)
      expect(await selected(page.getByRole('tab', { name: 'Terminal' }))).toEqual(own)
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({ path: shotFor(`terminal-selection-13.08-phone-320-${theme}`), fullPage: true })
    })
  }

  test("the desktop's grid selects in the same colours and the page in its own", async ({ page }) => {
    await openSession(page)
    const own = await selected(page.getByRole('tab', { name: 'Terminal' }))
    expect(own).not.toEqual(SESSION)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const piece = page.locator('[data-testid="terminal-piece"][data-line="0"][data-column="0"]')
    await expect(piece).toHaveText('$ cargo test -p kr-client')
    await piece.evaluate((element) => {
      getSelection()?.selectAllChildren(element)
    })
    expect(await selected(piece)).toEqual(SESSION)
    expect(await selected(page.getByRole('tab', { name: 'Terminal' }))).toEqual(own)
  })
})

// KR-REQ-13.18, KR-REQ-13.19: the phone keeps room for its terminal. On a small phone and a larger
// one, on both platforms, in both modes, with the keyboard down and up, the grid the host is told is
// the grid the terminal's surface shows, never the one a view opens at when nothing can be
// measured, and the surface holds at least the rows the layout keeps for it.
test.describe("the phone's room for its terminal", () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** The rows the terminal keeps at the least, however much of the screen the keyboard covers. */
  const FLOOR = 4

  /**
   * Two phones: how much of the screen a software keyboard covers on a phone that size, and the rows
   * the terminal keeps with the keyboard down and with it up.
   */
  const PHONES = [
    { width: 320, height: 720, keyboard: 260, rows: 8, typing: 8 },
    { width: 390, height: 844, keyboard: 336, rows: 14, typing: 10 }
  ] as const

  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /** Opens the harness in one colour mode, whatever the system's. */
  async function inTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.addInitScript((mode) => {
      localStorage.setItem('kalareach-theme', mode)
    }, theme)
  }

  /** Covers the bottom `inset` pixels of the screen, as a software keyboard does. */
  async function keyboard(page: Page, inset: number): Promise<void> {
    await page.evaluate((covered) => {
      document.documentElement.style.setProperty('--keyboard', `${covered}px`)
    }, inset)
  }

  /**
   * The grid the terminal's surface shows, measured from what it draws: the line pitch between two
   * drawn lines, a cell from a drawn piece, and the part of the surface a person sees, inside its
   * border and the grid's padding, above the keyboard and inside the pane and the session's scroll
   * area, which each clip it. With every grid the page has told the host.
   */
  async function shownAndTold(page: Page) {
    return page.evaluate(() => {
      const surface = document.querySelector<HTMLElement>('[data-testid="mobile-terminal"]')
      const grid = surface?.querySelector<HTMLElement>('.m-terminal-grid')
      const lines = Array.from(
        surface?.querySelectorAll<HTMLElement>('[data-testid="mobile-terminal-line"]') ?? []
      )
      const piece = lines[0]?.querySelector<HTMLElement>('[data-cells]')
      const pane = document.querySelector<HTMLElement>('.m-pane')
      const main = document.querySelector<HTMLElement>('.m-main')
      if (!surface || !grid || !piece || !pane || !main || lines.length < 2) return null
      const pitch = (lines[1]?.getBoundingClientRect().top ?? 0) - (lines[0]?.getBoundingClientRect().top ?? 0)
      const cell = piece.getBoundingClientRect().width / Number(piece.dataset.cells)
      const style = getComputedStyle(grid)
      const covered =
        parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--keyboard')) || 0
      const top = surface.getBoundingClientRect().top + surface.clientTop
      const clips = [pane.getBoundingClientRect(), main.getBoundingClientRect()]
      const seen =
        Math.min(top + surface.clientHeight, window.innerHeight - covered, ...clips.map((box) => box.bottom)) -
        Math.max(top, ...clips.map((box) => box.top))
      const rows = Math.floor((seen - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom)) / pitch)
      const columns = Math.floor(
        (surface.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)) / cell
      )
      return { shown: { columns, rows }, told: window.krTestHost?.terminalViews.at(-1)?.grids ?? [] }
    })
  }

  /** Waits for the page to tell the host the grid its surface shows, and checks the rows it holds. */
  async function expectRoom(page: Page, rows: number, what: string): Promise<void> {
    await expect
      .poll(async () => {
        const seen = await shownAndTold(page)
        const told = seen?.told.at(-1)
        return seen === null
          ? 'nothing drawn'
          : `shown ${seen.shown.columns}×${seen.shown.rows}, told ${told?.columns}×${told?.rows}`
      }, { message: what })
      .toMatch(/^shown (\d+)×(\d+), told \1×\2$/)
    const seen = await shownAndTold(page)
    expect(seen?.shown.rows ?? 0, what).toBeGreaterThanOrEqual(rows)
    expect(seen?.told, what).not.toContainEqual({ columns: 80, rows: 24 })
  }

  for (const surface of ['ios', 'android'] as const) {
    for (const phone of PHONES) {
      for (const mode of ['control', 'view'] as const) {
        test(`keeps room on ${surface} at ${phone.width}×${phone.height} in ${mode} mode, with the keyboard down and up`, async ({
          page
        }) => {
          await page.setViewportSize({ width: phone.width, height: phone.height })
          await page.goto(`/harness.html?surface=${surface}&session=${SESSION_MAIN}`)
          await page.getByRole('tab', { name: 'Terminal' }).click()
          await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
          if (mode === 'control') await takeControl(page)
          await expectRoom(page, phone.rows, 'with the keyboard down')
          // Nothing in the bar runs past the screen's edge; only the terminal keys scroll sideways.
          const past = await page.evaluate(() =>
            Array.from(
              document.querySelectorAll<HTMLElement>('.m-composer button, .m-composer textarea, .m-terminal-status p')
            )
              .filter(
                (element) =>
                  element.closest('.m-accessory') === null &&
                  element.getBoundingClientRect().right > window.innerWidth + 0.5
              )
              .map((element) => element.textContent || element.tagName)
          )
          expect(past).toEqual([])
          // A keyboard over the page, as a phone's browser measures it: the bar yields, and the
          // field sits on the keyboard's top edge with the terminal keys above it. In control mode
          // the field is the program's keyboard, in the draft field's place and size.
          await keyboard(page, phone.keyboard)
          await expect(page.locator('.m-terminal-hud')).toBeHidden()
          await expectRoom(page, phone.typing, 'with the keyboard up')
          const edge = phone.height - phone.keyboard
          const field = page.getByLabel(mode === 'control' ? 'Type to the program' : 'Message this session')
          await expect(field).toBeInViewport({ ratio: 1 })
          const box = await field.boundingBox()
          expect(Math.abs((box === null ? 0 : box.y + box.height) - edge)).toBeLessThanOrEqual(1)
          // The composer scrolls, and cuts what is drawn outside it: the field's focus ring is whole.
          await field.focus()
          expect(await ringHidden(field), 'the focus ring is whole in view').toBeLessThanOrEqual(1)
          const keys = page.getByRole('group', { name: 'Terminal keys' })
          await expect(keys).toBeInViewport({ ratio: 1 })
          // The keyboard gone, the bar is back.
          await keyboard(page, 0)
          await expect(page.locator('.m-terminal-hud')).toBeVisible()
          await expectRoom(page, phone.rows, 'with the keyboard gone')
        })

        // A keyboard that makes the page shorter, as a system that resizes the window for it does:
        // the terminal keeps its four rows and the field stays whole in view.
        test(`keeps room on ${surface} at ${phone.width}×${phone.height} in ${mode} mode, with a keyboard that makes the page shorter`, async ({
          page
        }) => {
          await page.setViewportSize({ width: phone.width, height: phone.height })
          await page.goto(`/harness.html?surface=${surface}&session=${SESSION_MAIN}`)
          await page.getByRole('tab', { name: 'Terminal' }).click()
          await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
          if (mode === 'control') await takeControl(page)
          await page.setViewportSize({ width: phone.width, height: phone.height - phone.keyboard })
          await expectRoom(page, FLOOR, 'on a page the keyboard made shorter')
          // Whole to the pixel: WebKit can leave a scrolled box's last fraction of a pixel out.
          const field = page.getByLabel(mode === 'control' ? 'Type to the program' : 'Message this session')
          expect(await hiddenPart(field)).toBeLessThanOrEqual(1)
        })
      }
    }
  }

  // Why a paste did not reach the program stays in view above the program's keyboard with a software
  // keyboard up, and the terminal keeps its floor while it does.
  for (const surface of ['ios', 'android'] as const) {
    test(`keeps room on ${surface} at 320×720 while it says why a paste did not go, with the keyboard up`, async ({
      page
    }) => {
      const phone = PHONES[0]
      await page.setViewportSize({ width: phone.width, height: phone.height })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION_MAIN}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await takeControl(page)
      const field = page.getByLabel('Type to the program')
      await field.focus()
      await keyboard(page, phone.keyboard)
      await expect(page.locator('.m-terminal-hud')).toBeHidden()
      await page.evaluate((text) => {
        const data = new DataTransfer()
        data.setData('text/plain', text)
        document.activeElement?.dispatchEvent(
          new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true })
        )
      }, 'x'.repeat(64 * 1024))
      const words = page.locator('.m-unsent')
      await expect(words).toHaveText('That paste did not reach the program: it is longer than one input can carry.')
      await expect(words).toBeInViewport({ ratio: 1 })
      await expect(field).toBeInViewport({ ratio: 1 })
      await expectRoom(page, FLOOR, 'while it says why')
      await page.screenshot({ path: shotFor(`terminal-unsent-13.17-${surface}-320x720`) })
    })
  }

  // A person's own larger text size: every size given in rem grows with it. The field still shows
  // its whole line at no less than the platform's target, it and its focus ring are whole in view,
  // nothing runs past the screen's edge, and the terminal keeps its four rows of its own, larger,
  // type.
  for (const surface of ['ios', 'android'] as const) {
    for (const phone of PHONES) {
      for (const scale of ['150%', '200%']) {
        test(`keeps the field whole and room for the terminal on ${surface} at ${phone.width}×${phone.height} with text at ${scale}`, async ({
          page
        }) => {
          await withTextSize(page, scale)
          await page.setViewportSize({ width: phone.width, height: phone.height })
          await page.goto(`/harness.html?surface=${surface}&session=${SESSION_MAIN}`)
          await page.getByRole('tab', { name: 'Terminal' }).click()
          await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
          await expectTextSizeFromLoad(page, scale)
          const field = page.getByLabel('Message this session')
          await field.fill('ls -la')
          const fits = await field.evaluate((element) => ({
            clipped: element.scrollHeight - element.clientHeight,
            height: element.getBoundingClientRect().height
          }))
          expect(fits.clipped, 'the field shows its whole line').toBeLessThanOrEqual(1)
          expect(fits.height).toBeGreaterThanOrEqual(surface === 'ios' ? 44 : 48)
          // Whole to the pixel: WebKit can leave a scrolled box's last fraction of a pixel out.
          expect(await hiddenPart(field), 'the field is whole in view').toBeLessThanOrEqual(1)
          expect(await ringHidden(field), 'the focus ring is whole in view').toBeLessThanOrEqual(1)
          const past = await page.evaluate(() =>
            Array.from(document.querySelectorAll<HTMLElement>('.m-composer button, .m-composer textarea'))
              .filter(
                (element) =>
                  element.closest('.m-accessory') === null &&
                  element.getBoundingClientRect().right > window.innerWidth + 0.5
              )
              .map((element) => element.textContent || element.tagName)
          )
          expect(past).toEqual([])
          // Nor past the session's own box, whatever the fonts measure: with larger text the view
          // switch gives each choice a line of its own, and no row widens the session's column.
          const spill = await page.evaluate(() => {
            const session = document.querySelector('.m-session')?.getBoundingClientRect()
            if (session === undefined) return ['no session']
            return Array.from(
              document.querySelectorAll<HTMLElement>(
                '.m-session > *, .m-session .segmented, .m-composer button, .m-composer textarea'
              )
            )
              .filter(
                (element) =>
                  element.closest('.m-accessory') === null &&
                  element.getBoundingClientRect().right > session.right + 0.5
              )
              .map((element) => element.textContent?.trim().slice(0, 24) || element.className || element.tagName)
          })
          expect(spill, "what reaches past the session's box").toEqual([])
          await expectRoom(page, FLOOR, `text at ${scale}`)
        })
      }
    }
  }

  // While an action has no confirmed outcome, sending is held back and a sentence says why. The
  // sentence sits above the field's line, so however long it runs the line keeps the composer's
  // floor: once the page is scrolled to the composer, the field and Send are whole in view, with the
  // sentence and the terminal's four rows above them.
  for (const surface of ['ios', 'android'] as const) {
    for (const [phone, scale] of [
      [PHONES[0], '200%'],
      [PHONES[1], '100%']
    ] as const) {
      test(`keeps the field whole under the reason sending is held back on ${surface} at ${phone.width}×${phone.height} with text at ${scale}`, async ({
        page
      }) => {
        await withUnconfirmedAction(page, SESSION_MAIN)
        await withTextSize(page, scale)
        await page.setViewportSize({ width: phone.width, height: phone.height })
        await page.goto(`/harness.html?surface=${surface}&session=${SESSION_MAIN}`)
        await page.getByRole('tab', { name: 'Terminal' }).click()
        await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
        const field = page.getByLabel('Message this session')
        const send = page.getByRole('button', { name: 'Send' })
        const reason = page.locator('.m-composer .m-hint', { hasText: 'no confirmed outcome yet' })
        await expect(send).toBeDisabled()
        await expect(field).toHaveAttribute('aria-describedby', (await reason.getAttribute('id')) ?? 'no reason')
        // Down to the composer, as a person scrolls: the composer's own scroll stays where it starts.
        await page.locator('.m-main').evaluate((main) => {
          main.scrollTop = main.scrollHeight
        })
        expect(await hiddenPart(field), 'the field is whole in view').toBeLessThanOrEqual(1)
        expect(await hiddenPart(send), 'Send is whole in view').toBeLessThanOrEqual(1)
        const reasonBox = await reason.boundingBox()
        const fieldBox = await field.boundingBox()
        expect(
          (reasonBox?.y ?? Infinity) + (reasonBox?.height ?? 0),
          'the reason ends above the field'
        ).toBeLessThanOrEqual((fieldBox?.y ?? -Infinity) + 0.5)
        await field.focus()
        expect(await ringHidden(field), 'the focus ring is whole in view').toBeLessThanOrEqual(1)
        await expectRoom(page, FLOOR, `sending held back, text at ${scale}`)
        await still(page, `blocked-13.19-${surface}-${phone.width}x${phone.height}-${scale.replace('%', '')}`)
      })
    }
  }

  for (const theme of ['light', 'dark'] as const) {
    for (const phone of PHONES) {
      test(`the terminal and its bar at ${phone.width}×${phone.height}, ${theme}`, async ({ page }) => {
        await inTheme(page, theme)
        await page.setViewportSize({ width: phone.width, height: phone.height })
        await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
        await page.getByRole('tab', { name: 'Terminal' }).click()
        await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
        const size = `${phone.width}x${phone.height}`
        // A view opens in view mode.
        await expectRoom(page, phone.rows, 'view mode')
        await still(page, `terminal-room-13.19-phone-${size}-view-${theme}`)
        await page.getByRole('button', { name: 'More' }).click()
        await still(page, `terminal-room-13.19-phone-${size}-view-more-${theme}`)
        await page.getByRole('button', { name: 'Less' }).click()
        await takeControl(page)
        await expectRoom(page, phone.rows, 'control mode')
        await still(page, `terminal-room-13.19-phone-${size}-control-${theme}`)
        await keyboard(page, phone.keyboard)
        await expectRoom(page, phone.typing, 'the keyboard up')
        await still(page, `terminal-room-13.19-phone-${size}-keyboard-${theme}`)
      })
    }
  }
})

/** A phone's screen and a person's own text size. */
interface Seen {
  readonly width: number
  readonly height: number
  readonly scale: string
}

/** Opens the phone's harness on `surface` at `seen`, at `address`'s place. */
async function onPhone(page: Page, surface: 'ios' | 'android', seen: Seen, address = ''): Promise<void> {
  await withTextSize(page, seen.scale)
  await page.setViewportSize({ width: seen.width, height: seen.height })
  await page.goto(`/harness.html?surface=${surface}${address}`)
}

/**
 * Sets the letters of the tab labels as `rule` says, from the page's first frame, as a face wider
 * than the system's would be. Which face a platform's system font is differs from one to the next: a
 * layout that holds only for the widths of the face it was drawn with does not hold. The rule is
 * written to outrank the page's own, so no rule of the page's can take it back.
 */
async function withLabelFace(page: Page, rule: string): Promise<void> {
  await page.addInitScript((css) => {
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
  }, rule)
}

// KR-REQ-13.19: the tab bar names each destination whole at a person's own text size. With text too
// large for four labels side by side, the tabs take two rows of two, or a row each where two columns
// still cut a label, and no label runs into another or out of its own tab. Each tab stays the platform's target, and the tabs read in their order.
// KR-REQ-13.09: the phone's destinations are Attention, Sessions, Hosts and Account, in that order.
test.describe("the phone's tab bar", () => {
  // The letters as the system sets them, then as a face whose bold is much wider than its regular,
  // which the label of the tab the person is on is set in (its letters are spaced wider wherever the
  // bold weight is set), and as a face so wide that two rows of two cut a label on the narrow screen:
  // the widths a label has differ from one platform's system font to the next, and from one tab to
  // the next.
  interface Face {
    readonly name: string
    readonly shot: string
    /** The letter spacing the face adds, in em. */
    readonly em?: number
    /** Whether the spacing is added only where the bold weight is set. */
    readonly boldOnly?: boolean
  }
  const SYSTEM: Face = { name: '', shot: '' }
  const WIDE_BOLD: Face = { name: ' in a face with a wide bold', shot: '-wide-bold', em: 0.2, boldOnly: true }
  const WIDEST: Face = { name: ' in a face wider than two rows of two hold on the narrow screen', shot: '-widest-0.4em', em: 0.4 }
  const faceRule = (face: Face): string | undefined =>
    face.em === undefined
      ? undefined
      : face.boldOnly === true
        ? `:root .m-tab[aria-current='page'] .m-tab-label, :root .m-tab-label::after, :root .m-tabbar[data-measuring] .m-tab-label { letter-spacing: ${face.em}em; }`
        : `:root .m-tab-label { letter-spacing: ${face.em}em; }`

  /** A form the bar is laid out in: four tabs side by side, two rows of two, or a tab to a row. */
  type Form = 'row' | 'pairs' | 'column'

  /** One case: a platform's bar at a screen, a text size and a face, and what it shows that no other case does. */
  interface TabBarCase {
    readonly seen: Seen
    readonly face: Face
    /** The form the bar is laid out in, where the Mac's font and DejaVu Sans give it the same one. */
    readonly form?: Form
    readonly covers: string
  }

  // The bar takes the first of three forms in which every label shows whole: four tabs side by side
  // (row), two rows of two (pairs), or a tab to a row (column). Which form a screen, a text size and a
  // face lead to follows the widths of the platform's system font, which differ from one platform to
  // the next, so each case is chosen for the form it shows, and asserts that form where the Mac's font
  // and the Linux runner's DejaVu Sans agree on it. The bar's size follows the chrome unit, which stops
  // growing at a text size of 150%, so text at 150% and at 200% lay the bar out alike and only 200% is
  // here. The narrow screen at the largest text takes two rows of two in both fonts with the system's
  // face and with the wide bold, and a tab to a row with the widest face; the wide screen at the base
  // size keeps a row in both fonts with the system's face and with the wide bold; the wide screen at
  // the largest text takes two rows of two in both fonts with the wide bold, and in the system's own
  // face is a row in the Mac's font and two rows of two in DejaVu Sans, so that case asserts no form.
  // A tab is no shorter than its platform's target, which is what sets its height where the tabs
  // stack, so each platform has a case in each stacked form, and the column is the tallest bar the
  // page draws.
  const CASES: Readonly<Record<'ios' | 'android', readonly TabBarCase[]>> = {
    ios: [
      {
        seen: { width: 390, height: 844, scale: '100%' },
        face: SYSTEM,
        form: 'row',
        covers: "the bar's own form at the base size in the system's own face: four tabs side by side, each glyph over its label"
      },
      {
        seen: { width: 390, height: 844, scale: '200%' },
        face: WIDE_BOLD,
        form: 'pairs',
        covers: 'two rows of two on the wide screen at the largest text, with a bold much wider than the regular, tabs as tall as the iOS target'
      },
      {
        seen: { width: 320, height: 720, scale: '200%' },
        face: WIDE_BOLD,
        form: 'pairs',
        covers:
          'two rows of two on the narrow screen at the largest text, with a bold much wider than the regular that each label keeps the room of, tabs as tall as the iOS target'
      },
      {
        seen: { width: 320, height: 720, scale: '200%' },
        face: WIDEST,
        form: 'column',
        covers: 'a face so wide that two rows of two cut a label: a tab to a row, each as tall as the iOS target'
      }
    ],
    android: [
      {
        seen: { width: 390, height: 844, scale: '100%' },
        face: WIDE_BOLD,
        form: 'row',
        covers: "a row that keeps the current tab's label whole in a bold much wider than the regular, at the base size"
      },
      {
        seen: { width: 390, height: 844, scale: '200%' },
        face: SYSTEM,
        covers: "the wide screen at the largest text in the system's own face, at the edge between a row and two rows of two"
      },
      {
        seen: { width: 320, height: 720, scale: '200%' },
        face: SYSTEM,
        form: 'pairs',
        covers: "two rows of two on the narrow screen at the largest text in the system's own face, tabs as tall as the Android target"
      },
      {
        seen: { width: 320, height: 720, scale: '200%' },
        face: WIDEST,
        form: 'column',
        covers: 'a tab to a row, each as tall as the Android target: the tallest bar the page draws, which still ends on the screen'
      }
    ]
  }

  for (const surface of ['ios', 'android'] as const) {
    for (const { seen, face, form, covers } of CASES[surface]) {
      test(`names every destination whole and none over another on ${surface} at ${seen.width}×${seen.height} with text at ${seen.scale}${face.name}`, { annotation: { type: 'covers', description: covers } }, async ({
        page
      }) => {
        const rule = faceRule(face)
        if (rule !== undefined) await withLabelFace(page, rule)
        await onPhone(page, surface, seen)
        const tabs = page.getByRole('navigation', { name: 'Sections' }).getByRole('button')
        await expect(tabs).toHaveCount(4)
        const placed = await tabs.evaluateAll((buttons) =>
          buttons.map((button) => {
            const label = Array.from(button.children).find(
              (child): child is HTMLElement =>
                child instanceof HTMLElement && !child.matches('.m-tab-glyph, .visually-hidden')
            )
            const tab = button.getBoundingClientRect()
            const text = label?.getBoundingClientRect()
            return {
              name: label?.textContent ?? '',
              tab: { left: tab.left, right: tab.right, top: tab.top, bottom: tab.bottom },
              label: {
                left: text?.left ?? 0,
                right: text?.right ?? 0,
                top: text?.top ?? 0,
                bottom: text?.bottom ?? 0
              },
              cut: label === undefined ? Infinity : label.scrollWidth - label.clientWidth,
              // The word as typeset, which the label's box holds whole or ends in an ellipsis.
              word: (() => {
                if (label === undefined) return Infinity
                const range = document.createRange()
                range.selectNodeContents(label)
                return range.getBoundingClientRect().width
              })()
            }
          })
        )
        expect(placed.map((each) => each.name)).toEqual(['Attention', 'Sessions', 'Hosts', 'Account'])
        // The case is laid out in the form it says it is, as the rows its tabs are on show, so it cannot
        // go on passing after it has stopped covering that form.
        if (form !== undefined) {
          const rows = new Set(placed.map((each) => Math.round(each.tab.top))).size
          expect.soft(rows, `the tabs are in ${form} form`).toBe({ row: 1, pairs: 2, column: 4 }[form])
        }
        // The room a label keeps for its bold form is not read out: a tab is named once.
        for (const [index, each] of placed.entries()) {
          await expect(tabs.nth(index)).toHaveAccessibleName(new RegExp(`^${each.name}(\\s*, \\d+ waiting for you)?$`))
        }
        const target = surface === 'ios' ? 44 : 48
        for (const [index, each] of placed.entries()) {
          expect.soft(each.cut, `${each.name} is whole`).toBeLessThanOrEqual(1)
          expect
            .soft(each.word, `${each.name} shows its whole word`)
            .toBeLessThanOrEqual(each.label.right - each.label.left + 0.05)
          expect.soft(each.tab.left, `${each.name} is inside the screen on the left`).toBeGreaterThanOrEqual(-0.5)
          expect.soft(each.tab.right, `${each.name} is inside the screen on the right`).toBeLessThanOrEqual(seen.width + 0.5)
          expect.soft(each.label.left, `${each.name} starts inside its tab`).toBeGreaterThanOrEqual(each.tab.left - 0.5)
          expect.soft(each.label.right, `${each.name} ends inside its tab`).toBeLessThanOrEqual(each.tab.right + 0.5)
          expect.soft(each.tab.right - each.tab.left, `${each.name}'s width`).toBeGreaterThanOrEqual(target - 0.5)
          expect.soft(each.tab.bottom - each.tab.top, `${each.name}'s height`).toBeGreaterThanOrEqual(target - 0.5)
          expect.soft(each.tab.bottom, `${each.name} is on the screen`).toBeLessThanOrEqual(seen.height + 0.5)
          for (const other of placed.slice(index + 1)) {
            const apart =
              each.label.right <= other.label.left + 0.5 ||
              other.label.right <= each.label.left + 0.5 ||
              each.label.bottom <= other.label.top + 0.5 ||
              other.label.bottom <= each.label.top + 0.5
            expect.soft(apart, `${each.name} and ${other.name} do not overlap`).toBe(true)
          }
          // Each tab follows the one before it: to its right on its row, or on a row below.
          const before = placed[index - 1]
          if (before !== undefined) {
            const sameRow = each.tab.top < before.tab.bottom - 0.5 && before.tab.top < each.tab.bottom - 0.5
            expect
              .soft(sameRow ? each.tab.left >= before.tab.right - 0.5 : each.tab.top >= before.tab.bottom - 0.5, `${each.name} follows ${before.name}`)
              .toBe(true)
          }
        }
        // A face's rule is in force: a page rule that took it back would leave a case that proves nothing.
        if (face.em !== undefined) {
          const set = await tabs.first().locator('.m-tab-label').evaluate(
            (label, pseudo) => {
              const style = getComputedStyle(label, pseudo)
              return { spacing: parseFloat(style.letterSpacing), size: parseFloat(style.fontSize) }
            },
            face.boldOnly === true ? '::after' : null
          )
          expect(set.spacing, 'the face is in force').toBeCloseTo(face.em * set.size, 1)
        }
        // The bar keeps its form and its tabs where they are, and every label whole, wherever the
        // person is: a label is bolder on the tab the person is on, and which tab that is must not
        // change what the bar can hold. The bar is made to measure again on each tab, by a pixel's
        // change of the screen's width, and the tabs are visited again from the first.
        const shape = async () =>
          page.evaluate(() => {
            const bar = document.querySelector('.m-tabbar') as HTMLElement
            return {
              form: bar.getAttribute('data-form'),
              tabs: Array.from(bar.querySelectorAll('.m-tab')).map((tab) => {
                const box = tab.getBoundingClientRect()
                const label = tab.querySelector('.m-tab-label') as HTMLElement
                const word = document.createRange()
                word.selectNodeContents(label)
                return {
                  left: box.left,
                  top: box.top,
                  width: box.width,
                  height: box.height,
                  cut: label.scrollWidth - label.clientWidth,
                  short: word.getBoundingClientRect().width - label.getBoundingClientRect().width,
                  wordLeft: word.getBoundingClientRect().left - box.left
                }
              })
            }
          })
        const settle = async () =>
          page.evaluate(
            () =>
              new Promise<void>((done) => {
                requestAnimationFrame(() => {
                  requestAnimationFrame(() => {
                    setTimeout(done, 100)
                  })
                })
              })
          )
        const resting = await shape()
        const holds = async (where: string) => {
          const moved = await shape()
          expect.soft(moved.form, `the bar's form ${where}`).toBe(resting.form)
          for (const [at, each] of moved.tabs.entries()) {
            expect.soft(each.cut, `${where}: tab ${at + 1} is whole`).toBeLessThanOrEqual(1)
            expect.soft(each.short, `${where}: tab ${at + 1} shows its whole word`).toBeLessThanOrEqual(0.05)
            for (const key of ['left', 'top', 'width', 'height'] as const) {
              expect.soft(each[key], `${where}: tab ${at + 1}'s ${key}`).toBeCloseTo(resting.tabs[at]?.[key] ?? -1, 0)
            }
            // Beside its glyph a word starts where it started, whichever tab is the current one.
            if (resting.form !== null) {
              expect
                .soft(each.wordLeft, `${where}: tab ${at + 1}'s word starts in place`)
                .toBeCloseTo(resting.tabs[at]?.wordLeft ?? -1, 0)
            }
          }
        }
        // While the bar decides its form every label is set in the weight of the current tab's.
        const weights = await page.evaluate(() => {
          const bar = document.querySelector('.m-tabbar') as HTMLElement
          const current = bar.querySelector('.m-tab[aria-current="page"] .m-tab-label') as HTMLElement
          const labels = Array.from(bar.querySelectorAll<HTMLElement>('.m-tab-label'))
          const weight = getComputedStyle(current).fontWeight
          bar.setAttribute('data-measuring', '')
          const measured = labels.map((label) => getComputedStyle(label).fontWeight)
          bar.removeAttribute('data-measuring')
          return { weight, measured }
        })
        expect(weights.measured, 'every label is in the current tab\'s weight while the bar measures').toEqual(
          weights.measured.map(() => weights.weight)
        )
        const list = page.locator('.m-main')
        for (const [index, name] of ['Attention', 'Sessions', 'Hosts', 'Account', 'Attention'].entries()) {
          const at = index % 4
          await tabs.nth(at).click()
          await expect(tabs.nth(at)).toHaveAttribute('aria-current', 'page')
          await settle()
          await holds(`on ${name} after the press`)
          // A person at the end of a list stays there while the bar measures again. The bar is made
          // to measure by a pixel's change of its own width, which leaves the page above it alone.
          const end = await list.evaluate((element) => {
            element.scrollTop = element.scrollHeight
            return element.scrollTop
          })
          if (seen.scale === '200%' && at === 0) expect.soft(end, 'the list has an end to scroll to').toBeGreaterThan(0)
          await page.evaluate(() => {
            ;(document.querySelector('.m-tabbar') as HTMLElement).style.paddingLeft = '1px'
          })
          await settle()
          await page.evaluate(() => {
            ;(document.querySelector('.m-tabbar') as HTMLElement).style.removeProperty('padding-left')
          })
          await settle()
          await holds(`on ${name} after the bar's width changed`)
          // Within a pixel's rounding: what the bar's measuring did was to move it by the bar's height.
          expect
            .soft(Math.abs((await list.evaluate((element) => element.scrollTop)) - end), `${name}: the list stays at its end`)
            .toBeLessThanOrEqual(1.5)
          // And by a pixel's change of the screen's width, which also lays the page above it out again.
          await page.setViewportSize({ width: seen.width + 1, height: seen.height })
          await settle()
          await page.setViewportSize({ width: seen.width, height: seen.height })
          await settle()
          await holds(`on ${name} after the screen changed width`)
        }
        // The widest count a badge shows, 99+, stays clear of its own label.
        const badge = page.locator('.m-tab-badge')
        await expect(badge).toBeVisible()
        const clear = await badge.evaluate((element) => {
          element.textContent = '99+'
          const label = element.closest('.m-tab')?.querySelector('.m-tab-label')
          if (!label) return false
          const count = element.getBoundingClientRect()
          const text = label.getBoundingClientRect()
          return (
            count.right <= text.left + 0.5 ||
            text.right <= count.left + 0.5 ||
            count.bottom <= text.top + 0.5 ||
            text.bottom <= count.top + 0.5
          )
        })
        expect.soft(clear, 'the widest badge stays clear of its label').toBe(true)
        await still(
          page,
          `tabs-13.19-${surface}-${seen.width}x${seen.height}-${seen.scale.replace('%', '')}${face.shot}`
        )
      })
    }
  }
})

// KR-REQ-13.19: the conversation keeps a height it scrolls within at a person's own text size: at
// least three lines of its own type, whatever the composer under it holds. The last of it can be
// scrolled to, and the field and Send are whole on the screen as it opens, without scrolling the
// page.
test.describe("the phone's conversation", () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** The lines of its own type the conversation keeps at the least. */
  const FLOOR = 3

  const SIZES: readonly Seen[] = [
    { width: 320, height: 720, scale: '200%' },
    { width: 320, height: 720, scale: '150%' },
    { width: 390, height: 844, scale: '100%' }
  ]

  for (const surface of ['ios', 'android'] as const) {
    for (const seen of SIZES) {
      test(`keeps a height it scrolls within and the composer on screen on ${surface} at ${seen.width}×${seen.height} with text at ${seen.scale}`, async ({
        page
      }) => {
        await onPhone(page, surface, seen, `&session=${SESSION_MAIN}`)
        const stream = page.getByTestId('mobile-conversation')
        // The main session's agent has said five things so far.
        await expect(stream.locator('.m-node')).toHaveCount(5)
        const pane = page.locator('.m-pane')
        const room = await pane.evaluate((element) => {
          const text = element.querySelector<HTMLElement>('.m-node p:last-child')
          return {
            height: element.getBoundingClientRect().height,
            line: text === null ? Infinity : parseFloat(getComputedStyle(text).lineHeight)
          }
        })
        expect(room.height, 'the conversation keeps its lines').toBeGreaterThanOrEqual(FLOOR * room.line - 0.5)
        // The last thing said can be scrolled to: with the conversation at its end, the end of the
        // last node is in view.
        const end = await pane.evaluate((element) => {
          element.scrollTop = element.scrollHeight
          const last = Array.from(element.querySelectorAll<HTMLElement>('.m-node')).at(-1)
          if (last === undefined) return null
          let top = 0
          let bottom = window.innerHeight
          for (let around = last.parentElement; around !== null; around = around.parentElement) {
            const style = getComputedStyle(around)
            if (style.overflowY === 'visible' && style.overflowX === 'visible') continue
            const clip = around.getBoundingClientRect()
            top = Math.max(top, clip.top)
            bottom = Math.min(bottom, clip.bottom)
          }
          const box = last.getBoundingClientRect()
          return { endShown: box.bottom <= bottom + 1 && box.bottom > top, shown: Math.min(box.bottom, bottom) - Math.max(box.top, top) }
        })
        expect(end?.endShown, 'the end of the last node is in view').toBe(true)
        expect(end?.shown ?? 0, 'some of the last node is in view').toBeGreaterThan(0)
        expect(await hiddenPart(page.getByLabel('Message this session')), 'the field is whole in view').toBeLessThanOrEqual(1)
        expect(await hiddenPart(page.getByRole('button', { name: 'Send' })), 'Send is whole in view').toBeLessThanOrEqual(1)
        await still(page, `conversation-13.19-${surface}-${seen.width}x${seen.height}-${seen.scale.replace('%', '')}`)
      })
    }
  }
})

// KR-REQ-08.75, KR-REQ-13.18: in view mode the wheel and a drag move the window across the session
// and into its history, the phone's one-finger drag the same; control mode's wheel and drag are the
// program's and move nothing, and taking control brings a window in the history back.
test.describe("moving a raw view's window", () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /** Opens the harness in one colour mode, whatever the system's. */
  async function inTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.addInitScript((mode) => {
      localStorage.setItem('kalareach-theme', mode)
    }, theme)
  }

  /** How many moves the page has made with its view. */
  const moves = (page: Page): Promise<number> =>
    page.evaluate(() => window.krTestHost?.terminalViews[0]?.moves.length ?? -1)

  /** Drags the pointer from the middle of `locator` by `down` pixels. */
  async function drag(page: Page, locator: Locator, down: number): Promise<void> {
    const box = await locator.boundingBox()
    if (box === null) throw new Error('nothing to drag on')
    const x = box.x + box.width / 2
    const y = box.y + Math.min(box.height / 2, 40)
    await page.mouse.move(x, y)
    await page.mouse.down()
    await page.mouse.move(x, y + down, { steps: 8 })
    await page.mouse.up()
  }

  test("view mode's wheel and drag move the window, and control mode's do not", async ({ page }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    const position = page.getByTestId('terminal-position')
    await expect(surface).toContainText('$ cargo test -p kr-client')

    // View mode, where a view opens: the wheel turned up takes the window into the history, and down
    // brings it back. The program gets nothing.
    await surface.hover()
    await page.mouse.wheel(0, -120)
    await expect(position).toContainText('Showing the history')
    await expect(surface).toContainText('$ echo earlier')
    await expect(surface).toHaveAttribute('data-wheel-to-application', '0')
    await page.mouse.wheel(0, 600)
    await expect(position).toHaveText('')
    await expect(surface).toContainText('$ cargo test -p kr-client')

    // A drag down moves the window up, as the pointer carries the screen.
    const before = await moves(page)
    await drag(page, surface, 90)
    await expect.poll(async () => moves(page)).toBeGreaterThan(before)
    await expect(position).toContainText('Showing the history')

    // Taking control brings it back to the live screen. Then the wheel is the program's, and a drag
    // moves nothing.
    await takeControl(page)
    await expect(position).toHaveText('')
    await expect(surface).toContainText('$ cargo test -p kr-client')
    const moved = await moves(page)
    // Over a cell of the session's live screen, which the program is told the wheel turned at.
    await page.getByTestId('terminal-grid').hover({ position: { x: 20, y: 10 } })
    await page.mouse.wheel(0, -120)
    await expect(surface).not.toHaveAttribute('data-wheel-to-application', '0')
    await drag(page, surface, 90)
    expect(await moves(page)).toBe(moved)
    await expect(position).toHaveText('')
    expect((await programInputs(page)).every((input) => input.kind === 'wheel')).toBe(true)
  })

  // A zoom step during a drag begins the drag again from where the pointer is: the part of a row it
  // had not sent is dropped, and the release sends nothing for it. A step back to the size the drag
  // began at is a step too.
  for (const back of [false, true]) {
    test(`a zoom step${back ? ' and one back' : ''} during a drag drops the part it had not sent`, async ({
      page
    }) => {
      await openSession(page)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      const surface = page.getByTestId('terminal-surface')
      await expect(surface).toContainText('$ cargo test -p kr-client')
      const grid = page.getByTestId('terminal-grid')
      const rowHeight = await grid.evaluate(
        (element) => element.getBoundingClientRect().height / Number(element.getAttribute('data-rows'))
      )
      const lineHeight = () => grid.evaluate((element) => (element as HTMLElement).style.lineHeight)
      const first = await lineHeight()
      const box = await surface.boundingBox()
      if (box === null) throw new Error('the terminal is not laid out')
      const x = box.x + box.width / 2
      const y = box.y + 40
      await page.mouse.move(x, y)
      await page.mouse.down()
      // A row and a half down: one row goes, and half a row is drawn.
      await page.mouse.move(x, y + rowHeight * 1.5, { steps: 6 })
      await expect.poll(async () => moves(page)).toBe(1)
      await page.keyboard.down('Control')
      await page.mouse.wheel(0, -100)
      await expect.poll(lineHeight).not.toBe(first)
      if (back) {
        await page.mouse.wheel(0, 100)
        await expect.poll(lineHeight).toBe(first)
      }
      await page.keyboard.up('Control')
      await page.mouse.up()
      // Without the zoom step the half row would have rounded to a second row.
      await page.waitForTimeout(100)
      expect(await moves(page)).toBe(1)
    })
  }

  // The same on the desktop: whatever the page has selected, a drag in view mode moves the window
  // and the browser starts no selection and no native drag of its own.
  test("the desktop's view-mode drag moves the window whatever is selected, and starts no selection or native drag", async ({
    page
  }) => {
    await openSession(page)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const surface = page.getByTestId('terminal-surface')
    await expect(surface).toContainText('$ cargo test -p kr-client')
    await page.evaluate(() => {
      const started = { selections: 0, drags: 0 }
      Object.assign(window, { started })
      window.addEventListener('selectstart', () => {
        started.selections += 1
      })
      window.addEventListener('dragstart', (event) => {
        if (!event.defaultPrevented) started.drags += 1
      })
      const element = document.querySelector('[data-testid="terminal-grid"]')
      if (element !== null) getSelection()?.selectAllChildren(element)
    })
    await drag(page, surface, 90)
    await expect(page.getByTestId('terminal-position')).toContainText('Showing the history')
    expect(await page.evaluate(() => (window as unknown as { started: unknown }).started)).toEqual({
      selections: 0,
      drags: 0
    })
  })

  // A press in view mode is the view's alone. Whatever the page has selected, the phone's drag
  // moves the window and the browser starts no selection and no native drag of its own.
  test("the phone's view-mode drag moves the window whatever is selected, and starts no selection or native drag", async ({
    page
  }) => {
    await page.setViewportSize({ width: 320, height: 1000 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const terminal = page.getByTestId('mobile-terminal')
    await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
    // View mode's text, where a view opens, is not selectable, so neither a press nor a long press
    // starts a selection there; control mode leaves the browser its own way with the text.
    const selectable = () =>
      terminal.evaluate((element) => {
        const style = getComputedStyle(element)
        return (style.getPropertyValue('user-select') || style.getPropertyValue('-webkit-user-select')) !== 'none'
      })
    expect(await selectable()).toBe(false)
    await takeControl(page)
    expect(await selectable()).toBe(true)
    await page.getByRole('button', { name: 'Look around' }).click()
    expect(await selectable()).toBe(false)
    // The terminal's text selected, as a drag in control mode leaves it, and from here on every
    // selection and every native drag the browser starts counted.
    await page.evaluate(() => {
      const started = { selections: 0, drags: 0 }
      Object.assign(window, { started })
      window.addEventListener('selectstart', () => {
        started.selections += 1
      })
      window.addEventListener('dragstart', (event) => {
        if (!event.defaultPrevented) started.drags += 1
      })
      const element = document.querySelector('[data-testid="mobile-terminal"]')
      if (element !== null) getSelection()?.selectAllChildren(element)
    })
    await drag(page, terminal, 60)
    await expect(page.getByTestId('terminal-position')).toContainText('Showing the history')
    expect(await page.evaluate(() => (window as unknown as { started: unknown }).started)).toEqual({
      selections: 0,
      drags: 0
    })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`the desktop view moves across the session and into its history, ${theme}, at 320 px`, async ({
      page
    }) => {
      await inTheme(page, theme)
      await openSession(page)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      // Narrowed once open, as a person narrows a window: the sessions list is behind a button there.
      await page.setViewportSize({ width: 320, height: 720 })
      const surface = page.getByTestId('terminal-surface')
      const position = page.getByTestId('terminal-position')
      await expect(surface).toContainText('$ cargo')
      // The view reports its narrower grid, and the host's next screen is drawn for it.
      await expect
        .poll(async () => page.evaluate(() => window.krTestHost?.terminalViews[0]?.grids.at(-1)?.columns))
        .toBeLessThan(80)
      await page.evaluate(() => {
        window.krTestHost?.terminalViews[0]?.show()
      })
      await expect(position).toContainText('Showing columns 1–')

      await surface.hover()
      // Sideways across a session wider than the view, then up into its history.
      await page.mouse.wheel(120, 0)
      await expect(position).not.toContainText('Showing columns 1–')
      await expect(position).toContainText('Showing columns ')
      await page.mouse.wheel(0, -64)
      await expect(position).toContainText('Showing the history')
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({ path: shotFor(`terminal-pan-08.75-desktop-320-${theme}`), fullPage: true })
    })

    test(`the desktop view moves into the history, ${theme}, in a wide window`, async ({ page }) => {
      await inTheme(page, theme)
      await openSession(page)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      const surface = page.getByTestId('terminal-surface')
      await expect(surface).toContainText('$ cargo')
      await drag(page, surface, 60)
      await expect(page.getByTestId('terminal-position')).toContainText('Showing the history')
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({ path: shotFor(`terminal-pan-08.75-desktop-wide-${theme}`), fullPage: true })
    })

    test(`the phone's view moves with a one-finger drag, ${theme}, at 320 px`, async ({ page }) => {
      await inTheme(page, theme)
      await page.setViewportSize({ width: 320, height: 1000 })
      await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      const terminal = page.getByTestId('mobile-terminal')
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      // View mode, where a view opens: the drag moves the window.
      await expect(
        page.getByText('View: drag to move around the session, pinch to make the text larger or smaller.')
      ).toBeVisible()
      await drag(page, terminal, 60)
      await expect(page.getByTestId('terminal-position')).toContainText('Showing the history')
      await expect(terminal).toContainText('$ echo earlier')
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({ path: shotFor(`terminal-pan-08.75-phone-320-${theme}`), fullPage: true })
      // Taking control brings the window back to the live screen, and a drag then moves nothing.
      await takeControl(page)
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      const moved = await moves(page)
      await drag(page, terminal, 60)
      expect(await moves(page)).toBe(moved)
    })
  }

  // KR-REQ-08.76, KR-REQ-13.18: in control mode the phone's one-finger drag turns the program's
  // wheel, a turn for each row the finger crosses, at the session's cell under the finger, and never
  // becomes arrow keys.
  test("the phone's control-mode drag turns the program's wheel at the cell under the finger", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 1000 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION_MAIN}`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
    await takeControl(page)
    const cell = await page.locator('.m-terminal-grid').evaluate((element) => {
      const box = element.getBoundingClientRect()
      const style = getComputedStyle(element)
      const probe = element.querySelector('[aria-hidden="true"]')?.getBoundingClientRect()
      return {
        x: box.x + parseFloat(style.paddingLeft),
        y: box.y + parseFloat(style.paddingTop),
        width: (probe?.width ?? 0) / 10,
        height: parseFloat(style.lineHeight) || (probe?.height ?? 0)
      }
    })
    // Down on the session's column 3 and line 6, then up three and a half rows, with the finger.
    const x = cell.x + 3.5 * cell.width
    const y = cell.y + 6.5 * cell.height
    await page.mouse.move(x, y)
    await page.mouse.down()
    await page.mouse.move(x, y - 3.5 * cell.height, { steps: 7 })
    await page.mouse.up()
    await expect
      .poll(async () =>
        (await programInputs(page)).reduce((sum, input) => sum + (input.kind === 'wheel' ? input.turns : 0), 0)
      )
      .toBe(3)
    const turned = await programInputs(page)
    for (const input of turned) {
      expect(input).toMatchObject({ kind: 'wheel', take: 1, column: 3 })
      if (input.kind === 'wheel') {
        expect(input.line).toBeGreaterThanOrEqual(3)
        expect(input.line).toBeLessThanOrEqual(5)
      }
    }
    // The finger crossed each row it turned the wheel for: the lines go up with it.
    const lines = turned.map((input) => (input.kind === 'wheel' ? input.line : -1))
    expect([...lines].sort((one, other) => other - one)).toEqual(lines)
    expect(turned.some((input) => input.kind === 'key')).toBe(false)
    expect(await moves(page)).toBe(1)
  })
})

// KR-REQ-13.19: a window as narrow as a phone. Nothing runs past the window's edge or the
// terminal's, the controls keep the size they have in a wide window, and they read in the order the
// keyboard reaches them: along a row, then down to the next.
test.describe('a session in a window 320 px wide', () => {
  /** Where a screenshot for this browser goes, so each engine keeps its own. */
  const shotFor = (name: string): string => shot(`${name}-${test.info().project.name}`)

  /** How far the page runs past the window's width. */
  const pageOverflow = (page: Page): Promise<number> =>
    page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)

  /** How far what `locator` holds runs past its own box, whether it is shown or clipped. */
  const spill = (locator: Locator): Promise<number> =>
    locator.evaluate((element) => element.scrollWidth - element.clientWidth)

  interface Placed {
    readonly name: string
    /** Whether it is a tab, which is drawn inside its switch's frame and pressed across the target. */
    readonly tab: boolean
    readonly left: number
    readonly right: number
    readonly top: number
    readonly bottom: number
    readonly width: number
    readonly height: number
  }

  /** Each control inside `locator`, in the order the keyboard reaches them, with its box. */
  const placed = (locator: Locator): Promise<Placed[]> =>
    locator.locator('button').evaluateAll((buttons) =>
      buttons.map((button) => {
        const box = button.getBoundingClientRect()
        return {
          name: button.textContent ?? '',
          tab: button.getAttribute('role') === 'tab',
          left: box.left,
          right: box.right,
          top: box.top,
          bottom: box.bottom,
          width: box.width,
          height: box.height
        }
      })
    )

  /** Checks that each control follows the one before it: to its right on its row, or below it. */
  function inReadingOrder(controls: readonly Placed[]): void {
    for (let index = 1; index < controls.length; index += 1) {
      const before = controls[index - 1]
      const after = controls[index]
      const sameRow = after.top < before.bottom && before.top < after.bottom
      expect
        .soft(sameRow ? after.left >= before.right - 1 : after.top >= before.bottom - 1, `${after.name} follows ${before.name}`)
        .toBe(true)
    }
  }

  /** Checks that the narrow controls are the wide ones, each the same size and inside `edge`. */
  function wholeAndUnshrunk(
    narrow: readonly Placed[],
    wide: readonly Placed[],
    edge: { readonly left: number; readonly right: number }
  ): void {
    expect(narrow.map((each) => each.name)).toEqual(wide.map((each) => each.name))
    narrow.forEach((control, index) => {
      expect.soft(Math.abs(control.width - wide[index].width), `${control.name}'s width`).toBeLessThanOrEqual(1)
      expect.soft(Math.abs(control.height - wide[index].height), `${control.name}'s height`).toBeLessThanOrEqual(1)
      expect.soft(control.left, `${control.name}'s left edge`).toBeGreaterThanOrEqual(edge.left - 1)
      expect.soft(control.right, `${control.name}'s right edge`).toBeLessThanOrEqual(edge.right + 1)
    })
  }

  /**
   * What in `root` runs past its own box, shown or clipped. Left out: a code block or a diff, which
   * scroll sideways by design, text kept for a screen reader alone, and the terminal's screen with
   * the frame that holds it, because the screen is the host's columns, panned and zoomed, never
   * wrapped. What else the frame holds is checked against the frame by `pastTheTerminal`.
   */
  const runningPast = (root: Locator): Promise<string[]> =>
    root.evaluate((element) => {
      const found: string[] = []
      for (const each of [element, ...Array.from(element.querySelectorAll('*'))]) {
        if (!(each instanceof HTMLElement)) continue
        if (each.closest('.terminal-surface, .visually-hidden, .code-block, .diff-code')) continue
        if (each.querySelector('.terminal-surface')) continue
        if (each.scrollWidth - each.clientWidth > 1) {
          found.push(`${each.tagName.toLowerCase()}.${each.className} "${(each.textContent ?? '').slice(0, 40)}"`)
        }
      }
      return found
    })

  /** What the terminal holds, its screen aside, that reaches past the frame's inner edges. */
  const pastTheTerminal = (page: Page): Promise<string[]> =>
    page.getByTestId('raw-terminal').evaluate((frame) => {
      const left = frame.getBoundingClientRect().left + frame.clientLeft
      const right = left + frame.clientWidth
      const found: string[] = []
      for (const each of Array.from(frame.querySelectorAll('*'))) {
        if (!(each instanceof HTMLElement) || each.closest('.terminal-surface, .visually-hidden')) continue
        const box = each.getBoundingClientRect()
        if (box.width > 0 && (box.left < left - 1 || box.right > right + 1)) {
          found.push(`${each.tagName.toLowerCase()}.${each.className} "${(each.textContent ?? '').slice(0, 40)}"`)
        }
      }
      return found
    })

  /**
   * The tabs in `root` that a press does not reach across `target` px of height, centred on the
   * tab: each tab is the target, whatever its drawn height.
   */
  const tabsShortOf = (root: Locator, target: number): Promise<string[]> =>
    root.getByRole('tab').evaluateAll((tabs, size) => {
      const short: string[] = []
      for (const tab of tabs) {
        tab.scrollIntoView({ block: 'center' })
        const box = tab.getBoundingClientRect()
        const middle = box.top + box.height / 2
        for (const y of [middle - size / 2 + 0.5, middle + size / 2 - 0.5]) {
          const hit = document.elementFromPoint(box.left + box.width / 2, y)
          if (!hit || !tab.contains(hit)) short.push(`${tab.textContent ?? ''} at ${Math.round(y - middle)} px`)
        }
      }
      return short
    }, target)

  /** Opens a session's terminal and waits for the screen, whose badges come with it. */
  async function openTerminal(page: Page): Promise<void> {
    await page.getByRole('tab', { name: 'Terminal' }).click()
    await page.getByTestId('palette-provenance').waitFor()
  }

  test('the header and the conversation fit, with the header whole and in order', async ({ page }) => {
    await openSession(page)
    const header = page.locator('.session-header')
    const wide = await placed(header)
    await page.setViewportSize({ width: 320, height: 720 })

    expect.soft(await pageOverflow(page), 'the page').toBeLessThanOrEqual(1)
    expect.soft(await spill(header), 'the header').toBeLessThanOrEqual(1)
    const narrow = await placed(header)
    wholeAndUnshrunk(narrow, wide, { left: 0, right: 320 })
    inReadingOrder(narrow)
    expect.soft(await runningPast(page.locator('main')), 'what runs past its own box').toEqual([])

    // The working directory and the name are the host's. Long ones wrap inside the window, whole,
    // rather than widening the page or being cut off.
    await page.evaluate(() => {
      const name = document.querySelector('.session-header h1')
      const directory = document.querySelector('.session-header .session-meta')
      if (name) name.textContent = 'a-folder-whose-name-is-longer-than-the-window-is-wide'
      if (directory) {
        directory.textContent = '/Users/someone/work/clients/a-long-client-name/repositories/the-service'
      }
    })
    expect.soft(await pageOverflow(page), 'the page with a long directory').toBeLessThanOrEqual(1)
    expect.soft(await spill(header.locator('h1')), 'the name').toBeLessThanOrEqual(1)
    expect.soft(await spill(header.locator('.session-meta')), 'the directory').toBeLessThanOrEqual(1)
  })

  test('the terminal, its badges and its footer fit, with every control whole and in order', async ({
    page
  }) => {
    await openSession(page)
    await openTerminal(page)
    const footer = page.locator('.terminal-footer')
    const wide = await placed(footer)
    await page.setViewportSize({ width: 320, height: 720 })

    expect.soft(await pageOverflow(page), 'the page').toBeLessThanOrEqual(1)
    const terminal = await page.getByTestId('raw-terminal').evaluate((element) => {
      const box = element.getBoundingClientRect()
      return { left: box.left, right: box.right }
    })
    expect.soft(await spill(page.locator('.terminal-heading')), 'the heading').toBeLessThanOrEqual(1)
    expect.soft(await spill(footer), 'the footer').toBeLessThanOrEqual(1)
    for (const badge of await page.locator('.terminal-heading .badge').all()) {
      const box = await badge.boundingBox()
      expect.soft(box?.x ?? -1, 'a badge starts inside the terminal').toBeGreaterThanOrEqual(terminal.left - 1)
      expect
        .soft((box?.x ?? 0) + (box?.width ?? Number.POSITIVE_INFINITY), 'a badge ends inside the terminal')
        .toBeLessThanOrEqual(terminal.right + 1)
    }
    const narrow = await placed(footer)
    wholeAndUnshrunk(narrow, wide, terminal)
    inReadingOrder(narrow)
    expect.soft(await runningPast(page.locator('main')), 'what runs past its own box').toEqual([])
    expect.soft(await pastTheTerminal(page), 'what reaches past the terminal').toEqual([])

    // In control mode the heading says something else and the moves and sizes cannot be pressed; it
    // all still fits.
    await takeControl(page)
    await expect(page.getByTestId('raw-terminal')).toHaveAttribute('data-mode', 'control')
    expect.soft(await pageOverflow(page), 'the page in control mode').toBeLessThanOrEqual(1)
    expect
      .soft(await runningPast(page.locator('main')), 'what runs past its own box in control mode')
      .toEqual([])
    expect.soft(await pastTheTerminal(page), 'what reaches past the terminal in control mode').toEqual([])
    inReadingOrder(await placed(footer))
  })

  test("the header fits and reads in order at widths from a phone's to a desktop's, and with larger text", async ({
    page
  }) => {
    await openSession(page)
    const header = page.locator('.session-header')
    const wide = await placed(header)
    // Either side of the width where the sidebar goes, and the widths between a phone and a desktop.
    for (const width of [360, 390, 480, 600, 719, 721, 800, 1024]) {
      await page.setViewportSize({ width, height: 720 })
      expect.soft(await pageOverflow(page), `the page at ${width} px`).toBeLessThanOrEqual(1)
      expect.soft(await spill(header), `the header at ${width} px`).toBeLessThanOrEqual(1)
      const placedNow = await placed(header)
      wholeAndUnshrunk(placedNow, wide, { left: 0, right: width })
      inReadingOrder(placedNow)
    }

    // A person's own larger text size: every size given in rem grows with it, controls included.
    await page.setViewportSize({ width: 320, height: 720 })
    for (const scale of ['125%', '150%']) {
      await page.evaluate((size) => {
        document.documentElement.style.fontSize = size
      }, scale)
      expect.soft(await pageOverflow(page), `the page with text at ${scale}`).toBeLessThanOrEqual(1)
      expect.soft(await spill(header), `the header with text at ${scale}`).toBeLessThanOrEqual(1)
      const grown = await placed(header)
      for (const control of grown) {
        expect.soft(control.right, `${control.name} inside the window with text at ${scale}`).toBeLessThanOrEqual(321)
      }
      inReadingOrder(grown)
    }
  })

  test('the header and the footer still fit with touch targets of 44 and 48 px', async ({ page }) => {
    await openSession(page)
    await openTerminal(page)
    await page.setViewportSize({ width: 320, height: 720 })
    const own = await page.evaluate(() =>
      Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--target'))
    )
    expect.soft(await tabsShortOf(page.locator('main'), own), `the tabs at ${own} px`).toEqual([])
    for (const target of [44, 48]) {
      // The token every control takes its minimum from, as a coarse pointer or a phone sets it.
      await page.evaluate((size) => {
        document.documentElement.style.setProperty('--target', `${size}px`)
      }, target)
      expect.soft(await pageOverflow(page), `the page at ${target} px`).toBeLessThanOrEqual(1)
      expect.soft(await spill(page.locator('.terminal-footer')), `the footer at ${target} px`).toBeLessThanOrEqual(1)
      expect.soft(await pastTheTerminal(page), `what reaches past the terminal at ${target} px`).toEqual([])
      const controls = [
        ...(await placed(page.locator('.session-header'))),
        ...(await placed(page.locator('.terminal-footer')))
      ]
      for (const control of controls.filter((each) => !each.tab)) {
        expect.soft(control.height, `${control.name}'s height at ${target} px`).toBeGreaterThanOrEqual(target - 0.1)
        expect.soft(control.width, `${control.name}'s width at ${target} px`).toBeGreaterThanOrEqual(target - 0.1)
        expect.soft(control.right, `${control.name} inside the window at ${target} px`).toBeLessThanOrEqual(321)
      }
      // A tab is drawn inside its switch's frame; a press anywhere across the target still lands on it.
      expect.soft(await tabsShortOf(page.locator('main'), target), `the tabs at ${target} px`).toEqual([])
    }
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`the session in a wide window and at 320 px, ${theme}`, async ({ page }) => {
      await page.addInitScript((mode) => {
        localStorage.setItem('kalareach-theme', mode)
      }, theme)
      await openSession(page)
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      const size = page.viewportSize() ?? { width: 1280, height: 720 }
      for (const pane of ['conversation', 'terminal'] as const) {
        if (pane === 'terminal') await openTerminal(page)
        await page.setViewportSize(size)
        await page.screenshot({ path: shotFor(`session-13.19-${pane}-desktop-${theme}`), fullPage: true })
        await page.setViewportSize({ width: 320, height: 720 })
        expect.soft(await pageOverflow(page), `the ${pane} at 320 px`).toBeLessThanOrEqual(1)
        await page.screenshot({ path: shotFor(`session-13.19-${pane}-320-${theme}`), fullPage: true })
      }
    })
  }
})

test.describe('packages', () => {
  // KR-REQ-11.03: the Installed, Catalogue and Repositories views, with offline search, photographed.
  test('searches the catalogue with no network and says so', async ({ page }) => {
    await open(page)
    await page.getByRole('button', { name: 'Plugins' }).click()
    await expect(page.getByTestId('offline-search-note')).toBeVisible()
    await expect(page.getByTestId('installed-list')).toContainText('openai.codex')
    await page.getByTestId('catalogue-search').fill('tmux')
    await expect(page.getByTestId('installed-list')).toContainText('community.tmux-status')
    await expect(page.getByTestId('installed-list')).not.toContainText('openai.codex')
    await still(page, 'packages-11.03-installed')
    await page.getByRole('tab', { name: 'Catalogue' }).click()
    await page.getByTestId('catalogue-search').fill('mirror')
    await expect(page.getByTestId('catalogue-list')).toContainText('community-mirror')
    await expect(page.getByTestId('catalogue-list')).not.toContainText('packages.kala.to')
    await still(page, 'packages-11.03')
    await page.getByRole('tab', { name: 'Repositories' }).click()
    await page.getByTestId('catalogue-search').fill('')
    await expect(page.getByTestId('repository-list')).toContainText('https://packages.kala.to/metadata')
    await still(page, 'packages-11.03-repositories')
  })
})

test.describe('pairing', () => {
  // KR-REQ-10.18: the code entry names the rendezvous origin, the default one included, with its
  // change action, before an attempt starts.
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
            facts: [],
            notice: null,
            statement: null,
            reading: null,
            expires_at_ms: Date.now() + 120_000,
            checkable: true
          },
          {
            reference: 'request-2',
            host_name: 'build-box',
            title: 'Confirm a request from build-box',
            detail: null,
            value: null,
            facts: [],
            notice: null,
            statement: null,
            reading: null,
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

  // KR-REQ-11.42: a repository's root and an installation with a native bridge are listed with
  // everything the confirmation covers, the host's own notice first and the publisher's words
  // after it, quoted and named; a 64-character hash breaks inside its row, and nothing makes the
  // page scroll sideways at the narrowest screen the application supports.
  test('an enrolment and a native bridge installation are listed whole and fit a narrow screen', async ({
    page
  }) => {
    await open(page)
    const hash = ['1a2b3c4d', '5e6f7081', '92a3b4c5', 'd6e7f809', '1a2b3c4d', '5e6f7081', '92a3b4c5', 'd6e7f809']
    await page.evaluate((groups) => {
      window.krTestHost?.setConfirmations({
        ceremony: 'touch_id',
        requests: [
          {
            reference: 'request-1',
            host_name: 'studio',
            title: 'Trust a plugin repository',
            detail:
              'Trust the plugin repository community on studio, served from repo.example: its root starts 1a2b 3c4d, and its packages may hold 1 capability beyond the default.',
            value: null,
            facts: [
              { label: 'Name', value: 'community', code: false },
              { label: 'Kind', value: 'A community repository', code: false },
              { label: 'Metadata at', value: 'https://repo.example/plugins/community/metadata/', code: true },
              { label: 'Targets at', value: 'https://repo.example/plugins/community/targets/', code: true },
              { label: 'Root', value: groups.join(' '), code: true },
              { label: 'Root keys', value: 'f14e4ac91420a6515eb9ae321fcba909420d2cd09cf8c5fd42244af8f0e5fdf2', code: true },
              { label: 'Beyond the default', value: 'terminal.stream', code: true },
              { label: 'Offline copy', value: 'Not kept', code: false }
            ],
            notice: null,
            statement: null,
            reading: null,
            expires_at_ms: Date.now() + 120_000,
            checkable: true
          },
          {
            reference: 'request-2',
            host_name: 'studio',
            title: 'Install a plugin',
            detail:
              'Install kalareach/claude-code 0.3.0 from community on studio, granting 2 capabilities, among them a native bridge that runs outside the plugin sandbox; package starts 1a2b 3c4d.',
            value: null,
            facts: [
              { label: 'Plugin', value: 'kalareach/claude-code 0.3.0', code: true },
              { label: 'From', value: 'community', code: false },
              { label: 'Package hash', value: groups.join(' '), code: true },
              { label: 'Granted', value: 'approval.respond, native_bridge.install', code: true }
            ],
            notice:
              "This package installs a native bridge: code in the application's own directory that runs with the application's permissions, outside the plugin sandbox. The publisher's own statement of what it does follows.",
            statement:
              'Installs three registration files under /Users/someone/.claude/skills/kalareach-channels/hooks/hooks-with-a-long-name-and-no-break.json, where they apply  to every project  and every later session.',
            reading: null,
            expires_at_ms: Date.now() + 120_000,
            checkable: true
          }
        ]
      })
    }, hash)
    const rows = page.getByTestId('confirmation-row')
    await expect(rows).toHaveCount(2)
    await expect(rows.nth(0).getByTestId('confirmation-facts')).toContainText('Metadata at')
    await expect(rows.nth(1).getByTestId('confirmation-notice')).toContainText('outside the plugin sandbox')
    await expect(rows.nth(1).getByTestId('confirmation-statement')).toContainText('The publisher says')
    // The publisher's words keep every space they were written with.
    const written = await rows.nth(1).locator('blockquote').evaluate((element) => ({
      shown: (element as HTMLElement).innerText,
      kept: element.textContent
    }))
    expect(written.shown).toBe(written.kept)
    expect(written.shown).toContain('apply  to every project  and')
    await still(page, 'owner-confirmations-11.42-wide')
    await rows.nth(1).screenshot({
      path: shot(`owner-install-11.42-wide-${test.info().project.name}`),
      animations: 'disabled'
    })

    for (const width of [320, 390]) {
      await page.setViewportSize({ width, height: 900 })
      expect
        .soft(
          await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
          `the page at ${width}px`
        )
        .toBeLessThanOrEqual(1)
      for (const index of [0, 1]) {
        const row = rows.nth(index)
        const spill = await row.evaluate((element) => {
          const box = element.getBoundingClientRect()
          return Math.max(
            0,
            ...[...element.querySelectorAll<HTMLElement>('dd, blockquote, p')].map(
              (child) => child.getBoundingClientRect().right - box.right
            )
          )
        })
        expect.soft(spill, `row ${index} at ${width}px`).toBeLessThanOrEqual(1)
      }
      await still(page, `owner-confirmations-11.42-${width}`)
      await rows.nth(1).screenshot({
        path: shot(`owner-install-11.42-${width}-${test.info().project.name}`),
        animations: 'disabled'
      })
    }
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
              facts: [],
              notice: null,
              statement: null,
              reading: null,
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

/**
 * Starts recording every transition and animation the engine runs on an element matching
 * `selector`, inside one, or on anything that contains one. `krFeedbackMotion` returns the record.
 */
async function recordMotion(page: Page, selector: string): Promise<void> {
  await page.evaluate((selector) => {
    const motion: string[] = []
    const record = (what: string, target: EventTarget | null) => {
      if (!(target instanceof Element)) return
      if (target.closest(selector) === null && target.querySelector(selector) === null) return
      motion.push(`${what} on ${target.tagName.toLowerCase()}.${String(target.className)}`)
    }
    for (const type of ['transitionrun', 'animationstart']) {
      document.addEventListener(
        type,
        (event) => {
          const name =
            event instanceof TransitionEvent ? event.propertyName : (event as AnimationEvent).animationName
          record(`${type} ${name}`, event.target)
        },
        true
      )
    }
    ;(window as unknown as { krFeedbackMotion: () => string[] }).krFeedbackMotion = () => {
      for (const animation of document.getAnimations()) {
        const effect = animation.effect
        record('running', effect instanceof KeyframeEffect ? effect.target : null)
      }
      return motion
    }
  }, selector)
}

/** What `recordMotion` saw, two frames on, so anything the last change started has started. */
async function recordedMotion(page: Page): Promise<string[]> {
  return page.evaluate(
    () =>
      new Promise<string[]>((resolve) => {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            resolve((window as unknown as { krFeedbackMotion: () => string[] }).krFeedbackMotion())
          })
        })
      })
  )
}

/** How far down a surface is drawn from where it sits, as the engine placed it. */
async function drawnOffset(locator: Locator): Promise<number> {
  return locator.evaluate((element) => new DOMMatrixReadOnly(getComputedStyle(element).transform).m42)
}

/** Takes hold of the open sheet's grip, and answers where the pointer is. */
async function holdSheet(page: Page): Promise<{ x: number; y: number }> {
  await page.getByTestId('open-settings').click()
  await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', {
    timeout: PRESENTATION_DEADLINE
  })
  const box = await page.getByTestId('sheet-grip').boundingBox()
  if (!box) throw new Error('the sheet has no grip')
  const at = { x: box.x + box.width / 2, y: box.y + box.height / 2 }
  await page.mouse.move(at.x, at.y)
  await page.mouse.down()
  return at
}

/**
 * Lets go of the sheet still: a release velocity comes from the last 100 ms of the pointer, so a
 * pointer held where it is for longer than that carries none.
 */
async function releaseStill(page: Page): Promise<void> {
  await page.waitForTimeout(150)
  await page.mouse.up()
}

// KR-REQ-13.06: section 13's feedback paragraph. Input feedback is immediate, repeated keyboard
// actions and streamed text take no decorative delay, and gesture motion tracks the finger, can
// reverse during the movement and respects the preference for reduced motion.
test.describe('input feedback', () => {
  test('each key of a repeated burst has changed the text before the next arrives, and nothing moves', async ({
    page
  }) => {
    await openSession(page)
    const composer = page.getByTestId('composer-input')
    await composer.click()
    // The length of the text as each key arrives: a key the page had not yet applied when the
    // next one came would show as a length that did not move on.
    await page.evaluate(() => {
      const field = document.querySelector<HTMLTextAreaElement>('[data-testid="composer-input"]')
      const lengths: number[] = []
      field?.addEventListener('keydown', () => lengths.push(field.value.length), true)
      ;(window as unknown as { krLengths: () => number[] }).krLengths = () => [
        ...lengths,
        field?.value.length ?? -1
      ]
    })
    await recordMotion(page, '[data-testid="composer"]')

    // Typed, then one key held so it repeats, then deleted a key at a time.
    await page.keyboard.type('x'.repeat(30))
    for (let repeat = 0; repeat < 20; repeat += 1) await page.keyboard.down('y')
    await page.keyboard.up('y')
    for (let press = 0; press < 25; press += 1) await page.keyboard.press('Backspace')
    await expect(composer).toHaveValue(`${'x'.repeat(25)}`)

    const lengths = await page.evaluate(() =>
      (window as unknown as { krLengths: () => number[] }).krLengths()
    )
    const typed = Array.from({ length: 30 }, (_, index) => index)
    const held = Array.from({ length: 20 }, (_, index) => 30 + index)
    const deleted = Array.from({ length: 25 }, (_, index) => 50 - index)
    expect(lengths).toEqual([...typed, ...held, ...deleted, 25])
    expect(await recordedMotion(page)).toEqual([])
    await page.screenshot({ path: shot(`feedback-keys-13.06-${test.info().project.name}`) })
  })

  test('a held arrow key moves through the views one press at a time, with nothing animated', async ({
    page
  }) => {
    await openSession(page)
    const views = page.getByRole('tablist', { name: 'View' })
    await views.getByRole('tab', { name: 'Conversation' }).focus()
    // The view selected as each press arrives.
    await page.evaluate(() => {
      const selected: string[] = []
      document.addEventListener(
        'keydown',
        () => {
          const tab = document.querySelector('[role="tablist"][aria-label="View"] [aria-selected="true"]')
          selected.push(tab?.textContent ?? '')
        },
        true
      )
      ;(window as unknown as { krSelected: () => string[] }).krSelected = () => selected
    })
    await recordMotion(page, '[role="tablist"][aria-label="View"]')

    for (let repeat = 0; repeat < 4; repeat += 1) await page.keyboard.down('ArrowRight')
    await page.keyboard.up('ArrowRight')

    expect(await page.evaluate(() => (window as unknown as { krSelected: () => string[] }).krSelected())).toEqual(
      ['Conversation', 'Terminal', 'Output', 'Conversation']
    )
    await expect(views.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true')
    expect(await recordedMotion(page)).toEqual([])
  })

  test('streamed text is drawn whole as it arrives, never revealed or faded in', async ({ page }) => {
    await openSession(page)
    // Every state the streamed node is drawn in: its text and its opacity, from the moment it is
    // inserted.
    await page.evaluate(() => {
      const drawn: string[] = []
      const look = () => {
        const node = document.querySelector<HTMLElement>('[data-node-id="streamed-2"]')
        if (!node) return
        let opacity = 1
        for (let around: Element | null = node; around; around = around.parentElement) {
          opacity *= Number(getComputedStyle(around).opacity)
        }
        drawn.push(`${opacity} ${node.querySelector('.message-content > p')?.textContent ?? ''}`)
      }
      new MutationObserver(look).observe(document.body, {
        subtree: true,
        childList: true,
        characterData: true
      })
      ;(window as unknown as { krDrawn: () => string[] }).krDrawn = () => drawn
    })
    const words = ['kr-arriving', 'text', 'drawn', 'as', 'it', 'comes']
    const revisions = words.map((_, index) => words.slice(0, index + 1).join(' '))
    for (const [index, text] of revisions.entries()) {
      await page.evaluate(
        ({ revision, text }) => {
          window.krTestHost?.appendNode({
            id: 'streamed-2',
            revision: String(revision),
            body: { kind: 'message', author: 'agent', text }
          } as never)
        },
        { revision: index + 1, text }
      )
      await expect(page.getByText(text, { exact: true })).toBeVisible({
        timeout: PRESENTATION_DEADLINE
      })
    }
    const drawn = await page.evaluate(() => (window as unknown as { krDrawn: () => string[] }).krDrawn())
    expect(drawn.length).toBeGreaterThan(0)
    for (const state of drawn) {
      const [opacity, ...text] = state.split(' ')
      expect(opacity).toBe('1')
      // Each state is a whole revision the host sent, never part of one.
      expect(revisions).toContain(text.join(' '))
    }
  })

  test('the sheet follows the pointer as it is dragged and back, before it is let go', async ({ page }) => {
    await openSession(page)
    const sheet = page.getByTestId('sheet')
    const at = await holdSheet(page)

    await page.mouse.move(at.x, at.y + 90, { steps: 6 })
    expect(await drawnOffset(sheet)).toBeCloseTo(90, 0)
    await page.screenshot({ path: shot(`feedback-drag-13.06-${test.info().project.name}`) })
    // Back up during the same movement, and past where it sits, where it resists.
    await page.mouse.move(at.x, at.y + 30, { steps: 6 })
    expect(await drawnOffset(sheet)).toBeCloseTo(30, 0)
    await page.mouse.move(at.x, at.y - 60, { steps: 6 })
    const past = await drawnOffset(sheet)
    expect(past).toBeLessThan(0)
    expect(past).toBeGreaterThan(-60)

    // Let go short of a dismissal, and it settles back where it sits.
    await page.mouse.move(at.x, at.y + 20, { steps: 6 })
    await releaseStill(page)
    await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
    expect(await drawnOffset(sheet)).toBeCloseTo(0, 0)
  })
})

test.describe('input feedback with reduced motion', () => {
  test.use({ reducedMotion: 'reduce' })

  // KR-REQ-13.06: nothing moves by itself, and a drag is still the person's own motion.
  test('the sheet follows the pointer and back, stops at its edge, and nothing springs', async ({ page }) => {
    await openSession(page)
    const sheet = page.getByTestId('sheet')
    const at = await holdSheet(page)
    await recordMotion(page, '[data-testid="sheet"]')

    await page.mouse.move(at.x, at.y + 90, { steps: 6 })
    expect(await drawnOffset(sheet)).toBeCloseTo(90, 0)
    await page.screenshot({ path: shot(`feedback-drag-reduced-13.06-${test.info().project.name}`) })
    await page.mouse.move(at.x, at.y + 30, { steps: 6 })
    expect(await drawnOffset(sheet)).toBeCloseTo(30, 0)
    // Past where it sits it stops dead: stretching past the edge is motion of its own.
    await page.mouse.move(at.x, at.y - 60, { steps: 6 })
    expect(await drawnOffset(sheet)).toBeCloseTo(0, 0)

    // Let go short of a dismissal, and it is back where it sits at once.
    await page.mouse.move(at.x, at.y + 40, { steps: 6 })
    await releaseStill(page)
    expect(await drawnOffset(sheet)).toBeCloseTo(0, 0)
    await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
    // Nothing travelled by itself: the only motion the surface had was the pointer's.
    const motion = await recordedMotion(page)
    expect(motion.filter((entry) => entry.includes('transform'))).toEqual([])

    // A drag far enough still dismisses it, by a fade.
    await page.mouse.move(at.x, at.y)
    await page.mouse.down()
    await page.mouse.move(at.x, at.y + 420, { steps: 6 })
    await page.mouse.up()
    await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
  })
})

// KR-REQ-07.21: a stock shell is an explicit choice, and what it does not do is shown before the
// session exists and in the session's status, wherever the session is shown.
test.describe('a new session and its shell', () => {
  test('shows the difference before creation, and a stock shell in the status once it exists', async ({
    page
  }) => {
    const engine = test.info().project.name
    await open(page)
    await page.getByRole('button', { name: 'Sessions' }).click()
    await page.getByRole('button', { name: 'New session' }).click()
    const sheet = page.getByTestId('sheet')
    await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
    const difference = sheet.getByTestId('shell-difference')
    await expect(difference).toHaveAttribute('data-chosen', 'managed')

    await sheet.getByRole('radio', { name: /Stock shell/ }).check()
    await expect(difference).toHaveAttribute('data-chosen', 'native_compat')
    await sheet.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
    await expect(difference).toContainText('Does what the shell does, and can close the session')
    await still(page, 'shell-difference-before-creation-07.21')

    await sheet.getByRole('button', { name: 'Create session' }).click()
    const status = page.getByTestId('shell-mode')
    await expect(status).toContainText('Stock shell')
    await expect(status).toContainText('Ctrl-D can close this session')
    await expect(page.getByTestId('sheet')).toBeHidden({ timeout: PRESENTATION_DEADLINE })
    await still(page, 'shell-status-session-07.21')

    await page.getByTestId('open-settings').click()
    await page.getByRole('button', { name: 'This session' }).click()
    await expect(page.getByTestId('session-shell')).toContainText('Stock shell, /bin/zsh')
    await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', {
      timeout: PRESENTATION_DEADLINE
    })
    await still(page, 'shell-status-settings-07.21')
    await page.keyboard.press('Escape')

    await page.getByRole('button', { name: 'Sessions' }).click()
    await expect(page.getByTestId('session-row-4')).toContainText('Stock shell')
    await expect(page.getByTestId('session-row-1')).not.toContainText('Stock shell')
    await still(page, 'shell-status-list-07.21')
    expect(engine).not.toBe('')
  })
})

// KR-REQ-13.17: a pinch on the phone's terminal scales the text around the point between the
// fingers, as far as they go and back, and settles on a zoom step only when they lift. Two fingers
// are sent through Chromium's own input pipeline, which WebKit's driver has no way to do.
test.describe('the phone terminal under two fingers', () => {
  test.use({ hasTouch: true, viewport: { width: 412, height: 915 } })

  test('scales around the point between the fingers as they spread and come back, and settles on lifting', async ({
    page,
    browserName
  }) => {
    test.skip(browserName !== 'chromium', 'two touches at once are sent through the Chromium protocol')
    await page.goto(`/harness.html?surface=android&session=8a7b6c50-22bb-4c3d-8e4f-000000000101`)
    await page.getByRole('tab', { name: 'Terminal' }).click()
    const line = page.getByTestId('mobile-terminal-line').nth(4)
    await expect(line).toContainText('test result')
    const surface = page.getByTestId('mobile-terminal')
    const box = await surface.boundingBox()
    if (!box) throw new Error('the terminal has no box')
    const between = { x: box.x + box.width / 2, y: box.y + box.height / 2 }
    const session = await page.context().newCDPSession(page)
    const fingers = (spread: number) =>
      [-1, 1].map((side, id) => ({ x: between.x + (side * spread) / 2, y: between.y, id }))
    // Where the line's corner is drawn, once the frame that takes in the last movement is drawn:
    // the engine hands a page its touch movements a frame at a time.
    const glyph = () =>
      line.evaluate(
        (element) =>
          new Promise<{ x: number; y: number }>((resolve) => {
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                const first = element.getBoundingClientRect()
                resolve({ x: first.left, y: first.top })
              })
            })
          })
      )

    const at = await glyph()
    await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: fingers(100) })
    for (const spread of [120, 140, 160, 180, 160, 140]) {
      await session.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: fingers(spread) })
      const factor = spread / 100
      // What was under a point stays under it as the text grows: the line's corner is scaled
      // away from the point between the fingers by exactly the factor they reached.
      const now = await glyph()
      expect(now.x, `across at ${factor}`).toBeCloseTo(between.x + (at.x - between.x) * factor, 0)
      expect(now.y, `down at ${factor}`).toBeCloseTo(between.y + (at.y - between.y) * factor, 0)
    }
    await page.screenshot({ path: shot(`phone-pinch-13.17-${test.info().project.name}`) })
    await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
    // Lifted at 1.4: the step nearest is 150%, and the text is drawn at it with no scale left over.
    await expect(page.getByText('Zoom 150%')).toBeVisible()
    expect(
      await surface.evaluate((element) => (element.firstElementChild as HTMLElement).style.transform)
    ).toBe('')
  })
})

// KR-REQ-13.17: where the platform pans the page to keep a focused field in sight, the shell goes
// with the visual viewport, so what it holds is where the person sees it and nothing is above the
// screen; the page gains nothing to scroll by it.
test.describe("the phone's shell and a page the platform panned", () => {
  for (const surface of ['ios', 'android'] as const) {
    test(`follows the visual viewport by as much as it was panned, on ${surface}`, async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}`)
      await page.locator('.m-shell').waitFor()
      const shell = () =>
        page.locator('.m-shell').evaluate((element) => {
          const box = element.getBoundingClientRect()
          return { top: box.top, height: box.height, scroll: document.documentElement.scrollHeight }
        })
      const at = await shell()
      expect(at.top).toBe(0)
      await page.evaluate(() => {
        document.documentElement.style.setProperty('--pan', '200px')
      })
      const panned = await shell()
      expect(panned.top, 'the shell goes down with the visual viewport').toBe(200)
      expect(panned.height, 'and keeps its height').toBe(at.height)
      expect(panned.scroll, 'the page gains nothing to scroll').toBeLessThanOrEqual(Math.max(at.scroll, 844))
    })
  }
})

// KR-REQ-13.17: a session that cannot be shown whole above a software keyboard scrolls, and the
// field being typed into is always above the keyboard and wholly in view, where the platform
// panned the page to it and the shell went with the visual viewport. Each case is a keyboard and a
// pan as a platform reported them, through the visual viewport the page reads them from: the first
// focus and a later one at a person's own text size on a phone's width, a phone on its side, and
// the sizes where the session fits whole.
test.describe("the phone's field above a keyboard the platform panned the page for", () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
  const CASES: readonly { readonly seen: Seen; readonly keyboard: number; readonly pan: number; readonly fits: boolean }[] = [
    { seen: { width: 320, height: 658, scale: '200%' }, keyboard: 399, pan: 297, fits: false },
    { seen: { width: 320, height: 658, scale: '200%' }, keyboard: 259, pan: 227, fits: false },
    { seen: { width: 844, height: 390, scale: '100%' }, keyboard: 210, pan: 90, fits: false },
    { seen: { width: 390, height: 844, scale: '100%' }, keyboard: 336, pan: 0, fits: true },
    { seen: { width: 390, height: 844, scale: '100%' }, keyboard: 312, pan: 241, fits: true }
  ]

  /**
   * Where the shell's scrolling area is once nothing moves it any more: the platform may scroll it a
   * frame or two after a field takes the focus, and what the session does is measured from there.
   */
  async function settledScroll(page: Page): Promise<number> {
    let last = -1
    let steady = 0
    for (let tries = 0; tries < 40 && steady < 3; tries += 1) {
      await page.waitForTimeout(60)
      const now = await page.evaluate(() => document.querySelector('.m-main')?.scrollTop ?? -1)
      steady = now === last ? steady + 1 : 0
      last = now
    }
    return last
  }

  /**
   * How many animation frames in a row nothing about the field's layout may change before the page
   * has finished answering a keyboard. It counts frames and not time: what a frame costs is the
   * machine's answer, and a page that answers in steps needs frames to take them.
   */
  const STEADY_FRAMES = 10

  /**
   * What the person sees of the field once the page has finished answering the keyboard, and what is
   * wrong with it while it has not.
   *
   * The page answers a keyboard in steps. It places the field at once, and what that moves is worked
   * out again in the frames after, until nothing has changed for a moment: the field can rest on the
   * keyboard's edge, whole, in the first reading, then be above the edge and cut by the box around
   * it in the next frame, and under the keyboard in the one after. A reading taken between steps
   * says which step it caught, and two readings taken one after the other can each catch another. So
   * the rest and the view of the field are read from one frame, and only once the layout has not
   * moved through `STEADY_FRAMES` frames in a row; a field that is not whole or does not rest by
   * then is said in words, and the wait for it is bounded as the other layout waits are.
   */
  async function settledField(page: Page, onTheEdge: boolean, state = 'the keyboard'): Promise<void> {
    await expect
      .poll(
        () =>
          page.evaluate(
            ([steadyFrames, mustRestOnTheEdge]) =>
              new Promise<string>((resolve) => {
                let key = ''
                let steady = 0
                let frames = 0
                const look = () => {
                  const field = document.querySelector('textarea[id^="composer-"]')
                  const shell = document.querySelector('.m-shell')
                  if (field === null || shell === null) return { said: 'no field', key: 'none' }
                  const box = field.getBoundingClientRect()
                  const shellBox = shell.getBoundingClientRect()
                  const covered =
                    parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--keyboard')) || 0
                  // How far the field runs outside what a person sees of it: outside any box around
                  // it that clips what it holds, as `hiddenPart` reads it.
                  let top = 0
                  let bottom = window.innerHeight
                  const areas: number[] = []
                  for (let around = field.parentElement; around !== null; around = around.parentElement) {
                    const style = getComputedStyle(around)
                    if (style.overflowY === 'visible' && style.overflowX === 'visible') continue
                    const clip = around.getBoundingClientRect()
                    top = Math.max(top, clip.top)
                    bottom = Math.min(bottom, clip.bottom)
                    areas.push(clip.top, clip.bottom, around.scrollTop)
                  }
                  const hidden = Math.max(0, top - box.top) + Math.max(0, box.bottom - bottom)
                  const off = Math.round(box.bottom - (shellBox.bottom - covered))
                  // Under the terminal the field is the foot of the session and rests on the
                  // keyboard's edge. Under the conversation, in a session that fits whole, the
                  // pickers lie under the field and it is above the edge by their height, as it
                  // always was.
                  const rests = mustRestOnTheEdge ? Math.abs(off) <= 1 : off <= 1
                  const said = !rests
                    ? off > 0
                      ? `${off} px under the keyboard`
                      : `${-off} px above the keyboard`
                    : hidden > 1
                      ? `${Math.round(hidden * 10) / 10} px of the field is clipped`
                      : box.bottom <= shellBox.top
                        ? 'the field is above the top of what the person sees'
                        : 'where it rests'
                  const moved = [box.top, box.bottom, shellBox.top, shellBox.bottom, covered, ...areas]
                  return { said, key: moved.map((value) => Math.round(value * 10) / 10).join(',') }
                }
                const step = () => {
                  const now = look()
                  steady = now.key === key ? steady + 1 : 1
                  key = now.key
                  if (steady >= steadyFrames) return resolve(now.said === 'where it rests' ? 'settled' : now.said)
                  frames += 1
                  // A page still moving after a good many frames is looked at again by the wait.
                  if (frames >= 600) return resolve(`still moving: ${now.said}`)
                  requestAnimationFrame(step)
                }
                requestAnimationFrame(step)
              }),
            [STEADY_FRAMES, onTheEdge] as const
          ),
        {
          timeout: PRESENTATION_DEADLINE,
          message: `the field rests where it should, whole in view, once the layout is steady under ${state}`
        }
      )
      .toBe('settled')
  }

  /**
   * Replaces the visual viewport with one the test moves, as a platform does: a keyboard takes
   * `covered` pixels of the height and the page is panned `panned` pixels, and the page measures
   * both from it, as it does from a real one.
   */
  async function withViewport(page: Page): Promise<(covered: number, panned: number) => Promise<void>> {
    await page.addInitScript(() => {
      class Moved extends EventTarget {
        covered = 0
        offsetTop = 0
        readonly scale = 1
        get height(): number {
          return window.innerHeight - this.covered
        }
      }
      const fake = new Moved()
      Object.defineProperty(window, 'visualViewport', { configurable: true, value: fake })
      ;(window as unknown as { krMoveViewport: (covered: number, panned: number) => void }).krMoveViewport = (
        covered,
        panned
      ) => {
        fake.covered = covered
        fake.offsetTop = panned
        fake.dispatchEvent(new Event('resize'))
        fake.dispatchEvent(new Event('scroll'))
      }
    })
    return (covered, panned) =>
      page.evaluate(
        ([k, p]) =>
          (window as unknown as { krMoveViewport: (covered: number, panned: number) => void }).krMoveViewport(
            k,
            p
          ),
        [covered, panned]
      )
  }

  for (const surface of ['ios', 'android'] as const) {
    for (const pane of ['conversation', 'terminal'] as const) {
      for (const each of CASES) {
        const { seen, keyboard, pan } = each
        test(`${surface}, ${pane}, ${seen.width}×${seen.height} at ${seen.scale} text, keyboard ${keyboard}px, panned ${pan}px`, async ({
          page
        }) => {
          const move = await withViewport(page)
          await onPhone(page, surface, seen, `&session=${SESSION}`)
          if (pane === 'terminal') {
            await page.getByRole('tab', { name: 'Terminal' }).click()
            await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
          }
          const field = page.locator('textarea[id^="composer-"]')
          await field.focus()
          await move(keyboard, pan)
          // What the person sees: from the top of the visual viewport, which the shell goes with, to
          // where the keyboard begins at the shell's foot. Under the terminal the field is the foot of
          // the session and rests on the keyboard's edge; under the conversation, in a session that
          // fits whole, the pickers lie under the field and it is above the edge by their height; in
          // one that does not, the session is scrolled until the composer's field is on the edge.
          // Whole in view means no box around it (the composer's own scrolling area, the session's,
          // the shell) clips any of it, which its rectangle alone does not say.
          await settledField(page, pane === 'terminal' || !each.fits)
        })
      }
    }
  }

  for (const surface of ['ios', 'android'] as const) {
    test(`follows a keyboard that changes its height and goes, on ${surface}, and leaves the session where it was`, async ({
      page
    }) => {
      const move = await withViewport(page)
      await onPhone(page, surface, { width: 320, height: 658, scale: '200%' }, `&session=${SESSION}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      const field = page.locator('textarea[id^="composer-"]')
      await field.focus()
      const scrolled = () => page.evaluate(() => document.querySelector('.m-main')?.scrollTop ?? -1)
      const before = await settledScroll(page)
      // A keyboard first as tall as it is while it announces itself, with the page panned, and then
      // as tall as it stays, with the pan gone: the field is on its edge each time, never short of
      // it by what the first state needed.
      for (const [covered, panned] of [[399, 297], [259, 0], [312, 241], [259, 227]] as const) {
        await move(covered, panned)
        await settledField(page, true, `a keyboard of ${covered}px, panned ${panned}px`)
      }
      await field.blur()
      await move(0, 0)
      await expect.poll(scrolled, { message: 'the session is where it was before the keyboard' }).toBe(before)
    })

    test(`keeps the field whole in view when the keyboard becomes shorter than the bar under the session, on ${surface}`, async ({
      page
    }) => {
      const move = await withViewport(page)
      await onPhone(page, surface, { width: 320, height: 658, scale: '200%' }, `&session=${SESSION}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      const field = page.locator('textarea[id^="composer-"]')
      await field.focus()
      // A tall keyboard scrolls the session to its field. Then only a suggestion bar is left, which
      // is shorter than the tab bar under the session: the field is then above the keyboard where it
      // lies, and is not scrolled back to a place below the room the session has.
      await move(399, 297)
      await expect.poll(() => page.evaluate(() => document.querySelector('.m-main')?.scrollTop ?? 0)).toBeGreaterThan(0)
      await move(48, 0)
      await settledField(page, false, 'a keyboard of 48px')
    })

    test(`leaves the shell's scrolling area where it was when the person leaves the session with the keyboard up, on ${surface}`, async ({
      page
    }) => {
      const move = await withViewport(page)
      await onPhone(page, surface, { width: 320, height: 658, scale: '200%' }, `&session=${SESSION}`)
      await page.getByRole('tab', { name: 'Terminal' }).click()
      await expect(page.getByTestId('mobile-terminal-line').first()).toContainText('$ cargo')
      await page.locator('textarea[id^="composer-"]').focus()
      const scrolled = () => page.evaluate(() => document.querySelector('.m-main')?.scrollTop ?? -1)
      // Where the platform left the area when the field took the focus: the session's own scrolling
      // is measured from there.
      const before = await settledScroll(page)
      await move(399, 297)
      await expect.poll(scrolled, { message: 'the session scrolled to its field' }).toBeGreaterThan(before)
      // Let the session settle on its field, so what is put back is the whole of what it did.
      await settledField(page, true, 'a keyboard of 399px, panned 297px')
      // Away from the session while the keyboard is still up: what the destination opens on is not
      // scrolled by what the session did. The tab bar is under the keyboard, so the tab is pressed
      // as a pointer would press it, not scrolled to.
      await page.getByRole('button', { name: 'Attention' }).dispatchEvent('click')
      await expect(page.locator('.m-session')).toHaveCount(0)
      expect(
        await page.evaluate(() => {
          const main = document.querySelector('.m-main')
          return main ? main.scrollHeight - main.clientHeight : -1
        }),
        'the destination holds more than it shows, so it can keep a position'
      ).toBeGreaterThan(before)
      // No further down than the session was before it scrolled to its field: its own scrolling is
      // not carried into the next view.
      await expect.poll(scrolled, { message: 'the destination opens where it would have' }).toBeLessThanOrEqual(before)
    })
  }
})

// KR-REQ-13.09: the phone's settings open over a live session and leave it behind them, whole at a
// person's own text size: the bar's controls, the sheet's edges and each appearance choice.
test.describe("the phone's settings over a live session", () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
  const SIZES: readonly Seen[] = [
    { width: 390, height: 844, scale: '100%' },
    { width: 320, height: 720, scale: '200%' }
  ]

  for (const surface of ['ios', 'android'] as const) {
    for (const seen of SIZES) {
      test(`open over the session, whole, on ${surface} at ${seen.width}×${seen.height} with text at ${seen.scale}`, async ({
        page
      }) => {
        await onPhone(page, surface, seen, `&session=${SESSION}`)
        const field = page.getByLabel('Message this session')
        await field.fill('a draft the sheet leaves alone')
        const settings = page.getByRole('button', { name: 'Settings' })
        const target = surface === 'ios' ? 44 : 48
        const bar = await page.locator('.m-topbar').evaluate((header) => {
          const box = (element: Element | null) => {
            const rect = element?.getBoundingClientRect()
            return rect ? { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom } : null
          }
          return {
            title: box(header.querySelector('h1')),
            settings: box(header.querySelector('[aria-label="Settings"]')),
            back: box(header.querySelector('[aria-label="Back to sessions"]')),
            headerRight: header.getBoundingClientRect().right
          }
        })
        expect(bar.settings, 'the bar has settings').not.toBeNull()
        if (bar.settings === null || bar.title === null) return
        expect(bar.settings.right - bar.settings.left, 'settings target width').toBeGreaterThanOrEqual(target - 0.5)
        expect(bar.settings.bottom - bar.settings.top, 'settings target height').toBeGreaterThanOrEqual(target - 0.5)
        expect(bar.settings.right, 'settings stays on the screen').toBeLessThanOrEqual(seen.width + 0.5)
        expect(bar.title.right, 'the title is clear of settings').toBeLessThanOrEqual(bar.settings.left + 0.5)
        if (bar.back !== null) expect(bar.back.right, 'the title is clear of back').toBeLessThanOrEqual(bar.title.left + 0.5)

        await settings.click()
        const sheet = page.getByTestId('sheet')
        await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
        const shown = await sheet.evaluate((element) => {
          const rect = element.getBoundingClientRect()
          const body = element.querySelector<HTMLElement>('.dialog-body')
          const cards = Array.from(element.querySelectorAll<HTMLElement>('.theme-option')).map((card) => {
            const box = card.getBoundingClientRect()
            const caption = card.querySelector<HTMLElement>('.theme-caption')
            return {
              left: box.left,
              right: box.right,
              cut: caption === null ? Infinity : caption.scrollWidth - caption.clientWidth
            }
          })
          return {
            left: rect.left,
            right: rect.right,
            bottom: rect.bottom,
            sideways: body === null ? Infinity : body.scrollWidth - body.clientWidth,
            bodyLeft: body?.getBoundingClientRect().left ?? 0,
            bodyRight: body?.getBoundingClientRect().right ?? 0,
            cards
          }
        })
        expect(shown.left, 'the sheet starts on the screen').toBeGreaterThanOrEqual(-0.5)
        expect(shown.right, 'the sheet ends on the screen').toBeLessThanOrEqual(seen.width + 0.5)
        expect(shown.bottom, 'the sheet rests on the bottom edge').toBeCloseTo(seen.height, 0)
        expect(shown.sideways, 'nothing in the sheet runs sideways').toBeLessThanOrEqual(1)
        expect(shown.cards).toHaveLength(3)
        for (const card of shown.cards) {
          expect(card.left, 'each choice starts inside the sheet').toBeGreaterThanOrEqual(shown.bodyLeft - 0.5)
          expect(card.right, 'each choice ends inside the sheet').toBeLessThanOrEqual(shown.bodyRight + 0.5)
          expect(card.cut, 'each choice names itself whole').toBeLessThanOrEqual(1)
        }
        // The session is behind the sheet, with its draft.
        await expect(field).toHaveValue('a draft the sheet leaves alone')
        await still(page, `settings-13.09-${surface}-${seen.width}x${seen.height}-${seen.scale.replace('%', '')}`)
      })
    }

    test(`rest clear of the bottom safe area on ${surface}`, async ({ page }) => {
      await onPhone(page, surface, { width: 390, height: 844, scale: '100%' }, `&session=${SESSION}`)
      // A home indicator or a gesture bar 34 px high, as the platform reports it.
      await page.evaluate(() => {
        document.documentElement.style.setProperty('--safe-bottom', '34px')
      })
      await page.getByRole('button', { name: 'Settings' }).click()
      await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', {
        timeout: PRESENTATION_DEADLINE
      })
      const clear = await page.getByTestId('sheet').evaluate((sheet) => {
        const last = Array.from(sheet.querySelectorAll<HTMLElement>('.theme-caption')).at(-1)
        return last === undefined ? null : sheet.getBoundingClientRect().bottom - last.getBoundingClientRect().bottom
      })
      expect(clear, 'the last choice is above the indicator').not.toBeNull()
      expect(clear ?? 0).toBeGreaterThanOrEqual(34)
    })

    test(`close by the system's back first, and leave the session by the next, on ${surface}`, async ({
      page
    }) => {
      await onPhone(page, surface, { width: 390, height: 844, scale: '100%' }, `&session=${SESSION}`)
      await page.getByRole('button', { name: 'Settings' }).click()
      await expect(page.getByTestId('sheet')).toHaveAttribute('data-presentation', 'here', {
        timeout: PRESENTATION_DEADLINE
      })
      await page.evaluate(() => {
        window.history.back()
      })
      await expect(page.getByTestId('sheet')).toBeHidden({ timeout: PRESENTATION_DEADLINE })
      await expect(page.getByLabel('Message this session')).toBeVisible()
      await page.evaluate(() => {
        window.history.back()
      })
      await expect(page.getByLabel('Message this session')).toHaveCount(0)
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Sessions')
    })
  }
})

// KR-REQ-13.19: the inbox's rows stay inside the screen at a person's own text size, and the count
// on the Attention tab is a circle that holds its digits at any size. At the base text size neither
// moves.
test.describe("the phone's inbox and tab count at a person's own text size", () => {
  const SIZES: readonly Seen[] = [
    { width: 320, height: 720, scale: '200%' },
    { width: 320, height: 720, scale: '150%' },
    { width: 320, height: 720, scale: '100%' },
    { width: 390, height: 844, scale: '200%' },
    { width: 390, height: 844, scale: '100%' }
  ]

  for (const surface of ['ios', 'android'] as const) {
    for (const seen of SIZES) {
      test(`keeps every row inside the screen on ${surface} at ${seen.width}×${seen.height} with text at ${seen.scale}`, async ({
        page
      }) => {
        await onPhone(page, surface, seen)
        await page.locator('.m-row').first().waitFor()
        const placed = await page.evaluate(() => {
          const main = document.querySelector<HTMLElement>('.m-main')
          if (main === null) throw new Error('the shell has no main area')
          const style = getComputedStyle(main)
          const frame = main.getBoundingClientRect()
          const left = frame.left + parseFloat(style.paddingLeft)
          const right = frame.right - parseFloat(style.paddingRight)
          const rows = Array.from(document.querySelectorAll<HTMLElement>('.m-row')).map((row) => {
            const box = row.getBoundingClientRect()
            return { left: box.left, right: box.right }
          })
          // Anything else in the main area that ends past the screen, but the filters, which scroll
          // along their own strip.
          const outside = Array.from(main.querySelectorAll<HTMLElement>('*'))
            .filter((element) => element.closest('.m-filters') === null)
            .filter((element) => element.getBoundingClientRect().right > window.innerWidth + 0.5)
            .map((element) => `${element.tagName.toLowerCase()}.${String(element.className)}`)
          return { left, right, rows, outside, sideways: main.scrollWidth - main.clientWidth }
        })
        expect(placed.rows.length).toBeGreaterThan(0)
        expect(placed.sideways, 'nothing makes the main area scroll sideways').toBeLessThanOrEqual(1)
        expect(placed.outside, 'nothing ends past the screen').toEqual([])
        for (const [index, row] of placed.rows.entries()) {
          expect(row.left, `row ${index} starts inside the gutter`).toBeGreaterThanOrEqual(placed.left - 0.5)
          expect(row.right, `row ${index} ends inside the gutter`).toBeLessThanOrEqual(placed.right + 0.5)
          // A row takes the whole width there is.
          expect(row.right - row.left, `row ${index} takes the whole width`).toBeCloseTo(placed.right - placed.left, 0)
        }
        await still(page, `inbox-13.19-${surface}-${seen.width}x${seen.height}-${seen.scale.replace('%', '')}`)
      })

      test(`holds the count's digits in its circle on ${surface} at ${seen.width}×${seen.height} with text at ${seen.scale}`, async ({
        page
      }) => {
        await onPhone(page, surface, seen)
        const badge = page.locator('.m-tab-badge')
        await expect(badge).toBeVisible()
        for (const count of [null, '99+']) {
          const measured = await badge.evaluate((element, text) => {
            if (text !== null) element.textContent = text
            const box = element.getBoundingClientRect()
            const range = document.createRange()
            range.selectNodeContents(element)
            const digits = range.getBoundingClientRect()
            const style = getComputedStyle(element)
            return {
              width: box.width,
              height: box.height,
              digitsWidth: digits.width,
              digitsHeight: digits.height,
              padding: parseFloat(style.paddingLeft),
              root: parseFloat(getComputedStyle(document.documentElement).fontSize)
            }
          }, count)
          const label = `${count ?? 'the count'}`
          expect(measured.height, `${label}: the circle is as tall as its digits`).toBeGreaterThanOrEqual(measured.digitsHeight - 0.5)
          expect(measured.width, `${label}: the circle is as wide as its digits and their room`).toBeGreaterThanOrEqual(
            measured.digitsWidth + 2 * measured.padding - 0.5
          )
          expect(measured.width, `${label}: it is a circle or a pill, never narrower than tall`).toBeGreaterThanOrEqual(measured.height - 0.5)
          if (count === null && seen.scale === '100%') {
            // At the base text size the circle is what it was.
            expect(measured.width).toBeCloseTo(17, 0)
            expect(measured.height).toBeCloseTo(17, 0)
          }
        }
      })
    }
  }
})

test.describe('the harness control strip', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  test("the harness strip's reset leaves no draft behind once the page has been reloaded", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(`/harness.html?surface=ios&session=${SESSION}`)
    const field = page.getByLabel('Message this session')
    await field.fill('a draft the reset must remove')
    await expect(field).toHaveValue('a draft the reset must remove')
    // The page writes what it holds as it goes, so a reset that only cleared the store would be undone.
    await page.locator('#kr-strip-toggle').click()
    await Promise.all([page.waitForEvent('load'), page.locator('#kr-strip-reset').click()])
    await expect(page.getByLabel('Message this session')).toHaveValue('')
    // The reset is done once: what is typed after it is kept across another reload.
    await page.getByLabel('Message this session').fill('a draft written after')
    await page.reload()
    await expect(page.getByLabel('Message this session')).toHaveValue('a draft written after')
  })
})
