/**
 * Which sessions the page asks the host to describe, in a real engine with a real layout.
 *
 * A list longer than a screen asks about the rows a person can see and a margin beyond them, and
 * about the rest as they are scrolled to. What a component test cannot hold, because jsdom has no
 * layout, is that the rows asked about are the rows on the screen.
 */

import { expect, test, type Page } from '@playwright/test'

/** The margin the page allows beyond the screen's edge, and a little for a pixel rounded either way. */
const MARGIN = 160
const ROUNDING = 4

/** What the page has asked the host about, and the rows by how near the screen they are. */
interface Asked {
  readonly asked: readonly string[]
  /** Every row the list shows. */
  readonly all: readonly string[]
  /** The rows that touch the screen, or the box of what scrolls them. */
  readonly shown: readonly string[]
  /** The rows within the margin of it, with the allowance for rounding. */
  readonly near: readonly string[]
}

async function whatWasAsked(page: Page): Promise<Asked> {
  return await page.evaluate(
    ([margin, rounding]) => {
      const rows = [...document.querySelectorAll<HTMLElement>('[data-session]')]
      let box = { top: 0, bottom: window.innerHeight }
      for (let node = rows[0]?.parentElement ?? null; node !== null; node = node.parentElement) {
        const { overflowY } = getComputedStyle(node)
        if (overflowY === 'auto' || overflowY === 'scroll') {
          const rect = node.getBoundingClientRect()
          box = { top: rect.top, bottom: rect.bottom }
          break
        }
      }
      const within = (row: HTMLElement, by: number): boolean => {
        const rect = row.getBoundingClientRect()
        return rect.bottom >= box.top - by && rect.top <= box.bottom + by
      }
      const ids = (rows_: HTMLElement[]): string[] => rows_.map((row) => row.dataset.session ?? '')
      return {
        asked: [...(window.krTestHost?.described ?? [])],
        all: ids(rows),
        shown: ids(rows.filter((row) => within(row, 0))),
        near: ids(rows.filter((row) => within(row, margin + rounding)))
      }
    },
    [MARGIN, ROUNDING] as const
  )
}

/** Waits until every row on the screen has been asked about, then says what was asked. */
async function afterTheScreenIsRead(page: Page): Promise<Asked> {
  await expect
    .poll(async () => {
      const now = await whatWasAsked(page)
      return now.shown.every((id) => now.asked.includes(id))
    })
    .toBe(true)
  return await whatWasAsked(page)
}

/** Holds what a person scrolling sees: only rows near the screen were asked about, each once. */
function expectOnlyWhatIsNear(now: Asked): void {
  expect(now.all.length, 'a list longer than the screen').toBeGreaterThan(now.near.length)
  expect(now.asked.length, 'each session is asked about once').toBe(new Set(now.asked).size)
  for (const id of now.asked) expect(now.near, 'a row far from the screen was asked about').toContain(id)
}

// KR-REQ-13.10: the rows ask the host for the sessions on the screen, and a small margin, and
// not for every session listed.
test.describe('the session rows ask the host about what is on the screen', () => {
  for (const surface of ['ios', 'android'] as const) {
    test(`on the phone's list, ${surface}, and the rest as it is scrolled`, async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions&sessions=40`)
      await expect(page.locator('[data-session]').first()).toBeVisible()

      const first = await afterTheScreenIsRead(page)
      expectOnlyWhatIsNear(first)

      // Scrolled to the end, the last row is asked about, and every row asked about still once.
      await page.locator('.m-main').evaluate((main) => {
        main.scrollTop = main.scrollHeight
      })
      const last = await page.locator('[data-session]').last().getAttribute('data-session')
      await expect
        .poll(async () => (await whatWasAsked(page)).asked.includes(last ?? ''))
        .toBe(true)
      const scrolled = await whatWasAsked(page)
      expect(scrolled.asked.length).toBe(new Set(scrolled.asked).size)
      expect(scrolled.asked.length, 'the rows between were not asked about').toBeLessThan(scrolled.all.length)
    })
  }

  test('on the desktop list, and about every session once a search is made', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 })
    await page.goto('/harness.html?sessions=40')
    await page.getByRole('button', { name: 'Sessions' }).click()
    await expect(page.locator('[data-session]').first()).toBeVisible()

    const first = await afterTheScreenIsRead(page)
    expectOnlyWhatIsNear(first)

    // A search looks at the title of each session, so each is asked about.
    await page.getByRole('searchbox').fill('project')
    await expect
      .poll(async () => {
        const now = await whatWasAsked(page)
        return now.all.every((id) => now.asked.includes(id))
      })
      .toBe(true)
    const searched = await whatWasAsked(page)
    expect(searched.asked.length, 'each session is asked about once').toBe(new Set(searched.asked).size)
  })

  // The host's own words can be one long word, and the desktop's first column is not wide: the
  // title and the line break where the column ends, and do not run over the directory beside it.
  test('on the desktop list, a long word in what the host says stays in its column', async ({ page }) => {
    await page.addInitScript(() => {
      let held: Window['krTestHost']
      Object.defineProperty(window, 'krTestHost', {
        configurable: true,
        get: () => held,
        set: (controls: Window['krTestHost']) => {
          held = controls
          controls?.describe('8a7b6c50-22bb-4c3d-8e4f-000000000101', {
            title: 'Pairing-code-entry-and-host-approval-flow-for-a-narrow-column',
            source: 'generated',
            activity_text: 'Checks/the/code-entry/flow/and/host/approval/screen/on/a/narrow/phone',
            freshness: 'current'
          })
        }
      })
    })
    await page.setViewportSize({ width: 1100, height: 800 })
    await page.goto('/harness.html')
    await page.getByRole('button', { name: 'Sessions' }).click()
    const row = page.getByTestId('session-row-1')
    await expect(row.getByTestId('description-activity')).toBeVisible()
    const over = await row.evaluate((element) => {
      const cell = element.querySelector('[role="cell"]')?.getBoundingClientRect()
      if (cell === undefined) return ['no first cell']
      return [...element.querySelectorAll('h3, [data-testid="description-activity"]')]
        .filter((line) => line.getBoundingClientRect().right > cell.right + 0.5)
        .map((line) => line.textContent?.slice(0, 40) ?? '')
    })
    expect(over, 'lines that run past the first column').toEqual([])
  })
})

// KR-REQ-13.10: the session's own header names it as the list does, and what the host says can be
// one long word.
test("in a session's header, a long generated title and its label stay inside the window", async ({
  page
}) => {
  await page.addInitScript(() => {
    let held: Window['krTestHost']
    Object.defineProperty(window, 'krTestHost', {
      configurable: true,
      get: () => held,
      set: (controls: Window['krTestHost']) => {
        held = controls
        controls?.describe('8a7b6c50-22bb-4c3d-8e4f-000000000101', {
          title: 'Pairingcodeentryandhostapprovalflowforanarrowcolumnonaphone',
          source: 'generated',
          freshness: 'current'
        })
      }
    })
  })
  await page.setViewportSize({ width: 1100, height: 800 })
  await page.goto('/harness.html')
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
  await page.setViewportSize({ width: 320, height: 720 })

  const header = page.locator('.session-header')
  await expect(header.getByTestId('description-source')).toBeVisible()
  const over = await header.evaluate((element) => {
    const window_ = document.documentElement.clientWidth
    const title = element.querySelector('h1')
    return {
      page: document.documentElement.scrollWidth - window_,
      title: title === null ? Number.POSITIVE_INFINITY : title.scrollWidth - title.clientWidth,
      past: [...element.querySelectorAll('h1, [data-testid="description-source"]')]
        .filter((line) => {
          const box = line.getBoundingClientRect()
          return box.right > window_ + 0.5 || box.left < -0.5
        })
        .map((line) => line.textContent?.slice(0, 40) ?? '')
    }
  })
  expect(over.page, 'the page runs wider than the window').toBeLessThanOrEqual(1)
  expect(over.title, 'the title runs past its own box').toBeLessThanOrEqual(1)
  expect(over.past, 'the title or its label runs past the window').toEqual([])
})
