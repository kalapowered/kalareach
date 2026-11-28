/**
 * The lines that say which host holds an archive back, in a real browser engine: the three
 * sentences with the way that exists beneath each, a long host name that wraps and is never cut, and
 * a mark that a line breaks between its groups and never inside one. Each case runs at a phone's
 * width and a desktop's, at the ordinary text size and the largest, in the light colour scheme and
 * the dark. The backend is the scripted host the harness serves.
 *
 * The recovery section is the desktop shell's, and a window as narrow as a phone's has no sidebar, so
 * the narrow cases open the account sheet at the desktop's width and then narrow the window. The text
 * size is the factor the system gives the page, set before the page loads, and the face is as wide
 * as the Linux runner draws with, so that a layout that holds here holds there.
 *
 * Every screenshot goes under the test artefact directory, named for the case and the engine.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { brokenWords, overrunning } from './layout'

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  mark: 'ab'.repeat(32),
  outcome: null
} as const

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const MARK = '3fa9-1c07-b2e4-77ab'

const LONG_NAME =
  'studio-kitchen-workstation-with-a-very-long-name-that-has-to-wrap-and-must-never-be-cut'

/** The archives of the case: one of each sentence, a bundle's own hold, and one that is offered. */
const ARCHIVES = [
  {
    archive_id: '1a2b3c4d-0000-4000-8000-000000000001',
    generation: null,
    published_at_ms: null,
    withheld: 'held_back',
    held_generation: '3',
    checkpoint_generation: '18446744073709551615',
    host: { mark: MARK, name: LONG_NAME, listed: true }
  },
  {
    archive_id: '1a2b3c4d-0000-4000-8000-000000000002',
    generation: null,
    published_at_ms: null,
    withheld: 'disagree',
    held_generation: null,
    checkpoint_generation: '9',
    host: { mark: '77bc-db3b-2424-b1f2', name: null, listed: true }
  },
  {
    archive_id: '1a2b3c4d-0000-4000-8000-000000000003',
    generation: null,
    published_at_ms: null,
    withheld: 'host_contradicts',
    held_generation: null,
    checkpoint_generation: '9',
    host: { mark: '4885-5ba2-e7cf-e3f2', name: null, listed: false }
  },
  {
    archive_id: '1a2b3c4d-0000-4000-8000-000000000004',
    generation: null,
    published_at_ms: null,
    withheld: 'held_back',
    held_generation: '4',
    checkpoint_generation: '6',
    host: null
  },
  {
    archive_id: '1a2b3c4d-0000-4000-8000-000000000005',
    generation: '5',
    published_at_ms: Date.UTC(2026, 9, 12),
    withheld: null,
    held_generation: null,
    checkpoint_generation: null,
    host: null
  }
] as const

function shot(name: string): string {
  return screenshotPath(`kr-companion-recovery-host-${name}-${test.info().project.name}`)
}

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
 * Sets the page's face to one as wide as the Linux runner draws with, from the page's first frame:
 * DejaVu Sans sets the same text about a tenth wider across a line than a phone's or a Mac's face.
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

/** Lets every animation of the page settle before a measure or a picture. */
async function settled(page: Page): Promise<void> {
  await page.evaluate(() =>
    Promise.all(document.getAnimations().map((each) => each.finished.catch(() => undefined)))
  )
}

/** Sets the window as tall as the element is, so that a picture shows the whole of it. */
async function tallEnoughFor(page: Page, element: Locator): Promise<void> {
  const view = page.viewportSize()
  const height = await element.evaluate((each) => each.getBoundingClientRect().height)
  if (view !== null) {
    await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
    await settled(page)
  }
}

/**
 * Opens the harness signed in with recovery on and the archives above, opens the account sheet and
 * lists the offline copies, then sets the window to `width`. The recovery section belongs to the desktop
 * shell, whose sidebar, and so its way to the account, goes at a window as narrow as a phone's: the
 * sheet is opened at the desktop's width and the window is narrowed with the sheet open.
 */
async function atTheCopies(page: Page, width: number, largest: boolean, scheme: 'light' | 'dark') {
  await withWideFace(page)
  if (largest) await withSystemTextScale(page, LARGEST)
  await page.setViewportSize({ width: 1280, height: 900 })
  await page.emulateMedia({ colorScheme: scheme })
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.evaluate(
    ([account, archives]) => {
      window.krTestHost?.account.set(account)
      window.krTestHost?.recovery.set({ state: 'on', kept_at: 'reach.kala.to' })
      window.krTestHost?.recovery.setArchives(archives)
    },
    [SIGNED_IN, ARCHIVES] as const
  )
  await page.getByRole('button', { name: /^Account/ }).click()
  const sheet = page.getByRole('dialog', { name: 'Account' })
  await sheet.getByTestId('recovery-export-offline').click()
  const copies = sheet.getByTestId('recovery-copies')
  await expect(copies).toBeVisible()
  if (width !== 1280) await page.setViewportSize({ width, height: 900 })
  await settled(page)
  return { sheet, copies }
}

for (const width of [390, 1280]) {
  for (const largest of [false, true]) {
    for (const scheme of ['light', 'dark'] as const) {
      const size = largest ? 'largest' : 'default'
      test(`says which host holds an archive back at ${width}px, ${size} text, ${scheme}`, async ({
        page
      }) => {
        const { sheet, copies } = await atTheCopies(page, width, largest, scheme)

        // The picture is taken first, so that a case that fails leaves it behind.
        await tallEnoughFor(page, copies)
        // At a device scale of 2 this list passes WebKit's 32,767-pixel picture limit: take it at the CSS scale.
        await copies.screenshot({ path: shot(`${width}-${size}-${scheme}`), scale: 'css' })

        // The sentences are there, with the way beneath each of the three that a host causes.
        await expect(copies).toContainText(
          `the service offers generation 3, but ${LONG_NAME} (mark ${MARK}) reported generation 18446744073709551615`
        )
        await expect(copies).toContainText('reported another backup as generation 9')
        await expect(copies).toContainText('a host that this device no longer lists')
        await expect(copies.locator('.archive-way')).toHaveCount(3)

        // No line gives a reason it must not: no second claimant, no advice to forget a host.
        await expect(copies).not.toContainText(
          /two claimants|second host that reports|forget|has lost/i
        )

        // Nothing is drawn past the screen, and no word that would fit the line it is on is cut by
        // one. The check runs on each line and each way, not on the list: a button stands beside the
        // text, so the text's column is narrower than the list, and a figure of twenty digits may
        // break inside a column that is narrower than it is.
        expect(await overrunning(page, '[data-testid="recovery-copies"]')).toEqual([])
        expect(
          await brokenWords(
            page,
            '[data-testid="recovery-copies"] .account-lead, [data-testid="recovery-copies"] .archive-way'
          )
        ).toEqual([])

        // A mark breaks between its groups and never inside one: each group is on one line.
        const groups = await copies.locator('.host-mark-group').evaluateAll((nodes) =>
          nodes.map((node) => ({
            text: node.textContent,
            lines: new Set([...node.getClientRects()].map((rect) => Math.round(rect.top))).size
          }))
        )
        expect(groups.length).toBeGreaterThanOrEqual(12)
        for (const group of groups) {
          expect(group.text).toMatch(/^[0-9a-f]{4}$/)
          expect(group.lines).toBe(1)
        }

        // The long name wraps inside the line and is never cut: the line ends inside the list.
        const line = copies.locator('.account-lead').first()
        const box = await line.boundingBox()
        const list = await copies.boundingBox()
        expect(box).not.toBeNull()
        expect(list).not.toBeNull()
        if (box !== null && list !== null) {
          expect(box.x + box.width).toBeLessThanOrEqual(list.x + list.width + 1)
        }

        // A copy is offered only for the archive the service offers.
        await expect(
          sheet.getByTestId('recovery-copy-1a2b3c4d-0000-4000-8000-000000000005')
        ).toBeEnabled()
        for (const suffix of ['1', '2', '3', '4']) {
          await expect(
            sheet.getByTestId(`recovery-copy-1a2b3c4d-0000-4000-8000-00000000000${suffix}`)
          ).toBeDisabled()
        }

      })
    }
  }
}

for (const largest of [false, true]) {
  for (const scheme of ['light', 'dark'] as const) {
    const size = largest ? 'largest' : 'default'
    test(`shows the mark of each paired host on the pairing row at 390px, ${size} text, ${scheme}`, async ({
      page
    }) => {
      await withWideFace(page)
      if (largest) await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 390, height: 844 })
      await page.emulateMedia({ colorScheme: scheme })
      await page.goto('/harness.html?surface=ios&tab=hosts&scan=both')
      await expect(page.locator('.m-shell')).toBeVisible()
      await page.evaluate(() => {
        window.krTestHost?.setPairing({
          hosts: [
            {
              reference: 'kitchen-reference',
              in_use: false,
              name: 'kitchen-pc',
              mark: '3fa9-1c07-b2e4-77ab',
              owner: true,
              authority: 'manage the host as an owner',
              grant_expires_at_ms: null,
              in_contact: true
            },
            {
              reference: 'kitchen-reference-2',
              in_use: false,
              name: 'kitchen-pc',
              mark: '77bc-db3b-2424-b1f2',
              owner: false,
              authority: 'view sessions',
              grant_expires_at_ms: null,
              in_contact: null
            }
          ]
        })
      })
      const list = page.getByTestId('paired-hosts')
      await expect(list.getByTestId('host-mark')).toHaveText([
        'Mark 3fa9-1c07-b2e4-77ab',
        'Mark 77bc-db3b-2424-b1f2'
      ])
      expect(await overrunning(page, '[data-testid="paired-hosts"]')).toEqual([])
      await settled(page)
      await tallEnoughFor(page, list)
      await list.screenshot({ path: shot(`pairing-row-390-${size}-${scheme}`) })
    })
  }
}
