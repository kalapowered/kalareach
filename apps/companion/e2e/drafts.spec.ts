/**
 * The composer's draft on a phone, kept on the device across the application being started again,
 * and the list of drafts no composer shows, at the largest text size on the narrowest screen
 * (KR-REQ-13.13, 24.13, 13.19).
 *
 * The harness keeps the device's drafts in the page's storage, so a reload stands for starting the
 * application again. Nothing a test does here may send a prompt; the strip counts what was sent.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type Page } from '@playwright/test'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const GONE = 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

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

/** A draft its session no longer has, in the store the harness keeps, before the page loads. */
async function withAnOrphan(page: Page): Promise<void> {
  await page.addInitScript(
    ({ session, text }) => {
      if (window.localStorage.getItem('kr.fake.device-drafts') !== null) return
      window.localStorage.setItem(
        'kr.fake.device-drafts',
        JSON.stringify({
          counter: 1,
          clock: 1,
          drafts: [
            {
              id: '00000000-0000-4000-8000-000000000001',
              revision: '1',
              sessionId: session,
              applicationInstanceId: null,
              agentBindingRevision: null,
              state: 'orphaned',
              text,
              attachments: [],
              copyOf: null,
              createdAtMs: '1700000000001',
              updatedAtMs: '1700000000001'
            }
          ]
        })
      )
    },
    { session: GONE, text: 'for a session that went, written at some length so that it has to wrap on a narrow screen' }
  )
}

for (const surface of ['ios', 'android'] as const) {
  const finger = surface === 'ios' ? 44 : 48

  test.describe(`a draft on ${surface}`, () => {
    test('is still in the composer when the application is started again, and nothing was sent', async ({
      page
    }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      const field = page.getByLabel('Message this session')
      await field.fill('half a thought')
      // The page writes it as it goes: a reload is the application being started again.
      await page.reload()
      await expect(page.getByLabel('Message this session')).toHaveValue('half a thought')
      expect(await page.evaluate(() => window.krTestHost?.submissions)).toBe(0)
    })

    test('is listed in the kept drafts when its session has gone, with controls a finger can press at the largest size', async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await withAnOrphan(page)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
      await page.getByTestId('kept-drafts-entry').click()
      const entry = page.getByTestId('kept-draft')
      await expect(entry).toBeVisible()
      await expect(entry).toContainText('has gone')

      const across = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth,
        screen: window.innerWidth
      }))
      expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
      const outside = await page.evaluate(() => {
        const edge = window.innerWidth
        return [...document.querySelectorAll('[data-testid="kept-draft"] *')]
          .filter((element) => element.getBoundingClientRect().right > edge + 0.5)
          .map((element) => element.textContent?.slice(0, 40) ?? element.tagName)
      })
      expect(outside, 'lines of the draft that run past the screen').toEqual([])

      const small = await page.evaluate((least) => {
        const pressed = document.querySelectorAll<HTMLElement>(
          '[data-testid="kept-draft"] button, [data-testid="kept-draft"] select'
        )
        return [...pressed]
          .map((element) => ({ box: element.getBoundingClientRect(), name: element.textContent?.slice(0, 30) ?? '' }))
          .filter(({ box }) => box.height + 0.5 < least || box.width + 0.5 < least)
          .map(({ box, name }) => `${name}: ${Math.round(box.width)}×${Math.round(box.height)}`)
      }, finger)
      expect(small, `controls under ${finger} points`).toEqual([])

      const controls = page.locator(
        '[data-testid="kept-draft"] button:visible:not([disabled]), [data-testid="kept-draft"] select:visible:not([disabled])'
      )
      const count = await controls.count()
      expect(count, 'controls found on the kept draft').toBeGreaterThan(0)
      for (let index = 0; index < count; index += 1) {
        await controls.nth(index).click({ trial: true, timeout: 2_000 })
      }
    })

    test('shows the path of a picked file whole inside the screen at the largest size', async ({
      page
    }) => {
      await withSystemTextScale(page, LARGEST)
      await page.setViewportSize({ width: 320, height: 720 })
      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      const opened = page.waitForEvent('filechooser')
      await page.getByRole('button', { name: 'Files', exact: true }).click()
      const chooser = await opened
      await chooser.setFiles({
        name: 'a-file-with-a-name-long-enough-that-its-path-has-to-wrap-on-a-narrow-screen.png',
        mimeType: 'image/png',
        buffer: Buffer.from('a picked file')
      })
      const path = page.getByTestId('attachment-path')
      await expect(path).toBeVisible()
      await expect(path).toContainText('a-file-with-a-name-long-enough')
      await expect(page.getByTestId('attachment-thumb')).toBeVisible()

      const across = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth,
        screen: window.innerWidth
      }))
      expect(across.page, 'the page is no wider than the screen').toBeLessThanOrEqual(across.screen)
      const outside = await page.evaluate(() => {
        const edge = window.innerWidth
        interface Span {
          readonly left: number
          readonly right: number
          readonly what: string
        }
        const label = (text: string | null) => (text ?? '').trim().slice(0, 40)
        // Where everything under a root is drawn: each element's box, and each line of its text,
        // because a box does not say where its text runs when the text runs out of it.
        const spans = (root: Element): Span[] => {
          const found = [root, ...root.querySelectorAll('*')].map((element) => {
            const box = element.getBoundingClientRect()
            return { left: box.left, right: box.right, what: label(element.textContent) || element.tagName }
          })
          const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
          for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
            const range = document.createRange()
            range.selectNodeContents(node)
            for (const line of Array.from(range.getClientRects())) {
              if (line.width > 0) {
                found.push({ left: line.left, right: line.right, what: label(node.textContent) })
              }
            }
          }
          return found
        }
        const beyond = (found: readonly Span[], within: { left: number; right: number }) =>
          found
            .filter((one) => one.left < within.left - 0.5 || one.right > within.right + 0.5)
            .map((one) => one.what)
        const screen = { left: 0, right: edge }
        const path = [...document.querySelectorAll('[data-testid="attachment-paths"]')].flatMap(
          (each) => beyond(spans(each), screen)
        )
        // Everything in a chip lies inside the screen and inside the chip's own box, its name and
        // its lines of text among it.
        const chip = [...document.querySelectorAll('[data-testid="draft-attachments"] > *')].flatMap(
          (each) => [...beyond(spans(each), screen), ...beyond(spans(each), each.getBoundingClientRect())]
        )
        return [...path, ...chip]
      })
      expect(outside, 'lines of the chip and the path that run past the screen or their chip').toEqual([])
      // The notice after the upload covers the screen at this size, and the pointer that picked the
      // file can rest on it, which holds it there. The pointer moves off it, as a finger lifts, and
      // the case waits for the notice to go before it presses the chip's control.
      await page.mouse.move(1, 1)
      await expect(page.locator('.toast')).toHaveCount(0, { timeout: 10_000 })
      await page
        .getByRole('button', { name: /^Remove .* from this draft$/ })
        .click({ trial: true, timeout: 2_000 })
    })

    test('is moved to a session the person chooses, and is in that session’s composer after a restart', async ({
      page
    }) => {
      await withAnOrphan(page)
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(`/harness.html?surface=${surface}&tab=sessions`)
      await page.getByTestId('kept-drafts-entry').click()
      const entry = page.getByTestId('kept-draft')
      await expect(entry.getByTestId('kept-draft-session')).toBeEnabled()
      await entry.getByTestId('kept-draft-session').selectOption(SESSION)
      await entry.getByTestId('kept-draft-move').click()
      await expect(page.getByTestId('kept-drafts-empty')).toBeVisible()

      await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
      await expect(page.getByLabel('Message this session')).toHaveValue(/for a session that went/)
    })
  })
}
