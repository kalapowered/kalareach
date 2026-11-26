/**
 * The desktop window at the widths where the sidebar does not fit beside the page.
 *
 * At 720 points and below the sidebar is a drawer from the leading edge, opened from one control at
 * the start of the top bar, and it holds every destination and the way into Account. At 721 points
 * and wider the page is the one it always was. The backend is the scripted host the harness serves.
 *
 * Every screenshot goes under the test artefact directory, named for the width, the state, the
 * colour scheme, the text size and the engine.
 */

import { platform } from 'node:os'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning, stopWrapping } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

const WIDTHS = [480, 600, 720] as const
const SIZES = [
  ['the ordinary text size', 1],
  ['the largest text size', LARGEST]
] as const
const HEIGHT = 800

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  mark: 'ab'.repeat(32),
  outcome: null
} as const

/** What the sidebar holds besides Account, as the first words of each item. */
const DESTINATIONS: readonly (string | RegExp)[] = [
  'Attention',
  'Sessions',
  'Hosts',
  'Devices',
  'Change sets',
  'Plugins',
  'Pair with a host',
  /^Set up/
]

/** A reason for no contact as long as the host's own words can be, with a path that has no place to break. */
const LONG_REASON =
  'Not in contact: the host at /var/lib/someone/Application Support/KalaReach/sockets/controller-0123456789abcdef0123456789abcdef.sock refused the connection, and the retry twenty seconds later did not get through either.'

/**
 * The keys that move between controls. WebKit on a Mac stops at text fields with a plain Tab and
 * moves between every control with Option+Tab; every other engine moves between them with Tab.
 */
function tabKeys(): { readonly forward: string; readonly back: string } {
  const option = test.info().project.name === 'webkit' && platform() === 'darwin'
  return option ? { forward: 'Alt+Tab', back: 'Alt+Shift+Tab' } : { forward: 'Tab', back: 'Shift+Tab' }
}

function nameOf(label: string | RegExp): RegExp {
  return typeof label === 'string' ? new RegExp(`^${label}`) : label
}

/** The page's text scale, set before it loads, as a person who chose a larger text size has it. */
async function withTextScale(page: Page, ratio: number): Promise<void> {
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

/** Opens the harness signed in, in a window of `width` points, with the text at `ratio`. */
async function openWindow(page: Page, width: number, ratio = 1): Promise<void> {
  await withTextScale(page, ratio)
  await page.setViewportSize({ width, height: HEIGHT })
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.evaluate((view) => {
    window.krTestHost?.account.set(view)
  }, SIGNED_IN)
}

const menuOf = (page: Page): Locator =>
  page.locator('.topbar').getByRole('button', { name: 'Menu', exact: true })
/** The drawer while it is open: nothing matches while it is closed, and then it is not visible. */
const drawerOf = (page: Page): Locator => page.locator('aside.sidebar[data-open="true"]')
const closeOf = (page: Page): Locator => drawerOf(page).getByRole('button', { name: 'Close menu', exact: true })
const itemOf = (page: Page, label: string | RegExp): Locator =>
  drawerOf(page).getByRole('button', { name: nameOf(label) })

interface Rectangle {
  readonly x: number
  readonly y: number
  readonly width: number
  readonly height: number
}

async function rectangleOf(locator: Locator): Promise<Rectangle> {
  const found = await locator.boundingBox()
  if (found === null) throw new Error('the control has no box')
  return found
}

/** Where the sidebar's left edge is, as drawn. */
function sidebarLeft(page: Page): Promise<number> {
  return page.evaluate(() => Math.round((document.querySelector('.sidebar')?.getBoundingClientRect().left ?? NaN) * 10) / 10)
}

/** Starts reading the sidebar's left edge at every frame. */
async function startSampling(page: Page): Promise<void> {
  await page.evaluate(() => {
    const samples: number[] = []
    const sidebar = document.querySelector('.sidebar')
    const reading = { samples, running: true }
    const tick = (): void => {
      if (sidebar !== null) samples.push(Math.round(sidebar.getBoundingClientRect().left * 10) / 10)
      if (reading.running) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
    ;(window as unknown as { __sampling: typeof reading }).__sampling = reading
  })
}

/** What the sidebar's left edge read at each frame since `startSampling`. */
function stopSampling(page: Page): Promise<number[]> {
  return page.evaluate(() => {
    const reading = (window as unknown as { __sampling: { samples: number[]; running: boolean } }).__sampling
    reading.running = false
    return reading.samples
  })
}

/** The readings that are neither of the two places the drawer rests in: it was somewhere between. */
function between(samples: readonly number[], rests: readonly number[]): number[] {
  return samples.filter((sample) => !rests.some((rest) => Math.abs(sample - rest) < 0.5))
}

/** Whether the focus is inside the drawer. */
function focusInDrawer(page: Page): Promise<boolean> {
  return page.evaluate(() => document.activeElement?.closest('aside.sidebar') != null)
}

/**
 * The focus is on the page that was chosen: on `main` itself, or, for the one view that puts the
 * focus into its own field as it opens (pairing), inside it.
 */
async function expectFocusOnPage(page: Page, label: string | RegExp): Promise<void> {
  if (label === 'Pair with a host') {
    await expect.poll(() => page.evaluate(() => document.activeElement?.closest('main') != null)).toBe(true)
  } else {
    await expect(page.locator('main'), 'a choice leaves the focus on the page it chose').toBeFocused()
  }
}

/** Presses Shift+Tab until the focus is on `menu`. */
async function backToMenu(page: Page, menu: Locator): Promise<void> {
  for (let press = 0; press < 10; press += 1) {
    await page.keyboard.press(tabKeys().back)
    if (await menu.evaluate((element) => element === document.activeElement)) return
  }
  throw new Error('Shift+Tab did not reach the control that opens the navigation')
}

/** Presses Tab until the focus is on the item that starts with `label`. */
async function tabTo(page: Page, label: string | RegExp): Promise<void> {
  for (let press = 0; press < 14; press += 1) {
    await page.keyboard.press(tabKeys().forward)
    const name = await page.evaluate(() => (document.activeElement?.textContent ?? '').replace(/\s+/g, ' ').trim())
    if (typeof label === 'string' ? name.startsWith(label) : label.test(name)) return
  }
  throw new Error(`Tab did not reach ${String(label)}`)
}

function shot(name: string): string {
  return screenshotPath(`kr-companion-narrow-${name}-${test.info().project.name}`)
}

for (const width of WIDTHS) {
  for (const [size, ratio] of SIZES) {
    test.describe(`a window ${width} points wide at ${size}`, () => {
      test('a pointer reaches every destination and the Account sheet', async ({ page }) => {
        await openWindow(page, width, ratio)
        const menu = menuOf(page)
        const drawer = drawerOf(page)
        await expect(menu, 'the top bar has the control that opens the navigation').toBeVisible()
        await expect(drawer, 'the navigation is out of the way until it is asked for').toBeHidden()
        expect(
          await page.evaluate(() => (document.querySelector('aside.sidebar') as HTMLElement).inert),
          'closed, the navigation takes no focus and is not read'
        ).toBe(true)
        // The destination that is shown is chosen too: it closes the drawer like any other.
        const labels = [...DESTINATIONS, DESTINATIONS[0] ?? 'Attention']
        for (const label of labels) {
          await menu.click()
          await expect(drawer).toBeVisible()
          await itemOf(page, label).click()
          await expect(drawer).toBeHidden()
          await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText(nameOf(label))
          await expect(page.locator('main h1, main h2').first()).toBeVisible()
          await expectFocusOnPage(page, label)
        }
        await menu.click()
        await itemOf(page, /^Account/).click()
        await expect(page.getByRole('dialog', { name: 'Account' })).toBeVisible()
        await expect(drawer).toBeHidden()
      })

      test('the keyboard alone reaches every destination and the Account sheet, with the focus where it belongs', async ({
        page
      }) => {
        await openWindow(page, width, ratio)
        const menu = menuOf(page)
        const drawer = drawerOf(page)
        // The first stop is the skip link where the engine's Tab stops at links (WebKit's does not), and
        // the control that opens the navigation is the next: never behind the page's own controls.
        let presses = 0
        while (presses < 2 && !(await menu.evaluate((element) => element === document.activeElement))) {
          await page.keyboard.press(tabKeys().forward)
          presses += 1
        }
        await expect(menu, 'the control that opens the navigation is within the first two stops').toBeFocused()
        await expect(menu).toHaveAttribute('aria-expanded', 'false')
        await page.keyboard.press('Enter')
        await expect(drawer).toBeVisible()
        await expect(page.getByRole('complementary', { name: 'Workspace navigation' })).toBeVisible()
        await expect(menu).toHaveAttribute('aria-expanded', 'true')
        await expect(
          drawer.locator('[aria-current="page"]'),
          'the focus goes to the destination that is shown'
        ).toBeFocused()
        // Tab goes round inside the drawer, both ways, and never to the page behind it.
        for (const key of [tabKeys().forward, tabKeys().back]) {
          for (let press = 0; press < 13; press += 1) {
            await page.keyboard.press(key)
            expect(await focusInDrawer(page), `${key} ${press + 1} stays inside the drawer`).toBe(true)
          }
        }
        await page.keyboard.press('Escape')
        await expect(drawer).toBeHidden()
        await expect(menu, 'Escape returns the focus to the control that opened it').toBeFocused()

        for (const label of DESTINATIONS) {
          await page.keyboard.press('Enter')
          await expect(drawer).toBeVisible()
          await tabTo(page, label)
          await page.keyboard.press('Enter')
          await expect(drawer).toBeHidden()
          await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText(nameOf(label))
          await expectFocusOnPage(page, label)
          await backToMenu(page, menu)
          await expect(menu).toBeFocused()
        }

        await page.keyboard.press('Enter')
        await tabTo(page, /^Account/)
        await page.keyboard.press('Enter')
        const sheet = page.getByRole('dialog', { name: 'Account' })
        await expect(sheet).toBeVisible()
        await expect(drawer).toBeHidden()
        await page.keyboard.press('Escape')
        await expect(sheet).toBeHidden()
        await expect(menu, 'closing Account returns the focus to the control that led there').toBeFocused()
      })

      test('a press outside closes the drawer and returns the focus to the control', async ({ page }) => {
        await openWindow(page, width, ratio)
        const menu = menuOf(page)
        await menu.click()
        await expect(drawerOf(page)).toBeVisible()
        await page.mouse.click(width - 6, HEIGHT / 2)
        await expect(drawerOf(page)).toBeHidden()
        await expect(menu).toBeFocused()
        await expect(menu).toHaveAttribute('aria-expanded', 'false')
      })

      test('"Close menu" is drawn where "Menu" was, and the control is a target', async ({ page }) => {
        await openWindow(page, width, ratio)
        const menu = menuOf(page)
        await expect(menu).toBeVisible()
        const was = await rectangleOf(menu)
        const target = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--target')))
        expect(was.width, 'the control is at least a target wide').toBeGreaterThanOrEqual(target)
        expect(was.height, 'the control is at least a target high').toBeGreaterThanOrEqual(target)
        const x = was.x + was.width / 2
        const y = was.y + was.height / 2
        // A person who presses twice at one point opens the drawer and then closes it.
        await page.mouse.click(x, y)
        await expect(drawerOf(page)).toBeVisible()
        await expect.poll(() => sidebarLeft(page)).toBe(0)
        const now = await rectangleOf(closeOf(page))
        // One corner and one height, each its own width: the open control lies inside the close control.
        for (const edge of ['x', 'y', 'height'] as const) {
          expect(Math.abs(now[edge] - was[edge]), `the close control's ${edge} against the open control's`).toBeLessThanOrEqual(1)
        }
        expect(now.width, 'the open control lies inside the close control').toBeGreaterThanOrEqual(was.width - 1)
        await page.mouse.click(x, y)
        await expect(drawerOf(page)).toBeHidden()
      })

      test('the top bar and the open drawer stay inside the window', async ({ page }) => {
        await openWindow(page, width, ratio)
        await page.evaluate((reason) => {
          window.krTestHost?.setConnected(false, reason)
        }, LONG_REASON)
        const menu = menuOf(page)
        await expect(menu).toBeVisible()
        const connection = page.locator('.topbar .connection')
        await expect(connection).toContainText('refused the connection')
        expect(await overrunning(page, '.topbar')).toEqual([])
        // The status dot stays in the first line of the words, not between two lines of them.
        const dot = await page.evaluate(() => {
          const holder = document.querySelector('.topbar .connection') as Element
          const mark = (holder.querySelector('.status-dot') as Element).getBoundingClientRect()
          const walk = document.createTreeWalker(holder, NodeFilter.SHOW_TEXT)
          let first: DOMRect | undefined
          for (let node = walk.nextNode(); node !== null && first === undefined; node = walk.nextNode()) {
            const range = document.createRange()
            range.selectNodeContents(node)
            first = Array.from(range.getClientRects()).find((line) => line.width > 0)
          }
          return { middle: mark.top + mark.height / 2, top: first?.top ?? NaN, bottom: first?.bottom ?? NaN }
        })
        expect(dot.middle, 'the dot is level with the first line of the words').toBeGreaterThanOrEqual(dot.top - 0.5)
        expect(dot.middle, 'the dot is level with the first line of the words').toBeLessThanOrEqual(dot.bottom + 0.5)
        // The control and the words share a row when the words have room beside it, and otherwise the
        // words are under it: they never overlap, and neither is cut.
        const control = await rectangleOf(menu)
        const words = await rectangleOf(connection)
        const beside = words.x >= control.x + control.width - 1 && words.y < control.y + control.height
        const under = words.y >= control.y + control.height - 1
        expect(beside || under, 'the words are beside the control or under it').toBe(true)
        expect(words.x + words.width, 'the words end inside the window').toBeLessThanOrEqual(width + 0.5)
        expect(control.x + control.width, 'the control ends inside the window').toBeLessThanOrEqual(width + 0.5)
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
        await menu.click()
        await expect(drawerOf(page)).toBeVisible()
        await expect.poll(() => sidebarLeft(page)).toBe(0)
        expect(await overrunning(page, '.sidebar')).toEqual([])
        const drawer = await rectangleOf(drawerOf(page))
        expect(drawer.x, 'the drawer starts at the window edge').toBe(0)
        expect(drawer.width, 'the drawer leaves a strip of the page to press on').toBeLessThanOrEqual(width - 47)
      })
    })
  }
}

test.describe('the connection line', () => {
  for (const [size, ratio] of SIZES) {
    test(`keeps the distance from its dot to its first letter at 720 points that it has at 721 and wider, at ${size}`, async ({
      page
    }) => {
      await openWindow(page, 721, ratio)
      // The distance from the dot's right edge to the left edge of the first letter of the words.
      const distance = (): Promise<number> =>
        page.evaluate(() => {
          const holder = document.querySelector('.topbar .connection') as Element
          const mark = (holder.querySelector('.status-dot') as Element).getBoundingClientRect()
          const walk = document.createTreeWalker(holder, NodeFilter.SHOW_TEXT)
          for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
            const range = document.createRange()
            range.selectNodeContents(node)
            const first = Array.from(range.getClientRects()).find((line) => line.width > 0)
            if (first !== undefined) return first.left - mark.right
          }
          return NaN
        })
      await expect(page.locator('.topbar .connection')).toContainText('Connected to this machine')
      const wide = await distance()
      for (const width of [900, 1280, 720, 600, 480]) {
        await page.setViewportSize({ width, height: HEIGHT })
        await expect(page.locator('.topbar .connection')).toContainText('Connected to this machine')
        expect(await distance(), `the distance at ${width} points against ${wide.toFixed(1)} at 721`).toBeCloseTo(wide, 0)
      }
    })
  }
})

test.describe('the measure sees what it is there for', () => {
  test('text kept from wrapping runs out of the top bar at 480 points and the largest text size', async ({ page }) => {
    await openWindow(page, 480, LARGEST)
    await expect(menuOf(page)).toBeVisible()
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, LONG_REASON)
    await stopWrapping(page, ['.topbar'])
    expect((await overrunning(page, '.topbar')).length).toBeGreaterThan(0)
  })
})

test.describe('the window as it is at 721 points and wider', () => {
  for (const width of [721, 900, 1280]) {
    test(`${width} points: the sidebar stands beside the page and the top bar holds the connection only`, async ({ page }) => {
      await openWindow(page, width)
      const sidebar = await rectangleOf(page.locator('.sidebar'))
      expect(sidebar).toEqual({ x: 0, y: 0, width: 238, height: HEIGHT })
      expect(await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar') as Element).position)).toBe('sticky')
      expect(await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar') as Element).visibility)).toBe('visible')
      expect(
        await page.locator('.topbar > *').evaluateAll((children) => children.map((child) => child.getAttribute('class') ?? '')),
        'the top bar holds one child, the connection'
      ).toEqual(['row'])
      expect(await page.locator('.topbar button').count()).toBe(0)
      expect(await page.locator('.scrim').count()).toBe(0)
      expect(await page.evaluate(() => (document.querySelector('.workspace') as HTMLElement).inert)).toBe(false)
      expect(await page.locator('.sidebar').getByRole('button').count()).toBe(DESTINATIONS.length + 1)
      const main = await rectangleOf(page.locator('main'))
      expect(main.x).toBe(238)
      expect(await page.evaluate(() => getComputedStyle(document.querySelector('.topbar') as Element).paddingLeft)).toBe('34px')
    })
  }

  test('the window changes form at 720 and 721 points, in the style rules and in the page together', async ({ page }) => {
    await openWindow(page, 721)
    await expect(menuOf(page)).toHaveCount(0)
    for (const width of [720, 721, 720]) {
      await page.setViewportSize({ width, height: HEIGHT })
      const drawer = width <= 720
      await expect(menuOf(page)).toHaveCount(drawer ? 1 : 0)
      expect(await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar') as Element).position)).toBe(
        drawer ? 'fixed' : 'sticky'
      )
    }
  })

  test('a window widened past 720 points while the drawer is open keeps the sidebar, the focus and a working page', async ({
    page
  }) => {
    await openWindow(page, 600)
    await menuOf(page).click()
    await expect(drawerOf(page)).toBeVisible()
    await expect.poll(() => sidebarLeft(page)).toBe(0)
    const current = page.locator('.sidebar [aria-current="page"]')
    await expect(current).toBeFocused()
    await page.setViewportSize({ width: 800, height: HEIGHT })
    await expect(menuOf(page)).toHaveCount(0)
    await expect.poll(() => rectangleOf(page.locator('.sidebar'))).toEqual({ x: 0, y: 0, width: 238, height: HEIGHT })
    expect(await page.locator('.scrim').count()).toBe(0)
    expect(await page.evaluate(() => (document.querySelector('.workspace') as HTMLElement).inert)).toBe(false)
    await expect(current, 'the focus stays on the item it was on').toBeFocused()
    await page.getByRole('button', { name: /^Hosts/ }).click()
    await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText(/^Hosts/)
    // Narrowed again, the drawer is closed and ready.
    await page.setViewportSize({ width: 600, height: HEIGHT })
    await expect(menuOf(page)).toHaveAttribute('aria-expanded', 'false')
    await expect(drawerOf(page)).toBeHidden()
  })
})

test.describe('the drawer on a page that scrolls', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points: the page behind does not move, shift or scroll while it is open`, async ({ page }) => {
      await openWindow(page, width, ratio)
      const main = page.locator('main')
      await expect(menuOf(page)).toBeVisible()
      const atTop = await rectangleOf(menuOf(page))
      await page.mouse.move(width - 8, HEIGHT / 2)
      await page.mouse.wheel(0, 300)
      // The wheel moves the page when nothing is open, so a page that does not move later has been held.
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(100)
      const scrolled = await page.evaluate(() => window.scrollY)
      // The top bar stays at the top of the window as the page scrolls: the control is where it was.
      expect(await rectangleOf(menuOf(page)), 'the control is where it was after the page scrolled').toEqual(atTop)
      expect((await rectangleOf(page.locator('.topbar'))).y, 'the top bar is at the top of the window').toBe(0)
      const before = await rectangleOf(main)

      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await expect.poll(() => sidebarLeft(page)).toBe(0)
      const open = await rectangleOf(main)
      expect(open.x, 'the page behind starts where it did').toBe(before.x)
      expect(open.width, 'the page behind is as wide as it was').toBe(before.width)

      // A wheel over the scrim, and over the drawer, in both directions and past the drawer's own end.
      for (const [x, delta] of [
        [width - 8, 400],
        [width - 8, -400],
        [20, 600],
        [20, 600],
        [20, -2000]
      ] as const) {
        await page.mouse.move(x, HEIGHT / 2)
        await page.mouse.wheel(0, delta)
        await page.waitForTimeout(120)
        expect(await page.evaluate(() => window.scrollY), `the page after a wheel of ${delta} at ${x}`).toBe(scrolled)
      }
      expect(await rectangleOf(main)).toEqual(open)

      await page.keyboard.press('Escape')
      await expect(drawerOf(page)).toBeHidden()
      const after = await rectangleOf(main)
      expect(after.x).toBe(before.x)
      expect(after.width).toBe(before.width)
      expect(await page.evaluate(() => window.scrollY)).toBe(scrolled)
    })
  }
})

test.describe('what moves', () => {
  test('a pointer opens the drawer by travel from the edge it rests against, and a keyboard does not', async ({ page }) => {
    await openWindow(page, 600)
    const rest = await sidebarLeft(page)
    expect(rest, 'closed, the drawer is out of the window on its own side').toBeLessThanOrEqual(-238)

    await startSampling(page)
    await menuOf(page).click()
    await expect.poll(() => sidebarLeft(page)).toBe(0)
    await page.waitForTimeout(100)
    const travelled = between(await stopSampling(page), [rest, 0])
    expect(travelled.length, 'a pointer-driven open passes through places between').toBeGreaterThan(2)

    await page.keyboard.press('Escape')
    await expect(drawerOf(page)).toBeHidden()
    await menuOf(page).focus()
    await startSampling(page)
    await page.keyboard.press('Enter')
    await expect.poll(() => sidebarLeft(page)).toBe(0)
    await page.waitForTimeout(100)
    expect(between(await stopSampling(page), [rest, 0]), 'a keyboard-driven open has no travel').toEqual([])

    await startSampling(page)
    await page.keyboard.press('Escape')
    await expect.poll(() => sidebarLeft(page)).toBe(rest)
    await page.waitForTimeout(100)
    expect(between(await stopSampling(page), [rest, 0]), 'a keyboard-driven close has no travel').toEqual([])
  })

  test.describe('with reduced motion asked for', () => {
    test.use({ reducedMotion: 'reduce' })

    test('nothing travels when the drawer opens or closes', async ({ page }) => {
      await openWindow(page, 600)
      const rest = await sidebarLeft(page)
      await startSampling(page)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await page.waitForTimeout(250)
      await page.mouse.click(594, HEIGHT / 2)
      await expect(drawerOf(page)).toBeHidden()
      await page.waitForTimeout(250)
      const samples = await stopSampling(page)
      expect(samples.length).toBeGreaterThan(5)
      expect(between(samples, [rest]), 'the drawer is never anywhere but where it rests').toEqual([])
    })
  })
})

test.describe('under a right-to-left root', () => {
  test('the wide sidebar and the drawer both stand and travel at the end the page starts from', async ({ page }) => {
    await openWindow(page, 1280)
    await page.evaluate(() => {
      document.documentElement.dir = 'rtl'
    })
    const wide = await rectangleOf(page.locator('.sidebar'))
    expect(wide.x + wide.width, 'the wide sidebar stands against the right edge').toBe(1280)

    await page.setViewportSize({ width: 600, height: HEIGHT })
    const menu = menuOf(page)
    await expect(menu).toBeVisible()
    const was = await rectangleOf(menu)
    expect(was.x + was.width, 'the control is at the right end of the top bar').toBeGreaterThan(600 - 40)
    // Narrowed from a wide window, the sidebar travels out to the closed place: read it there.
    await expect.poll(() => sidebarLeft(page), 'closed, the drawer is out of the window on the right').toBe(600)
    const rest = await sidebarLeft(page)
    await startSampling(page)
    await menu.click()
    await expect(drawerOf(page)).toBeVisible()
    await expect.poll(() => sidebarLeft(page)).toBe(600 - 238)
    await page.waitForTimeout(100)
    const samples = await stopSampling(page)
    expect(Math.min(...samples), 'the drawer never goes past its open place towards the left').toBeGreaterThanOrEqual(600 - 238)
    expect(between(samples, [rest, 600 - 238]).length, 'it travels').toBeGreaterThan(2)
    const now = await rectangleOf(closeOf(page))
    // The leading corner is the right one: the open control's right edge, top and height are the close control's.
    expect(Math.abs(now.x + now.width - (was.x + was.width))).toBeLessThanOrEqual(1)
    expect(Math.abs(now.y - was.y)).toBeLessThanOrEqual(1)
    expect(Math.abs(now.height - was.height)).toBeLessThanOrEqual(1)
    expect(now.width).toBeGreaterThanOrEqual(was.width - 1)
  })
})

test.describe('the pictures', () => {
  for (const width of WIDTHS) {
    for (const [size, ratio] of SIZES) {
      for (const scheme of ['light', 'dark'] as const) {
        test(`${width} points, ${size}, ${scheme}: closed and open`, async ({ page }) => {
          await page.emulateMedia({ colorScheme: scheme })
          await openWindow(page, width, ratio)
          const name = `${width}-${ratio === 1 ? 'ordinary' : 'largest'}-${scheme}`
          await expect(menuOf(page)).toBeVisible()
          await page.screenshot({ path: shot(`${name}-closed`) })
          await menuOf(page).click()
          await expect(drawerOf(page)).toBeVisible()
          await expect.poll(() => sidebarLeft(page)).toBe(0)
          await page.screenshot({ path: shot(`${name}-open`) })
        })
      }
    }
  }
})
