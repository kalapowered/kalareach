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

import { chromium, expect, test, type Locator, type Page } from '@playwright/test'

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
/** The most of the window's height that the top bar, which stays in place, may take with the long reason. */
const BAR_SHARE = 0.27

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

/** A reason for no contact that is a few words, as the host most often gives one. */
const SHORT_REASON = 'The host is not running.'

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

/** Opens the harness signed in, in a window of `width` by `height` points, with the text at `ratio`. */
async function openWindow(page: Page, width: number, ratio = 1, height = HEIGHT): Promise<void> {
  await withTextScale(page, ratio)
  await page.setViewportSize({ width, height })
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

/** What the page was told of a transition of the sidebar: the event, the property, and the seconds it had run. */
interface TravelEvent {
  readonly type: string
  readonly property: string
  readonly elapsed: number
}

/** The ruled times, in seconds: the drawer comes in on `--surface-in` and goes out on `--state`. */
const OPEN_SECONDS = 0.2
const CLOSE_SECONDS = 0.16
/** How far the seconds a transition reports may be from the ruled time. */
const TOLERANCE_SECONDS = 0.01
/** The reduced-motion fade runs on `--press`. */
const FADE_SECONDS = 0.12

/**
 * Listens, from now on, for the transitions of the sidebar. A transition is the travel (or, with
 * reduced motion, the fade): the engine runs it for its ruled time whatever number of frames it draws
 * in that time, so the events are read and the frames are not counted.
 */
async function watchTravel(page: Page): Promise<void> {
  await page.evaluate(() => {
    const holder = window as unknown as {
      __travel?: { type: string; property: string; elapsed: number }[]
      __travelListening?: boolean
    }
    holder.__travel = []
    if (holder.__travelListening === true) return
    holder.__travelListening = true
    for (const type of ['transitionrun', 'transitionstart', 'transitionend', 'transitioncancel']) {
      document.addEventListener(
        type,
        (event) => {
          const transition = event as TransitionEvent
          if (!(transition.target as Element).matches('aside.sidebar')) return
          holder.__travel?.push({ type, property: transition.propertyName, elapsed: transition.elapsedTime })
        },
        true
      )
    }
  })
}

/** The events of the sidebar's `property` since `watchTravel`. */
async function travelOf(page: Page, property = 'transform'): Promise<TravelEvent[]> {
  const all = await page.evaluate(() => [...((window as unknown as { __travel?: TravelEvent[] }).__travel ?? [])])
  return all.filter((event) => event.property === property)
}

/** The sidebar's `property` ran its transition from start to end for the ruled time, and was not cut short. */
async function expectTravel(page: Page, seconds: number, what: string, property = 'transform'): Promise<void> {
  await expect
    .poll(
      async () => (await travelOf(page, property)).some((event) => event.type === 'transitionend' || event.type === 'transitioncancel'),
      what
    )
    .toBe(true)
  const events = await travelOf(page, property)
  expect(
    events.map((event) => event.type),
    `${what}: the events of the transition`
  ).toEqual(['transitionrun', 'transitionstart', 'transitionend'])
  const ran = events[2]?.elapsed ?? NaN
  expect(Math.abs(ran - seconds), `${what}: it ran for ${ran} s, and the ruled time is ${seconds} s`).toBeLessThanOrEqual(TOLERANCE_SECONDS)
}

/**
 * The page's scroll position once it has stopped: it has not changed for three frames in a row and
 * for 100 ms of the page's own clock. WebKit scrolls smoothly, so a read straight after a wheel can
 * fall in the middle of the scroll. The wait has a deadline of its own, a timer that does not depend
 * on a frame being drawn, and a page still moving at the deadline fails with the last value it read.
 * The timer and the frames run on the page's own thread: a page whose thread is blocked blocks the
 * deadline too, and the test's own time limit is the last bound. Three still frames and 100 ms are
 * evidence of rest, not proof: a pause in a scroll that is longer passes.
 */
function settledScroll(page: Page, boundMilliseconds = 3000): Promise<number> {
  return page.evaluate(
    (bound) =>
      new Promise<number>((resolve, reject) => {
        const end = performance.now() + bound
        let last = window.scrollY
        let since = performance.now()
        let frames = 0
        let over = false
        const fail = (): void => {
          over = true
          reject(new Error(`the page was still scrolling after ${bound} ms: its last read was ${last}`))
        }
        const deadline = setTimeout(fail, bound)
        const tick = (): void => {
          if (over) return
          const now = window.scrollY
          if (now !== last) {
            last = now
            since = performance.now()
            frames = 0
          } else {
            frames += 1
          }
          if (frames >= 3 && performance.now() - since >= 100) {
            clearTimeout(deadline)
            // A frame that comes after the deadline is late whatever it finds: the timer's own task may
            // not have run yet, so the clock is read here too.
            if (performance.now() >= end) fail()
            else resolve(now)
            return
          }
          requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      }),
    boundMilliseconds
  )
}

/** Starts counting the wheel events that reach the page, after the hold has had its say. */
async function watchWheels(page: Page): Promise<void> {
  await page.evaluate(() => {
    const holder = window as unknown as { __wheels?: number }
    holder.__wheels = 0
    window.addEventListener(
      'wheel',
      () => {
        holder.__wheels = (holder.__wheels ?? 0) + 1
      },
      { passive: true }
    )
  })
}

function wheelsDelivered(page: Page): Promise<number> {
  return page.evaluate(() => (window as unknown as { __wheels?: number }).__wheels ?? 0)
}

/** Whether the focus is inside the drawer. */
function focusInDrawer(page: Page): Promise<boolean> {
  return page.evaluate(() => document.activeElement?.closest('aside.sidebar') != null)
}

/**
 * What a person meets while the drawer is closed, whatever the web view does with `inert`: it takes
 * no press, it is not drawn once its exit has ended, so it takes no focus and is not read, and no
 * point of the window reaches it. The exit may still be running when this starts, so it is read
 * until it has ended.
 */
async function expectDrawerClosed(page: Page): Promise<void> {
  // Each part is read and reported, so that a failure says which of them a person would meet.
  const each = expect.configure({ soft: true })
  await each(page.locator('aside.sidebar'), 'a closed drawer is not drawn').toBeHidden()
  await each
    .poll(
      () =>
        page.evaluate(() => {
          const style = getComputedStyle(document.querySelector('aside.sidebar') as Element)
          return `${style.visibility} ${style.pointerEvents}`
        }),
      'a closed drawer takes no focus and no press'
    )
    .toBe('hidden none')
  each(await page.getByRole('button', { name: 'Close menu' }).count(), 'its controls are not in the accessibility tree').toBe(0)
  each(await page.getByRole('complementary', { name: 'Workspace navigation' }).count()).toBe(0)
  each(await page.locator('body').ariaSnapshot(), 'a reader is not told of the closed drawer').not.toContain('Close menu')
  const reached = await page.evaluate(() => {
    const found: string[] = []
    for (const x of [4, 60, 120, 180, 234]) {
      for (const y of [20, 100, 300, 500, 700]) {
        if (document.elementFromPoint(x, y)?.closest('aside.sidebar') != null) found.push(`${x},${y}`)
      }
    }
    return found
  })
  each(reached, 'no point of the window reaches the closed drawer').toEqual([])
}

/** How many of `presses` Tab stops from the start of the page are inside the drawer. */
async function tabStopsInDrawer(page: Page, presses: number): Promise<number> {
  await page.evaluate(() => {
    ;(document.activeElement as HTMLElement | null)?.blur()
  })
  let inside = 0
  for (let press = 0; press < presses; press += 1) {
    await page.keyboard.press(tabKeys().forward)
    if (await focusInDrawer(page)) inside += 1
  }
  return inside
}

/**
 * A web view that has no `inert`: no property, and no effect of the attribute either, which the
 * engine would honour whatever the property says. The page's own rules are all that is left.
 */
async function withoutInert(page: Page): Promise<void> {
  await page.addInitScript(() => {
    delete (HTMLElement.prototype as { inert?: boolean }).inert
    const setAttribute = Object.getOwnPropertyDescriptor(Element.prototype, 'setAttribute')?.value as Element['setAttribute']
    Element.prototype.setAttribute = function (this: Element, name: string, value: string): void {
      if (name.toLowerCase() !== 'inert') setAttribute.call(this, name, value)
    }
    const toggleAttribute = Object.getOwnPropertyDescriptor(Element.prototype, 'toggleAttribute')?.value as Element['toggleAttribute']
    Element.prototype.toggleAttribute = function (this: Element, name: string, force?: boolean): boolean {
      return name.toLowerCase() === 'inert' ? false : toggleAttribute.call(this, name, force)
    }
  })
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

/**
 * A person can see where `control` is, so a focus on it is seen: the control is drawn inside the
 * window, and what the window shows at its centre is the control and nothing over it.
 */
async function expectDrawnInWindow(control: Locator, what: string): Promise<void> {
  await expect(control, `${what}: it is drawn`).toBeVisible()
  const seen = await control.evaluate((element) => {
    const box = element.getBoundingClientRect()
    const x = box.x + box.width / 2
    const y = box.y + box.height / 2
    return {
      inside: box.width > 0 && box.height > 0 && x >= 0 && y >= 0 && x <= window.innerWidth && y <= window.innerHeight,
      uncovered: element.contains(document.elementFromPoint(x, y))
    }
  })
  expect(seen.inside, `${what}: it lies inside the window`).toBe(true)
  expect(seen.uncovered, `${what}: nothing is over it`).toBe(true)
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
        await expectDrawerClosed(page)
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
        await expectDrawerClosed(page)
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
        await expectDrawerClosed(page)
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
        await expectDrawerClosed(page)
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

      test('the top bar that stays in place leaves the window to the page, and the control is not covered', async ({ page }) => {
        await openWindow(page, width, ratio)
        await page.evaluate((reason) => {
          window.krTestHost?.setConnected(false, reason)
        }, LONG_REASON)
        const menu = menuOf(page)
        await expect(page.locator('.topbar .connection')).toContainText('refused the connection')
        const bar = await rectangleOf(page.locator('.topbar'))
        expect(bar.height, `the bar is at most ${BAR_SHARE * 100} % of the window, or ${BAR_SHARE * HEIGHT} points`).toBeLessThanOrEqual(
          BAR_SHARE * HEIGHT
        )
        const control = await rectangleOf(menu)
        expect(control.x, 'the control is inside the window').toBeGreaterThanOrEqual(0)
        expect(control.y).toBeGreaterThanOrEqual(0)
        expect(control.x + control.width).toBeLessThanOrEqual(width)
        expect(control.y + control.height).toBeLessThanOrEqual(HEIGHT)
        expect(
          await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.closest('button')?.textContent, [
            control.x + control.width / 2,
            control.y + control.height / 2
          ]),
          'nothing covers the control'
        ).toBe('Menu')
      })
    })
  }
}

test.describe('the words in the top bar', () => {
  const wordsOf = (page: Page): Locator => page.locator('.topbar .connection')
  const shown = (page: Page): Promise<{ more: string | null; mask: string; line: string; scrolled: number }> =>
    page.evaluate(() => {
      const element = document.querySelector('.topbar .connection') as HTMLElement
      const style = getComputedStyle(element)
      return {
        more: element.getAttribute('data-more'),
        mask: style.maskImage || style.webkitMaskImage || 'none',
        line: style.boxShadow,
        scrolled: element.scrollTop
      }
    })

  test('words that run past their box are one Tab stop with a name, scroll by the arrow keys, and fade while more follows', async ({
    page
  }) => {
    await openWindow(page, 480, LARGEST)
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, LONG_REASON)
    const words = wordsOf(page)
    await expect(words).toContainText('refused the connection')
    await expect(words, 'the words that are cut are a region with a name').toHaveAttribute('aria-label', 'Connection status')
    await expect(words).toHaveAttribute('role', 'group')
    await expect(words).toHaveAttribute('tabindex', '0')
    const first = await shown(page)
    expect(first.more, 'more follows').toBe('true')
    expect(first.mask, 'the lower edge fades while more follows').not.toBe('none')

    // One Tab stop: the next one after the control, and the one after that is not another of the bar.
    await menuOf(page).focus()
    await page.keyboard.press(tabKeys().forward)
    await expect(words, 'the Tab after the control reaches the words').toBeFocused()
    // An engine may take a key press for the start of a smooth scroll, so the key is pressed again
    // at each read until the words have moved.
    await expect
      .poll(async () => {
        await page.keyboard.press('ArrowDown')
        return (await shown(page)).scrolled
      }, 'an arrow key scrolls the words')
      .toBeGreaterThan(0)
    await expect
      .poll(async () => {
        await page.keyboard.press('End')
        return (await shown(page)).more
      }, 'at the end nothing follows')
      .toBe('false')
    const end = await shown(page)
    expect(end.mask, 'at the end there is no fade').toBe('none')
    expect(await page.evaluate(() => document.activeElement?.closest('.topbar') != null), 'the focus stays on the words').toBe(true)
  })

  test('words that fit have no Tab stop, no role and no fade', async ({ page }) => {
    await openWindow(page, 600)
    await expect(wordsOf(page)).toContainText('Connected to this machine')
    await expect(wordsOf(page)).not.toHaveAttribute('tabindex', /.*/)
    await expect(wordsOf(page)).not.toHaveAttribute('role', /.*/)
    await expect(wordsOf(page)).not.toHaveAttribute('aria-label', /.*/)
    const state = await shown(page)
    expect(state.more).toBeNull()
    expect(state.mask).toBe('none')
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, LONG_REASON)
    await expect(wordsOf(page)).toContainText('refused the connection')
    await expect(wordsOf(page), 'the long reason fits at the ordinary size in 600 points').not.toHaveAttribute('tabindex', /.*/)
    expect((await shown(page)).mask).toBe('none')
  })

  test('with more contrast asked for, a plain line says that more follows, in place of the fade', async ({ page }) => {
    await page.emulateMedia({ contrast: 'more' })
    await openWindow(page, 480, LARGEST)
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, LONG_REASON)
    await expect(wordsOf(page)).toHaveAttribute('data-more', 'true')
    const state = await shown(page)
    expect(state.mask, 'no fade').toBe('none')
    expect(state.line, 'a plain line at the lower edge').not.toBe('none')
  })

  test('the window of the words is two whole lines and the half of a third in a window 800 points high, and the fade leaves the two lines alone', async ({
    page
  }) => {
    await openWindow(page, 480, LARGEST)
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, LONG_REASON)
    await expect(wordsOf(page)).toHaveAttribute('data-more', 'true')
    const read = await page.evaluate(() => {
      const element = document.querySelector('.topbar .connection') as HTMLElement
      const style = getComputedStyle(element)
      const fade = /calc\(100% - ([\d.]+)px\)/.exec(style.maskImage || style.webkitMaskImage || '')
      return { box: element.clientHeight, line: parseFloat(style.lineHeight), fade: fade ? parseFloat(fade[1] ?? 'NaN') : Number.NaN }
    })
    expect(read.box, 'two whole lines are in the window').toBeGreaterThanOrEqual(2 * read.line - 1)
    expect(read.box, 'a third line is cut, and says that more follows').toBeLessThan(3 * read.line)
    expect(read.box - read.fade, 'the fade starts after the second line: the two are not faded').toBeGreaterThanOrEqual(2 * read.line - 1)
  })

  /**
   * The shell's smallest window is 480 points high. At the largest text size the box cannot hold two
   * whole lines there: it is held to a fifth of the window, 96 points, about 1.7 lines of 56, and the
   * fade starts after about 1.2. What holds at that height is that the bar keeps to its share, the
   * first line is whole and clear of the fade, and the whole reason is reached by the keys.
   */
  for (const width of [480, 720] as const) {
    test(`${width} points wide and 480 high at the largest size: the words keep to a fifth of the window, the first line is clear, and the keys reach the end`, async ({
      page
    }) => {
      await openWindow(page, width, LARGEST, 480)
      await page.evaluate((reason) => {
        window.krTestHost?.setConnected(false, reason)
      }, LONG_REASON)
      await expect(wordsOf(page)).toHaveAttribute('data-more', 'true')
      const read = await page.evaluate(() => {
        const element = document.querySelector('.topbar .connection') as HTMLElement
        const style = getComputedStyle(element)
        const fade = /calc\(100% - ([\d.]+)px\)/.exec(style.maskImage || style.webkitMaskImage || '')
        return {
          box: element.clientHeight,
          more: element.scrollHeight - element.clientHeight,
          line: parseFloat(style.lineHeight),
          fade: fade ? parseFloat(fade[1] ?? 'NaN') : Number.NaN,
          bar: (document.querySelector('.topbar') as HTMLElement).getBoundingClientRect().height,
          window: window.innerHeight
        }
      })
      expect(read.window, 'the window is the smallest one').toBe(480)
      expect(read.box, 'the words keep to a fifth of the window').toBeLessThanOrEqual(0.2 * read.window + 1)
      expect(read.bar, `the bar keeps to ${BAR_SHARE * 100} % of the window`).toBeLessThanOrEqual(BAR_SHARE * read.window)
      expect(read.box, 'the first line is whole').toBeGreaterThanOrEqual(read.line - 1)
      expect(read.box - read.fade, 'the first line is clear of the fade').toBeGreaterThanOrEqual(read.line - 1)
      expect(read.more, 'more of the reason lies below what is shown').toBeGreaterThan(0)

      const words = wordsOf(page)
      await menuOf(page).focus()
      await page.keyboard.press(tabKeys().forward)
      await expect(words, 'the Tab after the control reaches the words').toBeFocused()
      await expect
        .poll(async () => {
          await page.keyboard.press('ArrowDown')
          return (await shown(page)).scrolled
        }, 'an arrow key scrolls the words')
        .toBeGreaterThan(0)
      await expect
        .poll(async () => {
          await page.keyboard.press('End')
          return (await shown(page)).more
        }, 'at the end nothing follows')
        .toBe('false')
      const end = await shown(page)
      expect(end.mask, 'at the end there is no fade').toBe('none')
      expect(end.scrolled + read.box, 'the whole reason has been scrolled through').toBeGreaterThanOrEqual(read.box + read.more - 1)
    })
  }

  test('a short reason at the largest size fits its window: no stop, no role and no fade', async ({ page }) => {
    await openWindow(page, 480, LARGEST)
    await page.evaluate((reason) => {
      window.krTestHost?.setConnected(false, reason)
    }, SHORT_REASON)
    await expect(wordsOf(page)).toContainText('not running')
    await expect(wordsOf(page)).not.toHaveAttribute('tabindex', /.*/)
    const state = await shown(page)
    expect(state.more).toBeNull()
    expect(state.mask).toBe('none')
  })
})

test.describe('the strip of the page beside the open drawer', () => {
  test('a classic scrollbar does not narrow it: the drawer is measured from its own box, not from the window', async ({ baseURL }) => {
    // WebKit on a Mac draws overlay scrollbars, which take no room whatever the style says: only
    // Chromium can show the classic one that a person on Windows or Linux has.
    test.skip(test.info().project.name === 'webkit', 'no classic scrollbar in WebKit on this machine')
    // The browser that the tests drive hides its scrollbars, so this case drives a browser of its own.
    const browser = await chromium.launch({ ignoreDefaultArgs: ['--hide-scrollbars'] })
    try {
      const page = await (await browser.newContext({ baseURL })).newPage()
      await openWindow(page, 480, LARGEST)
      await page.addStyleTag({ content: 'html::-webkit-scrollbar { width: 15px; }' })
      expect(
        await page.evaluate(() => window.innerWidth - document.documentElement.clientWidth),
        'the page has a scrollbar that takes room'
      ).toBeGreaterThan(0)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await expect.poll(() => sidebarLeft(page)).toBe(0)
      const drawer = await rectangleOf(drawerOf(page))
      const room = await page.evaluate(() => document.documentElement.clientWidth)
      expect(room - drawer.width, 'the strip of the page that a press closes the drawer from is 48 points').toBeGreaterThanOrEqual(47.5)
    } finally {
      await browser.close()
    }
  })
})

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
    // Narrowed again, the drawer is closed and ready, nothing travelled to put it there, and the
    // focus, which the sidebar's item has, is on "Menu".
    await page.getByRole('button', { name: /^Hosts/ }).focus()
    await watchTravel(page)
    await page.setViewportSize({ width: 600, height: HEIGHT })
    await expect(menuOf(page), 'the sidebar item that had the focus hands it to "Menu"').toBeFocused()
    await expectDrawnInWindow(menuOf(page), 'the focus on "Menu"')
    await expect(menuOf(page)).toHaveAttribute('aria-expanded', 'false')
    await expect(drawerOf(page)).toBeHidden()
    await expect.poll(() => sidebarLeft(page)).toBeLessThanOrEqual(-238)
    expect(await travelOf(page), 'a window that changes form again moves the sidebar to its closed place without a transition').toEqual([])
    expect(await travelOf(page, 'opacity'), 'and fades nothing').toEqual([])
  })
})

/**
 * A window widened past 720 points takes "Menu" and "Close menu" away. Whatever of them had the focus,
 * and whatever was to return the focus to them, goes to the item of the destination that is shown.
 */
test.describe('the focus when the window widens over the drawer', () => {
  const currentItem = (page: Page): Locator => page.locator('.sidebar [aria-current="page"]')

  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points: "Close menu" had the focus, and the shown destination's item has it now`, async ({ page }) => {
      await openWindow(page, width, ratio)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await closeOf(page).focus()
      await expect(closeOf(page)).toBeFocused()
      await page.setViewportSize({ width: 800, height: HEIGHT })
      await expect(menuOf(page)).toHaveCount(0)
      await expect(currentItem(page), 'the focus is on the item of the destination that is shown').toBeFocused()
      await expect(currentItem(page)).toHaveText(/^Attention/)
    })

    test(`${width} points: "Menu" had the focus, and the shown destination's item has it now`, async ({ page }) => {
      await openWindow(page, width, ratio)
      await menuOf(page).focus()
      await expect(menuOf(page)).toBeFocused()
      await page.setViewportSize({ width: 800, height: HEIGHT })
      await expect(menuOf(page)).toHaveCount(0)
      await expect(currentItem(page), 'the focus is on the item of the destination that is shown').toBeFocused()
    })

    test(`${width} points: Account was opened from the drawer, and closing it after the window widened returns to the item`, async ({
      page
    }) => {
      await openWindow(page, width, ratio)
      await menuOf(page).click()
      await itemOf(page, /^Account/).click()
      const sheet = page.getByRole('dialog', { name: 'Account' })
      await expect(sheet).toBeVisible()
      await page.setViewportSize({ width: 800, height: HEIGHT })
      await expect(menuOf(page)).toHaveCount(0)
      await page.keyboard.press('Escape')
      await expect(sheet).toBeHidden()
      await expect(currentItem(page), 'the focus returns to the item of the destination that is shown').toBeFocused()
    })
  }
})

/**
 * The open drawer's focus listener goes with the drawer. A window widened past 720 points while the
 * drawer is open, on a web view without `inert`, takes the drawer away and leaves the sidebar
 * standing beside the page; a focus that the person then puts on the page stays where they put it,
 * and is not sent to the sidebar's first control by a listener that outlived the drawer. Only a
 * widening shows it: a drawer that closes while the window is narrow is hidden at once, and a hidden
 * control takes no focus, so a listener left behind there has nothing to send the focus to.
 */
test.describe('the open drawer\'s focus listener when the window widens over it, on a web view without the inert attribute', () => {
  test('600 points, with no inert: after the window widened over the open drawer, a focus put on the page stays where the person put it', async ({
    page
  }) => {
    await withoutInert(page)
    await openWindow(page, 600)
    await menuOf(page).click()
    await expect(drawerOf(page)).toBeVisible()
    await page.setViewportSize({ width: 800, height: HEIGHT })
    await expect(menuOf(page), 'the window is wide: there is no "Menu"').toHaveCount(0)
    await expect(drawerOf(page), 'there is no open drawer').toHaveCount(0)
    expect(
      await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar') as Element).position),
      'the sidebar stands beside the page'
    ).toBe('sticky')
    await page.locator('main').focus()
    await expect(page.locator('main'), 'the focus stays where the person put it').toBeFocused()
  })
})

/**
 * A window narrowed below 720 points puts the sidebar out of reach: it is the closed drawer, and
 * "Menu" is the control that stands for it. Whatever of the sidebar had the focus, and whatever was
 * to return the focus to it, goes to "Menu", which is drawn inside the window with nothing over it.
 * The drawer does not open: a resize is not an act that the drawer answers.
 */
test.describe('the focus when the window narrows over the standing sidebar', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    for (const [what, control] of [
      ['the item of the destination that is shown', '.sidebar [aria-current="page"]'],
      ['the Account item', '.sidebar .nav-item-account']
    ] as const) {
      test(`${width} points: ${what} had the focus, and "Menu" has it now`, async ({ page }) => {
        await openWindow(page, 800, ratio)
        await expect(menuOf(page)).toHaveCount(0)
        await page.locator(control).focus()
        await expect(page.locator(control)).toBeFocused()
        await page.setViewportSize({ width, height: HEIGHT })
        await expect(menuOf(page), 'the focus is on "Menu"').toBeFocused()
        await expectDrawnInWindow(menuOf(page), 'the focus on "Menu"')
        await expect(menuOf(page), 'the drawer did not open').toHaveAttribute('aria-expanded', 'false')
        await expectDrawerClosed(page)
      })
    }

    test(`${width} points: Account was opened from the wide sidebar, and closing it after the window narrowed returns to "Menu"`, async ({
      page
    }) => {
      await openWindow(page, 800, ratio)
      // By the keyboard: a press does not give a button the focus in every engine, and where it has
      // none to give there is no control that the focus could return to.
      await page.locator('.sidebar .nav-item-account').focus()
      await page.keyboard.press('Enter')
      const sheet = page.getByRole('dialog', { name: 'Account' })
      await expect(sheet).toBeVisible()
      await page.setViewportSize({ width, height: HEIGHT })
      await expect(menuOf(page)).toBeVisible()
      await page.keyboard.press('Escape')
      await expect(sheet).toBeHidden()
      await expect(menuOf(page), 'the focus returns to "Menu"').toBeFocused()
      await expectDrawnInWindow(menuOf(page), 'the focus on "Menu"')
      await expect(menuOf(page), 'the drawer did not open').toHaveAttribute('aria-expanded', 'false')
      await expectDrawerClosed(page)
    })
  }
})

/** The query that decides the narrow form, as the application writes it. */
const NARROW_QUERY = '(max-width: 720px)'

interface NarrowControl {
  hold(): void
  release(): void
  force(value: boolean | null): void
  tell(): void
}

/**
 * Puts the narrow query in the test's hand. An engine decides by itself whether the window's new
 * form is drawn before the page is told of the change or after, and a test cannot ask for either.
 * Here the telling is held back while the engine draws (`hold`, then `release`), or the page is told
 * while the window still has its old form (`force` sets what the query answers, `tell` sends the
 * change to those that listen). While a form is forced, the engine's own telling is dropped; `force`
 * with null gives the query back its own answer. While the telling is held, the page that is drawn
 * again for another reason still reads the old form, so that nothing but the telling changes it: only
 * the query that listens for the change answers with the new one.
 */
async function controlNarrowQuery(page: Page): Promise<void> {
  await page.addInitScript((text) => {
    const state = {
      forced: null as boolean | null,
      pinned: null as boolean | null,
      holding: false,
      queue: [] as (() => void)[],
      told: new Set<() => void>(),
      listening: new WeakSet<object>()
    }
    const real = window.matchMedia.bind(window)
    window.matchMedia = (query: string): MediaQueryList => {
      const list = real(query)
      if (query !== text) return list
      Object.defineProperty(list, 'matches', {
        get: () =>
          state.forced ?? (state.pinned !== null && !state.listening.has(list) ? state.pinned : Reflect.get(MediaQueryList.prototype, 'matches', list))
      })
      const gates = new Map<unknown, { gate: () => void; deliver: () => void }>()
      const add = list.addEventListener.bind(list)
      const remove = list.removeEventListener.bind(list)
      Object.defineProperty(list, 'addEventListener', {
        value: (type: string, listener: unknown, options?: unknown): void => {
          if (type !== 'change' || typeof listener !== 'function') {
            add(type, listener as EventListener, options as AddEventListenerOptions)
            return
          }
          const deliver = (): void => {
            ;(listener as (event: Event) => void).call(list, new Event('change'))
          }
          const gate = (): void => {
            if (state.forced !== null) return
            if (state.holding) state.queue.push(deliver)
            else deliver()
          }
          gates.set(listener, { gate, deliver })
          state.listening.add(list)
          state.told.add(deliver)
          add('change', gate)
        }
      })
      Object.defineProperty(list, 'removeEventListener', {
        value: (type: string, listener: unknown, options?: unknown): void => {
          const found = gates.get(listener)
          if (type !== 'change' || found === undefined) {
            remove(type, listener as EventListener, options as EventListenerOptions)
            return
          }
          gates.delete(listener)
          state.told.delete(found.deliver)
          remove('change', found.gate)
        }
      })
      return list
    }
    const control: NarrowControl = {
      hold: () => {
        state.holding = true
        state.pinned = Reflect.get(MediaQueryList.prototype, 'matches', real(text))
      },
      release: () => {
        state.holding = false
        state.pinned = null
        for (const deliver of state.queue.splice(0)) deliver()
      },
      force: (value) => {
        state.forced = value
      },
      tell: () => {
        for (const deliver of state.told) deliver()
      }
    }
    ;(window as unknown as { krNarrow: NarrowControl }).krNarrow = control
  }, NARROW_QUERY)
}

/** Holds back or lets through what the narrow query tells the page, or tells it now. */
function narrowQuery(page: Page, action: 'hold' | 'release' | 'tell'): Promise<void> {
  return page.evaluate((what) => {
    ;(window as unknown as { krNarrow: NarrowControl }).krNarrow[what]()
  }, action)
}

/** Sets what the narrow query answers, or, with null, gives it back its own answer. */
function forceNarrow(page: Page, value: boolean | null): Promise<void> {
  return page.evaluate((wanted) => {
    ;(window as unknown as { krNarrow: NarrowControl }).krNarrow.force(wanted)
  }, value)
}

/** The window has been drawn in its narrow form: the sidebar is the closed drawer, out of sight. */
async function expectNarrowFormDrawn(page: Page): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => getComputedStyle(document.querySelector('aside.sidebar') as Element).visibility), 'the window is drawn narrow')
    .toBe('hidden')
}

/**
 * The two orders in which an engine can draw a window's new form and tell the page of the change,
 * each made by the test. Drawn first: the sidebar is out of sight and the page has not been told
 * (there is no "Menu" yet); an engine of this order has already taken the focus off the control
 * that the new form hides. Told first: the page has its narrow form and the window has not.
 */
test.describe('the focus when the window narrows, whichever of the drawing and the telling comes first', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    for (const [what, control] of [
      ['the item of the destination that is shown', '.sidebar [aria-current="page"]'],
      ['the Account item', '.sidebar .nav-item-account']
    ] as const) {
      test(`${width} points: the window is drawn narrow before the page is told, and ${what} had the focus: "Menu" has it`, async ({
        page
      }) => {
        await controlNarrowQuery(page)
        await openWindow(page, 800, ratio)
        await page.locator(control).focus()
        await expect(page.locator(control)).toBeFocused()
        await narrowQuery(page, 'hold')
        await page.setViewportSize({ width, height: HEIGHT })
        await expectNarrowFormDrawn(page)
        await expect(menuOf(page), 'the page has not been told: there is no "Menu"').toHaveCount(0)
        await narrowQuery(page, 'release')
        await expect(menuOf(page), 'the focus is on "Menu"').toBeFocused()
        await expectDrawnInWindow(menuOf(page), 'the focus on "Menu"')
        await expect(menuOf(page), 'the drawer did not open').toHaveAttribute('aria-expanded', 'false')
        await expectDrawerClosed(page)
      })

      test(`${width} points: the page is told before the window is drawn narrow, and ${what} had the focus: "Menu" has it`, async ({
        page
      }) => {
        await controlNarrowQuery(page)
        await openWindow(page, 800, ratio)
        await page.locator(control).focus()
        await expect(page.locator(control)).toBeFocused()
        await forceNarrow(page, true)
        await narrowQuery(page, 'tell')
        await expect(menuOf(page), 'the page has its narrow form and the focus is on "Menu"').toBeFocused()
        expect(await page.evaluate(() => window.innerWidth), 'the window has not changed').toBe(800)
        await page.setViewportSize({ width, height: HEIGHT })
        await forceNarrow(page, null)
        await expect(menuOf(page), 'the focus stays on "Menu" as the window is drawn narrow').toBeFocused()
        await expectDrawnInWindow(menuOf(page), 'the focus on "Menu"')
        await expect(menuOf(page), 'the drawer did not open').toHaveAttribute('aria-expanded', 'false')
        await expectDrawerClosed(page)
      })
    }
  }
})

/**
 * What had the focus as the window changed form is kept for that change, and for no other. A person
 * who put the focus on the page after the new form was drawn, and before the page was told, keeps
 * it there; and a record that a change made without changing the page's form is not used by the
 * next change, which finds the focus where the person has put it.
 */
test.describe('the focus that the person moved while the window changed form stays where it is', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points: the person put the focus on the page after the window was drawn narrow and before the page was told`, async ({
      page
    }) => {
      await controlNarrowQuery(page)
      await openWindow(page, 800, ratio)
      await page.locator('.sidebar [aria-current="page"]').focus()
      await narrowQuery(page, 'hold')
      await page.setViewportSize({ width, height: HEIGHT })
      await expectNarrowFormDrawn(page)
      await page.locator('main').focus()
      await expect(page.locator('main')).toBeFocused()
      await narrowQuery(page, 'release')
      await expect(menuOf(page), 'the page is told and has its narrow form').toBeVisible()
      await expect(page.locator('main'), 'the focus stays where the person put it').toBeFocused()
    })

    test(`${width} points: a change that left the page's form as it was leaves nothing for the next one to use`, async ({ page }) => {
      await controlNarrowQuery(page)
      await openWindow(page, 800, ratio)
      await page.locator('.sidebar [aria-current="page"]').focus()
      await narrowQuery(page, 'hold')
      await page.setViewportSize({ width, height: HEIGHT })
      await expectNarrowFormDrawn(page)
      // Whichever engine drew the form, the focus is off the control that the form hides.
      await page.evaluate(() => {
        ;(document.activeElement as HTMLElement | null)?.blur()
      })
      await page.setViewportSize({ width: 800, height: HEIGHT })
      await expect
        .poll(() => page.evaluate(() => getComputedStyle(document.querySelector('aside.sidebar') as Element).visibility))
        .toBe('visible')
      await narrowQuery(page, 'release')
      await expect(menuOf(page), 'the page was told of both changes and was never narrow').toHaveCount(0)
      await page.locator('main').focus()
      await expect(page.locator('main')).toBeFocused()
      await page.setViewportSize({ width, height: HEIGHT })
      await expect(menuOf(page), 'the window narrows again and the page has its narrow form').toBeVisible()
      await expect(page.locator('main'), 'the focus stays where the person put it').toBeFocused()
    })
  }
})

/** What a host asks the owner to confirm, for the message that says so. */
const REQUEST = {
  ceremony: 'touch_id' as const,
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
      placement: null,
      reading: null,
      expires_at_ms: Date.now() + 600_000,
      checkable: true
    }
  ]
}

test.describe('a message that asks for confirmation while the drawer is open', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points: its action closes the drawer and puts the focus on the request`, async ({ page }) => {
      await openWindow(page, width, ratio)
      await menuOf(page).click()
      await itemOf(page, 'Hosts').click()
      await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText(/^Hosts/)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await page.evaluate((view) => {
        window.krTestHost?.setConfirmations(view)
      }, REQUEST)
      const toast = page.locator('.toast')
      await expect(toast).toContainText('needs your confirmation')
      await toast.getByRole('button', { name: 'Review' }).click()
      await expect(drawerOf(page), 'the drawer is closed').toBeHidden()
      await expectDrawerClosed(page)
      await expect(page.locator('.sidebar [aria-current="page"]'), 'the view is the one that holds the request').toHaveText(/^Attention/)
      await expect(page.getByTestId('confirmation-row'), 'the request holds the focus').toBeFocused()
      expect(await page.evaluate(() => (document.querySelector('.workspace') as HTMLElement).inert), 'the page is not inert').toBe(false)
    })
  }
})

/**
 * The same action where the web view has no `inert`: the focus listener of the open drawer is in
 * place, and the page behind is not inert. The drawer is gone and the listener with it before the
 * request's row takes the focus, so the row keeps it.
 */
test.describe('a message that asks for confirmation while the drawer is open, on a web view without the inert attribute', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points, with no inert: its action closes the drawer and puts the focus on the request`, async ({ page }) => {
      await withoutInert(page)
      await openWindow(page, width, ratio)
      await menuOf(page).click()
      await itemOf(page, 'Hosts').click()
      await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText(/^Hosts/)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await page.evaluate((view) => {
        window.krTestHost?.setConfirmations(view)
      }, REQUEST)
      const toast = page.locator('.toast')
      await expect(toast).toContainText('needs your confirmation')
      await toast.getByRole('button', { name: 'Review' }).click()
      await expect(drawerOf(page), 'the drawer is closed').toBeHidden()
      await expectDrawerClosed(page)
      await expect(page.locator('.sidebar [aria-current="page"]'), 'the view is the one that holds the request').toHaveText(/^Attention/)
      await expect(page.getByTestId('confirmation-row'), 'the request holds the focus').toBeFocused()
    })
  }
})

/**
 * A web view without `inert` leaves the page behind the open drawer in the tab order. The hook sends
 * the focus that lands there into the drawer, and leaves a message's own controls where they are: a
 * press on a message's action that ends over its plain words does not use the action and leaves the
 * focus on the message, and no Tab or Shift+Tab from there ends on the page behind.
 */
test.describe('the open drawer on a web view without the inert attribute: the keyboard from a message', () => {
  for (const [width, ratio] of [
    [600, 1],
    [480, LARGEST]
  ] as const) {
    test(`${width} points: after a press on a message's action that ended over its words, no key reaches the page behind`, async ({
      page
    }) => {
      await withoutInert(page)
      await openWindow(page, width, ratio)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await page.evaluate((view) => {
        window.krTestHost?.setConfirmations(view)
      }, REQUEST)
      const toast = page.locator('.toast')
      await expect(toast).toContainText('needs your confirmation')
      const review = toast.getByRole('button', { name: 'Review' })
      const action = await rectangleOf(review)
      const words = await rectangleOf(toast.locator('.toast-text'))
      await page.mouse.move(action.x + action.width / 2, action.y + action.height / 2)
      await page.mouse.down()
      await page.mouse.move(words.x + words.width / 2, words.y + words.height / 2, { steps: 4 })
      await page.mouse.up()
      await expect(drawerOf(page), 'the press did not use the action: the drawer is still open').toBeVisible()
      // An engine that does not give a button the focus on a press has it on the page's body here.
      if (!(await review.evaluate((element) => element === document.activeElement))) await review.focus()
      await expect(review, 'the focus is on the message').toBeFocused()

      const place = (): Promise<'drawer' | 'message' | 'behind' | 'elsewhere'> =>
        page.evaluate(() => {
          const active = document.activeElement
          if (active?.closest('aside.sidebar') != null) return 'drawer'
          if (active?.closest('.toast') != null) return 'message'
          if (active?.closest('.workspace, .skip-link') != null) return 'behind'
          return 'elsewhere'
        })
      for (const key of [tabKeys().back, tabKeys().forward, tabKeys().back, tabKeys().back, tabKeys().forward, tabKeys().forward]) {
        await page.keyboard.press(key)
        expect(await place(), `${key} ends inside the drawer, on the message or on nothing of the page`).not.toBe('behind')
      }
      // Shift+Tab from the message used to walk into the page behind; it ends in the drawer now.
      await review.focus()
      await page.keyboard.press(tabKeys().back)
      expect(await place(), 'Shift+Tab from the message ends inside the drawer').toBe('drawer')
      await expect(closeOf(page), 'the drawer\'s own first control has it').toBeFocused()
    })
  }
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
      const scrolled = await settledScroll(page)
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
      await watchWheels(page)
      for (const [x, delta] of [
        [width - 8, 400],
        [width - 8, -400],
        [20, 600],
        [20, 600],
        [20, -2000]
      ] as const) {
        await page.mouse.move(x, HEIGHT / 2)
        const before = await wheelsDelivered(page)
        await page.mouse.wheel(0, delta)
        // The wheel reached the page, and the page has stopped: what it reads then is what the hold left.
        await expect.poll(() => wheelsDelivered(page), `the wheel of ${delta} at ${x} reached the page`).toBeGreaterThan(before)
        expect(await settledScroll(page), `the page after a wheel of ${delta} at ${x}`).toBe(scrolled)
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
  test('the used mark of the drawer goes with the narrow form: absent when wide, "false" when narrowed again', async ({ page }) => {
    await openWindow(page, 600)
    const sidebar = page.locator('aside.sidebar')
    await expect(sidebar, 'a drawer nobody has opened is not used').toHaveAttribute('data-used', 'false')
    await menuOf(page).click()
    await expect(drawerOf(page)).toBeVisible()
    await expect(sidebar, 'a drawer a person has opened is used').toHaveAttribute('data-used', 'true')
    await page.setViewportSize({ width: 800, height: HEIGHT })
    await expect(menuOf(page)).toHaveCount(0)
    expect(await sidebar.getAttribute('data-used'), 'the wide form has no mark').toBeNull()
    await page.setViewportSize({ width: 600, height: HEIGHT })
    await expect(menuOf(page)).toBeVisible()
    await expect(sidebar, 'narrowed again, the drawer is not yet used').toHaveAttribute('data-used', 'false')
    await menuOf(page).click()
    await expect(drawerOf(page)).toBeVisible()
    await expect(sidebar, 'opened again by a person, it is used').toHaveAttribute('data-used', 'true')
  })

  test('a pointer opens the drawer by travel from the edge it rests against, and a keyboard does not', async ({ page }) => {
    await openWindow(page, 600)
    const rest = await sidebarLeft(page)
    expect(rest, 'closed, the drawer is out of the window on its own side').toBeLessThanOrEqual(-238)

    await watchTravel(page)
    await menuOf(page).click()
    await expectTravel(page, OPEN_SECONDS, 'a pointer-driven open travels')
    expect(await sidebarLeft(page), 'open, the drawer rests against the leading edge').toBe(0)

    // A press on the scrim closes it, and it goes out on the exit's time, to the place it came from.
    await watchTravel(page)
    await page.mouse.click(594, HEIGHT / 2)
    await expectTravel(page, CLOSE_SECONDS, 'a pointer-driven close travels')
    expect(await sidebarLeft(page), 'closed, the drawer is out of the window on its own side again').toBe(rest)
    await menuOf(page).focus()
    await watchTravel(page)
    await page.keyboard.press('Enter')
    await expect.poll(() => sidebarLeft(page)).toBe(0)
    expect(await travelOf(page), 'a keyboard-driven open runs no transition of the transform').toEqual([])

    await watchTravel(page)
    await page.keyboard.press('Escape')
    await expect.poll(() => sidebarLeft(page)).toBe(rest)
    expect(await travelOf(page), 'a keyboard-driven close runs no transition of the transform').toEqual([])
  })

  test('a window narrowed from a wide one meets the drawer closed, and nothing travels', async ({ page }) => {
    await openWindow(page, 1280)
    await watchTravel(page)
    await page.setViewportSize({ width: 600, height: HEIGHT })
    await expect(menuOf(page)).toBeVisible()
    await expect.poll(() => sidebarLeft(page), 'closed, the drawer is out of the window on its own side').toBeLessThanOrEqual(-238)
    expect(await travelOf(page), 'a change of the window moves the sidebar to its closed place without a transition').toEqual([])
  })

  test.describe('with reduced motion asked for', () => {
    test.use({ reducedMotion: 'reduce' })

    test('nothing travels when the drawer opens or closes, and it fades to its end', async ({ page }) => {
      await openWindow(page, 600)
      const rest = await sidebarLeft(page)
      const opacity = (): Promise<string> =>
        page.evaluate(() => getComputedStyle(document.querySelector('aside.sidebar') as Element).opacity)
      expect(await opacity(), 'closed, the drawer is not drawn').toBe('0')
      await watchTravel(page)
      await menuOf(page).click()
      await expect(drawerOf(page)).toBeVisible()
      await expectTravel(page, FADE_SECONDS, 'the drawer fades in', 'opacity')
      expect(await opacity(), 'open, the drawer is drawn in full').toBe('1')
      expect(await sidebarLeft(page), 'open, the drawer is where it rests').toBe(rest)
      await watchTravel(page)
      await page.mouse.click(594, HEIGHT / 2)
      await expect(drawerOf(page)).toBeHidden()
      expect(await sidebarLeft(page), 'closed, the drawer is where it rests').toBe(rest)
      await expectTravel(page, FADE_SECONDS, 'the drawer fades out', 'opacity')
      expect(await opacity(), 'closed again, the drawer is not drawn').toBe('0')
      await expectDrawerClosed(page)
      expect(await travelOf(page), 'a pointer-driven open and close run no transition of the transform').toEqual([])
    })
  })
})

/**
 * A web view without `inert` (the oldest of the baselines): the shell's attribute does nothing there,
 * so the closed drawer is out of reach by the page's own rules, or by nothing.
 */
for (const [reduced, how] of [
  [false, 'with the ordinary motion'],
  [true, 'with reduced motion asked for']
] as const) {
  test.describe(`the closed drawer on a web view without the inert attribute, ${how}`, () => {
    test.use({ reducedMotion: reduced ? 'reduce' : 'no-preference' })

    for (const [width, ratio] of [
      [600, 1],
      [480, LARGEST]
    ] as const) {
      test(`${width} points: it is out of reach until it is asked for, works when it is, and is out of reach again`, async ({
        page
      }) => {
        await withoutInert(page)
        await openWindow(page, width, ratio)
        expect(
          await page.evaluate(() => ({
            property: 'inert' in HTMLElement.prototype,
            attribute: document.querySelector('aside.sidebar')?.hasAttribute('inert')
          })),
          'this page has no inert, as the web view it stands for'
        ).toEqual({ property: false, attribute: false })
        const menu = menuOf(page)
        await expect(menu).toBeVisible()
        await expectDrawerClosed(page)
        expect.soft(await tabStopsInDrawer(page, 8), 'a Tab from the start of the page never lands in the closed drawer').toBe(0)

        // A press on the control reaches the control, also where the closed drawer rests over it.
        const box = await rectangleOf(menu)
        const x = box.x + box.width / 2
        const y = box.y + box.height / 2
        expect
          .soft(
            await page.evaluate(([px, py]) => document.elementFromPoint(px, py)?.closest('button')?.textContent, [x, y]),
            'the point on the control is the control, and not the closed drawer'
          )
          .toBe('Menu')
        await page.mouse.click(x, y)
        await expect(drawerOf(page)).toBeVisible()
        await expect(closeOf(page)).toBeVisible()
        await expect(drawerOf(page).locator('[aria-current="page"]'), 'the focus goes to the destination that is shown').toBeFocused()

        // The page behind is not inert here, so the drawer's own Tab cycle is what holds the keyboard.
        for (const key of [tabKeys().forward, tabKeys().back]) {
          for (let press = 0; press < 13; press += 1) {
            await page.keyboard.press(key)
            expect(await focusInDrawer(page), `${key} ${press + 1} stays inside the drawer`).toBe(true)
          }
        }

        await closeOf(page).click()
        await expect(drawerOf(page)).toBeHidden()
        await expectDrawerClosed(page)
        await expect(menu).toBeFocused()
        expect(await tabStopsInDrawer(page, 8), 'closed again, a Tab never lands in the drawer').toBe(0)
      })
    }
  })
}

/**
 * The drawer's exit lasts 160 ms, 120 ms with reduced motion. The cases that follow make it last
 * 3 s, read the drawer straight after the press and wait for no hidden state. A read made within
 * those 3 s is inside the exit; a stall of the machine of more than that, between the press and the
 * read, would let the exit end first, and these cases are not proof against it. Where the web view has `inert`
 * the drawer still goes out by its transition and is out of reach at once; where it has none it has
 * no exit, and is hidden at once.
 */
for (const inert of [false, true]) {
  for (const [reduced, how] of [
    [false, 'with the ordinary motion'],
    [true, 'with reduced motion asked for']
  ] as const) {
    test.describe(`straight after a press closed the drawer, ${inert ? 'with' : 'without'} the inert attribute, ${how}`, () => {
      test.use({ reducedMotion: reduced ? 'reduce' : 'no-preference' })

      for (const [width, ratio] of [
        [600, 1],
        [480, LARGEST]
      ] as const) {
        test(`${width} points: a Tab reaches no control of the drawer and no reader is told of them`, async ({ page }) => {
          if (!inert) await withoutInert(page)
          await openWindow(page, width, ratio)
          // Only the exit is lost where there is no `inert`: the drawer still comes in by its travel.
          await watchTravel(page)
          await menuOf(page).click()
          await expect(drawerOf(page)).toBeVisible()
          if (reduced) await expectTravel(page, FADE_SECONDS, 'the drawer fades in', 'opacity')
          else await expectTravel(page, OPEN_SECONDS, 'a pointer-driven open travels in')
          await page.addStyleTag({ content: 'html:root { --state: 3s !important; --press: 3s !important; }' })
          await closeOf(page).click()
          await expect(menuOf(page), 'the focus is back on the control that opened it').toBeFocused()

          // Nothing is awaited from here: the exit is running or, without `inert`, it never starts.
          const drawer = await page.evaluate(() => {
            const element = document.querySelector('aside.sidebar') as HTMLElement & { inert?: boolean }
            const style = getComputedStyle(element)
            return {
              visibility: style.visibility,
              pointerEvents: style.pointerEvents,
              inert: element.inert === true,
              reached: [4, 60, 120, 180, 234].flatMap((x) =>
                [20, 100, 300, 500, 700].filter((y) => document.elementFromPoint(x, y)?.closest('aside.sidebar') != null)
              )
            }
          })
          expect(drawer.pointerEvents, 'it takes no press').toBe('none')
          expect(drawer.reached, 'no point of the window reaches it').toEqual([])
          if (inert) {
            expect(drawer.inert, 'the web view makes it inert at once').toBe(true)
            expect(drawer.visibility, 'its exit is still running, as it is where inert exists').toBe('visible')
          } else {
            expect(drawer.visibility, 'it has no exit: it is hidden at once').toBe('hidden')
            expect(await page.getByRole('button', { name: 'Close menu' }).count(), 'its controls are not in the accessibility tree').toBe(0)
            expect(await page.locator('body').ariaSnapshot(), 'a reader is not told of the drawer').not.toContain('Close menu')
          }
          expect(await tabStopsInDrawer(page, 8), 'a Tab from the start of the page never lands in the drawer').toBe(0)
          await menuOf(page).focus()
          await page.keyboard.press(tabKeys().forward)
          expect(await focusInDrawer(page), 'a Tab from Menu does not enter the drawer').toBe(false)

          // A first open and close leaves the end state that an engine with `inert` has.
          await expectDrawerClosed(page)
          await expect(menuOf(page)).toHaveAttribute('aria-expanded', 'false')
          await expect(page.getByTestId('drawer-scrim')).toHaveAttribute('data-open', 'false')
          expect(await tabStopsInDrawer(page, 8), 'at the end a Tab never lands in the drawer').toBe(0)
        })
      }
    })
  }
}

test.describe('under a right-to-left root', () => {
  test('the wide sidebar and the drawer both stand and travel at the end the page starts from', async ({ page }) => {
    await openWindow(page, 1280)
    await page.evaluate(() => {
      document.documentElement.dir = 'rtl'
    })
    const wide = await rectangleOf(page.locator('.sidebar'))
    expect(wide.x + wide.width, 'the wide sidebar stands against the right edge').toBe(1280)

    await watchTravel(page)
    await page.setViewportSize({ width: 600, height: HEIGHT })
    const menu = menuOf(page)
    await expect(menu).toBeVisible()
    const was = await rectangleOf(menu)
    expect(was.x + was.width, 'the control is at the right end of the top bar').toBeGreaterThan(600 - 40)
    // Narrowed from a wide window, the sidebar is at the closed place at once, with no travel.
    await expect.poll(() => sidebarLeft(page), 'closed, the drawer is out of the window on the right').toBe(600)
    expect(await travelOf(page), 'a change of the window moves the sidebar to its closed place without a transition').toEqual([])
    await watchTravel(page)
    await startSampling(page)
    await menu.click()
    await expect(drawerOf(page)).toBeVisible()
    await expectTravel(page, OPEN_SECONDS, 'a pointer-driven open travels')
    await expect.poll(() => sidebarLeft(page)).toBe(600 - 238)
    const samples = await stopSampling(page)
    expect(Math.min(...samples), 'the drawer never goes past its open place towards the left').toBeGreaterThanOrEqual(600 - 238)
    const now = await rectangleOf(closeOf(page))
    // The leading corner is the right one: the open control's right edge, top and height are the close control's.
    expect(Math.abs(now.x + now.width - (was.x + was.width))).toBeLessThanOrEqual(1)
    expect(Math.abs(now.y - was.y)).toBeLessThanOrEqual(1)
    expect(Math.abs(now.height - was.height)).toBeLessThanOrEqual(1)
    expect(now.width).toBeGreaterThanOrEqual(was.width - 1)
  })
})

/**
 * The scroll wait of these cases fails when the page cannot show it is at rest in time. It is read on
 * a blank page: the frames it counts are stubbed, and so is the page's clock.
 */
test.describe('the cases\' own wait for the page to stop scrolling', () => {
  test('a page that draws no frame fails at the deadline, and says so', async ({ page }) => {
    await page.goto('about:blank')
    await page.evaluate(() => {
      window.requestAnimationFrame = () => 0
    })
    const started = Date.now()
    await expect(settledScroll(page, 300)).rejects.toThrow(/still scrolling after 300 ms/)
    expect(Date.now() - started, 'it did not wait for a frame that never comes').toBeLessThan(2500)
  })

  test('a quiet that is reached after the deadline is not a success', async ({ page }) => {
    await page.goto('about:blank')
    // The page's clock jumps past the deadline as the second frame is drawn: the three frames and the
    // 100 ms of quiet that follow are all there, and all late.
    await page.evaluate(() => {
      const now = performance.now.bind(performance)
      let skew = 0
      performance.now = () => now() + skew
      const frame = window.requestAnimationFrame.bind(window)
      let drawn = 0
      window.requestAnimationFrame = (callback) =>
        frame((time) => {
          drawn += 1
          if (drawn === 2) skew = 60_000
          callback(time)
        })
    })
    await expect(settledScroll(page, 3000)).rejects.toThrow(/still scrolling after 3000 ms/)
  })

  test('a page at rest settles at its position', async ({ page }) => {
    await page.goto('about:blank')
    await page.setContent('<div style="height: 3000px"></div>')
    await page.evaluate(() => {
      window.scrollTo(0, 240)
    })
    expect(await settledScroll(page)).toBe(240)
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
          await page.keyboard.press('Escape')
          await expect(drawerOf(page)).toBeHidden()
          await page.evaluate((reason) => {
            window.krTestHost?.setConnected(false, reason)
          }, SHORT_REASON)
          await expect(page.locator('.topbar .connection')).toContainText('not running')
          await page.screenshot({ path: shot(`${name}-closed-short-reason`) })
          await page.evaluate((reason) => {
            window.krTestHost?.setConnected(false, reason)
          }, LONG_REASON)
          await expect(page.locator('.topbar .connection')).toContainText('refused the connection')
          await page.screenshot({ path: shot(`${name}-closed-long-reason`) })
        })
      }
    }
  }
})
