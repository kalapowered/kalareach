/**
 * A button's label wraps by default.
 *
 * `.btn` lets its label wrap inside the button, breaks a word that is wider than the button's room,
 * and keeps the button inside the box that holds it, whatever the text size and the face. No caller
 * asks for it. The cases draw buttons with no attribute in the holders the product uses, in the real
 * stylesheet, and read them at the largest accessibility text size in the narrowest window of each
 * shell, and at the ordinary size, where a label that fits must keep the box it has when the label
 * is held on one line.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning, stopWrapping } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The widest face the layout cases use, with DejaVu Sans after it for the machine that has none. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

interface Form {
  readonly name: string
  readonly phone: boolean
  readonly width: number
  readonly height: number
}

/** The narrowest phone, and the desktop at the narrowest window that can open a sheet and at the shell's least. */
const FORMS: readonly Form[] = [
  { name: 'phone 320 wide', phone: true, width: 320, height: 720 },
  { name: 'desktop 480 wide', phone: false, width: 480, height: 800 },
  { name: 'desktop 721 wide', phone: false, width: 721, height: 800 }
]

const FIXTURE = '#wrap-fixture'

/** One button of a fixture: a label, and the class it is drawn with. */
interface Drawn {
  readonly label: string
  readonly className?: string
  readonly id?: string
}

/** One holder drawn the way the product draws it, with its buttons. */
interface Holder {
  readonly name: string
  readonly classes: string
  readonly style?: string
  readonly buttons: readonly (string | Drawn)[]
}

/** Opens the harness in `form` at `size` times the default text and puts `holders` over the page, in the real stylesheet. */
async function drawn(page: Page, form: Form, size: number, holders: readonly Holder[]): Promise<void> {
  await page.setViewportSize({ width: form.width, height: form.height })
  if (form.phone) {
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
    }, size)
  } else if (size !== 1) {
    await page.addInitScript((factor) => {
      document.addEventListener('DOMContentLoaded', () => {
        document.documentElement.style.fontSize = `${16 * factor}px`
      })
    }, size)
  }
  await page.goto(form.phone ? '/harness.html?surface=ios' : '/harness.html')
  await page.addStyleTag({ content: WIDE_FACE })
  await page.waitForSelector(form.phone ? '.m-shell' : '.app-shell')
  await page.evaluate(
    ([id, drawing]) => {
      const over = document.createElement('div')
      over.id = id
      over.style.cssText =
        'position:fixed;inset:0;overflow:auto;box-sizing:border-box;padding:16px;z-index:99999;background:var(--bg, #fff);color:var(--text, #000)'
      for (const one of drawing) {
        const box = document.createElement('div')
        box.className = one.classes
        box.dataset.case = one.name
        if (one.style !== undefined) box.style.cssText = one.style
        for (const each of one.buttons) {
          const spec = typeof each === 'string' ? { label: each } : each
          const button = document.createElement('button')
          button.type = 'button'
          button.className = 'className' in spec && spec.className !== undefined ? spec.className : 'btn'
          if ('id' in spec && spec.id !== undefined) button.id = spec.id
          if (button.className === 'icon-btn') button.setAttribute('aria-label', spec.label)
          button.textContent = spec.label
          box.append(button)
        }
        over.append(box)
      }
      document.body.append(over)
    },
    [FIXTURE.slice(1), holders] as const
  )
}

function holder(name: string, classes: string, buttons: readonly (string | Drawn)[], style?: string): Holder {
  return { name, classes, buttons, style }
}

const LONG = 'Keep it for the new conversation'
const NAME = 'sam-laptop-with-a-device-name-that-has-no-place-to-break'

/** Holders in which a button is drawn on its own, as a column holds it, a nowrap row, a wrapping row and a card. */
const BASIC: readonly Holder[] = [
  holder('nowrap row, one button', 'row', [LONG]),
  holder('column, one button', '', [`Invite ${NAME}`], 'display:flex;flex-direction:column;align-items:flex-start'),
  holder('wrapping row, three buttons', 'row wrap', ['Put it in its composer', 'Move it', 'Discard']),
  holder('block, one button', '', ['Back to the conversation'])
]

interface Found {
  readonly faults: readonly string[]
  readonly buttons: number
}

/**
 * What is wrong with the buttons under the fixture: a button outside the box of the holder it is in
 * (or of the fixture, to either side), a label drawn outside its own button, a button over another,
 * and, through the page's one measure of text that runs out of its box, a line of text past a box.
 */
async function measured(page: Page): Promise<Found> {
  const own = await page.evaluate((root) => {
    const faults: string[] = []
    const base = document.querySelector(root)
    if (base === null) return { faults: ['no fixture'], buttons: 0 }
    const room = base.getBoundingClientRect()
    let buttons = 0
    for (const holder of base.querySelectorAll('[data-case]')) {
      const name = holder.getAttribute('data-case') ?? 'holder'
      const box = holder.getBoundingClientRect()
      const each = Array.from(holder.querySelectorAll('.btn'))
      for (const button of each) {
        buttons += 1
        const b = button.getBoundingClientRect()
        const label = (button.textContent ?? '').trim().slice(0, 24)
        if (b.left < box.left - 0.5 || b.right > box.right + 0.5) faults.push(`${name}: "${label}" is outside its holder`)
        if (b.right > room.right + 0.5 || b.left < room.left - 0.5) faults.push(`${name}: "${label}" is outside the screen`)
        const range = document.createRange()
        range.selectNodeContents(button)
        for (const line of Array.from(range.getClientRects())) {
          if (line.width === 0) continue
          if (line.left < b.left - 0.5 || line.right > b.right + 0.5 || line.top < b.top - 0.5 || line.bottom > b.bottom + 0.5) {
            faults.push(`${name}: the label of "${label}" is drawn outside its button`)
            break
          }
        }
        for (const other of each) {
          if (other === button || other.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_PRECEDING) continue
          const o = other.getBoundingClientRect()
          if (Math.min(b.right, o.right) - Math.max(b.left, o.left) > 0.5 && Math.min(b.bottom, o.bottom) - Math.max(b.top, o.top) > 0.5) {
            faults.push(`${name}: "${label}" is drawn over another button`)
          }
        }
      }
    }
    return { faults, buttons }
  }, FIXTURE)
  const text = await overrunning(page, FIXTURE)
  return { faults: [...own.faults, ...text.map((each) => `text ${each}`)], buttons: own.buttons }
}

function shot(name: string): string {
  return screenshotPath(`kr-companion-button-wrapping-${name}-${test.info().project.name}`)
}

for (const form of FORMS) {
  test(`wraps a label inside its holder with no attribute at the largest size, ${form.name}`, async ({ page }) => {
    await drawn(page, form, LARGEST, BASIC)
    const found = await measured(page)
    expect(found.buttons, 'the fixture draws its buttons').toBe(6)
    expect(found.faults, 'buttons that run out of their holders').toEqual([])
    await page.screenshot({ path: shot(`default-${form.phone ? 'phone' : `desktop-${form.width}`}`) })
  })

  // The control of the case above: with the label held on one line, the same measure finds the fault.
  test(`sees a label that cannot wrap run out of its holder, ${form.name}`, async ({ page }) => {
    await drawn(page, form, LARGEST, BASIC)
    await stopWrapping(page, [FIXTURE])
    const found = await measured(page)
    expect(found.faults.length, 'the measure sees buttons held on one line').toBeGreaterThan(0)
  })
}

/** Short labels in the holders that are common in the product, drawn where the label fits on one line. */
const FITTING: readonly Holder[] = [
  holder('nowrap row', 'row', ['Try again']),
  holder('wrapping row', 'row wrap', ['Send', 'Queue', 'Steer']),
  holder('column', '', ['Refresh'], 'display:flex;flex-direction:column;align-items:flex-start'),
  holder('page actions', 'page-actions', ['Refresh', 'New session']),
  holder('banner', 'banner warning', ['Try again']),
  holder('card footer', 'card-footer', ['Open session', 'Mark as seen']),
  holder('divided row', 'divided-row', ['Export JSON'])
]

/** The way a button was held before the default: one line, no cap, no break inside a word. */
const HELD_ON_ONE_LINE = `${FIXTURE} .btn { white-space: nowrap !important; overflow-wrap: normal !important; max-inline-size: none !important }`

/** Each button's box, its position and the lines of its label. */
function boxes(page: Page): Promise<string[]> {
  return page.evaluate((root) => {
    return Array.from(document.querySelectorAll(`${root} .btn`)).map((button) => {
      const b = button.getBoundingClientRect()
      const range = document.createRange()
      range.selectNodeContents(button)
      const lines = new Set(Array.from(range.getClientRects()).filter((line) => line.width > 0).map((line) => Math.round(line.top)))
      return `${(button.textContent ?? '').trim()}: ${b.left.toFixed(1)},${b.top.toFixed(1)} ${b.width.toFixed(1)}x${b.height.toFixed(1)}, ${lines.size} line`
    })
  }, FIXTURE)
}

for (const form of FORMS) {
  test(`gives a label that fits the box it has when it is held on one line, ${form.name}`, async ({ page }) => {
    await drawn(page, form, 1, FITTING)
    const wrapping = await boxes(page)
    expect(wrapping.length, 'the fixture draws its buttons').toBe(11)
    await page.addStyleTag({ content: HELD_ON_ONE_LINE })
    expect(wrapping, 'the box, the place and the lines of each button, wrapping and held on one line').toEqual(await boxes(page))
  })
}

// The control of the comparison: a rule that gives a button a box of its own at the ordinary size
// makes the same comparison fail.
test('sees a rule that changes the box of a button at the ordinary size', async ({ page }) => {
  await drawn(page, FORMS[0], 1, FITTING)
  const before = await boxes(page)
  await page.addStyleTag({ content: `${FIXTURE} .btn { padding-inline: 1.5rem !important }` })
  expect(before).not.toEqual(await boxes(page))
})

test('keeps the icon button on one line and lets the text button wrap', async ({ page }) => {
  await drawn(page, FORMS[0], 1, [
    holder('buttons', '', [
      { label: 'Label', id: 'text' },
      { label: 'Close', className: 'icon-btn', id: 'icon' }
    ])
  ])
  const [text, icon] = await page.evaluate(() =>
    ['#text', '#icon'].map((selector) => {
      const style = getComputedStyle(document.querySelector(selector) as Element)
      return `${style.whiteSpace} ${style.overflowWrap} ${style.maxInlineSize}`
    })
  )
  expect(text).toMatch(/^normal (anywhere|break-word) 100%$/)
  expect(icon.startsWith('nowrap'), 'the icon button keeps its single line').toBe(true)
})
