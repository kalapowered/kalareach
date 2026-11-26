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

/** One piece of a fixture: a box with its classes and its parts, some text, or a button. */
interface Part {
  readonly tag?: string
  readonly classes?: string
  readonly style?: string
  /** Marks a holder: the measures read the buttons under it against its box. */
  readonly name?: string
  readonly attrs?: Readonly<Record<string, string>>
  readonly text?: string
  readonly button?: string | Drawn
  readonly parts?: readonly Part[]
}

/** Opens the harness in `form` at `size` times the default text and puts `holders` over the page, in the real stylesheet. */
async function drawn(page: Page, form: Form, size: number, holders: readonly Part[]): Promise<void> {
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
      const build = (part: Part): HTMLElement => {
        if (part.button !== undefined) {
          const spec = typeof part.button === 'string' ? { label: part.button } : part.button
          const button = document.createElement('button')
          button.type = 'button'
          button.className = 'className' in spec && spec.className !== undefined ? spec.className : 'btn'
          if ('id' in spec && spec.id !== undefined) button.id = spec.id
          if (button.className === 'icon-btn') button.setAttribute('aria-label', spec.label)
          button.textContent = spec.label
          return button
        }
        const box = document.createElement(part.tag ?? 'div')
        if (part.classes !== undefined) box.className = part.classes
        if (part.name !== undefined) box.dataset.case = part.name
        for (const [key, value] of Object.entries(part.attrs ?? {})) box.setAttribute(key, value)
        if (part.style !== undefined) box.style.cssText = part.style
        if (part.text !== undefined) box.textContent = part.text
        for (const each of part.parts ?? []) box.append(build(each))
        return box
      }
      const over = document.createElement('div')
      over.id = id
      over.style.cssText =
        'position:fixed;inset:0;overflow:auto;box-sizing:border-box;padding:16px;z-index:99999;background:var(--bg, #fff);color:var(--text, #000)'
      for (const one of drawing) over.append(build(one))
      document.body.append(over)
    },
    [FIXTURE.slice(1), holders] as const
  )
}

/** A holder with only buttons in it. */
function holder(name: string, classes: string, buttons: readonly (string | Drawn)[], style?: string): Part {
  return { name, classes, style, parts: buttons.map((button) => ({ button })) }
}

const button = (label: string): Part => ({ button: label })
const words = (tag: string, text: string, classes?: string): Part => ({ tag, text, classes })

const LONG = 'Keep it for the new conversation'
const NAME = 'sam-laptop-with-a-device-name-that-has-no-place-to-break'

/** Holders in which a button is drawn on its own, as a column holds it, a nowrap row, a wrapping row and a card. */
const BASIC: readonly Part[] = [
  holder('nowrap row, one button', 'row', [LONG]),
  holder('column, one button', '', [`Invite ${NAME}`], 'display:flex;flex-direction:column;align-items:flex-start'),
  holder('wrapping row, three buttons', 'row wrap', ['Put it in its composer', 'Move it', 'Discard']),
  holder('block, one button', '', ['Back to the conversation'])
]

interface Found {
  readonly faults: readonly string[]
  readonly buttons: number
  /** For each holder: the width of its content box, and each button's width, the width it would have on one line, and its lines. */
  readonly widths: readonly string[]
}

/**
 * What is wrong with the buttons under the fixture: a button outside the box of the holder it is in
 * (or of the fixture, to either side), a label drawn outside its own button, a button over another,
 * and, through the page's one measure of text that runs out of its box, a line of text past a box.
 */
async function measured(page: Page, text = true): Promise<Found> {
  const own = await page.evaluate((root) => {
    const faults: string[] = []
    const base = document.querySelector(root)
    if (base === null) return { faults: ['no fixture'], buttons: 0, widths: [] as string[] }
    const room = base.getBoundingClientRect()
    let buttons = 0
    const widths: string[] = []
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
      // The numbers: the content box of the holder, and each button as drawn and held on one line.
      const style = getComputedStyle(holder)
      const inset = (name2: string): number => parseFloat(style.getPropertyValue(name2)) || 0
      const content = box.width - inset('padding-left') - inset('padding-right') - inset('border-left-width') - inset('border-right-width')
      const now = each.map((button) => {
        const b = button.getBoundingClientRect()
        const range = document.createRange()
        range.selectNodeContents(button)
        const lines = new Set(Array.from(range.getClientRects()).filter((line) => line.width > 0).map((line) => Math.round(line.top))).size
        return { label: (button.textContent ?? '').trim(), width: b.width, lines }
      })
      for (const button of each) {
        ;(button as HTMLElement).style.whiteSpace = 'nowrap'
        ;(button as HTMLElement).style.maxInlineSize = 'none'
      }
      const one = each.map((button) => button.getBoundingClientRect().width)
      for (const button of each) {
        ;(button as HTMLElement).style.whiteSpace = ''
        ;(button as HTMLElement).style.maxInlineSize = ''
      }
      widths.push(
        `${name}: content ${content.toFixed(0)} px; ` +
          now.map((each2, at) => `"${each2.label}" ${each2.width.toFixed(0)} px (${one[at].toFixed(0)} px on one line, ${each2.lines} line)`).join('; ')
      )
    }
    return { faults, buttons, widths }
  }, FIXTURE)
  const overrun = text ? await overrunning(page, FIXTURE) : []
  return { faults: [...own.faults, ...overrun.map((each) => `text ${each}`)], buttons: own.buttons, widths: own.widths }
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
const FITTING: readonly Part[] = [
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

// ---- The holders of a button ---------------------------------------------------------------------------------

/**
 * Each holder a button is drawn in, with the real classes of the interface and the real label of the
 * button, at the largest size in the narrowest windows. A label that wraps is not enough: a holder
 * that cannot wrap its row, or that leaves its buttons no room, runs a button out of the box that
 * holds it however the label is set. The text beside a button is representative; the classes and the
 * labels are the interface's own.
 */
interface Holding {
  readonly name: string
  /** Only the phone's shell draws it. */
  readonly phoneOnly?: boolean
  /** The text beside the button is meant to be clipped with an ellipsis, so only the buttons are read. */
  readonly buttonsOnly?: boolean
  readonly parts: readonly Part[]
}

const banner: Part = {
  name: 'banner',
  classes: 'banner warning',
  parts: [
    {
      classes: 'spacer',
      parts: [
        words('strong', 'The sessions could not be listed.'),
        words('span', 'The host did not answer. Check that it is running and that this device can reach it.')
      ]
    },
    button('Try again')
  ]
}

const pageHeading = (name: string, title: string, actions: readonly string[]): Part => ({
  name,
  classes: 'page-heading',
  parts: [{ parts: [words('h1', title)] }, { classes: 'page-actions', parts: actions.map(button) }]
})

const card = (name: string, inner: Part): Part => ({ name, classes: 'card', parts: [inner] })

const HOLDINGS: readonly Holding[] = [
  { name: 'banner with an action', parts: [banner] },
  { name: 'page heading with one action', parts: [pageHeading('heading, one action', 'Kept drafts', ['Back to sessions'])] },
  { name: 'page heading with two actions', parts: [pageHeading('heading, two actions', 'Sessions', ['New session', 'Refresh'])] },
  {
    name: 'card footer with three buttons in a row',
    parts: [
      card('attention card', {
        classes: 'card-footer',
        parts: [{ tag: 'span', classes: 'row', parts: [button('Open session'), button('Review changes'), button('Mark as seen')] }]
      })
    ]
  },
  {
    name: 'composer note with three buttons in a row',
    parts: [
      {
        name: 'composer note',
        classes: 'composer',
        parts: [
          {
            classes: 'composer-note between',
            parts: [
              words('span', 'Sent when the agent can take it.'),
              { tag: 'span', classes: 'row', parts: [button('Steer'), button('Queue'), button('Send')] }
            ]
          }
        ]
      }
    ]
  },
  {
    name: 'terminal footer with the move keys',
    parts: [
      {
        name: 'terminal footer',
        parts: [
          {
            tag: 'footer',
            classes: 'terminal-footer between',
            parts: [
              words('span', 'Zoom 100%'),
              {
                tag: 'span',
                classes: 'row',
                parts: [
                  { tag: 'span', classes: 'row', parts: [button('Up'), button('Down'), button('Left'), button('Right')] },
                  button('Smaller'),
                  button('Larger')
                ]
              },
              { tag: 'span', classes: 'row', parts: [button('Back to the conversation')] }
            ]
          }
        ]
      }
    ]
  },
  {
    name: 'divided row with a text column and one button',
    parts: [
      card('export row', {
        classes: 'card-body',
        parts: [
          {
            classes: 'divided-row',
            parts: [
              { classes: 'spacer', parts: [words('strong', 'Export the session'), words('p', 'Every message, as JSON.', 'muted small')] },
              button('Export recording')
            ]
          }
        ]
      }),
      card('saved settings row', {
        classes: 'card-body',
        parts: [
          {
            classes: 'divided-row',
            parts: [
              { classes: 'spacer', parts: [words('strong', 'Saved settings'), words('p', 'Left at a time not known.', 'muted small')] },
              button('Remove from the bundle')
            ]
          }
        ]
      })
    ]
  },
  {
    name: 'card header with a title and one button',
    parts: [
      card('change set header', {
        classes: 'card-header',
        parts: [
          { parts: [words('h2', 'Reading this change set'), words('p', 'Version 12 against main, 1,204 paths', 'muted small')] },
          button('Mark version 12 reviewed')
        ]
      })
    ]
  },
  {
    name: 'settings row with a text column and one button',
    parts: [
      {
        name: 'settings row',
        parts: [
          {
            tag: 'li',
            classes: 'settings-row',
            style: 'list-style:none',
            parts: [{ parts: [words('h3', 'Review the changes'), words('p', 'claude --review', 'mono small')] }, button('Remove')]
          }
        ]
      }
    ]
  },
  {
    name: 'row with a field and one button',
    parts: [
      {
        name: 'argument row',
        classes: 'form-field',
        parts: [
          {
            tag: 'fieldset',
            parts: [{ classes: 'row', parts: [{ tag: 'input', style: 'flex:1 1 auto;min-width:0' }, button('Remove argument')] }]
          }
        ]
      }
    ]
  },
  {
    name: 'terminal heading with a title and one button',
    parts: [
      {
        name: 'terminal heading',
        parts: [
          {
            tag: 'header',
            classes: 'terminal-heading',
            parts: [
              { tag: 'span', classes: 'row', parts: [words('h2', 'Terminal'), button('Take control')] },
              { tag: 'span', classes: 'row', parts: [words('span', 'Connected')] }
            ]
          }
        ]
      }
    ]
  },
  {
    name: 'phone terminal status with one button',
    phoneOnly: true,
    buttonsOnly: true,
    parts: [
      {
        name: 'terminal status',
        parts: [
          {
            classes: 'm-terminal-status',
            parts: [{ attrs: { 'data-expanded': 'false' }, parts: [words('p', 'The program is waiting for you to answer its question about the files.')] }, button('More')]
          }
        ]
      }
    ]
  },
  {
    name: 'toast with an action',
    parts: [
      {
        name: 'toast',
        classes: 'toast-dock',
        style: 'position:static',
        parts: [
          {
            classes: 'toast',
            parts: [
              words('span', 'The session was closed on the host.', 'toast-text'),
              { classes: 'toast-controls', parts: [button('Open the session')] }
            ]
          }
        ]
      }
    ]
  }
]

for (const holding of HOLDINGS) {
  for (const form of FORMS) {
    if (holding.phoneOnly === true && !form.phone) continue
    test(`keeps the ${holding.name} whole at the largest size, ${form.name}`, async ({ page }) => {
      await drawn(page, form, LARGEST, holding.parts)
      const found = await measured(page, holding.buttonsOnly !== true)
      expect(found.buttons, 'the fixture draws its buttons').toBeGreaterThan(0)
      // The numbers go with the case, for whoever reads the holder's verdict.
      for (const line of found.widths) test.info().annotations.push({ type: 'widths', description: line })
      expect(found.faults, 'buttons and text that run out of the box that holds them').toEqual([])
    })
  }
}
