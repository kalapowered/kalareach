/**
 * The largest text size, in the places where a word, a row or a pair of buttons once looked careless.
 *
 * Spacing that grows with the text takes room from the text: at three times the size a list's
 * indentation took a third of a narrow column, and words that would have fitted it were broken
 * before their last letter. The cases draw the account panel, the deletion steps and the terminal's
 * footer in the real stylesheet, once at the ordinary size and once at the largest accessibility
 * size, and read the drawn text itself: the lines each word is laid on, not a picture.
 */

import { expect, test, type BrowserContext, type Page } from '@playwright/test'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/**
 * How far the phone's spacing grows with the text: its scale (`--chrome-unit` in the tokens) is the
 * root text size up to one and a half times the base size and stops there.
 */
const SPACING_CAP = 1.5

/** The widest face the layout cases use, with DejaVu Sans after it for the machine that has none. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

interface Form {
  readonly name: string
  readonly phone: boolean
  readonly width: number
  readonly height: number
}

const PHONE: Form = { name: 'phone 320 wide', phone: true, width: 320, height: 720 }
const DESKTOP: Form = { name: 'desktop 721 wide', phone: false, width: 721, height: 800 }
/** The raw terminal's footer is the desktop shell's: its narrowest window is 320 wide. */
const NARROW_WINDOW: Form = { name: 'window 320 wide', phone: false, width: 320, height: 900 }
const WIDE_WINDOW: Form = { name: 'window 721 wide', phone: false, width: 721, height: 900 }

/**
 * Sets the text size as the platform does, before the page loads: on the root's own size, or through
 * the phone's ratio. A script that is added to a page runs on every later load of it, and the order
 * of two such scripts is not defined, so a page is given one size and never another: each size is
 * read on a page of its own.
 */
async function withTextSize(page: Page, form: Form, size: number): Promise<void> {
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
}

/**
 * Fails unless the root's computed text size is the size that the page was asked for: the browser's
 * own 16 points at the ordinary size, and 53 over 17 times that at the largest. Every measure starts
 * here, so a page at another size cannot pass for the one it was meant to read.
 */
async function expectTextSize(page: Page, size: number): Promise<void> {
  const drawn = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.documentElement).fontSize))
  expect(drawn, `the root's text size at ${size === 1 ? 'the ordinary size' : 'the largest size'}`).toBeCloseTo(16 * size, 1)
}

/** Waits for the step's fade to end, so a measure reads what a person settles on. */
async function settled(page: Page): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().every((each) => each.playState !== 'running'))
}

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  mark: 'ab'.repeat(32),
  outcome: null
} as const

/** Opens the harness signed in, with what deleting does read from the service, and shows the Account panel. */
async function atTheAccount(page: Page, form: Form, size: number) {
  await withTextSize(page, form, size)
  await page.setViewportSize({ width: form.width, height: form.height })
  await page.goto(form.phone ? '/harness.html?surface=ios' : '/harness.html')
  await page.addStyleTag({ content: WIDE_FACE })
  await page.waitForSelector(form.phone ? '.m-shell' : '.app-shell')
  await page.evaluate((view) => {
    window.krTestHost?.account.set(view)
    window.krTestHost?.account.deletion.answerView({
      state: 'ready',
      preview: {
        address: 's***@example.com',
        warnings: [
          { kind: 'organisation_owner', ...{ organisation_id: 'org-1', name: 'Acme', members: 4 } },
          { kind: 'subscription' },
          { kind: 'credit' },
          { kind: 'money_owed' }
        ],
        deleted: [
          'sign_ins',
          'passkeys_and_address',
          'backup_records',
          'recovery_bundle',
          'relay_and_voice_ended',
          'payment_record',
          'organisation_memberships',
          'device_registrations'
        ],
        kept: [
          'billing_records',
          'relay_records',
          'call_records',
          'reasoning_records',
          'backup_index_rows',
          'organisation_records',
          'device_records',
          'recovery_copies',
          'other_services'
        ],
        unlisted: false,
        kept_records_years: 7,
        backup_file_days: 7,
        code_lifetime_minutes: 5
      }
    })
  }, SIGNED_IN)
  const account = form.phone
    ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
    : page.getByRole('button', { name: /^Account/ })
  await account.click()
  return form.phone ? page.getByTestId('mobile-account') : page.getByRole('dialog', { name: 'Account' })
}

/** The deletion step that lists what goes and what stays. */
async function atTheDeletion(page: Page, form: Form, size: number): Promise<void> {
  const panel = await atTheAccount(page, form, size)
  await panel.getByTestId('delete-account-open').click()
  await expect(panel.getByTestId('delete-account-before')).toBeVisible()
  await settled(page)
}

/** Opens the first session's raw terminal in the desktop shell, in a window of `form`'s width. */
async function atTheFooter(page: Page, form: Form, size: number): Promise<void> {
  await withTextSize(page, form, size)
  // The session is opened in a window wide enough to show the sections, then the window is narrowed.
  await page.setViewportSize({ width: 1280, height: form.height })
  await page.goto('/harness.html')
  await page.addStyleTag({ content: WIDE_FACE })
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
  await page.setViewportSize({ width: form.width, height: form.height })
  await page.getByRole('tab', { name: 'Terminal' }).click()
  await page.getByTestId('palette-provenance').waitFor()
  await settled(page)
}

/** A box that holds text, and the inline space between its text and the box that holds it. */
interface Owner {
  readonly text: string
  /** The padding, border and margin of the box and of every box between it and its holder, along the line. */
  readonly taken: number
}

/** A word that is laid on more than one line, with the room its holder has for a line. */
interface Cut {
  readonly word: string
  /** The index of the box that holds the word's text, in the order of `owners`. */
  readonly owner: number
  /** The word's width, in one piece. */
  readonly whole: number
  /** The width of the content box of the holder: the room a line has before any of the spacing is taken. */
  readonly holder: number
}

interface Reading {
  readonly owners: readonly Owner[]
  readonly cut: readonly Cut[]
}

/**
 * Every box under `root` that holds text, and every word of that text that is laid on more than one
 * line. A word's lines are read from its own text range, so a word that a line break has cut in two
 * is found whatever is drawn, and one that is moved whole to the next line is not. A box's holder is
 * the first box above it that is not a list, a list item or an inline box: the card a list is in, the
 * row a button is in. The page must be at the text size `size`.
 */
async function reading(page: Page, root: string, size: number): Promise<Reading> {
  await expectTextSize(page, size)
  return page.evaluate((selector) => {
    const base = document.querySelector(selector)
    if (base === null) throw new Error(`no ${selector} on the page`)
    const px = (value: string): number => Number.parseFloat(value) || 0
    const contentOf = (element: Element): number => {
      const style = getComputedStyle(element)
      return (
        element.getBoundingClientRect().width -
        px(style.paddingLeft) -
        px(style.paddingRight) -
        px(style.borderLeftWidth) -
        px(style.borderRightWidth)
      )
    }
    const insetOf = (element: Element): number => {
      const style = getComputedStyle(element)
      return (
        px(style.paddingLeft) +
        px(style.paddingRight) +
        px(style.borderLeftWidth) +
        px(style.borderRightWidth) +
        px(style.marginLeft) +
        px(style.marginRight)
      )
    }
    const owners: Element[] = []
    const holders: Element[] = []
    const found: Owner[] = []
    const cut: Cut[] = []
    const walk = document.createTreeWalker(base, NodeFilter.SHOW_TEXT)
    for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
      const text = node.textContent ?? ''
      if (text.trim() === '') continue
      let owner = node.parentElement
      while (owner !== null && owner !== base && getComputedStyle(owner).display === 'inline') owner = owner.parentElement
      if (owner === null) continue
      const style = getComputedStyle(owner)
      if (style.visibility === 'hidden' || style.display === 'none' || owner.getBoundingClientRect().width === 0) continue
      let at = owners.indexOf(owner)
      if (at < 0) {
        let holder: Element | null = owner.parentElement
        let taken = insetOf(owner)
        while (
          holder !== null &&
          holder !== base &&
          (['LI', 'UL', 'OL'].includes(holder.tagName) || ['inline', 'contents'].includes(getComputedStyle(holder).display))
        ) {
          taken += insetOf(holder)
          holder = holder.parentElement
        }
        at = owners.length
        owners.push(owner)
        holders.push(holder ?? owner)
        found.push({ text: (owner.textContent ?? '').trim().slice(0, 24), taken })
      }
      for (const word of text.matchAll(/[^\s‐-―-]+/gu)) {
        const range = document.createRange()
        range.setStart(node, word.index)
        range.setEnd(node, word.index + word[0].length)
        const pieces = Array.from(range.getClientRects()).filter((piece) => piece.width > 0)
        // Two rects on one line are one piece in two boxes; a word is cut when its pieces are on more than one line.
        if (new Set(pieces.map((piece) => Math.round(piece.top))).size < 2) continue
        cut.push({
          word: word[0],
          owner: at,
          whole: pieces.reduce((sum, piece) => sum + piece.width, 0),
          holder: contentOf(holders[at])
        })
      }
    }
    return { owners: found, cut }
  }, root)
}

/**
 * The words that are cut although they fit the room their holder has once the spacing between the
 * holder and the text is held at its bound: its size at the ordinary text size, grown with the text
 * as far as the cap. A word wider than that room cannot be kept whole by any spacing and is left out.
 */
function cutAtTheBound(ordinary: Reading, largest: Reading): string[] {
  expect(largest.owners.map((each) => each.text), 'the same text at both sizes').toEqual(
    ordinary.owners.map((each) => each.text)
  )
  return largest.cut
    .filter((one) => {
      const bound = SPACING_CAP * ordinary.owners[one.owner].taken
      const taken = Math.min(largest.owners[one.owner].taken, bound)
      return one.whole <= one.holder - taken + 0.5
    })
    .map((one) => {
      const bound = SPACING_CAP * ordinary.owners[one.owner].taken
      const room = one.holder - Math.min(largest.owners[one.owner].taken, bound)
      const line = one.holder - largest.owners[one.owner].taken
      return `${one.word}: ${one.whole.toFixed(0)} px wide, cut in a line of ${line.toFixed(0)} px, whole in ${room.toFixed(0)} px at the bound`
    })
}

/** What each word's holder leaves it at the largest size, for the words that no spacing can keep whole. */
function cannotFit(ordinary: Reading, largest: Reading): string[] {
  const bounded = (one: Cut): number =>
    one.holder - Math.min(largest.owners[one.owner].taken, SPACING_CAP * ordinary.owners[one.owner].taken)
  return [...new Set(largest.cut.filter((one) => one.whole > bounded(one) + 0.5).map((one) => `${one.word} (${one.whole.toFixed(0)} px in ${bounded(one).toFixed(0)} px)`))]
}

interface Place {
  readonly name: string
  readonly forms: readonly Form[]
  readonly root: (form: Form) => string
  readonly open: (page: Page, form: Form, size: number) => Promise<void>
}

const PLACES: readonly Place[] = [
  {
    name: 'the account panel',
    forms: [PHONE, DESKTOP],
    root: (form) => (form.phone ? '[data-testid="mobile-account"]' : '[role="dialog"]'),
    open: async (page, form, size) => {
      await atTheAccount(page, form, size)
      await settled(page)
    }
  },
  {
    name: 'the deletion step that lists what goes and what stays',
    forms: [PHONE, DESKTOP],
    root: () => '[data-testid="delete-account"]',
    open: atTheDeletion
  },
  {
    name: 'the terminal footer',
    forms: [NARROW_WINDOW, WIDE_WINDOW],
    root: () => '.terminal-footer',
    open: atTheFooter
  }
]

/** What a place reads at the ordinary size, on a page of its own that is closed after the reading. */
async function readAtTheOrdinarySize(
  context: BrowserContext,
  open: Place['open'],
  form: Form,
  root: string
): Promise<Reading> {
  const page = await context.newPage()
  try {
    await open(page, form, 1)
    return await reading(page, root, 1)
  } finally {
    await page.close()
  }
}

test.describe('A word is kept whole where its holder has room for it', () => {
  for (const place of PLACES) {
    for (const form of place.forms) {
      test(`${place.name}, ${form.name}`, async ({ context, page }) => {
        const ordinary = await readAtTheOrdinarySize(context, place.open, form, place.root(form))
        expect(ordinary.cut.map((one) => one.word), 'words cut at the ordinary size').toEqual([])
        await place.open(page, form, LARGEST)
        const largest = await reading(page, place.root(form), LARGEST)
        test.info().annotations.push(
          { type: 'cut', description: `${largest.cut.length} words are cut at the largest size` },
          { type: 'cannot fit', description: cannotFit(ordinary, largest).join('; ') || 'none' }
        )
        expect(cutAtTheBound(ordinary, largest), 'words cut although they fit').toEqual([])
      })
    }
  }

  test('the measure finds the words that an indentation which grows with the text cuts', async ({ context, page }) => {
    const root = '[data-testid="delete-account"]'
    const ordinary = await readAtTheOrdinarySize(context, atTheDeletion, PHONE, root)
    await atTheDeletion(page, PHONE, LARGEST)
    // The control: the list's indentation grows with the text, as it did, so words that fit are cut.
    await page.addStyleTag({ content: '.deletion-list { padding-inline-start: 4rem !important }' })
    expect(cutAtTheBound(ordinary, await reading(page, root, LARGEST)).length).toBeGreaterThan(0)
  })

  test('the measure refuses a page that is not at the size it was asked for', async ({ page }) => {
    await atTheDeletion(page, PHONE, LARGEST)
    await expect(expectTextSize(page, 1)).rejects.toThrow(/ordinary size/)
    await expect(reading(page, '[data-testid="delete-account"]', 1)).rejects.toThrow(/ordinary size/)
    await expectTextSize(page, LARGEST)
  })
})

/**
 * The distances between the rows of the footer: the space between each row of its controls and
 * status text and the one below, with the distance the footer itself keeps between its parts. A row
 * is the boxes that share a stretch of the page from top to bottom.
 */
async function footerRows(page: Page, size: number): Promise<{ readonly own: number; readonly gaps: readonly number[] }> {
  await expectTextSize(page, size)
  return page.evaluate(() => {
    const footer = document.querySelector('.terminal-footer')
    if (footer === null) throw new Error('no footer on the page')
    const boxes = Array.from(
      footer.querySelectorAll('.btn, [data-testid="terminal-presentation"], [data-testid="terminal-position"]')
    )
      .map((each) => each.getBoundingClientRect())
      .filter((box) => box.width > 0 && box.height > 0)
      .sort((a, b) => a.top - b.top)
    const rows: { top: number; bottom: number }[] = []
    for (const box of boxes) {
      const last = rows[rows.length - 1]
      if (last !== undefined && box.top < last.bottom - 0.5) last.bottom = Math.max(last.bottom, box.bottom)
      else rows.push({ top: box.top, bottom: box.bottom })
    }
    const gaps: number[] = []
    for (let at = 1; at < rows.length; at += 1) gaps.push(rows[at].top - rows[at - 1].bottom)
    return { own: Number.parseFloat(getComputedStyle(footer).rowGap), gaps }
  })
}

test.describe('The rows of the terminal footer stand one distance apart', () => {
  for (const form of [NARROW_WINDOW, WIDE_WINDOW]) {
    for (const size of [1, LARGEST]) {
      test(`${form.name}, text ${size === 1 ? 'ordinary' : 'largest'}`, async ({ page }) => {
        await atTheFooter(page, form, size)
        const { own, gaps } = await footerRows(page, size)
        expect(gaps.length, 'rows below the first').toBeGreaterThan(0)
        expect(
          gaps.map((gap) => Number(gap.toFixed(1))),
          `each row's distance from the one above, the footer keeps ${own} px`
        ).toEqual(gaps.map(() => own))
      })
    }
  }

  test('the measure finds rows that stand at another distance', async ({ page }) => {
    await atTheFooter(page, NARROW_WINDOW, LARGEST)
    await page.addStyleTag({ content: '.terminal-footer .row { row-gap: 3px !important }' })
    const { own, gaps } = await footerRows(page, LARGEST)
    expect(gaps.some((gap) => Math.abs(gap - own) > 0.5)).toBe(true)
  })
})

/** The card of the account's devices with everything it can say, among it an outcome the person can dismiss. */
const EVERYTHING = {
  state: 'on',
  kept_at: 'reach.kala.to',
  devices: {
    can_confirm: true,
    out: false,
    waiting: true,
    members: [
      { reference: 'me', name: 'This computer', this_computer: true, vouched: true },
      { reference: 'b', name: 'the-phone', this_computer: false, vouched: true }
    ],
    candidates: [{ reference: 'c', name: 'the-tablet-in-the-kitchen' }],
    held_out: [],
    offers: [],
    outcomes: [{ what: 'addition', ended: 'refused', name: 'the-tablet-in-the-kitchen' }]
  }
} as const

async function atTheDevices(page: Page, form: Form, size: number): Promise<void> {
  await atTheAccount(page, form, size)
  await page.evaluate((view) => {
    window.krTestHost?.settings.change({ sync: view })
  }, EVERYTHING)
  await expect(page.getByTestId('settings-devices-dismiss')).toBeVisible()
  await settled(page)
}

/** Where each of two buttons stands in the box that holds them, and whether the second is under the first. */
interface Standing {
  readonly first: { readonly left: number; readonly width: number }
  readonly second: { readonly left: number; readonly width: number }
  readonly stacked: boolean
}

/**
 * How a pair of buttons stands, read twice: as the interface draws it, and as the box that the
 * product's other choices stand in would hold the same two buttons (a row that wraps, the first
 * choice first), put beside it in the same card.
 */
async function pairBesideItsSiblings(
  page: Page,
  first: string,
  second: string,
  size: number
): Promise<{ readonly drawn: Standing; readonly siblings: Standing }> {
  await expectTextSize(page, size)
  return page.evaluate(
    ([one, two]) => {
      const a = document.querySelector(`[data-testid="${one}"]`)
      const b = document.querySelector(`[data-testid="${two}"]`)
      const holder = a?.parentElement
      if (a === null || b === null || b === undefined || !holder?.parentElement) throw new Error('the pair is not on the page')
      const standing = (x: Element, y: Element, within: Element): Standing => {
        const box = within.getBoundingClientRect()
        const p = x.getBoundingClientRect()
        const q = y.getBoundingClientRect()
        const round = (value: number): number => Math.round(value * 2) / 2
        return {
          first: { left: round(p.left - box.left), width: round(p.width) },
          second: { left: round(q.left - box.left), width: round(q.width) },
          stacked: q.top >= p.bottom - 0.5
        }
      }
      const drawn = standing(a, b, holder)
      // The settings choice's own classes: a row that wraps, as every other choice of this kind stands.
      const sibling = document.createElement('div')
      sibling.className = 'row choice-actions'
      for (const original of [a, b]) {
        const copy = document.createElement('button')
        copy.type = 'button'
        copy.className = original.className
        copy.textContent = original.textContent
        sibling.append(copy)
      }
      holder.after(sibling)
      const siblings = standing(sibling.children[0], sibling.children[1], sibling)
      sibling.remove()
      return { drawn, siblings }
    },
    [first, second] as const
  )
}

const PAIRS = [
  { name: 'the deletion step: "Send code" and "Cancel"', first: 'delete-account-send-code', second: 'delete-account-cancel', open: atTheDeletion },
  { name: 'the devices card: "Look for my devices" and "Dismiss"', first: 'settings-devices-look', second: 'settings-devices-dismiss', open: atTheDevices }
] as const

test.describe('A pair of buttons stands as the other choices of the product do', () => {
  for (const pair of PAIRS) {
    for (const form of [PHONE, DESKTOP]) {
      for (const size of [1, LARGEST]) {
        test(`${pair.name}, ${form.name}, text ${size === 1 ? 'ordinary' : 'largest'}`, async ({ page }) => {
          await pair.open(page, form, size)
          const { drawn, siblings } = await pairBesideItsSiblings(page, pair.first, pair.second, size)
          expect(drawn).toEqual(siblings)
        })
      }
    }
  }
})
