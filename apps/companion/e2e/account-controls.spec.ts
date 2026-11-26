/**
 * The controls of the account panel, in every state a person can reach, at the largest text size in
 * a wide face.
 *
 * A button keeps its label on one line unless it says it may wrap, so a label wider than the column
 * that holds it runs out of its button and out of its card. A measure of the text alone passes the
 * label that stays inside a button that has itself run past the card, so each case also measures the
 * button against the column it sits in. Every case reads the controls it expects to find by name, so
 * a state that did not show its control cannot pass for nothing, and ends with the control: with the
 * labels kept from wrapping, the same measure sees the panel run out.
 *
 * Every screenshot goes under the test artefact directory, named for the engine and the case.
 */

import { expect, test, type Page } from '@playwright/test'

import { screenshotPath } from './evidence'
import { overrunning, stopWrapping } from './layout'

/** The largest accessibility size's body text, 53 points, against 17 at the default setting. */
const LARGEST = 53 / 17

/** The widest face the layout cases use, with DejaVu Sans after it for the machine that has none. */
const WIDE_FACE = ':root { --font-ui: Verdana, "DejaVu Sans", sans-serif !important; }'

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: true,
  generation: 'aaaa',
  mark: 'ab'.repeat(32),
  outcome: null
} as const

type Surface = 'ios' | 'android' | 'desktop'

interface Form {
  readonly surface: Surface
  /** The text size as a multiple of the default one. */
  readonly size: number
  /** The window's size in points. */
  readonly width: number
  readonly height: number
  readonly name: string
}

/**
 * The narrowest phone, in both of its forms, and the desktop in the narrowest window that still has
 * the sidebar that opens the Account sheet (721 points: the sidebar goes at 720) at two and at the
 * largest size. The sheet is as wide as the window less 32 points, up to 820, so a wider window
 * holds the same controls in a column that fits more of every label.
 */
const PHONES: readonly Form[] = [
  { surface: 'ios', size: LARGEST, width: 320, height: 720, name: 'ios' },
  { surface: 'android', size: LARGEST, width: 320, height: 720, name: 'android' }
]
const DESKTOPS: readonly Form[] = [
  { surface: 'desktop', size: 2, width: 721, height: 800, name: 'desktop 721 wide, text 2.0x' },
  { surface: 'desktop', size: LARGEST, width: 721, height: 800, name: `desktop 721 wide, text ${LARGEST.toFixed(1)}x` }
]

/**
 * What the notices region shows once it is open: lines like the installers' own, and a path with no
 * place to break a line, which the region has to hold. The installers' whole file is some nineteen
 * thousand lines, far more than a layout measure can walk, and its length decides nothing here.
 */
const NOTICES_TEXT = [
  'Third-party notices',
  '',
  ...Array.from({ length: 24 }, (_, index) => `package-${index} 1.${index}.0: MIT OR Apache-2.0 (a notice of its own)`),
  '',
  `/home/build/.cargo/registry/src/index.crates.io-0000000000000000/${'a-crate-with-a-long-name-'.repeat(6)}/LICENSE`
].join('\n')

/** Answers the region's read of the notices with `NOTICES_TEXT`, so a case measures its layout, not the file's length. */
async function withShortNotices(page: Page): Promise<void> {
  await page.route('**/companion-third-party-notices*.txt', (route) =>
    route.fulfill({ contentType: 'text/plain', body: NOTICES_TEXT })
  )
}

function shot(name: string): string {
  return screenshotPath(`kr-companion-account-controls-${name}-${test.info().project.name}`)
}

/** What a measure found of one control. */
interface Control {
  readonly key: string
  readonly width: number
  readonly column: number
  readonly lines: number
  readonly past: boolean
}

/**
 * Every control under `root`, by its test id or its label: its width, the width of the column or row
 * that holds it, the number of lines its label is drawn on, and whether its box lies outside that
 * column.
 */
function controlsUnder(page: Page, root: string): Promise<Control[]> {
  return page.evaluate((selector) => {
    const found: Control[] = []
    for (const area of document.querySelectorAll(selector)) {
      for (const control of area.querySelectorAll('.btn')) {
        const box = control.getBoundingClientRect()
        if (box.width === 0 && box.height === 0) continue
        const held = control.closest('.account-actions, .device-row, .card')
        if (held === null) continue
        const column = held.getBoundingClientRect()
        const range = document.createRange()
        range.selectNodeContents(control)
        const tops = new Set(Array.from(range.getClientRects()).map((line) => Math.round(line.top)))
        found.push({
          key: control.getAttribute('data-testid') ?? (control.textContent ?? '').trim(),
          width: Math.round(box.width),
          column: Math.round(column.width),
          lines: tops.size,
          past: box.left < column.left - 0.5 || box.right > column.right + 0.5
        })
      }
    }
    return found
  }, root)
}

function describe(control: Control): string {
  return `${control.key}: ${control.width}px wide in a column ${control.column}px wide`
}

/** Sets the phone's text size as the web view would, before the page loads. */
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

/**
 * Opens the harness in `form`, in the widest face, and tells the fake host what `prepare` says before
 * the Account panel is shown: the phone reaches it from its tab bar, the desktop from its sidebar.
 */
async function atTheAccount(
  page: Page,
  form: Form,
  prepare: (page: Page) => Promise<void>,
  wide = true
): Promise<void> {
  const phone = form.surface !== 'desktop'
  await page.setViewportSize({ width: form.width, height: form.height })
  if (phone) {
    await withTextScale(page, form.size)
  } else if (form.size !== 1) {
    // A desktop browser has no system factor; its own text size scales the root.
    await page.addInitScript((factor) => {
      document.addEventListener('DOMContentLoaded', () => {
        document.documentElement.style.fontSize = `${16 * factor}px`
      })
    }, form.size)
  }
  await page.goto(phone ? `/harness.html?surface=${form.surface}` : '/harness.html')
  if (wide) await page.addStyleTag({ content: WIDE_FACE })
  await page.waitForSelector(phone ? '.m-shell' : '.app-shell')
  if (wide) {
    // The face is the one drawn, not only the one named: a machine with neither face would set the
    // page in the fallback, narrower than either, and the measures below would pass for nothing.
    const wider = await page.evaluate(() => {
      const context = document.createElement('canvas').getContext('2d')
      if (context === null) return false
      const sample = 'Your settings are kept in step through the sync service'
      context.font = '16px Verdana, "DejaVu Sans", monospace'
      const drawn = context.measureText(sample).width
      context.font = '16px monospace'
      return drawn !== context.measureText(sample).width
    })
    expect(wider, 'a wide face is installed').toBe(true)
  }
  await prepare(page)
  const account = phone
    ? page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: /^Account/ })
    : page.getByRole('button', { name: /^Account/ })
  await account.click()
  await expect(page.getByTestId('account-panel')).toBeVisible()
}

/** Photographs the whole of the panel: the window is made as tall as it is, so no bar lies across it. */
async function photograph(page: Page, path: string): Promise<void> {
  const panel = page.getByTestId('account-panel')
  const view = page.viewportSize()
  const height = await panel.evaluate((each) => each.getBoundingClientRect().height)
  if (view !== null) await page.setViewportSize({ width: view.width, height: Math.ceil(height) + view.height })
  await panel.screenshot({ path })
}

/** The roots a case holds: the panel, and each card of it, whose own box is the one a control leaves. */
const ROOTS = ['[data-testid="account-panel"]', '[data-testid="account-panel"] .card'] as const

interface Held {
  /** The controls the state shows, by test id or label: a state that shows fewer has not been reached. */
  readonly shows: readonly string[]
  /** Whether a label of the state is long enough to run out of the phone's column when it cannot wrap. */
  readonly strains: boolean
}

/** What the measures find of the panel as it stands. */
interface Found {
  /** Every control of the panel, by test id or label. */
  readonly keys: string[]
  /** The controls whose box lies outside the column that holds them. */
  readonly outside: string[]
  /** The lines of text, and the boxes, that run past the screen or their own box. */
  readonly lines: string[]
}

async function measured(page: Page): Promise<Found> {
  const controls = await controlsUnder(page, '[data-testid="account-panel"]')
  const lines: string[] = []
  for (const root of ROOTS) lines.push(...(await overrunning(page, root)).map((each) => `${root}: ${each}`))
  return { keys: controls.map((each) => each.key), outside: controls.filter((each) => each.past).map(describe), lines }
}

/**
 * The control: with the labels of the controls kept from wrapping, the same measures see a control
 * run out of its column, or its label out of its own box when the control is held to the column. A
 * case whose control still reports nothing cannot see the fault it is there to catch.
 */
async function foundWithoutWrapping(page: Page): Promise<string[]> {
  await stopWrapping(page, ['[data-testid="account-panel"] .btn'])
  const controls = await controlsUnder(page, '[data-testid="account-panel"]')
  return [
    ...controls.filter((each) => each.past).map(describe),
    ...(await overrunning(page, '[data-testid="account-panel"] .btn'))
  ]
}

// ---- The account, signed in or out ----------------------------------------------------------------

const ACCOUNT_STATES: readonly {
  readonly name: string
  readonly held: Held
  readonly prepare: (page: Page) => Promise<void>
}[] = [
  {
    name: 'signed in, with the usage it could not read and the account it can delete',
    held: { shows: ['Sign out', 'Try again', 'delete-account-open'], strains: true },
    prepare: (page) =>
      page.evaluate((view) => {
        window.krTestHost?.account.setUsage({ state: 'could_not_read' })
        window.krTestHost?.account.set(view)
      }, SIGNED_IN)
  },
  {
    name: 'signed out',
    held: { shows: ['Sign in'], strains: false },
    prepare: () => Promise.resolve()
  },
  {
    name: 'with the browser open for the sign-in',
    held: { shows: ['Cancel'], strains: false },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.account.set({ state: 'browser_open' })
      })
  }
]

for (const form of [...PHONES, ...DESKTOPS]) {
  for (const state of ACCOUNT_STATES) {
    test(`keeps the controls of the account ${state.name} whole at the largest size in a wide face, ${form.name}`, async ({
      page
    }) => {
      await atTheAccount(page, form, state.prepare)
      const found = await measured(page)
      for (const key of state.held.shows) expect(found.keys, `the panel shows ${key}`).toContain(key)
      expect(found.outside, 'controls that lie outside the column that holds them').toEqual([])
      expect(found.lines, 'lines that run past the screen or their box').toEqual([])
      await photograph(page, shot(`account-${state.held.shows[0] ?? 'none'}-${form.surface}-${form.size.toFixed(1)}`))
      if (state.held.strains && form.surface !== 'desktop') {
        expect(await foundWithoutWrapping(page), 'the measures see a label that cannot wrap run out').not.toEqual([])
      }
    })
  }
}

// ---- The recovery card of the desktop's sync service -----------------------------------------------

const RECOVERY_ARCHIVES = [
  { archive_id: 'a1', generation: 3, published_at_ms: 1_700_000_000_000, withheld: null },
  { archive_id: 'a2', generation: null, published_at_ms: null, withheld: 'refused' }
] as const

const RECOVERY_STATES: readonly {
  readonly name: string
  readonly held: Held
  readonly prepare: (page: Page) => Promise<void>
  readonly then?: (page: Page) => Promise<void>
}[] = [
  {
    name: 'off, with the way to turn it on and the way to restore',
    held: { shows: ['recovery-turn-on', 'recovery-restore-choose'], strains: false },
    prepare: () => Promise.resolve()
  },
  {
    name: 'waiting for a sign-in again',
    held: { shows: ['recovery-sign-in'], strains: false },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.recovery.set({ state: 'off', blocker: { reason: 'needs_sign_in' } })
      })
  },
  {
    name: 'on, with its settings stopped',
    held: {
      shows: [
        'recovery-resume-settings',
        'recovery-cover-host',
        'recovery-save-kit',
        'recovery-save-qr',
        'recovery-export-offline'
      ],
      strains: false
    },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.recovery.set({
          state: 'on',
          kept_at: 'reach.kala.to',
          blocker: null,
          settings: { state: 'stopped' }
        })
      })
  },
  {
    name: 'unsettled',
    held: { shows: ['recovery-settle'], strains: false },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.recovery.set({ state: 'unsettled', blocker: null })
      })
  },
  {
    name: 'that could not be read',
    held: { shows: ['Try again'], strains: false },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.recovery.failReads('The recovery state could not be read from this computer.')
      })
  },
  {
    name: 'on, with the choice to replace the backups of this host open',
    held: { shows: ['recovery-replace-confirm', 'recovery-replace-cancel', 'recovery-save-kit'], strains: false },
    prepare: (page) =>
      page.evaluate(() => {
        window.krTestHost?.recovery.set({ state: 'on', kept_at: 'reach.kala.to', blocker: null })
        window.krTestHost?.recovery.coverHostAnswers({
          state: 'left',
          why: { reason: 'other_kit', host_fingerprint: 'WXYZ-1234' }
        })
      }),
    then: async (page) => {
      await page.getByTestId('recovery-cover-host').click()
      await page.getByTestId('recovery-replace-host').click()
      await expect(page.getByTestId('recovery-replace-confirm')).toBeVisible()
    }
  },
  {
    name: 'on, with the copies of its backups listed',
    held: { shows: ['recovery-copy-a1', 'recovery-copies-close'], strains: false },
    prepare: (page) =>
      page.evaluate((archives) => {
        window.krTestHost?.recovery.set({ state: 'on', kept_at: 'reach.kala.to', blocker: null })
        window.krTestHost?.recovery.setArchives(archives)
      }, RECOVERY_ARCHIVES),
    then: async (page) => {
      await page.getByTestId('recovery-export-offline').click()
      await expect(page.getByTestId('recovery-copies')).toBeVisible()
    }
  }
]

for (const form of DESKTOPS) {
  for (const state of RECOVERY_STATES) {
    test(`keeps the controls of the recovery card ${state.name} whole at the largest size in a wide face, ${form.name}`, async ({
      page
    }) => {
      await atTheAccount(page, form, state.prepare)
      await state.then?.(page)
      const found = await measured(page)
      for (const key of state.held.shows) expect(found.keys, `the card shows ${key}`).toContain(key)
      expect(found.outside, 'controls that lie outside the column that holds them').toEqual([])
      expect(found.lines, 'lines that run past the screen or their box').toEqual([])
      await photograph(page, shot(`recovery-${state.held.shows[0] ?? 'none'}-${form.size.toFixed(1)}`))
    })
  }
}

// ---- The notices, shut and open ---------------------------------------------------------------------

for (const form of [...PHONES, ...DESKTOPS]) {
  test(`keeps the notices region whole once it is open at the largest size in a wide face, ${form.name}`, async ({
    page
  }) => {
    await withShortNotices(page)
    await atTheAccount(page, form, () => Promise.resolve())
    const region = page.getByTestId('third-party-notices')
    await region.getByRole('button', { name: 'Show notices' }).click()
    await expect(region.getByRole('button', { name: 'Hide notices' })).toBeVisible()
    // The text of the notices scrolls inside a box of its own, as it always has: what lies beyond
    // that box is meant to, and the measure leaves it out. Only the controls and the lines around
    // it are held to the card.
    await expect(region.locator('.account-notices')).toBeVisible()
    await expect(region.locator('.account-notices')).toHaveCSS('overflow-x', 'auto')
    const found = await measured(page)
    expect(found.keys, 'the region shows the control that shuts it').toContain('Hide notices')
    expect(found.outside, 'controls that lie outside the column that holds them').toEqual([])
    expect(found.lines, 'lines that run past the screen or their box').toEqual([])
    await photograph(page, shot(`notices-open-${form.surface}-${form.size.toFixed(1)}`))
    if (form.surface !== 'desktop') {
      expect(await foundWithoutWrapping(page), 'the measures see a label that cannot wrap run out').not.toEqual([])
    }
  })
}

// ---- Deleting the account ----------------------------------------------------------------------------

/** What the host answers when the person asks to delete the account: the lists the first step shows. */
const DELETION_PREVIEW = {
  address: 's***@example.com',
  warnings: [
    { kind: 'organisation_owner', organisation_id: 'org-1', name: 'Acme', members: 4 },
    { kind: 'subscription' },
    { kind: 'credit' },
    { kind: 'money_owed' }
  ],
  deleted: ['sign_ins', 'passkeys_and_address', 'backup_records', 'recovery_bundle', 'device_registrations'],
  kept: ['billing_records', 'relay_records', 'recovery_copies', 'other_services'],
  unlisted: false,
  kept_records_years: 7,
  backup_file_days: 7,
  code_lifetime_minutes: 5
} as const

/** Signs in, and has the host answer the deletion's first step. */
function signedInAndReadyToDelete(page: Page): Promise<void> {
  return page.evaluate(
    ({ view, preview }) => {
      window.krTestHost?.account.set(view)
      window.krTestHost?.account.deletion.answerView({ state: 'ready', preview })
    },
    { view: SIGNED_IN, preview: DELETION_PREVIEW }
  )
}

for (const form of [...PHONES, ...DESKTOPS]) {
  test(`keeps the controls of the account deletion, asked and then with its code sent, whole at the largest size in a wide face, ${form.name}`, async ({
    page
  }) => {
    await atTheAccount(page, form, signedInAndReadyToDelete)
    await page.getByTestId('delete-account-open').click()
    await expect(page.getByTestId('delete-account-before')).toBeVisible()
    const asked = await measured(page)
    for (const key of ['delete-account-send-code', 'delete-account-cancel']) {
      expect(asked.keys, `the first step shows ${key}`).toContain(key)
    }
    expect(asked.outside, 'controls that lie outside the column that holds them').toEqual([])
    expect(asked.lines, 'lines that run past the screen or their box').toEqual([])
    await photograph(page, shot(`deletion-asked-${form.surface}-${form.size.toFixed(1)}`))

    await page.getByTestId('delete-account-send-code').click()
    await expect(page.getByTestId('delete-account-code')).toBeFocused()
    const sent = await measured(page)
    for (const key of ['delete-account-confirm', 'delete-account-resend']) {
      expect(sent.keys, `the second step shows ${key}`).toContain(key)
    }
    expect(sent.outside, 'controls that lie outside the column that holds them').toEqual([])
    expect(sent.lines, 'lines that run past the screen or their box').toEqual([])
    await photograph(page, shot(`deletion-code-${form.surface}-${form.size.toFixed(1)}`))
  })
}

// ---- A control that fits looks as it did ------------------------------------------------------------

for (const form of [
  { surface: 'ios', size: 1, width: 390, height: 844, name: 'ios, text 1.0x' },
  { surface: 'desktop', size: 1, width: 1280, height: 720, name: 'desktop 1280 wide, text 1.0x' }
] as const satisfies readonly Form[]) {
  test(`gives every control of the panels the box it has when its label cannot wrap, ${form.name}`, async ({
    page
  }) => {
    await atTheAccount(
      page,
      form,
      (each) =>
        each.evaluate((view) => {
          window.krTestHost?.account.setUsage({ state: 'could_not_read' })
          window.krTestHost?.account.set(view)
          window.krTestHost?.recovery.set({
            state: 'on',
            kept_at: 'reach.kala.to',
            blocker: null,
            settings: { state: 'stopped' }
          })
        }, SIGNED_IN),
      false
    )
    const wrapping = await controlsUnder(page, '[data-testid="account-panel"]')
    await page.addStyleTag({
      content: '.btn { white-space: nowrap !important; overflow-wrap: normal !important; max-inline-size: none !important }'
    })
    const kept = await controlsUnder(page, '[data-testid="account-panel"]')
    expect(wrapping.length, 'the panel shows its controls').toBeGreaterThan(5)
    expect(
      wrapping.map((each) => `${each.key}: ${each.width}px, ${each.lines} line`),
      'the box of each control with and without the rule that lets its label wrap'
    ).toEqual(kept.map((each) => `${each.key}: ${each.width}px, ${each.lines} line`))
    expect(
      wrapping.filter((each) => each.lines !== 1).map(describe),
      'controls whose label is on more than one line at the ordinary size'
    ).toEqual([])
  })
}

// ---- A control that is added later wraps too ----------------------------------------------------------

/** The controls of the panel that carry no `data-wraps`, by test id or label, as the page's markup has them. */
function withoutTheAttribute(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="account-panel"] .btn:not([data-wraps])')).map(
      (control) => control.getAttribute('data-testid') ?? (control.textContent ?? '').trim()
    )
  )
}

// A control that cannot wrap is the fault the cases above find at the largest size; this one finds
// it in the markup, in every state the panels open into, so a control added to a column of these
// panels cannot be missed because no case happens to show its state at the largest size.
for (const state of ACCOUNT_STATES) {
  test(`lets every control of the account ${state.name} wrap its label`, async ({ page }) => {
    await atTheAccount(page, PHONES[0], state.prepare, false)
    const keys = (await controlsUnder(page, '[data-testid="account-panel"]')).map((each) => each.key)
    for (const key of state.held.shows) expect(keys, `the panel shows ${key}`).toContain(key)
    expect(await withoutTheAttribute(page), 'controls of the panel whose label cannot wrap').toEqual([])
  })
}

for (const state of RECOVERY_STATES) {
  test(`lets every control of the recovery card ${state.name} wrap its label`, async ({ page }) => {
    await atTheAccount(page, DESKTOPS[0], state.prepare, false)
    await state.then?.(page)
    const keys = (await controlsUnder(page, '[data-testid="account-panel"]')).map((each) => each.key)
    for (const key of state.held.shows) expect(keys, `the card shows ${key}`).toContain(key)
    expect(await withoutTheAttribute(page), 'controls of the panel whose label cannot wrap').toEqual([])
  })
}

test('lets every control of the notices region wrap its label once the region is open', async ({ page }) => {
  await withShortNotices(page)
  await atTheAccount(page, DESKTOPS[0], () => Promise.resolve(), false)
  const region = page.getByTestId('third-party-notices')
  await region.getByRole('button', { name: 'Show notices' }).click()
  await expect(region.getByRole('button', { name: 'Hide notices' })).toBeVisible()
  expect(await withoutTheAttribute(page), 'controls of the panel whose label cannot wrap').toEqual([])
})

test('lets every control of the account deletion, asked and then with its code sent, wrap its label', async ({
  page
}) => {
  await atTheAccount(page, PHONES[0], signedInAndReadyToDelete, false)
  await page.getByTestId('delete-account-open').click()
  await expect(page.getByTestId('delete-account-before')).toBeVisible()
  expect(await withoutTheAttribute(page), 'controls of the panel whose label cannot wrap').toEqual([])
  await page.getByTestId('delete-account-send-code').click()
  await expect(page.getByTestId('delete-account-code')).toBeFocused()
  expect(await withoutTheAttribute(page), 'controls of the panel whose label cannot wrap').toEqual([])
})
