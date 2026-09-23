/**
 * How long anything in the interface moves, as a browser engine reads the stylesheets.
 *
 * Section 13 gives the interface one range for motion: default transitions last 120 to 200 ms, and
 * a keyboard command or streamed text is not animated at all. The other browser tests check what a
 * person sees for the keyboard and for streamed text. This one reads every motion declaration in
 * the application's own stylesheets the way the engine does: the engine parses the files, every
 * block of declarations it parsed is visited, nested ones included, and each motion declaration is
 * applied to a probe element in the same document so that its duration is taken from the computed
 * style. A comment, a time in any CSS form or a computed value is therefore read exactly as the
 * engine reads it, rather than by a second parser here.
 *
 * The probe is one element, so a declaration is measured only when every element reads it the same
 * way. The engine settles that for a declaration without variables or other substitutions: its
 * duration must be a plain list of times once parsed, which no element can read differently.
 * Otherwise the declaration must be written in the one form the interface uses, a property or
 * animation name, a duration token and an optional easing, every token it names must be set by the
 * top-level document root and by nothing else, and the duration token's value there must itself be
 * a plain time, so every element inherits the one value the probe reads. Anything else is refused,
 * whatever it is, rather than read.
 */

import { readFileSync, readdirSync } from 'node:fs'

import { expect, test, type Page } from '@playwright/test'

/** Every stylesheet under `src`, the design tokens first so their variables are defined. */
function ownStylesheets(): Array<{ file: string; text: string }> {
  const root = new URL('../src/', import.meta.url)
  return readdirSync(root, { recursive: true })
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => file.endsWith('.css'))
    .sort((a, b) => Number(!a.endsWith('tokens.css')) - Number(!b.endsWith('tokens.css')))
    .map((file) => ({ file, text: readFileSync(new URL(file, root), 'utf8') }))
}

/** One motion declaration, and its durations in seconds or why they could not be read. */
interface Declared {
  readonly where: string
  readonly property: string
  readonly value: string
  readonly seconds: number[] | string
}

/**
 * Reads every motion declaration of the stylesheets `from` onwards in the page's document list.
 *
 * Runs in the page. Every rule the engine parsed is visited, and a rule is read when it holds a
 * block of declarations of its own, whatever kind of rule it is.
 */
async function motionIn(
  page: Page,
  from: number
): Promise<{ rules: number; declared: Declared[] }> {
  return page.evaluate((first) => {
    const MOTION = ['transition', 'transition-duration', 'animation', 'animation-duration']
    const probe = document.createElement('div')
    document.body.append(probe)

    // Where every variable is set, and whether that place is the document root outside any
    // condition. Read from every stylesheet in the document, not only the ones being checked.
    const setAt = new Map<string, Array<{ where: string; atRoot: boolean }>>()
    const found: Array<{ where: string; property: string; value: string }> = []
    let rules = 0
    // A block of declarations nested inside a style rule is named by that rule's selector, so a
    // declaration is named the same way whether the engine keeps it in its own block or not.
    const visit = (list: CSSRuleList, depth: number, reading: boolean, within: string): void => {
      for (const rule of Array.from(list)) {
        if (reading) rules += 1
        const where =
          rule instanceof CSSStyleRule
            ? rule.selectorText
            : within !== ''
              ? within
              : rule.cssText.slice(0, 60)
        if (rule.constructor.name === 'CSSPropertyRule') {
          const name = (rule as unknown as { name: string }).name
          setAt.set(name, [...(setAt.get(name) ?? []), { where: '@property', atRoot: false }])
        }
        const style = (rule as unknown as { style?: unknown }).style
        if (style instanceof CSSStyleDeclaration) {
          const atRoot =
            depth === 0 && rule instanceof CSSStyleRule && rule.selectorText === ':root'
          for (let index = 0; index < style.length; index += 1) {
            const name = style.item(index)
            if (name.startsWith('--')) {
              setAt.set(name, [...(setAt.get(name) ?? []), { where, atRoot }])
            }
          }
          if (reading) {
            for (const property of MOTION) {
              const value = style.getPropertyValue(property)
              if (value !== '') found.push({ where, property, value })
            }
          }
        }
        const children = (rule as unknown as { cssRules?: unknown }).cssRules
        if (children instanceof CSSRuleList) {
          visit(children, depth + 1, reading, rule instanceof CSSStyleRule ? where : within)
        }
      }
    }
    Array.from(document.styleSheets).forEach((sheet, index) => {
      visit(sheet.cssRules, 0, index >= first, '')
    })

    // The one written form a declaration that uses variables may take: per item, a property or
    // animation name, a duration token, an optional easing token or keyword and an optional delay
    // written as a plain time.
    const EASING = [
      String.raw`var\((--ease-out|--ease-in-out)\)`,
      'ease',
      'linear',
      'ease-in',
      'ease-out',
      'ease-in-out'
    ].join('|')
    const DURATION = String.raw`var\((--press|--state|--surface-in)\)`
    const TIME = String.raw`\d+(?:\.\d+)?m?s`
    const ITEM = new RegExp(
      String.raw`^[a-z][a-z0-9-]*\s+${DURATION}(?:\s+(?:${EASING}))?(?:\s+${TIME})?$`
    )
    const ALONE = new RegExp(`^${DURATION}$`)
    // How the engine writes a list of durations it parsed with no context: nothing but times, or
    // `auto`, which a time-based animation reads as zero.
    const PLAIN = new RegExp(`^(?:auto|${TIME})(?:, (?:auto|${TIME}))*$`)
    // Whether the engine parses `value` as a duration with no element context: plain times.
    const scratch = document.createElement('div')
    const plain = (value: string): boolean => {
      scratch.removeAttribute('style')
      scratch.style.setProperty('transition-duration', value)
      return PLAIN.test(scratch.style.getPropertyValue('transition-duration'))
    }
    const measure = (property: string, value: string): number[] | string => {
      const longhand = property.startsWith('transition')
        ? 'transition-duration'
        : 'animation-duration'
      const form = property === longhand ? ALONE : ITEM
      const items = value.split(',').map((item) => form.exec(item.trim()))
      probe.removeAttribute('style')
      probe.style.setProperty(property, value)
      if (items.every((item) => item !== null)) {
        for (const item of items) {
          for (const name of item.slice(1).filter((each) => each !== undefined)) {
            const places = setAt.get(name) ?? []
            if (places.length === 0) return `${name} is set nowhere`
            const elsewhere = places.find((place) => !place.atRoot)
            if (elsewhere) return `${name} is also set by ${elsewhere.where}`
          }
          // The duration token's own value, as the root holds it, has to be a plain time too: a
          // value the engine keeps unparsed until an element uses it could be read differently
          // by every element.
          const atRoot = getComputedStyle(document.documentElement)
            .getPropertyValue(item[1])
            .trim()
          if (!plain(atRoot)) return `${item[1]} is not a plain time at the root: ${atRoot}`
        }
      } else {
        const specified = probe.style.getPropertyValue(longhand)
        if (!PLAIN.test(specified)) return `not plain times for every element: ${value}`
      }
      const computed = getComputedStyle(probe)
      const list = property.startsWith('transition')
        ? computed.transitionDuration
        : computed.animationDuration
      return list.split(',').map((time) => {
        const text = time.trim()
        const amount = Number.parseFloat(text)
        return text.endsWith('ms') ? amount / 1000 : amount
      })
    }
    const declared = found.map((each) => ({
      ...each,
      seconds: measure(each.property, each.value)
    }))
    probe.remove()
    return { rules, declared }
  }, from)
}

/** The declarations whose durations are not all zero or 120 to 200 ms, or could not be read. */
function outsideTheRange(declared: Declared[]): Declared[] {
  return declared.filter(
    ({ seconds }) =>
      typeof seconds === 'string' ||
      seconds.some((value) => value !== 0 && !(value >= 0.12 && value <= 0.2))
  )
}

test.describe('motion', () => {
  // KR-REQ-13.20: every transition and animation the application's own stylesheets declare lasts 0
  // or 120 to 200 ms, as the engine reads it, including a declaration nested inside another rule; a
  // declaration an element could read differently from the probe is refused rather than read. The
  // same reading of a sheet this test adds shows it measures what it is given: a comment inside a
  // time, a time with no leading digit, a declaration after a nested rule, a duration token a rule
  // sets again, a variable outside the interface's tokens and a token whose own value depends on
  // the element.
  test('every duration the stylesheets declare is between 120 and 200 ms', async ({ page }) => {
    const sheets = ownStylesheets()
    expect(sheets.map(({ file }) => file)).toContain('styles/tokens.css')
    await page.setContent('<!doctype html><html><head></head><body></body></html>')
    for (const { text } of sheets) await page.addStyleTag({ content: text })

    const own = await motionIn(page, 0)
    expect(own.rules, 'the engine parsed the stylesheets').toBeGreaterThan(50)
    expect(own.declared.length, 'the stylesheets declare motion').toBeGreaterThan(0)
    expect(outsideTheRange(own.declared), 'a duration outside 120 to 200 ms, or unread').toEqual([])

    await page.addStyleTag({
      content: `
        .kr-comment { transition: opacity /* duration */500ms; }
        .kr-leading { transition: transform .5s; }
        .kr-nested { @media (min-width: 0px) { color: red; } transition: opacity 500ms; }
        .kr-reset { --state: 500ms; transition: opacity var(--state) ease; }
        .kr-other { --é: 500ms; transition: opacity var(--é); }
        :root { --surface-in: calc(160ms + 340ms * sign(1em - 16px)); }
        .kr-relative { transition: opacity var(--surface-in); }
      `
    })
    const controls = await motionIn(page, sheets.length)
    // A shorthand is read through its longhand as well, so a control can be read more than once;
    // every reading of it has to say the same thing.
    const expected: Record<string, number[] | string> = {
      '.kr-comment': [0.5],
      '.kr-leading': [0.5],
      '.kr-nested': [0.5],
      '.kr-reset': '--state is also set by .kr-reset',
      '.kr-other': 'not plain times for every element: opacity var(--é)',
      '.kr-relative':
        '--surface-in is not a plain time at the root: calc(160ms + 340ms * sign(1em - 16px))'
    }
    const readings = controls.declared.map(({ where, seconds }) => ({
      control: where.split(' ')[0],
      seconds
    }))
    expect(
      [...new Set(readings.map(({ control }) => control))],
      'every control is read'
    ).toEqual(Object.keys(expected))
    for (const { control, seconds } of readings) {
      expect(seconds, `${control} is read as what it declares`).toEqual(expected[control])
    }
  })
})
