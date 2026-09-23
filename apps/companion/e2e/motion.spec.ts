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
 * A variable is where the probe could read something an element does not: an element under a rule
 * that sets the variable again would see that value instead. So a motion declaration may use a
 * variable only when the one place any stylesheet sets it is the document root, outside any
 * condition, where the probe reads the same value every element does; any other is refused.
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

    const measure = (property: string, value: string): number[] | string => {
      for (const used of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
        const places = setAt.get(used[1]) ?? []
        if (places.length === 0) return `${used[1]} is set nowhere`
        const elsewhere = places.find((place) => !place.atRoot)
        if (elsewhere) return `${used[1]} is also set by ${elsewhere.where}`
      }
      probe.removeAttribute('style')
      probe.style.setProperty(property, value)
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
  // or 120 to 200 ms, as the engine reads it, including a declaration nested inside another rule.
  // A variable the root does not set once and alone is refused rather than read. The same reading
  // of a sheet this test adds shows it measures what it is given: a comment inside a time, a time
  // with no leading digit, a declaration after a nested rule and a variable a rule sets again.
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
        .kr-scoped { --kr-motion: 500ms; transition: opacity var(--kr-motion); }
      `
    })
    const controls = await motionIn(page, sheets.length)
    // A shorthand is read through its longhand as well, so a control can be read more than once;
    // every reading of it has to say the same thing.
    const expected: Record<string, number[] | string> = {
      '.kr-comment': [0.5],
      '.kr-leading': [0.5],
      '.kr-nested': [0.5],
      '.kr-scoped': '--kr-motion is also set by .kr-scoped'
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
