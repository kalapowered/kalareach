/**
 * How long anything in the interface moves, as a browser engine reads the stylesheets.
 *
 * Section 13 gives the interface one range for motion: default transitions last 120 to 200 ms, and
 * a keyboard command or streamed text is not animated at all. The other browser tests check what a
 * person sees for the keyboard and for streamed text. This one reads every motion declaration in
 * the application's own stylesheets the way the engine does: the engine parses the files, each
 * declaration it parsed is applied to a probe element in the same document, and its duration is
 * taken from the computed style. A comment, a time in any CSS form, a variable or a computed value
 * is therefore read exactly as the engine reads it, rather than by a second parser here.
 */

import { readFileSync, readdirSync } from 'node:fs'

import { expect, test } from '@playwright/test'

/** Every stylesheet under `src`, the design tokens first so their variables are defined. */
function ownStylesheets(): Array<{ file: string; text: string }> {
  const root = new URL('../src/', import.meta.url)
  const files = readdirSync(root, { recursive: true })
    .filter((file) => file.endsWith('.css'))
    .sort((a, b) => Number(!a.endsWith('tokens.css')) - Number(!b.endsWith('tokens.css')))
  return files.map((file) => ({ file, text: readFileSync(new URL(file, root), 'utf8') }))
}

test.describe('motion', () => {
  // KR-REQ-13.20: every transition and animation the application's own stylesheets declare lasts 0
  // or 120 to 200 ms, as the engine reads it. A variable the document root does not define is
  // refused rather than read as nothing, and the same reading of two declarations the stylesheets
  // do not carry, one with a comment inside it, shows that it measures what it is given.
  test('every duration the stylesheets declare is between 120 and 200 ms', async ({ page }) => {
    const sheets = ownStylesheets()
    expect(sheets.map(({ file }) => file)).toContain('styles/tokens.css')
    await page.setContent('<!doctype html><html><head></head><body></body></html>')
    for (const { text } of sheets) await page.addStyleTag({ content: text })

    const read = await page.evaluate(() => {
      const probe = document.createElement('div')
      document.body.append(probe)
      const measure = (property: string, value: string): number[] | string => {
        probe.removeAttribute('style')
        probe.style.setProperty(property, value)
        const computed = getComputedStyle(probe)
        for (const found of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
          if (computed.getPropertyValue(found[1]).trim() === '') {
            return `${found[1]} is undefined`
          }
        }
        const list = property.startsWith('transition')
          ? computed.transitionDuration
          : computed.animationDuration
        return list.split(',').map((time) => {
          const text = time.trim()
          const amount = Number.parseFloat(text)
          return Math.round(text.endsWith('ms') ? amount : amount * 1000)
        })
      }
      const declared: Array<{
        rule: string
        property: string
        value: string
        ms: number[] | string
      }> = []
      let rules = 0
      const walk = (list: CSSRuleList): void => {
        for (const rule of Array.from(list)) {
          rules += 1
          if (rule instanceof CSSStyleRule) {
            for (const property of [
              'transition',
              'transition-duration',
              'animation',
              'animation-duration'
            ]) {
              const value = rule.style.getPropertyValue(property)
              if (value !== '') {
                declared.push({
                  rule: rule.selectorText,
                  property,
                  value,
                  ms: measure(property, value)
                })
              }
            }
          }
          if ('cssRules' in rule) walk((rule as CSSGroupingRule).cssRules)
        }
      }
      for (const sheet of Array.from(document.styleSheets)) walk(sheet.cssRules)
      const controls = [
        measure('transition', 'opacity /* duration */500ms'),
        measure('transition', 'transform .5s')
      ]
      probe.remove()
      return { sheets: document.styleSheets.length, rules, declared, controls }
    })
    expect(read.sheets, 'each stylesheet was loaded').toBe(sheets.length)
    expect(read.rules, 'and the engine parsed their rules').toBeGreaterThan(50)
    expect(read.controls, 'the reading measures what it is given').toEqual([[500], [500]])
    expect(read.declared.length, 'the stylesheets declare motion').toBeGreaterThan(0)
    const outside = read.declared.filter(
      ({ ms }) =>
        typeof ms === 'string' ||
        ms.some((value) => value !== 0 && (value < 120 || value > 200))
    )
    expect(outside, 'a duration outside 120 to 200 ms, or one that could not be read').toEqual([])
  })
})
