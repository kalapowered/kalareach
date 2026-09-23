/**
 * How long anything in the interface moves, read from the stylesheets the application ships.
 *
 * Section 13 gives the interface one range for motion: default transitions last 120 to 200 ms,
 * and a keyboard command or streamed text is not animated at all. The browser tests check what a
 * person sees for the keyboard and for streamed text; this one checks the range across every
 * stylesheet, so a transition added later cannot quietly take longer.
 */

import { describe, expect, it } from 'vitest'

const sheets = import.meta.glob<string>('../src/**/*.css', {
  query: '?raw',
  import: 'default',
  eager: true
})

/** A CSS time in milliseconds. */
function milliseconds(amount: string, unit: string): number {
  const value = Number.parseFloat(amount)
  return unit === 's' ? value * 1000 : value
}

/** The parts of `text` between separators, leaving separators inside parentheses alone. */
function split(text: string, separator: (character: string) => boolean): string[] {
  const found: string[] = []
  let depth = 0
  let current = ''
  for (const character of text) {
    if (character === '(') depth += 1
    if (character === ')') depth -= 1
    if (depth === 0 && separator(character)) {
      found.push(current)
      current = ''
    } else {
      current += character
    }
  }
  found.push(current)
  return found.map((part) => part.trim()).filter((part) => part.length > 0)
}

/** The three duration tokens. */
const DURATION_TOKENS = new Set(['press', 'state', 'surface-in'])

/** The easing tokens, which a declaration may name beside its duration. */
const EASING_TOKENS = new Set(['ease-out', 'ease-in-out'])

/** A CSS time: a number, with or without a leading digit or an exponent, and its unit. */
const TIME = /^\+?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?(ms|s)$/i

describe('motion', () => {
  // KR-REQ-13.20: every transition and animation the interface declares lasts 120 to 200 ms,
  // through the three motion tokens or a literal inside that range. The only shorter value is the
  // zero that the keyboard and reduced-motion rules use to turn motion off. Every word of every
  // declaration is read: a time in any form CSS accepts is measured, and one this check cannot
  // measure, such as another variable, a computed value or an unknown unit, fails rather than
  // being passed over.
  it('keeps every declared duration between 120 and 200 ms', () => {
    const tokens = sheets['../src/styles/tokens.css']
    expect(tokens, 'the motion tokens are defined').toBeDefined()
    const declared = new Map<string, number>()
    for (const match of tokens.matchAll(/--(press|state|surface-in):\s*([\d.]+)(ms|s)\b/g)) {
      declared.set(match[1], milliseconds(match[2], match[3]))
    }
    expect([...declared.values()].sort((a, b) => a - b)).toEqual([120, 160, 200])

    /** How long one word of a declaration lasts, `null` for a word that is not a time. */
    const measure = (word: string): number | null | 'unread' => {
      const time = TIME.exec(word)
      if (time) return milliseconds(`${time[1]}${time[2] ?? ''}`, time[3].toLowerCase())
      const variable = /^var\(\s*--([\w-]+)\s*\)$/.exec(word)
      if (variable) {
        if (DURATION_TOKENS.has(variable[1])) return declared.get(variable[1]) ?? 'unread'
        return EASING_TOKENS.has(variable[1]) ? null : 'unread'
      }
      // An easing function is not a time; any other function could compute one.
      if (/^[\w-]+\(/.test(word)) return /^(cubic-bezier|steps|linear)\(/.test(word) ? null : 'unread'
      // A number with no unit is an iteration count; a number with a unit that is not a time
      // unit is not something this check can measure.
      if (/^[+-]?(\d|\.\d)/.test(word)) return /^\d+(\.\d+)?$/.test(word) ? null : 'unread'
      return null
    }

    const durations: Array<{ sheet: string; declaration: string; ms: number }> = []
    const unread: Array<{ sheet: string; declaration: string }> = []
    for (const [sheet, text] of Object.entries(sheets)) {
      for (const match of text.matchAll(/(?:transition|animation)(?:-duration)?\s*:([^;]*);/g)) {
        // In each item of the list the first time is how long it lasts; a second one is a delay
        // before it starts, which is not a duration.
        for (const declaration of split(match[1], (character) => character === ',')) {
          const times = split(declaration, (character) => /\s/.test(character)).map(measure)
          if (times.includes('unread')) {
            unread.push({ sheet, declaration })
            continue
          }
          const first = times.find((time) => typeof time === 'number')
          if (typeof first === 'number') durations.push({ sheet, declaration, ms: first })
        }
      }
    }
    expect(unread, 'a motion declaration whose time this check cannot read').toEqual([])
    expect(durations.length, 'the interface declares its motion').toBeGreaterThan(0)
    const outside = durations.filter(({ ms }) => ms !== 0 && !(ms >= 120 && ms <= 200))
    expect(outside, 'a duration outside 120 to 200 ms').toEqual([])
  })
})
