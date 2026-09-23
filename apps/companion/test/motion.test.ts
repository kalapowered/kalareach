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

/** The items of a comma-separated list, leaving the commas inside parentheses alone. */
function items(list: string): string[] {
  const found: string[] = []
  let depth = 0
  let current = ''
  for (const character of list) {
    if (character === '(') depth += 1
    if (character === ')') depth -= 1
    if (character === ',' && depth === 0) {
      found.push(current)
      current = ''
    } else {
      current += character
    }
  }
  found.push(current)
  return found
}

describe('motion', () => {
  // KR-REQ-13.20: every transition and animation the interface declares lasts 120 to 200 ms,
  // through the three motion tokens or a literal inside that range. The only shorter value is the
  // zero that the keyboard and reduced-motion rules use to turn motion off.
  it('keeps every declared duration between 120 and 200 ms', () => {
    const tokens = sheets['../src/styles/tokens.css']
    expect(tokens, 'the motion tokens are defined').toBeDefined()
    const declared = new Map<string, number>()
    for (const match of tokens.matchAll(/--(press|state|surface-in):\s*([\d.]+)(ms|s)\b/g)) {
      declared.set(match[1], milliseconds(match[2], match[3]))
    }
    expect([...declared.values()].sort((a, b) => a - b)).toEqual([120, 160, 200])

    const durations: Array<{ sheet: string; declaration: string; ms: number }> = []
    for (const [sheet, text] of Object.entries(sheets)) {
      for (const match of text.matchAll(/(?:transition|animation)(?:-duration)?\s*:([^;]*);/g)) {
        // In each item of the list the first time is how long it lasts; a second one is a delay
        // before it starts, which is not a duration.
        for (const declaration of items(match[1])) {
          const time = /var\(--(press|state|surface-in)\)|(?<![\w.-])(\d+(?:\.\d+)?)(ms|s)\b/.exec(
            declaration
          )
          if (time === null) continue
          const ms =
            time[1] !== undefined
              ? (declared.get(time[1]) ?? Number.NaN)
              : milliseconds(time[2], time[3])
          durations.push({ sheet, declaration, ms })
        }
      }
    }
    expect(durations.length, 'the interface declares its motion').toBeGreaterThan(0)
    const outside = durations.filter(({ ms }) => ms !== 0 && !(ms >= 120 && ms <= 200))
    expect(outside, 'a duration outside 120 to 200 ms').toEqual([])
  })
})
