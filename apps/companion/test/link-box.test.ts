/**
 * The declarations that give a link of a message its box on a phone, and the pane the link is tapped in.
 *
 * Nothing here measures a layout: jsdom has none. The browser cases (`e2e/accessibility.spec.ts`, "the box
 * of a link in a message") hold what the declarations do in both engines; this holds the declarations, so
 * that a rule taken out or loosened is seen without a browser.
 */

import { describe, expect, it } from 'vitest'

const sheets = import.meta.glob('../src/mobile/mobile.css', { query: '?raw', import: 'default', eager: true })
const sheet = String(sheets['../src/mobile/mobile.css'] ?? '').replace(/\/\*[\s\S]*?\*\//g, '')

/** The declarations of the rule whose selector is exactly `selector`, by property, with their whitespace folded. */
function rule(selector: string): Map<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const found = new RegExp(`(?:^|\\})\\s*${escaped}\\s*\\{([^}]*)\\}`, 'm').exec(sheet)
  if (found === null) return new Map()
  const declarations = new Map<string, string>()
  for (const declaration of (found[1] ?? '').split(';')) {
    const colon = declaration.indexOf(':')
    if (colon < 0) continue
    declarations.set(declaration.slice(0, colon).trim(), declaration.slice(colon + 1).replace(/\s+/g, ' ').trim())
  }
  return declarations
}

describe('the box of a link in a message', () => {
  const link = rule('.m-node .md-link')

  it('is padded to the least size above and below, and the margin takes the same room back so no line or word moves', () => {
    expect(link.get('--md-link-pad'), 'the room above and below: half of what the line lacks of the least size').toBe(
      'max(0px, calc((var(--target) - 1lh) / 2 + 0.05px))'
    )
    expect(link.get('padding-block'), 'the padding of the button above and below').toBe('var(--md-link-pad)')
    expect(link.get('margin-block'), 'the margin of the button above and below').toBe('calc(-1 * var(--md-link-pad))')
  })

  it('is padded beside its words by what the page measures for it, and the margin takes the same room back', () => {
    expect(link.get('padding-left'), 'the padding on the left').toBe('var(--md-link-left, 0px)')
    expect(link.get('padding-right'), 'the padding on the right').toBe('var(--md-link-right, 0px)')
    expect(link.get('margin-left'), 'the margin on the left').toBe('calc(-1 * var(--md-link-left, 0px))')
    expect(link.get('margin-right'), 'the margin on the right').toBe('calc(-1 * var(--md-link-right, 0px))')
    // A shorthand or a logical property beside these would give a second room that nothing measures.
    for (const name of ['padding', 'margin', 'padding-inline', 'margin-inline', 'padding-inline-start', 'padding-inline-end', 'margin-inline-start', 'margin-inline-end']) {
      expect(link.has(name), `a ${name} of the button`).toBe(false)
    }
  })

  it('takes no tap in its padded room: the button has no hit of its own and the words keep theirs', () => {
    expect(link.get('pointer-events')).toBe('none')
    expect(rule('.m-node .md-link-label').get('pointer-events')).toBe('auto')
  })

  it('shows the focus ring on the words, in the accent of every other ring, and none on the padded box', () => {
    expect(rule('.m-node .md-link:focus-visible').get('outline')).toBe('none')
    const ring = rule('.m-node .md-link:focus-visible .md-link-label')
    expect(ring.get('outline')).toBe('2px solid var(--accent)')
    expect(ring.get('outline-offset')).toBe('2px')
  })
})

describe('the pane a message is tapped in', () => {
  it('has no scroll bar, so that no strip at its right edge takes the hit of a tap on the words that end there', () => {
    expect(rule('.m-pane').get('overflow-y'), 'the reader finds the pane’s rule').toBe('auto')
    expect(rule('.m-pane').get('scrollbar-width')).toBe('none')
    expect(rule('.m-pane::-webkit-scrollbar').get('display')).toBe('none')
  })
})
