/**
 * What the form says of a command before the host is asked (KR-REQ-13.11).
 *
 * The host is the authority on what it saves, and the page's check is feedback only. Both are held
 * to one file of rows, `tests/fixtures/launch-command-rows.json`, which the host's own case
 * (`a_record_or_command_that_breaks_a_rule_is_refused`) and `kr`'s case read too: each refused row
 * names the field, the place of the first refused character and its code point, or a size. The
 * sentences are written out here again, as the host writes them, so that a change of either side
 * fails this case instead of following the code.
 */

import { describe, expect, it } from 'vitest'

import rows from '../../../tests/fixtures/launch-command-rows.json'
import { foresee, holds, offersOf, replaced, type LaunchDraft } from '../src/model/launch-commands'

interface Row {
  readonly name: string
  readonly label: string
  readonly program: string
  readonly arguments: readonly string[]
  readonly refused?: {
    readonly field: 'label' | 'program' | 'argument' | 'arguments' | 'command'
    readonly argument?: number
    readonly position?: number
    readonly code_point?: string
    readonly size?: true
  }
}

const LABEL =
  'A label has 1 to 48 characters, with no control, format, invisible or line-break characters.'
const PROGRAM =
  'A program has 1 to 512 bytes, with no control, format, invisible or line-break characters.'
const ARGUMENT =
  'A command has at most 16 arguments of at most 512 bytes each, with no control, format, invisible or line-break characters. An argument may be empty.'
const TOTAL = 'A command may use at most 3,072 bytes in all, label included.'

/** What the form says of a row the host refuses, written from the row alone. */
function words(row: Row): string | null {
  const refused = row.refused
  if (refused === undefined) return null
  if (refused.size === true) {
    switch (refused.field) {
      case 'label':
        return row.label.trim() === '' ? 'A name is needed.' : LABEL
      case 'program':
        return row.program === '' ? 'A program is needed.' : PROGRAM
      case 'arguments':
      case 'argument':
        return ARGUMENT
      case 'command':
        return TOTAL
    }
  }
  const rule = { label: LABEL, program: PROGRAM, argument: ARGUMENT, arguments: ARGUMENT, command: TOTAL }[
    refused.field
  ]
  const whose =
    refused.field === 'argument'
      ? `argument ${String(refused.argument)}`
      : `the ${refused.field}`
  return `${rule} Character ${String(refused.position)} of ${whose} is ${String(refused.code_point)}, which is not allowed.`
}

const draftOf = (row: Row): LaunchDraft => ({
  label: row.label,
  program: row.program,
  arguments: row.arguments
})

describe('the form foresees what the host refuses', () => {
  const all = rows.rows as unknown as readonly Row[]

  it('reads a file of rows that holds refused and accepted ones', () => {
    expect(all.length).toBeGreaterThan(90)
    expect(all.filter((row) => row.refused !== undefined).length).toBeGreaterThan(70)
    expect(all.filter((row) => row.refused === undefined).length).toBeGreaterThan(5)
  })

  it.each(all.map((row) => [row.name, row] as const))('%s', (_name, row) => {
    const seen = foresee(draftOf(row), [])
    const wanted = words(row)
    if (wanted === null) expect(seen).toBeNull()
    else expect(seen?.words).toBe(wanted)
  })

  it('names the first refused character by its code point and its place in the field as typed', () => {
    // The label is not trimmed before the check: a refused character at the end of a label counts
    // as the position it has in what was typed, and an invisible character is named, not guessed.
    const seen = foresee({ label: 'ab\u200b', program: 'claude', arguments: [] }, [])
    expect(seen).toEqual({
      kind: 'refused',
      words: `${LABEL} Character 3 of the label is U+200B, which is not allowed.`
    })
    const second = foresee(
      { label: 'ok', program: 'claude', arguments: ['fine', 'a\u{e0100}b'] },
      []
    )
    expect(second?.words).toBe(
      `${ARGUMENT} Character 2 of argument 2 is U+E0100, which is not allowed.`
    )
  })

  it('says a full list refuses a new label and not the replacement of a saved one', () => {
    const saved = Array.from({ length: 32 }, (_, index) => ({
      label: `Command ${String(index)}`,
      program: 'claude',
      arguments: []
    }))
    expect(foresee({ label: 'Another', program: 'claude', arguments: [] }, saved)?.words).toBe(
      'This host holds 32 launch commands. Replace one or remove one first.'
    )
    expect(foresee({ label: 'command 7', program: 'claude', arguments: [] }, saved)).toBeNull()
  })

  it('finds the command a label would replace by lower case, in the spelling saved', () => {
    const saved = [{ label: 'Claude Code', program: 'claude', arguments: [] }]
    expect(replaced(' claude code ', saved)?.label).toBe('Claude Code')
    expect(replaced('Codex', saved)).toBeNull()
  })

  it('holds a vector only as the list holds it, word for word and in order', () => {
    const list = {
      revision: '7',
      commands: [{ label: 'Agent', program: 'C:\\tools\\agent.exe', arguments: ['', 'two words'] }]
    }
    const [offer] = offersOf(list)
    expect(offer.vector).toEqual(['C:\\tools\\agent.exe', '', 'two words'])
    expect(holds(list, 'Agent', offer.vector)).toBe(true)
    expect(holds(list, 'Agent', ['C:\\tools\\agent.exe', 'two words'])).toBe(false)
    expect(holds(list, 'Agent', ['C:\\tools\\agent.exe', 'two words', ''])).toBe(false)
    expect(holds(list, 'agent', offer.vector)).toBe(false)
    expect(holds(null, 'Agent', offer.vector)).toBe(false)
  })
})
