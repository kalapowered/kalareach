/**
 * The terminal recording: each screen the raw view drew, when it drew it and at the grid it drew
 * it in, written as the drawing a player repeats.
 *
 * The drawing is checked by playing it: a small player below carries out the sequences a
 * recording may hold and nothing else, so a recording that held any other sequence, or that drew a
 * piece anywhere but its cells, fails here.
 */

import { describe, expect, it } from 'vitest'

import type { CellRendition } from '@kalareach/protocol'

import { terminalScreen } from '../src/host/fake'
import type { TerminalPiece, TerminalScreen } from '../src/host/port'
import {
  emptyRecording,
  MAX_RECORDED_FRAMES,
  recorded,
  recordingExport,
  screenText
} from '../src/model/recording'
import { copiedText, placedPieces } from '../src/terminal/frame'
import drawn from './fixtures/drawn-screens.json'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const PLAIN: CellRendition = {
  background: 'default',
  blink: 'none',
  bold: false,
  faint: false,
  foreground: 'default',
  invisible: false,
  italic: false,
  overline: false,
  reverse: false,
  strikethrough: false,
  underline: 'none',
  underline_colour: 'default',
  vertical_align: 'baseline'
}

function piece(column: number, text: string, cells = [...text].length, rendition = PLAIN): TerminalPiece {
  return { column, cells, text, rendition, hyperlink: null }
}

/** A screen of `columns` by `rows` whose lines hold `pieces`, with the cursor where it says. */
function screenOf(
  columns: number,
  rows: number,
  pieces: readonly (readonly TerminalPiece[])[],
  cursor: TerminalScreen['cursor'] = null
): TerminalScreen {
  return {
    ...terminalScreen(SESSION_MAIN, { columns, rows }),
    window: { columns, rows, column: 0, line: 0, above: 0 },
    lines: Array.from({ length: rows }, (_, index) => ({
      row: String(index + 1),
      soft_wrapped: false,
      truncated: false,
      pieces: pieces[index] ?? []
    })),
    cursor
  }
}

/** What a player shows after drawing `text`: each line, the colours of each cell, and the cursor. */
interface Played {
  readonly lines: string[]
  readonly colours: string[][]
  readonly cursor: { readonly line: number; readonly column: number } | null
}

/**
 * Plays `text` on a grid of `columns` by `rows`, one cell per character. It knows the cursor
 * position, the clears, the colours, line wrapping and the cursor's visibility, and throws on any
 * other sequence and on any control character.
 */
function play(text: string, columns: number, rows: number): Played {
  const cells = Array.from({ length: rows }, () => Array.from({ length: columns }, () => ' '))
  const colours = Array.from({ length: rows }, () => Array.from({ length: columns }, () => '0'))
  let line = 0
  let column = 0
  let sgr = '0'
  let wrapping = true
  let visible = true
  let at = 0
  const erase = (from: number, to: number) => {
    for (let each = from; each < Math.min(to, columns); each += 1) {
      const row = cells[line]
      const tint = colours[line]
      if (row === undefined || tint === undefined) continue
      row[each] = ' '
      tint[each] = sgr
    }
  }
  while (at < text.length) {
    const character = text[at] ?? ''
    if (character === '\u001b') {
      // Only a control sequence: an escape, a bracket, parameters and a final letter.
      const sequence = /^\[(\??)([0-9;]*)([A-Za-z])/.exec(text.slice(at + 1))
      if (sequence === null) throw new Error(`not a sequence a recording holds at ${at}`)
      const [body, mark, parameters, final] = sequence
      const whole = `\u001b${body}`
      const numbers = (parameters ?? '').split(';').map((each) => (each === '' ? 0 : Number(each)))
      at += whole.length
      if (mark === '?') {
        if (parameters === '7' && final === 'l') wrapping = false
        else if (parameters === '7' && final === 'h') wrapping = true
        else if (parameters === '25' && final === 'l') visible = false
        else if (parameters === '25' && final === 'h') visible = true
        else throw new Error(`a mode a recording never sets: ${JSON.stringify(whole)}`)
        continue
      }
      switch (final) {
        case 'H':
          line = Math.min(rows, Math.max(1, numbers[0] || 1)) - 1
          column = Math.min(columns, Math.max(1, numbers[1] || 1)) - 1
          break
        case 'J':
          if (parameters !== '2') throw new Error('only a whole clear')
          for (let row = 0; row < rows; row += 1) {
            cells[row]?.fill(' ')
            colours[row]?.fill(sgr)
          }
          break
        case 'm':
          sgr = parameters === '' ? '0' : (parameters ?? '0')
          break
        case 'X':
          erase(column, column + Math.max(1, numbers[0] ?? 1))
          break
        case 'K':
          if (parameters !== '') throw new Error('only a clear to the end of the line')
          erase(column, columns)
          break
        default:
          throw new Error(`a sequence a recording never holds: ${JSON.stringify(whole)}`)
      }
      continue
    }
    const code = character.codePointAt(0) ?? 0
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) throw new Error(`a control character at ${at}`)
    const row = cells[line]
    const tint = colours[line]
    if (row !== undefined && tint !== undefined) {
      row[column] = character
      tint[column] = sgr
    }
    if (column < columns - 1) column += 1
    else if (wrapping) {
      line = Math.min(rows - 1, line + 1)
      column = 0
    }
    at += 1
  }
  return {
    lines: cells.map((row) => row.join('').trimEnd()),
    colours,
    cursor: visible ? { line, column } : null
  }
}

describe('a screen as a recording draws it (KR-REQ-25.25)', () => {
  it('draws each piece at its own cells, as the view does, and the cursor where the view drew it', () => {
    const drawnScreen = screenOf(
      12,
      3,
      [[piece(0, '$ ls')], [piece(0, 'a.txt'), piece(8, 'b')], []],
      { line: 2, column: 2, style: 1, visible: true }
    )
    const played = play(screenText(drawnScreen), 12, 3)
    expect(played.lines.join('\n').trimEnd()).toBe(copiedText(placedPieces(drawnScreen)))
    expect(played.lines).toEqual(['$ ls', 'a.txt   b', ''])
    expect(played.cursor).toEqual({ line: 2, column: 2 })
  })

  it('hides the cursor when the view drew none, and when it is outside the window', () => {
    const hidden = screenOf(8, 2, [[piece(0, 'x')]], { line: 0, column: 1, style: 1, visible: false })
    expect(play(screenText(hidden), 8, 2).cursor).toBeNull()
    const outside = screenOf(8, 2, [[piece(0, 'x')]], { line: 5, column: 1, style: 1, visible: true })
    expect(play(screenText(outside), 8, 2).cursor).toBeNull()
  })

  it('draws each piece in the colours the view resolves through the palette, and the rest in its background', () => {
    const red: CellRendition = { ...PLAIN, foreground: { indexed: 1 }, bold: true }
    const filled: CellRendition = { ...PLAIN, background: { direct: { red: 10, green: 20, blue: 300 } } }
    const played = play(
      screenText(screenOf(8, 1, [[piece(0, 'ok', 2, red), piece(3, '', 3, filled)]])),
      8,
      1
    )
    const tints = played.colours[0] ?? []
    // Index 1 is the palette's own red, and the default background is the palette's.
    expect(tints.slice(0, 2)).toEqual(Array(2).fill('0;1;38;2;162;53;46;48;2;7;18;23'))
    // A box with no text is still drawn in its colours, at exactly its cells, held to a byte, in
    // the palette's default text colour.
    expect(tints.slice(3, 6)).toEqual(Array(3).fill('0;38;2;220;220;218;48;2;10;20;255'))
    // Every cell no piece covers is the session's background, not the player's.
    expect([tints[2], tints[6], tints[7]]).toEqual(Array(3).fill('0;48;2;7;18;23'))
  })

  it('draws an underline in its own colour', () => {
    const underlined: CellRendition = { ...PLAIN, underline: 'single', underline_colour: { indexed: 1 } }
    const played = play(screenText(screenOf(4, 1, [[piece(0, 'ul', 2, underlined)]])), 4, 1)
    expect(played.colours[0]?.[0]).toBe('0;4;38;2;220;220;218;48;2;7;18;23;58;2;162;53;46')
  })

  it('keeps text a player lays out wider than its cells inside the cells the view gave it', () => {
    const played = play(
      screenText(screenOf(8, 3, [[piece(0, 'abcd', 2), piece(4, 'xy')], [piece(6, 'wxyz', 2)], []])),
      8,
      3
    )
    // The spill after a box is cleared before the next piece is drawn.
    expect(played.lines[0]).toBe('ab  xy')
    // At the window's edge the text stays on its line rather than running onto the next.
    expect(played.lines[1]).toMatch(/^ {6}w./)
    expect(played.lines[2]).toBe('')
  })

  it('draws a control character in a piece as a mark, never as itself', () => {
    const text = screenText(screenOf(12, 1, [[piece(0, 'a\u001b]52;c;x\u0007b')]]))
    const played = play(text, 12, 1)
    expect(played.lines[0]).toBe('a\u{FFFD}]52;c;x\u{FFFD}b')
    expect(text).not.toContain('\u0007')
  })

  it('writes each screen exactly as the export is checked to keep it', () => {
    // The native export keeps what the view draws with, byte for byte, and removes every other
    // sequence. Between them these two screens use every sequence the view draws with, and the
    // export's own tests replay the same text, so a sequence the view starts to write is one the
    // export has to be taught to keep.
    const prompt: CellRendition = { ...PLAIN, bold: true, foreground: { indexed: 2 } }
    const styled: CellRendition = {
      ...PLAIN,
      faint: true,
      italic: true,
      underline: 'double',
      underline_colour: { indexed: 1 },
      background: { direct: { red: 10, green: 20, blue: 30 } }
    }
    const marked: CellRendition = {
      ...PLAIN,
      reverse: true,
      invisible: true,
      strikethrough: true,
      overline: true,
      underline: 'single'
    }
    const shown = screenOf(
      12,
      2,
      [[piece(0, '$ ls', 4, prompt), piece(5, 'é界', 3, styled)], [piece(0, 'x', 1, marked)]],
      { line: 1, column: 2, style: 1, visible: true }
    )
    const hidden = screenOf(4, 1, [[piece(0, 'ok')]])
    const shownText = drawn.screens['colours, attributes and wide text, with the cursor shown']
    const hiddenText = drawn.screens['a plain line, with the cursor hidden']
    expect(screenText(shown)).toBe(shownText)
    expect(screenText(hidden)).toBe(hiddenText)
    expect(play(shownText, 12, 2).cursor).toEqual({ line: 1, column: 2 })
    expect(play(hiddenText, 4, 1).cursor).toBeNull()
  })

  it('draws only the pieces the view places: none past the right edge, none inside another', () => {
    const played = play(
      screenText(screenOf(6, 1, [[piece(0, 'abcd'), piece(2, 'zz'), piece(6, 'past')]])),
      6,
      1
    )
    expect(played.lines[0]).toBe('abcd')
  })
})

describe('the recording the raw view keeps (KR-REQ-25.25)', () => {
  const first = screenOf(10, 2, [[piece(0, 'one')]])
  const second = screenOf(10, 2, [[piece(0, 'two')]])

  it('holds nothing until the view draws, and exports nothing then', () => {
    expect(recordingExport(emptyRecording())).toBeNull()
  })

  it('keeps each screen once, with its time from the first, at the size the view drew it', () => {
    let recording = recorded(emptyRecording(), first, 1_700_000_000_250)
    recording = recorded(recording, first, 1_700_000_000_400)
    recording = recorded(recording, second, 1_700_000_001_000)
    const exported = recordingExport(recording)
    expect(exported?.startedAtUnixSeconds).toBe(1_700_000_000)
    expect(exported?.dimensions).toEqual({ columns: 10, rows: 2 })
    expect(exported?.frames.map((frame) => frame.at_ms)).toEqual([0, 750])
    expect(exported?.frames.map((frame) => play(frame.text, 10, 2).lines[0])).toEqual(['one', 'two'])
    expect(exported?.omissions).toEqual([])
  })

  it('plays at the last size, and declares the screens drawn at another', () => {
    let recording = recorded(emptyRecording(), first, 0)
    recording = recorded(recording, screenOf(20, 4, [[piece(0, 'wide')]]), 10)
    recording = recorded(recording, screenOf(20, 4, [[piece(0, 'wider')]]), 20)
    const exported = recordingExport(recording)
    expect(exported?.dimensions).toEqual({ columns: 20, rows: 4 })
    expect(exported?.omissions).toEqual([
      {
        kind: 'resized_screens',
        detail: 'Screens drawn at another size, which play back at 20×4',
        count: 1
      }
    ])
  })

  it('keeps a screen whose palette alone changed, since the view drew it in other colours', () => {
    const one = screenOf(10, 2, [[piece(0, 'same')]])
    const other = { ...one, palette: { ...one.palette, background: { red: 250, green: 250, blue: 250 } } }
    let recording = recorded(emptyRecording(), one, 0)
    recording = recorded(recording, other, 10)
    expect(recordingExport(recording)?.frames).toHaveLength(2)
  })

  it('declares what a player draws in its own way: the cursor, and underlines other than single or double', () => {
    const curly: CellRendition = { ...PLAIN, underline: 'curly' }
    let recording = recorded(
      emptyRecording(),
      screenOf(10, 2, [[piece(0, 'wavy', 4, curly)]], { line: 0, column: 4, style: 3, visible: true }),
      0
    )
    recording = recorded(recording, screenOf(10, 2, [[piece(0, 'plain')]]), 10)
    expect(recordingExport(recording)?.omissions).toEqual([
      {
        kind: 'underline_styles',
        detail: 'Curly, dotted and dashed underlines, which play back as single ones',
        count: 1
      },
      {
        kind: 'cursor_style',
        detail: "The cursor's shape and colour, which a player draws in its own",
        count: 1
      }
    ])
  })

  it('keeps a screen whose only change is an underline a player draws as a single one, and declares it', () => {
    const single: CellRendition = { ...PLAIN, underline: 'single' }
    const curly: CellRendition = { ...PLAIN, underline: 'curly' }
    let recording = recorded(emptyRecording(), screenOf(10, 1, [[piece(0, 'wavy', 4, single)]]), 0)
    recording = recorded(recording, screenOf(10, 1, [[piece(0, 'wavy', 4, curly)]]), 10)
    expect(recording.frames).toHaveLength(2)
    expect(recordingExport(recording)?.omissions).toContainEqual({
      kind: 'underline_styles',
      detail: 'Curly, dotted and dashed underlines, which play back as single ones',
      count: 1
    })
  })

  it('counts its bound in bytes, and keeps no screen larger than the whole bound', () => {
    // Each of these is under the bound in UTF-16 units and over half of it in bytes.
    const wide = (mark: string) => screenOf(10, 1, [[piece(0, mark.repeat(1_500_000), 10)]])
    let recording = recorded(emptyRecording(), wide('€'), 0)
    recording = recorded(recording, wide('₹'), 10)
    expect(recording.frames).toHaveLength(1)
    expect(recording.dropped).toBe(1)
    // One screen larger than the whole bound is not kept at all, and is declared.
    recording = recorded(recording, screenOf(10, 1, [[piece(0, '€'.repeat(3_000_000), 10)]]), 20)
    expect(recording.frames).toHaveLength(1)
    expect(recordingExport(recording)?.omissions).toContainEqual({
      kind: 'oversized_screens',
      detail: 'Screens larger than the whole recording keeps',
      count: 1
    })
  })

  it('records no screen of no cells', () => {
    expect(recorded(emptyRecording(), screenOf(0, 0, []), 0).frames).toHaveLength(0)
  })

  it('lets the oldest screens go past its bound, and says how many went', () => {
    let recording = emptyRecording()
    for (let index = 0; index < MAX_RECORDED_FRAMES + 5; index += 1) {
      recording = recorded(recording, screenOf(10, 1, [[piece(0, String(index))]]), index)
    }
    const exported = recordingExport(recording)
    expect(exported?.frames).toHaveLength(MAX_RECORDED_FRAMES)
    expect(exported?.frames[0]?.at_ms).toBe(0)
    expect(play(exported?.frames[0]?.text ?? '', 10, 1).lines[0]).toBe('5')
    expect(exported?.omissions).toEqual([
      {
        kind: 'earlier_screens',
        detail: 'Screens the view drew before the recording reached its bound',
        count: 5
      }
    ])
  })
})
