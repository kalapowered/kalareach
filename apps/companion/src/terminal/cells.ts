/**
 * Drawing a view's screen as text on a phone.
 *
 * A phone has no terminal renderer and no parser: each piece of a line becomes a text node with a
 * style, at its column, and the cells no piece covers are spaces. Every piece a phone is sent is
 * plain ASCII or blank, a cell per character, so in a monospaced font the columns line up without
 * anything being measured.
 */

import type { CSSProperties } from 'react'

import type { CellRendition, PaletteState } from '@kalareach/protocol'

import type { TerminalLine, TerminalPiece } from '../host/port'
import { drawableText } from './frame'

type Colour = CellRendition['foreground']

/** The sixteen colours a palette that overrides none of them is drawn with. */
const DEFAULT_SIXTEEN = [
  '#2e3436',
  '#cc0000',
  '#4e9a06',
  '#c4a000',
  '#3465a4',
  '#75507b',
  '#06989a',
  '#d3d7cf',
  '#555753',
  '#ef2929',
  '#8ae234',
  '#fce94f',
  '#729fcf',
  '#ad7fa8',
  '#34e2e2',
  '#eeeeec'
] as const

/** The steps of the 6×6×6 colour cube that indices 16 to 231 name. */
const CUBE = [0, 95, 135, 175, 215, 255] as const

function hex(red: number, green: number, blue: number): string {
  return `#${[red, green, blue].map((part) => Math.min(255, Math.max(0, Math.trunc(part))).toString(16).padStart(2, '0')).join('')}`
}

/** An indexed colour: the palette's override, or the standard colour at that index. */
function indexed(index: number, palette: PaletteState): string {
  const override = palette.overrides.find((each) => each.index === index)
  if (override) return hex(override.colour.red, override.colour.green, override.colour.blue)
  if (index < 16) return DEFAULT_SIXTEEN[index] ?? DEFAULT_SIXTEEN[7]
  if (index < 232) {
    const cube = index - 16
    return hex(
      CUBE[Math.floor(cube / 36) % 6] ?? 0,
      CUBE[Math.floor(cube / 6) % 6] ?? 0,
      CUBE[cube % 6] ?? 0
    )
  }
  const grey = 8 + (index - 232) * 10
  return hex(grey, grey, grey)
}

/** A cell colour as CSS, with `fallback` for the default. */
function css(colour: Colour, palette: PaletteState, fallback: string): string {
  if (typeof colour !== 'object') return fallback
  if ('indexed' in colour) return indexed(Math.min(255, Math.max(0, colour.indexed)), palette)
  return hex(colour.direct.red, colour.direct.green, colour.direct.blue)
}

/** How one piece is drawn: its colours, with reverse video swapping them, and its attributes. */
export function styleOf(rendition: CellRendition, palette: PaletteState): CSSProperties {
  const foreground = hex(palette.foreground.red, palette.foreground.green, palette.foreground.blue)
  const background = hex(palette.background.red, palette.background.green, palette.background.blue)
  let colour = css(rendition.foreground, palette, foreground)
  let fill = css(rendition.background, palette, background)
  if (rendition.reverse) [colour, fill] = [fill, colour]
  const lines = [
    rendition.underline === 'none' ? null : 'underline',
    rendition.strikethrough ? 'line-through' : null,
    rendition.overline ? 'overline' : null
  ].filter((line) => line !== null)
  return {
    color: colour,
    backgroundColor: fill === background ? undefined : fill,
    fontWeight: rendition.bold ? 700 : undefined,
    fontStyle: rendition.italic ? 'italic' : undefined,
    opacity: rendition.faint ? 0.6 : undefined,
    visibility: rendition.invisible ? 'hidden' : undefined,
    textDecorationLine: lines.length > 0 ? lines.join(' ') : undefined
  }
}

/** One stretch of a line as text: a piece, or the blank cells before one. */
export interface Stretch {
  readonly column: number
  readonly text: string
  readonly piece: TerminalPiece | null
}

/**
 * A line as the stretches a phone draws, left to right: each piece at its column, and spaces for
 * the cells before it that no piece covers. A piece that would start inside the one before it is
 * left out, so no column ever moves.
 */
export function stretchesOf(line: TerminalLine): Stretch[] {
  const stretches: Stretch[] = []
  let at = 0
  const pieces = [...line.pieces].sort((one, other) => one.column - other.column)
  for (const piece of pieces) {
    if (piece.column < at) continue
    if (piece.column > at) stretches.push({ column: at, text: ' '.repeat(piece.column - at), piece: null })
    stretches.push({ column: piece.column, text: drawableText(piece.text), piece })
    at = piece.column + Math.max(0, piece.cells)
  }
  return stretches
}
