/**
 * Drawing a view's screen as text on a phone.
 *
 * A phone has no terminal renderer and no parser: each piece of a line becomes a text node with a
 * style, at its column, and the cells no piece covers are spaces. Native code sends a phone only
 * pieces of printable ASCII, a cell per character, so in a monospaced font the columns line up
 * without anything being measured. A piece that is anything else did not come from native code, and
 * a phone cannot say how wide it would draw, so it is drawn as blank cells.
 */

import type { CSSProperties } from 'react'

import type { CellRendition, PaletteState } from '@kalareach/protocol'

import type { TerminalLine, TerminalPiece, TerminalScreen } from '../host/port'

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
function css<Fallback>(colour: Colour, palette: PaletteState, fallback: Fallback): string | Fallback {
  if (typeof colour !== 'object') return fallback
  if ('indexed' in colour) return indexed(Math.min(255, Math.max(0, colour.indexed)), palette)
  return hex(colour.direct.red, colour.direct.green, colour.direct.blue)
}

/** A colour from `hex` at half strength, which is how faint text is drawn. */
function halfStrength(colour: string): string {
  const part = (at: number) => parseInt(colour.slice(at, at + 2), 16)
  return `rgba(${part(1)}, ${part(3)}, ${part(5)}, 0.5)`
}

/** The line each underline style is drawn with. */
const UNDERLINE_STYLE: Readonly<
  Record<Exclude<CellRendition['underline'], 'none'>, CSSProperties['textDecorationStyle']>
> = {
  single: 'solid',
  double: 'double',
  curly: 'wavy',
  dotted: 'dotted',
  dashed: 'dashed'
}

/**
 * How one piece is drawn: its colours, with reverse video swapping them, and its attributes.
 *
 * Faint text is drawn at half strength and invisible text in no colour, each over the piece's own
 * background; an invisible piece keeps its underline. CSS draws every line of one element in one
 * style and colour, so a strikethrough or an overline on an underlined piece takes the underline's.
 * The desktop draws its pieces with this too.
 */
export function styleOf(rendition: CellRendition, palette: PaletteState): CSSProperties {
  const foreground = hex(palette.foreground.red, palette.foreground.green, palette.foreground.blue)
  const background = hex(palette.background.red, palette.background.green, palette.background.blue)
  let colour = css(rendition.foreground, palette, foreground)
  let fill = css(rendition.background, palette, background)
  if (rendition.reverse) [colour, fill] = [fill, colour]
  const underlined = rendition.underline !== 'none'
  const lines = [
    underlined ? 'underline' : null,
    rendition.strikethrough ? 'line-through' : null,
    rendition.overline ? 'overline' : null
  ].filter((line) => line !== null)
  const drawn = rendition.faint ? halfStrength(colour) : colour
  // An underline in the default colour takes the text's, which invisible text does not show.
  const underlineColour = underlined
    ? css(rendition.underline_colour, palette, rendition.invisible ? drawn : undefined)
    : undefined
  return {
    color: rendition.invisible ? 'transparent' : drawn,
    backgroundColor: fill === background ? undefined : fill,
    fontWeight: rendition.bold ? 700 : undefined,
    fontStyle: rendition.italic ? 'italic' : undefined,
    textDecorationLine: lines.length > 0 ? lines.join(' ') : undefined,
    textDecorationStyle:
      rendition.underline === 'none' ? undefined : UNDERLINE_STYLE[rendition.underline],
    textDecorationColor: underlineColour
  }
}

/** One stretch of a line as text: a piece, or the blank cells before one. */
export interface Stretch {
  readonly column: number
  readonly text: string
  readonly piece: TerminalPiece | null
  /** Whether it is a piece whose text the phone drew as blank cells. */
  readonly leftBlank: boolean
}

/**
 * A line as the stretches a phone draws, left to right: each piece at its column, and spaces for
 * the cells before it that no piece covers. A piece that would start inside the one before it is
 * left out, so no column ever moves.
 *
 * Each piece is drawn in exactly its cells: printable ASCII cut or filled with spaces to its cell
 * count, and anything else as blank cells.
 */
export function stretchesOf(line: TerminalLine): Stretch[] {
  const stretches: Stretch[] = []
  let at = 0
  const pieces = [...line.pieces].sort((one, other) => one.column - other.column)
  for (const piece of pieces) {
    if (piece.column < at) continue
    if (piece.column > at) {
      stretches.push({ column: at, text: ' '.repeat(piece.column - at), piece: null, leftBlank: false })
    }
    const cells = Number.isFinite(piece.cells) ? Math.max(0, Math.trunc(piece.cells)) : 0
    const plain = /^[\x20-\x7e]*$/.test(piece.text)
    stretches.push({
      column: piece.column,
      text: plain ? piece.text.slice(0, cells).padEnd(cells) : ' '.repeat(cells),
      piece,
      leftBlank: !plain
    })
    at = piece.column + cells
  }
  return stretches
}

/** How many pieces of `screen` the phone draws as blank cells. */
export function leftBlankOnPhone(screen: TerminalScreen): number {
  return screen.lines.reduce(
    (total, line) => total + stretchesOf(line).filter((stretch) => stretch.leftBlank).length,
    0
  )
}
