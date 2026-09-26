/**
 * Drawing a view's screen into the desktop's renderer.
 *
 * The screen arrives as cells: lines of pieces, each with its column and its rendition. What the
 * renderer is given is written here from those typed values alone: this page's own fixed sequences
 * (a full reset, the normal buffer, autowrap off, the cursor placed, the rendition as numbers, the
 * cursor's shape and visibility) and each piece's text with every control character replaced. No
 * host byte reaches the renderer's parser, so nothing a session printed can make it answer a query
 * or change a mode.
 */

import type { ITheme, Terminal } from '@xterm/xterm'

import type { CellRendition, PaletteState, Rgb10 } from '@kalareach/protocol'

import type { TerminalLine, TerminalScreen } from '../host/port'
import { cellsOf, standsAlone } from './widths'

/** The stand-in for a control character a piece should never have carried. */
export const REPLACEMENT = '\u{FFFD}'

const ESC = '\u{1b}'

/** Resets the renderer: every mode, the pen, the screen and the cursor. */
const FULL_RESET = `${ESC}c`

/**
 * DEC private mode 1047 off: the normal buffer, which a full reset has already selected.
 *
 * It changes nothing on the screen. It is written because xterm.js draws no cursor in a renderer
 * that has had no focus, no key and no switch of buffers, and this counts as the switch: without it
 * the session's cursor would show only after the person clicked into the view, and each zoom step
 * makes a new renderer.
 */
const NORMAL_BUFFER = `${ESC}[?1047l`

/** DEC private mode 7 off: nothing drawn can wrap onto the next line or scroll the screen. */
const AUTOWRAP_OFF = `${ESC}[?7l`

const CURSOR_HIDDEN = `${ESC}[?25l`
const CURSOR_SHOWN = `${ESC}[?25h`

/** The fewest columns xterm.js keeps, whatever it is asked for. */
const RENDERER_MINIMUM_COLUMNS = 2

/**
 * A piece's text as the renderer is given it: every C0 control, DEL and C1 control replaced.
 *
 * Native code has already removed them; this is for a shape that did not come from native code, so
 * a query in a cell is drawn as a mark rather than read as a sequence.
 */
export function drawableText(text: string): string {
  let drawn = ''
  for (const scalar of text) {
    const code = scalar.codePointAt(0) ?? 0
    drawn += code < 0x20 || (code >= 0x7f && code <= 0x9f) ? REPLACEMENT : scalar
  }
  return drawn
}

/** A number the renderer is given, held to a byte whatever a malformed state carried. */
function byte(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) ? Math.min(255, Math.max(0, number)) : 0
}

/** A non-negative whole number, whatever a malformed state carried. */
function count(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) && number > 0 ? number : 0
}

type Colour = CellRendition['foreground']

/** The SGR parameters for one colour, or none for the default. */
function colour(value: Colour, base: number, bright: number, extended: number): string | null {
  if (typeof value !== 'object') return null
  if ('indexed' in value) {
    const index = byte(value.indexed)
    if (index < 8) return String(base + index)
    if (index < 16) return String(bright + index - 8)
    return `${extended};5;${index}`
  }
  const rgb = value.direct
  return `${extended};2;${byte(rgb.red)};${byte(rgb.green)};${byte(rgb.blue)}`
}

/** The SGR parameters for the underline's colour, which has only the long forms, or none. */
function underlineColour(value: Colour): string | null {
  if (typeof value !== 'object') return null
  if ('indexed' in value) return `58;5;${byte(value.indexed)}`
  const rgb = value.direct
  return `58;2;${byte(rgb.red)};${byte(rgb.green)};${byte(rgb.blue)}`
}

const UNDERLINE: Record<CellRendition['underline'], string | null> = {
  none: null,
  single: '4',
  double: '4:2',
  curly: '4:3',
  dotted: '4:4',
  dashed: '4:5'
}

/**
 * The rendition as one select-graphic-rendition sequence, starting from the plain pen.
 *
 * Blink is never drawn: nothing on the surface animates. Superscript and subscript have no
 * rendering in a cell grid and are drawn on the baseline.
 */
export function sgr(rendition: CellRendition): string {
  const parameters = ['0']
  const add = (parameter: string | null) => {
    if (parameter !== null) parameters.push(parameter)
  }
  if (rendition.bold) add('1')
  if (rendition.faint) add('2')
  if (rendition.italic) add('3')
  add(UNDERLINE[rendition.underline] ?? null)
  if (rendition.reverse) add('7')
  if (rendition.invisible) add('8')
  if (rendition.strikethrough) add('9')
  if (rendition.overline) add('53')
  add(colour(rendition.foreground, 30, 90, 38))
  add(colour(rendition.background, 40, 100, 48))
  add(underlineColour(rendition.underline_colour))
  return `${ESC}[${parameters.join(';')}m`
}

/** The steady form of a cursor style: a cursor never blinks. */
function steadyCursor(style: number): number {
  if (style === 3 || style === 4) return 4
  if (style === 5 || style === 6) return 6
  return 2
}

/** One piece as the renderer is given it: text that fills exactly the piece's cells. */
interface Written {
  readonly column: number
  readonly text: string
  readonly rendition: CellRendition
  /** Whether the piece had text that could not be drawn in its cells alone, so it is blank. */
  readonly leftBlank: boolean
}

/**
 * The pieces of one line as the renderer is given them, left to right, each filling exactly its
 * cells.
 *
 * The renderer lays text out with the view's own cell table (`widths.ts`), and each piece is
 * written straight after its own cursor placement and rendition, where the renderer has forgotten
 * the character before. So `cellsOf` says exactly how many cells the renderer will give a piece's
 * text. A piece is written as its text followed by blank cells to its last cell when the text fits
 * and the browser draws it without touching its neighbours (`standsAlone`), and as blank cells
 * alone otherwise, or when it is invisible: the renderer measures invisible text by its glyphs and
 * draws it as spaces, which would move the rest of the line. Every character then lands in the
 * piece's own cells in the buffer and on the screen: none is drawn past them, none is dropped at
 * the window's edge, no mark joins a character of another piece, no cell of no width is made, and
 * no piece is joined to or reordered with another as the browser draws the line. A piece that
 * starts inside the one before it is left out, as native code never sends one, and a piece is cut
 * at the window's edge.
 */
function writtenOf(line: TerminalLine, columns: number): Written[] {
  const written: Written[] = []
  const pieces = [...line.pieces].sort((one, other) => count(one.column) - count(other.column))
  // The first cell of the line no piece so far owns.
  let free = 0
  for (const piece of pieces) {
    const column = count(piece.column)
    if (column < free || column >= columns) continue
    const cells = Math.min(count(piece.cells), columns - column)
    free = column + cells
    if (cells === 0) continue
    const text = drawableText(piece.text)
    if (piece.rendition.invisible) {
      written.push({ column, text: ' '.repeat(cells), rendition: piece.rendition, leftBlank: false })
      continue
    }
    const laid = text.length === 0 || !standsAlone(text) ? null : cellsOf(text)
    written.push(
      laid === null || laid > cells
        ? { column, text: ' '.repeat(cells), rendition: piece.rendition, leftBlank: text.length > 0 }
        : { column, text: text + ' '.repeat(cells - laid), rendition: piece.rendition, leftBlank: false }
    )
  }
  return written
}

/**
 * Everything the renderer is written for one screen, in one write that begins with a full reset.
 *
 * One write, so a screen still waiting in the renderer can never be drawn over this one: the reset
 * clears whatever an earlier write left, in the order the writes were made.
 */
export function frameOf(screen: TerminalScreen): string {
  let out = FULL_RESET + NORMAL_BUFFER + AUTOWRAP_OFF + CURSOR_HIDDEN
  const columns = count(screen.window.columns)
  screen.lines.forEach((line, index) => {
    for (const piece of writtenOf(line, columns)) {
      out += `${ESC}[${index + 1};${piece.column + 1}H${sgr(piece.rendition)}${piece.text}`
    }
  })
  out += `${ESC}[0m`
  const cursor = screen.cursor
  if (cursor !== null && cursor.visible) {
    out += `${ESC}[${count(cursor.line) + 1};${count(cursor.column) + 1}H`
    out += `${ESC}[${steadyCursor(count(cursor.style))} q${CURSOR_SHOWN}`
  }
  return out
}

/** How many pieces of `screen` the renderer is given as blank cells because their text does not fit. */
export function leftBlank(screen: TerminalScreen): number {
  const columns = count(screen.window.columns)
  return screen.lines.reduce(
    (total, line) => total + writtenOf(line, columns).filter((piece) => piece.leftBlank).length,
    0
  )
}

/**
 * Replaces what `terminal` shows with `screen`, at the size of the screen's window, or clears it
 * when there is no screen.
 *
 * The renderer takes the window's size, so every piece lands inside it; the surface around it clips
 * a window larger than itself at its right and bottom edges. A window of one column is drawn in the
 * two columns the renderer keeps at the least, and its second column stays blank.
 */
export function paint(terminal: Terminal, screen: TerminalScreen | null): void {
  if (screen === null) {
    // A full reset leaves the cursor shown or hidden as the last screen left it.
    terminal.write(FULL_RESET + CURSOR_HIDDEN)
    return
  }
  const columns = Math.max(RENDERER_MINIMUM_COLUMNS, count(screen.window.columns))
  const rows = Math.max(1, count(screen.window.rows))
  if (terminal.cols !== columns || terminal.rows !== rows) terminal.resize(columns, rows)
  terminal.write(frameOf(screen))
}

/** A colour as the renderer's theme takes it. */
function hex(rgb: Rgb10): string {
  return `#${[rgb.red, rgb.green, rgb.blue].map((part) => byte(part).toString(16).padStart(2, '0')).join('')}`
}

const NAMED: readonly (keyof ITheme)[] = [
  'black',
  'red',
  'green',
  'yellow',
  'blue',
  'magenta',
  'cyan',
  'white',
  'brightBlack',
  'brightRed',
  'brightGreen',
  'brightYellow',
  'brightBlue',
  'brightMagenta',
  'brightCyan',
  'brightWhite'
]

/**
 * The renderer's theme from the session's palette: its foreground, background, cursor and selection,
 * and each index it overrides. An index it does not override keeps the renderer's own colour, as a
 * terminal the CLI paints has its own colours put back first.
 */
export function themeOf(palette: PaletteState): ITheme {
  const theme: Record<string, unknown> = {
    foreground: hex(palette.foreground),
    background: hex(palette.background),
    cursor: hex(palette.cursor),
    cursorAccent: hex(palette.background),
    selectionBackground: hex(palette.selection_background),
    selectionForeground: hex(palette.selection_foreground)
  }
  const extended: (string | undefined)[] = []
  for (const override of palette.overrides) {
    const index = byte(override.index)
    const colour = hex(override.colour)
    if (index < 16) {
      const name = NAMED[index]
      if (name !== undefined) theme[name] = colour
    } else {
      extended[index - 16] = colour
    }
  }
  if (extended.length > 0) theme.extendedAnsi = extended
  return theme
}

/** The palette's background, for the surface around the renderer. */
export function backgroundOf(palette: PaletteState): string {
  return hex(palette.background)
}
