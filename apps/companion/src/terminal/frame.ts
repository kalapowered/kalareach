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

import type { TerminalScreen } from '../host/port'

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

/** At most `cells` of `text`'s grapheme clusters, the most a piece of that many cells can hold. */
function withinCells(text: string, cells: number): string {
  const segments = [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)]
  if (segments.length <= cells) return text
  return segments
    .slice(0, Math.max(0, cells))
    .map((each) => each.segment)
    .join('')
}

/** Whether every scalar of `text` is printable ASCII, which every renderer draws a cell each. */
function printableAscii(text: string): boolean {
  return /^[\x20-\x7e]*$/.test(text)
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

/**
 * Everything the renderer is written for one screen, in one write that begins with a full reset.
 *
 * One write, so a screen still waiting in the renderer can never be drawn over this one: the reset
 * clears whatever an earlier write left, in the order the writes were made.
 *
 * A piece never shows past its cells. The renderer measures text by its own width rules, which can
 * give a cluster more cells than the pinned width model native code placed it by: a mark the model
 * joins to its letter can take a cell of its own. So after a piece that is not printable ASCII,
 * everything from the end of its cells to the end of the line is erased, in this same write and
 * before anything is shown. The pieces after it on the line are drawn after the erase, left to
 * right, so they draw their own cells again, and a cell no piece covers stays blank. What the
 * renderer drew wider than the piece's cells is cut at its edge, and a wide glyph cut there is
 * erased whole.
 */
export function frameOf(screen: TerminalScreen): string {
  let out = FULL_RESET + NORMAL_BUFFER + AUTOWRAP_OFF + CURSOR_HIDDEN
  const columns = count(screen.window.columns)
  screen.lines.forEach((line, index) => {
    const pieces = [...line.pieces].sort((one, other) => count(one.column) - count(other.column))
    for (const piece of pieces) {
      const column = count(piece.column)
      const cells = count(piece.cells)
      const text = withinCells(drawableText(piece.text), cells)
      if (text.length === 0) continue
      out += `${ESC}[${index + 1};${column + 1}H${sgr(piece.rendition)}${text}`
      if (!printableAscii(text) && column + cells < columns) {
        out += `${ESC}[${index + 1};${column + cells + 1}H${ESC}[0m${ESC}[K`
      }
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

/**
 * Replaces what `terminal` shows with `screen`, at the size of the screen's window, or clears it
 * when there is no screen.
 *
 * The renderer takes the window's size, so every piece lands inside it; the surface around it clips
 * a window larger than itself at its right and bottom edges.
 */
export function paint(terminal: Terminal, screen: TerminalScreen | null): void {
  if (screen === null) {
    // A full reset leaves the cursor shown or hidden as the last screen left it.
    terminal.write(FULL_RESET + CURSOR_HIDDEN)
    return
  }
  const columns = Math.max(1, count(screen.window.columns))
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
