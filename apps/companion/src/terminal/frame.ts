/**
 * Placing a view's screen on the desktop's grid, and the selection colours both grids share.
 *
 * The screen arrives as cells: lines of pieces, each with its column, its cells and its rendition.
 * The desktop draws each piece as a box of its own at its canonical cells: at its column, exactly
 * its cells wide and one line high, with its text laid out inside the box, apart from every other
 * piece's, and cut at the box's edges. So nothing a piece holds can move, cover or join another
 * piece, whatever the browser's fonts, shaping, grapheme rules or text direction make of it: a
 * glyph wider than its cells is cut, a narrower one leaves blank cells, and a right-to-left letter
 * stays in its own cells. The session's text only ever becomes text inside a box; nothing parses
 * it, so nothing it holds can make the view answer a query or change a mode.
 */

import type { CellRendition, PaletteState, Rgb10 } from '@kalareach/protocol'

import type { TerminalScreen } from '../host/port'

/** The stand-in for a control character a piece should never have carried. */
export const REPLACEMENT = '\u{FFFD}'

/**
 * A piece's text as it is drawn: every C0 control, DEL and C1 control replaced.
 *
 * Native code has already removed them; this is for a shape that did not come from native code, so
 * a control in a cell is drawn as a mark rather than as nothing.
 */
export function drawableText(text: string): string {
  let drawn = ''
  for (const scalar of text) {
    const code = scalar.codePointAt(0) ?? 0
    drawn += code < 0x20 || (code >= 0x7f && code <= 0x9f) ? REPLACEMENT : scalar
  }
  return drawn
}

/** A non-negative whole number, whatever a malformed state carried. */
export function count(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) && number > 0 ? number : 0
}

/** A number the palette gives, held to a byte whatever a malformed state carried. */
function byte(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) ? Math.min(255, Math.max(0, number)) : 0
}

/** One piece where the desktop draws it. */
export interface PlacedPiece {
  /** The line of the window, from its top. */
  readonly line: number
  /** The column of the window, from its left. */
  readonly column: number
  readonly cells: number
  readonly text: string
  readonly rendition: CellRendition
}

/**
 * The pieces of `screen` where the desktop draws them, line by line and left to right.
 *
 * A piece that starts inside the one before it on its line is left out, as native code never sends
 * one, so no two boxes share a cell; a piece is cut at the window's right edge, and a piece of no
 * cells is not drawn.
 */
export function placedPieces(screen: TerminalScreen): PlacedPiece[] {
  const placed: PlacedPiece[] = []
  const columns = count(screen.window.columns)
  screen.lines.forEach((line, index) => {
    const pieces = [...line.pieces].sort((one, other) => count(one.column) - count(other.column))
    // The first cell of the line no piece so far owns.
    let free = 0
    for (const piece of pieces) {
      const column = count(piece.column)
      if (column < free || column >= columns) continue
      const cells = Math.min(count(piece.cells), columns - column)
      if (cells === 0) continue
      free = column + cells
      placed.push({
        line: index,
        column,
        cells,
        text: drawableText(piece.text),
        rendition: piece.rendition
      })
    }
  })
  return placed
}

/**
 * The text of `pieces` as a copy of the grid gives it: a line for each line from the first piece's
 * to the last's, each piece's text at its column with a space for every cell before it that no
 * piece covers, and no spaces after a line's last piece. The boxes a person selects are placed
 * apart from each other, so the browser's own copy of them would run the lines and pieces together.
 */
export function copiedText(pieces: readonly PlacedPiece[]): string {
  if (pieces.length === 0) return ''
  const lines = new Map<number, string>()
  const reached = new Map<number, number>()
  for (const piece of pieces) {
    const gap = Math.max(0, piece.column - (reached.get(piece.line) ?? 0))
    lines.set(piece.line, `${lines.get(piece.line) ?? ''}${' '.repeat(gap)}${piece.text}`)
    reached.set(piece.line, piece.column + piece.cells)
  }
  const numbers = [...lines.keys()]
  const first = Math.min(...numbers)
  const last = Math.max(...numbers)
  return Array.from({ length: last - first + 1 }, (_, index) =>
    (lines.get(first + index) ?? '').trimEnd()
  ).join('\n')
}

/** The shapes the session's cursor is drawn in, each steady: a cursor never blinks. */
export type CursorShape = 'block' | 'underline' | 'bar'

/** The session's cursor where the desktop draws it. */
export interface PlacedCursor {
  readonly line: number
  readonly column: number
  readonly shape: CursorShape
}

/** Where the session's cursor is drawn, or null when it is hidden or outside the window. */
export function placedCursor(screen: TerminalScreen): PlacedCursor | null {
  const cursor = screen.cursor
  if (cursor === null || !cursor.visible) return null
  const line = count(cursor.line)
  const column = count(cursor.column)
  if (line >= count(screen.window.rows) || column >= count(screen.window.columns)) return null
  const style = count(cursor.style)
  const shape: CursorShape =
    style === 3 || style === 4 ? 'underline' : style === 5 || style === 6 ? 'bar' : 'block'
  return { line, column, shape }
}

/** A palette colour as CSS. */
function hex(rgb: Rgb10): string {
  return `#${[rgb.red, rgb.green, rgb.blue].map((part) => byte(part).toString(16).padStart(2, '0')).join('')}`
}

/** The palette's background, for the surface around the grid and every cell no piece covers. */
export function backgroundOf(palette: PaletteState): string {
  return hex(palette.background)
}

/** The palette's foreground, for text in the default colour. */
export function foregroundOf(palette: PaletteState): string {
  return hex(palette.foreground)
}

/** The palette's cursor colour. */
export function cursorColourOf(palette: PaletteState): string {
  return hex(palette.cursor)
}

/**
 * The rule that colours a selection in one grid in the palette's selection colours, as the
 * terminal the session came from shows a selection. The desktop's grid and the phone's each carry
 * it, each named by `grid`, the value of its own `data-terminal-grid`, so a grid never takes
 * another grid's colours and nothing outside a grid takes them at all. A name is a React
 * identifier; one with any other character could reach outside the selector, so it colours nothing.
 */
export function selectionRule(grid: string, palette: PaletteState): string {
  if (!/^[\w-]+$/.test(grid)) return ''
  const background = hex(palette.selection_background)
  const foreground = hex(palette.selection_foreground)
  return `[data-terminal-grid="${grid}"] ::selection { background-color: ${background}; color: ${foreground}; }`
}
