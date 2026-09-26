/**
 * What a raw terminal view sends the program, as the page works it out.
 *
 * The wheel reaches the program at the session's cell under the pointer. That cell is found through
 * the frame the page draws there: the display cell under the pointer, measured from the grid's
 * content box as the browser reports it, its shift and a drag's part already in it, is a cell of that
 * frame's window, and the window says which of the session's cells it holds. Nothing is sent for a
 * pointer outside the surface's visible box, a cell off the window, a cell the shifted frame does not
 * cover, a row of the history, or a cell outside the session's grid, which a larger window draws
 * blank.
 *
 * A turn of the wheel is a row of pixels at the drawn cell height, and a finger dragged on a phone
 * turns the wheel once for each row it crosses. Native code writes each turn as the program asked
 * for the wheel, never as an arrow key.
 */

import type { TerminalScreen } from '../host/port'
import type { CellSize, Point } from './pan'

/** The most wheel turns one input carries, as native code reads it. */
export const MAX_TURNS = 1024

/** A cell of the session's grid: its column, and its line of the live screen, both from 0. */
export interface TerminalCell {
  readonly column: number
  readonly line: number
}

/**
 * The session's cell drawn at column `x` and line `y` of `screen`'s window, or null where the frame
 * draws none of the live screen: off the window, on a row of the history, or outside the session's
 * grid.
 */
export function cellAt(screen: TerminalScreen, x: number, y: number): TerminalCell | null {
  const window = screen.window
  if (!Number.isInteger(x) || !Number.isInteger(y)) return null
  if (x < 0 || y < 0 || x >= window.columns || y >= window.rows) return null
  // A window in the history starts `above` rows over the live screen's first line, and its line is 0.
  const row = y - window.above
  if (row < 0) return null
  const column = window.column + x
  const line = window.line + row
  if (column >= Number(screen.dimensions.columns) || line >= Number(screen.dimensions.rows)) return null
  return { column, line }
}

/** A length of a computed style, or 0 where it has none. */
function pixels(value: string | undefined): number {
  const number = Number.parseFloat(value ?? '')
  return Number.isFinite(number) ? number : 0
}

/**
 * The session's cell under a pointer at `at`, on `grid` drawn from `screen` in cells of `cell`, seen
 * through `surface`: measured from the grid's content box as the browser reports it, which already
 * holds its shift and a drag's part, so neither is counted again.
 */
export function cellUnder(
  at: Point,
  grid: Element,
  surface: Element,
  screen: TerminalScreen,
  cell: CellSize
): TerminalCell | null {
  if (!(cell.width > 0) || !(cell.height > 0)) return null
  const visible = surface.getBoundingClientRect()
  if (at.x < visible.left || at.x >= visible.right || at.y < visible.top || at.y >= visible.bottom) {
    return null
  }
  const box = grid.getBoundingClientRect()
  const style = getComputedStyle(grid)
  const left = box.left + pixels(style.borderLeftWidth) + pixels(style.paddingLeft)
  const top = box.top + pixels(style.borderTopWidth) + pixels(style.paddingTop)
  return cellAt(screen, Math.floor((at.x - left) / cell.width), Math.floor((at.y - top) / cell.height))
}

/** A wheel event, in the terms the page reads it in. */
export interface WheelReading {
  readonly deltaY: number
  /** 0 for pixels, 1 for lines, 2 for pages. */
  readonly deltaMode: number
}

/** How far a wheel event turned, in pixels: a line is a row of `row` pixels, a page `rows` rows. */
export function wheelPixels(wheel: WheelReading, row: number, rows: number): number {
  if (wheel.deltaMode === 1) return wheel.deltaY * row
  if (wheel.deltaMode === 2) return wheel.deltaY * rows * row
  return wheel.deltaY
}

/**
 * The turns `pixels` more of the wheel make, with `rest` carried from the turns before, a turn for
 * each row of `row` pixels: towards the person when positive. At most [`MAX_TURNS`] go at once; the
 * rows past them are dropped and only the part of a row is carried.
 */
export function wheelTurns(rest: number, pixels: number, row: number): { turns: number; rest: number } {
  if (!(row > 0)) return { turns: 0, rest: 0 }
  const total = rest + pixels
  const whole = Math.trunc(total / row)
  const turns = Math.max(-MAX_TURNS, Math.min(MAX_TURNS, whole))
  const part = total - whole * row
  return { turns: turns === 0 ? 0 : turns, rest: part === 0 ? 0 : part }
}

/**
 * How many rows a finger has crossed from `origin` to `y`, in rows of `row` pixels: towards the person
 * when positive, as a finger dragged up turns the wheel, the screen's content following the finger.
 */
export function dragRows(origin: number, y: number, row: number): number {
  if (!(row > 0)) return 0
  const rows = Math.trunc((origin - y) / row)
  return rows === 0 ? 0 : rows
}

/** `turns`, held to what one input carries. */
export function heldTurns(turns: number): number {
  return Math.max(-MAX_TURNS, Math.min(MAX_TURNS, turns))
}
