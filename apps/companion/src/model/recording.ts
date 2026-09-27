/**
 * The recording of what a raw terminal view drew, for the terminal recording export.
 *
 * Section 25's asciicast carries timestamps, dimensions and declared omissions, and safe rendering
 * data. What this records is exactly that: each screen the view drew, when it drew it, at the grid
 * it drew it in, written as the drawing a player repeats. A screen is written as a clear, then each
 * piece the view placed, at its own cells in its own rendition, then the cursor where the view drew
 * it: positions and colours, nothing that would act on the machine that plays it back, and nothing
 * the session printed is passed through as a sequence.
 *
 * The recording is bounded: past its bound the oldest screens go, and the export says how many.
 * A screen drawn at another size than the last is played at the last one, and the export says so.
 */

import type { CellRendition } from '@kalareach/protocol'

import type { ExportDimensions, Omission, RecordedFrame, TerminalScreen } from '../host/port'
import { count, placedCursor, placedPieces } from '../terminal/frame'

/** The most screens a recording keeps. */
export const MAX_RECORDED_FRAMES = 2000

/** The most text a recording keeps across its screens. */
export const MAX_RECORDED_TEXT = 8 * 1024 * 1024

/** One screen the view drew. */
interface Drawn {
  /** When it was drawn, on this device's clock. */
  readonly atMs: number
  readonly text: string
  readonly dimensions: ExportDimensions
}

/** What a raw terminal view drew while it was open. */
export interface Recording {
  readonly frames: readonly Drawn[]
  /** How much text the frames hold. */
  readonly text: number
  /** How many screens went to stay inside the bound. */
  readonly dropped: number
}

/** A recording with nothing in it. */
export function emptyRecording(): Recording {
  return { frames: [], text: 0, dropped: 0 }
}

/**
 * The recording with one more screen, drawn at `atMs`. A screen the same as the last adds nothing,
 * and neither does a window of no cells.
 */
export function recorded(recording: Recording, screen: TerminalScreen, atMs: number): Recording {
  const dimensions = { columns: count(screen.window.columns), rows: count(screen.window.rows) }
  if (dimensions.columns === 0 || dimensions.rows === 0) return recording
  const text = screenText(screen)
  const last = recording.frames.at(-1)
  if (
    last !== undefined &&
    last.text === text &&
    last.dimensions.columns === dimensions.columns &&
    last.dimensions.rows === dimensions.rows
  ) {
    return recording
  }
  let frames = [...recording.frames, { atMs, text, dimensions }]
  let held = recording.text + text.length
  let dropped = recording.dropped
  while (frames.length > 1 && (frames.length > MAX_RECORDED_FRAMES || held > MAX_RECORDED_TEXT)) {
    held -= frames[0]?.text.length ?? 0
    frames = frames.slice(1)
    dropped += 1
  }
  return { frames, text: held, dropped }
}

/** What the export writes: when it began, at what size, each screen, and what it leaves out. */
export interface RecordingExport {
  readonly startedAtUnixSeconds: number
  readonly dimensions: ExportDimensions
  readonly frames: readonly RecordedFrame[]
  readonly omissions: readonly Omission[]
}

/** The recording as the export writes it, or null while it holds no screen. */
export function recordingExport(recording: Recording): RecordingExport | null {
  const first = recording.frames[0]
  const last = recording.frames.at(-1)
  if (first === undefined || last === undefined) return null
  const dimensions = last.dimensions
  const resized = recording.frames.filter(
    (frame) =>
      frame.dimensions.columns !== dimensions.columns || frame.dimensions.rows !== dimensions.rows
  ).length
  const omissions: Omission[] = []
  if (recording.dropped > 0) {
    omissions.push({
      kind: 'earlier_screens',
      detail: 'Screens the view drew before the recording reached its bound',
      count: recording.dropped
    })
  }
  if (resized > 0) {
    omissions.push({
      kind: 'resized_screens',
      detail: `Screens drawn at another size, which play back at ${dimensions.columns}×${dimensions.rows}`,
      count: resized
    })
  }
  return {
    startedAtUnixSeconds: Math.floor(first.atMs / 1000),
    dimensions,
    frames: recording.frames.map((frame) => ({ at_ms: frame.atMs - first.atMs, text: frame.text })),
    omissions
  }
}

/** The escape that starts a control sequence. */
const CSI = '\u001b['

/**
 * One screen as the drawing a player repeats: a clear, each piece the view placed at its cells in
 * its rendition, and the cursor where the view drew it, or hidden when the view drew none.
 *
 * The view draws each piece as a box of its cells in the piece's colours, and cuts a glyph wider
 * than its cells at the box's edge. A player lays text out by its own idea of each glyph's width,
 * so the drawing does the same by hand: each box's cells are cleared in its colours before its text
 * is drawn, line wrapping is off while a screen is drawn, and the cells after each box are cleared
 * before the next piece is drawn over them, so nothing spills past the cells the view gave it.
 * Line wrapping is back on at the end.
 */
export function screenText(screen: TerminalScreen): string {
  const columns = count(screen.window.columns)
  let out = `${CSI}0m${CSI}?7l${CSI}H${CSI}2J`
  for (const piece of placedPieces(screen)) {
    out += `${CSI}${piece.line + 1};${piece.column + 1}H${CSI}${sgrOf(piece.rendition)}m${CSI}${piece.cells}X${piece.text}`
    const after = piece.column + piece.cells
    if (after < columns) out += `${CSI}0m${CSI}${piece.line + 1};${after + 1}H${CSI}K`
  }
  out += `${CSI}0m${CSI}?7h`
  const cursor = placedCursor(screen)
  return cursor === null
    ? `${out}${CSI}?25l`
    : `${out}${CSI}${cursor.line + 1};${cursor.column + 1}H${CSI}?25h`
}

/** The select-graphic-rendition parameters a rendition is drawn with. */
function sgrOf(rendition: CellRendition): string {
  const parameters = ['0']
  if (rendition.bold) parameters.push('1')
  if (rendition.faint) parameters.push('2')
  if (rendition.italic) parameters.push('3')
  if (rendition.underline !== 'none') parameters.push(rendition.underline === 'double' ? '21' : '4')
  if (rendition.reverse) parameters.push('7')
  if (rendition.invisible) parameters.push('8')
  if (rendition.strikethrough) parameters.push('9')
  if (rendition.overline) parameters.push('53')
  parameters.push(...colourOf(rendition.foreground, 38), ...colourOf(rendition.background, 48))
  return parameters.join(';')
}

/** A colour's parameters, for the foreground (38) or the background (48), held to what the view draws. */
function colourOf(colour: CellRendition['foreground'], base: 38 | 48): string[] {
  if (typeof colour !== 'object') return []
  if ('indexed' in colour) return [String(base), '5', String(byte(colour.indexed))]
  const { red, green, blue } = colour.direct
  return [String(base), '2', String(byte(red)), String(byte(green)), String(byte(blue))]
}

/** A number held to a byte, whatever a malformed state carried. */
function byte(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) ? Math.min(255, Math.max(0, number)) : 0
}
