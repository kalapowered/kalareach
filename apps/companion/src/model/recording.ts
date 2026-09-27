/**
 * The recording of what a raw terminal view drew, for the terminal recording export.
 *
 * Section 25's asciicast carries timestamps, dimensions and declared omissions, and safe rendering
 * data. What this records is exactly that: each screen the view drew, when it drew it, at the grid
 * it drew it in, written as the drawing a player repeats. A screen is written as a clear in the
 * session's background, then each piece the view placed, at its own cells in the colours the view
 * drew it in, then the cursor where the view drew it: positions and colours, nothing that would act
 * on the machine that plays it back, and nothing the session printed is passed through as a
 * sequence. Every colour is resolved through the session's palette as the view resolves it, so a
 * player's own colours never stand in for the session's, and a change of palette alone is a new
 * screen. What a player cannot be told without changing its own settings is declared instead: the
 * cursor's shape and colour, and underline styles other than single and double.
 *
 * The recording is bounded: past its bound the oldest screens go, and the export says how many.
 * A screen drawn at another size than the last is played at the last one, and the export says so.
 */

import type { CellRendition, PaletteState, Rgb10 } from '@kalareach/protocol'

import type { ExportDimensions, Omission, RecordedFrame, TerminalScreen } from '../host/port'
import { rgbOf, type Rgb } from '../terminal/cells'
import { count, placedCursor, placedPieces } from '../terminal/frame'

/** The most screens a recording keeps. */
export const MAX_RECORDED_FRAMES = 2000

/** The most drawing a recording keeps across its screens, in bytes of UTF-8. */
export const MAX_RECORDED_BYTES = 8 * 1024 * 1024

/** One screen the view drew. */
interface Drawn {
  /** When it was drawn, on this device's clock. */
  readonly atMs: number
  readonly text: string
  /** How many bytes of UTF-8 the text is. */
  readonly bytes: number
  readonly dimensions: ExportDimensions
  /** Whether it has an underline a player draws as a single one. */
  readonly restyled: boolean
  /** Whether the view drew the cursor, in a shape and colour a player draws in its own. */
  readonly cursor: boolean
}

/** What a raw terminal view drew while it was open. */
export interface Recording {
  readonly frames: readonly Drawn[]
  /** How many bytes the frames hold. */
  readonly bytes: number
  /** How many screens went to stay inside the bound. */
  readonly dropped: number
  /** How many screens were larger than the whole bound, and were not kept. */
  readonly oversized: number
}

/** A recording with nothing in it. */
export function emptyRecording(): Recording {
  return { frames: [], bytes: 0, dropped: 0, oversized: 0 }
}

/** The underline styles a player draws as they are. */
const PLAYED_UNDERLINES: readonly CellRendition['underline'][] = ['none', 'single', 'double']

/**
 * The recording with one more screen, drawn at `atMs`. A screen the same as the last adds nothing,
 * and neither does a window of no cells.
 */
export function recorded(recording: Recording, screen: TerminalScreen, atMs: number): Recording {
  const dimensions = { columns: count(screen.window.columns), rows: count(screen.window.rows) }
  if (dimensions.columns === 0 || dimensions.rows === 0) return recording
  const text = screenText(screen)
  // Two underline styles a player draws alike draw the same text, and the screen is still new.
  const restyled = placedPieces(screen).some(
    (piece) => !PLAYED_UNDERLINES.includes(piece.rendition.underline)
  )
  const last = recording.frames.at(-1)
  if (
    last !== undefined &&
    last.text === text &&
    last.restyled === restyled &&
    last.dimensions.columns === dimensions.columns &&
    last.dimensions.rows === dimensions.rows
  ) {
    return recording
  }
  const bytes = utf8Length(text)
  if (bytes > MAX_RECORDED_BYTES) return { ...recording, oversized: recording.oversized + 1 }
  const frame: Drawn = {
    atMs,
    text,
    bytes,
    dimensions,
    restyled,
    cursor: placedCursor(screen) !== null
  }
  let frames = [...recording.frames, frame]
  let held = recording.bytes + bytes
  let dropped = recording.dropped
  while (frames.length > 1 && (frames.length > MAX_RECORDED_FRAMES || held > MAX_RECORDED_BYTES)) {
    held -= frames[0]?.bytes ?? 0
    frames = frames.slice(1)
    dropped += 1
  }
  return { ...recording, frames, bytes: held, dropped }
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
  const restyled = recording.frames.filter((frame) => frame.restyled).length
  const cursors = recording.frames.filter((frame) => frame.cursor).length
  const omissions: Omission[] = []
  if (recording.dropped > 0) {
    omissions.push({
      kind: 'earlier_screens',
      detail: 'Screens the view drew before the recording reached its bound',
      count: recording.dropped
    })
  }
  if (recording.oversized > 0) {
    omissions.push({
      kind: 'oversized_screens',
      detail: 'Screens larger than the whole recording keeps',
      count: recording.oversized
    })
  }
  if (resized > 0) {
    omissions.push({
      kind: 'resized_screens',
      detail: `Screens drawn at another size, which play back at ${dimensions.columns}×${dimensions.rows}`,
      count: resized
    })
  }
  if (restyled > 0) {
    omissions.push({
      kind: 'underline_styles',
      detail: 'Curly, dotted and dashed underlines, which play back as single ones',
      count: restyled
    })
  }
  if (cursors > 0) {
    omissions.push({
      kind: 'cursor_style',
      detail: "The cursor's shape and colour, which a player draws in its own",
      count: cursors
    })
  }
  return {
    startedAtUnixSeconds: Math.floor(first.atMs / 1000),
    dimensions,
    frames: recording.frames.map((frame) => ({ at_ms: frame.atMs - first.atMs, text: frame.text })),
    omissions
  }
}

/** How many bytes `text` is in UTF-8. */
function utf8Length(text: string): number {
  let bytes = 0
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4
  }
  return bytes
}

/** The escape that starts a control sequence. */
const CSI = '\u001b['

/**
 * One screen as the drawing a player repeats: a clear in the session's background, each piece the
 * view placed at its cells in its colours, and the cursor where the view drew it, or hidden when
 * the view drew none.
 *
 * The view draws each piece as a box of its cells in the piece's colours, and cuts a glyph wider
 * than its cells at the box's edge. A player lays text out by its own idea of each glyph's width,
 * so the drawing does the same by hand: each box's cells are cleared in its colours before its text
 * is drawn, line wrapping is off while a screen is drawn, and the cells after each box are cleared
 * in the session's background before the next piece is drawn over them, so nothing spills past the
 * cells the view gave it. Line wrapping is back on at the end.
 *
 * The export keeps the sequences written here and removes every other, so a sequence added here is
 * one the export has to be taught to keep. The recording tests and the export's own tests hold the
 * two to the same screens.
 */
export function screenText(screen: TerminalScreen): string {
  const palette = screen.palette
  const columns = count(screen.window.columns)
  // The cells no piece covers, in the session's own background.
  const blank = `${CSI}0;${colour(48, parts(palette.background))}m`
  let out = `${blank}${CSI}?7l${CSI}H${CSI}2J`
  for (const piece of placedPieces(screen)) {
    out += `${CSI}${piece.line + 1};${piece.column + 1}H${CSI}${sgrOf(piece.rendition, palette)}m${CSI}${piece.cells}X${piece.text}`
    const after = piece.column + piece.cells
    if (after < columns) out += `${blank}${CSI}${piece.line + 1};${after + 1}H${CSI}K`
  }
  out += `${CSI}0m${CSI}?7h`
  const cursor = placedCursor(screen)
  return cursor === null
    ? `${out}${CSI}?25l`
    : `${out}${CSI}${cursor.line + 1};${cursor.column + 1}H${CSI}?25h`
}

/** A palette colour's parts, each held to a byte. */
function parts(rgb: Rgb10): Rgb {
  const byte = (value: number) => Math.min(255, Math.max(0, Math.trunc(Number(value) || 0)))
  return [byte(rgb.red), byte(rgb.green), byte(rgb.blue)]
}

/** A colour's parameters: 38 for the text, 48 for the background, 58 for the underline. */
function colour(base: 38 | 48 | 58, rgb: Rgb): string {
  return `${base};2;${rgb[0]};${rgb[1]};${rgb[2]}`
}

/**
 * The select-graphic-rendition parameters a piece is drawn with: its attributes, and its colours
 * resolved through the palette, a default one included, as the view draws them.
 */
function sgrOf(rendition: CellRendition, palette: PaletteState): string {
  const parameters = ['0']
  if (rendition.bold) parameters.push('1')
  if (rendition.faint) parameters.push('2')
  if (rendition.italic) parameters.push('3')
  if (rendition.underline !== 'none') parameters.push(rendition.underline === 'double' ? '21' : '4')
  if (rendition.reverse) parameters.push('7')
  if (rendition.invisible) parameters.push('8')
  if (rendition.strikethrough) parameters.push('9')
  if (rendition.overline) parameters.push('53')
  parameters.push(
    colour(38, rgbOf(rendition.foreground, palette) ?? parts(palette.foreground)),
    colour(48, rgbOf(rendition.background, palette) ?? parts(palette.background))
  )
  // An underline in the default colour takes the text's, which a player's does too.
  const underline = rendition.underline === 'none' ? null : rgbOf(rendition.underline_colour, palette)
  if (underline !== null) parameters.push(colour(58, underline))
  return parameters.join(';')
}
