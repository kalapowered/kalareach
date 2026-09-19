/**
 * Drawing a cell the renderer cannot reproduce, without moving the cells after it.
 *
 * The host's grid is canonical: every cell has a position and a column width that the terminal
 * state machine already decided. A web renderer does not have the same fonts, and a cluster it
 * cannot draw at the declared width will either overflow into the next cell or fall short of it.
 * Either way every following cell on the row moves, and a screen whose columns do not line up is
 * worse than one with a placeholder in it.
 *
 * So a cluster that cannot be reproduced is replaced by exactly as many columns as it declared, or
 * clipped to them. The replacement says what it is standing for, and the row keeps its shape.
 */

/** What the renderer can actually draw. */
export type Reproducible = (cluster: string, columns: number) => boolean

/** One cell, as the host published it. */
export interface Cell {
  readonly text: string
  readonly width: number
}

/** What is drawn for one cell, and why. */
export interface Drawn {
  /** The characters to draw. */
  readonly text: string
  /** How many columns they occupy, which always equals the cell's declared width. */
  readonly columns: number
  /** True when the cluster was not drawn as it was published. */
  readonly substituted: boolean
  /** What was left out, for the person who hovers it. */
  readonly original: string | null
}

/**
 * The stand-in for one column of a cluster that could not be drawn.
 *
 * U+FFFD is the replacement character: it is exactly what it means, it is in every font, and it is
 * one column wide, so `width` of them fill a `width`-column cluster exactly.
 */
export const REPLACEMENT = '�'

/** Decides what to draw for one cell. */
export function drawCell(cell: Cell, reproducible: Reproducible): Drawn {
  // A continuation cell of a wide cluster carries no text of its own and occupies no columns: the
  // cluster before it already claimed them.
  if (cell.width === 0) {
    return { text: '', columns: 0, substituted: false, original: null }
  }
  if (cell.text.length === 0) {
    return { text: ' '.repeat(cell.width), columns: cell.width, substituted: false, original: null }
  }
  if (reproducible(cell.text, cell.width)) {
    return { text: cell.text, columns: cell.width, substituted: false, original: null }
  }

  // A cluster that is a base character with marks the renderer cannot compose is clipped to the
  // base: it is still the right character, and it is one column.
  const base = baseCharacter(cell.text)
  if (base !== null && base !== cell.text && reproducible(base, cell.width)) {
    return { text: base, columns: cell.width, substituted: true, original: cell.text }
  }

  return {
    text: REPLACEMENT.repeat(cell.width),
    columns: cell.width,
    substituted: true,
    original: cell.text
  }
}

/** Draws a whole row, and reports how many cells were substituted. */
export function drawRow(
  cells: readonly Cell[],
  reproducible: Reproducible
): { readonly text: string; readonly substituted: number; readonly columns: number } {
  let text = ''
  let substituted = 0
  let columns = 0
  for (const cell of cells) {
    const drawn = drawCell(cell, reproducible)
    text += drawn.text
    columns += drawn.columns
    if (drawn.substituted) substituted += 1
  }
  return { text, substituted, columns }
}

/**
 * The base character of a grapheme cluster, when clipping to it would lose only marks.
 *
 * `e` with three diacritics clips to `e`: the letter is still the letter and only the accents are
 * gone. A joined emoji sequence does not clip, because its other code points are characters in
 * their own right and dropping them would show a different thing rather than a plainer one. That
 * case gets the replacement instead, which says plainly that something was not drawn.
 */
export function baseCharacter(cluster: string): string | null {
  const characters = [...cluster]
  const base = characters[0]
  if (base === undefined || isCombining(base)) return null
  return characters.slice(1).every(isCombining) ? base : null
}

const COMBINING_RANGES: readonly (readonly [number, number])[] = [
  [0x0300, 0x036f], // Combining diacritical marks
  [0x1ab0, 0x1aff],
  [0x1dc0, 0x1dff],
  [0x200b, 0x200f], // Zero-width space through the directional marks
  [0x20d0, 0x20ff],
  [0xfe00, 0xfe0f], // Variation selectors
  [0xfe20, 0xfe2f],
  [0xe0100, 0xe01ef] // Variation selectors supplement
]

/** Whether a character attaches to the one before it rather than standing on its own. */
export function isCombining(character: string): boolean {
  const code = character.codePointAt(0)
  if (code === undefined) return false
  return COMBINING_RANGES.some(([start, end]) => code >= start && code <= end)
}

/**
 * Builds a reproducibility test from a text-measuring function.
 *
 * A cluster is reproducible when the renderer draws it in the number of cell widths the host said
 * it occupies. The tolerance is a fifth of a cell: font hinting moves an advance by a fraction of a
 * pixel and a test that demanded exactness would substitute every character.
 */
export function measuredReproducible(
  measure: (text: string) => number,
  cellWidth: number
): Reproducible {
  const tolerance = cellWidth / 5
  return (cluster, columns) => {
    const advance = measure(cluster)
    if (advance === 0) return false
    return Math.abs(advance - columns * cellWidth) <= tolerance
  }
}
