/**
 * How many cells the desktop's renderer gives each character.
 *
 * The renderer does not use a table of its own: it is given this one as its Unicode version, and
 * the frame measures each piece's text with the same table before it writes it. So the frame knows
 * where the renderer will put every character of every piece, and writes a piece's text only when
 * it fits the piece's cells; any other piece is written as blank cells (see `frame.ts`).
 *
 * The table follows the Unicode character database the browser's regular expressions carry. Marks
 * and format characters take no cell and join the character before them; East Asian wide and
 * full-width characters, and emoji shown as pictures by default, take two; everything else takes
 * one. Where it and the pinned width model native code placed a piece by disagree, the piece is
 * drawn in fewer cells than it has, or left blank; it is never drawn outside them.
 */

import type { IUnicodeVersionProvider } from '@xterm/xterm'

type Width = 0 | 1 | 2

/** Marks and format characters: no cell of their own. */
const JOINING = /^[\p{Mn}\p{Me}\p{Cf}]$/u

/** Emoji shown as pictures unless a selector says otherwise: two cells. */
const PICTURE = /^\p{Emoji_Presentation}$/u

/**
 * Characters that take no cell although they are letters: the vowels and final consonants of
 * Hangul syllables spelled in jamo, which join the consonant before them.
 */
const JOINING_JAMO: readonly (readonly [number, number])[] = [
  [0x1160, 0x11ff],
  [0xd7b0, 0xd7ff]
]

/**
 * East Asian wide and full-width characters outside the emoji, as first and last code points. The
 * circled numbers on black squares, U+3248 to U+324F, are left out: their width is ambiguous, and
 * narrow is how the pinned model reads an ambiguous width.
 */
const WIDE: readonly (readonly [number, number])[] = [
  [0x1100, 0x115f],
  [0x2329, 0x232a],
  [0x2e80, 0x303e],
  [0x3041, 0x3247],
  [0x3250, 0x4dbf],
  [0x4e00, 0xa4cf],
  [0xa960, 0xa97f],
  [0xac00, 0xd7a3],
  [0xf900, 0xfaff],
  [0xfe10, 0xfe19],
  [0xfe30, 0xfe6f],
  [0xff00, 0xff60],
  [0xffe0, 0xffe6],
  [0x16fe0, 0x16fe4],
  [0x17000, 0x18cff],
  [0x1b000, 0x1b2ff],
  [0x1f200, 0x1f2ff],
  [0x20000, 0x2fffd],
  [0x30000, 0x3fffd]
]

function within(ranges: readonly (readonly [number, number])[], codepoint: number): boolean {
  return ranges.some(([first, last]) => codepoint >= first && codepoint <= last)
}

const measured = new Map<number, Width>()

/** The cells one character takes on its own. */
function widthOf(codepoint: number): Width {
  // Printable ASCII first: nearly every character a terminal shows, and one cell in every table.
  if (codepoint >= 0x20 && codepoint < 0x7f) return 1
  if (codepoint < 0xa0) return 0
  const known = measured.get(codepoint)
  if (known !== undefined) return known
  const scalar = String.fromCodePoint(codepoint)
  const width: Width =
    JOINING.test(scalar) || within(JOINING_JAMO, codepoint)
      ? 0
      : PICTURE.test(scalar) || within(WIDE, codepoint)
        ? 2
        : 1
  measured.set(codepoint, width)
  return width
}

/**
 * A character's properties as the renderer reads them: its width in the bits above the lowest, and
 * in the lowest bit whether it joins the character before it.
 */
function pack(width: number, joins: boolean): number {
  return (width << 1) | (joins ? 1 : 0)
}

function widthIn(packed: number): number {
  return (packed >> 1) & 3
}

/**
 * This table as the renderer takes a Unicode version. A character of no width joins the one before
 * it in the same run of text and takes that one's width; with nothing before it, it joins nothing.
 */
export const CELL_TABLE: IUnicodeVersionProvider = {
  version: 'kalareach-cells',
  wcwidth: widthOf,
  charProperties(codepoint: number, preceding: number): number {
    const width = widthOf(codepoint)
    if (width === 0 && widthIn(preceding) > 0) return pack(widthIn(preceding), true)
    return pack(width, false)
  }
}

/**
 * The cells the renderer gives `text` written straight after a control sequence, which is how
 * every piece is written, or null when its first character takes no cell: the renderer would store
 * that character in a cell of no width, which it draws as nothing and which moves the rest of the
 * line.
 */
export function cellsOf(text: string): number | null {
  if (/^[\x20-\x7e]*$/.test(text)) return text.length
  let preceding = 0
  let cells = 0
  for (const scalar of text) {
    const current = CELL_TABLE.charProperties(scalar.codePointAt(0) ?? 0, preceding)
    if ((current & 1) === 1) {
      // A joining character widens the cell it joins by what it adds, which this table makes none.
      cells += widthIn(current) - widthIn(preceding)
    } else if (widthIn(current) === 0) {
      return null
    } else {
      cells += widthIn(current)
    }
    preceding = current
  }
  return cells
}
