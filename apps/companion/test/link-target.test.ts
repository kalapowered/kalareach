/**
 * Which link of a message takes a press, over made rectangles.
 *
 * Each case below is a place where a link's box once took a press that belonged to a neighbour: the
 * words of two links one above the other in a table, two one-character links side by side, a link
 * that wraps over a short one, a link on a quote's first line, a plain line between two links, and
 * the pane's edges. The numbers are those of a 16 px line on a phone: a label's words are 17 px tall
 * and 24 px of line height separate one line's words from the next line's top.
 */

import { describe, expect, it } from 'vitest'

import { linkAt, type Rect, type Reach } from '../src/markdown/link-target'

/** The pane of a 390 px wide phone. */
const PANE: Rect = { left: 0, top: 0, right: 390, bottom: 844 }
/** The default size on Android: 48 dp, and the 16 px the gutter leaves beside a label. */
const ANDROID: Reach = { least: 48, beside: 16 }
const IOS: Reach = { least: 44, beside: 16 }

/** The words of one line of a label. */
function words(left: number, top: number, width: number, height = 17): Rect {
  return { left, top, right: left + width, bottom: top + height }
}

function press(
  x: number,
  y: number,
  links: readonly (readonly Rect[])[],
  reach: Reach = ANDROID,
  bounds: Rect = PANE,
  controls: readonly Rect[] = []
): number | null {
  return linkAt({ x, y }, links, reach, bounds, controls)
}

describe('a press on a link’s own words', () => {
  it('is that link’s, though another link’s target covers the same point', () => {
    const above = [words(16, 100, 120)]
    const below = [words(16, 122, 120)]
    expect(press(60, 108, [above, below])).toBe(0)
    expect(press(60, 130, [above, below])).toBe(1)
  })
})

describe('two links in one column of two table rows, 17.6 px apart', () => {
  // Twelve px text: the words are 14 px tall, and a row's padding and border put 13 px between the
  // lines, so the words of the rows are 17.6 px apart.
  const upper = [words(40, 100, 90, 14)]
  const lower = [words(40, 131.6, 100, 14)]

  it('gives a press 1 to 6 px under the upper link’s words to the upper link', () => {
    for (const under of [1, 2, 3, 4, 5, 6]) {
      expect(press(80, 114 + under, [upper, lower]), `${String(under)} px under`).toBe(0)
    }
  })

  it('gives a press 1 to 6 px above the lower link’s words to the lower link', () => {
    for (const over of [1, 2, 3, 4, 5, 6]) {
      expect(press(80, 131.6 - over, [upper, lower]), `${String(over)} px above`).toBe(1)
    }
  })

  it('shares the gap at its middle, and gives the middle to the earlier link', () => {
    expect(press(80, 114 + 8.8, [upper, lower])).toBe(0)
    expect(press(80, 114 + 8.9, [upper, lower])).toBe(1)
  })
})

describe('two one-character links side by side', () => {
  it('with no space between them splits a press under them where their words meet', () => {
    const first = [words(100, 200, 8)]
    const second = [words(108, 200, 8)]
    expect(press(102, 222, [first, second])).toBe(0)
    expect(press(107.9, 222, [first, second])).toBe(0)
    expect(press(108.1, 222, [first, second])).toBe(1)
    expect(press(114, 222, [first, second])).toBe(1)
    expect(press(102, 195, [first, second])).toBe(0)
    expect(press(114, 195, [first, second])).toBe(1)
  })

  it('with one space between them splits a press at the middle of the space, above and below', () => {
    const first = [words(100, 200, 8)]
    const second = [words(112, 200, 8)]
    for (const y of [195, 222]) {
      expect(press(103, y, [first, second]), `x 103, y ${String(y)}`).toBe(0)
      expect(press(109.9, y, [first, second]), `x 109.9, y ${String(y)}`).toBe(0)
      expect(press(110.1, y, [first, second]), `x 110.1, y ${String(y)}`).toBe(1)
      expect(press(117, y, [first, second]), `x 117, y ${String(y)}`).toBe(1)
    }
  })

  it('gives a press just below the first of them to the first, as on iOS', () => {
    const first = [words(100, 200, 8)]
    const second = [words(108, 200, 8)]
    expect(press(104, 219, [first, second], IOS)).toBe(0)
  })
})

describe('a link that wraps over two lines, above a short link', () => {
  const wrapped = [words(16, 300, 314), words(16, 324, 214)]
  const short = [words(16, 348, 24)]

  it('gives a press just above the short link’s words to the short link, though the wrapped link’s target covers it', () => {
    expect(press(22, 346, [wrapped, short])).toBe(1)
    expect(press(22, 345, [wrapped, short])).toBe(1)
  })

  it('gives a press just below the wrapped link’s last line to the wrapped link', () => {
    expect(press(22, 342, [wrapped, short])).toBe(0)
    expect(press(100, 342, [wrapped, short])).toBe(0)
  })

  it('gives a press beside the short link, where only the wrapped link’s target reaches, to the wrapped link', () => {
    expect(press(200, 350, [wrapped, short])).toBe(0)
  })

  it('gives a press on the empty part of the wrapped link’s last line, beside its words, to the wrapped link', () => {
    expect(press(280, 330, [wrapped, short])).toBe(0)
  })
})

describe('a link on the first line of a quote', () => {
  // The quote's margin puts 30 px between the words of the line above and the quote's first line.
  const above = [words(16, 200, 84)]
  const quoted = [words(32, 247, 88)]

  it('takes a press just above its words', () => {
    expect(press(60, 245, [above, quoted])).toBe(1)
    expect(press(60, 241, [above, quoted])).toBe(1)
  })

  it('leaves a press just under the link above to that link', () => {
    expect(press(60, 219, [above, quoted])).toBe(0)
    expect(press(60, 223, [above, quoted])).toBe(0)
  })
})

describe('a plain line between two links', () => {
  const upper = [words(16, 100, 84)]
  const lower = [words(16, 146, 84)]

  it('shares the plain line at the middle between the words', () => {
    expect(press(50, 130, [upper, lower])).toBe(0)
    expect(press(50, 133, [upper, lower])).toBe(1)
  })

  it('gives the exact middle to the earlier link, whichever link that is', () => {
    expect(press(50, 131.5, [upper, lower])).toBe(0)
    expect(press(50, 131.5, [lower, upper])).toBe(0)
  })
})

describe('a link at each edge of the pane', () => {
  const atStart = [words(16, 100, 8)]
  const atEnd = [words(366, 100, 8)]

  it('is pressable out to the pane’s edge and no further', () => {
    expect(press(1, 108, [atStart])).toBe(0)
    expect(press(0, 108, [atStart])).toBe(0)
    expect(press(389, 108, [atEnd])).toBe(0)
    expect(press(390, 108, [atEnd])).toBe(0)
    expect(press(392, 108, [atEnd])).toBeNull()
  })

  it('has the room the pane gives, so a narrow label beside the edge keeps what is left of its target', () => {
    // A label 8 wide is 48 wide as a target, 24 each side of its middle at 20: the pane holds it at 0.
    expect(press(0, 108, [[words(16, 100, 8)]])).toBe(0)
    expect(press(44.5, 108, [[words(16, 100, 8)]])).toBeNull()
  })

  it('takes a press at each edge for the link there, when both edges have a link', () => {
    const start = [words(16, 100, 8)]
    const end = [words(366, 100, 8)]
    expect(press(388, 108, [start, end])).toBe(1)
    expect(press(2, 108, [start, end])).toBe(0)
  })
})

describe('equal distance', () => {
  it('goes to the earlier link', () => {
    const left = [words(0, 100, 10)]
    const right = [words(30, 100, 10)]
    expect(press(20, 108, [left, right])).toBe(0)
    expect(press(20, 108, [right, left])).toBe(0)
  })
})

describe('a press no link’s target holds', () => {
  it('is no link’s: far above or below every link', () => {
    expect(press(60, 40, [[words(16, 100, 120)]])).toBeNull()
    expect(press(60, 180, [[words(16, 100, 120)]])).toBeNull()
  })

  it('is no link’s: beside a long label, past the reach beside its words', () => {
    const long = [words(40, 100, 200)]
    expect(press(240 + 16, 108, [long])).toBe(0)
    expect(press(240 + 17, 108, [long])).toBeNull()
    expect(press(40 - 17, 108, [long])).toBeNull()
  })

  it('is no link’s when there are no links, or a link with no words', () => {
    expect(press(60, 108, [])).toBeNull()
    expect(press(60, 108, [[]])).toBeNull()
  })
})

describe('the least size', () => {
  it('is 44 points on iOS and 48 dp on Android, in every direction, about the middle of a short label', () => {
    const label = [words(100, 100, 8)]
    // The middle is (104, 108.5): 22 and 24 from it.
    expect(press(104, 108.5 + 22, [label], IOS)).toBe(0)
    expect(press(104, 108.5 + 22.1, [label], IOS)).toBeNull()
    expect(press(104, 108.5 + 24, [label], ANDROID)).toBe(0)
    expect(press(104, 108.5 + 24.1, [label], ANDROID)).toBeNull()
    expect(press(104 + 24, 108.5, [label], ANDROID)).toBe(0)
    expect(press(104 + 24.1, 108.5, [label], ANDROID)).toBeNull()
  })
})

describe('another control of the message', () => {
  it('keeps a point on its own box, though a link’s target holds the point', () => {
    const link = [words(16, 100, 120)]
    const button: Rect = { left: 20, top: 118, right: 120, bottom: 150 }
    expect(press(60, 122, [link], ANDROID, PANE, [button])).toBeNull()
    expect(press(60, 116, [link], ANDROID, PANE, [button])).toBe(0)
  })
})
