/**
 * Which link of a message takes a press, over made rectangles.
 *
 * Each case below is a place where two links' targets overlap or a target meets an edge: the words
 * of two links one above the other in a table, two one-character links side by side, a link that
 * wraps over a short one, a link on a quote's first line, a plain line between two links, and the
 * pane's edges. The numbers are those of a 16 px line on a phone: a label's words are 17 px tall and
 * 24 px of line height separate one line's words from the next line's top.
 */

import { describe, expect, it } from 'vitest'

import { linkAt, type Rect, type Reach } from '../src/markdown/link-target'

/** The pane of a 390 px wide phone. */
const PANE: Rect = { left: 0, top: 0, right: 390, bottom: 844 }
/** The default size on Android: 48 dp, and half of it beside a label's words. */
const ANDROID: Reach = { least: 48, beside: 24 }
const IOS: Reach = { least: 44, beside: 22 }

/** The words of one line of a label. */
function words(left: number, top: number, width: number, height = 17): Rect {
  return { left, top, right: left + width, bottom: top + height }
}

/** A point, over links given by the rectangles of their words. */
function press(x: number, y: number, links: readonly (readonly Rect[])[], reach: Reach = ANDROID, bounds: Rect = PANE): number | null {
  return linkAt(
    { x, y },
    links.map((each) => ({ words: each })),
    reach,
    bounds
  )
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
  // The pane gives no room beside its words: a line's words start at the pane's left edge and end at
  // its right edge, and the last line of a conversation ends 10.7 px above the pane's bottom edge.
  const atStart = [words(0, 100, 8)]
  const atEnd = [words(382, 100, 8)]

  it('keeps its least size where the pane cuts one side: the cut room goes to the other side', () => {
    // 8 px of words are 56 wide as a target on Android (24 each side) and 52 on iOS (22 each side);
    // the pane cuts 24 and 22 of them at the start, and the target takes them back after the words.
    expect(press(0, 108.5, [atStart], ANDROID)).toBe(0)
    expect(press(48, 108.5, [atStart], ANDROID)).toBe(0)
    expect(press(56, 108.5, [atStart], ANDROID)).toBe(0)
    expect(press(56.1, 108.5, [atStart], ANDROID)).toBeNull()
    expect(press(44, 108.5, [atStart], IOS)).toBe(0)
    expect(press(52, 108.5, [atStart], IOS)).toBe(0)
    expect(press(52.1, 108.5, [atStart], IOS)).toBeNull()
  })

  it('does the same at the end of a line, sideways the other way', () => {
    expect(press(390, 108.5, [atEnd], ANDROID)).toBe(0)
    expect(press(342, 108.5, [atEnd], ANDROID)).toBe(0)
    expect(press(334, 108.5, [atEnd], ANDROID)).toBe(0)
    expect(press(333.9, 108.5, [atEnd], ANDROID)).toBeNull()
    expect(press(346, 108.5, [atEnd], IOS)).toBe(0)
    expect(press(338, 108.5, [atEnd], IOS)).toBe(0)
    expect(press(337.9, 108.5, [atEnd], IOS)).toBeNull()
  })

  it('is no wider than the pane where the pane is narrower than the least size', () => {
    const narrow: Rect = { left: 0, top: 0, right: 40, bottom: 844 }
    expect(press(-1, 108.5, [atStart], ANDROID, narrow)).toBeNull()
    expect(press(0, 108.5, [atStart], ANDROID, narrow)).toBe(0)
    expect(press(40, 108.5, [atStart], ANDROID, narrow)).toBe(0)
    expect(press(41, 108.5, [atStart], ANDROID, narrow)).toBeNull()
  })

  it('has the same least size above, where the last line of a conversation is cut below its words', () => {
    // The words end 10.7 px above the pane's bottom: the target's 48 dp reach 15.5 px under the
    // words, so the pane cuts 4.8 px of it, and the target takes them back above the words.
    const last = [words(100, 816.3, 120)]
    expect(press(150, 844, [last], ANDROID)).toBe(0)
    expect(press(150, 796, [last], ANDROID)).toBe(0)
    expect(press(150, 795.9, [last], ANDROID)).toBeNull()
    expect(press(150, 800, [last], IOS)).toBe(0)
    expect(press(150, 799.9, [last], IOS)).toBeNull()
  })

  it('has the same least size below, where the first line is cut above its words', () => {
    const first = [words(100, 4, 120)]
    expect(press(150, 0, [first], ANDROID)).toBe(0)
    expect(press(150, 48, [first], ANDROID)).toBe(0)
    expect(press(150, 48.1, [first], ANDROID)).toBeNull()
  })

  it('keeps the least size in both directions at a corner of the pane', () => {
    const corner = [words(0, 816.3, 8)]
    expect(press(0, 844, [corner], ANDROID)).toBe(0)
    expect(press(56, 796, [corner], ANDROID)).toBe(0)
    expect(press(56.1, 796, [corner], ANDROID)).toBeNull()
    expect(press(56, 795.9, [corner], ANDROID)).toBeNull()
  })

  it('takes no point that is nearer to another link’s words than to its own', () => {
    // At the start of the line the first link's target takes back 24 px to the right, out to x 56.
    // The point (40, 108) is 32 px from its words; the second link's words are 16 px under it and
    // its own target (which reaches 15.5 px above its words) does not hold it, but they are nearer.
    const first = [words(0, 100, 8)]
    const second = [words(36, 124, 24)]
    expect(press(40, 108, [first, second])).toBeNull()
    expect(press(40, 108, [second, first])).toBeNull()
    // Where no other link's words are nearer, the room given back is the first link's.
    expect(press(40, 108, [first])).toBe(0)
  })

  it('takes a point in the room given back where another link’s words are only as near', () => {
    const first = [words(0, 100, 8)]
    const second = [words(64, 100, 8)]
    expect(press(36, 108.5, [first, second])).toBe(0)
    expect(press(36, 108.5, [second, first])).toBe(1)
  })

  it('takes a press at each edge for the link there, when both edges have a link', () => {
    expect(press(388, 108.5, [atStart, atEnd])).toBe(1)
    expect(press(2, 108.5, [atStart, atEnd])).toBe(0)
  })

  it('is pressable out to the pane’s edge and no further', () => {
    expect(press(392, 108.5, [atEnd])).toBeNull()
  })
})

describe('a link the pane has scrolled out of view', () => {
  // The pane scrolls, so its box is the part of the conversation in view. A link takes part only by
  // what is in view of its words: words wholly outside the pane have no area, never take a point and
  // keep no other link's area from growing. Words are 17 px tall.
  const first = [words(100, 100, 120)]

  it('has no area at the top: words 10 and 30 px above the pane take no tap on the plain text below its edge', () => {
    for (const above of [10, 30]) {
      const hidden = [words(100, -above - 17, 120)]
      for (const y of [0, 2, 6, 12, 24, 36, 44, 48]) {
        expect(press(150, y, [hidden]), `${String(above)} px above, tap at y ${String(y)}`).toBeNull()
        expect(press(150, y, [hidden, first]), `${String(above)} px above, tap at y ${String(y)}, a link in view`).toBeNull()
      }
    }
  })

  it('has no area at the bottom: words 10 and 30 px below the pane take no tap on the plain text above its edge', () => {
    for (const below of [10, 30]) {
      const hidden = [words(100, 844 + below, 120)]
      for (const y of [844, 842, 838, 832, 820, 808, 800, 796]) {
        expect(press(150, y, [hidden]), `${String(below)} px below, tap at y ${String(y)}`).toBeNull()
      }
    }
  })

  it('has no area beside the pane where it scrolls sideways: words left or right of the pane take no tap', () => {
    const left = [words(-150, 100, 120)]
    const right = [words(400, 100, 120)]
    for (const x of [0, 6, 24, 48]) expect(press(x, 108, [left]), `left, tap at x ${String(x)}`).toBeNull()
    for (const x of [390, 384, 366, 342]) expect(press(x, 108, [right]), `right, tap at x ${String(x)}`).toBeNull()
  })

  it('is no link’s though its words are nearer to a point than the words of a link whose area holds it', () => {
    // The link at the start of the line gets back to the right what the pane cuts on the left, out to
    // x 56. The point (40, 30) is 32.8 px from its words; the hidden link's words are 32 px away.
    const atStart = [words(0, 6, 8)]
    const hidden = [words(36, -19, 24)]
    expect(press(40, 30, [atStart])).toBe(0)
    expect(press(40, 30, [atStart, hidden])).toBe(0)
    expect(press(40, 30, [hidden, atStart])).toBe(1)
  })

  it('has nothing in view of words that only touch an edge of the pane', () => {
    expect(press(150, 4, [[words(100, -17, 120)]])).toBeNull()
    expect(press(150, 840, [[words(100, 844, 120)]])).toBeNull()
    expect(press(4, 108, [[words(-120, 100, 120)]])).toBeNull()
    expect(press(386, 108, [[words(390, 100, 120)]])).toBeNull()
    // A hair in view is in view.
    expect(press(150, 4, [[words(100, -16.9, 120)]])).toBe(0)
  })

  it('takes part by the line of its words that is in view', () => {
    const wrapped = [words(16, -30, 300), words(16, -6, 200), words(16, 18, 120)]
    expect(press(60, 50, [wrapped])).toBe(0)
    expect(press(60, 4, [wrapped])).toBe(0)
    expect(press(60, 60, [wrapped])).toBeNull()
    const hidden = [words(16, -60, 300), words(16, -36, 200)]
    expect(press(60, 4, [hidden])).toBeNull()
    expect(press(60, 30, [hidden])).toBeNull()
  })
})

describe('a link whose line the pane’s edge cuts', () => {
  // It keeps what is in view of its words and their reach, held to the pane. Nothing is given back
  // on the axis the edge cuts, since words that are partly seen are where the person sees them.
  it('at the top, keeps the half of its target that is in view and takes nothing more below it', () => {
    const cut = [words(100, -8.5, 120)]
    // The words' middle is on the edge; the target reaches 24 px each way on Android, 22 on iOS.
    expect(press(150, 0, [cut], ANDROID)).toBe(0)
    expect(press(150, 24, [cut], ANDROID)).toBe(0)
    expect(press(150, 24.1, [cut], ANDROID)).toBeNull()
    expect(press(150, 48, [cut], ANDROID)).toBeNull()
    expect(press(150, 22, [cut], IOS)).toBe(0)
    expect(press(150, 22.1, [cut], IOS)).toBeNull()
  })

  it('at the bottom, keeps the half of its target that is in view and takes nothing more above it', () => {
    const cut = [words(100, 835.5, 120)]
    expect(press(150, 844, [cut], ANDROID)).toBe(0)
    expect(press(150, 820, [cut], ANDROID)).toBe(0)
    expect(press(150, 819.9, [cut], ANDROID)).toBeNull()
    expect(press(150, 796, [cut], ANDROID)).toBeNull()
  })

  it('at the side of a pane that scrolls sideways, keeps what is in view and takes nothing more past the words', () => {
    // Words from x 380 to 400 with the pane ending at 390: the target is the words and 24 px each side.
    const cut = [words(380, 100, 20)]
    expect(press(390, 108.5, [cut], ANDROID)).toBe(0)
    expect(press(356, 108.5, [cut], ANDROID)).toBe(0)
    expect(press(355.9, 108.5, [cut], ANDROID)).toBeNull()
  })

  it('gets back what the pane cuts on the axis where its words are in view', () => {
    // Cut at the top (nothing given back below), at the start of the line (given back to the right).
    const cut = [words(0, -8.5, 8)]
    expect(press(56, 24, [cut], ANDROID)).toBe(0)
    expect(press(56.1, 10, [cut], ANDROID)).toBeNull()
    expect(press(30, 24.1, [cut], ANDROID)).toBeNull()
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
    expect(press(240 + 24, 108, [long])).toBe(0)
    expect(press(240 + 25, 108, [long])).toBeNull()
    expect(press(40 - 24, 108, [long])).toBe(0)
    expect(press(40 - 25, 108, [long])).toBeNull()
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
    // Sideways a target is also the words grown by half the least size on each side: 56 and 52 wide.
    expect(press(104 + 28, 108.5, [label], ANDROID)).toBe(0)
    expect(press(104 + 28.1, 108.5, [label], ANDROID)).toBeNull()
    expect(press(104 + 26, 108.5, [label], IOS)).toBe(0)
    expect(press(104 + 26.1, 108.5, [label], IOS)).toBeNull()
  })
})

describe('a link on lines taller than its words', () => {
  // The largest iOS text size: the words are 56 px tall and each line 72.5 px. A target is never
  // shorter than the words, so a tap on plain text just above or below them, in the half-leading,
  // is the page's own to decide (it is the link's button, which the browser names) and no target
  // reaches past the words' height here.
  const LINE = 72.5
  const wrapped = [words(16, 100, 300, 56), words(16, 100 + LINE, 200, 56)]

  it('is the words’ own height', () => {
    expect(press(60, 92, [wrapped], IOS)).toBeNull()
    expect(press(60, 100, [wrapped], IOS)).toBe(0)
    expect(press(60, 156, [wrapped], IOS)).toBe(0)
  })

  it('leaves the gap between the words of two links on adjacent lines to the page’s own hit test', () => {
    const upper = [words(16, 100, 120, 56)]
    const lower = [words(16, 100 + LINE, 120, 56)]
    expect(press(60, 156, [upper, lower], IOS)).toBe(0)
    expect(press(60, 164, [upper, lower], IOS)).toBeNull()
    expect(press(60, 172.5, [upper, lower], IOS)).toBe(1)
  })
})
