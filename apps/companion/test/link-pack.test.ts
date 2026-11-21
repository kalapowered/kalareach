/**
 * The packing of a line's links, held against an exhaustive search.
 *
 * `packRooms` gives each short link of a line the room it lacks of the least size. The search below tries
 * every assignment of boxes to a small random line (whole pixels, a least size of 10): a box holds its
 * link's words, stays in the column, and keeps off every other link's box and every control. The packing
 * must complete as many links as the best assignment does, and its boxes must not cross one another, a
 * control or the column. The seeds are fixed, so a failure names its line.
 */

import { describe, expect, it } from 'vitest'

import { packRooms, type Item } from '../src/markdown/link-fit'

const LEAST = 10
const HIGH = 10

/** A small deterministic generator, so that a line is the same on every run. */
function generator(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let value = state
    value = Math.imul(value ^ (value >>> 15), value | 1)
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61)
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296
  }
}

interface Line {
  readonly items: Item[]
  readonly column: { left: number; right: number }
}

/** Links and controls in a row, with random widths and gaps (some gaps none), in a column that is at times no wider than the row. */
function lineOf(seed: number, rows = 1): Line {
  const next = generator(seed)
  const between = (low: number, high: number): number => low + Math.floor(next() * (high - low + 1))
  const count = between(2, 5)
  const kinds = Array.from({ length: count }, () => next() < 0.25)
  if (!kinds.includes(false)) kinds[0] = false
  const boxes: { left: number; right: number; control: boolean }[] = []
  let at = between(0, 6)
  for (const control of kinds) {
    const width = control ? between(6, 14) : between(2, 13)
    boxes.push({ left: at, right: at + width, control })
    at += width + (next() < 0.2 ? 0 : between(1, 16))
  }
  const first = boxes[0]?.left ?? 0
  const last = boxes[boxes.length - 1]?.right ?? 0
  const column = { left: next() < 0.4 ? first : Math.max(0, first - between(0, 14)), right: next() < 0.4 ? last : last + between(0, 14) }
  return {
    column,
    items: boxes.map((box) => {
      // On two lines every box reaches every other's height, and none is on the same line as one a few px lower.
      const top = rows === 2 && next() < 0.5 ? 5 : 0
      return { box: { left: box.left, top, right: box.right, bottom: top + HIGH }, link: !box.control, column }
    })
  }
}

/** The most links that any assignment of non-overlapping boxes completes, by trying all of them. */
function bestCount(line: Line): number {
  const links = line.items.flatMap((item, index) => (item.link ? [index] : []))
  const need = (index: number): number => Math.max(0, LEAST - ((line.items[index]).box.right - (line.items[index]).box.left))
  const shortLinks = links.filter((index) => need(index) > 0)
  let best = 0
  for (let mask = 0; mask < 1 << shortLinks.length; mask += 1) {
    const chosen = shortLinks.filter((_, bit) => (mask >> bit) & 1)
    if (chosen.length <= best) continue
    const grown = new Map<number, { left: number; right: number }>()
    const settle = (at: number): boolean => {
      if (at === chosen.length) return true
      const index = chosen[at]
      const own = (line.items[index]).box
      for (let left = 0; left <= need(index); left += 1) {
        const box = { left: own.left - left, right: own.right + (need(index) - left) }
        if (box.left < Math.min(line.column.left, own.left) || box.right > Math.max(line.column.right, own.right)) continue
        let clear = true
        line.items.forEach((other, otherIndex) => {
          if (otherIndex === index) return
          const against = grown.get(otherIndex) ?? other.box
          if (box.left < against.right && against.left < box.right) clear = false
        })
        if (!clear) continue
        grown.set(index, box)
        if (settle(at + 1)) return true
        grown.delete(index)
      }
      return false
    }
    if (settle(0)) best = chosen.length
  }
  return best
}

/** Packs `line` and checks it against the search: no box past the column or across another, and as many completed as the best assignment completes. */
function verify(line: Line, label: string, slack = 0): { completed: number; best: number; shortLinks: number } {
  const rooms = packRooms(line.items, LEAST, slack)
  const boxes = line.items.map((item, index) => {
    const room = rooms[index] ?? { left: 0, right: 0 }
    return { left: item.box.left - room.left, right: item.box.right + room.right }
  })
  const where = `${label}: ${JSON.stringify(line.items.map((item) => [item.link ? 'link' : 'control', item.box.left, item.box.right, item.box.top]))} in ${JSON.stringify(line.column)}`
  line.items.forEach((item, index) => {
    const box = boxes[index]
    expect(box.left, `${where}: the box of item ${String(index)} past the column`).toBeGreaterThanOrEqual(Math.min(line.column.left, item.box.left))
    expect(box.right, `${where}: the box of item ${String(index)} past the column`).toBeLessThanOrEqual(Math.max(line.column.right, item.box.right))
    if (!item.link) expect(rooms[index], `${where}: a control with room`).toEqual({ left: 0, right: 0 })
  })
  for (let first = 0; first < boxes.length; first += 1) {
    for (let second = first + 1; second < boxes.length; second += 1) {
      const a = boxes[first]
      const b = boxes[second]
      expect(a.right <= b.left || b.right <= a.left, `${where}: boxes ${String(first)} and ${String(second)} cross`).toBe(true)
    }
  }
  const completed = line.items.filter((item, index) => {
    const box = boxes[index]
    return item.link && box.right - box.left >= LEAST && item.box.right - item.box.left < LEAST
  }).length
  const best = bestCount(line)
  expect(completed, `${where}: links completed by the packing, against the most that any assignment completes`).toBe(best)
  return { completed, best, shortLinks: line.items.filter((item) => item.link && item.box.right - item.box.left < LEAST).length }
}

/** A line of links at `words` (left, right), in a column. */
const fixed = (words: readonly (readonly [number, number])[], column: { left: number; right: number }): Line => ({
  column,
  items: words.map(([left, right]) => ({ box: { left, top: 0, right, bottom: HIGH }, link: true, column }))
})

describe('the packing of a line', () => {
  it('completes as many short links as any assignment of non-overlapping boxes does, and no box crosses another, in 600 random lines', () => {
    let crowded = 0
    let completable = 0
    for (let seed = 1; seed <= 600; seed += 1) {
      const { best, shortLinks } = verify(lineOf(seed), `line ${String(seed)}`)
      if (shortLinks > best) crowded += 1
      if (best >= 2) completable += 1
    }
    // The case is vacuous unless some lines have links that compete for room and some have several that can all be completed.
    expect(crowded, 'lines where no assignment completes every short link').toBeGreaterThan(20)
    expect(completable, 'lines where two or more short links are completed').toBeGreaterThan(100)
  })

  it('completes as many short links as any assignment does across two lines whose links stand apart, in 600 random layouts', () => {
    let across = 0
    for (let seed = 1; seed <= 600; seed += 1) {
      const line = lineOf(seed + 10_000, 2)
      verify(line, `layout ${String(seed)}`)
      if (new Set(line.items.map((item) => item.box.top)).size === 2 && line.items.filter((item) => item.link).length >= 2) across += 1
    }
    expect(across, 'layouts that have links on both lines').toBeGreaterThan(200)
  })

  it('completes the two links that fit where the row has them, whatever the order of the choices of the table (fixed lines)', () => {
    // The first and the third link are completed (3 to 5 and 16 to 23 with 11 to 13 left short), not the second alone.
    expect(verify(fixed([[3, 5], [11, 13], [16, 23]], { left: 0, right: 23 }), 'three links').completed).toBe(2)
    // A skipped middle link leaves its gap whole: the first and the third reach 10 each, the second does not.
    expect(verify(fixed([[5, 7], [10, 12], [17, 19]], { left: 0, right: 22 }), 'three links in a narrow column').completed).toBe(2)
  })
})
