/**
 * The packing of a line's links, held against an exhaustive search.
 *
 * `packRooms` gives each short link of a line the room it lacks of the least size. The search below tries
 * every assignment of boxes to a small random line (the words on whole pixels, the boxes' edges on half
 * pixels, a least size of 10): a box holds its link's words, stays in the column, and keeps off every other
 * link's box and every control. The packing must complete as many links as the best assignment does, and
 * its boxes must not cross one another, a control or the column. Where a group is not a row, each of its
 * lines must complete no fewer links than a search of that line alone against the middles of the gaps to
 * the other lines' links does. The seeds are fixed, so a failure names its line.
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

/** Two boxes that have to keep apart: their heights reach one another and their words do not lie one over the other. */
const related = (a: Item, b: Item): boolean =>
  a.box.bottom > b.box.top && a.box.top < b.box.bottom && (a.box.right <= b.box.left || b.box.right <= a.box.left)

/** The groups of links whose heights reach one another (by index), and whether each is a row (every two of its links must keep apart). */
function groupsOf(items: readonly Item[]): { links: number[]; row: boolean }[] {
  const links = items.flatMap((item, index) => (item.link ? [index] : []))
  const seen = new Set<number>()
  const groups: { links: number[]; row: boolean }[] = []
  for (const start of links) {
    if (seen.has(start)) continue
    const group = [start]
    seen.add(start)
    for (let next = 0; next < group.length; next += 1) {
      for (const other of links) {
        const at = items[group[next]].box
        if (!seen.has(other) && items[other].box.bottom > at.top && items[other].box.top < at.bottom) {
          seen.add(other)
          group.push(other)
        }
      }
    }
    groups.push({ links: group, row: group.every((a) => group.every((b) => a === b || related(items[a], items[b]))) })
  }
  return groups
}

/** Whether every group of links whose heights reach one another is a row. */
const allRows = (items: readonly Item[]): boolean => groupsOf(items).every((group) => group.row)

/** Lines of links laid out each on its own, 6 px apart (the boxes are 10 high: neighbouring lines reach one another, lines two apart do not), so that links can lie over one another. */
function layoutOf(seed: number, rows: number): Line {
  const next = generator(seed)
  const between = (low: number, high: number): number => low + Math.floor(next() * (high - low + 1))
  const items: Item[] = []
  const columnWidth = between(30, 60)
  const column = { left: 0, right: columnWidth }
  for (let row = 0; row < rows; row += 1) {
    let at = between(0, 10)
    for (let count = between(1, 2); count > 0; count -= 1) {
      const width = between(2, 13)
      items.push({ box: { left: at, top: row * 6, right: at + width, bottom: row * 6 + HIGH }, link: true, column })
      at += width + between(1, 14)
    }
  }
  return { column, items }
}

/**
 * The most links that any assignment of non-overlapping boxes completes, by trying all of them. `scope` is the items that take part (all
 * of them by default) and `walls` an extra bound on each link's box (none by default). A box grows in half pixels, because the middle
 * of a gap between words on whole pixels can lie on a half pixel.
 */
function bestCount(line: Line, scope: readonly number[] = line.items.map((_, index) => index), walls?: (index: number) => { left: number; right: number }): number {
  const links = scope.filter((index) => line.items[index].link)
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
      const wall = walls?.(index) ?? { left: -Infinity, right: Infinity }
      for (let left = 0; left <= need(index); left += 0.5) {
        const box = { left: own.left - left, right: own.right + (need(index) - left) }
        if (box.left < Math.min(line.column.left, own.left) || box.right > Math.max(line.column.right, own.right)) continue
        if (box.left < wall.left || box.right > wall.right) continue
        let clear = true
        for (const otherIndex of scope) {
          if (otherIndex === index) continue
          const other = line.items[otherIndex]
          const against = grown.get(otherIndex) ?? other.box
          if (!related(line.items[index], other)) continue
          if (box.left < against.right && against.left < box.right) clear = false
        }
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

/**
 * What a line-by-line packing gives the lines of a group that is not a row, by a search of each line on its own: its links keep off the
 * links of the group's other lines at the middle of the gap to a short one, or at the edge of a wide one. A line is the links that
 * share a top. Returns, for each line, the links it has and the most of them that any such assignment completes.
 */
function lineByLine(line: Line, group: readonly number[]): { own: number[]; best: number }[] {
  const need = (index: number): number => Math.max(0, LEAST - ((line.items[index]).box.right - (line.items[index]).box.left))
  const tops = [...new Set(group.map((index) => line.items[index].box.top))]
  return tops.map((top) => {
    const own = group.filter((index) => line.items[index].box.top === top)
    const walls = (index: number): { left: number; right: number } => {
      const item = line.items[index]
      let left = -Infinity
      let right = Infinity
      for (const other of group) {
        const box = line.items[other].box
        if (own.includes(other) || box.bottom <= item.box.top || box.top >= item.box.bottom) continue
        if (box.right <= item.box.left) left = Math.max(left, need(other) > 0 ? (box.right + item.box.left) / 2 : box.right)
        else if (box.left >= item.box.right) right = Math.min(right, need(other) > 0 ? (item.box.right + box.left) / 2 : box.left)
      }
      return { left, right }
    }
    return { own, best: bestCount(line, own, walls) }
  })
}

/** Packs `line` and checks it against the search: no box past the column or across another, and as many completed as the best assignment completes. */
function verify(line: Line, label: string, slack = 0): { completed: number; best: number; shortLinks: number; lines: { label: string; completed: number; first: number }[] } {
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
      if (!related(line.items[first], line.items[second])) continue
      expect(a.right <= b.left || b.right <= a.left, `${where}: boxes ${String(first)} and ${String(second)} cross`).toBe(true)
    }
  }
  const done = (index: number): boolean => {
    const box = boxes[index]
    const item = line.items[index]
    return item.link && box.right - box.left >= LEAST && item.box.right - item.box.left < LEAST
  }
  const completed = line.items.filter((_, index) => done(index)).length
  const best = bestCount(line)
  // A group that is not a row is packed line by line, so its count is held to the best only where every group is a row.
  if (allRows(line.items)) expect(completed, `${where}: links completed by the packing, against the most that any assignment completes`).toBe(best)
  // Elsewhere each line completes no fewer links than the line-by-line packing does, by a search of the line against the middles of the gaps.
  const lines: { label: string; completed: number; first: number }[] = []
  for (const group of groupsOf(line.items)) {
    if (group.row) continue
    for (const { own, best: first } of lineByLine(line, group.links)) {
      lines.push({ label: `${where}: links completed on the line at ${String(line.items[own[0]].box.top)}, against the line-by-line packing`, completed: own.filter(done).length, first })
    }
  }
  return { completed, best, shortLinks: line.items.filter((item) => item.link && item.box.right - item.box.left < LEAST).length, lines }
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

  it('keeps boxes apart, and in the column, in 600 layouts of two and 600 of three lines each laid out on its own, completes the most where every group is a row, and elsewhere completes on each line no fewer than the line-by-line packing does', () => {
    let notRows = 0
    let compared = 0
    let gained = 0
    for (let seed = 1; seed <= 600; seed += 1) {
      for (const rows of [2, 3]) {
        const line = layoutOf(seed + 20_000 * rows, rows)
        const result = verify(line, `layout ${String(seed)} of ${String(rows)} lines`)
        if (!allRows(line.items)) notRows += 1
        for (const entry of result.lines) {
          expect(entry.completed, entry.label).toBeGreaterThanOrEqual(entry.first)
          if (entry.first > 0) compared += 1
          if (entry.completed > entry.first) gained += 1
        }
      }
    }
    // The case is vacuous unless many layouts have a group that is not a row (a link over another, or lines that do not all reach one another).
    expect(notRows, 'layouts that have a group that is not a row').toBeGreaterThan(300)
    expect(compared, 'lines of those layouts where the line-by-line packing completes a link').toBeGreaterThan(1000)
    expect(gained, 'lines where the second pass completes more links than the line-by-line packing').toBeGreaterThan(10)
  })

  it.each([
    ['three links, the first and the third completed (3 to 5, 11 to 13, 16 to 23 in a column of 23)', [[3, 5], [11, 13], [16, 23]] as const, 23],
    ['three links in a narrow column, the first and the third completed (5 to 7, 10 to 12, 17 to 19 in a column of 22)', [[5, 7], [10, 12], [17, 19]] as const, 22]
  ] as const)('completes two of %s, whatever the choices of the table', (_name, words, right) => {
    expect(verify(fixed(words, { left: 0, right }), 'fixed line').completed).toBe(2)
  })
})
