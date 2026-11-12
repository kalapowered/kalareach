/**
 * Which link of a message a press belongs to.
 *
 * A link's words are often smaller than a finger, so a link is pressable over a larger region, its
 * target. Targets of neighbouring links overlap, and a stylesheet can only say which of two boxes is
 * on top, never which link is nearer. This is the one rule that says it, over rectangles alone: no
 * element, no event and no layout is read here, so each case of it can be stated with numbers.
 *
 * Among the links of a message, a press belongs to the link whose words are nearest to the point.
 * A press that no link's target holds is no link's. A link's target is the region of its words, grown
 * to the least size and to the room beside them, and the box the page itself gives the link's button,
 * whole. The box is never smaller than the link's own line (so a press in the half-leading above and
 * below the words is the link's), and a link that wraps is one box over all its lines, with its words
 * centred in it. The page's own hit test gives a press anywhere in the box to the link. At an equal
 * distance the earlier link in the message takes the press.
 */

/** A point in the page's coordinates. */
export interface Point {
  readonly x: number
  readonly y: number
}

/** A rectangle in the page's coordinates. */
export interface Rect {
  readonly left: number
  readonly top: number
  readonly right: number
  readonly bottom: number
}

/** A link as the rule sees it. */
export interface Link {
  /** The rectangles of the link's words, one for each line its label covers. */
  readonly words: readonly Rect[]
  /** The rectangles of the link's own button. */
  readonly box: readonly Rect[]
}

/** How far a link's target reaches past its words. */
export interface Reach {
  /** The least size of a target in each direction: 44 points on iOS and 48 dp on Android. */
  readonly least: number
  /** How far a target reaches sideways beside a label's words, before the least size is taken. */
  readonly beside: number
}

/**
 * How far past a box's edges the page's own hit test still takes the box: it hits the whole pixels
 * that enclose a box, and layout puts a box's edge at a fraction of a pixel. The pane's own box is
 * taken the same way.
 */
const SNAP = 1

/** Two distances closer than this are the same distance, so rounding in a layout takes no press away from the earlier link. */
const EQUAL = 1e-6

/**
 * The index of the link that takes a press at `point`, or null when none does.
 *
 * `links` are the links of the message in the order they have there. `bounds` is the room the pane
 * gives: no target reaches past it. A press arrives from inside the pane, so `bounds` only cuts a
 * target that the pane would cut.
 */
export function linkAt(point: Point, links: readonly Link[], reach: Reach, bounds: Rect): number | null {
  const room = grown(bounds, SNAP)
  let chosen: number | null = null
  let nearest = Number.POSITIVE_INFINITY
  for (let index = 0; index < links.length; index += 1) {
    const { words, box } = links[index] ?? { words: [], box: [] }
    const held =
      words.some((rect) => holds(within(targetOf(rect, reach), room), point)) ||
      box.some((rect) => holds(within(grown(rect, SNAP), room), point))
    if (!held) continue
    const distance = Math.min(...words.map((rect) => distanceTo(rect, point)))
    if (distance < nearest - EQUAL) {
      chosen = index
      nearest = distance
    }
  }
  return chosen
}

/** The region one rectangle of a link's words is pressable over: the words grown to the least size and to the reach beside them. */
export function targetOf(words: Rect, reach: Reach): Rect {
  const wide = Math.max(reach.least, words.right - words.left + 2 * reach.beside)
  const tall = Math.max(reach.least, words.bottom - words.top)
  const x = (words.left + words.right) / 2
  const y = (words.top + words.bottom) / 2
  return { left: x - wide / 2, right: x + wide / 2, top: y - tall / 2, bottom: y + tall / 2 }
}

/** `rect` with `by` more on every side. */
function grown(rect: Rect, by: number): Rect {
  return { left: rect.left - by, right: rect.right + by, top: rect.top - by, bottom: rect.bottom + by }
}

/** What `rect` keeps of itself inside `bounds`; a rectangle wholly outside keeps nothing. */
function within(rect: Rect, bounds: Rect): Rect {
  return {
    left: Math.max(rect.left, bounds.left),
    right: Math.min(rect.right, bounds.right),
    top: Math.max(rect.top, bounds.top),
    bottom: Math.min(rect.bottom, bounds.bottom)
  }
}

function holds(rect: Rect, point: Point): boolean {
  return point.x >= rect.left && point.x <= rect.right && point.y >= rect.top && point.y <= rect.bottom
}

/** How far `point` is from `rect`: nothing when it is inside. */
function distanceTo(rect: Rect, point: Point): number {
  const dx = Math.max(rect.left - point.x, 0, point.x - rect.right)
  const dy = Math.max(rect.top - point.y, 0, point.y - rect.bottom)
  return Math.hypot(dx, dy)
}
