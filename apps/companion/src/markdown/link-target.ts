/**
 * Which link of a message a press belongs to.
 *
 * A link's words are often smaller than a finger, so a link is pressable over a larger region, its
 * target. Targets of neighbouring links overlap, and a stylesheet can only say which of two boxes is
 * on top, never which link is nearer. This is the one rule that says it, over rectangles alone: no
 * element, no event and no layout is read here, so each case of it can be stated with numbers.
 *
 * Among the links of a message, a press belongs to the link whose words are nearest to the point.
 * A press that no target holds is no link's. At an equal distance the earlier link in the message
 * takes the press, and a point on another control of the message is that control's.
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

/** How far a link's target reaches past its words. */
export interface Reach {
  /** The least size of a target in each direction: 44 points on iOS and 48 dp on Android. */
  readonly least: number
  /** How far a target reaches sideways beside a label's words, before the least size is taken. */
  readonly beside: number
}

/** Two distances closer than this are the same distance, so rounding in a layout takes no press away from the earlier link. */
const EQUAL = 1e-6

/**
 * The index of the link that takes a press at `point`, or null when none does.
 *
 * `links` holds the rectangles of each link's words, one for each line the label covers, in the order
 * the links have in the message. `bounds` is the room the pane gives: no target reaches past it. A
 * press arrives from inside the pane, so `bounds` only cuts a target that the pane would cut.
 * `controls` are the boxes of the message's other controls, which a link's target never takes.
 */
export function linkAt(
  point: Point,
  links: readonly (readonly Rect[])[],
  reach: Reach,
  bounds: Rect,
  controls: readonly Rect[] = []
): number | null {
  if (controls.some((box) => holds(box, point))) return null
  let chosen: number | null = null
  let nearest = Number.POSITIVE_INFINITY
  for (let index = 0; index < links.length; index += 1) {
    const words = links[index] ?? []
    if (!words.some((rect) => holds(within(targetOf(rect, reach), bounds), point))) continue
    const distance = Math.min(...words.map((rect) => distanceTo(rect, point)))
    if (distance < nearest - EQUAL) {
      chosen = index
      nearest = distance
    }
  }
  return chosen
}

/** The region one rectangle of a link's words is pressable over. */
export function targetOf(words: Rect, reach: Reach): Rect {
  const wide = Math.max(reach.least, words.right - words.left + 2 * reach.beside)
  const tall = Math.max(reach.least, words.bottom - words.top)
  const x = (words.left + words.right) / 2
  const y = (words.top + words.bottom) / 2
  return { left: x - wide / 2, right: x + wide / 2, top: y - tall / 2, bottom: y + tall / 2 }
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
