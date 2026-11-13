/**
 * Which link of a message a tap on plain text near it belongs to, and what a click does besides what
 * the browser does with it.
 *
 * A link's words are often smaller than a finger, so a tap that lands on plain text near the words
 * is the link's. The browser decides every tap that lands on the link's own button or on another
 * control; this decides only where it names neither. Targets of neighbouring links overlap, and this
 * is the one rule that says which link is nearer, over rectangles alone: no element, no event and no
 * layout is read here, so each case of it can be stated with numbers.
 *
 * Among the links of a message, a point belongs to the link whose words are nearest to it. A point
 * that no link's target holds is no link's. A link's target is the region of its words, grown to the
 * least size and to the room beside them, and held to the pane. Where the pane cuts one side of a
 * target, the other side grows by what was cut, so a link at the pane's edge keeps the least size
 * too; the room that gives back goes to a link only where no other link's words are nearer. At an
 * equal distance the earlier link in the message takes the point.
 *
 * The pane scrolls, so its box is the part of the conversation that is in view, and a link takes part
 * only by what is in view of its words. A line of words wholly outside the pane has no area and no
 * distance: it never takes a point and keeps no other link's area from growing. The room that a cut is
 * given back applies only on an axis on which the words are wholly in view; words that the pane's edge
 * cuts keep the part of their target that is in view, and nothing is given back on that axis. A point
 * outside the pane's box (a scroll bar's strip) is no link's.
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
}

/** How far a link's target reaches past its words. */
export interface Reach {
  /** The least size of a target in each direction: 44 points on iOS and 48 dp on Android. */
  readonly least: number
  /** How far a target reaches sideways beside a label's words, before the least size is taken. */
  readonly beside: number
}

/** Two distances closer than this are the same distance, so rounding in a layout takes no point away from the earlier link. */
const EQUAL = 1e-6

/**
 * The index of the link that takes a press at `point`, or null when none does.
 *
 * `links` are the links of the message in the order they have there. `bounds` is the room the pane
 * gives: no target reaches past it.
 */
export function linkAt(point: Point, links: readonly Link[], reach: Reach, bounds: Rect): number | null {
  if (!holds(bounds, point)) return null
  const seen = links.map(({ words }) => words.filter((rect) => inView(rect, bounds)))
  const distances = seen.map((parts) => Math.min(...parts.map((rect) => distanceTo(rect, point))))
  const closest = Math.min(...distances)
  let chosen: number | null = null
  let nearest = Number.POSITIVE_INFINITY
  for (let index = 0; index < links.length; index += 1) {
    const parts = seen[index] ?? []
    const distance = distances[index] ?? Number.POSITIVE_INFINITY
    const own = parts.some((rect) => holds(within(targetOf(rect, reach), bounds), point))
    // What the pane's edge cut from one side is given back on the other, but not where it takes a
    // point from the link whose words are nearer.
    const given = !own && distance <= closest + EQUAL && parts.some((rect) => holds(fitted(rect, reach, bounds), point))
    if (!own && !given) continue
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

/** What `rect` keeps of itself inside `bounds`; a rectangle wholly outside keeps nothing. */
function within(rect: Rect, bounds: Rect): Rect {
  return {
    left: Math.max(rect.left, bounds.left),
    right: Math.min(rect.right, bounds.right),
    top: Math.max(rect.top, bounds.top),
    bottom: Math.min(rect.bottom, bounds.bottom)
  }
}

/**
 * The target of the words `rect` held to `bounds`, with each cut given back: where an edge of `bounds`
 * cuts one side of the target, the opposite side grows by what was cut. This is so only on an axis on
 * which the words are wholly in view; on an axis that the edge cuts through the words, the target is
 * what is in view of it. A target larger than `bounds` in a direction fills `bounds` there.
 */
function fitted(rect: Rect, reach: Reach, bounds: Rect): Rect {
  const target = targetOf(rect, reach)
  const across = rect.left >= bounds.left && rect.right <= bounds.right ? fit(target.left, target.right, bounds.left, bounds.right) : clamp(target.left, target.right, bounds.left, bounds.right)
  const down = rect.top >= bounds.top && rect.bottom <= bounds.bottom ? fit(target.top, target.bottom, bounds.top, bounds.bottom) : clamp(target.top, target.bottom, bounds.top, bounds.bottom)
  return { left: across[0], right: across[1], top: down[0], bottom: down[1] }
}

/** The span from `low` to `high` held to the span from `min` to `max`, a cut on one side given to the other. */
function fit(low: number, high: number, min: number, max: number): readonly [number, number] {
  let from = low
  let to = high
  if (from < min) {
    to += min - from
    from = min
  }
  if (to > max) {
    from -= to - max
    to = max
  }
  return [Math.max(from, min), to]
}

/** The span from `low` to `high` held to the span from `min` to `max`, with nothing given back. */
function clamp(low: number, high: number, min: number, max: number): readonly [number, number] {
  return [Math.max(low, min), Math.min(high, max)]
}

/** Whether any of `rect` is in view in `bounds`: a rectangle that only touches an edge has nothing in view. */
function inView(rect: Rect, bounds: Rect): boolean {
  return rect.right > bounds.left && rect.left < bounds.right && rect.bottom > bounds.top && rect.top < bounds.bottom
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

/** What a click names: the control or the link the browser sent it to, or neither (plain text). */
export type Named = 'control' | 'link' | 'neither'

/** A link of the pane as the decision reads it. `id` is the caller's own name for the element. */
export interface PaneLink<L> extends Link {
  readonly id: L
  /** What the link opens: a link that opens something else than it did is not the link that was pressed. */
  readonly destination: string
}

/** The links of the pane and what a target needs, as the page lays them out now. */
export interface Layout<L> {
  readonly links: readonly PaneLink<L>[]
  readonly reach: Reach
  readonly bounds: Rect
}

/** What the page keeps of a press: written at a primary pointer down, read by the click that follows. */
export interface Press<L> {
  /** `touch`, `pen` or `mouse`. */
  readonly pointerType: string
  /** The link the nearest-words rule named at the press's start, and what it opened then, or null. */
  readonly start: { readonly link: L; readonly destination: string } | null
  /** Whether the press moved beyond the slop between its pointer down and its pointer up. */
  readonly moved: boolean
  /** The clock's reading (milliseconds) when the pointer came up, or null while it is down. */
  readonly upAt: number | null
}

/** A click, as the decision reads it. */
export interface Click {
  readonly trusted: boolean
  readonly detail: number
  /** The clock's reading (milliseconds), on the clock of `Press.upAt`. */
  readonly at: number
  readonly names: Named
  readonly point: Point
}

export type Decision<L> = { readonly kind: 'stand' } | { readonly kind: 'open'; readonly link: L }

/** How long after a press's pointer up its click may still come, in milliseconds. */
export const CLICK_WITHIN = 3000

const STAND = { kind: 'stand' } as const

/**
 * What a click does besides what the browser does with it. The click itself always stands: it goes
 * where the browser sent it, and this adds one thing, a click on a link.
 *
 * A click that names a link or a control stands alone. A trusted click that names neither, a click on
 * plain text, also opens a link when a touch or a pen pressed that link's words or the room beside
 * them and the click's own point still belongs to it: the press did not move beyond the slop; the
 * click has a detail of 1 and comes after the pointer's up and within `CLICK_WITHIN` of it; and the
 * nearest-words rule names the same element, opening the same destination, at the press's start and at
 * the click's point. A mouse's click on plain text opens nothing, as on a desktop. The press is the
 * record of the latest primary pointer down: a later press, or a pointer cancel, leaves none.
 *
 * `layout` is read only when the other conditions hold.
 */
export function decide<L>(press: Press<L> | null, click: Click, layout: () => Layout<L>): Decision<L> {
  if (click.names !== 'neither' || !click.trusted || click.detail !== 1) return STAND
  if (press === null || (press.pointerType !== 'touch' && press.pointerType !== 'pen')) return STAND
  if (press.moved || press.start === null || press.upAt === null) return STAND
  if (click.at < press.upAt || click.at - press.upAt > CLICK_WITHIN) return STAND
  const { links, reach, bounds } = layout()
  const index = linkAt(click.point, links, reach, bounds)
  const chosen = index === null ? undefined : links[index]
  if (chosen === undefined || chosen.id !== press.start.link || chosen.destination !== press.start.destination) return STAND
  return { kind: 'open', link: chosen.id }
}
