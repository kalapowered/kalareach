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
 * The page scrolls, zooms and clips, so each link has a view: the part of the page that every box which
 * clips it leaves of it (the caller reads those boxes: the pane, the scrollers inside and outside it,
 * and the visual viewport). A link takes part only by what is in view of its words. A line of words
 * wholly outside the link's view has no area and no distance: it never takes a point and keeps no other
 * link's area from growing. The room that a cut is given back applies only on an axis on which the
 * words are wholly in view, and is fitted once against the whole view, never box by box; words that the
 * view cuts through keep the part of their target that is in view, and nothing is given back on that
 * axis. A point outside a link's view (a scroll bar's strip, another scroller's edge) is not that link's.
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
  /**
   * What every box that clips the link leaves of the page, in the page's coordinates: the intersection
   * of the client boxes of its clipping ancestors and of the visual viewport. It may be empty (a left
   * edge at or past the right edge).
   */
  readonly view: Rect
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
 * `links` are the links of the message in the order they have there, each with its own view: no target
 * reaches past it, and the words are weighed by what is in it.
 */
export function linkAt(point: Point, links: readonly Link[], reach: Reach): number | null {
  // The rectangles of the words that have something in view, with what is in view of each.
  const seen = links.map(({ words, view }) => words.filter((rect) => inView(rect, view)).map((rect) => ({ rect, part: within(rect, view) })))
  const distances = seen.map((parts) => Math.min(...parts.map(({ part }) => distanceTo(part, point))))
  const closest = Math.min(...distances)
  let chosen: number | null = null
  let nearest = Number.POSITIVE_INFINITY
  for (let index = 0; index < links.length; index += 1) {
    const parts = seen[index] ?? []
    const view = links[index]?.view
    const distance = distances[index] ?? Number.POSITIVE_INFINITY
    if (view === undefined) continue
    const own = parts.some(({ rect }) => holds(within(targetOf(rect, reach), view), point))
    // What the view cut from one side is given back on the other, but not where it takes a point
    // from the link whose words are nearer.
    const given = !own && distance <= closest + EQUAL && parts.some(({ rect }) => holds(fitted(rect, reach, view), point))
    if (!own && !given) continue
    if (distance < nearest - EQUAL) {
      chosen = index
      nearest = distance
    }
  }
  return chosen
}

/**
 * How far from a point the words of a link can be and still be nearer to it than the words of a link
 * whose area holds it: the farthest a point of an area lies from the words that it belongs to.
 *
 * A target reaches `beside` past the words on each side (or `(least - width) / 2`, where that is more),
 * and `(least - height) / 2` above and below them. Where the view cuts a side of a target, the opposite
 * side grows by what was cut; the words are wholly in view on an axis where that happens, so what is cut
 * is at most the reach on the cut side, and the area ends at most twice that reach past the words on the
 * other side: across, `2 * max(beside, least / 2)`, which is `least` for a reach of half the least size;
 * down, less than `least`. Both axes can be cut at once, at a corner of the pane, so the farthest point
 * of an area is at the corner of that rectangle: `hypot(least, least)` for the reach of the least size
 * and half of it beside. Words nearer to a point than the words of such a link are within the same radius
 * of it, so a layout that holds every link whose words are within this radius of a point holds every
 * link that the rule weighs there. (A link's view only takes from this: what is in view of words is part
 * of them, and a point outside a view is no more distant from the words than from their part in view.)
 */
export function contestRadius(reach: Reach): number {
  return Math.hypot(2 * Math.max(reach.beside, reach.least / 2), reach.least)
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

/**
 * Whether any of `rect` is in view in `bounds`: a rectangle that only touches an edge has nothing in
 * view, and a view that is empty (its left edge at or past its right edge, or its top at or past its
 * bottom) shows nothing, though a rectangle spans the gap.
 */
function inView(rect: Rect, bounds: Rect): boolean {
  if (bounds.left >= bounds.right || bounds.top >= bounds.bottom) return false
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
}

/** What the page keeps of a press: written at a primary pointer down, read by the click that follows. */
export interface Press<L> {
  /** `touch`, `pen` or `mouse`. */
  readonly pointerType: string
  /** Where the pointer went down. */
  readonly at: Point
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

/** How far a press may move and still be one tap, in CSS pixels: the platforms' touch slop is 8 to 10. */
export const SLOP = 10

/**
 * The most that an engine moves the click of a tap away from its press when it adjusts the touch toward
 * a nearby control, in CSS pixels at a page scale of 1 (the page's viewport sets it; on a zoomed page the
 * same distance is fewer CSS pixels).
 *
 * - Blink: `third_party/blink/renderer/core/page/touch_adjustment.cc`, `GetHitTestRectForAdjustment`,
 *   holds the touch's area between `kMinAdjustmentSizeDip` (20) and `kMaxAdjustmentSizeDip` (32) wide,
 *   and `SnapTo` puts the adjusted point inside that square: at most 16 px on an axis, `16 * sqrt(2)`
 *   at its corner. A finger-sized contact has the largest area; a synthetic touch has the smallest (10 px
 *   on an axis, which is what the browser cases log).
 * - WebKit: `Source/WebCore/page/LocalFrame.cpp`, `LocalFrame::qualifyingNodeAtViewportLocation`, tests
 *   points up to `unscaledSearchRadius` (15) times the screen's pixel density over 163 (about 1 on a
 *   phone) from the touch, on each axis: at most 15 px, less on a diagonal.
 *
 * The larger of the two is Blink's corner. The cases log the press-to-click distance of every tap on both
 * engines and on the emulated phones, and hold it to `CLICK_AWAY`.
 */
export const TOUCH_ADJUSTMENT = 16 * Math.SQRT2

/**
 * How far a click may lie from its press and still be that press's tap: the finger's slop and the
 * engine's largest adjustment of a touch. A click opens only the link that its press lit, whatever the
 * bound is; the bound keeps a click that another input made elsewhere from using an old press.
 */
export const CLICK_AWAY = SLOP + TOUCH_ADJUSTMENT

const STAND = { kind: 'stand' } as const

/**
 * Whether a press of this pointer type can get an open from `decide`: a touch or a pen. A mouse's or a
 * trackpad's click on plain text opens nothing, as on a desktop, so a press of those lights nothing by
 * the rule either, and keeps no look by it. This one test serves every path that lights or keeps a look
 * or opens: the pointer down (which link the press lights), each scroll or resize while a lit press lives
 * (whether a release would still open it) and the click (`decide`). A press on a link's own element is
 * kept besides by the element lying under the point, for every pointer type.
 */
export function opensByRule(pointerType: string): boolean {
  return pointerType === 'touch' || pointerType === 'pen'
}

/**
 * Whether the nearest-words rule, run at the press's own point in the layout that `layout` gives now,
 * still names the link that the press lit, opening what it opened then. A press that lit nothing has
 * nothing to keep and does not keep it.
 */
export function keepsPress<L>(press: Press<L>, layout: (at: Point) => Layout<L>): boolean {
  if (press.start === null) return false
  const { links, reach } = layout(press.at)
  const index = linkAt(press.at, links, reach)
  const chosen = index === null ? undefined : links[index]
  return chosen !== undefined && chosen.id === press.start.link && chosen.destination === press.start.destination
}

/**
 * What a click does besides what the browser does with it. The click itself always stands: it goes
 * where the browser sent it, and this adds one thing, a click on a link.
 *
 * A click that names a link or a control stands alone. A trusted click that names neither, a click on
 * plain text, also opens a link when a press that `opensByRule` pressed that link's words or the room
 * beside them: the press did not move beyond the slop; the click has a detail of 1, comes after the
 * pointer's up and within `CLICK_WITHIN` of it, and lies within `CLICK_AWAY` of the press, since the
 * engine reports the point of the same tap, rounded or moved toward a nearby link; and the
 * nearest-words rule, run again at the press's own point in the layout as it is now, names the same
 * element, opening the same destination, as it did at the press's start (`keepsPress`). For a touch or
 * a pen, the look at the press and the open at the click are therefore one function of one point. The
 * press is the record of the latest primary pointer down: a later press, or a pointer cancel, leaves
 * none.
 *
 * `layout` is read only when the other conditions hold, at the press's point.
 */
export function decide<L>(press: Press<L> | null, click: Click, layout: (at: Point) => Layout<L>): Decision<L> {
  if (click.names !== 'neither' || !click.trusted || click.detail !== 1) return STAND
  if (press === null || !opensByRule(press.pointerType)) return STAND
  if (press.moved || press.start === null || press.upAt === null) return STAND
  if (click.at < press.upAt || click.at - press.upAt > CLICK_WITHIN) return STAND
  if (Math.hypot(click.point.x - press.at.x, click.point.y - press.at.y) > CLICK_AWAY) return STAND
  return keepsPress(press, layout) ? { kind: 'open', link: press.start.link } : STAND
}
