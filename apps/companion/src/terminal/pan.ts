/**
 * Moving a raw terminal view's window, as the page sees it.
 *
 * The page never decides where the window is. Native code settles each move on the screen the
 * host names for it and tells the page a move is settled only with a screen that holds it. So the
 * page draws the newest screen it was sent, shifted to where the moves it sent and has not yet been
 * told are settled will put the window: replayed in order from that screen's own place, each held
 * to the screen's room, as native code applies them. The shift answers a move at once, and the
 * next screen replaces the shifted frame in one write.
 *
 * A drag follows the pointer one to one, part cells included, and sends a move for each whole cell
 * it crosses. A wheel sends whole cells and carries the part to its next turn. Past a limit a drag
 * resists, the further the harder, and nothing is sent. Nothing here animates: following a finger
 * is tracking, and a drag that ends drops what it had not sent at once.
 */

import type { TerminalMove, TerminalRoom, TerminalScreen } from '../host/port'

/** A movement of the window, in cells: to the right and down when positive. */
export interface Cells {
  readonly across: number
  readonly down: number
}

/** No movement. */
export const STILL: Cells = { across: 0, down: 0 }

/** A point on the page, in pixels. */
export interface Point {
  readonly x: number
  readonly y: number
}

/** One cell's size in pixels. */
export interface CellSize {
  readonly width: number
  readonly height: number
}

function clamp(value: number, lowest: number, highest: number): number {
  return Math.min(highest, Math.max(lowest, value))
}

/** A whole number of cells toward zero, never negative zero. */
function whole(cells: number): number {
  const truncated = Math.trunc(cells)
  return truncated === 0 ? 0 : truncated
}

/** The nearest whole number of cells, a half going away from zero, so both ways round alike. */
function nearest(cells: number): number {
  const rounded = cells < 0 ? -Math.round(-cells) : Math.round(cells)
  return rounded === 0 ? 0 : rounded
}

/** A room that has never been measured, or a malformed one, holds nothing. */
function held(value: unknown): number {
  const number = Math.trunc(Number(value))
  return Number.isFinite(number) && number > 0 ? number : 0
}

/**
 * Where the window will be, from where `screen` draws it, once `moves` have been applied in order,
 * each held to the screen's room, as native code applies them. A return takes a window above the
 * live screen to its first line, at its column, and leaves one on the live screen where it is.
 */
export function replay(screen: TerminalScreen, moves: readonly TerminalMove[]): Cells {
  const room = screen.room
  const up = held(room.up)
  const down = held(room.down)
  const left = held(room.left)
  const right = held(room.right)
  // Where the frame starts, measured from the live screen's first line: above it is below zero.
  const start = held(screen.window.above) > 0 ? -held(screen.window.above) : held(screen.window.line)
  let across = 0
  let rows = 0
  for (const move of moves) {
    if ('live' in move) {
      if (start + rows < 0) rows = -start
      continue
    }
    across = clamp(across + move.across, -left, right)
    rows = clamp(rows + move.down, -up, down)
  }
  return { across: across === 0 ? 0 : across, down: rows === 0 ? 0 : rows }
}

/** How far the window can still move each way once `moves` have been applied. */
export function roomLeft(screen: TerminalScreen, moves: readonly TerminalMove[]): TerminalRoom {
  const shift = replay(screen, moves)
  return {
    up: held(screen.room.up) + shift.down,
    down: held(screen.room.down) - shift.down,
    left: held(screen.room.left) + shift.across,
    right: held(screen.room.right) - shift.across
  }
}

/** `asked`, held to `room`. */
export function within(asked: Cells, room: TerminalRoom): Cells {
  const across = clamp(whole(asked.across), -room.left, room.right)
  const down = clamp(whole(asked.down), -room.up, room.down)
  return { across: across === 0 ? 0 : across, down: down === 0 ? 0 : down }
}

/**
 * How far a drag that has gone `overshoot` pixels past a limit is drawn past it: less the further
 * it goes, and never as far as `dimension`, the size of what it is dragged across.
 */
export function resisted(overshoot: number, dimension: number): number {
  if (dimension <= 0) return 0
  const constant = 0.55
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot))
}

/** One drag of the window, from where the pointer went down. */
export interface Drag {
  /** Where the pointer was when this drag began, or began again after the cell size changed. */
  readonly origin: Point
  /** The cells this drag has sent. */
  readonly sent: Cells
}

/** A drag that begins with the pointer at `at`. */
export function beginDrag(at: Point): Drag {
  return { origin: at, sent: STILL }
}

/** What a drag does when its pointer reaches a point. */
export interface DragStep {
  /** The whole cells to send now, which may be none. */
  readonly send: Cells
  /** How far the drawn frame is moved for the part not sent, in pixels, resisting past a limit. */
  readonly offset: Point
  /** The drag after this step. */
  readonly drag: Drag
}

/** The window's movement, in cells, that a pointer's travel from the drag's origin asks for. */
function asked(drag: Drag, at: Point, cell: CellSize): Cells {
  // The frame follows the pointer, so the window moves the other way.
  return {
    across: cell.width > 0 ? -(at.x - drag.origin.x) / cell.width : 0,
    down: cell.height > 0 ? -(at.y - drag.origin.y) / cell.height : 0
  }
}

/** The part of one axis's movement not yet sent, as drawn, in pixels of the frame's movement. */
function drawnPart(unsent: number, lowest: number, highest: number, cell: number, dimension: number): number {
  const inside = clamp(unsent, lowest, highest)
  const past = (unsent - inside) * cell
  const drawn = -(inside * cell + resisted(past, dimension))
  return drawn === 0 ? 0 : drawn
}

/**
 * The drag after its pointer reached `at`: the whole cells to send, held to `room` (the room the
 * window has once every unsettled move is applied), and the part not sent, drawn one to one inside
 * the room and resisting past it. `surface` is the size the frame is dragged across.
 */
export function dragTo(
  drag: Drag,
  at: Point,
  cell: CellSize,
  room: TerminalRoom,
  surface: { readonly width: number; readonly height: number }
): DragStep {
  const wanted = asked(drag, at, cell)
  const unsent = { across: wanted.across - drag.sent.across, down: wanted.down - drag.sent.down }
  const send = within(unsent, room)
  const sent = { across: drag.sent.across + send.across, down: drag.sent.down + send.down }
  const rest = { across: unsent.across - send.across, down: unsent.down - send.down }
  return {
    send,
    offset: {
      x: drawnPart(rest.across, -(room.left + send.across), room.right - send.across, cell.width, surface.width),
      y: drawnPart(rest.down, -(room.up + send.down), room.down - send.down, cell.height, surface.height)
    },
    drag: { origin: drag.origin, sent }
  }
}

/**
 * What a drag sends when its pointer is released at `at`: only the cells rounding the rest to the
 * nearest whole cell adds, held to `room`. Every other end of a drag sends nothing: the part not
 * sent is dropped, and the moves already sent stay until they settle.
 */
export function releaseDrag(drag: Drag, at: Point, cell: CellSize, room: TerminalRoom): Cells {
  const wanted = asked(drag, at, cell)
  return within(
    {
      across: nearest(wanted.across - drag.sent.across),
      down: nearest(wanted.down - drag.sent.down)
    },
    room
  )
}

/** A drag in progress: its pointer, the drag, the cell it is measured in, and its last point. */
export interface HeldDrag {
  readonly pointer: number
  readonly drag: Drag
  readonly cell: CellSize
  readonly last: Point
}

/**
 * `held` begun again in `cell`, after a zoom step: from the pointer's last point, its part not
 * sent dropped, and the moves it sent kept, for they are the page's moves now.
 */
export function restartDrag(held: HeldDrag, cell: CellSize): HeldDrag {
  return { pointer: held.pointer, drag: beginDrag(held.last), cell, last: held.last }
}

/** The part of a wheel's movement not yet a whole cell, in pixels. */
export interface WheelRest {
  readonly across: number
  readonly down: number
}

/** A wheel that has not turned. */
export const WHEEL_AT_REST: WheelRest = { across: 0, down: 0 }

/**
 * One turn of the wheel: `pixels` more of the window's movement, in cells of `cell`, held to
 * `room`. The part short of a whole cell is carried to the next turn, unless it points past a limit
 * the window has reached, before this turn or after it, so a turn the other way moves at once; what
 * a limit refused is dropped.
 */
export function wheelTurn(
  rest: WheelRest,
  pixels: { readonly across: number; readonly down: number },
  cell: CellSize,
  room: TerminalRoom
): { readonly send: Cells; readonly rest: WheelRest } {
  // Whether a part points past a limit, with `before` cells of room back and `after` ahead.
  const pastLimit = (part: number, before: number, after: number): boolean =>
    (part > 0 && after <= 0) || (part < 0 && before <= 0)
  // A part carried toward a limit that something else has since reached is gone.
  const across = (pastLimit(rest.across, room.left, room.right) ? 0 : rest.across) + pixels.across
  const down = (pastLimit(rest.down, room.up, room.down) ? 0 : rest.down) + pixels.down
  const wholeAcross = cell.width > 0 ? whole(across / cell.width) : 0
  const wholeDown = cell.height > 0 ? whole(down / cell.height) : 0
  const send = within({ across: wholeAcross, down: wholeDown }, room)
  const kept = (part: number, refused: boolean, before: number, after: number): number =>
    refused || pastLimit(part, before, after) ? 0 : part
  return {
    send,
    rest: {
      across: kept(
        across - wholeAcross * cell.width,
        send.across !== wholeAcross,
        room.left + send.across,
        room.right - send.across
      ),
      down: kept(
        down - wholeDown * cell.height,
        send.down !== wholeDown,
        room.up + send.down,
        room.down - send.down
      )
    }
  }
}
