/**
 * The page's side of moving a raw terminal view's window: where the frame is drawn while moves
 * wait for their screen, how far the window can still go, and how a drag and a wheel turn into
 * whole cells.
 */

import { describe, expect, it } from 'vitest'

import { terminalScreen } from '../src/host/fake'
import type { TerminalMove, TerminalRoom, TerminalScreen } from '../src/host/port'
import {
  beginDrag,
  dragTo,
  releaseDrag,
  replay,
  resisted,
  roomLeft,
  STILL,
  WHEEL_AT_REST,
  wheelTurn,
  within
} from '../src/terminal/pan'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** A frame of the main session with its window at `window` and `room` to move. */
function frameAt(window: Partial<TerminalScreen['window']>, room: TerminalRoom): TerminalScreen {
  const base = terminalScreen(SESSION_MAIN, { columns: 10, rows: 2 })
  return { ...base, window: { ...base.window, ...window }, room }
}

const pan = (number: number, across: number, down: number): TerminalMove => ({ number, across, down })
const back = (number: number): TerminalMove => ({ number, live: true })

describe('where the frame is drawn while moves wait', () => {
  it('replays the moves in order, each held to the room, so a reversal at a limit keeps its path', () => {
    // Columns 0 to 10, the frame at 5: right 5, left 10, right 5 end at 5, not at 0.
    const frame = frameAt({ column: 5 }, { up: 0, down: 0, left: 5, right: 5 })
    expect(replay(frame, [pan(1, 5, 0), pan(2, -10, 0), pan(3, 5, 0)])).toEqual({ across: 0, down: 0 })
    // The same moves on a frame the host drew after a narrower session held it at 7 of 0 to 7.
    const narrower = frameAt({ column: 7 }, { up: 0, down: 0, left: 7, right: 0 })
    expect(replay(narrower, [pan(2, -10, 0), pan(3, 5, 0)])).toEqual({ across: -2, down: 0 })
  })

  it('takes a window in the history back to the live screen on a return, and leaves a live one', () => {
    const history = frameAt({ above: 12, line: 0 }, { up: 3, down: 16, left: 0, right: 0 })
    expect(replay(history, [pan(1, 0, -2), back(2)])).toEqual({ across: 0, down: 12 })
    const live = frameAt({ above: 0, line: 2 }, { up: 30, down: 2, left: 0, right: 0 })
    expect(replay(live, [pan(1, 0, 1), back(2)])).toEqual({ across: 0, down: 1 })
  })

  it('leaves the room the replayed moves did not use', () => {
    const frame = frameAt({ column: 5 }, { up: 4, down: 4, left: 5, right: 5 })
    expect(roomLeft(frame, [pan(1, 3, -1)])).toEqual({ up: 3, down: 5, left: 8, right: 2 })
    expect(within({ across: 9, down: -9 }, { up: 3, down: 5, left: 8, right: 2 })).toEqual({
      across: 2,
      down: -3
    })
  })
})

describe('a drag', () => {
  const cell = { width: 8, height: 16 }
  const surface = { width: 320, height: 160 }
  const room: TerminalRoom = { up: 2, down: 10, left: 0, right: 0 }

  it('follows the pointer one to one and sends a move for each whole cell it crosses', () => {
    const drag = beginDrag({ x: 100, y: 100 })
    // Down by half a row: the frame follows it, and nothing is sent.
    const half = dragTo(drag, { x: 100, y: 108 }, cell, room, surface)
    expect(half.send).toEqual(STILL)
    expect(half.offset).toEqual({ x: 0, y: 8 })
    // Down by a row and a half: the window goes up one row, and the half is drawn.
    const more = dragTo(half.drag, { x: 100, y: 124 }, cell, room, surface)
    expect(more.send).toEqual({ across: 0, down: -1 })
    expect(more.offset).toEqual({ x: 0, y: 8 })
    // On release, the nearest whole cell: the half rounds up to one more row.
    expect(releaseDrag(more.drag, { x: 100, y: 124 }, cell, roomLeftAfter(room, more.send))).toEqual({
      across: 0,
      down: -1
    })
  })

  it('resists past a limit, sends nothing past it, and releases only to the limit', () => {
    const drag = beginDrag({ x: 100, y: 100 })
    // Five rows down with two rows of history left: two go, the rest is drawn resisting.
    const past = dragTo(drag, { x: 100, y: 180 }, cell, room, surface)
    expect(past.send).toEqual({ across: 0, down: -2 })
    expect(past.offset.y).toBeGreaterThan(0)
    expect(past.offset.y).toBeLessThan(3 * cell.height)
    expect(past.offset.y).toBeCloseTo(resisted(3 * cell.height, surface.height), 6)
    expect(releaseDrag(past.drag, { x: 100, y: 180 }, cell, roomLeftAfter(room, past.send))).toEqual(STILL)
  })

  it('resists more the further it goes, and never as far as the surface', () => {
    expect(resisted(0, 160)).toBe(0)
    expect(resisted(40, 160)).toBeLessThan(40)
    expect(resisted(400, 160)).toBeLessThan(160)
    expect(resisted(-40, 160)).toBe(-resisted(40, 160))
  })
})

describe('a wheel', () => {
  const cell = { width: 8, height: 16 }
  const room: TerminalRoom = { up: 5, down: 5, left: 5, right: 5 }

  it('sends whole cells and carries the part to its next turn', () => {
    const first = wheelTurn(WHEEL_AT_REST, { across: 0, down: 24 }, cell, room)
    expect(first.send).toEqual({ across: 0, down: 1 })
    expect(first.rest).toEqual({ across: 0, down: 8 })
    const second = wheelTurn(first.rest, { across: 12, down: 8 }, cell, room)
    expect(second.send).toEqual({ across: 1, down: 1 })
    expect(second.rest).toEqual({ across: 4, down: 0 })
  })

  it('drops what a limit refused rather than carrying it against the limit', () => {
    const turned = wheelTurn(WHEEL_AT_REST, { across: 0, down: 16 * 9 }, cell, room)
    expect(turned.send).toEqual({ across: 0, down: 5 })
    expect(turned.rest).toEqual({ across: 0, down: 0 })
  })
})

/** The room left once `sent` has been sent from `room`. */
function roomLeftAfter(room: TerminalRoom, sent: { across: number; down: number }): TerminalRoom {
  return {
    up: room.up + sent.down,
    down: room.down - sent.down,
    left: room.left + sent.across,
    right: room.right - sent.across
  }
}
