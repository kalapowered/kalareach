/**
 * What a raw terminal view sends the program, as the page works it out: the session's cell under
 * the pointer, drawn through the window of the frame the page shows; the wheel's turns, a row of
 * pixels each; the rows a finger has crossed; and the one shape native code reads, which the
 * scripted host holds the page to.
 */

import { describe, expect, it } from 'vitest'

import { fakeHost, readTerminalInput, terminalScreen } from '../src/host/fake'
import type { TerminalScreen, TerminalView, TerminalViewState } from '../src/host/port'
import { cellAt, cellUnder, dragRows, MAX_TURNS, wheelPixels, wheelTurns } from '../src/terminal/input'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** Gives `element` the box a browser would report for it, transforms included. */
function laidOut(element: HTMLElement, box: { x: number; y: number; width: number; height: number }): HTMLElement {
  Object.defineProperty(element, 'getBoundingClientRect', { value: () => DOMRect.fromRect(box) })
  return element
}

describe("the session's cell under the pointer (KR-REQ-08.76)", () => {
  it('maps a cell of the frame through the window it is drawn for', () => {
    // A window of 10 by 4 at column 3 and line 2 of the main session, 80 by 8.
    const screen = terminalScreen(SESSION_MAIN, { columns: 10, rows: 4 }, { column: 3, line: 2, above: 0 })
    expect(cellAt(screen, 0, 0)).toEqual({ column: 3, line: 2 })
    expect(cellAt(screen, 9, 3)).toEqual({ column: 12, line: 5 })
    for (const [x, y] of [
      [10, 0],
      [-1, 0],
      [0, 4],
      [0, -1],
      [0.5, 0]
    ] as const) {
      expect(cellAt(screen, x, y), `${x}, ${y}`).toBeNull()
    }
  })

  it('names no cell on a row of the history, whose rows are not the live screen', () => {
    const screen = terminalScreen(SESSION_MAIN, { columns: 10, rows: 4 }, { column: 0, line: 0, above: 2 })
    expect(cellAt(screen, 4, 0)).toBeNull()
    expect(cellAt(screen, 4, 1)).toBeNull()
    expect(cellAt(screen, 4, 2)).toEqual({ column: 4, line: 0 })
    expect(cellAt(screen, 4, 3)).toEqual({ column: 4, line: 1 })
  })

  it("names no cell a window larger than the session draws blank, outside the session's grid", () => {
    const small = terminalScreen(SESSION_MAIN, { columns: 80, rows: 8 })
    const larger: TerminalScreen = { ...small, window: { ...small.window, columns: 100, rows: 10 } }
    expect(cellAt(larger, 79, 7)).toEqual({ column: 79, line: 7 })
    expect(cellAt(larger, 80, 0)).toBeNull()
    expect(cellAt(larger, 0, 8)).toBeNull()
  })

  it('measures from the grid content box as the page shows it, its shift counted once', () => {
    const screen = terminalScreen(SESSION_MAIN, { columns: 40, rows: 8 })
    const cell = { width: 8, height: 16 }
    const surface = laidOut(document.createElement('div'), { x: 0, y: 0, width: 336, height: 160 })
    // The grid has eight pixels of padding, and is drawn two rows up by the moves that wait: the
    // box a browser reports is already moved.
    const grid = document.createElement('pre')
    grid.style.padding = '8px'
    laidOut(grid, { x: 0, y: -32, width: 336, height: 144 })
    // Five cells across and three down from the content box's corner, a pixel inside the cell.
    expect(cellUnder({ x: 8 + 5 * 8 + 1, y: -32 + 8 + 3 * 16 + 1 }, grid, surface, screen, cell)).toEqual({
      column: 5,
      line: 3
    })
    // In the padding, and above the surface's visible box, nothing is under the pointer.
    expect(cellUnder({ x: 4, y: 40 }, grid, surface, screen, cell)).toBeNull()
    expect(cellUnder({ x: 8 + 5 * 8 + 1, y: -2 }, grid, surface, screen, cell)).toBeNull()
  })
})

describe('the wheel counted in turns (KR-REQ-13.18)', () => {
  it('counts a turn for each row of pixels, and carries the part of a row to the next event', () => {
    expect(wheelTurns(0, 48, 16)).toEqual({ turns: 3, rest: 0 })
    const part = wheelTurns(0, 10, 16)
    expect(part).toEqual({ turns: 0, rest: 10 })
    expect(wheelTurns(part.rest, 6, 16)).toEqual({ turns: 1, rest: 0 })
    expect(wheelTurns(0, -40, 16)).toEqual({ turns: -2, rest: -8 })
  })

  it('turns at most as often as one input carries, and keeps only the part of a row', () => {
    expect(wheelTurns(0, 16 * (MAX_TURNS + 50) + 4, 16)).toEqual({ turns: MAX_TURNS, rest: 4 })
    expect(wheelTurns(0, -16 * (MAX_TURNS + 50), 16)).toEqual({ turns: -MAX_TURNS, rest: 0 })
    expect(wheelTurns(5, 40, 0)).toEqual({ turns: 0, rest: 0 })
  })

  it('reads a wheel that counts in lines or pages in rows of the grid', () => {
    expect(wheelPixels({ deltaY: 3, deltaMode: 1 }, 16, 24)).toBe(48)
    expect(wheelPixels({ deltaY: -1, deltaMode: 2 }, 16, 24)).toBe(-16 * 24)
    expect(wheelPixels({ deltaY: 30, deltaMode: 0 }, 16, 24)).toBe(30)
  })

  it('counts the rows a finger crosses, a finger dragged up turning the wheel towards the person', () => {
    expect(dragRows(200, 160, 16)).toBe(2)
    expect(dragRows(200, 217, 16)).toBe(-1)
    expect(dragRows(200, 190, 16)).toBe(0)
    expect(dragRows(200, 100, 0)).toBe(0)
  })
})

describe('the scripted host reads input as native code does (KR-REQ-10.01)', () => {
  it("refuses the page's old requests and anything else that is not the view's shape", () => {
    for (const shape of [
      { session_id: SESSION_MAIN, wheel: { lines: 3 } },
      { session_id: SESSION_MAIN, bytes: '\u001b[A' },
      { kind: 'scroll', take: 1 },
      { kind: 'take' },
      { kind: 'take', number: -1 },
      { kind: 'take', number: 1.5 },
      { kind: 'keys', take: 1, keys: 'a', session_id: SESSION_MAIN },
      { kind: 'keys', take: 1, keys: '' },
      { kind: 'keys', take: 1, keys: 'x'.repeat(64 * 1024 + 1) },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 0, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1025, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: -1, line: 0, turns: 1, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1, shift: 'no', alt: false, control: false },
      null,
      'take'
    ]) {
      expect(typeof readTerminalInput(shape), JSON.stringify(shape)).toBe('string')
    }
    expect(readTerminalInput({ kind: 'release', number: 4 })).toEqual({ kind: 'release', number: 4 })
    expect(
      readTerminalInput({ kind: 'wheel', take: 1, column: 2, line: 3, turns: -1024, shift: true, alt: false, control: false })
    ).toEqual({ kind: 'wheel', take: 1, column: 2, line: 3, turns: -1024, shift: true, alt: false, control: false })
  })

  it('refuses a wheel turn or keys while the view does not control the program, and takes them while it does', async () => {
    const { port, controls } = fakeHost()
    const states: TerminalViewState[] = []
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, (state) => {
      states.push(state)
    })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    await expect(view.input({ kind: 'keys', take: 0, keys: 'q' })).rejects.toMatchObject({ code: 'LEASE_LOST' })
    await expect(
      // A shape the page used to send, which no type allows now.
      view.input({ session_id: SESSION_MAIN, bytes: 'q' } as never)
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
    await view.input({ kind: 'take', number: 1 })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    expect(controls.terminalViews[0]?.control).toEqual({ number: 1, state: 'controlling', ended: null })
    await expect(view.input({ kind: 'keys', take: 2, keys: 'q' })).rejects.toMatchObject({ code: 'LEASE_LOST' })
    await view.input({ kind: 'keys', take: 1, keys: 'q' })
    expect(controls.terminalViews[0]?.inputs).toEqual([
      { kind: 'take', number: 1 },
      { kind: 'keys', take: 1, keys: 'q' }
    ])
    // The change of control reaches the page once the view has taken the request.
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    const last = states.at(-1)
    expect(last !== undefined && last.state !== 'ended' ? last.control.state : null).toBe('controlling')
  })

  it('refuses any input once the view has ended, as native code does, and records none of it', async () => {
    const { port, controls } = fakeHost()
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, () => {})
    await view.input({ kind: 'take', number: 1 })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    await view.close()
    for (const input of [
      { kind: 'keys', take: 1, keys: 'q' },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1, shift: false, alt: false, control: false },
      { kind: 'take', number: 2 },
      { kind: 'release', number: 3 }
    ] as const) {
      await expect(view.input(input), input.kind).rejects.toMatchObject({ code: 'LEASE_LOST' })
    }
    expect(controls.terminalViews[0]?.inputs).toEqual([{ kind: 'take', number: 1 }])
  })
})
