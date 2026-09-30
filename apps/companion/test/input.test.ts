/**
 * What a raw terminal view sends the program, as the page works it out: the session's cell under
 * the pointer, drawn through the window of the frame the page shows; the wheel's turns, a row of
 * pixels each; the rows a finger has crossed; and the one shape native code reads, which the
 * scripted host holds the page to.
 */

import { describe, expect, it } from 'vitest'

import refusals from './fixtures/terminal-input-refusals.json'

import { fakeHost, readTerminalInput, terminalScreen } from '../src/host/fake'
import type { TerminalScreen, TerminalView, TerminalViewState } from '../src/host/port'
import { cellAt, cellUnder, dragRows, MAX_TURNS, wheelPixels, wheelTurns } from '../src/terminal/input'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The q key pressed under the page's take 1. */
const Q = {
  kind: 'key',
  take: 1,
  key: 'q',
  base: 'q',
  keypad: null,
  shift: false,
  alt: false,
  control: false,
  caps_lock: false,
  num_lock: false,
  event: 'press'
} as const

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

/** A key input named as native code reads one, with anything `over` gives. */
function keyShape(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'key',
    take: 1,
    key: 'a',
    base: 'a',
    keypad: null,
    shift: false,
    alt: false,
    control: false,
    caps_lock: false,
    num_lock: false,
    event: 'press',
    ...over
  }
}

describe('the scripted host reads input as native code does (KR-REQ-10.01)', () => {
  it("refuses the page's old requests and anything else that is not the view's shape", () => {
    for (const shape of [
      { session_id: SESSION_MAIN, wheel: { lines: 3 } },
      { session_id: SESSION_MAIN, bytes: '\u001b[A' },
      { kind: 'scroll', take: 1 },
      { kind: 'take' },
      { kind: 'take', number: -1 },
      { kind: 'take', number: 1.5 },
      // Bytes the page spells are no input at all.
      { kind: 'keys', take: 1, keys: 'a' },
      keyShape({ session_id: SESSION_MAIN }),
      keyShape({ key: '' }),
      keyShape({ key: '\u001b' }),
      keyShape({ key: '\u009b' }),
      keyShape({ key: 'Arrow Up' }),
      keyShape({ key: 'x'.repeat(33) }),
      keyShape({ base: 'ab' }),
      keyShape({ base: '\t' }),
      keyShape({ keypad: 'Numpad10' }),
      keyShape({ event: 'hold' }),
      keyShape({ shift: 1 }),
      keyShape({ take: -1 }),
      { kind: 'key', take: 1, key: 'a', event: 'press' },
      { kind: 'text', take: 1, text: '' },
      { kind: 'text', take: 1, text: 'ls\r' },
      { kind: 'text', take: 1, text: 'a\tb' },
      { kind: 'text', take: 1, text: 'x'.repeat(64 * 1024 + 1) },
      { kind: 'text', take: 1, text: 'a', keys: 'a' },
      { kind: 'paste', take: 1, text: '' },
      { kind: 'paste', take: 1, text: 'x'.repeat(64 * 1024 - 11) },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 0, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1025, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: -1, line: 0, turns: 1, shift: false, alt: false, control: false },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1, shift: 'no', alt: false, control: false },
      // Past what the field's integer type holds: a take's number is a u64, a cell's column a u32.
      { kind: 'take', number: 2 ** 64 },
      { kind: 'wheel', take: 1, column: 2 ** 32, line: 0, turns: 1, shift: false, alt: false, control: false },
      null,
      'take'
    ]) {
      expect(typeof readTerminalInput(shape), JSON.stringify(shape)).toBe('string')
    }
    expect(readTerminalInput({ kind: 'release', number: 4 })).toEqual({ kind: 'release', number: 4 })
    // A u64 past Number.MAX_SAFE_INTEGER is read, and so is the largest u32.
    expect(readTerminalInput({ kind: 'take', number: 2 ** 53 })).toEqual({ kind: 'take', number: 2 ** 53 })
    expect(
      readTerminalInput({ kind: 'wheel', take: 1, column: 2 ** 32 - 1, line: 0, turns: 1, shift: false, alt: false, control: false })
    ).toMatchObject({ kind: 'wheel', column: 2 ** 32 - 1 })
    expect(
      readTerminalInput({ kind: 'wheel', take: 1, column: 2, line: 3, turns: -1024, shift: true, alt: false, control: false })
    ).toEqual({ kind: 'wheel', take: 1, column: 2, line: 3, turns: -1024, shift: true, alt: false, control: false })
  })

  it('refuses an input in the words native code refuses it in, and reads what it reads', () => {
    // The cases and their words are native code's own, read from its decoder by a test of its own:
    // an input it refuses is refused here in the same words, and one it reads is read.
    expect(refusals.length).toBeGreaterThan(100)
    for (const each of refusals) {
      const read = readTerminalInput(each.input)
      if (each.words === null) expect(typeof read, JSON.stringify(each.input)).toBe('object')
      else expect(read, JSON.stringify(each.input)).toBe(each.words)
    }
  })

  it('refuses an input a view was sent in the command layer\'s words, as a refusal that asks nothing more', async () => {
    const { port } = fakeHost()
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, () => {})
    const wheel = { kind: 'wheel', take: 1, column: 0, line: 0, turns: 0, shift: false, alt: false, control: false }
    await expect(view.input(wheel as never)).rejects.toEqual({
      code: 'INVALID_ARGUMENT',
      message:
        "those are not this operation's parameters: a wheel turns between 1 and 1024 times either way, not 0",
      user_action: 'nothing'
    })
  })

  it('reads a key named as one character or a name, text with no control character, and a paste as it is', () => {
    for (const shape of [
      keyShape(),
      keyShape({ key: 'é', base: null }),
      keyShape({ key: 'End', base: null, keypad: 'Numpad1', event: 'release', num_lock: true }),
      keyShape({ key: 'F24', base: null, event: 'repeat', control: true, caps_lock: true })
    ]) {
      expect(readTerminalInput(shape), JSON.stringify(shape)).toEqual(shape)
    }
    // Native code reads a key's unshifted character and keypad key left out as none.
    const bare = keyShape()
    delete bare['base']
    delete bare['keypad']
    expect(readTerminalInput(bare)).toEqual(keyShape({ base: null }))
    expect(readTerminalInput({ kind: 'text', take: 2, text: '日本語' })).toEqual({ kind: 'text', take: 2, text: '日本語' })
    const most = 'x'.repeat(64 * 1024 - 12)
    expect(readTerminalInput({ kind: 'paste', take: 2, text: most })).toEqual({ kind: 'paste', take: 2, text: most })
    expect(readTerminalInput({ kind: 'paste', take: 2, text: 'one\ntwo\t\u001b' })).toEqual({
      kind: 'paste',
      take: 2,
      text: 'one\ntwo\t\u001b'
    })
  })

  it('refuses a wheel turn or a key while the view does not control the program, and takes them while it does', async () => {
    const { port, controls } = fakeHost()
    const states: TerminalViewState[] = []
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, (state) => {
      states.push(state)
    })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    await expect(view.input({ ...Q, take: 0 })).rejects.toMatchObject({ code: 'LEASE_LOST' })
    await expect(
      // A shape the page used to send, which no type allows now.
      view.input({ session_id: SESSION_MAIN, bytes: 'q' } as never)
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
    await view.input({ kind: 'take', number: 1 })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    expect(controls.terminalViews[0]?.control).toEqual({ number: 1, state: 'controlling', ended: null })
    await expect(view.input({ ...Q, take: 2 })).rejects.toMatchObject({ code: 'LEASE_LOST' })
    await view.input(Q)
    await view.input({ kind: 'text', take: 1, text: 'ls' })
    await view.input({ kind: 'paste', take: 1, text: 'echo hi\n' })
    expect(controls.terminalViews[0]?.inputs).toEqual([
      { kind: 'take', number: 1 },
      Q,
      { kind: 'text', take: 1, text: 'ls' },
      { kind: 'paste', take: 1, text: 'echo hi\n' }
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
      Q,
      { kind: 'text', take: 1, text: 'q' },
      { kind: 'paste', take: 1, text: 'q' },
      { kind: 'wheel', take: 1, column: 0, line: 0, turns: 1, shift: false, alt: false, control: false },
      { kind: 'take', number: 2 },
      { kind: 'release', number: 3 }
    ] as const) {
      await expect(view.input(input), input.kind).rejects.toMatchObject({ code: 'LEASE_LOST' })
    }
    expect(controls.terminalViews[0]?.inputs).toEqual([{ kind: 'take', number: 1 }])
  })

  it("refuses a key, text or a paste before the view holds the session's screen, as native code does, and keeps control", async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, () => {})
    const held = controls.terminalViews[0]
    held?.attach()
    await view.input({ kind: 'take', number: 1 })
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
    expect(held?.control.state).toBe('controlling')
    await expect(view.input(Q)).rejects.toMatchObject({
      code: 'INPUT_INCOMPATIBLE',
      message: "That key did not reach the program: the view is waiting for the session's screen."
    })
    await expect(view.input({ kind: 'text', take: 1, text: 'q' })).rejects.toMatchObject({
      code: 'INPUT_INCOMPATIBLE',
      message: "That text did not reach the program: the view is waiting for the session's screen."
    })
    await expect(view.input({ kind: 'paste', take: 1, text: 'q' })).rejects.toMatchObject({
      code: 'INPUT_INCOMPATIBLE',
      message: "That paste did not reach the program: the view is waiting for the session's screen."
    })
    expect(held?.control.state).toBe('controlling')
    // The wheel needs no screen to be taken: it reaches no program without one.
    await view.input({ kind: 'wheel', take: 1, column: 0, line: 0, turns: 1, shift: false, alt: false, control: false })
    held?.show()
    await view.input(Q)
    // And after the host's reset, until the next screen, again.
    held?.wait()
    await expect(view.input(Q)).rejects.toMatchObject({ code: 'INPUT_INCOMPATIBLE' })
    expect(held?.inputs.filter((input) => input.kind === 'key')).toEqual([Q])
  })
})

describe("the scripted host reads a view's opening, size and moves as native code does", () => {
  /** What the command layer says of an argument it cannot decode, before native code sees the call. */
  const undecodable = (command: string, key: string) => new RegExp(`^invalid args \`${key}\` for command \`${command}\`: `)

  /** Sizes of whole numbers outside a terminal's bounds, which native code refuses in its words. */
  const outOfBounds: readonly [{ columns: number; rows: number }, string][] = [
    [{ columns: 0, rows: 24 }, 'columns 0 must be between 1 and 2048'],
    [{ columns: 2049, rows: 1 }, 'columns 2049 must be between 1 and 2048'],
    [{ columns: 80, rows: 0 }, 'rows 0 must be between 1 and 1024'],
    [{ columns: 80, rows: 1025 }, 'rows 1025 must be between 1 and 1024'],
    // Within each bound on its own, and over the cells a terminal may have.
    [{ columns: 1024, rows: 257 }, 'cells 263168 must not exceed 262144'],
    // A whole number past Number.MAX_SAFE_INTEGER is one the decoder reads, and the bound refuses.
    [{ columns: 2 ** 53, rows: 1 }, 'columns 9007199254740992 must be between 1 and 2048']
  ]

  /** Sizes the command layer cannot decode, with the argument it names. */
  const unreadable: readonly [unknown, string][] = [
    [{ columns: 80.5, rows: 24 }, 'columns'],
    [{ columns: -1, rows: 24 }, 'columns'],
    [{ columns: '80', rows: 24 }, 'columns'],
    [{ columns: 2 ** 64, rows: 24 }, 'columns'],
    [{ columns: 80, rows: Number.NaN }, 'rows'],
    [{ columns: 80 }, 'rows']
  ]

  it('refuses to open a view native code would not open, in the order it reads the call, and opens none', async () => {
    const { port, controls } = fakeHost()
    for (const sessionId of [
      'session-1',
      '8a7b6c50-22bb-4c3d-8e4f-00000000010',
      '8a7b6c50x22bb-4c3d-8e4f-000000000101',
      'zzzzzzzz-22bb-4c3d-8e4f-000000000101'
    ]) {
      await expect(port.openTerminalView(sessionId, { columns: 80, rows: 8 }, () => {}), sessionId).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
        message: 'that is not a session identifier'
      })
    }
    for (const [grid, words] of outOfBounds) {
      await expect(port.openTerminalView(SESSION_MAIN, grid, () => {}), JSON.stringify(grid)).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
        message: `that is not a terminal's size: ${words}`
      })
    }
    for (const [grid, key] of unreadable) {
      await expect(port.openTerminalView(SESSION_MAIN, grid as never, () => {}), JSON.stringify(grid)).rejects.toMatch(
        undecodable('terminal_view_open', key)
      )
    }
    // Every argument is decoded before the session identifier is parsed.
    await expect(port.openTerminalView('session-1', { columns: 80.5, rows: 24 }, () => {})).rejects.toMatch(
      undecodable('terminal_view_open', 'columns')
    )
    // No size at all: the port cannot read one, as the desktop's cannot, and says so as a refusal.
    await expect(port.openTerminalView(SESSION_MAIN, null as never, () => {})).rejects.toThrow(TypeError)
    expect(controls.terminalViews).toHaveLength(0)
    // The largest a terminal may be, 262,144 cells, opens, and so does an identifier in capitals.
    await port.openTerminalView(SESSION_MAIN, { columns: 2048, rows: 128 }, () => {})
    await port.openTerminalView(SESSION_MAIN.toUpperCase(), { columns: 80, rows: 8 }, () => {})
    expect(controls.terminalViews).toHaveLength(2)
  })

  it('refuses a size or a move native code would not take, and takes neither', async () => {
    const { port, controls } = fakeHost()
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, () => {})
    for (const [grid, words] of outOfBounds) {
      await expect(view.resize(grid), JSON.stringify(grid)).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
        message: `that is not a terminal's size: ${words}`
      })
    }
    for (const [grid, key] of unreadable) {
      await expect(view.resize(grid as never), JSON.stringify(grid)).rejects.toMatch(undecodable('terminal_view_resize', key))
    }
    for (const [move, key] of [
      [{ number: -1, across: 1, down: 0 }, 'number'],
      [{ number: 1.5, across: 1, down: 0 }, 'number'],
      [{ number: 2 ** 64, live: true }, 'number'],
      [{ across: 1, down: 0 }, 'number'],
      [{ number: 1, across: 0.5, down: 0 }, 'across'],
      [{ number: 1, across: Number.NaN, down: 0 }, 'across'],
      [{ number: 1, across: 2 ** 63, down: 0 }, 'across'],
      [{ number: 1, down: 1 }, 'across'],
      [{ number: 1, across: 1 }, 'down']
    ] as const) {
      await expect(view.move(move as never), JSON.stringify(move)).rejects.toMatch(undecodable('terminal_view_move', key))
    }
    expect(() => view.resize(null as never)).toThrow(TypeError)
    expect(() => view.move(null as never)).toThrow(TypeError)
    expect(controls.terminalViews[0]?.grids).toEqual([{ columns: 80, rows: 8 }])
    expect(controls.terminalViews[0]?.moves).toEqual([])
    // What native code takes, the scripted host takes: whole numbers past Number.MAX_SAFE_INTEGER
    // among them, negative zero as zero, and a move with `live`, which the port sends as a return to
    // the live screen.
    await view.resize({ columns: 40, rows: 6 })
    await view.move({ number: 1, across: 2 ** 53, down: -(2 ** 53) })
    await view.move({ number: 2 ** 53, live: true })
    await view.move({ number: 2 ** 53 + 2, across: 3, down: 4, live: false } as never)
    await view.move({ number: -0, across: -0, down: 1 })
    expect(controls.terminalViews[0]?.grids).toEqual([
      { columns: 80, rows: 8 },
      { columns: 40, rows: 6 }
    ])
    expect(controls.terminalViews[0]?.moves).toEqual([
      { number: 1, across: 2 ** 53, down: -(2 ** 53) },
      { number: 2 ** 53, live: true },
      { number: 2 ** 53 + 2, live: true },
      { number: -0, across: -0, down: 1 }
    ])
  })

  it('words each refusal as the command layer or native code words it', async () => {
    const { port } = fakeHost()
    const view: TerminalView = await port.openTerminalView(SESSION_MAIN, { columns: 80, rows: 8 }, () => {})
    const said = async (call: Promise<unknown>): Promise<unknown> => call.then(() => 'taken', (refusal: unknown) => refusal)
    expect(await said(port.openTerminalView(1 as never, { columns: 80, rows: 8 }, () => {}))).toBe(
      'invalid args `sessionId` for command `terminal_view_open`: invalid type: integer `1`, expected a string'
    )
    for (const [grid, words] of [
      [{ columns: 80.5, rows: 24 }, 'invalid args `columns` for command `terminal_view_resize`: invalid type: floating point `80.5`, expected u64'],
      [{ columns: -1, rows: 24 }, 'invalid args `columns` for command `terminal_view_resize`: invalid value: integer `-1`, expected u64'],
      [{ columns: 80, rows: Number.NaN }, 'invalid args `rows` for command `terminal_view_resize`: invalid type: unit value, expected u64'],
      [{ columns: 80 }, 'invalid args `rows` for command `terminal_view_resize`: command terminal_view_resize missing required key rows']
    ] as const) {
      expect(await said(view.resize(grid as never)), JSON.stringify(grid)).toBe(words)
    }
    for (const [move, words] of [
      // Digits past 64 bits are a floating point number to the decoder, which writes an exponent from
      // 1e16 up and below 1e-5.
      [{ number: 2 ** 64, live: true }, 'invalid args `number` for command `terminal_view_move`: invalid type: floating point `1.8446744073709552e+19`, expected u64'],
      // JSON writes 2^63 as 9223372036854776000, an integer the decoder reads and i64 does not hold.
      [{ number: 1, across: 2 ** 63, down: 0 }, 'invalid args `across` for command `terminal_view_move`: invalid value: integer `9223372036854776000`, expected i64'],
      // The least i64 as JavaScript writes it is past 64 bits too.
      [{ number: 1, across: -(2 ** 63), down: 0 }, 'invalid args `across` for command `terminal_view_move`: invalid type: floating point `-9.223372036854776e+18`, expected i64'],
      [{ number: 1, across: 0, down: 1e21 }, 'invalid args `down` for command `terminal_view_move`: invalid type: floating point `1e+21`, expected i64']
    ] as const) {
      expect(await said(view.move(move as never)), JSON.stringify(move)).toBe(words)
    }
    expect(await said(view.resize({ columns: 1024, rows: 257 }))).toEqual({
      code: 'INVALID_ARGUMENT',
      message: "that is not a terminal's size: cells 263168 must not exceed 262144",
      user_action: expect.any(String) as string
    })
  })
})
