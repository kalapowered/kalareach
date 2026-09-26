/**
 * The desktop's raw terminal view, drawn from the states native code publishes on its channel.
 *
 * The scripted host publishes what native code does for a view: attached with no screen, a
 * complete screen of cells, waiting after the host's reset, ended with the host's words. What is
 * checked is what the page makes of them: nothing drawn before the first screen, each piece drawn in
 * a box of its own at its cells, the last frame kept while the view waits, a view opened again
 * after it ended, closed when it is left, and never a state of one session drawn in another's view.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, terminalScreen } from '../src/host/fake'
import type { HostPort, TerminalScreen } from '../src/host/port'
import { ATTACHING, SLOW_MS, WAITING } from '../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

function open(
  port: HostPort,
  place: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }
): ReturnType<typeof render> {
  return render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** Lets everything already queued run, inside React's act. */
async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
  })
}

/**
 * Every line of the grid as a person reads it: each piece's text at its column, with a space for
 * each cell before it that no piece covers.
 */
function drawn(): string[] {
  const grid = screen.queryByTestId('terminal-grid')
  if (grid === null) return []
  const lines: string[] = []
  const reached: number[] = []
  for (const box of Array.from(grid.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]'))) {
    const line = Number(box.dataset.line)
    const column = Number(box.dataset.column)
    const gap = Math.max(0, column - (reached[line] ?? 0))
    lines[line] = `${lines[line] ?? ''}${' '.repeat(gap)}${box.textContent ?? ''}`
    reached[line] = column + Number(box.dataset.cells)
  }
  return Array.from({ length: Number(grid.dataset.rows) }, (_, index) => lines[index] ?? '')
}

/** Each piece's box as the grid places it: its line, column, cells and text. */
function boxes(): [number, number, number, string][] {
  return Array.from(document.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]')).map((box) => [
    Number(box.dataset.line),
    Number(box.dataset.column),
    Number(box.dataset.cells),
    box.textContent ?? ''
  ])
}

const presentation = () => screen.getByTestId('terminal-presentation').textContent
const position = () => screen.getByTestId('terminal-position').textContent

describe('the raw view draws the screen native code holds for it (KR-REQ-08.02)', () => {
  it('draws nothing before its first screen, and says it is attaching', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    expect(presentation()).toBe(ATTACHING)
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByTestId('palette-provenance')).toBeNull()
    expect(screen.queryByTestId('terminal-grid')).toBeNull()

    // Attached, with no screen yet: the host's sentence, and the words for waiting at once.
    act(() => {
      controls.terminalViews[0]?.attach()
    })
    expect(presentation()).toBe(
      "This view is shown a viewport because its client declared no terminal profile, so what the session's output would do on its terminal is not known."
    )
    expect(position()).toBe(WAITING)
    expect(screen.queryByTestId('terminal-grid')).toBeNull()
  })

  it('draws a published screen piece by piece, each at its own column', async () => {
    const { port } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const lines = drawn()
    expect(lines.slice(0, 6)).toEqual([
      '$ cargo test -p kr-client',
      '   Compiling kr-client v0.1.0',
      '    Finished test profile in 12.4s',
      // The run native code left blank keeps every later cell on its own column.
      'ok    done',
      'test result: ok. 143 passed',
      '$ '
    ])
    expect(screen.getByTestId('palette-provenance').textContent).toBe(
      "Palette: the creating terminal's colours"
    )
    expect(screen.getByTestId('terminal-size').textContent).toBe('80×8')
    expect(screen.getByTestId('substituted-count').textContent).toBe('1 left blank')
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
  })

  it('draws the bottom-right cell without scrolling the screen', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const full: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 4, rows: 2 }),
      window: { columns: 4, rows: 2, column: 0, line: 0, above: 0 },
      lines: [
        { row: '1', soft_wrapped: false, truncated: false, pieces: [piece(0, 'abcd')] },
        { row: '2', soft_wrapped: false, truncated: false, pieces: [piece(0, 'efgh')] }
      ],
      cursor: null
    }
    act(() => {
      controls.terminalViews[0]?.attach()
      controls.terminalViews[0]?.show(full)
    })
    expect(drawn().slice(0, 2)).toEqual(['abcd', 'efgh'])
  })

  it('draws each piece in a box of its own at exactly its cells, whatever its text', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const invisible = { ...piece(0, '').rendition, invisible: true }
    const mixed: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 16, rows: 2 }),
      window: { columns: 16, rows: 2, column: 0, line: 0, above: 0 },
      lines: [
        {
          row: '1',
          soft_wrapped: false,
          truncated: false,
          // A letter and its mark, a wide character in one cell, a mark with nothing before it,
          // native code's split of a man technologist, and a heart shown as a picture in one cell.
          pieces: [
            { ...piece(0, 'a\u{1ab0}'), cells: 1 },
            { ...piece(1, '\u{4e2d}'), cells: 1 },
            { ...piece(2, '\u{301}'), cells: 1 },
            { ...piece(3, '\u{1f468}\u{200d}'), cells: 2 },
            { ...piece(5, '\u{1f4bb}'), cells: 2 },
            { ...piece(7, '\u{2764}\u{fe0f}'), cells: 1 },
            piece(8, 'x')
          ]
        },
        {
          row: '2',
          soft_wrapped: false,
          truncated: false,
          // Two Arabic semicolons with marks, a Hebrew letter, and invisible text.
          pieces: [
            { ...piece(0, '\u{61b}\u{64b}'), cells: 1 },
            { ...piece(1, '\u{61b}\u{64c}'), cells: 1 },
            { ...piece(2, '\u{5e9}'), cells: 1 },
            { ...piece(3, '\u{4e2d}'), cells: 2, rendition: invisible },
            piece(5, 'y')
          ]
        }
      ],
      cursor: null
    }
    act(() => {
      controls.terminalViews[0]?.attach()
      controls.terminalViews[0]?.show(mixed)
    })
    expect(boxes()).toEqual([
      [0, 0, 1, 'a\u{1ab0}'],
      [0, 1, 1, '\u{4e2d}'],
      [0, 2, 1, '\u{301}'],
      [0, 3, 2, '\u{1f468}\u{200d}'],
      [0, 5, 2, '\u{1f4bb}'],
      [0, 7, 1, '\u{2764}\u{fe0f}'],
      [0, 8, 1, 'x'],
      [1, 0, 1, '\u{61b}\u{64b}'],
      [1, 1, 1, '\u{61b}\u{64c}'],
      [1, 2, 1, '\u{5e9}'],
      [1, 3, 2, '\u{4e2d}'],
      [1, 5, 1, 'y']
    ])
    // Each box sits at its own cells, laid out on its own and cut at its edges. With no layout
    // here, a cell is the grid's unmeasured one, 8 by 16 pixels.
    const placed = Array.from(document.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]'))
    for (const box of placed) {
      expect(box.style.left).toBe(`${Number(box.dataset.column) * 8}px`)
      expect(box.style.top).toBe(`${Number(box.dataset.line) * 16}px`)
      expect(box.style.width).toBe(`${Number(box.dataset.cells) * 8}px`)
      expect(box.style.position).toBe('absolute')
      expect(box.style.overflow).toBe('hidden')
      expect(box.style.unicodeBidi).toBe('isolate')
    }
    // The invisible text takes no colour, over its own cells.
    expect(placed[10]?.style.color).toBe('transparent')
  })

  it("colours a selection of the screen in the session's selection colours", async () => {
    const { port } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const grid = screen.getByTestId('terminal-grid')
    const rule = document.querySelector('style[data-terminal-selection]')?.textContent ?? ''
    expect(grid.classList.contains('kr-terminal-grid')).toBe(true)
    expect(rule).toContain('.kr-terminal-grid ::selection')
    expect(rule).toContain('background-color: #315e4a')
    expect(rule).toContain('color: #ffffff')
  })

  it("draws the session's cursor in its steady shape at its cell", async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const cursor = screen.getByTestId('terminal-cursor')
    expect([cursor.dataset.line, cursor.dataset.column, cursor.dataset.shape]).toEqual([
      '5',
      '2',
      'block'
    ])
    act(() => {
      controls.terminalViews[0]?.show({ cursor: { line: 1, column: 4, style: 6, visible: true } })
    })
    expect(screen.getByTestId('terminal-cursor').dataset.shape).toBe('bar')
    act(() => {
      controls.terminalViews[0]?.show({ cursor: { line: 1, column: 4, style: 2, visible: false } })
    })
    expect(screen.queryByTestId('terminal-cursor')).toBeNull()
  })

  it('leaves out a piece that starts inside the one before it, and keeps that one whole', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const overlapping: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 8, rows: 1 }),
      window: { columns: 8, rows: 1, column: 0, line: 0, above: 0 },
      lines: [
        {
          row: '1',
          soft_wrapped: false,
          truncated: false,
          // Native code never sends pieces that overlap; this state did not come from it.
          pieces: [piece(0, 'abcdef'), { ...piece(2, '\u{e9}'), cells: 1 }, piece(7, 'g')]
        }
      ],
      cursor: null
    }
    act(() => {
      controls.terminalViews[0]?.attach()
      controls.terminalViews[0]?.show(overlapping)
    })
    expect(drawn()[0]).toBe('abcdef g')
  })

  it('warns of cells left blank, rows cut short and a shortened screen', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    expect(screen.getByTestId('substituted-count').textContent).toBe('1 left blank')
    expect(screen.queryByTestId('rows-truncated')).toBeNull()
    expect(screen.queryByTestId('screen-degraded')).toBeNull()
    const whole = terminalScreen(SESSION_MAIN, { columns: 80, rows: 8 })
    act(() => {
      controls.terminalViews[0]?.show({
        ...whole,
        degraded: true,
        replaced: 3,
        lines: whole.lines.map((line, index) => (index === 1 ? { ...line, truncated: true } : line))
      })
    })
    expect(screen.getByTestId('substituted-count').textContent).toBe('3 left blank')
    expect(screen.getByTestId('rows-truncated').textContent).toBe('Rows cut short')
    expect(screen.getByTestId('screen-degraded').textContent).toBe('Shortened by the session')
  })

  it('keeps the last frame while it waits, busy at once and saying so only after a moment', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const view = controls.terminalViews[0]
    act(() => {
      view?.wait()
    })
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
    expect(position()).not.toBe(WAITING)
    expect(drawn()[0]).toBe('$ cargo test -p kr-client')
    await waitFor(
      () => {
        expect(position()).toBe(WAITING)
      },
      { timeout: SLOW_MS * 20 }
    )
    expect(drawn()[0]).toBe('$ cargo test -p kr-client')

    // The next complete screen replaces the frame, and the words go.
    act(() => {
      view?.show()
    })
    expect(position()).not.toBe(WAITING)
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
  })

  it('says which part of the session the window shows when it holds only part of it', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    expect(position()).toBe('')
    act(() => {
      controls.terminalViews[0]?.show(terminalScreen(SESSION_MAIN, { columns: 60, rows: 5 }))
    })
    expect(position()).toBe("Showing columns 1–60 and lines 1–5 of the session's 80×8.")
  })

  it('ends with the host words, keeps the last frame, and attaches again when asked', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    act(() => {
      controls.terminalViews[0]?.wait()
      controls.terminalViews[0]?.end('This session has closed.')
    })
    expect(screen.getByTestId('terminal-ended')).toHaveTextContent('This session has closed.')
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
    expect(screen.queryByTestId('terminal-presentation')).toBeNull()
    expect(drawn()[0]).toBe('$ cargo test -p kr-client')
    await new Promise((resolve) => {
      setTimeout(resolve, SLOW_MS * 2)
    })
    expect(position()).not.toBe(WAITING)

    await person.click(screen.getByTestId('attach-again'))
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    expect(await screen.findByText(/declared no terminal profile/)).toBeInTheDocument()
    expect(screen.queryByTestId('terminal-ended')).toBeNull()
  })

  it('opens again when the host connection comes back after an open was refused', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    open(port)
    expect(await screen.findByTestId('terminal-ended')).toHaveTextContent(
      'This session could not be reached'
    )
    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    expect(await screen.findByTestId('palette-provenance')).toBeInTheDocument()
    expect(screen.queryByTestId('terminal-ended')).toBeNull()
  })

  it('leaves a live view alone when the host connection comes back', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    act(() => {
      controls.setConnected(false)
      controls.setConnected(true)
    })
    await settle()
    expect(controls.terminalViews).toHaveLength(1)
    expect(controls.terminalViews[0]?.closed).toBe(false)
  })

  it('closes its view when the person leaves it, and says nothing of a size claim', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByTestId('release-geometry'))
    await waitFor(() => {
      expect(controls.terminalViews[0]?.closed).toBe(true)
    })
    expect(document.body.textContent).not.toContain('size claim')
  })

  it('closes its view when the page goes, and a view still opening once its open answers', async () => {
    const { port, controls } = fakeHost()
    const shown = open(port)
    await screen.findByTestId('palette-provenance')
    shown.unmount()
    await waitFor(() => {
      expect(controls.terminalViews[0]?.closed).toBe(true)
    })

    const answer = controls.holdTerminalOpens()
    const opening = open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    opening.unmount()
    // The page holds no handle yet, so there is nothing it can close.
    expect(controls.terminalViews[1]?.closed).toBe(false)
    await act(async () => {
      answer()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(controls.terminalViews[1]?.closed).toBe(true)
  })

  it("never draws a late state of one session in another session's view", async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'sessions' })
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByText('Session 1 · Waiting for you')

    controls.holdTerminalViews()
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const first = controls.terminalViews[0]
    act(() => {
      fireEvent.click(screen.getByRole('tab', { name: 'Session 02' }))
    })
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    expect(first?.closed).toBe(true)
    expect(controls.terminalViews[1]?.sessionId).toBe(SESSION_BUILD)

    // Session 2's view attaches and shows its screen.
    act(() => {
      controls.terminalViews[1]?.attach()
      controls.terminalViews[1]?.show()
    })
    expect(drawn()[0]).toBe('$ pnpm -r build')

    // Session 1's view was closed, and a state it published before the close reached it arrives
    // now: it is session 1's, and it neither draws in session 2's view nor takes the place of what
    // session 2's view says.
    act(() => {
      first?.deliverInFlight({
        state: 'showing',
        attachment: first.attachment,
        settled: 0,
        screen: terminalScreen(SESSION_MAIN, { columns: 80, rows: 24 })
      })
    })
    await settle()
    const lines = drawn()
    expect(lines[0]).toBe('$ pnpm -r build')
    expect(lines.join('')).not.toContain('cargo test')
    expect(presentation()).toContain('declared no terminal profile')
    expect(screen.getByTestId('terminal-size').textContent).toBe('100×4')
  })

  it('draws the queries a malformed state carries as marks', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const hostile: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 40, rows: 1 }),
      window: { columns: 40, rows: 1, column: 0, line: 0, above: 0 },
      lines: [
        {
          row: '1',
          soft_wrapped: false,
          truncated: false,
          pieces: [piece(0, 'a\u{1b}[6n\u{1b}]11;?\u{7}b')]
        }
      ],
      cursor: null
    }
    act(() => {
      controls.terminalViews[0]?.attach()
      controls.terminalViews[0]?.show(hostile)
    })
    expect(drawn()[0]).toBe('a\u{fffd}[6n\u{fffd}]11;?\u{fffd}b')
  })

  it('gives the wheel to the program in control mode, and moves the window with it in view mode', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const forwarded = vi.spyOn(port, 'terminalInput')
    open(port)
    await screen.findByTestId('palette-provenance')

    // Control mode: the same call the page has always made for the program's wheel, and no move.
    const given = wheel({ deltaY: 48 })
    expect(given.defaultPrevented).toBe(false)
    expect(forwarded).toHaveBeenCalledWith({ session_id: SESSION_MAIN, wheel: { lines: 3 } })
    expect(controls.terminalViews[0]?.moves).toEqual([])

    await person.click(screen.getByRole('tab', { name: 'View' }))
    forwarded.mockClear()
    // Three rows of wheel up take the window three rows into the history.
    const taken = wheel({ deltaY: -48 })
    expect(taken.defaultPrevented).toBe(true)
    expect(forwarded).not.toHaveBeenCalled()
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -3 }])
    await waitFor(() => {
      expect(position()).toBe('Showing the history, 3 rows above the live screen.')
    })
    expect(drawn()[0]).toBe('$ echo earlier 10')
    expect(controls.terminalViews[0]?.grids).toHaveLength(1)
  })

  it('moves the window only as far as it can go, and a wheel at a limit moves nothing', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // The window holds the live screen's last line already, and the session is narrower than it.
    wheel({ deltaY: 160 })
    wheel({ deltaX: 80 })
    await settle()
    expect(controls.terminalViews[0]?.moves).toEqual([])
    // Twelve rows of history are kept: twenty asked for, twelve go.
    wheel({ deltaY: -320 })
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -12 }])
    await waitFor(() => {
      expect(position()).toBe(
        'Showing the history, 12 rows above the live screen, the oldest the session keeps.'
      )
    })
    wheel({ deltaY: -48 })
    await settle()
    expect(controls.terminalViews[0]?.moves).toHaveLength(1)
  })

  it('draws the frame where its unsettled moves put it, busy at once and saying so after a moment', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const person = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      open(port)
      await screen.findByTestId('palette-provenance')
      await person.click(screen.getByRole('tab', { name: 'View' }))
      wheel({ deltaY: -32 })
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -2 }])
      // The frame moves down two rows at once, over the cells it does not cover.
      expect(gridShift()).toEqual({ x: 0, y: 32 })
      expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
      expect(position()).not.toBe(WAITING)
      // A state that arrives before the wait is long enough to say does not start it again.
      act(() => {
        vi.advanceTimersByTime(SLOW_MS - 100)
      })
      act(() => {
        controls.terminalViews[0]?.show(undefined, 0)
      })
      expect(position()).not.toBe(WAITING)
      act(() => {
        vi.advanceTimersByTime(100)
      })
      expect(position()).toBe(WAITING)
      // A screen that settles nothing, such as a repaint of the old place, leaves the move waiting.
      act(() => {
        controls.terminalViews[0]?.show(undefined, 0)
      })
      expect(gridShift()).toEqual({ x: 0, y: 32 })
      expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
      // Native code says the move is settled with the screen that holds it: the frame is replaced
      // in one write and nothing is shifted any more.
      act(() => {
        controls.terminalViews[0]?.show(
          terminalScreen(SESSION_MAIN, { columns: 80, rows: 24 }, { column: 0, line: 0, above: 2 }),
          1
        )
      })
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      expect(drawn()[0]).toBe('$ echo earlier 11')
      expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
      expect(position()).toBe('Showing the history, 2 rows above the live screen.')
    } finally {
      vi.useRealTimers()
    }
  })

  it('follows a drag in view mode to the pixel, and sends a move for each whole row it crosses', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // Down a row and a half: the window goes up one row, and the frame follows the pointer.
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 124)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -1 }])
    expect(gridShift()).toEqual({ x: 0, y: 24 })
    // Released there: the half rounds to one more row, and the frame rests on whole rows.
    pointer('pointerup', 100, 124)
    expect(controls.terminalViews[0]?.moves).toEqual([
      { number: 1, across: 0, down: -1 },
      { number: 2, across: 0, down: -1 }
    ])
    expect(gridShift()).toEqual({ x: 0, y: 32 })
  })

  it('ends a drag any other way by dropping what it had not sent, and a switch to control returns', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    for (const end of ['pointercancel', 'lostpointercapture']) {
      pointer('pointerdown', 100, 100)
      pointer('pointermove', 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 8 })
      pointer(end, 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 0 })
    }
    expect(controls.terminalViews[0]?.moves).toEqual([])

    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 124)
    await person.click(screen.getByRole('tab', { name: 'Control' }))
    expect(controls.terminalViews[0]?.moves).toEqual([
      { number: 1, across: 0, down: -1 },
      { number: 2, live: true }
    ])
    // The part of the drag not sent is gone; the row it sent waits for its screen, behind which the
    // return takes the window back to the live screen.
    expect(gridShift()).toEqual({ x: 0, y: 0 })
  })

  it('resists a drag past a limit and sends nothing past it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // Fifteen rows down with twelve kept: twelve go, and the other three are drawn resisting.
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 100 + 15 * 16)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -12 }])
    const shifted = gridShift().y
    expect(shifted).toBeGreaterThan(12 * 16)
    expect(shifted).toBeLessThan(15 * 16)
    pointer('pointerup', 100, 100 + 15 * 16)
    expect(controls.terminalViews[0]?.moves).toHaveLength(1)
    expect(gridShift()).toEqual({ x: 0, y: 12 * 16 })
  })

  it('takes no move once the view has ended, so nothing is left shifted or busy', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    act(() => {
      controls.terminalViews[0]?.end('This session has closed.')
    })
    wheel({ deltaY: -48 })
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 140)
    pointer('pointerup', 100, 140)
    await person.click(screen.getByRole('tab', { name: 'Control' }))
    await settle()
    expect(controls.terminalViews[0]?.moves).toEqual([])
    expect(gridShift()).toEqual({ x: 0, y: 0 })
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
  })

  it('ends a drag without sending its part when a second pointer comes down', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 108)
    expect(gridShift()).toEqual({ x: 0, y: 8 })
    pointer('pointerdown', 200, 100, 2)
    expect(gridShift()).toEqual({ x: 0, y: 0 })
    pointer('pointerup', 100, 140)
    expect(controls.terminalViews[0]?.moves).toEqual([])
  })

  it('settles only the moves a frame holds, and replays the rest over it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // A frame of a session wider than the view, at column 5 of 0 to 10.
    const wide = (column: number, right: number, settled: number) => {
      act(() => {
        controls.terminalViews[0]?.show(
          {
            window: { rows: 8, columns: 70, column, line: 0, above: 0 },
            room: { up: 0, down: 0, left: column, right }
          },
          settled
        )
      })
    }
    wide(5, 5, 0)
    wheel({ deltaX: 40 })
    wheel({ deltaX: -80 })
    wheel({ deltaX: 40 })
    expect(controls.terminalViews[0]?.moves).toEqual([
      { number: 1, across: 5, down: 0 },
      { number: 2, across: -10, down: 0 },
      { number: 3, across: 5, down: 0 }
    ])
    expect(gridShift()).toEqual({ x: 0, y: 0 })
    // The first is settled with a frame the host held at column 7, the last it can now reach: the
    // other two are replayed over it in order, each held to its room, and end at column 5.
    wide(7, 0, 1)
    expect(gridShift()).toEqual({ x: 16, y: 0 })
  })

  it('offers labelled controls that move the window a page at a time, only in view mode and within its room', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    const up = screen.getByRole('button', { name: 'Move the window up' })
    expect(up).toBeDisabled()
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // Twelve rows of history above a window of eight: a page up is eight rows.
    expect(up).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Move the window down' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Move the window left' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Move the window right' })).toBeDisabled()
    await person.click(up)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -8 }])
    // The rest of the history is four rows: the next page goes four, and then there is no more.
    await person.click(up)
    expect(controls.terminalViews[0]?.moves.at(-1)).toEqual({ number: 2, across: 0, down: -4 })
    expect(up).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Move the window down' })).toBeEnabled()
  })

  it('ends a drag at any change of the view, one that comes back to where it was included', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 108)
    expect(gridShift()).toEqual({ x: 0, y: 8 })
    // Control, and back to view, with the pointer still down and not moving.
    await person.click(screen.getByRole('tab', { name: 'Control' }))
    await person.click(screen.getByRole('tab', { name: 'View' }))
    expect(gridShift()).toEqual({ x: 0, y: 0 })
    pointer('pointermove', 100, 140)
    pointer('pointerup', 100, 140)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, live: true }])
    expect(gridShift()).toEqual({ x: 0, y: 0 })
  })

  it('begins a drag again at each zoom step, one back to the size it began at included', async () => {
    const person = userEvent.setup()
    // A cell two thirds of the type size wide and four thirds of it high: 8 by 16 at first.
    const rects = vi
      .spyOn(Element.prototype, 'getBoundingClientRect')
      .mockImplementation(function (this: Element) {
        const text = this.textContent ?? ''
        const size = parseFloat(this.parentElement?.style.fontSize ?? '')
        if (this.getAttribute('aria-hidden') !== 'true' || !/^M+$/.test(text) || !(size > 0)) {
          return new DOMRect()
        }
        return DOMRect.fromRect({ x: 0, y: 0, width: (text.length * size * 2) / 3, height: (size * 4) / 3 })
      })
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      open(port)
      await screen.findByTestId('palette-provenance')
      await person.click(screen.getByRole('tab', { name: 'View' }))
      pointer('pointerdown', 100, 100)
      pointer('pointermove', 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 8 })
      // Larger, and back to the size the drag began at, with the pointer still down and not moving:
      // the half row is dropped at each step.
      wheel({ deltaY: -100, ctrlKey: true })
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      wheel({ deltaY: 100, ctrlKey: true })
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      // A row from where the pointer was: one row goes, and nothing is left to round on release.
      pointer('pointermove', 100, 124)
      expect(gridShift()).toEqual({ x: 0, y: 16 })
      pointer('pointerup', 100, 124)
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -1 }])
    } finally {
      rects.mockRestore()
    }
  })

  it("drops a wheel's part of a cell at any change of the view, and a part a move has put past a limit", async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    // A session wider than the view, with one column of room to the right.
    act(() => {
      controls.terminalViews[0]?.show({
        window: { rows: 8, columns: 70, column: 9, line: 0, above: 0 },
        room: { up: 0, down: 0, left: 9, right: 1 }
      })
    })
    // Half a column, then the view changes and comes back: the half is gone.
    wheel({ deltaX: 4 })
    await person.click(screen.getByRole('tab', { name: 'Control' }))
    await person.click(screen.getByRole('tab', { name: 'View' }))
    wheel({ deltaX: 4 })
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, live: true }])
    // Half a column carried, then a button takes the last column: a turn back goes at once.
    await person.click(screen.getByRole('button', { name: 'Move the window right' }))
    wheel({ deltaX: -8 })
    expect(controls.terminalViews[0]?.moves).toEqual([
      { number: 1, live: true },
      { number: 2, across: 1, down: 0 },
      { number: 3, across: -1, down: 0 }
    ])
  })

  it('keeps an ended view ended when a move it took before the end is answered after it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    await person.click(screen.getByRole('tab', { name: 'View' }))
    wheel({ deltaY: -48 })
    act(() => {
      controls.terminalViews[0]?.end('This session has closed.')
    })
    await settle()
    expect(screen.getByTestId('terminal-ended')).toHaveTextContent('This session has closed.')
  })

  it('moves nothing with a drag in control mode', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    pointer('pointerdown', 100, 100)
    pointer('pointermove', 100, 180)
    pointer('pointerup', 100, 180)
    await settle()
    expect(controls.terminalViews[0]?.moves).toEqual([])
    expect(gridShift()).toEqual({ x: 0, y: 0 })
  })
})

/** Turns the wheel over the terminal. */
function wheel(init: WheelEventInit): WheelEvent {
  const event = new WheelEvent('wheel', { bubbles: true, cancelable: true, ...init })
  act(() => {
    screen.getByTestId('terminal-surface').firstElementChild?.dispatchEvent(event)
  })
  return event
}

/** Sends pointer `id`'s `type` over the terminal at `x`, `y`: the primary one unless told. */
function pointer(type: string, x: number, y: number, id = 1): void {
  act(() => {
    screen
      .getByTestId('terminal-surface')
      .firstElementChild?.dispatchEvent(
        new PointerEvent(type, {
          bubbles: true,
          cancelable: true,
          pointerId: id,
          pointerType: 'mouse',
          isPrimary: id === 1,
          button: 0,
          buttons: type === 'pointerup' ? 0 : 1,
          clientX: x,
          clientY: y
        })
      )
  })
}

/** How far `element` is drawn from its place, in pixels. */
function translation(element: HTMLElement | null): { x: number; y: number } {
  const found = /translate\((-?[\d.]+)px, (-?[\d.]+)px\)/.exec(element?.style.transform ?? '')
  return found === null ? { x: 0, y: 0 } : { x: Number(found[1]), y: Number(found[2]) }
}

/** How far the grid is drawn from its place, in pixels: the moves waiting and the drag's part. */
function gridShift(): { x: number; y: number } {
  const grid = screen.getByTestId('terminal-grid')
  const waiting = translation(grid)
  const dragged = translation(grid.parentElement)
  const x = waiting.x + dragged.x
  const y = waiting.y + dragged.y
  return { x: x === 0 ? 0 : x, y: y === 0 ? 0 : y }
}

function piece(column: number, text: string): TerminalScreen['lines'][number]['pieces'][number] {
  return {
    column,
    cells: [...text].length,
    text,
    rendition: {
      background: 'default',
      blink: 'none',
      bold: false,
      faint: false,
      foreground: 'default',
      invisible: false,
      italic: false,
      overline: false,
      reverse: false,
      strikethrough: false,
      underline: 'none',
      underline_colour: 'default',
      vertical_align: 'baseline'
    },
    hyperlink: null
  }
}
