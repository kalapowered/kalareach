/**
 * The desktop's raw terminal view, drawn from the states native code publishes on its channel.
 *
 * The scripted host publishes what native code does for a view: attached with no screen, a
 * complete screen of cells, waiting after the host's reset, ended with the host's words. What is
 * checked is what the page makes of them: nothing drawn before the first screen, the screen drawn
 * piece by piece at its columns, the last frame kept while the view waits, a view opened again
 * after it ended, closed when it is left, and never a state of one session drawn in another's view.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Terminal } from '@xterm/xterm'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, terminalScreen } from '../src/host/fake'
import type { HostPort, TerminalScreen } from '../src/host/port'
import { ATTACHING, SLOW_MS, WAITING } from '../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

function open(port: HostPort, place: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }): void {
  render(
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

/** The renderer the view created last. */
function renderer(opened: { mock: { contexts: unknown[] } }): Terminal {
  return opened.mock.contexts.at(-1) as Terminal
}

/** Every line a renderer holds, once everything written to it has been processed. */
async function drawn(terminal: Terminal): Promise<string[]> {
  await new Promise<void>((resolve) => {
    terminal.write('', resolve)
  })
  const buffer = terminal.buffer.active
  const lines: string[] = []
  for (let line = 0; line < buffer.length; line += 1) {
    lines.push(buffer.getLine(line)?.translateToString(true) ?? '')
  }
  return lines
}

const presentation = () => screen.getByTestId('terminal-presentation').textContent
const position = () => screen.getByTestId('terminal-position').textContent

describe('the raw view draws the screen native code holds for it (KR-REQ-08.02)', () => {
  it('draws nothing before its first screen, and says it is attaching', async () => {
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    expect(presentation()).toBe(ATTACHING)
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByTestId('palette-provenance')).toBeNull()
    expect((await drawn(renderer(opened))).join('').trim()).toBe('')

    // Attached, with no screen yet: the host's sentence, and the words for waiting at once.
    act(() => {
      controls.terminalViews[0]?.attach()
    })
    expect(presentation()).toBe(
      "This view is shown a viewport because its client declared no terminal profile, so what the session's output would do on its terminal is not known."
    )
    expect(position()).toBe(WAITING)
    expect((await drawn(renderer(opened))).join('').trim()).toBe('')
    opened.mockRestore()
  })

  it('draws a published screen piece by piece, each at its own column', async () => {
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const lines = await drawn(renderer(opened))
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
    opened.mockRestore()
  })

  it('draws the bottom-right cell without scrolling the screen', async () => {
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const full: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 4, rows: 2 }),
      window: { columns: 4, rows: 2 },
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
    expect((await drawn(renderer(opened))).slice(0, 2)).toEqual(['abcd', 'efgh'])
    opened.mockRestore()
  })

  it('keeps each piece inside its cells when the renderer measures its text wider', async () => {
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const measured: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 6, rows: 2 }),
      window: { columns: 6, rows: 2 },
      lines: [
        // A letter and a mark native code measures as one cell, which this renderer gives a cell of
        // its own, then a blank cell and a letter.
        {
          row: '1',
          soft_wrapped: false,
          truncated: false,
          pieces: [{ ...piece(0, 'a\u{1ab0}'), cells: 1 }, piece(2, 'b')]
        },
        // A wide character in a piece of one cell, from a state that did not come from native code.
        {
          row: '2',
          soft_wrapped: false,
          truncated: false,
          pieces: [{ ...piece(0, '\u{4e2d}'), cells: 1 }, piece(2, 'c')]
        }
      ],
      cursor: null
    }
    act(() => {
      controls.terminalViews[0]?.attach()
      controls.terminalViews[0]?.show(measured)
    })
    // Nothing is drawn past a piece's cells: the blank cell after each stays blank, and what the
    // renderer could not fit is left out.
    expect((await drawn(renderer(opened))).slice(0, 2)).toEqual(['a b', '  c'])
    opened.mockRestore()
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
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    const view = controls.terminalViews[0]
    act(() => {
      view?.wait()
    })
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'true')
    expect(position()).not.toBe(WAITING)
    expect((await drawn(renderer(opened)))[0]).toBe('$ cargo test -p kr-client')
    await waitFor(
      () => {
        expect(position()).toBe(WAITING)
      },
      { timeout: SLOW_MS * 20 }
    )
    expect((await drawn(renderer(opened)))[0]).toBe('$ cargo test -p kr-client')

    // The next complete screen replaces the frame, and the words go.
    act(() => {
      view?.show()
    })
    expect(position()).not.toBe(WAITING)
    expect(screen.getByTestId('terminal-surface')).toHaveAttribute('aria-busy', 'false')
    opened.mockRestore()
  })

  it('says when the window shows only the top left of the session', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await screen.findByTestId('palette-provenance')
    expect(position()).toBe('')
    act(() => {
      controls.terminalViews[0]?.show(terminalScreen(SESSION_MAIN, { columns: 60, rows: 5 }))
    })
    expect(position()).toBe("Showing the top-left 60×5 of the session's 80×8.")
  })

  it('ends with the host words, keeps the last frame, and attaches again when asked', async () => {
    const person = userEvent.setup()
    const opened = vi.spyOn(Terminal.prototype, 'open')
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
    expect((await drawn(renderer(opened)))[0]).toBe('$ cargo test -p kr-client')
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
    opened.mockRestore()
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

  it("never draws a late state of one session in another session's view", async () => {
    const person = userEvent.setup()
    const opened = vi.spyOn(Terminal.prototype, 'open')
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
    expect((await drawn(renderer(opened)))[0]).toBe('$ pnpm -r build')

    // Session 1's view was closed, and a state it published before the close reached it arrives
    // now: it is session 1's, and it neither draws in session 2's view nor takes the place of what
    // session 2's view says.
    act(() => {
      first?.deliverInFlight({
        state: 'showing',
        attachment: first.attachment,
        screen: terminalScreen(SESSION_MAIN, { columns: 80, rows: 24 })
      })
    })
    await settle()
    const lines = await drawn(renderer(opened))
    expect(lines[0]).toBe('$ pnpm -r build')
    expect(lines.join('')).not.toContain('cargo test')
    expect(presentation()).toContain('declared no terminal profile')
    expect(screen.getByTestId('terminal-size').textContent).toBe('100×4')
    opened.mockRestore()
  })

  it('draws a query a malformed state carries as marks, and its renderer answers nothing', async () => {
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    const terminal = renderer(opened)
    const answered: string[] = []
    const listening = terminal.onData((data) => {
      answered.push(data)
    })
    const hostile: TerminalScreen = {
      ...terminalScreen(SESSION_MAIN, { columns: 40, rows: 1 }),
      window: { columns: 40, rows: 1 },
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
    expect((await drawn(terminal))[0]).toBe('a\u{fffd}[6n\u{fffd}]11;?\u{fffd}b')
    expect(answered).toEqual([])
    listening.dispose()
    opened.mockRestore()
  })

  it('gives the wheel to the program in control mode, and moves nothing with it in view mode', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const forwarded = vi.spyOn(port, 'terminalInput')
    open(port)
    await screen.findByTestId('palette-provenance')
    const wheel = (deltaY: number, ctrlKey = false) => {
      const event = new WheelEvent('wheel', { deltaY, ctrlKey, bubbles: true, cancelable: true })
      act(() => {
        screen.getByTestId('terminal-surface').firstElementChild?.dispatchEvent(event)
      })
      return event
    }

    // Control mode: the same call the page has always made for the program's wheel.
    const given = wheel(48)
    expect(given.defaultPrevented).toBe(false)
    expect(forwarded).toHaveBeenCalledWith({ session_id: SESSION_MAIN, wheel: { lines: 3 } })

    await person.click(screen.getByRole('tab', { name: 'View' }))
    forwarded.mockClear()
    const taken = wheel(120)
    expect(taken.defaultPrevented).toBe(true)
    expect(forwarded).not.toHaveBeenCalled()
    expect(controls.terminalViews[0]?.grids).toHaveLength(1)
  })
})

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
